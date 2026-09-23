package node

import (
	"context"
	"database/sql"
	"errors"

	"github.com/boxvtk621/harness-codex/internal/diagnosticlog"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

const actionDispatchStart = "dispatch.start"

type DispatchResult struct {
	Outcome   string
	AttemptID string
	RequestID string
}

type dispatchCandidate struct {
	RequestID     string
	DialogID      string
	MessageID     string
	MessageText   string
	QueueSequence int64
	StateVersion  int64
}

func (node *Node) DispatchNext(ctx context.Context) (DispatchResult, error) {
	if node.config.ProviderAuth != nil {
		envelope, failure := node.config.ProviderAuth.Snapshot(ctx, node.config.NodeID)
		if failure != nil || envelope.State != "authenticated" || (envelope.Operation != nil && envelope.Operation.Status == "pending") {
			return DispatchResult{Outcome: "blocked"}, nil
		}
	}
	candidate, err := node.peekDispatch(ctx)
	if err != nil || candidate == nil {
		return DispatchResult{Outcome: "idle"}, err
	}
	if node.config.Policies == nil {
		node.blockPolicy(ctx)
		return DispatchResult{Outcome: "blocked"}, nil
	}
	policy, err := node.config.Policies.Current(ctx, candidate.DialogID)
	if err != nil {
		node.blockPolicy(ctx)
		return DispatchResult{Outcome: "blocked"}, nil
	}
	policy, err = harnessadapter.PreparePolicySnapshot(policy)
	if err != nil {
		node.blockPolicy(ctx)
		return DispatchResult{Outcome: "blocked"}, nil
	}

	// Serialize the final authentication proof and durable dispatch intent with
	// provider login/logout. The lock order is startGate, then mu.
	node.startGate.Lock()
	defer node.startGate.Unlock()
	if !node.providerAuthReady(ctx) {
		return DispatchResult{Outcome: "blocked"}, nil
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	if node.settingsBarrier || node.settingsNotReady {
		return DispatchResult{Outcome: "blocked"}, nil
	}
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return DispatchResult{}, err
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return DispatchResult{}, err
	}
	if state.StateVersion != candidate.StateVersion || state.QueuePaused || state.ActiveAttemptID.Valid || state.PendingCount == 0 {
		return DispatchResult{Outcome: "changed"}, nil
	}
	var status, currentRequest, currentDialog, currentMessage, messageText, disposition string
	var queueSequence int64
	err = tx.QueryRowContext(ctx, `SELECT r.status,r.request_id,r.dialog_id,r.input_message_id,r.queue_sequence,m.text,m.disposition
		FROM requests r JOIN messages m ON m.message_id=r.input_message_id WHERE r.status='queued'
		AND NOT EXISTS (SELECT 1 FROM administrative_holds h WHERE h.node_id=?
			AND NOT EXISTS (SELECT 1 FROM administrative_hold_outcomes o WHERE o.operation_id=h.operation_id)
			AND (h.scope='node' OR (h.scope='dialog' AND h.dialog_id=r.dialog_id)))
		ORDER BY r.queue_sequence LIMIT 1`, state.NodeID).Scan(
		&status, &currentRequest, &currentDialog, &currentMessage, &queueSequence, &messageText, &disposition)
	if errors.Is(err, sql.ErrNoRows) {
		return DispatchResult{Outcome: "held"}, nil
	}
	if err != nil {
		return DispatchResult{}, err
	}
	if currentRequest != candidate.RequestID || currentDialog != candidate.DialogID || currentMessage != candidate.MessageID || queueSequence != candidate.QueueSequence {
		return DispatchResult{Outcome: "changed"}, nil
	}
	attemptID, err := node.newID()
	if err != nil {
		return DispatchResult{}, err
	}
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(a.generation),0)+1 FROM attempts a JOIN requests r ON r.request_id=a.request_id WHERE r.input_message_id=?`, currentMessage).Scan(&generation); err != nil {
		return DispatchResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_snapshots(effective_hash,revision,content,content_hash,tool_manifest,tool_manifest_hash,approval_mode)
		VALUES(?,?,?,?,?,?,?) ON CONFLICT(effective_hash) DO NOTHING`, policy.EffectiveHash, policy.Revision, policy.Content, policy.ContentHash, policy.ToolManifest, policy.ToolManifestHash, policy.ApprovalMode); err != nil {
		return DispatchResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO attempts(attempt_id,node_id,dialog_id,request_id,generation,version,state,effect_status,context_boundary_message_id,policy_hash)
		VALUES(?,?,?,?,?,1,'dispatching','none',?,?)`, attemptID, state.NodeID, currentDialog, currentRequest, generation, currentMessage, policy.EffectiveHash); err != nil {
		return DispatchResult{}, err
	}
	now := timestamp(node.config.Clock())
	if _, err := tx.ExecContext(ctx, "UPDATE requests SET version=version+1,status='dispatching',updated_at=? WHERE request_id=?", now, currentRequest); err != nil {
		return DispatchResult{}, err
	}
	if disposition == "queued" {
		var messageVersion int64
		if err := tx.QueryRowContext(ctx, "SELECT version FROM messages WHERE message_id=?", currentMessage).Scan(&messageVersion); err != nil {
			return DispatchResult{}, err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE messages SET version=version+1,disposition='applied',attempt_id=? WHERE message_id=?", attemptID, currentMessage); err != nil {
			return DispatchResult{}, err
		}
		if _, err := node.appendEvent(ctx, tx, &state, "message.disposition_changed", currentMessage, messageVersion+1, "", "", harnessprotocol.MessageDispositionPayload{MessageID: currentMessage, From: "queued", To: "applied", ReasonCode: "request_dispatched"}, false); err != nil {
			return DispatchResult{}, err
		}
	}
	state.PendingCount--
	state.QueueVersion++
	state.StateVersion++
	state.ActiveAttemptID = sql.NullString{String: attemptID, Valid: true}
	state.EngineReadiness = "ready"
	state.Occupancy = "active"
	state.BlockedReasons = removeReason(state.BlockedReasons, "policy_unavailable")
	if _, err := node.appendEvent(ctx, tx, &state, "attempt.dispatching", attemptID, 1, attemptID, currentDialog, harnessprotocol.AttemptDispatchingPayload{
		RequestID: currentRequest, Generation: generation, ContextBoundaryMessageID: currentMessage,
		PolicyRevision: policy.Revision, PolicyHash: policy.EffectiveHash,
	}, false); err != nil {
		return DispatchResult{}, err
	}
	if err := node.appendQueueEvent(ctx, tx, &state); err != nil {
		return DispatchResult{}, err
	}
	if err := node.appendNodeEvent(ctx, tx, &state); err != nil {
		return DispatchResult{}, err
	}
	proof, err := failedTailProof(ctx, tx, currentDialog, currentMessage)
	if err != nil {
		return DispatchResult{}, err
	}
	actionPayload := mustJSON(map[string]any{"generation": generation, "dialogId": currentDialog, "requestId": currentRequest, "failedTailRetry": proof})
	if _, err := tx.ExecContext(ctx, `INSERT INTO control_actions(command_id,kind,attempt_id,payload,status) VALUES(?,?,?,?,'pending')`, attemptID, actionDispatchStart, attemptID, []byte(actionPayload)); err != nil {
		return DispatchResult{}, err
	}
	if err := saveState(ctx, tx, state); err != nil {
		return DispatchResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return DispatchResult{}, err
	}
	node.config.Logger.Emit(diagnosticlog.LevelInfo, diagnosticlog.EventAttemptDispatch, diagnosticlog.Fields{
		NodeID: state.NodeID, DialogID: currentDialog, RequestID: currentRequest, AttemptID: attemptID, Generation: generation,
	})
	if err := node.checkFault(FaultAfterDispatchIntent); err != nil {
		return DispatchResult{Outcome: "unknown", AttemptID: attemptID, RequestID: currentRequest}, err
	}
	node.afterCommit(context.Background(), postCommitAction{commandID: attemptID, kind: actionDispatchStart, attemptID: attemptID, payload: actionPayload})
	_ = messageText
	return DispatchResult{Outcome: "dispatching", AttemptID: attemptID, RequestID: currentRequest}, nil
}

func (node *Node) peekDispatch(ctx context.Context) (*dispatchCandidate, error) {
	node.mu.Lock()
	defer node.mu.Unlock()
	state, err := loadState(ctx, node.db)
	if err != nil {
		return nil, err
	}
	if state.QueuePaused || state.ActiveAttemptID.Valid || state.PendingCount == 0 || slicesContains(state.BlockedReasons, "execution_unknown") {
		return nil, nil
	}
	var candidate dispatchCandidate
	candidate.StateVersion = state.StateVersion
	err = node.db.QueryRowContext(ctx, `SELECT r.request_id,r.dialog_id,r.input_message_id,r.queue_sequence,m.text FROM requests r
		JOIN messages m ON m.message_id=r.input_message_id WHERE r.status='queued'
		AND NOT EXISTS (SELECT 1 FROM administrative_holds h WHERE h.node_id=?
			AND NOT EXISTS (SELECT 1 FROM administrative_hold_outcomes o WHERE o.operation_id=h.operation_id)
			AND (h.scope='node' OR (h.scope='dialog' AND h.dialog_id=r.dialog_id)))
		ORDER BY r.queue_sequence LIMIT 1`, state.NodeID).Scan(
		&candidate.RequestID, &candidate.DialogID, &candidate.MessageID, &candidate.QueueSequence, &candidate.MessageText)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &candidate, err
}

func slicesContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func (node *Node) blockPolicy(ctx context.Context) {
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return
	}
	if state.EngineReadiness == "blocked" && slicesContains(state.BlockedReasons, "policy_unavailable") {
		return
	}
	state.EngineReadiness = "blocked"
	state.BlockedReasons = addReason(state.BlockedReasons, "policy_unavailable")
	state.StateVersion++
	if node.appendNodeEvent(ctx, tx, &state) == nil && saveState(ctx, tx, state) == nil {
		_ = tx.Commit()
	}
}
