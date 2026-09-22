package node

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

func (node *Node) afterCommit(_ context.Context, action postCommitAction) {
	select {
	case node.actions <- struct{}{}:
	default:
	}
}

func (node *Node) actionLoop(ctx context.Context) {
	heartbeat := time.NewTicker(time.Second)
	defer heartbeat.Stop()
	type actionLane struct {
		name     string
		capacity chan struct{}
	}
	lanes := []actionLane{
		{name: "stop", capacity: make(chan struct{}, 1)},
		{name: "dispatch", capacity: make(chan struct{}, 1)},
		{name: "control", capacity: make(chan struct{}, 6)},
	}
	var running sync.WaitGroup
	defer func() {
		running.Wait()
		close(node.done)
	}()
	firstCycle := true
	for {
		if !firstCycle {
			select {
			case <-ctx.Done():
				return
			case <-node.actions:
			case <-heartbeat.C:
			}
			node.recordExecutorHeartbeat()
		}
		firstCycle = false
		for {
			scheduled := false
			for _, lane := range lanes {
				select {
				case lane.capacity <- struct{}{}:
				default:
					continue
				}
				action, ok := node.claimAction(ctx, lane.name)
				if !ok {
					<-lane.capacity
					continue
				}
				scheduled = true
				running.Add(1)
				go func(action postCommitAction, capacity chan struct{}) {
					defer running.Done()
					defer func() {
						<-capacity
						select {
						case node.actions <- struct{}{}:
						default:
						}
					}()
					node.performAction(ctx, action)
				}(action, lane.capacity)
			}
			if !scheduled {
				break
			}
		}
		if !node.config.ManualDispatchForTesting {
			for retries := 0; retries < 4 && ctx.Err() == nil; retries++ {
				result, err := node.DispatchNext(ctx)
				if err != nil || result.Outcome != "changed" {
					break
				}
			}
		}
	}
}

func (node *Node) recordExecutorHeartbeat() {
	node.heartbeatMu.Lock()
	node.heartbeatAt = timestamp(node.config.Clock())
	node.heartbeatMu.Unlock()
}

func (node *Node) executorHeartbeatAt() string {
	node.heartbeatMu.RLock()
	defer node.heartbeatMu.RUnlock()
	return node.heartbeatAt
}

func (node *Node) claimAction(ctx context.Context, lane string) (postCommitAction, bool) {
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return postCommitAction{}, false
	}
	defer tx.Rollback()
	var action postCommitAction
	var messageID, actorID sql.NullString
	query := `SELECT command_id,kind,attempt_id,message_id,actor_id,payload FROM control_actions WHERE status='pending' AND kind NOT IN (?,?) ORDER BY rowid LIMIT 1`
	arguments := []any{actionDispatchStart, string(harnessprotocol.CommandAttemptStop)}
	if lane == "dispatch" {
		query = `SELECT c.command_id,c.kind,c.attempt_id,c.message_id,c.actor_id,c.payload FROM control_actions c
			JOIN attempts a ON a.attempt_id=c.attempt_id WHERE c.status='pending' AND c.kind=?
			AND NOT EXISTS (SELECT 1 FROM administrative_holds h WHERE h.node_id=a.node_id
				AND NOT EXISTS (SELECT 1 FROM administrative_hold_outcomes o WHERE o.operation_id=h.operation_id)
				AND (h.scope='node' OR (h.scope='dialog' AND h.dialog_id=a.dialog_id)))
			ORDER BY c.rowid LIMIT 1`
		arguments = []any{actionDispatchStart}
	} else if lane == "stop" {
		query = `SELECT command_id,kind,attempt_id,message_id,actor_id,payload FROM control_actions WHERE status='pending' AND kind=? ORDER BY rowid LIMIT 1`
		arguments = []any{string(harnessprotocol.CommandAttemptStop)}
	}
	if err := tx.QueryRowContext(ctx, query, arguments...).Scan(&action.commandID, &action.kind, &action.attemptID, &messageID, &actorID, &action.payload); err != nil {
		return postCommitAction{}, false
	}
	action.messageID = messageID.String
	action.actorID = actorID.String
	if _, err := tx.ExecContext(ctx, "UPDATE control_actions SET status='inflight' WHERE command_id=? AND status='pending'", action.commandID); err != nil {
		return postCommitAction{}, false
	}
	if err := tx.Commit(); err != nil {
		return postCommitAction{}, false
	}
	return action, true
}

type actionPayload struct {
	Generation      int64  `json:"generation"`
	DialogID        string `json:"dialogId"`
	RequestID       string `json:"requestId"`
	Text            string `json:"text"`
	ApprovalID      string `json:"approvalId"`
	ApprovalVersion int64  `json:"approvalVersion"`
	CallID          string `json:"callId"`
	ActionHash      string `json:"actionHash"`
	Decision        string `json:"decision"`
	InputRequestID  string `json:"inputRequestId"`
	InputVersion    int64  `json:"inputVersion"`
}

func (node *Node) performAction(ctx context.Context, action postCommitAction) {
	var payload actionPayload
	if json.Unmarshal(action.payload, &payload) != nil {
		return
	}
	reference := harnessadapter.AttemptRef{
		NodeID: node.config.NodeID, DialogID: payload.DialogID, RequestID: payload.RequestID,
		AttemptID: action.attemptID, Generation: payload.Generation,
	}
	switch action.kind {
	case actionDispatchStart:
		node.performDispatch(ctx, action, reference)
	case string(harnessprotocol.CommandAttemptStop):
		result, err := node.config.Adapter.Cancel(ctx, harnessadapter.CancelInput{Attempt: reference})
		if err != nil || result.Outcome == harnessadapter.CancelUnknown {
			node.markAttemptUnknown(context.Background(), reference, "cancel_unconfirmed", "unknown")
			node.finishAction(action.commandID, "unknown")
		} else if result.Outcome == harnessadapter.CancelRejected {
			node.finishAction(action.commandID, "rejected")
		} else if result.Outcome == harnessadapter.CancelAcknowledged {
			node.finishAction(action.commandID, "acknowledged")
		} else {
			node.markAttemptUnknown(context.Background(), reference, "adapter_protocol", "unknown")
			node.finishAction(action.commandID, "unknown")
		}
	case string(harnessprotocol.CommandMessageSteer):
		result, err := node.config.Adapter.Steer(ctx, harnessadapter.SteerInput{Attempt: reference, MessageID: action.messageID, Text: payload.Text})
		if err != nil {
			node.finishSteer(context.Background(), reference, action.messageID, harnessadapter.SteerUnknown)
			node.finishAction(action.commandID, "unknown")
		} else if result.Outcome == harnessadapter.SteerApplied || result.Outcome == harnessadapter.SteerFallbackQueued || result.Outcome == harnessadapter.SteerUnknown || result.Outcome == harnessadapter.SteerRejected {
			node.finishSteer(context.Background(), reference, action.messageID, result.Outcome)
			status := "acknowledged"
			if result.Outcome == harnessadapter.SteerUnknown {
				status = "unknown"
			} else if result.Outcome == harnessadapter.SteerRejected {
				status = "rejected"
			}
			node.finishAction(action.commandID, status)
		} else {
			node.markAttemptUnknown(context.Background(), reference, "adapter_protocol", "unknown")
			node.finishSteer(context.Background(), reference, action.messageID, harnessadapter.SteerUnknown)
			node.finishAction(action.commandID, "unknown")
		}
	case string(harnessprotocol.CommandApprovalRespond):
		result, err := node.config.Adapter.RespondApproval(ctx, harnessadapter.RespondApprovalInput{
			Attempt: reference, ApprovalID: payload.ApprovalID, ApprovalVersion: payload.ApprovalVersion,
			ActionHash: payload.ActionHash, Decision: payload.Decision,
		})
		outcome, invalid := responseOutcome(result, err)
		if invalid {
			node.markAttemptUnknown(context.Background(), reference, "adapter_protocol", "unknown")
		}
		node.finishApproval(context.Background(), reference, action.actorID, payload, outcome)
		node.finishAction(action.commandID, actionStatus(outcome))
	case string(harnessprotocol.CommandInputRespond):
		result, err := node.config.Adapter.RespondInput(ctx, harnessadapter.RespondInputInput{
			Attempt: reference, InputRequestID: payload.InputRequestID, InputVersion: payload.InputVersion, Text: payload.Text,
		})
		outcome, invalid := responseOutcome(result, err)
		if invalid {
			node.markAttemptUnknown(context.Background(), reference, "adapter_protocol", "unknown")
		}
		node.finishInput(context.Background(), reference, action.messageID, payload, outcome)
		node.finishAction(action.commandID, actionStatus(outcome))
	}
}

func (node *Node) performDispatch(ctx context.Context, action postCommitAction, reference harnessadapter.AttemptRef) {
	node.startGate.Lock()
	gateHeld := true
	defer func() {
		if gateHeld {
			node.startGate.Unlock()
		}
	}()
	// A recovered dispatch may have been claimed immediately before auth
	// readiness closed. Requeue it without touching provider state or starting
	// a native turn; the action loop retries only after a fresh proof.
	if !node.providerAuthReady(ctx) {
		node.requeueAction(action.commandID)
		return
	}
	node.mu.Lock()
	var prompt, boundaryMessageID, revision, contentHash, toolHash, approvalMode, effectiveHash string
	var boundarySequence int64
	var resume bool
	var content, tools []byte
	err := node.db.QueryRowContext(ctx, `SELECT m.text,a.context_boundary_message_id,m.sequence,p.revision,p.content,p.content_hash,p.tool_manifest,p.tool_manifest_hash,p.approval_mode,p.effective_hash,
		EXISTS(SELECT 1 FROM attempts prior WHERE prior.dialog_id=a.dialog_id AND prior.attempt_id<>a.attempt_id AND prior.state IN('completed','failed','interrupted'))
		FROM attempts a JOIN requests r ON r.request_id=a.request_id JOIN messages m ON m.message_id=r.input_message_id
		JOIN policy_snapshots p ON p.effective_hash=a.policy_hash WHERE a.attempt_id=? AND a.state='dispatching'`, reference.AttemptID).Scan(
		&prompt, &boundaryMessageID, &boundarySequence, &revision, &content, &contentHash, &tools, &toolHash, &approvalMode, &effectiveHash, &resume)
	node.mu.Unlock()
	if err != nil {
		node.markAttemptUnknown(context.Background(), reference, "dispatch_uncertain", "unknown")
		node.finishAction(action.commandID, "unknown")
		return
	}
	policy, err := harnessadapter.PreparePolicySnapshot(harnessadapter.PolicySnapshot{
		Revision: revision, Content: content, ContentHash: contentHash, ToolManifest: tools,
		ToolManifestHash: toolHash, ApprovalMode: approvalMode, EffectiveHash: effectiveHash,
	})
	if err != nil {
		node.markAttemptUnknown(context.Background(), reference, "adapter_protocol", "unknown")
		node.finishAction(action.commandID, "unknown")
		return
	}
	boundary := harnessadapter.ContextBoundary{MessageID: boundaryMessageID, Sequence: boundarySequence}
	if resume {
		result, err := node.config.Adapter.Resume(ctx, harnessadapter.ResumeInput{Attempt: reference, Prompt: prompt, Policy: policy, Context: boundary})
		if err != nil || result.Outcome == harnessadapter.ResumeUnknown {
			node.markAttemptUnknown(context.Background(), reference, "dispatch_uncertain", "unknown")
			node.finishAction(action.commandID, "unknown")
			return
		}
		if result.Outcome == harnessadapter.ResumeContextMissing || result.Outcome == harnessadapter.ResumeRejected {
			_ = node.Observe(context.Background(), Observation{AttemptID: reference.AttemptID, Generation: reference.Generation, Kind: "terminal", TerminalState: "failed", EffectStatus: "none", Confirmed: true})
			node.finishAction(action.commandID, "rejected")
			return
		}
		if result.Outcome != harnessadapter.ResumeStarted {
			node.markAttemptUnknown(context.Background(), reference, "adapter_protocol", "unknown")
			node.finishAction(action.commandID, "unknown")
			return
		}
	} else {
		result, err := node.config.Adapter.Start(ctx, harnessadapter.StartInput{Attempt: reference, Prompt: prompt, Policy: policy, Context: boundary})
		if err != nil || result.Outcome == harnessadapter.StartUnknown {
			node.markAttemptUnknown(context.Background(), reference, "dispatch_uncertain", "unknown")
			node.finishAction(action.commandID, "unknown")
			return
		}
		if result.Outcome == harnessadapter.StartRejected {
			_ = node.Observe(context.Background(), Observation{AttemptID: reference.AttemptID, Generation: reference.Generation, Kind: "terminal", TerminalState: "failed", EffectStatus: "none", Confirmed: true})
			node.finishAction(action.commandID, "rejected")
			return
		}
		if result.Outcome != harnessadapter.StartStarted {
			node.markAttemptUnknown(context.Background(), reference, "adapter_protocol", "unknown")
			node.finishAction(action.commandID, "unknown")
			return
		}
	}
	if node.markStarted(context.Background(), reference) != nil {
		node.markAttemptUnknown(context.Background(), reference, "dispatch_uncertain", "unknown")
		node.finishAction(action.commandID, "unknown")
		return
	}
	node.finishAction(action.commandID, "acknowledged")
	node.startGate.Unlock()
	gateHeld = false
	node.observeAdapterStream(ctx, reference)
}

func (node *Node) requeueAction(commandID string) {
	node.mu.Lock()
	defer node.mu.Unlock()
	_, _ = node.db.Exec("UPDATE control_actions SET status='pending' WHERE command_id=? AND status='inflight'", commandID)
}

func (node *Node) markStarted(ctx context.Context, reference harnessadapter.AttemptRef) error {
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return err
	}
	if !state.ActiveAttemptID.Valid || state.ActiveAttemptID.String != reference.AttemptID {
		return errors.New("dispatch attempt is no longer active")
	}
	var version int64
	var attemptState string
	if err := tx.QueryRowContext(ctx, "SELECT version,state FROM attempts WHERE attempt_id=?", reference.AttemptID).Scan(&version, &attemptState); err != nil {
		return err
	}
	if attemptState != "dispatching" {
		return errors.New("attempt is not dispatching")
	}
	now := timestamp(node.config.Clock())
	if _, err := tx.ExecContext(ctx, "UPDATE attempts SET version=version+1,state='running',started_at=? WHERE attempt_id=?", now, reference.AttemptID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE requests SET version=version+1,status='active',updated_at=? WHERE request_id=?", now, reference.RequestID); err != nil {
		return err
	}
	state.StateVersion++
	started := adapterProjection{eventType: "attempt.started", entityID: reference.AttemptID, entityVersion: version + 1, payload: harnessprotocol.AttemptStartedPayload{RequestID: reference.RequestID, Generation: reference.Generation}, key: "started"}
	if _, err := node.appendEvent(ctx, tx, &state, started.eventType, started.entityID, started.entityVersion, reference.AttemptID, reference.DialogID, started.payload, false); err != nil {
		return err
	}
	if err := recordAdapterProjection(ctx, tx, state.LastEventSeq, reference.AttemptID, started); err != nil {
		return err
	}
	if err := node.appendNodeEvent(ctx, tx, &state); err != nil {
		return err
	}
	if err := saveState(ctx, tx, state); err != nil {
		return err
	}
	return tx.Commit()
}

func actionStatus(outcome harnessadapter.ResponseOutcome) string {
	switch outcome {
	case harnessadapter.ResponseApplied:
		return "acknowledged"
	case harnessadapter.ResponseRejected:
		return "rejected"
	default:
		return "unknown"
	}
}

func (node *Node) finishAction(commandID, status string) {
	node.mu.Lock()
	defer node.mu.Unlock()
	_, _ = node.db.Exec("UPDATE control_actions SET status=? WHERE command_id=? AND status='inflight'", status, commandID)
}

func responseOutcome(result harnessadapter.ResponseResult, err error) (harnessadapter.ResponseOutcome, bool) {
	if err != nil {
		return harnessadapter.ResponseUnknown, false
	}
	switch result.Outcome {
	case harnessadapter.ResponseApplied, harnessadapter.ResponseRejected, harnessadapter.ResponseUnknown:
		return result.Outcome, false
	default:
		return harnessadapter.ResponseUnknown, true
	}
}

func (node *Node) finishSteer(ctx context.Context, attempt harnessadapter.AttemptRef, messageID string, outcome harnessadapter.SteerOutcome) {
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return
	}
	var version int64
	var disposition, requestID string
	if err := tx.QueryRowContext(ctx, "SELECT version,disposition,request_id FROM messages WHERE message_id=?", messageID).Scan(&version, &disposition, &requestID); err != nil || disposition != "steer_pending" {
		return
	}
	to, reason := "queued", "steer_fallback"
	if outcome == harnessadapter.SteerApplied {
		to, reason = "applied", "steer_applied"
		state.PendingCount--
		_, err = tx.ExecContext(ctx, "UPDATE requests SET version=version+1,status='completed',updated_at=? WHERE request_id=?", timestamp(node.config.Clock()), requestID)
	} else if outcome == harnessadapter.SteerUnknown {
		to, reason = "unknown", "steer_unknown"
		state.PendingCount--
		_, err = tx.ExecContext(ctx, "UPDATE requests SET version=version+1,status='unknown',updated_at=? WHERE request_id=?", timestamp(node.config.Clock()), requestID)
	}
	if err != nil {
		return
	}
	if _, err := tx.ExecContext(ctx, "UPDATE messages SET version=version+1,disposition=? WHERE message_id=?", to, messageID); err != nil {
		return
	}
	state.QueueVersion++
	state.StateVersion++
	if _, err := node.appendEvent(ctx, tx, &state, "message.disposition_changed", messageID, version+1, "", "", harnessprotocol.MessageDispositionPayload{MessageID: messageID, From: "steer_pending", To: to, ReasonCode: reason}, false); err != nil {
		return
	}
	if outcome == harnessadapter.SteerUnknown {
		if err := node.setAttemptUnknown(ctx, tx, &state, attempt, "provider_state", "unknown"); err != nil {
			return
		}
	}
	if err := node.appendQueueEvent(ctx, tx, &state); err != nil || saveState(ctx, tx, state) != nil {
		return
	}
	_ = tx.Commit()
}

func (node *Node) finishApproval(ctx context.Context, attempt harnessadapter.AttemptRef, actor string, payload actionPayload, outcome harnessadapter.ResponseOutcome) {
	node.finishResponse(ctx, attempt, outcome, func(tx *sql.Tx, state *durableState) error {
		status := "pending"
		if outcome == harnessadapter.ResponseApplied {
			status = "resolved"
		} else if outcome == harnessadapter.ResponseUnknown {
			status = "unknown"
		}
		if _, err := tx.ExecContext(ctx, "UPDATE approvals SET status=? WHERE approval_id=? AND version=?", status, payload.ApprovalID, payload.ApprovalVersion); err != nil {
			return err
		}
		if outcome == harnessadapter.ResponseApplied {
			_, err := node.appendEvent(ctx, tx, state, "approval.resolved", payload.ApprovalID, payload.ApprovalVersion, attempt.AttemptID, attempt.DialogID, harnessprotocol.ApprovalResolvedPayload{ApprovalID: payload.ApprovalID, Decision: payload.Decision, ActorID: harnessprotocol.ActorID(actor), ApprovalVersion: payload.ApprovalVersion}, false)
			return err
		}
		return nil
	})
}

func (node *Node) finishInput(ctx context.Context, attempt harnessadapter.AttemptRef, messageID string, payload actionPayload, outcome harnessadapter.ResponseOutcome) {
	node.finishResponse(ctx, attempt, outcome, func(tx *sql.Tx, state *durableState) error {
		status := "pending"
		if outcome == harnessadapter.ResponseApplied {
			status = "resolved"
		} else if outcome == harnessadapter.ResponseUnknown {
			status = "unknown"
		}
		if _, err := tx.ExecContext(ctx, "UPDATE input_requests SET status=? WHERE input_request_id=? AND version=?", status, payload.InputRequestID, payload.InputVersion); err != nil {
			return err
		}
		if outcome == harnessadapter.ResponseApplied {
			_, err := node.appendEvent(ctx, tx, state, "input.resolved", payload.InputRequestID, payload.InputVersion, attempt.AttemptID, attempt.DialogID, harnessprotocol.InputResolvedPayload{InputRequestID: payload.InputRequestID, MessageID: messageID, InputVersion: payload.InputVersion}, false)
			return err
		}
		return nil
	})
}

func (node *Node) finishResponse(ctx context.Context, attempt harnessadapter.AttemptRef, outcome harnessadapter.ResponseOutcome, mutate func(*sql.Tx, *durableState) error) {
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil || mutate(tx, &state) != nil {
		return
	}
	if outcome == harnessadapter.ResponseUnknown {
		if err := node.setAttemptUnknown(ctx, tx, &state, attempt, "provider_state", "unknown"); err != nil {
			return
		}
	}
	if saveState(ctx, tx, state) == nil {
		_ = tx.Commit()
	}
}
