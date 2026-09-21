package node

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

// ReconcileUnknown is an in-process host operation. It has no browser/HTTP
// route. The adapter call runs outside node.mu and a terminal result is applied
// only after an exact durable scope/fence check and unresolved-effect guard.
func (node *Node) ReconcileUnknown(ctx context.Context, reference harnessadapter.AttemptRef) (harnessadapter.ReconcileResult, error) {
	if err := node.verifyUnknownReference(ctx, reference); err != nil {
		return harnessadapter.ReconcileResult{}, err
	}
	result, err := node.config.Adapter.Reconcile(ctx, harnessadapter.ReconcileInput{Attempt: reference})
	result = cloneReconcileResult(result)
	if err != nil {
		return result, err
	}
	switch result.Outcome {
	case harnessadapter.ReconcileRunning, harnessadapter.ReconcileWaitingInput, harnessadapter.ReconcileUnknown:
		// These observations confirm no terminal boundary. The durable unknown
		// fence and active slot intentionally remain unchanged.
		return result, nil
	case harnessadapter.ReconcileCompleted, harnessadapter.ReconcileFailed, harnessadapter.ReconcileInterrupted:
		if result.EffectStatus != "known" && result.EffectStatus != "none" {
			return result, errors.New("terminal reconciliation did not prove an effect status")
		}
		return result, node.applyReconciledTerminal(ctx, reference, result)
	default:
		return result, errors.New("adapter returned an invalid reconciliation outcome")
	}
}

func (node *Node) verifyUnknownReference(ctx context.Context, reference harnessadapter.AttemptRef) error {
	if reference.NodeID != node.config.NodeID || !uuidPattern.MatchString(reference.DialogID) || !uuidPattern.MatchString(reference.RequestID) || !uuidPattern.MatchString(reference.AttemptID) || reference.Generation < 1 {
		return errors.New("reconciliation attempt reference is invalid")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	state, err := loadState(ctx, node.db)
	if err != nil {
		return err
	}
	return verifyActiveUnknown(ctx, node.db, state, reference)
}

func verifyActiveUnknown(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, state durableState, reference harnessadapter.AttemptRef) error {
	if !state.ActiveAttemptID.Valid || state.ActiveAttemptID.String != reference.AttemptID {
		return errors.New("reconciliation attempt is not the active slot")
	}
	var actual harnessadapter.AttemptRef
	var attemptState string
	actual.NodeID = state.NodeID
	if err := query.QueryRowContext(ctx, `SELECT dialog_id,request_id,attempt_id,generation,state FROM attempts WHERE attempt_id=?`, reference.AttemptID).Scan(&actual.DialogID, &actual.RequestID, &actual.AttemptID, &actual.Generation, &attemptState); err != nil {
		return err
	}
	if actual != reference || attemptState != "unknown" {
		return errors.New("reconciliation attempt fence changed")
	}
	return nil
}

func (node *Node) applyReconciledTerminal(ctx context.Context, reference harnessadapter.AttemptRef, result harnessadapter.ReconcileResult) (resultErr error) {
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	publication := newSafeTextPublication(node)
	defer func() {
		resultErr = errors.Join(resultErr, publication.cleanupKnownRollback())
	}()
	state, err := loadState(ctx, tx)
	if err != nil {
		return err
	}
	if err := verifyActiveUnknown(ctx, tx, state, reference); err != nil {
		return err
	}
	unresolved, err := unresolvedReconciliationEffects(ctx, tx, reference.AttemptID)
	if err != nil {
		return err
	}
	if unresolved {
		return errors.New("reconciliation has unresolved control or effect outcomes")
	}
	var version int64
	if err := tx.QueryRowContext(ctx, "SELECT version FROM attempts WHERE attempt_id=?", reference.AttemptID).Scan(&version); err != nil {
		return err
	}
	if err := node.ensureReconciledAssistantMessage(ctx, tx, publication, &state, reference, version, result); err != nil {
		return err
	}
	event := harnessadapter.TerminalEvent{
		EventBase:    harnessadapter.EventBase{Attempt: reference},
		Outcome:      result.Outcome,
		Output:       result.Output,
		Usage:        result.Usage,
		Failure:      result.Failure,
		EffectStatus: result.EffectStatus,
	}
	terminal, wake, err := node.projectAdapterEvent(ctx, tx, publication, &state, reference, version, "unknown", event)
	if err != nil {
		return err
	}
	if !terminal {
		return errors.New("reconciliation did not produce a terminal projection")
	}
	if err := saveState(ctx, tx, state); err != nil {
		return err
	}
	if err := node.checkFault(FaultBeforeCommit); err != nil {
		return err
	}
	publication.retainForCommit()
	if err := tx.Commit(); err != nil {
		return err
	}
	node.cancelAttemptStream(reference)
	if wake || terminal {
		node.afterCommit(context.Background(), postCommitAction{})
	}
	return nil
}

func (node *Node) ensureReconciledAssistantMessage(ctx context.Context, tx *sql.Tx, publication *safeTextPublication, state *durableState, reference harnessadapter.AttemptRef, attemptVersion int64, result harnessadapter.ReconcileResult) error {
	if result.Outcome != harnessadapter.ReconcileCompleted || result.Output == nil {
		return nil
	}
	var encoded []byte
	err := tx.QueryRowContext(ctx, `SELECT content_json FROM messages WHERE attempt_id=? AND role='assistant' ORDER BY sequence DESC LIMIT 1`, reference.AttemptID).Scan(&encoded)
	if err == nil {
		var stored harnessprotocol.SafeContent
		if err := json.Unmarshal(encoded, &stored); err != nil {
			return errors.New("durable assistant content is invalid")
		}
		if safeContentEqual(stored, *result.Output) {
			return nil
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	messageID, err := node.newID()
	if err != nil {
		return err
	}
	terminal, _, err := node.projectAdapterEvent(ctx, tx, publication, state, reference, attemptVersion, "unknown", harnessadapter.AssistantMessageEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: messageID, Content: *result.Output, FinishReason: "complete",
	})
	if err != nil {
		return err
	}
	if terminal {
		return errors.New("reconciled assistant output produced a terminal projection")
	}
	return nil
}

func unresolvedReconciliationEffects(ctx context.Context, tx *sql.Tx, attemptID string) (bool, error) {
	var count int
	err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM control_actions WHERE attempt_id=? AND kind IN(?,?,?) AND status IN('pending','inflight','unknown')) +
		(SELECT COUNT(*) FROM tool_calls WHERE attempt_id=? AND status='running') +
		(SELECT COUNT(*) FROM approvals WHERE attempt_id=? AND status IN('pending','responding','unknown')) +
		(SELECT COUNT(*) FROM input_requests WHERE attempt_id=? AND status IN('pending','responding','unknown')) +
		(SELECT COUNT(*) FROM events WHERE attempt_id=? AND projection_key LIKE 'tool.completed:%'
			AND json_extract(CAST(event_json AS TEXT),'$.payload.effectStatus')='unknown')`,
		attemptID, string(harnessprotocol.CommandMessageSteer), string(harnessprotocol.CommandApprovalRespond), string(harnessprotocol.CommandInputRespond),
		attemptID, attemptID, attemptID, attemptID).Scan(&count)
	return count > 0, err
}

func cloneReconcileResult(result harnessadapter.ReconcileResult) harnessadapter.ReconcileResult {
	if result.Output != nil {
		output := *result.Output
		if output.SizeBytes != nil {
			size := *output.SizeBytes
			output.SizeBytes = &size
		}
		result.Output = &output
	}
	if result.Usage != nil {
		usage := *result.Usage
		result.Usage = &usage
	}
	if result.Failure != nil {
		failure := *result.Failure
		result.Failure = &failure
	}
	return result
}
