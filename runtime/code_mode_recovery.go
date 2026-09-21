package node

import (
	"context"
	"database/sql"
	"errors"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

// CodexCodeModeDelegationProof identifies the exact no-effect state produced
// when Codex Code Mode delegated a dynamic tool before item/started. This is a
// bounded repair for the historical adapter ordering defect, not a general
// unknown-state override.
type CodexCodeModeDelegationProof struct {
	Attempt                harnessadapter.AttemptRef
	ExpectedAttemptVersion int64
	ExpectedUnknownSeq     int64
	ExpectedDeltaCount     int64
	AssistantMessageID     string
}

// RecoverCodexCodeModeDelegation marks the exactly proven historical attempt
// failed with no effects so the operator can retry it on the corrected adapter.
func (node *Node) RecoverCodexCodeModeDelegation(ctx context.Context, proof CodexCodeModeDelegationProof) error {
	if err := validateCodexCodeModeDelegationProof(node.config.NodeID, proof); err != nil {
		return err
	}
	verifier, ok := node.config.Adapter.(priorTerminalVerifier)
	if !ok {
		return errors.New("adapter does not support Codex Code Mode recovery")
	}
	if err := verifier.ConfirmPriorTerminal(ctx, proof.Attempt); err != nil {
		return err
	}

	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return err
	}
	already, err := verifyCodexCodeModeDelegation(ctx, tx, state, proof)
	if err != nil || already {
		return err
	}
	if unresolved, err := unresolvedReconciliationEffects(ctx, tx, proof.Attempt.AttemptID); err != nil {
		return err
	} else if unresolved {
		return errors.New("Codex Code Mode recovery has unresolved effects")
	}
	failure := &harnessadapter.Failure{
		Class: harnessadapter.FailureTask, Code: "codex_code_mode_delegation",
		SafeMessage: "Codex tool delegation used an unsupported event order", Retryable: true,
	}
	terminal, wake, err := node.projectAdapterEvent(ctx, tx, nil, &state, proof.Attempt,
		proof.ExpectedAttemptVersion, "unknown", harnessadapter.TerminalEvent{
			EventBase: harnessadapter.EventBase{Attempt: proof.Attempt},
			Outcome:   harnessadapter.ReconcileFailed, Failure: failure, EffectStatus: "none",
		})
	if err != nil {
		return err
	}
	if !terminal {
		return errors.New("Codex Code Mode recovery did not produce a terminal projection")
	}
	if err := saveState(ctx, tx, state); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	node.cancelAttemptStream(proof.Attempt)
	if terminal || wake {
		node.afterCommit(context.Background(), postCommitAction{})
	}
	return nil
}

func validateCodexCodeModeDelegationProof(nodeID string, proof CodexCodeModeDelegationProof) error {
	if proof.Attempt.NodeID != nodeID || !uuidPattern.MatchString(proof.Attempt.DialogID) ||
		!uuidPattern.MatchString(proof.Attempt.RequestID) || !uuidPattern.MatchString(proof.Attempt.AttemptID) ||
		proof.Attempt.Generation < 1 || proof.ExpectedAttemptVersion < 1 || proof.ExpectedUnknownSeq < 1 ||
		proof.ExpectedDeltaCount < 1 || proof.ExpectedDeltaCount > 1024 || !uuidPattern.MatchString(proof.AssistantMessageID) {
		return errors.New("Codex Code Mode recovery proof is invalid")
	}
	return nil
}

func verifyCodexCodeModeDelegation(ctx context.Context, tx *sql.Tx, state durableState, proof CodexCodeModeDelegationProof) (bool, error) {
	var attemptVersion int64
	var attemptState, effectStatus, requestStatus string
	if err := tx.QueryRowContext(ctx, `SELECT a.version,a.state,a.effect_status,r.status
		FROM attempts a JOIN requests r ON r.request_id=a.request_id
		WHERE a.attempt_id=? AND a.dialog_id=? AND a.request_id=? AND a.generation=?`,
		proof.Attempt.AttemptID, proof.Attempt.DialogID, proof.Attempt.RequestID,
		proof.Attempt.Generation).Scan(&attemptVersion, &attemptState, &effectStatus, &requestStatus); err != nil {
		return false, err
	}
	already := attemptVersion == proof.ExpectedAttemptVersion+1 && attemptState == "failed" &&
		effectStatus == "none" && requestStatus == "failed" && !state.ActiveAttemptID.Valid &&
		!slicesContains(state.BlockedReasons, "execution_unknown")
	pending := attemptVersion == proof.ExpectedAttemptVersion && attemptState == "unknown" &&
		effectStatus == "unknown" && requestStatus == "unknown" && state.ActiveAttemptID.Valid &&
		state.ActiveAttemptID.String == proof.Attempt.AttemptID && state.PendingCount == 0 &&
		slicesContains(state.BlockedReasons, "execution_unknown")
	if !pending && !already {
		return false, errors.New("Codex Code Mode attempt fence does not match")
	}

	var toolCalls, approvals, inputs, artifacts, late, assistantMessages int64
	var assistantMessageID string
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM tool_calls WHERE attempt_id=?),
		(SELECT COUNT(*) FROM approvals WHERE attempt_id=?),
		(SELECT COUNT(*) FROM input_requests WHERE attempt_id=?),
		(SELECT COUNT(*) FROM artifacts WHERE attempt_id=? AND disposition!='transcript_internal'),
		(SELECT COUNT(*) FROM late_observations WHERE attempt_id=?),
		(SELECT COUNT(*) FROM messages WHERE attempt_id=? AND role='assistant'),
		COALESCE((SELECT MAX(message_id) FROM messages WHERE attempt_id=? AND role='assistant'),'')`,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID, proof.Attempt.AttemptID,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID, proof.Attempt.AttemptID,
		proof.Attempt.AttemptID).Scan(&toolCalls, &approvals, &inputs, &artifacts, &late,
		&assistantMessages, &assistantMessageID); err != nil {
		return false, err
	}
	if toolCalls != 0 || approvals != 0 || inputs != 0 || artifacts != 0 || late != 0 ||
		assistantMessages != 1 || assistantMessageID != proof.AssistantMessageID {
		return false, errors.New("Codex Code Mode durable effect evidence does not match")
	}

	var dispatchActions, conflicting int64
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM control_actions WHERE attempt_id=? AND command_id=? AND kind=? AND status='acknowledged'),
		(SELECT COUNT(*) FROM control_actions WHERE attempt_id=? AND NOT(command_id=? AND kind=? AND status='acknowledged'))`,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID, actionDispatchStart,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID, actionDispatchStart).Scan(&dispatchActions, &conflicting); err != nil {
		return false, err
	}
	if dispatchActions != 1 || conflicting != 0 {
		return false, errors.New("Codex Code Mode dispatch evidence does not match")
	}
	if err := verifyCodexCodeModeDelegationEvents(ctx, tx, proof, already); err != nil {
		return false, err
	}
	return already, nil
}

func verifyCodexCodeModeDelegationEvents(ctx context.Context, tx *sql.Tx, proof CodexCodeModeDelegationProof, already bool) error {
	rows, err := tx.QueryContext(ctx, `SELECT event_json FROM events WHERE attempt_id=? ORDER BY seq`, proof.Attempt.AttemptID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var dispatching, started, assistant, unknown, failed int64
	var deltaCount, startedSeq, lastDeltaSeq, assistantSeq int64
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return err
		}
		event, err := harnessprotocol.DecodeEvent(encoded)
		if err != nil || event.Envelope.AttemptID != proof.Attempt.AttemptID ||
			event.Envelope.DialogID != proof.Attempt.DialogID {
			return errors.New("Codex Code Mode event evidence is invalid")
		}
		switch payload := event.Payload.(type) {
		case *harnessprotocol.AttemptDispatchingPayload:
			dispatching++
		case *harnessprotocol.AttemptStartedPayload:
			started++
			startedSeq = event.Envelope.Seq
		case *harnessprotocol.AssistantDeltaPayload:
			if payload.MessageID != proof.AssistantMessageID || payload.Content.Kind != "inline" ||
				payload.Content.Truncated || payload.DeltaIndex != deltaCount {
				return errors.New("Codex Code Mode delta sequence does not match")
			}
			deltaCount++
			lastDeltaSeq = event.Envelope.Seq
		case *harnessprotocol.AssistantMessagePayload:
			if payload.MessageID != proof.AssistantMessageID || payload.FinishReason != "complete" ||
				payload.Content.Kind != "inline" || payload.Content.Truncated {
				return errors.New("Codex Code Mode assistant message does not match")
			}
			assistant++
			assistantSeq = event.Envelope.Seq
		case *harnessprotocol.AttemptUnknownPayload:
			if event.Envelope.Seq != proof.ExpectedUnknownSeq || payload.Generation != proof.Attempt.Generation ||
				payload.Reason != "adapter_protocol" || payload.EffectStatus != "unknown" {
				return errors.New("Codex Code Mode unknown event does not match")
			}
			unknown++
		case *harnessprotocol.AttemptFailedPayload:
			if !already || payload.Generation != proof.Attempt.Generation || payload.FailureClass != "task" ||
				payload.ErrorCode != "codex_code_mode_delegation" || !payload.Retryable || payload.EffectStatus != "none" {
				return errors.New("Codex Code Mode terminal event does not match")
			}
			failed++
		default:
			return errors.New("Codex Code Mode recovery has an unexpected event")
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	expectedFailed := int64(0)
	if already {
		expectedFailed = 1
	}
	if dispatching != 1 || started != 1 || assistant != 1 || unknown != 1 || failed != expectedFailed ||
		deltaCount != proof.ExpectedDeltaCount || startedSeq >= lastDeltaSeq || lastDeltaSeq >= assistantSeq ||
		assistantSeq >= proof.ExpectedUnknownSeq {
		return errors.New("Codex Code Mode event counts do not match")
	}
	return nil
}
