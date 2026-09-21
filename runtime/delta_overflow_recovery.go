package node

import (
	"context"
	"database/sql"
	"errors"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

// minimumCodexOverflowDeltas is the exact historical queue bound whose
// character-sized Codex deltas could fence an otherwise terminal attempt.
const minimumCodexOverflowDeltas int64 = 1024

// CodexDeltaOverflowProof identifies one historical no-effect attempt that
// overflowed the Codex adapter event queue. It is intentionally not a general
// unknown-state override.
type CodexDeltaOverflowProof struct {
	Attempt                harnessadapter.AttemptRef
	ExpectedAttemptVersion int64
	ExpectedUnknownSeq     int64
	ExpectedDeltaCount     int64
	CallID                 string
	ExpectedToolVersion    int64
	ActionHash             string
}

type priorTerminalVerifier interface {
	ConfirmPriorTerminal(context.Context, harnessadapter.AttemptRef) error
}

// RecoverCodexDeltaOverflow marks the exact historical attempt failed with no
// effects, allowing an explicit retry. The provider must prove a prior terminal
// turn, while the transaction independently proves one completed no-effect
// tool, a contiguous fine-grained delta stream, and no unresolved interaction.
func (node *Node) RecoverCodexDeltaOverflow(ctx context.Context, proof CodexDeltaOverflowProof) error {
	if err := validateCodexDeltaOverflowProof(node.config.NodeID, proof); err != nil {
		return err
	}
	verifier, ok := node.config.Adapter.(priorTerminalVerifier)
	if !ok {
		return errors.New("adapter does not support Codex delta overflow recovery")
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
	already, err := verifyCodexDeltaOverflow(ctx, tx, state, proof)
	if err != nil || already {
		return err
	}
	if unresolved, err := unresolvedReconciliationEffects(ctx, tx, proof.Attempt.AttemptID); err != nil {
		return err
	} else if unresolved {
		return errors.New("Codex delta overflow recovery has unresolved effects")
	}
	failure := &harnessadapter.Failure{
		Class: harnessadapter.FailureTask, Code: "codex_delta_overflow",
		SafeMessage: "Codex response exceeded the adapter event queue", Retryable: true,
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
		return errors.New("Codex delta overflow recovery did not produce a terminal projection")
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

func validateCodexDeltaOverflowProof(nodeID string, proof CodexDeltaOverflowProof) error {
	if proof.Attempt.NodeID != nodeID || !uuidPattern.MatchString(proof.Attempt.DialogID) ||
		!uuidPattern.MatchString(proof.Attempt.RequestID) || !uuidPattern.MatchString(proof.Attempt.AttemptID) ||
		proof.Attempt.Generation < 1 || proof.ExpectedAttemptVersion < 1 ||
		proof.ExpectedUnknownSeq < 1 || proof.ExpectedDeltaCount < minimumCodexOverflowDeltas ||
		!uuidPattern.MatchString(proof.CallID) || proof.ExpectedToolVersion < 2 ||
		!validLowerSHA256(proof.ActionHash) {
		return errors.New("Codex delta overflow proof is invalid")
	}
	return nil
}

func verifyCodexDeltaOverflow(ctx context.Context, tx *sql.Tx, state durableState, proof CodexDeltaOverflowProof) (bool, error) {
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
		return false, errors.New("Codex delta overflow attempt fence does not match")
	}

	var toolCount, toolVersion int64
	var toolStatus, toolHash string
	var effectRef sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),MAX(version),MAX(status),MAX(action_hash),MAX(effect_ref)
		FROM tool_calls WHERE attempt_id=?`, proof.Attempt.AttemptID).Scan(
		&toolCount, &toolVersion, &toolStatus, &toolHash, &effectRef); err != nil {
		return false, err
	}
	var observedCallID string
	if toolCount == 1 {
		if err := tx.QueryRowContext(ctx, `SELECT call_id FROM tool_calls WHERE attempt_id=?`,
			proof.Attempt.AttemptID).Scan(&observedCallID); err != nil {
			return false, err
		}
	}
	if toolCount != 1 || observedCallID != proof.CallID || toolVersion != proof.ExpectedToolVersion ||
		toolStatus != "failed" || toolHash != proof.ActionHash || effectRef.Valid {
		return false, errors.New("Codex delta overflow tool evidence does not match")
	}

	var dispatchActions, conflicting int64
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM control_actions WHERE attempt_id=? AND command_id=? AND kind=? AND status='acknowledged'),
		(SELECT COUNT(*) FROM control_actions WHERE attempt_id=? AND NOT(command_id=? AND kind=? AND status='acknowledged')) +
		(SELECT COUNT(*) FROM approvals WHERE attempt_id=?) +
		(SELECT COUNT(*) FROM input_requests WHERE attempt_id=?) +
		(SELECT COUNT(*) FROM artifacts WHERE attempt_id=? AND disposition!='transcript_internal') +
		(SELECT COUNT(*) FROM late_observations WHERE attempt_id=?) +
		(SELECT COUNT(*) FROM messages WHERE attempt_id=? AND role='assistant')`,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID, actionDispatchStart,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID, actionDispatchStart,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID, proof.Attempt.AttemptID).Scan(&dispatchActions, &conflicting); err != nil {
		return false, err
	}
	if dispatchActions != 1 || conflicting != 0 {
		return false, errors.New("Codex delta overflow has conflicting durable records")
	}
	if err := verifyCodexDeltaOverflowEvents(ctx, tx, proof, already); err != nil {
		return false, err
	}
	return already, nil
}

func verifyCodexDeltaOverflowEvents(ctx context.Context, tx *sql.Tx, proof CodexDeltaOverflowProof, already bool) error {
	rows, err := tx.QueryContext(ctx, `SELECT event_json FROM events WHERE attempt_id=? ORDER BY seq`, proof.Attempt.AttemptID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var dispatching, started, toolStarted, toolOutput, toolCompleted, unknown, failed int64
	var deltaCount, lastDeltaSeq int64
	var deltaMessageID string
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return err
		}
		event, err := harnessprotocol.DecodeEvent(encoded)
		if err != nil || event.Envelope.AttemptID != proof.Attempt.AttemptID ||
			event.Envelope.DialogID != proof.Attempt.DialogID {
			return errors.New("Codex delta overflow event evidence is invalid")
		}
		switch payload := event.Payload.(type) {
		case *harnessprotocol.AttemptDispatchingPayload:
			dispatching++
		case *harnessprotocol.AttemptStartedPayload:
			started++
		case *harnessprotocol.ToolStartedPayload:
			if payload.CallID != proof.CallID || payload.ActionHash != proof.ActionHash {
				return errors.New("Codex delta overflow tool start does not match")
			}
			toolStarted++
		case *harnessprotocol.ToolOutputPayload:
			if payload.CallID != proof.CallID {
				return errors.New("Codex delta overflow tool output does not match")
			}
			toolOutput++
		case *harnessprotocol.ToolCompletedPayload:
			if payload.CallID != proof.CallID || payload.Status != "failed" ||
				payload.EffectStatus != "none" || payload.EffectRef != "" {
				return errors.New("Codex delta overflow tool completion does not match")
			}
			toolCompleted++
		case *harnessprotocol.AssistantDeltaPayload:
			if payload.Content.Kind != "inline" || payload.Content.Truncated ||
				(deltaMessageID != "" && payload.MessageID != deltaMessageID) ||
				payload.DeltaIndex != deltaCount {
				return errors.New("Codex delta overflow delta sequence does not match")
			}
			deltaMessageID = payload.MessageID
			deltaCount++
			lastDeltaSeq = event.Envelope.Seq
		case *harnessprotocol.AttemptUnknownPayload:
			if event.Envelope.Seq != proof.ExpectedUnknownSeq || payload.Generation != proof.Attempt.Generation ||
				payload.Reason != "adapter_protocol" || payload.EffectStatus != "unknown" {
				return errors.New("Codex delta overflow unknown event does not match")
			}
			unknown++
		case *harnessprotocol.AttemptFailedPayload:
			if !already || payload.Generation != proof.Attempt.Generation || payload.FailureClass != "task" ||
				payload.ErrorCode != "codex_delta_overflow" || !payload.Retryable || payload.EffectStatus != "none" {
				return errors.New("Codex delta overflow terminal event does not match")
			}
			failed++
		default:
			return errors.New("Codex delta overflow has an unexpected event")
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	expectedFailed := int64(0)
	if already {
		expectedFailed = 1
	}
	if dispatching != 1 || started != 1 || toolStarted != 1 || toolOutput != 1 || toolCompleted != 1 ||
		unknown != 1 || failed != expectedFailed || deltaCount != proof.ExpectedDeltaCount ||
		deltaMessageID == "" || lastDeltaSeq >= proof.ExpectedUnknownSeq {
		return errors.New("Codex delta overflow event counts do not match")
	}
	return nil
}
