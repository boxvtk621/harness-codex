package node

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

// CodexUnsupportedModelProof fences a single historical provider rejection.
// The native SHA pins the complete rollout, not merely its terminal message.
type CodexUnsupportedModelProof struct {
	Attempt                                                            harnessadapter.AttemptRef
	ExpectedEpoch, ExpectedStateVersion, ExpectedLastEventSeq          int64
	ExpectedAttemptVersion, ExpectedRequestVersion, ExpectedUnknownSeq int64
	ExpectedLateObservationID                                          int64
	ExpectedLateHash                                                   string
	ExpectedProcessGeneration                                          int64
	RolloutRelativePath, RolloutSHA256                                 string
}

type unsupportedModelNativeVerifier interface {
	ConfirmUnsupportedModelRejection(context.Context, harnessadapter.AttemptRef, string, string, int64) error
}

// RecoverCodexUnsupportedModel performs no provider call and no dispatch. A
// check validates every fence and rolls back; apply adds one terminal projection.
func (node *Node) RecoverCodexUnsupportedModel(ctx context.Context, proof CodexUnsupportedModelProof, check bool) error {
	if !node.recoveryOnly || proof.Attempt.NodeID != node.config.NodeID ||
		!uuidPattern.MatchString(proof.Attempt.DialogID) || !uuidPattern.MatchString(proof.Attempt.RequestID) ||
		!uuidPattern.MatchString(proof.Attempt.AttemptID) || proof.Attempt.Generation < 1 ||
		proof.ExpectedEpoch < 1 || proof.ExpectedStateVersion < 1 || proof.ExpectedLastEventSeq < 1 ||
		proof.ExpectedAttemptVersion < 1 || proof.ExpectedRequestVersion < 1 || proof.ExpectedUnknownSeq < 1 ||
		proof.ExpectedLateObservationID < 1 || !validLowerSHA256(proof.ExpectedLateHash) ||
		!validLowerSHA256(proof.RolloutSHA256) || proof.ExpectedProcessGeneration < 2 {
		return errors.New("Codex unsupported-model recovery proof is invalid")
	}
	verifier, ok := node.config.Adapter.(unsupportedModelNativeVerifier)
	if !ok {
		return errors.New("offline native rejection verifier is required")
	}
	if err := verifier.ConfirmUnsupportedModelRejection(ctx, proof.Attempt, proof.RolloutRelativePath, proof.RolloutSHA256, proof.ExpectedProcessGeneration); err != nil {
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
	if state.StateVersion == proof.ExpectedStateVersion+1 && state.LastEventSeq == proof.ExpectedLastEventSeq+2 {
		return node.verifyUnsupportedModelAlready(ctx, tx, state, proof)
	}
	if state.Epoch != proof.ExpectedEpoch || state.NodeID != proof.Attempt.NodeID || state.PendingCount != 0 ||
		state.StateVersion != proof.ExpectedStateVersion || state.LastEventSeq != proof.ExpectedLastEventSeq ||
		state.Occupancy != "unknown" || !state.ActiveAttemptID.Valid || state.ActiveAttemptID.String != proof.Attempt.AttemptID ||
		!slicesContains(state.BlockedReasons, "execution_unknown") {
		return errors.New("Codex unsupported-model node fence does not match")
	}
	var attemptVersion, requestVersion, outputBytes int64
	var attemptState, effectStatus, requestStatus string
	err = tx.QueryRowContext(ctx, `SELECT a.version,a.state,a.effect_status,a.output_bytes,r.version,r.status
		FROM attempts a JOIN requests r ON r.request_id=a.request_id
		WHERE a.attempt_id=? AND a.dialog_id=? AND a.request_id=? AND a.generation=?`,
		proof.Attempt.AttemptID, proof.Attempt.DialogID, proof.Attempt.RequestID, proof.Attempt.Generation).
		Scan(&attemptVersion, &attemptState, &effectStatus, &outputBytes, &requestVersion, &requestStatus)
	if err != nil {
		return err
	}
	if attemptVersion != proof.ExpectedAttemptVersion || requestVersion != proof.ExpectedRequestVersion ||
		attemptState != "unknown" || effectStatus != "unknown" || requestStatus != "unknown" || outputBytes != 0 {
		return errors.New("Codex unsupported-model attempt fence does not match")
	}
	var controls, otherControls, effects, assistantMessages, lateCount int64
	err = tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM control_actions WHERE attempt_id=? AND command_id=? AND kind=? AND status='acknowledged'),
		(SELECT COUNT(*) FROM control_actions WHERE attempt_id=? AND NOT(command_id=? AND kind=? AND status='acknowledged')),
		(SELECT COUNT(*) FROM tool_calls WHERE attempt_id=?) + (SELECT COUNT(*) FROM approvals WHERE attempt_id=?) +
		(SELECT COUNT(*) FROM input_requests WHERE attempt_id=?) + (SELECT COUNT(*) FROM artifacts WHERE attempt_id=?),
		(SELECT COUNT(*) FROM messages WHERE attempt_id=? AND role='assistant'),
		(SELECT COUNT(*) FROM late_observations WHERE attempt_id=?)`,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID, actionDispatchStart,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID, actionDispatchStart,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID, proof.Attempt.AttemptID, proof.Attempt.AttemptID,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID).Scan(&controls, &otherControls, &effects, &assistantMessages, &lateCount)
	if err != nil {
		return err
	}
	if controls != 1 || otherControls != 0 || effects != 0 || assistantMessages != 0 || lateCount != 1 {
		return errors.New("Codex unsupported-model durable effects do not match")
	}
	var lateGeneration, lateSeq, lateOutputBytes int64
	var lateKind, lateKey, lateHash string
	var lateJSON []byte
	err = tx.QueryRowContext(ctx, `SELECT generation,kind,observation_json,event_seq,projection_key,projection_hash,output_bytes
		FROM late_observations WHERE attempt_id=? AND observation_id=?`, proof.Attempt.AttemptID, proof.ExpectedLateObservationID).
		Scan(&lateGeneration, &lateKind, &lateJSON, &lateSeq, &lateKey, &lateHash, &lateOutputBytes)
	if err != nil {
		return err
	}
	var late harnessadapter.TerminalEvent
	if json.Unmarshal(lateJSON, &late) != nil || lateGeneration != proof.Attempt.Generation || lateKind != "terminal_while_steer_unresolved" ||
		lateSeq != proof.ExpectedLastEventSeq || lateKey != "archive:terminal" || lateHash != proof.ExpectedLateHash ||
		lateOutputBytes != 17 || late.Attempt != proof.Attempt || late.Outcome != harnessadapter.ReconcileFailed ||
		late.EffectStatus != "unknown" || late.Output != nil || late.Usage != nil || late.Failure == nil ||
		late.Failure.Class != harnessadapter.FailureTask || late.Failure.Code != "codex_turn_failed" ||
		late.Failure.SafeMessage != "codex turn failed" || late.Failure.Retryable {
		return errors.New("Codex unsupported-model archived terminal does not match")
	}
	projection, _, err := node.prepareLateProjection(late, proof.ExpectedAttemptVersion)
	if err != nil {
		return err
	}
	digest, err := adapterProjectionDigest(projection)
	if err != nil || digest != lateHash {
		return errors.New("Codex unsupported-model archived projection hash does not match")
	}
	rows, err := tx.QueryContext(ctx, `SELECT event_json FROM events WHERE attempt_id=? ORDER BY seq`, proof.Attempt.AttemptID)
	if err != nil {
		return err
	}
	var dispatching, started, unknown int
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			rows.Close()
			return err
		}
		event, err := harnessprotocol.DecodeEvent(encoded)
		if err != nil || event.Envelope.AttemptID != proof.Attempt.AttemptID || event.Envelope.DialogID != proof.Attempt.DialogID || event.Envelope.Epoch != proof.ExpectedEpoch {
			rows.Close()
			return errors.New("Codex unsupported-model event binding is invalid")
		}
		switch payload := event.Payload.(type) {
		case *harnessprotocol.AttemptDispatchingPayload:
			if payload.RequestID != proof.Attempt.RequestID || payload.Generation != proof.Attempt.Generation {
				rows.Close()
				return errors.New("dispatch event does not match")
			}
			dispatching++
		case *harnessprotocol.AttemptStartedPayload:
			if payload.RequestID != proof.Attempt.RequestID || payload.Generation != proof.Attempt.Generation {
				rows.Close()
				return errors.New("started event does not match")
			}
			started++
		case *harnessprotocol.AttemptUnknownPayload:
			if event.Envelope.Seq != proof.ExpectedUnknownSeq || payload.Generation != proof.Attempt.Generation || payload.Reason != "provider_state" || payload.EffectStatus != "unknown" {
				rows.Close()
				return errors.New("unknown event does not match")
			}
			unknown++
		default:
			rows.Close()
			return errors.New("Codex unsupported-model attempt has other activity")
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if dispatching != 1 || started != 1 || unknown != 1 || proof.ExpectedUnknownSeq >= proof.ExpectedLastEventSeq {
		return errors.New("Codex unsupported-model event sequence is incomplete")
	}
	if unresolved, err := unresolvedReconciliationEffects(ctx, tx, proof.Attempt.AttemptID); err != nil {
		return err
	} else if unresolved {
		return errors.New("Codex unsupported-model has unresolved effects")
	}
	if check {
		return nil
	}
	failure := &harnessadapter.Failure{Class: harnessadapter.FailureTask, Code: "codex_model_unsupported",
		SafeMessage: "The configured Codex model is not supported by this ChatGPT account. Select an available model before retrying.", Retryable: false}
	terminal, _, err := node.projectAdapterEvent(ctx, tx, nil, &state, proof.Attempt, proof.ExpectedAttemptVersion, "unknown", harnessadapter.TerminalEvent{
		EventBase: harnessadapter.EventBase{Attempt: proof.Attempt}, Outcome: harnessadapter.ReconcileFailed,
		Failure: failure, EffectStatus: "none",
	})
	if err != nil {
		return err
	}
	if !terminal {
		return errors.New("Codex unsupported-model terminal projection was not produced")
	}
	if err := saveState(ctx, tx, state); err != nil {
		return err
	}
	return tx.Commit()
}

func (node *Node) verifyUnsupportedModelAlready(ctx context.Context, tx *sql.Tx, state durableState, proof CodexUnsupportedModelProof) error {
	if state.NodeID != proof.Attempt.NodeID || state.Epoch != proof.ExpectedEpoch || state.PendingCount != 0 ||
		state.Occupancy != "idle" || state.ActiveAttemptID.Valid || slicesContains(state.BlockedReasons, "execution_unknown") {
		return errors.New("Codex unsupported-model replay node fence does not match")
	}
	var attemptVersion, requestVersion, outputBytes int64
	var attemptState, effectStatus, requestStatus string
	if err := tx.QueryRowContext(ctx, `SELECT a.version,a.state,a.effect_status,a.output_bytes,r.version,r.status
		FROM attempts a JOIN requests r ON r.request_id=a.request_id
		WHERE a.attempt_id=? AND a.dialog_id=? AND a.request_id=? AND a.generation=?`,
		proof.Attempt.AttemptID, proof.Attempt.DialogID, proof.Attempt.RequestID, proof.Attempt.Generation).
		Scan(&attemptVersion, &attemptState, &effectStatus, &outputBytes, &requestVersion, &requestStatus); err != nil {
		return err
	}
	if attemptVersion != proof.ExpectedAttemptVersion+1 || requestVersion != proof.ExpectedRequestVersion+1 ||
		attemptState != "failed" || effectStatus != "none" || requestStatus != "failed" || outputBytes != 0 {
		return errors.New("Codex unsupported-model replay attempt fence does not match")
	}
	var controls, otherControls, effects, assistantMessages, lateCount, matchingLate int64
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM control_actions WHERE attempt_id=? AND command_id=? AND kind=? AND status='acknowledged'),
		(SELECT COUNT(*) FROM control_actions WHERE attempt_id=? AND NOT(command_id=? AND kind=? AND status='acknowledged')),
		(SELECT COUNT(*) FROM tool_calls WHERE attempt_id=?) + (SELECT COUNT(*) FROM approvals WHERE attempt_id=?) +
		(SELECT COUNT(*) FROM input_requests WHERE attempt_id=?) + (SELECT COUNT(*) FROM artifacts WHERE attempt_id=?),
		(SELECT COUNT(*) FROM messages WHERE attempt_id=? AND role='assistant'),
		(SELECT COUNT(*) FROM late_observations WHERE attempt_id=?),
		(SELECT COUNT(*) FROM late_observations WHERE attempt_id=? AND observation_id=? AND generation=? AND kind='terminal_while_steer_unresolved' AND event_seq=? AND projection_key='archive:terminal' AND projection_hash=?)`,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID, actionDispatchStart,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID, actionDispatchStart,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID, proof.Attempt.AttemptID, proof.Attempt.AttemptID,
		proof.Attempt.AttemptID, proof.Attempt.AttemptID, proof.Attempt.AttemptID, proof.ExpectedLateObservationID,
		proof.Attempt.Generation, proof.ExpectedLastEventSeq, proof.ExpectedLateHash).
		Scan(&controls, &otherControls, &effects, &assistantMessages, &lateCount, &matchingLate); err != nil {
		return err
	}
	if controls != 1 || otherControls != 0 || effects != 0 || assistantMessages != 0 || lateCount != 1 || matchingLate != 1 {
		return errors.New("Codex unsupported-model replay effect fence does not match")
	}
	var lateJSON []byte
	var lateOutputBytes int64
	if err := tx.QueryRowContext(ctx, `SELECT observation_json,output_bytes FROM late_observations WHERE observation_id=? AND attempt_id=?`,
		proof.ExpectedLateObservationID, proof.Attempt.AttemptID).Scan(&lateJSON, &lateOutputBytes); err != nil {
		return err
	}
	var late harnessadapter.TerminalEvent
	if json.Unmarshal(lateJSON, &late) != nil || lateOutputBytes != 17 || late.Attempt != proof.Attempt ||
		late.Outcome != harnessadapter.ReconcileFailed || late.EffectStatus != "unknown" || late.Output != nil || late.Usage != nil ||
		late.Failure == nil || late.Failure.Class != harnessadapter.FailureTask || late.Failure.Code != "codex_turn_failed" ||
		late.Failure.SafeMessage != "codex turn failed" || late.Failure.Retryable {
		return errors.New("Codex unsupported-model replay archived terminal does not match")
	}
	lateProjection, _, err := node.prepareLateProjection(late, proof.ExpectedAttemptVersion)
	if err != nil {
		return err
	}
	lateDigest, err := adapterProjectionDigest(lateProjection)
	if err != nil || lateDigest != proof.ExpectedLateHash {
		return errors.New("Codex unsupported-model replay archived hash does not match")
	}
	for offset, expectedType := range []string{"attempt.failed", "node.state_changed"} {
		var encoded []byte
		if err := tx.QueryRowContext(ctx, `SELECT event_json FROM events WHERE node_id=? AND seq=?`,
			proof.Attempt.NodeID, proof.ExpectedLastEventSeq+int64(offset)+1).Scan(&encoded); err != nil {
			return err
		}
		event, err := harnessprotocol.DecodeEvent(encoded)
		if err != nil || event.Envelope.Type != expectedType || event.Envelope.Epoch != proof.ExpectedEpoch {
			return errors.New("Codex unsupported-model replay event fence does not match")
		}
		if offset == 0 {
			payload, ok := event.Payload.(*harnessprotocol.AttemptFailedPayload)
			if !ok || event.Envelope.AttemptID != proof.Attempt.AttemptID || event.Envelope.DialogID != proof.Attempt.DialogID ||
				payload.Generation != proof.Attempt.Generation || payload.FailureClass != "task" || payload.ErrorCode != "codex_model_unsupported" ||
				payload.SafeMessage != "The configured Codex model is not supported by this ChatGPT account. Select an available model before retrying." ||
				payload.Retryable || payload.EffectStatus != "none" {
				return errors.New("Codex unsupported-model replay failure does not match")
			}
		}
	}
	return nil
}
