package node

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

// failedTailProof never infers absence of effects from native mappings. The
// SQLite ledger must prove every native-started attempt at or after the input
// was rejected for the unsupported model, with no output or effects. A prior
// successful retry below this input is deliberately outside this scope.
func failedTailProof(ctx context.Context, tx *sql.Tx, dialogID, messageID string) (*harnessadapter.FailedTailRetry, error) {
	rows, err := tx.QueryContext(ctx, `SELECT a.node_id,a.dialog_id,a.request_id,a.attempt_id,a.generation,
		m.message_id,m.sequence,m.text,a.policy_hash,a.state,a.effect_status,a.output_bytes,
		(SELECT COUNT(*) FROM messages WHERE attempt_id=a.attempt_id AND (role='assistant' OR message_id<>m.message_id)) +
		(SELECT COUNT(*) FROM tool_calls WHERE attempt_id=a.attempt_id) +
		(SELECT COUNT(*) FROM approvals WHERE attempt_id=a.attempt_id) +
		(SELECT COUNT(*) FROM input_requests WHERE attempt_id=a.attempt_id) +
		(SELECT COUNT(*) FROM artifacts WHERE attempt_id=a.attempt_id) +
		(SELECT COUNT(*) FROM control_actions WHERE attempt_id=a.attempt_id AND (kind<>'dispatch.start' OR status<>'acknowledged'))
		FROM attempts a JOIN requests r ON r.request_id=a.request_id JOIN messages m ON m.message_id=r.input_message_id
		WHERE a.dialog_id=? AND a.started_at IS NOT NULL AND m.sequence>=(SELECT sequence FROM messages WHERE message_id=?)
		ORDER BY m.sequence,a.generation`, dialogID, messageID)
	if err != nil {
		return nil, err
	}
	proof := &harnessadapter.FailedTailRetry{}
	for rows.Next() {
		var prior harnessadapter.FailedTailAttempt
		var prompt, state, effects string
		var output, activity int64
		if err := rows.Scan(&prior.Attempt.NodeID, &prior.Attempt.DialogID, &prior.Attempt.RequestID, &prior.Attempt.AttemptID, &prior.Attempt.Generation,
			&prior.Context.MessageID, &prior.Context.Sequence, &prompt, &prior.PolicyHash, &state, &effects, &output, &activity); err != nil {
			rows.Close()
			return nil, err
		}
		if state != "failed" || effects != "none" || output != 0 || activity != 0 || len(proof.Attempts) >= 100 {
			rows.Close()
			return nil, nil
		}
		hash := sha256.Sum256([]byte(prompt))
		prior.PromptHash = hex.EncodeToString(hash[:])
		proof.Attempts = append(proof.Attempts, prior)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(proof.Attempts) == 0 || proof.Attempts[0].Context.MessageID != messageID {
		return nil, nil
	}
	for _, prior := range proof.Attempts {
		var encoded []byte
		if err := tx.QueryRowContext(ctx, `SELECT event_json FROM events WHERE attempt_id=? AND late=0 ORDER BY seq DESC LIMIT 1`, prior.Attempt.AttemptID).Scan(&encoded); err != nil {
			return nil, err
		}
		event, err := harnessprotocol.DecodeEvent(encoded)
		if err != nil {
			return nil, nil
		}
		failure, ok := event.Payload.(*harnessprotocol.AttemptFailedPayload)
		if !ok || event.Envelope.AttemptID != prior.Attempt.AttemptID || event.Envelope.DialogID != dialogID || failure.Generation != prior.Attempt.Generation || failure.FailureClass != "task" || failure.ErrorCode != "codex_model_unsupported" || failure.EffectStatus != "none" {
			return nil, nil
		}
		// The old unsupported-model recovery retains one historical, generic
		// terminal archive. It is the only late observation allowed here; any
		// output, tool, input or additional observation defeats the proof.
		late, err := tx.QueryContext(ctx, `SELECT generation,kind,observation_json,projection_key,output_bytes FROM late_observations WHERE attempt_id=?`, prior.Attempt.AttemptID)
		if err != nil {
			return nil, err
		}
		count := 0
		for late.Next() {
			var generation, bytes int64
			var kind, key string
			var data []byte
			if err := late.Scan(&generation, &kind, &data, &key, &bytes); err != nil {
				late.Close()
				return nil, err
			}
			var terminal harnessadapter.TerminalEvent
			count++
			if count > 1 || json.Unmarshal(data, &terminal) != nil || generation != prior.Attempt.Generation || kind != "terminal_while_steer_unresolved" || key != "archive:terminal" || bytes != 17 || terminal.Attempt != prior.Attempt || terminal.Outcome != harnessadapter.ReconcileFailed || terminal.EffectStatus != "unknown" || terminal.Output != nil || terminal.Usage != nil || terminal.Failure == nil || terminal.Failure.Class != harnessadapter.FailureTask || terminal.Failure.Code != "codex_turn_failed" || terminal.Failure.SafeMessage != "codex turn failed" || terminal.Failure.Retryable {
				late.Close()
				return nil, nil
			}
		}
		if err := late.Err(); err != nil {
			late.Close()
			return nil, err
		}
		late.Close()
	}
	proof.HighWater = proof.Attempts[len(proof.Attempts)-1].Context
	return proof, nil
}
