package node

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

const MaximumAttemptOutputBytes int64 = 64 * 1024 * 1024

var ErrOutputLimit = errors.New("attempt output limit exceeded")

type outputCharge struct {
	Exceeded      bool
	NewlyExceeded bool
}

// chargeAttemptOutput accounts bytes of one distinct output projection. A
// value above the maximum is a durable sticky overflow marker, not a byte
// count. Callers must perform projection deduplication before charging.
func chargeAttemptOutput(ctx context.Context, tx *sql.Tx, attemptID string, bytes int64) (outputCharge, error) {
	if bytes < 0 || bytes > MaximumAttemptOutputBytes {
		return outputCharge{}, errors.New("output charge is invalid")
	}
	var current, archived int64
	if err := tx.QueryRowContext(ctx, "SELECT output_bytes FROM attempts WHERE attempt_id=?", attemptID).Scan(&current); err != nil {
		return outputCharge{}, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(output_bytes),0) FROM late_observations WHERE attempt_id=? AND projection_key IS NOT NULL", attemptID).Scan(&archived); err != nil {
		return outputCharge{}, err
	}
	if current > MaximumAttemptOutputBytes || archived > MaximumAttemptOutputBytes || current > MaximumAttemptOutputBytes-archived {
		return outputCharge{Exceeded: true}, nil
	}
	if bytes > MaximumAttemptOutputBytes-current-archived {
		result, err := tx.ExecContext(ctx, "UPDATE attempts SET output_bytes=? WHERE attempt_id=? AND output_bytes=?", MaximumAttemptOutputBytes+1, attemptID, current)
		if err != nil {
			return outputCharge{}, err
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return outputCharge{}, errors.New("output charge fence changed")
		}
		return outputCharge{Exceeded: true, NewlyExceeded: true}, nil
	}
	if bytes == 0 {
		return outputCharge{}, nil
	}
	result, err := tx.ExecContext(ctx, "UPDATE attempts SET output_bytes=output_bytes+? WHERE attempt_id=? AND output_bytes=?", bytes, attemptID, current)
	if err != nil {
		return outputCharge{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return outputCharge{}, errors.New("output charge fence changed")
	}
	return outputCharge{}, nil
}

func chargeSafeOutput(ctx context.Context, tx *sql.Tx, attemptID string, content harnessprotocol.SafeContent) (outputCharge, error) {
	bytes := int64(0)
	if content.Kind == "inline" {
		bytes = int64(len([]byte(content.Content)))
	}
	return chargeAttemptOutput(ctx, tx, attemptID, bytes)
}

// chargeArchivedAttemptOutput accounts bytes without mutating attempts. Late
// observations are outside the durable domain projection, so their ledger is
// stored with the archive row that will be committed in the same transaction.
// The returned value is the amount the caller must persist in output_bytes.
func chargeArchivedAttemptOutput(ctx context.Context, tx *sql.Tx, attemptID string, bytes int64) (outputCharge, int64, error) {
	if bytes < 0 || bytes > MaximumAttemptOutputBytes {
		return outputCharge{}, 0, errors.New("archived output charge is invalid")
	}
	var active, archived int64
	if err := tx.QueryRowContext(ctx, "SELECT output_bytes FROM attempts WHERE attempt_id=?", attemptID).Scan(&active); err != nil {
		return outputCharge{}, 0, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(output_bytes),0) FROM late_observations WHERE attempt_id=? AND projection_key IS NOT NULL", attemptID).Scan(&archived); err != nil {
		return outputCharge{}, 0, err
	}
	if active > MaximumAttemptOutputBytes || archived > MaximumAttemptOutputBytes || active > MaximumAttemptOutputBytes-archived {
		return outputCharge{Exceeded: true}, 0, nil
	}
	current := active + archived
	if bytes > MaximumAttemptOutputBytes-current {
		return outputCharge{Exceeded: true, NewlyExceeded: true}, MaximumAttemptOutputBytes + 1 - current, nil
	}
	return outputCharge{}, bytes, nil
}

func attemptOutputExceeded(ctx context.Context, tx *sql.Tx, attemptID string) (bool, error) {
	var active, archived int64
	if err := tx.QueryRowContext(ctx, "SELECT output_bytes FROM attempts WHERE attempt_id=?", attemptID).Scan(&active); err != nil {
		return false, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(output_bytes),0) FROM late_observations WHERE attempt_id=? AND projection_key IS NOT NULL", attemptID).Scan(&archived); err != nil {
		return false, err
	}
	return active > MaximumAttemptOutputBytes || archived > MaximumAttemptOutputBytes || active > MaximumAttemptOutputBytes-archived, nil
}

func outputLimitContent() harnessprotocol.SafeContent {
	return harnessprotocol.SafeContent{Kind: "unavailable", Reason: "output_limit", Redaction: "unknown", Truncated: true}
}

// appendArtifactOutputLimitMarker persists the visible marker needed when raw
// artifact bytes exceed the aggregate budget before an adapter event can
// reference them. It never attributes synthetic assistant text to the adapter.
func (node *Node) appendArtifactOutputLimitMarker(ctx context.Context, tx *sql.Tx, state *durableState, reference harnessadapter.AttemptRef, attemptVersion int64) error {
	messageID, err := node.newID()
	if err != nil {
		return err
	}
	content := outputLimitContent()
	encoded, err := json.Marshal(content)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO messages(message_id,dialog_id,sequence,version,role,content_json,attempt_id,finish_reason,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, messageID, reference.DialogID, state.NextMessageSequence, 1, "assistant", encoded, reference.AttemptID, "length", timestamp(node.config.Clock())); err != nil {
		return err
	}
	state.NextMessageSequence++
	state.StateVersion++
	late := !state.ActiveAttemptID.Valid || state.ActiveAttemptID.String != reference.AttemptID
	payload := harnessprotocol.AssistantMessagePayload{MessageID: messageID, Content: content, FinishReason: "length"}
	if _, err := node.appendEvent(ctx, tx, state, "assistant.message", messageID, 1, reference.AttemptID, reference.DialogID, payload, late); err != nil {
		return err
	}
	return recordAdapterProjection(ctx, tx, state.LastEventSeq, reference.AttemptID, adapterProjection{key: "output_limit:artifact", payload: payload, eventType: "assistant.message", entityID: messageID, entityVersion: attemptVersion})
}
