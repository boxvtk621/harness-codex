package node

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

type durableState struct {
	NodeID                string
	OwnerID               string
	RegistryVersion       int64
	Epoch                 int64
	StateVersion          int64
	LastEventSeq          int64
	QueueVersion          int64
	QueuePaused           bool
	TransportAvailability string
	EngineReadiness       string
	Occupancy             string
	ActiveAttemptID       sql.NullString
	PendingCount          int64
	BlockedReasons        []string
	NextQueueSequence     int64
	NextMessageSequence   int64
}

func loadState(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (durableState, error) {
	var state durableState
	var paused int
	var reasons []byte
	err := query.QueryRowContext(ctx, `SELECT node_id,owner_id,registry_version,epoch,state_version,last_event_seq,
		queue_version,queue_paused,transport_availability,engine_readiness,occupancy,active_attempt_id,pending_count,
		blocked_reasons,next_queue_sequence,next_message_sequence FROM node_state WHERE singleton=1`).Scan(
		&state.NodeID, &state.OwnerID, &state.RegistryVersion, &state.Epoch, &state.StateVersion, &state.LastEventSeq,
		&state.QueueVersion, &paused, &state.TransportAvailability, &state.EngineReadiness, &state.Occupancy,
		&state.ActiveAttemptID, &state.PendingCount, &reasons, &state.NextQueueSequence, &state.NextMessageSequence)
	if err != nil {
		return durableState{}, err
	}
	state.QueuePaused = paused == 1
	if err := json.Unmarshal(reasons, &state.BlockedReasons); err != nil {
		return durableState{}, fmt.Errorf("decode blocked reasons: %w", err)
	}
	return state, nil
}

func saveState(ctx context.Context, tx *sql.Tx, state durableState) error {
	reasons, err := json.Marshal(state.BlockedReasons)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE node_state SET epoch=?,state_version=?,last_event_seq=?,queue_version=?,queue_paused=?,
		transport_availability=?,engine_readiness=?,occupancy=?,active_attempt_id=?,pending_count=?,blocked_reasons=?,
		next_queue_sequence=?,next_message_sequence=? WHERE singleton=1`, state.Epoch, state.StateVersion, state.LastEventSeq,
		state.QueueVersion, state.QueuePaused, state.TransportAvailability, state.EngineReadiness, state.Occupancy,
		nullableString(state.ActiveAttemptID), state.PendingCount, string(reasons), state.NextQueueSequence, state.NextMessageSequence)
	return err
}

func nullableString(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}

func timestamp(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func (node *Node) newID() (string, error) { return node.config.IDs.NewID() }

func (node *Node) errorResult(status int, code, message, correlation string, currentVersion *int64, currentState string) Result {
	if correlation == "" {
		correlation, _ = node.newID()
	}
	retryable := code == "queue_full" || code == "node_unavailable" || code == "not_durable"
	body, _ := json.Marshal(harnessprotocol.Error{
		ProtocolVersion: harnessprotocol.ProtocolVersion, SchemaID: harnessprotocol.SchemaID,
		Code: code, SafeMessage: message, Retryable: retryable, CorrelationID: correlation,
		CurrentVersion: currentVersion, CurrentState: currentState,
	})
	return Result{HTTPStatus: status, Body: body}
}

func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

func (node *Node) checkFault(point FaultPoint) error {
	if node.fault == nil {
		return nil
	}
	return node.fault(point)
}
