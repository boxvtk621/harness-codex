package node

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

func (node *Node) appendEvent(ctx context.Context, tx *sql.Tx, state *durableState, eventType, entityID string, entityVersion int64, attemptID, dialogID string, payload any, late bool) ([]byte, error) {
	state.LastEventSeq++
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	event := harnessprotocol.EventEnvelope{
		ProtocolVersion: harnessprotocol.ProtocolVersion, SchemaID: harnessprotocol.SchemaID,
		NodeID: state.NodeID, Seq: state.LastEventSeq, Epoch: state.Epoch,
		Type: eventType, EntityID: entityID, EntityVersion: entityVersion,
		AttemptID: attemptID, DialogID: dialogID, ObservedAt: timestamp(node.config.Clock()),
		Completeness: "complete", Payload: payloadJSON,
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	if err := harnessprotocol.Validate("event", encoded); err != nil {
		return nil, fmt.Errorf("internal event %s: %w", eventType, err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO events(node_id,seq,epoch,event_json,attempt_id,dialog_id,late,created_at)
		VALUES(?,?,?,?,?,?,?,?)`, state.NodeID, state.LastEventSeq, state.Epoch, encoded, nullText(attemptID), nullText(dialogID), late, event.ObservedAt)
	return encoded, err
}

func nullText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nodePayload(state durableState) harnessprotocol.NodeState {
	var active *string
	if state.ActiveAttemptID.Valid {
		value := state.ActiveAttemptID.String
		active = &value
	}
	return harnessprotocol.NodeState{
		TransportAvailability: state.TransportAvailability, EngineReadiness: state.EngineReadiness,
		Occupancy: state.Occupancy, QueuePaused: state.QueuePaused, QueueVersion: state.QueueVersion,
		PendingCount: state.PendingCount, BlockedReasons: state.BlockedReasons, ActiveAttemptID: active,
	}
}

func (node *Node) appendNodeEvent(ctx context.Context, tx *sql.Tx, state *durableState) error {
	_, err := node.appendEvent(ctx, tx, state, "node.state_changed", state.NodeID, state.StateVersion, "", "", nodePayload(*state), false)
	return err
}

func (node *Node) appendQueueEvent(ctx context.Context, tx *sql.Tx, state *durableState) error {
	var active *string
	if state.ActiveAttemptID.Valid {
		value := state.ActiveAttemptID.String
		active = &value
	}
	_, err := node.appendEvent(ctx, tx, state, "queue.changed", state.NodeID, state.QueueVersion, "", "", harnessprotocol.QueueChangedPayload{
		QueueVersion: state.QueueVersion, PendingCount: state.PendingCount, ActiveAttemptID: active, QueuePaused: state.QueuePaused,
	}, false)
	return err
}
