package node

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

// EventReplay is a bounded durable SSE read. The caller must request again
// after LastEventSeq to follow new commits; no database lock is held while the
// network client is idle.
type EventReplay struct {
	Epoch        int64
	LastEventSeq int64
	Events       []json.RawMessage
}

func (node *Node) ReplayEvents(ctx context.Context, trust TrustContext, after int64, limit int) (EventReplay, Result, bool) {
	if denied := node.authorizeRead(trust); denied != nil {
		return EventReplay{}, *denied, false
	}
	if after < 0 || limit < 1 || limit > 100 {
		return EventReplay{}, node.Invalid("event cursor is invalid"), false
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return EventReplay{}, node.errorResult(503, "not_durable", "events are unavailable", "", nil, ""), false
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return EventReplay{}, node.errorResult(503, "not_durable", "events are unavailable", "", nil, ""), false
	}
	if after > state.LastEventSeq {
		return EventReplay{}, node.errorResult(409, "stale", "event cursor is ahead of durable history", "", nil, ""), false
	}
	rows, err := tx.QueryContext(ctx, `SELECT event_json FROM events WHERE node_id=? AND seq>? ORDER BY seq LIMIT ?`, state.NodeID, after, limit)
	if err != nil {
		return EventReplay{}, node.errorResult(503, "not_durable", "events are unavailable", "", nil, ""), false
	}
	defer rows.Close()
	type replayEvent struct {
		raw      json.RawMessage
		envelope harnessprotocol.EventEnvelope
	}
	window := make([]replayEvent, 0, limit)
	messageCandidates := map[string]struct{}{}
	totalBytes := 0
	expected := after + 1
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return EventReplay{}, node.errorResult(503, "not_durable", "events are unavailable", "", nil, ""), false
		}
		var envelope harnessprotocol.EventEnvelope
		if harnessprotocol.Validate("event", raw) != nil || json.Unmarshal(raw, &envelope) != nil || envelope.NodeID != state.NodeID || envelope.Epoch != state.Epoch || envelope.Seq != expected {
			return EventReplay{}, node.errorResult(409, "stale", "durable event history has a gap", "", nil, ""), false
		}
		if totalBytes+len(raw) > harnessprotocol.MaximumWireBytes-1024 {
			break
		}
		if envelope.Type == "message.disposition_changed" {
			messageCandidates[envelope.EntityID] = struct{}{}
		}
		window = append(window, replayEvent{raw: append(json.RawMessage(nil), raw...), envelope: envelope})
		totalBytes += len(raw)
		expected++
	}
	if err := rows.Err(); err != nil {
		return EventReplay{}, node.errorResult(503, "not_durable", "events are unavailable", "", nil, ""), false
	}
	if err := rows.Close(); err != nil {
		return EventReplay{}, node.errorResult(503, "not_durable", "events are unavailable", "", nil, ""), false
	}
	deletedMessages, err := deletedMessageScopes(ctx, tx, messageCandidates, node.deletedDialogs)
	if err != nil {
		return EventReplay{}, node.errorResult(503, "not_durable", "events are unavailable", "", nil, ""), false
	}
	events := make([]json.RawMessage, 0, len(window))
	for _, candidate := range window {
		if eventBelongsToDeletedDialog(candidate.envelope, node.deletedDialogs, deletedMessages) {
			return EventReplay{}, node.errorResult(409, "stale", "event history requires snapshot resynchronization", "", nil, ""), false
		}
		events = append(events, candidate.raw)
	}
	return EventReplay{Epoch: state.Epoch, LastEventSeq: state.LastEventSeq, Events: events}, Result{}, true
}

func loadDeletedDialogs(ctx context.Context, queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (map[string]struct{}, error) {
	dialogs := map[string]struct{}{}
	rows, err := queryer.QueryContext(ctx, "SELECT dialog_id FROM events WHERE projection_key='dialog.deleted' AND dialog_id IS NOT NULL")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var dialogID string
		if err := rows.Scan(&dialogID); err != nil {
			return nil, err
		}
		dialogs[dialogID] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return dialogs, nil
}

func deletedMessageScopes(ctx context.Context, tx *sql.Tx, candidates map[string]struct{}, deletedDialogs map[string]struct{}) (map[string]struct{}, error) {
	messages := map[string]struct{}{}
	if len(candidates) == 0 {
		return messages, nil
	}
	if len(candidates) > 100 {
		return nil, fmt.Errorf("replay message candidate limit exceeded")
	}
	ids := make([]string, 0, len(candidates))
	for messageID := range candidates {
		ids = append(ids, messageID)
	}
	sort.Strings(ids)
	arguments := make([]any, len(ids))
	for index, messageID := range ids {
		arguments[index] = messageID
	}
	rows, err := tx.QueryContext(ctx, `SELECT message_id,dialog_id FROM messages WHERE message_id IN (`+strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")+`)`, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var messageID, dialogID string
		if err := rows.Scan(&messageID, &dialogID); err != nil {
			return nil, err
		}
		if _, deleted := deletedDialogs[dialogID]; deleted {
			messages[messageID] = struct{}{}
		}
	}
	return messages, rows.Err()
}

func eventBelongsToDeletedDialog(envelope harnessprotocol.EventEnvelope, dialogs, messages map[string]struct{}) bool {
	if envelope.Type == "dialog.deleted" {
		return false
	}
	_, deletedDialog := dialogs[envelope.DialogID]
	_, deletedMessage := messages[envelope.EntityID]
	if deletedDialog || (envelope.Type == "message.disposition_changed" && deletedMessage) {
		return true
	}
	if envelope.Type == "message.accepted" {
		var payload harnessprotocol.MessageAcceptedPayload
		if json.Unmarshal(envelope.Payload, &payload) != nil {
			return false
		}
		_, deleted := dialogs[payload.DialogID]
		return deleted
	}
	return false
}
