package node

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/tooltimeline"
)

type toolCursor struct {
	Epoch int64  `json:"e"`
	After int64  `json:"a"`
	Scope string `json:"s"`
}

func encodeToolCursor(value toolCursor) *string {
	raw, _ := json.Marshal(value)
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	return &encoded
}

func decodeToolCursor(raw, scope string, epoch int64) (int64, *commandFailure) {
	if raw == "" {
		return 0, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) > harnessprotocol.MaximumCursorBytes {
		return 0, &commandFailure{status: http.StatusBadRequest, code: "invalid", message: "tool cursor is invalid"}
	}
	var cursor toolCursor
	if json.Unmarshal(decoded, &cursor) != nil || cursor.Epoch != epoch || cursor.Scope != scope || cursor.After < 0 || cursor.After > harnessprotocol.MaximumSafeInteger {
		return 0, &commandFailure{status: http.StatusConflict, code: "stale", message: "tool cursor is invalid or stale"}
	}
	return cursor.After, nil
}

func (node *Node) toolTimelineResult(value any) Result {
	body, err := tooltimeline.Marshal(value)
	if err != nil || len(body) > harnessprotocol.MaximumWireBytes {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "tool timeline response is invalid", "", nil, "")
	}
	return Result{HTTPStatus: http.StatusOK, Body: body}
}

func toolAttemptScope(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, state durableState, attemptID string) (string, string, error) {
	var dialogID, requestID string
	err := query.QueryRowContext(ctx, `SELECT a.dialog_id,a.request_id FROM attempts a JOIN dialogs d ON d.dialog_id=a.dialog_id
		WHERE a.attempt_id=? AND d.node_id=? AND d.owner_id=? AND NOT EXISTS (
			SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`,
		attemptID, state.NodeID, state.OwnerID).Scan(&dialogID, &requestID)
	return dialogID, requestID, err
}

func validatedToolEvent(raw []byte, attemptID, dialogID, eventType, callID string) (harnessprotocol.EventEnvelope, error) {
	var envelope harnessprotocol.EventEnvelope
	if harnessprotocol.Validate("event", raw) != nil || json.Unmarshal(raw, &envelope) != nil || envelope.Type != eventType ||
		envelope.AttemptID != attemptID || envelope.DialogID != dialogID || (callID != "" && envelope.EntityID != callID) {
		return envelope, errors.New("tool event scope is invalid")
	}
	return envelope, nil
}

func loadToolSummary(ctx context.Context, tx *sql.Tx, attemptID, dialogID string, started harnessprotocol.EventEnvelope) (tooltimeline.Summary, error) {
	var payload harnessprotocol.ToolStartedPayload
	if json.Unmarshal(started.Payload, &payload) != nil || payload.CallID != started.EntityID {
		return tooltimeline.Summary{}, errors.New("tool start is invalid")
	}
	var state string
	var version int64
	if err := tx.QueryRowContext(ctx, "SELECT status,version FROM tool_calls WHERE call_id=? AND attempt_id=?", payload.CallID, attemptID).Scan(&state, &version); err != nil {
		return tooltimeline.Summary{}, err
	}
	if state != "running" && state != "succeeded" && state != "failed" && state != "unknown" {
		return tooltimeline.Summary{}, errors.New("tool state is invalid")
	}
	item := tooltimeline.Summary{ToolCallID: payload.CallID, ToolName: payload.ToolName, State: state, StartedAt: started.ObservedAt, DetailVersion: version}
	var completedRaw []byte
	err := tx.QueryRowContext(ctx, "SELECT event_json FROM events WHERE attempt_id=? AND projection_key IN(?,?) ORDER BY seq DESC LIMIT 1", attemptID, "tool.completed:"+payload.CallID, "archive:tool.completed:"+payload.CallID).Scan(&completedRaw)
	if err == nil {
		completed, validateErr := validatedToolEvent(completedRaw, attemptID, dialogID, "tool.completed", payload.CallID)
		if validateErr != nil {
			return tooltimeline.Summary{}, validateErr
		}
		item.FinishedAt = completed.ObservedAt
	} else if !errors.Is(err, sql.ErrNoRows) {
		return tooltimeline.Summary{}, err
	} else if state != "running" {
		return tooltimeline.Summary{}, errors.New("terminal tool is missing completion event")
	}
	return item, nil
}

func (node *Node) ToolCalls(ctx context.Context, trust TrustContext, attemptID, cursor string, limit int) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	limit, ok := normalizedLimit(limit)
	if !ok || !uuidPattern.MatchString(attemptID) {
		return node.Invalid("tool timeline query is invalid")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return node.errorResult(503, "not_durable", "tool timeline is unavailable", attemptID, nil, "")
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return node.errorResult(503, "not_durable", "tool timeline is unavailable", attemptID, nil, "")
	}
	dialogID, requestID, err := toolAttemptScope(ctx, tx, state, attemptID)
	if errors.Is(err, sql.ErrNoRows) {
		return node.errorResult(404, "not_found", "attempt was not found", attemptID, nil, "")
	}
	if err != nil {
		return node.errorResult(503, "not_durable", "tool timeline is unavailable", attemptID, nil, "")
	}
	scope := "tool_calls:" + attemptID
	after, failure := decodeToolCursor(cursor, scope, state.Epoch)
	if failure != nil {
		return node.commandError(failure, attemptID)
	}
	rows, err := tx.QueryContext(ctx, `SELECT seq,event_json FROM events WHERE node_id=? AND attempt_id=? AND seq>? AND projection_key LIKE 'tool.started:%' ORDER BY seq LIMIT ?`, state.NodeID, attemptID, after, limit+1)
	if err != nil {
		return node.errorResult(503, "not_durable", "tool timeline is unavailable", attemptID, nil, "")
	}
	defer rows.Close()
	items := make([]tooltimeline.Summary, 0, limit)
	sequences := make([]int64, 0, limit+1)
	for rows.Next() {
		var seq int64
		var raw []byte
		if err := rows.Scan(&seq, &raw); err != nil {
			return node.errorResult(503, "not_durable", "tool timeline is unavailable", attemptID, nil, "")
		}
		if len(items) == limit {
			sequences = append(sequences, seq)
			break
		}
		started, err := validatedToolEvent(raw, attemptID, dialogID, "tool.started", "")
		if err != nil {
			return node.errorResult(503, "not_durable", "tool timeline is invalid", attemptID, nil, "")
		}
		item, err := loadToolSummary(ctx, tx, attemptID, dialogID, started)
		if err != nil {
			return node.errorResult(503, "not_durable", "tool timeline is invalid", attemptID, nil, "")
		}
		items = append(items, item)
		sequences = append(sequences, seq)
	}
	if err := rows.Err(); err != nil {
		return node.errorResult(503, "not_durable", "tool timeline is unavailable", attemptID, nil, "")
	}
	var next *string
	if len(sequences) > len(items) && len(items) > 0 {
		next = encodeToolCursor(toolCursor{Epoch: state.Epoch, After: sequences[len(items)-1], Scope: scope})
	}
	return node.toolTimelineResult(tooltimeline.Page{ProtocolVersion: 1, SchemaID: tooltimeline.SchemaID, NodeID: state.NodeID, Epoch: state.Epoch, SnapshotStateVersion: state.StateVersion, LastEventSeq: state.LastEventSeq, DialogID: dialogID, RequestID: requestID, AttemptID: attemptID, Items: items, NextCursor: next, PageType: tooltimeline.PageType})
}

func (node *Node) ToolCall(ctx context.Context, trust TrustContext, attemptID, callID string, after int64, limit int) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	limit, ok := normalizedLimit(limit)
	if !ok || !uuidPattern.MatchString(attemptID) || !uuidPattern.MatchString(callID) || after < 0 || after > harnessprotocol.MaximumSafeInteger {
		return node.Invalid("tool detail query is invalid")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return node.errorResult(503, "not_durable", "tool detail is unavailable", callID, nil, "")
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return node.errorResult(503, "not_durable", "tool detail is unavailable", callID, nil, "")
	}
	dialogID, requestID, err := toolAttemptScope(ctx, tx, state, attemptID)
	if errors.Is(err, sql.ErrNoRows) {
		return node.errorResult(404, "not_found", "attempt was not found", attemptID, nil, "")
	}
	if err != nil {
		return node.errorResult(503, "not_durable", "tool detail is unavailable", callID, nil, "")
	}
	var startedRaw []byte
	if err := tx.QueryRowContext(ctx, "SELECT event_json FROM events WHERE attempt_id=? AND projection_key IN(?,?) ORDER BY seq LIMIT 1", attemptID, "tool.started:"+callID, "archive:tool.started:"+callID).Scan(&startedRaw); errors.Is(err, sql.ErrNoRows) {
		return node.errorResult(404, "not_found", "tool call was not found", callID, nil, "")
	} else if err != nil {
		return node.errorResult(503, "not_durable", "tool detail is unavailable", callID, nil, "")
	}
	started, err := validatedToolEvent(startedRaw, attemptID, dialogID, "tool.started", callID)
	if err != nil {
		return node.errorResult(503, "not_durable", "tool detail is invalid", callID, nil, "")
	}
	summary, err := loadToolSummary(ctx, tx, attemptID, dialogID, started)
	if err != nil {
		return node.errorResult(503, "not_durable", "tool detail is invalid", callID, nil, "")
	}
	var startPayload harnessprotocol.ToolStartedPayload
	_ = json.Unmarshal(started.Payload, &startPayload)
	detail := tooltimeline.Detail{Summary: summary, Input: startPayload.Input, Outputs: make([]tooltimeline.Output, 0, limit)}
	var completedRaw []byte
	if err := tx.QueryRowContext(ctx, "SELECT event_json FROM events WHERE attempt_id=? AND projection_key IN(?,?) ORDER BY seq DESC LIMIT 1", attemptID, "tool.completed:"+callID, "archive:tool.completed:"+callID).Scan(&completedRaw); err == nil {
		completed, validateErr := validatedToolEvent(completedRaw, attemptID, dialogID, "tool.completed", callID)
		var payload harnessprotocol.ToolCompletedPayload
		if validateErr != nil || json.Unmarshal(completed.Payload, &payload) != nil || payload.CallID != callID {
			return node.errorResult(503, "not_durable", "tool detail is invalid", callID, nil, "")
		}
		detail.Result = &payload.Result
	} else if !errors.Is(err, sql.ErrNoRows) {
		return node.errorResult(503, "not_durable", "tool detail is unavailable", callID, nil, "")
	}
	rows, err := tx.QueryContext(ctx, `SELECT seq,event_json FROM events WHERE node_id=? AND attempt_id=? AND seq>? AND (projection_key LIKE ? OR projection_key LIKE ?) ORDER BY seq LIMIT ?`, state.NodeID, attemptID, after, "tool.output:"+callID+":%", "archive:tool.output:"+callID+":%", limit+1)
	if err != nil {
		return node.errorResult(503, "not_durable", "tool detail is unavailable", callID, nil, "")
	}
	defer rows.Close()
	encodedBytes := 0
	lastSeq := int64(0)
	hasMore := false
	for rows.Next() {
		var seq int64
		var raw []byte
		if err := rows.Scan(&seq, &raw); err != nil {
			return node.errorResult(503, "not_durable", "tool detail is unavailable", callID, nil, "")
		}
		envelope, err := validatedToolEvent(raw, attemptID, dialogID, "tool.output", callID)
		if err != nil {
			return node.errorResult(503, "not_durable", "tool detail is invalid", callID, nil, "")
		}
		var payload harnessprotocol.ToolOutputPayload
		if json.Unmarshal(envelope.Payload, &payload) != nil || payload.CallID != callID {
			return node.errorResult(503, "not_durable", "tool detail is invalid", callID, nil, "")
		}
		item := tooltimeline.Output{Index: payload.ChunkIndex, Stream: payload.Stream, Content: payload.Output, ObservedAt: envelope.ObservedAt}
		encoded, _ := json.Marshal(item)
		if len(detail.Outputs) == limit || encodedBytes+len(encoded) > harnessprotocol.MaximumWireBytes-128<<10 {
			hasMore = true
			break
		}
		detail.Outputs = append(detail.Outputs, item)
		encodedBytes += len(encoded)
		lastSeq = seq
	}
	if err := rows.Err(); err != nil {
		return node.errorResult(503, "not_durable", "tool detail is unavailable", callID, nil, "")
	}
	if hasMore && lastSeq > 0 {
		value := strconv.FormatInt(lastSeq, 10)
		detail.NextOutputCursor = &value
	}
	return node.toolTimelineResult(tooltimeline.DetailRead{ProtocolVersion: 1, SchemaID: tooltimeline.SchemaID, NodeID: state.NodeID, Epoch: state.Epoch, StateVersion: state.StateVersion, LastEventSeq: state.LastEventSeq, DialogID: dialogID, RequestID: requestID, AttemptID: attemptID, ToolCall: detail})
}
