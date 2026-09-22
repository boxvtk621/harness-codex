package node

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"

	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

type historyPage struct {
	ProtocolVersion      int               `json:"protocolVersion"`
	SchemaID             string            `json:"schemaId"`
	NodeID               string            `json:"nodeId"`
	Epoch                int64             `json:"epoch"`
	SnapshotStateVersion int64             `json:"snapshotStateVersion"`
	LastEventSeq         int64             `json:"lastEventSeq"`
	Items                []json.RawMessage `json:"items"`
	NextCursor           *string           `json:"nextCursor"`
	PageType             string            `json:"pageType"`
	DialogID             string            `json:"dialogId"`
}

type eventPage struct {
	ProtocolVersion      int               `json:"protocolVersion"`
	SchemaID             string            `json:"schemaId"`
	NodeID               string            `json:"nodeId"`
	Epoch                int64             `json:"epoch"`
	SnapshotStateVersion int64             `json:"snapshotStateVersion"`
	LastEventSeq         int64             `json:"lastEventSeq"`
	Items                []json.RawMessage `json:"items"`
	NextCursor           *string           `json:"nextCursor"`
	PageType             string            `json:"pageType"`
	DialogID             string            `json:"dialogId"`
	AttemptID            string            `json:"attemptId"`
}

type pageCursor struct {
	Epoch        int64  `json:"e"`
	StateVersion int64  `json:"s"`
	Offset       int64  `json:"o"`
	Scope        string `json:"p"`
}

type latestHistoryCursor struct {
	Epoch          int64  `json:"e"`
	BeforeSequence int64  `json:"b"`
	Scope          string `json:"p"`
}

func encodeCursor(cursor pageCursor) *string {
	encoded, _ := json.Marshal(cursor)
	value := base64.RawURLEncoding.EncodeToString(encoded)
	return &value
}

func decodeCursor(raw, scope string, state durableState) (int64, *commandFailure) {
	if raw == "" {
		return 0, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) > harnessprotocol.MaximumCursorBytes {
		return 0, &commandFailure{status: http.StatusBadRequest, code: "invalid", message: "cursor is invalid"}
	}
	var cursor pageCursor
	if json.Unmarshal(decoded, &cursor) != nil || cursor.Offset < 0 || cursor.Scope != scope {
		return 0, &commandFailure{status: http.StatusBadRequest, code: "invalid", message: "cursor is invalid"}
	}
	if cursor.Epoch != state.Epoch || cursor.StateVersion != state.StateVersion {
		return 0, &commandFailure{status: http.StatusConflict, code: "stale", message: "cursor snapshot is stale"}
	}
	return cursor.Offset, nil
}

func encodeLatestHistoryCursor(cursor latestHistoryCursor) *string {
	encoded, _ := json.Marshal(cursor)
	value := base64.RawURLEncoding.EncodeToString(encoded)
	return &value
}

func decodeLatestHistoryCursor(raw, scope string, epoch int64) (int64, *commandFailure) {
	if raw == "" {
		return harnessprotocol.MaximumSafeInteger + 1, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) > harnessprotocol.MaximumCursorBytes {
		return 0, &commandFailure{status: http.StatusBadRequest, code: "invalid", message: "history cursor is invalid"}
	}
	var cursor latestHistoryCursor
	if json.Unmarshal(decoded, &cursor) != nil || cursor.Epoch != epoch || cursor.Scope != scope || cursor.BeforeSequence < 1 || cursor.BeforeSequence > harnessprotocol.MaximumSafeInteger {
		return 0, &commandFailure{status: http.StatusConflict, code: "stale", message: "history cursor is invalid or stale"}
	}
	return cursor.BeforeSequence, nil
}

func normalizedLimit(limit int) (int, bool) {
	if limit == 0 {
		return harnessprotocol.MaximumPageSize, true
	}
	return limit, limit > 0 && limit <= harnessprotocol.MaximumPageSize
}

func (node *Node) History(ctx context.Context, trust TrustContext, dialogID, cursor string, limit int) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	limit, ok := normalizedLimit(limit)
	if !ok {
		return node.Invalid("limit is invalid")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return node.errorResult(503, "not_durable", "history is unavailable", dialogID, nil, "")
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return node.errorResult(503, "not_durable", "history is unavailable", dialogID, nil, "")
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM dialogs d WHERE d.dialog_id=? AND d.node_id=? AND d.owner_id=? AND NOT EXISTS (
		SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`, dialogID, state.NodeID, state.OwnerID).Scan(&exists); err != nil {
		if isNoRows(err) {
			return node.errorResult(404, "not_found", "dialog was not found", dialogID, nil, "")
		}
		return node.errorResult(503, "not_durable", "history is unavailable", dialogID, nil, "")
	}
	scope := "history:" + dialogID
	offset, failure := decodeCursor(cursor, scope, state)
	if failure != nil {
		return node.commandError(failure, dialogID)
	}
	rows, err := tx.QueryContext(ctx, `SELECT message_id,role,sequence,version,created_at,text,content_json,disposition,command_id,request_id,attempt_id,finish_reason FROM messages WHERE dialog_id=? ORDER BY sequence LIMIT ? OFFSET ?`, dialogID, limit+1, offset)
	if err != nil {
		return node.errorResult(503, "not_durable", "history is unavailable", dialogID, nil, "")
	}
	defer rows.Close()
	items := make([]json.RawMessage, 0, limit+1)
	encodedBytes := 0
	hasMore := false
	for rows.Next() {
		var messageID, role, createdAt string
		var sequence, version int64
		var text, disposition, commandID, requestID, attemptID, finishReason sql.NullString
		var content []byte
		if err := rows.Scan(&messageID, &role, &sequence, &version, &createdAt, &text, &content, &disposition, &commandID, &requestID, &attemptID, &finishReason); err != nil {
			return node.errorResult(503, "not_durable", "history is unavailable", dialogID, nil, "")
		}
		var item any
		switch role {
		case "user":
			item = harnessprotocol.UserHistoryItem{MessageID: messageID, Role: role, DialogID: dialogID, Sequence: sequence, Version: version, CreatedAt: createdAt, Text: text.String, Disposition: disposition.String, CommandID: commandID.String, RequestID: requestID.String}
		case "assistant":
			var safe harnessprotocol.SafeContent
			if len(content) == 0 || json.Unmarshal(content, &safe) != nil {
				return node.errorResult(503, "not_durable", "history content is unavailable", dialogID, nil, "")
			}
			item = harnessprotocol.AssistantHistoryItem{MessageID: messageID, Role: role, DialogID: dialogID, Sequence: sequence, Version: version, CreatedAt: createdAt, AttemptID: attemptID.String, Content: safe, FinishReason: finishReason.String}
		default:
			return node.errorResult(503, "not_durable", "history role is invalid", dialogID, nil, "")
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return node.errorResult(503, "not_durable", "history is unavailable", dialogID, nil, "")
		}
		if len(items) == limit || encodedBytes+len(encoded) > harnessprotocol.MaximumWireBytes-4096 {
			hasMore = true
			break
		}
		items = append(items, encoded)
		encodedBytes += len(encoded)
	}
	if err := rows.Err(); err != nil {
		return node.errorResult(503, "not_durable", "history is unavailable", dialogID, nil, "")
	}
	var next *string
	if hasMore {
		next = encodeCursor(pageCursor{Epoch: state.Epoch, StateVersion: state.StateVersion, Offset: offset + int64(len(items)), Scope: scope})
	}
	return node.wireResult("historyPage", historyPage{ProtocolVersion: 1, SchemaID: harnessprotocol.SchemaID, NodeID: state.NodeID, Epoch: state.Epoch, SnapshotStateVersion: state.StateVersion, LastEventSeq: state.LastEventSeq, Items: items, NextCursor: next, PageType: "history", DialogID: dialogID})
}

// HistoryLatest returns the newest bounded window and then walks backwards by
// immutable message sequence. New messages do not invalidate an older cursor.
func (node *Node) HistoryLatest(ctx context.Context, trust TrustContext, dialogID, cursor string, limit int) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	limit, ok := normalizedLimit(limit)
	if !ok {
		return node.Invalid("limit is invalid")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return node.errorResult(503, "not_durable", "history is unavailable", dialogID, nil, "")
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return node.errorResult(503, "not_durable", "history is unavailable", dialogID, nil, "")
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM dialogs d WHERE d.dialog_id=? AND d.node_id=? AND d.owner_id=? AND NOT EXISTS (
		SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`, dialogID, state.NodeID, state.OwnerID).Scan(&exists); err != nil {
		if isNoRows(err) {
			return node.errorResult(404, "not_found", "dialog was not found", dialogID, nil, "")
		}
		return node.errorResult(503, "not_durable", "history is unavailable", dialogID, nil, "")
	}
	scope := "history-latest:" + dialogID
	before, failure := decodeLatestHistoryCursor(cursor, scope, state.Epoch)
	if failure != nil {
		return node.commandError(failure, dialogID)
	}
	rows, err := tx.QueryContext(ctx, `SELECT message_id,role,sequence,version,created_at,text,content_json,disposition,command_id,request_id,attempt_id,finish_reason FROM messages WHERE dialog_id=? AND sequence<? ORDER BY sequence DESC LIMIT ?`, dialogID, before, limit+1)
	if err != nil {
		return node.errorResult(503, "not_durable", "history is unavailable", dialogID, nil, "")
	}
	defer rows.Close()
	items := make([]json.RawMessage, 0, limit)
	sequences := make([]int64, 0, limit+1)
	encodedBytes := 0
	hasMore := false
	for rows.Next() {
		var messageID, role, createdAt string
		var sequence, version int64
		var text, disposition, commandID, requestID, attemptID, finishReason sql.NullString
		var content []byte
		if err := rows.Scan(&messageID, &role, &sequence, &version, &createdAt, &text, &content, &disposition, &commandID, &requestID, &attemptID, &finishReason); err != nil {
			return node.errorResult(503, "not_durable", "history is unavailable", dialogID, nil, "")
		}
		var item any
		switch role {
		case "user":
			item = harnessprotocol.UserHistoryItem{MessageID: messageID, Role: role, DialogID: dialogID, Sequence: sequence, Version: version, CreatedAt: createdAt, Text: text.String, Disposition: disposition.String, CommandID: commandID.String, RequestID: requestID.String}
		case "assistant":
			var safe harnessprotocol.SafeContent
			if len(content) == 0 || json.Unmarshal(content, &safe) != nil {
				return node.errorResult(503, "not_durable", "history content is unavailable", dialogID, nil, "")
			}
			item = harnessprotocol.AssistantHistoryItem{MessageID: messageID, Role: role, DialogID: dialogID, Sequence: sequence, Version: version, CreatedAt: createdAt, AttemptID: attemptID.String, Content: safe, FinishReason: finishReason.String}
		default:
			return node.errorResult(503, "not_durable", "history role is invalid", dialogID, nil, "")
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return node.errorResult(503, "not_durable", "history is unavailable", dialogID, nil, "")
		}
		if len(items) == limit || encodedBytes+len(encoded) > harnessprotocol.MaximumWireBytes-4096 {
			hasMore = true
			break
		}
		items = append(items, encoded)
		sequences = append(sequences, sequence)
		encodedBytes += len(encoded)
	}
	if err := rows.Err(); err != nil {
		return node.errorResult(503, "not_durable", "history is unavailable", dialogID, nil, "")
	}
	var next *string
	if hasMore && len(sequences) > 0 {
		next = encodeLatestHistoryCursor(latestHistoryCursor{Epoch: state.Epoch, BeforeSequence: sequences[len(sequences)-1], Scope: scope})
	}
	slices.Reverse(items)
	return node.wireResult("historyPage", historyPage{ProtocolVersion: 1, SchemaID: harnessprotocol.SchemaID, NodeID: state.NodeID, Epoch: state.Epoch, SnapshotStateVersion: state.StateVersion, LastEventSeq: state.LastEventSeq, Items: items, NextCursor: next, PageType: "history", DialogID: dialogID})
}

func (node *Node) Dialogs(ctx context.Context, trust TrustContext, cursor string, limit int) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	limit, ok := normalizedLimit(limit)
	if !ok {
		return node.Invalid("limit is invalid")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "dialogs are unavailable", "", nil, "")
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "dialogs are unavailable", "", nil, "")
	}
	offset, failure := decodeCursor(cursor, "dialogs", state)
	if failure != nil {
		return node.commandError(failure, "")
	}
	rows, err := tx.QueryContext(ctx, `SELECT d.dialog_id,d.version,d.title,d.created_at FROM dialogs d WHERE d.node_id=? AND d.owner_id=? AND NOT EXISTS (
		SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted') ORDER BY d.created_at,d.dialog_id LIMIT ? OFFSET ?`, state.NodeID, state.OwnerID, limit+1, offset)
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "dialogs are unavailable", "", nil, "")
	}
	items := make([]harnessprotocol.DialogSummary, 0, limit)
	for rows.Next() {
		var item harnessprotocol.DialogSummary
		var title sql.NullString
		if err := rows.Scan(&item.DialogID, &item.Version, &title, &item.CreatedAt); err != nil {
			rows.Close()
			return node.errorResult(http.StatusServiceUnavailable, "not_durable", "dialogs are unavailable", "", nil, "")
		}
		item.Title = title.String
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "dialogs are unavailable", "", nil, "")
	}
	rows.Close()
	var next *string
	if len(items) > limit {
		items = items[:limit]
		next = encodeCursor(pageCursor{Epoch: state.Epoch, StateVersion: state.StateVersion, Offset: offset + int64(limit), Scope: "dialogs"})
	}
	return node.wireResult("dialogPage", harnessprotocol.Page[harnessprotocol.DialogSummary]{ProtocolVersion: 1, SchemaID: harnessprotocol.SchemaID, NodeID: state.NodeID, Epoch: state.Epoch, SnapshotStateVersion: state.StateVersion, LastEventSeq: state.LastEventSeq, Items: items, NextCursor: next, PageType: "dialogs"})
}

func (node *Node) Requests(ctx context.Context, trust TrustContext, stateFilter, cursor string, limit int) Result {
	return node.requests(ctx, trust, "", stateFilter, cursor, limit)
}

func (node *Node) RequestsForDialog(ctx context.Context, trust TrustContext, dialogID, stateFilter, cursor string, limit int) Result {
	if !uuidPattern.MatchString(dialogID) {
		return node.Invalid("dialog id is invalid")
	}
	return node.requests(ctx, trust, dialogID, stateFilter, cursor, limit)
}

func (node *Node) requests(ctx context.Context, trust TrustContext, dialogID, stateFilter, cursor string, limit int) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	limit, ok := normalizedLimit(limit)
	allowed := []string{"", "queued", "cancelled", "dispatching", "active", "completed", "failed", "interrupted", "unknown"}
	if !ok || !slices.Contains(allowed, stateFilter) {
		return node.Invalid("request query is invalid")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return node.errorResult(503, "not_durable", "requests are unavailable", "", nil, "")
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return node.errorResult(503, "not_durable", "requests are unavailable", "", nil, "")
	}
	scope := "requests:" + dialogID + ":" + stateFilter
	offset, failure := decodeCursor(cursor, scope, state)
	if failure != nil {
		return node.commandError(failure, "")
	}
	query := `SELECT r.request_id,r.dialog_id,r.input_message_id,r.queue_sequence,r.version,r.status FROM requests r JOIN dialogs d ON d.dialog_id=r.dialog_id WHERE d.node_id=? AND d.owner_id=? AND NOT EXISTS (
		SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`
	arguments := []any{state.NodeID, state.OwnerID}
	if dialogID != "" {
		query += " AND r.dialog_id=?"
		arguments = append(arguments, dialogID)
	}
	if stateFilter != "" {
		query += " AND r.status=?"
		arguments = append(arguments, stateFilter)
	}
	query += " ORDER BY r.queue_sequence,r.request_id LIMIT ? OFFSET ?"
	arguments = append(arguments, limit+1, offset)
	rows, err := tx.QueryContext(ctx, query, arguments...)
	if err != nil {
		return node.errorResult(503, "not_durable", "requests are unavailable", "", nil, "")
	}
	items := make([]harnessprotocol.Request, 0, limit+1)
	for rows.Next() {
		var item harnessprotocol.Request
		if err := rows.Scan(&item.RequestID, &item.DialogID, &item.InputMessageID, &item.QueueSequence, &item.Version, &item.Status); err != nil {
			rows.Close()
			return node.errorResult(503, "not_durable", "requests are unavailable", "", nil, "")
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return node.errorResult(503, "not_durable", "requests are unavailable", "", nil, "")
	}
	rows.Close()
	var next *string
	if len(items) > limit {
		items = items[:limit]
		next = encodeCursor(pageCursor{Epoch: state.Epoch, StateVersion: state.StateVersion, Offset: offset + int64(limit), Scope: scope})
	}
	return node.wireResult("requestPage", harnessprotocol.Page[harnessprotocol.Request]{ProtocolVersion: 1, SchemaID: harnessprotocol.SchemaID, NodeID: state.NodeID, Epoch: state.Epoch, SnapshotStateVersion: state.StateVersion, LastEventSeq: state.LastEventSeq, Items: items, NextCursor: next, PageType: "requests"})
}

type attemptPage struct {
	ProtocolVersion      int                       `json:"protocolVersion"`
	SchemaID             string                    `json:"schemaId"`
	NodeID               string                    `json:"nodeId"`
	Epoch                int64                     `json:"epoch"`
	SnapshotStateVersion int64                     `json:"snapshotStateVersion"`
	LastEventSeq         int64                     `json:"lastEventSeq"`
	DialogID             string                    `json:"dialogId"`
	RequestID            string                    `json:"requestId"`
	Items                []harnessprotocol.Attempt `json:"items"`
	NextCursor           *string                   `json:"nextCursor"`
	PageType             string                    `json:"pageType"`
}

func scanAttempt(scanner interface{ Scan(...any) error }) (harnessprotocol.Attempt, error) {
	var item harnessprotocol.Attempt
	var started, finished sql.NullString
	err := scanner.Scan(&item.AttemptID, &item.DialogID, &item.RequestID, &item.Generation, &item.Version, &item.State, &item.EffectStatus, &started, &finished)
	item.StartedAt, item.FinishedAt = started.String, finished.String
	return item, err
}

func (node *Node) Attempt(ctx context.Context, trust TrustContext, attemptID string) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	state, err := loadState(ctx, node.db)
	if err != nil {
		return node.errorResult(503, "not_durable", "attempt is unavailable", attemptID, nil, "")
	}
	item, err := scanAttempt(node.db.QueryRowContext(ctx, `SELECT a.attempt_id,a.dialog_id,a.request_id,a.generation,a.version,a.state,a.effect_status,a.started_at,a.finished_at FROM attempts a JOIN dialogs d ON d.dialog_id=a.dialog_id WHERE a.attempt_id=? AND d.node_id=? AND d.owner_id=? AND NOT EXISTS (
		SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`, attemptID, state.NodeID, state.OwnerID))
	if err != nil {
		if isNoRows(err) {
			return node.errorResult(404, "not_found", "attempt was not found", attemptID, nil, "")
		}
		return node.errorResult(503, "not_durable", "attempt is unavailable", attemptID, nil, "")
	}
	return node.wireResult("attemptRead", harnessprotocol.AttemptRead{ProtocolVersion: 1, SchemaID: harnessprotocol.SchemaID, NodeID: state.NodeID, Epoch: state.Epoch, StateVersion: state.StateVersion, Attempt: item})
}

func (node *Node) Attempts(ctx context.Context, trust TrustContext, requestID, cursor string, limit int) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	limit, ok := normalizedLimit(limit)
	if !ok {
		return node.Invalid("limit is invalid")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return node.errorResult(503, "not_durable", "attempts are unavailable", requestID, nil, "")
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return node.errorResult(503, "not_durable", "attempts are unavailable", requestID, nil, "")
	}
	var dialogID string
	if err := tx.QueryRowContext(ctx, `SELECT r.dialog_id FROM requests r JOIN dialogs d ON d.dialog_id=r.dialog_id WHERE r.request_id=? AND d.node_id=? AND d.owner_id=? AND NOT EXISTS (
		SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`, requestID, state.NodeID, state.OwnerID).Scan(&dialogID); err != nil {
		if isNoRows(err) {
			return node.errorResult(404, "not_found", "request was not found", requestID, nil, "")
		}
		return node.errorResult(503, "not_durable", "attempts are unavailable", requestID, nil, "")
	}
	scope := "attempts:" + requestID
	offset, failure := decodeCursor(cursor, scope, state)
	if failure != nil {
		return node.commandError(failure, requestID)
	}
	rows, err := tx.QueryContext(ctx, `SELECT attempt_id,dialog_id,request_id,generation,version,state,effect_status,started_at,finished_at FROM attempts WHERE request_id=? ORDER BY generation LIMIT ? OFFSET ?`, requestID, limit+1, offset)
	if err != nil {
		return node.errorResult(503, "not_durable", "attempts are unavailable", requestID, nil, "")
	}
	items := make([]harnessprotocol.Attempt, 0, limit+1)
	for rows.Next() {
		item, err := scanAttempt(rows)
		if err != nil {
			rows.Close()
			return node.errorResult(503, "not_durable", "attempts are unavailable", requestID, nil, "")
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return node.errorResult(503, "not_durable", "attempts are unavailable", requestID, nil, "")
	}
	rows.Close()
	var next *string
	if len(items) > limit {
		items = items[:limit]
		next = encodeCursor(pageCursor{Epoch: state.Epoch, StateVersion: state.StateVersion, Offset: offset + int64(limit), Scope: scope})
	}
	return node.wireResult("attemptPage", attemptPage{ProtocolVersion: 1, SchemaID: harnessprotocol.SchemaID, NodeID: state.NodeID, Epoch: state.Epoch, SnapshotStateVersion: state.StateVersion, LastEventSeq: state.LastEventSeq, DialogID: dialogID, RequestID: requestID, Items: items, NextCursor: next, PageType: "attempts"})
}

func (node *Node) AttemptEvents(ctx context.Context, trust TrustContext, attemptID string, after int64, limit int) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	limit, ok := normalizedLimit(limit)
	if !ok || after < 0 || after > harnessprotocol.MaximumSafeInteger {
		return node.Invalid("event query is invalid")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return node.errorResult(503, "not_durable", "events are unavailable", attemptID, nil, "")
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return node.errorResult(503, "not_durable", "events are unavailable", attemptID, nil, "")
	}
	var dialogID string
	if err := tx.QueryRowContext(ctx, `SELECT a.dialog_id FROM attempts a JOIN dialogs d ON d.dialog_id=a.dialog_id WHERE a.attempt_id=? AND d.node_id=? AND d.owner_id=? AND NOT EXISTS (
		SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`, attemptID, state.NodeID, state.OwnerID).Scan(&dialogID); err != nil {
		if isNoRows(err) {
			return node.errorResult(404, "not_found", "attempt was not found", attemptID, nil, "")
		}
		return node.errorResult(503, "not_durable", "events are unavailable", attemptID, nil, "")
	}
	if after > state.LastEventSeq {
		return node.errorResult(409, "stale", "event cursor is ahead of durable history", attemptID, nil, "")
	}
	rows, err := tx.QueryContext(ctx, `SELECT event_json FROM events WHERE node_id=? AND attempt_id=? AND seq>? ORDER BY seq LIMIT ?`, state.NodeID, attemptID, after, limit+1)
	if err != nil {
		return node.errorResult(503, "not_durable", "events are unavailable", attemptID, nil, "")
	}
	defer rows.Close()
	items := make([]json.RawMessage, 0, limit+1)
	encodedBytes := 0
	hasMore := false
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return node.errorResult(503, "not_durable", "events are unavailable", attemptID, nil, "")
		}
		var envelope harnessprotocol.EventEnvelope
		if json.Unmarshal(raw, &envelope) != nil || envelope.AttemptID != attemptID || envelope.DialogID != dialogID || envelope.Epoch != state.Epoch {
			return node.errorResult(503, "not_durable", "event scope is invalid", attemptID, nil, "")
		}
		if len(items) == limit || encodedBytes+len(raw) > harnessprotocol.MaximumWireBytes-4096 {
			hasMore = true
			break
		}
		items = append(items, raw)
		encodedBytes += len(raw)
	}
	if err := rows.Err(); err != nil {
		return node.errorResult(503, "not_durable", "events are unavailable", attemptID, nil, "")
	}
	var next *string
	if hasMore {
		var envelope harnessprotocol.EventEnvelope
		_ = json.Unmarshal(items[len(items)-1], &envelope)
		value := strconv.FormatInt(envelope.Seq, 10)
		next = &value
	}
	return node.wireResult("eventPage", eventPage{ProtocolVersion: 1, SchemaID: harnessprotocol.SchemaID, NodeID: state.NodeID, Epoch: state.Epoch, SnapshotStateVersion: state.StateVersion, LastEventSeq: state.LastEventSeq, Items: items, NextCursor: next, PageType: "events", DialogID: dialogID, AttemptID: attemptID})
}
