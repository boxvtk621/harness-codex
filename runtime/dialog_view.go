package node

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"github.com/boxvtk621/harness-codex/internal/dialogview"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

type dialogActivityCursor struct {
	Epoch          int64  `json:"e"`
	StateVersion   int64  `json:"s"`
	LastActivityAt string `json:"a"`
	DialogID       string `json:"d"`
}

var dialogActivityTimestampPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$`)

func encodeDialogActivityCursor(cursor dialogActivityCursor) *string {
	raw, _ := json.Marshal(cursor)
	value := base64.RawURLEncoding.EncodeToString(raw)
	return &value
}

func decodeDialogActivityCursor(raw string, state durableState) (dialogActivityCursor, *commandFailure) {
	if raw == "" {
		return dialogActivityCursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) > harnessprotocol.MaximumCursorBytes {
		return dialogActivityCursor{}, &commandFailure{status: http.StatusBadRequest, code: "invalid", message: "dialog cursor is invalid"}
	}
	var cursor dialogActivityCursor
	if json.Unmarshal(decoded, &cursor) != nil || cursor.Epoch != state.Epoch || cursor.StateVersion != state.StateVersion || !dialogActivityTimestampPattern.MatchString(cursor.LastActivityAt) || !uuidPattern.MatchString(cursor.DialogID) {
		return dialogActivityCursor{}, &commandFailure{status: http.StatusConflict, code: "stale", message: "dialog cursor is invalid or stale"}
	}
	return cursor, nil
}

func (node *Node) dialogViewResult(value any) Result {
	body, err := dialogview.Marshal(value)
	if err != nil || len(body) > harnessprotocol.MaximumWireBytes {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "dialog view response is invalid", "", nil, "")
	}
	return Result{HTTPStatus: http.StatusOK, Body: body}
}

func loadDialogView(ctx context.Context, tx *sql.Tx, dialogID string) (dialogview.Dialog, error) {
	var item dialogview.Dialog
	var title sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT dialog_id,version,title,created_at FROM dialogs WHERE dialog_id=?", dialogID).Scan(&item.DialogID, &item.Version, &title, &item.CreatedAt); err != nil {
		return item, err
	}
	item.Title = title.String
	item.LastActivityAt = item.CreatedAt
	var activity string
	err := tx.QueryRowContext(ctx, `SELECT happened_at FROM (
		SELECT created_at AS happened_at FROM messages WHERE dialog_id=?
		UNION ALL SELECT updated_at FROM requests WHERE dialog_id=?
		UNION ALL SELECT created_at FROM events WHERE dialog_id=?
	) ORDER BY happened_at DESC LIMIT 1`, dialogID, dialogID, dialogID).Scan(&activity)
	if err == nil {
		item.LastActivityAt = activity
	} else if !errors.Is(err, sql.ErrNoRows) {
		return item, err
	}
	item.State = "idle"
	var requestID, attemptID, attemptState string
	err = tx.QueryRowContext(ctx, `SELECT request_id,attempt_id,state FROM attempts WHERE dialog_id=?
		AND state IN('dispatching','running','waiting_input','stopping','unknown') ORDER BY generation DESC LIMIT 1`, dialogID).Scan(&requestID, &attemptID, &attemptState)
	if err == nil {
		item.ActiveRequestID = requestID
		item.ActiveAttemptID = attemptID
		switch attemptState {
		case "dispatching":
			item.State = "dispatching"
		case "unknown":
			item.State = "unknown"
		case "running", "waiting_input", "stopping":
			item.State = "active"
		default:
			return item, errors.New("dialog attempt state is invalid")
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return item, err
	}
	if item.ActiveAttemptID == "" {
		var requestState string
		err = tx.QueryRowContext(ctx, `SELECT request_id,status FROM requests WHERE dialog_id=?
			ORDER BY CASE WHEN status='queued' THEN 0 ELSE 1 END,queue_sequence DESC LIMIT 1`, dialogID).Scan(&requestID, &requestState)
		if err == nil {
			switch requestState {
			case "queued", "cancelled", "dispatching", "active", "completed", "failed", "interrupted", "unknown":
				item.State = requestState
			default:
				return item, errors.New("dialog request state is invalid")
			}
			if requestState == "queued" || requestState == "dispatching" || requestState == "active" || requestState == "unknown" {
				item.ActiveRequestID = requestID
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return item, err
		}
	}
	return item, nil
}

func (node *Node) DialogViews(ctx context.Context, trust TrustContext, cursor string, limit int) Result {
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
		return node.errorResult(503, "not_durable", "dialog views are unavailable", "", nil, "")
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return node.errorResult(503, "not_durable", "dialog views are unavailable", "", nil, "")
	}
	before, failure := decodeDialogActivityCursor(cursor, state)
	if failure != nil {
		return node.commandError(failure, "")
	}
	rows, err := tx.QueryContext(ctx, `WITH activity AS (
		SELECT d.dialog_id,max(
			d.created_at,
			coalesce((SELECT max(created_at) FROM messages WHERE dialog_id=d.dialog_id),d.created_at),
			coalesce((SELECT max(updated_at) FROM requests WHERE dialog_id=d.dialog_id),d.created_at),
			coalesce((SELECT max(created_at) FROM events WHERE dialog_id=d.dialog_id),d.created_at)
		) AS last_activity_at
		FROM dialogs d WHERE d.node_id=? AND d.owner_id=? AND NOT EXISTS (
			SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')
	)
	SELECT dialog_id,last_activity_at FROM activity
	WHERE ?='' OR last_activity_at<? OR (last_activity_at=? AND dialog_id>?)
	ORDER BY last_activity_at DESC,dialog_id LIMIT ?`, state.NodeID, state.OwnerID, before.LastActivityAt, before.LastActivityAt, before.LastActivityAt, before.DialogID, limit+1)
	if err != nil {
		return node.errorResult(503, "not_durable", "dialog views are unavailable", "", nil, "")
	}
	defer rows.Close()
	type activityKey struct{ dialogID, lastActivityAt string }
	keys := make([]activityKey, 0, limit+1)
	for rows.Next() {
		var key activityKey
		if err := rows.Scan(&key.dialogID, &key.lastActivityAt); err != nil {
			return node.errorResult(503, "not_durable", "dialog views are unavailable", "", nil, "")
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return node.errorResult(503, "not_durable", "dialog views are unavailable", "", nil, "")
	}
	hasMore := len(keys) > limit
	if hasMore {
		keys = keys[:limit]
	}
	items := make([]dialogview.Dialog, 0, len(keys))
	for _, key := range keys {
		item, err := loadDialogView(ctx, tx, key.dialogID)
		if err != nil {
			return node.errorResult(503, "not_durable", "dialog view is invalid", key.dialogID, nil, "")
		}
		items = append(items, item)
	}
	var next *string
	if hasMore && len(keys) > 0 {
		last := keys[len(keys)-1]
		next = encodeDialogActivityCursor(dialogActivityCursor{Epoch: state.Epoch, StateVersion: state.StateVersion, LastActivityAt: last.lastActivityAt, DialogID: last.dialogID})
	}
	return node.dialogViewResult(dialogview.Page{ProtocolVersion: 1, SchemaID: dialogview.SchemaID, NodeID: state.NodeID, Epoch: state.Epoch, SnapshotStateVersion: state.StateVersion, LastEventSeq: state.LastEventSeq, Items: items, NextCursor: next, PageType: dialogview.PageType})
}

func (node *Node) DialogView(ctx context.Context, trust TrustContext, dialogID string) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	if !uuidPattern.MatchString(dialogID) {
		return node.Invalid("dialog id is invalid")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return node.errorResult(503, "not_durable", "dialog view is unavailable", dialogID, nil, "")
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return node.errorResult(503, "not_durable", "dialog view is unavailable", dialogID, nil, "")
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM dialogs d WHERE d.dialog_id=? AND d.node_id=? AND d.owner_id=? AND NOT EXISTS (
		SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`, dialogID, state.NodeID, state.OwnerID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return node.errorResult(404, "not_found", "dialog was not found", dialogID, nil, "")
	} else if err != nil {
		return node.errorResult(503, "not_durable", "dialog view is unavailable", dialogID, nil, "")
	}
	item, err := loadDialogView(ctx, tx, dialogID)
	if err != nil {
		return node.errorResult(503, "not_durable", "dialog view is invalid", dialogID, nil, "")
	}
	return node.dialogViewResult(dialogview.Read{ProtocolVersion: 1, SchemaID: dialogview.SchemaID, NodeID: state.NodeID, Epoch: state.Epoch, StateVersion: state.StateVersion, LastEventSeq: state.LastEventSeq, Dialog: item})
}
