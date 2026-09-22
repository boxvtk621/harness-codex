package node

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/boxvtk621/harness-codex/internal/diagnosticlog"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

type commandFailure struct {
	status         int
	code           string
	message        string
	currentVersion *int64
	currentState   string
}

func (failure *commandFailure) Error() string { return failure.code }

func reject(status int, code, message string) error {
	return &commandFailure{status: status, code: code, message: message}
}

func stale(version int64, state string) error {
	return &commandFailure{status: http.StatusConflict, code: "stale", message: "expected state is stale", currentVersion: &version, currentState: state}
}

type postCommitAction struct {
	commandID string
	kind      string
	attemptID string
	messageID string
	actorID   string
	payload   json.RawMessage
}

// SubmitCommand is the only durable command admission entry point. TrustContext
// carries routing and fencing data only, never caller identity.
func (node *Node) SubmitCommand(ctx context.Context, trust TrustContext, raw []byte) (response Result) {
	started := time.Now()
	correlation := bestEffortCommandID(raw)
	kind := ""
	duplicate := false
	defer func() {
		event, level := diagnosticlog.EventCommandRejected, diagnosticlog.LevelWarn
		if duplicate {
			event, level = diagnosticlog.EventCommandDuplicate, diagnosticlog.LevelInfo
		} else if response.Committed {
			event, level = diagnosticlog.EventCommandAccepted, diagnosticlog.LevelInfo
		}
		node.config.Logger.Emit(level, event, diagnosticlog.Fields{
			NodeID: node.config.NodeID, CommandID: correlation, Operation: kind,
			Outcome: fmt.Sprintf("http_%d", response.HTTPStatus), DurationMS: time.Since(started).Milliseconds(),
		})
	}()
	if trust.TransportNodeID != node.config.NodeID {
		return node.errorResult(http.StatusNotFound, "not_found", "node was not found", correlation, nil, "")
	}
	canonical, digest, err := CanonicalCommand(raw)
	if err != nil {
		return node.errorResult(http.StatusBadRequest, "invalid", "command does not match harness-wire-v2", correlation, nil, "")
	}
	var envelope harnessprotocol.CommandEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return node.errorResult(http.StatusBadRequest, "invalid", "command cannot be decoded", correlation, nil, "")
	}
	correlation = envelope.CommandID
	kind = string(envelope.Kind)
	if envelope.Kind == harnessprotocol.CommandDialogDelete {
		return node.errorResult(http.StatusForbidden, "forbidden", "dialog deletion requires the logical delete coordinator", correlation, nil, "")
	}

	node.mu.Lock()
	defer node.mu.Unlock()
	reserveReleased := false
	defer func() { node.replenishControlReserve(reserveReleased) }()

	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "durable store is unavailable", correlation, nil, "")
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "durable state is unavailable", correlation, nil, "")
	}
	if expected := trust.ExpectedIdentity; expected != nil &&
		(expected.NodeID != node.config.NodeID || expected.RegistryVersion != state.RegistryVersion ||
			expected.IdentityEpoch != state.Epoch || expected.Adapter.Kind != string(node.identity.Kind) ||
			expected.Adapter.Version != node.identity.Version) {
		return node.errorResult(http.StatusConflict, "stale", "routing identity changed", correlation, nil, "")
	}
	outcome, found, err := loadCommandOutcome(ctx, tx, envelope.CommandID)
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "command lookup failed", correlation, nil, "")
	}
	if found {
		if outcome.hash != digest {
			return node.errorResult(http.StatusConflict, "id_conflict", "commandId already names different bytes", correlation, nil, "")
		}
		if deleted, lookupErr := commandOutcomeTargetsDeletedDialog(ctx, tx, outcome); lookupErr != nil {
			return node.errorResult(http.StatusServiceUnavailable, "not_durable", "command scope lookup failed", correlation, nil, "")
		} else if deleted {
			return node.errorResult(http.StatusNotFound, "not_found", "command was not found", correlation, nil, "")
		}
		duplicate = true
		return Result{HTTPStatus: outcome.status, Body: outcome.body}
	}
	if err := node.authorizeObject(ctx, tx, envelope); err != nil {
		return node.commandError(err, correlation)
	}
	hold, err := node.coveringHoldForCommand(ctx, tx, envelope)
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "hold lookup failed", correlation, nil, "")
	}
	if hold != nil {
		reserveReleased, err = node.releaseControlReserve()
		if err != nil || !reserveReleased {
			return node.errorResult(http.StatusServiceUnavailable, "not_durable", "control reserve is unavailable", correlation, nil, "")
		}
		return node.commitCommandRejection(ctx, tx, state, trust, envelope, canonical, digest, *hold)
	}
	if !harnessprotocol.IsAdmissionCommand(envelope.Kind) {
		// Release the physically allocated reserve before any control write,
		// regardless of the advisory space probe. This avoids replaying a
		// transaction after SQLITE_FULL, whose documented outcome may be either a
		// statement rollback or a whole-transaction rollback. The bounded control
		// transaction gets 8 MiB of headroom and any later write/COMMIT error fails
		// closed without retry (https://www.sqlite.org/lang_transaction.html#response_to_errors_within_a_transaction).
		storageLow := node.storageBelowAdmissionFloor() || node.physicalStorageBelowAdmissionFloor()
		reserveReleased, err = node.releaseControlReserve()
		if err != nil || !reserveReleased {
			return node.errorResult(http.StatusServiceUnavailable, "not_durable", "control reserve is unavailable", correlation, nil, "")
		}
		if storageLow {
			state.EngineReadiness = "blocked"
			state.BlockedReasons = addReason(state.BlockedReasons, "storage_unavailable")
		}
	}
	if harnessprotocol.IsAdmissionCommand(envelope.Kind) {
		space, measureErr := node.config.Space.Measure(node.config.DataDir)
		if measureErr != nil || space.FreeBytes < admissionFloor(space.TotalBytes) {
			return node.errorResult(http.StatusServiceUnavailable, "not_durable", "admission storage floor is unavailable", correlation, nil, "")
		}
	}
	references, result, blocking, action, err := node.applyCommand(ctx, tx, &state, trust, envelope)
	if err != nil {
		return node.commandError(err, correlation)
	}
	receiptID, err := node.newID()
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "receipt identity is unavailable", correlation, nil, "")
	}
	referenceJSON, _ := json.Marshal(references)
	receipt := harnessprotocol.Receipt{
		ProtocolVersion: harnessprotocol.ProtocolVersion, SchemaID: harnessprotocol.SchemaID,
		CommandID: envelope.CommandID, CommandKind: envelope.Kind, ReceiptID: receiptID,
		AcceptedAt: timestamp(node.config.Clock()), NodeID: node.config.NodeID,
		EventSeq: state.LastEventSeq, Result: result, BlockingReason: blocking, References: referenceJSON,
	}
	receiptJSON, err := json.Marshal(receipt)
	if err != nil || harnessprotocol.Validate("receipt", receiptJSON) != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "internal receipt is invalid", correlation, nil, "")
	}
	if action.kind != "" {
		action.commandID = envelope.CommandID
		if _, err := tx.ExecContext(ctx, `INSERT INTO control_actions(command_id,kind,attempt_id,message_id,actor_id,payload,status)
			VALUES(?,?,?,?,?,?,'pending')`, action.commandID, action.kind, action.attemptID, nullText(action.messageID), nullText(action.actorID), []byte(action.payload)); err != nil {
			return node.errorResult(http.StatusServiceUnavailable, "not_durable", "control intent commit failed", correlation, nil, "")
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO commands(command_id,actor_id,node_id,kind,canonical_json,canonical_payload_hash,receipt_json,accepted_at,event_seq)
		VALUES(?,?,?,?,?,?,?,?,?)`, envelope.CommandID, node.config.OwnerID, node.config.NodeID, envelope.Kind, canonical, digest, receiptJSON, receipt.AcceptedAt, receipt.EventSeq); err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "command commit failed", correlation, nil, "")
	}
	if err := saveState(ctx, tx, state); err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "state commit failed", correlation, nil, "")
	}
	if err := node.checkFault(FaultBeforeCommit); err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "commit was not attempted", correlation, nil, "")
	}
	if err := tx.Commit(); err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "atomic commit failed", correlation, nil, "")
	}
	// Wake from durable state before response delivery can fail. The wake is
	// nonblocking and detached from the HTTP request lifetime; the worker claims
	// the committed intent exactly once.
	node.afterCommit(context.Background(), action)
	if err := node.checkFault(FaultAfterCommit); err != nil {
		return Result{HTTPStatus: http.StatusServiceUnavailable, Body: node.errorResult(http.StatusServiceUnavailable, "node_unavailable", "receipt delivery was interrupted", correlation, nil, "").Body, Committed: true}
	}
	response = Result{HTTPStatus: http.StatusAccepted, Body: receiptJSON, Committed: true}
	return response
}

func commandOutcomeTargetsDeletedDialog(ctx context.Context, tx *sql.Tx, outcome storedCommandOutcome) (bool, error) {
	dialogID := ""
	if outcome.accepted {
		var receipt harnessprotocol.Receipt
		var references struct {
			DialogID string `json:"dialogId"`
		}
		if json.Unmarshal(outcome.body, &receipt) == nil {
			_ = json.Unmarshal(receipt.References, &references)
			dialogID = references.DialogID
		}
	}
	var envelope harnessprotocol.CommandEnvelope
	var target struct {
		DialogID       string `json:"dialogId"`
		RequestID      string `json:"requestId"`
		AttemptID      string `json:"attemptId"`
		ApprovalID     string `json:"approvalId"`
		InputRequestID string `json:"inputRequestId"`
	}
	if dialogID == "" && json.Unmarshal(outcome.canonical, &envelope) == nil && json.Unmarshal(envelope.Target, &target) == nil {
		dialogID = target.DialogID
		var err error
		switch {
		case dialogID != "":
		case target.RequestID != "":
			err = tx.QueryRowContext(ctx, "SELECT dialog_id FROM requests WHERE request_id=?", target.RequestID).Scan(&dialogID)
		case target.AttemptID != "":
			err = tx.QueryRowContext(ctx, "SELECT dialog_id FROM attempts WHERE attempt_id=?", target.AttemptID).Scan(&dialogID)
		case target.ApprovalID != "":
			err = tx.QueryRowContext(ctx, `SELECT a.dialog_id FROM approvals p JOIN attempts a ON a.attempt_id=p.attempt_id WHERE p.approval_id=?`, target.ApprovalID).Scan(&dialogID)
		case target.InputRequestID != "":
			err = tx.QueryRowContext(ctx, `SELECT a.dialog_id FROM input_requests i JOIN attempts a ON a.attempt_id=i.attempt_id WHERE i.input_request_id=?`, target.InputRequestID).Scan(&dialogID)
		}
		if err != nil && !isNoRows(err) {
			return false, err
		}
	}
	if dialogID == "" {
		return false, nil
	}
	var deleted int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM events WHERE dialog_id=? AND projection_key='dialog.deleted')`, dialogID).Scan(&deleted); err != nil {
		return false, err
	}
	return deleted != 0, nil
}

func bestEffortCommandID(raw []byte) string {
	var envelope struct {
		CommandID string `json:"commandId"`
	}
	_ = json.Unmarshal(raw, &envelope)
	if !uuidPattern.MatchString(envelope.CommandID) {
		return ""
	}
	return envelope.CommandID
}

func (node *Node) commandError(err error, correlation string) Result {
	var failure *commandFailure
	if errors.As(err, &failure) {
		return node.errorResult(failure.status, failure.code, failure.message, correlation, failure.currentVersion, failure.currentState)
	}
	// Raw errors may contain storage paths, provider output or content. Emit
	// only the stable classification and correlation identifier.
	node.config.Logger.Emit(diagnosticlog.LevelError, diagnosticlog.EventCommandFailed, diagnosticlog.Fields{NodeID: node.config.NodeID, Reason: "not_durable", CommandID: correlation})
	return node.errorResult(http.StatusServiceUnavailable, "not_durable", "durable operation failed", correlation, nil, "")
}

func (node *Node) authorizeObject(ctx context.Context, tx *sql.Tx, envelope harnessprotocol.CommandEnvelope) error {
	var target struct {
		NodeID         string `json:"nodeId"`
		DialogID       string `json:"dialogId"`
		RequestID      string `json:"requestId"`
		AttemptID      string `json:"attemptId"`
		ApprovalID     string `json:"approvalId"`
		InputRequestID string `json:"inputRequestId"`
	}
	if err := json.Unmarshal(envelope.Target, &target); err != nil || target.NodeID != node.config.NodeID {
		return reject(http.StatusNotFound, "not_found", "target was not found")
	}
	var nodeID, ownerID string
	var err error
	switch envelope.Kind {
	case harnessprotocol.CommandDialogCreate, harnessprotocol.CommandQueueResume:
		return nil
	case harnessprotocol.CommandMessageEnqueue, harnessprotocol.CommandMessageSteer:
		err = tx.QueryRowContext(ctx, `SELECT d.node_id,d.owner_id FROM dialogs d WHERE d.dialog_id=? AND NOT EXISTS (
			SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`, target.DialogID).Scan(&nodeID, &ownerID)
	case harnessprotocol.CommandRequestCancel:
		err = tx.QueryRowContext(ctx, `SELECT d.node_id,d.owner_id FROM requests r JOIN dialogs d ON d.dialog_id=r.dialog_id WHERE r.request_id=? AND NOT EXISTS (
			SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`, target.RequestID).Scan(&nodeID, &ownerID)
	case harnessprotocol.CommandAttemptStop, harnessprotocol.CommandAttemptRetry:
		err = tx.QueryRowContext(ctx, `SELECT d.node_id,d.owner_id FROM attempts a JOIN dialogs d ON d.dialog_id=a.dialog_id WHERE a.attempt_id=? AND NOT EXISTS (
			SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`, target.AttemptID).Scan(&nodeID, &ownerID)
	case harnessprotocol.CommandApprovalRespond:
		err = tx.QueryRowContext(ctx, `SELECT d.node_id,d.owner_id FROM approvals p JOIN attempts a ON a.attempt_id=p.attempt_id JOIN dialogs d ON d.dialog_id=a.dialog_id WHERE p.approval_id=? AND p.attempt_id=? AND NOT EXISTS (
			SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`, target.ApprovalID, target.AttemptID).Scan(&nodeID, &ownerID)
	case harnessprotocol.CommandInputRespond:
		err = tx.QueryRowContext(ctx, `SELECT d.node_id,d.owner_id FROM input_requests i JOIN attempts a ON a.attempt_id=i.attempt_id JOIN dialogs d ON d.dialog_id=a.dialog_id WHERE i.input_request_id=? AND i.attempt_id=? AND NOT EXISTS (
			SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`, target.InputRequestID, target.AttemptID).Scan(&nodeID, &ownerID)
	default:
		return reject(http.StatusBadRequest, "invalid", "unsupported command kind")
	}
	if isNoRows(err) || nodeID != node.config.NodeID || ownerID != node.config.OwnerID {
		return reject(http.StatusNotFound, "not_found", "target was not found")
	}
	if err != nil {
		return fmt.Errorf("object isolation lookup: %w", err)
	}
	return nil
}

func (node *Node) applyCommand(ctx context.Context, tx *sql.Tx, state *durableState, trust TrustContext, envelope harnessprotocol.CommandEnvelope) (any, string, string, postCommitAction, error) {
	switch envelope.Kind {
	case harnessprotocol.CommandDialogCreate:
		return node.applyDialogCreate(ctx, tx, state, envelope)
	case harnessprotocol.CommandMessageEnqueue:
		return node.applyMessageEnqueue(ctx, tx, state, envelope)
	case harnessprotocol.CommandRequestCancel:
		return node.applyRequestCancel(ctx, tx, state, envelope)
	case harnessprotocol.CommandQueueResume:
		return node.applyQueueResume(ctx, tx, state, envelope)
	case harnessprotocol.CommandAttemptStop:
		return node.applyAttemptStop(ctx, tx, state, envelope)
	case harnessprotocol.CommandAttemptRetry:
		return node.applyAttemptRetry(ctx, tx, state, envelope)
	case harnessprotocol.CommandMessageSteer:
		return node.applyMessageSteer(ctx, tx, state, envelope)
	case harnessprotocol.CommandApprovalRespond:
		return node.applyApproval(ctx, tx, state, trust, envelope)
	case harnessprotocol.CommandInputRespond:
		return node.applyInput(ctx, tx, state, trust, envelope)
	default:
		return nil, "", "", postCommitAction{}, reject(http.StatusBadRequest, "invalid", "unsupported command kind")
	}
}
