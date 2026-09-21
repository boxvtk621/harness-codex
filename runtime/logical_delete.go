package node

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/boxvtk621/harness-codex/internal/harnessbarrier"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/logicaldelete"
	"github.com/boxvtk621/harness-codex/internal/strictjson"
)

// DeleteLogicalDialog applies dialog.delete only through the exact R13 hold.
// It commits the node tombstone, ordinary command receipt, private operation
// receipt, and hold release in one SQLite transaction.
func (node *Node) DeleteLogicalDialog(ctx context.Context, trust OperatorTrustContext, raw []byte) Result {
	if !trust.PeerVerified || trust.ActorID == "" || trust.ActorID != node.config.OwnerID {
		return node.errorResult(http.StatusForbidden, "forbidden", "trusted operator is not allowed", "", nil, "")
	}
	if trust.TransportNodeID != node.config.NodeID {
		return node.errorResult(http.StatusNotFound, "not_found", "node was not found", "", nil, "")
	}
	var request logicaldelete.NodeRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) == 0 || len(raw) > harnessbarrier.MaximumWireBytes || !strictjson.Valid(raw) ||
		decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || logicaldelete.ValidateNodeRequest(request) != nil {
		return node.errorResult(http.StatusBadRequest, "invalid", "logical delete request is invalid", "", nil, "")
	}
	requestHash, _ := logicaldelete.NodeRequestHash(request)
	if request.NodeID != node.config.NodeID {
		return node.errorResult(http.StatusNotFound, "not_found", "node was not found", request.OperationID, nil, "")
	}

	node.startGate.Lock()
	defer node.startGate.Unlock()
	node.mu.Lock()
	defer node.mu.Unlock()
	reserveReleased := false
	defer func() { node.replenishControlReserve(reserveReleased) }()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "durable store is unavailable", request.OperationID, nil, "")
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "durable state is unavailable", request.OperationID, nil, "")
	}
	if request.ExpectedEpoch != state.Epoch || request.RegistryVersion != state.RegistryVersion {
		return node.errorResult(http.StatusConflict, "stale", "node identity changed", request.OperationID, &state.Epoch, "blocked")
	}
	var storedHash string
	var storedReceipt []byte
	err = tx.QueryRowContext(ctx, `SELECT node_request_hash,receipt_json FROM logical_delete_receipts WHERE operation_id=?`,
		request.OperationID).Scan(&storedHash, &storedReceipt)
	if err == nil {
		if storedHash != requestHash {
			return node.errorResult(http.StatusConflict, "id_conflict", "operationId already names different bytes", request.OperationID, nil, "")
		}
		return Result{HTTPStatus: http.StatusOK, Body: storedReceipt}
	}
	if !isNoRows(err) {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "logical delete lookup failed", request.OperationID, nil, "")
	}

	var hold durableHold
	var holdEpoch, holdBinding int64
	err = tx.QueryRowContext(ctx, `SELECT h.operation_id,h.scope,h.dialog_id,h.hold_version,h.scope_revision,h.node_epoch,h.binding_generation
		FROM administrative_holds h WHERE h.operation_id=? AND h.node_id=?
		AND NOT EXISTS(SELECT 1 FROM administrative_hold_outcomes o WHERE o.operation_id=h.operation_id)`,
		request.OperationID, state.NodeID).Scan(&hold.OperationID, &hold.ScopeKind, &hold.DialogID, &hold.HoldVersion,
		&hold.ScopeRevision, &holdEpoch, &holdBinding)
	if isNoRows(err) {
		return node.errorResult(http.StatusConflict, "stale", "logical delete hold is not active", request.OperationID, nil, "blocked")
	}
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "logical delete hold is unavailable", request.OperationID, nil, "")
	}
	if hold.ScopeKind != "dialog" || !hold.DialogID.Valid || hold.DialogID.String != request.NodeDialogID ||
		hold.HoldVersion != request.HoldVersion || hold.ScopeRevision != request.HoldScopeRevision ||
		holdEpoch != request.ExpectedEpoch || holdBinding != request.RegistryVersion {
		return node.errorResult(http.StatusConflict, "stale", "logical delete hold changed", request.OperationID, nil, "blocked")
	}
	var currentScopeRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM hold_scope_revisions WHERE scope_key=?`,
		"dialog:"+request.NodeDialogID).Scan(&currentScopeRevision); err != nil || currentScopeRevision != hold.ScopeRevision {
		return node.errorResult(http.StatusConflict, "stale", "logical delete scope changed", request.OperationID, &currentScopeRevision, "blocked")
	}

	target, _ := json.Marshal(harnessprotocol.DialogTarget{NodeID: state.NodeID, DialogID: request.NodeDialogID})
	expected, _ := json.Marshal(harnessprotocol.DialogExpected{DialogVersion: request.ExpectedDialogVersion})
	payload, _ := json.Marshal(harnessprotocol.EmptyPayload{})
	command := harnessprotocol.CommandEnvelope{
		ProtocolVersion: harnessprotocol.ProtocolVersion, SchemaID: harnessprotocol.SchemaID,
		CommandID: request.CommandID, Kind: harnessprotocol.CommandDialogDelete,
		Target: target, Expected: expected, Payload: payload,
	}
	commandRaw, _ := json.Marshal(command)
	canonicalCommand, commandHash, err := CanonicalCommand(commandRaw)
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "internal delete command is invalid", request.OperationID, nil, "")
	}
	if outcome, found, lookupErr := loadCommandOutcome(ctx, tx, request.CommandID); lookupErr != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "delete command lookup failed", request.OperationID, nil, "")
	} else if found {
		if outcome.hash != commandHash {
			return node.errorResult(http.StatusConflict, "id_conflict", "commandId already names different bytes", request.OperationID, nil, "")
		}
		return node.errorResult(http.StatusConflict, "stale", "delete command exists without operation receipt", request.OperationID, nil, "blocked")
	}
	references, result, blocking, _, err := node.applyDialogDelete(ctx, tx, &state, command)
	if err != nil {
		return node.commandError(err, request.OperationID)
	}
	commandReceiptID, err := node.newID()
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "command receipt identity is unavailable", request.OperationID, nil, "")
	}
	referenceJSON, _ := json.Marshal(references)
	deletedAt := timestamp(node.config.Clock())
	commandReceipt := harnessprotocol.Receipt{
		ProtocolVersion: harnessprotocol.ProtocolVersion, SchemaID: harnessprotocol.SchemaID,
		CommandID: request.CommandID, CommandKind: harnessprotocol.CommandDialogDelete, ReceiptID: commandReceiptID,
		AcceptedAt: deletedAt, NodeID: state.NodeID, EventSeq: state.LastEventSeq, Result: result,
		BlockingReason: blocking, References: referenceJSON,
	}
	commandReceiptJSON, err := json.Marshal(commandReceipt)
	if err != nil || harnessprotocol.Validate("receipt", commandReceiptJSON) != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "internal command receipt is invalid", request.OperationID, nil, "")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO commands(command_id,actor_id,node_id,kind,canonical_json,
		canonical_payload_hash,receipt_json,accepted_at,event_seq) VALUES(?,?,?,?,?,?,?,?,?)`, request.CommandID,
		trust.ActorID, state.NodeID, command.Kind, canonicalCommand, commandHash, commandReceiptJSON,
		commandReceipt.AcceptedAt, commandReceipt.EventSeq); err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "delete command commit failed", request.OperationID, nil, "")
	}

	releaseReceiptID, err := node.newID()
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "release receipt identity is unavailable", request.OperationID, nil, "")
	}
	releaseReceipt := harnessbarrier.ReleaseReceipt{
		ProtocolVersion: harnessbarrier.ProtocolVersion, SchemaID: harnessbarrier.SchemaID, Kind: "hold.released",
		OperationID: request.OperationID, ReceiptID: releaseReceiptID, NodeID: state.NodeID, Epoch: state.Epoch,
		BindingGeneration: state.RegistryVersion, Scope: hold.scope(), HoldVersion: hold.HoldVersion,
		ScopeRevision: currentScopeRevision + 1, ManualPause: state.QueuePaused, ReleasedAt: deletedAt,
	}
	releaseJSON, err := json.Marshal(releaseReceipt)
	if err != nil || harnessbarrier.Validate("releaseReceipt", releaseJSON) != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "internal release receipt is invalid", request.OperationID, nil, "")
	}
	receiptID, err := node.newID()
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "logical delete receipt identity is unavailable", request.OperationID, nil, "")
	}
	receipt := logicaldelete.NodeReceipt{
		SchemaID: logicaldelete.NodeSchemaID, OperationID: request.OperationID, NodeRequestHash: requestHash,
		CoordinatorRequestHash: request.CoordinatorRequestHash, ReceiptID: receiptID, CommandID: request.CommandID,
		LogicalDialogID: request.LogicalDialogID, NodeID: state.NodeID, NodeDialogID: request.NodeDialogID,
		Epoch: state.Epoch, RegistryVersion: state.RegistryVersion, BindingVersion: request.BindingVersion,
		DeletedDialogVersion: request.ExpectedDialogVersion + 1, HoldVersion: hold.HoldVersion,
		HoldScopeRevision: currentScopeRevision + 1, TombstoneEventSeq: state.LastEventSeq,
		CommandReceipt: commandReceiptJSON, DeletedAt: deletedAt,
	}
	receiptJSON, err := json.Marshal(receipt)
	if err != nil || logicaldelete.ValidateNodeReceipt(receipt) != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "internal logical delete receipt is invalid", request.OperationID, nil, "")
	}
	reserveReleased, err = node.releaseControlReserve()
	if err != nil || !reserveReleased {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "control reserve is unavailable", request.OperationID, nil, "")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE hold_scope_revisions SET revision=? WHERE scope_key=? AND revision=?`,
		currentScopeRevision+1, "dialog:"+request.NodeDialogID, currentScopeRevision); err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "release revision commit failed", request.OperationID, nil, "")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO administrative_hold_outcomes(
		operation_id,action,canonical_json,canonical_payload_hash,receipt_json,scope_revision,released_at)
		VALUES(?,'release',?,?,?,?,?)`, request.OperationID, raw, requestHash, releaseJSON,
		currentScopeRevision+1, deletedAt); err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "logical delete release commit failed", request.OperationID, nil, "")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO logical_delete_receipts(
		operation_id,node_request_hash,coordinator_request_hash,command_id,logical_dialog_id,node_dialog_id,
		binding_version,hold_version,hold_scope_revision,receipt_json,deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		request.OperationID, requestHash, request.CoordinatorRequestHash, request.CommandID, request.LogicalDialogID,
		request.NodeDialogID, request.BindingVersion, request.HoldVersion, currentScopeRevision+1, receiptJSON, deletedAt); err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "logical delete receipt commit failed", request.OperationID, nil, "")
	}
	if err := saveState(ctx, tx, state); err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "logical delete state commit failed", request.OperationID, nil, "")
	}
	if err := node.checkFault(FaultBeforeLogicalDeleteCommit); err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "logical delete commit was not attempted", request.OperationID, nil, "")
	}
	if err := tx.Commit(); err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "atomic logical delete commit failed", request.OperationID, nil, "")
	}
	node.deletedDialogs[request.NodeDialogID] = struct{}{}
	node.afterCommit(context.Background(), postCommitAction{})
	if err := node.checkFault(FaultAfterLogicalDeleteCommit); err != nil {
		return Result{HTTPStatus: http.StatusServiceUnavailable, Body: node.errorResult(http.StatusServiceUnavailable,
			"node_unavailable", "logical delete receipt delivery was interrupted", request.OperationID, nil, "").Body, Committed: true}
	}
	return Result{HTTPStatus: http.StatusCreated, Body: receiptJSON, Committed: true}
}

// LogicalDeleteStatus is the only lost-ACK readback. It never replays the
// command effect and is unavailable through the generic browser read surface.
func (node *Node) LogicalDeleteStatus(ctx context.Context, trust OperatorTrustContext, operationID string) Result {
	if !trust.PeerVerified || trust.ActorID == "" || trust.ActorID != node.config.OwnerID {
		return node.errorResult(http.StatusForbidden, "forbidden", "trusted operator is not allowed", "", nil, "")
	}
	if trust.TransportNodeID != node.config.NodeID || !uuidPattern.MatchString(operationID) {
		return node.errorResult(http.StatusNotFound, "not_found", "operation was not found", operationID, nil, "")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	var receipt []byte
	if err := node.db.QueryRowContext(ctx, `SELECT receipt_json FROM logical_delete_receipts WHERE operation_id=?`, operationID).Scan(&receipt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return node.errorResult(http.StatusNotFound, "not_found", "operation was not found", operationID, nil, "")
		}
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "logical delete status is unavailable", operationID, nil, "")
	}
	var value logicaldelete.NodeReceipt
	if json.Unmarshal(receipt, &value) != nil || logicaldelete.ValidateNodeReceipt(value) != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "logical delete status is invalid", operationID, nil, "")
	}
	return Result{HTTPStatus: http.StatusOK, Body: receipt}
}
