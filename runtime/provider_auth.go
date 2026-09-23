package node

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/boxvtk621/harness-codex/internal/providerauth"
)

func (node *Node) ProviderAuthSnapshot(ctx context.Context, nodeID string) Result {
	if node.config.ProviderAuth == nil {
		return providerAuthError(http.StatusUnprocessableEntity, "unsupported_method")
	}
	envelope, failure := node.config.ProviderAuth.Snapshot(ctx, nodeID)
	return providerAuthResult(envelope, failure)
}

func (node *Node) ProviderAuthOperation(ctx context.Context, nodeID, operationID string) Result {
	if node.config.ProviderAuth == nil {
		return providerAuthError(http.StatusUnprocessableEntity, "unsupported_method")
	}
	envelope, failure := node.config.ProviderAuth.Operation(ctx, nodeID, operationID)
	return providerAuthResult(envelope, failure)
}

func (node *Node) ProviderAuthStart(ctx context.Context, nodeID, commandID, method string, secret *string) Result {
	if node.config.ProviderAuth == nil {
		return providerAuthError(http.StatusUnprocessableEntity, "unsupported_method")
	}
	node.startGate.Lock()
	defer node.startGate.Unlock()
	if node.settingsApplyBusy() {
		return providerAuthError(http.StatusConflict, "busy")
	}
	if node.providerAuthWorkBusy(ctx) {
		return providerAuthError(http.StatusConflict, "busy")
	}
	envelope, failure := node.config.ProviderAuth.StartAuth(ctx, nodeID, commandID, method, secret)
	return providerAuthResult(envelope, failure)
}

func (node *Node) ProviderAuthCheck(ctx context.Context, nodeID, commandID string) Result {
	if node.config.ProviderAuth == nil {
		return providerAuthError(http.StatusUnprocessableEntity, "unsupported_method")
	}
	envelope, failure := node.config.ProviderAuth.Check(ctx, nodeID, commandID)
	return providerAuthResult(envelope, failure)
}

func (node *Node) ProviderAuthCancel(ctx context.Context, nodeID, commandID, operationID string) Result {
	if node.config.ProviderAuth == nil {
		return providerAuthError(http.StatusUnprocessableEntity, "unsupported_method")
	}
	envelope, failure := node.config.ProviderAuth.CancelAuth(ctx, nodeID, commandID, operationID)
	return providerAuthResult(envelope, failure)
}

func (node *Node) ProviderAuthLogout(ctx context.Context, nodeID, commandID string) Result {
	if node.config.ProviderAuth == nil {
		return providerAuthError(http.StatusUnprocessableEntity, "unsupported_method")
	}
	node.startGate.Lock()
	defer node.startGate.Unlock()
	if node.settingsApplyBusy() {
		return providerAuthError(http.StatusConflict, "busy")
	}
	if node.providerAuthWorkBusy(ctx) {
		return providerAuthError(http.StatusConflict, "busy")
	}
	envelope, failure := node.config.ProviderAuth.Logout(ctx, nodeID, commandID)
	return providerAuthResult(envelope, failure)
}

func (node *Node) providerAuthWorkBusy(ctx context.Context) bool {
	node.mu.Lock()
	defer node.mu.Unlock()
	var occupancy string
	var active sql.NullString
	if err := node.db.QueryRowContext(ctx, "SELECT occupancy,active_attempt_id FROM node_state WHERE singleton=1").Scan(&occupancy, &active); err != nil {
		return true
	}
	return occupancy != "idle" || active.Valid
}

func (node *Node) providerAuthReady(ctx context.Context) bool {
	if node.config.ProviderAuth == nil {
		return true
	}
	envelope, failure := node.config.ProviderAuth.Snapshot(ctx, node.config.NodeID)
	return failure == nil && envelope.State == "authenticated" && (envelope.Operation == nil || envelope.Operation.Status != "pending")
}

func providerAuthResult(envelope providerauth.Envelope, failure *providerauth.Failure) Result {
	if failure != nil {
		return providerAuthError(failure.Status, failure.Code)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return providerAuthError(http.StatusServiceUnavailable, "provider_unavailable")
	}
	return Result{HTTPStatus: http.StatusOK, Body: body}
}

func providerAuthError(status int, code string) Result {
	body, _ := json.Marshal(struct {
		Code string `json:"code"`
	}{Code: code})
	return Result{HTTPStatus: status, Body: body}
}
