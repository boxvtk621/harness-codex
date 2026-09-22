package codex

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/boxvtk621/harness-codex/internal/providerauth"
)

const (
	providerAuthFile      = "provider-auth-v1.json"
	providerAuthVersion   = 2
	providerAuthTimeout   = 15 * time.Minute
	maximumAuthStateBytes = 64 << 20
	maximumAuthReceipts   = 65536
)

type providerAuthReceipt struct {
	Action      string `json:"action"`
	OperationID string `json:"operationId,omitempty"`
	CreatedAt   string `json:"createdAt"`
	FailureCode string `json:"failureCode,omitempty"`
	FailureHTTP int    `json:"failureHttp,omitempty"`
}

type storedAuthOperation struct {
	providerauth.Operation
	ProviderLoginID string `json:"providerLoginId,omitempty"`
}

type providerAuthState struct {
	Version    int                            `json:"version"`
	Revision   int64                          `json:"revision"`
	State      string                         `json:"state"`
	CheckedAt  *string                        `json:"checkedAt"`
	ReasonCode *string                        `json:"reasonCode"`
	Operation  *storedAuthOperation           `json:"operation"`
	Operations map[string]storedAuthOperation `json:"operations"`
	Receipts   map[string]providerAuthReceipt `json:"receipts"`
}

type accountLoginCompleted struct {
	LoginID *string `json:"loginId"`
	Success bool    `json:"success"`
	Error   *string `json:"error"`
}

type accountReadResponse struct {
	Account *struct {
		Type string `json:"type"`
	} `json:"account"`
	RequiresOpenAIAuth bool `json:"requiresOpenaiAuth"`
}

type deviceLoginResponse struct {
	Type            string `json:"type"`
	LoginID         string `json:"loginId"`
	VerificationURL string `json:"verificationUrl"`
	UserCode        string `json:"userCode"`
}

type cancelLoginResponse struct {
	Status string `json:"status"`
}

type providerAuthIndeterminateCommitError struct{ cause error }

func (err *providerAuthIndeterminateCommitError) Error() string {
	return "provider auth commit is indeterminate: " + err.cause.Error()
}
func (err *providerAuthIndeterminateCommitError) Unwrap() error { return err.cause }

var _ providerauth.Manager = (*Adapter)(nil)

func (adapter *Adapter) initializeProviderAuth(ctx context.Context) error {
	adapter.authMu.Lock()
	defer adapter.authMu.Unlock()
	state, err := adapter.loadProviderAuthState()
	if err != nil {
		return err
	}
	adapter.auth = state
	if adapter.auth.Operation != nil && adapter.auth.Operation.Status == "pending" {
		now := authTimestamp(time.Now())
		reason := "interrupted_by_restart"
		adapter.auth.Operation.Status = "failed"
		adapter.auth.Operation.UpdatedAt = now
		adapter.auth.Operation.ReasonCode = &reason
		adapter.auth.Revision++
	}
	var response accountReadResponse
	if err := adapter.session.Call(ctx, "account/read", map[string]bool{"refreshToken": true}, &response); err == nil {
		adapter.applyAccountReadLocked(response, time.Now())
	} else {
		adapter.auth.State = "unknown"
		adapter.auth.CheckedAt = nil
		reason := "provider_unavailable"
		adapter.auth.ReasonCode = &reason
		adapter.auth.Revision++
	}
	return adapter.persistProviderAuthLocked()
}

func (adapter *Adapter) Snapshot(_ context.Context, nodeID string) (providerauth.Envelope, *providerauth.Failure) {
	if nodeID != adapter.config.NodeID {
		return providerauth.Envelope{}, authFailure(http.StatusNotFound, "not_found")
	}
	adapter.authMu.Lock()
	adapter.expireProviderAuthLocked(time.Now())
	envelope := adapter.providerAuthEnvelopeLocked()
	adapter.authMu.Unlock()
	return envelope, nil
}

func (adapter *Adapter) Operation(_ context.Context, nodeID, operationID string) (providerauth.Envelope, *providerauth.Failure) {
	if nodeID != adapter.config.NodeID || !providerauth.UUIDPattern.MatchString(operationID) {
		return providerauth.Envelope{}, authFailure(http.StatusNotFound, "not_found")
	}
	adapter.authMu.Lock()
	adapter.expireProviderAuthLocked(time.Now())
	if adapter.auth.Operation == nil || adapter.auth.Operation.OperationID != operationID {
		historical, ok := adapter.auth.Operations[operationID]
		if !ok {
			adapter.authMu.Unlock()
			return providerauth.Envelope{}, authFailure(http.StatusNotFound, "not_found")
		}
		envelope := adapter.providerAuthEnvelopeForOperationLocked(&historical)
		adapter.authMu.Unlock()
		return envelope, nil
	}
	envelope := adapter.providerAuthEnvelopeLocked()
	adapter.authMu.Unlock()
	return envelope, nil
}

func (adapter *Adapter) StartAuth(ctx context.Context, nodeID, commandID, method string, secret *string) (providerauth.Envelope, *providerauth.Failure) {
	if nodeID != adapter.config.NodeID {
		return providerauth.Envelope{}, authFailure(http.StatusNotFound, "not_found")
	}
	if !providerauth.UUIDPattern.MatchString(commandID) {
		return providerauth.Envelope{}, authFailure(http.StatusBadRequest, "invalid_request")
	}
	if method != "device_code" {
		return providerauth.Envelope{}, authFailure(http.StatusUnprocessableEntity, "unsupported_method")
	}
	if secret != nil {
		return providerauth.Envelope{}, authFailure(http.StatusBadRequest, "invalid_request")
	}
	action := "start:device_code"
	adapter.authMu.Lock()
	adapter.expireProviderAuthLocked(time.Now())
	if envelope, failure, found := adapter.authReceiptLocked(commandID, action); found {
		adapter.authMu.Unlock()
		return envelope, failure
	}
	if adapter.authBusy {
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusConflict, "busy")
	}
	if adapter.auth.Operation != nil && adapter.auth.Operation.Status == "pending" {
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusConflict, "pending_operation")
	}
	if len(adapter.auth.Receipts) >= maximumAuthReceipts {
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	previous := cloneProviderAuthState(adapter.auth)
	operationID, err := newAuthID()
	if err != nil {
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	now := time.Now()
	created, timeout := authTimestamp(now), authTimestamp(now.Add(providerAuthTimeout))
	if adapter.auth.Operation != nil {
		adapter.auth.Operations[adapter.auth.Operation.OperationID] = *adapter.auth.Operation
	}
	adapter.auth.Operation = &storedAuthOperation{Operation: providerauth.Operation{
		OperationID: operationID, CommandID: commandID, Method: method, Status: "pending",
		CreatedAt: created, UpdatedAt: created, TimeoutAt: &timeout,
	}}
	if failure := adapter.storeAuthReceiptLocked(commandID, providerAuthReceipt{Action: action, OperationID: operationID}); failure != nil {
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, failure
	}
	adapter.auth.Revision++
	adapter.authBusy = true
	if err := adapter.persistProviderAuthLocked(); err != nil {
		adapter.authBusy = false
		var indeterminate *providerAuthIndeterminateCommitError
		if errors.As(err, &indeterminate) {
			adapter.failAuthOperationLocked(adapter.auth.Operation, "provider_unavailable", time.Now())
			adapter.markAuthReceiptFailureLocked(commandID, http.StatusServiceUnavailable, "provider_unavailable")
			adapter.auth.State = "unknown"
			adapter.auth.CheckedAt = nil
			reason := "provider_unavailable"
			adapter.auth.ReasonCode = &reason
		} else {
			adapter.auth = previous
		}
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	adapter.authMu.Unlock()

	written := false
	var response deviceLoginResponse
	err = adapter.session.CallAfterWrite(ctx, "account/login/start", map[string]string{"type": "chatgptDeviceCode"}, &response, func() { written = true })

	adapter.authMu.Lock()
	adapter.authBusy = false
	current := adapter.auth.Operation
	if current == nil || current.OperationID != operationID || current.Status != "pending" {
		envelope := adapter.providerAuthEnvelopeLocked()
		adapter.authMu.Unlock()
		return envelope, nil
	}
	if err != nil {
		if !written {
			adapter.failAuthOperationLocked(current, "provider_unavailable", time.Now())
			adapter.markAuthReceiptFailureLocked(commandID, http.StatusServiceUnavailable, "provider_unavailable")
		}
		_ = adapter.persistProviderAuthLocked()
		envelope := adapter.providerAuthEnvelopeLocked()
		adapter.authMu.Unlock()
		if written {
			return envelope, nil
		}
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	if !validDeviceLoginResponse(response) {
		adapter.failAuthOperationLocked(current, "provider_protocol_error", time.Now())
		adapter.markAuthReceiptFailureLocked(commandID, http.StatusServiceUnavailable, "provider_unavailable")
		_ = adapter.persistProviderAuthLocked()
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	current.ProviderLoginID = response.LoginID
	current.VerificationURL = stringPointer(response.VerificationURL)
	current.UserCode = stringPointer(response.UserCode)
	current.UpdatedAt = authTimestamp(time.Now())
	adapter.auth.Revision++
	completion, completedEarly := adapter.authCompletions[response.LoginID]
	delete(adapter.authCompletions, response.LoginID)
	if err := adapter.persistProviderAuthLocked(); err != nil {
		adapter.markAuthReceiptFailureLocked(commandID, http.StatusServiceUnavailable, "provider_unavailable")
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	envelope := adapter.providerAuthEnvelopeLocked()
	adapter.authMu.Unlock()
	if completedEarly {
		go adapter.completeProviderLogin(completion)
	}
	return envelope, nil
}

func (adapter *Adapter) Check(ctx context.Context, nodeID, commandID string) (providerauth.Envelope, *providerauth.Failure) {
	if nodeID != adapter.config.NodeID {
		return providerauth.Envelope{}, authFailure(http.StatusNotFound, "not_found")
	}
	if !providerauth.UUIDPattern.MatchString(commandID) {
		return providerauth.Envelope{}, authFailure(http.StatusBadRequest, "invalid_request")
	}
	const action = "check"
	adapter.authMu.Lock()
	if envelope, failure, found := adapter.authReceiptLocked(commandID, action); found {
		adapter.authMu.Unlock()
		return envelope, failure
	}
	if adapter.authBusy {
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusConflict, "busy")
	}
	if failure := adapter.storeAuthReceiptLocked(commandID, providerAuthReceipt{Action: action}); failure != nil {
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, failure
	}
	adapter.authBusy = true
	if err := adapter.persistProviderAuthLocked(); err != nil {
		adapter.authBusy = false
		adapter.markAuthReceiptFailureLocked(commandID, http.StatusServiceUnavailable, "provider_unavailable")
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	adapter.authMu.Unlock()
	var response accountReadResponse
	err := adapter.session.Call(ctx, "account/read", map[string]bool{"refreshToken": true}, &response)
	adapter.authMu.Lock()
	adapter.authBusy = false
	if err != nil {
		adapter.auth.State = "unknown"
		adapter.auth.CheckedAt = nil
		reason := "provider_unavailable"
		adapter.auth.ReasonCode = &reason
		adapter.auth.Revision++
		adapter.markAuthReceiptFailureLocked(commandID, http.StatusServiceUnavailable, "provider_unavailable")
		_ = adapter.persistProviderAuthLocked()
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	adapter.applyAccountReadLocked(response, time.Now())
	if err := adapter.persistProviderAuthLocked(); err != nil {
		adapter.markAuthReceiptFailureLocked(commandID, http.StatusServiceUnavailable, "provider_unavailable")
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	envelope := adapter.providerAuthEnvelopeLocked()
	adapter.authMu.Unlock()
	return envelope, nil
}

func (adapter *Adapter) CancelAuth(ctx context.Context, nodeID, commandID, operationID string) (providerauth.Envelope, *providerauth.Failure) {
	if nodeID != adapter.config.NodeID {
		return providerauth.Envelope{}, authFailure(http.StatusNotFound, "not_found")
	}
	if !providerauth.UUIDPattern.MatchString(commandID) || !providerauth.UUIDPattern.MatchString(operationID) {
		return providerauth.Envelope{}, authFailure(http.StatusBadRequest, "invalid_request")
	}
	action := "cancel:" + operationID
	adapter.authMu.Lock()
	if envelope, failure, found := adapter.authReceiptLocked(commandID, action); found {
		adapter.authMu.Unlock()
		return envelope, failure
	}
	if adapter.authBusy {
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusConflict, "busy")
	}
	operation := adapter.auth.Operation
	if operation == nil || operation.OperationID != operationID {
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusNotFound, "not_found")
	}
	if operation.Status != "pending" {
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusConflict, "id_conflict")
	}
	if operation.ProviderLoginID == "" {
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusConflict, "busy")
	}
	if failure := adapter.storeAuthReceiptLocked(commandID, providerAuthReceipt{Action: action, OperationID: operationID}); failure != nil {
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, failure
	}
	adapter.authBusy = true
	loginID := operation.ProviderLoginID
	if err := adapter.persistProviderAuthLocked(); err != nil {
		adapter.authBusy = false
		adapter.markAuthReceiptFailureLocked(commandID, http.StatusServiceUnavailable, "provider_unavailable")
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	adapter.authMu.Unlock()
	var response cancelLoginResponse
	err := adapter.session.Call(ctx, "account/login/cancel", map[string]string{"loginId": loginID}, &response)
	adapter.authMu.Lock()
	adapter.authBusy = false
	operation = adapter.auth.Operation
	if err != nil {
		if operation != nil && operation.OperationID == operationID && operation.Status == "pending" {
			adapter.failAuthOperationLocked(operation, "provider_unavailable", time.Now())
		}
		adapter.markAuthReceiptFailureLocked(commandID, http.StatusServiceUnavailable, "provider_unavailable")
		_ = adapter.persistProviderAuthLocked()
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	if operation != nil && operation.OperationID == operationID && operation.Status == "pending" {
		if response.Status == "canceled" {
			adapter.finishAuthOperationLocked(operation, "cancelled", "cancelled", time.Now())
		} else if response.Status == "notFound" {
			adapter.failAuthOperationLocked(operation, "provider_operation_missing", time.Now())
		} else {
			adapter.failAuthOperationLocked(operation, "provider_protocol_error", time.Now())
		}
	}
	if err := adapter.persistProviderAuthLocked(); err != nil {
		adapter.markAuthReceiptFailureLocked(commandID, http.StatusServiceUnavailable, "provider_unavailable")
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	envelope := adapter.providerAuthEnvelopeLocked()
	adapter.authMu.Unlock()
	return envelope, nil
}

func (adapter *Adapter) Logout(ctx context.Context, nodeID, commandID string) (providerauth.Envelope, *providerauth.Failure) {
	if nodeID != adapter.config.NodeID {
		return providerauth.Envelope{}, authFailure(http.StatusNotFound, "not_found")
	}
	if !providerauth.UUIDPattern.MatchString(commandID) {
		return providerauth.Envelope{}, authFailure(http.StatusBadRequest, "invalid_request")
	}
	const action = "logout"
	adapter.authMu.Lock()
	if envelope, failure, found := adapter.authReceiptLocked(commandID, action); found {
		adapter.authMu.Unlock()
		return envelope, failure
	}
	if adapter.authBusy || (adapter.auth.Operation != nil && adapter.auth.Operation.Status == "pending") {
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusConflict, "busy")
	}
	if failure := adapter.storeAuthReceiptLocked(commandID, providerAuthReceipt{Action: action}); failure != nil {
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, failure
	}
	adapter.authBusy = true
	if err := adapter.persistProviderAuthLocked(); err != nil {
		adapter.authBusy = false
		adapter.markAuthReceiptFailureLocked(commandID, http.StatusServiceUnavailable, "provider_unavailable")
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	adapter.authMu.Unlock()
	var ignored struct{}
	_ = adapter.session.Call(ctx, "account/logout", struct{}{}, &ignored)
	var readback accountReadResponse
	readErr := adapter.session.Call(ctx, "account/read", map[string]bool{"refreshToken": true}, &readback)
	adapter.authMu.Lock()
	adapter.authBusy = false
	if readErr != nil {
		adapter.auth.State = "unknown"
		adapter.auth.CheckedAt = nil
		reason := "provider_unavailable"
		adapter.auth.ReasonCode = &reason
		adapter.auth.Revision++
		adapter.markAuthReceiptFailureLocked(commandID, http.StatusServiceUnavailable, "provider_unavailable")
		_ = adapter.persistProviderAuthLocked()
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	adapter.applyAccountReadLocked(readback, time.Now())
	if readback.Account != nil {
		adapter.markAuthReceiptFailureLocked(commandID, http.StatusServiceUnavailable, "provider_unavailable")
		_ = adapter.persistProviderAuthLocked()
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	if err := adapter.persistProviderAuthLocked(); err != nil {
		adapter.markAuthReceiptFailureLocked(commandID, http.StatusServiceUnavailable, "provider_unavailable")
		adapter.authMu.Unlock()
		return providerauth.Envelope{}, authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	envelope := adapter.providerAuthEnvelopeLocked()
	adapter.authMu.Unlock()
	return envelope, nil
}

func (adapter *Adapter) handleProviderAuthNotification(notification rpcNotification) bool {
	if notification.Method != "account/login/completed" {
		return false
	}
	var completion accountLoginCompleted
	if !decodeStrict(notification.Params, &completion) || completion.LoginID == nil || !boundedSessionText(*completion.LoginID, 512) {
		return true
	}
	go adapter.completeProviderLogin(completion)
	return true
}

func (adapter *Adapter) completeProviderLogin(completion accountLoginCompleted) {
	loginID := *completion.LoginID
	adapter.authMu.Lock()
	operation := adapter.auth.Operation
	if operation == nil || operation.ProviderLoginID != loginID {
		if operation != nil && operation.Status == "pending" && operation.ProviderLoginID == "" && len(adapter.authCompletions) < 4 {
			adapter.authCompletions[loginID] = completion
		}
		adapter.authMu.Unlock()
		return
	}
	operationID := operation.OperationID
	if !completion.Success {
		if operation.Status == "pending" {
			adapter.failAuthOperationLocked(operation, "credential_rejected", time.Now())
			adapter.persistProviderAuthOrBlockLocked(operation)
		}
		adapter.authMu.Unlock()
		return
	}
	adapter.authMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), adapter.config.OperationTimeout)
	defer cancel()
	var response accountReadResponse
	err := adapter.session.Call(ctx, "account/read", map[string]bool{"refreshToken": true}, &response)
	adapter.authMu.Lock()
	defer adapter.authMu.Unlock()
	operation = adapter.auth.Operation
	if operation == nil || operation.OperationID != operationID || operation.ProviderLoginID != loginID {
		return
	}
	if err == nil {
		adapter.applyAccountReadLocked(response, time.Now())
	} else {
		adapter.auth.State = "unknown"
		adapter.auth.CheckedAt = nil
		reason := "provider_unavailable"
		adapter.auth.ReasonCode = &reason
		adapter.auth.Revision++
	}
	if operation.Status == "pending" {
		if err != nil || response.Account == nil || response.Account.Type != "chatgpt" {
			adapter.failAuthOperationLocked(operation, "verification_failed", time.Now())
		} else {
			adapter.finishAuthOperationLocked(operation, "succeeded", "", time.Now())
		}
	}
	adapter.persistProviderAuthOrBlockLocked(operation)
}

func (adapter *Adapter) applyAccountReadLocked(response accountReadResponse, now time.Time) {
	checked := authTimestamp(now)
	adapter.auth.CheckedAt = &checked
	adapter.auth.ReasonCode = nil
	switch {
	case response.Account != nil && response.Account.Type == "chatgpt":
		adapter.auth.State = "authenticated"
	case response.Account != nil:
		adapter.auth.State = "reauthentication_required"
		reason := "managed_auth_required"
		adapter.auth.ReasonCode = &reason
	case response.RequiresOpenAIAuth:
		adapter.auth.State = "unauthenticated"
	case !response.RequiresOpenAIAuth:
		adapter.auth.State = "reauthentication_required"
		reason := "managed_auth_required"
		adapter.auth.ReasonCode = &reason
	}
	adapter.auth.Revision++
}

func (adapter *Adapter) expireProviderAuthLocked(now time.Time) {
	operation := adapter.auth.Operation
	if operation == nil || operation.Status != "pending" || operation.TimeoutAt == nil {
		return
	}
	deadline, err := time.Parse(time.RFC3339Nano, *operation.TimeoutAt)
	if err != nil || now.Before(deadline) {
		return
	}
	adapter.finishAuthOperationLocked(operation, "expired", "expired", now)
	if !adapter.persistProviderAuthOrBlockLocked(operation) {
		return
	}
	if operation.ProviderLoginID != "" {
		loginID := operation.ProviderLoginID
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), adapter.config.OperationTimeout)
			defer cancel()
			var response cancelLoginResponse
			_ = adapter.session.Call(ctx, "account/login/cancel", map[string]string{"loginId": loginID}, &response)
		}()
	}
}

func (adapter *Adapter) finishAuthOperationLocked(operation *storedAuthOperation, status, reason string, now time.Time) {
	operation.Status = status
	operation.UpdatedAt = authTimestamp(now)
	operation.VerificationURL = nil
	operation.UserCode = nil
	if reason == "" {
		operation.ReasonCode = nil
	} else {
		operation.ReasonCode = stringPointer(reason)
	}
	adapter.auth.Revision++
}

func (adapter *Adapter) failAuthOperationLocked(operation *storedAuthOperation, reason string, now time.Time) {
	adapter.finishAuthOperationLocked(operation, "failed", reason, now)
}

func (adapter *Adapter) authReceiptLocked(commandID, action string) (providerauth.Envelope, *providerauth.Failure, bool) {
	receipt, found := adapter.auth.Receipts[commandID]
	if !found {
		return providerauth.Envelope{}, nil, false
	}
	if receipt.Action != action {
		return providerauth.Envelope{}, authFailure(http.StatusConflict, "id_conflict"), true
	}
	if receipt.FailureCode != "" {
		return providerauth.Envelope{}, authFailure(receipt.FailureHTTP, receipt.FailureCode), true
	}
	if receipt.OperationID != "" && (adapter.auth.Operation == nil || adapter.auth.Operation.OperationID != receipt.OperationID) {
		historical, ok := adapter.auth.Operations[receipt.OperationID]
		if !ok {
			return providerauth.Envelope{}, authFailure(http.StatusNotFound, "not_found"), true
		}
		return adapter.providerAuthEnvelopeForOperationLocked(&historical), nil, true
	}
	return adapter.providerAuthEnvelopeLocked(), nil, true
}

func (adapter *Adapter) storeAuthReceiptLocked(commandID string, receipt providerAuthReceipt) *providerauth.Failure {
	if adapter.auth.Receipts == nil {
		adapter.auth.Receipts = make(map[string]providerAuthReceipt)
	}
	if len(adapter.auth.Receipts) >= maximumAuthReceipts {
		return authFailure(http.StatusServiceUnavailable, "provider_unavailable")
	}
	receipt.CreatedAt = authTimestamp(time.Now())
	adapter.auth.Receipts[commandID] = receipt
	return nil
}

func (adapter *Adapter) markAuthReceiptFailureLocked(commandID string, status int, code string) {
	receipt, ok := adapter.auth.Receipts[commandID]
	if !ok {
		return
	}
	receipt.FailureHTTP, receipt.FailureCode = status, code
	adapter.auth.Receipts[commandID] = receipt
}

func (adapter *Adapter) providerAuthEnvelopeLocked() providerauth.Envelope {
	return adapter.providerAuthEnvelopeForOperationLocked(adapter.auth.Operation)
}

func (adapter *Adapter) providerAuthEnvelopeForOperationLocked(stored *storedAuthOperation) providerauth.Envelope {
	var operation *providerauth.Operation
	if stored != nil {
		copy := stored.Operation
		operation = &copy
	}
	return providerauth.Envelope{
		SchemaID: providerauth.SchemaID, NodeID: adapter.config.NodeID, Revision: adapter.auth.Revision,
		State: adapter.auth.State, CheckedAt: cloneStringPointer(adapter.auth.CheckedAt), ReasonCode: cloneStringPointer(adapter.auth.ReasonCode),
		Capabilities: providerauth.Capabilities{Methods: []string{"device_code"}, CanCheck: true, CanLogout: true}, Operation: operation,
	}
}

func (adapter *Adapter) loadProviderAuthState() (providerAuthState, error) {
	path := filepath.Join(adapter.config.StateDir, providerAuthFile)
	info, statErr := os.Lstat(path)
	if statErr == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0o600) {
		return providerAuthState{}, errors.New("provider auth state permissions are invalid")
	}
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return providerAuthState{}, errors.New("provider auth state is unavailable")
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return providerAuthState{Version: providerAuthVersion, State: "unknown", Operations: make(map[string]storedAuthOperation), Receipts: make(map[string]providerAuthReceipt)}, nil
	}
	if err != nil || len(raw) == 0 || len(raw) > maximumAuthStateBytes {
		return providerAuthState{}, errors.New("provider auth state is unavailable")
	}
	var state providerAuthState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(new(any)) != io.EOF || state.Revision < 0 ||
		!migrateProviderAuthState(&state) || !validProviderAuthState(state) {
		return providerAuthState{}, errors.New("provider auth state is invalid")
	}
	if state.Receipts == nil {
		state.Receipts = make(map[string]providerAuthReceipt)
	}
	if state.Operations == nil {
		state.Operations = make(map[string]storedAuthOperation)
	}
	return state, nil
}

func migrateProviderAuthState(state *providerAuthState) bool {
	if state.Version == providerAuthVersion {
		return true
	}
	if state.Version != 1 {
		return false
	}
	createdAt := "1970-01-01T00:00:00Z"
	if state.Operation != nil && validAuthTimestamp(state.Operation.CreatedAt) {
		createdAt = state.Operation.CreatedAt
	} else if state.CheckedAt != nil && validAuthTimestamp(*state.CheckedAt) {
		createdAt = *state.CheckedAt
	}
	for commandID, receipt := range state.Receipts {
		if receipt.CreatedAt == "" {
			receipt.CreatedAt = createdAt
			state.Receipts[commandID] = receipt
		}
	}
	state.Version = providerAuthVersion
	return true
}

func validProviderAuthState(state providerAuthState) bool {
	switch state.State {
	case "unknown", "unauthenticated", "authenticated", "reauthentication_required":
	default:
		return false
	}
	if len(state.Receipts) > maximumAuthReceipts {
		return false
	}
	if len(state.Operations) > maximumAuthReceipts {
		return false
	}
	for operationID, operation := range state.Operations {
		if operationID != operation.OperationID || !validStoredAuthOperation(operation) ||
			(state.Operation != nil && operationID == state.Operation.OperationID) {
			return false
		}
	}
	for id, receipt := range state.Receipts {
		if !providerauth.UUIDPattern.MatchString(id) || !validProviderAuthReceipt(receipt) {
			return false
		}
	}
	if state.CheckedAt != nil && !validAuthTimestamp(*state.CheckedAt) {
		return false
	}
	if !validAuthReason(state.ReasonCode) {
		return false
	}
	return state.Operation == nil || validStoredAuthOperation(*state.Operation)
}

func validProviderAuthReceipt(receipt providerAuthReceipt) bool {
	if !validAuthTimestamp(receipt.CreatedAt) {
		return false
	}
	if (receipt.FailureCode == "") != (receipt.FailureHTTP == 0) ||
		(receipt.FailureCode != "" && (receipt.FailureCode != "provider_unavailable" || receipt.FailureHTTP != http.StatusServiceUnavailable)) {
		return false
	}
	switch {
	case receipt.Action == "check" || receipt.Action == "logout":
		return receipt.OperationID == ""
	case receipt.Action == "start:device_code":
		return providerauth.UUIDPattern.MatchString(receipt.OperationID)
	case strings.HasPrefix(receipt.Action, "cancel:"):
		operationID := strings.TrimPrefix(receipt.Action, "cancel:")
		return operationID == receipt.OperationID && providerauth.UUIDPattern.MatchString(operationID)
	default:
		return false
	}
}

func validStoredAuthOperation(operation storedAuthOperation) bool {
	if !providerauth.UUIDPattern.MatchString(operation.OperationID) ||
		!providerauth.UUIDPattern.MatchString(operation.CommandID) || operation.Method != "device_code" ||
		!validAuthTimestamp(operation.CreatedAt) || !validAuthTimestamp(operation.UpdatedAt) ||
		!validAuthReason(operation.ReasonCode) || operation.ExpiresAt != nil {
		return false
	}
	switch operation.Status {
	case "pending":
		if operation.TimeoutAt == nil || !validAuthTimestamp(*operation.TimeoutAt) || operation.ReasonCode != nil {
			return false
		}
		if operation.ProviderLoginID != "" && !boundedSessionText(operation.ProviderLoginID, 512) {
			return false
		}
		if operation.VerificationURL != nil {
			parsed, err := url.Parse(*operation.VerificationURL)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || len(*operation.VerificationURL) > 2048 {
				return false
			}
		}
		return operation.UserCode == nil || boundedAuthText(*operation.UserCode, 128)
	case "succeeded", "failed", "cancelled", "expired":
		return operation.VerificationURL == nil && operation.UserCode == nil
	default:
		return false
	}
}

func validAuthTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.UTC().Format(time.RFC3339Nano) == value
}

func validAuthReason(reason *string) bool {
	if reason == nil {
		return true
	}
	switch *reason {
	case "cancelled", "credential_rejected", "expired", "interrupted_by_restart", "invalid_secret",
		"managed_auth_required", "provider_operation_missing", "provider_protocol_error", "provider_unavailable", "verification_failed":
		return true
	default:
		return false
	}
}

func (adapter *Adapter) persistProviderAuthLocked() error {
	adapter.auth.Version = providerAuthVersion
	raw, err := json.Marshal(adapter.auth)
	if err != nil || len(raw) > maximumAuthStateBytes {
		return errors.New("provider auth state is unavailable")
	}
	path := filepath.Join(adapter.config.StateDir, providerAuthFile)
	temporary, err := os.CreateTemp(adapter.config.StateDir, ".provider-auth-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(adapter.config.StateDir)
	if err != nil {
		return &providerAuthIndeterminateCommitError{cause: err}
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return &providerAuthIndeterminateCommitError{cause: err}
	}
	return nil
}

func (adapter *Adapter) persistProviderAuthOrBlockLocked(operation *storedAuthOperation) bool {
	if err := adapter.persistProviderAuthLocked(); err == nil {
		return true
	}
	adapter.auth.State = "unknown"
	adapter.auth.CheckedAt = nil
	reason := "provider_unavailable"
	adapter.auth.ReasonCode = &reason
	adapter.auth.Revision++
	if operation != nil {
		operation.Status = "failed"
		operation.UpdatedAt = authTimestamp(time.Now())
		operation.ReasonCode = &reason
		operation.VerificationURL = nil
		operation.UserCode = nil
		adapter.auth.Revision++
	}
	// A second atomic write lets a transient fault durably record the safe
	// blocked reconciliation state. Persistent faults remain fail closed in
	// memory and startup will reject or reconcile the last durable receipt.
	_ = adapter.persistProviderAuthLocked()
	return false
}

func cloneProviderAuthState(state providerAuthState) providerAuthState {
	copy := state
	copy.CheckedAt = cloneStringPointer(state.CheckedAt)
	copy.ReasonCode = cloneStringPointer(state.ReasonCode)
	if state.Operation != nil {
		operation := *state.Operation
		operation.ReasonCode = cloneStringPointer(state.Operation.ReasonCode)
		operation.VerificationURL = cloneStringPointer(state.Operation.VerificationURL)
		operation.UserCode = cloneStringPointer(state.Operation.UserCode)
		operation.ExpiresAt = cloneStringPointer(state.Operation.ExpiresAt)
		operation.TimeoutAt = cloneStringPointer(state.Operation.TimeoutAt)
		copy.Operation = &operation
	}
	copy.Operations = make(map[string]storedAuthOperation, len(state.Operations))
	for id, operation := range state.Operations {
		copy.Operations[id] = operation
	}
	copy.Receipts = make(map[string]providerAuthReceipt, len(state.Receipts))
	for id, receipt := range state.Receipts {
		copy.Receipts[id] = receipt
	}
	return copy
}

func validDeviceLoginResponse(response deviceLoginResponse) bool {
	if response.Type != "chatgptDeviceCode" || !boundedSessionText(response.LoginID, 512) ||
		!boundedAuthText(response.UserCode, 128) {
		return false
	}
	parsed, err := url.Parse(response.VerificationURL)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && len(response.VerificationURL) <= 2048
}

func boundedAuthText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func newAuthID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func authTimestamp(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
func stringPointer(value string) *string   { return &value }

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func authFailure(status int, code string) *providerauth.Failure {
	return &providerauth.Failure{Status: status, Code: code}
}
