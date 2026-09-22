// Package providerauth defines the provider-neutral Harness authentication seam.
package providerauth

import (
	"context"
	"regexp"
)

const SchemaID = "harness-provider-auth-v1"

var UUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Capabilities struct {
	Methods   []string `json:"methods"`
	CanCheck  bool     `json:"canCheck"`
	CanLogout bool     `json:"canLogout"`
}

type Operation struct {
	OperationID     string  `json:"operationId"`
	CommandID       string  `json:"commandId"`
	Method          string  `json:"method"`
	Status          string  `json:"status"`
	CreatedAt       string  `json:"createdAt"`
	UpdatedAt       string  `json:"updatedAt"`
	ReasonCode      *string `json:"reasonCode"`
	VerificationURL *string `json:"verificationUrl"`
	UserCode        *string `json:"userCode"`
	ExpiresAt       *string `json:"expiresAt"`
	TimeoutAt       *string `json:"timeoutAt"`
}

type Envelope struct {
	SchemaID     string       `json:"schemaId"`
	NodeID       string       `json:"nodeId"`
	Revision     int64        `json:"revision"`
	State        string       `json:"state"`
	CheckedAt    *string      `json:"checkedAt"`
	ReasonCode   *string      `json:"reasonCode"`
	Capabilities Capabilities `json:"capabilities"`
	Operation    *Operation   `json:"operation"`
}

type Failure struct {
	Status int
	Code   string
}

type Manager interface {
	Snapshot(context.Context, string) (Envelope, *Failure)
	Operation(context.Context, string, string) (Envelope, *Failure)
	StartAuth(context.Context, string, string, string, *string) (Envelope, *Failure)
	Check(context.Context, string, string) (Envelope, *Failure)
	CancelAuth(context.Context, string, string, string) (Envelope, *Failure)
	Logout(context.Context, string, string) (Envelope, *Failure)
}
