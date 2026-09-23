// Package nodesettings defines the provider-neutral node settings contract.
package nodesettings

import (
	"context"
	"encoding/json"
)

const Contract = "harness-node-settings-v1"

type MCPAuthInput struct {
	Kind         string  `json:"kind"`
	SecretAction string  `json:"secretAction"`
	Secret       *string `json:"secret,omitempty"`
}

type MCPAuth struct {
	Kind                  string `json:"kind"`
	BearerTokenConfigured bool   `json:"bearerTokenConfigured"`
}

type MCPServerInput struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Enabled   bool         `json:"enabled"`
	URL       string       `json:"url"`
	Transport string       `json:"transport"`
	TimeoutMS int64        `json:"timeoutMs"`
	Auth      MCPAuthInput `json:"auth"`
}

type MCPServer struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Enabled   bool    `json:"enabled"`
	URL       string  `json:"url"`
	Transport string  `json:"transport"`
	TimeoutMS int64   `json:"timeoutMs"`
	Auth      MCPAuth `json:"auth"`
}

type Inference struct {
	ModelID         *string `json:"modelId"`
	SpeedMode       *string `json:"speedMode"`
	ReasoningEffort *string `json:"reasoningEffort"`
}

type SettingsInput struct {
	ExpectedRevision int64      `json:"expectedRevision"`
	Draft            DraftInput `json:"draft"`
}

type DraftInput struct {
	MCPServers []MCPServerInput `json:"mcpServers"`
	Inference  Inference        `json:"inference"`
}

type Settings struct {
	MCPServers []MCPServer `json:"mcpServers"`
	Inference  Inference   `json:"inference"`
}

type Snapshot struct {
	SchemaID        string            `json:"schemaId"`
	NodeID          string            `json:"nodeId"`
	DraftRevision   int64             `json:"draftRevision"`
	AppliedRevision int64             `json:"appliedRevision"`
	Draft           Settings          `json:"draft"`
	Applied         *Settings         `json:"applied"`
	Capabilities    map[string]string `json:"capabilities"`
	Operation       *Operation        `json:"operation,omitempty"`
	Observations    []Observation     `json:"observations,omitempty"`
}

type Observation struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type ApplyRequest struct {
	CommandID        string `json:"commandId"`
	ExpectedRevision int64  `json:"expectedRevision"`
	TargetRevision   int64  `json:"targetRevision"`
}

type Operation struct {
	OperationID      string `json:"operationId"`
	CommandID        string `json:"commandId"`
	TargetRevision   int64  `json:"targetRevision"`
	PreviousRevision int64  `json:"previousRevision"`
	Status           string `json:"status"`
	Phase            string `json:"phase"`
	ReasonCode       string `json:"reasonCode,omitempty"`
	CreatedAt        string `json:"createdAt"`
	UpdatedAt        string `json:"updatedAt"`
}

type Model struct {
	ID                        string   `json:"id"`
	Model                     string   `json:"-"`
	SupportedReasoningEfforts []string `json:"-"`
	DefaultReasoningEffort    *string  `json:"-"`
	ServiceTiers              []string `json:"-"`
	DefaultServiceTier        *string  `json:"-"`
	AdditionalSpeedTiers      []string `json:"-"`
	DisplayName               string   `json:"displayName"`
	ReasoningEfforts          []Mode   `json:"reasoningEfforts"`
	SpeedModes                []Mode   `json:"speedModes"`
}

type Mode struct {
	ID        string `json:"id"`
	IsDefault bool   `json:"isDefault,omitempty"`
}

type ModelPage struct {
	SchemaID          string  `json:"schemaId"`
	NodeID            string  `json:"nodeId"`
	CatalogRevision   int64   `json:"catalogRevision"`
	FetchedAt         string  `json:"fetchedAt"`
	State             string  `json:"state"`
	Models            []Model `json:"models"`
	NextCursor        *string `json:"nextCursor"`
	ProcessGeneration int64   `json:"-"`
	Fresh             bool    `json:"-"`
}

type MCPCheck struct {
	SchemaID          string `json:"schemaId"`
	NodeID            string `json:"nodeId"`
	MCPID             string `json:"mcpServerId"`
	CheckedAt         string `json:"checkedAt"`
	State             string `json:"state"`
	ReasonCode        string `json:"reasonCode,omitempty"`
	Status            string `json:"-"`
	ErrorCode         string `json:"-"`
	ProcessGeneration int64  `json:"-"`
}

// MCPConfig is passed only inside the process. Its token must never be logged or
// serialized into an API response.
type MCPConfig struct {
	MCPServer
	BearerToken string
}

type Provider interface {
	ListModels(context.Context, string, int) (ModelPage, error)
	CheckMCP(context.Context, MCPConfig) (MCPCheck, error)
	ApplySettings(context.Context, Settings, []MCPConfig) error
}

type persistedSecret struct {
	Value   string `json:"value"`
	Version int64  `json:"version"`
}

type persistedMCP struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Enabled     bool             `json:"enabled"`
	URL         string           `json:"url"`
	Transport   string           `json:"transport"`
	TimeoutMS   int64            `json:"timeoutMs"`
	AuthKind    string           `json:"authKind"`
	BearerToken *persistedSecret `json:"bearerToken,omitempty"`
}

type persistedSettings struct {
	MCPServers []persistedMCP `json:"mcpServers"`
	Inference  Inference      `json:"inference"`
}

type persistedState struct {
	Contract        string                     `json:"contract"`
	NodeID          string                     `json:"nodeId"`
	DraftRevision   int64                      `json:"draftRevision"`
	AppliedRevision int64                      `json:"appliedRevision"`
	Draft           persistedSettings          `json:"draft"`
	Applied         persistedSettings          `json:"applied"`
	Operations      map[string]Operation       `json:"operations"`
	Commands        map[string]string          `json:"commands"`
	CommandPayloads map[string]json.RawMessage `json:"commandPayloads"`
}
