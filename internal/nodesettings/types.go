// Package nodesettings defines the provider-neutral node settings contract.
package nodesettings

import (
	"context"
	"encoding/json"
)

const Contract = "harness-node-settings-v2"
const MCPDocumentSchema = "harness-mcp-document-v2"

type SecretSlotInput struct {
	Slot   string  `json:"slot"`
	Action string  `json:"action"`
	Secret *string `json:"secret,omitempty"`
}
type SecretSlot struct {
	Slot       string `json:"slot"`
	Configured bool   `json:"configured"`
}

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
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Enabled       bool              `json:"enabled"`
	URL           string            `json:"url"`
	Transport     string            `json:"transport"`
	TimeoutMS     int64             `json:"timeoutMs"`
	Auth          MCPAuthInput      `json:"auth"`
	Command       string            `json:"command,omitempty"`
	Args          []string          `json:"args,omitempty"`
	SecretSlots   []SecretSlotInput `json:"secretSlots,omitempty"`
	ForbiddenPath string            `json:"-"`
}

func (server *MCPServerInput) UnmarshalJSON(raw []byte) error {
	type alias MCPServerInput
	var decoded alias
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	*server = MCPServerInput(decoded)
	if server.Transport == "streamable_http" {
		for _, field := range []string{"command", "args", "secretSlots"} {
			if _, ok := fields[field]; ok {
				server.ForbiddenPath = field
				break
			}
		}
	}
	if server.Transport == "stdio" {
		for _, field := range []string{"url", "auth"} {
			if _, ok := fields[field]; ok {
				server.ForbiddenPath = field
				break
			}
		}
	}
	return nil
}

type MCPServer struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Enabled     bool         `json:"enabled"`
	URL         string       `json:"url"`
	Transport   string       `json:"transport"`
	TimeoutMS   int64        `json:"timeoutMs"`
	Auth        MCPAuth      `json:"auth"`
	Command     string       `json:"command,omitempty"`
	Args        []string     `json:"args,omitempty"`
	SecretSlots []SecretSlot `json:"secretSlots,omitempty"`
}

func (server MCPServer) MarshalJSON() ([]byte, error) {
	base := map[string]any{"id": server.ID, "name": server.Name, "enabled": server.Enabled, "transport": server.Transport, "timeoutMs": server.TimeoutMS}
	if server.Transport == "stdio" {
		base["command"] = server.Command
		if server.Args == nil {
			base["args"] = []string{}
		} else {
			base["args"] = server.Args
		}
		if server.SecretSlots == nil {
			base["secretSlots"] = []SecretSlot{}
		} else {
			base["secretSlots"] = server.SecretSlots
		}
	} else {
		base["url"] = server.URL
		base["auth"] = server.Auth
	}
	return json.Marshal(base)
}

type MCPDocumentInput struct {
	SchemaID string           `json:"schemaId"`
	Servers  []MCPServerInput `json:"servers"`
}
type MCPDocument struct {
	SchemaID string      `json:"schemaId"`
	Servers  []MCPServer `json:"servers"`
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
	MCPServers  []MCPServerInput  `json:"mcpServers,omitempty"`
	MCPDocument *MCPDocumentInput `json:"mcpDocument,omitempty"`
	Inference   Inference         `json:"inference"`
}

type Settings struct {
	MCPServers  []MCPServer `json:"-"`
	MCPDocument MCPDocument `json:"mcpDocument"`
	Inference   Inference   `json:"inference"`
}

type Snapshot struct {
	SchemaID        string            `json:"schemaId"`
	NodeID          string            `json:"nodeId"`
	DraftRevision   int64             `json:"draftRevision"`
	AppliedRevision int64             `json:"appliedRevision"`
	Draft           Settings          `json:"draft"`
	Applied         *Settings         `json:"applied"`
	Capabilities    map[string]string `json:"capabilities"`
	MCPSchema       string            `json:"mcpSchema"`
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
	IsDefault                 bool     `json:"isDefault"`
	ReasoningEfforts          []Mode   `json:"reasoningEfforts"`
	SpeedModes                []Mode   `json:"speedModes"`
	Compatibility             string   `json:"compatibility"`
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
	BearerToken  string
	SecretValues map[string]string `json:"-"`
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
	ID          string                     `json:"id"`
	Name        string                     `json:"name"`
	Enabled     bool                       `json:"enabled"`
	URL         string                     `json:"url"`
	Transport   string                     `json:"transport"`
	TimeoutMS   int64                      `json:"timeoutMs"`
	AuthKind    string                     `json:"authKind"`
	BearerToken *persistedSecret           `json:"bearerToken,omitempty"`
	Command     string                     `json:"command,omitempty"`
	Args        []string                   `json:"args,omitempty"`
	SecretSlots map[string]persistedSecret `json:"secretSlots,omitempty"`
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
