package server

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/boxvtk621/harness-codex/internal/nodesettings"
)

func TestNodeSettingsUnknownFieldHasJSONPointer(t *testing.T) {
	raw := []byte(`{"expectedRevision":0,"draft":{"inference":{"modelId":null},"mcpDocument":{"schemaId":"harness-mcp-document-v2","servers":[{"id":"docs","name":"Docs","enabled":true,"transport":"streamable_http","url":"https://example.test","timeoutMs":1000,"auth":{"kind":"none"},"surprise":true}]}}}`)
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	if path := unknownJSONPath(generic, reflect.TypeOf(&nodesettings.SettingsInput{}), ""); path != "/draft/mcpDocument/servers/0/surprise" {
		t.Fatalf("unknown field pointer = %q", path)
	}
}

func TestNodeSettingsTransportFieldPresence(t *testing.T) {
	for _, tc := range []struct {
		raw       string
		forbidden string
	}{
		{`{"transport":"stdio","auth":{}}`, "auth"},
		{`{"transport":"streamable_http","command":""}`, "command"},
	} {
		var server nodesettings.MCPServerInput
		if err := json.Unmarshal([]byte(tc.raw), &server); err != nil {
			t.Fatal(err)
		}
		if server.ForbiddenPath != tc.forbidden {
			t.Fatalf("forbidden field = %q", server.ForbiddenPath)
		}
	}
}
