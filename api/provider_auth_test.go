package server_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/boxvtk621/harness-codex/api"
	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/providerauth"
	"github.com/boxvtk621/harness-codex/runtime"
)

type providerAuthFixture struct {
	state     string
	operation *providerauth.Operation
}

func (fixture *providerAuthFixture) envelope(nodeID string) providerauth.Envelope {
	return providerauth.Envelope{
		SchemaID: providerauth.SchemaID, NodeID: nodeID, Revision: 1, State: fixture.state,
		Capabilities: providerauth.Capabilities{Methods: []string{"device_code"}, CanCheck: true, CanLogout: true},
		Operation:    fixture.operation,
	}
}

func (fixture *providerAuthFixture) Snapshot(_ context.Context, nodeID string) (providerauth.Envelope, *providerauth.Failure) {
	return fixture.envelope(nodeID), nil
}
func (fixture *providerAuthFixture) Operation(_ context.Context, nodeID, _ string) (providerauth.Envelope, *providerauth.Failure) {
	return fixture.envelope(nodeID), nil
}
func (fixture *providerAuthFixture) StartAuth(_ context.Context, nodeID, commandID, method string, _ *string) (providerauth.Envelope, *providerauth.Failure) {
	fixture.operation = &providerauth.Operation{OperationID: "62000000-0000-4000-8000-000000000001", CommandID: commandID, Method: method, Status: "pending", CreatedAt: "2026-09-21T12:00:00Z", UpdatedAt: "2026-09-21T12:00:00Z"}
	return fixture.envelope(nodeID), nil
}
func (fixture *providerAuthFixture) Check(_ context.Context, nodeID, _ string) (providerauth.Envelope, *providerauth.Failure) {
	return fixture.envelope(nodeID), nil
}
func (fixture *providerAuthFixture) CancelAuth(_ context.Context, nodeID, _, _ string) (providerauth.Envelope, *providerauth.Failure) {
	return fixture.envelope(nodeID), nil
}
func (fixture *providerAuthFixture) Logout(_ context.Context, nodeID, _ string) (providerauth.Envelope, *providerauth.Failure) {
	return fixture.envelope(nodeID), nil
}

func TestProviderAuthRoutesAndStrictBodies(t *testing.T) {
	fixtureAuth := &providerAuthFixture{state: "authenticated"}
	authority, err := node.Open(context.Background(), node.Config{
		DataDir: t.TempDir(), NodeID: testNodeID, OwnerID: "1-1", RegistryVersion: 1,
		Adapter: fixture.NewAdapter(), Policies: fixture.NewPolicySource(), Space: enoughSpace{},
		ManualDispatchForTesting: true, ProviderAuth: fixtureAuth,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	handler, err := server.New(server.Config{NodeID: testNodeID}, authority)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(handler)
	defer endpoint.Close()

	response, err := http.Get(endpoint.URL + "/v1/provider-auth?nodeId=" + testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	assertProviderAuthResponse(t, response, http.StatusOK)

	body := `{"nodeId":"` + testNodeID + `","commandId":"61000000-0000-4000-8000-000000000001","method":"device_code"}`
	request, _ := http.NewRequest(http.MethodPost, endpoint.URL+"/v1/provider-auth/operations", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	envelope := assertProviderAuthResponse(t, response, http.StatusOK)
	if envelope.NodeID != testNodeID || envelope.Operation == nil || envelope.Operation.CommandID != "61000000-0000-4000-8000-000000000001" {
		t.Fatalf("unexpected envelope: %+v", envelope)
	}

	invalid := strings.TrimSuffix(body, "}") + `,"unexpected":true}`
	request, _ = http.NewRequest(http.MethodPost, endpoint.URL+"/v1/provider-auth/operations", strings.NewReader(invalid))
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusBadRequest || string(raw) != `{"code":"invalid_request"}` {
		t.Fatalf("strict body status=%d body=%s", response.StatusCode, raw)
	}
}

func assertProviderAuthResponse(t *testing.T, response *http.Response, status int) providerauth.Envelope {
	t.Helper()
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != status {
		t.Fatalf("status=%d body=%s err=%v", response.StatusCode, raw, err)
	}
	var envelope providerauth.Envelope
	if json.Unmarshal(raw, &envelope) != nil || envelope.SchemaID != providerauth.SchemaID {
		t.Fatalf("invalid provider auth envelope: %s", raw)
	}
	return envelope
}
