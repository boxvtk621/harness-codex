package node

import (
	"context"
	"database/sql"
	"encoding/json"
	"sync"
	"testing"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/providerauth"
)

type testAuthManager struct {
	mu    sync.Mutex
	state string
}

func (manager *testAuthManager) envelope(nodeID string) providerauth.Envelope {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return providerauth.Envelope{SchemaID: providerauth.SchemaID, NodeID: nodeID, State: manager.state,
		Capabilities: providerauth.Capabilities{Methods: []string{"device_code"}, CanCheck: true, CanLogout: true}}
}
func (manager *testAuthManager) Snapshot(_ context.Context, nodeID string) (providerauth.Envelope, *providerauth.Failure) {
	return manager.envelope(nodeID), nil
}
func (manager *testAuthManager) Operation(_ context.Context, nodeID, _ string) (providerauth.Envelope, *providerauth.Failure) {
	return manager.envelope(nodeID), nil
}
func (manager *testAuthManager) StartAuth(_ context.Context, nodeID, _, _ string, _ *string) (providerauth.Envelope, *providerauth.Failure) {
	return manager.envelope(nodeID), nil
}
func (manager *testAuthManager) Check(_ context.Context, nodeID, _ string) (providerauth.Envelope, *providerauth.Failure) {
	return manager.envelope(nodeID), nil
}
func (manager *testAuthManager) CancelAuth(_ context.Context, nodeID, _, _ string) (providerauth.Envelope, *providerauth.Failure) {
	return manager.envelope(nodeID), nil
}
func (manager *testAuthManager) Logout(_ context.Context, nodeID, _ string) (providerauth.Envelope, *providerauth.Failure) {
	return manager.envelope(nodeID), nil
}

func (manager *testAuthManager) setState(state string) {
	manager.mu.Lock()
	manager.state = state
	manager.mu.Unlock()
}

func TestRecoveredDispatchRequeuesWhenAuthenticationCloses(t *testing.T) {
	ctx := context.Background()
	const nodeID = "20000000-0000-4000-8000-000000000001"
	manager := &testAuthManager{state: "authenticated"}
	adapter := fixture.NewAdapter()
	opened, err := Open(ctx, Config{DataDir: t.TempDir(), NodeID: nodeID, OwnerID: "1-1", RegistryVersion: 1,
		Adapter: adapter, Policies: fixture.NewPolicySource(), Space: fullSpace{}, ManualDispatchForTesting: true, ProviderAuth: manager})
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	opened.stop()
	<-opened.done
	trust := TrustContext{TransportNodeID: nodeID}
	created := opened.SubmitCommand(ctx, trust, []byte(`{"protocolVersion":1,"schemaId":"harness-wire-v2","commandId":"10000000-0000-4000-8000-000000000001","kind":"dialog.create","target":{"nodeId":"`+nodeID+`"},"expected":{"registryVersion":1},"payload":{}}`))
	var receipt harnessprotocol.Receipt
	if created.HTTPStatus != 202 || json.Unmarshal(created.Body, &receipt) != nil {
		t.Fatalf("create=%d %s", created.HTTPStatus, created.Body)
	}
	var references harnessprotocol.DialogCreateReferences
	if json.Unmarshal(receipt.References, &references) != nil {
		t.Fatal("dialog references are invalid")
	}
	enqueued := opened.SubmitCommand(ctx, trust, []byte(`{"protocolVersion":1,"schemaId":"harness-wire-v2","commandId":"10000000-0000-4000-8000-000000000002","kind":"message.enqueue","target":{"nodeId":"`+nodeID+`","dialogId":"`+references.DialogID+`"},"expected":{"dialogVersion":1},"payload":{"text":"must wait"}}`))
	if enqueued.HTTPStatus != 202 {
		t.Fatalf("enqueue=%d %s", enqueued.HTTPStatus, enqueued.Body)
	}
	dispatched, err := opened.DispatchNext(ctx)
	if err != nil || dispatched.AttemptID == "" {
		t.Fatalf("dispatch=%+v err=%v", dispatched, err)
	}
	manager.setState("unknown")
	action, ok := opened.claimAction(ctx, "dispatch")
	if !ok {
		t.Fatal("durable dispatch action was not claimable")
	}
	opened.performAction(ctx, action)
	var status string
	if err := opened.db.QueryRow("SELECT status FROM control_actions WHERE command_id=?", action.commandID).Scan(&status); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	if status != "pending" || len(adapter.Calls) != 0 {
		t.Fatalf("closed auth crossed native boundary: status=%s calls=%+v", status, adapter.Calls)
	}
}
