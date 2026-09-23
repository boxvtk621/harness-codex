package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

func TestSettingsFenceDrainsWithoutCancelAndReleasesOnTimeout(t *testing.T) {
	ctx := context.Background()
	const nodeID = "20000000-0000-4000-8000-000000000001"
	opened, err := Open(ctx, Config{DataDir: t.TempDir(), NodeID: nodeID, OwnerID: "1-1", RegistryVersion: 1,
		Adapter: fixture.NewAdapter(), Policies: fixture.NewPolicySource(), Space: fullSpace{}, ManualDispatchForTesting: true,
		ProviderAuth: &testAuthManager{state: "authenticated"}})
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if _, err := opened.db.ExecContext(ctx, "UPDATE node_state SET occupancy='running' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := opened.BeginSettingsChange(waitCtx); done <- err }()
	deadline := time.Now().Add(time.Second)
	for !opened.settingsApplyBusy() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !opened.settingsApplyBusy() {
		t.Fatal("settings barrier was not installed")
	}
	if result := opened.ProviderAuthStart(ctx, nodeID, "command", "device_code", nil); result.HTTPStatus != http.StatusConflict {
		t.Fatalf("provider auth crossed settings barrier: %d", result.HTTPStatus)
	}
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain returned %v", err)
	}
	if opened.settingsApplyBusy() {
		t.Fatal("timed out barrier was retained")
	}
	if _, err := opened.db.ExecContext(ctx, "UPDATE node_state SET occupancy='idle' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	trust := TrustContext{TransportNodeID: nodeID}
	created := opened.SubmitCommand(ctx, trust, []byte(`{"protocolVersion":1,"schemaId":"harness-wire-v2","commandId":"10000000-0000-4000-8000-000000000001","kind":"dialog.create","target":{"nodeId":"`+nodeID+`"},"expected":{"registryVersion":1},"payload":{}}`))
	var receipt harnessprotocol.Receipt
	if created.HTTPStatus != http.StatusAccepted || json.Unmarshal(created.Body, &receipt) != nil {
		t.Fatalf("create dialog: %d %s", created.HTTPStatus, created.Body)
	}
	var references harnessprotocol.DialogCreateReferences
	if json.Unmarshal(receipt.References, &references) != nil {
		t.Fatal("dialog reference is invalid")
	}
	enqueued := opened.SubmitCommand(ctx, trust, []byte(`{"protocolVersion":1,"schemaId":"harness-wire-v2","commandId":"10000000-0000-4000-8000-000000000002","kind":"message.enqueue","target":{"nodeId":"`+nodeID+`","dialogId":"`+references.DialogID+`"},"expected":{"dialogVersion":1},"payload":{"text":"wait for apply"}}`))
	if enqueued.HTTPStatus != http.StatusAccepted {
		t.Fatalf("enqueue: %d %s", enqueued.HTTPStatus, enqueued.Body)
	}
	release, err := opened.BeginSettingsChange(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !opened.settingsApplyBusy() {
		t.Fatal("successful fence was not retained")
	}
	dispatched := make(chan DispatchResult, 1)
	go func() { result, _ := opened.DispatchNext(ctx); dispatched <- result }()
	select {
	case result := <-dispatched:
		t.Fatalf("dispatch crossed settings fence: %+v", result)
	case <-time.After(50 * time.Millisecond):
	}
	release()
	select {
	case result := <-dispatched:
		if result.AttemptID == "" {
			t.Fatalf("dispatch did not resume after release: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("dispatch did not resume after release")
	}
	if opened.settingsApplyBusy() {
		t.Fatal("release did not reopen lifecycle")
	}
	opened.SetSettingsReady(false)
	if result := opened.HealthReady(ctx, TrustContext{TransportNodeID: nodeID}); result.HTTPStatus != http.StatusOK || !bytes.Contains(result.Body, []byte(`"engine_unavailable"`)) {
		t.Fatalf("failed rollback did not block readiness: %d %s", result.HTTPStatus, result.Body)
	}
}
