package nodesettings

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeProvider struct{ applyErr error }

func (provider fakeProvider) ListModels(context.Context, string, int) (ModelPage, error) {
	return ModelPage{Models: []Model{{ID: "m", Model: "m"}}, Fresh: true, ProcessGeneration: 2}, nil
}
func (provider fakeProvider) CheckMCP(_ context.Context, config MCPConfig) (MCPCheck, error) {
	return MCPCheck{MCPID: config.ID, Status: "available", ProcessGeneration: 2}, nil
}
func (provider fakeProvider) ApplySettings(context.Context, Settings, []MCPConfig) error {
	return provider.applyErr
}

func draftInput(revision int64, action string, secret *string) SettingsInput {
	model := "gpt-test"
	return SettingsInput{ExpectedRevision: revision, Draft: DraftInput{Inference: Inference{ModelID: &model}, MCPServers: []MCPServerInput{{
		ID: "docs", Name: "Docs", Enabled: true, URL: "https://mcp.example.test/rpc", Transport: "streamable_http", TimeoutMS: 5000,
		Auth: MCPAuthInput{Kind: "bearer", SecretAction: action, Secret: secret},
	}}}}
}

func TestDraftCASMasksAndPersistsSecrets(t *testing.T) {
	directory := t.TempDir()
	secret := "do-not-return"
	service, err := Open(directory, "node", fakeProvider{applyErr: ErrUnsupported})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Update(draftInput(0, "replace", &secret))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DraftRevision != 1 || !snapshot.Draft.MCPServers[0].Auth.BearerTokenConfigured {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "node-settings-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "" {
		t.Fatal("state was not persisted")
	}
	if _, err := service.Update(draftInput(0, "keep", nil)); !errors.Is(err, ErrStale) {
		t.Fatalf("expected stale, got %v", err)
	}
	reopened, err := Open(directory, "node", fakeProvider{applyErr: ErrUnsupported})
	if err != nil {
		t.Fatal(err)
	}
	masked := reopened.Snapshot()
	if masked.DraftRevision != 1 || !masked.Draft.MCPServers[0].Auth.BearerTokenConfigured {
		t.Fatalf("unexpected reopened snapshot: %#v", masked)
	}
	encoded, _ := os.ReadFile(filepath.Join(directory, "node-settings-v1.json"))
	if !contains(encoded, []byte(secret)) {
		t.Fatal("durable secret missing")
	}
	public, _ := jsonBytes(masked)
	if contains(public, []byte(secret)) {
		t.Fatal("secret leaked in public snapshot")
	}
}

func TestCatalogAndMCPCheckUseProviderNeutralContract(t *testing.T) {
	service, err := Open(t.TempDir(), "node", fakeProvider{})
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.Models(context.Background(), "", 50)
	if err != nil {
		t.Fatal(err)
	}
	if page.SchemaID != "harness-model-catalog-v1" || page.NodeID != "node" || page.State != "fresh" || page.CatalogRevision != 2 || len(page.Models) != 1 || page.Models[0].DisplayName != "m" || page.Models[0].ReasoningEfforts == nil || page.Models[0].SpeedModes == nil {
		t.Fatalf("unexpected catalog: %#v", page)
	}
	secret := "token"
	if _, err := service.Update(draftInput(0, "replace", &secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CheckMCP(context.Background(), 0, "docs"); !errors.Is(err, ErrStale) {
		t.Fatalf("expected stale MCP check, got %v", err)
	}
	check, err := service.CheckMCP(context.Background(), 1, "docs")
	if err != nil {
		t.Fatal(err)
	}
	if check.SchemaID != Contract || check.NodeID != "node" || check.MCPID != "docs" || check.State != "available" || check.CheckedAt == "" {
		t.Fatalf("unexpected MCP check: %#v", check)
	}
}

func TestApplyReceiptIsDurableIdempotentAndUnsupported(t *testing.T) {
	service, err := Open(t.TempDir(), "node", fakeProvider{applyErr: ErrUnsupported})
	if err != nil {
		t.Fatal(err)
	}
	secret := "token"
	if _, err := service.Update(draftInput(0, "replace", &secret)); err != nil {
		t.Fatal(err)
	}
	request := ApplyRequest{CommandID: "command-1", ExpectedRevision: 1, TargetRevision: 1}
	first, err := service.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "failed" || first.ReasonCode != "native_restart_unsupported" || service.Snapshot().Applied != nil {
		t.Fatalf("unexpected operation: %#v", first)
	}
	second, err := service.Apply(context.Background(), request)
	if err != nil || second.OperationID != first.OperationID {
		t.Fatalf("idempotency failed: %#v %v", second, err)
	}
	conflict := request
	conflict.TargetRevision = 2
	if _, err := service.Apply(context.Background(), conflict); !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrIDConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestSuccessfulApplyPublishesAppliedRevision(t *testing.T) {
	service, err := Open(t.TempDir(), "node", fakeProvider{})
	if err != nil {
		t.Fatal(err)
	}
	secret := "token"
	if _, err := service.Update(draftInput(0, "replace", &secret)); err != nil {
		t.Fatal(err)
	}
	operation, err := service.Apply(context.Background(), ApplyRequest{CommandID: "command-1", ExpectedRevision: 1, TargetRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if operation.Status != "succeeded" || operation.PreviousRevision != 0 {
		t.Fatalf("unexpected operation: %#v", operation)
	}
	snapshot := service.Snapshot()
	if snapshot.AppliedRevision != 1 || snapshot.Applied == nil {
		t.Fatalf("applied revision was not published: %#v", snapshot)
	}
}

func TestOpenRecoversRunningOperation(t *testing.T) {
	directory := t.TempDir()
	service, err := Open(directory, "node", fakeProvider{applyErr: ErrUnsupported})
	if err != nil {
		t.Fatal(err)
	}
	secret := "token"
	if _, err := service.Update(draftInput(0, "replace", &secret)); err != nil {
		t.Fatal(err)
	}
	operation, err := service.Apply(context.Background(), ApplyRequest{CommandID: "command-1", ExpectedRevision: 1, TargetRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "node-settings-v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state persistedState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	crashed := state.Operations[operation.OperationID]
	crashed.Status, crashed.Phase, crashed.ReasonCode = "running", "restart", ""
	state.Operations[operation.OperationID] = crashed
	raw, _ = json.Marshal(state)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(directory, "node", fakeProvider{applyErr: ErrUnsupported})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.Operation(operation.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Status != "failed" || recovered.Phase != "recovery" || recovered.ReasonCode != "interrupted_by_restart" {
		t.Fatalf("operation was not recovered: %#v", recovered)
	}
}

func TestPostRenameFailureReloadsCommittedDraft(t *testing.T) {
	directory := t.TempDir()
	service, err := Open(directory, "node", fakeProvider{applyErr: ErrUnsupported})
	if err != nil {
		t.Fatal(err)
	}
	service.syncDirectory = func(string) error { return errors.New("sync failed") }
	secret := "token"
	if _, err := service.Update(draftInput(0, "replace", &secret)); !errors.Is(err, ErrIndeterminate) {
		t.Fatalf("expected indeterminate error, got %v", err)
	}
	if service.Snapshot().DraftRevision != 1 {
		t.Fatalf("committed draft was rolled back in memory: %#v", service.Snapshot())
	}
	reopened, err := Open(directory, "node", fakeProvider{applyErr: ErrUnsupported})
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Snapshot().DraftRevision != 1 {
		t.Fatal("committed draft was not durable")
	}
}

func TestChangingBearerToNoneRemovesSecret(t *testing.T) {
	directory := t.TempDir()
	service, err := Open(directory, "node", fakeProvider{applyErr: ErrUnsupported})
	if err != nil {
		t.Fatal(err)
	}
	secret := "token-to-remove"
	if _, err := service.Update(draftInput(0, "replace", &secret)); err != nil {
		t.Fatal(err)
	}
	input := draftInput(1, "remove", nil)
	input.Draft.MCPServers[0].Auth.Kind = "none"
	snapshot, err := service.Update(input)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Draft.MCPServers[0].Auth.BearerTokenConfigured {
		t.Fatal("bearer token remains configured")
	}
	service.mu.Lock()
	config := providerMCP(service.state.Draft.MCPServers[0])
	service.mu.Unlock()
	if config.BearerToken != "" {
		t.Fatal("bearer token was forwarded for auth kind none")
	}
	raw, err := os.ReadFile(filepath.Join(directory, "node-settings-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if contains(raw, []byte(secret)) {
		t.Fatal("removed bearer token remains durable")
	}
	invalid := draftInput(2, "keep", nil)
	invalid.Draft.MCPServers[0].Auth.Kind = "none"
	if _, err := service.Update(invalid); !errors.Is(err, ErrInvalid) {
		t.Fatalf("none+keep accepted: %v", err)
	}
}

func jsonBytes(value any) ([]byte, error) { return json.Marshal(value) }
func contains(value, part []byte) bool    { return bytes.Contains(value, part) }
