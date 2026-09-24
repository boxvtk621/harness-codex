package nodesettings

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type immediateLifecycle struct{}

func (immediateLifecycle) BeginSettingsChange(context.Context) (func(), error) { return func() {}, nil }

func awaitOperation(t *testing.T, service *Service, id string) Operation {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		operation, err := service.Operation(id)
		if err != nil {
			t.Fatal(err)
		}
		if operation.Status != "running" {
			return operation
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("node settings apply did not complete")
	return Operation{}
}

type fakeProvider struct{ applyErr error }

type recordingProvider struct{ applied []Settings }

func (provider *recordingProvider) ListModels(context.Context, string, int) (ModelPage, error) {
	return ModelPage{}, nil
}
func (provider *recordingProvider) CheckMCP(context.Context, MCPConfig) (MCPCheck, error) {
	return MCPCheck{}, nil
}
func (provider *recordingProvider) ApplySettings(_ context.Context, settings Settings, _ []MCPConfig) error {
	provider.applied = append(provider.applied, settings)
	return nil
}

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
	if page.SchemaID != "harness-model-catalog-v2" || page.NodeID != "node" || page.State != "fresh" || page.CatalogRevision != 2 || len(page.Models) != 1 || page.Models[0].DisplayName != "m" || page.Models[0].ReasoningEfforts == nil || page.Models[0].SpeedModes == nil {
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
	service.SetLifecycle(immediateLifecycle{})
	secret := "token"
	if _, err := service.Update(draftInput(0, "replace", &secret)); err != nil {
		t.Fatal(err)
	}
	request := ApplyRequest{CommandID: "command-1", ExpectedRevision: 1, TargetRevision: 1}
	first, err := service.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	first = awaitOperation(t, service, first.OperationID)
	if first.Status != "failed" || first.ReasonCode != "parameter_unsupported" || service.Snapshot().Applied != nil {
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
	service.SetLifecycle(immediateLifecycle{})
	secret := "token"
	if _, err := service.Update(draftInput(0, "replace", &secret)); err != nil {
		t.Fatal(err)
	}
	operation, err := service.Apply(context.Background(), ApplyRequest{CommandID: "command-1", ExpectedRevision: 1, TargetRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	operation = awaitOperation(t, service, operation.OperationID)
	if operation.Status != "succeeded" || operation.PreviousRevision != 0 {
		t.Fatalf("unexpected operation: %#v", operation)
	}
	snapshot := service.Snapshot()
	if snapshot.AppliedRevision != 1 || snapshot.Applied == nil {
		t.Fatalf("applied revision was not published: %#v", snapshot)
	}
}

func TestRestartRestoresOnlyConfirmedSnapshotAndReplaysCommand(t *testing.T) {
	directory := t.TempDir()
	provider := &recordingProvider{}
	service, err := Open(directory, "node", provider)
	if err != nil {
		t.Fatal(err)
	}
	service.SetLifecycle(immediateLifecycle{})
	firstModel, secondModel := "confirmed", "draft-only"
	if _, err := service.Update(SettingsInput{ExpectedRevision: 0, Draft: DraftInput{Inference: Inference{ModelID: &firstModel}}}); err != nil {
		t.Fatal(err)
	}
	request := ApplyRequest{CommandID: "stable-command", ExpectedRevision: 1, TargetRevision: 1}
	first, err := service.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if completed := awaitOperation(t, service, first.OperationID); completed.Status != "succeeded" {
		t.Fatalf("apply: %+v", completed)
	}
	if _, err := service.Update(SettingsInput{ExpectedRevision: 1, Draft: DraftInput{Inference: Inference{ModelID: &secondModel}}}); err != nil {
		t.Fatal(err)
	}
	restarted := &recordingProvider{}
	reopened, err := Open(directory, "node", restarted)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.RestoreApplied(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(restarted.applied) != 1 || restarted.applied[0].Inference.ModelID == nil || *restarted.applied[0].Inference.ModelID != firstModel {
		t.Fatalf("draft activated on restart: %+v", restarted.applied)
	}
	replay, err := reopened.Apply(context.Background(), request)
	if err != nil || replay.OperationID != first.OperationID || len(restarted.applied) != 1 {
		t.Fatalf("command replay caused apply: %+v %v", replay, err)
	}
}

func TestOpenRecoversRunningOperation(t *testing.T) {
	directory := t.TempDir()
	service, err := Open(directory, "node", fakeProvider{applyErr: ErrUnsupported})
	if err != nil {
		t.Fatal(err)
	}
	service.SetLifecycle(immediateLifecycle{})
	secret := "token"
	if _, err := service.Update(draftInput(0, "replace", &secret)); err != nil {
		t.Fatal(err)
	}
	operation, err := service.Apply(context.Background(), ApplyRequest{CommandID: "command-1", ExpectedRevision: 1, TargetRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	awaitOperation(t, service, operation.OperationID)
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

func TestV2StdioSecretSlotsAndLocalValidation(t *testing.T) {
	service, err := Open(t.TempDir(), "node", fakeProvider{})
	if err != nil {
		t.Fatal(err)
	}
	secret := "hidden-stdio-value"
	server := MCPServerInput{ID: "local", Name: "Local", Enabled: true, Transport: "stdio", Command: "/usr/bin/mcp-local", Args: []string{"serve"}, TimeoutMS: 5000, SecretSlots: []SecretSlotInput{{Slot: "API_KEY", Action: "replace", Secret: &secret}}}
	document := MCPDocumentInput{SchemaID: MCPDocumentSchema, Servers: []MCPServerInput{server}}
	if err := service.ValidateMCPDocument(document); err != nil {
		t.Fatal(err)
	}
	if service.Snapshot().DraftRevision != 0 {
		t.Fatal("validation wrote state")
	}
	snapshot, err := service.Update(SettingsInput{ExpectedRevision: 0, Draft: DraftInput{MCPDocument: &document}})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaID != Contract || snapshot.MCPSchema != MCPDocumentSchema || len(snapshot.Draft.MCPDocument.Servers) != 1 {
		t.Fatalf("unexpected V2 snapshot: %#v", snapshot)
	}
	public, _ := json.Marshal(snapshot)
	if bytes.Contains(public, []byte(secret)) || bytes.Contains(public, []byte("env")) {
		t.Fatalf("stdio secret leaked: %s", public)
	}
	server.SecretSlots = []SecretSlotInput{{Slot: "API_KEY", Action: "keep"}}
	document.Servers = []MCPServerInput{server}
	if _, err := service.Update(SettingsInput{ExpectedRevision: 1, Draft: DraftInput{MCPDocument: &document}}); err != nil {
		t.Fatal(err)
	}
	service.mu.Lock()
	config := providerMCP(service.state.Draft.MCPServers[0])
	service.mu.Unlock()
	if config.SecretValues["API_KEY"] != secret {
		t.Fatal("stable secret slot was not retained")
	}
	server.ForbiddenPath = "url"
	document.Servers = []MCPServerInput{server}
	if err := service.ValidateMCPDocument(document); !errors.Is(err, ErrInvalid) {
		t.Fatalf("type-specific field accepted: %v", err)
	}
	server.ForbiddenPath = ""
	server.SecretSlots = []SecretSlotInput{{Slot: "API_KEY", Action: "remove"}}
	document.Servers = []MCPServerInput{server}
	if _, err := service.Update(SettingsInput{ExpectedRevision: 2, Draft: DraftInput{MCPDocument: &document}}); err != nil {
		t.Fatal(err)
	}
	service.mu.Lock()
	config = providerMCP(service.state.Draft.MCPServers[0])
	service.mu.Unlock()
	if len(config.SecretValues) != 0 {
		t.Fatal("removed secret survived")
	}
}

func TestPersistedV1BearerMigratesLosslessly(t *testing.T) {
	directory := t.TempDir()
	service, err := Open(directory, "node", fakeProvider{})
	if err != nil {
		t.Fatal(err)
	}
	secret := "legacy-secret"
	if _, err := service.Update(draftInput(0, "replace", &secret)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "node-settings-v1.json")
	raw, _ := os.ReadFile(path)
	var state persistedState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	state.Contract = "harness-node-settings-v1"
	raw, _ = json.Marshal(state)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(directory, "node", fakeProvider{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := reopened.Snapshot()
	if snapshot.SchemaID != Contract || !snapshot.Draft.MCPDocument.Servers[0].Auth.BearerTokenConfigured {
		t.Fatalf("legacy bearer lost: %#v", snapshot)
	}
	reopened.mu.Lock()
	config := providerMCP(reopened.state.Draft.MCPServers[0])
	reopened.mu.Unlock()
	if config.BearerToken != secret {
		t.Fatal("legacy secret changed")
	}
}
