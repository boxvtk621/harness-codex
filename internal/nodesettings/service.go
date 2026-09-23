package nodesettings

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

var (
	ErrInvalid        = errors.New("node settings input is invalid")
	ErrStale          = errors.New("node settings revision is stale")
	ErrNotFound       = errors.New("node settings object was not found")
	ErrIDConflict     = errors.New("node settings command id conflicts")
	ErrUnsupported    = errors.New("node settings apply is unsupported")
	ErrIndeterminate  = errors.New("node settings persistence is indeterminate")
	ErrRollbackFailed = errors.New("node settings rollback failed")
)

type Service struct {
	mu        sync.Mutex
	applyMu   sync.Mutex
	path      string
	state     persistedState
	provider  Provider
	lifecycle interface {
		BeginSettingsChange(context.Context) (func(), error)
	}
	now           func() time.Time
	syncDirectory func(string) error
}

func (service *Service) markReady(ready bool) {
	if lifecycle, ok := service.lifecycle.(interface{ SetSettingsReady(bool) }); ok {
		lifecycle.SetSettingsReady(ready)
	}
}

// SetLifecycle connects settings apply to the node's dispatch and auth fence.
// It must be called before the HTTP server starts accepting requests.
func (service *Service) SetLifecycle(lifecycle interface {
	BeginSettingsChange(context.Context) (func(), error)
}) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.lifecycle = lifecycle
}

// RestoreApplied returns only the last confirmed configuration. A draft is
// never used during process startup or crash recovery.
func (service *Service) RestoreApplied(ctx context.Context) error {
	service.mu.Lock()
	applied := service.state.Applied
	revision := service.state.AppliedRevision
	service.mu.Unlock()
	if revision == 0 {
		return nil
	}
	return service.provider.ApplySettings(ctx, publicSettings(applied), providerMCPs(applied))
}

func Open(dataDir, nodeID string, provider Provider) (*Service, error) {
	if dataDir == "" || nodeID == "" || provider == nil {
		return nil, ErrInvalid
	}
	service := &Service{path: filepath.Join(dataDir, "node-settings-v1.json"), provider: provider, now: time.Now, syncDirectory: syncDirectory}
	service.state = persistedState{Contract: Contract, NodeID: nodeID, Operations: map[string]Operation{}, Commands: map[string]string{}, CommandPayloads: map[string]json.RawMessage{}}
	raw, err := os.ReadFile(service.path)
	if errors.Is(err, os.ErrNotExist) {
		return service, service.persistLocked()
	}
	if err != nil || len(raw) > 1<<20 {
		return nil, errors.New("read node settings state")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&service.state); err != nil || decoder.Decode(new(any)) != io.EOF || service.state.Contract != Contract || service.state.NodeID != nodeID || service.state.DraftRevision < service.state.AppliedRevision {
		return nil, errors.New("node settings state is invalid")
	}
	if service.state.Operations == nil || service.state.Commands == nil || service.state.CommandPayloads == nil {
		return nil, errors.New("node settings state is incomplete")
	}
	recovered := false
	for operationID, operation := range service.state.Operations {
		if operation.Status == "running" {
			operation.Status, operation.Phase, operation.ReasonCode = "failed", "recovery", "interrupted_by_restart"
			operation.UpdatedAt = service.now().UTC().Format(time.RFC3339Nano)
			service.state.Operations[operationID] = operation
			recovered = true
		}
	}
	if recovered {
		if err := service.persistLocked(); err != nil {
			return nil, fmt.Errorf("recover node settings operations: %w", err)
		}
	}
	return service, nil
}

func (service *Service) Snapshot() Snapshot {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.snapshotLocked()
}

func (service *Service) Update(input SettingsInput) (Snapshot, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if input.ExpectedRevision != service.state.DraftRevision {
		return service.snapshotLocked(), ErrStale
	}
	next, err := mergeSettings(service.state.Draft, input)
	if err != nil {
		return Snapshot{}, err
	}
	previous := service.state.Draft
	service.state.Draft = next
	service.state.DraftRevision++
	if err := service.persistLocked(); err != nil {
		if errors.Is(err, ErrIndeterminate) {
			if reloadErr := service.reloadLocked(); reloadErr != nil {
				return Snapshot{}, fmt.Errorf("reload indeterminate node settings: %w", reloadErr)
			}
		} else {
			service.state.DraftRevision--
			service.state.Draft = previous
		}
		return Snapshot{}, err
	}
	return service.snapshotLocked(), nil
}

func (service *Service) Apply(ctx context.Context, input ApplyRequest) (Operation, error) {
	service.applyMu.Lock()
	defer service.applyMu.Unlock()
	service.mu.Lock()
	if !identifier.MatchString(input.CommandID) {
		service.mu.Unlock()
		return Operation{}, ErrInvalid
	}
	payload, _ := json.Marshal(input)
	if operationID, ok := service.state.Commands[input.CommandID]; ok {
		if !bytes.Equal(service.state.CommandPayloads[input.CommandID], payload) {
			service.mu.Unlock()
			return Operation{}, ErrIDConflict
		}
		operation := service.state.Operations[operationID]
		service.mu.Unlock()
		return operation, nil
	}
	if input.TargetRevision <= 0 {
		service.mu.Unlock()
		return Operation{}, ErrInvalid
	}
	if input.ExpectedRevision != service.state.DraftRevision || input.TargetRevision != service.state.DraftRevision {
		service.mu.Unlock()
		return Operation{}, ErrStale
	}
	for _, existing := range service.state.Operations {
		if existing.Status == "running" {
			service.mu.Unlock()
			return Operation{}, ErrStale
		}
	}
	if service.lifecycle == nil {
		service.mu.Unlock()
		return Operation{}, ErrUnsupported
	}
	operationID, err := randomID()
	if err != nil {
		service.mu.Unlock()
		return Operation{}, err
	}
	now := service.now().UTC().Format(time.RFC3339Nano)
	operation := Operation{OperationID: operationID, CommandID: input.CommandID, TargetRevision: input.TargetRevision, PreviousRevision: service.state.AppliedRevision, Status: "running", Phase: "preflight", CreatedAt: now, UpdatedAt: now}
	service.state.Operations[operationID] = operation
	service.state.Commands[input.CommandID] = operationID
	service.state.CommandPayloads[input.CommandID] = payload
	if err := service.persistLocked(); err != nil {
		if errors.Is(err, ErrIndeterminate) {
			if reloadErr := service.reloadLocked(); reloadErr != nil {
				service.mu.Unlock()
				return Operation{}, fmt.Errorf("reload indeterminate apply receipt: %w", reloadErr)
			}
		} else {
			delete(service.state.Operations, operationID)
			delete(service.state.Commands, input.CommandID)
			delete(service.state.CommandPayloads, input.CommandID)
		}
		service.mu.Unlock()
		return Operation{}, err
	}
	draft := service.state.Draft
	service.mu.Unlock()
	go service.runApply(operationID, input.TargetRevision, draft)
	return operation, nil
}

func (service *Service) runApply(operationID string, revision int64, draft persistedSettings) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	service.mu.Lock()
	previous := service.state.Applied
	previousRevision := service.state.AppliedRevision
	service.mu.Unlock()
	var applyErr error
	if preflight, ok := service.provider.(interface {
		PreflightSettings(context.Context, Settings, []MCPConfig) error
	}); ok {
		applyErr = preflight.PreflightSettings(ctx, publicSettings(draft), providerMCPs(draft))
	}
	if applyErr == nil {
		applyErr = service.phase(operationID, "waiting")
	}
	if applyErr == nil {
		var release func()
		release, applyErr = service.lifecycle.BeginSettingsChange(ctx)
		if applyErr == nil {
			defer release()
			applyErr = service.phase(operationID, "stopping")
			if applyErr == nil {
				applyErr = service.provider.ApplySettings(ctx, publicSettings(draft), providerMCPs(draft))
			}
		}
	}
	if applyErr == nil {
		service.mu.Lock()
		operation := service.state.Operations[operationID]
		operation.Status, operation.Phase = "succeeded", "verified"
		operation.UpdatedAt = service.now().UTC().Format(time.RFC3339Nano)
		service.state.Operations[operationID] = operation
		service.state.Applied = draft
		service.state.AppliedRevision = revision
		persistErr := service.persistLocked()
		if persistErr == nil {
			service.mu.Unlock()
			service.markReady(true)
			return
		}
		service.state.Applied = previous
		service.state.AppliedRevision = previousRevision
		service.mu.Unlock()
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 30*time.Second)
		rollbackErr := service.provider.ApplySettings(rollbackCtx, publicSettings(previous), providerMCPs(previous))
		rollbackCancel()
		if rollbackErr != nil {
			applyErr = ErrRollbackFailed
		} else {
			applyErr = persistErr
		}
	}
	service.mu.Lock()
	operation := service.state.Operations[operationID]
	operation.UpdatedAt = service.now().UTC().Format(time.RFC3339Nano)
	operation.Status = "failed"
	if errors.Is(applyErr, ErrRollbackFailed) {
		operation.ReasonCode = "rollback_failed"
	} else if errors.Is(applyErr, ErrUnsupported) {
		operation.ReasonCode = "parameter_unsupported"
	} else if errors.Is(applyErr, context.DeadlineExceeded) {
		operation.ReasonCode = "active_attempt_timeout"
	} else if errors.Is(applyErr, ErrIndeterminate) {
		operation.ReasonCode = "persistence_indeterminate"
	} else {
		operation.ReasonCode = "provider_unavailable"
	}
	service.state.Operations[operationID] = operation
	persistErr := service.persistLocked()
	service.mu.Unlock()
	if errors.Is(applyErr, ErrRollbackFailed) || persistErr != nil {
		service.markReady(false)
	}
}

func (service *Service) phase(operationID, phase string) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	operation := service.state.Operations[operationID]
	operation.Phase = phase
	operation.UpdatedAt = service.now().UTC().Format(time.RFC3339Nano)
	service.state.Operations[operationID] = operation
	return service.persistLocked()
}

func (service *Service) Operation(operationID string) (Operation, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	operation, ok := service.state.Operations[operationID]
	if !ok {
		return Operation{}, ErrNotFound
	}
	return operation, nil
}

func (service *Service) Models(ctx context.Context, cursor string, limit int) (ModelPage, error) {
	if limit < 1 || limit > 100 || len(cursor) > 512 {
		return ModelPage{}, ErrInvalid
	}
	page, err := service.provider.ListModels(ctx, cursor, limit)
	if err != nil {
		return ModelPage{}, err
	}
	page.SchemaID = "harness-model-catalog-v1"
	page.NodeID = service.state.NodeID
	page.CatalogRevision = page.ProcessGeneration
	page.FetchedAt = service.now().UTC().Format(time.RFC3339Nano)
	page.State = "stale"
	if page.Fresh {
		page.State = "fresh"
	}
	for index := range page.Models {
		model := &page.Models[index]
		model.DisplayName = model.Model
		if model.DisplayName == "" {
			model.DisplayName = model.ID
		}
		model.ReasoningEfforts = modes(model.SupportedReasoningEfforts, model.DefaultReasoningEffort)
		model.SpeedModes = modes(model.ServiceTiers, model.DefaultServiceTier)
	}
	return page, nil
}

func (service *Service) CheckMCP(ctx context.Context, expectedRevision int64, mcpID string) (MCPCheck, error) {
	service.mu.Lock()
	if expectedRevision != service.state.DraftRevision {
		service.mu.Unlock()
		return MCPCheck{}, ErrStale
	}
	var target *persistedMCP
	for index := range service.state.Draft.MCPServers {
		if service.state.Draft.MCPServers[index].ID == mcpID {
			copy := service.state.Draft.MCPServers[index]
			target = &copy
			break
		}
	}
	service.mu.Unlock()
	if target == nil {
		return MCPCheck{}, ErrNotFound
	}
	result, err := service.provider.CheckMCP(ctx, providerMCP(*target))
	if err != nil {
		return MCPCheck{}, err
	}
	result.SchemaID = Contract
	result.NodeID = service.state.NodeID
	result.CheckedAt = service.now().UTC().Format(time.RFC3339Nano)
	result.State = result.Status
	result.ReasonCode = result.ErrorCode
	return result, nil
}

func modes(values []string, defaultValue *string) []Mode {
	result := make([]Mode, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, Mode{ID: value, IsDefault: defaultValue != nil && *defaultValue == value})
	}
	return result
}

func mergeSettings(current persistedSettings, input SettingsInput) (persistedSettings, error) {
	if len(input.Draft.MCPServers) > 64 || !optionalIdentifier(input.Draft.Inference.ModelID) || !optionalIdentifier(input.Draft.Inference.SpeedMode) || !optionalIdentifier(input.Draft.Inference.ReasoningEffort) {
		return persistedSettings{}, ErrInvalid
	}
	prior := make(map[string]persistedMCP, len(current.MCPServers))
	for _, server := range current.MCPServers {
		prior[server.ID] = server
	}
	next := persistedSettings{Inference: Inference{ModelID: cloneString(input.Draft.Inference.ModelID), SpeedMode: cloneString(input.Draft.Inference.SpeedMode), ReasoningEffort: cloneString(input.Draft.Inference.ReasoningEffort)}}
	seen := map[string]bool{}
	for _, candidate := range input.Draft.MCPServers {
		parsed, parseErr := url.Parse(candidate.URL)
		if !identifier.MatchString(candidate.ID) || !validText(candidate.Name, 200) || parseErr != nil || parsed == nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || seen[candidate.ID] || candidate.Transport != "streamable_http" || candidate.TimeoutMS < 100 || candidate.TimeoutMS > 30000 || (candidate.Auth.Kind != "none" && candidate.Auth.Kind != "bearer") {
			return persistedSettings{}, ErrInvalid
		}
		seen[candidate.ID] = true
		server := persistedMCP{ID: candidate.ID, Name: candidate.Name, Enabled: candidate.Enabled, URL: candidate.URL, Transport: candidate.Transport, TimeoutMS: candidate.TimeoutMS, AuthKind: candidate.Auth.Kind}
		old := prior[candidate.ID].BearerToken
		switch candidate.Auth.SecretAction {
		case "keep":
			if candidate.Auth.Kind != "bearer" || candidate.Auth.Secret != nil || old == nil {
				return persistedSettings{}, ErrInvalid
			}
			server.BearerToken = old
		case "replace":
			if candidate.Auth.Kind != "bearer" || candidate.Auth.Secret == nil || !validText(*candidate.Auth.Secret, 8192) {
				return persistedSettings{}, ErrInvalid
			}
			version := int64(1)
			if old != nil {
				version = old.Version + 1
			}
			server.BearerToken = &persistedSecret{Value: *candidate.Auth.Secret, Version: version}
		case "remove":
			if candidate.Auth.Secret != nil {
				return persistedSettings{}, ErrInvalid
			}
		case "":
			if candidate.Auth.Kind != "none" || candidate.Auth.Secret != nil {
				return persistedSettings{}, ErrInvalid
			}
		default:
			return persistedSettings{}, ErrInvalid
		}
		next.MCPServers = append(next.MCPServers, server)
	}
	return next, nil
}

func (service *Service) snapshotLocked() Snapshot {
	result := Snapshot{SchemaID: Contract, NodeID: service.state.NodeID, DraftRevision: service.state.DraftRevision, AppliedRevision: service.state.AppliedRevision, Draft: publicSettings(service.state.Draft), Capabilities: map[string]string{"provider": "codex", "modelCatalog": "runtime", "modelDefault": "supported", "mcpCheck": "runtime", "mcpTimeout": "supported", "nativeRestart": "managed"}}
	if service.state.AppliedRevision > 0 {
		applied := publicSettings(service.state.Applied)
		result.Applied = &applied
	}
	for _, operation := range service.state.Operations {
		if result.Operation == nil || operation.UpdatedAt > result.Operation.UpdatedAt {
			copy := operation
			result.Operation = &copy
		}
	}
	return result
}

func publicSettings(settings persistedSettings) Settings {
	result := Settings{Inference: Inference{ModelID: cloneString(settings.Inference.ModelID), SpeedMode: cloneString(settings.Inference.SpeedMode), ReasoningEffort: cloneString(settings.Inference.ReasoningEffort)}}
	for _, server := range settings.MCPServers {
		result.MCPServers = append(result.MCPServers, publicMCP(server))
	}
	if result.MCPServers == nil {
		result.MCPServers = []MCPServer{}
	}
	return result
}

func publicMCP(server persistedMCP) MCPServer {
	result := MCPServer{ID: server.ID, Name: server.Name, Enabled: server.Enabled, URL: server.URL, Transport: server.Transport, TimeoutMS: server.TimeoutMS, Auth: MCPAuth{Kind: server.AuthKind, BearerTokenConfigured: server.BearerToken != nil}}
	return result
}

func providerMCP(server persistedMCP) MCPConfig {
	result := MCPConfig{MCPServer: publicMCP(server)}
	if server.AuthKind == "bearer" && server.BearerToken != nil {
		result.BearerToken = server.BearerToken.Value
	}
	return result
}

func providerMCPs(settings persistedSettings) []MCPConfig {
	result := make([]MCPConfig, 0, len(settings.MCPServers))
	for _, server := range settings.MCPServers {
		result = append(result, providerMCP(server))
	}
	return result
}

func (service *Service) persistLocked() error {
	raw, err := json.Marshal(service.state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(service.path), ".node-settings-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
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
	if err := os.Rename(name, service.path); err != nil {
		return err
	}
	if err := service.syncDirectory(filepath.Dir(service.path)); err != nil {
		return fmt.Errorf("%w: %v", ErrIndeterminate, err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (service *Service) reloadLocked() error {
	raw, err := os.ReadFile(service.path)
	if err != nil {
		return err
	}
	var state persistedState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(new(any)) != io.EOF || state.Contract != Contract || state.NodeID != service.state.NodeID {
		return errors.New("reloaded node settings state is invalid")
	}
	service.state = state
	return nil
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	value := hex.EncodeToString(raw[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", value[:8], value[8:12], value[12:16], value[16:20], value[20:]), nil
}

func optionalIdentifier(value *string) bool { return value == nil || identifier.MatchString(*value) }
func validText(value string, max int) bool {
	return value != "" && utf8.ValidString(value) && len([]byte(value)) <= max && !strings.ContainsRune(value, 0)
}
func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
