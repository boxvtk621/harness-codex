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
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var environmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

type ValidationError struct {
	Path string
	Code string
}

func (e *ValidationError) Error() string { return "invalid node settings at " + e.Path }
func (e *ValidationError) Unwrap() error { return ErrInvalid }
func invalid(path string) error          { return &ValidationError{Path: path, Code: "invalid"} }

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
	if err := os.Mkdir(dataDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create node settings data directory: %w", err)
	}
	info, err := os.Lstat(dataDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("node settings data directory is unsafe")
	}
	if info.Mode().Perm()&0o077 != 0 {
		entries, readErr := os.ReadDir(dataDir)
		if readErr != nil || len(entries) != 0 || os.Chmod(dataDir, 0o700) != nil {
			return nil, errors.New("node settings data directory is unsafe")
		}
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
	if err := decoder.Decode(&service.state); err != nil || decoder.Decode(new(any)) != io.EOF || (service.state.Contract != Contract && service.state.Contract != "harness-node-settings-v1") || service.state.NodeID != nodeID || service.state.DraftRevision < service.state.AppliedRevision {
		return nil, errors.New("node settings state is invalid")
	}
	if service.state.Contract != Contract {
		service.state.Contract = Contract
		if err := service.persistLocked(); err != nil {
			return nil, fmt.Errorf("migrate node settings: %w", err)
		}
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
	page.SchemaID = "harness-model-catalog-v2"
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
		model.SpeedModes = []Mode{{ID: "off", IsDefault: true}}
		if containsCatalogValue(model.ServiceTiers, "priority") || containsCatalogValue(model.AdditionalSpeedTiers, "priority") {
			model.SpeedModes = append(model.SpeedModes, Mode{ID: "on"})
		}
		model.Compatibility = "unknown"
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

// ValidateMCPDocument checks an unsaved document against the current draft.
// It makes no network calls and leaves revisions and secrets unchanged.
func (service *Service) ValidateMCPDocument(document MCPDocumentInput) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	_, err := mergeSettings(service.state.Draft, SettingsInput{Draft: DraftInput{Inference: service.state.Draft.Inference, MCPDocument: &document}})
	return err
}

func containsCatalogValue(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func mergeSettings(current persistedSettings, input SettingsInput) (persistedSettings, error) {
	servers := input.Draft.MCPServers
	if input.Draft.MCPDocument != nil {
		if input.Draft.MCPServers != nil || input.Draft.MCPDocument.SchemaID != MCPDocumentSchema {
			return persistedSettings{}, invalid("/draft/mcpDocument/schemaId")
		}
		if input.Draft.MCPDocument.Servers == nil {
			return persistedSettings{}, invalid("/draft/mcpDocument/servers")
		}
		servers = input.Draft.MCPDocument.Servers
	}
	if len(servers) > 64 {
		return persistedSettings{}, invalid("/draft/mcpDocument/servers")
	}
	if !optionalIdentifier(input.Draft.Inference.ModelID) {
		return persistedSettings{}, invalid("/draft/inference/modelId")
	}
	if input.Draft.Inference.SpeedMode != nil && *input.Draft.Inference.SpeedMode != "off" && *input.Draft.Inference.SpeedMode != "on" {
		return persistedSettings{}, invalid("/draft/inference/speedMode")
	}
	if !optionalIdentifier(input.Draft.Inference.ReasoningEffort) {
		return persistedSettings{}, invalid("/draft/inference/reasoningEffort")
	}
	prior := make(map[string]persistedMCP, len(current.MCPServers))
	for _, server := range current.MCPServers {
		prior[server.ID] = server
	}
	next := persistedSettings{Inference: Inference{ModelID: cloneString(input.Draft.Inference.ModelID), SpeedMode: cloneString(input.Draft.Inference.SpeedMode), ReasoningEffort: cloneString(input.Draft.Inference.ReasoningEffort)}}
	seen := map[string]bool{}
	for index, candidate := range servers {
		base := fmt.Sprintf("/draft/mcpDocument/servers/%d", index)
		if candidate.ForbiddenPath != "" {
			return persistedSettings{}, invalid(base + "/" + candidate.ForbiddenPath)
		}
		if !identifier.MatchString(candidate.ID) || seen[candidate.ID] {
			return persistedSettings{}, invalid(base + "/id")
		}
		if !validText(candidate.Name, 200) {
			return persistedSettings{}, invalid(base + "/name")
		}
		if candidate.TimeoutMS < 100 || candidate.TimeoutMS > 30000 {
			return persistedSettings{}, invalid(base + "/timeoutMs")
		}
		seen[candidate.ID] = true
		server := persistedMCP{ID: candidate.ID, Name: candidate.Name, Enabled: candidate.Enabled, Transport: candidate.Transport, TimeoutMS: candidate.TimeoutMS}
		switch candidate.Transport {
		case "streamable_http":
			parsed, parseErr := url.Parse(candidate.URL)
			if parseErr != nil || parsed == nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
				return persistedSettings{}, invalid(base + "/url")
			}
			if candidate.Command != "" || candidate.Args != nil || candidate.SecretSlots != nil {
				return persistedSettings{}, invalid(base)
			}
			if candidate.Auth.Kind != "none" && candidate.Auth.Kind != "bearer" {
				return persistedSettings{}, invalid(base + "/auth/kind")
			}
			server.URL, server.AuthKind = candidate.URL, candidate.Auth.Kind
		case "stdio":
			if candidate.URL != "" || candidate.Auth.Kind != "" || candidate.Auth.SecretAction != "" || candidate.Auth.Secret != nil {
				return persistedSettings{}, invalid(base)
			}
			if !validText(candidate.Command, 1024) || len(candidate.Args) > 64 || len(candidate.SecretSlots) > 64 {
				return persistedSettings{}, invalid(base + "/command")
			}
			server.Command = candidate.Command
			server.Args = append([]string(nil), candidate.Args...)
			for _, arg := range server.Args {
				if !utf8.ValidString(arg) || len(arg) > 4096 || strings.ContainsRune(arg, 0) {
					return persistedSettings{}, invalid(base + "/args")
				}
			}
			server.SecretSlots = make(map[string]persistedSecret)
			seenSlots := map[string]bool{}
			for slotIndex, slot := range candidate.SecretSlots {
				path := fmt.Sprintf("%s/secretSlots/%d", base, slotIndex)
				if !environmentName.MatchString(slot.Slot) {
					return persistedSettings{}, invalid(path + "/slot")
				}
				if seenSlots[slot.Slot] {
					return persistedSettings{}, invalid(path + "/slot")
				}
				seenSlots[slot.Slot] = true
				old, exists := prior[candidate.ID].SecretSlots[slot.Slot]
				switch slot.Action {
				case "keep":
					if !exists || slot.Secret != nil {
						return persistedSettings{}, invalid(path + "/action")
					}
					server.SecretSlots[slot.Slot] = old
				case "replace":
					if slot.Secret == nil || !validText(*slot.Secret, 8192) {
						return persistedSettings{}, invalid(path + "/secret")
					}
					version := int64(1)
					if exists {
						version = old.Version + 1
					}
					server.SecretSlots[slot.Slot] = persistedSecret{Value: *slot.Secret, Version: version}
				case "remove":
					if slot.Secret != nil {
						return persistedSettings{}, invalid(path + "/secret")
					}
				default:
					return persistedSettings{}, invalid(path + "/action")
				}
			}
			for priorSlot := range prior[candidate.ID].SecretSlots {
				if !seenSlots[priorSlot] {
					return persistedSettings{}, invalid(base + "/secretSlots")
				}
			}
			next.MCPServers = append(next.MCPServers, server)
			continue
		default:
			return persistedSettings{}, invalid(base + "/transport")
		}
		old := prior[candidate.ID].BearerToken
		switch candidate.Auth.SecretAction {
		case "keep":
			if candidate.Auth.Kind != "bearer" || candidate.Auth.Secret != nil || old == nil {
				return persistedSettings{}, invalid(base + "/auth/secretAction")
			}
			server.BearerToken = old
		case "replace":
			if candidate.Auth.Kind != "bearer" || candidate.Auth.Secret == nil || !validText(*candidate.Auth.Secret, 8192) {
				return persistedSettings{}, invalid(base + "/auth/secret")
			}
			version := int64(1)
			if old != nil {
				version = old.Version + 1
			}
			server.BearerToken = &persistedSecret{Value: *candidate.Auth.Secret, Version: version}
		case "remove":
			if candidate.Auth.Secret != nil {
				return persistedSettings{}, invalid(base + "/auth/secret")
			}
		case "":
			if candidate.Auth.Kind != "none" || candidate.Auth.Secret != nil {
				return persistedSettings{}, invalid(base + "/auth/secretAction")
			}
		default:
			return persistedSettings{}, invalid(base + "/auth/secretAction")
		}
		next.MCPServers = append(next.MCPServers, server)
	}
	return next, nil
}

func (service *Service) snapshotLocked() Snapshot {
	result := Snapshot{SchemaID: Contract, MCPSchema: MCPDocumentSchema, NodeID: service.state.NodeID, DraftRevision: service.state.DraftRevision, AppliedRevision: service.state.AppliedRevision, Draft: publicSettings(service.state.Draft), Capabilities: map[string]string{"provider": "codex", "modelCatalog": "runtime", "modelDefault": "supported", "reasoningDefault": "supported", "speedDefault": "supported", "mcpCheck": "runtime", "mcpTimeout": "supported", "nativeRestart": "managed", "mcpTransports": "streamable_http,stdio", "speedModes": "off,on"}}
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
	result := Settings{Inference: Inference{ModelID: cloneString(settings.Inference.ModelID), SpeedMode: cloneString(settings.Inference.SpeedMode), ReasoningEffort: cloneString(settings.Inference.ReasoningEffort)}, MCPDocument: MCPDocument{SchemaID: MCPDocumentSchema, Servers: []MCPServer{}}}
	for _, server := range settings.MCPServers {
		result.MCPServers = append(result.MCPServers, publicMCP(server))
		result.MCPDocument.Servers = append(result.MCPDocument.Servers, publicMCP(server))
	}
	if result.MCPServers == nil {
		result.MCPServers = []MCPServer{}
	}
	return result
}

func publicMCP(server persistedMCP) MCPServer {
	result := MCPServer{ID: server.ID, Name: server.Name, Enabled: server.Enabled, URL: server.URL, Transport: server.Transport, TimeoutMS: server.TimeoutMS, Command: server.Command, Args: append([]string(nil), server.Args...)}
	if server.Transport == "streamable_http" {
		result.Auth = MCPAuth{Kind: server.AuthKind, BearerTokenConfigured: server.BearerToken != nil}
	}
	for slot := range server.SecretSlots {
		result.SecretSlots = append(result.SecretSlots, SecretSlot{Slot: slot, Configured: true})
	}
	sort.Slice(result.SecretSlots, func(i, j int) bool { return result.SecretSlots[i].Slot < result.SecretSlots[j].Slot })
	return result
}

func providerMCP(server persistedMCP) MCPConfig {
	result := MCPConfig{MCPServer: publicMCP(server)}
	if server.AuthKind == "bearer" && server.BearerToken != nil {
		result.BearerToken = server.BearerToken.Value
	}
	if len(server.SecretSlots) > 0 {
		result.SecretValues = map[string]string{}
		for slot, secret := range server.SecretSlots {
			result.SecretValues[slot] = secret.Value
		}
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
