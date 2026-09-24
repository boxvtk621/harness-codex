// Package codex implements the private Codex app-server adapter for Harness.
package codex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/boxvtk621/harness-codex/internal/diagnosticlog"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/nodesettings"
	"github.com/boxvtk621/harness-codex/internal/toolrunner"
	"github.com/boxvtk621/harness-codex/runtime"
)

const (
	defaultOperationTimeout = 30 * time.Second
	defaultMaximumFrame     = 8 << 20
	defaultEffort           = "medium"
	maximumFeaturePages     = 10
	maximumNativeToolOutput = 64 << 10
	maximumToolCalls        = 64
	maximumToolCallsAttempt = 8
	maximumInteractions     = 64
	maximumInteractionsTurn = 8
)

// codexAppServerVersion is pinned, so this list is an exact deny fence for all
// model-facing native surfaces. Explicit tools use app-server dynamicTools and
// the Harness-owned isolated runner, never native shell/file/MCP execution.
var deniedNativeFeatures = []string{
	"apps",
	"artifact",
	"auth_elicitation",
	"browser_use",
	"browser_use_external",
	"browser_use_full_cdp_access",
	"code_mode",
	"code_mode_host",
	"computer_use",
	"deferred_executor",
	"enable_mcp_apps",
	"exec_permission_approvals",
	"external_agent_memory_import",
	"goals",
	"guardian_approval",
	"hooks",
	"image_generation",
	"in_app_browser",
	"in_app_local_automation",
	"memories",
	"multi_agent",
	"multi_agent_v2",
	"network_proxy",
	"plugins",
	"psp",
	"realtime_conversation",
	"remote_plugin",
	"request_permissions_tool",
	"shell_snapshot",
	"shell_snapshot_v2",
	"shell_tool",
	"skill_mcp_dependency_install",
	"skill_search",
	"sleep_tool",
	"standalone_web_search",
	"tool_call_mcp_elicitation",
	"tool_suggest",
	"view_image",
	"workspace_dependencies",
	"write_stdin_approval",
}

// Config contains only private app-server process settings. Authentication is
// owned by the dedicated CODEX_HOME supplied in Environment; no API token is
// accepted by this adapter.
type Config struct {
	NodeID           string
	Executable       string
	Arguments        []string
	VersionArguments []string
	Environment      []string
	StateDir         string
	WorkingDir       string
	Model            string
	Effort           string
	OperationTimeout time.Duration
	MaxFrameBytes    int
	Runner           toolrunner.Runner
	Logger           diagnosticlog.Sink
}

type nativeAttempt struct {
	mu          sync.Mutex
	toolCtx     context.Context
	cancelTools context.CancelFunc
	runtime     *attemptRuntime
	reference   harnessadapter.AttemptRef
	threadID    string
	turnID      string
	tools       map[string]nativeTool
	output      *harnessprotocol.SafeContent
	usage       *harnessprotocol.Usage
	policy      string
	policyHash  string
	workspace   string
	toolCalls   int
	// Sticky evidence: a later request rejection cannot erase earlier execution
	// or an ambiguous retry in this turn.
	executionObserved   bool
	retryObserved       bool
	turnStartedObserved bool
}

type nativeTool struct {
	itemID           string
	requestID        rpcID
	callID           string
	toolName         string
	actionHash       string
	canonicalArgs    []byte
	request          toolrunner.Request
	input            harnessprotocol.SafeContent
	safePrompt       string
	expectedResponse *nativeDynamicToolResponse
	effectStatus     string
	outputTruncated  bool
	fullSafeOutput   *string
	fullIncomplete   bool
	requested        bool
	started          bool
	startedByRequest bool
	done             bool
}

type pendingApproval struct {
	id         rpcID
	attempt    *nativeAttempt
	itemID     string
	actionHash string
	result     chan bool
	responding bool
	resolved   bool
}

type pendingInput struct {
	id         rpcID
	attempt    *nativeAttempt
	questionID string
	result     chan bool
	responding bool
	resolved   bool
}

// Adapter owns all native thread, turn, item and request identifiers.
type Adapter struct {
	config          Config
	baseEnvironment []string
	settings        activeSettings // protected by mu; config remains immutable after New
	artifacts       node.ArtifactSink
	store           *mappingStore
	session         *nativeSession

	dispatchMu    sync.Mutex
	mu            sync.Mutex
	attempts      map[string]*nativeAttempt
	byThread      map[string]*nativeAttempt
	byTurn        map[string]*nativeAttempt
	inputs        map[string]*pendingInput
	inputByRPC    map[string]string
	approvals     map[string]*pendingApproval
	approvalByRPC map[string]string
	toolCallSlots chan struct{}
	closed        bool

	authMu          sync.Mutex
	auth            providerAuthState
	authBusy        bool
	authCompletions map[string]accountLoginCompleted
}

type activeSettings struct {
	Model       string
	Effort      string
	Speed       *string
	MCPServers  []nodesettings.MCPConfig
	Environment []string
}

var _ harnessadapter.Adapter = (*Adapter)(nil)
var _ nodesettings.Provider = (*Adapter)(nil)

func New(config Config, artifacts node.ArtifactSink) (*Adapter, error) {
	home, homeOK := exactEnvironmentPath(config.Environment, "HOME")
	codexHome, codexHomeOK := exactEnvironmentPath(config.Environment, "CODEX_HOME")
	if config.Executable == "" || strings.ContainsAny(config.Executable, "\x00\r\n") ||
		config.StateDir == "" || !filepath.IsAbs(config.StateDir) || config.WorkingDir == "" || !filepath.IsAbs(config.WorkingDir) ||
		!boundedText(config.Model) || !validEffort(config.Effort) || invalidEnvironment(config.Environment) ||
		!homeOK || !codexHomeOK || home == codexHome || pathsOverlap(config.WorkingDir, home) ||
		pathsOverlap(config.WorkingDir, codexHome) || pathsOverlap(config.WorkingDir, config.StateDir) {
		return nil, errors.New("codex adapter config is incomplete")
	}
	if len(config.Arguments) == 0 {
		config.Arguments = []string{"app-server", "--listen", "stdio://"}
	}
	if config.OperationTimeout == 0 {
		config.OperationTimeout = defaultOperationTimeout
	}
	if config.OperationTimeout < 0 {
		return nil, errors.New("codex operation timeout is invalid")
	}
	if config.MaxFrameBytes == 0 {
		config.MaxFrameBytes = defaultMaximumFrame
	}
	if config.MaxFrameBytes < 4096 || config.MaxFrameBytes > harnessprotocol.MaximumWireBytes {
		return nil, errors.New("codex app-server frame limit is invalid")
	}
	if config.Logger == nil {
		config.Logger = diagnosticlog.Nop()
	}
	store, err := openMappingStore(config.StateDir)
	if err != nil {
		return nil, err
	}
	adapter := &Adapter{
		config: config, baseEnvironment: append([]string(nil), config.Environment...), settings: activeSettings{Model: config.Model, Effort: config.Effort, Environment: append([]string(nil), config.Environment...)}, artifacts: artifacts, store: store,
		attempts: make(map[string]*nativeAttempt), byThread: make(map[string]*nativeAttempt),
		byTurn: make(map[string]*nativeAttempt), inputs: make(map[string]*pendingInput), inputByRPC: make(map[string]string),
		approvals: make(map[string]*pendingApproval), approvalByRPC: make(map[string]string),
		toolCallSlots:   make(chan struct{}, maximumToolCalls),
		authCompletions: make(map[string]accountLoginCompleted),
	}
	ctx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	defer cancel()
	session, err := startNativeSession(ctx, bridgeConfig{
		Executable: config.Executable, Arguments: append([]string(nil), config.Arguments...),
		VersionArguments: append([]string(nil), config.VersionArguments...), Environment: append([]string(nil), config.Environment...),
		WorkingDir: config.WorkingDir, MaxFrameBytes: config.MaxFrameBytes,
	}, store, sessionHandlers{
		Notification: adapter.handleNotification, Request: adapter.handleRequest, Exit: adapter.handleExit,
		Ready: func(session *nativeSession) { adapter.mu.Lock(); adapter.session = session; adapter.mu.Unlock() },
	})
	if err != nil {
		return nil, err
	}
	adapter.mu.Lock()
	adapter.session = session
	adapter.mu.Unlock()
	adapter.config.Logger.Emit(diagnosticlog.LevelInfo, diagnosticlog.EventProviderReady, diagnosticlog.Fields{
		NodeID: config.NodeID, ProcessGeneration: session.ProcessGeneration(),
	})
	if err := adapter.initializeProviderAuth(ctx); err != nil {
		_ = session.Close()
		_ = session.Wait()
		return nil, err
	}
	return adapter, nil
}

func (adapter *Adapter) Identity(context.Context) (harnessadapter.Identity, error) {
	declared := make(map[harnessadapter.Capability]bool)
	verified := make(map[harnessadapter.Capability]bool)
	for _, capability := range []harnessadapter.Capability{
		harnessadapter.CapabilityChat, harnessadapter.CapabilityEvents,
		harnessadapter.CapabilityToolResults, harnessadapter.CapabilityCancel,
		harnessadapter.CapabilitySteerAttached, harnessadapter.CapabilitySessionResume,
		harnessadapter.CapabilityPolicyEnforcement,
	} {
		declared[capability] = true
		verified[capability] = true
	}
	return harnessadapter.Identity{
		Kind: harnessadapter.KindCodex, Version: harnessadapter.CodexAppServerVersion,
		ProtocolVersion: harnessprotocol.ProtocolVersion, SchemaID: harnessprotocol.SchemaID,
		SchemaSHA256: harnessprotocol.SchemaSHA256, Declared: declared, Verified: verified,
	}, nil
}

type nativeReasoningEffort struct {
	ReasoningEffort string `json:"reasoningEffort"`
}
type nativeServiceTier struct {
	ID string `json:"id"`
}
type nativeModel struct {
	ID                        string                  `json:"id"`
	IsDefault                 bool                    `json:"isDefault"`
	Model                     string                  `json:"model"`
	SupportedReasoningEfforts []nativeReasoningEffort `json:"supportedReasoningEfforts"`
	DefaultReasoningEffort    *string                 `json:"defaultReasoningEffort"`
	ServiceTiers              []nativeServiceTier     `json:"serviceTiers"`
	DefaultServiceTier        *string                 `json:"defaultServiceTier"`
	AdditionalSpeedTiers      []string                `json:"additionalSpeedTiers"`
}

func (adapter *Adapter) ListModels(ctx context.Context, cursor string, limit int) (nodesettings.ModelPage, error) {
	if limit < 1 || limit > 100 || len(cursor) > 512 {
		return nodesettings.ModelPage{}, nodesettings.ErrInvalid
	}
	adapter.mu.Lock()
	closed, session := adapter.closed, adapter.session
	adapter.mu.Unlock()
	if closed || session == nil {
		return nodesettings.ModelPage{}, errors.New("codex app-server is unavailable")
	}
	params := map[string]any{"limit": limit, "includeHidden": true}
	if cursor != "" {
		params["cursor"] = cursor
	}
	var response struct {
		Data       []nativeModel `json:"data"`
		NextCursor *string       `json:"nextCursor"`
	}
	operationCtx, cancel := adapter.operationContext(ctx)
	defer cancel()
	if err := session.Call(operationCtx, "model/list", params, &response); err != nil {
		return nodesettings.ModelPage{}, fmt.Errorf("list codex models: %w", err)
	}
	if response.Data == nil || response.NextCursor != nil && (!boundedSessionText(*response.NextCursor, 512) || *response.NextCursor == cursor) {
		return nodesettings.ModelPage{}, errors.New("codex model catalog response is invalid")
	}
	page := nodesettings.ModelPage{Models: make([]nodesettings.Model, 0, len(response.Data)), NextCursor: response.NextCursor, ProcessGeneration: session.ProcessGeneration(), Fresh: true}
	seen := map[string]bool{}
	for _, native := range response.Data {
		if !boundedSessionText(native.ID, 256) || !boundedSessionText(native.Model, 256) || seen[native.ID] {
			return nodesettings.ModelPage{}, errors.New("codex model catalog item is invalid")
		}
		seen[native.ID] = true
		model := nodesettings.Model{ID: native.ID, Model: native.Model, IsDefault: native.IsDefault, DefaultReasoningEffort: native.DefaultReasoningEffort, DefaultServiceTier: native.DefaultServiceTier, AdditionalSpeedTiers: append([]string(nil), native.AdditionalSpeedTiers...)}
		for _, effort := range native.SupportedReasoningEfforts {
			model.SupportedReasoningEfforts = append(model.SupportedReasoningEfforts, effort.ReasoningEffort)
		}
		for _, tier := range native.ServiceTiers {
			model.ServiceTiers = append(model.ServiceTiers, tier.ID)
		}
		if !validCatalogModel(model) {
			return nodesettings.ModelPage{}, errors.New("codex model capability item is invalid")
		}
		page.Models = append(page.Models, model)
	}
	return page, nil
}

func (adapter *Adapter) CheckMCP(ctx context.Context, server nodesettings.MCPConfig) (nodesettings.MCPCheck, error) {
	adapter.mu.Lock()
	closed, session := adapter.closed, adapter.session
	currentSettings := adapter.settings
	configured := false
	for _, current := range currentSettings.MCPServers {
		if current.ID == server.ID && current.Enabled == server.Enabled && current.URL == server.URL && current.Transport == server.Transport && current.Command == server.Command && current.TimeoutMS == server.TimeoutMS && current.Auth.Kind == server.Auth.Kind && current.BearerToken == server.BearerToken && reflect.DeepEqual(current.Args, server.Args) && reflect.DeepEqual(current.SecretValues, server.SecretValues) {
			configured = true
			break
		}
	}
	adapter.mu.Unlock()
	if closed || session == nil {
		return nodesettings.MCPCheck{}, errors.New("codex app-server is unavailable")
	}
	result := nodesettings.MCPCheck{MCPID: server.ID, Status: "unavailable", ErrorCode: "draft_requires_apply", ProcessGeneration: session.ProcessGeneration()}
	if !configured {
		return result, nil
	}
	if !server.Enabled {
		result.ErrorCode = "mcp_disabled"
		return result, nil
	}
	operationCtx, cancel := adapter.operationContext(ctx)
	defer cancel()
	options := adapter.threadOptionsWithSettings(harnessadapter.PolicySnapshot{Content: []byte("managed node settings verification")}, adapter.config.WorkingDir, false, currentSettings)
	var started nativeThreadResponse
	if err := session.Call(operationCtx, "thread/start", options, &started); err != nil || !boundedNativeID(started.Thread.ID) {
		result.ErrorCode = "mcp_runtime_unavailable"
		return result, nil
	}
	var response struct {
		Data []struct {
			Name          string                     `json:"name"`
			RuntimeStatus *string                    `json:"runtimeStatus"`
			Tools         map[string]json.RawMessage `json:"tools"`
			ToolsError    *string                    `json:"toolsError"`
		} `json:"data"`
	}
	if err := session.Call(operationCtx, "mcpServerStatus/list", map[string]any{"threadId": started.Thread.ID, "limit": 100, "detail": "toolsAndAuthOnly"}, &response); err != nil {
		result.ErrorCode = "mcp_status_unavailable"
		return result, nil
	}
	for _, entry := range response.Data {
		if entry.Name != server.ID {
			continue
		}
		if entry.RuntimeStatus != nil && *entry.RuntimeStatus == "connected" && entry.Tools != nil && entry.ToolsError == nil {
			result.Status, result.ErrorCode = "available", ""
		} else if entry.RuntimeStatus != nil && *entry.RuntimeStatus == "authenticationRequired" {
			result.ErrorCode = "mcp_auth_required"
		} else if entry.RuntimeStatus != nil && *entry.RuntimeStatus == "failed" {
			result.ErrorCode = "mcp_connection_failed"
		} else {
			result.ErrorCode = "mcp_tools_unverified"
		}
		return result, nil
	}
	result.ErrorCode = "mcp_inventory_missing"
	return result, nil
}

func (adapter *Adapter) PreflightSettings(ctx context.Context, settings nodesettings.Settings, servers []nodesettings.MCPConfig) error {
	_ = servers
	var modelID string
	if settings.Inference.ModelID != nil {
		modelID = *settings.Inference.ModelID
	}
	model, err := adapter.resolveModel(ctx, modelID)
	if err != nil {
		return err
	}
	if settings.Inference.ReasoningEffort != nil && !containsValue(model.SupportedReasoningEfforts, *settings.Inference.ReasoningEffort) {
		return nodesettings.ErrUnsupported
	}
	if settings.Inference.ReasoningEffort == nil && (model.DefaultReasoningEffort == nil || !containsValue(model.SupportedReasoningEfforts, *model.DefaultReasoningEffort)) {
		return nodesettings.ErrUnsupported
	}
	if settings.Inference.SpeedMode != nil && *settings.Inference.SpeedMode == "on" && !containsValue(model.ServiceTiers, "priority") && !containsValue(model.AdditionalSpeedTiers, "priority") {
		return nodesettings.ErrUnsupported
	}
	if settings.Inference.SpeedMode != nil && *settings.Inference.SpeedMode != "off" && *settings.Inference.SpeedMode != "on" {
		return nodesettings.ErrUnsupported
	}
	return nil
}

func (adapter *Adapter) resolveModel(ctx context.Context, modelID string) (nodesettings.Model, error) {
	var cursor string
	seen := map[string]bool{}
	for pageNo := 0; pageNo < maximumFeaturePages; pageNo++ {
		page, err := adapter.ListModels(ctx, cursor, 100)
		if err != nil {
			return nodesettings.Model{}, err
		}
		for _, model := range page.Models {
			if model.ID != modelID && !(modelID == "" && model.IsDefault) {
				continue
			}
			return model, nil
		}
		if page.NextCursor == nil {
			return nodesettings.Model{}, nodesettings.ErrUnsupported
		}
		cursor = *page.NextCursor
		if seen[cursor] {
			return nodesettings.Model{}, errors.New("codex model catalog cursor repeats")
		}
		seen[cursor] = true
	}
	return nodesettings.Model{}, errors.New("codex model catalog exceeds page limit")
}

func containsValue(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (adapter *Adapter) currentSettings() activeSettings {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.settings
}

func (adapter *Adapter) ApplySettings(ctx context.Context, settings nodesettings.Settings, servers []nodesettings.MCPConfig) error {
	adapter.mu.Lock()
	if adapter.closed || adapter.session == nil {
		adapter.mu.Unlock()
		return errors.New("codex app-server is unavailable")
	}
	previous := adapter.settings
	old := adapter.session
	adapter.mu.Unlock()
	candidate := previous
	candidate.Model = ""
	candidate.Effort = ""
	if settings.Inference.ModelID != nil {
		candidate.Model = *settings.Inference.ModelID
	}
	if settings.Inference.ReasoningEffort != nil {
		candidate.Effort = *settings.Inference.ReasoningEffort
	} else {
		model, err := adapter.resolveModel(ctx, candidate.Model)
		if err != nil {
			return err
		}
		if model.DefaultReasoningEffort == nil {
			return nodesettings.ErrUnsupported
		}
		candidate.Effort = *model.DefaultReasoningEffort
	}
	candidate.Speed = settings.Inference.SpeedMode
	candidate.MCPServers = append([]nodesettings.MCPConfig(nil), servers...)
	candidate.Environment = adapter.settingsEnvironment(candidate.MCPServers)
	if err := old.Close(); err != nil {
		return err
	}
	_ = old.Wait() // stop intentionally kills the old child
	adapter.mu.Lock()
	adapter.session = nil
	adapter.settings = candidate
	adapter.mu.Unlock()
	if err := adapter.restartSession(ctx, candidate.Environment); err == nil {
		if err = adapter.verifyAppliedSettings(ctx, candidate); err == nil {
			return nil
		}
		adapter.mu.Lock()
		failed := adapter.session
		adapter.mu.Unlock()
		if failed != nil {
			_ = failed.Close()
			_ = failed.Wait()
		}
	}
	adapter.mu.Lock()
	adapter.session = nil
	adapter.settings = previous
	adapter.mu.Unlock()
	rollbackCtx, cancel := context.WithTimeout(context.Background(), adapter.config.OperationTimeout)
	defer cancel()
	if rollbackErr := adapter.restartSession(rollbackCtx, previous.Environment); rollbackErr != nil {
		return fmt.Errorf("%w: %v", nodesettings.ErrRollbackFailed, rollbackErr)
	}
	return errors.New("codex settings start or verification failed; prior process restored")
}

func (adapter *Adapter) settingsEnvironment(servers []nodesettings.MCPConfig) []string {
	environment := append([]string(nil), adapter.baseEnvironment...)
	for _, server := range servers {
		if server.Enabled && server.Auth.Kind == "bearer" {
			environment = append(environment, mcpTokenVariable(server.ID)+"="+server.BearerToken)
		}
	}
	return environment
}

func mcpTokenVariable(id string) string {
	digest := sha256.Sum256([]byte(id))
	return "HARNESS_CODEX_MCP_TOKEN_" + strings.ToUpper(hex.EncodeToString(digest[:8]))
}

func (adapter *Adapter) restartSession(ctx context.Context, environment []string) error {
	config := adapter.config
	session, err := startNativeSession(ctx, bridgeConfig{
		Executable: config.Executable, Arguments: append([]string(nil), config.Arguments...),
		VersionArguments: append([]string(nil), config.VersionArguments...), Environment: append([]string(nil), environment...),
		WorkingDir: config.WorkingDir, MaxFrameBytes: config.MaxFrameBytes,
	}, adapter.store, sessionHandlers{
		Notification: adapter.handleNotification, Request: adapter.handleRequest, Exit: adapter.handleExit,
		Ready: func(session *nativeSession) { adapter.mu.Lock(); adapter.session = session; adapter.mu.Unlock() },
	})
	if err != nil {
		return err
	}
	adapter.mu.Lock()
	adapter.session = session
	adapter.mu.Unlock()
	return nil
}

func (adapter *Adapter) verifyAppliedSettings(ctx context.Context, config activeSettings) error {
	model := config.Model
	effort := config.Effort
	if err := adapter.PreflightSettings(ctx, nodesettings.Settings{Inference: nodesettings.Inference{ModelID: optionalNativeString(model), ReasoningEffort: optionalNativeString(effort), SpeedMode: config.Speed}}, config.MCPServers); err != nil {
		return err
	}
	adapter.mu.Lock()
	session := adapter.session
	adapter.mu.Unlock()
	if session == nil {
		return errors.New("codex app-server is unavailable")
	}
	options := adapter.threadOptions(harnessadapter.PolicySnapshot{Content: []byte("managed node settings verification")}, adapter.config.WorkingDir, false)
	var response nativeThreadResponse
	if err := session.Call(ctx, "thread/start", options, &response); err != nil {
		return fmt.Errorf("verify codex settings thread: %w", err)
	}
	if !boundedNativeID(response.Thread.ID) {
		return errors.New("codex settings thread response is invalid")
	}
	return adapter.verifyMCPInventory(ctx, response.Thread.ID)
}

func validCatalogModel(model nodesettings.Model) bool {
	unique := func(values []string) bool {
		seen := map[string]bool{}
		for _, value := range values {
			if !boundedSessionText(value, 256) || seen[value] {
				return false
			}
			seen[value] = true
		}
		return true
	}
	if !unique(model.SupportedReasoningEfforts) || !unique(model.ServiceTiers) || !unique(model.AdditionalSpeedTiers) {
		return false
	}
	contains := func(values []string, target string) bool {
		for _, value := range values {
			if value == target {
				return true
			}
		}
		return false
	}
	return (model.DefaultReasoningEffort == nil || contains(model.SupportedReasoningEfforts, *model.DefaultReasoningEffort)) && (model.DefaultServiceTier == nil || contains(model.ServiceTiers, *model.DefaultServiceTier))
}

func (adapter *Adapter) Start(ctx context.Context, input harnessadapter.StartInput) (harnessadapter.StartResult, error) {
	policy, failure := adapter.validateDispatch(input.Attempt, input.Prompt, input.Context, input.Policy)
	if failure != nil {
		return harnessadapter.StartResult{Outcome: harnessadapter.StartRejected, Failure: failure}, nil
	}
	if _, attempted := adapter.store.attempt(input.Attempt); attempted {
		failure, err := adapter.dispatch(ctx, "start", input.Attempt, input.Prompt, input.Context, policy, "")
		if err != nil || failure != nil {
			if failure == nil {
				failure = nodeFailure("codex_dispatch_unknown", "codex dispatch acknowledgement is unknown", true)
			}
			return harnessadapter.StartResult{Outcome: harnessadapter.StartUnknown, Failure: failure}, err
		}
		return harnessadapter.StartResult{Outcome: harnessadapter.StartStarted}, nil
	}
	if _, exists := adapter.store.dialog(input.Attempt.DialogID); exists {
		return harnessadapter.StartResult{Outcome: harnessadapter.StartRejected, Failure: taskFailure("codex_dialog_exists", "codex dialog already has native context")}, nil
	}
	failure, err := adapter.dispatch(ctx, "start", input.Attempt, input.Prompt, input.Context, policy, "")
	if err != nil || failure != nil {
		if failure == nil {
			failure = nodeFailure("codex_dispatch_unknown", "codex dispatch acknowledgement is unknown", true)
		}
		return harnessadapter.StartResult{Outcome: harnessadapter.StartUnknown, Failure: failure}, err
	}
	return harnessadapter.StartResult{Outcome: harnessadapter.StartStarted}, nil
}

func (adapter *Adapter) Resume(ctx context.Context, input harnessadapter.ResumeInput) (harnessadapter.ResumeResult, error) {
	policy, failure := adapter.validateDispatch(input.Attempt, input.Prompt, input.Context, input.Policy)
	if failure != nil {
		return harnessadapter.ResumeResult{Outcome: harnessadapter.ResumeRejected, Failure: failure}, nil
	}
	if _, attempted := adapter.store.attempt(input.Attempt); attempted {
		failure, err := adapter.dispatch(ctx, "resume", input.Attempt, input.Prompt, input.Context, policy, "")
		if err != nil || failure != nil {
			if failure == nil {
				failure = nodeFailure("codex_dispatch_unknown", "codex dispatch acknowledgement is unknown", true)
			}
			return harnessadapter.ResumeResult{Outcome: harnessadapter.ResumeUnknown, Failure: failure}, err
		}
		return harnessadapter.ResumeResult{Outcome: harnessadapter.ResumeStarted}, nil
	}
	dialog, exists := adapter.store.dialog(input.Attempt.DialogID)
	exactRetryBoundary := input.Context == dialog.Boundary
	failedTail := adapter.store.validFailedTail(input.Attempt, input.Context, policy.EffectiveHash, digestString(input.Prompt), input.FailedTailRetry)
	if !exists || !boundedNativeID(dialog.ThreadID) || (input.Context.Sequence < dialog.Boundary.Sequence && !failedTail) ||
		(input.Context.Sequence == dialog.Boundary.Sequence && !exactRetryBoundary) {
		return harnessadapter.ResumeResult{Outcome: harnessadapter.ResumeContextMissing, Failure: taskFailure("codex_context_missing", "codex dialog context is unavailable")}, nil
	}
	if dialog.PolicyHash != policy.EffectiveHash {
		return harnessadapter.ResumeResult{Outcome: harnessadapter.ResumeRejected, Failure: policyFailure("codex_resume_policy_changed", "codex dialog policy changed; start a new dialog")}, nil
	}
	failure, err := adapter.dispatch(ctx, "resume", input.Attempt, input.Prompt, input.Context, policy, dialog.ThreadID, input.FailedTailRetry)
	if err != nil || failure != nil {
		if failure == nil {
			failure = nodeFailure("codex_dispatch_unknown", "codex dispatch acknowledgement is unknown", true)
		}
		return harnessadapter.ResumeResult{Outcome: harnessadapter.ResumeUnknown, Failure: failure}, err
	}
	return harnessadapter.ResumeResult{Outcome: harnessadapter.ResumeStarted}, nil
}

func (adapter *Adapter) dispatch(ctx context.Context, kind string, reference harnessadapter.AttemptRef, prompt string, boundary harnessadapter.ContextBoundary, policy harnessadapter.PolicySnapshot, resumeThreadID string, proofs ...*harnessadapter.FailedTailRetry) (*harnessadapter.Failure, error) {
	adapter.dispatchMu.Lock()
	defer adapter.dispatchMu.Unlock()
	if previous, exists := adapter.store.attempt(reference); exists {
		if previous.DispatchKind != kind || previous.Context != boundary || previous.PolicyHash != policy.EffectiveHash || previous.PromptHash != digestString(prompt) {
			return protocolFailure("codex_dispatch_conflict", "codex dispatch does not match the durable attempt"), nil
		}
		adapter.mu.Lock()
		live := adapter.attempts[attemptKey(reference)]
		adapter.mu.Unlock()
		if previous.State == "active" && live != nil {
			outcome := live.runtime.reconcile().Outcome
			if outcome == harnessadapter.ReconcileRunning || outcome == harnessadapter.ReconcileWaitingInput {
				return nil, nil
			}
		}
		return nodeFailure("codex_dispatch_unknown", "codex dispatch was previously attempted", true), nil
	}
	workspace := adapter.config.WorkingDir
	if policy.ApprovalMode == harnessadapter.ApprovalModeExplicitOnce {
		var err error
		workspace, err = adapter.prepareWorkspace(reference.DialogID)
		if err != nil {
			return nodeFailure("codex_workspace_unavailable", "codex dialog workspace is unavailable", true), err
		}
	}
	if err := adapter.store.putIntent(kind, reference, boundary, policy.EffectiveHash, digestString(prompt), resumeThreadID, proofs...); err != nil {
		return nil, err
	}
	toolCtx, cancelTools := context.WithCancel(context.Background())
	dispatched := false
	defer func() {
		if !dispatched {
			cancelTools()
		}
	}()
	native := &nativeAttempt{
		runtime: newAttemptRuntime(reference), reference: reference, tools: make(map[string]nativeTool),
		policy: policy.ApprovalMode, policyHash: policy.EffectiveHash, workspace: workspace, toolCtx: toolCtx, cancelTools: cancelTools,
	}
	key := attemptKey(reference)
	adapter.mu.Lock()
	if adapter.closed {
		adapter.mu.Unlock()
		return nil, errors.New("codex adapter is closed")
	}
	adapter.attempts[key] = native
	adapter.mu.Unlock()

	options := adapter.threadOptions(policy, workspace, kind == "start")
	var threadResponse nativeThreadResponse
	operationCtx, cancel := adapter.operationContext(ctx)
	defer cancel()
	if kind == "start" {
		if err := adapter.session.Call(operationCtx, "thread/start", options, &threadResponse); err != nil {
			native.runtime.failUnknown("dispatch_uncertain")
			return nil, err
		}
	} else {
		params := options
		params.ThreadID = resumeThreadID
		if err := adapter.session.Call(operationCtx, "thread/resume", params, &threadResponse); err != nil {
			native.runtime.failUnknown("dispatch_uncertain")
			return nil, err
		}
	}
	threadID, err := validateThreadResponse(threadResponse, resumeThreadID, policy, workspace)
	if err != nil {
		native.runtime.failUnknown("adapter_protocol")
		return nil, err
	}
	if err := adapter.store.acknowledgeThread(reference, threadID, adapter.session.ProcessGeneration()); err != nil {
		native.runtime.failUnknown("dispatch_uncertain")
		return nil, err
	}
	adapter.bindThread(native, threadID)
	if err := adapter.verifyThreadFeatures(operationCtx, threadID, policy); err != nil {
		native.runtime.failUnknown("policy_unconfirmed")
		return nil, err
	}
	if err := adapter.verifyMCPInventory(operationCtx, threadID); err != nil {
		native.runtime.failUnknown("policy_unconfirmed")
		return nil, err
	}
	if err := adapter.store.beginTurn(reference); err != nil {
		native.runtime.failUnknown("dispatch_uncertain")
		return nil, err
	}
	var turnResponse nativeTurnResponse
	active := adapter.currentSettings()
	if err := adapter.session.Call(operationCtx, "turn/start", turnParamsWithSettings(threadID, prompt, boundary.MessageID, workspace, active), &turnResponse); err != nil {
		native.runtime.failUnknown("dispatch_uncertain")
		return nil, err
	}
	turnID := turnResponse.Turn.ID
	if !boundedNativeID(turnID) || turnResponse.Turn.Status != "inProgress" || !adapter.bindTurn(native, turnID) {
		native.runtime.failUnknown("adapter_protocol")
		return nil, errors.New("codex turn acknowledgement is invalid")
	}
	if err := adapter.store.activate(reference, turnID, adapter.session.ProcessGeneration()); err != nil {
		native.runtime.failUnknown("dispatch_uncertain")
		return nil, err
	}
	native.runtime.activate()
	activated := native.runtime.reconcile().Outcome
	if activated != harnessadapter.ReconcileRunning && activated != harnessadapter.ReconcileWaitingInput {
		_ = adapter.store.terminal(reference)
	}
	dispatched = true
	return nil, nil
}

type nativeFeature struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type nativeFeaturePage struct {
	Data       []nativeFeature `json:"data"`
	NextCursor *string         `json:"nextCursor"`
}

type nativeMCPPage struct {
	Data       []json.RawMessage `json:"data"`
	NextCursor *string           `json:"nextCursor"`
}

func (adapter *Adapter) verifyThreadFeatures(ctx context.Context, threadID string, policy harnessadapter.PolicySnapshot) error {
	wanted := nativeFeatureOverrides(policy)
	observed := make(map[string]bool, len(wanted))
	seenCursors := make(map[string]bool)
	var cursor string
	for page := 0; page < maximumFeaturePages; page++ {
		params := map[string]any{"threadId": threadID, "limit": 100}
		if cursor != "" {
			params["cursor"] = cursor
		}
		var response nativeFeaturePage
		if err := adapter.session.Call(ctx, "experimentalFeature/list", params, &response); err != nil {
			return fmt.Errorf("verify codex thread policy: %w", err)
		}
		if response.Data == nil {
			return errors.New("codex feature policy response is invalid")
		}
		for _, feature := range response.Data {
			if _, required := wanted[feature.Name]; !required {
				continue
			}
			if previous, exists := observed[feature.Name]; exists && previous != feature.Enabled {
				return errors.New("codex feature policy is conflicting")
			}
			observed[feature.Name] = feature.Enabled
		}
		if response.NextCursor == nil {
			if len(observed) != len(wanted) {
				return errors.New("codex feature policy is incomplete")
			}
			for name, enabled := range wanted {
				if observed[name] != enabled {
					return errors.New("codex feature policy is not enforced")
				}
			}
			if len(wanted) == 0 {
				return errors.New("codex feature policy is not enforced")
			}
			return nil
		}
		cursor = *response.NextCursor
		if !boundedSessionText(cursor, 4096) || seenCursors[cursor] {
			return errors.New("codex feature policy cursor is invalid")
		}
		seenCursors[cursor] = true
	}
	return errors.New("codex feature policy exceeds page limit")
}

func (adapter *Adapter) verifyMCPInventory(ctx context.Context, threadID string) error {
	wanted := map[string]bool{}
	adapter.mu.Lock()
	configured := append([]nodesettings.MCPConfig(nil), adapter.settings.MCPServers...)
	adapter.mu.Unlock()
	for _, server := range configured {
		if server.Enabled {
			wanted[server.ID] = true
		}
	}
	observed := map[string]bool{}
	seenCursors := make(map[string]bool)
	var cursor string
	for page := 0; page < maximumFeaturePages; page++ {
		params := map[string]any{"threadId": threadID, "limit": 100, "detail": "toolsAndAuthOnly"}
		if cursor != "" {
			params["cursor"] = cursor
		}
		var response nativeMCPPage
		if err := adapter.session.Call(ctx, "mcpServerStatus/list", params, &response); err != nil {
			return fmt.Errorf("verify codex MCP isolation: %w", err)
		}
		if response.Data == nil {
			return errors.New("codex MCP inventory is invalid")
		}
		for _, item := range response.Data {
			var entry struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(item, &entry) != nil || !wanted[entry.Name] || observed[entry.Name] {
				return errors.New("codex MCP inventory differs from applied settings")
			}
			observed[entry.Name] = true
		}
		if response.NextCursor == nil {
			if len(observed) != len(wanted) {
				return errors.New("codex MCP inventory is incomplete")
			}
			return nil
		}
		cursor = *response.NextCursor
		if !boundedSessionText(cursor, 4096) || seenCursors[cursor] {
			return errors.New("codex MCP status cursor is invalid")
		}
		seenCursors[cursor] = true
	}
	return errors.New("codex MCP status exceeds page limit")
}

func (adapter *Adapter) Events(_ context.Context, input harnessadapter.EventsInput) (harnessadapter.EventStream, error) {
	adapter.mu.Lock()
	native := adapter.attempts[attemptKey(input.Attempt)]
	adapter.mu.Unlock()
	if native == nil {
		return nil, errors.New("codex event stream is unavailable for attempt")
	}
	return native.runtime.claim()
}

func (adapter *Adapter) Steer(ctx context.Context, input harnessadapter.SteerInput) (harnessadapter.SteerResult, error) {
	if !validReference(input.Attempt) || !uuidPattern.MatchString(input.MessageID) || !boundedText(input.Text) {
		return harnessadapter.SteerResult{Outcome: harnessadapter.SteerRejected, Failure: protocolFailure("codex_steer_invalid", "codex steer input is invalid")}, nil
	}
	mapping, native := adapter.active(input.Attempt)
	if native == nil {
		return harnessadapter.SteerResult{Outcome: harnessadapter.SteerUnknown, Failure: nodeFailure("codex_turn_unavailable", "codex turn is unavailable", true)}, nil
	}
	native.observeExecution()
	var response struct {
		TurnID string `json:"turnId"`
	}
	operationCtx, cancel := adapter.operationContext(ctx)
	defer cancel()
	err := adapter.session.Call(operationCtx, "turn/steer", map[string]any{
		"threadId": mapping.ThreadID, "expectedTurnId": mapping.TurnID,
		"clientUserMessageId": input.MessageID, "input": []nativeUserInput{{Type: "text", Text: input.Text}},
	}, &response)
	if err != nil || response.TurnID != mapping.TurnID {
		return harnessadapter.SteerResult{Outcome: harnessadapter.SteerUnknown, Failure: nodeFailure("codex_steer_unknown", "codex steer acknowledgement is unknown", true)}, err
	}
	return harnessadapter.SteerResult{Outcome: harnessadapter.SteerApplied}, nil
}

func (adapter *Adapter) Cancel(ctx context.Context, input harnessadapter.CancelInput) (harnessadapter.CancelResult, error) {
	if !validReference(input.Attempt) {
		return harnessadapter.CancelResult{Outcome: harnessadapter.CancelRejected, Failure: protocolFailure("codex_cancel_invalid", "codex cancel input is invalid")}, nil
	}
	mapping, native := adapter.cancellable(input.Attempt)
	if native == nil {
		return harnessadapter.CancelResult{Outcome: harnessadapter.CancelUnknown, Failure: nodeFailure("codex_turn_unavailable", "codex turn is unavailable", true)}, nil
	}
	native.observeExecution()
	operationCtx, cancel := adapter.operationContext(ctx)
	defer cancel()
	err := adapter.session.CallAfterWrite(operationCtx, "turn/interrupt", map[string]string{"threadId": mapping.ThreadID, "turnId": mapping.TurnID}, &struct{}{}, native.cancelTools)
	// The hook is not reached when the provider session is already unavailable.
	// Cancellation is idempotent and still has to stop the isolated runner.
	native.cancelTools()
	if err != nil {
		return harnessadapter.CancelResult{Outcome: harnessadapter.CancelUnknown, Failure: nodeFailure("codex_cancel_unknown", "codex interrupt acknowledgement is unknown", true)}, err
	}
	return harnessadapter.CancelResult{Outcome: harnessadapter.CancelAcknowledged}, nil
}

func (adapter *Adapter) RespondApproval(ctx context.Context, input harnessadapter.RespondApprovalInput) (harnessadapter.ResponseResult, error) {
	if !validReference(input.Attempt) || !uuidPattern.MatchString(input.ApprovalID) || input.ApprovalVersion != 2 ||
		!validPolicyHash(input.ActionHash) || (input.Decision != "allow_once" && input.Decision != "deny") {
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseRejected, Failure: protocolFailure("codex_approval_invalid", "codex approval response is invalid")}, nil
	}
	adapter.mu.Lock()
	pending, ok := adapter.approvals[input.ApprovalID]
	if !ok || pending.attempt.reference != input.Attempt || pending.actionHash != input.ActionHash {
		ok = false
	} else if pending.responding {
		adapter.mu.Unlock()
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseUnknown, Failure: nodeFailure("codex_approval_unknown", "codex approval response acknowledgement is unknown", true)}, nil
	} else if pending.resolved {
		delete(adapter.approvals, input.ApprovalID)
		delete(adapter.approvalByRPC, pending.id.key)
		adapter.mu.Unlock()
		pending.attempt.runtime.setWaitingInput(false)
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseRejected, Failure: taskFailure("codex_approval_stale", "codex approval request is no longer pending")}, nil
	} else {
		pending.responding = true
	}
	adapter.mu.Unlock()
	if !ok {
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseRejected, Failure: taskFailure("codex_approval_stale", "codex approval request is no longer pending")}, nil
	}
	tool, toolOK := pending.attempt.tool(pending.itemID)
	if !toolOK || tool.actionHash != pending.actionHash {
		adapter.resolvePendingApproval(input.ApprovalID, false)
		pending.attempt.runtime.failUnknown("adapter_protocol")
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseUnknown, Failure: nodeFailure("codex_approval_unknown", "codex tool request changed before execution", true)}, nil
	}
	response := declinedDynamicResponse()
	effectStatus := "none"
	outputTruncated := false
	var fullSafeOutput *string
	fullIncomplete := false
	if input.Decision == "allow_once" {
		runCtx, cancelRun := context.WithCancel(ctx)
		stopCancel := context.AfterFunc(pending.attempt.toolCtx, cancelRun)
		result, runErr := adapter.config.Runner.Run(runCtx, tool.request)
		stopCancel()
		cancelRun()
		response = safeRunnerResponse(result, runErr)
		fullSafeOutput, fullIncomplete = safeRunnerFullText(result, runErr)
		effectStatus = "known"
		if runErr != nil {
			effectStatus = "unknown"
		}
		outputTruncated = result.Truncated
	}
	if !adapter.setExpectedToolResponse(pending.attempt, pending.itemID, response, effectStatus, outputTruncated, fullSafeOutput, fullIncomplete) {
		adapter.resolvePendingApproval(input.ApprovalID, false)
		pending.attempt.runtime.failUnknown("adapter_protocol")
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseUnknown, Failure: nodeFailure("codex_approval_unknown", "codex tool response state is unknown", true)}, nil
	}
	if err := adapter.session.Respond(pending.id, response); err != nil {
		adapter.resolvePendingApproval(input.ApprovalID, false)
		pending.attempt.runtime.failUnknown("provider_state")
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseUnknown, Failure: nodeFailure("codex_approval_unknown", "codex approval response acknowledgement is unknown", true)}, err
	}
	select {
	case applied := <-pending.result:
		if applied {
			return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseApplied}, nil
		}
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseUnknown, Failure: nodeFailure("codex_approval_unknown", "codex approval request ended before acknowledgement", true)}, nil
	case <-ctx.Done():
		pending.attempt.runtime.failUnknown("provider_state")
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseUnknown, Failure: nodeFailure("codex_approval_unknown", "codex approval response acknowledgement is unknown", true)}, ctx.Err()
	case <-adapter.session.Done():
		pending.attempt.runtime.failUnknown("provider_state")
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseUnknown, Failure: nodeFailure("codex_approval_unknown", "codex approval response acknowledgement is unknown", true)}, errBridgeClosed
	}
}

func (adapter *Adapter) RespondInput(ctx context.Context, input harnessadapter.RespondInputInput) (harnessadapter.ResponseResult, error) {
	if !validReference(input.Attempt) || !uuidPattern.MatchString(input.InputRequestID) || input.InputVersion != 2 || !boundedText(input.Text) {
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseRejected, Failure: protocolFailure("codex_input_invalid", "codex input response is invalid")}, nil
	}
	adapter.mu.Lock()
	pending, ok := adapter.inputs[input.InputRequestID]
	if !ok || pending.attempt.reference != input.Attempt {
		ok = false
	} else if pending.responding {
		adapter.mu.Unlock()
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseUnknown, Failure: nodeFailure("codex_input_unknown", "codex input response acknowledgement is unknown", true)}, nil
	} else {
		pending.responding = true
	}
	adapter.mu.Unlock()
	if !ok {
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseRejected, Failure: taskFailure("codex_input_stale", "codex input request is no longer pending")}, nil
	}
	err := adapter.session.Respond(pending.id, map[string]any{"answers": map[string]any{
		pending.questionID: map[string]any{"answers": []string{input.Text}},
	}})
	if err != nil {
		adapter.resolvePendingInput(input.InputRequestID, false)
		pending.attempt.runtime.failUnknown("provider_state")
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseUnknown, Failure: nodeFailure("codex_input_unknown", "codex input response acknowledgement is unknown", true)}, err
	}
	select {
	case applied := <-pending.result:
		if applied {
			return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseApplied}, nil
		}
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseUnknown, Failure: nodeFailure("codex_input_unknown", "codex input request ended before acknowledgement", true)}, nil
	case <-ctx.Done():
		pending.attempt.runtime.failUnknown("provider_state")
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseUnknown, Failure: nodeFailure("codex_input_unknown", "codex input response acknowledgement is unknown", true)}, ctx.Err()
	case <-adapter.session.Done():
		pending.attempt.runtime.failUnknown("provider_state")
		return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseUnknown, Failure: nodeFailure("codex_input_unknown", "codex input response acknowledgement is unknown", true)}, errBridgeClosed
	}
}

func (adapter *Adapter) Reconcile(_ context.Context, input harnessadapter.ReconcileInput) (harnessadapter.ReconcileResult, error) {
	if !validReference(input.Attempt) {
		return harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileUnknown, EffectStatus: "unknown", Failure: protocolFailure("codex_reconcile_invalid", "codex reconcile input is invalid")}, nil
	}
	adapter.mu.Lock()
	native := adapter.attempts[attemptKey(input.Attempt)]
	adapter.mu.Unlock()
	if native != nil {
		return native.runtime.reconcile(), nil
	}
	if _, exists := adapter.store.attempt(input.Attempt); exists {
		return harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileUnknown, EffectStatus: "unknown", Failure: nodeFailure("codex_provider_state_unknown", "codex provider state is unknown after restart", true)}, nil
	}
	return harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileUnknown, EffectStatus: "none", Failure: taskFailure("codex_attempt_missing", "codex attempt mapping is unavailable")}, nil
}

// ConfirmCompletedApprovalRace supplies only the provider-owned half of the
// bounded recovery proof. A terminal mapping from an earlier app-server process
// confirms that the native turn ended; the node separately verifies the exact
// approval, successful known tool effect, final assistant message and event
// order before it changes durable Harness state.
func (adapter *Adapter) ConfirmCompletedApprovalRace(ctx context.Context, reference harnessadapter.AttemptRef) error {
	return adapter.ConfirmPriorTerminal(ctx, reference)
}

// ConfirmPriorTerminal proves only that the exact native turn reached a
// terminal boundary in an earlier app-server process generation. Node-level
// recovery code must independently prove the durable effect state before it
// releases an unknown attempt.
func (adapter *Adapter) ConfirmPriorTerminal(ctx context.Context, reference harnessadapter.AttemptRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validReference(reference) {
		return errors.New("codex approval race reference is invalid")
	}
	adapter.mu.Lock()
	_, active := adapter.attempts[attemptKey(reference)]
	adapter.mu.Unlock()
	adapter.store.mu.Lock()
	persisted, exists := adapter.store.contents.Attempts[attemptKey(reference)]
	processGeneration := adapter.store.contents.ProcessGeneration
	adapter.store.mu.Unlock()
	if active || !exists || persisted.Reference != reference || persisted.State != "terminal" ||
		persisted.ProcessGeneration < 1 || persisted.ProcessGeneration >= processGeneration {
		return errors.New("codex attempt has no prior terminal mapping")
	}
	return nil
}

func (adapter *Adapter) Close() error {
	adapter.mu.Lock()
	if adapter.closed {
		adapter.mu.Unlock()
		return nil
	}
	adapter.closed = true
	session := adapter.session
	for _, native := range adapter.attempts {
		native.cancelTools()
	}
	adapter.mu.Unlock()
	if session == nil {
		return nil
	}
	if err := session.Close(); err != nil {
		return err
	}
	_ = session.Wait()
	return nil
}

type nativeThreadOptions struct {
	ThreadID              string                  `json:"threadId,omitempty"`
	Model                 *string                 `json:"model"`
	ServiceTier           *string                 `json:"serviceTier,omitempty"`
	CWD                   string                  `json:"cwd"`
	ApprovalPolicy        string                  `json:"approvalPolicy"`
	ApprovalsReviewer     string                  `json:"approvalsReviewer"`
	Sandbox               string                  `json:"sandbox"`
	DeveloperInstructions string                  `json:"developerInstructions"`
	Config                map[string]any          `json:"config"`
	DynamicTools          []nativeDynamicToolSpec `json:"dynamicTools,omitempty"`
}

type nativeThreadResponse struct {
	Thread struct {
		ID string `json:"id"`
	} `json:"thread"`
	ApprovalPolicy    json.RawMessage `json:"approvalPolicy"`
	ApprovalsReviewer string          `json:"approvalsReviewer"`
	CWD               string          `json:"cwd"`
	Sandbox           struct {
		Type                string   `json:"type"`
		WritableRoots       []string `json:"writableRoots"`
		NetworkAccess       bool     `json:"networkAccess"`
		ExcludeTmpdirEnvVar bool     `json:"excludeTmpdirEnvVar"`
		ExcludeSlashTmp     bool     `json:"excludeSlashTmp"`
	} `json:"sandbox"`
}

type nativeUserInput struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type nativeSandboxPolicy struct {
	Type                string   `json:"type"`
	WritableRoots       []string `json:"writableRoots,omitempty"`
	NetworkAccess       bool     `json:"networkAccess"`
	ExcludeTmpdirEnvVar bool     `json:"excludeTmpdirEnvVar,omitempty"`
	ExcludeSlashTmp     bool     `json:"excludeSlashTmp,omitempty"`
}

type nativeDynamicToolSpec struct {
	Type        string                  `json:"type"`
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Tools       []nativeDynamicFunction `json:"tools"`
}

type nativeDynamicFunction struct {
	Type         string         `json:"type"`
	Name         string         `json:"name"`
	Description  string         `json:"description"`
	InputSchema  map[string]any `json:"inputSchema"`
	DeferLoading bool           `json:"deferLoading"`
}

type nativeTurnParams struct {
	ThreadID            string              `json:"threadId"`
	Input               []nativeUserInput   `json:"input"`
	ClientUserMessageID string              `json:"clientUserMessageId"`
	CWD                 string              `json:"cwd"`
	ApprovalPolicy      string              `json:"approvalPolicy"`
	ApprovalsReviewer   string              `json:"approvalsReviewer"`
	SandboxPolicy       nativeSandboxPolicy `json:"sandboxPolicy"`
	Model               *string             `json:"model"`
	Effort              *string             `json:"effort"`
	ServiceTier         *string             `json:"serviceTier,omitempty"`
}

type nativeTurnResponse struct {
	Turn struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"turn"`
}

func (adapter *Adapter) threadOptions(policy harnessadapter.PolicySnapshot, workspace string, includeDynamicTools bool) nativeThreadOptions {
	adapter.mu.Lock()
	settings := adapter.settings
	adapter.mu.Unlock()
	return adapter.threadOptionsWithSettings(policy, workspace, includeDynamicTools, settings)
}

func (adapter *Adapter) threadOptionsWithSettings(policy harnessadapter.PolicySnapshot, workspace string, includeDynamicTools bool, settings activeSettings) nativeThreadOptions {
	mcpServers := map[string]any{}
	for _, server := range settings.MCPServers {
		if !server.Enabled {
			continue
		}
		entry := map[string]any{"enabled": true,
			"startup_timeout_sec": float64(server.TimeoutMS) / 1000, "tool_timeout_sec": float64(server.TimeoutMS) / 1000}
		if server.Transport == "stdio" {
			entry["command"] = server.Command
			entry["args"] = server.Args
			if len(server.SecretValues) > 0 {
				entry["env"] = server.SecretValues
			}
		} else {
			entry["url"] = server.URL
			if server.Auth.Kind == "bearer" {
				entry["bearer_token_env_var"] = mcpTokenVariable(server.ID)
			}
		}
		mcpServers[server.ID] = entry
	}
	options := nativeThreadOptions{
		Model: optionalNativeString(settings.Model), ServiceTier: serviceTierForTurn(settings.Speed), CWD: workspace, ApprovalPolicy: nativeApprovalPolicy(),
		ApprovalsReviewer: nativeApprovalsReviewer(), Sandbox: "read-only",
		DeveloperInstructions: string(policy.Content),
		Config: map[string]any{
			"features": nativeFeatureOverrides(policy), "mcp_servers": mcpServers,
			"model_reasoning_effort": optionalNativeString(settings.Effort), "web_search": "disabled",
		},
	}
	if includeDynamicTools && policy.ApprovalMode == harnessadapter.ApprovalModeExplicitOnce {
		options.DynamicTools = codexDynamicTools()
	}
	return options
}

func optionalNativeString(value string) *string {
	if value == "" {
		return nil
	}
	copy := value
	return &copy
}
func serviceTierForTurn(speed *string) *string {
	tier := "default"
	if speed != nil && *speed == "on" {
		tier = "priority"
	}
	return &tier
}

func turnParamsWithSettings(threadID, prompt, messageID, workspace string, settings activeSettings) nativeTurnParams {
	return nativeTurnParams{ThreadID: threadID, Input: []nativeUserInput{{Type: "text", Text: prompt}}, ClientUserMessageID: messageID, CWD: workspace, ApprovalPolicy: nativeApprovalPolicy(), ApprovalsReviewer: nativeApprovalsReviewer(), SandboxPolicy: readOnlySandboxPolicy(), Model: optionalNativeString(settings.Model), Effort: optionalNativeString(settings.Effort), ServiceTier: serviceTierForTurn(settings.Speed)}
}

func nativeFeatureOverrides(_ harnessadapter.PolicySnapshot) map[string]bool {
	features := make(map[string]bool, len(deniedNativeFeatures))
	for _, name := range deniedNativeFeatures {
		features[name] = false
	}
	return features
}

func validateThreadResponse(response nativeThreadResponse, expectedThreadID string, _ harnessadapter.PolicySnapshot, workspace string) (string, error) {
	threadID := response.Thread.ID
	var approval string
	if !boundedNativeID(threadID) || (expectedThreadID != "" && threadID != expectedThreadID) ||
		json.Unmarshal(response.ApprovalPolicy, &approval) != nil || approval != nativeApprovalPolicy() ||
		response.CWD != workspace || response.ApprovalsReviewer != nativeApprovalsReviewer() ||
		response.Sandbox.Type != "readOnly" || response.Sandbox.NetworkAccess || len(response.Sandbox.WritableRoots) != 0 ||
		response.Sandbox.ExcludeTmpdirEnvVar || response.Sandbox.ExcludeSlashTmp {
		return "", errors.New("codex thread acknowledgement is invalid")
	}
	return threadID, nil
}

func nativeApprovalPolicy() string    { return "never" }
func nativeApprovalsReviewer() string { return "user" }
func readOnlySandboxPolicy() nativeSandboxPolicy {
	return nativeSandboxPolicy{Type: "readOnly", NetworkAccess: false}
}

func codexDynamicTools() []nativeDynamicToolSpec {
	object := func(properties map[string]any, required ...string) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "required": required}
	}
	command := nativeDynamicFunction{Type: "function", Name: "command", DeferLoading: false,
		Description: "Run one bounded command inside this dialog workspace with no network access. Read access runs immediately. Write access is requested by calling this tool: the call creates the one-time operator approval, so call it before approval and do not ask for approval in chat.",
		InputSchema: object(map[string]any{
			"command":        map[string]any{"type": "string", "minLength": 1, "maxLength": toolrunner.MaximumCommandBytes},
			"cwd":            map[string]any{"type": "string", "minLength": 1, "maxLength": 4096},
			"access":         map[string]any{"type": "string", "enum": []string{"read", "write"}},
			"timeoutSeconds": map[string]any{"type": "integer", "minimum": 1, "maximum": int(toolrunner.MaximumRuntime / time.Second)},
		}, "command", "cwd", "access", "timeoutSeconds")}
	change := object(map[string]any{
		"path":           map[string]any{"type": "string", "minLength": 1, "maxLength": 4096},
		"operation":      map[string]any{"type": "string", "enum": []string{"write", "delete"}},
		"expectedSha256": map[string]any{"type": []string{"string", "null"}, "pattern": "^[0-9a-f]{64}$"},
		"content":        map[string]any{"type": []string{"string", "null"}, "maxLength": toolrunner.MaximumFileBytes},
	}, "path", "operation", "expectedSha256", "content")
	fileChange := nativeDynamicFunction{Type: "function", Name: "file_change", DeferLoading: false,
		Description: "Request bounded text file writes or deletes inside this dialog workspace using exact content hashes. Calling this tool creates the one-time operator approval; call it before approval and do not ask for approval in chat. This Harness tool is separate from the read-only native Codex sandbox.",
		InputSchema: object(map[string]any{"changes": map[string]any{"type": "array", "minItems": 1, "maxItems": toolrunner.MaximumChanges, "items": change}}, "changes")}
	return []nativeDynamicToolSpec{{Type: "namespace", Name: "codex", Description: "Isolated tools for this dialog workspace.", Tools: []nativeDynamicFunction{command, fileChange}}}
}

func (adapter *Adapter) bindThread(native *nativeAttempt, threadID string) {
	native.mu.Lock()
	native.threadID = threadID
	native.mu.Unlock()
	adapter.mu.Lock()
	adapter.byThread[threadID] = native
	adapter.mu.Unlock()
}

func turnKey(threadID, turnID string) string { return threadID + "\x00" + turnID }

func (adapter *Adapter) bindTurn(native *nativeAttempt, turnID string) bool {
	native.mu.Lock()
	if native.turnID != "" && native.turnID != turnID {
		native.mu.Unlock()
		return false
	}
	native.turnID = turnID
	threadID := native.threadID
	native.mu.Unlock()
	if !boundedNativeID(threadID) || !boundedNativeID(turnID) {
		return false
	}
	adapter.mu.Lock()
	key := turnKey(threadID, turnID)
	if existing := adapter.byTurn[key]; existing != nil && existing != native {
		adapter.mu.Unlock()
		return false
	}
	adapter.byTurn[key] = native
	adapter.mu.Unlock()
	return true
}

func (adapter *Adapter) active(reference harnessadapter.AttemptRef) (persistedAttempt, *nativeAttempt) {
	return adapter.live(reference, false)
}

func (adapter *Adapter) cancellable(reference harnessadapter.AttemptRef) (persistedAttempt, *nativeAttempt) {
	return adapter.live(reference, true)
}

func (adapter *Adapter) live(reference harnessadapter.AttemptRef, includeWaiting bool) (persistedAttempt, *nativeAttempt) {
	mapping, exists := adapter.store.attempt(reference)
	if !exists || mapping.State != "active" || !boundedNativeID(mapping.ThreadID) || !boundedNativeID(mapping.TurnID) {
		return persistedAttempt{}, nil
	}
	adapter.mu.Lock()
	native := adapter.attempts[attemptKey(reference)]
	adapter.mu.Unlock()
	if native == nil {
		return persistedAttempt{}, nil
	}
	outcome := native.runtime.reconcile().Outcome
	if outcome != harnessadapter.ReconcileRunning && (!includeWaiting || outcome != harnessadapter.ReconcileWaitingInput) {
		return persistedAttempt{}, nil
	}
	return mapping, native
}

func (adapter *Adapter) prepareWorkspace(dialogID string) (string, error) {
	if !uuidPattern.MatchString(dialogID) {
		return "", errors.New("codex dialog workspace identifier is invalid")
	}
	root := filepath.Clean(adapter.config.WorkingDir)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("codex workspace root is unsafe")
	}
	workspace := filepath.Join(root, dialogID)
	if filepath.Dir(workspace) != root {
		return "", errors.New("codex dialog workspace escapes root")
	}
	if err := os.Mkdir(workspace, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("create codex dialog workspace: %w", err)
	}
	info, err = os.Lstat(workspace)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return "", errors.New("codex dialog workspace is unsafe")
	}
	return workspace, nil
}

func (adapter *Adapter) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, adapter.config.OperationTimeout)
}

func (adapter *Adapter) validateDispatch(reference harnessadapter.AttemptRef, prompt string, boundary harnessadapter.ContextBoundary, policy harnessadapter.PolicySnapshot) (harnessadapter.PolicySnapshot, *harnessadapter.Failure) {
	if !validReference(reference) || !boundedText(prompt) || !validBoundary(boundary) {
		return harnessadapter.PolicySnapshot{}, protocolFailure("codex_dispatch_invalid", "codex dispatch input is invalid")
	}
	prepared, err := harnessadapter.PreparePolicySnapshot(policy)
	if err != nil {
		return harnessadapter.PolicySnapshot{}, protocolFailure("codex_policy_invalid", "codex policy snapshot is invalid")
	}
	if !validCodexToolManifest(prepared) {
		return harnessadapter.PolicySnapshot{}, policyFailure("codex_policy_unsupported", "codex node policy and tool manifest are unsupported")
	}
	if prepared.ApprovalMode == harnessadapter.ApprovalModeExplicitOnce && adapter.config.Runner == nil {
		return harnessadapter.PolicySnapshot{}, policyFailure("codex_tool_runner_required", "codex isolated tool runner is unavailable")
	}
	if !boundedText(string(prepared.Content)) || strings.TrimSpace(string(prepared.Content)) == "" {
		return harnessadapter.PolicySnapshot{}, policyFailure("codex_policy_unsupported", "codex developer instructions are unavailable")
	}
	return prepared, nil
}

type manifestTool struct {
	Name string `json:"name"`
}

func validCodexToolManifest(policy harnessadapter.PolicySnapshot) bool {
	decoder := json.NewDecoder(strings.NewReader(string(policy.ToolManifest)))
	decoder.DisallowUnknownFields()
	var tools []manifestTool
	if decoder.Decode(&tools) != nil || tools == nil || decoder.Decode(new(any)) != io.EOF {
		return false
	}
	if policy.ApprovalMode == harnessadapter.ApprovalModeDeny {
		return len(tools) == 0
	}
	if policy.ApprovalMode != harnessadapter.ApprovalModeExplicitOnce || len(tools) != 2 {
		return false
	}
	wanted := map[string]bool{"codex.command": false, "codex.file_change": false}
	for _, tool := range tools {
		seen, ok := wanted[tool.Name]
		if !ok || seen {
			return false
		}
		wanted[tool.Name] = true
	}
	return wanted["codex.command"] && wanted["codex.file_change"]
}

func invalidEnvironment(environment []string) bool {
	if len(environment) == 0 || len(environment) > 64 {
		return true
	}
	seen := make(map[string]bool, len(environment))
	for _, value := range environment {
		name, _, ok := strings.Cut(value, "=")
		if !ok || name == "" || seen[name] || strings.ContainsAny(value, "\x00\r\n") || name == "OPENAI_API_KEY" || name == "CODEX_API_KEY" || name == "ANTHROPIC_API_KEY" || name == "CURSOR_API_KEY" {
			return true
		}
		seen[name] = true
	}
	return false
}

func validEffort(value string) bool {
	switch value {
	case "minimal", "low", "medium", "high", "xhigh":
		return true
	default:
		return false
	}
}

func boundedText(value string) bool {
	return value != "" && utf8.ValidString(value) && len(value) <= harnessprotocol.MaximumMessageBytes
}

func taskFailure(code, message string) *harnessadapter.Failure {
	return &harnessadapter.Failure{Class: harnessadapter.FailureTask, Code: code, SafeMessage: message}
}

func nodeFailure(code, message string, retryable bool) *harnessadapter.Failure {
	return &harnessadapter.Failure{Class: harnessadapter.FailureNode, Code: code, SafeMessage: message, Retryable: retryable}
}

func policyFailure(code, message string) *harnessadapter.Failure {
	return &harnessadapter.Failure{Class: harnessadapter.FailurePolicy, Code: code, SafeMessage: message}
}

func protocolFailure(code, message string) *harnessadapter.Failure {
	return &harnessadapter.Failure{Class: harnessadapter.FailureProtocol, Code: code, SafeMessage: message}
}

func safeInline(value string) harnessprotocol.SafeContent {
	if !utf8.ValidString(value) {
		return unavailableContent("provider_redacted")
	}
	truncated := false
	if len(value) > harnessprotocol.MaximumMessageBytes {
		value = value[:harnessprotocol.MaximumMessageBytes]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
		truncated = true
	}
	return harnessprotocol.SafeContent{Kind: "inline", Content: value, Redaction: "none", Truncated: truncated}
}

func unavailableContent(reason string) harnessprotocol.SafeContent {
	return harnessprotocol.SafeContent{Kind: "unavailable", Reason: reason, Redaction: "unknown"}
}

func finishReason(content harnessprotocol.SafeContent) string {
	if content.Truncated {
		return "length"
	}
	return "complete"
}

func digestString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func derivedUUID(domain, value string) string {
	sum := sha256.Sum256([]byte(domain + "\x00" + value))
	raw := sum[:16]
	raw[6] = raw[6]&0x0f | 0x50
	raw[8] = raw[8]&0x3f | 0x80
	hexValue := hex.EncodeToString(raw)
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexValue[:8], hexValue[8:12], hexValue[12:16], hexValue[16:20], hexValue[20:])
}
