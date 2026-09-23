package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/boxvtk621/harness-codex/adapters/codex"
	harnessserver "github.com/boxvtk621/harness-codex/api"
	"github.com/boxvtk621/harness-codex/internal/diagnosticlog"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/nodesettings"
	"github.com/boxvtk621/harness-codex/internal/providerauth"
	"github.com/boxvtk621/harness-codex/internal/toolrunner"
	runtime "github.com/boxvtk621/harness-codex/runtime"
)

const (
	codexExplicitToolManifest = "[{\"name\":\"codex.command\"},{\"name\":\"codex.file_change\"}]\n"
	toolRunnerExecutable      = "/harness-tool-runner"
)

type config struct {
	Listen                   string       `json:"listen"`
	NodeID                   string       `json:"nodeId"`
	OwnerID                  string       `json:"ownerId"`
	DataDir                  string       `json:"dataDir"`
	RegistryVersion          int64        `json:"registryVersion"`
	CertificateFile          string       `json:"certificateFile"`
	KeyFile                  string       `json:"keyFile"`
	PolicyFile               string       `json:"policyFile"`
	ToolManifestFile         string       `json:"toolManifestFile"`
	PolicyRevision           string       `json:"policyRevision"`
	ApprovalMode             string       `json:"approvalMode,omitempty"`
	ManualDispatchForTesting bool         `json:"manualDispatchForTesting,omitempty"`
	Adapter                  string       `json:"adapter"`
	Codex                    *codexConfig `json:"codex,omitempty"`
}

type codexConfig struct {
	Executable string `json:"executable"`
	StateDir   string `json:"stateDir"`
	WorkingDir string `json:"workingDir"`
	CodexHome  string `json:"codexHome"`
	HomeDir    string `json:"homeDir"`
	Model      string `json:"model"`
	Effort     string `json:"effort"`
}

type providerAdapter interface {
	harnessadapter.Adapter
	providerauth.Manager
	nodesettings.Provider
	Close() error
}

type approvalRaceFlags struct {
	dialogID                string
	requestID               string
	attemptID               string
	generation              int64
	expectedAttemptVersion  int64
	approvalID              string
	expectedApprovalVersion int64
	decision                string
	callID                  string
	expectedToolVersion     int64
	actionHash              string
	commandID               string
	assistantMessageID      string
	expectedUnknownSeq      int64
	expectedDeltaCount      int64
}

func main() {
	path := flag.String("config", "", "path to the node JSON configuration")
	recoverApprovalRace := flag.Bool("recover-completed-approval-race", false, "recover one exactly proven Codex approval acknowledgement race")
	recoverDeltaOverflow := flag.Bool("recover-codex-delta-overflow", false, "recover one exactly proven Codex assistant delta overflow")
	recoverCodeMode := flag.Bool("recover-codex-code-mode-delegation", false, "recover one exactly proven Codex Code Mode delegation ordering failure")
	recoverUnsupportedModel := flag.Bool("recover-codex-unsupported-model", false, "recover one SHA-pinned historical Codex unsupported-model rejection offline")
	checkRecovery := flag.Bool("check-recovery", false, "validate the unsupported-model recovery proof without mutation")
	expectedEpoch := flag.Int64("expected-epoch", 0, "exact node epoch")
	expectedStateVersion := flag.Int64("expected-state-version", 0, "exact node state version")
	expectedLastEventSeq := flag.Int64("expected-last-event-seq", 0, "exact node event high-water mark")
	expectedRequestVersion := flag.Int64("expected-request-version", 0, "exact unknown request version")
	expectedLateObservationID := flag.Int64("expected-late-observation-id", 0, "exact archived terminal row ID")
	expectedLateHash := flag.String("expected-late-hash", "", "exact archived terminal projection SHA-256")
	expectedProcessGeneration := flag.Int64("expected-process-generation", 0, "exact persisted Codex process generation")
	rolloutRelativePath := flag.String("rollout-relative-path", "", "SHA-pinned rollout path relative to CODEX_HOME")
	rolloutSHA256 := flag.String("rollout-sha256", "", "SHA-256 of complete native rollout")
	flags := approvalRaceFlags{}
	flag.StringVar(&flags.dialogID, "dialog-id", "", "exact dialog UUID")
	flag.StringVar(&flags.requestID, "request-id", "", "exact request UUID")
	flag.StringVar(&flags.attemptID, "attempt-id", "", "exact attempt UUID")
	flag.Int64Var(&flags.generation, "attempt-generation", 0, "exact attempt generation")
	flag.Int64Var(&flags.expectedAttemptVersion, "expected-attempt-version", 0, "expected unknown attempt version")
	flag.StringVar(&flags.approvalID, "approval-id", "", "exact approval UUID")
	flag.Int64Var(&flags.expectedApprovalVersion, "expected-approval-version", 0, "expected responding approval version")
	flag.StringVar(&flags.decision, "approval-decision", "", "exact approval decision; defaults to allow_once")
	flag.StringVar(&flags.callID, "call-id", "", "exact tool call UUID")
	flag.Int64Var(&flags.expectedToolVersion, "expected-tool-version", 0, "expected completed tool version")
	flag.StringVar(&flags.actionHash, "action-hash", "", "exact approved action SHA-256")
	flag.StringVar(&flags.commandID, "command-id", "", "exact approval response command UUID")
	flag.StringVar(&flags.assistantMessageID, "assistant-message-id", "", "exact final assistant message UUID")
	flag.Int64Var(&flags.expectedUnknownSeq, "expected-unknown-seq", 0, "exact adapter protocol unknown event sequence")
	flag.Int64Var(&flags.expectedDeltaCount, "expected-delta-count", 0, "exact number of fine-grained assistant deltas")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 || os.Geteuid() == 0 || boolCount(*recoverApprovalRace, *recoverDeltaOverflow, *recoverCodeMode, *recoverUnsupportedModel) > 1 {
		fmt.Fprintln(os.Stderr, "HARNESS_CONFIG_INVALID")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	diagnostics := diagnosticlog.New(diagnosticlog.Config{Writer: os.Stderr, Component: "harness-codex"})
	defer diagnostics.Close()
	unsupportedFlagsSet := *checkRecovery || *expectedEpoch != 0 || *expectedStateVersion != 0 || *expectedLastEventSeq != 0 ||
		*expectedRequestVersion != 0 || *expectedLateObservationID != 0 || *expectedLateHash != "" ||
		*expectedProcessGeneration != 0 || *rolloutRelativePath != "" || *rolloutSHA256 != ""
	if *recoverUnsupportedModel {
		if flags.approvalID != "" || flags.expectedApprovalVersion != 0 || flags.decision != "" ||
			flags.callID != "" || flags.expectedToolVersion != 0 || flags.actionHash != "" || flags.commandID != "" ||
			flags.assistantMessageID != "" || flags.expectedDeltaCount != 0 {
			fmt.Fprintln(os.Stderr, "HARNESS_CONFIG_INVALID")
			os.Exit(2)
		}
		proof := runtime.CodexUnsupportedModelProof{Attempt: harnessadapter.AttemptRef{
			NodeID: "", DialogID: flags.dialogID, RequestID: flags.requestID,
			AttemptID: flags.attemptID, Generation: flags.generation,
		}, ExpectedEpoch: *expectedEpoch, ExpectedStateVersion: *expectedStateVersion,
			ExpectedLastEventSeq: *expectedLastEventSeq, ExpectedAttemptVersion: flags.expectedAttemptVersion,
			ExpectedRequestVersion: *expectedRequestVersion, ExpectedUnknownSeq: flags.expectedUnknownSeq,
			ExpectedLateObservationID: *expectedLateObservationID, ExpectedLateHash: *expectedLateHash,
			ExpectedProcessGeneration: *expectedProcessGeneration, RolloutRelativePath: *rolloutRelativePath,
			RolloutSHA256: *rolloutSHA256}
		if err := recoverCodexUnsupportedModel(ctx, *path, proof, *checkRecovery, diagnostics); err != nil {
			diagnostics.Emit(diagnosticlog.LevelError, diagnosticlog.EventRecoveryFailed, diagnosticlog.Fields{Operation: "unsupported_model", Reason: "recovery_failed"})
			diagnostics.Close()
			fmt.Fprintln(os.Stderr, "HARNESS_RECOVERY_FAILED")
			os.Exit(1)
		}
		if *checkRecovery {
			fmt.Fprintln(os.Stdout, "HARNESS_RECOVERY_CHECK_PASSED")
		} else {
			fmt.Fprintln(os.Stdout, "HARNESS_RECOVERY_COMPLETED")
		}
		return
	}
	if unsupportedFlagsSet {
		fmt.Fprintln(os.Stderr, "HARNESS_CONFIG_INVALID")
		os.Exit(2)
	}
	if *recoverApprovalRace {
		if flags.expectedUnknownSeq != 0 || flags.expectedDeltaCount != 0 {
			fmt.Fprintln(os.Stderr, "HARNESS_CONFIG_INVALID")
			os.Exit(2)
		}
		if err := recoverCompletedApprovalRace(ctx, *path, flags, diagnostics); err != nil {
			diagnostics.Emit(diagnosticlog.LevelError, diagnosticlog.EventRecoveryFailed, diagnosticlog.Fields{Operation: "approval_race", Reason: "recovery_failed"})
			diagnostics.Close()
			fmt.Fprintln(os.Stderr, "HARNESS_RECOVERY_FAILED")
			os.Exit(1)
		}
		diagnostics.Emit(diagnosticlog.LevelInfo, diagnosticlog.EventRecoveryComplete, diagnosticlog.Fields{Operation: "approval_race"})
		fmt.Fprintln(os.Stdout, "HARNESS_RECOVERY_COMPLETED")
		return
	}
	if *recoverDeltaOverflow {
		if flags.approvalID != "" || flags.expectedApprovalVersion != 0 || flags.decision != "" ||
			flags.commandID != "" || flags.assistantMessageID != "" {
			fmt.Fprintln(os.Stderr, "HARNESS_CONFIG_INVALID")
			os.Exit(2)
		}
		if err := recoverCodexDeltaOverflow(ctx, *path, flags, diagnostics); err != nil {
			diagnostics.Emit(diagnosticlog.LevelError, diagnosticlog.EventRecoveryFailed, diagnosticlog.Fields{Operation: "delta_overflow", Reason: "recovery_failed"})
			diagnostics.Close()
			fmt.Fprintln(os.Stderr, "HARNESS_RECOVERY_FAILED")
			os.Exit(1)
		}
		diagnostics.Emit(diagnosticlog.LevelInfo, diagnosticlog.EventRecoveryComplete, diagnosticlog.Fields{Operation: "delta_overflow"})
		fmt.Fprintln(os.Stdout, "HARNESS_RECOVERY_COMPLETED")
		return
	}
	if *recoverCodeMode {
		if flags.approvalID != "" || flags.expectedApprovalVersion != 0 || flags.decision != "" ||
			flags.callID != "" || flags.expectedToolVersion != 0 || flags.actionHash != "" || flags.commandID != "" {
			fmt.Fprintln(os.Stderr, "HARNESS_CONFIG_INVALID")
			os.Exit(2)
		}
		if err := recoverCodexCodeModeDelegation(ctx, *path, flags, diagnostics); err != nil {
			diagnostics.Emit(diagnosticlog.LevelError, diagnosticlog.EventRecoveryFailed, diagnosticlog.Fields{Operation: "code_mode", Reason: "recovery_failed"})
			diagnostics.Close()
			fmt.Fprintln(os.Stderr, "HARNESS_RECOVERY_FAILED")
			os.Exit(1)
		}
		diagnostics.Emit(diagnosticlog.LevelInfo, diagnosticlog.EventRecoveryComplete, diagnosticlog.Fields{Operation: "code_mode"})
		fmt.Fprintln(os.Stdout, "HARNESS_RECOVERY_COMPLETED")
		return
	}
	if !flags.empty() {
		fmt.Fprintln(os.Stderr, "HARNESS_CONFIG_INVALID")
		os.Exit(2)
	}
	if err := serve(ctx, *path, diagnostics); err != nil {
		// Provider errors and configuration can contain credentials or prompts.
		diagnostics.Emit(diagnosticlog.LevelError, diagnosticlog.EventServiceFailed, diagnosticlog.Fields{Reason: "start_or_serve_failed"})
		diagnostics.Close()
		fmt.Fprintln(os.Stderr, "HARNESS_START_OR_SERVE_FAILED")
		os.Exit(1)
	}
}

func boolCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

func (flags approvalRaceFlags) empty() bool {
	return flags == (approvalRaceFlags{})
}

func (flags approvalRaceFlags) proof(nodeID string) runtime.CompletedApprovalRaceProof {
	return runtime.CompletedApprovalRaceProof{
		Attempt: harnessadapter.AttemptRef{
			NodeID: nodeID, DialogID: flags.dialogID, RequestID: flags.requestID,
			AttemptID: flags.attemptID, Generation: flags.generation,
		},
		ExpectedAttemptVersion: flags.expectedAttemptVersion,
		ApprovalID:             flags.approvalID, ExpectedApprovalVersion: flags.expectedApprovalVersion,
		Decision: flags.decision,
		CallID:   flags.callID, ExpectedToolVersion: flags.expectedToolVersion,
		ActionHash: flags.actionHash, CommandID: flags.commandID,
		AssistantMessageID: flags.assistantMessageID,
	}
}

func (flags approvalRaceFlags) deltaOverflowProof(nodeID string) runtime.CodexDeltaOverflowProof {
	return runtime.CodexDeltaOverflowProof{
		Attempt: harnessadapter.AttemptRef{
			NodeID: nodeID, DialogID: flags.dialogID, RequestID: flags.requestID,
			AttemptID: flags.attemptID, Generation: flags.generation,
		},
		ExpectedAttemptVersion: flags.expectedAttemptVersion,
		ExpectedUnknownSeq:     flags.expectedUnknownSeq,
		ExpectedDeltaCount:     flags.expectedDeltaCount,
		CallID:                 flags.callID,
		ExpectedToolVersion:    flags.expectedToolVersion,
		ActionHash:             flags.actionHash,
	}
}

func (flags approvalRaceFlags) codeModeDelegationProof(nodeID string) runtime.CodexCodeModeDelegationProof {
	return runtime.CodexCodeModeDelegationProof{
		Attempt: harnessadapter.AttemptRef{
			NodeID: nodeID, DialogID: flags.dialogID, RequestID: flags.requestID,
			AttemptID: flags.attemptID, Generation: flags.generation,
		},
		ExpectedAttemptVersion: flags.expectedAttemptVersion,
		ExpectedUnknownSeq:     flags.expectedUnknownSeq,
		ExpectedDeltaCount:     flags.expectedDeltaCount,
		AssistantMessageID:     flags.assistantMessageID,
	}
}

func boundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) > limit {
		return nil, errors.New("file exceeds limit")
	}
	return content, nil
}

func loadConfig(path string) (config, error) {
	raw, err := boundedFile(path, 64<<10)
	if err != nil {
		return config{}, err
	}
	var cfg config
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return config{}, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return config{}, errors.New("multiple configuration values")
	}
	return cfg, nil
}

func serve(ctx context.Context, path string, diagnostics diagnosticlog.Sink) error {
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	diagnostics.SetNodeID(cfg.NodeID)
	if err := validateProviderSelection(cfg); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil || net.ParseIP(host) == nil || port == "" {
		return errors.New("explicit listen IP and port required")
	}
	certificate, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.KeyFile)
	if err != nil {
		return err
	}
	adapterKind := selectedAdapter(cfg)
	policies := filePolicy{contentPath: cfg.PolicyFile, manifestPath: cfg.ToolManifestFile, revision: cfg.PolicyRevision, approvalMode: cfg.ApprovalMode, adapter: adapterKind}
	policy, err := policies.Current(ctx, cfg.NodeID)
	if err != nil {
		return err
	}
	artifacts := runtime.NewArtifactIngress()
	adapter, err := openProviderAdapter(ctx, cfg, artifacts, policy, diagnostics)
	if err != nil {
		return err
	}
	defer adapter.Close()
	authority, err := runtime.Open(ctx, runtime.Config{
		DataDir: cfg.DataDir, NodeID: cfg.NodeID, OwnerID: cfg.OwnerID,
		RegistryVersion: cfg.RegistryVersion, Adapter: adapter, Policies: policies, Artifacts: artifacts,
		ProviderAuth:             adapter,
		Logger:                   diagnostics,
		ManualDispatchForTesting: cfg.ManualDispatchForTesting,
	})
	if err != nil {
		return err
	}
	defer authority.Close()
	settings, err := nodesettings.Open(cfg.DataDir, cfg.NodeID, adapter)
	if err != nil {
		return err
	}
	handler, err := harnessserver.New(harnessserver.Config{NodeID: cfg.NodeID, Logger: diagnostics, NodeSettings: settings}, authority)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: cfg.Listen, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		// SSE outlives individual HTTP commands and can span long agent runs.
		WriteTimeout: 0, ErrorLog: log.New(io.Discard, "", 0),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}},
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if server.Shutdown(shutdown) != nil {
				_ = server.Close()
			}
		case <-done:
		}
	}()
	fmt.Fprintln(os.Stdout, "HARNESS_STARTING")
	diagnostics.Emit(diagnosticlog.LevelInfo, diagnosticlog.EventServiceStarting, diagnosticlog.Fields{NodeID: cfg.NodeID})
	err = server.ListenAndServeTLS("", "")
	if errors.Is(err, http.ErrServerClosed) {
		diagnostics.Emit(diagnosticlog.LevelInfo, diagnosticlog.EventServiceStopped, diagnosticlog.Fields{NodeID: cfg.NodeID})
		return nil
	}
	return err
}

func recoverCompletedApprovalRace(ctx context.Context, path string, flags approvalRaceFlags, diagnostics diagnosticlog.Sink) error {
	cfg, err := loadConfig(path)
	if err != nil || selectedAdapter(cfg) != string(harnessadapter.KindCodex) || cfg.Codex == nil {
		return errors.New("Codex recovery configuration is invalid")
	}
	diagnostics.SetNodeID(cfg.NodeID)
	diagnostics.Emit(diagnosticlog.LevelInfo, diagnosticlog.EventRecoveryStarted, diagnosticlog.Fields{Operation: "approval_race"})
	policies := filePolicy{
		contentPath: cfg.PolicyFile, manifestPath: cfg.ToolManifestFile,
		revision: cfg.PolicyRevision, approvalMode: cfg.ApprovalMode,
		adapter: string(harnessadapter.KindCodex),
	}
	policy, err := policies.Current(ctx, cfg.NodeID)
	if err != nil {
		return err
	}
	artifacts := runtime.NewArtifactIngress()
	adapter, err := openProviderAdapter(ctx, cfg, artifacts, policy, diagnostics)
	if err != nil {
		return err
	}
	defer adapter.Close()
	authority, err := runtime.Open(ctx, runtime.Config{
		DataDir: cfg.DataDir, NodeID: cfg.NodeID, OwnerID: cfg.OwnerID,
		RegistryVersion: cfg.RegistryVersion, Adapter: adapter, Policies: policies,
		Artifacts: artifacts, ManualDispatchForTesting: true,
		Logger: diagnostics,
	})
	if err != nil {
		return err
	}
	defer authority.Close()
	return authority.RecoverCompletedApprovalRace(ctx, flags.proof(cfg.NodeID))
}

func recoverCodexDeltaOverflow(ctx context.Context, path string, flags approvalRaceFlags, diagnostics diagnosticlog.Sink) error {
	cfg, err := loadConfig(path)
	if err != nil || selectedAdapter(cfg) != string(harnessadapter.KindCodex) || cfg.Codex == nil {
		return errors.New("Codex recovery configuration is invalid")
	}
	diagnostics.SetNodeID(cfg.NodeID)
	diagnostics.Emit(diagnosticlog.LevelInfo, diagnosticlog.EventRecoveryStarted, diagnosticlog.Fields{Operation: "delta_overflow"})
	policies := filePolicy{
		contentPath: cfg.PolicyFile, manifestPath: cfg.ToolManifestFile,
		revision: cfg.PolicyRevision, approvalMode: cfg.ApprovalMode,
		adapter: string(harnessadapter.KindCodex),
	}
	policy, err := policies.Current(ctx, cfg.NodeID)
	if err != nil {
		return err
	}
	artifacts := runtime.NewArtifactIngress()
	adapter, err := openProviderAdapter(ctx, cfg, artifacts, policy, diagnostics)
	if err != nil {
		return err
	}
	defer adapter.Close()
	authority, err := runtime.Open(ctx, runtime.Config{
		DataDir: cfg.DataDir, NodeID: cfg.NodeID, OwnerID: cfg.OwnerID,
		RegistryVersion: cfg.RegistryVersion, Adapter: adapter, Policies: policies,
		Artifacts: artifacts, ManualDispatchForTesting: true,
		Logger: diagnostics,
	})
	if err != nil {
		return err
	}
	defer authority.Close()
	return authority.RecoverCodexDeltaOverflow(ctx, flags.deltaOverflowProof(cfg.NodeID))
}

func recoverCodexCodeModeDelegation(ctx context.Context, path string, flags approvalRaceFlags, diagnostics diagnosticlog.Sink) error {
	cfg, err := loadConfig(path)
	if err != nil || selectedAdapter(cfg) != string(harnessadapter.KindCodex) || cfg.Codex == nil {
		return errors.New("Codex recovery configuration is invalid")
	}
	diagnostics.SetNodeID(cfg.NodeID)
	diagnostics.Emit(diagnosticlog.LevelInfo, diagnosticlog.EventRecoveryStarted, diagnosticlog.Fields{Operation: "code_mode"})
	policies := filePolicy{
		contentPath: cfg.PolicyFile, manifestPath: cfg.ToolManifestFile,
		revision: cfg.PolicyRevision, approvalMode: cfg.ApprovalMode,
		adapter: string(harnessadapter.KindCodex),
	}
	policy, err := policies.Current(ctx, cfg.NodeID)
	if err != nil {
		return err
	}
	artifacts := runtime.NewArtifactIngress()
	adapter, err := openProviderAdapter(ctx, cfg, artifacts, policy, diagnostics)
	if err != nil {
		return err
	}
	defer adapter.Close()
	authority, err := runtime.Open(ctx, runtime.Config{
		DataDir: cfg.DataDir, NodeID: cfg.NodeID, OwnerID: cfg.OwnerID,
		RegistryVersion: cfg.RegistryVersion, Adapter: adapter, Policies: policies,
		Artifacts: artifacts, ManualDispatchForTesting: true,
		Logger: diagnostics,
	})
	if err != nil {
		return err
	}
	defer authority.Close()
	return authority.RecoverCodexCodeModeDelegation(ctx, flags.codeModeDelegationProof(cfg.NodeID))
}

func recoverCodexUnsupportedModel(ctx context.Context, path string, proof runtime.CodexUnsupportedModelProof, check bool, diagnostics diagnosticlog.Sink) error {
	cfg, err := loadConfig(path)
	if err != nil || selectedAdapter(cfg) != string(harnessadapter.KindCodex) || cfg.Codex == nil {
		return errors.New("Codex recovery configuration is invalid")
	}
	proof.Attempt.NodeID = cfg.NodeID
	diagnostics.SetNodeID(cfg.NodeID)
	adapter, err := codex.NewUnsupportedModelRecoveryAdapter(cfg.Codex.StateDir, cfg.Codex.CodexHome, cfg.Codex.Model)
	if err != nil {
		return err
	}
	authority, err := runtime.OpenForRecovery(ctx, runtime.Config{
		DataDir: cfg.DataDir, NodeID: cfg.NodeID, OwnerID: cfg.OwnerID,
		RegistryVersion: cfg.RegistryVersion, Adapter: adapter, Logger: diagnostics,
	})
	if err != nil {
		return err
	}
	defer authority.Close()
	return authority.RecoverCodexUnsupportedModel(ctx, proof, check)
}

func openProviderAdapter(ctx context.Context, cfg config, artifacts runtime.ArtifactSink, policy harnessadapter.PolicySnapshot, diagnostics diagnosticlog.Sink) (providerAdapter, error) {
	if selectedAdapter(cfg) != string(harnessadapter.KindCodex) || cfg.Codex == nil ||
		!filepath.IsAbs(cfg.Codex.HomeDir) || !filepath.IsAbs(cfg.Codex.CodexHome) ||
		strings.ContainsAny(cfg.Codex.HomeDir+cfg.Codex.CodexHome, "\x00\r\n") {
		return nil, errors.New("exactly one Codex adapter config is required")
	}
	var runner toolrunner.Runner
	if policy.ApprovalMode == harnessadapter.ApprovalModeExplicitOnce {
		if err := validateExplicitToolWorkspace("Codex", cfg.Codex.WorkingDir); err != nil {
			return nil, err
		}
		var err error
		runner, err = newToolRunner(ctx)
		if err != nil {
			return nil, err
		}
	}
	return codex.New(codex.Config{
		NodeID:     cfg.NodeID,
		Executable: cfg.Codex.Executable, Environment: []string{
			"HOME=" + cfg.Codex.HomeDir,
			"CODEX_HOME=" + cfg.Codex.CodexHome,
			"PATH=/opt/codex/node_modules/.bin:/usr/local/bin:/usr/bin:/bin",
			"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		},
		StateDir: cfg.Codex.StateDir, WorkingDir: cfg.Codex.WorkingDir,
		Model: cfg.Codex.Model, Effort: cfg.Codex.Effort,
		OperationTimeout: 30 * time.Second, MaxFrameBytes: 8 << 20, Runner: runner,
		Logger: diagnostics,
	}, artifacts)
}

func validateExplicitToolWorkspace(adapter, workingDir string) error {
	if workingDir != "/workspace" {
		return fmt.Errorf("%s explicit tool workspace is invalid", adapter)
	}
	return nil
}

func newToolRunner(ctx context.Context) (toolrunner.Runner, error) {
	return toolrunner.NewHelper(ctx, toolrunner.Config{
		Executable: toolRunnerExecutable,
		SystemReadRoots: []string{
			"/usr", "/etc/ld.so.cache", "/etc/ssl/certs", "/dev/null", "/dev/urandom",
		},
	})
}

func selectedAdapter(cfg config) string {
	return cfg.Adapter
}

func validateProviderSelection(cfg config) error {
	if selectedAdapter(cfg) != string(harnessadapter.KindCodex) || cfg.Codex == nil {
		return errors.New("exactly one Codex adapter config is required")
	}
	if cfg.ManualDispatchForTesting &&
		(cfg.PolicyRevision != "hl304-fixture@1" || effectiveApprovalMode(cfg.ApprovalMode) != harnessadapter.ApprovalModeDeny || cfg.Codex.Model != "fixture-no-provider-call") {
		return errors.New("manual dispatch is restricted to the HL-304 no-provider fixture")
	}
	return nil
}

func effectiveApprovalMode(mode string) string {
	if mode == "" {
		return harnessadapter.ApprovalModeDeny
	}
	return mode
}

type filePolicy struct {
	contentPath, manifestPath, revision string
	approvalMode                        string
	adapter                             string
}

func (source filePolicy) Current(ctx context.Context, _ string) (harnessadapter.PolicySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return harnessadapter.PolicySnapshot{}, err
	}
	content, err := boundedFile(source.contentPath, 64<<10)
	if err != nil {
		return harnessadapter.PolicySnapshot{}, err
	}
	manifest, err := boundedFile(source.manifestPath, 64<<10)
	if err != nil {
		return harnessadapter.PolicySnapshot{}, err
	}
	approvalMode := source.approvalMode
	if approvalMode == "" {
		approvalMode = harnessadapter.ApprovalModeDeny
	}
	switch approvalMode {
	case harnessadapter.ApprovalModeDeny:
		var tools []json.RawMessage
		if json.Unmarshal(manifest, &tools) != nil || tools == nil || len(tools) != 0 {
			return harnessadapter.PolicySnapshot{}, errors.New("deny policy requires an empty tool manifest")
		}
	case harnessadapter.ApprovalModeExplicitOnce:
		if source.adapter != string(harnessadapter.KindCodex) || !bytes.Equal(manifest, []byte(codexExplicitToolManifest)) {
			return harnessadapter.PolicySnapshot{}, errors.New("explicit_once policy requires the exact adapter tool manifest")
		}
	default:
		return harnessadapter.PolicySnapshot{}, errors.New("approval mode is invalid")
	}
	contentHash, manifestHash := sha256.Sum256(content), sha256.Sum256(manifest)
	policy := harnessadapter.PolicySnapshot{
		Revision: source.revision, Content: content, ToolManifest: manifest,
		ContentHash: hex.EncodeToString(contentHash[:]), ToolManifestHash: hex.EncodeToString(manifestHash[:]),
		ApprovalMode: approvalMode,
	}
	policy.EffectiveHash = harnessadapter.EffectivePolicyHash(policy)
	return harnessadapter.PreparePolicySnapshot(policy)
}
