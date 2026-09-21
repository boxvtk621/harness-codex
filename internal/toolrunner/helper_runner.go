package toolrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	Executable      string
	SystemReadRoots []string
	MaxOutputBytes  int
	MaxRuntime      time.Duration
}

type helperRunner struct {
	config       Config
	gateMu       sync.Mutex
	workspaceRun map[string]*workspaceRunGate
	runSlots     chan struct{}
}

type workspaceRunGate struct {
	slot chan struct{}
	refs int
}

const maximumConcurrentRuns = 8

func NewHelper(ctx context.Context, config Config) (Runner, error) {
	if !filepath.IsAbs(config.Executable) || filepath.Clean(config.Executable) != config.Executable {
		return nil, errors.New("tool runner executable is invalid")
	}
	if err := validateHelperExecutable(config.Executable); err != nil {
		return nil, err
	}
	if config.MaxOutputBytes == 0 {
		config.MaxOutputBytes = DefaultMaximumOutput
	}
	if config.MaxRuntime == 0 {
		config.MaxRuntime = MaximumRuntime
	}
	if config.MaxOutputBytes < 1024 || config.MaxOutputBytes > DefaultMaximumOutput || config.MaxRuntime <= 0 || config.MaxRuntime > MaximumRuntime || len(config.SystemReadRoots) == 0 || len(config.SystemReadRoots) > 32 {
		return nil, errors.New("tool runner configuration is invalid")
	}
	canonicalRoots := make([]string, 0, len(config.SystemReadRoots))
	seen := make(map[string]struct{}, len(config.SystemReadRoots))
	for _, root := range config.SystemReadRoots {
		canonical, err := validateSystemReadRoot(root)
		if err != nil {
			return nil, errors.New("tool runner configuration is invalid")
		}
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		canonicalRoots = append(canonicalRoots, canonical)
	}
	config.SystemReadRoots = canonicalRoots
	runner := &helperRunner{config: config, workspaceRun: make(map[string]*workspaceRunGate), runSlots: make(chan struct{}, maximumConcurrentRuns)}
	if err := runner.SelfTest(ctx); err != nil {
		return nil, err
	}
	return runner, nil
}

func (runner *helperRunner) SelfTest(ctx context.Context) error {
	root, err := os.MkdirTemp("", "harness-tool-runner-self-test-")
	if err != nil {
		return errors.New("tool runner self-test is unavailable")
	}
	defer os.RemoveAll(root)
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		return errors.New("tool runner self-test is unavailable")
	}
	response, err := runner.invoke(ctx, "self-test", Request{CallID: "self-test", Workspace: workspace, Kind: KindCommand, Command: &CommandRequest{Command: ":", CWD: ".", Access: AccessWrite, Timeout: time.Second}})
	if err != nil || !response.Success {
		return errors.New("tool runner self-test failed")
	}
	return nil
}

func (runner *helperRunner) Run(ctx context.Context, request Request) (Result, error) {
	if err := ValidateRequest(request); err != nil {
		return Result{}, err
	}
	if err := validateWorkspaceForRun(request.Workspace, runner.config.SystemReadRoots); err != nil {
		return Result{}, err
	}
	if request.Command != nil && request.Command.Timeout > runner.config.MaxRuntime {
		return Result{}, errors.New("tool runner request exceeds runtime limit")
	}
	runCtx := ctx
	cancel := func() {}
	if request.Command != nil {
		runCtx, cancel = context.WithTimeout(ctx, request.Command.Timeout)
	}
	defer cancel()
	gate, err := runner.acquireWorkspace(runCtx, request.Workspace)
	if err != nil {
		return Result{}, err
	}
	defer runner.releaseWorkspace(request.Workspace, gate)
	if err := runCtx.Err(); err != nil {
		return Result{}, err
	}
	runner.gateMu.Lock()
	if runner.runSlots == nil {
		runner.runSlots = make(chan struct{}, maximumConcurrentRuns)
	}
	slots := runner.runSlots
	runner.gateMu.Unlock()
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-runCtx.Done():
		return Result{}, runCtx.Err()
	}
	response, err := runner.invoke(runCtx, "run", request)
	if err != nil {
		return Result{}, err
	}
	return Result{Success: response.Success, Output: response.Output, Truncated: response.Truncated, ExitCode: response.ExitCode, Changes: response.Changes}, nil
}

func (runner *helperRunner) acquireWorkspace(ctx context.Context, workspace string) (*workspaceRunGate, error) {
	runner.gateMu.Lock()
	if runner.workspaceRun == nil {
		runner.workspaceRun = make(map[string]*workspaceRunGate)
	}
	gate := runner.workspaceRun[workspace]
	if gate == nil {
		gate = &workspaceRunGate{slot: make(chan struct{}, 1)}
		runner.workspaceRun[workspace] = gate
	}
	gate.refs++
	runner.gateMu.Unlock()
	select {
	case gate.slot <- struct{}{}:
		return gate, nil
	case <-ctx.Done():
		runner.dropWorkspaceRef(workspace, gate)
		return nil, ctx.Err()
	}
}

func (runner *helperRunner) releaseWorkspace(workspace string, gate *workspaceRunGate) {
	<-gate.slot
	runner.dropWorkspaceRef(workspace, gate)
}

func (runner *helperRunner) dropWorkspaceRef(workspace string, gate *workspaceRunGate) {
	runner.gateMu.Lock()
	gate.refs--
	if gate.refs == 0 && runner.workspaceRun[workspace] == gate {
		delete(runner.workspaceRun, workspace)
	}
	runner.gateMu.Unlock()
}

func validateSystemReadRoot(root string) (string, error) {
	if !validWorkspace(root) {
		return "", errors.New("tool runner system root is invalid")
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil || !filepath.IsAbs(canonical) || filepath.Clean(canonical) != canonical || canonical == string(filepath.Separator) || pathIsReserved(canonical) {
		return "", errors.New("tool runner system root is invalid")
	}
	info, err := os.Stat(canonical)
	if err != nil || (!info.IsDir() && !info.Mode().IsRegular() && info.Mode()&os.ModeDevice == 0) {
		return "", errors.New("tool runner system root is invalid")
	}
	if !trustedRootOwner(info) || (info.Mode()&os.ModeDevice == 0 && info.Mode().Perm()&0o022 != 0) {
		return "", errors.New("tool runner system root is untrusted")
	}
	return canonical, nil
}

func validateWorkspaceForRun(workspace string, systemRoots []string) error {
	canonical, err := filepath.EvalSymlinks(workspace)
	if err != nil || canonical != workspace || canonical == string(filepath.Separator) || pathIsReserved(canonical) {
		return errors.New("tool runner workspace is invalid")
	}
	for _, root := range systemRoots {
		if pathsOverlap(canonical, root) {
			return errors.New("tool runner workspace is invalid")
		}
	}
	return nil
}

func pathIsReserved(path string) bool {
	for _, reserved := range []string{"/auth", "/config", "/state", "/proc"} {
		if path == reserved || strings.HasPrefix(path, reserved+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func pathsOverlap(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+string(filepath.Separator)) || strings.HasPrefix(right, left+string(filepath.Separator))
}

func (runner *helperRunner) invoke(ctx context.Context, mode string, request Request) (helperResponse, error) {
	if err := ctx.Err(); err != nil {
		return helperResponse{}, err
	}
	envelope := helperEnvelope{ProtocolVersion: helperProtocolVersion, Mode: mode, Request: toWireRequest(request), SystemReadRoots: append([]string(nil), runner.config.SystemReadRoots...), MaximumOutput: runner.config.MaxOutputBytes}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return helperResponse{}, errors.New("tool runner request encoding failed")
	}
	command := exec.Command(runner.config.Executable, "--serve")
	command.Stdin = bytes.NewReader(encoded)
	output := &limitedBuffer{maximum: runner.config.MaxOutputBytes*2 + 64<<10}
	command.Stdout = output
	command.Stderr = io.Discard
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return helperResponse{}, errors.New("tool runner helper failed to start")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		// A shell may exit successfully after starting detached descendants. Kill
		// the complete helper process group even on the normal path so nothing can
		// outlive a single approved call.
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if err != nil {
			return helperResponse{}, errors.New("tool runner helper failed")
		}
	case <-ctx.Done():
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		<-done
		return helperResponse{}, ctx.Err()
	}
	if output.overflow {
		return helperResponse{}, errors.New("tool runner helper response exceeded limit")
	}
	var response helperResponse
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	if decoder.Decode(&response) != nil || decoder.Decode(new(any)) != io.EOF || response.ProtocolVersion != helperProtocolVersion || response.Failure != "" || len(response.Output) > runner.config.MaxOutputBytes {
		return helperResponse{}, errors.New("tool runner helper response is invalid")
	}
	return response, nil
}

type limitedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
	maximum  int
	overflow bool
}

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	original := len(value)
	remaining := buffer.maximum - buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return original, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		buffer.overflow = true
	}
	_, _ = buffer.Buffer.Write(value)
	return original, nil
}
