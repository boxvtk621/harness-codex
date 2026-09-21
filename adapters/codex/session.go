package codex

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"
)

const maximumVersionOutputBytes = 256

type sessionHandlers struct {
	Notification func(rpcNotification)
	Request      func(rpcServerRequest)
	Exit         func()
	Ready        func(*nativeSession)
}

// nativeSession owns one exact Codex app-server process generation. It only
// establishes the native protocol session; provider turns and policy mapping
// remain the responsibility of the adapter built on top of it.
type nativeSession struct {
	bridge     *bridge
	handlers   sessionHandlers
	generation int64
	done       chan struct{}
	doneOnce   sync.Once
	closeOnce  sync.Once

	mu      sync.Mutex
	ready   bool
	closing bool
	exited  bool
}

func startNativeSession(ctx context.Context, config bridgeConfig, store *mappingStore, handlers sessionHandlers) (*nativeSession, error) {
	if store == nil {
		return nil, errors.New("codex native mapping store is required")
	}
	expectedCodexHome, ok := exactEnvironmentPath(config.Environment, "CODEX_HOME")
	if !ok {
		return nil, errors.New("dedicated codex home is required")
	}
	if err := verifyCodexExecutable(ctx, config); err != nil {
		return nil, err
	}
	session := &nativeSession{handlers: handlers, done: make(chan struct{})}
	instance, err := startBridge(config, session.handleNotification, session.handleRequest, session.handleExit)
	if err != nil {
		return nil, err
	}
	session.mu.Lock()
	session.bridge = instance
	session.mu.Unlock()
	fail := func(cause error) (*nativeSession, error) {
		session.mu.Lock()
		session.closing = true
		session.ready = false
		session.mu.Unlock()
		_ = instance.Close()
		return nil, cause
	}

	var initialized initializeResponse
	if err := instance.call(ctx, "initialize", initializeParams{
		ClientInfo:   initializeClientInfo{Name: codexClientName, Title: codexClientTitle, Version: codexClientVersion},
		Capabilities: initializeCapabilities{ExperimentalAPI: true},
	}, &initialized); err != nil {
		return fail(fmtSessionError("initialize codex app-server", err))
	}
	if err := validateInitializeResponse(initialized, expectedCodexHome); err != nil {
		return fail(err)
	}
	if err := instance.notify("initialized", struct{}{}); err != nil {
		return fail(fmtSessionError("complete codex app-server initialization", err))
	}
	select {
	case <-instance.done:
		instance.mu.Lock()
		failure := instance.failureLocked()
		instance.mu.Unlock()
		return fail(fmtSessionError("complete codex app-server initialization", failure))
	default:
	}
	generation, err := store.beginProcess()
	if err != nil {
		return fail(fmtSessionError("persist codex process generation", err))
	}
	session.mu.Lock()
	if session.exited {
		session.mu.Unlock()
		return fail(errors.New("codex app-server exited during initialization"))
	}
	session.generation = generation
	if session.handlers.Ready != nil {
		session.handlers.Ready(session)
	}
	session.ready = true
	session.mu.Unlock()
	return session, nil
}

func verifyCodexExecutable(ctx context.Context, config bridgeConfig) error {
	if ctx == nil {
		return errors.New("codex app-server context is required")
	}
	arguments := config.VersionArguments
	if len(arguments) == 0 {
		arguments = []string{"--version"}
	}
	command := exec.CommandContext(ctx, config.Executable, arguments...)
	command.Env = append([]string(nil), config.Environment...)
	command.Dir = config.WorkingDir
	output := &boundedOutput{maximum: maximumVersionOutputBytes}
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return fmtSessionError("read codex executable version", err)
	}
	if err := parseCodexVersion(output.Bytes()); err != nil {
		return err
	}
	return nil
}

func parseCodexVersion(output []byte) error {
	if len(output) == 0 || len(output) > maximumVersionOutputBytes || !utf8.Valid(output) {
		return errors.New("codex executable version is invalid")
	}
	line := string(output)
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if line != "codex-cli "+codexAppServerVersion {
		return errors.New("codex executable version mismatch")
	}
	return nil
}

func validateInitializeResponse(response initializeResponse, expectedCodexHome string) error {
	prefix := codexClientName + "/" + codexAppServerVersion + " "
	if !boundedSessionText(response.UserAgent, 4096) || !strings.HasPrefix(response.UserAgent, prefix) ||
		len(response.UserAgent) == len(prefix) || response.UserAgent[len(prefix)] != '(' {
		return errors.New("codex app-server user agent version mismatch")
	}
	if !filepath.IsAbs(response.CodexHome) || !boundedSessionText(response.CodexHome, 4096) || !sameFilesystemPath(response.CodexHome, expectedCodexHome) ||
		!boundedSessionText(response.PlatformFamily, 64) || !boundedSessionText(response.PlatformOS, 64) {
		return errors.New("codex app-server initialize response is invalid")
	}
	return nil
}

func sameFilesystemPath(first, second string) bool {
	if filepath.Clean(first) == filepath.Clean(second) {
		return true
	}
	canonicalFirst, firstErr := filepath.EvalSymlinks(first)
	canonicalSecond, secondErr := filepath.EvalSymlinks(second)
	return firstErr == nil && secondErr == nil && canonicalFirst == canonicalSecond
}

func exactEnvironmentPath(environment []string, wanted string) (string, bool) {
	var value string
	found := false
	for _, entry := range environment {
		name, candidate, ok := strings.Cut(entry, "=")
		if !ok || name != wanted {
			continue
		}
		if found || !filepath.IsAbs(candidate) || !boundedSessionText(candidate, 4096) {
			return "", false
		}
		value, found = candidate, true
	}
	return value, found
}

func boundedSessionText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func fmtSessionError(operation string, err error) error {
	return fmt.Errorf("%s: %w", operation, err)
}

func (session *nativeSession) Call(ctx context.Context, method string, params, result any) error {
	instance, ok := session.availableBridge()
	if !ok {
		return errBridgeClosed
	}
	return instance.call(ctx, method, params, result)
}

func (session *nativeSession) CallAfterWrite(ctx context.Context, method string, params, result any, afterWrite func()) error {
	instance, ok := session.availableBridge()
	if !ok {
		return errBridgeClosed
	}
	return instance.callAfterWrite(ctx, method, params, result, afterWrite)
}

func (session *nativeSession) Respond(id rpcID, result any) error {
	instance, ok := session.availableBridge()
	if !ok {
		return errBridgeClosed
	}
	return instance.respond(id, result)
}

func (session *nativeSession) Reject(id rpcID, code int64) error {
	instance, ok := session.availableBridge()
	if !ok {
		return errBridgeClosed
	}
	return instance.reject(id, code)
}

func (session *nativeSession) ResolveInbound(id rpcID) bool {
	instance, ok := session.availableBridge()
	return ok && instance.resolveInbound(id)
}

func (session *nativeSession) ProcessGeneration() int64 {
	return session.generation
}

func (session *nativeSession) Done() <-chan struct{} {
	return session.done
}

func (session *nativeSession) Close() error {
	session.closeOnce.Do(func() {
		session.mu.Lock()
		alreadyExited := session.exited
		session.closing = true
		session.ready = false
		instance := session.bridge
		session.doneOnce.Do(func() { close(session.done) })
		session.mu.Unlock()
		if instance != nil && !alreadyExited {
			instance.stop()
		}
	})
	return nil
}

// Wait blocks until the app-server child has been reaped. It is intentionally
// separate from Close because callbacks run on the bridge reader goroutine and
// must be able to request a non-blocking close without deadlocking Cmd.Wait.
func (session *nativeSession) Wait() error {
	session.mu.Lock()
	instance := session.bridge
	session.mu.Unlock()
	if instance == nil {
		return nil
	}
	return <-instance.wait
}

func (session *nativeSession) availableBridge() (*bridge, bool) {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.bridge, session.bridge != nil && session.ready && !session.closing && !session.exited
}

func (session *nativeSession) beginCallback() bool {
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.ready || session.closing || session.exited {
		return false
	}
	return true
}

func (session *nativeSession) handleNotification(notification rpcNotification) {
	if !session.beginCallback() {
		return
	}
	if session.handlers.Notification != nil {
		session.handlers.Notification(notification)
	}
}

func (session *nativeSession) handleRequest(request rpcServerRequest) {
	if !session.beginCallback() {
		session.mu.Lock()
		instance := session.bridge
		session.mu.Unlock()
		if instance != nil {
			_ = instance.reject(request.ID, -32601)
		}
		return
	}
	if session.handlers.Request != nil {
		session.handlers.Request(request)
		return
	}
	session.mu.Lock()
	instance := session.bridge
	session.mu.Unlock()
	if instance != nil {
		_ = instance.reject(request.ID, -32601)
	}
}

func (session *nativeSession) handleExit() {
	session.mu.Lock()
	publish := session.ready && !session.closing && !session.exited && session.handlers.Exit != nil
	session.ready = false
	session.exited = true
	session.doneOnce.Do(func() { close(session.done) })
	session.mu.Unlock()
	if publish {
		session.handlers.Exit()
	}
}

type boundedOutput struct {
	buffer  bytes.Buffer
	maximum int
}

func (output *boundedOutput) Write(chunk []byte) (int, error) {
	if output.buffer.Len()+len(chunk) > output.maximum {
		return 0, errors.New("codex executable version output exceeds limit")
	}
	return output.buffer.Write(chunk)
}

func (output *boundedOutput) Bytes() []byte {
	return output.buffer.Bytes()
}
