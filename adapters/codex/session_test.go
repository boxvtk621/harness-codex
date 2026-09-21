package codex

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	sessionHelperEnvironment = "CODEX_SESSION_HELPER=1"
	versionHelperEnvironment = "CODEX_VERSION_HELPER=1"
)

func TestParseCodexVersionRequiresExactPin(t *testing.T) {
	for _, output := range [][]byte{
		[]byte("codex-cli " + codexAppServerVersion),
		[]byte("codex-cli " + codexAppServerVersion + "\n"),
		[]byte("codex-cli " + codexAppServerVersion + "\r\n"),
	} {
		if err := parseCodexVersion(output); err != nil {
			t.Fatalf("valid version %q: %v", output, err)
		}
	}
	for _, output := range [][]byte{
		nil,
		[]byte("codex-cli 0.153.3\n"),
		[]byte("codex-cli 0.153.40\n"),
		[]byte("prefix codex-cli " + codexAppServerVersion + "\n"),
		[]byte("codex-cli " + codexAppServerVersion + " suffix\n"),
		[]byte("codex-cli " + codexAppServerVersion + "\nextra\n"),
		{0xff},
	} {
		if err := parseCodexVersion(output); err == nil {
			t.Fatalf("invalid version %q was accepted", output)
		}
	}
}

func TestNativeSessionInitializesAndAdvancesProcessGeneration(t *testing.T) {
	store, err := openMappingStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	exits := atomic.Int64{}
	config := sessionBridgeConfig(t, "success", "codex-cli "+codexAppServerVersion+"\n", validSessionUserAgent())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := startNativeSession(ctx, config, store, sessionHandlers{Exit: func() { exits.Add(1) }})
	if err != nil {
		t.Fatal(err)
	}
	if first.ProcessGeneration() != 1 {
		t.Fatalf("first process generation = %d", first.ProcessGeneration())
	}
	var pong struct {
		Status string `json:"status"`
	}
	if err := first.Call(ctx, "fixture/ping", struct{}{}, &pong); err != nil || pong.Status != "ok" {
		t.Fatalf("ping = %#v, %v", pong, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	select {
	case <-first.Done():
	default:
		t.Fatal("session done signal remained open after close")
	}
	if err := first.Call(ctx, "fixture/ping", struct{}{}, &pong); !errors.Is(err, errBridgeClosed) {
		t.Fatalf("call after close = %v", err)
	}
	if exits.Load() != 0 {
		t.Fatalf("explicit close published %d exit callbacks", exits.Load())
	}

	second, err := startNativeSession(ctx, config, store, sessionHandlers{})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.ProcessGeneration() != 2 {
		t.Fatalf("second process generation = %d", second.ProcessGeneration())
	}
}

func TestNativeSessionRejectsFailedHandshakeWithoutAdvancingGeneration(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		version   string
		userAgent string
	}{
		{name: "executable version mismatch", mode: "success", version: "codex-cli 0.153.3\n", userAgent: validSessionUserAgent()},
		{name: "server version mismatch", mode: "success", version: "codex-cli " + codexAppServerVersion + "\n", userAgent: codexClientName + "/0.153.3 (fixture)"},
		{name: "codex home mismatch", mode: "home-mismatch", version: "codex-cli " + codexAppServerVersion + "\n", userAgent: validSessionUserAgent()},
		{name: "initialize remote error", mode: "remote-error", version: "codex-cli " + codexAppServerVersion + "\n", userAgent: validSessionUserAgent()},
		{name: "invalid initialize response", mode: "invalid-response", version: "codex-cli " + codexAppServerVersion + "\n", userAgent: validSessionUserAgent()},
		{name: "exit before initialize response", mode: "exit-before-response", version: "codex-cli " + codexAppServerVersion + "\n", userAgent: validSessionUserAgent()},
		{name: "exit after initialize response", mode: "exit-after-response", version: "codex-cli " + codexAppServerVersion + "\n", userAgent: validSessionUserAgent()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := openMappingStore(filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if session, err := startNativeSession(ctx, sessionBridgeConfig(t, test.mode, test.version, test.userAgent), store, sessionHandlers{}); err == nil {
				_ = session.Close()
				t.Fatal("failed handshake was accepted")
			}
			if store.contents.ProcessGeneration != 0 {
				t.Fatalf("failed handshake advanced generation to %d", store.contents.ProcessGeneration)
			}
		})
	}
}

func TestNativeSessionClosesProcessWhenGenerationPersistenceFails(t *testing.T) {
	store, err := openMappingStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	store.persist = func(mappingState) error { return errors.New("injected persistence failure") }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if session, err := startNativeSession(ctx, sessionBridgeConfig(t, "success", "codex-cli "+codexAppServerVersion+"\n", validSessionUserAgent()), store, sessionHandlers{}); err == nil {
		_ = session.Close()
		t.Fatal("session started without durable process generation")
	}
	if store.contents.ProcessGeneration != 0 {
		t.Fatalf("failed generation persistence published generation %d", store.contents.ProcessGeneration)
	}
}

func TestNativeSessionRoutesCallbacksOnlyWhileReady(t *testing.T) {
	store, err := openMappingStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	notifications := make(chan rpcNotification, 1)
	requests := make(chan rpcServerRequest, 1)
	var session *nativeSession
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err = startNativeSession(ctx, sessionBridgeConfig(t, "success", "codex-cli "+codexAppServerVersion+"\n", validSessionUserAgent()), store, sessionHandlers{
		Notification: func(notification rpcNotification) { notifications <- notification },
		Request:      func(request rpcServerRequest) { requests <- request },
	})
	if err != nil {
		t.Fatal(err)
	}
	callDone := make(chan error, 1)
	go func() {
		var response struct {
			Status string `json:"status"`
		}
		callDone <- session.Call(ctx, "fixture/events", struct{}{}, &response)
	}()
	select {
	case request := <-requests:
		if request.Method != "item/commandExecution/requestApproval" {
			t.Fatalf("request method = %q", request.Method)
		}
		if err := session.Respond(request.ID, map[string]string{"decision": "decline"}); err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case notification := <-notifications:
		if notification.Method != "turn/started" {
			t.Fatalf("notification method = %q", notification.Method)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := <-callDone; err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeSessionHandlersCanCloseWithoutDeadlock(t *testing.T) {
	for _, test := range []struct {
		name   string
		method string
		kind   string
	}{
		{name: "notification", method: "fixture/notification", kind: "notification"},
		{name: "request", method: "fixture/request", kind: "request"},
		{name: "exit", method: "fixture/exit", kind: "exit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := openMappingStore(filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatal(err)
			}
			called := make(chan struct{})
			var session *nativeSession
			handlers := sessionHandlers{}
			closeFromHandler := func() {
				_ = session.Close()
				close(called)
			}
			switch test.kind {
			case "notification":
				handlers.Notification = func(rpcNotification) { closeFromHandler() }
			case "request":
				handlers.Request = func(rpcServerRequest) { closeFromHandler() }
			case "exit":
				handlers.Exit = closeFromHandler
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			session, err = startNativeSession(ctx, sessionBridgeConfig(t, "success", "codex-cli "+codexAppServerVersion+"\n", validSessionUserAgent()), store, handlers)
			if err != nil {
				t.Fatal(err)
			}
			_ = session.Call(ctx, test.method, struct{}{}, &struct{}{})
			select {
			case <-called:
			case <-ctx.Done():
				t.Fatal("handler self-close deadlocked")
			}
			select {
			case <-session.Done():
			case <-ctx.Done():
				t.Fatal("session remained open after handler self-close")
			}
		})
	}
}

func TestNativeSessionInitializesPinnedLocalAppServer(t *testing.T) {
	executable := os.Getenv("HARNESS_CODEX_BIN")
	if executable == "" {
		var err error
		executable, err = exec.LookPath("codex")
		if err != nil {
			t.Skip("codex is not installed")
		}
	}
	home := t.TempDir()
	codexHome := filepath.Join(home, "codex")
	if err := os.Mkdir(codexHome, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := openMappingStore(filepath.Join(home, "mapping"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := startNativeSession(ctx, bridgeConfig{
		Executable: executable,
		Arguments:  []string{"app-server", "--listen", "stdio://"},
		Environment: []string{
			"CODEX_HOME=" + codexHome,
			"HOME=" + home,
			"PATH=" + os.Getenv("PATH"),
		},
		WorkingDir:    home,
		MaxFrameBytes: 1024 * 1024,
	}, store, sessionHandlers{})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if session.ProcessGeneration() != 1 {
		t.Fatalf("process generation = %d", session.ProcessGeneration())
	}
}

func sessionBridgeConfig(t *testing.T, mode, version, userAgent string) bridgeConfig {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return bridgeConfig{
		Executable:       executable,
		Arguments:        []string{"-test.run=^TestCodexSessionHelperProcess$"},
		VersionArguments: []string{"-test.run=^TestCodexVersionHelperProcess$"},
		Environment: []string{
			sessionHelperEnvironment,
			versionHelperEnvironment,
			"CODEX_SESSION_MODE=" + mode,
			"CODEX_VERSION_OUTPUT=" + version,
			"CODEX_SESSION_USER_AGENT=" + userAgent,
			"HOME=/private/tmp/codex-session-home",
			"CODEX_HOME=/private/tmp/codex-session-fixture",
		},
		MaxFrameBytes: 64 * 1024,
	}
}

func validSessionUserAgent() string {
	return codexClientName + "/" + codexAppServerVersion + " (fixture; test)"
}

func TestCodexVersionHelperProcess(t *testing.T) {
	if os.Getenv("CODEX_VERSION_HELPER") != "1" {
		return
	}
	_, _ = fmt.Fprint(os.Stdout, os.Getenv("CODEX_VERSION_OUTPUT"))
	os.Exit(0)
}

func TestCodexSessionHelperProcess(t *testing.T) {
	if os.Getenv("CODEX_SESSION_HELPER") != "1" {
		return
	}
	os.Exit(runSessionHelper())
}

func runSessionHelper() int {
	mode := os.Getenv("CODEX_SESSION_MODE")
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var frame rpcFrame
		if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil {
			return 2
		}
		if frame.Method == "initialize" {
			var params initializeParams
			if err := json.Unmarshal(frame.Params, &params); err != nil || params.ClientInfo.Name != codexClientName || params.ClientInfo.Title != codexClientTitle || params.ClientInfo.Version != codexClientVersion || !params.Capabilities.ExperimentalAPI {
				return 3
			}
			switch mode {
			case "exit-before-response":
				return 0
			case "remote-error":
				_ = encoder.Encode(map[string]any{"id": frame.ID, "error": map[string]any{"code": -32600, "message": "fixture rejection"}})
				continue
			case "invalid-response":
				_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]string{"userAgent": os.Getenv("CODEX_SESSION_USER_AGENT")}})
				continue
			default:
				codexHome := "/private/tmp/codex-session-fixture"
				if mode == "home-mismatch" {
					codexHome = "/private/tmp/unexpected-codex-home"
				}
				_ = encoder.Encode(map[string]any{"id": frame.ID, "result": initializeResponse{
					UserAgent: os.Getenv("CODEX_SESSION_USER_AGENT"), CodexHome: codexHome,
					PlatformFamily: "unix", PlatformOS: "test",
				}})
				if mode == "exit-after-response" {
					_ = os.Stdin.Close()
					time.Sleep(200 * time.Millisecond)
					return 0
				}
			}
			continue
		}
		if len(frame.ID) == 0 {
			if frame.Method != "initialized" {
				return 4
			}
			continue
		}
		switch frame.Method {
		case "fixture/ping":
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]string{"status": "ok"}})
		case "fixture/events":
			_ = encoder.Encode(map[string]any{"method": "turn/started", "params": map[string]any{"turn": map[string]string{"id": "turn-1"}}})
			_ = encoder.Encode(map[string]any{"id": "approval-1", "method": "item/commandExecution/requestApproval", "params": map[string]string{"threadId": "thread-1", "turnId": "turn-1", "itemId": "item-1"}})
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]string{"status": "ok"}})
		case "fixture/notification":
			_ = encoder.Encode(map[string]any{"method": "turn/started", "params": map[string]any{"turn": map[string]string{"id": "turn-1"}}})
		case "fixture/request":
			_ = encoder.Encode(map[string]any{"id": "approval-self-close", "method": "item/commandExecution/requestApproval", "params": map[string]string{"threadId": "thread-1", "turnId": "turn-1", "itemId": "item-1"}})
		case "fixture/exit":
			return 0
		default:
			if frame.Method == "" && len(frame.ID) > 0 {
				continue
			}
			return 5
		}
	}
	if err := scanner.Err(); err != nil && !strings.Contains(err.Error(), "file already closed") {
		return 6
	}
	return 0
}
