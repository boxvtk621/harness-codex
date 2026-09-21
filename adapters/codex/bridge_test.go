package codex

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const helperEnvironment = "CODEX_BRIDGE_HELPER=1"

func TestBridgeRoutesCallsNotificationsAndServerRequests(t *testing.T) {
	requests := make(chan rpcServerRequest, 1)
	notices := make(chan rpcNotification, 1)
	exits := atomic.Int64{}
	bridge, err := startBridge(helperBridgeConfig(t), func(notice rpcNotification) {
		notices <- notice
	}, func(request rpcServerRequest) {
		requests <- request
	}, func() {
		exits.Add(1)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()

	var result struct {
		Version string `json:"version"`
	}
	if err := bridge.call(context.Background(), "initialize", map[string]any{"clientInfo": map[string]string{"name": "Harness", "version": "1"}}, &result); err != nil {
		t.Fatal(err)
	}
	if result.Version != "0.153.4" {
		t.Fatalf("version = %q", result.Version)
	}
	if err := bridge.notify("initialized", map[string]any{}); err != nil {
		t.Fatal(err)
	}

	select {
	case notice := <-notices:
		if notice.Method != "turn/started" || string(notice.Params) != `{"turn":{"id":"turn-1"}}` {
			t.Fatalf("notification = %#v", notice)
		}
	case <-time.After(time.Second):
		t.Fatal("notification was not routed")
	}

	select {
	case request := <-requests:
		if request.Method != "item/commandExecution/requestApproval" || request.ID.key != "s:approval-1" {
			t.Fatalf("server request = %#v", request)
		}
		if err := bridge.respond(request.ID, map[string]string{"decision": "decline"}); err != nil {
			t.Fatal(err)
		}
		if err := bridge.respond(request.ID, map[string]string{"decision": "decline"}); err == nil {
			t.Fatal("duplicate response was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("server request was not routed")
	}

	var acknowledged struct {
		Decision string `json:"decision"`
	}
	if err := bridge.call(context.Background(), "fixture/approvalResponse", map[string]any{}, &acknowledged); err != nil {
		t.Fatal(err)
	}
	if acknowledged.Decision != "decline" {
		t.Fatalf("approval response = %#v", acknowledged)
	}
	if exits.Load() != 0 {
		t.Fatal("bridge exited before close")
	}
}

func TestBridgeTimeoutDoesNotResend(t *testing.T) {
	bridge, err := startBridge(helperBridgeConfig(t), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := bridge.call(ctx, "fixture/ignore", map[string]any{}, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ignored call error = %v", err)
	}
	var count struct {
		Requests int `json:"requests"`
	}
	if err := bridge.call(context.Background(), "fixture/count", map[string]any{}, &count); err != nil {
		t.Fatal(err)
	}
	if count.Requests != 2 {
		t.Fatalf("request count = %d; timed-out request was unexpectedly retried", count.Requests)
	}
}

func TestBridgeCallAfterWriteRunsHookAfterFrameBeforeResponseWrite(t *testing.T) {
	writer := &observedWriteCloser{}
	instance := &bridge{
		stdin: writer, maximum: 64 * 1024,
		pending: make(map[string]chan rpcResponse), inbound: make(map[string]rpcID),
		done: make(chan struct{}),
	}
	hookCalled := atomic.Bool{}
	err := instance.callAfterWrite(context.Background(), "turn/interrupt", map[string]string{"threadId": "thread-1", "turnId": "turn-1"}, &struct{}{}, func() {
		if !writer.written.Load() {
			t.Error("interrupt hook ran before request frame write")
		}
		hookCalled.Store(true)
		instance.mu.Lock()
		response := instance.pending["n:1"]
		delete(instance.pending, "n:1")
		instance.mu.Unlock()
		response <- rpcResponse{result: json.RawMessage(`{}`)}
	})
	if err != nil || !hookCalled.Load() {
		t.Fatalf("callAfterWrite err=%v hook=%v", err, hookCalled.Load())
	}
}

type observedWriteCloser struct{ written atomic.Bool }

func (writer *observedWriteCloser) Write(value []byte) (int, error) {
	writer.written.Store(true)
	return len(value), nil
}

func (*observedWriteCloser) Close() error { return nil }

var _ io.WriteCloser = (*observedWriteCloser)(nil)

func TestBridgeProtocolFailureClosesPendingCalls(t *testing.T) {
	bridge, err := startBridge(helperBridgeConfig(t), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	if err := bridge.call(context.Background(), "fixture/malformed", map[string]any{}, nil); err == nil || err.Error() != "codex app-server emitted an invalid frame" {
		t.Fatalf("malformed frame error = %v", err)
	}
	if err := bridge.call(context.Background(), "fixture/count", map[string]any{}, nil); err == nil {
		t.Fatal("call after protocol failure succeeded")
	}
}

func TestBridgeInitializesPinnedLocalAppServer(t *testing.T) {
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
	bridge, err := startBridge(bridgeConfig{
		Executable: executable,
		Arguments:  []string{"app-server", "--listen", "stdio://"},
		Environment: []string{
			"CODEX_HOME=" + codexHome,
			"HOME=" + home,
			"PATH=" + os.Getenv("PATH"),
		},
		WorkingDir:    home,
		MaxFrameBytes: 1024 * 1024,
	}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var initialized struct {
		UserAgent string `json:"userAgent"`
	}
	if err := bridge.call(ctx, "initialize", map[string]any{
		"clientInfo": map[string]string{"name": "homelab-harness-test", "title": "Harness test", "version": "1"},
	}, &initialized); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(initialized.UserAgent, "0.153.4") {
		t.Fatalf("unexpected app-server user agent %q", initialized.UserAgent)
	}
	if err := bridge.notify("initialized", map[string]any{}); err != nil {
		t.Fatal(err)
	}
}

func TestParseRPCIDAcceptsOnlyBoundedStringsAndIntegers(t *testing.T) {
	valid := map[string]string{`"request-1"`: "s:request-1", `42`: "n:42", `-1`: "n:-1"}
	for encoded, key := range valid {
		id, err := parseRPCID(json.RawMessage(encoded))
		if err != nil || id.key != key {
			t.Fatalf("parseRPCID(%s) = %#v, %v", encoded, id, err)
		}
	}
	for _, encoded := range []string{"", `null`, `true`, `1.5`, `{}`, `[]`, `""`} {
		if id, err := parseRPCID(json.RawMessage(encoded)); err == nil {
			t.Fatalf("parseRPCID(%s) accepted %#v", encoded, id)
		}
	}
}

func helperBridgeConfig(t *testing.T) bridgeConfig {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return bridgeConfig{
		Executable:    executable,
		Arguments:     []string{"-test.run=^TestCodexBridgeHelperProcess$"},
		Environment:   []string{helperEnvironment},
		MaxFrameBytes: 64 * 1024,
	}
}

func TestCodexBridgeHelperProcess(t *testing.T) {
	if os.Getenv("CODEX_BRIDGE_HELPER") != "1" {
		return
	}
	os.Exit(runBridgeHelper())
}

func runBridgeHelper() int {
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	requests := 0
	approvalDecision := ""
	for scanner.Scan() {
		var frame rpcFrame
		if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil {
			return 2
		}
		if frame.Method == "" && len(frame.ID) > 0 {
			var response struct {
				Decision string `json:"decision"`
			}
			if err := json.Unmarshal(frame.Result, &response); err != nil {
				return 3
			}
			approvalDecision = response.Decision
			continue
		}
		if len(frame.ID) == 0 {
			if frame.Method != "initialized" {
				return 4
			}
			_ = encoder.Encode(map[string]any{"method": "turn/started", "params": map[string]any{"turn": map[string]string{"id": "turn-1"}}})
			_ = encoder.Encode(map[string]any{"id": "approval-1", "method": "item/commandExecution/requestApproval", "params": map[string]string{"threadId": "thread-1", "turnId": "turn-1", "itemId": "item-1"}})
			continue
		}
		requests++
		switch frame.Method {
		case "initialize":
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]string{"version": "0.153.4"}})
		case "fixture/ignore":
			continue
		case "fixture/count":
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]int{"requests": requests}})
		case "fixture/approvalResponse":
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]string{"decision": approvalDecision}})
		case "fixture/malformed":
			_, _ = fmt.Fprintln(os.Stdout, "{broken")
		default:
			_ = encoder.Encode(map[string]any{"id": frame.ID, "error": map[string]any{"code": -32601, "message": "unknown"}})
		}
	}
	return 0
}
