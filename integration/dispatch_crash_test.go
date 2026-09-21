package integration_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	hp "github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

var dispatchCrashHelper = flag.Bool("hl252-dispatch-crash-helper", false, "run the isolated dispatch crash helper")

type dispatchCrashAdapter struct {
	*fixture.Adapter
	marker string
}

func (adapter *dispatchCrashAdapter) Start(ctx context.Context, input harnessadapter.StartInput) (harnessadapter.StartResult, error) {
	if err := os.WriteFile(adapter.marker, []byte("fixture start invoked"), 0o600); err != nil {
		return harnessadapter.StartResult{}, err
	}
	return adapter.Adapter.Start(ctx, input)
}

func (adapter *dispatchCrashAdapter) Resume(ctx context.Context, input harnessadapter.ResumeInput) (harnessadapter.ResumeResult, error) {
	if err := os.WriteFile(adapter.marker, []byte("fixture resume invoked"), 0o600); err != nil {
		return harnessadapter.ResumeResult{}, err
	}
	return adapter.Adapter.Resume(ctx, input)
}

func TestDispatchCrashChild(t *testing.T) {
	if !*dispatchCrashHelper {
		t.Skip("subprocess helper")
	}
	dir := os.Getenv("HL252_DISPATCH_CRASH_DIR")
	if dir == "" {
		t.Fatal("missing isolated fixture directory")
	}
	cfg := config(dir)
	cfg.Policies = fixture.NewPolicySource()
	cfg.Adapter = &dispatchCrashAdapter{Adapter: fixture.NewAdapter(), marker: filepath.Join(dir, "native-called")}
	n, err := node.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	n.SetFaultInjector(func(point node.FaultPoint) error {
		if point == node.FaultAfterDispatchIntent {
			if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	})
	_, err = n.DispatchNext(context.Background())
	t.Fatalf("dispatch crash boundary was not reached: %v", err)
}

func TestRealCrashAfterDispatchIntentRetainsUnknownFence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dir := t.TempDir()
	cfg := config(dir)
	cfg.Policies = fixture.NewPolicySource()
	n, err := node.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := n.Close(); err != nil {
			t.Error(err)
		}
	})
	created := receipt(t, n.SubmitCommand(ctx, trusted(), createCommand()), 202, createCommand())
	var dialog hp.DialogCreateReferences
	if err := json.Unmarshal(created.References, &dialog); err != nil {
		t.Fatal(err)
	}
	enqueue := func(id, text string, version int64) hp.MessageEnqueueReferences {
		t.Helper()
		command := messageCommand(t, id, dialog.DialogID, text, version)
		r := receipt(t, n.SubmitCommand(ctx, trusted(), command), 202, command)
		var refs hp.MessageEnqueueReferences
		if err := json.Unmarshal(r.References, &refs); err != nil {
			t.Fatal(err)
		}
		return refs
	}
	first := enqueue("10000000-0000-4000-8000-000000005001", "first", 1)
	second := enqueue("10000000-0000-4000-8000-000000005002", "second", 2)
	initial := queueSnapshot(t, ctx, n)
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	accepted := readAdmissionProjection(t, ctx, dir).Commands
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDispatchCrashChild$", "-test.timeout=6s", "-hl252-dispatch-crash-helper=true")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "HL252_DISPATCH_CRASH_DIR=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "HL252_DISPATCH_CRASH_DIR="+dir)
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exit) {
		t.Fatalf("helper did not crash at dispatch boundary: %v %s", err, output)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("helper was not SIGKILLed: %v %s", err, output)
	}
	assertNoNativeCall := func() {
		t.Helper()
		if _, err := os.Stat(filepath.Join(dir, "native-called")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("native Start crossed the crash or recovery fence: %v", err)
		}
	}
	assertNoNativeCall()
	uri := &url.URL{Scheme: "file", Path: filepath.Join(dir, "harness.db"), RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var attemptID, requestID, attemptState, actionState string
	var generation int64
	if err := db.QueryRowContext(ctx, `SELECT a.attempt_id,a.request_id,a.generation,a.state,c.status
		FROM attempts a JOIN control_actions c ON c.attempt_id=a.attempt_id WHERE c.kind='dispatch.start'`).Scan(&attemptID, &requestID, &generation, &attemptState, &actionState); err != nil {
		t.Fatal(err)
	}
	if requestID != first.RequestID || generation != 1 || attemptState != "dispatching" || actionState != "pending" {
		t.Fatalf("committed dispatch intent missing before recovery: request=%s generation=%d attempt=%s action=%s", requestID, generation, attemptState, actionState)
	}
	if !reflect.DeepEqual(accepted, readAdmissionProjection(t, ctx, dir).Commands) {
		t.Fatal("dispatch crash changed accepted receipts")
	}
	// Exercise production-default startup scheduling on the recovered volume.
	cfg.ManualDispatchForTesting = false
	cfg.Adapter = &dispatchCrashAdapter{Adapter: fixture.NewAdapter(), marker: filepath.Join(dir, "native-called")}
	reopened, err := node.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertFence := func() {
		t.Helper()
		snapshot := queueSnapshot(t, ctx, reopened)
		if snapshot.Epoch != initial.Epoch || snapshot.Node.QueuePaused || snapshot.ActiveAttempt == nil ||
			snapshot.ActiveAttempt.AttemptID != attemptID || snapshot.ActiveAttempt.Generation != 1 || snapshot.ActiveAttempt.State != "unknown" ||
			len(snapshot.PendingQueue) != 1 || snapshot.PendingQueue[0].RequestID != second.RequestID {
			t.Fatalf("recovered fence or FIFO changed: %+v", snapshot)
		}
	}
	assertFence()
	if result := reopened.HealthReady(ctx, trusted()); result.HTTPStatus != 200 {
		t.Fatalf("health read failed: %d", result.HTTPStatus)
	}
	if result, err := reopened.DispatchNext(ctx); err != nil || result.Outcome != "idle" {
		t.Fatalf("unknown attempt permitted dispatch: %+v %v", result, err)
	}
	assertFence()
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoNativeCall() // Close joins workers before this final assertion.
	var attempts int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempts").Scan(&attempts); err != nil || attempts != 1 {
		t.Fatalf("recovery created another attempt: count=%d err=%v", attempts, err)
	}
}
