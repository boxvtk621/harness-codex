//go:build linux

package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	hp "github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

var physicalDiskFull = flag.Bool("hl252-physical-disk-full", false, "allow bounded ENOSPC injection inside an isolated Linux tmpfs")

func TestPhysicalFullDiskPreservesAdmissionAndStopReserve(t *testing.T) {
	if !*physicalDiskFull {
		t.Skip("requires an explicitly selected disposable Linux tmpfs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dir := t.TempDir()
	var fs syscall.Statfs_t
	if err := syscall.Statfs(dir, &fs); err != nil {
		t.Fatal(err)
	}
	// Never fill a normal host volume or an unbounded RAM filesystem. The
	// container runner must allocate its own isolated 32 MiB tmpfs mount.
	const tmpfsMagic = 0x01021994
	capacity := uint64(fs.Blocks) * uint64(fs.Bsize)
	if uint64(fs.Type) != tmpfsMagic || capacity < 24<<20 || capacity > 64<<20 {
		t.Fatalf("refuse disk fill: filesystem type=%x capacity=%d", fs.Type, capacity)
	}
	adapter := &queuedAdapter{fixture.NewAdapter()}
	cancelCalled := make(chan struct{}, 1)
	adapter.CancelCalled = cancelCalled
	cfg := config(dir)
	cfg.Adapter = adapter
	cfg.Policies = fixture.NewPolicySource()
	n, err := node.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if n != nil {
			if err := n.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	created := receipt(t, n.SubmitCommand(ctx, trusted(), createCommand()), 202, createCommand())
	var dialog hp.DialogCreateReferences
	if err := json.Unmarshal(created.References, &dialog); err != nil {
		t.Fatal(err)
	}
	first := messageCommand(t, "10000000-0000-4000-8000-000000003000", dialog.DialogID, "synthetic active input", 1)
	receipt(t, n.SubmitCommand(ctx, trusted(), first), 202, first)
	dispatched, err := n.DispatchNext(ctx)
	if err != nil || dispatched.Outcome != "dispatching" {
		t.Fatal(dispatched, err)
	}
	running := waitRunning(t, ctx, n, dispatched.AttemptID)
	queued := messageCommand(t, "10000000-0000-4000-8000-000000003001", dialog.DialogID, "synthetic pending input", 2)
	receipt(t, n.SubmitCommand(ctx, trusted(), queued), 202, queued)
	before := readAdmissionProjection(t, ctx, dir)
	reservePath := filepath.Join(dir, ".control.reserve")
	reserve, err := os.Lstat(reservePath)
	if err != nil {
		t.Fatal(err)
	}
	allocated := reserve.Sys().(*syscall.Stat_t).Blocks * 512
	if !reserve.Mode().IsRegular() || reserve.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || reserve.Size() != 8<<20 || allocated < 8<<20 {
		t.Fatal("stop reserve is not physically backed by8MiB")
	}
	fillerPath := filepath.Join(dir, "test-owned-enospc-filler")
	filler, err := os.OpenFile(fillerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer filler.Close()
	block := make([]byte, 1<<20)
	filled := int64(0)
	hitFull := false
	for filled < 64<<20 {
		if err := ctx.Err(); err != nil {
			t.Fatal(err)
		}
		wrote, err := filler.Write(block)
		filled += int64(wrote)
		if err != nil {
			if !errors.Is(err, syscall.ENOSPC) {
				t.Fatal(err)
			}
			hitFull = true
			break
		}
	}
	if !hitFull {
		t.Fatal("bounded fill did not reach physical ENOSPC")
	}
	if err := filler.Close(); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Statfs(dir, &fs); err != nil {
		t.Fatal(err)
	}
	if fs.Bavail != 0 {
		t.Fatal("filesystem still has available blocks after fill")
	}
	// EnoughSpace bypasses the estimated admission floor only in this test;
	// the actual SQLite journal/COMMIT must still fail without a false receipt.
	rejected := messageCommand(t, "10000000-0000-4000-8000-000000003002", dialog.DialogID, "must not persist on full disk", 3)
	fault(t, n.SubmitCommand(ctx, trusted(), rejected), 503, "not_durable")
	if !reflect.DeepEqual(before, readAdmissionProjection(t, ctx, dir)) {
		t.Fatal("ENOSPC admission partially committed domain/receipt/events")
	}
	stop, err := json.Marshal(map[string]any{"protocolVersion": 1, "schemaId": hp.SchemaID, "commandId": "10000000-0000-4000-8000-000000003003", "kind": "attempt.stop", "target": map[string]string{"nodeId": integrationNode, "attemptId": dispatched.AttemptID}, "expected": map[string]int64{"attemptGeneration": running.ActiveAttempt.Generation}, "payload": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	receipt(t, n.SubmitCommand(ctx, trusted(), stop), 202, stop)
	select {
	case <-cancelCalled:
	case <-ctx.Done():
		t.Fatal("full-disk stop did not reach the adapter", ctx.Err())
	}
	paused := queueSnapshot(t, ctx, n)
	if !paused.Node.QueuePaused || paused.ActiveAttempt == nil || paused.ActiveAttempt.AttemptID != dispatched.AttemptID || paused.ActiveAttempt.State != "stopping" || paused.Node.PendingCount != 1 {
		t.Fatal("full-disk stop lost pause/attempt/queue or invented terminal")
	}
	cancelCount := 0
	for _, call := range adapter.CallsSnapshot() {
		if call.Method == "cancel" {
			cancelCount++
			if call.Attempt.AttemptID != dispatched.AttemptID || call.Attempt.Generation != running.ActiveAttempt.Generation {
				t.Fatal("cancel targets wrong attempt/generation")
			}
		}
	}
	if cancelCount != 1 {
		t.Fatalf("stop invoked %d native cancels", cancelCount)
	}
	remainingReserve, statErr := os.Lstat(reservePath)
	if statErr == nil {
		if !remainingReserve.Mode().IsRegular() || remainingReserve.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			t.Fatal("remaining reserve file is unsafe")
		}
		if remainingReserve.Sys().(*syscall.Stat_t).Blocks*512 >= allocated {
			t.Fatal("physical stop reserve was not released")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal(statErr)
	}
	// Reclaim only the filler created by this test, then restore the same node
	// volume. Startup must not resend the previous execution/control.
	if err := os.Remove(fillerPath); err != nil {
		t.Fatal(err)
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	n = nil
	callsBefore := len(adapter.CallsSnapshot())
	n, err = node.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	recovered := queueSnapshot(t, ctx, n)
	if !recovered.Node.QueuePaused || recovered.Node.PendingCount != 1 || recovered.ActiveAttempt == nil || recovered.ActiveAttempt.AttemptID != dispatched.AttemptID || recovered.ActiveAttempt.State != "unknown" {
		t.Fatal("reopen did not preserve manual pause and unknown active execution")
	}
	if len(adapter.CallsSnapshot()) != callsBefore {
		t.Fatal("reopen blindly resent native start/control")
	}
	if next, err := n.DispatchNext(ctx); err != nil || next.AttemptID != "" {
		t.Fatal("unknown/paused node dispatched", next, err)
	}
	closeErr := n.Close()
	n = nil
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	t.Logf("actual ENOSPC reached after %d bytes on %d-byte isolated tmpfs; stop reserve remained durable", filled, capacity)
}
