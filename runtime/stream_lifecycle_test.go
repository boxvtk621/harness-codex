package node_test

import (
	"context"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/runtime"
)

func TestHostTerminalReleasesStreamLeaseAndWakesScheduler(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	streamInput := make(chan harnessadapter.Event, 1)
	adapter := fixture.NewAdapter()
	adapter.StreamInput = streamInput
	config := testConfig(t.TempDir())
	config.ManualDispatchForTesting = false
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()

	firstDialog := createDialog(t, ctx, opened, "37000000-0000-4000-8000-000000000001")
	firstMessage := enqueue(t, ctx, opened, "37000000-0000-4000-8000-000000000002", firstDialog, "first", 1)
	var first harnessadapter.AttemptRef
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		if active == nil || active.RequestID != firstMessage.RequestID || active.State != "running" {
			return false
		}
		first = harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: active.DialogID, RequestID: active.RequestID, AttemptID: active.AttemptID, Generation: active.Generation}
		return true
	})
	secondDialog := createDialog(t, ctx, opened, "37000000-0000-4000-8000-000000000003")
	secondMessage := enqueue(t, ctx, opened, "37000000-0000-4000-8000-000000000004", secondDialog, "second", 1)

	if err := opened.Observe(ctx, node.Observation{AttemptID: first.AttemptID, Generation: first.Generation, Kind: "terminal", TerminalState: "completed", EffectStatus: "none", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	var second harnessadapter.AttemptRef
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		if active == nil || active.RequestID != secondMessage.RequestID || active.State != "running" {
			return false
		}
		second = harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: active.DialogID, RequestID: active.RequestID, AttemptID: active.AttemptID, Generation: active.Generation}
		return true
	})

	invalidTerminal := harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: second}, Outcome: harnessadapter.ReconcileCompleted}
	if err := opened.ObserveAdapterEvent(ctx, second, invalidTerminal); err == nil {
		t.Fatal("invalid terminal unexpectedly committed")
	}
	if err := opened.Observe(ctx, node.Observation{AttemptID: first.AttemptID, Generation: first.Generation, Kind: "terminal", TerminalState: "completed", EffectStatus: "none", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	streamInput <- harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: second}, Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "none"}
	waitFor(t, func() bool { return currentSnapshot(t, ctx, opened).ActiveAttempt == nil })
}

func TestReconciledTerminalReleasesUnknownStreamLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	streamInput := make(chan harnessadapter.Event)
	base := fixture.NewAdapter()
	base.StreamInput = streamInput
	adapter := &reconcileAdapter{Adapter: base, result: harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "none"}}
	config := testConfig(t.TempDir())
	config.ManualDispatchForTesting = false
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()

	firstDialog := createDialog(t, ctx, opened, "38000000-0000-4000-8000-000000000001")
	firstMessage := enqueue(t, ctx, opened, "38000000-0000-4000-8000-000000000002", firstDialog, "first", 1)
	var first harnessadapter.AttemptRef
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		if active == nil || active.RequestID != firstMessage.RequestID || active.State != "running" {
			return false
		}
		first = harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: active.DialogID, RequestID: active.RequestID, AttemptID: active.AttemptID, Generation: active.Generation}
		return true
	})
	secondDialog := createDialog(t, ctx, opened, "38000000-0000-4000-8000-000000000003")
	secondMessage := enqueue(t, ctx, opened, "38000000-0000-4000-8000-000000000004", secondDialog, "second", 1)
	if err := opened.Observe(ctx, node.Observation{AttemptID: first.AttemptID, Generation: first.Generation, Kind: "unknown", Reason: "provider_state", EffectStatus: "none"}); err != nil {
		t.Fatal(err)
	}
	stillObserved := make(chan struct{})
	go func() {
		streamInput <- harnessadapter.WaitingEvent{EventBase: harnessadapter.EventBase{Attempt: first}, Kind: "input"}
		close(stillObserved)
	}()
	select {
	case <-stillObserved:
	case <-ctx.Done():
		t.Fatal("unknown attempt closed its live event stream")
	}

	if _, err := opened.ReconcileUnknown(ctx, first); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.RequestID == secondMessage.RequestID && active.State == "running"
	})
}
