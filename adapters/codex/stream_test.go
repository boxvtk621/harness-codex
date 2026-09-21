package codex

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

func TestAttemptRuntimeActivationFencesEarlyNativeEvents(t *testing.T) {
	reference := codexTestReference(1)
	runtime := newAttemptRuntime(reference)
	content := harnessprotocol.SafeContent{Kind: "inline", Content: "answer", Redaction: "none"}
	runtime.push(harnessadapter.AssistantMessageEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference},
		MessageID: "50000000-0000-4000-8000-000000000002", Content: content, FinishReason: "complete",
	})
	runtime.finish(harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileCompleted, Output: &content, EffectStatus: "known"},
		harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, Outcome: harnessadapter.ReconcileCompleted, Output: &content, EffectStatus: "known"})
	runtime.activate()
	stream, err := runtime.claim()
	if err != nil {
		t.Fatal(err)
	}
	first, err := stream.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := first.(harnessadapter.StartedEvent); !ok {
		t.Fatalf("first event = %T; native event escaped before durable activation", first)
	}
	second, err := stream.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := second.(harnessadapter.AssistantMessageEvent); !ok {
		t.Fatalf("second event = %T", second)
	}
	third, err := stream.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if terminal, ok := third.(harnessadapter.TerminalEvent); !ok || terminal.Outcome != harnessadapter.ReconcileCompleted {
		t.Fatalf("terminal event = %#v", third)
	}
	if _, err := stream.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("stream end = %v", err)
	}
	if result := runtime.reconcile(); result.Outcome != harnessadapter.ReconcileCompleted {
		t.Fatalf("reconcile = %#v", result)
	}
}

func TestAttemptRuntimeIsSingleConsumerAndCloseIsLocal(t *testing.T) {
	runtime := newAttemptRuntime(codexTestReference(1))
	runtime.activate()
	stream, err := runtime.claim()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.claim(); err == nil {
		t.Fatal("second event consumer was accepted")
	}
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("closed stream = %v", err)
	}
	if result := runtime.reconcile(); result.Outcome != harnessadapter.ReconcileRunning {
		t.Fatalf("closing consumer changed provider state: %#v", result)
	}
}

func TestAttemptRuntimeOverflowBecomesUnknown(t *testing.T) {
	runtime := newAttemptRuntime(codexTestReference(1))
	runtime.activate()
	for index := 0; index <= maximumQueuedEvents; index++ {
		runtime.push(harnessadapter.WaitingEvent{EventBase: harnessadapter.EventBase{Attempt: runtime.reference}, Kind: "fixture"})
	}
	if result := runtime.reconcile(); result.Outcome != harnessadapter.ReconcileUnknown || result.EffectStatus != "unknown" {
		t.Fatalf("overflow reconcile = %#v", result)
	}
	stream, err := runtime.claim()
	if err != nil {
		t.Fatal(err)
	}
	event, err := stream.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if unknown, ok := event.(harnessadapter.UnknownEvent); !ok || unknown.Reason != "adapter_protocol" {
		t.Fatalf("overflow event = %#v", event)
	}
	if _, err := stream.Next(context.Background()); err == nil || err.Error() != "codex event queue limit exceeded" {
		t.Fatalf("overflow stream error = %v", err)
	}
}

func TestAttemptRuntimeCoalescesFineGrainedAssistantDeltas(t *testing.T) {
	runtime := newAttemptRuntime(codexTestReference(1))
	runtime.activate()
	messageID := "50000000-0000-4000-8000-000000000002"
	for index := 0; index <= maximumQueuedEvents; index++ {
		runtime.push(harnessadapter.AssistantDeltaEvent{
			EventBase: harnessadapter.EventBase{Attempt: runtime.reference},
			MessageID: messageID,
			Content:   harnessprotocol.SafeContent{Kind: "inline", Content: "x", Redaction: "none"},
		})
	}
	if result := runtime.reconcile(); result.Outcome != harnessadapter.ReconcileRunning {
		t.Fatalf("coalesced delta reconcile = %#v", result)
	}
	stream, err := runtime.claim()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	event, err := stream.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	delta, ok := event.(harnessadapter.AssistantDeltaEvent)
	if !ok || delta.DeltaIndex != 0 || len(delta.Content.Content) != maximumQueuedEvents+1 {
		t.Fatalf("coalesced delta = %#v", event)
	}
}

func TestAttemptRuntimePreservesCoalescedDeltaIndexAcrossActivation(t *testing.T) {
	runtime := newAttemptRuntime(codexTestReference(1))
	messageID := "50000000-0000-4000-8000-000000000002"
	for _, content := range []string{"a", "b"} {
		runtime.push(harnessadapter.AssistantDeltaEvent{
			EventBase: harnessadapter.EventBase{Attempt: runtime.reference},
			MessageID: messageID,
			Content:   harnessprotocol.SafeContent{Kind: "inline", Content: content, Redaction: "none"},
		})
	}
	runtime.activate()
	stream, err := runtime.claim()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	event, err := stream.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	delta, ok := event.(harnessadapter.AssistantDeltaEvent)
	if !ok || delta.DeltaIndex != 0 || delta.Content.Content != "ab" {
		t.Fatalf("activated delta = %#v", event)
	}
}

func TestAttemptRuntimeRejectsCrossGenerationEvent(t *testing.T) {
	runtime := newAttemptRuntime(codexTestReference(1))
	runtime.activate()
	runtime.push(harnessadapter.WaitingEvent{EventBase: harnessadapter.EventBase{Attempt: codexTestReference(2)}, Kind: "fixture"})
	if result := runtime.reconcile(); result.Outcome != harnessadapter.ReconcileUnknown {
		t.Fatalf("cross-generation reconcile = %#v", result)
	}
	stream, err := runtime.claim()
	if err != nil {
		t.Fatal(err)
	}
	event, err := stream.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if unknown, ok := event.(harnessadapter.UnknownEvent); !ok || unknown.Attempt != runtime.reference {
		t.Fatalf("cross-generation event = %#v", event)
	}
}

func TestAttemptRuntimeNextHonorsContext(t *testing.T) {
	runtime := newAttemptRuntime(codexTestReference(1))
	runtime.activate()
	stream, err := runtime.claim()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := stream.Next(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Next context error = %v", err)
	}
}
