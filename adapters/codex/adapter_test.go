package codex

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/toolrunner"
)

const adapterHelperEnvironment = "CODEX_ADAPTER_HELPER=1"

func TestAdapterStartResumeAndIndependentDialogs(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	first := adapterReference(1, 1, 1)
	second := adapterReference(2, 1, 1)
	assertStartAndTerminal(t, ctx, adapter, first, adapterBoundary(1), "first")
	assertStartAndTerminal(t, ctx, adapter, second, adapterBoundary(2), "second")
	firstDialog, ok := adapter.store.dialog(first.DialogID)
	if !ok {
		t.Fatal("first dialog mapping is missing")
	}
	secondDialog, ok := adapter.store.dialog(second.DialogID)
	if !ok || firstDialog.ThreadID == secondDialog.ThreadID {
		t.Fatalf("dialog mappings are not independent: %#v %#v", firstDialog, secondDialog)
	}

	continued := adapterReference(1, 2, 2)
	result, err := adapter.Resume(ctx, harnessadapter.ResumeInput{
		Attempt: continued, Prompt: "continued", Context: adapterBoundary(3), Policy: adapterPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.ResumeStarted {
		t.Fatalf("resume = %#v, %v", result, err)
	}
	assertTerminalEvents(t, ctx, adapter, continued)
	updated, ok := adapter.store.dialog(first.DialogID)
	if !ok || updated.ThreadID != firstDialog.ThreadID || updated.Boundary.Sequence != 3 {
		t.Fatalf("resumed dialog = %#v", updated)
	}
}

func TestAdapterResumeAcceptsExactRetryBoundaryAndRejectsConflictingReplay(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	boundary := adapterBoundary(1)
	first := adapterReference(1, 1, 1)
	assertStartAndTerminal(t, ctx, adapter, first, boundary, "first")

	retry := adapterReference(1, 2, 2)
	result, err := adapter.Resume(ctx, harnessadapter.ResumeInput{
		Attempt: retry, Prompt: "first", Context: boundary, Policy: adapterPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.ResumeStarted {
		t.Fatalf("exact retry resume = %#v, %v", result, err)
	}
	assertTerminalEvents(t, ctx, adapter, retry)

	conflicting := boundary
	conflicting.MessageID = adapterBoundary(2).MessageID
	rejected, err := adapter.Resume(ctx, harnessadapter.ResumeInput{
		Attempt: adapterReference(1, 3, 3), Prompt: "conflict", Context: conflicting, Policy: adapterPolicy(),
	})
	if err != nil || rejected.Outcome != harnessadapter.ResumeContextMissing {
		t.Fatalf("conflicting retry boundary = %#v, %v", rejected, err)
	}
}

func TestAdapterCreatesDistinctPrivateDialogWorkspaces(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for index := int64(1); index <= 2; index++ {
		reference := adapterReference(index, index, 1)
		result, err := adapter.Start(ctx, harnessadapter.StartInput{
			Attempt: reference, Prompt: fmt.Sprintf("dialog-%d", index), Context: adapterBoundary(index), Policy: adapterToolPolicy(),
		})
		if err != nil || result.Outcome != harnessadapter.StartStarted {
			t.Fatalf("start %d = %#v, %v", index, result, err)
		}
		_ = readAdapterEvents(t, ctx, adapter, reference)
		workspace := filepath.Join(adapter.config.WorkingDir, reference.DialogID)
		info, err := os.Lstat(workspace)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("workspace %d = %#v, %v", index, info, err)
		}
	}
}

func TestAdapterLegacyDenyDoesNotRequireWritableWorkspace(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	if err := os.Chmod(adapter.config.WorkingDir, 0o500); err != nil {
		t.Fatal(err)
	}
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(context.Background(), harnessadapter.StartInput{
		Attempt: reference, Prompt: "legacy-deny", Context: adapterBoundary(1), Policy: adapterPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("legacy deny start = %#v, %v", result, err)
	}
	_ = readAdapterEvents(t, context.Background(), adapter, reference)
}

func TestAdapterSteerAndInterruptUseExactTurnFence(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "hold", Context: adapterBoundary(1), Policy: adapterPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("start = %#v, %v", result, err)
	}
	steer, err := adapter.Steer(ctx, harnessadapter.SteerInput{Attempt: reference, MessageID: adapterBoundary(2).MessageID, Text: "steer"})
	if err != nil || steer.Outcome != harnessadapter.SteerApplied {
		t.Fatalf("steer = %#v, %v", steer, err)
	}
	cancelResult, err := adapter.Cancel(ctx, harnessadapter.CancelInput{Attempt: reference})
	if err != nil || cancelResult.Outcome != harnessadapter.CancelAcknowledged {
		t.Fatalf("cancel = %#v, %v", cancelResult, err)
	}
	if reconciled, err := adapter.Reconcile(ctx, harnessadapter.ReconcileInput{Attempt: reference}); err != nil || reconciled.Outcome != harnessadapter.ReconcileRunning {
		t.Fatalf("interrupt ACK became terminal: %#v, %v", reconciled, err)
	}
	events := readAdapterEvents(t, ctx, adapter, reference)
	terminal, ok := events[len(events)-1].(harnessadapter.TerminalEvent)
	if !ok || terminal.Outcome != harnessadapter.ReconcileInterrupted {
		t.Fatalf("terminal = %#v", events[len(events)-1])
	}
}

func TestAdapterDeduplicatesExactActiveDispatchAndRejectsConflict(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	input := harnessadapter.StartInput{Attempt: reference, Prompt: "hold", Context: adapterBoundary(1), Policy: adapterPolicy()}
	first, err := adapter.Start(ctx, input)
	if err != nil || first.Outcome != harnessadapter.StartStarted {
		t.Fatalf("first start = %#v, %v", first, err)
	}
	duplicate, err := adapter.Start(ctx, input)
	if err != nil || duplicate.Outcome != harnessadapter.StartStarted {
		t.Fatalf("duplicate start = %#v, %v", duplicate, err)
	}
	input.Prompt = "different"
	conflict, err := adapter.Start(ctx, input)
	if err != nil || conflict.Outcome != harnessadapter.StartUnknown || conflict.Failure == nil || conflict.Failure.Class != harnessadapter.FailureProtocol {
		t.Fatalf("conflicting duplicate = %#v, %v", conflict, err)
	}
	if result, err := adapter.Cancel(ctx, harnessadapter.CancelInput{Attempt: reference}); err != nil || result.Outcome != harnessadapter.CancelAcknowledged {
		t.Fatalf("cancel = %#v, %v", result, err)
	}
	_ = readAdapterEvents(t, ctx, adapter, reference)
}

func TestAdapterDeduplicatesExactDispatchWhileApprovalIsPending(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	input := harnessadapter.StartInput{Attempt: reference, Prompt: "command-approval", Context: adapterBoundary(1), Policy: adapterToolPolicy()}
	first, err := adapter.Start(ctx, input)
	if err != nil || first.Outcome != harnessadapter.StartStarted {
		t.Fatalf("first start = %#v, %v", first, err)
	}
	stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	for index := 0; index < 3; index++ {
		if _, err := stream.Next(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if reconciled, err := adapter.Reconcile(ctx, harnessadapter.ReconcileInput{Attempt: reference}); err != nil || reconciled.Outcome != harnessadapter.ReconcileWaitingInput {
		t.Fatalf("pending approval reconcile = %#v, %v", reconciled, err)
	}
	duplicate, err := adapter.Start(ctx, input)
	if err != nil || duplicate.Outcome != harnessadapter.StartStarted {
		t.Fatalf("duplicate start = %#v, %v", duplicate, err)
	}
	if result, err := adapter.Cancel(ctx, harnessadapter.CancelInput{Attempt: reference}); err != nil || result.Outcome != harnessadapter.CancelAcknowledged {
		t.Fatalf("cancel = %#v, %v", result, err)
	}
}

func TestAdapterMapsOneNonSecretInputRequest(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "ask-input", Context: adapterBoundary(1), Policy: adapterPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("start = %#v, %v", result, err)
	}
	stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
	if err != nil {
		t.Fatal(err)
	}
	if event, err := stream.Next(ctx); err != nil {
		t.Fatal(err)
	} else if _, ok := event.(harnessadapter.StartedEvent); !ok {
		t.Fatalf("first event = %T", event)
	}
	event, err := stream.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	requested, ok := event.(harnessadapter.InputRequestedEvent)
	if !ok || requested.Prompt.Content != "Choose one value" {
		t.Fatalf("input request = %#v", event)
	}
	response, err := adapter.RespondInput(ctx, harnessadapter.RespondInputInput{
		Attempt: reference, InputRequestID: requested.InputRequestID, InputVersion: 2, Text: "value",
	})
	if err != nil || response.Outcome != harnessadapter.ResponseApplied {
		t.Fatalf("input response = %#v, %v", response, err)
	}
	var terminal harnessadapter.TerminalEvent
	for {
		event, err = stream.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if value, ok := event.(harnessadapter.TerminalEvent); ok {
			terminal = value
		}
	}
	if terminal.Outcome != harnessadapter.ReconcileCompleted || terminal.Output == nil || terminal.Output.Content != "answer:value" {
		t.Fatalf("terminal = %#v", terminal)
	}
}

func TestAdapterRejectsInputResolvedBeforeClientResponse(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "ask-input-resolved", Context: adapterBoundary(1), Policy: adapterPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("start = %#v, %v", result, err)
	}
	stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Next(ctx); err != nil {
		t.Fatal(err)
	}
	event, err := stream.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	requested, ok := event.(harnessadapter.InputRequestedEvent)
	if !ok {
		t.Fatalf("input request = %#v", event)
	}
	response, err := adapter.RespondInput(ctx, harnessadapter.RespondInputInput{
		Attempt: reference, InputRequestID: requested.InputRequestID, InputVersion: 2, Text: "late",
	})
	if err != nil || response.Outcome != harnessadapter.ResponseRejected {
		t.Fatalf("stale input response = %#v, %v", response, err)
	}
	if cancelResult, err := adapter.Cancel(ctx, harnessadapter.CancelInput{Attempt: reference}); err != nil || cancelResult.Outcome != harnessadapter.CancelAcknowledged {
		t.Fatalf("cancel = %#v, %v", cancelResult, err)
	}
}

func TestAdapterInputLifecycleResolutionWithoutProgressStaysUnknown(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "ask-input-cleanup", Context: adapterBoundary(1), Policy: adapterPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("start = %#v, %v", result, err)
	}
	stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Next(ctx); err != nil {
		t.Fatal(err)
	}
	event, err := stream.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	requested, ok := event.(harnessadapter.InputRequestedEvent)
	if !ok {
		t.Fatalf("input request = %#v", event)
	}
	response, err := adapter.RespondInput(ctx, harnessadapter.RespondInputInput{
		Attempt: reference, InputRequestID: requested.InputRequestID, InputVersion: 2, Text: "value",
	})
	if err != nil || response.Outcome != harnessadapter.ResponseUnknown {
		t.Fatalf("unconfirmed input response = %#v, %v", response, err)
	}
	reconciled, err := adapter.Reconcile(ctx, harnessadapter.ReconcileInput{Attempt: reference})
	if err != nil || reconciled.Outcome != harnessadapter.ReconcileUnknown || reconciled.EffectStatus != "unknown" {
		t.Fatalf("unconfirmed input reconcile = %#v, %v", reconciled, err)
	}
}

func TestAdapterMapsExplicitOnceCommandApprovalAndOutput(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "command-approval", Context: adapterBoundary(1), Policy: adapterToolPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("start = %#v, %v", result, err)
	}
	stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if event, err := stream.Next(ctx); err != nil {
		t.Fatal(err)
	} else if _, ok := event.(harnessadapter.StartedEvent); !ok {
		t.Fatalf("first event = %#v", event)
	}
	startedEvent, err := stream.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	started, ok := startedEvent.(harnessadapter.ToolStartedEvent)
	if !ok || started.ToolName != "codex.command" || started.Input.Redaction != "none" ||
		!strings.Contains(started.Input.Content, "printf fixture") || !validPolicyHash(started.ActionHash) {
		t.Fatalf("tool started = %#v", startedEvent)
	}
	requestedEvent, err := stream.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	requested, ok := requestedEvent.(harnessadapter.ApprovalRequestedEvent)
	if !ok || requested.CallID != started.CallID || requested.ActionHash != started.ActionHash || !strings.Contains(requested.SafePrompt, "printf fixture") {
		t.Fatalf("approval requested = %#v", requestedEvent)
	}
	providerVersion, err := adapter.RespondApproval(ctx, harnessadapter.RespondApprovalInput{
		Attempt: reference, ApprovalID: requested.ApprovalID, ApprovalVersion: 1,
		ActionHash: requested.ActionHash, Decision: "allow_once",
	})
	if err != nil || providerVersion.Outcome != harnessadapter.ResponseRejected {
		t.Fatalf("untranslated provider approval version = %#v, %v", providerVersion, err)
	}
	response, err := adapter.RespondApproval(ctx, harnessadapter.RespondApprovalInput{
		Attempt: reference, ApprovalID: requested.ApprovalID, ApprovalVersion: 2,
		ActionHash: requested.ActionHash, Decision: "allow_once",
	})
	if err != nil || response.Outcome != harnessadapter.ResponseApplied {
		t.Fatalf("approval response = %#v, %v", response, err)
	}
	if calls := adapter.config.Runner.(*fakeToolRunner).requestCount(); calls != 1 {
		t.Fatalf("runner calls = %d, want 1", calls)
	}
	events := drainStream(t, ctx, stream)
	if len(events) != 3 {
		t.Fatalf("remaining events = %#v", events)
	}
	output, ok := events[0].(harnessadapter.ToolOutputEvent)
	if !ok || output.CallID != started.CallID || output.ChunkIndex != 0 || output.Stream != "result" || output.Output.Content != "fixture output\n" {
		t.Fatalf("tool output = %#v", events[0])
	}
	completed, ok := events[1].(harnessadapter.ToolCompletedEvent)
	if !ok || completed.CallID != started.CallID || completed.Status != "succeeded" || completed.EffectStatus != "known" || completed.EffectRef != started.ActionHash {
		t.Fatalf("tool completed = %#v", events[1])
	}
	if terminal, ok := events[2].(harnessadapter.TerminalEvent); !ok || terminal.Outcome != harnessadapter.ReconcileCompleted {
		t.Fatalf("terminal = %#v", events[2])
	}
	duplicate, err := adapter.RespondApproval(ctx, harnessadapter.RespondApprovalInput{
		Attempt: reference, ApprovalID: requested.ApprovalID, ApprovalVersion: 2,
		ActionHash: requested.ActionHash, Decision: "allow_once",
	})
	if err != nil || duplicate.Outcome != harnessadapter.ResponseRejected {
		t.Fatalf("duplicate approval = %#v, %v", duplicate, err)
	}
}

func TestAdapterConfirmsApprovalWhenToolCompletesBeforeRequestResolution(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "command-approval-completed-first", Context: adapterBoundary(1), Policy: adapterToolPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("start = %#v, %v", result, err)
	}
	stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_, _ = stream.Next(ctx)
	startedEvent, _ := stream.Next(ctx)
	started := startedEvent.(harnessadapter.ToolStartedEvent)
	requestedEvent, _ := stream.Next(ctx)
	requested := requestedEvent.(harnessadapter.ApprovalRequestedEvent)
	response, err := adapter.RespondApproval(ctx, harnessadapter.RespondApprovalInput{
		Attempt: reference, ApprovalID: requested.ApprovalID, ApprovalVersion: 2,
		ActionHash: requested.ActionHash, Decision: "allow_once",
	})
	if err != nil || response.Outcome != harnessadapter.ResponseApplied {
		t.Fatalf("approval response = %#v, %v", response, err)
	}
	events := drainStream(t, ctx, stream)
	var completed harnessadapter.ToolCompletedEvent
	var terminal harnessadapter.TerminalEvent
	for _, event := range events {
		switch value := event.(type) {
		case harnessadapter.ToolCompletedEvent:
			completed = value
		case harnessadapter.TerminalEvent:
			terminal = value
		}
	}
	if completed.CallID != started.CallID || completed.Status != "succeeded" || completed.EffectStatus != "known" {
		t.Fatalf("tool completion = %#v", events)
	}
	if terminal.Outcome != harnessadapter.ReconcileCompleted {
		t.Fatalf("terminal = %#v, events=%#v", terminal, events)
	}
}

func TestAdapterConfirmsDeniedApprovalWhenTurnCompletesBeforeRequestResolution(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "command-approval-terminal-first", Context: adapterBoundary(1), Policy: adapterToolPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("start = %#v, %v", result, err)
	}
	stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_, _ = stream.Next(ctx)
	_, _ = stream.Next(ctx)
	requestedEvent, _ := stream.Next(ctx)
	requested := requestedEvent.(harnessadapter.ApprovalRequestedEvent)
	response, err := adapter.RespondApproval(ctx, harnessadapter.RespondApprovalInput{
		Attempt: reference, ApprovalID: requested.ApprovalID, ApprovalVersion: 2,
		ActionHash: requested.ActionHash, Decision: "deny",
	})
	if err != nil || response.Outcome != harnessadapter.ResponseApplied {
		t.Fatalf("approval response = %#v, %v", response, err)
	}
	if calls := adapter.config.Runner.(*fakeToolRunner).requestCount(); calls != 0 {
		t.Fatalf("runner calls = %d, want 0", calls)
	}
	events := drainStream(t, ctx, stream)
	var completed harnessadapter.ToolCompletedEvent
	var terminal harnessadapter.TerminalEvent
	for _, event := range events {
		switch value := event.(type) {
		case harnessadapter.ToolCompletedEvent:
			completed = value
		case harnessadapter.TerminalEvent:
			terminal = value
		}
	}
	if completed.Status != "failed" || completed.EffectStatus != "none" {
		t.Fatalf("tool completion = %#v", events)
	}
	if terminal.Outcome != harnessadapter.ReconcileCompleted {
		t.Fatalf("terminal = %#v, events=%#v", terminal, events)
	}
}

func TestCodexDynamicToolsExplainExternalApprovalTrigger(t *testing.T) {
	tools := codexDynamicTools()
	if len(tools) != 1 || len(tools[0].Tools) != 2 {
		t.Fatalf("dynamic tool descriptions do not explain the Harness approval boundary: %#v", tools)
	}
	for _, tool := range tools[0].Tools {
		description := strings.ToLower(tool.Description)
		if !strings.Contains(description, "call") || !strings.Contains(description, "one-time operator approval") {
			t.Fatalf("%s description does not explain the approval trigger: %q", tool.Name, tool.Description)
		}
	}
	if !strings.Contains(tools[0].Tools[1].Description, "separate from the read-only native Codex sandbox") {
		t.Fatalf("file tool description does not explain the sandbox boundary: %q", tools[0].Tools[1].Description)
	}
}

func TestAdapterRejectsStaleApprovalHashWithoutConsumingRequest(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "command-approval", Context: adapterBoundary(1), Policy: adapterToolPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("start = %#v, %v", result, err)
	}
	stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_, _ = stream.Next(ctx)
	_, _ = stream.Next(ctx)
	requestedEvent, err := stream.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	requested := requestedEvent.(harnessadapter.ApprovalRequestedEvent)
	stale, err := adapter.RespondApproval(ctx, harnessadapter.RespondApprovalInput{
		Attempt: reference, ApprovalID: requested.ApprovalID, ApprovalVersion: 2,
		ActionHash: strings.Repeat("a", 64), Decision: "allow_once",
	})
	if err != nil || stale.Outcome != harnessadapter.ResponseRejected {
		t.Fatalf("stale approval = %#v, %v", stale, err)
	}
	response, err := adapter.RespondApproval(ctx, harnessadapter.RespondApprovalInput{
		Attempt: reference, ApprovalID: requested.ApprovalID, ApprovalVersion: 2,
		ActionHash: requested.ActionHash, Decision: "deny",
	})
	if err != nil || response.Outcome != harnessadapter.ResponseApplied {
		t.Fatalf("deny response = %#v, %v", response, err)
	}
	events := drainStream(t, ctx, stream)
	var completed harnessadapter.ToolCompletedEvent
	for _, event := range events {
		if value, ok := event.(harnessadapter.ToolCompletedEvent); ok {
			completed = value
		}
	}
	if completed.Status != "failed" || completed.EffectStatus != "none" || completed.EffectRef != "" {
		t.Fatalf("declined tool = %#v", events)
	}
	if calls := adapter.config.Runner.(*fakeToolRunner).requestCount(); calls != 0 {
		t.Fatalf("denied action spawned runner %d times", calls)
	}
}

func TestAdapterRunsReadCommandWithoutApprovalAndReportsNoEffect(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "command-read", Context: adapterBoundary(1), Policy: adapterToolPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("start = %#v, %v", result, err)
	}
	stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	events := drainStream(t, ctx, stream)
	if len(events) != 5 {
		t.Fatalf("events = %#v", events)
	}
	if _, ok := events[0].(harnessadapter.StartedEvent); !ok {
		t.Fatalf("start event = %#v", events[0])
	}
	started, ok := events[1].(harnessadapter.ToolStartedEvent)
	if !ok || started.ToolName != "codex.command" || !strings.Contains(started.Input.Content, "только чтение") {
		t.Fatalf("tool start = %#v", events[1])
	}
	completed, ok := events[3].(harnessadapter.ToolCompletedEvent)
	if !ok || completed.Status != "succeeded" || completed.EffectStatus != "none" || completed.EffectRef != "" {
		t.Fatalf("tool completion = %#v", events[3])
	}
	if _, ok := events[4].(harnessadapter.TerminalEvent); !ok {
		t.Fatalf("terminal = %#v", events[4])
	}
	for _, event := range events {
		if _, ok := event.(harnessadapter.ApprovalRequestedEvent); ok {
			t.Fatalf("read-only command requested approval: %#v", events)
		}
	}
	if calls := adapter.config.Runner.(*fakeToolRunner).requestCount(); calls != 1 {
		t.Fatalf("runner calls = %d, want 1", calls)
	}
}

func TestAdapterAdmitsCodeModeReadCommandRequestedBeforeLifecycleStart(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "command-read-request-first", Context: adapterBoundary(1), Policy: adapterToolPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("start = %#v, %v", result, err)
	}
	stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	events := drainStream(t, ctx, stream)
	if len(events) != 5 {
		t.Fatalf("events = %#v", events)
	}
	started, ok := events[1].(harnessadapter.ToolStartedEvent)
	if !ok || started.ToolName != "codex.command" || !strings.Contains(started.Input.Content, "только чтение") {
		t.Fatalf("tool start = %#v", events[1])
	}
	completed, ok := events[3].(harnessadapter.ToolCompletedEvent)
	if !ok || completed.Status != "succeeded" || completed.EffectStatus != "none" || completed.EffectRef != "" {
		t.Fatalf("tool completion = %#v", events[3])
	}
	if terminal, ok := events[4].(harnessadapter.TerminalEvent); !ok || terminal.Outcome != harnessadapter.ReconcileCompleted {
		t.Fatalf("terminal = %#v", events[4])
	}
	if calls := adapter.config.Runner.(*fakeToolRunner).requestCount(); calls != 1 {
		t.Fatalf("runner calls = %d, want 1", calls)
	}
}

func TestAdapterCancelStopsApprovedRunnerBeforeProviderInterrupt(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	runner := &blockingToolRunner{started: make(chan struct{}), canceled: make(chan struct{})}
	adapter.config.Runner = runner
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "command-approval", Context: adapterBoundary(1), Policy: adapterToolPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("start = %#v, %v", result, err)
	}
	stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_, _ = stream.Next(ctx)
	_, _ = stream.Next(ctx)
	requestedEvent, err := stream.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	requested := requestedEvent.(harnessadapter.ApprovalRequestedEvent)
	responseDone := make(chan struct{})
	go func() {
		defer close(responseDone)
		_, _ = adapter.RespondApproval(ctx, harnessadapter.RespondApprovalInput{
			Attempt: reference, ApprovalID: requested.ApprovalID, ApprovalVersion: 2,
			ActionHash: requested.ActionHash, Decision: "allow_once",
		})
	}()
	select {
	case <-runner.started:
	case <-ctx.Done():
		t.Fatal("runner did not start")
	}
	canceled, err := adapter.Cancel(ctx, harnessadapter.CancelInput{Attempt: reference})
	if err != nil || canceled.Outcome != harnessadapter.CancelAcknowledged {
		t.Fatalf("cancel = %#v, %v", canceled, err)
	}
	select {
	case <-runner.canceled:
	case <-ctx.Done():
		t.Fatal("attempt cancel did not cancel runner context")
	}
	select {
	case <-responseDone:
	case <-ctx.Done():
		t.Fatal("approval response remained blocked after cancel")
	}
}

func TestAdapterCancelAcknowledgesWhileApprovalIsPendingWithoutSpawningRunner(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "command-approval", Context: adapterBoundary(1), Policy: adapterToolPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("start = %#v, %v", result, err)
	}
	stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_, _ = stream.Next(ctx)
	_, _ = stream.Next(ctx)
	if event, err := stream.Next(ctx); err != nil {
		t.Fatal(err)
	} else if _, ok := event.(harnessadapter.ApprovalRequestedEvent); !ok {
		t.Fatalf("approval event = %#v", event)
	}
	reconciled, err := adapter.Reconcile(ctx, harnessadapter.ReconcileInput{Attempt: reference})
	if err != nil || reconciled.Outcome != harnessadapter.ReconcileWaitingInput {
		t.Fatalf("waiting approval reconcile = %#v, %v", reconciled, err)
	}
	canceled, err := adapter.Cancel(ctx, harnessadapter.CancelInput{Attempt: reference})
	if err != nil || canceled.Outcome != harnessadapter.CancelAcknowledged {
		t.Fatalf("cancel = %#v, %v", canceled, err)
	}
	if calls := adapter.config.Runner.(*fakeToolRunner).requestCount(); calls != 0 {
		t.Fatalf("runner calls after cancel-before-approval = %d", calls)
	}
}

func TestPendingInteractionCapacityReservesSlotsForOtherAttempts(t *testing.T) {
	adapter := &Adapter{inputs: make(map[string]*pendingInput), approvals: make(map[string]*pendingApproval)}
	first := &nativeAttempt{runtime: newAttemptRuntime(adapterReference(1, 1, 1))}
	second := &nativeAttempt{runtime: newAttemptRuntime(adapterReference(2, 2, 1))}
	for index := 0; index < maximumInteractionsTurn; index++ {
		adapter.approvals[fmt.Sprintf("first-%d", index)] = &pendingApproval{attempt: first}
	}
	if adapter.hasInteractionCapacityLocked(first) {
		t.Fatal("one attempt exceeded its pending interaction share")
	}
	if !adapter.hasInteractionCapacityLocked(second) {
		t.Fatal("one attempt consumed the global interaction reserve")
	}
	for len(adapter.approvals) < maximumInteractions {
		index := len(adapter.approvals)
		adapter.approvals[fmt.Sprintf("global-%d", index)] = &pendingApproval{attempt: &nativeAttempt{}}
	}
	if adapter.hasInteractionCapacityLocked(second) {
		t.Fatal("global pending interaction limit was not enforced")
	}
}

func TestNativeToolRequestClaimIsAtomicPerProviderItem(t *testing.T) {
	actionHash := strings.Repeat("a", 64)
	native := &nativeAttempt{tools: map[string]nativeTool{"item-1": {
		itemID: "item-1", callID: "call-1", actionHash: actionHash, started: true,
	}}}
	start := make(chan struct{})
	results := make(chan bool, 64)
	var workers sync.WaitGroup
	for index := 0; index < cap(results); index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			<-start
			_, claimed := native.claimToolRequest("item-1", actionHash, rpcID{raw: json.RawMessage(fmt.Sprintf("%d", index+1)), key: fmt.Sprintf("n:%d", index+1)})
			results <- claimed
		}(index)
	}
	close(start)
	workers.Wait()
	close(results)
	claimed := 0
	for result := range results {
		if result {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("successful claims = %d, want exactly 1", claimed)
	}
}

func TestAdapterRejectsDuplicateDynamicRequestBeforeSecondApprovalOrEffect(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "command-duplicate", Context: adapterBoundary(1), Policy: adapterToolPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("start = %#v, %v", result, err)
	}
	stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	events := drainStream(t, ctx, stream)
	approvals := 0
	var requested harnessadapter.ApprovalRequestedEvent
	for _, event := range events {
		if value, ok := event.(harnessadapter.ApprovalRequestedEvent); ok {
			approvals++
			requested = value
		}
	}
	if approvals != 1 {
		t.Fatalf("approval events = %d, events=%#v", approvals, events)
	}
	response, err := adapter.RespondApproval(ctx, harnessadapter.RespondApprovalInput{
		Attempt: reference, ApprovalID: requested.ApprovalID, ApprovalVersion: 2,
		ActionHash: requested.ActionHash, Decision: "allow_once",
	})
	if err != nil || response.Outcome != harnessadapter.ResponseRejected {
		t.Fatalf("stale duplicate approval response = %#v, %v", response, err)
	}
	if calls := adapter.config.Runner.(*fakeToolRunner).requestCount(); calls != 0 {
		t.Fatalf("duplicate provider request spawned %d effects", calls)
	}
	var observed struct {
		IDs []string `json:"ids"`
	}
	if err := adapter.session.Call(ctx, "fixture/dynamicResponseIDs", map[string]any{}, &observed); err != nil {
		t.Fatal(err)
	}
	slices.Sort(observed.IDs)
	want := []string{"approval-command-1", "duplicate-command-1"}
	if !slices.Equal(observed.IDs, want) {
		t.Fatalf("provider response ids = %#v, want %#v", observed.IDs, want)
	}
}

func TestAdapterKeepsApprovalUnknownAfterResolutionWithoutCausalItemProgress(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "command-approval-ack", Context: adapterBoundary(1), Policy: adapterToolPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("start = %#v, %v", result, err)
	}
	stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_, _ = stream.Next(ctx)
	_, _ = stream.Next(ctx)
	requestedEvent, err := stream.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	requested := requestedEvent.(harnessadapter.ApprovalRequestedEvent)
	response, err := adapter.RespondApproval(ctx, harnessadapter.RespondApprovalInput{
		Attempt: reference, ApprovalID: requested.ApprovalID, ApprovalVersion: 2,
		ActionHash: requested.ActionHash, Decision: "allow_once",
	})
	if !errors.Is(err, context.DeadlineExceeded) || response.Outcome != harnessadapter.ResponseUnknown {
		t.Fatalf("approval response = %#v, %v", response, err)
	}
	reconciled, err := adapter.Reconcile(ctx, harnessadapter.ReconcileInput{Attempt: reference})
	if err != nil || reconciled.Outcome != harnessadapter.ReconcileUnknown || reconciled.EffectStatus != "unknown" {
		t.Fatalf("unconfirmed approval = %#v, %v", reconciled, err)
	}
}

func TestAdapterMapsFileApprovalAndBoundsCommandOutput(t *testing.T) {
	for _, prompt := range []string{"file-approval", "command-large"} {
		t.Run(prompt, func(t *testing.T) {
			adapter := newTestAdapter(t, 2*time.Second)
			defer adapter.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			reference := adapterReference(1, 1, 1)
			result, err := adapter.Start(ctx, harnessadapter.StartInput{
				Attempt: reference, Prompt: prompt, Context: adapterBoundary(1), Policy: adapterToolPolicy(),
			})
			if err != nil || result.Outcome != harnessadapter.StartStarted {
				t.Fatalf("start = %#v, %v", result, err)
			}
			stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			_, _ = stream.Next(ctx)
			startedEvent, _ := stream.Next(ctx)
			started := startedEvent.(harnessadapter.ToolStartedEvent)
			requestedEvent, _ := stream.Next(ctx)
			requested := requestedEvent.(harnessadapter.ApprovalRequestedEvent)
			response, err := adapter.RespondApproval(ctx, harnessadapter.RespondApprovalInput{
				Attempt: reference, ApprovalID: requested.ApprovalID, ApprovalVersion: 2,
				ActionHash: requested.ActionHash, Decision: "allow_once",
			})
			if err != nil || response.Outcome != harnessadapter.ResponseApplied {
				t.Fatalf("approval response = %#v, %v", response, err)
			}
			events := drainStream(t, ctx, stream)
			var inlineBytes int
			var limited bool
			var completed harnessadapter.ToolCompletedEvent
			for _, event := range events {
				switch value := event.(type) {
				case harnessadapter.ToolOutputEvent:
					if value.Output.Kind == "inline" {
						inlineBytes += len(value.Output.Content)
					}
					limited = limited || value.Output.Reason == "output_limit"
				case harnessadapter.ToolCompletedEvent:
					completed = value
				}
			}
			if completed.CallID != started.CallID || completed.Status != "succeeded" || completed.EffectRef != started.ActionHash {
				t.Fatalf("tool completion = %#v", events)
			}
			if prompt == "command-large" && (inlineBytes != maximumNativeToolOutput || !limited) {
				t.Fatalf("output bound = %d, limited=%v", inlineBytes, limited)
			}
			if prompt == "file-approval" && started.ToolName != "codex.file_change" {
				t.Fatalf("file tool = %#v", started)
			}
		})
	}
}

func TestNativeToolPathsStayInsideDialogWorkspace(t *testing.T) {
	workspace := filepath.Join(string(filepath.Separator), "workspace", "dialog")
	arguments := json.RawMessage(`{"changes":[{"path":"nested/file.txt","operation":"write","expectedSha256":null,"content":"fixture"}]}`)
	request, _, _, _, ok := decodeDynamicArguments("file_change", arguments, workspace, "60000000-0000-4000-8000-000000000001")
	if !ok || request.FileChange == nil || request.FileChange.Changes[0].Path != "nested/file.txt" {
		t.Fatalf("valid relative file request = %#v, %v", request, ok)
	}
	arguments = json.RawMessage(`{"changes":[{"path":"../outside","operation":"write","expectedSha256":null,"content":"fixture"}]}`)
	if _, _, _, _, ok := decodeDynamicArguments("file_change", arguments, workspace, "60000000-0000-4000-8000-000000000001"); ok {
		t.Fatal("cross-workspace path was accepted")
	}
}

func TestNativeApprovalDecisionSetSupportsOnlyOneTimeBridge(t *testing.T) {
	valid := json.RawMessage(`{"command":"printf ok","cwd":".","access":"read","timeoutSeconds":5}`)
	if _, _, _, _, ok := decodeDynamicArguments("command", valid, "/workspace/dialog", "60000000-0000-4000-8000-000000000001"); !ok {
		t.Fatal("strict command arguments were rejected")
	}
	for _, raw := range []string{
		`{"command":"printf ok","cwd":".","access":"read","timeoutSeconds":5,"session":true}`,
		`{"command":"printf ok","cwd":"../state","access":"read","timeoutSeconds":5}`,
		`{"command":"printf ok","cwd":".","access":"session","timeoutSeconds":5}`,
	} {
		if _, _, _, _, ok := decodeDynamicArguments("command", json.RawMessage(raw), "/workspace/dialog", "60000000-0000-4000-8000-000000000001"); ok {
			t.Fatalf("unsafe dynamic arguments accepted: %s", raw)
		}
	}
}

func TestDynamicToolPreviewIsInformativeBoundedAndSecretSafe(t *testing.T) {
	workspace := "/workspace/dialog"
	callID := "60000000-0000-4000-8000-000000000001"
	normal := json.RawMessage(`{"command":"printf fixture","cwd":"nested","access":"write","timeoutSeconds":5}`)
	_, _, input, prompt, ok := decodeDynamicArguments("command", normal, workspace, callID)
	if !ok || input.Redaction != "none" || !strings.Contains(input.Content, "printf fixture") ||
		!strings.Contains(prompt, "Каталог: nested") || !strings.HasSuffix(prompt, "Разрешить один раз?") {
		t.Fatalf("normal command preview = %#v %q, ok=%v", input, prompt, ok)
	}
	for name, command := range map[string]string{
		"api key":    `printf '{"api_key":"top-secret"}'`,
		"cookie":     `printf 'Cookie: session=top-secret'`,
		"pem":        "printf '-----BEGIN PRIVATE KEY-----top-secret'",
		"auth json":  `printf '{"authorization":"Bearer top-secret"}'`,
		"openai":     `printf 'sk-abcd1234secret'`,
		"github":     `printf 'ghp_abcdefgh12345678'`,
		"jwt":        `printf 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLWZpeHR1cmU'`,
		"url auth":   `printf 'https://alice:swordfish@example.test/private'`,
		"aws secret": `printf 'AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuv'`,
		"aws json":   `printf '{"AWS_SECRET_ACCESS_KEY":"abcdefghijklmnopqrstuv"}'`,
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(commandArguments{Command: command, CWD: ".", Access: toolrunner.AccessWrite, TimeoutSeconds: 5})
			if err != nil {
				t.Fatal(err)
			}
			_, _, input, prompt, ok := decodeDynamicArguments("command", encoded, workspace, callID)
			if !ok || input.Redaction != "applied" || strings.Contains(input.Content+prompt, "top-secret") || strings.Contains(input.Content+prompt, command) || !strings.Contains(prompt, "скрытые политикой") {
				t.Fatalf("secret preview = %#v %q, ok=%v", input, prompt, ok)
			}
		})
	}
	for name, command := range map[string]string{
		"ascii": strings.Repeat("x", toolrunner.MaximumCommandBytes),
		"emoji": strings.Repeat("🛡️", 2000),
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(commandArguments{Command: command, CWD: ".", Access: toolrunner.AccessWrite, TimeoutSeconds: 5})
			if err != nil {
				t.Fatal(err)
			}
			_, _, input, prompt, ok := decodeDynamicArguments("command", encoded, workspace, callID)
			if !ok || len(prompt) > 8192 || utf8.RuneCountInString(prompt) > 2000 || !strings.Contains(prompt, "[описание сокращено]") ||
				!strings.HasSuffix(prompt, "Разрешить один раз?") || !input.Truncated {
				t.Fatalf("bounded preview bytes=%d runes=%d input=%#v ok=%v", len(prompt), utf8.RuneCountInString(prompt), input, ok)
			}
		})
	}
	files := json.RawMessage(`{"changes":[{"path":"nested/fixture.txt","operation":"write","expectedSha256":null,"content":"api_key=top-secret"}]}`)
	_, _, input, prompt, ok = decodeDynamicArguments("file_change", files, workspace, callID)
	if !ok || !strings.Contains(input.Content, "Запись: nested/fixture.txt") || !strings.Contains(prompt, "Запись: nested/fixture.txt") || strings.Contains(input.Content+prompt, "top-secret") {
		t.Fatalf("file preview = %#v %q, ok=%v", input, prompt, ok)
	}
}

func TestDynamicActionHashBindsAttemptPolicyAndCanonicalArguments(t *testing.T) {
	base := &nativeAttempt{reference: adapterReference(1, 1, 1), policyHash: strings.Repeat("a", 64)}
	arguments := []byte(`{"command":"printf ok","cwd":".","access":"read","timeoutSeconds":5}`)
	first := dynamicActionHash(base, "provider-call", "command", arguments)
	if !validPolicyHash(first) {
		t.Fatalf("invalid action hash %q", first)
	}
	changedReference := base.reference
	changedReference.Generation++
	changed := &nativeAttempt{reference: changedReference, policyHash: base.policyHash}
	if first == dynamicActionHash(changed, "provider-call", "command", arguments) {
		t.Fatal("generation was not bound into action hash")
	}
	changed = &nativeAttempt{reference: base.reference, policyHash: strings.Repeat("b", 64)}
	if first == dynamicActionHash(changed, "provider-call", "command", arguments) {
		t.Fatal("policy hash was not bound into action hash")
	}
	if first == dynamicActionHash(base, "provider-call", "command", []byte(`{"command":"printf changed","cwd":".","access":"read","timeoutSeconds":5}`)) {
		t.Fatal("canonical arguments were not bound into action hash")
	}
}

func TestDynamicOutputRedactsCredentialShapesAndBoundsAggregate(t *testing.T) {
	for _, value := range []string{
		`api_key=secret-value`,
		`Cookie: session=secret-value`,
		`{"auth":"dXNlcjpwYXNz"}`,
		"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
		`Authorization: Bearer secret-value`,
		`sk-abcd1234secret`,
		`gho_abcdefgh12345678`,
		`eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLWZpeHR1cmU`,
		`https://alice:swordfish@example.test/private`,
		`AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuv`,
		`{"AWS_SECRET_ACCESS_KEY":"abcdefghijklmnopqrstuv"}`,
	} {
		content := safeNativeOutput(value, false)
		if content.Kind != "unavailable" || content.Redaction != "applied" || content.Reason != "provider_redacted" {
			t.Fatalf("credential output was not redacted: %#v", content)
		}
		response := safeRunnerResponse(toolrunner.Result{Success: true, Output: []byte(value)}, nil)
		if len(response.ContentItems) != 1 || strings.Contains(response.ContentItems[0].Text, value) ||
			response.ContentItems[0].Text != "Вывод инструмента скрыт политикой безопасности." {
			t.Fatalf("credential leaked to provider response: %#v", response)
		}
		eventContent := safeDynamicResponse(nativeDynamicToolResponse{Success: true, ContentItems: []nativeDynamicContentItem{{Type: "inputText", Text: value}}})
		if eventContent.Kind != "unavailable" || eventContent.Redaction != "applied" || eventContent.Reason != "provider_redacted" {
			t.Fatalf("credential leaked to Panel event content: %#v", eventContent)
		}
		if full, incomplete := safeRunnerFullText(toolrunner.Result{Success: true, Output: []byte(value)}, nil); full != nil || incomplete {
			t.Fatal("credential leaked into the private full-text source")
		}
	}
	partial := safeRunnerResponse(toolrunner.Result{Success: false, Output: []byte("file operation rejected"), Changes: []toolrunner.FileChangeResult{{Path: "first.txt", Operation: toolrunner.FileWrite}}}, nil)
	if partial.Success || len(partial.ContentItems) != 1 || partial.ContentItems[0].Text != "Операции с файлами завершились с ошибкой после применённых изменений: 1." {
		t.Fatalf("partial file failure = %#v", partial)
	}
	content := safeNativeOutput(strings.Repeat("ж", maximumNativeToolOutput), false)
	if content.Kind != "inline" || len(content.Content) > maximumNativeToolOutput || !utf8.ValidString(content.Content) || !content.Truncated {
		t.Fatalf("multibyte aggregate was not bounded: %#v", content)
	}
	retained := strings.Repeat("x", toolrunner.DefaultMaximumOutput)
	full, incomplete := safeRunnerFullText(toolrunner.Result{Success: true, Output: []byte(retained)}, nil)
	if full == nil || *full != retained || incomplete {
		t.Fatal("complete 1 MiB runner result was not retained")
	}
	full, incomplete = safeRunnerFullText(toolrunner.Result{Success: true, Output: []byte(retained), Truncated: true}, nil)
	if full == nil || *full != retained || !incomplete {
		t.Fatal("runner limit was not carried as an explicit incomplete source")
	}
}

func TestAdapterColdResumeRestoresPersistedDynamicTools(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	first, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := first.Start(ctx, harnessadapter.StartInput{Attempt: reference, Prompt: "seed", Context: adapterBoundary(1), Policy: adapterToolPolicy()})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("seed start = %#v, %v", result, err)
	}
	_ = readAdapterEvents(t, ctx, first, reference)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	continued := adapterReference(1, 2, 2)
	resumed, err := second.Resume(ctx, harnessadapter.ResumeInput{Attempt: continued, Prompt: "command-approval", Context: adapterBoundary(2), Policy: adapterToolPolicy()})
	if err != nil || resumed.Outcome != harnessadapter.ResumeStarted {
		t.Fatalf("cold resume = %#v, %v", resumed, err)
	}
	stream, err := second.Events(ctx, harnessadapter.EventsInput{Attempt: continued})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_, _ = stream.Next(ctx)
	startedEvent, _ := stream.Next(ctx)
	requestedEvent, _ := stream.Next(ctx)
	started, startedOK := startedEvent.(harnessadapter.ToolStartedEvent)
	requested, requestedOK := requestedEvent.(harnessadapter.ApprovalRequestedEvent)
	if !startedOK || !requestedOK || started.ToolName != "codex.command" || requested.CallID != started.CallID {
		t.Fatalf("restored dynamic lifecycle = %#v %#v", startedEvent, requestedEvent)
	}
	response, err := second.RespondApproval(ctx, harnessadapter.RespondApprovalInput{
		Attempt: continued, ApprovalID: requested.ApprovalID, ApprovalVersion: 2, ActionHash: requested.ActionHash, Decision: "deny",
	})
	if err != nil || response.Outcome != harnessadapter.ResponseApplied {
		t.Fatalf("cold-resume approval = %#v, %v", response, err)
	}
	_ = drainStream(t, ctx, stream)
}

func TestAdapterMapsNativeErrorRetrySemantics(t *testing.T) {
	tests := []struct {
		prompt string
		want   harnessadapter.ReconcileOutcome
	}{
		{prompt: "error-no-retry", want: harnessadapter.ReconcileFailed},
		{prompt: "error-retry", want: harnessadapter.ReconcileCompleted},
	}
	for index, test := range tests {
		t.Run(test.prompt, func(t *testing.T) {
			adapter := newTestAdapter(t, 2*time.Second)
			defer adapter.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			reference := adapterReference(int64(index+1), 1, 1)
			result, err := adapter.Start(ctx, harnessadapter.StartInput{
				Attempt: reference, Prompt: test.prompt, Context: adapterBoundary(1), Policy: adapterPolicy(),
			})
			if err != nil || result.Outcome != harnessadapter.StartStarted {
				t.Fatalf("start = %#v, %v", result, err)
			}
			events := readAdapterEvents(t, ctx, adapter, reference)
			terminal, ok := events[len(events)-1].(harnessadapter.TerminalEvent)
			if !ok || terminal.Outcome != test.want {
				t.Fatalf("terminal = %#v", events[len(events)-1])
			}
		})
	}
}

func TestAdapterFailsClosedForEveryUnexpectedNativeItem(t *testing.T) {
	itemTypes := []string{
		"functionCallOutput", "commandExecution", "fileChange", "mcpToolCall", "dynamicToolCall",
		"collabAgentToolCall", "subAgentActivity", "webSearch", "imageView", "sleep",
		"imageGeneration", "enteredReviewMode", "exitedReviewMode", "futureToolItem",
	}
	for index, itemType := range itemTypes {
		t.Run(itemType, func(t *testing.T) {
			adapter := newTestAdapter(t, 2*time.Second)
			defer adapter.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			reference := adapterReference(int64(index+1), 1, 1)
			result, err := adapter.Start(ctx, harnessadapter.StartInput{
				Attempt: reference, Prompt: "unexpected-item:" + itemType, Context: adapterBoundary(1), Policy: adapterPolicy(),
			})
			if err != nil || result.Outcome != harnessadapter.StartStarted {
				t.Fatalf("start = %#v, %v", result, err)
			}
			events := readAdapterEvents(t, ctx, adapter, reference)
			unknown, ok := events[len(events)-1].(harnessadapter.UnknownEvent)
			if !ok || unknown.EffectStatus != "unknown" {
				t.Fatalf("fail-closed event = %#v", events[len(events)-1])
			}
			reconciled, err := adapter.Reconcile(ctx, harnessadapter.ReconcileInput{Attempt: reference})
			if err != nil || reconciled.Outcome != harnessadapter.ReconcileUnknown || reconciled.EffectStatus != "unknown" {
				t.Fatalf("fail-closed reconcile = %#v, %v", reconciled, err)
			}
		})
	}
}

func TestAdapterLostTurnAcknowledgementStaysDurablyUnknownWithoutRetry(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	adapter.config.OperationTimeout = 50 * time.Millisecond
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "lose-turn-ack", Context: adapterBoundary(1), Policy: adapterPolicy(),
	})
	if err == nil || result.Outcome != harnessadapter.StartUnknown {
		t.Fatalf("lost ACK = %#v, %v", result, err)
	}
	mapping, ok := adapter.store.attempt(reference)
	if !ok || mapping.State != "turn_dispatching" || mapping.ThreadID == "" || mapping.TurnID != "" {
		t.Fatalf("durable lost ACK mapping = %#v, %v", mapping, ok)
	}
	result, err = adapter.Start(ctx, harnessadapter.StartInput{
		Attempt: reference, Prompt: "lose-turn-ack", Context: adapterBoundary(1), Policy: adapterPolicy(),
	})
	if err != nil || result.Outcome != harnessadapter.StartUnknown {
		t.Fatalf("duplicate dispatch = %#v, %v", result, err)
	}
}

func TestAdapterDoesNotStartTurnUntilNativeFeaturePolicyIsConfirmed(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	config.Environment = append(config.Environment, "CODEX_FEATURE_SHELL_ENABLED=1")
	adapter, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(context.Background(), harnessadapter.StartInput{
		Attempt: reference, Prompt: "must-not-run", Context: adapterBoundary(1), Policy: adapterPolicy(),
	})
	if err == nil || result.Outcome != harnessadapter.StartUnknown {
		t.Fatalf("unconfirmed policy = %#v, %v", result, err)
	}
	mapping, ok := adapter.store.attempt(reference)
	if !ok || mapping.State != "thread_acknowledged" || mapping.ThreadID == "" || mapping.TurnID != "" {
		t.Fatalf("policy fence mapping = %#v, %v", mapping, ok)
	}
}

func TestAdapterDoesNotStartTurnWhenNativeMCPServerIsPresent(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	config.Environment = append(config.Environment, "CODEX_MCP_ENABLED=1")
	adapter, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	reference := adapterReference(1, 1, 1)
	result, err := adapter.Start(context.Background(), harnessadapter.StartInput{
		Attempt: reference, Prompt: "must-not-run", Context: adapterBoundary(1), Policy: adapterPolicy(),
	})
	if err == nil || result.Outcome != harnessadapter.StartUnknown {
		t.Fatalf("unconfirmed MCP isolation = %#v, %v", result, err)
	}
	mapping, ok := adapter.store.attempt(reference)
	if !ok || mapping.State != "thread_acknowledged" || mapping.ThreadID == "" || mapping.TurnID != "" {
		t.Fatalf("MCP isolation fence mapping = %#v, %v", mapping, ok)
	}
}

func TestAdapterRejectsNonEmptyToolsAndProviderKeyEnvironment(t *testing.T) {
	policy := adapterPolicy()
	policy.ToolManifest = []byte(`[{"name":"unsafe"}]`)
	digest := sha256.Sum256(policy.ToolManifest)
	policy.ToolManifestHash = hex.EncodeToString(digest[:])
	policy.EffectiveHash = harnessadapter.EffectivePolicyHash(policy)
	if _, failure := (&Adapter{config: Config{Runner: &fakeToolRunner{}}}).validateDispatch(adapterReference(1, 1, 1), "prompt", adapterBoundary(1), policy); failure == nil || failure.Class != harnessadapter.FailurePolicy {
		t.Fatalf("tool manifest failure = %#v", failure)
	}
	config := testAdapterConfig(t, time.Second)
	config.Environment = append(config.Environment, "OPENAI_API_KEY=forbidden")
	if adapter, err := New(config, nil); err == nil {
		_ = adapter.Close()
		t.Fatal("provider key environment was accepted")
	}
}

func assertStartAndTerminal(t *testing.T, ctx context.Context, adapter *Adapter, reference harnessadapter.AttemptRef, boundary harnessadapter.ContextBoundary, prompt string) {
	t.Helper()
	result, err := adapter.Start(ctx, harnessadapter.StartInput{Attempt: reference, Prompt: prompt, Context: boundary, Policy: adapterPolicy()})
	if err != nil || result.Outcome != harnessadapter.StartStarted {
		t.Fatalf("start = %#v, %v", result, err)
	}
	assertTerminalEvents(t, ctx, adapter, reference)
}

func assertTerminalEvents(t *testing.T, ctx context.Context, adapter *Adapter, reference harnessadapter.AttemptRef) {
	t.Helper()
	events := readAdapterEvents(t, ctx, adapter, reference)
	if len(events) < 4 {
		t.Fatalf("events = %#v", events)
	}
	if _, ok := events[0].(harnessadapter.StartedEvent); !ok {
		t.Fatalf("first event = %T", events[0])
	}
	if _, ok := events[1].(harnessadapter.AssistantDeltaEvent); !ok {
		t.Fatalf("second event = %T", events[1])
	}
	if message, ok := events[2].(harnessadapter.AssistantMessageEvent); !ok || message.Content.Content == "" || message.FullText == nil || *message.FullText != message.Content.Content {
		t.Fatalf("assistant message = %#v", events[2])
	}
	if terminal, ok := events[len(events)-1].(harnessadapter.TerminalEvent); !ok || terminal.Outcome != harnessadapter.ReconcileCompleted || terminal.Usage == nil || terminal.Usage.Source != "per_attempt" || terminal.Usage.TotalTokens >= 100 {
		t.Fatalf("terminal = %#v", events[len(events)-1])
	}
}

func readAdapterEvents(t *testing.T, ctx context.Context, adapter *Adapter, reference harnessadapter.AttemptRef) []harnessadapter.Event {
	t.Helper()
	stream, err := adapter.Events(ctx, harnessadapter.EventsInput{Attempt: reference})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	var events []harnessadapter.Event
	for {
		event, err := stream.Next(ctx)
		if err == io.EOF {
			return events
		}
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
}

func drainStream(t *testing.T, ctx context.Context, stream harnessadapter.EventStream) []harnessadapter.Event {
	t.Helper()
	var events []harnessadapter.Event
	for {
		event, err := stream.Next(ctx)
		if err == io.EOF {
			return events
		}
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
}

func newTestAdapter(t *testing.T, timeout time.Duration) *Adapter {
	t.Helper()
	adapter, err := New(testAdapterConfig(t, timeout), nil)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := adapter.Identity(context.Background())
	if err != nil || harnessadapter.ValidateIdentity(identity) != nil || identity.Kind != harnessadapter.KindCodex {
		_ = adapter.Close()
		t.Fatalf("identity = %#v, %v", identity, err)
	}
	return adapter
}

func testAdapterConfig(t *testing.T, timeout time.Duration) Config {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	workingDir := t.TempDir()
	if err := os.Chmod(workingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return Config{
		NodeID:     "10000000-0000-4000-8000-000000000001",
		Executable: executable, Arguments: []string{"-test.run=^TestCodexAdapterHelperProcess$"},
		VersionArguments: []string{"-test.run=^TestCodexVersionHelperProcess$"},
		Environment: []string{
			adapterHelperEnvironment, versionHelperEnvironment, "CODEX_VERSION_OUTPUT=codex-cli " + codexAppServerVersion,
			"HOME=/private/tmp/codex-adapter-home", "CODEX_HOME=/private/tmp/codex-adapter-fixture",
		},
		StateDir: filepath.Join(t.TempDir(), "mapping"), WorkingDir: workingDir, Model: "fixture-model", Effort: defaultEffort,
		OperationTimeout: timeout, MaxFrameBytes: 256 << 10, Runner: &fakeToolRunner{},
	}
}

type fakeToolRunner struct {
	mu       sync.Mutex
	requests []toolrunner.Request
}

type blockingToolRunner struct {
	started  chan struct{}
	canceled chan struct{}
}

func (*blockingToolRunner) SelfTest(context.Context) error { return nil }

func (runner *blockingToolRunner) Run(ctx context.Context, _ toolrunner.Request) (toolrunner.Result, error) {
	close(runner.started)
	<-ctx.Done()
	close(runner.canceled)
	return toolrunner.Result{}, ctx.Err()
}

func (runner *fakeToolRunner) requestCount() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return len(runner.requests)
}

func (*fakeToolRunner) SelfTest(context.Context) error { return nil }

func (runner *fakeToolRunner) Run(_ context.Context, request toolrunner.Request) (toolrunner.Result, error) {
	runner.mu.Lock()
	runner.requests = append(runner.requests, request)
	runner.mu.Unlock()
	if request.Kind == toolrunner.KindFileChange {
		changes := make([]toolrunner.FileChangeResult, len(request.FileChange.Changes))
		for index, change := range request.FileChange.Changes {
			changes[index] = toolrunner.FileChangeResult{Path: change.Path, Operation: change.Operation}
		}
		return toolrunner.Result{Success: true, Output: []byte("file changes completed"), Changes: changes}, nil
	}
	if strings.Contains(request.Command.Command, "large") {
		return toolrunner.Result{Success: true, Output: []byte(strings.Repeat("x", maximumNativeToolOutput)), Truncated: true}, nil
	}
	return toolrunner.Result{Success: true, Output: []byte("fixture output\n")}, nil
}

func adapterPolicy() harnessadapter.PolicySnapshot {
	policy := harnessadapter.PolicySnapshot{
		Revision: "fixture-policy@1", Content: []byte("fixture policy"), ToolManifest: []byte("[]"), ApprovalMode: harnessadapter.ApprovalModeDeny,
	}
	contentHash, manifestHash := sha256.Sum256(policy.Content), sha256.Sum256(policy.ToolManifest)
	policy.ContentHash = hex.EncodeToString(contentHash[:])
	policy.ToolManifestHash = hex.EncodeToString(manifestHash[:])
	policy.EffectiveHash = harnessadapter.EffectivePolicyHash(policy)
	return policy
}

func adapterToolPolicy() harnessadapter.PolicySnapshot {
	policy := harnessadapter.PolicySnapshot{
		Revision:     "fixture-policy@tools-1",
		Content:      []byte("fixture tool policy"),
		ToolManifest: []byte(`[{"name":"codex.command"},{"name":"codex.file_change"}]`),
		ApprovalMode: harnessadapter.ApprovalModeExplicitOnce,
	}
	contentHash, manifestHash := sha256.Sum256(policy.Content), sha256.Sum256(policy.ToolManifest)
	policy.ContentHash = hex.EncodeToString(contentHash[:])
	policy.ToolManifestHash = hex.EncodeToString(manifestHash[:])
	policy.EffectiveHash = harnessadapter.EffectivePolicyHash(policy)
	return policy
}

func adapterReference(dialog, request, generation int64) harnessadapter.AttemptRef {
	return harnessadapter.AttemptRef{
		NodeID:    "10000000-0000-4000-8000-000000000001",
		DialogID:  fmt.Sprintf("20000000-0000-4000-8000-%012d", dialog),
		RequestID: fmt.Sprintf("30000000-0000-4000-8000-%012d", request),
		AttemptID: fmt.Sprintf("40000000-0000-4000-8000-%012d", request), Generation: generation,
	}
}

func adapterBoundary(sequence int64) harnessadapter.ContextBoundary {
	return harnessadapter.ContextBoundary{MessageID: fmt.Sprintf("50000000-0000-4000-8000-%012d", sequence), Sequence: sequence}
}

func TestCodexAdapterHelperProcess(t *testing.T) {
	if os.Getenv("CODEX_ADAPTER_HELPER") != "1" {
		return
	}
	os.Exit(runAdapterHelper())
}

func runAdapterHelper() int {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 256<<10)
	encoder := json.NewEncoder(os.Stdout)
	threads := 0
	turns := 0
	activeThread := ""
	activeTurn := ""
	pendingInput := ""
	pendingApproval := ""
	pendingApprovalIDs := map[string]struct{}{}
	dynamicResponseIDs := []string{}
	activeExplicit := false
	activeWorkspace := ""
	activeFeatures := map[string]any{}
	authenticated := false
	pendingLoginID := ""
	for scanner.Scan() {
		var frame rpcFrame
		if json.Unmarshal(scanner.Bytes(), &frame) != nil {
			return 2
		}
		if frame.Method == "" && len(frame.ID) > 0 {
			if pendingApproval != "" {
				var responseID string
				var response nativeDynamicToolResponse
				if json.Unmarshal(frame.ID, &responseID) != nil || json.Unmarshal(frame.Result, &response) != nil || len(response.ContentItems) != 1 || response.ContentItems[0].Type != "inputText" {
					return 3
				}
				dynamicResponseIDs = append(dynamicResponseIDs, responseID)
				mode := pendingApproval
				if mode == "command-duplicate" {
					if _, expected := pendingApprovalIDs[responseID]; !expected {
						return 3
					}
					delete(pendingApprovalIDs, responseID)
					if len(pendingApprovalIDs) > 0 {
						continue
					}
				}
				pendingApproval = ""
				if mode == "command-approval-ack" {
					emitResolved(encoder, activeThread, frame.ID)
					continue
				}
				if mode == "command-approval-completed-first" {
					emitDynamicCompleted(encoder, activeThread, activeTurn, mode, response)
					emitResolved(encoder, activeThread, frame.ID)
					emitTerminal(encoder, activeThread, activeTurn, "completed")
					continue
				}
				if mode == "command-approval-terminal-first" {
					emitDynamicCompleted(encoder, activeThread, activeTurn, mode, response)
					emitTerminal(encoder, activeThread, activeTurn, "completed")
					emitResolved(encoder, activeThread, frame.ID)
					continue
				}
				if mode != "command-read" {
					emitResolved(encoder, activeThread, frame.ID)
				}
				emitDynamicCompleted(encoder, activeThread, activeTurn, mode, response)
				emitTerminal(encoder, activeThread, activeTurn, "completed")
				continue
			}
			if pendingInput == "" {
				return 3
			}
			var response struct {
				Answers map[string]struct {
					Answers []string `json:"answers"`
				} `json:"answers"`
			}
			if json.Unmarshal(frame.Result, &response) != nil || len(response.Answers["question-1"].Answers) != 1 {
				return 4
			}
			answer := response.Answers["question-1"].Answers[0]
			mode := pendingInput
			pendingInput = ""
			if mode == "resolve" {
				emitResolved(encoder, activeThread, frame.ID)
				emitAssistant(encoder, activeThread, activeTurn, "answer:"+answer)
				emitTerminal(encoder, activeThread, activeTurn, "completed")
			} else if mode == "cleanup" {
				emitResolved(encoder, activeThread, frame.ID)
				emitTerminal(encoder, activeThread, activeTurn, "completed")
			}
			continue
		}
		if len(frame.ID) == 0 {
			if frame.Method != "initialized" {
				return 5
			}
			continue
		}
		switch frame.Method {
		case "initialize":
			var params initializeParams
			if json.Unmarshal(frame.Params, &params) != nil || !params.Capabilities.ExperimentalAPI {
				return 14
			}
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": initializeResponse{
				UserAgent: validSessionUserAgent(), CodexHome: "/private/tmp/codex-adapter-fixture", PlatformFamily: "unix", PlatformOS: "test",
			}})
		case "account/read":
			var request struct {
				RefreshToken bool `json:"refreshToken"`
			}
			if json.Unmarshal(frame.Params, &request) != nil {
				return 15
			}
			if request.RefreshToken && authenticated && os.Getenv("CODEX_AUTH_FAIL_REFRESH_AFTER_LOGIN") == "1" {
				_ = encoder.Encode(map[string]any{"id": frame.ID, "error": map[string]any{"code": -32000, "message": "refresh failed"}})
				continue
			}
			var account any
			if authenticated {
				account = map[string]any{"type": "chatgpt", "email": "fixture@example.invalid", "planType": "unknown"}
			}
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]any{"account": account, "requiresOpenaiAuth": true}})
		case "account/login/start":
			pendingLoginID = "fixture-login-1"
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]any{
				"type": "chatgptDeviceCode", "loginId": pendingLoginID,
				"verificationUrl": "https://auth.openai.com/codex/device", "userCode": "FIXT-URE1",
			}})
			if os.Getenv("CODEX_AUTH_NO_COMPLETE") != "1" {
				authenticated = true
				_ = encoder.Encode(map[string]any{"method": "account/login/completed", "params": map[string]any{"loginId": pendingLoginID, "success": true, "error": nil}})
			}
		case "account/login/cancel":
			status := "notFound"
			if pendingLoginID != "" {
				status = "canceled"
				pendingLoginID = ""
			}
			if os.Getenv("CODEX_AUTH_CANCEL_AUTHENTICATES") == "1" {
				authenticated = true
			}
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]any{"status": status}})
		case "account/logout":
			authenticated = false
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]any{}})
		case "thread/start":
			var params nativeThreadOptions
			if json.Unmarshal(frame.Params, &params) != nil || !validHelperPolicy(params) || params.ThreadID != "" {
				return 6
			}
			activeExplicit = len(params.DynamicTools) > 0
			activeWorkspace = params.CWD
			activeFeatures, _ = params.Config["features"].(map[string]any)
			threads++
			activeThread = fmt.Sprintf("thread-%d", threads)
			emitThreadResponse(encoder, frame.ID, activeThread, params.CWD)
		case "thread/resume":
			var params nativeThreadOptions
			if json.Unmarshal(frame.Params, &params) != nil || !validHelperPolicy(params) || params.ThreadID == "" {
				return 7
			}
			activeExplicit = params.DeveloperInstructions == "fixture tool policy"
			activeWorkspace = params.CWD
			activeFeatures, _ = params.Config["features"].(map[string]any)
			activeThread = params.ThreadID
			emitThreadResponse(encoder, frame.ID, activeThread, params.CWD)
		case "experimentalFeature/list":
			var params struct {
				ThreadID string `json:"threadId"`
				Limit    int    `json:"limit"`
			}
			if json.Unmarshal(frame.Params, &params) != nil || params.ThreadID != activeThread || params.Limit != 100 {
				return 12
			}
			features := make([]map[string]any, 0, len(deniedNativeFeatures))
			for _, name := range deniedNativeFeatures {
				enabled, _ := activeFeatures[name].(bool)
				if name == "shell_tool" && os.Getenv("CODEX_FEATURE_SHELL_ENABLED") == "1" {
					enabled = true
				}
				features = append(features, map[string]any{"name": name, "enabled": enabled})
			}
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]any{"data": features, "nextCursor": nil}})
		case "mcpServerStatus/list":
			var params struct {
				ThreadID string `json:"threadId"`
				Limit    int    `json:"limit"`
				Detail   string `json:"detail"`
			}
			if json.Unmarshal(frame.Params, &params) != nil || params.ThreadID != activeThread || params.Limit != 100 || params.Detail != "toolsAndAuthOnly" {
				return 13
			}
			servers := []map[string]any{}
			if os.Getenv("CODEX_MCP_ENABLED") == "1" {
				servers = append(servers, map[string]any{"name": "unexpected"})
			}
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]any{"data": servers, "nextCursor": nil}})
		case "fixture/dynamicResponseIDs":
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]any{"ids": dynamicResponseIDs}})
		case "turn/start":
			var params nativeTurnParams
			if json.Unmarshal(frame.Params, &params) != nil || params.ThreadID != activeThread || len(params.Input) != 1 || params.Input[0].Type != "text" || params.ClientUserMessageID == "" || params.CWD != activeWorkspace || !validHelperTurnPolicy(params) {
				return 8
			}
			turns++
			activeTurn = fmt.Sprintf("turn-%d", turns)
			_ = encoder.Encode(map[string]any{"method": "turn/started", "params": map[string]any{"threadId": activeThread, "turn": map[string]string{"id": activeTurn, "status": "inProgress"}}})
			if params.Input[0].Text == "lose-turn-ack" {
				continue
			}
			if params.Input[0].Text == "ask-input" || params.Input[0].Text == "ask-input-cleanup" || params.Input[0].Text == "ask-input-resolved" {
				pendingInput = map[string]string{"ask-input": "resolve", "ask-input-cleanup": "cleanup", "ask-input-resolved": "resolved"}[params.Input[0].Text]
				_ = encoder.Encode(map[string]any{"id": "input-request-1", "method": "item/tool/requestUserInput", "params": map[string]any{
					"threadId": activeThread, "turnId": activeTurn, "itemId": "input-item-1", "isBlocking": true,
					"questions": []map[string]any{{"id": "question-1", "header": "Choice", "question": "Choose one value", "isSecret": false}},
				}})
				if pendingInput == "resolved" {
					emitResolved(encoder, activeThread, json.RawMessage(`"input-request-1"`))
					pendingInput = ""
				}
			}
			if params.Input[0].Text == "command-approval" || params.Input[0].Text == "command-approval-ack" || params.Input[0].Text == "command-approval-completed-first" || params.Input[0].Text == "command-approval-terminal-first" || params.Input[0].Text == "command-duplicate" || params.Input[0].Text == "command-large" || params.Input[0].Text == "command-read" || params.Input[0].Text == "command-read-request-first" {
				if !activeExplicit {
					return 15
				}
				pendingApproval = params.Input[0].Text
				if pendingApproval == "command-duplicate" {
					pendingApprovalIDs = map[string]struct{}{"approval-command-1": {}, "duplicate-command-1": {}}
				}
				emitDynamicStartedAndRequest(encoder, activeThread, activeTurn, params.Input[0].Text)
			}
			if params.Input[0].Text == "file-approval" {
				if !activeExplicit {
					return 15
				}
				pendingApproval = params.Input[0].Text
				emitDynamicStartedAndRequest(encoder, activeThread, activeTurn, params.Input[0].Text)
			}
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]any{"turn": map[string]string{"id": activeTurn, "status": "inProgress"}}})
			switch params.Input[0].Text {
			case "error-no-retry":
				emitError(encoder, activeThread, activeTurn, false)
			case "error-retry":
				emitError(encoder, activeThread, activeTurn, true)
				emitAssistant(encoder, activeThread, activeTurn, "answer:retry")
				emitUsage(encoder, activeThread, activeTurn, turns)
				emitTerminal(encoder, activeThread, activeTurn, "completed")
			default:
				if itemType, ok := strings.CutPrefix(params.Input[0].Text, "unexpected-item:"); ok {
					emitUnexpectedItem(encoder, activeThread, activeTurn, itemType)
					emitTerminal(encoder, activeThread, activeTurn, "completed")
				} else if params.Input[0].Text != "hold" && !strings.HasPrefix(params.Input[0].Text, "ask-input") && !strings.Contains(params.Input[0].Text, "-approval") && params.Input[0].Text != "command-large" && params.Input[0].Text != "command-read" && params.Input[0].Text != "command-read-request-first" {
					emitAssistant(encoder, activeThread, activeTurn, "answer:"+params.Input[0].Text)
					emitUsage(encoder, activeThread, activeTurn, turns)
					emitTerminal(encoder, activeThread, activeTurn, "completed")
				}
			}
		case "turn/steer":
			var params struct {
				ThreadID       string `json:"threadId"`
				ExpectedTurnID string `json:"expectedTurnId"`
			}
			if json.Unmarshal(frame.Params, &params) != nil || params.ThreadID != activeThread || params.ExpectedTurnID != activeTurn {
				return 9
			}
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]string{"turnId": activeTurn}})
		case "turn/interrupt":
			var params struct{ ThreadID, TurnID string }
			if json.Unmarshal(frame.Params, &params) != nil || params.ThreadID != activeThread || params.TurnID != activeTurn {
				return 10
			}
			_ = encoder.Encode(map[string]any{"id": frame.ID, "result": map[string]any{}})
			time.Sleep(150 * time.Millisecond)
			emitTerminal(encoder, activeThread, activeTurn, "interrupted")
		default:
			_ = encoder.Encode(map[string]any{"id": frame.ID, "error": map[string]any{"code": -32601, "message": "unsupported"}})
		}
	}
	if scanner.Err() != nil {
		return 11
	}
	return 0
}

func validHelperPolicy(params nativeThreadOptions) bool {
	features, ok := params.Config["features"].(map[string]any)
	mcpServers, mcpOK := params.Config["mcp_servers"].(map[string]any)
	if params.Model != "fixture-model" || params.CWD == "" || params.ApprovalsReviewer != "user" || !ok || len(features) != len(deniedNativeFeatures) || !mcpOK || len(mcpServers) != 0 {
		return false
	}
	explicit := params.DeveloperInstructions == "fixture tool policy"
	deny := params.DeveloperInstructions == "fixture policy"
	if params.ApprovalPolicy != "never" || params.Sandbox != "read-only" || (!explicit && !deny) {
		return false
	}
	if (params.ThreadID == "" && explicit && len(params.DynamicTools) != 1) || (params.ThreadID != "" && len(params.DynamicTools) != 0) || (deny && len(params.DynamicTools) != 0) {
		return false
	}
	for _, name := range deniedNativeFeatures {
		if features[name] != false {
			return false
		}
	}
	if explicit && params.ThreadID == "" {
		tools := params.DynamicTools[0]
		if tools.Type != "namespace" || tools.Name != "codex" || len(tools.Tools) != 2 || tools.Tools[0].Name != "command" || tools.Tools[1].Name != "file_change" {
			return false
		}
	}
	return true
}

func validHelperTurnPolicy(params nativeTurnParams) bool {
	return params.ApprovalPolicy == "never" && params.ApprovalsReviewer == "user" &&
		params.SandboxPolicy.Type == "readOnly" && !params.SandboxPolicy.NetworkAccess &&
		len(params.SandboxPolicy.WritableRoots) == 0 && !params.SandboxPolicy.ExcludeTmpdirEnvVar && !params.SandboxPolicy.ExcludeSlashTmp
}

func emitThreadResponse(encoder *json.Encoder, id json.RawMessage, threadID, cwd string) {
	sandbox := map[string]any{"type": "readOnly", "networkAccess": false, "writableRoots": []string{}, "excludeTmpdirEnvVar": false, "excludeSlashTmp": false}
	_ = encoder.Encode(map[string]any{"id": id, "result": map[string]any{
		"thread": map[string]string{"id": threadID}, "approvalPolicy": "never",
		"approvalsReviewer": "user", "cwd": cwd, "sandbox": sandbox,
	}})
}

func emitDynamicStartedAndRequest(encoder *json.Encoder, threadID, turnID, mode string) {
	callID := "command-1"
	tool := "command"
	arguments := map[string]any{"command": "printf fixture", "cwd": ".", "access": "write", "timeoutSeconds": 5}
	if mode == "command-read" || mode == "command-read-request-first" {
		arguments["access"] = "read"
	}
	if mode == "command-large" {
		arguments["command"] = "printf large"
	}
	if mode == "file-approval" {
		callID = "file-1"
		tool = "file_change"
		arguments = map[string]any{"changes": []map[string]any{{"path": "fixture.txt", "operation": "write", "expectedSha256": nil, "content": "fixture"}}}
	}
	item := map[string]any{"id": callID, "type": "dynamicToolCall", "status": "inProgress", "namespace": "codex", "tool": tool, "arguments": arguments}
	if mode != "command-read-request-first" {
		_ = encoder.Encode(map[string]any{"method": "item/started", "params": map[string]any{"threadId": threadID, "turnId": turnID, "item": item}})
	}
	_ = encoder.Encode(map[string]any{"id": "approval-" + callID, "method": "item/tool/call", "params": map[string]any{
		"threadId": threadID, "turnId": turnID, "callId": callID, "namespace": "codex", "tool": tool, "arguments": arguments,
	}})
	if mode == "command-duplicate" {
		_ = encoder.Encode(map[string]any{"id": "duplicate-" + callID, "method": "item/tool/call", "params": map[string]any{
			"threadId": threadID, "turnId": turnID, "callId": callID, "namespace": "codex", "tool": tool, "arguments": arguments,
		}})
	}
}

func emitDynamicCompleted(encoder *json.Encoder, threadID, turnID, mode string, response nativeDynamicToolResponse) {
	callID := "command-1"
	tool := "command"
	arguments := map[string]any{"command": "printf fixture", "cwd": ".", "access": "write", "timeoutSeconds": 5}
	if mode == "command-read" || mode == "command-read-request-first" {
		arguments["access"] = "read"
	}
	if mode == "command-large" {
		arguments["command"] = "printf large"
	}
	if mode == "file-approval" {
		callID = "file-1"
		tool = "file_change"
		arguments = map[string]any{"changes": []map[string]any{{"path": "fixture.txt", "operation": "write", "expectedSha256": nil, "content": "fixture"}}}
	}
	status := "failed"
	if response.Success {
		status = "completed"
	}
	item := map[string]any{
		"id": callID, "type": "dynamicToolCall", "status": status, "namespace": "codex", "tool": tool,
		"arguments": arguments, "contentItems": response.ContentItems, "success": response.Success, "durationMs": 1,
	}
	_ = encoder.Encode(map[string]any{"method": "item/completed", "params": map[string]any{"threadId": threadID, "turnId": turnID, "item": item}})
}

func emitAssistant(encoder *json.Encoder, threadID, turnID, text string) {
	itemID := "message-" + turnID
	_ = encoder.Encode(map[string]any{"method": "item/agentMessage/delta", "params": map[string]string{"threadId": threadID, "turnId": turnID, "itemId": itemID, "delta": text}})
	_ = encoder.Encode(map[string]any{"method": "item/completed", "params": map[string]any{
		"threadId": threadID, "turnId": turnID, "completedAtMs": 1, "item": map[string]string{"id": itemID, "type": "agentMessage", "text": text},
	}})
}

func emitTerminal(encoder *json.Encoder, threadID, turnID, status string) {
	_ = encoder.Encode(map[string]any{"method": "turn/completed", "params": map[string]any{"threadId": threadID, "turn": map[string]any{"id": turnID, "status": status, "items": []any{}}}})
}

func emitResolved(encoder *json.Encoder, threadID string, requestID json.RawMessage) {
	_ = encoder.Encode(map[string]any{"method": "serverRequest/resolved", "params": map[string]any{"threadId": threadID, "requestId": requestID}})
}

func emitError(encoder *json.Encoder, threadID, turnID string, willRetry bool) {
	_ = encoder.Encode(map[string]any{"method": "error", "params": map[string]any{
		"threadId": threadID, "turnId": turnID, "willRetry": willRetry, "error": map[string]string{"message": "fixture failure"},
	}})
}

func emitUsage(encoder *json.Encoder, threadID, turnID string, turns int) {
	_ = encoder.Encode(map[string]any{"method": "thread/tokenUsage/updated", "params": map[string]any{
		"threadId": threadID, "turnId": turnID, "tokenUsage": map[string]any{
			"last":  map[string]int{"inputTokens": turns, "outputTokens": turns, "totalTokens": turns * 2},
			"total": map[string]int{"inputTokens": 100 + turns, "outputTokens": 100 + turns, "totalTokens": 200 + turns*2},
		},
	}})
}

func emitUnexpectedItem(encoder *json.Encoder, threadID, turnID, itemType string) {
	item := map[string]string{"id": "unexpected-" + turnID, "type": itemType, "status": "completed"}
	if itemType == "mcpToolCall" {
		item["server"], item["tool"] = "fixture", "tool"
	}
	if itemType == "dynamicToolCall" {
		item["tool"] = "fixture"
	}
	_ = encoder.Encode(map[string]any{"method": "item/started", "params": map[string]any{"threadId": threadID, "turnId": turnID, "item": item}})
}
