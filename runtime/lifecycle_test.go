package node_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
	_ "modernc.org/sqlite"
)

func command(t *testing.T, id, kind string, target, expected, payload any) []byte {
	t.Helper()
	value, err := json.Marshal(map[string]any{
		"protocolVersion": 1, "schemaId": harnessprotocol.SchemaID, "commandId": id, "kind": kind,
		"target": target, "expected": expected, "payload": payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func decodeReceipt(t *testing.T, result node.Result, status int) harnessprotocol.Receipt {
	t.Helper()
	if result.HTTPStatus != status {
		t.Fatalf("status=%d want=%d body=%s", result.HTTPStatus, status, result.Body)
	}
	var receipt harnessprotocol.Receipt
	if err := json.Unmarshal(result.Body, &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func waitFor(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}

func nodeTrust() node.TrustContext {
	return node.TrustContext{TransportNodeID: testNodeID}
}

func currentSnapshot(t *testing.T, ctx context.Context, opened *node.Node) harnessprotocol.Snapshot {
	t.Helper()
	result := opened.Snapshot(ctx, nodeTrust())
	if result.HTTPStatus != 200 {
		t.Fatalf("snapshot status=%d body=%s", result.HTTPStatus, result.Body)
	}
	var snapshot harnessprotocol.Snapshot
	if err := json.Unmarshal(result.Body, &snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func attemptEvents(t *testing.T, ctx context.Context, opened *node.Node, attemptID string) []harnessprotocol.EventEnvelope {
	t.Helper()
	result := opened.AttemptEvents(ctx, nodeTrust(), attemptID, 0, 100)
	if result.HTTPStatus != 200 {
		t.Fatalf("events status=%d body=%s", result.HTTPStatus, result.Body)
	}
	var page struct {
		Items []harnessprotocol.EventEnvelope `json:"items"`
	}
	if err := json.Unmarshal(result.Body, &page); err != nil {
		t.Fatal(err)
	}
	return page.Items
}

func hasEventType(events []harnessprotocol.EventEnvelope, eventType string) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func createDialog(t *testing.T, ctx context.Context, opened *node.Node, commandID string) string {
	t.Helper()
	receipt := decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, commandID, "dialog.create", map[string]any{"nodeId": testNodeID}, map[string]any{"registryVersion": 1}, map[string]any{})), 202)
	var references harnessprotocol.DialogCreateReferences
	if err := json.Unmarshal(receipt.References, &references); err != nil {
		t.Fatal(err)
	}
	return references.DialogID
}

func enqueue(t *testing.T, ctx context.Context, opened *node.Node, commandID, dialogID, text string, dialogVersion int64) harnessprotocol.MessageEnqueueReferences {
	t.Helper()
	receipt := decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, commandID, "message.enqueue", map[string]any{"nodeId": testNodeID, "dialogId": dialogID}, map[string]any{"dialogVersion": dialogVersion}, map[string]any{"text": text})), 202)
	var references harnessprotocol.MessageEnqueueReferences
	if err := json.Unmarshal(receipt.References, &references); err != nil {
		t.Fatal(err)
	}
	return references
}

func dispatch(t *testing.T, ctx context.Context, opened *node.Node) node.DispatchResult {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		result, err := opened.DispatchNext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if result.AttemptID != "" {
			return result
		}
		snapshot := currentSnapshot(t, ctx, opened)
		if snapshot.ActiveAttempt != nil {
			return node.DispatchResult{Outcome: snapshot.ActiveAttempt.State, AttemptID: snapshot.ActiveAttempt.AttemptID, RequestID: snapshot.ActiveAttempt.RequestID}
		}
		if time.Now().After(deadline) {
			t.Fatalf("request did not dispatch: outcome=%s", result.Outcome)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDispatchIntentPrecedesAdapterAndBlockedAdapterDoesNotBlockAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	startGate := make(chan struct{})
	startCalled := make(chan struct{}, 1)
	adapter := fixture.NewAdapter()
	adapter.StartGate = startGate
	adapter.StartCalled = startCalled
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	created := decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "10000000-0000-4000-8000-000000000101", "dialog.create", map[string]any{"nodeId": testNodeID}, map[string]any{"registryVersion": 1}, map[string]any{})), 202)
	var dialog harnessprotocol.DialogCreateReferences
	if err := json.Unmarshal(created.References, &dialog); err != nil {
		t.Fatal(err)
	}
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "10000000-0000-4000-8000-000000000102", "message.enqueue", map[string]any{"nodeId": testNodeID, "dialogId": dialog.DialogID}, map[string]any{"dialogVersion": 1}, map[string]any{"text": "first"})), 202)
	dispatched := dispatch(t, ctx, opened)
	if dispatched.Outcome != "dispatching" && dispatched.Outcome != "running" {
		t.Fatalf("dispatch=%+v", dispatched)
	}
	select {
	case <-startCalled:
	case <-ctx.Done():
		t.Fatal("adapter start was not called")
	}
	snapshot := opened.Snapshot(ctx, nodeTrust())
	if snapshot.HTTPStatus != 200 {
		t.Fatalf("snapshot status=%d body=%s", snapshot.HTTPStatus, snapshot.Body)
	}
	var state harnessprotocol.Snapshot
	if err := json.Unmarshal(snapshot.Body, &state); err != nil {
		t.Fatal(err)
	}
	if state.ActiveAttempt == nil || state.ActiveAttempt.AttemptID != dispatched.AttemptID || state.ActiveAttempt.State != "dispatching" {
		t.Fatalf("dispatch intent was not durable before adapter result: %+v", state.ActiveAttempt)
	}
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "10000000-0000-4000-8000-000000000103", "message.enqueue", map[string]any{"nodeId": testNodeID, "dialogId": dialog.DialogID}, map[string]any{"dialogVersion": 2}, map[string]any{"text": "second"})), 202)
	close(startGate)
	waitFor(t, func() bool {
		snapshot := opened.Snapshot(ctx, nodeTrust())
		if snapshot.HTTPStatus != 200 {
			return false
		}
		var current harnessprotocol.Snapshot
		_ = json.Unmarshal(snapshot.Body, &current)
		return current.ActiveAttempt != nil && current.ActiveAttempt.State == "running" && len(current.PendingQueue) == 1
	})
}

func TestStopAcknowledgementIsNotTerminalAndBlockedCancelDoesNotBlockResume(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cancelGate := make(chan struct{})
	cancelCalled := make(chan struct{}, 1)
	adapter := fixture.NewAdapter()
	adapter.CancelGate = cancelGate
	adapter.CancelCalled = cancelCalled
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	created := decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "10000000-0000-4000-8000-000000000111", "dialog.create", map[string]any{"nodeId": testNodeID}, map[string]any{"registryVersion": 1}, map[string]any{})), 202)
	var dialog harnessprotocol.DialogCreateReferences
	_ = json.Unmarshal(created.References, &dialog)
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "10000000-0000-4000-8000-000000000112", "message.enqueue", map[string]any{"nodeId": testNodeID, "dialogId": dialog.DialogID}, map[string]any{"dialogVersion": 1}, map[string]any{"text": "run"})), 202)
	dispatched := dispatch(t, ctx, opened)
	waitFor(t, func() bool {
		var snapshot harnessprotocol.Snapshot
		result := opened.Snapshot(ctx, nodeTrust())
		_ = json.Unmarshal(result.Body, &snapshot)
		return snapshot.ActiveAttempt != nil && snapshot.ActiveAttempt.State == "running"
	})
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "10000000-0000-4000-8000-000000000113", "attempt.stop", map[string]any{"nodeId": testNodeID, "attemptId": dispatched.AttemptID}, map[string]any{"attemptGeneration": 1}, map[string]any{})), 202)
	select {
	case <-cancelCalled:
	case <-ctx.Done():
		t.Fatal("cancel was not called")
	}
	var paused harnessprotocol.Snapshot
	result := opened.Snapshot(ctx, nodeTrust())
	_ = json.Unmarshal(result.Body, &paused)
	if !paused.Node.QueuePaused || paused.ActiveAttempt == nil || paused.ActiveAttempt.State != "stopping" {
		t.Fatalf("stop intent is not durable: %+v", paused)
	}
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "10000000-0000-4000-8000-000000000114", "queue.resume", map[string]any{"nodeId": testNodeID}, map[string]any{"queueVersion": paused.Node.QueueVersion}, map[string]any{})), 202)
	close(cancelGate)
	waitFor(t, func() bool { return len(adapter.CallsSnapshot()) >= 2 })
	var after harnessprotocol.Snapshot
	result = opened.Snapshot(ctx, nodeTrust())
	_ = json.Unmarshal(result.Body, &after)
	if after.ActiveAttempt == nil || after.ActiveAttempt.State != "stopping" {
		t.Fatalf("cancel ACK became terminal: %+v", after.ActiveAttempt)
	}
	reference := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialog.DialogID, RequestID: dispatched.RequestID, AttemptID: dispatched.AttemptID, Generation: 1}
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.WaitingEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, Kind: "approval"}); err != nil {
		t.Fatal(err)
	}
	if active := currentSnapshot(t, ctx, opened).ActiveAttempt; active == nil || active.State != "stopping" {
		t.Fatalf("late wait changed stopping state: %+v", active)
	}
}

func TestAdapterEventsProjectAtomicallyWithDedupAndArtifactBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	streamInput := make(chan harnessadapter.Event, 16)
	eventsCalled := make(chan struct{}, 1)
	adapter := fixture.NewAdapter()
	adapter.StreamInput = streamInput
	adapter.EventsCalled = eventsCalled
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "20000000-0000-4000-8000-000000000001")
	message := enqueue(t, ctx, opened, "20000000-0000-4000-8000-000000000002", dialogID, "run", 1)
	dispatched := dispatch(t, ctx, opened)
	select {
	case <-eventsCalled:
	case <-ctx.Done():
		t.Fatal("event stream was not opened")
	}
	reference := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialogID, RequestID: message.RequestID, AttemptID: dispatched.AttemptID, Generation: 1}
	inline := harnessprotocol.SafeContent{Kind: "inline", Content: "answer", Redaction: "none", Truncated: false}
	messageID := "20000000-0000-4000-8000-000000000003"
	callID := "20000000-0000-4000-8000-000000000004"
	approvalID := "20000000-0000-4000-8000-000000000005"
	inputID := "20000000-0000-4000-8000-000000000006"
	actionHash := strings.Repeat("a", 64)
	delta := harnessadapter.AssistantDeltaEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: messageID, DeltaIndex: 0, Content: inline}
	streamInput <- delta
	streamInput <- delta
	started := harnessadapter.ToolStartedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID, ToolName: "fixture.echo", ActionHash: actionHash, Input: inline}
	streamInput <- started
	streamInput <- started
	waitFor(t, func() bool { return hasEventType(attemptEvents(t, ctx, opened, dispatched.AttemptID), "tool.started") })
	metadata, err := opened.ArtifactSink().StoreArtifact(ctx, node.ArtifactInput{Attempt: reference, CallID: callID, Name: "result.txt", MediaType: "text/plain", Redaction: "none", Disposition: "attachment"}, []byte("artifact result"))
	if err != nil {
		t.Fatal(err)
	}
	size := metadata.SizeBytes
	artifact := harnessprotocol.SafeContent{Kind: "artifact", ArtifactID: metadata.ArtifactID, SizeBytes: &size, SHA256: metadata.SHA256, Redaction: metadata.Redaction, Truncated: metadata.Truncated}
	streamInput <- harnessadapter.AssistantMessageEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: messageID, Content: artifact, FinishReason: "complete"}
	streamInput <- harnessadapter.ToolOutputEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID, ChunkIndex: 0, Stream: "result", Output: artifact}
	streamInput <- harnessadapter.ToolCompletedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID, Status: "succeeded", Result: artifact, EffectStatus: "known", EffectRef: "fixture-effect"}
	streamInput <- harnessadapter.ApprovalRequestedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, ApprovalID: approvalID, CallID: callID, ActionHash: actionHash, SafePrompt: "Allow fixture action?"}
	streamInput <- harnessadapter.InputRequestedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, InputRequestID: inputID, Prompt: inline}
	terminalSize := metadata.SizeBytes
	terminalArtifact := artifact
	terminalArtifact.SizeBytes = &terminalSize
	streamInput <- harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, Outcome: harnessadapter.ReconcileCompleted, Output: &terminalArtifact, Usage: &harnessprotocol.Usage{Source: "per_attempt", InputTokens: 1, OutputTokens: 2, TotalTokens: 3}, EffectStatus: "known"}
	waitFor(t, func() bool {
		snapshot := currentSnapshot(t, ctx, opened)
		return snapshot.ActiveAttempt == nil && snapshot.Node.Occupancy == "idle"
	})
	events := attemptEvents(t, ctx, opened, dispatched.AttemptID)
	for _, eventType := range []string{"assistant.delta", "assistant.message", "tool.started", "artifact.available", "tool.output", "tool.completed", "attempt.waiting_input", "approval.requested", "input.requested", "attempt.completed"} {
		if !hasEventType(events, eventType) {
			t.Errorf("missing event %s", eventType)
		}
	}
	for _, uniqueType := range []string{"assistant.delta", "tool.started"} {
		count := 0
		for _, event := range events {
			if event.Type == uniqueType {
				count++
			}
		}
		if count != 1 {
			t.Errorf("%s count=%d want=1", uniqueType, count)
		}
	}
	waitingCount := 0
	for _, event := range events {
		if event.Type == "attempt.waiting_input" {
			waitingCount++
		}
	}
	if waitingCount != 2 {
		t.Errorf("repeat wait transitions=%d want=2", waitingCount)
	}
	history := opened.History(ctx, nodeTrust(), dialogID, "", 100)
	if history.HTTPStatus != 200 || !strings.Contains(string(history.Body), messageID) || !strings.Contains(string(history.Body), metadata.ArtifactID) {
		t.Fatalf("assistant history missing status=%d body=%s", history.HTTPStatus, history.Body)
	}
}

func TestEventEOFBecomesUnknownAndCloseJoinsStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	adapter := fixture.NewAdapter()
	adapter.StreamEOF = true
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	dialogID := createDialog(t, ctx, opened, "21000000-0000-4000-8000-000000000001")
	enqueue(t, ctx, opened, "21000000-0000-4000-8000-000000000002", dialogID, "run", 1)
	_ = dispatch(t, ctx, opened)
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.State == "unknown"
	})
	done := make(chan error, 1)
	go func() { done <- opened.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join the event worker")
	}
}

func TestTerminalWithoutAssistantTextUsesEmptyOutput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	streamInput := make(chan harnessadapter.Event, 1)
	adapter := fixture.NewAdapter()
	adapter.StreamInput = streamInput
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "22000000-0000-4000-8000-000000000001")
	message := enqueue(t, ctx, opened, "22000000-0000-4000-8000-000000000002", dialogID, "run", 1)
	dispatched := dispatch(t, ctx, opened)
	reference := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialogID, RequestID: message.RequestID, AttemptID: dispatched.AttemptID, Generation: 1}
	streamInput <- harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "none"}
	waitFor(t, func() bool { return currentSnapshot(t, ctx, opened).ActiveAttempt == nil })
	for _, event := range attemptEvents(t, ctx, opened, dispatched.AttemptID) {
		if event.Type == "attempt.completed" {
			var payload harnessprotocol.AttemptCompletedPayload
			if json.Unmarshal(event.Payload, &payload) != nil || payload.Output.Kind != "empty" || payload.Output.AssistantMessageID != "" {
				t.Fatalf("completed payload=%s", event.Payload)
			}
			return
		}
	}
	t.Fatal("completed event missing")
}

func TestLateTerminalDoesNotMutateNewGenerationAndBoundaryUsesDurableSequence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	streamInput := make(chan harnessadapter.Event, 2)
	adapter := fixture.NewAdapter()
	adapter.StreamInput = streamInput
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "23000000-0000-4000-8000-000000000001")
	firstMessage := enqueue(t, ctx, opened, "23000000-0000-4000-8000-000000000002", dialogID, "first", 1)
	first := dispatch(t, ctx, opened)
	firstRef := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialogID, RequestID: firstMessage.RequestID, AttemptID: first.AttemptID, Generation: 1}
	streamInput <- harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: firstRef}, Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "none"}
	waitFor(t, func() bool { return currentSnapshot(t, ctx, opened).ActiveAttempt == nil })
	secondMessage := enqueue(t, ctx, opened, "23000000-0000-4000-8000-000000000003", dialogID, "second", 2)
	second := dispatch(t, ctx, opened)
	waitFor(t, func() bool {
		for _, call := range adapter.CallsSnapshot() {
			if call.Method == "resume" && call.Attempt.AttemptID == second.AttemptID {
				return true
			}
		}
		return false
	})
	for _, call := range adapter.CallsSnapshot() {
		if call.Method == "resume" && call.Attempt.AttemptID == second.AttemptID {
			if call.Context.MessageID != secondMessage.MessageID || call.Context.Sequence != 2 {
				t.Fatalf("second boundary=%+v", call.Context)
			}
		}
	}
	late := harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: firstRef}, Outcome: harnessadapter.ReconcileInterrupted, EffectStatus: "known"}
	if err := opened.ObserveAdapterEvent(ctx, firstRef, late); err != nil {
		t.Fatal(err)
	}
	lateDelta := harnessadapter.AssistantDeltaEvent{EventBase: harnessadapter.EventBase{Attempt: firstRef}, MessageID: "23000000-0000-4000-8000-000000000004", DeltaIndex: 0, Content: harnessprotocol.SafeContent{Kind: "inline", Content: "late", Redaction: "none"}}
	if err := opened.ObserveAdapterEvent(ctx, firstRef, lateDelta); err != nil {
		t.Fatal(err)
	}
	after := currentSnapshot(t, ctx, opened)
	if after.ActiveAttempt == nil || after.ActiveAttempt.AttemptID != second.AttemptID || after.ActiveAttempt.State != "running" {
		t.Fatalf("late terminal mutated new active slot: %+v", after.ActiveAttempt)
	}
	lateFound, lateDeltaFound := false, false
	for _, event := range attemptEvents(t, ctx, opened, first.AttemptID) {
		if event.Type == "attempt.interrupted" {
			lateFound = true
		}
		if event.Type == "assistant.delta" && event.EntityID == lateDelta.MessageID {
			lateDeltaFound = true
		}
	}
	if !lateFound || !lateDeltaFound {
		t.Fatalf("late projections terminal=%v delta=%v", lateFound, lateDeltaFound)
	}
}

func TestTerminalDuringUnresolvedSteerKeepsUnknownSlot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	streamInput := make(chan harnessadapter.Event, 1)
	steerGate := make(chan struct{})
	steerCalled := make(chan struct{}, 1)
	adapter := fixture.NewAdapter()
	adapter.StreamInput = streamInput
	adapter.SteerGate = steerGate
	adapter.SteerCalled = steerCalled
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "24000000-0000-4000-8000-000000000001")
	firstMessage := enqueue(t, ctx, opened, "24000000-0000-4000-8000-000000000002", dialogID, "first", 1)
	dispatched := dispatch(t, ctx, opened)
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.State == "running"
	})
	secondMessage := enqueue(t, ctx, opened, "24000000-0000-4000-8000-000000000003", dialogID, "steer", 2)
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "24000000-0000-4000-8000-000000000004", "message.steer", map[string]any{"nodeId": testNodeID, "dialogId": dialogID, "attemptId": dispatched.AttemptID, "messageId": secondMessage.MessageID}, map[string]any{"attemptGeneration": 1, "messageVersion": 1}, map[string]any{})), 202)
	select {
	case <-steerCalled:
	case <-ctx.Done():
		t.Fatal("steer was not called")
	}
	reference := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialogID, RequestID: firstMessage.RequestID, AttemptID: dispatched.AttemptID, Generation: 1}
	streamInput <- harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "known"}
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.State == "unknown"
	})
	if hasEventType(attemptEvents(t, ctx, opened, dispatched.AttemptID), "attempt.completed") {
		t.Fatal("terminal event bypassed unresolved steer fence")
	}
	close(steerGate)
}

func TestStopDuringBlockedStartCannotReviveAttemptOrOpenEvents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	startGate := make(chan struct{})
	startCalled := make(chan struct{}, 1)
	cancelCalled := make(chan struct{}, 1)
	eventsCalled := make(chan struct{}, 1)
	adapter := fixture.NewAdapter()
	adapter.StartGate = startGate
	adapter.StartCalled = startCalled
	adapter.CancelCalled = cancelCalled
	adapter.EventsCalled = eventsCalled
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "25000000-0000-4000-8000-000000000001")
	enqueue(t, ctx, opened, "25000000-0000-4000-8000-000000000002", dialogID, "run", 1)
	dispatched := dispatch(t, ctx, opened)
	select {
	case <-startCalled:
	case <-ctx.Done():
		t.Fatal("start was not called")
	}
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "25000000-0000-4000-8000-000000000003", "attempt.stop", map[string]any{"nodeId": testNodeID, "attemptId": dispatched.AttemptID}, map[string]any{"attemptGeneration": 1}, map[string]any{})), 202)
	select {
	case <-cancelCalled:
	case <-ctx.Done():
		t.Fatal("cancel was blocked behind Start")
	}
	close(startGate)
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.State == "unknown"
	})
	select {
	case <-eventsCalled:
		t.Fatal("late Start acknowledgement opened an event stream")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestBlockedSteersCannotConsumeReservedStopWorker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	streamInput := make(chan harnessadapter.Event)
	steerGate := make(chan struct{})
	steerCalled := make(chan struct{}, 8)
	cancelCalled := make(chan struct{}, 1)
	adapter := fixture.NewAdapter()
	adapter.StreamInput = streamInput
	adapter.SteerGate = steerGate
	adapter.SteerCalled = steerCalled
	adapter.CancelCalled = cancelCalled
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "26000000-0000-4000-8000-000000000001")
	enqueue(t, ctx, opened, "26000000-0000-4000-8000-000000000002", dialogID, "active", 1)
	dispatched := dispatch(t, ctx, opened)
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.State == "running"
	})
	for index := 0; index < 7; index++ {
		commandID := fmt.Sprintf("26000000-0000-4000-8000-%012d", 3+index)
		message := enqueue(t, ctx, opened, commandID, dialogID, "steer", int64(2+index))
		steerCommandID := fmt.Sprintf("26000000-0000-4000-8000-%012d", 10+index)
		decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, steerCommandID, "message.steer", map[string]any{"nodeId": testNodeID, "dialogId": dialogID, "attemptId": dispatched.AttemptID, "messageId": message.MessageID}, map[string]any{"attemptGeneration": 1, "messageVersion": 1}, map[string]any{})), 202)
	}
	for count := 0; count < 6; count++ {
		select {
		case <-steerCalled:
		case <-ctx.Done():
			t.Fatal("general control workers did not fill")
		}
	}
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "26000000-0000-4000-8000-000000000020", "attempt.stop", map[string]any{"nodeId": testNodeID, "attemptId": dispatched.AttemptID}, map[string]any{"attemptGeneration": 1}, map[string]any{})), 202)
	select {
	case <-cancelCalled:
	case <-ctx.Done():
		t.Fatal("stop was starved by blocked steer calls")
	}
	close(steerGate)
}

func TestTerminalFailureClassControlsReadiness(t *testing.T) {
	for _, test := range []struct {
		name          string
		class         harnessadapter.FailureClass
		wantReadiness string
		wantReason    string
	}{
		{name: "task releases ready node", class: harnessadapter.FailureTask, wantReadiness: "ready"},
		{name: "node blocks dispatch", class: harnessadapter.FailureNode, wantReadiness: "blocked", wantReason: "engine_unavailable"},
		{name: "policy blocks dispatch", class: harnessadapter.FailurePolicy, wantReadiness: "blocked", wantReason: "policy_unavailable"},
		{name: "protocol blocks dispatch", class: harnessadapter.FailureProtocol, wantReadiness: "blocked", wantReason: "adapter_protocol"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			streamInput := make(chan harnessadapter.Event, 1)
			adapter := fixture.NewAdapter()
			adapter.StreamInput = streamInput
			config := testConfig(t.TempDir())
			config.Adapter = adapter
			config.Policies = fixture.NewPolicySource()
			opened, err := node.Open(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			dialogID := createDialog(t, ctx, opened, "27000000-0000-4000-8000-000000000001")
			message := enqueue(t, ctx, opened, "27000000-0000-4000-8000-000000000002", dialogID, "run", 1)
			dispatched := dispatch(t, ctx, opened)
			reference := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialogID, RequestID: message.RequestID, AttemptID: dispatched.AttemptID, Generation: 1}
			streamInput <- harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, Outcome: harnessadapter.ReconcileFailed, Failure: &harnessadapter.Failure{Class: test.class, Code: "fixture_failure", SafeMessage: "fixture failed", Retryable: false}, EffectStatus: "none"}
			waitFor(t, func() bool { return currentSnapshot(t, ctx, opened).ActiveAttempt == nil })
			snapshot := currentSnapshot(t, ctx, opened)
			if snapshot.Node.EngineReadiness != test.wantReadiness {
				t.Fatalf("readiness=%s want=%s reasons=%v", snapshot.Node.EngineReadiness, test.wantReadiness, snapshot.Node.BlockedReasons)
			}
			if test.wantReason != "" && !slicesContains(snapshot.Node.BlockedReasons, test.wantReason) {
				t.Fatalf("missing reason %s in %v", test.wantReason, snapshot.Node.BlockedReasons)
			}
		})
	}
}

func TestSupervisorDispatchesFIFOAfterTerminalWithoutExternalPolling(t *testing.T) {
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
	dialogID := createDialog(t, ctx, opened, "28000000-0000-4000-8000-000000000001")
	first := enqueue(t, ctx, opened, "28000000-0000-4000-8000-000000000002", dialogID, "first", 1)
	waitFor(t, func() bool {
		for _, call := range adapter.CallsSnapshot() {
			if call.Method == "start" && call.Attempt.RequestID == first.RequestID {
				return true
			}
		}
		return false
	})
	second := enqueue(t, ctx, opened, "28000000-0000-4000-8000-000000000003", dialogID, "second", 2)
	var firstReference harnessadapter.AttemptRef
	for _, call := range adapter.CallsSnapshot() {
		if call.Method == "start" && call.Attempt.RequestID == first.RequestID {
			firstReference = call.Attempt
		}
	}
	streamInput <- harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: firstReference}, Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "none"}
	waitFor(t, func() bool {
		calls := make([]fixture.Call, 0, 2)
		for _, call := range adapter.CallsSnapshot() {
			if call.Method == "start" || call.Method == "resume" {
				calls = append(calls, call)
			}
		}
		return len(calls) == 2 && calls[0].Method == "start" && calls[0].Attempt.RequestID == first.RequestID && calls[1].Method == "resume" && calls[1].Attempt.RequestID == second.RequestID
	})
}

func TestAttemptOutputBudgetCountsDistinctContentAndArtifactOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	adapter := fixture.NewAdapter()
	adapter.StreamInput = make(chan harnessadapter.Event)
	dataDir := t.TempDir()
	config := testConfig(dataDir)
	config.ManualDispatchForTesting = true
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "29000000-0000-4000-8000-000000000001")
	message := enqueue(t, ctx, opened, "29000000-0000-4000-8000-000000000002", dialogID, "aggregate output", 1)
	dispatched := dispatch(t, ctx, opened)
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.State == "running"
	})
	reference := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialogID, RequestID: message.RequestID, AttemptID: dispatched.AttemptID, Generation: 1}
	callID := "29000000-0000-4000-8000-000000000003"
	input := harnessprotocol.SafeContent{Kind: "inline", Content: "i", Redaction: "none"}
	started := harnessadapter.ToolStartedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID, ToolName: "fixture.aggregate", ActionHash: strings.Repeat("b", 64), Input: input}
	if err := opened.ObserveAdapterEvent(ctx, reference, started); err != nil {
		t.Fatal(err)
	}
	metadata, err := opened.ArtifactSink().StoreArtifact(ctx, node.ArtifactInput{Attempt: reference, CallID: callID, Name: "small.bin", MediaType: "application/octet-stream", Redaction: "none", Disposition: "attachment"}, []byte("art"))
	if err != nil {
		t.Fatal(err)
	}
	size := metadata.SizeBytes
	artifact := harnessprotocol.SafeContent{Kind: "artifact", ArtifactID: metadata.ArtifactID, SizeBytes: &size, SHA256: metadata.SHA256, Redaction: "none"}
	toolOutput := harnessadapter.ToolOutputEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID, ChunkIndex: 0, Stream: "stdout", Output: artifact}
	if err := opened.ObserveAdapterEvent(ctx, reference, toolOutput); err != nil {
		t.Fatal(err)
	}
	inlineOutput := harnessadapter.ToolOutputEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID, ChunkIndex: 1, Stream: "stdout", Output: harnessprotocol.SafeContent{Kind: "inline", Content: "o", Redaction: "none"}}
	if err := opened.ObserveAdapterEvent(ctx, reference, inlineOutput); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, inlineOutput); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, toolOutput); err != nil {
		t.Fatal(err)
	}
	delta := harnessadapter.AssistantDeltaEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: "29000000-0000-4000-8000-000000000004", DeltaIndex: 0, Content: harnessprotocol.SafeContent{Kind: "inline", Content: "aa", Redaction: "none"}}
	if err := opened.ObserveAdapterEvent(ctx, reference, delta); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, delta); err != nil {
		t.Fatal(err)
	}
	completed := harnessadapter.ToolCompletedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID, Status: "succeeded", Result: harnessprotocol.SafeContent{Kind: "inline", Content: "bb", Redaction: "none"}, EffectStatus: "known", EffectRef: "fixture-effect"}
	if err := opened.ObserveAdapterEvent(ctx, reference, completed); err != nil {
		t.Fatal(err)
	}
	if got := attemptOutputBytes(t, ctx, dataDir, dispatched.AttemptID); got != 9 {
		t.Fatalf("aggregate bytes=%d want=9 (tool input 1 + artifact 3 + tool output 1 + assistant 2 + result 2)", got)
	}
}

func TestAttemptOutputBudgetReplacesAssistantAndToolCompletedOverflow(t *testing.T) {
	for _, kind := range []string{"assistant", "tool.completed"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			opened, _, dataDir, reference, cancelCalled := openOutputTestNode(t, ctx)
			defer opened.Close()
			var terminalOutput *harnessprotocol.SafeContent
			if kind == "tool.completed" {
				started := harnessadapter.ToolStartedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: "35000000-0000-4000-8000-000000000004", ToolName: "fixture.aggregate", ActionHash: strings.Repeat("c", 64), Input: harnessprotocol.SafeContent{Kind: "inline", Content: "q", Redaction: "none"}}
				if err := opened.ObserveAdapterEvent(ctx, reference, started); err != nil {
					t.Fatal(err)
				}
			}
			lifecycleSetAttemptOutputBytes(t, ctx, dataDir, reference.AttemptID, node.MaximumAttemptOutputBytes-1)
			content := harnessprotocol.SafeContent{Kind: "inline", Content: "xx", Redaction: "none"}
			if kind == "assistant" {
				terminalOutput = &content
				event := harnessadapter.AssistantMessageEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: "35000000-0000-4000-8000-000000000005", Content: content, FinishReason: "complete"}
				if err := opened.ObserveAdapterEvent(ctx, reference, event); err != nil {
					t.Fatal(err)
				}
			} else {
				event := harnessadapter.ToolCompletedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: "35000000-0000-4000-8000-000000000004", Status: "succeeded", Result: content, EffectStatus: "known", EffectRef: "fixture-effect"}
				if err := opened.ObserveAdapterEvent(ctx, reference, event); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-cancelCalled:
			case <-ctx.Done():
				t.Fatal("aggregate output limit did not wake native cancel")
			}
			found := false
			for _, event := range attemptEvents(t, ctx, opened, reference.AttemptID) {
				if event.Type != "assistant.message" && event.Type != "tool.completed" {
					continue
				}
				if kind == "assistant" && event.Type == "assistant.message" {
					var payload harnessprotocol.AssistantMessagePayload
					if json.Unmarshal(event.Payload, &payload) == nil && payload.Content.Kind == "unavailable" && payload.Content.Reason == "output_limit" {
						found = true
					}
				}
				if kind == "tool.completed" && event.Type == "tool.completed" {
					var payload harnessprotocol.ToolCompletedPayload
					if json.Unmarshal(event.Payload, &payload) == nil && payload.Result.Kind == "unavailable" && payload.Result.Reason == "output_limit" {
						found = true
					}
				}
			}
			if !found {
				t.Fatal("overflow projection did not expose output_limit")
			}
			if kind == "assistant" {
				terminal := harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, Outcome: harnessadapter.ReconcileCompleted, Output: terminalOutput, EffectStatus: "none"}
				if err := opened.ObserveAdapterEvent(ctx, reference, terminal); err != nil {
					t.Fatalf("terminal did not bind durable output_limit marker: %v", err)
				}
				if currentSnapshot(t, ctx, opened).ActiveAttempt != nil {
					t.Fatal("known terminal after output_limit did not release attempt")
				}
			}
		})
	}
}

func TestAttemptOutputBudgetFencesInteractiveOverflow(t *testing.T) {
	for _, kind := range []string{"approval", "input"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			opened, _, dataDir, reference, cancelCalled := openOutputTestNode(t, ctx)
			defer opened.Close()
			callID := "36000000-0000-4000-8000-000000000004"
			if kind == "approval" {
				started := harnessadapter.ToolStartedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID, ToolName: "fixture.approval", ActionHash: strings.Repeat("d", 64), Input: harnessprotocol.SafeContent{Kind: "inline", Content: "q", Redaction: "none"}}
				if err := opened.ObserveAdapterEvent(ctx, reference, started); err != nil {
					t.Fatal(err)
				}
			}
			lifecycleSetAttemptOutputBytes(t, ctx, dataDir, reference.AttemptID, node.MaximumAttemptOutputBytes-1)
			if kind == "approval" {
				event := harnessadapter.ApprovalRequestedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, ApprovalID: "36000000-0000-4000-8000-000000000005", CallID: callID, ActionHash: strings.Repeat("d", 64), SafePrompt: "xx"}
				if err := opened.ObserveAdapterEvent(ctx, reference, event); err != nil {
					t.Fatal(err)
				}
			} else {
				event := harnessadapter.InputRequestedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, InputRequestID: "36000000-0000-4000-8000-000000000006", Prompt: harnessprotocol.SafeContent{Kind: "inline", Content: "xx", Redaction: "none"}}
				if err := opened.ObserveAdapterEvent(ctx, reference, event); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-cancelCalled:
			case <-ctx.Done():
				t.Fatal("interactive overflow did not wake native cancel")
			}
			active := currentSnapshot(t, ctx, opened).ActiveAttempt
			if active == nil || active.State != "stopping" {
				t.Fatalf("interactive overflow revived waiting state: %+v", active)
			}
			if kind == "approval" {
				if hasEventType(attemptEvents(t, ctx, opened, reference.AttemptID), "approval.requested") {
					t.Fatal("approval overflow persisted an actionable approval")
				}
				if got := tableRows(t, ctx, dataDir, "approvals"); got != 0 {
					t.Fatalf("approval overflow persisted %d approval rows", got)
				}
			} else {
				found := false
				for _, event := range attemptEvents(t, ctx, opened, reference.AttemptID) {
					if event.Type != "input.requested" {
						continue
					}
					var payload harnessprotocol.InputRequestedPayload
					if json.Unmarshal(event.Payload, &payload) == nil && payload.Prompt.Kind == "unavailable" && payload.Prompt.Reason == "output_limit" {
						found = true
					}
				}
				if !found {
					t.Fatal("input overflow did not replace prompt")
				}
			}
		})
	}
}

func TestResumeContextMissingFailsClosedWithoutStartFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	streamInput := make(chan harnessadapter.Event, 1)
	adapter := fixture.NewAdapter()
	adapter.StreamInput = streamInput
	config := testConfig(t.TempDir())
	config.ManualDispatchForTesting = true
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "30000000-0000-4000-8000-000000000001")
	firstMessage := enqueue(t, ctx, opened, "30000000-0000-4000-8000-000000000002", dialogID, "first", 1)
	first := dispatch(t, ctx, opened)
	firstReference := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialogID, RequestID: firstMessage.RequestID, AttemptID: first.AttemptID, Generation: 1}
	streamInput <- harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: firstReference}, Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "none"}
	waitFor(t, func() bool { return currentSnapshot(t, ctx, opened).ActiveAttempt == nil })
	adapter.ResumeResult = harnessadapter.ResumeResult{Outcome: harnessadapter.ResumeContextMissing}
	secondMessage := enqueue(t, ctx, opened, "30000000-0000-4000-8000-000000000003", dialogID, "second", 2)
	second := dispatch(t, ctx, opened)
	waitFor(t, func() bool { return currentSnapshot(t, ctx, opened).ActiveAttempt == nil })
	startForSecond, resumeForSecond := false, false
	for _, call := range adapter.CallsSnapshot() {
		if call.Attempt.RequestID != secondMessage.RequestID {
			continue
		}
		startForSecond = startForSecond || call.Method == "start"
		resumeForSecond = resumeForSecond || call.Method == "resume"
	}
	if !resumeForSecond || startForSecond {
		t.Fatalf("resume calls did not fail closed: resume=%v startFallback=%v", resumeForSecond, startForSecond)
	}
	result := opened.Attempt(ctx, nodeTrust(), second.AttemptID)
	if result.HTTPStatus != 200 || !strings.Contains(string(result.Body), `"state":"failed"`) {
		t.Fatalf("resume rejection attempt status=%d body=%s", result.HTTPStatus, result.Body)
	}
}

func TestUnknownEffectsRemainFencedAfterTerminal(t *testing.T) {
	for _, test := range []struct {
		name  string
		steer bool
	}{
		{name: "terminal effect unknown"},
		{name: "steer outcome unknown before terminal", steer: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			streamInput := make(chan harnessadapter.Event, 1)
			adapter := fixture.NewAdapter()
			adapter.StreamInput = streamInput
			if test.steer {
				adapter.SteerResult = harnessadapter.SteerResult{Outcome: harnessadapter.SteerUnknown}
			}
			config := testConfig(t.TempDir())
			config.ManualDispatchForTesting = true
			config.Adapter = adapter
			config.Policies = fixture.NewPolicySource()
			opened, err := node.Open(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			dialogID := createDialog(t, ctx, opened, "31000000-0000-4000-8000-000000000001")
			message := enqueue(t, ctx, opened, "31000000-0000-4000-8000-000000000002", dialogID, "run", 1)
			dispatched := dispatch(t, ctx, opened)
			reference := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialogID, RequestID: message.RequestID, AttemptID: dispatched.AttemptID, Generation: 1}
			if test.steer {
				waitFor(t, func() bool {
					active := currentSnapshot(t, ctx, opened).ActiveAttempt
					return active != nil && active.State == "running"
				})
				steerMessage := enqueue(t, ctx, opened, "31000000-0000-4000-8000-000000000003", dialogID, "steer", 2)
				decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "31000000-0000-4000-8000-000000000004", "message.steer", map[string]any{"nodeId": testNodeID, "dialogId": dialogID, "attemptId": dispatched.AttemptID, "messageId": steerMessage.MessageID}, map[string]any{"attemptGeneration": 1, "messageVersion": 1}, map[string]any{})), 202)
				waitFor(t, func() bool {
					active := currentSnapshot(t, ctx, opened).ActiveAttempt
					return active != nil && active.State == "unknown"
				})
			}
			effectStatus := "unknown"
			if test.steer {
				effectStatus = "known"
			}
			streamInput <- harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, Outcome: harnessadapter.ReconcileCompleted, EffectStatus: effectStatus}
			waitFor(t, func() bool {
				active := currentSnapshot(t, ctx, opened).ActiveAttempt
				return active != nil && active.State == "unknown"
			})
			if hasEventType(attemptEvents(t, ctx, opened, dispatched.AttemptID), "attempt.completed") {
				t.Fatal("unknown effect terminal released the slot")
			}
		})
	}
}

func TestInvalidNativeOutcomeFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		cancel bool
	}{
		{name: "start"},
		{name: "cancel", cancel: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			adapter := fixture.NewAdapter()
			if test.cancel {
				adapter.CancelResult = harnessadapter.CancelResult{Outcome: harnessadapter.CancelOutcome("future")}
			} else {
				adapter.StartResult = harnessadapter.StartResult{Outcome: harnessadapter.StartOutcome("future")}
			}
			config := testConfig(t.TempDir())
			config.ManualDispatchForTesting = true
			config.Adapter = adapter
			config.Policies = fixture.NewPolicySource()
			opened, err := node.Open(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			dialogID := createDialog(t, ctx, opened, "32000000-0000-4000-8000-000000000001")
			enqueue(t, ctx, opened, "32000000-0000-4000-8000-000000000002", dialogID, "run", 1)
			dispatched := dispatch(t, ctx, opened)
			if test.cancel {
				waitFor(t, func() bool {
					active := currentSnapshot(t, ctx, opened).ActiveAttempt
					return active != nil && active.State == "running"
				})
				decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "32000000-0000-4000-8000-000000000003", "attempt.stop", map[string]any{"nodeId": testNodeID, "attemptId": dispatched.AttemptID}, map[string]any{"attemptGeneration": 1}, map[string]any{})), 202)
			}
			waitFor(t, func() bool {
				active := currentSnapshot(t, ctx, opened).ActiveAttempt
				return active != nil && active.State == "unknown"
			})
			found := false
			for _, event := range attemptEvents(t, ctx, opened, dispatched.AttemptID) {
				if event.Type != "attempt.unknown" {
					continue
				}
				var payload harnessprotocol.AttemptUnknownPayload
				if json.Unmarshal(event.Payload, &payload) == nil && payload.Reason == "adapter_protocol" {
					found = true
				}
			}
			if !found {
				t.Fatal("invalid native outcome was not classified adapter_protocol")
			}
		})
	}
}

func TestInvalidTerminalEffectStatusFailsClosed(t *testing.T) {
	for name, status := range map[string]string{"empty": "", "unmapped": "bogus"} {
		t.Run(name, func(t *testing.T) { assertInvalidTerminalEffectStatusFailsClosed(t, status) })
	}
}

func TestSuppressedInteractiveEventsValidateBeforeArchive(t *testing.T) {
	for _, test := range []struct {
		name    string
		unknown bool
	}{
		{name: "stopping invalid wait kind"},
		{name: "unknown oversized input", unknown: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			adapter := fixture.NewAdapter()
			dataDir := t.TempDir()
			config := testConfig(dataDir)
			config.ManualDispatchForTesting = true
			config.Adapter = adapter
			config.Policies = fixture.NewPolicySource()
			opened, err := node.Open(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			dialogID := createDialog(t, ctx, opened, "34000000-0000-4000-8000-000000000001")
			message := enqueue(t, ctx, opened, "34000000-0000-4000-8000-000000000002", dialogID, "run", 1)
			dispatched := dispatch(t, ctx, opened)
			waitFor(t, func() bool {
				active := currentSnapshot(t, ctx, opened).ActiveAttempt
				return active != nil && active.State == "running"
			})
			reference := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialogID, RequestID: message.RequestID, AttemptID: dispatched.AttemptID, Generation: 1}
			var invalid harnessadapter.Event
			if test.unknown {
				if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.UnknownEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, Reason: "provider_state", EffectStatus: "unknown"}); err != nil {
					t.Fatal(err)
				}
				invalid = harnessadapter.InputRequestedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, InputRequestID: "34000000-0000-4000-8000-000000000003", Prompt: harnessprotocol.SafeContent{Kind: "inline", Content: strings.Repeat("x", harnessprotocol.MaximumMessageBytes+1), Redaction: "none"}}
			} else {
				decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "34000000-0000-4000-8000-000000000004", "attempt.stop", map[string]any{"nodeId": testNodeID, "attemptId": dispatched.AttemptID}, map[string]any{"attemptGeneration": 1}, map[string]any{})), 202)
				waitFor(t, func() bool {
					active := currentSnapshot(t, ctx, opened).ActiveAttempt
					return active != nil && active.State == "stopping"
				})
				invalid = harnessadapter.WaitingEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, Kind: "future"}
			}
			before := currentSnapshot(t, ctx, opened)
			var beforeLate, beforeEvents int64
			reader, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, "harness.db")+"?mode=ro&_pragma=busy_timeout(5000)")
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if err := reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM late_observations").Scan(&beforeLate); err != nil {
				t.Fatal(err)
			}
			if err := reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&beforeEvents); err != nil {
				t.Fatal(err)
			}
			if err := opened.ObserveAdapterEvent(ctx, reference, invalid); err == nil {
				t.Fatal("invalid suppressed event was archived")
			}
			after := currentSnapshot(t, ctx, opened)
			var afterLate, afterEvents int64
			if err := reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM late_observations").Scan(&afterLate); err != nil {
				t.Fatal(err)
			}
			if err := reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&afterEvents); err != nil {
				t.Fatal(err)
			}
			if after.StateVersion != before.StateVersion || after.LastEventSeq != before.LastEventSeq || after.ActiveAttempt == nil || before.ActiveAttempt == nil || after.ActiveAttempt.State != before.ActiveAttempt.State {
				t.Fatalf("invalid suppressed event changed projection before=%+v after=%+v", before, after)
			}
			if afterLate != beforeLate || afterEvents != beforeEvents {
				t.Fatalf("invalid suppressed event persisted rows late=%d->%d events=%d->%d", beforeLate, afterLate, beforeEvents, afterEvents)
			}
		})
	}
}

func openOutputTestNode(t *testing.T, ctx context.Context) (*node.Node, *fixture.Adapter, string, harnessadapter.AttemptRef, <-chan struct{}) {
	t.Helper()
	adapter := fixture.NewAdapter()
	adapter.StreamInput = make(chan harnessadapter.Event)
	cancelCalled := make(chan struct{}, 1)
	adapter.CancelCalled = cancelCalled
	dataDir := t.TempDir()
	config := testConfig(dataDir)
	config.ManualDispatchForTesting = true
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	dialogID := createDialog(t, ctx, opened, "35000000-0000-4000-8000-000000000001")
	message := enqueue(t, ctx, opened, "35000000-0000-4000-8000-000000000002", dialogID, "aggregate boundary", 1)
	dispatched := dispatch(t, ctx, opened)
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.State == "running"
	})
	reference := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialogID, RequestID: message.RequestID, AttemptID: dispatched.AttemptID, Generation: 1}
	return opened, adapter, dataDir, reference, cancelCalled
}

func lifecycleSetAttemptOutputBytes(t *testing.T, ctx context.Context, dataDir, attemptID string, bytes int64) {
	t.Helper()
	// Fixture seeding shares the live node's DB with its stream writer.
	database, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, "harness.db")+"?mode=rw&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	result, err := database.ExecContext(ctx, "UPDATE attempts SET output_bytes=? WHERE attempt_id=?", bytes, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		t.Fatalf("seed output bytes changed=%d err=%v", changed, err)
	}
}

func attemptOutputBytes(t *testing.T, ctx context.Context, dataDir, attemptID string) int64 {
	t.Helper()
	database, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, "harness.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var bytes int64
	if err := database.QueryRowContext(ctx, "SELECT output_bytes FROM attempts WHERE attempt_id=?", attemptID).Scan(&bytes); err != nil {
		t.Fatal(err)
	}
	return bytes
}

func tableRows(t *testing.T, ctx context.Context, dataDir, table string) int64 {
	t.Helper()
	if table != "approvals" {
		t.Fatalf("unsupported test table %q", table)
	}
	database, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, "harness.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var rows int64
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM approvals").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func assertInvalidTerminalEffectStatusFailsClosed(t *testing.T, effectStatus string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	streamInput := make(chan harnessadapter.Event, 1)
	adapter := fixture.NewAdapter()
	adapter.StreamInput = streamInput
	config := testConfig(t.TempDir())
	config.ManualDispatchForTesting = true
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "33000000-0000-4000-8000-000000000001")
	message := enqueue(t, ctx, opened, "33000000-0000-4000-8000-000000000002", dialogID, "run", 1)
	dispatched := dispatch(t, ctx, opened)
	reference := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialogID, RequestID: message.RequestID, AttemptID: dispatched.AttemptID, Generation: 1}
	streamInput <- harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, Outcome: harnessadapter.ReconcileCompleted, EffectStatus: effectStatus}
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.State == "unknown"
	})
	completed, protocolUnknown := false, false
	for _, event := range attemptEvents(t, ctx, opened, dispatched.AttemptID) {
		completed = completed || event.Type == "attempt.completed"
		if event.Type == "attempt.unknown" {
			var payload harnessprotocol.AttemptUnknownPayload
			if json.Unmarshal(event.Payload, &payload) == nil && payload.Reason == "adapter_protocol" {
				protocolUnknown = true
			}
		}
	}
	if completed || !protocolUnknown {
		t.Fatalf("invalid terminal projection completed=%v protocolUnknown=%v", completed, protocolUnknown)
	}
}

func slicesContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
