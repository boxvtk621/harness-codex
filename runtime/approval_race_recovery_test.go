package node_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

type approvalRaceRecoveryAdapter struct {
	*fixture.Adapter
	approvalCalled  chan<- struct{}
	approvalRelease <-chan struct{}
	verificationErr error
}

func (adapter *approvalRaceRecoveryAdapter) RespondApproval(ctx context.Context, input harnessadapter.RespondApprovalInput) (harnessadapter.ResponseResult, error) {
	if adapter.approvalCalled != nil {
		select {
		case adapter.approvalCalled <- struct{}{}:
		default:
		}
	}
	if adapter.approvalRelease != nil {
		select {
		case <-adapter.approvalRelease:
		case <-ctx.Done():
			return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseUnknown}, ctx.Err()
		}
	}
	return harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseUnknown}, nil
}

func (adapter *approvalRaceRecoveryAdapter) ConfirmCompletedApprovalRace(ctx context.Context, _ harnessadapter.AttemptRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return adapter.verificationErr
}

func TestRecoverCompletedApprovalRaceRequiresExactDurableAndNativeEvidence(t *testing.T) {
	called := make(chan struct{}, 1)
	release := make(chan struct{})
	adapter := &approvalRaceRecoveryAdapter{
		Adapter: fixture.NewAdapter(), approvalCalled: called, approvalRelease: release,
	}
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, reference := runningAttemptWithConfig(t, config)
	defer opened.Close()

	callID := "61000000-0000-4000-8000-000000000001"
	approvalID := "61000000-0000-4000-8000-000000000002"
	commandID := "61000000-0000-4000-8000-000000000003"
	messageID := "61000000-0000-4000-8000-000000000004"
	actionHash := strings.Repeat("a", 64)
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ToolStartedEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID,
		ToolName: "codex.file_change", ActionHash: actionHash,
		Input: harnessprotocol.SafeContent{Kind: "inline", Content: "change", Redaction: "none"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ApprovalRequestedEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, ApprovalID: approvalID,
		CallID: callID, ActionHash: actionHash, SafePrompt: "Изменить файл?",
	}); err != nil {
		t.Fatal(err)
	}
	approval := command(t, commandID, "approval.respond",
		map[string]any{"nodeId": testNodeID, "approvalId": approvalID, "attemptId": reference.AttemptID},
		map[string]any{"approvalVersion": 1, "attemptGeneration": reference.Generation},
		map[string]any{"decision": "allow_once", "actionHash": actionHash})
	decodeReceipt(t, opened.SubmitCommand(context.Background(), nodeTrust(), approval), 202)
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("approval response was not called")
	}
	resultContent := harnessprotocol.SafeContent{Kind: "inline", Content: "changed", Redaction: "none"}
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ToolOutputEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID,
		ChunkIndex: 0, Stream: "result", Output: resultContent,
	}); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ToolCompletedEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID,
		Status: "succeeded", Result: resultContent, EffectStatus: "known", EffectRef: actionHash,
	}); err != nil {
		t.Fatal(err)
	}
	close(release)
	waitFor(t, func() bool {
		snapshot := currentSnapshot(t, context.Background(), opened)
		return snapshot.ActiveAttempt != nil && snapshot.ActiveAttempt.State == "unknown"
	})
	assistant := harnessprotocol.SafeContent{Kind: "inline", Content: "Готово.", Redaction: "none"}
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.AssistantMessageEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: messageID,
		Content: assistant, FinishReason: "complete",
	}); err != nil {
		t.Fatal(err)
	}

	read := opened.Attempt(context.Background(), nodeTrust(), reference.AttemptID)
	var attempt harnessprotocol.AttemptRead
	if read.HTTPStatus != 200 || json.Unmarshal(read.Body, &attempt) != nil || attempt.Attempt.State != "unknown" {
		t.Fatalf("unexpected repair input: status=%d body=%s", read.HTTPStatus, read.Body)
	}
	proof := node.CompletedApprovalRaceProof{
		Attempt: reference, ExpectedAttemptVersion: attempt.Attempt.Version,
		ApprovalID: approvalID, ExpectedApprovalVersion: 2,
		CallID: callID, ExpectedToolVersion: 2, ActionHash: actionHash,
		CommandID: commandID, AssistantMessageID: messageID,
	}
	wrong := proof
	wrong.ActionHash = strings.Repeat("b", 64)
	if err := opened.RecoverCompletedApprovalRace(context.Background(), wrong); err == nil {
		t.Fatal("mismatched action hash was accepted")
	}
	if snapshot := currentSnapshot(t, context.Background(), opened); snapshot.ActiveAttempt == nil || snapshot.ActiveAttempt.State != "unknown" {
		t.Fatalf("rejected proof changed the unknown fence: %+v", snapshot)
	}
	adapter.verificationErr = errors.New("native terminal unconfirmed")
	if err := opened.RecoverCompletedApprovalRace(context.Background(), proof); err == nil {
		t.Fatal("missing native terminal proof was accepted")
	}
	adapter.verificationErr = nil
	if err := opened.RecoverCompletedApprovalRace(context.Background(), proof); err != nil {
		t.Fatal(err)
	}
	if err := opened.RecoverCompletedApprovalRace(context.Background(), proof); err != nil {
		t.Fatalf("exact replay was not idempotent: %v", err)
	}

	read = opened.Attempt(context.Background(), nodeTrust(), reference.AttemptID)
	if read.HTTPStatus != 200 || json.Unmarshal(read.Body, &attempt) != nil ||
		attempt.Attempt.State != "completed" || attempt.Attempt.EffectStatus != "known" {
		t.Fatalf("attempt was not recovered: status=%d body=%s", read.HTTPStatus, read.Body)
	}
	events := attemptEvents(t, context.Background(), opened, reference.AttemptID)
	resolved, completed := 0, 0
	for _, event := range events {
		switch event.Type {
		case "approval.resolved":
			resolved++
		case "attempt.completed":
			completed++
			var payload harnessprotocol.AttemptCompletedPayload
			if json.Unmarshal(event.Payload, &payload) != nil || payload.Output.Kind != "message" || payload.Output.AssistantMessageID != messageID {
				t.Fatalf("completion does not reference final message: %s", event.Payload)
			}
		}
	}
	if resolved != 1 || completed != 1 {
		t.Fatalf("recovery events: resolved=%d completed=%d events=%+v", resolved, completed, events)
	}
}

func TestRecoverCompletedApprovalRaceAcceptsExactDeniedNoEffectTurn(t *testing.T) {
	called := make(chan struct{}, 1)
	release := make(chan struct{})
	adapter := &approvalRaceRecoveryAdapter{
		Adapter: fixture.NewAdapter(), approvalCalled: called, approvalRelease: release,
	}
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, reference := runningAttemptWithConfig(t, config)
	defer opened.Close()

	callID := "62000000-0000-4000-8000-000000000001"
	approvalID := "62000000-0000-4000-8000-000000000002"
	commandID := "62000000-0000-4000-8000-000000000003"
	firstMessageID := "62000000-0000-4000-8000-000000000004"
	finalMessageID := "62000000-0000-4000-8000-000000000005"
	actionHash := strings.Repeat("c", 64)
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.AssistantMessageEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: firstMessageID,
		Content: harnessprotocol.SafeContent{Kind: "inline", Content: "Запрашиваю подтверждение.", Redaction: "none"}, FinishReason: "complete",
	}); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ToolStartedEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID,
		ToolName: "codex.file_change", ActionHash: actionHash,
		Input: harnessprotocol.SafeContent{Kind: "inline", Content: "change", Redaction: "none"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ApprovalRequestedEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, ApprovalID: approvalID,
		CallID: callID, ActionHash: actionHash, SafePrompt: "Изменить файл?",
	}); err != nil {
		t.Fatal(err)
	}
	approval := command(t, commandID, "approval.respond",
		map[string]any{"nodeId": testNodeID, "approvalId": approvalID, "attemptId": reference.AttemptID},
		map[string]any{"approvalVersion": 1, "attemptGeneration": reference.Generation},
		map[string]any{"decision": "deny", "actionHash": actionHash})
	decodeReceipt(t, opened.SubmitCommand(context.Background(), nodeTrust(), approval), 202)
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("approval response was not called")
	}
	resultContent := harnessprotocol.SafeContent{Kind: "inline", Content: "Операция отклонена.", Redaction: "none"}
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ToolOutputEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID,
		ChunkIndex: 0, Stream: "result", Output: resultContent,
	}); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ToolCompletedEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID,
		Status: "failed", Result: resultContent, EffectStatus: "none",
	}); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.AssistantMessageEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: finalMessageID,
		Content: harnessprotocol.SafeContent{Kind: "inline", Content: "Изменение не выполнено.", Redaction: "none"}, FinishReason: "complete",
	}); err != nil {
		t.Fatal(err)
	}
	close(release)
	waitFor(t, func() bool {
		snapshot := currentSnapshot(t, context.Background(), opened)
		return snapshot.ActiveAttempt != nil && snapshot.ActiveAttempt.State == "unknown"
	})

	read := opened.Attempt(context.Background(), nodeTrust(), reference.AttemptID)
	var attempt harnessprotocol.AttemptRead
	if read.HTTPStatus != 200 || json.Unmarshal(read.Body, &attempt) != nil || attempt.Attempt.State != "unknown" {
		t.Fatalf("unexpected repair input: status=%d body=%s", read.HTTPStatus, read.Body)
	}
	proof := node.CompletedApprovalRaceProof{
		Attempt: reference, ExpectedAttemptVersion: attempt.Attempt.Version,
		ApprovalID: approvalID, ExpectedApprovalVersion: 2, Decision: "deny",
		CallID: callID, ExpectedToolVersion: 2, ActionHash: actionHash,
		CommandID: commandID, AssistantMessageID: finalMessageID,
	}
	wrong := proof
	wrong.Decision = "allow_once"
	if err := opened.RecoverCompletedApprovalRace(context.Background(), wrong); err == nil {
		t.Fatal("mismatched approval decision was accepted")
	}
	if err := opened.RecoverCompletedApprovalRace(context.Background(), proof); err != nil {
		t.Fatal(err)
	}
	if err := opened.RecoverCompletedApprovalRace(context.Background(), proof); err != nil {
		t.Fatalf("exact replay was not idempotent: %v", err)
	}

	read = opened.Attempt(context.Background(), nodeTrust(), reference.AttemptID)
	if read.HTTPStatus != 200 || json.Unmarshal(read.Body, &attempt) != nil ||
		attempt.Attempt.State != "completed" || attempt.Attempt.EffectStatus != "none" {
		t.Fatalf("denied attempt was not recovered: status=%d body=%s", read.HTTPStatus, read.Body)
	}
	events := attemptEvents(t, context.Background(), opened, reference.AttemptID)
	resolved, completed := 0, 0
	for _, event := range events {
		switch event.Type {
		case "approval.resolved":
			resolved++
			var payload harnessprotocol.ApprovalResolvedPayload
			if json.Unmarshal(event.Payload, &payload) != nil || payload.Decision != "deny" {
				t.Fatalf("resolution does not preserve denial: %s", event.Payload)
			}
		case "attempt.completed":
			completed++
			var payload harnessprotocol.AttemptCompletedPayload
			if json.Unmarshal(event.Payload, &payload) != nil || payload.Output.Kind != "message" || payload.Output.AssistantMessageID != finalMessageID {
				t.Fatalf("completion does not reference final denial message: %s", event.Payload)
			}
		}
	}
	if resolved != 1 || completed != 1 {
		t.Fatalf("denial recovery events: resolved=%d completed=%d events=%+v", resolved, completed, events)
	}
}
