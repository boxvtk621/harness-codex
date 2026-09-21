package node_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

type deltaOverflowRecoveryAdapter struct {
	*fixture.Adapter
	verificationErr error
}

func (adapter *deltaOverflowRecoveryAdapter) ConfirmPriorTerminal(ctx context.Context, _ harnessadapter.AttemptRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return adapter.verificationErr
}

func TestRecoverCodexDeltaOverflowRequiresExactDurableAndNativeEvidence(t *testing.T) {
	adapter := &deltaOverflowRecoveryAdapter{Adapter: fixture.NewAdapter()}
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, reference := runningAttemptWithConfig(t, config)
	defer opened.Close()

	callID := "63000000-0000-4000-8000-000000000001"
	messageID := "63000000-0000-4000-8000-000000000002"
	actionHash := strings.Repeat("d", 64)
	input := harnessprotocol.SafeContent{Kind: "inline", Content: "read", Redaction: "none"}
	result := harnessprotocol.SafeContent{Kind: "inline", Content: "network denied", Redaction: "none"}
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ToolStartedEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID,
		ToolName: "codex.command", ActionHash: actionHash, Input: input,
	}); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ToolOutputEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID,
		ChunkIndex: 0, Stream: "result", Output: result,
	}); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ToolCompletedEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID,
		Status: "failed", Result: result, EffectStatus: "none",
	}); err != nil {
		t.Fatal(err)
	}
	const deltaCount = int64(1024)
	for index := int64(0); index < deltaCount; index++ {
		if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.AssistantDeltaEvent{
			EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: messageID,
			DeltaIndex: index,
			Content:    harnessprotocol.SafeContent{Kind: "inline", Content: "x", Redaction: "none"},
		}); err != nil {
			t.Fatalf("delta %d: %v", index, err)
		}
	}
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.UnknownEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, Reason: "adapter_protocol", EffectStatus: "unknown",
	}); err != nil {
		t.Fatal(err)
	}

	read := opened.Attempt(context.Background(), nodeTrust(), reference.AttemptID)
	var attempt harnessprotocol.AttemptRead
	if read.HTTPStatus != 200 || json.Unmarshal(read.Body, &attempt) != nil || attempt.Attempt.State != "unknown" {
		t.Fatalf("unexpected recovery input: status=%d body=%s", read.HTTPStatus, read.Body)
	}
	events := allAttemptEvents(t, opened, reference.AttemptID)
	unknownSeq := int64(0)
	for _, event := range events {
		if event.Type == "attempt.unknown" {
			unknownSeq = event.Seq
		}
	}
	proof := node.CodexDeltaOverflowProof{
		Attempt: reference, ExpectedAttemptVersion: attempt.Attempt.Version,
		ExpectedUnknownSeq: unknownSeq, ExpectedDeltaCount: deltaCount,
		CallID: callID, ExpectedToolVersion: 2, ActionHash: actionHash,
	}
	wrong := proof
	wrong.ExpectedDeltaCount++
	if err := opened.RecoverCodexDeltaOverflow(context.Background(), wrong); err == nil {
		t.Fatal("mismatched delta count was accepted")
	}
	if snapshot := currentSnapshot(t, context.Background(), opened); snapshot.ActiveAttempt == nil || snapshot.ActiveAttempt.State != "unknown" {
		t.Fatalf("rejected proof changed the unknown fence: %+v", snapshot)
	}
	adapter.verificationErr = errors.New("native terminal unconfirmed")
	if err := opened.RecoverCodexDeltaOverflow(context.Background(), proof); err == nil {
		t.Fatal("missing native terminal proof was accepted")
	}
	adapter.verificationErr = nil
	if err := opened.RecoverCodexDeltaOverflow(context.Background(), proof); err != nil {
		t.Fatal(err)
	}
	if err := opened.RecoverCodexDeltaOverflow(context.Background(), proof); err != nil {
		t.Fatalf("exact replay was not idempotent: %v", err)
	}

	read = opened.Attempt(context.Background(), nodeTrust(), reference.AttemptID)
	if read.HTTPStatus != 200 || json.Unmarshal(read.Body, &attempt) != nil ||
		attempt.Attempt.State != "failed" || attempt.Attempt.EffectStatus != "none" {
		t.Fatalf("attempt was not recovered: status=%d body=%s", read.HTTPStatus, read.Body)
	}
	snapshot := currentSnapshot(t, context.Background(), opened)
	if snapshot.ActiveAttempt != nil || snapshot.Node.EngineReadiness != "ready" ||
		snapshot.Node.Occupancy != "idle" || len(snapshot.Node.BlockedReasons) != 0 {
		t.Fatalf("node remained fenced after recovery: %+v", snapshot)
	}
	events = allAttemptEvents(t, opened, reference.AttemptID)
	failed := 0
	for _, event := range events {
		if event.Type != "attempt.failed" {
			continue
		}
		failed++
		var payload harnessprotocol.AttemptFailedPayload
		if json.Unmarshal(event.Payload, &payload) != nil || payload.ErrorCode != "codex_delta_overflow" ||
			payload.FailureClass != "task" || !payload.Retryable || payload.EffectStatus != "none" {
			t.Fatalf("unexpected recovery failure: %s", event.Payload)
		}
	}
	if failed != 1 {
		t.Fatalf("recovery failures=%d want=1", failed)
	}
}

func allAttemptEvents(t *testing.T, opened *node.Node, attemptID string) []harnessprotocol.EventEnvelope {
	t.Helper()
	var events []harnessprotocol.EventEnvelope
	after := int64(0)
	for {
		result := opened.AttemptEvents(context.Background(), nodeTrust(), attemptID, after, 100)
		if result.HTTPStatus != 200 {
			t.Fatalf("events status=%d body=%s", result.HTTPStatus, result.Body)
		}
		var page struct {
			Items []harnessprotocol.EventEnvelope `json:"items"`
		}
		if err := json.Unmarshal(result.Body, &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Items) == 0 {
			return events
		}
		events = append(events, page.Items...)
		after = page.Items[len(page.Items)-1].Seq
	}
}
