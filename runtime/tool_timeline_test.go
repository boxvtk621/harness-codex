package node_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/internal/dialogview"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/tooltimeline"
	"github.com/boxvtk621/harness-codex/runtime"
)

func TestToolTimelineIsStablePagedAndSafe(t *testing.T) {
	ctx := context.Background()
	opened, reference := runningAttempt(t, t.TempDir())
	defer opened.Close()
	content := harnessprotocol.SafeContent{Kind: "inline", Content: "safe preview", Redaction: "none"}
	actionHash := strings.Repeat("a", 64)
	calls := []string{"35000000-0000-4000-8000-000000000001", "35000000-0000-4000-8000-000000000002"}
	for _, callID := range calls {
		if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.ToolStartedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID, ToolName: "fixture.echo", ActionHash: actionHash, Input: content}); err != nil {
			t.Fatal(err)
		}
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.ToolOutputEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: calls[1], ChunkIndex: 0, Stream: "stdout", Output: content}); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.ToolOutputEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: calls[1], ChunkIndex: 1, Stream: "stderr", Output: content}); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.ToolCompletedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: calls[1], Status: "succeeded", Result: content, EffectStatus: "known", EffectRef: "private-effect-ref"}); err != nil {
		t.Fatal(err)
	}

	first := opened.ToolCalls(ctx, nodeTrust(), reference.AttemptID, "", 1)
	if first.HTTPStatus != 200 {
		t.Fatalf("timeline status=%d body=%s", first.HTTPStatus, first.Body)
	}
	var page tooltimeline.Page
	if json.Unmarshal(first.Body, &page) != nil || page.SchemaID != tooltimeline.SchemaID || len(page.Items) != 1 || page.Items[0].ToolCallID != calls[0] || page.NextCursor == nil {
		t.Fatalf("unexpected first page: %s", first.Body)
	}
	third := "35000000-0000-4000-8000-000000000003"
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.ToolStartedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: third, ToolName: "fixture.echo", ActionHash: actionHash, Input: content}); err != nil {
		t.Fatal(err)
	}
	second := opened.ToolCalls(ctx, nodeTrust(), reference.AttemptID, *page.NextCursor, 2)
	if second.HTTPStatus != 200 || json.Unmarshal(second.Body, &page) != nil || len(page.Items) != 2 || page.Items[0].ToolCallID != calls[1] || page.Items[1].ToolCallID != third {
		t.Fatalf("stable second page status=%d body=%s", second.HTTPStatus, second.Body)
	}

	detailResult := opened.ToolCall(ctx, nodeTrust(), reference.AttemptID, calls[1], 0, 1)
	if detailResult.HTTPStatus != 200 || strings.Contains(string(detailResult.Body), actionHash) || strings.Contains(string(detailResult.Body), "private-effect-ref") {
		t.Fatalf("unsafe detail status=%d body=%s", detailResult.HTTPStatus, detailResult.Body)
	}
	var detail tooltimeline.DetailRead
	if json.Unmarshal(detailResult.Body, &detail) != nil || detail.ToolCall.State != "succeeded" || detail.ToolCall.Result == nil || len(detail.ToolCall.Outputs) != 1 || detail.ToolCall.NextOutputCursor == nil {
		t.Fatalf("unexpected detail: %s", detailResult.Body)
	}
	continued := opened.ToolCall(ctx, nodeTrust(), reference.AttemptID, calls[1], mustInt64(t, *detail.ToolCall.NextOutputCursor), 1)
	if continued.HTTPStatus != 200 || json.Unmarshal(continued.Body, &detail) != nil || len(detail.ToolCall.Outputs) != 1 || detail.ToolCall.Outputs[0].Index != 1 {
		t.Fatalf("unexpected continued detail: %s", continued.Body)
	}
}

func mustInt64(t *testing.T, value string) int64 {
	t.Helper()
	var parsed int64
	if _, err := fmt.Sscan(value, &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestLatestHistoryCursorSurvivesNewMessages(t *testing.T) {
	ctx := context.Background()
	opened, err := node.Open(ctx, testConfig(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	created := decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "10000000-0000-4000-8000-000000000701", "dialog.create", map[string]any{"nodeId": testNodeID}, map[string]any{"registryVersion": 1}, map[string]any{})), 202)
	var refs harnessprotocol.DialogCreateReferences
	_ = json.Unmarshal(created.References, &refs)
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("10000000-0000-4000-8000-%012d", 702+i)
		decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, id, "message.enqueue", map[string]any{"nodeId": testNodeID, "dialogId": refs.DialogID}, map[string]any{"dialogVersion": int64(i + 1)}, map[string]any{"text": fmt.Sprintf("message-%d", i+1)})), 202)
	}
	latest := opened.HistoryLatest(ctx, nodeTrust(), refs.DialogID, "", 2)
	var page struct {
		Items      []harnessprotocol.UserHistoryItem `json:"items"`
		NextCursor *string                           `json:"nextCursor"`
	}
	if latest.HTTPStatus != 200 || json.Unmarshal(latest.Body, &page) != nil || len(page.Items) != 2 || page.Items[0].Sequence != 2 || page.Items[1].Sequence != 3 || page.NextCursor == nil {
		t.Fatalf("latest page status=%d body=%s", latest.HTTPStatus, latest.Body)
	}
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "10000000-0000-4000-8000-000000000705", "message.enqueue", map[string]any{"nodeId": testNodeID, "dialogId": refs.DialogID}, map[string]any{"dialogVersion": 4}, map[string]any{"text": "new append"})), 202)
	older := opened.HistoryLatest(ctx, nodeTrust(), refs.DialogID, *page.NextCursor, 2)
	if older.HTTPStatus != 200 || json.Unmarshal(older.Body, &page) != nil || len(page.Items) != 1 || page.Items[0].Sequence != 1 {
		t.Fatalf("older page status=%d body=%s", older.HTTPStatus, older.Body)
	}
}

func TestDialogActivityViewExposesStableStateAndActivity(t *testing.T) {
	ctx := context.Background()
	config := testConfig(t.TempDir())
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	config.Clock = func() time.Time {
		now = now.Add(time.Second)
		return now
	}
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	created := decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "10000000-0000-4000-8000-000000000711", "dialog.create", map[string]any{"nodeId": testNodeID}, map[string]any{"registryVersion": 1}, map[string]any{"title": "Activity"})), 202)
	var refs harnessprotocol.DialogCreateReferences
	_ = json.Unmarshal(created.References, &refs)
	read := opened.DialogView(ctx, nodeTrust(), refs.DialogID)
	var decoded dialogview.Read
	if read.HTTPStatus != 200 || json.Unmarshal(read.Body, &decoded) != nil || decoded.Dialog.State != "idle" || decoded.Dialog.LastActivityAt != decoded.Dialog.CreatedAt {
		t.Fatalf("idle dialog status=%d body=%s", read.HTTPStatus, read.Body)
	}
	otherDialogs := make([]string, 0, 2)
	for index := 0; index < 2; index++ {
		other := decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, fmt.Sprintf("10000000-0000-4000-8000-%012d", 712+index), "dialog.create", map[string]any{"nodeId": testNodeID}, map[string]any{"registryVersion": 1}, map[string]any{"title": fmt.Sprintf("Other %d", index)})), 202)
		var otherRefs harnessprotocol.DialogCreateReferences
		_ = json.Unmarshal(other.References, &otherRefs)
		otherDialogs = append(otherDialogs, otherRefs.DialogID)
	}
	enqueued := decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "10000000-0000-4000-8000-000000000714", "message.enqueue", map[string]any{"nodeId": testNodeID, "dialogId": refs.DialogID}, map[string]any{"dialogVersion": 1}, map[string]any{"text": "activity"})), 202)
	var messageRefs harnessprotocol.MessageEnqueueReferences
	_ = json.Unmarshal(enqueued.References, &messageRefs)
	read = opened.DialogView(ctx, nodeTrust(), refs.DialogID)
	if read.HTTPStatus != 200 || json.Unmarshal(read.Body, &decoded) != nil || decoded.Dialog.State != "queued" || decoded.Dialog.ActiveRequestID != messageRefs.RequestID || decoded.Dialog.LastActivityAt < decoded.Dialog.CreatedAt {
		t.Fatalf("queued dialog status=%d body=%s", read.HTTPStatus, read.Body)
	}
	page := opened.DialogViews(ctx, nodeTrust(), "", 1)
	var listed dialogview.Page
	if page.HTTPStatus != 200 || json.Unmarshal(page.Body, &listed) != nil || len(listed.Items) != 1 || listed.Items[0].DialogID != refs.DialogID || listed.Items[0].State != "queued" || listed.NextCursor == nil {
		t.Fatalf("dialog activity page status=%d body=%s", page.HTTPStatus, page.Body)
	}
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "10000000-0000-4000-8000-000000000715", "message.enqueue", map[string]any{"nodeId": testNodeID, "dialogId": otherDialogs[0]}, map[string]any{"dialogVersion": 1}, map[string]any{"text": "activity after first page"})), 202)
	stale := opened.DialogViews(ctx, nodeTrust(), *listed.NextCursor, 1)
	if stale.HTTPStatus != 409 {
		t.Fatalf("mutable activity continuation status=%d body=%s", stale.HTTPStatus, stale.Body)
	}
}
