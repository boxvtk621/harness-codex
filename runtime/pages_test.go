package node_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

func TestTypedPagesScopeAndStaleCursor(t *testing.T) {
	ctx := context.Background()
	opened, reference := runningAttempt(t, t.TempDir())
	defer opened.Close()
	assertWire := func(wire string, result node.Result) {
		t.Helper()
		if result.HTTPStatus != 200 {
			t.Fatalf("%s status=%d body=%s", wire, result.HTTPStatus, result.Body)
		}
		if err := harnessprotocol.Validate(wire, result.Body); err != nil {
			t.Fatalf("%s invalid: %v body=%s", wire, err, result.Body)
		}
	}
	assertWire("historyPage", opened.History(ctx, nodeTrust(), reference.DialogID, "", 1))
	assertWire("requestPage", opened.Requests(ctx, nodeTrust(), "active", "", 1))
	assertWire("attemptRead", opened.Attempt(ctx, nodeTrust(), reference.AttemptID))
	assertWire("attemptPage", opened.Attempts(ctx, nodeTrust(), reference.RequestID, "", 1))
	assertWire("eventPage", opened.AttemptEvents(ctx, nodeTrust(), reference.AttemptID, 0, 1))
	if result := opened.Attempt(ctx, nodeTrust(), "10000000-0000-4000-8000-000000000299"); result.HTTPStatus != 404 {
		t.Fatalf("missing attempt=%d body=%s", result.HTTPStatus, result.Body)
	}
	for index := 0; index < 2; index++ {
		id := "10000000-0000-4000-8000-00000000022" + string(rune('0'+index))
		result := opened.SubmitCommand(ctx, nodeTrust(), command(t, id, "dialog.create", map[string]any{"nodeId": testNodeID}, map[string]any{"registryVersion": 1}, map[string]any{}))
		if result.HTTPStatus != 202 {
			t.Fatalf("create page dialog=%d %s", result.HTTPStatus, result.Body)
		}
	}
	page := opened.Dialogs(ctx, nodeTrust(), "", 1)
	assertWire("dialogPage", page)
	var decoded harnessprotocol.Page[harnessprotocol.DialogSummary]
	if err := json.Unmarshal(page.Body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.NextCursor == nil {
		t.Fatal("dialog cursor missing")
	}
	result := opened.SubmitCommand(ctx, nodeTrust(), command(t, "10000000-0000-4000-8000-000000000229", "dialog.create", map[string]any{"nodeId": testNodeID}, map[string]any{"registryVersion": 1}, map[string]any{}))
	if result.HTTPStatus != 202 {
		t.Fatal(result.HTTPStatus, string(result.Body))
	}
	if stale := opened.Dialogs(ctx, nodeTrust(), *decoded.NextCursor, 1); stale.HTTPStatus != 409 {
		t.Fatalf("stale cursor=%d body=%s", stale.HTTPStatus, stale.Body)
	}
	if foreign := opened.History(ctx, node.TrustContext{ActorID: "1-2", TransportNodeID: testNodeID, PeerVerified: true}, reference.DialogID, "", 1); foreign.HTTPStatus != 403 {
		t.Fatalf("foreign history=%d", foreign.HTTPStatus)
	}
}

func TestHistoryPageStopsAtWireByteBudget(t *testing.T) {
	ctx := context.Background()
	config := testConfig(t.TempDir())
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	created := decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t, "10000000-0000-4000-8000-000000000301", "dialog.create", map[string]any{"nodeId": testNodeID}, map[string]any{"registryVersion": 1}, map[string]any{})), 202)
	var d harnessprotocol.DialogCreateReferences
	_ = json.Unmarshal(created.References, &d)
	text := strings.Repeat("<", harnessprotocol.MaximumMessageBytes)
	for i := 0; i < 25; i++ {
		id := fmt.Sprintf("10000000-0000-4000-8000-%012d", 400+i)
		result := opened.SubmitCommand(ctx, nodeTrust(), command(t, id, "message.enqueue", map[string]any{"nodeId": testNodeID, "dialogId": d.DialogID}, map[string]any{"dialogVersion": int64(i + 1)}, map[string]any{"text": text}))
		if result.HTTPStatus != 202 {
			t.Fatalf("enqueue %d: %d %s", i, result.HTTPStatus, result.Body)
		}
	}
	result := opened.History(ctx, nodeTrust(), d.DialogID, "", 100)
	if result.HTTPStatus != 200 || len(result.Body) > harnessprotocol.MaximumWireBytes {
		t.Fatalf("history status=%d bytes=%d", result.HTTPStatus, len(result.Body))
	}
	var page struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor *string           `json:"nextCursor"`
	}
	if err := json.Unmarshal(result.Body, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) >= 25 || page.NextCursor == nil {
		t.Fatalf("byte budget did not paginate: items=%d cursor=%v", len(page.Items), page.NextCursor)
	}
}

func TestRecoverySnapshotExcludesUnknownActiveRequest(t *testing.T) {
	path := t.TempDir()
	opened, active := runningAttempt(t, path)
	queued := command(t, "10000000-0000-4000-8000-000000000299", "message.enqueue", map[string]any{"nodeId": testNodeID, "dialogId": active.DialogID}, map[string]any{"dialogVersion": 2}, map[string]any{"text": "after recovery"})
	decodeReceipt(t, opened.SubmitCommand(context.Background(), nodeTrust(), queued), 202)
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	config := testConfig(path)
	config.Policies = fixture.NewPolicySource()
	reopened, err := node.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	result := reopened.Snapshot(context.Background(), nodeTrust())
	if result.HTTPStatus != 200 {
		t.Fatalf("snapshot status=%d body=%s", result.HTTPStatus, result.Body)
	}
	var snapshot harnessprotocol.Snapshot
	if err := json.Unmarshal(result.Body, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.ActiveAttempt == nil || snapshot.ActiveAttempt.AttemptID != active.AttemptID || snapshot.ActiveAttempt.State != "unknown" || len(snapshot.PendingQueue) != 1 || snapshot.PendingQueue[0].Status != "queued" || snapshot.Node.PendingCount != 1 || snapshot.Node.QueuePaused || slices.Contains(snapshot.Node.BlockedReasons, "operator_pause") {
		t.Fatalf("unexpected recovery snapshot: %+v", snapshot)
	}
}

func TestRecoverySnapshotPreservesExistingManualPause(t *testing.T) {
	path := t.TempDir()
	opened, active := runningAttempt(t, path)
	stop := command(t, "10000000-0000-4000-8000-000000000298", "attempt.stop", map[string]any{"nodeId": testNodeID, "attemptId": active.AttemptID}, map[string]any{"attemptGeneration": active.Generation}, map[string]any{})
	decodeReceipt(t, opened.SubmitCommand(context.Background(), nodeTrust(), stop), 202)
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	config := testConfig(path)
	config.Policies = fixture.NewPolicySource()
	reopened, err := node.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	result := reopened.Snapshot(context.Background(), nodeTrust())
	if result.HTTPStatus != 200 {
		t.Fatalf("snapshot status=%d body=%s", result.HTTPStatus, result.Body)
	}
	var snapshot harnessprotocol.Snapshot
	if err := json.Unmarshal(result.Body, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.ActiveAttempt == nil || snapshot.ActiveAttempt.State != "unknown" || !snapshot.Node.QueuePaused || !slices.Contains(snapshot.Node.BlockedReasons, "operator_pause") {
		t.Fatalf("manual pause changed during recovery: %+v", snapshot)
	}
}
