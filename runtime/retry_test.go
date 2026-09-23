package node_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

func TestDistinctRetryCommandsCannotReserveTheSameInputTwice(t *testing.T) {
	ctx := context.Background()
	opened, prior := runningAttempt(t, t.TempDir())
	defer opened.Close()
	if err := opened.Observe(ctx, node.Observation{AttemptID: prior.AttemptID, Generation: prior.Generation, Kind: "terminal", TerminalState: "failed", EffectStatus: "none", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	retry := func(commandID string) []byte {
		return command(t, commandID, "attempt.retry", map[string]any{"nodeId": testNodeID, "attemptId": prior.AttemptID}, map[string]any{"attemptGeneration": prior.Generation}, map[string]any{"acknowledgeKnownEffects": false})
	}
	firstCommand := retry("10000000-0000-4000-8000-000000000301")
	first := opened.SubmitCommand(ctx, nodeTrust(), firstCommand)
	firstReceipt := decodeReceipt(t, first, 202)
	var firstRefs harnessprotocol.AttemptRetryReferences
	if err := json.Unmarshal(firstReceipt.References, &firstRefs); err != nil {
		t.Fatal(err)
	}
	second := opened.SubmitCommand(ctx, nodeTrust(), retry("10000000-0000-4000-8000-000000000302"))
	if second.HTTPStatus != 409 {
		t.Fatalf("second retry status=%d body=%s", second.HTTPStatus, second.Body)
	}
	var failure harnessprotocol.Error
	if err := json.Unmarshal(second.Body, &failure); err != nil || failure.Code != "stale" {
		t.Fatalf("second retry failure=%+v err=%v", failure, err)
	}
	replay := opened.SubmitCommand(ctx, nodeTrust(), firstCommand)
	if replay.HTTPStatus != 200 || string(replay.Body) != string(first.Body) {
		t.Fatalf("same command replay status=%d body=%s want=%s", replay.HTTPStatus, replay.Body, first.Body)
	}
	result := opened.Snapshot(ctx, nodeTrust())
	if result.HTTPStatus != 200 {
		t.Fatalf("snapshot status=%d body=%s", result.HTTPStatus, result.Body)
	}
	var snapshot harnessprotocol.Snapshot
	if err := json.Unmarshal(result.Body, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Node.PendingCount != 1 || len(snapshot.PendingQueue) != 1 || snapshot.PendingQueue[0].RequestID != firstRefs.RequestID || snapshot.PendingQueue[0].InputMessageID == "" {
		t.Fatalf("duplicate retry changed pending reservation: %+v", snapshot)
	}
}

func TestRetryRejectsSupersededAttemptAndNewerOriginal(t *testing.T) {
	for _, scenario := range []string{"completed-retry", "failed-retry", "newer-queued", "newer-completed", "newer-unknown"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			opened, prior := runningAttempt(t, t.TempDir())
			defer opened.Close()
			if err := opened.Observe(ctx, node.Observation{AttemptID: prior.AttemptID, Generation: prior.Generation, Kind: "terminal", TerminalState: "failed", EffectStatus: "none", Confirmed: true}); err != nil {
				t.Fatal(err)
			}
			retry := func(id string) node.Result {
				return opened.SubmitCommand(ctx, nodeTrust(), command(t, id, "attempt.retry", map[string]any{"nodeId": testNodeID, "attemptId": prior.AttemptID}, map[string]any{"attemptGeneration": prior.Generation}, map[string]any{"acknowledgeKnownEffects": false}))
			}
			if scenario == "completed-retry" || scenario == "failed-retry" {
				decodeReceipt(t, retry("10000000-0000-4000-8000-000000000311"), 202)
			} else {
				enqueue(t, ctx, opened, "10000000-0000-4000-8000-000000000312", prior.DialogID, "newer", 2)
			}
			if scenario != "newer-queued" {
				next := dispatch(t, ctx, opened)
				waitFor(t, func() bool {
					return currentSnapshot(t, ctx, opened).ActiveAttempt != nil && currentSnapshot(t, ctx, opened).ActiveAttempt.State == "running"
				})
				active := currentSnapshot(t, ctx, opened).ActiveAttempt
				terminal, effects := "completed", "none"
				if scenario == "failed-retry" {
					terminal = "failed"
				}
				if scenario == "newer-unknown" {
					terminal = "failed"
					effects = "unknown"
				}
				if err := opened.Observe(ctx, node.Observation{AttemptID: next.AttemptID, Generation: active.Generation, Kind: "terminal", TerminalState: terminal, EffectStatus: effects, Confirmed: true}); err != nil {
					t.Fatal(err)
				}
			}
			result := retry("10000000-0000-4000-8000-000000000313")
			if result.HTTPStatus != 409 {
				t.Fatalf("unsafe retry admitted: %d %s", result.HTTPStatus, result.Body)
			}
		})
	}
}
