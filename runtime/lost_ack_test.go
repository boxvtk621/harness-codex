package node_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

func TestCommittedStopWakesWorkerBeforeReceiptDeliveryFailure(t *testing.T) {
	ctx := context.Background()
	adapter := fixture.NewAdapter()
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, active := runningAttemptWithConfig(t, config)
	defer opened.Close()
	stop := command(t, "10000000-0000-4000-8000-000000000320", "attempt.stop", map[string]any{"nodeId": testNodeID, "attemptId": active.AttemptID}, map[string]any{"attemptGeneration": active.Generation}, map[string]any{})
	opened.SetFaultInjector(func(point node.FaultPoint) error {
		if point == node.FaultAfterCommit {
			return errors.New("synthetic lost receipt")
		}
		return nil
	})
	lost := opened.SubmitCommand(ctx, nodeTrust(), stop)
	if lost.HTTPStatus != 503 || !lost.Committed {
		t.Fatalf("lost ACK status=%d committed=%v body=%s", lost.HTTPStatus, lost.Committed, lost.Body)
	}
	opened.SetFaultInjector(nil)
	waitFor(t, func() bool {
		cancelCount := 0
		for _, call := range adapter.CallsSnapshot() {
			if call.Method == "cancel" {
				cancelCount++
			}
		}
		return cancelCount == 1
	})
	var snapshot harnessprotocol.Snapshot
	snapshotResult := opened.Snapshot(ctx, nodeTrust())
	if snapshotResult.HTTPStatus != 200 || json.Unmarshal(snapshotResult.Body, &snapshot) != nil || !snapshot.Node.QueuePaused || snapshot.ActiveAttempt == nil || snapshot.ActiveAttempt.State != "stopping" {
		t.Fatalf("committed stop projection missing: status=%d snapshot=%+v", snapshotResult.HTTPStatus, snapshot)
	}
	status := opened.CommandStatus(ctx, nodeTrust(), "10000000-0000-4000-8000-000000000320")
	if status.HTTPStatus != 200 {
		t.Fatalf("command status=%d body=%s", status.HTTPStatus, status.Body)
	}
	var commandStatus harnessprotocol.CommandStatus
	if err := json.Unmarshal(status.Body, &commandStatus); err != nil {
		t.Fatal(err)
	}
	wantReceipt, err := json.Marshal(commandStatus.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	replay := opened.SubmitCommand(ctx, nodeTrust(), stop)
	if replay.HTTPStatus != 200 || string(replay.Body) != string(wantReceipt) {
		t.Fatalf("replay status=%d body=%s want=%s", replay.HTTPStatus, replay.Body, wantReceipt)
	}
	time.Sleep(20 * time.Millisecond)
	cancelCount := 0
	for _, call := range adapter.CallsSnapshot() {
		if call.Method == "cancel" {
			cancelCount++
		}
	}
	if cancelCount != 1 {
		t.Fatalf("lost ACK replay invoked %d cancels", cancelCount)
	}
}
