package node_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessbarrier"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

func operatorTrust() node.OperatorTrustContext {
	return node.OperatorTrustContext{TransportNodeID: testNodeID}
}

func holdRequest(t *testing.T, operationID string, scope harnessbarrier.Scope, epoch, scopeRevision int64) []byte {
	t.Helper()
	raw, err := json.Marshal(harnessbarrier.InstallRequest{
		ProtocolVersion: harnessbarrier.ProtocolVersion, SchemaID: harnessbarrier.SchemaID,
		OperationID: operationID, NodeID: testNodeID, ExpectedEpoch: epoch, BindingGeneration: 1,
		Scope: scope, ExpectedScopeRevision: scopeRevision,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func installHold(t *testing.T, opened *node.Node, raw []byte, status int) harnessbarrier.HoldReceipt {
	t.Helper()
	result := opened.InstallHold(context.Background(), operatorTrust(), raw)
	if result.HTTPStatus != status {
		t.Fatalf("hold status=%d want=%d body=%s", result.HTTPStatus, status, result.Body)
	}
	if err := harnessbarrier.Validate("holdReceipt", result.Body); err != nil {
		t.Fatalf("invalid hold receipt: %v body=%s", err, result.Body)
	}
	var receipt harnessbarrier.HoldReceipt
	if err := json.Unmarshal(result.Body, &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func proofForHold(t *testing.T, opened *node.Node, operationID string, status int) harnessbarrier.QuiescenceProof {
	t.Helper()
	result := opened.QuiescenceProof(context.Background(), operatorTrust(), operationID)
	if result.HTTPStatus != status {
		t.Fatalf("proof status=%d want=%d body=%s", result.HTTPStatus, status, result.Body)
	}
	if status != http.StatusOK {
		return harnessbarrier.QuiescenceProof{}
	}
	if err := harnessbarrier.Validate("quiescenceProof", result.Body); err != nil {
		t.Fatalf("invalid proof: %v body=%s", err, result.Body)
	}
	var proof harnessbarrier.QuiescenceProof
	if json.Unmarshal(result.Body, &proof) != nil {
		t.Fatal("cannot decode proof")
	}
	return proof
}

func releaseRequest(t *testing.T, hold harnessbarrier.HoldReceipt, action string) []byte {
	t.Helper()
	raw, err := json.Marshal(harnessbarrier.ReleaseRequest{
		ProtocolVersion: harnessbarrier.ProtocolVersion, SchemaID: harnessbarrier.SchemaID,
		OperationID: hold.OperationID, NodeID: hold.NodeID, ExpectedEpoch: hold.Epoch,
		BindingGeneration: hold.BindingGeneration, Scope: hold.Scope, HoldVersion: hold.HoldVersion,
		ExpectedScopeRevision: hold.ScopeRevision, Action: action,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func rejectionReceipt(t *testing.T, result node.Result) harnessbarrier.RejectionReceipt {
	t.Helper()
	if result.HTTPStatus != http.StatusConflict {
		t.Fatalf("rejection status=%d body=%s", result.HTTPStatus, result.Body)
	}
	if err := harnessbarrier.Validate("rejectionReceipt", result.Body); err != nil {
		t.Fatalf("invalid rejection receipt: %v body=%s", err, result.Body)
	}
	var receipt harnessbarrier.RejectionReceipt
	if err := json.Unmarshal(result.Body, &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

type switchableSpace struct {
	low bool
}

type gatedPolicySource struct {
	inner   *fixture.PolicySource
	entered chan struct{}
	release <-chan struct{}
}

func (source *gatedPolicySource) Current(ctx context.Context, dialogID string) (harnessadapter.PolicySnapshot, error) {
	select {
	case source.entered <- struct{}{}:
	default:
	}
	select {
	case <-source.release:
		return source.inner.Current(ctx, dialogID)
	case <-ctx.Done():
		return harnessadapter.PolicySnapshot{}, ctx.Err()
	}
}

func (space *switchableSpace) Measure(string) (node.SpaceInfo, error) {
	if space.low {
		return node.SpaceInfo{FreeBytes: 0, TotalBytes: 64 << 30}, nil
	}
	return node.SpaceInfo{FreeBytes: 16 << 30, TotalBytes: 64 << 30}, nil
}

func TestNodeHoldDurablyRejectsLateAdmissionWithoutQueueMutation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	path := t.TempDir()
	adapter := fixture.NewAdapter()
	config := testConfig(path)
	config.Adapter = adapter
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opened.Close() }()

	dialogID := createDialog(t, ctx, opened, "51000000-0000-4000-8000-000000000001")
	accepted := enqueue(t, ctx, opened, "51000000-0000-4000-8000-000000000002", dialogID, "accepted before hold", 1)
	before := currentSnapshot(t, ctx, opened)
	holdRaw := holdRequest(t, "node-hold-1", harnessbarrier.Scope{Kind: "node"}, before.Epoch, 0)
	hold := installHold(t, opened, holdRaw, http.StatusCreated)
	status := opened.HoldStatus(ctx, operatorTrust(), hold.OperationID)
	if status.HTTPStatus != http.StatusOK || !bytes.Equal(status.Body, mustJSONBytes(t, hold)) {
		t.Fatalf("hold readback changed: status=%d body=%s", status.HTTPStatus, status.Body)
	}
	replayedHold := opened.InstallHold(ctx, operatorTrust(), holdRaw)
	if replayedHold.HTTPStatus != http.StatusOK || !bytes.Equal(replayedHold.Body, status.Body) {
		t.Fatalf("hold replay changed: status=%d body=%s", replayedHold.HTTPStatus, replayedHold.Body)
	}
	conflictingHold := holdRequest(t, "node-hold-1", harnessbarrier.Scope{Kind: "node"}, before.Epoch, 9)
	assertWireError(t, opened.InstallHold(ctx, operatorTrust(), conflictingHold), http.StatusConflict, "id_conflict")

	late := command(t, "51000000-0000-4000-8000-000000000003", "message.enqueue",
		map[string]any{"nodeId": testNodeID, "dialogId": dialogID}, map[string]any{"dialogVersion": 2}, map[string]any{"text": "late"})
	rejected := opened.SubmitCommand(ctx, nodeTrust(), late)
	rejection := rejectionReceipt(t, rejected)
	if rejection.HoldOperationID != hold.OperationID || rejection.HoldVersion != hold.HoldVersion || rejection.Scope.Kind != "node" {
		t.Fatalf("rejection not bound to hold: %+v", rejection)
	}
	after := currentSnapshot(t, ctx, opened)
	if after.StateVersion != before.StateVersion || after.LastEventSeq != before.LastEventSeq ||
		after.Node.QueueVersion != before.Node.QueueVersion || after.Node.PendingCount != before.Node.PendingCount ||
		!reflect.DeepEqual(after.PendingQueue, before.PendingQueue) || after.PendingQueue[0].RequestID != accepted.RequestID {
		t.Fatalf("late rejection changed queue/checkpoint: before=%+v after=%+v", before, after)
	}
	if replay := opened.SubmitCommand(ctx, nodeTrust(), late); replay.HTTPStatus != http.StatusConflict || !bytes.Equal(replay.Body, rejected.Body) {
		t.Fatalf("rejected replay changed: status=%d body=%s", replay.HTTPStatus, replay.Body)
	}
	lateDifferent := command(t, "51000000-0000-4000-8000-000000000003", "message.enqueue",
		map[string]any{"nodeId": testNodeID, "dialogId": dialogID}, map[string]any{"dialogVersion": 2}, map[string]any{"text": "different"})
	assertWireError(t, opened.SubmitCommand(ctx, nodeTrust(), lateDifferent), http.StatusConflict, "id_conflict")
	readback := opened.CommandStatus(ctx, nodeTrust(), rejection.CommandID)
	if readback.HTTPStatus != http.StatusConflict || !bytes.Equal(readback.Body, rejected.Body) {
		t.Fatalf("rejection readback changed: status=%d body=%s", readback.HTTPStatus, readback.Body)
	}

	opened.SetFaultInjector(func(point node.FaultPoint) error {
		if point == node.FaultBeforeRejectionCommit {
			return errors.New("synthetic before rejection commit")
		}
		return nil
	})
	rolledBack := command(t, "51000000-0000-4000-8000-000000000004", "dialog.create",
		map[string]any{"nodeId": testNodeID}, map[string]any{"registryVersion": 1}, map[string]any{})
	beforeFault := opened.SubmitCommand(ctx, nodeTrust(), rolledBack)
	assertWireError(t, beforeFault, http.StatusServiceUnavailable, "not_durable")
	if beforeFault.Committed || opened.CommandStatus(ctx, nodeTrust(), "51000000-0000-4000-8000-000000000004").HTTPStatus != http.StatusNotFound {
		t.Fatal("pre-commit rejection fault left a durable decision")
	}
	opened.SetFaultInjector(nil)
	rejectionReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), rolledBack))

	opened.SetFaultInjector(func(point node.FaultPoint) error {
		if point == node.FaultAfterRejectionCommit {
			return errors.New("synthetic lost rejection receipt")
		}
		return nil
	})
	lost := command(t, "51000000-0000-4000-8000-000000000005", "queue.resume",
		map[string]any{"nodeId": testNodeID}, map[string]any{"queueVersion": before.Node.QueueVersion}, map[string]any{})
	lostResult := opened.SubmitCommand(ctx, nodeTrust(), lost)
	assertWireError(t, lostResult, http.StatusServiceUnavailable, "node_unavailable")
	if !lostResult.Committed {
		t.Fatal("post-commit rejection fault was not marked committed")
	}
	opened.SetFaultInjector(nil)
	lostReplay := opened.SubmitCommand(ctx, nodeTrust(), lost)
	rejectionReceipt(t, lostReplay)

	if next, err := opened.DispatchNext(ctx); err != nil || next.AttemptID != "" {
		t.Fatalf("node hold permitted dispatch: %+v err=%v", next, err)
	}
	if len(adapter.CallsSnapshot()) != 0 {
		t.Fatalf("node hold invoked adapter: %+v", adapter.CallsSnapshot())
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	opened = reopened
	if replay := reopened.SubmitCommand(ctx, nodeTrust(), late); replay.HTTPStatus != http.StatusConflict || !bytes.Equal(replay.Body, rejected.Body) {
		t.Fatalf("restart changed rejected replay: status=%d body=%s", replay.HTTPStatus, replay.Body)
	}
	if read := reopened.HoldStatus(ctx, operatorTrust(), hold.OperationID); read.HTTPStatus != http.StatusOK || !bytes.Equal(read.Body, status.Body) {
		t.Fatalf("restart changed hold: status=%d body=%s", read.HTTPStatus, read.Body)
	}
	if replay := reopened.SubmitCommand(ctx, nodeTrust(), lost); replay.HTTPStatus != http.StatusConflict || !bytes.Equal(replay.Body, lostReplay.Body) {
		t.Fatalf("restart changed lost rejection: status=%d body=%s", replay.HTTPStatus, replay.Body)
	}
	cancelCommand := command(t, "51000000-0000-4000-8000-000000000006", "request.cancel",
		map[string]any{"nodeId": testNodeID, "requestId": accepted.RequestID}, map[string]any{"requestVersion": 1}, map[string]any{})
	decodeReceipt(t, reopened.SubmitCommand(ctx, nodeTrust(), cancelCommand), http.StatusAccepted)
}

func TestDialogHoldsPreserveFIFOAndDoNotBlockSiblingDispatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	adapter := fixture.NewAdapter()
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()

	dialogA := createDialog(t, ctx, opened, "52000000-0000-4000-8000-000000000001")
	dialogB := createDialog(t, ctx, opened, "52000000-0000-4000-8000-000000000002")
	requestA := enqueue(t, ctx, opened, "52000000-0000-4000-8000-000000000003", dialogA, "held head", 1)
	requestB := enqueue(t, ctx, opened, "52000000-0000-4000-8000-000000000004", dialogB, "eligible sibling", 1)
	before := currentSnapshot(t, ctx, opened)
	lateA := command(t, "52000000-0000-4000-8000-000000000005", "message.enqueue",
		map[string]any{"nodeId": testNodeID, "dialogId": dialogA}, map[string]any{"dialogVersion": 2}, map[string]any{"text": "late A"})
	deliverLate := make(chan struct{})
	lateResult := make(chan node.Result, 1)
	go func() {
		<-deliverLate
		lateResult <- opened.SubmitCommand(ctx, nodeTrust(), lateA)
	}()
	holdA := installHold(t, opened, holdRequest(t, "dialog-hold-a", harnessbarrier.Scope{Kind: "dialog", DialogID: dialogA}, before.Epoch, 0), http.StatusCreated)
	close(deliverLate)
	if rejected := rejectionReceipt(t, <-lateResult); rejected.HoldOperationID != holdA.OperationID {
		t.Fatalf("dialog rejection used wrong hold: %+v", rejected)
	}
	requestB2 := enqueue(t, ctx, opened, "52000000-0000-4000-8000-000000000006", dialogB, "eligible sibling tail", 2)

	const racers = 16
	answers := make(chan node.DispatchResult, racers)
	errorsCh := make(chan error, racers)
	var workers sync.WaitGroup
	for i := 0; i < racers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			result, err := opened.DispatchNext(ctx)
			answers <- result
			errorsCh <- err
		}()
	}
	workers.Wait()
	close(answers)
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	attempts := 0
	for answer := range answers {
		if answer.AttemptID != "" {
			attempts++
			if answer.RequestID != requestB.RequestID {
				t.Fatalf("held head was dispatched or FIFO skipped wrong request: %+v", answer)
			}
		}
	}
	if attempts != 1 {
		t.Fatalf("concurrent dispatch created %d attempts", attempts)
	}
	waitFor(t, func() bool {
		snapshot := currentSnapshot(t, ctx, opened)
		return snapshot.ActiveAttempt != nil && snapshot.ActiveAttempt.RequestID == requestB.RequestID && snapshot.ActiveAttempt.State == "running"
	})
	after := currentSnapshot(t, ctx, opened)
	if len(after.PendingQueue) != 2 || after.PendingQueue[0].RequestID != requestA.RequestID || after.PendingQueue[1].RequestID != requestB2.RequestID {
		t.Fatalf("held FIFO/sibling tail changed: %+v", after.PendingQueue)
	}
	holdB := installHold(t, opened, holdRequest(t, "dialog-hold-b", harnessbarrier.Scope{Kind: "dialog", DialogID: dialogB}, after.Epoch, 0), http.StatusCreated)
	if holdB.ScopeRevision != 1 || holdA.ScopeRevision != 1 {
		t.Fatalf("dialog-local revisions were coupled: A=%+v B=%+v", holdA, holdB)
	}
	steer := command(t, "52000000-0000-4000-8000-000000000007", "message.steer",
		map[string]any{"nodeId": testNodeID, "dialogId": dialogB, "attemptId": after.ActiveAttempt.AttemptID, "messageId": requestB2.MessageID},
		map[string]any{"attemptGeneration": 1, "messageVersion": 1}, map[string]any{})
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), steer), http.StatusAccepted)
	waitFor(t, func() bool {
		for _, call := range adapter.CallsSnapshot() {
			if call.Method == "steer" {
				return true
			}
		}
		return false
	})
	starts, steers := 0, 0
	for _, call := range adapter.CallsSnapshot() {
		switch call.Method {
		case "start":
			starts++
		case "steer":
			steers++
		}
	}
	if starts != 1 || steers != 1 {
		t.Fatalf("barrier adapter calls start=%d steer=%d calls=%+v", starts, steers, adapter.CallsSnapshot())
	}
	if err := opened.Observe(ctx, node.Observation{AttemptID: after.ActiveAttempt.AttemptID, Generation: 1, Kind: "terminal", TerminalState: "failed", EffectStatus: "none", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	retry := command(t, "52000000-0000-4000-8000-000000000008", "attempt.retry",
		map[string]any{"nodeId": testNodeID, "attemptId": after.ActiveAttempt.AttemptID}, map[string]any{"attemptGeneration": 1}, map[string]any{"acknowledgeKnownEffects": false})
	rejectionReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), retry))
	cancelA := command(t, "52000000-0000-4000-8000-000000000009", "request.cancel",
		map[string]any{"nodeId": testNodeID, "requestId": requestA.RequestID}, map[string]any{"requestVersion": 1}, map[string]any{})
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), cancelA), http.StatusAccepted)
}

func TestHoldCommitFaultsRollbackAndPreserveExactReadback(t *testing.T) {
	ctx := context.Background()
	opened, err := node.Open(ctx, testConfig(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	request := holdRequest(t, "faulted-hold", harnessbarrier.Scope{Kind: "node"}, currentSnapshot(t, ctx, opened).Epoch, 0)
	opened.SetFaultInjector(func(point node.FaultPoint) error {
		if point == node.FaultBeforeHoldCommit {
			return errors.New("synthetic before hold commit")
		}
		return nil
	})
	before := opened.InstallHold(ctx, operatorTrust(), request)
	assertWireError(t, before, http.StatusServiceUnavailable, "not_durable")
	if before.Committed || opened.HoldStatus(ctx, operatorTrust(), "faulted-hold").HTTPStatus != http.StatusNotFound {
		t.Fatal("pre-commit hold fault left durable state")
	}
	opened.SetFaultInjector(func(point node.FaultPoint) error {
		if point == node.FaultAfterHoldCommit {
			return errors.New("synthetic lost hold receipt")
		}
		return nil
	})
	after := opened.InstallHold(ctx, operatorTrust(), request)
	assertWireError(t, after, http.StatusServiceUnavailable, "node_unavailable")
	if !after.Committed {
		t.Fatal("post-commit hold fault was not marked committed")
	}
	opened.SetFaultInjector(nil)
	readback := opened.HoldStatus(ctx, operatorTrust(), "faulted-hold")
	if readback.HTTPStatus != http.StatusOK || harnessbarrier.Validate("holdReceipt", readback.Body) != nil {
		t.Fatalf("committed hold unavailable: status=%d body=%s", readback.HTTPStatus, readback.Body)
	}
	replay := opened.InstallHold(ctx, operatorTrust(), request)
	if replay.HTTPStatus != http.StatusOK || !bytes.Equal(replay.Body, readback.Body) {
		t.Fatalf("hold replay changed: status=%d body=%s", replay.HTTPStatus, replay.Body)
	}
}

func TestDialogHoldWinsBetweenPolicyLookupAndDispatchClaim(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	release := make(chan struct{})
	policies := &gatedPolicySource{inner: fixture.NewPolicySource(), entered: make(chan struct{}, 1), release: release}
	config := testConfig(t.TempDir())
	config.Policies = policies
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogA := createDialog(t, ctx, opened, "52600000-0000-4000-8000-000000000001")
	dialogB := createDialog(t, ctx, opened, "52600000-0000-4000-8000-000000000002")
	enqueue(t, ctx, opened, "52600000-0000-4000-8000-000000000003", dialogA, "selected before hold", 1)
	requestB := enqueue(t, ctx, opened, "52600000-0000-4000-8000-000000000004", dialogB, "eligible after hold", 1)
	epoch := currentSnapshot(t, ctx, opened).Epoch
	dispatchDone := make(chan node.DispatchResult, 1)
	dispatchErr := make(chan error, 1)
	go func() {
		result, err := opened.DispatchNext(ctx)
		dispatchDone <- result
		dispatchErr <- err
	}()
	select {
	case <-policies.entered:
	case <-ctx.Done():
		t.Fatal("policy lookup was not reached")
	}
	installHold(t, opened, holdRequest(t, "hold-during-policy", harnessbarrier.Scope{Kind: "dialog", DialogID: dialogA}, epoch, 0), http.StatusCreated)
	close(release)
	if err := <-dispatchErr; err != nil {
		t.Fatal(err)
	}
	if result := <-dispatchDone; result.Outcome != "changed" || result.AttemptID != "" {
		t.Fatalf("stale policy candidate crossed hold: %+v", result)
	}
	second, err := opened.DispatchNext(ctx)
	if err != nil || second.RequestID != requestB.RequestID || second.AttemptID == "" {
		t.Fatalf("eligible sibling did not dispatch: %+v err=%v", second, err)
	}
}

func TestHeldAdmissionUsesControlReserveBelowAdmissionFloor(t *testing.T) {
	ctx := context.Background()
	space := &switchableSpace{}
	config := testConfig(t.TempDir())
	config.Space = space
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "52500000-0000-4000-8000-000000000001")
	snapshot := currentSnapshot(t, ctx, opened)
	installHold(t, opened, holdRequest(t, "low-storage-hold", harnessbarrier.Scope{Kind: "dialog", DialogID: dialogID}, snapshot.Epoch, 0), http.StatusCreated)
	space.low = true
	late := command(t, "52500000-0000-4000-8000-000000000002", "message.enqueue",
		map[string]any{"nodeId": testNodeID, "dialogId": dialogID}, map[string]any{"dialogVersion": 1}, map[string]any{"text": "late below floor"})
	rejectionReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), late))
	if after := currentSnapshot(t, ctx, opened); after.StateVersion != snapshot.StateVersion || after.LastEventSeq != snapshot.LastEventSeq || after.Node.PendingCount != 0 {
		t.Fatalf("low-storage rejection changed checkpoint: before=%+v after=%+v", snapshot, after)
	}
}

func TestHoldWaitsForCrossedAdapterStartGate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
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
	dialogID := createDialog(t, ctx, opened, "53000000-0000-4000-8000-000000000001")
	enqueue(t, ctx, opened, "53000000-0000-4000-8000-000000000002", dialogID, "cross start gate", 1)
	dispatched := dispatch(t, ctx, opened)
	select {
	case <-startCalled:
	case <-ctx.Done():
		t.Fatal("adapter start was not reached")
	}
	holdResult := make(chan node.Result, 1)
	request := holdRequest(t, "hold-after-start-crossed", harnessbarrier.Scope{Kind: "dialog", DialogID: dialogID}, currentSnapshot(t, ctx, opened).Epoch, 0)
	go func() { holdResult <- opened.InstallHold(ctx, operatorTrust(), request) }()
	select {
	case result := <-holdResult:
		t.Fatalf("hold overtook an in-flight Start: status=%d body=%s", result.HTTPStatus, result.Body)
	case <-time.After(20 * time.Millisecond):
	}
	close(startGate)
	var installed node.Result
	select {
	case installed = <-holdResult:
	case <-ctx.Done():
		t.Fatal("hold did not complete after Start")
	}
	if installed.HTTPStatus != http.StatusCreated || harnessbarrier.Validate("holdReceipt", installed.Body) != nil {
		t.Fatalf("hold failed after crossed Start: status=%d body=%s", installed.HTTPStatus, installed.Body)
	}
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.AttemptID == dispatched.AttemptID && active.State == "running"
	})
	late := command(t, "53000000-0000-4000-8000-000000000003", "message.enqueue",
		map[string]any{"nodeId": testNodeID, "dialogId": dialogID}, map[string]any{"dialogVersion": 2}, map[string]any{"text": "must not start"})
	rejectionReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), late))
}

func TestHoldDoesNotCommitAcrossDurablePreStartIntent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	adapter := fixture.NewAdapter()
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	dialogID := createDialog(t, ctx, opened, "54000000-0000-4000-8000-000000000001")
	enqueue(t, ctx, opened, "54000000-0000-4000-8000-000000000002", dialogID, "durable intent", 1)
	epoch := currentSnapshot(t, ctx, opened).Epoch
	intentCommitted := make(chan struct{}, 1)
	releaseDispatch := make(chan struct{})
	opened.SetFaultInjector(func(point node.FaultPoint) error {
		if point == node.FaultAfterDispatchIntent {
			intentCommitted <- struct{}{}
			<-releaseDispatch
			return errors.New("synthetic dispatch interruption")
		}
		return nil
	})
	dispatchDone := make(chan error, 1)
	go func() {
		_, err := opened.DispatchNext(ctx)
		dispatchDone <- err
	}()
	select {
	case <-intentCommitted:
	case <-ctx.Done():
		t.Fatal("dispatch intent was not committed")
	}
	holdDone := make(chan node.Result, 1)
	request := holdRequest(t, "hold-vs-prestart", harnessbarrier.Scope{Kind: "dialog", DialogID: dialogID}, epoch, 0)
	go func() { holdDone <- opened.InstallHold(ctx, operatorTrust(), request) }()
	close(releaseDispatch)
	if err := <-dispatchDone; err == nil {
		t.Fatal("dispatch fault was not returned")
	}
	hold := <-holdDone
	assertWireError(t, hold, http.StatusConflict, "stale")
	if status := opened.HoldStatus(ctx, operatorTrust(), "hold-vs-prestart"); status.HTTPStatus != http.StatusNotFound {
		t.Fatalf("busy hold was persisted: status=%d body=%s", status.HTTPStatus, status.Body)
	}
	if len(adapter.CallsSnapshot()) != 0 {
		t.Fatalf("pre-start intent invoked adapter: %+v", adapter.CallsSnapshot())
	}
	opened.SetFaultInjector(nil)
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if snapshot := currentSnapshot(t, ctx, reopened); snapshot.ActiveAttempt == nil || snapshot.ActiveAttempt.State != "unknown" {
		t.Fatalf("restart did not fence pre-start intent: %+v", snapshot.ActiveAttempt)
	}
	if len(adapter.CallsSnapshot()) != 0 {
		t.Fatalf("recovery double-started intent: %+v", adapter.CallsSnapshot())
	}
}

func TestQuiescenceProofReleasePreservesManualPauseAndParkedFIFO(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	config := testConfig(t.TempDir())
	config.Adapter = fixture.NewAdapter()
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "55000000-0000-4000-8000-000000000001")
	first := enqueue(t, ctx, opened, "55000000-0000-4000-8000-000000000002", dialogID, "active", 1)
	second := enqueue(t, ctx, opened, "55000000-0000-4000-8000-000000000003", dialogID, "parked", 2)
	dispatched := dispatch(t, ctx, opened)
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.State == "running"
	})
	stop := command(t, "55000000-0000-4000-8000-000000000004", "attempt.stop",
		map[string]any{"nodeId": testNodeID, "attemptId": dispatched.AttemptID}, map[string]any{"attemptGeneration": 1}, map[string]any{})
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), stop), http.StatusAccepted)
	if err := opened.Observe(ctx, node.Observation{AttemptID: dispatched.AttemptID, Generation: 1, Kind: "terminal", TerminalState: "interrupted", EffectStatus: "none", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	before := currentSnapshot(t, ctx, opened)
	if !before.Node.QueuePaused || len(before.PendingQueue) != 1 || before.PendingQueue[0].RequestID != second.RequestID || first.RequestID == second.RequestID {
		t.Fatalf("manual pause/FIFO fixture invalid: %+v", before)
	}
	hold := installHold(t, opened, holdRequest(t, "parked-node", harnessbarrier.Scope{Kind: "node"}, before.Epoch, 0), http.StatusCreated)
	proof := proofForHold(t, opened, hold.OperationID, http.StatusOK)
	if proof.Scope.Kind != "node" || proof.HoldVersion != hold.HoldVersion || proof.ScopeRevision != hold.ScopeRevision || proof.Active != nil || proof.UnsettledCount != 0 {
		t.Fatalf("proof is not bound to hold: %+v", proof)
	}
	raw := releaseRequest(t, hold, "release")
	released := opened.ReleaseHold(ctx, operatorTrust(), raw)
	if released.HTTPStatus != http.StatusCreated || harnessbarrier.Validate("releaseReceipt", released.Body) != nil {
		t.Fatalf("release failed: status=%d body=%s", released.HTTPStatus, released.Body)
	}
	var receipt harnessbarrier.ReleaseReceipt
	if json.Unmarshal(released.Body, &receipt) != nil || !receipt.ManualPause || receipt.ScopeRevision != 2 {
		t.Fatalf("release did not preserve manual pause: %+v", receipt)
	}
	if replay := opened.ReleaseHold(ctx, operatorTrust(), raw); replay.HTTPStatus != http.StatusOK || !bytes.Equal(replay.Body, released.Body) {
		t.Fatalf("release replay changed: status=%d body=%s", replay.HTTPStatus, replay.Body)
	}
	conflict := releaseRequest(t, hold, "cancel")
	assertWireError(t, opened.ReleaseHold(ctx, operatorTrust(), conflict), http.StatusConflict, "id_conflict")
	after := currentSnapshot(t, ctx, opened)
	if !after.Node.QueuePaused || len(after.PendingQueue) != 1 || after.PendingQueue[0].RequestID != second.RequestID {
		t.Fatalf("release changed manual pause/FIFO: %+v", after)
	}
	if next, err := opened.DispatchNext(ctx); err != nil || next.AttemptID != "" {
		t.Fatalf("manual pause did not remain authoritative: %+v err=%v", next, err)
	}
	installHold(t, opened, holdRequest(t, "next-node-hold", harnessbarrier.Scope{Kind: "node"}, after.Epoch, 2), http.StatusCreated)
}

func TestDialogProofIsInvalidatedLocallyAndIgnoresSiblingTransitions(t *testing.T) {
	ctx := context.Background()
	opened, err := node.Open(ctx, testConfig(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogA := createDialog(t, ctx, opened, "56000000-0000-4000-8000-000000000001")
	dialogB := createDialog(t, ctx, opened, "56000000-0000-4000-8000-000000000002")
	requestA := enqueue(t, ctx, opened, "56000000-0000-4000-8000-000000000003", dialogA, "A", 1)
	enqueue(t, ctx, opened, "56000000-0000-4000-8000-000000000004", dialogB, "B", 1)
	epoch := currentSnapshot(t, ctx, opened).Epoch
	holdA := installHold(t, opened, holdRequest(t, "proof-dialog-a", harnessbarrier.Scope{Kind: "dialog", DialogID: dialogA}, epoch, 0), http.StatusCreated)
	proofA := proofForHold(t, opened, holdA.OperationID, http.StatusOK)
	enqueue(t, ctx, opened, "56000000-0000-4000-8000-000000000005", dialogB, "B2", 2)
	proofAfterSibling := proofForHold(t, opened, holdA.OperationID, http.StatusOK)
	if proofAfterSibling != proofA {
		t.Fatalf("sibling transition invalidated dialog proof: before=%+v after=%+v", proofA, proofAfterSibling)
	}
	holdB := installHold(t, opened, holdRequest(t, "proof-dialog-b", harnessbarrier.Scope{Kind: "dialog", DialogID: dialogB}, epoch, 0), http.StatusCreated)
	proofB := proofForHold(t, opened, holdB.OperationID, http.StatusOK)
	cancelA := command(t, "56000000-0000-4000-8000-000000000006", "request.cancel",
		map[string]any{"nodeId": testNodeID, "requestId": requestA.RequestID}, map[string]any{"requestVersion": 1}, map[string]any{})
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), cancelA), http.StatusAccepted)
	changedA := proofForHold(t, opened, holdA.OperationID, http.StatusOK)
	if changedA.ProofHash == proofA.ProofHash || changedA.StateVersion <= proofA.StateVersion || changedA.QueueRevision <= proofA.QueueRevision {
		t.Fatalf("selected queue transition did not invalidate proof: before=%+v after=%+v", proofA, changedA)
	}
	if proofBAfter := proofForHold(t, opened, holdB.OperationID, http.StatusOK); proofBAfter != proofB {
		t.Fatalf("dialog A control invalidated dialog B proof: before=%+v after=%+v", proofB, proofBAfter)
	}
	if result := opened.ReleaseHold(ctx, operatorTrust(), releaseRequest(t, holdA, "cancel")); result.HTTPStatus != http.StatusCreated {
		t.Fatalf("cancel failed: status=%d body=%s", result.HTTPStatus, result.Body)
	}
	proofForHold(t, opened, holdA.OperationID, http.StatusNotFound)
	if proofBAfter := proofForHold(t, opened, holdB.OperationID, http.StatusOK); proofBAfter != proofB {
		t.Fatalf("dialog A release invalidated dialog B proof: before=%+v after=%+v", proofB, proofBAfter)
	}
}

func TestQuiescenceProofNeverCompletesUnknownByTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	config := testConfig(t.TempDir())
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "57000000-0000-4000-8000-000000000001")
	enqueue(t, ctx, opened, "57000000-0000-4000-8000-000000000002", dialogID, "unknown", 1)
	dispatched := dispatch(t, ctx, opened)
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.State == "running"
	})
	hold := installHold(t, opened, holdRequest(t, "unknown-dialog", harnessbarrier.Scope{Kind: "dialog", DialogID: dialogID}, currentSnapshot(t, ctx, opened).Epoch, 0), http.StatusCreated)
	if err := opened.Observe(ctx, node.Observation{AttemptID: dispatched.AttemptID, Generation: 1, Kind: "unknown", Reason: "provider_state", EffectStatus: "unknown"}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		result := opened.QuiescenceProof(ctx, operatorTrust(), hold.OperationID)
		assertWireError(t, result, http.StatusConflict, "stale")
		time.Sleep(5 * time.Millisecond)
	}
	if active := currentSnapshot(t, ctx, opened).ActiveAttempt; active == nil || active.State != "unknown" || active.EffectStatus != "unknown" {
		t.Fatalf("proof polling converted unknown to terminal: %+v", active)
	}
}

func TestHeldScopeKeepsStopApprovalAndInputControlsAvailable(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(*testing.T, *node.Node, harnessadapter.AttemptRef)
	}{
		{name: "stop", run: func(t *testing.T, opened *node.Node, reference harnessadapter.AttemptRef) {
			stop := command(t, "58000000-0000-4000-8000-000000000001", "attempt.stop",
				map[string]any{"nodeId": testNodeID, "attemptId": reference.AttemptID}, map[string]any{"attemptGeneration": reference.Generation}, map[string]any{})
			decodeReceipt(t, opened.SubmitCommand(context.Background(), nodeTrust(), stop), http.StatusAccepted)
		}},
		{name: "approval", run: func(t *testing.T, opened *node.Node, reference harnessadapter.AttemptRef) {
			callID := "58000000-0000-4000-8000-000000000002"
			approvalID := "58000000-0000-4000-8000-000000000003"
			actionHash := strings.Repeat("a", 64)
			content := harnessprotocol.SafeContent{Kind: "inline", Content: "safe", Redaction: "none"}
			if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ToolStartedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID, ToolName: "fixture.echo", ActionHash: actionHash, Input: content}); err != nil {
				t.Fatal(err)
			}
			if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ApprovalRequestedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, ApprovalID: approvalID, CallID: callID, ActionHash: actionHash, SafePrompt: "allow?"}); err != nil {
				t.Fatal(err)
			}
			approval := command(t, "58000000-0000-4000-8000-000000000004", "approval.respond",
				map[string]any{"nodeId": testNodeID, "approvalId": approvalID, "attemptId": reference.AttemptID},
				map[string]any{"approvalVersion": 1, "attemptGeneration": reference.Generation},
				map[string]any{"decision": "allow_once", "actionHash": actionHash})
			decodeReceipt(t, opened.SubmitCommand(context.Background(), nodeTrust(), approval), http.StatusAccepted)
		}},
		{name: "input", run: func(t *testing.T, opened *node.Node, reference harnessadapter.AttemptRef) {
			inputID := "58000000-0000-4000-8000-000000000005"
			if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.InputRequestedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, InputRequestID: inputID, Prompt: harnessprotocol.SafeContent{Kind: "inline", Content: "continue?", Redaction: "none"}}); err != nil {
				t.Fatal(err)
			}
			input := command(t, "58000000-0000-4000-8000-000000000006", "input.respond",
				map[string]any{"nodeId": testNodeID, "inputRequestId": inputID, "attemptId": reference.AttemptID},
				map[string]any{"inputVersion": 1, "attemptGeneration": reference.Generation}, map[string]any{"text": "continue"})
			decodeReceipt(t, opened.SubmitCommand(context.Background(), nodeTrust(), input), http.StatusAccepted)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testConfig(t.TempDir())
			config.Policies = fixture.NewPolicySource()
			opened, reference := runningAttemptWithConfig(t, config)
			defer opened.Close()
			hold := installHold(t, opened, holdRequest(t, "control-"+test.name, harnessbarrier.Scope{Kind: "dialog", DialogID: reference.DialogID}, currentSnapshot(t, context.Background(), opened).Epoch, 0), http.StatusCreated)
			assertWireError(t, opened.QuiescenceProof(context.Background(), operatorTrust(), hold.OperationID), http.StatusConflict, "stale")
			test.run(t, opened, reference)
		})
	}
}

func TestReleaseCommitFaultsAreAtomicAndReplayable(t *testing.T) {
	ctx := context.Background()
	opened, err := node.Open(ctx, testConfig(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	hold := installHold(t, opened, holdRequest(t, "release-fault", harnessbarrier.Scope{Kind: "node"}, currentSnapshot(t, ctx, opened).Epoch, 0), http.StatusCreated)
	raw := releaseRequest(t, hold, "release")
	opened.SetFaultInjector(func(point node.FaultPoint) error {
		if point == node.FaultBeforeReleaseCommit {
			return errors.New("synthetic before release commit")
		}
		return nil
	})
	before := opened.ReleaseHold(ctx, operatorTrust(), raw)
	assertWireError(t, before, http.StatusServiceUnavailable, "not_durable")
	if proof := opened.QuiescenceProof(ctx, operatorTrust(), hold.OperationID); proof.HTTPStatus != http.StatusOK {
		t.Fatalf("pre-commit release fault removed hold: status=%d body=%s", proof.HTTPStatus, proof.Body)
	}
	opened.SetFaultInjector(func(point node.FaultPoint) error {
		if point == node.FaultAfterReleaseCommit {
			return errors.New("synthetic lost release receipt")
		}
		return nil
	})
	after := opened.ReleaseHold(ctx, operatorTrust(), raw)
	assertWireError(t, after, http.StatusServiceUnavailable, "node_unavailable")
	if !after.Committed {
		t.Fatal("post-commit release fault was not marked committed")
	}
	opened.SetFaultInjector(nil)
	replay := opened.ReleaseHold(ctx, operatorTrust(), raw)
	if replay.HTTPStatus != http.StatusOK || harnessbarrier.Validate("releaseReceipt", replay.Body) != nil {
		t.Fatalf("lost release receipt was not replayed: status=%d body=%s", replay.HTTPStatus, replay.Body)
	}
	proofForHold(t, opened, hold.OperationID, http.StatusNotFound)
}

func assertWireError(t *testing.T, result node.Result, status int, code string) {
	t.Helper()
	if result.HTTPStatus != status || harnessprotocol.Validate("error", result.Body) != nil {
		t.Fatalf("wire error status=%d want=%d body=%s", result.HTTPStatus, status, result.Body)
	}
	var failure harnessprotocol.Error
	if json.Unmarshal(result.Body, &failure) != nil || failure.Code != code {
		t.Fatalf("wire error=%+v want=%s", failure, code)
	}
}

func mustJSONBytes(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
