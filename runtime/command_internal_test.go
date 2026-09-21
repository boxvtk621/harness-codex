package node

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

type fullSpace struct{}

func (fullSpace) Measure(string) (SpaceInfo, error) {
	return SpaceInfo{FreeBytes: 16 << 30, TotalBytes: 64 << 30}, nil
}

type switchSpace struct{ low atomic.Bool }

func (space *switchSpace) Measure(string) (SpaceInfo, error) {
	if space.low.Load() {
		return SpaceInfo{FreeBytes: 1, TotalBytes: 64 << 30}, nil
	}
	return SpaceInfo{FreeBytes: 16 << 30, TotalBytes: 64 << 30}, nil
}

func TestLowStorageRejectsAdmissionButPreservesControlPath(t *testing.T) {
	ctx := context.Background()
	space := &switchSpace{}
	n, err := Open(ctx, Config{DataDir: t.TempDir(), NodeID: "20000000-0000-4000-8000-000000000001", OwnerID: "1-1", RegistryVersion: 1, Adapter: fixture.NewAdapter(), Policies: fixture.NewPolicySource(), Space: space, ManualDispatchForTesting: true})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	trust := TrustContext{TransportNodeID: "20000000-0000-4000-8000-000000000001"}
	created := n.SubmitCommand(ctx, trust, []byte(`{"protocolVersion":1,"schemaId":"harness-wire-v2","commandId":"10000000-0000-4000-8000-000000000011","kind":"dialog.create","target":{"nodeId":"20000000-0000-4000-8000-000000000001"},"expected":{"registryVersion":1},"payload":{}}`))
	if created.HTTPStatus != 202 {
		t.Fatalf("create %d %s", created.HTTPStatus, created.Body)
	}
	var receipt harnessprotocol.Receipt
	_ = json.Unmarshal(created.Body, &receipt)
	var d harnessprotocol.DialogCreateReferences
	_ = json.Unmarshal(receipt.References, &d)
	enqueue := func(id, text string, version int64) Result {
		return n.SubmitCommand(ctx, trust, []byte(`{"protocolVersion":1,"schemaId":"harness-wire-v2","commandId":"`+id+`","kind":"message.enqueue","target":{"nodeId":"20000000-0000-4000-8000-000000000001","dialogId":"`+d.DialogID+`"},"expected":{"dialogVersion":`+strconv.FormatInt(version, 10)+`},"payload":{"text":"`+text+`"}}`))
	}
	if result := enqueue("10000000-0000-4000-8000-000000000012", "run", 1); result.HTTPStatus != 202 {
		t.Fatalf("enqueue %d %s", result.HTTPStatus, result.Body)
	}
	dispatched, err := n.DispatchNext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		var s harnessprotocol.Snapshot
		r := n.Snapshot(ctx, trust)
		_ = json.Unmarshal(r.Body, &s)
		if s.ActiveAttempt != nil && s.ActiveAttempt.State == "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("attempt did not start")
		}
		time.Sleep(time.Millisecond)
	}
	space.low.Store(true)
	if result := enqueue("10000000-0000-4000-8000-000000000013", "blocked", 2); result.HTTPStatus != 503 {
		t.Fatalf("low-storage admission=%d body=%s", result.HTTPStatus, result.Body)
	}
	stop := []byte(`{"protocolVersion":1,"schemaId":"harness-wire-v2","commandId":"10000000-0000-4000-8000-000000000014","kind":"attempt.stop","target":{"nodeId":"20000000-0000-4000-8000-000000000001","attemptId":"` + dispatched.AttemptID + `"},"expected":{"attemptGeneration":1},"payload":{}}`)
	if result := n.SubmitCommand(ctx, trust, stop); result.HTTPStatus != 202 {
		t.Fatalf("control path=%d body=%s", result.HTTPStatus, result.Body)
	}
	var snapshot harnessprotocol.Snapshot
	result := n.Snapshot(ctx, trust)
	if result.HTTPStatus != 200 || json.Unmarshal(result.Body, &snapshot) != nil || !snapshot.Node.QueuePaused || snapshot.ActiveAttempt == nil || snapshot.ActiveAttempt.State != "stopping" || !slices.Contains(snapshot.Node.BlockedReasons, "storage_unavailable") {
		t.Fatalf("low-storage control projection: status=%d %+v", result.HTTPStatus, snapshot)
	}
}

func TestMessageAdmissionBuildsValidatedEvents(t *testing.T) {
	ctx := context.Background()
	node, err := Open(ctx, Config{DataDir: t.TempDir(), NodeID: "20000000-0000-4000-8000-000000000001", OwnerID: "1-1", RegistryVersion: 1, Adapter: fixture.NewAdapter(), Space: fullSpace{}, ManualDispatchForTesting: true})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	create := []byte(`{"protocolVersion":1,"schemaId":"harness-wire-v2","commandId":"10000000-0000-4000-8000-000000000001","kind":"dialog.create","target":{"nodeId":"20000000-0000-4000-8000-000000000001"},"expected":{"registryVersion":1},"payload":{}}`)
	created := node.SubmitCommand(ctx, TrustContext{TransportNodeID: "20000000-0000-4000-8000-000000000001"}, create)
	if created.HTTPStatus != 202 {
		t.Fatalf("create status=%d body=%s", created.HTTPStatus, created.Body)
	}
	var receipt harnessprotocol.Receipt
	if err := json.Unmarshal(created.Body, &receipt); err != nil {
		t.Fatal(err)
	}
	var refs harnessprotocol.DialogCreateReferences
	if err := json.Unmarshal(receipt.References, &refs); err != nil {
		t.Fatal(err)
	}
	message := []byte(`{"protocolVersion":1,"schemaId":"harness-wire-v2","commandId":"10000000-0000-4000-8000-000000000002","kind":"message.enqueue","target":{"nodeId":"20000000-0000-4000-8000-000000000001","dialogId":"` + refs.DialogID + `"},"expected":{"dialogVersion":1},"payload":{"text":"safe synthetic"}}`)
	var envelope harnessprotocol.CommandEnvelope
	if err := json.Unmarshal(message, &envelope); err != nil {
		t.Fatal(err)
	}
	tx, err := node.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := node.applyMessageEnqueue(ctx, tx, &state, envelope); err != nil {
		t.Fatal(err)
	}
}

func TestAdmissionFloor(t *testing.T) {
	for _, test := range []struct {
		total uint64
		want  uint64
	}{{4 << 30, 1 << 30}, {20 << 30, 2 << 30}} {
		if got := admissionFloor(test.total); got != test.want {
			t.Fatalf("floor(%d)=%d want=%d", test.total, got, test.want)
		}
	}
}
