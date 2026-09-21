package integration_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	hp "github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

// Keep the synthetic event connection alive until the test explicitly observes
// terminal. An empty fixture stream would instead mean transport loss.
type queuedAdapter struct{ *fixture.Adapter }

func (a *queuedAdapter) Events(ctx context.Context, in harnessadapter.EventsInput) (harnessadapter.EventStream, error) {
	stream, err := a.Adapter.Events(ctx, in)
	if err != nil {
		return nil, err
	}
	if err := stream.Close(); err != nil {
		return nil, err
	}
	return &quietStream{closed: make(chan struct{})}, nil
}

type quietStream struct {
	closed chan struct{}
	once   sync.Once
}

func (s *quietStream) Next(ctx context.Context) (harnessadapter.Event, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, io.EOF
	}
}
func (s *quietStream) Close() error { s.once.Do(func() { close(s.closed) }); return nil }

func queueSnapshot(t *testing.T, ctx context.Context, n *node.Node) hp.Snapshot {
	t.Helper()
	r := n.Snapshot(ctx, trusted())
	if r.HTTPStatus != 200 {
		t.Fatalf("snapshot status=%d body=%s", r.HTTPStatus, r.Body)
	}
	if err := hp.Validate("snapshot", r.Body); err != nil {
		t.Fatal("snapshot violates C1", err)
	}
	var state hp.Snapshot
	if err := json.Unmarshal(r.Body, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func waitRunning(t *testing.T, ctx context.Context, n *node.Node, id string) hp.Snapshot {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	for {
		s := queueSnapshot(t, ctx, n)
		if s.ActiveAttempt != nil && s.ActiveAttempt.AttemptID == id && s.ActiveAttempt.State == "running" {
			return s
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-deadline.C:
			t.Fatal("attempt did not become running", id)
		case <-tick.C:
		}
	}
}

func TestQueueCapacityRecoveryFIFOAndSingleDispatchSlot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	dir := t.TempDir()
	adapter := &queuedAdapter{fixture.NewAdapter()}
	cfg := config(dir)
	cfg.Adapter = adapter
	cfg.Policies = fixture.NewPolicySource()
	n, err := node.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if n != nil {
			if err := n.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	created := receipt(t, n.SubmitCommand(ctx, trusted(), createCommand()), 202, createCommand())
	var dialog hp.DialogCreateReferences
	if err := json.Unmarshal(created.References, &dialog); err != nil {
		t.Fatal(err)
	}
	accepted := make([]hp.MessageEnqueueReferences, 100)
	for i := 0; i < 100; i++ {
		command := messageCommand(t, fmt.Sprintf("10000000-0000-4000-8000-%012d", 1000+i), dialog.DialogID, fmt.Sprintf("synthetic-%03d", i), int64(i+1))
		r := receipt(t, n.SubmitCommand(ctx, trusted(), command), 202, command)
		if err := json.Unmarshal(r.References, &accepted[i]); err != nil {
			t.Fatal(err)
		}
	}
	full := queueSnapshot(t, ctx, n)
	if full.Node.PendingCount != 100 || len(full.PendingQueue) != 100 || full.ActiveAttempt != nil {
		t.Fatal("100 admissions lost capacity or invented execution")
	}
	for i, item := range full.PendingQueue {
		if item.RequestID != accepted[i].RequestID || item.InputMessageID != accepted[i].MessageID || item.Status != "queued" {
			t.Fatalf("FIFO item %d differs from admitted intent", i)
		}
		if i > 0 && item.QueueSequence <= full.PendingQueue[i-1].QueueSequence {
			t.Fatal("queue order is not strictly increasing")
		}
	}
	beforeReject := readAdmissionProjection(t, ctx, dir)
	overflow := messageCommand(t, "10000000-0000-4000-8000-000000002000", dialog.DialogID, "previously rejected", 101)
	fault(t, n.SubmitCommand(ctx, trusted(), overflow), 429, "queue_full")
	if !reflect.DeepEqual(beforeReject, readAdmissionProjection(t, ctx, dir)) {
		t.Fatal("capacity rejection wrote durable state")
	}
	if len(adapter.CallsSnapshot()) != 0 {
		t.Fatal("admission invoked adapter before dispatch")
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	n = nil
	n, err = node.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	reopened := queueSnapshot(t, ctx, n)
	if reopened.Epoch != full.Epoch || reopened.Node.QueueVersion != full.Node.QueueVersion || !reflect.DeepEqual(reopened.PendingQueue, full.PendingQueue) {
		t.Fatal("ordinary reopen changed epoch or queued FIFO")
	}
	if len(adapter.CallsSnapshot()) != 0 {
		t.Fatal("reopen invoked execution automatically")
	}

	// Remove the second item, preserving all other positions; a new intent must
	// enter at the tail, even when its previous admission was rejected.
	cancelCommand, err := json.Marshal(map[string]any{"protocolVersion": 1, "schemaId": hp.SchemaID, "commandId": "10000000-0000-4000-8000-000000002001", "kind": "request.cancel", "target": map[string]string{"nodeId": integrationNode, "requestId": accepted[1].RequestID}, "expected": map[string]int64{"requestVersion": 1}, "payload": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	receipt(t, n.SubmitCommand(ctx, trusted(), cancelCommand), 202, cancelCommand)
	refilled := receipt(t, n.SubmitCommand(ctx, trusted(), overflow), 202, overflow)
	var tail hp.MessageEnqueueReferences
	if err := json.Unmarshal(refilled.References, &tail); err != nil {
		t.Fatal(err)
	}
	ready := queueSnapshot(t, ctx, n)
	if ready.Node.PendingCount != 100 || ready.PendingQueue[0].RequestID != accepted[0].RequestID || ready.PendingQueue[1].RequestID != accepted[2].RequestID || ready.PendingQueue[99].RequestID != tail.RequestID {
		t.Fatal("cancel/refill changed FIFO positions")
	}

	if ready.PendingQueue[99].QueueSequence != beforeReject.NextQueueSequence || messageSequence(t, ctx, dir, tail.MessageID) != beforeReject.NextMessageSequence {
		t.Fatal("rejected admission consumed a queue/message sequence")
	}

	type dispatchAnswer struct {
		result node.DispatchResult
		err    error
	}
	answers := make(chan dispatchAnswer, 8)
	for i := 0; i < 8; i++ {
		go func() { r, e := n.DispatchNext(ctx); answers <- dispatchAnswer{r, e} }()
	}
	var first node.DispatchResult
	started := 0
	for i := 0; i < 8; i++ {
		select {
		case answer := <-answers:
			if answer.err != nil {
				t.Fatal(answer.err)
			}
			if answer.result.Outcome == "dispatching" {
				first = answer.result
				started++
			} else if (answer.result.Outcome != "idle" && answer.result.Outcome != "changed") || answer.result.AttemptID != "" || answer.result.RequestID != "" {
				t.Fatal("non-winning dispatch did not report an empty busy/changed result", answer.result)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if started != 1 || first.RequestID != accepted[0].RequestID {
		t.Fatalf("concurrent dispatch reserved %d slots or skipped FIFO", started)
	}
	running := waitRunning(t, ctx, n, first.AttemptID)
	if running.Node.PendingCount != 99 || len(running.PendingQueue) != 99 {
		t.Fatal("dispatch did not consume exactly one queued request")
	}
	ordinary := messageCommand(t, "10000000-0000-4000-8000-000000002002", dialog.DialogID, "ordinary input while running", 102)
	receipt(t, n.SubmitCommand(ctx, trusted(), ordinary), 202, ordinary)
	if other, err := n.DispatchNext(ctx); err != nil || other.AttemptID != "" {
		t.Fatal("active slot admitted a second dispatch", other, err)
	}
	active := queueSnapshot(t, ctx, n)
	if active.Node.PendingCount != 100 || active.ActiveAttempt.AttemptID != first.AttemptID {
		t.Fatal("ordinary message changed active execution")
	}
	starts := 0
	for _, call := range adapter.CallsSnapshot() {
		if call.Method == "start" {
			starts++
		}
	}
	if starts != 1 {
		t.Fatalf("one active slot invoked %d starts", starts)
	}

	// A known task failure on a healthy node permits the next queued request;
	// the cancelled second item must never be sent.
	firstBefore := terminalProjection(t, ctx, dir, first.AttemptID)
	firstSeq := queueSnapshot(t, ctx, n).LastEventSeq
	if err := n.Observe(ctx, node.Observation{AttemptID: first.AttemptID, Generation: running.ActiveAttempt.Generation, Kind: "terminal", TerminalState: "failed", EffectStatus: "none", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	assertQueueTerminal(t, ctx, n, dir, firstBefore, firstSeq, "failed")
	second, err := n.DispatchNext(ctx)
	if err != nil || second.Outcome != "dispatching" || second.RequestID != accepted[2].RequestID {
		t.Fatal("healthy task failure blocked or reordered FIFO", second, err)
	}
	secondRunning := waitRunning(t, ctx, n, second.AttemptID)
	secondBefore := terminalProjection(t, ctx, dir, second.AttemptID)
	if err := n.Observe(ctx, node.Observation{AttemptID: second.AttemptID, Generation: secondRunning.ActiveAttempt.Generation, Kind: "terminal", TerminalState: "completed", EffectStatus: "none", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	assertQueueTerminal(t, ctx, n, dir, secondBefore, secondRunning.LastEventSeq, "completed")
	remaining := queueSnapshot(t, ctx, n)
	if remaining.ActiveAttempt != nil || remaining.Node.PendingCount != 99 || remaining.PendingQueue[0].RequestID != accepted[3].RequestID {
		t.Fatal("terminal lost or reordered remaining work")
	}
	var executions []fixture.Call
	for _, call := range adapter.CallsSnapshot() {
		if call.Method == "start" || call.Method == "resume" {
			executions = append(executions, call)
			if call.Attempt.RequestID == accepted[1].RequestID {
				t.Fatal("cancelled request executed")
			}
		}
	}
	if len(executions) != 2 {
		t.Fatalf("expected two explicit executions, got %d", len(executions))
	}
	expectedAttempts := []harnessadapter.AttemptRef{
		{NodeID: integrationNode, DialogID: dialog.DialogID, RequestID: first.RequestID, AttemptID: first.AttemptID, Generation: running.ActiveAttempt.Generation},
		{NodeID: integrationNode, DialogID: dialog.DialogID, RequestID: second.RequestID, AttemptID: second.AttemptID, Generation: secondRunning.ActiveAttempt.Generation},
	}
	for i, method := range []string{"start", "resume"} {
		if executions[i].Method != method || executions[i].Attempt != expectedAttempts[i] {
			t.Fatalf("execution %d differs: got %+v, expected %s %+v", i, executions[i], method, expectedAttempts[i])
		}
	}
	closeErr := n.Close()
	n = nil
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

type terminalRows struct {
	AttemptID, RequestID, DialogID, AttemptState, RequestState, EffectStatus string
	Generation, AttemptVersion, RequestVersion                               int64
}

func queueDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	uri := &url.URL{Scheme: "file", Path: filepath.Join(dir, "harness.db"), RawQuery: url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(5000)"}}.Encode()}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	return db
}
func messageSequence(t *testing.T, ctx context.Context, dir, id string) int64 {
	t.Helper()
	db := queueDB(t, dir)
	defer db.Close()
	var sequence int64
	if err := db.QueryRowContext(ctx, "SELECT sequence FROM messages WHERE message_id=?", id).Scan(&sequence); err != nil {
		t.Fatal(err)
	}
	return sequence
}
func terminalProjection(t *testing.T, ctx context.Context, dir, id string) terminalRows {
	t.Helper()
	db := queueDB(t, dir)
	defer db.Close()
	var out terminalRows
	if err := db.QueryRowContext(ctx, `SELECT a.attempt_id,a.request_id,a.dialog_id,a.state,r.status,a.effect_status,a.generation,a.version,r.version FROM attempts a JOIN requests r ON r.request_id=a.request_id WHERE a.attempt_id=?`, id).Scan(&out.AttemptID, &out.RequestID, &out.DialogID, &out.AttemptState, &out.RequestState, &out.EffectStatus, &out.Generation, &out.AttemptVersion, &out.RequestVersion); err != nil {
		t.Fatal(err)
	}
	return out
}
func assertQueueTerminal(t *testing.T, ctx context.Context, n *node.Node, dir string, before terminalRows, afterSeq int64, want string) {
	t.Helper()
	after := terminalProjection(t, ctx, dir, before.AttemptID)
	if after.AttemptID != before.AttemptID || after.RequestID != before.RequestID || after.DialogID != before.DialogID || after.Generation != before.Generation || after.AttemptState != want || after.RequestState != want || after.EffectStatus != "none" || after.AttemptVersion != before.AttemptVersion+1 || after.RequestVersion != before.RequestVersion+1 {
		t.Fatalf("terminal projection mismatch: before=%+v after=%+v want=%s", before, after, want)
	}
	snapshot := queueSnapshot(t, ctx, n)
	db := queueDB(t, dir)
	defer db.Close()
	rows, err := db.QueryContext(ctx, "SELECT event_json,late FROM events WHERE seq>? AND seq<=? ORDER BY seq", afterSeq, snapshot.LastEventSeq)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	next := afterSeq + 1
	terminals := 0
	for rows.Next() {
		var raw []byte
		var late bool
		if err := rows.Scan(&raw, &late); err != nil {
			t.Fatal(err)
		}
		if err := hp.Validate("event", raw); err != nil {
			t.Fatal(err)
		}
		var event hp.EventEnvelope
		if err := json.Unmarshal(raw, &event); err != nil {
			t.Fatal(err)
		}
		if event.Seq != next || event.Epoch != snapshot.Epoch || event.NodeID != integrationNode {
			t.Fatal("terminal event watermark/scope mismatch")
		}
		next++
		if event.Type == "attempt."+want {
			terminals++
			if event.AttemptID != before.AttemptID || event.EntityID != before.AttemptID || event.DialogID != before.DialogID || event.EntityVersion != after.AttemptVersion || late {
				t.Fatal("terminal event identity/version mismatch")
			}
			var payload struct {
				Generation   int64  `json:"generation"`
				EffectStatus string `json:"effectStatus"`
			}
			if err := json.Unmarshal(event.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Generation != before.Generation || (want == "failed" && payload.EffectStatus != "none") {
				t.Fatal("terminal event generation/effects mismatch")
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if terminals != 1 || next != snapshot.LastEventSeq+1 || snapshot.LastEventSeq <= afterSeq {
		t.Fatal("terminal event missing, duplicated, or watermark inconsistent")
	}
}
