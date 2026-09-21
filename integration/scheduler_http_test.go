package integration_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/api"
	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	hp "github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

// The production default must execute HTTP-admitted work without an external
// caller polling DispatchNext. Only the native adapter is synthetic.
func TestAutonomousFIFOAndPauseThroughPrivateAPIClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	events := make(chan harnessadapter.Event, 4)
	adapter := fixture.NewAdapter()
	adapter.StreamInput = events
	cfg := config(t.TempDir())
	cfg.ManualDispatchForTesting = false
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
	roots, serverCert, clientCert := transportCertificates(t)
	pin := sha256.Sum256(clientCert.Certificate[0])
	handler, err := server.New(server.Config{NodeID: integrationNode, GatewayCertificateSHA256: hex.EncodeToString(pin[:])}, n)
	if err != nil {
		t.Fatal(err)
	}
	disconnected := make(chan struct{}, 1)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/nodes/"+integrationNode+"/events" {
			defer func() { disconnected <- struct{}{} }()
		}
		handler.ServeHTTP(w, r)
	}))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	s.StartTLS()
	t.Cleanup(s.Close)
	client := signedClient(t, s.URL, roots, serverCert, clientCert)
	t.Cleanup(client.Close)
	command := func(raw []byte) hp.Receipt {
		t.Helper()
		r, err := client.Command(ctx, integrationNode, integrationOwner, raw)
		if err != nil {
			t.Fatal(err)
		}
		return receipt(t, node.Result{HTTPStatus: r.Status, Body: r.Body}, http.StatusAccepted, raw)
	}
	snapshot := func() hp.Snapshot {
		t.Helper()
		r, err := client.Read(ctx, integrationNode, integrationOwner, "snapshot", "")
		if err != nil || r.Status != 200 {
			t.Fatalf("snapshot status=%d err=%v body=%s", r.Status, err, r.Body)
		}
		var value hp.Snapshot
		if err := json.Unmarshal(r.Body, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	wait := func(matches func(hp.Snapshot) bool) hp.Snapshot {
		t.Helper()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			current := snapshot()
			if matches(current) {
				return current
			}
			select {
			case <-ctx.Done():
				t.Fatal("autonomous scheduler did not reach expected state")
			case <-ticker.C:
			}
		}
	}
	created := command(createCommand())
	var dialog hp.DialogCreateReferences
	if err := json.Unmarshal(created.References, &dialog); err != nil {
		t.Fatal(err)
	}
	enqueue := func(id, text string, version int64) hp.MessageEnqueueReferences {
		t.Helper()
		r := command(messageCommand(t, id, dialog.DialogID, text, version))
		var refs hp.MessageEnqueueReferences
		if err := json.Unmarshal(r.References, &refs); err != nil {
			t.Fatal(err)
		}
		return refs
	}
	waitRunning := func(requestID string) hp.Snapshot {
		return wait(func(s hp.Snapshot) bool {
			return s.ActiveAttempt != nil && s.ActiveAttempt.RequestID == requestID && s.ActiveAttempt.State == "running"
		})
	}
	ref := func(attempt *hp.Attempt) harnessadapter.AttemptRef {
		return harnessadapter.AttemptRef{NodeID: integrationNode, DialogID: dialog.DialogID, RequestID: attempt.RequestID, AttemptID: attempt.AttemptID, Generation: attempt.Generation}
	}
	first := enqueue("10000000-0000-4000-8000-000000004001", "first", 1)
	firstRunning := waitRunning(first.RequestID)
	second := enqueue("10000000-0000-4000-8000-000000004002", "second", 2)
	queued := snapshot()
	if queued.Node.PendingCount != 1 || queued.ActiveAttempt == nil || queued.ActiveAttempt.AttemptID != firstRunning.ActiveAttempt.AttemptID {
		t.Fatal("ordinary HTTP message bypassed FIFO")
	}
	stream, err := client.OpenEvents(ctx, integrationNode, integrationOwner, queued.LastEventSeq)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-disconnected:
	case <-ctx.Done():
		t.Fatal("server SSE handler did not finish after disconnect")
	}
	for _, call := range adapter.CallsSnapshot() {
		if call.Method == "cancel" {
			t.Fatal("SSE disconnect cancelled active execution")
		}
	}
	// Disconnecting the consumer cannot stop the provider or future dispatch.
	events <- harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: ref(firstRunning.ActiveAttempt)}, Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "none"}
	secondRunning := waitRunning(second.RequestID)
	third := enqueue("10000000-0000-4000-8000-000000004003", "third", 3)
	stop, err := json.Marshal(map[string]any{
		"protocolVersion": 1, "schemaId": hp.SchemaID, "commandId": "10000000-0000-4000-8000-000000004004", "kind": "attempt.stop",
		"target":   map[string]any{"nodeId": integrationNode, "attemptId": secondRunning.ActiveAttempt.AttemptID},
		"expected": map[string]any{"attemptGeneration": secondRunning.ActiveAttempt.Generation}, "payload": map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	command(stop)
	stopping := wait(func(s hp.Snapshot) bool {
		if !s.Node.QueuePaused || s.ActiveAttempt == nil || s.ActiveAttempt.State != "stopping" {
			return false
		}
		for _, call := range adapter.CallsSnapshot() {
			if call.Method == "cancel" {
				return true
			}
		}
		return false
	})
	if stopping.Node.PendingCount != 1 {
		t.Fatal("stop lost queued followup")
	}
	events <- harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: ref(secondRunning.ActiveAttempt)}, Outcome: harnessadapter.ReconcileInterrupted, EffectStatus: "none"}
	paused := wait(func(s hp.Snapshot) bool { return s.ActiveAttempt == nil })
	if !paused.Node.QueuePaused || paused.Node.PendingCount != 1 || len(paused.PendingQueue) != 1 || paused.PendingQueue[0].RequestID != third.RequestID {
		t.Fatal("terminal cleared manual pause or changed FIFO")
	}
	resume, err := json.Marshal(map[string]any{
		"protocolVersion": 1, "schemaId": hp.SchemaID, "commandId": "10000000-0000-4000-8000-000000004005", "kind": "queue.resume",
		"target": map[string]any{"nodeId": integrationNode}, "expected": map[string]any{"queueVersion": paused.Node.QueueVersion}, "payload": map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	command(resume)
	thirdRunning := waitRunning(third.RequestID)
	events <- harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: ref(thirdRunning.ActiveAttempt)}, Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "none"}
	idle := wait(func(s hp.Snapshot) bool { return s.ActiveAttempt == nil && s.Node.PendingCount == 0 })
	if idle.Node.QueuePaused {
		t.Fatal("explicit resume did not clear manual pause")
	}
	var starts []harnessadapter.AttemptRef
	var methods []string
	cancels := 0
	for _, call := range adapter.CallsSnapshot() {
		if call.Method == "start" || call.Method == "resume" {
			starts = append(starts, call.Attempt)
			methods = append(methods, call.Method)
		}
		if call.Method == "cancel" {
			cancels++
			if call.Attempt != ref(secondRunning.ActiveAttempt) {
				t.Fatal("stop targeted a different generation")
			}
		}
	}
	if len(starts) != 3 || starts[0].RequestID != first.RequestID || starts[1].RequestID != second.RequestID || starts[2].RequestID != third.RequestID || cancels != 1 {
		t.Fatalf("native calls violate FIFO/exact cancel: starts=%+v cancels=%d", starts, cancels)
	}
	if methods[0] != "start" || methods[1] != "resume" || methods[2] != "resume" || starts[0] != ref(firstRunning.ActiveAttempt) || starts[1] != ref(secondRunning.ActiveAttempt) || starts[2] != ref(thirdRunning.ActiveAttempt) {
		t.Fatalf("dialog continuity or exact attempt binding lost: methods=%v attempts=%+v", methods, starts)
	}
	err = n.Close()
	n = nil
	if err != nil {
		t.Fatal(err)
	}
}
