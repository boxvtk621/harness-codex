package node_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

func TestSuppressedArchiveDeduplicatesBeforeChargeAndPreservesStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opened, adapter, dataDir, reference, cancelCalled := openOutputTestNode(t, ctx)
	defer opened.Close()

	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t,
		"37000000-0000-4000-8000-000000000001", "attempt.stop",
		map[string]any{"nodeId": testNodeID, "attemptId": reference.AttemptID},
		map[string]any{"attemptGeneration": reference.Generation}, map[string]any{})), 202)
	select {
	case <-cancelCalled:
	case <-ctx.Done():
		t.Fatal("stop did not call Cancel")
	}
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.State == "stopping"
	})
	archiveSeedAttemptOutputBytes(t, dataDir, reference.AttemptID, node.MaximumAttemptOutputBytes-1)

	event := harnessadapter.InputRequestedEvent{
		EventBase:      harnessadapter.EventBase{Attempt: reference},
		InputRequestID: "37000000-0000-4000-8000-000000000002",
		Prompt:         harnessprotocol.SafeContent{Kind: "inline", Content: "xx", Redaction: "none"},
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, event); err != nil {
		t.Fatal(err)
	}
	rows, events, inputs, charge, encoded := archiveStats(t, dataDir, reference.AttemptID)
	if rows != 1 || inputs != 0 || charge != 2 {
		t.Fatalf("suppressed overflow rows=%d inputs=%d charge=%d", rows, inputs, charge)
	}
	var marker harnessprotocol.SafeContent
	if json.Unmarshal(encoded, &marker) != nil || marker.Kind != "unavailable" || marker.Reason != "output_limit" {
		t.Fatalf("suppressed archive retained raw prompt: %s", encoded)
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, event); err != nil {
		t.Fatalf("exact duplicate failed: %v", err)
	}
	postLimit := event
	postLimit.InputRequestID = "37000000-0000-4000-8000-000000000003"
	if err := opened.ObserveAdapterEvent(ctx, reference, postLimit); err != nil {
		t.Fatalf("post-limit event failed closed with an error: %v", err)
	}
	postLimitDelta := harnessadapter.AssistantDeltaEvent{
		EventBase:  harnessadapter.EventBase{Attempt: reference},
		MessageID:  "37000000-0000-4000-8000-000000000004",
		DeltaIndex: 0,
		Content:    harnessprotocol.SafeContent{Kind: "inline", Content: "raw-after-limit", Redaction: "none"},
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, postLimitDelta); err != nil {
		t.Fatalf("active post-limit delta failed closed with an error: %v", err)
	}
	_, err := opened.StoreArtifact(ctx, node.ArtifactInput{Attempt: reference, Name: "post-limit.txt", MediaType: "text/plain", Redaction: "none", Disposition: "attachment"}, []byte("raw-artifact-after-limit"))
	if !errors.Is(err, node.ErrOutputLimit) {
		t.Fatalf("active post-limit artifact error=%v", err)
	}
	rowsAfter, eventsAfter, inputsAfter, chargeAfter, _ := archiveStats(t, dataDir, reference.AttemptID)
	if rowsAfter != rows || eventsAfter != events || inputsAfter != inputs || chargeAfter != charge {
		t.Fatalf("exact duplicate changed persistence rows=%d->%d events=%d->%d inputs=%d->%d charge=%d->%d", rows, rowsAfter, events, eventsAfter, inputs, inputsAfter, charge, chargeAfter)
	}
	var artifacts, rawRows int64
	db := archiveDB(t, dataDir)
	if err := db.QueryRow("SELECT COUNT(*) FROM artifacts WHERE attempt_id=?", reference.AttemptID).Scan(&artifacts); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT (SELECT COUNT(*) FROM events WHERE attempt_id=? AND instr(CAST(event_json AS TEXT),'raw-after-limit')>0)+(SELECT COUNT(*) FROM late_observations WHERE attempt_id=? AND instr(CAST(observation_json AS TEXT),'raw-after-limit')>0)`, reference.AttemptID, reference.AttemptID).Scan(&rawRows); err != nil {
		t.Fatal(err)
	}
	if artifacts != 0 || rawRows != 0 {
		t.Fatalf("post-limit raw output persisted artifacts=%d rawRows=%d", artifacts, rawRows)
	}
	conflict := event
	conflict.Prompt.Content = "yy"
	if err := opened.ObserveAdapterEvent(ctx, reference, conflict); err == nil {
		t.Fatal("conflicting duplicate was accepted")
	}
	after := currentSnapshot(t, ctx, opened)
	if after.ActiveAttempt == nil || after.ActiveAttempt.State != "stopping" || !after.Node.QueuePaused || countAdapterCalls(adapter, "cancel") != 1 {
		t.Fatalf("suppressed overflow changed stop/pause: snapshot=%+v calls=%+v", after, adapter.CallsSnapshot())
	}
	terminalOutput := harnessprotocol.SafeContent{Kind: "inline", Content: "raw-terminal-after-limit", Redaction: "none"}
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, Outcome: harnessadapter.ReconcileCompleted, Output: &terminalOutput, EffectStatus: "none"}); err != nil {
		t.Fatalf("archive output-limit marker blocked confirmed terminal: %v", err)
	}
	if currentSnapshot(t, ctx, opened).ActiveAttempt != nil {
		t.Fatal("confirmed terminal did not release output-limited attempt")
	}
	if err := db.QueryRow(`SELECT (SELECT COUNT(*) FROM events WHERE attempt_id=? AND instr(CAST(event_json AS TEXT),'raw-terminal-after-limit')>0)+(SELECT COUNT(*) FROM late_observations WHERE attempt_id=? AND instr(CAST(observation_json AS TEXT),'raw-terminal-after-limit')>0)`, reference.AttemptID, reference.AttemptID).Scan(&rawRows); err != nil {
		t.Fatal(err)
	}
	if rawRows != 0 {
		t.Fatalf("confirmed terminal persisted raw output after archive limit: %d", rawRows)
	}
}

func TestSuppressedArchiveDeduplicatesActiveProjection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opened, adapter, dataDir, reference, cancelCalled := openOutputTestNode(t, ctx)
	defer opened.Close()
	event := harnessadapter.InputRequestedEvent{
		EventBase:      harnessadapter.EventBase{Attempt: reference},
		InputRequestID: "37500000-0000-4000-8000-000000000001",
		Prompt:         harnessprotocol.SafeContent{Kind: "inline", Content: "x", Redaction: "none"},
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, event); err != nil {
		t.Fatal(err)
	}
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t,
		"37500000-0000-4000-8000-000000000002", "attempt.stop",
		map[string]any{"nodeId": testNodeID, "attemptId": reference.AttemptID},
		map[string]any{"attemptGeneration": reference.Generation}, map[string]any{})), 202)
	select {
	case <-cancelCalled:
	case <-ctx.Done():
		t.Fatal("stop did not call Cancel")
	}
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.State == "stopping"
	})
	rows, events, inputs, charge, _ := archiveStats(t, dataDir, reference.AttemptID)
	if rows != 0 || inputs != 1 || charge != 0 {
		t.Fatalf("unexpected active projection baseline rows=%d inputs=%d charge=%d", rows, inputs, charge)
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, event); err != nil {
		t.Fatalf("active-path duplicate failed: %v", err)
	}
	rowsAfter, eventsAfter, inputsAfter, chargeAfter, _ := archiveStats(t, dataDir, reference.AttemptID)
	if rowsAfter != rows || eventsAfter != events || inputsAfter != inputs || chargeAfter != charge {
		t.Fatalf("active-path duplicate was archived rows=%d->%d events=%d->%d inputs=%d->%d charge=%d->%d", rows, rowsAfter, events, eventsAfter, inputs, inputsAfter, charge, chargeAfter)
	}
	conflict := event
	conflict.Prompt.Content = "y"
	if err := opened.ObserveAdapterEvent(ctx, reference, conflict); err == nil {
		t.Fatal("active-path conflicting duplicate was accepted")
	}
	if countAdapterCalls(adapter, "cancel") != 1 {
		t.Fatalf("duplicate interactive event changed Cancel count: %+v", adapter.CallsSnapshot())
	}
}

func TestLateArchiveBudgetDoesNotMutateCurrentGeneration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	adapter := fixture.NewAdapter()
	adapter.StreamInput = make(chan harnessadapter.Event)
	dataDir := t.TempDir()
	config := testConfig(dataDir)
	config.ManualDispatchForTesting = true
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()

	dialogID := createDialog(t, ctx, opened, "38000000-0000-4000-8000-000000000001")
	firstMessage := enqueue(t, ctx, opened, "38000000-0000-4000-8000-000000000002", dialogID, "first", 1)
	first := dispatch(t, ctx, opened)
	firstRef := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialogID, RequestID: firstMessage.RequestID, AttemptID: first.AttemptID, Generation: 1}
	if err := opened.ObserveAdapterEvent(ctx, firstRef, harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: firstRef}, Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "none"}); err != nil {
		t.Fatal(err)
	}
	secondMessage := enqueue(t, ctx, opened, "38000000-0000-4000-8000-000000000003", dialogID, "second", 2)
	second := dispatch(t, ctx, opened)
	secondRef := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialogID, RequestID: secondMessage.RequestID, AttemptID: second.AttemptID, Generation: 1}
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.AttemptID == secondRef.AttemptID && active.State == "running"
	})
	archiveSeedAttemptOutputBytes(t, dataDir, firstRef.AttemptID, node.MaximumAttemptOutputBytes-1)

	late := harnessadapter.AssistantDeltaEvent{
		EventBase:  harnessadapter.EventBase{Attempt: firstRef},
		MessageID:  "38000000-0000-4000-8000-000000000004",
		DeltaIndex: 0,
		Content:    harnessprotocol.SafeContent{Kind: "inline", Content: "xx", Redaction: "none"},
	}
	if err := opened.ObserveAdapterEvent(ctx, firstRef, late); err != nil {
		t.Fatal(err)
	}
	rows, _, _, charge, encoded := archiveStats(t, dataDir, firstRef.AttemptID)
	if rows != 1 || charge != 2 {
		t.Fatalf("late overflow rows=%d charge=%d", rows, charge)
	}
	var marker harnessprotocol.SafeContent
	if json.Unmarshal(encoded, &marker) != nil || marker.Kind != "unavailable" || marker.Reason != "output_limit" {
		t.Fatalf("late archive retained raw delta: %s", encoded)
	}
	var outputBytes int64
	db := archiveDB(t, dataDir)
	if err := db.QueryRow("SELECT output_bytes FROM attempts WHERE attempt_id=?", firstRef.AttemptID).Scan(&outputBytes); err != nil {
		t.Fatal(err)
	}
	if outputBytes != node.MaximumAttemptOutputBytes-1 {
		t.Fatalf("late charge mutated attempt row: %d", outputBytes)
	}
	after := currentSnapshot(t, ctx, opened)
	if after.ActiveAttempt == nil || after.ActiveAttempt.AttemptID != secondRef.AttemptID || after.ActiveAttempt.State != "running" || countAdapterCalls(adapter, "cancel") != 0 {
		t.Fatalf("late old generation changed current execution: snapshot=%+v calls=%+v", after, adapter.CallsSnapshot())
	}
	events := attemptEvents(t, ctx, opened, firstRef.AttemptID)
	found := false
	for _, envelope := range events {
		if envelope.Type != "assistant.delta" {
			continue
		}
		var payload harnessprotocol.AssistantDeltaPayload
		if json.Unmarshal(envelope.Payload, &payload) == nil && payload.Content.Kind == "unavailable" && payload.Content.Reason == "output_limit" {
			found = true
		}
	}
	if !found {
		t.Fatal("late C1 event did not expose unavailable/output_limit")
	}
}

func TestLateTerminalDigestIncludesOutputAndMatchesActiveProjection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	streamInput := make(chan harnessadapter.Event, 1)
	adapter := fixture.NewAdapter()
	adapter.StreamInput = streamInput
	dataDir := t.TempDir()
	config := testConfig(dataDir)
	config.ManualDispatchForTesting = true
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "38500000-0000-4000-8000-000000000001")
	firstMessage := enqueue(t, ctx, opened, "38500000-0000-4000-8000-000000000002", dialogID, "first", 1)
	first := dispatch(t, ctx, opened)
	firstRef := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialogID, RequestID: firstMessage.RequestID, AttemptID: first.AttemptID, Generation: 1}
	completed := harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: firstRef}, Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "none"}
	streamInput <- completed
	waitFor(t, func() bool { return currentSnapshot(t, ctx, opened).ActiveAttempt == nil })
	secondMessage := enqueue(t, ctx, opened, "38500000-0000-4000-8000-000000000003", firstRef.DialogID, "second", 2)
	second := dispatch(t, ctx, opened)
	secondRef := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: firstRef.DialogID, RequestID: secondMessage.RequestID, AttemptID: second.AttemptID, Generation: 1}
	waitFor(t, func() bool {
		active := currentSnapshot(t, ctx, opened).ActiveAttempt
		return active != nil && active.AttemptID == secondRef.AttemptID && active.State == "running"
	})
	if err := opened.ObserveAdapterEvent(ctx, firstRef, completed); err != nil {
		t.Fatalf("active terminal duplicate failed: %v", err)
	}
	rows, _, _, _, _ := archiveStats(t, dataDir, firstRef.AttemptID)
	if rows != 0 {
		t.Fatalf("active terminal duplicate was archived: %d", rows)
	}
	firstOutput := harnessprotocol.SafeContent{Kind: "inline", Content: "late-a", Redaction: "none"}
	late := completed
	late.Output = &firstOutput
	if err := opened.ObserveAdapterEvent(ctx, firstRef, late); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(ctx, firstRef, late); err != nil {
		t.Fatalf("exact late terminal duplicate failed: %v", err)
	}
	rows, _, _, charge, _ := archiveStats(t, dataDir, firstRef.AttemptID)
	if rows != 1 || charge != int64(len(firstOutput.Content)) {
		t.Fatalf("late terminal ledger rows=%d charge=%d", rows, charge)
	}
	secondOutput := firstOutput
	secondOutput.Content = "late-b"
	conflict := completed
	conflict.Output = &secondOutput
	if err := opened.ObserveAdapterEvent(ctx, firstRef, conflict); err == nil {
		t.Fatal("different terminal Output was silently deduplicated")
	}
	after := currentSnapshot(t, ctx, opened)
	if after.ActiveAttempt == nil || after.ActiveAttempt.AttemptID != secondRef.AttemptID || after.ActiveAttempt.State != "running" || countAdapterCalls(adapter, "cancel") != 0 {
		t.Fatalf("late terminal digest check changed current execution: snapshot=%+v calls=%+v", after, adapter.CallsSnapshot())
	}
}

func TestArchiveLedgerBudgetQueryUsesAttemptIndex(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opened, _, dataDir, reference, _ := openOutputTestNode(t, ctx)
	defer opened.Close()
	db := archiveDB(t, dataDir)
	assertQueryPlanUses(t, ctx, db, "one_late_projection", "EXPLAIN QUERY PLAN SELECT COALESCE(SUM(output_bytes),0) FROM late_observations WHERE attempt_id=? AND projection_key IS NOT NULL", reference.AttemptID)
	assertQueryPlanUses(t, ctx, db, "one_event_projection", "EXPLAIN QUERY PLAN SELECT EXISTS(SELECT 1 FROM events WHERE attempt_id=? AND projection_hash=? AND projection_key IS NOT NULL)", reference.AttemptID, strings.Repeat("0", 64))
}

func assertQueryPlanUses(t *testing.T, ctx context.Context, db *sql.DB, indexName, query string, args ...any) {
	t.Helper()
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var id, parent, unused int64
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail, indexName) {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("query plan did not use %s", indexName)
	}
}

func archiveDB(t *testing.T, dataDir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, "harness.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func archiveSeedAttemptOutputBytes(t *testing.T, dataDir, attemptID string, bytes int64) {
	t.Helper()
	if _, err := archiveDB(t, dataDir).Exec("UPDATE attempts SET output_bytes=? WHERE attempt_id=?", bytes, attemptID); err != nil {
		t.Fatal(err)
	}
}

func archiveStats(t *testing.T, dataDir, attemptID string) (rows, events, inputs, charge int64, encoded []byte) {
	t.Helper()
	db := archiveDB(t, dataDir)
	if err := db.QueryRow("SELECT COUNT(*),COALESCE(SUM(output_bytes),0) FROM late_observations WHERE attempt_id=?", attemptID).Scan(&rows, &charge); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE attempt_id=?", attemptID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM input_requests WHERE attempt_id=?", attemptID).Scan(&inputs); err != nil {
		t.Fatal(err)
	}
	if rows > 0 {
		if err := db.QueryRow("SELECT observation_json FROM late_observations WHERE attempt_id=? ORDER BY observation_id DESC LIMIT 1", attemptID).Scan(&encoded); err != nil {
			t.Fatal(err)
		}
	}
	return
}
