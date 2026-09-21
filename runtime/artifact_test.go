package node_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

func runningAttempt(t *testing.T, path string) (*node.Node, harnessadapter.AttemptRef) {
	t.Helper()
	config := testConfig(path)
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	created := decodeReceipt(t, opened.SubmitCommand(context.Background(), nodeTrust(), command(t, "10000000-0000-4000-8000-000000000201", "dialog.create", map[string]any{"nodeId": testNodeID}, map[string]any{"registryVersion": 1}, map[string]any{})), 202)
	var refs harnessprotocol.DialogCreateReferences
	if err := json.Unmarshal(created.References, &refs); err != nil {
		t.Fatal(err)
	}
	enqueued := decodeReceipt(t, opened.SubmitCommand(context.Background(), nodeTrust(), command(t, "10000000-0000-4000-8000-000000000202", "message.enqueue", map[string]any{"nodeId": testNodeID, "dialogId": refs.DialogID}, map[string]any{"dialogVersion": 1}, map[string]any{"text": "artifact"})), 202)
	var message harnessprotocol.MessageEnqueueReferences
	if err := json.Unmarshal(enqueued.References, &message); err != nil {
		t.Fatal(err)
	}
	dispatched, err := opened.DispatchNext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		var snapshot harnessprotocol.Snapshot
		result := opened.Snapshot(context.Background(), nodeTrust())
		return result.HTTPStatus == 200 && json.Unmarshal(result.Body, &snapshot) == nil && snapshot.ActiveAttempt != nil && snapshot.ActiveAttempt.State == "running"
	})
	return opened, harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: refs.DialogID, RequestID: message.RequestID, AttemptID: dispatched.AttemptID, Generation: 1}
}

func TestArtifactSinkDurabilityScopeAndCorruption(t *testing.T) {
	path := t.TempDir()
	ingress := node.NewArtifactIngress()
	if _, err := ingress.StoreArtifact(context.Background(), node.ArtifactInput{}, nil); err == nil {
		t.Fatal("unbound ingress accepted bytes")
	}
	config := testConfig(path)
	config.Policies = fixture.NewPolicySource()
	config.Artifacts = ingress
	opened, reference := runningAttemptWithConfig(t, config)
	content := []byte("safe artifact bytes")
	metadata, err := ingress.StoreArtifact(context.Background(), node.ArtifactInput{Attempt: reference, Name: "result.txt", MediaType: "text/plain; charset=utf-8", Redaction: "applied", Disposition: "attachment"}, content)
	if err != nil {
		t.Fatal(err)
	}
	for i := range content {
		content[i] = 'x'
	}
	blob, failure, ok := opened.Artifact(context.Background(), nodeTrust(), metadata.ArtifactID)
	if !ok || failure.HTTPStatus != 0 || !bytes.Equal(blob.Bytes, []byte("safe artifact bytes")) {
		t.Fatalf("durable artifact mismatch ok=%v failure=%+v", ok, failure)
	}
	if result := opened.ArtifactMetadata(context.Background(), nodeTrust(), metadata.ArtifactID); result.HTTPStatus != 200 || harnessprotocol.Validate("artifactMetadata", result.Body) != nil {
		t.Fatalf("metadata invalid status=%d body=%s", result.HTTPStatus, result.Body)
	}
	if err := os.WriteFile(filepath.Join(path, "artifacts", metadata.ArtifactID), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result := opened.ArtifactMetadata(context.Background(), nodeTrust(), metadata.ArtifactID); result.HTTPStatus != 503 {
		t.Fatalf("corrupt metadata status=%d body=%s", result.HTTPStatus, result.Body)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ingress.StoreArtifact(context.Background(), node.ArtifactInput{Attempt: reference}, nil); err == nil {
		t.Fatal("closed ingress accepted bytes")
	}
}

func TestArtifactMetadataUsesContractUTF8ByteLimit(t *testing.T) {
	opened, reference := runningAttempt(t, t.TempDir())
	defer opened.Close()
	validName := strings.Repeat("я", 100)
	if _, err := opened.StoreArtifact(context.Background(), node.ArtifactInput{Attempt: reference, Name: validName, MediaType: "text/plain", Redaction: "none", Disposition: "attachment"}, []byte("safe")); err != nil {
		t.Fatalf("200-byte UTF-8 artifact name rejected: %v", err)
	}
	if _, err := opened.StoreArtifact(context.Background(), node.ArtifactInput{Attempt: reference, Name: validName + "x", MediaType: "text/plain", Redaction: "none", Disposition: "attachment"}, []byte("safe")); err == nil {
		t.Fatal("201-byte artifact name accepted")
	}
	for _, input := range []node.ArtifactInput{
		{Attempt: reference, Name: "safe-text-forged.txt", MediaType: "text/plain", Redaction: "none", Disposition: "attachment"},
		{Attempt: reference, Name: "forged.json", MediaType: "application/vnd.homelab.transcript-view-v1+json", Redaction: "none", Disposition: "attachment"},
	} {
		if _, err := opened.StoreArtifact(context.Background(), input, []byte("safe")); err == nil {
			t.Fatalf("reserved transcript artifact accepted: %+v", input)
		}
	}
}

func TestArtifactOutputBudgetPersistsMarkerAndSchedulesOneStop(t *testing.T) {
	path := t.TempDir()
	adapter := fixture.NewAdapter()
	config := testConfig(path)
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, reference := runningAttemptWithConfig(t, config)
	defer opened.Close()
	setAttemptOutputBytes(t, path, reference.AttemptID, node.MaximumAttemptOutputBytes)
	input := node.ArtifactInput{Attempt: reference, Name: "overflow.txt", MediaType: "text/plain", Redaction: "none", Disposition: "attachment"}
	if _, err := opened.StoreArtifact(context.Background(), input, []byte("x")); !errors.Is(err, node.ErrOutputLimit) {
		t.Fatalf("artifact overflow error=%v", err)
	}
	waitFor(t, func() bool { return countAdapterCalls(adapter, "cancel") == 1 })
	if _, err := opened.StoreArtifact(context.Background(), input, []byte("y")); !errors.Is(err, node.ErrOutputLimit) {
		t.Fatalf("sticky artifact overflow error=%v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if got := countAdapterCalls(adapter, "cancel"); got != 1 {
		t.Fatalf("artifact overflow scheduled %d cancels", got)
	}
	var outputBytes, artifacts, markers int64
	queryArtifactProjection(t, path, reference.AttemptID, &outputBytes, &artifacts, &markers)
	if outputBytes != node.MaximumAttemptOutputBytes+1 || artifacts != 0 || markers != 1 {
		t.Fatalf("overflow projection bytes=%d artifacts=%d markers=%d", outputBytes, artifacts, markers)
	}
}

func TestArtifactOverflowForOldAttemptDoesNotCancelNewGeneration(t *testing.T) {
	path := t.TempDir()
	adapter := fixture.NewAdapter()
	config := testConfig(path)
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, old := runningAttemptWithConfig(t, config)
	defer opened.Close()
	if err := opened.ObserveAdapterEvent(context.Background(), old, harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: old}, Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "none"}); err != nil {
		t.Fatal(err)
	}
	queued := enqueue(t, context.Background(), opened, "10000000-0000-4000-8000-000000000344", old.DialogID, "new generation", 2)
	dispatched, err := opened.DispatchNext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	active := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: old.DialogID, RequestID: queued.RequestID, AttemptID: dispatched.AttemptID, Generation: 1}
	waitFor(t, func() bool {
		snapshot := currentSnapshot(t, context.Background(), opened)
		return snapshot.ActiveAttempt != nil && snapshot.ActiveAttempt.AttemptID == active.AttemptID && snapshot.ActiveAttempt.State == "running"
	})
	setAttemptOutputBytes(t, path, old.AttemptID, node.MaximumAttemptOutputBytes)
	input := node.ArtifactInput{Attempt: old, Name: "late-overflow.txt", MediaType: "text/plain", Redaction: "none", Disposition: "attachment"}
	if _, err := opened.StoreArtifact(context.Background(), input, []byte("x")); !errors.Is(err, node.ErrOutputLimit) {
		t.Fatalf("old artifact overflow error=%v", err)
	}
	time.Sleep(20 * time.Millisecond)
	snapshot := currentSnapshot(t, context.Background(), opened)
	if snapshot.ActiveAttempt == nil || snapshot.ActiveAttempt.AttemptID != active.AttemptID || snapshot.ActiveAttempt.State != "running" || countAdapterCalls(adapter, "cancel") != 0 {
		t.Fatalf("old overflow affected active generation: snapshot=%+v calls=%+v", snapshot, adapter.CallsSnapshot())
	}
}

func setAttemptOutputBytes(t *testing.T, path, attemptID string, bytes int64) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(path, "harness.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE attempts SET output_bytes=? WHERE attempt_id=?", bytes, attemptID); err != nil {
		t.Fatal(err)
	}
}

func queryArtifactProjection(t *testing.T, path, attemptID string, outputBytes, artifacts, markers *int64) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(path, "harness.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.QueryRow("SELECT output_bytes FROM attempts WHERE attempt_id=?", attemptID).Scan(outputBytes); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM artifacts WHERE attempt_id=?", attemptID).Scan(artifacts); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE attempt_id=? AND projection_key='output_limit:artifact'", attemptID).Scan(markers); err != nil {
		t.Fatal(err)
	}
}

func countAdapterCalls(adapter *fixture.Adapter, method string) int {
	count := 0
	for _, call := range adapter.CallsSnapshot() {
		if call.Method == method {
			count++
		}
	}
	return count
}

func runningAttemptWithConfig(t *testing.T, config node.Config) (*node.Node, harnessadapter.AttemptRef) {
	t.Helper()
	opened, err := node.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	created := decodeReceipt(t, opened.SubmitCommand(context.Background(), nodeTrust(), command(t, "10000000-0000-4000-8000-000000000211", "dialog.create", map[string]any{"nodeId": testNodeID}, map[string]any{"registryVersion": 1}, map[string]any{})), 202)
	var d harnessprotocol.DialogCreateReferences
	_ = json.Unmarshal(created.References, &d)
	enqueued := decodeReceipt(t, opened.SubmitCommand(context.Background(), nodeTrust(), command(t, "10000000-0000-4000-8000-000000000212", "message.enqueue", map[string]any{"nodeId": testNodeID, "dialogId": d.DialogID}, map[string]any{"dialogVersion": 1}, map[string]any{"text": "artifact"})), 202)
	var m harnessprotocol.MessageEnqueueReferences
	_ = json.Unmarshal(enqueued.References, &m)
	dispatched, err := opened.DispatchNext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		var s harnessprotocol.Snapshot
		r := opened.Snapshot(context.Background(), nodeTrust())
		return r.HTTPStatus == 200 && json.Unmarshal(r.Body, &s) == nil && s.ActiveAttempt != nil && s.ActiveAttempt.State == "running"
	})
	return opened, harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: d.DialogID, RequestID: m.RequestID, AttemptID: dispatched.AttemptID, Generation: 1}
}

func TestArtifactReferenceIsNotCommittedBeforeBytes(t *testing.T) {
	path := t.TempDir()
	opened, reference := runningAttempt(t, path)
	defer opened.Close()
	projectionCounts := func() (int, int) {
		// The live node can still be committing stream events in DELETE journal
		// mode. Bound the observer's wait for that writer, as other DB probes do.
		db, err := sql.Open("sqlite", "file:"+filepath.Join(path, "harness.db")+"?mode=ro&_pragma=busy_timeout(5000)")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		var artifacts, availableEvents int
		if err := db.QueryRow("SELECT COUNT(*) FROM artifacts").Scan(&artifacts); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE json_extract(CAST(event_json AS TEXT),'$.type')='artifact.available'`).Scan(&availableEvents); err != nil {
			t.Fatal(err)
		}
		return artifacts, availableEvents
	}
	before, err := os.ReadDir(filepath.Join(path, "artifacts"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	beforeArtifacts, beforeEvents := projectionCounts()
	opened.SetFaultInjector(func(point node.FaultPoint) error {
		if point == node.FaultBeforeCommit {
			return errors.New("synthetic commit fault")
		}
		return nil
	})
	_, err = opened.ArtifactSink().StoreArtifact(context.Background(), node.ArtifactInput{Attempt: reference, Name: "failed.bin", MediaType: "application/octet-stream", Redaction: "none", Disposition: "attachment"}, []byte("never referenced"))
	if err == nil {
		t.Fatal("artifact commit fault succeeded")
	}
	opened.SetFaultInjector(nil)
	after, err := os.ReadDir(filepath.Join(path, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("failed artifact left bytes: before=%v after=%v", before, after)
	}
	afterArtifacts, afterEvents := projectionCounts()
	if afterArtifacts != beforeArtifacts || afterEvents != beforeEvents {
		t.Fatalf("failed artifact changed projection: artifacts %d->%d available events %d->%d", beforeArtifacts, afterArtifacts, beforeEvents, afterEvents)
	}
}

func TestArtifactLostAcknowledgementKeepsCommittedBytes(t *testing.T) {
	opened, reference := runningAttempt(t, t.TempDir())
	defer opened.Close()
	opened.SetFaultInjector(func(point node.FaultPoint) error {
		if point == node.FaultAfterCommit {
			return errors.New("synthetic lost acknowledgement")
		}
		return nil
	})
	metadata, err := opened.ArtifactSink().StoreArtifact(context.Background(), node.ArtifactInput{Attempt: reference, Name: "committed.bin", MediaType: "application/octet-stream", Redaction: "none", Disposition: "attachment"}, []byte("committed"))
	if err == nil || metadata.ArtifactID == "" {
		t.Fatalf("lost acknowledgement result metadata=%+v err=%v", metadata, err)
	}
	opened.SetFaultInjector(nil)
	blob, failure, ok := opened.Artifact(context.Background(), nodeTrust(), metadata.ArtifactID)
	if !ok || failure.HTTPStatus != 0 || !bytes.Equal(blob.Bytes, []byte("committed")) {
		t.Fatalf("committed artifact lost after ACK fault ok=%v failure=%+v", ok, failure)
	}
}

func TestArtifactDirectorySymlinkIsRejected(t *testing.T) {
	path := t.TempDir()
	outside := t.TempDir()
	config := testConfig(path)
	config.Policies = fixture.NewPolicySource()
	opened, reference := runningAttemptWithConfig(t, config)
	defer opened.Close()
	if err := os.Symlink(outside, filepath.Join(path, "artifacts")); err != nil {
		t.Fatal(err)
	}
	_, err := opened.ArtifactSink().StoreArtifact(context.Background(), node.ArtifactInput{Attempt: reference, Name: "escape", MediaType: "application/octet-stream", Redaction: "none", Disposition: "attachment"}, []byte("x"))
	if err == nil {
		t.Fatal("artifact symlink was accepted")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatalf("artifact escaped owner path: %v", entries)
	}
}

func TestArtifactReadRejectsReplacedDirectory(t *testing.T) {
	path := t.TempDir()
	opened, reference := runningAttempt(t, path)
	defer opened.Close()
	metadata, err := opened.ArtifactSink().StoreArtifact(context.Background(), node.ArtifactInput{Attempt: reference, Name: "safe", MediaType: "application/octet-stream", Redaction: "none", Disposition: "attachment"}, []byte("same bytes"))
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(path, "artifacts")
	moved := filepath.Join(path, "artifacts-original")
	if err := os.Rename(directory, moved); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, metadata.ArtifactID), []byte("same bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, directory); err != nil {
		t.Fatal(err)
	}
	if result := opened.ArtifactMetadata(context.Background(), nodeTrust(), metadata.ArtifactID); result.HTTPStatus != 503 {
		t.Fatalf("replaced parent accepted: %d %s", result.HTTPStatus, result.Body)
	}
}
