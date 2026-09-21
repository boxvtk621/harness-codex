package node_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/transcriptview"
	"github.com/boxvtk621/harness-codex/runtime"
)

func safeTextContent(value string, incomplete bool) harnessprotocol.SafeContent {
	preview := value
	if len(preview) > transcriptview.MaximumPreview {
		preview = preview[:transcriptview.MaximumPreview]
		for !utf8.ValidString(preview) {
			preview = preview[:len(preview)-1]
		}
	}
	return harnessprotocol.SafeContent{
		Kind: "inline", Content: preview, Redaction: "none",
		Truncated: incomplete || len(preview) != len(value),
	}
}

func readSafeTextManifest(t *testing.T, opened *node.Node, reference harnessadapter.AttemptRef, source transcriptview.Source) transcriptview.Manifest {
	t.Helper()
	result := opened.SafeTextManifest(context.Background(), nodeTrust(), reference.DialogID, reference.AttemptID, source)
	if result.HTTPStatus != 200 {
		t.Fatalf("manifest status=%d body=%s", result.HTTPStatus, result.Body)
	}
	manifest, err := transcriptview.Decode(result.Body)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func readSafeText(t *testing.T, opened *node.Node, manifest transcriptview.Manifest) []byte {
	t.Helper()
	value := make([]byte, manifest.SizeBytes)
	for _, chunk := range manifest.Chunks {
		if metadata := opened.ArtifactMetadata(context.Background(), nodeTrust(), chunk.ArtifactID); metadata.HTTPStatus != 404 {
			t.Fatalf("private chunk escaped generic metadata: %d %s", metadata.HTTPStatus, metadata.Body)
		}
		if _, failure, ok := opened.Artifact(context.Background(), nodeTrust(), chunk.ArtifactID); ok || failure.HTTPStatus != 404 {
			t.Fatalf("private chunk escaped generic bytes: ok=%v failure=%+v", ok, failure)
		}
		blob, failure, ok := opened.SafeTextChunk(
			context.Background(), nodeTrust(), manifest.DialogID, manifest.AttemptID, manifest.TextID, manifest.Source,
			chunk.Index, chunk.ArtifactID, chunk.SizeBytes, chunk.SHA256,
		)
		if !ok || failure.HTTPStatus != 0 || blob.TextID != manifest.TextID || blob.Chunk != chunk || int64(len(blob.Bytes)) != chunk.SizeBytes {
			t.Fatalf("exact chunk read failed ok=%v failure=%+v chunk=%+v", ok, failure, blob.Chunk)
		}
		copy(value[chunk.OffsetBytes:chunk.OffsetBytes+chunk.SizeBytes], blob.Bytes)
	}
	return value
}

func artifactEntryNames(t *testing.T, path string) map[string]struct{} {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(path, "artifacts"))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]struct{}{}
	}
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		result[entry.Name()] = struct{}{}
	}
	return result
}

func requireSameArtifactEntries(t *testing.T, before, after map[string]struct{}) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("artifact entries changed: before=%v after=%v", before, after)
	}
	for name := range before {
		if _, ok := after[name]; !ok {
			t.Fatalf("artifact entry %q changed: before=%v after=%v", name, before, after)
		}
	}
}

func TestSafeTextKnownRollbackRemovesPublishedFiles(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	opened, reference := runningAttempt(t, path)
	defer opened.Close()
	before := artifactEntryNames(t, path)
	answer := strings.Repeat("rollback-safe-", transcriptview.MaximumPreview/14+2)
	messageID := "71000000-0000-4000-8000-000000000020"
	event := harnessadapter.AssistantMessageEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: messageID,
		Content: safeTextContent(answer, false), FinishReason: "complete", FullText: &answer,
	}
	opened.SetFaultInjector(func(point node.FaultPoint) error {
		if point == node.FaultBeforeCommit {
			return errors.New("synthetic safe text commit fault")
		}
		return nil
	})
	if err := opened.ObserveAdapterEvent(ctx, reference, event); err == nil {
		t.Fatal("safe text commit fault succeeded")
	}
	opened.SetFaultInjector(nil)
	requireSameArtifactEntries(t, before, artifactEntryNames(t, path))
	source := transcriptview.Source{Kind: "assistant_message", ID: messageID, Stream: "none"}
	if result := opened.SafeTextManifest(ctx, nodeTrust(), reference.DialogID, reference.AttemptID, source); result.HTTPStatus != 404 {
		t.Fatalf("rolled back safe text remained durable: %d %s", result.HTTPStatus, result.Body)
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, event); err != nil {
		t.Fatalf("safe text retry after known rollback failed: %v", err)
	}
	manifest := readSafeTextManifest(t, opened, reference, source)
	if !bytes.Equal(readSafeText(t, opened, manifest), []byte(answer)) {
		t.Fatal("safe text retry changed bytes")
	}
}

func TestSafeTextStartupRemovesOnlyUnreferencedArtifactFiles(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	opened, reference := runningAttempt(t, path)
	answer := "committed transcript survives orphan reconciliation"
	messageID := "71000000-0000-4000-8000-000000000021"
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.AssistantMessageEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: messageID,
		Content: safeTextContent(answer, false), FinishReason: "complete", FullText: &answer,
	}); err != nil {
		t.Fatal(err)
	}
	source := transcriptview.Source{Kind: "assistant_message", ID: messageID, Stream: "none"}
	manifest := readSafeTextManifest(t, opened, reference, source)
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}

	directoryPath := filepath.Join(path, "artifacts")
	orphanID := "79000000-0000-4000-8000-000000000001"
	temporaryID := "79000000-0000-4000-8000-000000000002"
	for name, body := range map[string]string{orphanID: "fsync orphan", "." + temporaryID + ".tmp": "partial"} {
		file, err := os.OpenFile(filepath.Join(directoryPath, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString(body); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Sync(); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	directory, err := os.Open(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}

	reopenConfig := testConfig(path)
	reopenConfig.Policies = fixture.NewPolicySource()
	opened, err = node.Open(ctx, reopenConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	for _, name := range []string{orphanID, "." + temporaryID + ".tmp"} {
		if _, err := os.Lstat(filepath.Join(directoryPath, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unreferenced artifact %q remained after startup: %v", name, err)
		}
	}
	if !bytes.Equal(readSafeText(t, opened, manifest), []byte(answer)) {
		t.Fatal("startup reconciliation removed committed safe text")
	}
}

func TestSafeTextDurabilityChunkingScopeAndReplay(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	opened, reference := runningAttempt(t, path)

	messageID := "71000000-0000-4000-8000-000000000001"
	answer := strings.Repeat("a", transcriptview.MaximumPreview+257)
	event := harnessadapter.AssistantMessageEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: messageID,
		Content: safeTextContent(answer, false), FinishReason: "complete", FullText: &answer,
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, event); err != nil {
		t.Fatal(err)
	}
	source := transcriptview.Source{Kind: "assistant_message", ID: messageID, Stream: "none"}
	manifest := readSafeTextManifest(t, opened, reference, source)
	if !manifest.Complete || !manifest.PreviewTruncated || manifest.SizeBytes != int64(len(answer)) || len(manifest.Chunks) != 1 ||
		!bytes.Equal(readSafeText(t, opened, manifest), []byte(answer)) {
		t.Fatalf("complete answer was not retained: %+v", manifest)
	}
	chunkSize := manifest.Chunks[0].SizeBytes
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.AssistantMessageEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: "71000000-0000-4000-8000-000000000010",
		Content: harnessprotocol.SafeContent{
			Kind: "artifact", ArtifactID: manifest.Chunks[0].ArtifactID, SizeBytes: &chunkSize,
			SHA256: manifest.Chunks[0].SHA256, Redaction: manifest.Redaction,
		}, FinishReason: "complete",
	}); err == nil || !strings.Contains(err.Error(), "artifact safe content binding mismatch") {
		t.Fatalf("internal transcript chunk was accepted as provider artifact: %v", err)
	}

	if err := opened.ObserveAdapterEvent(ctx, reference, event); err != nil {
		t.Fatalf("exact replay was not idempotent: %v", err)
	}
	conflict := answer[:len(answer)-1] + "b"
	conflictingEvent := event
	conflictingEvent.FullText = &conflict
	if err := opened.ObserveAdapterEvent(ctx, reference, conflictingEvent); err == nil || !strings.Contains(err.Error(), "conflicting safe text source") {
		t.Fatalf("same source with another full-text hash was accepted: %v", err)
	}

	multibyteID := "71000000-0000-4000-8000-000000000002"
	multibyte := strings.Repeat("€", transcriptview.MaximumChunkBytes/3+3)
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.AssistantMessageEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: multibyteID,
		Content: safeTextContent(multibyte, false), FinishReason: "complete", FullText: &multibyte,
	}); err != nil {
		t.Fatal(err)
	}
	multibyteManifest := readSafeTextManifest(t, opened, reference, transcriptview.Source{Kind: "assistant_message", ID: multibyteID, Stream: "none"})
	if len(multibyteManifest.Chunks) != 2 || multibyteManifest.Chunks[0].SizeBytes > transcriptview.MaximumChunkBytes ||
		multibyteManifest.Chunks[1].OffsetBytes != multibyteManifest.Chunks[0].SizeBytes ||
		!bytes.Equal(readSafeText(t, opened, multibyteManifest), []byte(multibyte)) {
		t.Fatalf("UTF-8 text was not split into exact bounded chunks: %+v", multibyteManifest.Chunks)
	}

	oldMessageID := "71000000-0000-4000-8000-000000000003"
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.AssistantMessageEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: oldMessageID,
		Content: harnessprotocol.SafeContent{Kind: "inline", Content: "old preview", Redaction: "none", Truncated: true}, FinishReason: "length",
	}); err != nil {
		t.Fatal(err)
	}
	missing := opened.SafeTextManifest(ctx, nodeTrust(), reference.DialogID, reference.AttemptID, transcriptview.Source{Kind: "assistant_message", ID: oldMessageID, Stream: "none"})
	if missing.HTTPStatus != 404 {
		t.Fatalf("old truncated result was presented as complete: %d %s", missing.HTTPStatus, missing.Body)
	}
	foreign := opened.SafeTextManifest(ctx, node.TrustContext{ActorID: "1-2", TransportNodeID: testNodeID, PeerVerified: true}, reference.DialogID, reference.AttemptID, source)
	if foreign.HTTPStatus != 403 {
		t.Fatalf("foreign owner read safe text: %d %s", foreign.HTTPStatus, foreign.Body)
	}
	wrongSource := source
	wrongSource.ID = "71000000-0000-4000-8000-000000000009"
	if result := opened.SafeTextManifest(ctx, nodeTrust(), reference.DialogID, reference.AttemptID, wrongSource); result.HTTPStatus != 404 {
		t.Fatalf("wrong source resolved: %d %s", result.HTTPStatus, result.Body)
	}

	var schemaVersion, transcriptTables, usageRows, artifactRows, internalRows, manifestRows, publicArtifactEvents int
	var usageArtifactID, usageEncoding string
	var usageSealed bool
	db, err := sql.Open("sqlite", "file:"+filepath.Join(path, "harness.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("PRAGMA user_version").Scan(&schemaVersion); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('safe_texts','safe_text_chunks','safe_text_usage')").Scan(&transcriptTables); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM artifacts WHERE media_type='application/vnd.homelab.transcript-usage-v1'").Scan(&usageRows); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT artifact_id,COALESCE(call_id,''),truncated FROM artifacts WHERE media_type='application/vnd.homelab.transcript-usage-v1'").Scan(&usageArtifactID, &usageEncoding, &usageSealed); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM artifacts").Scan(&artifactRows); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM artifacts WHERE disposition='transcript_internal'").Scan(&internalRows); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM artifacts WHERE media_type='application/vnd.homelab.transcript-view-v1+json'").Scan(&manifestRows); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE json_extract(CAST(event_json AS TEXT),'$.type')='artifact.available'`).Scan(&publicArtifactEvents); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	if schemaVersion != node.SchemaVersion || transcriptTables != 0 || usageRows != 1 || artifactRows != 6 || internalRows != 6 || manifestRows != 2 || publicArtifactEvents != 0 {
		t.Fatalf("private transcript storage is not additive: schema=%d tables=%d usage=%d artifacts=%d internal=%d manifests=%d events=%d", schemaVersion, transcriptTables, usageRows, artifactRows, internalRows, manifestRows, publicArtifactEvents)
	}
	usageParts := strings.Split(usageEncoding, ":")
	if len(usageParts) != 5 || usageParts[0] != "v1" || usageSealed {
		t.Fatalf("private transcript usage row is invalid: encoding=%q sealed=%v", usageEncoding, usageSealed)
	}
	usageValues := make([]int64, 4)
	for index, part := range usageParts[1:] {
		usageValues[index], err = strconv.ParseInt(part, 10, 64)
		if err != nil {
			t.Fatalf("private transcript usage value %q is invalid: %v", part, err)
		}
	}
	wantTextBytes := int64(len(answer) + len(multibyte))
	if usageValues[0] != wantTextBytes || usageValues[1] <= wantTextBytes || usageValues[2] != 2 || usageValues[3] != 3 {
		t.Fatalf("private transcript usage was not exact: got=%v want text=%d sources=2 chunks=3", usageValues, wantTextBytes)
	}
	if result := opened.ArtifactMetadata(ctx, nodeTrust(), usageArtifactID); result.HTTPStatus != 404 {
		t.Fatalf("private usage ledger escaped generic metadata: %d %s", result.HTTPStatus, result.Body)
	}
	if _, failure, ok := opened.Artifact(ctx, nodeTrust(), usageArtifactID); ok || failure.HTTPStatus != 404 {
		t.Fatalf("private usage ledger escaped generic bytes: ok=%v failure=%+v", ok, failure)
	}

	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopenConfig := testConfig(path)
	reopenConfig.Policies = fixture.NewPolicySource()
	opened, err = node.Open(ctx, reopenConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	restarted := readSafeTextManifest(t, opened, reference, source)
	if !bytes.Equal(readSafeText(t, opened, restarted), []byte(answer)) {
		t.Fatal("safe text changed after restart")
	}
}

func TestSafeToolTextLimitAndChunkIntegrity(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	opened, reference := runningAttempt(t, path)
	defer opened.Close()

	callID := "72000000-0000-4000-8000-000000000001"
	startTool(t, opened, reference, callID, "a")
	toolResult := strings.Repeat("t", 1<<20)
	content := safeTextContent(toolResult, false)
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.ToolOutputEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID, ChunkIndex: 0, Stream: "result",
		Output: content, FullText: &toolResult,
	}); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.ToolCompletedEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID, Status: "succeeded",
		Result: content, EffectStatus: "none", FullText: &toolResult,
	}); err != nil {
		t.Fatal(err)
	}
	for _, source := range []transcriptview.Source{
		{Kind: "tool_output", ID: callID, Index: 0, Stream: "result"},
		{Kind: "tool_result", ID: callID, Stream: "none"},
	} {
		manifest := readSafeTextManifest(t, opened, reference, source)
		if !manifest.Complete || manifest.SizeBytes != 1<<20 || !bytes.Equal(readSafeText(t, opened, manifest), []byte(toolResult)) {
			t.Fatalf("1 MiB tool result was not retained: %+v", manifest)
		}
	}

	incompleteCallID := "72000000-0000-4000-8000-000000000002"
	startTool(t, opened, reference, incompleteCallID, "b")
	retainedPrefix := strings.Repeat("p", 1<<20)
	incompleteContent := safeTextContent(retainedPrefix, true)
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.ToolOutputEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: incompleteCallID, ChunkIndex: 0, Stream: "result",
		Output: incompleteContent, FullText: &retainedPrefix, FullTextIncomplete: true,
	}); err != nil {
		t.Fatal(err)
	}
	incomplete := readSafeTextManifest(t, opened, reference, transcriptview.Source{Kind: "tool_output", ID: incompleteCallID, Index: 0, Stream: "result"})
	if incomplete.Complete || incomplete.Reason != "output_limit_exceeded" || len(incomplete.Chunks) != 0 || !incomplete.PreviewTruncated {
		t.Fatalf("producer truncation was not explicit: %+v", incomplete)
	}
	var rowsBefore, rowsAfter, sealed int
	var usageBefore, usageAfter string
	database, err := sql.Open("sqlite", "file:"+filepath.Join(path, "harness.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT COUNT(*) FROM artifacts WHERE disposition='transcript_internal'").Scan(&rowsBefore); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT COALESCE(call_id,'') FROM artifacts WHERE attempt_id=? AND media_type='application/vnd.homelab.transcript-usage-v1'", reference.AttemptID).Scan(&usageBefore); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	ignored := "ignored after durable limit marker"
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.ToolOutputEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: incompleteCallID, ChunkIndex: 1, Stream: "result",
		Output: safeTextContent(ignored, false), FullText: &ignored,
	}); err != nil {
		t.Fatal(err)
	}
	missingSource := transcriptview.Source{Kind: "tool_output", ID: incompleteCallID, Index: 1, Stream: "result"}
	if result := opened.SafeTextManifest(ctx, nodeTrust(), reference.DialogID, reference.AttemptID, missingSource); result.HTTPStatus != 404 {
		t.Fatalf("sealed usage created another manifest: %d %s", result.HTTPStatus, result.Body)
	}
	database, err = sql.Open("sqlite", "file:"+filepath.Join(path, "harness.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT COUNT(*) FROM artifacts WHERE disposition='transcript_internal'").Scan(&rowsAfter); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT truncated FROM artifacts WHERE attempt_id=? AND media_type='application/vnd.homelab.transcript-usage-v1'", reference.AttemptID).Scan(&sealed); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT COALESCE(call_id,'') FROM artifacts WHERE attempt_id=? AND media_type='application/vnd.homelab.transcript-usage-v1'", reference.AttemptID).Scan(&usageAfter); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if rowsAfter != rowsBefore || usageAfter != usageBefore || sealed != 1 {
		t.Fatalf("sealed usage grew private storage: rows=%d/%d usage=%q/%q sealed=%d", rowsBefore, rowsAfter, usageBefore, usageAfter, sealed)
	}

	complete := readSafeTextManifest(t, opened, reference, transcriptview.Source{Kind: "tool_result", ID: callID, Stream: "none"})
	chunk := complete.Chunks[0]
	if err := os.WriteFile(filepath.Join(path, "artifacts", chunk.ArtifactID), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, failure, ok := opened.SafeTextChunk(ctx, nodeTrust(), complete.DialogID, complete.AttemptID, complete.TextID, complete.Source, chunk.Index, chunk.ArtifactID, chunk.SizeBytes, chunk.SHA256); ok || failure.HTTPStatus != 503 {
		t.Fatalf("corrupt safe text chunk remained readable: ok=%v status=%d body=%s", ok, failure.HTTPStatus, failure.Body)
	}
}

func startTool(t *testing.T, opened *node.Node, reference harnessadapter.AttemptRef, callID, hashDigit string) {
	t.Helper()
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ToolStartedEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID,
		ToolName: "cursor.command", ActionHash: strings.Repeat(hashDigit, 64),
		Input: harnessprotocol.SafeContent{Kind: "inline", Content: "safe input", Redaction: "none"},
	}); err != nil {
		t.Fatal(err)
	}
}
