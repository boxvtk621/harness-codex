package node_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/historyreplica"
	"github.com/boxvtk621/harness-codex/runtime"
)

func TestHistoryExportStableChainAndBindingStreams(t *testing.T) {
	ctx := context.Background()
	config := testConfig(t.TempDir())
	config.Clock = func() time.Time { return time.Date(2026, 9, 17, 1, 2, 3, 0, time.UTC) }
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	created := decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t,
		"10000000-0000-4000-8000-000000000401", "dialog.create",
		map[string]any{"nodeId": testNodeID}, map[string]any{"registryVersion": 1}, map[string]any{})), 202)
	var dialog harnessprotocol.DialogCreateReferences
	if json.Unmarshal(created.References, &dialog) != nil {
		t.Fatal("dialog references are invalid")
	}
	queued := decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t,
		"10000000-0000-4000-8000-000000000402", "message.enqueue",
		map[string]any{"nodeId": testNodeID, "dialogId": dialog.DialogID},
		map[string]any{"dialogVersion": 1}, map[string]any{"text": "immutable user text"})), 202)
	var message harnessprotocol.MessageEnqueueReferences
	if json.Unmarshal(queued.References, &message) != nil {
		t.Fatal("message references are invalid")
	}
	identity := historyreplica.StreamIdentity{
		OwnerID: testOwnerID, LogicalDialogID: "10000000-0000-4000-8000-000000000499",
		NodeID: testNodeID, NodeDialogID: dialog.DialogID, BindingGeneration: 1,
	}
	first := collectHistoryExport(t, ctx, opened, identity, 2)
	if !first.checkpoint.Ready || first.checkpoint.IncompleteReason != "" ||
		first.checkpoint.AssetManifestHash == historyreplica.GenesisHash {
		t.Fatalf("checkpoint is not retirement-ready: %+v", first.checkpoint)
	}
	wantTypes := []string{
		historyreplica.RecordEntry, historyreplica.RecordExecutionFact,
		historyreplica.RecordReceipt, historyreplica.RecordAssetManifest,
	}
	for _, recordType := range wantTypes {
		if !slices.Contains(first.types, recordType) {
			t.Fatalf("record type %q missing: %v", recordType, first.types)
		}
	}
	if first.entryID != message.MessageID {
		t.Fatalf("entry id=%q want=%q", first.entryID, message.MessageID)
	}
	if slices.Contains(first.factKinds, "attempt.started") || slices.Contains(first.factKinds, "attempt.dispatching") {
		t.Fatalf("export executed future queue: %v", first.factKinds)
	}
	requests := opened.Requests(ctx, nodeTrust(), "queued", "", 10)
	if requests.HTTPStatus != 200 || !strings.Contains(string(requests.Body), message.RequestID) {
		t.Fatalf("queued request changed during export: %d %s", requests.HTTPStatus, requests.Body)
	}
	replayed := collectHistoryExport(t, ctx, opened, identity, 200)
	if first.streamID != replayed.streamID || first.checkpoint.ThroughSeq != replayed.checkpoint.ThroughSeq ||
		first.checkpoint.ChainHash != replayed.checkpoint.ChainHash || !slices.Equal(first.hashes, replayed.hashes) {
		t.Fatalf("duplicate export changed ledger: first=%+v replay=%+v", first, replayed)
	}
	dispatched := dispatch(t, ctx, opened)
	reference := harnessadapter.AttemptRef{
		NodeID: testNodeID, DialogID: dialog.DialogID, RequestID: message.RequestID,
		AttemptID: dispatched.AttemptID, Generation: 1,
	}
	if _, err := opened.StoreArtifact(ctx, node.ArtifactInput{
		Attempt: reference, Name: "generation-result.txt", MediaType: "text/plain", Redaction: "none", Disposition: "attachment",
	}, []byte("new generation asset")); err != nil {
		t.Fatal(err)
	}
	returned := identity
	returned.BindingGeneration = 3
	returnExport := collectHistoryExport(t, ctx, opened, returned, 200)
	if returnExport.streamID == first.streamID || returnExport.entryID != first.entryID ||
		returnExport.checkpoint.ThroughSeq <= first.checkpoint.ThroughSeq || !slices.Contains(returnExport.assetRevisions, 2) {
		t.Fatalf("A-B-A identity contract failed: first=%+v returned=%+v", first, returnExport)
	}
}

func TestHistoryExportKeepsTerminalFactWithoutAssistantEntry(t *testing.T) {
	ctx := context.Background()
	config := testConfig(t.TempDir())
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "10000000-0000-4000-8000-000000000421")
	message := enqueue(t, ctx, opened, "10000000-0000-4000-8000-000000000422", dialogID, "finish without text", 1)
	dispatched := dispatch(t, ctx, opened)
	reference := harnessadapter.AttemptRef{
		NodeID: testNodeID, DialogID: dialogID, RequestID: message.RequestID,
		AttemptID: dispatched.AttemptID, Generation: 1,
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.TerminalEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "none",
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return currentSnapshot(t, ctx, opened).ActiveAttempt == nil })
	exported := collectHistoryExport(t, ctx, opened, historyreplica.StreamIdentity{
		OwnerID: testOwnerID, LogicalDialogID: "10000000-0000-4000-8000-000000000429",
		NodeID: testNodeID, NodeDialogID: dialogID, BindingGeneration: 1,
	}, 200)
	if !slices.Contains(exported.factKinds, "attempt.completed") || slices.Contains(exported.entryRoles, "assistant") ||
		exported.checkpoint.EffectsSummary.FactCount == 0 {
		t.Fatalf("terminal fact or assistant absence was lost: facts=%v roles=%v checkpoint=%+v",
			exported.factKinds, exported.entryRoles, exported.checkpoint)
	}
}

func TestHistoryExportRemainsImmutableAcrossDispatchAssistantTerminalAndRestart(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	config := testConfig(path)
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	dialogID := createDialog(t, ctx, opened, "10000000-0000-4000-8000-000000000431")
	message := enqueue(t, ctx, opened, "10000000-0000-4000-8000-000000000432", dialogID, "immutable lifecycle", 1)
	identity := historyreplica.StreamIdentity{
		OwnerID: testOwnerID, LogicalDialogID: "10000000-0000-4000-8000-000000000439",
		NodeID: testNodeID, NodeDialogID: dialogID, BindingGeneration: 1,
	}
	queued := collectHistoryExport(t, ctx, opened, identity, 200)
	dispatched := dispatch(t, ctx, opened)
	running := collectHistoryExport(t, ctx, opened, identity, 200)
	assertHistoryHashPrefix(t, queued.hashes, running.hashes)
	reference := harnessadapter.AttemptRef{
		NodeID: testNodeID, DialogID: dialogID, RequestID: message.RequestID,
		AttemptID: dispatched.AttemptID, Generation: 1,
	}
	answerID := "10000000-0000-4000-8000-000000000433"
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.AssistantMessageEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: answerID,
		Content:      harnessprotocol.SafeContent{Kind: "inline", Content: "stable answer", Redaction: "none"},
		FinishReason: "complete",
	}); err != nil {
		t.Fatal(err)
	}
	withAssistant := collectHistoryExport(t, ctx, opened, identity, 200)
	assertHistoryHashPrefix(t, running.hashes, withAssistant.hashes)
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.TerminalEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, Outcome: harnessadapter.ReconcileCompleted,
		EffectStatus: "none",
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return currentSnapshot(t, ctx, opened).ActiveAttempt == nil })
	terminal := collectHistoryExport(t, ctx, opened, identity, 200)
	assertHistoryHashPrefix(t, withAssistant.hashes, terminal.hashes)
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	replayed := collectHistoryExport(t, ctx, reopened, identity, 200)
	if !slices.Equal(terminal.hashes, replayed.hashes) || terminal.checkpoint.ChainHash != replayed.checkpoint.ChainHash {
		t.Fatalf("restart changed immutable history: terminal=%+v replayed=%+v", terminal, replayed)
	}
}

func TestHistoryExportIncludesMessageDispositionFacts(t *testing.T) {
	ctx := context.Background()
	config := testConfig(t.TempDir())
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "10000000-0000-4000-8000-000000000441")
	message := enqueue(t, ctx, opened, "10000000-0000-4000-8000-000000000442", dialogID, "cancel me", 1)
	decodeReceipt(t, opened.SubmitCommand(ctx, nodeTrust(), command(t,
		"10000000-0000-4000-8000-000000000443", "request.cancel",
		map[string]any{"nodeId": testNodeID, "requestId": message.RequestID},
		map[string]any{"requestVersion": 1}, map[string]any{})), 202)
	exported := collectHistoryExport(t, ctx, opened, historyreplica.StreamIdentity{
		OwnerID: testOwnerID, LogicalDialogID: "10000000-0000-4000-8000-000000000449",
		NodeID: testNodeID, NodeDialogID: dialogID, BindingGeneration: 1,
	}, 200)
	if !slices.Contains(exported.factKinds, "message.disposition_changed") {
		t.Fatalf("message disposition fact missing: %v", exported.factKinds)
	}
}

func assertHistoryHashPrefix(t *testing.T, prefix, full []string) {
	t.Helper()
	if len(full) < len(prefix) || !slices.Equal(prefix, full[:len(prefix)]) {
		t.Fatalf("immutable history prefix changed: prefix=%v full=%v", prefix, full)
	}
}

type collectedExport struct {
	streamID       string
	entryID        string
	types          []string
	factKinds      []string
	entryRoles     []string
	assetRevisions []int64
	hashes         []string
	checkpoint     historyreplica.Checkpoint
}

func collectHistoryExport(t *testing.T, ctx context.Context, authority *node.Node, identity historyreplica.StreamIdentity, limit int) collectedExport {
	t.Helper()
	after := int64(0)
	result := collectedExport{}
	for {
		response := authority.ExportHistory(ctx, nodeTrust(), identity, after, limit)
		if response.HTTPStatus != 200 {
			t.Fatalf("export status=%d body=%s", response.HTTPStatus, response.Body)
		}
		var page historyreplica.ExportPage
		if json.Unmarshal(response.Body, &page) != nil || historyreplica.ValidatePage(page) != nil {
			t.Fatalf("invalid export page: %s", response.Body)
		}
		result.streamID, result.checkpoint = page.StreamID, page.Checkpoint
		for _, record := range page.Records {
			result.types = append(result.types, record.Type)
			result.hashes = append(result.hashes, record.RecordHash)
			switch record.Type {
			case historyreplica.RecordEntry:
				var entry historyreplica.TranscriptEntry
				if json.Unmarshal(record.Payload, &entry) != nil {
					t.Fatal("entry payload is invalid")
				}
				result.entryID = entry.EntryID
				result.entryRoles = append(result.entryRoles, entry.Role)
			case historyreplica.RecordExecutionFact:
				var fact historyreplica.ExecutionFact
				if json.Unmarshal(record.Payload, &fact) != nil {
					t.Fatal("fact payload is invalid")
				}
				result.factKinds = append(result.factKinds, fact.Kind)
			case historyreplica.RecordAssetManifest:
				result.assetRevisions = append(result.assetRevisions, record.Revision)
			}
		}
		if page.NextAfter == nil {
			break
		}
		after = *page.NextAfter
	}
	return result
}
