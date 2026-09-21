package node

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessbarrier"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/logicaldelete"
)

const (
	deleteTestNodeID  = "42000000-0000-4000-8000-000000000001"
	deleteTestOwnerID = "1-1"
)

func openDeleteNode(t *testing.T) *Node {
	t.Helper()
	opened, err := Open(context.Background(), Config{
		DataDir: t.TempDir(), NodeID: deleteTestNodeID, OwnerID: deleteTestOwnerID, RegistryVersion: 1,
		Adapter: fixture.NewAdapter(), Policies: fixture.NewPolicySource(), Space: fullSpace{}, ManualDispatchForTesting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return opened
}

func deleteTestTrust() TrustContext {
	return TrustContext{TransportNodeID: deleteTestNodeID}
}

func deleteTestOperatorTrust() OperatorTrustContext {
	return OperatorTrustContext{TransportNodeID: deleteTestNodeID}
}

func TestExecutorHeartbeatReturnsWorkerObservation(t *testing.T) {
	opened := openDeleteNode(t)
	defer opened.Close()

	const workerObservedAt = "2026-09-21T12:34:56Z"
	opened.heartbeatMu.Lock()
	opened.heartbeatAt = workerObservedAt
	opened.heartbeatMu.Unlock()

	result := opened.ExecutorHeartbeat(context.Background(), deleteTestTrust())
	if result.HTTPStatus != 200 {
		t.Fatalf("heartbeat status=%d body=%s", result.HTTPStatus, result.Body)
	}
	var heartbeat struct {
		NodeID     string `json:"nodeId"`
		BootID     string `json:"bootId"`
		ObservedAt string `json:"observedAt"`
	}
	if err := json.Unmarshal(result.Body, &heartbeat); err != nil {
		t.Fatal(err)
	}
	if heartbeat.NodeID != deleteTestNodeID || heartbeat.BootID == "" || heartbeat.ObservedAt != workerObservedAt {
		t.Fatalf("heartbeat did not return stored worker observation: %+v", heartbeat)
	}
}

func TestBootIdentityChangesAcrossRestartWithFixedClock(t *testing.T) {
	dataDir := t.TempDir()
	fixed := time.Date(2026, 9, 21, 12, 34, 56, 0, time.UTC)
	open := func() *Node {
		opened, err := Open(context.Background(), Config{
			DataDir: dataDir, NodeID: deleteTestNodeID, OwnerID: deleteTestOwnerID, RegistryVersion: 1,
			Adapter: fixture.NewAdapter(), Policies: fixture.NewPolicySource(), Space: fullSpace{}, ManualDispatchForTesting: true,
			Clock: func() time.Time { return fixed },
		})
		if err != nil {
			t.Fatal(err)
		}
		return opened
	}

	first := open()
	firstBootID := first.bootID
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := open()
	defer second.Close()
	if firstBootID == second.bootID {
		t.Fatalf("boot identity was reused across restart: %s", firstBootID)
	}
}

func createDeleteTestDialog(t *testing.T, opened *Node) string {
	t.Helper()
	result := opened.SubmitCommand(context.Background(), deleteTestTrust(), []byte(`{"protocolVersion":1,"schemaId":"harness-wire-v2","commandId":"42000000-0000-4000-8000-000000000002","kind":"dialog.create","target":{"nodeId":"`+deleteTestNodeID+`"},"expected":{"registryVersion":1},"payload":{}}`))
	if result.HTTPStatus != 202 {
		t.Fatalf("create status=%d body=%s", result.HTTPStatus, result.Body)
	}
	var receipt harnessprotocol.Receipt
	var references harnessprotocol.DialogCreateReferences
	if json.Unmarshal(result.Body, &receipt) != nil || json.Unmarshal(receipt.References, &references) != nil {
		t.Fatal("invalid create receipt")
	}
	return references.DialogID
}

func submitDelete(t *testing.T, opened *Node, dialogID string, version int64) Result {
	t.Helper()
	state, err := loadState(context.Background(), opened.db)
	if err != nil {
		t.Fatal(err)
	}
	install := harnessbarrier.InstallRequest{
		ProtocolVersion: harnessbarrier.ProtocolVersion, SchemaID: harnessbarrier.SchemaID,
		OperationID: "42000000-0000-4000-8000-000000000020", NodeID: deleteTestNodeID,
		ExpectedEpoch: state.Epoch, BindingGeneration: state.RegistryVersion,
		Scope: harnessbarrier.Scope{Kind: "dialog", DialogID: dialogID}, ExpectedScopeRevision: 0,
	}
	installRaw, _ := json.Marshal(install)
	installed := opened.InstallHold(context.Background(), deleteTestOperatorTrust(), installRaw)
	var hold harnessbarrier.HoldReceipt
	if installed.HTTPStatus != 201 || json.Unmarshal(installed.Body, &hold) != nil {
		t.Fatalf("install delete hold status=%d body=%s", installed.HTTPStatus, installed.Body)
	}
	request := logicaldelete.NodeRequest{
		SchemaID: logicaldelete.NodeSchemaID, OperationID: install.OperationID,
		CoordinatorRequestHash: strings.Repeat("a", 64), CommandID: "42000000-0000-4000-8000-000000000003",
		LogicalDialogID: "42000000-0000-4000-8000-000000000021", NodeID: deleteTestNodeID, NodeDialogID: dialogID,
		ExpectedEpoch: state.Epoch, RegistryVersion: state.RegistryVersion, BindingVersion: 1,
		ExpectedDialogVersion: version, HoldVersion: hold.HoldVersion, HoldScopeRevision: hold.ScopeRevision,
	}
	raw, _ := json.Marshal(request)
	return opened.DeleteLogicalDialog(context.Background(), deleteTestOperatorTrust(), raw)
}

func TestDialogDeleteRejectsStaleBusyAndUnresolvedWithoutMutation(t *testing.T) {
	for _, test := range []struct {
		name    string
		version int64
		seed    func(*testing.T, *Node, string)
	}{
		{name: "stale version", version: 2},
		{name: "queued request", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "queued", "")
		}},
		{name: "dispatching request", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "dispatching", "")
		}},
		{name: "active request", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "active", "")
		}},
		{name: "unknown request", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "unknown", "")
		}},
		{name: "dispatching attempt", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "completed", "dispatching")
		}},
		{name: "running attempt", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "active", "running")
		}},
		{name: "waiting input attempt", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "completed", "waiting_input")
		}},
		{name: "stopping attempt", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "completed", "stopping")
		}},
		{name: "unknown attempt", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "completed", "unknown")
		}},
		{name: "unresolved control", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "completed", "completed")
			if _, err := opened.db.Exec(`INSERT INTO control_actions(command_id,kind,attempt_id,payload,status) VALUES(?,?,?,?,?)`, "42000000-0000-4000-8000-000000000013", "approval.respond", "42000000-0000-4000-8000-000000000012", []byte(`{}`), "unknown"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "terminal attempt with unknown effects", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "completed", "completed")
			if _, err := opened.db.Exec("UPDATE attempts SET effect_status='unknown' WHERE dialog_id=?", dialogID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "terminal attempt with unrecognized effects", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "completed", "completed")
			if _, err := opened.db.Exec("UPDATE attempts SET effect_status='future_effect' WHERE dialog_id=?", dialogID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "running tool", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "completed", "completed")
			if _, err := opened.db.Exec(`INSERT INTO tool_calls(call_id,attempt_id,action_hash,version,status,safe_input_json) VALUES(?,?,?,?,?,?)`, "42000000-0000-4000-8000-000000000014", "42000000-0000-4000-8000-000000000012", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, "running", []byte(`{"kind":"inline","content":"safe","redaction":"none","truncated":false}`)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "pending approval", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "completed", "completed")
			if _, err := opened.db.Exec(`INSERT INTO approvals(approval_id,attempt_id,call_id,action_hash,version,status) VALUES(?,?,?,?,?,?)`, "42000000-0000-4000-8000-000000000015", "42000000-0000-4000-8000-000000000012", "42000000-0000-4000-8000-000000000014", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, "pending"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "pending input", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "completed", "completed")
			if _, err := opened.db.Exec(`INSERT INTO input_requests(input_request_id,attempt_id,version,status,prompt_json) VALUES(?,?,?,?,?)`, "42000000-0000-4000-8000-000000000016", "42000000-0000-4000-8000-000000000012", 1, "pending", []byte(`{"kind":"inline","content":"continue?","redaction":"none","truncated":false}`)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unknown completed tool effect", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "completed", "completed")
			seedToolEffect(t, opened, dialogID, `"unknown"`)
		}},
		{name: "unrecognized completed tool effect", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "completed", "completed")
			seedToolEffect(t, opened, dialogID, `"future_effect"`)
		}},
		{name: "missing completed tool effect", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "completed", "completed")
			seedToolEffect(t, opened, dialogID, "")
		}},
		{name: "unrecognized request state", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "future_nonterminal", "")
		}},
		{name: "unrecognized attempt state", version: 1, seed: func(t *testing.T, opened *Node, dialogID string) {
			seedDeleteAttempt(t, opened, dialogID, "completed", "future_nonterminal")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			opened := openDeleteNode(t)
			defer opened.Close()
			dialogID := createDeleteTestDialog(t, opened)
			if test.seed != nil {
				test.seed(t, opened, dialogID)
			}
			before, err := loadState(context.Background(), opened.db)
			if err != nil {
				t.Fatal(err)
			}
			result := submitDelete(t, opened, dialogID, test.version)
			if result.HTTPStatus != 409 {
				t.Fatalf("delete status=%d body=%s", result.HTTPStatus, result.Body)
			}
			after, err := loadState(context.Background(), opened.db)
			if err != nil {
				t.Fatal(err)
			}
			var dialogVersion, tombstones int64
			if err := opened.db.QueryRow(`SELECT d.version,(SELECT COUNT(*) FROM events WHERE projection_key='dialog.deleted') FROM dialogs d WHERE d.dialog_id=?`, dialogID).Scan(&dialogVersion, &tombstones); err != nil {
				t.Fatal(err)
			}
			if after.StateVersion != before.StateVersion || after.LastEventSeq != before.LastEventSeq || dialogVersion != 1 || tombstones != 0 {
				t.Fatalf("rejected delete mutated projection: before=%+v after=%+v dialogVersion=%d tombstones=%d", before, after, dialogVersion, tombstones)
			}
		})
	}
}

func seedDeleteAttempt(t *testing.T, opened *Node, dialogID, requestStatus, attemptState string) {
	t.Helper()
	messageID := "42000000-0000-4000-8000-000000000010"
	requestID := "42000000-0000-4000-8000-000000000011"
	if _, err := opened.db.Exec(`INSERT INTO messages(message_id,dialog_id,sequence,version,role,text,disposition,command_id,request_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, messageID, dialogID, 1, 1, "user", "retained", "applied", "42000000-0000-4000-8000-000000000009", requestID, "2026-09-13T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.db.Exec(`INSERT INTO requests(request_id,dialog_id,input_message_id,queue_sequence,version,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, requestID, dialogID, messageID, 1, 1, requestStatus, "2026-09-13T00:00:00Z", "2026-09-13T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if attemptState == "" {
		return
	}
	if _, err := opened.db.Exec(`INSERT INTO attempts(attempt_id,node_id,dialog_id,request_id,generation,version,state,effect_status) VALUES(?,?,?,?,?,?,?,?)`, "42000000-0000-4000-8000-000000000012", deleteTestNodeID, dialogID, requestID, 1, 1, attemptState, "none"); err != nil {
		t.Fatal(err)
	}
}

func seedToolEffect(t *testing.T, opened *Node, dialogID, effectStatusJSON string) {
	t.Helper()
	ctx := context.Background()
	tx, err := opened.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	callID := "42000000-0000-4000-8000-000000000014"
	if _, err := opened.appendEvent(ctx, tx, &state, "tool.completed", callID, 2, "42000000-0000-4000-8000-000000000012", dialogID, harnessprotocol.ToolCompletedPayload{
		CallID: callID, Status: "succeeded", EffectStatus: "unknown",
		Result: harnessprotocol.SafeContent{Kind: "inline", Content: "safe", Redaction: "none"},
	}, false); err != nil {
		t.Fatal(err)
	}
	if effectStatusJSON == "" {
		if _, err := tx.Exec("UPDATE events SET event_json=CAST(json_remove(CAST(event_json AS TEXT),'$.payload.effectStatus') AS BLOB) WHERE node_id=? AND seq=?", state.NodeID, state.LastEventSeq); err != nil {
			t.Fatal(err)
		}
	} else if effectStatusJSON != `"unknown"` {
		var effectStatus string
		if err := json.Unmarshal([]byte(effectStatusJSON), &effectStatus); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec("UPDATE events SET event_json=CAST(json_set(CAST(event_json AS TEXT),'$.payload.effectStatus',?) AS BLOB) WHERE node_id=? AND seq=?", effectStatus, state.NodeID, state.LastEventSeq); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec("UPDATE events SET projection_key=? WHERE node_id=? AND seq=?", "tool.completed:"+callID, state.NodeID, state.LastEventSeq); err != nil {
		t.Fatal(err)
	}
	if err := saveState(ctx, tx, state); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestDialogDeleteAllowsResolvedTerminalWork(t *testing.T) {
	opened := openDeleteNode(t)
	defer opened.Close()
	dialogID := createDeleteTestDialog(t, opened)
	seedDeleteAttempt(t, opened, dialogID, "completed", "completed")
	if _, err := opened.db.Exec(`INSERT INTO tool_calls(call_id,attempt_id,action_hash,version,status,safe_input_json) VALUES(?,?,?,?,?,?)`, "42000000-0000-4000-8000-000000000014", "42000000-0000-4000-8000-000000000012", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 2, "succeeded", []byte(`{"kind":"inline","content":"safe","redaction":"none","truncated":false}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.db.Exec(`INSERT INTO approvals(approval_id,attempt_id,call_id,action_hash,version,status,decision,actor_id) VALUES(?,?,?,?,?,?,?,?)`, "42000000-0000-4000-8000-000000000015", "42000000-0000-4000-8000-000000000012", "42000000-0000-4000-8000-000000000014", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 2, "resolved", "allow_once", deleteTestOwnerID); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.db.Exec(`INSERT INTO input_requests(input_request_id,attempt_id,version,status,prompt_json) VALUES(?,?,?,?,?)`, "42000000-0000-4000-8000-000000000016", "42000000-0000-4000-8000-000000000012", 2, "resolved", []byte(`{"kind":"inline","content":"continue?","redaction":"none","truncated":false}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.db.Exec(`INSERT INTO control_actions(command_id,kind,attempt_id,payload,status) VALUES(?,?,?,?,?)`, "42000000-0000-4000-8000-000000000017", "approval.respond", "42000000-0000-4000-8000-000000000012", []byte(`{}`), "acknowledged"); err != nil {
		t.Fatal(err)
	}
	if result := submitDelete(t, opened, dialogID, 1); result.HTTPStatus != 201 {
		t.Fatalf("resolved terminal dialog delete status=%d body=%s", result.HTTPStatus, result.Body)
	}
}

func TestDeletedDialogScopesTerminalReadsAndCommands(t *testing.T) {
	ctx := context.Background()
	opened := openDeleteNode(t)
	defer opened.Close()
	dialogID := createDeleteTestDialog(t, opened)
	seedDeleteAttempt(t, opened, dialogID, "completed", "completed")
	artifactID := "42000000-0000-4000-8000-000000000014"
	if _, err := opened.db.Exec(`INSERT INTO artifacts(artifact_id,dialog_id,attempt_id,name,media_type,size_bytes,sha256,redaction,truncated,disposition,relative_path) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, artifactID, dialogID, "42000000-0000-4000-8000-000000000012", "retained.txt", "text/plain", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "none", false, "attachment", "artifacts/"+artifactID); err != nil {
		t.Fatal(err)
	}
	if result := submitDelete(t, opened, dialogID, 1); result.HTTPStatus != 201 {
		t.Fatalf("delete status=%d body=%s", result.HTTPStatus, result.Body)
	}
	for name, result := range map[string]Result{
		"attempt":           opened.Attempt(ctx, deleteTestTrust(), "42000000-0000-4000-8000-000000000012"),
		"attempts":          opened.Attempts(ctx, deleteTestTrust(), "42000000-0000-4000-8000-000000000011", "", 100),
		"attempt events":    opened.AttemptEvents(ctx, deleteTestTrust(), "42000000-0000-4000-8000-000000000012", 0, 100),
		"artifact metadata": opened.ArtifactMetadata(ctx, deleteTestTrust(), artifactID),
	} {
		if result.HTTPStatus != 404 {
			t.Fatalf("%s status=%d body=%s", name, result.HTTPStatus, result.Body)
		}
	}
	if _, failure, ok := opened.Artifact(ctx, deleteTestTrust(), artifactID); ok || failure.HTTPStatus != 404 {
		t.Fatalf("artifact read ok=%v status=%d body=%s", ok, failure.HTTPStatus, failure.Body)
	}
	retry, err := json.Marshal(map[string]any{
		"protocolVersion": 1, "schemaId": harnessprotocol.SchemaID, "commandId": "42000000-0000-4000-8000-000000000015", "kind": "attempt.retry",
		"target": map[string]any{"nodeId": deleteTestNodeID, "attemptId": "42000000-0000-4000-8000-000000000012"}, "expected": map[string]any{"attemptGeneration": 1}, "payload": map[string]any{"acknowledgeKnownEffects": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result := opened.SubmitCommand(ctx, deleteTestTrust(), retry); result.HTTPStatus != 404 {
		t.Fatalf("deleted attempt accepted command: status=%d body=%s", result.HTTPStatus, result.Body)
	}
	deletedState, err := loadState(ctx, opened.db)
	if err != nil {
		t.Fatal(err)
	}
	reference := harnessadapter.AttemptRef{
		NodeID: deleteTestNodeID, DialogID: dialogID, RequestID: "42000000-0000-4000-8000-000000000011",
		AttemptID: "42000000-0000-4000-8000-000000000012", Generation: 1,
	}
	if err := opened.ObserveAdapterEvent(ctx, reference, harnessadapter.StartedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}}); err == nil {
		t.Fatal("deleted dialog accepted a late adapter event")
	}
	if _, err := opened.StoreArtifact(ctx, ArtifactInput{
		Attempt: reference, Name: "late.txt", MediaType: "text/plain", Redaction: "none", Disposition: "attachment",
	}, []byte("late")); err == nil {
		t.Fatal("deleted dialog accepted a late artifact")
	}
	afterLateWrites, err := loadState(ctx, opened.db)
	if err != nil {
		t.Fatal(err)
	}
	var artifactCount int
	if err := opened.db.QueryRow("SELECT COUNT(*) FROM artifacts WHERE dialog_id=?", dialogID).Scan(&artifactCount); err != nil {
		t.Fatal(err)
	}
	if afterLateWrites.StateVersion != deletedState.StateVersion || afterLateWrites.LastEventSeq != deletedState.LastEventSeq || artifactCount != 1 {
		t.Fatalf("late writes changed deleted dialog: state=%+v want=%+v artifacts=%d", afterLateWrites, deletedState, artifactCount)
	}
}
