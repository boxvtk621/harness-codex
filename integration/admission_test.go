// Package integration_test checks the real B1 authority through its public seam.
// Every input is synthetic; the fixture adapter cannot invoke a provider.
package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	hp "github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

const integrationNode = "20000000-0000-4000-8000-000000000001"
const integrationOwner = "1-1"
const createID = "10000000-0000-4000-8000-000000000011"

var crashHelper = flag.Bool("hl252-crash-helper", false, "run the isolated HL252 crash helper")

type enoughSpace struct{}

func (enoughSpace) Measure(string) (node.SpaceInfo, error) {
	return node.SpaceInfo{FreeBytes: 16 << 30, TotalBytes: 64 << 30}, nil
}

func config(path string) node.Config {
	return node.Config{DataDir: path, NodeID: integrationNode, OwnerID: integrationOwner,
		RegistryVersion: 1, Adapter: fixture.NewAdapter(), Space: enoughSpace{}, ManualDispatchForTesting: true}
}

func trusted() node.TrustContext {
	return node.TrustContext{PeerVerified: true, ActorID: integrationOwner, TransportNodeID: integrationNode}
}

func createCommand() []byte {
	return []byte(`{"protocolVersion":1,"schemaId":"harness-wire-v2","commandId":"` + createID + `","kind":"dialog.create","target":{"nodeId":"` + integrationNode + `"},"expected":{"registryVersion":1},"payload":{"title":"Synthetic recovery"}}`)
}

func messageCommand(t *testing.T, id, dialog, text string, version int64) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"protocolVersion": 1, "schemaId": hp.SchemaID, "commandId": id, "kind": "message.enqueue",
		"target":   map[string]string{"nodeId": integrationNode, "dialogId": dialog},
		"expected": map[string]int64{"dialogVersion": version}, "payload": map[string]string{"text": text},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func receipt(t *testing.T, result node.Result, status int, command []byte) hp.Receipt {
	t.Helper()
	if result.HTTPStatus != status {
		t.Fatalf("status=%d, want=%d, body=%s", result.HTTPStatus, status, result.Body)
	}
	if err := hp.Validate("receipt", result.Body); err != nil {
		t.Fatalf("invalid C1 receipt: %v", err)
	}
	var value hp.Receipt
	if err := json.Unmarshal(result.Body, &value); err != nil {
		t.Fatal(err)
	}
	var envelope hp.CommandEnvelope
	var target, refs map[string]string
	if err := json.Unmarshal(command, &envelope); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(envelope.Target, &target); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(value.References, &refs); err != nil {
		t.Fatal(err)
	}
	if value.CommandID != envelope.CommandID || value.CommandKind != envelope.Kind || value.NodeID != target["nodeId"] {
		t.Fatal("receipt is not bound to submitted command")
	}
	for key, wanted := range target {
		if got, present := refs[key]; present && got != wanted {
			t.Fatalf("receipt reference %s=%s, want=%s", key, got, wanted)
		}
	}
	return value
}

func fault(t *testing.T, result node.Result, status int, code string) {
	t.Helper()
	if result.HTTPStatus != status {
		t.Fatalf("status=%d, want=%d", result.HTTPStatus, status)
	}
	if err := hp.Validate("error", result.Body); err != nil {
		t.Fatalf("invalid C1 error: %v; body=%s", err, result.Body)
	}
	var value hp.Error
	if err := json.Unmarshal(result.Body, &value); err != nil || value.Code != code {
		t.Fatalf("error=%s, want=%s, decode=%v", value.Code, code, err)
	}
}

func TestAdmissionReplaysOriginalReceiptAcrossVersionAndRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	dir := t.TempDir()
	n, err := node.Open(ctx, config(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if n != nil {
			_ = n.Close()
		}
	})
	created := receipt(t, n.SubmitCommand(ctx, trusted(), createCommand()), 202, createCommand())
	var refs hp.DialogCreateReferences
	if err := json.Unmarshal(created.References, &refs); err != nil {
		t.Fatal(err)
	}
	text := "Проверка <>&\n😀e\u0301\u2028\u2029"
	first := messageCommand(t, "10000000-0000-4000-8000-000000000012", refs.DialogID, text, 1)
	accepted := n.SubmitCommand(ctx, trusted(), first)
	receipt(t, accepted, 202, first)
	// Independent expected JCS bytes for this fixed text; do not call the
	// implementation's CanonicalCommand to calculate its own expected hash.
	canonical := `{"commandId":"10000000-0000-4000-8000-000000000012","expected":{"dialogVersion":1},"kind":"message.enqueue","payload":{"text":"` + "Проверка <>&\\n😀e\u0301\u2028\u2029" + `"},"protocolVersion":1,"schemaId":"harness-wire-v2","target":{"dialogId":"` + refs.DialogID + `","nodeId":"` + integrationNode + `"}}`
	digest := sha256.Sum256([]byte(canonical))
	projection := readAdmissionProjection(t, ctx, dir)
	found := false
	for _, command := range projection.Commands {
		if command.ID == "10000000-0000-4000-8000-000000000012" {
			found = true
			if command.Hash != hex.EncodeToString(digest[:]) {
				t.Fatal("persisted Unicode hash differs from independent JCS bytes")
			}
		}
	}
	if !found {
		t.Fatal("admitted command absent from durable projection")
	}
	second := messageCommand(t, "10000000-0000-4000-8000-000000000013", refs.DialogID, "later queued message", 2)
	receipt(t, n.SubmitCommand(ctx, trusted(), second), 202, second)
	duplicate := n.SubmitCommand(ctx, trusted(), first)
	receipt(t, duplicate, 200, first)
	if !bytes.Equal(accepted.Body, duplicate.Body) {
		t.Fatal("replay rewrote the original receipt after current CAS changed")
	}
	// Different lexical order must retain exactly the same semantic command.
	var parts map[string]json.RawMessage
	if err := json.Unmarshal(first, &parts); err != nil {
		t.Fatal(err)
	}
	reordered := []byte(`{"target":{"nodeId":"` + integrationNode + `","dialogId":"` + refs.DialogID + `"},"schemaId":` + string(parts["schemaId"]) + `,"protocolVersion":1,"payload":` + string(parts["payload"]) + `,"kind":"message.enqueue","expected":` + string(parts["expected"]) + `,"commandId":` + string(parts["commandId"]) + `}`)
	reorderedResult := n.SubmitCommand(ctx, trusted(), reordered)
	receipt(t, reorderedResult, 200, reordered)
	if !bytes.Equal(accepted.Body, reorderedResult.Body) {
		t.Fatal("key order changed command identity")
	}
	changedExpected := messageCommand(t, "10000000-0000-4000-8000-000000000012", refs.DialogID, text, 3)
	fault(t, n.SubmitCommand(ctx, trusted(), changedExpected), 409, "id_conflict")
	changed := messageCommand(t, "10000000-0000-4000-8000-000000000012", refs.DialogID, "different intent", 1)
	fault(t, n.SubmitCommand(ctx, trusted(), changed), 409, "id_conflict")
	foreign := trusted()
	foreign.ActorID = "1-2"
	fault(t, n.SubmitCommand(ctx, foreign, first), 403, "forbidden")
	fault(t, n.SubmitCommand(ctx, trusted(), []byte(`{"broken":true}`)), 400, "invalid")
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	n, err = node.Open(ctx, config(dir))
	if err != nil {
		t.Fatal(err)
	}
	afterRestart := n.SubmitCommand(ctx, trusted(), first)
	receipt(t, afterRestart, 200, first)
	if !bytes.Equal(accepted.Body, afterRestart.Body) {
		t.Fatal("reopen lost or rewrote durable receipt")
	}
}

// Invoked only as this test binary's child. SIGKILL bypasses SQLite/Go cleanup;
// the parent checks the recovered DB instead of treating a mock error as crash.
func TestAdmissionCrashChild(t *testing.T) {
	if !*crashHelper {
		t.Skip("subprocess helper")
	}
	phase := os.Getenv("HL252_CRASH_PHASE")
	if phase == "" {
		t.Skip("subprocess helper")
	}
	if phase != string(node.FaultBeforeCommit) && phase != string(node.FaultAfterCommit) {
		t.Fatal("invalid crash phase")
	}
	n, err := node.Open(context.Background(), config(os.Getenv("HL252_CRASH_DIR")))
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	n.SetFaultInjector(func(point node.FaultPoint) error {
		if string(point) == phase {
			if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	})
	n.SubmitCommand(context.Background(), trusted(), createCommand())
	t.Fatal("crash hook was not reached")
}

func TestAdmissionRealCrashBeforeAndAfterCommit(t *testing.T) {
	for _, phase := range []node.FaultPoint{node.FaultBeforeCommit, node.FaultAfterCommit} {
		t.Run(string(phase), func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			initialNode, err := node.Open(ctx, config(dir))
			if err != nil {
				t.Fatal(err)
			}
			if err := initialNode.Close(); err != nil {
				t.Fatal(err)
			}
			initial := readAdmissionProjection(t, ctx, dir)
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAdmissionCrashChild$", "-test.timeout=6s", "-hl252-crash-helper=true")
			cmd.Env = make([]string, 0, len(os.Environ())+2)
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "HL252_CRASH_PHASE=") && !strings.HasPrefix(entry, "HL252_CRASH_DIR=") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "HL252_CRASH_PHASE="+string(phase), "HL252_CRASH_DIR="+dir)
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exit) {
				t.Fatalf("helper did not exit at crash boundary: %v %s", err, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("helper was not SIGKILLed at hook: %v %s", err, output)
			}
			n, err := node.Open(ctx, config(dir))
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close()
			recovered := readAdmissionProjection(t, ctx, dir)
			want := 202
			if phase == node.FaultBeforeCommit {
				if !reflect.DeepEqual(initial, recovered) {
					t.Fatalf("pre-commit crash leaked partial state: before=%+v after=%+v", initial, recovered)
				}
			} else {
				want = 200
				assertOneCreatedDialog(t, initial, recovered)
			}
			result := n.SubmitCommand(ctx, trusted(), createCommand())
			receipt(t, result, want, createCommand())
			committed := readAdmissionProjection(t, ctx, dir)
			assertOneCreatedDialog(t, initial, committed)
			if want == 200 && !reflect.DeepEqual(recovered, committed) {
				t.Fatal("post-crash replay changed domain/command/event state")
			}
			replayed := n.SubmitCommand(ctx, trusted(), createCommand())
			receipt(t, replayed, 200, createCommand())
			if !reflect.DeepEqual(committed, readAdmissionProjection(t, ctx, dir)) {
				t.Fatal("duplicate changed domain/command/event state")
			}
			if !bytes.Equal(result.Body, replayed.Body) {
				t.Fatal("crash recovery replay returned a different receipt")
			}
		})
	}
}

// Read the actual SQLite projection after Node.Open has performed recovery, but
// before resubmitting any command. Looking only at receipts could miss a split
// transaction where a command survived and its dialog/event did not.
type admissionProjection struct {
	StateVersion, LastEventSeq, PendingCount int64
	NextQueueSequence, NextMessageSequence   int64
	Epoch                                    int64
	Node                                     hp.NodeState
	ActiveAttemptID                          sql.NullString
	Dialogs                                  []storedDialog
	Commands                                 []storedCommand
	Events                                   [][]byte
	MessageCount, RequestCount               int
}

type storedDialog struct {
	ID, NodeID, OwnerID, Title string
	Version                    int64
}

type storedCommand struct {
	ID, Kind, NodeID, ActorID, Hash string
	Receipt                         []byte
	EventSeq                        int64
}

func readAdmissionProjection(t *testing.T, ctx context.Context, dir string) admissionProjection {
	t.Helper()
	uri := &url.URL{Scheme: "file", Path: filepath.Join(dir, "harness.db"), RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var out admissionProjection
	if err := db.QueryRowContext(ctx, "SELECT state_version,last_event_seq,pending_count,active_attempt_id FROM node_state WHERE singleton=1").Scan(&out.StateVersion, &out.LastEventSeq, &out.PendingCount, &out.ActiveAttemptID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT next_queue_sequence,next_message_sequence FROM node_state WHERE singleton=1").Scan(&out.NextQueueSequence, &out.NextMessageSequence); err != nil {
		t.Fatal(err)
	}
	var blocked string
	if err := db.QueryRowContext(ctx, "SELECT epoch,transport_availability,engine_readiness,occupancy,queue_paused,queue_version,blocked_reasons FROM node_state WHERE singleton=1").Scan(&out.Epoch, &out.Node.TransportAvailability, &out.Node.EngineReadiness, &out.Node.Occupancy, &out.Node.QueuePaused, &out.Node.QueueVersion, &blocked); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(blocked), &out.Node.BlockedReasons); err != nil {
		t.Fatal(err)
	}
	out.Node.PendingCount = out.PendingCount
	if out.ActiveAttemptID.Valid {
		value := out.ActiveAttemptID.String
		out.Node.ActiveAttemptID = &value
	}
	if err := db.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM messages),(SELECT count(*) FROM requests)").Scan(&out.MessageCount, &out.RequestCount); err != nil {
		t.Fatal(err)
	}
	rows, err := db.QueryContext(ctx, "SELECT dialog_id,node_id,owner_id,version,coalesce(title,'') FROM dialogs ORDER BY dialog_id")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var row storedDialog
		if err := rows.Scan(&row.ID, &row.NodeID, &row.OwnerID, &row.Version, &row.Title); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		out.Dialogs = append(out.Dialogs, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	rows, err = db.QueryContext(ctx, "SELECT command_id,kind,node_id,actor_id,canonical_payload_hash,receipt_json,event_seq FROM commands ORDER BY command_id")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var row storedCommand
		if err := rows.Scan(&row.ID, &row.Kind, &row.NodeID, &row.ActorID, &row.Hash, &row.Receipt, &row.EventSeq); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		out.Commands = append(out.Commands, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	rows, err = db.QueryContext(ctx, "SELECT event_json FROM events ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		out.Events = append(out.Events, raw)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	return out
}

func assertOneCreatedDialog(t *testing.T, initial, current admissionProjection) {
	t.Helper()
	if len(initial.Commands) != 0 || len(initial.Dialogs) != 0 || len(current.Commands) != 1 || len(current.Dialogs) != 1 || current.MessageCount != 0 || current.RequestCount != 0 || current.PendingCount != 0 || current.ActiveAttemptID.Valid {
		t.Fatalf("create is not exactly one atomic dialog/command: %+v", current)
	}
	command, dialog := current.Commands[0], current.Dialogs[0]
	if command.ID != createID || command.Kind != "dialog.create" || command.ActorID != integrationOwner || command.NodeID != integrationNode || dialog.NodeID != integrationNode || dialog.OwnerID != integrationOwner || dialog.Version != 1 || dialog.Title != "Synthetic recovery" {
		t.Fatal("durable command/dialog identity or content mismatch")
	}
	value := receipt(t, node.Result{HTTPStatus: 200, Body: command.Receipt}, 200, createCommand())
	var refs hp.DialogCreateReferences
	if err := json.Unmarshal(value.References, &refs); err != nil || refs.DialogID != dialog.ID {
		t.Fatal("receipt refers to a missing/different dialog", err)
	}
	if current.StateVersion != initial.StateVersion+1 || current.LastEventSeq != initial.LastEventSeq+1 || len(current.Events) != len(initial.Events)+1 || command.EventSeq != value.EventSeq || value.EventSeq != current.LastEventSeq || int64(len(current.Events)) != current.LastEventSeq {
		t.Fatal("receipt, event log and state watermark are not one commit")
	}
	for index, raw := range current.Events {
		if err := hp.Validate("event", raw); err != nil {
			t.Fatal(err)
		}
		var event hp.EventEnvelope
		if err := json.Unmarshal(raw, &event); err != nil || event.Seq != int64(index+1) || event.NodeID != integrationNode {
			t.Fatal("persisted event scope/order mismatch", err)
		}
		if event.Type != "node.state_changed" || event.EntityID != integrationNode || event.EntityVersion != current.StateVersion || event.Epoch != current.Epoch || event.AttemptID != "" || event.DialogID != "" {
			t.Fatal("create emitted an unrelated or inconsistent domain event")
		}
		var payload hp.NodeState
		if err := json.Unmarshal(event.Payload, &payload); err != nil || !reflect.DeepEqual(payload, current.Node) {
			t.Fatal("event payload does not match durable state", err)
		}
	}
}
