package node

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

func TestFailedTailProofRequiresExactDurableFailureAndNoEffects(t *testing.T) {
	for _, change := range []string{"valid", "generic", "known", "output", "tool", "input", "pending-control", "assistant", "successful-later", "late-output", "recovered"} {
		t.Run(change, func(t *testing.T) {
			db, err := sql.Open("sqlite", ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			for _, schema := range []string{
				"CREATE TABLE attempts(node_id TEXT,dialog_id TEXT,request_id TEXT,attempt_id TEXT,generation INTEGER,policy_hash TEXT,state TEXT,effect_status TEXT,output_bytes INTEGER,started_at TEXT)",
				"CREATE TABLE requests(request_id TEXT,input_message_id TEXT)",
				"CREATE TABLE messages(message_id TEXT,sequence INTEGER,text TEXT,attempt_id TEXT,role TEXT)",
				"CREATE TABLE events(attempt_id TEXT,seq INTEGER,event_json BLOB,late INTEGER)",
				"CREATE TABLE late_observations(attempt_id TEXT,generation INTEGER,kind TEXT,observation_json BLOB,projection_key TEXT,output_bytes INTEGER)",
				"CREATE TABLE control_actions(attempt_id TEXT,kind TEXT,status TEXT)",
				"CREATE TABLE tool_calls(attempt_id TEXT)", "CREATE TABLE approvals(attempt_id TEXT)", "CREATE TABLE input_requests(attempt_id TEXT)", "CREATE TABLE artifacts(attempt_id TEXT)",
			} {
				if _, err := db.Exec(schema); err != nil {
					t.Fatal(err)
				}
			}
			id := func(i int) string { return fmt.Sprintf("10000000-0000-4000-8000-%012d", i) }
			for i := 1; i <= 3; i++ {
				if _, err := db.Exec("INSERT INTO attempts VALUES(?,?,?,?,1,?,'failed','none',0,'started')", id(1), id(2), id(10+i), id(20+i), "policy"); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec("INSERT INTO requests VALUES(?,?)", id(10+i), id(30+i)); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec("INSERT INTO messages VALUES(?,?,?,?,'user')", id(30+i), i, "prompt", id(20+i)); err != nil {
					t.Fatal(err)
				}
				code := "codex_model_unsupported"
				if change == "generic" && i == 1 {
					code = "adapter_failed"
				}
				event := harnessprotocol.EventEnvelope{ProtocolVersion: 1, SchemaID: harnessprotocol.SchemaID, NodeID: id(1), Seq: int64(i), Epoch: 1, Type: "attempt.failed", EntityID: id(20 + i), EntityVersion: 3, AttemptID: id(20 + i), DialogID: id(2), ObservedAt: "2026-09-23T00:00:00Z", Completeness: "complete", Payload: mustJSON(harnessprotocol.AttemptFailedPayload{Generation: 1, FailureClass: "task", ErrorCode: code, SafeMessage: "fixed", EffectStatus: "none"})}
				if _, err := db.Exec("INSERT INTO events VALUES(?,?,?,0)", id(20+i), i, []byte(mustJSON(event))); err != nil {
					t.Fatal(err)
				}
			}
			mutations := map[string]string{
				"late-output":      "INSERT INTO late_observations SELECT attempt_id,1,'assistant',X'7B7D','archive:assistant',10 FROM attempts LIMIT 1",
				"known":            "UPDATE attempts SET effect_status='known' WHERE generation=1",
				"output":           "UPDATE attempts SET output_bytes=1",
				"tool":             "INSERT INTO tool_calls SELECT attempt_id FROM attempts LIMIT 1",
				"input":            "INSERT INTO input_requests SELECT attempt_id FROM attempts LIMIT 1",
				"pending-control":  "INSERT INTO control_actions SELECT attempt_id,'message.steer','pending' FROM attempts LIMIT 1",
				"assistant":        "INSERT INTO messages SELECT 'assistant',4,'output',attempt_id,'assistant' FROM attempts LIMIT 1",
				"successful-later": "UPDATE attempts SET state='completed' WHERE attempt_id='" + id(23) + "'",
			}
			if mutation := mutations[change]; mutation != "" {
				if _, err := db.Exec(mutation); err != nil {
					t.Fatal(err)
				}
			}
			if change == "recovered" {
				terminal := harnessadapter.TerminalEvent{EventBase: harnessadapter.EventBase{Attempt: harnessadapter.AttemptRef{NodeID: id(1), DialogID: id(2), RequestID: id(11), AttemptID: id(21), Generation: 1}}, Outcome: harnessadapter.ReconcileFailed, EffectStatus: "unknown", Failure: &harnessadapter.Failure{Class: harnessadapter.FailureTask, Code: "codex_turn_failed", SafeMessage: "codex turn failed"}}
				if _, err := db.Exec("INSERT INTO late_observations VALUES(?,1,'terminal_while_steer_unresolved',?,'archive:terminal',17)", id(21), []byte(mustJSON(terminal))); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			proof, err := failedTailProof(context.Background(), tx, id(2), id(31))
			_ = tx.Rollback()
			if err != nil {
				t.Fatal(err)
			}
			if (proof != nil) != (change == "valid" || change == "recovered") {
				t.Fatalf("%s proof=%+v", change, proof)
			}
			if change == "valid" {
				// A completed earlier retry must not invalidate the next original suffix.
				if _, err := db.Exec("UPDATE attempts SET state='completed' WHERE attempt_id=?", id(21)); err != nil {
					t.Fatal(err)
				}
				tx, err := db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				suffix, err := failedTailProof(context.Background(), tx, id(2), id(32))
				_ = tx.Rollback()
				if err != nil || suffix == nil || len(suffix.Attempts) != 2 {
					t.Fatalf("remaining suffix=%+v error=%v", suffix, err)
				}
			}
		})
	}
}
