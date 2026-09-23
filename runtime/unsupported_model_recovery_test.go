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
	_ "modernc.org/sqlite"
)

type offlineRecoveryFixtureAdapter struct {
	*fixture.Adapter
	reject bool
}

func (*offlineRecoveryFixtureAdapter) RecoveryOnlyAdapter() {}
func (adapter *offlineRecoveryFixtureAdapter) ConfirmUnsupportedModelRejection(_ context.Context, _ harnessadapter.AttemptRef, _, _ string, _ int64) error {
	if adapter.reject {
		return errors.New("native rejection unconfirmed")
	}
	return nil
}

func TestUnsupportedModelRecoveryIsOfflineFencedAndIdempotent(t *testing.T) {
	ctx := context.Background()
	config := testConfig(t.TempDir())
	config.Policies = fixture.NewPolicySource()
	opened, ref := runningAttemptWithConfig(t, config)
	if err := opened.ObserveAdapterEvent(ctx, ref, harnessadapter.TerminalEvent{
		EventBase: harnessadapter.EventBase{Attempt: ref}, Outcome: harnessadapter.ReconcileFailed,
		Failure:      &harnessadapter.Failure{Class: harnessadapter.FailureTask, Code: "codex_turn_failed", SafeMessage: "codex turn failed"},
		EffectStatus: "unknown",
	}); err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", "file:"+filepath.Join(config.DataDir, "harness.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	proof := node.CodexUnsupportedModelProof{Attempt: ref, ExpectedProcessGeneration: 2,
		RolloutRelativePath: "sessions/2026/09/23/example.jsonl", RolloutSHA256: strings.Repeat("a", 64)}
	if err := db.QueryRow(`SELECT epoch,state_version,last_event_seq FROM node_state WHERE singleton=1`).Scan(
		&proof.ExpectedEpoch, &proof.ExpectedStateVersion, &proof.ExpectedLastEventSeq); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT version FROM attempts WHERE attempt_id=?`, ref.AttemptID).Scan(&proof.ExpectedAttemptVersion); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT version FROM requests WHERE request_id=?`, ref.RequestID).Scan(&proof.ExpectedRequestVersion); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT observation_id,projection_hash FROM late_observations WHERE attempt_id=?`, ref.AttemptID).Scan(
		&proof.ExpectedLateObservationID, &proof.ExpectedLateHash); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT seq FROM events WHERE attempt_id=? AND json_extract(CAST(event_json AS TEXT),'$.type')='attempt.unknown'`, ref.AttemptID).Scan(&proof.ExpectedUnknownSeq); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	adapter := &offlineRecoveryFixtureAdapter{Adapter: fixture.NewAdapter()}
	config.Adapter = adapter
	recovery, err := node.OpenForRecovery(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.Close()
	if _, err := node.OpenForRecovery(ctx, config); err == nil {
		t.Fatal("recovery failed to lock volume exclusively")
	}
	if err := recovery.RecoverCodexUnsupportedModel(ctx, proof, true); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	adapter.reject = true
	if err := recovery.RecoverCodexUnsupportedModel(ctx, proof, false); err == nil {
		t.Fatal("missing native confirmation accepted")
	}
	adapter.reject = false
	wrong := proof
	wrong.ExpectedLateHash = strings.Repeat("b", 64)
	if err := recovery.RecoverCodexUnsupportedModel(ctx, wrong, false); err == nil {
		t.Fatal("wrong archived hash accepted")
	}
	wrong = proof
	wrong.ExpectedStateVersion++
	if err := recovery.RecoverCodexUnsupportedModel(ctx, wrong, false); err == nil {
		t.Fatal("wrong node version accepted")
	}
	mutator, err := sql.Open("sqlite", "file:"+filepath.Join(config.DataDir, "harness.db")+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	defer mutator.Close()
	const pendingID = "99000000-0000-4000-8000-000000000001"
	if _, err := mutator.Exec(`INSERT INTO control_actions(command_id,kind,attempt_id,payload,status) VALUES(?,?,?,?,?)`,
		pendingID, "attempt.stop", ref.AttemptID, []byte(`{}`), "pending"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := recovery.RecoverCodexUnsupportedModel(ctx, proof, false); err == nil {
		t.Fatal("pending control accepted")
	}
	var pendingStatus string
	if err := mutator.QueryRow(`SELECT status FROM control_actions WHERE command_id=?`, pendingID).Scan(&pendingStatus); err != nil || pendingStatus != "pending" {
		t.Fatalf("recovery executor changed pending control: %q %v", pendingStatus, err)
	}
	if len(adapter.Calls) != 0 {
		t.Fatalf("recovery started provider calls: %+v", adapter.Calls)
	}
	if _, err := mutator.Exec(`DELETE FROM control_actions WHERE command_id=?`, pendingID); err != nil {
		t.Fatal(err)
	}
	const toolID = "99000000-0000-4000-8000-000000000002"
	if _, err := mutator.Exec(`INSERT INTO tool_calls(call_id,attempt_id,action_hash,version,status,safe_input_json) VALUES(?,?,?,?,?,?)`,
		toolID, ref.AttemptID, strings.Repeat("a", 64), 1, "completed", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := recovery.RecoverCodexUnsupportedModel(ctx, proof, false); err == nil {
		t.Fatal("durable tool side effect accepted")
	}
	if _, err := mutator.Exec(`DELETE FROM tool_calls WHERE call_id=?`, toolID); err != nil {
		t.Fatal(err)
	}
	before := currentSnapshot(t, ctx, recovery)
	if before.ActiveAttempt == nil || before.ActiveAttempt.State != "unknown" || before.LastEventSeq != proof.ExpectedLastEventSeq {
		t.Fatalf("failed checks changed durable state: %+v", before)
	}
	if err := recovery.RecoverCodexUnsupportedModel(ctx, proof, false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := recovery.RecoverCodexUnsupportedModel(ctx, proof, false); err != nil {
		t.Fatalf("idempotent repeat: %v", err)
	}
	after := currentSnapshot(t, ctx, recovery)
	if after.ActiveAttempt != nil || after.LastEventSeq != proof.ExpectedLastEventSeq+2 || after.Node.Occupancy != "idle" {
		t.Fatalf("unexpected recovered state: %+v", after)
	}
	read := recovery.Attempt(ctx, nodeTrust(), ref.AttemptID)
	var attempt harnessprotocol.AttemptRead
	if read.HTTPStatus != 200 || json.Unmarshal(read.Body, &attempt) != nil || attempt.Attempt.State != "failed" || attempt.Attempt.EffectStatus != "none" {
		t.Fatalf("attempt not failed/no-effect: %s", read.Body)
	}
	events := allAttemptEvents(t, recovery, ref.AttemptID)
	failed := 0
	for _, event := range events {
		if event.Type == "attempt.failed" {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("terminal projection count=%d", failed)
	}
}
