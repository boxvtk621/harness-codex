package node

import (
	"context"
	"database/sql"
	"errors"
	"slices"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
)

// recoverPristinePolicy upgrades only the exact unused state written by older
// binaries. Policy failures remain represented by the durable blocked state so
// startup stays observable and Router activation remains closed.
func (node *Node) recoverPristinePolicy(ctx context.Context) error {
	if node.config.Policies == nil {
		return nil
	}
	policy, err := node.config.Policies.Current(ctx, "")
	if err != nil {
		return nil
	}
	if _, err := harnessadapter.PreparePolicySnapshot(policy); err != nil {
		return nil
	}

	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return err
	}
	if !isPristinePolicySentinel(state) {
		return tx.Commit()
	}
	var durableRows int64
	if err := tx.QueryRowContext(ctx, `SELECT SUM(row_count) FROM (
		SELECT COUNT(*) AS row_count FROM dialogs UNION ALL
		SELECT COUNT(*) FROM messages UNION ALL
		SELECT COUNT(*) FROM requests UNION ALL
		SELECT COUNT(*) FROM attempts UNION ALL
		SELECT COUNT(*) FROM commands UNION ALL
		SELECT COUNT(*) FROM control_actions UNION ALL
		SELECT COUNT(*) FROM events UNION ALL
		SELECT COUNT(*) FROM tool_calls UNION ALL
		SELECT COUNT(*) FROM approvals UNION ALL
		SELECT COUNT(*) FROM input_requests UNION ALL
		SELECT COUNT(*) FROM artifacts UNION ALL
		SELECT COUNT(*) FROM late_observations UNION ALL
		SELECT COUNT(*) FROM policy_snapshots UNION ALL
		SELECT COUNT(*) FROM administrative_holds UNION ALL
		SELECT COUNT(*) FROM administrative_hold_outcomes UNION ALL
		SELECT COUNT(*) FROM command_rejections
	)`).Scan(&durableRows); err != nil {
		return err
	}
	if durableRows != 0 {
		return tx.Commit()
	}
	state.EngineReadiness = "ready"
	state.BlockedReasons = []string{}
	state.StateVersion++
	if err := node.appendNodeEvent(ctx, tx, &state); err != nil {
		return err
	}
	if err := saveState(ctx, tx, state); err != nil {
		return err
	}
	return tx.Commit()
}

func isPristinePolicySentinel(state durableState) bool {
	return state.StateVersion == 0 && state.LastEventSeq == 0 && state.QueueVersion == 0 && !state.QueuePaused &&
		state.TransportAvailability == "online" && state.EngineReadiness == "blocked" && state.Occupancy == "idle" &&
		!state.ActiveAttemptID.Valid && state.PendingCount == 0 && slices.Equal(state.BlockedReasons, []string{"policy_unavailable"}) &&
		state.NextQueueSequence == 1 && state.NextMessageSequence == 1
}

func (node *Node) recoverStartup(ctx context.Context) error {
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE control_actions SET status='unknown' WHERE status IN('pending','inflight')"); err != nil {
		return err
	}
	if !state.ActiveAttemptID.Valid {
		return tx.Commit()
	}
	var reference harnessadapter.AttemptRef
	var attemptState string
	reference.NodeID = state.NodeID
	err = tx.QueryRowContext(ctx, `SELECT dialog_id,request_id,attempt_id,generation,state FROM attempts WHERE attempt_id=?`, state.ActiveAttemptID.String).Scan(
		&reference.DialogID, &reference.RequestID, &reference.AttemptID, &reference.Generation, &attemptState)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("node active attempt reference is missing")
	}
	if err != nil {
		return err
	}
	if attemptState == "unknown" {
		return tx.Commit()
	}
	if attemptState != "dispatching" && attemptState != "running" && attemptState != "waiting_input" && attemptState != "stopping" {
		return errors.New("node active attempt is not active")
	}
	if err := node.setAttemptUnknown(ctx, tx, &state, reference, "dispatch_uncertain", "unknown"); err != nil {
		return err
	}
	if err := saveState(ctx, tx, state); err != nil {
		return err
	}
	return tx.Commit()
}
