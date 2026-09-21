package node

import (
	"context"
	"errors"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
)

type attemptStreamLease struct {
	reference harnessadapter.AttemptRef
	cancel    context.CancelFunc
}

// registerAttemptStream binds the one live adapter stream to the exact durable
// slot. The durable check prevents a terminal commit racing ahead of stream
// registration from leaving an unowned stream behind.
func (node *Node) registerAttemptStream(parent context.Context, reference harnessadapter.AttemptRef) (context.Context, *attemptStreamLease, bool, error) {
	node.mu.Lock()
	defer node.mu.Unlock()
	if err := parent.Err(); err != nil {
		return nil, nil, false, err
	}
	state, err := loadState(parent, node.db)
	if err != nil {
		return nil, nil, false, err
	}
	if !state.ActiveAttemptID.Valid || state.ActiveAttemptID.String != reference.AttemptID {
		return nil, nil, false, nil
	}
	actual := harnessadapter.AttemptRef{NodeID: state.NodeID}
	var attemptState string
	if err := node.db.QueryRowContext(parent, `SELECT dialog_id,request_id,attempt_id,generation,state FROM attempts WHERE attempt_id=?`, reference.AttemptID).Scan(&actual.DialogID, &actual.RequestID, &actual.AttemptID, &actual.Generation, &attemptState); err != nil {
		return nil, nil, false, err
	}
	if actual != reference {
		return nil, nil, false, errors.New("adapter stream durable scope mismatch")
	}
	switch attemptState {
	case "running", "waiting_input", "stopping", "unknown":
	default:
		return nil, nil, false, nil
	}

	streamContext, cancel := context.WithCancel(parent)
	lease := &attemptStreamLease{reference: reference, cancel: cancel}
	node.streamMu.Lock()
	defer node.streamMu.Unlock()
	if node.streamLease != nil {
		cancel()
		return nil, nil, false, errors.New("adapter stream lease is already active")
	}
	node.streamLease = lease
	return streamContext, lease, true, nil
}

func (node *Node) finishAttemptStream(lease *attemptStreamLease) {
	lease.cancel()
	node.streamMu.Lock()
	if node.streamLease == lease {
		node.streamLease = nil
	}
	node.streamMu.Unlock()
}

func (node *Node) cancelAttemptStream(reference harnessadapter.AttemptRef) {
	node.streamMu.Lock()
	if node.streamLease != nil && node.streamLease.reference == reference {
		node.streamLease.cancel()
	}
	node.streamMu.Unlock()
}
