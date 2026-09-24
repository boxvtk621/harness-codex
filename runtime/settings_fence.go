package node

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"
)

var ErrSettingsBusy = errors.New("node settings lifecycle is busy")

// BeginSettingsChange closes admission for new attempts and provider auth, then
// waits for the current attempt to finish without cancelling it. The returned
// release function owns startGate until the provider has completed its swap.
func (node *Node) BeginSettingsChange(ctx context.Context) (func(), error) {
	node.startGate.Lock()
	node.mu.Lock()
	if node.settingsBarrier || !node.providerAuthSettled(ctx) {
		node.mu.Unlock()
		node.startGate.Unlock()
		return nil, ErrSettingsBusy
	}
	node.settingsBarrier = true
	node.mu.Unlock()
	node.startGate.Unlock()

	clear := func() {
		node.startGate.Lock()
		node.mu.Lock()
		node.settingsBarrier = false
		node.mu.Unlock()
		node.startGate.Unlock()
		node.afterCommit(context.Background(), postCommitAction{})
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			clear()
			return nil, ctx.Err()
		}
		node.startGate.Lock()
		node.mu.Lock()
		var occupancy string
		var active sql.NullString
		err := node.db.QueryRowContext(ctx, "SELECT occupancy,active_attempt_id FROM node_state WHERE singleton=1").Scan(&occupancy, &active)
		if err == nil && occupancy == "idle" && !active.Valid {
			node.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					node.mu.Lock()
					node.settingsBarrier = false
					node.mu.Unlock()
					node.startGate.Unlock()
					node.afterCommit(context.Background(), postCommitAction{})
				})
			}, nil
		}
		node.mu.Unlock()
		node.startGate.Unlock()
		if err != nil {
			clear()
			return nil, err
		}
		select {
		case <-ctx.Done():
			clear()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (node *Node) settingsApplyBusy() bool {
	node.mu.Lock()
	defer node.mu.Unlock()
	return node.settingsBarrier
}

func (node *Node) SetSettingsReady(ready bool) {
	node.mu.Lock()
	node.settingsNotReady = !ready
	node.mu.Unlock()
	if ready {
		node.afterCommit(context.Background(), postCommitAction{})
	}
}
