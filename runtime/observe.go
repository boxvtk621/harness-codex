package node

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/transcriptview"
)

func (node *Node) observeAdapterStream(ctx context.Context, reference harnessadapter.AttemptRef) {
	streamContext, lease, current, err := node.registerAttemptStream(ctx, reference)
	if err != nil {
		if ctx.Err() == nil {
			node.markAttemptUnknown(context.Background(), reference, "provider_state", "unknown")
		}
		return
	}
	if !current {
		return
	}
	defer node.finishAttemptStream(lease)
	stream, err := node.config.Adapter.Events(streamContext, harnessadapter.EventsInput{Attempt: reference})
	if err != nil || stream == nil {
		if streamContext.Err() == nil {
			node.markAttemptUnknown(context.Background(), reference, "provider_state", "unknown")
		}
		return
	}
	var closeOnce sync.Once
	closeStream := func() { closeOnce.Do(func() { _ = stream.Close() }) }
	stopCloser := make(chan struct{})
	go func() {
		select {
		case <-streamContext.Done():
			closeStream()
		case <-stopCloser:
		}
	}()
	defer close(stopCloser)
	defer closeStream()
	for {
		event, err := stream.Next(streamContext)
		if err != nil {
			if streamContext.Err() == nil {
				reason := "provider_state"
				if !errors.Is(err, io.EOF) {
					reason = "provider_state"
				}
				node.markAttemptUnknown(context.Background(), reference, reason, "unknown")
			}
			return
		}
		if event == nil {
			node.markAttemptUnknown(context.Background(), reference, "adapter_protocol", "unknown")
			return
		}
		if err := node.ObserveAdapterEvent(streamContext, reference, event); err != nil {
			if streamContext.Err() == nil {
				node.markAttemptUnknown(context.Background(), reference, "adapter_protocol", "unknown")
			}
			return
		}
		switch event.(type) {
		case harnessadapter.TerminalEvent, harnessadapter.UnknownEvent:
			return
		}
	}
}

// ObserveAdapterEvent projects one provider-neutral event atomically. expected
// identifies the stream that delivered it; mismatched provider references fail
// closed instead of changing a different attempt.
func (node *Node) ObserveAdapterEvent(ctx context.Context, expected harnessadapter.AttemptRef, event harnessadapter.Event) (resultErr error) {
	if event == nil || event.AttemptReference() != expected {
		return errors.New("adapter event attempt scope mismatch")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	publication := newSafeTextPublication(node)
	defer func() {
		resultErr = errors.Join(resultErr, publication.cleanupKnownRollback())
	}()
	state, err := loadState(ctx, tx)
	if err != nil {
		return err
	}
	var actual harnessadapter.AttemptRef
	var attemptVersion int64
	var attemptState string
	actual.NodeID = state.NodeID
	err = tx.QueryRowContext(ctx, `SELECT a.dialog_id,a.request_id,a.attempt_id,a.generation,a.version,a.state FROM attempts a WHERE a.attempt_id=? AND NOT EXISTS (
		SELECT 1 FROM events deleted WHERE deleted.dialog_id=a.dialog_id AND deleted.projection_key='dialog.deleted')`, expected.AttemptID).Scan(
		&actual.DialogID, &actual.RequestID, &actual.AttemptID, &actual.Generation, &attemptVersion, &attemptState)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("adapter event durable scope mismatch")
	}
	if (attemptState == "stopping" || attemptState == "unknown") && isInteractiveWaitEvent(event) {
		if err := node.archiveSuppressedAdapterEvent(ctx, tx, &state, event, attemptVersion); err != nil {
			return err
		}
		if err := node.checkFault(FaultBeforeCommit); err != nil {
			return err
		}
		publication.retainForCommit()
		return tx.Commit()
	}
	if !state.ActiveAttemptID.Valid || state.ActiveAttemptID.String != expected.AttemptID ||
		(attemptState != "dispatching" && attemptState != "running" && attemptState != "waiting_input" && attemptState != "stopping" && attemptState != "unknown") {
		if err := node.archiveLateAdapterEvent(ctx, tx, publication, &state, event, attemptVersion); err != nil {
			return err
		}
		if err := saveState(ctx, tx, state); err != nil {
			return err
		}
		if err := node.checkFault(FaultBeforeCommit); err != nil {
			return err
		}
		publication.retainForCommit()
		return tx.Commit()
	}
	terminal, wakeActions, err := node.projectAdapterEvent(ctx, tx, publication, &state, actual, attemptVersion, attemptState, event)
	if err != nil {
		return err
	}
	if err := saveState(ctx, tx, state); err != nil {
		return err
	}
	if err := node.checkFault(FaultBeforeCommit); err != nil {
		return err
	}
	// Once Commit begins its outcome can be unknown. Retain fsync-published
	// files and let startup reconciliation compare them with committed rows.
	publication.retainForCommit()
	if err := tx.Commit(); err != nil {
		return err
	}
	released := !state.ActiveAttemptID.Valid || state.ActiveAttemptID.String != expected.AttemptID
	if released {
		node.cancelAttemptStream(actual)
	}
	if terminal || wakeActions {
		node.afterCommit(ctx, postCommitAction{})
	}
	return nil
}

func adapterEventSafeText(event harnessadapter.Event) (transcriptview.Source, harnessprotocol.SafeContent, *string, bool, bool) {
	source := transcriptview.Source{Index: 0, Stream: "none"}
	var content harnessprotocol.SafeContent
	var full *string
	incomplete := false
	switch value := event.(type) {
	case harnessadapter.AssistantMessageEvent:
		source.Kind, source.ID = "assistant_message", value.MessageID
		content, full, incomplete = value.Content, value.FullText, value.FullTextIncomplete
	case harnessadapter.ToolStartedEvent:
		source.Kind, source.ID = "tool_input", value.CallID
		content, full, incomplete = value.Input, value.FullText, value.FullTextIncomplete
	case harnessadapter.ToolOutputEvent:
		source.Kind, source.ID, source.Index, source.Stream = "tool_output", value.CallID, value.ChunkIndex, value.Stream
		content, full, incomplete = value.Output, value.FullText, value.FullTextIncomplete
	case harnessadapter.ToolCompletedEvent:
		source.Kind, source.ID = "tool_result", value.CallID
		content, full, incomplete = value.Result, value.FullText, value.FullTextIncomplete
	default:
		return transcriptview.Source{}, harnessprotocol.SafeContent{}, nil, false, false
	}
	return source, content, full, incomplete, true
}

func (node *Node) captureAdapterEventSafeText(ctx context.Context, tx *sql.Tx, publication *safeTextPublication, reference harnessadapter.AttemptRef, event harnessadapter.Event) error {
	source, content, full, incomplete, ok := adapterEventSafeText(event)
	if !ok {
		return nil
	}
	if publication == nil {
		return errors.New("safe text publication is unavailable")
	}
	return node.captureSafeText(ctx, tx, publication, reference, source, content, full, incomplete)
}

func (node *Node) validateAdapterEventSafeTextReplay(ctx context.Context, tx *sql.Tx, reference harnessadapter.AttemptRef, event harnessadapter.Event) error {
	source, content, full, incomplete, ok := adapterEventSafeText(event)
	if !ok {
		return nil
	}
	return node.validateExistingSafeTextReplay(ctx, tx, reference, source, content, full, incomplete)
}

type adapterProjection struct {
	eventType     string
	entityID      string
	entityVersion int64
	payload       any
	hashPayload   any
	key           string
	outputLimit   bool
	markerOnly    bool
}

func (node *Node) projectAdapterEvent(ctx context.Context, tx *sql.Tx, publication *safeTextPublication, state *durableState, reference harnessadapter.AttemptRef, attemptVersion int64, attemptState string, event harnessadapter.Event) (bool, bool, error) {
	// Replays are deduplicated by their frozen wire-v2 projection. Compare the
	// private safe bytes first so a changed tail behind the same 64 KiB preview
	// cannot be accepted as the same semantic source.
	if err := node.validateAdapterEventSafeTextReplay(ctx, tx, reference, event); err != nil {
		return false, false, err
	}
	projection, terminal, err := node.prepareProjection(ctx, tx, state, reference, attemptVersion, attemptState, event)
	if err != nil {
		return false, false, err
	}
	if projection.eventType == "" {
		return terminal, false, nil
	}
	duplicate, err := adapterProjectionExists(ctx, tx, reference.AttemptID, projection)
	if err != nil {
		return terminal, false, err
	}
	if duplicate {
		return terminal, false, node.validateAdapterEventSafeTextReplay(ctx, tx, reference, event)
	}
	if err := node.captureAdapterEventSafeText(ctx, tx, publication, reference, event); err != nil {
		return false, false, err
	}
	if projection.markerOnly {
		if err := node.appendAdapterOutputLimitMarker(ctx, tx, state, reference, projection); err != nil {
			return false, false, err
		}
		if err := node.scheduleOutputLimitStop(ctx, tx, state, reference); err != nil {
			return false, false, err
		}
		return false, true, nil
	}
	state.StateVersion++
	if _, err := node.appendEvent(ctx, tx, state, projection.eventType, projection.entityID, projection.entityVersion, reference.AttemptID, reference.DialogID, projection.payload, false); err != nil {
		return false, false, err
	}
	if err := recordAdapterProjection(ctx, tx, state.LastEventSeq, reference.AttemptID, projection); err != nil {
		return false, false, err
	}
	if projection.outputLimit {
		if err := node.scheduleOutputLimitStop(ctx, tx, state, reference); err != nil {
			return false, false, err
		}
	}
	if terminal {
		if err := node.appendNodeEvent(ctx, tx, state); err != nil {
			return false, false, err
		}
	}
	return terminal, projection.outputLimit, nil
}

func (node *Node) prepareProjection(ctx context.Context, tx *sql.Tx, state *durableState, reference harnessadapter.AttemptRef, attemptVersion int64, attemptState string, event harnessadapter.Event) (adapterProjection, bool, error) {
	switch value := event.(type) {
	case harnessadapter.StartedEvent:
		return adapterProjection{eventType: "attempt.started", entityID: reference.AttemptID, entityVersion: attemptVersion, payload: harnessprotocol.AttemptStartedPayload{RequestID: reference.RequestID, Generation: reference.Generation}, key: "started"}, false, nil
	case harnessadapter.WaitingEvent:
		if value.Kind != "approval" && value.Kind != "input" {
			return adapterProjection{}, false, errors.New("adapter wait kind is invalid")
		}
		if attemptState == "waiting_input" {
			return adapterProjection{}, false, nil
		}
		if attemptState == "running" {
			if _, err := tx.ExecContext(ctx, "UPDATE attempts SET version=version+1,state='waiting_input' WHERE attempt_id=?", reference.AttemptID); err != nil {
				return adapterProjection{}, false, err
			}
			attemptVersion++
		} else {
			return adapterProjection{}, false, errors.New("attempt cannot enter waiting_input")
		}
		return adapterProjection{eventType: "attempt.waiting_input", entityID: reference.AttemptID, entityVersion: attemptVersion, payload: harnessprotocol.AttemptWaitingPayload{RequestID: reference.RequestID, Generation: reference.Generation, WaitKind: value.Kind}, key: fmt.Sprintf("waiting:%d", attemptVersion)}, false, nil
	case harnessadapter.AssistantDeltaEvent:
		if err := validateSafeContentReference(ctx, tx, reference, value.Content, "", false); err != nil {
			return adapterProjection{}, false, err
		}
		payload := harnessprotocol.AssistantDeltaPayload{MessageID: value.MessageID, DeltaIndex: value.DeltaIndex, Content: value.Content}
		projection := adapterProjection{eventType: "assistant.delta", entityID: value.MessageID, entityVersion: value.DeltaIndex + 1, payload: payload, hashPayload: payload, key: fmt.Sprintf("assistant.delta:%s:%d", value.MessageID, value.DeltaIndex)}
		charge, duplicate, err := node.chargeSafeAdapterProjection(ctx, tx, *state, reference, projection, value.Content)
		if err != nil || duplicate || (charge.Exceeded && !charge.NewlyExceeded) {
			return adapterProjection{}, false, err
		}
		if charge.Exceeded {
			payload.Content = outputLimitContent()
			projection.payload = payload
			projection.outputLimit = true
		}
		return projection, false, nil
	case harnessadapter.AssistantMessageEvent:
		if err := validateSafeContentReference(ctx, tx, reference, value.Content, "", false); err != nil {
			return adapterProjection{}, false, err
		}
		payload := harnessprotocol.AssistantMessagePayload{MessageID: value.MessageID, Content: value.Content, FinishReason: value.FinishReason}
		projection := adapterProjection{eventType: "assistant.message", entityID: value.MessageID, entityVersion: 1, payload: payload, hashPayload: payload, key: "assistant.message:" + value.MessageID}
		charge, duplicate, err := node.chargeSafeAdapterProjection(ctx, tx, *state, reference, projection, value.Content)
		if err != nil || duplicate || (charge.Exceeded && !charge.NewlyExceeded) {
			return adapterProjection{}, false, err
		}
		if charge.Exceeded {
			payload.Content = outputLimitContent()
			projection.payload = payload
			projection.outputLimit = true
		}
		content, err := json.Marshal(payload.Content)
		if err != nil {
			return adapterProjection{}, false, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO messages(message_id,dialog_id,sequence,version,role,content_json,attempt_id,finish_reason,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, value.MessageID, reference.DialogID, state.NextMessageSequence, 1, "assistant", content, reference.AttemptID, value.FinishReason, timestamp(node.config.Clock())); err != nil {
			return adapterProjection{}, false, err
		}
		state.NextMessageSequence++
		return projection, false, nil
	case harnessadapter.ToolStartedEvent:
		if err := validateSafeContentReference(ctx, tx, reference, value.Input, value.CallID, true); err != nil {
			return adapterProjection{}, false, err
		}
		payload := harnessprotocol.ToolStartedPayload{CallID: value.CallID, ToolName: value.ToolName, ActionHash: value.ActionHash, Input: value.Input}
		projection := adapterProjection{eventType: "tool.started", entityID: value.CallID, entityVersion: 1, payload: payload, hashPayload: payload, key: "tool.started:" + value.CallID}
		charge, duplicate, err := node.chargeSafeAdapterProjection(ctx, tx, *state, reference, projection, value.Input)
		if err != nil || duplicate || (charge.Exceeded && !charge.NewlyExceeded) {
			return adapterProjection{}, false, err
		}
		if charge.Exceeded {
			payload.Input = outputLimitContent()
			projection.payload = payload
			projection.outputLimit = true
		}
		encoded, err := json.Marshal(payload.Input)
		if err != nil {
			return adapterProjection{}, false, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO tool_calls(call_id,attempt_id,action_hash,version,status,safe_input_json) VALUES(?,?,?,1,'running',?)`, value.CallID, reference.AttemptID, value.ActionHash, encoded); err != nil {
			return adapterProjection{}, false, err
		}
		return projection, false, nil
	case harnessadapter.ToolOutputEvent:
		if err := validateSafeContentReference(ctx, tx, reference, value.Output, value.CallID, true); err != nil {
			return adapterProjection{}, false, err
		}
		var exists int
		if err := tx.QueryRowContext(ctx, "SELECT 1 FROM tool_calls WHERE call_id=? AND attempt_id=?", value.CallID, reference.AttemptID).Scan(&exists); err != nil {
			return adapterProjection{}, false, err
		}
		payload := harnessprotocol.ToolOutputPayload{CallID: value.CallID, ChunkIndex: value.ChunkIndex, Stream: value.Stream, Output: value.Output}
		projection := adapterProjection{eventType: "tool.output", entityID: value.CallID, entityVersion: value.ChunkIndex + 1, payload: payload, hashPayload: payload, key: fmt.Sprintf("tool.output:%s:%d", value.CallID, value.ChunkIndex)}
		charge, duplicate, err := node.chargeSafeAdapterProjection(ctx, tx, *state, reference, projection, value.Output)
		if err != nil || duplicate || (charge.Exceeded && !charge.NewlyExceeded) {
			return adapterProjection{}, false, err
		}
		if charge.Exceeded {
			payload.Output = outputLimitContent()
			projection.payload = payload
			projection.outputLimit = true
		}
		return projection, false, nil
	case harnessadapter.ToolCompletedEvent:
		if err := validateSafeContentReference(ctx, tx, reference, value.Result, value.CallID, true); err != nil {
			return adapterProjection{}, false, err
		}
		var version int64
		if err := tx.QueryRowContext(ctx, "SELECT version FROM tool_calls WHERE call_id=? AND attempt_id=?", value.CallID, reference.AttemptID).Scan(&version); err != nil {
			return adapterProjection{}, false, err
		}
		payload := harnessprotocol.ToolCompletedPayload{CallID: value.CallID, Status: value.Status, Result: value.Result, EffectStatus: value.EffectStatus, EffectRef: value.EffectRef}
		projection := adapterProjection{eventType: "tool.completed", entityID: value.CallID, entityVersion: version + 1, payload: payload, hashPayload: payload, key: "tool.completed:" + value.CallID}
		charge, duplicate, err := node.chargeSafeAdapterProjection(ctx, tx, *state, reference, projection, value.Result)
		if err != nil || duplicate || (charge.Exceeded && !charge.NewlyExceeded) {
			return adapterProjection{}, false, err
		}
		if charge.Exceeded {
			payload.Result = outputLimitContent()
			projection.payload = payload
			projection.outputLimit = true
		}
		result, err := json.Marshal(payload.Result)
		if err != nil {
			return adapterProjection{}, false, err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE tool_calls SET version=version+1,status=?,safe_result_json=?,effect_ref=? WHERE call_id=?", value.Status, result, nullText(value.EffectRef), value.CallID); err != nil {
			return adapterProjection{}, false, err
		}
		return projection, false, nil
	case harnessadapter.ApprovalRequestedEvent:
		var actionHash string
		if err := tx.QueryRowContext(ctx, "SELECT action_hash FROM tool_calls WHERE call_id=? AND attempt_id=?", value.CallID, reference.AttemptID).Scan(&actionHash); err != nil || actionHash != value.ActionHash {
			if err == nil {
				err = errors.New("approval action hash mismatch")
			}
			return adapterProjection{}, false, err
		}
		payload := harnessprotocol.ApprovalRequestedPayload{ApprovalID: value.ApprovalID, CallID: value.CallID, ActionHash: value.ActionHash, SafePrompt: value.SafePrompt, ApprovalVersion: 1}
		projection := adapterProjection{eventType: "approval.requested", entityID: value.ApprovalID, entityVersion: 1, payload: payload, hashPayload: payload, key: "approval.requested:" + value.ApprovalID}
		charge, duplicate, err := node.chargeAdapterProjection(ctx, tx, *state, reference, projection, int64(len([]byte(value.SafePrompt))))
		if err != nil || duplicate || (charge.Exceeded && !charge.NewlyExceeded) {
			return adapterProjection{}, false, err
		}
		if charge.Exceeded {
			projection.outputLimit = true
			projection.markerOnly = true
			return projection, false, nil
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO approvals(approval_id,attempt_id,call_id,action_hash,version,status) VALUES(?,?,?,?,1,'pending')`, value.ApprovalID, reference.AttemptID, value.CallID, value.ActionHash); err != nil {
			return adapterProjection{}, false, err
		}
		if err := transitionWaiting(ctx, tx, reference, attemptVersion, attemptState, "approval", node, state); err != nil {
			return adapterProjection{}, false, err
		}
		return projection, false, nil
	case harnessadapter.InputRequestedEvent:
		if err := validateSafeContentReference(ctx, tx, reference, value.Prompt, "", false); err != nil {
			return adapterProjection{}, false, err
		}
		payload := harnessprotocol.InputRequestedPayload{InputRequestID: value.InputRequestID, Prompt: value.Prompt, InputVersion: 1}
		projection := adapterProjection{eventType: "input.requested", entityID: value.InputRequestID, entityVersion: 1, payload: payload, hashPayload: payload, key: "input.requested:" + value.InputRequestID}
		charge, duplicate, err := node.chargeSafeAdapterProjection(ctx, tx, *state, reference, projection, value.Prompt)
		if err != nil || duplicate || (charge.Exceeded && !charge.NewlyExceeded) {
			return adapterProjection{}, false, err
		}
		if charge.Exceeded {
			payload.Prompt = outputLimitContent()
			projection.payload = payload
			projection.outputLimit = true
		}
		prompt, err := json.Marshal(payload.Prompt)
		if err != nil {
			return adapterProjection{}, false, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO input_requests(input_request_id,attempt_id,version,status,prompt_json) VALUES(?,?,1,'pending',?)`, value.InputRequestID, reference.AttemptID, prompt); err != nil {
			return adapterProjection{}, false, err
		}
		if !charge.Exceeded {
			if err := transitionWaiting(ctx, tx, reference, attemptVersion, attemptState, "input", node, state); err != nil {
				return adapterProjection{}, false, err
			}
		}
		return projection, false, nil
	case harnessadapter.TerminalEvent:
		return node.prepareTerminalProjection(ctx, tx, state, reference, attemptVersion, value)
	case harnessadapter.UnknownEvent:
		if err := node.setAttemptUnknown(ctx, tx, state, reference, value.Reason, value.EffectStatus); err != nil {
			return adapterProjection{}, false, err
		}
		return adapterProjection{}, true, nil
	default:
		return adapterProjection{}, false, errors.New("unsupported adapter event")
	}
}

func (node *Node) scheduleOutputLimitStop(ctx context.Context, tx *sql.Tx, state *durableState, reference harnessadapter.AttemptRef) error {
	if !state.ActiveAttemptID.Valid || state.ActiveAttemptID.String != reference.AttemptID {
		return nil
	}
	var version, generation int64
	var attemptState string
	if err := tx.QueryRowContext(ctx, "SELECT version,generation,state FROM attempts WHERE attempt_id=?", reference.AttemptID).Scan(&version, &generation, &attemptState); err != nil {
		return err
	}
	if generation != reference.Generation || (attemptState != "running" && attemptState != "waiting_input") {
		return nil
	}
	commandID, err := node.newID()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE attempts SET version=version+1,state='stopping' WHERE attempt_id=?", reference.AttemptID); err != nil {
		return err
	}
	state.StateVersion++
	if _, err := node.appendEvent(ctx, tx, state, "attempt.stop_requested", reference.AttemptID, version+1, reference.AttemptID, reference.DialogID, harnessprotocol.AttemptStopRequestedPayload{Generation: reference.Generation, CommandID: commandID}, false); err != nil {
		return err
	}
	payload := mustJSON(map[string]any{"generation": reference.Generation, "dialogId": reference.DialogID, "requestId": reference.RequestID})
	_, err = tx.ExecContext(ctx, `INSERT INTO control_actions(command_id,kind,attempt_id,payload,status) VALUES(?,?,?,?, 'pending')`, commandID, string(harnessprotocol.CommandAttemptStop), reference.AttemptID, []byte(payload))
	return err
}

type Observation struct {
	AttemptID     string
	Generation    int64
	Kind          string
	TerminalState string
	Reason        string
	EffectStatus  string
	Confirmed     bool
}

func (node *Node) Observe(ctx context.Context, observation Observation) error {
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
	var generation, version int64
	var dialogID, requestID, attemptState string
	if err := tx.QueryRowContext(ctx, `SELECT a.generation,a.version,a.dialog_id,a.request_id,a.state FROM attempts a WHERE a.attempt_id=? AND NOT EXISTS (
		SELECT 1 FROM events deleted WHERE deleted.dialog_id=a.dialog_id AND deleted.projection_key='dialog.deleted')`, observation.AttemptID).Scan(&generation, &version, &dialogID, &requestID, &attemptState); err != nil {
		return err
	}
	if observation.Generation != generation || !state.ActiveAttemptID.Valid || state.ActiveAttemptID.String != observation.AttemptID {
		return node.archiveLateObservation(ctx, tx, &state, observation, version, dialogID)
	}
	reference := harnessadapter.AttemptRef{NodeID: state.NodeID, DialogID: dialogID, RequestID: requestID, AttemptID: observation.AttemptID, Generation: generation}
	switch observation.Kind {
	case "unknown":
		if err := node.setAttemptUnknown(ctx, tx, &state, reference, observation.Reason, observation.EffectStatus); err != nil {
			return err
		}
	case "terminal":
		if !observation.Confirmed {
			return errors.New("unconfirmed terminal observation")
		}
		if err := node.applyTerminal(ctx, tx, &state, reference, version, observation); err != nil {
			return err
		}
	default:
		return errors.New("unsupported observation kind")
	}
	if err := saveState(ctx, tx, state); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if observation.Kind == "terminal" {
		node.cancelAttemptStream(reference)
		node.afterCommit(context.Background(), postCommitAction{})
	}
	return nil
}

func (node *Node) markAttemptUnknown(ctx context.Context, reference harnessadapter.AttemptRef, reason, effectStatus string) {
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil || !state.ActiveAttemptID.Valid || state.ActiveAttemptID.String != reference.AttemptID {
		return
	}
	if err := node.setAttemptUnknown(ctx, tx, &state, reference, reason, effectStatus); err != nil || saveState(ctx, tx, state) != nil {
		return
	}
	_ = tx.Commit()
}

func (node *Node) setAttemptUnknown(ctx context.Context, tx *sql.Tx, state *durableState, reference harnessadapter.AttemptRef, reason, effectStatus string) error {
	var version int64
	var currentState string
	if err := tx.QueryRowContext(ctx, "SELECT version,state FROM attempts WHERE attempt_id=? AND generation=?", reference.AttemptID, reference.Generation).Scan(&version, &currentState); err != nil {
		return err
	}
	if currentState == "unknown" {
		return nil
	}
	if effectStatus == "" {
		effectStatus = "unknown"
	}
	if _, err := tx.ExecContext(ctx, "UPDATE attempts SET version=version+1,state='unknown',effect_status=? WHERE attempt_id=?", effectStatus, reference.AttemptID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE requests SET version=version+1,status='unknown',updated_at=? WHERE request_id=?", timestamp(node.config.Clock()), reference.RequestID); err != nil {
		return err
	}
	state.StateVersion++
	state.EngineReadiness = "unknown"
	state.Occupancy = "unknown"
	state.ActiveAttemptID = sql.NullString{String: reference.AttemptID, Valid: true}
	state.BlockedReasons = addReason(state.BlockedReasons, "execution_unknown")
	if _, err := node.appendEvent(ctx, tx, state, "attempt.unknown", reference.AttemptID, version+1, reference.AttemptID, reference.DialogID, harnessprotocol.AttemptUnknownPayload{
		Generation: reference.Generation, Reason: reason, EffectStatus: effectStatus,
	}, false); err != nil {
		return err
	}
	return node.appendNodeEvent(ctx, tx, state)
}

func (node *Node) applyTerminal(ctx context.Context, tx *sql.Tx, state *durableState, reference harnessadapter.AttemptRef, version int64, observation Observation) error {
	terminal := observation.TerminalState
	if terminal != "completed" && terminal != "failed" && terminal != "interrupted" {
		return errors.New("unsupported terminal state")
	}
	now := timestamp(node.config.Clock())
	if _, err := tx.ExecContext(ctx, "UPDATE attempts SET version=version+1,state=?,effect_status=?,finished_at=? WHERE attempt_id=?", terminal, observation.EffectStatus, now, reference.AttemptID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE requests SET version=version+1,status=?,updated_at=? WHERE request_id=?", terminal, now, reference.RequestID); err != nil {
		return err
	}
	state.StateVersion++
	state.ActiveAttemptID = sql.NullString{}
	state.Occupancy = "idle"
	if state.EngineReadiness == "unknown" {
		state.EngineReadiness = "blocked"
	}
	var eventType string
	var payload any
	switch terminal {
	case "completed":
		eventType = "attempt.completed"
		payload = harnessprotocol.AttemptCompletedPayload{Generation: reference.Generation, Output: harnessprotocol.AttemptOutput{Kind: "empty"}}
	case "failed":
		eventType = "attempt.failed"
		payload = harnessprotocol.AttemptFailedPayload{Generation: reference.Generation, FailureClass: "task", ErrorCode: "adapter_failed", SafeMessage: "attempt failed", Retryable: false, EffectStatus: observation.EffectStatus}
	case "interrupted":
		eventType = "attempt.interrupted"
		payload = harnessprotocol.AttemptInterruptedPayload{Generation: reference.Generation, Reason: "provider_interrupt", EffectStatus: observation.EffectStatus}
	}
	if _, err := node.appendEvent(ctx, tx, state, eventType, reference.AttemptID, version+1, reference.AttemptID, reference.DialogID, payload, false); err != nil {
		return err
	}
	return node.appendNodeEvent(ctx, tx, state)
}

func (node *Node) archiveLateObservation(ctx context.Context, tx *sql.Tx, state *durableState, observation Observation, entityVersion int64, dialogID string) error {
	eventType := "attempt.unknown"
	payload := any(harnessprotocol.AttemptUnknownPayload{Generation: observation.Generation, Reason: "provider_state", EffectStatus: observation.EffectStatus})
	if observation.Kind == "terminal" {
		switch observation.TerminalState {
		case "completed":
			eventType = "attempt.completed"
			payload = harnessprotocol.AttemptCompletedPayload{Generation: observation.Generation, Output: harnessprotocol.AttemptOutput{Kind: "empty"}}
		case "failed":
			eventType = "attempt.failed"
			payload = harnessprotocol.AttemptFailedPayload{Generation: observation.Generation, FailureClass: "task", ErrorCode: "late_failure", SafeMessage: "late attempt failure", Retryable: false, EffectStatus: observation.EffectStatus}
		case "interrupted":
			eventType = "attempt.interrupted"
			payload = harnessprotocol.AttemptInterruptedPayload{Generation: observation.Generation, Reason: "provider_interrupt", EffectStatus: observation.EffectStatus}
		default:
			return errors.New("unsupported late terminal state")
		}
	}
	encoded, err := json.Marshal(observation)
	if err != nil {
		return err
	}
	if _, err := node.appendEvent(ctx, tx, state, eventType, observation.AttemptID, entityVersion, observation.AttemptID, dialogID, payload, true); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO late_observations(attempt_id,generation,kind,observation_json,event_seq,observed_at) VALUES(?,?,?,?,?,?)`, observation.AttemptID, observation.Generation, observation.Kind, encoded, state.LastEventSeq, timestamp(node.config.Clock())); err != nil {
		return err
	}
	if err := saveState(ctx, tx, *state); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit late observation: %w", err)
	}
	return nil
}

func transitionWaiting(ctx context.Context, tx *sql.Tx, reference harnessadapter.AttemptRef, attemptVersion int64, attemptState, waitKind string, node *Node, state *durableState) error {
	if attemptState != "running" && attemptState != "waiting_input" {
		return errors.New("attempt cannot enter waiting_input")
	}
	if _, err := tx.ExecContext(ctx, "UPDATE attempts SET version=version+1,state='waiting_input' WHERE attempt_id=?", reference.AttemptID); err != nil {
		return err
	}
	state.StateVersion++
	_, err := node.appendEvent(ctx, tx, state, "attempt.waiting_input", reference.AttemptID, attemptVersion+1, reference.AttemptID, reference.DialogID, harnessprotocol.AttemptWaitingPayload{RequestID: reference.RequestID, Generation: reference.Generation, WaitKind: waitKind}, false)
	return err
}

func validateSafeContentReference(ctx context.Context, tx *sql.Tx, reference harnessadapter.AttemptRef, content harnessprotocol.SafeContent, expectedCallID string, bindCall bool) error {
	if content.Kind != "artifact" {
		return nil
	}
	if content.SizeBytes == nil {
		return errors.New("artifact safe content is missing size")
	}
	var size int64
	var hash, redaction, callID, disposition string
	var truncated bool
	if err := tx.QueryRowContext(ctx, `SELECT size_bytes,sha256,redaction,truncated,COALESCE(call_id,''),disposition FROM artifacts WHERE artifact_id=? AND dialog_id=? AND attempt_id=?`, content.ArtifactID, reference.DialogID, reference.AttemptID).Scan(&size, &hash, &redaction, &truncated, &callID, &disposition); err != nil {
		return err
	}
	if size != *content.SizeBytes || hash != content.SHA256 || redaction != content.Redaction || truncated != content.Truncated ||
		(disposition != "inline" && disposition != "attachment") || (bindCall && callID != expectedCallID) {
		return errors.New("artifact safe content binding mismatch")
	}
	return nil
}

func (node *Node) prepareTerminalProjection(ctx context.Context, tx *sql.Tx, state *durableState, reference harnessadapter.AttemptRef, attemptVersion int64, event harnessadapter.TerminalEvent) (adapterProjection, bool, error) {
	if event.EffectStatus != "none" && event.EffectStatus != "known" && event.EffectStatus != "unknown" {
		return adapterProjection{}, false, errors.New("adapter terminal effect status is invalid")
	}
	var unresolved int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM control_actions WHERE attempt_id=? AND kind IN(?,?,?) AND status IN('pending','inflight','unknown')`, reference.AttemptID, string(harnessprotocol.CommandMessageSteer), string(harnessprotocol.CommandApprovalRespond), string(harnessprotocol.CommandInputRespond)).Scan(&unresolved); err != nil {
		return adapterProjection{}, false, err
	}
	if unresolved > 0 || event.EffectStatus == "unknown" {
		if err := node.setAttemptUnknown(ctx, tx, state, reference, "provider_state", "unknown"); err != nil {
			return adapterProjection{}, false, err
		}
		var archivedVersion int64
		if err := tx.QueryRowContext(ctx, "SELECT version FROM attempts WHERE attempt_id=?", reference.AttemptID).Scan(&archivedVersion); err != nil {
			return adapterProjection{}, false, err
		}
		if err := node.archiveAdapterEvent(ctx, tx, nil, state, event, archivedVersion, true, "terminal_while_steer_unresolved"); err != nil {
			return adapterProjection{}, false, err
		}
		return adapterProjection{}, true, nil
	}

	effectStatus := event.EffectStatus
	var terminalState, eventType string
	var payload any
	switch event.Outcome {
	case harnessadapter.ReconcileCompleted:
		terminalState, eventType = "completed", "attempt.completed"
		output := harnessprotocol.AttemptOutput{Kind: "empty"}
		var messageID string
		var encoded []byte
		err := tx.QueryRowContext(ctx, `SELECT message_id,content_json FROM messages WHERE attempt_id=? AND role='assistant' ORDER BY sequence DESC LIMIT 1`, reference.AttemptID).Scan(&messageID, &encoded)
		if err == nil {
			if event.Output != nil {
				var stored harnessprotocol.SafeContent
				if json.Unmarshal(encoded, &stored) != nil {
					return adapterProjection{}, false, errors.New("terminal output does not match assistant message")
				}
				limited := false
				if safeContentEqual(stored, outputLimitContent()) {
					var err error
					limited, err = attemptOutputExceeded(ctx, tx, reference.AttemptID)
					if err != nil {
						return adapterProjection{}, false, err
					}
				}
				if !limited && !safeContentEqual(stored, *event.Output) {
					return adapterProjection{}, false, errors.New("terminal output does not match assistant message")
				}
			}
			output = harnessprotocol.AttemptOutput{Kind: "message", AssistantMessageID: messageID}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return adapterProjection{}, false, err
		} else if event.Output != nil {
			limited, limitErr := attemptOutputExceeded(ctx, tx, reference.AttemptID)
			if limitErr != nil {
				return adapterProjection{}, false, limitErr
			}
			if !limited {
				return adapterProjection{}, false, errors.New("terminal output has no durable assistant message")
			}
		}
		payload = harnessprotocol.AttemptCompletedPayload{Generation: reference.Generation, Output: output, Usage: event.Usage}
	case harnessadapter.ReconcileFailed:
		if event.Failure == nil {
			return adapterProjection{}, false, errors.New("failed terminal is missing failure")
		}
		terminalState, eventType = "failed", "attempt.failed"
		payload = harnessprotocol.AttemptFailedPayload{Generation: reference.Generation, FailureClass: string(event.Failure.Class), ErrorCode: event.Failure.Code, SafeMessage: event.Failure.SafeMessage, Retryable: event.Failure.Retryable, EffectStatus: effectStatus}
	case harnessadapter.ReconcileInterrupted:
		terminalState, eventType = "interrupted", "attempt.interrupted"
		payload = harnessprotocol.AttemptInterruptedPayload{Generation: reference.Generation, Reason: "provider_interrupt", EffectStatus: effectStatus}
	case harnessadapter.ReconcileUnknown:
		if err := node.setAttemptUnknown(ctx, tx, state, reference, "provider_state", effectStatus); err != nil {
			return adapterProjection{}, false, err
		}
		return adapterProjection{}, true, nil
	default:
		return adapterProjection{}, false, errors.New("adapter terminal outcome is not terminal")
	}
	projection := adapterProjection{eventType: eventType, entityID: reference.AttemptID, entityVersion: attemptVersion + 1, payload: payload, key: "terminal"}
	duplicate, err := adapterProjectionExists(ctx, tx, reference.AttemptID, projection)
	if err != nil || duplicate {
		return adapterProjection{}, true, err
	}
	now := timestamp(node.config.Clock())
	if _, err := tx.ExecContext(ctx, "UPDATE attempts SET version=version+1,state=?,effect_status=?,finished_at=? WHERE attempt_id=?", terminalState, effectStatus, now, reference.AttemptID); err != nil {
		return adapterProjection{}, false, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE requests SET version=version+1,status=?,updated_at=? WHERE request_id=?", terminalState, now, reference.RequestID); err != nil {
		return adapterProjection{}, false, err
	}
	state.ActiveAttemptID = sql.NullString{}
	state.Occupancy = "idle"
	state.BlockedReasons = removeReason(state.BlockedReasons, "execution_unknown")
	if event.Outcome == harnessadapter.ReconcileFailed {
		failure := event.Failure
		switch failure.Class {
		case harnessadapter.FailureNode:
			state.BlockedReasons = addReason(state.BlockedReasons, "engine_unavailable")
		case harnessadapter.FailurePolicy:
			state.BlockedReasons = addReason(state.BlockedReasons, "policy_unavailable")
		case harnessadapter.FailureProtocol:
			state.BlockedReasons = addReason(state.BlockedReasons, "adapter_protocol")
		}
	}
	if len(state.BlockedReasons) == 0 {
		state.EngineReadiness = "ready"
	} else {
		state.EngineReadiness = "blocked"
	}
	return projection, true, nil
}

func safeContentEqual(left, right harnessprotocol.SafeContent) bool {
	leftHash, leftErr := adapterProjectionHash(left)
	rightHash, rightErr := adapterProjectionHash(right)
	return leftErr == nil && rightErr == nil && leftHash == rightHash
}

func isInteractiveWaitEvent(event harnessadapter.Event) bool {
	switch event.(type) {
	case harnessadapter.WaitingEvent, harnessadapter.ApprovalRequestedEvent, harnessadapter.InputRequestedEvent:
		return true
	default:
		return false
	}
}

func (node *Node) archiveSuppressedAdapterEvent(ctx context.Context, tx *sql.Tx, state *durableState, event harnessadapter.Event, attemptVersion int64) error {
	return node.archiveAdapterEvent(ctx, tx, nil, state, event, attemptVersion, true, "")
}

func (node *Node) validateArchivedAdapterEvent(ctx context.Context, tx *sql.Tx, state durableState, event harnessadapter.Event, projection adapterProjection) error {
	reference := event.AttemptReference()
	if err := validateAdapterEventSafeContent(ctx, tx, reference, event); err != nil {
		return err
	}
	switch value := event.(type) {
	case harnessadapter.ToolOutputEvent:
		var exists int
		if err := tx.QueryRowContext(ctx, "SELECT 1 FROM tool_calls WHERE call_id=? AND attempt_id=?", value.CallID, reference.AttemptID).Scan(&exists); err != nil {
			return err
		}
	case harnessadapter.ToolCompletedEvent:
		var exists int
		if err := tx.QueryRowContext(ctx, "SELECT 1 FROM tool_calls WHERE call_id=? AND attempt_id=?", value.CallID, reference.AttemptID).Scan(&exists); err != nil {
			return err
		}
	case harnessadapter.ApprovalRequestedEvent:
		var actionHash string
		if err := tx.QueryRowContext(ctx, "SELECT action_hash FROM tool_calls WHERE call_id=? AND attempt_id=?", value.CallID, reference.AttemptID).Scan(&actionHash); err != nil {
			return err
		}
		if actionHash != value.ActionHash {
			return errors.New("archived approval action hash mismatch")
		}
	case harnessadapter.TerminalEvent:
		if value.EffectStatus != "none" && value.EffectStatus != "known" && value.EffectStatus != "unknown" {
			return errors.New("archived terminal effect status is invalid")
		}
	}
	return node.validateAdapterProjectionEnvelope(state, reference, projection)
}

func archivedProjectionExists(ctx context.Context, tx *sql.Tx, attemptID string, projection adapterProjection) (bool, error) {
	want, err := adapterProjectionDigest(projection)
	if err != nil {
		return false, err
	}
	var exact int
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM events WHERE attempt_id=? AND projection_hash=? AND projection_key IS NOT NULL)", attemptID, want).Scan(&exact); err != nil {
		return false, err
	}
	if exact != 0 {
		return true, nil
	}
	activeKey := strings.TrimPrefix(projection.key, "archive:")
	terminal := activeKey == "terminal" || strings.HasPrefix(activeKey, "terminal:")
	if strings.HasPrefix(activeKey, "terminal:") {
		activeKey = "terminal"
	} else if activeKey == "unknown" {
		activeKey = ""
	}
	if activeKey != "" {
		var stored string
		err := tx.QueryRowContext(ctx, "SELECT projection_hash FROM events WHERE attempt_id=? AND projection_key=?", attemptID, activeKey).Scan(&stored)
		if err == nil && terminal {
			compatible, digestErr := activeTerminalProjectionDigest(ctx, tx, attemptID, projection)
			if digestErr != nil {
				return false, digestErr
			}
			if stored == compatible {
				return true, nil
			}
		}
		if err == nil && stored != want && !terminal && !strings.HasPrefix(activeKey, "waiting:") {
			return false, errors.New("conflicting duplicate archived adapter event")
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
	}
	for _, query := range []string{
		"SELECT projection_hash FROM events WHERE attempt_id=? AND projection_key=?",
		"SELECT projection_hash FROM late_observations WHERE attempt_id=? AND projection_key=?",
	} {
		var stored string
		err := tx.QueryRowContext(ctx, query, attemptID, projection.key).Scan(&stored)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return false, err
		}
		if stored != want {
			return false, errors.New("conflicting duplicate archived adapter event")
		}
		return true, nil
	}
	return false, nil
}

func activeTerminalProjectionDigest(ctx context.Context, tx *sql.Tx, attemptID string, projection adapterProjection) (string, error) {
	compatible := projection
	compatible.hashPayload = nil
	if payload, ok := compatible.payload.(harnessprotocol.AttemptCompletedPayload); ok {
		var messageID string
		var encoded []byte
		err := tx.QueryRowContext(ctx, `SELECT message_id,content_json FROM messages WHERE attempt_id=? AND role='assistant' ORDER BY sequence DESC LIMIT 1`, attemptID).Scan(&messageID, &encoded)
		if err == nil {
			identity, _ := projection.hashPayload.(archivedTerminalIdentity)
			if identity.Output != nil {
				var stored harnessprotocol.SafeContent
				if json.Unmarshal(encoded, &stored) != nil || !safeContentEqual(stored, *identity.Output) {
					return "", nil
				}
			}
			payload.Output = harnessprotocol.AttemptOutput{Kind: "message", AssistantMessageID: messageID}
			compatible.payload = payload
		} else if !errors.Is(err, sql.ErrNoRows) {
			return "", err
		} else if identity, ok := projection.hashPayload.(archivedTerminalIdentity); ok && identity.Output != nil {
			return "", nil
		}
	}
	return adapterProjectionDigest(compatible)
}

func archivedAdapterOutputBytes(event harnessadapter.Event) int64 {
	var content harnessprotocol.SafeContent
	var bytes int64
	switch value := event.(type) {
	case harnessadapter.AssistantDeltaEvent:
		content = value.Content
	case harnessadapter.AssistantMessageEvent:
		content = value.Content
	case harnessadapter.ToolStartedEvent:
		content = value.Input
	case harnessadapter.ToolOutputEvent:
		content = value.Output
	case harnessadapter.ToolCompletedEvent:
		content = value.Result
	case harnessadapter.InputRequestedEvent:
		content = value.Prompt
	case harnessadapter.TerminalEvent:
		if value.Output != nil {
			content = *value.Output
		}
		if value.Failure != nil {
			bytes += int64(len([]byte(value.Failure.SafeMessage)))
		}
	case harnessadapter.ApprovalRequestedEvent:
		return int64(len([]byte(value.SafePrompt)))
	}
	if content.Kind == "inline" {
		bytes += int64(len([]byte(content.Content)))
	}
	return bytes
}

func (node *Node) archivedOutputLimitProjection(projection adapterProjection) (adapterProjection, error) {
	limited := outputLimitContent()
	switch payload := projection.payload.(type) {
	case harnessprotocol.AssistantDeltaPayload:
		payload.Content = limited
		projection.payload = payload
	case harnessprotocol.AssistantMessagePayload:
		payload.Content = limited
		projection.payload = payload
	case harnessprotocol.ToolStartedPayload:
		payload.Input = limited
		projection.payload = payload
	case harnessprotocol.ToolOutputPayload:
		payload.Output = limited
		projection.payload = payload
	case harnessprotocol.ToolCompletedPayload:
		payload.Result = limited
		projection.payload = payload
	case harnessprotocol.InputRequestedPayload:
		payload.Prompt = limited
		projection.payload = payload
	default:
		messageID, err := node.newID()
		if err != nil {
			return adapterProjection{}, err
		}
		projection.eventType = "assistant.message"
		projection.entityID = messageID
		projection.entityVersion = 1
		projection.payload = harnessprotocol.AssistantMessagePayload{MessageID: messageID, Content: limited, FinishReason: "length"}
	}
	return projection, nil
}

func (node *Node) validateAdapterProjectionEnvelope(state durableState, reference harnessadapter.AttemptRef, projection adapterProjection) error {
	payload, err := json.Marshal(projection.payload)
	if err != nil {
		return err
	}
	envelope, err := json.Marshal(harnessprotocol.EventEnvelope{
		ProtocolVersion: harnessprotocol.ProtocolVersion,
		SchemaID:        harnessprotocol.SchemaID,
		NodeID:          state.NodeID,
		Seq:             state.LastEventSeq + 1,
		Epoch:           state.Epoch,
		Type:            projection.eventType,
		EntityID:        projection.entityID,
		EntityVersion:   projection.entityVersion,
		AttemptID:       reference.AttemptID,
		DialogID:        reference.DialogID,
		ObservedAt:      timestamp(node.config.Clock()),
		Completeness:    "complete",
		Payload:         payload,
	})
	if err != nil {
		return err
	}
	return harnessprotocol.Validate("event", envelope)
}

func (node *Node) chargeSafeAdapterProjection(ctx context.Context, tx *sql.Tx, state durableState, reference harnessadapter.AttemptRef, projection adapterProjection, content harnessprotocol.SafeContent) (outputCharge, bool, error) {
	if err := node.validateAdapterProjectionEnvelope(state, reference, projection); err != nil {
		return outputCharge{}, false, err
	}
	duplicate, err := adapterProjectionExists(ctx, tx, reference.AttemptID, projection)
	if err != nil || duplicate {
		return outputCharge{}, duplicate, err
	}
	charge, err := chargeSafeOutput(ctx, tx, reference.AttemptID, content)
	return charge, false, err
}

func (node *Node) chargeAdapterProjection(ctx context.Context, tx *sql.Tx, state durableState, reference harnessadapter.AttemptRef, projection adapterProjection, bytes int64) (outputCharge, bool, error) {
	if err := node.validateAdapterProjectionEnvelope(state, reference, projection); err != nil {
		return outputCharge{}, false, err
	}
	duplicate, err := adapterProjectionExists(ctx, tx, reference.AttemptID, projection)
	if err != nil || duplicate {
		return outputCharge{}, duplicate, err
	}
	charge, err := chargeAttemptOutput(ctx, tx, reference.AttemptID, bytes)
	return charge, false, err
}

func (node *Node) appendAdapterOutputLimitMarker(ctx context.Context, tx *sql.Tx, state *durableState, reference harnessadapter.AttemptRef, source adapterProjection) error {
	messageID, err := node.newID()
	if err != nil {
		return err
	}
	content := outputLimitContent()
	encoded, err := json.Marshal(content)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO messages(message_id,dialog_id,sequence,version,role,content_json,attempt_id,finish_reason,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, messageID, reference.DialogID, state.NextMessageSequence, 1, "assistant", encoded, reference.AttemptID, "length", timestamp(node.config.Clock())); err != nil {
		return err
	}
	state.NextMessageSequence++
	state.StateVersion++
	payload := harnessprotocol.AssistantMessagePayload{MessageID: messageID, Content: content, FinishReason: "length"}
	if _, err := node.appendEvent(ctx, tx, state, "assistant.message", messageID, 1, reference.AttemptID, reference.DialogID, payload, false); err != nil {
		return err
	}
	return recordAdapterProjection(ctx, tx, state.LastEventSeq, reference.AttemptID, source)
}

func adapterProjectionExists(ctx context.Context, tx *sql.Tx, attemptID string, projection adapterProjection) (bool, error) {
	want, err := adapterProjectionDigest(projection)
	if err != nil {
		return false, err
	}
	var stored string
	err = tx.QueryRowContext(ctx, "SELECT projection_hash FROM events WHERE attempt_id=? AND projection_key=?", attemptID, projection.key).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if stored != want {
		return false, errors.New("conflicting duplicate adapter event")
	}
	return true, nil
}

func adapterProjectionHash(payload any) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func adapterProjectionDigest(projection adapterProjection) (string, error) {
	payload := projection.payload
	if projection.hashPayload != nil {
		payload = projection.hashPayload
	}
	return adapterProjectionHash(payload)
}

func recordAdapterProjection(ctx context.Context, tx *sql.Tx, eventSeq int64, attemptID string, projection adapterProjection) error {
	if projection.key == "" {
		return nil
	}
	hash, err := adapterProjectionDigest(projection)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE events SET projection_key=?,projection_hash=? WHERE seq=? AND attempt_id=? AND projection_key IS NULL`, projection.key, hash, eventSeq, attemptID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return errors.New("adapter projection event binding failed")
	}
	return nil
}

func (node *Node) archiveLateAdapterEvent(ctx context.Context, tx *sql.Tx, publication *safeTextPublication, state *durableState, event harnessadapter.Event, attemptVersion int64) error {
	return node.archiveAdapterEvent(ctx, tx, publication, state, event, attemptVersion, false, "")
}

func (node *Node) archiveAdapterEvent(ctx context.Context, tx *sql.Tx, publication *safeTextPublication, state *durableState, event harnessadapter.Event, attemptVersion int64, suppressed bool, kindOverride string) error {
	reference := event.AttemptReference()
	projection, _, err := node.prepareLateProjection(event, attemptVersion)
	if err != nil {
		return err
	}
	if err := node.validateArchivedAdapterEvent(ctx, tx, *state, event, projection); err != nil {
		return err
	}
	duplicate, err := archivedProjectionExists(ctx, tx, reference.AttemptID, projection)
	if err != nil {
		return err
	}
	if duplicate {
		return node.validateAdapterEventSafeTextReplay(ctx, tx, reference, event)
	}
	if err := node.captureAdapterEventSafeText(ctx, tx, publication, reference, event); err != nil {
		return err
	}
	charge, ledgerBytes, err := chargeArchivedAttemptOutput(ctx, tx, reference.AttemptID, archivedAdapterOutputBytes(event))
	if err != nil || (charge.Exceeded && !charge.NewlyExceeded) {
		return err
	}
	archivedProjection := projection
	archiveValue := any(event)
	if charge.NewlyExceeded {
		archivedProjection, err = node.archivedOutputLimitProjection(projection)
		if err != nil {
			return err
		}
		if err := node.validateAdapterProjectionEnvelope(*state, reference, archivedProjection); err != nil {
			return err
		}
		archiveValue = outputLimitContent()
	}
	encoded, err := json.Marshal(archiveValue)
	if err != nil {
		return err
	}
	if !suppressed {
		if _, err := node.appendEvent(ctx, tx, state, archivedProjection.eventType, archivedProjection.entityID, archivedProjection.entityVersion, reference.AttemptID, reference.DialogID, archivedProjection.payload, true); err != nil {
			return err
		}
		if err := recordAdapterProjection(ctx, tx, state.LastEventSeq, reference.AttemptID, projection); err != nil {
			return err
		}
	}
	hash, err := adapterProjectionDigest(projection)
	if err != nil {
		return err
	}
	kind := projection.eventType
	if suppressed {
		kind = "suppressed." + kind
	}
	if kindOverride != "" {
		kind = kindOverride
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO late_observations(attempt_id,generation,kind,observation_json,event_seq,observed_at,projection_key,projection_hash,output_bytes) VALUES(?,?,?,?,?,?,?,?,?)`, reference.AttemptID, reference.Generation, kind, encoded, state.LastEventSeq, timestamp(node.config.Clock()), projection.key, hash, ledgerBytes); err != nil {
		return err
	}
	if charge.NewlyExceeded {
		return node.scheduleOutputLimitStop(ctx, tx, state, reference)
	}
	return nil
}

func validateAdapterEventSafeContent(ctx context.Context, tx *sql.Tx, reference harnessadapter.AttemptRef, event harnessadapter.Event) error {
	content := harnessprotocol.SafeContent{}
	expectedCallID := ""
	bindCall := false
	switch value := event.(type) {
	case harnessadapter.AssistantDeltaEvent:
		content = value.Content
	case harnessadapter.AssistantMessageEvent:
		content = value.Content
	case harnessadapter.ToolStartedEvent:
		content, expectedCallID, bindCall = value.Input, value.CallID, true
	case harnessadapter.ToolOutputEvent:
		content, expectedCallID, bindCall = value.Output, value.CallID, true
	case harnessadapter.ToolCompletedEvent:
		content, expectedCallID, bindCall = value.Result, value.CallID, true
	case harnessadapter.InputRequestedEvent:
		content = value.Prompt
	case harnessadapter.TerminalEvent:
		if value.Output != nil {
			content = *value.Output
		}
	default:
		return nil
	}
	if content.Kind == "" {
		return nil
	}
	return validateSafeContentReference(ctx, tx, reference, content, expectedCallID, bindCall)
}

type archivedTerminalIdentity struct {
	Outcome      harnessadapter.ReconcileOutcome
	Output       *harnessprotocol.SafeContent
	Usage        *harnessprotocol.Usage
	Failure      *harnessadapter.Failure
	EffectStatus string
}

func (node *Node) prepareLateProjection(event harnessadapter.Event, attemptVersion int64) (adapterProjection, bool, error) {
	reference := event.AttemptReference()
	switch value := event.(type) {
	case harnessadapter.StartedEvent:
		payload := harnessprotocol.AttemptStartedPayload{RequestID: reference.RequestID, Generation: reference.Generation}
		return adapterProjection{eventType: "attempt.started", entityID: reference.AttemptID, entityVersion: attemptVersion, payload: payload, hashPayload: payload, key: "archive:started"}, false, nil
	case harnessadapter.WaitingEvent:
		payload := harnessprotocol.AttemptWaitingPayload{RequestID: reference.RequestID, Generation: reference.Generation, WaitKind: value.Kind}
		return adapterProjection{eventType: "attempt.waiting_input", entityID: reference.AttemptID, entityVersion: attemptVersion, payload: payload, hashPayload: payload, key: fmt.Sprintf("archive:waiting:%d", attemptVersion)}, false, nil
	case harnessadapter.AssistantDeltaEvent:
		payload := harnessprotocol.AssistantDeltaPayload{MessageID: value.MessageID, DeltaIndex: value.DeltaIndex, Content: value.Content}
		return adapterProjection{eventType: "assistant.delta", entityID: value.MessageID, entityVersion: value.DeltaIndex + 1, payload: payload, hashPayload: payload, key: fmt.Sprintf("archive:assistant.delta:%s:%d", value.MessageID, value.DeltaIndex)}, false, nil
	case harnessadapter.AssistantMessageEvent:
		payload := harnessprotocol.AssistantMessagePayload{MessageID: value.MessageID, Content: value.Content, FinishReason: value.FinishReason}
		return adapterProjection{eventType: "assistant.message", entityID: value.MessageID, entityVersion: 1, payload: payload, hashPayload: payload, key: "archive:assistant.message:" + value.MessageID}, false, nil
	case harnessadapter.ToolStartedEvent:
		payload := harnessprotocol.ToolStartedPayload{CallID: value.CallID, ToolName: value.ToolName, ActionHash: value.ActionHash, Input: value.Input}
		return adapterProjection{eventType: "tool.started", entityID: value.CallID, entityVersion: 1, payload: payload, hashPayload: payload, key: "archive:tool.started:" + value.CallID}, false, nil
	case harnessadapter.ToolOutputEvent:
		payload := harnessprotocol.ToolOutputPayload{CallID: value.CallID, ChunkIndex: value.ChunkIndex, Stream: value.Stream, Output: value.Output}
		return adapterProjection{eventType: "tool.output", entityID: value.CallID, entityVersion: value.ChunkIndex + 1, payload: payload, hashPayload: payload, key: fmt.Sprintf("archive:tool.output:%s:%d", value.CallID, value.ChunkIndex)}, false, nil
	case harnessadapter.ToolCompletedEvent:
		payload := harnessprotocol.ToolCompletedPayload{CallID: value.CallID, Status: value.Status, Result: value.Result, EffectStatus: value.EffectStatus, EffectRef: value.EffectRef}
		return adapterProjection{eventType: "tool.completed", entityID: value.CallID, entityVersion: 1, payload: payload, hashPayload: payload, key: "archive:tool.completed:" + value.CallID}, false, nil
	case harnessadapter.ApprovalRequestedEvent:
		payload := harnessprotocol.ApprovalRequestedPayload{ApprovalID: value.ApprovalID, CallID: value.CallID, ActionHash: value.ActionHash, SafePrompt: value.SafePrompt, ApprovalVersion: 1}
		return adapterProjection{eventType: "approval.requested", entityID: value.ApprovalID, entityVersion: 1, payload: payload, hashPayload: payload, key: "archive:approval.requested:" + value.ApprovalID}, false, nil
	case harnessadapter.InputRequestedEvent:
		payload := harnessprotocol.InputRequestedPayload{InputRequestID: value.InputRequestID, Prompt: value.Prompt, InputVersion: 1}
		return adapterProjection{eventType: "input.requested", entityID: value.InputRequestID, entityVersion: 1, payload: payload, hashPayload: payload, key: "archive:input.requested:" + value.InputRequestID}, false, nil
	case harnessadapter.TerminalEvent:
		effectStatus := value.EffectStatus
		if effectStatus == "" {
			effectStatus = "none"
		}
		identity := archivedTerminalIdentity{Outcome: value.Outcome, Output: value.Output, Usage: value.Usage, Failure: value.Failure, EffectStatus: effectStatus}
		switch value.Outcome {
		case harnessadapter.ReconcileCompleted:
			payload := harnessprotocol.AttemptCompletedPayload{Generation: reference.Generation, Output: harnessprotocol.AttemptOutput{Kind: "empty"}, Usage: value.Usage}
			return adapterProjection{eventType: "attempt.completed", entityID: reference.AttemptID, entityVersion: attemptVersion, payload: payload, hashPayload: identity, key: "archive:terminal"}, true, nil
		case harnessadapter.ReconcileFailed:
			if value.Failure == nil {
				return adapterProjection{}, false, errors.New("late failure is missing failure")
			}
			payload := harnessprotocol.AttemptFailedPayload{Generation: reference.Generation, FailureClass: string(value.Failure.Class), ErrorCode: value.Failure.Code, SafeMessage: value.Failure.SafeMessage, Retryable: value.Failure.Retryable, EffectStatus: effectStatus}
			return adapterProjection{eventType: "attempt.failed", entityID: reference.AttemptID, entityVersion: attemptVersion, payload: payload, hashPayload: identity, key: "archive:terminal"}, true, nil
		case harnessadapter.ReconcileInterrupted:
			payload := harnessprotocol.AttemptInterruptedPayload{Generation: reference.Generation, Reason: "provider_interrupt", EffectStatus: effectStatus}
			return adapterProjection{eventType: "attempt.interrupted", entityID: reference.AttemptID, entityVersion: attemptVersion, payload: payload, hashPayload: identity, key: "archive:terminal"}, true, nil
		}
	case harnessadapter.UnknownEvent:
		payload := harnessprotocol.AttemptUnknownPayload{Generation: reference.Generation, Reason: value.Reason, EffectStatus: value.EffectStatus}
		return adapterProjection{eventType: "attempt.unknown", entityID: reference.AttemptID, entityVersion: attemptVersion, payload: payload, hashPayload: payload, key: "archive:unknown"}, false, nil
	}
	return adapterProjection{}, false, errors.New("unsupported late adapter event")
}
