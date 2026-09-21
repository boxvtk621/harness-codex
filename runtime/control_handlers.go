package node

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

func (node *Node) applyAttemptStop(ctx context.Context, tx *sql.Tx, state *durableState, envelope harnessprotocol.CommandEnvelope) (any, string, string, postCommitAction, error) {
	target, expected, _, err := decodeParts[harnessprotocol.AttemptTarget, harnessprotocol.AttemptExpected, harnessprotocol.EmptyPayload](envelope)
	if err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	var generation, version int64
	var attemptState, dialogID, requestID string
	if err := tx.QueryRowContext(ctx, "SELECT generation,version,state,dialog_id,request_id FROM attempts WHERE attempt_id=?", target.AttemptID).Scan(&generation, &version, &attemptState, &dialogID, &requestID); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	if expected.AttemptGeneration != generation || !state.ActiveAttemptID.Valid || state.ActiveAttemptID.String != target.AttemptID {
		return nil, "", "", postCommitAction{}, stale(generation, attemptState)
	}
	if attemptState != "dispatching" && attemptState != "running" && attemptState != "waiting_input" && attemptState != "stopping" {
		return nil, "", "", postCommitAction{}, stale(generation, attemptState)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE attempts SET version=version+1,state='stopping' WHERE attempt_id=?", target.AttemptID); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	state.QueuePaused = true
	state.BlockedReasons = addReason(state.BlockedReasons, "operator_pause")
	state.QueueVersion++
	state.StateVersion++
	if _, err := node.appendEvent(ctx, tx, state, "attempt.stop_requested", target.AttemptID, version+1, target.AttemptID, dialogID, harnessprotocol.AttemptStopRequestedPayload{
		Generation: generation, CommandID: envelope.CommandID,
	}, false); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	if err := node.appendQueueEvent(ctx, tx, state); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	if err := node.appendNodeEvent(ctx, tx, state); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	return harnessprotocol.AttemptStopReferences{AttemptID: target.AttemptID}, "admitted", "operator_pause", postCommitAction{
		kind: string(envelope.Kind), attemptID: target.AttemptID, payload: mustJSON(map[string]any{"generation": generation, "dialogId": dialogID, "requestId": requestID}),
	}, nil
}

func (node *Node) applyAttemptRetry(ctx context.Context, tx *sql.Tx, state *durableState, envelope harnessprotocol.CommandEnvelope) (any, string, string, postCommitAction, error) {
	target, expected, payload, err := decodeParts[harnessprotocol.AttemptTarget, harnessprotocol.AttemptExpected, harnessprotocol.RetryPayload](envelope)
	if err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	var generation int64
	var attemptState, effectStatus, dialogID, messageID string
	if err := tx.QueryRowContext(ctx, `SELECT a.generation,a.state,a.effect_status,a.dialog_id,r.input_message_id
		FROM attempts a JOIN requests r ON r.request_id=a.request_id WHERE a.attempt_id=?`, target.AttemptID).Scan(&generation, &attemptState, &effectStatus, &dialogID, &messageID); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	if expected.AttemptGeneration != generation {
		return nil, "", "", postCommitAction{}, stale(generation, attemptState)
	}
	if attemptState != "failed" && attemptState != "interrupted" {
		return nil, "", "", postCommitAction{}, stale(generation, attemptState)
	}
	if effectStatus == "unknown" {
		return nil, "", "", postCommitAction{}, reject(http.StatusConflict, "stale", "unknown effects require reconciliation")
	}
	if effectStatus == "known" && !payload.AcknowledgeKnownEffects {
		return nil, "", "", postCommitAction{}, reject(http.StatusConflict, "stale", "known effects require acknowledgement")
	}
	if state.PendingCount >= QueueCapacity {
		return nil, "", "", postCommitAction{}, reject(http.StatusTooManyRequests, "queue_full", "pending queue is full")
	}
	var existingRequest, existingStatus string
	err = tx.QueryRowContext(ctx, `SELECT request_id,status FROM requests WHERE input_message_id=?
		AND status IN('queued','dispatching','active','unknown') ORDER BY queue_sequence LIMIT 1`, messageID).Scan(&existingRequest, &existingStatus)
	if err == nil {
		return nil, "", "", postCommitAction{}, reject(http.StatusConflict, "stale", "a retry for this input is already pending")
	}
	if !isNoRows(err) {
		return nil, "", "", postCommitAction{}, err
	}
	requestID, err := node.newID()
	if err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	now := timestamp(node.config.Clock())
	if _, err := tx.ExecContext(ctx, `INSERT INTO requests(request_id,dialog_id,input_message_id,queue_sequence,version,status,created_at,updated_at)
		VALUES(?,?,?,?,1,'queued',?,?)`, requestID, dialogID, messageID, state.NextQueueSequence, now, now); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	state.NextQueueSequence++
	state.PendingCount++
	state.QueueVersion++
	state.StateVersion++
	if err := node.appendQueueEvent(ctx, tx, state); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	if err := node.appendNodeEvent(ctx, tx, state); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	return harnessprotocol.AttemptRetryReferences{PriorAttemptID: target.AttemptID, RequestID: requestID}, "admitted", node.blockingReason(*state), postCommitAction{}, nil
}

func (node *Node) applyMessageSteer(ctx context.Context, tx *sql.Tx, state *durableState, envelope harnessprotocol.CommandEnvelope) (any, string, string, postCommitAction, error) {
	target, expected, _, err := decodeParts[harnessprotocol.SteerTarget, harnessprotocol.SteerExpected, harnessprotocol.EmptyPayload](envelope)
	if err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	var generation, attemptVersion, messageVersion int64
	var attemptState, attemptDialogID, requestID, disposition, text string
	if err := tx.QueryRowContext(ctx, "SELECT generation,version,state,dialog_id FROM attempts WHERE attempt_id=?", target.AttemptID).Scan(&generation, &attemptVersion, &attemptState, &attemptDialogID); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT version,disposition,request_id,text FROM messages WHERE message_id=? AND dialog_id=?", target.MessageID, target.DialogID).Scan(&messageVersion, &disposition, &requestID, &text); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	if generation != expected.AttemptGeneration || messageVersion != expected.MessageVersion || attemptDialogID != target.DialogID || !state.ActiveAttemptID.Valid || state.ActiveAttemptID.String != target.AttemptID {
		return nil, "", "", postCommitAction{}, stale(generation, attemptState)
	}
	if disposition != "queued" || (attemptState != "running" && attemptState != "waiting_input") {
		return nil, "", "", postCommitAction{}, stale(messageVersion, disposition)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE messages SET version=version+1,disposition='steer_pending' WHERE message_id=?", target.MessageID); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	state.QueueVersion++
	state.StateVersion++
	if _, err := node.appendEvent(ctx, tx, state, "message.disposition_changed", target.MessageID, messageVersion+1, "", "", harnessprotocol.MessageDispositionPayload{
		MessageID: target.MessageID, From: "queued", To: "steer_pending", ReasonCode: "steer_requested",
	}, false); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	if err := node.appendQueueEvent(ctx, tx, state); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	return harnessprotocol.MessageSteerReferences{DialogID: target.DialogID, MessageID: target.MessageID, AttemptID: target.AttemptID}, "admitted", "", postCommitAction{
		kind: string(envelope.Kind), attemptID: target.AttemptID, messageID: target.MessageID,
		payload: mustJSON(map[string]any{"generation": generation, "dialogId": target.DialogID, "requestId": requestID, "text": text}),
	}, nil
}

func (node *Node) applyApproval(ctx context.Context, tx *sql.Tx, state *durableState, trust TrustContext, envelope harnessprotocol.CommandEnvelope) (any, string, string, postCommitAction, error) {
	target, expected, payload, err := decodeParts[harnessprotocol.ApprovalTarget, harnessprotocol.ApprovalExpected, harnessprotocol.ApprovalPayload](envelope)
	if err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	var version, generation int64
	var status, actionHash, dialogID, requestID, callID string
	if err := tx.QueryRowContext(ctx, `SELECT p.version,p.status,p.action_hash,p.call_id,a.generation,a.dialog_id,a.request_id
		FROM approvals p JOIN attempts a ON a.attempt_id=p.attempt_id WHERE p.approval_id=? AND p.attempt_id=?`, target.ApprovalID, target.AttemptID).Scan(&version, &status, &actionHash, &callID, &generation, &dialogID, &requestID); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	if version != expected.ApprovalVersion || generation != expected.AttemptGeneration || status != "pending" || actionHash != payload.ActionHash {
		return nil, "", "", postCommitAction{}, stale(version, status)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE approvals SET version=version+1,status='responding',decision=?,actor_id=? WHERE approval_id=?", payload.Decision, trust.ActorID, target.ApprovalID); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	return harnessprotocol.ApprovalRespondReferences{ApprovalID: target.ApprovalID, AttemptID: target.AttemptID}, "admitted", "", postCommitAction{
		kind: string(envelope.Kind), attemptID: target.AttemptID, actorID: trust.ActorID,
		payload: mustJSON(map[string]any{"generation": generation, "dialogId": dialogID, "requestId": requestID, "approvalId": target.ApprovalID, "approvalVersion": version + 1, "callId": callID, "actionHash": actionHash, "decision": payload.Decision}),
	}, nil
}

func (node *Node) applyInput(ctx context.Context, tx *sql.Tx, state *durableState, trust TrustContext, envelope harnessprotocol.CommandEnvelope) (any, string, string, postCommitAction, error) {
	target, expected, payload, err := decodeParts[harnessprotocol.InputTarget, harnessprotocol.InputExpected, harnessprotocol.MessagePayload](envelope)
	if err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	var version, generation int64
	var status, dialogID, requestID string
	if err := tx.QueryRowContext(ctx, `SELECT i.version,i.status,a.generation,a.dialog_id,a.request_id
		FROM input_requests i JOIN attempts a ON a.attempt_id=i.attempt_id WHERE i.input_request_id=? AND i.attempt_id=?`, target.InputRequestID, target.AttemptID).Scan(&version, &status, &generation, &dialogID, &requestID); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	if version != expected.InputVersion || generation != expected.AttemptGeneration || status != "pending" {
		return nil, "", "", postCommitAction{}, stale(version, status)
	}
	messageID, err := node.newID()
	if err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	now := timestamp(node.config.Clock())
	if _, err := tx.ExecContext(ctx, `INSERT INTO messages(message_id,dialog_id,sequence,version,role,text,disposition,command_id,request_id,attempt_id,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`, messageID, dialogID, state.NextMessageSequence, 1, "user", payload.Text, "applied", envelope.CommandID, requestID, target.AttemptID, now); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE input_requests SET version=version+1,status='responding',response_message_id=? WHERE input_request_id=?", messageID, target.InputRequestID); err != nil {
		return nil, "", "", postCommitAction{}, err
	}
	state.NextMessageSequence++
	return harnessprotocol.InputRespondReferences{InputRequestID: target.InputRequestID, AttemptID: target.AttemptID, MessageID: messageID}, "admitted", "", postCommitAction{
		kind: string(envelope.Kind), attemptID: target.AttemptID, messageID: messageID, actorID: trust.ActorID,
		payload: mustJSON(map[string]any{"generation": generation, "dialogId": dialogID, "requestId": requestID, "inputRequestId": target.InputRequestID, "inputVersion": version + 1, "text": payload.Text}),
	}, nil
}

func mustJSON(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}
