package node

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/strictjson"
)

// CompletedApprovalRaceProof identifies the exact durable records produced by
// the Codex approval acknowledgement race fixed after v0.2.0-rc.6. It is not a
// general unknown-state override: every identifier, version and action hash is
// fenced and the provider adapter must independently confirm a terminal native
// turn from an earlier process generation.
type CompletedApprovalRaceProof struct {
	Attempt                 harnessadapter.AttemptRef
	ExpectedAttemptVersion  int64
	ApprovalID              string
	ExpectedApprovalVersion int64
	Decision                string
	CallID                  string
	ExpectedToolVersion     int64
	ActionHash              string
	CommandID               string
	AssistantMessageID      string
}

type completedApprovalRaceVerifier interface {
	ConfirmCompletedApprovalRace(context.Context, harnessadapter.AttemptRef) error
}

// RecoverCompletedApprovalRace repairs only the historical state in which an
// approval response lost its acknowledgement after the exact tool and native
// turn had already completed. Durable Harness evidence is checked
// again under the write transaction after the adapter confirmation. The method
// is idempotent for the exact completed projection.
func (node *Node) RecoverCompletedApprovalRace(ctx context.Context, proof CompletedApprovalRaceProof) error {
	if err := validateCompletedApprovalRaceProof(node.config.NodeID, proof); err != nil {
		return err
	}
	verifier, ok := node.config.Adapter.(completedApprovalRaceVerifier)
	if !ok {
		return errors.New("adapter does not support approval race recovery")
	}
	if err := verifier.ConfirmCompletedApprovalRace(ctx, proof.Attempt); err != nil {
		return err
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
	evidence, already, err := verifyCompletedApprovalRace(ctx, tx, state, proof)
	if err != nil || already {
		return err
	}

	decision := completedApprovalRaceDecision(proof)
	result, err := tx.ExecContext(ctx, `UPDATE approvals SET status='resolved'
		WHERE approval_id=? AND attempt_id=? AND version=? AND status='unknown'
		AND call_id=? AND action_hash=? AND decision=? AND actor_id=?`,
		proof.ApprovalID, proof.Attempt.AttemptID, proof.ExpectedApprovalVersion,
		proof.CallID, proof.ActionHash, decision, evidence.actorID)
	if err != nil || !changedExactlyOne(result) {
		if err == nil {
			err = errors.New("approval race fence changed")
		}
		return err
	}
	result, err = tx.ExecContext(ctx, `UPDATE control_actions SET status='acknowledged'
		WHERE command_id=? AND kind=? AND attempt_id=? AND actor_id=? AND status='unknown'`,
		proof.CommandID, string(harnessprotocol.CommandApprovalRespond),
		proof.Attempt.AttemptID, evidence.actorID)
	if err != nil || !changedExactlyOne(result) {
		if err == nil {
			err = errors.New("approval control fence changed")
		}
		return err
	}
	if _, err := node.appendEvent(ctx, tx, &state, "approval.resolved", proof.ApprovalID,
		proof.ExpectedApprovalVersion, proof.Attempt.AttemptID, proof.Attempt.DialogID,
		harnessprotocol.ApprovalResolvedPayload{
			ApprovalID: proof.ApprovalID, Decision: decision,
			ActorID:         harnessprotocol.ActorID(evidence.actorID),
			ApprovalVersion: proof.ExpectedApprovalVersion,
		}, false); err != nil {
		return err
	}
	if unresolved, err := unresolvedReconciliationEffects(ctx, tx, proof.Attempt.AttemptID); err != nil {
		return err
	} else if unresolved {
		return errors.New("approval race recovery has unresolved effects")
	}
	effectStatus := "known"
	if decision == "deny" {
		effectStatus = "none"
	}
	terminal, wake, err := node.projectAdapterEvent(ctx, tx, nil, &state, proof.Attempt,
		proof.ExpectedAttemptVersion, "unknown", harnessadapter.TerminalEvent{
			EventBase: harnessadapter.EventBase{Attempt: proof.Attempt},
			Outcome:   harnessadapter.ReconcileCompleted, EffectStatus: effectStatus,
		})
	if err != nil {
		return err
	}
	if !terminal {
		return errors.New("approval race recovery did not produce a terminal projection")
	}
	if err := saveState(ctx, tx, state); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	node.cancelAttemptStream(proof.Attempt)
	if terminal || wake {
		node.afterCommit(context.Background(), postCommitAction{})
	}
	return nil
}

type completedApprovalRaceEvidence struct {
	actorID string
}

func verifyCompletedApprovalRace(ctx context.Context, tx *sql.Tx, state durableState, proof CompletedApprovalRaceProof) (completedApprovalRaceEvidence, bool, error) {
	decision := completedApprovalRaceDecision(proof)
	effectStatusWant := "known"
	if decision == "deny" {
		effectStatusWant = "none"
	}
	var attemptVersion int64
	var attemptState, effectStatus, requestStatus string
	if err := tx.QueryRowContext(ctx, `SELECT a.version,a.state,a.effect_status,r.status
		FROM attempts a JOIN requests r ON r.request_id=a.request_id
		WHERE a.attempt_id=? AND a.dialog_id=? AND a.request_id=? AND a.generation=?`,
		proof.Attempt.AttemptID, proof.Attempt.DialogID, proof.Attempt.RequestID,
		proof.Attempt.Generation).Scan(&attemptVersion, &attemptState, &effectStatus, &requestStatus); err != nil {
		return completedApprovalRaceEvidence{}, false, err
	}
	already := attemptVersion == proof.ExpectedAttemptVersion+1 && attemptState == "completed" &&
		effectStatus == effectStatusWant && requestStatus == "completed" && !state.ActiveAttemptID.Valid &&
		!slicesContains(state.BlockedReasons, "execution_unknown")
	pending := attemptVersion == proof.ExpectedAttemptVersion && attemptState == "unknown" &&
		effectStatus == "unknown" && requestStatus == "unknown" && state.ActiveAttemptID.Valid &&
		state.ActiveAttemptID.String == proof.Attempt.AttemptID && state.PendingCount == 0 &&
		slicesContains(state.BlockedReasons, "execution_unknown")
	if !pending && !already {
		return completedApprovalRaceEvidence{}, false, errors.New("approval race attempt fence does not match")
	}

	var approvalCallID, approvalHash, approvalStatus, observedDecision string
	var approvalVersion int64
	var approvalActor sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT call_id,action_hash,version,status,decision,actor_id
		FROM approvals WHERE approval_id=? AND attempt_id=?`, proof.ApprovalID,
		proof.Attempt.AttemptID).Scan(&approvalCallID, &approvalHash, &approvalVersion,
		&approvalStatus, &observedDecision, &approvalActor); err != nil {
		return completedApprovalRaceEvidence{}, false, err
	}
	expectedApprovalStatus := "unknown"
	if already {
		expectedApprovalStatus = "resolved"
	}
	if approvalCallID != proof.CallID || approvalHash != proof.ActionHash ||
		approvalVersion != proof.ExpectedApprovalVersion || approvalStatus != expectedApprovalStatus ||
		observedDecision != decision || !approvalActor.Valid || approvalActor.String == "" {
		return completedApprovalRaceEvidence{}, false, errors.New("approval race approval evidence does not match")
	}

	var actionKind, actionAttemptID, actionStatus string
	var actionActor sql.NullString
	var actionPayloadJSON []byte
	if err := tx.QueryRowContext(ctx, `SELECT kind,attempt_id,actor_id,payload,status
		FROM control_actions WHERE command_id=?`, proof.CommandID).Scan(&actionKind,
		&actionAttemptID, &actionActor, &actionPayloadJSON, &actionStatus); err != nil {
		return completedApprovalRaceEvidence{}, false, err
	}
	expectedActionStatus := "unknown"
	if already {
		expectedActionStatus = "acknowledged"
	}
	if actionKind != string(harnessprotocol.CommandApprovalRespond) ||
		actionAttemptID != proof.Attempt.AttemptID || !actionActor.Valid ||
		actionActor.String != approvalActor.String || actionStatus != expectedActionStatus ||
		!strictjson.Valid(actionPayloadJSON) {
		return completedApprovalRaceEvidence{}, false, errors.New("approval race control evidence does not match")
	}
	var action actionPayload
	var actionKeys map[string]json.RawMessage
	if json.Unmarshal(actionPayloadJSON, &action) != nil || json.Unmarshal(actionPayloadJSON, &actionKeys) != nil || len(actionKeys) != 8 ||
		action.Generation != proof.Attempt.Generation || action.DialogID != proof.Attempt.DialogID ||
		action.RequestID != proof.Attempt.RequestID || action.ApprovalID != proof.ApprovalID ||
		action.ApprovalVersion != proof.ExpectedApprovalVersion || action.CallID != proof.CallID ||
		action.ActionHash != proof.ActionHash || action.Decision != decision {
		return completedApprovalRaceEvidence{}, false, errors.New("approval race control payload does not match")
	}

	var commandActor, commandKind string
	var commandJSON []byte
	if err := tx.QueryRowContext(ctx, `SELECT actor_id,kind,canonical_json FROM commands WHERE command_id=?`,
		proof.CommandID).Scan(&commandActor, &commandKind, &commandJSON); err != nil {
		return completedApprovalRaceEvidence{}, false, err
	}
	decoded, err := harnessprotocol.DecodeCommand(commandJSON)
	command, ok := decoded.(harnessprotocol.ApprovalRespondCommand)
	if err != nil || !ok || commandActor != approvalActor.String ||
		commandKind != string(harnessprotocol.CommandApprovalRespond) ||
		command.Envelope.CommandID != proof.CommandID || command.Target.NodeID != proof.Attempt.NodeID ||
		command.Target.AttemptID != proof.Attempt.AttemptID || command.Target.ApprovalID != proof.ApprovalID ||
		command.Expected.AttemptGeneration != proof.Attempt.Generation ||
		command.Expected.ApprovalVersion+1 != proof.ExpectedApprovalVersion ||
		command.Payload.Decision != decision || command.Payload.ActionHash != proof.ActionHash {
		return completedApprovalRaceEvidence{}, false, errors.New("approval race command evidence does not match")
	}

	var toolVersion int64
	var toolStatus string
	var effectRef sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT version,status,effect_ref FROM tool_calls
		WHERE call_id=? AND attempt_id=? AND action_hash=?`, proof.CallID,
		proof.Attempt.AttemptID, proof.ActionHash).Scan(&toolVersion, &toolStatus, &effectRef); err != nil {
		return completedApprovalRaceEvidence{}, false, err
	}
	toolMatches := toolVersion == proof.ExpectedToolVersion
	if decision == "allow_once" {
		toolMatches = toolMatches && toolStatus == "succeeded" && effectRef.Valid && effectRef.String == proof.ActionHash
	} else {
		toolMatches = toolMatches && toolStatus == "failed" && !effectRef.Valid
	}
	if !toolMatches {
		return completedApprovalRaceEvidence{}, false, errors.New("approval race tool evidence does not match")
	}

	var messageCount int
	var messageContent []byte
	var finishReason string
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),MAX(content_json),MAX(finish_reason)
		FROM messages WHERE attempt_id=? AND role='assistant' AND message_id=?`,
		proof.Attempt.AttemptID, proof.AssistantMessageID).Scan(&messageCount,
		&messageContent, &finishReason); err != nil {
		return completedApprovalRaceEvidence{}, false, err
	}
	var attemptAssistantCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM messages
		WHERE attempt_id=? AND role='assistant'`, proof.Attempt.AttemptID).Scan(&attemptAssistantCount); err != nil {
		return completedApprovalRaceEvidence{}, false, err
	}
	var lastAssistantID string
	if err := tx.QueryRowContext(ctx, `SELECT message_id FROM messages
		WHERE attempt_id=? AND role='assistant' ORDER BY sequence DESC LIMIT 1`,
		proof.Attempt.AttemptID).Scan(&lastAssistantID); err != nil {
		return completedApprovalRaceEvidence{}, false, err
	}
	assistantCountMatches := attemptAssistantCount == 1
	if decision == "deny" {
		assistantCountMatches = attemptAssistantCount >= 1
	}
	var content harnessprotocol.SafeContent
	if messageCount != 1 || !assistantCountMatches || lastAssistantID != proof.AssistantMessageID || finishReason != "complete" ||
		json.Unmarshal(messageContent, &content) != nil || content.Kind == "unavailable" {
		return completedApprovalRaceEvidence{}, false, errors.New("approval race assistant evidence does not match")
	}

	if err := verifyCompletedApprovalRaceEvents(ctx, tx, proof, already); err != nil {
		return completedApprovalRaceEvidence{}, false, err
	}
	if !already {
		var otherUnresolved int
		if err := tx.QueryRowContext(ctx, `SELECT
			(SELECT COUNT(*) FROM control_actions WHERE attempt_id=? AND status IN('pending','inflight','unknown') AND command_id<>?) +
			(SELECT COUNT(*) FROM approvals WHERE attempt_id=? AND status IN('pending','responding','unknown') AND approval_id<>?) +
			(SELECT COUNT(*) FROM input_requests WHERE attempt_id=? AND status IN('pending','responding','unknown')) +
			(SELECT COUNT(*) FROM tool_calls WHERE attempt_id=? AND status='running') +
			(SELECT COUNT(*) FROM late_observations WHERE attempt_id=?)`,
			proof.Attempt.AttemptID, proof.CommandID, proof.Attempt.AttemptID,
			proof.ApprovalID, proof.Attempt.AttemptID, proof.Attempt.AttemptID,
			proof.Attempt.AttemptID).Scan(&otherUnresolved); err != nil {
			return completedApprovalRaceEvidence{}, false, err
		}
		if otherUnresolved != 0 {
			return completedApprovalRaceEvidence{}, false, errors.New("approval race has other unresolved effects")
		}
	}
	return completedApprovalRaceEvidence{actorID: approvalActor.String}, already, nil
}

func verifyCompletedApprovalRaceEvents(ctx context.Context, tx *sql.Tx, proof CompletedApprovalRaceProof, already bool) error {
	decision := completedApprovalRaceDecision(proof)
	rows, err := tx.QueryContext(ctx, `SELECT event_json FROM events WHERE attempt_id=? ORDER BY seq`, proof.Attempt.AttemptID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var approvalSeq, toolSeq, unknownSeq, assistantSeq, resolvedSeq, completedSeq int64
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return err
		}
		event, err := harnessprotocol.DecodeEvent(encoded)
		if err != nil || event.Envelope.AttemptID != proof.Attempt.AttemptID || event.Envelope.DialogID != proof.Attempt.DialogID {
			return errors.New("approval race event evidence is invalid")
		}
		switch payload := event.Payload.(type) {
		case *harnessprotocol.ApprovalRequestedPayload:
			if payload.ApprovalID == proof.ApprovalID && payload.CallID == proof.CallID && payload.ActionHash == proof.ActionHash && payload.ApprovalVersion+1 == proof.ExpectedApprovalVersion {
				if approvalSeq != 0 {
					return errors.New("approval race has duplicate approval evidence")
				}
				approvalSeq = event.Envelope.Seq
			}
		case *harnessprotocol.ToolCompletedPayload:
			matches := payload.CallID == proof.CallID
			if decision == "allow_once" {
				matches = matches && payload.Status == "succeeded" && payload.EffectStatus == "known" && payload.EffectRef == proof.ActionHash
			} else {
				matches = matches && payload.Status == "failed" && payload.EffectStatus == "none" && payload.EffectRef == ""
			}
			if matches {
				if toolSeq != 0 {
					return errors.New("approval race has duplicate tool evidence")
				}
				toolSeq = event.Envelope.Seq
			}
		case *harnessprotocol.AttemptUnknownPayload:
			if payload.Generation == proof.Attempt.Generation && payload.Reason == "provider_state" && payload.EffectStatus == "unknown" {
				unknownSeq = event.Envelope.Seq
			}
		case *harnessprotocol.AssistantMessagePayload:
			if payload.MessageID == proof.AssistantMessageID && payload.FinishReason == "complete" {
				if assistantSeq != 0 {
					return errors.New("approval race has duplicate assistant evidence")
				}
				assistantSeq = event.Envelope.Seq
			}
		case *harnessprotocol.ApprovalResolvedPayload:
			if payload.ApprovalID == proof.ApprovalID && payload.Decision == decision && payload.ApprovalVersion == proof.ExpectedApprovalVersion {
				resolvedSeq = event.Envelope.Seq
			}
		case *harnessprotocol.AttemptCompletedPayload:
			if payload.Generation == proof.Attempt.Generation && payload.Output.Kind == "message" && payload.Output.AssistantMessageID == proof.AssistantMessageID {
				completedSeq = event.Envelope.Seq
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	preRecoveryOrderMatches := approvalSeq > 0 && toolSeq > approvalSeq
	if decision == "allow_once" {
		preRecoveryOrderMatches = preRecoveryOrderMatches && unknownSeq > toolSeq && assistantSeq > unknownSeq
	} else {
		preRecoveryOrderMatches = preRecoveryOrderMatches && assistantSeq > toolSeq && unknownSeq > assistantSeq
	}
	if !preRecoveryOrderMatches {
		return errors.New("approval race event order does not match")
	}
	if already {
		if !(resolvedSeq > assistantSeq && completedSeq > resolvedSeq) {
			return errors.New("approval race completion evidence does not match")
		}
	} else if resolvedSeq != 0 || completedSeq != 0 {
		return errors.New("approval race already has conflicting terminal evidence")
	}
	return nil
}

func validateCompletedApprovalRaceProof(nodeID string, proof CompletedApprovalRaceProof) error {
	decision := completedApprovalRaceDecision(proof)
	if proof.Attempt.NodeID != nodeID || (decision != "allow_once" && decision != "deny") || !uuidPattern.MatchString(proof.Attempt.DialogID) ||
		!uuidPattern.MatchString(proof.Attempt.RequestID) || !uuidPattern.MatchString(proof.Attempt.AttemptID) ||
		proof.Attempt.Generation < 1 || proof.ExpectedAttemptVersion < 1 ||
		!uuidPattern.MatchString(proof.ApprovalID) || proof.ExpectedApprovalVersion < 2 ||
		!uuidPattern.MatchString(proof.CallID) || proof.ExpectedToolVersion < 2 ||
		!uuidPattern.MatchString(proof.CommandID) || !uuidPattern.MatchString(proof.AssistantMessageID) ||
		!validLowerSHA256(proof.ActionHash) {
		return errors.New("approval race proof is invalid")
	}
	return nil
}

func completedApprovalRaceDecision(proof CompletedApprovalRaceProof) string {
	if proof.Decision == "" {
		return "allow_once"
	}
	return proof.Decision
}

func validLowerSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}

func changedExactlyOne(result sql.Result) bool {
	changed, err := result.RowsAffected()
	return err == nil && changed == 1
}
