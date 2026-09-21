package node

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessbarrier"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

func (node *Node) authorizeRead(trust TrustContext) *Result {
	if trust.TransportNodeID != node.config.NodeID {
		result := node.errorResult(http.StatusNotFound, "not_found", "node was not found", "", nil, "")
		return &result
	}
	return nil
}

func (node *Node) NodeID() string { return node.config.NodeID }

// OwnerID is immutable historical namespace metadata, not caller identity.
func (node *Node) OwnerID() string { return node.config.OwnerID }

func (node *Node) Invalid(message string) Result {
	return node.errorResult(http.StatusBadRequest, "invalid", message, "", nil, "")
}

func (node *Node) wireResult(wireType string, value any) Result {
	body, err := json.Marshal(value)
	if err != nil || harnessprotocol.Validate(wireType, body) != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "durable response is invalid", "", nil, "")
	}
	return Result{HTTPStatus: http.StatusOK, Body: body}
}

func (node *Node) Snapshot(ctx context.Context, trust TrustContext) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "snapshot is unavailable", "", nil, "")
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "snapshot is unavailable", "", nil, "")
	}
	requests := make([]harnessprotocol.Request, 0, QueueCapacity)
	rows, err := tx.QueryContext(ctx, `SELECT request_id,dialog_id,input_message_id,queue_sequence,version,status FROM requests WHERE status='queued' ORDER BY queue_sequence LIMIT ?`, QueueCapacity)
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "snapshot is unavailable", "", nil, "")
	}
	for rows.Next() {
		var request harnessprotocol.Request
		if err := rows.Scan(&request.RequestID, &request.DialogID, &request.InputMessageID, &request.QueueSequence, &request.Version, &request.Status); err != nil {
			rows.Close()
			return node.errorResult(http.StatusServiceUnavailable, "not_durable", "snapshot is unavailable", "", nil, "")
		}
		requests = append(requests, request)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "snapshot is unavailable", "", nil, "")
	}
	if err := rows.Close(); err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "snapshot is unavailable", "", nil, "")
	}
	var active *harnessprotocol.Attempt
	if state.ActiveAttemptID.Valid {
		attempt := harnessprotocol.Attempt{}
		var started, finished sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT attempt_id,dialog_id,request_id,generation,version,state,effect_status,started_at,finished_at FROM attempts WHERE attempt_id=?`, state.ActiveAttemptID.String).Scan(&attempt.AttemptID, &attempt.DialogID, &attempt.RequestID, &attempt.Generation, &attempt.Version, &attempt.State, &attempt.EffectStatus, &started, &finished)
		if err != nil {
			return node.errorResult(http.StatusServiceUnavailable, "not_durable", "snapshot is inconsistent", "", nil, "")
		}
		attempt.StartedAt, attempt.FinishedAt = started.String, finished.String
		active = &attempt
	}
	if err := tx.Commit(); err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "snapshot is unavailable", "", nil, "")
	}
	return node.wireResult("snapshot", harnessprotocol.Snapshot{ProtocolVersion: harnessprotocol.ProtocolVersion, SchemaID: harnessprotocol.SchemaID, NodeID: state.NodeID, Epoch: state.Epoch, StateVersion: state.StateVersion, LastEventSeq: state.LastEventSeq, CapturedAt: timestamp(node.config.Clock()), Node: nodePayload(state), PendingQueue: requests, ActiveAttempt: active, Completeness: "complete"})
}

func (node *Node) CommandStatus(ctx context.Context, trust TrustContext, commandID string) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	if !uuidPattern.MatchString(commandID) {
		return node.errorResult(http.StatusBadRequest, "invalid", "command id is invalid", "", nil, "")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "command status is unavailable", commandID, nil, "")
	}
	defer tx.Rollback()
	outcome, found, err := loadCommandOutcome(ctx, tx, commandID)
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "command status is unavailable", commandID, nil, "")
	}
	if !found {
		return node.errorResult(http.StatusNotFound, "not_found", "command was not found", commandID, nil, "")
	}
	if deleted, lookupErr := commandOutcomeTargetsDeletedDialog(ctx, tx, outcome); lookupErr != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "command status is unavailable", commandID, nil, "")
	} else if deleted {
		return node.errorResult(http.StatusNotFound, "not_found", "command was not found", commandID, nil, "")
	}
	if !outcome.accepted {
		if harnessbarrier.Validate("rejectionReceipt", outcome.body) != nil {
			return node.errorResult(http.StatusServiceUnavailable, "not_durable", "command status is invalid", commandID, nil, "")
		}
		if err := tx.Commit(); err != nil {
			return node.errorResult(http.StatusServiceUnavailable, "not_durable", "command status is unavailable", commandID, nil, "")
		}
		return Result{HTTPStatus: outcome.status, Body: outcome.body}
	}
	var receipt harnessprotocol.Receipt
	if json.Unmarshal(outcome.body, &receipt) != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "command status is invalid", commandID, nil, "")
	}
	if err := tx.Commit(); err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "command status is unavailable", commandID, nil, "")
	}
	return node.wireResult("commandStatus", harnessprotocol.CommandStatus{ProtocolVersion: harnessprotocol.ProtocolVersion, SchemaID: harnessprotocol.SchemaID, NodeID: node.config.NodeID, CommandID: commandID, CanonicalPayloadHash: outcome.hash, Status: "accepted", Receipt: receipt})
}

func capabilityStatus(identity harnessadapter.Identity, capability harnessadapter.Capability) string {
	if identity.Verified[capability] {
		return "verified"
	}
	if identity.Declared[capability] {
		return "declared"
	}
	return "unsupported"
}

func (node *Node) Identity(ctx context.Context, trust TrustContext) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	node.mu.Lock()
	state, err := loadState(ctx, node.db)
	node.mu.Unlock()
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "identity is unavailable", "", nil, "")
	}
	capabilities := harnessprotocol.Capabilities{Chat: capabilityStatus(node.identity, harnessadapter.CapabilityChat), Events: capabilityStatus(node.identity, harnessadapter.CapabilityEvents), ToolResults: capabilityStatus(node.identity, harnessadapter.CapabilityToolResults), Cancel: capabilityStatus(node.identity, harnessadapter.CapabilityCancel), SteerAttached: capabilityStatus(node.identity, harnessadapter.CapabilitySteerAttached), SessionResume: capabilityStatus(node.identity, harnessadapter.CapabilitySessionResume), PolicyEnforcement: capabilityStatus(node.identity, harnessadapter.CapabilityPolicyEnforcement)}
	return node.wireResult("nodeIdentity", harnessprotocol.NodeIdentity{ProtocolVersion: harnessprotocol.ProtocolVersion, SchemaID: harnessprotocol.SchemaID, SchemaSHA256: harnessprotocol.SchemaSHA256, NodeID: node.config.NodeID, RegistryVersion: node.config.RegistryVersion, IdentityEpoch: state.Epoch, Adapter: harnessprotocol.AdapterIdentity{Kind: string(node.identity.Kind), Version: node.identity.Version}, Capabilities: capabilities})
}

// Admission reports only capabilities implemented by this concrete Harness.
// Replica/assets/target reservation remain false until their native producer
// paths exist; a protocol fixture may exercise the complete R10 admission flow
// without turning this runtime response into a production compatibility claim.
func (node *Node) Admission(ctx context.Context, trust TrustContext) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	node.mu.Lock()
	state, err := loadState(ctx, node.db)
	node.mu.Unlock()
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "admission profile is unavailable", "", nil, "")
	}
	profile := harnessprotocol.AdmissionProfile{
		SchemaID: harnessprotocol.AdmissionSchemaID, OwnerID: node.config.OwnerID, NodeID: node.config.NodeID,
		RegistrationRevision: node.config.RegistryVersion, IdentityEpoch: state.Epoch,
		WireSchemaSHA256: harnessprotocol.SchemaSHA256,
		Adapter:          harnessprotocol.AdapterIdentity{Kind: string(node.identity.Kind), Version: node.identity.Version},
		Readiness:        state.EngineReadiness,
		Capabilities: harnessprotocol.AdmissionCapabilities{
			Profile: true, NativeEpoch: true,
			PolicyEnforcement: node.identity.Verified[harnessadapter.CapabilityPolicyEnforcement],
			History:           true, DurableReceipts: true, ScopedQuiesce: true, OwnershipRelease: true,
		},
	}
	return node.wireResult("admissionProfile", profile)
}

func (node *Node) HealthLive() Result {
	return node.wireResult("healthLive", harnessprotocol.HealthLive{ProtocolVersion: harnessprotocol.ProtocolVersion, SchemaID: harnessprotocol.SchemaID, Status: "live", ProcessStartedAt: node.startedAt})
}

// ExecutorHeartbeat is runtime observation, not an SSE transport keepalive.
func (node *Node) ExecutorHeartbeat(ctx context.Context, trust TrustContext) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	node.mu.Lock()
	state, err := loadState(ctx, node.db)
	node.mu.Unlock()
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "executor heartbeat is unavailable", "", nil, "")
	}
	body, err := json.Marshal(struct {
		NodeID     string `json:"nodeId"`
		BootID     string `json:"bootId"`
		ObservedAt string `json:"observedAt"`
		Health     string `json:"health"`
		Readiness  string `json:"readiness"`
		Capacity   int    `json:"capacity"`
	}{node.config.NodeID, node.bootID, node.executorHeartbeatAt(), "live", state.EngineReadiness, QueueCapacity})
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "executor heartbeat is unavailable", "", nil, "")
	}
	return Result{HTTPStatus: http.StatusOK, Body: body}
}

func (node *Node) HealthReady(ctx context.Context, trust TrustContext) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	node.mu.Lock()
	state, err := loadState(ctx, node.db)
	node.mu.Unlock()
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "readiness is unavailable", "", nil, "")
	}
	identityResult := node.Identity(ctx, trust)
	if identityResult.HTTPStatus != http.StatusOK {
		return identityResult
	}
	var identity harnessprotocol.NodeIdentity
	if json.Unmarshal(identityResult.Body, &identity) != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "identity response is invalid", "", nil, "")
	}
	return node.wireResult("healthReady", harnessprotocol.HealthReady{ProtocolVersion: harnessprotocol.ProtocolVersion, SchemaID: harnessprotocol.SchemaID, CheckedAt: timestamp(node.config.Clock()), Identity: identity, Readiness: state.EngineReadiness, BlockedReasons: state.BlockedReasons})
}
