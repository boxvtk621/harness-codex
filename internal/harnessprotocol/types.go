// Package harnessprotocol defines the pure, versioned Harness wire contract.
// It performs shape validation only and owns no authorization, state or storage.
package harnessprotocol

import "encoding/json"

const (
	ProtocolVersion      = 1
	SchemaID             = "harness-wire-v2"
	AdmissionSchemaID    = "harness-admission-v1"
	SchemaSHA256         = "5bd97f2ea08854a8e56d46ff11a1539e6bc54e8ca6d42841b366561accba73d9"
	MaximumSafeInteger   = int64(1<<53 - 1)
	MaximumMessageBytes  = 64 * 1024
	MaximumPageSize      = 100
	MaximumCursorBytes   = 512
	MaximumArtifactBytes = 16 * 1024 * 1024
	MaximumWireBytes     = 8 * 1024 * 1024

	ExpectedNodeIDHeader         = "X-Harness-Expected-Node-ID"
	ExpectedRegistryHeader       = "X-Harness-Expected-Registry-Version"
	ExpectedEpochHeader          = "X-Harness-Expected-Identity-Epoch"
	ExpectedAdapterKindHeader    = "X-Harness-Expected-Adapter-Kind"
	ExpectedAdapterVersionHeader = "X-Harness-Expected-Adapter-Version"
)

// IsAdmissionCommand identifies commands that create new executable work. It is
// shared by the authoritative Harness admission path and the non-authoritative
// Router so the two boundaries cannot silently classify assignments differently.
func IsAdmissionCommand(kind CommandKind) bool {
	return kind == CommandDialogCreate || kind == CommandMessageEnqueue || kind == CommandAttemptRetry
}

// IsDrainBlockedCommand also includes queue.resume: resuming a durable queue can
// start work and therefore cannot cross a deployment drain barrier.
func IsDrainBlockedCommand(kind CommandKind) bool {
	return IsAdmissionCommand(kind) || kind == CommandQueueResume
}

// IsDrainControlCommand is an explicit allowlist. Unknown future mutations are
// therefore fenced by default until their drain semantics are reviewed.
func IsDrainControlCommand(kind CommandKind) bool {
	switch kind {
	case CommandMessageSteer, CommandRequestCancel, CommandAttemptStop, CommandApprovalRespond, CommandInputRespond:
		return true
	default:
		return false
	}
}

// ActorID is a bounded server-derived identity such as a YouTrack user ID.
// Harness entity IDs are canonical UUIDs; actor identities intentionally are not.
type ActorID string

type CommandKind string

const (
	CommandDialogCreate    CommandKind = "dialog.create"
	CommandDialogDelete    CommandKind = "dialog.delete"
	CommandMessageEnqueue  CommandKind = "message.enqueue"
	CommandMessageSteer    CommandKind = "message.steer"
	CommandRequestCancel   CommandKind = "request.cancel"
	CommandAttemptStop     CommandKind = "attempt.stop"
	CommandQueueResume     CommandKind = "queue.resume"
	CommandAttemptRetry    CommandKind = "attempt.retry"
	CommandApprovalRespond CommandKind = "approval.respond"
	CommandInputRespond    CommandKind = "input.respond"
)

type CommandEnvelope struct {
	ProtocolVersion int             `json:"protocolVersion"`
	SchemaID        string          `json:"schemaId"`
	CommandID       string          `json:"commandId"`
	Kind            CommandKind     `json:"kind"`
	Target          json.RawMessage `json:"target"`
	Expected        json.RawMessage `json:"expected"`
	Payload         json.RawMessage `json:"payload"`
}

type NodeTarget struct {
	NodeID string `json:"nodeId"`
}
type DialogTarget struct {
	NodeID   string `json:"nodeId"`
	DialogID string `json:"dialogId"`
}
type SteerTarget struct {
	NodeID    string `json:"nodeId"`
	DialogID  string `json:"dialogId"`
	AttemptID string `json:"attemptId"`
	MessageID string `json:"messageId"`
}
type RequestTarget struct {
	NodeID    string `json:"nodeId"`
	RequestID string `json:"requestId"`
}
type AttemptTarget struct {
	NodeID    string `json:"nodeId"`
	AttemptID string `json:"attemptId"`
}
type ApprovalTarget struct {
	NodeID     string `json:"nodeId"`
	ApprovalID string `json:"approvalId"`
	AttemptID  string `json:"attemptId"`
}
type InputTarget struct {
	NodeID         string `json:"nodeId"`
	InputRequestID string `json:"inputRequestId"`
	AttemptID      string `json:"attemptId"`
}

type RegistryExpected struct {
	RegistryVersion int64 `json:"registryVersion"`
}
type DialogExpected struct {
	DialogVersion int64 `json:"dialogVersion"`
}
type SteerExpected struct {
	AttemptGeneration int64 `json:"attemptGeneration"`
	MessageVersion    int64 `json:"messageVersion"`
}
type RequestExpected struct {
	RequestVersion int64 `json:"requestVersion"`
}
type AttemptExpected struct {
	AttemptGeneration int64 `json:"attemptGeneration"`
}
type QueueExpected struct {
	QueueVersion int64 `json:"queueVersion"`
}
type ApprovalExpected struct {
	ApprovalVersion   int64 `json:"approvalVersion"`
	AttemptGeneration int64 `json:"attemptGeneration"`
}
type InputExpected struct {
	InputVersion      int64 `json:"inputVersion"`
	AttemptGeneration int64 `json:"attemptGeneration"`
}

type DialogCreatePayload struct {
	Title string `json:"title,omitempty"`
}
type MessagePayload struct {
	Text string `json:"text"`
}
type EmptyPayload struct{}
type RetryPayload struct {
	AcknowledgeKnownEffects bool `json:"acknowledgeKnownEffects"`
}
type ApprovalPayload struct {
	Decision   string `json:"decision"`
	ActionHash string `json:"actionHash"`
}

type DialogCreateCommand struct {
	Envelope CommandEnvelope
	Target   NodeTarget
	Expected RegistryExpected
	Payload  DialogCreatePayload
}
type DialogDeleteCommand struct {
	Envelope CommandEnvelope
	Target   DialogTarget
	Expected DialogExpected
	Payload  EmptyPayload
}
type MessageEnqueueCommand struct {
	Envelope CommandEnvelope
	Target   DialogTarget
	Expected DialogExpected
	Payload  MessagePayload
}
type MessageSteerCommand struct {
	Envelope CommandEnvelope
	Target   SteerTarget
	Expected SteerExpected
	Payload  EmptyPayload
}
type RequestCancelCommand struct {
	Envelope CommandEnvelope
	Target   RequestTarget
	Expected RequestExpected
	Payload  EmptyPayload
}
type AttemptStopCommand struct {
	Envelope CommandEnvelope
	Target   AttemptTarget
	Expected AttemptExpected
	Payload  EmptyPayload
}
type QueueResumeCommand struct {
	Envelope CommandEnvelope
	Target   NodeTarget
	Expected QueueExpected
	Payload  EmptyPayload
}
type AttemptRetryCommand struct {
	Envelope CommandEnvelope
	Target   AttemptTarget
	Expected AttemptExpected
	Payload  RetryPayload
}
type ApprovalRespondCommand struct {
	Envelope CommandEnvelope
	Target   ApprovalTarget
	Expected ApprovalExpected
	Payload  ApprovalPayload
}
type InputRespondCommand struct {
	Envelope CommandEnvelope
	Target   InputTarget
	Expected InputExpected
	Payload  MessagePayload
}

type Receipt struct {
	ProtocolVersion int             `json:"protocolVersion"`
	SchemaID        string          `json:"schemaId"`
	CommandID       string          `json:"commandId"`
	CommandKind     CommandKind     `json:"commandKind"`
	ReceiptID       string          `json:"receiptId"`
	AcceptedAt      string          `json:"acceptedAt"`
	NodeID          string          `json:"nodeId"`
	EventSeq        int64           `json:"eventSeq"`
	Result          string          `json:"result"`
	BlockingReason  string          `json:"blockingReason,omitempty"`
	References      json.RawMessage `json:"references"`
}

type DialogCreateReferences struct {
	DialogID string `json:"dialogId"`
}
type DialogDeleteReferences struct {
	DialogID string `json:"dialogId"`
}
type MessageEnqueueReferences struct {
	DialogID  string `json:"dialogId"`
	MessageID string `json:"messageId"`
	RequestID string `json:"requestId"`
}
type MessageSteerReferences struct {
	DialogID  string `json:"dialogId"`
	MessageID string `json:"messageId"`
	AttemptID string `json:"attemptId"`
}
type RequestCancelReferences struct {
	RequestID string `json:"requestId"`
}
type AttemptStopReferences struct {
	AttemptID string `json:"attemptId"`
}
type QueueResumeReferences struct {
	NodeID string `json:"nodeId"`
}
type AttemptRetryReferences struct {
	PriorAttemptID string `json:"priorAttemptId"`
	RequestID      string `json:"requestId"`
}
type ApprovalRespondReferences struct {
	ApprovalID string `json:"approvalId"`
	AttemptID  string `json:"attemptId"`
}
type InputRespondReferences struct {
	InputRequestID string `json:"inputRequestId"`
	AttemptID      string `json:"attemptId"`
	MessageID      string `json:"messageId"`
}

type Error struct {
	ProtocolVersion int    `json:"protocolVersion"`
	SchemaID        string `json:"schemaId"`
	Code            string `json:"code"`
	SafeMessage     string `json:"safeMessage"`
	Retryable       bool   `json:"retryable"`
	CorrelationID   string `json:"correlationId"`
	CurrentVersion  *int64 `json:"currentVersion,omitempty"`
	CurrentState    string `json:"currentState,omitempty"`
}

type NodeState struct {
	TransportAvailability string   `json:"transportAvailability"`
	EngineReadiness       string   `json:"engineReadiness"`
	Occupancy             string   `json:"occupancy"`
	QueuePaused           bool     `json:"queuePaused"`
	QueueVersion          int64    `json:"queueVersion"`
	PendingCount          int64    `json:"pendingCount"`
	BlockedReasons        []string `json:"blockedReasons"`
	ActiveAttemptID       *string  `json:"activeAttemptId"`
}

type DialogSummary struct {
	DialogID  string `json:"dialogId"`
	Version   int64  `json:"version"`
	Title     string `json:"title,omitempty"`
	CreatedAt string `json:"createdAt"`
}
type UserHistoryItem struct {
	MessageID   string `json:"messageId"`
	Role        string `json:"role"`
	DialogID    string `json:"dialogId"`
	Sequence    int64  `json:"sequence"`
	Version     int64  `json:"version"`
	CreatedAt   string `json:"createdAt"`
	Text        string `json:"text"`
	Disposition string `json:"disposition"`
	CommandID   string `json:"commandId"`
	RequestID   string `json:"requestId"`
}
type AssistantHistoryItem struct {
	MessageID    string      `json:"messageId"`
	Role         string      `json:"role"`
	DialogID     string      `json:"dialogId"`
	Sequence     int64       `json:"sequence"`
	Version      int64       `json:"version"`
	CreatedAt    string      `json:"createdAt"`
	AttemptID    string      `json:"attemptId"`
	Content      SafeContent `json:"content"`
	FinishReason string      `json:"finishReason"`
}
type Request struct {
	RequestID      string `json:"requestId"`
	DialogID       string `json:"dialogId"`
	InputMessageID string `json:"inputMessageId"`
	QueueSequence  int64  `json:"queueSequence"`
	Version        int64  `json:"version"`
	Status         string `json:"status"`
}
type Attempt struct {
	AttemptID    string `json:"attemptId"`
	DialogID     string `json:"dialogId"`
	RequestID    string `json:"requestId"`
	Generation   int64  `json:"generation"`
	Version      int64  `json:"version"`
	State        string `json:"state"`
	EffectStatus string `json:"effectStatus"`
	StartedAt    string `json:"startedAt,omitempty"`
	FinishedAt   string `json:"finishedAt,omitempty"`
}

type Snapshot struct {
	ProtocolVersion int       `json:"protocolVersion"`
	SchemaID        string    `json:"schemaId"`
	NodeID          string    `json:"nodeId"`
	Epoch           int64     `json:"epoch"`
	StateVersion    int64     `json:"stateVersion"`
	LastEventSeq    int64     `json:"lastEventSeq"`
	CapturedAt      string    `json:"capturedAt"`
	Node            NodeState `json:"node"`
	PendingQueue    []Request `json:"pendingQueue"`
	ActiveAttempt   *Attempt  `json:"activeAttempt"`
	Completeness    string    `json:"completeness"`
}

type Page[T any] struct {
	ProtocolVersion      int     `json:"protocolVersion"`
	SchemaID             string  `json:"schemaId"`
	NodeID               string  `json:"nodeId"`
	Epoch                int64   `json:"epoch"`
	SnapshotStateVersion int64   `json:"snapshotStateVersion"`
	LastEventSeq         int64   `json:"lastEventSeq"`
	Items                []T     `json:"items"`
	NextCursor           *string `json:"nextCursor"`
	PageType             string  `json:"pageType"`
}

type Capabilities struct {
	Chat              string `json:"chat"`
	Events            string `json:"events"`
	ToolResults       string `json:"tool_results"`
	Cancel            string `json:"cancel"`
	SteerAttached     string `json:"steer_attached"`
	SessionResume     string `json:"session_resume"`
	PolicyEnforcement string `json:"policy_enforcement"`
}
type AdapterIdentity struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
}
type NodeIdentity struct {
	ProtocolVersion int             `json:"protocolVersion"`
	SchemaID        string          `json:"schemaId"`
	SchemaSHA256    string          `json:"schemaSHA256"`
	NodeID          string          `json:"nodeId"`
	RegistryVersion int64           `json:"registryVersion"`
	IdentityEpoch   int64           `json:"identityEpoch"`
	Adapter         AdapterIdentity `json:"adapter"`
	Capabilities    Capabilities    `json:"capabilities"`
}

// AdmissionCapabilities is a separate registration-time contract. It is not
// inferred from the legacy runtime capability object: every required v2
// migration and ownership primitive must be stated explicitly.
type AdmissionCapabilities struct {
	Profile           bool `json:"profile"`
	NativeEpoch       bool `json:"native_epoch"`
	PolicyEnforcement bool `json:"policy_enforcement"`
	History           bool `json:"history"`
	Facts             bool `json:"facts"`
	DurableReceipts   bool `json:"durable_receipts"`
	ReplicaExport     bool `json:"replica_export"`
	ReplicaImport     bool `json:"replica_import"`
	AssetExport       bool `json:"asset_export"`
	AssetImport       bool `json:"asset_import"`
	ScopedQuiesce     bool `json:"scoped_quiesce"`
	OwnershipRelease  bool `json:"ownership_release"`
	TargetReservation bool `json:"target_reservation"`
}

type AdmissionProfile struct {
	SchemaID             string                `json:"schemaId"`
	OwnerID              string                `json:"ownerId"`
	NodeID               string                `json:"nodeId"`
	RegistrationRevision int64                 `json:"registrationRevision"`
	IdentityEpoch        int64                 `json:"identityEpoch"`
	WireSchemaSHA256     string                `json:"wireSchemaSHA256"`
	Adapter              AdapterIdentity       `json:"adapter"`
	Readiness            string                `json:"readiness"`
	Capabilities         AdmissionCapabilities `json:"capabilities"`
}

func MissingAdmissionCapabilities(value AdmissionCapabilities) []string {
	checks := []struct {
		name    string
		present bool
	}{
		{"profile", value.Profile}, {"native_epoch", value.NativeEpoch},
		{"policy_enforcement", value.PolicyEnforcement}, {"history", value.History},
		{"facts", value.Facts}, {"durable_receipts", value.DurableReceipts},
		{"replica_export", value.ReplicaExport}, {"replica_import", value.ReplicaImport},
		{"asset_export", value.AssetExport}, {"asset_import", value.AssetImport},
		{"scoped_quiesce", value.ScopedQuiesce}, {"ownership_release", value.OwnershipRelease},
		{"target_reservation", value.TargetReservation},
	}
	missing := make([]string, 0, len(checks))
	for _, check := range checks {
		if !check.present {
			missing = append(missing, check.name)
		}
	}
	return missing
}

type AttemptRead struct {
	ProtocolVersion int     `json:"protocolVersion"`
	SchemaID        string  `json:"schemaId"`
	NodeID          string  `json:"nodeId"`
	Epoch           int64   `json:"epoch"`
	StateVersion    int64   `json:"stateVersion"`
	Attempt         Attempt `json:"attempt"`
}
type CommandStatus struct {
	ProtocolVersion      int     `json:"protocolVersion"`
	SchemaID             string  `json:"schemaId"`
	NodeID               string  `json:"nodeId"`
	CommandID            string  `json:"commandId"`
	CanonicalPayloadHash string  `json:"canonicalPayloadHash"`
	Status               string  `json:"status"`
	Receipt              Receipt `json:"receipt"`
}
type HealthLive struct {
	ProtocolVersion  int    `json:"protocolVersion"`
	SchemaID         string `json:"schemaId"`
	Status           string `json:"status"`
	ProcessStartedAt string `json:"processStartedAt"`
}
type HealthReady struct {
	ProtocolVersion int          `json:"protocolVersion"`
	SchemaID        string       `json:"schemaId"`
	CheckedAt       string       `json:"checkedAt"`
	Identity        NodeIdentity `json:"identity"`
	Readiness       string       `json:"readiness"`
	BlockedReasons  []string     `json:"blockedReasons"`
}
type ArtifactMetadata struct {
	ProtocolVersion int    `json:"protocolVersion"`
	SchemaID        string `json:"schemaId"`
	NodeID          string `json:"nodeId"`
	DialogID        string `json:"dialogId"`
	AttemptID       string `json:"attemptId"`
	ArtifactID      string `json:"artifactId"`
	CallID          string `json:"callId,omitempty"`
	Name            string `json:"name"`
	MediaType       string `json:"mediaType"`
	SizeBytes       int64  `json:"sizeBytes"`
	SHA256          string `json:"sha256"`
	Redaction       string `json:"redaction"`
	Truncated       bool   `json:"truncated"`
	Disposition     string `json:"disposition"`
}

type EventEnvelope struct {
	ProtocolVersion int             `json:"protocolVersion"`
	SchemaID        string          `json:"schemaId"`
	NodeID          string          `json:"nodeId"`
	Seq             int64           `json:"seq"`
	Epoch           int64           `json:"epoch"`
	Type            string          `json:"type"`
	EntityID        string          `json:"entityId"`
	EntityVersion   int64           `json:"entityVersion"`
	AttemptID       string          `json:"attemptId,omitempty"`
	DialogID        string          `json:"dialogId,omitempty"`
	ObservedAt      string          `json:"observedAt"`
	SourceAt        string          `json:"sourceAt,omitempty"`
	Completeness    string          `json:"completeness"`
	Payload         json.RawMessage `json:"payload"`
}

type NodeStateChangedPayload = NodeState
type QueueChangedPayload struct {
	QueueVersion    int64   `json:"queueVersion"`
	PendingCount    int64   `json:"pendingCount"`
	ActiveAttemptID *string `json:"activeAttemptId"`
	QueuePaused     bool    `json:"queuePaused"`
}
type MessageAcceptedPayload struct {
	DialogID    string `json:"dialogId"`
	MessageID   string `json:"messageId"`
	RequestID   string `json:"requestId"`
	Sequence    int64  `json:"sequence"`
	Disposition string `json:"disposition"`
}
type DialogDeletedPayload struct {
	DialogID string `json:"dialogId"`
}
type MessageDispositionPayload struct {
	MessageID  string `json:"messageId"`
	From       string `json:"from"`
	To         string `json:"to"`
	ReasonCode string `json:"reasonCode"`
}
type AttemptDispatchingPayload struct {
	RequestID                string `json:"requestId"`
	Generation               int64  `json:"generation"`
	ContextBoundaryMessageID string `json:"contextBoundaryMessageId"`
	PolicyRevision           string `json:"policyRevision"`
	PolicyHash               string `json:"policyHash"`
}
type AttemptStartedPayload struct {
	RequestID  string `json:"requestId"`
	Generation int64  `json:"generation"`
}
type AttemptWaitingPayload struct {
	RequestID  string `json:"requestId"`
	Generation int64  `json:"generation"`
	WaitKind   string `json:"waitKind"`
}
type AttemptStopRequestedPayload struct {
	Generation int64  `json:"generation"`
	CommandID  string `json:"commandId"`
}
type Usage struct {
	Source       string `json:"source"`
	InputTokens  int64  `json:"inputTokens"`
	OutputTokens int64  `json:"outputTokens"`
	TotalTokens  int64  `json:"totalTokens"`
}
type AttemptOutput struct {
	Kind               string `json:"kind"`
	AssistantMessageID string `json:"assistantMessageId,omitempty"`
}
type AttemptCompletedPayload struct {
	Generation int64         `json:"generation"`
	Output     AttemptOutput `json:"output"`
	Usage      *Usage        `json:"usage,omitempty"`
}
type AttemptFailedPayload struct {
	Generation   int64  `json:"generation"`
	FailureClass string `json:"failureClass"`
	ErrorCode    string `json:"errorCode"`
	SafeMessage  string `json:"safeMessage"`
	Retryable    bool   `json:"retryable"`
	EffectStatus string `json:"effectStatus"`
}
type AttemptInterruptedPayload struct {
	Generation   int64  `json:"generation"`
	Reason       string `json:"reason"`
	EffectStatus string `json:"effectStatus"`
}
type AttemptUnknownPayload struct {
	Generation   int64  `json:"generation"`
	Reason       string `json:"reason"`
	EffectStatus string `json:"effectStatus"`
}
type AssistantDeltaPayload struct {
	MessageID  string      `json:"messageId"`
	DeltaIndex int64       `json:"deltaIndex"`
	Content    SafeContent `json:"content"`
}
type AssistantMessagePayload struct {
	MessageID    string      `json:"messageId"`
	Content      SafeContent `json:"content"`
	FinishReason string      `json:"finishReason"`
}
type SafeContent struct {
	Kind       string `json:"kind"`
	Content    string `json:"content,omitempty"`
	ArtifactID string `json:"artifactId,omitempty"`
	SizeBytes  *int64 `json:"sizeBytes,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Redaction  string `json:"redaction"`
	Truncated  bool   `json:"truncated"`
}
type ToolStartedPayload struct {
	CallID     string      `json:"callId"`
	ToolName   string      `json:"toolName"`
	ActionHash string      `json:"actionHash"`
	Input      SafeContent `json:"input"`
}
type ToolOutputPayload struct {
	CallID     string      `json:"callId"`
	ChunkIndex int64       `json:"chunkIndex"`
	Stream     string      `json:"stream"`
	Output     SafeContent `json:"output"`
}
type ToolCompletedPayload struct {
	CallID       string      `json:"callId"`
	Status       string      `json:"status"`
	Result       SafeContent `json:"result"`
	EffectStatus string      `json:"effectStatus"`
	EffectRef    string      `json:"effectRef,omitempty"`
}
type ApprovalRequestedPayload struct {
	ApprovalID      string `json:"approvalId"`
	CallID          string `json:"callId"`
	ActionHash      string `json:"actionHash"`
	SafePrompt      string `json:"safePrompt"`
	ApprovalVersion int64  `json:"approvalVersion"`
}
type ApprovalResolvedPayload struct {
	ApprovalID      string  `json:"approvalId"`
	Decision        string  `json:"decision"`
	ActorID         ActorID `json:"actorId"`
	ApprovalVersion int64   `json:"approvalVersion"`
}
type InputRequestedPayload struct {
	InputRequestID string      `json:"inputRequestId"`
	Prompt         SafeContent `json:"prompt"`
	InputVersion   int64       `json:"inputVersion"`
}
type InputResolvedPayload struct {
	InputRequestID string `json:"inputRequestId"`
	MessageID      string `json:"messageId"`
	InputVersion   int64  `json:"inputVersion"`
}
type ArtifactAvailablePayload struct {
	ArtifactID string `json:"artifactId"`
	CallID     string `json:"callId,omitempty"`
	Name       string `json:"name"`
	MediaType  string `json:"mediaType"`
	SizeBytes  int64  `json:"sizeBytes"`
	SHA256     string `json:"sha256"`
	Redaction  string `json:"redaction"`
	Truncated  bool   `json:"truncated"`
}
type HistoryGapPayload struct {
	ExpectedSeq      int64  `json:"expectedSeq"`
	AvailableFromSeq int64  `json:"availableFromSeq"`
	Reason           string `json:"reason"`
}
