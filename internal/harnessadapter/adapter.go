// Package harnessadapter defines the provider-neutral execution seam used by a
// future Harness supervisor. It has no provider implementation or runtime loop.
package harnessadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

const (
	CursorSDKVersion      = "1.0.31"
	CodexAppServerVersion = "0.153.4"
)

type Kind string

const (
	KindCursor Kind = "cursor"
	KindCodex  Kind = "codex"
)

type Capability string

const (
	CapabilityChat              Capability = "chat"
	CapabilityEvents            Capability = "events"
	CapabilityToolResults       Capability = "tool_results"
	CapabilityCancel            Capability = "cancel"
	CapabilitySteerAttached     Capability = "steer_attached"
	CapabilitySessionResume     Capability = "session_resume"
	CapabilityPolicyEnforcement Capability = "policy_enforcement"
)

var mandatoryCapabilities = []Capability{
	CapabilityChat, CapabilityEvents, CapabilityToolResults, CapabilityCancel,
	CapabilitySteerAttached, CapabilitySessionResume, CapabilityPolicyEnforcement,
}

type Identity struct {
	Kind            Kind
	Version         string
	ProtocolVersion int
	SchemaID        string
	SchemaSHA256    string
	Declared        map[Capability]bool
	Verified        map[Capability]bool
}

// ValidateIdentity enforces the exact C1 pins. A declared capability is not a
// verified one; every mandatory capability must be both before readiness.
func ValidateIdentity(identity Identity) error {
	if identity.ProtocolVersion != harnessprotocol.ProtocolVersion || identity.SchemaID != harnessprotocol.SchemaID || identity.SchemaSHA256 != harnessprotocol.SchemaSHA256 {
		return errors.New("adapter protocol/schema pin mismatch")
	}
	if (identity.Kind == KindCursor && identity.Version != CursorSDKVersion) ||
		(identity.Kind == KindCodex && identity.Version != CodexAppServerVersion) {
		return errors.New("adapter implementation version mismatch")
	}
	if identity.Kind != KindCursor && identity.Kind != KindCodex {
		return errors.New("unknown adapter kind")
	}
	for _, capability := range mandatoryCapabilities {
		if !identity.Declared[capability] || !identity.Verified[capability] {
			return errors.New("mandatory adapter capability is not verified")
		}
	}
	return nil
}

type AttemptRef struct {
	NodeID     string
	DialogID   string
	RequestID  string
	AttemptID  string
	Generation int64
}

type PolicySnapshot struct {
	Revision         string
	Content          []byte
	ContentHash      string
	ToolManifest     []byte
	ToolManifestHash string
	ApprovalMode     string
	EffectiveHash    string
}

const (
	ApprovalModeDeny         = "deny"
	ApprovalModeExplicitOnce = "explicit_once"
)

// ValidatePolicySnapshot fails closed unless the exact policy and tool manifest
// bytes match the hashes that were durably selected for this attempt.
func ValidatePolicySnapshot(policy PolicySnapshot) error {
	if policy.Revision == "" || len(policy.Content) == 0 || len(policy.ToolManifest) == 0 || policy.ContentHash == "" || policy.ToolManifestHash == "" || policy.EffectiveHash == "" {
		return errors.New("incomplete policy snapshot")
	}
	if policy.ApprovalMode != ApprovalModeDeny && policy.ApprovalMode != ApprovalModeExplicitOnce {
		return errors.New("unknown approval mode")
	}
	if digest(policy.Content) != policy.ContentHash || digest(policy.ToolManifest) != policy.ToolManifestHash {
		return errors.New("policy snapshot hash mismatch")
	}
	if EffectivePolicyHash(policy) != policy.EffectiveHash {
		return errors.New("effective policy hash mismatch")
	}
	return nil
}

// PreparePolicySnapshot validates and clones caller-owned bytes before an
// asynchronous native call can observe them.
func PreparePolicySnapshot(policy PolicySnapshot) (PolicySnapshot, error) {
	if err := ValidatePolicySnapshot(policy); err != nil {
		return PolicySnapshot{}, err
	}
	policy.Content = bytes.Clone(policy.Content)
	policy.ToolManifest = bytes.Clone(policy.ToolManifest)
	return policy, nil
}

// EffectivePolicyHash is domain-separated and length-framed. It binds the
// revision, individually verified content hashes, and approval mode.
func EffectivePolicyHash(policy PolicySnapshot) string {
	hash := sha256.New()
	hash.Write([]byte("harness-effective-policy-v1\x00"))
	var length [8]byte
	for _, value := range []string{policy.Revision, policy.ContentHash, policy.ToolManifestHash, policy.ApprovalMode} {
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		hash.Write(length[:])
		hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

type ContextBoundary struct {
	MessageID string
	Sequence  int64
}

type StartInput struct {
	Attempt AttemptRef
	Prompt  string
	Policy  PolicySnapshot
	Context ContextBoundary
}

// ResumeInput repeats the full policy and manifest. Adapters must not inherit
// native defaults or an earlier provider policy after process/session resume.
type ResumeInput struct {
	Attempt AttemptRef
	Prompt  string
	Policy  PolicySnapshot
	Context ContextBoundary
}

type StartOutcome string

const (
	StartStarted  StartOutcome = "started"
	StartRejected StartOutcome = "rejected"
	StartUnknown  StartOutcome = "unknown"
)

type StartResult struct {
	Outcome StartOutcome
	Failure *Failure
}

type ResumeOutcome string

const (
	ResumeStarted        ResumeOutcome = "started"
	ResumeContextMissing ResumeOutcome = "context_missing"
	ResumeRejected       ResumeOutcome = "rejected"
	ResumeUnknown        ResumeOutcome = "unknown"
)

type ResumeResult struct {
	Outcome ResumeOutcome
	Failure *Failure
}

type EventsInput struct{ Attempt AttemptRef }
type EventStream interface {
	Next(context.Context) (Event, error)
	Close() error
}

// Event is a closed provider-neutral union. Every value carries the Harness
// attempt generation so B1 can persist late events without mutating a newer slot.
type Event interface {
	adapterEvent()
	AttemptReference() AttemptRef
}
type EventBase struct{ Attempt AttemptRef }

func (EventBase) adapterEvent()                      {}
func (event EventBase) AttemptReference() AttemptRef { return event.Attempt }

type StartedEvent struct{ EventBase }
type WaitingEvent struct {
	EventBase
	Kind string
}
type AssistantDeltaEvent struct {
	EventBase
	MessageID  string
	DeltaIndex int64
	Content    harnessprotocol.SafeContent
}
type AssistantMessageEvent struct {
	EventBase
	MessageID    string
	Content      harnessprotocol.SafeContent
	FinishReason string
	FullText     *string `json:"-"`
	// FullTextIncomplete marks producer-side truncation. FullText then contains
	// only the safely retained prefix and must not be exposed as complete.
	FullTextIncomplete bool `json:"-"`
}
type ToolStartedEvent struct {
	EventBase
	CallID             string
	ToolName           string
	ActionHash         string
	Input              harnessprotocol.SafeContent
	FullText           *string `json:"-"`
	FullTextIncomplete bool    `json:"-"`
}
type ToolOutputEvent struct {
	EventBase
	CallID             string
	ChunkIndex         int64
	Stream             string
	Output             harnessprotocol.SafeContent
	FullText           *string `json:"-"`
	FullTextIncomplete bool    `json:"-"`
}
type ToolCompletedEvent struct {
	EventBase
	CallID             string
	Status             string
	Result             harnessprotocol.SafeContent
	EffectStatus       string
	EffectRef          string
	FullText           *string `json:"-"`
	FullTextIncomplete bool    `json:"-"`
}
type ApprovalRequestedEvent struct {
	EventBase
	ApprovalID string
	CallID     string
	ActionHash string
	SafePrompt string
}
type InputRequestedEvent struct {
	EventBase
	InputRequestID string
	Prompt         harnessprotocol.SafeContent
}
type TerminalEvent struct {
	EventBase
	Outcome      ReconcileOutcome
	Output       *harnessprotocol.SafeContent
	Usage        *harnessprotocol.Usage
	Failure      *Failure
	EffectStatus string
}
type UnknownEvent struct {
	EventBase
	Reason       string
	EffectStatus string
}

// Steer addresses one Harness generation. Codex implementations fence the
// corresponding private turn with expectedTurnId; Cursor maps its three native
// outcomes to applied, fallback_queued and unknown without blind resend.
type SteerInput struct {
	Attempt   AttemptRef
	MessageID string
	Text      string
}
type SteerOutcome string

const (
	SteerApplied        SteerOutcome = "applied"
	SteerFallbackQueued SteerOutcome = "fallback_queued"
	SteerUnknown        SteerOutcome = "unknown"
	SteerRejected       SteerOutcome = "rejected"
)

type SteerResult struct {
	Outcome SteerOutcome
	Failure *Failure
}

type CancelInput struct{ Attempt AttemptRef }
type CancelOutcome string

const (
	CancelAcknowledged CancelOutcome = "acknowledged"
	CancelRejected     CancelOutcome = "rejected"
	CancelUnknown      CancelOutcome = "unknown"
)

// CancelAcknowledged only confirms provider receipt. It is never terminal.
type CancelResult struct {
	Outcome CancelOutcome
	Failure *Failure
}

type RespondApprovalInput struct {
	Attempt         AttemptRef
	ApprovalID      string
	ApprovalVersion int64
	ActionHash      string
	Decision        string
}

type RespondInputInput struct {
	Attempt        AttemptRef
	InputRequestID string
	InputVersion   int64
	Text           string
}

type ResponseOutcome string

const (
	ResponseApplied  ResponseOutcome = "applied"
	ResponseRejected ResponseOutcome = "rejected"
	ResponseUnknown  ResponseOutcome = "unknown"
)

// ResponseApplied confirms delivery to the addressed native pending request;
// it does not imply that the attempt reached a terminal state.
type ResponseResult struct {
	Outcome ResponseOutcome
	Failure *Failure
}

type ReconcileInput struct{ Attempt AttemptRef }
type ReconcileOutcome string

const (
	ReconcileRunning      ReconcileOutcome = "running"
	ReconcileWaitingInput ReconcileOutcome = "waiting_input"
	ReconcileCompleted    ReconcileOutcome = "completed"
	ReconcileFailed       ReconcileOutcome = "failed"
	ReconcileInterrupted  ReconcileOutcome = "interrupted"
	ReconcileUnknown      ReconcileOutcome = "unknown"
)

type ReconcileResult struct {
	Outcome      ReconcileOutcome
	Output       *harnessprotocol.SafeContent
	Usage        *harnessprotocol.Usage
	Failure      *Failure
	EffectStatus string
}

type FailureClass string

const (
	FailureTask     FailureClass = "task"
	FailureNode     FailureClass = "node"
	FailurePolicy   FailureClass = "policy"
	FailureProtocol FailureClass = "protocol"
)

type Failure struct {
	Class       FailureClass
	Code        string
	SafeMessage string
	Retryable   bool
}

// Adapter owns all native Cursor agent/run IDs and Codex thread/turn IDs.
// Those references never cross this interface or appear in harnessprotocol.
type Adapter interface {
	Identity(context.Context) (Identity, error)
	Start(context.Context, StartInput) (StartResult, error)
	Resume(context.Context, ResumeInput) (ResumeResult, error)
	Events(context.Context, EventsInput) (EventStream, error)
	Steer(context.Context, SteerInput) (SteerResult, error)
	Cancel(context.Context, CancelInput) (CancelResult, error)
	RespondApproval(context.Context, RespondApprovalInput) (ResponseResult, error)
	RespondInput(context.Context, RespondInputInput) (ResponseResult, error)
	Reconcile(context.Context, ReconcileInput) (ReconcileResult, error)
}
