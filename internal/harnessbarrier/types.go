// Package harnessbarrier defines the additive, versioned wire records used by
// the Harness administrative admission barrier. It deliberately does not add
// variants to the frozen harness-wire-v2 contract.
package harnessbarrier

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/boxvtk621/harness-codex/internal/strictjson"
)

const (
	ProtocolVersion    = 1
	SchemaID           = "harness-barrier-v1"
	SchemaSHA256       = "eccff50e2e5679f3b5f8551228d6b77e29bc8cb498cdabc8d1e10f94f3822225"
	MaximumSafeInteger = int64(1<<53 - 1)
	MaximumWireBytes   = 16 << 10
)

var (
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	operationPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)
	sha256Pattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Scope struct {
	Kind     string `json:"kind"`
	DialogID string `json:"dialogId,omitempty"`
}

type InstallRequest struct {
	ProtocolVersion       int    `json:"protocolVersion"`
	SchemaID              string `json:"schemaId"`
	OperationID           string `json:"operationId"`
	NodeID                string `json:"nodeId"`
	ExpectedEpoch         int64  `json:"expectedEpoch"`
	BindingGeneration     int64  `json:"bindingGeneration"`
	Scope                 Scope  `json:"scope"`
	ExpectedScopeRevision int64  `json:"expectedScopeRevision"`
}

type HoldReceipt struct {
	ProtocolVersion   int    `json:"protocolVersion"`
	SchemaID          string `json:"schemaId"`
	Kind              string `json:"kind"`
	OperationID       string `json:"operationId"`
	ReceiptID         string `json:"receiptId"`
	NodeID            string `json:"nodeId"`
	Epoch             int64  `json:"epoch"`
	BindingGeneration int64  `json:"bindingGeneration"`
	Scope             Scope  `json:"scope"`
	HoldVersion       int64  `json:"holdVersion"`
	ScopeRevision     int64  `json:"scopeRevision"`
	InstalledAt       string `json:"installedAt"`
}

type RejectionReceipt struct {
	ProtocolVersion      int    `json:"protocolVersion"`
	SchemaID             string `json:"schemaId"`
	Kind                 string `json:"kind"`
	CommandID            string `json:"commandId"`
	CommandKind          string `json:"commandKind"`
	ReceiptID            string `json:"receiptId"`
	NodeID               string `json:"nodeId"`
	Epoch                int64  `json:"epoch"`
	CanonicalPayloadHash string `json:"canonicalPayloadHash"`
	RejectedAt           string `json:"rejectedAt"`
	Reason               string `json:"reason"`
	HoldOperationID      string `json:"holdOperationId"`
	HoldVersion          int64  `json:"holdVersion"`
	Scope                Scope  `json:"scope"`
	ScopeRevision        int64  `json:"scopeRevision"`
}

// QuiescenceProof is a deterministic, scope-bound readback. It has no expiry:
// consumers must compare it with a fresh authenticated node readback.
type QuiescenceProof struct {
	ProtocolVersion        int     `json:"protocolVersion"`
	SchemaID               string  `json:"schemaId"`
	Kind                   string  `json:"kind"`
	OperationID            string  `json:"operationId"`
	NodeID                 string  `json:"nodeId"`
	Epoch                  int64   `json:"epoch"`
	BindingGeneration      int64   `json:"bindingGeneration"`
	Scope                  Scope   `json:"scope"`
	HoldVersion            int64   `json:"holdVersion"`
	ScopeRevision          int64   `json:"scopeRevision"`
	StateVersion           int64   `json:"stateVersion"`
	QueueRevision          int64   `json:"queueRevision"`
	ParkedRequestIDsDigest string  `json:"parkedRequestIdsDigest"`
	CheckpointStreamID     string  `json:"checkpointStreamId"`
	CheckpointSeq          int64   `json:"checkpointSeq"`
	Active                 *string `json:"active"`
	EffectStatus           string  `json:"effectStatus"`
	UnsettledCount         int64   `json:"unsettledCount"`
	ProofHash              string  `json:"proofHash"`
}

type ReleaseRequest struct {
	ProtocolVersion       int    `json:"protocolVersion"`
	SchemaID              string `json:"schemaId"`
	OperationID           string `json:"operationId"`
	NodeID                string `json:"nodeId"`
	ExpectedEpoch         int64  `json:"expectedEpoch"`
	BindingGeneration     int64  `json:"bindingGeneration"`
	Scope                 Scope  `json:"scope"`
	HoldVersion           int64  `json:"holdVersion"`
	ExpectedScopeRevision int64  `json:"expectedScopeRevision"`
	Action                string `json:"action"`
}

type ReleaseReceipt struct {
	ProtocolVersion   int    `json:"protocolVersion"`
	SchemaID          string `json:"schemaId"`
	Kind              string `json:"kind"`
	OperationID       string `json:"operationId"`
	ReceiptID         string `json:"receiptId"`
	NodeID            string `json:"nodeId"`
	Epoch             int64  `json:"epoch"`
	BindingGeneration int64  `json:"bindingGeneration"`
	Scope             Scope  `json:"scope"`
	HoldVersion       int64  `json:"holdVersion"`
	ScopeRevision     int64  `json:"scopeRevision"`
	ManualPause       bool   `json:"manualPause"`
	ReleasedAt        string `json:"releasedAt"`
}

func Validate(wireType string, raw []byte) error {
	if len(raw) == 0 || len(raw) > MaximumWireBytes || !strictjson.Valid(raw) {
		return errors.New("invalid barrier JSON")
	}
	switch wireType {
	case "installRequest":
		var value InstallRequest
		if err := decodeExact(raw, &value); err != nil {
			return err
		}
		if !validPins(value.ProtocolVersion, value.SchemaID) || !operationPattern.MatchString(value.OperationID) ||
			!uuidPattern.MatchString(value.NodeID) || !validPositiveInteger(value.ExpectedEpoch) ||
			!validPositiveInteger(value.BindingGeneration) || !validSafeInteger(value.ExpectedScopeRevision) || !validScope(value.Scope) || !validScopeEncoding(raw) {
			return errors.New("invalid barrier install request")
		}
	case "holdReceipt":
		var value HoldReceipt
		if err := decodeExact(raw, &value); err != nil {
			return err
		}
		if !validPins(value.ProtocolVersion, value.SchemaID) || value.Kind != "hold.installed" ||
			!operationPattern.MatchString(value.OperationID) || !uuidPattern.MatchString(value.ReceiptID) ||
			!uuidPattern.MatchString(value.NodeID) || !validPositiveInteger(value.Epoch) || !validPositiveInteger(value.BindingGeneration) ||
			!validPositiveInteger(value.HoldVersion) || !validPositiveInteger(value.ScopeRevision) || !validScope(value.Scope) || !validScopeEncoding(raw) || !validTimestamp(value.InstalledAt) {
			return errors.New("invalid barrier hold receipt")
		}
	case "rejectionReceipt":
		var value RejectionReceipt
		if err := decodeExact(raw, &value); err != nil {
			return err
		}
		if !validPins(value.ProtocolVersion, value.SchemaID) || value.Kind != "command.rejected" ||
			!uuidPattern.MatchString(value.CommandID) || !validRejectedCommand(value.CommandKind) ||
			!uuidPattern.MatchString(value.ReceiptID) || !uuidPattern.MatchString(value.NodeID) || !validPositiveInteger(value.Epoch) ||
			!sha256Pattern.MatchString(value.CanonicalPayloadHash) || !validTimestamp(value.RejectedAt) ||
			value.Reason != "administrative_hold" || !operationPattern.MatchString(value.HoldOperationID) ||
			!validPositiveInteger(value.HoldVersion) || !validPositiveInteger(value.ScopeRevision) || !validScope(value.Scope) || !validScopeEncoding(raw) {
			return errors.New("invalid barrier rejection receipt")
		}
	case "quiescenceProof":
		var value QuiescenceProof
		if err := decodeExact(raw, &value); err != nil {
			return err
		}
		if !exactFields(raw, "protocolVersion", "schemaId", "kind", "operationId", "nodeId", "epoch", "bindingGeneration", "scope", "holdVersion", "scopeRevision", "stateVersion", "queueRevision", "parkedRequestIdsDigest", "checkpointStreamId", "checkpointSeq", "active", "effectStatus", "unsettledCount", "proofHash") ||
			!validPins(value.ProtocolVersion, value.SchemaID) || value.Kind != "scope.parked" ||
			!operationPattern.MatchString(value.OperationID) || !uuidPattern.MatchString(value.NodeID) ||
			!validPositiveInteger(value.Epoch) || !validPositiveInteger(value.BindingGeneration) || !validScope(value.Scope) || !validScopeEncoding(raw) ||
			!validPositiveInteger(value.HoldVersion) || !validPositiveInteger(value.ScopeRevision) ||
			!validPositiveInteger(value.StateVersion) || !validPositiveInteger(value.QueueRevision) ||
			!sha256Pattern.MatchString(value.ParkedRequestIDsDigest) || !uuidPattern.MatchString(value.CheckpointStreamID) ||
			!validPositiveInteger(value.CheckpointSeq) || value.Active != nil || value.EffectStatus != "known" || value.UnsettledCount != 0 ||
			!sha256Pattern.MatchString(value.ProofHash) || value.ProofHash != ComputeProofHash(value) {
			return errors.New("invalid quiescence proof")
		}
	case "releaseRequest":
		var value ReleaseRequest
		if err := decodeExact(raw, &value); err != nil {
			return err
		}
		if !exactFields(raw, "protocolVersion", "schemaId", "operationId", "nodeId", "expectedEpoch", "bindingGeneration", "scope", "holdVersion", "expectedScopeRevision", "action") ||
			!validPins(value.ProtocolVersion, value.SchemaID) || !operationPattern.MatchString(value.OperationID) ||
			!uuidPattern.MatchString(value.NodeID) || !validPositiveInteger(value.ExpectedEpoch) || !validPositiveInteger(value.BindingGeneration) ||
			!validScope(value.Scope) || !validScopeEncoding(raw) || !validPositiveInteger(value.HoldVersion) ||
			!validPositiveInteger(value.ExpectedScopeRevision) || (value.Action != "release" && value.Action != "cancel") {
			return errors.New("invalid hold release request")
		}
	case "releaseReceipt":
		var value ReleaseReceipt
		if err := decodeExact(raw, &value); err != nil {
			return err
		}
		if !exactFields(raw, "protocolVersion", "schemaId", "kind", "operationId", "receiptId", "nodeId", "epoch", "bindingGeneration", "scope", "holdVersion", "scopeRevision", "manualPause", "releasedAt") ||
			!validPins(value.ProtocolVersion, value.SchemaID) || (value.Kind != "hold.released" && value.Kind != "hold.cancelled") ||
			!operationPattern.MatchString(value.OperationID) || !uuidPattern.MatchString(value.ReceiptID) || !uuidPattern.MatchString(value.NodeID) ||
			!validPositiveInteger(value.Epoch) || !validPositiveInteger(value.BindingGeneration) || !validScope(value.Scope) || !validScopeEncoding(raw) ||
			!validPositiveInteger(value.HoldVersion) || !validPositiveInteger(value.ScopeRevision) || !validTimestamp(value.ReleasedAt) {
			return errors.New("invalid hold release receipt")
		}
	default:
		return errors.New("unknown barrier wire type")
	}
	return nil
}

// ComputeProofHash binds every proof field except the hash itself to a
// domain-separated encoding with stable struct field order.
func ComputeProofHash(value QuiescenceProof) string {
	type proofHashInput struct {
		ProtocolVersion        int     `json:"protocolVersion"`
		SchemaID               string  `json:"schemaId"`
		Kind                   string  `json:"kind"`
		OperationID            string  `json:"operationId"`
		NodeID                 string  `json:"nodeId"`
		Epoch                  int64   `json:"epoch"`
		BindingGeneration      int64   `json:"bindingGeneration"`
		Scope                  Scope   `json:"scope"`
		HoldVersion            int64   `json:"holdVersion"`
		ScopeRevision          int64   `json:"scopeRevision"`
		StateVersion           int64   `json:"stateVersion"`
		QueueRevision          int64   `json:"queueRevision"`
		ParkedRequestIDsDigest string  `json:"parkedRequestIdsDigest"`
		CheckpointStreamID     string  `json:"checkpointStreamId"`
		CheckpointSeq          int64   `json:"checkpointSeq"`
		Active                 *string `json:"active"`
		EffectStatus           string  `json:"effectStatus"`
		UnsettledCount         int64   `json:"unsettledCount"`
	}
	encoded, err := json.Marshal(proofHashInput{
		value.ProtocolVersion, value.SchemaID, value.Kind, value.OperationID, value.NodeID, value.Epoch,
		value.BindingGeneration, value.Scope, value.HoldVersion, value.ScopeRevision, value.StateVersion,
		value.QueueRevision, value.ParkedRequestIDsDigest, value.CheckpointStreamID, value.CheckpointSeq,
		value.Active, value.EffectStatus, value.UnsettledCount,
	})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(append([]byte("hl263-quiescence-proof/v1\x00"), encoded...))
	return fmt.Sprintf("%x", digest[:])
}

func exactFields(raw []byte, fields ...string) bool {
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil || len(value) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, ok := value[field]; !ok {
			return false
		}
	}
	return true
}

func validPins(version int, schema string) bool {
	return version == ProtocolVersion && schema == SchemaID
}

func validSafeInteger(value int64) bool {
	return value >= 0 && value <= MaximumSafeInteger
}

func validPositiveInteger(value int64) bool {
	return value > 0 && value <= MaximumSafeInteger
}

func validScope(scope Scope) bool {
	switch scope.Kind {
	case "node":
		return scope.DialogID == ""
	case "dialog":
		return uuidPattern.MatchString(scope.DialogID)
	default:
		return false
	}
}

func validScopeEncoding(raw []byte) bool {
	var envelope map[string]json.RawMessage
	var scope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil || json.Unmarshal(envelope["scope"], &scope) != nil {
		return false
	}
	var kind string
	if json.Unmarshal(scope["kind"], &kind) != nil {
		return false
	}
	switch kind {
	case "node":
		return len(scope) == 1
	case "dialog":
		_, present := scope["dialogId"]
		return len(scope) == 2 && present
	default:
		return false
	}
}

func validRejectedCommand(kind string) bool {
	switch kind {
	case "dialog.create", "dialog.delete", "message.enqueue", "queue.resume", "attempt.retry":
		return true
	default:
		return false
	}
}

func validTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Format(time.RFC3339Nano) == value
}

func decodeExact(raw []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("trailing barrier JSON")
	}
	return nil
}
