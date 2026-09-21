// Package logicaldelete defines the additive R13 contracts used by the
// coordinator and the private Harness control plane. It does not extend the
// frozen harness-wire-v2 browser command contract.
package logicaldelete

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

const (
	SchemaID        = "logical-dialog-delete-v1"
	AdvanceSchemaID = "logical-dialog-delete-advance-v1"
	NodeSchemaID    = "logical-dialog-node-delete-v1"
	MaximumSafeInt  = int64(1<<53 - 1)
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	codePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)
)

type Request struct {
	SchemaID               string `json:"schemaId"`
	OperationID            string `json:"operationId"`
	CommandID              string `json:"commandId"`
	LogicalDialogID        string `json:"logicalDialogId"`
	ExpectedBindingVersion int64  `json:"expectedBindingVersion"`
	ExpectedDialogVersion  int64  `json:"expectedDialogVersion"`
}

type Status struct {
	SchemaID               string       `json:"schemaId"`
	OperationID            string       `json:"operationId"`
	RequestHash            string       `json:"requestHash"`
	CommandID              string       `json:"commandId"`
	LogicalDialogID        string       `json:"logicalDialogId"`
	ExpectedBindingVersion int64        `json:"expectedBindingVersion"`
	ExpectedDialogVersion  int64        `json:"expectedDialogVersion"`
	NodeID                 string       `json:"nodeId"`
	NodeDialogID           string       `json:"nodeDialogId"`
	RegistryVersion        int64        `json:"registryVersion"`
	IdentityEpoch          int64        `json:"identityEpoch"`
	HoldScopeRevision      int64        `json:"holdScopeRevision"`
	HoldVersion            int64        `json:"holdVersion,omitempty"`
	Phase                  string       `json:"phase"`
	EffectState            string       `json:"effectState"`
	OperationVersion       int64        `json:"operationVersion"`
	Archived               bool         `json:"archived"`
	ResultCode             string       `json:"resultCode,omitempty"`
	NodeReceipt            *NodeReceipt `json:"nodeReceipt,omitempty"`
	UpdatedAt              string       `json:"updatedAt"`
}

type AdvanceRequest struct {
	SchemaID                  string       `json:"schemaId"`
	OperationID               string       `json:"operationId"`
	RequestHash               string       `json:"requestHash"`
	ExpectedOperationVersion  int64        `json:"expectedOperationVersion"`
	Action                    string       `json:"action"`
	HoldVersion               int64        `json:"holdVersion"`
	ObservedHoldScopeRevision int64        `json:"observedHoldScopeRevision"`
	ResultCode                string       `json:"resultCode"`
	NodeReceipt               *NodeReceipt `json:"nodeReceipt"`
}

type NodeRequest struct {
	SchemaID               string `json:"schemaId"`
	OperationID            string `json:"operationId"`
	CoordinatorRequestHash string `json:"coordinatorRequestHash"`
	CommandID              string `json:"commandId"`
	LogicalDialogID        string `json:"logicalDialogId"`
	NodeID                 string `json:"nodeId"`
	NodeDialogID           string `json:"nodeDialogId"`
	ExpectedEpoch          int64  `json:"expectedEpoch"`
	RegistryVersion        int64  `json:"registryVersion"`
	BindingVersion         int64  `json:"bindingVersion"`
	ExpectedDialogVersion  int64  `json:"expectedDialogVersion"`
	HoldVersion            int64  `json:"holdVersion"`
	HoldScopeRevision      int64  `json:"holdScopeRevision"`
}

type NodeReceipt struct {
	SchemaID               string          `json:"schemaId"`
	OperationID            string          `json:"operationId"`
	NodeRequestHash        string          `json:"nodeRequestHash"`
	CoordinatorRequestHash string          `json:"coordinatorRequestHash"`
	ReceiptID              string          `json:"receiptId"`
	CommandID              string          `json:"commandId"`
	LogicalDialogID        string          `json:"logicalDialogId"`
	NodeID                 string          `json:"nodeId"`
	NodeDialogID           string          `json:"nodeDialogId"`
	Epoch                  int64           `json:"epoch"`
	RegistryVersion        int64           `json:"registryVersion"`
	BindingVersion         int64           `json:"bindingVersion"`
	DeletedDialogVersion   int64           `json:"deletedDialogVersion"`
	HoldVersion            int64           `json:"holdVersion"`
	HoldScopeRevision      int64           `json:"holdScopeRevision"`
	TombstoneEventSeq      int64           `json:"tombstoneEventSeq"`
	CommandReceipt         json.RawMessage `json:"commandReceipt"`
	DeletedAt              string          `json:"deletedAt"`
}

// ClosureDescriptor is written only by a separately verified retirement or
// archival workflow. R13 consumes it but does not infer one from offline state.
type ClosureDescriptor struct {
	LogicalDialogID       string          `json:"logicalDialogId"`
	BindingVersion        int64           `json:"bindingVersion"`
	NodeID                string          `json:"nodeId"`
	NodeDialogID          string          `json:"nodeDialogId"`
	DialogVersion         int64           `json:"dialogVersion"`
	DescriptorVersion     int64           `json:"descriptorVersion"`
	ZeroPending           bool            `json:"zeroPending"`
	FinalCheckpoint       json.RawMessage `json:"finalCheckpoint"`
	FinalCheckpointSHA256 string          `json:"finalCheckpointSHA256"`
	VerifiedAt            string          `json:"verifiedAt"`
}

func ValidateRequest(value Request) error {
	if value.SchemaID != SchemaID || !validUUID(value.OperationID) || !validUUID(value.CommandID) ||
		!validUUID(value.LogicalDialogID) || !positive(value.ExpectedBindingVersion) || !incrementable(value.ExpectedDialogVersion) {
		return errors.New("logical delete request is invalid")
	}
	return nil
}

func RequestHash(value Request) (string, error) {
	if err := ValidateRequest(value); err != nil {
		return "", err
	}
	return hash(value)
}

func ValidateStatus(value Status) error {
	if value.SchemaID != SchemaID || !validUUID(value.OperationID) || !sha256Pattern.MatchString(value.RequestHash) ||
		!validUUID(value.CommandID) || !validUUID(value.LogicalDialogID) || !positive(value.ExpectedBindingVersion) ||
		!incrementable(value.ExpectedDialogVersion) || !validUUID(value.NodeID) || !validUUID(value.NodeDialogID) ||
		!positive(value.RegistryVersion) || value.IdentityEpoch < 1 || value.IdentityEpoch > MaximumSafeInt ||
		value.HoldScopeRevision < 0 || value.HoldScopeRevision > MaximumSafeInt || !positive(value.OperationVersion) ||
		!oneOf(value.Phase, "accepted", "holding", "reconciling", "succeeded", "failed") ||
		!oneOf(value.EffectState, "not_sent", "sent", "unknown", "reconciled", "failed") {
		return errors.New("logical delete status is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, value.UpdatedAt); err != nil {
		return errors.New("logical delete status time is invalid")
	}
	switch value.Phase {
	case "accepted":
		if value.EffectState != "not_sent" || value.HoldVersion != 0 || value.Archived || value.ResultCode != "" || value.NodeReceipt != nil {
			return errors.New("logical delete accepted state is invalid")
		}
	case "holding":
		if value.EffectState != "sent" || !positive(value.HoldVersion) || value.Archived || value.ResultCode != "" || value.NodeReceipt != nil {
			return errors.New("logical delete hold is invalid")
		}
	case "reconciling":
		if value.EffectState != "unknown" || !positive(value.HoldVersion) || value.Archived || value.ResultCode != "" || value.NodeReceipt != nil {
			return errors.New("logical delete reconciliation state is invalid")
		}
	case "succeeded":
		if value.EffectState != "reconciled" || !codePattern.MatchString(value.ResultCode) {
			return errors.New("logical delete success state is invalid")
		}
		if value.Archived {
			if value.HoldVersion != 0 || value.NodeReceipt != nil || value.ResultCode != "archive_tombstoned" {
				return errors.New("logical delete archive state is invalid")
			}
		} else if !positive(value.HoldVersion) || value.NodeReceipt == nil || !statusReceiptMatches(value, *value.NodeReceipt) || value.ResultCode != "node_tombstoned" {
			return errors.New("logical delete node receipt is missing")
		}
	case "failed":
		if value.EffectState != "failed" || value.HoldVersion < 0 || value.HoldVersion > MaximumSafeInt ||
			value.Archived || !codePattern.MatchString(value.ResultCode) || value.NodeReceipt != nil {
			return errors.New("logical delete failure state is invalid")
		}
	}
	return nil
}

func statusReceiptMatches(status Status, receipt NodeReceipt) bool {
	return ValidateNodeReceipt(receipt) == nil && receipt.OperationID == status.OperationID &&
		receipt.CoordinatorRequestHash == status.RequestHash && receipt.CommandID == status.CommandID &&
		receipt.LogicalDialogID == status.LogicalDialogID && receipt.NodeID == status.NodeID &&
		receipt.NodeDialogID == status.NodeDialogID && receipt.Epoch == status.IdentityEpoch &&
		receipt.RegistryVersion == status.RegistryVersion && receipt.BindingVersion == status.ExpectedBindingVersion &&
		receipt.DeletedDialogVersion == status.ExpectedDialogVersion+1 && receipt.HoldVersion == status.HoldVersion &&
		receipt.HoldScopeRevision == status.HoldScopeRevision
}

func ValidateAdvance(value AdvanceRequest) error {
	if value.SchemaID != AdvanceSchemaID || !validUUID(value.OperationID) || !sha256Pattern.MatchString(value.RequestHash) ||
		!positive(value.ExpectedOperationVersion) || !oneOf(value.Action, "hold", "unknown", "complete", "reject") {
		return errors.New("logical delete advance is invalid")
	}
	switch value.Action {
	case "hold":
		if !positive(value.HoldVersion) || !positive(value.ObservedHoldScopeRevision) || value.NodeReceipt != nil || value.ResultCode != "" {
			return errors.New("logical delete hold advance is invalid")
		}
	case "unknown":
		if value.HoldVersion != 0 || value.ObservedHoldScopeRevision != 0 || value.NodeReceipt != nil || value.ResultCode != "" {
			return errors.New("logical delete unknown advance is invalid")
		}
	case "complete":
		if value.HoldVersion != 0 || value.ObservedHoldScopeRevision != 0 || value.NodeReceipt == nil || ValidateNodeReceipt(*value.NodeReceipt) != nil || value.ResultCode != "" {
			return errors.New("logical delete completion is invalid")
		}
	case "reject":
		if value.HoldVersion != 0 || value.NodeReceipt != nil || !codePattern.MatchString(value.ResultCode) ||
			value.ObservedHoldScopeRevision < 0 || value.ObservedHoldScopeRevision > MaximumSafeInt {
			return errors.New("logical delete rejection is invalid")
		}
	}
	return nil
}

func ValidateNodeRequest(value NodeRequest) error {
	if value.SchemaID != NodeSchemaID || !validUUID(value.OperationID) || !sha256Pattern.MatchString(value.CoordinatorRequestHash) ||
		!validUUID(value.CommandID) || !validUUID(value.LogicalDialogID) || !validUUID(value.NodeID) ||
		!validUUID(value.NodeDialogID) || !positive(value.ExpectedEpoch) || !positive(value.RegistryVersion) ||
		!positive(value.BindingVersion) || !incrementable(value.ExpectedDialogVersion) || !positive(value.HoldVersion) ||
		!positive(value.HoldScopeRevision) {
		return errors.New("node logical delete request is invalid")
	}
	return nil
}

func NodeRequestHash(value NodeRequest) (string, error) {
	if err := ValidateNodeRequest(value); err != nil {
		return "", err
	}
	return hash(value)
}

func ValidateNodeReceipt(value NodeReceipt) error {
	if value.SchemaID != NodeSchemaID || !validUUID(value.OperationID) || !sha256Pattern.MatchString(value.NodeRequestHash) ||
		!sha256Pattern.MatchString(value.CoordinatorRequestHash) || !validUUID(value.ReceiptID) || !validUUID(value.CommandID) ||
		!validUUID(value.LogicalDialogID) || !validUUID(value.NodeID) || !validUUID(value.NodeDialogID) ||
		!positive(value.Epoch) || !positive(value.RegistryVersion) || !positive(value.BindingVersion) ||
		!positive(value.DeletedDialogVersion) || !positive(value.HoldVersion) || !positive(value.HoldScopeRevision) ||
		!positive(value.TombstoneEventSeq) || !validCommandReceipt(value) {
		return errors.New("node logical delete receipt is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, value.DeletedAt); err != nil {
		return errors.New("node logical delete receipt time is invalid")
	}
	return nil
}

func validCommandReceipt(value NodeReceipt) bool {
	if harnessprotocol.Validate("receipt", value.CommandReceipt) != nil {
		return false
	}
	var receipt harnessprotocol.Receipt
	var references harnessprotocol.DialogDeleteReferences
	return json.Unmarshal(value.CommandReceipt, &receipt) == nil && json.Unmarshal(receipt.References, &references) == nil &&
		receipt.ProtocolVersion == harnessprotocol.ProtocolVersion && receipt.SchemaID == harnessprotocol.SchemaID &&
		receipt.CommandID == value.CommandID && receipt.CommandKind == harnessprotocol.CommandDialogDelete &&
		receipt.NodeID == value.NodeID && receipt.EventSeq == value.TombstoneEventSeq && receipt.Result == "deleted" &&
		receipt.AcceptedAt == value.DeletedAt && references.DialogID == value.NodeDialogID
}

func ValidateClosure(value ClosureDescriptor) error {
	if !validUUID(value.LogicalDialogID) || !positive(value.BindingVersion) || !validUUID(value.NodeID) ||
		!validUUID(value.NodeDialogID) || !positive(value.DialogVersion) || !positive(value.DescriptorVersion) ||
		!value.ZeroPending || len(value.FinalCheckpoint) == 0 || !sha256Pattern.MatchString(value.FinalCheckpointSHA256) {
		return errors.New("logical dialog closure is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, value.VerifiedAt); err != nil {
		return errors.New("logical dialog closure time is invalid")
	}
	digest := sha256.Sum256(value.FinalCheckpoint)
	if hex.EncodeToString(digest[:]) != value.FinalCheckpointSHA256 {
		return errors.New("logical dialog closure checkpoint hash is invalid")
	}
	return nil
}

func validUUID(value string) bool { return uuidPattern.MatchString(value) }

func positive(value int64) bool { return value >= 1 && value <= MaximumSafeInt }

func incrementable(value int64) bool { return value >= 1 && value < MaximumSafeInt }

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func hash(value any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}
