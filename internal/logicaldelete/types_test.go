package logicaldelete

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

func validNodeReceipt(t *testing.T) NodeReceipt {
	t.Helper()
	deletedAt := "2026-09-17T10:00:00Z"
	references, _ := json.Marshal(harnessprotocol.DialogDeleteReferences{DialogID: "61000000-0000-4000-8000-000000000004"})
	commandReceipt, _ := json.Marshal(harnessprotocol.Receipt{
		ProtocolVersion: harnessprotocol.ProtocolVersion, SchemaID: harnessprotocol.SchemaID,
		CommandID: "61000000-0000-4000-8000-000000000002", CommandKind: harnessprotocol.CommandDialogDelete,
		ReceiptID: "61000000-0000-4000-8000-000000000005", AcceptedAt: deletedAt,
		NodeID: "61000000-0000-4000-8000-000000000003", EventSeq: 9, Result: "deleted", References: references,
	})
	return NodeReceipt{
		SchemaID: NodeSchemaID, OperationID: "61000000-0000-4000-8000-000000000001",
		NodeRequestHash: strings.Repeat("a", 64), CoordinatorRequestHash: strings.Repeat("b", 64),
		ReceiptID: "61000000-0000-4000-8000-000000000006", CommandID: "61000000-0000-4000-8000-000000000002",
		LogicalDialogID: "61000000-0000-4000-8000-000000000007",
		NodeID:          "61000000-0000-4000-8000-000000000003", NodeDialogID: "61000000-0000-4000-8000-000000000004",
		Epoch: 1, RegistryVersion: 1, BindingVersion: 1, DeletedDialogVersion: 3,
		HoldVersion: 1, HoldScopeRevision: 2, TombstoneEventSeq: 9,
		CommandReceipt: commandReceipt, DeletedAt: deletedAt,
	}
}

func TestContractsRejectOverflowAndForgedEmbeddedReceipt(t *testing.T) {
	request := Request{
		SchemaID: SchemaID, OperationID: "61000000-0000-4000-8000-000000000001",
		CommandID:              "61000000-0000-4000-8000-000000000002",
		LogicalDialogID:        "61000000-0000-4000-8000-000000000003",
		ExpectedBindingVersion: 1, ExpectedDialogVersion: MaximumSafeInt,
	}
	if ValidateRequest(request) == nil {
		t.Fatal("increment overflow was accepted")
	}
	receipt := validNodeReceipt(t)
	if err := ValidateNodeReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	var command map[string]any
	if json.Unmarshal(receipt.CommandReceipt, &command) != nil {
		t.Fatal("cannot decode command receipt")
	}
	command["commandId"] = "61000000-0000-4000-8000-000000000099"
	receipt.CommandReceipt, _ = json.Marshal(command)
	if ValidateNodeReceipt(receipt) == nil {
		t.Fatal("forged embedded command receipt was accepted")
	}
}

func TestAdvanceJSONKeepsCompleteExactShape(t *testing.T) {
	raw, err := json.Marshal(AdvanceRequest{
		SchemaID: AdvanceSchemaID, OperationID: "61000000-0000-4000-8000-000000000001",
		RequestHash: strings.Repeat("a", 64), ExpectedOperationVersion: 1, Action: "unknown",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"holdVersion":0`, `"observedHoldScopeRevision":0`, `"resultCode":""`, `"nodeReceipt":null`} {
		if !strings.Contains(string(raw), field) {
			t.Fatalf("advance JSON omitted %s: %s", field, raw)
		}
	}
}

func TestAdvanceRejectsUnusedAndUnsafeFields(t *testing.T) {
	base := AdvanceRequest{
		SchemaID: AdvanceSchemaID, OperationID: "61000000-0000-4000-8000-000000000001",
		RequestHash: strings.Repeat("a", 64), ExpectedOperationVersion: 1, Action: "unknown",
	}
	if err := ValidateAdvance(base); err != nil {
		t.Fatal(err)
	}
	withUnused := base
	withUnused.HoldVersion = 1
	if ValidateAdvance(withUnused) == nil {
		t.Fatal("unused holdVersion was accepted for unknown transition")
	}
	unsafeReject := base
	unsafeReject.Action = "reject"
	unsafeReject.ObservedHoldScopeRevision = 2
	unsafeReject.ResultCode = "unsafe result"
	if ValidateAdvance(unsafeReject) == nil {
		t.Fatal("unsafe rejection result code was accepted")
	}
}

func TestStatusRejectsImpossiblePhaseCombinations(t *testing.T) {
	status := Status{
		SchemaID: SchemaID, OperationID: "61000000-0000-4000-8000-000000000001",
		RequestHash: strings.Repeat("a", 64), CommandID: "61000000-0000-4000-8000-000000000002",
		LogicalDialogID: "61000000-0000-4000-8000-000000000003", ExpectedBindingVersion: 1,
		ExpectedDialogVersion: 2, NodeID: "61000000-0000-4000-8000-000000000004",
		NodeDialogID: "61000000-0000-4000-8000-000000000005", RegistryVersion: 1, IdentityEpoch: 1,
		Phase: "accepted", EffectState: "not_sent", OperationVersion: 1, UpdatedAt: "2026-09-17T10:00:00Z",
	}
	if err := ValidateStatus(status); err != nil {
		t.Fatal(err)
	}
	status.EffectState = "sent"
	if ValidateStatus(status) == nil {
		t.Fatal("accepted phase with sent effect was accepted")
	}
	status.Phase, status.EffectState, status.ResultCode = "failed", "failed", "hold_rejected"
	if err := ValidateStatus(status); err != nil {
		t.Fatalf("pre-hold failure was rejected: %v", err)
	}
	preHoldReject := AdvanceRequest{
		SchemaID: AdvanceSchemaID, OperationID: status.OperationID, RequestHash: status.RequestHash,
		ExpectedOperationVersion: 1, Action: "reject", ResultCode: "hold_rejected",
	}
	if err := ValidateAdvance(preHoldReject); err != nil {
		t.Fatalf("zero-revision pre-hold rejection was rejected: %v", err)
	}
}
