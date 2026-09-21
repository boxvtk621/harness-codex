package harnessadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

func TestExactAdapterPinsAndCapabilities(t *testing.T) {
	for _, test := range []struct {
		kind    Kind
		version string
	}{{KindCursor, CursorSDKVersion}, {KindCodex, CodexAppServerVersion}} {
		declared, verified := map[Capability]bool{}, map[Capability]bool{}
		for _, capability := range mandatoryCapabilities {
			declared[capability], verified[capability] = true, true
		}
		identity := Identity{Kind: test.kind, Version: test.version, ProtocolVersion: harnessprotocol.ProtocolVersion, SchemaID: harnessprotocol.SchemaID, SchemaSHA256: harnessprotocol.SchemaSHA256, Declared: declared, Verified: verified}
		if err := ValidateIdentity(identity); err != nil {
			t.Fatalf("valid %s identity: %v", test.kind, err)
		}
		identity.Verified[CapabilitySteerAttached] = false
		if err := ValidateIdentity(identity); err == nil {
			t.Fatalf("unverified %s steer accepted", test.kind)
		}
	}
}

func TestPolicySnapshotRequiresExactContent(t *testing.T) {
	policy := []byte("policy content")
	tools := []byte(`[{"name":"read"}]`)
	policySum := sha256.Sum256(policy)
	toolsSum := sha256.Sum256(tools)
	snapshot := PolicySnapshot{
		Revision: "hl-a-600@0.1", Content: policy, ContentHash: hex.EncodeToString(policySum[:]),
		ToolManifest: tools, ToolManifestHash: hex.EncodeToString(toolsSum[:]), ApprovalMode: ApprovalModeExplicitOnce,
	}
	snapshot.EffectiveHash = EffectivePolicyHash(snapshot)
	prepared, err := PreparePolicySnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	policy[0] = 'P'
	tools[0] = '{'
	if string(prepared.Content) != "policy content" || string(prepared.ToolManifest) != `[{"name":"read"}]` {
		t.Fatal("prepared policy retained caller-owned bytes")
	}
	snapshot.Content = []byte("changed")
	if err := ValidatePolicySnapshot(snapshot); err == nil {
		t.Fatal("policy hash mismatch accepted")
	}
	snapshot.Content = []byte("policy content")
	snapshot.ApprovalMode = "native"
	if err := ValidatePolicySnapshot(snapshot); err == nil {
		t.Fatal("unknown approval mode accepted")
	}
}

func TestOutcomesKeepUnknownAndAcknowledgedDistinct(t *testing.T) {
	if SteerApplied == SteerFallbackQueued || SteerFallbackQueued == SteerUnknown {
		t.Fatal("steer outcomes collapsed")
	}
	if CancelAcknowledged == CancelUnknown {
		t.Fatal("cancel ACK collapsed into unknown")
	}
	if ReconcileCompleted == ReconcileUnknown || ReconcileInterrupted == ReconcileUnknown {
		t.Fatal("terminal outcome collapsed into unknown")
	}
	if ResponseApplied == ResponseUnknown || ResponseRejected == ResponseUnknown {
		t.Fatal("native response outcome collapsed into unknown")
	}
}
