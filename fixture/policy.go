package fixture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
)

type PolicySource struct {
	Policy harnessadapter.PolicySnapshot
	Err    error
}

func NewPolicySource() *PolicySource {
	policy := harnessadapter.PolicySnapshot{
		Revision: "fixture-policy@1", Content: []byte("fixture policy"), ToolManifest: []byte("fixture tools"),
		ApprovalMode: harnessadapter.ApprovalModeExplicitOnce,
	}
	policy.ContentHash = fixtureDigest(policy.Content)
	policy.ToolManifestHash = fixtureDigest(policy.ToolManifest)
	policy.EffectiveHash = harnessadapter.EffectivePolicyHash(policy)
	return &PolicySource{Policy: policy}
}

func (source *PolicySource) Current(context.Context, string) (harnessadapter.PolicySnapshot, error) {
	return source.Policy, source.Err
}

func fixtureDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
