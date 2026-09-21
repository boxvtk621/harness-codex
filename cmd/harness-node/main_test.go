package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
)

func TestExplicitToolWorkspaceIsPinned(t *testing.T) {
	for _, test := range []struct {
		name, adapter, workingDir string
		wantErr                   bool
	}{
		{name: "codex", adapter: "Codex", workingDir: "/workspace"},
		{name: "missing", adapter: "Codex", wantErr: true},
		{name: "different absolute path", adapter: "Codex", workingDir: "/tmp/workspace", wantErr: true},
		{name: "relative path", adapter: "Codex", workingDir: "workspace", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateExplicitToolWorkspace(test.adapter, test.workingDir)
			if (err != nil) != test.wantErr {
				t.Fatalf("validate explicit tool workspace = %v", err)
			}
		})
	}
}

func TestSelectedAdapterRequiresExplicitCodex(t *testing.T) {
	tests := []struct {
		name string
		cfg  config
		want string
	}{
		{name: "explicit codex", cfg: config{Adapter: "codex", Codex: &codexConfig{}}, want: "codex"},
		{name: "missing selector for codex", cfg: config{Codex: &codexConfig{}}, want: ""},
		{name: "unknown selector", cfg: config{Adapter: "unknown", Codex: &codexConfig{}}, want: "unknown"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := selectedAdapter(test.cfg); got != test.want {
				t.Fatalf("selected adapter = %q, want %q", got, test.want)
			}
		})
	}
}

func TestProviderSelectionRejectsMissingAndUnknown(t *testing.T) {
	for _, test := range []struct {
		name string
		cfg  config
		ok   bool
	}{
		{name: "missing"},
		{name: "missing selector", cfg: config{Codex: &codexConfig{}}},
		{name: "unknown", cfg: config{Adapter: "unknown", Codex: &codexConfig{}}},
		{name: "codex", cfg: config{Adapter: "codex", Codex: &codexConfig{}}, ok: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateProviderSelection(test.cfg)
			if (err == nil) != test.ok {
				t.Fatalf("validate provider selection = %v", err)
			}
		})
	}
}

func TestPeerPinsRejectEquivalentHexWithDifferentCase(t *testing.T) {
	if err := validatePeerPins(strings.Repeat("a1", 32), strings.Repeat("A1", 32)); err == nil {
		t.Fatal("the same certificate pin with different hex casing was accepted")
	}
	if err := validatePeerPins(strings.Repeat("a1", 32), strings.Repeat("b2", 32)); err != nil {
		t.Fatal("distinct certificate pins were rejected", err)
	}
}

func TestLoadConfigRejectsCursorAndAmbiguousProviderFields(t *testing.T) {
	for _, raw := range []string{
		`{"adapter":"cursor","cursor":{"workingDir":"/workspace"}}`,
		`{"adapter":"codex","codex":{},"cursor":{}}`,
	} {
		path := filepath.Join(t.TempDir(), "node.json")
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Fatal("unsupported provider field was accepted")
		}
	}
}

func TestFilePolicyPreservesLegacyDeny(t *testing.T) {
	for _, test := range []struct {
		name, manifest string
	}{
		{name: "compact", manifest: "[]\n"},
		{name: "formatted", manifest: "[  ]\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			contentPath, manifestPath := filepath.Join(root, "policy.txt"), filepath.Join(root, "tools.json")
			if err := os.WriteFile(contentPath, []byte("policy\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifestPath, []byte(test.manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			policy, err := (filePolicy{contentPath: contentPath, manifestPath: manifestPath, revision: "test@1"}).Current(context.Background(), "node")
			if err != nil || policy.ApprovalMode != harnessadapter.ApprovalModeDeny {
				t.Fatalf("policy = %#v, %v", policy, err)
			}
		})
	}
}

func TestFilePolicyAcceptsOnlyExactExplicitOnceManifestForAdapter(t *testing.T) {
	for _, test := range []struct{ name, adapter, manifest string }{
		{name: "codex", adapter: "codex", manifest: codexExplicitToolManifest},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			contentPath, manifestPath := filepath.Join(root, "policy.txt"), filepath.Join(root, "tools.json")
			if err := os.WriteFile(contentPath, []byte("policy\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifestPath, []byte(test.manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			policy, err := (filePolicy{contentPath: contentPath, manifestPath: manifestPath, revision: "agent-tools-v1", approvalMode: "explicit_once", adapter: test.adapter}).Current(context.Background(), "node")
			if err != nil || policy.ApprovalMode != harnessadapter.ApprovalModeExplicitOnce || string(policy.ToolManifest) != test.manifest {
				t.Fatalf("policy = %#v, %v", policy, err)
			}
		})
	}
}

func TestFilePolicyFailsClosedForMismatchedModeOrManifest(t *testing.T) {
	for _, test := range []struct{ name, adapter, mode, manifest string }{
		{name: "explicit missing lf", adapter: "codex", mode: "explicit_once", manifest: strings.TrimSuffix(codexExplicitToolManifest, "\n")},
		{name: "wrong adapter", adapter: "unknown", mode: "explicit_once", manifest: codexExplicitToolManifest},
		{name: "wrong order", adapter: "codex", mode: "explicit_once", manifest: `[{"name":"codex.file_change"},{"name":"codex.command"}]` + "\n"},
		{name: "unknown tool", adapter: "codex", mode: "explicit_once", manifest: `[{"name":"unsafe"}]`},
		{name: "deny nonempty", adapter: "codex", mode: "deny", manifest: codexExplicitToolManifest},
		{name: "invalid mode", adapter: "codex", mode: "allow", manifest: "[]\n"},
		{name: "invalid", adapter: "codex", mode: "deny", manifest: `{}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			contentPath, manifestPath := filepath.Join(root, "policy.txt"), filepath.Join(root, "tools.json")
			if err := os.WriteFile(contentPath, []byte("policy\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifestPath, []byte(test.manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := (filePolicy{contentPath: contentPath, manifestPath: manifestPath, revision: "test@1", approvalMode: test.mode, adapter: test.adapter}).Current(context.Background(), "node"); err == nil {
				t.Fatal("unsafe manifest was accepted")
			}
		})
	}
}
