package codex

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/internal/nodesettings"
)

func TestNativeInferenceMappingForIndependentAndResetChanges(t *testing.T) {
	model, effort, defaultEffort, on, off := "fixture-entitled-model", "high", "medium", "on", "off"
	cases := []struct {
		name       string
		settings   activeSettings
		wantModel  *string
		wantEffort *string
		wantTier   string
	}{
		{"model-only", activeSettings{Model: model, Effort: effort}, &model, &effort, "default"},
		{"speed-only", activeSettings{Effort: defaultEffort, Speed: &on}, nil, &defaultEffort, "priority"},
		{"reasoning-only", activeSettings{Effort: effort}, nil, &effort, "default"},
		{"default", activeSettings{Effort: defaultEffort}, nil, &defaultEffort, "default"},
		{"reset", activeSettings{Effort: defaultEffort, Speed: &off}, nil, &defaultEffort, "default"},
		{"joint", activeSettings{Model: model, Effort: effort, Speed: &on}, &model, &effort, "priority"},
	}
	adapter := &Adapter{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, resume := range []bool{false, true} {
				options := adapter.threadOptionsWithSettings(adapterPolicy(), "/workspace", false, tc.settings)
				if resume {
					options.ThreadID = "existing-thread"
				}
				encoded, err := json.Marshal(options)
				if err != nil {
					t.Fatal(err)
				}
				var wire map[string]any
				if err := json.Unmarshal(encoded, &wire); err != nil {
					t.Fatal(err)
				}
				if wire["model"] != pointerValue(tc.wantModel) || wire["serviceTier"] != tc.wantTier {
					t.Fatalf("thread start/resume mismatch: %s", encoded)
				}
				config := wire["config"].(map[string]any)
				if config["model_reasoning_effort"] != pointerValue(tc.wantEffort) {
					t.Fatalf("thread effort mismatch: %s", encoded)
				}
			}
			turn := turnParamsWithSettings("thread", "prompt", "message", "/workspace", tc.settings)
			encoded, _ := json.Marshal(turn)
			var wire map[string]any
			_ = json.Unmarshal(encoded, &wire)
			if wire["model"] != pointerValue(tc.wantModel) || wire["effort"] != pointerValue(tc.wantEffort) || wire["serviceTier"] != tc.wantTier {
				t.Fatalf("turn mismatch: %s", encoded)
			}
		})
	}
}

func pointerValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func TestNativeStdioMCPMapping(t *testing.T) {
	server := nodesettings.MCPConfig{MCPServer: nodesettings.MCPServer{ID: "local", Enabled: true, Transport: "stdio", Command: "/usr/bin/mcp-local", Args: []string{"serve"}, TimeoutMS: 2000}, SecretValues: map[string]string{"API_KEY": "fixture-secret"}}
	adapter := &Adapter{}
	options := adapter.threadOptionsWithSettings(adapterPolicy(), "/workspace", false, activeSettings{MCPServers: []nodesettings.MCPConfig{server}})
	entry := options.Config["mcp_servers"].(map[string]any)["local"].(map[string]any)
	if entry["command"] != "/usr/bin/mcp-local" || entry["url"] != nil || entry["env"].(map[string]string)["API_KEY"] != "fixture-secret" {
		t.Fatalf("native stdio entry missing: %#v", entry)
	}
}

func TestManagedSettingsRestartAndRollback(t *testing.T) {
	for _, failStart := range []bool{false, true} {
		t.Run(map[bool]string{false: "apply", true: "rollback"}[failStart], func(t *testing.T) {
			config := testAdapterConfig(t, 5*time.Second)
			if failStart {
				config.Environment = append(config.Environment, "CODEX_SETTINGS_FAIL_FOR_MCP_B=1")
			}
			adapter, err := New(config, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()
			before := adapter.session.ProcessGeneration()
			model, effort, speed := "fixture-entitled-model", "high", "on"
			settings := nodesettings.Settings{Inference: nodesettings.Inference{ModelID: &model, ReasoningEffort: &effort, SpeedMode: &speed}}
			servers := []nodesettings.MCPConfig{{MCPServer: nodesettings.MCPServer{ID: "B", Name: "B", Enabled: true, URL: "https://mcp.example.test/rpc", Transport: "streamable_http", TimeoutMS: 1000, Auth: nodesettings.MCPAuth{Kind: "bearer"}}, BearerToken: "secret-fixture"}}
			if err := adapter.PreflightSettings(context.Background(), settings, servers); err != nil {
				t.Fatal(err)
			}
			err = adapter.ApplySettings(context.Background(), settings, servers)
			if failStart {
				if err == nil {
					t.Fatal("expected startup failure")
				}
				if adapter.session == nil || adapter.settings.Model != "fixture-model" || adapter.session.ProcessGeneration() <= before {
					t.Fatal("previous process was not restored")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			check, err := adapter.CheckMCP(context.Background(), servers[0])
			if err != nil || check.Status != "available" {
				t.Fatalf("native MCP check = %+v, %v", check, err)
			}
			if adapter.session.ProcessGeneration() != before+1 || adapter.settings.Model != model || adapter.settings.Effort != effort || adapter.settings.Speed == nil || *adapter.settings.Speed != speed {
				t.Fatal("new process did not use requested inference")
			}
			options := adapter.threadOptions(adapterPolicy(), config.WorkingDir, false)
			if _, ok := options.Config["mcp_servers"].(map[string]any)["B"]; !ok {
				t.Fatal("MCP B missing from thread options")
			}
			if os.Getenv(mcpTokenVariable("B")) != "" {
				t.Fatal("secret leaked to parent process")
			}
		})
	}
}

func TestManagedSettingsConcurrentRead(t *testing.T) {
	config := testAdapterConfig(t, 5*time.Second)
	adapter, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	model, effort, speed := "fixture-entitled-model", "high", "on"
	settings := nodesettings.Settings{Inference: nodesettings.Inference{ModelID: &model, ReasoningEffort: &effort, SpeedMode: &speed}}
	server := nodesettings.MCPConfig{MCPServer: nodesettings.MCPServer{ID: "B", Name: "B", Enabled: true, URL: "https://mcp.example.test/rpc", Transport: "streamable_http", TimeoutMS: 1000, Auth: nodesettings.MCPAuth{Kind: "none"}}}
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		for i := 0; i < 20; i++ {
			_ = adapter.currentSettings()
			_ = adapter.threadOptions(adapterPolicy(), config.WorkingDir, false)
			_, _ = adapter.CheckMCP(context.Background(), server)
		}
	}()
	if err := adapter.ApplySettings(context.Background(), settings, []nodesettings.MCPConfig{server}); err != nil {
		t.Fatal(err)
	}
	readers.Wait()
}

func TestManagedSettingsResetUsesNativeDefaults(t *testing.T) {
	config := testAdapterConfig(t, 5*time.Second)
	adapter, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	model := "fixture-entitled-model"
	modelOnly := nodesettings.Settings{Inference: nodesettings.Inference{ModelID: &model}}
	if err := adapter.PreflightSettings(context.Background(), modelOnly, nil); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ApplySettings(context.Background(), modelOnly, nil); err != nil {
		t.Fatal(err)
	}
	if adapter.settings.Model != model || adapter.settings.Effort != "high" {
		t.Fatalf("model-only selection did not resolve model default reasoning: %+v", adapter.settings)
	}
	settings := nodesettings.Settings{Inference: nodesettings.Inference{}}
	if err := adapter.PreflightSettings(context.Background(), settings, nil); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ApplySettings(context.Background(), settings, nil); err != nil {
		t.Fatal(err)
	}
	if adapter.settings.Model != "" || adapter.settings.Effort != "medium" {
		t.Fatalf("native defaults not selected: %+v", adapter.settings)
	}
	options := adapter.threadOptions(adapterPolicy(), config.WorkingDir, false)
	if options.Model != nil || options.ServiceTier == nil || *options.ServiceTier != "default" {
		t.Fatalf("wrong native reset mapping: %+v", options)
	}
}
