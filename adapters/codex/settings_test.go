package codex

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/internal/nodesettings"
)

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
			model, effort, speed := "fixture-entitled-model", "high", "priority"
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
	model, effort, speed := "fixture-entitled-model", "high", "priority"
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
