package codex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineUnsupportedModelProofRequiresExactNativeNoEffectTurn(t *testing.T) {
	stateDir, home := filepath.Join(t.TempDir(), "state"), filepath.Join(t.TempDir(), "codex-home")
	store, err := openMappingStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	process, err := store.beginProcess()
	if err != nil {
		t.Fatal(err)
	}
	ref := codexTestReference(1)
	thread, turn := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	if err := store.putIntent("start", ref, codexTestBoundary(1), strings.Repeat("a", 64), strings.Repeat("b", 64), ""); err != nil {
		t.Fatal(err)
	}
	if err := store.acknowledgeThread(ref, thread, process); err != nil {
		t.Fatal(err)
	}
	if err := store.beginTurn(ref); err != nil {
		t.Fatal(err)
	}
	if err := store.activate(ref, turn, process); err != nil {
		t.Fatal(err)
	}
	if err := store.terminal(ref); err != nil {
		t.Fatal(err)
	}
	if _, err := store.beginProcess(); err != nil {
		t.Fatal(err)
	}
	adapter, err := NewUnsupportedModelRecoveryAdapter(stateDir, home, "gpt-5.2-codex")
	if err != nil {
		t.Fatal(err)
	}
	relative := "sessions/2026/09/23/rollout-2026-09-23T10-16-49-" + thread + ".jsonl"
	path := filepath.Join(home, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	valid := []map[string]any{
		{"type": "session_meta", "payload": map[string]any{"id": thread}},
		{"type": "event_msg", "payload": map[string]any{"type": "task_started", "turn_id": turn}},
		{"type": "response_item", "payload": map[string]any{"type": "message", "role": "developer"}},
		{"type": "turn_context", "payload": map[string]any{"turn_id": turn, "model": "gpt-5.2-codex"}},
		{"type": "event_msg", "payload": map[string]any{"type": "item_completed", "thread_id": thread, "turn_id": turn, "item": map[string]any{"type": "UserMessage"}}},
		{"type": "event_msg", "payload": map[string]any{"type": "task_complete", "turn_id": turn, "last_agent_message": "", "error": map[string]any{
			"message":          `{"type":"error","status":400,"error":{"type":"invalid_request_error","message":"The 'gpt-5.2-codex' model is not supported when using Codex with a ChatGPT account."}}`,
			"codex_error_info": "other"}}},
	}
	write := func(records []map[string]any) string {
		t.Helper()
		var raw []byte
		for _, record := range records {
			line, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, line...)
			raw = append(raw, '\n')
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		return hex.EncodeToString(digest[:])
	}
	sha := write(valid)
	if err := adapter.ConfirmUnsupportedModelRejection(context.Background(), ref, relative, sha, 2); err != nil {
		t.Fatalf("valid proof: %v", err)
	}
	if err := adapter.ConfirmUnsupportedModelRejection(context.Background(), ref, relative, strings.Repeat("0", 64), 2); err == nil {
		t.Fatal("wrong rollout hash accepted")
	}
	if err := adapter.ConfirmUnsupportedModelRejection(context.Background(), ref, relative, sha, 3); err == nil {
		t.Fatal("wrong process fence accepted")
	}
	for name, mutate := range map[string]func([]map[string]any){
		"other_turn": func(records []map[string]any) {
			records[5]["payload"].(map[string]any)["turn_id"] = "33333333-3333-4333-8333-333333333333"
		},
		"assistant_activity": func(records []map[string]any) { records[2]["payload"].(map[string]any)["role"] = "assistant" },
		"tool_activity": func(records []map[string]any) {
			records[4]["payload"].(map[string]any)["item"] = map[string]any{"type": "CommandExecution"}
		},
		"generic_failure": func(records []map[string]any) {
			records[5]["payload"].(map[string]any)["error"].(map[string]any)["message"] = "failed"
		},
		"cancel_event": func(records []map[string]any) { records[4]["payload"].(map[string]any)["type"] = "turn_cancelled" },
	} {
		t.Run(name, func(t *testing.T) {
			copyRecords := make([]map[string]any, len(valid))
			for i, record := range valid {
				encoded, _ := json.Marshal(record)
				_ = json.Unmarshal(encoded, &copyRecords[i])
			}
			mutate(copyRecords)
			if err := adapter.ConfirmUnsupportedModelRejection(context.Background(), ref, relative, write(copyRecords), 2); err == nil {
				t.Fatal("unsafe native proof accepted")
			}
		})
	}
	for name, records := range map[string][]map[string]any{
		"post_terminal":     append(append([]map[string]any{}, valid...), map[string]any{"type": "response_item", "payload": map[string]any{"type": "message", "role": "user"}}),
		"missing_session":   valid[1:],
		"duplicate_context": append(append([]map[string]any{}, valid[:5]...), append([]map[string]any{valid[3]}, valid[5:]...)...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := adapter.ConfirmUnsupportedModelRejection(context.Background(), ref, relative, write(records), 2); err == nil {
				t.Fatal("incomplete or postterminal rollout accepted")
			}
		})
	}
	sha = write(valid)
	linkedHome := filepath.Join(t.TempDir(), "linked-home")
	if err := os.Symlink(home, linkedHome); err != nil {
		t.Fatal(err)
	}
	linked, err := NewUnsupportedModelRecoveryAdapter(stateDir, linkedHome, "gpt-5.2-codex")
	if err != nil {
		t.Fatal(err)
	}
	if err := linked.ConfirmUnsupportedModelRejection(context.Background(), ref, relative, sha, 2); err == nil {
		t.Fatal("symlinked native root accepted")
	}
}
