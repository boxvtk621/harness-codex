package codex

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	node "github.com/boxvtk621/harness-codex/runtime"
)

// This deliberately uses the real runtime action loop and Codex adapter, with
// only the native process replaced by the existing deterministic subprocess.
// In particular, the test never manufactures or injects FailedTailRetry proof.
func TestRuntimeDispatchCarriesFailedTailProofToNativeResume(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	adapterConfig := testAdapterConfig(t, 3*time.Second)
	dataDir := t.TempDir()
	trust := node.TrustContext{TransportNodeID: adapterConfig.NodeID}
	var adapter *Adapter
	var authority *node.Node
	open := func() {
		t.Helper()
		var err error
		adapter, err = New(adapterConfig, nil)
		if err != nil {
			t.Fatal(err)
		}
		authority, err = node.Open(ctx, node.Config{DataDir: dataDir, NodeID: adapterConfig.NodeID,
			OwnerID: "retry-integration", RegistryVersion: 1, Adapter: adapter,
			Policies: &fixture.PolicySource{Policy: adapterPolicy()}, ManualDispatchForTesting: true})
		if err != nil {
			_ = adapter.Close()
			t.Fatal(err)
		}
	}
	close := func() {
		t.Helper()
		if authority != nil {
			if err := authority.Close(); err != nil {
				t.Fatal(err)
			}
			authority = nil
		}
		if adapter != nil {
			if err := adapter.Close(); err != nil {
				t.Fatal(err)
			}
			adapter = nil
		}
	}
	open()
	defer close()
	commandSequence := 0
	command := func(kind string, target, expected, payload map[string]any) harnessprotocol.Receipt {
		t.Helper()
		commandSequence++
		target["nodeId"] = adapterConfig.NodeID
		body, err := json.Marshal(map[string]any{"protocolVersion": 1, "schemaId": harnessprotocol.SchemaID,
			"commandId": fmt.Sprintf("31800000-0000-4000-8000-%012d", commandSequence), "kind": kind,
			"target": target, "expected": expected, "payload": payload})
		if err != nil {
			t.Fatal(err)
		}
		result := authority.SubmitCommand(ctx, trust, body)
		if result.HTTPStatus != 202 {
			t.Fatalf("%s: %d %s", kind, result.HTTPStatus, result.Body)
		}
		var receipt harnessprotocol.Receipt
		if err := json.Unmarshal(result.Body, &receipt); err != nil {
			t.Fatal(err)
		}
		return receipt
	}
	created := command("dialog.create", map[string]any{}, map[string]any{"registryVersion": 1}, map[string]any{})
	var dialogRef harnessprotocol.DialogCreateReferences
	if err := json.Unmarshal(created.References, &dialogRef); err != nil {
		t.Fatal(err)
	}
	dispatch := func(expectedState string) harnessprotocol.Attempt {
		t.Helper()
		started, err := authority.DispatchNext(ctx)
		if err != nil || started.AttemptID == "" {
			t.Fatalf("dispatch: %+v %v", started, err)
		}
		for ctx.Err() == nil {
			result := authority.Attempt(ctx, trust, started.AttemptID)
			var read struct {
				Attempt harnessprotocol.Attempt `json:"attempt"`
			}
			if result.HTTPStatus != 200 || json.Unmarshal(result.Body, &read) != nil {
				t.Fatalf("attempt: %s", result.Body)
			}
			if read.Attempt.State == "completed" || read.Attempt.State == "failed" || read.Attempt.State == "unknown" || read.Attempt.State == "interrupted" {
				if read.Attempt.State != expectedState {
					t.Fatalf("attempt state=%s want=%s; events=%s", read.Attempt.State, expectedState, authority.AttemptEvents(ctx, trust, started.AttemptID, 0, 100).Body)
				}
				return read.Attempt
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal(ctx.Err())
		return harnessprotocol.Attempt{}
	}
	originals := make([]harnessprotocol.MessageEnqueueReferences, 0, 3)
	failed := make([]harnessprotocol.Attempt, 0, 3)
	for range 3 {
		result := authority.DialogView(ctx, trust, dialogRef.DialogID)
		var read struct {
			Dialog struct {
				Version int64 `json:"version"`
			} `json:"dialog"`
		}
		if result.HTTPStatus != 200 || json.Unmarshal(result.Body, &read) != nil {
			t.Fatalf("dialog: %s", result.Body)
		}
		receipt := command("message.enqueue", map[string]any{"dialogId": dialogRef.DialogID}, map[string]any{"dialogVersion": read.Dialog.Version}, map[string]any{"text": "unsupported-model"})
		var refs harnessprotocol.MessageEnqueueReferences
		if err := json.Unmarshal(receipt.References, &refs); err != nil {
			t.Fatal(err)
		}
		originals = append(originals, refs)
		attempt := dispatch("failed")
		if attempt.EffectStatus != "none" {
			t.Fatalf("effects=%s", attempt.EffectStatus)
		}
		failed = append(failed, attempt)
	}
	close()
	adapterConfig.Model = "fixture-entitled-model"
	open()
	for _, attempt := range failed {
		command("attempt.retry", map[string]any{"attemptId": attempt.AttemptID}, map[string]any{"attemptGeneration": attempt.Generation}, map[string]any{"acknowledgeKnownEffects": false})
	}
	for i := range 3 {
		retried := dispatch("completed")
		if retried.Generation != 2 || retried.RequestID == originals[i].RequestID {
			t.Fatalf("retry identity: %+v", retried)
		}
	}
	result := authority.RequestsForDialog(ctx, trust, dialogRef.DialogID, "", "", 100)
	var requests struct {
		Items []harnessprotocol.Request `json:"items"`
	}
	if result.HTTPStatus != 200 || json.Unmarshal(result.Body, &requests) != nil || len(requests.Items) != 6 {
		t.Fatalf("requests: %s", result.Body)
	}
	for _, original := range originals {
		counts := map[string]int{}
		for _, request := range requests.Items {
			if request.InputMessageID == original.MessageID {
				counts[request.Status]++
			}
		}
		if counts["failed"] != 1 || counts["completed"] != 1 {
			t.Fatalf("original input lost or duplicated: %+v", counts)
		}
	}
	history := authority.History(ctx, trust, dialogRef.DialogID, "", 100)
	var messages struct {
		Items []struct {
			Role string `json:"role"`
		} `json:"items"`
	}
	if history.HTTPStatus != 200 || json.Unmarshal(history.Body, &messages) != nil {
		t.Fatalf("history: %s", history.Body)
	}
	counts := map[string]int{}
	for _, message := range messages.Items {
		counts[message.Role]++
	}
	if counts["user"] != 3 || counts["assistant"] != 3 {
		t.Fatalf("history counts: %+v", counts)
	}
}
