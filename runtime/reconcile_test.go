package node_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	api "github.com/boxvtk621/harness-codex/api"
	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/nodesettings"
	"github.com/boxvtk621/harness-codex/runtime"
)

type startupSettingsProvider struct{}

func (startupSettingsProvider) ListModels(context.Context, string, int) (nodesettings.ModelPage, error) {
	return nodesettings.ModelPage{}, nil
}
func (startupSettingsProvider) CheckMCP(context.Context, nodesettings.MCPConfig) (nodesettings.MCPCheck, error) {
	return nodesettings.MCPCheck{}, nil
}
func (startupSettingsProvider) ApplySettings(context.Context, nodesettings.Settings, []nodesettings.MCPConfig) error {
	return nil
}

type reconcileAdapter struct {
	*fixture.Adapter
	called  chan<- struct{}
	release <-chan struct{}
	result  harnessadapter.ReconcileResult
}

func TestFailedTerminalReleasesAdmissionOnlyWithResolvedEffects(t *testing.T) {
	for _, effect := range []string{"none", "unknown"} {
		t.Run(effect, func(t *testing.T) {
			config := testConfig(t.TempDir())
			config.Adapter = fixture.NewAdapter()
			config.Policies = fixture.NewPolicySource()
			opened, reference := runningAttemptWithConfig(t, config)
			defer opened.Close()
			failure := &harnessadapter.Failure{Class: harnessadapter.FailureTask, Code: "codex_model_unsupported", SafeMessage: "Select an available model before retrying."}
			err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.TerminalEvent{
				EventBase: harnessadapter.EventBase{Attempt: reference}, Outcome: harnessadapter.ReconcileFailed, Failure: failure, EffectStatus: effect,
			})
			if err != nil {
				t.Fatal(err)
			}
			var snapshot harnessprotocol.Snapshot
			result := opened.Snapshot(context.Background(), nodeTrust())
			if result.HTTPStatus != 200 || json.Unmarshal(result.Body, &snapshot) != nil {
				t.Fatalf("snapshot: %s", result.Body)
			}
			var read harnessprotocol.AttemptRead
			attempt := opened.Attempt(context.Background(), nodeTrust(), reference.AttemptID)
			if attempt.HTTPStatus != 200 || json.Unmarshal(attempt.Body, &read) != nil {
				t.Fatalf("attempt: %s", attempt.Body)
			}
			if effect == "none" {
				if snapshot.ActiveAttempt != nil || snapshot.Node.Occupancy != "idle" || read.Attempt.State != "failed" || read.Attempt.EffectStatus != "none" {
					t.Fatalf("proven rejection retained fence: %+v %+v", snapshot, read)
				}
				found := false
				for _, event := range attemptEvents(t, context.Background(), opened, reference.AttemptID) {
					if event.Type == "attempt.failed" {
						var payload harnessprotocol.AttemptFailedPayload
						if json.Unmarshal(event.Payload, &payload) != nil || payload.ErrorCode != failure.Code || payload.SafeMessage != failure.SafeMessage || payload.Retryable {
							t.Fatalf("failure payload: %s", event.Payload)
						}
						found = true
					}
				}
				if !found {
					t.Fatal("safe failure diagnostic missing")
				}
			} else if snapshot.ActiveAttempt == nil || snapshot.Node.Occupancy != "unknown" || read.Attempt.State != "unknown" || read.Attempt.EffectStatus != "unknown" {
				t.Fatalf("ambiguous rejection released fence: %+v %+v", snapshot, read)
			}
		})
	}
}

func (adapter *reconcileAdapter) Reconcile(ctx context.Context, input harnessadapter.ReconcileInput) (harnessadapter.ReconcileResult, error) {
	if adapter.called != nil {
		select {
		case adapter.called <- struct{}{}:
		default:
		}
	}
	if adapter.release != nil {
		select {
		case <-adapter.release:
		case <-ctx.Done():
			return harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileUnknown}, ctx.Err()
		}
	}
	return adapter.result, nil
}

func unknownAttempt(t *testing.T, adapter harnessadapter.Adapter) (*node.Node, harnessadapter.AttemptRef) {
	t.Helper()
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, reference := runningAttemptWithConfig(t, config)
	if err := opened.Observe(context.Background(), node.Observation{AttemptID: reference.AttemptID, Generation: reference.Generation, Kind: "unknown", Reason: "provider_state", EffectStatus: "known"}); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	return opened, reference
}

func TestReconcileUnknownCallsAdapterOutsideStoreLockAndKeepsLiveFence(t *testing.T) {
	called := make(chan struct{}, 1)
	release := make(chan struct{})
	adapter := &reconcileAdapter{Adapter: fixture.NewAdapter(), called: called, release: release, result: harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileRunning, EffectStatus: "known"}}
	opened, reference := unknownAttempt(t, adapter)
	defer opened.Close()
	done := make(chan error, 1)
	go func() {
		_, err := opened.ReconcileUnknown(context.Background(), reference)
		done <- err
	}()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("adapter reconcile was not called")
	}
	if result := opened.Snapshot(context.Background(), nodeTrust()); result.HTTPStatus != 200 {
		t.Fatalf("snapshot blocked behind adapter reconcile: status=%d body=%s", result.HTTPStatus, result.Body)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var snapshot harnessprotocol.Snapshot
	result := opened.Snapshot(context.Background(), nodeTrust())
	if result.HTTPStatus != 200 || json.Unmarshal(result.Body, &snapshot) != nil || snapshot.ActiveAttempt == nil || snapshot.ActiveAttempt.State != "unknown" {
		t.Fatalf("running reconciliation released fence: status=%d snapshot=%+v", result.HTTPStatus, snapshot)
	}
}

func TestReconcileUnknownAppliesOnlyResolvedTerminal(t *testing.T) {
	adapter := &reconcileAdapter{Adapter: fixture.NewAdapter(), result: harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "none"}}
	opened, reference := unknownAttempt(t, adapter)
	defer opened.Close()
	if _, err := opened.ReconcileUnknown(context.Background(), reference); err != nil {
		t.Fatal(err)
	}
	var snapshot harnessprotocol.Snapshot
	result := opened.Snapshot(context.Background(), nodeTrust())
	if result.HTTPStatus != 200 || json.Unmarshal(result.Body, &snapshot) != nil || snapshot.ActiveAttempt != nil || snapshot.Node.Occupancy != "idle" {
		t.Fatalf("terminal reconciliation did not release exact slot: status=%d snapshot=%+v", result.HTTPStatus, snapshot)
	}
	read := opened.Attempt(context.Background(), nodeTrust(), reference.AttemptID)
	if read.HTTPStatus != 200 {
		t.Fatalf("attempt read status=%d body=%s", read.HTTPStatus, read.Body)
	}
	var attempt harnessprotocol.AttemptRead
	if err := json.Unmarshal(read.Body, &attempt); err != nil || attempt.Attempt.State != "completed" || attempt.Attempt.EffectStatus != "none" {
		t.Fatalf("reconciled attempt=%+v err=%v", attempt, err)
	}
}

func TestReconcileUnknownPersistsObservedAssistantOutputAtomically(t *testing.T) {
	intermediate := harnessprotocol.SafeContent{Kind: "inline", Content: "intermediate output", Redaction: "none", Truncated: false}
	content := harnessprotocol.SafeContent{Kind: "inline", Content: "recovered output", Redaction: "none", Truncated: false}
	adapter := &reconcileAdapter{Adapter: fixture.NewAdapter(), result: harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileCompleted, Output: &content, EffectStatus: "known"}}
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, reference := runningAttemptWithConfig(t, config)
	defer opened.Close()
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.AssistantMessageEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: "10000000-0000-4000-8000-000000000343", Content: intermediate, FinishReason: "complete"}); err != nil {
		t.Fatal(err)
	}
	if err := opened.ObserveAdapterEvent(context.Background(), reference, harnessadapter.UnknownEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, Reason: "provider_state", EffectStatus: "unknown"}); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.ReconcileUnknown(context.Background(), reference); err != nil {
		t.Fatal(err)
	}
	result := opened.History(context.Background(), nodeTrust(), reference.DialogID, "", 100)
	if result.HTTPStatus != 200 {
		t.Fatalf("history status=%d body=%s", result.HTTPStatus, result.Body)
	}
	var history struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(result.Body, &history); err != nil {
		t.Fatal(err)
	}
	assistantMessages := 0
	intermediateFound := false
	var messageID string
	for _, raw := range history.Items {
		var item struct {
			MessageID string                      `json:"messageId"`
			Role      string                      `json:"role"`
			Content   harnessprotocol.SafeContent `json:"content"`
		}
		if json.Unmarshal(raw, &item) == nil && item.Role == "assistant" {
			assistantMessages++
			if safeContentForTestEqual(item.Content, intermediate) {
				intermediateFound = true
			} else if safeContentForTestEqual(item.Content, content) {
				messageID = item.MessageID
			} else {
				t.Fatalf("unexpected assistant content=%+v", item.Content)
			}
		}
	}
	if assistantMessages != 2 || !intermediateFound || messageID == "" {
		t.Fatalf("assistant messages=%d history=%s", assistantMessages, result.Body)
	}
	attemptResult := opened.Attempt(context.Background(), nodeTrust(), reference.AttemptID)
	var attempt harnessprotocol.AttemptRead
	if attemptResult.HTTPStatus != 200 || json.Unmarshal(attemptResult.Body, &attempt) != nil || attempt.Attempt.AttemptID != reference.AttemptID || attempt.Attempt.State != "completed" {
		t.Fatalf("attempt output not bound to recovered message: status=%d attempt=%+v", attemptResult.HTTPStatus, attempt)
	}
	events := attemptEvents(t, context.Background(), opened, reference.AttemptID)
	if !hasEventType(events, "assistant.message") || !hasEventType(events, "attempt.completed") {
		t.Fatalf("recovered output events=%+v", events)
	}
	completed := 0
	for _, event := range events {
		if event.Type != "attempt.completed" {
			continue
		}
		completed++
		var payload harnessprotocol.AttemptCompletedPayload
		if json.Unmarshal(event.Payload, &payload) != nil || payload.Generation != reference.Generation || payload.Output.Kind != "message" || payload.Output.AssistantMessageID != messageID {
			t.Fatalf("terminal event does not reference the recovered final message: %+v", event)
		}
	}
	if completed != 1 {
		t.Fatalf("expected one durable completion, got %d", completed)
	}
}

func safeContentForTestEqual(left, right harnessprotocol.SafeContent) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}

func TestReconcileUnknownDoesNotOverrideUnknownSteerEffect(t *testing.T) {
	base := fixture.NewAdapter()
	base.SteerResult = harnessadapter.SteerResult{Outcome: harnessadapter.SteerUnknown}
	adapter := &reconcileAdapter{Adapter: base, result: harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "none"}}
	config := testConfig(t.TempDir())
	config.Adapter = adapter
	config.Policies = fixture.NewPolicySource()
	opened, active := runningAttemptWithConfig(t, config)
	defer opened.Close()
	enqueued := decodeReceipt(t, opened.SubmitCommand(context.Background(), nodeTrust(), command(t, "10000000-0000-4000-8000-000000000330", "message.enqueue", map[string]any{"nodeId": testNodeID, "dialogId": active.DialogID}, map[string]any{"dialogVersion": 2}, map[string]any{"text": "steer uncertain"})), 202)
	var refs harnessprotocol.MessageEnqueueReferences
	if err := json.Unmarshal(enqueued.References, &refs); err != nil {
		t.Fatal(err)
	}
	steer := command(t, "10000000-0000-4000-8000-000000000331", "message.steer", map[string]any{"nodeId": testNodeID, "dialogId": active.DialogID, "messageId": refs.MessageID, "attemptId": active.AttemptID}, map[string]any{"attemptGeneration": active.Generation, "messageVersion": 1}, map[string]any{})
	decodeReceipt(t, opened.SubmitCommand(context.Background(), nodeTrust(), steer), 202)
	waitFor(t, func() bool {
		var snapshot harnessprotocol.Snapshot
		result := opened.Snapshot(context.Background(), nodeTrust())
		return result.HTTPStatus == 200 && json.Unmarshal(result.Body, &snapshot) == nil && snapshot.ActiveAttempt != nil && snapshot.ActiveAttempt.State == "unknown"
	})
	if _, err := opened.ReconcileUnknown(context.Background(), active); err == nil {
		t.Fatal("terminal reconciliation overrode an unresolved steer outcome")
	}
	var snapshot harnessprotocol.Snapshot
	result := opened.Snapshot(context.Background(), nodeTrust())
	if result.HTTPStatus != 200 || json.Unmarshal(result.Body, &snapshot) != nil || snapshot.ActiveAttempt == nil || snapshot.ActiveAttempt.State != "unknown" {
		t.Fatalf("unresolved steer fence changed: status=%d snapshot=%+v", result.HTTPStatus, snapshot)
	}
}

func TestReconcileUnknownAfterReopenAllowsTerminalProofForDispatchAndStop(t *testing.T) {
	for _, test := range []struct {
		name string
		stop bool
	}{
		{name: "dispatch"},
		{name: "stop", stop: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := t.TempDir()
			blocked := make(chan struct{})
			called := make(chan struct{}, 1)
			base := fixture.NewAdapter()
			if test.stop {
				base.CancelGate, base.CancelCalled = blocked, called
			} else {
				base.StartGate, base.StartCalled = blocked, called
			}
			config := testConfig(path)
			config.Adapter = base
			config.Policies = fixture.NewPolicySource()

			var opened *node.Node
			var reference harnessadapter.AttemptRef
			if test.stop {
				opened, reference = runningAttemptWithConfig(t, config)
				stop := command(t, "10000000-0000-4000-8000-000000000340", "attempt.stop", map[string]any{"nodeId": testNodeID, "attemptId": reference.AttemptID}, map[string]any{"attemptGeneration": reference.Generation}, map[string]any{})
				decodeReceipt(t, opened.SubmitCommand(context.Background(), nodeTrust(), stop), 202)
			} else {
				var err error
				opened, err = node.Open(context.Background(), config)
				if err != nil {
					t.Fatal(err)
				}
				dialogID := createDialog(t, context.Background(), opened, "10000000-0000-4000-8000-000000000341")
				queued := enqueue(t, context.Background(), opened, "10000000-0000-4000-8000-000000000342", dialogID, "reconcile dispatch", 1)
				dispatched, err := opened.DispatchNext(context.Background())
				if err != nil || dispatched.Outcome != "dispatching" {
					t.Fatalf("dispatch=%+v err=%v", dispatched, err)
				}
				reference = harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: dialogID, RequestID: queued.RequestID, AttemptID: dispatched.AttemptID, Generation: 1}
			}
			select {
			case <-called:
			case <-time.After(time.Second):
				opened.Close()
				t.Fatal("uncertain adapter call did not start")
			}
			if err := opened.Close(); err != nil {
				t.Fatal(err)
			}

			reconciler := &reconcileAdapter{Adapter: fixture.NewAdapter(), result: harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileCompleted, EffectStatus: "none"}}
			config.Adapter = reconciler
			reopened, err := node.Open(context.Background(), config)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if _, err := reopened.ReconcileUnknown(context.Background(), reference); err != nil {
				t.Fatalf("terminal proof rejected after %s uncertainty: %v", test.name, err)
			}
			snapshot := currentSnapshot(t, context.Background(), reopened)
			if snapshot.ActiveAttempt != nil || snapshot.Node.Occupancy != "idle" {
				t.Fatalf("terminal proof kept slot after %s uncertainty: %+v", test.name, snapshot)
			}
		})
	}
}

func TestReconcileUnknownRejectsUnprovedEffectStatus(t *testing.T) {
	for _, status := range []string{"", "unknown", "bogus"} {
		t.Run(status, func(t *testing.T) {
			adapter := &reconcileAdapter{Adapter: fixture.NewAdapter(), result: harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileCompleted, EffectStatus: status}}
			opened, reference := unknownAttempt(t, adapter)
			defer opened.Close()
			if _, err := opened.ReconcileUnknown(context.Background(), reference); err == nil {
				t.Fatalf("terminal reconciliation accepted effectStatus %q", status)
			}
			snapshot := currentSnapshot(t, context.Background(), opened)
			if snapshot.ActiveAttempt == nil || snapshot.ActiveAttempt.State != "unknown" {
				t.Fatalf("invalid effect status released fence: %+v", snapshot)
			}
		})
	}
}

func TestUnknownAttemptRestartStillServesNodeAPI(t *testing.T) {
	path := t.TempDir()
	config := testConfig(path)
	config.Policies = fixture.NewPolicySource()
	opened, reference := runningAttemptWithConfig(t, config)
	if err := opened.Observe(context.Background(), node.Observation{
		AttemptID: reference.AttemptID, Generation: reference.Generation,
		Kind: "unknown", Reason: "provider_state", EffectStatus: "unknown",
	}); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := node.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	settings, err := nodesettings.Open(path, testNodeID, startupSettingsProvider{})
	if err != nil {
		t.Fatalf("node settings blocked restart with unknown attempt: %v", err)
	}
	handler, err := api.New(api.Config{NodeID: testNodeID, NodeSettings: settings}, reopened)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		path string
		want int
	}{
		{path: "/health/live", want: http.StatusOK},
		{path: "/health/ready", want: http.StatusOK},
		{path: "/v1/nodes/" + testNodeID + "/identity", want: http.StatusOK},
		{path: "/v1/nodes/" + testNodeID + "/settings", want: http.StatusOK},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, check.path, nil))
		if response.Code != check.want {
			t.Fatalf("GET %s = %d, want %d: %s", check.path, response.Code, check.want, response.Body.String())
		}
	}
	var health harnessprotocol.HealthReady
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if json.Unmarshal(response.Body.Bytes(), &health) != nil || health.Readiness != "unknown" {
		t.Fatalf("unknown readiness was not exposed: %s", response.Body.String())
	}
}
