package codex

import (
	"context"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
)

func TestFailedTailThreeOrderedRetriesPreserveHighWaterAfterModelChange(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	policy, _ := harnessadapter.PreparePolicySnapshot(adapterPolicy())
	proof := &harnessadapter.FailedTailRetry{HighWater: adapterBoundary(3)}
	for i := int64(1); i <= 3; i++ {
		ref := adapterReference(1, i, 1)
		if i == 1 {
			result, err := adapter.Start(ctx, harnessadapter.StartInput{Attempt: ref, Prompt: "unsupported-model", Context: adapterBoundary(i), Policy: policy})
			if err != nil || result.Outcome != harnessadapter.StartStarted {
				t.Fatalf("start: %+v %v", result, err)
			}
		} else {
			result, err := adapter.Resume(ctx, harnessadapter.ResumeInput{Attempt: ref, Prompt: "unsupported-model", Context: adapterBoundary(i), Policy: policy})
			if err != nil || result.Outcome != harnessadapter.ResumeStarted {
				t.Fatalf("resume: %+v %v", result, err)
			}
		}
		events := readAdapterEvents(t, ctx, adapter, ref)
		terminal := events[len(events)-1].(harnessadapter.TerminalEvent)
		if terminal.Outcome != harnessadapter.ReconcileFailed || terminal.EffectStatus != "none" || terminal.Failure.Code != "codex_model_unsupported" {
			t.Fatalf("rejection: %+v", terminal)
		}
		proof.Attempts = append(proof.Attempts, harnessadapter.FailedTailAttempt{Attempt: ref, Context: adapterBoundary(i), PolicyHash: policy.EffectiveHash, PromptHash: digestString("unsupported-model")})
	}
	config := adapter.config
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
	config.Model = "fixture-entitled-model"
	var err error
	adapter, err = New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	// The persisted terminal mappings survive a restart and the corrected model
	// must be forwarded on both thread/resume and turn/start.
	for i := int64(1); i <= 3; i++ {
		ref := adapterReference(1, 10+i, 2)
		scoped := &harnessadapter.FailedTailRetry{HighWater: proof.HighWater, Attempts: proof.Attempts[i-1:]}
		result, err := adapter.Resume(ctx, harnessadapter.ResumeInput{Attempt: ref, Prompt: "unsupported-model", Context: adapterBoundary(i), Policy: policy, FailedTailRetry: scoped})
		if err != nil || result.Outcome != harnessadapter.ResumeStarted {
			t.Fatalf("retry %d: %+v %v", i, result, err)
		}
		events := readAdapterEvents(t, ctx, adapter, ref)
		if terminal := events[len(events)-1].(harnessadapter.TerminalEvent); terminal.Outcome != harnessadapter.ReconcileCompleted {
			t.Fatalf("retry %d: %+v", i, terminal)
		}
		dialog, _ := adapter.store.dialog(ref.DialogID)
		if dialog.Boundary != adapterBoundary(3) {
			t.Fatalf("boundary regressed: %+v", dialog)
		}
		reloaded, err := openMappingStore(config.StateDir)
		if err != nil {
			t.Fatal(err)
		}
		mapped, ok := reloaded.attempt(ref)
		if !ok || mapped.FailedTailRetry == nil {
			t.Fatal("scoped proof was not persisted")
		}
	}
}

func TestFailedTailProofRejectsMissingTamperedAndUncoveredMappings(t *testing.T) {
	policy, _ := harnessadapter.PreparePolicySnapshot(adapterPolicy())
	ref := adapterReference(1, 1, 1)
	retry := adapterReference(1, 3, 2)
	other := adapterReference(1, 2, 1)
	state := mappingState{Dialogs: map[string]persistedDialog{ref.DialogID: {ThreadID: "thread", Boundary: adapterBoundary(2), PolicyHash: policy.EffectiveHash}}, Attempts: map[string]persistedAttempt{}}
	proof := &harnessadapter.FailedTailRetry{HighWater: adapterBoundary(2)}
	for i, r := range []harnessadapter.AttemptRef{ref, other} {
		item := harnessadapter.FailedTailAttempt{Attempt: r, Context: adapterBoundary(int64(i + 1)), PolicyHash: policy.EffectiveHash, PromptHash: digestString("prompt")}
		proof.Attempts = append(proof.Attempts, item)
		state.Attempts[attemptKey(r)] = persistedAttempt{Reference: r, Context: item.Context, PolicyHash: item.PolicyHash, PromptHash: item.PromptHash, ThreadID: "thread", State: "terminal"}
	}
	check := func(p *harnessadapter.FailedTailRetry) bool {
		return validFailedTail(state, retry, adapterBoundary(1), policy.EffectiveHash, digestString("prompt"), p)
	}
	if !check(proof) {
		t.Fatal("valid proof rejected")
	}
	if check(nil) || check(&harnessadapter.FailedTailRetry{HighWater: proof.HighWater, Attempts: proof.Attempts[:1]}) {
		t.Fatal("incomplete proof admitted")
	}
	altered := *proof
	altered.HighWater = adapterBoundary(3)
	if check(&altered) {
		t.Fatal("stale high water admitted")
	}
	mapped := state.Attempts[attemptKey(other)]
	mapped.State = "active"
	state.Attempts[attemptKey(other)] = mapped
	if check(proof) {
		t.Fatal("active mapping admitted")
	}
}

func TestFailedTailPersistedIntentRestartDoesNotDispatchAgain(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	policy, _ := harnessadapter.PreparePolicySnapshot(adapterPolicy())
	proof := &harnessadapter.FailedTailRetry{HighWater: adapterBoundary(2)}
	for i := int64(1); i <= 2; i++ {
		ref := adapterReference(1, i, 1)
		if i == 1 {
			result, err := adapter.Start(ctx, harnessadapter.StartInput{Attempt: ref, Prompt: "unsupported-model", Context: adapterBoundary(i), Policy: policy})
			if err != nil || result.Outcome != harnessadapter.StartStarted {
				t.Fatalf("start: %+v %v", result, err)
			}
		} else {
			result, err := adapter.Resume(ctx, harnessadapter.ResumeInput{Attempt: ref, Prompt: "unsupported-model", Context: adapterBoundary(i), Policy: policy})
			if err != nil || result.Outcome != harnessadapter.ResumeStarted {
				t.Fatalf("resume: %+v %v", result, err)
			}
		}
		events := readAdapterEvents(t, ctx, adapter, ref)
		terminal := events[len(events)-1].(harnessadapter.TerminalEvent)
		if terminal.Failure == nil || terminal.Failure.Code != "codex_model_unsupported" {
			t.Fatalf("terminal: %+v", terminal)
		}
		proof.Attempts = append(proof.Attempts, harnessadapter.FailedTailAttempt{Attempt: ref, Context: adapterBoundary(i), PolicyHash: policy.EffectiveHash, PromptHash: digestString("unsupported-model")})
	}
	retry := adapterReference(1, 3, 2)
	dialog, _ := adapter.store.dialog(retry.DialogID)
	// Place the exact durable boundary before any thread/turn acknowledgement.
	if err := adapter.store.putIntent("resume", retry, adapterBoundary(1), policy.EffectiveHash, digestString("unsupported-model"), dialog.ThreadID, proof); err != nil {
		t.Fatal(err)
	}
	intent, _ := adapter.store.attempt(retry)
	config := adapter.config
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
	config.Model = "fixture-entitled-model"
	var err error
	adapter, err = New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	reloaded, ok := adapter.store.attempt(retry)
	if !ok || reloaded.FailedTailRetry == nil || len(reloaded.FailedTailRetry.Attempts) != 2 || reloaded.State != "thread_dispatching" {
		t.Fatalf("intent not retained: %+v", reloaded)
	}
	for count := 0; count < 2; count++ {
		result, err := adapter.Resume(ctx, harnessadapter.ResumeInput{Attempt: retry, Context: adapterBoundary(1), Prompt: "unsupported-model", Policy: policy, FailedTailRetry: proof})
		if err != nil || result.Outcome != harnessadapter.ResumeUnknown {
			t.Fatalf("duplicate resume: %+v %v", result, err)
		}
	}
	result, err := adapter.Reconcile(ctx, harnessadapter.ReconcileInput{Attempt: retry})
	if err != nil || result.Outcome != harnessadapter.ReconcileUnknown || result.EffectStatus != "unknown" {
		t.Fatalf("reconcile: %+v %v", result, err)
	}
	if err := adapter.store.activate(retry, "stale-turn", intent.ProcessGeneration); err == nil {
		t.Fatal("stale activation accepted")
	}
	adapter.mu.Lock()
	live := len(adapter.attempts)
	adapter.mu.Unlock()
	if live != 0 {
		t.Fatalf("duplicate native attempt started: %d", live)
	}
	if got, _ := adapter.store.attempt(retry); got.State != "thread_dispatching" || got.TurnID != "" {
		t.Fatalf("intent advanced after restart: %+v", got)
	}
	if got, _ := adapter.store.dialog(retry.DialogID); got.Boundary != proof.HighWater {
		t.Fatal("high water changed")
	}
}
