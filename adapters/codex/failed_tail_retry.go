package codex

import "github.com/boxvtk621/harness-codex/internal/harnessadapter"

func (store *mappingStore) validFailedTail(reference harnessadapter.AttemptRef, boundary harnessadapter.ContextBoundary, policyHash, promptHash string, proof *harnessadapter.FailedTailRetry) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return validFailedTail(store.contents, reference, boundary, policyHash, promptHash, proof)
}

func validFailedTail(state mappingState, reference harnessadapter.AttemptRef, boundary harnessadapter.ContextBoundary, policyHash, promptHash string, proof *harnessadapter.FailedTailRetry) bool {
	dialog, exists := state.Dialogs[reference.DialogID]
	if !exists || proof == nil || len(proof.Attempts) == 0 || len(proof.Attempts) > 100 || proof.HighWater != dialog.Boundary || boundary.Sequence >= dialog.Boundary.Sequence || dialog.PolicyHash != policyHash {
		return false
	}
	covered := make(map[string]bool)
	target := false
	for _, prior := range proof.Attempts {
		key := attemptKey(prior.Attempt)
		mapped, ok := state.Attempts[key]
		if !ok || covered[key] || prior.Attempt.NodeID != reference.NodeID || prior.Attempt.DialogID != reference.DialogID || mapped.State != "terminal" || mapped.ThreadID != dialog.ThreadID || mapped.Context != prior.Context || mapped.PolicyHash != prior.PolicyHash || mapped.PromptHash != prior.PromptHash || prior.PolicyHash != policyHash || prior.Context.Sequence < boundary.Sequence || prior.Context.Sequence > dialog.Boundary.Sequence {
			return false
		}
		covered[key] = true
		if prior.Context == boundary {
			if prior.PromptHash != promptHash || prior.Attempt.Generation >= reference.Generation {
				return false
			}
			target = true
		}
	}
	for key, mapped := range state.Attempts {
		if mapped.Reference.DialogID == reference.DialogID && mapped.Reference != reference && mapped.Context.Sequence >= boundary.Sequence && !covered[key] {
			return false
		}
	}
	return target
}
