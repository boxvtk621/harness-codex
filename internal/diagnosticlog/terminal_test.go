package diagnosticlog

import (
	"strings"
	"testing"
)

func TestTerminalExplanationsAreFixedAndDoNotEchoCodes(t *testing.T) {
	if got := terminalExplanation(EventAttemptTerminal, Fields{Outcome: "failed", Reason: "codex_model_unsupported"}); !strings.Contains(got, "entitled model") {
		t.Fatal(got)
	}
	if got := terminalExplanation(EventAttemptTerminal, Fields{Outcome: "failed", Reason: "provider-secret"}); strings.Contains(got, "secret") || !strings.Contains(got, "effect status") {
		t.Fatal(got)
	}
	if got := terminalExplanation(EventAttemptTerminal, Fields{Outcome: "interrupted"}); !strings.Contains(got, "interrupted") {
		t.Fatal(got)
	}
	if got := terminalExplanation(EventAttemptStarted, Fields{Reason: "codex_model_unsupported"}); got != "" {
		t.Fatal(got)
	}
}
