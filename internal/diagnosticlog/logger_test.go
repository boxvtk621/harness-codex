package diagnosticlog

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLoggerEmitsBoundedAllowlistedJSON(t *testing.T) {
	var output bytes.Buffer
	logger := New(Config{Writer: &output, Component: "runtime", Clock: func() time.Time { return time.Unix(1, 0) }})
	logger.Emit(LevelInfo, EventAttemptStarted, Fields{NodeID: "10000000-0000-4000-8000-000000000001", AttemptID: "20000000-0000-4000-8000-000000000001", Generation: 1, Operation: "start"})
	logger.Close()
	if output.Len() > MaximumRecord {
		t.Fatalf("record bytes = %d", output.Len())
	}
	var decoded map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["schema"] != Schema || decoded["event"] != string(EventAttemptStarted) || decoded["component"] != "runtime" {
		t.Fatalf("record = %#v", decoded)
	}
	for _, forbidden := range []string{"message", "error", "prompt", "content", "payload", "path"} {
		if _, exists := decoded[forbidden]; exists {
			t.Fatalf("forbidden field %q present", forbidden)
		}
	}
}

func TestLoggerRejectsFreeFormMetadataAndSummarizesDrop(t *testing.T) {
	var output bytes.Buffer
	logger := New(Config{Writer: &output, Component: "runtime", Clock: func() time.Time { return time.Unix(1, 0) }})
	logger.SetNodeID("10000000-0000-4000-8000-000000000000")
	logger.Emit(LevelError, EventCommandFailed, Fields{Reason: "secret value with spaces"})
	logger.Close()
	if strings.Contains(output.String(), "secret") {
		t.Fatalf("unsafe value escaped into log: %s", output.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["event"] != string(EventLogDropped) || decoded["count"] != float64(1) {
		t.Fatalf("drop summary = %#v", decoded)
	}
}

func TestSharedGoldenVector(t *testing.T) {
	var output bytes.Buffer
	logger := New(Config{Writer: &output, Component: "runtime", Clock: func() time.Time { return time.Unix(1, 0) }})
	logger.SetNodeID("10000000-0000-4000-8000-000000000000")
	logger.Emit(LevelWarn, EventAttemptUnknown, Fields{
		DialogID: "20000000-0000-4000-8000-000000000001", RequestID: "20000000-0000-4000-8000-000000000002",
		AttemptID: "20000000-0000-4000-8000-000000000003", CommandID: "20000000-0000-4000-8000-000000000004",
		OperationID: "20000000-0000-4000-8000-000000000005", CallID: "20000000-0000-4000-8000-000000000006",
		Kind: "reconcile", Tool: "cursor.command", Operation: "observe", Outcome: "unknown", EffectStatus: "unknown", Reason: "provider_state",
		Generation: 2, ProcessGeneration: 3, DurationMS: 7, Count: 4, Truncated: true,
	})
	logger.Close()
	var decoded map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &decoded); err != nil {
		t.Fatal(err)
	}
	delete(decoded, "bootId")
	encoded, _ := json.Marshal(decoded)
	want := `{"attemptId":"20000000-0000-4000-8000-000000000003","commandId":"20000000-0000-4000-8000-000000000004","component":"runtime","count":4,"dialogId":"20000000-0000-4000-8000-000000000001","durationMs":7,"effectStatus":"unknown","event":"attempt.unknown","generation":2,"kind":"reconcile","level":"warn","nodeId":"10000000-0000-4000-8000-000000000000","operation":"observe","operationId":"20000000-0000-4000-8000-000000000005","outcome":"unknown","processGeneration":3,"reasonCode":"provider_state","requestId":"20000000-0000-4000-8000-000000000002","schema":"harness.console.v1","tool":"cursor.command","toolCallId":"20000000-0000-4000-8000-000000000006","truncated":true,"ts":"1970-01-01T00:00:01Z"}`
	if string(encoded) != want {
		t.Fatalf("golden vector mismatch:\n got %s\nwant %s", encoded, want)
	}
}

type shortThenBuffer struct {
	bytes.Buffer
	short bool
}

func (writer *shortThenBuffer) Write(value []byte) (int, error) {
	if !writer.short {
		writer.short = true
		return len(value) / 2, nil
	}
	return writer.Buffer.Write(value)
}

func TestShortWriteProducesWriteFailureSummary(t *testing.T) {
	writer := &shortThenBuffer{}
	logger := New(Config{Writer: writer, Component: "runtime", Clock: func() time.Time { return time.Unix(1, 0) }})
	logger.SetNodeID("10000000-0000-4000-8000-000000000000")
	logger.Emit(LevelInfo, EventRuntimeOpened, Fields{})
	logger.Close()
	if !strings.Contains(writer.String(), `"event":"log.write_failed"`) || !strings.Contains(writer.String(), `"count":1`) {
		t.Fatalf("missing write failure summary: %s", writer.String())
	}
}
