package node

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

type scenarioCorpus struct {
	Scenarios []scenario `json:"scenarios"`
}

type scenario struct {
	ID        string        `json:"id"`
	Given     scenarioGiven `json:"given"`
	Operation struct {
		Type        string          `json:"type"`
		Value       json.RawMessage `json:"value"`
		AttemptID   string          `json:"attemptId"`
		Generation  int64           `json:"generation"`
		Observation struct {
			Kind          string `json:"kind"`
			TerminalState string `json:"terminalState"`
			Reason        string `json:"reason"`
			EffectStatus  string `json:"effectStatus"`
			Confirmed     bool   `json:"confirmed"`
		} `json:"observation"`
	} `json:"operation"`
	Expect struct {
		DomainProjection       string         `json:"domainProjection"`
		OtherNodeProjections   string         `json:"otherNodeProjections"`
		PostProjection         *scenarioGiven `json:"postProjection"`
		UnchangedEntities      []string       `json:"unchangedEntities"`
		QueuedRequestUnchanged string         `json:"queuedRequestUnchanged"`
		AfterReadinessRefresh  *struct {
			ActiveAttemptID string `json:"activeAttemptId"`
			StillBlockedBy  string `json:"stillBlockedBy"`
		} `json:"afterReadinessRefresh"`
		AppendedObservation *struct {
			AttemptID     string `json:"attemptId"`
			Generation    int64  `json:"generation"`
			Late          bool   `json:"late"`
			Kind          string `json:"kind"`
			TerminalState string `json:"terminalState"`
		} `json:"appendedObservation"`
		HTTPStatus          int                      `json:"httpStatus"`
		PersistedProjection string                   `json:"persistedProjection"`
		ErrorCode           string                   `json:"errorCode"`
		ReceiptEquals       *harnessprotocol.Receipt `json:"receiptEquals"`
		LastEventSeqDelta   int64                    `json:"lastEventSeqDelta"`
		ActiveAttemptID     string                   `json:"activeAttemptId"`
		Attempt             *harnessprotocol.Attempt `json:"attempt"`
		EventsRequired      []json.RawMessage        `json:"eventsRequired"`
		AppendedEventsCount int                      `json:"appendedEventsCount"`
		Node                *struct {
			ActiveAttemptID string   `json:"activeAttemptId"`
			QueuePaused     bool     `json:"queuePaused"`
			StateVersion    int64    `json:"stateVersion"`
			LastEventSeq    int64    `json:"lastEventSeq"`
			QueueVersion    int64    `json:"queueVersion"`
			PendingCount    int64    `json:"pendingCount"`
			EngineReadiness string   `json:"engineReadiness"`
			Occupancy       string   `json:"occupancy"`
			BlockedReasons  []string `json:"blockedReasons"`
		} `json:"node"`
	} `json:"expect"`
}

type scenarioGiven struct {
	OtherNodes      []scenarioGiven `json:"otherNodes"`
	ActorID         string          `json:"actorId"`
	TransportNodeID string          `json:"transportNodeId"`
	RegistryVersion int64           `json:"registryVersion"`
	Node            struct {
		NodeID                string   `json:"nodeId"`
		OwnerID               string   `json:"ownerId"`
		Epoch                 int64    `json:"epoch"`
		StateVersion          int64    `json:"stateVersion"`
		LastEventSeq          int64    `json:"lastEventSeq"`
		QueueVersion          int64    `json:"queueVersion"`
		QueuePaused           bool     `json:"queuePaused"`
		TransportAvailability string   `json:"transportAvailability"`
		EngineReadiness       string   `json:"engineReadiness"`
		Occupancy             string   `json:"occupancy"`
		ActiveAttemptID       *string  `json:"activeAttemptId"`
		PendingCount          int64    `json:"pendingCount"`
		BlockedReasons        []string `json:"blockedReasons"`
	} `json:"node"`
	Dialogs []struct {
		DialogID  string `json:"dialogId"`
		NodeID    string `json:"nodeId"`
		OwnerID   string `json:"ownerId"`
		Version   int64  `json:"version"`
		CreatedAt string `json:"createdAt"`
	} `json:"dialogs"`
	Messages []struct {
		MessageID   string `json:"messageId"`
		DialogID    string `json:"dialogId"`
		Sequence    int64  `json:"sequence"`
		Version     int64  `json:"version"`
		Text        string `json:"text"`
		Disposition string `json:"disposition"`
		CommandID   string `json:"commandId"`
	} `json:"messages"`
	Requests []harnessprotocol.Request `json:"requests"`
	Attempts []harnessprotocol.Attempt `json:"attempts"`
	Commands []struct {
		CommandID            string                  `json:"commandId"`
		ActorID              string                  `json:"actorId"`
		CanonicalValue       json.RawMessage         `json:"canonicalValue"`
		CanonicalPayloadHash string                  `json:"canonicalPayloadHash"`
		Receipt              harnessprotocol.Receipt `json:"receipt"`
	} `json:"commands"`
}

func loadScenarios(t *testing.T) scenarioCorpus {
	t.Helper()
	content, err := os.ReadFile("../api/harness-v1.scenarios.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus scenarioCorpus
	if err := json.Unmarshal(content, &corpus); err != nil {
		t.Fatal(err)
	}
	return corpus
}

func seedScenario(t *testing.T, node *Node, given scenarioGiven) {
	t.Helper()
	ctx := context.Background()
	tx, err := node.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, table := range []string{"late_observations", "artifacts", "approvals", "input_requests", "tool_calls", "control_actions", "events", "commands", "attempts", "requests", "messages", "dialogs", "policy_snapshots"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			t.Fatal(err)
		}
	}
	reasons, _ := json.Marshal(given.Node.BlockedReasons)
	if _, err := tx.ExecContext(ctx, `UPDATE node_state SET epoch=?,state_version=?,last_event_seq=?,queue_version=?,queue_paused=?,transport_availability=?,engine_readiness=?,occupancy=?,active_attempt_id=?,pending_count=?,blocked_reasons=?,next_queue_sequence=100,next_message_sequence=100 WHERE singleton=1`,
		given.Node.Epoch, given.Node.StateVersion, given.Node.LastEventSeq, given.Node.QueueVersion, given.Node.QueuePaused,
		given.Node.TransportAvailability, given.Node.EngineReadiness, given.Node.Occupancy, given.Node.ActiveAttemptID, given.Node.PendingCount, string(reasons)); err != nil {
		t.Fatal(err)
	}
	for _, dialog := range given.Dialogs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO dialogs(dialog_id,node_id,owner_id,version,created_at) VALUES(?,?,?,?,?)`, dialog.DialogID, dialog.NodeID, dialog.OwnerID, dialog.Version, dialog.CreatedAt); err != nil {
			t.Fatal(err)
		}
	}
	requestByMessage := make(map[string]string)
	for _, request := range given.Requests {
		requestByMessage[request.InputMessageID] = request.RequestID
	}
	for _, message := range given.Messages {
		if _, err := tx.ExecContext(ctx, `INSERT INTO messages(message_id,dialog_id,sequence,version,role,text,disposition,command_id,request_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			message.MessageID, message.DialogID, message.Sequence, message.Version, "user", message.Text, message.Disposition, message.CommandID, requestByMessage[message.MessageID], "2026-09-09T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	for _, request := range given.Requests {
		if _, err := tx.ExecContext(ctx, `INSERT INTO requests(request_id,dialog_id,input_message_id,queue_sequence,version,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
			request.RequestID, request.DialogID, request.InputMessageID, request.QueueSequence, request.Version, request.Status, "2026-09-09T00:00:00Z", "2026-09-09T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	for _, attempt := range given.Attempts {
		if _, err := tx.ExecContext(ctx, `INSERT INTO attempts(attempt_id,node_id,dialog_id,request_id,generation,version,state,effect_status) VALUES(?,?,?,?,?,?,?,?)`,
			attempt.AttemptID, given.Node.NodeID, attempt.DialogID, attempt.RequestID, attempt.Generation, attempt.Version, attempt.State, attempt.EffectStatus); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range given.Commands {
		canonical, digest, err := CanonicalCommand(command.CanonicalValue)
		if err != nil || digest != command.CanonicalPayloadHash {
			t.Fatalf("scenario command hash mismatch got=%s want=%s err=%v", digest, command.CanonicalPayloadHash, err)
		}
		receipt, _ := json.Marshal(command.Receipt)
		if _, err := tx.ExecContext(ctx, `INSERT INTO commands(command_id,actor_id,node_id,kind,canonical_json,canonical_payload_hash,receipt_json,accepted_at,event_seq) VALUES(?,?,?,?,?,?,?,?,?)`,
			command.CommandID, command.ActorID, given.Node.NodeID, command.Receipt.CommandKind, canonical, digest, receipt, command.Receipt.AcceptedAt, command.Receipt.EventSeq); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

type scenarioRows map[string][]map[string]any

// Read every column, including durable receipts, counters and row contents.
// Counting rows would miss in-place corruption during a rejected command.
func projection(t *testing.T, node *Node) scenarioRows {
	t.Helper()
	node.mu.Lock()
	defer node.mu.Unlock()
	value := scenarioRows{}
	for _, table := range []string{"node_state", "dialogs", "messages", "requests", "attempts", "commands", "events", "late_observations", "control_actions", "policy_snapshots", "artifacts", "approvals", "input_requests", "tool_calls"} {
		rows, err := node.db.Query("SELECT * FROM " + table + " ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		value[table] = []map[string]any{}
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			row := map[string]any{}
			for i, column := range columns {
				if bytes, ok := values[i].([]byte); ok {
					values[i] = slices.Clone(bytes)
				}
				row[column] = values[i]
			}
			value[table] = append(value[table], row)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return value
}

func scenarioJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func scenarioDomain(rows scenarioRows, omitLastSequence bool) scenarioRows {
	result := scenarioRows{}
	for table, records := range rows {
		if table == "events" || table == "late_observations" {
			continue
		}
		result[table] = make([]map[string]any, len(records))
		for i, record := range records {
			copy := map[string]any{}
			for key, value := range record {
				if omitLastSequence && table == "node_state" && key == "last_event_seq" {
					continue
				}
				copy[key] = value
			}
			result[table][i] = copy
		}
	}
	return result
}

func openScenario(t *testing.T, given scenarioGiven) (*Node, *fixture.Adapter) {
	t.Helper()
	adapter := fixture.NewAdapter()
	opened, err := Open(context.Background(), Config{DataDir: t.TempDir(), NodeID: given.Node.NodeID, OwnerID: given.Node.OwnerID, RegistryVersion: given.RegistryVersion, Adapter: adapter, Space: fullSpace{}, ManualDispatchForTesting: true, Clock: func() time.Time { return time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := opened.Close(); err != nil {
			t.Error(err)
		}
	})
	seedScenario(t, opened, given)
	return opened, adapter
}

func TestAuthoritativeScenariosExecute(t *testing.T) {
	for _, scenario := range loadScenarios(t).Scenarios {
		t.Run(scenario.ID, func(t *testing.T) {
			opened, adapter := openScenario(t, scenario.Given)
			var otherNodes []*Node
			var otherBefore []string
			for _, given := range scenario.Given.OtherNodes {
				other, _ := openScenario(t, given)
				otherNodes = append(otherNodes, other)
				otherBefore = append(otherBefore, scenarioJSON(t, projection(t, other)))
			}
			before := projection(t, opened)
			if scenario.Operation.Type == "command" {
				result := opened.SubmitCommand(context.Background(), TrustContext{TransportNodeID: scenario.Given.TransportNodeID}, scenario.Operation.Value)
				if result.HTTPStatus != scenario.Expect.HTTPStatus {
					t.Fatalf("status=%d want=%d body=%s", result.HTTPStatus, scenario.Expect.HTTPStatus, result.Body)
				}
				if scenario.Expect.ErrorCode != "" {
					var wireError harnessprotocol.Error
					if err := json.Unmarshal(result.Body, &wireError); err != nil || wireError.Code != scenario.Expect.ErrorCode {
						t.Fatalf("error=%+v decode=%v", wireError, err)
					}
				}
				if scenario.Expect.ReceiptEquals != nil {
					expected, _ := json.Marshal(scenario.Expect.ReceiptEquals)
					if string(expected) != string(result.Body) {
						t.Fatalf("receipt=%s want=%s", result.Body, expected)
					}
				}
			} else {
				err := opened.Observe(context.Background(), Observation{AttemptID: scenario.Operation.AttemptID, Generation: scenario.Operation.Generation, Kind: scenario.Operation.Observation.Kind, TerminalState: scenario.Operation.Observation.TerminalState, Reason: scenario.Operation.Observation.Reason, EffectStatus: scenario.Operation.Observation.EffectStatus, Confirmed: scenario.Operation.Observation.Confirmed})
				if err != nil {
					t.Fatal(err)
				}
			}
			after := projection(t, opened)
			if scenario.Expect.PersistedProjection == "byte_for_byte_unchanged" && scenarioJSON(t, before) != scenarioJSON(t, after) {
				t.Fatal("rejected/replayed durable rows changed")
			}
			if scenario.Expect.DomainProjection == "unchanged" && scenarioJSON(t, scenarioDomain(before, true)) != scenarioJSON(t, scenarioDomain(after, true)) {
				t.Fatal("late observation changed domain rows beyond last_event_seq")
			}
			if scenario.Expect.OtherNodeProjections == "byte_for_byte_unchanged" {
				if len(otherNodes) == 0 {
					t.Fatal("foreign-node assertion has no arranged foreign node")
				}
				for i, other := range otherNodes {
					if scenarioJSON(t, projection(t, other)) != otherBefore[i] {
						t.Fatal("foreign node changed")
					}
				}
			}
			for _, table := range scenario.Expect.UnchangedEntities {
				if _, ok := before[table]; !ok {
					t.Fatalf("unchecked table %s", table)
				}
				if scenarioJSON(t, before[table]) != scenarioJSON(t, after[table]) {
					t.Fatalf("%s changed", table)
				}
			}
			if id := scenario.Expect.QueuedRequestUnchanged; id != "" {
				found := false
				for i, request := range before["requests"] {
					if request["request_id"] == id {
						found = true
						if i >= len(after["requests"]) || scenarioJSON(t, request) != scenarioJSON(t, after["requests"][i]) {
							t.Fatal("queued request changed")
						}
					}
				}
				if !found {
					t.Fatal("queued request assertion has no arranged request")
				}
			}
			if scenario.Expect.PostProjection != nil {
				expectedNode, _ := openScenario(t, *scenario.Expect.PostProjection)
				if scenarioJSON(t, scenarioDomain(after, false)) != scenarioJSON(t, scenarioDomain(projection(t, expectedNode), false)) {
					t.Fatal("post-transition domain rows differ from authoritative corpus")
				}
			}
			if want := scenario.Expect.AppendedObservation; want != nil {
				if len(after["late_observations"]) != len(before["late_observations"])+1 || len(after["events"]) != len(before["events"])+1 {
					t.Fatal("late event/observation count mismatch")
				}
				observation := after["late_observations"][len(after["late_observations"])-1]
				var actual Observation
				encoded, ok := observation["observation_json"].([]byte)
				if !ok || json.Unmarshal(encoded, &actual) != nil || actual.AttemptID != want.AttemptID || actual.Generation != want.Generation || actual.Kind != want.Kind || actual.TerminalState != want.TerminalState {
					t.Fatal("late observation content mismatch")
				}
				last := after["events"][len(after["events"])-1]
				if !want.Late || last["late"] != int64(1) || last["attempt_id"] != want.AttemptID || observation["event_seq"] != last["seq"] {
					t.Fatal("late archive binding mismatch")
				}
			}
			state, err := loadState(context.Background(), opened.db)
			if err != nil {
				t.Fatal(err)
			}
			wantDelta := scenario.Expect.LastEventSeqDelta
			if scenario.Expect.AppendedEventsCount > 0 {
				wantDelta = int64(scenario.Expect.AppendedEventsCount)
			}
			if state.LastEventSeq-scenario.Given.Node.LastEventSeq != wantDelta {
				t.Fatalf("event delta=%d want=%d", state.LastEventSeq-scenario.Given.Node.LastEventSeq, wantDelta)
			}
			if scenario.Expect.ActiveAttemptID != "" && (!state.ActiveAttemptID.Valid || state.ActiveAttemptID.String != scenario.Expect.ActiveAttemptID) {
				t.Fatalf("active attempt=%v want=%s", state.ActiveAttemptID, scenario.Expect.ActiveAttemptID)
			}
			if scenario.Expect.Node != nil {
				if state.StateVersion != scenario.Expect.Node.StateVersion || state.LastEventSeq != scenario.Expect.Node.LastEventSeq || state.QueueVersion != scenario.Expect.Node.QueueVersion || state.QueuePaused != scenario.Expect.Node.QueuePaused || state.PendingCount != scenario.Expect.Node.PendingCount || state.EngineReadiness != scenario.Expect.Node.EngineReadiness || state.Occupancy != scenario.Expect.Node.Occupancy || state.ActiveAttemptID.String != scenario.Expect.Node.ActiveAttemptID || !slices.Equal(state.BlockedReasons, scenario.Expect.Node.BlockedReasons) {
					t.Fatalf("node mismatch: %+v want=%+v", state, *scenario.Expect.Node)
				}
			}
			if scenario.Expect.Attempt != nil {
				var attempt harnessprotocol.Attempt
				if err := opened.db.QueryRow(`SELECT attempt_id,dialog_id,request_id,generation,version,state,effect_status FROM attempts WHERE attempt_id=?`, scenario.Expect.Attempt.AttemptID).Scan(&attempt.AttemptID, &attempt.DialogID, &attempt.RequestID, &attempt.Generation, &attempt.Version, &attempt.State, &attempt.EffectStatus); err != nil {
					t.Fatal(err)
				}
				if attempt.Generation != scenario.Expect.Attempt.Generation || attempt.Version != scenario.Expect.Attempt.Version || attempt.State != scenario.Expect.Attempt.State || attempt.EffectStatus != scenario.Expect.Attempt.EffectStatus {
					t.Fatalf("attempt=%+v want=%+v", attempt, *scenario.Expect.Attempt)
				}
			}
			if len(scenario.Expect.EventsRequired) > 0 {
				rows, err := opened.db.Query(`SELECT event_json FROM events WHERE seq>? ORDER BY seq`, scenario.Given.Node.LastEventSeq)
				if err != nil {
					t.Fatal(err)
				}
				var actual [][]byte
				for rows.Next() {
					var event []byte
					if err := rows.Scan(&event); err != nil {
						t.Fatal(err)
					}
					if err := harnessprotocol.Validate("event", event); err != nil {
						t.Fatalf("invalid stored event: %v", err)
					}
					actual = append(actual, event)
				}
				if err := rows.Err(); err != nil {
					rows.Close()
					t.Fatal(err)
				}
				if err := rows.Close(); err != nil {
					t.Fatal(err)
				}
				if len(actual) != len(scenario.Expect.EventsRequired) {
					t.Fatalf("event count=%d want=%d", len(actual), len(scenario.Expect.EventsRequired))
				}
				for index := range actual {
					var gotValue, wantValue any
					_ = json.Unmarshal(actual[index], &gotValue)
					_ = json.Unmarshal(scenario.Expect.EventsRequired[index], &wantValue)
					gotJSON, _ := json.Marshal(gotValue)
					wantJSON, _ := json.Marshal(wantValue)
					if string(gotJSON) != string(wantJSON) {
						t.Fatalf("event[%d]=%s want=%s", index, gotJSON, wantJSON)
					}
				}
			}
			if want := scenario.Expect.AfterReadinessRefresh; want != nil {
				trust := TrustContext{TransportNodeID: scenario.Given.TransportNodeID}
				ready := opened.HealthReady(context.Background(), trust)
				var health harnessprotocol.HealthReady
				if ready.HTTPStatus != 200 || json.Unmarshal(ready.Body, &health) != nil || !slices.Contains(health.BlockedReasons, want.StillBlockedBy) {
					t.Fatal("readiness hid unknown execution")
				}
				if next, err := opened.DispatchNext(context.Background()); err != nil || next.AttemptID != "" {
					t.Fatal("readiness allowed a second execution", next, err)
				}
				current, err := loadState(context.Background(), opened.db)
				if err != nil || current.ActiveAttemptID.String != want.ActiveAttemptID || scenarioJSON(t, projection(t, opened)) != scenarioJSON(t, after) {
					t.Fatal("readiness check changed unknown projection")
				}
			}
			if calls := adapter.CallsSnapshot(); len(calls) != 0 {
				t.Fatalf("unexpected adapter calls: %+v", calls)
			}
		})
	}
}
