package harnessprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type corpus struct {
	ProtocolVersion int       `json:"protocolVersion"`
	SchemaID        string    `json:"schemaId"`
	Fixtures        []fixture `json:"fixtures"`
}

type fixture struct {
	Name                 string          `json:"name"`
	WireType             string          `json:"wireType"`
	ShapeValid           bool            `json:"shapeValid"`
	ErrorCode            string          `json:"errorCode"`
	AuthoritativeOutcome string          `json:"authoritativeOutcome"`
	Value                json.RawMessage `json:"value"`
	Raw                  string          `json:"raw"`
}

func TestSharedFixtureCorpus(t *testing.T) {
	data := readAPIFile(t, "harness-v1.fixtures.json")
	var cases corpus
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if cases.ProtocolVersion != ProtocolVersion || cases.SchemaID != SchemaID {
		t.Fatal("corpus pin mismatch")
	}
	valid, invalid, authoritative := 0, 0, 0
	commandKinds, eventTypes := map[CommandKind]bool{}, map[string]bool{}
	for _, item := range cases.Fixtures {
		t.Run(item.Name, func(t *testing.T) {
			wire := item.Value
			if item.Raw != "" {
				wire = []byte(item.Raw)
			}
			err := Validate(item.WireType, wire)
			if item.ShapeValid && err != nil {
				t.Fatalf("valid fixture rejected: %v", err)
			}
			if !item.ShapeValid && err == nil {
				t.Fatal("invalid fixture accepted")
			}
			if item.AuthoritativeOutcome != "" {
				authoritative++
				if !item.ShapeValid {
					t.Fatal("authoritative state case must remain shape-valid")
				}
			}
			if item.ShapeValid {
				valid++
			} else {
				invalid++
			}
			if item.WireType == "command" && item.ShapeValid {
				decoded, err := DecodeCommand(wire)
				if err != nil {
					t.Fatal(err)
				}
				switch command := decoded.(type) {
				case DialogCreateCommand:
					commandKinds[command.Envelope.Kind] = true
				case DialogDeleteCommand:
					commandKinds[command.Envelope.Kind] = true
				case MessageEnqueueCommand:
					commandKinds[command.Envelope.Kind] = true
				case MessageSteerCommand:
					commandKinds[command.Envelope.Kind] = true
				case RequestCancelCommand:
					commandKinds[command.Envelope.Kind] = true
				case AttemptStopCommand:
					commandKinds[command.Envelope.Kind] = true
				case QueueResumeCommand:
					commandKinds[command.Envelope.Kind] = true
				case AttemptRetryCommand:
					commandKinds[command.Envelope.Kind] = true
				case ApprovalRespondCommand:
					commandKinds[command.Envelope.Kind] = true
				case InputRespondCommand:
					commandKinds[command.Envelope.Kind] = true
				default:
					t.Fatalf("unexpected typed command %T", decoded)
				}
			}
			if item.WireType == "event" && item.ShapeValid {
				event, err := DecodeEvent(wire)
				if err != nil {
					t.Fatal(err)
				}
				eventTypes[event.Envelope.Type] = true
			}
			if item.WireType == "receipt" && item.ShapeValid {
				if _, err := DecodeReceipt(wire); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	if valid < 60 || invalid < 15 || authoritative != 6 {
		t.Fatalf("incomplete corpus: valid=%d invalid=%d authoritative=%d", valid, invalid, authoritative)
	}
	if len(commandKinds) != 10 {
		t.Fatalf("got %d command kinds", len(commandKinds))
	}
	if len(eventTypes) != 24 {
		t.Fatalf("got %d event types", len(eventTypes))
	}
}

func TestGeneratedArtifactHashes(t *testing.T) {
	manifestData := readAPIFile(t, "harness-v1.manifest.json")
	var manifest struct {
		SchemaSHA256    string `json:"schemaSHA256"`
		FixturesSHA256  string `json:"fixturesSHA256"`
		ScenariosSHA256 string `json:"scenariosSHA256"`
		CommandKinds    int    `json:"commandKinds"`
		EventTypes      int    `json:"eventTypes"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	for file, expected := range map[string]string{"harness-v1.schema.json": manifest.SchemaSHA256, "harness-v1.fixtures.json": manifest.FixturesSHA256, "harness-v1.scenarios.json": manifest.ScenariosSHA256} {
		sum := sha256.Sum256(readAPIFile(t, file))
		if actual := hex.EncodeToString(sum[:]); actual != expected {
			t.Fatalf("%s hash %s, manifest %s", file, actual, expected)
		}
	}
	if manifest.CommandKinds != 10 || manifest.EventTypes != 24 {
		t.Fatal("manifest subtype counts changed")
	}
	if manifest.SchemaSHA256 != SchemaSHA256 {
		t.Fatal("compiled schema pin differs from manifest")
	}
}

func TestDialogDeleteDrainClassification(t *testing.T) {
	if IsAdmissionCommand(CommandDialogDelete) || IsDrainBlockedCommand(CommandDialogDelete) || IsDrainControlCommand(CommandDialogDelete) {
		t.Fatal("dialog.delete must remain a non-admission command blocked by the Router control allowlist while draining")
	}
}

func TestAuthoritativeScenarioOperationsUseWireContract(t *testing.T) {
	var document struct {
		ProtocolVersion int    `json:"protocolVersion"`
		SchemaID        string `json:"schemaId"`
		Scenarios       []struct {
			ID        string `json:"id"`
			Operation struct {
				Type  string          `json:"type"`
				Value json.RawMessage `json:"value"`
			} `json:"operation"`
			Expect struct {
				EventsRequired []json.RawMessage `json:"eventsRequired"`
			} `json:"expect"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(readAPIFile(t, "harness-v1.scenarios.json"), &document); err != nil {
		t.Fatal(err)
	}
	if document.ProtocolVersion != ProtocolVersion || document.SchemaID != SchemaID || len(document.Scenarios) != 10 {
		t.Fatal("authoritative scenario corpus pin/count mismatch")
	}
	eventCount := 0
	for _, scenario := range document.Scenarios {
		if scenario.Operation.Type == "command" {
			if err := Validate("command", scenario.Operation.Value); err != nil {
				t.Fatalf("%s operation: %v", scenario.ID, err)
			}
		}
		for index, event := range scenario.Expect.EventsRequired {
			if err := Validate("event", event); err != nil {
				t.Fatalf("%s expected event %d: %v", scenario.ID, index, err)
			}
			eventCount++
		}
	}
	if eventCount != 2 {
		t.Fatalf("authoritative scenarios expected %d typed events, want 2", eventCount)
	}
}

func TestStrictRawAndNullableBoundaries(t *testing.T) {
	valid := `{"protocolVersion":1,"schemaId":"harness-wire-v2","commandId":"10000000-0000-4000-8000-000000000001","kind":"message.enqueue","target":{"nodeId":"20000000-0000-4000-8000-000000000001","dialogId":"30000000-0000-4000-8000-000000000001"},"expected":{"dialogVersion":1},"payload":{"text":"test"}}`
	for name, wire := range map[string]string{
		"nullable target":  replaceOnce(valid, `"target":{`, `"target":null,"discarded":{`),
		"non JSON space":   replaceOnce(valid, `,"schemaId"`, "\u00a0\"schemaId\""),
		"negative integer": replaceOnce(valid, `"dialogVersion":1`, `"dialogVersion":-1`),
		"leading zero":     replaceOnce(valid, `"dialogVersion":1`, `"dialogVersion":01`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := Validate("command", []byte(wire)); err == nil {
				t.Fatal("invalid raw boundary accepted")
			}
		})
	}
}

func TestWireJSONByteLimit(t *testing.T) {
	valid := []byte(`{"protocolVersion":1,"schemaId":"harness-wire-v2","status":"live","processStartedAt":"2026-01-01T00:00:00Z"}`)
	oversized := append(valid, make([]byte, MaximumWireBytes-len(valid)+1)...)
	for index := len(valid); index < len(oversized); index++ {
		oversized[index] = ' '
	}
	if err := Validate("healthLive", oversized); err == nil {
		t.Fatal("oversized wire JSON accepted")
	}
}

func TestAdmissionProfileRequiresExactCompleteCapabilityShape(t *testing.T) {
	profile := AdmissionProfile{
		SchemaID: AdmissionSchemaID, OwnerID: "owner-1", NodeID: "20000000-0000-4000-8000-000000000001",
		RegistrationRevision: 2, IdentityEpoch: 7, WireSchemaSHA256: SchemaSHA256,
		Adapter: AdapterIdentity{Kind: "cursor", Version: "1.0.31"}, Readiness: "ready",
		Capabilities: AdmissionCapabilities{
			Profile: true, NativeEpoch: true, PolicyEnforcement: true, History: true, Facts: true,
			DurableReceipts: true, ReplicaExport: true, ReplicaImport: true, AssetExport: true,
			AssetImport: true, ScopedQuiesce: true, OwnershipRelease: true, TargetReservation: true,
		},
	}
	raw, err := json.Marshal(profile)
	if err != nil || Validate("admissionProfile", raw) != nil {
		t.Fatalf("valid admission profile rejected: %v", err)
	}
	if missing := MissingAdmissionCapabilities(profile.Capabilities); len(missing) != 0 {
		t.Fatalf("complete admission profile reports missing capabilities: %v", missing)
	}
	profile.Capabilities.ReplicaImport = false
	if missing := MissingAdmissionCapabilities(profile.Capabilities); len(missing) != 1 || missing[0] != "replica_import" {
		t.Fatalf("missing capability set=%v", missing)
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("cannot decode admission fixture")
	}
	capabilities := value["capabilities"].(map[string]any)
	delete(capabilities, "target_reservation")
	malformed, _ := json.Marshal(value)
	if Validate("admissionProfile", malformed) == nil {
		t.Fatal("admission profile with omitted capability was accepted")
	}
}

func replaceOnce(value, old, replacement string) string {
	for index := 0; index+len(old) <= len(value); index++ {
		if value[index:index+len(old)] == old {
			return value[:index] + replacement + value[index+len(old):]
		}
	}
	return value
}

func readAPIFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "api", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
