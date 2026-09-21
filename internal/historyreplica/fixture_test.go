package historyreplica

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestCanonicalFixtureMatchesProducerContract(t *testing.T) {
	schema, err := os.ReadFile("../../api/history-replica-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(schema)
	if hex.EncodeToString(digest[:]) != SchemaSHA256 {
		t.Fatal("compiled history schema pin is stale")
	}
	raw, err := os.ReadFile("../../api/history-replica-v1.fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ValidPage ExportPage `json:"validPage"`
	}
	if json.Unmarshal(raw, &fixture) != nil || ValidatePage(fixture.ValidPage) != nil {
		t.Fatal("canonical history fixture is not valid for producer")
	}
}
