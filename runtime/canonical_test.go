package node_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/boxvtk621/harness-codex/runtime"
)

func TestCanonicalCommandIndependentVectors(t *testing.T) {
	content, err := os.ReadFile("testdata/canonical-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			Name    string          `json:"name"`
			Command json.RawMessage `json:"command"`
			SHA256  string          `json:"sha256"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(content, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Vectors) != 19 {
		t.Fatalf("vector count=%d", len(corpus.Vectors))
	}
	for _, vector := range corpus.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			_, digest, err := node.CanonicalCommand(vector.Command)
			if err != nil {
				t.Fatal(err)
			}
			if digest != vector.SHA256 {
				t.Fatalf("digest=%s want=%s", digest, vector.SHA256)
			}
		})
	}
}
