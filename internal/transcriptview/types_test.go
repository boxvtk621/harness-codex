package transcriptview

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestManifestValidation(t *testing.T) {
	hash := sha256.Sum256([]byte("answer"))
	manifest := Manifest{
		SchemaID: SchemaID, NodeID: "10000000-0000-4000-8000-000000000001",
		DialogID: "20000000-0000-4000-8000-000000000001", AttemptID: "30000000-0000-4000-8000-000000000001",
		Generation: 1, TextID: "40000000-0000-4000-8000-000000000001",
		Source:  Source{Kind: "assistant_message", ID: "50000000-0000-4000-8000-000000000001", Stream: "none"},
		Preview: "answer", Redaction: "none", Complete: true, SizeBytes: 6, SHA256: hex.EncodeToString(hash[:]),
		Chunks: []Chunk{{Index: 0, ArtifactID: "60000000-0000-4000-8000-000000000001", SizeBytes: 6, SHA256: hex.EncodeToString(hash[:])}},
	}
	raw, err := Encode(manifest)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw)
	if err != nil || decoded.TextID != manifest.TextID {
		t.Fatalf("decode err=%v manifest=%+v", err, decoded)
	}

	bad := manifest
	bad.Chunks[0].OffsetBytes = 1
	if Validate(bad) == nil {
		t.Fatal("non-contiguous manifest accepted")
	}
	if _, err := Decode(append(raw[:len(raw)-1], []byte(`,"ownerId":"browser"}`)...)); err == nil {
		t.Fatal("unknown manifest field accepted")
	}
}
