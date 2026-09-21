// Package transcriptview owns the additive transcript-view-v1 contract.
// It is deliberately separate from the frozen harness-wire-v2 schema.
package transcriptview

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"unicode/utf8"

	"github.com/boxvtk621/harness-codex/internal/strictjson"
)

const (
	SchemaID          = "transcript-view-v1"
	SchemaSHA256      = "301f1c9457434d3c6ed1c663cc33ba9ca41b1f0da35621792dae5c1dd205e326"
	MaximumPreview    = 64 * 1024
	MaximumChunkBytes = 16 * 1024 * 1024
	MaximumTextBytes  = int64(512 * 1024 * 1024)
	MaximumChunks     = 64
	MaximumSafeInt    = int64(1<<53 - 1)
	TextIDHeader      = "X-Harness-Transcript-Text-ID"
	ChunkIndexHeader  = "X-Harness-Transcript-Chunk-Index"
	ArtifactIDHeader  = "X-Harness-Transcript-Artifact-ID"
	ChunkSHA256Header = "X-Harness-Transcript-Chunk-SHA256"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Source struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Index  int64  `json:"index"`
	Stream string `json:"stream"`
}

type Chunk struct {
	Index       int64  `json:"index"`
	OffsetBytes int64  `json:"offsetBytes"`
	ArtifactID  string `json:"artifactId"`
	SizeBytes   int64  `json:"sizeBytes"`
	SHA256      string `json:"sha256"`
}

type Manifest struct {
	SchemaID         string  `json:"schemaId"`
	NodeID           string  `json:"nodeId"`
	DialogID         string  `json:"dialogId"`
	AttemptID        string  `json:"attemptId"`
	Generation       int64   `json:"generation"`
	TextID           string  `json:"textId"`
	Source           Source  `json:"source"`
	Preview          string  `json:"preview"`
	PreviewTruncated bool    `json:"previewTruncated"`
	Redaction        string  `json:"redaction"`
	Complete         bool    `json:"complete"`
	Reason           string  `json:"reason,omitempty"`
	SizeBytes        int64   `json:"sizeBytes"`
	SHA256           string  `json:"sha256"`
	Chunks           []Chunk `json:"chunks"`
}

func Encode(manifest Manifest) ([]byte, error) {
	if err := Validate(manifest); err != nil {
		return nil, err
	}
	return json.Marshal(manifest)
}

func Decode(raw []byte) (Manifest, error) {
	var manifest Manifest
	if !strictjson.Valid(raw) {
		return manifest, errors.New("transcript manifest is not strict JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, errors.New("transcript manifest shape is invalid")
	}
	if decoder.Decode(new(any)) == nil {
		return Manifest{}, errors.New("transcript manifest has trailing data")
	}
	if err := Validate(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func Validate(manifest Manifest) error {
	if manifest.SchemaID != SchemaID || !uuidPattern.MatchString(manifest.NodeID) ||
		!uuidPattern.MatchString(manifest.DialogID) || !uuidPattern.MatchString(manifest.AttemptID) ||
		!uuidPattern.MatchString(manifest.TextID) || manifest.Generation < 1 || manifest.Generation > MaximumSafeInt ||
		!validSource(manifest.Source) || !utf8.ValidString(manifest.Preview) || len(manifest.Preview) > MaximumPreview ||
		(manifest.Redaction != "none" && manifest.Redaction != "applied") ||
		manifest.SizeBytes < 0 || manifest.SizeBytes > MaximumSafeInt || !sha256Pattern.MatchString(manifest.SHA256) {
		return errors.New("transcript manifest is invalid")
	}
	if !manifest.Complete {
		if manifest.Reason != "output_limit_exceeded" || len(manifest.Chunks) != 0 {
			return errors.New("incomplete transcript manifest is invalid")
		}
		return nil
	}
	if manifest.Reason != "" || manifest.SizeBytes > MaximumTextBytes || len(manifest.Chunks) > MaximumChunks {
		return errors.New("complete transcript manifest is invalid")
	}
	if manifest.SizeBytes == 0 {
		if len(manifest.Chunks) != 0 {
			return errors.New("empty transcript manifest has chunks")
		}
		return nil
	}
	if len(manifest.Chunks) == 0 {
		return errors.New("complete transcript manifest has no chunks")
	}
	offset := int64(0)
	seen := make(map[string]struct{}, len(manifest.Chunks))
	for index, chunk := range manifest.Chunks {
		if chunk.Index != int64(index) || chunk.OffsetBytes != offset || chunk.SizeBytes < 1 ||
			chunk.SizeBytes > MaximumChunkBytes || !uuidPattern.MatchString(chunk.ArtifactID) ||
			!sha256Pattern.MatchString(chunk.SHA256) {
			return errors.New("transcript chunk manifest is invalid")
		}
		if _, duplicate := seen[chunk.ArtifactID]; duplicate {
			return errors.New("transcript chunk artifact is repeated")
		}
		seen[chunk.ArtifactID] = struct{}{}
		offset += chunk.SizeBytes
	}
	if offset != manifest.SizeBytes {
		return errors.New("transcript chunk sizes do not cover text")
	}
	return nil
}

func ValidateSource(source Source) error {
	if !validSource(source) {
		return errors.New("transcript source is invalid")
	}
	return nil
}

func validSource(source Source) bool {
	if !uuidPattern.MatchString(source.ID) {
		return false
	}
	switch source.Kind {
	case "assistant_message", "tool_input", "tool_result":
		return source.Index == 0 && source.Stream == "none"
	case "tool_output":
		return source.Index >= 0 && source.Index <= MaximumSafeInt &&
			(source.Stream == "stdout" || source.Stream == "stderr" || source.Stream == "result" || source.Stream == "diagnostic")
	default:
		return false
	}
}
