// Package historyreplica owns the additive R11/R12 normalized history
// contract. It is deliberately separate from harness-wire-v2: browser reads
// remain a projection while these records are immutable replication facts.
package historyreplica

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/boxvtk621/harness-codex/internal/strictjson"
)

const (
	SchemaID          = "harness-history-export-v1"
	SchemaSHA256      = "0bf89d20d3e8a5235248257fca1d64ce3af00c33eab3dbfc83a1c680f15ec221"
	ReadSchemaID      = "history-replica-read-v1"
	ReceiptSchemaID   = "history-origin-receipt-v1"
	MaximumPageSize   = 200
	MaximumPageBytes  = 8 * 1024 * 1024
	MaximumChunkBytes = 1024 * 1024
	MaximumSafeInt    = int64(1<<53 - 1)
	GenesisHash       = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	RecordEntry         = "entry"
	RecordExecutionFact = "execution_fact"
	RecordReceipt       = "receipt_revision"
	RecordTextManifest  = "text_manifest"
	RecordTextChunk     = "text_chunk"
	RecordAssetManifest = "asset_manifest"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type StreamIdentity struct {
	OwnerID           string `json:"ownerId"`
	LogicalDialogID   string `json:"logicalDialogId"`
	NodeID            string `json:"nodeId"`
	NodeDialogID      string `json:"nodeDialogId"`
	BindingGeneration int64  `json:"bindingGeneration"`
}

type Origin struct {
	NodeID        string `json:"nodeId"`
	NodeDialogID  string `json:"nodeDialogId"`
	AuthorEventID string `json:"authorEventId"`
}

// Record stores canonical payload bytes. RecordHash excludes stream position;
// ChainHash binds those bytes to one exact stream sequence.
type Record struct {
	StreamSeq  int64           `json:"streamSeq"`
	Type       string          `json:"type"`
	RecordID   string          `json:"recordId"`
	EntityID   string          `json:"entityId"`
	Revision   int64           `json:"revision"`
	Payload    json.RawMessage `json:"payload"`
	RecordHash string          `json:"recordHash"`
	PrevHash   string          `json:"prevHash"`
	ChainHash  string          `json:"chainHash"`
}

type EffectsSummary struct {
	EntryCount           int64 `json:"entryCount"`
	FactCount            int64 `json:"factCount"`
	ReceiptRevisionCount int64 `json:"receiptRevisionCount"`
	TextManifestCount    int64 `json:"textManifestCount"`
	TextChunkCount       int64 `json:"textChunkCount"`
	AssetManifestCount   int64 `json:"assetManifestCount"`
}

type Checkpoint struct {
	ThroughSeq        int64          `json:"throughSeq"`
	ChainHash         string         `json:"chainHash"`
	DialogVersion     int64          `json:"dialogVersion"`
	QueueRevision     int64          `json:"queueRevision"`
	EntriesHash       string         `json:"entriesHash"`
	FactsHash         string         `json:"factsHash"`
	ReceiptsHash      string         `json:"receiptsHash"`
	TextHash          string         `json:"textHash"`
	AssetManifestHash string         `json:"assetManifestHash"`
	EffectsSummary    EffectsSummary `json:"effectsSummary"`
	Ready             bool           `json:"ready"`
	IncompleteReason  string         `json:"incompleteReason,omitempty"`
	CapturedAt        string         `json:"capturedAt"`
}

type ExportPage struct {
	SchemaID     string         `json:"schemaId"`
	SchemaSHA256 string         `json:"schemaSHA256"`
	StreamID     string         `json:"streamId"`
	Identity     StreamIdentity `json:"identity"`
	AfterSeq     int64          `json:"afterSeq"`
	Records      []Record       `json:"records"`
	NextAfter    *int64         `json:"nextAfterSeq"`
	Checkpoint   Checkpoint     `json:"checkpoint"`
}

type TranscriptEntry struct {
	EntryID          string          `json:"entryId"`
	Origin           Origin          `json:"origin"`
	LogicalDialogID  string          `json:"logicalDialogId"`
	MessageID        string          `json:"messageId"`
	RequestID        string          `json:"requestId,omitempty"`
	AttemptID        string          `json:"attemptId,omitempty"`
	Kind             string          `json:"kind"`
	Role             string          `json:"role"`
	Content          json.RawMessage `json:"content"`
	CreatedAt        string          `json:"createdAt"`
	ProfileHash      string          `json:"profileHash,omitempty"`
	SourceGeneration int64           `json:"sourceGeneration"`
	ExecutionOrdinal int64           `json:"executionOrdinal"`
	ExecutionStatus  string          `json:"executionStatus"`
}

type ExecutionFact struct {
	FactID          string          `json:"factId"`
	Origin          Origin          `json:"origin"`
	LogicalDialogID string          `json:"logicalDialogId"`
	RequestID       string          `json:"requestId,omitempty"`
	AttemptID       string          `json:"attemptId,omitempty"`
	Kind            string          `json:"kind"`
	Status          string          `json:"status"`
	EventSeq        int64           `json:"eventSeq"`
	OccurredAt      string          `json:"occurredAt"`
	Event           json.RawMessage `json:"event"`
}

type ReceiptRevision struct {
	ReceiptRevisionID string          `json:"receiptRevisionId"`
	Origin            Origin          `json:"origin"`
	LogicalDialogID   string          `json:"logicalDialogId"`
	CommandID         string          `json:"commandId"`
	CommandKind       string          `json:"commandKind"`
	Fingerprint       string          `json:"fingerprint"`
	RequestID         string          `json:"requestId,omitempty"`
	AttemptID         string          `json:"attemptId,omitempty"`
	Revision          int64           `json:"revision"`
	PredecessorHash   string          `json:"predecessorHash"`
	Admission         string          `json:"admission"`
	Outcome           string          `json:"outcome"`
	Receipt           json.RawMessage `json:"receipt"`
	AcceptedAt        string          `json:"acceptedAt"`
}

type TextManifest struct {
	TextID          string          `json:"textId"`
	Origin          Origin          `json:"origin"`
	LogicalDialogID string          `json:"logicalDialogId"`
	AttemptID       string          `json:"attemptId"`
	Source          json.RawMessage `json:"source"`
	Preview         string          `json:"preview"`
	Redaction       string          `json:"redaction"`
	Complete        bool            `json:"complete"`
	Reason          string          `json:"reason,omitempty"`
	SizeBytes       int64           `json:"sizeBytes"`
	SHA256          string          `json:"sha256"`
	ChunkCount      int64           `json:"chunkCount"`
}

type TextChunk struct {
	TextID          string `json:"textId"`
	LogicalDialogID string `json:"logicalDialogId"`
	ChunkIndex      int64  `json:"chunkIndex"`
	OffsetBytes     int64  `json:"offsetBytes"`
	SizeBytes       int64  `json:"sizeBytes"`
	SHA256          string `json:"sha256"`
	Bytes           []byte `json:"bytes"`
}

type Asset struct {
	ArtifactID string `json:"artifactId"`
	AttemptID  string `json:"attemptId"`
	CallID     string `json:"callId,omitempty"`
	Name       string `json:"name"`
	MediaType  string `json:"mediaType"`
	SizeBytes  int64  `json:"sizeBytes"`
	SHA256     string `json:"sha256"`
	Redaction  string `json:"redaction"`
	Truncated  bool   `json:"truncated"`
}

type AssetManifest struct {
	LogicalDialogID string  `json:"logicalDialogId"`
	Assets          []Asset `json:"assets"`
}

type ReadPage struct {
	SchemaID        string            `json:"schemaId"`
	LogicalDialogID string            `json:"logicalDialogId"`
	Entries         []TranscriptEntry `json:"entries"`
	Facts           []ExecutionFact   `json:"facts"`
	Receipts        []ReceiptRevision `json:"receipts"`
	NextCursor      *string           `json:"nextCursor"`
	SyncedThrough   Checkpoint        `json:"syncedThrough"`
	StreamCoverage  []StreamCoverage  `json:"streamCoverage"`
	ObservedAt      string            `json:"observedAt"`
	LagMillis       int64             `json:"lagMillis"`
	Incomplete      bool              `json:"incomplete"`
}

type StreamCoverage struct {
	StreamID   string `json:"streamId"`
	ThroughSeq int64  `json:"throughSeq"`
	ChainHash  string `json:"chainHash"`
	Complete   bool   `json:"complete"`
	ObservedAt string `json:"observedAt"`
}

type ReceiptLookup struct {
	SchemaID   string          `json:"schemaId"`
	Receipt    ReceiptRevision `json:"receipt"`
	Checkpoint Checkpoint      `json:"checkpoint"`
}

type recordCore struct {
	Type     string          `json:"type"`
	RecordID string          `json:"recordId"`
	EntityID string          `json:"entityId"`
	Revision int64           `json:"revision"`
	Payload  json.RawMessage `json:"payload"`
}

func StableUUID(namespace, value string) string {
	digest := sha256.Sum256([]byte(namespace + "\x00" + value))
	raw := append([]byte(nil), digest[:16]...)
	raw[6] = raw[6]&0x0f | 0x50
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}

func StreamID(identity StreamIdentity) string {
	return StableUUID("history-stream-v1", strings.Join([]string{
		identity.OwnerID, identity.LogicalDialogID, identity.NodeID, identity.NodeDialogID,
		strconv.FormatInt(identity.BindingGeneration, 10),
	}, "\x00"))
}

func HashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func FoldCoverageHash(previous, value string) string {
	return HashBytes([]byte("history-coverage-v1\x00" + previous + "\x00" + value))
}

// ChainGenesis binds an otherwise empty chain to one exact stream identity.
// Entry hashes remain portable across transfers; stream chains do not.
func ChainGenesis(streamID string) string {
	return HashBytes([]byte("history-chain-genesis-v1\x00" + streamID))
}

func HashJSON(value any) (string, []byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", nil, err
	}
	return HashBytes(raw), raw, nil
}

func NewRecord(recordType, recordID, entityID string, revision int64, payload any) (Record, error) {
	raw, err := json.Marshal(payload)
	if err != nil || !strictjson.Valid(raw) {
		return Record{}, errors.New("record payload is invalid")
	}
	core := recordCore{Type: recordType, RecordID: recordID, EntityID: entityID, Revision: revision, Payload: raw}
	hash, _, err := HashJSON(core)
	if err != nil {
		return Record{}, err
	}
	record := Record{Type: recordType, RecordID: recordID, EntityID: entityID, Revision: revision, Payload: raw, RecordHash: hash}
	if err := validateRecordCore(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func SealRecord(record Record, streamID string, sequence int64, previous string) (Record, error) {
	if err := validateRecordCore(record); err != nil || !uuidPattern.MatchString(streamID) ||
		sequence < 1 || sequence > MaximumSafeInt || !sha256Pattern.MatchString(previous) {
		return Record{}, errors.New("record chain input is invalid")
	}
	record.StreamSeq = sequence
	record.PrevHash = previous
	record.ChainHash = HashBytes([]byte("history-chain-v1\x00" + streamID + "\x00" + strconv.FormatInt(sequence, 10) + "\x00" + previous + "\x00" + record.RecordHash))
	return record, nil
}

func ValidatePage(page ExportPage) error {
	if page.SchemaID != SchemaID || page.SchemaSHA256 != SchemaSHA256 || !ValidIdentity(page.Identity) || page.StreamID != StreamID(page.Identity) ||
		page.AfterSeq < 0 || page.AfterSeq > MaximumSafeInt || len(page.Records) > MaximumPageSize ||
		page.AfterSeq > page.Checkpoint.ThroughSeq || !validCheckpoint(page.Checkpoint) {
		return errors.New("history export page is invalid")
	}
	previous := ChainGenesis(page.StreamID)
	if page.AfterSeq > 0 {
		if len(page.Records) == 0 {
			previous = page.Checkpoint.ChainHash
		} else {
			previous = page.Records[0].PrevHash
		}
	}
	for index, record := range page.Records {
		if record.StreamSeq != page.AfterSeq+int64(index)+1 || record.PrevHash != previous || validateRecord(page.StreamID, record) != nil {
			return errors.New("history export chain is invalid")
		}
		previous = record.ChainHash
	}
	if page.NextAfter != nil {
		if len(page.Records) == 0 || *page.NextAfter != page.Records[len(page.Records)-1].StreamSeq || *page.NextAfter >= page.Checkpoint.ThroughSeq {
			return errors.New("history export cursor is invalid")
		}
	} else if len(page.Records) > 0 && page.Records[len(page.Records)-1].StreamSeq != page.Checkpoint.ThroughSeq {
		return errors.New("history export boundary is invalid")
	} else if len(page.Records) == 0 && page.AfterSeq != page.Checkpoint.ThroughSeq {
		return errors.New("history export boundary is missing records")
	} else if page.Checkpoint.ThroughSeq == 0 && page.Checkpoint.ChainHash != ChainGenesis(page.StreamID) {
		return errors.New("history export empty chain is invalid")
	}
	raw, err := json.Marshal(page)
	if err != nil || len(raw) > MaximumPageBytes {
		return errors.New("history export page is too large")
	}
	return nil
}

func ValidIdentity(identity StreamIdentity) bool {
	return identity.OwnerID != "" && utf8.ValidString(identity.OwnerID) && len([]byte(identity.OwnerID)) <= 200 &&
		uuidPattern.MatchString(identity.LogicalDialogID) && uuidPattern.MatchString(identity.NodeID) &&
		uuidPattern.MatchString(identity.NodeDialogID) && identity.BindingGeneration >= 1 && identity.BindingGeneration <= MaximumSafeInt
}

func validateRecord(streamID string, record Record) error {
	if err := validateRecordCore(record); err != nil || record.StreamSeq < 1 || record.StreamSeq > MaximumSafeInt ||
		!sha256Pattern.MatchString(record.PrevHash) || !sha256Pattern.MatchString(record.ChainHash) {
		return errors.New("history record is invalid")
	}
	want := HashBytes([]byte("history-chain-v1\x00" + streamID + "\x00" + strconv.FormatInt(record.StreamSeq, 10) + "\x00" + record.PrevHash + "\x00" + record.RecordHash))
	if record.ChainHash != want {
		return errors.New("history record chain hash mismatch")
	}
	return nil
}

func validateRecordCore(record Record) error {
	validType := record.Type == RecordEntry || record.Type == RecordExecutionFact || record.Type == RecordReceipt ||
		record.Type == RecordTextManifest || record.Type == RecordTextChunk || record.Type == RecordAssetManifest
	if !validType || !uuidPattern.MatchString(record.RecordID) || !uuidPattern.MatchString(record.EntityID) ||
		record.Revision < 1 || record.Revision > MaximumSafeInt || !sha256Pattern.MatchString(record.RecordHash) ||
		len(record.Payload) == 0 || !strictjson.Valid(record.Payload) {
		return errors.New("history record core is invalid")
	}
	core := recordCore{Type: record.Type, RecordID: record.RecordID, EntityID: record.EntityID, Revision: record.Revision, Payload: record.Payload}
	hash, raw, err := HashJSON(core)
	if err != nil || hash != record.RecordHash || !bytes.Equal(bytes.TrimSpace(raw), raw) {
		return errors.New("history record hash mismatch")
	}
	return nil
}

func validCheckpoint(checkpoint Checkpoint) bool {
	if checkpoint.ThroughSeq < 0 || checkpoint.ThroughSeq > MaximumSafeInt || checkpoint.DialogVersion < 1 ||
		checkpoint.DialogVersion > MaximumSafeInt || checkpoint.QueueRevision < 1 || checkpoint.QueueRevision > MaximumSafeInt ||
		checkpoint.CapturedAt == "" || !sha256Pattern.MatchString(checkpoint.ChainHash) ||
		!sha256Pattern.MatchString(checkpoint.EntriesHash) || !sha256Pattern.MatchString(checkpoint.FactsHash) ||
		!sha256Pattern.MatchString(checkpoint.ReceiptsHash) || !sha256Pattern.MatchString(checkpoint.TextHash) ||
		!sha256Pattern.MatchString(checkpoint.AssetManifestHash) {
		return false
	}
	counts := checkpoint.EffectsSummary
	if counts.EntryCount < 0 || counts.FactCount < 0 || counts.ReceiptRevisionCount < 0 ||
		counts.TextManifestCount < 0 || counts.TextChunkCount < 0 || counts.AssetManifestCount < 0 ||
		counts.EntryCount+counts.FactCount+counts.ReceiptRevisionCount+counts.TextManifestCount+
			counts.TextChunkCount+counts.AssetManifestCount != checkpoint.ThroughSeq {
		return false
	}
	return (checkpoint.Ready && checkpoint.IncompleteReason == "") || (!checkpoint.Ready && checkpoint.IncompleteReason != "")
}
