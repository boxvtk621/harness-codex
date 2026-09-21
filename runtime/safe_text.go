package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/transcriptview"
)

const (
	safeTextArtifactNamePrefix = "safe-text-"
	safeTextManifestMediaType  = "application/vnd.homelab.transcript-view-v1+json"
	safeTextChunkMediaType     = "text/plain; charset=utf-8"
	safeTextUsageMediaType     = "application/vnd.homelab.transcript-usage-v1"
	safeTextDisposition        = "transcript_internal"
	safeTextEmptySHA256        = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	safeTextMaximumSources     = int64(1024)
	safeTextMaximumChunks      = int64(2048)
	safeTextMaximumStorage     = int64(1024 * 1024 * 1024)
	safeTextLimitMarkerReserve = int64(512 * 1024)
)

type safeTextArtifactRow struct {
	artifactID  string
	dialogID    string
	attemptID   string
	callID      string
	name        string
	mediaType   string
	sizeBytes   int64
	sha256      string
	redaction   string
	truncated   bool
	disposition string
	relative    string
}

type safeTextPublishedArtifact struct {
	id       string
	name     string
	media    string
	size     int64
	hash     string
	relative string
}

type safeTextPublication struct {
	node                 *Node
	created              []string
	commitOutcomeUnknown bool
}

type safeTextUsage struct {
	textBytes    int64
	storageBytes int64
	sourceCount  int64
	chunkCount   int64
	sealed       bool
}

func newSafeTextPublication(node *Node) *safeTextPublication {
	return &safeTextPublication{node: node}
}

func (publication *safeTextPublication) publish(artifactID string, content []byte) (string, error) {
	relative, created, err := publication.node.publishSafeTextArtifact(artifactID, content)
	if err == nil && created {
		publication.created = append(publication.created, artifactID)
	}
	return relative, err
}

func (publication *safeTextPublication) retainForCommit() {
	publication.commitOutcomeUnknown = true
}

func (publication *safeTextPublication) cleanupKnownRollback() error {
	if publication.commitOutcomeUnknown || len(publication.created) == 0 {
		return nil
	}
	return removeArtifactFiles(publication.node.config.DataDir, publication.created)
}

type safeTextChunkSpan struct {
	start int
	end   int
	chunk transcriptview.Chunk
}

type SafeTextChunkBlob struct {
	TextID string
	Chunk  transcriptview.Chunk
	Bytes  []byte
}

type safeTextQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

const safeTextArtifactColumns = `artifact_id,dialog_id,attempt_id,COALESCE(call_id,''),name,media_type,size_bytes,sha256,redaction,truncated,disposition,relative_path`

func stableSafeTextUUID(namespace, value string) string {
	sum := sha256.Sum256([]byte(namespace + "\x00" + value))
	raw := sum[:16]
	raw[6] = raw[6]&0x0f | 0x50
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}

func safeTextID(reference harnessadapter.AttemptRef, source transcriptview.Source) string {
	value := strings.Join([]string{
		reference.NodeID, reference.DialogID, reference.RequestID, reference.AttemptID,
		strconv.FormatInt(reference.Generation, 10), source.Kind, source.ID,
		strconv.FormatInt(source.Index, 10), source.Stream,
	}, "\x00")
	return stableSafeTextUUID("transcript-text-v1", value)
}

func safeTextManifestID(textID string) string {
	return stableSafeTextUUID("transcript-manifest-v1", textID)
}

func safeTextChunkID(textID string, index int64) string {
	return stableSafeTextUUID("transcript-chunk-v1", textID+"\x00"+strconv.FormatInt(index, 10))
}

func safeTextUsageID(attemptID string) string {
	return stableSafeTextUUID("transcript-usage-v1", attemptID)
}

func safeTextManifestName(textID string) string {
	return safeTextArtifactNamePrefix + "manifest-" + textID + ".json"
}

func safeTextChunkName(_ string, index int64) string {
	return fmt.Sprintf("%s%02d.txt", safeTextArtifactNamePrefix, index)
}

func safeTextUsageName(attemptID string) string {
	return safeTextArtifactNamePrefix + "usage-" + attemptID + ".state"
}

func reservedSafeTextArtifact(name, mediaType string) bool {
	return strings.HasPrefix(name, safeTextArtifactNamePrefix) || mediaType == safeTextManifestMediaType
}

func safeTextPreview(value string) string {
	if len(value) <= transcriptview.MaximumPreview {
		return value
	}
	preview := value[:transcriptview.MaximumPreview]
	for preview != "" && !utf8.ValidString(preview) {
		preview = preview[:len(preview)-1]
	}
	return preview
}

func safeTextValue(content harnessprotocol.SafeContent, full *string, incomplete bool) (string, bool, error) {
	if content.Kind != "inline" {
		if full != nil || incomplete {
			return "", false, errors.New("non-inline content carried full safe text")
		}
		return "", false, nil
	}
	if content.Redaction != "none" && content.Redaction != "applied" {
		return "", false, errors.New("safe text redaction is invalid")
	}
	if full == nil {
		if incomplete {
			return "", false, errors.New("incomplete safe text has no retained prefix")
		}
		if content.Truncated {
			return "", false, nil
		}
		return content.Content, true, nil
	}
	if !utf8.ValidString(*full) {
		return "", false, errors.New("full safe text is not UTF-8")
	}
	preview := safeTextPreview(*full)
	if content.Content != preview || content.Truncated != (incomplete || len(preview) != len(*full)) {
		return "", false, errors.New("full safe text does not match preview")
	}
	return *full, true, nil
}

func safeTextManifestMatches(manifest transcriptview.Manifest, reference harnessadapter.AttemptRef, source transcriptview.Source, preview, redaction string, size int64, hash string, upstreamIncomplete bool) bool {
	return manifest.NodeID == reference.NodeID && manifest.DialogID == reference.DialogID &&
		manifest.AttemptID == reference.AttemptID && manifest.Generation == reference.Generation && manifest.Source == source &&
		manifest.Preview == preview && manifest.PreviewTruncated == (upstreamIncomplete || int64(len(preview)) != size) &&
		manifest.Redaction == redaction && manifest.SizeBytes == size && manifest.SHA256 == hash &&
		(!upstreamIncomplete || !manifest.Complete)
}

func expectedSafeTextCallID(source transcriptview.Source) string {
	if source.Kind == "assistant_message" {
		return ""
	}
	return source.ID
}

func scanSafeTextArtifact(scanner interface{ Scan(...any) error }, row *safeTextArtifactRow) error {
	return scanner.Scan(
		&row.artifactID, &row.dialogID, &row.attemptID, &row.callID, &row.name, &row.mediaType,
		&row.sizeBytes, &row.sha256, &row.redaction, &row.truncated, &row.disposition, &row.relative,
	)
}

func (node *Node) readSafeTextArtifact(row safeTextArtifactRow) ([]byte, error) {
	metadata := harnessprotocol.ArtifactMetadata{ArtifactID: row.artifactID, SizeBytes: row.sizeBytes, SHA256: row.sha256}
	return node.readArtifactFile(row.relative, metadata)
}

func validateSafeTextManifestRow(row safeTextArtifactRow, raw []byte, manifest transcriptview.Manifest, reference harnessadapter.AttemptRef) error {
	if manifest.NodeID != reference.NodeID || manifest.DialogID != reference.DialogID ||
		manifest.AttemptID != reference.AttemptID || manifest.Generation != reference.Generation ||
		manifest.TextID != safeTextID(reference, manifest.Source) ||
		row.artifactID != safeTextManifestID(manifest.TextID) || row.dialogID != reference.DialogID ||
		row.attemptID != reference.AttemptID || row.callID != expectedSafeTextCallID(manifest.Source) ||
		row.name != safeTextManifestName(manifest.TextID) || row.mediaType != safeTextManifestMediaType ||
		row.sizeBytes != int64(len(raw)) || row.sha256 != digestBytes(raw) || row.redaction != manifest.Redaction ||
		row.truncated || row.disposition != safeTextDisposition || row.relative != filepath.Join("artifacts", row.artifactID) {
		return errors.New("safe text manifest binding mismatch")
	}
	return nil
}

func (node *Node) readSafeTextManifest(ctx context.Context, query safeTextQuery, reference harnessadapter.AttemptRef, source transcriptview.Source) (transcriptview.Manifest, []byte, error) {
	textID := safeTextID(reference, source)
	manifestID := safeTextManifestID(textID)
	var row safeTextArtifactRow
	if err := scanSafeTextArtifact(query.QueryRowContext(ctx, "SELECT "+safeTextArtifactColumns+" FROM artifacts WHERE artifact_id=?", manifestID), &row); err != nil {
		return transcriptview.Manifest{}, nil, err
	}
	raw, err := node.readSafeTextArtifact(row)
	if err != nil {
		return transcriptview.Manifest{}, nil, err
	}
	manifest, err := transcriptview.Decode(raw)
	if err != nil || manifest.Source != source || manifest.TextID != textID {
		return transcriptview.Manifest{}, nil, errors.New("safe text manifest is invalid")
	}
	if err := validateSafeTextManifestRow(row, raw, manifest, reference); err != nil {
		return transcriptview.Manifest{}, nil, err
	}
	if err := node.validateSafeTextRows(ctx, query, manifest); err != nil {
		return transcriptview.Manifest{}, nil, err
	}
	return manifest, raw, nil
}

// validateExistingSafeTextReplay compares private producer bytes on an event
// replay without creating new state. Older durable rows legitimately have no
// transcript manifest; a new replay must not manufacture integration history.
func (node *Node) validateExistingSafeTextReplay(ctx context.Context, tx *sql.Tx, reference harnessadapter.AttemptRef, source transcriptview.Source, content harnessprotocol.SafeContent, full *string, upstreamIncomplete bool) error {
	value, available, err := safeTextValue(content, full, upstreamIncomplete)
	if err != nil || !available {
		return err
	}
	if err := transcriptview.ValidateSource(source); err != nil {
		return err
	}
	manifest, _, err := node.readSafeTextManifest(ctx, tx, reference, source)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !safeTextManifestMatches(manifest, reference, source, safeTextPreview(value), content.Redaction, int64(len(value)), digestString(value), upstreamIncomplete) {
		return errors.New("conflicting safe text source")
	}
	return nil
}

// captureSafeText persists producer-observed safe bytes before its frozen
// wire-v2 preview is committed. Reserved artifact rows retain immutable bytes;
// one reserved usage row bounds private storage without changing wire-v2 or
// the already deployed database compatibility contract.
func (node *Node) captureSafeText(ctx context.Context, tx *sql.Tx, publication *safeTextPublication, reference harnessadapter.AttemptRef, source transcriptview.Source, content harnessprotocol.SafeContent, full *string, upstreamIncomplete bool) error {
	value, available, err := safeTextValue(content, full, upstreamIncomplete)
	if err != nil || !available {
		return err
	}
	if err := transcriptview.ValidateSource(source); err != nil {
		return err
	}
	textHash := digestString(value)
	preview := safeTextPreview(value)

	usage, err := node.loadSafeTextUsage(ctx, tx, publication, reference)
	if err != nil {
		return err
	}

	manifest, _, err := node.readSafeTextManifest(ctx, tx, reference, source)
	if err == nil {
		if !safeTextManifestMatches(manifest, reference, source, preview, content.Redaction, int64(len(value)), textHash, upstreamIncomplete) {
			return errors.New("conflicting safe text source")
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	if usage.sealed {
		return nil
	}
	textID := safeTextID(reference, source)
	manifestBase := transcriptview.Manifest{
		SchemaID: transcriptview.SchemaID, NodeID: reference.NodeID, DialogID: reference.DialogID,
		AttemptID: reference.AttemptID, Generation: reference.Generation, TextID: textID, Source: source,
		Preview: preview, PreviewTruncated: upstreamIncomplete || len(preview) != len(value), Redaction: content.Redaction,
		SizeBytes: int64(len(value)), SHA256: textHash,
	}

	manifest, spans, manifestJSON, complete, err := prepareSafeTextManifest(manifestBase, value, usage, upstreamIncomplete)
	if err != nil {
		return err
	}
	published := make([]safeTextPublishedArtifact, 0)
	if complete {
		for _, span := range spans {
			chunkBytes := []byte(value[span.start:span.end])
			relative, err := publication.publish(span.chunk.ArtifactID, chunkBytes)
			if err != nil {
				return err
			}
			published = append(published, safeTextPublishedArtifact{
				id: span.chunk.ArtifactID, name: safeTextChunkName(textID, span.chunk.Index), media: safeTextChunkMediaType,
				size: span.chunk.SizeBytes, hash: span.chunk.SHA256, relative: relative,
			})
		}
	}
	manifestID := safeTextManifestID(textID)
	manifestRelative, err := publication.publish(manifestID, manifestJSON)
	if err != nil {
		return err
	}
	callID := expectedSafeTextCallID(source)
	for _, artifact := range published {
		if err := insertSafeTextArtifact(ctx, tx, reference, callID, artifact, content.Redaction); err != nil {
			return err
		}
	}
	if err := insertSafeTextArtifact(ctx, tx, reference, callID, safeTextPublishedArtifact{
		id: manifestID, name: safeTextManifestName(textID), media: safeTextManifestMediaType,
		size: int64(len(manifestJSON)), hash: digestBytes(manifestJSON), relative: manifestRelative,
	}, content.Redaction); err != nil {
		return err
	}
	return updateSafeTextUsage(ctx, tx, reference.AttemptID, usage, manifest, int64(len(manifestJSON)))
}

func prepareSafeTextManifest(base transcriptview.Manifest, value string, usage safeTextUsage, upstreamIncomplete bool) (transcriptview.Manifest, []safeTextChunkSpan, []byte, bool, error) {
	if !upstreamIncomplete && int64(len(value)) <= transcriptview.MaximumTextBytes {
		complete := base
		complete.Complete = true
		complete.Chunks = []transcriptview.Chunk{}
		spans := make([]safeTextChunkSpan, 0, (len(value)+transcriptview.MaximumChunkBytes-1)/transcriptview.MaximumChunkBytes)
		for start, index := 0, int64(0); start < len(value); index++ {
			end := start + transcriptview.MaximumChunkBytes
			if end > len(value) {
				end = len(value)
			}
			for end > start && !utf8.ValidString(value[start:end]) {
				end--
			}
			if end == start {
				return transcriptview.Manifest{}, nil, nil, false, errors.New("safe text chunk boundary is invalid")
			}
			chunkBytes := []byte(value[start:end])
			chunk := transcriptview.Chunk{
				Index: index, OffsetBytes: int64(start), ArtifactID: safeTextChunkID(base.TextID, index),
				SizeBytes: int64(len(chunkBytes)), SHA256: digestBytes(chunkBytes),
			}
			complete.Chunks = append(complete.Chunks, chunk)
			spans = append(spans, safeTextChunkSpan{start: start, end: end, chunk: chunk})
			start = end
		}
		encoded, err := transcriptview.Encode(complete)
		if err != nil {
			return transcriptview.Manifest{}, nil, nil, false, err
		}
		storageBytes := int64(len(value)) + int64(len(encoded))
		if safeTextCanStoreComplete(usage, int64(len(value)), storageBytes, int64(len(spans))) {
			return complete, spans, encoded, true, nil
		}
	}

	incomplete := base
	incomplete.Complete = false
	incomplete.Reason = "output_limit_exceeded"
	incomplete.Chunks = []transcriptview.Chunk{}
	encoded, err := transcriptview.Encode(incomplete)
	if err != nil {
		return transcriptview.Manifest{}, nil, nil, false, err
	}
	if int64(len(encoded)) > safeTextLimitMarkerReserve || usage.sourceCount >= safeTextMaximumSources ||
		usage.storageBytes > safeTextMaximumStorage-int64(len(encoded)) {
		return transcriptview.Manifest{}, nil, nil, false, errors.New("safe text usage reserve is invalid")
	}
	return incomplete, nil, encoded, false, nil
}

func insertSafeTextArtifact(ctx context.Context, tx *sql.Tx, reference harnessadapter.AttemptRef, callID string, artifact safeTextPublishedArtifact, redaction string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO artifacts(artifact_id,dialog_id,attempt_id,call_id,name,media_type,size_bytes,sha256,redaction,truncated,disposition,relative_path) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		artifact.id, reference.DialogID, reference.AttemptID, nullText(callID), artifact.name, artifact.media,
		artifact.size, artifact.hash, redaction, false, safeTextDisposition, artifact.relative)
	return err
}

func encodeSafeTextUsage(usage safeTextUsage) string {
	return fmt.Sprintf("v1:%d:%d:%d:%d", usage.textBytes, usage.storageBytes, usage.sourceCount, usage.chunkCount)
}

func decodeSafeTextUsage(encoded string, sealed bool) (safeTextUsage, error) {
	parts := strings.Split(encoded, ":")
	if len(parts) != 5 || parts[0] != "v1" {
		return safeTextUsage{}, errors.New("safe text usage encoding is invalid")
	}
	values := make([]int64, 4)
	for index, part := range parts[1:] {
		value, err := strconv.ParseInt(part, 10, 64)
		if err != nil || strconv.FormatInt(value, 10) != part {
			return safeTextUsage{}, errors.New("safe text usage encoding is invalid")
		}
		values[index] = value
	}
	usage := safeTextUsage{
		textBytes: values[0], storageBytes: values[1], sourceCount: values[2], chunkCount: values[3], sealed: sealed,
	}
	if !validSafeTextUsage(usage) {
		return safeTextUsage{}, errors.New("safe text usage is invalid")
	}
	return usage, nil
}

func (node *Node) loadSafeTextUsage(ctx context.Context, tx *sql.Tx, publication *safeTextPublication, reference harnessadapter.AttemptRef) (safeTextUsage, error) {
	artifactID := safeTextUsageID(reference.AttemptID)
	var row safeTextArtifactRow
	err := scanSafeTextArtifact(tx.QueryRowContext(ctx, "SELECT "+safeTextArtifactColumns+" FROM artifacts WHERE artifact_id=?", artifactID), &row)
	if errors.Is(err, sql.ErrNoRows) {
		relative, publishErr := publication.publish(artifactID, nil)
		if publishErr != nil {
			return safeTextUsage{}, publishErr
		}
		initial := safeTextUsage{}
		_, insertErr := tx.ExecContext(ctx, `INSERT INTO artifacts(artifact_id,dialog_id,attempt_id,call_id,name,media_type,size_bytes,sha256,redaction,truncated,disposition,relative_path) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
			artifactID, reference.DialogID, reference.AttemptID, encodeSafeTextUsage(initial), safeTextUsageName(reference.AttemptID),
			safeTextUsageMediaType, 0, safeTextEmptySHA256, "none", false, safeTextDisposition, relative)
		if insertErr != nil {
			return safeTextUsage{}, insertErr
		}
		return initial, nil
	}
	if err != nil {
		return safeTextUsage{}, err
	}
	if row.artifactID != artifactID || row.dialogID != reference.DialogID || row.attemptID != reference.AttemptID ||
		row.name != safeTextUsageName(reference.AttemptID) || row.mediaType != safeTextUsageMediaType || row.sizeBytes != 0 ||
		row.sha256 != safeTextEmptySHA256 || row.redaction != "none" || row.disposition != safeTextDisposition ||
		row.relative != filepath.Join("artifacts", artifactID) {
		return safeTextUsage{}, errors.New("safe text usage binding mismatch")
	}
	if body, readErr := node.readSafeTextArtifact(row); readErr != nil || len(body) != 0 {
		return safeTextUsage{}, errors.New("safe text usage artifact mismatch")
	}
	return decodeSafeTextUsage(row.callID, row.truncated)
}

func validSafeTextUsage(usage safeTextUsage) bool {
	return usage.textBytes >= 0 && usage.textBytes <= transcriptview.MaximumTextBytes &&
		usage.storageBytes >= 0 && usage.storageBytes <= safeTextMaximumStorage &&
		usage.sourceCount >= 0 && usage.sourceCount <= safeTextMaximumSources &&
		usage.chunkCount >= 0 && usage.chunkCount <= safeTextMaximumChunks && (!usage.sealed || usage.sourceCount > 0)
}

func safeTextCanStoreComplete(usage safeTextUsage, textBytes, storageBytes, chunks int64) bool {
	return validSafeTextUsage(usage) && !usage.sealed && textBytes >= 0 && storageBytes >= textBytes && chunks >= 0 &&
		usage.textBytes <= transcriptview.MaximumTextBytes-textBytes &&
		usage.storageBytes <= safeTextMaximumStorage-safeTextLimitMarkerReserve-storageBytes &&
		usage.sourceCount < safeTextMaximumSources-1 && usage.chunkCount <= safeTextMaximumChunks-chunks
}

func updateSafeTextUsage(ctx context.Context, tx *sql.Tx, attemptID string, prior safeTextUsage, manifest transcriptview.Manifest, manifestBytes int64) error {
	next := prior
	next.sourceCount++
	next.storageBytes += manifestBytes
	if manifest.Complete {
		next.textBytes += manifest.SizeBytes
		next.storageBytes += manifest.SizeBytes
		next.chunkCount += int64(len(manifest.Chunks))
	} else {
		next.sealed = true
	}
	if !validSafeTextUsage(next) {
		return errors.New("safe text usage update exceeds bound")
	}
	result, err := tx.ExecContext(ctx, `UPDATE artifacts SET call_id=?,truncated=?
		WHERE artifact_id=? AND call_id=? AND truncated=? AND media_type=? AND disposition=?`,
		encodeSafeTextUsage(next), next.sealed, safeTextUsageID(attemptID), encodeSafeTextUsage(prior), prior.sealed,
		safeTextUsageMediaType, safeTextDisposition)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return errors.New("safe text usage fence changed")
	}
	return nil
}

func (node *Node) publishSafeTextArtifact(artifactID string, content []byte) (string, bool, error) {
	directory := filepath.Join(node.config.DataDir, "artifacts")
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", false, err
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || validateOwner(info) != nil {
		return "", false, errors.New("artifact directory is unsafe")
	}
	relative := filepath.Join("artifacts", artifactID)
	final := filepath.Join(directory, artifactID)
	metadata := harnessprotocol.ArtifactMetadata{ArtifactID: artifactID, SizeBytes: int64(len(content)), SHA256: digestBytes(content)}
	if _, err := os.Lstat(final); err == nil {
		body, readErr := node.readArtifactFile(relative, metadata)
		if readErr != nil || !bytes.Equal(body, content) {
			return "", false, errors.New("orphan safe text artifact conflicts with source")
		}
		return relative, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	temporaryID, err := node.newID()
	if err != nil {
		return "", false, err
	}
	temporary := filepath.Join(directory, "."+temporaryID+".tmp")
	file, err := secureOpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", false, err
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(temporary)
			_ = os.Remove(final)
			if directoryHandle, openErr := os.Open(directory); openErr == nil {
				_ = directoryHandle.Sync()
				_ = directoryHandle.Close()
			}
		}
	}()
	written, err := io.Copy(file, bytes.NewReader(content))
	if err != nil || written != int64(len(content)) {
		return "", false, errors.New("safe text artifact write failed")
	}
	if err := file.Sync(); err != nil {
		return "", false, err
	}
	if err := file.Close(); err != nil {
		return "", false, err
	}
	if err := os.Rename(temporary, final); err != nil {
		return "", false, err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return "", false, err
	}
	if err := directoryHandle.Sync(); err != nil {
		directoryHandle.Close()
		return "", false, err
	}
	if err := directoryHandle.Close(); err != nil {
		return "", false, err
	}
	keep = true
	return relative, true, nil
}

func digestBytes(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func digestString(content string) string {
	digest := sha256.New()
	_, _ = io.WriteString(digest, content)
	return hex.EncodeToString(digest.Sum(nil))
}

func (node *Node) SafeTextManifest(ctx context.Context, trust TrustContext, dialogID, attemptID string, source transcriptview.Source) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	if !uuidPattern.MatchString(dialogID) || !uuidPattern.MatchString(attemptID) || transcriptview.ValidateSource(source) != nil {
		return node.Invalid("transcript source is invalid")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return node.errorResult(503, "not_durable", "safe text is unavailable", source.ID, nil, "")
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return node.errorResult(503, "not_durable", "safe text is unavailable", source.ID, nil, "")
	}
	reference, err := safeTextReference(ctx, tx, state, dialogID, attemptID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return node.errorResult(404, "not_found", "safe text was not found", source.ID, nil, "")
		}
		return node.errorResult(503, "not_durable", "safe text is unavailable", source.ID, nil, "")
	}
	_, raw, err := node.readSafeTextManifest(ctx, tx, reference, source)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return node.errorResult(404, "not_found", "safe text was not found", source.ID, nil, "")
		}
		return node.errorResult(503, "not_durable", "safe text manifest mismatch", source.ID, nil, "")
	}
	return Result{HTTPStatus: 200, Body: bytes.Clone(raw)}
}

func safeTextReference(ctx context.Context, query safeTextQuery, state durableState, dialogID, attemptID string) (harnessadapter.AttemptRef, error) {
	var requestID string
	var generation int64
	err := query.QueryRowContext(ctx, `SELECT a.request_id,a.generation FROM attempts a JOIN dialogs d ON d.dialog_id=a.dialog_id
		WHERE a.attempt_id=? AND a.dialog_id=? AND d.node_id=? AND d.owner_id=? AND NOT EXISTS (
			SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`,
		attemptID, dialogID, state.NodeID, state.OwnerID).Scan(&requestID, &generation)
	if err != nil {
		return harnessadapter.AttemptRef{}, err
	}
	return harnessadapter.AttemptRef{
		NodeID: state.NodeID, DialogID: dialogID, RequestID: requestID, AttemptID: attemptID, Generation: generation,
	}, nil
}

func validSafeTextHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

// SafeTextChunk exposes one bounded chunk only after the complete exact
// owner/node/dialog/attempt/source/text/index/id/size/hash binding is proven.
// Generic artifact reads intentionally cannot address transcript_internal rows.
func (node *Node) SafeTextChunk(ctx context.Context, trust TrustContext, dialogID, attemptID, textID string, source transcriptview.Source, chunkIndex int64, artifactID string, sizeBytes int64, hash string) (SafeTextChunkBlob, Result, bool) {
	if denied := node.authorizeRead(trust); denied != nil {
		return SafeTextChunkBlob{}, *denied, false
	}
	if !uuidPattern.MatchString(dialogID) || !uuidPattern.MatchString(attemptID) || !uuidPattern.MatchString(textID) ||
		!uuidPattern.MatchString(artifactID) || chunkIndex < 0 || chunkIndex > transcriptview.MaximumSafeInt ||
		sizeBytes < 1 || sizeBytes > transcriptview.MaximumChunkBytes || !validSafeTextHash(hash) ||
		transcriptview.ValidateSource(source) != nil {
		return SafeTextChunkBlob{}, node.Invalid("transcript chunk is invalid"), false
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return SafeTextChunkBlob{}, node.errorResult(503, "not_durable", "safe text is unavailable", source.ID, nil, ""), false
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return SafeTextChunkBlob{}, node.errorResult(503, "not_durable", "safe text is unavailable", source.ID, nil, ""), false
	}
	reference, err := safeTextReference(ctx, tx, state, dialogID, attemptID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SafeTextChunkBlob{}, node.errorResult(404, "not_found", "safe text was not found", source.ID, nil, ""), false
		}
		return SafeTextChunkBlob{}, node.errorResult(503, "not_durable", "safe text is unavailable", source.ID, nil, ""), false
	}
	manifest, _, err := node.readSafeTextManifest(ctx, tx, reference, source)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SafeTextChunkBlob{}, node.errorResult(404, "not_found", "safe text was not found", source.ID, nil, ""), false
		}
		return SafeTextChunkBlob{}, node.errorResult(503, "not_durable", "safe text manifest mismatch", source.ID, nil, ""), false
	}
	if !manifest.Complete || manifest.TextID != textID || chunkIndex >= int64(len(manifest.Chunks)) {
		return SafeTextChunkBlob{}, node.errorResult(404, "not_found", "safe text chunk was not found", source.ID, nil, ""), false
	}
	chunk := manifest.Chunks[chunkIndex]
	if chunk.Index != chunkIndex || chunk.ArtifactID != artifactID || chunk.SizeBytes != sizeBytes || chunk.SHA256 != hash {
		return SafeTextChunkBlob{}, node.errorResult(404, "not_found", "safe text chunk was not found", source.ID, nil, ""), false
	}
	var row safeTextArtifactRow
	if err := scanSafeTextArtifact(tx.QueryRowContext(ctx, "SELECT "+safeTextArtifactColumns+" FROM artifacts WHERE artifact_id=?", artifactID), &row); err != nil {
		return SafeTextChunkBlob{}, node.errorResult(503, "not_durable", "safe text chunk is unavailable", source.ID, nil, ""), false
	}
	body, err := node.readSafeTextArtifact(row)
	if err != nil {
		return SafeTextChunkBlob{}, node.errorResult(503, "not_durable", "safe text chunk mismatch", source.ID, nil, ""), false
	}
	return SafeTextChunkBlob{TextID: manifest.TextID, Chunk: chunk, Bytes: body}, Result{}, true
}

func (node *Node) validateSafeTextRows(ctx context.Context, query safeTextQuery, manifest transcriptview.Manifest) error {
	expectedCallID := expectedSafeTextCallID(manifest.Source)
	for _, chunk := range manifest.Chunks {
		var row safeTextArtifactRow
		if err := scanSafeTextArtifact(query.QueryRowContext(ctx, "SELECT "+safeTextArtifactColumns+" FROM artifacts WHERE artifact_id=?", chunk.ArtifactID), &row); err != nil {
			return err
		}
		if chunk.ArtifactID != safeTextChunkID(manifest.TextID, chunk.Index) || row.artifactID != chunk.ArtifactID ||
			row.dialogID != manifest.DialogID || row.attemptID != manifest.AttemptID || row.callID != expectedCallID ||
			row.name != safeTextChunkName(manifest.TextID, chunk.Index) || row.mediaType != safeTextChunkMediaType ||
			row.sizeBytes != chunk.SizeBytes || row.sha256 != chunk.SHA256 || row.redaction != manifest.Redaction ||
			row.truncated || row.disposition != safeTextDisposition || row.relative != filepath.Join("artifacts", row.artifactID) {
			return errors.New("safe text chunk binding mismatch")
		}
	}
	return nil
}
