package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

type ArtifactInput struct {
	Attempt     harnessadapter.AttemptRef
	CallID      string
	Name        string
	MediaType   string
	Redaction   string
	Truncated   bool
	Disposition string
}

type ArtifactBlob struct {
	Metadata harnessprotocol.ArtifactMetadata
	Bytes    []byte
}

// ArtifactSink is the provider-neutral out-of-band byte ingress missing from
// the closed C1 event union. A native adapter receives an ArtifactIngress at
// construction time; Open binds it to exactly one node and Close waits for any
// in-flight ingestion before making it unavailable.
type ArtifactSink interface {
	StoreArtifact(context.Context, ArtifactInput, []byte) (harnessprotocol.ArtifactMetadata, error)
}

type ArtifactIngress struct {
	mu     sync.Mutex
	ready  *sync.Cond
	node   *Node
	active int
}

func NewArtifactIngress() *ArtifactIngress {
	ingress := &ArtifactIngress{}
	ingress.ready = sync.NewCond(&ingress.mu)
	return ingress
}

func (ingress *ArtifactIngress) bind(node *Node) error {
	ingress.mu.Lock()
	defer ingress.mu.Unlock()
	if ingress.node != nil {
		return errors.New("artifact ingress is already bound")
	}
	ingress.node = node
	return nil
}

func (ingress *ArtifactIngress) unbind(node *Node) {
	ingress.mu.Lock()
	if ingress.node != node {
		ingress.mu.Unlock()
		return
	}
	ingress.node = nil
	for ingress.active > 0 {
		ingress.ready.Wait()
	}
	ingress.mu.Unlock()
}

func (ingress *ArtifactIngress) StoreArtifact(ctx context.Context, input ArtifactInput, content []byte) (harnessprotocol.ArtifactMetadata, error) {
	ingress.mu.Lock()
	bound := ingress.node
	if bound == nil {
		ingress.mu.Unlock()
		return harnessprotocol.ArtifactMetadata{}, errors.New("artifact ingress is unavailable")
	}
	ingress.active++
	ingress.mu.Unlock()
	defer func() { ingress.mu.Lock(); ingress.active--; ingress.ready.Broadcast(); ingress.mu.Unlock() }()
	return bound.StoreArtifact(ctx, input, content)
}

func (node *Node) ArtifactSink() ArtifactSink { return node.config.Artifacts }

// StoreArtifact durably ingests safe adapter output into a B1-owned file. A1/A2
// must receive this sink explicitly; the C1 Adapter interface has no artifact
// byte transport and this method is never exposed to the browser.
func (node *Node) StoreArtifact(ctx context.Context, input ArtifactInput, content []byte) (harnessprotocol.ArtifactMetadata, error) {
	if len(content) > harnessprotocol.MaximumArtifactBytes || input.Attempt.NodeID != node.config.NodeID || !uuidPattern.MatchString(input.Attempt.DialogID) || !uuidPattern.MatchString(input.Attempt.RequestID) || !uuidPattern.MatchString(input.Attempt.AttemptID) || input.Attempt.Generation < 1 || (input.CallID != "" && !uuidPattern.MatchString(input.CallID)) || !boundedArtifactText(input.Name) || strings.ContainsAny(input.Name, "/\\\x00\r\n") || !boundedArtifactText(input.MediaType) || reservedSafeTextArtifact(input.Name, input.MediaType) || (input.Redaction != "none" && input.Redaction != "applied") || (input.Disposition != "inline" && input.Disposition != "attachment") {
		return harnessprotocol.ArtifactMetadata{}, errors.New("artifact input is invalid")
	}
	content = bytes.Clone(content)
	artifactID, err := node.newID()
	if err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	directory := filepath.Join(node.config.DataDir, "artifacts")
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || validateOwner(info) != nil {
		return harnessprotocol.ArtifactMetadata{}, errors.New("artifact directory is unsafe")
	}
	temporary := filepath.Join(directory, "."+artifactID+".tmp")
	final := filepath.Join(directory, artifactID)
	file, err := secureOpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(temporary)
			_ = os.Remove(final)
			if directoryHandle, err := os.Open(directory); err == nil {
				_ = directoryHandle.Sync()
				_ = directoryHandle.Close()
			}
		}
	}()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), bytes.NewReader(content))
	if err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	if err := file.Sync(); err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	if err := file.Close(); err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	if err := os.Rename(temporary, final); err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	if err := directoryHandle.Sync(); err != nil {
		directoryHandle.Close()
		return harnessprotocol.ArtifactMetadata{}, err
	}
	if err := directoryHandle.Close(); err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	relative := filepath.Join("artifacts", artifactID)

	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	var dialogID string
	var requestID string
	var generation, attemptVersion int64
	var attemptState string
	if err := tx.QueryRowContext(ctx, `SELECT a.dialog_id,a.request_id,a.generation,a.version,a.state FROM attempts a JOIN dialogs d ON d.dialog_id=a.dialog_id WHERE a.attempt_id=? AND d.node_id=? AND d.owner_id=? AND NOT EXISTS (
		SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`, input.Attempt.AttemptID, state.NodeID, state.OwnerID).Scan(&dialogID, &requestID, &generation, &attemptVersion, &attemptState); err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	if dialogID != input.Attempt.DialogID || requestID != input.Attempt.RequestID || generation != input.Attempt.Generation {
		return harnessprotocol.ArtifactMetadata{}, errors.New("artifact attempt scope mismatch")
	}
	if input.CallID != "" {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM tool_calls WHERE call_id=? AND attempt_id=?`, input.CallID, input.Attempt.AttemptID).Scan(&exists); err != nil {
			return harnessprotocol.ArtifactMetadata{}, err
		}
	}
	charge, err := chargeAttemptOutput(ctx, tx, input.Attempt.AttemptID, int64(len(content)))
	if err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	if charge.Exceeded {
		if charge.NewlyExceeded {
			if err := node.appendArtifactOutputLimitMarker(ctx, tx, &state, input.Attempt, attemptVersion); err != nil {
				return harnessprotocol.ArtifactMetadata{}, err
			}
			if state.ActiveAttemptID.Valid && state.ActiveAttemptID.String == input.Attempt.AttemptID && (attemptState == "running" || attemptState == "waiting_input") {
				if err := node.scheduleOutputLimitStop(ctx, tx, &state, input.Attempt); err != nil {
					return harnessprotocol.ArtifactMetadata{}, err
				}
			}
			if err := saveState(ctx, tx, state); err != nil {
				return harnessprotocol.ArtifactMetadata{}, err
			}
			if err := node.checkFault(FaultBeforeCommit); err != nil {
				return harnessprotocol.ArtifactMetadata{}, err
			}
			// Preserve fsync-published bytes across an unknown commit outcome.
			keep = true
			if err := tx.Commit(); err != nil {
				return harnessprotocol.ArtifactMetadata{}, err
			}
			node.afterCommit(context.Background(), postCommitAction{})
			// The successful transaction contains no artifact reference. Remove
			// its unreferenced bytes through the normal cleanup defer.
			keep = false
		}
		return harnessprotocol.ArtifactMetadata{}, ErrOutputLimit
	}
	metadata := harnessprotocol.ArtifactMetadata{ProtocolVersion: 1, SchemaID: harnessprotocol.SchemaID, NodeID: state.NodeID, DialogID: dialogID, AttemptID: input.Attempt.AttemptID, ArtifactID: artifactID, CallID: input.CallID, Name: input.Name, MediaType: input.MediaType, SizeBytes: written, SHA256: hex.EncodeToString(hash.Sum(nil)), Redaction: input.Redaction, Truncated: input.Truncated, Disposition: input.Disposition}
	if result := node.wireResult("artifactMetadata", metadata); result.HTTPStatus != 200 {
		return harnessprotocol.ArtifactMetadata{}, errors.New("artifact metadata violates wire contract")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO artifacts(artifact_id,dialog_id,attempt_id,call_id,name,media_type,size_bytes,sha256,redaction,truncated,disposition,relative_path) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, artifactID, dialogID, input.Attempt.AttemptID, nullText(input.CallID), input.Name, input.MediaType, written, metadata.SHA256, input.Redaction, input.Truncated, input.Disposition, relative); err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	if _, err := node.appendEvent(ctx, tx, &state, "artifact.available", artifactID, 1, input.Attempt.AttemptID, dialogID, harnessprotocol.ArtifactAvailablePayload{ArtifactID: artifactID, CallID: input.CallID, Name: input.Name, MediaType: input.MediaType, SizeBytes: written, SHA256: metadata.SHA256, Redaction: input.Redaction, Truncated: input.Truncated}, false); err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	if err := saveState(ctx, tx, state); err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	if err := node.checkFault(FaultBeforeCommit); err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	// From this point commit outcome may be unknown. Retain fsync-published
	// bytes so a committed SQLite reference can never point at a deleted file;
	// an unreferenced orphan is safe for later bounded cleanup.
	keep = true
	if err := tx.Commit(); err != nil {
		return harnessprotocol.ArtifactMetadata{}, err
	}
	if err := node.checkFault(FaultAfterCommit); err != nil {
		return metadata, err
	}
	return metadata, nil
}

func boundedArtifactText(value string) bool {
	return value != "" && utf8.ValidString(value) && utf8.RuneCountInString(value) <= 200 && len(value) <= 200
}

func (node *Node) ArtifactMetadata(ctx context.Context, trust TrustContext, artifactID string) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	state, err := loadState(ctx, node.db)
	if err != nil {
		return node.errorResult(503, "not_durable", "artifact is unavailable", artifactID, nil, "")
	}
	var m harnessprotocol.ArtifactMetadata
	var truncated bool
	var relative string
	err = node.db.QueryRowContext(ctx, `SELECT a.dialog_id,a.attempt_id,a.artifact_id,COALESCE(a.call_id,''),a.name,a.media_type,a.size_bytes,a.sha256,a.redaction,a.truncated,a.disposition,a.relative_path FROM artifacts a JOIN dialogs d ON d.dialog_id=a.dialog_id WHERE a.artifact_id=? AND a.disposition!='transcript_internal' AND d.node_id=? AND d.owner_id=? AND NOT EXISTS (
		SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`, artifactID, state.NodeID, state.OwnerID).Scan(&m.DialogID, &m.AttemptID, &m.ArtifactID, &m.CallID, &m.Name, &m.MediaType, &m.SizeBytes, &m.SHA256, &m.Redaction, &truncated, &m.Disposition, &relative)
	if err != nil {
		if isNoRows(err) {
			return node.errorResult(404, "not_found", "artifact was not found", artifactID, nil, "")
		}
		return node.errorResult(503, "not_durable", "artifact is unavailable", artifactID, nil, "")
	}
	m.ProtocolVersion = 1
	m.SchemaID = harnessprotocol.SchemaID
	m.NodeID = state.NodeID
	m.Truncated = truncated
	if _, err := node.readArtifactFile(relative, m); err != nil {
		return node.errorResult(503, "not_durable", "artifact bytes mismatch", artifactID, nil, "")
	}
	return node.wireResult("artifactMetadata", m)
}

func (node *Node) readArtifactFile(relative string, metadata harnessprotocol.ArtifactMetadata) ([]byte, error) {
	if filepath.Clean(relative) != filepath.Join("artifacts", metadata.ArtifactID) {
		return nil, errors.New("artifact path is invalid")
	}
	directoryPath := filepath.Join(node.config.DataDir, "artifacts")
	before, err := os.Lstat(directoryPath)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() || before.Mode().Perm()&0o077 != 0 || validateOwner(before) != nil {
		return nil, errors.New("artifact directory is unsafe")
	}
	directory, err := os.OpenRoot(directoryPath)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	after, err := directory.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("artifact directory changed")
	}
	file, err := directory.Open(metadata.ArtifactID)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm()&^os.FileMode(0o600) != 0 || validateOwner(fileInfo) != nil {
		return nil, errors.New("artifact file is unsafe")
	}
	body, err := io.ReadAll(io.LimitReader(file, harnessprotocol.MaximumArtifactBytes+1))
	if err != nil || int64(len(body)) != metadata.SizeBytes || len(body) > harnessprotocol.MaximumArtifactBytes {
		return nil, errors.New("artifact size mismatch")
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != metadata.SHA256 {
		return nil, errors.New("artifact hash mismatch")
	}
	return body, nil
}

func (node *Node) Artifact(ctx context.Context, trust TrustContext, artifactID string) (ArtifactBlob, Result, bool) {
	metadataResult := node.ArtifactMetadata(ctx, trust, artifactID)
	if metadataResult.HTTPStatus != 200 {
		return ArtifactBlob{}, metadataResult, false
	}
	var metadata harnessprotocol.ArtifactMetadata
	if err := json.Unmarshal(metadataResult.Body, &metadata); err != nil {
		return ArtifactBlob{}, node.errorResult(503, "not_durable", "artifact is unavailable", artifactID, nil, ""), false
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	var relative string
	if err := node.db.QueryRowContext(ctx, "SELECT relative_path FROM artifacts WHERE artifact_id=?", artifactID).Scan(&relative); err != nil {
		return ArtifactBlob{}, node.errorResult(503, "not_durable", "artifact is unavailable", artifactID, nil, ""), false
	}
	body, err := node.readArtifactFile(relative, metadata)
	if err != nil {
		return ArtifactBlob{}, node.errorResult(503, "not_durable", "artifact bytes mismatch", artifactID, nil, ""), false
	}
	return ArtifactBlob{Metadata: metadata, Bytes: body}, Result{}, true
}
