package node

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/historyreplica"
	"github.com/boxvtk621/harness-codex/internal/transcriptview"
)

type replicaMessage struct {
	messageID, role, createdAt, text, requestID, attemptID string
	sequence, generation                                   int64
	content                                                []byte
	profileHash                                            string
}

type replicaEvent struct {
	sequence           int64
	attemptID, created string
	raw                []byte
	envelope           harnessprotocol.EventEnvelope
}

type replicaCommand struct {
	commandID, kind, fingerprint, acceptedAt string
	canonical, receipt                       []byte
}

type replicaStreamState struct {
	nextSeq                                                           int64
	entriesHash, factsHash, receiptsHash, textHash, assetManifestHash string
	effects                                                           historyreplica.EffectsSummary
	ready                                                             bool
	incompleteReason                                                  string
}

// ExportHistory materializes an immutable per-binding stream and returns one
// verified page. It never dispatches queued work and never changes the
// authoritative messages, attempts, events, commands, or artifact rows.
func (node *Node) ExportHistory(ctx context.Context, trust TrustContext, identity historyreplica.StreamIdentity, after int64, limit int) Result {
	if denied := node.authorizeRead(trust); denied != nil {
		return *denied
	}
	if !historyreplica.ValidIdentity(identity) || identity.OwnerID != node.config.OwnerID ||
		identity.NodeID != node.config.NodeID || identity.NodeDialogID == "" ||
		after < 0 || after > historyreplica.MaximumSafeInt || limit < 1 || limit > historyreplica.MaximumPageSize {
		return node.Invalid("history export query is invalid")
	}
	streamID := historyreplica.StreamID(identity)
	node.mu.Lock()
	defer node.mu.Unlock()
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "history export is unavailable", streamID, nil, "")
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil || state.NodeID != identity.NodeID || state.OwnerID != identity.OwnerID {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "history export identity is unavailable", streamID, nil, "")
	}
	stream, checkpoint, err := node.materializeHistoryReplica(ctx, tx, state, identity, streamID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return node.errorResult(http.StatusNotFound, "not_found", "dialog was not found", identity.NodeDialogID, nil, "")
		}
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "history export is unavailable", streamID, nil, "")
	}
	if after > checkpoint.ThroughSeq {
		return node.errorResult(http.StatusConflict, "stale", "history export cursor is ahead of the durable checkpoint", streamID, nil, "")
	}
	rows, err := tx.QueryContext(ctx, `SELECT canonical_json FROM history_replica_records
		WHERE stream_id=? AND stream_seq>? ORDER BY stream_seq LIMIT ?`, streamID, after, limit)
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "history export page is unavailable", streamID, nil, "")
	}
	records := make([]historyreplica.Record, 0, limit+1)
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			rows.Close()
			return node.errorResult(http.StatusServiceUnavailable, "not_durable", "history export page is unavailable", streamID, nil, "")
		}
		var record historyreplica.Record
		if json.Unmarshal(raw, &record) != nil {
			rows.Close()
			return node.errorResult(http.StatusServiceUnavailable, "not_durable", "history export record is invalid", streamID, nil, "")
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "history export page is unavailable", streamID, nil, "")
	}
	rows.Close()
	page := historyreplica.ExportPage{
		SchemaID: historyreplica.SchemaID, SchemaSHA256: historyreplica.SchemaSHA256, StreamID: streamID, Identity: identity,
		AfterSeq: after, Checkpoint: checkpoint,
	}
	page, body, err := encodeHistoryExportPage(page, records)
	if err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "history export proof is invalid", streamID, nil, "")
	}
	if err := tx.Commit(); err != nil {
		return node.errorResult(http.StatusServiceUnavailable, "not_durable", "history export commit failed", streamID, nil, "")
	}
	_ = stream
	return Result{HTTPStatus: http.StatusOK, Body: body, Committed: true}
}

func encodeHistoryExportPage(page historyreplica.ExportPage, records []historyreplica.Record) (historyreplica.ExportPage, []byte, error) {
	for {
		page.Records = records
		page.NextAfter = nil
		if len(records) > 0 && records[len(records)-1].StreamSeq < page.Checkpoint.ThroughSeq {
			next := records[len(records)-1].StreamSeq
			page.NextAfter = &next
		}
		body, err := json.Marshal(page)
		if err != nil {
			return historyreplica.ExportPage{}, nil, err
		}
		if len(body) <= historyreplica.MaximumPageBytes {
			if err := historyreplica.ValidatePage(page); err != nil {
				return historyreplica.ExportPage{}, nil, err
			}
			return page, body, nil
		}
		if len(records) == 0 {
			return historyreplica.ExportPage{}, nil, errors.New("one history record exceeds the page byte limit")
		}
		records = records[:len(records)-1]
	}
}

func (node *Node) materializeHistoryReplica(ctx context.Context, tx *sql.Tx, state durableState, identity historyreplica.StreamIdentity, streamID string) (replicaStreamState, historyreplica.Checkpoint, error) {
	var dialogVersion, queueRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT d.version FROM dialogs d WHERE d.dialog_id=? AND d.node_id=? AND d.owner_id=?
		AND NOT EXISTS(SELECT 1 FROM events deleted WHERE deleted.dialog_id=d.dialog_id AND deleted.projection_key='dialog.deleted')`,
		identity.NodeDialogID, identity.NodeID, identity.OwnerID).Scan(&dialogVersion); err != nil {
		return replicaStreamState{}, historyreplica.Checkpoint{}, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT queue_revision FROM quiescence_scope_revisions WHERE scope_key=?",
		"dialog:"+identity.NodeDialogID).Scan(&queueRevision); err != nil {
		return replicaStreamState{}, historyreplica.Checkpoint{}, err
	}
	now := timestamp(node.config.Clock())
	if _, err := tx.ExecContext(ctx, `INSERT INTO history_replica_streams(
		stream_id,owner_id,logical_dialog_id,node_id,node_dialog_id,binding_generation,next_seq,dialog_version,queue_revision,
		complete,incomplete_reason,entries_hash,facts_hash,receipts_hash,text_hash,asset_manifest_hash,captured_at)
		VALUES(?,?,?,?,?,?,1,?,?,0,'materializing',?,?,?,?,?,?)
		ON CONFLICT(stream_id) DO NOTHING`,
		streamID, identity.OwnerID, identity.LogicalDialogID, identity.NodeID, identity.NodeDialogID, identity.BindingGeneration,
		dialogVersion, queueRevision, historyreplica.GenesisHash, historyreplica.GenesisHash, historyreplica.GenesisHash,
		historyreplica.GenesisHash, historyreplica.GenesisHash, now); err != nil {
		return replicaStreamState{}, historyreplica.Checkpoint{}, err
	}
	var stored historyreplica.StreamIdentity
	if err := tx.QueryRowContext(ctx, `SELECT owner_id,logical_dialog_id,node_id,node_dialog_id,binding_generation
		FROM history_replica_streams WHERE stream_id=?`, streamID).Scan(
		&stored.OwnerID, &stored.LogicalDialogID, &stored.NodeID, &stored.NodeDialogID, &stored.BindingGeneration); err != nil || stored != identity {
		return replicaStreamState{}, historyreplica.Checkpoint{}, errors.New("history stream identity conflict")
	}
	if err := node.materializeReplicaEntries(ctx, tx, identity, streamID, now); err != nil {
		return replicaStreamState{}, historyreplica.Checkpoint{}, err
	}
	if err := node.materializeReplicaFacts(ctx, tx, identity, streamID, now); err != nil {
		return replicaStreamState{}, historyreplica.Checkpoint{}, err
	}
	if err := node.materializeReplicaReceipts(ctx, tx, identity, streamID, now); err != nil {
		return replicaStreamState{}, historyreplica.Checkpoint{}, err
	}
	textComplete, err := node.materializeReplicaText(ctx, tx, identity, streamID, now)
	if err != nil {
		return replicaStreamState{}, historyreplica.Checkpoint{}, err
	}
	if err := node.materializeReplicaAssets(ctx, tx, identity, streamID, now); err != nil {
		return replicaStreamState{}, historyreplica.Checkpoint{}, err
	}
	stream, err := replicaHashes(ctx, tx, streamID)
	if err != nil {
		return replicaStreamState{}, historyreplica.Checkpoint{}, err
	}
	stream.ready = textComplete
	if !stream.ready {
		stream.incompleteReason = "safe_text_incomplete"
	}
	through := stream.nextSeq - 1
	chainHash := historyreplica.ChainGenesis(streamID)
	if through > 0 {
		if err := tx.QueryRowContext(ctx, "SELECT chain_hash FROM history_replica_records WHERE stream_id=? AND stream_seq=?",
			streamID, through).Scan(&chainHash); err != nil {
			return replicaStreamState{}, historyreplica.Checkpoint{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE history_replica_streams SET dialog_version=?,queue_revision=?,complete=?,
		incomplete_reason=?,entries_hash=?,facts_hash=?,receipts_hash=?,text_hash=?,asset_manifest_hash=?,captured_at=?
		WHERE stream_id=?`, dialogVersion, queueRevision, stream.ready, nullText(stream.incompleteReason), stream.entriesHash,
		stream.factsHash, stream.receiptsHash, stream.textHash, stream.assetManifestHash, now, streamID); err != nil {
		return replicaStreamState{}, historyreplica.Checkpoint{}, err
	}
	checkpoint := historyreplica.Checkpoint{
		ThroughSeq: through, ChainHash: chainHash, DialogVersion: dialogVersion, QueueRevision: queueRevision,
		EntriesHash: stream.entriesHash, FactsHash: stream.factsHash, ReceiptsHash: stream.receiptsHash,
		TextHash: stream.textHash, AssetManifestHash: stream.assetManifestHash, EffectsSummary: stream.effects, Ready: stream.ready,
		IncompleteReason: stream.incompleteReason, CapturedAt: now,
	}
	return stream, checkpoint, nil
}

func (node *Node) materializeReplicaEntries(ctx context.Context, tx *sql.Tx, identity historyreplica.StreamIdentity, streamID, now string) error {
	rows, err := tx.QueryContext(ctx, `SELECT m.message_id,m.role,m.sequence,m.created_at,COALESCE(m.text,''),m.content_json,
		COALESCE(m.request_id,''),COALESCE(m.attempt_id,''),COALESCE(a.generation,0),COALESCE(a.policy_hash,'')
		FROM messages m LEFT JOIN attempts a ON a.attempt_id=m.attempt_id
		WHERE m.dialog_id=? ORDER BY m.sequence`, identity.NodeDialogID)
	if err != nil {
		return err
	}
	messages := make([]replicaMessage, 0)
	for rows.Next() {
		var message replicaMessage
		if err := rows.Scan(&message.messageID, &message.role, &message.sequence, &message.createdAt, &message.text,
			&message.content, &message.requestID, &message.attemptID, &message.generation, &message.profileHash); err != nil {
			rows.Close()
			return err
		}
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, message := range messages {
		content := json.RawMessage(message.content)
		if message.role == "user" {
			encoded, err := json.Marshal(struct {
				Kind    string `json:"kind"`
				Content string `json:"content"`
			}{Kind: "inline", Content: message.text})
			if err != nil {
				return err
			}
			content = encoded
		}
		if len(content) == 0 || !json.Valid(content) {
			return errors.New("history entry content is invalid")
		}
		authorEvent := "message:" + message.messageID
		var eventSeq int64
		if err := tx.QueryRowContext(ctx, "SELECT seq FROM events WHERE node_id=? AND json_extract(CAST(event_json AS TEXT),'$.entityId')=? ORDER BY seq LIMIT 1",
			identity.NodeID, message.messageID).Scan(&eventSeq); err == nil {
			authorEvent = identity.NodeID + ":" + strconv.FormatInt(eventSeq, 10)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		entry := historyreplica.TranscriptEntry{
			EntryID: message.messageID, Origin: historyreplica.Origin{NodeID: identity.NodeID, NodeDialogID: identity.NodeDialogID, AuthorEventID: authorEvent},
			LogicalDialogID: identity.LogicalDialogID, MessageID: message.messageID, RequestID: message.requestID,
			Kind: "message", Role: message.role, Content: content, CreatedAt: message.createdAt,
			SourceGeneration: message.generation, ExecutionOrdinal: message.sequence, ExecutionStatus: "recorded",
		}
		if message.role == "assistant" {
			entry.AttemptID, entry.ProfileHash = message.attemptID, message.profileHash
		} else {
			// A queued user message can acquire an attempt after its immutable
			// entry has already been exported. Execution facts carry that later
			// lifecycle; the accepted entry itself always remains generation zero.
			entry.SourceGeneration = 0
		}
		record, err := historyreplica.NewRecord(historyreplica.RecordEntry,
			historyreplica.StableUUID("history-record-entry-v1", message.messageID), message.messageID, 1, entry)
		if err != nil {
			return err
		}
		if _, err := appendReplicaRecord(ctx, tx, streamID, record, now); err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) materializeReplicaFacts(ctx context.Context, tx *sql.Tx, identity historyreplica.StreamIdentity, streamID, now string) error {
	rows, err := tx.QueryContext(ctx, `SELECT e.seq,COALESCE(e.attempt_id,''),e.created_at,e.event_json
			FROM events e WHERE e.node_id=? AND (
				e.dialog_id=? OR e.attempt_id IN(SELECT attempt_id FROM attempts WHERE dialog_id=?) OR
				json_extract(CAST(e.event_json AS TEXT),'$.payload.dialogId')=? OR
				json_extract(CAST(e.event_json AS TEXT),'$.entityId') IN(SELECT message_id FROM messages WHERE dialog_id=?) OR
				json_extract(CAST(e.event_json AS TEXT),'$.entityId') IN(SELECT request_id FROM requests WHERE dialog_id=?)
			) ORDER BY e.seq`, identity.NodeID, identity.NodeDialogID, identity.NodeDialogID, identity.NodeDialogID,
		identity.NodeDialogID, identity.NodeDialogID)
	if err != nil {
		return err
	}
	events := make([]replicaEvent, 0)
	for rows.Next() {
		var event replicaEvent
		if err := rows.Scan(&event.sequence, &event.attemptID, &event.created, &event.raw); err != nil ||
			json.Unmarshal(event.raw, &event.envelope) != nil {
			rows.Close()
			return errors.New("history event is invalid")
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, event := range events {
		requestID := ""
		var payload map[string]json.RawMessage
		if json.Unmarshal(event.envelope.Payload, &payload) == nil {
			_ = json.Unmarshal(payload["requestId"], &requestID)
		}
		if requestID == "" && event.attemptID != "" {
			_ = tx.QueryRowContext(ctx, "SELECT request_id FROM attempts WHERE attempt_id=?", event.attemptID).Scan(&requestID)
		}
		factID := historyreplica.StableUUID("history-execution-fact-v1", identity.NodeID+"\x00"+strconv.FormatInt(event.sequence, 10))
		fact := historyreplica.ExecutionFact{
			FactID: factID, Origin: historyreplica.Origin{NodeID: identity.NodeID, NodeDialogID: identity.NodeDialogID,
				AuthorEventID: identity.NodeID + ":" + strconv.FormatInt(event.sequence, 10)},
			LogicalDialogID: identity.LogicalDialogID, RequestID: requestID, AttemptID: event.attemptID,
			Kind: event.envelope.Type, Status: event.envelope.Type, EventSeq: event.sequence, OccurredAt: event.created,
			Event: append(json.RawMessage(nil), event.raw...),
		}
		record, err := historyreplica.NewRecord(historyreplica.RecordExecutionFact,
			historyreplica.StableUUID("history-record-fact-v1", factID), factID, 1, fact)
		if err != nil {
			return err
		}
		if _, err := appendReplicaRecord(ctx, tx, streamID, record, now); err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) materializeReplicaReceipts(ctx context.Context, tx *sql.Tx, identity historyreplica.StreamIdentity, streamID, now string) error {
	rows, err := tx.QueryContext(ctx, `SELECT command_id,kind,canonical_payload_hash,canonical_json,receipt_json,accepted_at
		FROM commands WHERE node_id=? ORDER BY accepted_at,command_id`, identity.NodeID)
	if err != nil {
		return err
	}
	commands := make([]replicaCommand, 0)
	for rows.Next() {
		var command replicaCommand
		if err := rows.Scan(&command.commandID, &command.kind, &command.fingerprint, &command.canonical, &command.receipt, &command.acceptedAt); err != nil {
			rows.Close()
			return err
		}
		commands = append(commands, command)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, command := range commands {
		belongs, requestID, attemptID, receipt, err := replicaCommandScope(ctx, tx, identity.NodeDialogID, command)
		if err != nil {
			return err
		}
		if !belongs {
			continue
		}
		revisionID := historyreplica.StableUUID("history-receipt-revision-v1", identity.NodeID+"\x00"+command.commandID+"\x001")
		revision := historyreplica.ReceiptRevision{
			ReceiptRevisionID: revisionID,
			Origin: historyreplica.Origin{NodeID: identity.NodeID, NodeDialogID: identity.NodeDialogID,
				AuthorEventID: identity.NodeID + ":" + strconv.FormatInt(receipt.EventSeq, 10)},
			LogicalDialogID: identity.LogicalDialogID, CommandID: command.commandID, CommandKind: command.kind,
			Fingerprint: command.fingerprint, RequestID: requestID, AttemptID: attemptID, Revision: 1,
			PredecessorHash: historyreplica.GenesisHash, Admission: "accepted", Outcome: receipt.Result,
			Receipt: append(json.RawMessage(nil), command.receipt...), AcceptedAt: command.acceptedAt,
		}
		record, err := historyreplica.NewRecord(historyreplica.RecordReceipt, revisionID, revisionID, 1, revision)
		if err != nil {
			return err
		}
		if _, err := appendReplicaRecord(ctx, tx, streamID, record, now); err != nil {
			return err
		}
	}
	return nil
}

func replicaCommandScope(ctx context.Context, tx *sql.Tx, dialogID string, command replicaCommand) (bool, string, string, harnessprotocol.Receipt, error) {
	var envelope harnessprotocol.CommandEnvelope
	var receipt harnessprotocol.Receipt
	if json.Unmarshal(command.canonical, &envelope) != nil || json.Unmarshal(command.receipt, &receipt) != nil {
		return false, "", "", receipt, errors.New("history command is invalid")
	}
	values := map[string]string{}
	var target map[string]json.RawMessage
	var references map[string]json.RawMessage
	_ = json.Unmarshal(envelope.Target, &target)
	_ = json.Unmarshal(receipt.References, &references)
	for key, raw := range target {
		var value string
		if json.Unmarshal(raw, &value) == nil {
			values[key] = value
		}
	}
	for key, raw := range references {
		var value string
		if json.Unmarshal(raw, &value) == nil {
			values[key] = value
		}
	}
	requestID, attemptID := values["requestId"], values["attemptId"]
	if values["dialogId"] == dialogID {
		return true, requestID, attemptID, receipt, nil
	}
	if requestID != "" {
		var found string
		err := tx.QueryRowContext(ctx, "SELECT dialog_id FROM requests WHERE request_id=?", requestID).Scan(&found)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, "", "", receipt, err
		}
		if found == dialogID {
			return true, requestID, attemptID, receipt, nil
		}
	}
	for _, key := range []string{"attemptId", "priorAttemptId"} {
		if values[key] == "" {
			continue
		}
		var found, linkedRequest string
		err := tx.QueryRowContext(ctx, "SELECT dialog_id,request_id FROM attempts WHERE attempt_id=?", values[key]).Scan(&found, &linkedRequest)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, "", "", receipt, err
		}
		if found == dialogID {
			if attemptID == "" {
				attemptID = values[key]
			}
			if requestID == "" {
				requestID = linkedRequest
			}
			return true, requestID, attemptID, receipt, nil
		}
	}
	return false, requestID, attemptID, receipt, nil
}

func (node *Node) materializeReplicaText(ctx context.Context, tx *sql.Tx, identity historyreplica.StreamIdentity, streamID, now string) (bool, error) {
	rows, err := tx.QueryContext(ctx, "SELECT "+safeTextArtifactColumns+` FROM artifacts
		WHERE dialog_id=? AND media_type=? ORDER BY artifact_id`, identity.NodeDialogID, safeTextManifestMediaType)
	if err != nil {
		return false, err
	}
	manifestRows := make([]safeTextArtifactRow, 0)
	for rows.Next() {
		var row safeTextArtifactRow
		if scanSafeTextArtifact(rows, &row) != nil {
			rows.Close()
			return false, errors.New("history text manifest row is invalid")
		}
		manifestRows = append(manifestRows, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	rows.Close()
	complete := true
	for _, row := range manifestRows {
		raw, err := node.readSafeTextArtifact(row)
		if err != nil {
			return false, err
		}
		observed, err := transcriptview.Decode(raw)
		if err != nil {
			return false, err
		}
		var requestID string
		var generation int64
		if err := tx.QueryRowContext(ctx, "SELECT request_id,generation FROM attempts WHERE attempt_id=?", row.attemptID).Scan(&requestID, &generation); err != nil {
			return false, err
		}
		reference := harnessadapter.AttemptRef{NodeID: identity.NodeID, DialogID: identity.NodeDialogID, RequestID: requestID, AttemptID: row.attemptID, Generation: generation}
		manifest, _, err := node.readSafeTextManifest(ctx, tx, reference, observed.Source)
		if err != nil {
			return false, err
		}
		source, _ := json.Marshal(manifest.Source)
		payload := historyreplica.TextManifest{
			TextID: manifest.TextID, Origin: historyreplica.Origin{NodeID: identity.NodeID, NodeDialogID: identity.NodeDialogID,
				AuthorEventID: "text:" + manifest.TextID},
			LogicalDialogID: identity.LogicalDialogID, AttemptID: manifest.AttemptID, Source: source,
			Preview: manifest.Preview, Redaction: manifest.Redaction, Complete: manifest.Complete, Reason: manifest.Reason,
			SizeBytes: manifest.SizeBytes, SHA256: manifest.SHA256,
		}
		if manifest.Complete {
			payload.ChunkCount = (manifest.SizeBytes + historyreplica.MaximumChunkBytes - 1) / historyreplica.MaximumChunkBytes
		}
		record, err := historyreplica.NewRecord(historyreplica.RecordTextManifest,
			historyreplica.StableUUID("history-record-text-manifest-v1", manifest.TextID), manifest.TextID, 1, payload)
		if err != nil {
			return false, err
		}
		if _, err := appendReplicaRecord(ctx, tx, streamID, record, now); err != nil {
			return false, err
		}
		if !manifest.Complete {
			complete = false
			continue
		}
		hasher := sha256.New()
		var total, outputIndex int64
		for _, sourceChunk := range manifest.Chunks {
			var chunkRow safeTextArtifactRow
			if err := scanSafeTextArtifact(tx.QueryRowContext(ctx, "SELECT "+safeTextArtifactColumns+" FROM artifacts WHERE artifact_id=?", sourceChunk.ArtifactID), &chunkRow); err != nil {
				return false, err
			}
			content, err := node.readSafeTextArtifact(chunkRow)
			if err != nil {
				return false, err
			}
			_, _ = hasher.Write(content)
			for start := 0; start < len(content); start += historyreplica.MaximumChunkBytes {
				end := start + historyreplica.MaximumChunkBytes
				if end > len(content) {
					end = len(content)
				}
				part := append([]byte(nil), content[start:end]...)
				partHash := historyreplica.HashBytes(part)
				chunk := historyreplica.TextChunk{
					TextID: manifest.TextID, LogicalDialogID: identity.LogicalDialogID, ChunkIndex: outputIndex,
					OffsetBytes: total + int64(start), SizeBytes: int64(len(part)), SHA256: partHash, Bytes: part,
				}
				chunkEntity := historyreplica.StableUUID("history-text-chunk-v1", manifest.TextID+"\x00"+strconv.FormatInt(chunk.OffsetBytes, 10))
				chunkRecord, err := historyreplica.NewRecord(historyreplica.RecordTextChunk,
					historyreplica.StableUUID("history-record-text-chunk-v1", chunkEntity+"\x00"+partHash), chunkEntity, 1, chunk)
				if err != nil {
					return false, err
				}
				if _, err := appendReplicaRecord(ctx, tx, streamID, chunkRecord, now); err != nil {
					return false, err
				}
				outputIndex++
			}
			total += int64(len(content))
		}
		if total != manifest.SizeBytes || hex.EncodeToString(hasher.Sum(nil)) != manifest.SHA256 || outputIndex != payload.ChunkCount {
			return false, errors.New("history text bytes do not match manifest")
		}
	}
	return complete, nil
}

func (node *Node) materializeReplicaAssets(ctx context.Context, tx *sql.Tx, identity historyreplica.StreamIdentity, streamID, now string) error {
	rows, err := tx.QueryContext(ctx, `SELECT artifact_id,attempt_id,COALESCE(call_id,''),name,media_type,size_bytes,sha256,redaction,truncated
		FROM artifacts WHERE dialog_id=? AND disposition<>? ORDER BY artifact_id`, identity.NodeDialogID, safeTextDisposition)
	if err != nil {
		return err
	}
	assets := make([]historyreplica.Asset, 0)
	for rows.Next() {
		var asset historyreplica.Asset
		if err := rows.Scan(&asset.ArtifactID, &asset.AttemptID, &asset.CallID, &asset.Name, &asset.MediaType,
			&asset.SizeBytes, &asset.SHA256, &asset.Redaction, &asset.Truncated); err != nil {
			rows.Close()
			return err
		}
		assets = append(assets, asset)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	sort.Slice(assets, func(i, j int) bool { return assets[i].ArtifactID < assets[j].ArtifactID })
	manifest := historyreplica.AssetManifest{LogicalDialogID: identity.LogicalDialogID, Assets: assets}
	payloadHash, _, err := historyreplica.HashJSON(manifest)
	if err != nil {
		return err
	}
	entityID := historyreplica.StableUUID("history-asset-manifest-entity-v1", identity.NodeDialogID)
	recordID := historyreplica.StableUUID("history-record-asset-manifest-v1", entityID+"\x00"+payloadHash)
	revision := int64(0)
	err = tx.QueryRowContext(ctx, `SELECT revision FROM history_replica_records WHERE record_id=? ORDER BY revision LIMIT 1`, recordID).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision),0)+1 FROM history_replica_records
			WHERE record_type=? AND entity_id=?`, historyreplica.RecordAssetManifest, entityID).Scan(&revision); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	record, err := historyreplica.NewRecord(historyreplica.RecordAssetManifest, recordID, entityID, revision, manifest)
	if err != nil {
		return err
	}
	record, err = appendReplicaRecord(ctx, tx, streamID, record, now)
	if err != nil {
		return err
	}
	return nil
}

func appendReplicaRecord(ctx context.Context, tx *sql.Tx, streamID string, candidate historyreplica.Record, now string) (historyreplica.Record, error) {
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT canonical_json FROM history_replica_records WHERE stream_id=? AND record_id=?`,
		streamID, candidate.RecordID).Scan(&raw); err == nil {
		var existing historyreplica.Record
		if json.Unmarshal(raw, &existing) != nil || existing.RecordHash != candidate.RecordHash {
			return historyreplica.Record{}, errors.New("history record identity conflict")
		}
		return existing, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return historyreplica.Record{}, err
	}
	var next int64
	if err := tx.QueryRowContext(ctx, "SELECT next_seq FROM history_replica_streams WHERE stream_id=?", streamID).Scan(&next); err != nil {
		return historyreplica.Record{}, err
	}
	previous := historyreplica.ChainGenesis(streamID)
	if next > 1 {
		if err := tx.QueryRowContext(ctx, "SELECT chain_hash FROM history_replica_records WHERE stream_id=? AND stream_seq=?",
			streamID, next-1).Scan(&previous); err != nil {
			return historyreplica.Record{}, err
		}
	}
	sealed, err := historyreplica.SealRecord(candidate, streamID, next, previous)
	if err != nil {
		return historyreplica.Record{}, err
	}
	encoded, err := json.Marshal(sealed)
	if err != nil {
		return historyreplica.Record{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO history_replica_records(
		stream_id,stream_seq,record_id,record_type,entity_id,revision,canonical_json,record_hash,prev_hash,chain_hash,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`, streamID, sealed.StreamSeq, sealed.RecordID, sealed.Type, sealed.EntityID,
		sealed.Revision, encoded, sealed.RecordHash, sealed.PrevHash, sealed.ChainHash, now); err != nil {
		return historyreplica.Record{}, err
	}
	if result, err := tx.ExecContext(ctx, "UPDATE history_replica_streams SET next_seq=next_seq+1 WHERE stream_id=? AND next_seq=?",
		streamID, next); err != nil {
		return historyreplica.Record{}, err
	} else if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return historyreplica.Record{}, errors.New("history stream sequence changed")
	}
	return sealed, nil
}

func replicaHashes(ctx context.Context, tx *sql.Tx, streamID string) (replicaStreamState, error) {
	rows, err := tx.QueryContext(ctx, `SELECT record_type,record_hash FROM history_replica_records
		WHERE stream_id=? ORDER BY stream_seq`, streamID)
	if err != nil {
		return replicaStreamState{}, err
	}
	defer rows.Close()
	state := replicaStreamState{
		entriesHash: historyreplica.GenesisHash, factsHash: historyreplica.GenesisHash,
		receiptsHash: historyreplica.GenesisHash, textHash: historyreplica.GenesisHash,
		assetManifestHash: historyreplica.GenesisHash, nextSeq: 1,
	}
	for rows.Next() {
		var recordType, hash string
		if rows.Scan(&recordType, &hash) != nil {
			return replicaStreamState{}, errors.New("history hash row is invalid")
		}
		switch recordType {
		case historyreplica.RecordEntry:
			state.entriesHash = historyreplica.FoldCoverageHash(state.entriesHash, hash)
			state.effects.EntryCount++
		case historyreplica.RecordExecutionFact:
			state.factsHash = historyreplica.FoldCoverageHash(state.factsHash, hash)
			state.effects.FactCount++
		case historyreplica.RecordReceipt:
			state.receiptsHash = historyreplica.FoldCoverageHash(state.receiptsHash, hash)
			state.effects.ReceiptRevisionCount++
		case historyreplica.RecordTextManifest:
			state.textHash = historyreplica.FoldCoverageHash(state.textHash, hash)
			state.effects.TextManifestCount++
		case historyreplica.RecordTextChunk:
			state.textHash = historyreplica.FoldCoverageHash(state.textHash, hash)
			state.effects.TextChunkCount++
		case historyreplica.RecordAssetManifest:
			state.assetManifestHash = historyreplica.FoldCoverageHash(state.assetManifestHash, hash)
			state.effects.AssetManifestCount++
		}
		state.nextSeq++
	}
	return state, rows.Err()
}
