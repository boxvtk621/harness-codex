package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/strictjson"
)

const (
	legacySchemaVersion         = 1
	wireSchemaVersion           = 2
	barrierSchemaVersion        = 3
	quiescenceSchemaVersion     = 4
	historyReplicaSchemaVersion = 5
	legacySchemaFingerprintV1   = "2ef224cb3489121c3b8fb21f38bba849b2a7eb36383eb2fae1a5e255099b987d"
	legacySchemaFingerprintV2   = "5ae1b8abce397d2cb3e5221757c3069529b302d7842ab791dc430442bcc101df"
	legacySchemaFingerprintV3   = "37f9f276e85034b12ca892db8ea4be0793e5fc553df92d3ec38c8e8c3a6f5fc8"
	legacySchemaFingerprintV4   = "fd9cad2c3a251af79e18f74ebed996a6cd1bc2b9a89dfff0dc1f71f683cca407"
	legacySchemaFingerprintV5   = "7402ceae50bd385c73576fc6c1f55fd7648f4678b9a24e3cd7abff13f2a029fe"
	legacyWireSchemaID          = "harness-wire-v1"
	legacyWireBatchSize         = 128
)

var (
	legacySchemaToken  = []byte(`"schemaId":"harness-wire-v1"`)
	currentSchemaToken = []byte(`"schemaId":"harness-wire-v2"`)
)

func currentSchemaFingerprint() string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("harness-schema-v%d\x00%s", SchemaVersion, strings.Join(schemaStatements, "\x00"))))
	return hex.EncodeToString(digest[:])
}

func expectedSchemaFingerprint(version int) (string, bool) {
	switch version {
	case legacySchemaVersion:
		return legacySchemaFingerprintV1, true
	case wireSchemaVersion:
		return legacySchemaFingerprintV2, true
	case barrierSchemaVersion:
		return legacySchemaFingerprintV3, true
	case quiescenceSchemaVersion:
		return legacySchemaFingerprintV4, true
	case historyReplicaSchemaVersion:
		return legacySchemaFingerprintV5, true
	case SchemaVersion:
		return currentSchemaFingerprint(), true
	default:
		return "", false
	}
}

func (node *Node) verifySchemaFingerprint(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) error {
	var fingerprint string
	if err := query.QueryRowContext(ctx, "SELECT fingerprint FROM schema_meta WHERE singleton=1").Scan(&fingerprint); err != nil {
		return fmt.Errorf("schema fingerprint: %w", err)
	}
	if fingerprint != currentSchemaFingerprint() {
		return errors.New("database schema fingerprint does not match binary")
	}
	node.runtime.SchemaFingerprint = fingerprint
	return nil
}

func verifySchemaDDL(ctx context.Context, db *sql.DB, statements []string) error {
	expected := make(map[string]string, len(statements))
	for _, statement := range statements {
		fields := strings.Fields(statement)
		nameIndex := 2
		if len(fields) > 3 && fields[1] == "UNIQUE" {
			nameIndex = 3
		}
		if len(fields) <= nameIndex {
			return errors.New("invalid compiled schema statement")
		}
		name := strings.Trim(fields[nameIndex], "`\"")
		if opening := strings.IndexByte(name, '('); opening >= 0 {
			name = name[:opening]
		}
		expected[name] = strings.Join(fields, " ")
	}
	rows, err := db.QueryContext(ctx, `SELECT name,sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	actual := make(map[string]string)
	for rows.Next() {
		var name, ddl string
		if err := rows.Scan(&name, &ddl); err != nil {
			return err
		}
		actual[name] = strings.Join(strings.Fields(ddl), " ")
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(actual) != len(expected) {
		return errors.New("sqlite_schema object count does not match binary")
	}
	for name, ddl := range expected {
		if actual[name] != ddl {
			return fmt.Errorf("sqlite_schema object %s does not match binary", name)
		}
	}
	return nil
}

func (node *Node) migrate(ctx context.Context, newVolume bool) error {
	var version int
	if err := node.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > SchemaVersion {
		return fmt.Errorf("database schema %d is newer than binary schema %d", version, SchemaVersion)
	}
	if version == 0 && !newVolume {
		return errors.New("pre-existing unversioned database is not a Harness volume")
	}
	if version < 0 || (version != 0 && version != legacySchemaVersion && version != wireSchemaVersion && version != barrierSchemaVersion && version != quiescenceSchemaVersion && version != historyReplicaSchemaVersion && version != SchemaVersion) {
		return fmt.Errorf("unsupported database schema %d", version)
	}
	if version == SchemaVersion {
		node.runtime.SchemaVersion = version
		return node.verifySchemaFingerprint(ctx, node.db)
	}
	if node.config.StartupFault != nil {
		if err := node.config.StartupFault(StartupBeforeMigration); err != nil {
			return err
		}
	}
	tx, err := node.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if version != 0 {
		expected, ok := expectedSchemaFingerprint(version)
		var actual string
		if !ok || tx.QueryRowContext(ctx, "SELECT fingerprint FROM schema_meta WHERE singleton=1").Scan(&actual) != nil || actual != expected {
			return fmt.Errorf("legacy database schema fingerprint does not match v%d", version)
		}
		if version == legacySchemaVersion {
			if err := node.migrateLegacyWireV1(ctx, tx); err != nil {
				return err
			}
		}
		if version == legacySchemaVersion || version == wireSchemaVersion {
			for _, statement := range administrativeSchemaStatements {
				if _, err := tx.ExecContext(ctx, statement); err != nil {
					return fmt.Errorf("administrative barrier schema migration: %w", err)
				}
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO hold_clock(singleton,next_version) VALUES(1,1)"); err != nil {
				return err
			}
		}
		if version == legacySchemaVersion || version == wireSchemaVersion || version == barrierSchemaVersion {
			if version == barrierSchemaVersion {
				if _, err := tx.ExecContext(ctx, "DROP INDEX one_dialog_hold"); err != nil {
					return fmt.Errorf("drop legacy dialog hold index: %w", err)
				}
				if _, err := tx.ExecContext(ctx, "DROP INDEX one_node_hold"); err != nil {
					return fmt.Errorf("drop legacy node hold index: %w", err)
				}
			}
			for _, statement := range quiescenceSchemaStatements {
				if _, err := tx.ExecContext(ctx, statement); err != nil {
					return fmt.Errorf("quiescence proof schema migration: %w", err)
				}
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO quiescence_scope_revisions(scope_key,state_version,queue_revision)
			SELECT 'node',CASE WHEN state_version<1 THEN 1 ELSE state_version+1 END,
				CASE WHEN queue_version<1 THEN 1 ELSE queue_version+1 END FROM node_state`); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO quiescence_scope_revisions(scope_key,state_version,queue_revision)
			SELECT 'dialog:'||dialog_id,CASE WHEN version<1 THEN 1 ELSE version END,1 FROM dialogs`); err != nil {
				return err
			}
			if node.config.StartupFault != nil {
				if err := node.config.StartupFault(StartupDuringMigration); err != nil {
					return err
				}
			}
		}
		if version < historyReplicaSchemaVersion {
			for _, statement := range historyReplicaSchemaStatements {
				if _, err := tx.ExecContext(ctx, statement); err != nil {
					return fmt.Errorf("history replica schema migration: %w", err)
				}
			}
		}
		for _, statement := range logicalDeleteSchemaStatements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("logical delete schema migration: %w", err)
			}
		}
		if version >= quiescenceSchemaVersion && node.config.StartupFault != nil {
			if err := node.config.StartupFault(StartupDuringMigration); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, "UPDATE schema_meta SET fingerprint=? WHERE singleton=1", currentSchemaFingerprint()); err != nil {
			return err
		}
	} else {
		for _, statement := range schemaStatements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("schema migration: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_meta(singleton,fingerprint) VALUES(1,?)", currentSchemaFingerprint()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO hold_clock(singleton,next_version) VALUES(1,1)"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO node_state(
			singleton,node_id,owner_id,registry_version,epoch,state_version,last_event_seq,queue_version,queue_paused,
			transport_availability,engine_readiness,occupancy,active_attempt_id,pending_count,blocked_reasons,next_queue_sequence,next_message_sequence
			) VALUES(1,?,?,?,1,0,0,0,0,'online','blocked','idle',NULL,0,'["policy_unavailable"]',1,1)`, node.config.NodeID, node.config.OwnerID, node.config.RegistryVersion); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO quiescence_scope_revisions(scope_key,state_version,queue_revision) VALUES('node',1,1)"); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", SchemaVersion)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if node.config.StartupFault != nil {
		if err := node.config.StartupFault(StartupAfterMigration); err != nil {
			return err
		}
	}
	node.runtime.SchemaVersion = SchemaVersion
	node.runtime.SchemaFingerprint = currentSchemaFingerprint()
	return nil
}

type legacyCommandRow struct {
	commandID string
	nodeID    string
	kind      string
	eventSeq  int64
	canonical []byte
	hash      string
	receipt   []byte
}

type legacyEventRow struct {
	rowID     int64
	nodeID    string
	seq       int64
	epoch     int64
	attemptID sql.NullString
	dialogID  sql.NullString
	wire      []byte
}

func (node *Node) migrateLegacyWireV1(ctx context.Context, tx *sql.Tx) error {
	var fingerprint string
	if err := tx.QueryRowContext(ctx, "SELECT fingerprint FROM schema_meta WHERE singleton=1").Scan(&fingerprint); err != nil || fingerprint != legacySchemaFingerprintV1 {
		return errors.New("legacy database schema fingerprint does not match v1")
	}
	if err := node.migrateLegacyCommands(ctx, tx); err != nil {
		return err
	}
	if err := node.migrateLegacyEvents(ctx, tx); err != nil {
		return err
	}
	return nil
}

func (node *Node) migrateLegacyCommands(ctx context.Context, tx *sql.Tx) error {
	lastCommandID := ""
	for {
		rows, err := tx.QueryContext(ctx, `SELECT command_id,node_id,kind,event_seq,canonical_json,canonical_payload_hash,receipt_json
			FROM commands WHERE command_id>? ORDER BY command_id LIMIT ?`, lastCommandID, legacyWireBatchSize)
		if err != nil {
			return fmt.Errorf("read legacy commands: %w", err)
		}
		batch := make([]legacyCommandRow, 0, legacyWireBatchSize)
		for rows.Next() {
			var row legacyCommandRow
			if err := rows.Scan(&row.commandID, &row.nodeID, &row.kind, &row.eventSeq, &row.canonical, &row.hash, &row.receipt); err != nil {
				rows.Close()
				return fmt.Errorf("decode legacy command row: %w", err)
			}
			batch = append(batch, row)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("read legacy commands: %w", err)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		for _, row := range batch {
			canonical, digest, receipt, err := migrateLegacyCommandRow(row)
			if err != nil {
				return fmt.Errorf("migrate legacy command %s: %w", row.commandID, err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE commands SET canonical_json=?,canonical_payload_hash=?,receipt_json=? WHERE command_id=?`, canonical, digest, receipt, row.commandID); err != nil {
				return fmt.Errorf("write migrated command %s: %w", row.commandID, err)
			}
		}
		lastCommandID = batch[len(batch)-1].commandID
	}
}

func migrateLegacyCommandRow(row legacyCommandRow) ([]byte, string, []byte, error) {
	var command harnessprotocol.CommandEnvelope
	if err := json.Unmarshal(row.canonical, &command); err != nil || command.ProtocolVersion != harnessprotocol.ProtocolVersion || command.SchemaID != legacyWireSchemaID {
		return nil, "", nil, errors.New("canonical command does not carry exact v1 pins")
	}
	if command.Kind == harnessprotocol.CommandDialogDelete {
		return nil, "", nil, errors.New("v1 command contains a v2-only variant")
	}
	var target harnessprotocol.NodeTarget
	if err := json.Unmarshal(command.Target, &target); err != nil || command.CommandID != row.commandID || string(command.Kind) != row.kind || target.NodeID != row.nodeID {
		return nil, "", nil, errors.New("canonical command does not match durable row scope")
	}
	if !strictjson.Valid(row.canonical) {
		return nil, "", nil, errors.New("canonical command is not strict JSON")
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(row.canonical))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, "", nil, err
	}
	legacyCanonical, err := appendCanonical(nil, value)
	if err != nil || !bytes.Equal(legacyCanonical, row.canonical) {
		return nil, "", nil, errors.New("legacy command bytes are not canonical")
	}
	legacyDigest := sha256.Sum256(row.canonical)
	if row.hash != hex.EncodeToString(legacyDigest[:]) {
		return nil, "", nil, errors.New("legacy canonical payload hash mismatch")
	}
	canonical, err := rewriteLegacyWireBytes(row.canonical, "command")
	if err != nil {
		return nil, "", nil, err
	}
	digest := sha256.Sum256(canonical)

	var receipt harnessprotocol.Receipt
	if err := json.Unmarshal(row.receipt, &receipt); err != nil || receipt.ProtocolVersion != harnessprotocol.ProtocolVersion || receipt.SchemaID != legacyWireSchemaID {
		return nil, "", nil, errors.New("receipt does not carry exact v1 pins")
	}
	if receipt.CommandKind == harnessprotocol.CommandDialogDelete {
		return nil, "", nil, errors.New("v1 receipt contains a v2-only variant")
	}
	if receipt.CommandID != row.commandID || string(receipt.CommandKind) != row.kind || receipt.NodeID != row.nodeID || receipt.EventSeq != row.eventSeq {
		return nil, "", nil, errors.New("receipt does not match durable command scope")
	}
	migratedReceipt, err := rewriteLegacyWireBytes(row.receipt, "receipt")
	if err != nil {
		return nil, "", nil, err
	}
	return canonical, hex.EncodeToString(digest[:]), migratedReceipt, nil
}

func (node *Node) migrateLegacyEvents(ctx context.Context, tx *sql.Tx) error {
	lastRowID := int64(0)
	for {
		rows, err := tx.QueryContext(ctx, `SELECT rowid,node_id,seq,epoch,attempt_id,dialog_id,event_json
			FROM events WHERE rowid>? ORDER BY rowid LIMIT ?`, lastRowID, legacyWireBatchSize)
		if err != nil {
			return fmt.Errorf("read legacy events: %w", err)
		}
		batch := make([]legacyEventRow, 0, legacyWireBatchSize)
		for rows.Next() {
			var row legacyEventRow
			if err := rows.Scan(&row.rowID, &row.nodeID, &row.seq, &row.epoch, &row.attemptID, &row.dialogID, &row.wire); err != nil {
				rows.Close()
				return fmt.Errorf("decode legacy event row: %w", err)
			}
			batch = append(batch, row)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("read legacy events: %w", err)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		for _, row := range batch {
			var event harnessprotocol.EventEnvelope
			if err := json.Unmarshal(row.wire, &event); err != nil || event.ProtocolVersion != harnessprotocol.ProtocolVersion || event.SchemaID != legacyWireSchemaID {
				return fmt.Errorf("migrate legacy event %d: event does not carry exact v1 pins", row.seq)
			}
			if event.Type == "dialog.deleted" {
				return fmt.Errorf("migrate legacy event %d: v1 event contains a v2-only variant", row.seq)
			}
			if event.NodeID != row.nodeID || event.NodeID != node.config.NodeID || event.Seq != row.seq || event.Epoch != row.epoch || event.AttemptID != row.attemptID.String || event.DialogID != row.dialogID.String {
				return fmt.Errorf("migrate legacy event %d: event does not match durable row scope", row.seq)
			}
			migrated, err := rewriteLegacyWireBytes(row.wire, "event")
			if err != nil {
				return fmt.Errorf("migrate legacy event %d: %w", row.seq, err)
			}
			if _, err := tx.ExecContext(ctx, "UPDATE events SET event_json=? WHERE rowid=?", migrated, row.rowID); err != nil {
				return fmt.Errorf("write migrated event %d: %w", row.seq, err)
			}
		}
		lastRowID = batch[len(batch)-1].rowID
	}
}

func rewriteLegacyWireBytes(raw []byte, wireType string) ([]byte, error) {
	if !strictjson.Valid(raw) || bytes.Count(raw, legacySchemaToken) != 1 {
		return nil, errors.New("wire bytes are not exact strict v1 JSON")
	}
	migrated := bytes.Replace(raw, legacySchemaToken, currentSchemaToken, 1)
	if err := harnessprotocol.Validate(wireType, migrated); err != nil {
		return nil, fmt.Errorf("migrated %s does not validate: %w", wireType, err)
	}
	return migrated, nil
}

var legacySchemaStatements = []string{
	`CREATE TABLE schema_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), fingerprint TEXT NOT NULL) STRICT`,
	`CREATE TABLE node_state(
		singleton INTEGER PRIMARY KEY CHECK(singleton=1), node_id TEXT NOT NULL UNIQUE, owner_id TEXT NOT NULL,
		registry_version INTEGER NOT NULL, epoch INTEGER NOT NULL, state_version INTEGER NOT NULL, last_event_seq INTEGER NOT NULL,
		queue_version INTEGER NOT NULL, queue_paused INTEGER NOT NULL CHECK(queue_paused IN(0,1)),
		transport_availability TEXT NOT NULL, engine_readiness TEXT NOT NULL, occupancy TEXT NOT NULL,
		active_attempt_id TEXT, pending_count INTEGER NOT NULL, blocked_reasons TEXT NOT NULL,
		next_queue_sequence INTEGER NOT NULL, next_message_sequence INTEGER NOT NULL
	) STRICT`,
	`CREATE TABLE dialogs(
		dialog_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, owner_id TEXT NOT NULL, version INTEGER NOT NULL,
		title TEXT, created_at TEXT NOT NULL, engine_session_ref BLOB, policy_revision TEXT,
		UNIQUE(node_id,dialog_id)
	) STRICT`,
	`CREATE TABLE messages(
		message_id TEXT PRIMARY KEY, dialog_id TEXT NOT NULL REFERENCES dialogs(dialog_id), sequence INTEGER NOT NULL,
		version INTEGER NOT NULL, role TEXT NOT NULL CHECK(role IN('user','assistant')), text TEXT, content_json BLOB,
		disposition TEXT, command_id TEXT, request_id TEXT, attempt_id TEXT, finish_reason TEXT, created_at TEXT NOT NULL,
		UNIQUE(dialog_id,sequence)
	) STRICT`,
	`CREATE TABLE requests(
		request_id TEXT PRIMARY KEY, dialog_id TEXT NOT NULL REFERENCES dialogs(dialog_id), input_message_id TEXT NOT NULL REFERENCES messages(message_id),
		queue_sequence INTEGER NOT NULL UNIQUE, version INTEGER NOT NULL, status TEXT NOT NULL,
		created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	) STRICT`,
	`CREATE TABLE attempts(
		attempt_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, dialog_id TEXT NOT NULL REFERENCES dialogs(dialog_id),
		request_id TEXT NOT NULL REFERENCES requests(request_id), generation INTEGER NOT NULL, version INTEGER NOT NULL,
		state TEXT NOT NULL, effect_status TEXT NOT NULL, context_boundary_message_id TEXT, policy_hash TEXT,
		started_at TEXT, finished_at TEXT, engine_ref BLOB,
		output_bytes INTEGER NOT NULL DEFAULT 0 CHECK(output_bytes>=0), UNIQUE(request_id,generation)
	) STRICT`,
	`CREATE UNIQUE INDEX one_active_attempt ON attempts(node_id) WHERE state IN('dispatching','running','waiting_input','stopping','unknown')`,
	`CREATE TABLE commands(
		command_id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, node_id TEXT NOT NULL, kind TEXT NOT NULL,
		canonical_json BLOB NOT NULL, canonical_payload_hash TEXT NOT NULL, receipt_json BLOB NOT NULL,
		accepted_at TEXT NOT NULL, event_seq INTEGER NOT NULL
	) STRICT`,
	`CREATE TABLE control_actions(
		command_id TEXT PRIMARY KEY, kind TEXT NOT NULL, attempt_id TEXT NOT NULL, message_id TEXT, actor_id TEXT,
		payload BLOB NOT NULL, status TEXT NOT NULL CHECK(status IN('pending','inflight','acknowledged','rejected','unknown'))
	) STRICT`,
	`CREATE TABLE events(
		node_id TEXT NOT NULL, seq INTEGER NOT NULL, epoch INTEGER NOT NULL, event_json BLOB NOT NULL,
		attempt_id TEXT, dialog_id TEXT, projection_key TEXT, projection_hash TEXT,
		late INTEGER NOT NULL DEFAULT 0 CHECK(late IN(0,1)), created_at TEXT NOT NULL,
		PRIMARY KEY(node_id,seq)
	) STRICT`,
	`CREATE UNIQUE INDEX one_event_projection ON events(attempt_id,projection_key) WHERE projection_key IS NOT NULL`,
	`CREATE TABLE tool_calls(
		call_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id), action_hash TEXT NOT NULL,
		version INTEGER NOT NULL, status TEXT NOT NULL, safe_input_json BLOB NOT NULL, safe_result_json BLOB, effect_ref TEXT
	) STRICT`,
	`CREATE TABLE approvals(
		approval_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id), call_id TEXT NOT NULL,
		action_hash TEXT NOT NULL, version INTEGER NOT NULL, status TEXT NOT NULL, decision TEXT, actor_id TEXT
	) STRICT`,
	`CREATE TABLE input_requests(
		input_request_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id), version INTEGER NOT NULL,
		status TEXT NOT NULL, prompt_json BLOB NOT NULL, response_message_id TEXT
	) STRICT`,
	`CREATE TABLE artifacts(
		artifact_id TEXT PRIMARY KEY, dialog_id TEXT NOT NULL REFERENCES dialogs(dialog_id), attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
		call_id TEXT, name TEXT NOT NULL, media_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL,
		redaction TEXT NOT NULL, truncated INTEGER NOT NULL CHECK(truncated IN(0,1)), disposition TEXT NOT NULL, relative_path TEXT NOT NULL UNIQUE
	) STRICT`,
	`CREATE TABLE late_observations(
		observation_id INTEGER PRIMARY KEY, attempt_id TEXT NOT NULL, generation INTEGER NOT NULL, kind TEXT NOT NULL,
		observation_json BLOB NOT NULL, event_seq INTEGER NOT NULL, observed_at TEXT NOT NULL,
		projection_key TEXT, projection_hash TEXT, output_bytes INTEGER NOT NULL DEFAULT 0 CHECK(output_bytes>=0)
	) STRICT`,
	`CREATE UNIQUE INDEX one_late_projection ON late_observations(attempt_id,projection_key) WHERE projection_key IS NOT NULL`,
	`CREATE TABLE policy_snapshots(
		effective_hash TEXT PRIMARY KEY, revision TEXT NOT NULL, content BLOB NOT NULL, content_hash TEXT NOT NULL,
		tool_manifest BLOB NOT NULL, tool_manifest_hash TEXT NOT NULL, approval_mode TEXT NOT NULL
	) STRICT`,
}

var administrativeSchemaStatementsV3 = []string{
	`CREATE TABLE hold_clock(
		singleton INTEGER PRIMARY KEY CHECK(singleton=1), next_version INTEGER NOT NULL CHECK(next_version>0)
	) STRICT`,
	`CREATE TABLE hold_scope_revisions(
		scope_key TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK(revision>0)
	) STRICT`,
	`CREATE TABLE administrative_holds(
		operation_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, node_epoch INTEGER NOT NULL,
		binding_generation INTEGER NOT NULL, scope TEXT NOT NULL CHECK(scope IN('node','dialog')),
		dialog_id TEXT REFERENCES dialogs(dialog_id), hold_version INTEGER NOT NULL UNIQUE, scope_revision INTEGER NOT NULL,
		canonical_json BLOB NOT NULL, canonical_payload_hash TEXT NOT NULL, receipt_json BLOB NOT NULL, installed_at TEXT NOT NULL,
		CHECK((scope='node' AND dialog_id IS NULL) OR (scope='dialog' AND dialog_id IS NOT NULL))
	) STRICT`,
	`CREATE UNIQUE INDEX one_node_hold ON administrative_holds(node_id) WHERE scope='node'`,
	`CREATE UNIQUE INDEX one_dialog_hold ON administrative_holds(node_id,dialog_id) WHERE scope='dialog'`,
	`CREATE TABLE command_rejections(
		command_id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, node_id TEXT NOT NULL, kind TEXT NOT NULL,
		canonical_json BLOB NOT NULL, canonical_payload_hash TEXT NOT NULL, receipt_json BLOB NOT NULL,
		http_status INTEGER NOT NULL CHECK(http_status=409), rejected_at TEXT NOT NULL,
		hold_operation_id TEXT NOT NULL REFERENCES administrative_holds(operation_id)
	) STRICT`,
}

var administrativeSchemaStatements = func() []string {
	statements := make([]string, 0, len(administrativeSchemaStatementsV3)-2)
	for _, statement := range administrativeSchemaStatementsV3 {
		if strings.Contains(statement, "one_node_hold") || strings.Contains(statement, "one_dialog_hold") {
			continue
		}
		statements = append(statements, statement)
	}
	return statements
}()

var quiescenceSchemaStatements = []string{
	`CREATE TABLE quiescence_scope_revisions(
		scope_key TEXT PRIMARY KEY, state_version INTEGER NOT NULL CHECK(state_version BETWEEN 1 AND 9007199254740991),
		queue_revision INTEGER NOT NULL CHECK(queue_revision BETWEEN 1 AND 9007199254740991)
	) STRICT`,
	`CREATE TABLE administrative_hold_outcomes(
		operation_id TEXT PRIMARY KEY REFERENCES administrative_holds(operation_id), action TEXT NOT NULL CHECK(action IN('release','cancel')),
		canonical_json BLOB NOT NULL, canonical_payload_hash TEXT NOT NULL, receipt_json BLOB NOT NULL,
		scope_revision INTEGER NOT NULL CHECK(scope_revision BETWEEN 1 AND 9007199254740991), released_at TEXT NOT NULL
	) STRICT`,
	`CREATE TRIGGER quiescence_dialog_insert AFTER INSERT ON dialogs BEGIN
		INSERT INTO quiescence_scope_revisions(scope_key,state_version,queue_revision) VALUES('dialog:'||NEW.dialog_id,1,1);
		UPDATE quiescence_scope_revisions SET state_version=state_version+1 WHERE scope_key='node';
	END`,
	`CREATE TRIGGER quiescence_request_insert AFTER INSERT ON requests BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1,queue_revision=queue_revision+1
		WHERE scope_key IN('node','dialog:'||NEW.dialog_id);
	END`,
	`CREATE TRIGGER quiescence_request_update AFTER UPDATE OF status,queue_sequence,version ON requests
	WHEN OLD.status<>NEW.status OR OLD.queue_sequence<>NEW.queue_sequence OR OLD.version<>NEW.version BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1,queue_revision=queue_revision+1
		WHERE scope_key IN('node','dialog:'||NEW.dialog_id);
	END`,
	`CREATE TRIGGER quiescence_request_delete AFTER DELETE ON requests BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1,queue_revision=queue_revision+1
		WHERE scope_key IN('node','dialog:'||OLD.dialog_id);
	END`,
	`CREATE TRIGGER quiescence_attempt_insert AFTER INSERT ON attempts BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1 WHERE scope_key IN('node','dialog:'||NEW.dialog_id);
	END`,
	`CREATE TRIGGER quiescence_attempt_update AFTER UPDATE ON attempts BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1 WHERE scope_key IN('node','dialog:'||NEW.dialog_id);
	END`,
	`CREATE TRIGGER quiescence_attempt_delete AFTER DELETE ON attempts BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1 WHERE scope_key IN('node','dialog:'||OLD.dialog_id);
	END`,
	`CREATE TRIGGER quiescence_control_insert AFTER INSERT ON control_actions BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1
		WHERE scope_key IN('node','dialog:'||(SELECT dialog_id FROM attempts WHERE attempt_id=NEW.attempt_id));
	END`,
	`CREATE TRIGGER quiescence_control_update AFTER UPDATE ON control_actions BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1
		WHERE scope_key IN('node','dialog:'||(SELECT dialog_id FROM attempts WHERE attempt_id=NEW.attempt_id));
	END`,
	`CREATE TRIGGER quiescence_control_delete AFTER DELETE ON control_actions BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1
		WHERE scope_key IN('node','dialog:'||(SELECT dialog_id FROM attempts WHERE attempt_id=OLD.attempt_id));
	END`,
	`CREATE TRIGGER quiescence_tool_insert AFTER INSERT ON tool_calls BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1
		WHERE scope_key IN('node','dialog:'||(SELECT dialog_id FROM attempts WHERE attempt_id=NEW.attempt_id));
	END`,
	`CREATE TRIGGER quiescence_tool_update AFTER UPDATE ON tool_calls BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1
		WHERE scope_key IN('node','dialog:'||(SELECT dialog_id FROM attempts WHERE attempt_id=NEW.attempt_id));
	END`,
	`CREATE TRIGGER quiescence_tool_delete AFTER DELETE ON tool_calls BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1
		WHERE scope_key IN('node','dialog:'||(SELECT dialog_id FROM attempts WHERE attempt_id=OLD.attempt_id));
	END`,
	`CREATE TRIGGER quiescence_approval_insert AFTER INSERT ON approvals BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1
		WHERE scope_key IN('node','dialog:'||(SELECT dialog_id FROM attempts WHERE attempt_id=NEW.attempt_id));
	END`,
	`CREATE TRIGGER quiescence_approval_update AFTER UPDATE ON approvals BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1
		WHERE scope_key IN('node','dialog:'||(SELECT dialog_id FROM attempts WHERE attempt_id=NEW.attempt_id));
	END`,
	`CREATE TRIGGER quiescence_approval_delete AFTER DELETE ON approvals BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1
		WHERE scope_key IN('node','dialog:'||(SELECT dialog_id FROM attempts WHERE attempt_id=OLD.attempt_id));
	END`,
	`CREATE TRIGGER quiescence_input_insert AFTER INSERT ON input_requests BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1
		WHERE scope_key IN('node','dialog:'||(SELECT dialog_id FROM attempts WHERE attempt_id=NEW.attempt_id));
	END`,
	`CREATE TRIGGER quiescence_input_update AFTER UPDATE ON input_requests BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1
		WHERE scope_key IN('node','dialog:'||(SELECT dialog_id FROM attempts WHERE attempt_id=NEW.attempt_id));
	END`,
	`CREATE TRIGGER quiescence_input_delete AFTER DELETE ON input_requests BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1
		WHERE scope_key IN('node','dialog:'||(SELECT dialog_id FROM attempts WHERE attempt_id=OLD.attempt_id));
	END`,
	`CREATE TRIGGER quiescence_event_insert AFTER INSERT ON events BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1
		WHERE scope_key='node' OR (NEW.dialog_id IS NOT NULL AND scope_key='dialog:'||NEW.dialog_id);
	END`,
	`CREATE TRIGGER quiescence_hold_insert AFTER INSERT ON administrative_holds BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1
		WHERE scope_key='node' OR (NEW.dialog_id IS NOT NULL AND scope_key='dialog:'||NEW.dialog_id);
	END`,
	`CREATE TRIGGER quiescence_hold_outcome_insert AFTER INSERT ON administrative_hold_outcomes BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1
		WHERE scope_key='node' OR scope_key='dialog:'||(SELECT dialog_id FROM administrative_holds WHERE operation_id=NEW.operation_id);
	END`,
	`CREATE TRIGGER quiescence_node_identity_update AFTER UPDATE OF epoch,registry_version ON node_state
	WHEN OLD.epoch<>NEW.epoch OR OLD.registry_version<>NEW.registry_version BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1;
	END`,
	`CREATE TRIGGER quiescence_node_pause_update AFTER UPDATE OF queue_paused ON node_state WHEN OLD.queue_paused<>NEW.queue_paused BEGIN
		UPDATE quiescence_scope_revisions SET state_version=state_version+1,queue_revision=queue_revision+1;
	END`,
}

var barrierSchemaStatements = append(append([]string{}, legacySchemaStatements...), administrativeSchemaStatementsV3...)
var quiescenceV4SchemaStatements = append(append(append([]string{}, legacySchemaStatements...), administrativeSchemaStatements...), quiescenceSchemaStatements...)

var historyReplicaSchemaStatements = []string{
	`CREATE TABLE history_replica_streams(
		stream_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, logical_dialog_id TEXT NOT NULL,
		node_id TEXT NOT NULL, node_dialog_id TEXT NOT NULL, binding_generation INTEGER NOT NULL CHECK(binding_generation>0),
		next_seq INTEGER NOT NULL DEFAULT 1 CHECK(next_seq>0), dialog_version INTEGER NOT NULL CHECK(dialog_version>0),
		queue_revision INTEGER NOT NULL CHECK(queue_revision>0), complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN(0,1)),
		incomplete_reason TEXT, entries_hash TEXT NOT NULL, facts_hash TEXT NOT NULL, receipts_hash TEXT NOT NULL,
		text_hash TEXT NOT NULL, asset_manifest_hash TEXT NOT NULL, captured_at TEXT NOT NULL,
		UNIQUE(owner_id,logical_dialog_id,node_id,node_dialog_id,binding_generation),
		CHECK((complete=1 AND incomplete_reason IS NULL) OR (complete=0 AND incomplete_reason IS NOT NULL))
	) STRICT`,
	`CREATE TABLE history_replica_records(
		stream_id TEXT NOT NULL REFERENCES history_replica_streams(stream_id), stream_seq INTEGER NOT NULL CHECK(stream_seq>0),
		record_id TEXT NOT NULL, record_type TEXT NOT NULL CHECK(record_type IN('entry','execution_fact','receipt_revision','text_manifest','text_chunk','asset_manifest')),
		entity_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0), canonical_json BLOB NOT NULL,
		record_hash TEXT NOT NULL, prev_hash TEXT NOT NULL, chain_hash TEXT NOT NULL, created_at TEXT NOT NULL,
		PRIMARY KEY(stream_id,stream_seq), UNIQUE(stream_id,record_id)
	) STRICT`,
	`CREATE INDEX history_replica_records_type_idx ON history_replica_records(stream_id,record_type,stream_seq)`,
	`CREATE TRIGGER history_replica_records_no_update BEFORE UPDATE ON history_replica_records BEGIN SELECT RAISE(ABORT,'history replica records are immutable'); END`,
	`CREATE TRIGGER history_replica_records_no_delete BEFORE DELETE ON history_replica_records BEGIN SELECT RAISE(ABORT,'history replica records are immutable'); END`,
}

var historyReplicaV5SchemaStatements = append(append([]string{}, quiescenceV4SchemaStatements...), historyReplicaSchemaStatements...)

var logicalDeleteSchemaStatements = []string{
	`CREATE TABLE logical_delete_receipts (
		operation_id TEXT PRIMARY KEY, node_request_hash TEXT NOT NULL, coordinator_request_hash TEXT NOT NULL,
		command_id TEXT NOT NULL UNIQUE, logical_dialog_id TEXT NOT NULL, node_dialog_id TEXT NOT NULL,
		binding_version INTEGER NOT NULL CHECK(binding_version>0), hold_version INTEGER NOT NULL CHECK(hold_version>0),
		hold_scope_revision INTEGER NOT NULL CHECK(hold_scope_revision>0), receipt_json BLOB NOT NULL, deleted_at TEXT NOT NULL
	) STRICT`,
}

var schemaStatements = append(append([]string{}, historyReplicaV5SchemaStatements...), logicalDeleteSchemaStatements...)

func schemaStatementsForVersion(version int) []string {
	if version == legacySchemaVersion || version == wireSchemaVersion {
		return legacySchemaStatements
	}
	if version == barrierSchemaVersion {
		return barrierSchemaStatements
	}
	if version == quiescenceSchemaVersion {
		return quiescenceV4SchemaStatements
	}
	if version == historyReplicaSchemaVersion {
		return historyReplicaV5SchemaStatements
	}
	return schemaStatements
}
