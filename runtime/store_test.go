package node_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
	_ "modernc.org/sqlite"
)

const (
	testNodeID  = "00000000-0000-4000-8000-000000000001"
	testOwnerID = "1-1"
)

func testConfig(path string) node.Config {
	return node.Config{
		DataDir: path, NodeID: testNodeID, OwnerID: testOwnerID,
		RegistryVersion: 1, Adapter: fixture.NewAdapter(), ManualDispatchForTesting: true,
	}
}

func TestOpenPinsSQLiteAndDurableIdentity(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	opened, err := node.Open(ctx, testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	runtime := opened.Runtime()
	if runtime.SQLiteVersion != "3.53.3" || runtime.SQLiteSourceID == "" {
		t.Fatalf("unexpected SQLite identity: %+v", runtime)
	}
	if runtime.JournalMode != "delete" || runtime.Synchronous != 3 || !runtime.ForeignKeys || runtime.SchemaVersion != node.SchemaVersion {
		t.Fatalf("unsafe runtime: %+v", runtime)
	}
	reserve, err := os.Stat(filepath.Join(path, ".control.reserve"))
	if err != nil {
		t.Fatal(err)
	}
	if reserve.Size() != node.ControlReserveBytes {
		t.Fatalf("control reserve size=%d", reserve.Size())
	}
	if _, err := node.Open(ctx, testConfig(path)); err == nil || !strings.Contains(err.Error(), "already owned") {
		t.Fatalf("second writer was not rejected: %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := node.Open(ctx, testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRecoversOnlyExistingPristinePolicySentinel(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	config := testConfig(path)
	config.Policies = fixture.NewPolicySource()
	opened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	fresh := currentSnapshot(t, ctx, opened)
	if fresh.StateVersion != 0 || fresh.LastEventSeq != 0 || fresh.Node.EngineReadiness != "blocked" ||
		len(fresh.Node.BlockedReasons) != 1 || fresh.Node.BlockedReasons[0] != "policy_unavailable" {
		t.Fatalf("fresh volume lost legacy initialization contract: %+v", fresh)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered := currentSnapshot(t, ctx, reopened)
	if recovered.StateVersion != 1 || recovered.LastEventSeq != 1 || recovered.Node.EngineReadiness != "ready" ||
		len(recovered.Node.BlockedReasons) != 0 || recovered.Node.QueueVersion != 0 || recovered.Node.PendingCount != 0 ||
		recovered.Node.ActiveAttemptID != nil || recovered.ActiveAttempt != nil || len(recovered.PendingQueue) != 0 {
		t.Fatalf("pristine policy sentinel was not recovered exactly: %+v", recovered)
	}
	replay, failure, ok := reopened.ReplayEvents(ctx, nodeTrust(), 0, 10)
	if !ok || failure.HTTPStatus != 0 || len(replay.Events) != 1 {
		t.Fatalf("recovery event missing: ok=%v failure=%+v replay=%+v", ok, failure, replay)
	}
	var event harnessprotocol.EventEnvelope
	if err := json.Unmarshal(replay.Events[0], &event); err != nil || event.Type != "node.state_changed" ||
		event.EntityID != testNodeID || event.EntityVersion != 1 || event.Seq != 1 {
		t.Fatalf("unexpected recovery event: %+v err=%v", event, err)
	}
}

func TestOpenLeavesPristinePolicySentinelBlockedWhenValidationFails(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	opened, err := node.Open(ctx, testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	config := testConfig(path)
	config.Policies = &fixture.PolicySource{Err: errors.New("policy unavailable")}
	reopened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	snapshot := currentSnapshot(t, ctx, reopened)
	if snapshot.StateVersion != 0 || snapshot.LastEventSeq != 0 || snapshot.Node.EngineReadiness != "blocked" ||
		len(snapshot.Node.BlockedReasons) != 1 || snapshot.Node.BlockedReasons[0] != "policy_unavailable" {
		t.Fatalf("invalid policy changed pristine sentinel: %+v", snapshot)
	}
}

func TestOpenDoesNotRecoverUsedPolicyBlockedVolume(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	opened, err := node.Open(ctx, testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	created := opened.SubmitCommand(ctx, nodeTrust(), command(t,
		"10000000-0000-4000-8000-000000000901", "dialog.create",
		map[string]any{"nodeId": testNodeID}, map[string]any{"registryVersion": 1}, map[string]any{}))
	if created.HTTPStatus != 202 {
		t.Fatalf("dialog setup failed: status=%d body=%s", created.HTTPStatus, created.Body)
	}
	before := currentSnapshot(t, ctx, opened)
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	config := testConfig(path)
	config.Policies = fixture.NewPolicySource()
	reopened, err := node.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after := currentSnapshot(t, ctx, reopened)
	if after.StateVersion != before.StateVersion || after.LastEventSeq != before.LastEventSeq ||
		after.Node.EngineReadiness != "blocked" || len(after.Node.BlockedReasons) != 1 || after.Node.BlockedReasons[0] != "policy_unavailable" {
		t.Fatalf("used blocked volume was normalized: before=%+v after=%+v", before, after)
	}
}

func TestOpenRejectsForeignDurableIdentity(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	opened, err := node.Open(ctx, testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	config := testConfig(path)
	config.OwnerID = "1-2"
	if _, err := node.Open(ctx, config); err == nil || !strings.Contains(err.Error(), "durable volume") {
		t.Fatalf("foreign identity was not rejected: %v", err)
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	opened, err := node.Open(ctx, testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(path, "harness.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version=999"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := node.Open(ctx, testConfig(path)); err == nil || !strings.Contains(err.Error(), "newer than binary") {
		t.Fatalf("newer schema was not rejected: %v", err)
	}
}

func TestOpenRejectsUnverifiedAdapter(t *testing.T) {
	path := t.TempDir()
	config := testConfig(path)
	adapter := fixture.NewAdapter()
	adapter.AdapterIdentity.Verified = map[harnessadapter.Capability]bool{}
	config.Adapter = adapter
	if _, err := node.Open(context.Background(), config); err == nil || !strings.Contains(err.Error(), "capability") {
		t.Fatalf("unverified adapter was not rejected: %v", err)
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed adapter claimed new volume: entries=%v err=%v", entries, err)
	}
}

func TestExistingForeignVolumeIsByteUnmodified(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	opened, err := node.Open(ctx, testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(path, "harness.db")
	before, err := os.ReadFile(database)
	if err != nil {
		t.Fatal(err)
	}
	config := testConfig(path)
	config.OwnerID = "1-2"
	if _, err := node.Open(ctx, config); err == nil {
		t.Fatal("foreign volume was accepted")
	}
	after, err := os.ReadFile(database)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("foreign volume bytes changed during rejection")
	}
	if _, err := os.Stat(database + "-journal"); !os.IsNotExist(err) {
		t.Fatalf("foreign preflight created journal: %v", err)
	}
}

func TestExistingUnversionedAndAlteredSchemaAreRejected(t *testing.T) {
	ctx := context.Background()
	t.Run("unversioned", func(t *testing.T) {
		path := t.TempDir()
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
		database := filepath.Join(path, "harness.db")
		db, err := sql.Open("sqlite", database)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("CREATE TABLE unrelated(id INTEGER)"); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(database, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := node.Open(ctx, testConfig(path)); err == nil || !strings.Contains(err.Error(), "unversioned") {
			t.Fatalf("unversioned DB was not rejected: %v", err)
		}
	})
	t.Run("altered ddl", func(t *testing.T) {
		path := t.TempDir()
		opened, err := node.Open(ctx, testConfig(path))
		if err != nil {
			t.Fatal(err)
		}
		if err := opened.Close(); err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("sqlite", filepath.Join(path, "harness.db"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("CREATE TABLE injected(value TEXT) STRICT"); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := node.Open(ctx, testConfig(path)); err == nil || !strings.Contains(err.Error(), "object count") {
			t.Fatalf("altered schema was not rejected: %v", err)
		}
	})
}

func TestFilesystemSymlinksAndSparseReserveAreRejected(t *testing.T) {
	ctx := context.Background()
	t.Run("data symlink", func(t *testing.T) {
		parent := t.TempDir()
		realPath := filepath.Join(parent, "real")
		if err := os.Mkdir(realPath, 0o700); err != nil {
			t.Fatal(err)
		}
		linkPath := filepath.Join(parent, "link")
		if err := os.Symlink(realPath, linkPath); err != nil {
			t.Fatal(err)
		}
		if _, err := node.Open(ctx, testConfig(linkPath)); err == nil {
			t.Fatal("data symlink was accepted")
		}
	})
	t.Run("database symlink", func(t *testing.T) {
		path := t.TempDir()
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
		outside, err := os.CreateTemp(t.TempDir(), "outside")
		if err != nil {
			t.Fatal(err)
		}
		outside.Close()
		if err := os.Symlink(outside.Name(), filepath.Join(path, "harness.db")); err != nil {
			t.Fatal(err)
		}
		if _, err := node.Open(ctx, testConfig(path)); err == nil {
			t.Fatal("database symlink was accepted")
		}
	})
	t.Run("sparse reserve", func(t *testing.T) {
		path := t.TempDir()
		opened, err := node.Open(ctx, testConfig(path))
		if err != nil {
			t.Fatal(err)
		}
		if err := opened.Close(); err != nil {
			t.Fatal(err)
		}
		reserve := filepath.Join(path, ".control.reserve")
		if err := os.Truncate(reserve, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(reserve, node.ControlReserveBytes); err != nil {
			t.Fatal(err)
		}
		if _, err := node.Open(ctx, testConfig(path)); err == nil || !strings.Contains(err.Error(), "fully allocated") {
			t.Fatalf("sparse reserve was not rejected: %v", err)
		}
	})
}

func TestFreshInitializationFailureCleansOnlyCreatedFilesAndCanRetry(t *testing.T) {
	for _, point := range []node.StartupPoint{
		node.StartupReserveWrite,
		node.StartupReserveSync,
		node.StartupBeforeMigration,
		node.StartupAfterMigration,
	} {
		t.Run(string(point), func(t *testing.T) {
			path := t.TempDir()
			config := testConfig(path)
			config.StartupFault = func(actual node.StartupPoint) error {
				if actual == point {
					return errors.New("synthetic startup fault")
				}
				return nil
			}
			if _, err := node.Open(context.Background(), config); err == nil {
				t.Fatal("startup fault did not fail Open")
			}
			entries, err := os.ReadDir(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != ".harness.lock" {
				t.Fatalf("failed fresh init left claimed files: %v", entries)
			}
			retried, err := node.Open(context.Background(), testConfig(path))
			if err != nil {
				t.Fatalf("clean retry failed: %v", err)
			}
			if err := retried.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFreshInitializationCleanupRemainsUnderPermanentVolumeLock(t *testing.T) {
	path := t.TempDir()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	config := testConfig(path)
	config.StartupFault = func(point node.StartupPoint) error {
		if point == node.StartupAfterMigration {
			once.Do(func() { close(entered) })
			<-release
			return errors.New("synthetic init failure")
		}
		return nil
	}
	result := make(chan error, 1)
	go func() { _, err := node.Open(context.Background(), config); result <- err }()
	<-entered
	if _, err := node.Open(context.Background(), testConfig(path)); err == nil || !strings.Contains(err.Error(), "already owned") {
		t.Fatalf("concurrent opener bypassed permanent lock: %v", err)
	}
	close(release)
	if err := <-result; err == nil {
		t.Fatal("first startup unexpectedly succeeded")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != ".harness.lock" {
		t.Fatalf("cleanup removed lock or left volume files: %v", entries)
	}
	retried, err := node.Open(context.Background(), testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := retried.Close(); err != nil {
		t.Fatal(err)
	}
}
