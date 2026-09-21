package node

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	_ "modernc.org/sqlite"
)

type RuntimeInfo struct {
	SQLiteVersion     string
	SQLiteSourceID    string
	JournalMode       string
	Synchronous       int
	ForeignKeys       bool
	SchemaVersion     int
	SchemaFingerprint string
}

const (
	SQLiteVersionPin  = "3.53.3"
	SQLiteSourceIDPin = "2026-06-26 20:14:12 d4c0e51e4aeb96955b99185ab9cde75c339e2c29c3f3f12428d364a10d782c62"
)

type Node struct {
	config Config
	db     *sql.DB
	lock   *os.File
	mu     sync.Mutex
	// startGate is ordered before mu. It covers the last pre-provider dispatch
	// check through Start/Resume completion so a committed hold cannot be crossed
	// by a later native start.
	startGate      sync.Mutex
	fault          FaultInjector
	runtime        RuntimeInfo
	identity       harnessadapter.Identity
	startedAt      string
	actions        chan struct{}
	stop           context.CancelFunc
	done           chan struct{}
	workerStarted  bool
	streamMu       sync.Mutex
	streamLease    *attemptStreamLease
	deletedDialogs map[string]struct{}
}

type filesystemSpace struct{}

func (filesystemSpace) Measure(path string) (SpaceInfo, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return SpaceInfo{}, err
	}
	return SpaceInfo{FreeBytes: stat.Bavail * uint64(stat.Bsize), TotalBytes: stat.Blocks * uint64(stat.Bsize)}, nil
}

func Open(ctx context.Context, config Config) (*Node, error) {
	if err := config.defaults(); err != nil {
		return nil, err
	}
	identity, err := config.Adapter.Identity(ctx)
	if err != nil {
		return nil, fmt.Errorf("adapter identity: %w", err)
	}
	if err := harnessadapter.ValidateIdentity(identity); err != nil {
		return nil, fmt.Errorf("adapter identity: %w", err)
	}
	dataDir, err := secureDataDir(config.DataDir)
	if err != nil {
		return nil, err
	}
	config.DataDir = dataDir
	lockPath := filepath.Join(dataDir, ".harness.lock")
	lock, err := secureOpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open volume lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("harness volume is already owned")
	}

	dbPath := filepath.Join(dataDir, "harness.db")
	databaseCreated, err := prepareDatabaseFile(ctx, dbPath, config)
	if err != nil {
		unlock(lock)
		return nil, err
	}
	reserveCreated, err := ensureControlReserve(dataDir, config.StartupFault)
	if err != nil {
		cleanupFreshVolume(databaseCreated)
		unlock(lock)
		return nil, err
	}
	db, err := sql.Open("sqlite", writerDSN(dbPath))
	if err != nil {
		cleanupOwnedFile(reserveCreated)
		cleanupFreshVolume(databaseCreated)
		unlock(lock)
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	workerContext, stop := context.WithCancel(context.Background())
	node := &Node{config: config, db: db, lock: lock, identity: identity, startedAt: timestamp(config.Clock()), actions: make(chan struct{}, 1), stop: stop, done: make(chan struct{})}
	if err := node.initialize(ctx, databaseCreated.valid); err != nil {
		stop()
		_ = db.Close()
		cleanupOwnedFile(reserveCreated)
		cleanupFreshVolume(databaseCreated)
		_ = unlock(lock)
		return nil, err
	}
	if err := node.reconcileArtifactFiles(ctx); err != nil {
		stop()
		_ = db.Close()
		cleanupOwnedFile(reserveCreated)
		cleanupFreshVolume(databaseCreated)
		_ = unlock(lock)
		return nil, err
	}
	if err := node.recoverStartup(ctx); err != nil {
		stop()
		_ = db.Close()
		cleanupOwnedFile(reserveCreated)
		cleanupFreshVolume(databaseCreated)
		_ = unlock(lock)
		return nil, err
	}
	// Older nodes kept an unused volume policy-blocked until first dispatch.
	// Validate and normalize only that exact legacy sentinel on upgrade.
	if !databaseCreated.valid {
		if err := node.recoverPristinePolicy(ctx); err != nil {
			stop()
			_ = db.Close()
			cleanupOwnedFile(reserveCreated)
			cleanupFreshVolume(databaseCreated)
			_ = unlock(lock)
			return nil, err
		}
	}
	if err := config.Artifacts.bind(node); err != nil {
		stop()
		_ = db.Close()
		cleanupOwnedFile(reserveCreated)
		cleanupFreshVolume(databaseCreated)
		_ = unlock(lock)
		return nil, err
	}
	node.workerStarted = true
	go node.actionLoop(workerContext)
	return node, nil
}

func (node *Node) Runtime() RuntimeInfo { return node.runtime }

func (node *Node) SetFaultInjector(injector FaultInjector) { node.fault = injector }

func (node *Node) Close() error {
	if node.stop != nil {
		node.stop()
		if node.workerStarted {
			<-node.done
		}
		node.stop = nil
	}
	if node.config.Artifacts != nil {
		node.config.Artifacts.unbind(node)
	}
	var result error
	if node.db != nil {
		result = node.db.Close()
		node.db = nil
	}
	if node.lock != nil {
		if err := unlock(node.lock); result == nil {
			result = err
		}
		node.lock = nil
	}
	return result
}

func unlock(file *os.File) error {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return file.Close()
}

func (node *Node) initialize(ctx context.Context, newVolume bool) error {
	var foreignKeys int
	if err := node.db.QueryRowContext(ctx, "SELECT sqlite_version(), sqlite_source_id()").Scan(&node.runtime.SQLiteVersion, &node.runtime.SQLiteSourceID); err != nil {
		return fmt.Errorf("sqlite identity: %w", err)
	}
	if node.runtime.SQLiteVersion != SQLiteVersionPin || node.runtime.SQLiteSourceID != SQLiteSourceIDPin {
		return fmt.Errorf("sqlite runtime pin mismatch version=%q source=%q", node.runtime.SQLiteVersion, node.runtime.SQLiteSourceID)
	}
	if err := node.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&node.runtime.JournalMode); err != nil {
		return err
	}
	if err := node.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&node.runtime.Synchronous); err != nil {
		return err
	}
	if err := node.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return err
	}
	node.runtime.ForeignKeys = foreignKeys == 1
	if node.runtime.JournalMode != "delete" || node.runtime.Synchronous != 3 || !node.runtime.ForeignKeys {
		return fmt.Errorf("unsafe sqlite pragmas journal=%s synchronous=%d foreign_keys=%d", node.runtime.JournalMode, node.runtime.Synchronous, foreignKeys)
	}
	if err := node.migrate(ctx, newVolume); err != nil {
		return err
	}
	if err := node.verifyIdentity(ctx); err != nil {
		return err
	}
	if err := verifySchemaDDL(ctx, node.db, schemaStatements); err != nil {
		return err
	}
	if err := verifyIntegrity(ctx, node.db); err != nil {
		return err
	}
	deletedDialogs, err := loadDeletedDialogs(ctx, node.db)
	if err != nil {
		return fmt.Errorf("load deleted dialogs: %w", err)
	}
	node.deletedDialogs = deletedDialogs
	return nil
}

func ensureControlReserve(dataDir string, fault func(StartupPoint) error) (ownedFile, error) {
	path := filepath.Join(dataDir, ".control.reserve")
	info, err := os.Stat(path)
	if err == nil {
		if err := validateRegularFile(path, info, 0o600); err != nil {
			return ownedFile{}, err
		}
		if info.Size() != ControlReserveBytes || allocatedBytes(info) < ControlReserveBytes {
			return ownedFile{}, errors.New("control reserve is not fully allocated")
		}
		return ownedFile{}, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ownedFile{}, fmt.Errorf("stat control reserve: %w", err)
	}
	file, err := secureOpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ownedFile{}, fmt.Errorf("create control reserve: %w", err)
	}
	token, err := identifyOwnedFile(path, file)
	if err != nil {
		file.Close()
		_ = os.Remove(path)
		return ownedFile{}, err
	}
	created := true
	defer func() {
		if created {
			file.Close()
			cleanupOwnedFile(token)
		}
	}()
	buffer := make([]byte, 1024*1024)
	for index := range buffer {
		buffer[index] = byte(index*31 + 17)
	}
	for remaining := int64(ControlReserveBytes); remaining > 0; remaining -= int64(len(buffer)) {
		if fault != nil {
			if err := fault(StartupReserveWrite); err != nil {
				return ownedFile{}, err
			}
		}
		if _, err := file.Write(buffer); err != nil {
			return ownedFile{}, fmt.Errorf("allocate control reserve: %w", err)
		}
	}
	if fault != nil {
		if err := fault(StartupReserveSync); err != nil {
			return ownedFile{}, err
		}
	}
	if err := file.Sync(); err != nil {
		return ownedFile{}, fmt.Errorf("sync control reserve: %w", err)
	}
	if err := file.Close(); err != nil {
		return ownedFile{}, err
	}
	info, err = os.Lstat(path)
	if err != nil {
		return ownedFile{}, err
	}
	if allocatedBytes(info) < ControlReserveBytes {
		return ownedFile{}, errors.New("control reserve allocation is sparse")
	}
	created = false
	return token, nil
}

func cleanupFreshVolume(created ownedFile) {
	if !sameOwnedFile(created) {
		return
	}
	journal := created.path + "-journal"
	if info, err := os.Lstat(journal); err == nil && validateRegularFile(journal, info, 0o600) == nil {
		_ = os.Remove(journal)
	}
	cleanupOwnedFile(created)
}

func admissionFloor(total uint64) uint64 {
	floor := total / 10
	if floor < MinimumFreeBytes {
		return MinimumFreeBytes
	}
	return floor
}

func (node *Node) verifyIdentity(ctx context.Context) error {
	var nodeID, ownerID string
	var registryVersion int64
	err := node.db.QueryRowContext(ctx, "SELECT node_id, owner_id, registry_version FROM node_state WHERE singleton=1").Scan(&nodeID, &ownerID, &registryVersion)
	if err != nil {
		return fmt.Errorf("load node identity: %w", err)
	}
	if nodeID != node.config.NodeID || ownerID != node.config.OwnerID || registryVersion != node.config.RegistryVersion {
		return errors.New("configured node identity does not match durable volume")
	}
	return nil
}
