package node

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
)

func secureDataDir(input string) (string, error) {
	absolute, err := filepath.Abs(input)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", fmt.Errorf("resolve data parent: %w", err)
	}
	path := filepath.Join(parent, filepath.Base(absolute))
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return "", fmt.Errorf("create data directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("data directory must be a real directory")
	}
	if err := validateOwner(info); err != nil {
		return "", fmt.Errorf("data directory: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		entries, readErr := os.ReadDir(path)
		if readErr != nil || len(entries) != 0 {
			return "", fmt.Errorf("data directory permissions are too broad: %04o", info.Mode().Perm())
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return "", fmt.Errorf("secure new data directory: %w", err)
		}
		info, err = os.Lstat(path)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("data directory changed while securing permissions")
		}
	}
	if err := validateOwner(info); err != nil {
		return "", fmt.Errorf("data directory: %w", err)
	}
	return path, nil
}

func secureOpenFile(path string, flags int, mode os.FileMode) (*os.File, error) {
	file, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if err := validateRegularFile(path, info, mode); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func validateRegularFile(path string, info os.FileInfo, maximumMode os.FileMode) error {
	lstat, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if lstat.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("volume file must be a regular non-symlink file")
	}
	if info.Mode().Perm()&^maximumMode.Perm() != 0 {
		return errors.New("volume file permissions are too broad")
	}
	return validateOwner(info)
}

func validateOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("filesystem object has unexpected owner")
	}
	return nil
}

func allocatedBytes(info os.FileInfo) int64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return stat.Blocks * 512
}

func sqliteDSN(path string, mode string, pragmas bool) string {
	uri := &url.URL{Scheme: "file", Path: path}
	query := url.Values{"mode": []string{mode}}
	if pragmas {
		query.Add("_pragma", "busy_timeout(2000)")
		query.Add("_pragma", "journal_mode(DELETE)")
		query.Add("_pragma", "synchronous(EXTRA)")
		query.Add("_pragma", "foreign_keys(1)")
	}
	uri.RawQuery = query.Encode()
	return uri.String()
}

func writerDSN(path string) string { return sqliteDSN(path, "rw", true) }

type ownedFile struct {
	path   string
	device uint64
	inode  uint64
	valid  bool
}

func identifyOwnedFile(path string, file *os.File) (ownedFile, error) {
	info, err := file.Stat()
	if err != nil {
		return ownedFile{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ownedFile{}, errors.New("file identity unavailable")
	}
	return ownedFile{path: path, device: uint64(stat.Dev), inode: uint64(stat.Ino), valid: true}, nil
}

func sameOwnedFile(file ownedFile) bool {
	if !file.valid {
		return false
	}
	info, err := os.Lstat(file.path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Dev) == file.device && uint64(stat.Ino) == file.inode
}

func cleanupOwnedFile(file ownedFile) {
	if sameOwnedFile(file) {
		_ = os.Remove(file.path)
	}
}

func prepareDatabaseFile(ctx context.Context, path string, config Config) (ownedFile, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		file, err := secureOpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return ownedFile{}, fmt.Errorf("create database: %w", err)
		}
		token, identityErr := identifyOwnedFile(path, file)
		if identityErr != nil {
			file.Close()
			_ = os.Remove(path)
			return ownedFile{}, identityErr
		}
		if err := file.Close(); err != nil {
			cleanupOwnedFile(token)
			return ownedFile{}, err
		}
		return token, nil
	}
	if err != nil {
		return ownedFile{}, err
	}
	if err := validateRegularFile(path, info, 0o600); err != nil {
		return ownedFile{}, fmt.Errorf("database file: %w", err)
	}
	if err := inspectExistingDatabase(ctx, path, config); err != nil {
		return ownedFile{}, err
	}
	return ownedFile{}, nil
}

func inspectExistingDatabase(ctx context.Context, path string, config Config) error {
	journal := path + "-journal"
	if info, err := os.Lstat(journal); err == nil && info.Size() > 0 {
		if err := validateRegularFile(journal, info, 0o600); err != nil {
			return fmt.Errorf("rollback journal: %w", err)
		}
		return inspectRecoveredClone(ctx, path, journal, config)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect rollback journal: %w", err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(path, "ro", false))
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer db.Close()
	return inspectDatabaseIdentity(ctx, db, config)
}

func inspectRecoveredClone(ctx context.Context, database, journal string, config Config) error {
	directory, err := os.MkdirTemp(filepath.Dir(database), ".recovery-preflight-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	clone := filepath.Join(directory, "harness.db")
	if err := copyOwnedFile(database, clone); err != nil {
		return err
	}
	if err := copyOwnedFile(journal, clone+"-journal"); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", writerDSN(clone))
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer db.Close()
	return inspectDatabaseIdentity(ctx, db, config)
}

func copyOwnedFile(source, destination string) error {
	input, err := secureOpenFile(source, os.O_RDONLY, 0o600)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := secureOpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = output.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func inspectDatabaseIdentity(ctx context.Context, db *sql.DB, config Config) error {
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version == 0 {
		return errors.New("pre-existing unversioned database is not a Harness volume")
	}
	if version > SchemaVersion {
		return fmt.Errorf("database schema %d is newer than binary schema %d", version, SchemaVersion)
	}
	if version != legacySchemaVersion && version != wireSchemaVersion && version != barrierSchemaVersion && version != quiescenceSchemaVersion && version != historyReplicaSchemaVersion && version != SchemaVersion {
		return fmt.Errorf("unsupported database schema %d", version)
	}
	var fingerprint string
	expectedFingerprint, ok := expectedSchemaFingerprint(version)
	if !ok {
		return fmt.Errorf("unsupported database schema %d", version)
	}
	if err := db.QueryRowContext(ctx, "SELECT fingerprint FROM schema_meta WHERE singleton=1").Scan(&fingerprint); err != nil || fingerprint != expectedFingerprint {
		return errors.New("database schema fingerprint does not match binary")
	}
	if err := verifySchemaDDL(ctx, db, schemaStatementsForVersion(version)); err != nil {
		return err
	}
	var nodeID, ownerID string
	var registryVersion int64
	if err := db.QueryRowContext(ctx, "SELECT node_id,owner_id,registry_version FROM node_state WHERE singleton=1").Scan(&nodeID, &ownerID, &registryVersion); err != nil {
		return fmt.Errorf("read durable identity: %w", err)
	}
	if nodeID != config.NodeID || ownerID != config.OwnerID || registryVersion != config.RegistryVersion {
		return errors.New("configured node identity does not match durable volume")
	}
	return verifyIntegrity(ctx, db)
}

func verifyIntegrity(ctx context.Context, db *sql.DB) error {
	var result string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil || result != "ok" {
		return fmt.Errorf("sqlite integrity check failed: %s: %w", result, err)
	}
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("sqlite foreign key check failed")
	}
	return rows.Err()
}
