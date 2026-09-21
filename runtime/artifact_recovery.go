package node

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func openArtifactDirectory(dataDir string) (*os.Root, *os.File, error) {
	path := filepath.Join(dataDir, "artifacts")
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() || before.Mode().Perm()&0o077 != 0 || validateOwner(before) != nil {
		return nil, nil, errors.New("artifact directory is unsafe")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, err
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, nil, errors.New("artifact directory changed")
	}
	directory, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, nil, err
	}
	return root, directory, nil
}

func removableArtifactFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&^os.FileMode(0o600) == 0 && validateOwner(info) == nil
}

func removeArtifactFiles(dataDir string, names []string) error {
	root, directory, err := openArtifactDirectory(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	defer directory.Close()
	removed := false
	for _, name := range names {
		if !uuidPattern.MatchString(name) {
			return errors.New("artifact cleanup name is invalid")
		}
		info, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !removableArtifactFile(info) {
			return errors.New("artifact cleanup target is unsafe")
		}
		if err := root.Remove(name); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return directory.Sync()
	}
	return nil
}

func artifactTemporaryID(name string) (string, bool) {
	if !strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".tmp") {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(name, "."), ".tmp")
	return id, uuidPattern.MatchString(id)
}

// reconcileArtifactFiles runs while the volume lock is held and before the
// worker starts. A final UUID name is created only after file fsync+rename;
// when no committed row references it, the file is an unknown-commit orphan.
// Temporary UUID files can never be referenced and are safe to remove too.
func (node *Node) reconcileArtifactFiles(ctx context.Context) error {
	node.mu.Lock()
	defer node.mu.Unlock()
	rows, err := node.db.QueryContext(ctx, "SELECT artifact_id,relative_path FROM artifacts")
	if err != nil {
		return err
	}
	committed := make(map[string]struct{})
	for rows.Next() {
		var artifactID, relative string
		if err := rows.Scan(&artifactID, &relative); err != nil {
			rows.Close()
			return err
		}
		if !uuidPattern.MatchString(artifactID) || relative != filepath.Join("artifacts", artifactID) {
			rows.Close()
			return errors.New("artifact row path is invalid")
		}
		committed[artifactID] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	root, directory, err := openArtifactDirectory(node.config.DataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := committed[name]; ok {
			continue
		}
		_, temporary := artifactTemporaryID(name)
		if !uuidPattern.MatchString(name) && !temporary {
			continue
		}
		info, err := root.Lstat(name)
		if err != nil || !removableArtifactFile(info) {
			return errors.New("orphan artifact is unsafe")
		}
		if err := root.Remove(name); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return directory.Sync()
	}
	return nil
}
