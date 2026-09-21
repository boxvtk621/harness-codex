package node

import (
	"errors"
	"os"
	"path/filepath"
)

func (node *Node) storageBelowAdmissionFloor() bool {
	space, err := node.config.Space.Measure(node.config.DataDir)
	return err != nil || space.FreeBytes < admissionFloor(space.TotalBytes)
}

func (node *Node) physicalStorageBelowAdmissionFloor() bool {
	space, err := (filesystemSpace{}).Measure(node.config.DataDir)
	return err != nil || space.FreeBytes < admissionFloor(space.TotalBytes)
}

// releaseControlReserve is called only while node.mu and the volume flock are
// held, after authority/idempotency lookup and before the first control write.
func (node *Node) releaseControlReserve() (bool, error) {
	path := filepath.Join(node.config.DataDir, ".control.reserve")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := validateRegularFile(path, info, 0o600); err != nil || info.Size() != ControlReserveBytes || allocatedBytes(info) < ControlReserveBytes {
		return false, errors.New("control reserve is invalid")
	}
	if err := os.Remove(path); err != nil {
		return false, err
	}
	directory, err := os.Open(node.config.DataDir)
	if err != nil {
		return true, err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return true, err
	}
	return true, nil
}

func (node *Node) replenishControlReserve(released bool) {
	if !released {
		return
	}
	_, _ = ensureControlReserve(node.config.DataDir, nil)
}
