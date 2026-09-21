//go:build !linux

package toolrunner

import (
	"errors"
	"os"
)

func validateHelperExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("tool runner executable is untrusted")
	}
	return nil
}

func trustedRootOwner(os.FileInfo) bool { return true }
