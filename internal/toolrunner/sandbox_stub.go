//go:build !linux

package toolrunner

import "errors"

func applyPlatformSandbox(string, Access, []string) error {
	return errors.New("tool runner isolation is unsupported")
}

func sandboxSelfTest(string, []string) error {
	return errors.New("tool runner isolation is unsupported")
}

func enterWorkspaceDirectory(string, string) error {
	return errors.New("tool runner isolation is unsupported")
}

func applySecureFileChanges(string, []FileChange) ([]FileChangeResult, error) {
	return nil, errors.New("tool runner isolation is unsupported")
}
