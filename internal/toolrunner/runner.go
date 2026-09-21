// Package toolrunner defines the provider-independent contract for executing
// agent tools in a separate, fail-closed helper process.
package toolrunner

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	DefaultMaximumOutput = 1 << 20
	MaximumCommandBytes  = 32 << 10
	MaximumFileBytes     = 1 << 20
	MaximumChangeBytes   = 4 << 20
	MaximumChanges       = 32
	MaximumRuntime       = 60 * time.Second
)

type Kind string

const (
	KindCommand    Kind = "command"
	KindFileChange Kind = "file_change"
)

type Access string

const (
	AccessRead  Access = "read"
	AccessWrite Access = "write"
)

type FileOperation string

const (
	FileWrite  FileOperation = "write"
	FileDelete FileOperation = "delete"
)

type Runner interface {
	SelfTest(context.Context) error
	Run(context.Context, Request) (Result, error)
}

type Request struct {
	CallID     string
	Workspace  string
	Kind       Kind
	Command    *CommandRequest
	FileChange *FileChangeRequest
}

type CommandRequest struct {
	Command string
	CWD     string
	Access  Access
	Timeout time.Duration
}

type FileChangeRequest struct {
	Changes []FileChange
}

type FileChange struct {
	Path           string
	Operation      FileOperation
	ExpectedSHA256 *string
	Content        []byte
}

type FileChangeResult struct {
	Path      string
	Operation FileOperation
}

type Result struct {
	Success   bool
	Output    []byte
	Truncated bool
	ExitCode  *int
	Changes   []FileChangeResult
}

var (
	callIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)
	shaPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func ValidateRequest(request Request) error {
	if !callIDPattern.MatchString(request.CallID) || !validWorkspace(request.Workspace) {
		return errors.New("tool runner request is invalid")
	}
	switch request.Kind {
	case KindCommand:
		if request.Command == nil || request.FileChange != nil {
			return errors.New("tool runner request is invalid")
		}
		command := request.Command
		if command.Command == "" || len(command.Command) > MaximumCommandBytes || !utf8.ValidString(command.Command) ||
			strings.ContainsRune(command.Command, 0) || !validRelative(command.CWD, true) ||
			(command.Access != AccessRead && command.Access != AccessWrite) || command.Timeout <= 0 || command.Timeout > MaximumRuntime {
			return errors.New("tool runner command is invalid")
		}
	case KindFileChange:
		if request.FileChange == nil || request.Command != nil || len(request.FileChange.Changes) == 0 || len(request.FileChange.Changes) > MaximumChanges {
			return errors.New("tool runner file change is invalid")
		}
		seen := make(map[string]bool, len(request.FileChange.Changes))
		total := 0
		for _, change := range request.FileChange.Changes {
			if !validRelative(change.Path, false) || seen[change.Path] ||
				(change.Operation != FileWrite && change.Operation != FileDelete) ||
				(change.ExpectedSHA256 != nil && !shaPattern.MatchString(*change.ExpectedSHA256)) ||
				len(change.Content) > MaximumFileBytes || (change.Operation == FileDelete && len(change.Content) != 0) {
				return errors.New("tool runner file change is invalid")
			}
			if change.Operation == FileDelete && change.ExpectedSHA256 == nil {
				return errors.New("tool runner file change is invalid")
			}
			seen[change.Path] = true
			total += len(change.Content)
			if total > MaximumChangeBytes {
				return errors.New("tool runner file change is invalid")
			}
		}
	default:
		return errors.New("tool runner request is invalid")
	}
	return nil
}

func validWorkspace(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && len(value) <= 4096 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func validRelative(value string, allowDot bool) bool {
	if value == "" || filepath.IsAbs(value) || filepath.Clean(value) != value || len(value) > 4096 ||
		!utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") || value == ".." || strings.HasPrefix(value, ".."+string(filepath.Separator)) {
		return false
	}
	return allowDot || value != "."
}
