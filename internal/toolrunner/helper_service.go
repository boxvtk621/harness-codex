package toolrunner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

// Valid file_change payloads use base64 for up to MaximumChangeBytes and can
// contain 32 maximally escaped paths. The 8 MiB internal frame keeps the full
// public request contract representable without leaving the helper unbounded.
const maximumHelperRequestBytes = 8 << 20

// HelperMain is the complete entrypoint for the static sandbox helper. It
// accepts exactly one JSON request on stdin and writes exactly one bounded JSON
// response. Failure strings are fixed codes and never include arguments,
// paths, command output, or OS error text.
func HelperMain(arguments []string, input io.Reader, output io.Writer) int {
	// Landlock and seccomp apply to the calling Linux thread. Pin the complete
	// decode/sandbox/execute lifecycle so Go cannot migrate execution back onto
	// a pre-existing unrestricted runtime thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if len(arguments) != 1 || arguments[0] != "--serve" {
		return 2
	}
	encoded, err := io.ReadAll(io.LimitReader(input, maximumHelperRequestBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maximumHelperRequestBytes {
		return writeHelperFailure(output, "invalid_request")
	}
	var envelope helperEnvelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF ||
		envelope.ProtocolVersion != helperProtocolVersion || (envelope.Mode != "run" && envelope.Mode != "self-test") ||
		envelope.MaximumOutput < 1024 || envelope.MaximumOutput > DefaultMaximumOutput ||
		len(envelope.SystemReadRoots) == 0 || len(envelope.SystemReadRoots) > 32 {
		return writeHelperFailure(output, "invalid_request")
	}
	canonicalRoots := make([]string, 0, len(envelope.SystemReadRoots))
	for _, root := range envelope.SystemReadRoots {
		canonical, rootErr := validateSystemReadRoot(root)
		if rootErr != nil {
			return writeHelperFailure(output, "invalid_system_root")
		}
		canonicalRoots = append(canonicalRoots, canonical)
	}
	envelope.SystemReadRoots = canonicalRoots
	request := fromWireRequest(envelope.Request)
	if ValidateRequest(request) != nil {
		return writeHelperFailure(output, "invalid_tool_request")
	}
	if validateWorkspaceDirectory(request.Workspace) != nil {
		return writeHelperFailure(output, "invalid_workspace")
	}
	if validateWorkspaceForRun(request.Workspace, envelope.SystemReadRoots) != nil {
		return writeHelperFailure(output, "invalid_workspace_scope")
	}
	syscall.Umask(0o077)
	if setResourceLimits() != nil {
		return writeHelperFailure(output, "isolation_unavailable")
	}
	if envelope.Mode == "self-test" {
		if sandboxSelfTest(request.Workspace, envelope.SystemReadRoots) != nil {
			return writeHelperFailure(output, "isolation_unavailable")
		}
		return writeHelperResponse(output, helperResponse{ProtocolVersion: helperProtocolVersion, Success: true})
	}
	access := AccessWrite
	if request.Command != nil {
		access = request.Command.Access
	}
	if applyPlatformSandbox(request.Workspace, access, envelope.SystemReadRoots) != nil {
		return writeHelperFailure(output, "isolation_unavailable")
	}
	var response helperResponse
	if request.Kind == KindCommand {
		response = executeCommand(request, envelope.MaximumOutput)
	} else {
		response = executeFileChange(request)
	}
	response.ProtocolVersion = helperProtocolVersion
	return writeHelperResponse(output, response)
}

func validateWorkspaceDirectory(workspace string) error {
	info, err := os.Lstat(workspace)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("workspace is invalid")
	}
	return nil
}

func executeCommand(request Request, maximum int) helperResponse {
	if enterWorkspaceDirectory(request.Workspace, request.Command.CWD) != nil {
		return helperResponse{Success: false, Output: []byte("working directory rejected")}
	}
	command := exec.Command("/bin/sh", "-c", request.Command.Command)
	command.Dir = "."
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + request.Workspace, "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	command.Stdin = nil
	buffer := &limitedBuffer{maximum: maximum}
	command.Stdout = buffer
	command.Stderr = buffer
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: false}
	err := command.Run()
	exitCode := 0
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			exitCode = exit.ExitCode()
		} else {
			exitCode = 127
		}
	}
	return helperResponse{Success: exitCode == 0, Output: bytes.Clone(buffer.Bytes()), Truncated: buffer.overflow, ExitCode: &exitCode}
}

func executeFileChange(request Request) helperResponse {
	completed, err := applySecureFileChanges(request.Workspace, request.FileChange.Changes)
	if err != nil {
		return helperResponse{Success: false, Output: []byte("file operation rejected"), Changes: completed}
	}
	return helperResponse{Success: true, Output: []byte("file changes completed"), Changes: completed}
}

func setResourceLimits() error {
	limits := []struct {
		resource int
		value    uint64
	}{
		{syscall.RLIMIT_CORE, 0},
		{syscall.RLIMIT_NOFILE, 64},
		{syscall.RLIMIT_FSIZE, MaximumChangeBytes + DefaultMaximumOutput},
		{syscall.RLIMIT_CPU, uint64(MaximumRuntime/time.Second) + 1},
	}
	for _, limit := range limits {
		if syscall.Setrlimit(limit.resource, &syscall.Rlimit{Cur: limit.value, Max: limit.value}) != nil {
			return errors.New("resource limit failed")
		}
	}
	return nil
}

func writeHelperFailure(output io.Writer, code string) int {
	return writeHelperResponse(output, helperResponse{ProtocolVersion: helperProtocolVersion, Failure: code})
}

func writeHelperResponse(output io.Writer, response helperResponse) int {
	if json.NewEncoder(output).Encode(response) != nil {
		return 1
	}
	return 0
}
