package toolrunner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(main *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--serve" {
		os.Exit(HelperMain(os.Args[1:], os.Stdin, os.Stdout))
	}
	if len(os.Args) == 2 && (os.Args[1] == "--setpgid-probe" || os.Args[1] == "--setsid-probe") {
		os.Exit(runEscapeProbe(os.Args[1]))
	}
	os.Exit(main.Run())
}

func TestValidateRequestRejectsEscapesAndInvalidUnions(t *testing.T) {
	base := Request{CallID: "call-1", Workspace: "/workspace/dialog", Kind: KindCommand, Command: &CommandRequest{
		Command: "printf ok", CWD: ".", Access: AccessRead, Timeout: time.Second,
	}}
	if err := ValidateRequest(base); err != nil {
		t.Fatalf("valid command rejected: %v", err)
	}
	cases := []Request{
		{CallID: "call-1", Workspace: "/workspace/dialog", Kind: KindCommand, Command: base.Command, FileChange: &FileChangeRequest{}},
		{CallID: "call-1", Workspace: "/workspace/dialog", Kind: KindCommand, Command: &CommandRequest{Command: "x", CWD: "../state", Access: AccessRead, Timeout: time.Second}},
		{CallID: "call-1", Workspace: "/workspace/dialog", Kind: KindCommand, Command: &CommandRequest{Command: strings.Repeat("x", MaximumCommandBytes+1), CWD: ".", Access: AccessRead, Timeout: time.Second}},
		{CallID: "call-1", Workspace: "/workspace/dialog", Kind: KindFileChange, FileChange: &FileChangeRequest{Changes: []FileChange{{Path: "../auth", Operation: FileWrite}}}},
		{CallID: "call-1", Workspace: "/workspace/dialog", Kind: KindFileChange, FileChange: &FileChangeRequest{Changes: []FileChange{{Path: "a", Operation: FileDelete}}}},
	}
	for index, request := range cases {
		if ValidateRequest(request) == nil {
			t.Fatalf("invalid case %d accepted", index)
		}
	}
}

func TestLimitedBufferIsBounded(t *testing.T) {
	buffer := &limitedBuffer{maximum: 4}
	if count, err := buffer.Write([]byte("abcdef")); err != nil || count != 6 {
		t.Fatalf("unexpected write result: count=%d err=%v", count, err)
	}
	if got := buffer.String(); got != "abcd" || !buffer.overflow {
		t.Fatalf("buffer=%q overflow=%v", got, buffer.overflow)
	}
}

func TestHelperMainRejectsMalformedEnvelope(t *testing.T) {
	var output strings.Builder
	if exit := HelperMain([]string{"--serve"}, strings.NewReader(`{}`), &output); exit != 0 || !strings.Contains(output.String(), `"failure":"invalid_request"`) {
		t.Fatalf("exit=%d output=%q", exit, output.String())
	}
}

func TestMaximumValidFileChangeFitsBoundedHelperFrame(t *testing.T) {
	changes := make([]FileChange, 0, MaximumChanges)
	for index := 0; index < MaximumChanges; index++ {
		path := strings.Repeat("\x01", 4090) + string(rune('a'+index))
		changes = append(changes, FileChange{Path: path, Operation: FileWrite, Content: make([]byte, MaximumChangeBytes/MaximumChanges)})
	}
	request := Request{CallID: strings.Repeat("a", 256), Workspace: "/workspace/dialog", Kind: KindFileChange, FileChange: &FileChangeRequest{Changes: changes}}
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("maximum public request rejected: %v", err)
	}
	roots := make([]string, 0, 32)
	for index := 0; index < 32; index++ {
		roots = append(roots, "/"+strings.Repeat("\x01", 4093)+string(rune('a'+index)))
	}
	encoded, err := json.Marshal(helperEnvelope{
		ProtocolVersion: helperProtocolVersion, Mode: "run", Request: toWireRequest(request),
		SystemReadRoots: roots, MaximumOutput: DefaultMaximumOutput,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > maximumHelperRequestBytes {
		t.Fatalf("maximum valid helper request requires %d bytes, frame allows %d", len(encoded), maximumHelperRequestBytes)
	}
}

func TestHelperMainRejectsInputAboveFrameLimit(t *testing.T) {
	var output strings.Builder
	input := strings.NewReader(strings.Repeat(" ", maximumHelperRequestBytes+1))
	if exit := HelperMain([]string{"--serve"}, input, &output); exit != 0 || !strings.Contains(output.String(), `"failure":"invalid_request"`) {
		t.Fatalf("exit=%d output=%q", exit, output.String())
	}
}

func TestHelperRunnerDoesNotSpawnAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &helperRunner{config: Config{Executable: "/does/not/exist", SystemReadRoots: []string{"/bin"}, MaxOutputBytes: DefaultMaximumOutput}}
	_, err := runner.invoke(ctx, "run", Request{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled invoke = %v", err)
	}
}

func TestRunnerTrustBoundaryRejectsReservedAndOverlappingRoots(t *testing.T) {
	for _, root := range []string{"/", "/auth", "/auth/codex", "/config", "/state", "/proc/1"} {
		if _, err := validateSystemReadRoot(root); err == nil {
			t.Fatalf("reserved system root %q accepted", root)
		}
	}
	base := t.TempDir()
	system := filepath.Join(base, "runtime")
	workspace := filepath.Join(system, "dialog")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkspaceForRun(workspace, []string{system}); err == nil {
		t.Fatal("workspace overlapping a system read root was accepted")
	}
	reservedWorkspace := "/state/dialog"
	if err := validateWorkspaceForRun(reservedWorkspace, []string{"/usr"}); err == nil {
		t.Fatal("reserved workspace was accepted")
	}
}

func TestHelperExecutableRejectsSymlinkAndWritableBinary(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "helper")
	if err := os.WriteFile(binary, []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "helper-link")
	if err := os.Symlink(binary, symlink); err != nil {
		t.Fatal(err)
	}
	if err := validateHelperExecutable(symlink); err == nil {
		t.Fatal("symlink helper executable was accepted")
	}
	if err := os.Chmod(binary, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := validateHelperExecutable(binary); err == nil {
		t.Fatal("group-writable helper executable was accepted")
	}
}

func TestNewHelperFailsClosedOffLinux(t *testing.T) {
	if isLinux() {
		t.Skip("covered by linux isolation tests")
	}
	_, err := NewHelper(context.Background(), Config{Executable: os.Args[0], SystemReadRoots: []string{"/bin"}})
	if err == nil {
		t.Fatal("unsupported host accepted helper isolation")
	}
}
