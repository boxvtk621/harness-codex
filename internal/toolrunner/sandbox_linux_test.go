//go:build linux

package toolrunner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLinuxHelperIsolationAndLifecycle(t *testing.T) {
	runner := linuxTestRunner(t)
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	readOnly, err := runner.Run(context.Background(), Request{CallID: "read-deny-write", Workspace: workspace, Kind: KindCommand, Command: &CommandRequest{
		Command: "printf blocked > file", CWD: ".", Access: AccessRead, Timeout: 3 * time.Second,
	}})
	if err != nil || readOnly.Success {
		t.Fatalf("read-only write result=%+v err=%v", readOnly, err)
	}
	write, err := runner.Run(context.Background(), Request{CallID: "write", Workspace: workspace, Kind: KindCommand, Command: &CommandRequest{
		Command: "printf ok > file && printf done", CWD: ".", Access: AccessWrite, Timeout: 3 * time.Second,
	}})
	if err != nil || !write.Success || string(write.Output) != "done" {
		t.Fatalf("write result=%+v err=%v", write, err)
	}
	if info, err := os.Stat(filepath.Join(workspace, "file")); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("shell-created file mode=%v err=%v", info, err)
	}
	background, err := runner.Run(context.Background(), Request{CallID: "background", Workspace: workspace, Kind: KindCommand, Command: &CommandRequest{
		Command: "sleep 30 > bg.log 2>&1 & printf $!", CWD: ".", Access: AccessWrite, Timeout: 3 * time.Second,
	}})
	if err != nil || !background.Success {
		t.Fatalf("background result=%+v err=%v", background, err)
	}
	probePath := filepath.Join(workspace, "escape-probe")
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	probe, err := os.OpenFile(probePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(probe, source)
	closeProbeErr := probe.Close()
	closeSourceErr := source.Close()
	if copyErr != nil || closeProbeErr != nil || closeSourceErr != nil {
		t.Fatalf("copy escape probe: copy=%v probe=%v source=%v", copyErr, closeProbeErr, closeSourceErr)
	}
	escaped, err := runner.Run(context.Background(), Request{CallID: "process-group-escape", Workspace: workspace, Kind: KindCommand, Command: &CommandRequest{
		Command: "./escape-probe --setpgid-probe && ./escape-probe --setsid-probe", CWD: ".", Access: AccessWrite, Timeout: 15 * time.Second,
	}})
	if err != nil || !escaped.Success {
		t.Fatalf("process-group escape probes result=%+v err=%v", escaped, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(background.Output)))
	if err != nil || pid <= 1 {
		t.Fatalf("invalid child pid %q", background.Output)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat")); err == nil {
			fields := strings.Fields(string(status))
			if len(fields) >= 3 && fields[2] == "Z" {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("background process %d survived approved call", pid)
}

func TestSeccompPolicyDeniesNetworkAndProcessEscapes(t *testing.T) {
	wanted := map[string][]uint32{
		"amd64": {
			41, 53, 288, 299, 307, // socket, socketpair, accept4, recvmmsg, sendmmsg
			101, 155, 165, 166, 272, 298, 304, 308, 310, 311, 313, 321, 323, // ptrace, namespaces, mounts, keyring and BPF
			425, 426, 427, // io_uring
			62, 109, 112, 129, 200, 234, 297, 424, // cross-process signals and process-group/session escape
		},
		"arm64": {
			198, 199, 242, 243, 269, // socket, socketpair, accept4, recvmmsg, sendmmsg
			117, 39, 40, 41, 97, 241, 265, 268, 270, 271, 273, 280, 282, // ptrace, namespaces, mounts, keyring and BPF
			425, 426, 427, // io_uring
			129, 130, 131, 138, 154, 157, 240, 424, // cross-process signals and process-group/session escape
		},
	}
	clone := map[string]uint32{"amd64": 56, "arm64": 220}
	for _, architecture := range []string{"amd64", "arm64"} {
		_, cloneNumber, denied, _, ok := seccompPolicy(architecture)
		if !ok {
			t.Fatalf("missing policy for %s", architecture)
		}
		if cloneNumber != clone[architecture] {
			t.Fatalf("%s clone syscall = %d", architecture, cloneNumber)
		}
		for _, number := range wanted[architecture] {
			found := false
			for _, candidate := range denied {
				found = found || candidate == number
			}
			if !found {
				t.Fatalf("%s syscall %d is not denied", architecture, number)
			}
		}
	}
}

func TestLinuxSandboxSelfTestDirect(t *testing.T) {
	if os.Getenv("TOOLRUNNER_DIRECT_SELF_TEST") == "1" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := sandboxSelfTest(os.Getenv("TOOLRUNNER_TEST_WORKSPACE"), linuxReadRoots()); err != nil {
			t.Fatal(err)
		}
		return
	}
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run", "^TestLinuxSandboxSelfTestDirect$", "-test.v")
	command.Env = append(os.Environ(), "TOOLRUNNER_DIRECT_SELF_TEST=1", "TOOLRUNNER_TEST_WORKSPACE="+workspace)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("direct self-test failed: %v\n%s", err, output)
	}
}

func TestLinuxFileChangeUsesExactHashesAndRejectsSymlinks(t *testing.T) {
	runner := linuxTestRunner(t)
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	create := Request{CallID: "create", Workspace: workspace, Kind: KindFileChange, FileChange: &FileChangeRequest{Changes: []FileChange{{Path: "note.txt", Operation: FileWrite, Content: []byte("one")}}}}
	if result, err := runner.Run(context.Background(), create); err != nil || !result.Success {
		t.Fatalf("create result=%+v err=%v", result, err)
	}
	digest := sha256.Sum256([]byte("one"))
	expected := hex.EncodeToString(digest[:])
	update := create
	update.CallID = "update"
	update.FileChange = &FileChangeRequest{Changes: []FileChange{{Path: "note.txt", Operation: FileWrite, ExpectedSHA256: &expected, Content: []byte("two")}}}
	if result, err := runner.Run(context.Background(), update); err != nil || !result.Success {
		t.Fatalf("update result=%+v err=%v", result, err)
	}
	outside := filepath.Join(filepath.Dir(workspace), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, "link")); err != nil {
		t.Fatal(err)
	}
	bad := create
	bad.CallID = "symlink"
	bad.FileChange = &FileChangeRequest{Changes: []FileChange{{Path: "link", Operation: FileWrite, Content: []byte("bad")}}}
	if result, err := runner.Run(context.Background(), bad); err != nil || result.Success {
		t.Fatalf("symlink result=%+v err=%v", result, err)
	}
	if content, err := os.ReadFile(outside); err != nil || string(content) != "secret" {
		t.Fatalf("outside file changed: %q err=%v", content, err)
	}
}

func TestLinuxCancellationKillsDescendantsBeforeTheyCanWrite(t *testing.T) {
	runner := linuxTestRunner(t)
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := runner.Run(ctx, Request{CallID: "cancel-descendants", Workspace: workspace, Kind: KindCommand, Command: &CommandRequest{
			Command: "printf started > started; (sleep 1; printf escaped > after-stop) & wait", CWD: ".", Access: AccessWrite, Timeout: 5 * time.Second,
		}})
		done <- err
	}()
	started := filepath.Join(workspace, "started")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sandboxed command did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled run = %v", err)
	}
	time.Sleep(1200 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(workspace, "after-stop")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("descendant wrote after cancellation: %v", err)
	}
}

func TestLinuxRunnerSerializesOneWorkspaceWithoutBlockingAnother(t *testing.T) {
	runner := linuxTestRunner(t)
	root := t.TempDir()
	firstWorkspace := filepath.Join(root, "first")
	secondWorkspace := filepath.Join(root, "second")
	for _, workspace := range []string{firstWorkspace, secondWorkspace} {
		if err := os.Mkdir(workspace, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	firstDone := make(chan error, 1)
	go func() {
		result, err := runner.Run(context.Background(), Request{CallID: "first-long", Workspace: firstWorkspace, Kind: KindCommand, Command: &CommandRequest{
			Command: "printf ready > ready; sleep 5; printf done > done", CWD: ".", Access: AccessWrite, Timeout: 10 * time.Second,
		}})
		if err == nil && !result.Success {
			err = errors.New("first workspace command failed")
		}
		firstDone <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(firstWorkspace, "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first workspace command did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	other, err := runner.Run(context.Background(), Request{CallID: "other-workspace", Workspace: secondWorkspace, Kind: KindCommand, Command: &CommandRequest{
		Command: "printf independent", CWD: ".", Access: AccessRead, Timeout: 3 * time.Second,
	}})
	if err != nil || !other.Success || string(other.Output) != "independent" {
		t.Fatalf("other workspace was blocked: result=%+v err=%v", other, err)
	}
	serialized, err := runner.Run(context.Background(), Request{CallID: "same-workspace", Workspace: firstWorkspace, Kind: KindCommand, Command: &CommandRequest{
		Command: "test -f done && printf serialized", CWD: ".", Access: AccessRead, Timeout: 10 * time.Second,
	}})
	if err != nil || !serialized.Success || string(serialized.Output) != "serialized" {
		t.Fatalf("same workspace was not serialized: result=%+v err=%v", serialized, err)
	}
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func linuxTestRunner(t *testing.T) Runner {
	t.Helper()
	roots := linuxReadRoots()
	canonical := make([]string, 0, len(roots))
	for _, root := range roots {
		value, err := validateSystemReadRoot(root)
		if err != nil {
			t.Fatalf("system root rejected: %v", err)
		}
		canonical = append(canonical, value)
	}
	var runner Runner
	var err error
	if os.Geteuid() == 0 {
		runner, err = NewHelper(context.Background(), Config{Executable: os.Args[0], SystemReadRoots: roots})
	} else {
		// Hosted CI test binaries are not root-owned. Exercise the same helper
		// protocol and self-test while leaving NewHelper's production uid=0
		// trust gate intact; the container test covers that exact ownership gate.
		unchecked := &helperRunner{config: Config{Executable: os.Args[0], SystemReadRoots: canonical, MaxOutputBytes: DefaultMaximumOutput, MaxRuntime: MaximumRuntime}}
		err = unchecked.SelfTest(context.Background())
		runner = unchecked
	}
	if err != nil {
		t.Fatalf("helper self-test failed: %v", err)
	}
	return runner
}

func linuxReadRoots() []string {
	roots := make([]string, 0)
	for _, root := range []string{"/bin", "/usr", "/lib", "/lib64", "/etc/ld.so.cache", "/dev/null", "/dev/urandom"} {
		if _, err := os.Stat(root); err == nil {
			roots = append(roots, root)
		}
	}
	return roots
}
