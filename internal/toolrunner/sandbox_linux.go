//go:build linux

package toolrunner

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	landlockCreateRulesetVersion = 1
	landlockRulePathBeneath      = 1

	landlockAccessFSExecute    = 1 << 0
	landlockAccessFSWriteFile  = 1 << 1
	landlockAccessFSReadFile   = 1 << 2
	landlockAccessFSReadDir    = 1 << 3
	landlockAccessFSRemoveDir  = 1 << 4
	landlockAccessFSRemoveFile = 1 << 5
	landlockAccessFSMakeChar   = 1 << 6
	landlockAccessFSMakeDir    = 1 << 7
	landlockAccessFSMakeReg    = 1 << 8
	landlockAccessFSMakeSock   = 1 << 9
	landlockAccessFSMakeFIFO   = 1 << 10
	landlockAccessFSMakeBlock  = 1 << 11
	landlockAccessFSMakeSym    = 1 << 12
	landlockAccessFSRefer      = 1 << 13
	landlockAccessFSTruncate   = 1 << 14
	landlockAccessFSIOCTLDev   = 1 << 15

	prSetNoNewPrivileges = 38
	prSetSeccomp         = 22
	seccompModeFilter    = 2

	bpfLoadWordAbsolute = 0x20
	bpfJumpEqual        = 0x15
	bpfJumpSet          = 0x45
	bpfReturn           = 0x06
	seccompReturnKill   = 0x80000000
	seccompReturnErrno  = 0x00050000
	seccompReturnAllow  = 0x7fff0000
)

type landlockRulesetAttribute struct {
	HandledAccessFS uint64
}

type landlockPathBeneathAttribute struct {
	AllowedAccess uint64
	ParentFD      int32
	_             uint32
}

func applyPlatformSandbox(workspace string, access Access, systemReadRoots []string) error {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return errors.New("unsupported linux architecture")
	}
	abi, _, errno := syscall.Syscall(444, 0, 0, landlockCreateRulesetVersion)
	if errno != 0 || abi < 3 {
		return errors.New("landlock is unavailable")
	}
	handled := uint64(landlockAccessFSExecute | landlockAccessFSWriteFile | landlockAccessFSReadFile | landlockAccessFSReadDir |
		landlockAccessFSRemoveDir | landlockAccessFSRemoveFile | landlockAccessFSMakeChar | landlockAccessFSMakeDir |
		landlockAccessFSMakeReg | landlockAccessFSMakeSock | landlockAccessFSMakeFIFO | landlockAccessFSMakeBlock |
		landlockAccessFSMakeSym | landlockAccessFSRefer | landlockAccessFSTruncate)
	if abi >= 5 {
		handled |= landlockAccessFSIOCTLDev
	}
	attribute := landlockRulesetAttribute{HandledAccessFS: handled}
	rulesetFD, _, errno := syscall.Syscall(444, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute), 0)
	if errno != 0 {
		return errors.New("landlock ruleset failed")
	}
	defer syscall.Close(int(rulesetFD))
	readAccess := uint64(landlockAccessFSExecute | landlockAccessFSReadFile | landlockAccessFSReadDir)
	for _, root := range systemReadRoots {
		if err := addLandlockPath(int(rulesetFD), root, readAccess); err != nil {
			return err
		}
	}
	workspaceAccess := readAccess
	if access == AccessWrite {
		workspaceAccess |= handled &^ landlockAccessFSIOCTLDev
	}
	if err := addLandlockPath(int(rulesetFD), workspace, workspaceAccess); err != nil {
		return err
	}
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivileges, 1, 0, 0, 0, 0); errno != 0 {
		return errors.New("no_new_privs failed")
	}
	if _, _, errno := syscall.Syscall(446, rulesetFD, 0, 0); errno != 0 {
		return errors.New("landlock restriction failed")
	}
	// RLIMIT_NPROC is accounted for the complete real UID, including unrelated
	// processes and Go runtime threads on a shared host. Lowering it here can
	// prevent this already-isolated helper from starting even one shell, while
	// still not forming a per-call process boundary. The supported containers
	// provide that boundary with pids_limit=128; every invocation also owns a
	// process group which the parent kills on completion or cancellation.
	return applyNetworkAndEscapeSeccomp(access)
}

func addLandlockPath(rulesetFD int, path string, requested uint64) error {
	info, err := os.Stat(path)
	if err != nil {
		return errors.New("landlock root is unavailable")
	}
	allowed := requested
	if !info.IsDir() {
		allowed &= landlockAccessFSExecute | landlockAccessFSWriteFile | landlockAccessFSReadFile | landlockAccessFSTruncate | landlockAccessFSIOCTLDev
	}
	fd, err := syscall.Open(path, 0x200000|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("landlock root open failed")
	}
	defer syscall.Close(fd)
	attribute := landlockPathBeneathAttribute{AllowedAccess: allowed, ParentFD: int32(fd)}
	if _, _, errno := syscall.Syscall6(445, uintptr(rulesetFD), landlockRulePathBeneath, uintptr(unsafe.Pointer(&attribute)), 0, 0, 0); errno != 0 {
		return errors.New("landlock rule failed")
	}
	return nil
}

func applyNetworkAndEscapeSeccomp(access Access) error {
	arch, cloneNumber, denied, readOnlyDenied, ok := seccompPolicy(runtime.GOARCH)
	if !ok {
		return errors.New("seccomp architecture is unsupported")
	}
	if access == AccessRead {
		denied = append(denied, readOnlyDenied...)
	}
	filters := []syscall.SockFilter{
		{Code: bpfLoadWordAbsolute, K: 4},
		{Code: bpfJumpEqual, Jt: 1, Jf: 0, K: arch},
		{Code: bpfReturn, K: seccompReturnKill},
		{Code: bpfLoadWordAbsolute, K: 0},
		{Code: bpfJumpEqual, Jt: 0, Jf: 3, K: cloneNumber},
		{Code: bpfLoadWordAbsolute, K: 16},
		{Code: bpfJumpSet, Jt: 0, Jf: 1, K: 0x7e020000},
		{Code: bpfReturn, K: seccompReturnErrno | uint32(syscall.EPERM)},
		{Code: bpfLoadWordAbsolute, K: 0},
		// clone3 arguments live behind a userspace pointer and cannot be safely
		// inspected by classic BPF. Report it unavailable so libc/Go falls back to
		// clone, whose inline flags are filtered above.
		{Code: bpfJumpEqual, Jt: 0, Jf: 1, K: 435},
		{Code: bpfReturn, K: seccompReturnErrno | uint32(syscall.ENOSYS)},
	}
	for _, number := range denied {
		filters = append(filters,
			syscall.SockFilter{Code: bpfJumpEqual, Jt: 0, Jf: 1, K: number},
			syscall.SockFilter{Code: bpfReturn, K: seccompReturnErrno | uint32(syscall.EPERM)},
		)
	}
	filters = append(filters, syscall.SockFilter{Code: bpfReturn, K: seccompReturnAllow})
	program := syscall.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter, uintptr(unsafe.Pointer(&program)), 0, 0, 0); errno != 0 {
		return errors.New("seccomp restriction failed")
	}
	return nil
}

func seccompPolicy(architecture string) (uint32, uint32, []uint32, []uint32, bool) {
	// The deny list covers networking plus namespace, mount, kernel/module,
	// descriptor-stealing, tracing, and cross-process memory escape surfaces.
	switch architecture {
	case "amd64":
		return 0xc000003e, 56, []uint32{
				41, 42, 43, 44, 45, 46, 47, 49, 50, 53, 288, 299, 307,
				101, 155, 165, 166, 175, 176, 246, 248, 249, 250, 272,
				298, 304, 308, 310, 311, 313, 321, 323, 425, 426, 427, 438,
				16, 62, 109, 112, 129, 200, 234, 297, 302, 424, 440,
			}, []uint32{
				90, 91, 92, 93, 94, 132, 188, 189, 190, 197, 198, 199,
				235, 260, 261, 268, 280,
			}, true
	case "arm64":
		return 0xc00000b7, 220, []uint32{
				198, 199, 200, 201, 202, 203, 206, 207, 211, 212, 242, 243, 269,
				117, 39, 40, 41, 104, 105, 106, 217, 218, 219, 97,
				241, 265, 268, 270, 271, 273, 280, 282, 425, 426, 427, 438,
				29, 129, 130, 131, 138, 154, 157, 240, 261, 424, 440,
			}, []uint32{
				5, 6, 7, 14, 15, 16, 52, 53, 54, 88,
			}, true
	default:
		return 0, 0, nil, nil, false
	}
}

func sandboxSelfTest(workspace string, systemReadRoots []string) error {
	sibling := filepath.Join(filepath.Dir(workspace), "sibling-secret")
	if err := os.WriteFile(sibling, []byte("secret"), 0o600); err != nil {
		return err
	}
	symlink := filepath.Join(workspace, "sibling-link")
	if err := os.Symlink(sibling, symlink); err != nil {
		return err
	}
	if err := applyPlatformSandbox(workspace, AccessWrite, systemReadRoots); err != nil {
		return err
	}
	inside := filepath.Join(workspace, "probe")
	if err := os.WriteFile(inside, []byte("ok"), 0o600); err != nil {
		return errors.New("workspace write was denied")
	}
	if _, err := os.ReadFile(inside); err != nil {
		return errors.New("workspace read was denied")
	}
	child := execCommand("/bin/sh", "-c", "printf child-ok > child-probe")
	child.Dir = workspace
	child.Stdin = strings.NewReader("")
	child.Stdout = io.Discard
	child.Stderr = io.Discard
	if err := child.Run(); err != nil {
		return errors.New("sandboxed child execution failed")
	}
	if content, err := os.ReadFile(filepath.Join(workspace, "child-probe")); err != nil || string(content) != "child-ok" {
		return errors.New("sandboxed child result is invalid")
	}
	if err := os.WriteFile(sibling, []byte("changed"), 0o600); err == nil {
		return errors.New("sibling path remained writable")
	}
	for _, path := range []string{sibling, symlink, "/proc/1/environ"} {
		if file, err := os.Open(path); err == nil {
			file.Close()
			return errors.New("restricted path remained readable")
		}
	}
	for _, path := range []string{"/auth", "/config", "/state"} {
		if _, err := os.Stat(path); err == nil {
			if file, openErr := os.Open(path); openErr == nil {
				file.Close()
				return errors.New("secret root remained readable")
			}
		}
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.Close(fd)
		return errors.New("network socket remained available")
	}
	if !errors.Is(err, syscall.EPERM) {
		return errors.New("network isolation check failed")
	}
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.Close(pair[0])
		syscall.Close(pair[1])
		return errors.New("local socket pair remained available")
	}
	if !errors.Is(err, syscall.EPERM) {
		return errors.New("local socket isolation check failed")
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_UNSHARE, 0x40000000, 0, 0); errno != syscall.EPERM {
		return errors.New("namespace isolation check failed")
	}
	return nil
}

func enterWorkspaceDirectory(workspace, relative string) error {
	fd, err := openRelativeDirectory(workspace, relative)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if syscall.Fchdir(fd) != nil {
		return errors.New("working directory rejected")
	}
	return nil
}

type secureChange struct {
	change   FileChange
	parentFD int
	base     string
}

func applySecureFileChanges(workspace string, changes []FileChange) ([]FileChangeResult, error) {
	prepared := make([]secureChange, 0, len(changes))
	defer func() {
		for _, item := range prepared {
			syscall.Close(item.parentFD)
		}
	}()
	for _, change := range changes {
		parent, base := filepath.Split(change.Path)
		parent = strings.TrimSuffix(parent, string(filepath.Separator))
		if parent == "" {
			parent = "."
		}
		parentFD, err := openRelativeDirectory(workspace, parent)
		if err != nil || !matchesExpectedAt(parentFD, base, change.ExpectedSHA256) {
			if err == nil {
				syscall.Close(parentFD)
			}
			return nil, errors.New("file precondition rejected")
		}
		prepared = append(prepared, secureChange{change: change, parentFD: parentFD, base: base})
	}
	completed := make([]FileChangeResult, 0, len(prepared))
	for _, item := range prepared {
		var err error
		if item.change.Operation == FileDelete {
			err = syscall.Unlinkat(item.parentFD, item.base)
		} else {
			err = atomicWriteAt(item.parentFD, item.base, item.change.Content)
		}
		if err != nil {
			return completed, errors.New("file operation failed")
		}
		completed = append(completed, FileChangeResult{Path: item.change.Path, Operation: item.change.Operation})
	}
	return completed, nil
}

func openRelativeDirectory(workspace, relative string) (int, error) {
	current, err := syscall.Open(workspace, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return -1, errors.New("workspace rejected")
	}
	if relative == "." {
		return current, nil
	}
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		next, openErr := syscall.Openat(current, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		syscall.Close(current)
		if openErr != nil {
			return -1, errors.New("workspace path rejected")
		}
		current = next
	}
	return current, nil
}

func matchesExpectedAt(parentFD int, base string, expected *string) bool {
	fd, err := syscall.Openat(parentFD, base, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if expected == nil {
		if err == nil {
			syscall.Close(fd)
		}
		return errors.Is(err, syscall.ENOENT)
	}
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(fd), "")
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, MaximumFileBytes+1))
	if err != nil || len(content) > MaximumFileBytes {
		return false
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]) == *expected
}

func atomicWriteAt(parentFD int, base string, content []byte) error {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporary := ".agent-tool-" + hex.EncodeToString(random[:])
	fd, err := syscall.Openat(parentFD, temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "")
	cleanup := true
	defer func() {
		file.Close()
		if cleanup {
			_ = syscall.Unlinkat(parentFD, temporary)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syscall.Renameat(parentFD, temporary, parentFD, base); err != nil {
		return err
	}
	cleanup = false
	return syscall.Fsync(parentFD)
}

var execCommand = exec.Command
