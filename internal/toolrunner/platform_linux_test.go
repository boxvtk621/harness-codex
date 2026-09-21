//go:build linux

package toolrunner

import "syscall"

func isLinux() bool { return true }

func runEscapeProbe(mode string) int {
	var err error
	if mode == "--setpgid-probe" {
		err = syscall.Setpgid(0, 0)
	} else {
		_, err = syscall.Setsid()
	}
	if err == syscall.EPERM {
		return 0
	}
	return 1
}
