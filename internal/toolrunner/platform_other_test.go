//go:build !linux

package toolrunner

func isLinux() bool { return false }

func runEscapeProbe(string) int { return 2 }
