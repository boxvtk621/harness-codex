package main

import (
	"os"

	"github.com/boxvtk621/harness-codex/internal/toolrunner"
)

func main() {
	os.Exit(toolrunner.HelperMain(os.Args[1:], os.Stdin, os.Stdout))
}
