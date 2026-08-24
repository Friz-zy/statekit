// Command statekit is the portable StateKit binary.
package main

import (
	"os"

	"github.com/friz-zy/statekit/internal/bootstrap"
	"github.com/friz-zy/statekit/internal/cli"
	"github.com/friz-zy/statekit/internal/runtime"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

func buildRuntime() (*runtime.Runtime, error) {
	return bootstrap.BuildRuntime()
}

func main() {
	os.Exit(cli.NewApp(version, buildRuntime).Run(os.Args[1:]))
}
