// Command statekit is the portable StateKit binary.
package main

import (
	"os"

	"github.com/friz-zy/statekit/internal/cli"
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	exectest "github.com/friz-zy/statekit/modules/exec/test"
	statetest "github.com/friz-zy/statekit/modules/state/test"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

func buildRuntime() (*runtime.Runtime, error) {
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.Detect(),
		Providers: runtime.NewProviderRegistry(),
		Runner:    process.NewRunner(),
		FS:        runtime.NewOSFileSystem(),
	}
	if err := exectest.Register(rt.Exec); err != nil {
		return nil, err
	}
	if err := statetest.Register(rt.States); err != nil {
		return nil, err
	}
	return rt, nil
}

func main() {
	os.Exit(cli.NewApp(version, buildRuntime).Run(os.Args[1:]))
}
