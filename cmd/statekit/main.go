// Command statekit is the portable StateKit binary.
package main

import (
	"os"

	"github.com/friz-zy/statekit/internal/cli"
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"

	execarchive "github.com/friz-zy/statekit/modules/exec/archive"
	execcmd "github.com/friz-zy/statekit/modules/exec/cmd"
	execcron "github.com/friz-zy/statekit/modules/exec/cron"
	execdisk "github.com/friz-zy/statekit/modules/exec/disk"
	execfile "github.com/friz-zy/statekit/modules/exec/file"
	execgroup "github.com/friz-zy/statekit/modules/exec/group"
	exechosts "github.com/friz-zy/statekit/modules/exec/hosts"
	execlocale "github.com/friz-zy/statekit/modules/exec/locale"
	execmount "github.com/friz-zy/statekit/modules/exec/mount"
	execpkg "github.com/friz-zy/statekit/modules/exec/pkg"
	execservice "github.com/friz-zy/statekit/modules/exec/service"
	execshadow "github.com/friz-zy/statekit/modules/exec/shadow"
	execstatus "github.com/friz-zy/statekit/modules/exec/status"
	execsysctl "github.com/friz-zy/statekit/modules/exec/sysctl"
	exectest "github.com/friz-zy/statekit/modules/exec/test"
	executimezone "github.com/friz-zy/statekit/modules/exec/timezone"
	execuser "github.com/friz-zy/statekit/modules/exec/user"
	statetest "github.com/friz-zy/statekit/modules/state/test"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
	serviceprovider "github.com/friz-zy/statekit/providers/service"
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

	if err := pkgprovider.Register(rt.Providers); err != nil {
		return nil, err
	}
	if err := serviceprovider.Register(rt.Providers); err != nil {
		return nil, err
	}
	for _, register := range []func(*runtime.ExecRegistry) error{
		exectest.Register,
		execcmd.Register,
		execfile.Register,
		execstatus.Register,
		execuser.Register,
		execgroup.Register,
		execshadow.Register,
		execpkg.Register,
		execservice.Register,
		execarchive.Register,
		execcron.Register,
		execdisk.Register,
		exechosts.Register,
		execlocale.Register,
		execmount.Register,
		execsysctl.Register,
		executimezone.Register,
	} {
		if err := register(rt.Exec); err != nil {
			return nil, err
		}
	}
	if err := statetest.Register(rt.States); err != nil {
		return nil, err
	}
	return rt, nil
}

func main() {
	os.Exit(cli.NewApp(version, buildRuntime).Run(os.Args[1:]))
}
