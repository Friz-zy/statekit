// Package virtualenv manages Python virtual environments via python -m venv.
//
// Reference: saltstack/salt/modules/virtualenv_mod.py @ pinned revision.
package virtualenv

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

type CreateArgs struct {
	Path               string `statekit:"required,name=venv_dir"`
	Bin                string `statekit:"name=python"`
	SystemSitePackages bool   `statekit:"name=system_site_packages"`
}

type createFunc struct{}

func (createFunc) Name() string { return "virtualenv.create" }
func (createFunc) Args() any    { return CreateArgs{} }
func (createFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CreateArgs)
	interpreter := a.Bin
	if interpreter == "" {
		interpreter = "python3"
	}
	argv := []string{interpreter, "-m", "venv"}
	if a.SystemSitePackages {
		argv = append(argv, "--system-site-packages")
	}
	argv = append(argv, a.Path)
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("venv creation exited with code %d: %s",
			res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return map[string]any{"path": a.Path}, nil
}

// Register installs all virtualenv-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	return reg.Register(createFunc{})
}
