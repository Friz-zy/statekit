// Package npm wraps the standard npm CLI.
//
// Reference: saltstack/salt/modules/npm.py @ pinned revision (reduced).
package npm

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

func run(ctx context.Context, rt *runtime.Runtime, argv ...string) (string, error) {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return "", res.Err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("npm exited with code %d: %s",
			res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return string(res.Stdout), nil
}

type InstallArgs struct {
	Pkg     string `statekit:"name=pkg"`
	Cwd     string `statekit:"name=dir"`
	Global  bool   `statekit:"name=global"`
	RunSync bool   `statekit:"name=run_sync"`
}

type installFunc struct{}

func (installFunc) Name() string { return "npm.install" }
func (installFunc) Args() any    { return InstallArgs{} }
func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InstallArgs)
	argv := []string{"npm", "install"}
	if a.Global {
		argv = append(argv, "--global")
	}
	if a.RunSync || a.Pkg == "" {
		argv = append(argv, "--save")
	}
	if a.Pkg != "" {
		argv = append(argv, a.Pkg)
	}
	cmd := runtime.Command(argv...)
	if a.Cwd != "" {
		cmd.Dir = a.Cwd
	}
	res := rt.Runner.Run(ctx, cmd)
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("npm exited with code %d: %s",
			res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return true, nil
}

type UninstallArgs struct {
	Pkg    string `statekit:"required,name=pkg"`
	Cwd    string `statekit:"name=dir"`
	Global bool   `statekit:"name=global"`
}

type uninstallFunc struct{}

func (uninstallFunc) Name() string { return "npm.uninstall" }
func (uninstallFunc) Args() any    { return UninstallArgs{} }
func (uninstallFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*UninstallArgs)
	argv := []string{"npm", "uninstall"}
	if a.Global {
		argv = append(argv, "--global")
	}
	argv = append(argv, a.Pkg)
	cmd := runtime.Command(argv...)
	if a.Cwd != "" {
		cmd.Dir = a.Cwd
	}
	res := rt.Runner.Run(ctx, cmd)
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("npm exited with code %d: %s",
			res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return true, nil
}

type ListArgs struct {
	Cwd    string `statekit:"name=dir"`
	Global bool   `statekit:"name=global"`
}

type listFunc struct{}

func (listFunc) Name() string { return "npm.list" }
func (listFunc) Args() any    { return ListArgs{} }
func (listFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListArgs)
	argv := []string{"npm", "list", "--json"}
	if a.Global {
		argv = append(argv, "--global")
	}
	cmd := runtime.Command(argv...)
	if a.Cwd != "" {
		cmd.Dir = a.Cwd
	}
	res := rt.Runner.Run(ctx, cmd)
	out := strings.TrimSpace(string(res.Stdout))
	if res.ExitCode != 0 && out == "" {
		return nil, fmt.Errorf("npm list exited with code %d", res.ExitCode)
	}
	return out, nil // raw JSON document from npm
}

// Register installs all npm-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{installFunc{}, uninstallFunc{}, listFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
