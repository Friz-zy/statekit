// Package pip wraps the standard pip CLI.
//
// Reference: saltstack/salt/modules/pip.py @ pinned revision (reduced).
package pip

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

func run(ctx context.Context, rt *runtime.Runtime, cwd string, argv ...string) (string, error) {
	cmd := runtime.Command(argv...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	res := rt.Runner.Run(ctx, cmd)
	if res.Err != nil {
		return "", res.Err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("%s exited with code %d: %s",
			argv[0], res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return string(res.Stdout), nil
}

type ListArgs struct {
	Bin string `statekit:"name=bin"`
	Cwd string `statekit:"name=cwd"`
}

type listFunc struct{}

func (listFunc) Name() string { return "pip.list" }
func (listFunc) Args() any    { return ListArgs{} }
func (listFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListArgs)
	bin := a.Bin
	if bin == "" {
		bin = "pip3"
	}
	out, err := run(ctx, rt, a.Cwd, bin, "list", "--format=freeze")
	if err != nil {
		return nil, err
	}
	packages := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		name, version, ok := strings.Cut(strings.TrimSpace(line), "==")
		if ok {
			packages[name] = version
		}
	}
	return packages, nil
}

type InstallArgs struct {
	Pkg     string `statekit:"required,name=pkgs"`
	Bin     string `statekit:"name=bin"`
	Cwd     string `statekit:"name=cwd"`
	Upgrade bool   `statekit:"name=upgrade"`
}

type installFunc struct{}

func (installFunc) Name() string { return "pip.install" }
func (installFunc) Args() any    { return InstallArgs{} }
func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InstallArgs)
	bin := a.Bin
	if bin == "" {
		bin = "pip3"
	}
	argv := []string{bin, "install"}
	if a.Upgrade {
		argv = append(argv, "--upgrade")
	}
	argv = append(argv, strings.Fields(a.Pkg)...)
	if _, err := run(ctx, rt, a.Cwd, argv...); err != nil {
		return nil, err
	}
	return true, nil
}

type UninstallArgs struct {
	Pkg string `statekit:"required,name=pkgs"`
	Bin string `statekit:"name=bin"`
	Cwd string `statekit:"name=cwd"`
}

type uninstallFunc struct{}

func (uninstallFunc) Name() string { return "pip.uninstall" }
func (uninstallFunc) Args() any    { return UninstallArgs{} }
func (uninstallFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*UninstallArgs)
	bin := a.Bin
	if bin == "" {
		bin = "pip3"
	}
	argv := append([]string{bin, "uninstall", "-y"}, strings.Fields(a.Pkg)...)
	if _, err := run(ctx, rt, a.Cwd, argv...); err != nil {
		return nil, err
	}
	return true, nil
}

// Register installs all pip-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{listFunc{}, installFunc{}, uninstallFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
