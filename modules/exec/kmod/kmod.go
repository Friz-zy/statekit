// Package kmod implements Salt-compatible kernel module management on Linux.
//
// Reference: saltstack/salt/modules/kmod.py @ pinned revision. Loaded-module
// inspection reads /proc/modules directly; load/unload delegate to
// modprobe/modprobe -r through the central Runner.
package kmod

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

const procModules = "/proc/modules"

func loadedModules(rt *runtime.Runtime) []string {
	data, err := rt.FS.ReadFile(procModules)
	if err != nil {
		return nil
	}
	names := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			names = append(names, fields[0])
		}
	}
	return names
}

type lsmodArgs struct{}

type lsmodFunc struct{}

func (lsmodFunc) Name() string { return "kmod.lsmod" }
func (lsmodFunc) Args() any    { return lsmodArgs{} }
func (lsmodFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	modules := loadedModules(rt)
	if modules == nil {
		return nil, fmt.Errorf("could not read %s", procModules)
	}
	return modules, nil
}

type isLoadedArgs struct {
	Mod string `statekit:"required,name=mod"`
}

type isLoadedFunc struct{}

func (isLoadedFunc) Name() string { return "kmod.is_loaded" }
func (isLoadedFunc) Args() any    { return isLoadedArgs{} }
func (isLoadedFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*isLoadedArgs)
	for _, name := range loadedModules(rt) {
		if name == a.Mod {
			return true, nil
		}
	}
	return false, nil
}

func runOK(ctx context.Context, rt *runtime.Runtime, argv ...string) error {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return res.Err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s exited with code %d: %s", argv[0], res.ExitCode, res.Stderr)
	}
	return nil
}

func done(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return true, nil
}

type loadArgs struct {
	Mod     string `statekit:"required,name=mod"`
	Persist bool   `statekit:"name=persist"`
}

type loadFunc struct{}

func (loadFunc) Name() string { return "kmod.load" }
func (loadFunc) Args() any    { return loadArgs{} }
func (loadFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*loadArgs)
	if err := runOK(ctx, rt, "modprobe", a.Mod); err != nil {
		return nil, err
	}
	return done(nil)
}

type removeArgs struct {
	Mod     string `statekit:"required,name=mod"`
	Persist bool   `statekit:"name=persist"`
}

type removeFunc struct{}

func (removeFunc) Name() string { return "kmod.remove" }
func (removeFunc) Args() any    { return removeArgs{} }
func (removeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*removeArgs)
	if err := runOK(ctx, rt, "modprobe", "-r", a.Mod); err != nil {
		return nil, err
	}
	return done(nil)
}

// Register installs all kmod-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{lsmodFunc{}, isLoadedFunc{}, loadFunc{}, removeFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
