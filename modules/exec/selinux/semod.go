package selinux

// SELinux module management port: saltstack/salt/modules/selinux.py @
// pinned revision. Upstream drives the semodule binary (--list-modules=full,
// --enable, --disable, --install, --remove); install_semod resolves salt://
// sources through the cp.cache_file delegate like __salt__ would.

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
	cpmod "github.com/friz-zy/statekit/modules/exec/cp"
)

type ListSemodArgs struct{}

type listSemodFunc struct {
	linuxOnly
}

func (listSemodFunc) Name() string { return "selinux.list_semod" }
func (listSemodFunc) Args() any    { return ListSemodArgs{} }
func (listSemodFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return listSemodules(ctx, rt)
}

// listSemodules backs list_semod and getsemod. A full listing row is
// "<priority> <name> pp [disabled]": four columns mean the module is
// disabled. Version stays nil exactly like the pinned source.
func listSemodules(ctx context.Context, rt *runtime.Runtime) (map[string]any, error) {
	if err := whichGuard("semodule"); err != nil {
		return nil, err
	}
	res := rt.Runner.Run(ctx, runtime.Command("semodule", "--list-modules=full"))
	if res.Err != nil {
		return nil, res.Err
	}
	ret := map[string]any{}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		comps := strings.Fields(line)
		if len(comps) < 2 {
			// Python indexes comps[1] and would raise IndexError.
			return nil, fmt.Errorf("malformed semodule listing line: %q", line)
		}
		ret[comps[1]] = map[string]any{"Enabled": len(comps) != 4, "Version": nil}
	}
	return ret, nil
}

type GetsemodArgs struct {
	Module string `statekit:"required,name=module"`
}

type getsemodFunc struct {
	linuxOnly
}

func (getsemodFunc) Name() string { return "selinux.getsemod" }
func (getsemodFunc) Args() any    { return GetsemodArgs{} }
func (getsemodFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetsemodArgs)
	modules, err := listSemodules(ctx, rt)
	if err != nil {
		return nil, err
	}
	if entry, ok := modules[a.Module]; ok {
		return entry, nil
	}
	return map[string]any{}, nil // list_semod().get(module, {})
}

type SetsemodArgs struct {
	Module string `statekit:"required,name=module"`
	State  string `statekit:"required"`
}

type setsemodFunc struct {
	linuxOnly
}

func (setsemodFunc) Name() string { return "selinux.setsemod" }
func (setsemodFunc) Args() any    { return SetsemodArgs{} }
func (setsemodFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetsemodArgs)
	if err := whichGuard("semodule"); err != nil {
		return nil, err
	}
	if err := validateArgRunes("module", a.Module); err != nil {
		return nil, err
	}
	var flag string
	switch strings.ToLower(a.State) {
	case "enabled":
		flag = "--enable"
	case "disabled":
		flag = "--disable"
	default:
		return nil, fmt.Errorf("Invalid state %s", a.State)
	}
	res := rt.Runner.Run(ctx, runtime.Command("semodule", flag, a.Module))
	if res.Err != nil {
		return nil, res.Err
	}
	return res.ExitCode == 0, nil
}

type InstallSemodArgs struct {
	ModulePath string `statekit:"required,name=module_path"`
}

type installSemodFunc struct {
	linuxOnly
}

func (installSemodFunc) Name() string { return "selinux.install_semod" }
func (installSemodFunc) Args() any    { return InstallSemodArgs{} }
func (installSemodFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InstallSemodArgs)
	if err := whichGuard("semodule"); err != nil {
		return nil, err
	}
	path := a.ModulePath
	if strings.HasPrefix(path, "salt://") {
		// __salt__["cp.cache_file"]: local-only StateKit surfaces the
		// master-backed scheme as an UnsupportedError by design.
		cachedRaw, err := rt.Exec.Call(ctx, rt, "cp.cache_file", &cpmod.CacheFileArgs{Path: path})
		if err != nil {
			return nil, err
		}
		cached, ok := cachedRaw.(string)
		if !ok {
			return nil, fmt.Errorf("module path %q could not be cached", path)
		}
		path = cached
	}
	if err := validateArgRunes("module_path", path); err != nil {
		return nil, err
	}
	res := rt.Runner.Run(ctx, runtime.Command("semodule", "--install", path))
	if res.Err != nil {
		return nil, res.Err
	}
	return res.ExitCode == 0, nil
}

type RemoveSemodArgs struct {
	Module string `statekit:"required,name=module"`
}

type removeSemodFunc struct {
	linuxOnly
}

func (removeSemodFunc) Name() string { return "selinux.remove_semod" }
func (removeSemodFunc) Args() any    { return RemoveSemodArgs{} }
func (removeSemodFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RemoveSemodArgs)
	if err := whichGuard("semodule"); err != nil {
		return nil, err
	}
	if err := validateArgRunes("module", a.Module); err != nil {
		return nil, err
	}
	res := rt.Runner.Run(ctx, runtime.Command("semodule", "--remove", a.Module))
	if res.Err != nil {
		return nil, res.Err
	}
	return res.ExitCode == 0, nil
}
