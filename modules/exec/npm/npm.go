// Package npm wraps the standard npm CLI.
//
// Reference: saltstack/salt/modules/npm.py @ pinned revision. The cache
// trio (cache_path/cache_list/cache_clean) ports the upstream argv and
// return shapes; the SUDO_UID/SUDO_USER runas seeding degrades to explicit
// env vars under StateKit's single-user model (documented divergence).
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

type CacheCleanArgs struct {
	Path  *string        `statekit:"name=path"`
	Runas *string        `statekit:"name=runas"`
	Env   map[string]any `statekit:"name=env"`
	Force bool           `statekit:"name=force"`
}

type cacheCleanFunc struct{}

// cacheEnv mirrors the SUDO_UID/SUDO_USER env seeding upstream performs
// for runas; StateKit's single-user model keeps only explicit env vars
// (documented divergence).
func cacheEnv(env map[string]any) []string {
	if env == nil {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sortStrings(keys)
	var out []string
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s=%v", k, env[k]))
	}
	return out
}

func sortStrings(items []string) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j] < items[j-1]; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

func (cacheCleanFunc) Name() string { return "npm.cache_clean" }
func (cacheCleanFunc) Args() any    { return CacheCleanArgs{} }
func (cacheCleanFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CacheCleanArgs)
	argv := []string{"npm", "cache", "clean"}
	if a.Path != nil && *a.Path != "" {
		argv = append(argv, *a.Path)
	}
	if a.Force {
		argv = append(argv, "--force")
	}
	cmd := runtime.Command(argv...)
	cmd.Env = cacheEnv(a.Env)
	res := rt.Runner.Run(ctx, cmd)
	if res.ExitCode != 0 {
		return false, nil
	}
	return true, nil
}

type CacheListArgs struct {
	Path  *string        `statekit:"name=path"`
	Runas *string        `statekit:"name=runas"`
	Env   map[string]any `statekit:"name=env"`
}

type cacheListFunc struct{}

func (cacheListFunc) Name() string { return "npm.cache_list" }
func (cacheListFunc) Args() any    { return CacheListArgs{} }
func (cacheListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CacheListArgs)
	argv := []string{"npm", "cache", "ls"}
	if a.Path != nil && *a.Path != "" {
		argv = append(argv, *a.Path)
	}
	cmd := runtime.Command(argv...)
	cmd.Env = cacheEnv(a.Env)
	res := rt.Runner.Run(ctx, cmd)
	stderr := strings.TrimSpace(string(res.Stderr))
	if res.ExitCode != 0 && stderr != "" {
		return nil, fmt.Errorf("%s", stderr)
	}
	return string(res.Stdout), nil
}

type CachePathArgs struct {
	Runas *string        `statekit:"name=runas"`
	Env   map[string]any `statekit:"name=env"`
}

type cachePathFunc struct{}

func (cachePathFunc) Name() string { return "npm.cache_path" }
func (cachePathFunc) Args() any    { return CachePathArgs{} }
func (cachePathFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CachePathArgs)
	cmd := runtime.Command("npm", "config", "get", "cache")
	cmd.Env = cacheEnv(a.Env)
	res := rt.Runner.Run(ctx, cmd)
	if stdout := strings.TrimSpace(string(res.Stdout)); stdout != "" {
		return stdout, nil
	}
	return string(res.Stderr), nil
}

// Register installs all npm-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{installFunc{}, uninstallFunc{}, listFunc{},
		cacheCleanFunc{}, cacheListFunc{}, cachePathFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
