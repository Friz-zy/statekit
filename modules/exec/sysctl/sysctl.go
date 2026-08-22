// Package sysctl implements Salt-compatible kernel parameter management on
// Linux.
//
// Reference: saltstack/salt/modules/linux_sysctl.py @ pinned revision.
package sysctl

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

const defaultConfig = "/etc/sysctl.conf"

type showArgs struct {
	Name string `statekit:"required"`
}

type showFunc struct{}

func (showFunc) Name() string { return "sysctl.show" }
func (showFunc) Args() any    { return showArgs{} }
func (showFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*showArgs)
	procPath := "/proc/sys/" + strings.ReplaceAll(a.Name, ".", "/")
	data, err := rt.FS.ReadFile(procPath)
	if err != nil {
		return nil, fmt.Errorf("could not read sysctl value for %q: %w", a.Name, err)
	}
	return strings.TrimSpace(string(data)), nil
}

type assignArgs struct {
	Name    string `statekit:"required"`
	Value   string `statekit:"required,name=value"`
	Config  string `statekit:"name=config"`
	Persist bool   `statekit:"name=persist"`
}

type assignFunc struct{}

func (assignFunc) Name() string { return "sysctl.assign" }
func (assignFunc) Args() any    { return assignArgs{} }
func (assignFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*assignArgs)
	res := rt.Runner.Run(ctx, runtime.Command("sysctl", "-w",
		fmt.Sprintf("%s=%s", a.Name, a.Value)))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("sysctl -w exited with code %d: %s", res.ExitCode, res.Stderr)
	}
	if a.Persist {
		config := a.Config
		if config == "" {
			config = defaultConfig
		}
		if err := persistSetting(rt, config, a.Name, a.Value); err != nil {
			return nil, err
		}
	}
	return true, nil
}

// persistSetting upserts one key=value line in the config file, preserving
// all other content and ordering.
func persistSetting(rt *runtime.Runtime, configPath, name, value string) error {
	data, _ := rt.FS.ReadFile(configPath)
	lines := []string{}
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if !found && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			if existing, _, ok := strings.Cut(trimmed, "="); ok &&
				strings.TrimSpace(existing) == name {
				lines = append(lines, name+" = "+value)
				found = true
				continue
			}
		}
		lines = append(lines, line)
	}
	if !found {
		lines = append(lines, name+" = "+value)
	}
	out := strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
	mode := fs.FileMode(0o600)
	if info, err := rt.FS.Stat(configPath); err == nil {
		mode = info.Mode().Perm()
	}
	return rt.FS.WriteFile(configPath, []byte(out), mode)
}

type defaultConfigArgs struct{}

type defaultConfigFunc struct{}

func (defaultConfigFunc) Name() string { return "sysctl.default_config" }
func (defaultConfigFunc) Args() any    { return defaultConfigArgs{} }
func (defaultConfigFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return path.Clean(defaultConfig), nil
}

// Register installs all sysctl-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{showFunc{}, assignFunc{}, defaultConfigFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
