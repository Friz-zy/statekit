// Package environ implements Salt-compatible environment variable management.
//
// Reference: saltstack/salt/modules/environ.py @ pinned revision. Persistent
// values live in /etc/environment through the runtime FileSystem.
package environ

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

const etcEnvironment = "/etc/environment"

func readEnvironment(rt *runtime.Runtime) map[string]string {
	values := map[string]string{}
	data, err := rt.FS.ReadFile(etcEnvironment)
	if err != nil {
		return values
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if key, value, ok := strings.Cut(line, "="); ok {
			values[strings.TrimSpace(key)] = strings.Trim(value, `"`)
		}
	}
	return values
}

type getArgs struct {
	Name string `statekit:"required"`
}

type getFunc struct{}

func (getFunc) Name() string { return "environ.get" }
func (getFunc) Args() any    { return getArgs{} }
func (getFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*getArgs)
	if value, ok := readEnvironment(rt)[a.Name]; ok {
		return value, nil
	}
	return "", nil
}

type setArgs struct {
	Name  string `statekit:"required"`
	Value string `statekit:"required,name=value"`
}

type setFunc struct{}

func (setFunc) Name() string { return "environ.set" }
func (setFunc) Args() any    { return setArgs{} }
func (setFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*setArgs)
	lines := []string{}
	replaced := false
	if data, err := rt.FS.ReadFile(etcEnvironment); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			key := ""
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				if k, _, ok := strings.Cut(trimmed, "="); ok {
					key = strings.TrimSpace(k)
				}
			}
			if key == a.Name {
				if !replaced {
					lines = append(lines, fmt.Sprintf("%s=%q", a.Name, a.Value))
					replaced = true
				}
				continue
			}
			lines = append(lines, line)
		}
	}
	if !replaced {
		lines = append(lines, fmt.Sprintf("%s=%q", a.Name, a.Value))
	}
	out := strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
	mode := fs.FileMode(0o600)
	if info, err := rt.FS.Stat(etcEnvironment); err == nil {
		mode = info.Mode().Perm()
	}
	if err := rt.FS.WriteFile(etcEnvironment, []byte(out), mode); err != nil {
		return nil, err
	}
	return true, nil
}

// Register installs all environ-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{getFunc{}, setFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
