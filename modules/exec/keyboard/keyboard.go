// Package keyboard implements Salt-compatible keyboard layout management.
//
// Reference: saltstack/salt/modules/keyboard.py @ pinned revision. Layout is
// read from /etc/default/keyboard; setting updates the file and best-effort
// refreshes the console via localectl.
package keyboard

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

type GetLayoutArgs struct{}

const keyboardConfig = "/etc/default/keyboard"

type getLayoutArgs struct{}

type getLayoutFunc struct{}

func (getLayoutFunc) Name() string { return "keyboard.get_layout" }
func (getLayoutFunc) Args() any    { return getLayoutArgs{} }
func (getLayoutFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	data, err := rt.FS.ReadFile(keyboardConfig)
	if err != nil {
		return "", nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "XKBLAYOUT=") {
			return strings.Trim(strings.TrimPrefix(line, "XKBLAYOUT="), `"`), nil
		}
	}
	return "", nil
}

type SetLayoutArgs struct {
	Layout string `statekit:"required,name=layout"`
}

type setLayoutFunc struct{}

func (setLayoutFunc) Name() string { return "keyboard.set_layout" }
func (setLayoutFunc) Args() any    { return SetLayoutArgs{} }
func (setLayoutFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetLayoutArgs)
	current, err := getLayoutFunc{}.Execute(ctx, rt, &GetLayoutArgs{})
	if err == nil && current == a.Layout {
		return fmt.Sprintf("Layout %s already set", a.Layout), nil
	}

	lines := []string{}
	found := false
	if data, readErr := rt.FS.ReadFile(keyboardConfig); readErr == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "XKBLAYOUT=") {
				lines = append(lines, fmt.Sprintf("XKBLAYOUT=%q", a.Layout))
				found = true
				continue
			}
			lines = append(lines, line)
		}
	}
	if !found {
		lines = append(lines, fmt.Sprintf("XKBLAYOUT=%q", a.Layout))
	}
	mode := fs.FileMode(0o644)
	if info, statErr := rt.FS.Stat(keyboardConfig); statErr == nil {
		mode = info.Mode().Perm()
	}
	rt.FS.MkdirAll("/etc/default", 0o755)
	if err := rt.FS.WriteFile(keyboardConfig, []byte(strings.Join(lines, "\n")+"\n"), mode); err != nil {
		return nil, err
	}
	res := rt.Runner.Run(ctx, runtime.Command("localectl", "set-x11-keymap", a.Layout))
	if res.Err != nil || res.ExitCode != 0 {
		// localectl may be absent on servers; the persistent file is updated.
		return fmt.Sprintf("Layout %s written; localectl refresh skipped", a.Layout), nil
	}
	return fmt.Sprintf("Layout %s applied", a.Layout), nil
}

// Register installs all keyboard-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{getLayoutFunc{}, setLayoutFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
