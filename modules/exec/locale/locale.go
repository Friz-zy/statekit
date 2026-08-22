// Package locale implements Salt-compatible system locale functions.
//
// Reference: saltstack/salt/modules/localemod.py @ pinned revision.
package locale

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

type getLocaleArgs struct{}

type getLocaleFunc struct{}

func (getLocaleFunc) Name() string { return "locale.get_locale" }
func (getLocaleFunc) Args() any    { return getLocaleArgs{} }
func (getLocaleFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	res := rt.Runner.Run(ctx, runtime.Command("locale"))
	if res.Err == nil && res.ExitCode == 0 {
		for _, line := range strings.Split(string(res.Stdout), "\n") {
			if strings.HasPrefix(line, "LANG=") {
				value := strings.Trim(strings.TrimPrefix(line, "LANG="), `"`)
				return value, nil
			}
		}
	}
	return "", fmt.Errorf("could not determine system locale")
}

type setLocaleArgs struct {
	Locale string `statekit:"required"`
}

type setLocaleFunc struct{}

func (setLocaleFunc) Name() string { return "locale.set_locale" }
func (setLocaleFunc) Args() any    { return setLocaleArgs{} }
func (setLocaleFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*setLocaleArgs)
	res := rt.Runner.Run(ctx, runtime.Command("update-locale", "LANG="+a.Locale))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("update-locale exited with code %d: %s", res.ExitCode, res.Stderr)
	}
	return true, nil
}

type listAvailArgs struct{}

type listAvailFunc struct{}

func (listAvailFunc) Name() string { return "locale.list_avail" }
func (listAvailFunc) Args() any    { return listAvailArgs{} }
func (listAvailFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	res := rt.Runner.Run(ctx, runtime.Command("locale", "-a"))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("locale -a exited with code %d", res.ExitCode)
	}
	out := []string{}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

type availArgs struct {
	Locale string `statekit:"required"`
}

type availFunc struct{}

func (availFunc) Name() string { return "locale.avail" }
func (availFunc) Args() any    { return availArgs{} }
func (availFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*availArgs)
	res := rt.Runner.Run(ctx, runtime.Command("locale", "-a"))
	if res.Err != nil {
		return false, nil
	}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if strings.TrimSpace(line) == a.Locale || strings.HasPrefix(strings.TrimSpace(line), a.Locale+".") {
			return true, nil
		}
	}
	return false, nil
}

// Register installs all locale-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{getLocaleFunc{}, setLocaleFunc{}, listAvailFunc{}, availFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
