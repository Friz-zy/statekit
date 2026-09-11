package selinux

// Booleans port: saltstack/salt/modules/selinux.py @ pinned revision.
// Upstream reads booleans from `semanage boolean --list` (not the getsebool
// binary) and mutates them through `setsebool [-P] boolean value` or one
// `setsebool [-P] name=value ...` invocation for setsebools.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

type ListSeboolArgs struct{}

type listSeboolFunc struct {
	linuxOnly
}

func (listSeboolFunc) Name() string { return "selinux.list_sebool" }
func (listSeboolFunc) Args() any    { return ListSeboolArgs{} }
func (listSeboolFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return listBooleans(ctx, rt)
}

// listBooleans backs list_sebool and getsebool. It mirrors the upstream
// column parse: State=comps[1][1:], Default=comps[3][:-1], Description=
// " ".join(comps[4:]), with the header row dropped and blank lines skipped.
func listBooleans(ctx context.Context, rt *runtime.Runtime) (map[string]any, error) {
	if err := whichGuard("semanage"); err != nil {
		return nil, err
	}
	res := rt.Runner.Run(ctx, runtime.Command("semanage", "boolean", "--list"))
	if res.Err != nil {
		return nil, res.Err
	}
	ret := map[string]any{}
	for i, line := range strings.Split(string(res.Stdout), "\n") {
		if i == 0 {
			continue // bdata[1:]: drop the header row
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		comps := strings.Fields(line)
		if len(comps) < 4 {
			// Python indexes comps[1]/comps[3] and would raise IndexError.
			return nil, fmt.Errorf("malformed semanage boolean line %d: %q", i+1, line)
		}
		ret[comps[0]] = map[string]any{
			"State":       comps[1][1:],
			"Default":     comps[3][:len(comps[3])-1],
			"Description": strings.Join(comps[4:], " "),
		}
	}
	return ret, nil
}

type GetseboolArgs struct {
	Boolean string `statekit:"required,name=boolean"`
}

type getseboolFunc struct {
	linuxOnly
}

func (getseboolFunc) Name() string { return "selinux.getsebool" }
func (getseboolFunc) Args() any    { return GetseboolArgs{} }
func (getseboolFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetseboolArgs)
	booleans, err := listBooleans(ctx, rt)
	if err != nil {
		return nil, err
	}
	if entry, ok := booleans[a.Boolean]; ok {
		return entry, nil
	}
	return map[string]any{}, nil // list_sebool().get(boolean, {})
}

type SetseboolArgs struct {
	Boolean string `statekit:"required,name=boolean"`
	Value   string `statekit:"required"`
	Persist bool   `statekit:"name=persist"`
}

type setseboolFunc struct {
	linuxOnly
}

func (setseboolFunc) Name() string { return "selinux.setsebool" }
func (setseboolFunc) Args() any    { return SetseboolArgs{} }
func (setseboolFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetseboolArgs)
	if err := whichGuard("setsebool"); err != nil {
		return nil, err
	}
	if err := validateArgRunes("boolean", a.Boolean); err != nil {
		return nil, err
	}
	if err := validateArgRunes("value", a.Value); err != nil {
		return nil, err
	}
	// Salt: setsebool -P 'boolean' 'value' (shlex keeps one argv element per
	// quoted token); values pass through unvalidated for the tool to judge.
	argv := []string{"setsebool"}
	if a.Persist {
		argv = append(argv, "-P")
	}
	argv = append(argv, a.Boolean, a.Value)
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return nil, res.Err
	}
	return res.ExitCode == 0, nil // not cmd.retcode(...)
}

type SetseboolsArgs struct {
	Pairs   map[string]string `statekit:"required,name=pairs"`
	Persist bool              `statekit:"name=persist"`
}

type setseboolsFunc struct {
	linuxOnly
}

func (setseboolsFunc) Name() string { return "selinux.setsebools" }
func (setseboolsFunc) Args() any    { return SetseboolsArgs{} }
func (setseboolsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetseboolsArgs)
	if err := whichGuard("setsebool"); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(a.Pairs))
	for name := range a.Pairs {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic argv (Python relies on dict order)
	argv := []string{"setsebool"}
	if a.Persist {
		argv = append(argv, "-P")
	}
	for _, name := range names {
		if err := validateArgRunes("boolean", name); err != nil {
			return nil, err
		}
		if err := validateArgRunes("value", a.Pairs[name]); err != nil {
			return nil, err
		}
		argv = append(argv, name+"="+a.Pairs[name])
	}
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return nil, res.Err
	}
	return res.ExitCode == 0, nil
}
