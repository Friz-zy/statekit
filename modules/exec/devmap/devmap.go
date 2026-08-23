// Package devmap implements Salt-compatible device-mapper multipath
// inspection through the multipath tool.
//
// Reference: saltstack/salt/modules/devmap.py @ pinned revision.
package devmap

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts every function of this module to linux; device-mapper
// multipath is a Linux contract.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

type MultipathListArgs struct{}

type multipathListFunc struct {
	linuxOnly
}

func (multipathListFunc) Name() string { return "devmap.multipath_list" }
func (multipathListFunc) Args() any    { return MultipathListArgs{} }
func (multipathListFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	res := rt.Runner.Run(ctx, runtime.Command("multipath", "-l"))
	if res.Err != nil {
		return nil, res.Err
	}
	return linesFromStdout(string(res.Stdout)), nil
}

// linesFromStdout splits command output like Python str.splitlines: empty
// output yields an empty list.
func linesFromStdout(out string) []string {
	out = strings.TrimRight(out, "\n")
	if out == "" {
		return []string{}
	}
	return strings.Split(out, "\n")
}

type MultipathFlushArgs struct {
	Device string `statekit:"required,name=device"`
}

type multipathFlushFunc struct {
	linuxOnly
}

func (multipathFlushFunc) Name() string { return "devmap.multipath_flush" }
func (multipathFlushFunc) Args() any    { return MultipathFlushArgs{} }
func (multipathFlushFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*MultipathFlushArgs)
	if _, err := rt.FS.Stat(a.Device); err != nil {
		return nil, fmt.Errorf("%s does not exist", a.Device)
	}
	res := rt.Runner.Run(ctx, runtime.Command("multipath", "-f", a.Device))
	if res.Err != nil {
		return nil, res.Err
	}
	return linesFromStdout(string(res.Stdout)), nil
}

// Register installs all devmap-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{multipathListFunc{}, multipathFlushFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
