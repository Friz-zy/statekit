// Package disk implements Salt-compatible storage inspection.
//
// Reference: saltstack/salt/modules/disk.py @ pinned revision, reduced to
// local statfs-based usage reporting.
package disk

import (
	"context"

	"github.com/friz-zy/statekit/internal/runtime"
)

type usageArgs struct {
	Path string `statekit:"name=path"`
}

type usageFunc struct{}

func (usageFunc) Name() string { return "disk.usage" }
func (usageFunc) Args() any    { return usageArgs{} }
func (usageFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*usageArgs)
	path := a.Path
	if path == "" {
		path = "/"
	}
	entry, err := filesystemUsage(path)
	if err != nil {
		return nil, err
	}
	return map[string]any{path: entry}, nil
}

type percentArgs struct {
	Path string `statekit:"required,name=path"`
}

type percentFunc struct{}

func (percentFunc) Name() string { return "disk.percent" }
func (percentFunc) Args() any    { return percentArgs{} }
func (percentFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*percentArgs)
	return filesystemPercent(a.Path)
}

// Register installs all disk-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{usageFunc{}, percentFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
