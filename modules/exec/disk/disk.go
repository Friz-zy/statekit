// Package disk implements Salt-compatible storage inspection.
//
// Reference: saltstack/salt/modules/disk.py @ pinned revision, reduced to
// local statfs-based usage reporting.
package disk

import (
	"context"
	"fmt"
	"syscall"

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
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return nil, fmt.Errorf("could not read filesystem usage for %q: %w", path, err)
	}
	total := int64(stat.Blocks) * int64(stat.Bsize)
	free := int64(stat.Bfree) * int64(stat.Bsize)
	available := int64(stat.Bavail) * int64(stat.Bsize)
	used := total - free

	entry := map[string]any{
		"filesystem": path,
		"1K-blocks":  fmt.Sprintf("%d", total/1024),
		"used":       fmt.Sprintf("%d", used/1024),
		"available":  fmt.Sprintf("%d", available/1024),
	}
	if total > 0 {
		entry["use%"] = fmt.Sprintf("%.0f%%", float64(used)/float64(total)*100)
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
	var stat syscall.Statfs_t
	if err := syscall.Statfs(a.Path, &stat); err != nil {
		return nil, err
	}
	total := float64(stat.Blocks) * float64(stat.Bsize)
	if total == 0 {
		return 0.0, nil
	}
	used := float64(stat.Blocks-stat.Bfree) * float64(stat.Bsize)
	return used / total * 100, nil
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
