// Package rsync wraps the standard rsync binary.
//
// Reference: saltstack/salt/modules/rsync.py @ pinned revision.
package rsync

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

type SyncArgs struct {
	Src     string   `statekit:"required,name=src"`
	Dst     string   `statekit:"required,name=dst"`
	Delete  bool     `statekit:"name=delete"`
	Archive bool     `statekit:"name=archive"`
	Opts    []string `statekit:"name=options"`
}

type syncFunc struct{}

func (syncFunc) Name() string { return "rsync.sync" }
func (syncFunc) Args() any    { return SyncArgs{} }
func (syncFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SyncArgs)
	argv := []string{"rsync"}
	useArchive := a.Archive || len(a.Opts) == 0
	if useArchive {
		argv = append(argv, "-a")
	}
	if a.Delete {
		argv = append(argv, "--delete")
	}
	argv = append(argv, a.Opts...)
	argv = append(argv, a.Src, a.Dst)

	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("rsync exited with code %d: %s",
			res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return map[string]any{
		"stdout": strings.TrimRight(string(res.Stdout), "\n"),
	}, nil
}

// Register installs all rsync-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	return reg.Register(syncFunc{})
}
