// Package group implements Salt-compatible local group inspection and
// management on Linux.
//
// Reference: saltstack/salt/modules/groupadd.py @ pinned revision.
package group

import (
	"context"
	"fmt"

	"github.com/friz-zy/statekit/internal/runtime"
	"github.com/friz-zy/statekit/internal/sysfiles"
)

const groupPath = "/etc/group"

func readGroups(rt *runtime.Runtime) []sysfiles.GroupEntry {
	data, err := rt.FS.ReadFile(groupPath)
	if err != nil {
		return nil
	}
	return sysfiles.ParseGroup(string(data))
}

func run(ctx context.Context, rt *runtime.Runtime, argv ...string) error {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return res.Err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s exited with code %d: %s", argv[0], res.ExitCode, res.Stderr)
	}
	return nil
}

func done(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return true, nil
}

type infoArgs struct {
	Name string `statekit:"required"`
}

type infoFunc struct{}

func (infoFunc) Name() string { return "group.info" }
func (infoFunc) Args() any    { return infoArgs{} }
func (infoFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*infoArgs)
	for _, entry := range readGroups(rt) {
		if entry.Name == a.Name {
			return map[string]any{
				"name":    entry.Name,
				"gid":     entry.GID,
				"members": entry.Members,
			}, nil
		}
	}
	return nil, fmt.Errorf("group %q does not exist", a.Name)
}

type listGroupsArgs struct{}

type listGroupsFunc struct{}

func (listGroupsFunc) Name() string { return "group.list_groups" }
func (listGroupsFunc) Args() any    { return listGroupsArgs{} }
func (listGroupsFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	names := []string{}
	for _, entry := range readGroups(rt) {
		names = append(names, entry.Name)
	}
	return names, nil
}

type addArgs struct {
	Name string `statekit:"required"`
	GID  string `statekit:"name=gid"`
}

type addFunc struct{}

func (addFunc) Name() string { return "group.add" }
func (addFunc) Args() any    { return addArgs{} }
func (addFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*addArgs)
	argv := []string{"groupadd"}
	if a.GID != "" {
		argv = append(argv, "-g", a.GID)
	}
	argv = append(argv, a.Name)
	return done(run(ctx, rt, argv...))
}

type deleteArgs struct {
	Name string `statekit:"required"`
}

type deleteFunc struct{}

func (deleteFunc) Name() string { return "group.delete" }
func (deleteFunc) Args() any    { return deleteArgs{} }
func (deleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*deleteArgs)
	return done(run(ctx, rt, "groupdel", a.Name))
}

type chGIDArgs struct {
	Name string `statekit:"required"`
	GID  string `statekit:"required,name=gid"`
}

type chGIDFunc struct{}

func (chGIDFunc) Name() string { return "group.chgid" }
func (chGIDFunc) Args() any    { return chGIDArgs{} }
func (chGIDFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*chGIDArgs)
	return done(run(ctx, rt, "groupmod", "-g", a.GID, a.Name))
}

// Register installs all group-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{infoFunc{}, listGroupsFunc{}, addFunc{}, deleteFunc{}, chGIDFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
