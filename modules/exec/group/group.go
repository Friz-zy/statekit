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

type InfoArgs struct {
	Name string `statekit:"required"`
}

type infoFunc struct{}

func (infoFunc) Name() string { return "group.info" }
func (infoFunc) Args() any    { return InfoArgs{} }
func (infoFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InfoArgs)
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

type ListGroupsArgs struct{}

type listGroupsFunc struct{}

func (listGroupsFunc) Name() string { return "group.list_groups" }
func (listGroupsFunc) Args() any    { return ListGroupsArgs{} }
func (listGroupsFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	names := []string{}
	for _, entry := range readGroups(rt) {
		names = append(names, entry.Name)
	}
	return names, nil
}

type AddArgs struct {
	Name string `statekit:"required"`
	GID  string `statekit:"name=gid"`
}

type addFunc struct{}

func (addFunc) Name() string { return "group.add" }
func (addFunc) Args() any    { return AddArgs{} }
func (addFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AddArgs)
	argv := []string{"groupadd"}
	if a.GID != "" {
		argv = append(argv, "-g", a.GID)
	}
	argv = append(argv, a.Name)
	return done(run(ctx, rt, argv...))
}

type DeleteArgs struct {
	Name string `statekit:"required"`
}

type deleteFunc struct{}

func (deleteFunc) Name() string { return "group.delete" }
func (deleteFunc) Args() any    { return DeleteArgs{} }
func (deleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DeleteArgs)
	return done(run(ctx, rt, "groupdel", a.Name))
}

type ChGIDArgs struct {
	Name string `statekit:"required"`
	GID  string `statekit:"required,name=gid"`
}

type chGIDFunc struct{}

func (chGIDFunc) Name() string { return "group.chgid" }
func (chGIDFunc) Args() any    { return ChGIDArgs{} }
func (chGIDFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ChGIDArgs)
	return done(run(ctx, rt, "groupmod", "-g", a.GID, a.Name))
}

// Register installs all group-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	if runtime.CurrentGOOS() == "freebsd" {
		return registerFreeBSD(reg)
	}
	// Official Go distributions list solaris/amd64 and illumos/amd64 compile
	// targets. This host has no native Solaris runtime runner; the branch keeps
	// dispatch exhaustive and registerSolaris is covered by the untagged mock
	// tests on the Linux host.
	if runtime.CurrentGOOS() == "solaris" {
		return registerSolaris(reg)
	}
	if runtime.CurrentGOOS() == "darwin" {
		return registerMac(reg)
	}
	if runtime.CurrentGOOS() == "windows" {
		return registerWindows(reg)
	}
	for _, fn := range []runtime.ExecFunction{infoFunc{}, listGroupsFunc{}, addFunc{}, deleteFunc{}, chGIDFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
