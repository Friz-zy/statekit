// Package user implements Salt-compatible local account inspection and
// management on Linux.
//
// Reference: saltstack/salt/modules/useradd.py @ pinned revision. Database
// reads go through the runtime FileSystem (/etc/passwd, /etc/group);
// mutations delegate to useradd/userdel/usermod via the central Runner.
package user

import (
	"context"
	"fmt"
	"strconv"

	"github.com/friz-zy/statekit/internal/runtime"
	"github.com/friz-zy/statekit/internal/sysfiles"
)

const passwdPath = "/etc/passwd"
const groupPath = "/etc/group"

func readPasswd(rt *runtime.Runtime) []sysfiles.PasswdEntry {
	data, err := rt.FS.ReadFile(passwdPath)
	if err != nil {
		return nil
	}
	return sysfiles.ParsePasswd(string(data))
}

func readGroups(rt *runtime.Runtime) []sysfiles.GroupEntry {
	data, err := rt.FS.ReadFile(groupPath)
	if err != nil {
		return nil
	}
	return sysfiles.ParseGroup(string(data))
}

func groupsOfUser(rt *runtime.Runtime, name string) []string {
	groups := []string{}
	for _, group := range readGroups(rt) {
		for _, member := range group.Members {
			if member == name {
				groups = append(groups, group.Name)
				break
			}
		}
	}
	return groups
}

type infoArgs struct {
	Name string `statekit:"required"`
}

type infoFunc struct{}

func (infoFunc) Name() string { return "user.info" }
func (infoFunc) Args() any    { return infoArgs{} }
func (infoFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*infoArgs)
	for _, entry := range readPasswd(rt) {
		if entry.Name != a.Name {
			continue
		}
		return map[string]any{
			"name":   entry.Name,
			"uid":    entry.UID,
			"gid":    entry.GID,
			"home":   entry.Home,
			"shell":  entry.Shell,
			"gecos":  entry.Gecos,
			"groups": groupsOfUser(rt, entry.Name),
		}, nil
	}
	return nil, fmt.Errorf("user %q does not exist", a.Name)
}

type listUsersArgs struct{}

type listUsersFunc struct{}

func (listUsersFunc) Name() string { return "user.list_users" }
func (listUsersFunc) Args() any    { return listUsersArgs{} }
func (listUsersFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	names := []string{}
	for _, entry := range readPasswd(rt) {
		names = append(names, entry.Name)
	}
	return names, nil
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

type addArgs struct {
	Name   string `statekit:"required"`
	UID    string `statekit:"name=uid"`
	GID    string `statekit:"name=gid"`
	Home   string `statekit:"name=home"`
	Shell  string `statekit:"name=shell"`
	Create bool   `statekit:"name=createhome"`
}

type addFunc struct{}

func (addFunc) Name() string { return "user.add" }
func (addFunc) Args() any    { return addArgs{} }
func (addFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*addArgs)
	argv := []string{"useradd"}
	if a.UID != "" {
		argv = append(argv, "-u", a.UID)
	}
	if a.GID != "" {
		argv = append(argv, "-g", a.GID)
	}
	if a.Home != "" {
		argv = append(argv, "-d", a.Home)
	}
	if a.Shell != "" {
		argv = append(argv, "-s", a.Shell)
	}
	if !a.Create {
		argv = append(argv, "-M")
	} else {
		argv = append(argv, "-m")
	}
	argv = append(argv, a.Name)
	return done(run(ctx, rt, argv...))
}

type deleteArgs struct {
	Name   string `statekit:"required"`
	Remove bool   `statekit:"name=remove"`
	Force  bool   `statekit:"name=force"`
}

type deleteFunc struct{}

func (deleteFunc) Name() string { return "user.delete" }
func (deleteFunc) Args() any    { return deleteArgs{} }
func (deleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*deleteArgs)
	argv := []string{"userdel"}
	if a.Remove {
		argv = append(argv, "-r")
	}
	if a.Force {
		argv = append(argv, "-f")
	}
	argv = append(argv, a.Name)
	return done(run(ctx, rt, argv...))
}

type chUIDArgs struct {
	Name string `statekit:"required"`
	UID  string `statekit:"required,name=uid"`
}

type chUIDFunc struct{}

func (chUIDFunc) Name() string { return "user.chuid" }
func (chUIDFunc) Args() any    { return chUIDArgs{} }
func (chUIDFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*chUIDArgs)
	return done(run(ctx, rt, "usermod", "-u", a.UID, a.Name))
}

type chGIDArgs struct {
	Name string `statekit:"required"`
	GID  string `statekit:"required,name=gid"`
}

type chGIDFunc struct{}

func (chGIDFunc) Name() string { return "user.chgid" }
func (chGIDFunc) Args() any    { return chGIDArgs{} }
func (chGIDFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*chGIDArgs)
	return done(run(ctx, rt, "usermod", "-g", a.GID, a.Name))
}

type chShellArgs struct {
	Name  string `statekit:"required"`
	Shell string `statekit:"required,name=shell"`
}

type chShellFunc struct{}

func (chShellFunc) Name() string { return "user.chshell" }
func (chShellFunc) Args() any    { return chShellArgs{} }
func (chShellFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*chShellArgs)
	return done(run(ctx, rt, "usermod", "-s", a.Shell, a.Name))
}

type chHomeArgs struct {
	Name string `statekit:"required"`
	Home string `statekit:"required,name=home"`
	Move bool   `statekit:"name=move_current"`
}

type chHomeFunc struct{}

func (chHomeFunc) Name() string { return "user.chhome" }
func (chHomeFunc) Args() any    { return chHomeArgs{} }
func (chHomeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*chHomeArgs)
	argv := []string{"usermod"}
	if a.Move {
		argv = append(argv, "-m")
	}
	argv = append(argv, "-d", a.Home, a.Name)
	return done(run(ctx, rt, argv...))
}

// currentUID resolves the numeric uid of a passwd entry when available.
func currentUID(entries []sysfiles.PasswdEntry, name string) (int, bool) {
	for _, entry := range entries {
		if entry.Name == name {
			uid, err := strconv.Atoi(entry.UID)
			if err != nil {
				return 0, false
			}
			return uid, true
		}
	}
	return 0, false
}

// Register installs all user-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		infoFunc{}, listUsersFunc{}, addFunc{}, deleteFunc{},
		chUIDFunc{}, chGIDFunc{}, chShellFunc{}, chHomeFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
