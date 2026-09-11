package group

// FreeBSD virtual group implementation for Salt's pw_group module
// (saltstack/salt/modules/pw_group.py @ pinned revision 8b63e700637e,
// tests/pytests/unit/modules/test_pw_group.py). The pinned source reads
// group records through Python's grp module; StateKit routes the same
// colon-separated records through `pw groupshow` via the central
// shell-free Runner. The surface is untagged so the Linux test host can
// exercise every provider function directly with a recording fake
// Runner; Platforms() provides the freebsd-only gating (mirroring
// Salt's __virtual__ FreeBSD/DragonFly check). group.Register selects
// this surface on GOOS=freebsd.

import (
	"context"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func registerFreeBSD(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		pwGroupAddFunc{}, pwGroupDeleteFunc{}, pwGroupInfoFunc{}, pwGroupGetentFunc{},
		pwGroupChgidFunc{}, pwGroupAddUserFunc{}, pwGroupDelUserFunc{}, pwGroupMembersFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// pwGroupRun is the bounded shell-free Runner bridge. Cancellation is
// checked before any process starts; Runner errors (including a missing
// pw binary) surface as errors, never as fabricated success.
func pwGroupRun(ctx context.Context, rt *runtime.Runtime, argv ...string) (process.CommandResult, error) {
	if err := ctx.Err(); err != nil {
		return process.CommandResult{}, err
	}
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return res, res.Err
	}
	return res, nil
}

// pwGroupRecord is one /etc/group record as printed by `pw groupshow`:
// name:passwd:gid:member1,member2.
type pwGroupRecord struct {
	name    string
	passwd  string
	gid     int
	members []string
}

func pwGroupParseLine(line string) (pwGroupRecord, bool) {
	fields := strings.Split(strings.TrimRight(line, "\n"), ":")
	if len(fields) != 4 {
		return pwGroupRecord{}, false
	}
	gid, _ := strconv.Atoi(fields[2])
	members := []string{}
	if fields[3] != "" {
		members = strings.Split(fields[3], ",")
	}
	return pwGroupRecord{name: fields[0], passwd: fields[1], gid: gid, members: members}, true
}

// pwGroupShow resolves one group via `pw groupshow -n name`. A non-zero
// exit means the grp.getgrnam KeyError lookup miss.
func pwGroupShow(ctx context.Context, rt *runtime.Runtime, name string) (pwGroupRecord, bool, error) {
	res, err := pwGroupRun(ctx, rt, "pw", "groupshow", "-n", name)
	if err != nil {
		return pwGroupRecord{}, false, err
	}
	if res.ExitCode != 0 {
		return pwGroupRecord{}, false, nil
	}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if record, ok := pwGroupParseLine(line); ok && record.name == name {
			return record, true, nil
		}
	}
	return pwGroupRecord{}, false, nil
}

// pwAllGroups enumerates every group via `pw groupshow -a`.
func pwAllGroups(ctx context.Context, rt *runtime.Runtime) ([]pwGroupRecord, error) {
	res, err := pwGroupRun(ctx, rt, "pw", "groupshow", "-a")
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, nil
	}
	var groups []pwGroupRecord
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if record, ok := pwGroupParseLine(line); ok {
			groups = append(groups, record)
		}
	}
	return groups, nil
}

// pwGroupInfoMap is the info()/getent() record shape: name, passwd,
// gid, members, mirroring the pinned info() dict exactly.
func pwGroupInfoMap(record pwGroupRecord) map[string]any {
	return map[string]any{
		"name":    record.name,
		"passwd":  record.passwd,
		"gid":     record.gid,
		"members": record.members,
	}
}

// ---------------------------------------------------------------------------
// add / delete

type pwGroupAddArgs struct {
	Name string `statekit:"required"`
	GID  string `statekit:"name=gid"`
}

type pwGroupAddFunc struct{}

func (pwGroupAddFunc) Name() string        { return "group.add" }
func (pwGroupAddFunc) Args() any           { return pwGroupAddArgs{} }
func (pwGroupAddFunc) Platforms() []string { return []string{"freebsd"} }
func (pwGroupAddFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwGroupAddArgs)
	// The pinned source builds "pw groupadd -g {gid} -n {name}" and
	// hands it to cmd.run_all with python_shell=False, which splits the
	// string into argv; the argv form is produced directly here.
	argv := []string{"pw", "groupadd"}
	if a.GID != "" {
		argv = append(argv, "-g", a.GID)
	}
	argv = append(argv, "-n", a.Name)
	res, err := pwGroupRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	return res.ExitCode == 0, nil
}

type pwGroupDeleteArgs struct {
	Name string `statekit:"required"`
}

type pwGroupDeleteFunc struct{}

func (pwGroupDeleteFunc) Name() string        { return "group.delete" }
func (pwGroupDeleteFunc) Args() any           { return pwGroupDeleteArgs{} }
func (pwGroupDeleteFunc) Platforms() []string { return []string{"freebsd"} }
func (pwGroupDeleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwGroupDeleteArgs)
	res, err := pwGroupRun(ctx, rt, "pw", "groupdel", a.Name)
	if err != nil {
		return nil, err
	}
	return res.ExitCode == 0, nil
}

// ---------------------------------------------------------------------------
// info / getent

type pwGroupInfoArgs struct {
	Name string `statekit:"required"`
}

type pwGroupInfoFunc struct{}

func (pwGroupInfoFunc) Name() string        { return "group.info" }
func (pwGroupInfoFunc) Args() any           { return pwGroupInfoArgs{} }
func (pwGroupInfoFunc) Platforms() []string { return []string{"freebsd"} }
func (pwGroupInfoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwGroupInfoArgs)
	record, ok, err := pwGroupShow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if !ok {
		// grp.getgrnam's KeyError maps to the pinned source's empty dict.
		return map[string]any{}, nil
	}
	return pwGroupInfoMap(record), nil
}

type pwGroupGetentArgs struct {
	Refresh bool `statekit:"name=refresh"`
}

type pwGroupGetentFunc struct{}

func (pwGroupGetentFunc) Name() string        { return "group.getent" }
func (pwGroupGetentFunc) Args() any           { return pwGroupGetentArgs{} }
func (pwGroupGetentFunc) Platforms() []string { return []string{"freebsd"} }
func (pwGroupGetentFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	groups, err := pwAllGroups(ctx, rt)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, record := range groups {
		out = append(out, pwGroupInfoMap(record))
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// chgid / adduser / deluser / members

type pwGroupChgidArgs struct {
	Name string `statekit:"required"`
	GID  string `statekit:"required,name=gid"`
}

type pwGroupChgidFunc struct{}

func (pwGroupChgidFunc) Name() string        { return "group.chgid" }
func (pwGroupChgidFunc) Args() any           { return pwGroupChgidArgs{} }
func (pwGroupChgidFunc) Platforms() []string { return []string{"freebsd"} }
func (pwGroupChgidFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwGroupChgidArgs)
	// file.group_to_gid in the pinned source: resolve the group's
	// current gid by name.
	pre, ok, err := pwGroupShow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	preGID := ""
	if ok {
		preGID = strconv.Itoa(pre.gid)
	}
	if a.GID == preGID {
		return true, nil
	}
	if _, err := pwGroupRun(ctx, rt, "pw", "groupmod", a.Name, "-g", a.GID); err != nil {
		return nil, err
	}
	post, ok, err := pwGroupShow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	postGID := ""
	if ok {
		postGID = strconv.Itoa(post.gid)
	}
	if postGID != preGID {
		return postGID == a.GID, nil
	}
	return false, nil
}

type pwGroupAddUserArgs struct {
	Name     string `statekit:"required"`
	Username string `statekit:"required,name=username"`
}

type pwGroupAddUserFunc struct{}

func (pwGroupAddUserFunc) Name() string        { return "group.adduser" }
func (pwGroupAddUserFunc) Args() any           { return pwGroupAddUserArgs{} }
func (pwGroupAddUserFunc) Platforms() []string { return []string{"freebsd"} }
func (pwGroupAddUserFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwGroupAddUserArgs)
	// pw exits with code 65 if the group is unknown; retcodes are data.
	res, err := pwGroupRun(ctx, rt, "pw", "groupmod", a.Name, "-m", a.Username)
	if err != nil {
		return nil, err
	}
	return res.ExitCode == 0, nil
}

type pwGroupDelUserArgs struct {
	Name     string `statekit:"required"`
	Username string `statekit:"required,name=username"`
}

type pwGroupDelUserFunc struct{}

func (pwGroupDelUserFunc) Name() string        { return "group.deluser" }
func (pwGroupDelUserFunc) Args() any           { return pwGroupDelUserArgs{} }
func (pwGroupDelUserFunc) Platforms() []string { return []string{"freebsd"} }
func (pwGroupDelUserFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwGroupDelUserArgs)
	record, ok, err := pwGroupShow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if !ok || !pwGroupHasMember(record, a.Username) {
		// Removing a user that is not a member (or from a missing group)
		// is already settled.
		return true, nil
	}
	res, err := pwGroupRun(ctx, rt, "pw", "groupmod", a.Name, "-d", a.Username)
	if err != nil {
		return nil, err
	}
	return res.ExitCode == 0, nil
}

func pwGroupHasMember(record pwGroupRecord, username string) bool {
	for _, member := range record.members {
		if member == username {
			return true
		}
	}
	return false
}

type pwGroupMembersArgs struct {
	Name        string `statekit:"required"`
	MembersList string `statekit:"required,name=members_list"`
}

type pwGroupMembersFunc struct{}

func (pwGroupMembersFunc) Name() string        { return "group.members" }
func (pwGroupMembersFunc) Args() any           { return pwGroupMembersArgs{} }
func (pwGroupMembersFunc) Platforms() []string { return []string{"freebsd"} }
func (pwGroupMembersFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwGroupMembersArgs)
	res, err := pwGroupRun(ctx, rt, "pw", "groupmod", a.Name, "-M", a.MembersList)
	if err != nil {
		return nil, err
	}
	return res.ExitCode == 0, nil
}
