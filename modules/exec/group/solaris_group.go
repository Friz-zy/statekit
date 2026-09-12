package group

// Solaris virtual group implementation for Salt's solaris_group module
// (saltstack/salt/modules/solaris_group.py @ pinned revision
// 8b63e700637e). The pinned source reads group records through
// Python's grp module; StateKit routes the same colon-separated
// records through `getent group` via the central shell-free Runner,
// and mutates through groupadd/groupdel/groupmod. The surface is
// untagged so the Linux test host can exercise every provider function
// directly with a recording fake Runner; Platforms() provides the
// solaris-only gating (mirroring Salt's __virtual__ kernel==SunOS
// check). group.Register selects this surface on a solaris GOOS. Official Go
// distributions list solaris/amd64 and illumos/amd64 compile targets; this
// host has no native Solaris runtime runner, so the branch is exercised
// through registerSolaris directly.

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func registerSolaris(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		sunGroupAddFunc{}, sunGroupDeleteFunc{}, sunGroupInfoFunc{},
		sunGroupGetentFunc{}, sunGroupChgidFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// sunGroupRun is the bounded shell-free Runner bridge. Cancellation is
// checked before any process starts; Runner errors (including a
// missing getent binary) surface as errors, never as fabricated
// success.
func sunGroupRun(ctx context.Context, rt *runtime.Runtime, argv ...string) (process.CommandResult, error) {
	if err := ctx.Err(); err != nil {
		return process.CommandResult{}, err
	}
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return res, res.Err
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	return res, nil
}

// sunGroupRecord is one group record as printed by `getent group`:
// name:passwd:gid:member1,member2.
type sunGroupRecord struct {
	name    string
	passwd  string
	gid     int
	members []string
}

func sunGroupParseLine(line string) (sunGroupRecord, bool, error) {
	fields := strings.Split(strings.TrimRight(line, "\n"), ":")
	if len(fields) != 4 {
		return sunGroupRecord{}, false, nil
	}
	gid, err := strconv.Atoi(fields[2])
	if err != nil || gid < 0 {
		return sunGroupRecord{}, false, fmt.Errorf("solaris group: invalid gid %q", fields[2])
	}
	members := []string{}
	if fields[3] != "" {
		members = strings.Split(fields[3], ",")
	}
	return sunGroupRecord{name: fields[0], passwd: fields[1], gid: gid, members: members}, true, nil
}

// sunGroupShow resolves one group via `getent group name`. A non-zero
// exit means the grp.getgrnam KeyError lookup miss.
func sunGroupShow(ctx context.Context, rt *runtime.Runtime, name string) (sunGroupRecord, bool, error) {
	res, err := sunGroupRun(ctx, rt, "getent", "group", name)
	if err != nil {
		return sunGroupRecord{}, false, err
	}
	if res.ExitCode != 0 {
		return sunGroupRecord{}, false, nil
	}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		record, ok, parseErr := sunGroupParseLine(line)
		if parseErr != nil {
			return sunGroupRecord{}, false, parseErr
		}
		if ok && record.name == name {
			return record, true, nil
		}
	}
	return sunGroupRecord{}, false, nil
}

// sunGroupAll enumerates every group via `getent group`.
func sunGroupAll(ctx context.Context, rt *runtime.Runtime) ([]sunGroupRecord, error) {
	res, err := sunGroupRun(ctx, rt, "getent", "group")
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, nil
	}
	var groups []sunGroupRecord
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		record, ok, parseErr := sunGroupParseLine(line)
		if parseErr != nil {
			return nil, parseErr
		}
		if ok {
			groups = append(groups, record)
		}
	}
	return groups, nil
}

// sunGroupInfoMap is the info()/getent() record shape: name, passwd,
// gid, members, mirroring the pinned info() dict exactly.
func sunGroupInfoMap(record sunGroupRecord) map[string]any {
	return map[string]any{
		"name":    record.name,
		"passwd":  record.passwd,
		"gid":     record.gid,
		"members": record.members,
	}
}

type sunGroupAddArgs struct {
	Name string `statekit:"required"`
	GID  string `statekit:"name=gid"`
}

type sunGroupAddFunc struct{}

func (sunGroupAddFunc) Name() string        { return "group.add" }
func (sunGroupAddFunc) Args() any           { return sunGroupAddArgs{} }
func (sunGroupAddFunc) Platforms() []string { return []string{"solaris"} }
func (sunGroupAddFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunGroupAddArgs)
	// The pinned source builds "groupadd -g {gid} {name}" and hands it
	// to cmd.run_all with python_shell=False, which splits the string
	// into argv; the argv form is produced directly here.
	argv := []string{"groupadd"}
	if a.GID != "" {
		argv = append(argv, "-g", a.GID)
	}
	argv = append(argv, a.Name)
	res, err := sunGroupRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	return res.ExitCode == 0, nil
}

type sunGroupDeleteArgs struct {
	Name string `statekit:"required"`
}

type sunGroupDeleteFunc struct{}

func (sunGroupDeleteFunc) Name() string        { return "group.delete" }
func (sunGroupDeleteFunc) Args() any           { return sunGroupDeleteArgs{} }
func (sunGroupDeleteFunc) Platforms() []string { return []string{"solaris"} }
func (sunGroupDeleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunGroupDeleteArgs)
	res, err := sunGroupRun(ctx, rt, "groupdel", a.Name)
	if err != nil {
		return nil, err
	}
	return res.ExitCode == 0, nil
}

type sunGroupInfoArgs struct {
	Name string `statekit:"required"`
}

type sunGroupInfoFunc struct{}

func (sunGroupInfoFunc) Name() string        { return "group.info" }
func (sunGroupInfoFunc) Args() any           { return sunGroupInfoArgs{} }
func (sunGroupInfoFunc) Platforms() []string { return []string{"solaris"} }
func (sunGroupInfoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunGroupInfoArgs)
	record, ok, err := sunGroupShow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if !ok {
		// grp.getgrnam's KeyError maps to the pinned source's empty dict.
		return map[string]any{}, nil
	}
	return sunGroupInfoMap(record), nil
}

type sunGroupGetentArgs struct {
	Refresh bool `statekit:"name=refresh"`
}

type sunGroupGetentFunc struct{}

func (sunGroupGetentFunc) Name() string        { return "group.getent" }
func (sunGroupGetentFunc) Args() any           { return sunGroupGetentArgs{} }
func (sunGroupGetentFunc) Platforms() []string { return []string{"solaris"} }
func (sunGroupGetentFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	groups, err := sunGroupAll(ctx, rt)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, record := range groups {
		out = append(out, sunGroupInfoMap(record))
	}
	return out, nil
}

type sunGroupChgidArgs struct {
	Name string `statekit:"required"`
	GID  string `statekit:"required,name=gid"`
}

type sunGroupChgidFunc struct{}

func (sunGroupChgidFunc) Name() string        { return "group.chgid" }
func (sunGroupChgidFunc) Args() any           { return sunGroupChgidArgs{} }
func (sunGroupChgidFunc) Platforms() []string { return []string{"solaris"} }
func (sunGroupChgidFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunGroupChgidArgs)
	// file.group_to_gid in the pinned source resolves the group's
	// current gid by name ("" when the group is unknown).
	pre, ok, err := sunGroupShow(ctx, rt, a.Name)
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
	if _, err := sunGroupRun(ctx, rt, "groupmod", "-g", a.GID, a.Name); err != nil {
		return nil, err
	}
	post, ok, err := sunGroupShow(ctx, rt, a.Name)
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
