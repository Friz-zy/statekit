package user

// Solaris virtual user implementation for Salt's solaris_user module
// (saltstack/salt/modules/solaris_user.py @ pinned revision 8b63e700637e).
// The pinned source reads the user database through Python's pwd module
// and salt.utils.user.get_group_list; StateKit routes the same
// colon-separated records through `getent passwd` / `getent group` via
// the central shell-free Runner (the documented Solaris name-service
// CLI), and mutates through the useradd/userdel/usermod binaries the
// source shells out to. The surface is untagged so the Linux test host
// can exercise every provider function directly with a recording fake
// Runner; Platforms() provides the solaris-only gating (mirroring
// Salt's __virtual__ kernel==SunOS check). user.Register selects this
// surface on a solaris GOOS. Official Go distributions list solaris/amd64
// and illumos/amd64 compile targets; this host has no native Solaris runtime
// runner, so the branch is exercised through registerSolaris directly.

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func registerSolaris(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		sunAddFunc{}, sunDeleteFunc{}, sunGetentFunc{}, sunChuidFunc{}, sunChgidFunc{},
		sunChshellFunc{}, sunChhomeFunc{}, sunChgroupsFunc{}, sunChfullnameFunc{},
		sunChroomnumberFunc{}, sunChworkphoneFunc{}, sunChhomephoneFunc{}, sunInfoFunc{},
		sunListGroupsFunc{}, sunListUsersFunc{}, sunRenameFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// sunRun is the bounded shell-free Runner bridge. Cancellation is checked
// before and after the Runner call; Runner errors (including a missing getent
// binary) surface as errors, never as fabricated success.
func sunRun(ctx context.Context, rt *runtime.Runtime, argv ...string) (process.CommandResult, error) {
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

// sunRunStrict retains the historical helper name used by the ch* mutators,
// but mirrors Salt's cmd.run default: completed non-zero exits remain command
// data. Only Runner failures and context cancellation are errors.
func sunRunStrict(ctx context.Context, rt *runtime.Runtime, argv ...string) (process.CommandResult, error) {
	res, err := sunRun(ctx, rt, argv...)
	if err != nil {
		return res, err
	}
	return res, nil
}

// sunUserEntry is one passwd record as printed by `getent passwd`:
// name:passwd:uid:gid:gecos:home:shell, expanded with the four GECOS
// fields the pinned info() dict reports.
type sunUserEntry struct {
	name       string
	passwd     string
	uid        int
	gid        int
	gecos      string
	home       string
	shell      string
	fullname   string
	roomnumber string
	workphone  string
	homephone  string
}

// sunParsePasswdLine parses one colon-separated passwd line. It returns false
// when the line is not a 7-field record and a deterministic error when a
// numeric UID/GID field is invalid or outside the int range.
func sunParsePasswdLine(line string) (sunUserEntry, bool, error) {
	fields := strings.Split(strings.TrimRight(line, "\n"), ":")
	if len(fields) != 7 {
		return sunUserEntry{}, false, nil
	}
	uid, err := strconv.Atoi(fields[2])
	if err != nil || uid < 0 {
		return sunUserEntry{}, false, fmt.Errorf("solaris passwd: invalid uid %q", fields[2])
	}
	gid, err := strconv.Atoi(fields[3])
	if err != nil || gid < 0 {
		return sunUserEntry{}, false, fmt.Errorf("solaris passwd: invalid gid %q", fields[3])
	}
	entry := sunUserEntry{
		name:   fields[0],
		passwd: fields[1],
		uid:    uid,
		gid:    gid,
		gecos:  fields[4],
		home:   fields[5],
		shell:  fields[6],
	}
	gecosFields := strings.SplitN(entry.gecos, ",", 4)
	for len(gecosFields) < 4 {
		gecosFields = append(gecosFields, "")
	}
	entry.fullname = gecosFields[0]
	entry.roomnumber = gecosFields[1]
	entry.workphone = gecosFields[2]
	entry.homephone = gecosFields[3]
	return entry, true, nil
}

// sunGroupEntry is one group record as printed by `getent group`:
// name:passwd:gid:member1,member2.
type sunGroupEntry struct {
	name    string
	passwd  string
	gid     int
	members []string
}

func sunParseGroupLine(line string) (sunGroupEntry, bool, error) {
	fields := strings.Split(strings.TrimRight(line, "\n"), ":")
	if len(fields) != 4 {
		return sunGroupEntry{}, false, nil
	}
	gid, err := strconv.Atoi(fields[2])
	if err != nil || gid < 0 {
		return sunGroupEntry{}, false, fmt.Errorf("solaris group: invalid gid %q", fields[2])
	}
	members := []string{}
	if fields[3] != "" {
		members = strings.Split(fields[3], ",")
	}
	return sunGroupEntry{name: fields[0], passwd: fields[1], gid: gid, members: members}, true, nil
}

// sunUserShow resolves one user via `getent passwd name`. A non-zero
// exit (getent: not found) means the pwd.getpwnam KeyError lookup miss.
func sunUserShow(ctx context.Context, rt *runtime.Runtime, name string) (sunUserEntry, bool, error) {
	res, err := sunRun(ctx, rt, "getent", "passwd", name)
	if err != nil {
		return sunUserEntry{}, false, err
	}
	if res.ExitCode != 0 {
		return sunUserEntry{}, false, nil
	}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		entry, ok, parseErr := sunParsePasswdLine(line)
		if parseErr != nil {
			return sunUserEntry{}, false, parseErr
		}
		if ok && entry.name == name {
			return entry, true, nil
		}
	}
	return sunUserEntry{}, false, nil
}

// sunAllUsers enumerates every record via `getent passwd` in the order
// the name service prints them.
func sunAllUsers(ctx context.Context, rt *runtime.Runtime) ([]sunUserEntry, error) {
	res, err := sunRun(ctx, rt, "getent", "passwd")
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, nil
	}
	var users []sunUserEntry
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		entry, ok, parseErr := sunParsePasswdLine(line)
		if parseErr != nil {
			return nil, parseErr
		}
		if ok {
			users = append(users, entry)
		}
	}
	return users, nil
}

// sunAllGroups enumerates every group via `getent group`.
func sunAllGroups(ctx context.Context, rt *runtime.Runtime) ([]sunGroupEntry, error) {
	res, err := sunRun(ctx, rt, "getent", "group")
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, nil
	}
	var groups []sunGroupEntry
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		entry, ok, parseErr := sunParseGroupLine(line)
		if parseErr != nil {
			return nil, parseErr
		}
		if ok {
			groups = append(groups, entry)
		}
	}
	return groups, nil
}

// sunGroupsOf reproduces salt.utils.user.get_group_list: primary and
// supplementary memberships are combined, deduplicated, and sorted.
func sunGroupsOf(ctx context.Context, rt *runtime.Runtime, entry sunUserEntry) ([]string, error) {
	groups, err := sunAllGroups(ctx, rt)
	if err != nil {
		return nil, err
	}
	groupNames := map[string]struct{}{}
	for _, group := range groups {
		if group.gid == entry.gid {
			groupNames[group.name] = struct{}{}
		}
		for _, member := range group.members {
			if member == entry.name {
				groupNames[group.name] = struct{}{}
				break
			}
		}
	}
	out := make([]string, 0, len(groupNames))
	for name := range groupNames {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// sunInfoMap is the info()/getent() record shape: gid, groups, home,
// name, passwd, shell, uid plus the four GECOS fields, mirroring the
// pinned info() dict exactly.
func sunInfoMap(ctx context.Context, rt *runtime.Runtime, entry sunUserEntry) (map[string]any, error) {
	groups, err := sunGroupsOf(ctx, rt, entry)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"gid":        entry.gid,
		"groups":     groups,
		"home":       entry.home,
		"name":       entry.name,
		"passwd":     entry.passwd,
		"shell":      entry.shell,
		"uid":        entry.uid,
		"fullname":   entry.fullname,
		"roomnumber": entry.roomnumber,
		"workphone":  entry.workphone,
		"homephone":  entry.homephone,
	}, nil
}

// ---------------------------------------------------------------------------
// add / delete

type sunAddArgs struct {
	Name       string   `statekit:"required"`
	UID        string   `statekit:"name=uid"`
	GID        string   `statekit:"name=gid"`
	Groups     []string `statekit:"name=groups"`
	Home       *string  `statekit:"name=home"`
	Shell      string   `statekit:"name=shell"`
	Unique     *bool    `statekit:"name=unique"`
	Fullname   string   `statekit:"name=fullname"`
	Roomnumber string   `statekit:"name=roomnumber"`
	Workphone  string   `statekit:"name=workphone"`
	Homephone  string   `statekit:"name=homephone"`
	CreateHome *bool    `statekit:"name=createhome"`
}

type sunAddFunc struct{}

func (sunAddFunc) Name() string        { return "user.add" }
func (sunAddFunc) Args() any           { return sunAddArgs{} }
func (sunAddFunc) Platforms() []string { return []string{"solaris"} }
func (sunAddFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunAddArgs)
	unique := true
	if a.Unique != nil {
		unique = *a.Unique
	}
	createHome := true
	if a.CreateHome != nil {
		createHome = *a.CreateHome
	}
	// Flag order follows the pinned source: shell, uid, gid, groups,
	// createhome, home, unique, name.
	argv := []string{"useradd"}
	if a.Shell != "" {
		argv = append(argv, "-s", a.Shell)
	}
	if a.UID != "" {
		argv = append(argv, "-u", a.UID)
	}
	if a.GID != "" {
		argv = append(argv, "-g", a.GID)
	}
	if len(a.Groups) > 0 {
		argv = append(argv, "-G", strings.Join(a.Groups, ","))
	}
	if createHome {
		argv = append(argv, "-m")
	}
	if a.Home != nil {
		argv = append(argv, "-d", *a.Home)
	}
	if !unique {
		argv = append(argv, "-o")
	}
	argv = append(argv, a.Name)
	res, err := sunRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return false, nil
	}
	// The user exists now: the pinned source fires the GECOS follow-ups
	// and returns true regardless of their outcomes (failures surface
	// in a later call). Runner errors still propagate, matching the
	// Python exception path.
	if a.Fullname != "" {
		if _, err := sunUpdateGecos(ctx, rt, a.Name, "fullname", a.Fullname); err != nil {
			return nil, err
		}
	}
	if a.Roomnumber != "" {
		if _, err := sunUpdateGecos(ctx, rt, a.Name, "roomnumber", a.Roomnumber); err != nil {
			return nil, err
		}
	}
	if a.Workphone != "" {
		if _, err := sunUpdateGecos(ctx, rt, a.Name, "workphone", a.Workphone); err != nil {
			return nil, err
		}
	}
	if a.Homephone != "" {
		if _, err := sunUpdateGecos(ctx, rt, a.Name, "homephone", a.Homephone); err != nil {
			return nil, err
		}
	}
	return true, nil
}

type sunDeleteArgs struct {
	Name   string `statekit:"required"`
	Remove bool   `statekit:"name=remove"`
	Force  bool   `statekit:"name=force"`
}

type sunDeleteFunc struct{}

func (sunDeleteFunc) Name() string        { return "user.delete" }
func (sunDeleteFunc) Args() any           { return sunDeleteArgs{} }
func (sunDeleteFunc) Platforms() []string { return []string{"solaris"} }
func (sunDeleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunDeleteArgs)
	// userdel does not support force-deleting a user while logged in;
	// the pinned source only logs that limitation.
	argv := []string{"userdel"}
	if a.Remove {
		argv = append(argv, "-r")
	}
	argv = append(argv, a.Name)
	res, err := sunRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	return res.ExitCode == 0, nil
}

// ---------------------------------------------------------------------------
// getent / info / listing

type sunGetentArgs struct {
	Refresh bool `statekit:"name=refresh"`
}

type sunGetentFunc struct{}

func (sunGetentFunc) Name() string        { return "user.getent" }
func (sunGetentFunc) Args() any           { return sunGetentArgs{} }
func (sunGetentFunc) Platforms() []string { return []string{"solaris"} }
func (sunGetentFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	users, err := sunAllUsers(ctx, rt)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, entry := range users {
		info, err := sunInfoMap(ctx, rt, entry)
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, nil
}

type sunInfoArgs struct {
	Name string `statekit:"required"`
}

type sunInfoFunc struct{}

func (sunInfoFunc) Name() string        { return "user.info" }
func (sunInfoFunc) Args() any           { return sunInfoArgs{} }
func (sunInfoFunc) Platforms() []string { return []string{"solaris"} }
func (sunInfoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunInfoArgs)
	entry, ok, err := sunUserShow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if !ok {
		// pwd.getpwnam's KeyError maps to the pinned source's empty dict.
		return map[string]any{}, nil
	}
	return sunInfoMap(ctx, rt, entry)
}

type sunListUsersArgs struct{}

type sunListUsersFunc struct{}

func (sunListUsersFunc) Name() string        { return "user.list_users" }
func (sunListUsersFunc) Args() any           { return sunListUsersArgs{} }
func (sunListUsersFunc) Platforms() []string { return []string{"solaris"} }
func (sunListUsersFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	users, err := sunAllUsers(ctx, rt)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(users))
	for _, entry := range users {
		names = append(names, entry.name)
	}
	sort.Strings(names)
	return names, nil
}

type sunListGroupsArgs struct {
	Name string `statekit:"required"`
}

type sunListGroupsFunc struct{}

func (sunListGroupsFunc) Name() string        { return "user.list_groups" }
func (sunListGroupsFunc) Args() any           { return sunListGroupsArgs{} }
func (sunListGroupsFunc) Platforms() []string { return []string{"solaris"} }
func (sunListGroupsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunListGroupsArgs)
	entry, ok, err := sunUserShow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if !ok {
		// get_group_list catches lookup failures and returns an empty list.
		return []string{}, nil
	}
	return sunGroupsOf(ctx, rt, entry)
}

// ---------------------------------------------------------------------------
// attribute changes

// sunRequireUser resolves the pre-change record; the pinned source
// raises CommandExecutionError for a missing user.
func sunRequireUser(ctx context.Context, rt *runtime.Runtime, name string) (sunUserEntry, error) {
	entry, ok, err := sunUserShow(ctx, rt, name)
	if err != nil {
		return sunUserEntry{}, err
	}
	if !ok {
		return sunUserEntry{}, fmt.Errorf("User '%s' does not exist", name)
	}
	return entry, nil
}

type sunChuidArgs struct {
	Name string `statekit:"required"`
	UID  string `statekit:"required,name=uid"`
}

type sunChuidFunc struct{}

func (sunChuidFunc) Name() string        { return "user.chuid" }
func (sunChuidFunc) Args() any           { return sunChuidArgs{} }
func (sunChuidFunc) Platforms() []string { return []string{"solaris"} }
func (sunChuidFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunChuidArgs)
	pre, err := sunRequireUser(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if a.UID == strconv.Itoa(pre.uid) {
		return true, nil
	}
	if _, err := sunRunStrict(ctx, rt, "usermod", "-u", a.UID, a.Name); err != nil {
		return nil, err
	}
	post, ok, err := sunUserShow(ctx, rt, a.Name)
	if err != nil || !ok {
		return false, err
	}
	return strconv.Itoa(post.uid) == a.UID, nil
}

type sunChgidArgs struct {
	Name string `statekit:"required"`
	GID  string `statekit:"required,name=gid"`
}

type sunChgidFunc struct{}

func (sunChgidFunc) Name() string        { return "user.chgid" }
func (sunChgidFunc) Args() any           { return sunChgidArgs{} }
func (sunChgidFunc) Platforms() []string { return []string{"solaris"} }
func (sunChgidFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunChgidArgs)
	pre, err := sunRequireUser(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if a.GID == strconv.Itoa(pre.gid) {
		return true, nil
	}
	if _, err := sunRunStrict(ctx, rt, "usermod", "-g", a.GID, a.Name); err != nil {
		return nil, err
	}
	post, ok, err := sunUserShow(ctx, rt, a.Name)
	if err != nil || !ok {
		return false, err
	}
	return strconv.Itoa(post.gid) == a.GID, nil
}

type sunChshellArgs struct {
	Name  string `statekit:"required"`
	Shell string `statekit:"required,name=shell"`
}

type sunChshellFunc struct{}

func (sunChshellFunc) Name() string        { return "user.chshell" }
func (sunChshellFunc) Args() any           { return sunChshellArgs{} }
func (sunChshellFunc) Platforms() []string { return []string{"solaris"} }
func (sunChshellFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunChshellArgs)
	pre, err := sunRequireUser(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if a.Shell == pre.shell {
		return true, nil
	}
	if _, err := sunRunStrict(ctx, rt, "usermod", "-s", a.Shell, a.Name); err != nil {
		return nil, err
	}
	post, ok, err := sunUserShow(ctx, rt, a.Name)
	if err != nil || !ok {
		return false, err
	}
	return post.shell == a.Shell, nil
}

type sunChhomeArgs struct {
	Name    string `statekit:"required"`
	Home    string `statekit:"required,name=home"`
	Persist bool   `statekit:"name=persist"`
}

type sunChhomeFunc struct{}

func (sunChhomeFunc) Name() string        { return "user.chhome" }
func (sunChhomeFunc) Args() any           { return sunChhomeArgs{} }
func (sunChhomeFunc) Platforms() []string { return []string{"solaris"} }
func (sunChhomeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunChhomeArgs)
	pre, err := sunRequireUser(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if a.Home == pre.home {
		return true, nil
	}
	argv := []string{"usermod", "-d", a.Home}
	if a.Persist {
		argv = append(argv, "-m")
	}
	argv = append(argv, a.Name)
	if _, err := sunRunStrict(ctx, rt, argv...); err != nil {
		return nil, err
	}
	post, ok, err := sunUserShow(ctx, rt, a.Name)
	if err != nil || !ok {
		return false, err
	}
	return post.home == a.Home, nil
}

type sunChgroupsArgs struct {
	Name   string   `statekit:"required"`
	Groups []string `statekit:"required,name=groups"`
	Append bool     `statekit:"name=append"`
}

type sunChgroupsFunc struct{}

func (sunChgroupsFunc) Name() string        { return "user.chgroups" }
func (sunChgroupsFunc) Args() any           { return sunChgroupsArgs{} }
func (sunChgroupsFunc) Platforms() []string { return []string{"solaris"} }
func (sunChgroupsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunChgroupsArgs)
	entry, ok, err := sunUserShow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("user %q does not exist", a.Name)
	}
	current, err := sunGroupsOf(ctx, rt, entry)
	if err != nil {
		return nil, err
	}
	set := func(values []string) map[string]bool {
		out := map[string]bool{}
		for _, value := range values {
			out[value] = true
		}
		return out
	}
	currentSet, wantSet := set(current), set(a.Groups)
	same := len(currentSet) == len(wantSet)
	if same {
		for group := range wantSet {
			if !currentSet[group] {
				same = false
				break
			}
		}
	}
	if same {
		return true, nil
	}
	// The pinned source's append branch calls groups.update(ugrps) on a
	// list, which raises AttributeError; the intended semantics (per
	// pw_user and the states contract) are the set union, requested
	// order first.
	groups := append([]string{}, a.Groups...)
	if a.Append {
		for _, group := range current {
			if !wantSet[group] {
				groups = append(groups, group)
			}
		}
	}
	res, err := sunRun(ctx, rt, "usermod", "-G", strings.Join(groups, ","), a.Name)
	if err != nil {
		return nil, err
	}
	return res.ExitCode == 0, nil
}

// ---------------------------------------------------------------------------
// GECOS field updates (_get_gecos / _build_gecos / _update_gecos)

func sunGecosValue(entry sunUserEntry, key string) string {
	switch key {
	case "fullname":
		return entry.fullname
	case "roomnumber":
		return entry.roomnumber
	case "workphone":
		return entry.workphone
	case "homephone":
		return entry.homephone
	}
	return ""
}

// sunUpdateGecos ports _update_gecos: _get_gecos propagates a missing-user
// KeyError, same-value short-circuits to true, otherwise `usermod -c gecos
// name` runs and the post-change GECOS field decides the result.
func sunUpdateGecos(ctx context.Context, rt *runtime.Runtime, name, key, value string) (any, error) {
	pre, err := sunRequireUser(ctx, rt, name)
	if err != nil {
		return nil, err
	}
	if value == sunGecosValue(pre, key) {
		return true, nil
	}
	gecos := strings.Join([]string{
		sunGecosUpdated(pre.fullname, key, "fullname", value),
		sunGecosUpdated(pre.roomnumber, key, "roomnumber", value),
		sunGecosUpdated(pre.workphone, key, "workphone", value),
		sunGecosUpdated(pre.homephone, key, "homephone", value),
	}, ",")
	if _, err := sunRunStrict(ctx, rt, "usermod", "-c", gecos, name); err != nil {
		return nil, err
	}
	post, ok, err := sunUserShow(ctx, rt, name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("User '%s' does not exist", name)
	}
	return sunGecosValue(post, key) == value, nil
}

func sunGecosUpdated(current, key, field, value string) string {
	if key == field {
		return value
	}
	return current
}

type sunChfullnameArgs struct {
	Name     string `statekit:"required"`
	Fullname string `statekit:"required,name=fullname"`
}

type sunChfullnameFunc struct{}

func (sunChfullnameFunc) Name() string        { return "user.chfullname" }
func (sunChfullnameFunc) Args() any           { return sunChfullnameArgs{} }
func (sunChfullnameFunc) Platforms() []string { return []string{"solaris"} }
func (sunChfullnameFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunChfullnameArgs)
	return sunUpdateGecos(ctx, rt, a.Name, "fullname", a.Fullname)
}

type sunChroomnumberArgs struct {
	Name       string `statekit:"required"`
	Roomnumber string `statekit:"required,name=roomnumber"`
}

type sunChroomnumberFunc struct{}

func (sunChroomnumberFunc) Name() string        { return "user.chroomnumber" }
func (sunChroomnumberFunc) Args() any           { return sunChroomnumberArgs{} }
func (sunChroomnumberFunc) Platforms() []string { return []string{"solaris"} }
func (sunChroomnumberFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunChroomnumberArgs)
	return sunUpdateGecos(ctx, rt, a.Name, "roomnumber", a.Roomnumber)
}

type sunChworkphoneArgs struct {
	Name      string `statekit:"required"`
	Workphone string `statekit:"required,name=workphone"`
}

type sunChworkphoneFunc struct{}

func (sunChworkphoneFunc) Name() string        { return "user.chworkphone" }
func (sunChworkphoneFunc) Args() any           { return sunChworkphoneArgs{} }
func (sunChworkphoneFunc) Platforms() []string { return []string{"solaris"} }
func (sunChworkphoneFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunChworkphoneArgs)
	return sunUpdateGecos(ctx, rt, a.Name, "workphone", a.Workphone)
}

type sunChhomephoneArgs struct {
	Name      string `statekit:"required"`
	Homephone string `statekit:"required,name=homephone"`
}

type sunChhomephoneFunc struct{}

func (sunChhomephoneFunc) Name() string        { return "user.chhomephone" }
func (sunChhomephoneFunc) Args() any           { return sunChhomephoneArgs{} }
func (sunChhomephoneFunc) Platforms() []string { return []string{"solaris"} }
func (sunChhomephoneFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunChhomephoneArgs)
	return sunUpdateGecos(ctx, rt, a.Name, "homephone", a.Homephone)
}

// ---------------------------------------------------------------------------
// rename

type sunRenameArgs struct {
	Name    string `statekit:"required"`
	NewName string `statekit:"required,name=new_name"`
}

type sunRenameFunc struct{}

func (sunRenameFunc) Name() string        { return "user.rename" }
func (sunRenameFunc) Args() any           { return sunRenameArgs{} }
func (sunRenameFunc) Platforms() []string { return []string{"solaris"} }
func (sunRenameFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunRenameArgs)
	_, ok, err := sunUserShow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("User '%s' does not exist", a.Name)
	}
	if _, exists, err := sunUserShow(ctx, rt, a.NewName); err != nil {
		return nil, err
	} else if exists {
		return nil, fmt.Errorf("User '%s' already exists", a.NewName)
	}
	if _, err := sunRunStrict(ctx, rt, "usermod", "-l", a.NewName, a.Name); err != nil {
		return nil, err
	}
	post, ok, err := sunUserShow(ctx, rt, a.NewName)
	if err != nil || !ok {
		return false, err
	}
	return post.name == a.NewName, nil
}
