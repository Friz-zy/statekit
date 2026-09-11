package user

// FreeBSD virtual user implementation for Salt's pw_user module
// (saltstack/salt/modules/pw_user.py @ pinned revision 8b63e700637e,
// tests/pytests/unit/modules/test_pw_user.py). The pinned source reads
// the user database through Python's pwd module; StateKit routes the
// same master.passwd-shaped records through `pw usershow -7` (and
// `pw groupshow` for membership) via the central shell-free Runner, the
// format the module header documents. The surface is untagged so the
// Linux test host can exercise every provider function directly with a
// recording fake Runner; Platforms() provides the freebsd-only gating
// (mirroring Salt's __virtual__ FreeBSD/DragonFly check). user.Register
// selects this surface on GOOS=freebsd.

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func registerFreeBSD(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		pwAddFunc{}, pwDeleteFunc{}, pwGetentFunc{}, pwChuidFunc{}, pwChgidFunc{},
		pwChshellFunc{}, pwChhomeFunc{}, pwChgroupsFunc{}, pwChfullnameFunc{},
		pwChroomnumberFunc{}, pwChworkphoneFunc{}, pwChhomephoneFunc{}, pwChloginclassFunc{},
		pwInfoFunc{}, pwGetLoginclassFunc{}, pwListGroupsFunc{}, pwListUsersFunc{},
		pwPrimaryGroupFunc{}, pwRenameFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// pwRun is the bounded shell-free Runner bridge. Cancellation is checked
// before any process starts; Runner errors (including a missing pw
// binary) surface as errors, never as fabricated success.
func pwRun(ctx context.Context, rt *runtime.Runtime, argv ...string) (process.CommandResult, error) {
	if err := ctx.Err(); err != nil {
		return process.CommandResult{}, err
	}
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return res, res.Err
	}
	return res, nil
}

// pwUserEntry is one /etc/master.passwd record as printed by
// `pw usershow -7`: name:passwd:uid:gid:class:change:expire:gecos:home:shell.
type pwUserEntry struct {
	name       string
	passwd     string
	uid        int
	gid        int
	class      string
	change     string
	expire     string
	gecos      string
	home       string
	shell      string
	fullname   string
	roomnumber string
	workphone  string
	homephone  string
}

// pwParseUserLine parses one colon-separated passwd line into the
// GECOS-expanded record shape Salt's pwd access produces. It returns
// false when the line is not a 10-field master.passwd record.
func pwParseUserLine(line string) (pwUserEntry, bool) {
	fields := strings.Split(strings.TrimRight(line, "\n"), ":")
	if len(fields) != 10 {
		return pwUserEntry{}, false
	}
	uid, _ := strconv.Atoi(fields[2])
	gid, _ := strconv.Atoi(fields[3])
	entry := pwUserEntry{
		name:   fields[0],
		passwd: fields[1],
		uid:    uid,
		gid:    gid,
		class:  fields[4],
		change: fields[5],
		expire: fields[6],
		gecos:  fields[7],
		home:   fields[8],
		shell:  fields[9],
	}
	gecosFields := strings.Split(entry.gecos, ",")
	for len(gecosFields) < 4 {
		gecosFields = append(gecosFields, "")
	}
	entry.fullname = gecosFields[0]
	entry.roomnumber = gecosFields[1]
	entry.workphone = gecosFields[2]
	entry.homephone = gecosFields[3]
	return entry, true
}

// pwGroupEntry is one /etc/group record as printed by `pw groupshow`:
// name:passwd:gid:member1,member2.
type pwGroupEntry struct {
	name    string
	passwd  string
	gid     int
	members []string
}

func pwParseGroupLine(line string) (pwGroupEntry, bool) {
	fields := strings.Split(strings.TrimRight(line, "\n"), ":")
	if len(fields) != 4 {
		return pwGroupEntry{}, false
	}
	gid, _ := strconv.Atoi(fields[2])
	members := []string{}
	if fields[3] != "" {
		members = strings.Split(fields[3], ",")
	}
	return pwGroupEntry{name: fields[0], passwd: fields[1], gid: gid, members: members}, true
}

// pwUserShow resolves one user via `pw usershow -n name -7`. A non-zero
// exit (pw: unknown user) means the lookup miss that Salt gets from
// pwd.getpwnam's KeyError.
func pwUserShow(ctx context.Context, rt *runtime.Runtime, name string) (pwUserEntry, bool, error) {
	res, err := pwRun(ctx, rt, "pw", "usershow", "-n", name, "-7")
	if err != nil {
		return pwUserEntry{}, false, err
	}
	if res.ExitCode != 0 {
		return pwUserEntry{}, false, nil
	}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if entry, ok := pwParseUserLine(line); ok && entry.name == name {
			return entry, true, nil
		}
	}
	return pwUserEntry{}, false, nil
}

// pwAllUsers enumerates every record via `pw usershow -a -7` in the
// order pw prints them.
func pwAllUsers(ctx context.Context, rt *runtime.Runtime) ([]pwUserEntry, error) {
	res, err := pwRun(ctx, rt, "pw", "usershow", "-a", "-7")
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, nil
	}
	var users []pwUserEntry
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if entry, ok := pwParseUserLine(line); ok {
			users = append(users, entry)
		}
	}
	return users, nil
}

// pwAllGroups enumerates every group via `pw groupshow -a`.
func pwAllGroups(ctx context.Context, rt *runtime.Runtime) ([]pwGroupEntry, error) {
	res, err := pwRun(ctx, rt, "pw", "groupshow", "-a")
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, nil
	}
	var groups []pwGroupEntry
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if entry, ok := pwParseGroupLine(line); ok {
			groups = append(groups, entry)
		}
	}
	return groups, nil
}

// pwUserInfo is the info()/getent() record shape: gid, groups, home,
// name, passwd, shell, uid plus the four GECOS fields, mirroring the
// pinned info() dict exactly.
func pwUserInfo(ctx context.Context, rt *runtime.Runtime, entry pwUserEntry) (map[string]any, error) {
	groups, err := pwGroupsOf(ctx, rt, entry)
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

// pwGroupsOf reproduces salt.utils.user.get_group_list ordering: the
// primary group first, then every supplementary group listing the user
// as a member.
func pwGroupsOf(ctx context.Context, rt *runtime.Runtime, entry pwUserEntry) ([]string, error) {
	groups, err := pwAllGroups(ctx, rt)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, group := range groups {
		if group.gid == entry.gid {
			out = append(out, group.name)
		}
	}
	for _, group := range groups {
		if group.gid == entry.gid {
			continue
		}
		for _, member := range group.members {
			if member == entry.name {
				out = append(out, group.name)
				break
			}
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// add / delete

type pwAddArgs struct {
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
	Loginclass string   `statekit:"name=loginclass"`
}

type pwAddFunc struct{}

func (pwAddFunc) Name() string        { return "user.add" }
func (pwAddFunc) Args() any           { return pwAddArgs{} }
func (pwAddFunc) Platforms() []string { return []string{"freebsd"} }
func (pwAddFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwAddArgs)
	unique := true
	if a.Unique != nil {
		unique = *a.Unique
	}
	createHome := true
	if a.CreateHome != nil {
		createHome = *a.CreateHome
	}
	argv := []string{"pw", "useradd"}
	if a.UID != "" {
		argv = append(argv, "-u", a.UID)
	}
	if a.GID != "" {
		argv = append(argv, "-g", a.GID)
	}
	if len(a.Groups) > 0 {
		argv = append(argv, "-G", strings.Join(a.Groups, ","))
	}
	if a.Home != nil {
		argv = append(argv, "-d", *a.Home)
	}
	if createHome {
		argv = append(argv, "-m")
	}
	if a.Loginclass != "" {
		argv = append(argv, "-L", a.Loginclass)
	}
	if a.Shell != "" {
		argv = append(argv, "-s", a.Shell)
	}
	if !unique {
		argv = append(argv, "-o")
	}
	gecos := strings.Join([]string{a.Fullname, a.Roomnumber, a.Workphone, a.Homephone}, ",")
	argv = append(argv, "-c", gecos, "-n", a.Name)
	res, err := pwRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	return res.ExitCode == 0, nil
}

type pwDeleteArgs struct {
	Name   string `statekit:"required"`
	Remove bool   `statekit:"name=remove"`
	Force  bool   `statekit:"name=force"`
}

type pwDeleteFunc struct{}

func (pwDeleteFunc) Name() string        { return "user.delete" }
func (pwDeleteFunc) Args() any           { return pwDeleteArgs{} }
func (pwDeleteFunc) Platforms() []string { return []string{"freebsd"} }
func (pwDeleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwDeleteArgs)
	// pw userdel does not support force-deleting a user while logged in;
	// the pinned source only logs that limitation.
	argv := []string{"pw", "userdel"}
	if a.Remove {
		argv = append(argv, "-r")
	}
	argv = append(argv, "-n", a.Name)
	res, err := pwRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	return res.ExitCode == 0, nil
}

// ---------------------------------------------------------------------------
// getent / info / listing

type pwGetentArgs struct {
	Refresh bool `statekit:"name=refresh"`
}

type pwGetentFunc struct{}

func (pwGetentFunc) Name() string        { return "user.getent" }
func (pwGetentFunc) Args() any           { return pwGetentArgs{} }
func (pwGetentFunc) Platforms() []string { return []string{"freebsd"} }
func (pwGetentFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	users, err := pwAllUsers(ctx, rt)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, entry := range users {
		info, err := pwUserInfo(ctx, rt, entry)
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, nil
}

type pwInfoArgs struct {
	Name string `statekit:"required"`
}

type pwInfoFunc struct{}

func (pwInfoFunc) Name() string        { return "user.info" }
func (pwInfoFunc) Args() any           { return pwInfoArgs{} }
func (pwInfoFunc) Platforms() []string { return []string{"freebsd"} }
func (pwInfoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwInfoArgs)
	entry, ok, err := pwUserShow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if !ok {
		// pwd.getpwnam's KeyError maps to the pinned source's empty dict.
		return map[string]any{}, nil
	}
	return pwUserInfo(ctx, rt, entry)
}

type pwListUsersArgs struct{}

type pwListUsersFunc struct{}

func (pwListUsersFunc) Name() string        { return "user.list_users" }
func (pwListUsersFunc) Args() any           { return pwListUsersArgs{} }
func (pwListUsersFunc) Platforms() []string { return []string{"freebsd"} }
func (pwListUsersFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	users, err := pwAllUsers(ctx, rt)
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

type pwListGroupsArgs struct {
	Name string `statekit:"required"`
}

type pwListGroupsFunc struct{}

func (pwListGroupsFunc) Name() string        { return "user.list_groups" }
func (pwListGroupsFunc) Args() any           { return pwListGroupsArgs{} }
func (pwListGroupsFunc) Platforms() []string { return []string{"freebsd"} }
func (pwListGroupsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwListGroupsArgs)
	entry, ok, err := pwUserShow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if !ok {
		// salt.utils.user.get_group_list propagates pwd's KeyError.
		return nil, fmt.Errorf("user %q does not exist", a.Name)
	}
	return pwGroupsOf(ctx, rt, entry)
}

type pwPrimaryGroupArgs struct {
	Name string `statekit:"required"`
}

type pwPrimaryGroupFunc struct{}

func (pwPrimaryGroupFunc) Name() string        { return "user.primary_group" }
func (pwPrimaryGroupFunc) Args() any           { return pwPrimaryGroupArgs{} }
func (pwPrimaryGroupFunc) Platforms() []string { return []string{"freebsd"} }
func (pwPrimaryGroupFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwPrimaryGroupArgs)
	entry, ok, err := pwUserShow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("user %q does not exist", a.Name)
	}
	groups, err := pwAllGroups(ctx, rt)
	if err != nil {
		return nil, err
	}
	for _, group := range groups {
		if group.gid == entry.gid {
			return group.name, nil
		}
	}
	return "", nil
}

// ---------------------------------------------------------------------------
// attribute changes

// pwRequireUser resolves the pre-change record; the pinned source
// raises CommandExecutionError for a missing user.
func pwRequireUser(ctx context.Context, rt *runtime.Runtime, name string) (pwUserEntry, error) {
	entry, ok, err := pwUserShow(ctx, rt, name)
	if err != nil {
		return pwUserEntry{}, err
	}
	if !ok {
		return pwUserEntry{}, fmt.Errorf("User '%s' does not exist", name)
	}
	return entry, nil
}

type pwChuidArgs struct {
	Name string `statekit:"required"`
	UID  string `statekit:"required,name=uid"`
}

type pwChuidFunc struct{}

func (pwChuidFunc) Name() string        { return "user.chuid" }
func (pwChuidFunc) Args() any           { return pwChuidArgs{} }
func (pwChuidFunc) Platforms() []string { return []string{"freebsd"} }
func (pwChuidFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwChuidArgs)
	pre, err := pwRequireUser(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if a.UID == strconv.Itoa(pre.uid) {
		return true, nil
	}
	if _, err := pwRun(ctx, rt, "pw", "usermod", "-u", a.UID, "-n", a.Name); err != nil {
		return nil, err
	}
	post, ok, err := pwUserShow(ctx, rt, a.Name)
	if err != nil || !ok {
		return false, err
	}
	return strconv.Itoa(post.uid) == a.UID, nil
}

type pwChgidArgs struct {
	Name string `statekit:"required"`
	GID  string `statekit:"required,name=gid"`
}

type pwChgidFunc struct{}

func (pwChgidFunc) Name() string        { return "user.chgid" }
func (pwChgidFunc) Args() any           { return pwChgidArgs{} }
func (pwChgidFunc) Platforms() []string { return []string{"freebsd"} }
func (pwChgidFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwChgidArgs)
	pre, err := pwRequireUser(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if a.GID == strconv.Itoa(pre.gid) {
		return true, nil
	}
	if _, err := pwRun(ctx, rt, "pw", "usermod", "-g", a.GID, "-n", a.Name); err != nil {
		return nil, err
	}
	post, ok, err := pwUserShow(ctx, rt, a.Name)
	if err != nil || !ok {
		return false, err
	}
	return strconv.Itoa(post.gid) == a.GID, nil
}

type pwChshellArgs struct {
	Name  string `statekit:"required"`
	Shell string `statekit:"required,name=shell"`
}

type pwChshellFunc struct{}

func (pwChshellFunc) Name() string        { return "user.chshell" }
func (pwChshellFunc) Args() any           { return pwChshellArgs{} }
func (pwChshellFunc) Platforms() []string { return []string{"freebsd"} }
func (pwChshellFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwChshellArgs)
	pre, err := pwRequireUser(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if a.Shell == pre.shell {
		return true, nil
	}
	if _, err := pwRun(ctx, rt, "pw", "usermod", "-s", a.Shell, "-n", a.Name); err != nil {
		return nil, err
	}
	post, ok, err := pwUserShow(ctx, rt, a.Name)
	if err != nil || !ok {
		return false, err
	}
	return post.shell == a.Shell, nil
}

type pwChhomeArgs struct {
	Name    string `statekit:"required"`
	Home    string `statekit:"required,name=home"`
	Persist bool   `statekit:"name=persist"`
}

type pwChhomeFunc struct{}

func (pwChhomeFunc) Name() string        { return "user.chhome" }
func (pwChhomeFunc) Args() any           { return pwChhomeArgs{} }
func (pwChhomeFunc) Platforms() []string { return []string{"freebsd"} }
func (pwChhomeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwChhomeArgs)
	pre, err := pwRequireUser(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if a.Home == pre.home {
		return true, nil
	}
	argv := []string{"pw", "usermod", a.Name, "-d", a.Home}
	if a.Persist {
		argv = append(argv, "-m")
	}
	if _, err := pwRun(ctx, rt, argv...); err != nil {
		return nil, err
	}
	post, ok, err := pwUserShow(ctx, rt, a.Name)
	if err != nil || !ok {
		return false, err
	}
	return post.home == a.Home, nil
}

type pwChgroupsArgs struct {
	Name   string   `statekit:"required"`
	Groups []string `statekit:"required,name=groups"`
	Append bool     `statekit:"name=append"`
}

type pwChgroupsFunc struct{}

func (pwChgroupsFunc) Name() string        { return "user.chgroups" }
func (pwChgroupsFunc) Args() any           { return pwChgroupsArgs{} }
func (pwChgroupsFunc) Platforms() []string { return []string{"freebsd"} }
func (pwChgroupsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwChgroupsArgs)
	entry, ok, err := pwUserShow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("user %q does not exist", a.Name)
	}
	current, err := pwGroupsOf(ctx, rt, entry)
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
	groups := append([]string{}, a.Groups...)
	if a.Append {
		for _, group := range current {
			if !wantSet[group] {
				groups = append(groups, group)
			}
		}
	}
	res, err := pwRun(ctx, rt, "pw", "usermod", "-G", strings.Join(groups, ","), "-n", a.Name)
	if err != nil {
		return nil, err
	}
	return res.ExitCode == 0, nil
}

// ---------------------------------------------------------------------------
// GECOS field updates (_get_gecos / _build_gecos / _update_gecos)

func pwGecosValue(entry pwUserEntry, key string) string {
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

// pwUpdateGecos ports _update_gecos: same-value short-circuits to true,
// a missing record to false, otherwise `pw usermod NAME -c gecos` runs
// and the post-change GECOS field decides the result.
func pwUpdateGecos(ctx context.Context, rt *runtime.Runtime, name, key, value string) (any, error) {
	pre, ok, err := pwUserShow(ctx, rt, name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return false, nil
	}
	if value == pwGecosValue(pre, key) {
		return true, nil
	}
	gecos := strings.Join([]string{
		pwGecosUpdated(pre.fullname, key, "fullname", value),
		pwGecosUpdated(pre.roomnumber, key, "roomnumber", value),
		pwGecosUpdated(pre.workphone, key, "workphone", value),
		pwGecosUpdated(pre.homephone, key, "homephone", value),
	}, ",")
	if _, err := pwRun(ctx, rt, "pw", "usermod", name, "-c", gecos); err != nil {
		return nil, err
	}
	post, ok, err := pwUserShow(ctx, rt, name)
	if err != nil || !ok {
		return false, err
	}
	return pwGecosValue(post, key) == value, nil
}

func pwGecosUpdated(current, key, field, value string) string {
	if key == field {
		return value
	}
	return current
}

type pwChfullnameArgs struct {
	Name     string `statekit:"required"`
	Fullname string `statekit:"required,name=fullname"`
}

type pwChfullnameFunc struct{}

func (pwChfullnameFunc) Name() string        { return "user.chfullname" }
func (pwChfullnameFunc) Args() any           { return pwChfullnameArgs{} }
func (pwChfullnameFunc) Platforms() []string { return []string{"freebsd"} }
func (pwChfullnameFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwChfullnameArgs)
	return pwUpdateGecos(ctx, rt, a.Name, "fullname", a.Fullname)
}

type pwChroomnumberArgs struct {
	Name       string `statekit:"required"`
	Roomnumber string `statekit:"required,name=roomnumber"`
}

type pwChroomnumberFunc struct{}

func (pwChroomnumberFunc) Name() string        { return "user.chroomnumber" }
func (pwChroomnumberFunc) Args() any           { return pwChroomnumberArgs{} }
func (pwChroomnumberFunc) Platforms() []string { return []string{"freebsd"} }
func (pwChroomnumberFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwChroomnumberArgs)
	return pwUpdateGecos(ctx, rt, a.Name, "roomnumber", a.Roomnumber)
}

type pwChworkphoneArgs struct {
	Name      string `statekit:"required"`
	Workphone string `statekit:"required,name=workphone"`
}

type pwChworkphoneFunc struct{}

func (pwChworkphoneFunc) Name() string        { return "user.chworkphone" }
func (pwChworkphoneFunc) Args() any           { return pwChworkphoneArgs{} }
func (pwChworkphoneFunc) Platforms() []string { return []string{"freebsd"} }
func (pwChworkphoneFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwChworkphoneArgs)
	return pwUpdateGecos(ctx, rt, a.Name, "workphone", a.Workphone)
}

type pwChhomephoneArgs struct {
	Name      string `statekit:"required"`
	Homephone string `statekit:"required,name=homephone"`
}

type pwChhomephoneFunc struct{}

func (pwChhomephoneFunc) Name() string        { return "user.chhomephone" }
func (pwChhomephoneFunc) Args() any           { return pwChhomephoneArgs{} }
func (pwChhomephoneFunc) Platforms() []string { return []string{"freebsd"} }
func (pwChhomephoneFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwChhomephoneArgs)
	return pwUpdateGecos(ctx, rt, a.Name, "homephone", a.Homephone)
}

// ---------------------------------------------------------------------------
// login class and rename

func pwGetLoginclass(ctx context.Context, rt *runtime.Runtime, name string) (string, error) {
	// The pinned source runs `pw usershow -n name` WITHOUT -7 and reads
	// field 5 only when the line carries all ten master.passwd fields.
	res, err := pwRun(ctx, rt, "pw", "usershow", "-n", name)
	if err != nil {
		return "", err
	}
	fields := strings.Split(strings.TrimRight(string(res.Stdout), "\n"), ":")
	if len(fields) == 10 {
		return fields[4], nil
	}
	return "", nil
}

type pwGetLoginclassArgs struct {
	Name string `statekit:"required"`
}

type pwGetLoginclassFunc struct{}

func (pwGetLoginclassFunc) Name() string        { return "user.get_loginclass" }
func (pwGetLoginclassFunc) Args() any           { return pwGetLoginclassArgs{} }
func (pwGetLoginclassFunc) Platforms() []string { return []string{"freebsd"} }
func (pwGetLoginclassFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return pwGetLoginclass(ctx, rt, args.(*pwGetLoginclassArgs).Name)
}

type pwChloginclassArgs struct {
	Name       string `statekit:"required"`
	Loginclass string `statekit:"required,name=loginclass"`
}

type pwChloginclassFunc struct{}

func (pwChloginclassFunc) Name() string        { return "user.chloginclass" }
func (pwChloginclassFunc) Args() any           { return pwChloginclassArgs{} }
func (pwChloginclassFunc) Platforms() []string { return []string{"freebsd"} }
func (pwChloginclassFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwChloginclassArgs)
	current, err := pwGetLoginclass(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if a.Loginclass == current {
		return true, nil
	}
	if _, err := pwRun(ctx, rt, "pw", "usermod", "-L", a.Loginclass, "-n", a.Name); err != nil {
		return nil, err
	}
	post, err := pwGetLoginclass(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	return post == a.Loginclass, nil
}

type pwRenameArgs struct {
	Name    string `statekit:"required"`
	NewName string `statekit:"required,name=new_name"`
}

type pwRenameFunc struct{}

func (pwRenameFunc) Name() string        { return "user.rename" }
func (pwRenameFunc) Args() any           { return pwRenameArgs{} }
func (pwRenameFunc) Platforms() []string { return []string{"freebsd"} }
func (pwRenameFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pwRenameArgs)
	current, ok, err := pwUserShow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("User '%s' does not exist", a.Name)
	}
	if _, exists, err := pwUserShow(ctx, rt, a.NewName); err != nil {
		return nil, err
	} else if exists {
		return nil, fmt.Errorf("User '%s' already exists", a.NewName)
	}
	if _, err := pwRun(ctx, rt, "pw", "usermod", "-l", a.NewName, "-n", a.Name); err != nil {
		return nil, err
	}
	post, ok, err := pwUserShow(ctx, rt, a.NewName)
	if err != nil || !ok {
		return false, err
	}
	if post.name != current.name {
		return post.name == a.NewName, nil
	}
	return false, nil
}
