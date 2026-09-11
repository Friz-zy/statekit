//go:build darwin

package user

// R6.10 mock tests for the Darwin user surface, mapped onto
// saltstack/salt/modules/mac_user.py @ pinned revision 8b63e700637e
// and tests/pytests/unit/modules/test_mac_user.py: the add/delete
// validation ladder and dscl argv sequence, attribute-change flows
// (same-value short-circuits, old→new change argv), chgroups append
// semantics, list_users/getent, rename, the auto-login defaults
// surface, the pinned kcpassword reference vectors, legacy dscl
// routing and the darwin registry matrix. The runner is a stateful
// in-memory directory-services store; no real binary runs.

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type dsUserRecord struct {
	uid      string
	gid      string
	shell    string
	home     string
	realname string
}

// dsStoreRunner simulates the dscacheutil/id/dscl/defaults/rm tool
// surface against a live user + membership store.
type dsStoreRunner struct {
	users     map[string]dsUserRecord
	members   map[string][]string // group → member users
	primary   map[string]string   // user → primary group
	autoLogin string
	calls     []process.Command
}

func newDSStoreRunner() *dsStoreRunner {
	return &dsStoreRunner{
		users: map[string]dsUserRecord{
			"alice": {uid: "501", gid: "20", shell: "/bin/zsh", home: "/Users/alice", realname: "Alice Example"},
		},
		members: map[string][]string{
			"staff":  {"alice"},
			"devops": {"alice"},
		},
		primary: map[string]string{"alice": "staff"},
	}
}

func (r *dsStoreRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	joined := strings.Join(append([]string{command.Name}, command.Args...), " ")
	switch {
	case command.Name == "dscacheutil" && strings.Contains(joined, "-q user -a name"):
		name := command.Args[len(command.Args)-1]
		if record, ok := r.users[name]; ok {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(userRecord(name, record))}
		}
		return process.CommandResult{ExitCode: 0}
	case command.Name == "dscacheutil":
		var out []string
		for name, record := range r.users {
			out = append(out, userRecord(name, record))
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(strings.Join(out, "\n\n"))}
	case command.Name == "id" && command.Args[0] == "-Gn":
		name := command.Args[len(command.Args)-1]
		return process.CommandResult{ExitCode: 0, Stdout: []byte(strings.Join(r.groupsOf(name), " "))}
	case command.Name == "id" && command.Args[0] == "-g":
		return process.CommandResult{ExitCode: 0, Stdout: []byte(r.primary[command.Args[len(command.Args)-1]])}
	case command.Name == "dscl" && command.Args[1] == "-list":
		return process.CommandResult{ExitCode: 0, Stdout: []byte("alice bob carol")}
	case command.Name == "dscl":
		// argv: dscl <source> <verb> <path> [fields...]
		return r.dsclMutate(command.Args[1], command.Args[2], command.Args[3:])
	case command.Name == "defaults" && command.Args[0] == "read":
		if r.autoLogin == "" {
			return process.CommandResult{ExitCode: 1, Stderr: []byte("Domain /Library/Preferences/com.apple.loginwindow.plist does not exist")}
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(r.autoLogin)}
	case command.Name == "defaults" && command.Args[0] == "write":
		r.autoLogin = command.Args[len(command.Args)-1]
		return process.CommandResult{ExitCode: 0}
	case command.Name == "defaults" && command.Args[0] == "delete":
		r.autoLogin = ""
		return process.CommandResult{ExitCode: 0}
	case command.Shell && strings.HasPrefix(command.Name, "rm -f /etc/kcpassword"):
		return process.CommandResult{ExitCode: 0}
	}
	return process.CommandResult{ExitCode: 0}
}

func (r *dsStoreRunner) groupsOf(name string) []string {
	groups := []string{}
	if primary, ok := r.primary[name]; ok {
		groups = append(groups, primary)
	}
	for group, members := range r.members {
		if group == r.primary[name] {
			continue
		}
		for _, member := range members {
			if member == name {
				groups = append(groups, group)
				break
			}
		}
	}
	return groups
}

// dsclMutate applies create/change/delete/append verbs against the
// store so post-change verification reads observe the mutation.
func (r *dsStoreRunner) dsclMutate(verb, path string, fields []string) process.CommandResult {
	switch {
	case strings.HasPrefix(path, "/Users/") && len(fields) == 0 && verb == "-delete":
		delete(r.users, strings.TrimPrefix(path, "/Users/"))
	case strings.HasPrefix(path, "/Users/") && verb == "-create":
		name := strings.TrimPrefix(path, "/Users/")
		record := r.users[name]
		switch fields[0] {
		case "UniqueID":
			record.uid = fields[1]
		case "PrimaryGroupID":
			record.gid = fields[1]
		case "UserShell":
			record.shell = fields[1]
		case "NFSHomeDirectory":
			record.home = fields[1]
		case "RealName":
			record.realname = strings.Join(fields[1:], " ")
		}
		r.users[name] = record
	case strings.HasPrefix(path, "/Users/") && verb == "-change" && len(fields) == 3 && fields[0] == "RecordName":
		record := r.users[fields[1]]
		delete(r.users, fields[1])
		r.users[fields[2]] = record
	case strings.HasPrefix(path, "/Users/") && verb == "-change" && len(fields) == 3:
		name := strings.TrimPrefix(path, "/Users/")
		record := r.users[name]
		switch fields[0] {
		case "UniqueID":
			record.uid = fields[2]
		case "PrimaryGroupID":
			record.gid = fields[2]
		case "UserShell":
			record.shell = fields[2]
		case "NFSHomeDirectory":
			record.home = fields[2]
		}
		r.users[name] = record
	case strings.HasPrefix(path, "/Groups/") && len(fields) >= 2:
		group := strings.TrimPrefix(path, "/Groups/")
		member := fields[len(fields)-1]
		switch verb {
		case "-append":
			r.members[group] = append(r.members[group], member)
		case "-delete":
			var kept []string
			for _, existing := range r.members[group] {
				if existing != member {
					kept = append(kept, existing)
				}
			}
			r.members[group] = kept
		}
	}
	return process.CommandResult{ExitCode: 0}
}

func userRecord(name string, record dsUserRecord) string {
	return fmt.Sprintf("name: %s\nuid: %s\ngid: %s\ndir: %s\nshell: %s\ngecos: %s\n",
		name, record.uid, record.gid, record.home, record.shell, record.realname)
}

func dsUserRT(t *testing.T) (*runtime.Runtime, *dsStoreRunner) {
	t.Helper()
	macUserCacheMu.Lock()
	saved := macUserCache
	macUserCache = nil
	macUserCacheMu.Unlock()
	t.Cleanup(func() {
		macUserCacheMu.Lock()
		macUserCache = saved
		macUserCacheMu.Unlock()
	})
	oldSleep := sleepMac
	sleepMac = func(time.Duration) {}
	t.Cleanup(func() { sleepMac = oldSleep })
	runner := newDSStoreRunner()
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}, runner
}

func dsuArgv(command process.Command) string {
	return strings.Join(append([]string{command.Name}, command.Args...), " ")
}

func dsclCalls(r *dsStoreRunner) []string {
	var out []string
	for _, command := range r.calls {
		if command.Name == "dscl" {
			out = append(out, dsuArgv(command))
		}
	}
	return out
}

func shellCommands(r *dsStoreRunner) []string {
	var out []string
	for _, command := range r.calls {
		if command.Shell {
			out = append(out, command.Name)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// add

func TestDarwinAddUserValidation(t *testing.T) {
	rt, runner := dsUserRT(t)
	_, err := (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{Name: "alice"})
	if err == nil || err.Error() != "User 'alice' already exists" {
		t.Fatalf("exists = %v", err)
	}
	_, err = (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{Name: "foo bar"})
	if err == nil || err.Error() != "Username cannot contain whitespace" {
		t.Fatalf("whitespace = %v", err)
	}
	negative := -1
	_, err = (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{Name: "foo", UID: &negative})
	if err == nil || err.Error() != "uid must be an integer" {
		t.Fatalf("uid int = %v", err)
	}
	_, err = (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{Name: "foo", GID: &negative})
	if err == nil || err.Error() != "gid must be an integer" {
		t.Fatalf("gid int = %v", err)
	}
	if len(dsclCalls(runner)) != 0 {
		t.Fatalf("validation ladder reached dscl: %v", dsclCalls(runner))
	}
}

func TestDarwinAddUserArgvSequence(t *testing.T) {
	rt, runner := dsUserRT(t)
	uid, gid := 900, 100
	home, shell, fullname := "/Users/op", "/bin/sh", "Op User"
	noHome := false
	res, err := (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{
		Name: "op", UID: &uid, GID: &gid, Home: &home, Shell: &shell,
		Fullname: &fullname, CreateHome: &noHome,
	})
	if err != nil || res != true {
		t.Fatalf("add = %v %v", res, err)
	}
	var creates []string
	for _, argv := range dsclCalls(runner) {
		if strings.Contains(argv, "-create") {
			creates = append(creates, argv)
		}
	}
	want := []string{
		"dscl localhost -create /Local/Default/Users/op UniqueID 900",
		"dscl localhost -create /Local/Default/Users/op PrimaryGroupID 100",
		"dscl localhost -create /Local/Default/Users/op UserShell /bin/sh",
		"dscl localhost -create /Local/Default/Users/op NFSHomeDirectory /Users/op",
		"dscl localhost -create /Local/Default/Users/op RealName Op User",
	}
	if !reflect.DeepEqual(creates, want) {
		t.Fatalf("create sequence = %v", creates)
	}
	// createhome=False must not build the home directory
	if _, err := rt.FS.Stat("/Users/op"); err == nil {
		t.Fatal("createhome=False created the home directory")
	}
}

func TestDarwinAddUserDefaultsAndHome(t *testing.T) {
	rt, runner := dsUserRT(t)
	res, err := (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{Name: "bob"})
	if err != nil || res != true {
		t.Fatalf("add = %v %v", res, err)
	}
	// first free uid after 501, default gid 20, default shell bash
	seen := map[string]string{}
	for _, argv := range dsclCalls(runner) {
		switch {
		case strings.Contains(argv, "UniqueID"):
			seen["uid"] = argv
		case strings.Contains(argv, "PrimaryGroupID"):
			seen["gid"] = argv
		case strings.Contains(argv, "UserShell"):
			seen["shell"] = argv
		}
	}
	if !strings.HasSuffix(seen["uid"], "UniqueID 502") {
		t.Fatalf("first free uid = %q", seen["uid"])
	}
	if !strings.HasSuffix(seen["gid"], "PrimaryGroupID 20") {
		t.Fatalf("default gid = %q", seen["gid"])
	}
	if !strings.HasSuffix(seen["shell"], "UserShell /bin/bash") {
		t.Fatalf("default shell = %q", seen["shell"])
	}
	// default home is created with createhome defaulting to true
	info, err := rt.FS.Stat("/Users/bob")
	if err != nil || info.IsDir() != true {
		t.Fatalf("default home missing: %v", err)
	}
}

func TestDarwinAddUserGroupsAppend(t *testing.T) {
	rt, runner := dsUserRT(t)
	res, err := (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{
		Name: "carol", Groups: []string{"devops"},
	})
	if err != nil || res != true {
		t.Fatalf("add with groups = %v %v", res, err)
	}
	var appends []string
	for _, argv := range dsclCalls(runner) {
		if strings.Contains(argv, "-append") {
			appends = append(appends, argv)
		}
	}
	if len(appends) != 1 || appends[0] != "dscl localhost -append /Local/Default/Groups/devops GroupMembership carol" {
		t.Fatalf("group appends = %v", appends)
	}
}

// ---------------------------------------------------------------------------
// delete / getent / list_users

func TestDarwinDeleteUserFlows(t *testing.T) {
	rt, runner := dsUserRT(t)
	ctx := context.Background()
	// missing user is a no-op True (pytest test_delete_user_exists)
	res, err := (macDeleteFunc{}).Execute(ctx, rt, &macDeleteArgs{Name: "ghost"})
	if err != nil || res != true {
		t.Fatalf("missing delete = %v %v", res, err)
	}
	if _, err := (macDeleteFunc{}).Execute(ctx, rt, &macDeleteArgs{Name: "foo bar"}); err == nil ||
		err.Error() != "Username cannot contain whitespace" {
		t.Fatalf("whitespace delete = %v", err)
	}
	// remove=True also deletes the home directory from the FS
	if err := rt.FS.MkdirAll("/Users/alice", 0o755); err != nil {
		t.Fatal(err)
	}
	res, err = (macDeleteFunc{}).Execute(ctx, rt, &macDeleteArgs{Name: "alice", Remove: true})
	if err != nil || res != true {
		t.Fatalf("delete = %v %v", res, err)
	}
	var deleteCall string
	for _, argv := range dsclCalls(runner) {
		if strings.Contains(argv, "-delete /Local/Default/Users/alice") {
			deleteCall = argv
		}
	}
	if deleteCall != "dscl localhost -delete /Local/Default/Users/alice" {
		t.Fatalf("delete argv = %q", deleteCall)
	}
	if _, err := rt.FS.Stat("/Users/alice"); err == nil {
		t.Fatal("remove=True did not delete the home directory")
	}
}

func TestDarwinGetentAndListUsers(t *testing.T) {
	rt, runner := dsUserRT(t)
	ctx := context.Background()
	res, err := (macGetentFunc{}).Execute(ctx, rt, &macGetentArgs{})
	if err != nil {
		t.Fatal(err)
	}
	users := res.([]map[string]any)
	if len(users) != 1 || users[0]["name"] != "alice" || users[0]["uid"] != 501 {
		t.Fatalf("getent = %#v", users)
	}
	if groups := users[0]["groups"].([]string); len(groups) != 2 {
		t.Fatalf("getent groups = %v", groups)
	}
	afterFirst := len(runner.calls)
	// cached getent does not re-query
	if _, err := (macGetentFunc{}).Execute(ctx, rt, &macGetentArgs{}); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != afterFirst {
		t.Fatalf("cache re-queried: %d calls", len(runner.calls)-afterFirst)
	}
	// refresh does
	if _, err := (macGetentFunc{}).Execute(ctx, rt, &macGetentArgs{Refresh: true}); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) == afterFirst {
		t.Fatal("refresh did not re-query")
	}
	res, err = (macListUsersFunc{}).Execute(ctx, rt, &macListUsersArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res, []string{"alice", "bob", "carol"}) {
		t.Fatalf("list_users = %#v", res)
	}
	var listArgv string
	for _, argv := range dsclCalls(runner) {
		if strings.Contains(argv, "-list") {
			listArgv = argv
		}
	}
	if listArgv != "dscl localhost -list /Local/Default/users" {
		t.Fatalf("list_users argv = %q", listArgv)
	}
}

func TestDarwinFirstAvailableUID(t *testing.T) {
	rt, _ := dsUserRT(t)
	// alice holds 501; the next free uid is 502
	if got := firstAvailableUID(context.Background(), rt); got != 502 {
		t.Fatalf("first available uid = %d", got)
	}
	// a full 501..503 block pushes the scan onward
	runner := rt.Runner.(*dsStoreRunner)
	runner.users["bob"] = dsUserRecord{uid: "502", gid: "20"}
	runner.users["carol"] = dsUserRecord{uid: "503", gid: "20"}
	if got := firstAvailableUID(context.Background(), rt); got != 504 {
		t.Fatalf("packed uid = %d", got)
	}
}

// ---------------------------------------------------------------------------
// attribute changes

func TestDarwinAttributeChangeValidation(t *testing.T) {
	rt, _ := dsUserRT(t)
	ctx := context.Background()
	// missing user error text (pytest chuid/chgid/chshell/chhome/chfullname)
	_, err := (macChuidFunc{}).Execute(ctx, rt, &macChuidArgs{Name: "ghost", UID: 1})
	if err == nil || err.Error() != "User 'ghost' does not exist" {
		t.Fatalf("chuid missing = %v", err)
	}
	_, err = (macChgidFunc{}).Execute(ctx, rt, &macChgidArgs{Name: "ghost", GID: 1})
	if err == nil || err.Error() != "User 'ghost' does not exist" {
		t.Fatalf("chgid missing = %v", err)
	}
	_, err = (macChshellFunc{}).Execute(ctx, rt, &macChshellArgs{Name: "ghost", Shell: "/bin/sh"})
	if err == nil || err.Error() != "User 'ghost' does not exist" {
		t.Fatalf("chshell missing = %v", err)
	}
	_, err = (macChhomeFunc{}).Execute(ctx, rt, &macChhomeArgs{Name: "ghost", Home: "/x"})
	if err == nil || err.Error() != "User 'ghost' does not exist" {
		t.Fatalf("chhome missing = %v", err)
	}
	_, err = (macChfullnameFunc{}).Execute(ctx, rt, &macChfullnameArgs{Name: "ghost", Fullname: "X"})
	if err == nil || err.Error() != "User 'ghost' does not exist" {
		t.Fatalf("chfullname missing = %v", err)
	}
}

func TestDarwinAttributeChangesSameValueShortCircuit(t *testing.T) {
	rt, runner := dsUserRT(t)
	ctx := context.Background()
	steps := []func() (any, error){
		func() (any, error) { return (macChuidFunc{}).Execute(ctx, rt, &macChuidArgs{Name: "alice", UID: 501}) },
		func() (any, error) { return (macChgidFunc{}).Execute(ctx, rt, &macChgidArgs{Name: "alice", GID: 20}) },
		func() (any, error) {
			return (macChshellFunc{}).Execute(ctx, rt, &macChshellArgs{Name: "alice", Shell: "/bin/zsh"})
		},
		func() (any, error) {
			return (macChhomeFunc{}).Execute(ctx, rt, &macChhomeArgs{Name: "alice", Home: "/Users/alice"})
		},
		func() (any, error) {
			return (macChfullnameFunc{}).Execute(ctx, rt, &macChfullnameArgs{Name: "alice", Fullname: "Alice Example"})
		},
	}
	for _, step := range steps {
		before := len(dsclCalls(runner))
		res, err := step()
		if err != nil || res != true {
			t.Fatalf("same-value change = %v %v", res, err)
		}
		if len(dsclCalls(runner)) != before {
			t.Fatal("same-value change must not issue dscl commands")
		}
	}
}

func TestDarwinAttributeChangeArgv(t *testing.T) {
	rt, runner := dsUserRT(t)
	ctx := context.Background()
	steps := []func() (any, error){
		func() (any, error) { return (macChuidFunc{}).Execute(ctx, rt, &macChuidArgs{Name: "alice", UID: 600}) },
		func() (any, error) { return (macChgidFunc{}).Execute(ctx, rt, &macChgidArgs{Name: "alice", GID: 80}) },
		func() (any, error) {
			return (macChshellFunc{}).Execute(ctx, rt, &macChshellArgs{Name: "alice", Shell: "/bin/sh"})
		},
		func() (any, error) {
			return (macChhomeFunc{}).Execute(ctx, rt, &macChhomeArgs{Name: "alice", Home: "/Users/alice2"})
		},
	}
	for _, step := range steps {
		res, err := step()
		if err != nil || res != true {
			t.Fatalf("change = %v %v", res, err)
		}
	}
	var changes []string
	for _, argv := range dsclCalls(runner) {
		if strings.Contains(argv, "-change") {
			changes = append(changes, argv)
		}
	}
	want := []string{
		"dscl localhost -change /Local/Default/Users/alice UniqueID 501 600",
		"dscl localhost -change /Local/Default/Users/alice PrimaryGroupID 20 80",
		"dscl localhost -change /Local/Default/Users/alice UserShell /bin/zsh /bin/sh",
		"dscl localhost -change /Local/Default/Users/alice NFSHomeDirectory /Users/alice /Users/alice2",
	}
	if !reflect.DeepEqual(changes, want) {
		t.Fatalf("change argv = %v", changes)
	}
	// chfullname uses -create with the new value only (Salt ctype default)
	res, err := (macChfullnameFunc{}).Execute(ctx, rt, &macChfullnameArgs{Name: "alice", Fullname: "Alice Renamed"})
	if err != nil || res != true {
		t.Fatalf("chfullname = %v %v", res, err)
	}
	found := false
	for _, argv := range dsclCalls(runner) {
		if argv == "dscl localhost -create /Local/Default/Users/alice RealName Alice Renamed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("chfullname argv missing: %v", dsclCalls(runner))
	}
	// verification read observed the mutations
	info := macUserInfo(ctx, rt, "alice")
	if info["uid"] != 600 || info["gid"] != 80 || info["shell"] != "/bin/sh" ||
		info["home"] != "/Users/alice2" || info["fullname"] != "Alice Renamed" {
		t.Fatalf("post-change info = %#v", info)
	}
}

func TestDarwinRename(t *testing.T) {
	rt, runner := dsUserRT(t)
	ctx := context.Background()
	_, err := (macRenameFunc{}).Execute(ctx, rt, &macRenameArgs{Name: "ghost", NewName: "new"})
	if err == nil || err.Error() != "User 'ghost' does not exist" {
		t.Fatalf("rename missing = %v", err)
	}
	runner.users["taken"] = dsUserRecord{uid: "502", gid: "20"}
	_, err = (macRenameFunc{}).Execute(ctx, rt, &macRenameArgs{Name: "alice", NewName: "taken"})
	if err == nil || err.Error() != "User 'taken' already exists" {
		t.Fatalf("rename onto existing = %v", err)
	}
	res, err := (macRenameFunc{}).Execute(ctx, rt, &macRenameArgs{Name: "alice", NewName: "alicia"})
	if err != nil || res != true {
		t.Fatalf("rename = %v %v", res, err)
	}
	found := false
	for _, argv := range dsclCalls(runner) {
		if argv == "dscl localhost -change /Local/Default/Users/alice RecordName alice alicia" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rename argv missing: %v", dsclCalls(runner))
	}
	if _, exists := runner.users["alicia"]; !exists {
		t.Fatal("store did not observe the rename")
	}
}

// ---------------------------------------------------------------------------
// groups

func TestDarwinChgroups(t *testing.T) {
	rt, runner := dsUserRT(t)
	ctx := context.Background()
	_, err := (macChgroupsFunc{}).Execute(ctx, rt, &macChgroupsArgs{Name: "ghost", Groups: []string{"staff"}})
	if err == nil || err.Error() != "User 'ghost' does not exist" {
		t.Fatalf("chgroups missing = %v", err)
	}
	_, err = (macChgroupsFunc{}).Execute(ctx, rt, &macChgroupsArgs{Name: "alice", Groups: []string{"bad group"}})
	if err == nil || err.Error() != "Invalid group name(s): bad group" {
		t.Fatalf("chgroups whitespace group = %v", err)
	}
	// alice is in staff(primary)+devops; desired staff only → drop devops
	res, err := (macChgroupsFunc{}).Execute(ctx, rt, &macChgroupsArgs{Name: "alice", Groups: []string{"staff"}})
	if err != nil || res != true {
		t.Fatalf("chgroups drop = %v %v", res, err)
	}
	var dropArgv string
	for _, argv := range dsclCalls(runner) {
		if strings.Contains(argv, "-delete /Local/Default/Groups/devops") {
			dropArgv = argv
		}
	}
	if dropArgv != "dscl localhost -delete /Local/Default/Groups/devops GroupMembership alice" {
		t.Fatalf("drop argv = %q", dropArgv)
	}
	// append=True keeps groups not mentioned in the desired list
	runner.calls = nil
	res, err = macChgroupsImpl(ctx, rt, "alice", []string{"news"}, true)
	if err != nil || res != true {
		t.Fatalf("chgroups append = %v %v", res, err)
	}
	if got := runner.groupsOf("alice"); !reflect.DeepEqual(got, []string{"staff", "news"}) {
		t.Fatalf("append groups = %v", got)
	}
	// the primary group is always retained (Salt keeps file.gid_to_group)
	runner.calls = nil
	res, err = macChgroupsImpl(ctx, rt, "alice", []string{"devops"}, false)
	if err != nil || res != true {
		t.Fatalf("chgroups primary retention = %v %v", res, err)
	}
	if got := runner.groupsOf("alice"); !containsStr(got, "staff") {
		t.Fatalf("primary dropped: %v", got)
	}
	// same desired set short-circuits to True with zero dscl calls
	runner.calls = nil
	desired := runner.groupsOf("alice")
	res, err = macChgroupsImpl(ctx, rt, "alice", desired, false)
	if err != nil || res != true {
		t.Fatalf("chgroups same = %v %v", res, err)
	}
	if len(dsclCalls(runner)) != 0 {
		t.Fatalf("same set issued dscl commands: %v", dsclCalls(runner))
	}
}

func containsStr(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestDarwinPrimaryAndListGroups(t *testing.T) {
	rt, runner := dsUserRT(t)
	ctx := context.Background()
	if got := macPrimaryGroup(ctx, rt, "alice"); got != "staff" {
		t.Fatalf("primary group = %q", got)
	}
	if got := macUserGroups(ctx, rt, "alice"); !reflect.DeepEqual(got, []string{"staff", "devops"}) {
		t.Fatalf("groups = %v", got)
	}
	var primaryArgv, groupsArgv string
	for _, command := range runner.calls {
		joined := dsuArgv(command)
		switch {
		case strings.HasPrefix(joined, "id -g"):
			primaryArgv = joined
		case strings.HasPrefix(joined, "id -Gn"):
			groupsArgv = joined
		}
	}
	if primaryArgv != "id -g -n alice" {
		t.Fatalf("primary argv = %q", primaryArgv)
	}
	if groupsArgv != "id -Gn alice" {
		t.Fatalf("groups argv = %q", groupsArgv)
	}
	if got := (macPrimaryGroupFunc{}).Name(); got != "user.primary_group" {
		t.Fatalf("primary name = %q", got)
	}
}

// ---------------------------------------------------------------------------
// auto-login

func TestDarwinAutoLogin(t *testing.T) {
	rt, runner := dsUserRT(t)
	ctx := context.Background()
	// no auto-login set → False
	res, err := (macGetAutoLoginFunc{}).Execute(ctx, rt, &macGetAutoLoginArgs{})
	if err != nil || res != false {
		t.Fatalf("get_auto_login unset = %v %v", res, err)
	}
	// enable writes the defaults entry and the obfuscated kcpassword file
	res, err = (macEnableAutoLoginFunc{}).Execute(ctx, rt, &macEnableAutoLoginArgs{Name: "alice", Password: "password"})
	if err != nil || res != true {
		t.Fatalf("enable_auto_login = %v %v", res, err)
	}
	var writeArgv string
	for _, command := range runner.calls {
		if strings.HasPrefix(dsuArgv(command), "defaults write") {
			writeArgv = dsuArgv(command)
		}
	}
	if writeArgv != "defaults write /Library/Preferences/com.apple.loginwindow.plist autoLoginUser alice" {
		t.Fatalf("write argv = %q", writeArgv)
	}
	kcp, err := rt.FS.ReadFile("/etc/kcpassword")
	if err != nil {
		t.Fatal(err)
	}
	want, kerr := kcpassword("password")
	if kerr != nil || !bytes.Equal(kcp, want) {
		t.Fatalf("kcpassword file = % x; want % x", kcp, want)
	}
	res, err = (macGetAutoLoginFunc{}).Execute(ctx, rt, &macGetAutoLoginArgs{})
	if err != nil || res != "alice" {
		t.Fatalf("get_auto_login = %v %v", res, err)
	}
	// disable removes both artifacts
	res, err = (macDisableAutoLoginFunc{}).Execute(ctx, rt, &macDisableAutoLoginArgs{})
	if err != nil || res != true {
		t.Fatalf("disable_auto_login = %v %v", res, err)
	}
	shells := shellCommands(runner)
	if len(shells) == 0 || shells[len(shells)-1] != "rm -f /etc/kcpassword" {
		t.Fatalf("rm shell commands = %v", shells)
	}
	var deleteArgv string
	for _, command := range runner.calls {
		if strings.HasPrefix(dsuArgv(command), "defaults delete") {
			deleteArgv = dsuArgv(command)
		}
	}
	if deleteArgv != "defaults delete /Library/Preferences/com.apple.loginwindow.plist autoLoginUser" {
		t.Fatalf("delete argv = %q", deleteArgv)
	}
	res, err = (macGetAutoLoginFunc{}).Execute(ctx, rt, &macGetAutoLoginArgs{})
	if err != nil || res != false {
		t.Fatalf("post-disable get_auto_login = %v %v", res, err)
	}
}

// ---------------------------------------------------------------------------
// kcpassword reference vectors (tests/pytests test_kcpassword)

func TestDarwinKcpasswordReferenceVectors(t *testing.T) {
	// Obfuscations recorded from macOS: the deterministic port
	// reproduces the password-byte region and the padded length for
	// every vector; macOS pads the region beyond the trailing null with
	// random bytes, so those tail bytes are not asserted per vector.
	vectors := map[string]string{
		"0":                        "4d 89 f9 91 1f 7a 46 5e f7 a8 11 ff",
		"password":                 "0d e8 21 50 a5 d3 af 8e a3 de d9 14",
		"shorterpwd":               "0e e1 3d 51 a6 d9 af 9a d4 dd 1f 27",
		"Squarepants":              "2e f8 27 42 a0 d9 ad 8b cd cd 6c 7d",
		"longerpasswd":             "11 e6 3c 44 b7 ce ad 8b d0 ca 68 19 89 b1 65 ae 7e 89 12 b8 51 f8 f0 ff",
		"ridiculouslyextendedpass": "0f e0 36 4a b1 c9 b1 85 d6 ca 73 04 ec 2a 57 b7 d2 b9 8f c7 c9 7e 0e fa 52 7b 71 e6 f8 b7 a6 ae 47 94 d7 86",
	}
	for password, hash := range vectors {
		recorded := hexBytes(t, hash)
		got, err := kcpassword(password)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got[:len(password)], recorded[:len(password)]) {
			t.Fatalf("%q password region = % x; recorded % x", password, got, recorded)
		}
		if len(got) != len(recorded) {
			t.Fatalf("%q length = %d; recorded %d", password, len(got), len(recorded))
		}
	}
	// the deterministic null+padding tail is pinned exactly: the null is
	// XORed with the first key byte and zero padding stays zero-XORed.
	got, err := kcpassword("password")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x0d, 0xe8, 0x21, 0x50, 0xa5, 0xd3, 0xaf, 0x8e, 0xa3, 0xb9, 0x1f, 0x7d}
	if !bytes.Equal(got, want) {
		t.Fatalf("deterministic kcpassword = % x; want % x", got, want)
	}
	// 11-char passwords need no padding, so the recorded macOS hash is
	// fully deterministic and matches byte-for-byte.
	recorded := hexBytes(t, "2e f8 27 42 a0 d9 ad 8b cd cd 6c 7d")
	got, err = kcpassword("Squarepants")
	if err != nil || !bytes.Equal(got, recorded) {
		t.Fatalf("Squarepants = % x; recorded % x", got, recorded)
	}
}

func hexBytes(t *testing.T, spaced string) []byte {
	t.Helper()
	fields := strings.Fields(spaced)
	out := make([]byte, len(fields))
	for i, field := range fields {
		value := 0
		if _, err := fmt.Sscanf(field, "%02x", &value); err != nil {
			t.Fatalf("hex field %q: %v", field, err)
		}
		out[i] = byte(value)
	}
	return out
}

// ---------------------------------------------------------------------------
// legacy dscl routing and parsing helpers

func TestDarwinLegacyDSCLTable(t *testing.T) {
	vectors := []struct {
		version string
		legacy  bool
	}{
		{"10.7.5", true},
		{"10.7", true},
		{"10.8.0", false},
		{"10.9.1", false},
		{"11.0", false},
		{"14.4.1", false},
		{"banana", false},
		{"10.x.1", false},
		{"", false},
	}
	for _, vector := range vectors {
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Version: vector.version}})}
		if got := legacyDSCL(rt); got != vector.legacy {
			t.Fatalf("legacyDSCL(%q) = %v; want %v", vector.version, got, vector.legacy)
		}
	}
	if legacyDSCL(nil) {
		t.Fatal("nil runtime must not select legacy dscl")
	}
	rt := &runtime.Runtime{Runner: newDSStoreRunner(), FS: runtime.NewMemoryFS()}
	pathVectors := map[string]string{
		"/Users/alice":               "/Local/Default/Users/alice",
		"/Local/Default/Users/alice": "/Local/Default/Users/alice",
		"RelativePath":               "RelativePath",
	}
	for input, want := range pathVectors {
		if got := dsclPath(rt, input); got != want {
			t.Fatalf("dsclPath(%q) = %q; want %q", input, got, want)
		}
	}
	legacy := &runtime.Runtime{
		Runner: newDSStoreRunner(),
		Facts:  facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Version: "10.7.5"}}),
		FS:     runtime.NewMemoryFS(),
	}
	if got := dsclPath(legacy, "/Users/alice"); got != "/Users/alice" {
		t.Fatalf("legacy dsclPath = %q", got)
	}
}

func TestDarwinParseRecordsAndRecordInfo(t *testing.T) {
	output := "name: alice\nuid: 501\ngid: 20\n\n" +
		"RecordName: bob\nRealName: Bob B\ndir: /Users/bob\nuid: 502\n"
	records := parseRecords(output)
	if len(records) != 2 {
		t.Fatalf("records = %#v", records)
	}
	first := userRecordInfo(records[0])
	if first["name"] != "alice" || first["uid"] != 501 || first["home"] != "" {
		t.Fatalf("first record info = %#v", first)
	}
	second := userRecordInfo(records[1])
	if second["name"] != "bob" || second["fullname"] != "Bob B" || second["home"] != "/Users/bob" {
		t.Fatalf("second record info = %#v", second)
	}
	// name falls back to RecordName; gecos falls back to RealName
	info := userRecordInfo(map[string]string{"RecordName": "carl", "RealName": "Carl C", "uid": "503"})
	if info["name"] != "carl" || info["fullname"] != "Carl C" || info["uid"] != 503 {
		t.Fatalf("fallback info = %#v", info)
	}
	if got := recordInt(map[string]string{"uid": "not-a-number"}, "uid"); got != 0 {
		t.Fatalf("recordInt parse failure = %d", got)
	}
}

// ---------------------------------------------------------------------------
// registry matrix

func TestDarwinUserRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerMac(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"user.add",
		"user.chfullname",
		"user.chgid",
		"user.chgroups",
		"user.chhome",
		"user.chshell",
		"user.chuid",
		"user.delete",
		"user.disable_auto_login",
		"user.enable_auto_login",
		"user.get_auto_login",
		"user.getent",
		"user.info",
		"user.list_groups",
		"user.list_users",
		"user.primary_group",
		"user.rename",
	}
	if names := reg.Names(); !reflect.DeepEqual(names, want) {
		t.Fatalf("names = %v", names)
	}
	for _, name := range want {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok {
			t.Fatalf("%s is not platform-constrained", name)
		}
		platforms := constrained.Platforms()
		if len(platforms) != 1 || platforms[0] != "darwin" {
			t.Fatalf("%s platforms = %v", name, platforms)
		}
	}
}
