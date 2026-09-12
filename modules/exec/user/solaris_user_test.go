package user

// R8.2 mock tests for the Solaris solaris_user virtual user surface,
// mapped onto saltstack/salt/modules/solaris_user.py @ pinned revision
// 8b63e700637e: the add argv ladder (shell/uid/gid/groups/createhome/
// home/unique order plus the post-add GECOS follow-ups), delete, the
// info/getent/list_users shapes, list_groups unique sorted ordering,
// the chuid/chgid/chshell/chhome same-value short-circuit plus change
// and failed-verification paths, chgroups set semantics, the four GECOS
// field changers, rename error and success paths, cancellation and
// binary-missing boundaries, non-zero cmd.run post-state handling, and
// strict numeric passwd/group parsing. The runner is a stateful in-memory
// getent/useradd store; no real binary runs.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// sunStoreUser is one record in the fake passwd database.
type sunStoreUser struct {
	name  string
	uid   string
	gid   string
	gecos string
	home  string
	shell string
}

func (u sunStoreUser) line() string {
	return strings.Join([]string{u.name, "x", u.uid, u.gid, u.gecos, u.home, u.shell}, ":")
}

// sunStoreGroup is one record in the fake group database.
type sunStoreGroup struct {
	name    string
	gid     string
	members []string
}

func (g sunStoreGroup) line() string {
	return strings.Join([]string{g.name, "x", g.gid, strings.Join(g.members, ",")}, ":")
}

// sunStoreRunner simulates the Solaris tool surface against a live
// user and group store: `getent passwd/group` reads, useradd/userdel/
// usermod writes (solaris usermod takes the login as the final
// positional argument). frozen=true makes mutating verbs succeed
// without applying changes, reproducing the failed-verification paths.
type sunStoreRunner struct {
	users         map[string]sunStoreUser
	groups        map[string]sunStoreGroup
	order         []string
	frozen        bool
	missing       bool
	retcode       int
	retcodeStdout []byte
	retcodeStderr []byte
	groupListing  string
	passwdListing string
	calls         []process.Command
}

func newSunStoreRunner() *sunStoreRunner {
	return &sunStoreRunner{
		users: map[string]sunStoreUser{
			"root":  {name: "root", uid: "0", gid: "0", gecos: "Super-User", home: "/root", shell: "/usr/bin/bash"},
			"alice": {name: "alice", uid: "1001", gid: "10", gecos: "Alice Example,101,555,777", home: "/home/alice", shell: "/bin/bash"},
		},
		groups: map[string]sunStoreGroup{
			"root":   {name: "root", gid: "0", members: []string{}},
			"other":  {name: "other", gid: "1", members: []string{"root"}},
			"staff":  {name: "staff", gid: "10", members: []string{"root"}},
			"devops": {name: "devops", gid: "1002", members: []string{"alice"}},
		},
		order: []string{"root", "alice"},
	}
}

func sunIndexOf(argv []string, flag string) int {
	for i, arg := range argv {
		if arg == flag {
			return i
		}
	}
	return -1
}

func (r *sunStoreRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	missing := process.CommandResult{
		Err:      errors.New("exec: executable file not found in $PATH"),
		ExitCode: -1,
	}
	known := map[string]bool{"getent": true, "useradd": true, "userdel": true, "usermod": true}
	if r.missing || !known[command.Name] {
		return missing
	}
	argv := append([]string{command.Name}, command.Args...)
	joined := strings.Join(argv, " ")
	if r.retcode != 0 && (command.Name == "useradd" || command.Name == "userdel" || command.Name == "usermod") {
		if command.Name == "usermod" && !r.frozen {
			r.sunApplyUserMod(argv)
		}
		return process.CommandResult{ExitCode: r.retcode, Stdout: r.retcodeStdout, Stderr: r.retcodeStderr}
	}
	notFound := process.CommandResult{ExitCode: 2}
	ok := process.CommandResult{ExitCode: 0}
	switch {
	case strings.Contains(joined, "getent passwd") && len(argv) == 3:
		if r.passwdListing != "" {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.passwdListing)}
		}
		name := argv[2]
		if user, exists := r.users[name]; exists {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(user.line() + "\n")}
		}
		return notFound
	case strings.Contains(joined, "getent passwd"):
		var lines []string
		for _, name := range r.order {
			lines = append(lines, r.users[name].line())
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(strings.Join(lines, "\n") + "\n")}
	case strings.Contains(joined, "getent group") && len(argv) == 3:
		name := argv[2]
		if group, exists := r.groups[name]; exists {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(group.line() + "\n")}
		}
		return notFound
	case strings.Contains(joined, "getent group"):
		if r.groupListing != "" {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.groupListing)}
		}
		var lines []string
		for _, group := range sunSortedGroupValues(r.groups) {
			lines = append(lines, group.line())
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(strings.Join(lines, "\n") + "\n")}
	case strings.Contains(joined, "useradd"):
		r.sunApplyUserAdd(argv)
		return ok
	case strings.Contains(joined, "userdel"):
		delete(r.users, argv[len(argv)-1])
		r.sunForgetOrder(argv[len(argv)-1])
		return ok
	case strings.Contains(joined, "usermod"):
		if !r.frozen {
			r.sunApplyUserMod(argv)
		}
		return ok
	}
	return ok
}

func (r *sunStoreRunner) sunApplyUserAdd(argv []string) {
	user := sunStoreUser{name: argv[len(argv)-1], uid: "10100", gid: "10", home: "/export/home/" + argv[len(argv)-1], shell: "/bin/sh"}
	if idx := sunIndexOf(argv, "-u"); idx > 0 {
		user.uid = argv[idx+1]
	}
	if idx := sunIndexOf(argv, "-g"); idx > 0 {
		user.gid = argv[idx+1]
	}
	if idx := sunIndexOf(argv, "-d"); idx > 0 {
		user.home = argv[idx+1]
	}
	if idx := sunIndexOf(argv, "-s"); idx > 0 {
		user.shell = argv[idx+1]
	}
	if idx := sunIndexOf(argv, "-G"); idx > 0 {
		for _, group := range strings.Split(argv[idx+1], ",") {
			if record, exists := r.groups[group]; exists && !sunMember(record, user.name) {
				record.members = append(record.members, user.name)
				r.groups[group] = record
			}
		}
	}
	r.users[user.name] = user
	r.sunRememberOrder(user.name)
}

// sunApplyUserMod interprets the solaris usermod flag surface the
// module emits: the positional login is the final argument, then
// -u/-g/-s/-d, -G groups, -c gecos, -l rename, -m.
func (r *sunStoreRunner) sunApplyUserMod(argv []string) {
	name := argv[len(argv)-1]
	user, exists := r.users[name]
	if !exists {
		return
	}
	for i := 1; i < len(argv)-1; i++ {
		switch argv[i] {
		case "-u":
			user.uid = argv[i+1]
			i++
		case "-g":
			user.gid = argv[i+1]
			i++
		case "-s":
			user.shell = argv[i+1]
			i++
		case "-d":
			user.home = argv[i+1]
			i++
		case "-c":
			user.gecos = argv[i+1]
			i++
		case "-l":
			newName := argv[i+1]
			delete(r.users, name)
			user.name = newName
			r.users[newName] = user
			r.sunForgetOrder(name)
			r.sunRememberOrder(newName)
			return
		case "-G":
			members := strings.Split(argv[i+1], ",")
			for _, group := range r.sunSortedGroupNames() {
				record := r.groups[group]
				kept := []string{}
				for _, member := range record.members {
					if member != name {
						kept = append(kept, member)
					}
				}
				record.members = kept
				r.groups[group] = record
			}
			for _, entry := range members {
				if entry == "" {
					continue
				}
				record := r.groups[entry]
				if !sunMember(record, name) {
					record.members = append(record.members, name)
				}
				r.groups[entry] = record
			}
			i++
		case "-m":
		default:
			// positional name argument (already captured)
		}
	}
	r.users[name] = user
}

func sunMember(group sunStoreGroup, name string) bool {
	for _, member := range group.members {
		if member == name {
			return true
		}
	}
	return false
}

func (r *sunStoreRunner) sunRememberOrder(name string) {
	for _, existing := range r.order {
		if existing == name {
			return
		}
	}
	r.order = append(r.order, name)
}

func (r *sunStoreRunner) sunForgetOrder(name string) {
	for i, existing := range r.order {
		if existing == name {
			r.order = append(r.order[:i], r.order[i+1:]...)
			return
		}
	}
}

func (r *sunStoreRunner) sunSortedGroupNames() []string {
	names := make([]string, 0, len(r.groups))
	for name := range r.groups {
		names = append(names, name)
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return names
}

func sunSortedGroupValues(groups map[string]sunStoreGroup) []sunStoreGroup {
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	out := make([]sunStoreGroup, 0, len(names))
	for _, name := range names {
		out = append(out, groups[name])
	}
	return out
}

func sunTestRuntime(runner *sunStoreRunner) *runtime.Runtime {
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
}

func sunArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

func sunOnlyCalls(runner *sunStoreRunner, verb string) [][]string {
	var out [][]string
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(sunArgv(call), " "), verb) {
			out = append(out, sunArgv(call))
		}
	}
	return out
}

func TestSunAddArgvLadder(t *testing.T) {
	// Bare add: createhome defaults on (-m), no gecos follow-ups.
	runner := newSunStoreRunner()
	rt := sunTestRuntime(runner)
	got, err := sunAddFunc{}.Execute(context.Background(), rt, &sunAddArgs{Name: "svc"})
	if err != nil || got != true {
		t.Fatalf("add = %v err=%v", got, err)
	}
	if want := []string{"useradd", "-m", "svc"}; !reflect.DeepEqual(sunArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v, want %v", sunArgv(runner.calls[0]), want)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("bare add calls = %d, want 1 (no gecos follow-ups)", len(runner.calls))
	}

	// Full option ladder preserves the pinned flag order (shell, uid,
	// gid, groups, createhome, home, unique) and fires the four GECOS
	// follow-ups after a successful create.
	home := "/export/home/svc"
	unique := false
	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	got, err = sunAddFunc{}.Execute(context.Background(), rt, &sunAddArgs{
		Name: "svc", UID: "123", GID: "10", Groups: []string{"staff", "devops"},
		Home: &home, Shell: "/usr/sbin/nologin", Unique: &unique,
		Fullname: "Service", Roomnumber: "101", Workphone: "555", Homephone: "777",
	})
	if err != nil || got != true {
		t.Fatalf("add = %v err=%v", got, err)
	}
	want := []string{
		"useradd", "-s", "/usr/sbin/nologin", "-u", "123", "-g", "10",
		"-G", "staff,devops", "-m", "-d", "/export/home/svc", "-o", "svc",
	}
	if !reflect.DeepEqual(sunArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v, want %v", sunArgv(runner.calls[0]), want)
	}
	gecosCalls := sunOnlyCalls(runner, "usermod -c")
	wantGecos := [][]string{
		{"usermod", "-c", "Service,,,", "svc"},
		{"usermod", "-c", "Service,101,,", "svc"},
		{"usermod", "-c", "Service,101,555,", "svc"},
		{"usermod", "-c", "Service,101,555,777", "svc"},
	}
	if !reflect.DeepEqual(gecosCalls, wantGecos) {
		t.Fatalf("gecos follow-ups = %v, want %v", gecosCalls, wantGecos)
	}

	// createhome=False drops the -m flag.
	createHome := false
	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	if _, err := (sunAddFunc{}).Execute(context.Background(), rt, &sunAddArgs{Name: "svc", CreateHome: &createHome}); err != nil {
		t.Fatal(err)
	}
	if joined := strings.Join(sunArgv(runner.calls[0]), " "); strings.Contains(joined, " -m") {
		t.Fatalf("createhome=false argv = %v", joined)
	}

	// Home dir creation is observed in the store.
	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	if _, err := (sunAddFunc{}).Execute(context.Background(), rt, &sunAddArgs{Name: "svc"}); err != nil {
		t.Fatal(err)
	}
	if _, exists := runner.users["svc"]; !exists {
		t.Fatalf("useradd did not create the store record")
	}

	// Non-zero retcode reports false (cmd.retcode == 0 in the source).
	runner = newSunStoreRunner()
	runner.retcode = 96
	rt = sunTestRuntime(runner)
	got, err = sunAddFunc{}.Execute(context.Background(), rt, &sunAddArgs{Name: "svc"})
	if err != nil || got != false {
		t.Fatalf("add retcode = %v err=%v", got, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("failed add must not run gecos follow-ups, calls = %d", len(runner.calls))
	}
}

func TestSunAddBinaryMissing(t *testing.T) {
	runner := newSunStoreRunner()
	runner.missing = true
	rt := sunTestRuntime(runner)
	_, err := sunAddFunc{}.Execute(context.Background(), rt, &sunAddArgs{Name: "svc"})
	if err == nil {
		t.Fatal("binary-missing add must error, not fabricate success")
	}
}

func TestSunDelete(t *testing.T) {
	runner := newSunStoreRunner()
	rt := sunTestRuntime(runner)
	got, err := sunDeleteFunc{}.Execute(context.Background(), rt, &sunDeleteArgs{Name: "alice"})
	if err != nil || got != true {
		t.Fatalf("delete = %v err=%v", got, err)
	}
	if want := []string{"userdel", "alice"}; !reflect.DeepEqual(sunArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v, want %v", sunArgv(runner.calls[0]), want)
	}
	// force only logs in the pinned source; remove adds -r.
	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	if _, err := (sunDeleteFunc{}).Execute(context.Background(), rt, &sunDeleteArgs{Name: "alice", Remove: true, Force: true}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"userdel", "-r", "alice"}; !reflect.DeepEqual(sunArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v, want %v", sunArgv(runner.calls[0]), want)
	}
	if _, exists := runner.users["alice"]; exists {
		t.Fatalf("userdel did not remove the store record")
	}
}

func TestSunInfoShape(t *testing.T) {
	runner := newSunStoreRunner()
	rt := sunTestRuntime(runner)
	got, err := sunInfoFunc{}.Execute(context.Background(), rt, &sunInfoArgs{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"gid":        10,
		"groups":     []string{"devops", "staff"},
		"home":       "/home/alice",
		"name":       "alice",
		"passwd":     "x",
		"shell":      "/bin/bash",
		"uid":        1001,
		"fullname":   "Alice Example",
		"roomnumber": "101",
		"workphone":  "555",
		"homephone":  "777",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("info = %#v, want %#v", got, want)
	}

	// Missing user returns the empty dict (KeyError path).
	got, err = sunInfoFunc{}.Execute(context.Background(), rt, &sunInfoArgs{Name: "nobody-here"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("missing info = %#v", got)
	}
}

func TestSunGetentAndListUsers(t *testing.T) {
	runner := newSunStoreRunner()
	rt := sunTestRuntime(runner)
	got, err := sunGetentFunc{}.Execute(context.Background(), rt, &sunGetentArgs{})
	if err != nil {
		t.Fatal(err)
	}
	entries, ok := got.([]map[string]any)
	if !ok || len(entries) != 2 {
		t.Fatalf("getent = %#v", got)
	}
	if entries[0]["name"] != "root" || !reflect.DeepEqual(entries[0]["groups"], []string{"other", "root", "staff"}) {
		t.Fatalf("getent root entry = %#v", entries[0])
	}
	if entries[1]["groups"] == nil || reflect.DeepEqual(entries[1]["groups"], []string{"staff"}) {
		t.Fatalf("getent alice groups = %#v", entries[1]["groups"])
	}

	got, err = sunListUsersFunc{}.Execute(context.Background(), rt, &sunListUsersArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"alice", "root"}) {
		t.Fatalf("list_users = %#v (sorted)", got)
	}
}

func TestSunListGroups(t *testing.T) {
	runner := newSunStoreRunner()
	rt := sunTestRuntime(runner)
	got, err := sunListGroupsFunc{}.Execute(context.Background(), rt, &sunListGroupsArgs{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	// The pinned get_group_list returns unique names sorted lexicographically.
	if !reflect.DeepEqual(got, []string{"devops", "staff"}) {
		t.Fatalf("list_groups = %#v", got)
	}
	// get_group_list catches lookup failures and returns an empty list.
	got, err = (sunListGroupsFunc{}).Execute(context.Background(), rt, &sunListGroupsArgs{Name: "nobody-here"})
	if err != nil || !reflect.DeepEqual(got, []string{}) {
		t.Fatalf("missing list_groups = %#v err=%v, want empty list", got, err)
	}
}

func TestSunGroupsOfSortsAndDeduplicates(t *testing.T) {
	runner := newSunStoreRunner()
	runner.groupListing = "zeta:x:30:alice,alice\nstaff:x:10:alice\nalpha:x:20:alice\nstaff:x:10:alice\n"
	rt := sunTestRuntime(runner)
	got, err := sunGroupsOf(context.Background(), rt, sunUserEntry{name: "alice", gid: 10})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"alpha", "staff", "zeta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("groups = %#v, want %#v", got, want)
	}
}

func TestSunSolarisParsersRejectInvalidIDs(t *testing.T) {
	passwdCases := []struct {
		name  string
		line  string
		valid bool
	}{
		{"alpha uid", "alice:x:alpha:10:Alice:/home/alice:/bin/sh", false},
		{"overflow uid", "alice:x:" + strings.Repeat("9", 100) + ":10:Alice:/home/alice:/bin/sh", false},
		{"negative uid", "alice:x:-1:10:Alice:/home/alice:/bin/sh", false},
		{"zero ids", "root:x:0:0:Super:/root:/bin/sh", true},
	}
	for _, tc := range passwdCases {
		t.Run(tc.name, func(t *testing.T) {
			entry, ok, err := sunParsePasswdLine(tc.line)
			if tc.valid {
				if err != nil || !ok || entry.uid != 0 || entry.gid != 0 {
					t.Fatalf("parse = %#v ok=%v err=%v, want zero IDs", entry, ok, err)
				}
				return
			}
			if err == nil || ok {
				t.Fatalf("parse = %#v ok=%v err=%v, want deterministic error", entry, ok, err)
			}
		})
	}

	groupCases := []struct {
		name  string
		line  string
		valid bool
	}{
		{"alpha gid", "staff:x:alpha:alice", false},
		{"overflow gid", "staff:x:" + strings.Repeat("9", 100) + ":alice", false},
		{"negative gid", "staff:x:-1:alice", false},
		{"zero gid", "root:x:0:alice", true},
	}
	for _, tc := range groupCases {
		t.Run(tc.name, func(t *testing.T) {
			entry, ok, err := sunParseGroupLine(tc.line)
			if tc.valid {
				if err != nil || !ok || entry.gid != 0 {
					t.Fatalf("parse = %#v ok=%v err=%v, want zero gid", entry, ok, err)
				}
				return
			}
			if err == nil || ok {
				t.Fatalf("parse = %#v ok=%v err=%v, want deterministic error", entry, ok, err)
			}
		})
	}
}

func TestSunUserProvidersRejectInvalidNumericIDs(t *testing.T) {
	passwdLines := []string{
		"alice:x:alpha:10:Alice:/home/alice:/bin/sh",
		"alice:x:" + strings.Repeat("9", 100) + ":10:Alice:/home/alice:/bin/sh",
		"alice:x:-1:10:Alice:/home/alice:/bin/sh",
		"alice:x:0:0:Alice:/home/alice:/bin/sh",
	}
	for i, line := range passwdLines {
		runner := newSunStoreRunner()
		runner.passwdListing = line + "\n"
		entry, ok, err := sunUserShow(context.Background(), sunTestRuntime(runner), "alice")
		if i < len(passwdLines)-1 {
			if err == nil || ok {
				t.Fatalf("passwd provider line %q = %#v ok=%v err=%v, want parse error", line, entry, ok, err)
			}
		} else if err != nil || !ok || entry.uid != 0 || entry.gid != 0 {
			t.Fatalf("zero passwd provider = %#v ok=%v err=%v", entry, ok, err)
		}
	}

	groupLines := []string{
		"root:x:alpha:alice",
		"root:x:" + strings.Repeat("9", 100) + ":alice",
		"root:x:-1:alice",
		"root:x:0:alice",
	}
	for i, line := range groupLines {
		runner := newSunStoreRunner()
		runner.groupListing = line + "\n"
		groups, err := sunGroupsOf(context.Background(), sunTestRuntime(runner), sunUserEntry{name: "alice", gid: 0})
		if i < len(groupLines)-1 {
			if err == nil {
				t.Fatalf("group provider line %q = %#v err=%v, want parse error", line, groups, err)
			}
		} else if err != nil || !reflect.DeepEqual(groups, []string{"root"}) {
			t.Fatalf("zero group provider = %#v err=%v", groups, err)
		}
	}
}

func TestSunChuidChgidChshellChhome(t *testing.T) {
	ctx := context.Background()

	// Same value short-circuits: a single getent lookup, no usermod.
	runner := newSunStoreRunner()
	rt := sunTestRuntime(runner)
	got, err := sunChuidFunc{}.Execute(ctx, rt, &sunChuidArgs{Name: "alice", UID: "1001"})
	if err != nil || got != true {
		t.Fatalf("chuid same = %v err=%v", got, err)
	}
	if len(sunOnlyCalls(runner, "usermod")) != 0 || len(runner.calls) != 1 {
		t.Fatalf("same-value calls = %#v", runner.calls)
	}

	// Change runs the pinned argv and verifies through getent.
	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	got, err = sunChuidFunc{}.Execute(ctx, rt, &sunChuidArgs{Name: "alice", UID: "1234"})
	if err != nil || got != true {
		t.Fatalf("chuid change = %v err=%v", got, err)
	}
	if want := []string{"usermod", "-u", "1234", "alice"}; !reflect.DeepEqual(sunArgv(runner.calls[1]), want) {
		t.Fatalf("argv = %v, want %v", sunArgv(runner.calls[1]), want)
	}

	// cmd.run uses raise_err=False: a completed non-zero usermod still
	// reaches the pinned post-state verification.
	runner = newSunStoreRunner()
	runner.retcode = 7
	runner.retcodeStdout = []byte("usermod warning\n")
	rt = sunTestRuntime(runner)
	got, err = sunChuidFunc{}.Execute(ctx, rt, &sunChuidArgs{Name: "alice", UID: "1234"})
	if err != nil || got != true {
		t.Fatalf("chuid non-zero post-state = %v err=%v", got, err)
	}
	result, runErr := sunRunStrict(ctx, rt, "usermod", "-u", "2345", "alice")
	if runErr != nil || result.ExitCode != 7 || string(result.Stdout) != "usermod warning\n" || len(result.Stderr) != 0 {
		t.Fatalf("sunRunStrict result = %#v err=%v, want non-zero stdout data", result, runErr)
	}

	// Frozen store: verification fails.
	runner = newSunStoreRunner()
	runner.frozen = true
	rt = sunTestRuntime(runner)
	got, err = sunChuidFunc{}.Execute(ctx, rt, &sunChuidArgs{Name: "alice", UID: "1234"})
	if err != nil || got != false {
		t.Fatalf("chuid frozen = %v err=%v", got, err)
	}

	// Missing user raises the pinned CommandExecutionError text.
	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	_, err = sunChuidFunc{}.Execute(ctx, rt, &sunChuidArgs{Name: "nobody-here", UID: "1"})
	if err == nil || !strings.Contains(err.Error(), "User 'nobody-here' does not exist") {
		t.Fatalf("chuid missing err=%v", err)
	}

	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	if got, err = (sunChgidFunc{}).Execute(ctx, rt, &sunChgidArgs{Name: "alice", GID: "20"}); err != nil || got != true {
		t.Fatalf("chgid change = %v err=%v", got, err)
	}
	if want := []string{"usermod", "-g", "20", "alice"}; !reflect.DeepEqual(sunArgv(runner.calls[1]), want) {
		t.Fatalf("argv = %v", sunArgv(runner.calls[1]))
	}

	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	if got, err = (sunChshellFunc{}).Execute(ctx, rt, &sunChshellArgs{Name: "alice", Shell: "/usr/bin/zsh"}); err != nil || got != true {
		t.Fatalf("chshell change = %v err=%v", got, err)
	}
	if want := []string{"usermod", "-s", "/usr/bin/zsh", "alice"}; !reflect.DeepEqual(sunArgv(runner.calls[1]), want) {
		t.Fatalf("argv = %v", sunArgv(runner.calls[1]))
	}

	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	if got, err = (sunChhomeFunc{}).Execute(ctx, rt, &sunChhomeArgs{Name: "alice", Home: "/export/home/alice"}); err != nil || got != true {
		t.Fatalf("chhome change = %v err=%v", got, err)
	}
	if want := []string{"usermod", "-d", "/export/home/alice", "alice"}; !reflect.DeepEqual(sunArgv(runner.calls[1]), want) {
		t.Fatalf("argv = %v", sunArgv(runner.calls[1]))
	}

	// persist adds -m between the home flag and the login.
	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	if _, err = (sunChhomeFunc{}).Execute(ctx, rt, &sunChhomeArgs{Name: "alice", Home: "/export/home/alice", Persist: true}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"usermod", "-d", "/export/home/alice", "-m", "alice"}; !reflect.DeepEqual(sunArgv(runner.calls[1]), want) {
		t.Fatalf("argv = %v", sunArgv(runner.calls[1]))
	}
}

func TestSunChgroups(t *testing.T) {
	ctx := context.Background()

	// Set equality short-circuits to true with no mutation.
	runner := newSunStoreRunner()
	rt := sunTestRuntime(runner)
	got, err := sunChgroupsFunc{}.Execute(ctx, rt, &sunChgroupsArgs{Name: "alice", Groups: []string{"staff", "devops"}})
	if err != nil || got != true {
		t.Fatalf("chgroups equal = %v err=%v", got, err)
	}
	if len(sunOnlyCalls(runner, "usermod")) != 0 {
		t.Fatalf("equal set mutated: %#v", runner.calls)
	}

	// Replace emits exactly the requested list.
	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	if got, err = (sunChgroupsFunc{}).Execute(ctx, rt, &sunChgroupsArgs{Name: "alice", Groups: []string{"staff"}}); err != nil || got != true {
		t.Fatalf("chgroups replace = %v err=%v", got, err)
	}
	if want := []string{"usermod", "-G", "staff", "alice"}; !reflect.DeepEqual(sunArgv(runner.calls[2]), want) {
		t.Fatalf("argv = %v, want %v", sunArgv(runner.calls[2]), want)
	}

	// Append unions the requested list with the current memberships.
	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	if _, err = (sunChgroupsFunc{}).Execute(ctx, rt, &sunChgroupsArgs{Name: "alice", Groups: []string{"other"}, Append: true}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(sunOnlyCalls(runner, "usermod")[0], " ")
	if !strings.Contains(joined, "-G other,devops,staff alice") {
		t.Fatalf("append argv = %v", joined)
	}

	// Missing user errors before any mutation.
	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	if _, err = (sunChgroupsFunc{}).Execute(ctx, rt, &sunChgroupsArgs{Name: "nobody-here", Groups: []string{"staff"}}); err == nil {
		t.Fatal("chgroups on missing user must error")
	}
}

func TestSunGecosChangers(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		key   string
		value string
		argv  []string
	}{
		{"chfullname", "fullname", "Alice A", []string{"usermod", "-c", "Alice A,101,555,777", "alice"}},
		{"chroomnumber", "roomnumber", "42", []string{"usermod", "-c", "Alice Example,42,555,777", "alice"}},
		{"chworkphone", "workphone", "312", []string{"usermod", "-c", "Alice Example,101,312,777", "alice"}},
		{"chhomephone", "homephone", "999", []string{"usermod", "-c", "Alice Example,101,555,999", "alice"}},
	}
	for _, tc := range cases {
		// Same value short-circuits.
		runner := newSunStoreRunner()
		rt := sunTestRuntime(runner)
		var got any
		var err error
		switch tc.name {
		case "chfullname":
			got, err = sunChfullnameFunc{}.Execute(ctx, rt, &sunChfullnameArgs{Name: "alice", Fullname: "Alice Example"})
		case "chroomnumber":
			got, err = sunChroomnumberFunc{}.Execute(ctx, rt, &sunChroomnumberArgs{Name: "alice", Roomnumber: "101"})
		case "chworkphone":
			got, err = sunChworkphoneFunc{}.Execute(ctx, rt, &sunChworkphoneArgs{Name: "alice", Workphone: "555"})
		case "chhomephone":
			got, err = sunChhomephoneFunc{}.Execute(ctx, rt, &sunChhomephoneArgs{Name: "alice", Homephone: "777"})
		}
		if err != nil || got != true {
			t.Fatalf("%s same = %v err=%v", tc.name, got, err)
		}
		if len(sunOnlyCalls(runner, "usermod")) != 0 {
			t.Fatalf("%s same-value mutated: %#v", tc.name, runner.calls)
		}

		// Change fires usermod -c with the rebuilt GECOS.
		runner = newSunStoreRunner()
		rt = sunTestRuntime(runner)
		switch tc.name {
		case "chfullname":
			got, err = sunChfullnameFunc{}.Execute(ctx, rt, &sunChfullnameArgs{Name: "alice", Fullname: tc.value})
		case "chroomnumber":
			got, err = sunChroomnumberFunc{}.Execute(ctx, rt, &sunChroomnumberArgs{Name: "alice", Roomnumber: tc.value})
		case "chworkphone":
			got, err = sunChworkphoneFunc{}.Execute(ctx, rt, &sunChworkphoneArgs{Name: "alice", Workphone: tc.value})
		case "chhomephone":
			got, err = sunChhomephoneFunc{}.Execute(ctx, rt, &sunChhomephoneArgs{Name: "alice", Homephone: tc.value})
		}
		if err != nil || got != true {
			t.Fatalf("%s change = %v err=%v", tc.name, got, err)
		}
		if want := tc.argv; !reflect.DeepEqual(sunArgv(runner.calls[1]), want) {
			t.Fatalf("%s argv = %v, want %v", tc.name, sunArgv(runner.calls[1]), want)
		}

		// Frozen store: verification fails with false, not an error.
		runner = newSunStoreRunner()
		runner.frozen = true
		rt = sunTestRuntime(runner)
		switch tc.name {
		case "chfullname":
			got, err = sunChfullnameFunc{}.Execute(ctx, rt, &sunChfullnameArgs{Name: "alice", Fullname: tc.value})
		case "chroomnumber":
			got, err = sunChroomnumberFunc{}.Execute(ctx, rt, &sunChroomnumberArgs{Name: "alice", Roomnumber: tc.value})
		case "chworkphone":
			got, err = sunChworkphoneFunc{}.Execute(ctx, rt, &sunChworkphoneArgs{Name: "alice", Workphone: tc.value})
		case "chhomephone":
			got, err = sunChhomephoneFunc{}.Execute(ctx, rt, &sunChhomephoneArgs{Name: "alice", Homephone: tc.value})
		}
		if err != nil || got != false {
			t.Fatalf("%s frozen = %v err=%v", tc.name, got, err)
		}

		// _get_gecos calls pwd.getpwnam directly, so a missing user
		// propagates the lookup error instead of returning false.
		runner = newSunStoreRunner()
		rt = sunTestRuntime(runner)
		switch tc.name {
		case "chfullname":
			got, err = sunChfullnameFunc{}.Execute(ctx, rt, &sunChfullnameArgs{Name: "nobody-here", Fullname: tc.value})
		case "chroomnumber":
			got, err = sunChroomnumberFunc{}.Execute(ctx, rt, &sunChroomnumberArgs{Name: "nobody-here", Roomnumber: tc.value})
		case "chworkphone":
			got, err = sunChworkphoneFunc{}.Execute(ctx, rt, &sunChworkphoneArgs{Name: "nobody-here", Workphone: tc.value})
		case "chhomephone":
			got, err = sunChhomephoneFunc{}.Execute(ctx, rt, &sunChhomephoneArgs{Name: "nobody-here", Homephone: tc.value})
		}
		if err == nil || got != nil || !strings.Contains(err.Error(), "User 'nobody-here' does not exist") {
			t.Fatalf("%s missing = %v err=%v", tc.name, got, err)
		}
	}
}

func TestSunRename(t *testing.T) {
	ctx := context.Background()

	runner := newSunStoreRunner()
	rt := sunTestRuntime(runner)
	if _, err := (sunRenameFunc{}).Execute(ctx, rt, &sunRenameArgs{Name: "nobody-here", NewName: "bob"}); err == nil ||
		!strings.Contains(err.Error(), "User 'nobody-here' does not exist") {
		t.Fatalf("rename missing err=%v", err)
	}

	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	if _, err := (sunRenameFunc{}).Execute(ctx, rt, &sunRenameArgs{Name: "alice", NewName: "root"}); err == nil ||
		!strings.Contains(err.Error(), "User 'root' already exists") {
		t.Fatalf("rename exists err=%v", err)
	}

	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	got, err := sunRenameFunc{}.Execute(ctx, rt, &sunRenameArgs{Name: "alice", NewName: "alicia"})
	if err != nil || got != true {
		t.Fatalf("rename = %v err=%v", got, err)
	}
	if want := []string{"usermod", "-l", "alicia", "alice"}; !reflect.DeepEqual(sunArgv(runner.calls[2]), want) {
		t.Fatalf("argv = %v, want %v", sunArgv(runner.calls[2]), want)
	}
	if _, exists := runner.users["alicia"]; !exists {
		t.Fatalf("rename did not move the store record")
	}

	// Frozen store: verification fails.
	runner = newSunStoreRunner()
	runner.frozen = true
	rt = sunTestRuntime(runner)
	got, err = sunRenameFunc{}.Execute(ctx, rt, &sunRenameArgs{Name: "alice", NewName: "alicia"})
	if err != nil || got != false {
		t.Fatalf("rename frozen = %v err=%v", got, err)
	}
}

func TestSunUserCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := newSunStoreRunner()
	rt := sunTestRuntime(runner)
	if _, err := (sunInfoFunc{}).Execute(ctx, rt, &sunInfoArgs{Name: "alice"}); err == nil {
		t.Fatal("canceled context must error before the Runner starts")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled context spawned %#v", runner.calls)
	}
}
