package user

// R8.1 mock tests for the FreeBSD pw_user virtual user surface, mapped
// onto saltstack/salt/modules/pw_user.py @ pinned revision 8b63e700637e
// and tests/pytests/unit/modules/test_pw_user.py: the add/delete argv
// ladder (gecos assembly, createhome/unique defaults, loginclass), the
// chuid/chgid/chshell/chhome same-value short-circuit plus change and
// failed-verification paths, chgroups append semantics, the GECOS field
// changers with the pinned Unicode vectors, info/getent/list_users
// shapes, get_loginclass field position, list_groups primary-first
// ordering, primary_group, rename error and success paths, cancellation
// and binary-missing boundaries, and the freebsd registry matrix. The
// runner is a stateful in-memory pw store; no real pw binary runs.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// pwStoreUser is one record in the fake passwd database.
type pwStoreUser struct {
	name  string
	uid   string
	gid   string
	class string
	gecos string
	home  string
	shell string
}

func (u pwStoreUser) line() string {
	return strings.Join([]string{u.name, "*", u.uid, u.gid, u.class, "0", "0", u.gecos, u.home, u.shell}, ":")
}

// pwStoreGroup is one record in the fake group database.
type pwStoreGroup struct {
	name    string
	gid     string
	members []string
}

func (g pwStoreGroup) line() string {
	return strings.Join([]string{g.name, "*", g.gid, strings.Join(g.members, ",")}, ":")
}

// pwStoreRunner simulates the pw tool surface against a live user and
// group store. frozen=true makes mutating verbs succeed without
// applying changes, reproducing the failed-verification paths.
type pwStoreRunner struct {
	users   map[string]pwStoreUser
	groups  map[string]pwStoreGroup
	order   []string
	frozen  bool
	missing bool
	retcode int
	calls   []process.Command
}

func newPwStoreRunner() *pwStoreRunner {
	return &pwStoreRunner{
		users: map[string]pwStoreUser{
			"root":  {name: "root", uid: "0", gid: "0", class: "default", gecos: "Charlie &", home: "/root", shell: "/bin/csh"},
			"alice": {name: "alice", uid: "1001", gid: "1001", class: "staff", gecos: "Alice Example,101,555,777", home: "/home/alice", shell: "/bin/sh"},
		},
		groups: map[string]pwStoreGroup{
			"wheel":  {name: "wheel", gid: "0", members: []string{"root"}},
			"staff":  {name: "staff", gid: "20", members: []string{"root"}},
			"alice":  {name: "alice", gid: "1001", members: []string{}},
			"devops": {name: "devops", gid: "1002", members: []string{"alice"}},
		},
		order: []string{"root", "alice"},
	}
}

func (r *pwStoreRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	missing := process.CommandResult{
		Err:      errors.New("exec: \"pw\": executable file not found in $PATH"),
		ExitCode: -1,
	}
	if r.missing || command.Name != "pw" {
		return missing
	}
	if r.retcode != 0 {
		return process.CommandResult{ExitCode: r.retcode, Stderr: []byte("pw: simulated failure")}
	}
	ok := process.CommandResult{ExitCode: 0}
	argv := append([]string{command.Name}, command.Args...)
	joined := strings.Join(argv, " ")
	fail := process.CommandResult{ExitCode: 65, Stderr: []byte("pw: unknown user/group")}
	switch {
	case strings.Contains(joined, "usershow -a"):
		var lines []string
		for _, name := range r.order {
			lines = append(lines, r.users[name].line())
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(strings.Join(lines, "\n") + "\n")}
	case strings.Contains(joined, "usershow -n"):
		name := argv[indexOf(argv, "-n")+1]
		if user, exists := r.users[name]; exists {
			return commandResultFromLine(user.line())
		}
		return fail
	case strings.Contains(joined, "groupshow -a"):
		var lines []string
		for _, group := range sortedGroupValues(r.groups) {
			lines = append(lines, group.line())
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(strings.Join(lines, "\n") + "\n")}
	case strings.Contains(joined, "groupshow -n"):
		name := argv[indexOf(argv, "-n")+1]
		if group, exists := r.groups[name]; exists {
			return commandResultFromLine(group.line())
		}
		return fail
	case strings.Contains(joined, "useradd"):
		r.rememberOrder(lastArg(argv))
		return ok
	case strings.Contains(joined, "userdel"):
		delete(r.users, argv[indexOf(argv, "-n")+1])
		r.forgetOrder(argv[indexOf(argv, "-n")+1])
		return ok
	case strings.Contains(joined, "usermod"):
		if r.frozen {
			return ok
		}
		r.applyUserMod(argv)
		return ok
	case strings.Contains(joined, "groupadd"), strings.Contains(joined, "groupdel"), strings.Contains(joined, "groupmod"):
		return ok
	}
	return ok
}

func commandResultFromLine(line string) process.CommandResult {
	return process.CommandResult{ExitCode: 0, Stdout: []byte(line)}
}

func indexOf(argv []string, flag string) int {
	for i, arg := range argv {
		if arg == flag {
			return i
		}
	}
	return -1
}

func lastArg(argv []string) string {
	return argv[len(argv)-1]
}

func (r *pwStoreRunner) rememberOrder(name string) {
	for _, existing := range r.order {
		if existing == name {
			return
		}
	}
	r.order = append(r.order, name)
}

func (r *pwStoreRunner) forgetOrder(name string) {
	for i, existing := range r.order {
		if existing == name {
			r.order = append(r.order[:i], r.order[i+1:]...)
			return
		}
	}
}

// applyUserMod interprets the usermod flag surface the module emits:
// -n target (or the positional name directly after `usermod`), then
// -u/-g/-s/-d, -L class, -G groups, -c gecos, -l rename.
func (r *pwStoreRunner) applyUserMod(argv []string) {
	name := ""
	if idx := indexOf(argv, "-n"); idx > 0 {
		name = argv[idx+1]
	} else if len(argv) > 2 {
		name = argv[2]
	}
	user, exists := r.users[name]
	if !exists {
		return
	}
	for i := 1; i < len(argv); i++ {
		switch argv[i] {
		case "-n":
			i++
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
		case "-L":
			user.class = argv[i+1]
			i++
		case "-c":
			user.gecos = argv[i+1]
			i++
		case "-l":
			newName := argv[i+1]
			delete(r.users, name)
			user.name = newName
			r.users[newName] = user
			r.forgetOrder(name)
			r.rememberOrder(newName)
			return
		case "-G":
			members := strings.Split(argv[i+1], ",")
			for _, group := range r.sortedGroupNames() {
				memberList := []string{}
				for _, member := range r.groups[group].members {
					if member != name {
						memberList = append(memberList, member)
					}
				}
				record := r.groups[group]
				record.members = memberList
				r.groups[group] = record
			}
			for _, entry := range members {
				if entry == "" {
					continue
				}
				record := r.groups[entry]
				found := false
				for _, member := range record.members {
					if member == name {
						found = true
					}
				}
				if !found {
					record.members = append(record.members, name)
				}
				r.groups[entry] = record
			}
			i++
		case "-m":
		default:
			// positional name argument
		}
	}
	r.users[name] = user
}

func (r *pwStoreRunner) sortedGroupNames() []string {
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

func sortedGroupValues(groups map[string]pwStoreGroup) []pwStoreGroup {
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
	out := make([]pwStoreGroup, 0, len(names))
	for _, name := range names {
		out = append(out, groups[name])
	}
	return out
}

func pwTestRuntime(runner *pwStoreRunner) *runtime.Runtime {
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
}

func pwArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

func pwOnlyCalls(runner *pwStoreRunner, verb string) [][]string {
	var out [][]string
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(pwArgv(call), " "), verb) {
			out = append(out, pwArgv(call))
		}
	}
	return out
}

func TestPwAddArgvLadder(t *testing.T) {
	// Bare add: createhome defaults on (-m) and the empty gecos is
	// carried by -c with -n naming the account.
	runner := newPwStoreRunner()
	rt := pwTestRuntime(runner)
	got, err := pwAddFunc{}.Execute(context.Background(), rt, &pwAddArgs{Name: "svc"})
	if err != nil || got != true {
		t.Fatalf("add = %v err=%v", got, err)
	}
	want := []string{"pw", "useradd", "-m", "-c", ",,,", "-n", "svc"}
	if !reflect.DeepEqual(pwArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v, want %v", pwArgv(runner.calls[0]), want)
	}

	// Full option ladder preserves the pinned flag order: uid, gid,
	// groups, home, createhome, loginclass, shell, unique, gecos, name.
	home := "/home/svc"
	unique := false
	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	if _, err := (pwAddFunc{}).Execute(context.Background(), rt, &pwAddArgs{
		Name: "svc", UID: "123", GID: "123", Groups: []string{"wheel", "devops"},
		Home: &home, Shell: "/usr/sbin/nologin", Unique: &unique,
		Fullname: "Service", Roomnumber: "101", Workphone: "555", Homephone: "777",
		Loginclass: "daemon",
	}); err != nil {
		t.Fatal(err)
	}
	want = []string{
		"pw", "useradd", "-u", "123", "-g", "123", "-G", "wheel,devops",
		"-d", "/home/svc", "-m", "-L", "daemon", "-s", "/usr/sbin/nologin",
		"-o", "-c", "Service,101,555,777", "-n", "svc",
	}
	if !reflect.DeepEqual(pwArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v, want %v", pwArgv(runner.calls[0]), want)
	}

	// createhome=False drops the -m flag.
	createHome := false
	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	if _, err := (pwAddFunc{}).Execute(context.Background(), rt, &pwAddArgs{Name: "svc", CreateHome: &createHome}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(pwArgv(runner.calls[0]), " ")
	if strings.Contains(joined, " -m") {
		t.Fatalf("createhome=false argv = %v", joined)
	}

	// Non-zero retcode reports false (cmd.retcode == 0 in the source).
	runner = newPwStoreRunner()
	runner.retcode = 65
	rt = pwTestRuntime(runner)
	got, err = pwAddFunc{}.Execute(context.Background(), rt, &pwAddArgs{Name: "svc"})
	if err != nil || got != false {
		t.Fatalf("add retcode = %v err=%v", got, err)
	}
}

func TestPwDelete(t *testing.T) {
	runner := newPwStoreRunner()
	rt := pwTestRuntime(runner)
	got, err := pwDeleteFunc{}.Execute(context.Background(), rt, &pwDeleteArgs{Name: "alice"})
	if err != nil || got != true {
		t.Fatalf("delete = %v err=%v", got, err)
	}
	if want := []string{"pw", "userdel", "-n", "alice"}; !reflect.DeepEqual(pwArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v", pwArgv(runner.calls[0]))
	}
	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	if _, err := (pwDeleteFunc{}).Execute(context.Background(), rt, &pwDeleteArgs{Name: "alice", Remove: true, Force: true}); err != nil {
		t.Fatal(err)
	}
	// force only logs in the pinned source; remove adds -r.
	if want := []string{"pw", "userdel", "-r", "-n", "alice"}; !reflect.DeepEqual(pwArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v", pwArgv(runner.calls[0]))
	}
	if _, exists := runner.users["alice"]; exists {
		t.Fatalf("userdel did not remove the store record")
	}
}

func TestPwInfoShape(t *testing.T) {
	runner := newPwStoreRunner()
	rt := pwTestRuntime(runner)
	got, err := pwInfoFunc{}.Execute(context.Background(), rt, &pwInfoArgs{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"gid":        1001,
		"groups":     []string{"alice", "devops"},
		"home":       "/home/alice",
		"name":       "alice",
		"passwd":     "*",
		"shell":      "/bin/sh",
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
	got, err = pwInfoFunc{}.Execute(context.Background(), rt, &pwInfoArgs{Name: "nobody-here"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("missing info = %#v", got)
	}
}

func TestPwGetentAndListUsers(t *testing.T) {
	runner := newPwStoreRunner()
	rt := pwTestRuntime(runner)
	got, err := pwGetentFunc{}.Execute(context.Background(), rt, &pwGetentArgs{})
	if err != nil {
		t.Fatal(err)
	}
	entries, ok := got.([]map[string]any)
	if !ok || len(entries) != 2 {
		t.Fatalf("getent = %#v", got)
	}
	if entries[0]["name"] != "root" || entries[0]["groups"] != nil && entries[0]["groups"].([]string)[0] != "wheel" {
		t.Fatalf("getent root entry = %#v", entries[0])
	}

	got, err = pwListUsersFunc{}.Execute(context.Background(), rt, &pwListUsersArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"alice", "root"}) {
		t.Fatalf("list_users = %#v (sorted)", got)
	}
}

func TestPwChAttributeSameChangeFrozen(t *testing.T) {
	// Same value short-circuits: a single usershow, no usermod.
	runner := newPwStoreRunner()
	rt := pwTestRuntime(runner)
	got, err := pwChuidFunc{}.Execute(context.Background(), rt, &pwChuidArgs{Name: "alice", UID: "1001"})
	if err != nil || got != true {
		t.Fatalf("chuid same = %v err=%v", got, err)
	}
	if len(pwOnlyCalls(runner, "usermod")) != 0 || len(runner.calls) != 1 {
		t.Fatalf("same-value calls = %#v", runner.calls)
	}

	// Applied change verifies true with the pinned usermod argv.
	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	got, err = pwChuidFunc{}.Execute(context.Background(), rt, &pwChuidArgs{Name: "alice", UID: "4376"})
	if err != nil || got != true {
		t.Fatalf("chuid change = %v err=%v", got, err)
	}
	if want := []string{"pw", "usermod", "-u", "4376", "-n", "alice"}; !reflect.DeepEqual(pwOnlyCalls(runner, "usermod")[0], want) {
		t.Fatalf("argv = %v", pwOnlyCalls(runner, "usermod")[0])
	}

	// Frozen store: the change did not apply, verification fails.
	runner = newPwStoreRunner()
	runner.frozen = true
	rt = pwTestRuntime(runner)
	got, err = pwChuidFunc{}.Execute(context.Background(), rt, &pwChuidArgs{Name: "alice", UID: "4376"})
	if err != nil || got != false {
		t.Fatalf("chuid frozen = %v err=%v", got, err)
	}

	// Missing user raises the pinned CommandExecutionError.
	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	got, err = pwChuidFunc{}.Execute(context.Background(), rt, &pwChuidArgs{Name: "ghost", UID: "1"})
	if got != nil || err == nil || err.Error() != "User 'ghost' does not exist" {
		t.Fatalf("chuid missing got=%#v err=%v", got, err)
	}
}

func TestPwChgidChshellChhome(t *testing.T) {
	runner := newPwStoreRunner()
	rt := pwTestRuntime(runner)
	got, err := pwChgidFunc{}.Execute(context.Background(), rt, &pwChgidArgs{Name: "alice", GID: "20"})
	if err != nil || got != true {
		t.Fatalf("chgid = %v err=%v", got, err)
	}
	if want := []string{"pw", "usermod", "-g", "20", "-n", "alice"}; !reflect.DeepEqual(pwOnlyCalls(runner, "usermod")[0], want) {
		t.Fatalf("argv = %v", pwOnlyCalls(runner, "usermod")[0])
	}

	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	got, err = pwChshellFunc{}.Execute(context.Background(), rt, &pwChshellArgs{Name: "alice", Shell: "/bin/zsh"})
	if err != nil || got != true {
		t.Fatalf("chshell = %v err=%v", got, err)
	}
	if want := []string{"pw", "usermod", "-s", "/bin/zsh", "-n", "alice"}; !reflect.DeepEqual(pwOnlyCalls(runner, "usermod")[0], want) {
		t.Fatalf("argv = %v", pwOnlyCalls(runner, "usermod")[0])
	}

	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	got, err = pwChhomeFunc{}.Execute(context.Background(), rt, &pwChhomeArgs{Name: "alice", Home: "/home/users/alice", Persist: true})
	if err != nil || got != true {
		t.Fatalf("chhome = %v err=%v", got, err)
	}
	// chhome passes the name positionally and appends -m when persist.
	want := []string{"pw", "usermod", "alice", "-d", "/home/users/alice", "-m"}
	if !reflect.DeepEqual(pwOnlyCalls(runner, "usermod")[0], want) {
		t.Fatalf("argv = %v", pwOnlyCalls(runner, "usermod")[0])
	}
}

func TestPwChgroups(t *testing.T) {
	// Identical membership is settled without a mutation.
	runner := newPwStoreRunner()
	rt := pwTestRuntime(runner)
	got, err := pwChgroupsFunc{}.Execute(context.Background(), rt,
		&pwChgroupsArgs{Name: "alice", Groups: []string{"alice", "devops"}})
	if err != nil || got != true {
		t.Fatalf("chgroups same = %v err=%v", got, err)
	}
	if len(pwOnlyCalls(runner, "usermod")) != 0 {
		t.Fatalf("settled chgroups mutated: %#v", runner.calls)
	}

	// Replace: the requested list replaces the current membership.
	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	got, err = pwChgroupsFunc{}.Execute(context.Background(), rt,
		&pwChgroupsArgs{Name: "alice", Groups: []string{"wheel"}})
	if err != nil || got != true {
		t.Fatalf("chgroups replace = %v err=%v", got, err)
	}
	if want := []string{"pw", "usermod", "-G", "wheel", "-n", "alice"}; !reflect.DeepEqual(pwOnlyCalls(runner, "usermod")[0], want) {
		t.Fatalf("argv = %v", pwOnlyCalls(runner, "usermod")[0])
	}

	// Append merges the current groups into the requested set.
	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	if _, err := (pwChgroupsFunc{}).Execute(context.Background(), rt,
		&pwChgroupsArgs{Name: "alice", Groups: []string{"wheel"}, Append: true}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(pwOnlyCalls(runner, "usermod")[0], " ")
	for _, group := range []string{"wheel", "alice", "devops"} {
		if !strings.Contains(joined, group) {
			t.Fatalf("append argv %q missing %s", joined, group)
		}
	}
}

func TestPwGecosChangers(t *testing.T) {
	// Same value short-circuits (pinned Unicode vector).
	runner := newPwStoreRunner()
	rt := pwTestRuntime(runner)
	got, err := pwChfullnameFunc{}.Execute(context.Background(), rt,
		&pwChfullnameArgs{Name: "alice", Fullname: "Alice Example"})
	if err != nil || got != true {
		t.Fatalf("chfullname same = %v err=%v", got, err)
	}
	if len(pwOnlyCalls(runner, "usermod")) != 0 {
		t.Fatalf("same-value gecos mutated: %#v", runner.calls)
	}

	// Applied change keeps the other GECOS fields and verifies true.
	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	got, err = pwChfullnameFunc{}.Execute(context.Background(), rt,
		&pwChfullnameArgs{Name: "alice", Fullname: "Unicøde name ①③②"})
	if err != nil || got != true {
		t.Fatalf("chfullname change = %v err=%v", got, err)
	}
	want := []string{"pw", "usermod", "alice", "-c", "Unicøde name ①③②,101,555,777"}
	if !reflect.DeepEqual(pwOnlyCalls(runner, "usermod")[0], want) {
		t.Fatalf("argv = %v", pwOnlyCalls(runner, "usermod")[0])
	}

	// Frozen store fails verification like the pinned False vectors.
	runner = newPwStoreRunner()
	runner.frozen = true
	rt = pwTestRuntime(runner)
	for _, row := range []struct {
		name string
		exec func() (any, error)
	}{
		{"chroomnumber", func() (any, error) {
			return pwChroomnumberFunc{}.Execute(context.Background(), rt, &pwChroomnumberArgs{Name: "alice", Roomnumber: "42"})
		}},
		{"chworkphone", func() (any, error) {
			return pwChworkphoneFunc{}.Execute(context.Background(), rt, &pwChworkphoneArgs{Name: "alice", Workphone: "999"})
		}},
		{"chhomephone", func() (any, error) {
			return pwChhomephoneFunc{}.Execute(context.Background(), rt, &pwChhomephoneArgs{Name: "alice", Homephone: "888"})
		}},
	} {
		got, err := row.exec()
		if err != nil || got != false {
			t.Fatalf("%s frozen = %v err=%v", row.name, got, err)
		}
	}

	// Missing user returns false (the falsy pre_info branch).
	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	got, err = pwChfullnameFunc{}.Execute(context.Background(), rt,
		&pwChfullnameArgs{Name: "ghost", Fullname: "x"})
	if err != nil || got != false {
		t.Fatalf("chfullname missing = %v err=%v", got, err)
	}
}

func TestPwLoginclass(t *testing.T) {
	runner := newPwStoreRunner()
	rt := pwTestRuntime(runner)
	got, err := pwGetLoginclassFunc{}.Execute(context.Background(), rt, &pwGetLoginclassArgs{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "staff" {
		t.Fatalf("get_loginclass = %v", got)
	}

	// Same class settles without a mutation; a change verifies.
	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	got, err = pwChloginclassFunc{}.Execute(context.Background(), rt,
		&pwChloginclassArgs{Name: "alice", Loginclass: "staff"})
	if err != nil || got != true || len(pwOnlyCalls(runner, "usermod")) != 0 {
		t.Fatalf("chloginclass same = %v err=%v", got, err)
	}
	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	got, err = pwChloginclassFunc{}.Execute(context.Background(), rt,
		&pwChloginclassArgs{Name: "alice", Loginclass: "daemon"})
	if err != nil || got != true {
		t.Fatalf("chloginclass change = %v err=%v", got, err)
	}
	if want := []string{"pw", "usermod", "-L", "daemon", "-n", "alice"}; !reflect.DeepEqual(pwOnlyCalls(runner, "usermod")[0], want) {
		t.Fatalf("argv = %v", pwOnlyCalls(runner, "usermod")[0])
	}
}

func TestPwListGroupsAndPrimaryGroup(t *testing.T) {
	runner := newPwStoreRunner()
	rt := pwTestRuntime(runner)
	got, err := pwListGroupsFunc{}.Execute(context.Background(), rt, &pwListGroupsArgs{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"alice", "devops"}) {
		t.Fatalf("list_groups = %#v", got)
	}
	got, err = pwPrimaryGroupFunc{}.Execute(context.Background(), rt, &pwPrimaryGroupArgs{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "alice" {
		t.Fatalf("primary_group = %v", got)
	}

	// Missing user errors (get_group_list/get_default_group KeyError).
	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	if got, err := (pwPrimaryGroupFunc{}).Execute(context.Background(), rt, &pwPrimaryGroupArgs{Name: "ghost"}); got != nil || err == nil {
		t.Fatalf("primary_group missing got=%#v err=%v", got, err)
	}
	if got, err := (pwListGroupsFunc{}).Execute(context.Background(), rt, &pwListGroupsArgs{Name: "ghost"}); got != nil || err == nil {
		t.Fatalf("list_groups missing got=%#v err=%v", got, err)
	}
}

func TestPwRename(t *testing.T) {
	// Missing source user raises.
	runner := newPwStoreRunner()
	rt := pwTestRuntime(runner)
	if got, err := (pwRenameFunc{}).Execute(context.Background(), rt, &pwRenameArgs{Name: "ghost", NewName: "new"}); got != nil || err == nil || err.Error() != "User 'ghost' does not exist" {
		t.Fatalf("rename missing got=%#v err=%v", got, err)
	}
	// Existing target raises.
	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	if got, err := (pwRenameFunc{}).Execute(context.Background(), rt, &pwRenameArgs{Name: "alice", NewName: "root"}); got != nil || err == nil || err.Error() != "User 'root' already exists" {
		t.Fatalf("rename target-exists got=%#v err=%v", got, err)
	}
	// Applied rename verifies.
	runner = newPwStoreRunner()
	rt = pwTestRuntime(runner)
	got, err := pwRenameFunc{}.Execute(context.Background(), rt, &pwRenameArgs{Name: "alice", NewName: "alicia"})
	if err != nil || got != true {
		t.Fatalf("rename = %v err=%v", got, err)
	}
	if want := []string{"pw", "usermod", "-l", "alicia", "-n", "alice"}; !reflect.DeepEqual(pwOnlyCalls(runner, "usermod")[0], want) {
		t.Fatalf("argv = %v", pwOnlyCalls(runner, "usermod")[0])
	}
	// Frozen store: post_info name still equals current, returns false.
	runner = newPwStoreRunner()
	runner.frozen = true
	rt = pwTestRuntime(runner)
	if got, err := (pwRenameFunc{}).Execute(context.Background(), rt, &pwRenameArgs{Name: "alice", NewName: "alicia"}); err != nil || got != false {
		t.Fatalf("rename frozen = %v err=%v", got, err)
	}
}

func TestPwCancellationAndBinaryMissing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := newPwStoreRunner()
	rt := pwTestRuntime(runner)
	if got, err := (pwInfoFunc{}).Execute(ctx, rt, &pwInfoArgs{Name: "alice"}); got != nil || !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}

	// A missing pw binary surfaces the Runner error (Salt's __virtual__
	// guard depends on the pwd module / pw availability).
	missing := newPwStoreRunner()
	missing.missing = true
	rt = pwTestRuntime(missing)
	if got, err := (pwAddFunc{}).Execute(context.Background(), rt, &pwAddArgs{Name: "svc"}); got != nil || err == nil || len(missing.calls) != 1 {
		t.Fatalf("binary-missing got=%#v err=%v", got, err)
	}
	if got, err := (pwInfoFunc{}).Execute(context.Background(), rt, &pwInfoArgs{Name: "alice"}); got != nil || err == nil {
		t.Fatalf("binary-missing info got=%#v err=%v", got, err)
	}
}

func TestPwParseUserLineGecosPadding(t *testing.T) {
	// GECOS with fewer than four fields pads with empty strings.
	entry, ok := pwParseUserLine("svc:*:10:10::0:0:Only Fullname:/home/svc:/bin/sh")
	if !ok || entry.fullname != "Only Fullname" || entry.roomnumber != "" || entry.workphone != "" || entry.homephone != "" {
		t.Fatalf("gecos padding = %#v", entry)
	}
	// A 7-field /etc/passwd line is not a master.passwd record.
	if _, ok := pwParseUserLine("svc:*:10:10:Only Fullname:/home/svc:/bin/sh"); ok {
		t.Fatalf("7-field line accepted")
	}
}
