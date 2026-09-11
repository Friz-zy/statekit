//go:build darwin

package group

// R6.10 mock tests for the Darwin group surface, mapped onto
// saltstack/salt/modules/mac_group.py @ pinned revision 8b63e700637e
// and tests/pytests/unit/modules/test_mac_group.py: the add/delete
// validation ladder with Salt's exact error texts, dseditgroup argv
// (including the Salt `if gid:` zero-skip), membership shell commands,
// getent underscore filtering and caching, chgid flows, dscacheutil
// record parsing and the darwin registry matrix. The runner is a
// stateful in-memory directory-services store; no real binary runs.

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type dsGroupEntry struct {
	gid     string
	members []string
}

// dsGroupRunner simulates the dscacheutil/dseditgroup/dscl tool surface
// against a live group store so create/edit/delete are observable.
type dsGroupRunner struct {
	mu       sync.Mutex
	groups   map[string]dsGroupEntry
	calls    []process.Command
	failOn   string // command substring that exits 1
	shellCmd []string
}

func newDSGroupRunner() *dsGroupRunner {
	return &dsGroupRunner{groups: map[string]dsGroupEntry{
		"staff":   {gid: "20", members: []string{"alice", "bob"}},
		"_hidden": {gid: "213", members: nil},
	}}
}

func (r *dsGroupRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, command)
	joined := strings.Join(append([]string{command.Name}, command.Args...), " ")
	if r.failOn != "" && strings.Contains(joined, r.failOn) {
		return process.CommandResult{ExitCode: 1, Stderr: []byte("simulated failure")}
	}
	switch {
	case command.Name == "dscacheutil" && len(command.Args) >= 5 && command.Args[2] == "-a" && command.Args[3] == "name":
		name := command.Args[4]
		if entry, ok := r.groups[name]; ok {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(groupRecord(name, entry))}
		}
		return process.CommandResult{ExitCode: 0}
	case command.Name == "dscacheutil":
		var out []string
		for name, entry := range r.groups {
			out = append(out, groupRecord(name, entry))
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(strings.Join(out, "\n"))}
	case command.Name == "dseditgroup" && command.Args[1] == "create":
		name := command.Args[len(command.Args)-1]
		gid := "next"
		for i, arg := range command.Args {
			if arg == "-i" && i+1 < len(command.Args) {
				gid = command.Args[i+1]
			}
		}
		r.groups[name] = dsGroupEntry{gid: gid}
		return process.CommandResult{ExitCode: 0}
	case command.Name == "dseditgroup" && command.Args[1] == "delete":
		delete(r.groups, command.Args[len(command.Args)-1])
		return process.CommandResult{ExitCode: 0}
	case command.Name == "dseditgroup" && command.Args[1] == "edit":
		name := command.Args[len(command.Args)-1]
		if entry, ok := r.groups[name]; ok {
			for i, arg := range command.Args {
				if arg == "-i" && i+1 < len(command.Args) {
					entry.gid = command.Args[i+1]
				}
			}
			r.groups[name] = entry
		}
		return process.CommandResult{ExitCode: 0}
	case command.Name == "dscl" || command.Name == "/usr/bin/dscl":
		r.shellCmd = append(r.shellCmd, command.Name)
		words := strings.Fields(command.Name)
		// membership clear: dscl . -delete /Groups/X GroupMembership
		if len(words) == 5 && words[2] == "-delete" && words[4] == "GroupMembership" {
			name := strings.Split(words[3], "/")[2]
			if entry, ok := r.groups[name]; ok {
				entry.members = nil
				r.groups[name] = entry
			}
			return process.CommandResult{ExitCode: 0}
		}
		return process.CommandResult{ExitCode: 0}
	}
	return process.CommandResult{ExitCode: 0}
}

func groupRecord(name string, entry dsGroupEntry) string {
	return "name: " + name + "\npassword: *\ngid: " + entry.gid + "\nusers: " +
		strings.Join(entry.members, " ") + "\n"
}

func dsGroupRT(t *testing.T) (*runtime.Runtime, *dsGroupRunner) {
	t.Helper()
	macGroupCacheMu.Lock()
	saved := macGroupCache
	macGroupCache = nil
	macGroupCacheMu.Unlock()
	t.Cleanup(func() {
		macGroupCacheMu.Lock()
		macGroupCache = saved
		macGroupCacheMu.Unlock()
	})
	runner := newDSGroupRunner()
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}, runner
}

func dsArgv(command process.Command) string {
	return strings.Join(append([]string{command.Name}, command.Args...), " ")
}

// ---------------------------------------------------------------------------
// add

func TestDarwinAddValidationLadder(t *testing.T) {
	rt, runner := dsGroupRT(t)
	// existing group: CommandExecutionError text from the pytest
	_, err := (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{Name: "staff"})
	if err == nil || err.Error() != "Group 'staff' already exists" {
		t.Fatalf("exists = %v", err)
	}
	// whitespace and underscore: SaltInvocationError texts
	_, err = (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{Name: "white space"})
	if err == nil || err.Error() != "Group name cannot contain whitespace" {
		t.Fatalf("whitespace = %v", err)
	}
	_, err = (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{Name: "_Test"})
	if err == nil || err.Error() != "Salt will not create groups beginning with underscores" {
		t.Fatalf("underscore = %v", err)
	}
	// negative gid
	negative := -1
	_, err = (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{Name: "foo", GID: &negative})
	if err == nil || err.Error() != "gid must be an integer" {
		t.Fatalf("gid int = %v", err)
	}
	// gid already in use
	used := 20
	_, err = (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{Name: "foo", GID: &used})
	if err == nil || err.Error() != "gid '20' already exists" {
		t.Fatalf("gid exists = %v", err)
	}
	for _, command := range runner.calls {
		if command.Name == "dseditgroup" {
			t.Fatalf("validation ladder reached dseditgroup: %+v", command)
		}
	}
}

func TestDarwinAddArgv(t *testing.T) {
	rt, runner := dsGroupRT(t)
	gid := 500
	res, err := (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{Name: "test", GID: &gid})
	if err != nil || res != true {
		t.Fatalf("add = %v %v", res, err)
	}
	if got := dsArgv(runner.calls[len(runner.calls)-1]); got != "dseditgroup -o create -i 500 test" {
		t.Fatalf("add argv = %q", got)
	}
	// Salt's `if gid:` skips -i for gid 0
	zero := 0
	res, err = (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{Name: "zero", GID: &zero})
	if err != nil || res != true {
		t.Fatalf("add zero = %v %v", res, err)
	}
	if got := dsArgv(runner.calls[len(runner.calls)-1]); got != "dseditgroup -o create zero" {
		t.Fatalf("add zero argv = %q", got)
	}
	// without a gid there is no -i flag either
	res, err = (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{Name: "plain"})
	if err != nil || res != true {
		t.Fatalf("add plain = %v %v", res, err)
	}
	if got := dsArgv(runner.calls[len(runner.calls)-1]); got != "dseditgroup -o create plain" {
		t.Fatalf("add plain argv = %q", got)
	}
	if runner.calls[0].Shell {
		t.Fatal("dseditgroup commands must stay shell-free")
	}
	// a failed create surfaces False
	runner.failOn = "dseditgroup"
	res, err = (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{Name: "broken"})
	if err != nil || res != false {
		t.Fatalf("failed add = %v %v", res, err)
	}
}

// ---------------------------------------------------------------------------
// delete

func TestDarwinDeleteFlows(t *testing.T) {
	rt, runner := dsGroupRT(t)
	// missing group deletes as a no-op True (pytest test_delete_group_exists)
	res, err := (macDeleteFunc{}).Execute(context.Background(), rt, &macDeleteArgs{Name: "ghost"})
	if err != nil || res != true {
		t.Fatalf("missing delete = %v %v", res, err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("missing delete issued commands: %+v", runner.calls)
	}
	res, err = (macDeleteFunc{}).Execute(context.Background(), rt, &macDeleteArgs{Name: "staff"})
	if err != nil || res != true {
		t.Fatalf("delete = %v %v", res, err)
	}
	if got := dsArgv(runner.calls[0]); got != "dseditgroup -o delete staff" {
		t.Fatalf("delete argv = %q", got)
	}
	// underscore rejection uses the "remove" wording
	if _, err := (macDeleteFunc{}).Execute(context.Background(), rt, &macDeleteArgs{Name: "_hidden"}); err == nil ||
		err.Error() != "Salt will not remove groups beginning with underscores" {
		t.Fatalf("underscore delete = %v", err)
	}
	// a failing dseditgroup returns False, not an error
	if _, err := (macAddFunc{}).Execute(context.Background(), rt, &macAddArgs{Name: "plain"}); err != nil {
		t.Fatal(err)
	}
	runner.failOn = "dseditgroup -o delete"
	res, err = (macDeleteFunc{}).Execute(context.Background(), rt, &macDeleteArgs{Name: "plain"})
	if err != nil || res != false {
		t.Fatalf("failed delete = %v %v", res, err)
	}
}

// ---------------------------------------------------------------------------
// membership

func TestDarwinDelUserShellCommand(t *testing.T) {
	rt, runner := dsGroupRT(t)
	res, err := (macDelUserFunc{}).Execute(context.Background(), rt, &macAddUserArgs{Group: "staff", Name: "charlie"})
	if err != nil || res != true {
		t.Fatalf("deluser = %v %v", res, err)
	}
	command := runner.calls[len(runner.calls)-1]
	if !command.Shell {
		t.Fatal("deluser uses the shell command contract")
	}
	if command.Name != "dscl . -delete /Groups/staff GroupMembership charlie" {
		t.Fatalf("deluser command = %q", command.Name)
	}
}

func TestDarwinMembersFlow(t *testing.T) {
	rt, runner := dsGroupRT(t)
	res, err := (macMembersFunc{}).Execute(context.Background(), rt, &macMembersArgs{
		Name: "staff", Members: []string{"alice", "dave"},
	})
	if err != nil || res != true {
		t.Fatalf("members = %v %v", res, err)
	}
	// Salt clears membership first, then merges each member in order.
	var commands []string
	for _, command := range runner.calls {
		if command.Shell {
			commands = append(commands, command.Name)
		}
	}
	want := []string{
		"/usr/bin/dscl . -delete /Groups/staff GroupMembership",
		"/usr/bin/dscl . -merge /Groups/staff GroupMembership alice",
		"/usr/bin/dscl . -merge /Groups/staff GroupMembership dave",
	}
	if len(commands) != len(want) {
		t.Fatalf("member commands = %v", commands)
	}
	for i := range want {
		if commands[i] != want[i] {
			t.Fatalf("command %d = %q; want %q", i, commands[i], want[i])
		}
	}
	// a missing group reports False without touching dscl
	runner.calls = nil
	res, err = (macMembersFunc{}).Execute(context.Background(), rt, &macMembersArgs{
		Name: "ghost", Members: []string{"alice"},
	})
	if err != nil || res != false {
		t.Fatalf("missing members = %v %v", res, err)
	}
	for _, command := range runner.calls {
		if command.Shell {
			t.Fatalf("missing members touched dscl: %q", command.Name)
		}
	}
	// a failing merge aborts with False
	runner.failOn = "-merge /Groups/staff GroupMembership dave"
	res, err = (macMembersFunc{}).Execute(context.Background(), rt, &macMembersArgs{
		Name: "staff", Members: []string{"alice", "dave"},
	})
	if err != nil || res != false {
		t.Fatalf("failed merge = %v %v", res, err)
	}
}

// ---------------------------------------------------------------------------
// info / getent / chgid

func TestDarwinInfoWhitespaceAndMissing(t *testing.T) {
	rt, _ := dsGroupRT(t)
	if _, err := (macInfoFunc{}).Execute(context.Background(), rt, &macInfoArgs{Name: "white space"}); err == nil ||
		err.Error() != "Group name cannot contain whitespace" {
		t.Fatalf("info whitespace = %v", err)
	}
	res, err := (macInfoFunc{}).Execute(context.Background(), rt, &macInfoArgs{Name: "ghost"})
	if err != nil || !reflect.DeepEqual(res, map[string]any{}) {
		t.Fatalf("missing info = %#v %v", res, err)
	}
}

func TestDarwinGetentFiltersAndCaches(t *testing.T) {
	rt, runner := dsGroupRT(t)
	res, err := (macGetentFunc{}).Execute(context.Background(), rt, &macGetentArgs{})
	if err != nil {
		t.Fatal(err)
	}
	groups := res.([]map[string]any)
	if len(groups) != 1 || groups[0]["name"] != "staff" {
		t.Fatalf("getent = %#v (underscore groups must be filtered)", groups)
	}
	afterFirst := len(runner.calls)
	// cached reads never re-query the directory service
	res, err = (macGetentFunc{}).Execute(context.Background(), rt, &macGetentArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != afterFirst {
		t.Fatalf("cache miss: %d commands", len(runner.calls)-afterFirst)
	}
	if !reflect.DeepEqual(res.([]map[string]any), groups) {
		t.Fatal("cached getent diverged")
	}
	// refresh re-queries
	res, err = (macGetentFunc{}).Execute(context.Background(), rt, &macGetentArgs{Refresh: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2*afterFirst {
		t.Fatalf("refresh commands = %d", len(runner.calls)-afterFirst)
	}
}

func TestDarwinChgidFlows(t *testing.T) {
	rt, runner := dsGroupRT(t)
	// missing group error text (pytest test_chgid_group_exists)
	_, err := (macChgidFunc{}).Execute(context.Background(), rt, &macChgidArgs{Name: "ghost", GID: 500})
	if err == nil || err.Error() != "Group 'ghost' does not exist" {
		t.Fatalf("chgid missing = %v", err)
	}
	// same gid short-circuits to True without dseditgroup
	before := len(runner.calls)
	res, err := (macChgidFunc{}).Execute(context.Background(), rt, &macChgidArgs{Name: "staff", GID: 20})
	if err != nil || res != true {
		t.Fatalf("chgid same = %v %v", res, err)
	}
	if len(runner.calls) != before {
		t.Fatal("same-gid chgid must not run dseditgroup")
	}
	// real change runs the edit command (pytest test_chgid argv)
	res, err = (macChgidFunc{}).Execute(context.Background(), rt, &macChgidArgs{Name: "staff", GID: 500})
	if err != nil || res != true {
		t.Fatalf("chgid = %v %v", res, err)
	}
	if got := dsArgv(runner.calls[len(runner.calls)-1]); got != "dseditgroup -o edit -i 500 staff" {
		t.Fatalf("chgid argv = %q", got)
	}
	// the store observed the new gid
	if info := macGroupInfo(context.Background(), rt, "staff"); info["gid"] != 500 {
		t.Fatalf("post-chgid gid = %v", info["gid"])
	}
}

func TestDarwinGroupIDsAndRecordParsing(t *testing.T) {
	rt, _ := dsGroupRT(t)
	ids := macGroupIDs(context.Background(), rt)
	if !ids["20"] || !ids["213"] {
		t.Fatalf("gids = %v", ids)
	}
	records := parseGroupRecords("name: a\npassword: *\ngid: 1\nusers: x y\n\nname: b\ngid: 2\ngarbage-line\n")
	if len(records) != 2 || records[0]["name"] != "a" || records[1]["gid"] != "2" {
		t.Fatalf("records = %#v", records)
	}
	// users field parsing: Fields splits whitespace, empty users → empty list
	info := groupRecordInfo(map[string]string{"name": "n", "password": "*", "gid": "7", "users": ""})
	if !reflect.DeepEqual(info["members"], []string{}) || info["gid"] != 7 {
		t.Fatalf("record info = %#v", info)
	}
	info = groupRecordInfo(map[string]string{"name": "n", "gid": " 8 ", "users": "  a\tb "})
	if !reflect.DeepEqual(info["members"], []string{"a", "b"}) || info["gid"] != 8 {
		t.Fatalf("record info fields = %#v", info)
	}
}

func TestDarwinGroupRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerMac(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"group.add",
		"group.adduser",
		"group.chgid",
		"group.delete",
		"group.deluser",
		"group.getent",
		"group.info",
		"group.members",
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
