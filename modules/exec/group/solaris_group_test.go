package group

// R8.2 mock tests for the Solaris solaris_group virtual group surface,
// mapped onto saltstack/salt/modules/solaris_group.py @ pinned revision
// 8b63e700637e: the add/delete argv forms, the info/getent dict shapes,
// chgid's pre/post gid verification, cancellation and binary-missing
// boundaries, strict numeric gid parsing, and the solaris registry matrix.
// The runner is a stateful in-memory getent/groupadd store; no real binary
// runs.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// sunStoreGroup is one record in the fake group database.
type sunStoreGroup struct {
	name    string
	gid     string
	members []string
}

func (g sunStoreGroup) line() string {
	return strings.Join([]string{g.name, "x", g.gid, strings.Join(g.members, ",")}, ":")
}

// sunStoreRunner simulates the Solaris group tool surface: getent
// group reads and groupadd/groupdel/groupmod writes. frozen=true makes
// mutating verbs succeed without applying changes.
type sunStoreRunner struct {
	groups  map[string]sunStoreGroup
	frozen  bool
	missing bool
	retcode int
	listing string
	calls   []process.Command
}

func newSunStoreRunner() *sunStoreRunner {
	return &sunStoreRunner{
		groups: map[string]sunStoreGroup{
			"root":   {name: "root", gid: "0", members: []string{}},
			"other":  {name: "other", gid: "1", members: []string{"root"}},
			"staff":  {name: "staff", gid: "10", members: []string{"root"}},
			"devops": {name: "devops", gid: "1002", members: []string{"alice"}},
		},
	}
}

func (r *sunStoreRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	missing := process.CommandResult{
		Err:      errors.New("exec: executable file not found in $PATH"),
		ExitCode: -1,
	}
	known := map[string]bool{"getent": true, "groupadd": true, "groupdel": true, "groupmod": true}
	if r.missing || !known[command.Name] {
		return missing
	}
	if r.retcode != 0 {
		return process.CommandResult{ExitCode: r.retcode, Stderr: []byte("UX command failure")}
	}
	argv := append([]string{command.Name}, command.Args...)
	joined := strings.Join(argv, " ")
	ok := process.CommandResult{ExitCode: 0}
	switch {
	case strings.HasPrefix(joined, "getent group") && len(argv) == 3:
		if r.listing != "" {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.listing)}
		}
		if group, exists := r.groups[argv[2]]; exists {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(group.line() + "\n")}
		}
		return process.CommandResult{ExitCode: 2}
	case strings.HasPrefix(joined, "getent group"):
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
		var lines []string
		for _, name := range names {
			lines = append(lines, r.groups[name].line())
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(strings.Join(lines, "\n") + "\n")}
	case strings.HasPrefix(joined, "groupadd"):
		group := sunStoreGroup{name: argv[len(argv)-1], gid: "10100"}
		if idx := sunGroupFlag(argv, "-g"); idx > 0 {
			group.gid = argv[idx+1]
		}
		r.groups[group.name] = group
		return ok
	case strings.HasPrefix(joined, "groupdel"):
		delete(r.groups, argv[len(argv)-1])
		return ok
	case strings.HasPrefix(joined, "groupmod"):
		if r.frozen {
			return ok
		}
		name := argv[len(argv)-1]
		group, exists := r.groups[name]
		if !exists {
			return ok
		}
		if idx := sunGroupFlag(argv, "-g"); idx > 0 {
			group.gid = argv[idx+1]
			r.groups[name] = group
		}
		return ok
	}
	return ok
}

func sunGroupFlag(argv []string, flag string) int {
	for i, arg := range argv {
		if arg == flag {
			return i
		}
	}
	return -1
}

func sunTestRuntime(runner *sunStoreRunner) *runtime.Runtime {
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
}

func sunArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

func TestSunGroupAdd(t *testing.T) {
	runner := newSunStoreRunner()
	rt := sunTestRuntime(runner)
	got, err := sunGroupAddFunc{}.Execute(context.Background(), rt, &sunGroupAddArgs{Name: "foo"})
	if err != nil || got != true {
		t.Fatalf("add = %v err=%v", got, err)
	}
	if want := []string{"groupadd", "foo"}; !reflect.DeepEqual(sunArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v, want %v", sunArgv(runner.calls[0]), want)
	}

	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	if _, err := (sunGroupAddFunc{}).Execute(context.Background(), rt, &sunGroupAddArgs{Name: "foo", GID: "3456"}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"groupadd", "-g", "3456", "foo"}; !reflect.DeepEqual(sunArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v, want %v", sunArgv(runner.calls[0]), want)
	}

	// Non-zero retcode reports false (not retcode in the source).
	runner = newSunStoreRunner()
	runner.retcode = 9
	rt = sunTestRuntime(runner)
	got, err = sunGroupAddFunc{}.Execute(context.Background(), rt, &sunGroupAddArgs{Name: "foo"})
	if err != nil || got != false {
		t.Fatalf("add retcode = %v err=%v", got, err)
	}
}

func TestSunGroupDelete(t *testing.T) {
	runner := newSunStoreRunner()
	rt := sunTestRuntime(runner)
	got, err := sunGroupDeleteFunc{}.Execute(context.Background(), rt, &sunGroupDeleteArgs{Name: "staff"})
	if err != nil || got != true {
		t.Fatalf("delete = %v err=%v", got, err)
	}
	if want := []string{"groupdel", "staff"}; !reflect.DeepEqual(sunArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v", sunArgv(runner.calls[0]))
	}
	if _, exists := runner.groups["staff"]; exists {
		t.Fatalf("groupdel did not remove the store record")
	}
}

func TestSunGroupInfoAndGetent(t *testing.T) {
	runner := newSunStoreRunner()
	rt := sunTestRuntime(runner)
	got, err := sunGroupInfoFunc{}.Execute(context.Background(), rt, &sunGroupInfoArgs{Name: "devops"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"name":    "devops",
		"passwd":  "x",
		"gid":     1002,
		"members": []string{"alice"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("info = %#v, want %#v", got, want)
	}

	// Missing group returns the empty dict (KeyError path).
	got, err = sunGroupInfoFunc{}.Execute(context.Background(), rt, &sunGroupInfoArgs{Name: "ghost"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("missing info = %#v", got)
	}

	got, err = sunGroupGetentFunc{}.Execute(context.Background(), rt, &sunGroupGetentArgs{})
	if err != nil {
		t.Fatal(err)
	}
	entries, ok := got.([]map[string]any)
	if !ok || len(entries) != 4 {
		t.Fatalf("getent = %#v", got)
	}
	if entries[0]["name"] != "devops" || entries[3]["name"] != "staff" {
		t.Fatalf("getent order = %#v", entries)
	}
}

func TestSunGroupParserRejectsInvalidIDs(t *testing.T) {
	cases := []struct {
		name  string
		gid   string
		valid bool
	}{
		{"alpha", "alpha", false},
		{"overflow", strings.Repeat("9", 100), false},
		{"negative", "-1", false},
		{"zero", "0", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record, ok, err := sunGroupParseLine("staff:x:" + tc.gid + ":alice")
			if tc.valid {
				if err != nil || !ok || record.gid != 0 {
					t.Fatalf("parse = %#v ok=%v err=%v, want zero gid", record, ok, err)
				}
				return
			}
			if err == nil || ok {
				t.Fatalf("parse = %#v ok=%v err=%v, want deterministic error", record, ok, err)
			}
		})
	}
}

func TestSunGroupProviderRejectsInvalidIDs(t *testing.T) {
	lines := []string{
		"root:x:alpha:alice",
		"root:x:" + strings.Repeat("9", 100) + ":alice",
		"root:x:-1:alice",
		"root:x:0:alice",
	}
	for i, line := range lines {
		runner := newSunStoreRunner()
		runner.listing = line + "\n"
		record, ok, err := sunGroupShow(context.Background(), sunTestRuntime(runner), "root")
		if i < len(lines)-1 {
			if err == nil || ok {
				t.Fatalf("group provider line %q = %#v ok=%v err=%v, want parse error", line, record, ok, err)
			}
		} else if err != nil || !ok || record.gid != 0 {
			t.Fatalf("zero group provider = %#v ok=%v err=%v", record, ok, err)
		}
	}
}

func TestSunGroupChgid(t *testing.T) {
	ctx := context.Background()

	// Same gid short-circuits with a single lookup.
	runner := newSunStoreRunner()
	rt := sunTestRuntime(runner)
	got, err := sunGroupChgidFunc{}.Execute(ctx, rt, &sunGroupChgidArgs{Name: "devops", GID: "1002"})
	if err != nil || got != true {
		t.Fatalf("chgid same = %v err=%v", got, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("same-value calls = %#v", runner.calls)
	}

	// Change runs groupmod -g and verifies the new gid.
	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	got, err = sunGroupChgidFunc{}.Execute(ctx, rt, &sunGroupChgidArgs{Name: "devops", GID: "4376"})
	if err != nil || got != true {
		t.Fatalf("chgid change = %v err=%v", got, err)
	}
	if want := []string{"groupmod", "-g", "4376", "devops"}; !reflect.DeepEqual(sunArgv(runner.calls[1]), want) {
		t.Fatalf("argv = %v", sunArgv(runner.calls[1]))
	}

	// Frozen store: the gid never moves, the pinned tail returns false.
	runner = newSunStoreRunner()
	runner.frozen = true
	rt = sunTestRuntime(runner)
	got, err = sunGroupChgidFunc{}.Execute(ctx, rt, &sunGroupChgidArgs{Name: "devops", GID: "4376"})
	if err != nil || got != false {
		t.Fatalf("chgid frozen = %v err=%v", got, err)
	}

	// Unknown group: pre_gid "" never equals the request, the mutation
	// runs, and the unchanged lookup closes with false.
	runner = newSunStoreRunner()
	rt = sunTestRuntime(runner)
	got, err = sunGroupChgidFunc{}.Execute(ctx, rt, &sunGroupChgidArgs{Name: "ghost", GID: "123"})
	if err != nil || got != false {
		t.Fatalf("chgid ghost = %v err=%v", got, err)
	}
	if want := []string{"groupmod", "-g", "123", "ghost"}; !reflect.DeepEqual(sunArgv(runner.calls[1]), want) {
		t.Fatalf("argv = %v", sunArgv(runner.calls[1]))
	}
}

func TestSunGroupCancellationAndMissing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := newSunStoreRunner()
	rt := sunTestRuntime(runner)
	if _, err := (sunGroupInfoFunc{}).Execute(ctx, rt, &sunGroupInfoArgs{Name: "devops"}); err == nil {
		t.Fatal("canceled context must error before the Runner starts")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled context spawned %#v", runner.calls)
	}

	runner = newSunStoreRunner()
	runner.missing = true
	rt = sunTestRuntime(runner)
	if _, err := (sunGroupDeleteFunc{}).Execute(context.Background(), rt, &sunGroupDeleteArgs{Name: "devops"}); err == nil {
		t.Fatal("binary-missing delete must error, not fabricate success")
	}
}

// ---------------------------------------------------------------------------
// registry matrix

var sunGroupRegistryNames = []string{
	"group.add",
	"group.chgid",
	"group.delete",
	"group.getent",
	"group.info",
}

func TestSunGroupRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerSolaris(reg); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != len(sunGroupRegistryNames) {
		t.Fatalf("registered %d functions, want %d", reg.Len(), len(sunGroupRegistryNames))
	}
	for _, name := range sunGroupRegistryNames {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing from solaris registration", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok {
			t.Fatalf("%s is not platform-constrained", name)
		}
		platforms := constrained.Platforms()
		if len(platforms) != 1 || platforms[0] != "solaris" {
			t.Fatalf("%s platforms = %v", name, platforms)
		}
		if !runtime.SupportsPlatform(fn, "solaris") {
			t.Fatalf("%s does not support solaris", name)
		}
		if runtime.SupportsPlatform(fn, "linux") {
			t.Fatalf("%s must not support linux", name)
		}
	}
	if runtime.CurrentGOOS() != "solaris" && len(reg.Names()) != 0 {
		t.Fatalf("host registry leaked solaris group names: %v", reg.Names())
	}
	if err := registerSolaris(reg); err == nil {
		t.Fatalf("duplicate solaris registration accepted")
	}

	// The solaris dispatch adds no duplicate group.* registration on
	// the Linux host.
	if runtime.CurrentGOOS() != "solaris" {
		linux := runtime.NewExecRegistry()
		if err := Register(linux); err != nil {
			t.Fatal(err)
		}
		if _, exists := linux.Get("group.getent"); exists {
			t.Fatal("linux registry unexpectedly carries solaris-only group.getent")
		}
		for _, name := range []string{"group.add", "group.info"} {
			count := 0
			for _, registered := range linux.Names() {
				if registered == name {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("%s registered %d times on linux", name, count)
			}
		}
	}
}
