package group

// R8.1 mock tests for the FreeBSD pw_group virtual group surface,
// mapped onto saltstack/salt/modules/pw_group.py @ pinned revision
// 8b63e700637e and tests/pytests/unit/modules/test_pw_group.py: the
// add/delete argv forms (shlex-split from the pinned string commands),
// the info/getent record shape, the chgid pre/post verification vectors
// including the unchanged-gid False branch, adduser/deluser retcode
// contracts with the not-a-member short-circuit, members replacement,
// cancellation and binary-missing boundaries, and the freebsd registry
// matrix. The runner is a recording fake; no real pw binary runs.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// pwGroupMockRunner scripts the pw group tool surface. groupmod -g N
// applies the gid change to the store so post-change verification
// reads observe the mutation; frozen=true makes mutations no-ops.
type pwGroupMockRunner struct {
	groups  map[string]string // name -> "passwd:gid:members" body
	frozen  bool
	missing bool
	retcode int
	calls   []process.Command
}

func newPwGroupMockRunner() *pwGroupMockRunner {
	return &pwGroupMockRunner{
		groups: map[string]string{
			"wheel":  "*:0:root",
			"devops": "*:1002:alice,bob",
			"empty":  "*:1003:",
		},
	}
}

func (r *pwGroupMockRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	missing := process.CommandResult{
		Err:      errors.New("exec: \"pw\": executable file not found in $PATH"),
		ExitCode: -1,
	}
	if r.missing || command.Name != "pw" {
		return missing
	}
	if r.retcode != 0 {
		// pw exits 65 when the group is unknown.
		return process.CommandResult{ExitCode: r.retcode, Stderr: []byte("pw: unknown group")}
	}
	argv := append([]string{command.Name}, command.Args...)
	joined := strings.Join(argv, " ")
	switch {
	case strings.Contains(joined, "groupshow -a"):
		var lines []string
		for _, name := range []string{"devops", "empty", "wheel"} {
			lines = append(lines, name+":"+r.groups[name])
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(strings.Join(lines, "\n") + "\n")}
	case strings.Contains(joined, "groupshow -n"):
		name := argv[len(argv)-1]
		if body, ok := r.groups[name]; ok {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(name + ":" + body)}
		}
		return process.CommandResult{ExitCode: 65, Stderr: []byte("pw: unknown group")}
	case strings.Contains(joined, "groupmod") && indexOf(argv, "-g") > 0 && !r.frozen:
		name := argv[indexOf(argv, "groupmod")+1]
		if body, ok := r.groups[name]; ok {
			fields := strings.Split(body, ":")
			fields[1] = argv[indexOf(argv, "-g")+1]
			r.groups[name] = strings.Join(fields, ":")
		}
		return process.CommandResult{ExitCode: 0}
	}
	return process.CommandResult{ExitCode: 0}
}

func pwGroupTestRuntime(runner *pwGroupMockRunner) *runtime.Runtime {
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
}

func pwGroupArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

func indexOf(argv []string, flag string) int {
	for i, arg := range argv {
		if arg == flag {
			return i
		}
	}
	return -1
}

func TestPwGroupAdd(t *testing.T) {
	runner := newPwGroupMockRunner()
	rt := pwGroupTestRuntime(runner)
	got, err := pwGroupAddFunc{}.Execute(context.Background(), rt, &pwGroupAddArgs{Name: "a"})
	if err != nil || got != true {
		t.Fatalf("add = %v err=%v", got, err)
	}
	if want := []string{"pw", "groupadd", "-n", "a"}; !reflect.DeepEqual(pwGroupArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v, want %v", pwGroupArgv(runner.calls[0]), want)
	}
	runner = newPwGroupMockRunner()
	rt = pwGroupTestRuntime(runner)
	if _, err := (pwGroupAddFunc{}).Execute(context.Background(), rt, &pwGroupAddArgs{Name: "foo", GID: "3456"}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"pw", "groupadd", "-g", "3456", "-n", "foo"}; !reflect.DeepEqual(pwGroupArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v", pwGroupArgv(runner.calls[0]))
	}
	// Non-zero retcode reports false (not retcode in the source).
	runner = newPwGroupMockRunner()
	runner.retcode = 65
	rt = pwGroupTestRuntime(runner)
	if got, err := (pwGroupAddFunc{}).Execute(context.Background(), rt, &pwGroupAddArgs{Name: "a"}); err != nil || got != false {
		t.Fatalf("add retcode = %v err=%v", got, err)
	}
}

func TestPwGroupDelete(t *testing.T) {
	runner := newPwGroupMockRunner()
	rt := pwGroupTestRuntime(runner)
	got, err := pwGroupDeleteFunc{}.Execute(context.Background(), rt, &pwGroupDeleteArgs{Name: "a"})
	if err != nil || got != true {
		t.Fatalf("delete = %v err=%v", got, err)
	}
	if want := []string{"pw", "groupdel", "a"}; !reflect.DeepEqual(pwGroupArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v", pwGroupArgv(runner.calls[0]))
	}
}

func TestPwGroupInfoAndGetent(t *testing.T) {
	runner := newPwGroupMockRunner()
	rt := pwGroupTestRuntime(runner)
	got, err := pwGroupInfoFunc{}.Execute(context.Background(), rt, &pwGroupInfoArgs{Name: "devops"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"name":    "devops",
		"passwd":  "*",
		"gid":     1002,
		"members": []string{"alice", "bob"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("info = %#v, want %#v", got, want)
	}
	// Missing group returns the empty dict (grp KeyError path).
	got, err = pwGroupInfoFunc{}.Execute(context.Background(), rt, &pwGroupInfoArgs{Name: "ghost"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("missing info = %#v", got)
	}
	// An empty member list parses to a real empty slice.
	got, err = pwGroupInfoFunc{}.Execute(context.Background(), rt, &pwGroupInfoArgs{Name: "empty"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.(map[string]any)["members"], []string{}) {
		t.Fatalf("empty members = %#v", got)
	}

	got, err = pwGroupGetentFunc{}.Execute(context.Background(), rt, &pwGroupGetentArgs{})
	if err != nil {
		t.Fatal(err)
	}
	entries, ok := got.([]map[string]any)
	if !ok || len(entries) != 3 || entries[0]["name"] != "devops" {
		t.Fatalf("getent = %#v", got)
	}
}

func TestPwGroupChgidVectors(t *testing.T) {
	// Same gid settles with exactly one lookup and no mutation.
	runner := newPwGroupMockRunner()
	rt := pwGroupTestRuntime(runner)
	got, err := pwGroupChgidFunc{}.Execute(context.Background(), rt, &pwGroupChgidArgs{Name: "devops", GID: "1002"})
	if err != nil || got != true {
		t.Fatalf("chgid same = %v err=%v", got, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("same-gid calls = %#v", runner.calls)
	}

	// Applied change verifies true (pinned [1, 0] vector): the mock's
	// groupmod mutates the store gid.
	runner = newPwGroupMockRunner()
	rt = pwGroupTestRuntime(runner)
	got, err = pwGroupChgidFunc{}.Execute(context.Background(), rt, &pwGroupChgidArgs{Name: "devops", GID: "0"})
	if err != nil || got != true {
		t.Fatalf("chgid change = %v err=%v", got, err)
	}
	if want := []string{"pw", "groupmod", "devops", "-g", "0"}; !reflect.DeepEqual(pwGroupArgv(runner.calls[1]), want) {
		t.Fatalf("argv = %v", pwGroupArgv(runner.calls[1]))
	}

	// Unchanged gid after the mutation returns false (pinned [1, 1]).
	runner = newPwGroupMockRunner()
	runner.frozen = true
	rt = pwGroupTestRuntime(runner)
	got, err = pwGroupChgidFunc{}.Execute(context.Background(), rt, &pwGroupChgidArgs{Name: "devops", GID: "0"})
	if err != nil || got != false {
		t.Fatalf("chgid unchanged = %v err=%v", got, err)
	}
	if want := []string{"pw", "groupmod", "devops", "-g", "0"}; !reflect.DeepEqual(pwGroupArgv(runner.calls[1]), want) {
		t.Fatalf("argv = %v", pwGroupArgv(runner.calls[1]))
	}
}

func TestPwGroupAddUserDelUserMembers(t *testing.T) {
	runner := newPwGroupMockRunner()
	rt := pwGroupTestRuntime(runner)
	got, err := pwGroupAddUserFunc{}.Execute(context.Background(), rt, &pwGroupAddUserArgs{Name: "foo", Username: "bar"})
	if err != nil || got != true {
		t.Fatalf("adduser = %v err=%v", got, err)
	}
	if want := []string{"pw", "groupmod", "foo", "-m", "bar"}; !reflect.DeepEqual(pwGroupArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v", pwGroupArgv(runner.calls[0]))
	}
	// pw exit 65 (unknown group) reports false without error.
	runner = newPwGroupMockRunner()
	runner.retcode = 65
	rt = pwGroupTestRuntime(runner)
	if got, err := (pwGroupAddUserFunc{}).Execute(context.Background(), rt, &pwGroupAddUserArgs{Name: "foo", Username: "bar"}); err != nil || got != false {
		t.Fatalf("adduser retcode = %v err=%v", got, err)
	}

	// deluser of a non-member is settled with a single info call.
	runner = newPwGroupMockRunner()
	rt = pwGroupTestRuntime(runner)
	got, err = pwGroupDelUserFunc{}.Execute(context.Background(), rt, &pwGroupDelUserArgs{Name: "devops", Username: "carol"})
	if err != nil || got != true || len(runner.calls) != 1 {
		t.Fatalf("deluser non-member = %v err=%v calls=%d", got, err, len(runner.calls))
	}
	// deluser of a member runs the mutation.
	runner = newPwGroupMockRunner()
	rt = pwGroupTestRuntime(runner)
	if _, err := (pwGroupDelUserFunc{}).Execute(context.Background(), rt, &pwGroupDelUserArgs{Name: "devops", Username: "bob"}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"pw", "groupmod", "devops", "-d", "bob"}; !reflect.DeepEqual(pwGroupArgv(runner.calls[1]), want) {
		t.Fatalf("argv = %v", pwGroupArgv(runner.calls[1]))
	}

	// members replaces the list wholesale.
	runner = newPwGroupMockRunner()
	rt = pwGroupTestRuntime(runner)
	if _, err := (pwGroupMembersFunc{}).Execute(context.Background(), rt,
		&pwGroupMembersArgs{Name: "devops", MembersList: "user1,user2,user3"}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"pw", "groupmod", "devops", "-M", "user1,user2,user3"}; !reflect.DeepEqual(pwGroupArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v", pwGroupArgv(runner.calls[0]))
	}
}

func TestPwGroupCancellationAndBinaryMissing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := newPwGroupMockRunner()
	rt := pwGroupTestRuntime(runner)
	if got, err := (pwGroupInfoFunc{}).Execute(ctx, rt, &pwGroupInfoArgs{Name: "devops"}); got != nil || !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}

	missing := newPwGroupMockRunner()
	missing.missing = true
	rt = pwGroupTestRuntime(missing)
	if got, err := (pwGroupAddFunc{}).Execute(context.Background(), rt, &pwGroupAddArgs{Name: "a"}); got != nil || err == nil || len(missing.calls) != 1 {
		t.Fatalf("binary-missing got=%#v err=%v", got, err)
	}
}

var pwGroupRegistryNames = []string{
	"group.add",
	"group.adduser",
	"group.chgid",
	"group.delete",
	"group.deluser",
	"group.getent",
	"group.info",
	"group.members",
}

func TestPwGroupRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerFreeBSD(reg); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != len(pwGroupRegistryNames) {
		t.Fatalf("registered %d functions, want %d", reg.Len(), len(pwGroupRegistryNames))
	}
	for _, name := range pwGroupRegistryNames {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing from freebsd registration", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok {
			t.Fatalf("%s is not platform-constrained", name)
		}
		platforms := constrained.Platforms()
		if len(platforms) != 1 || platforms[0] != "freebsd" {
			t.Fatalf("%s platforms = %v", name, platforms)
		}
		if !runtime.SupportsPlatform(fn, "freebsd") {
			t.Fatalf("%s does not support freebsd", name)
		}
		if runtime.CurrentGOOS() != "freebsd" && runtime.SupportsPlatform(fn, "linux") {
			t.Fatalf("%s must not support linux", name)
		}
	}
	if runtime.CurrentGOOS() != "freebsd" {
		if names := reg.Names(); len(names) != 0 {
			t.Fatalf("linux registry leaked freebsd group names: %v", names)
		}
		_, err := reg.Call(context.Background(), &runtime.Runtime{}, "group.members", &pwGroupMembersArgs{})
		var unsupported *runtime.UnsupportedError
		if !errors.As(err, &unsupported) {
			t.Fatalf("group.members on linux err=%v, want UnsupportedError", err)
		}
	} else if names := reg.Names(); !reflect.DeepEqual(names, pwGroupRegistryNames) {
		t.Fatalf("freebsd registry names = %v", names)
	}
	if err := registerFreeBSD(reg); err == nil {
		t.Fatalf("duplicate freebsd registration accepted")
	}
}

// TestPwGroupRegisterKeepsLinuxSurfaceCanonical proves the freebsd file
// adds no duplicate group.* registration on the Linux host: the shared
// names stay single-registration and the freebsd-only names stay
// unregistered.
func TestPwGroupRegisterKeepsLinuxSurfaceCanonical(t *testing.T) {
	if runtime.CurrentGOOS() == "freebsd" {
		t.Skip("freebsd host registers the freebsd surface")
	}
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"group.adduser", "group.deluser", "group.members", "group.getent"} {
		if _, exists := reg.Get(name); exists {
			t.Fatalf("linux registry unexpectedly carries freebsd-only %s", name)
		}
	}
	for _, name := range []string{"group.add", "group.delete", "group.info", "group.list_groups", "group.chgid"} {
		count := 0
		for _, registered := range reg.Names() {
			if registered == name {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s registered %d times on linux", name, count)
		}
	}
}
