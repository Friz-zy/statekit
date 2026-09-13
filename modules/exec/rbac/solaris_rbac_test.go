package rbac

// Mock coverage for every public function in the pinned rbac_solaris source.
// The filesystem contains pinned policy.conf/prof_attr/user_attr/auth_attr
// fixtures and the Runner only records shell-free argv; no Solaris database or
// command is touched.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type rbacFakeRunner struct {
	results       map[string][]process.CommandResult
	defaultResult process.CommandResult
	calls         []process.Command
}

func (r *rbacFakeRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	command.Args = append([]string(nil), command.Args...)
	r.calls = append(r.calls, command)
	key := strings.Join(append([]string{command.Name}, command.Args...), " ")
	if queued := r.results[key]; len(queued) > 0 {
		result := queued[0]
		r.results[key] = queued[1:]
		return result
	}
	return r.defaultResult
}

func newRBACRuntime(t *testing.T, runner *rbacFakeRunner) *runtime.Runtime {
	t.Helper()
	fsys := runtime.NewMemoryFS()
	if err := fsys.MkdirAll("/etc/security", 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, data string) {
		t.Helper()
		if err := fsys.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("/etc/security/policy.conf", "# fixture\nPROFS_GRANTED=Basic,All\n")
	write("/etc/security/prof_attr", "All:x:x:All profile:x\nBasic:x:x:Basic profile:x\nHidden:x:x:Hidden profile:x\nbad\n")
	write("/etc/user_attr", strings.Join([]string{
		"alice::::profiles=All,Basic,Hidden;roles=netcfg,operator;auths=solaris.zone.manage,solaris.mail.mailq;type=normal",
		"netcfg::::auths=solaris.zone.manage;profiles=Network;type=role",
		"operator::::roles=netcfg;type=role",
		"bob::::profiles=Hidden;type=normal",
		"",
	}, "\n"))
	write("/etc/security/auth_attr", strings.Join([]string{
		"solaris.zone.manage:x:x:Zone Manage:x:x",
		"solaris.mail.mailq:x:x:Mail Queue:x:x",
		"solaris.system.:x:x:System subtree:x:x",
		"bad:x:y:z",
		"",
	}, "\n"))
	return &runtime.Runtime{Runner: runner, FS: fsys}
}

func newRBACRuntimeWithEOFRole(t *testing.T, runner *rbacFakeRunner) *runtime.Runtime {
	t.Helper()
	rt := newRBACRuntime(t, runner)
	fsys := rt.FS.(*runtime.MemoryFS)
	data := strings.Join([]string{
		"alice::::profiles=All,Basic,Hidden;roles=netcfg,operator;auths=solaris.zone.manage,solaris.mail.mailq;type=normal",
		"operator::::roles=netcfg;type=role",
		// role_list intentionally recognizes only this final record: the
		// preceding records retain their line-ending newline in type.
		"netcfg::::auths=solaris.zone.manage;profiles=Network;type=role",
	}, "\n")
	if err := fsys.WriteFile("/etc/user_attr", []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return rt
}

func rbacArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

func assertRBACBounded(t *testing.T, command process.Command) {
	t.Helper()
	if command.Shell || command.Timeout != rbacCommandTimeout ||
		command.MaxStdoutBytes != rbacOutputLimit || command.MaxStderrBytes != rbacOutputLimit {
		t.Fatalf("unsafe Runner command: %#v", command)
	}
}

func TestRBACRegistryMatrixAndArgs(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerSolaris(reg); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		prototype any
		args      []string
	}{
		"rbac.profile_list": {profileListArgs{}, []string{"default_only"}},
		"rbac.profile_get":  {profileGetArgs{}, []string{"default_hidden", "user"}},
		"rbac.profile_add":  {profileMutationArgs{}, []string{"profile", "user"}},
		"rbac.profile_rm":   {profileMutationArgs{}, []string{"profile", "user"}},
		"rbac.role_list":    {roleListArgs{}, []string{}},
		"rbac.role_get":     {roleGetArgs{}, []string{"user"}},
		"rbac.role_add":     {roleMutationArgs{}, []string{"role", "user"}},
		"rbac.role_rm":      {roleMutationArgs{}, []string{"role", "user"}},
		"rbac.auth_list":    {authListArgs{}, []string{}},
		"rbac.auth_get":     {authGetArgs{}, []string{"computed", "user"}},
		"rbac.auth_add":     {authMutationArgs{}, []string{"auth", "user"}},
		"rbac.auth_rm":      {authMutationArgs{}, []string{"auth", "user"}},
	}
	if reg.Len() != len(want) {
		t.Fatalf("registry length=%d want=%d", reg.Len(), len(want))
	}
	for name, row := range want {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if reflect.TypeOf(fn.Args()) != reflect.TypeOf(row.prototype) {
			t.Fatalf("%s args type=%T want=%T", name, fn.Args(), row.prototype)
		}
		got, err := config.ArgumentNames(fn.Args())
		if err != nil || !reflect.DeepEqual(got, row.args) {
			t.Fatalf("%s args=%v err=%v want=%v", name, got, err, row.args)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok || !reflect.DeepEqual(constrained.Platforms(), []string{"solaris"}) {
			t.Fatalf("%s platform constraint=%v/%t", name, constrained, ok)
		}
		if runtime.SupportsPlatform(fn, "linux") || !runtime.SupportsPlatform(fn, "solaris") {
			t.Fatalf("%s platform support incorrect", name)
		}
	}
	if err := registerSolaris(reg); err == nil {
		t.Fatal("duplicate Solaris registration accepted")
	}
	if runtime.CurrentGOOS() != "solaris" && len(reg.Names()) != 0 {
		t.Fatalf("Solaris names leaked into Linux Names: %v", reg.Names())
	}
}

func TestRBACRegisterLeavesLinuxSurfaceUnchanged(t *testing.T) {
	if runtime.CurrentGOOS() == "solaris" {
		t.Skip("Linux surface assertion does not apply on Solaris")
	}
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Names()) != 0 {
		t.Fatalf("rbac Register exposed Solaris functions: %v", reg.Names())
	}
	runner := &rbacFakeRunner{}
	_, err := func() (any, error) {
		return reg.Call(context.Background(), &runtime.Runtime{Runner: runner}, "rbac.auth_list", &authListArgs{})
	}()
	var unsupported *runtime.UnsupportedError
	if !errors.As(err, &unsupported) || len(runner.calls) != 0 {
		t.Fatalf("Linux call err=%v calls=%d", err, len(runner.calls))
	}
}

func TestRBACReadFixturesAndExactShapes(t *testing.T) {
	runner := &rbacFakeRunner{}
	rt := newRBACRuntime(t, runner)

	got, err := (profileListFunc{}).Execute(context.Background(), rt, &profileListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"All": "All profile", "Basic": "Basic profile", "Hidden": "Hidden profile"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("profile_list=%#v want=%#v", got, want)
	}
	defaultOnly := true
	got, err = (profileListFunc{}).Execute(context.Background(), rt, &profileListArgs{DefaultOnly: &defaultOnly})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"All": "All profile", "Basic": "Basic profile"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("profile_list default=%#v want=%#v", got, want)
	}

	got, err = (profileGetFunc{}).Execute(context.Background(), rt, &profileGetArgs{User: "alice"})
	if err != nil || !reflect.DeepEqual(got, []string{"Hidden"}) {
		t.Fatalf("profile_get default=%#v err=%v", got, err)
	}
	hidden := false
	got, err = (profileGetFunc{}).Execute(context.Background(), rt, &profileGetArgs{User: "alice", DefaultHidden: &hidden})
	if err != nil || !reflect.DeepEqual(got, []string{"All", "Basic", "Hidden"}) {
		t.Fatalf("profile_get all=%#v err=%v", got, err)
	}

	got, err = (roleListFunc{}).Execute(context.Background(), rt, &roleListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	// role_list preserves the source's direct line parser: both role records
	// retain a trailing newline in type and are skipped.
	wantRoles := map[string]map[string]any{}
	if !reflect.DeepEqual(got, wantRoles) {
		t.Fatalf("role_list=%#v want=%#v", got, wantRoles)
	}
	got, err = (roleGetFunc{}).Execute(context.Background(), rt, &roleGetArgs{User: "alice"})
	if err != nil || !reflect.DeepEqual(got, []string{"netcfg", "operator"}) {
		t.Fatalf("role_get=%#v err=%v", got, err)
	}

	got, err = (authListFunc{}).Execute(context.Background(), rt, &authListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	wantAuths := map[string]string{
		"solaris.zone.manage": "Zone Manage",
		"solaris.mail.mailq":  "Mail Queue",
		"solaris.system.*":    "System subtree",
	}
	if !reflect.DeepEqual(got, wantAuths) {
		t.Fatalf("auth_list=%#v want=%#v", got, wantAuths)
	}
	computed := false
	got, err = (authGetFunc{}).Execute(context.Background(), rt, &authGetArgs{User: "alice", Computed: &computed})
	if err != nil || !reflect.DeepEqual(got, []string{"solaris.mail.mailq", "solaris.zone.manage"}) {
		t.Fatalf("auth_get static=%#v err=%v", got, err)
	}
	runner.results = map[string][]process.CommandResult{
		"auths alice": {{ExitCode: 0, Stdout: []byte("solaris.computed,solaris.zone.manage\nsolaris.extra\n")}},
	}
	got, err = (authGetFunc{}).Execute(context.Background(), rt, &authGetArgs{User: "alice"})
	if err != nil || !reflect.DeepEqual(got, []string{"solaris.computed", "solaris.extra", "solaris.mail.mailq", "solaris.zone.manage"}) {
		t.Fatalf("auth_get computed=%#v err=%v", got, err)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(rbacArgv(runner.calls[0]), []string{"auths", "alice"}) {
		t.Fatalf("auths argv=%v", rbacArgv(runner.calls[0]))
	}
	assertRBACBounded(t, runner.calls[0])
}

func TestRBACFunctionSpecificParsingContracts(t *testing.T) {
	runner := &rbacFakeRunner{}
	rt := newRBACRuntime(t, runner)
	fsys := rt.FS.(*runtime.MemoryFS)
	writeUserAttr := func(data string) {
		t.Helper()
		if err := fsys.WriteFile("/etc/user_attr", []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// role_list does not strip the record or attribute before comparing type.
	writeUserAttr("testrole::::type=role\n")
	got, err := (roleListFunc{}).Execute(context.Background(), rt, &roleListArgs{})
	if err != nil || !reflect.DeepEqual(got, map[string]map[string]any{}) {
		t.Fatalf("newline role_list=%#v err=%v", got, err)
	}
	writeUserAttr("testrole::::type=role")
	got, err = (roleListFunc{}).Execute(context.Background(), rt, &roleListArgs{})
	if err != nil || !reflect.DeepEqual(got, map[string]map[string]any{"testrole": {}}) {
		t.Fatalf("EOF role_list=%#v err=%v", got, err)
	}

	// User getters strip their records, but list values retain source order
	// and per-element whitespace until the public result is deduplicated.
	writeUserAttr("alice::::profiles=All,All,Other;type=normal\n")
	got, err = (profileGetFunc{}).Execute(context.Background(), rt, &profileGetArgs{User: "alice"})
	if err != nil || !reflect.DeepEqual(got, []string{"All", "Other"}) {
		t.Fatalf("duplicate default profile_get=%#v err=%v", got, err)
	}
	writeUserAttr("alice::::profiles=First, All ,Second;type=normal\n")
	values, err := rbacProfileValues(context.Background(), rt, "alice", false)
	if err != nil || !reflect.DeepEqual(values, []string{"First", " All ", "Second"}) {
		t.Fatalf("profile whitespace values=%#v err=%v", values, err)
	}
	hidden := false
	writeUserAttr("alice::::profiles =All;type=normal\n")
	got, err = (profileGetFunc{}).Execute(context.Background(), rt, &profileGetArgs{User: "alice", DefaultHidden: &hidden})
	if err != nil || !reflect.DeepEqual(got, []string{}) {
		t.Fatalf("whitespace profile key=%#v err=%v", got, err)
	}

	// The newline contract also affects role validation: an unrecognized role
	// must not reach usermod in either mutation direction.
	writeUserAttr("testrole::::type=role\n")
	runner.calls = nil
	got, err = (roleAddFunc{}).Execute(context.Background(), rt, &roleMutationArgs{User: "alice", Role: "testrole"})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"testrole": "Unknown"}) || len(runner.calls) != 0 {
		t.Fatalf("newline role_add=%#v err=%v calls=%#v", got, err, runner.calls)
	}
	got, err = (roleRemoveFunc{}).Execute(context.Background(), rt, &roleMutationArgs{User: "alice", Role: "testrole"})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"testrole": "Unknown"}) || len(runner.calls) != 0 {
		t.Fatalf("newline role_rm=%#v err=%v calls=%#v", got, err, runner.calls)
	}
}

func TestRBACAuthGetPublicSplitlinesVectors(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   []string
	}{
		{"empty", "", []string{}},
		{"single empty line", "\n", []string{""}},
		{"one trailing LF", "auth.one\n", []string{"auth.one"}},
		{"two trailing LF", "auth.one\n\n", []string{"", "auth.one"}},
		{"interior empty", "auth.one\n\nauth.two", []string{"", "auth.one", "auth.two"}},
		{"CRLF", "auth.one\r\nauth.two\r\n", []string{"auth.one", "auth.two"}},
		{"CR", "auth.one\rauth.two\r", []string{"auth.one", "auth.two"}},
		{"VT FF and record separators", "auth.vt\vauth.ff\fauth.fs\x1cauth.gs\x1dauth.rs\x1e", []string{"auth.ff", "auth.fs", "auth.gs", "auth.rs", "auth.vt"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &rbacFakeRunner{results: map[string][]process.CommandResult{
				"auths alice": {{ExitCode: 0, Stdout: []byte(tc.stdout)}},
			}}
			rt := newRBACRuntime(t, runner)
			if err := rt.FS.(*runtime.MemoryFS).WriteFile("/etc/user_attr", []byte("alice::::type=normal"), 0o600); err != nil {
				t.Fatal(err)
			}
			reg := runtime.NewExecRegistry()
			if err := registerSolaris(reg); err != nil {
				t.Fatal(err)
			}
			fn, ok := reg.Get("rbac.auth_get")
			if !ok {
				t.Fatal("rbac.auth_get is not registered")
			}
			got, err := fn.Execute(context.Background(), rt, &authGetArgs{User: "alice"})
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("auth_get=%#v err=%v want=%#v", got, err, tc.want)
			}
			if reflect.TypeOf(got) != reflect.TypeOf([]string{}) {
				t.Fatalf("auth_get type=%T want=[]string", got)
			}
			if len(runner.calls) != 1 || !reflect.DeepEqual(rbacArgv(runner.calls[0]), []string{"auths", "alice"}) {
				t.Fatalf("argv=%v", runner.calls)
			}
			assertRBACBounded(t, runner.calls[0])
		})
	}
}

func TestRBACMutatorsArgvStatusAndErrors(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name  string
		setup func(*testing.T, *rbacFakeRunner) *runtime.Runtime
		call  func(*runtime.Runtime) (any, error)
		argv  []string
		want  any
	}{
		{
			"profile_add",
			nil,
			func(rt *runtime.Runtime) (any, error) {
				return (profileAddFunc{}).Execute(ctx, rt, &profileMutationArgs{User: "alice", Profile: "Hidden,Unknown"})
			},
			[]string{"usermod", "-P", "Hidden", "alice"},
			map[string]any{"Hidden": "Added", "Unknown": "Unknown"},
		},
		{
			"profile_rm",
			nil,
			func(rt *runtime.Runtime) (any, error) {
				return (profileRemoveFunc{}).Execute(ctx, rt, &profileMutationArgs{User: "alice", Profile: "Basic,Unknown"})
			},
			[]string{"usermod", "-P", "Hidden", "alice"},
			map[string]any{"Basic": "Failed", "Unknown": "Unknown"},
		},
		{
			"role_add",
			newRBACRuntimeWithEOFRole,
			func(rt *runtime.Runtime) (any, error) {
				return (roleAddFunc{}).Execute(ctx, rt, &roleMutationArgs{User: "alice", Role: "netcfg,Unknown"})
			},
			[]string{"usermod", "-R", "netcfg,operator", "alice"},
			map[string]any{"netcfg": "Added", "Unknown": "Unknown"},
		},
		{
			"role_rm",
			newRBACRuntimeWithEOFRole,
			func(rt *runtime.Runtime) (any, error) {
				return (roleRemoveFunc{}).Execute(ctx, rt, &roleMutationArgs{User: "alice", Role: "netcfg,Unknown"})
			},
			[]string{"usermod", "-R", "operator", "alice"},
			map[string]any{"netcfg": "Failed", "Unknown": "Unknown"},
		},
		{
			"auth_add",
			nil,
			func(rt *runtime.Runtime) (any, error) {
				return (authAddFunc{}).Execute(ctx, rt, &authMutationArgs{User: "alice", Auth: "solaris.mail.mailq,Unknown"})
			},
			[]string{"usermod", "-A", "solaris.mail.mailq,solaris.zone.manage", "alice"},
			map[string]any{"solaris.mail.mailq": "Added", "Unknown": "Unknown"},
		},
		{
			"auth_rm",
			nil,
			func(rt *runtime.Runtime) (any, error) {
				return (authRemoveFunc{}).Execute(ctx, rt, &authMutationArgs{User: "alice", Auth: "solaris.mail.mailq,Unknown"})
			},
			[]string{"usermod", "-A", "solaris.zone.manage", "alice"},
			map[string]any{"solaris.mail.mailq": "Failed", "Unknown": "Unknown"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &rbacFakeRunner{}
			rt := newRBACRuntime(t, runner)
			if tc.setup != nil {
				rt = tc.setup(t, runner)
			}
			got, err := tc.call(rt)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, tc.want)
			}
			if len(runner.calls) != 1 || !reflect.DeepEqual(rbacArgv(runner.calls[0]), tc.argv) {
				t.Fatalf("argv=%v want=%v", rbacArgv(runner.calls[0]), tc.argv)
			}
			assertRBACBounded(t, runner.calls[0])
		})
	}

	runner := &rbacFakeRunner{results: map[string][]process.CommandResult{
		"usermod -P Hidden alice": {{ExitCode: 7, Stderr: []byte("denied")}},
	}}
	rt := newRBACRuntime(t, runner)
	got, err := (profileAddFunc{}).Execute(ctx, rt, &profileMutationArgs{User: "alice", Profile: "Hidden"})
	want := map[string]any{"Error": map[string]any{"retcode": 7, "message": "denied"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("retcode got=%#v err=%v want=%#v", got, err, want)
	}
}

func TestRBACNoMutationOnUnknownAndFailures(t *testing.T) {
	runner := &rbacFakeRunner{}
	rt := newRBACRuntime(t, runner)
	got, err := (profileAddFunc{}).Execute(context.Background(), rt, &profileMutationArgs{User: "alice", Profile: "Unknown"})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"Unknown": "Unknown"}) || len(runner.calls) != 0 {
		t.Fatalf("unknown profile got=%#v err=%v calls=%v", got, err, runner.calls)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (authGetFunc{}).Execute(ctx, rt, &authGetArgs{User: "alice"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error=%v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled RBAC call reached Runner: %v", runner.calls)
	}

	runner.results = map[string][]process.CommandResult{
		"auths alice": {{ExitCode: 0, Stdout: []byte("x"), StdoutTruncated: true}},
	}
	if _, err := (authGetFunc{}).Execute(context.Background(), rt, &authGetArgs{User: "alice"}); !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("output-limit error=%v", err)
	}
	runner.results = map[string][]process.CommandResult{
		"auths alice": {{ExitCode: -1, Err: errors.New("auths missing")}},
	}
	if _, err := (authGetFunc{}).Execute(context.Background(), rt, &authGetArgs{User: "alice"}); err == nil || !strings.Contains(err.Error(), "auths missing") {
		t.Fatalf("runner error=%v", err)
	}
}

func TestRBACMalformedFixturesAndBounds(t *testing.T) {
	if rbacCommandTimeout != 30*time.Second || rbacOutputLimit != 4<<20 || rbacFileLimit != 1<<20 {
		t.Fatalf("unexpected bounds timeout=%s output=%d file=%d", rbacCommandTimeout, rbacOutputLimit, rbacFileLimit)
	}
	if _, err := parseRBACAttrs("profiles=one=two"); err == nil {
		t.Fatal("malformed attribute accepted")
	}
	if _, err := parseRBACPolicyDefaults([]string{"PROFS_GRANTED"}, []string{"All"}); err == nil {
		t.Fatal("malformed policy accepted")
	}
	runner := &rbacFakeRunner{}
	rt := newRBACRuntime(t, runner)
	fsys := rt.FS.(*runtime.MemoryFS)
	if err := fsys.WriteFile("/etc/user_attr", []byte("alice::::profiles=broken=two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (profileGetFunc{}).Execute(context.Background(), rt, &profileGetArgs{User: "alice"}); err == nil {
		t.Fatal("malformed user_attr accepted")
	}
	if _, err := (profileListFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: runner}, &profileListArgs{}); err == nil {
		t.Fatal("missing filesystem accepted")
	}
}
