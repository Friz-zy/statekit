package selinux

// R5.3 admin-surface tests: booleans and semodule management, the exact
// which-guard texts, runner bounds (Shell=false, default capture limits),
// cancellation and output-limit propagation, filesystem non-mutation, and
// the registry/CLI surface of all 19 newly registered functions.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/cli"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	cpmod "github.com/friz-zy/statekit/modules/exec/cp"
)

const seboolListing = `SELinux boolean                State  Default Description

ftp_home_dir                   (off ,  off)  Allow ftp to read and write files in the user home directories
virt_use_usb                   (on ,   on)   Allow virt to use USB devices
`

const semodListing = `100 apache                  pp
400 custom                  pp  disabled
`

func TestListSeboolParsesColumns(t *testing.T) {
	withTools(t, "semanage")
	rt, runner := newRT()
	runner.script = []process.CommandResult{out(seboolListing)}
	got, err := (listSeboolFunc{}).Execute(context.Background(), rt, &ListSeboolArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"ftp_home_dir": map[string]any{
			"State": "off", "Default": "off",
			"Description": "Allow ftp to read and write files in the user home directories",
		},
		"virt_use_usb": map[string]any{
			"State": "on", "Default": "on",
			"Description": "Allow virt to use USB devices",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("list_sebool = %#v; want %#v", got, want)
	}
	if argv := runner.calls[0]; strings.Join(argv, "\x00") != strings.Join([]string{"semanage", "boolean", "--list"}, "\x00") {
		t.Fatalf("argv = %v", argv)
	}
}

func TestListSeboolMalformedLine(t *testing.T) {
	withTools(t, "semanage")
	rt, runner := newRT()
	runner.script = []process.CommandResult{out("header\ntruncated boolean row\n")}
	if _, err := (listSeboolFunc{}).Execute(context.Background(), rt, &ListSeboolArgs{}); err == nil ||
		!strings.Contains(err.Error(), "malformed semanage boolean line") {
		t.Fatalf("malformed listing error = %v", err)
	}
}

func TestGetseboolLookupAndEmptyDefault(t *testing.T) {
	withTools(t, "semanage")
	rt, runner := newRT()
	runner.script = []process.CommandResult{out(seboolListing)}
	got, err := (getseboolFunc{}).Execute(context.Background(), rt, &GetseboolArgs{Boolean: "ftp_home_dir"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"State": "off", "Default": "off",
		"Description": "Allow ftp to read and write files in the user home directories",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("getsebool = %#v", got)
	}
	rt2, runner2 := newRT()
	runner2.script = []process.CommandResult{out(seboolListing)}
	missing, err := (getseboolFunc{}).Execute(context.Background(), rt2, &GetseboolArgs{Boolean: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(missing, map[string]any{}) {
		t.Fatalf("missing boolean = %#v; want {}", missing)
	}
}

func TestSetseboolArgvAndRetcode(t *testing.T) {
	withTools(t, "setsebool")
	rt, runner := newRT()
	runner.script = []process.CommandResult{{ExitCode: 0}}
	got, err := (setseboolFunc{}).Execute(context.Background(), rt, &SetseboolArgs{Boolean: "virt_use_usb", Value: "off"})
	if err != nil || got != true {
		t.Fatalf("setsebool = %v, %v", got, err)
	}
	want := []string{"setsebool", "virt_use_usb", "off"}
	if argv := runner.calls[0]; strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv = %v; want %v", argv, want)
	}

	rt2, runner2 := newRT()
	runner2.script = []process.CommandResult{{ExitCode: 1, Stderr: []byte("nope")}}
	got2, err2 := (setseboolFunc{}).Execute(context.Background(), rt2, &SetseboolArgs{Boolean: "x", Value: "on", Persist: true})
	if err2 != nil || got2 != false {
		t.Fatalf("setsebool nonzero = %v, %v; want false", got2, err2)
	}
	wantPersist := []string{"setsebool", "-P", "x", "on"}
	if argv := runner2.calls[0]; strings.Join(argv, "\x00") != strings.Join(wantPersist, "\x00") {
		t.Fatalf("persist argv = %v; want %v", argv, wantPersist)
	}
}

func TestSetseboolsSingleInvocation(t *testing.T) {
	withTools(t, "setsebool")
	rt, runner := newRT()
	runner.script = []process.CommandResult{{ExitCode: 0}}
	got, err := (setseboolsFunc{}).Execute(context.Background(), rt, &SetseboolsArgs{
		Pairs: map[string]string{"squid_use_tproxy": "off", "virt_use_usb": "on"},
	})
	if err != nil || got != true {
		t.Fatalf("setsebools = %v, %v", got, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("setsebools must issue one call, got %d", len(runner.calls))
	}
	want := []string{"setsebool", "squid_use_tproxy=off", "virt_use_usb=on"}
	if argv := runner.calls[0]; strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv = %v; want %v", argv, want)
	}
}

func TestSemodFamily(t *testing.T) {
	withTools(t, "semodule")
	rt, runner := newRT()
	runner.script = []process.CommandResult{out(semodListing)}
	got, err := (listSemodFunc{}).Execute(context.Background(), rt, &ListSemodArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"apache": map[string]any{"Enabled": true, "Version": nil},
		"custom": map[string]any{"Enabled": false, "Version": nil},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("list_semod = %#v; want %#v", got, want)
	}
	if argv := runner.calls[0]; strings.Join(argv, "\x00") != strings.Join([]string{"semodule", "--list-modules=full"}, "\x00") {
		t.Fatalf("argv = %v", argv)
	}

	rt2, runner2 := newRT()
	runner2.script = []process.CommandResult{out(semodListing)}
	single, err := (getsemodFunc{}).Execute(context.Background(), rt2, &GetsemodArgs{Module: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(single, map[string]any{"Enabled": false, "Version": nil}) {
		t.Fatalf("getsemod = %#v", single)
	}

	rt3, runner3 := newRT()
	runner3.script = []process.CommandResult{{ExitCode: 0}}
	ok, err := (setsemodFunc{}).Execute(context.Background(), rt3, &SetsemodArgs{Module: "nagios", State: "Enabled"})
	if err != nil || ok != true {
		t.Fatalf("setsemod = %v, %v", ok, err)
	}
	if argv := runner3.calls[0]; strings.Join(argv, "\x00") != strings.Join([]string{"semodule", "--enable", "nagios"}, "\x00") {
		t.Fatalf("argv = %v", argv)
	}

	rt4, runner4 := newRT()
	runner4.script = []process.CommandResult{{ExitCode: 0}}
	if _, err := (setsemodFunc{}).Execute(context.Background(), rt4, &SetsemodArgs{Module: "m", State: "Disabled"}); err != nil {
		t.Fatal(err)
	}
	if argv := runner4.calls[0]; strings.Join(argv, "\x00") != strings.Join([]string{"semodule", "--disable", "m"}, "\x00") {
		t.Fatalf("argv = %v", argv)
	}

	rt5, _ := newRT()
	if _, err := (setsemodFunc{}).Execute(context.Background(), rt5, &SetsemodArgs{Module: "m", State: "Banana"}); err == nil ||
		err.Error() != "Invalid state Banana" {
		t.Fatalf("invalid state = %v", err)
	}

	rt6, runner6 := newRT()
	runner6.script = []process.CommandResult{{ExitCode: 0}}
	okInstall, err := (installSemodFunc{}).Execute(context.Background(), rt6, &InstallSemodArgs{ModulePath: "/opt/mod.pp"})
	if err != nil || okInstall != true {
		t.Fatalf("install_semod = %v, %v", okInstall, err)
	}
	if argv := runner6.calls[0]; strings.Join(argv, "\x00") != strings.Join([]string{"semodule", "--install", "/opt/mod.pp"}, "\x00") {
		t.Fatalf("argv = %v", argv)
	}

	rt7, runner7 := newRT()
	runner7.script = []process.CommandResult{{ExitCode: 2}}
	removed, err := (removeSemodFunc{}).Execute(context.Background(), rt7, &RemoveSemodArgs{Module: "custom"})
	if err != nil || removed != false {
		t.Fatalf("remove_semod = %v, %v", removed, err)
	}
	if argv := runner7.calls[0]; strings.Join(argv, "\x00") != strings.Join([]string{"semodule", "--remove", "custom"}, "\x00") {
		t.Fatalf("argv = %v", argv)
	}
}

func TestListSemodMalformedLine(t *testing.T) {
	withTools(t, "semodule")
	rt, runner := newRT()
	runner.script = []process.CommandResult{out("solo\n")}
	if _, err := (listSemodFunc{}).Execute(context.Background(), rt, &ListSemodArgs{}); err == nil ||
		!strings.Contains(err.Error(), "malformed semodule listing line") {
		t.Fatalf("malformed semodule error = %v", err)
	}
}

func TestInstallSemodSaltSchemeDelegatesToCacheFile(t *testing.T) {
	withTools(t, "semodule")
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := cpmod.Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &scriptRunner{}
	rt := &runtime.Runtime{Exec: reg, Runner: runner, FS: runtime.NewMemoryFS()}

	_, err := (installSemodFunc{}).Execute(context.Background(), rt, &InstallSemodArgs{ModulePath: "salt://modules/mine.pp"})
	if err == nil || !strings.Contains(err.Error(), "cp.cache_file") {
		t.Fatalf("salt:// boundary error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatal("salt:// must not reach semodule before caching resolves")
	}
}

// ---------------------------------------------------------------------------
// which-guards, bounds, cancel, output limits, mutation

func TestWhichGuardExactMessages(t *testing.T) {
	withTools(t) // nothing resolvable
	cases := []struct {
		binary string
		call   func(ctx context.Context, rt *runtime.Runtime) (any, error)
	}{
		{"semanage", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (listSeboolFunc{}).Execute(ctx, rt, &ListSeboolArgs{})
		}},
		{"semanage", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (getseboolFunc{}).Execute(ctx, rt, &GetseboolArgs{Boolean: "x"})
		}},
		{"semanage", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (fcontextGetPolicyFunc{}).Execute(ctx, rt, &FcontextPolicyArgs{Name: "/x"})
		}},
		{"semanage", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (fcontextAddPolicyFunc{}).Execute(ctx, rt, &FcontextPolicyArgs{Name: "/x"})
		}},
		{"semanage", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (fcontextDeletePolicyFunc{}).Execute(ctx, rt, &FcontextPolicyArgs{Name: "/x"})
		}},
		{"semanage", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (portGetPolicyFunc{}).Execute(ctx, rt, &PortGetPolicyArgs{Name: "tcp/80"})
		}},
		{"semanage", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (portAddPolicyFunc{}).Execute(ctx, rt, &PortAddPolicyArgs{Name: "tcp/80", SelType: strPtr("t")})
		}},
		{"semanage", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (portModifyPolicyFunc{}).Execute(ctx, rt, &PortModifyPolicyArgs{Name: "tcp/80", SelType: strPtr("t")})
		}},
		{"semanage", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (portDeletePolicyFunc{}).Execute(ctx, rt, &PortDeletePolicyArgs{Name: "tcp/80"})
		}},
		{"setsebool", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (setseboolFunc{}).Execute(ctx, rt, &SetseboolArgs{Boolean: "x", Value: "on"})
		}},
		{"setsebool", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (setseboolsFunc{}).Execute(ctx, rt, &SetseboolsArgs{Pairs: map[string]string{"x": "on"}})
		}},
		{"semodule", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (listSemodFunc{}).Execute(ctx, rt, &ListSemodArgs{})
		}},
		{"semodule", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (getsemodFunc{}).Execute(ctx, rt, &GetsemodArgs{Module: "m"})
		}},
		{"semodule", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (setsemodFunc{}).Execute(ctx, rt, &SetsemodArgs{Module: "m", State: "enabled"})
		}},
		{"semodule", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (installSemodFunc{}).Execute(ctx, rt, &InstallSemodArgs{ModulePath: "/m.pp"})
		}},
		{"semodule", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (removeSemodFunc{}).Execute(ctx, rt, &RemoveSemodArgs{Module: "m"})
		}},
		{"restorecon", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (fcontextPolicyIsAppliedFunc{}).Execute(ctx, rt, &FcontextPolicyIsAppliedArgs{Name: "/x"})
		}},
		{"restorecon", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (fcontextApplyPolicyFunc{}).Execute(ctx, rt, &FcontextApplyPolicyArgs{Name: "/x"})
		}},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		rt, runner := newRT()
		_, err := tc.call(context.Background(), rt)
		want := "The '" + tc.binary + "' binary was not found in $PATH."
		if err == nil || err.Error() != want {
			t.Fatalf("guard for %s = %v; want %q", tc.binary, err, want)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s: runner must not spawn before the guard passes", tc.binary)
		}
		seen[tc.binary] = true
	}
	if len(seen) != 4 {
		t.Fatalf("guard coverage = %v", seen)
	}
}

func TestRunnerBoundedShellFreeCommands(t *testing.T) {
	withTools(t, "semanage", "setsebool", "semodule", "restorecon")
	capture := &capturingRunner{}
	rt := &runtime.Runtime{Runner: capture, FS: runtime.NewMemoryFS()}
	calls := []func(){
		func() { (listSeboolFunc{}).Execute(context.Background(), rt, &ListSeboolArgs{}) },
		func() { (setseboolFunc{}).Execute(context.Background(), rt, &SetseboolArgs{Boolean: "b", Value: "on"}) },
		func() {
			(setseboolsFunc{}).Execute(context.Background(), rt, &SetseboolsArgs{Pairs: map[string]string{"b": "on"}})
		},
		func() { (listSemodFunc{}).Execute(context.Background(), rt, &ListSemodArgs{}) },
		func() {
			(setsemodFunc{}).Execute(context.Background(), rt, &SetsemodArgs{Module: "m", State: "enabled"})
		},
		func() { (installSemodFunc{}).Execute(context.Background(), rt, &InstallSemodArgs{ModulePath: "/m.pp"}) },
		func() { (removeSemodFunc{}).Execute(context.Background(), rt, &RemoveSemodArgs{Module: "m"}) },
		func() { (fcontextGetPolicyFunc{}).Execute(context.Background(), rt, &FcontextPolicyArgs{Name: "/x"}) },
		func() {
			(fcontextAddPolicyFunc{}).Execute(context.Background(), rt, &FcontextPolicyArgs{Name: "/x", SelType: strPtr("t")})
		},
		func() {
			(fcontextDeletePolicyFunc{}).Execute(context.Background(), rt, &FcontextPolicyArgs{Name: "/x"})
		},
		func() {
			(fcontextPolicyIsAppliedFunc{}).Execute(context.Background(), rt, &FcontextPolicyIsAppliedArgs{Name: "/x"})
		},
		func() {
			(fcontextApplyPolicyFunc{}).Execute(context.Background(), rt, &FcontextApplyPolicyArgs{Name: "/x"})
		},
		func() { (portGetPolicyFunc{}).Execute(context.Background(), rt, &PortGetPolicyArgs{Name: "tcp/80"}) },
		func() {
			(portAddPolicyFunc{}).Execute(context.Background(), rt, &PortAddPolicyArgs{Name: "tcp/80", SelType: strPtr("t")})
		},
		func() {
			(portModifyPolicyFunc{}).Execute(context.Background(), rt, &PortModifyPolicyArgs{Name: "tcp/80", SelType: strPtr("t")})
		},
		func() {
			(portDeletePolicyFunc{}).Execute(context.Background(), rt, &PortDeletePolicyArgs{Name: "tcp/80"})
		},
	}
	for i, call := range calls {
		call()
		if len(capture.commands) <= i {
			t.Fatalf("call %d did not reach the runner", i)
		}
	}
	for _, cmd := range capture.commands {
		if cmd.Shell {
			t.Fatalf("%s must run shell-free", cmd.Name)
		}
		// zero selects the central 1 MiB default capture limit
		if cmd.MaxStdoutBytes != 0 || cmd.MaxStderrBytes != 0 {
			t.Fatalf("%s overrides the default capture limits", cmd.Name)
		}
	}
}

func TestCancellationAndOutputLimitPropagate(t *testing.T) {
	withTools(t, "semanage", "setsebool", "semodule", "restorecon")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt := &runtime.Runtime{Runner: errRunner{err: context.Canceled}, FS: runtime.NewMemoryFS()}
	if _, err := (listSeboolFunc{}).Execute(ctx, rt, &ListSeboolArgs{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("list_sebool cancel = %v", err)
	}
	if _, err := (setseboolFunc{}).Execute(ctx, rt, &SetseboolArgs{Boolean: "b", Value: "on"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("setsebool cancel = %v", err)
	}
	if _, err := (fcontextGetPolicyFunc{}).Execute(ctx, rt, &FcontextPolicyArgs{Name: "/x"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("fcontext_get_policy cancel = %v", err)
	}
	// the apply preview failure must abort before the apply invocation
	countRunner := &countingErrRunner{err: context.Canceled}
	rt2 := &runtime.Runtime{Runner: countRunner, FS: runtime.NewMemoryFS()}
	if _, err := (fcontextApplyPolicyFunc{}).Execute(ctx, rt2, &FcontextApplyPolicyArgs{Name: "/x"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("fcontext_apply_policy cancel = %v", err)
	}
	if countRunner.calls != 1 {
		t.Fatalf("apply after canceled preview must not run; calls = %d", countRunner.calls)
	}

	limited := &runtime.Runtime{Runner: errRunner{err: process.ErrOutputLimit}, FS: runtime.NewMemoryFS()}
	if _, err := (listSeboolFunc{}).Execute(context.Background(), limited, &ListSeboolArgs{}); !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("list_sebool limit = %v", err)
	}
	if _, err := (portGetPolicyFunc{}).Execute(context.Background(), limited, &PortGetPolicyArgs{Name: "tcp/80"}); !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("port_get_policy limit = %v", err)
	}
	res, err := (fcontextAddPolicyFunc{}).Execute(context.Background(), limited, &FcontextPolicyArgs{Name: "/x", SelType: strPtr("t")})
	if !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("fcontext_add_policy limit = %v", err)
	}
	if res == nil {
		t.Fatal("run_all-shaped result should still carry retcode/output")
	}
}

type countingErrRunner struct {
	err   error
	calls int
}

func (c *countingErrRunner) Run(_ context.Context, _ process.Command) process.CommandResult {
	c.calls++
	return process.CommandResult{ExitCode: -1, Err: c.err}
}

func TestNoFilesystemMutation(t *testing.T) {
	withTools(t, "semanage", "setsebool", "semodule", "restorecon")
	rt, runner := newRT()
	before, err := rt.FS.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	entriesBefore, err := rt.FS.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	runner.script = []process.CommandResult{
		out(seboolListing), // getsebool listing
		{ExitCode: 0},      // setsebool
		{ExitCode: 0},      // setsebools
		out(semodListing),  // getsemod listing
		{ExitCode: 0},      // setsemod
		{ExitCode: 0},      // install_semod
		{ExitCode: 0},      // remove_semod
		out(""),            // fcontext add listing
		{ExitCode: 0},      // fcontext add run
		out(""),            // fcontext delete is direct (no listing)
		out("Would relabel /x from u:r:t:s0 to u:r:t2:s0"), // is_applied preview
		out("Would relabel /x from u:r:t:s0 to u:r:t2:s0"), // apply preview
		{ExitCode: 0}, // apply run
		out("cma_port_t                     tcp      1050"), // port get listing
		{ExitCode: 0}, // port add
		{ExitCode: 0}, // port modify
		{ExitCode: 0}, // port delete
	}
	steps := []func(){
		func() { (getseboolFunc{}).Execute(context.Background(), rt, &GetseboolArgs{Boolean: "ftp_home_dir"}) },
		func() { (setseboolFunc{}).Execute(context.Background(), rt, &SetseboolArgs{Boolean: "b", Value: "on"}) },
		func() {
			(setseboolsFunc{}).Execute(context.Background(), rt, &SetseboolsArgs{Pairs: map[string]string{"b": "on"}})
		},
		func() { (getsemodFunc{}).Execute(context.Background(), rt, &GetsemodArgs{Module: "apache"}) },
		func() {
			(setsemodFunc{}).Execute(context.Background(), rt, &SetsemodArgs{Module: "m", State: "enabled"})
		},
		func() { (installSemodFunc{}).Execute(context.Background(), rt, &InstallSemodArgs{ModulePath: "/m.pp"}) },
		func() { (removeSemodFunc{}).Execute(context.Background(), rt, &RemoveSemodArgs{Module: "m"}) },
		func() {
			(fcontextAddPolicyFunc{}).Execute(context.Background(), rt, &FcontextPolicyArgs{Name: "/x", SelType: strPtr("t")})
		},
		func() {
			(fcontextDeletePolicyFunc{}).Execute(context.Background(), rt, &FcontextPolicyArgs{Name: "/x"})
		},
		func() {
			(fcontextPolicyIsAppliedFunc{}).Execute(context.Background(), rt, &FcontextPolicyIsAppliedArgs{Name: "/x"})
		},
		func() {
			(fcontextApplyPolicyFunc{}).Execute(context.Background(), rt, &FcontextApplyPolicyArgs{Name: "/x"})
		},
		func() { (portGetPolicyFunc{}).Execute(context.Background(), rt, &PortGetPolicyArgs{Name: "tcp/1050"}) },
		func() {
			(portAddPolicyFunc{}).Execute(context.Background(), rt, &PortAddPolicyArgs{Name: "tcp/80", SelType: strPtr("t")})
		},
		func() {
			(portModifyPolicyFunc{}).Execute(context.Background(), rt, &PortModifyPolicyArgs{Name: "tcp/80", SelType: strPtr("t")})
		},
		func() {
			(portDeletePolicyFunc{}).Execute(context.Background(), rt, &PortDeletePolicyArgs{Name: "tcp/80"})
		},
	}
	for _, step := range steps {
		step()
	}
	after, err := rt.FS.ReadFile(configPath)
	if err != nil || string(before) != string(after) {
		t.Fatal("config file mutated")
	}
	entriesAfter, err := rt.FS.ReadDir("/")
	if err != nil || len(entriesBefore) != len(entriesAfter) {
		t.Fatalf("root entries changed: %d -> %d", len(entriesBefore), len(entriesAfter))
	}
}

func TestControlRunesRejected(t *testing.T) {
	withTools(t, "semanage", "setsebool", "semodule", "restorecon")
	rt, _ := newRT()
	if _, err := (setseboolFunc{}).Execute(context.Background(), rt, &SetseboolArgs{Boolean: "b", Value: "on\nreboot"}); err == nil ||
		!strings.Contains(err.Error(), "control runes") {
		t.Fatalf("newline value = %v", err)
	}
	if _, err := (fcontextAddPolicyFunc{}).Execute(context.Background(), rt, &FcontextPolicyArgs{Name: "/x\x00"}); err == nil {
		t.Fatal("NUL in name must fail")
	}
	if _, err := (setsemodFunc{}).Execute(context.Background(), rt, &SetsemodArgs{Module: "m\t", State: "enabled"}); err == nil {
		t.Fatal("tab in module must fail")
	}
	if _, err := (portAddPolicyFunc{}).Execute(context.Background(), rt, &PortAddPolicyArgs{Name: "tcp/80", SelType: strPtr("t\n")}); err == nil {
		t.Fatal("newline in sel_type must fail")
	}
}

// ---------------------------------------------------------------------------
// registry and CLI surface

func TestRegisteredNamesAndPrototypes(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	wantNames := []string{
		"selinux.fcontext_add_policy",
		"selinux.fcontext_apply_policy",
		"selinux.fcontext_delete_policy",
		"selinux.fcontext_get_policy",
		"selinux.fcontext_policy_is_applied",
		"selinux.filetype_id_to_string",
		"selinux.getconfig",
		"selinux.getenforce",
		"selinux.getsebool",
		"selinux.getsemod",
		"selinux.install_semod",
		"selinux.list_sebool",
		"selinux.list_semod",
		"selinux.port_add_policy",
		"selinux.port_delete_policy",
		"selinux.port_get_policy",
		"selinux.port_modify_policy",
		"selinux.remove_semod",
		"selinux.selinux_fs_path",
		"selinux.setenforce",
		"selinux.setsebool",
		"selinux.setsebools",
		"selinux.setsemod",
	}
	names := reg.Names()
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("registered names = %v", names)
	}
	prototypes := map[string]string{
		"selinux.fcontext_add_policy":        "FcontextPolicyArgs",
		"selinux.fcontext_apply_policy":      "FcontextApplyPolicyArgs",
		"selinux.fcontext_delete_policy":     "FcontextPolicyArgs",
		"selinux.fcontext_get_policy":        "FcontextPolicyArgs",
		"selinux.fcontext_policy_is_applied": "FcontextPolicyIsAppliedArgs",
		"selinux.filetype_id_to_string":      "FiletypeIdToStringArgs",
		"selinux.getsebool":                  "GetseboolArgs",
		"selinux.getsemod":                   "GetsemodArgs",
		"selinux.install_semod":              "InstallSemodArgs",
		"selinux.list_sebool":                "ListSeboolArgs",
		"selinux.list_semod":                 "ListSemodArgs",
		"selinux.port_add_policy":            "PortAddPolicyArgs",
		"selinux.port_delete_policy":         "PortDeletePolicyArgs",
		"selinux.port_get_policy":            "PortGetPolicyArgs",
		"selinux.port_modify_policy":         "PortModifyPolicyArgs",
		"selinux.remove_semod":               "RemoveSemodArgs",
		"selinux.setsebool":                  "SetseboolArgs",
		"selinux.setsebools":                 "SetseboolsArgs",
		"selinux.setsemod":                   "SetsemodArgs",
	}
	for name, typeName := range prototypes {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s not registered", name)
		}
		if got := reflect.TypeOf(fn.Args()).Name(); got != typeName {
			t.Fatalf("%s prototype = %s; want %s", name, got, typeName)
		}
	}
}

func TestRegistryCallDispatch(t *testing.T) {
	withTools(t, "semanage")
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &scriptRunner{script: []process.CommandResult{out(seboolListing)}}
	rt := &runtime.Runtime{Exec: reg, Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := rt.Exec.Call(context.Background(), rt, "selinux.getsebool", &GetseboolArgs{Boolean: "virt_use_usb"})
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := res.(map[string]any)
	if !ok || entry["State"] != "on" {
		t.Fatalf("registry dispatch = %#v", res)
	}
}

func TestCLISurface(t *testing.T) {
	withTools(t, "semanage", "setsebool", "semodule", "restorecon")
	var script []process.CommandResult
	build := func() (*runtime.Runtime, error) {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			return nil, err
		}
		return &runtime.Runtime{
			Exec:   reg,
			States: runtime.NewStateRegistry(),
			Runner: &scriptRunner{script: script},
			FS:     runtime.NewMemoryFS(),
		}, nil
	}
	app := cli.NewApp("test", build)

	script = nil
	if code := app.Run([]string{"exec", "selinux.filetype_id_to_string", "--filetype", "d", "-o", "json"}); code != 0 {
		t.Fatalf("filetype_id_to_string exit = %d", code)
	}
	script = []process.CommandResult{out(seboolListing)}
	if code := app.Run([]string{"exec", "selinux.getsebool", "--boolean", "ftp_home_dir", "-o", "json"}); code != 0 {
		t.Fatalf("getsebool exit = %d", code)
	}
	script = []process.CommandResult{{ExitCode: 0}}
	if code := app.Run([]string{"exec", "selinux.setsebool", "--boolean", "virt_use_usb", "--value", "off", "--persist", "-o", "json"}); code != 0 {
		t.Fatalf("setsebool exit = %d", code)
	}
	script = []process.CommandResult{{ExitCode: 0}}
	if code := app.Run([]string{"exec", "selinux.setsebools", "--config",
		`{"pairs":{"virt_use_usb":"on"}}`, "-o", "json"}); code != 0 {
		t.Fatalf("setsebools exit = %d", code)
	}
	script = []process.CommandResult{out(semodListing)}
	if code := app.Run([]string{"exec", "selinux.list_semod", "-o", "json"}); code != 0 {
		t.Fatalf("list_semod exit = %d", code)
	}
	script = []process.CommandResult{out(""), {ExitCode: 0}}
	if code := app.Run([]string{"exec", "selinux.fcontext_add_policy", "--name", "/opt/data", "--sel_type", "data_t", "-o", "json"}); code != 0 {
		t.Fatalf("fcontext_add_policy exit = %d", code)
	}
	script = []process.CommandResult{out("Would relabel /srv from u:r:t:s0 to u:r:t2:s0"), {ExitCode: 0}}
	if code := app.Run([]string{"exec", "selinux.fcontext_apply_policy", "--name", "/srv", "--recursive", "-o", "json"}); code != 0 {
		t.Fatalf("fcontext_apply_policy exit = %d", code)
	}
	script = []process.CommandResult{out("cma_port_t                     tcp      1050")}
	if code := app.Run([]string{"exec", "selinux.port_get_policy", "--name", "tcp/1050", "-o", "json"}); code != 0 {
		t.Fatalf("port_get_policy exit = %d", code)
	}
	script = []process.CommandResult{{ExitCode: 0}}
	if code := app.Run([]string{"exec", "selinux.port_add_policy", "--name", "tcp/8080", "--sel_type", "http_port_t", "-o", "json"}); code != 0 {
		t.Fatalf("port_add_policy exit = %d", code)
	}

	// missing required argument -> invalid input
	script = nil
	if code := app.Run([]string{"exec", "selinux.getsebool", "-o", "json"}); code != 2 {
		t.Fatalf("missing required exit = %d, want 2", code)
	}
	if code := app.Run([]string{"exec", "selinux.setsemod", "--module", "m", "-o", "json"}); code != 2 {
		t.Fatalf("setsemod missing state exit = %d, want 2", code)
	}

	// which-guard failure surfaces as a function error (exit 1)
	saved := toolLookup
	toolLookup = func(string) bool { return false }
	defer func() { toolLookup = saved }()
	script = nil
	if code := app.Run([]string{"exec", "selinux.list_sebool", "-o", "json"}); code != 1 {
		t.Fatalf("which-guard exit = %d, want 1", code)
	}
}
