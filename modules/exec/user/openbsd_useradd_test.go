package user

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type openBSDTestRunner struct {
	calls   []process.Command
	results []process.CommandResult
	runFn   func(context.Context, process.Command) process.CommandResult
}

func (r *openBSDTestRunner) Run(ctx context.Context, cmd process.Command) process.CommandResult {
	cmd.Args = append([]string(nil), cmd.Args...)
	cmd.Env = append([]string(nil), cmd.Env...)
	r.calls = append(r.calls, cmd)
	if r.runFn != nil {
		return r.runFn(ctx, cmd)
	}
	if len(r.calls) <= len(r.results) {
		return r.results[len(r.calls)-1]
	}
	return process.CommandResult{}
}

type openBSDAvailableRunner struct {
	*openBSDTestRunner
	available         bool
	availabilityCalls int
	availabilityName  string
}

func (r *openBSDAvailableRunner) CommandAvailable(name string) bool {
	r.availabilityCalls++
	r.availabilityName = name
	return r.available
}

func openBSDRuntime(runner process.Runner) *runtime.Runtime {
	return &runtime.Runtime{Runner: runner}
}

func openBSDResult(stdout string, exitCode int) process.CommandResult {
	return process.CommandResult{Stdout: []byte(stdout), ExitCode: exitCode}
}

func assertFixedOpenBSDError(t *testing.T, err error, markers ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, marker := range markers {
		if marker != "" && strings.Contains(err.Error(), marker) {
			t.Fatal("error exposed sensitive or input data")
		}
	}
}

func assertBytesCleared(t *testing.T, b []byte) {
	t.Helper()
	for i, value := range b {
		if value != 0 {
			t.Fatalf("owned output byte %d was not cleared", i)
		}
	}
}

func TestOpenBSDLoginclassSchemaAndParser(t *testing.T) {
	get := openBSDGetLoginclassFunc{}
	getArgs, ok := get.Args().(openBSDGetLoginclassArgs)
	if !ok || reflect.TypeOf(get.Args()) != reflect.TypeOf(openBSDGetLoginclassArgs{}) {
		t.Fatalf("get Args() = %T, want openBSDGetLoginclassArgs", get.Args())
	}
	if tag := reflect.TypeOf(getArgs).Field(0).Tag.Get("statekit"); tag != "required" {
		t.Fatalf("get name schema = %q", tag)
	}
	change := openBSDChloginclassFunc{}
	changeArgs, ok := change.Args().(openBSDChloginclassArgs)
	if !ok || reflect.TypeOf(change.Args()) != reflect.TypeOf(openBSDChloginclassArgs{}) {
		t.Fatalf("change Args() = %T, want openBSDChloginclassArgs", change.Args())
	}
	fields := reflect.TypeOf(changeArgs)
	if fields.Field(0).Tag.Get("statekit") != "required" || fields.Field(1).Tag.Get("statekit") != "required,name=loginclass" || fields.Field(2).Tag.Get("statekit") != "name=root" {
		t.Fatalf("change argument schema = %q, %q, %q", fields.Field(0).Tag.Get("statekit"), fields.Field(1).Tag.Get("statekit"), fields.Field(2).Tag.Get("statekit"))
	}
	if changeArgs.Root != nil {
		t.Fatal("optional root default must be nil")
	}
	for _, fn := range []runtime.ExecFunction{get, change} {
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok || !reflect.DeepEqual(constrained.Platforms(), []string{"openbsd"}) {
			t.Fatalf("%s platforms = %v", fn.Name(), constrained)
		}
	}

	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "class", data: "class staff\n", want: "staff"},
		{name: "classic prefix", data: "classic staff\n", want: "staff"},
		{name: "split once preserves remainder", data: "class \t staff with  spaces \t\n", want: "staff with  spaces \t"},
		{name: "Unicode whitespace", data: "class\u00a0staff\n", want: "staff"},
		{name: "malformed match continues", data: "class\nclass daemon\n", want: "daemon"},
		{name: "first usable match wins", data: "class staff\nclass daemon\n", want: "staff"},
		{name: "no usable match", data: "class\nname alice\n", want: ""},
		{name: "CRLF", data: "other value\r\nclass staff\r\n", want: "staff"},
		{name: "hash stays outside result", data: "passwd $6$HASH-MARKER\nclass staff\n", want: "staff"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := openBSDLoginclassFromOutput([]byte(tc.data)); got != tc.want {
				t.Fatalf("%s parser output mismatch", tc.name)
			}
		})
	}
}

func TestOpenBSDGetLoginclassUsesFixedBoundedCommandAndClearsOutput(t *testing.T) {
	stdout := []byte("passwd $6$HASH-MARKER\nclass staff\r\n")
	stderr := []byte("private stderr marker")
	runner := &openBSDTestRunner{results: []process.CommandResult{{Stdout: stdout, Stderr: stderr, ExitCode: 9}}}
	value, err := (openBSDGetLoginclassFunc{}).Execute(context.Background(), openBSDRuntime(runner), &openBSDGetLoginclassArgs{Name: "alice"})
	if err != nil || value != "staff" {
		t.Fatal("get_loginclass did not return only the class")
	}
	if len(runner.calls) != 1 {
		t.Fatalf("userinfo calls = %d, want 1", len(runner.calls))
	}
	cmd := runner.calls[0]
	if cmd.Name != "userinfo" || !reflect.DeepEqual(cmd.Args, []string{"alice"}) || cmd.Shell || !reflect.DeepEqual(cmd.Env, []string{"LC_ALL=C"}) || cmd.Timeout <= 0 || cmd.MaxStdoutBytes <= 0 || cmd.MaxStderrBytes <= 0 {
		t.Fatal("userinfo command contract mismatch")
	}
	class, ok := value.(string)
	if !ok || class == "$6$HASH-MARKER" || strings.Contains(class, "HASH-MARKER") {
		t.Fatal("get_loginclass returned non-class output")
	}
	assertBytesCleared(t, stdout)
	assertBytesCleared(t, stderr)
}

func TestOpenBSDGetLoginclassRejectsInvalidInputsBeforeRunner(t *testing.T) {
	for _, name := range []string{"", "-root", "line\nbreak", "control\x01", "nul\x00"} {
		runner := &openBSDTestRunner{}
		_, err := (openBSDGetLoginclassFunc{}).Execute(context.Background(), openBSDRuntime(runner), &openBSDGetLoginclassArgs{Name: name})
		assertFixedOpenBSDError(t, err, name)
		if len(runner.calls) != 0 {
			t.Fatalf("invalid username dispatched %d commands", len(runner.calls))
		}
	}
}

func TestOpenBSDGetLoginclassFixedErrorsAndClearsOutput(t *testing.T) {
	marker := "HASH-AND-ERROR-MARKER"
	tests := []struct {
		name   string
		result process.CommandResult
	}{
		{name: "runner error", result: process.CommandResult{Stdout: []byte(marker), Stderr: []byte(marker), Err: errors.New(marker)}},
		{name: "stdout truncated", result: process.CommandResult{Stdout: []byte(marker), Stderr: []byte(marker), StdoutTruncated: true}},
		{name: "stderr truncated", result: process.CommandResult{Stdout: []byte(marker), Stderr: []byte(marker), StderrTruncated: true}},
		{name: "deadline", result: process.CommandResult{Stdout: []byte(marker), Stderr: []byte(marker), Err: context.DeadlineExceeded}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &openBSDTestRunner{results: []process.CommandResult{tc.result}}
			stdout, stderr := tc.result.Stdout, tc.result.Stderr
			value, err := (openBSDGetLoginclassFunc{}).Execute(context.Background(), openBSDRuntime(runner), &openBSDGetLoginclassArgs{Name: "alice"})
			if value != nil {
				t.Fatal("getter exposed a value after Runner failure")
			}
			assertFixedOpenBSDError(t, err, marker)
			assertBytesCleared(t, stdout)
			assertBytesCleared(t, stderr)
		})
	}

	runner := &openBSDTestRunner{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (openBSDGetLoginclassFunc{}).Execute(ctx, openBSDRuntime(runner), &openBSDGetLoginclassArgs{Name: "alice"})
	assertFixedOpenBSDError(t, err)
	if len(runner.calls) != 0 {
		t.Fatal("pre-canceled getter invoked Runner")
	}

	stdout, stderr := []byte("cancel output marker"), []byte("cancel stderr marker")
	runner = &openBSDTestRunner{}
	ctx, cancel = context.WithCancel(context.Background())
	runner.runFn = func(context.Context, process.Command) process.CommandResult {
		cancel()
		return process.CommandResult{Stdout: stdout, Stderr: stderr}
	}
	_, err = (openBSDGetLoginclassFunc{}).Execute(ctx, openBSDRuntime(runner), &openBSDGetLoginclassArgs{Name: "alice"})
	assertFixedOpenBSDError(t, err, "cancel output marker", "cancel stderr marker")
	assertBytesCleared(t, stdout)
	assertBytesCleared(t, stderr)
}

func TestOpenBSDChloginclassRootAndValidationAreNoOps(t *testing.T) {
	emptyRoot := ""
	for _, root := range []*string{&emptyRoot, func() *string { value := "/alternate"; return &value }()} {
		base := &openBSDTestRunner{}
		runner := &openBSDAvailableRunner{openBSDTestRunner: base, available: true}
		_, err := (openBSDChloginclassFunc{}).Execute(context.Background(), openBSDRuntime(runner), &openBSDChloginclassArgs{Name: "alice", Loginclass: "staff", Root: root})
		assertFixedOpenBSDError(t, err, *root, "alice", "staff")
		if len(base.calls) != 0 || runner.availabilityCalls != 0 {
			t.Fatalf("alternate root made calls: runner=%d availability=%d", len(base.calls), runner.availabilityCalls)
		}
	}

	for _, tc := range []struct {
		name string
		args *openBSDChloginclassArgs
	}{
		{name: "invalid name", args: &openBSDChloginclassArgs{Name: "-alice", Loginclass: "staff"}},
		{name: "name newline", args: &openBSDChloginclassArgs{Name: "alice\r", Loginclass: "staff"}},
		{name: "empty class", args: &openBSDChloginclassArgs{Name: "alice", Loginclass: ""}},
		{name: "class NUL", args: &openBSDChloginclassArgs{Name: "alice", Loginclass: "staff\x00"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := &openBSDTestRunner{}
			runner := &openBSDAvailableRunner{openBSDTestRunner: base, available: true}
			_, err := (openBSDChloginclassFunc{}).Execute(context.Background(), openBSDRuntime(runner), tc.args)
			assertFixedOpenBSDError(t, err, tc.args.Name, tc.args.Loginclass)
			if len(base.calls) != 0 || runner.availabilityCalls != 0 {
				t.Fatalf("invalid arguments made calls: runner=%d availability=%d", len(base.calls), runner.availabilityCalls)
			}
		})
	}
}

func TestOpenBSDChloginclassSameValueSkipsSetAndAvailability(t *testing.T) {
	base := &openBSDTestRunner{results: []process.CommandResult{openBSDResult("class staff\n", 0)}}
	runner := &openBSDAvailableRunner{openBSDTestRunner: base, available: false}
	value, err := (openBSDChloginclassFunc{}).Execute(context.Background(), openBSDRuntime(runner), &openBSDChloginclassArgs{Name: "alice", Loginclass: "staff"})
	if err != nil || value != true || len(base.calls) != 1 || runner.availabilityCalls != 0 {
		t.Fatal("same-value class did not short-circuit before availability/setter")
	}
	if base.calls[0].Name != "userinfo" {
		t.Fatalf("first command = %q, want userinfo", base.calls[0].Name)
	}
}

func TestOpenBSDChloginclassDoesNotInventClassGrammar(t *testing.T) {
	wantClass := "staff-β"
	base := &openBSDTestRunner{results: []process.CommandResult{
		openBSDResult("class staff\n", 0),
		{},
		openBSDResult("class "+wantClass+"\n", 0),
	}}
	runner := &openBSDAvailableRunner{openBSDTestRunner: base, available: true}
	value, err := (openBSDChloginclassFunc{}).Execute(context.Background(), openBSDRuntime(runner), &openBSDChloginclassArgs{Name: "alice", Loginclass: wantClass})
	if err != nil || value != true {
		t.Fatal("non-ASCII login class was rejected or failed readback")
	}
	if !reflect.DeepEqual(base.calls[1].Args, []string{"-L", wantClass, "alice"}) {
		t.Fatal("login class was not passed as one argv element")
	}
}

func TestOpenBSDChloginclassGetterFailureStopsMutation(t *testing.T) {
	marker := "getter-error-marker"
	stdout, stderr := []byte(marker), []byte(marker)
	base := &openBSDTestRunner{results: []process.CommandResult{{Stdout: stdout, Stderr: stderr, Err: errors.New(marker)}}}
	runner := &openBSDAvailableRunner{openBSDTestRunner: base, available: true}
	_, err := (openBSDChloginclassFunc{}).Execute(context.Background(), openBSDRuntime(runner), &openBSDChloginclassArgs{Name: "alice", Loginclass: "daemon"})
	assertFixedOpenBSDError(t, err, marker)
	if len(base.calls) != 1 || runner.availabilityCalls != 0 {
		t.Fatalf("pre-read failure proceeded: calls=%d availability=%d", len(base.calls), runner.availabilityCalls)
	}
	assertBytesCleared(t, stdout)
	assertBytesCleared(t, stderr)
}

func TestOpenBSDChloginclassMutationAndReadbackSemantics(t *testing.T) {
	for _, tc := range []struct {
		name       string
		setExit    int
		postClass  string
		wantResult bool
	}{
		{name: "success", setExit: 0, postClass: "daemon", wantResult: true},
		{name: "nonzero exit with matching state", setExit: 7, postClass: "daemon", wantResult: true},
		{name: "nonzero exit with unchanged state", setExit: 7, postClass: "staff", wantResult: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setStdout, setStderr := []byte("setter stdout marker"), []byte("setter stderr marker")
			base := &openBSDTestRunner{results: []process.CommandResult{
				openBSDResult("class staff\n", 0),
				{Stdout: setStdout, Stderr: setStderr, ExitCode: tc.setExit},
				openBSDResult("class "+tc.postClass+"\n", 0),
			}}
			runner := &openBSDAvailableRunner{openBSDTestRunner: base, available: true}
			value, err := (openBSDChloginclassFunc{}).Execute(context.Background(), openBSDRuntime(runner), &openBSDChloginclassArgs{Name: "alice", Loginclass: "daemon"})
			if err != nil || value != tc.wantResult {
				t.Fatal("chloginclass readback result mismatch")
			}
			if len(base.calls) != 3 || runner.availabilityCalls != 1 || runner.availabilityName != "usermod" {
				t.Fatalf("calls=%d availability=%d name=%q", len(base.calls), runner.availabilityCalls, runner.availabilityName)
			}
			if base.calls[0].Name != "userinfo" || base.calls[1].Name != "usermod" || base.calls[2].Name != "userinfo" || !reflect.DeepEqual(base.calls[1].Args, []string{"-L", "daemon", "alice"}) {
				t.Fatal("chloginclass command sequence mismatch")
			}
			for i, cmd := range base.calls {
				if cmd.Shell || !reflect.DeepEqual(cmd.Env, []string{"LC_ALL=C"}) || cmd.Timeout <= 0 || cmd.MaxStdoutBytes <= 0 || cmd.MaxStderrBytes <= 0 {
					t.Fatalf("command %d contract mismatch", i)
				}
			}
			assertBytesCleared(t, setStdout)
			assertBytesCleared(t, setStderr)
		})
	}
}

func TestOpenBSDChloginclassAvailabilityAndMissingCapability(t *testing.T) {
	base := &openBSDTestRunner{results: []process.CommandResult{openBSDResult("class staff\n", 0)}}
	runner := &openBSDAvailableRunner{openBSDTestRunner: base, available: false}
	_, err := (openBSDChloginclassFunc{}).Execute(context.Background(), openBSDRuntime(runner), &openBSDChloginclassArgs{Name: "alice", Loginclass: "daemon"})
	assertFixedOpenBSDError(t, err, "alice", "daemon")
	if len(base.calls) != 1 || runner.availabilityCalls != 1 {
		t.Fatalf("unavailable mutator calls=%d availability=%d", len(base.calls), runner.availabilityCalls)
	}

	marker := "missing-usermod-marker"
	missing := &openBSDTestRunner{results: []process.CommandResult{
		openBSDResult("class staff\n", 0),
		{Err: errors.New(marker), Stderr: []byte(marker)},
	}}
	_, err = (openBSDChloginclassFunc{}).Execute(context.Background(), openBSDRuntime(missing), &openBSDChloginclassArgs{Name: "alice", Loginclass: "daemon"})
	assertFixedOpenBSDError(t, err, marker)
	if len(missing.calls) != 2 || missing.calls[1].Name != "usermod" {
		t.Fatal("Runner without availability capability did not resolve usermod")
	}
}

func TestOpenBSDChloginclassSetterFailuresLeaveStateUnknown(t *testing.T) {
	marker := "sensitive-runner-marker"
	for _, tc := range []struct {
		name   string
		result process.CommandResult
		cancel bool
	}{
		{name: "runner error", result: process.CommandResult{Stdout: []byte(marker), Stderr: []byte(marker), Err: errors.New(marker)}},
		{name: "deadline", result: process.CommandResult{Stdout: []byte(marker), Stderr: []byte(marker), Err: context.DeadlineExceeded}},
		{name: "stdout truncated", result: process.CommandResult{Stdout: []byte(marker), Stderr: []byte(marker), StdoutTruncated: true}},
		{name: "stderr truncated", result: process.CommandResult{Stdout: []byte(marker), Stderr: []byte(marker), StderrTruncated: true}},
		{name: "context canceled during setter", result: process.CommandResult{Stdout: []byte(marker), Stderr: []byte(marker)}, cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setStdout, setStderr := tc.result.Stdout, tc.result.Stderr
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			base := &openBSDTestRunner{results: []process.CommandResult{openBSDResult("class staff\n", 0), tc.result}}
			if tc.cancel {
				base.runFn = func(_ context.Context, cmd process.Command) process.CommandResult {
					if cmd.Name == "usermod" {
						cancel()
						return tc.result
					}
					return openBSDResult("class staff\n", 0)
				}
			}
			runner := &openBSDAvailableRunner{openBSDTestRunner: base, available: true}
			value, err := (openBSDChloginclassFunc{}).Execute(ctx, openBSDRuntime(runner), &openBSDChloginclassArgs{Name: "alice", Loginclass: "daemon"})
			if value != nil {
				t.Fatal("setter failure returned a state value")
			}
			assertFixedOpenBSDError(t, err, marker)
			if len(base.calls) != 2 || runner.availabilityCalls != 1 {
				t.Fatalf("failure retried or read back: calls=%d availability=%d", len(base.calls), runner.availabilityCalls)
			}
			assertBytesCleared(t, setStdout)
			assertBytesCleared(t, setStderr)
		})
	}
}

func TestOpenBSDExecuteTypeContextAndRuntimeSafeguards(t *testing.T) {
	get := openBSDGetLoginclassFunc{}
	change := openBSDChloginclassFunc{}
	for _, tc := range []struct {
		name string
		fn   runtime.ExecFunction
		ctx  context.Context
		rt   *runtime.Runtime
		args any
	}{
		{name: "get wrong type", fn: get, ctx: context.Background(), rt: openBSDRuntime(&openBSDTestRunner{}), args: &openBSDChloginclassArgs{}},
		{name: "get nil args", fn: get, ctx: context.Background(), rt: openBSDRuntime(&openBSDTestRunner{}), args: (*openBSDGetLoginclassArgs)(nil)},
		{name: "get nil context", fn: get, rt: openBSDRuntime(&openBSDTestRunner{}), args: &openBSDGetLoginclassArgs{Name: "alice"}},
		{name: "get nil runtime", fn: get, ctx: context.Background(), args: &openBSDGetLoginclassArgs{Name: "alice"}},
		{name: "get nil runner", fn: get, ctx: context.Background(), rt: openBSDRuntime(nil), args: &openBSDGetLoginclassArgs{Name: "alice"}},
		{name: "change wrong type", fn: change, ctx: context.Background(), rt: openBSDRuntime(&openBSDTestRunner{}), args: &openBSDGetLoginclassArgs{}},
		{name: "change nil args", fn: change, ctx: context.Background(), rt: openBSDRuntime(&openBSDTestRunner{}), args: (*openBSDChloginclassArgs)(nil)},
		{name: "change nil context", fn: change, rt: openBSDRuntime(&openBSDTestRunner{}), args: &openBSDChloginclassArgs{Name: "alice", Loginclass: "staff"}},
		{name: "change nil runtime", fn: change, ctx: context.Background(), args: &openBSDChloginclassArgs{Name: "alice", Loginclass: "staff"}},
		{name: "change nil runner", fn: change, ctx: context.Background(), rt: openBSDRuntime(nil), args: &openBSDChloginclassArgs{Name: "alice", Loginclass: "staff"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.fn.Execute(tc.ctx, tc.rt, tc.args)
			assertFixedOpenBSDError(t, err)
		})
	}
}

func TestOpenBSDRequiredArgumentsFailBeforeRunner(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerUserForGOOS(reg, "openbsd"); err != nil {
		t.Fatal(err)
	}
	base := &openBSDTestRunner{}
	runner := &openBSDAvailableRunner{openBSDTestRunner: base, available: true}
	rt := openBSDRuntime(runner)

	tests := []struct {
		name        string
		function    string
		provided    map[string]string
		missingName string
	}{
		{name: "getter absent name", function: "user.get_loginclass", missingName: "name"},
		{name: "getter empty name", function: "user.get_loginclass", provided: map[string]string{"name": ""}, missingName: "name"},
		{name: "changer absent arguments", function: "user.chloginclass", missingName: "name"},
		{name: "changer missing name", function: "user.chloginclass", provided: map[string]string{"loginclass": "staff"}, missingName: "name"},
		{name: "changer missing loginclass", function: "user.chloginclass", provided: map[string]string{"name": "alice"}, missingName: "loginclass"},
		{name: "changer empty name", function: "user.chloginclass", provided: map[string]string{"name": "", "loginclass": "staff"}, missingName: "name"},
		{name: "changer empty loginclass", function: "user.chloginclass", provided: map[string]string{"name": "alice", "loginclass": ""}, missingName: "loginclass"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prototype, err := reg.ResolveArgs(rt, tc.function)
			if err != nil {
				var unsupported *runtime.UnsupportedError
				if runtime.CurrentGOOS() == "openbsd" || !errors.As(err, &unsupported) {
					t.Fatal("ResolveArgs failed to resolve the production OpenBSD argument schema")
				}
				// ResolveArgs intentionally filters against the host GOOS. On a
				// non-OpenBSD test host, validate the same selector-registered
				// production function's Args prototype directly.
				fn, ok := reg.Get(tc.function)
				if !ok {
					t.Fatal("selector-registered function is missing")
				}
				prototype = fn.Args()
			}
			args := reflect.New(reflect.TypeOf(prototype)).Interface()
			err = config.Decode(args, nil, tc.provided)
			var missing *config.MissingRequiredError
			if !errors.As(err, &missing) || missing.Name != tc.missingName {
				t.Fatal("required argument was not rejected by the registered schema")
			}
		})
	}
	if len(base.calls) != 0 || runner.availabilityCalls != 0 {
		t.Fatalf("required-argument failures invoked Runner or availability: %d, %d", len(base.calls), runner.availabilityCalls)
	}
}

func TestRegisterUserForGOOSOpenBSDSurface(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerUserForGOOS(reg, "openbsd"); err != nil {
		t.Fatal(err)
	}
	want := []string{"user.add", "user.chgid", "user.chhome", "user.chloginclass", "user.chshell", "user.chuid", "user.delete", "user.get_loginclass", "user.info", "user.list_users"}
	if reg.Len() != len(want) {
		t.Fatalf("openbsd registry has %d functions, want %d", reg.Len(), len(want))
	}
	for _, name := range want {
		if _, ok := reg.Get(name); !ok {
			t.Fatalf("openbsd registry missing %s", name)
		}
	}
	for _, name := range []string{"user.get_loginclass", "user.chloginclass"} {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing from openbsd registration", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok || !reflect.DeepEqual(constrained.Platforms(), []string{"openbsd"}) {
			t.Fatalf("%s platform metadata = %v", name, fn)
		}
	}
	if err := registerUserForGOOS(reg, "openbsd"); err == nil {
		t.Fatal("duplicate OpenBSD registration succeeded")
	}

	linux := runtime.NewExecRegistry()
	if err := registerUserForGOOS(linux, "linux"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"user.get_loginclass", "user.chloginclass"} {
		if _, exists := linux.Get(name); exists {
			t.Fatalf("non-OpenBSD registry contains %s", name)
		}
	}
	if runtime.CurrentGOOS() == "linux" {
		if _, err := reg.Call(context.Background(), &runtime.Runtime{}, "user.get_loginclass", &openBSDGetLoginclassArgs{Name: "alice"}); err == nil {
			t.Fatal("OpenBSD getter was callable on Linux")
		} else {
			var unsupported *runtime.UnsupportedError
			if !errors.As(err, &unsupported) {
				t.Fatalf("Linux call error = %v, want UnsupportedError", err)
			}
		}
	}

	freeBSDDirect, freeBSDSelector := runtime.NewExecRegistry(), runtime.NewExecRegistry()
	if err := registerFreeBSD(freeBSDDirect); err != nil {
		t.Fatal(err)
	}
	if err := registerUserForGOOS(freeBSDSelector, "freebsd"); err != nil {
		t.Fatal(err)
	}
	if freeBSDSelector.Len() != len(pwRegistryNames) || freeBSDDirect.Len() != len(pwRegistryNames) {
		t.Fatalf("FreeBSD registry lengths changed: direct=%d selector=%d want=%d", freeBSDDirect.Len(), freeBSDSelector.Len(), len(pwRegistryNames))
	}
	for _, name := range pwRegistryNames {
		if _, ok := freeBSDSelector.Get(name); !ok {
			t.Fatalf("FreeBSD selector missing existing function %s", name)
		}
		if _, ok := freeBSDDirect.Get(name); !ok {
			t.Fatalf("direct FreeBSD registry missing existing function %s", name)
		}
	}
}
