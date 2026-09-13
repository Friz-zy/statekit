package at

// R8.3c mock coverage for every catalog function in at_solaris.py at the
// pinned Salt revision.  The Runner only records shell-free commands and the
// filesystem is an in-memory bounded filesystem; no at job is created or
// removed by these tests.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/cli"
	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type solarisAtRecordingRunner struct {
	results      []process.CommandResult
	calls        []process.Command
	available    map[string]bool
	cancel       context.CancelFunc
	availability bool
}

func (r *solarisAtRecordingRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	command.Args = append([]string(nil), command.Args...)
	command.Stdin = append([]byte(nil), command.Stdin...)
	r.calls = append(r.calls, command)
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	if len(r.results) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func (r *solarisAtRecordingRunner) CommandAvailable(name string) bool {
	if !r.availability {
		return true
	}
	return r.available[name]
}

func solarisAtRuntime(t *testing.T, runner *solarisAtRecordingRunner) *runtime.Runtime {
	t.Helper()
	fsys := runtime.NewMemoryFS()
	if err := fsys.MkdirAll(solarisAtJobDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	return &runtime.Runtime{Runner: runner, FS: fsys}
}

func solarisAtWriteJob(t *testing.T, rt *runtime.Runtime, jobID, content string) {
	t.Helper()
	if err := rt.FS.WriteFile(solarisAtJobPath(jobID), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func solarisAtArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

func assertSolarisAtBounded(t *testing.T, command process.Command) {
	t.Helper()
	if command.Shell || command.Timeout != solarisAtCommandTimeout ||
		command.MaxStdoutBytes != solarisAtOutputLimit ||
		command.MaxStderrBytes != solarisAtOutputLimit ||
		len(command.Stdin) > runtime.MaxCommandInputBytes {
		t.Fatalf("unsafe at command: %#v", command)
	}
}

func solarisAtQueueFixture() string {
	return " Rank     Execution Date     Owner     Job Queue\n" +
		"  1     Jun 20, 2026 12:03 alice 123.a cron\n" +
		"  2     Jun 21, 2025 13:04 bob 456-b batch\n"
}

func solarisAtQueueRuntime(t *testing.T, runner *solarisAtRecordingRunner) *runtime.Runtime {
	t.Helper()
	rt := solarisAtRuntime(t, runner)
	solarisAtWriteJob(t, rt, "123.a", "### SALT: nightly\n/sbin/reboot\n")
	solarisAtWriteJob(t, rt, "456-b", "echo no-tag\n")
	return rt
}

func assertAtRunasUnsupported(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("runas unexpectedly succeeded")
	}
	var unsupported *runtime.UnsupportedError
	if !errors.As(err, &unsupported) || unsupported.Kind != "function" || unsupported.Name != "at.at" {
		t.Fatalf("runas error=%v, want stable at.at UnsupportedError", err)
	}
	if err.Error() != `unsupported function "at.at"` {
		t.Fatalf("runas error=%q, want stable error text", err)
	}
	if strings.Contains(err.Error(), "alice") || strings.Contains(err.Error(), "root") {
		t.Fatalf("runas error reflected input: %v", err)
	}
}

func TestAtRunasUnsupportedBoundaryAcrossDirectRegistryAndCLI(t *testing.T) {
	if runtime.CurrentGOOS() == "solaris" {
		t.Skip("generic at.at is replaced by the Solaris provider")
	}

	runner := &solarisAtRecordingRunner{}
	rt := solarisAtRuntime(t, runner)
	_, directErr := (atFunc{}).Execute(ctxBG(), rt, &atArgs{
		Command:  "echo x",
		TimeSpec: "now",
		Kwargs:   map[string]any{"runas": "alice"},
	})
	assertAtRunasUnsupported(t, directErr)
	if len(runner.calls) != 0 {
		t.Fatalf("direct runas reached Runner: %#v", runner.calls)
	}

	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner = &solarisAtRecordingRunner{}
	rt = solarisAtRuntime(t, runner)
	rt.Exec = reg
	_, registryErr := reg.Call(ctxBG(), rt, "at.at", &atArgs{
		Command:  "echo x",
		TimeSpec: "now",
		Kwargs:   map[string]any{"runas": "root"},
	})
	assertAtRunasUnsupported(t, registryErr)
	if len(runner.calls) != 0 {
		t.Fatalf("registry runas reached Runner: %#v", runner.calls)
	}

	runner = &solarisAtRecordingRunner{}
	cliRuntime := solarisAtRuntime(t, runner)
	cliRuntime.Exec = reg
	app := cli.NewApp("test", func() (*runtime.Runtime, error) { return cliRuntime, nil })
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = stderrWrite
	code := app.Run([]string{
		"exec", "at.at", "--config",
		`{"command":"echo x","timespec":"now","kwargs":{"runas":"alice"}}`,
	})
	_ = stderrWrite.Close()
	os.Stderr = oldStderr
	stderr, readErr := io.ReadAll(stderrRead)
	_ = stderrRead.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if code != cli.ExitUnsupported {
		t.Fatalf("CLI runas exit=%d want=%d", code, cli.ExitUnsupported)
	}
	if strings.Contains(string(stderr), "alice") {
		t.Fatalf("CLI runas error reflected input: %q", stderr)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("CLI runas reached Runner: %#v", runner.calls)
	}
}

func TestSolarisAtRunasUnsupportedBeforeShortArgs(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "zero", args: nil},
		{name: "one", args: []string{"now"}},
		{name: "two", args: []string{"now", "echo x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &solarisAtRecordingRunner{}
			got, err := (solarisAtFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtArgs{
				Args: tc.args, Kwargs: map[string]any{"runas": "alice"},
			})
			if got != nil {
				t.Fatalf("direct result=%#v, want nil", got)
			}
			assertAtRunasUnsupported(t, err)
			if len(runner.calls) != 0 {
				t.Fatalf("direct runas reached Runner: %#v", runner.calls)
			}

			runner = &solarisAtRecordingRunner{}
			reg := newSolarisAtTestRegistry(t)
			rt := solarisAtRuntime(t, runner)
			rt.Exec = reg
			got, err = reg.Call(ctxBG(), rt, "at.at", &solarisAtArgs{
				Args: tc.args, Kwargs: map[string]any{"runas": "root"},
			})
			if got != nil {
				t.Fatalf("registry result=%#v, want nil", got)
			}
			assertAtRunasUnsupported(t, err)
			if len(runner.calls) != 0 {
				t.Fatalf("registry runas reached Runner: %#v", runner.calls)
			}

			var input string
			switch len(tc.args) {
			case 0:
				input = `{"kwargs":{"runas":"alice"}}`
			case 1:
				input = `{"args":["now"],"kwargs":{"runas":"alice"}}`
			default:
				input = `{"args":["now","echo x"],"kwargs":{"runas":"alice"}}`
			}
			runner = &solarisAtRecordingRunner{}
			code, _, stderr := runSolarisAtTestCLI(t, input, runner)
			if code != cli.ExitUnsupported || strings.Contains(stderr, "alice") || strings.Contains(stderr, "root") {
				t.Fatalf("CLI code=%d stderr=%q, want exit %d without reflected input", code, stderr, cli.ExitUnsupported)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("CLI runas reached Runner: %#v", runner.calls)
			}
		})
	}
}

func TestSolarisAtTimespecRejectsOptionLikeOperandsAcrossDirectRegistryAndCLI(t *testing.T) {
	for _, spec := range []string{"-f", "--help", "-x"} {
		t.Run(spec, func(t *testing.T) {
			args := &solarisAtArgs{Args: []string{spec, "echo x"}}
			runner := &solarisAtRecordingRunner{}
			got, err := (solarisAtFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), args)
			if got != nil || err == nil || err.Error() != "at: invalid timespec" || len(runner.calls) != 0 {
				t.Fatalf("direct spec=%q got=%#v err=%v calls=%d", spec, got, err, len(runner.calls))
			}

			runner = &solarisAtRecordingRunner{}
			reg := newSolarisAtTestRegistry(t)
			rt := solarisAtRuntime(t, runner)
			rt.Exec = reg
			got, err = reg.Call(ctxBG(), rt, "at.at", &solarisAtArgs{Args: []string{spec, "echo x"}})
			if got != nil || err == nil || err.Error() != "at: invalid timespec" || len(runner.calls) != 0 {
				t.Fatalf("registry spec=%q got=%#v err=%v calls=%d", spec, got, err, len(runner.calls))
			}

			runner = &solarisAtRecordingRunner{}
			code, stdout, stderr := runSolarisAtTestCLI(t, `{"args":["`+spec+`","echo x"]}`, runner)
			if code != cli.ExitFailed || stdout != "" || !strings.Contains(stderr, "at: invalid timespec") || len(runner.calls) != 0 {
				t.Fatalf("CLI spec=%q code=%d stdout=%q stderr=%q calls=%d", spec, code, stdout, stderr, len(runner.calls))
			}
		})
	}
}

func TestSolarisAtAcceptsValidTimespecOperandsAcrossDirectRegistryAndCLI(t *testing.T) {
	for _, spec := range []string{"now", "+1min", "3:05am +3 days"} {
		t.Run(spec, func(t *testing.T) {
			creation := process.CommandResult{
				ExitCode: 1, Stderr: []byte("bad time specification"),
			}
			runner := &solarisAtRecordingRunner{results: []process.CommandResult{creation}}
			got, err := (solarisAtFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtArgs{
				Args: []string{spec, "echo x"},
			})
			if err != nil || !reflect.DeepEqual(got, map[string]any{"jobs": []map[string]any{}, "error": "invalid timespec"}) || len(runner.calls) != 1 {
				t.Fatalf("direct spec=%q got=%#v err=%v calls=%d", spec, got, err, len(runner.calls))
			}
			if !reflect.DeepEqual(solarisAtArgv(runner.calls[0]), []string{"at", spec}) {
				t.Fatalf("direct spec=%q argv=%#v", spec, solarisAtArgv(runner.calls[0]))
			}

			runner = &solarisAtRecordingRunner{results: []process.CommandResult{creation}}
			reg := newSolarisAtTestRegistry(t)
			rt := solarisAtRuntime(t, runner)
			rt.Exec = reg
			got, err = reg.Call(ctxBG(), rt, "at.at", &solarisAtArgs{Args: []string{spec, "echo x"}})
			if err != nil || !reflect.DeepEqual(got, map[string]any{"jobs": []map[string]any{}, "error": "invalid timespec"}) || len(runner.calls) != 1 {
				t.Fatalf("registry spec=%q got=%#v err=%v calls=%d", spec, got, err, len(runner.calls))
			}
			if !reflect.DeepEqual(solarisAtArgv(runner.calls[0]), []string{"at", spec}) {
				t.Fatalf("registry spec=%q argv=%#v", spec, solarisAtArgv(runner.calls[0]))
			}

			runner = &solarisAtRecordingRunner{results: []process.CommandResult{creation}}
			code, stdout, stderr := runSolarisAtTestCLI(t, `{"args":["`+spec+`","echo x"]}`, runner)
			if code != cli.ExitOK || stdout == "" || stderr != "" || len(runner.calls) != 1 {
				t.Fatalf("CLI spec=%q code=%d stdout=%q stderr=%q calls=%d", spec, code, stdout, stderr, len(runner.calls))
			}
			if !reflect.DeepEqual(solarisAtArgv(runner.calls[0]), []string{"at", spec}) {
				t.Fatalf("CLI spec=%q argv=%#v", spec, solarisAtArgv(runner.calls[0]))
			}
		})
	}
}

func TestSolarisAtRegistryArgsCapabilityAndLinuxDispatch(t *testing.T) {
	want := map[string]struct {
		prototype any
		args      []string
	}{
		"at.atq":      {solarisAtqArgs{}, []string{"tag"}},
		"at.atrm":     {solarisAtrmArgs{}, []string{"args"}},
		"at.at":       {solarisAtArgs{}, []string{"args", "kwargs"}},
		"at.atc":      {solarisAtcArgs{}, []string{"jobid"}},
		"at._atq":     {solarisAtKwargsArgs{}, []string{"kwargs"}},
		"at.jobcheck": {solarisAtKwargsArgs{}, []string{"kwargs"}},
	}
	reg := runtime.NewExecRegistry()
	if err := registerSolaris(reg); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != len(want) {
		t.Fatalf("Solaris registry length=%d want=%d", reg.Len(), len(want))
	}
	for name, row := range want {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if reflect.TypeOf(fn.Args()) != reflect.TypeOf(row.prototype) {
			t.Fatalf("%s args type=%T want=%T", name, fn.Args(), row.prototype)
		}
		gotArgs, err := config.ArgumentNames(fn.Args())
		if err != nil || !reflect.DeepEqual(gotArgs, row.args) {
			t.Fatalf("%s argument names=%v err=%v want=%v", name, gotArgs, err, row.args)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok || !reflect.DeepEqual(constrained.Platforms(), []string{"solaris"}) ||
			runtime.SupportsPlatform(fn, "linux") || !runtime.SupportsPlatform(fn, "solaris") {
			t.Fatalf("%s capability=%v constrained=%t", name, constrained, ok)
		}
	}
	if err := registerSolaris(reg); err == nil {
		t.Fatal("duplicate Solaris registration accepted")
	}

	if runtime.CurrentGOOS() == "solaris" {
		return
	}
	linux := runtime.NewExecRegistry()
	if err := Register(linux); err != nil {
		t.Fatal(err)
	}
	if got := linux.Names(); !reflect.DeepEqual(got, []string{"at.at", "at.atq", "at.atrm"}) {
		t.Fatalf("Linux at names=%v", got)
	}
	for _, name := range []string{"at.atc", "at._atq", "at.jobcheck"} {
		if _, ok := linux.Get(name); ok {
			t.Fatalf("Linux registry unexpectedly exposes %s", name)
		}
	}

	// Calling the explicitly registered Solaris provider on Linux is still a
	// registry UnsupportedError and cannot reach a Runner.  CLI maps it to 3.
	runner := &solarisAtRecordingRunner{}
	unsupportedRT := solarisAtRuntime(t, runner)
	unsupportedRT.Exec = reg
	for name, args := range map[string]any{
		"at.atq":      &solarisAtqArgs{},
		"at.atrm":     &solarisAtrmArgs{},
		"at.at":       &solarisAtArgs{},
		"at.atc":      &solarisAtcArgs{JobID: "123.a"},
		"at._atq":     &solarisAtKwargsArgs{},
		"at.jobcheck": &solarisAtKwargsArgs{},
	} {
		if _, err := reg.Call(context.Background(), unsupportedRT, name, args); err == nil {
			t.Fatalf("%s unexpectedly ran on Linux", name)
		} else {
			var unsupported *runtime.UnsupportedError
			if !errors.As(err, &unsupported) || unsupported.Name != name {
				t.Fatalf("%s error=%v, want UnsupportedError", name, err)
			}
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unsupported Solaris calls reached Runner: %#v", runner.calls)
	}
	app := cli.NewApp("test", func() (*runtime.Runtime, error) { return unsupportedRT, nil })
	for _, name := range []string{"at.atq", "at.atrm", "at.at", "at.atc", "at._atq", "at.jobcheck"} {
		if code := app.Run([]string{"exec", name}); code != cli.ExitUnsupported {
			t.Fatalf("CLI %s exit=%d want=%d", name, code, cli.ExitUnsupported)
		}
	}
}

func TestSolarisAtqParsesDatesTagsAndFilters(t *testing.T) {
	runner := &solarisAtRecordingRunner{results: []process.CommandResult{{
		ExitCode: 0, Stdout: []byte(solarisAtQueueFixture()),
	}}}
	rt := solarisAtQueueRuntime(t, runner)
	got, err := (solarisAtqFunc{}).Execute(context.Background(), rt, &solarisAtqArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"jobs": []map[string]any{
		{"job": "123.a", "date": "2026-06-20", "time": "12:03:00", "queue": "cron", "user": "alice", "tag": "nightly"},
		{"job": "456-b", "date": "2025-06-21", "time": "13:04:00", "queue": "batch", "user": "bob", "tag": ""},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("atq=%#v want=%#v", got, want)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(solarisAtArgv(runner.calls[0]), []string{"atq"}) {
		t.Fatalf("atq argv=%#v", runner.calls)
	}
	assertSolarisAtBounded(t, runner.calls[0])

	nightly := "nightly"
	runner = &solarisAtRecordingRunner{results: []process.CommandResult{{
		ExitCode: 0, Stdout: []byte(solarisAtQueueFixture()),
	}}}
	rt = solarisAtQueueRuntime(t, runner)
	filtered, err := (solarisAtqFunc{}).Execute(context.Background(), rt, &solarisAtqArgs{Tag: &nightly})
	if err != nil || !reflect.DeepEqual(filtered, map[string]any{"jobs": []map[string]any{want["jobs"].([]map[string]any)[0]}}) {
		t.Fatalf("tag filter=%#v err=%v", filtered, err)
	}

	jobID := "456-b"
	runner = &solarisAtRecordingRunner{results: []process.CommandResult{{
		ExitCode: 0, Stdout: []byte(solarisAtQueueFixture()),
	}}}
	rt = solarisAtQueueRuntime(t, runner)
	filtered, err = solarisAtq(ctxBG(), rt, jobID)
	if err != nil || len(filtered.(map[string]any)["jobs"].([]map[string]any)) != 1 ||
		filtered.(map[string]any)["jobs"].([]map[string]any)[0]["job"] != jobID {
		t.Fatalf("job filter=%#v err=%v", filtered, err)
	}
}

func TestSolarisAtqEmptyFailureMalformedAndRunnerBoundaries(t *testing.T) {
	for _, output := range []string{"", "no files in queue.", "no files in queue.\n"} {
		runner := &solarisAtRecordingRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte(output)}}}
		got, err := (solarisAtqFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtqArgs{})
		if err != nil || !reflect.DeepEqual(got, solarisAtEmptyJobs()) {
			t.Fatalf("empty output %q = %#v err=%v", output, got, err)
		}
	}

	runner := &solarisAtRecordingRunner{results: []process.CommandResult{{ExitCode: 7, Stderr: []byte("queue denied")}}}
	got, err := (solarisAtqFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtqArgs{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"error": "queue denied"}) {
		t.Fatalf("nonzero atq=%#v err=%v", got, err)
	}

	for _, output := range []string{
		"  1 Jun 20, 2026 12:03 alice only-two-fields\n",
		"  1 Foo 20, 2026 12:03 alice 123.a cron\n",
		"  1 Jun 20, 2026 12:03 alice ../escape cron\n",
	} {
		runner = &solarisAtRecordingRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte(output)}}}
		got, err = (solarisAtqFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtqArgs{})
		if got != nil || err == nil {
			t.Fatalf("malformed output=%q got=%#v err=%v", output, got, err)
		}
	}

	runner = &solarisAtRecordingRunner{results: []process.CommandResult{{Err: errors.New("runner failure"), ExitCode: -1}}}
	if got, err = (solarisAtqFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtqArgs{}); got != nil || err == nil || !strings.Contains(err.Error(), "runner failure") {
		t.Fatalf("runner error got=%#v err=%v", got, err)
	}
	runner = &solarisAtRecordingRunner{results: []process.CommandResult{{ExitCode: 0, StdoutTruncated: true}}}
	if got, err = (solarisAtqFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtqArgs{}); got != nil || !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("output bound got=%#v err=%v", got, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &solarisAtRecordingRunner{}
	if got, err = (solarisAtqFunc{}).Execute(ctx, solarisAtRuntime(t, runner), &solarisAtqArgs{}); got != nil || !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("pre-cancel got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
	ctx, cancel = context.WithCancel(context.Background())
	runner = &solarisAtRecordingRunner{cancel: cancel, results: []process.CommandResult{{ExitCode: 0}}}
	if got, err = (solarisAtqFunc{}).Execute(ctx, solarisAtRuntime(t, runner), &solarisAtqArgs{}); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("post-run cancel got=%#v err=%v", got, err)
	}
}

func TestSolarisAtSchedulesExactArgvAndParsesJobID(t *testing.T) {
	runner := &solarisAtRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stderr: []byte("warning: commands will be executed\njob 123.a at Sat Jun 20 12:03:00 2026\n")},
		{ExitCode: 0, Stdout: []byte(solarisAtQueueFixture())},
	}}
	rt := solarisAtQueueRuntime(t, runner)
	got, err := (solarisAtFunc{}).Execute(ctxBG(), rt, &solarisAtArgs{
		Args:   []string{"3:05am +3 days", "/sbin/reboot"},
		Kwargs: map[string]any{"tag": "nightly"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 || !reflect.DeepEqual(solarisAtArgv(runner.calls[0]), []string{"at", "3:05am +3 days"}) ||
		string(runner.calls[0].Stdin) != "### SALT: nightly\n/sbin/reboot" {
		t.Fatalf("at calls=%#v", runner.calls)
	}
	for _, call := range runner.calls {
		assertSolarisAtBounded(t, call)
	}
	if jobs := got.(map[string]any)["jobs"].([]map[string]any); len(jobs) != 1 || jobs[0]["job"] != "123.a" {
		t.Fatalf("created job result=%#v", got)
	}

	for _, tc := range []struct {
		name   string
		result process.CommandResult
		want   any
	}{
		{"bad-time", process.CommandResult{ExitCode: 1, Stderr: []byte("bad time specification")}, map[string]any{"jobs": []map[string]any{}, "error": "invalid timespec"}},
		{"failure", process.CommandResult{ExitCode: 2, Stderr: []byte("permission denied")}, map[string]any{"jobs": []map[string]any{}, "error": "permission denied"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &solarisAtRecordingRunner{results: []process.CommandResult{tc.result}}
			got, err := (solarisAtFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtArgs{Args: []string{"now", "echo x"}})
			if err != nil || !reflect.DeepEqual(got, tc.want) || len(runner.calls) != 1 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.calls))
			}
		})
	}

	for _, stderr := range [][]byte{[]byte("only one line\n"), []byte("notice\njob ../escape at now\n")} {
		runner := &solarisAtRecordingRunner{results: []process.CommandResult{{ExitCode: 0, Stderr: stderr}}}
		got, err := (solarisAtFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtArgs{Args: []string{"now", "echo x"}})
		if got != nil || err == nil || len(runner.calls) != 1 {
			t.Fatalf("malformed creation stderr=%q got=%#v err=%v", stderr, got, err)
		}
	}

	runner = &solarisAtRecordingRunner{}
	if got, err = (solarisAtFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtArgs{}); err != nil || !reflect.DeepEqual(got, solarisAtEmptyJobs()) || len(runner.calls) != 0 {
		t.Fatalf("short args got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
	for _, args := range []solarisAtArgs{
		{Args: []string{"now\nunsafe", "echo x"}},
		{Args: []string{"now", strings.Repeat("x", runtime.MaxCommandInputBytes+1)}},
	} {
		runner = &solarisAtRecordingRunner{}
		if got, err = (solarisAtFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &args); got != nil || err == nil || len(runner.calls) != 0 {
			t.Fatalf("unsafe at args=%#v got=%#v err=%v calls=%d", args, got, err, len(runner.calls))
		}
	}
	runner = &solarisAtRecordingRunner{}
	if got, err = (solarisAtFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtArgs{
		Args: []string{"now", "echo x"}, Kwargs: map[string]any{"runas": "alice"},
	}); got != nil {
		t.Fatalf("runas result=%#v, want nil", got)
	} else {
		assertAtRunasUnsupported(t, err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("Solaris runas reached Runner: %#v", runner.calls)
	}
	runner = &solarisAtRecordingRunner{results: []process.CommandResult{{ExitCode: 1}}}
	if got, err = (solarisAtFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtArgs{
		Args: []string{"now", "echo x"}, Kwargs: map[string]any{"tag": ""},
	}); err != nil || len(runner.calls) != 1 || string(runner.calls[0].Stdin) != "### SALT: \necho x" {
		stdin := []byte(nil)
		if len(runner.calls) == 1 {
			stdin = runner.calls[0].Stdin
		}
		t.Fatalf("empty tag stdin=%q got=%#v err=%v calls=%d", stdin, got, err, len(runner.calls))
	}
}

func TestSolarisAtrmExactDeleteOrderFailuresAndNoMutation(t *testing.T) {
	runner := &solarisAtRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(solarisAtQueueFixture())},
		{ExitCode: 0},
		{ExitCode: 4, Stderr: []byte("busy")},
	}}
	rt := solarisAtQueueRuntime(t, runner)
	got, err := (solarisAtrmFunc{}).Execute(ctxBG(), rt, &solarisAtrmArgs{Args: []string{"123.a", "456-b"}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"jobs": map[string]any{
		"removed": []string{"123.a"}, "tag": nil,
		"failed": map[string]any{"456-b": "busy"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("atrm=%#v want=%#v", got, want)
	}
	if len(runner.calls) != 3 || !reflect.DeepEqual(solarisAtArgv(runner.calls[0]), []string{"atq"}) ||
		!reflect.DeepEqual(solarisAtArgv(runner.calls[1]), []string{"atrm", "123.a"}) ||
		!reflect.DeepEqual(solarisAtArgv(runner.calls[2]), []string{"atrm", "456-b"}) {
		t.Fatalf("delete calls=%#v", runner.calls)
	}
	for _, call := range runner.calls {
		assertSolarisAtBounded(t, call)
	}

	runner = &solarisAtRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(solarisAtQueueFixture())}, {ExitCode: 0},
	}}
	got, err = (solarisAtrmFunc{}).Execute(ctxBG(), solarisAtQueueRuntime(t, runner), &solarisAtrmArgs{Args: []string{"all", "nightly"}})
	if err != nil || !reflect.DeepEqual(got.(map[string]any)["jobs"].(map[string]any)["removed"], []string{"123.a"}) ||
		got.(map[string]any)["jobs"].(map[string]any)["tag"] != "nightly" {
		t.Fatalf("all/tag=%#v err=%v", got, err)
	}
	if len(runner.calls) != 2 || !reflect.DeepEqual(solarisAtArgv(runner.calls[1]), []string{"atrm", "123.a"}) {
		t.Fatalf("all/tag calls=%#v", runner.calls)
	}

	for _, args := range [][]string{nil, {"../escape"}, {"123.a", "../escape"}} {
		runner = &solarisAtRecordingRunner{}
		got, err = (solarisAtrmFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtrmArgs{Args: args})
		if args == nil {
			if err != nil || !reflect.DeepEqual(got, map[string]any{"jobs": map[string]any{"removed": []string{}, "tag": nil}}) || len(runner.calls) != 0 {
				t.Fatalf("empty atrm=%#v err=%v calls=%d", got, err, len(runner.calls))
			}
		} else if got != nil || err == nil || len(runner.calls) != 0 {
			t.Fatalf("invalid atrm=%#v got=%#v err=%v calls=%d", args, got, err, len(runner.calls))
		}
	}

	runner = &solarisAtRecordingRunner{results: []process.CommandResult{{ExitCode: 3, Stderr: []byte("queue unavailable")}}}
	got, err = (solarisAtrmFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtrmArgs{Args: []string{"123.a"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"error": "queue unavailable"}) || len(runner.calls) != 1 {
		t.Fatalf("queue failure atrm=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
}

func TestSolarisAtcDisplaysBoundedFileAndValidatesPath(t *testing.T) {
	runner := &solarisAtRecordingRunner{}
	rt := solarisAtRuntime(t, runner)
	content := "#!/bin/sh\necho tagged\n"
	solarisAtWriteJob(t, rt, "123.a", content)
	got, err := (solarisAtcFunc{}).Execute(ctxBG(), rt, &solarisAtcArgs{JobID: "123.a"})
	if err != nil || got != content || len(runner.calls) != 0 {
		t.Fatalf("atc=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
	missing, err := (solarisAtcFunc{}).Execute(ctxBG(), rt, &solarisAtcArgs{JobID: "999"})
	if err != nil || !reflect.DeepEqual(missing, map[string]any{"error": "invalid job id '999'"}) {
		t.Fatalf("missing atc=%#v err=%v", missing, err)
	}
	for _, jobID := range []string{"", "../escape", "a/b", "a\n"} {
		got, err := (solarisAtcFunc{}).Execute(ctxBG(), rt, &solarisAtcArgs{JobID: jobID})
		if got != nil || err == nil || len(runner.calls) != 0 {
			t.Fatalf("unsafe job id %q got=%#v err=%v calls=%d", jobID, got, err, len(runner.calls))
		}
	}

	solarisAtWriteJob(t, rt, "large", strings.Repeat("x", solarisAtJobFileLimit+1))
	if got, err = (solarisAtcFunc{}).Execute(ctxBG(), rt, &solarisAtcArgs{JobID: "large"}); got != nil || !errors.Is(err, runtime.ErrReadLimit) {
		t.Fatalf("bounded atc got=%#v err=%v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err = (solarisAtcFunc{}).Execute(ctx, rt, &solarisAtcArgs{JobID: "123.a"}); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled atc got=%#v err=%v", got, err)
	}

	runner = &solarisAtRecordingRunner{
		availability: true,
		available:    map[string]bool{"at": true, "atq": false, "atrm": true},
	}
	rt = solarisAtRuntime(t, runner)
	solarisAtWriteJob(t, rt, "123.a", content)
	if got, err = (solarisAtcFunc{}).Execute(ctxBG(), rt, &solarisAtcArgs{JobID: "123.a"}); got != nil || !errors.Is(err, errSolarisAtToolsUnavailable) || len(runner.calls) != 0 {
		t.Fatalf("missing at tool got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
}

func TestSolarisAtFiltersAndJobcheck(t *testing.T) {
	runner := &solarisAtRecordingRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte(solarisAtQueueFixture())}}}
	rt := solarisAtQueueRuntime(t, runner)
	got, err := (solarisAtqFilterFunc{}).Execute(ctxBG(), rt, &solarisAtKwargsArgs{Kwargs: map[string]any{
		"runas": "alice", "tag": "nightly", "hour": "12", "minute": 3,
		"day": 20, "month": "6", "year": "26",
	}})
	if err != nil {
		t.Fatal(err)
	}
	jobs := got.(map[string]any)["jobs"].([]map[string]any)
	if len(jobs) != 1 || jobs[0]["job"] != "123.a" {
		t.Fatalf("filtered jobs=%#v", got)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(solarisAtArgv(runner.calls[0]), []string{"atq"}) {
		t.Fatalf("filter argv=%#v", runner.calls)
	}

	runner = &solarisAtRecordingRunner{}
	got, err = (solarisAtJobcheckFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtKwargsArgs{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"error": "You have given a condition"}) || len(runner.calls) != 0 {
		t.Fatalf("empty jobcheck=%#v err=%v calls=%d", got, err, len(runner.calls))
	}

	runner = &solarisAtRecordingRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte(solarisAtQueueFixture())}}}
	got, err = (solarisAtqFilterFunc{}).Execute(ctxBG(), solarisAtQueueRuntime(t, runner), &solarisAtKwargsArgs{Kwargs: map[string]any{"hour": 99}})
	if got != nil || err == nil || len(runner.calls) != 0 {
		t.Fatalf("invalid filter got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}

	runner = &solarisAtRecordingRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte(solarisAtQueueFixture())}}}
	got, err = (solarisAtqFilterFunc{}).Execute(ctxBG(), solarisAtQueueRuntime(t, runner), &solarisAtKwargsArgs{Kwargs: map[string]any{"hour": 1}})
	if err != nil || got.(map[string]any)["note"] != "No match jobs or time format error" {
		t.Fatalf("no-match filter=%#v err=%v", got, err)
	}

	runner = &solarisAtRecordingRunner{results: []process.CommandResult{{ExitCode: 6, Stderr: []byte("queue unavailable")}}}
	got, err = (solarisAtJobcheckFunc{}).Execute(ctxBG(), solarisAtRuntime(t, runner), &solarisAtKwargsArgs{Kwargs: map[string]any{"tag": "nightly"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"error": "queue unavailable"}) {
		t.Fatalf("jobcheck queue error=%#v err=%v", got, err)
	}
}

func TestSolarisAtYearFilterPreservesSourceTypes(t *testing.T) {
	tests := []struct {
		name      string
		year      any
		wantJobs  int
		wantError bool
	}{
		{name: "int two digits converts", year: 26, wantJobs: 1},
		{name: "int four digits stays numeric", year: 2026, wantJobs: 0},
		{name: "float two digits converts", year: float64(26), wantJobs: 1},
		{name: "float four digits stays numeric", year: float64(2026), wantJobs: 0},
		{name: "string two digits converts", year: "26", wantJobs: 1},
		{name: "string four digits matches", year: "2026", wantJobs: 1},
		{name: "malformed", year: "20x6", wantError: true},
		{name: "fractional", year: 26.5, wantError: true},
		{name: "not a number", year: math.NaN(), wantError: true},
		{name: "infinite", year: math.Inf(1), wantError: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &solarisAtRecordingRunner{results: []process.CommandResult{{
				ExitCode: 0, Stdout: []byte(solarisAtQueueFixture()),
			}}}
			got, err := (solarisAtqFilterFunc{}).Execute(ctxBG(), solarisAtQueueRuntime(t, runner), &solarisAtKwargsArgs{
				Kwargs: map[string]any{"year": tc.year},
			})
			if tc.wantError {
				if got != nil || err == nil || len(runner.calls) != 0 {
					t.Fatalf("malformed year got=%#v err=%v calls=%d", got, err, len(runner.calls))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			jobs, ok := got.(map[string]any)["jobs"].([]map[string]any)
			if !ok || len(jobs) != tc.wantJobs || len(runner.calls) != 1 {
				t.Fatalf("year=%#v got=%#v calls=%d", tc.year, got, len(runner.calls))
			}
		})
	}
}

// The Solaris provider is platform-gated in production.  These unconstrained
// test adapters keep structured-input regressions executable on Linux while
// delegating to the real provider implementations; the production registry's
// platform-gating contract is covered by TestSolarisAtRegistryArgsCapabilityAndLinuxDispatch.
type solarisAtTestExec struct{}

func (solarisAtTestExec) Name() string { return "at.at" }
func (solarisAtTestExec) Args() any    { return solarisAtArgs{} }
func (solarisAtTestExec) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return (solarisAtFunc{}).Execute(ctx, rt, args)
}

func newSolarisAtTestRegistry(t *testing.T) *runtime.ExecRegistry {
	t.Helper()
	reg := runtime.NewExecRegistry()
	if err := reg.Register(solarisAtTestExec{}); err != nil {
		t.Fatal(err)
	}
	return reg
}

func runSolarisAtTestCLI(t *testing.T, input string, runner *solarisAtRecordingRunner) (int, string, string) {
	t.Helper()
	reg := newSolarisAtTestRegistry(t)
	rt := solarisAtRuntime(t, runner)
	rt.Exec = reg
	app := cli.NewApp("test", func() (*runtime.Runtime, error) { return rt, nil })

	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout, oldStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutWrite, stderrWrite
	code := app.Run([]string{"exec", "at.at", "--config", input})
	_ = stdoutWrite.Close()
	_ = stderrWrite.Close()
	os.Stdout, os.Stderr = oldStdout, oldStderr
	stdout, readErr := io.ReadAll(stdoutRead)
	_ = stdoutRead.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	stderr, readErr := io.ReadAll(stderrRead)
	_ = stderrRead.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return code, string(stdout), string(stderr)
}

type solarisAtFilterTestExec struct{}

func (solarisAtFilterTestExec) Name() string { return "at._atq" }
func (solarisAtFilterTestExec) Args() any    { return solarisAtKwargsArgs{} }
func (solarisAtFilterTestExec) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return (solarisAtqFilterFunc{}).Execute(ctx, rt, args)
}

func newSolarisAtFilterTestRegistry(t *testing.T) *runtime.ExecRegistry {
	t.Helper()
	reg := runtime.NewExecRegistry()
	if err := reg.Register(solarisAtFilterTestExec{}); err != nil {
		t.Fatal(err)
	}
	return reg
}

func decodeSolarisAtFilterJSON(t *testing.T, input string) (*solarisAtKwargsArgs, string) {
	t.Helper()
	structured, err := config.ParseStructured([]byte(input))
	if err != nil {
		t.Fatalf("ParseStructured(%s): %v", input, err)
	}
	args := &solarisAtKwargsArgs{}
	if err := config.Decode(args, structured, nil); err != nil {
		t.Fatalf("Decode(%s): %v", input, err)
	}
	raw := args.Kwargs["year"]
	return args, reflect.TypeOf(raw).String()
}

func runSolarisAtFilterCLI(t *testing.T, input string, runner *solarisAtRecordingRunner) (int, string, string) {
	t.Helper()
	reg := newSolarisAtFilterTestRegistry(t)
	rt := solarisAtQueueRuntime(t, runner)
	rt.Exec = reg
	app := cli.NewApp("test", func() (*runtime.Runtime, error) { return rt, nil })

	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout, oldStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutWrite, stderrWrite
	code := app.Run([]string{"exec", "at._atq", "--config", input, "--output", "json"})
	_ = stdoutWrite.Close()
	_ = stderrWrite.Close()
	os.Stdout, os.Stderr = oldStdout, oldStderr
	stdout, readErr := io.ReadAll(stdoutRead)
	_ = stdoutRead.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	stderr, readErr := io.ReadAll(stderrRead)
	_ = stderrRead.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return code, string(stdout), string(stderr)
}

func TestSolarisAtYearFilterJSONStructuredRegistryAndCLI(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		decodedType string
		wantJobs    int
		wantCalls   int
		wantError   bool
		wantExit    int
	}{
		{name: "json numeric two digits", input: `{"kwargs":{"year":26}}`, decodedType: "float64", wantJobs: 1, wantCalls: 1, wantExit: cli.ExitOK},
		{name: "json numeric four digits", input: `{"kwargs":{"year":2026}}`, decodedType: "float64", wantCalls: 1, wantExit: cli.ExitOK},
		{name: "json string two digits", input: `{"kwargs":{"year":"26"}}`, decodedType: "string", wantJobs: 1, wantCalls: 1, wantExit: cli.ExitOK},
		{name: "json string four digits", input: `{"kwargs":{"year":"2026"}}`, decodedType: "string", wantJobs: 1, wantCalls: 1, wantExit: cli.ExitOK},
		{name: "json malformed year", input: `{"kwargs":{"year":"20x6"}}`, decodedType: "string", wantError: true, wantExit: cli.ExitFailed},
		{name: "json fractional year", input: `{"kwargs":{"year":26.5}}`, decodedType: "float64", wantError: true, wantExit: cli.ExitFailed},
		{name: "json wrong year type", input: `{"kwargs":{"year":true}}`, decodedType: "bool", wantError: true, wantExit: cli.ExitFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args, gotType := decodeSolarisAtFilterJSON(t, tc.input)
			if gotType != tc.decodedType {
				t.Fatalf("decoded year type=%s want=%s", gotType, tc.decodedType)
			}

			runner := &solarisAtRecordingRunner{results: []process.CommandResult{{
				ExitCode: 0, Stdout: []byte(solarisAtQueueFixture()),
			}}}
			rt := solarisAtQueueRuntime(t, runner)
			reg := newSolarisAtFilterTestRegistry(t)
			prototype, err := reg.ResolveArgs(rt, "at._atq")
			if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(solarisAtKwargsArgs{}) {
				t.Fatalf("ResolveArgs prototype=%T err=%v", prototype, err)
			}
			got, err := reg.Call(context.Background(), rt, "at._atq", args)
			if tc.wantError {
				if got != nil || err == nil || err.Error() != "at: invalid year filter" || len(runner.calls) != 0 {
					t.Fatalf("registry invalid year got=%#v err=%v calls=%d", got, err, len(runner.calls))
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				jobs := got.(map[string]any)["jobs"].([]map[string]any)
				if len(jobs) != tc.wantJobs || len(runner.calls) != tc.wantCalls {
					t.Fatalf("registry got=%#v calls=%d wantJobs=%d wantCalls=%d", got, len(runner.calls), tc.wantJobs, tc.wantCalls)
				}
			}

			cliRunner := &solarisAtRecordingRunner{results: []process.CommandResult{{
				ExitCode: 0, Stdout: []byte(solarisAtQueueFixture()),
			}}}
			code, stdout, stderr := runSolarisAtFilterCLI(t, tc.input, cliRunner)
			if code != tc.wantExit || len(cliRunner.calls) != tc.wantCalls {
				t.Fatalf("CLI code=%d calls=%d stderr=%q wantCode=%d wantCalls=%d", code, len(cliRunner.calls), stderr, tc.wantExit, tc.wantCalls)
			}
			if tc.wantError {
				if stdout != "" || !strings.Contains(stderr, "at: invalid year filter") {
					t.Fatalf("CLI invalid year stdout=%q stderr=%q", stdout, stderr)
				}
				return
			}
			var payload map[string]any
			if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
				t.Fatalf("CLI JSON=%q: %v", stdout, err)
			}
			jobs, ok := payload["jobs"].([]any)
			if !ok || len(jobs) != tc.wantJobs {
				t.Fatalf("CLI payload=%#v want jobs=%d", payload, tc.wantJobs)
			}
		})
	}
}

func ctxBG() context.Context { return context.Background() }
