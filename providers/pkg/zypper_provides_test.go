package pkg

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func TestZypperListProvidesArgvAndOrderedMapping(t *testing.T) {
	root := "/target"
	args := map[string]any{"root": &root}
	before := map[string]any{"root": &root}
	stdout := "perl(Button)_|-perl-Wx\n" +
		"python3-futures_|-python3\n" +
		"perl(Button)_|-perl-Tk\n" +
		" vim_|-vim \n" +
		"weird line without separator\n" +
		"a_|-b_|-c\n" +
		"self_|-self\n" +
		"\n"
	rt, runner := zypperLowpkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(stdout)})

	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_provides", args)
	want := map[string]any{
		"perl(Button)":    []string{"perl-Wx", "perl-Tk"},
		"python3-futures": []string{"python3"},
		" vim":            []string{"vim "},
	}
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) {
		t.Fatalf("got=%#v err=%v args=%#v", got, err, args)
	}
	wantArgv := []string{"rpm", "--root", root, "-qa", "--queryformat", "%{PROVIDES}_|-%{NAME}\\n"}
	if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), wantArgv) {
		t.Fatalf("argv=%#v want=%v", runner.commands, wantArgv)
	}
	command := runner.commands[0]
	if command.Shell || command.MaxStdoutBytes != zypperLowpkgOutputLimit || command.MaxStderrBytes != zypperLowpkgOutputLimit || command.Env != nil {
		t.Fatalf("unsafe command=%#v", command)
	}
}

func TestZypperListProvidesEmptyOutputAndNoRoot(t *testing.T) {
	rt, runner := zypperLowpkgRuntime(process.CommandResult{})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_provides", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 1 {
		t.Fatalf("empty got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	if want := []string{"rpm", "-qa", "--queryformat", "%{PROVIDES}_|-%{NAME}\\n"}; !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), want) {
		t.Fatalf("argv=%v want=%v", zypperCommandArgs(runner.commands[0]), want)
	}
}

func TestZypperListProvidesNonzeroRetcodeFailsWithoutParsing(t *testing.T) {
	// Salt drives rpm through cmd.run without ignore_retcode: a nonzero
	// retcode raises before any line is parsed and never echoes rpm output.
	rt, runner := zypperLowpkgRuntime(process.CommandResult{ExitCode: 1, Stdout: []byte("parsed_|-never\n"), Stderr: []byte("rpm: no such command")})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_provides", map[string]any{})
	if got != nil || err == nil || len(runner.commands) != 1 || strings.Contains(err.Error(), "rpm: no such command") {
		t.Fatalf("retcode got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperListProvidesErrorsCancellationAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result process.CommandResult
	}{
		{"runner-error", process.CommandResult{Err: errors.New("rpm runner failure")}},
		{"stdout-truncated", process.CommandResult{StdoutTruncated: true}},
		{"stderr-truncated", process.CommandResult{StderrTruncated: true}},
		{"stdout-limit", process.CommandResult{Stdout: make([]byte, zypperLowpkgOutputLimit+1)}},
	} {
		rt, runner := zypperLowpkgRuntime(tc.result)
		if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_provides", map[string]any{}); got != nil || err == nil || len(runner.commands) != 1 {
			t.Fatalf("%s got=%#v err=%v calls=%d", tc.name, got, err, len(runner.commands))
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancelRunner := &zypperCancelRunner{cancel: cancel}
	rt := &runtime.Runtime{Runner: cancelRunner}
	if got, err := zypperLowpkgProvider().Zypper(ctx, rt, "list_provides", map[string]any{}); got != nil || !errors.Is(err, context.Canceled) || len(cancelRunner.calls) != 1 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(cancelRunner.calls))
	}

	if got, err := zypperParseProvides(strings.Repeat("a_|-b\n", zypperLowpkgMaxItems+1)); got != nil || err == nil {
		t.Fatalf("line bound got=%#v err=%v", got, err)
	}
	entries := strings.Repeat("a_|-b\n", zypperLowpkgMaxItems)
	if _, err := zypperParseProvides(entries); err != nil {
		t.Fatalf("exact bound err=%v", err)
	}
}

func TestZypperListProvidesRejectsInvalidArgumentsWithoutCalls(t *testing.T) {
	for _, args := range []map[string]any{
		{"root": 3},
		{"refresh": true},
		{"options": []string{"--details"}},
	} {
		rt, runner := zypperLowpkgRuntime()
		if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_provides", args); got != nil || err == nil || len(runner.commands) != 0 {
			t.Fatalf("args=%#v got=%#v err=%v calls=%d", args, got, err, len(runner.commands))
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := zypperLowpkgRuntime()
	if got, err := zypperLowpkgProvider().Zypper(ctx, rt, "list_provides", map[string]any{}); got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("pre-cancel got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}
