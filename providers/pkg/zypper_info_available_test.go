package pkg

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type zypperInfoAvailableRunner struct {
	commands []process.Command
	results  []process.CommandResult
	after    func(int)
}

func (r *zypperInfoAvailableRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	if r.after != nil {
		r.after(len(r.commands))
	}
	if len(r.results) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func TestZypperInfoAvailableSourceFlowAndParser(t *testing.T) {
	refresh, gpgautoimport := true, true
	root := "/target"
	names := []string{"zeta", "demo", "zeta", "alpha"}
	args := map[string]any{
		"names":         names,
		"refresh":       &refresh,
		"root":          &root,
		"repos":         "base",
		"gpgautoimport": &gpgautoimport,
	}
	before := map[string]any{
		"names":         append([]string(nil), names...),
		"refresh":       &refresh,
		"root":          &root,
		"repos":         "base",
		"gpgautoimport": &gpgautoimport,
	}
	output := "Loading repository data...\n" +
		"Information for package alpha:\n" +
		"----------------------------\n" +
		"Name: alpha\nInstalled: No\nStatus: not installed\n" +
		"Value: first:second\nDescription:\n-----\n" +
		"Information for package alpha:\n" +
		"Name: alpha\nInstalled: Yes\nStatus: up-to-date\n" +
		"Vendor: ACME: corp\n-----\n" +
		"Information for package demo:\n" +
		"Name: demo\nInstalled: No\nStatus: not installed\n-----\n"
	runner := &zypperInfoAvailableRunner{results: []process.CommandResult{
		{},
		{Stdout: []byte(output)},
	}}
	rt := &runtime.Runtime{Runner: runner, FS: &zypperNoCallFS{}}
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "info_available", args)
	want := map[string]any{
		"alpha": map[string]any{
			"installed": true,
			"status":    "up-to-date",
			"vendor":    "ACME: corp",
		},
		"demo": map[string]any{
			"installed": false,
			"status":    "not installed",
		},
	}
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) {
		t.Fatalf("got=%#v err=%v args=%#v", got, err, args)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("commands=%d", len(runner.commands))
	}
	wantRefresh := []string{"zypper", "--non-interactive", "--root", root, "--gpg-auto-import-keys", "refresh", "--force", "base"}
	wantQuery := []string{"zypper", "--non-interactive", "--no-refresh", "--root", root, "info", "-t", "package", "alpha", "demo", "zeta"}
	if got := zypperCommandArgs(runner.commands[0]); !reflect.DeepEqual(got, wantRefresh) {
		t.Fatalf("refresh argv=%#v want=%#v", got, wantRefresh)
	}
	if got := zypperCommandArgs(runner.commands[1]); !reflect.DeepEqual(got, wantQuery) {
		t.Fatalf("query argv=%#v want=%#v", got, wantQuery)
	}
	for i, command := range runner.commands {
		if command.Shell || command.MaxStdoutBytes != zypperLowpkgOutputLimit || command.MaxStderrBytes != zypperLowpkgOutputLimit {
			t.Fatalf("command %d is not bounded/shell-free: %#v", i, command)
		}
		wantEnv := []string{"LC_ALL=C"}
		if i == 1 {
			wantEnv = append(wantEnv, "ZYPP_READONLY_HACK=1")
		}
		if !reflect.DeepEqual(command.Env, wantEnv) {
			t.Fatalf("command %d env=%v want=%v", i, command.Env, wantEnv)
		}
	}
}

func TestZypperInfoAvailableRefreshRootForceVectors(t *testing.T) {
	var typedNilRoot *string
	emptyRoot := ""
	nonEmptyRoot := "/target"
	for _, tc := range []struct {
		name    string
		args    map[string]any
		results []process.CommandResult
		argv    [][]string
	}{
		{
			name: "root-absent",
			args: map[string]any{"names": []string{"demo"}},
			results: []process.CommandResult{
				{}, {Stdout: []byte("Information for package demo:\nName: demo\nInstalled: No\n")},
			},
			argv: [][]string{
				{"zypper", "--non-interactive", "refresh", "--force"},
				{"zypper", "--non-interactive", "--no-refresh", "info", "-t", "package", "demo"},
			},
		},
		{
			name: "root-nil-interface",
			args: map[string]any{"names": []string{"demo"}, "root": nil},
			results: []process.CommandResult{
				{}, {Stdout: []byte("Information for package demo:\nName: demo\nInstalled: No\n")},
			},
			argv: [][]string{
				{"zypper", "--non-interactive", "refresh", "--force"},
				{"zypper", "--non-interactive", "--no-refresh", "info", "-t", "package", "demo"},
			},
		},
		{
			name: "root-typed-nil-pointer",
			args: map[string]any{"names": []string{"demo"}, "root": typedNilRoot},
			results: []process.CommandResult{
				{}, {Stdout: []byte("Information for package demo:\nName: demo\nInstalled: No\n")},
			},
			argv: [][]string{
				{"zypper", "--non-interactive", "refresh", "--force"},
				{"zypper", "--non-interactive", "--no-refresh", "info", "-t", "package", "demo"},
			},
		},
		{
			name: "root-empty-pointer",
			args: map[string]any{"names": []string{"demo"}, "root": &emptyRoot},
			results: []process.CommandResult{
				{}, {Stdout: []byte("Information for package demo:\nName: demo\nInstalled: No\n")},
			},
			argv: [][]string{
				{"zypper", "--non-interactive", "refresh"},
				{"zypper", "--non-interactive", "--no-refresh", "info", "-t", "package", "demo"},
			},
		},
		{
			name: "root-nonempty-pointer",
			args: map[string]any{"names": []string{"demo"}, "root": &nonEmptyRoot},
			results: []process.CommandResult{
				{}, {Stdout: []byte("Information for package demo:\nName: demo\nInstalled: No\n")},
			},
			argv: [][]string{
				{"zypper", "--non-interactive", "--root", nonEmptyRoot, "refresh", "--force"},
				{"zypper", "--non-interactive", "--no-refresh", "--root", nonEmptyRoot, "info", "-t", "package", "demo"},
			},
		},
		{
			name:    "explicit-refresh-false",
			args:    map[string]any{"names": []string{"demo"}, "refresh": false},
			results: []process.CommandResult{{Stdout: []byte("Information for package demo:\nName: demo\nInstalled: No\n")}},
			argv: [][]string{
				{"zypper", "--non-interactive", "--no-refresh", "info", "-t", "package", "demo"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &zypperInfoAvailableRunner{results: tc.results}
			got, err := zypperLowpkgProvider().Zypper(context.Background(), &runtime.Runtime{Runner: runner}, "info_available", tc.args)
			if err != nil || !reflect.DeepEqual(got, map[string]any{"demo": map[string]any{"installed": false}}) {
				t.Fatalf("got=%#v err=%v", got, err)
			}
			if len(runner.commands) != len(tc.argv) {
				t.Fatalf("calls=%d want=%d", len(runner.commands), len(tc.argv))
			}
			for i, command := range runner.commands {
				if got := zypperCommandArgs(command); !reflect.DeepEqual(got, tc.argv[i]) {
					t.Fatalf("argv[%d]=%#v want=%#v", i, got, tc.argv[i])
				}
			}
		})
	}
}

func TestZypperInfoAvailableBatchesDeduplicatedSortedNames(t *testing.T) {
	names := make([]string, 0, 402)
	for i := 400; i >= 0; i-- {
		name := "pkg-" + strconv.Itoa(i)
		names = append(names, name)
		if i%100 == 0 {
			names = append(names, name)
		}
	}
	wantNames := append([]string(nil), names...)
	sort.Strings(wantNames)
	uniqueWantNames := wantNames[:0]
	for _, name := range wantNames {
		if len(uniqueWantNames) == 0 || uniqueWantNames[len(uniqueWantNames)-1] != name {
			uniqueWantNames = append(uniqueWantNames, name)
		}
	}
	runner := &zypperInfoAvailableRunner{}
	got, err := zypperLowpkgProvider().Zypper(context.Background(), &runtime.Runtime{Runner: runner}, "info_available", map[string]any{
		"names":   names,
		"refresh": false,
	})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if len(runner.commands) != 3 {
		t.Fatalf("calls=%d want=3", len(runner.commands))
	}
	for i, command := range runner.commands {
		argv := zypperCommandArgs(command)
		wantCount := 200
		if i == 2 {
			wantCount = 1
		}
		if len(argv) != 6+wantCount {
			t.Fatalf("batch %d argv length=%d", i, len(argv))
		}
		if argv[0] != "zypper" || argv[1] != "--non-interactive" || argv[2] != "--no-refresh" || argv[3] != "info" || argv[4] != "-t" || argv[5] != "package" {
			t.Fatalf("batch %d prefix=%#v", i, argv[:6])
		}
		if len(argv[6:]) != wantCount {
			t.Fatalf("batch %d names=%d want=%d", i, len(argv[6:]), wantCount)
		}
		wantBatch := uniqueWantNames[i*200 : i*200+wantCount]
		if !reflect.DeepEqual(argv[6:], wantBatch) {
			t.Fatalf("batch %d names=%#v want=%#v", i, argv[6:], wantBatch)
		}
	}
}

func TestZypperInfoAvailableEmptyNotFoundAndMalformedText(t *testing.T) {
	for _, output := range []string{"", "No matching items found.\n", "not a package record\nName:\nInstalled:\n-----\n"} {
		runner := &zypperInfoAvailableRunner{results: []process.CommandResult{{Stdout: []byte(output)}}}
		got, err := zypperLowpkgProvider().Zypper(context.Background(), &runtime.Runtime{Runner: runner}, "info_available", map[string]any{
			"names":   []string{"missing"},
			"refresh": false,
		})
		if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 1 {
			t.Fatalf("output=%q got=%#v err=%v calls=%d", output, got, err, len(runner.commands))
		}
	}
	if _, err := zypperParseInfoAvailable(context.Background(), strings.Repeat("Information for package", zypperLowpkgMaxItems+1)); !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("section overflow err=%v", err)
	}
}

func TestZypperInfoAvailableNoNamesAndArgumentBoundsAvoidSideEffects(t *testing.T) {
	runner := &zypperInfoAvailableRunner{}
	fsys := &zypperNoCallFS{}
	rt := &runtime.Runtime{Runner: runner, FS: fsys}
	for _, args := range []map[string]any{
		{},
		{"names": []string{}},
		{"names": []string{}, "refresh": "not-a-bool", "unknown": true},
	} {
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "info_available", args)
		if err != nil || !reflect.DeepEqual(got, map[string]any{}) {
			t.Fatalf("args=%#v got=%#v err=%v", args, got, err)
		}
	}
	if len(runner.commands) != 0 || fsys.calls != 0 {
		t.Fatalf("empty-input side effects: runner=%d fs=%d", len(runner.commands), fsys.calls)
	}

	tooLong := make([]string, zypperInfoAvailableBatchSize)
	for i := range tooLong {
		tooLong[i] = "pkg-" + strings.Repeat("x", 400) + strconv.Itoa(i)
	}
	if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "info_available", map[string]any{
		"names":   tooLong,
		"refresh": false,
	}); got != nil || err == nil || len(runner.commands) != 0 || fsys.calls != 0 {
		t.Fatalf("argv bound got=%#v err=%v runner=%d fs=%d", got, err, len(runner.commands), fsys.calls)
	}
	if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "info_available", map[string]any{
		"names": []string{"--help"}, "refresh": false,
	}); got != nil || err == nil || len(runner.commands) != 0 || fsys.calls != 0 {
		t.Fatalf("unsafe name got=%#v err=%v runner=%d fs=%d", got, err, len(runner.commands), fsys.calls)
	}
}

func TestZypperInfoAvailableRunnerErrorsRetcodesAndOutputLimits(t *testing.T) {
	results := []process.CommandResult{
		{Err: errors.New("runner failure")},
		{ExitCode: 1},
		{ExitCode: 7},
		{StdoutTruncated: true},
		{StderrTruncated: true},
		{Stdout: make([]byte, zypperLowpkgOutputLimit+1)},
		{Stderr: make([]byte, zypperLowpkgOutputLimit+1)},
	}
	for i, result := range results {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			runner := &zypperInfoAvailableRunner{results: []process.CommandResult{result}}
			got, err := zypperLowpkgProvider().Zypper(context.Background(), &runtime.Runtime{Runner: runner}, "info_available", map[string]any{
				"names": []string{"demo"}, "refresh": false,
			})
			if got != nil || err == nil || len(runner.commands) != 1 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
			}
			if i >= 3 && !errors.Is(err, process.ErrOutputLimit) {
				t.Fatalf("output-limit err=%v", err)
			}
		})
	}
}

func TestZypperInfoAvailableCancellationAndWrongProviderNoCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &zypperInfoAvailableRunner{}
	got, err := zypperLowpkgProvider().Zypper(ctx, &runtime.Runtime{Runner: runner}, "info_available", map[string]any{
		"names": []string{"demo"}, "refresh": false,
	})
	if got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("pre-cancel got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	ctx, cancel = context.WithCancel(context.Background())
	runner = &zypperInfoAvailableRunner{
		results: []process.CommandResult{{}},
		after: func(calls int) {
			if calls == 1 {
				cancel()
			}
		},
	}
	got, err = zypperLowpkgProvider().Zypper(ctx, &runtime.Runtime{Runner: runner}, "info_available", map[string]any{
		"names": []string{"demo"},
	})
	if got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 1 {
		t.Fatalf("post-refresh cancel got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	for _, manager := range []string{"apt", "yum"} {
		wrongRunner := &yumNoCallRunner{}
		got, err := (&commandProvider{spec: spec{manager: manager}}).Zypper(context.Background(), &runtime.Runtime{Runner: wrongRunner}, "info_available", map[string]any{
			"names": []string{"demo"},
		})
		if got != nil || !errors.Is(err, ErrUnsupportedZypper) || wrongRunner.calls != 0 {
			t.Fatalf("manager=%s got=%#v err=%v calls=%d", manager, got, err, wrongRunner.calls)
		}
	}
}
