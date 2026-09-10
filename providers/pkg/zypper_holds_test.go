package pkg

import (
	"context"
	"errors"
	"fmt"
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func zypperHoldsRuntime(t *testing.T, root, locks string, results ...process.CommandResult) (*runtime.Runtime, *yumRecordingRunner) {
	t.Helper()
	memory := runtime.NewMemoryFS()
	lockPath := zypperLocksPath(root)
	if err := memory.MkdirAll(path.Dir(lockPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := memory.WriteFile(lockPath, []byte(locks), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &yumRecordingRunner{results: results}
	return &runtime.Runtime{Runner: runner, FS: memory}, runner
}

func zypperHoldsSearchResult(names ...string) process.CommandResult {
	var out strings.Builder
	out.WriteString("<stream>")
	for _, name := range names {
		fmt.Fprintf(&out, "<solvable name=%q/>", name)
	}
	out.WriteString("</stream>")
	return process.CommandResult{Stdout: []byte(out.String())}
}

// zypperHoldsInfoResult renders the rpm --queryformat records produced for
// attr "edition,epoch": one record per edition, ---- separated.
func zypperHoldsInfoResult(records ...string) process.CommandResult {
	var out strings.Builder
	for _, record := range records {
		out.WriteString(record)
		out.WriteString("-----\n")
	}
	return process.CommandResult{Stdout: []byte(out.String())}
}

func zypperHoldsCommandArgv(runner *yumRecordingRunner) [][]string {
	argv := make([][]string, 0, len(runner.commands))
	for _, command := range runner.commands {
		argv = append(argv, zypperCommandArgs(command))
	}
	return argv
}

// zypperHoldsCheckInfoArgv asserts the rpm info query structurally because
// the long queryformat literal is pinned by the shared lowpkg builder.
func zypperHoldsCheckInfoArgv(t *testing.T, command process.Command, root, name string) {
	t.Helper()
	argv := zypperCommandArgs(command)
	want := []string{"rpm", "-q", name, "--queryformat"}
	if root != "" {
		want = []string{"rpm", "--root", root, "-q", name, "--queryformat"}
	}
	if len(argv) != len(want)+1 || !reflect.DeepEqual(argv[:len(want)], want) {
		t.Fatalf("info argv=%v want prefix=%v", argv, want)
	}
	format := argv[len(argv)-1]
	if !strings.Contains(format, "edition:") || !strings.Contains(format, "epoch:") || !strings.Contains(format, "name: %{NAME}") {
		t.Fatalf("queryformat=%q", format)
	}
	if !reflect.DeepEqual(command.Env, []string{"TZ=UTC"}) {
		t.Fatalf("info env=%v", command.Env)
	}
}

func TestZypperListHoldsComposesLocksSearchAndInfo(t *testing.T) {
	root := "/target"
	locks := "solvable_name: demo\ntype: package\n\n" +
		"solvable_name: skipped\ntype: pattern\n\n" +
		"solvable_name: plain\n"
	rt, runner := zypperHoldsRuntime(t, root, locks,
		zypperHoldsSearchResult("demo"),
		process.CommandResult{Stdout: []byte("SIZE\n")},
		zypperHoldsInfoResult("edition: 1.0-1\nname: demo\n", "edition: 2.0-1\nname: demo\n"),
		zypperHoldsSearchResult("plain"),
		process.CommandResult{Stdout: []byte("SIZE\n")},
		zypperHoldsInfoResult("edition: 1-1\nname: plain\n"),
	)
	args := map[string]any{"root": zypperStringPtr(root)}
	before := map[string]any{"root": args["root"]}
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_holds", args)
	// The type: pattern lock is skipped without a search call; attribute-less
	// entries default to package; editions render in descending version order
	// with the 0 epoch default.
	want := []string{"demo-0:2.0-1.*", "demo-0:1.0-1.*", "plain-0:1-1.*"}
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) {
		t.Fatalf("got=%#v err=%v args=%#v want=%#v", got, err, args, want)
	}
	if len(runner.commands) != 6 {
		t.Fatalf("calls=%d argv=%#v", len(runner.commands), zypperHoldsCommandArgv(runner))
	}
	wantSearchDemo := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "search", "--match-exact", "--case-sensitive", "--installed-only", "--details", "demo"}
	if got := zypperCommandArgs(runner.commands[0]); !reflect.DeepEqual(got, wantSearchDemo) {
		t.Fatalf("search demo argv=%v", got)
	}
	if got := zypperCommandArgs(runner.commands[1]); !reflect.DeepEqual(got, []string{"rpm", "--querytags"}) {
		t.Fatalf("querytags argv=%v", got)
	}
	zypperHoldsCheckInfoArgv(t, runner.commands[2], root, "demo")
	wantSearchPlain := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "search", "--match-exact", "--case-sensitive", "--installed-only", "--details", "plain"}
	if got := zypperCommandArgs(runner.commands[3]); !reflect.DeepEqual(got, wantSearchPlain) {
		t.Fatalf("search plain argv=%v", got)
	}
	if got := zypperCommandArgs(runner.commands[4]); !reflect.DeepEqual(got, []string{"rpm", "--querytags"}) {
		t.Fatalf("querytags argv=%v", got)
	}
	zypperHoldsCheckInfoArgv(t, runner.commands[5], root, "plain")
	for i, command := range runner.commands {
		if command.Shell || command.MaxStdoutBytes != zypperLowpkgOutputLimit || command.MaxStderrBytes != zypperLowpkgOutputLimit {
			t.Fatalf("unsafe command[%d]=%#v", i, command)
		}
	}
	if !reflect.DeepEqual(runner.commands[0].Env, []string{"LC_ALL=C", "ZYPP_READONLY_HACK=1"}) {
		t.Fatalf("search env=%v", runner.commands[0].Env)
	}
}

func TestZypperListHoldsWildcardSearchSkippedLocksAndBareNames(t *testing.T) {
	locks := "solvable_name: lib*\n\n" +
		"solvable_name: gone\n\n" +
		"solvable_name: cslock\ncase_sensitive: off\n"
	rt, runner := zypperHoldsRuntime(t, "", locks,
		zypperHoldsSearchResult("libtwo", "libone"),
		process.CommandResult{Stdout: []byte("SIZE\n")},
		zypperHoldsInfoResult("edition: 1-1\nname: libone\n"),
		process.CommandResult{Stdout: []byte("SIZE\n")},
		zypperHoldsInfoResult("edition: 1-1\nname: libtwo\n"),
		zypperHoldsSearchResult(),
		zypperHoldsSearchResult("cslock"),
		process.CommandResult{Stdout: []byte("SIZE\n")},
		zypperHoldsInfoResult("edition: 1-1\nname: cslock\n"),
	)
	full := false
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_holds", map[string]any{"full": &full})
	// The wildcard lock searches without a match flag; the empty search
	// result skips only its own lock; names dedupe in sorted order.
	want := []string{"libone", "libtwo", "cslock"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
	}
	if len(runner.commands) != 9 {
		t.Fatalf("calls=%d argv=%#v", len(runner.commands), zypperHoldsCommandArgv(runner))
	}
	for _, flag := range runner.commands[0].Args {
		if flag == "--match-exact" || flag == "--match-substrings" {
			t.Fatalf("wildcard search passed match flag: %v", runner.commands[0].Args)
		}
	}
	// case_sensitive: off is still a present kwarg, and pinned search maps
	// kwarg presence to the CLI flag.
	csArgv := runner.commands[6].Args
	found := false
	for _, flag := range csArgv {
		if flag == "--case-sensitive" {
			found = true
		}
	}
	if !found {
		t.Fatalf("case_sensitive lock lost its flag: %v", csArgv)
	}
}

func TestZypperListHoldsSearchFailureCategories(t *testing.T) {
	locks := "solvable_name: exitfail\n\nsolvable_name: demo\n"
	rt, runner := zypperHoldsRuntime(t, "", locks,
		process.CommandResult{ExitCode: 7},
		zypperHoldsSearchResult("demo"),
		process.CommandResult{Stdout: []byte("SIZE\n")},
		zypperHoldsInfoResult("edition: 1-1\nname: demo\n"),
	)
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_holds", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, []string{"demo-0:1-1.*"}) || len(runner.commands) != 4 {
		t.Fatalf("exit-skip got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// A failing zypper exit code in the last lock is skipped the same way.
	rt, runner = zypperHoldsRuntime(t, "", "solvable_name: demo\n\nsolvable_name: exitfail\n",
		zypperHoldsSearchResult("demo"),
		process.CommandResult{Stdout: []byte("SIZE\n")},
		zypperHoldsInfoResult("edition: 1-1\nname: demo\n"),
		process.CommandResult{ExitCode: 104},
	)
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_holds", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, []string{"demo-0:1-1.*"}) || len(runner.commands) != 4 {
		t.Fatalf("tail-skip got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// Runner errors are infrastructure failures and must propagate.
	rt, runner = zypperHoldsRuntime(t, "", "solvable_name: demo\n", process.CommandResult{Err: errors.New("runner failure")})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_holds", map[string]any{})
	if got != nil || err == nil || len(runner.commands) != 1 {
		t.Fatalf("runner-err got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// An output-limit violation on the search output propagates.
	rt, runner = zypperHoldsRuntime(t, "", "solvable_name: demo\n", process.CommandResult{StdoutTruncated: true})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_holds", map[string]any{})
	if got != nil || err == nil || len(runner.commands) != 1 {
		t.Fatalf("limit got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// Cancellation propagates instead of being swallowed as a skip.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &yumRecordingRunner{}
	rt = &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	got, err = zypperLowpkgProvider().Zypper(ctx, rt, "list_holds", map[string]any{})
	if got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// A canceled context surfacing mid-search propagates too.
	ctx, cancel = context.WithCancel(context.Background())
	cancelRunner := &zypperCancelRunner{cancel: cancel}
	memory := runtime.NewMemoryFS()
	if err := memory.MkdirAll("/etc/zypp", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := memory.WriteFile("/etc/zypp/locks", []byte("solvable_name: demo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rt = &runtime.Runtime{Runner: cancelRunner, FS: memory}
	got, err = zypperLowpkgProvider().Zypper(ctx, rt, "list_holds", map[string]any{})
	if got != nil || !errors.Is(err, context.Canceled) || len(cancelRunner.calls) != 1 {
		t.Fatalf("mid-cancel got=%#v err=%v calls=%d", got, err, len(cancelRunner.calls))
	}
}

func TestZypperListHoldsDedupeEpochAndFullShapes(t *testing.T) {
	locks := "solvable_name: demo\n\nsolvable_name: de*\n"
	rt, runner := zypperHoldsRuntime(t, "", locks,
		zypperHoldsSearchResult("demo"),
		process.CommandResult{Stdout: []byte("SIZE\n")},
		zypperHoldsInfoResult("edition: 2:1.0-1\nepoch: 2\nname: demo\n"),
		zypperHoldsSearchResult("deb", "demo"),
		process.CommandResult{Stdout: []byte("SIZE\n")},
		zypperHoldsInfoResult("edition: 3-1\nname: deb\n"),
	)
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_holds", map[string]any{})
	// demo is not queried twice across locks; the epoch from rpm is kept and
	// the edition carries its own epoch prefix exactly like the format string.
	want := []string{"demo-2:2:1.0-1.*", "deb-0:3-1.*"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
	}
	// search(demo), querytags, info(demo), search(de*), querytags, info(deb):
	// no second querytags/info pair for demo.
	if len(runner.commands) != 6 {
		t.Fatalf("calls=%d argv=%#v", len(runner.commands), zypperHoldsCommandArgv(runner))
	}

	// full=false collapses every edition to the bare, deduped name.
	rt, runner = zypperHoldsRuntime(t, "", "solvable_name: demo\n",
		zypperHoldsSearchResult("demo"),
		process.CommandResult{Stdout: []byte("SIZE\n")},
		zypperHoldsInfoResult("edition: 1.0-1\nname: demo\n", "edition: 2.0-1\nname: demo\n"),
	)
	full := false
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_holds", map[string]any{"full": &full})
	if err != nil || !reflect.DeepEqual(got, []string{"demo"}) || len(runner.commands) != 3 {
		t.Fatalf("bare got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperListHoldsPatternMatrix(t *testing.T) {
	results := []process.CommandResult{
		zypperHoldsSearchResult("demo"),
		process.CommandResult{Stdout: []byte("SIZE\n")},
		zypperHoldsInfoResult("edition: 2.0-1\nname: demo\n"),
	}
	for _, tc := range []struct {
		name    string
		pattern string
		full    *bool
		want    []string
	}{
		{name: "match full", pattern: "demo", want: []string{"demo-0:2.0-1.*"}},
		{name: "prefix only does not match", pattern: "mo", want: []string{}},
		{name: "nonmatch", pattern: "other", want: []string{}},
		{name: "empty pattern matches all", pattern: "", want: []string{"demo-0:2.0-1.*"}},
		{name: "bare name never carries a version suffix", pattern: "demo", full: zypperBoolPtr(false), want: []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := zypperHoldsRuntime(t, "", "solvable_name: demo\ntype: package\n", results...)
			args := map[string]any{"pattern": zypperStringPtr(tc.pattern)}
			if tc.full != nil {
				args["full"] = tc.full
			}
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_holds", args)
			if err != nil || !reflect.DeepEqual(got, tc.want) || len(runner.commands) != 3 {
				t.Fatalf("got=%#v err=%v want=%#v calls=%d", got, err, tc.want, len(runner.commands))
			}
		})
	}
}

func TestZypperListHoldsEmptyLocksAndPureRejection(t *testing.T) {
	// Locks containing only non-package entries return an empty list with
	// zero search/info calls.
	rt, runner := zypperHoldsRuntime(t, "", "solvable_name: skipped\ntype: pattern\n")
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_holds", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, []string{}) || len(runner.commands) != 0 {
		t.Fatalf("empty got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// A missing lock file is an empty source-compatible result.
	rt, runner = zypperHoldsRuntime(t, "", "")
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_holds", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, []string{}) || len(runner.commands) != 0 {
		t.Fatalf("missing got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// Invalid regex, unsupported keys, and wrong types are rejected before
	// the Runner or the filesystem are touched. Python-only lookahead is not
	// compilable by RE2 and is rejected deterministically.
	for _, args := range []map[string]any{
		{"pattern": "["},
		{"pattern": "demo(?=x)"},
		{"unknown": true},
		{"full": "yes"},
		{"root": false},
	} {
		rt := &runtime.Runtime{Runner: &zypperNoCallRunner{}, FS: &zypperNoCallFS{}}
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_holds", args)
		if got != nil || err == nil {
			t.Fatalf("args=%#v got=%#v err=%v", args, got, err)
		}
	}

	// An unknown key is caller input: the rejection keeps the shared
	// argument-unsupported classification without echoing the key, mirroring
	// the sanitized pattern category below.
	const unknownKeyMarker = "secret_key_name"
	keyRunner := &zypperNoCallRunner{}
	keyFS := &zypperNoCallFS{}
	rt = &runtime.Runtime{Runner: keyRunner, FS: keyFS}
	_, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_holds", map[string]any{unknownKeyMarker: true})
	var unsupportedArg *runtime.UnsupportedError
	if err == nil || err.Error() != `unsupported argument ""` || strings.Contains(err.Error(), unknownKeyMarker) ||
		!errors.As(err, &unsupportedArg) || unsupportedArg.Kind != "argument" || unsupportedArg.Name != "" {
		t.Fatalf("unsafe unknown key error=%v", err)
	}
	if keyRunner.calls != 0 || keyFS.calls != 0 {
		t.Fatalf("unknown key side effects: runner=%d fs=%d", keyRunner.calls, keyFS.calls)
	}

	// The pattern error message never echoes the malformed value.
	rt = &runtime.Runtime{Runner: &zypperNoCallRunner{}, FS: &zypperNoCallFS{}}
	_, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_holds", map[string]any{"pattern": "[secret\nvalue"})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe pattern error=%v", err)
	}

	// An unclosed group is an error kind whose native compile message echoes
	// the whole expression, so this pins the sanitized stable category for
	// the syntax errors that would otherwise reflect the malformed pattern.
	const groupLeakMarker = "r33i-group-leak-marker"
	rt = &runtime.Runtime{Runner: &zypperNoCallRunner{}, FS: &zypperNoCallFS{}}
	_, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_holds", map[string]any{"pattern": "(" + groupLeakMarker})
	if err == nil || err.Error() != `argument "pattern": invalid hold pattern` || strings.Contains(err.Error(), groupLeakMarker) {
		t.Fatalf("unsafe group pattern error=%v", err)
	}
}
