package pkg

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type aptHoldTestRunner struct {
	results  []process.CommandResult
	commands []process.Command
	cancel   context.CancelFunc
}

func (r *aptHoldTestRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	if r.cancel != nil && len(r.commands) == 1 {
		r.cancel()
	}
	if len(r.results) == 0 {
		return process.CommandResult{}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

type aptPurgeTestRunner struct {
	results  []process.CommandResult
	commands []process.Command
	after    func(int)
}

func (r *aptPurgeTestRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	if r.after != nil {
		r.after(len(r.commands))
	}
	if len(r.results) == 0 {
		return process.CommandResult{}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func aptPurgeRuntime(r *aptPurgeTestRunner) *runtime.Runtime {
	return &runtime.Runtime{Runner: r, Facts: facts.ForTesting(facts.Overrides{
		CPU: &facts.CPUFacts{Arch: "amd64"},
	})}
}

func aptPurgeArgv(commands []process.Command) [][]string {
	argv := make([][]string, 0, len(commands))
	for _, command := range commands {
		argv = append(argv, append([]string{command.Name}, command.Args...))
	}
	return argv
}

func assertAPTPurgeCommands(t *testing.T, commands []process.Command, want [][]string) {
	t.Helper()
	if got := aptPurgeArgv(commands); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv=%#v want=%#v", got, want)
	}
	for i, command := range commands {
		if command.Shell || command.MaxStdoutBytes != aptPurgeOutputLimit || command.MaxStderrBytes != aptPurgeOutputLimit {
			t.Fatalf("command[%d]=%#v", i, command)
		}
	}
}

func aptPurgeInstalled(name, version string) string {
	return "install ok installed " + name + " " + version + " amd64\n"
}

func aptPurgeRemoved(name, version string) string {
	return "deinstall ok config-files " + name + " " + version + " amd64\n"
}

func TestAPTPurgeParseTargetsPrecedenceMappingsAndCommaNames(t *testing.T) {
	p := &commandProvider{spec: aptSpec}
	old := aptPurgeInstalled("literal", "1") + aptPurgeInstalled("versioned", "2") + aptPurgeInstalled("native", "3")
	new := aptPurgeRemoved("literal", "1") + aptPurgeRemoved("versioned", "2") + aptPurgeRemoved("native", "3")
	r := &aptPurgeTestRunner{results: []process.CommandResult{{Stdout: []byte(old)}, {}, {Stdout: []byte(new)}}}
	args := map[string]any{
		// A truthy pkgs branch ignores this malformed name before validation.
		"name": true,
		"pkgs": []any{
			"literal",
			// _uninstall uses the repacked mapping key as its target and ignores
			// the version value, as aptpkg.py does.
			map[string]any{"versioned": "does-not-match"},
			map[string]any{"native:amd64": 1.5},
		},
	}
	got, err := p.Apt(context.Background(), aptPurgeRuntime(r), "purge", args)
	want := map[string]any{
		"removed": map[string]any{
			"literal":   map[string]any{"old": "", "new": "1"},
			"versioned": map[string]any{"old": "", "new": "2"},
			"native":    map[string]any{"old": "", "new": "3"},
		},
		"installed": map[string]any{
			"literal":   map[string]any{"old": "1", "new": ""},
			"versioned": map[string]any{"old": "2", "new": ""},
			"native":    map[string]any{"old": "3", "new": ""},
		},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	assertAPTPurgeCommands(t, r.commands, [][]string{
		{"dpkg-query", "--showformat", aptPurgeQueryFormat, "-W"},
		{"apt-get", "-q", "-y", "purge", "literal", "versioned", "native"},
		{"dpkg-query", "--showformat", aptPurgeQueryFormat, "-W"},
	})

	// An explicitly empty list is falsey to parse_targets and therefore falls
	// through to name. The empty comma component remains a nonmatching key.
	r = &aptPurgeTestRunner{results: []process.CommandResult{{Stdout: []byte(
		aptPurgeInstalled("first", "1") + aptPurgeInstalled("second", "2"),
	)}, {}, {Stdout: []byte(aptPurgeRemoved("first", "1") + aptPurgeRemoved("second", "2"))}}}
	got, err = p.Apt(context.Background(), aptPurgeRuntime(r), "purge", map[string]any{
		"name": "first,,second", "pkgs": []any{},
	})
	if err != nil || got == nil {
		t.Fatalf("empty pkgs fallback got=%#v err=%v", got, err)
	}
	assertAPTPurgeCommands(t, r.commands, [][]string{
		{"dpkg-query", "--showformat", aptPurgeQueryFormat, "-W"},
		{"apt-get", "-q", "-y", "purge", "first", "second"},
		{"dpkg-query", "--showformat", aptPurgeQueryFormat, "-W"},
	})

	noCall := &aptPurgeTestRunner{}
	_, err = p.Apt(context.Background(), aptPurgeRuntime(noCall), "purge", map[string]any{
		"pkgs": []any{map[string]any{"same:amd64": "1"}, map[string]any{"same": "2"}},
	})
	if err == nil || len(noCall.commands) != 0 {
		t.Fatalf("normalized collision err=%v calls=%d", err, len(noCall.commands))
	}
}

func TestAPTPurgeWildcardOrderOldRemovedAndLiteralMetacharacters(t *testing.T) {
	p := &commandProvider{spec: aptSpec}
	old := aptPurgeInstalled("bar1", "1") + aptPurgeInstalled("foo1", "1") + aptPurgeInstalled("foo2", "1") + aptPurgeInstalled("literal", "1")
	new := aptPurgeRemoved("foo1", "1") + aptPurgeRemoved("foo2", "1") + aptPurgeRemoved("literal", "1")
	r := &aptPurgeTestRunner{results: []process.CommandResult{{Stdout: []byte(old + aptPurgeRemoved("stale", "2"))}, {}, {Stdout: []byte(new)}}}
	got, err := p.Apt(context.Background(), aptPurgeRuntime(r), "purge", map[string]any{"pkgs": []any{
		map[string]any{"bar*": "first"},
		"foo1",
		map[string]any{"literal": nil},
		map[string]any{"foo*": "last"},
		"stale",
	}})
	if err != nil || got == nil {
		t.Fatalf("wildcard got=%#v err=%v", got, err)
	}
	// The first wildcard is discarded, the final wildcard replaces foo1's value
	// without moving it, and the removed-only target follows installed targets.
	assertAPTPurgeCommands(t, r.commands, [][]string{
		{"dpkg-query", "--showformat", aptPurgeQueryFormat, "-W"},
		{"apt-get", "-q", "-y", "purge", "foo1", "literal", "foo2", "stale"},
		{"dpkg-query", "--showformat", aptPurgeQueryFormat, "-W"},
	})

	r = &aptPurgeTestRunner{results: []process.CommandResult{{Stdout: []byte(
		aptPurgeInstalled("foo?", "1") + aptPurgeInstalled("foo1", "1"),
	)}, {}, {Stdout: []byte(aptPurgeRemoved("foo?", "1"))}}}
	_, err = p.Apt(context.Background(), aptPurgeRuntime(r), "purge", map[string]any{"pkgs": []any{"foo?"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := aptPurgeArgv(r.commands)[1]; !reflect.DeepEqual(got, []string{"apt-get", "-q", "-y", "purge", "foo?"}) {
		t.Fatalf("plain question target argv=%#v", got)
	}
}

func TestAPTPurgeCompletedFailureAndAbortBoundaries(t *testing.T) {
	p := &commandProvider{spec: aptSpec}
	old := []byte(aptPurgeInstalled("demo", "1"))
	new := []byte(aptPurgeRemoved("demo", "1"))
	shape := map[string]any{
		"removed":   map[string]any{"demo": map[string]any{"old": "", "new": "1"}},
		"installed": map[string]any{"demo": map[string]any{"old": "1", "new": ""}},
	}
	for _, tc := range []struct {
		name    string
		remove  process.CommandResult
		wantErr bool
	}{
		{"nonzero stderr", process.CommandResult{ExitCode: 9, Stderr: []byte("remove failed")}, true},
		{"nonzero empty stderr", process.CommandResult{ExitCode: 9}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &aptPurgeTestRunner{results: []process.CommandResult{{Stdout: old}, tc.remove, {Stdout: new}}}
			got, err := p.Apt(context.Background(), aptPurgeRuntime(r), "purge", map[string]any{"pkgs": []any{"demo"}})
			if !reflect.DeepEqual(got, shape) || (err != nil) != tc.wantErr || len(r.commands) != 3 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.commands))
			}
			if tc.wantErr {
				var purgeErr *aptPurgeError
				if !errors.As(err, &purgeErr) || !reflect.DeepEqual(purgeErr.Info(), map[string]any{
					"errors": []string{"remove failed"}, "changes": shape,
				}) {
					t.Fatalf("error=%T %v info=%#v", err, err, purgeErr.Info())
				}
			}
			assertAPTPurgeCommands(t, r.commands, [][]string{
				{"dpkg-query", "--showformat", aptPurgeQueryFormat, "-W"},
				{"apt-get", "-q", "-y", "purge", "demo"},
				{"dpkg-query", "--showformat", aptPurgeQueryFormat, "-W"},
			})
		})
	}

	sentinel := errors.New("runner failure")
	for _, tc := range []struct {
		name   string
		result process.CommandResult
		want   error
	}{
		{"runner error", process.CommandResult{Err: sentinel}, sentinel},
		{"output limit", process.CommandResult{Err: process.ErrOutputLimit}, process.ErrOutputLimit},
		{"truncated output", process.CommandResult{StdoutTruncated: true}, process.ErrOutputLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &aptPurgeTestRunner{results: []process.CommandResult{{Stdout: old}, tc.result, {Stdout: []byte("must not run")}}}
			got, err := p.Apt(context.Background(), aptPurgeRuntime(r), "purge", map[string]any{"pkgs": []any{"demo"}})
			if got != nil || !errors.Is(err, tc.want) || len(r.commands) != 2 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.commands))
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := &aptPurgeTestRunner{results: []process.CommandResult{{Stdout: old}, {}}, after: func(calls int) {
		if calls == 2 {
			cancel()
		}
	}}
	got, err := p.Apt(ctx, aptPurgeRuntime(r), "purge", map[string]any{"pkgs": []any{"demo"}})
	if got != nil || !errors.Is(err, context.Canceled) || len(r.commands) != 2 {
		t.Fatalf("post-remove cancel got=%#v err=%v calls=%d", got, err, len(r.commands))
	}

	preCanceled, preCancel := context.WithCancel(context.Background())
	preCancel()
	r = &aptPurgeTestRunner{}
	got, err = p.Apt(preCanceled, aptPurgeRuntime(r), "purge", map[string]any{"pkgs": []any{"demo"}})
	if got != nil || !errors.Is(err, context.Canceled) || len(r.commands) != 0 {
		t.Fatalf("pre-cancel got=%#v err=%v calls=%d", got, err, len(r.commands))
	}

	unsupported := &aptPurgeTestRunner{}
	_, err = p.Apt(context.Background(), aptPurgeRuntime(unsupported), "purge", map[string]any{"pkgs": []any{map[string]any{"a": []string{"1"}}}})
	var unsupportedErr *runtime.UnsupportedError
	if !errors.As(err, &unsupportedErr) || len(unsupported.commands) != 0 || !strings.Contains(unsupportedErr.Name, "pkg.purge") {
		t.Fatalf("unsupported=%T %v calls=%d", err, err, len(unsupported.commands))
	}
}

func TestAPTHoldTestModeAndMutationGate(t *testing.T) {
	p := &commandProvider{spec: aptSpec}
	args := map[string]any{"name": "demo"}
	r := &aptHoldTestRunner{results: []process.CommandResult{{Stdout: []byte("demo install\n")}}}
	rt := &runtime.Runtime{Runner: r, Options: runtime.RuntimeOptions{Test: true}}
	got, err := p.Apt(context.Background(), rt, "hold", args)
	want := map[string]any{"demo": map[string]any{"name": "demo", "changes": map[string]any{}, "result": nil, "comment": "Package demo is set to be held."}}
	if err != nil || !reflect.DeepEqual(got, want) || len(r.commands) != 1 || len(r.commands[0].Stdin) != 0 {
		t.Fatalf("got=%#v err=%v commands=%#v", got, err, r.commands)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r = &aptHoldTestRunner{results: []process.CommandResult{{Stdout: []byte("demo install\n")}}, cancel: cancel}
	got, err = p.Apt(ctx, &runtime.Runtime{Runner: r}, "hold", args)
	if got != nil || !errors.Is(err, context.Canceled) || len(r.commands) != 1 {
		t.Fatalf("cancel gate got=%#v err=%v commands=%d", got, err, len(r.commands))
	}
}

func TestAPTHoldBoundedReadbackAndMutationFailures(t *testing.T) {
	sentinel := errors.New("runner failure")
	for _, tc := range []struct {
		name    string
		results []process.CommandResult
		want    error
	}{
		{"readback", []process.CommandResult{{Err: sentinel}}, sentinel},
		{"mutation", []process.CommandResult{{Stdout: []byte("demo install\n")}, {Err: sentinel}}, sentinel},
		{"bounds", []process.CommandResult{{Err: process.ErrOutputLimit}}, process.ErrOutputLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &aptHoldTestRunner{results: tc.results}
			got, err := (&commandProvider{spec: aptSpec}).Apt(context.Background(), &runtime.Runtime{Runner: r}, "hold", map[string]any{"name": "demo"})
			if got != nil || !errors.Is(err, tc.want) {
				t.Fatalf("got=%#v err=%v want=%v", got, err, tc.want)
			}
			for _, command := range r.commands {
				if command.Shell || command.MaxStdoutBytes != aptHoldOutputLimit || command.MaxStderrBytes != aptHoldOutputLimit {
					t.Fatalf("unbounded command=%#v", command)
				}
			}
		})
	}
}

func TestAPTHoldProcessesTargetsSequentiallyAndPreservesPartialResult(t *testing.T) {
	sentinel := errors.New("second readback failed")
	r := &aptHoldTestRunner{results: []process.CommandResult{
		{Stdout: []byte("first install\n")}, {},
		{Err: sentinel},
	}}
	args := map[string]any{"pkgs": []string{"first", "second"}}
	got, err := (&commandProvider{spec: aptSpec}).Apt(context.Background(), &runtime.Runtime{Runner: r}, "hold", args)
	want := map[string]any{"first": map[string]any{
		"name": "first", "changes": map[string]any{"old": "install", "new": "hold"},
		"result": true, "comment": "Package first is now being held.",
	}}
	if !errors.Is(err, sentinel) || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if len(r.commands) != 3 {
		t.Fatalf("commands=%#v", r.commands)
	}
	wantArgv := [][]string{{"dpkg", "--get-selections", "first"}, {"dpkg", "--set-selections"}, {"dpkg", "--get-selections", "second"}}
	for i, command := range r.commands {
		if !reflect.DeepEqual(append([]string{command.Name}, command.Args...), wantArgv[i]) || command.Shell || command.MaxStdoutBytes != aptHoldOutputLimit || command.MaxStderrBytes != aptHoldOutputLimit {
			t.Fatalf("command[%d]=%#v", i, command)
		}
	}
	if string(r.commands[1].Stdin) != "first hold\n" || !reflect.DeepEqual(args, map[string]any{"pkgs": []string{"first", "second"}}) {
		t.Fatalf("stdin/args mutated: stdin=%q args=%#v", r.commands[1].Stdin, args)
	}
}

func TestAPTHoldAlreadyHeldAndNotInstalled(t *testing.T) {
	r := &aptHoldTestRunner{results: []process.CommandResult{
		{Stdout: []byte("held hold\n")}, {Stdout: []byte{}}, {},
	}}
	got, err := (&commandProvider{spec: aptSpec}).Apt(context.Background(), &runtime.Runtime{Runner: r}, "hold", map[string]any{"pkgs": []string{"held", "missing"}})
	want := map[string]any{
		"held":    map[string]any{"name": "held", "changes": map[string]any{}, "result": true, "comment": "Package held is already set to be held."},
		"missing": map[string]any{"name": "missing", "changes": map[string]any{}, "result": false, "comment": "Package missing not currently held."},
	}
	if err != nil || !reflect.DeepEqual(got, want) || len(r.commands) != 2 {
		t.Fatalf("got=%#v err=%v commands=%#v", got, err, r.commands)
	}
}

func TestAPTEmptyHoldReadbackReturnsNotHeldWithoutMutation(t *testing.T) {
	for _, testMode := range []bool{false, true} {
		r := &aptHoldTestRunner{results: []process.CommandResult{{Stdout: []byte{}}}}
		rt := &runtime.Runtime{Runner: r, Options: runtime.RuntimeOptions{Test: testMode}}
		got, err := (&commandProvider{spec: aptSpec}).Apt(context.Background(), rt, "hold", map[string]any{"name": "empty"})
		if err != nil {
			t.Fatal(err)
		}
		entry := got.(map[string]any)["empty"].(map[string]any)
		if entry["result"] != false || entry["comment"] != "Package empty not currently held." || !reflect.DeepEqual(entry["changes"], map[string]any{}) || len(r.commands) != 1 {
			t.Fatalf("test=%v entry=%#v commands=%#v", testMode, entry, r.commands)
		}
	}
}

func TestAPTNameAndArchitectureHelpers(t *testing.T) {
	for _, tc := range []struct {
		in, arch, name string
		parsed         map[string]any
	}{
		{"zsh:amd64", "amd64", "zsh", map[string]any{"name": "zsh", "arch": "amd64"}},
		{"zsh:i386", "amd64", "zsh:i386", map[string]any{"name": "zsh", "arch": "i386"}},
		{"zsh", "amd64", "zsh", map[string]any{"name": "zsh", "arch": nil}},
	} {
		if got := normalizeName(tc.in, tc.arch); got != tc.name {
			t.Errorf("normalizeName(%q)=%q", tc.in, got)
		}
		got := parseArch(tc.in)
		if got["name"] != tc.parsed["name"] || got["arch"] != tc.parsed["arch"] {
			t.Errorf("parseArch(%q)=%v", tc.in, got)
		}
	}
}

func TestDebianVersionOrdering(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0~rc1", "1.0", -1}, {"1:1.0", "2.0", 1},
		{"1.0-1", "1.0-2", -1}, {"1.0+really", "1.0~really", 1},
		{"1.0-1", "1.0-1", 0}, {"1.0-1", "1.0-1~bpo", 1},
	} {
		if got := debVersionCmp(tc.a, tc.b, false); got != tc.want {
			t.Errorf("compare %q %q=%d want %d", tc.a, tc.b, got, tc.want)
		}
	}
	if debVersionCmp("9:1", "2:9", true) >= 0 {
		t.Error("ignore_epoch must remove epochs")
	}
}
