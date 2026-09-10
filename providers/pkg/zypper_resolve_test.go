package pkg

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func zypperResolveSearchXML(names ...string) string {
	out := "<stream>"
	for _, name := range names {
		out += `<solvable name="` + name + `"/>`
	}
	return out + "</stream>"
}

func TestZypperResolveCapabilitiesFalsePassesInputThrough(t *testing.T) {
	rt, runner := zypperLowpkgRuntime()
	args := map[string]any{"pkgs": []any{"w3m_ssl", map[string]any{"vim": "9.0"}, map[string]any{"curl": nil}, map[string]any{"empty": ""}}}
	before := map[string]any{"pkgs": []any{"w3m_ssl", map[string]any{"vim": "9.0"}, map[string]any{"curl": nil}, map[string]any{"empty": ""}}}
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "resolve_capabilities", args)
	want := []any{"w3m_ssl", map[string]any{"vim": "9.0"}, "curl", "empty"}
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) || len(runner.commands) != 0 {
		t.Fatalf("pass-through got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	rt, runner = zypperLowpkgRuntime()
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "resolve_capabilities", map[string]any{"pkgs": []any{}})
	if err != nil || !reflect.DeepEqual(got, []any{}) || len(runner.commands) != 0 {
		t.Fatalf("empty got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperResolveCapabilitiesExactNameStaysUnchanged(t *testing.T) {
	rt, runner := zypperLowpkgRuntime(
		process.CommandResult{Stdout: []byte(zypperResolveSearchXML("w3m_ssl"))},
		process.CommandResult{Stdout: []byte(zypperResolveSearchXML("w3m_ssl"))},
	)
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "resolve_capabilities", map[string]any{
		"pkgs": []any{"w3m_ssl", map[string]any{"w3m_ssl": "1.0"}}, "resolve_capabilities": true,
	})
	want := []any{"w3m_ssl", map[string]any{"w3m_ssl": "1.0"}}
	if err != nil || !reflect.DeepEqual(got, want) || len(runner.commands) != 2 {
		t.Fatalf("exact got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	wantArgv := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "search", "--match-exact", "w3m_ssl"}
	for i, command := range runner.commands {
		if !reflect.DeepEqual(zypperCommandArgs(command), wantArgv) {
			t.Fatalf("argv[%d]=%v want=%v", i, zypperCommandArgs(command), wantArgv)
		}
		if command.Shell || command.MaxStdoutBytes != zypperLowpkgOutputLimit {
			t.Fatalf("unsafe command=%#v", command)
		}
	}
}

func TestZypperResolveCapabilitiesProvidesSingleResultRenames(t *testing.T) {
	root := "/target"
	rt, runner := zypperLowpkgRuntime(
		process.CommandResult{Stdout: []byte(`<stream/>`)},
		process.CommandResult{Stdout: []byte(zypperResolveSearchXML("openssl"))},
		process.CommandResult{Stdout: []byte(`<stream/>`)},
		process.CommandResult{Stdout: []byte(zypperResolveSearchXML("openssl"))},
	)
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "resolve_capabilities", map[string]any{
		"pkgs": []any{"libssl.so.1.1()(64bit)", map[string]any{"libssl.so.1.1()(64bit)": "1.1"}}, "resolve_capabilities": true, "root": &root,
	})
	want := []any{"openssl", map[string]any{"openssl": "1.1"}}
	if err != nil || !reflect.DeepEqual(got, want) || len(runner.commands) != 4 {
		t.Fatalf("provides got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	wantArgv := [][]string{
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "search", "--match-exact", "libssl.so.1.1()(64bit)"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "search", "--match-exact", "--provides", "libssl.so.1.1()(64bit)"},
	}
	for i, command := range runner.commands {
		wantIndex := i
		if i > 1 {
			// The version-pinned entry repeats the same miss/provides pair.
			wantIndex = i - 2
		}
		if !reflect.DeepEqual(zypperCommandArgs(command), wantArgv[wantIndex]) {
			t.Fatalf("argv[%d]=%v want=%v", i, zypperCommandArgs(command), wantArgv[wantIndex])
		}
	}
}

func TestZypperResolveCapabilitiesAmbiguousAndFailedLookupsKeepOriginal(t *testing.T) {
	// Ambiguous provides results keep the original name.
	rt, runner := zypperLowpkgRuntime(
		process.CommandResult{Stdout: []byte(`<stream/>`)},
		process.CommandResult{Stdout: []byte(zypperResolveSearchXML("openssl", "openssl-steam"))},
	)
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "resolve_capabilities", map[string]any{"pkgs": []any{"libssl"}, "resolve_capabilities": true})
	if err != nil || !reflect.DeepEqual(got, []any{"libssl"}) || len(runner.commands) != 2 {
		t.Fatalf("ambiguous got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// A failed provides search keeps the original name too.
	rt, runner = zypperLowpkgRuntime(
		process.CommandResult{Stdout: []byte(`<stream/>`)},
		process.CommandResult{Stdout: []byte(`<stream/>`)},
	)
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "resolve_capabilities", map[string]any{"pkgs": []any{"missing-cap"}, "resolve_capabilities": true})
	if err != nil || !reflect.DeepEqual(got, []any{"missing-cap"}) || len(runner.commands) != 2 {
		t.Fatalf("double-miss got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// An exact-search exit failure falls back to provides like the
	// CommandExecutionError category in the source.
	rt, runner = zypperLowpkgRuntime(
		process.CommandResult{ExitCode: 1, Stderr: []byte("secret")},
		process.CommandResult{Stdout: []byte(zypperResolveSearchXML("openssl"))},
	)
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "resolve_capabilities", map[string]any{"pkgs": []any{"cap"}, "resolve_capabilities": true})
	if err != nil || !reflect.DeepEqual(got, []any{"openssl"}) || len(runner.commands) != 2 {
		t.Fatalf("exit-fallback got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperResolveCapabilitiesPropagatesNonCommandErrors(t *testing.T) {
	sentinel := errors.New("zypper runner failure")
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Err: sentinel})
	if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "resolve_capabilities", map[string]any{"pkgs": []any{"demo"}, "resolve_capabilities": true}); got != nil || !errors.Is(err, sentinel) || len(runner.commands) != 1 {
		t.Fatalf("runner error got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	rt, runner = zypperLowpkgRuntime(
		process.CommandResult{Stdout: []byte(`<stream/>`)},
		process.CommandResult{Err: sentinel},
	)
	if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "resolve_capabilities", map[string]any{"pkgs": []any{"demo"}, "resolve_capabilities": true}); got != nil || !errors.Is(err, sentinel) || len(runner.commands) != 2 {
		t.Fatalf("provides runner error got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperResolveCapabilitiesRefreshRootPositionAndForce(t *testing.T) {
	root := "/target"
	refresh := true
	rt, runner := zypperLowpkgRuntime(
		process.CommandResult{},
		process.CommandResult{Stdout: []byte(zypperResolveSearchXML("demo"))},
		process.CommandResult{Stdout: []byte(zypperResolveSearchXML("demo"))},
	)
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "resolve_capabilities", map[string]any{
		"pkgs": []any{"demo", "two"}, "refresh": &refresh, "root": &root, "resolve_capabilities": true,
	})
	if err != nil || !reflect.DeepEqual(got, []any{"demo", "two"}) || len(runner.commands) != 3 {
		t.Fatalf("refresh got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	want := [][]string{
		{"zypper", "--non-interactive", "refresh", "--force"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "search", "--match-exact", "demo"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "search", "--match-exact", "two"},
	}
	for i, command := range runner.commands {
		if !reflect.DeepEqual(zypperCommandArgs(command), want[i]) {
			t.Fatalf("argv[%d]=%v want=%v", i, zypperCommandArgs(command), want[i])
		}
	}

	emptyRoot := ""
	rt, runner = zypperLowpkgRuntime(process.CommandResult{})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "resolve_capabilities", map[string]any{
		"pkgs": []any{"demo"}, "refresh": true, "root": &emptyRoot,
	})
	// resolve_capabilities is unset: only the refresh runs, no search.
	if err != nil || !reflect.DeepEqual(got, []any{"demo"}) || len(runner.commands) != 1 {
		t.Fatalf("empty-root got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	if want := []string{"zypper", "--non-interactive", "refresh"}; !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), want) {
		t.Fatalf("empty-root refresh argv=%v want=%v", zypperCommandArgs(runner.commands[0]), want)
	}
}

func TestZypperResolveCapabilitiesRejectsInvalidInputWithoutCalls(t *testing.T) {
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"missing-pkgs", map[string]any{"resolve_capabilities": true}},
		{"pkgs-not-list", map[string]any{"pkgs": "demo"}},
		{"multi-key-dict", map[string]any{"pkgs": []any{map[string]any{"a": "1", "b": "2"}}}},
		{"non-string-version", map[string]any{"pkgs": []any{map[string]any{"a": 1}}}},
		{"empty-name", map[string]any{"pkgs": []any{""}}},
		{"empty-dict-name", map[string]any{"pkgs": []any{map[string]any{"": "1"}}}},
		{"control-name", map[string]any{"pkgs": []any{"bad\x01name"}}},
		{"non-string-entry", map[string]any{"pkgs": []any{1}}},
		{"control-version", map[string]any{"pkgs": []any{map[string]any{"vim": "1.0\x01"}}}},
		{"bad-refresh", map[string]any{"pkgs": []any{"demo"}, "refresh": "yes"}},
		{"bad-resolve", map[string]any{"pkgs": []any{"demo"}, "resolve_capabilities": "true"}},
		{"bad-root", map[string]any{"pkgs": []any{"demo"}, "root": 7}},
		{"unknown-kwarg", map[string]any{"pkgs": []any{"demo"}, "fromrepo": "repo"}},
	} {
		rt, runner := zypperLowpkgRuntime()
		if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "resolve_capabilities", tc.args); got != nil || err == nil || len(runner.commands) != 0 {
			t.Fatalf("%s args=%#v got=%#v err=%v calls=%d", tc.name, tc.args, got, err, len(runner.commands))
		}
	}
}

func TestZypperResolveCapabilitiesCancellationPropagates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := zypperLowpkgRuntime()
	if got, err := zypperLowpkgProvider().Zypper(ctx, rt, "resolve_capabilities", map[string]any{"pkgs": []any{"demo"}}); got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("pre-cancel got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// Cancellation during the first search propagates instead of being
	// swallowed by the CommandExecutionError fallback.
	liveCtx, liveCancel := context.WithCancel(context.Background())
	t.Cleanup(liveCancel)
	cancelRunner := &zypperCancelRunner{cancel: liveCancel}
	rt = &runtime.Runtime{Runner: cancelRunner}
	if got, err := zypperLowpkgProvider().Zypper(liveCtx, rt, "resolve_capabilities", map[string]any{"pkgs": []any{"demo"}, "resolve_capabilities": true}); got != nil || !errors.Is(err, context.Canceled) || len(cancelRunner.calls) != 1 {
		t.Fatalf("mid-cancel got=%#v err=%v calls=%d", got, err, len(cancelRunner.calls))
	}
}
