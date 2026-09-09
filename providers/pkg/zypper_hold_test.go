package pkg

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func TestZypperHoldExactSourceFlow(t *testing.T) {
	root := "/target"
	content := "solvable_name: held\nmatch_type: exact\n\n" +
		"solvable_name: pinned\nversion: = 2.0\nmatch_type: exact\n"
	rt, runner, fsys := zypperLocksRuntime(t, root, content, process.CommandResult{})
	args := map[string]any{
		"root": root,
		"pkgs": []any{"held", "new", map[string]any{"pinned": "9.9"}, map[string]any{"fresh": "1.0"}, "bare"},
	}
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "hold", args)
	want := map[string]any{
		"held": map[string]any{"name": "held", "changes": map[string]any{}, "result": true, "comment": "Package held is already set to be held."},
		"new":  map[string]any{"name": "new", "changes": map[string]any{"new": "hold", "old": ""}, "result": true, "comment": "Package new is now being held."},
		"pinned": map[string]any{"name": "pinned", "changes": map[string]any{}, "result": true,
			"comment": "Package pinned is already set to be held."},
		"fresh": map[string]any{"name": "fresh", "changes": map[string]any{"new": "hold", "old": ""}, "result": true, "comment": "Package fresh is now being held."},
		"bare":  map[string]any{"name": "bare", "changes": map[string]any{"new": "hold", "old": ""}, "result": true, "comment": "Package bare is now being held."},
	}
	if err != nil || !reflect.DeepEqual(zypperLocksPlain(got), want) || fsys.writes != 0 {
		t.Fatalf("got=%#v err=%v writes=%d want=%#v", zypperLocksPlain(got), err, fsys.writes, want)
	}
	wantArgv := []string{"zypper", "--non-interactive", "--no-refresh", "--root", root, "al", "new", "fresh=1.0", "bare"}
	if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), wantArgv) {
		t.Fatalf("argv=%v want=%v", zypperCommandArgs(runner.commands[0]), wantArgv)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, order := range [][2]string{{"held", "new"}, {"new", "pinned"}, {"pinned", "fresh"}, {"fresh", "bare"}} {
		if first, second := strings.Index(string(encoded), `"`+order[0]+`":`), strings.Index(string(encoded), `"`+order[1]+`":`); first < 0 || second < 0 || first > second {
			t.Fatalf("target order lost: %s (%d) vs %s (%d) in %s", order[0], first, order[1], second, encoded)
		}
	}
}

func TestZypperHoldNameIsOneTargetWithoutCommaSplitting(t *testing.T) {
	rt, runner, _ := zypperLocksRuntime(t, "", "", process.CommandResult{})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "hold", map[string]any{"name": "alpha,beta"})
	want := map[string]any{
		"alpha,beta": map[string]any{"name": "alpha,beta", "changes": map[string]any{"new": "hold", "old": ""}, "result": true, "comment": "Package alpha,beta is now being held."},
	}
	if err != nil || !reflect.DeepEqual(zypperLocksPlain(got), want) || len(runner.commands) != 1 {
		t.Fatalf("got=%#v err=%v calls=%d", zypperLocksPlain(got), err, len(runner.commands))
	}
	wantArgv := []string{"zypper", "--non-interactive", "--no-refresh", "al", "alpha,beta"}
	if !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), wantArgv) {
		t.Fatalf("argv=%v want=%v", zypperCommandArgs(runner.commands[0]), wantArgv)
	}
}

func TestZypperHoldPkgsPrecedenceOverName(t *testing.T) {
	rt, runner, _ := zypperLocksRuntime(t, "", "", process.CommandResult{})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "hold", map[string]any{
		"name": "ignored", "pkgs": []string{"chosen"},
	})
	plain := zypperLocksPlain(got)
	if err != nil || len(plain.(map[string]any)) != 1 || plain.(map[string]any)["chosen"] == nil {
		t.Fatalf("got=%#v err=%v", plain, err)
	}
	if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), []string{"zypper", "--non-interactive", "--no-refresh", "al", "chosen"}) {
		t.Fatalf("argv=%#v", runner.commands)
	}
}

func TestZypperHoldDuplicateTargetsKeepSnapshotSemantics(t *testing.T) {
	rt, runner, _ := zypperLocksRuntime(t, "", "", process.CommandResult{})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "hold", map[string]any{
		"pkgs": []any{"demo", "other", "demo"},
	})
	plain, ok := zypperLocksPlain(got).(map[string]any)
	if err != nil || !ok || len(plain) != 2 {
		t.Fatalf("got=%#v err=%v", zypperLocksPlain(got), err)
	}
	entry, ok := plain["demo"].(map[string]any)
	if !ok || entry["comment"] != "Package demo is now being held." {
		t.Fatalf("demo entry=%#v", plain["demo"])
	}
	// The lock snapshot cannot change mid-call, so both duplicate entries
	// collect and the batch receives the target twice, like the source.
	wantArgv := []string{"zypper", "--non-interactive", "--no-refresh", "al", "demo", "other", "demo"}
	if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), wantArgv) {
		t.Fatalf("argv=%#v want=%v", runner.commands, wantArgv)
	}
}

func TestZypperUnholdExactSourceFlow(t *testing.T) {
	root := "/target"
	content := "solvable_name: plain\nmatch_type: exact\n\n" +
		"solvable_name: pinned\nversion: == 2.0\n\n" +
		"solvable_name: stripped\nversion: = 3.1\n"
	for _, tc := range []struct {
		name      string
		args      map[string]any
		want      map[string]any
		wantBatch []string
	}{
		{
			name:      "versionless-lock-uses-plain-target",
			args:      map[string]any{"root": root, "name": "plain"},
			want:      map[string]any{"plain": map[string]any{"name": "plain", "changes": map[string]any{"new": "", "old": "hold"}, "result": true, "comment": "Package plain is no longer held."}},
			wantBatch: []string{"rl", "plain"},
		},
		{
			name:      "version-attribute-normalized-and-preserved",
			args:      map[string]any{"root": root, "name": "pinned"},
			want:      map[string]any{"pinned": map[string]any{"name": "pinned", "changes": map[string]any{"new": "", "old": "hold"}, "result": true, "comment": "Package pinned is no longer held."}},
			wantBatch: []string{"rl", "pinned=2.0"},
		},
		{
			name:      "requested-version-matches-lock",
			args:      map[string]any{"root": root, "pkgs": []any{map[string]any{"stripped": "3.1"}}},
			want:      map[string]any{"stripped": map[string]any{"name": "stripped", "changes": map[string]any{"new": "", "old": "hold"}, "result": true, "comment": "Package stripped is no longer held."}},
			wantBatch: []string{"rl", "stripped=3.1"},
		},
		{
			name: "requested-version-mismatch-fails-target",
			args: map[string]any{"root": root, "pkgs": []any{map[string]any{"stripped": "9.9"}}},
			want: map[string]any{"stripped": map[string]any{"name": "stripped", "changes": map[string]any{}, "result": false, "comment": "Unable to unhold package stripped as it is held with the other version."}},
		},
		{
			name: "requested-version-against-versionless-lock-fails-target",
			args: map[string]any{"root": root, "pkgs": []any{map[string]any{"plain": "1.0"}}},
			want: map[string]any{"plain": map[string]any{"name": "plain", "changes": map[string]any{}, "result": false, "comment": "Unable to unhold package plain as it is held with the other version."}},
		},
		{
			name: "not-locked-target",
			args: map[string]any{"root": root, "pkgs": []any{"plain", "missing"}},
			want: map[string]any{
				"plain":   map[string]any{"name": "plain", "changes": map[string]any{"new": "", "old": "hold"}, "result": true, "comment": "Package plain is no longer held."},
				"missing": map[string]any{"name": "missing", "changes": map[string]any{}, "result": true, "comment": "Package missing was already unheld."},
			},
			wantBatch: []string{"rl", "plain"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner, fsys := zypperLocksRuntime(t, root, content, process.CommandResult{})
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "unhold", tc.args)
			if err != nil || !reflect.DeepEqual(zypperLocksPlain(got), tc.want) || fsys.writes != 0 {
				t.Fatalf("got=%#v err=%v writes=%d want=%#v", zypperLocksPlain(got), err, fsys.writes, tc.want)
			}
			if tc.wantBatch == nil {
				if len(runner.commands) != 0 {
					t.Fatalf("unexpected call: %#v", runner.commands)
				}
				return
			}
			wantArgv := append([]string{"zypper", "--non-interactive", "--no-refresh", "--root", root}, tc.wantBatch...)
			if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), wantArgv) {
				t.Fatalf("argv=%#v want=%v", runner.commands, wantArgv)
			}
		})
	}
}

func TestZypperHoldUnholdEmptyInputFailsBeforeRunnerAndLocks(t *testing.T) {
	for _, function := range []string{"hold", "unhold"} {
		runner := &zypperNoCallRunner{}
		fsys := &zypperLocksReadErrorFS{MemoryFS: runtime.NewMemoryFS(), err: errors.New("locks read must not happen")}
		rt := &runtime.Runtime{Runner: runner, FS: fsys}
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, function, map[string]any{})
		if got != nil || err == nil || err.Error() != "Name or packages must be specified." || runner.calls != 0 || fsys.reads != 0 {
			t.Fatalf("%s got=%#v err=%v calls=%d reads=%d", function, got, err, runner.calls, fsys.reads)
		}
		got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, function, map[string]any{"name": "", "pkgs": []any{}, "sources": "also-rejected-later"})
		if got != nil || err == nil || err.Error() != "Name or packages must be specified." || runner.calls != 0 || fsys.reads != 0 {
			t.Fatalf("%s empty-values got=%#v err=%v calls=%d reads=%d", function, got, err, runner.calls, fsys.reads)
		}
	}
}

func TestZypperHoldAttributelessLockEntryIsFalsy(t *testing.T) {
	// A lock block with only solvable_name parses to an empty attribute
	// dict; Python treats it as falsy in `if locks.get(target)`.
	content := "solvable_name: bare\n"
	rt, runner, fsys := zypperLocksRuntime(t, "", content, process.CommandResult{})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "hold", map[string]any{"name": "bare"})
	want := map[string]any{"bare": map[string]any{"name": "bare", "changes": map[string]any{"new": "hold", "old": ""}, "result": true, "comment": "Package bare is now being held."}}
	if err != nil || !reflect.DeepEqual(zypperLocksPlain(got), want) || len(runner.commands) != 1 || fsys.writes != 0 {
		t.Fatalf("hold got=%#v err=%v", zypperLocksPlain(got), err)
	}

	rt, runner, _ = zypperLocksRuntime(t, "", content, process.CommandResult{})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "unhold", map[string]any{"name": "bare"})
	want = map[string]any{"bare": map[string]any{"name": "bare", "changes": map[string]any{}, "result": true, "comment": "Package bare was already unheld."}}
	if err != nil || !reflect.DeepEqual(zypperLocksPlain(got), want) || len(runner.commands) != 0 {
		t.Fatalf("unhold got=%#v err=%v", zypperLocksPlain(got), err)
	}
}

func TestZypperHoldUnholdNoCallWithoutNewTargets(t *testing.T) {
	content := "solvable_name: demo\nmatch_type: exact\n"
	locksFS := func(t *testing.T) runtime.FileSystem {
		memory := runtime.NewMemoryFS()
		if err := memory.MkdirAll(path.Dir(zypperLocksPath("")), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := memory.WriteFile(zypperLocksPath(""), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return memory
	}
	for _, tc := range []struct {
		function string
		target   string
		args     map[string]any
		comment  string
	}{
		{"hold", "demo", map[string]any{"name": "demo"}, "Package demo is already set to be held."},
		{"unhold", "missing", map[string]any{"name": "missing"}, "Package missing was already unheld."},
	} {
		noCall := &zypperNoCallRunner{}
		rt := &runtime.Runtime{Runner: noCall, FS: locksFS(t)}
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, tc.function, tc.args)
		entry, ok := zypperLocksPlain(got).(map[string]any)[tc.target]
		if !ok || err != nil || entry.(map[string]any)["comment"] != tc.comment || noCall.calls != 0 {
			t.Fatalf("%s got=%#v err=%v calls=%d", tc.function, zypperLocksPlain(got), err, noCall.calls)
		}
	}
}

func TestZypperHoldMutationCommandBoundary(t *testing.T) {
	root := "/target"
	rt, runner, _ := zypperLocksRuntime(t, root, "solvable_name: unheld\nmatch_type: exact\n", process.CommandResult{})
	if _, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "unhold", map[string]any{"root": root, "name": "unheld"}); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("calls=%d", len(runner.commands))
	}
	command := runner.commands[0]
	if command.Shell || command.MaxStdoutBytes != zypperLowpkgOutputLimit || command.MaxStderrBytes != zypperLowpkgOutputLimit || !reflect.DeepEqual(command.Env, []string{"LC_ALL=C"}) {
		t.Fatalf("unsafe mutation command=%#v", command)
	}
}

func TestZypperHoldUnholdRunnerErrorsPropagateWithoutFabricatedSuccess(t *testing.T) {
	root := "/target"
	content := "solvable_name: demo\nmatch_type: exact\n"
	for _, result := range []process.CommandResult{
		{Err: errors.New("runner failed")},
		{ExitCode: 7},
		{ExitCode: 4},
		{StdoutTruncated: true},
		{StderrTruncated: true},
		{Stdout: make([]byte, zypperLowpkgOutputLimit+1)},
	} {
		for _, function := range []string{"hold", "unhold"} {
			rt, runner, fsys := zypperLocksRuntime(t, root, content, result)
			var args map[string]any
			if function == "hold" {
				args = map[string]any{"root": root, "pkgs": []any{"demo", "fresh"}}
			} else {
				args = map[string]any{"root": root, "pkgs": []any{"demo"}}
			}
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, function, args)
			if got != nil || err == nil || len(runner.commands) != 1 || fsys.writes != 0 {
				t.Fatalf("%s result=%#v got=%#v err=%v calls=%d", function, result, got, err, len(runner.commands))
			}
		}
	}

	// Source cmd semantics: zypper warning exits are tolerated like
	// __zypper__.call's SUCCESS/WARNING sets; only genuine failures raise.
	for _, code := range []int{0, 6, 100, 101, 102, 103, 106, 107} {
		rt, runner, _ := zypperLocksRuntime(t, root, content, process.CommandResult{ExitCode: code})
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "hold", map[string]any{"root": root, "name": "fresh"})
		if err != nil || got == nil || len(runner.commands) != 1 {
			t.Fatalf("warning exit %d got=%#v err=%v calls=%d", code, got, err, len(runner.commands))
		}
	}
}

func TestZypperHoldUnholdCancellation(t *testing.T) {
	root := "/target"
	content := "solvable_name: demo\nmatch_type: exact\n"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner, _ := zypperLocksRuntime(t, root, content, process.CommandResult{})
	if got, err := zypperLowpkgProvider().Zypper(ctx, rt, "hold", map[string]any{"root": root, "name": "demo"}); got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("pre-cancel got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	cancelingRT, _, _ := zypperLocksRuntime(t, root, content, process.CommandResult{})
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancelingRunner := &zypperLocksCancelRunner{cancel: cancel2}
	cancelingRT.Runner = cancelingRunner
	got, err := zypperLowpkgProvider().Zypper(ctx2, cancelingRT, "hold", map[string]any{"root": root, "name": "fresh"})
	if got != nil || !errors.Is(err, context.Canceled) || len(cancelingRunner.commands) != 1 {
		t.Fatalf("post-cancel got=%#v err=%v calls=%d", got, err, len(cancelingRunner.commands))
	}
}

func TestZypperHoldValidationRejectsUnsafeTargetsBeforeRunner(t *testing.T) {
	root := "/target"
	cases := []struct {
		name   string
		args   map[string]any
		wantEr error
	}{
		{"unsupported-key", map[string]any{"name": "demo", "sources": []any{}}, nil},
		{"bad-root", map[string]any{"name": "demo", "root": "../escape"}, nil},
		{"pkgs-not-list", map[string]any{"pkgs": "demo"}, nil},
		{"name-not-string", map[string]any{"name": 7}, nil},
		{"pkgs-item-not-string", map[string]any{"pkgs": []any{7}}, nil},
		{"multi-key-mapping", map[string]any{"pkgs": []any{map[string]any{"a": "1", "b": "2"}}}, &runtime.UnsupportedError{}},
		{"empty-mapping", map[string]any{"pkgs": []any{map[string]any{}}}, nil},
		{"mapping-version-not-string", map[string]any{"pkgs": []any{map[string]any{"a": 1}}}, nil},
		{"empty-name-token", map[string]any{"pkgs": []any{""}}, nil},
		{"option-like-name", map[string]any{"pkgs": []any{"--evil"}}, nil},
		{"control-char-name", map[string]any{"pkgs": []any{"bad\nname"}}, nil},
		{"bad-version-token", map[string]any{"pkgs": []any{map[string]any{"demo": strings.Repeat("v", maxZypperTokenRunes+1)}}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, function := range []string{"hold", "unhold"} {
				runner := &zypperNoCallRunner{}
				fsys := &zypperLocksReadErrorFS{MemoryFS: runtime.NewMemoryFS(), err: errors.New("locks read must not happen")}
				rt := &runtime.Runtime{Runner: runner, FS: fsys}
				args := map[string]any{}
				for key, value := range tc.args {
					args[key] = value
				}
				if _, exists := args["root"]; !exists {
					args["root"] = root
				}
				got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, function, args)
				if got != nil || err == nil || runner.calls != 0 || fsys.reads != 0 {
					t.Fatalf("%s %s got=%#v err=%v calls=%d reads=%d", tc.name, function, got, err, runner.calls, fsys.reads)
				}
				var unsupported *runtime.UnsupportedError
				if tc.wantEr != nil && !errors.As(err, &unsupported) {
					t.Fatalf("%s %s err=%v want UnsupportedError", tc.name, function, err)
				}
			}
		})
	}

	oversized := make([]any, zypperLowpkgMaxItems+1)
	for i := range oversized {
		oversized[i] = "demo"
	}
	runner := &zypperNoCallRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "hold", map[string]any{"pkgs": oversized}); got != nil || err == nil || runner.calls != 0 {
		t.Fatalf("oversized got=%#v err=%v", got, err)
	}
}

func TestZypperHoldInputIsNotMutated(t *testing.T) {
	rt, runner, _ := zypperLocksRuntime(t, "", "solvable_name: demo\n", process.CommandResult{})
	pkgs := []any{"demo", map[string]any{"fresh": "1.0"}}
	args := map[string]any{"name": "unused", "pkgs": pkgs, "root": ""}
	if _, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "hold", args); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pkgs, []any{"demo", map[string]any{"fresh": "1.0"}}) || args["name"] != "unused" || args["root"] != "" {
		t.Fatalf("input mutated: args=%#v pkgs=%#v", args, pkgs)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("calls=%d", len(runner.commands))
	}
}
