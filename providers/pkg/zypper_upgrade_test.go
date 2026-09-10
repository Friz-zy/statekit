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

func zypperUpgradeRuntime(runner process.Runner, osVersion string) *runtime.Runtime {
	return &runtime.Runtime{
		Facts: facts.ForTesting(facts.Overrides{
			Package: "zypper",
			OS:      &facts.OSFacts{Family: facts.FamilySuse, Version: osVersion},
			CPU:     &facts.CPUFacts{Arch: "x86_64"},
		}),
		Runner: runner,
	}
}

const zypperUpgradeQueryFormat = "%{NAME}_|-%{EPOCH}_|-%{VERSION}_|-%{RELEASE}_|-%{ARCH}_|-(none)_|-%{INSTALLTIME}\n"

func TestZypperUpgradeUpdateActionComparesOldNew(t *testing.T) {
	runner := &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("foo_|-0_|-1_|-1_|-x86_64_|-(none)_|-0\n")},
		{},
		{Stdout: []byte("foo_|-0_|-2_|-1_|-x86_64_|-(none)_|-0\n")},
	}}
	rt := zypperUpgradeRuntime(runner, "15")
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade", map[string]any{"refresh": false})
	want := map[string]any{"foo": map[string]any{"old": "1-1", "new": "2-1"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
	}
	wantArgv := [][]string{
		{"rpm", "-qa", "--queryformat", zypperUpgradeQueryFormat},
		{"zypper", "--non-interactive", "--no-refresh", "update", "--auto-agree-with-licenses"},
		{"rpm", "-qa", "--queryformat", zypperUpgradeQueryFormat},
	}
	if len(runner.commands) != len(wantArgv) {
		t.Fatalf("calls=%d argv=%v", len(runner.commands), zypperAllArgv(runner))
	}
	for i, command := range runner.commands {
		if argv := zypperCommandArgs(command); !reflect.DeepEqual(argv, wantArgv[i]) {
			t.Fatalf("argv[%d]=%v want=%v", i, argv, wantArgv[i])
		}
		if command.Shell || command.MaxStdoutBytes != zypperLowpkgOutputLimit {
			t.Fatalf("unsafe command[%d]=%#v", i, command)
		}
	}
}

func zypperAllArgv(runner *yumRecordingRunner) [][]string {
	out := make([][]string, 0, len(runner.commands))
	for _, command := range runner.commands {
		out = append(out, zypperCommandArgs(command))
	}
	return out
}

func TestZypperUpgradeDistUpgradeOptionsAndSkipVerifyPosition(t *testing.T) {
	for _, tc := range []struct {
		name             string
		osVersion        string
		wantMutationArgv []string
	}{
		{
			name:      "sle15-vendor-change-disabled",
			osVersion: "15.4",
			wantMutationArgv: []string{"zypper", "--non-interactive", "--no-refresh", "--root", "/target", "--no-gpg-checks",
				"dist-upgrade", "--auto-agree-with-licenses", "--from", "RepoA", "--from", "Repo B", "--no-allow-vendor-change", "--no-recommends"},
		},
		{
			name:      "sle11-vendor-change-unsupported",
			osVersion: "11.4",
			wantMutationArgv: []string{"zypper", "--non-interactive", "--no-refresh", "--root", "/target", "--no-gpg-checks",
				"dist-upgrade", "--auto-agree-with-licenses", "--from", "RepoA", "--from", "Repo B", "--no-recommends"},
		},
		{
			name:      "unparsable-release-is-below-gate",
			osVersion: "tumbleweed",
			wantMutationArgv: []string{"zypper", "--non-interactive", "--no-refresh", "--root", "/target", "--no-gpg-checks",
				"dist-upgrade", "--auto-agree-with-licenses", "--from", "RepoA", "--from", "Repo B", "--no-recommends"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &yumRecordingRunner{results: []process.CommandResult{{}, {}, {}}}
			rt := zypperUpgradeRuntime(runner, tc.osVersion)
			args := map[string]any{
				"refresh":        false,
				"root":           "/target",
				"skip_verify":    true,
				"dist_upgrade":   true,
				"fromrepo":       []string{"RepoA", "Repo B"},
				"novendorchange": true,
				"no_recommends":  true,
			}
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade", args)
			if err != nil || !reflect.DeepEqual(got, map[string]any{}) {
				t.Fatalf("got=%#v err=%v", got, err)
			}
			if len(runner.commands) != 3 {
				t.Fatalf("calls=%d argv=%v", len(runner.commands), zypperAllArgv(runner))
			}
			if argv := zypperCommandArgs(runner.commands[1]); !reflect.DeepEqual(argv, tc.wantMutationArgv) {
				t.Fatalf("mutation argv=%v want=%v", argv, tc.wantMutationArgv)
			}
		})
	}
}

func TestZypperUpgradeFromrepoUsesRepoForUpdate(t *testing.T) {
	runner := &yumRecordingRunner{results: []process.CommandResult{{}, {}, {}}}
	rt := zypperUpgradeRuntime(runner, "15")
	_, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade", map[string]any{
		"refresh": false, "fromrepo": []string{"Only"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"zypper", "--non-interactive", "--no-refresh", "update", "--auto-agree-with-licenses", "--repo", "Only"}
	if argv := zypperCommandArgs(runner.commands[1]); !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv=%v want=%v", argv, want)
	}
}

func TestZypperUpgradeRefreshForceQuirk(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      map[string]any
		wantFirst []string
	}{
		{
			name:      "omitted-root-keeps-force-default",
			args:      map[string]any{},
			wantFirst: []string{"zypper", "--non-interactive", "refresh", "--force"},
		},
		{
			name:      "root-moves-into-force-slot-and-refresh-stays-unrooted",
			args:      map[string]any{"root": "/target"},
			wantFirst: []string{"zypper", "--non-interactive", "refresh", "--force"},
		},
		{
			name:      "explicit-empty-root-disables-force",
			args:      map[string]any{"root": ""},
			wantFirst: []string{"zypper", "--non-interactive", "refresh"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &yumRecordingRunner{results: []process.CommandResult{{}, {}, {}, {}}}
			rt := zypperUpgradeRuntime(runner, "15")
			if _, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade", tc.args); err != nil {
				t.Fatal(err)
			}
			if len(runner.commands) != 4 {
				t.Fatalf("calls=%d argv=%v", len(runner.commands), zypperAllArgv(runner))
			}
			if argv := zypperCommandArgs(runner.commands[0]); !reflect.DeepEqual(argv, tc.wantFirst) {
				t.Fatalf("refresh argv=%v want=%v", argv, tc.wantFirst)
			}
		})
	}
}

func TestZypperUpgradeDryRunDistUpgradeDiscardsDebugSolver(t *testing.T) {
	runner := &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("discarded solver case output")},
		{},
		{Stdout: []byte("The following 2 packages will be upgraded:"), Stderr: []byte("warning: repository metadata expired")},
		{},
	}}
	rt := zypperUpgradeRuntime(runner, "15")
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade", map[string]any{
		"refresh": false, "dist_upgrade": true, "dryrun": true})
	if err != nil {
		t.Fatal(err)
	}
	wantString := "The following 2 packages will be upgraded:\nwarning: repository metadata expired"
	if got != wantString {
		t.Fatalf("dryrun got=%q want=%q", got, wantString)
	}
	wantArgv := [][]string{
		{"zypper", "--non-interactive", "--no-refresh", "dist-upgrade", "--auto-agree-with-licenses", "--dry-run", "--debug-solver"},
		{"rpm", "-qa", "--queryformat", zypperUpgradeQueryFormat},
		{"zypper", "--non-interactive", "--no-refresh", "dist-upgrade", "--auto-agree-with-licenses", "--dry-run"},
		{"rpm", "-qa", "--queryformat", zypperUpgradeQueryFormat},
	}
	if !reflect.DeepEqual(zypperAllArgv(runner), wantArgv) {
		t.Fatalf("argv=%v want=%v", zypperAllArgv(runner), wantArgv)
	}
}

func TestZypperUpgradeTargetKeysFromNameAndPkgs(t *testing.T) {
	for _, tc := range []struct {
		name        string
		args        map[string]any
		mutationIdx int
		targetStart int
		want        []string
	}{
		// normalize_name keeps an unknown arch-like suffix; the known osarch
		// suffix "foo.x86_64" would collapse to "foo" and dedupe.
		{name: "name-comma-split", args: map[string]any{"name": "foo,bar.vhk", "refresh": false}, mutationIdx: 1, targetStart: 5, want: []string{"foo", "bar.vhk"}},
		{name: "pkgs-precedence", args: map[string]any{"name": "ignored", "pkgs": []any{"chosen"}, "refresh": false}, mutationIdx: 1, targetStart: 5, want: []string{"chosen"}},
		{name: "pkgs-mapping-keys-only", args: map[string]any{"pkgs": []any{map[string]any{"vim": "9.0"}, "bare"}, "refresh": false}, mutationIdx: 1, targetStart: 5, want: []string{"vim", "bare"}},
		{name: "dryrun-still-forwards-targets", args: map[string]any{"name": "foo", "dryrun": true, "refresh": false}, mutationIdx: 1, targetStart: 6, want: []string{"foo"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &yumRecordingRunner{}
			rt := zypperUpgradeRuntime(runner, "15")
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade", tc.args)
			if err != nil {
				t.Fatalf("got=%#v err=%v", got, err)
			}
			if len(runner.commands) != 3 {
				t.Fatalf("calls=%d argv=%v", len(runner.commands), zypperAllArgv(runner))
			}
			argv := zypperCommandArgs(runner.commands[tc.mutationIdx])
			if !reflect.DeepEqual(argv[tc.targetStart:], tc.want) {
				t.Fatalf("targets=%v want=%v (argv=%v)", argv[tc.targetStart:], tc.want, argv)
			}
		})
	}
}

func TestZypperUpgradeDuplicatePkgsFailBeforeCommands(t *testing.T) {
	runner := &yumRecordingRunner{}
	rt := zypperUpgradeRuntime(runner, "15")
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade", map[string]any{
		"pkgs": []any{"demo", map[string]any{"demo": "1.0"}}, "refresh": false})
	if got != nil || err == nil || !strings.Contains(err.Error(), "duplicated packages names") || len(runner.commands) != 0 {
		t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperUpgradeExitCodeErrorInfoShape(t *testing.T) {
	oldList := []byte("foo_|-0_|-1_|-1_|-x86_64_|-(none)_|-0\n")
	for _, tc := range []struct {
		name       string
		retcode    int
		wantChange bool
	}{
		{"error-code-4", 4, true},
		{"warning-code-6-still-fails-upgrade", 6, true},
		{"patch-code-100-is-success", 100, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &yumRecordingRunner{results: []process.CommandResult{
				{Stdout: oldList},
				{ExitCode: tc.retcode, Stdout: []byte("out"), Stderr: []byte("err")},
				{},
			}}
			rt := zypperUpgradeRuntime(runner, "15")
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade", map[string]any{"refresh": false})
			changes := map[string]any{"foo": map[string]any{"old": "1-1", "new": ""}}
			if tc.wantChange {
				if !reflect.DeepEqual(got, changes) {
					t.Fatalf("changes=%#v want=%#v", got, changes)
				}
				var upgradeErr *zypperUpgradeError
				if !errors.As(err, &upgradeErr) || upgradeErr.Error() != "Problem encountered upgrading packages" {
					t.Fatalf("err=%v", err)
				}
				wantInfo := map[string]any{
					"changes": changes,
					"result":  map[string]any{"retcode": tc.retcode, "stdout": "out", "stderr": "err"},
				}
				if !reflect.DeepEqual(upgradeErr.Info(), wantInfo) {
					t.Fatalf("info=%#v want=%#v", upgradeErr.Info(), wantInfo)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, changes) {
				t.Fatalf("got=%#v err=%v", got, err)
			}
		})
	}
}

func TestZypperUpgradeDiffAttrShapes(t *testing.T) {
	// old: version 1 release 1; new: version 2 release 1. The bare-version
	// attributes differ, so both the string join and every attr shape report
	// the change. Install time 0 renders as absent install_date attributes.
	oldList := []byte("foo_|-0_|-1_|-1_|-x86_64_|-(none)_|-0\n")
	newList := []byte("foo_|-0_|-2_|-1_|-x86_64_|-(none)_|-0\n")
	for _, tc := range []struct {
		name string
		attr any
		all  bool
	}{
		{name: "attr-list", attr: []string{"version", "arch"}},
		{name: "attr-comma-string", attr: "version,arch"},
		{name: "attr-all-string", attr: "all", all: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &yumRecordingRunner{results: []process.CommandResult{
				{Stdout: oldList}, {}, {Stdout: newList}, {},
			}}
			rt := zypperUpgradeRuntime(runner, "15")
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade", map[string]any{
				"refresh": false, "diff_attr": tc.attr})
			if err != nil {
				t.Fatal(err)
			}
			oldAttrs := map[string]any{"version": "1", "arch": "x86_64"}
			newAttrs := map[string]any{"version": "2", "arch": "x86_64"}
			if tc.all {
				oldAttrs = map[string]any{"epoch": nil, "version": "1", "release": "1", "arch": "x86_64", "install_date": nil, "install_date_time_t": nil}
				newAttrs = map[string]any{"epoch": nil, "version": "2", "release": "1", "arch": "x86_64", "install_date": nil, "install_date_time_t": nil}
			}
			want := map[string]any{"foo": map[string]any{
				"old": []any{oldAttrs},
				"new": []any{newAttrs},
			}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got=%#v want=%#v", got, want)
			}
		})
	}
}

func TestZypperUpgradeDiffAttrUnknownNamesSilentlyDrop(t *testing.T) {
	runner := &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("foo_|-0_|-1_|-1_|-x86_64_|-(none)_|-0\n")},
		{},
		{Stdout: []byte("foo_|-0_|-2_|-1_|-x86_64_|-(none)_|-0\n")},
		{},
	}}
	rt := zypperUpgradeRuntime(runner, "15")
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade", map[string]any{
		"refresh": false, "diff_attr": []string{"bogus", "version"}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"foo": map[string]any{
		"old": []any{map[string]any{"version": "1", "arch": "x86_64"}},
		"new": []any{map[string]any{"version": "2", "arch": "x86_64"}},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v want=%#v", got, want)
	}
}

func TestZypperUpgradeTestModeAndBoundaries(t *testing.T) {
	// Process-wide test mode returns before refresh or any query.
	runner := &yumRecordingRunner{}
	rt := zypperUpgradeRuntime(runner, "15")
	rt.Options.Test = true
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 0 {
		t.Fatalf("test mode got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// A typed-nil runner fails closed.
	nilRunner := zypperUpgradeRuntime(nil, "15")
	if got, err := zypperLowpkgProvider().Zypper(context.Background(), nilRunner, "upgrade", map[string]any{"refresh": false}); got != nil || err == nil {
		t.Fatalf("nil runner got=%#v err=%v", got, err)
	}

	// Cancellation propagates before any command.
	runner = &yumRecordingRunner{}
	rt = zypperUpgradeRuntime(runner, "15")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := zypperLowpkgProvider().Zypper(ctx, rt, "upgrade", map[string]any{"refresh": false}); got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// Runner failure on the mutation aborts without the post-query.
	failure := errors.New("zypper gone")
	runner = &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("foo_|-0_|-1_|-1_|-x86_64_|-(none)_|-0\n")},
		{Err: failure, ExitCode: -1},
	}}
	rt = zypperUpgradeRuntime(runner, "15")
	if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade", map[string]any{"refresh": false}); got != nil || !errors.Is(err, failure) || len(runner.commands) != 2 {
		t.Fatalf("runner failure got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperUpgradeRejectsUnsupportedArgumentsBeforeCommands(t *testing.T) {
	for key, value := range map[string]any{
		"normalize": true, "sources": []any{"x.rpm"}, "kwargs": map[string]any{"x": true},
	} {
		runner := &yumRecordingRunner{}
		rt := zypperUpgradeRuntime(runner, "15")
		args := map[string]any{"refresh": false, key: value}
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade", args)
		var unsupported *runtime.UnsupportedError
		if got != nil || !errors.As(err, &unsupported) || len(runner.commands) != 0 {
			t.Fatalf("key=%q got=%#v err=%v calls=%d", key, got, err, len(runner.commands))
		}
	}
	runner := &yumRecordingRunner{}
	rt := zypperUpgradeRuntime(runner, "15")
	if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade", map[string]any{"pkgs": "not-a-list"}); got != nil || err == nil || len(runner.commands) != 0 {
		t.Fatalf("non-list pkgs got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}
