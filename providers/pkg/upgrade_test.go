package pkg

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type upgradeRecordingRunner struct {
	commands []process.Command
	results  []process.CommandResult
	after    func(int)
}

func (r *upgradeRecordingRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	call := len(r.commands)
	r.commands = append(r.commands, command)
	result := process.CommandResult{}
	if len(r.results) > 0 {
		result, r.results = r.results[0], r.results[1:]
	}
	if r.after != nil {
		r.after(call)
	}
	return result
}

type upgradeNoCallRunner struct{ calls int }

func (r *upgradeNoCallRunner) Run(context.Context, process.Command) process.CommandResult {
	r.calls++
	return process.CommandResult{}
}

func upgradeRuntime(manager string, runner process.Runner) *runtime.Runtime {
	return &runtime.Runtime{
		Facts: facts.ForTesting(facts.Overrides{
			Package: manager,
			OS:      &facts.OSFacts{Family: facts.FamilyRedHat},
			CPU:     &facts.CPUFacts{Arch: "x86_64"},
		}),
		Runner: runner,
	}
}

func upgradeRecord(name, epoch, version, release, arch, installTime string) string {
	return fmt.Sprintf("%s_|-%s_|-%s_|-%s_|-%s_|-(none)_|-%s\n", name, epoch, version, release, arch, installTime)
}

func upgradeArgv(commands []process.Command) [][]string {
	result := make([][]string, 0, len(commands))
	for _, command := range commands {
		result = append(result, append([]string{command.Name}, command.Args...))
	}
	return result
}

func assertUpgradeCommandsBounded(t *testing.T, commands []process.Command) {
	t.Helper()
	for i, command := range commands {
		if command.Shell || command.MaxStdoutBytes != yumUpgradeOutputLimit || command.MaxStderrBytes != yumUpgradeOutputLimit {
			t.Fatalf("command[%d] is not shell-free and bounded: %#v", i, command)
		}
	}
}

func directUpgrade(manager, function string, rt *runtime.Runtime, args map[string]any) (any, error) {
	return (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), rt, function, args)
}

func TestYumUpgradeDirectFlowOptionsTargetsAndInputImmutability(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			args := map[string]any{
				// A truthy pkgs list wins before source parse_targets inspects name.
				"name":            true,
				"pkgs":            []any{"foo.x86_64", map[string]any{"bar.i686": "9.9"}},
				"skip_verify":     true,
				"minimal":         true,
				"obsoletes":       false,
				"fromrepo":        "base",
				"enablerepo":      []string{"ignored"},
				"disableexcludes": "main",
				"branch":          "stable",
				"setopt":          []string{"a=1", "obsoletes=True"},
				"kwargs":          map[string]any{"security": true, "exclude": "kernel*"},
			}
			before := map[string]any{
				"name":            true,
				"pkgs":            []any{"foo.x86_64", map[string]any{"bar.i686": "9.9"}},
				"skip_verify":     true,
				"minimal":         true,
				"obsoletes":       false,
				"fromrepo":        "base",
				"enablerepo":      []string{"ignored"},
				"disableexcludes": "main",
				"branch":          "stable",
				"setopt":          []string{"a=1", "obsoletes=True"},
				"kwargs":          map[string]any{"security": true, "exclude": "kernel*"},
			}
			old := upgradeRecord("foo", "0", "1", "", "x86_64", "0") + upgradeRecord("bar", "0", "1", "", "i686", "0")
			newer := upgradeRecord("foo", "0", "2", "", "x86_64", "0") + upgradeRecord("bar", "0", "2", "", "i686", "0")
			runner := &upgradeRecordingRunner{results: []process.CommandResult{{}, {ExitCode: 100}, {Stdout: []byte(old)}, {}, {Stdout: []byte(newer)}}}
			got, err := directUpgrade(manager, "upgrade", upgradeRuntime(manager, runner), args)
			want := map[string]any{
				"foo":      map[string]any{"old": "1", "new": "2"},
				"bar.i686": map[string]any{"old": "1", "new": "2"},
			}
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) {
				t.Fatalf("got=%#v err=%v args=%#v", got, err, args)
			}
			setopts := []string{"--setopt=a=1", "--setopt=obsoletes=True"}
			action := "update-minimal"
			if manager != "yum" {
				setopts = []string{"--setopt=a=1", "--setopt=obsoletes=False"}
				action = "upgrade-minimal"
			}
			options := append([]string{"--disablerepo=*", "--enablerepo=base", "--disableexcludes=main", "--branch=stable"}, setopts...)
			refresh := append([]string{manager, "--quiet", "--assumeyes", "clean", "expire-cache"}, options...)
			check := append([]string{manager, "--quiet", "--assumeyes", "check-update"}, options...)
			transaction := append([]string{manager, "--quiet", "-y"}, options...)
			transaction = append(transaction, "--exclude=kernel*", "--security", "--nogpgcheck", action, "foo", "bar.i686")
			wantArgv := [][]string{
				refresh,
				check,
				{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", yumInstalledQueryFormat},
				transaction,
				{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", yumInstalledQueryFormat},
			}
			if actual := upgradeArgv(runner.commands); !reflect.DeepEqual(actual, wantArgv) {
				t.Fatalf("argv=%#v want=%#v", actual, wantArgv)
			}
			assertUpgradeCommandsBounded(t, runner.commands)
		})
	}
}

func TestYumUpgradeDefaultsUpdateAliasAndNoTarget(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		for _, tc := range []struct {
			name       string
			function   string
			args       map[string]any
			wantAction string
			wantTarget []string
		}{
			{"upgrade defaults", "upgrade", map[string]any{"name": "foo", "refresh": false}, "upgrade", []string{"foo"}},
			{"upgrade explicit false", "upgrade", map[string]any{"name": "foo.x86_64", "refresh": false, "skip_verify": false, "normalize": false, "minimal": false, "obsoletes": false}, "update", []string{"foo.x86_64"}},
			{"update alias default", "update", map[string]any{"name": "foo", "refresh": false}, "update", []string{"foo"}},
			{"update explicit obsoletes", "update", map[string]any{"name": "foo", "refresh": false, "obsoletes": true}, "upgrade", []string{"foo"}},
			{"full system no target", "upgrade", map[string]any{"refresh": false}, "upgrade", nil},
		} {
			t.Run(manager+"/"+tc.name, func(t *testing.T) {
				old := upgradeRecord("foo", "0", "1", "", "x86_64", "0")
				newer := upgradeRecord("foo", "0", "2", "", "x86_64", "0")
				runner := &upgradeRecordingRunner{results: []process.CommandResult{{Stdout: []byte(old)}, {}, {Stdout: []byte(newer)}}}
				got, err := directUpgrade(manager, tc.function, upgradeRuntime(manager, runner), tc.args)
				if err != nil || !reflect.DeepEqual(got, map[string]any{"foo": map[string]any{"old": "1", "new": "2"}}) {
					t.Fatalf("got=%#v err=%v", got, err)
				}
				action := tc.wantAction
				if manager != "yum" && action == "update" {
					action = "upgrade"
				}
				obsoletes := tc.function != "update"
				if value, present := tc.args["obsoletes"].(bool); present {
					obsoletes = value
				}
				transaction := []string{manager, "--quiet", "-y"}
				if manager != "yum" && !obsoletes {
					transaction = append(transaction, "--setopt=obsoletes=False")
				}
				transaction = append(transaction, action)
				transaction = append(transaction, tc.wantTarget...)
				wantArgv := [][]string{
					{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", yumInstalledQueryFormat},
					transaction,
					{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", yumInstalledQueryFormat},
				}
				if actual := upgradeArgv(runner.commands); !reflect.DeepEqual(actual, wantArgv) {
					t.Fatalf("argv=%#v want=%#v", actual, wantArgv)
				}
				assertUpgradeCommandsBounded(t, runner.commands)
			})
		}
	}
}

func TestYumUpgradeRefreshDBRHEL7Ordering(t *testing.T) {
	runner := &upgradeRecordingRunner{results: []process.CommandResult{
		{}, {},
		{Stdout: []byte(upgradeRecord("foo", "0", "1", "", "x86_64", "0"))},
		{},
		{Stdout: []byte(upgradeRecord("foo", "0", "2", "", "x86_64", "0"))},
	}}
	rt := upgradeRuntime("yum", runner)
	rt.Facts = facts.ForTesting(facts.Overrides{
		Package: "yum", OS: &facts.OSFacts{Family: facts.FamilyRedHat, Version: "7"}, CPU: &facts.CPUFacts{Arch: "x86_64"},
	})
	got, err := directUpgrade("yum", "upgrade", rt, map[string]any{"fromrepo": "base"})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"foo": map[string]any{"old": "1", "new": "2"}}) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	want := [][]string{
		{"yum", "--quiet", "--assumeyes", "clean", "expire-cache", "--disablerepo=*", "--enablerepo=base"},
		{"yum", "--quiet", "--assumeyes", "check-update", "--setopt=autocheck_running_kernel=false", "--disablerepo=*", "--enablerepo=base"},
		{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", yumInstalledQueryFormat},
		{"yum", "--quiet", "-y", "--disablerepo=*", "--enablerepo=base", "upgrade"},
		{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", yumInstalledQueryFormat},
	}
	if actual := upgradeArgv(runner.commands); !reflect.DeepEqual(actual, want) {
		t.Fatalf("argv=%#v want=%#v", actual, want)
	}
}

func TestYumUpgradeDiffAttrChangesAndCompletedNonzeroInfo(t *testing.T) {
	old := upgradeRecord("foo", "1", "1", "old", "x86_64", "1") + upgradeRecord("gone", "0", "3", "", "x86_64", "0")
	newer := upgradeRecord("foo", "1", "2", "new", "x86_64", "2") + upgradeRecord("added", "0", "4", "", "x86_64", "0")
	oldFoo := []map[string]any{{"epoch": "1", "version": "1", "release": "old", "arch": "x86_64"}}
	newFoo := []map[string]any{{"epoch": "1", "version": "2", "release": "new", "arch": "x86_64"}}
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager+"/diff", func(t *testing.T) {
			runner := &upgradeRecordingRunner{results: []process.CommandResult{{Stdout: []byte(old)}, {}, {Stdout: []byte(newer)}}}
			got, err := directUpgrade(manager, "upgrade", upgradeRuntime(manager, runner), map[string]any{"refresh": false, "diff_attr": "epoch,release"})
			want := map[string]any{
				"foo":   map[string]any{"old": oldFoo, "new": newFoo},
				"gone":  map[string]any{"old": []map[string]any{{"epoch": nil, "version": "3", "release": nil, "arch": "x86_64"}}, "new": ""},
				"added": map[string]any{"old": "", "new": []map[string]any{{"epoch": nil, "version": "4", "release": nil, "arch": "x86_64"}}},
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
			}
			assertUpgradeCommandsBounded(t, runner.commands)
		})

		t.Run(manager+"/nonzero retains changes", func(t *testing.T) {
			runner := &upgradeRecordingRunner{results: []process.CommandResult{{Stdout: []byte(upgradeRecord("foo", "0", "1", "", "x86_64", "0"))}, {ExitCode: 9, Stdout: []byte("partial"), Stderr: []byte("failed")}, {Stdout: []byte(upgradeRecord("foo", "0", "2", "", "x86_64", "0"))}}}
			got, err := directUpgrade(manager, "upgrade", upgradeRuntime(manager, runner), map[string]any{"refresh": false})
			want := map[string]any{"foo": map[string]any{"old": "1", "new": "2"}}
			problem := &yumUpgradeError{}
			if !errors.As(err, &problem) || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(problem.Info(), map[string]any{"changes": want, "result": map[string]any{"retcode": 9, "stdout": "partial", "stderr": "failed"}}) {
				t.Fatalf("got=%#v err=%#v info=%#v", got, err, problem.Info())
			}
			if len(runner.commands) != 3 {
				t.Fatalf("completed nonzero skipped source post-query: %#v", runner.commands)
			}
		})
	}
}

func TestYumUpgradeDiffAttrAllShapesAndValidation(t *testing.T) {
	old := upgradeRecord("foo", "1", "1", "old", "x86_64", "1")
	newer := upgradeRecord("foo", "2", "2", "new", "x86_64", "2")
	allOld := []map[string]any{{
		"epoch": "1", "version": "1", "release": "old", "arch": "x86_64",
		"install_date": "1970-01-01T00:00:01+00:00Z", "install_date_time_t": int64(1),
	}}
	allNew := []map[string]any{{
		"epoch": "2", "version": "2", "release": "new", "arch": "x86_64",
		"install_date": "1970-01-01T00:00:02+00:00Z", "install_date_time_t": int64(2),
	}}
	subsetOld := []map[string]any{{"epoch": "1", "version": "1", "release": "old", "arch": "x86_64"}}
	subsetNew := []map[string]any{{"epoch": "2", "version": "2", "release": "new", "arch": "x86_64"}}
	cases := []struct {
		name     string
		diffAttr any
		supplied bool
		want     map[string]any
		wantErr  bool
	}{
		{
			name: "omitted", want: map[string]any{
				"foo": map[string]any{"old": "1:1-old", "new": "2:2-new"},
			},
		},
		{
			name: "scalar all", diffAttr: "all", supplied: true, want: map[string]any{
				"foo": map[string]any{"old": allOld, "new": allNew},
			},
		},
		{
			name: "structured string list all", diffAttr: []string{"all"}, supplied: true, want: map[string]any{
				"foo": map[string]any{"old": allOld, "new": allNew},
			},
		},
		{
			name: "structured interface list all", diffAttr: []any{"all"}, supplied: true, want: map[string]any{
				"foo": map[string]any{"old": allOld, "new": allNew},
			},
		},
		{
			name: "valid string list subset", diffAttr: []string{"epoch", "release"}, supplied: true, want: map[string]any{
				"foo": map[string]any{"old": subsetOld, "new": subsetNew},
			},
		},
		{
			name: "valid interface list subset", diffAttr: []any{"epoch", "release"}, supplied: true, want: map[string]any{
				"foo": map[string]any{"old": subsetOld, "new": subsetNew},
			},
		},
		{name: "unknown scalar", diffAttr: "epoch,unknown", supplied: true, wantErr: true},
		{name: "unknown list", diffAttr: []string{"epoch", "unknown"}, supplied: true, wantErr: true},
		{name: "invalid list element type", diffAttr: []any{"epoch", 1}, supplied: true, wantErr: true},
		{name: "invalid type", diffAttr: 1, supplied: true, wantErr: true},
	}
	clone := func(value any) any {
		switch value := value.(type) {
		case []string:
			return append([]string(nil), value...)
		case []any:
			return append([]any(nil), value...)
		default:
			return value
		}
	}
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		for _, tc := range cases {
			t.Run(manager+"/"+tc.name, func(t *testing.T) {
				args := map[string]any{"name": "foo", "refresh": false}
				before := map[string]any{"name": "foo", "refresh": false}
				if tc.supplied {
					args["diff_attr"] = tc.diffAttr
					before["diff_attr"] = clone(tc.diffAttr)
				}
				runner := &upgradeRecordingRunner{}
				if !tc.wantErr {
					runner.results = []process.CommandResult{{Stdout: []byte(old)}, {}, {Stdout: []byte(newer)}}
				}
				got, err := directUpgrade(manager, "upgrade", upgradeRuntime(manager, runner), args)
				if tc.wantErr {
					if got != nil || err == nil || len(runner.commands) != 0 || !reflect.DeepEqual(args, before) {
						t.Fatalf("got=%#v err=%v commands=%#v args=%#v", got, err, runner.commands, args)
					}
					return
				}
				wantArgv := [][]string{
					{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", yumInstalledQueryFormat},
					{manager, "--quiet", "-y", "upgrade", "foo"},
					{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", yumInstalledQueryFormat},
				}
				if err != nil || !reflect.DeepEqual(got, tc.want) || !reflect.DeepEqual(upgradeArgv(runner.commands), wantArgv) || !reflect.DeepEqual(args, before) {
					t.Fatalf("got=%#v err=%v argv=%#v args=%#v", got, err, upgradeArgv(runner.commands), args)
				}
			})
		}
	}
}

func TestYumUpgradeFailureCancellationBoundsAndValidationStopBeforeMutation(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		for _, tc := range []struct {
			name   string
			result process.CommandResult
			check  func(error) bool
		}{
			{"runner error", process.CommandResult{Err: errors.New("runner failed")}, func(err error) bool { return err != nil && err.Error() == "runner failed" }},
			{"truncated", process.CommandResult{StdoutTruncated: true}, func(err error) bool { return errors.Is(err, process.ErrOutputLimit) }},
			{"oversized", process.CommandResult{Stdout: make([]byte, yumUpgradeOutputLimit+1)}, func(err error) bool { return errors.Is(err, process.ErrOutputLimit) }},
		} {
			t.Run(manager+"/"+tc.name, func(t *testing.T) {
				runner := &upgradeRecordingRunner{results: []process.CommandResult{{Stdout: []byte(upgradeRecord("foo", "0", "1", "", "x86_64", "0"))}, tc.result, {Stdout: []byte("post-query-must-not-run")}}}
				got, err := directUpgrade(manager, "upgrade", upgradeRuntime(manager, runner), map[string]any{"refresh": false})
				if got != nil || !tc.check(err) || len(runner.commands) != 2 {
					t.Fatalf("got=%#v err=%v commands=%#v", got, err, upgradeArgv(runner.commands))
				}
				assertUpgradeCommandsBounded(t, runner.commands)
			})
		}

		t.Run(manager+"/canceled after transaction", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runner := &upgradeRecordingRunner{results: []process.CommandResult{{Stdout: []byte(upgradeRecord("foo", "0", "1", "", "x86_64", "0"))}, {}, {Stdout: []byte("post-query-must-not-run")}}, after: func(call int) {
				if call == 1 {
					cancel()
				}
			}}
			got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(ctx, upgradeRuntime(manager, runner), "upgrade", map[string]any{"refresh": false})
			if got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 2 {
				t.Fatalf("got=%#v err=%v commands=%#v", got, err, upgradeArgv(runner.commands))
			}
		})

		for _, args := range []map[string]any{
			{"name": "foo", "refresh": false, "pkgs": "not-a-list"},
			{"name": "foo", "refresh": "false"},
			{"name": "foo", "refresh": false, "diff_attr": "unsupported"},
			{"name": "foo", "refresh": false, "setopt": []any{1}},
			{"name": "foo", "refresh": false, "kwargs": map[string]any{"security": false}},
			{"name": "foo", "refresh": false, "kwargs": map[string]any{"repo": "base"}},
			{"name": "foo", "refresh": false, "unsafe": 1},
		} {
			runner := &upgradeNoCallRunner{}
			got, err := directUpgrade(manager, "upgrade", upgradeRuntime(manager, runner), args)
			if got != nil || err == nil || runner.calls != 0 {
				t.Fatalf("args=%#v got=%#v err=%v calls=%d", args, got, err, runner.calls)
			}
		}

		t.Run(manager+"/test mode", func(t *testing.T) {
			runner := &upgradeNoCallRunner{}
			rt := upgradeRuntime(manager, runner)
			rt.Options.Test = true
			got, err := directUpgrade(manager, "update", rt, map[string]any{"name": "foo", "refresh": true})
			if err != nil || !reflect.DeepEqual(got, map[string]any{}) || runner.calls != 0 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, runner.calls)
			}
		})
	}
}

func TestYumUpgradeFailsClosedWithoutRuntimeFactsOrRunner(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		for _, function := range []string{"upgrade", "update"} {
			t.Run(manager+"/"+function, func(t *testing.T) {
				noCall := &upgradeNoCallRunner{}
				validFacts := facts.ForTesting(facts.Overrides{
					Package: manager,
					OS:      &facts.OSFacts{Family: facts.FamilyRedHat},
					CPU:     &facts.CPUFacts{Arch: "x86_64"},
				})
				emptyArch := facts.ForTesting(facts.Overrides{
					Package: manager,
					OS:      &facts.OSFacts{Family: facts.FamilyRedHat},
				})
				var typedNil *upgradeNoCallRunner
				cases := []struct {
					name   string
					rt     *runtime.Runtime
					runner *upgradeNoCallRunner
				}{
					{"nil runtime", nil, nil},
					{"nil facts", &runtime.Runtime{Runner: noCall}, noCall},
					{"empty cpu architecture", &runtime.Runtime{Facts: emptyArch, Runner: noCall}, noCall},
					{"nil runner", &runtime.Runtime{Facts: validFacts}, nil},
					{"typed nil runner", &runtime.Runtime{Facts: validFacts, Runner: typedNil}, nil},
				}
				for _, tc := range cases {
					t.Run(tc.name, func(t *testing.T) {
						got, err := directUpgrade(manager, function, tc.rt, map[string]any{"refresh": false})
						if got != nil || err == nil {
							t.Fatalf("got=%#v err=%v", got, err)
						}
						if tc.runner != nil && tc.runner.calls != 0 {
							t.Fatalf("runner calls=%d", tc.runner.calls)
						}
					})
				}
			})
		}
	}
}

func TestYumUpgradeRefreshCheckUpdateSemantics(t *testing.T) {
	falseValue, trueValue := false, true
	cases := []struct {
		name        string
		refresh     bool
		checkUpdate *bool
		wantCheck   bool
	}{
		{"refresh omitted check_update", true, nil, true},
		{"refresh explicit check_update true", true, &trueValue, true},
		{"refresh explicit check_update false", true, &falseValue, false},
		{"no refresh omitted check_update", false, nil, false},
		{"no refresh explicit check_update true", false, &trueValue, false},
		{"no refresh explicit check_update false", false, &falseValue, false},
	}
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		for _, function := range []string{"upgrade", "update"} {
			for _, tc := range cases {
				t.Run(manager+"/"+function+"/"+tc.name, func(t *testing.T) {
					args := map[string]any{"refresh": tc.refresh}
					if tc.checkUpdate != nil {
						args["check_update"] = *tc.checkUpdate
					}
					results := []process.CommandResult{}
					if tc.refresh {
						results = append(results, process.CommandResult{})
						if tc.wantCheck {
							results = append(results, process.CommandResult{})
						}
					}
					results = append(results,
						process.CommandResult{Stdout: []byte(upgradeRecord("foo", "0", "1", "", "x86_64", "0"))},
						process.CommandResult{},
						process.CommandResult{Stdout: []byte(upgradeRecord("foo", "0", "2", "", "x86_64", "0"))},
					)
					runner := &upgradeRecordingRunner{results: results}
					got, err := directUpgrade(manager, function, upgradeRuntime(manager, runner), args)
					if err != nil || !reflect.DeepEqual(got, map[string]any{"foo": map[string]any{"old": "1", "new": "2"}}) {
						t.Fatalf("got=%#v err=%v", got, err)
					}
					transaction := []string{manager, "--quiet", "-y"}
					if function == "update" && manager != "yum" {
						transaction = append(transaction, "--setopt=obsoletes=False")
					}
					if function == "update" && manager == "yum" {
						transaction = append(transaction, "update")
					} else {
						transaction = append(transaction, "upgrade")
					}
					refreshOptions := []string{}
					if function == "update" && manager != "yum" {
						refreshOptions = []string{"--setopt=obsoletes=False"}
					}
					want := [][]string{}
					if tc.refresh {
						want = append(want, append([]string{manager, "--quiet", "--assumeyes", "clean", "expire-cache"}, refreshOptions...))
						if tc.wantCheck {
							want = append(want, append([]string{manager, "--quiet", "--assumeyes", "check-update"}, refreshOptions...))
						}
					}
					want = append(want,
						[]string{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", yumInstalledQueryFormat},
						transaction,
						[]string{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", yumInstalledQueryFormat},
					)
					if actual := upgradeArgv(runner.commands); !reflect.DeepEqual(actual, want) {
						t.Fatalf("argv=%#v want=%#v", actual, want)
					}
					for _, argv := range upgradeArgv(runner.commands) {
						for _, arg := range argv {
							if arg == "--check_update" || strings.HasPrefix(arg, "--check_update=") {
								t.Fatalf("check_update leaked into argv=%#v", argv)
							}
						}
					}
				})
			}
		}
	}
}

func TestYumUpgradeRHEL7WorkaroundOnlyOnCheckUpdate(t *testing.T) {
	checkUpdate := false
	runner := &upgradeRecordingRunner{results: []process.CommandResult{
		{},
		{Stdout: []byte(upgradeRecord("foo", "0", "1", "", "x86_64", "0"))},
		{},
		{Stdout: []byte(upgradeRecord("foo", "0", "2", "", "x86_64", "0"))},
	}}
	rt := upgradeRuntime("yum", runner)
	rt.Facts = facts.ForTesting(facts.Overrides{
		Package: "yum", OS: &facts.OSFacts{Family: facts.FamilyRedHat, Version: "7"}, CPU: &facts.CPUFacts{Arch: "x86_64"},
	})
	if _, err := directUpgrade("yum", "update", rt, map[string]any{"check_update": checkUpdate}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"yum", "--quiet", "--assumeyes", "clean", "expire-cache"},
		{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", yumInstalledQueryFormat},
		{"yum", "--quiet", "-y", "update"},
		{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", yumInstalledQueryFormat},
	}
	if actual := upgradeArgv(runner.commands); !reflect.DeepEqual(actual, want) {
		t.Fatalf("argv=%#v want=%#v", actual, want)
	}
}
