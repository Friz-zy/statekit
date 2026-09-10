package pkg

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
)

const zypperPurgePTFFormat = "%{NAME}: [%{PROVIDES} ]\\n"

func zypperPurgeListRows(names ...string) []byte {
	var rows strings.Builder
	for _, name := range names {
		fmt.Fprintf(&rows, "%s_|-0_|-1_|-1_|-x86_64_|-(none)_|-0\n", name)
	}
	return []byte(rows.String())
}

func TestZypperPurgeTargetMatchingMatrix(t *testing.T) {
	oldSingle := zypperPurgeListRows("foo", "baz")
	multi := []byte("bar_|-0_|-2_|-1_|-x86_64_|-(none)_|-0\nbar_|-0_|-3_|-1_|-x86_64_|-(none)_|-0\n")
	for _, tc := range []struct {
		name        string
		old         []byte
		new         []byte
		args        map[string]any
		wantPtfArgv []string
		wantTargets []string
		want        map[string]any
	}{
		{
			name:        "version-match-appends-name-version",
			old:         oldSingle,
			new:         []byte(""),
			args:        map[string]any{"pkgs": []any{map[string]any{"foo": "1-1"}, map[string]any{"baz": "1-1"}}},
			wantPtfArgv: []string{"foo", "baz"},
			wantTargets: []string{"foo-1-1", "baz-1-1"},
			want: map[string]any{
				"foo": map[string]any{"old": "1-1", "new": ""},
				"baz": map[string]any{"old": "1-1", "new": ""},
			},
		},
		{
			name:        "multi-version-target-removes-one-version",
			old:         multi,
			new:         []byte("bar_|-0_|-2_|-1_|-x86_64_|-(none)_|-0\n"),
			args:        map[string]any{"pkgs": []any{map[string]any{"bar": "3-1"}}},
			wantPtfArgv: []string{"bar"},
			wantTargets: []string{"bar-3-1"},
			want:        map[string]any{"bar": map[string]any{"old": "2-1,3-1", "new": "2-1"}},
		},
		{
			name:        "version-mismatch-drops-target",
			old:         oldSingle,
			new:         oldSingle,
			args:        map[string]any{"pkgs": []any{map[string]any{"foo": "9-9"}}},
			wantPtfArgv: []string{"foo"},
			wantTargets: nil,
			want:        map[string]any{},
		},
		{
			name:        "bare-target-requires-installed",
			old:         oldSingle,
			new:         zypperPurgeListRows("foo"),
			args:        map[string]any{"pkgs": []any{"baz", "missing"}},
			wantPtfArgv: []string{"baz", "missing"},
			wantTargets: []string{"baz"},
			want:        map[string]any{"baz": map[string]any{"old": "1-1", "new": ""}},
		},
		{
			name:        "mapping-with-nil-version-is-bare",
			old:         oldSingle,
			new:         zypperPurgeListRows("foo"),
			args:        map[string]any{"pkgs": []any{map[string]any{"baz": nil}}},
			wantPtfArgv: []string{"baz"},
			wantTargets: []string{"baz"},
			want:        map[string]any{"baz": map[string]any{"old": "1-1", "new": ""}},
		},
		{
			name:        "name-is-comma-split",
			old:         oldSingle,
			new:         []byte(""),
			args:        map[string]any{"name": "baz,foo"},
			wantPtfArgv: []string{"baz", "foo"},
			wantTargets: []string{"baz", "foo"},
			want: map[string]any{
				"foo": map[string]any{"old": "1-1", "new": ""},
				"baz": map[string]any{"old": "1-1", "new": ""},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &yumRecordingRunner{results: []process.CommandResult{
				{Stdout: []byte("")}, // ptf query: no ptf packages
				{Stdout: tc.old},
				{}, // remove mutation
				{Stdout: tc.new},
			}}
			rt := zypperUpgradeRuntime(runner, "15")
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "purge", tc.args)
			if err != nil {
				t.Fatalf("got=%#v err=%v", got, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%#v want=%#v", got, tc.want)
			}
			ptf := append([]string{"rpm", "-q", "--qf", zypperPurgePTFFormat}, tc.wantPtfArgv...)
			mutation := []string{"zypper", "--non-interactive", "--no-refresh", "remove"}
			mutation = append(mutation, tc.wantTargets...)
			wantArgv := [][]string{
				ptf,
				{"rpm", "-qa", "--queryformat", zypperUpgradeQueryFormat},
				mutation,
				{"rpm", "-qa", "--queryformat", zypperUpgradeQueryFormat},
			}
			if len(tc.wantTargets) == 0 {
				// No targets and no ptf packages return before any zypper call.
				wantArgv = wantArgv[:2]
			}
			if !reflect.DeepEqual(zypperAllArgv(runner), wantArgv) {
				t.Fatalf("argv=\n%v\nwant=\n%v", zypperAllArgv(runner), wantArgv)
			}
		})
	}
}

func TestZypperPurgePTFSkipAndRemoveptfBatches(t *testing.T) {
	oldList := zypperPurgeListRows("plain", "ptfpkg")
	runner := &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("ptfpkg: ptf() = 1.1\nplain: plain() = 1\n")},
		{Stdout: oldList},
		{},
		{},
		{Stdout: []byte("")},
	}}
	rt := zypperUpgradeRuntime(runner, "15")
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "purge", map[string]any{
		"root": "/target", "pkgs": []any{"ptfpkg", "plain"}})
	want := map[string]any{
		"plain":  map[string]any{"old": "1-1", "new": ""},
		"ptfpkg": map[string]any{"old": "1-1", "new": ""},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
	}
	wantArgv := [][]string{
		{"rpm", "--root", "/target", "-q", "--qf", zypperPurgePTFFormat, "ptfpkg", "plain"},
		{"rpm", "--root", "/target", "-qa", "--queryformat", zypperUpgradeQueryFormat},
		{"zypper", "--non-interactive", "--no-refresh", "--root", "/target", "remove", "plain"},
		{"zypper", "--non-interactive", "--no-refresh", "--root", "/target", "removeptf", "--allow-downgrade", "ptfpkg"},
		{"rpm", "--root", "/target", "-qa", "--queryformat", zypperUpgradeQueryFormat},
	}
	if !reflect.DeepEqual(zypperAllArgv(runner), wantArgv) {
		t.Fatalf("argv=%v want=%v", zypperAllArgv(runner), wantArgv)
	}
}

func TestZypperPurgeBatchBoundary500(t *testing.T) {
	const total = 501
	names := make([]string, total)
	for i := range names {
		names[i] = fmt.Sprintf("p%04d", i)
	}
	records := zypperPurgeListRows(names...)
	runner := &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("")},
		{Stdout: records},
		{},
		{},
		{Stdout: []byte("")},
	}}
	rt := zypperUpgradeRuntime(runner, "15")
	pkgs := make([]any, total)
	for i, name := range names {
		pkgs[i] = name
	}
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "purge", map[string]any{"pkgs": pkgs})
	if err != nil {
		t.Fatal(err)
	}
	changes, ok := got.(map[string]any)
	if !ok || len(changes) != total {
		t.Fatalf("changes=%d", len(changes))
	}
	if len(runner.commands) != 5 {
		t.Fatalf("calls=%d", len(runner.commands))
	}
	first := zypperCommandArgs(runner.commands[2])
	second := zypperCommandArgs(runner.commands[3])
	if first[3] != "remove" || len(first) != 4+500 {
		t.Fatalf("first batch len=%d argv0-4=%v", len(first), first[:4])
	}
	if second[3] != "remove" || len(second) != 4+1 || second[4] != names[500] {
		t.Fatalf("second batch=%v", second)
	}
}

func TestZypperPurgeErrorStopsBatchingWithoutPostQuery(t *testing.T) {
	const total = 501
	names := make([]string, total)
	for i := range names {
		names[i] = fmt.Sprintf("p%04d", i)
	}
	records := zypperPurgeListRows(names...)
	runner := &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("")},
		{Stdout: records},
		{ExitCode: 4, Stderr: []byte("failure")},
	}}
	rt := zypperUpgradeRuntime(runner, "15")
	pkgs := make([]any, total)
	for i, name := range names {
		pkgs[i] = name
	}
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "purge", map[string]any{"pkgs": pkgs})
	var exitErr *zypperExitCodeError
	if got != nil || !errors.As(err, &exitErr) || exitErr.exitCode != 4 {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	// The failing batch stops the loop: no second remove, no new snapshot.
	if len(runner.commands) != 3 {
		t.Fatalf("calls=%d argv=%v", len(runner.commands), zypperAllArgv(runner))
	}

	// Warning exit code 6 is tolerated by the call wrapper: batching and the
	// post-removal snapshot proceed.
	runner = &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("")},
		{Stdout: zypperPurgeListRows("foo")},
		{ExitCode: 6},
		{Stdout: []byte("")},
	}}
	rt = zypperUpgradeRuntime(runner, "15")
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "purge", map[string]any{"pkgs": []any{"foo"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"foo": map[string]any{"old": "1-1", "new": ""}}) {
		t.Fatalf("warning got=%#v err=%v", got, err)
	}
	if len(runner.commands) != 4 {
		t.Fatalf("warning calls=%d", len(runner.commands))
	}
}

func TestZypperPurgeIncludesPatternTargets(t *testing.T) {
	patternsXML := `<stream><solvable name="base" status="installed" summary="Base"/></stream>`
	infoText := "Information for package base:\nName: base\nVersion: 2019.1\nArch: noarch\nStatus: not installed\n"
	patternsCapability := "pattern() = base\n"
	runner := &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("")},                 // ptf query
		{Stdout: zypperPurgeListRows("vim")}, // rpm -qa
		{Stdout: []byte(patternsCapability)}, // rpm --provides pattern()
		{Stdout: []byte(patternsXML)},        // zypper se -t pattern (visible)
		{Stdout: []byte(infoText)},           // zypper info -t package pattern:base
		{},                                   // remove
		{Stdout: []byte("")},                 // rpm -qa (vim gone)
		{Stdout: []byte(patternsCapability)},
		{Stdout: []byte(patternsXML)},
		{Stdout: []byte(infoText)},
	}}
	rt := zypperUpgradeRuntime(runner, "15")
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "purge", map[string]any{
		"root": "/target", "pkgs": []any{"pattern:base", "vim"}})
	if err != nil {
		t.Fatal(err)
	}
	// pattern:base stays installed in the new snapshot, so only vim changes.
	want := map[string]any{"vim": map[string]any{"old": "1-1", "new": ""}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v want=%#v", got, want)
	}
	wantArgv := [][]string{
		{"rpm", "--root", "/target", "-q", "--qf", zypperPurgePTFFormat, "pattern:base", "vim"},
		{"rpm", "--root", "/target", "-qa", "--queryformat", zypperUpgradeQueryFormat},
		{"rpm", "--root", "/target", "-q", "--provides", "--whatprovides", "pattern()"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "se", "-t", "pattern"},
		{"zypper", "--non-interactive", "--no-refresh", "--root", "/target", "info", "-t", "package", "pattern:base"},
		{"zypper", "--non-interactive", "--no-refresh", "--root", "/target", "remove", "pattern:base", "vim"},
		{"rpm", "--root", "/target", "-qa", "--queryformat", zypperUpgradeQueryFormat},
		{"rpm", "--root", "/target", "-q", "--provides", "--whatprovides", "pattern()"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "se", "-t", "pattern"},
		{"zypper", "--non-interactive", "--no-refresh", "--root", "/target", "info", "-t", "package", "pattern:base"},
	}
	if !reflect.DeepEqual(zypperAllArgv(runner), wantArgv) {
		t.Fatalf("argv=\n%v\nwant=\n%v", zypperAllArgv(runner), wantArgv)
	}
}

func TestZypperPurgeEmptyInputAndBoundaries(t *testing.T) {
	// No name and no pkgs: parse_targets yields nothing and no command runs.
	runner := &yumRecordingRunner{}
	rt := zypperUpgradeRuntime(runner, "15")
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "purge", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 0 {
		t.Fatalf("empty got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// Version-mismatched targets still run the ptf query and old snapshot
	// before returning {}, matching the source order.
	runner = &yumRecordingRunner{results: []process.CommandResult{{}, {}}}
	rt = zypperUpgradeRuntime(runner, "15")
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "purge", map[string]any{
		"pkgs": []any{map[string]any{"ghost": "1.0"}}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 2 {
		t.Fatalf("mismatch got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// Cancellation propagates before the first command.
	runner = &yumRecordingRunner{}
	rt = zypperUpgradeRuntime(runner, "15")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := zypperLowpkgProvider().Zypper(ctx, rt, "purge", map[string]any{"name": "vim"}); got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// Unsupported arguments fail before any command.
	runner = &yumRecordingRunner{}
	rt = zypperUpgradeRuntime(runner, "15")
	if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "purge", map[string]any{"name": "vim", "refresh": true}); got != nil || err == nil || len(runner.commands) != 0 {
		t.Fatalf("unsupported got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperFindTypesPrefixes(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkgs []string
		want []string
	}{
		{"mixed", []string{"pattern:base", "product:SLES", "patch:opensuse", "vim"}, []string{"patch", "pattern", "product"}},
		{"dedupe-and-sort", []string{"patch:b", "patch:a", "pattern:x"}, []string{"patch", "pattern"}},
		{"empty-prefix-kept", []string{":weird", "vim"}, []string{""}},
		{"none", []string{"vim", "emacs"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := zypperFindTypes(tc.pkgs); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%v want=%v", got, tc.want)
			}
		})
	}
}
