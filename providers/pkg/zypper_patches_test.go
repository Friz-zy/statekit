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

const zypperPatchesXML = `<stream><search-result><solvable-list><solvable name="SUSE-SLE-Module-1" summary="Security update" status="installed" kind="patch"/><solvable name="SUSE-SLE-Module-2" summary="Recommended update" status="not-installed" kind="patch"/><solvable name="SUSE-SLE-Module-3" summary="Case matters" status="Installed" kind="patch"/><solvable name="SUSE-SLE-Module-1" summary="Last wins" status="not-installed" kind="patch"/></solvable-list></search-result></stream>`

func TestZypperPatchesVisibleQueryUsesSourceArgvAndExactStatus(t *testing.T) {
	root := "/target"
	refresh := false
	args := map[string]any{"refresh": &refresh, "root": &root}
	before := map[string]any{"refresh": &refresh, "root": &root}
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(zypperPatchesXML)})

	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_patches", args)
	want := map[string]any{
		"SUSE-SLE-Module-1": map[string]any{"installed": false, "summary": "Last wins"},
		"SUSE-SLE-Module-2": map[string]any{"installed": false, "summary": "Recommended update"},
		"SUSE-SLE-Module-3": map[string]any{"installed": false, "summary": "Case matters"},
	}
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) {
		t.Fatalf("got=%#v err=%v args=%#v", got, err, args)
	}
	wantArgv := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "se", "-t", "patch"}
	if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), wantArgv) {
		t.Fatalf("argv=%#v want=%#v", runner.commands, wantArgv)
	}
	assertZypperPatternsCommand(t, runner.commands[0], true)
}

func TestZypperListInstalledPatchesKeepsOnlyInstalledStatus(t *testing.T) {
	root := "/target"
	args := map[string]any{"root": &root}
	before := map[string]any{"root": &root}
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(zypperPatchesXML)})

	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_installed_patches", args)
	// The installed-only variant reuses the last-record-wins duplicate rule:
	// the second SUSE-SLE-Module-1 record (not-installed) replaces the
	// installed one, so nothing survives the filter.
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || !reflect.DeepEqual(args, before) {
		t.Fatalf("got=%#v err=%v args=%#v", got, err, args)
	}
	wantArgv := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "se", "-t", "patch"}
	if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), wantArgv) {
		t.Fatalf("argv=%#v want=%#v", runner.commands, wantArgv)
	}

	// A patch whose last record stays installed is retained.
	installedXML := `<stream><solvable-list><solvable name="SUSE-SLE-1" summary="Sec" status="installed" kind="patch"/><solvable name="SUSE-SLE-2" summary="Rec" status="not-installed" kind="patch"/></solvable-list></stream>`
	rt, runner = zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(installedXML)})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_installed_patches", map[string]any{})
	want := map[string]any{"SUSE-SLE-1": map[string]any{"installed": true, "summary": "Sec"}}
	if err != nil || !reflect.DeepEqual(got, want) || len(runner.commands) != 1 {
		t.Fatalf("retained got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperPatchesEmptyResultStaysEmptyMap(t *testing.T) {
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(`<stream/>`)})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_patches", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 1 {
		t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperPatchesRefreshRootPositionAndQueryRoot(t *testing.T) {
	root := "/target"
	refresh := true
	rt, runner := zypperLowpkgRuntime(
		process.CommandResult{},
		process.CommandResult{Stdout: []byte(`<stream/>`)},
	)
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_patches", map[string]any{"refresh": &refresh, "root": &root})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 2 {
		t.Fatalf("refresh got=%#v err=%v commands=%#v", got, err, runner.commands)
	}
	want := [][]string{
		{"zypper", "--non-interactive", "refresh", "--force"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "se", "-t", "patch"},
	}
	for i, command := range runner.commands {
		if !reflect.DeepEqual(zypperCommandArgs(command), want[i]) {
			t.Fatalf("argv[%d]=%v want=%v", i, zypperCommandArgs(command), want[i])
		}
		assertZypperPatternsCommand(t, command, i == 1)
	}

	emptyRoot := ""
	rt, runner = zypperLowpkgRuntime(process.CommandResult{}, process.CommandResult{Stdout: []byte(`<stream/>`)})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_patches", map[string]any{"refresh": true, "root": &emptyRoot})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 2 {
		t.Fatalf("empty-root got=%#v err=%v commands=%#v", got, err, runner.commands)
	}
	if want := []string{"zypper", "--non-interactive", "refresh"}; !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), want) {
		t.Fatalf("empty-root refresh argv=%#v want=%#v", zypperCommandArgs(runner.commands[0]), want)
	}

	rt, runner = zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(`<stream/>`)})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_installed_patches", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 1 {
		t.Fatalf("default got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperPatchesRejectUnsupportedArgumentsBeforeRunner(t *testing.T) {
	for _, tc := range []struct {
		function string
		args     map[string]any
	}{
		{"list_patches", map[string]any{"refresh": "yes"}},
		{"list_installed_patches", map[string]any{"refresh": zypperBoolPtr(true)}},
		{"services_need_restart", map[string]any{"other": true}},
	} {
		rt, runner := zypperLowpkgRuntime()
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, tc.function, tc.args)
		if got != nil || err == nil || len(runner.commands) != 0 {
			t.Fatalf("%s got=%#v err=%v calls=%d", tc.function, got, err, len(runner.commands))
		}
	}
	rt, runner := zypperLowpkgRuntime()
	if _, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_patches", map[string]any{"root": 7}); err == nil || len(runner.commands) != 0 {
		t.Fatalf("bad root type err=%v calls=%d", err, len(runner.commands))
	}
}

func TestZypperServicesNeedRestartSplitsWhitespace(t *testing.T) {
	root := "/target"
	args := map[string]any{"root": &root}
	before := map[string]any{"root": &root}
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte("sshd.service\ncron.service\t\n  systemd-journald\n")})

	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "services_need_restart", args)
	want := []string{"sshd.service", "cron.service", "systemd-journald"}
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) {
		t.Fatalf("got=%#v err=%v args=%#v", got, err, args)
	}
	wantArgv := []string{"zypper", "--non-interactive", "--no-refresh", "--root", root, "ps", "-sss"}
	if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), wantArgv) {
		t.Fatalf("argv=%#v want=%#v", runner.commands, wantArgv)
	}
	assertZypperPatternsCommand(t, runner.commands[0], true)

	rt, runner = zypperLowpkgRuntime(process.CommandResult{Stdout: []byte("  \n\t ")})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "services_need_restart", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, []string{}) {
		t.Fatalf("blank got=%#v err=%v", got, err)
	}
}

func TestZypperServicesNeedRestartExitCodeAndCancelBoundaries(t *testing.T) {
	rt, runner := zypperLowpkgRuntime(process.CommandResult{ExitCode: 104})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "services_need_restart", map[string]any{})
	if got != nil || err == nil || len(runner.commands) != 1 {
		t.Fatalf("exit got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	var exitErr *zypperExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("exit err=%v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancelRunner := &zypperCancelRunner{cancel: cancel}
	rt = &runtime.Runtime{Runner: cancelRunner}
	got, err = zypperLowpkgProvider().Zypper(ctx, rt, "services_need_restart", map[string]any{})
	if got != nil || !errors.Is(err, context.Canceled) || len(cancelRunner.calls) != 1 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(cancelRunner.calls))
	}
}

func TestZypperPatchesServicesRejectMalformedXML(t *testing.T) {
	for _, output := range []string{
		"",
		"not xml",
		"<a/><b/>",
		"<stream><solvable/></wrong>",
		"<stream>" + strings.Repeat(`<solvable name="x"/>`, zypperLowpkgMaxItems+1) + "</stream>",
	} {
		rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(output)})
		if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_patches", map[string]any{}); got != nil || err == nil || len(runner.commands) != 1 {
			t.Fatalf("output=%q got=%#v err=%v", output, got, err)
		}
	}
}
