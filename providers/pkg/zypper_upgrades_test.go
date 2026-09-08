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

func TestZypperUpgradesSourceArgv(t *testing.T) {
	for _, tc := range []struct {
		function string
		args     map[string]any
		output   string
		argv     [][]string
		want     any
	}{
		{"list_upgrades", map[string]any{"refresh": false, "root": "/target", "fromrepo": []string{"base", "updates"}}, `<stream><update kind="patch" name="skip"/><update kind="package" name="demo" edition="1"/><update kind="package" name="demo" edition="2&amp;3"/></stream>`, [][]string{{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "list-updates", "--repo", "base", "--repo", "updates"}}, map[string]string{"demo": "2&3"}},
		{"list_upgrades", map[string]any{}, `<stream/>`, [][]string{{"zypper", "--non-interactive", "refresh", "--force"}, {"zypper", "--non-interactive", "--xmlout", "--no-refresh", "list-updates"}}, map[string]string{}},
		{"list_upgrades", map[string]any{"root": "/target", "repos": "base"}, `<stream/>`, [][]string{{"zypper", "--non-interactive", "refresh", "--force", "base"}, {"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "list-updates"}}, map[string]string{}},
		{"upgrade_available", map[string]any{"name": "demo.x86_64", "root": "/target"}, "Information for package demo:\nName: demo\nVersion: 2\nStatus: not installed\n", [][]string{{"zypper", "--non-interactive", "--root", "/target", "refresh", "--force"}, {"zypper", "--non-interactive", "--no-refresh", "--root", "/target", "info", "-t", "package", "demo.x86_64"}}, false},
		{"upgrade_available", map[string]any{"name": "demo", "refresh": false}, "Information for package demo:\nName: demo\nVersion: 2\nStatus: OUT-OF-DATE (installed)\n", [][]string{{"zypper", "--non-interactive", "--no-refresh", "info", "-t", "package", "demo"}}, true},
	} {
		t.Run(tc.function+tc.output, func(t *testing.T) {
			results := make([]process.CommandResult, len(tc.argv))
			results[len(results)-1].Stdout = []byte(tc.output)
			rt, runner := zypperLowpkgRuntime(results...)
			rt.FS = &zypperNoCallFS{}
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, tc.function, tc.args)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, tc.want)
			}
			var argv [][]string
			for i, command := range runner.commands {
				argv = append(argv, zypperCommandArgs(command))
				if command.Shell || command.MaxStdoutBytes != 1<<20 || command.MaxStderrBytes != 1<<20 {
					t.Fatalf("unsafe command %#v", command)
				}
				wantEnv := []string{"LC_ALL=C"}
				if i == len(tc.argv)-1 {
					wantEnv = append(wantEnv, "ZYPP_READONLY_HACK=1")
				}
				if !reflect.DeepEqual(command.Env, wantEnv) {
					t.Fatalf("env=%v", command.Env)
				}
			}
			if !reflect.DeepEqual(argv, tc.argv) {
				t.Fatalf("argv=%v want=%v", argv, tc.argv)
			}
		})
	}
}

func TestZypperUpgradeAvailableStatuses(t *testing.T) {
	for _, tc := range []struct {
		status, version string
		want            bool
	}{
		{"not installed", "2", true}, {"out-of-date", "2", true}, {"NOT INSTALLED", "2", true},
		{"up-to-date", "2", false}, {"installed", "2", false}, {"", "2", false}, {"not installed", "", false},
	} {
		got, err := zypperParseUpgradeAvailable(context.Background(), "Name: demo\nStatus: "+tc.status+"\nVersion: "+tc.version, "demo")
		if err != nil || got != tc.want {
			t.Fatalf("%+v got=%v err=%v", tc, got, err)
		}
	}
	got, err := zypperParseUpgradeAvailable(context.Background(), "Information for package demo:\nName: demo\nStatus: not installed\nVersion: 2\nInformation for package demo:\nName: demo\nStatus: installed\nVersion: 2", "demo")
	if err != nil || got {
		t.Fatalf("last record must win: %v %v", got, err)
	}
}

func TestZypperUpgradesErrorsCancelBoundsNoCall(t *testing.T) {
	for _, args := range []map[string]any{
		{"refresh": "false"}, {"root": false}, {"fromrepo": "--help"}, {"repos": []string{"bad\nrepo"}},
		{"unknown": true}, {"fromrepo": strings.Repeat("x", 4097)}, {"fromrepo": []string{strings.Repeat("x", 4096), strings.Repeat("y", 4096), strings.Repeat("z", 4096), strings.Repeat("q", 4096), strings.Repeat("x", 4096), strings.Repeat("y", 4096), strings.Repeat("z", 4096), strings.Repeat("q", 4096), strings.Repeat("x", 4096), strings.Repeat("y", 4096), strings.Repeat("z", 4096), strings.Repeat("q", 4096), strings.Repeat("x", 4096), strings.Repeat("y", 4096), strings.Repeat("z", 4096), strings.Repeat("q", 4096)}},
	} {
		rt, runner := zypperLowpkgRuntime()
		if _, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_upgrades", args); err == nil || len(runner.commands) != 0 {
			t.Fatalf("args=%v err=%v calls=%d", args, err, len(runner.commands))
		}
	}
	for _, result := range []process.CommandResult{{Err: errors.New("runner failed")}, {ExitCode: 1}, {ExitCode: 7}, {StdoutTruncated: true}, {StderrTruncated: true}, {Stdout: make([]byte, (1<<20)+1)}} {
		rt, runner := zypperLowpkgRuntime(result)
		if _, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_upgrades", map[string]any{}); err == nil || len(runner.commands) != 1 {
			t.Fatalf("err=%v calls=%d", err, len(runner.commands))
		}
	}
	for _, output := range []string{"", "not xml", "<a>", "<a/><b/>", strings.Repeat("<a>", 129) + strings.Repeat("</a>", 129), "<s>" + strings.Repeat("<update/>", 4097) + "</s>"} {
		if _, err := zypperParseUpgrades(context.Background(), output); err == nil {
			t.Fatal("accepted invalid or unbounded XML")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := zypperLowpkgRuntime()
	if _, err := zypperLowpkgProvider().Zypper(ctx, rt, "list_upgrades", map[string]any{}); !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("err=%v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	r := &zypperCancelRunner{cancel: cancel}
	if _, err := zypperLowpkgProvider().Zypper(ctx, &runtime.Runtime{Runner: r}, "list_upgrades", map[string]any{}); !errors.Is(err, context.Canceled) || len(r.calls) != 1 {
		t.Fatalf("err=%v calls=%d", err, len(r.calls))
	}
	for _, manager := range []string{"apt", "yum"} {
		if _, err := (&commandProvider{spec: spec{manager: manager}}).Zypper(context.Background(), rt, "list_upgrades", map[string]any{}); !errors.Is(err, ErrUnsupportedZypper) {
			t.Fatalf("err=%v", err)
		}
	}
}
