package pkg

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
)

func TestZypperRepoScalarRenderingAndEarlyBound(t *testing.T) {
	for _, tc := range []struct {
		value float64
		want  string
	}{
		{1, "1.0"}, {1e6, "1000000.0"}, {1e15, "1000000000000000.0"},
		{1e16, "1e+16"}, {0.0001, "0.0001"}, {0.00001, "1e-05"},
	} {
		values, err := zypperUpgradeRepos(map[string]any{"fromrepo": []any{tc.value}}, "fromrepo")
		if err != nil || !reflect.DeepEqual(values, []string{tc.want}) {
			t.Fatalf("value=%v got=%v err=%v", tc.value, values, err)
		}
	}
	rt, runner := zypperLowpkgRuntime()
	_, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_upgrades", map[string]any{"fromrepo": make([]any, 4097)})
	if err == nil || len(runner.commands) != 0 {
		t.Fatalf("err=%v calls=%d", err, len(runner.commands))
	}
}

func TestZypperUpgradesRetcodesAndQueryFailures(t *testing.T) {
	for _, code := range []int{0, 6, 100, 101, 102, 103, 106, 107} {
		rt, r := zypperLowpkgRuntime(process.CommandResult{ExitCode: code, Stdout: []byte("<stream/>")})
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_upgrades", map[string]any{"refresh": false})
		if err != nil || !reflect.DeepEqual(got, map[string]string{}) || len(r.commands) != 1 {
			t.Fatalf("code=%d got=%v err=%v", code, got, err)
		}
	}
	for _, function := range []string{"list_upgrades", "upgrade_available"} {
		for _, result := range []process.CommandResult{{Err: context.DeadlineExceeded}, {ExitCode: 1}, {ExitCode: 7}, {Stderr: make([]byte, (1<<20)+1)}, {StdoutTruncated: true}, {StderrTruncated: true}} {
			rt, r := zypperLowpkgRuntime(result)
			args := map[string]any{"refresh": false}
			if function == "upgrade_available" {
				args["name"] = "demo"
			}
			if _, err := zypperLowpkgProvider().Zypper(context.Background(), rt, function, args); err == nil || len(r.commands) != 1 {
				t.Fatalf("%s err=%v calls=%d", function, err, len(r.commands))
			}
		}
	}
	for _, args := range []map[string]any{{"name": "-evil"}, {"name": "bad\nname"}, {"name": 2}, {"name": "demo", "root": "/bad\nroot"}} {
		rt, r := zypperLowpkgRuntime()
		if _, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade_available", args); err == nil || len(r.commands) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(r.commands))
		}
	}
	if _, err := zypperLowpkgProvider().Zypper(context.Background(), nil, "list_upgrades", map[string]any{}); err == nil {
		t.Fatal("accepted missing runtime")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := zypperParseUpgradeAvailable(ctx, "Name: demo", "demo"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := zypperParseUpgradeAvailable(context.Background(), strings.Repeat("Information for package", 4097), "demo"); !errors.Is(err, process.ErrOutputLimit) {
		t.Fatal(err)
	}
}

func TestZypperUpgradesRefreshAndRepoEdges(t *testing.T) {
	for _, tc := range []struct {
		root  any
		force bool
	}{{nil, true}, {(*string)(nil), true}, {"", false}, {"/target", true}} {
		rt, r := zypperLowpkgRuntime(process.CommandResult{}, process.CommandResult{Stdout: []byte("<stream/>")})
		_, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_upgrades", map[string]any{"root": tc.root, "repos": "repo name", "gpgautoimport": true})
		want := []string{"zypper", "--non-interactive", "--gpg-auto-import-keys", "refresh"}
		if tc.force {
			want = append(want, "--force")
		}
		want = append(want, "repo name")
		if err != nil || len(r.commands) != 2 || !reflect.DeepEqual(zypperCommandArgs(r.commands[0]), want) {
			t.Fatalf("root=%v err=%v commands=%v", tc.root, err, r.commands)
		}
	}
	rt, r := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte("<stream/>")})
	_, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_upgrades", map[string]any{"refresh": false, "fromrepo": []any{"repo name", 42, true, nil}})
	want := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "list-updates", "--repo", "repo name", "--repo", "42", "--repo", "True", "--repo", "None"}
	if err != nil || !reflect.DeepEqual(zypperCommandArgs(r.commands[0]), want) {
		t.Fatalf("err=%v commands=%v", err, r.commands)
	}
	rt, r = zypperLowpkgRuntime(process.CommandResult{Stdout: []byte("Name: demo\nStatus: not installed\nVersion: 2")})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "upgrade_available", map[string]any{"name": "demo", "refresh": false, "fromrepo": "ignored"})
	want = []string{"zypper", "--non-interactive", "--no-refresh", "info", "-t", "package", "demo"}
	if err != nil || got != true || !reflect.DeepEqual(zypperCommandArgs(r.commands[0]), want) {
		t.Fatalf("got=%v err=%v", got, err)
	}
}
