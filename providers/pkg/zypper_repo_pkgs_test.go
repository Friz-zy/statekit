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

const zypperRepoPkgsXML = `<stream><search-result><solvable-list>` +
	`<solvable name="bash" edition="4.3-83.3.1" arch="x86_64" repository="OSS Update" status="not-installed" kind="package"/>` +
	`<solvable name="bash" edition="4.3-82.6" arch="x86_64" repository="OSS" status="installed" kind="package"/>` +
	`<solvable name="bash" edition="4.3-83.3.1" arch="x86_64" repository="OSS" status="not-installed" kind="package"/>` +
	`<solvable name="vim" edition="7.4.326-12.1" arch="x86_64" repository="OSS" status="not-installed" kind="package"/>` +
	`<solvable name="zsh" edition="5.9-1.1" arch="x86_64" repository="OSS" status="not-installed" kind="package"/>` +
	`<solvable name="not-a-package" edition="1" arch="x86_64" repository="OSS" status="installed" kind="pattern"/>` +
	`<solvable name="missing-edition" repository="OSS" kind="package"/>` +
	`<solvable name="missing-repo" edition="1" kind="package"/>` +
	`</solvable-list></search-result></stream>`

func TestZypperListRepoPkgsFlattensAcrossRepositories(t *testing.T) {
	root := "/target"
	args := map[string]any{"pkgs": []string{"ba*", "vim"}, "root": &root}
	before := map[string]any{"pkgs": []string{"ba*", "vim"}, "root": &root}
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(zypperRepoPkgsXML)})

	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_repo_pkgs", args)
	// bash 4.3-83.3.1 appears in two repositories but collapses to one
	// flattened entry; versions sort newest first.
	want := map[string]any{
		"bash": []string{"4.3-83.3.1", "4.3-82.6"},
		"vim":  []string{"7.4.326-12.1"},
	}
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) {
		t.Fatalf("got=%#v err=%v args=%#v", got, err, args)
	}
	wantArgv := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "se", "-s", "ba*", "vim"}
	if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), wantArgv) {
		t.Fatalf("argv=%#v want=%#v", runner.commands, wantArgv)
	}
	assertZypperPatternsCommand(t, runner.commands[0], true)
}

func TestZypperListRepoPkgsByRepoGroupsPerRepository(t *testing.T) {
	byrepo := true
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(zypperRepoPkgsXML)})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_repo_pkgs", map[string]any{"byrepo": &byrepo})
	want := map[string]any{
		"OSS Update": map[string]any{"bash": []string{"4.3-83.3.1"}},
		"OSS": map[string]any{
			"bash": []string{"4.3-83.3.1", "4.3-82.6"},
			"vim":  []string{"7.4.326-12.1"},
			"zsh":  []string{"5.9-1.1"},
		},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "se", "-s"}) {
		t.Fatalf("argv=%#v", runner.commands)
	}
}

func TestZypperListRepoPkgsFromrepoFiltersExactRepositoryName(t *testing.T) {
	fromrepo := "OSS Update"
	rt, _ := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(zypperRepoPkgsXML)})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_repo_pkgs", map[string]any{"fromrepo": &fromrepo})
	want := map[string]any{"bash": []string{"4.3-83.3.1"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v", got, err)
	}

	// fromrepo="" is the source default: no filtering at all.
	empty := ""
	rt, _ = zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(zypperRepoPkgsXML)})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_repo_pkgs", map[string]any{"fromrepo": &empty})
	if err != nil || len(got.(map[string]any)) != 3 {
		t.Fatalf("empty fromrepo got=%#v err=%v", got, err)
	}
}

func TestZypperListRepoPkgsMatchSemantics(t *testing.T) {
	for _, tc := range []struct {
		name    string
		targets []string
		want    []string
	}{
		{"no targets match all", nil, []string{"bash", "vim", "zsh"}},
		{"exact match", []string{"vim"}, []string{"vim"}},
		{"glob match", []string{"b*"}, []string{"bash"}},
		{"substring is not a match", []string{"im"}, nil},
		{"case sensitive", []string{"VIM"}, nil},
		{"multiple targets any", []string{"VIM", "vim"}, []string{"vim"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]any{}
			if tc.targets != nil {
				args["pkgs"] = tc.targets
			}
			rt, _ := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(zypperRepoPkgsXML)})
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_repo_pkgs", args)
			if err != nil {
				t.Fatal(err)
			}
			names := make([]string, 0, len(got.(map[string]any)))
			for name := range got.(map[string]any) {
				names = append(names, name)
			}
			if len(names) != len(tc.want) {
				t.Fatalf("names=%v want=%v", names, tc.want)
			}
			for _, want := range tc.want {
				if _, ok := got.(map[string]any)[want]; !ok {
					t.Fatalf("names=%v want %q", names, want)
				}
			}
		})
	}
}

func TestZypperListRepoPkgsVersionSortIsLooseVersionDescending(t *testing.T) {
	xml := `<stream><solvable-list>` +
		`<solvable name="p" edition="1.0" repository="r" kind="package"/>` +
		`<solvable name="p" edition="1.10" repository="r" kind="package"/>` +
		`<solvable name="p" edition="1.9" repository="r" kind="package"/>` +
		`<solvable name="p" edition="1.02" repository="r" kind="package"/>` +
		`</solvable-list></stream>`
	rt, _ := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(xml)})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_repo_pkgs", map[string]any{})
	// LooseVersion compares numeric components numerically: 1.10 > 1.9 >
	// 1.02 > 1.0.
	want := map[string]any{"p": []string{"1.10", "1.9", "1.02", "1.0"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
}

func TestZypperListRepoPkgsRejectsBadArgumentsBeforeRunner(t *testing.T) {
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"byrepo not bool", map[string]any{"byrepo": "true"}},
		{"fromrepo control char", map[string]any{"fromrepo": "bad\nrepo"}},
		{"fromrepo wrong type", map[string]any{"fromrepo": 7}},
		{"pkgs unsafe token", map[string]any{"pkgs": []string{"bad name"}}},
		{"pkgs dash token", map[string]any{"pkgs": []string{"-x"}}},
		{"pkgs wrong type", map[string]any{"pkgs": "bash"}},
		{"unknown kwarg", map[string]any{"enablerepo": "x"}},
		{"bad root", map[string]any{"root": 7}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := zypperLowpkgRuntime()
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_repo_pkgs", tc.args)
			if got != nil || err == nil || len(runner.commands) != 0 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
			}
		})
	}
}

func TestZypperListRepoPkgsCancelAndMalformedXML(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancelRunner := &zypperCancelRunner{cancel: cancel}
	rt := &runtime.Runtime{Runner: cancelRunner}
	if got, err := zypperLowpkgProvider().Zypper(ctx, rt, "list_repo_pkgs", map[string]any{}); got != nil || !errors.Is(err, context.Canceled) || len(cancelRunner.calls) != 1 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(cancelRunner.calls))
	}

	for _, output := range []string{
		"",
		"not xml",
		"<a/><b/>",
		"<stream><solvable/></wrong>",
		"<stream>" + strings.Repeat(`<solvable name="x" edition="1" repository="r" kind="package"/>`, zypperLowpkgMaxItems+1) + "</stream>",
	} {
		rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(output)})
		if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_repo_pkgs", map[string]any{}); got != nil || err == nil || len(runner.commands) != 1 {
			t.Fatalf("output=%q got=%#v err=%v", output, got, err)
		}
	}
}
