package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
)

func TestZypperPatternsCLIUsesExactArgvAndResults(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		results []process.CommandResult
		want    map[string]map[string]any
		argv    [][]string
	}{
		{
			args:    []string{"exec", "pkg.list_patterns", "--refresh=false", "--root", "/target"},
			results: []process.CommandResult{{Stdout: []byte(`<stream><solvable name="base" summary="Base" status="installed"/></stream>`)}},
			want:    map[string]map[string]any{"base": {"installed": true, "summary": "Base"}},
			argv:    [][]string{{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "se", "-t", "pattern"}},
		},
		{
			args:    []string{"exec", "pkg.list_patterns"},
			results: []process.CommandResult{{Stdout: []byte(`<stream xmlns="urn:default" xmlns:ns="urn:prefixed"><ns:solvable name="ignored" summary="Ignored" status="installed"/><solvable name="nested" summary="outer" status="installed"><solvable name="nested" summary="inner" status="not-installed"/></solvable><solvable name="default" summary="Default" status="installed"/></stream>`)}},
			want: map[string]map[string]any{
				"default": {"installed": true, "summary": "Default"},
				"nested":  {"installed": false, "summary": "inner"},
			},
			argv: [][]string{{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "se", "-t", "pattern"}},
		},
		{
			args:    []string{"exec", "pkg.list_patterns"},
			results: []process.CommandResult{{Stdout: []byte(`<stream><solvable summary="absent" status="installed"/><solvable name="" summary="empty" status="not-installed"/><solvable name="nested" summary="outer" status="installed"><solvable name="nested" summary="inner" status="not-installed"/></solvable></stream>`)}},
			want: map[string]map[string]any{
				"":       {"installed": false, "summary": "empty"},
				"nested": {"installed": false, "summary": "inner"},
			},
			argv: [][]string{{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "se", "-t", "pattern"}},
		},
		{
			args: []string{"exec", "pkg.list_installed_patterns", "--root", "/target"},
			results: []process.CommandResult{
				{Stdout: []byte("pattern() = hidden\n")},
				{Stdout: []byte(`<stream><solvable name="base" summary="Base" status="installed"/></stream>`)},
			},
			want: map[string]map[string]any{
				"base":   {"installed": true, "summary": "Base"},
				"hidden": {"installed": true, "summary": "Non-visible pattern"},
			},
			argv: [][]string{
				{"rpm", "--root", "/target", "-q", "--provides", "--whatprovides", "pattern()"},
				{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "se", "-t", "pattern"},
			},
		},
		{
			args: []string{"exec", "pkg.list_installed_patterns"},
			results: []process.CommandResult{
				{Stdout: []byte("pattern() = \npattern() = hidden\n")},
				{Stdout: []byte(`<stream><solvable summary="absent" status="not-installed"/><solvable name="nested" summary="outer" status="installed"><solvable name="nested" summary="inner" status="not-installed"/></solvable><solvable name="" summary="empty" status="installed"/></stream>`)},
			},
			want: map[string]map[string]any{
				"":       {"installed": true, "summary": "empty"},
				"hidden": {"installed": true, "summary": "Non-visible pattern"},
			},
			argv: [][]string{
				{"rpm", "-q", "--provides", "--whatprovides", "pattern()"},
				{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "se", "-t", "pattern"},
			},
		},
	} {
		t.Run(strings.Join(tc.args, "/"), func(t *testing.T) {
			runner := &cliRecordingRunner{results: tc.results}
			fsys := &cliCountingFS{}
			code, out, errS := captureCode(t, providerCLIAppWithFS(t, "zypper", runner, fsys), append(tc.args, "-o", "json")...)
			var got map[string]map[string]any
			if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &got) != nil || len(runner.calls) != len(tc.argv) || fsys.calls != 0 {
				t.Fatalf("code=%d out=%q err=%q calls=%d fs=%d", code, out, errS, len(runner.calls), fsys.calls)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("result=%#v want=%#v", got, tc.want)
			}
			for i, command := range runner.calls {
				if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv, tc.argv[i]) {
					t.Fatalf("argv[%d]=%v want=%v", i, argv, tc.argv[i])
				}
				if command.Shell || command.MaxStdoutBytes == 0 || command.MaxStderrBytes == 0 {
					t.Fatalf("unsafe command[%d]=%#v", i, command)
				}
			}
		})
	}
}

func TestZypperPatternsCLINoCallForInvalidOrWrongProvider(t *testing.T) {
	for _, args := range [][]string{
		{"exec", "pkg.list_patterns", "--refresh=invalid"},
		{"exec", "pkg.list_patterns", "--repo", "base"},
		{"exec", "pkg.list_installed_patterns", "--refresh=false"},
		{"exec", "pkg.list_patterns", "--root", "bad\nroot"},
	} {
		runner := &cliRecordingRunner{}
		code, _, errS := captureCode(t, providerCLIApp(t, "zypper", runner), args...)
		if code == ExitOK || len(runner.calls) != 0 || strings.Contains(errS, "bad\nroot") {
			t.Fatalf("args=%v code=%d err=%q calls=%d", args, code, errS, len(runner.calls))
		}
	}
	for _, manager := range []string{"apt", "yum"} {
		for _, name := range []string{"pkg.list_patterns", "pkg.list_installed_patterns"} {
			runner := &cliRecordingRunner{}
			code, _, _ := captureCode(t, providerCLIApp(t, manager, runner), "exec", name)
			if code != ExitUnsupported || len(runner.calls) != 0 {
				t.Fatalf("manager=%s name=%s code=%d calls=%d", manager, name, code, len(runner.calls))
			}
		}
	}
}
