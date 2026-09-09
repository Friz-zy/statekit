package pkg

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const zypperVisiblePatternsXML = `<stream><search-result><solvable-list><solvable name="base" summary="Base" status="installed" kind="pattern"/><solvable name="not-installed" summary="No" status="not-installed" kind="pattern"/><solvable name="mixed" summary="Case" status="Installed" kind="pattern"/><solvable name="base" summary="Last" status="not-installed" kind="pattern"/><pattern name="ignored" summary="Ignored" status="installed"/></solvable-list></search-result></stream>`

func TestZypperPatternsVisibleQueryUsesSourceArgvAndExactStatus(t *testing.T) {
	root := "/target"
	refresh := false
	args := map[string]any{"refresh": &refresh, "root": &root}
	before := map[string]any{"refresh": &refresh, "root": &root}
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(zypperVisiblePatternsXML)})

	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_patterns", args)
	want := map[string]any{
		"base":          map[string]any{"installed": false, "summary": "Last"},
		"not-installed": map[string]any{"installed": false, "summary": "No"},
		"mixed":         map[string]any{"installed": false, "summary": "Case"},
	}
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) {
		t.Fatalf("got=%#v err=%v args=%#v", got, err, args)
	}
	wantArgv := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "se", "-t", "pattern"}
	if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), wantArgv) {
		t.Fatalf("argv=%#v want=%#v", runner.commands, wantArgv)
	}
	assertZypperPatternsCommand(t, runner.commands[0], true)
}

func TestZypperPatternsInstalledMergesRPMCapabilitiesAndPreservesSequence(t *testing.T) {
	root := "/target"
	rpmOutput := "pattern() = base\n" +
		"pattern() = " + "\n" +
		"pattern() = hidden\n" +
		"pattern() = .hidden-alias\n" +
		"pattern() = not-installed\n" +
		"pattern() = hidden\n" +
		"pattern-visible()\n"
	rt, runner := zypperLowpkgRuntime(
		process.CommandResult{Stdout: []byte(rpmOutput), ExitCode: 0},
		process.CommandResult{Stdout: []byte(`<stream><search-result><solvable-list><solvable name="base" summary="Base" status="installed"/><solvable name="not-installed" summary="No" status="not-installed"/><solvable name="mixed" summary="Case" status="Installed"/></solvable-list></search-result></stream>`)},
	)
	args := map[string]any{"root": &root}
	before := map[string]any{"root": &root}

	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_installed_patterns", args)
	want := map[string]any{
		"":              map[string]any{"installed": true, "summary": "Non-visible pattern"},
		"base":          map[string]any{"installed": true, "summary": "Base"},
		"hidden":        map[string]any{"installed": true, "summary": "Non-visible pattern"},
		"not-installed": map[string]any{"installed": true, "summary": "Non-visible pattern"},
	}
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) {
		t.Fatalf("got=%#v err=%v args=%#v", got, err, args)
	}
	wantArgv := [][]string{
		{"rpm", "--root", root, "-q", "--provides", "--whatprovides", "pattern()"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "se", "-t", "pattern"},
	}
	if len(runner.commands) != len(wantArgv) {
		t.Fatalf("commands=%#v want=%#v", runner.commands, wantArgv)
	}
	for i, command := range runner.commands {
		if !reflect.DeepEqual(zypperCommandArgs(command), wantArgv[i]) {
			t.Fatalf("argv[%d]=%#v want=%#v", i, zypperCommandArgs(command), wantArgv[i])
		}
		if command.Shell || command.MaxStdoutBytes != zypperLowpkgOutputLimit || command.MaxStderrBytes != zypperLowpkgOutputLimit {
			t.Fatalf("unsafe command[%d]=%#v", i, command)
		}
	}
	assertZypperPatternsCommand(t, runner.commands[1], true)
}

func TestZypperPatternsRefreshRootPositionAndQueryRoot(t *testing.T) {
	root := "/target"
	refresh := true
	rt, runner := zypperLowpkgRuntime(
		process.CommandResult{},
		process.CommandResult{Stdout: []byte(`<stream/>`)},
	)
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_patterns", map[string]any{"refresh": &refresh, "root": &root})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 2 {
		t.Fatalf("refresh got=%#v err=%v commands=%#v", got, err, runner.commands)
	}
	want := [][]string{
		{"zypper", "--non-interactive", "refresh", "--force"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "se", "-t", "pattern"},
	}
	for i, command := range runner.commands {
		if !reflect.DeepEqual(zypperCommandArgs(command), want[i]) {
			t.Fatalf("argv[%d]=%#v want=%#v", i, zypperCommandArgs(command), want[i])
		}
		assertZypperPatternsCommand(t, command, i == 1)
	}

	emptyRoot := ""
	rt, runner = zypperLowpkgRuntime(process.CommandResult{}, process.CommandResult{Stdout: []byte(`<stream/>`)})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_patterns", map[string]any{"refresh": true, "root": &emptyRoot})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 2 {
		t.Fatalf("empty-root got=%#v err=%v commands=%#v", got, err, runner.commands)
	}
	if want := []string{"zypper", "--non-interactive", "refresh"}; !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), want) {
		t.Fatalf("empty-root refresh argv=%#v want=%#v", zypperCommandArgs(runner.commands[0]), want)
	}
	if want := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "se", "-t", "pattern"}; !reflect.DeepEqual(zypperCommandArgs(runner.commands[1]), want) {
		t.Fatalf("empty-root query argv=%#v want=%#v", zypperCommandArgs(runner.commands[1]), want)
	}

	rt, runner = zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(`<stream/>`)})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_patterns", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 1 {
		t.Fatalf("default got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	if want := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "se", "-t", "pattern"}; !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), want) {
		t.Fatalf("default argv=%#v want=%#v", zypperCommandArgs(runner.commands[0]), want)
	}
}

func TestZypperPatternsParserRejectsMismatchedRawTokenXML(t *testing.T) {
	for _, output := range []string{
		`<stream><solvable/></wrong>`,
		`<stream><solvable></stream></solvable>`,
		`<stream></wrong>`,
		`</stream>`,
	} {
		got, err := zypperParsePatterns(context.Background(), output, false)
		if got != nil || err != errZypperPatternsInvalidXML {
			t.Fatalf("output=%q got=%#v err=%v want=%v", output, got, err, errZypperPatternsInvalidXML)
		}
	}
}

func TestZypperPatternsParserEnforcesAttributeAndOutputLimits(t *testing.T) {
	var attrs strings.Builder
	for i := 0; i <= zypperPatternsMaxAttributesPerElement; i++ {
		_, _ = fmt.Fprintf(&attrs, ` a%d="v"`, i)
	}
	if got, err := zypperParsePatterns(context.Background(), `<stream`+attrs.String()+`/>`, false); got != nil || !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("attribute-count got=%#v err=%v", got, err)
	}
	largeAttr := `<stream value="` + strings.Repeat("v", zypperPatternsMaxAttributeBytes+1) + `"/>`
	if got, err := zypperParsePatterns(context.Background(), largeAttr, false); got != nil || !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("attribute-bytes got=%#v err=%v", got, err)
	}
	if got, err := zypperParsePatterns(context.Background(), strings.Repeat("x", zypperLowpkgOutputLimit+1), false); got != nil || !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("output-bytes got=%#v err=%v", got, err)
	}
}

func TestZypperPatternsRawTokenPreservesLexicalPrefixes(t *testing.T) {
	decoder := xml.NewDecoder(strings.NewReader(`<stream xmlns="urn:default" xmlns:ns="urn:prefixed"><solvable/><ns:solvable/></stream>`))
	var starts []xml.Name
	for {
		token, err := decoder.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if start, ok := token.(xml.StartElement); ok {
			starts = append(starts, start.Name)
		}
	}
	want := []xml.Name{{Local: "stream"}, {Local: "solvable"}, {Space: "ns", Local: "solvable"}}
	if !reflect.DeepEqual(starts, want) {
		t.Fatalf("RawToken start names=%#v want=%#v", starts, want)
	}
}

func TestZypperPatternsParserUsesLexicalNamespaceAndNestedDocumentOrder(t *testing.T) {
	output := `<stream xmlns="urn:default" xmlns:ns="urn:prefixed"><ns:solvable name="ignored" summary="Ignored" status="installed"/><solvable name="nested" summary="outer" status="installed"><ns:solvable name="nested" summary="prefixed" status="installed"/><solvable name="nested" summary="inner" status="not-installed"/></solvable><solvable name="default" summary="Default" status="installed"/></stream>`
	want := map[string]any{
		"default": map[string]any{"installed": true, "summary": "Default"},
		"nested":  map[string]any{"installed": false, "summary": "inner"},
	}
	got, err := zypperParsePatterns(context.Background(), output, false)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
	}
	installed, err := zypperParsePatterns(context.Background(), output, true)
	if err != nil || !reflect.DeepEqual(installed, map[string]any{"default": map[string]any{"installed": true, "summary": "Default"}}) {
		t.Fatalf("installed=%#v err=%v", installed, err)
	}
}

func TestZypperPatternsParserSolvableAttributesAndExactInstalledStatus(t *testing.T) {
	output := `<stream><solvable summary="absent" status="installed"/><solvable name="" summary="empty" status="not-installed"/><solvable name="nested" summary="outer" status="installed"><container><solvable name="nested" summary="inner" status="not-installed"/></container></solvable><solvable name="one" summary="first" status="installed"><name>child-name</name><summary>child-summary</summary></solvable><solvable name="two" summary="two" status="Installed"/><solvable name="three" summary="three" status=" installed "/><solvable name="one" summary="replacement" status="installed"/><pattern name="four" summary="ignored" status="installed"/></stream>`
	got, err := zypperParsePatterns(context.Background(), output, false)
	want := map[string]any{
		"":       map[string]any{"installed": false, "summary": "empty"},
		"nested": map[string]any{"installed": false, "summary": "inner"},
		"one":    map[string]any{"installed": true, "summary": "replacement"},
		"two":    map[string]any{"installed": false, "summary": "two"},
		"three":  map[string]any{"installed": false, "summary": "three"},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
	}

	installed, err := zypperParsePatterns(context.Background(), output, true)
	if err != nil || !reflect.DeepEqual(installed, map[string]any{"one": map[string]any{"installed": true, "summary": "replacement"}}) {
		t.Fatalf("installed=%#v err=%v", installed, err)
	}
}

func TestZypperPatternsRejectInvalidArgumentsAndNoCall(t *testing.T) {
	for _, tc := range []struct {
		function string
		args     map[string]any
	}{
		{"list_patterns", map[string]any{"refresh": "false"}},
		{"list_patterns", map[string]any{"root": false}},
		{"list_patterns", map[string]any{"repo": "base"}},
		{"list_installed_patterns", map[string]any{"refresh": false}},
		{"list_installed_patterns", map[string]any{"options": []string{"--details"}}},
		{"list_installed_patterns", map[string]any{"root": strings.Repeat("r", maxZypperTokenRunes+1)}},
	} {
		rt, runner := zypperLowpkgRuntime()
		if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, tc.function, tc.args); got != nil || err == nil || len(runner.commands) != 0 {
			t.Fatalf("%s args=%#v got=%#v err=%v calls=%d", tc.function, tc.args, got, err, len(runner.commands))
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := zypperLowpkgRuntime()
	if got, err := zypperLowpkgProvider().Zypper(ctx, rt, "list_patterns", map[string]any{}); got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("pre-cancel got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperPatternsRPMRetcodesErrorsCancellationAndBounds(t *testing.T) {
	visible := []byte(`<stream><solvable name="visible" summary="Visible" status="installed"/></stream>`)
	for _, tc := range []struct {
		name   string
		result process.CommandResult
		want   any
	}{
		{"retcode-one-empty", process.CommandResult{ExitCode: 1, Stderr: []byte("no matching capabilities")}, map[string]any{"visible": map[string]any{"installed": true, "summary": "Visible"}}},
		{"retcode-zero", process.CommandResult{ExitCode: 0, Stdout: []byte("pattern() = hidden\n")}, map[string]any{"visible": map[string]any{"installed": true, "summary": "Visible"}, "hidden": map[string]any{"installed": true, "summary": "Non-visible pattern"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := zypperLowpkgRuntime(tc.result, process.CommandResult{Stdout: visible})
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_installed_patterns", map[string]any{})
			if err != nil || !reflect.DeepEqual(got, tc.want) || len(runner.commands) != 2 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
			}
		})
	}

	sentinel := errors.New("rpm runner failure")
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Err: sentinel})
	if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_installed_patterns", map[string]any{}); got != nil || !errors.Is(err, sentinel) || len(runner.commands) != 1 || strings.Contains(err.Error(), "stderr") {
		t.Fatalf("runner error got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancelRunner := &zypperCancelRunner{cancel: cancel}
	rt = &runtime.Runtime{Runner: cancelRunner}
	if got, err := zypperLowpkgProvider().Zypper(ctx, rt, "list_installed_patterns", map[string]any{}); got != nil || !errors.Is(err, context.Canceled) || len(cancelRunner.calls) != 1 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(cancelRunner.calls))
	}

	rt, runner = zypperLowpkgRuntime(process.CommandResult{Stdout: make([]byte, zypperLowpkgOutputLimit+1)})
	if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_installed_patterns", map[string]any{}); got != nil || !errors.Is(err, process.ErrOutputLimit) || len(runner.commands) != 1 {
		t.Fatalf("rpm output bound got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	for _, result := range []process.CommandResult{
		{Err: errors.New("zypper runner failure")},
		{ExitCode: 1, Stderr: []byte("secret zypper stderr")},
		{StdoutTruncated: true},
		{StderrTruncated: true},
		{Stdout: make([]byte, zypperLowpkgOutputLimit+1)},
		{Stderr: make([]byte, zypperLowpkgOutputLimit+1)},
	} {
		rt, runner = zypperLowpkgRuntime(result)
		if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_patterns", map[string]any{}); got != nil || err == nil || len(runner.commands) != 1 || strings.Contains(err.Error(), "secret zypper stderr") {
			t.Fatalf("query result=%#v got=%#v err=%v calls=%d", result, got, err, len(runner.commands))
		}
	}
}

func TestZypperPatternsParserEmptyMalformedAndBounds(t *testing.T) {
	for _, output := range []string{
		"",
		"not xml",
		"<a/><b/>",
		"<stream><solvable>",
		"<stream>" + strings.Repeat("<node>", zypperSearchMaxXMLDepth) + strings.Repeat("</node>", zypperSearchMaxXMLDepth) + "</stream>",
		"<stream>" + strings.Repeat(`<solvable name="x"/>`, zypperLowpkgMaxItems+1) + "</stream>",
	} {
		if got, err := zypperParsePatterns(context.Background(), output, false); got != nil || err == nil {
			t.Fatalf("output=%q got=%#v err=%v", output, got, err)
		}
	}

	capabilities := strings.Repeat("pattern() = duplicate\n", zypperLowpkgMaxItems+1)
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(capabilities)})
	if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_installed_patterns", map[string]any{}); got != nil || !errors.Is(err, process.ErrOutputLimit) || len(runner.commands) != 1 {
		t.Fatalf("capability bound got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func assertZypperPatternsCommand(t *testing.T, command process.Command, xmlQuery bool) {
	t.Helper()
	if command.Shell || command.MaxStdoutBytes != zypperLowpkgOutputLimit || command.MaxStderrBytes != zypperLowpkgOutputLimit {
		t.Fatalf("unsafe command=%#v", command)
	}
	wantEnv := []string{"LC_ALL=C"}
	if xmlQuery {
		wantEnv = append(wantEnv, "ZYPP_READONLY_HACK=1")
	}
	if !reflect.DeepEqual(command.Env, wantEnv) {
		t.Fatalf("env=%v want=%v", command.Env, wantEnv)
	}
}
