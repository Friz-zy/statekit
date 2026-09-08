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

func TestZypperSearchSourceArgvAndDuplicateAttributes(t *testing.T) {
	refresh := false
	root := "/target"
	match := "exact"
	trueValue := true
	args := map[string]any{
		"criteria":            "demo",
		"refresh":             &refresh,
		"root":                &root,
		"match":               &match,
		"provides":            &trueValue,
		"recommends":          &trueValue,
		"requires":            &trueValue,
		"suggests":            &trueValue,
		"conflicts":           &trueValue,
		"obsoletes":           &trueValue,
		"file_list":           &trueValue,
		"search_descriptions": &trueValue,
		"case_sensitive":      &trueValue,
		"installed_only":      &trueValue,
		"not_installed_only":  &trueValue,
		"details":             &trueValue,
	}
	output := `<stream><solvable name="demo" edition="1" kind="package"/><solvable name="demo" edition="2" vendor="ACME &amp; Co"/></stream>`
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(output)})

	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "search", args)
	want := map[string]map[string]string{
		"demo": {"name": "demo", "edition": "2", "vendor": "ACME & Co"},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
	}
	wantArgv := []string{
		"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root,
		"search", "--match-exact", "--provides", "--recommends", "--requires", "--suggests",
		"--conflicts", "--obsoletes", "--file-list", "--search-descriptions", "--case-sensitive",
		"--installed-only", "-u", "--details", "demo",
	}
	if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), wantArgv) {
		t.Fatalf("argv=%#v want=%#v", runner.commands, wantArgv)
	}
	command := runner.commands[0]
	if command.Shell || command.MaxStdoutBytes != zypperLowpkgOutputLimit || command.MaxStderrBytes != zypperLowpkgOutputLimit {
		t.Fatalf("unsafe command=%#v", command)
	}
	if !reflect.DeepEqual(command.Env, []string{"LC_ALL=C", "ZYPP_READONLY_HACK=1"}) {
		t.Fatalf("env=%v", command.Env)
	}
}

func TestZypperSearchDefaultsAndRefreshOrdering(t *testing.T) {
	rt, runner := zypperLowpkgRuntime(process.CommandResult{}, process.CommandResult{
		Stdout: []byte(`<stream><solvable name="demo"/></stream>`),
	})
	root := "/target"
	refresh := true
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "search", map[string]any{
		"criteria": "demo", "refresh": &refresh, "root": &root,
	})
	if err != nil || !reflect.DeepEqual(got, map[string]map[string]string{"demo": {"name": "demo"}}) {
		t.Fatalf("refresh got=%#v err=%v", got, err)
	}
	want := [][]string{
		{"zypper", "--non-interactive", "--root", root, "refresh", "--force"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "search", "demo"},
	}
	if len(runner.commands) != len(want) {
		t.Fatalf("commands=%d want=%d", len(runner.commands), len(want))
	}
	for i, command := range runner.commands {
		if !reflect.DeepEqual(zypperCommandArgs(command), want[i]) {
			t.Fatalf("argv[%d]=%#v want=%#v", i, zypperCommandArgs(command), want[i])
		}
	}

	rt, runner = zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(`<stream><solvable name="demo"/></stream>`)})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "search", map[string]any{"criteria": "demo"})
	if err != nil || got == nil || len(runner.commands) != 1 {
		t.Fatalf("defaults got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	if want := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "search", "demo"}; !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), want) {
		t.Fatalf("default argv=%#v want=%#v", zypperCommandArgs(runner.commands[0]), want)
	}
}

func TestZypperSearchRejectsInvalidArgumentsWithoutRunner(t *testing.T) {
	for _, args := range []map[string]any{
		{},
		{"criteria": 7},
		{"criteria": ""},
		{"criteria": "bad\ncriteria"},
		{"criteria": "--help"},
		{"criteria": "safe", "refresh": "false"},
		{"criteria": "safe", "root": false},
		{"criteria": "safe", "match": "invalid"},
		{"criteria": "safe", "match": 7},
		{"criteria": "safe", "provides": "true"},
		{"criteria": "safe", "unknown": true},
	} {
		rt, runner := zypperLowpkgRuntime()
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "search", args)
		if got != nil || err == nil || len(runner.commands) != 0 {
			t.Fatalf("args=%#v got=%#v err=%v calls=%d", args, got, err, len(runner.commands))
		}
	}

	secret := "bad\ncriteria-secret"
	rt, runner := zypperLowpkgRuntime()
	_, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "search", map[string]any{"criteria": secret})
	if err == nil || strings.Contains(err.Error(), "criteria-secret") || len(runner.commands) != 0 {
		t.Fatalf("unsafe criteria err=%v calls=%d", err, len(runner.commands))
	}
}

func TestZypperSearchPreservesExplicitOptionPresenceAndMatchModes(t *testing.T) {
	falseValue := false
	for _, tc := range []struct {
		match string
		flag  string
	}{
		{match: "exact", flag: "--match-exact"},
		{match: "words", flag: "--match-words"},
		{match: "substrings", flag: "--match-substrings"},
	} {
		rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(`<stream><solvable name="demo"/></stream>`)})
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "search", map[string]any{
			"criteria": "demo", "match": tc.match, "provides": &falseValue,
		})
		if err != nil || got == nil || len(runner.commands) != 1 {
			t.Fatalf("match=%s got=%#v err=%v calls=%d", tc.match, got, err, len(runner.commands))
		}
		want := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "search", tc.flag, "--provides", "demo"}
		if got := zypperCommandArgs(runner.commands[0]); !reflect.DeepEqual(got, want) {
			t.Fatalf("match=%s argv=%#v want=%#v", tc.match, got, want)
		}
	}

	nilValue := (*bool)(nil)
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(`<stream><solvable name="demo"/></stream>`)})
	if _, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "search", map[string]any{
		"criteria": "demo", "provides": nilValue,
	}); err != nil || len(runner.commands) != 1 {
		t.Fatalf("nil option err=%v calls=%d", err, len(runner.commands))
	}
	if want := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "search", "demo"}; !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), want) {
		t.Fatalf("nil option argv=%#v want=%#v", zypperCommandArgs(runner.commands[0]), want)
	}
}

func TestZypperSearchNoResultsAndXMLBounds(t *testing.T) {
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(`<stream/>`)})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "search", map[string]any{"criteria": "missing"})
	if got != nil || err == nil || err.Error() != "No packages found matching 'missing'" || len(runner.commands) != 1 {
		t.Fatalf("no results got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	if _, err := zypperParseSearch(context.Background(), `<stream/>`, "bad\ncriteria-secret"); err == nil || strings.Contains(err.Error(), "criteria-secret") {
		t.Fatalf("unsafe no-result error=%v", err)
	}

	deep := `<stream>` + strings.Repeat("<node>", 129) + strings.Repeat("</node>", 129) + `</stream>`
	items := `<stream>` + strings.Repeat(`<solvable name="demo"/>`, zypperLowpkgMaxItems+1) + `</stream>`
	for _, output := range []string{"", "not xml", "<a/><b/>", deep, items} {
		rt, runner = zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(output)})
		got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "search", map[string]any{"criteria": "demo"})
		if got != nil || err == nil || len(runner.commands) != 1 {
			t.Fatalf("output=%q got=%#v err=%v calls=%d", output, got, err, len(runner.commands))
		}
	}
}

func TestZypperSearchRedactsXMLDecoderDetails(t *testing.T) {
	const marker = "xml-secret-mismatch-marker"
	output := `<stream><` + marker + `></stream>`

	_, err := zypperParseSearch(context.Background(), output, "criteria-secret")
	if err == nil {
		t.Fatal("malformed XML unexpectedly parsed")
	}
	if got := err.Error(); got != errZypperSearchInvalidXML.Error() || strings.Contains(got, marker) || strings.Contains(got, "criteria-secret") {
		t.Fatalf("decoder details leaked: %q", got)
	}
}

func TestZypperSearchRetcodesErrorsCancellationAndOutputBounds(t *testing.T) {
	valid := []byte(`<stream><solvable name="demo"/></stream>`)
	for _, code := range []int{0, 6, 100, 101, 102, 103, 106, 107} {
		rt, runner := zypperLowpkgRuntime(process.CommandResult{ExitCode: code, Stdout: valid})
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "search", map[string]any{"criteria": "demo"})
		if err != nil || got == nil || len(runner.commands) != 1 {
			t.Fatalf("retcode=%d got=%#v err=%v calls=%d", code, got, err, len(runner.commands))
		}
	}
	for _, result := range []process.CommandResult{
		{Err: errors.New("runner failure")},
		{ExitCode: 1, Stderr: []byte("secret stderr")},
		{ExitCode: 7},
		{StdoutTruncated: true},
		{StderrTruncated: true},
		{Stdout: make([]byte, zypperLowpkgOutputLimit+1)},
		{Stderr: make([]byte, zypperLowpkgOutputLimit+1)},
	} {
		rt, runner := zypperLowpkgRuntime(result)
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "search", map[string]any{"criteria": "demo"})
		if got != nil || err == nil || len(runner.commands) != 1 {
			t.Fatalf("result=%#v got=%#v err=%v calls=%d", result, got, err, len(runner.commands))
		}
		if strings.Contains(err.Error(), "secret stderr") {
			t.Fatalf("error leaked command output: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := zypperLowpkgRuntime()
	got, err := zypperLowpkgProvider().Zypper(ctx, rt, "search", map[string]any{"criteria": "demo"})
	if got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("pre-cancel got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	ctx, cancel = context.WithCancel(context.Background())
	cancelRunner := &zypperCancelRunner{cancel: cancel}
	got, err = zypperLowpkgProvider().Zypper(ctx, &runtime.Runtime{Runner: cancelRunner}, "search", map[string]any{"criteria": "demo"})
	if got != nil || !errors.Is(err, context.Canceled) || len(cancelRunner.calls) != 1 {
		t.Fatalf("post-cancel got=%#v err=%v calls=%d", got, err, len(cancelRunner.calls))
	}

	for _, manager := range []string{"apt", "yum"} {
		rt, runner = zypperLowpkgRuntime()
		got, err = (&commandProvider{spec: spec{manager: manager}}).Zypper(context.Background(), rt, "search", map[string]any{"criteria": "demo"})
		if got != nil || !errors.Is(err, ErrUnsupportedZypper) || len(runner.commands) != 0 {
			t.Fatalf("manager=%s got=%#v err=%v calls=%d", manager, got, err, len(runner.commands))
		}
	}
}
