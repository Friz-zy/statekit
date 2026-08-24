package debconfmod

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// Tests mapped onto saltstack/tests/pytests/unit/modules/test_debconfmod.py
// and saltstack/tests/pytests/unit/states/test_debconfmod.py.

const debconfSelections = `# Debconf preseeding
nullmailer\tshared/mailname\tstring\tserver.domain.tld
ferm\tferm/enable\tboolean\ttrue
dash\tdash/sh\tboolean\tdash-value
empty-pkg\tempty/question\tstring\t
`

type fakeRunner struct {
	calls       [][]string
	results     map[string]process.CommandResult
	onRunRecord func(argv []string) // optional extra capture
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	f.calls = append(f.calls, argv)
	if f.onRunRecord != nil {
		f.onRunRecord(argv)
	}
	if res, ok := f.results[strings.Join(argv, "\x00")]; ok {
		return res
	}
	return process.CommandResult{}
}

func debRT(t *testing.T, runner *fakeRunner, files map[string]string) *runtime.Runtime {
	t.Helper()
	savedWhich := whichBin
	whichBin = func(name string) string {
		if name == "debconf-get-selections" {
			return "/usr/bin/debconf-get-selections"
		}
		return ""
	}
	t.Cleanup(func() { whichBin = savedWhich })
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
			ID: "debian", Name: "Debian GNU/Linux", Family: facts.FamilyDebian,
		}}),
		Runner: runner,
	}
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	for path, content := range files {
		if err := rt.FS.MkdirAll(parentOf(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return rt
}

func boolPtr(b bool) *bool { return &b }

func parentOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "/"
}

func TestUnpackLines(t *testing.T) {
	lines := unpackLines(strings.ReplaceAll(debconfSelections, `\t`, "\t"))
	if len(lines) != 4 {
		t.Fatalf("lines = %#v", lines)
	}
	first := lines[0]
	if first.pkg != "nullmailer" || first.question != "shared/mailname" ||
		first.typ != "string" || first.value != "server.domain.tld" {
		t.Fatalf("first = %#v", first)
	}
	if lines[3].value != "" {
		t.Fatalf("empty value parsed as %q", lines[3].value)
	}

	// Comment lines never match.
	noComment := unpackLines("# just a comment")
	if len(noComment) != 0 {
		t.Fatalf("comment matched: %#v", noComment)
	}
}

func TestGetSelections(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{
		"debconf-get-selections": {Stdout: []byte(strings.ReplaceAll(debconfSelections, `\t`, "\t"))},
	}}
	rt := debRT(t, runner, nil)

	sel, err := getSelectionsFunc{}.Execute(context.Background(), rt, &GetSelectionsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	all := sel.(map[string][][]string)
	if len(all["nullmailer"]) != 1 || all["nullmailer"][0][0] != "shared/mailname" {
		t.Fatalf("nullmailer = %#v", all["nullmailer"])
	}

	// fetchempty=False drops empty-valued rows.
	sel, err = getSelectionsFunc{}.Execute(context.Background(), rt,
		&GetSelectionsArgs{FetchEmpty: boolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}
	all = sel.(map[string][][]string)
	if _, hasEmpty := all["empty-pkg"]; hasEmpty {
		t.Fatalf("empty rows kept despite fetchempty=False: %#v", all)
	}
}

func TestShow(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{
		"debconf-get-selections": {Stdout: []byte("nullmailer\tshared/mailname\tstring\tserver.domain.tld\n")},
	}}
	rt := debRT(t, runner, nil)

	got, err := showFunc{}.Execute(context.Background(), rt, &ShowArgs{Name: "nullmailer"})
	if err != nil {
		t.Fatal(err)
	}
	rows := got.([][]string)
	if len(rows) != 1 || rows[0][2] != "server.domain.tld" {
		t.Fatalf("show = %#v", got)
	}

	got, err = showFunc{}.Execute(context.Background(), rt, &ShowArgs{Name: "ghost"})
	if err != nil || got != nil {
		t.Fatalf("unknown show = %#v, %v; want nil", got, err)
	}
}

// Mirrors test_set_: the temp selections file content and cleanup.
func TestSet(t *testing.T) {
	var captured []string
	runner := &fakeRunner{onRunRecord: func(argv []string) { captured = append(captured, strings.Join(argv, " ")) }}
	rt := debRT(t, runner, nil)

	got, err := setFunc{}.Execute(context.Background(), rt, &SetArgs{
		Package: "package", Question: "question", Type: "type", Value: "value",
	})
	if err != nil || got != true {
		t.Fatalf("set = %#v, %v", got, err)
	}
	if len(captured) != 1 || !strings.HasPrefix(captured[0], "debconf-set-selections /tmp/salt-") {
		t.Fatalf("set argv = %#v", captured)
	}
	path := strings.TrimPrefix(captured[0], "debconf-set-selections ")
	if _, serr := rt.FS.Stat(path); serr == nil {
		t.Fatalf("temp file survived: %s", path)
	}
}

// Mirrors test_set_template: templating stays unsupported.
func TestSetTemplateUnsupported(t *testing.T) {
	rt := debRT(t, &fakeRunner{}, nil)
	_, err := setTemplateFunc{}.Execute(context.Background(), rt, &SetTemplateArgs{
		Path: "/testbed/in/selections", Template: "jinja",
	})
	var unsupported *runtime.UnsupportedError
	foundUnsupported := false
	for e := err; e != nil && !foundUnsupported; {
		if ue, is := e.(*runtime.UnsupportedError); is {
			unsupported = ue
			foundUnsupported = true
			break
		}
		type unwrapper interface{ Unwrap() error }
		if w, is := e.(unwrapper); is {
			e = w.Unwrap()
			continue
		}
		break
	}
	if !foundUnsupported || unsupported.Name != "cp.get_template" {
		t.Fatalf("error = %v", err)
	}
}

// Mirrors test_set_file with a local selections file.
func TestSetFile(t *testing.T) {
	runner := &fakeRunner{}
	rt := debRT(t, runner, map[string]string{
		"/testbed/in/pkg.selections": "pkg\tquestion\tstring\tvalue",
	})
	got, err := setFileFunc{}.Execute(context.Background(), rt, &SetFileArgs{
		Path: "/testbed/in/pkg.selections",
	})
	if err != nil || got != true {
		t.Fatalf("set_file = %#v, %v", got, err)
	}
	if len(runner.calls) != 1 ||
		strings.Join(runner.calls[0], " ") != "debconf-set-selections /testbed/in/pkg.selections" {
		t.Fatalf("argv = %#v", runner.calls)
	}

	// Remote scheme surfaces UnsupportedError.
	got, err = setFileFunc{}.Execute(context.Background(), rt, &SetFileArgs{
		Path: "salt://pkg.selections",
	})
	if got != false || err == nil {
		t.Fatalf("remote accepted: %#v, %v", got, err)
	}
}

func TestBackendGate(t *testing.T) {
	runner := &fakeRunner{}
	rt := debRT(t, runner, nil)
	rt.Facts = facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
		ID: "fedora", Family: facts.FamilyRedHat,
	}})
	_, err := getSelectionsFunc{}.Execute(context.Background(), rt, &GetSelectionsArgs{})
	if err == nil || err.Error() != "The debconfmod module could not be loaded: unsupported OS family" {
		t.Fatalf("family gate error = %v", err)
	}

	rt = debRT(t, runner, nil)
	saved := whichBin
	whichBin = func(string) string { return "" }
	defer func() { whichBin = saved }()
	_, err = getSelectionsFunc{}.Execute(context.Background(), rt, &GetSelectionsArgs{})
	if err == nil || !strings.Contains(err.Error(), "debconf-utils is not installed.") {
		t.Fatalf("toolchain gate error = %v", err)
	}
}
