package main

import (
	"strings"
	"testing"
)

const sampleModule = `# -*- coding: utf-8 -*-
"""
Sample module docstring.
"""

__virtualname__ = "pkg"


def __virtual__():
    return __virtualname__


def install(
    name=None,
    pkgs=None,
    version='1.2.3',
    refresh=True,
    extra={"a": 1, "b": [2]},
):
    """
    Install the named package.

    CLI Example:

    .. code-block:: bash

        salt '*' pkg.install curl
    """
    ret = __salt__["cmd.run"](["echo", name])
    utils_ret = __utils__["files.expanduser"]("~")
    return ret


def remove(name):
    """Remove the package."""
    return __salt__["pkg.remove"](name)
`

func TestParseModule(t *testing.T) {
	doc := parseModule("exec", "salt/modules/sample.py", "sample", sampleModule)

	if doc.Module != "pkg" || !doc.Virtual {
		t.Fatalf("module = %q virtual=%v; want pkg/true", doc.Module, doc.Virtual)
	}

	byName := map[string]Entry{}
	for _, fn := range doc.Functions {
		byName[fn.Function] = fn
	}
	if _, ok := byName["__virtual__"]; ok {
		t.Fatal("dunder functions must be excluded from entries")
	}
	if len(doc.Functions) != 2 {
		t.Fatalf("functions = %d, want 2 (%v)", len(doc.Functions), names(doc.Functions))
	}

	install := byName["install"]
	wantParams := []Parameter{
		{Name: "name", Default: strPtr("None")},
		{Name: "pkgs", Default: strPtr("None")},
		{Name: "version", Default: strPtr("'1.2.3'")},
		{Name: "refresh", Default: strPtr("True")},
		{Name: "extra", Default: strPtr(`{"a": 1, "b": [2]}`)},
	}
	if len(install.Parameters) != len(wantParams) {
		t.Fatalf("params = %+v", install.Parameters)
	}
	for i, p := range install.Parameters {
		if p.Name != wantParams[i].Name {
			t.Fatalf("param[%d] = %q want %q", i, p.Name, wantParams[i].Name)
		}
		if (p.Default == nil) != (wantParams[i].Default == nil) ||
			(p.Default != nil && *p.Default != *wantParams[i].Default) {
			t.Fatalf("param[%d] default = %v want %v", i, p.Default, wantParams[i].Default)
		}
	}
	if install.Summary != "Install the named package." {
		t.Fatalf("summary = %q", install.Summary)
	}
	deps := strings.Join(install.ExecutionDependencies, ",")
	if !strings.Contains(deps, "cmd.run") {
		t.Fatalf("execution dependencies missing cmd.run: %v", install.ExecutionDependencies)
	}
	if got := strings.Join(install.UtilityDependencies, ","); !strings.Contains(got, "files.expanduser") || len(install.UtilityDependencies) != 1 {
		t.Fatalf("utility dependencies = %v", install.UtilityDependencies)
	}

	removeEntry := byName["remove"]
	if removeEntry.Summary != "Remove the package." {
		t.Fatalf("remove summary = %q", removeEntry.Summary)
	}
	if len(removeEntry.Parameters) != 1 || removeEntry.Parameters[0].Default != nil {
		t.Fatalf("required param must have nil default: %+v", removeEntry.Parameters)
	}
}

func TestStripDocstringsAndComments(t *testing.T) {
	src := "# a comment with pkg.install\ndoc = \"\"\"\n__salt__['fake.decoy']\n\"\"\"\nreal = __salt__['real.dep']\n"
	stripped := stripDocstrings(src)
	if strings.Contains(stripped, "decoy") {
		t.Fatalf("docstring content survived stripping:\n%s", stripped)
	}
	if strings.Contains(stripped, "comment") {
		t.Fatalf("comment content survived stripping:\n%s", stripped)
	}
	if !strings.Contains(stripped, "'real.dep'") {
		t.Fatalf("live code damaged by stripping:\n%s", stripped)
	}
}

func TestSplitTopLevelEdgeCases(t *testing.T) {
	got := splitTopLevel(`a, f(1, 2), {"k": "x,y"}, 'lit,eral', b`)
	want := []string{`a`, ` f(1, 2)`, ` {"k": "x,y"}`, ` 'lit,eral'`, ` b`}
	if len(got) != len(want) {
		t.Fatalf("split = %q", got)
	}
	for i := range want {
		if strings.TrimSpace(got[i]) != strings.TrimSpace(want[i]) {
			t.Fatalf("split[%d] = %q want %q", i, got[i], want[i])
		}
	}
}

func TestIndexDefaultIgnoresComparisons(t *testing.T) {
	if got := indexDefault("a == b"); got != -1 {
		t.Fatalf("== misread as default at %d", got)
	}
	if got := indexDefault("d={'x': '=y'}"); got != 1 {
		t.Fatalf("default index = %d, want 1", got)
	}
	if got := indexDefault("name"); got != -1 {
		t.Fatalf("plain param misread as default at %d", got)
	}
}

func TestCountTestFunctions(t *testing.T) {
	src := "def test_one():\n    pass\n\n\ndef helper():\n    pass\n\n\ndef test_two(x):\n    pass\n"
	if n := countTestFunctions(src); n != 2 {
		t.Fatalf("count = %d, want 2", n)
	}
}

func names(entries []Entry) string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Function)
	}
	return strings.Join(out, ",")
}

func strPtr(s string) *string { return &s }
