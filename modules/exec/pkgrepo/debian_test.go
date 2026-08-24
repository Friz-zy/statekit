package pkgrepo

import (
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
)

// Engine tests mapped onto saltstack/tests/pytests/unit/modules/test_aptpkg.py
// (test__parse_source, test__skip_source, test_sourceslist_*) plus the
// salt.utils.pkg.deb behaviors those tests exercise indirectly.

func strPtr(s string) *string { return &s }

func boolPtr(b bool) *bool { return &b }

func factsForTesting() *facts.Facts { return facts.ForTesting(facts.Overrides{}) }

// redirectPaths points the engine at the /testbed layout for the duration
// of the test, mirroring Salt's _APT_SOURCES_LIST/_APT_SOURCES_PARTSDIR
// patches.
func redirectPaths(t *testing.T) {
	t.Helper()
	savedList, savedParts := aptSourcesList, aptSourcesParts
	aptSourcesList = "/testbed/sources.list"
	aptSourcesParts = "/testbed/sources.list.d/"
	t.Cleanup(func() {
		aptSourcesList, aptSourcesParts = savedList, savedParts
	})
}

func mustWrite(rt *runtime.Runtime, path, content string) {
	if err := rt.FS.MkdirAll(dirOf(path), 0o755); err != nil {
		panic(err)
	}
	if err := rt.FS.WriteFile(path, []byte(content), 0o644); err != nil {
		panic(err)
	}
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "/"
}

// Mirrors test__parse_source.
func TestParseSource(t *testing.T) {
	cases := []struct {
		line     string
		ok       bool
		invalid  bool
		disabled bool
	}{
		{line: "", invalid: true},
		{line: "#", invalid: true, disabled: true},
		{line: "##", invalid: true, disabled: true},
		{line: "# comment", invalid: true, disabled: true},
		{line: "## comment", invalid: true, disabled: true},
		{line: "deb #", invalid: true},
		{line: "# deb #", invalid: true, disabled: true},
		{line: "deb [ invalid line", invalid: true},
		{line: "# deb http://debian.org/debian/ stretch main\n", ok: true, disabled: true},
		{line: "deb http://debian.org/debian/ stretch main # comment\n", ok: true},
		{line: "deb [trusted=yes] http://debian.org/debian/ stretch main\n", ok: true},
		{
			line: "# deb cdrom:[Debian GNU/Linux 11.4.0 _Bullseye_ - Official amd64 NETINST 20220709-10:31]/ bullseye main\n" +
				"\n" +
				"deb http://httpredir.debian.org/debian bullseye main\n" +
				"deb-src http://httpredir.debian.org/debian bullseye main\n",
			ok:       true,
			disabled: true,
		},
	}
	for _, c := range cases {
		entry, err := newSourceEntry(c.line, "")
		if err != nil {
			t.Fatalf("parse(%q) raised %v", c.line, err)
		}
		parsed, err := entry.parse(c.line)
		if err != nil {
			t.Fatalf("parse(%q) raised %v", c.line, err)
		}
		if parsed != c.ok || entry.invalid != c.invalid || entry.disabled != c.disabled {
			t.Fatalf("parse(%q) = ok=%v invalid=%v disabled=%v; want ok=%v invalid=%v disabled=%v",
				c.line, parsed, entry.invalid, entry.disabled, c.ok, c.invalid, c.disabled)
		}
	}
}

// Mirrors test__skip_source; the bracketed arm needs a synthetic entry
// because parsed entries never carry a type while marked invalid.
func TestSkipSource(t *testing.T) {
	valid := &sourceEntry{
		typ:  "deb",
		uri:  "http://cdn-aws.deb.debian.org/debian",
		line: "deb http://cdn-aws.deb.debian.org/debian stretch main\n",
	}
	if skip, err := skipSource(valid); err != nil || skip {
		t.Fatalf("valid source skipped: %v, %v", skip, err)
	}

	badType := &sourceEntry{
		invalid: true,
		typ:     "ded",
		uri:     "http://cdn-aws.deb.debian.org/debian",
		line:    "ded http://cdn-aws.deb.debian.org/debian stretch main\n",
	}
	if skip, err := skipSource(badType); err != nil || !skip {
		t.Fatalf("invalid type not skipped: %v, %v", skip, err)
	}

	bracketed := &sourceEntry{
		invalid: true,
		typ:     "deb",
		uri:     "http://cdn-aws.deb.debian.org/debian",
		line:    "deb [http://cdn-aws.deb.debian.org/debian] stretch main\n",
	}
	if skip, err := skipSource(bracketed); err != nil || skip {
		t.Fatalf("bracketed invalid source skipped: %v, %v", skip, err)
	}
}

// Mirrors test_sourceslist_architectures.
func TestSourcesListArchitectures(t *testing.T) {
	lines := []string{
		"deb [ arch=amd64 ] http://archive.ubuntu.com/ubuntu/ focal-updates main restricted",
		"deb [arch=amd64 ] http://archive.ubuntu.com/ubuntu/ focal-updates main restricted",
		"deb [arch=amd64 test=one ] http://archive.ubuntu.com/ubuntu/ focal-updates main restricted",
		"deb [arch=amd64,armel test=one ] http://archive.ubuntu.com/ubuntu/ focal-updates main restricted",
		"deb [ arch=amd64,armel test=one ] http://archive.ubuntu.com/ubuntu/ focal-updates main restricted",
		"deb [ arch=amd64,armel test=one] http://archive.ubuntu.com/ubuntu/ focal-updates main restricted",
		"deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ focal-updates main restricted",
	}
	for _, line := range lines {
		redirectPaths(t)
		rt := &runtime.Runtime{FS: runtime.NewMemoryFS(), Facts: factsForTesting()}
		mustWrite(rt, "/testbed/sources.list", line)
		sources := newSourcesList(rt)
		count := 0
		for _, item := range sources.list {
			se, ok := item.(*sourceEntry)
			if !ok {
				t.Fatalf("%q: unexpected entry type %T", line, item)
			}
			count++
			if se.typ != "deb" ||
				se.uri != "http://archive.ubuntu.com/ubuntu/" ||
				!equalSlices(se.comps, []string{"main", "restricted"}) ||
				se.dist != "focal-updates" {
				t.Fatalf("%q parsed wrong: %+v", line, se)
			}
			wantArch := []string{"amd64"}
			if strings.Contains(line, ",") {
				wantArch = []string{"amd64", "armel"}
			}
			if !equalSlices(se.architectures, wantArch) {
				t.Fatalf("%q architectures = %v; want %v", line, se.architectures, wantArch)
			}
		}
		if count != 1 {
			t.Fatalf("%q produced %d entries", line, count)
		}
	}
}

// Mirrors test_sourceslist_subdirectory_no_exception.
func TestSourcesListSubdirectoryNoException(t *testing.T) {
	redirectPaths(t)
	rt := &runtime.Runtime{FS: runtime.NewMemoryFS(), Facts: factsForTesting()}
	if err := rt.FS.MkdirAll("/testbed/sources.list.d/backup.list", 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(rt, "/testbed/sources.list.d/backup/test.list", "deb http://archive.ubuntu.com/ubuntu/ focal main")
	sources := newSourcesList(rt)
	if len(sources.list) != 0 {
		t.Fatalf("expected zero entries, got %d", len(sources.list))
	}
}

// Mirrors string_to_bool coverage exercised across the deb822 batteries.
func TestStringToBool(t *testing.T) {
	for _, s := range []string{"no", "false", "without", "off", "disable", "DisAble", "WithOUT", "0"} {
		v, err := stringToBool(s)
		if err != nil || v {
			t.Fatalf("stringToBool(%q) = %v, %v", s, v, err)
		}
	}
	for _, s := range []string{"yes", "true", "with", "on", "enable", "EnAble", "With", "1"} {
		v, err := stringToBool(s)
		if err != nil || !v {
			t.Fatalf("stringToBool(%q) = %v, %v", s, v, err)
		}
	}
	if _, err := stringToBool("garbage"); err == nil || err.Error() != "Unable to convert to boolean: garbage" {
		t.Fatalf("garbage error = %v", err)
	}
}

// Mirrors the deb822_repo_bool_false_file / deb822_repo_bool_true_file
// fixture batteries feeding test_get_repo_deb822_with_{false,true}.
func TestDeb822EnabledParsing(t *testing.T) {
	falseSet := []string{"no", "false", "without", "off", "disable", "DisAble", "WithOUT", "0"}
	trueSet := []string{"yes", "true", "with", "on", "enable", "EnAble", "With", "1"}
	for _, set := range []struct {
		values   []string
		disabled bool
	}{
		{falseSet, true},
		{trueSet, false},
	} {
		for _, value := range set.values {
			content := "Types: deb\nURIs: http://u/\nSuites: noble\nComponents: main\nEnabled: " + value + "\n"
			section, err := parseDeb822Section(content)
			if err != nil {
				t.Fatal(err)
			}
			entry := newDeb822SourceEntryFromSection(section, "/testbed/x.sources")
			disabled, err := entry.Disabled()
			if err != nil {
				t.Fatalf("Enabled: %s raised %v", value, err)
			}
			if disabled != set.disabled {
				t.Fatalf("Enabled: %s -> disabled=%v; want %v", value, disabled, set.disabled)
			}
		}
	}
}

// Pins the classic RepoLine rendering quirks: option rebuild, trusted=no
// dropping, and comment round-tripping.
func TestSourceEntryRepoLineRendering(t *testing.T) {
	entry, err := newSourceEntry("deb [trusted=yes] http://u/ focal main\n", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := entry.String(); got != "deb [trusted=yes] http://u/ focal main" {
		t.Fatalf("trusted=yes round trip = %q", got)
	}

	entry, err = newSourceEntry("deb [trusted=no] http://u/ focal main\n", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := entry.String(); got != "deb http://u/ focal main" {
		t.Fatalf("trusted=no round trip = %q", got)
	}

	entry, err = newSourceEntry("deb [arch=i386] http://u/ focal main\n", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := entry.String(); got != "deb [arch=i386] http://u/ focal main" {
		t.Fatalf("arch round trip = %q", got)
	}

	entry, err = newSourceEntry("deb http://u/ focal main # note\n", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := entry.String(); got != "deb http://u/ focal main # note" {
		t.Fatalf("comment round trip = %q", got)
	}
}

func TestSplitSourceLineBrackets(t *testing.T) {
	got := splitSourceLine("deb [arch=amd64,test=one] http://u/ focal main")
	want := []string{"deb", "[arch=amd64,test=one]", "http://u/", "focal", "main"}
	if !equalSlices(got, want) {
		t.Fatalf("splitSourceLine = %v; want %v", got, want)
	}
	got = splitSourceLine("")
	if len(got) != 0 {
		t.Fatalf("empty split = %v", got)
	}
}
