package facts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestGoldenPlatformFixtures verifies every per-OS parser against recorded
// tool output from real systems (plans/porting.md E4: golden facts fixtures
// per OS image). Each testdata/<platform> directory carries the raw tool
// output plus the expected typed facts.
func TestGoldenPlatformFixtures(t *testing.T) {
	cases := []struct {
		dir      string
		filename string
		parse    func([]byte) OSFacts
	}{
		{dir: "darwin", filename: "sw_vers.out", parse: parseSwVers},
		{dir: "windows", filename: "cim.json", parse: parseWinCIM},
		{dir: "freebsd", filename: "sysctl.out", parse: parseBsdSysctl},
		{dir: "openbsd", filename: "sysctl.out", parse: parseBsdSysctl},
	}
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", tc.dir, tc.filename))
			if err != nil {
				t.Fatalf("recorded output: %v", err)
			}
			wantRaw, err := os.ReadFile(filepath.Join("testdata", tc.dir, "expected.json"))
			if err != nil {
				t.Fatalf("expected facts: %v", err)
			}
			var want OSFacts
			if err := json.Unmarshal(wantRaw, &want); err != nil {
				t.Fatalf("decode expected: %v", err)
			}
			got := tc.parse(raw)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("parsed facts = %+v, want %+v", got, want)
			}
		})
	}
}

func TestParseWinCIMAcceptsArrayForm(t *testing.T) {
	out := []byte(`[
  {
    "Caption": "Microsoft Windows Server 2022 Standard",
    "Version": "10.0.20348",
    "BuildNumber": "20348"
  }
]`)
	got := parseWinCIM(out)
	if got.ID != FamilyWindows || got.Name != "Windows Server 2022 Standard" ||
		got.Version != "10.0.20348" || got.Build != "20348" {
		t.Fatalf("array-form CIM parsed = %+v", got)
	}
}

func TestParsersDegradeToEmptyOnGarbage(t *testing.T) {
	garbage := []byte("command not found\npartial")
	if got := parseSwVers(garbage); got != (OSFacts{}) {
		t.Fatalf("sw_vers garbage = %+v", got)
	}
	if got := parseWinCIM(garbage); got != (OSFacts{}) {
		t.Fatalf("CIM garbage = %+v", got)
	}
	if got := parseBsdSysctl(garbage); got != (OSFacts{}) {
		t.Fatalf("sysctl garbage = %+v", got)
	}
	if got := parseBsdSysctl(nil); got != (OSFacts{}) {
		t.Fatalf("empty sysctl = %+v", got)
	}
}

// TestNilRunnerAndZeroValueSafe pins the runner-independent contracts: tool
// helpers never execute with a nil Runner, and a zero Facts value resolves
// the family-driven package manager to empty instead of panicking.
func TestNilRunnerAndZeroValueSafe(t *testing.T) {
	if got := runTool(nil, "sysctl", "-n", "kern.ostype"); got != "" {
		t.Fatalf("nil-runner runTool = %q", got)
	}
	if got := runShellTool(nil, "Get-Date"); got != "" {
		t.Fatalf("nil-runner runShellTool = %q", got)
	}
	f := &Facts{}
	if got := f.PackageManager(); got != "" {
		t.Fatalf("zero PackageManager = %q", got)
	}
}

func TestManagerCandidatesCoverNewFamilies(t *testing.T) {
	for _, family := range []string{FamilyMacOS, FamilyWindows, FamilyFreeBSD, FamilyOpenBSD, FamilyNetBSD} {
		if len(managerCandidates[family]) == 0 {
			t.Fatalf("family %q has no package manager candidates", family)
		}
	}
}
