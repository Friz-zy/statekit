package pkg

import (
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
)

func TestSolarisRuntimeSelectorUsesOneCanonicalProvider(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
		want    int
		probe   string
	}{
		{"solaris10", "5.10", 7, "pkg.list_pkgs"},
		{"solaris10-older", "5.9", 7, "pkg.list_pkgs"},
		{"solaris11", "5.11", 14, "pkg.refresh_db"},
		{"solaris12", "6.0", 14, "pkg.refresh_db"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := runtime.NewExecRegistry()
			f := facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilySolaris, Version: tc.version}})
			if err := RegisterForRuntime(reg, f); err != nil {
				t.Fatal(err)
			}
			if reg.Len() != tc.want {
				t.Fatalf("registry length=%d want=%d", reg.Len(), tc.want)
			}
			if _, ok := reg.Get(tc.probe); !ok {
				t.Fatalf("missing %s", tc.probe)
			}
			for _, name := range reg.Names() {
				if count := countName(reg, name); count != 1 {
					t.Fatalf("%s registrations=%d", name, count)
				}
			}
		})
	}
}

func countName(reg *runtime.ExecRegistry, target string) int {
	count := 0
	for _, name := range reg.Names() {
		if name == target {
			count++
		}
	}
	return count
}

func TestSolarisReleaseComparisonFailsClosedToIPSForUnknown(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{"5.10", false}, {"5.11", true}, {"6.1", true}, {"5.9", false}, {"", true}, {"invalid", true},
	} {
		if got := solarisIPSRelease(tc.version); got != tc.want {
			t.Fatalf("solarisIPSRelease(%q)=%t want=%t", tc.version, got, tc.want)
		}
	}
}
