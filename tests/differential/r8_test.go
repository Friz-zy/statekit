// R8 is the BSD/Solaris platform-split round: on Linux the registry
// deliberately filters every freebsd/solaris-tagged provider, so a
// Linux registry-vs-catalog count would falsely report all of those
// functions as pending. This report reconciles the round's source
// catalogs (pkgng, pw_user, pw_group; solaris_user, solaris_group,
// solaris_shadow, solaris_system, solaris_fmadm, rbac_solaris,
// smf_service, at_solaris, solarispkg, solarisipspkg) against the generated implementation
// inventory and records the runtime limitation separately; the
// blocking gates are the untagged Linux mock tests plus the
// GOOS=freebsd cross-build. Official Go distributions list solaris/amd64
// and illumos/amd64 compile targets, but this host has no native Solaris or
// illumos runtime runner; the Solaris surface is validated by the untagged
// mock tests and compile-target evidence without claiming unrun runtime
// behavior.
package differential

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type r8FamilyReport struct {
	Catalog       int      `yaml:"catalog_functions"`
	Public        int      `yaml:"public_functions"`
	Private       int      `yaml:"private_functions"`
	PortedPublic  int      `yaml:"ported_public"`
	PendingPublic []string `yaml:"pending_public,omitempty"`
	Platform      string   `yaml:"platform"`
}

type r8Report struct {
	Round         string                    `yaml:"round"`
	Platform      string                    `yaml:"platform"`
	RuntimeStatus string                    `yaml:"runtime_status"`
	Families      map[string]r8FamilyReport `yaml:"families"`
	Totals        r8ReportTotals            `yaml:"totals"`
}

type r8ReportTotals struct {
	Catalog int `yaml:"catalog_functions"`
	Public  int `yaml:"public_functions"`
	Ported  int `yaml:"ported_public"`
}

type r8CoverageFile struct {
	Implemented struct {
		Exec []string `yaml:"exec"`
	} `yaml:"implemented"`
}

var r8ScopeFamilies = []string{
	"pkgng", "pw_user", "pw_group",
	"solaris_user", "solaris_group", "solaris_shadow", "solaris_system", "solaris_fmadm",
	"rbac_solaris", "smf_service", "at_solaris", "solarispkg", "solarisipspkg",
}

// r8ScopeModule maps each platform-split Salt source module onto the Go
// virtual family that carries its registration names.
var r8ScopeModule = map[string]string{
	"pkgng":          "pkg",
	"pw_user":        "user",
	"pw_group":       "group",
	"solaris_user":   "user",
	"solaris_group":  "group",
	"solaris_shadow": "shadow",
	"solaris_system": "system",
	"solaris_fmadm":  "fmadm",
	"rbac_solaris":   "rbac",
	"smf_service":    "service",
	"at_solaris":     "at",
	"solarispkg":     "pkg",
	"solarisipspkg":  "pkg",
}

// r8ScopePlatform records each family's source platform.
var r8ScopePlatform = map[string]string{
	"pkgng":          "freebsd",
	"pw_user":        "freebsd",
	"pw_group":       "freebsd",
	"solaris_user":   "solaris",
	"solaris_group":  "solaris",
	"solaris_shadow": "solaris",
	"solaris_system": "solaris",
	"solaris_fmadm":  "solaris",
	"rbac_solaris":   "solaris",
	"smf_service":    "solaris",
	"at_solaris":     "solaris",
	"solarispkg":     "solaris",
	"solarisipspkg":  "solaris",
}

// r8ScopeFunctionAliases records source-level __func_alias__ names that are
// intentionally exposed under one canonical StateKit name.
var r8ScopeFunctionAliases = map[string]map[string]string{
	"solaris_fmadm": {"list_records": "list"},
	"smf_service":   {"reload_": "reload"},
}

// at_solaris._atq is listed by the pinned catalog and is an intentional
// StateKit execution surface for this round. Keep it in the six-function
// public count even though its source spelling begins with an underscore.
var r8ScopePublicUnderscores = map[string]map[string]bool{
	"at_solaris": {"_atq": true},
}

func r8TargetName(source, function string) string {
	alias := function
	if aliases, ok := r8ScopeFunctionAliases[source]; ok {
		if canonical, ok := aliases[alias]; ok {
			alias = canonical
		}
	}
	if strings.HasSuffix(alias, "_") {
		alias = strings.TrimSuffix(alias, "_")
	}
	return r8ScopeModule[source] + "." + alias
}

func TestR8DifferentialScopeReport(t *testing.T) {
	coverageData, err := os.ReadFile(filepath.Join("..", "..", "docs", "catalog", "coverage.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var coverage r8CoverageFile
	if err := yaml.Unmarshal(coverageData, &coverage); err != nil {
		t.Fatal(err)
	}
	implemented := map[string]bool{}
	for _, name := range coverage.Implemented.Exec {
		implemented[name] = true
	}
	report := r8Report{
		Round:    "R8",
		Platform: "freebsd+solaris",
		RuntimeStatus: "FreeBSD and Solaris source registration reconciled; FreeBSD runtime requires " +
			"a native runner; official Go compile targets include solaris/amd64 and illumos/amd64, " +
			"but no native Solaris or illumos runtime runner is attached. Untagged Linux mock tests " +
			"and cross-builds verify contracts and compilation only; no unrun Solaris runtime " +
			"behavior is claimed",
		Families: map[string]r8FamilyReport{},
	}
	for _, family := range r8ScopeFamilies {
		catalogNames := loadCatalogFunctionNames(t, family)
		fam := r8FamilyReport{Catalog: len(catalogNames), Platform: r8ScopePlatform[family]}
		for _, name := range catalogNames {
			publicUnderscore := false
			if names := r8ScopePublicUnderscores[family]; names != nil {
				publicUnderscore = names[name]
			}
			if strings.HasPrefix(name, "_") && !publicUnderscore {
				fam.Private++
				continue
			}
			fam.Public++
			// The generated implementation inventory is produced by the
			// same scanner that feeds coverage. It proves every source
			// symbol has a corresponding per-platform registration name;
			// the separate per-function Platforms() gating and the
			// untagged provider mock tests prove the surface itself.
			target := r8TargetName(family, name)
			if !implemented[target] {
				fam.PendingPublic = append(fam.PendingPublic, target)
				continue
			}
			fam.PortedPublic++
		}
		report.Totals.Catalog += fam.Catalog
		report.Totals.Public += fam.Public
		report.Totals.Ported += fam.PortedPublic
		report.Families[family] = fam
	}

	encoded, err := yaml.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "differential", "R8", "report.yaml")
	want := "# Generated by tests/differential (TestR8DifferentialScopeReport); do not edit.\n" + string(encoded)
	existing, readErr := os.ReadFile(path)
	if readErr == nil && string(existing) == want {
		return
	}
	if os.Getenv("UPDATE_DIFFERENTIAL") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("R8 differential scope report stale; run UPDATE_DIFFERENTIAL=1 go test ./tests/differential")
}
