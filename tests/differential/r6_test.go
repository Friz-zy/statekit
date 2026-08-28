// R6 is platform-scoped: on Linux the registry deliberately filters all
// Darwin providers, so a Linux registry-vs-catalog count would falsely report
// every macOS function as pending. This report reconciles the Darwin source
// catalog against the explicitly registered Darwin surfaces and records the
// runtime limitation separately; the blocking gate is GOOS=darwin go build.
package differential

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type r6FamilyReport struct {
	Catalog       int      `yaml:"catalog_functions"`
	Public        int      `yaml:"public_functions"`
	Private       int      `yaml:"private_functions"`
	PortedPublic  int      `yaml:"ported_public"`
	PendingPublic []string `yaml:"pending_public,omitempty"`
	Platform      string   `yaml:"platform"`
	Scenarios     []string `yaml:"differential_scenarios"`
}

type r6Report struct {
	Round         string                    `yaml:"round"`
	Platform      string                    `yaml:"platform"`
	RuntimeStatus string                    `yaml:"runtime_status"`
	Families      map[string]r6FamilyReport `yaml:"families"`
	Totals        r6ReportTotals            `yaml:"totals"`
}

type r6ReportTotals struct {
	Catalog int `yaml:"catalog_functions"`
	Public  int `yaml:"public_functions"`
	Ported  int `yaml:"ported_public"`
}

type r6CoverageFile struct {
	Implemented struct {
		Exec []string `yaml:"exec"`
	} `yaml:"implemented"`
}

var r6ScopeFamilies = []string{
	"mac_user", "mac_group", "mac_brew_pkg", "mac_portspkg", "mac_pkgutil",
	"macpackage", "mac_service", "macdefaults", "mac_keychain",
	"mac_softwareupdate", "mac_desktop", "mac_assistive", "mac_xattr", "mac_power",
}

var r6ScopeModule = map[string]string{
	"mac_user":           "user",
	"mac_group":          "group",
	"mac_brew_pkg":       "pkg",
	"mac_portspkg":       "pkg",
	"mac_pkgutil":        "pkgutil",
	"macpackage":         "macpackage",
	"mac_service":        "service",
	"macdefaults":        "macdefaults",
	"mac_keychain":       "keychain",
	"mac_softwareupdate": "softwareupdate",
	"mac_desktop":        "desktop",
	"mac_assistive":      "assistive",
	"mac_xattr":          "xattr",
	"mac_power":          "power",
}

var r6ScopeScenarios = map[string][]string{
	"mac_user":           {"user.dscl-account-lifecycle", "user.auto-login-and-legacy-dscl"},
	"mac_group":          {"group.dseditgroup-membership-and-gid"},
	"mac_brew_pkg":       {"pkg.homebrew-json-lifecycle-and-pins", "pkg.cask-formula-trust"},
	"mac_portspkg":       {"pkg.macports-active-and-outdated"},
	"mac_pkgutil":        {"pkgutil.receipts-install-forget"},
	"macpackage":         {"macpackage.installer-app-dmg-and-xar"},
	"mac_service":        {"service.launchd-plist-discovery-and-lifecycle"},
	"macdefaults":        {"macdefaults.xml-plist-nested-write-delete"},
	"mac_keychain":       {"keychain.security-and-pkcs12-inspection"},
	"mac_softwareupdate": {"softwareupdate.modern-and-legacy-list-filters"},
	"mac_desktop":        {"desktop.osascript-session-and-say"},
	"mac_assistive":      {"assistive.tcc-schema-lifecycle"},
	"mac_xattr":          {"xattr.attribute-lifecycle-and-utf8"},
	"mac_power":          {"power.systemsetup-validation-and-confirmation"},
}

func r6TargetName(source, function string) string {
	alias := function
	if strings.HasSuffix(alias, "_") {
		alias = strings.TrimSuffix(alias, "_")
	}
	return r6ScopeModule[source] + "." + alias
}

func TestR6DifferentialScopeReport(t *testing.T) {
	coverageData, err := os.ReadFile(filepath.Join("..", "..", "docs", "catalog", "coverage.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var coverage r6CoverageFile
	if err := yaml.Unmarshal(coverageData, &coverage); err != nil {
		t.Fatal(err)
	}
	implemented := map[string]bool{}
	for _, name := range coverage.Implemented.Exec {
		implemented[name] = true
	}
	report := r6Report{
		Round:         "R6",
		Platform:      "darwin",
		RuntimeStatus: "Darwin source registration reconciled; local runtime requires a macOS runner (GOOS=darwin cross-build is the available gate)",
		Families:      map[string]r6FamilyReport{},
	}
	for _, family := range r6ScopeFamilies {
		catalogNames := loadCatalogFunctionNames(t, family)
		fam := r6FamilyReport{
			Catalog:   len(catalogNames),
			Platform:  "darwin",
			Scenarios: r6ScopeScenarios[family],
		}
		for _, name := range catalogNames {
			if strings.HasPrefix(name, "_") {
				fam.Private++
				continue
			}
			fam.Public++
			// The generated implementation inventory is produced by the
			// same scanner that feeds coverage. It proves every source
			// symbol has a corresponding Darwin registration name; the
			// separate GOOS=darwin build gate proves the provider tree
			// compiles. Linux registry names are intentionally not used
			// here because platform filtering would produce false pending
			// rows.
			target := r6TargetName(family, name)
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
	path := filepath.Join("..", "..", "docs", "differential", "R6", "report.yaml")
	want := "# Generated by tests/differential (TestR6DifferentialScopeReport); do not edit.\n" + string(encoded)
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
	t.Fatalf("R6 differential scope report stale; run UPDATE_DIFFERENTIAL=1 go test ./tests/differential")
}
