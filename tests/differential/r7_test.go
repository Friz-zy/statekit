// R7 is Windows-scoped: Linux registry names intentionally exclude the
// Windows build-tag providers. This report reconciles Windows source catalogs
// with the generated implementation inventory and records that runtime
// validation requires a Windows runner; GOOS=windows cross-builds are the
// available local gate.
package differential

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type r7FamilyReport struct {
	Catalog       int      `yaml:"catalog_functions"`
	Public        int      `yaml:"public_functions"`
	Private       int      `yaml:"private_functions"`
	PortedPublic  int      `yaml:"ported_public"`
	PendingPublic []string `yaml:"pending_public,omitempty"`
	Platform      string   `yaml:"platform"`
}

type r7Report struct {
	Round         string                    `yaml:"round"`
	Platform      string                    `yaml:"platform"`
	RuntimeStatus string                    `yaml:"runtime_status"`
	Families      map[string]r7FamilyReport `yaml:"families"`
	Totals        r7ReportTotals            `yaml:"totals"`
}

type r7ReportTotals struct {
	Catalog int `yaml:"catalog_functions"`
	Public  int `yaml:"public_functions"`
	Ported  int `yaml:"ported_public"`
}

type r7ExecCoverage struct {
	Implemented []string `yaml:"exec"`
}
type r7StateCoverage struct {
	Implemented []string `yaml:"state"`
}
type r7CoverageFile struct {
	Implemented r7ExecCoverage `yaml:"implemented"`
	Execution   struct {
		Implemented int `yaml:"implemented"`
	} `yaml:"execution"`
	State struct {
		Implemented int `yaml:"implemented"`
	} `yaml:"state"`
}
type r7CatalogFile struct {
	Functions []struct {
		Function string `yaml:"function"`
	} `yaml:"functions"`
}

var r7ExecFamilies = []string{
	"reg", "win_useradd", "win_groupadd", "win_service", "win_pkg", "win_file",
	"win_firewall", "win_dns_client", "win_pki", "win_dacl", "win_event", "win_path",
	"win_iis", "win_servermanager", "win_smtp_server", "win_snmp", "win_wua",
}
var r7ExecTargets = map[string]string{
	"reg": "reg", "win_useradd": "user", "win_groupadd": "group", "win_service": "service",
	"win_pkg": "pkg", "win_file": "file", "win_firewall": "firewall", "win_dns_client": "win_dns_client",
	"win_pki": "win_pki", "win_dacl": "win_dacl", "win_event": "win_event", "win_path": "win_path",
	"win_iis": "win_iis", "win_servermanager": "win_servermanager", "win_smtp_server": "win_smtp_server",
	"win_snmp": "win_snmp", "win_wua": "win_wua",
}
var r7StateFamilies = []string{"win_firewall"}

func loadR7CatalogNames(t *testing.T, kind, family string) []string {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "catalog", kind, family+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("catalog %s/%s: %v", kind, family, err)
	}
	var catalog r7CatalogFile
	if err := yaml.Unmarshal(data, &catalog); err != nil {
		t.Fatalf("catalog %s/%s parse: %v", kind, family, err)
	}
	names := make([]string, 0, len(catalog.Functions))
	for _, fn := range catalog.Functions {
		names = append(names, fn.Function)
	}
	sort.Strings(names)
	return names
}

func r7Target(family, function string, state bool) string {
	if state {
		return "win_firewall." + function
	}
	return r7ExecTargets[family] + "." + function
}

func r7ImplementationSet(t *testing.T) (map[string]bool, map[string]bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "catalog", "coverage.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var coverage struct {
		Implemented struct {
			Exec  []string `yaml:"exec"`
			State []string `yaml:"state"`
		} `yaml:"implemented"`
	}
	if err := yaml.Unmarshal(data, &coverage); err != nil {
		t.Fatal(err)
	}
	execSet, stateSet := map[string]bool{}, map[string]bool{}
	for _, name := range coverage.Implemented.Exec {
		execSet[name] = true
	}
	for _, name := range coverage.Implemented.State {
		stateSet[name] = true
	}
	return execSet, stateSet
}

func TestR7DifferentialScopeReport(t *testing.T) {
	execSet, stateSet := r7ImplementationSet(t)
	report := r7Report{
		Round:         "R7",
		Platform:      "windows",
		RuntimeStatus: "Windows source registration reconciled; local runtime requires a Windows runner (GOOS=windows cross-build is the available gate)",
		Families:      map[string]r7FamilyReport{},
	}
	for _, family := range r7ExecFamilies {
		names := loadR7CatalogNames(t, "exec", family)
		fam := r7FamilyReport{Catalog: len(names), Platform: "windows"}
		for _, name := range names {
			if strings.HasPrefix(name, "_") {
				fam.Private++
				continue
			}
			fam.Public++
			target := r7Target(family, name, false)
			if !execSet[target] {
				fam.PendingPublic = append(fam.PendingPublic, target)
				continue
			}
			fam.PortedPublic++
		}
		report.Totals.Catalog += fam.Catalog
		report.Totals.Public += fam.Public
		report.Totals.Ported += fam.PortedPublic
		report.Families["exec/"+family] = fam
	}
	for _, family := range r7StateFamilies {
		names := loadR7CatalogNames(t, "states", family)
		fam := r7FamilyReport{Catalog: len(names), Platform: "windows"}
		for _, name := range names {
			if strings.HasPrefix(name, "_") {
				fam.Private++
				continue
			}
			fam.Public++
			target := r7Target(family, name, true)
			if !stateSet[target] {
				fam.PendingPublic = append(fam.PendingPublic, target)
				continue
			}
			fam.PortedPublic++
		}
		report.Totals.Catalog += fam.Catalog
		report.Totals.Public += fam.Public
		report.Totals.Ported += fam.PortedPublic
		report.Families["state/"+family] = fam
	}
	encoded, err := yaml.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "differential", "R7", "report.yaml")
	want := "# Generated by tests/differential (TestR7DifferentialScopeReport); do not edit.\n" + string(encoded)
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
	t.Fatalf("R7 differential scope report stale; run UPDATE_DIFFERENTIAL=1 go test ./tests/differential -run TestR7DifferentialScopeReport")
}
