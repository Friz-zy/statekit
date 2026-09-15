package differential

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/bootstrap"
	"github.com/friz-zy/statekit/internal/runtime"

	"gopkg.in/yaml.v3"
)

// R9.1 is the mockable broker-CLI round. It reconciles every public function
// from the pinned rabbitmq catalog against bootstrap registration without
// starting a broker. The module's untagged fake-runner suite supplies the
// command, parser, error, cancellation, bounds, and CLI evidence.
var r9ScopeFamily = "rabbitmq"

var r9Scenarios = []string{
	"rabbitmq.users-vhosts-permissions",
	"rabbitmq.password-check-and-status",
	"rabbitmq.policy-list-set-delete",
	"rabbitmq.plugin-list-enable-disable",
	"rabbitmq.federation-upstream-list-set-delete",
}

type r9FamilyReport struct {
	Catalog            int      `yaml:"catalog_functions"`
	Public             int      `yaml:"public_functions"`
	Private            int      `yaml:"private_functions"`
	Registered         int      `yaml:"registered_public"`
	PendingPublic      []string `yaml:"pending_public,omitempty"`
	Platform           string   `yaml:"platform"`
	Scenarios          []string `yaml:"differential_scenarios"`
	SourceReference    string   `yaml:"source_reference"`
	SourceTests        string   `yaml:"source_tests"`
	Evidence           []string `yaml:"evidence"`
	CompatibilityNotes []string `yaml:"compatibility_notes"`
}

type r9Report struct {
	Round            string                    `yaml:"round"`
	Platform         string                    `yaml:"platform"`
	RuntimeStatus    string                    `yaml:"runtime_status"`
	BehavioralParity string                    `yaml:"behavioral_parity"`
	Families         map[string]r9FamilyReport `yaml:"families"`
	Totals           r9ReportTotals            `yaml:"totals"`
	PriorReports     map[string]string         `yaml:"prior_report_sha256"`
	RepeatStable     bool                      `yaml:"repeat_stable"`
}

type r9ReportTotals struct {
	Catalog    int `yaml:"catalog_functions"`
	Public     int `yaml:"public_functions"`
	Registered int `yaml:"registered_public"`
}

func TestR9DifferentialScopeReport(t *testing.T) {
	first, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	second, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	firstNames, secondNames := first.Exec.Names(), second.Exec.Names()
	repeatStable := strings.Join(firstNames, "\x00") == strings.Join(secondNames, "\x00")
	registered := registeredNames(first)

	catalogNames := loadCatalogFunctionNames(t, r9ScopeFamily)
	family := r9FamilyReport{
		Catalog:         len(catalogNames),
		Platform:        "cross-platform CLI wrapper",
		Scenarios:       append([]string(nil), r9Scenarios...),
		SourceReference: "salt/modules/rabbitmq.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		SourceTests:     "tests/pytests/unit/modules/test_rabbitmq.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		Evidence: []string{
			"fake Runner tests reject temporary-user creation before execution and preserve replacements after successful non-atomic authentication without destructive cleanup",
			"source-derived helper/version/layout vectors run without package installation or a live broker",
			"Windows batch quoting is builder-tested on a non-Windows host; no native Windows runtime claim is made",
		},
		CompatibilityNotes: []string{
			"runas is rejected before Runner invocation because the central runtime is single-user and has no elevation contract",
			"DefaultRunner follows Salt PATH/registry discovery; Unix plugin fallback uses pkg.version(rabbitmq-server) and the exact versioned /usr/lib layout",
			"list_policies uses pkg.version(rabbitmq-server), or pkg.version(rabbitmq) on FreeBSD; no status/glob guess is used",
			"Windows .bat helpers pass a final cmd.exe /D /S /C line via SysProcAttr.CmdLine with an 8191 UTF-16-unit limit and injection rejection; native helpers remain direct argv",
			"Windows .bat transport is fail-closed for embedded double quotes and command metacharacters; rejected values never fall back to shell execution",
			"Therefore set_upstream JSON, nonempty JSON set_policy definitions, and legacy check_password Erlang eval paths may be rejected through batch transport",
			"37/37 means the registered/mock contract only; it does not mean successful native Windows batch execution",
			"Future support requires a separately gated Windows-safe transport, not weakening validation",
			"add_user without password is unsupported: no atomic ownership-conditioned cleanup exists; explicit-password add_user and join_cluster do not create temporary accounts",
			"policy layout follows Salt package-version hyphen splitting then PEP 440 comparison with 3.7, including prerelease/dev/local ordering",
			"list_upstreams redacts AMQP URI user-info before returning CLI-visible parameter data",
		},
	}
	for _, name := range catalogNames {
		if strings.HasPrefix(name, "_") {
			family.Private++
			continue
		}
		family.Public++
		full := r9ScopeFamily + "." + name
		if registered[full] {
			family.Registered++
			continue
		}
		alias := strings.TrimSuffix(name, "_")
		if alias != name && registered[r9ScopeFamily+"."+alias] {
			family.Registered++
			continue
		}
		family.PendingPublic = append(family.PendingPublic, full)
	}

	report := r9Report{
		Round:            "R9.1",
		Platform:         "cross-platform",
		RuntimeStatus:    "mock-only: RabbitMQ is never started; shell-free fake Runner tests provide the executable contract",
		BehavioralParity: "not claimed: live Salt/broker differential execution is prohibited for R9.1",
		Families:         map[string]r9FamilyReport{r9ScopeFamily: family},
		PriorReports:     priorR3R8ReportHashes(t),
		RepeatStable:     repeatStable,
	}
	report.Totals.Catalog = family.Catalog
	report.Totals.Public = family.Public
	report.Totals.Registered = family.Registered

	if family.Public != family.Registered || len(family.PendingPublic) != 0 {
		t.Fatalf("R9 registration incomplete: %+v", family)
	}
	if !repeatStable {
		t.Fatal("R9 registration inventory is not repeat-stable")
	}

	encoded, err := yaml.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "differential", "R9", "report.yaml")
	want := "# Generated by tests/differential (TestR9DifferentialScopeReport); do not edit.\n" + string(encoded)
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
	t.Fatalf("R9 differential scope report stale; run UPDATE_DIFFERENTIAL=1 go test ./tests/differential -run TestR9DifferentialScopeReport")
}

func priorR3R8ReportHashes(t *testing.T) map[string]string {
	t.Helper()
	baseline := map[string]string{
		"R3": "107e2f25863c853efc2e163173fd8590dc299d0e85205f1b153837b4f9e139a6",
		"R4": "d089e09723938b43d4a9e7097d05bd0e3b6ae35d05de42a15dd7a1ae22e2a4e5",
		"R5": "adbd9caef01054add60c7d33a6200ae17aabcb60e32565a26057c93d5584c1c9",
		"R6": "f976d922a1370350733396460e01d7cea74a3d29935ab10548a65b189f3c29ea",
		"R7": "74763e9298e03a7cb714551d34e219ec06d1ecb558da4edc27efc8ddea23a0f5",
		"R8": "5c4908a211ddbec245df73b677a55025678ddf1d345a582c733ba85410553fb1",
	}
	out := make(map[string]string, len(baseline))
	for _, round := range []string{"R3", "R4", "R5", "R6", "R7", "R8"} {
		path := filepath.Join("..", "..", "docs", "differential", round, "report.yaml")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s report: %v", round, err)
		}
		digest := sha256.Sum256(data)
		actual := hex.EncodeToString(digest[:])
		if actual != baseline[round] {
			t.Fatalf("%s report hash changed: got %s want baseline", round, actual)
		}
		out[round] = baseline[round]
	}
	return out
}

// Keep the package's R9 platform assertion explicit: no function may acquire
// a Windows-only or Linux-only gate merely because the Salt source contains
// is_windows branching in __virtual__.
func TestR9FunctionsArePlatformNeutral(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range loadCatalogFunctionNames(t, r9ScopeFamily) {
		if strings.HasPrefix(name, "_") {
			continue
		}
		fn, ok := rt.Exec.Get(r9ScopeFamily + "." + name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if constrained, ok := fn.(runtime.PlatformConstrained); ok {
			t.Fatalf("%s unexpectedly constrained to %v", name, constrained.Platforms())
		}
	}
}

func init() {
	// YAML map emission is deterministic in yaml.v3, but keep the scenario list
	// and prior hash keys deterministic if this report is inspected manually.
	sort.Strings(r9Scenarios)
}
