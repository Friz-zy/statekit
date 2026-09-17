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

// R9 is the services-tier round. R9.1 reconciled the complete rabbitmq
// catalog against bootstrap registration without starting a broker (the
// module's untagged fake-runner suite supplies the command, parser, error,
// cancellation, bounds, and CLI evidence). R9.2a adds the mysql family's
// driver-free pure slice: quote_identifier and tokenize_grant, pinned by
// source-derived lexer vectors. R9.2b adds the postgres family's CLI-first
// slice: the psql-backed version probe plus the internal LooseVersion-
// equivalent parsed-version helper. R9.2c extends that slice with the five
// read-only catalog primitives db_list, db_exists, tablespace_list,
// tablespace_exists, and user_list, pinned against the pinned pytest CSV
// and row fixtures through the same fake-Runner transport. R9.2d adds the
// eight read-only extension and language catalog functions
// available_extensions, installed_extensions, get_available_extension,
// get_installed_extension, is_available_extension, is_installed_extension,
// language_list, and language_exists (postgres.py:1654-1846, 2602-2695),
// with every extension and language lookup matched client-side so no
// caller string reaches SQL. R9.2e adds the three read-only schema catalog
// functions schema_exists, schema_get, and schema_list
// (postgres.py:2444-2599) with the pinned schema-family connection
// signature and the same client-side name matching. R9.2f adds the three
// read-only role and privilege checks role_get, user_exists, and
// has_privileges (postgres.py:1104-1170, 3574-3711): role_get reuses the
// user_list catalog with the pinned .get(name, None) and
// bool(role_get(...)) shapes, and has_privileges keeps the pinned owner
// and ACL catalogs as fixed queries whose interpolated equality literals
// are matched client-side, reproducing the pinned table, group, and
// function privilege outcomes. The generic psql_query surface and the
// remaining mysql and postgres surfaces need their client protocol
// boundaries and stay pending.
type r9FamilySpec struct {
	Source             string
	SourceTests        string
	Platform           string
	Scenarios          []string
	Evidence           []string
	CompatibilityNotes []string
	// RegisteredSubset is nil when every public catalog function must be
	// registered (R9.1 rabbitmq). Otherwise it names the exact partial
	// slice this round registers; all other public functions stay pending.
	RegisteredSubset []string
}

var r9FamilySpecs = map[string]r9FamilySpec{
	"rabbitmq": {
		Source:      "salt/modules/rabbitmq.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		SourceTests: "tests/pytests/unit/modules/test_rabbitmq.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		Platform:    "cross-platform CLI wrapper",
		Scenarios: []string{
			"rabbitmq.users-vhosts-permissions",
			"rabbitmq.password-check-and-status",
			"rabbitmq.policy-list-set-delete",
			"rabbitmq.plugin-list-enable-disable",
			"rabbitmq.federation-upstream-list-set-delete",
		},
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
	},
	"mysql": {
		Source:      "salt/modules/mysql.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		SourceTests: "tests/pytests/unit/modules/test_mysql.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		Platform:    "cross-platform pure functions",
		Scenarios: []string{
			"mysql.identifier-quoting",
			"mysql.grant-lexer-shapes",
		},
		Evidence: []string{
			"source-derived quoting and lexer vectors from the pinned mysql.py, including the three _grant_to_tokens docstring split examples run verbatim",
			"direct, registry, and CLI mock tests execute with a nil Runner and no filesystem access; no MySQL driver or protocol client is linked",
			"the pinned pytests map the module but do not cover the tokenizer; coverage here is algorithm-derived, not test-file-derived",
		},
		CompatibilityNotes: []string{
			"R9.2a registers only the two driver-free pure functions quote_identifier and tokenize_grant; the remaining public surface requires the MySQL client protocol boundary (E5) and stays pending",
			"the tokenizer keeps the pinned shlex configuration (quotes apostrophe/backtick, double-quote folded into wordchars, non-posix inert escape) so backslash separates tokens instead of escaping",
			"read-ahead edge behavior is preserved: shlex ValueError(No closing quotation) and the grants/user IndexError map to execution errors, the db-phrase IndexError ends parsing, and a missing host after @ degrades to an empty host",
			"PROXY-style grants concatenate every post-ON token into database without separators because the pinned phrase machine never leaves the db phase",
			"column privileges keep the pinned current_grant prefixing, including the empty-prefix .token shape after multi-word privileges",
			"quote_identifier keeps the pinned replacement order: backtick doubling first, underscore escaping only for for_grants, then percent doubling",
			"grant values render as a JSON array ([] never null) and dict-mode qry input unescapes MySQLdb %% while leaving string-mode %% untouched",
			"no MySQL driver, live server, network egress, or new dependency is claimed or added",
		},
		RegisteredSubset: []string{
			"mysql.quote_identifier",
			"mysql.tokenize_grant",
		},
	},
	"postgres": {
		Source:      "salt/modules/postgres.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		SourceTests: "tests/pytests/unit/modules/test_postgres.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		Platform:    "cross-platform CLI wrapper",
		Scenarios: []string{
			"postgres.server-version-probe",
			"postgres.read-only-catalog-lists",
			"postgres.extension-and-language-catalogs",
			"postgres.schema-catalogs",
			"postgres.role-and-privilege-checks",
		},
		Evidence: []string{
			"direct, registry, and CLI fake-Runner tests pin the exact psql argv (SQL at index 14 as the pinned test_version asserts), the clean PG environment, first-line split semantics, and the None fallthrough for empty stdout",
			"db_list, db_exists, tablespace_list, and tablespace_exists run the pinned get_test_list_db_csv and tablespace fixtures verbatim through the COPY-to-CSV transport and match the pinned expected dictionaries",
			"user_list pins the pinned test_user_list row shape (t/f/None booleans, strptime expiry, CSV-decoded groups array, connections None) and the version-dependent 9.1/9.5 column selection including the return_password joins",
			"the two CSV decoders are pinned by vectors generated from the pinned Python csv.reader itself (python:3.12): PostgreSQL array text with backslash-escaped elements decodes like list(csv.reader([row[\"groups\"].strip(\"{}\")]))[0] (for example {\"a\\\"b\",\"x\\\\y\"} yields [a\\b\", x\\y]), and COPY CSV rows keep embedded CRLF byte-exact inside quoted fields where Go's encoding/csv would normalize it to LF",
			"available_extensions and installed_extensions reproduce the pinned test_available_extensions/test_installed_extensions dictionaries verbatim (the whole row stored under its name/extname key) plus realistic pg_available_extensions and pg_extension COPY CSV fixtures with the pinned short-row column filtering",
			"get_available_extension and get_installed_extension keep the pinned .get(name, None) exact-case row-or-None shape, is_available_extension keeps the pinned case-insensitive name.lower() key membership, is_installed_extension keeps the pinned bool(get_installed_extension(...)) exact-case truthiness, and language_exists keeps the pinned exact-case `name in languages` membership",
			"language_list runs the pinned get_test_list_language_csv fixture verbatim to the pinned name→name dictionary with the pinned SELECT lanname AS \"Name\" FROM pg_language SQL, and maintenance_db stays the pinned required positional",
			"schema_list runs the pinned get_test_list_schema_csv fixture verbatim to the pinned {public, pg_toast} dictionary with only the owner and acl pair per row (the pinned SELECT pg_namespace.nspname ... LEFT JOIN pg_roles SQL byte-for-byte), schema_get keeps the pinned .get(name, None) exact-case row-or-None shape with the empty-acl pg_toast row still a hit, and schema_exists keeps the pinned bool(schema_get(...)) truthiness",
			"role_get and user_exists keep the pinned user_list(...).get(name, None) and bool(role_get(..., return_password=False)) shapes including Salt's False-catalog AttributeError-to-None fallthrough after one psql call, and has_privileges reproduces the pinned test_has_privileges_on_table, test_has_privileges_on_group, and test_has_privileges_with_function outcomes verbatim: the pinned table ACL fixture decodes to the pinned three-role privilege dictionary, the owner shortcut, the grant-option dict equality, the ALL sorted-key equality, the strict-subset check, and the group admin_option boolean",
			"the pinned _get_object_owner and _make_privileges_list_query interpolate caller names into SQL string literals; StateKit keeps the pinned catalogs, join shapes, and orderings as fixed COPY-wrapped queries and matches the object name, schema prefix, and group membership client-side, so no caller string reaches SQL (asserted by leak checks with names that collide with no SQL keyword or column)",
			"password redaction is asserted on the rendered command, captured output, and returned errors; no real psql, database, or package-manager path exists",
			"cancellation, output limits, runas rejection, nonzero-exit compatibility data, and psql-unavailable fail-closed behavior are covered without any live server",
			"the internal parsed-version helper is pinned by LooseVersion comparison vectors because no existing package consumes it yet",
		},
		CompatibilityNotes: []string{
			"R9.2c registers the version probe plus the five read-only catalog primitives db_list, db_exists, tablespace_list, tablespace_exists, and user_list; R9.2d adds the eight read-only extension and language catalog functions available_extensions, installed_extensions, get_available_extension, get_installed_extension, is_available_extension, is_installed_extension, language_list, and language_exists; R9.2e adds the three read-only schema catalog functions schema_exists, schema_get, and schema_list; R9.2f adds the three read-only role and privilege checks role_get, user_exists, and has_privileges; the generic psql_query surface and every write path stay pending (no arbitrary-query or identifier-interpolating registration exists in this phase)",
			"has_privileges keeps the pinned argument contract (name, object_name, object_type, privileges=None, grant_option=None, prepend=\"public\", maintenance_db, user, host, port, password, runas) with the pinned _mod_priv_opts object-type lowercasing, comma-split with optional single spaces, and uppercasing; the pinned KeyError on an unknown object type and the SaltInvocationError privilege and group-privilege rejections all map to execution errors raised before any Runner invocation",
			"the pinned _get_object_owner and _make_privileges_list_query build SQL by formatting the caller's object name and schema prefix into single-quoted literals; StateKit replaces every interpolated equality with a client-side exact match over the same fixed catalog query (key column selected beside the pinned value column, pinned relkind filters and orderings kept, the group membership keyed by the group role's name), which is result-equivalent for every non-malicious input because each pinned equality targets a unique catalog key, and refuses the injection the pinned format permits",
			"ACL text decodes through the pinned strip(\"{}\")/split(\",\")/split(\"/\")/split(\"=\") ladder: exactly one grantor slash and one grantee equals per entry, the empty grantee becomes public, _process_priv_part's grant-star flip and leading-star GRANT key are preserved, and NULL or malformed ACL text is the pinned ValueError mapped to an execution error whose message embeds no input",
			"role_get and user_exists reuse the registered user_list catalog: the exact-case miss is None (never an error), Salt's False catalog from an unanswered version probe maps through the pinned AttributeError branch to None, and bool(role_get(...)) is the row's presence because a stored role row always carries the pinned columns",
			"the schema family keeps the pinned schema_* signature (postgres.py:2444-2599): dbname is the required database positional, user is the pinned system-user argument rejected like every runas surface, and db_user/db_host/db_port/db_password project onto the shared psql connection tuple; schema rows are reduced to exactly the pinned owner/acl pair keyed by name, and schema_get/schema_exists match names client-side so no caller string reaches SQL",
			"extension and language lookups are client-side only: get_*/is_*/language_exists match names against the fetched catalog so no caller string reaches SQL, and the installed_extensions query keeps the pinned double space after \"pg_extension a,\" byte-for-byte",
			"available_extensions/installed_extensions store the full row under its name/extname key (no column removed, unlike db_list's Name pop), rows whose zipped prefix lacks either pinned key column are skipped, and language_list maps each Name column to itself exactly like the pinned ret[row[\"Name\"]] = row[\"Name\"]",
			"the pinned _run_psql PGPASSFILE temp-file credential transport is replaced by psql-native PGPASSWORD (with PGUSER/PGHOST/PGPORT) in an otherwise clean environment because the single-user runtime has no file-chown/elevation contract; the password is a Redact secret and never rendered",
			"a non-zero psql exit stays compatibility data (Salt logs and returns the empty row list), while Runner failures, cancellation, and output-limit violations are errors",
			"Salt's postgres.timeout default of 0 (unbounded) is replaced by a finite 30s ceiling as the R9 resource-control convention",
			"runas is rejected before Runner invocation because the central runtime is single-user and has no elevation contract; Salt's implicit postgres runas default therefore does not apply",
			"the pinned config.option defaults (postgres.user/host/port/maintenance_db/pass/bins_dir) have no StateKit module-config surface yet, so omitted arguments keep Salt's None meaning and psql resolves through PATH only, failing closed when absent",
			"the catalog queries are the pinned fixed SQL fragments wrapped in the pinned COPY (...) TO STDOUT WITH CSV HEADER transport with datestyle=ISO,MDY; db_exists/tablespace_exists match names client-side so no caller string reaches SQL",
			"CSV parsing is a bounded port of the pinned non-strict Python csv.reader state machine: comma delimiter, double-quote quotechar with doubled-quote collapsing, bare quotes and NUL bytes as literal data, and backslash as an ordinary character, so PostgreSQL array text with backslash-escaped elements decodes exactly like the pinned groups expression and no strict-encoding/csv rejection exists; embedded CR, LF, and CRLF survive byte-exact inside quoted fields (a CRLF the Go standard reader would normalize to LF), the 131072-character field limit and the new-line-in-unquoted-field error map to Salt's csv.Error, empty rows are skipped, and rows are dict(zip(header,row)) truncated, with Salt's KeyError on short rows mapped to an execution error",
			"user_list keeps the pinned column contract: rolreplication is real on >=9.1, rolcatupdate is NULL on >=9.5, an unanswered version probe returns False, connections keeps get_bool's None for non-t/f values, and expiry parsing tolerates invalid values as None (Python strptime accepts some non-padded shapes Go rejects; PostgreSQL timestamp(0) output is always padded)",
			"the internal _parsed_version helper follows pinned salt/utils/versions.py:73-101: digit runs become integers, separator dots are discarded, and lists compare numerically unless either contains strings, when all integer components use zfill(8) string comparison; mixed int/string comparison is defined; the helper is deliberately not registered publicly",
			"no postgres driver, live server, network egress, or new dependency is claimed or added",
		},
		RegisteredSubset: []string{
			"postgres.version",
			"postgres.db_list",
			"postgres.db_exists",
			"postgres.tablespace_list",
			"postgres.tablespace_exists",
			"postgres.user_list",
			"postgres.available_extensions",
			"postgres.installed_extensions",
			"postgres.get_available_extension",
			"postgres.get_installed_extension",
			"postgres.is_available_extension",
			"postgres.is_installed_extension",
			"postgres.language_list",
			"postgres.language_exists",
			"postgres.schema_exists",
			"postgres.schema_get",
			"postgres.schema_list",
			"postgres.role_get",
			"postgres.user_exists",
			"postgres.has_privileges",
		},
	},
}

// r9FamilyOrder keeps generated map emission deterministic.
var r9FamilyOrder = []string{"mysql", "postgres", "rabbitmq"}

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
	Pending    int `yaml:"pending_public"`
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

	report := r9Report{
		Round:    "R9.2f",
		Platform: "cross-platform",
		RuntimeStatus: "mock-only: RabbitMQ is never started, MySQL is never connected, and PostgreSQL is never contacted; " +
			"shell-free fake Runner tests and pure-function vectors provide the executable contract",
		BehavioralParity: "not claimed: live Salt/broker/database differential execution is prohibited for R9",
		Families:         map[string]r9FamilyReport{},
		PriorReports:     priorR3R8ReportHashes(t),
		RepeatStable:     repeatStable,
	}

	for _, familyName := range r9FamilyOrder {
		spec := r9FamilySpecs[familyName]
		subset := map[string]bool{}
		for _, name := range spec.RegisteredSubset {
			subset[name] = true
		}
		catalogNames := loadCatalogFunctionNames(t, familyName)
		family := r9FamilyReport{
			Catalog:            len(catalogNames),
			Platform:           spec.Platform,
			Scenarios:          append([]string(nil), spec.Scenarios...),
			SourceReference:    spec.Source,
			SourceTests:        spec.SourceTests,
			Evidence:           append([]string(nil), spec.Evidence...),
			CompatibilityNotes: append([]string(nil), spec.CompatibilityNotes...),
		}
		for _, name := range catalogNames {
			if strings.HasPrefix(name, "_") {
				family.Private++
				continue
			}
			family.Public++
			full := familyName + "." + name
			if registered[full] {
				family.Registered++
				continue
			}
			alias := strings.TrimSuffix(name, "_")
			if alias != name && registered[familyName+"."+alias] {
				family.Registered++
				continue
			}
			family.PendingPublic = append(family.PendingPublic, full)
		}

		if spec.RegisteredSubset == nil {
			// Complete families (R9.1 rabbitmq) must register every public
			// catalog function.
			if family.Public != family.Registered || len(family.PendingPublic) != 0 {
				t.Fatalf("R9 %s registration incomplete: %+v", familyName, family)
			}
		} else {
			// Slice families (R9.2a mysql) must register exactly the named
			// subset: nothing more, nothing less.
			for _, name := range spec.RegisteredSubset {
				if !registered[name] {
					t.Fatalf("R9 %s slice member %s not registered", familyName, name)
				}
			}
			if family.Registered != len(spec.RegisteredSubset) {
				t.Fatalf("R9 %s registered %d functions, want exactly the %d slice members: %+v",
					familyName, family.Registered, len(spec.RegisteredSubset), family.PendingPublic)
			}
			wantPending := map[string]bool{}
			for _, name := range family.PendingPublic {
				if subset[name] {
					t.Fatalf("R9 %s slice member %s listed pending", familyName, name)
				}
				wantPending[name] = true
			}
			for _, name := range spec.RegisteredSubset {
				if wantPending[name] {
					t.Fatalf("R9 %s slice member %s listed pending", familyName, name)
				}
			}
		}

		report.Totals.Catalog += family.Catalog
		report.Totals.Public += family.Public
		report.Totals.Registered += family.Registered
		report.Totals.Pending += len(family.PendingPublic)
		report.Families[familyName] = family
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
// is_windows branching in __virtual__. Slice families check their
// registered subset; unregistered pending names have no gate to check.
func TestR9FunctionsArePlatformNeutral(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	for _, familyName := range r9FamilyOrder {
		spec := r9FamilySpecs[familyName]
		for _, name := range loadCatalogFunctionNames(t, familyName) {
			if strings.HasPrefix(name, "_") {
				continue
			}
			full := familyName + "." + name
			fn, ok := rt.Exec.Get(full)
			if !ok {
				if spec.RegisteredSubset == nil {
					t.Fatalf("missing %s", full)
				}
				continue
			}
			if constrained, ok := fn.(runtime.PlatformConstrained); ok {
				t.Fatalf("%s unexpectedly constrained to %v", full, constrained.Platforms())
			}
		}
	}
}

func init() {
	// YAML map emission is deterministic in yaml.v3, but keep the scenario
	// lists and prior hash keys deterministic if this report is inspected
	// manually.
	for _, spec := range r9FamilySpecs {
		sort.Strings(spec.Scenarios)
	}
}
