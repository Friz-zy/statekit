package differential

// R10 is the cloud & SaaS API round (plans/porting.md §2 R10: thin stdlib
// HTTP for webhook-style APIs). R10.1 registers the slack family — the
// complete public catalog of salt/modules/slack_notify.py @ pinned
// revision (list_rooms, list_users, find_room, find_user, post_message,
// call_hook over salt/utils/slack.py query and salt/utils/http.py
// transport semantics) with the two private config ladders (_get_api_key,
// _get_hook_id) ported as internal helpers over the optional config.get
// delegate. Every observation in this round is mock-only: the fake HTTP
// transport and the loopback-only httptest server carry the contract, no
// real Slack endpoint is contacted, and live smoke remains behind an
// opt-in label per the R10 plan (not implemented in this phase).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/bootstrap"
	"github.com/friz-zy/statekit/internal/runtime"
	execslack "github.com/friz-zy/statekit/modules/exec/slack"

	"gopkg.in/yaml.v3"
)

type r10FamilySpec struct {
	Source             string
	SourceTests        string
	Platform           string
	Scenarios          []string
	Evidence           []string
	CompatibilityNotes []string
	// RegisteredSubset is nil when every public catalog function must be
	// registered (the R10.1 slack family is complete).
	RegisteredSubset []string
}

var r10FamilySpecs = map[string]r10FamilySpec{
	"slack": {
		Source:      "salt/modules/slack_notify.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		SourceTests: "tests/pytests/unit/modules/test_slack.py, tests/pytests/unit/utils/test_slack.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		Platform:    "cross-platform stdlib HTTP client",
		Scenarios: []string{
			"slack.api-list-rooms-users",
			"slack.find-room-user-shapes",
			"slack.post-message-form-transport",
			"slack.call-hook-payload-shapes",
			"slack.config-key-resolution",
			"slack.bounded-transport-errors",
			"slack.secret-redaction",
			"slack.registry-cli-surfaces",
		},
		Evidence: []string{
			"direct, registry, and CLI fake-transport tests pin the exact URL, verb, header, and body per function: GET https://slack.com/api/conversations.list and users.list with Accept application/json, POST chat.postMessage with the pinned urlencoded Content-Type, and POST https://hooks.slack.com/services/<identifier> with the single payload form field; the token travels only in the Authorization Bearer header and never in a URL, query, or body",
			"the pinned tests/pytests/unit/modules/test_slack.py vectors run through the Go transport: the bare post_message body is byte-identical (channel=%23fake_channel&username=salt+server&text=test+message&attachments=%5B%5D&blocks=%5B%5D), every Python-falsy attachments/blocks input (nil, empty string, false, zero, empty map, empty array) renders [] exactly like the pinned `or []` truthiness, and the attachments/blocks vector keeps the pinned parameter order with compact-JSON composite rendering (the documented Python str()-repr divergence)",
			"the pinned tests/pytests/unit/utils/test_slack.py result ladder is reproduced: a 200 error-key body answers {message: token_revoked, res: false}, 204 answers the bare true, a non-200/204 body decoding to an object without an error key answers Unknown response, a body decoding to an object WITH an error key reaches the pinned KeyError crash position and maps to the fixed value-free unexpected-response sentinel, and any body that does not decode to an object answers invalid_auth",
			"call_hook payload shapes are pinned with the color=good and short=false defaults, the fallback/color/pretext/fields attachment quad, the optional channel/username/icon_emoji positions, the status<=201 true window, and the {res: false, message: body-or-status} failure dict redacted against the hook identifier AND its canonical forms — the decoded path token, the normalized default-port-removed full URL, and the path-only echo — each matched in raw, percent-encoded, and JSON-escaped variants (Go's encoder and Python json.dumps ASCII escaping included)",
			"the fixed-origin identifier contract (SEC-001) is pinned directly: path-style tokens join beneath https://hooks.slack.com/services/ with decoded-path traversal AND decoded-backslash rejection (percent-encoded dot-dot and encoded separators like %5C/%5c included, in both the token and full-URL forms), the only accepted full URL is exactly the pinned origin (https, exact host, no userinfo, default-or-absent port, path under /services/, no query/fragment), and foreign hosts, plaintext http, scheme-relative authorities, rooted/dot-dot paths, encoded or mixed backslashes, ports, userinfo, and query/fragment forms are rejected value-free before any dispatch — asserted at direct, registry, and CLI surfaces (zero-dispatch vectors included) with the pre-remediation absolute loopback acceptance vector replaced by a rejection vector",
			"the exact-origin redirect contract (F1/SEC-002/F5) is pinned at the policy level and end-to-end over loopback-only TLS: followed hops repeat the exact origin (scheme https, identical host including port — subdomains, foreign hosts, downgrades, and port changes fail closed), the Referer header is stripped on every followed hop, exactly 3 redirects are followed (4 exchanges total; the 4th redirect fails closed), and a 307 hop replays the method and body only inside the identical origin",
			"transport failures (DNS/refused/timeout/cancellation/unsafe redirect) are value-free errors at direct, registry, and CLI surfaces — the documented safe divergence from the pinned status-0 mappings (invalid_auth for the API family, a successful True for call_hook)",
			"bounds are pinned: a fixed 30s exchange deadline carried on the request context (so it holds for the module-owned client and the testing-scoped injected transport alike), 1 MiB request ceiling rejected before any dispatch, 4 MiB response ceiling, strict object-only JSON decode with malformed and non-object bodies rejected value-free, and a module-owned bounded stdlib client that is never mutated — test injection exists only as a testing.TB-scoped seam (SEC-004)",
			"the config boundary is pinned: the pinned slack.api_key/slack:api_key and slack.hook/slack:hook ladders over the optional config.get delegate with the pinned SaltInvocationError texts (value-free) and zero transport dispatch on failure, and the falsy-empty-string explicit key resolving through config exactly like the pinned head",
			"the redaction inventory is pinned (F2/SEC-003): the api key and hook identifier never appear in errors, CLI stdout/stderr, or decoded server data; recursive redaction covers values AND object KEYS in raw, percent-encoded, and JSON-escaped normalized forms across nested objects and arrays (Go's encoder plus Python json.dumps default ASCII escaping — control characters, DEL, and non-ASCII as \\uXXXX with astral runes as surrogate pairs, both in keys and values), ordinary keys keep their exact inventory, a key-redaction collision fails closed with the value-free slack: redacted key collision error instead of overwriting (the mysql header-collision precedent), and call_hook failure bodies are redacted against the identifier AND its canonical forms — decoded path token, normalized default-port-removed full URL, path-only echo — each with the full normalized-variant set",
			"the enforced SEC-006 boundary is stated exactly: value-free slack-scoped diagnostics cover flag-parse failures, unexpected positionals, invalid output-format values (namespace-level and function-level -o/--output alike), and unknown structured keys on slack.* dispatch targets — each reports one fixed category, and synthetic-secret vectors at the CLI surface assert exactly empty stdout, no secret bytes on stderr, and zero transport dispatch (the CLI mixed-encoding decoded-backslash rejection vectors — token T00/%2e%5C../B00 included — assert the same exactly-empty stdout and zero dispatch); scalar decode texts are value-free repo-wide, quoting only the template-declared argument NAME plus the failure class, never the raw caller value; argument NAMES may still appear in diagnostics per the module metadata convention, non-slack families keep the flag package's name-bearing parse errors and Salt's unknown-kwarg echo (the mysql CLI tests assert the flag-name convention), and target-less surfaces (version, facts, --list) keep verbatim output-format diagnostics",
			"no real network is used anywhere in the R10 differential suite: the testing-scoped fake HTTP boundary carries the fixed-endpoint contract and the httptest vectors bind 127.0.0.1 loopback only",
		},
		CompatibilityNotes: []string{
			"the pinned module inherits the minion http_request_timeout default (one hour) and a 100 GB max_body over the tornado backend; StateKit bounds every exchange at a fixed 30s deadline on the request context, 1 MiB request body, 4 MiB response body, and an exact-origin https redirect policy (exactly 3 redirects followed, Referer stripped) — resource-control divergences, not behavioral claims",
			"the pinned query maps socket-level failures onto the status-0 ladder (invalid_auth for the API family) and call_hook's status<=201 check turns a status-0 transport failure into a successful True; StateKit deliberately fails closed with value-free errors on both surfaces because a network fault must not masquerade as an authentication failure or a delivered notification",
			"the pinned call_hook joins the identifier under urllib.parse.urljoin, which lets an absolute identifier replace the https://hooks.slack.com/services/ base entirely — an unrestricted destination; StateKit restricts identifiers to the fixed origin (path tokens with traversal rejection, or a full URL that must already be exactly that origin), a security divergence from the pinned behavior, not a parity claim",
			"the pinned post_message stringifies composite form values with Python str()/repr (single-quoted, invalid JSON for structured attachments); StateKit renders compact JSON — the empty list still renders [] exactly like the pinned source, every Python-falsy attachments/blocks input renders [] exactly like the pinned `or []` truthiness, keeping the urlencoded field-per-parameter shape",
			"the pinned decode is content-type-dispatched (json/xml/yaml/plain); StateKit always strict-JSON-decodes the fixed endpoints, requires a top-level object (the stdlib decoder bounds nesting depth), and maps malformed or non-object 200 bodies to fixed value-free errors",
			"the pinned TypeError/KeyError crash positions (a 204 boolean consumed by find_room/post_message, and the non-200/204 error-dict branch reading result[\"error\"] — a key the http layer never set) map to one fixed value-free unexpected-response error; the rest of the pinned else ladder is reproduced (object body without error answers Unknown response, non-object bodies answer invalid_auth)",
			"the pinned source performs no redaction of the api key or hook identifier anywhere; StateKit redacts both from values and object KEYS (raw, percent-encoded, and JSON-escaped normalized forms, Go and Python json.dumps ASCII escaping, with webhook failure bodies additionally covered against the identifier's canonical forms — decoded token, normalized default-port-removed URL, path-only echo) with fail-closed collision handling — a security divergence, not a parity claim",
			"_get_api_key/_get_hook_id resolve through the optional config.get delegate — the module-local form of Salt's config boundary (gpg/nacl/file/ssh_pki precedent); with no delegate registered the ladders fail closed with the pinned SaltInvocationError texts, and the pinned falsy-empty-string explicit-argument head still resolves through config",
			"the pinned channel normalization is preserved exactly, including the logged-but-proceeding missing channel/message/from_name heads (no logging surface exists here) and the explicit-empty-channel '#' + '' result; empty strings for required positional arguments are rejected at argument decode instead, matching the TypeError for an absent positional in the pinned signature",
			"no live Slack endpoint, OAuth flow, or Salt oracle is executed; contract tests run against recorded-response-style fake transports only, and the R10 plan's live smoke behind an opt-in label is not implemented in this phase — external evidence remains pending_external_ci",
		},
	},
}

// r10FamilyOrder keeps generated map emission deterministic.
var r10FamilyOrder = []string{"slack"}

type r10FamilyReport struct {
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

type r10Report struct {
	Round            string                     `yaml:"round"`
	Platform         string                     `yaml:"platform"`
	RuntimeStatus    string                     `yaml:"runtime_status"`
	BehavioralParity string                     `yaml:"behavioral_parity"`
	ExternalCI       string                     `yaml:"external_ci_status"`
	Families         map[string]r10FamilyReport `yaml:"families"`
	Totals           r10ReportTotals            `yaml:"totals"`
	PriorReports     map[string]string          `yaml:"prior_report_sha256"`
	RepeatStable     bool                       `yaml:"repeat_stable"`
}

type r10ReportTotals struct {
	Catalog    int `yaml:"catalog_functions"`
	Public     int `yaml:"public_functions"`
	Registered int `yaml:"registered_public"`
	Pending    int `yaml:"pending_public"`
}

// r10SlackCatalogFile is the catalog entry of the salt family (the file
// keeps the pinned source module name slack_notify while the runtime
// module is the pinned virtual name slack).
const r10SlackCatalogFile = "slack_notify"

func loadR10Catalog(t *testing.T) (string, []string) {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "catalog", "exec", r10SlackCatalogFile+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("catalog %s: %v", r10SlackCatalogFile, err)
	}
	var parsed struct {
		Module    string `yaml:"module"`
		Functions []struct {
			Function string `yaml:"function"`
		} `yaml:"functions"`
	}
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("catalog %s parse: %v", r10SlackCatalogFile, err)
	}
	names := make([]string, 0, len(parsed.Functions))
	for _, fn := range parsed.Functions {
		names = append(names, fn.Function)
	}
	sort.Strings(names)
	if parsed.Module != "slack" {
		t.Fatalf("catalog module = %q, want slack", parsed.Module)
	}
	return parsed.Module, names
}

// r10SlackTransport is the fake HTTP boundary for the R10 differential
// vectors: no DNS, no network.
type r10SlackTransport struct {
	requests  []r10SlackRequest
	responses []r10SlackResponse
}

type r10SlackRequest struct {
	method        string
	url           string
	authorization string
	contentType   string
	body          string
}

type r10SlackResponse struct {
	status int
	body   string
}

func (f *r10SlackTransport) Do(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	f.requests = append(f.requests, r10SlackRequest{
		method:        req.Method,
		url:           req.URL.String(),
		authorization: req.Header.Get("Authorization"),
		contentType:   req.Header.Get("Content-Type"),
		body:          string(body),
	})
	if len(f.responses) == 0 {
		return nil, errR10Transport
	}
	result := f.responses[0]
	f.responses = f.responses[1:]
	return &http.Response{
		StatusCode: result.status,
		Body:       io.NopCloser(strings.NewReader(result.body)),
		Header:     make(http.Header),
	}, nil
}

var errR10Transport = &r10TransportError{}

type r10TransportError struct{}

func (*r10TransportError) Error() string { return "r10 fake transport exhausted" }

// TestR10SlackMockDifferential pins the family contract through the
// registered names with the injected fake transport: the token header
// placement, the pinned result ladder, and the call_hook payload form.
func TestR10SlackMockDifferential(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := execslack.Register(reg); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{Exec: reg}
	transport := &r10SlackTransport{responses: []r10SlackResponse{
		{status: 200, body: `{"ok": true, "channels": [{"id": "C1", "name": "general"}]}`},
		{status: 200, body: `{"ok": false, "error": "token_revoked"}`},
		{status: 200, body: "ok"},
	}}
	execslack.SetTestHTTPClient(t, transport)

	apiKey := "xoxp-r10-key"
	value, err := reg.Call(context.Background(), rt, "slack.list_rooms", &execslack.ListRoomsArgs{APIKey: &apiKey})
	if err != nil {
		t.Fatalf("r10 list_rooms: %v", err)
	}
	if !reflect.DeepEqual(value, map[string]any{
		"message": []any{map[string]any{"id": "C1", "name": "general"}},
		"res":     true,
	}) {
		t.Fatalf("r10 list_rooms value = %#v", value)
	}
	first := transport.requests[0]
	if first.method != http.MethodGet || first.url != "https://slack.com/api/conversations.list" ||
		first.authorization != "Bearer "+apiKey || first.body != "" {
		t.Fatalf("r10 list_rooms request = %#v", first)
	}
	if strings.Contains(first.url, apiKey) || strings.Contains(first.body, apiKey) {
		t.Fatalf("r10 token escaped the header boundary: %#v", first)
	}

	value, err = reg.Call(context.Background(), rt, "slack.list_users", &execslack.ListUsersArgs{APIKey: &apiKey})
	if err != nil {
		t.Fatalf("r10 list_users: %v", err)
	}
	if !reflect.DeepEqual(value, map[string]any{"message": "token_revoked", "res": false}) {
		t.Fatalf("r10 list_users ladder value = %#v", value)
	}

	identifier := "T00/B00/R10"
	value, err = reg.Call(context.Background(), rt, "slack.call_hook", &execslack.CallHookArgs{
		Message:    "r10 differential",
		Identifier: &identifier,
	})
	if err != nil || value != true {
		t.Fatalf("r10 call_hook value = %#v err = %v", value, err)
	}
	hook := transport.requests[2]
	if hook.method != http.MethodPost || hook.url != "https://hooks.slack.com/services/T00/B00/R10" {
		t.Fatalf("r10 call_hook request = %#v", hook)
	}
	if !strings.HasPrefix(hook.body, "payload=") {
		t.Fatalf("r10 call_hook body = %q", hook.body)
	}
	if !strings.Contains(hook.body, "payload=%7B%22text%22%3A%22r10+differential%22%7D") {
		t.Fatalf("r10 call_hook payload form = %q", hook.body)
	}
	form, err := url.ParseQuery(hook.body)
	if err != nil || len(form["payload"]) != 1 {
		t.Fatalf("r10 call_hook form = %q err=%v", hook.body, err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(form["payload"][0]), &payload); err != nil {
		t.Fatalf("r10 payload decode: %v (%q)", err, form["payload"][0])
	}
	if payload["text"] != "r10 differential" || len(payload) != 1 {
		t.Fatalf("r10 payload = %#v", payload)
	}
}

func TestR10DifferentialScopeReport(t *testing.T) {
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

	report := r10Report{
		Round:    "R10.1",
		Platform: "cross-platform",
		RuntimeStatus: "mock-only differential contract: no Slack endpoint is contacted and no live Salt runs; " +
			"the testing-scoped fake HTTP transport and loopback-only httptest vectors (exact-origin redirect chains, " +
			"foreign-origin hook rejection) provide the executable contract",
		BehavioralParity: "not claimed: local R10 differential tests do not execute live Salt or Slack; the R10 plan's opt-in live smoke is not implemented; separately configured external CI is pending_external_ci",
		ExternalCI:       "pending_external_ci",
		Families:         map[string]r10FamilyReport{},
		PriorReports:     priorR3R9ReportHashes(t),
		RepeatStable:     repeatStable,
	}

	for _, familyName := range r10FamilyOrder {
		spec := r10FamilySpecs[familyName]
		catalogModule, catalogNames := loadR10Catalog(t)
		family := r10FamilyReport{
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
			if registered[catalogModule+"."+name] {
				family.Registered++
				continue
			}
			family.PendingPublic = append(family.PendingPublic, catalogModule+"."+name)
		}

		// Complete families (R10.1 slack) must register every public
		// catalog function with nothing pending.
		if spec.RegisteredSubset == nil &&
			(family.Registered != family.Public || len(family.PendingPublic) != 0) {
			t.Fatalf("R10 %s registration incomplete: %+v", familyName, family)
		}

		report.Totals.Catalog += family.Catalog
		report.Totals.Public += family.Public
		report.Totals.Registered += family.Registered
		report.Totals.Pending += len(family.PendingPublic)
		report.Families[familyName] = family
	}

	if !repeatStable {
		t.Fatal("R10 registration inventory is not repeat-stable")
	}

	encoded, err := yaml.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "differential", "R10", "report.yaml")
	want := "# Generated by tests/differential (TestR10DifferentialScopeReport); do not edit.\n" + string(encoded)
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
	t.Fatalf("R10 differential scope report stale; run UPDATE_DIFFERENTIAL=1 go test ./tests/differential -run TestR10DifferentialScopeReport")
}

func priorR3R9ReportHashes(t *testing.T) map[string]string {
	t.Helper()
	baseline := map[string]string{
		"R3": "107e2f25863c853efc2e163173fd8590dc299d0e85205f1b153837b4f9e139a6",
		"R4": "d089e09723938b43d4a9e7097d05bd0e3b6ae35d05de42a15dd7a1ae22e2a4e5",
		"R5": "adbd9caef01054add60c7d33a6200ae17aabcb60e32565a26057c93d5584c1c9",
		"R6": "f976d922a1370350733396460e01d7cea74a3d29935ab10548a65b189f3c29ea",
		"R7": "74763e9298e03a7cb714551d34e219ec06d1ecb558da4edc27efc8ddea23a0f5",
		"R8": "5c4908a211ddbec245df73b677a55025678ddf1d345a582c733ba85410553fb1",
		"R9": "8830a48aaaa194c2b2736fe984e236bfd3df3a5738d15e98ae0e323fca01e2de",
	}
	out := make(map[string]string, len(baseline))
	for _, round := range []string{"R3", "R4", "R5", "R6", "R7", "R8", "R9"} {
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

// Keep the package's R10 platform assertion explicit: no function may
// acquire a Windows-only or Linux-only gate merely because the Salt
// source contains platform branching elsewhere.
func TestR10FunctionsArePlatformNeutral(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	module, catalogNames := loadR10Catalog(t)
	for _, name := range catalogNames {
		if strings.HasPrefix(name, "_") {
			continue
		}
		full := module + "." + name
		fn, ok := rt.Exec.Get(full)
		if !ok {
			t.Fatalf("missing %s", full)
		}
		if constrained, ok := fn.(runtime.PlatformConstrained); ok {
			t.Fatalf("%s unexpectedly constrained to %v", full, constrained.Platforms())
		}
	}
}

func init() {
	// Keep scenario emission deterministic like the R9 generator.
	for _, spec := range r10FamilySpecs {
		sort.Strings(spec.Scenarios)
	}
}
