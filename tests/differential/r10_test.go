package differential

// R10 is the cloud & SaaS API round (plans/porting.md §2 R10: thin
// stdlib HTTP for webhook-style APIs). R10.1 registers the slack
// family — the complete public catalog of salt/modules/
// slack_notify.py @ pinned revision (list_rooms, list_users,
// find_room, find_user, post_message, call_hook over
// salt/utils/slack.py query and salt/utils/http.py transport
// semantics) with the two private config ladders (_get_api_key,
// _get_hook_id) ported as internal helpers over the optional
// config.get delegate. R10.2 registers the dig family — the complete
// public catalog of salt/modules/dig.py @ pinned revision (check_ip,
// A, PTR, AAAA, CNAME, NS, SPF, MX, TXT plus the seven source aliases
// a, ptr, aaaa, cname, ns, spf, mx; there is no txt alias in the
// pinned source) over the central shell-free Runner. R10.3a registers
// the bounded dnsutil slice — eight of the eleven public functions of
// salt/modules/dnsutil.py @ pinned revision (parse_hosts, parse_zone,
// check_ip, A, AAAA, NS, SPF, MX) with _to_seconds/_has_dig kept
// private; hosts_append, hosts_remove, and serial stay pending with
// recorded reasons (arbitrary-path mutation and the missing persistent
// grains store). Every observation in this round is mock-only: the
// fake HTTP transport, the loopback-only httptest server, the scripted
// fake Runner, and the MemoryFS file fixtures carry the contract — no
// real Slack endpoint is contacted, no dig binary is executed, no DNS
// name is resolved, no host /etc/hosts or zone file is read, and live
// smoke remains behind an opt-in label per the R10 plan (not
// implemented in this phase).
//
// The three dig behavioral fake-Runner vectors (TestR10DigMockDifferential,
// TestR10DigTrustedGateAndUnverifiedExecutable, TestR10DigPythonSemantics)
// and the four dnsutil behavioral vectors (TestR10DNSUtilPinnedSourceVectors,
// TestR10DNSUtilDelegationArgv, TestR10DNSUtilGateAndPendingLedger,
// TestR10DNSUtilParserBoundsAndMalformedJoins) live
// behind the dns_contract build tag, so the default host CI
// `go test ./...` never executes them; TestR10DNSContractTagBoundary
// below statically pins that tag boundary.

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
	"regexp"
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
	// RegisteredSubset is nil when every public catalog function must
	// be registered (the R10.1 slack and R10.2 dig families are
	// complete). A non-nil subset declares the bounded slice of a
	// partial family (the R10.3a dnsutil slice): exactly the subset is
	// registered and every other public name stays pending with
	// recorded reasons.
	RegisteredSubset []string
	// CatalogFile is the concrete catalog file of the family (the slack
	// file keeps the pinned source module name slack_notify).
	CatalogFile string
	// Aliases are the pinned source-module aliases registered beside
	// the canonical catalog names (reported separately from the
	// canonical totals).
	Aliases []string
}

var r10FamilySpecs = map[string]r10FamilySpec{
	"dig": {
		Source:      "salt/modules/dig.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		SourceTests: "tests/pytests/unit/modules/test_dig.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		Platform:    "cross-platform dig subprocess over the central shell-free Runner",
		CatalogFile: "dig",
		Aliases:     []string{"a", "ptr", "aaaa", "cname", "ns", "spf", "mx"},
		Scenarios: []string{
			"dig.availability-gating",
			"dig.argv-transport-contract",
			"dig.check-ip-prefix-families",
			"dig.python-int-and-whitespace-parity",
			"dig.record-shapes-raw-splits",
			"dig.spf-fallback-redirect-include",
			"dig.revalidation-zero-dispatch",
			"dig.shared-budgets-and-cycles",
			"dig.trusted-process-boundary",
			"dig.value-free-diagnostics",
			"dig.registry-cli-alias-parity",
		},
		Evidence: []string{
			"the nine canonical catalog functions (check_ip, A, PTR, AAAA, CNAME, NS, SPF, MX, TXT) are registered complete plus the seven source aliases (a, ptr, aaaa, cname, ns, spf, mx) with alias-vs-canonical parity asserted through the registry; no dig.txt alias exists because the pinned module tail defines none, and the catalog keeps exactly the nine canonical entries with aliases reported separately here",
			"the transport contract is pinned at direct, registry, and CLI surfaces with a scripted fake Runner: every dispatch is the fixed dig command with the separate argv `-r +short -q <name> -t <type>` and an optional single trailing validated `@server` element, Shell is always false, per-call capture is bounded at 64 KiB stdout and 8 KiB stderr, the per-call timeout never exceeds 2s, and PTR validates its argument as a bare IP literal and always queries the fixed reverse form (8.8.8.8 answers -q 8.8.8.8.in-addr.arpa -t PTR; 2001:db8::1 answers the 32 nibble-reversed ip6.arpa name) instead of the pinned raw `-x <host>` spelling — so no caller-controlled dig flag surface exists",
			"the trusted native process boundary (R102-SEC-01, full symlink-chain verification) is pinned with a test resolver returning a synthetic absolute path: when the Runner implements process.TrustedCommandResolver every dig dispatch carries the resolved absolute path as argv[0]; DefaultRunner's implementation resolves only the fixed `dig` name from the canonical system candidate paths (/usr/bin/dig, /bin/dig, and /usr/local/bin/dig) by walking every candidate and every symlink target component-wise with Lstat — every directory on the chain must be root-owned with no group/world write, every symlink must be root-owned (Linux symlinks are always lrwxrwxrwx, so the enforceable link controls are its owner and the non-group/world-writable containing directory), relative targets join the link's directory and absolute targets are cleaned so every resulting normalized path must stay inside the approved system roots (/bin, /usr, /usr/local) — containment is decided on the normalized target, never a raw lexical prefix (R102-FINAL-02: /usr/../opt/vendor/dig normalizes to /opt/vendor/dig and is rejected unless the cleaned final target remains inside a canonical approved root) — symlink hops are bounded so loops and deep chains fail closed, and the final target must be an absolute regular root-owned executable with no group/world write — failing closed on unsupported names and platforms (ErrTrustedCommandUnsupported) and on missing or untrusted binaries (ErrTrustedCommandUnavailable); unit-tested over a synthetic filesystem seam plus synthetic temp trees (real directories, files, and symlinks through the production Lstat/Readlink walker with only ownership synthesized) covering the safe root chain/link, user-owned symlink, writable parent, loop, traversal, absolute dot-dot targets that lexically start inside the approved root but clean outside it (final-component and mid-chain directory symlinks), and candidate-outside-allowed-roots vectors so no test depends on or executes a native dig binary; a user-installed dig outside the canonical candidates and approved roots (a homebrew or $HOME prefix, any custom PATH directory) is unsupported and fails closed with the fixed unavailable error; the dig module never performs a host LookPath and a Runner without the resolver fails closed with the fixed unverified-executable error and zero dispatch — no bare-name PATH fallback exists anywhere",
			"the child environment is exactly the fixed allowlist HOME=/nonexistent (a fixed nonexistent directory; -r is kept), PATH=/usr/bin:/bin, LANG=C, LC_ALL=C, TZ=UTC — asserted byte-exact at direct, registry, and CLI surfaces — so the parent environment is never inherited and RES_OPTIONS, LOCALDOMAIN, HOSTALIASES, LD_*, and caller secrets cannot reach the dig process; the -r flag stays and a resolver answering a relative or empty path fails closed with the fixed unavailable gate error and zero dispatch",
			"the pinned __virtual__ gate is enforced through the Runner's optional process.TrustedCommandResolver capability: when trusted resolution fails every dig.* function including check_ip fails closed with the fixed value-free gate error and zero dispatch; a Runner without the capability cannot verify the executable and every dig.* function including check_ip fails closed with the fixed value-free unverified-executable error and zero dispatch — the module never performs a host LookPath or a bare-name PATH fallback of its own",
			"the pinned tests/pytests/unit/modules/test_dig.py vectors run through the Go transport against scripted dig answers: check_ip's 127.0.0.1 / 1111:2222:3333:4444:5555:6666:7777:8888 / 2607:fa18:0:3::4 / -127.0.0.1 / empty ladder; A's six-address ordered list; PTR's dns.google. answer; NS's resolve-default child A lookup; MX's five-row raw shape; and the three SPF fixtures (foo.com direct ip4 ranges, xmission.com include recursion, xmission-redirect.com redirect chain) all answer the pinned values",
			"input validation is pinned with zero-dispatch vectors: query names are bounded ASCII DNS names (1..63-byte labels, at most 253 bytes excluding one terminal dot, underscore labels supported) rejecting empty names, empty interior labels, whitespace, control and NUL bytes, escaped and other non-allowlisted bytes, option-like (leading -) and server-like (leading @) forms, over-long labels and names, and non-ASCII; nameservers are absent, a validated hostname, or a bare IPv4/IPv6 literal, never an @-prefixed, port-bearing, URL, CIDR, bracketed, or zoned form; PTR rejects non-literal hosts; the SPF record argument accepts exactly SPF or TXT; and every response-derived NS host, MX exchange, and SPF include/redirect target is revalidated before its child dispatch — a spoofed `-spoof.example` NS line, MX exchange, include, or redirect target rejects value-free with the partial results withheld",
			"the shared budgets are pinned: one 10s operation deadline per public call (a canceled operation context rejects with the fixed canceled class before any dispatch), at most 2s or the remaining deadline per dig process, at most 10 dig processes per operation with the SPF-to-TXT fallback and NS/MX child A lookups counted (an eleven-dispatch include fanout fails closed), at most 5 simultaneously active lookups (a six-deep redirect chain fails closed), at most 256 KiB aggregate captured output (a five-child 300 KiB NS resolve fails closed), at most 256 result entries, and per-process truncation plus defensive rejection of custom Runners ignoring the requested caps — each failure returns no partial results",
			"recursion control is pinned: active-path cycles keyed by (query, type, resolver) reject value-free (a redirect= to the active domain, an include: of the active domain, and a two-hop redirect loop all fail closed) while siblings are never deduplicated (two includes of one target both dispatch and both contribute, matching the pinned source's repeated lookups), and Runner launch, deadline, cancellation, and truncation failures map to fixed value-free classes — asserted to carry no raw argv, stdout, stderr, domain, or resolver bytes",
			"the verified Python check_ip semantics are pinned (R102-F2, runtime-oracle corrected): the address half follows Python ipaddress over net/netip — leading-zero octets, short v4 forms, whitespace-wrapped literals, and zoned IPv4 literals are invalid while the scoped IPv6 literal fe80::1%eth0 is valid (Python >= 3.9 IPv6Address accepts scope ids) and a v4-in-v6 textual literal reports IPv6, and IPv6 scope text carrying more than one percent delimiter is invalid (R102-BACKEND-FINAL-01: Python ip_address raises ValueError for fe80::1%eth0%extra where Go netip.ParseAddr accepts the same text, so one shared guard rejects more than one '%' before parsing for every consumer of the single predicate — check_ip, the A/AAAA response filter, the SPF ip6 filter, and PTR literal validation — while the valid single zone fe80::1%eth0 with or without a prefix, every IPv4/IPv6/prefix answer, and the already zone-rejecting host/query resolver validators stay unchanged; asserted with one-zone true and multiple-zone false check_ip vectors plus A/AAAA result-filter and SPF ip6 exclusion vectors and the zero-dispatch PTR rejection) — and the prefix int() accepts Python base-10 grammar: outer int() whitespace (the ASCII whitespace set plus non-ASCII Python spaces such as U+3000 — but NOT U+001C..U+001F, which int() rejects even though str.isspace() accepts them; the runtime oracle answers int('\\x1c24\\x1f') with ValueError), one ASCII +/- sign, Unicode Nd decimal digits (192.0.2.1/２４ and /٢٤ parse as 24), and single underscores strictly between digits (192.0.2.1/2_4 is valid; _24, 24_, 2__4, +_24, and interior non-digits fail like ValueError), with values still range-checked IPv4 1..32 and IPv6 8..128 and no host-bit alignment",
			"the verified Python whitespace semantics are pinned (R102-F3): the trailing rstrip applied once to dig stdout and the whitespace token split used for MX rows and SPF sections use the Python str.isspace() predicate — Go unicode.IsSpace plus U+001C..U+001F — so a trailing U+001C run is trimmed from TXT and raw NS output before the literal newline split while interior U+001C survives it, and MX/SPF fields split on U+001C like separators (10\\x1cmx.example. answers the two-field row [10 mx.example.], v=spf1\\x1cip4:... tokenizes into separate sections); response bytes and string limits are unchanged (64 KiB stdout and 8 KiB stderr per process, 256 KiB aggregate, 256 results)",
			"the preserved quirks are pinned: A and AAAA share one predicate (the verified check_ip above) retaining cross-family literals, CIDR strings, scoped IPv6 literals, order, and duplicates; PTR and TXT keep the literal newline split retaining empties, quotes, and trailing dots (an empty successful stdout answers [\"\"] like the pinned split, and raw MX answers [[]] whose rows are allocated non-nil slices exactly like Salt's line.split() — a Python list is never null — so the JSON shape is [[]] for an empty successful stdout and [] for interior blank/whitespace rows, never null, asserted with reflect-level nil-vs-empty distinctions and literal JSON decoder vectors at module and CLI surfaces, R102-FINAL-01); CNAME answers the stdout string on success including empty and [] on a completed nonzero exit; NS defaults to resolve=true and raw-splits when false with the empty answer dispatching no child; MX takes only the first A address when resolving; SPF falls back to TXT only on an exactly empty answer with record exactly SPF (counted against the call budget), strips every double quote, requires the exact first token v=spf1, honors redirect= only as the second token, keeps the pinned include/ip4/ip6 regex with +/~ prefixes and minus rejected, and preserves ordering and duplicates",
			"the pinned crash positions map to fixed results instead of panics: a lone `v=spf1` answers [] (the redirect check applies only to a second token), a malformed MX row under resolve=true and an MX exchange whose A lookup answers no address are rejected as malformed aggregates value-free, and an empty A result never panics",
			"no dig binary is executed and no DNS name is resolved anywhere in the R10 differential suite: the scripted fake Runner carries the transport contract, the trusted-resolution vectors use a test resolver over synthetic absolute paths, and the module's native contract tests carry the dns_contract build tag so the default host CI `go test ./...` does not execute them",
		},
		CompatibilityNotes: []string{
			"the pinned module passes caller strings to dig unvalidated through cmd.run_all; StateKit validates every query name, nameserver, PTR literal, and SPF record value fail-closed before dispatch and revalidates every response-derived NS/MX/include/redirect input — a security divergence, not a parity claim",
			"the pinned module resolves dig through the minion PATH and inherits its full environment; StateKit never launches a PATH-resolved dig: DefaultRunner resolves only the canonical system dig candidate paths (/usr/bin/dig, /bin/dig, /usr/local/bin/dig under full symlink-chain verification — Lstat per component, root-owned directories and symlinks with no group/world write, every symlink target cleaned and inside the approved system roots /bin, /usr, and /usr/local so a lexical prefix like /usr/ on /usr/../opt/vendor/dig never decides containment, bounded symlink hops, final target an absolute regular root-owned executable; a dig installed outside these roots, such as a homebrew or $HOME prefix, is unsupported and fails closed with the fixed unavailable error) and the child receives exactly HOME=/nonexistent (a fixed nonexistent directory; -r kept), PATH=/usr/bin:/bin, LANG=C, LC_ALL=C, TZ=UTC, while a Runner without the resolver capability fails closed with the fixed unverified-executable error and zero dispatch — security divergences (R102-SEC-01), not parity claims",
			"the pinned module has no resource bounds; StateKit bounds each public call at a shared 10s deadline, 2s per process, 10 processes, 5 active depth, 64 KiB stdout and 8 KiB stderr per process, 256 KiB aggregate output, and 256 results — resource-control divergences, not behavioral claims",
			"the pinned PTR passes the raw host to `dig -x`; StateKit requires a bare IP literal and always queries the fixed in-addr.arpa/ip6.arpa reverse form with -t PTR, so a non-literal PTR argument rejects value-free instead of dispatching dig with attacker-shaped input",
			"the pinned module maps every failure surface through retcode fallbacks (a nonzero dig exit answers the empty fallback each function specifies, preserved here); Runner launch, deadline, cancellation, and truncation failures stay fixed value-free errors because the underlying Go errors can carry argv and captured output — a safe divergence from the pinned log-and-fallback behavior",
			"the pinned SPF IndexError positions (a lone v=spf1 reading sections[1], a short MX row, an MX exchange with no A address) crash in Salt; StateKit answers [] for the lone v=spf1 and rejects the malformed MX aggregates value-free — safe divergences, not parity claims",
			"the pinned nameserver argument appends `@{nameserver}` unvalidated (an empty string appends a bare @); StateKit treats an absent nameserver and an explicitly empty one identically (no server element) and rejects every other invalid form before dispatch",
			"check_ip is gated on the dig binary exactly like __virtual__ (the whole module loads or nothing does); StateKit registers the family statically — an architectural constraint: the registration inventory and this report must stay environment-independent while the dns_contract evidence containers ship no dig binary, so bootstrap cannot skip the family without making the cataloged surface host-dependent — and instead enforces the gate per call through the Runner's optional TrustedCommandResolver capability (every dig.* function including check_ip fails closed with the fixed value-free unavailable error and zero dispatch when trusted resolution fails, and with the fixed value-free unverified-executable error and zero dispatch when the Runner has no resolver capability at all) — a registration-shape divergence preserving the availability contract, documented here exactly",
			"the native dig contract tests are build-tagged dns_contract so host CI `go test ./...` does not execute them; the rootless contract CI job remains DevOps-owned and external evidence stays pending_external_ci",
		},
	},
	"dnsutil": {
		Source:      "salt/modules/dnsutil.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		SourceTests: "tests/pytests/unit/modules/test_dnsutil.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		Platform:    "cross-platform local parsing plus dig delegation over the central shell-free Runner",
		CatalogFile: "dnsutil",
		// R10.3a is a bounded slice: exactly these eight public
		// functions are registered; hosts_append, hosts_remove, and
		// serial stay pending with recorded reasons and upgrade paths.
		RegisteredSubset: []string{
			"A", "AAAA", "MX", "NS", "SPF", "check_ip", "parse_hosts", "parse_zone",
		},
		Scenarios: []string{
			"dnsutil.availability-gating",
			"dnsutil.bounded-file-reads",
			"dnsutil.delegation-argv-and-defaults",
			"dnsutil.hosts-parser-quirks",
			"dnsutil.parser-resource-ceilings",
			"dnsutil.registry-cli-surfaces",
			"dnsutil.result-output-budgets",
			"dnsutil.time-parsing-quirks",
			"dnsutil.value-free-diagnostics",
			"dnsutil.zone-parser-quirks",
		},
		Evidence: []string{
			"the bounded R10.3a slice registers exactly eight of the eleven public dnsutil catalog functions — parse_hosts, parse_zone, check_ip, A, AAAA, NS, SPF, MX — with the pinned module's two private helpers (_to_seconds, _has_dig) kept private; hosts_append and hosts_remove stay pending because the pinned implementations mutate arbitrary caller-supplied file paths with no validation, backup, or atomicity (upgrade path: a bounded regular/no-follow writer over the same Runtime.FS discipline this slice uses), and serial stays pending because it requires a persistent grains store that StateKit does not yet have (upgrade path: register once a persistent local grains/state store module lands) — no 100%-or-family-complete claim is made for this family",
			"parse_hosts is pinned at direct, registry, and CLI surfaces against the pinned tests/pytests/unit/modules/test_dnsutil.py fixture and a local Python oracle over the pinned source: Python-falsy inline input (nil or empty string) triggers the file read, a failed read answers the exact pinned result string 'Error: hosts data was not found', comments are recognized only when '#' is column 0 (an inline '#' becomes an ordinary alias token and a ' # col0' line contributes the '#' IP key exactly like the pinned startswith check), duplicate aliases accumulate per IP in encounter order with duplicates kept, a bare-IP line answers an allocated non-nil empty alias list (JSON [] never null), and the default path is exactly /etc/hosts — never read from the host in any test (MemoryFS fixtures only)",
			"every parse_hosts/parse_zone file read runs only through runtime.ReadFileBounded over Runtime.FS with an explicit 1 MiB ceiling: regular file required, no symlink following on the final component or any parent, oversized input rejected by the bound — a fixed divergence from the pinned unbounded fopen; the symlink, directory, oversized, and missing-path vectors all answer the pinned compatibility string with no path or content bytes in any result, error, or log",
			"the documented parse_hosts divergence is pinned: a whitespace-only line raises IndexError in the pinned source and is skipped here (pinned vector), while Python splitlines/split whitespace semantics (\\r, \\r\\n, \\v, \\f, U+001C..U+001E, U+0085, U+2028, U+2029 boundaries; U+001F a split() separator but not a line boundary) are ported exactly",
			"parse_zone is pinned against the local Python oracle over the pinned source: semicolon comment stripping, $DIRECTIVE capture ($TTL, $ORIGIN), the '(' … ')' multi-line SOA join including the unterminated-parenthesis partial-result quirk, the global '@'→ORIGIN replacement, substring SOA detection, the comps.pop(1) branch for non-IN second tokens, CONTACT's first-dot→'@' replacement, _to_seconds SOA fields, the NS list, the first-MX-only quirk, the A/AAAA TARGET/TTL form for owner-TTL-IN-A/AAAA records beside the generic string bucket for 4-token records, and TXT/CAA through the generic bucket (the naive quoted-value truncation included) — all oracle-verified expected shapes asserted field-exactly",
			"every pinned parse_zone crash position maps to one fixed value-free malformed-zone error with no partial results (oracle-verified crash classes): short NS/PTR/MX record lines (IndexError), a record before any ORIGIN is known (KeyError), a directive without a value (IndexError), a non-numeric H/D refresh (ValueError), directive/record type collisions over the NS/A/TXT keys (AttributeError/TypeError), and — closed as R103A-FINAL-01 — a multi-line '(' … ')' continuation join that strips every token (the whitespace-only join of the multiline zone \"(\\n)\\n\", an empty token slice after the parenthesis/continuation parsing where the pinned parser reads comps[0] of an empty list), pinned at direct, registry (bootstrap), and CLI surfaces with the exact fixed text 'dnsutil: malformed zone data', no partial result, no panic, and zero dig dispatch; a truthy zonefile is read first through the bounded read and its content REPLACES the inline zone on success (an empty file answers the pinned not-found string even when inline data exists — oracle-verified) while read failures silently keep the inline data exactly like the pinned try/except",
			"the R10.3A-SEC-01 parser ceilings are pinned with exact boundaries and small inputs (no huge allocations): inline hosts/zone values are capped at the shared 1 MiB source ceiling before processing (exactly 1 MiB of comment parses and one byte over rejects value-free with no partial result), hostsfile/zonefile path arguments over 4096 bytes are rejected BEFORE the filesystem is touched (a counting fake filesystem proves zero bounded reads) answering the pinned read-failure compatibility shapes (the hosts not-found string and the zone inline fallback), a path of exactly 4096 bytes still reaches the filesystem, and a fake bounded filesystem reporting oversize without holding data answers the same compatibility shapes for the file side of the shared ReadFileBounded 1 MiB ceiling",
			"the R10.3A-SEC-01 in-parser ceilings are pinned with exact boundaries: at most 4096 input records (non-blank, non-comment lines — 4096 unique hosts rows parse and 4097 reject value-free; the $ORIGIN directive plus 4095 zone record lines parses and one more rejects) and at most 4096 bytes per parsed token or derived cell (a token of exactly 4096 parses and one byte over rejects, including directive values), each answering the fixed value-free 'dnsutil: parser limit exceeded', and the '@'→ORIGIN expansion is guarded BEFORE allocation by the exact match-count estimate len(line)+matches*(len(origin)-1) in int64 (a dot-terminated 4096-byte origin with 255 spaced '@' tokens computes 1,044,734 bytes, stays within the 1 MiB ceiling and parses; 256 tokens compute 1,048,831 bytes and reject value-free) — the multi-line continuation join and the expansion are linear builders (no repeated string concatenation), and every slice/index access is length-checked so no input can panic the parser",
			"the R103A-GATE-01/02 result budgets are pinned with exact boundaries against an encoding/json test oracle: the aggregate ceiling is 4 MiB of the COMPLETE serialized result representation — every map key (including every expanded '@'→ORIGIN generic-bucket key), every value, the exact JSON escaping (quotes, backslash, the \\b\\f\\n\\r\\t short forms, the remaining control bytes, the HTML triplet <, >, &, U+2028/U+2029, and invalid UTF-8), and every nested map/array delimiter, colon, and comma — tracked exactly while the result is built through a jsonStringLength length oracle plus per-insertion structural deltas (the parser never calls json.Marshal and never materializes an encoded result; the overflow-safe counters are compared as delta > ceiling minus current), enforced BEFORE a key/value/row is inserted with one fixed value-free error ('dnsutil: result byte limit exceeded'); the nested TARGET/TTL object of the A/AAAA form contributes exactly 18 structural bytes excluding the encoded values ({, \\\"TARGET\\\", :, ,, \\\"TTL\\\", :, } — R103A-FINAL-BYTES-01 corrected both calculation sites from a one-byte overcount), pinned by an exact-boundary oracle: a nested A/AAAA result whose exact compact encoding is exactly 4,194,304 bytes parses with byte-exact oracle shape while one encoded byte above rejects before insertion with nil result; the item ceiling is 8192 retained result items — every JSON object member across all nested maps plus every list element and duplicate-appended element, so one owner-TTL-IN-A record accounts its owner member and the TARGET and TTL members, and 4095 unique owner-TTL-IN-A rows retain 12,287 items (ORIGIN + the A bucket member + 3 per row; the exact boundary is 2730 rows = 8192 items) — with its own fixed value-free error ('dnsutil: result item limit exceeded'); both counters are exact at every step and REPLACE a key/member's old retained subtree with the new subtree's exact byte and item delta (R103A-GATE-02 closed: a plain-string bucket owner morphing into the TARGET/TTL object gains its two nested members, an object flattened to a string or a directive flattening a whole bucket/list subtree returns every nested item it removes, so a shape-changing replacement reserves exactly new-minus-old and the counters stay monotonic — no sequence of records, overwrites, or duplicate appends can end over a ceiling the counter did not see) while duplicate rows keep Salt order; the gate probes are regression-pinned at direct, registry (bootstrap), and CLI surfaces: the ~17 KiB zone (origin = 3999 'a' chars + dot, 1024 distinct records 'x. IN @<i> @') that previously answered ~8.2 MB of JSON rejects value-free with nil result before the budget is exceeded (the boundary located by bisection against the oracle map: the largest fitting count parses with byte-exact oracle shape and size, one more rejects), 1100 distinct 't<i>@' type keys over a 4081-byte origin reject before the expanded bucket key is inserted, the 4095-row item fanout rejects with nil result, the shape-changing-replacement regression ($ORIGIN + two generic A strings for x0/x1 + the two owner-TTL-IN-A rewrites of those owners + 2729 fresh rows = 8195 final retained items, which the pre-fix zero-delta accounting let escape at a counter reading of 8191) rejects with nil result while the separate exact-8192 2730-row structure parses, the top-level bucket→directive shrink (a 100-owner TXT bucket flattened to one scalar before the exact-8192 fill that the stale counter falsely rejected) parses and its one-row-over variant rejects, control-byte escaping amplification on parse_hosts (each 4096-byte \\x01 alias retains 24,578 JSON bytes) rejects 200 aliases value-free, and under-ceiling distinct buckets carrying quotes/backslash/control/DEL/HTML-triplet/non-ASCII keys and values parse successfully with the measured encoding/json size within the cap (U+2028/U+2029 are pythonSplitlines line boundaries that cannot survive into a parser cell, so their escaping classes are oracle-pinned at the jsonStringLength level); empty containers follow the documented definition — an empty alias list or bucket contributes zero items and only its two delimiter bytes to the byte budget, and null never appears",
			"_to_seconds is pinned with the pinned unit vectors (4H→14400, 1D→86400, 2W→604800, ''→604800, 604801→604800) plus the oracle-verified quirk set: case-insensitive H/D/W, every 'H'/'D' removed before the parse, the W branch answering one week without any numeric parse ('w', 'abcW'), the else branch answering one week for unparsable values ('abc', U+001C-wrapped digits), zero and negatives passing through (0H→0, -2H→-7200, -1→-1), 168H landing exactly on the cap, and Python base-10 int() grammar — outer int() whitespace (' 12 H '→43200), Unicode Nd digits (２４H→86400, ٢٤H→86400), single between-digit underscores (2_4H→86400; _24H rejects), and one ASCII sign (+2H→7200); positive magnitudes beyond int64 still cap to one week and negative magnitudes saturate to math.MinInt64 (documented divergence from Python's arbitrary-precision ints), and the single-codepoint U+1E96 full-uppercase divergence is documented in the source",
			"the dig-backed surface delegates to the registered dig family through rt.Exec.Call with exact argument pass-through pinned at direct, registry, and CLI surfaces: nameservers forward as-is, NS forwards resolve with the pinned True default and explicit false, SPF forwards record with the pinned exact 'SPF' default and explicit TXT, MX forwards resolve with the pinned False default, and check_ip forwards addr — the delegated result value and error class propagate unchanged (dig's fixed value-free errors included), the caller's context carries cancellation into the nested call, and the dig module's own budgets and trusted-process boundary apply per delegation",
			"_has_dig is ported as the trusted-resolution gate through the Runner's optional process.TrustedCommandResolver capability (the dig module's documented PATH divergence): a failing resolver, a capability-less Runner, and no Runner at all answer the pinned result string 'This function requires dig, which is not currently available' with zero dispatch, and the pinned A/AAAA socket.getaddrinfo fallback is an explicitly deferred divergence — no host resolver egress exists (no net.DefaultResolver, no net.LookupIP, no socket use anywhere in the family); when the gate passes but the registry carries no matching dig function (the pinned __salt__ lookup crash position), the call fails closed with one fixed value-free unavailable error",
			"no dig binary is executed, no DNS name is resolved, no network is touched, and no host /etc/hosts or zone file is read anywhere in the R10 differential suite: the dig delegation vectors run over the real dig family with a scripted fake Runner behind a test trusted resolver, the file vectors run over runtime.MemoryFS, and the native dnsutil contract tests carry the dns_contract build tag so the default host CI `go test ./...` does not execute them",
		},
		CompatibilityNotes: []string{
			"the pinned parse_hosts/parse_zone read caller-named files unbounded through salt.utils.files.fopen; StateKit reads only through runtime.ReadFileBounded with an explicit 1 MiB ceiling, a regular-file requirement, and no symlink following — a security divergence, not a parity claim; the boundary is intended for local trusted same-principal CLI use only",
			"the pinned parsers have no resource bounds and crash on the empty multi-line join (IndexError on comps[0] of an empty list); StateKit enforces the exact parser ceilings — the shared 1 MiB ceiling on inline hosts/zone values, file reads, and the computed '@'→ORIGIN expansion size, a 4096-byte bound on hostsfile/zonefile path arguments rejected before filesystem use, at most 4096 input records, 8192 retained result items (every nested JSON object member plus every list and duplicate-appended element, so one A/AAAA record accounts owner + TARGET + TTL), 4096-byte cells, and 4 MiB of the COMPLETE serialized result representation (every map key including expanded bucket keys, every value, the exact encoding/json escaping, and every delimiter, colon, and comma — counted exactly while the result is built and enforced BEFORE insertion, never by encoding an oversized result; the nested TARGET/TTL entry contributes its exact 18 structural bytes and every shape-changing replacement reserves the exact new-minus-old subtree delta of both the byte and item budgets) — and maps the empty-join IndexError to the fixed value-free malformed-zone error; every ceiling failure answers one fixed value-free error ('dnsutil: input exceeds limit', 'dnsutil: parser limit exceeded', 'dnsutil: result item limit exceeded', or 'dnsutil: result byte limit exceeded') with no partial results, the joins and expansions are linear builders, and all slice access is length-checked — security divergences (R103A-FINAL-01/R10.3A-SEC-01/R103A-GATE-01/02/R103A-FINAL-BYTES-01 closed), not parity claims",
			"the pinned parse_hosts raises IndexError on a whitespace-only line; StateKit skips such lines — a documented safe divergence",
			"the pinned parse_zone crashes on short record lines, missing ORIGIN, malformed SOA fields, a non-numeric H/D time value, and directive/record type collisions; StateKit maps every crash position to one fixed value-free malformed-zone error with no partial results — a safe divergence, not a parity claim",
			"the pinned parse_zone is a simplistic line parser, and so is this port (parser ceiling, not RFC 1035 complete): no $INCLUDE, no escape/quoting handling, no TTL inheritance, no class negotiation; Python dicts preserve insertion order and Go maps do not, so record-bucket key order is not preserved (list order is)",
			"the pinned _to_seconds relies on Python's arbitrary-precision int; StateKit saturates magnitudes beyond int64 (positive saturation still caps to one week; negative saturation answers math.MinInt64) and Go's simple ToUpper does not reproduce the single U+1E96 full-uppercase expansion — documented micro-divergences",
			"the pinned check_ip/A/AAAA/NS/SPF/MX call __salt__['dig.*'] after a PATH which() probe, and the pinned A/AAAA fall back to socket.getaddrinfo when dig is missing; StateKit gates through the Runner's TrustedCommandResolver capability, answers the pinned unavailable string when the gate fails, defers the socket fallback (no host resolver egress), and maps the registry-miss crash position to a fixed value-free error — availability-shape divergences documented here exactly",
			"hosts_append and hosts_remove stay pending because the pinned implementations mutate arbitrary caller paths with no validation, backup, or atomicity, and serial stays pending because its pinned contract requires a persistent grains store; the upgrade paths are recorded in the family evidence and the porting ledger — no family-complete claim is made",
		},
	},
	"slack": {
		Source:      "salt/modules/slack_notify.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		SourceTests: "tests/pytests/unit/modules/test_slack.py, tests/pytests/unit/utils/test_slack.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		Platform:    "cross-platform stdlib HTTP client",
		CatalogFile: "slack_notify",
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
var r10FamilyOrder = []string{"dig", "dnsutil", "slack"}

type r10FamilyReport struct {
	Catalog         int      `yaml:"catalog_functions"`
	Public          int      `yaml:"public_functions"`
	Private         int      `yaml:"private_functions"`
	Registered      int      `yaml:"registered_public"`
	PendingPublic   []string `yaml:"pending_public,omitempty"`
	Platform        string   `yaml:"platform"`
	Scenarios       []string `yaml:"differential_scenarios"`
	SourceReference string   `yaml:"source_reference"`
	SourceTests     string   `yaml:"source_tests"`
	// SourceAliases counts the pinned source-module aliases beside the
	// canonical catalog names; RegisteredAliases counts those actually
	// registered. The dig family ships 7 (a, ptr, aaaa, cname, ns, spf,
	// mx — the pinned module tail has no txt alias).
	SourceAliases      int      `yaml:"source_aliases,omitempty"`
	RegisteredAliases  int      `yaml:"registered_aliases,omitempty"`
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
	Catalog           int `yaml:"catalog_functions"`
	Public            int `yaml:"public_functions"`
	Registered        int `yaml:"registered_public"`
	Pending           int `yaml:"pending_public"`
	SourceAliases     int `yaml:"source_aliases,omitempty"`
	RegisteredAliases int `yaml:"registered_aliases,omitempty"`
}

// r10SlackCatalogFile is the catalog entry of the slack family (the file
// keeps the pinned source module name slack_notify while the runtime
// module is the pinned virtual name slack).
const r10SlackCatalogFile = "slack_notify"

func loadR10Catalog(t *testing.T) (string, []string) {
	return loadR10CatalogFile(t, r10SlackCatalogFile, "slack")
}

func loadR10CatalogFile(t *testing.T, file, wantModule string) (string, []string) {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "catalog", "exec", file+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("catalog %s: %v", file, err)
	}
	var parsed struct {
		Module    string `yaml:"module"`
		Functions []struct {
			Function string `yaml:"function"`
		} `yaml:"functions"`
	}
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("catalog %s parse: %v", file, err)
	}
	names := make([]string, 0, len(parsed.Functions))
	for _, fn := range parsed.Functions {
		names = append(names, fn.Function)
	}
	sort.Strings(names)
	if parsed.Module != wantModule {
		t.Fatalf("catalog module = %q, want %s", parsed.Module, wantModule)
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
		Round:    "R10.3a",
		Platform: "cross-platform",
		RuntimeStatus: "mock-only differential contract: no Slack endpoint is contacted, no dig binary is executed, " +
			"no DNS name is resolved, no host /etc/hosts or zone file is read, and no live Salt runs; the testing-scoped " +
			"fake HTTP transport, the loopback-only httptest vectors (exact-origin redirect chains, foreign-origin hook " +
			"rejection), the scripted fake Runner behind the dig and dnsutil families (exact argv, shell-free dispatch), " +
			"and the MemoryFS fixtures behind the dnsutil file reads provide the executable contract",
		BehavioralParity: "not claimed: local R10 differential tests do not execute live Salt, Slack, or dig; the R10 plan's opt-in live smoke is not implemented; separately configured external CI is pending_external_ci",
		ExternalCI:       "pending_external_ci",
		Families:         map[string]r10FamilyReport{},
		PriorReports:     priorR3R9ReportHashes(t),
		RepeatStable:     repeatStable,
	}

	for _, familyName := range r10FamilyOrder {
		spec := r10FamilySpecs[familyName]
		catalogModule, catalogNames := loadR10CatalogFile(t, spec.CatalogFile, familyName)
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
		family.SourceAliases = len(spec.Aliases)
		for _, alias := range spec.Aliases {
			if registered[catalogModule+"."+alias] {
				family.RegisteredAliases++
			}
		}

		// Complete families (R10.1 slack, R10.2 dig) must register
		// every public catalog function — and every declared source
		// alias — with nothing pending. A bounded-slice family
		// (R10.3a dnsutil) must register exactly its declared subset:
		// every subset name registered, every other public name
		// pending, and no extra registration.
		if spec.RegisteredSubset == nil {
			if family.Registered != family.Public || len(family.PendingPublic) != 0 ||
				family.RegisteredAliases != family.SourceAliases {
				t.Fatalf("R10 %s registration incomplete: %+v", familyName, family)
			}
		} else {
			subset := map[string]bool{}
			for _, name := range spec.RegisteredSubset {
				subset[name] = true
				if !registered[catalogModule+"."+name] {
					t.Fatalf("R10 %s subset name %s not registered", familyName, name)
				}
			}
			for _, pending := range family.PendingPublic {
				if subset[strings.TrimPrefix(pending, catalogModule+".")] {
					t.Fatalf("R10 %s subset name %s reported pending", familyName, pending)
				}
			}
			if family.Registered != len(subset) ||
				len(family.PendingPublic) != family.Public-len(subset) {
				t.Fatalf("R10 %s slice registration mismatch: %+v subset=%d",
					familyName, family, len(subset))
			}
		}

		report.Totals.Catalog += family.Catalog
		report.Totals.Public += family.Public
		report.Totals.Registered += family.Registered
		report.Totals.Pending += len(family.PendingPublic)
		report.Totals.SourceAliases += family.SourceAliases
		report.Totals.RegisteredAliases += family.RegisteredAliases
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
// source contains platform branching elsewhere. Complete families
// assert every public catalog name; a bounded-slice family asserts its
// registered subset and that the pending names are genuinely absent.
func TestR10FunctionsArePlatformNeutral(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	for _, familyName := range r10FamilyOrder {
		spec := r10FamilySpecs[familyName]
		module, catalogNames := loadR10CatalogFile(t, spec.CatalogFile, familyName)
		subset := map[string]bool{}
		for _, name := range spec.RegisteredSubset {
			subset[name] = true
		}
		for _, name := range catalogNames {
			if strings.HasPrefix(name, "_") {
				continue
			}
			full := module + "." + name
			fn, ok := rt.Exec.Get(full)
			if spec.RegisteredSubset == nil || subset[name] {
				if !ok {
					t.Fatalf("missing %s", full)
				}
				if constrained, ok := fn.(runtime.PlatformConstrained); ok {
					t.Fatalf("%s unexpectedly constrained to %v", full, constrained.Platforms())
				}
				continue
			}
			if ok {
				t.Fatalf("pending %s unexpectedly registered", full)
			}
		}
		for _, alias := range spec.Aliases {
			full := module + "." + alias
			fn, ok := rt.Exec.Get(full)
			if !ok {
				t.Fatalf("missing alias %s", full)
			}
			if constrained, ok := fn.(runtime.PlatformConstrained); ok {
				t.Fatalf("%s unexpectedly constrained to %v", full, constrained.Platforms())
			}
		}
	}
}

// TestR10DNSContractTagBoundary statically pins the dns_contract build
// tag boundary for the R10 behavioral tests: the default untagged
// host test list (`go test ./...`) must declare no TestR10Dig* or
// TestR10DNSUtil* function, while the dns_contract-tagged files of
// this package must declare exactly the contract tests executed by the
// rootless contract job (`go test -tags=dns_contract ...
// ./tests/differential`). The check is a deterministic source scan of
// this package directory — it executes no dig binary, resolves no DNS
// name, and touches no network.
func TestR10DNSContractTagBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	digTestFunc := regexp.MustCompile(`^func (TestR10Dig\w+)\(t \*testing\.T\) \{`)
	dnsutilTestFunc := regexp.MustCompile(`^func (TestR10DNSUtil\w+)\(t \*testing\.T\) \{`)
	untagged := map[string]bool{}
	tagged := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		tagContract := false
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "package ") {
				break
			}
			if strings.HasPrefix(line, "//go:build") && strings.Contains(line, "dns_contract") {
				tagContract = true
			}
		}
		found := untagged
		if tagContract {
			found = tagged
		}
		for _, line := range lines {
			if m := digTestFunc.FindStringSubmatch(line); m != nil {
				found[m[1]] = true
			}
			if m := dnsutilTestFunc.FindStringSubmatch(line); m != nil {
				found[m[1]] = true
			}
		}
	}
	if len(untagged) != 0 {
		names := make([]string, 0, len(untagged))
		for name := range untagged {
			names = append(names, name)
		}
		sort.Strings(names)
		t.Fatalf("dns_contract test functions reachable by the default untagged test list: %v", names)
	}
	want := []string{
		"TestR10DNSUtilDelegationArgv",
		"TestR10DNSUtilGateAndPendingLedger",
		"TestR10DNSUtilParserBoundsAndMalformedJoins",
		"TestR10DNSUtilPinnedSourceVectors",
		"TestR10DigMockDifferential",
		"TestR10DigPythonSemantics",
		"TestR10DigTrustedGateAndUnverifiedExecutable",
	}
	got := make([]string, 0, len(tagged))
	for name := range tagged {
		got = append(got, name)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dns_contract behavioral tests = %v, want %v", got, want)
	}
}

func init() {
	// Keep scenario emission deterministic like the R9 generator.
	for _, spec := range r10FamilySpecs {
		sort.Strings(spec.Scenarios)
	}
}
