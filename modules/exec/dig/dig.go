// Package dig implements the pinned Salt dig execution module
// (saltstack/salt/modules/dig.py @
// 8b63e700637e40d76f80a00d95c60471797c73b9, virtual name "dig") as one
// Go family over the central shell-free Runner.
//
// R10.2 registers the family's complete public catalog: check_ip, A,
// PTR, AAAA, CNAME, NS, SPF, MX, and TXT, plus the seven source aliases
// of the pinned module tail (a, ptr, aaaa, cname, ns, spf, mx — there
// is no txt alias in the pinned source). dig.__virtual__ gates the whole
// module on the dig binary. StateKit registers the family statically
// (the registration inventory and the differential report must stay
// environment-independent: the dns_contract evidence containers ship no
// dig binary, so bootstrap cannot skip the family without making the
// cataloged surface depend on the host) and enforces the gate per call
// through the Runner's optional process.TrustedCommandResolver
// capability (R102-SEC-01): when the Runner resolves dig, the resolved
// absolute trusted path becomes argv[0] and every dig.* function
// including check_ip fails closed with the fixed value-free gate error
// when resolution fails; a Runner without the capability cannot verify
// the executable, so every dig.* function fails closed with the fixed
// unverified-executable error and zero dispatch — the module never
// falls back to a host LookPath or a bare-name PATH dispatch of its
// own. This registration-shape divergence from __virtual__ (load-time
// skip versus call-time fixed unavailability) is deliberate and
// documented.
//
// Trusted native boundary (R102-SEC-01): DefaultRunner resolves only
// the canonical system dig candidate paths, symlink-resolves each, and
// requires an absolute regular executable that is root-owned with no
// group/world write on the binary and every path component; unsupported
// names/platforms, untrusted paths, and missing binaries fail closed.
// Every dig process runs the resolved absolute path with no inherited
// environment: the child receives exactly HOME=/nonexistent (a fixed
// nonexistent directory; -r already ignores per-user digrc),
// PATH=/usr/bin:/bin, LANG=C, LC_ALL=C, and TZ=UTC, so RES_OPTIONS,
// LOCALDOMAIN, HOSTALIASES, LD_*, and any caller secret from the parent
// environment cannot reach dig. A Runner that cannot establish a
// trusted executable (no TrustedCommandResolver capability) fails every
// dig.* function closed with the fixed unverified-executable error and
// zero dispatch — the module never falls back to a bare-name PATH
// lookup of its own.
//
// Transport contract: the fixed dig executable is always dispatched as
// an explicit argv (Shell=false, no generic flags, no shell) shaped
// `dig -r +short -q <name> -t <type> [@server]`: -r ignores user dig
// configuration, +short keeps the pinned short form, the query name
// rides an explicit -q value, and the RR type is fixed by the calling
// function (A/AAAA/CNAME/NS/MX/SPF/TXT/PTR). PTR validates its argument
// as a bare IP literal first and always queries the fixed reverse form
// (d.c.b.a.in-addr.arpa or the nibble-reversed ip6.arpa name) with -t
// PTR — the pinned source's raw `-x <host>` spelling is never used, so
// no caller-controlled dig flag surface exists. A nameserver is a
// single optional validated `@server` argv element.
//
// Input validation (a documented safe divergence from the pinned
// source, which passes caller strings to dig unvalidated): query names
// are bounded ASCII DNS names — 1..63-byte labels, at most 253 bytes
// excluding one terminal dot, underscore labels supported — rejecting
// empty names, empty interior labels, whitespace, control and NUL
// bytes, escaped and other non-LDH/underscore bytes, option-like
// (leading "-") and server-like (leading "@") forms, and non-ASCII.
// Nameservers are absent, a validated hostname, or a bare IPv4/IPv6
// literal — never an @-prefixed, port-bearing, URL, CIDR, bracketed, or
// zoned form. The SPF record argument accepts exactly SPF or TXT. Every
// response-derived NS host, MX exchange, and SPF include/redirect
// target is revalidated through the same validators before any child
// dispatch, so untrusted DNS data can never steer flags or shell.
//
// Resource bounds (each a fixed, documented divergence from the pinned
// module, which has none): one shared 10s operation deadline per public
// call, at most 2s (or the remaining deadline) per dig process, at most
// 10 dig processes per operation (the SPF->TXT fallback and NS/MX child
// A lookups are counted), at most 5 simultaneously active lookups, at
// most 64 KiB stdout and 8 KiB stderr captured per process, at most
// 256 KiB aggregate captured output, and at most 256 result entries.
// Recursion carries active-path cycle detection keyed by
// (query, type, resolver) — siblings are never deduplicated, matching
// the pinned source's repeated child lookups — and truncation,
// cancellation, deadline, launch, and budget failures reject the whole
// operation without partial results.
//
// Python semantics are ported exactly where the pinned source depends
// on them (R102-F2/R102-F3, verified against the runtime checker):
// check_ip keeps the pinned prefix ranges (IPv4 1..32, IPv6 8..128, no
// host-bit alignment) over Python ip_address semantics on net/netip —
// leading-zero octets and short v4 forms are invalid, a scoped IPv6
// literal such as fe80::1%eth0 is valid (Python >= 3.9 IPv6Address
// accepts scope ids) while scope text with more than one percent
// delimiter (fe80::1%eth0%extra) is invalid because Python ip_address
// rejects it and Go netip.ParseAddr would accept it (one shared guard
// rejects more than one '%' before parsing — R102-BACKEND-FINAL-01,
// with the exact single-zone, IPv4, IPv6, and prefix answers
// unchanged), and a v4-in-v6 textual literal reports IPv6; the
// prefix int() conversion accepts Python base-10 grammar: outer int()
// whitespace (ASCII whitespace plus non-ASCII Python spaces such as
// U+3000 — but not U+001C..U+001F, which int() rejects even though
// str.isspace() accepts them), one ASCII +/- sign, Unicode Nd decimal
// digits (so fullwidth "２４" parses as 24), and single underscores
// strictly between digits ("2_4" parses, "_24", "24_", "2__4" do not).
// The str.isspace() predicate (Go's unicode.IsSpace plus U+001C..U+001F)
// separately drives the trailing rstrip applied once to dig stdout and
// the whitespace token split used for MX rows and SPF sections.
//
// Compatibility shapes are preserved exactly where the pinned source
// specifies them: A and AAAA share one predicate and retain
// cross-family and CIDR strings, order, and duplicates; PTR and TXT
// keep the literal newline split (empties, quotes, and trailing dots
// retained — an empty successful stdout answers [""] for PTR/TXT and
// [[]] for raw MX, whose rows are allocated non-nil slices like
// Python's line.split() so the JSON shape is [] and never null —
// R102-FINAL-01); CNAME answers the stdout string on success
// (including empty) and [] on a completed nonzero exit; NS defaults to
// resolve=true and raw-splits when false; MX answers raw string rows
// and, when resolving, takes only the first A address per exchange; SPF
// falls back to TXT only on an exactly empty SPF-record answer with
// record exactly "SPF", strips every double quote, requires the exact
// first token v=spf1, honors redirect= only as the second token, and
// keeps the pinned include/ip4/ip6 regex with ordering and duplicates.
// Salt cmd.run_all's trailing whitespace rstrip is applied once to dig
// stdout before parsing, exactly like the pinned transport.
//
// The pinned Python crash positions map to fixed value-free results
// instead of panics: a lone `v=spf1` token answers [] (the redirect
// check only applies to a second token), a malformed MX row under
// resolve=true and an MX exchange whose A lookup answers no address are
// rejected as malformed aggregates, and a nonzero dig process exit maps
// to the source empty fallback wherever the pinned function specifies
// one. Runner launch, deadline, cancellation, and truncation failures
// are fixed value-free errors — no raw argv, stdout, stderr, domain, or
// resolver ever enters an error or log surface.
package dig

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	// digExecutable is the fixed query binary; __virtual__ gates on it.
	digExecutable = "dig"

	recordA     = "A"
	recordPTR   = "PTR"
	recordAAAA  = "AAAA"
	recordCNAME = "CNAME"
	recordNS    = "NS"
	recordSPF   = "SPF"
	recordMX    = "MX"
	recordTXT   = "TXT"

	// operationDeadline bounds one public dig call end to end.
	operationDeadline = 10 * time.Second
	// callTimeout bounds a single dig process (or the remaining
	// operation deadline, whichever is smaller).
	callTimeout = 2 * time.Second
	// maxDigCalls bounds dig processes per operation, counting the
	// SPF->TXT fallback and every NS/MX child A lookup.
	maxDigCalls = 10
	// maxActiveDepth bounds simultaneously active lookups on one
	// recursion path (SPF include/redirect chains, NS/MX children).
	maxActiveDepth = 5
	// maxStdoutPerCall and maxStderrPerCall bound captured output per
	// dig process.
	maxStdoutPerCall = 64 << 10
	maxStderrPerCall = 8 << 10
	// maxAggregateOutput bounds total captured output per operation.
	maxAggregateOutput = 256 << 10
	// maxResults bounds the entries one public call may return.
	maxResults = 256
	// maxNameBytes and maxLabelBytes are the DNS name bounds (the name
	// length limit excludes exactly one terminal dot).
	maxNameBytes  = 253
	maxLabelBytes = 63
)

var (
	errDigRunnerUnavailable = errors.New("dig: runner unavailable")
	// errDigUnavailable mirrors the pinned __virtual__ gate: the whole
	// module, check_ip included, fails closed when trusted dig
	// resolution cannot establish a trusted binary.
	errDigUnavailable = errors.New("dig module cannot be loaded: the dig binary is not in the path")
	// errDigUnverifiedExecutable is the fixed fail-closed answer for a
	// Runner that cannot establish a trusted dig executable at all (no
	// TrustedCommandResolver capability). The module never substitutes
	// a bare-name dispatch or a PATH lookup of its own, so the
	// unverified executable is never run.
	errDigUnverifiedExecutable = errors.New("dig: unverified executable")
	// Value-free input rejections: none of these carry the rejected
	// name, resolver, or record value.
	errDigInvalidName       = errors.New("dig: invalid query name")
	errDigInvalidNameserver = errors.New("dig: invalid nameserver")
	errDigInvalidRecord     = errors.New("dig: invalid record type")
	errDigInvalidAddress    = errors.New("dig: invalid address")
	// Fixed value-free budget failures.
	errDigCallBudget      = errors.New("dig: call budget exceeded")
	errDigDepthBudget     = errors.New("dig: lookup depth exceeded")
	errDigCycle           = errors.New("dig: lookup cycle detected")
	errDigOutputLimit     = errors.New("dig: output limit exceeded")
	errDigAggregateLimit  = errors.New("dig: aggregate output limit exceeded")
	errDigResultLimit     = errors.New("dig: result limit exceeded")
	errDigMalformedRecord = errors.New("dig: malformed record")
	// Fixed value-free Runner failure classes; the underlying errors can
	// carry argv or captured output, so only the class travels onward.
	errDigLaunch   = errors.New("dig: command failed to start")
	errDigTimeout  = errors.New("dig: command timed out")
	errDigCanceled = errors.New("dig: command canceled")

	// digCommandEnv is the exact environment every dig process receives
	// (R102-SEC-01): the parent environment is never inherited, so
	// RES_OPTIONS, LOCALDOMAIN, HOSTALIASES, LD_*, and any caller secret
	// cannot reach the child. HOME is the fixed nonexistent directory
	// /nonexistent (dig -r already ignores per-user digrc, and no home
	// directory is provisioned per call); PATH, LANG, LC_ALL, and TZ are
	// fixed.
	digCommandEnv = []string{
		"HOME=/nonexistent",
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/bin:/bin",
		"TZ=UTC",
	}

	// spfRe ports the pinned `(?:\+|~)?(ip[46]|include):(.+)` matcher.
	// re.match anchors at the start; sections come from a whitespace
	// split so they never contain newlines.
	spfRe = regexp.MustCompile(`^(?:\+|~)?(ip[46]|include):(.+)$`)
)

// ---------------------------------------------------------------------------
// shared operation state

// digOp carries the shared budget of one public call: the resolved
// trusted dig executable path, the operation deadline, the per-operation
// call and output budgets, and the active lookup path used for cycle and
// depth detection. Child lookups (SPF include/redirect recursion, the
// SPF->TXT fallback, NS/MX A resolves) run on the same digOp so every
// budget is shared.
type digOp struct {
	rt        *runtime.Runtime
	ctx       context.Context
	deadline  time.Time
	calls     int
	aggregate int
	active    map[string]bool
	// path is argv[0] of every dispatch: the trusted absolute dig
	// binary path resolved through the Runner's
	// TrustedCommandResolver capability (a capability-less Runner never
	// reaches a dispatch; it fails closed first).
	path string
}

// newDigOp starts the shared 10s operation deadline. Callers must defer
// the returned cancel.
func newDigOp(ctx context.Context, rt *runtime.Runtime, digPath string) (*digOp, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	opCtx, cancel := context.WithTimeout(ctx, operationDeadline)
	return &digOp{
		rt:       rt,
		ctx:      opCtx,
		deadline: time.Now().Add(operationDeadline),
		active:   make(map[string]bool),
		path:     digPath,
	}, cancel
}

// frameKey identifies one lookup on the active path by query, type, and
// resolver together.
func frameKey(name, rrtype, nameserver string) string {
	return name + "\x00" + rrtype + "\x00" + nameserver
}

// enter pushes one lookup onto the active path, rejecting an identical
// in-flight lookup (cycle) and any fifth-level nesting (depth). exit
// pops it, so sibling lookups of the same target stay allowed — only a
// repeat on the active path is a cycle.
func (op *digOp) enter(key string) error {
	if op.active[key] {
		return errDigCycle
	}
	if len(op.active) >= maxActiveDepth {
		return errDigDepthBudget
	}
	op.active[key] = true
	return nil
}

func (op *digOp) exit(key string) { delete(op.active, key) }

// dispatch runs one dig process. It validates every input (including
// response-derived names) before the Runner is touched, shapes the
// fixed argv, enforces the shared call and output budgets, and maps
// Runner failures onto fixed value-free errors. A nonzero process exit
// is compatibility data: the caller applies the source empty fallback
// where the pinned function specifies one.
func (op *digOp) dispatch(name, rrtype, nameserver string) (stdout string, nonzero bool, err error) {
	if !validQueryName(name) {
		return "", false, errDigInvalidName
	}
	if nameserver != "" && !validNameserver(nameserver) {
		return "", false, errDigInvalidNameserver
	}
	if op.calls >= maxDigCalls {
		return "", false, errDigCallBudget
	}
	if err := op.ctx.Err(); err != nil {
		return "", false, classifyRunnerErr(err)
	}
	remaining := time.Until(op.deadline)
	if remaining <= 0 {
		return "", false, errDigTimeout
	}
	timeout := callTimeout
	if remaining < timeout {
		timeout = remaining
	}
	argv := []string{op.path, "-r", "+short", "-q", name, "-t", rrtype}
	if nameserver != "" {
		argv = append(argv, "@"+nameserver)
	}
	command := runtime.Command(argv...)
	command.Shell = false
	command.Timeout = timeout
	command.MaxStdoutBytes = maxStdoutPerCall
	command.MaxStderrBytes = maxStderrPerCall
	// No inherited environment: the child sees exactly the fixed
	// allowlist (a fresh copy, so no Runner can mutate the shared
	// template).
	command.Env = append([]string(nil), digCommandEnv...)
	op.calls++
	result := op.rt.Runner.Run(op.ctx, command)
	op.aggregate += len(result.Stdout) + len(result.Stderr)
	if op.aggregate > maxAggregateOutput {
		return "", false, errDigAggregateLimit
	}
	if result.Err != nil {
		return "", false, classifyRunnerErr(result.Err)
	}
	if err := op.ctx.Err(); err != nil {
		return "", false, classifyRunnerErr(err)
	}
	// Defend against custom Runners that ignore the requested bounds.
	if result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stdout) > maxStdoutPerCall || len(result.Stderr) > maxStderrPerCall {
		return "", false, errDigOutputLimit
	}
	// Salt cmd.run_all rstrips trailing Python whitespace once before
	// the result reaches the module; the pinned parsers rely on it.
	return pythonRstrip(string(result.Stdout)), result.ExitCode != 0, nil
}

// classifyRunnerErr maps any Runner or context failure onto one fixed
// value-free sentinel. The wrapped errors can embed the full command
// display (argv) or captured output, so the message never travels.
func classifyRunnerErr(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return errDigTimeout
	case errors.Is(err, context.Canceled):
		return errDigCanceled
	case errors.Is(err, process.ErrOutputLimit):
		return errDigOutputLimit
	default:
		return errDigLaunch
	}
}

// resolveDig enforces the pinned __virtual__ gate through the Runner's
// optional process.TrustedCommandResolver capability (R102-SEC-01) and
// returns argv[0] for the operation. DefaultRunner resolves only the
// canonical system dig candidate paths — symlink-resolved, absolute,
// regular, executable, root-owned, and free of group/world write on the
// binary and every path component — and fails closed on unsupported
// names/platforms, untrusted paths, and missing binaries. A Runner
// without the capability cannot verify the executable, so every call
// fails closed with the fixed errDigUnverifiedExecutable error and zero
// dispatch: the module never performs a host LookPath or a bare-name
// PATH fallback of its own.
func resolveDig(rt *runtime.Runtime) (string, error) {
	if rt == nil || rt.Runner == nil {
		return "", errDigRunnerUnavailable
	}
	resolver, ok := rt.Runner.(process.TrustedCommandResolver)
	if !ok {
		return "", errDigUnverifiedExecutable
	}
	path, err := resolver.ResolveTrustedCommand(digExecutable)
	if err != nil || path == "" || !filepath.IsAbs(path) {
		return "", errDigUnavailable
	}
	return path, nil
}

// ---------------------------------------------------------------------------
// validators

// validQueryName accepts bounded ASCII DNS names: labels of 1..63 bytes
// over letters, digits, hyphen, and underscore (underscore labels stay
// supported for SRV/SPF-style names), a total of at most 253 bytes
// excluding exactly one terminal dot, no empty interior labels, and no
// option-like (leading "-") form. The character allowlist rejects
// whitespace, control and NUL bytes, escaped (backslash) forms,
// server-like "@" forms, and every non-ASCII byte.
func validQueryName(name string) bool {
	if name == "" || name[0] == '-' {
		return false
	}
	trimmed := strings.TrimSuffix(name, ".")
	if trimmed == "" || len(trimmed) > maxNameBytes {
		return false
	}
	for _, label := range strings.Split(trimmed, ".") {
		if label == "" || len(label) > maxLabelBytes {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '-' || c == '_':
			default:
				return false
			}
		}
	}
	return true
}

// validNameserver accepts an absent nameserver (checked by the caller),
// a bare IPv4/IPv6 literal, or a validated hostname. At-signs, ports,
// URL and CIDR forms, brackets, zones, and escapes are rejected.
func validNameserver(server string) bool {
	if server == "" {
		return false
	}
	if parsed, err := netip.ParseAddr(server); err == nil && parsed.Zone() == "" {
		return true
	}
	if strings.ContainsAny(server, ":@/\\%") {
		return false
	}
	return validQueryName(server)
}

// pythonWhitespace reports Python str.isspace() semantics: Go's
// unicode.IsSpace (Unicode White_Space: \t-\r, space, NEL, NBSP, and the
// Zs/Zl/Zp separators) plus U+001C..U+001F (FILE/GROUP/RECORD/UNIT
// SEPARATOR), which CPython's Latin-1 whitespace table classifies as
// space and Go does not (R102-F3).
func pythonWhitespace(r rune) bool {
	switch r {
	case '\x1c', '\x1d', '\x1e', '\x1f':
		return true
	}
	return unicode.IsSpace(r)
}

// pythonRstrip strips one trailing run of Python whitespace, exactly
// like str.rstrip() with no argument.
func pythonRstrip(s string) string {
	return strings.TrimRightFunc(s, pythonWhitespace)
}

// pythonFields splits s around runs of Python whitespace, exactly like
// str.split() with no argument: leading and trailing whitespace is
// dropped and an all-whitespace (or empty) string yields an allocated
// empty (non-nil) slice, never nil — a Python list is never null, so
// an empty MX row serializes as JSON [] and an empty successful MX
// stdout as [[]] (R102-FINAL-01).
func pythonFields(s string) []string {
	fields := []string{}
	start := -1
	for index, r := range s {
		if pythonWhitespace(r) {
			if start >= 0 {
				fields = append(fields, s[start:index])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = index
		}
	}
	if start >= 0 {
		fields = append(fields, s[start:])
	}
	return fields
}

// errPythonInt is the value-free Python ValueError stand-in.
var errPythonInt = errors.New("dig: invalid prefix")

// pythonDecimalDigit returns the decimal value of a Unicode Nd digit.
// Python int() accepts every general-category-Nd character; every Nd
// range in the Unicode data is a contiguous run of exactly ten code
// points ordered by digit value and starting at the digit-zero code
// point, so the value is the offset within the run.
func pythonDecimalDigit(r rune) (int, bool) {
	if r >= '0' && r <= '9' {
		return int(r - '0'), true
	}
	table := unicode.Categories["Nd"]
	for _, rng := range table.R16 {
		if r >= rune(rng.Lo) && r <= rune(rng.Hi) {
			if rng.Stride != 1 {
				return 0, false
			}
			return int((uint32(r) - uint32(rng.Lo)) % 10), true
		}
	}
	for _, rng := range table.R32 {
		if uint32(r) >= rng.Lo && uint32(r) <= rng.Hi {
			if rng.Stride != 1 {
				return 0, false
			}
			return int((uint32(r) - uint32(rng.Lo)) % 10), true
		}
	}
	return 0, false
}

// pythonIntWhitespace reports the whitespace Python's base-10 int()
// actually strips around the literal (R102-F2, runtime-oracle
// corrected): the ASCII C-locale whitespace set (' ' and \t-\r) plus,
// for non-ASCII code points only, the Python whitespace set — Go's
// unicode.IsSpace matches Python exactly above U+007F (U+0085, U+00A0,
// U+1680, U+2000..U+200A, U+2028, U+2029, U+202F, U+205F, U+3000).
// U+001C..U+001F are NOT int() whitespace even though str.isspace()
// accepts them: CPython's int parser skips only C-locale whitespace and
// its decimal-and-space fold maps only code points above 127, so the
// ASCII information separators reach the digit grammar unchanged and
// fail like any interior non-digit (int('\x1c24\x1f') raises
// ValueError). pythonWhitespace below keeps them for str.rstrip and
// str.split parity.
func pythonIntWhitespace(r rune) bool {
	if r < 0x80 {
		switch r {
		case ' ', '\t', '\n', '\v', '\f', '\r':
			return true
		}
		return false
	}
	return unicode.IsSpace(r)
}

// pythonInt ports Python's base-10 int() grammar (R102-F2, verified
// against the runtime checker): outer int() whitespace
// (pythonIntWhitespace — ASCII whitespace plus non-ASCII Python spaces
// such as U+3000, but NOT U+001C..U+001F, which int() rejects), one
// optional ASCII +/- sign, and digits over Unicode Nd with single
// underscores strictly between digit groups ("2_4" and "２４" parse as
// 24; "_24", "24_", "2__4", "+_24", and interior non-digits fail like
// ValueError). Magnitude is clamped: any value beyond the IPv6 prefix
// maximum simply fails the caller's range check like Python's large
// ints do.
func pythonInt(s string) (int, error) {
	runes := []rune(s)
	i, j := 0, len(runes)
	for i < j && pythonIntWhitespace(runes[i]) {
		i++
	}
	for j > i && pythonIntWhitespace(runes[j-1]) {
		j--
	}
	digits := runes[i:j]
	negative := false
	if len(digits) > 0 && (digits[0] == '+' || digits[0] == '-') {
		negative = digits[0] == '-'
		digits = digits[1:]
	}
	if len(digits) == 0 {
		return 0, errPythonInt
	}
	value := 0
	underscore := true // a leading underscore (or one after the sign) is invalid
	for index, r := range digits {
		if r == '_' {
			if underscore || index == len(digits)-1 {
				return 0, errPythonInt
			}
			underscore = true
			continue
		}
		digit, ok := pythonDecimalDigit(r)
		if !ok {
			return 0, errPythonInt
		}
		underscore = false
		if value < 1<<20 {
			value = value*10 + digit
		}
	}
	if negative {
		value = -value
	}
	return value, nil
}

// pythonIPVersion ports salt.utils.network.is_ipv4/is_ipv6 over Python
// ipaddress.ip_address semantics using net/netip (R102-F2): an empty
// string, leading-zero octets, short v4 forms, and whitespace-wrapped
// literals are invalid; a scoped (zoned) IPv6 literal such as
// fe80::1%eth0 is valid because Python >= 3.9 IPv6Address accepts scope
// ids (a zoned IPv4 literal stays invalid like ip_address); a v4-in-v6
// textual literal ("::ffff:1.2.3.4") reports IPv6 like
// ip_address.version.
//
// R102-BACKEND-FINAL-01: Python ip_address rejects IPv6 scope text
// carrying more than one percent delimiter (ip_address(
// 'fe80::1%eth0%extra') raises ValueError) while Go netip.ParseAddr
// accepts the same text, so a shared guard rejects any input with more
// than one '%' before parsing. Exactly one '%' keeps flowing into
// netip.ParseAddr, which already rejects the remaining Python-invalid
// single-zone forms (an empty zone "fe80::1%" fails both parsers), so
// parity is exact: valid one-zone literals (fe80::1%eth0, with or
// without a prefix) and every IPv4/IPv6/prefix answer are unchanged.
// The guard lives in this one predicate, so check_ip, the A/AAAA
// response filter, the SPF ip4/ip6 filter, and PTR's literal
// validation share it; validNameserver and validQueryName are separate
// validators that already reject every zone and are unchanged.
func pythonIPVersion(addr string) int {
	if addr == "" {
		return 0
	}
	if strings.Count(addr, "%") > 1 {
		return 0
	}
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return 0
	}
	if parsed.Is4() {
		return 4
	}
	return 6
}

// checkIP ports the pinned dig.check_ip: split on the last "/", then
// require a valid IPv4 literal with prefix 1..32 or a valid IPv6
// literal with prefix 8..128, with no host-bit alignment. A bare valid
// literal passes; a non-integer prefix fails; the address half before
// the last "/" must be a bare literal, so "1.2.3.4/5/6" fails.
func checkIP(addr string) bool {
	head, tail := addr, ""
	last := strings.LastIndexByte(addr, '/')
	if last >= 0 {
		head, tail = addr[:last], addr[last+1:]
	}
	switch pythonIPVersion(head) {
	case 4:
		if last < 0 {
			return true
		}
		prefix, err := pythonInt(tail)
		if err != nil {
			return false
		}
		return prefix >= 1 && prefix <= 32
	case 6:
		if last < 0 {
			return true
		}
		prefix, err := pythonInt(tail)
		if err != nil {
			return false
		}
		return prefix >= 8 && prefix <= 128
	default:
		return false
	}
}

// reverseQuery validates a bare IP literal and renders the fixed
// reverse query name: d.c.b.a.in-addr.arpa for IPv4, the 32
// nibble-reversed lowercase hex labels plus ip6.arpa for IPv6. A scoped
// IPv6 literal with exactly one zone delimiter is accepted (Python
// literal semantics) and contributes only its 16 address bytes; the
// zone never reaches the query name. Multi-percent scope text is
// rejected through the shared pythonIPVersion guard
// (R102-BACKEND-FINAL-01), exactly like Python ip_address.
func reverseQuery(addr string) (string, bool) {
	const hexDigits = "0123456789abcdef"
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return "", false
	}
	switch pythonIPVersion(addr) {
	case 4:
		ip := parsed.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", ip[3], ip[2], ip[1], ip[0]), true
	case 6:
		ip := parsed.As16()
		var b strings.Builder
		// RFC 3596 reverse: the least significant nibble of the address
		// becomes the first label, so each byte (walked last to first)
		// contributes its low nibble before its high nibble.
		for i := 15; i >= 0; i-- {
			b.WriteByte(hexDigits[ip[i]&0x0f])
			b.WriteByte('.')
			b.WriteByte(hexDigits[ip[i]>>4])
			b.WriteByte('.')
		}
		b.WriteString("ip6.arpa")
		return b.String(), true
	default:
		return "", false
	}
}

// ---------------------------------------------------------------------------
// lookups

// digALookup ports A (and AAAA, which shares the predicate): every
// stdout line is kept only when check_ip accepts it, so cross-family
// literals and CIDR strings are retained in order with duplicates. A
// completed nonzero exit answers the pinned empty fallback.
func digALookup(op *digOp, host, rrtype, nameserver string) ([]string, error) {
	key := frameKey(host, rrtype, nameserver)
	if err := op.enter(key); err != nil {
		return nil, err
	}
	defer op.exit(key)
	stdout, nonzero, err := op.dispatch(host, rrtype, nameserver)
	if err != nil {
		return nil, err
	}
	if nonzero {
		return []string{}, nil
	}
	ret := []string{}
	for _, line := range strings.Split(stdout, "\n") {
		if !checkIP(line) {
			continue
		}
		ret = append(ret, line)
		if len(ret) > maxResults {
			return nil, errDigResultLimit
		}
	}
	return ret, nil
}

// digPTRLookup ports PTR: the argument must be a bare IP literal and the
// fixed reverse name is queried with -t PTR. The literal newline split
// keeps empties, quotes, and trailing dots — an empty successful stdout
// answers [""] exactly like the pinned split.
func digPTRLookup(op *digOp, host, nameserver string) ([]string, error) {
	reverse, ok := reverseQuery(host)
	if !ok {
		return nil, errDigInvalidAddress
	}
	key := frameKey(reverse, recordPTR, nameserver)
	if err := op.enter(key); err != nil {
		return nil, err
	}
	defer op.exit(key)
	stdout, nonzero, err := op.dispatch(reverse, recordPTR, nameserver)
	if err != nil {
		return nil, err
	}
	if nonzero {
		return []string{}, nil
	}
	lines := strings.Split(stdout, "\n")
	if len(lines) > maxResults {
		return nil, errDigResultLimit
	}
	return lines, nil
}

// digTXTLookup ports TXT: the literal newline split keeps everything.
func digTXTLookup(op *digOp, host, nameserver string) ([]string, error) {
	key := frameKey(host, recordTXT, nameserver)
	if err := op.enter(key); err != nil {
		return nil, err
	}
	defer op.exit(key)
	stdout, nonzero, err := op.dispatch(host, recordTXT, nameserver)
	if err != nil {
		return nil, err
	}
	if nonzero {
		return []string{}, nil
	}
	lines := strings.Split(stdout, "\n")
	if len(lines) > maxResults {
		return nil, errDigResultLimit
	}
	return lines, nil
}

// digCNAMELookup ports CNAME: the stdout string itself is the success
// answer (including empty); a completed nonzero exit answers [].
func digCNAMELookup(op *digOp, host, nameserver string) (any, error) {
	key := frameKey(host, recordCNAME, nameserver)
	if err := op.enter(key); err != nil {
		return nil, err
	}
	defer op.exit(key)
	stdout, nonzero, err := op.dispatch(host, recordCNAME, nameserver)
	if err != nil {
		return nil, err
	}
	if nonzero {
		return []string{}, nil
	}
	return stdout, nil
}

// digNSLookup ports NS: with resolve=true (the pinned default) every
// nameserver line is revalidated and resolved through the shared A
// lookup (order and duplicates kept); with resolve=false the raw split
// lines are returned. An empty successful stdout answers [] without
// dispatching a child lookup for the pinned empty record.
func digNSLookup(op *digOp, domain, nameserver string, resolve bool) ([]string, error) {
	key := frameKey(domain, recordNS, nameserver)
	if err := op.enter(key); err != nil {
		return nil, err
	}
	defer op.exit(key)
	stdout, nonzero, err := op.dispatch(domain, recordNS, nameserver)
	if err != nil {
		return nil, err
	}
	if nonzero {
		return []string{}, nil
	}
	if !resolve {
		lines := strings.Split(stdout, "\n")
		if len(lines) > maxResults {
			return nil, errDigResultLimit
		}
		return lines, nil
	}
	ret := []string{}
	if stdout == "" {
		return ret, nil
	}
	for _, line := range strings.Split(stdout, "\n") {
		if !validQueryName(line) {
			return nil, errDigInvalidName
		}
		addrs, err := digALookup(op, line, recordA, nameserver)
		if err != nil {
			return nil, err
		}
		ret = append(ret, addrs...)
		if len(ret) > maxResults {
			return nil, errDigResultLimit
		}
	}
	return ret, nil
}

// digMXLookup ports MX: raw whitespace-split string rows in line order
// (an empty successful stdout answers [[]]); with resolve=true each
// exchange is revalidated and resolved through the shared A lookup,
// keeping only the first address, exactly like the pinned `A(x[1])[0]`.
// The pinned IndexError crash positions (a short row, or an exchange
// with no A address) map to the fixed malformed-record rejection.
func digMXLookup(op *digOp, domain, nameserver string, resolve bool) ([][]string, error) {
	key := frameKey(domain, recordMX, nameserver)
	if err := op.enter(key); err != nil {
		return nil, err
	}
	defer op.exit(key)
	stdout, nonzero, err := op.dispatch(domain, recordMX, nameserver)
	if err != nil {
		return nil, err
	}
	if nonzero {
		return [][]string{}, nil
	}
	lines := strings.Split(stdout, "\n")
	if len(lines) > maxResults {
		return nil, errDigResultLimit
	}
	rows := make([][]string, 0, len(lines))
	for _, line := range lines {
		rows = append(rows, pythonFields(line))
	}
	if !resolve {
		return rows, nil
	}
	out := make([][]string, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			return nil, errDigMalformedRecord
		}
		if !validQueryName(row[1]) {
			return nil, errDigInvalidName
		}
		addrs, err := digALookup(op, row[1], recordA, nameserver)
		if err != nil {
			return nil, err
		}
		if len(addrs) == 0 {
			return nil, errDigMalformedRecord
		}
		out = append(out, []string{row[0], addrs[0]})
	}
	return out, nil
}

// digSPFLookup ports SPF. The record argument is exactly SPF or TXT;
// an exactly empty successful SPF answer falls back to TXT (still
// inside the shared budgets and counted against the call limit);
// double quotes are stripped everywhere; the first token must be
// exactly v=spf1 (a lone v=spf1 answers [] instead of the pinned
// IndexError); redirect= is honored only as the second token; and the
// pinned include/ip4/ip6 regex drives recursion and collection with
// ordering and duplicates preserved. include targets and redirect
// targets are revalidated before their dispatch.
func digSPFLookup(op *digOp, domain, record, nameserver string) ([]string, error) {
	if record != recordSPF && record != recordTXT {
		return nil, errDigInvalidRecord
	}
	key := frameKey(domain, record, nameserver)
	if err := op.enter(key); err != nil {
		return nil, err
	}
	defer op.exit(key)
	stdout, nonzero, err := op.dispatch(domain, record, nameserver)
	if err != nil {
		return nil, err
	}
	if nonzero {
		return []string{}, nil
	}
	if stdout == "" && record == recordSPF {
		// Empty string is a successful query with nothing to return;
		// only an exactly-SPF record falls back to TXT.
		return digSPFLookup(op, domain, recordTXT, nameserver)
	}
	sections := pythonFields(strings.ReplaceAll(stdout, "\"", ""))
	if len(sections) == 0 || sections[0] != "v=spf1" {
		return []string{}, nil
	}
	if len(sections) > 1 && strings.HasPrefix(sections[1], "redirect=") {
		return digSPFLookup(op, strings.TrimPrefix(sections[1], "redirect="), recordSPF, nameserver)
	}
	ret := []string{}
	for _, section := range sections[1:] {
		match := spfRe.FindStringSubmatch(section)
		if match == nil {
			continue
		}
		switch match[1] {
		case "include":
			sub, err := digSPFLookup(op, match[2], recordSPF, nameserver)
			if err != nil {
				return nil, err
			}
			ret = append(ret, sub...)
		case "ip4", "ip6":
			if checkIP(match[2]) {
				ret = append(ret, match[2])
			}
		}
		if len(ret) > maxResults {
			return nil, errDigResultLimit
		}
	}
	return ret, nil
}

// ---------------------------------------------------------------------------
// registration

func typedArgs[T any](args any, name string) (*T, error) {
	value, ok := args.(*T)
	if !ok || value == nil {
		return nil, fmt.Errorf("%s: expected *arguments, got %T", name, args)
	}
	return value, nil
}

func pointerString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func pointerBool(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

type CheckIPArgs struct {
	Addr string `statekit:"required,name=addr"`
}

type checkIPFunc struct{}

func (checkIPFunc) Name() string { return "dig.check_ip" }
func (checkIPFunc) Args() any    { return CheckIPArgs{} }

func (checkIPFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[CheckIPArgs](args, "dig.check_ip")
	if err != nil {
		return nil, err
	}
	// check_ip never dispatches dig, but the pinned __virtual__ gate
	// covers the whole module, so it stays unavailable without a
	// trusted dig identity.
	if _, err := resolveDig(rt); err != nil {
		return nil, err
	}
	return checkIP(a.Addr), nil
}

type AArgs struct {
	Host       string  `statekit:"required,name=host"`
	Nameserver *string `statekit:"name=nameserver"`
}

type aFunc struct{}

func (aFunc) Name() string { return "dig.A" }
func (aFunc) Args() any    { return AArgs{} }

func (aFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[AArgs](args, "dig.A")
	if err != nil {
		return nil, err
	}
	return runLookup(ctx, rt, func(op *digOp) (any, error) {
		return digALookup(op, a.Host, recordA, pointerString(a.Nameserver))
	})
}

type PTRArgs struct {
	Host       string  `statekit:"required,name=host"`
	Nameserver *string `statekit:"name=nameserver"`
}

type ptrFunc struct{}

func (ptrFunc) Name() string { return "dig.PTR" }
func (ptrFunc) Args() any    { return PTRArgs{} }

func (ptrFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[PTRArgs](args, "dig.PTR")
	if err != nil {
		return nil, err
	}
	return runLookup(ctx, rt, func(op *digOp) (any, error) {
		return digPTRLookup(op, a.Host, pointerString(a.Nameserver))
	})
}

type AAAAArgs struct {
	Host       string  `statekit:"required,name=host"`
	Nameserver *string `statekit:"name=nameserver"`
}

type aaaaFunc struct{}

func (aaaaFunc) Name() string { return "dig.AAAA" }
func (aaaaFunc) Args() any    { return AAAAArgs{} }

func (aaaaFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[AAAAArgs](args, "dig.AAAA")
	if err != nil {
		return nil, err
	}
	return runLookup(ctx, rt, func(op *digOp) (any, error) {
		return digALookup(op, a.Host, recordAAAA, pointerString(a.Nameserver))
	})
}

type CNAMEArgs struct {
	Host       string  `statekit:"required,name=host"`
	Nameserver *string `statekit:"name=nameserver"`
}

type cnameFunc struct{}

func (cnameFunc) Name() string { return "dig.CNAME" }
func (cnameFunc) Args() any    { return CNAMEArgs{} }

func (cnameFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[CNAMEArgs](args, "dig.CNAME")
	if err != nil {
		return nil, err
	}
	return runLookup(ctx, rt, func(op *digOp) (any, error) {
		return digCNAMELookup(op, a.Host, pointerString(a.Nameserver))
	})
}

type NSArgs struct {
	Domain     string  `statekit:"required,name=domain"`
	Resolve    *bool   `statekit:"name=resolve"`
	Nameserver *string `statekit:"name=nameserver"`
}

type nsFunc struct{}

func (nsFunc) Name() string { return "dig.NS" }
func (nsFunc) Args() any    { return NSArgs{} }

func (nsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[NSArgs](args, "dig.NS")
	if err != nil {
		return nil, err
	}
	return runLookup(ctx, rt, func(op *digOp) (any, error) {
		return digNSLookup(op, a.Domain, pointerString(a.Nameserver), pointerBool(a.Resolve, true))
	})
}

type SPFArgs struct {
	Domain     string  `statekit:"required,name=domain"`
	Record     *string `statekit:"name=record"`
	Nameserver *string `statekit:"name=nameserver"`
}

type spfFunc struct{}

func (spfFunc) Name() string { return "dig.SPF" }
func (spfFunc) Args() any    { return SPFArgs{} }

func (spfFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[SPFArgs](args, "dig.SPF")
	if err != nil {
		return nil, err
	}
	// The pinned default is exactly "SPF"; any explicit value must be
	// SPF or TXT (an empty string is neither, so it rejects with zero
	// dispatch instead of querying a bogus type).
	record := recordSPF
	if a.Record != nil {
		record = *a.Record
	}
	if record != recordSPF && record != recordTXT {
		return nil, errDigInvalidRecord
	}
	return runLookup(ctx, rt, func(op *digOp) (any, error) {
		return digSPFLookup(op, a.Domain, record, pointerString(a.Nameserver))
	})
}

type MXArgs struct {
	Domain     string  `statekit:"required,name=domain"`
	Resolve    *bool   `statekit:"name=resolve"`
	Nameserver *string `statekit:"name=nameserver"`
}

type mxFunc struct{}

func (mxFunc) Name() string { return "dig.MX" }
func (mxFunc) Args() any    { return MXArgs{} }

func (mxFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[MXArgs](args, "dig.MX")
	if err != nil {
		return nil, err
	}
	return runLookup(ctx, rt, func(op *digOp) (any, error) {
		return digMXLookup(op, a.Domain, pointerString(a.Nameserver), pointerBool(a.Resolve, false))
	})
}

type TXTArgs struct {
	Host       string  `statekit:"required,name=host"`
	Nameserver *string `statekit:"name=nameserver"`
}

type txtFunc struct{}

func (txtFunc) Name() string { return "dig.TXT" }
func (txtFunc) Args() any    { return TXTArgs{} }

func (txtFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[TXTArgs](args, "dig.TXT")
	if err != nil {
		return nil, err
	}
	return runLookup(ctx, rt, func(op *digOp) (any, error) {
		return digTXTLookup(op, a.Host, pointerString(a.Nameserver))
	})
}

// runLookup applies the __virtual__ availability gate and starts the
// shared 10s operation deadline for one public call.
func runLookup(ctx context.Context, rt *runtime.Runtime, lookup func(*digOp) (any, error)) (any, error) {
	digPath, err := resolveDig(rt)
	if err != nil {
		return nil, err
	}
	op, cancel := newDigOp(ctx, rt, digPath)
	defer cancel()
	return lookup(op)
}

// The pinned module tail aliases the seven lowercase names to their
// canonical functions; there is no txt alias in the pinned source.

type aAliasFunc struct{ aFunc }

func (aAliasFunc) Name() string { return "dig.a" }

type ptrAliasFunc struct{ ptrFunc }

func (ptrAliasFunc) Name() string { return "dig.ptr" }

type aaaaAliasFunc struct{ aaaaFunc }

func (aaaaAliasFunc) Name() string { return "dig.aaaa" }

type cnameAliasFunc struct{ cnameFunc }

func (cnameAliasFunc) Name() string { return "dig.cname" }

type nsAliasFunc struct{ nsFunc }

func (nsAliasFunc) Name() string { return "dig.ns" }

type spfAliasFunc struct{ spfFunc }

func (spfAliasFunc) Name() string { return "dig.spf" }

type mxAliasFunc struct{ mxFunc }

func (mxAliasFunc) Name() string { return "dig.mx" }

// Register installs the complete public dig catalog: nine canonical
// functions plus the seven source aliases.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		checkIPFunc{},
		aFunc{},
		ptrFunc{},
		aaaaFunc{},
		cnameFunc{},
		nsFunc{},
		spfFunc{},
		mxFunc{},
		txtFunc{},
		aAliasFunc{},
		ptrAliasFunc{},
		aaaaAliasFunc{},
		cnameAliasFunc{},
		nsAliasFunc{},
		spfAliasFunc{},
		mxAliasFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
