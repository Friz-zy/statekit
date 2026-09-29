// Package dnsutil implements the bounded R10.3a slice of the pinned Salt
// dnsutil execution module (saltstack/salt/modules/dnsutil.py @
// 8b63e700637e40d76f80a00d95c60471797c73b9, virtual name "dnsutil").
//
// Registered public functions (8 of the 11 in the pinned public catalog):
// parse_hosts, parse_zone, check_ip, A, AAAA, NS, SPF, and MX. The two
// private helpers of the pinned source stay private here (_to_seconds
// backs parse_zone; _has_dig backs the delegation gate). Three public
// functions are deliberately NOT registered in this slice:
//
//   - hosts_append / hosts_remove mutate arbitrary caller-supplied file
//     paths with no validation, backup, or atomicity in the pinned
//     source. Upgrade path: a bounded writer over the same
//     Runtime.FS/ReadFileBounded discipline this slice uses (validated
//     destination, regular/no-follow, temp-file rename), following the
//     hosts module's fixture-root override precedent.
//   - serial reads and writes a persistent grain (dnsserial_<zone>).
//     No persistent grains store exists in StateKit yet, and a
//     stateless reimplementation would silently change the pinned
//     contract (update=True must increment the stored value across
//     runs). Upgrade path: register it once a persistent local
//     grains/state store module lands.
//
// File reads (parse_hosts, parse_zone) happen only through
// runtime.ReadFileBounded over Runtime.FS with an explicit 1 MiB ceiling
// per read — a fixed divergence from the pinned source, which reads the
// whole file unbounded through salt.utils.files.fopen. The bounded read
// requires a regular file and never follows symlinks (final component or
// any parent), so devices, FIFOs, and symlink-redirected paths are
// rejected before any content is allocated. The same 1 MiB ceiling caps
// inline hosts/zone values before any processing, hostsfile/zonefile
// path arguments are rejected at 4096 bytes before the filesystem is
// touched, and the parsers enforce fixed ceilings (R10.3A-SEC-01,
// tightened as R103A-GATE-01/02 and R103A-SEC-FINAL-01): at most 4096
// input records (non-blank, non-comment lines), 8192 retained result
// items — every retained JSON object member across all nested maps
// plus every list element and duplicate-appended element, so one
// owner-TTL-IN-A record accounts its owner member and the TARGET and
// TTL members it inserts — 4096 bytes per parsed token or derived
// cell, 4 MiB of the COMPLETE serialized result representation (every
// map key including every expanded '@'→ORIGIN generic-bucket key,
// every value, the exact encoding/json escaping of quotes, backslash,
// control bytes, the HTML triplet, and U+2028/U+2029, and every
// nested map/array delimiter, colon, and comma), and an '@'→ORIGIN
// expansion whose exact computed size must stay within the 1 MiB
// source ceiling before any output is allocated. The result budgets
// are tracked exactly as the retained serialized output while it is
// built — insertions add, and a map-key overwrite replaces the old
// value's whole retained subtree, reserving the exact new-minus-old
// delta of both the byte count and the nested item count (so a
// shape-changing replacement — a bucket owner morphing between the
// plain-string and TARGET/TTL forms, or a directive flattening a
// bucket or list — gains and returns exactly the structural items and
// bytes it changes) — and enforced BEFORE a key/value/row is inserted,
// so an oversized answer rejects whole without materializing an
// oversized encoding and without a partial result; the parser never
// encodes the result to measure it. Every ceiling failure answers one
// fixed value-free error with no partial result. This boundary is
// intended for local trusted same-principal CLI use only; every error
// surface is value-free (no file content and no caller path travels
// in a result, error, or log).
//
// parse_hosts ports the pinned parser exactly where the source defines
// behavior: Python-falsy inline input (nil or the empty string) triggers
// the file read; a failed read answers the pinned result string
// "Error: hosts data was not found"; comment lines are recognized only
// when '#' is the first character of the line (an inline '#' token
// becomes an ordinary alias exactly like the pinned startswith check);
// duplicate aliases accumulate per IP in encounter order, duplicates
// included; and the default path is exactly /etc/hosts. Python
// str.splitlines()/str.split() whitespace semantics are ported (Go
// unicode.IsSpace plus U+001C..U+001F). Divergence: the pinned parser
// raises IndexError on a whitespace-only line (split() yields no
// components); this port skips such lines — a documented safe
// divergence instead of a crash.
//
// parse_zone ports the pinned simplistic line parser — semicolon
// comment stripping, $DIRECTIVE capture, the '(' … ')' multi-line SOA
// join, global '@' replacement by ORIGIN, substring "SOA" detection,
// the NS list, the first-MX-only quirk, the A/AAAA TARGET/TTL form for
// owner TTL IN A/AAAA addr records, and the generic per-type bucket for
// everything else (TXT, CAA, PTR, …). It is NOT an RFC 1035 parser
// (parser ceiling, matching the pinned source): no $INCLUDE, no
// escape/quoting handling, no TTL inheritance, no class negotiation,
// and no validation of record semantics. Every pinned crash position
// (short record lines, missing ORIGIN, malformed SOA fields, a
// non-numeric H/D time value, type collisions between directive
// strings and record buckets, and the R103A-FINAL-01 position — a
// multi-line '(' … ')' join that strips every token, e.g. the zone
// "(\n)\n", where the pinned parser reads comps[0] of an empty list)
// maps to one fixed value-free malformed-zone error and no partial
// results; the continuation join is a linear builder and every slice
// access is length-checked, so no input can panic the parser. A truthy
// zonefile is read first through the bounded read and the inline zone
// data is the fallback when that read fails, exactly like the pinned
// try/except; when neither source yields data the pinned result string
// "Error: Zone data was not found" is returned. Divergence: Python
// dicts preserve insertion order and Go maps do not, so record-bucket
// key order is not preserved (list order — NS rows, MX rows — is).
//
// _to_seconds ports the pinned H/D/W quirks exactly: case-insensitive
// detection, removal of every 'H'/'D' before the numeric parse, the W
// branch answering one week without any numeric parse, the else branch
// answering one week for every unparsable value (the pinned except
// ValueError), negative values passing through unchanged, and the
// one-week cap for anything larger. The numeric parse is Python's
// base-10 int() grammar (the same predicate family the dig module
// verified against the runtime oracle): outer int() whitespace
// (ASCII whitespace plus non-ASCII Python spaces such as U+3000, but
// not U+001C..U+001F), one ASCII +/- sign, Unicode Nd decimal digits,
// and single underscores strictly between digits. Two documented
// micro-divergences: magnitudes beyond int64 saturate (Python's int is
// arbitrary precision; positive saturation still caps to one week,
// negative saturation answers math.MinInt64), and Python's full
// uppercase expansion U+1E96 (ẖ → "H" + combining low line) is not
// reproduced by Go's simple ToUpper, so that one code point falls to
// the else branch (one week) instead of the pinned H-branch ValueError
// crash position (which this port maps to the malformed-zone error).
//
// The dig-backed surface (check_ip, A, AAAA, NS, SPF, MX) delegates to
// the registered dig family through rt.Exec.Call — the StateKit nested
// invocation boundary: the caller's context (cancellation and any
// deadline) propagates into the nested call, and the dig module's own
// call-time gates and resource budgets apply per delegation.
// dnsutil never parses addresses itself (no netip, no socket, no
// net.DefaultResolver, no net.LookupIP anywhere in this package) and
// never dispatches a process: _has_dig is ported as a trusted-resolution
// gate through the Runner's optional process.TrustedCommandResolver
// capability — the same divergence from the pinned PATH which() lookup
// that the dig module documents — so a Runner that cannot establish a
// trusted dig executable answers the pinned result string
// "This function requires dig, which is not currently available" with
// zero dispatch. The pinned A/AAAA socket.getaddrinfo fallback when dig
// is unavailable is an explicitly deferred divergence: StateKit performs
// no host-resolver egress, so the unavailable answer is returned
// instead. When the gate passes but the registry has no matching dig
// function (a crash position in the pinned __salt__ lookup), the call
// fails closed with one fixed value-free unavailable error. Exact
// argument pass-through is preserved: nameservers forward as-is, NS
// forwards resolve with the pinned True default, SPF forwards record
// with the pinned "SPF" default, and MX forwards resolve with the
// pinned False default; the delegated result shape — value and error —
// propagates unchanged.
package dnsutil

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execdig "github.com/friz-zy/statekit/modules/exec/dig"
)

const (
	// defaultHostsPath is the pinned parse_hosts default.
	defaultHostsPath = "/etc/hosts"

	// maxSourceBytes is the shared 1 MiB ceiling of the parsing
	// surface (within runtime.MaxBoundedReadLimit): one
	// parse_hosts/parse_zone file read through runtime.ReadFileBounded,
	// one inline hosts/zone value before any processing, and the exact
	// computed size of one '@'→ORIGIN line expansion (R10.3A-SEC-01).
	maxSourceBytes = 1 << 20

	// maxPathBytes bounds a hostsfile/zonefile argument before the
	// filesystem is touched (R10.3A-SEC-01); a longer path is rejected
	// as a read failure and never reaches Runtime.FS.
	maxPathBytes = 4096

	// maxInputRecords bounds the parsed input records (non-blank,
	// non-comment lines) of one parse_hosts/parse_zone call.
	maxInputRecords = 4096

	// maxResultItems bounds the retained result items of one call:
	// every JSON object member at any nesting depth plus every array
	// element, duplicate-appended elements included (R103A-GATE-02).
	// An empty object or array retains zero items and contributes only
	// its two delimiter bytes to the byte budget; null never appears
	// (a Python list is never null, so empty lists stay []).
	maxResultItems = 8192

	// maxCellBytes bounds one parsed token or derived result cell.
	maxCellBytes = 4096

	// maxEncodedBytes bounds the COMPLETE serialized result
	// representation of one call: the exact byte length of the value's
	// encoding/json output — every map key, every value, the escaping
	// of quotes/backslash/control/HTML/U+2028/U+2029, and every
	// delimiter, colon, and comma (R103A-GATE-01). Transport framing
	// outside the value (for example the CLI encoder's trailing
	// newline) is not part of the representation.
	maxEncodedBytes = 4 << 20

	// oneWeekSeconds is the RFC 1035 maximum _to_seconds caps to.
	oneWeekSeconds = 604800

	digExecutable = "dig"
)

// Pinned compatibility result strings (value-free; exact Salt texts).
const (
	hostsNotFoundMessage  = "Error: hosts data was not found"
	zoneNotFoundMessage   = "Error: Zone data was not found"
	digUnavailableMessage = "This function requires dig, which is not currently available"
)

var (
	// errZoneMalformed is the single fixed value-free answer for every
	// pinned parse_zone/_to_seconds crash position (IndexError, KeyError,
	// TypeError, ValueError) — including the R103A-FINAL-01 empty
	// multi-line join — the whole operation rejects with no partial
	// results.
	errZoneMalformed = errors.New("dnsutil: malformed zone data")
	// errInputTooLarge is the fixed value-free answer when an input
	// byte ceiling is exceeded before processing: an inline hosts/zone
	// value over maxSourceBytes, or an '@'→ORIGIN expansion whose
	// exact computed size would exceed maxSourceBytes (R10.3A-SEC-01).
	errInputTooLarge = errors.New("dnsutil: input exceeds limit")
	// errParseLimit is the fixed value-free answer when an input
	// count or single-cell ceiling is exceeded mid-parse: input
	// records over maxInputRecords or a parsed/derived cell over
	// maxCellBytes (R10.3A-SEC-01). No partial result escapes.
	errParseLimit = errors.New("dnsutil: parser limit exceeded")
	// errResultItems is the fixed value-free answer when the retained
	// result would exceed maxResultItems — every nested JSON member
	// and every list/duplicate-appended element counted
	// (R103A-GATE-02). No partial result escapes.
	errResultItems = errors.New("dnsutil: result item limit exceeded")
	// errResultBytes is the fixed value-free answer when the retained
	// result's COMPLETE serialized representation would exceed
	// maxEncodedBytes — every key (expanded bucket keys included),
	// every value, the exact JSON escaping, and every delimiter,
	// colon, and comma counted (R103A-GATE-01). No partial result
	// escapes and the oversized encoding is never materialized.
	errResultBytes = errors.New("dnsutil: result byte limit exceeded")
	// errDigFunctionUnavailable is the fixed value-free error for the
	// pinned __salt__["dig.<fn>"] lookup crash position: the gate passed
	// but the registry carries no such function.
	errDigFunctionUnavailable = errors.New("dnsutil: dig function unavailable")
	// errDigRunnerUnavailable mirrors the dig module's runner guard for a
	// nil Runner/Exec runtime.
	errDigRunnerUnavailable = errors.New("dnsutil: runner unavailable")
)

// ---------------------------------------------------------------------------
// Python string semantics (shared predicate family with the dig module)

// pythonWhitespace reports Python str.isspace() semantics: Go's
// unicode.IsSpace plus U+001C..U+001F, which CPython's Latin-1
// whitespace table classifies as space and Go does not.
func pythonWhitespace(r rune) bool {
	switch r {
	case '\x1c', '\x1d', '\x1e', '\x1f':
		return true
	}
	return unicode.IsSpace(r)
}

// pythonStrip strips Python whitespace from both ends, exactly like
// str.strip() with no argument.
func pythonStrip(s string) string {
	return strings.TrimFunc(s, pythonWhitespace)
}

// pythonFields splits s around runs of Python whitespace, exactly like
// str.split() with no argument: leading and trailing whitespace is
// dropped and an all-whitespace (or empty) string yields an allocated
// empty slice, never nil — a Python list is never null, so an IP line
// without aliases serializes its alias list as JSON [] and never null.
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

// pythonSplitlines splits on the exact Python str.splitlines()
// boundaries: \n, \r, \r\n (one boundary), \v, \f, U+001C..U+001E,
// U+0085, U+2028, and U+2029. U+001F is whitespace but not a line
// boundary. A trailing boundary yields no trailing empty element.
func pythonSplitlines(s string) []string {
	var lines []string
	start := 0
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		boundary := false
		switch r {
		case '\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029':
			boundary = true
		case '\r':
			boundary = true
			if i+1 < len(runes) && runes[i+1] == '\n' {
				i++
			}
		}
		if boundary {
			lines = append(lines, string(runes[start:i]))
			start = i + 1
		}
	}
	if start < len(runes) {
		lines = append(lines, string(runes[start:]))
	}
	return lines
}

// pythonIntWhitespace reports the whitespace Python's base-10 int()
// strips around the literal: the ASCII C-locale whitespace set (' ' and
// \t-\r) plus, for non-ASCII code points only, the Python whitespace
// set. U+001C..U+001F are NOT int() whitespace even though
// str.isspace() accepts them.
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

// pythonDecimalDigit returns the decimal value of a Unicode Nd digit.
// Every Nd range in the Unicode data is a contiguous run of exactly ten
// code points ordered by digit value starting at the digit zero.
func pythonDecimalDigit(r rune) (int64, bool) {
	if r >= '0' && r <= '9' {
		return int64(r - '0'), true
	}
	table := unicode.Categories["Nd"]
	for _, rng := range table.R16 {
		if r >= rune(rng.Lo) && r <= rune(rng.Hi) {
			if rng.Stride != 1 {
				return 0, false
			}
			return int64((uint32(r) - uint32(rng.Lo)) % 10), true
		}
	}
	for _, rng := range table.R32 {
		if uint32(r) >= rng.Lo && uint32(r) <= rng.Hi {
			if rng.Stride != 1 {
				return 0, false
			}
			return int64((uint32(r) - uint32(rng.Lo)) % 10), true
		}
	}
	return 0, false
}

// errPythonInt is the value-free Python ValueError stand-in.
var errPythonInt = errors.New("dnsutil: invalid integer literal")

// pythonInt ports Python's base-10 int() grammar: outer int() whitespace
// (pythonIntWhitespace), one optional ASCII +/- sign, and digits over
// Unicode Nd with single underscores strictly between digit groups.
// Magnitudes beyond int64 saturate: positive saturation answers
// math.MaxInt64 (callers only compare against the one-week cap, so the
// exact value is irrelevant beyond the cap) and negative saturation
// answers math.MinInt64 — the documented divergence from Python's
// arbitrary-precision ints for |v| beyond 2^63-1.
func pythonInt(s string) (int64, error) {
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
	var value int64
	saturated := false
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
		if !saturated {
			if value > (math.MaxInt64-digit)/10 {
				saturated = true
				value = math.MaxInt64
				continue
			}
			value = value*10 + digit
		}
	}
	if negative {
		// -(2^63) is representable; every other saturated magnitude
		// clamps to MinInt64 (documented saturation divergence).
		if saturated {
			return math.MinInt64, nil
		}
		return -value, nil
	}
	return value, nil
}

// ---------------------------------------------------------------------------
// _to_seconds (private, backs parse_zone)

// scaleSeconds multiplies a parsed count by its unit factor with
// overflow-safe semantics: a positive product beyond int64 necessarily
// exceeds the one-week cap, so it answers the cap; a negative product
// beyond int64 saturates to math.MinInt64 (documented divergence —
// Python would keep the exact arbitrary-precision negative).
func scaleSeconds(n, unit int64) int64 {
	if n > 0 && n > math.MaxInt64/unit {
		return oneWeekSeconds
	}
	if n < 0 && n < math.MinInt64/unit {
		return math.MinInt64
	}
	return n * unit
}

// toSeconds ports the pinned _to_seconds: case-insensitive H/D/W
// detection on the uppercased string, every 'H'/'D' removed before the
// numeric parse (a non-numeric remainder is the pinned ValueError crash
// position and answers errZoneMalformed — unlike the else branch, whose
// failures answer one week), the W branch answering one week without
// any numeric parse, and the one-week cap applied last. Negative values
// pass through unchanged, exactly like the pinned comparisons.
func toSeconds(timestr string) (int64, error) {
	upper := strings.ToUpper(timestr)
	var seconds int64
	switch {
	case strings.Contains(upper, "H"):
		count, err := pythonInt(strings.ReplaceAll(upper, "H", ""))
		if err != nil {
			return 0, errZoneMalformed
		}
		seconds = scaleSeconds(count, 3600)
	case strings.Contains(upper, "D"):
		count, err := pythonInt(strings.ReplaceAll(upper, "D", ""))
		if err != nil {
			return 0, errZoneMalformed
		}
		seconds = scaleSeconds(count, 86400)
	case strings.Contains(upper, "W"):
		// The pinned W branch never parses the numeric part: "2W", "w",
		// and "abcW" all answer one week.
		seconds = oneWeekSeconds
	default:
		count, err := pythonInt(upper)
		if err != nil {
			// Pinned except ValueError: unparsable plain values answer
			// one week ("" and "604801"-style overflow cap below).
			return oneWeekSeconds, nil
		}
		seconds = count
	}
	if seconds > oneWeekSeconds {
		seconds = oneWeekSeconds
	}
	return seconds, nil
}

// ---------------------------------------------------------------------------
// R10.3A-SEC-01 / R103A-GATE-01/02 parser ceilings and result budgets
// (shared by parse_hosts and parse_zone)

// jsonEscapeSize lists the encoded length of every ASCII byte in the
// JSON string grammar of encoding/json with HTML escaping on — the
// default of both json.Marshal and json.Encoder, the CLI transport
// included: two-byte short escapes for the seven specials (quote,
// backslash, and the \b \f \n \r \t control forms), six-byte \u00XX
// escapes for the remaining control bytes and the HTML triplet
// <, >, &, and one byte for everything else (DEL included).
var jsonEscapeSize = func() [256]int8 {
	var sizes [256]int8
	for c := range sizes {
		sizes[c] = 1
	}
	for c := 0; c < 0x20; c++ {
		sizes[c] = 6
	}
	for _, c := range []byte{'"', '\\', '\b', '\f', '\n', '\r', '\t'} {
		sizes[c] = 2
	}
	sizes['<'], sizes['>'], sizes['&'] = 6, 6, 6
	return sizes
}()

// jsonStringLength returns the exact byte length of the JSON string
// literal encoding/json produces for s (HTML escaping on, the CLI
// transport's mode): two quotes plus, per rune, the tabulated ASCII
// escape size, six bytes for U+2028/U+2029 (always escaped), six bytes
// for every invalid UTF-8 byte (the encoder's \ufffd replacement), and
// the rune's byte length for everything else. The parser measures
// results through this length oracle only — it never materializes an
// encoded string, so no counting walker ever buffers the full output.
func jsonStringLength(s string) int64 {
	n := int64(2)
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			n += int64(jsonEscapeSize[c])
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1, r == '\u2028', r == '\u2029':
			n += 6
		default:
			n += int64(size)
		}
		i += size
	}
	return n
}

// jsonIntLength returns the exact byte length of the JSON encoding of
// one integer result value — the decimal digits and sign strconv
// emits, the same append encoding/json uses.
func jsonIntLength(v int64) int64 {
	return int64(len(strconv.FormatInt(v, 10)))
}

// parseBudget carries the shared parser ceilings through one parse
// call and measures the RETAINED result exactly as its serialized JSON
// representation (R103A-GATE-01/02): b.bytes always equals the byte
// length encoding/json would produce for the result value built so
// far — the outermost braces, every object key and colon, every array
// bracket, every separating comma, and every string and integer value
// with the exact escaping — and b.items always equals the number of
// retained JSON object members (a key:value pair at any depth) plus
// retained array elements, duplicate-appended elements included.
// Because both counters are exact at every step — insertions add, and
// an overwrite of an existing key replaces the previous value's whole
// retained subtree (its bytes AND its nested item count) with the new
// one's, so a shape-changing replacement reserves the exact new-minus-
// old delta of both budgets — no sequence of records can end over a
// ceiling the counter did not see, and enforcement in reserve happens
// BEFORE the caller mutates the result, so a rejection never leaves a
// partial value behind. parse_hosts values are append-only lists, so
// its members never take the replacement path.
type parseBudget struct {
	records int
	items   int
	bytes   int64
	// memberSizes caches the encoded size of every top-level member
	// VALUE so overwriting an existing key accounts the replacement
	// (new minus old) in O(1) without walking the previous value.
	memberSizes map[string]int64
	// memberItems caches the retained item count of every top-level
	// member's whole subtree (the member itself plus every nested
	// member and element), so a replacement that changes the value's
	// shape — a directive flattening a bucket, a bucket owner morphing
	// between the plain-string and TARGET/TTL forms — reserves the
	// exact new-minus-old item delta (R103A-GATE-02).
	memberItems map[string]int
}

// newParseBudget starts one parse call: the empty result object ("{}")
// serializes to 2 bytes and retains zero items.
func newParseBudget() parseBudget {
	return parseBudget{bytes: 2, memberSizes: map[string]int64{}, memberItems: map[string]int{}}
}

// record counts one parsed input record (a non-blank, non-comment
// line) and rejects past maxInputRecords.
func (b *parseBudget) record() error {
	b.records++
	if b.records > maxInputRecords {
		return errParseLimit
	}
	return nil
}

// reserve enforces the result ceilings BEFORE the caller inserts:
// items is the change in retained JSON members/elements the insertion
// causes and delta is the exact change to the serialized size (either
// may be negative for a replacement that shrinks the retained value).
// Both comparisons are overflow-safe by construction — the counters
// never exceed their ceilings, so maxEncodedBytes-b.bytes is never
// negative, b.items is never negative, and every delta is bounded by
// the 4096-byte cell ceiling times a small constant — and the counters
// move only when both ceilings hold.
func (b *parseBudget) reserve(items int, delta int64) error {
	if b.items+items > maxResultItems {
		return errResultItems
	}
	if delta > maxEncodedBytes-b.bytes {
		return errResultBytes
	}
	b.items += items
	b.bytes += delta
	return nil
}

// memberBytes returns the exact serialized-size contribution of one
// NEW top-level result member: the separating comma (when members
// already exist), the encoded key, the colon, and the encoded value.
func memberBytes(key string, valueSize int64, members int) int64 {
	n := jsonStringLength(key) + 1 + valueSize
	if members > 0 {
		n++
	}
	return n
}

// setZoneScalar reserves one top-level parse_zone member whose value
// is a scalar (a directive value or an SOA field): a new key adds one
// item and the key/colon/value bytes; an existing key — whatever its
// previous shape, scalar, list, or bucket — REPLACES the previous
// subtree's item count with the scalar's single item and its value
// bytes with the new value's, reserving the exact new-minus-old delta
// of both budgets (R103A-GATE-02: a directive flattening a bucket or
// list must return every nested item it removes). The caller assigns
// the result member immediately after a nil error.
func (b *parseBudget) setZoneScalar(key string, valueSize int64, members int, exists bool) error {
	items, delta := 1, memberBytes(key, valueSize, members)
	if exists {
		items, delta = 1-b.memberItems[key], valueSize-b.memberSizes[key]
	}
	if err := b.reserve(items, delta); err != nil {
		return err
	}
	b.memberSizes[key] = valueSize
	b.memberItems[key] = 1
	return nil
}

// zoneEntrySize returns the encoded size of one retained bucket entry
// value: the TARGET/TTL object of the A/AAAA form ({"TARGET":t,
// "TTL":l} = 18 structural bytes — {, "TARGET", :, ,, "TTL", :, } —
// plus the two encoded values; R103A-FINAL-BYTES-01: 18, not 19, the
// pre-fix budget overcounted one structural byte per nested entry) or
// the plain string of the generic form — both branches can write the
// same bucket key, so either shape can be the overwritten old value.
func zoneEntrySize(value any) (int64, error) {
	switch v := value.(type) {
	case map[string]string:
		return 18 + jsonStringLength(v["TARGET"]) + jsonStringLength(v["TTL"]), nil
	case string:
		return jsonStringLength(v), nil
	}
	// Defensive only: bucket entries are only ever assigned one of the
	// two shapes above.
	return 0, errZoneMalformed
}

// zoneEntryItems returns the retained item count of one bucket entry
// subtree besides its owner member: the TARGET/TTL object retains two
// nested members and the plain scalar retains none, so a replacement
// morphing between the shapes reserves exactly two gained or lost
// items (R103A-GATE-02).
func zoneEntryItems(value any) int {
	if _, ok := value.(map[string]string); ok {
		return 2
	}
	return 0
}

// cellOK reports whether one parsed token or derived result cell is
// within the single-cell ceiling.
func cellOK(cell string) bool { return len(cell) <= maxCellBytes }

// cellsOK reports whether every token of one parsed record is within
// the single-cell ceiling.
func cellsOK(comps []string) bool {
	for _, cell := range comps {
		if !cellOK(cell) {
			return false
		}
	}
	return true
}

// expandOrigin replaces every '@' in line with origin — the pinned
// global str.replace — behind the R10.3A-SEC-01 guard: the match count
// and the origin length decide the exact output size first (int64
// arithmetic, so no platform can overflow), and an expansion that
// would exceed the shared 1 MiB source ceiling — an attacker-shaped
// large origin or a repeated '@' run — rejects value-free before any
// output is allocated. The expansion itself is a linear builder.
func expandOrigin(line, origin string) (string, error) {
	if !strings.Contains(line, "@") {
		return line, nil
	}
	matches := int64(strings.Count(line, "@"))
	size := int64(len(line)) + matches*(int64(len(origin))-1)
	if size > maxSourceBytes {
		return "", errInputTooLarge
	}
	var expanded strings.Builder
	expanded.Grow(int(size))
	start := 0
	for i := 0; i < len(line); i++ {
		if line[i] == '@' {
			expanded.WriteString(line[start:i])
			expanded.WriteString(origin)
			start = i + 1
		}
	}
	expanded.WriteString(line[start:])
	return expanded.String(), nil
}

// ---------------------------------------------------------------------------
// parse_hosts

// parseHostsData ports the pinned parse_hosts loop over inline data:
// comment lines only when '#' is the first character, whitespace token
// split, IP-keyed alias accumulation in encounter order with duplicates
// kept, and allocated non-nil alias slices. A whitespace-only line — a
// pinned IndexError crash — is skipped (documented safe divergence).
// The R10.3A-SEC-01/R103A-GATE-01/02 ceilings bound input records,
// cell lengths, retained result items, and the complete serialized
// result representation, every reserve running BEFORE the map/list
// mutation; each failure answers one fixed value-free error with no
// partial result.
func parseHostsData(hosts string) (map[string][]string, error) {
	hostsdict := map[string][]string{}
	budget := newParseBudget()
	for _, line := range pythonSplitlines(hosts) {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		if err := budget.record(); err != nil {
			return nil, err
		}
		comps := pythonFields(line)
		if len(comps) == 0 {
			// Whitespace-only line: Salt raises IndexError here.
			continue
		}
		if !cellsOK(comps) {
			return nil, errParseLimit
		}
		ip := comps[0]
		aliases, exists := hostsdict[ip]
		if !exists {
			// The new member "ip": [] — key, colon, and the empty
			// (zero-item, two-byte) alias list.
			if err := budget.reserve(1, memberBytes(ip, 2, len(hostsdict))); err != nil {
				return nil, err
			}
			aliases = []string{}
		}
		for _, alias := range comps[1:] {
			// One alias element: the separating comma when the list
			// already holds elements, plus the encoded alias. Duplicates
			// append in encounter order and each one counts.
			delta := jsonStringLength(alias)
			if len(aliases) > 0 {
				delta++
			}
			if err := budget.reserve(1, delta); err != nil {
				return nil, err
			}
			aliases = append(aliases, alias)
		}
		hostsdict[ip] = aliases
	}
	return hostsdict, nil
}

// readBoundedSource reads one hosts/zone source through the bounded
// runtime boundary: at most maxSourceBytes bytes, regular file,
// no symlink following (final component and every parent), and —
// R10.3A-SEC-01 — a path argument longer than maxPathBytes is rejected
// before the filesystem is touched. Any failure is the caller's
// compatibility fallback; no error text travels on.
func readBoundedSource(rt *runtime.Runtime, name string) (string, bool) {
	if rt == nil || rt.FS == nil {
		return "", false
	}
	if len(name) > maxPathBytes {
		return "", false
	}
	data, err := runtime.ReadFileBounded(rt.FS, name, maxSourceBytes)
	if err != nil {
		return "", false
	}
	return string(data), true
}

// ParseHostsArgs mirrors the pinned signature
// parse_hosts(hostsfile="/etc/hosts", hosts=None).
type ParseHostsArgs struct {
	Hostsfile *string `statekit:"name=hostsfile"`
	Hosts     *string `statekit:"name=hosts"`
}

type parseHostsFunc struct{}

func (parseHostsFunc) Name() string { return "dnsutil.parse_hosts" }
func (parseHostsFunc) Args() any    { return ParseHostsArgs{} }

func (parseHostsFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ParseHostsArgs](args, "dnsutil.parse_hosts")
	if err != nil {
		return nil, err
	}
	hosts := pointerString(a.Hosts)
	// Python truthiness of the inline input: only None (nil) and the
	// empty string are falsy, so "   " parses inline like the source.
	if hosts == "" {
		path := defaultHostsPath
		if a.Hostsfile != nil {
			path = *a.Hostsfile
		}
		data, ok := readBoundedSource(rt, path)
		if !ok {
			// Pinned read-failure result, exact text, value-free.
			return hostsNotFoundMessage, nil
		}
		hosts = data
	}
	// R10.3A-SEC-01: the shared 1 MiB source ceiling applies before any
	// processing (file reads are already bounded to the same ceiling,
	// so this binds the inline value).
	if len(hosts) > maxSourceBytes {
		return nil, errInputTooLarge
	}
	parsed, err := parseHostsData(hosts)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

// ---------------------------------------------------------------------------
// parse_zone

// parseZoneData ports the pinned parse_zone loop. Every crash position
// of the Python source maps to errZoneMalformed and no partial results
// — including the R103A-FINAL-01 position: a multi-line '(' … ')'
// continuation join that strips every token answers the fixed
// value-free malformed error instead of indexing an empty slice. The
// continuation join and the '@'→ORIGIN expansion are linear builders,
// and the R10.3A-SEC-01/R103A-GATE-01/02 ceilings bound input records,
// cell lengths, retained result items (every nested JSON member and
// every list element), and the complete serialized result
// representation (every key including expanded bucket keys, every
// value, the exact JSON escaping, and every delimiter, colon, and
// comma), each reserve running BEFORE the map/list mutation.
func parseZoneData(zone string) (map[string]any, error) {
	zonedict := map[string]any{}
	budget := newParseBudget()
	multi := false
	var joined strings.Builder
	for _, raw := range pythonSplitlines(zone) {
		// comps = line.split(";"); line = comps[0].strip()
		line := pythonStrip(strings.SplitN(raw, ";", 2)[0])
		if line == "" {
			continue
		}
		if err := budget.record(); err != nil {
			return nil, err
		}
		if strings.HasPrefix(line, "$") {
			comps := pythonFields(line)
			if len(comps) < 2 {
				// Pinned IndexError: directive without a value.
				return nil, errZoneMalformed
			}
			if !cellsOK(comps) {
				return nil, errParseLimit
			}
			key := strings.ReplaceAll(comps[0], "$", "")
			_, exists := zonedict[key]
			if err := budget.setZoneScalar(key, jsonStringLength(comps[1]), len(zonedict), exists); err != nil {
				return nil, err
			}
			zonedict[key] = comps[1]
			continue
		}
		if strings.Contains(line, "(") && !strings.Contains(line, ")") {
			multi = true
			joined.Reset()
		}
		if multi {
			// Linear continuation join (the pinned repeated string
			// concatenation is the builder).
			joined.WriteString(" ")
			joined.WriteString(line)
			if !strings.Contains(line, ")") {
				continue
			}
			multi = false
			line = strings.ReplaceAll(strings.ReplaceAll(joined.String(), "(", ""), ")", "")
		}
		originValue, hasOrigin := zonedict["ORIGIN"]
		var origin string
		if hasOrigin {
			text, ok := originValue.(string)
			if !ok {
				// ORIGIN can only be assigned a string; defensive only.
				return nil, errZoneMalformed
			}
			origin = text
		}
		var comps []string
		if hasOrigin {
			// Pinned global replacement of every '@' in the line,
			// behind the R10.3A-SEC-01 expansion guard.
			expanded, err := expandOrigin(line, origin)
			if err != nil {
				return nil, err
			}
			comps = pythonFields(expanded)
		} else {
			comps = pythonFields(line)
		}
		if len(comps) == 0 {
			// R103A-FINAL-01: the multi-line join stripped every token
			// (whitespace-only or empty join); the pinned IndexError on
			// comps[0] maps to the fixed value-free malformed error —
			// never a panic, never a partial result.
			return nil, errZoneMalformed
		}
		if !cellsOK(comps) {
			return nil, errParseLimit
		}
		if strings.Contains(line, "SOA") {
			if len(comps) < 2 {
				return nil, errZoneMalformed
			}
			if comps[1] != "IN" {
				// Pinned comps.pop(1).
				comps = append(comps[:1:1], comps[2:]...)
			}
			if len(comps) < 10 {
				// Pinned IndexError on comps[9].
				return nil, errZoneMalformed
			}
			refresh, err := toSeconds(comps[6])
			if err != nil {
				return nil, err
			}
			retry, err := toSeconds(comps[7])
			if err != nil {
				return nil, err
			}
			expire, err := toSeconds(comps[8])
			if err != nil {
				return nil, err
			}
			minttl, err := toSeconds(comps[9])
			if err != nil {
				return nil, err
			}
			// Pinned replace(".", "@", 1) on the contact token.
			contact := strings.Replace(comps[4], ".", "@", 1)
			// The nine SOA members are reserved one by one against the
			// live map — a key a directive pre-created is an overwrite
			// that replaces its value bytes (ORIGIN over $ORIGIN
			// included).
			soaFields := []struct {
				key   string
				value any
				size  int64
			}{
				{"ORIGIN", comps[0], jsonStringLength(comps[0])},
				{"NETWORK", comps[1], jsonStringLength(comps[1])},
				{"SOURCE", comps[3], jsonStringLength(comps[3])},
				{"CONTACT", contact, jsonStringLength(contact)},
				{"SERIAL", comps[5], jsonStringLength(comps[5])},
				{"REFRESH", refresh, jsonIntLength(refresh)},
				{"RETRY", retry, jsonIntLength(retry)},
				{"EXPIRE", expire, jsonIntLength(expire)},
				{"MINTTL", minttl, jsonIntLength(minttl)},
			}
			for _, field := range soaFields {
				_, exists := zonedict[field.key]
				if err := budget.setZoneScalar(field.key, field.size, len(zonedict), exists); err != nil {
					return nil, err
				}
				zonedict[field.key] = field.value
			}
			continue
		}
		if comps[0] == "IN" {
			// Pinned comps.insert(0, zonedict["ORIGIN"]) — a KeyError
			// when no ORIGIN is known.
			if !hasOrigin {
				return nil, errZoneMalformed
			}
			comps = append([]string{origin}, comps...)
		}
		if !strings.HasSuffix(comps[0], ".") && !strings.Contains(line, "NS") {
			if !hasOrigin {
				// Pinned zonedict["ORIGIN"] KeyError.
				return nil, errZoneMalformed
			}
			comps[0] = comps[0] + "." + origin
			if !cellOK(comps[0]) {
				return nil, errParseLimit
			}
		}
		if len(comps) < 3 {
			// Pinned IndexError on comps[2].
			return nil, errZoneMalformed
		}
		switch {
		case comps[2] == "NS":
			if len(comps) < 4 {
				return nil, errZoneMalformed
			}
			existing, exists := zonedict["NS"]
			list, isList := existing.([]string)
			if exists && !isList {
				// Pinned AttributeError: a directive made "NS" a string.
				return nil, errZoneMalformed
			}
			if !exists {
				list = []string{}
			}
			rowSize := jsonStringLength(comps[3])
			var items int
			var delta int64
			if !exists {
				// The NS member plus its first list element.
				items, delta = 2, memberBytes("NS", 2+rowSize, len(zonedict))
			} else {
				items, delta = 1, rowSize
				if len(list) > 0 {
					delta++
				}
			}
			if err := budget.reserve(items, delta); err != nil {
				return nil, err
			}
			if exists {
				budget.memberSizes["NS"] += delta
				budget.memberItems["NS"]++
			} else {
				budget.memberSizes["NS"] = 2 + rowSize
				budget.memberItems["NS"] = 2
			}
			zonedict["NS"] = append(list, comps[3])
		case comps[2] == "MX":
			if len(comps) < 5 {
				return nil, errZoneMalformed
			}
			if _, exists := zonedict["MX"]; !exists {
				// Pinned quirk: only the first MX record is kept. The
				// retained value is [ {"priority":p,"host":h} ]: 23
				// structural bytes plus the two encoded values, four
				// items — the member, the array element, and the two
				// object members.
				valueSize := 23 + jsonStringLength(comps[3]) + jsonStringLength(comps[4])
				if err := budget.reserve(4, memberBytes("MX", valueSize, len(zonedict))); err != nil {
					return nil, err
				}
				budget.memberSizes["MX"] = valueSize
				budget.memberItems["MX"] = 4
				zonedict["MX"] = []map[string]string{{
					"priority": comps[3],
					"host":     comps[4],
				}}
			}
		case len(comps) >= 4 && (comps[3] == "A" || comps[3] == "AAAA"):
			if len(comps) < 5 {
				return nil, errZoneMalformed
			}
			bucket, bucketOK := zonedict[comps[3]].(map[string]any)
			_, typeExists := zonedict[comps[3]]
			if typeExists && !bucketOK {
				// Pinned TypeError: setdefault returned a string.
				return nil, errZoneMalformed
			}
			if !bucketOK {
				bucket = map[string]any{}
			}
			// The retained entry is {"TARGET":t,"TTL":l}: 18 structural
			// bytes ({, "TARGET", :, ,, "TTL", :, } — R103A-FINAL-BYTES-01;
			// the pre-fix budget counted 19) plus the two encoded values.
			// One record inserts up to three nested entries (owner member,
			// TARGET, TTL) plus the bucket member when the type is new, and
			// an owner that already exists — in either shape — REPLACES its
			// old retained subtree, reserving the exact new-minus-old item
			// and byte deltas (R103A-GATE-02: a plain-string owner morphing
			// into the TARGET/TTL object gains its two nested members).
			entrySize := 18 + jsonStringLength(comps[4]) + jsonStringLength(comps[1])
			oldEntry, ownerExists := bucket[comps[0]]
			var items int
			var delta int64
			switch {
			case !typeExists:
				items = 4
				delta = memberBytes(comps[3], 2+jsonStringLength(comps[0])+1+entrySize, len(zonedict))
			case ownerExists:
				oldSize, err := zoneEntrySize(oldEntry)
				if err != nil {
					return nil, err
				}
				items = 2 - zoneEntryItems(oldEntry)
				delta = entrySize - oldSize
			default:
				items = 3
				delta = jsonStringLength(comps[0]) + 1 + entrySize
				if len(bucket) > 0 {
					delta++
				}
			}
			if err := budget.reserve(items, delta); err != nil {
				return nil, err
			}
			if typeExists {
				budget.memberSizes[comps[3]] += delta
				budget.memberItems[comps[3]] += items
			} else {
				budget.memberSizes[comps[3]] = 2 + jsonStringLength(comps[0]) + 1 + entrySize
				budget.memberItems[comps[3]] = 4
			}
			bucket[comps[0]] = map[string]string{
				"TARGET": comps[4],
				"TTL":    comps[1],
			}
			zonedict[comps[3]] = bucket
		default:
			if len(comps) < 4 {
				// Pinned IndexError evaluating comps[3]/comps[3]= below.
				return nil, errZoneMalformed
			}
			bucket, bucketOK := zonedict[comps[2]].(map[string]any)
			_, typeExists := zonedict[comps[2]]
			if typeExists && !bucketOK {
				return nil, errZoneMalformed
			}
			if !bucketOK {
				bucket = map[string]any{}
			}
			valueSize := jsonStringLength(comps[3])
			oldEntry, ownerExists := bucket[comps[0]]
			var items int
			var delta int64
			switch {
			case !typeExists:
				// The type member (whose key is the expanded comps[2]
				// token, R103A-GATE-01) plus the first owner member.
				items = 2
				delta = memberBytes(comps[2], 2+jsonStringLength(comps[0])+1+valueSize, len(zonedict))
			case ownerExists:
				oldSize, err := zoneEntrySize(oldEntry)
				if err != nil {
					return nil, err
				}
				// The owner member stays; a TARGET/TTL object being
				// flattened returns its two nested items (R103A-GATE-02).
				items = -zoneEntryItems(oldEntry)
				delta = valueSize - oldSize
			default:
				items = 1
				delta = jsonStringLength(comps[0]) + 1 + valueSize
				if len(bucket) > 0 {
					delta++
				}
			}
			if err := budget.reserve(items, delta); err != nil {
				return nil, err
			}
			if typeExists {
				budget.memberSizes[comps[2]] += delta
				budget.memberItems[comps[2]] += items
			} else {
				budget.memberSizes[comps[2]] = 2 + jsonStringLength(comps[0]) + 1 + valueSize
				budget.memberItems[comps[2]] = 2
			}
			bucket[comps[0]] = comps[3]
			zonedict[comps[2]] = bucket
		}
	}
	return zonedict, nil
}

// ParseZoneArgs mirrors the pinned signature
// parse_zone(zonefile=None, zone=None).
type ParseZoneArgs struct {
	Zonefile *string `statekit:"name=zonefile"`
	Zone     *string `statekit:"name=zone"`
}

type parseZoneFunc struct{}

func (parseZoneFunc) Name() string { return "dnsutil.parse_zone" }
func (parseZoneFunc) Args() any    { return ParseZoneArgs{} }

func (parseZoneFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ParseZoneArgs](args, "dnsutil.parse_zone")
	if err != nil {
		return nil, err
	}
	// Pinned order: the inline data is the parameter value; a truthy
	// zonefile is read first and its content REPLACES the inline value
	// on success (even empty content — which then answers the pinned
	// not-found result), while every read failure silently keeps the
	// inline data (try/except pass), through the bounded no-follow
	// boundary.
	zone := ""
	if a.Zone != nil {
		zone = *a.Zone
	}
	if a.Zonefile != nil && *a.Zonefile != "" {
		if data, ok := readBoundedSource(rt, *a.Zonefile); ok {
			zone = data
		}
	}
	if zone == "" {
		return zoneNotFoundMessage, nil
	}
	// R10.3A-SEC-01: the shared 1 MiB source ceiling applies before any
	// processing (file reads are already bounded to the same ceiling,
	// so this binds the inline value).
	if len(zone) > maxSourceBytes {
		return nil, errInputTooLarge
	}
	parsed, err := parseZoneData(zone)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

// ---------------------------------------------------------------------------
// dig delegation (check_ip, A, AAAA, NS, SPF, MX)

// hasDig ports the pinned _has_dig availability probe as the dig
// module's trusted-resolution gate: a Runner must expose the
// process.TrustedCommandResolver capability and resolve the fixed dig
// name to an absolute path. A capability-less or failing Runner means
// unavailable — this package never falls back to a host PATH lookup,
// bare-name dispatch, or any socket resolver.
func hasDig(rt *runtime.Runtime) bool {
	if rt == nil || rt.Runner == nil {
		return false
	}
	resolver, ok := rt.Runner.(process.TrustedCommandResolver)
	if !ok {
		return false
	}
	path, err := resolver.ResolveTrustedCommand(digExecutable)
	return err == nil && path != "" && filepath.IsAbs(path)
}

// callDig performs the nested invocation for one dig function: the
// registry must carry the exact name (the pinned __salt__ lookup crash
// position maps to one fixed value-free unavailable error), then the
// caller's context and runtime flow into the nested call so
// cancellation, deadlines, and the dig module's own budgets apply.
func callDig(ctx context.Context, rt *runtime.Runtime, name string, args any) (any, error) {
	if rt == nil || rt.Exec == nil {
		return nil, errDigRunnerUnavailable
	}
	if _, ok := rt.Exec.Get(name); !ok {
		return nil, errDigFunctionUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return rt.Exec.Call(ctx, rt, name, args)
}

func typedArgs[T any](args any, name string) (*T, error) {
	value, ok := args.(*T)
	if !ok || value == nil {
		return nil, errors.New(name + ": expected *arguments")
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

// CheckIPArgs mirrors the pinned check_ip(ip_addr) signature.
type CheckIPArgs struct {
	Addr string `statekit:"required,name=addr"`
}

type checkIPFunc struct{}

func (checkIPFunc) Name() string { return "dnsutil.check_ip" }
func (checkIPFunc) Args() any    { return CheckIPArgs{} }

func (checkIPFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[CheckIPArgs](args, "dnsutil.check_ip")
	if err != nil {
		return nil, err
	}
	if !hasDig(rt) {
		return digUnavailableMessage, nil
	}
	return callDig(ctx, rt, "dig.check_ip", &execdig.CheckIPArgs{Addr: a.Addr})
}

// AArgs mirrors the pinned A(host, nameserver=None) signature.
type AArgs struct {
	Host       string  `statekit:"required,name=host"`
	Nameserver *string `statekit:"name=nameserver"`
}

type aFunc struct{}

func (aFunc) Name() string { return "dnsutil.A" }
func (aFunc) Args() any    { return AArgs{} }

func (aFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[AArgs](args, "dnsutil.A")
	if err != nil {
		return nil, err
	}
	if !hasDig(rt) {
		// The pinned socket.getaddrinfo fallback is an explicitly
		// deferred divergence: no host-resolver egress exists here.
		return digUnavailableMessage, nil
	}
	return callDig(ctx, rt, "dig.A", &execdig.AArgs{
		Host:       a.Host,
		Nameserver: a.Nameserver,
	})
}

// AAAAArgs mirrors the pinned AAAA(host, nameserver=None) signature.
type AAAAArgs struct {
	Host       string  `statekit:"required,name=host"`
	Nameserver *string `statekit:"name=nameserver"`
}

type aaaaFunc struct{}

func (aaaaFunc) Name() string { return "dnsutil.AAAA" }
func (aaaaFunc) Args() any    { return AAAAArgs{} }

func (aaaaFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[AAAAArgs](args, "dnsutil.AAAA")
	if err != nil {
		return nil, err
	}
	if !hasDig(rt) {
		return digUnavailableMessage, nil
	}
	return callDig(ctx, rt, "dig.AAAA", &execdig.AAAAArgs{
		Host:       a.Host,
		Nameserver: a.Nameserver,
	})
}

// NSArgs mirrors the pinned NS(domain, resolve=True, nameserver=None)
// signature.
type NSArgs struct {
	Domain     string  `statekit:"required,name=domain"`
	Resolve    *bool   `statekit:"name=resolve"`
	Nameserver *string `statekit:"name=nameserver"`
}

type nsFunc struct{}

func (nsFunc) Name() string { return "dnsutil.NS" }
func (nsFunc) Args() any    { return NSArgs{} }

func (nsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[NSArgs](args, "dnsutil.NS")
	if err != nil {
		return nil, err
	}
	if !hasDig(rt) {
		return digUnavailableMessage, nil
	}
	// The pinned call forwards resolve with its True default.
	resolve := pointerBool(a.Resolve, true)
	return callDig(ctx, rt, "dig.NS", &execdig.NSArgs{
		Domain:     a.Domain,
		Resolve:    &resolve,
		Nameserver: a.Nameserver,
	})
}

// SPFArgs mirrors the pinned SPF(domain, record="SPF", nameserver=None)
// signature.
type SPFArgs struct {
	Domain     string  `statekit:"required,name=domain"`
	Record     *string `statekit:"name=record"`
	Nameserver *string `statekit:"name=nameserver"`
}

type spfFunc struct{}

func (spfFunc) Name() string { return "dnsutil.SPF" }
func (spfFunc) Args() any    { return SPFArgs{} }

func (spfFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[SPFArgs](args, "dnsutil.SPF")
	if err != nil {
		return nil, err
	}
	if !hasDig(rt) {
		return digUnavailableMessage, nil
	}
	// The pinned call forwards record with its exact "SPF" default.
	record := "SPF"
	if a.Record != nil {
		record = *a.Record
	}
	return callDig(ctx, rt, "dig.SPF", &execdig.SPFArgs{
		Domain:     a.Domain,
		Record:     &record,
		Nameserver: a.Nameserver,
	})
}

// MXArgs mirrors the pinned MX(domain, resolve=False, nameserver=None)
// signature.
type MXArgs struct {
	Domain     string  `statekit:"required,name=domain"`
	Resolve    *bool   `statekit:"name=resolve"`
	Nameserver *string `statekit:"name=nameserver"`
}

type mxFunc struct{}

func (mxFunc) Name() string { return "dnsutil.MX" }
func (mxFunc) Args() any    { return MXArgs{} }

func (mxFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[MXArgs](args, "dnsutil.MX")
	if err != nil {
		return nil, err
	}
	if !hasDig(rt) {
		return digUnavailableMessage, nil
	}
	// The pinned call forwards resolve with its False default.
	resolve := pointerBool(a.Resolve, false)
	return callDig(ctx, rt, "dig.MX", &execdig.MXArgs{
		Domain:     a.Domain,
		Resolve:    &resolve,
		Nameserver: a.Nameserver,
	})
}

// Register installs the bounded R10.3a dnsutil catalog: the eight
// public functions of this slice. hosts_append, hosts_remove, and
// serial stay pending (see the package comment for the specific
// reasons and upgrade paths); the pinned module defines no aliases.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		parseHostsFunc{},
		parseZoneFunc{},
		checkIPFunc{},
		aFunc{},
		aaaaFunc{},
		nsFunc{},
		spfFunc{},
		mxFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
