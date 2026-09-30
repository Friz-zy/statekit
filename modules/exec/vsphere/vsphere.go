// Package vsphere contains the R10.4a private, source-backed parsing
// primitive for the pinned Salt vsphere execution module
// (saltstack/salt/modules/vsphere.py @ 8b63e700637e40d76f80a00d95c60471797c73b9,
// catalog docs/catalog/exec/vsphere.yaml).
//
// This package is deliberately PRIVATE and deliberately INCOMPLETE. It
// registers nothing: there is no Name() virtual function, no bootstrap
// registration, no public catalog entry, and no registry/counter
// increment. The vsphere family is an R10 cloud family whose real
// provider transport (PyVmomi or the govc vendor CLI) remains
// ADR/decision-gated per the R10 policy (porting plan §R10: vendor CLI
// wrappers first; provider connections are a separate gated decision).
// This package is an internal source-compatible parsing primitive, NOT
// a usable vSphere/cloud implementation: it holds no credentials, opens
// no endpoint, performs no network or provider call, and never invokes
// a vendor CLI. It only reshapes synthetic stdout bytes that the caller
// already holds.
//
// # formatCoredumpStdout
//
// formatCoredumpStdout ports _format_coredump_stdout (pinned lines
// 7655–7682) as a bounded, pure parser. The pinned source iterates
// cmd_ret["stdout"].splitlines(), strips and lowercases each line, and
// recognizes four case-insensitive prefixes:
//
//	enabled:             → bool via the substring test `"true" in parts[1]`
//	                     (substring truth: "trueish" and "nottrue" both
//	                     enable); on a false store the parser STOPS
//	                     immediately (the pinned break)
//	host vnic:           → parts[1].strip() stored as "host_vnic"
//	network server ip:   → parts[1].strip() stored as "ip"
//	network server port: → parts[1].strip() stored as "port"
//
// Ported source behaviors, quirk-inclusive:
//
//   - Python str.splitlines() boundaries: \n, \r, \r\n (one boundary),
//     \v, \f, U+001C..U+001E, U+0085, U+2028, U+2029. A trailing
//     boundary yields no trailing empty element; U+001F is whitespace
//     but never a line boundary.
//   - Python str.strip() whitespace semantics for every stripped token
//     (Go unicode.IsSpace plus U+001C..U+001F), and Python str.lower()
//     lowercasing of the whole line BEFORE prefix matching and before
//     the colon split — so every stored value is lowercased too, exactly
//     like the pinned source. U+0130 is lowercased to "i"+U+0307 like
//     Python's unconditional SpecialCasing entry (Go's simple table
//     would drop the dot); the context-dependent final-sigma rule of
//     SpecialCasing is the one documented lowercasing divergence — it
//     cannot affect the ASCII prefix matching or any bool result, only
//     exotic non-ASCII stored values.
//   - The colon split indexes Python split(":")[1] verbatim: the value
//     is exactly the text between the FIRST and SECOND colon of the
//     line. An IPv6 value is therefore truncated at its first inner
//     colon ("network server ip: fe80::1" stores "fe80"), adjacent
//     colons store an empty value, and everything past the second colon
//     is discarded. These quirks are never normalized or corrected.
//   - The enabled substring test runs against the UNSTRIPPED second
//     field (the pinned code strips only host_vnic/ip/port values).
//   - Duplicate recognized fields overwrite in encounter order (Python
//     dict assignment); unknown labels and blank lines are ignored.
//   - Empty stdout (or output with no recognized label) returns an
//     allocated empty map, never nil, matching the pinned empty dict.
//
// StateKit bounds that the pinned source lacks (fail-closed, fixed
// value-free errors, no partial map on any failure — the map is only
// returned on the success path):
//
//   - the "stdout" field must be a string (missing key, nil, or any
//     non-string type answers a fixed type error — the pinned source
//     would raise KeyError/AttributeError);
//   - input bytes ≤ 64 KiB (65536), checked before UTF-8 validation;
//   - stdout must be valid UTF-8;
//   - at most 1024 reached lines; the pinned enabled:false
//     short-circuit may stop before scanning later lines; the whole
//     input is still bounded at 64 KiB;
//   - each retained field value ≤ 4096 bytes (post-lower, post-strip
//     retained value; the four retained keys are fixed short literals,
//     so the cap is a value cap);
//   - at most 4 retained fields (unreachable through the fixed label
//     set; a defensive fail-closed guard, not a behavior change).
//
// Every violation answers one fixed sentinel error carrying no input
// bytes, no field values, and no caller data. The helper is pure: it
// reads nothing but the passed map, writes nothing, and calls nothing.
package vsphere

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Fixed parsing budgets (StateKit bounds; the pinned source is unbounded).
const (
	// coredumpMaxInput caps the synthetic stdout at 64 KiB.
	coredumpMaxInput = 64 * 1024
	// coredumpMaxLines caps the splitlines count at 1024.
	coredumpMaxLines = 1024
	// coredumpMaxFieldValue caps each retained field value at 4096 bytes.
	coredumpMaxFieldValue = 4096
	// coredumpMaxFields caps the retained map at 4 fields. Exactly four
	// labels are recognized, so this guard is unreachable by construction
	// and exists to fail closed if the label set ever grows.
	coredumpMaxFields = 4
)

// Fixed value-free sentinel errors. Constant text, no Unwrap, no custom
// Is — errors.Is matches only the fixed identity, and no input bytes,
// field values, or caller data ever travel in an error.
var (
	// errCoredumpStdoutType answers a missing "stdout" key or a
	// non-string value (the pinned KeyError/AttributeError positions).
	errCoredumpStdoutType = errors.New("vsphere: coredump stdout is missing or not a string")
	// errCoredumpStdoutSize answers stdout over 64 KiB.
	errCoredumpStdoutSize = errors.New("vsphere: coredump stdout exceeds the 64 KiB input limit")
	// errCoredumpStdoutUTF8 answers stdout that is not valid UTF-8.
	errCoredumpStdoutUTF8 = errors.New("vsphere: coredump stdout is not valid UTF-8")
	// errCoredumpLineLimit answers more than 1024 splitlines lines.
	errCoredumpLineLimit = errors.New("vsphere: coredump stdout exceeds the 1024 line limit")
	// errCoredumpFieldValue answers a retained field value over 4096 bytes.
	errCoredumpFieldValue = errors.New("vsphere: coredump field value exceeds the 4096 byte limit")
	// errCoredumpFieldCount answers a retained map over 4 fields
	// (unreachable through the fixed label set; defensive).
	errCoredumpFieldCount = errors.New("vsphere: coredump result exceeds the 4 field limit")
)

// formatCoredumpStdout is the bounded, pure Go port of the pinned Salt
// _format_coredump_stdout helper (saltstack/salt/modules/vsphere.py
// lines 7655–7682). It takes the cmd.run_all-shaped result dictionary
// and returns the coredump network config fields parsed from its
// "stdout" string member.
//
// The parser is private by design: it backs no registered function and
// is an internal source-compatible primitive only. Real vSphere
// transport remains ADR/decision-gated.
func formatCoredumpStdout(cmdRet map[string]any) (map[string]any, error) {
	// The pinned source reads cmd_ret["stdout"] and calls .splitlines()
	// on it; a missing key or non-string raises. StateKit answers the
	// fixed value-free type error instead (nil map reads are safe).
	raw, ok := cmdRet["stdout"]
	if !ok {
		return nil, errCoredumpStdoutType
	}
	stdout, ok := raw.(string)
	if !ok {
		return nil, errCoredumpStdoutType
	}

	// Budgets run in a fixed order before any parsing: size, then
	// UTF-8 validity, then the line count during the split. The result
	// map is local; every error path returns nil so no partial state
	// ever escapes.
	if len(stdout) > coredumpMaxInput {
		return nil, errCoredumpStdoutSize
	}
	if !utf8.ValidString(stdout) {
		return nil, errCoredumpStdoutUTF8
	}

	ret := make(map[string]any, 4)

	// Iterate the Python str.splitlines() boundaries byte-wise (input
	// is valid UTF-8, so C2 85 is exactly U+0085 and E2 80 A8/A9 are
	// exactly U+2028/U+2029; \r\n is one boundary). The line count is
	// enforced while scanning, so an over-budget input aborts before
	// more than one extra line is ever materialized.
	lines := 0
	start := 0
	stop := false
	for i := 0; i < len(stdout) && !stop; {
		b := stdout[i]
		width := 0
		switch {
		case b == '\n', b == '\v', b == '\f', b == '\x1c', b == '\x1d', b == '\x1e':
			width = 1
		case b == '\r':
			width = 1
			if i+1 < len(stdout) && stdout[i+1] == '\n' {
				width = 2
			}
		case b == 0xC2 && i+1 < len(stdout) && stdout[i+1] == 0x85:
			width = 2
		case b == 0xE2 && i+2 < len(stdout) && stdout[i+1] == 0x80 && (stdout[i+2] == 0xA8 || stdout[i+2] == 0xA9):
			width = 3
		default:
			i++
			continue
		}
		lines++
		if lines > coredumpMaxLines {
			return nil, errCoredumpLineLimit
		}
		lineStop, err := coredumpParseLine(ret, stdout[start:i])
		if err != nil {
			return nil, err
		}
		// The pinned break: an enabled: false stops the whole loop.
		stop = lineStop
		i += width
		start = i
	}
	if !stop && start < len(stdout) {
		lines++
		if lines > coredumpMaxLines {
			return nil, errCoredumpLineLimit
		}
		if _, err := coredumpParseLine(ret, stdout[start:]); err != nil {
			return nil, err
		}
	}
	if len(ret) > coredumpMaxFields {
		return nil, errCoredumpFieldCount
	}
	return ret, nil
}

// coredumpParseLine ports one iteration body of the pinned loop: strip,
// lowercase, then the four startswith branches in source order. It
// returns stop=true when the pinned break fired (enabled: false), which
// ends the whole loop immediately.
func coredumpParseLine(ret map[string]any, raw string) (bool, error) {
	// line = line.strip().lower() — the whole line, before matching and
	// before the colon split, so stored values are lowercased too.
	line := pythonLower(pythonStrip(raw))
	switch {
	case strings.HasPrefix(line, "enabled:"):
		// enabled = line.split(":"); "true" in enabled[1] — the
		// substring test runs on the UNSTRIPPED second field.
		if strings.Contains(coredumpColonField(line), "true") {
			ret["enabled"] = true
		} else {
			ret["enabled"] = false
			// The pinned break: stop parsing immediately.
			return true, nil
		}
	case strings.HasPrefix(line, "host vnic:"):
		v := pythonStrip(coredumpColonField(line))
		if len(v) > coredumpMaxFieldValue {
			return false, errCoredumpFieldValue
		}
		ret["host_vnic"] = v
	case strings.HasPrefix(line, "network server ip:"):
		v := pythonStrip(coredumpColonField(line))
		if len(v) > coredumpMaxFieldValue {
			return false, errCoredumpFieldValue
		}
		ret["ip"] = v
	case strings.HasPrefix(line, "network server port:"):
		v := pythonStrip(coredumpColonField(line))
		if len(v) > coredumpMaxFieldValue {
			return false, errCoredumpFieldValue
		}
		ret["port"] = v
	}
	// Unknown labels and blank lines are ignored, exactly like the
	// pinned fall-through.
	return false, nil
}

// coredumpColonField returns Python line.split(":")[1]: the exact text
// between the first and second colon. Source behavior is kept verbatim —
// no normalization of adjacent-colon empties, IPv6 truncation, or
// anything past the second field. The pinned prefixes all contain a
// colon, so the first colon always exists; the fallback answers "" as a
// defensive no-op.
func coredumpColonField(line string) string {
	first := strings.IndexByte(line, ':')
	if first < 0 {
		return ""
	}
	rest := line[first+1:]
	if next := strings.IndexByte(rest, ':'); next >= 0 {
		return rest[:next]
	}
	return rest
}

// ---------------------------------------------------------------------------
// Python string semantics (same predicate family as the dig/dnsutil ports)

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

// pythonLower lowercases exactly like Python str.lower(): the simple
// Unicode mappings plus the one unconditional SpecialCasing entry,
// U+0130 → "i"+U+0307, which Go's simple table collapses to "i". The
// context-dependent final-sigma SpecialCasing rule is NOT reproduced
// (documented divergence; it cannot affect the ASCII prefix matching
// or any bool result).
func pythonLower(s string) string {
	if !strings.Contains(s, "\u0130") {
		return strings.ToLower(s)
	}
	return strings.ToLower(strings.ReplaceAll(s, "\u0130", "i\u0307"))
}
