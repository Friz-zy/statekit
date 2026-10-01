//go:build r10_contract

package vsphere

// R10.4a/R10.4b/R10.4c private-helper contract tests (r10_contract build tag).
//
// Every vector is an inline synthetic stdout literal: the suite is pure
// and hermetic — no PyVmomi, no govc, no vendor CLI, no Runner, no
// network, no endpoint, no credentials, and no host file is ever read
// or written. The tests pin the pinned-source behavior of
// _format_coredump_stdout (saltstack/salt/modules/vsphere.py lines
// 7655–7682) quirk-inclusive, plus the StateKit fail-closed budgets
// (exact boundary and +1 rejections with nil results), and the
// value-free error discipline. R10.4b adds the same discipline for
// _format_firewall_stdout (pinned lines 7685–7702): raw "Name"/"---"
// prefix skips (no strip, no lower), Python str.split() row semantics
// with nonempty-string truthiness ("false" stores true), duplicate
// overwrite, the pinned {"success": true, "rulesets": {...}} ret_dict
// shape, the pinned IndexError positions mapped to a fixed malformed-row
// sentinel, and the 64 KiB / 1024-line / 4096-byte / 256-ruleset bounds.
// R10.4c adds the same discipline for _format_syslog_config (pinned
// lines 7704–7723): success DERIVED from cmd_ret["retcode"], the raw
// verbatim message path on a nonzero retcode, the pre-split
// line.strip() (so "a: " is malformed and ": x" stores the empty key),
// the literal ": " delimiter split with third-field discard, duplicate
// overwrite and the "success" string overwrite, Python
// whitespace/splitlines semantics with exact case preservation, and
// the 64 KiB / 1024-line / 4096-byte / 256-key bounds.

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// mustParse is a test helper: parse or fail the test.
func mustParse(t *testing.T, cmdRet map[string]any) map[string]any {
	t.Helper()
	ret, err := formatCoredumpStdout(cmdRet)
	if err != nil {
		t.Fatalf("formatCoredumpStdout(%q) returned unexpected error: %v", cmdRet["stdout"], err)
	}
	return ret
}

// wantOf builds the expected result map.
func wantOf(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}

func TestFormatCoredumpNormalFields(t *testing.T) {
	stdout := "Enabled: true\n" +
		"Host VNic: vmk0\n" +
		"Network Server IP: 10.1.2.3\n" +
		"Network Server Port: 65000\n"
	got := mustParse(t, map[string]any{"stdout": stdout})
	want := wantOf(
		"enabled", true,
		"host_vnic", "vmk0",
		"ip", "10.1.2.3",
		"port", "65000",
	)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normal fields: got %#v, want %#v", got, want)
	}
	// Pinned Go types: enabled is bool, every other field a string.
	if v, ok := got["enabled"].(bool); !ok || !v {
		t.Fatalf("enabled must be a Go bool true, got %#v", got["enabled"])
	}
	for key, wantStr := range map[string]string{"host_vnic": "vmk0", "ip": "10.1.2.3", "port": "65000"} {
		if v, ok := got[key].(string); !ok || v != wantStr {
			t.Fatalf("%s must be a Go string %q, got %#v", key, wantStr, got[key])
		}
	}
}

func TestFormatCoredumpMixedCaseAndWhitespace(t *testing.T) {
	vectors := []struct {
		name   string
		stdout string
		want   map[string]any
	}{
		{
			// The whole line is lowercased BEFORE the colon split, so
			// stored values are lowercased too (pinned source order).
			name:   "uppercase values are lowercased",
			stdout: "Host VNic: VMK0\nNetwork Server IP: FE80::1\nNetwork Server Port: PORT-X\n",
			want:   wantOf("host_vnic", "vmk0", "ip", "fe80", "port", "port-x"),
		},
		{
			name:   "tabs and spaces around values",
			stdout: "host vnic:\t VMK0 \t\n",
			want:   wantOf("host_vnic", "vmk0"),
		},
		{
			name:   "interior whitespace is retained, only ends stripped",
			stdout: "host vnic:  a b  \n",
			want:   wantOf("host_vnic", "a b"),
		},
		{
			// U+001C..U+001E are LINE boundaries; U+001F is Python
			// strip() whitespace while never being a boundary, so it
			// strips from around a value without splitting the line.
			name:   "U+001F strips as whitespace and is not a boundary",
			stdout: "host vnic:\x1fvmk0\x1f\nnetwork server port: 65000\x1f\n",
			want:   wantOf("host_vnic", "vmk0", "port", "65000"),
		},
		{
			// U+001F is whitespace but NOT a line boundary: the whole
			// thing is one line and the interior U+001F is retained.
			name:   "U+001F interior retained, not a boundary",
			stdout: "host vnic: a\x1fb\n",
			want:   wantOf("host_vnic", "a\x1fb"),
		},
		{
			// U+001C IS a line boundary AND strip whitespace.
			name:   "U+001C is a line boundary",
			stdout: "host vnic: a\x1cb\n",
			want:   wantOf("host_vnic", "a"),
		},
		{
			name:   "enabled with surrounding whitespace and mixed case",
			stdout: "  \t ENABLED : x", // not a prefix: "enabled :" has a space before the colon
			want:   map[string]any{},
		},
		{
			// The pinned source strips each line BEFORE the startswith
			// check, so leading Python whitespace never blocks a match.
			name:   "leading whitespace still matches after strip",
			stdout: "  \tEnabled: true\n",
			want:   wantOf("enabled", true),
		},
		{
			// U+200B is not Python whitespace: it survives strip and
			// keeps the line from matching at column zero.
			name:   "non-whitespace prefix garbage blocks the match",
			stdout: "\u200benabled: true\nhost vnic: vmk0\n",
			want:   wantOf("host_vnic", "vmk0"),
		},
	}
	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			got := mustParse(t, map[string]any{"stdout": tc.stdout})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestFormatCoredumpSubstringTrue(t *testing.T) {
	// The pinned test is the SUBSTRING test "true" in parts[1] on the
	// UNSTRIPPED second field — "trueish" and "nottrue" both enable,
	// and parsing CONTINUES afterwards.
	vectors := []string{
		"enabled: true\n",
		"Enabled: True\n",
		"enabled:true\n",
		"ENABLED:TRUEISH\n",  // substring truth
		"enabled: nottrue\n", // substring truth
		"enabled: trueish extra\n",
		"enabled: xtruex\n",
		"enabled: TRUE\n", // lowercased before the test
	}
	for _, stdout := range vectors {
		got := mustParse(t, map[string]any{"stdout": stdout})
		if got["enabled"] != true {
			t.Fatalf("substring truth: %q must store enabled=true, got %#v", stdout, got["enabled"])
		}
	}
	// After a true store the loop continues with later lines.
	stdout := "enabled: trueish\nhost vnic: VMK0\n"
	got := mustParse(t, map[string]any{"stdout": stdout})
	want := wantOf("enabled", true, "host_vnic", "vmk0")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("continue after true: got %#v, want %#v", got, want)
	}
}

func TestFormatCoredumpEarlyFalseTermination(t *testing.T) {
	vectors := []struct {
		name   string
		stdout string
		want   map[string]any
	}{
		{
			name:   "classic false",
			stdout: "Enabled: false\n",
			want:   wantOf("enabled", false),
		},
		{
			name:   "fields before the false are kept, everything after is dropped",
			stdout: "host vnic: vmk0\nenabled: false\nnetwork server ip: 1.2.3.4\nnetwork server port: 65000\n",
			want:   wantOf("host_vnic", "vmk0", "enabled", false),
		},
		{
			name:   "bare enabled: splits to an empty second field",
			stdout: "enabled:\n",
			want:   wantOf("enabled", false),
		},
		{
			name:   "adjacent colons also split to an empty second field",
			stdout: "enabled::\n",
			want:   wantOf("enabled", false),
		},
		{
			// parts[1] is exactly the text between the first two
			// colons: "false" — the trailing ":true" is never seen.
			name:   "second-field indexing: enabled:false:true stops",
			stdout: "enabled:false:true\n",
			want:   wantOf("enabled", false),
		},
		{
			name:   "second-field indexing: enabled:x:true is false (only parts[1] tested)",
			stdout: "enabled:x:true\n",
			want:   wantOf("enabled", false),
		},
		{
			// The break fires even though later lines would parse.
			name:   "break short-circuits thousands of remaining lines",
			stdout: "enabled: False\n" + strings.Repeat("host vnic: x\n", 5000),
			want:   wantOf("enabled", false),
		},
	}
	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			got := mustParse(t, map[string]any{"stdout": tc.stdout})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestFormatCoredumpDuplicateOverwrite(t *testing.T) {
	stdout := "host vnic: vmk0\n" +
		"network server ip: 10.0.0.1\n" +
		"host vnic: vmk1\n" +
		"network server ip: 10.0.0.2\n" +
		"enabled: true\n" +
		"network server port: 1\n" +
		"network server port: 2\n"
	got := mustParse(t, map[string]any{"stdout": stdout})
	want := wantOf(
		"host_vnic", "vmk1", // last write wins
		"ip", "10.0.0.2",
		"enabled", true,
		"port", "2",
	)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("duplicate overwrite: got %#v, want %#v", got, want)
	}
}

func TestFormatCoredumpUnknownLabelsIgnored(t *testing.T) {
	stdout := "Coredump Kernel Info:\n" +
		"random line with colons: a: b\n" +
		"\n" +
		"   \n" +
		"enabled\n" + // missing colon: not the prefix
		"enabledx: true\n" + // not the prefix
		"host vnic\n" + // missing colon
		"network server ipx: 1.2.3.4\n" +
		"network server port\n" +
		"network server ports: 1\n" +
		"zzz: zzz\n"
	got := mustParse(t, map[string]any{"stdout": stdout})
	if len(got) != 0 {
		t.Fatalf("unknown labels must all be ignored, got %#v", got)
	}
}

func TestFormatCoredumpColonIndexQuirks(t *testing.T) {
	vectors := []struct {
		name   string
		stdout string
		want   map[string]any
	}{
		{
			// The pinned split(":")[1] is exactly the text between the
			// first and second colon: an IPv6 address is truncated at
			// its first inner colon. Never normalized.
			name:   "IPv6 truncated at the first inner colon",
			stdout: "network server ip: fe80::1\n",
			want:   wantOf("ip", "fe80"),
		},
		{
			name:   "IPv6 link-local truncated after the prefix",
			stdout: "network server ip: 2001:db8::1:2:3\n",
			want:   wantOf("ip", "2001"),
		},
		{
			name:   "adjacent colons store an empty value",
			stdout: "network server ip::\n",
			want:   wantOf("ip", ""),
		},
		{
			name:   "vnic truncated at the second colon",
			stdout: "host vnic: vmk0:extra\n",
			want:   wantOf("host_vnic", "vmk0"),
		},
		{
			name:   "port truncated at the second colon",
			stdout: "network server port: 65000:x\n",
			want:   wantOf("port", "65000"),
		},
		{
			name:   "bare label stores an empty string",
			stdout: "host vnic:\n",
			want:   wantOf("host_vnic", ""),
		},
		{
			name:   "colon right after the prefix stores an empty string",
			stdout: "host vnic::x\n",
			want:   wantOf("host_vnic", ""),
		},
		{
			name:   "value with interior spaces keeps them after strip",
			stdout: "host vnic: vmk0 kernel\n",
			want:   wantOf("host_vnic", "vmk0 kernel"),
		},
	}
	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			got := mustParse(t, map[string]any{"stdout": tc.stdout})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestFormatCoredumpEmptyOutput(t *testing.T) {
	for _, stdout := range []string{"", "\n", "\r\n", "\r", "   ", "\n\n\n", "\v\f", "\u0085", "\u2028\u2029"} {
		got, err := formatCoredumpStdout(map[string]any{"stdout": stdout})
		if err != nil {
			t.Fatalf("empty output %q: unexpected error %v", stdout, err)
		}
		if got == nil {
			t.Fatalf("empty output %q must return an allocated empty map, got nil", stdout)
		}
		if len(got) != 0 {
			t.Fatalf("empty output %q must return an empty map, got %#v", stdout, got)
		}
	}
}

func TestFormatCoredumpTypeErrors(t *testing.T) {
	nonStrings := []any{
		nil,
		5,
		3.14,
		true,
		[]byte("Enabled: true"),
		[]any{"Enabled: true"},
		map[string]any{"stdout": "Enabled: true"},
		struct{}{},
	}
	for _, v := range nonStrings {
		cmdRet := map[string]any{}
		if v != nil {
			cmdRet["stdout"] = v
		}
		got, err := formatCoredumpStdout(cmdRet)
		if !errors.Is(err, errCoredumpStdoutType) {
			t.Fatalf("non-string stdout %#v: want errCoredumpStdoutType, got %v", v, err)
		}
		if got != nil {
			t.Fatalf("non-string stdout %#v: want nil result, got %#v", v, got)
		}
	}
	// A nil cmdRet map reads like a missing key and must not panic.
	got, err := formatCoredumpStdout(nil)
	if !errors.Is(err, errCoredumpStdoutType) || got != nil {
		t.Fatalf("nil cmdRet: want (nil, errCoredumpStdoutType), got (%#v, %v)", got, err)
	}
}

func TestFormatCoredumpInvalidUTF8(t *testing.T) {
	vectors := []string{
		"enabled: tru\xff",
		"\xc3\x28",
		"\xff\xfe",
		"host vnic: vmk0\xed\xa0\x80",
	}
	for _, stdout := range vectors {
		got, err := formatCoredumpStdout(map[string]any{"stdout": stdout})
		if !errors.Is(err, errCoredumpStdoutUTF8) {
			t.Fatalf("invalid UTF-8 %q: want errCoredumpStdoutUTF8, got %v", stdout, err)
		}
		if got != nil {
			t.Fatalf("invalid UTF-8 %q: want nil result, got %#v", stdout, got)
		}
	}
	// Order pin: an oversized AND invalid input answers the size error
	// (the size budget runs before UTF-8 validation).
	oversizeInvalid := strings.Repeat("a\x00", 40000) + "\xff" // 80001 bytes
	got, err := formatCoredumpStdout(map[string]any{"stdout": oversizeInvalid})
	if !errors.Is(err, errCoredumpStdoutSize) {
		t.Fatalf("oversize+invalid: want errCoredumpStdoutSize (size budget first), got %v", err)
	}
	if got != nil {
		t.Fatalf("oversize+invalid: want nil result, got %#v", got)
	}
}

func TestFormatCoredumpAllLineSeparators(t *testing.T) {
	// Every Python str.splitlines() boundary is exactly ONE boundary in
	// this parser: both fields must survive across every separator.
	separators := []struct {
		name string
		sep  string
	}{
		{"LF", "\n"},
		{"CRLF (one boundary)", "\r\n"},
		{"CR", "\r"},
		{"VT", "\v"},
		{"FF", "\f"},
		{"U+001C", "\x1c"},
		{"U+001D", "\x1d"},
		{"U+001E", "\x1e"},
		{"U+0085", "\u0085"},
		{"U+2028", "\u2028"},
		{"U+2029", "\u2029"},
	}
	for _, sep := range separators {
		t.Run(sep.name, func(t *testing.T) {
			stdout := "enabled: true" + sep.sep + "host vnic: VMK0" + sep.sep
			got := mustParse(t, map[string]any{"stdout": stdout})
			want := wantOf("enabled", true, "host_vnic", "vmk0")
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("separator %q: got %#v, want %#v", sep.name, got, want)
			}
		})
	}
	// \r\n is ONE boundary: "host vnic: a\r\nx" is two lines; a
	// stray \r inside a value terminates the line there.
	got := mustParse(t, map[string]any{"stdout": "host vnic: a\rb vnic: b"})
	want := wantOf("host_vnic", "a")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CR boundary: got %#v, want %#v", got, want)
	}
	// Trailing boundaries yield no trailing empty line, and \r\r is two
	// boundaries (two empty lines, both ignored).
	got = mustParse(t, map[string]any{"stdout": "host vnic: a\r\r"})
	want = wantOf("host_vnic", "a")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CR CR boundaries: got %#v, want %#v", got, want)
	}
}

func TestFormatCoredumpLimits(t *testing.T) {
	t.Run("input bytes: 64 KiB boundary", func(t *testing.T) {
		exact := strings.Repeat("x", 64*1024) // one benign over-budget-sized line
		got, err := formatCoredumpStdout(map[string]any{"stdout": exact})
		if err != nil {
			t.Fatalf("exactly 65536 bytes must parse, got error %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("benign filler must ignore, got %#v", got)
		}
		oversize := strings.Repeat("x", 64*1024+1)
		got, err = formatCoredumpStdout(map[string]any{"stdout": oversize})
		if !errors.Is(err, errCoredumpStdoutSize) {
			t.Fatalf("65537 bytes must reject with errCoredumpStdoutSize, got %v", err)
		}
		if got != nil {
			t.Fatalf("oversize input must return nil result, got %#v", got)
		}
	})

	t.Run("lines: 1024 boundary", func(t *testing.T) {
		exact := strings.Repeat("x\n", 1024)
		got, err := formatCoredumpStdout(map[string]any{"stdout": exact})
		if err != nil {
			t.Fatalf("exactly 1024 lines must parse, got error %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("junk lines must be ignored, got %#v", got)
		}
		// 1025 boundaries, with and without a final unterminated line.
		for name, over := range map[string]string{
			"terminated":   strings.Repeat("x\n", 1025),
			"unterminated": strings.Repeat("x\n", 1024) + "y",
		} {
			got, err := formatCoredumpStdout(map[string]any{"stdout": over})
			if !errors.Is(err, errCoredumpLineLimit) {
				t.Fatalf("%s: 1025 lines must reject with errCoredumpLineLimit, got %v", name, err)
			}
			if got != nil {
				t.Fatalf("%s: over-budget lines must return nil result, got %#v", name, got)
			}
		}
		// Multi-byte boundaries count individually toward the same cap.
		over := strings.Repeat("x\u2028", 1025)
		if got, err = formatCoredumpStdout(map[string]any{"stdout": over}); !errors.Is(err, errCoredumpLineLimit) {
			t.Fatalf("1025 U+2028 lines must reject with errCoredumpLineLimit, got %v", err)
		}
	})

	t.Run("field value: 4096 boundary", func(t *testing.T) {
		exact := "host vnic: " + strings.Repeat("a", 4096) + "\n"
		got, err := formatCoredumpStdout(map[string]any{"stdout": exact})
		if err != nil {
			t.Fatalf("exactly 4096-byte value must parse, got error %v", err)
		}
		if got["host_vnic"] != strings.Repeat("a", 4096) {
			t.Fatalf("4096-byte value must be retained, got %d bytes", len(got["host_vnic"].(string)))
		}
		over := "network server ip: " + strings.Repeat("a", 4097) + "\n"
		got, err = formatCoredumpStdout(map[string]any{"stdout": over})
		if !errors.Is(err, errCoredumpFieldValue) {
			t.Fatalf("4097-byte ip value must reject with errCoredumpFieldValue, got %v", err)
		}
		if got != nil {
			t.Fatalf("over-budget value must return nil result, got %#v", got)
		}
		overPort := "network server port: " + strings.Repeat("a", 4097) + "\n"
		if got, err = formatCoredumpStdout(map[string]any{"stdout": overPort}); !errors.Is(err, errCoredumpFieldValue) {
			t.Fatalf("4097-byte port value must reject with errCoredumpFieldValue, got %v", err)
		}
		// A huge UNSTRIPPED field whose retained value is short parses
		// (the cap applies to the retained value).
		padded := "host vnic: " + strings.Repeat(" ", 60000) + "vmk0\n"
		got, err = formatCoredumpStdout(map[string]any{"stdout": padded})
		if err != nil {
			t.Fatalf("padded value within input budget must parse, got error %v", err)
		}
		if got["host_vnic"] != "vmk0" {
			t.Fatalf("padded value must strip to vmk0, got %#v", got["host_vnic"])
		}
	})

	t.Run("retained fields: at most four", func(t *testing.T) {
		if coredumpMaxFields != 4 {
			t.Fatalf("coredumpMaxFields must stay 4 (the fixed label set), got %d", coredumpMaxFields)
		}
		full := "enabled: true\nhost vnic: vmk0\nnetwork server ip: 1.2.3.4\nnetwork server port: 65000\n"
		got := mustParse(t, map[string]any{"stdout": full})
		if len(got) != 4 {
			t.Fatalf("four recognized labels must retain four fields, got %#v", got)
		}
		// The count guard is unreachable through the fixed label set;
		// its sentinel text is pinned here as a regression check for
		// the fail-closed branch.
		if errCoredumpFieldCount.Error() != "vsphere: coredump result exceeds the 4 field limit" {
			t.Fatalf("errCoredumpFieldCount sentinel drifted: %v", errCoredumpFieldCount)
		}
	})
}

func TestFormatCoredumpErrorsAreValueFree(t *testing.T) {
	const marker = "MARKERZQ-secret-vector"
	paths := []struct {
		name   string
		cmdRet map[string]any
		want   error
	}{
		{
			name:   "type",
			cmdRet: map[string]any{"stdout": []byte(marker)},
			want:   errCoredumpStdoutType,
		},
		{
			name:   "size",
			cmdRet: map[string]any{"stdout": marker + strings.Repeat("x", 70000)},
			want:   errCoredumpStdoutSize,
		},
		{
			name:   "utf8",
			cmdRet: map[string]any{"stdout": "host vnic: " + marker + "\xff\n"},
			want:   errCoredumpStdoutUTF8,
		},
		{
			name:   "lines",
			cmdRet: map[string]any{"stdout": marker + "\n" + strings.Repeat("x\n", 1025)},
			want:   errCoredumpLineLimit,
		},
		{
			name:   "field value",
			cmdRet: map[string]any{"stdout": "host vnic: " + marker + strings.Repeat("a", 5000) + "\n"},
			want:   errCoredumpFieldValue,
		},
	}
	for _, tc := range paths {
		t.Run(tc.name, func(t *testing.T) {
			got, err := formatCoredumpStdout(tc.cmdRet)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want sentinel %v, got %v", tc.want, err)
			}
			if got != nil {
				t.Fatalf("want nil result, got %#v", got)
			}
			// Value-free: no vector bytes in the error text.
			if strings.Contains(err.Error(), "MARKERZQ") || strings.Contains(err.Error(), "vmk0") {
				t.Fatalf("error must be value-free, got %q", err.Error())
			}
			// Fixed identity: exact sentinel text, no wrapping.
			if err.Error() != tc.want.Error() {
				t.Fatalf("error text must be the fixed sentinel text, got %q", err.Error())
			}
		})
	}
	// All sentinels are pairwise distinct fixed values.
	sentinels := []error{errCoredumpStdoutType, errCoredumpStdoutSize, errCoredumpStdoutUTF8, errCoredumpLineLimit, errCoredumpFieldValue, errCoredumpFieldCount}
	seen := map[string]bool{}
	for _, s := range sentinels {
		if seen[s.Error()] {
			t.Fatalf("duplicate sentinel text %q", s.Error())
		}
		seen[s.Error()] = true
	}
}

func TestFormatCoredumpIgnoresOtherCmdRetMembers(t *testing.T) {
	cmdRet := map[string]any{
		"stdout":  "enabled: true\nhost vnic: vmk0\n",
		"stderr":  "enabled: false\nnetwork server ip: 9.9.9.9\n",
		"retcode": 1,
		"pid":     1234,
		"cmd":     []string{"esxcli"},
	}
	got := mustParse(t, cmdRet)
	want := wantOf("enabled", true, "host_vnic", "vmk0")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("only the stdout member is parsed: got %#v, want %#v", got, want)
	}
}

func TestFormatCoredumpU0130SpecialCasing(t *testing.T) {
	// Python lowercases U+0130 to "i"+U+0307 unconditionally; the port
	// matches (this is the unconditional SpecialCasing entry).
	got := mustParse(t, map[string]any{"stdout": "host vnic: \u013030\n"})
	want := wantOf("host_vnic", "i\u030730")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("U+0130 lowercasing: got %#v, want %#v", got, want)
	}
}

func TestFormatCoredumpPythonStripLowerOrder(t *testing.T) {
	// strip → lower order with non-ASCII Python whitespace (NBSP and
	// U+3000 are whitespace but never line boundaries) and case combined.
	got := mustParse(t, map[string]any{"stdout": "\u00a0\u3000 HOST VNIC:\t\u013030 \u00a0"})
	want := wantOf("host_vnic", "i\u030730")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("strip+lower: got %#v, want %#v", got, want)
	}
}

// ---------------------------------------------------------------------------
// R10.4b: _format_firewall_stdout (pinned lines 7685–7702)

// mustParseFirewall is a test helper: parse or fail the test.
func mustParseFirewall(t *testing.T, cmdRet map[string]any) map[string]any {
	t.Helper()
	ret, err := formatFirewallStdout(cmdRet)
	if err != nil {
		t.Fatalf("formatFirewallStdout(%q) returned unexpected error: %v", cmdRet["stdout"], err)
	}
	return ret
}

// wantFirewall builds the expected pinned ret_dict shape: the hardcoded
// success flag plus the ruleset map.
func wantFirewall(rulesets map[string]any) map[string]any {
	return map[string]any{"success": true, "rulesets": rulesets}
}

// firewallRows builds n rows of n distinct rule names, each two tokens.
func firewallRows(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("r")
		b.WriteString(strconv.Itoa(i))
		b.WriteString(" b\n")
	}
	return b.String()
}

func TestFormatFirewallNormalRulesets(t *testing.T) {
	// esxcli-shaped recorded synthetic stdout: the "Name ..." header and
	// the dashes row are skipped by the raw prefix checks, every data
	// row is split and stored.
	stdout := "Name            Enabled\n" +
		"---------------  -------\n" +
		"allowFwRule      True\n" +
		"sshServer        1\n"
	got := mustParseFirewall(t, map[string]any{"stdout": stdout})
	want := wantFirewall(wantOf(
		"allowFwRule", true,
		"sshServer", true,
	))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normal rulesets: got %#v, want %#v", got, want)
	}
	// Pinned Go types: success is a Go bool true and every ruleset value
	// is a Go bool true.
	if v, ok := got["success"].(bool); !ok || !v {
		t.Fatalf("success must be a Go bool true, got %#v", got["success"])
	}
	rulesets, ok := got["rulesets"].(map[string]any)
	if !ok {
		t.Fatalf("rulesets must be a Go map, got %#v", got["rulesets"])
	}
	for name := range want["rulesets"].(map[string]any) {
		if v, ok := rulesets[name].(bool); !ok || !v {
			t.Fatalf("rulesets[%q] must be a Go bool true, got %#v", name, rulesets[name])
		}
	}
}

func TestFormatFirewallHeaderPrefixSkips(t *testing.T) {
	vectors := []struct {
		name   string
		stdout string
		want   map[string]any
	}{
		{
			name:   "bare Name header skipped",
			stdout: "Name\n",
			want:   wantFirewall(map[string]any{}),
		},
		{
			name:   "Name header with columns skipped",
			stdout: "Name            Enabled\n",
			want:   wantFirewall(map[string]any{}),
		},
		{
			// startswith("Name") is a raw prefix test: longer words that
			// merely begin with Name are skipped too.
			name:   "Names is a Name prefix",
			stdout: "Names: x\na b\n",
			want:   wantFirewall(wantOf("a", true)),
		},
		{
			name:   "bare dashes row skipped",
			stdout: "---\n",
			want:   wantFirewall(map[string]any{}),
		},
		{
			name:   "dashes row with tail skipped",
			stdout: "---------------  -------\na b\n",
			want:   wantFirewall(wantOf("a", true)),
		},
		{
			// The skip test is the raw three-dash prefix: two dashes are
			// ordinary data.
			name:   "two dashes are data, not a skip",
			stdout: "-- x\n",
			want:   wantFirewall(wantOf("--", true)),
		},
	}
	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			got := mustParseFirewall(t, map[string]any{"stdout": tc.stdout})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestFormatFirewallRawPrefixNegativeControl(t *testing.T) {
	// Negative control: the pinned helper runs NO strip() and NO lower()
	// before the "Name"/"---" startswith checks (the coredump helper
	// strips and lowercases; the firewall helper does not). A
	// normalized/corrected parser that stripped or lowercased first
	// would differ on every vector here.
	t.Run("leading space: not skipped, stored as data", func(t *testing.T) {
		// "  Name: 1" does not start with "Name" at column zero, so it
		// falls through to line.split() and stores the exact key "Name:".
		// A strip-first parser would skip the row and answer empty.
		got := mustParseFirewall(t, map[string]any{"stdout": "  Name: 1\n"})
		want := wantFirewall(wantOf("Name:", true))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("leading-space Name row must be data: got %#v, want %#v", got, want)
		}
	})
	t.Run("leading space: single-token row fails closed", func(t *testing.T) {
		// "  Name" is a single-token row after the split: the pinned
		// IndexError position answers the malformed sentinel, while a
		// strip-first parser would have skipped it as a header.
		got, err := formatFirewallStdout(map[string]any{"stdout": "  Name\n"})
		if !errors.Is(err, errFirewallMalformedLine) {
			t.Fatalf("leading-space single token: want errFirewallMalformedLine, got %v", err)
		}
		if got != nil {
			t.Fatalf("leading-space single token: want nil result, got %#v", got)
		}
	})
	t.Run("case: NAME is data, never a skip", func(t *testing.T) {
		// A lowercasing parser (like the coredump port) would read
		// "NAME" as the header; the faithful parser stores it as data.
		got := mustParseFirewall(t, map[string]any{"stdout": "NAME x\n"})
		want := wantFirewall(wantOf("NAME", true))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("uppercase NAME row: got %#v, want %#v", got, want)
		}
	})
	t.Run("false token: truthy, a corrected bool parser would differ", func(t *testing.T) {
		// bool("false") is Python truthiness of a nonempty string —
		// always true. A "corrected" parser mapping the token "false"
		// (or any falsy-looking text) to Go false would differ.
		got := mustParseFirewall(t, map[string]any{"stdout": " fw  false\n"})
		want := wantFirewall(wantOf("fw", true))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("false token truthiness: got %#v, want %#v", got, want)
		}
		if v, ok := got["rulesets"].(map[string]any)["fw"].(bool); !ok || !v {
			t.Fatalf("the token \"false\" must store Go bool true, got %#v", got["rulesets"])
		}
	})
}

func TestFormatFirewallTokenTruthy(t *testing.T) {
	// Any nonempty string is Python-truthy; split() can never yield an
	// empty token, so every well-formed row stores true.
	for _, stdout := range []string{
		"r false\n",
		"r FALSE\n",
		"r 0\n",
		"r no\n",
		"r None\n",
		"r off\n",
		"r -\n",
		"r F\n",
	} {
		got := mustParseFirewall(t, map[string]any{"stdout": stdout})
		rulesets, ok := got["rulesets"].(map[string]any)
		if !ok || len(rulesets) != 1 {
			t.Fatalf("%q: want exactly one ruleset, got %#v", stdout, got["rulesets"])
		}
		for name, value := range rulesets {
			if v, isBool := value.(bool); !isBool || name != "r" || !v {
				t.Fatalf("%q: want rulesets[r]=true (Go bool), got rulesets[%q]=%#v", stdout, name, value)
			}
		}
	}
}

func TestFormatFirewallDuplicateOverwrite(t *testing.T) {
	// Duplicate names overwrite in encounter order (Python dict
	// assignment) while keeping plain map semantics: the map never
	// grows, and every value is the same Python-true.
	stdout := "a true\nb true\na false\nb 0\n"
	got := mustParseFirewall(t, map[string]any{"stdout": stdout})
	want := wantFirewall(wantOf("a", true, "b", true))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("duplicate overwrite: got %#v, want %#v", got, want)
	}
	rulesets := got["rulesets"].(map[string]any)
	if len(rulesets) != 2 {
		t.Fatalf("overwrites must not grow the map, got %#v", rulesets)
	}
}

func TestFormatFirewallUnknownNamesAndTailTokens(t *testing.T) {
	// Unknown headings/rules are data: any token[0] is stored, and only
	// tokens [0] and [1] are consumed — a longer row's tail is discarded
	// exactly like the pinned indexing.
	stdout := "weird heading with many tokens\n" +
		"x y\n" +
		"--- ignored row\n" +
		"Name Header Row\n"
	got := mustParseFirewall(t, map[string]any{"stdout": stdout})
	want := wantFirewall(wantOf("weird", true, "x", true))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unknown names and tails: got %#v, want %#v", got, want)
	}
}

func TestFormatFirewallPythonWhitespaceSplits(t *testing.T) {
	vectors := []struct {
		name   string
		stdout string
		want   map[string]any
	}{
		{
			name:   "tabs separate fields",
			stdout: "allowFwRule\tTrue\n",
			want:   wantFirewall(wantOf("allowFwRule", true)),
		},
		{
			// U+001F is Python split() whitespace but never a line
			// boundary: one line, two tokens.
			name:   "U+001F is split whitespace, not a boundary",
			stdout: "a\x1fb\n",
			want:   wantFirewall(wantOf("a", true)),
		},
		{
			// U+001C is BOTH a splitlines boundary and split whitespace:
			// two lines, each well-formed.
			name:   "U+001C is a line boundary",
			stdout: "a b\x1cc d\n",
			want:   wantFirewall(wantOf("a", true, "c", true)),
		},
		{
			name:   "CRLF is one boundary",
			stdout: "a b\r\nc d\r\n",
			want:   wantFirewall(wantOf("a", true, "c", true)),
		},
		{
			name:   "U+2028 is a boundary",
			stdout: "a b\u2028c d",
			want:   wantFirewall(wantOf("a", true, "c", true)),
		},
		{
			// NBSP and U+3000 are Python whitespace separators; leading
			// and trailing whitespace is dropped.
			name:   "NBSP and U+3000 separate and collapse",
			stdout: " a\u00a0\u3000b\u00a0 c ",
			want:   wantFirewall(wantOf("a", true)),
		},
		{
			name:   "mixed whitespace runs collapse",
			stdout: "vmk0 \t allowFwRule\n",
			want:   wantFirewall(wantOf("vmk0", true)),
		},
	}
	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			got := mustParseFirewall(t, map[string]any{"stdout": tc.stdout})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestFormatFirewallUnicodeNamesExact(t *testing.T) {
	// Names are stored EXACTLY: this helper runs no lower() (unlike the
	// coredump port), so case, Cyrillic, and U+0130 all survive
	// verbatim.
	stdout := "Правило true\nFW\u0130LE x\n"
	got := mustParseFirewall(t, map[string]any{"stdout": stdout})
	want := wantFirewall(wantOf("Правило", true, "FW\u0130LE", true))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unicode names: got %#v, want %#v", got, want)
	}
}

func TestFormatFirewallEmptyOutput(t *testing.T) {
	// Empty stdout iterates zero lines: the pinned empty dict with an
	// allocated (non-nil) ruleset map.
	got, err := formatFirewallStdout(map[string]any{"stdout": ""})
	if err != nil {
		t.Fatalf("empty stdout: unexpected error %v", err)
	}
	want := wantFirewall(map[string]any{})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("empty stdout: got %#v, want %#v", got, want)
	}
	rulesets, ok := got["rulesets"].(map[string]any)
	if !ok || rulesets == nil {
		t.Fatalf("empty stdout must return an allocated ruleset map, got %#v", got["rulesets"])
	}
}

func TestFormatFirewallMalformedRows(t *testing.T) {
	// The pinned IndexError positions: a whitespace-only row splits to
	// zero tokens (ruleset_status[0]) and a single-token row to one
	// token (ruleset_status[1]). Both answer the fixed malformed-row
	// sentinel with a nil result — never a panic and never a partial
	// map.
	vectors := []string{
		"\n",       // empty line
		"   \n",    // whitespace-only line
		"\v\f",     // only line boundaries: two empty lines
		"one\n",    // single token
		"a \n",     // single token with trailing whitespace
		"\ta\t\n",  // single token with surrounding tabs
		"a b\n \n", // valid row followed by a whitespace-only row
		"a b\n\n",  // valid row followed by an empty line
		"good row\nbad\n",
	}
	var got map[string]any
	var err error
	for _, stdout := range vectors {
		got, err = formatFirewallStdout(map[string]any{"stdout": stdout})
		if !errors.Is(err, errFirewallMalformedLine) {
			t.Fatalf("malformed row %q: want errFirewallMalformedLine, got %v", stdout, err)
		}
		if got != nil {
			t.Fatalf("malformed row %q: want nil result, got %#v", stdout, got)
		}
	}
	// A valid row BEFORE a malformed row never escapes: the result is
	// only returned on the success path.
	got, err = formatFirewallStdout(map[string]any{"stdout": "ok row\nbad\nworse\n"})
	if !errors.Is(err, errFirewallMalformedLine) || got != nil {
		t.Fatalf("no partial map: want (nil, errFirewallMalformedLine), got (%#v, %v)", got, err)
	}
}

func TestFormatFirewallTypeErrors(t *testing.T) {
	nonStrings := []any{
		nil,
		5,
		3.14,
		true,
		[]byte("a true"),
		[]any{"a true"},
		map[string]any{"stdout": "a true"},
		struct{}{},
	}
	for _, v := range nonStrings {
		cmdRet := map[string]any{}
		if v != nil {
			cmdRet["stdout"] = v
		}
		got, err := formatFirewallStdout(cmdRet)
		if !errors.Is(err, errFirewallStdoutType) {
			t.Fatalf("non-string stdout %#v: want errFirewallStdoutType, got %v", v, err)
		}
		if got != nil {
			t.Fatalf("non-string stdout %#v: want nil result, got %#v", v, got)
		}
	}
	// A nil cmdRet map reads like a missing key and must not panic.
	got, err := formatFirewallStdout(nil)
	if !errors.Is(err, errFirewallStdoutType) || got != nil {
		t.Fatalf("nil cmdRet: want (nil, errFirewallStdoutType), got (%#v, %v)", got, err)
	}
}

func TestFormatFirewallInvalidUTF8(t *testing.T) {
	vectors := []string{
		"a tru\xff",
		"\xc3\x28",
		"\xff\xfe",
		"allowFwRule\xed\xa0\x80 x",
	}
	for _, stdout := range vectors {
		got, err := formatFirewallStdout(map[string]any{"stdout": stdout})
		if !errors.Is(err, errFirewallStdoutUTF8) {
			t.Fatalf("invalid UTF-8 %q: want errFirewallStdoutUTF8, got %v", stdout, err)
		}
		if got != nil {
			t.Fatalf("invalid UTF-8 %q: want nil result, got %#v", stdout, got)
		}
	}
	// Order pin: an oversized AND invalid input answers the size error
	// (the size budget runs before UTF-8 validation).
	oversizeInvalid := strings.Repeat("a\x00", 40000) + "\xff" // 80001 bytes
	got, err := formatFirewallStdout(map[string]any{"stdout": oversizeInvalid})
	if !errors.Is(err, errFirewallStdoutSize) {
		t.Fatalf("oversize+invalid: want errFirewallStdoutSize (size budget first), got %v", err)
	}
	if got != nil {
		t.Fatalf("oversize+invalid: want nil result, got %#v", got)
	}
}

func TestFormatFirewallLimits(t *testing.T) {
	t.Run("input bytes: 64 KiB boundary", func(t *testing.T) {
		// A skipped header row is the benign filler: it parses without
		// storing anything.
		exact := "Name " + strings.Repeat("x", 65531) // exactly 65536 bytes, one skipped row
		if len(exact) != 64*1024 {
			t.Fatalf("vector must be exactly 65536 bytes, got %d", len(exact))
		}
		got, err := formatFirewallStdout(map[string]any{"stdout": exact})
		if err != nil {
			t.Fatalf("exactly 65536 bytes must parse, got error %v", err)
		}
		if !reflect.DeepEqual(got, wantFirewall(map[string]any{})) {
			t.Fatalf("skipped filler must answer the empty dict, got %#v", got)
		}
		oversize := exact + "y"
		got, err = formatFirewallStdout(map[string]any{"stdout": oversize})
		if !errors.Is(err, errFirewallStdoutSize) {
			t.Fatalf("65537 bytes must reject with errFirewallStdoutSize, got %v", err)
		}
		if got != nil {
			t.Fatalf("oversize input must return nil result, got %#v", got)
		}
	})

	t.Run("lines: 1024 boundary", func(t *testing.T) {
		// Duplicate rows keep the ruleset map at one entry: the line
		// budget is reachable without the ruleset budget.
		exact := strings.Repeat("a b\n", 1024)
		got, err := formatFirewallStdout(map[string]any{"stdout": exact})
		if err != nil {
			t.Fatalf("exactly 1024 lines must parse, got error %v", err)
		}
		if !reflect.DeepEqual(got, wantFirewall(wantOf("a", true))) {
			t.Fatalf("1024 duplicate rows must keep one ruleset, got %#v", got)
		}
		// 1025 boundaries, with and without a final unterminated line.
		for name, over := range map[string]string{
			"terminated":   strings.Repeat("a b\n", 1025),
			"unterminated": strings.Repeat("a b\n", 1024) + "c d",
		} {
			got, err := formatFirewallStdout(map[string]any{"stdout": over})
			if !errors.Is(err, errFirewallLineLimit) {
				t.Fatalf("%s: 1025 lines must reject with errFirewallLineLimit, got %v", name, err)
			}
			if got != nil {
				t.Fatalf("%s: over-budget lines must return nil result, got %#v", name, got)
			}
		}
		// Multi-byte boundaries count individually toward the same cap.
		over := strings.Repeat("a b\u2028", 1025)
		if got, err = formatFirewallStdout(map[string]any{"stdout": over}); !errors.Is(err, errFirewallLineLimit) {
			t.Fatalf("1025 U+2028 lines must reject with errFirewallLineLimit, got %v", err)
		}
		// Order pin: the line budget is enforced BEFORE the row is
		// parsed, so a malformed 1025th row answers the LINE sentinel.
		overMalformed := strings.Repeat("a b\n", 1024) + "lonetoken"
		if got, err = formatFirewallStdout(map[string]any{"stdout": overMalformed}); !errors.Is(err, errFirewallLineLimit) {
			t.Fatalf("malformed 1025th row must answer the line limit, got %v", err)
		}
		// ...while a malformed 1024th row (still within budget) answers
		// the malformed sentinel.
		atLimit := strings.Repeat("a b\n", 1023) + "lonetoken\n"
		if got, err = formatFirewallStdout(map[string]any{"stdout": atLimit}); !errors.Is(err, errFirewallMalformedLine) {
			t.Fatalf("malformed 1024th row must answer the malformed sentinel, got %v", err)
		}
	})

	t.Run("tokens: 4096 boundary", func(t *testing.T) {
		exactName := strings.Repeat("n", 4096) + " b\n"
		got, err := formatFirewallStdout(map[string]any{"stdout": exactName})
		if err != nil {
			t.Fatalf("exactly 4096-byte name must parse, got error %v", err)
		}
		if got["rulesets"].(map[string]any)[strings.Repeat("n", 4096)] != true {
			t.Fatalf("4096-byte name must be retained, got %#v", got["rulesets"])
		}
		overName := strings.Repeat("n", 4097) + " b\n"
		got, err = formatFirewallStdout(map[string]any{"stdout": overName})
		if !errors.Is(err, errFirewallTokenLimit) {
			t.Fatalf("4097-byte name must reject with errFirewallTokenLimit, got %v", err)
		}
		if got != nil {
			t.Fatalf("over-budget name must return nil result, got %#v", got)
		}
		exactValue := "a " + strings.Repeat("v", 4096) + "\n"
		if got, err = formatFirewallStdout(map[string]any{"stdout": exactValue}); err != nil {
			t.Fatalf("exactly 4096-byte value must parse, got error %v", err)
		}
		overValue := "a " + strings.Repeat("v", 4097) + "\n"
		if got, err = formatFirewallStdout(map[string]any{"stdout": overValue}); !errors.Is(err, errFirewallTokenLimit) {
			t.Fatalf("4097-byte value must reject with errFirewallTokenLimit, got %v", err)
		}
		// A discarded tail token is unbounded data: only the consumed
		// tokens [0] and [1] carry the cap.
		longTail := "a b " + strings.Repeat("t", 9000) + "\n"
		if got, err = formatFirewallStdout(map[string]any{"stdout": longTail}); err != nil {
			t.Fatalf("oversized discarded tail must parse, got error %v", err)
		}
		if !reflect.DeepEqual(got, wantFirewall(wantOf("a", true))) {
			t.Fatalf("oversized tail must be discarded, got %#v", got)
		}
	})

	t.Run("rulesets: 256 boundary", func(t *testing.T) {
		distinct := firewallRows
		exact := distinct(256)
		got, err := formatFirewallStdout(map[string]any{"stdout": exact})
		if err != nil {
			t.Fatalf("exactly 256 rulesets must parse, got error %v", err)
		}
		if len(got["rulesets"].(map[string]any)) != 256 {
			t.Fatalf("256 distinct names must retain 256 rulesets, got %d", len(got["rulesets"].(map[string]any)))
		}
		over := distinct(257)
		got, err = formatFirewallStdout(map[string]any{"stdout": over})
		if !errors.Is(err, errFirewallRulesetLimit) {
			t.Fatalf("257 distinct rulesets must reject with errFirewallRulesetLimit, got %v", err)
		}
		if got != nil {
			t.Fatalf("over-budget rulesets must return nil result, got %#v", got)
		}
		// A duplicate row over an existing name never grows the map: 257
		// rows but only 256 distinct names parse.
		dup := distinct(256) + "r0 again\n"
		got, err = formatFirewallStdout(map[string]any{"stdout": dup})
		if err != nil {
			t.Fatalf("257 rows with 256 distinct names must parse, got error %v", err)
		}
		if len(got["rulesets"].(map[string]any)) != 256 {
			t.Fatalf("duplicate row must not grow the map, got %d", len(got["rulesets"].(map[string]any)))
		}
	})
}

func TestFormatFirewallErrorsAreValueFree(t *testing.T) {
	const marker = "MARKERZQFW-secret-vector"
	paths := []struct {
		name   string
		cmdRet map[string]any
		want   error
	}{
		{
			name:   "type",
			cmdRet: map[string]any{"stdout": []byte(marker)},
			want:   errFirewallStdoutType,
		},
		{
			name:   "size",
			cmdRet: map[string]any{"stdout": marker + strings.Repeat("x", 70000)},
			want:   errFirewallStdoutSize,
		},
		{
			name:   "utf8",
			cmdRet: map[string]any{"stdout": "a b " + marker + "\xff\n"},
			want:   errFirewallStdoutUTF8,
		},
		{
			name:   "lines",
			cmdRet: map[string]any{"stdout": marker + " x\n" + strings.Repeat("a b\n", 1025)},
			want:   errFirewallLineLimit,
		},
		{
			name:   "token",
			cmdRet: map[string]any{"stdout": "a " + marker + strings.Repeat("v", 5000) + "\n"},
			want:   errFirewallTokenLimit,
		},
		{
			name:   "rulesets",
			cmdRet: map[string]any{"stdout": firewallRows(256) + "zz" + marker + " x\n"},
			want:   errFirewallRulesetLimit,
		},
		{
			name:   "malformed",
			cmdRet: map[string]any{"stdout": marker + "\n"},
			want:   errFirewallMalformedLine,
		},
	}
	for _, tc := range paths {
		t.Run(tc.name, func(t *testing.T) {
			got, err := formatFirewallStdout(tc.cmdRet)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want sentinel %v, got %v", tc.want, err)
			}
			if got != nil {
				t.Fatalf("want nil result, got %#v", got)
			}
			// Value-free: no vector bytes in the error text.
			if strings.Contains(err.Error(), "MARKERZQ") || strings.Contains(err.Error(), "allowFwRule") {
				t.Fatalf("error must be value-free, got %q", err.Error())
			}
			// Fixed identity: exact sentinel text, no wrapping.
			if err.Error() != tc.want.Error() {
				t.Fatalf("error text must be the fixed sentinel text, got %q", err.Error())
			}
		})
	}
	// All sentinels are pairwise distinct fixed values.
	sentinels := []error{
		errFirewallStdoutType,
		errFirewallStdoutSize,
		errFirewallStdoutUTF8,
		errFirewallLineLimit,
		errFirewallTokenLimit,
		errFirewallRulesetLimit,
		errFirewallMalformedLine,
	}
	seen := map[string]bool{}
	for _, s := range sentinels {
		if seen[s.Error()] {
			t.Fatalf("duplicate sentinel text %q", s.Error())
		}
		seen[s.Error()] = true
	}
}

func TestFormatFirewallIgnoresOtherCmdRetMembers(t *testing.T) {
	// Only the stdout member is parsed; success is the pinned hardcoded
	// True and is NOT derived from retcode.
	cmdRet := map[string]any{
		"stdout":  "a true\nb false\n",
		"stderr":  "c true\nd false\n",
		"retcode": 1,
		"pid":     1234,
		"cmd":     []string{"esxcli", "network", "firewall", "ruleset", "list"},
	}
	got := mustParseFirewall(t, cmdRet)
	want := wantFirewall(wantOf("a", true, "b", true))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("only the stdout member is parsed: got %#v, want %#v", got, want)
	}
	if v, ok := got["success"].(bool); !ok || !v {
		t.Fatalf("success must stay the hardcoded true regardless of retcode, got %#v", got["success"])
	}
}

func TestFormatFirewallResultShape(t *testing.T) {
	// The pinned ret_dict shape: exactly two top-level keys, and the
	// ruleset map is an allocated (non-nil) empty map even when every
	// row is skipped.
	got := mustParseFirewall(t, map[string]any{"stdout": "Name\n---\n"})
	if len(got) != 2 {
		t.Fatalf("ret_dict must have exactly the success and rulesets keys, got %#v", got)
	}
	if _, ok := got["success"]; !ok {
		t.Fatalf("ret_dict must carry the success key, got %#v", got)
	}
	rulesets, ok := got["rulesets"].(map[string]any)
	if !ok || rulesets == nil {
		t.Fatalf("rulesets must be an allocated map, got %#v", got["rulesets"])
	}
	if len(rulesets) != 0 {
		t.Fatalf("skipped rows must retain no rulesets, got %#v", rulesets)
	}
}

// ---------------------------------------------------------------------------
// R10.4c: _format_syslog_config (pinned lines 7704–7723)

// mustParseSyslog is a test helper: parse or fail the test.
func mustParseSyslog(t *testing.T, cmdRet map[string]any) map[string]any {
	t.Helper()
	ret, err := formatSyslogConfig(cmdRet)
	if err != nil {
		t.Fatalf("formatSyslogConfig(%q) returned unexpected error: %v", cmdRet["stdout"], err)
	}
	return ret
}

// syslogRows builds n rows with n distinct keys, each a simple
// "key: value" pair.
func syslogRows(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("k")
		b.WriteString(strconv.Itoa(i))
		b.WriteString(": v\n")
	}
	return b.String()
}

func TestFormatSyslogNonzeroMessage(t *testing.T) {
	// The pinned message path: retcode != 0 stores the RAW stdout
	// verbatim (never stripped) and never parses the lines — even rows
	// that would be malformed on the parsing path are ignored.
	raw := "  not: a: valid config row\n\nsingleword\n"
	got := mustParseSyslog(t, map[string]any{"retcode": 1, "stdout": raw})
	want := wantOf("success", false, "message", raw)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nonzero message: got %#v, want %#v", got, want)
	}
	if v, ok := got["success"].(bool); !ok || v {
		t.Fatalf("success must be a Go bool false, got %#v", got["success"])
	}
	if v, ok := got["message"].(string); !ok || v != raw {
		t.Fatalf("message must be the RAW stdout string verbatim, got %#v", got["message"])
	}
	if len(got) != 2 {
		t.Fatalf("message path ret_dict must be exactly success+message, got %#v", got)
	}
	// Any nonzero retcode takes the message path, negative included.
	for _, rc := range []int{-1, 2, 255} {
		got := mustParseSyslog(t, map[string]any{"retcode": rc, "stdout": raw})
		if got["success"] != false || got["message"] != raw {
			t.Fatalf("retcode %d: got %#v, want the message dict", rc, got)
		}
	}
}

func TestFormatSyslogTypeErrors(t *testing.T) {
	// The retcode must be exactly a Go int: the pinned code compares
	// it to 0; missing/nil/float64/string/bool/int64 all answer the
	// fixed value-free sentinel (a JSON round-trip float64 must NOT be
	// coerced into a retcode).
	badRetcodes := []any{
		nil,
		"0",
		0.0,
		1.5,
		int64(0),
		true,
		[]int{0},
		struct{}{},
	}
	for _, v := range badRetcodes {
		cmdRet := map[string]any{"stdout": "k: v\n"}
		if v != nil {
			cmdRet["retcode"] = v
		}
		got, err := formatSyslogConfig(cmdRet)
		if !errors.Is(err, errSyslogRetcodeType) {
			t.Fatalf("non-int retcode %#v: want errSyslogRetcodeType, got %v", v, err)
		}
		if got != nil {
			t.Fatalf("non-int retcode %#v: want nil result, got %#v", v, got)
		}
	}
	// The stdout must be a string on BOTH paths: a valid int retcode
	// (zero or nonzero) does not exempt it, since both pinned branches
	// read cmd_ret["stdout"].
	badStdouts := []any{
		nil,
		5,
		3.14,
		true,
		[]byte("k: v"),
		[]any{"k: v"},
		map[string]any{"k": "v"},
		struct{}{},
	}
	for _, rc := range []int{0, 1} {
		for _, v := range badStdouts {
			cmdRet := map[string]any{"retcode": rc}
			if v != nil {
				cmdRet["stdout"] = v
			}
			got, err := formatSyslogConfig(cmdRet)
			if !errors.Is(err, errSyslogStdoutType) {
				t.Fatalf("retcode %d non-string stdout %#v: want errSyslogStdoutType, got %v", rc, v, err)
			}
			if got != nil {
				t.Fatalf("retcode %d non-string stdout %#v: want nil result, got %#v", rc, v, got)
			}
		}
	}
	// Order pin: with BOTH members malformed, the retcode sentinel
	// wins (the pinned source reads retcode first, at line 7711).
	got, err := formatSyslogConfig(map[string]any{"retcode": "x", "stdout": 5})
	if !errors.Is(err, errSyslogRetcodeType) || got != nil {
		t.Fatalf("both malformed: want (nil, errSyslogRetcodeType), got (%#v, %v)", got, err)
	}
	// A nil cmdRet map reads like a missing retcode and must not panic.
	got, err = formatSyslogConfig(nil)
	if !errors.Is(err, errSyslogRetcodeType) || got != nil {
		t.Fatalf("nil cmdRet: want (nil, errSyslogRetcodeType), got (%#v, %v)", got, err)
	}
	// A missing stdout key with a valid retcode is the stdout sentinel.
	got, err = formatSyslogConfig(map[string]any{"retcode": 0})
	if !errors.Is(err, errSyslogStdoutType) || got != nil {
		t.Fatalf("missing stdout: want (nil, errSyslogStdoutType), got (%#v, %v)", got, err)
	}
}

func TestFormatSyslogSuccessEmptyStdout(t *testing.T) {
	// Empty stdout iterates ZERO lines: exactly the pinned
	// {"success": True} dict with no other key.
	got := mustParseSyslog(t, map[string]any{"retcode": 0, "stdout": ""})
	want := wantOf("success", true)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("empty stdout: got %#v, want %#v", got, want)
	}
	if v, ok := got["success"].(bool); !ok || !v {
		t.Fatalf("success must be a Go bool true, got %#v", got["success"])
	}
	// A blank line is NOT empty stdout: splitlines yields one empty
	// line, which is malformed (the pinned IndexError). Unlike the
	// coredump helper, blank lines are never skipped here.
	for _, stdout := range []string{"\n", "\r\n", "   \n", "\v\f", "\u2028"} {
		got, err := formatSyslogConfig(map[string]any{"retcode": 0, "stdout": stdout})
		if !errors.Is(err, errSyslogMalformedLine) {
			t.Fatalf("blank line %q: want errSyslogMalformedLine, got %v", stdout, err)
		}
		if got != nil {
			t.Fatalf("blank line %q: want nil result, got %#v", stdout, got)
		}
	}
}

func TestFormatSyslogNormalFields(t *testing.T) {
	// esxcli-shaped recorded synthetic stdout: key/value config rows
	// with interior spaces in keys, exact case preservation (this
	// helper runs NO lower(), unlike the coredump port), and interior
	// whitespace runs around the delimiter.
	stdout := "Satellite Server: vpxa.example.com\n" +
		"Syslog Default Rotation: 10\n" +
		"Syslog  Default  Size: 1024\n" +
		"Syslog Check: True\n" +
		"   Leading   :   spaced   \n"
	got := mustParseSyslog(t, map[string]any{"retcode": 0, "stdout": stdout})
	want := wantOf(
		"success", true,
		"Satellite Server", "vpxa.example.com",
		"Syslog Default Rotation", "10",
		"Syslog  Default  Size", "1024",
		"Syslog Check", "True",
		"Leading", "spaced",
	)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normal fields: got %#v, want %#v", got, want)
	}
	// Pinned Go types: success is a bool, every parsed value a string
	// — numeric-looking values ("10") are strings, never numbers.
	for key, wantStr := range map[string]string{
		"Satellite Server":        "vpxa.example.com",
		"Syslog Default Rotation": "10",
		"Syslog Check":            "True",
	} {
		if v, ok := got[key].(string); !ok || v != wantStr {
			t.Fatalf("%s must be a Go string %q, got %#v", key, wantStr, got[key])
		}
	}
}

func TestFormatSyslogDuplicateOverwrite(t *testing.T) {
	// Duplicate keys overwrite in encounter order (Python dict
	// assignment): the last write wins, in any position.
	stdout := "a: 1\nb: x\na: 2\nb: y\na: 3\n"
	got := mustParseSyslog(t, map[string]any{"retcode": 0, "stdout": stdout})
	want := wantOf("success", true, "a", "3", "b", "y")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("duplicate overwrite: got %#v, want %#v", got, want)
	}
	if len(got) != 3 {
		t.Fatalf("overwrites must not grow the map, got %#v", got)
	}
}

func TestFormatSyslogColonSplitQuirks(t *testing.T) {
	vectors := []struct {
		name   string
		stdout string
		want   map[string]any
	}{
		{
			// The pinned split(": ") runs on ALL occurrences but
			// consumes only cfgvars[0] and cfgvars[1]: every third
			// field is discarded data.
			name:   "third field dropped",
			stdout: "a: b: c\n",
			want:   wantOf("success", true, "a", "b"),
		},
		{
			name:   "longer tail dropped",
			stdout: "a: b: c: d: e\n",
			want:   wantOf("success", true, "a", "b"),
		},
		{
			// Adjacent delimiters store an empty value: cfgvars[1]
			// is the (stripped) empty run between them.
			name:   "adjacent delimiters store an empty value",
			stdout: "a: : b\n",
			want:   wantOf("success", true, "a", ""),
		},
		{
			// A delimiter at the very start stores the empty key
			// (pinned dict assignment under "").
			name:   "leading delimiter stores the empty key",
			stdout: ": x\n",
			want:   wantOf("success", true, "", "x"),
		},
		{
			// The leading colon belongs to the first field when only
			// its space tail forms the delimiter.
			name:   "colon-only first field",
			stdout: ":: x\n",
			want:   wantOf("success", true, ":", "x"),
		},
		{
			// A value with interior spaces keeps them after strip.
			name:   "interior value spaces retained",
			stdout: "a:  x y  z \n",
			want:   wantOf("success", true, "a", "x y  z"),
		},
	}
	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			got := mustParseSyslog(t, map[string]any{"retcode": 0, "stdout": tc.stdout})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestFormatSyslogMalformedRows(t *testing.T) {
	// The pinned IndexError positions, each confirmed against the
	// pinned function: a stripped line without the literal ": "
	// delimiter — a blank line, a whitespace-only line, a colon with
	// no trailing space, a colon followed by a tab, and a line whose
	// only delimiter space is stripped away pre-split ("a: " strips
	// to "a:"). All answer the fixed malformed sentinel with a nil
	// result; rows before the bad one never escape.
	vectors := []string{
		"\n",          // blank line
		"   \n",       // whitespace-only line
		"\v\f",        // only line boundaries: two empty lines
		"a:b\n",       // colon without a space
		"a:\tb\n",     // colon followed by a tab: the literal ": " never matches
		"a :b\n",      // space before but not after the colon
		"a: \n",       // the delimiter's space is stripped away pre-split
		"a:\n",        // bare colon
		"k: v\nbad\n", // valid row followed by a delimiter-less row
		"k: v\n\n",    // valid row followed by a blank line
	}
	var got map[string]any
	var err error
	for _, stdout := range vectors {
		got, err = formatSyslogConfig(map[string]any{"retcode": 0, "stdout": stdout})
		if !errors.Is(err, errSyslogMalformedLine) {
			t.Fatalf("malformed row %q: want errSyslogMalformedLine, got %v", stdout, err)
		}
		if got != nil {
			t.Fatalf("malformed row %q: want nil result, got %#v", stdout, got)
		}
	}
	// A valid row BEFORE a malformed row never escapes: the result is
	// only returned on the success path.
	got, err = formatSyslogConfig(map[string]any{"retcode": 0, "stdout": "ok: v\nbad\nworse\n"})
	if !errors.Is(err, errSyslogMalformedLine) || got != nil {
		t.Fatalf("no partial map: want (nil, errSyslogMalformedLine), got (%#v, %v)", got, err)
	}
}

func TestFormatSyslogSuccessKeyOverwrite(t *testing.T) {
	// A parsed key "success" overwrites the initial boolean true with
	// the string, exactly like the pinned dict assignment.
	got := mustParseSyslog(t, map[string]any{"retcode": 0, "stdout": "success: now\n"})
	want := wantOf("success", "now")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("success overwrite: got %#v, want %#v", got, want)
	}
	if _, ok := got["success"].(string); !ok {
		t.Fatalf("success must be overwritten with a Go string, got %#v", got["success"])
	}
	// The overwrite composes with other keys and with duplicates.
	got = mustParseSyslog(t, map[string]any{"retcode": 0, "stdout": "k: v\nsuccess: a\nsuccess: b\n"})
	want = wantOf("success", "b", "k", "v")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("success overwrite with duplicates: got %#v, want %#v", got, want)
	}
	// A nonzero retcode never reaches the parsing path, so its
	// success false is never overwritten by config rows.
	got = mustParseSyslog(t, map[string]any{"retcode": 3, "stdout": "success: never\n"})
	want = wantOf("success", false, "message", "success: never\n")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("message path success stays false: got %#v, want %#v", got, want)
	}
}

func TestFormatSyslogUnicodeWhitespaceAndSplitlines(t *testing.T) {
	vectors := []struct {
		name   string
		stdout string
		want   map[string]any
	}{
		{
			// NBSP and U+3000 are Python strip whitespace: they are
			// stripped from key ends and value ends.
			name:   "NBSP and U+3000 strip at the ends",
			stdout: "\u00a0k\u3000: v\u00a0\n",
			want:   wantOf("success", true, "k", "v"),
		},
		{
			// U+001F is Python strip whitespace but never a line
			// boundary: it strips from the value ends.
			name:   "U+001F strips as whitespace and is not a boundary",
			stdout: "k: \x1f v\x1f\n",
			want:   wantOf("success", true, "k", "v"),
		},
		{
			name:   "U+001F interior retained",
			stdout: "k: a\x1fb\n",
			want:   wantOf("success", true, "k", "a\x1fb"),
		},
		{
			// U+001C is a line boundary AND strip whitespace.
			name:   "U+001C is a line boundary",
			stdout: "k a: v\x1ck2: v2\n",
			want:   wantOf("success", true, "k a", "v", "k2", "v2"),
		},
		{
			name:   "CRLF is one boundary",
			stdout: "k: v\r\nk2: v2\r\n",
			want:   wantOf("success", true, "k", "v", "k2", "v2"),
		},
		{
			name:   "U+2028 and U+2029 are boundaries",
			stdout: "k: v\u2028k2: v2\u2029k3: v3",
			want:   wantOf("success", true, "k", "v", "k2", "v2", "k3", "v3"),
		},
		{
			name:   "U+0085 is a boundary",
			stdout: "k: v\u0085k2: v2",
			want:   wantOf("success", true, "k", "v", "k2", "v2"),
		},
		{
			// This helper runs NO lower(): values keep their exact
			// case (a lowercasing port would differ here).
			name:   "exact case preservation",
			stdout: "host: VMK0\n",
			want:   wantOf("success", true, "host", "VMK0"),
		},
		{
			// Unicode keys/values are stored verbatim: Cyrillic and
			// the U+0130 capital I survive exactly (no SpecialCasing).
			name:   "exact unicode preservation",
			stdout: "\u041a\u043b\u044e\u0447: \u0417\u043d\u0430\u0447\u0414\u0130FF\n",
			want:   wantOf("success", true, "\u041a\u043b\u044e\u0447", "\u0417\u043d\u0430\u0447\u0414\u0130FF"),
		},
	}
	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			got := mustParseSyslog(t, map[string]any{"retcode": 0, "stdout": tc.stdout})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestFormatSyslogLimits(t *testing.T) {
	t.Run("input bytes: 64 KiB boundary", func(t *testing.T) {
		// The parsing path has NO skipped rows, so benign filler must
		// be well-formed rows: each padded row is exactly 128 bytes
		// ("k: " + 123 spaces + "v\n"), strips to key "k" value "v",
		// and 512 rows are exactly 65536 bytes.
		row := "k: " + strings.Repeat(" ", 123) + "v\n"
		if len(row) != 128 {
			t.Fatalf("filler row must be 128 bytes, got %d", len(row))
		}
		exact := strings.Repeat(row, 512)
		got, err := formatSyslogConfig(map[string]any{"retcode": 0, "stdout": exact})
		if err != nil {
			t.Fatalf("exactly 65536 bytes must parse, got error %v", err)
		}
		if !reflect.DeepEqual(got, wantOf("success", true, "k", "v")) {
			t.Fatalf("duplicate filler rows must overwrite to one key, got %#v", got)
		}
		oversize := exact + "y"
		got, err = formatSyslogConfig(map[string]any{"retcode": 0, "stdout": oversize})
		if !errors.Is(err, errSyslogStdoutSize) {
			t.Fatalf("65537 bytes must reject with errSyslogStdoutSize, got %v", err)
		}
		if got != nil {
			t.Fatalf("oversize input must return nil result, got %#v", got)
		}
		// The size budget runs BEFORE the retcode branch: an oversized
		// message-path stdout is rejected too (the message copy stays
		// bounded).
		got, err = formatSyslogConfig(map[string]any{"retcode": 1, "stdout": oversize})
		if !errors.Is(err, errSyslogStdoutSize) {
			t.Fatalf("oversize nonzero-retcode stdout must answer the size sentinel, got %v", err)
		}
		if got != nil {
			t.Fatalf("oversize nonzero-retcode stdout must return nil result, got %#v", got)
		}
	})

	t.Run("lines: 1024 boundary", func(t *testing.T) {
		exact := strings.Repeat("a: b\n", 1024)
		got, err := formatSyslogConfig(map[string]any{"retcode": 0, "stdout": exact})
		if err != nil {
			t.Fatalf("exactly 1024 lines must parse, got error %v", err)
		}
		if !reflect.DeepEqual(got, wantOf("success", true, "a", "b")) {
			t.Fatalf("1024 duplicate rows must keep one key, got %#v", got)
		}
		// 1025 boundaries, with and without a final unterminated line.
		for name, over := range map[string]string{
			"terminated":   strings.Repeat("a: b\n", 1025),
			"unterminated": strings.Repeat("a: b\n", 1024) + "c: d",
		} {
			got, err := formatSyslogConfig(map[string]any{"retcode": 0, "stdout": over})
			if !errors.Is(err, errSyslogLineLimit) {
				t.Fatalf("%s: 1025 lines must reject with errSyslogLineLimit, got %v", name, err)
			}
			if got != nil {
				t.Fatalf("%s: over-budget lines must return nil result, got %#v", name, got)
			}
		}
		// Multi-byte boundaries count individually toward the same cap.
		over := strings.Repeat("a: b\u2028", 1025)
		if got, err = formatSyslogConfig(map[string]any{"retcode": 0, "stdout": over}); !errors.Is(err, errSyslogLineLimit) {
			t.Fatalf("1025 U+2028 lines must reject with errSyslogLineLimit, got %v", err)
		}
		// Order pin: the line budget is enforced BEFORE the row is
		// parsed, so a malformed 1025th row answers the LINE sentinel.
		overMalformed := strings.Repeat("a: b\n", 1024) + "lonetoken"
		if got, err = formatSyslogConfig(map[string]any{"retcode": 0, "stdout": overMalformed}); !errors.Is(err, errSyslogLineLimit) {
			t.Fatalf("malformed 1025th row must answer the line limit, got %v", err)
		}
		// ...while a malformed 1024th row (still within budget) answers
		// the malformed sentinel.
		atLimit := strings.Repeat("a: b\n", 1023) + "lonetoken\n"
		if got, err = formatSyslogConfig(map[string]any{"retcode": 0, "stdout": atLimit}); !errors.Is(err, errSyslogMalformedLine) {
			t.Fatalf("malformed 1024th row must answer the malformed sentinel, got %v", err)
		}
	})

	t.Run("key/value: 4096 boundary", func(t *testing.T) {
		exactKey := strings.Repeat("k", 4096) + ": v\n"
		got, err := formatSyslogConfig(map[string]any{"retcode": 0, "stdout": exactKey})
		if err != nil {
			t.Fatalf("exactly 4096-byte key must parse, got error %v", err)
		}
		if got[strings.Repeat("k", 4096)] != "v" {
			t.Fatalf("4096-byte key must be retained, got %#v", got)
		}
		overKey := strings.Repeat("k", 4097) + ": v\n"
		got, err = formatSyslogConfig(map[string]any{"retcode": 0, "stdout": overKey})
		if !errors.Is(err, errSyslogFieldLimit) {
			t.Fatalf("4097-byte key must reject with errSyslogFieldLimit, got %v", err)
		}
		if got != nil {
			t.Fatalf("over-budget key must return nil result, got %#v", got)
		}
		exactValue := "a: " + strings.Repeat("v", 4096) + "\n"
		if got, err = formatSyslogConfig(map[string]any{"retcode": 0, "stdout": exactValue}); err != nil {
			t.Fatalf("exactly 4096-byte value must parse, got error %v", err)
		}
		overValue := "a: " + strings.Repeat("v", 4097) + "\n"
		if got, err = formatSyslogConfig(map[string]any{"retcode": 0, "stdout": overValue}); !errors.Is(err, errSyslogFieldLimit) {
			t.Fatalf("4097-byte value must reject with errSyslogFieldLimit, got %v", err)
		}
		// A huge UNSTRIPPED part whose retained bytes are short parses
		// (the cap applies to the retained key/value): padding before
		// the value and between key and colon both vanish in strip.
		paddedValue := "a: " + strings.Repeat(" ", 60000) + "v\n"
		got, err = formatSyslogConfig(map[string]any{"retcode": 0, "stdout": paddedValue})
		if err != nil {
			t.Fatalf("padded value within input budget must parse, got error %v", err)
		}
		if !reflect.DeepEqual(got, wantOf("success", true, "a", "v")) {
			t.Fatalf("padded value must strip to v, got %#v", got)
		}
		paddedKey := "a" + strings.Repeat(" ", 5000) + ": v\n"
		got, err = formatSyslogConfig(map[string]any{"retcode": 0, "stdout": paddedKey})
		if err != nil {
			t.Fatalf("padded key within input budget must parse, got error %v", err)
		}
		if !reflect.DeepEqual(got, wantOf("success", true, "a", "v")) {
			t.Fatalf("padded key must strip to a, got %#v", got)
		}
	})

	t.Run("keys: 256 boundary", func(t *testing.T) {
		// The cap counts the retained ret_dict INCLUDING the initial
		// success entry: 255 distinct data rows fill it exactly.
		exact := syslogRows(255)
		got, err := formatSyslogConfig(map[string]any{"retcode": 0, "stdout": exact})
		if err != nil {
			t.Fatalf("exactly 256 ret_dict entries (success + 255) must parse, got error %v", err)
		}
		if len(got) != 256 {
			t.Fatalf("success + 255 distinct keys must retain 256 entries, got %d", len(got))
		}
		over := syslogRows(256)
		got, err = formatSyslogConfig(map[string]any{"retcode": 0, "stdout": over})
		if !errors.Is(err, errSyslogKeyLimit) {
			t.Fatalf("a 257th distinct entry must reject with errSyslogKeyLimit, got %v", err)
		}
		if got != nil {
			t.Fatalf("over-budget keys must return nil result, got %#v", got)
		}
		// A duplicate row over a full map never grows it: 256 data rows
		// but only 255 distinct data keys parse, and the duplicate's
		// value wins.
		dup := syslogRows(255) + "k0: dup\n"
		got, err = formatSyslogConfig(map[string]any{"retcode": 0, "stdout": dup})
		if err != nil {
			t.Fatalf("duplicate row over a full map must parse, got error %v", err)
		}
		if len(got) != 256 {
			t.Fatalf("duplicate row must not grow the map, got %d", len(got))
		}
		if got["k0"] != "dup" {
			t.Fatalf("duplicate value must overwrite, got %#v", got["k0"])
		}
		// The parsed "success" entry is an existing key: overwriting it
		// over a full map parses too.
		success := syslogRows(255) + "success: now\n"
		got, err = formatSyslogConfig(map[string]any{"retcode": 0, "stdout": success})
		if err != nil {
			t.Fatalf("success overwrite over a full map must parse, got error %v", err)
		}
		if len(got) != 256 {
			t.Fatalf("success overwrite must not grow the map, got %d", len(got))
		}
		if got["success"] != "now" {
			t.Fatalf("success must be the overwritten string, got %#v", got["success"])
		}
	})
}

func TestFormatSyslogErrorsAreValueFree(t *testing.T) {
	const marker = "MARKERZQSYS-secret-vector"
	paths := []struct {
		name   string
		cmdRet map[string]any
		want   error
	}{
		{
			name:   "retcode type",
			cmdRet: map[string]any{"retcode": marker, "stdout": "k: v\n"},
			want:   errSyslogRetcodeType,
		},
		{
			name:   "stdout type",
			cmdRet: map[string]any{"retcode": 0, "stdout": []byte(marker)},
			want:   errSyslogStdoutType,
		},
		{
			name:   "size",
			cmdRet: map[string]any{"retcode": 0, "stdout": marker + strings.Repeat("x", 70000)},
			want:   errSyslogStdoutSize,
		},
		{
			name:   "utf8",
			cmdRet: map[string]any{"retcode": 0, "stdout": "k: " + marker + "\xff\n"},
			want:   errSyslogStdoutUTF8,
		},
		{
			name:   "lines",
			cmdRet: map[string]any{"retcode": 0, "stdout": "k: " + marker + "\n" + strings.Repeat("a: b\n", 1025)},
			want:   errSyslogLineLimit,
		},
		{
			name:   "field value",
			cmdRet: map[string]any{"retcode": 0, "stdout": "k: " + marker + strings.Repeat("v", 5000) + "\n"},
			want:   errSyslogFieldLimit,
		},
		{
			name:   "field key",
			cmdRet: map[string]any{"retcode": 0, "stdout": marker + strings.Repeat("k", 5000) + ": v\n"},
			want:   errSyslogFieldLimit,
		},
		{
			name:   "keys",
			cmdRet: map[string]any{"retcode": 0, "stdout": syslogRows(255) + "zz" + marker + ": v\n"},
			want:   errSyslogKeyLimit,
		},
		{
			name:   "malformed",
			cmdRet: map[string]any{"retcode": 0, "stdout": marker + "\n"},
			want:   errSyslogMalformedLine,
		},
	}
	for _, tc := range paths {
		t.Run(tc.name, func(t *testing.T) {
			got, err := formatSyslogConfig(tc.cmdRet)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want sentinel %v, got %v", tc.want, err)
			}
			if got != nil {
				t.Fatalf("want nil result, got %#v", got)
			}
			// Value-free: no vector bytes in the error text.
			if strings.Contains(err.Error(), "MARKERZQ") || strings.Contains(err.Error(), "vpxa") {
				t.Fatalf("error must be value-free, got %q", err.Error())
			}
			// Fixed identity: exact sentinel text, no wrapping.
			if err.Error() != tc.want.Error() {
				t.Fatalf("error text must be the fixed sentinel text, got %q", err.Error())
			}
		})
	}
	// All sentinels are pairwise distinct fixed values.
	sentinels := []error{
		errSyslogRetcodeType,
		errSyslogStdoutType,
		errSyslogStdoutSize,
		errSyslogStdoutUTF8,
		errSyslogLineLimit,
		errSyslogFieldLimit,
		errSyslogKeyLimit,
		errSyslogMalformedLine,
	}
	seen := map[string]bool{}
	for _, s := range sentinels {
		if seen[s.Error()] {
			t.Fatalf("duplicate sentinel text %q", s.Error())
		}
		seen[s.Error()] = true
	}
}

func TestFormatSyslogIgnoresOtherCmdRetMembers(t *testing.T) {
	// Only the retcode and stdout members are read; stderr, pid, and
	// cmd are ignored even when they carry malformed rows.
	cmdRet := map[string]any{
		"retcode": 0,
		"stdout":  "k: v\n",
		"stderr":  "bad row without delimiter\n\nalso: bad: extra\n",
		"pid":     1234,
		"cmd":     []string{"esxcli", "system", "syslog", "config", "get"},
	}
	got := mustParseSyslog(t, cmdRet)
	want := wantOf("success", true, "k", "v")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("only the stdout member is parsed: got %#v, want %#v", got, want)
	}
}

func TestFormatSyslogResultShape(t *testing.T) {
	// Zero retcode with no parseable rows: exactly the one success key.
	got := mustParseSyslog(t, map[string]any{"retcode": 0, "stdout": ""})
	if len(got) != 1 {
		t.Fatalf("success-only ret_dict must have exactly one key, got %#v", got)
	}
	if v, ok := got["success"].(bool); !ok || !v {
		t.Fatalf("success must be a Go bool true, got %#v", got["success"])
	}
	// Nonzero retcode: exactly the success and message keys, and an
	// empty stdout message is stored verbatim as the empty string.
	got = mustParseSyslog(t, map[string]any{"retcode": 1, "stdout": ""})
	if len(got) != 2 {
		t.Fatalf("message ret_dict must have exactly success and message, got %#v", got)
	}
	if _, ok := got["message"]; !ok {
		t.Fatalf("message ret_dict must carry the message key, got %#v", got)
	}
	if v, ok := got["message"].(string); !ok || v != "" {
		t.Fatalf("message must be the raw stdout string, got %#v", got["message"])
	}
}
