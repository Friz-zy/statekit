//go:build r10_contract

package vsphere

// R10.4a private-helper contract tests (r10_contract build tag).
//
// Every vector is an inline synthetic stdout literal: the suite is pure
// and hermetic — no PyVmomi, no govc, no vendor CLI, no Runner, no
// network, no endpoint, no credentials, and no host file is ever read
// or written. The tests pin the pinned-source behavior of
// _format_coredump_stdout (saltstack/salt/modules/vsphere.py lines
// 7655–7682) quirk-inclusive, plus the StateKit fail-closed budgets
// (exact boundary and +1 rejections with nil results), and the
// value-free error discipline.

import (
	"errors"
	"reflect"
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
