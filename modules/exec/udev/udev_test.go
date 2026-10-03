package udev

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct {
	results map[string]process.CommandResult
	calls   [][]string
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	f.calls = append(f.calls, argv)
	if res, ok := f.results[strings.Join(argv, " ")]; ok {
		return res
	}
	return process.CommandResult{}
}

func newRT(results map[string]process.CommandResult) (*runtime.Runtime, *fakeRunner) {
	runner := &fakeRunner{results: results}
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Runner: runner,
	}
	if err := Register(rt.Exec); err != nil {
		panic(err)
	}
	return rt, runner
}

// Mirrors test_info's fixture: env extracts the E section with numeric
// coercion and single-element collapse for other sections.
func TestEnvNameQuery(t *testing.T) {
	stdout := "P: /devices/virtual/vc/vcsa7\n" +
		"N: vcsa7\n" +
		"E: DEVNAME=/dev/vcsa7\n" +
		"E: DEVPATH=/devices/virtual/vc/vcsa7\n" +
		"E: MAJOR=7\n" +
		"E: MINOR=135\n" +
		"E: SUBSYSTEM=vc\n" +
		"\n"
	rt, runner := newRT(map[string]process.CommandResult{
		"udevadm info --export --query=all --name=/dev/vcsa7": {Stdout: []byte(stdout)},
	})

	gotRaw, err := (envFunc{}).Execute(context.Background(), rt, &EnvArgs{Dev: "/dev/vcsa7"})
	if err != nil {
		t.Fatal(err)
	}
	got := gotRaw.(map[string]any)
	want := map[string]any{
		"DEVNAME":   "/dev/vcsa7",
		"DEVPATH":   "/devices/virtual/vc/vcsa7",
		"MAJOR":     int64(7),
		"MINOR":     int64(135),
		"SUBSYSTEM": "vc",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("env = %#v, want %#v", got, want)
	}

	// /dev names query through --name=; no shell involved.
	argv := runner.calls[0]
	last := argv[len(argv)-1]
	if last != "--name=/dev/vcsa7" || argv[0] != "udevadm" || !reflect.DeepEqual(argv[:4],
		[]string{"udevadm", "info", "--export", "--query=all"}) {
		t.Fatalf("argv = %v", argv)
	}
}

// A dev containing "sys" switches udevadm to the path query.
func TestEnvPathQuery(t *testing.T) {
	rt, runner := newRT(map[string]process.CommandResult{
		"udevadm info --export --query=all --path=/sys/class/net/eth0": {Stdout: []byte("")},
	})
	if _, err := (&envFunc{}).Execute(context.Background(), rt, &EnvArgs{Dev: "/sys/class/net/eth0"}); err == nil {
		t.Fatal("expected error for empty record")
	}
	if last := runner.calls[0][len(runner.calls[0])-1]; last != "--path=/sys/class/net/eth0" {
		t.Fatalf("query type argv = %v", runner.calls[0])
	}
}

// Multi-device exportdb-style output: env reports the first record only,
// lists collapse when they carry a single element.
func TestParseInfoMultiDevice(t *testing.T) {
	devices, err := parseInfo("" +
		"P: /devices/LNXSYSTM:00/LNXPWRBN:00\n" +
		"E: DEVPATH=/devices/LNXSYSTM:00/LNXPWRBN:00\n" +
		"E: DRIVER=button\n" +
		"E: ID_INPUT=1\n" +
		"\n" +
		"P: /devices/input/event2\n" +
		"N: input/event2\n" +
		"S: input/by-id/x\n" +
		"S: input/by-path/y\n" +
		"E: MAJOR=13\n" +
		"\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 2 {
		t.Fatalf("device count = %d", len(devices))
	}
	first := devices[0]
	// Single-element sections collapse to scalars; E stays a dict.
	if first["P"] != "/devices/LNXSYSTM:00/LNXPWRBN:00" {
		t.Fatalf("first P = %#v", first["P"])
	}
	env := first["E"].(map[string]any)
	if env["ID_INPUT"] != int64(1) {
		t.Fatalf("numeric coercion = %#v", env["ID_INPUT"])
	}
	if devices[1]["N"] != "input/event2" {
		t.Fatalf("collapsed N = %#v", devices[1]["N"])
	}
	links, ok := devices[1]["S"].([]any)
	if !ok || len(links) != 2 {
		t.Fatalf("multi-element S = %#v", devices[1]["S"])
	}
}

// upstreamExportFixture is the pinned three-record export-db fixture from
// saltstack/tests/pytests/unit/modules/test_udev.py (test_exportdb).
const upstreamExportFixture = `
P: /devices/LNXSYSTM:00/LNXPWRBN:00
E: DEVPATH=/devices/LNXSYSTM:00/LNXPWRBN:00
E: DRIVER=button
E: MODALIAS=acpi:LNXPWRBN:
E: SUBSYSTEM=acpi

P: /devices/LNXSYSTM:00/LNXPWRBN:00/input/input2
E: DEVPATH=/devices/LNXSYSTM:00/LNXPWRBN:00/input/input2
E: EV=3
E: ID_FOR_SEAT=input-acpi-LNXPWRBN_00
E: ID_INPUT=1
E: ID_INPUT_KEY=1
E: ID_PATH=acpi-LNXPWRBN:00
E: ID_PATH_TAG=acpi-LNXPWRBN_00
E: KEY=10000000000000 0
E: MODALIAS=input:b0019v0000p0001e0000-e0,1,k74,ramlsfw
E: NAME="Power Button"
E: PHYS="LNXPWRBN/button/input0"
E: PRODUCT=19/0/1/0
E: PROP=0
E: SUBSYSTEM=input
E: TAGS=:seat:
E: USEC_INITIALIZED=2010022

P: /devices/LNXSYSTM:00/LNXPWRBN:00/input/input2/event2
N: input/event2
E: BACKSPACE=guess
E: DEVNAME=/dev/input/event2
E: DEVPATH=/devices/LNXSYSTM:00/LNXPWRBN:00/input/input2/event2
E: ID_INPUT=1
E: ID_INPUT_KEY=1
E: ID_PATH=acpi-LNXPWRBN:00
E: ID_PATH_TAG=acpi-LNXPWRBN_00
E: MAJOR=13
E: MINOR=66
E: SUBSYSTEM=input
E: TAGS=:power-switch:
E: USEC_INITIALIZED=2076101
E: XKBLAYOUT=us
E: XKBMODEL=pc105
`

// TestParseInfoExportFixture walks the full pinned upstream fixture:
// record order and count, section shapes (scalar P, absent N, E map),
// quoting preserved verbatim, colons inside values, and the int/float
// coercion chain.
func TestParseInfoExportFixture(t *testing.T) {
	devices, err := parseInfo(upstreamExportFixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 3 {
		t.Fatalf("record count = %d, want 3", len(devices))
	}

	first := devices[0]
	if _, hasN := first["N"]; hasN {
		t.Fatalf("first record must carry no N section: %#v", first)
	}
	if first["P"] != "/devices/LNXSYSTM:00/LNXPWRBN:00" {
		t.Fatalf("first P = %#v", first["P"])
	}
	firstEnv := first["E"].(map[string]any)
	wantFirst := map[string]any{
		"DEVPATH":   "/devices/LNXSYSTM:00/LNXPWRBN:00",
		"DRIVER":    "button",
		"MODALIAS":  "acpi:LNXPWRBN:",
		"SUBSYSTEM": "acpi",
	}
	if !reflect.DeepEqual(firstEnv, wantFirst) {
		t.Fatalf("first E = %#v", firstEnv)
	}

	second := devices[1]
	secondEnv := second["E"].(map[string]any)
	if len(secondEnv) != 16 {
		t.Fatalf("second E key count = %d, want 16", len(secondEnv))
	}
	// Quoted values stay verbatim (upstream keeps the quotes).
	if secondEnv["NAME"] != `"Power Button"` {
		t.Fatalf("NAME = %#v", secondEnv["NAME"])
	}
	if secondEnv["PHYS"] != `"LNXPWRBN/button/input0"` {
		t.Fatalf("PHYS = %#v", secondEnv["PHYS"])
	}
	// Colons inside values survive the section split.
	if secondEnv["ID_PATH"] != "acpi-LNXPWRBN:00" {
		t.Fatalf("ID_PATH = %#v", secondEnv["ID_PATH"])
	}
	if secondEnv["MODALIAS"] != "input:b0019v0000p0001e0000-e0,1,k74,ramlsfw" {
		t.Fatalf("MODALIAS = %#v", secondEnv["MODALIAS"])
	}
	// Numeric fixture values coerce to int64.
	for key, want := range map[string]int64{
		"EV": 3, "ID_INPUT": 1, "ID_INPUT_KEY": 1, "PROP": 0,
		"USEC_INITIALIZED": 2010022,
	} {
		if secondEnv[key] != want {
			t.Fatalf("second E[%s] = %#v, want %d", key, secondEnv[key], want)
		}
	}
	// Space-separated numbers stay strings (not a single number).
	if secondEnv["KEY"] != "10000000000000 0" {
		t.Fatalf("KEY = %#v", secondEnv["KEY"])
	}
	if secondEnv["PRODUCT"] != "19/0/1/0" {
		t.Fatalf("PRODUCT = %#v", secondEnv["PRODUCT"])
	}

	third := devices[2]
	if third["P"] != "/devices/LNXSYSTM:00/LNXPWRBN:00/input/input2/event2" {
		t.Fatalf("third P = %#v", third["P"])
	}
	if third["N"] != "input/event2" {
		t.Fatalf("third N = %#v", third["N"])
	}
	thirdEnv := third["E"].(map[string]any)
	if thirdEnv["MAJOR"] != int64(13) || thirdEnv["MINOR"] != int64(66) {
		t.Fatalf("third numeric fields = %#v/%#v", thirdEnv["MAJOR"], thirdEnv["MINOR"])
	}
	if thirdEnv["SUBSYSTEM"] != "input" || secondEnv["SUBSYSTEM"] != "input" {
		t.Fatalf("SUBSYSTEM values = %#v/%#v", secondEnv["SUBSYSTEM"], thirdEnv["SUBSYSTEM"])
	}
}

// TestParseInfoNumericCoercion pins the int-then-float chain plus the
// documented int64 divergence: values beyond int64 fall back to float64
// where Python would keep an arbitrary-precision int.
func TestParseInfoNumericCoercion(t *testing.T) {
	devices, err := parseInfo("E: A=7\nE: B=1.5\nE: C=9223372036854775808\nE: D=-3\nE: E=xf\n")
	if err != nil {
		t.Fatal(err)
	}
	env := devices[0]["E"].(map[string]any)
	if env["A"] != int64(7) || env["B"] != float64(1.5) || env["D"] != int64(-3) {
		t.Fatalf("coercion = %#v", env)
	}
	if _, isFloat := env["C"].(float64); !isFloat {
		t.Fatalf("beyond-int64 value = %#v, want float64 fallback", env["C"])
	}
	if env["E"] != "xf" {
		t.Fatalf("non-numeric stays string: %#v", env["E"])
	}
}

// TestParseInfoRepeatedSections keeps repeated non-E sections as lists and
// collapses only single-element ones, in first-seen order.
func TestParseInfoRepeatedSections(t *testing.T) {
	devices, err := parseInfo("" +
		"P: /devices/a\n" +
		"P: /devices/b\n" +
		"S: link1\n" +
		"S: link2\n" +
		"S: link3\n" +
		"\n")
	if err != nil {
		t.Fatal(err)
	}
	rec := devices[0]
	paths, ok := rec["P"].([]any)
	if !ok || !reflect.DeepEqual(paths, []any{"/devices/a", "/devices/b"}) {
		t.Fatalf("repeated P = %#v", rec["P"])
	}
	links, ok := rec["S"].([]any)
	if !ok || len(links) != 3 || links[0] != "link1" || links[2] != "link3" {
		t.Fatalf("repeated S = %#v", rec["S"])
	}
}

// TestParseInfoMalformedEFailsWholeParse pins the parser error contract: an
// E line without '=' fails the whole parse with no partial records, even
// after earlier valid records; lines without ':' stay skipped.
func TestParseInfoMalformedEFailsWholeParse(t *testing.T) {
	got, err := parseInfo("" +
		"P: /devices/ok\n" +
		"E: SUBSYSTEM=block\n" +
		"\n" +
		"P: /devices/broken\n" +
		"E: NO_EQUALS_HERE\n" +
		"\n")
	if err == nil {
		t.Fatal("expected malformed E error")
	}
	if got != nil {
		t.Fatalf("malformed input must yield no partial records, got %#v", got)
	}

	// Colon-less lines are skipped silently (upstream continue).
	devices, err := parseInfo("noise without colon\nE: OK=1\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0]["E"].(map[string]any)["OK"] != int64(1) {
		t.Fatalf("colon-less skip = %#v", devices)
	}
}

// TestParseInfoSingletonEMapKeepsMap documents the deliberate divergence
// from Salt's _normalize_info, which indexes a one-entry E dict with [0]
// and raises KeyError; the port keeps the singleton map intact.
func TestParseInfoSingletonEMapKeepsMap(t *testing.T) {
	devices, err := parseInfo("P: /devices/only\nE: ONLY_FIELD=1\n\n")
	if err != nil {
		t.Fatal(err)
	}
	env, ok := devices[0]["E"].(map[string]any)
	if !ok || env["ONLY_FIELD"] != int64(1) {
		t.Fatalf("singleton E must stay a map: %#v", devices[0]["E"])
	}
}

// TestParseInfoLimits proves the finite parser controls at the exact cap
// and cap+1 boundaries: input bytes, raw line bytes (checked before
// trimming), records, and parsed field occurrences per record counting
// duplicate keys.
func TestParseInfoLimits(t *testing.T) {
	t.Run("input bytes", func(t *testing.T) {
		if _, err := parseInfo(strings.Repeat("\n", 16<<20)); err != nil {
			t.Fatalf("16 MiB exactly must parse: %v", err)
		}
		if got, err := parseInfo(strings.Repeat("\n", (16<<20)+1)); err == nil {
			t.Fatalf("16 MiB + 1 must fail, got %d records", len(got))
		}
	})

	t.Run("line bytes", func(t *testing.T) {
		exact := "P: " + strings.Repeat("a", (64<<10)-3) + "\n\n"
		if _, err := parseInfo(exact); err != nil {
			t.Fatalf("64 KiB raw line must parse: %v", err)
		}
		// The over-limit line is longer before any trimming.
		over := "P: " + strings.Repeat("a", (64<<10)-2) + "\n\n"
		if got, err := parseInfo(over); err == nil {
			t.Fatalf("64 KiB + 1 raw line must fail, got %d records", len(got))
		}
		// Trailing spaces cannot dodge the raw-length check.
		spacey := "P: " + strings.Repeat("a", (64<<10)-3) + " \n\n"
		if _, err := parseInfo(spacey); err == nil {
			t.Fatal("over-limit raw line with trimmable tail must fail")
		}
	})

	t.Run("fields per record", func(t *testing.T) {
		build := func(occurrences int) string {
			var b strings.Builder
			for i := 0; i < occurrences; i++ {
				// Duplicate keys count once per occurrence, not per
				// distinct key.
				fmt.Fprintf(&b, "E: K%d=1\n", i%512)
			}
			return b.String()
		}
		if _, err := parseInfo(build(1024)); err != nil {
			t.Fatalf("1024 field occurrences must parse: %v", err)
		}
		if got, err := parseInfo(build(1025)); err == nil {
			t.Fatalf("1025 field occurrences must fail, got %#v", got)
		}
		// Non-E sections count toward the same per-record budget.
		mixed := strings.Repeat("S: link\n", 1024)
		if _, err := parseInfo(mixed); err != nil {
			t.Fatalf("1024 section lines must parse: %v", err)
		}
		if _, err := parseInfo(strings.Repeat("S: link\n", 1025)); err == nil {
			t.Fatal("1025 section lines must fail")
		}
	})

	t.Run("records", func(t *testing.T) {
		build := func(count int) string {
			var b strings.Builder
			for i := 0; i < count; i++ {
				b.WriteString("P: /d\n\n")
			}
			return b.String()
		}
		if devices, err := parseInfo(build(65536)); err != nil || len(devices) != 65536 {
			t.Fatalf("65536 records must parse: %d records, err %v", len(devices), err)
		}
		if _, err := parseInfo(build(65537)); err == nil {
			t.Fatal("65537 records must fail")
		}
	})
}

// TestEnvInfoMalformedParsePropagates: env and info surface the parser
// error for malformed E lines while keeping their command boundaries and
// the pre-existing non-parser failure policy.
func TestEnvInfoMalformedParsePropagates(t *testing.T) {
	malformed := "P: /devices/vcsa7\nE: DEVNAME=/dev/vcsa7\nE: BROKEN\n\n"
	rt, runner := newRT(map[string]process.CommandResult{
		"udevadm info --export --query=all --name=/dev/vcsa7": {Stdout: []byte(malformed)},
	})
	if _, err := (envFunc{}).Execute(context.Background(), rt, &EnvArgs{Dev: "/dev/vcsa7"}); err == nil {
		t.Fatal("env must fail on malformed E line")
	}
	if _, err := (infoFunc{}).Execute(context.Background(), rt, &InfoArgs{Dev: "/dev/vcsa7"}); err == nil {
		t.Fatal("info must fail on malformed E line")
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want one per function", len(runner.calls))
	}
}

// Non-zero retcodes surface the stderr as an error (Salt raises
// CommandExecutionError).
func TestEnvRetcodeFailure(t *testing.T) {
	rt, _ := newRT(map[string]process.CommandResult{
		"udevadm info --export --query=all --name=/dev/gone": {ExitCode: 1, Stderr: []byte("Unknown device")},
	})
	_, err := (envFunc{}).Execute(context.Background(), rt, &EnvArgs{Dev: "/dev/gone"})
	if err == nil || !strings.Contains(err.Error(), "Unknown device") {
		t.Fatalf("err = %v", err)
	}
}

// namePathLinksFixture is an upstream-style single record with scalar P
// and N plus a two-value S list, for the section-extraction wrappers.
const namePathLinksFixture = "P: /devices/LNXSYSTM:00/LNXPWRBN:00/input/input2/event2\n" +
	"N: input/event2\n" +
	"S: input/by-id/x\n" +
	"S: input/by-path/y\n" +
	"E: DEVNAME=/dev/input/event2\n" +
	"E: MAJOR=13\n" +
	"\n"

// upstreamThirdRecordFixture is the third record of
// upstreamExportFixture verbatim: what `udevadm info --name=input/event2`
// would emit for that device, so info(dev) sees exactly one record.
const upstreamThirdRecordFixture = "P: /devices/LNXSYSTM:00/LNXPWRBN:00/input/input2/event2\n" +
	"N: input/event2\n" +
	"E: BACKSPACE=guess\n" +
	"E: DEVNAME=/dev/input/event2\n" +
	"E: DEVPATH=/devices/LNXSYSTM:00/LNXPWRBN:00/input/input2/event2\n" +
	"E: ID_INPUT=1\n" +
	"E: ID_INPUT_KEY=1\n" +
	"E: ID_PATH=acpi-LNXPWRBN:00\n" +
	"E: ID_PATH_TAG=acpi-LNXPWRBN_00\n" +
	"E: MAJOR=13\n" +
	"E: MINOR=66\n" +
	"E: SUBSYSTEM=input\n" +
	"E: TAGS=:power-switch:\n" +
	"E: USEC_INITIALIZED=2076101\n" +
	"E: XKBLAYOUT=us\n" +
	"E: XKBMODEL=pc105\n" +
	"\n"

// TestNamePathLinksSectionExtraction pins Salt's name/path/links
// (.get("N"/"P"/"S", None)) over the pinned upstream fixture's third
// record: name and path return the collapsed scalar sections and a
// record without S maps links to nil.
func TestNamePathLinksSectionExtraction(t *testing.T) {
	rt, _ := newRT(map[string]process.CommandResult{
		"udevadm info --export --query=all --name=input/event2": {Stdout: []byte(upstreamThirdRecordFixture)},
	})

	gotName, err := (nameFunc{}).Execute(context.Background(), rt, &NameArgs{Dev: "input/event2"})
	if err != nil {
		t.Fatal(err)
	}
	if gotName != "input/event2" {
		t.Fatalf("name = %#v, want input/event2", gotName)
	}

	gotPath, err := (pathFunc{}).Execute(context.Background(), rt, &PathArgs{Dev: "input/event2"})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/devices/LNXSYSTM:00/LNXPWRBN:00/input/input2/event2" {
		t.Fatalf("path = %#v", gotPath)
	}

	// The pinned fixture's third record carries no S section: Salt's
	// .get("S", None) maps to a missing key returning None, not an error.
	gotLinks, err := (linksFunc{}).Execute(context.Background(), rt, &LinksArgs{Dev: "input/event2"})
	if err != nil {
		t.Fatal(err)
	}
	if gotLinks != nil {
		t.Fatalf("links over S-less record = %#v, want nil", gotLinks)
	}
}

// TestLinksMultiValueStaysList: a multi-value S section survives as a
// []any (no single-element collapse), in first-seen order.
func TestLinksMultiValueStaysList(t *testing.T) {
	rt, _ := newRT(map[string]process.CommandResult{
		"udevadm info --export --query=all --name=/dev/vcsa7": {Stdout: []byte(namePathLinksFixture)},
	})
	gotRaw, err := (linksFunc{}).Execute(context.Background(), rt, &LinksArgs{Dev: "/dev/vcsa7"})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := gotRaw.([]any)
	if !ok || !reflect.DeepEqual(got, []any{"input/by-id/x", "input/by-path/y"}) {
		t.Fatalf("links = %#v, want []any{input/by-id/x, input/by-path/y}", gotRaw)
	}
}

// TestNamePathLinksAbsentSectionsNil pins the None mapping for every
// wrapper: absent N, P, and S sections yield nil (not an empty string,
// not an error), with the record still valid through its E section.
func TestNamePathLinksAbsentSectionsNil(t *testing.T) {
	rt, _ := newRT(map[string]process.CommandResult{
		"udevadm info --export --query=all --name=/dev/gone": {Stdout: []byte("E: SUBSYSTEM=block\n\n")},
	})
	for _, tc := range []struct {
		name string
		run  func() (any, error)
	}{
		{"name without N", func() (any, error) {
			return (nameFunc{}).Execute(context.Background(), rt, &NameArgs{Dev: "/dev/gone"})
		}},
		{"path without P", func() (any, error) {
			return (pathFunc{}).Execute(context.Background(), rt, &PathArgs{Dev: "/dev/gone"})
		}},
		{"links without S", func() (any, error) {
			return (linksFunc{}).Execute(context.Background(), rt, &LinksArgs{Dev: "/dev/gone"})
		}},
	} {
		got, err := tc.run()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != nil {
			t.Fatalf("%s = %#v, want nil (not empty string)", tc.name, got)
		}
	}
}

// TestNamePathLinksQueryDispatch: a plain dev queries through --name= and
// a sys-containing dev switches to --path=, each dispatching the exact
// shell-free argv exactly once.
func TestNamePathLinksQueryDispatch(t *testing.T) {
	wantName := []string{"udevadm", "info", "--export", "--query=all", "--name=/dev/vcsa7"}
	wantPath := []string{"udevadm", "info", "--export", "--query=all", "--path=/sys/class/net/eth0"}

	rt, runner := newRT(map[string]process.CommandResult{
		strings.Join(wantName, " "): {Stdout: []byte(namePathLinksFixture)},
		strings.Join(wantPath, " "): {Stdout: []byte(namePathLinksFixture)},
	})
	if _, err := (nameFunc{}).Execute(context.Background(), rt, &NameArgs{Dev: "/dev/vcsa7"}); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(runner.calls[0], wantName) {
		t.Fatalf("name argv = %v (calls %d), want %v", runner.calls, len(runner.calls), wantName)
	}

	rt, runner = newRT(map[string]process.CommandResult{
		strings.Join(wantName, " "): {Stdout: []byte(namePathLinksFixture)},
		strings.Join(wantPath, " "): {Stdout: []byte(namePathLinksFixture)},
	})
	if _, err := (pathFunc{}).Execute(context.Background(), rt, &PathArgs{Dev: "/sys/class/net/eth0"}); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(runner.calls[0], wantPath) {
		t.Fatalf("path argv = %v (calls %d), want %v", runner.calls, len(runner.calls), wantPath)
	}

	rt, runner = newRT(map[string]process.CommandResult{
		strings.Join(wantName, " "): {Stdout: []byte(namePathLinksFixture)},
		strings.Join(wantPath, " "): {Stdout: []byte(namePathLinksFixture)},
	})
	if _, err := (linksFunc{}).Execute(context.Background(), rt, &LinksArgs{Dev: "/sys/class/net/eth0"}); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(runner.calls[0], wantPath) {
		t.Fatalf("links argv = %v (calls %d), want %v", runner.calls, len(runner.calls), wantPath)
	}
}

// TestNamePathLinksErrors keeps info's failure policy across all three
// wrappers: Runner errors pass through unchanged, nonzero exits echo
// udevadm stderr (Salt's CommandExecutionError), malformed E lines
// propagate the parser error, and an empty parse reports no device.
func TestNamePathLinksErrors(t *testing.T) {
	for _, fn := range []struct {
		name string
		run  func(*runtime.Runtime, string) (any, error)
	}{
		{"name", func(rt *runtime.Runtime, dev string) (any, error) {
			return (nameFunc{}).Execute(context.Background(), rt, &NameArgs{Dev: dev})
		}},
		{"path", func(rt *runtime.Runtime, dev string) (any, error) {
			return (pathFunc{}).Execute(context.Background(), rt, &PathArgs{Dev: dev})
		}},
		{"links", func(rt *runtime.Runtime, dev string) (any, error) {
			return (linksFunc{}).Execute(context.Background(), rt, &LinksArgs{Dev: dev})
		}},
	} {
		t.Run(fn.name, func(t *testing.T) {
			// Runner errors return as-is.
			runnerErr := errors.New("spawn udevadm: no such file")
			rt, _ := newRT(map[string]process.CommandResult{
				"udevadm info --export --query=all --name=/dev/x": {Err: runnerErr},
			})
			if _, err := fn.run(rt, "/dev/x"); !errors.Is(err, runnerErr) {
				t.Fatalf("runner err = %v, want passthrough of %v", err, runnerErr)
			}

			// Nonzero exits echo stderr, matching env/info.
			rt, _ = newRT(map[string]process.CommandResult{
				"udevadm info --export --query=all --name=/dev/x": {ExitCode: 1, Stderr: []byte("Unknown device")},
			})
			if _, err := fn.run(rt, "/dev/x"); err == nil || !strings.Contains(err.Error(), "Unknown device") {
				t.Fatalf("nonzero exit err = %v, want stderr echo", err)
			}

			// Parser errors propagate.
			rt, _ = newRT(map[string]process.CommandResult{
				"udevadm info --export --query=all --name=/dev/x": {Stdout: []byte("E: BROKEN\n\n")},
			})
			if _, err := fn.run(rt, "/dev/x"); err == nil {
				t.Fatal("malformed E line must fail")
			}

			// Empty parse reports the missing device.
			rt, _ = newRT(map[string]process.CommandResult{
				"udevadm info --export --query=all --name=/dev/x": {Stdout: []byte("")},
			})
			_, err := fn.run(rt, "/dev/x")
			if err == nil || err.Error() != "no device found for /dev/x" {
				t.Fatalf("empty parse err = %v, want no device found for /dev/x", err)
			}
		})
	}
}

func TestRegisterNames(t *testing.T) {
	rt, _ := newRT(nil)
	names := map[string]bool{}
	for _, name := range rt.Exec.Names() {
		names[name] = true
	}
	// The whole udev family is registered: env/info plus the exportdb and
	// name/path/links rounds.
	for _, planned := range []string{"udev.env", "udev.info", "udev.exportdb", "udev.name", "udev.path", "udev.links"} {
		if !names[planned] {
			t.Fatalf("missing %s registration", planned)
		}
	}
}

// TestParseInfoLineBoundarySemantics pins the exact LF-splitting behavior
// the incremental scanner must preserve: a trailing newline is a final
// empty segment, CRLF endings survive through trimming, a lone CR inside a
// line is not a boundary, and input without a trailing newline still
// flushes its record.
func TestParseInfoLineBoundarySemantics(t *testing.T) {
	devices, err := parseInfo("P: /a\nE: K=1\n")
	if err != nil || len(devices) != 1 {
		t.Fatalf("trailing newline = %#v, %v", devices, err)
	}

	devices, err = parseInfo("P: /a\nE: K=1")
	if err != nil || len(devices) != 1 {
		t.Fatalf("no trailing newline must still flush = %#v, %v", devices, err)
	}

	devices, err = parseInfo("P: /a\r\nE: K=1\r\n\r\n")
	if err != nil || len(devices) != 1 {
		t.Fatalf("CRLF endings = %#v, %v", devices, err)
	}
	if devices[0]["P"] != "/a" {
		t.Fatalf("CRLF P = %#v", devices[0]["P"])
	}
	env := devices[0]["E"].(map[string]any)
	if env["K"] != int64(1) {
		t.Fatalf("CRLF E = %#v", env)
	}

	devices, err = parseInfo("E: KEY=a\rb\n\n")
	if err != nil || len(devices) != 1 {
		t.Fatalf("lone CR is not a boundary = %#v, %v", devices, err)
	}
	if devices[0]["E"].(map[string]any)["KEY"] != "a\rb" {
		t.Fatalf("embedded CR must stay in the value: %#v", devices[0]["E"])
	}

	// Multiple consecutive blank lines flush once per blank; empty dev
	// flushes are no-ops.
	devices, err = parseInfo("P: /a\n\n\n\nP: /b\n\n")
	if err != nil || len(devices) != 2 {
		t.Fatalf("blank-line runs = %#v, %v", devices, err)
	}
}

// TestParseInfoRecordsCeilingBoundaries pins the record-ceiling contract:
// colonless noise and trailing blank lines after exactly 65,536 records
// stay acceptable (they never start a record), the next valid field line
// of a 65,537th record is rejected before that record is built, and a
// malformed E line reports the parser error rather than the record cap.
func TestParseInfoRecordsCeilingBoundaries(t *testing.T) {
	build := func(count int) string {
		var b strings.Builder
		for i := 0; i < count; i++ {
			b.WriteString("P: /d\n\n")
		}
		return b.String()
	}
	max := build(udevMaxRecords)

	withNoise := max + "just noise without a colon\n\n\n"
	devices, err := parseInfo(withNoise)
	if err != nil {
		t.Fatalf("noise and blanks after exactly %d records must parse: %v", udevMaxRecords, err)
	}
	if len(devices) != udevMaxRecords {
		t.Fatalf("records = %d, want %d", len(devices), udevMaxRecords)
	}

	over := max + "P: /extra\n"
	devices, err = parseInfo(over)
	if err != errUdevTooManyRecords {
		t.Fatalf("65,537th record err = %v, want the record-count limit", err)
	}
	if devices != nil {
		t.Fatalf("over-ceiling parse must return no partial records, got %d", len(devices))
	}

	malformedNext := max + "E: NO_EQUALS\n"
	if _, err = parseInfo(malformedNext); err != errUdevMalformedELine {
		t.Fatalf("malformed E on the next record err = %v, want the malformed-line error", err)
	}
}

// TestExportdbFilterCeilingsMatchDecoderTag ties the real ExportdbArgs
// tag ceilings to the module-side invariant: the agreed maximum
// (256 entries x 256 bytes) is accepted by BOTH the decoder and
// validateExportdbFilter, the decoder rejects 257 entries at input time,
// and the module rejects a directly supplied 257-entry filter.
func TestExportdbFilterCeilingsMatchDecoderTag(t *testing.T) {
	maxFilter := make([]string, exportdbFilterMaxEntries)
	for i := range maxFilter {
		maxFilter[i] = strings.Repeat("s", exportdbFilterMaxBytes)
	}

	args := &ExportdbArgs{}
	if err := config.Decode(args, map[string]any{"subsystems": toAny(maxFilter)}, nil); err != nil {
		t.Fatalf("decoder must accept the agreed 256x256 maximum: %v", err)
	}
	if args.Subsystems == nil || len(*args.Subsystems) != exportdbFilterMaxEntries {
		t.Fatalf("decoded maximum = %v", args.Subsystems)
	}
	if err := validateExportdbFilter(*args.Subsystems); err != nil {
		t.Fatalf("module invariant must accept the agreed maximum: %v", err)
	}

	over := append(append([]string(nil), maxFilter...), "one-too-many")
	if err := config.Decode(&ExportdbArgs{}, map[string]any{"subsystems": toAny(over)}, nil); err == nil {
		t.Fatal("decoder must reject 257 entries at input time")
	}
	if err := validateExportdbFilter(over); err != errExportdbFilterMax {
		t.Fatalf("module invariant err = %v, want the filter limit", err)
	}
}

func toAny(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

// TestParseInfoSizeCheckPrecedesLineChecks proves the 16 MiB input ceiling
// is rejected before any per-line work, even when the oversized input also
// contains an over-limit line.
func TestParseInfoSizeCheckPrecedesLineChecks(t *testing.T) {
	oversized := strings.Repeat("a", (16<<20)+1) + "\n" + strings.Repeat("b", (64<<10)+1) + "\n"
	devices, err := parseInfo(oversized)
	if err == nil {
		t.Fatalf("oversized input must fail, got %d records", len(devices))
	}
	if err != errUdevOutputTooLarge {
		t.Fatalf("err = %v, want the output-size error reported first", err)
	}
}

// exportdbRecorder deep-copies every process.Command it observes so the
// dispatch assertions compare the whole fixed command, not just argv.
type exportdbRecorder struct {
	commands []process.Command
	result   process.CommandResult
}

func (r *exportdbRecorder) Run(_ context.Context, cmd process.Command) process.CommandResult {
	c := cmd
	c.Args = append([]string(nil), cmd.Args...)
	c.Env = append([]string(nil), cmd.Env...)
	c.Redact = append([]string(nil), cmd.Redact...)
	r.commands = append(r.commands, c)
	return r.result
}

func newExportdbRT(result process.CommandResult) (*runtime.Runtime, *exportdbRecorder) {
	rec := &exportdbRecorder{result: result}
	return &runtime.Runtime{Runner: rec}, rec
}

func strPtrSlice(values ...string) *[]string {
	list := append([]string(nil), values...)
	return &list
}

// wantExportdbCommand is the exact fixed dispatch contract of exportdb.
var wantExportdbCommand = process.Command{
	Name:           "udevadm",
	Args:           []string{"info", "--export-db"},
	Env:            []string{"LC_ALL=C"},
	Timeout:        30 * time.Second,
	MaxStdoutBytes: 16 << 20,
	MaxStderrBytes: 64 << 10,
}

// TestExportdbDispatchesFixedCommandOnce asserts, for every filter mode,
// exactly one dispatch whose every field — name, argv, env, shell, timeout,
// and both capture budgets — matches the fixed contract, with no filter
// value leaking into argv or env.
func TestExportdbDispatchesFixedCommandOnce(t *testing.T) {
	for _, mode := range []struct {
		name       string
		subsystems *[]string
	}{
		{"nil filter", nil},
		{"empty filter", strPtrSlice()},
		{"valued filter", strPtrSlice("usb", "block", "MARKER-FILTER-VALUE")},
	} {
		t.Run(mode.name, func(t *testing.T) {
			rt, rec := newExportdbRT(process.CommandResult{
				ExitCode: 0,
				Stdout:   []byte(upstreamExportFixture),
			})
			if _, err := (exportdbFunc{}).Execute(context.Background(), rt,
				&ExportdbArgs{Subsystems: mode.subsystems}); err != nil {
				t.Fatal(err)
			}
			if len(rec.commands) != 1 {
				t.Fatalf("dispatch count = %d, want exactly 1", len(rec.commands))
			}
			got := rec.commands[0]
			if !reflect.DeepEqual(got, wantExportdbCommand) {
				t.Fatalf("command = %+v, want %+v", got, wantExportdbCommand)
			}
			for _, arg := range got.Args {
				if strings.Contains(arg, "MARKER-FILTER-VALUE") {
					t.Fatalf("filter value leaked into argv: %q", arg)
				}
			}
			for _, kv := range got.Env {
				if strings.Contains(kv, "MARKER-FILTER-VALUE") {
					t.Fatalf("filter value leaked into env: %q", kv)
				}
			}
		})
	}
}

// TestExportdbResults covers the success shapes: unfiltered passthrough of
// records without E, filter matching with order, case sensitivity,
// duplicate filter values not duplicating records, duplicate input records
// retained, empty filter selecting none, numeric SUBSYSTEM never matching a
// string filter, and an empty database returning a nonnil empty slice.
func TestExportdbResults(t *testing.T) {
	run := func(t *testing.T, stdout string, subsystems *[]string) ([]map[string]any, error) {
		t.Helper()
		rt, rec := newExportdbRT(process.CommandResult{ExitCode: 0, Stdout: []byte(stdout)})
		gotRaw, err := (exportdbFunc{}).Execute(context.Background(), rt,
			&ExportdbArgs{Subsystems: subsystems})
		if len(rec.commands) != 1 {
			t.Fatalf("dispatch count = %d, want 1", len(rec.commands))
		}
		if err != nil {
			return nil, err
		}
		got, ok := gotRaw.([]map[string]any)
		if !ok {
			t.Fatalf("exportdb result type = %T", gotRaw)
		}
		return got, nil
	}

	t.Run("unfiltered full fixture order", func(t *testing.T) {
		got, err := run(t, upstreamExportFixture, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 || got[0]["P"] != "/devices/LNXSYSTM:00/LNXPWRBN:00" ||
			got[2]["N"] != "input/event2" {
			t.Fatalf("unfiltered records = %#v", got)
		}
	})

	t.Run("records without E survive unfiltered", func(t *testing.T) {
		got, err := run(t, "P: /devices/no-env\n\nP: /devices/with\nE: SUBSYSTEM=block\n\n", nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("records = %#v", got)
		}
	})

	t.Run("empty database returns nonnil empty", func(t *testing.T) {
		got, err := run(t, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || len(got) != 0 {
			t.Fatalf("empty database = %#v, want nonnil empty", got)
		}
	})

	t.Run("filter match order and no-match", func(t *testing.T) {
		got, err := run(t, upstreamExportFixture, strPtrSlice("acpi", "usb"))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0]["P"] != "/devices/LNXSYSTM:00/LNXPWRBN:00" {
			t.Fatalf("filtered = %#v", got)
		}
		got, err = run(t, upstreamExportFixture, strPtrSlice("input"))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0]["P"] != "/devices/LNXSYSTM:00/LNXPWRBN:00/input/input2" ||
			got[1]["P"] != "/devices/LNXSYSTM:00/LNXPWRBN:00/input/input2/event2" {
			t.Fatalf("input filter = %#v", got)
		}
	})

	t.Run("case sensitive exact match", func(t *testing.T) {
		if got, err := run(t, upstreamExportFixture, strPtrSlice("ACPI", "Input")); err != nil || len(got) != 0 {
			t.Fatalf("case-insensitive match = %#v, %v", got, err)
		}
	})

	t.Run("duplicate filter values do not duplicate records", func(t *testing.T) {
		got, err := run(t, upstreamExportFixture, strPtrSlice("acpi", "acpi", "acpi"))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("repeated filter values duplicated records: %#v", got)
		}
	})

	t.Run("duplicate input records remain", func(t *testing.T) {
		dup := "P: /devices/a\nE: SUBSYSTEM=block\n\nP: /devices/a\nE: SUBSYSTEM=block\n\n"
		got, err := run(t, dup, strPtrSlice("block"))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("duplicate input records = %#v", got)
		}
	})

	t.Run("empty filter selects none but validates", func(t *testing.T) {
		got, err := run(t, upstreamExportFixture, strPtrSlice())
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || len(got) != 0 {
			t.Fatalf("empty filter = %#v, want validated nonnil empty", got)
		}
	})

	t.Run("numeric subsystem never matches string filter", func(t *testing.T) {
		numeric := "P: /devices/odd\nE: SUBSYSTEM=123\n\n"
		got, err := run(t, numeric, strPtrSlice("123"))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("numeric SUBSYSTEM matched a string filter: %#v", got)
		}
	})
}

// TestExportdbFilterMissingSections pins the source direct-index failure:
// with a filter active, a record without E, or an E without SUBSYSTEM,
// fails with the fixed filter error and a nil result.
func TestExportdbFilterMissingSections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stdout string
	}{
		{"record without E", "P: /devices/no-env\n\nP: /devices/ok\nE: SUBSYSTEM=block\n\n"},
		{"E without SUBSYSTEM", "P: /devices/x\nE: DEVNAME=/dev/x\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, _ := newExportdbRT(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.stdout)})
			got, err := (exportdbFunc{}).Execute(context.Background(), rt,
				&ExportdbArgs{Subsystems: strPtrSlice("block", "MARKER-FILTER-VALUE")})
			if err == nil {
				t.Fatal("expected filter failure")
			}
			if err.Error() != "udev.exportdb: subsystem filter failed" {
				t.Fatalf("err = %q", err)
			}
			if got != nil {
				t.Fatalf("filtered failure must return nil, got %#v", got)
			}
			// The same records pass unfiltered.
			rt2, _ := newExportdbRT(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.stdout)})
			if _, err := (exportdbFunc{}).Execute(context.Background(), rt2, &ExportdbArgs{}); err != nil {
				t.Fatalf("unfiltered must pass: %v", err)
			}
		})
	}
}

// TestExportdbFilterLimits proves the finite filter ceilings at cap and
// cap+1, and that limit violations fail before any dispatch.
func TestExportdbFilterLimits(t *testing.T) {
	mk := func(count, entryLen int) *[]string {
		entry := strings.Repeat("s", entryLen)
		list := make([]string, count)
		for i := range list {
			list[i] = entry
		}
		return &list
	}
	for _, tc := range []struct {
		name  string
		args  *[]string
		valid bool
	}{
		{"256 entries", mk(256, 1), true},
		{"257 entries", mk(257, 1), false},
		{"256 byte entry", mk(1, 256), true},
		{"257 byte entry", mk(1, 257), false},
		// 256 entries x 256 bytes = exactly the 64 KiB aggregate ceiling;
		// exceeding the aggregate without breaking the entry or count
		// ceiling is arithmetically impossible, so the aggregate check is
		// defense in depth and only its exact-cap validity is reachable.
		{"aggregate 64 KiB", mk(256, 256), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, rec := newExportdbRT(process.CommandResult{ExitCode: 0})
			_, err := (exportdbFunc{}).Execute(context.Background(), rt,
				&ExportdbArgs{Subsystems: tc.args})
			if tc.valid {
				if err != nil {
					t.Fatalf("valid filter rejected: %v", err)
				}
				if len(rec.commands) != 1 {
					t.Fatalf("valid filter dispatch = %d, want 1", len(rec.commands))
				}
				return
			}
			if err == nil {
				t.Fatal("invalid filter must fail")
			}
			if err.Error() != "udev.exportdb: subsystems exceed filter limit" {
				t.Fatalf("err = %q", err)
			}
			if len(rec.commands) != 0 {
				t.Fatalf("invalid args must dispatch zero times, got %d", len(rec.commands))
			}
		})
	}
}

// TestExportdbFailures covers every failure mode before parsing: nonzero
// exit, arbitrary Runner errors, parse failure, independent stdout/stderr
// truncation, cancellation, and deadline. Errors are fixed and value-free,
// preserve errors.Is only for the three safe sentinel identities, and the
// result is nil in every case.
func TestExportdbFailures(t *testing.T) {
	markerStdout := []byte("P: /MARKER-STDOUT-RECORD\nE: SUBSYSTEM=MARKER\n\n")
	for _, tc := range []struct {
		name string
		res  process.CommandResult
		// wantErr pins the exact fixed error text.
		wantErr string
		// isSentinels lists identities errors.Is must report.
		isSentinels []error
		// notSentinels lists identities errors.Is must not report.
		notSentinels []error
	}{
		{
			name: "nonzero exit",
			res: process.CommandResult{
				ExitCode: 1, Stdout: markerStdout, Stderr: []byte("MARKER-STDERR-CONTENT"),
			},
			wantErr: "udev.exportdb: command failed",
			notSentinels: []error{context.Canceled, context.DeadlineExceeded,
				process.ErrOutputLimit},
		},
		{
			name: "arbitrary runner error",
			res: process.CommandResult{
				ExitCode: -1, Stdout: markerStdout,
				Err: fmt.Errorf("spawn /MARKER/PATH/udevadm: MARKER-CAUSE-TEXT"),
			},
			wantErr: "udev.exportdb: command failed",
			notSentinels: []error{context.Canceled, context.DeadlineExceeded,
				process.ErrOutputLimit},
		},
		{
			name:    "parse failure",
			res:     process.CommandResult{ExitCode: 0, Stdout: []byte("E: MARKER-BROKEN-LINE\n")},
			wantErr: "udev.exportdb: failed to parse udev database",
			notSentinels: []error{context.Canceled, context.DeadlineExceeded,
				process.ErrOutputLimit},
		},
		{
			name: "stdout truncation with runner error",
			res: process.CommandResult{
				ExitCode: 0, StdoutTruncated: true,
				Err: fmt.Errorf("udevadm info --export-db: %w", process.ErrOutputLimit),
			},
			wantErr:     "udev.exportdb: command output exceeded limit",
			isSentinels: []error{process.ErrOutputLimit},
		},
		{
			name:        "stdout truncation flag only",
			res:         process.CommandResult{ExitCode: 0, StdoutTruncated: true},
			wantErr:     "udev.exportdb: command output exceeded limit",
			isSentinels: []error{process.ErrOutputLimit},
		},
		{
			name:        "stderr truncation flag only",
			res:         process.CommandResult{ExitCode: 0, StderrTruncated: true},
			wantErr:     "udev.exportdb: command output exceeded limit",
			isSentinels: []error{process.ErrOutputLimit},
		},
		{
			name: "cancellation",
			res: process.CommandResult{
				ExitCode: -1,
				Err:      fmt.Errorf("udevadm info --export-db canceled: %w", context.Canceled),
			},
			wantErr:      "udev.exportdb: command canceled",
			isSentinels:  []error{context.Canceled},
			notSentinels: []error{context.DeadlineExceeded, process.ErrOutputLimit},
		},
		{
			name: "deadline",
			res: process.CommandResult{
				ExitCode: -1,
				Err: fmt.Errorf("udevadm info --export-db timed out after 30s: %w",
					context.DeadlineExceeded),
			},
			wantErr:      "udev.exportdb: command deadline exceeded",
			isSentinels:  []error{context.DeadlineExceeded},
			notSentinels: []error{context.Canceled, process.ErrOutputLimit},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, rec := newExportdbRT(tc.res)
			got, err := (exportdbFunc{}).Execute(context.Background(), rt,
				&ExportdbArgs{Subsystems: strPtrSlice("MARKER-FILTER-VALUE")})
			if err == nil {
				t.Fatal("expected failure")
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("err = %q, want %q", err, tc.wantErr)
			}
			if got != nil {
				t.Fatalf("failure must return nil result, got %#v", got)
			}
			if len(rec.commands) != 1 {
				t.Fatalf("dispatch = %d, want exactly 1", len(rec.commands))
			}
			for _, marker := range []string{
				"MARKER-STDOUT-RECORD", "MARKER-STDERR-CONTENT", "MARKER-CAUSE-TEXT",
				"/MARKER/PATH", "MARKER-FILTER-VALUE", "MARKER-BROKEN-LINE",
			} {
				if strings.Contains(err.Error(), marker) {
					t.Fatalf("error leaked marker %q: %v", marker, err)
				}
			}
			for _, sentinel := range tc.isSentinels {
				if !errors.Is(err, sentinel) {
					t.Fatalf("errors.Is(err, %v) = false, want true", sentinel)
				}
			}
			for _, sentinel := range tc.notSentinels {
				if errors.Is(err, sentinel) {
					t.Fatalf("errors.Is(err, %v) = true, want false", sentinel)
				}
			}
		})
	}
}

// TestExportdbOutputPrecheck rejects stdout above the 16 MiB capture
// budget before any parsing, with the fixed value-free error.
func TestExportdbOutputPrecheck(t *testing.T) {
	rt, rec := newExportdbRT(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(strings.Repeat("\n", (16<<20)+1)),
	})
	got, err := (exportdbFunc{}).Execute(context.Background(), rt, &ExportdbArgs{})
	if err == nil {
		t.Fatal("oversized stdout must fail")
	}
	if err.Error() != "udev.exportdb: udev database output exceeds limit" {
		t.Fatalf("err = %q", err)
	}
	if got != nil {
		t.Fatalf("oversized stdout must return nil, got %#v", got)
	}
	if len(rec.commands) != 1 {
		t.Fatalf("dispatch = %d, want 1 (check happens after the run)", len(rec.commands))
	}
}
