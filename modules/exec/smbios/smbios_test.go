package smbios

import (
	"context"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct {
	results map[string]process.CommandResult
	calls   []string
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	f.calls = append(f.calls, cmd.Name)
	if res, ok := f.results[cmd.Name]; ok {
		return res
	}
	return process.CommandResult{}
}

const dmiDump = `# dmidecode 3.3
Getting SMBIOS data from sysfs.
Handle 0x0002, DMI type 2, 8 bytes
Base Board Information
	Manufacturer: Supermicro
	Product Name: X11SCH-F
	Serial Number: 0123456789
	Version: 1.01

Handle 0x0004, DMI type 4, 42 bytes
Processor Information
	Socket Designation: CPU 1
	Family: Core i5
	Core Count: 6
	Current Speed: 3600 MHz
	Serial Number: Not Specified
	Signature: Type 0, Family 6, Model 158

Handle 0x0012, DMI type 13, 22 bytes
BIOS Language Information
	Installable Languages: 2
		en-US
		fr-FR
	Currently Installed Language: en-US

Handle 0x000B, DMI type 11, 5 bytes
OEM Strings
	String 1: To Be Filled By O.E.M.
`

func newRT(t *testing.T, results map[string]process.CommandResult) (*runtime.Runtime, *fakeRunner) {
	t.Helper()
	saved := dmiBin
	dmiBin = func() string { return "/usr/sbin/dmidecode" }
	t.Cleanup(func() { dmiBin = saved })
	runner := &fakeRunner{results: results}
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Runner: runner,
	}
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return rt, runner
}

// Source-derived contract for records(): handle splitting, key
// normalization, list continuation, numeric casting, and clean filtering.
func TestRecords(t *testing.T) {
	rt, runner := newRT(t, map[string]process.CommandResult{
		"/usr/sbin/dmidecode": {Stdout: []byte(dmiDump)},
	})

	gotRaw, err := (recordsFunc{}).Execute(context.Background(), rt, &RecordsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	records := gotRaw.([]any)
	if len(records) != 3 {
		t.Fatalf("record count = %d (%v)", len(records), records)
	}

	board := records[0].(map[string]any)
	if board["handle"] != "0x0002" || board["type"] != int64(2) ||
		board["description"] != "Base Board Information" {
		t.Fatalf("board header = %#v", board)
	}
	data := board["data"].(map[string]any)
	if data["manufacturer"] != "Supermicro" || data["product_name"] != "X11SCH-F" ||
		data["version"] != "1.01" {
		t.Fatalf("board data = %#v", data)
	}
	// Serial 0123456789 trips the sequential-digits filter under clean.
	if _, has := data["serial_number"]; has {
		t.Fatalf("dirty serial must be cleaned out: %#v", data)
	}

	cpu := records[1].(map[string]any)
	cpuData := cpu["data"].(map[string]any)
	// "3600 MHz" fails int() upstream and stays a string.
	if cpuData["family"] != "Core i5" || cpuData["core_count"] != int64(6) ||
		cpuData["current_speed"] != "3600 MHz" {
		t.Fatalf("cpu data = %#v", cpuData)
	}
	if _, has := cpuData["serial_number"]; has {
		t.Fatalf("'Not Specified' serial must be cleaned: %#v", cpuData)
	}

	langs := records[2].(map[string]any)
	langData := langs["data"].(map[string]any)
	// Upstream inserts the scalar value on top of the continuation list
	// when both exist ("On the rare occasion..." comment).
	installable, ok := langData["installable_languages"].([]any)
	if !ok || !reflect.DeepEqual(installable, []any{int64(2), "en-US", "fr-FR"}) {
		t.Fatalf("list continuation = %#v", langData["installable_languages"])
	}

	for _, call := range runner.calls {
		if call == "/usr/sbin/dmidecode -t 4" {
			t.Fatal("no -t expected without rec_type")
		}
	}
}

// rec_type narrows the query argv; fields filters keys; clean=False keeps
// dirty values and empty records.
func TestRecordsTypeFieldsAndUnclean(t *testing.T) {
	rt, runner := newRT(t, map[string]process.CommandResult{
		"/usr/sbin/dmidecode":      {Stdout: []byte(dmiDump)},
		"/usr/sbin/dmidecode -t 4": {Stdout: []byte(dmiDump)},
	})

	recType := "4"
	fields := []string{"family"}
	gotRaw, err := (recordsFunc{}).Execute(context.Background(), rt, &RecordsArgs{
		RecType: &recType, Fields: fields,
	})
	if err != nil {
		t.Fatal(err)
	}
	records := gotRaw.([]any)
	if len(records) != 1 {
		t.Fatalf("filtered record count = %d", len(records))
	}
	cpuData := records[0].(map[string]any)["data"].(map[string]any)
	if len(cpuData) != 1 || cpuData["family"] != "Core i5" {
		t.Fatalf("fields filter = %#v", cpuData)
	}
	found := false
	for _, call := range runner.calls {
		if call == "/usr/sbin/dmidecode -t 4" {
			found = true
		}
	}
	if !found {
		t.Fatalf("-t argv missing: %v", runner.calls)
	}

	cleanFalse := false
	gotRaw, err = (recordsFunc{}).Execute(context.Background(), rt, &RecordsArgs{Clean: &cleanFalse})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotRaw.([]any)) < 3 {
		t.Fatalf("clean=false must keep everything parseable: %#v", gotRaw)
	}
}

// Mirrors the get() flow: comment filtering, /dev/mem guard, and the
// clean filter returning nil.
func TestGet(t *testing.T) {
	rt, _ := newRT(t, map[string]process.CommandResult{
		"/usr/sbin/dmidecode -s system-serial-number":   {Stdout: []byte("/dev/mem: Permission denied\n")},
		"/usr/sbin/dmidecode -s system-uuid":            {Stdout: []byte("03000200-0400-0500-0006-000700080009\n")},
		"/usr/sbin/dmidecode -s baseboard-product-name": {Stdout: []byte("# trailing comment\nX11SCH-F\n")},
		"/usr/sbin/dmidecode -s bios-vendor":            {Stdout: []byte("American Megaminds\n")},
	})

	gf := getFunc{}

	// /dev/mem output becomes nil regardless of clean.
	got, err := gf.Execute(context.Background(), rt, &GetArgs{String: "system-serial-number"})
	if err != nil || got != nil {
		t.Fatalf("/dev/mem guard = %#v, %v", got, err)
	}

	// Invalid UUID is nil under clean, present under clean=False.
	uuid := "03000200-0400-0500-0006-000700080009"
	got, err = gf.Execute(context.Background(), rt, &GetArgs{String: "system-uuid"})
	if err != nil || got != nil {
		t.Fatalf("invalid uuid clean = %#v, %v", got, err)
	}
	cleanFalse := false
	got, err = gf.Execute(context.Background(), rt, &GetArgs{String: "system-uuid", Clean: &cleanFalse})
	if err != nil || got != uuid {
		t.Fatalf("invalid uuid unclean = %#v, %v", got, err)
	}

	// Comments are stripped before the value surfaces.
	got, err = gf.Execute(context.Background(), rt, &GetArgs{String: "baseboard-product-name"})
	if err != nil || got != "X11SCH-F" {
		t.Fatalf("comment cleanup = %#v, %v", got, err)
	}

	got, err = gf.Execute(context.Background(), rt, &GetArgs{String: "bios-vendor"})
	if err != nil || got != "American Megaminds" {
		t.Fatalf("plain get = %#v, %v", got, err)
	}
}

func TestDmiIsClean(t *testing.T) {
	cases := []struct {
		key, val string
		want     bool
	}{
		{"manufacturer", "Supermicro", true},
		{"manufacturer", "To Be Filled By O.E.M.", false},
		{"manufacturer", "Manufacturer04", false},
		{"asset_tag", "NoNe", false},
		{"serial_number", "0000000000", false},
		{"serial_number", "123456789", false},
		{"serial_number", "WX12CD34", true},
		{"version", "Not Applicable", false},
		{"uuid", "03000200-0400-0500-0006-000700080009", false},
		{"uuid", "e5faeb17-b0f7-4118-9c9b-a5e9f7b7d9c4", true},
		{"family", "", false},
		{"family", "unknown asset present", false},
		{"family", "Core i5", true},
	}
	for _, c := range cases {
		if got := dmiIsClean(c.key, c.val); got != c.want {
			t.Errorf("isclean(%q,%q) = %v, want %v", c.key, c.val, got, c.want)
		}
	}
}

func TestRegisterNames(t *testing.T) {
	rt, _ := newRT(t, nil)
	names := map[string]bool{}
	for _, name := range rt.Exec.Names() {
		names[name] = true
	}
	for _, want := range []string{"smbios.get", "smbios.records"} {
		if !names[want] {
			t.Errorf("missing registration %s", want)
		}
	}
}
