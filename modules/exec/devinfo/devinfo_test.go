package devinfo

import (
	"context"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execudev "github.com/friz-zy/statekit/modules/exec/udev"
)

type fakeDelegate struct {
	name string
	run  func(args any) (any, error)
}

func (f *fakeDelegate) Name() string { return f.name }
func (f *fakeDelegate) Args() any    { return struct{}{} }
func (f *fakeDelegate) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	return f.run(args)
}

// Mirrors test_udev.
func TestUdevKey(t *testing.T) {
	info := map[string]any{"A": map[string]any{"B": 1}}
	cases := []struct {
		key  string
		want any
	}{
		{"a.b", 1},
		{"A.B", 1},
		{"a.c", "n/a"},
		{"", info},
	}
	for _, c := range cases {
		if got := udevKey(info, c.key); !reflect.DeepEqual(got, c.want) {
			t.Fatalf("udevKey(%q) = %#v, want %#v", c.key, got, c.want)
		}
	}
	// A list node reads "n/a" like the non-dict guard.
	if got := udevKey(map[string]any{"A": []any{1, 2}}, "a.b"); got != "n/a" {
		t.Fatalf("list node = %#v", got)
	}
}

// Mirrors test_match.
func TestMatch(t *testing.T) {
	info := map[string]any{"A": map[string]any{"B": 1}}
	if !match(info, map[string]any{"a.b": 1}) {
		t.Fatal("1 matches 1")
	}
	if match(info, map[string]any{"a.b": 2}) {
		t.Fatal("2 must not match 1")
	}
	if !match(info, map[string]any{"a.b": []any{1, 2}}) {
		t.Fatal("list overlap")
	}
	if match(info, map[string]any{"a.b": []any{2, 3}}) {
		t.Fatal("no list overlap")
	}
	listInfo := map[string]any{"A": map[string]any{"B": []any{1, 2}}}
	if !match(listInfo, map[string]any{"a.b": 1}) {
		t.Fatal("scalar in list")
	}
	if !match(listInfo, map[string]any{"a.b": []any{1, 3}}) {
		t.Fatal("partial list overlap")
	}
	if match(listInfo, map[string]any{"a.b": []any{3, 4}}) {
		t.Fatal("disjoint lists")
	}
	if !match(info, map[string]any{}) {
		t.Fatal("empty match always true")
	}
}

// Mirrors test_devices through the registry with a udev.info delegate.
func TestFilter(t *testing.T) {
	cdrom := map[string]any{"S": []any{"dvd", "cdrom"}, "E": map[string]any{"ID_BUS": "ata"}}
	usb := map[string]any{"E": map[string]any{"ID_BUS": "usb"}}
	hd := map[string]any{"E": map[string]any{"ID_BUS": "ata"}}

	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
	}
	if err := rt.Exec.Register(&fakeDelegate{
		name: "udev.info",
		run: func(args any) (any, error) {
			dev := args.(*execudev.InfoArgs).Dev
			return map[string]map[string]any{"sda": hd, "sdb": usb, "sr0": cdrom}[dev], nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	saved := disksHook
	disksHook = func(*runtime.Runtime) []string { return []string{"sda", "sdb", "sr0"} }
	t.Cleanup(func() { disksHook = saved })
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}

	ff := filterFunc{}
	gotRaw, err := ff.Execute(context.Background(), rt, &FilterArgs{
		UdevIn: map[string]any{"e.id_bus": "ata"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotRaw, []any{"sda", "sr0"}) {
		t.Fatalf("ata devices = %#v", gotRaw)
	}

	gotRaw, err = ff.Execute(context.Background(), rt, &FilterArgs{
		UdevIn: map[string]any{"e.id_bus": "usb"},
	})
	if err != nil || !reflect.DeepEqual(gotRaw, []any{"sdb"}) {
		t.Fatalf("usb devices = %#v, %v", gotRaw, err)
	}

	gotRaw, err = ff.Execute(context.Background(), rt, &FilterArgs{
		UdevIn: map[string]any{"e.id_bus": "ata"},
		UdevEx: map[string]any{"s": []string{"cdrom"}},
	})
	if err != nil || !reflect.DeepEqual(gotRaw, []any{"sda"}) {
		t.Fatalf("excluded cdrom = %#v, %v", gotRaw, err)
	}
}

// Mirrors test__hwinfo_parse_short.
func TestParseShort(t *testing.T) {
	report := "\n" +
		"cpu:\n" +
		"                       QEMU Virtual CPU version 2.5+, 3591 MHz\n" +
		"keyboard:\n" +
		"  /dev/input/event0    AT Translated Set 2 keyboard\n" +
		"mouse:\n" +
		"  /dev/input/mice      VirtualPS/2 VMware VMMouse\n" +
		"  /dev/input/mice      VirtualPS/2 VMware VMMouse\n" +
		"network:\n" +
		"  ens3                 Virtio Ethernet Card 0\n" +
		"disk:\n" +
		"  /dev/fd0             Disk\n" +
		"  /dev/sda             QEMU HARDDISK\n" +
		"bios:\n" +
		"                       BIOS\n"
	got := parseShort(report)
	want := map[string]any{
		"cpu":      map[string]any{"0": "QEMU Virtual CPU version 2.5+, 3591 MHz"},
		"keyboard": map[string]any{"/dev/input/event0": "AT Translated Set 2 keyboard"},
		// Duplicate keys collapse to the last value, matching the dict
		// semantics of upstream's parser.
		"mouse":   map[string]any{"/dev/input/mice": "VirtualPS/2 VMware VMMouse"},
		"network": map[string]any{"ens3": "Virtio Ethernet Card 0"},
		"disk":    map[string]any{"/dev/fd0": "Disk", "/dev/sda": "QEMU HARDDISK"},
		"bios":    map[string]any{"0": "BIOS"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("short = %#v, want %#v", got, want)
	}
}

// Numeric keys are strings in Go maps; mirror via sorted comparison.
func TestParseShortNumericKeys(t *testing.T) {
	report := "storage:\n" +
		"                       Floppy disk controller\n" +
		"                       Red Hat Qemu virtual machine\n" +
		"unknown:\n" +
		"                       FPU\n" +
		"  /dev/lp0             Parallel controller\n" +
		"                       PS/2 Controller\n" +
		"  /dev/ttyS0           16550A\n"
	got := parseShort(report)
	storage := got["storage"].(map[string]any)
	if storage["0"] != "Floppy disk controller" || storage["1"] != "Red Hat Qemu virtual machine" {
		t.Fatalf("numeric keys = %#v", storage)
	}
	unknown := got["unknown"].(map[string]any)
	if unknown["0"] != "FPU" || unknown["/dev/lp0"] != "Parallel controller" ||
		unknown["1"] != "PS/2 Controller" || unknown["/dev/ttyS0"] != "16550A" {
		t.Fatalf("mixed keys = %#v", unknown)
	}
}

// Mirrors test__hwinfo_parse_full_floppy.
func TestParseFullFloppy(t *testing.T) {
	report := "\n" +
		"01: None 00.0: 0102 Floppy disk controller\n" +
		"  [Created at floppy.112]\n" +
		"  Unique ID: rdCR.3wRL2_g4d2B\n" +
		"  Hardware Class: storage\n" +
		"  Model: \"Floppy disk controller\"\n" +
		"  I/O Port: 0x3f2 (rw)\n" +
		"  I/O Ports: 0x3f4-0x3f5 (rw)\n" +
		"  I/O Port: 0x3f7 (rw)\n" +
		"  DMA: 2\n" +
		"  Config Status: cfg=new, avail=yes, need=no, active=unknown\n" +
		"\n" +
		"02: Floppy 00.0: 10603 Floppy Disk\n" +
		"  [Created at floppy.127]\n" +
		"  Unique ID: sPPV.oZ89vuho4Y3\n" +
		"  Parent ID: rdCR.3wRL2_g4d2B\n" +
		"  Hardware Class: floppy\n" +
		"  Model: \"Floppy Disk\"\n" +
		"  Device File: /dev/fd0\n" +
		"  Size: 3.5 ''\n" +
		"  Config Status: cfg=new, avail=yes, need=no, active=unknown\n" +
		"  Size: 5760 sectors a 512 bytes\n" +
		"  Capacity: 0 GB (2949120 bytes)\n" +
		"  Drive status: no medium\n" +
		"  Config Status: cfg=new, avail=yes, need=no, active=unknown\n" +
		"  Attached to: #1 (Floppy disk controller)\n"

	got := parseFull(report)

	first, ok := got["01"].(map[string]any)
	if !ok {
		t.Fatalf("01 section = %#v", got["01"])
	}
	if first["None 00.0"] != "0102 Floppy disk controller" ||
		first["Note"] != "Created at floppy.112" ||
		first["Model"] != "Floppy disk controller" ||
		first["DMA"] != "2" {
		t.Fatalf("01 fields = %#v", first)
	}
	if !reflect.DeepEqual(first["I/O Ports"], []any{"0x3f2 (rw)", "0x3f4-0x3f5 (rw)", "0x3f7 (rw)"}) {
		t.Fatalf("I/O Ports merge = %#v", first["I/O Ports"])
	}
	if !reflect.DeepEqual(first["Config Status"], map[string]any{
		"cfg": "new", "avail": "yes", "need": "no", "active": "unknown",
	}) {
		t.Fatalf("Config Status = %#v", first["Config Status"])
	}

	second, ok := got["02"].(map[string]any)
	if !ok {
		t.Fatalf("02 section = %#v", got["02"])
	}
	if second["Model"] != "Floppy Disk" || second["Device File"] != "/dev/fd0" ||
		second["Capacity"] != "0 GB (2949120 bytes)" {
		t.Fatalf("02 fields = %#v", second)
	}
	if !reflect.DeepEqual(second["Size"], []any{"3.5 ''", "5760 sectors a 512 bytes"}) {
		t.Fatalf("Size collision = %#v", second["Size"])
	}
	if !reflect.DeepEqual(second["Attached to"], map[string]any{
		"Handle": "#1 (Floppy disk controller)",
	}) {
		t.Fatalf("Attached to = %#v", second["Attached to"])
	}
}

func TestHwinfoGrainSections(t *testing.T) {
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Runner: fakeHwinfoRunner{},
	}
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	savedEfi, savedMem, savedFqdn := efiHook, memTotalHook, fqdnHook
	efiHook = func(*runtime.Runtime) bool { return false }
	memTotalHook = func(*runtime.Runtime) int64 { return 3952 }
	fqdnHook = func(*runtime.Runtime) string { return "mini.example.internal" }
	t.Cleanup(func() {
		efiHook, memTotalHook, fqdnHook = savedEfi, savedMem, savedFqdn
	})

	short := true
	retRaw, err := hwinfoFunc{}.Execute(context.Background(), rt, &HwinfoArgs{
		Items: []string{"memory"}, Short: &short,
	})
	if err != nil {
		t.Fatal(err)
	}
	ret := retRaw.(map[string]any)
	memory := ret["memory grains"].(map[string]any)
	if memory["mem_total"] != int64(3952) {
		t.Fatalf("mem grain = %#v", memory)
	}
	if _, hasNetwork := ret["network grains"]; hasNetwork {
		t.Fatal("unselected items must not appear")
	}
}

type fakeHwinfoRunner struct{}

func (fakeHwinfoRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	return process.CommandResult{}
}
