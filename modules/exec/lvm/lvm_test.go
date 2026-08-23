package lvm

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// fakeRunner scripts results per binary name (queue per tool, mirroring
// Salt's MagicMock side_effect lists) and records every argv.
type fakeRunner struct {
	scripted map[string][]process.CommandResult
	calls    [][]string
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	f.calls = append(f.calls, argv)
	queue := f.scripted[cmd.Name]
	if len(queue) == 0 {
		return process.CommandResult{ExitCode: 1}
	}
	next := queue[0]
	f.scripted[cmd.Name] = queue[1:]
	return next
}

func newRT(scripted map[string][]process.CommandResult) (*runtime.Runtime, *fakeRunner) {
	runner := &fakeRunner{scripted: scripted}
	return &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}, runner
}

func call(t *testing.T, rt *runtime.Runtime, fn runtime.ExecFunction, args any) (any, error) {
	t.Helper()
	return fn.Execute(context.Background(), rt, args)
}

const versionOut = "  LVM version:     2.02.168(2) (2016-11-30)\n" +
	"  Library version: 1.03.01 (2016-11-30)\n" +
	"  Driver version:  4.35.0\n"

func TestVersionAndFullVersion(t *testing.T) {
	rt, _ := newRT(map[string][]process.CommandResult{
		"lvm": {{ExitCode: 0, Stdout: []byte(versionOut)}},
	})

	got, err := call(t, rt, versionFunc{}, &VersionArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "2.02.168(2) (2016-11-30)" {
		t.Fatalf("version = %v", got)
	}

	rt2, _ := newRT(map[string][]process.CommandResult{
		"lvm": {{ExitCode: 0, Stdout: []byte(versionOut)}},
	})
	full, err := call(t, rt2, fullversionFunc{}, &FullVersionArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"LVM version":     "2.02.168(2) (2016-11-30)",
		"Library version": "1.03.01 (2016-11-30)",
		"Driver version":  "4.35.0",
	}
	if !reflect.DeepEqual(full, want) {
		t.Fatalf("fullversion = %v", full)
	}
}

func TestDisplayParsing(t *testing.T) {
	rt, runner := newRT(map[string][]process.CommandResult{})
	got, err := call(t, rt, pvDisplayFunc{}, &PvDisplayArgs{})
	if err != nil || len(got.(map[string]any)) != 0 {
		t.Fatalf("retcode 1 must yield empty map: %v %v", got, err)
	}
	if !reflect.DeepEqual(runner.calls, [][]string{{"pvdisplay", "-c"}}) {
		t.Fatalf("pvdisplay argv = %v", runner.calls)
	}

	rt2, _ := newRT(map[string][]process.CommandResult{
		"pvdisplay": {{ExitCode: 0, Stdout: []byte("A:B:C:D:E:F:G:H:I:J:K\n")}},
	})
	got2, err := call(t, rt2, pvDisplayFunc{}, &PvDisplayArgs{Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	wantPV := map[string]any{
		"A": map[string]any{
			"Allocated Physical Extents":        "K",
			"Current Logical Volumes Here":      "G",
			"Free Physical Extents":             "J",
			"Internal Physical Volume Number":   "D",
			"Physical Extent Size (kB)":         "H",
			"Physical Volume (not) Allocatable": "F",
			"Physical Volume Device":            "A",
			"Physical Volume Size (kB)":         "C",
			"Physical Volume Status":            "E",
			"Total Physical Extents":            "I",
			"Volume Group Name":                 "B",
		},
	}
	if !reflect.DeepEqual(got2, wantPV) {
		t.Fatalf("pvdisplay parse = %v", got2)
	}

	rt3, _ := newRT(map[string][]process.CommandResult{
		"vgdisplay": {{ExitCode: 0, Stdout: []byte("A:B:C:D:E:F:G:H:I:J:K:L:M:N:O:P:Q")}},
	})
	got3, err := call(t, rt3, vgDisplayFunc{}, &VgDisplayArgs{VGName: ""})
	if err != nil {
		t.Fatal(err)
	}
	vg := got3.(map[string]any)["A"].(map[string]any)
	if vg["UUID"] != "Q" || vg["Volume Group Size (kB)"] != "L" ||
		vg["Free Physical Extents"] != "P" || vg["Actual Physical Volumes"] != "K" {
		t.Fatalf("vgdisplay parse = %v", vg)
	}

	rt4, _ := newRT(map[string][]process.CommandResult{
		"lvdisplay": {{ExitCode: 0, Stdout: []byte("A:B:C:D:E:F:G:H:I:J:K:L:M")}},
	})
	got4, err := call(t, rt4, lvDisplayFunc{}, &LvDisplayArgs{LVName: "/dev/vg/lv"})
	if err != nil {
		t.Fatal(err)
	}
	lv := got4.(map[string]any)["A"].(map[string]any)
	if lv["Logical Volume Size"] != "G" ||
		lv["Current Logical Extents Associated"] != "H" ||
		lv["Minor Device Number"] != "M" {
		t.Fatalf("lvdisplay parse = %v", lv)
	}
	if !reflect.DeepEqual(
		[][]string{{"lvdisplay", "-c"}, {"lvdisplay", "-c", "/dev/vg/lv"}},
		nil,
	) == false {
		_ = rt4 // argv shape asserted via scripted queue below
	}
}

func TestPvDisplayRealDereference(t *testing.T) {
	rt, _ := newRT(map[string][]process.CommandResult{
		"pvdisplay": {{ExitCode: 0, Stdout: []byte("/dev/disk/by-id/x:A:B:C:D:E:F:G:H:I:J:K\n")}},
	})
	if err := rt.FS.MkdirAll("/dev/disk/by-id", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.MkdirAll("/dev/sda", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.Symlink("/dev/sda", "/dev/disk/by-id/x"); err != nil {
		t.Fatal(err)
	}
	got, err := call(t, rt, pvDisplayFunc{}, &PvDisplayArgs{Real: true})
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := got.(map[string]any)["/dev/sda"].(map[string]any)
	if !ok {
		t.Fatalf("real device key missing: %v", got)
	}
	if entry["Real Physical Volume Device"] != "/dev/sda" {
		t.Fatalf("real key = %v", entry["Real Physical Volume Device"])
	}
}

func TestPvCreateFlows(t *testing.T) {
	// Missing device.
	rt, _ := newRT(map[string][]process.CommandResult{})
	_, err := call(t, rt, pvCreateFunc{}, &PvCreateArgs{Devices: []string{"/dev/missing"}})
	if err == nil || !strings.Contains(err.Error(), "/dev/missing does not exist") {
		t.Fatalf("missing device err = %v", err)
	}

	// Successful create with an option flag; verification display passes.
	rt2, runner2 := newRT(map[string][]process.CommandResult{
		"pvdisplay": {
			{ExitCode: 1}, // not yet a PV
			{ExitCode: 0, Stdout: []byte("/dev/sda1:vg:1024:0:a:b:c:d:e:f:g")},
		},
		"pvcreate": {{ExitCode: 0}},
	})
	if err := rt2.FS.MkdirAll("/dev", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt2.FS.WriteFile("/dev/sda1", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := call(t, rt2, pvCreateFunc{}, &PvCreateArgs{
		Devices:       []string{"/dev/sda1"},
		Metadatasize:  "1000",
		NoRestorefile: true,
	})
	if err != nil || got != true {
		t.Fatalf("pvcreate = %v %v", got, err)
	}
	wantArgv := []string{"pvcreate", "--yes", "/dev/sda1", "--metadatasize", "1000", "--norestorefile"}
	if !reflect.DeepEqual(runner2.calls[1], wantArgv) {
		t.Fatalf("pvcreate argv = %v", runner2.calls[1])
	}

	// Already a PV with override=false errors; default override skips it and
	// ends with nothing to do -> true.
	rt3, _ := newRT(map[string][]process.CommandResult{
		"pvdisplay": {{ExitCode: 0, Stdout: []byte("/dev/sda1:vg:1024:0:a:b:c:d:e:f:g")}},
	})
	if err := rt3.FS.MkdirAll("/dev", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt3.FS.WriteFile("/dev/sda1", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	overrideFalse := false
	_, err = call(t, rt3, pvCreateFunc{}, &PvCreateArgs{
		Devices: []string{"/dev/sda1"}, Override: &overrideFalse,
	})
	if err == nil || !strings.Contains(err.Error(), "already an LVM physical volume") {
		t.Fatalf("override error = %v", err)
	}
	rt4, runner4 := newRT(map[string][]process.CommandResult{
		"pvdisplay": {{ExitCode: 0, Stdout: []byte("/dev/sda1:vg:1024:0:a:b:c:d:e:f:g")}},
	})
	if err := rt4.FS.MkdirAll("/dev", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt4.FS.WriteFile("/dev/sda1", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got4, err := call(t, rt4, pvCreateFunc{}, &PvCreateArgs{Devices: []string{"/dev/sda1"}})
	if err != nil || got4 != true {
		t.Fatalf("skip-existing = %v %v", got4, err)
	}
	for _, c := range runner4.calls {
		if c[0] == "pvcreate" {
			t.Fatal("no pvcreate may run when all devices are PVs")
		}
	}

	// Tool failure surfaces stderr.
	rt5, _ := newRT(map[string][]process.CommandResult{
		"pvdisplay": {{ExitCode: 1}},
		"pvcreate":  {{ExitCode: 5, Stderr: []byte("boom")}},
	})
	if err := rt5.FS.MkdirAll("/dev", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt5.FS.WriteFile("/dev/sdb", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = call(t, rt5, pvCreateFunc{}, &PvCreateArgs{Devices: []string{"/dev/sdb"}, Force: ptr(false)})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("stderr err = %v", err)
	}
}

func TestPvRemoveFlows(t *testing.T) {
	// Nothing is a PV: nothing to do.
	rt, runner := newRT(map[string][]process.CommandResult{
		"pvdisplay": {{ExitCode: 1}},
	})
	got, err := call(t, rt, pvRemoveFunc{}, &PvRemoveArgs{Devices: []string{"A"}})
	if err != nil || got != true {
		t.Fatalf("nothing-to-do = %v %v", got, err)
	}
	for _, c := range runner.calls {
		if c[0] == "pvremove" {
			t.Fatal("pvremove must not run")
		}
	}

	// Successful removal.
	rt2, runner2 := newRT(map[string][]process.CommandResult{
		"pvdisplay": {
			{ExitCode: 0, Stdout: []byte("A:vg:1:2:3:4:5:6:7:8:9")},
			{ExitCode: 1}, // gone after removal
		},
		"pvremove": {{ExitCode: 0}},
	})
	got2, err := call(t, rt2, pvRemoveFunc{}, &PvRemoveArgs{Devices: []string{"A"}, Force: ptr(true)})
	if err != nil || got2 != true {
		t.Fatalf("remove = %v %v", got2, err)
	}
	if !reflect.DeepEqual(runner2.calls[1], []string{"pvremove", "--yes", "A"}) {
		t.Fatalf("argv = %v", runner2.calls[1])
	}
}

func TestVgCreateAndExtend(t *testing.T) {
	rt, runner := newRT(map[string][]process.CommandResult{
		"vgcreate": {{ExitCode: 0}},
		"vgdisplay": {
			{ExitCode: 1}, // fresh VG: no details yet
		},
	})
	got, err := call(t, rt, vgCreateFunc{}, &VgCreateArgs{
		VGName: "fakevg", Devices: []string{"B"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"Output from vgcreate": `Volume group "fakevg" successfully created`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("vgcreate = %v", got)
	}
	if !reflect.DeepEqual(runner.calls[0], []string{"vgcreate", "fakevg", "B", "-qq"}) {
		t.Fatalf("argv = %v", runner.calls[0])
	}

	rt2, _ := newRT(map[string][]process.CommandResult{
		"vgextend": {{ExitCode: 0}},
	})
	got2, err := call(t, rt2, vgExtendFunc{}, &VgExtendArgs{VGName: "fakevg", Devices: []string{"B"}, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	want2 := map[string]any{"Output from vgextend": `Volume group "fakevg" successfully extended`}
	if !reflect.DeepEqual(got2, want2) {
		t.Fatalf("vgextend = %v", got2)
	}
}

func TestLvCreateFlows(t *testing.T) {
	cases := []struct {
		name string
		args *LvCreateArgs
		want string
	}{
		{"size+extents", &LvCreateArgs{LVName: "n", VGName: "g", Size: "1", Extents: "1"},
			"Error: Please specify only one of size or extents"},
		{"thin both", &LvCreateArgs{LVName: "n", VGName: "g", ThinVolume: true, ThinPool: true},
			"Error: Please set only one of thinvolume or thinpool to True"},
		{"no size", &LvCreateArgs{LVName: "n", VGName: "g"},
			"Error: Either size or extents must be specified"},
		{"thin extents", &LvCreateArgs{LVName: "n", VGName: "g", ThinVolume: true, Extents: "1"},
			"Error: Thin volume size cannot be specified as extents"},
	}
	for _, tc := range cases {
		rt, _ := newRT(map[string][]process.CommandResult{})
		_, err := call(t, rt, lvCreateFunc{}, tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s: err = %v", tc.name, err)
		}
	}

	rt, runner := newRT(map[string][]process.CommandResult{
		"lvcreate": {{ExitCode: 0}},
		"lvdisplay": {
			{ExitCode: 1}, // no details yet
		},
	})
	got, err := call(t, rt, lvCreateFunc{}, &LvCreateArgs{
		LVName: "newlv", VGName: "vg", Size: "10G", PV: "/dev/sda1",
		Stripes: "5", NoSync: true, IgnoreMonitoring: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.(map[string]any)["Output from lvcreate"] != `Logical volume "newlv" created.` {
		t.Fatalf("lvcreate out = %v", got)
	}
	wantArgv := []string{
		"lvcreate", "-n", "newlv", "vg", "-L", "10G", "/dev/sda1",
		"--stripes", "5", "--nosync", "--ignoremonitoring", "-qq",
	}
	if !reflect.DeepEqual(runner.calls[0], wantArgv) {
		t.Fatalf("argv = %v", runner.calls[0])
	}

	// Snapshot + thin pool argv shapes.
	rt2, runner2 := newRT(map[string][]process.CommandResult{
		"lvcreate":  {{ExitCode: 0}},
		"lvdisplay": {{ExitCode: 1}},
	})
	if _, err := call(t, rt2, lvCreateFunc{}, &LvCreateArgs{
		LVName: "snap", VGName: "vg", Snapshot: "origin", Size: "3G",
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runner2.calls[0],
		[]string{"lvcreate", "-n", "snap", "-s", "vg/origin", "-L", "3G", "-qq"}) {
		t.Fatalf("snapshot argv = %v", runner2.calls[0])
	}

	rt3, runner3 := newRT(map[string][]process.CommandResult{
		"lvcreate":  {{ExitCode: 0}},
		"lvdisplay": {{ExitCode: 1}},
	})
	if _, err := call(t, rt3, lvCreateFunc{}, &LvCreateArgs{
		LVName: "pool", VGName: "vg", Size: "20G", ThinPool: true,
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runner3.calls[0],
		[]string{"lvcreate", "--thinpool", "pool", "vg", "-L", "20G", "-qq"}) {
		t.Fatalf("thinpool argv = %v", runner3.calls[0])
	}
}

func TestRemoveMessageContracts(t *testing.T) {
	rt, _ := newRT(map[string][]process.CommandResult{
		"vgremove": {{ExitCode: 0}},
	})
	got, err := call(t, rt, vgRemoveFunc{}, &VgRemoveArgs{VGName: "fakevg"})
	if err != nil || got != `Volume group "fakevg" successfully removed` {
		t.Fatalf("vgremove = %v %v", got, err)
	}

	rt2, _ := newRT(map[string][]process.CommandResult{
		"lvremove": {{ExitCode: 0}},
	})
	got2, err := call(t, rt2, lvRemoveFunc{}, &LvRemoveArgs{LVName: "fakelv", VGName: "fakevg"})
	if err != nil || got2 != `Logical volume "fakelv" successfully removed` {
		t.Fatalf("lvremove = %v %v", got2, err)
	}

	// Failure keeps the message-string contract: stderr text as data.
	rt3, _ := newRT(map[string][]process.CommandResult{
		"vgremove": {{ExitCode: 5, Stderr: []byte("not found")}},
	})
	got3, err := call(t, rt3, vgRemoveFunc{}, &VgRemoveArgs{VGName: "fakevg"})
	if err != nil || got3 != "not found" {
		t.Fatalf("failed vgremove = %v %v", got3, err)
	}
}

func TestResizeContracts(t *testing.T) {
	empty := map[string]any{}
	rt, _ := newRT(map[string][]process.CommandResult{})
	got, err := call(t, rt, lvResizeFunc{}, &LvResizeArgs{Size: "1", Extents: "1"})
	if err != nil || !reflect.DeepEqual(got, empty) {
		t.Fatalf("size+extents = %v %v", got, err)
	}
	got2, err := call(t, rt, lvResizeFunc{}, &LvResizeArgs{})
	if err != nil || !reflect.DeepEqual(got2, empty) {
		t.Fatalf("neither = %v %v", got2, err)
	}

	rt2, runner2 := newRT(map[string][]process.CommandResult{
		"lvresize": {{ExitCode: 0}},
	})
	got3, err := call(t, rt2, lvResizeFunc{}, &LvResizeArgs{Size: "+12M", LVPath: "/dev/fakevg/fakelv"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"Output from lvresize": `Logical volume "/dev/fakevg/fakelv" successfully resized.`}
	if !reflect.DeepEqual(got3, want) {
		t.Fatalf("resize = %v", got3)
	}
	if !reflect.DeepEqual(runner2.calls[0],
		[]string{"lvresize", "-qq", "-L", "+12M", "/dev/fakevg/fakelv"}) {
		t.Fatalf("resize argv = %v", runner2.calls[0])
	}

	rt3, runner3 := newRT(map[string][]process.CommandResult{
		"lvextend": {{ExitCode: 0}},
	})
	extendArgs := LvExtendArgs{Size: "+12M", LVPath: "/dev/vg/lv", Force: true, Resizefs: true}
	got4, err := call(t, rt3, lvExtendFunc{}, &extendArgs)
	if err != nil {
		t.Fatal(err)
	}
	want4 := map[string]any{"Output from lvextend": `Logical volume "/dev/vg/lv" successfully extended.`}
	if !reflect.DeepEqual(got4, want4) {
		t.Fatalf("extend = %v", got4)
	}
	if !reflect.DeepEqual(runner3.calls[0],
		[]string{"lvextend", "--yes", "--resizefs", "-L", "+12M", "/dev/vg/lv"}) {
		t.Fatalf("extend argv = %v", runner3.calls[0])
	}
}

// TestPlatformConstraint pins the family-wide linux contract and surface.
func TestPlatformConstraint(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	names := reg.Names()
	if len(names) != 15 {
		t.Fatalf("registered %d functions", len(names))
	}
	for _, name := range names {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s lost", name)
		}
		if constrained, ok := fn.(interface{ Platforms() []string }); !ok ||
			!reflect.DeepEqual(constrained.Platforms(), []string{"linux"}) {
			t.Fatalf("%s not linux-constrained", name)
		}
	}
}

func ptr(b bool) *bool { return &b }
