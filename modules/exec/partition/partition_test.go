package partition

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct {
	results map[string]process.CommandResult // keyed by joined argv
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
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	return rt, runner
}

// withBlockDevice registers /dev/sda as a "block device" for the session.
func withBlockDevice(t *testing.T, rt *runtime.Runtime) {
	t.Helper()
	withBlockDeviceFS(rt)
	saved := isBlockDev
	isBlockDev = func(fi os.FileInfo) bool { return strings.HasSuffix(fi.Name(), "sda") }
	t.Cleanup(func() { isBlockDev = saved })
}

// withBlockDeviceFS only seeds the FS entry; used for extra runtimes that
// share the already-installed hook.
func withBlockDeviceFS(rt *runtime.Runtime) {
	if err := rt.FS.MkdirAll("/dev", 0o755); err != nil {
		panic(err)
	}
	if err := rt.FS.WriteFile("/dev/sda", nil, 0o600); err != nil {
		panic(err)
	}
}

const partedPrint = `BYT;
/dev/sda:32.2GB:scsi:512B:4096B:gpt:ATA SSD
1:1049kB:2112MB:2111MB:::boot;
2:2112MB:32.2GB:30.1GB:ext4:primary:;
3:32.2GB:64.4GB:32.2GB:free;
`

// TestList pins the machine-format parser including the free-row variant.
func TestList(t *testing.T) {
	rt, runner := newRT(map[string]process.CommandResult{
		"parted -m -s /dev/sda print": {Stdout: []byte(partedPrint)},
	})
	withBlockDevice(t, rt)

	gotRaw, err := (listFunc{}).Execute(context.Background(), rt, &ListArgs{Device: "/dev/sda"})
	if err != nil {
		t.Fatal(err)
	}
	got := gotRaw.(map[string]any)

	info := got["info"].(map[string]any)
	if info["disk"] != "/dev/sda" || info["partition table"] != "gpt" ||
		info["model"] != "ATA SSD" || info["interface"] != "scsi" {
		t.Fatalf("info = %v", info)
	}
	if _, hasFlags := info["disk flags"]; hasFlags {
		t.Fatalf("7-column info must not carry disk flags: %v", info)
	}

	parts := got["partitions"].(map[string]any)
	p1 := parts["1"].(map[string]any)
	if p1["size"] != "2111MB" || p1["file system"] != "" || p1["flags"] != "boot" {
		t.Fatalf("p1 = %v", p1)
	}
	p3 := parts["3"].(map[string]any)
	if _, isFree := p3["free"]; isFree {
		t.Fatalf("free row keeps dropped column shape: %v", p3)
	}
	if p3["number"] != "3" || len(p3) != 4 {
		t.Fatalf("p3 = %v", p3)
	}
	if !reflect.DeepEqual(runner.calls[0], []string{"parted", "-m", "-s", "/dev/sda", "print"}) {
		t.Fatalf("argv = %v", runner.calls[0])
	}

	// Unit passthrough and validation.
	rt2, runner2 := newRT(map[string]process.CommandResult{
		"parted -m -s /dev/sda unit s print": {},
	})
	withBlockDeviceFS(rt2)
	lf := listFunc{}
	if _, err := lf.Execute(context.Background(), rt2, &ListArgs{Device: "/dev/sda", Unit: "s"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runner2.calls[len(runner2.calls)-1],
		[]string{"parted", "-m", "-s", "/dev/sda", "unit", "s", "print"}) {
		t.Fatalf("unit argv = %v", runner2.calls)
	}

	_, err = (listFunc{}).Execute(context.Background(), rt2, &ListArgs{Device: "/dev/sda", Unit: "parsec"})
	if err == nil || err.Error() != "Invalid unit passed to partition.part_list" {
		t.Fatalf("unit error = %v", err)
	}

	// Malformed info row errors like Salt.
	rt3, _ := newRT(map[string]process.CommandResult{
		"parted -m -s /dev/sda print": {Stdout: []byte("garbage:line\n")},
	})
	withBlockDeviceFS(rt3)
	_, err = (listFunc{}).Execute(context.Background(), rt3, &ListArgs{Device: "/dev/sda"})
	if err == nil || !strings.Contains(err.Error(), "Problem encountered while parsing output") {
		t.Fatalf("parse error = %v", err)
	}
}

// TestValidationsMirrorSaltMessages pins every repeated validation message.
func TestValidationsMirrorSaltMessages(t *testing.T) {
	rt, _ := newRT(nil)
	withBlockDevice(t, rt)

	cases := []struct {
		name string
		fn   runtime.ExecFunction
		args any
		want string
	}{
		{"probe bad device", probeFunc{}, &ProbeArgs{Devices: []string{"/dev/nope"}},
			"Invalid device passed to partition module."},
		{"align part_type", alignCheckFunc{}, &AlignCheckArgs{Device: "/dev/sda", PartType: "bogus", Partition: "1"},
			"Invalid part_type passed to partition.align_check"},
		{"align partition", alignCheckFunc{}, &AlignCheckArgs{Device: "/dev/sda", PartType: "minimal", Partition: "x"},
			"Invalid partition passed to partition.align_check"},
		{"check minor", checkFunc{}, &CheckArgs{Device: "/dev/sda", Minor: "x"},
			"Invalid minor number passed to partition.check"},
		{"cp minors", cpFunc{}, &CpArgs{Device: "/dev/sda", FromMinor: "1", ToMinor: "y"},
			"Invalid minor number passed to partition.cp"},
		{"get_id minor", getIDFunc{}, &GetIDArgs{Device: "/dev/sda", Minor: ""},
			"Invalid minor number passed to partition.get_id"},
		{"set_id minor", setIDFunc{}, &SetIDArgs{Device: "/dev/sda", Minor: "q", SystemID: "83"},
			"Invalid minor number passed to partition.set_id"},
		{"mkfs fs_type", mkfsFunc{}, &MkfsArgs{Device: "/dev/sda", FsType: "zfs"},
			"Invalid fs_type passed to partition.mkfs"},
		{"mklabel label", mklabelFunc{}, &MklabelArgs{Device: "/dev/sda", LabelType: "iso9660"},
			"Invalid label_type passed to partition.mklabel"},
		{"mkpart part_type", mkpartFunc{}, &MkpartArgs{Device: "/dev/sda", PartType: "weird"},
			"Invalid part_type passed to partition.mkpart"},
		{"mkpart fs_type", mkpartFunc{}, &MkpartArgs{Device: "/dev/sda", PartType: "primary", FsType: "bogusfs"},
			"Invalid fs_type passed to partition.mkpart"},
		{"name chars", nameFunc{}, &NameArgs{Device: "/dev/sda", Partition: "1", Name: "bad;name"},
			"Invalid characters passed to partition.name"},
		{"resize minor", resizeFunc{}, &ResizeArgs{Device: "/dev/sda", Minor: "x", Start: "0", End: "100"},
			"Invalid minor number passed to partition.resize"},
		{"rm minor", rmFunc{}, &RmArgs{Device: "/dev/sda", Minor: "x"},
			"Invalid minor number passed to partition.rm"},
		{"set flag", setFunc{}, &SetArgs{Device: "/dev/sda", Minor: "1", Flag: "bogus", State: "on"},
			"Invalid flag passed to partition.set"},
		{"set state", setFunc{}, &SetArgs{Device: "/dev/sda", Minor: "1", Flag: "boot", State: "maybe"},
			"Invalid state passed to partition.set"},
		{"toggle flag", toggleFunc{}, &ToggleArgs{Device: "/dev/sda", Partition: "1", Flag: "bogus"},
			"Invalid flag passed to partition.toggle"},
		{"disk_set flag", diskSetFunc{}, &DiskSetArgs{Device: "/dev/sda", Flag: "bogus", State: "on"},
			"Invalid flag passed to partition.disk_set"},
		{"disk_toggle flag", diskToggleFunc{}, &DiskToggleArgs{Device: "/dev/sda", Flag: "nope"},
			"Invalid flag passed to partition.disk_toggle"},
		{"boundary start", rescueFunc{}, &RescueArgs{Device: "/dev/sda", Start: "12xy", End: "100"},
			`Invalid partition boundary passed: "12xy"`},
	}
	for _, tc := range cases {
		_, err := tc.fn.Execute(context.Background(), rt, tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestArgvContracts(t *testing.T) {
	rt, runner := newRT(map[string]process.CommandResult{
		"sfdisk -T":                                   {Stdout: []byte("Id  Type\n82  Linux swap\n83  Linux\n")},
		"partprobe -- /dev/sda":                       {Stdout: []byte("")},
		"sfdisk --print-id /dev/sda 1":                {Stdout: []byte("/dev/sda1 83\n")},
		"mkswap /dev/sda":                             {},
		"parted -m -s /dev/sda name 1 'My Documents'": {},
		"lsblk -n -io KNAME -d -e 1,7,11 -l":          {Stdout: []byte("sda\nsdb\n")},
	})
	withBlockDevice(t, rt)

	(probeFunc{}).Execute(context.Background(), rt, &ProbeArgs{Devices: []string{"/dev/sda"}})
	if !reflect.DeepEqual(runner.calls[0], []string{"partprobe", "--", "/dev/sda"}) {
		t.Fatalf("probe argv = %v", runner.calls)
	}

	typesRaw, err := (systemTypesFunc{}).Execute(context.Background(), rt, &SystemTypesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	types := typesRaw.(map[string]any)
	if types["82"] != "Linux" || types["83"] != "Linux" {
		t.Fatalf("system_types = %v", types)
	}

	(setIDFunc{}).Execute(context.Background(), rt, &SetIDArgs{
		Device: "/dev/sda", Minor: "1", SystemID: "83"})
	last := runner.calls[len(runner.calls)-1]
	if !reflect.DeepEqual(last, []string{"sfdisk", "--change-id", "/dev/sda", "1", "83"}) {
		t.Fatalf("set_id argv = %v", last)
	}

	// Unknown system id errors.
	_, err = (setIDFunc{}).Execute(context.Background(), rt, &SetIDArgs{
		Device: "/dev/sda", Minor: "1", SystemID: "ff"})
	if err == nil || !strings.Contains(err.Error(), "Invalid system_id") {
		t.Fatalf("set_id system error = %v", err)
	}

	// linux-swap maps to mkswap.
	(mkfsFunc{}).Execute(context.Background(), rt, &MkfsArgs{Device: "/dev/sda", FsType: "linux-swap"})
	found := false
	for _, call := range runner.calls {
		if reflect.DeepEqual(call, []string{"mkswap", "/dev/sda"}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("mkswap argv missing: %v", runner.calls)
	}

	(nameFunc{}).Execute(context.Background(), rt, &NameArgs{
		Device: "/dev/sda", Partition: "1", Name: "My Documents"})
	found = false
	for _, call := range runner.calls {
		if reflect.DeepEqual(call, []string{
			"parted", "-m", "-s", "/dev/sda", "name", "1", "'My Documents'"}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("name argv missing: %v", runner.calls)
	}

	devs, err := (getBlockDeviceFunc{}).Execute(context.Background(), rt, &GetBlockDeviceArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(devs, []string{"sda", "sdb"}) {
		t.Fatalf("devices = %v", devs)
	}
}

func TestExistsAndBoundaryUnits(t *testing.T) {
	rt, _ := newRT(nil)
	withBlockDevice(t, rt)

	got, err := (existsFunc{}).Execute(context.Background(), rt, &ExistsArgs{Device: "/dev/sda"})
	if err != nil || got != true {
		t.Fatalf("exists = %v %v", got, err)
	}
	got2, _ := (existsFunc{}).Execute(context.Background(), rt, &ExistsArgs{Device: "/dev/none"})
	if got2 != false {
		t.Fatalf("exists missing = %v", got2)
	}

	// All VALID_UNITS pass boundary validation via mkpart.
	for _, unit := range []string{"", "s", "B", "kB", "MB", "MiB", "GB", "GiB", "TB", "TiB", "%", "cyl", "chs", "compact"} {
		start := "1" + unit
		end := "2" + unit
		fn := mkpartFunc{}
		_, _ = fn.Execute(context.Background(), rt, &MkpartArgs{
			Device: "/dev/sda", PartType: "primary", Start: start, End: end,
		})
	}
}

func TestPlatformConstraint(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Names()) != 22 {
		t.Fatalf("registered %d functions", len(reg.Names()))
	}
	for _, name := range reg.Names() {
		fn, _ := reg.Get(name)
		if c, ok := fn.(interface{ Platforms() []string }); !ok ||
			strings.Join(c.Platforms(), ",") != "linux" {
			t.Fatalf("%s not linux-constrained", name)
		}
	}
}
