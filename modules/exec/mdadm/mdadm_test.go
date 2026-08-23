package mdadm

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct {
	results map[string]process.CommandResult // keyed by joined argv or binary
	calls   [][]string
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	f.calls = append(f.calls, argv)
	if res, ok := f.results[strings.Join(argv, " ")]; ok {
		return res
	}
	if res, ok := f.results[cmd.Name]; ok {
		return res
	}
	return process.CommandResult{}
}

func newRT(results map[string]process.CommandResult) (*runtime.Runtime, *fakeRunner) {
	runner := &fakeRunner{results: results}
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		Facts:  facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{ID: "debian", Family: facts.FamilyDebian}}),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	return rt, runner
}

// TestList parses `mdadm --detail --scan` rows.
func TestList(t *testing.T) {
	rt, runner := newRT(map[string]process.CommandResult{
		"mdadm": {Stdout: []byte(
			"ARRAY /dev/md/1 metadata=1.2 UUID=51f245bc:a1402c8a name=tst:1\n" +
				"junkline\n")},
	})
	got, err := listFunc{}.Execute(context.Background(), rt, &ListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	arrays := got.(map[string]any)
	row := arrays["/dev/md/1"].(map[string]any)
	if row["device"] != "/dev/md/1" || row["metadata"] != "1.2" ||
		row["uuid"] != "51f245bc:a1402c8a" {
		t.Fatalf("row = %v", row)
	}
	if !reflect.DeepEqual(runner.calls[0], []string{"mdadm", "--detail", "--scan"}) {
		t.Fatalf("argv = %v", runner.calls[0])
	}
}

const detailOut = `/dev/md0:
           Version : 1.2
     Creation Time : Mon Jan  1 00:00:00 2024
        Raid Level : raid1
     Array Size : 524224 (512.00 MiB)
   Used Dev Size : 524224
    Raid Devices : 2
   Total Devices : 2
       State : clean 
   Active Devices : 2
  Working Devices : 2
   Failed Devices : 0
    Spare Devices : 0
Consistency Policy : resync
              Name : tst:0
              UUID : abc:def
            Events : 0.123
    Number   Major   Minor   RaidDevice State
       0       8        1        0      active sync   /dev/sda1
       1       8       17        1      active sync   /dev/sdb1
`

func TestDetail(t *testing.T) {
	rt, _ := newRT(map[string]process.CommandResult{
		"mdadm --detail /dev/md0": {Stdout: []byte(detailOut)},
	})
	if err := rt.FS.MkdirAll("/dev", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/dev/md0", nil, 0o600); err != nil {
		t.Fatal(err)
	}

	gotRaw, err := detailFunc{}.Execute(context.Background(), rt, &DetailArgs{Device: "/dev/md0"})
	if err != nil {
		t.Fatal(err)
	}
	detail := gotRaw.(map[string]any)
	if detail["raid_level"] != "raid1" || detail["state"] != "clean" ||
		detail["uuid"] != "abc:def" {
		t.Fatalf("headers = %v", detail)
	}
	members := detail["members"].(map[string]any)
	m0 := members["0"].(map[string]any)
	if m0["device"] != "/dev/sda1" || m0["major"] != "8" || m0["minor"] != "1" ||
		m0["raiddevice"] != "0" || m0["state"] != "active sync" {
		t.Fatalf("member 0 = %v", m0)
	}
	if len(members) != 2 {
		t.Fatalf("members = %v", members)
	}

	// Missing device mirrors Salt's CommandExecutionError text.
	rt2, _ := newRT(map[string]process.CommandResult{})
	_, err = detailFunc{}.Execute(context.Background(), rt2, &DetailArgs{Device: "/dev/mdX"})
	if err == nil || err.Error() != "Device /dev/mdX doesn't exist!" {
		t.Fatalf("missing device err = %v", err)
	}

	// Empty device falls back to Salt's /dev/md0 default.
	rt3, _ := newRT(map[string]process.CommandResult{"mdadm": {}})
	_, err = detailFunc{}.Execute(context.Background(), rt3, &DetailArgs{})
	if err == nil || !strings.Contains(err.Error(), "Device /dev/md0 doesn't exist!") {
		t.Fatalf("default device err = %v", err)
	}
}

// TestCreate pins the exact create argv including sorted kwargs and the
// test-mode string contract.
func TestCreate(t *testing.T) {
	rt, runner := newRT(map[string]process.CommandResult{})
	got, err := createFunc{}.Execute(context.Background(), rt, &CreateArgs{
		Name:     "/dev/md0",
		Level:    "5",
		Devices:  []string{"/dev/sdb1", "/dev/sdc1", "/dev/sdd1"},
		TestMode: true,
		Option:   map[string]string{"chunk": "256", "force": "true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantParts := strings.Split(
		"mdadm -C /dev/md0 -R -v -l 5 --chunk 256 --force -e default -n 3 "+
			"/dev/sdb1 /dev/sdc1 /dev/sdd1", " ")
	if got != strings.Join(wantParts, " ") {
		t.Fatalf("test mode cmd = %v", got)
	}
	for _, call := range runner.calls {
		if call[0] == "mdadm" {
			t.Fatal("test mode must not run mdadm")
		}
	}

	rt2, runner2 := newRT(map[string]process.CommandResult{
		"mdadm": {Stdout: []byte("salt\n")},
	})
	got2, err := createFunc{}.Execute(context.Background(), rt2, &CreateArgs{
		Name:    "/dev/md0",
		Level:   "5",
		Devices: []string{"/dev/sdb1", "/dev/sdc1", "/dev/sdd1"},
		Option:  map[string]string{"chunk": "256", "force": "true"},
	})
	if err != nil || got2 != "salt" {
		t.Fatalf("create = %v %v", got2, err)
	}
	wantArgv := []string{
		"mdadm", "-C", "/dev/md0", "-R", "-v", "-l", "5",
		"--chunk", "256", "--force", "-e", "default", "-n", "3",
		"/dev/sdb1", "/dev/sdc1", "/dev/sdd1",
	}
	if !reflect.DeepEqual(runner2.calls[0], wantArgv) {
		t.Fatalf("create argv = %v", runner2.calls[0])
	}

	// spare-devices reduces the device count.
	rt3, runner3 := newRT(map[string]process.CommandResult{"mdadm": {}})
	createFunc{}.Execute(context.Background(), rt3, &CreateArgs{
		Name: "/dev/md1", Level: "1",
		Devices: []string{"/dev/x", "/dev/y"},
		Option:  map[string]string{"spare-devices": "1"},
	})
	last := runner3.calls[len(runner3.calls)-1]
	nIdx := 0
	for i, tok := range last {
		if tok == "-n" {
			nIdx = i + 1
			break
		}
	}
	if last[nIdx] != "1" {
		t.Fatalf("-n value with spares = %v", last)
	}
}

// TestExamine mirrors the "=" partition semantics.
func TestExamine(t *testing.T) {
	rt, _ := newRT(map[string]process.CommandResult{
		"mdadm -Y -E /dev/md0": {Stdout: []byte(
			"ARRAY /dev/md/pool metadata=1.2 UUID=567da122 name=positron:pool\n")},
	})
	got, err := examineFunc{}.Execute(context.Background(), rt,
		&ExamineArgs{Device: "/dev/md0"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"ARRAY /dev/md/pool metadata": "1.2 UUID=567da122 name=positron:pool",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("examine = %v", got)
	}
}

// TestDestroy covers stop+zero+config-removal flow and failure result.
func TestDestroy(t *testing.T) {
	rt, runner := newRT(map[string]process.CommandResult{
		"mdadm --detail /dev/md0": {Stdout: []byte(detailOut)},
		"mdadm --stop /dev/md0":   {ExitCode: 0},
		"mdadm --detail --scan":   {Stdout: []byte("ARRAY /dev/md1 metadata=1.2\n")},
	})
	if err := rt.FS.MkdirAll("/dev", 0o755); err != nil {
		t.Fatal(err)
	}
	rt.FS.WriteFile("/dev/md0", nil, 0o600)

	ok, err := destroyFunc{}.Execute(context.Background(), rt, &DestroyArgs{Device: "/dev/md0"})
	if err != nil || ok != true {
		t.Fatalf("destroy = %v %v", ok, err)
	}
	var zero []string
	var stop []string
	for _, call := range runner.calls {
		switch {
		case reflect.DeepEqual(call[:2], []string{"mdadm", "--stop"}):
			stop = call
		case len(call) > 1 && call[1] == "--zero-superblock":
			zero = call
		}
	}
	if !reflect.DeepEqual(stop, []string{"mdadm", "--stop", "/dev/md0"}) {
		t.Fatalf("stop = %v", stop)
	}
	wantZero := []string{"mdadm", "--zero-superblock", "/dev/sda1", "/dev/sdb1"}
	if !reflect.DeepEqual(zero, wantZero) {
		t.Fatalf("zero = %v", zero)
	}

	// Detail failure short-circuits to false without running anything else:
	// the device file is missing, so detail errors first.
	rt2, _ := newRT(map[string]process.CommandResult{})
	if err := rt2.FS.MkdirAll("/dev", 0o755); err != nil {
		t.Fatal(err)
	}
	ok2, err := destroyFunc{}.Execute(context.Background(), rt2, &DestroyArgs{Device: "/dev/md0"})
	if err != nil || ok2 != false {
		t.Fatalf("destroy fail path = %v %v", ok2, err)
	}
}

// TestStopQuirk pins Salt's inverted retcode truthiness in raid.stop.
func TestStopQuirk(t *testing.T) {
	failing, _ := newRT(map[string]process.CommandResult{
		"mdadm --stop --scan": {ExitCode: 1},
	})
	got, err := stopFunc{}.Execute(context.Background(), failing, &StopArgs{})
	if err != nil || got != true {
		t.Fatalf("non-zero rc must yield true: %v %v", got, err)
	}
	succeeding, _ := newRT(map[string]process.CommandResult{
		"mdadm --stop --scan": {ExitCode: 0},
	})
	got2, err := stopFunc{}.Execute(context.Background(), succeeding, &StopArgs{})
	if err != nil || got2 != false {
		t.Fatalf("zero rc must yield false: %v %v", got2, err)
	}
}

// TestAddAndAssembleAndSaveConfig covers remaining contracts.
func TestAddAssembleSaveConfig(t *testing.T) {
	rt, _ := newRT(map[string]process.CommandResult{
		"mdadm --manage /dev/md0 --add /dev/sdc1": {ExitCode: 0},
	})
	got, err := addFunc{}.Execute(context.Background(), rt,
		&AddArgs{Name: "/dev/md0", Device: "/dev/sdc1"})
	if err != nil || got != true {
		t.Fatalf("add = %v %v", got, err)
	}

	rt2, runner2 := newRT(map[string]process.CommandResult{"mdadm": {Stdout: []byte("assembled\n")}})
	got2, err := assembleFunc{}.Execute(context.Background(), rt2, &AssembleArgs{
		Name: "/dev/md0", Devices: []string{"/dev/sdb1", "/dev/sdc1"},
	})
	if err != nil || got2 != "assembled" {
		t.Fatalf("assemble = %v %v", got2, err)
	}
	if !reflect.DeepEqual(runner2.calls[0],
		[]string{"mdadm", "-A", "/dev/md0", "-v", "/dev/sdb1", "/dev/sdc1"}) {
		t.Fatalf("assemble argv = %v", runner2.calls[0])
	}

	// test_mode returns the argv slice itself.
	rt3, _ := newRT(nil)
	got3, err := assembleFunc{}.Execute(context.Background(), rt3, &AssembleArgs{
		Name: "/dev/md9", Devices: []string{"/dev/z"}, TestMode: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got3, []string{"mdadm", "-A", "/dev/md9", "-v", "/dev/z"}) {
		t.Fatalf("assemble test mode = %v", got3)
	}

	// save_config writes the ARRAY line into the debian config path.
	scan := "ARRAY /dev/md0 metadata=1.2 UUID=abc\n"
	rt4, runner4 := newRT(map[string]process.CommandResult{
		"mdadm --detail --scan": {Stdout: []byte(scan)},
		"update-initramfs":      {Stdout: []byte("initramfs updated\n")},
	})
	if err := rt4.FS.MkdirAll("/etc/mdadm", 0o755); err != nil {
		t.Fatal(err)
	}
	rt4.FS.WriteFile("/etc/mdadm/mdadm.conf", []byte(""), 0o644)
	got4, err := saveConfigFunc{}.Execute(context.Background(), rt4, &SaveConfigArgs{})
	if err != nil || got4 != "initramfs updated" {
		t.Fatalf("save_config = %v %v", got4, err)
	}
	data, _ := rt4.FS.ReadFile("/etc/mdadm/mdadm.conf")
	if strings.TrimSpace(string(data)) != strings.TrimSpace(scan) {
		t.Fatalf("config content = %q", data)
	}
	if !reflect.DeepEqual(runner4.calls[len(runner4.calls)-1],
		[]string{"update-initramfs", "-u"}) {
		t.Fatalf("initramfs argv = %v", runner4.calls)
	}
}

func TestPlatformConstraint(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Names()) != 9 {
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
