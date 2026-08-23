package xfs

import (
	"context"
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

// TestParseXfsInfo ports Salt's test_parse_xfs_info fixture verbatim.
func TestParseXfsInfo(t *testing.T) {
	data := `
meta-data=/dev/vg00/testvol      isize=512    agcount=4, agsize=1310720 blks
         =                       sectsz=4096  attr=2, projid32bit=1
         =                       crc=1        finobt=1, sparse=1, rmapbt=0
         =                       reflink=1
data     =                       bsize=4096   blocks=5242880, imaxpct=25
         =                       sunit=0      swidth=0 blks
naming   =version 2              bsize=4096   ascii-ci=0, ftype=1
log      =internal log           bsize=4096   blocks=2560, version=2
         =                       sectsz=4096  sunit=1 blks, lazy-count=1
realtime =none                   extsz=4096   blocks=0, rtextents=0
Discarding blocks...Done.
`
	got := parseXfsInfo(data)
	want := map[string]any{
		"meta-data": map[string]any{
			"section": "/dev/vg00/testvol", "isize": "512", "agcount": "4",
			"agsize": "1310720 blks", "sectsz": "4096", "attr": "2",
			"projid32bit": "1", "crc": "1", "finobt": "1", "sparse": "1",
			"rmapbt": "0", "reflink": "1",
		},
		"data": map[string]any{
			"section": "data", "bsize": "4096", "blocks": "5242880",
			"imaxpct": "25", "sunit": "0", "swidth": "0 blks",
		},
		"naming": map[string]any{
			"section": "version 2", "bsize": "4096", "ascii-ci": "0", "ftype": "1",
		},
		"log": map[string]any{
			"section": "internal log", "bsize": "4096", "blocks": "2560",
			"version": "2", "sectsz": "4096", "sunit": "1 blks", "lazy-count": "1",
		},
		"realtime": map[string]any{
			"section": "none", "extsz": "4096", "blocks": "0", "rtextents": "0",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parse mismatch:\n got=%v\nwant=%v", got, want)
	}
}

// TestBlkidOutput ports Salt's test_blkid_output fixture verbatim.
func TestBlkidOutput(t *testing.T) {
	rt, _ := newRT(nil)
	blkidExport := `
DEVNAME=/dev/sda1
UUID=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
TYPE=xfs
PARTUUID=YYYYYYYY-YY

DEVNAME=/dev/sdb1
PARTUUID=ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ
`
	got := blkidOutput(rt, blkidExport)
	want := map[string]any{
		"/dev/sda1": map[string]any{
			"label":    nil,
			"partuuid": "YYYYYYYY-YY",
			"uuid":     "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("blkid = %v", got)
	}
}

func TestDevicesMergesMounts(t *testing.T) {
	rt, _ := newRT(map[string]process.CommandResult{
		"blkid -o export": {Stdout: []byte(
			"DEVNAME=/dev/sda1\nTYPE=xfs\nLABEL=backup\n")},
	})
	rt.FS.MkdirAll("/proc", 0o755)
	rt.FS.WriteFile("/proc/mounts", []byte(
		"/dev/sda1 /srv xfs rw,relatime 0 0\n"), 0o600)

	gotRaw, err := devicesFunc{}.Execute(context.Background(), rt, &DevicesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	entry := gotRaw.(map[string]any)["/dev/sda1"].(map[string]any)
	if entry["label"] != "backup" || entry["mount_point"] != "/srv" {
		t.Fatalf("entry = %v", entry)
	}
	if !reflect.DeepEqual(entry["options"], []string{"rw", "relatime"}) {
		t.Fatalf("options = %v", entry["options"])
	}
}

const dumpOut = `xfsdump: session id: b74a3586-e52e-4a4a-8775-c3334fa8ea2c
xfsdump: session label: weekly_backup
xfsdump: media file size 1234567 bytes
xfsdump: dump complete: 0 seconds elapsed
xfsdump: Dump Status: SUCCESS
`

func TestDumpContract(t *testing.T) {
	rt, _ := newRT(map[string]process.CommandResult{
		"xfsdump -F -E -L weekly -l 2 -f /backup/file /dev/sda1": {
			Stdout: []byte(dumpOut),
		},
	})
	savedLook := lookPath
	lookPath = func(name string) (string, error) { return "/usr/sbin/xfsdump", nil }
	defer func() { lookPath = savedLook }()

	gotRaw, err := dumpFunc{}.Execute(context.Background(), rt, &DumpArgs{
		Device: "/dev/sda1", Destination: "/backup/file", Level: "2", Label: "weekly",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := gotRaw.(map[string]any)
	if got["Session ID"] != "b74a3586-e52e-4a4a-8775-c3334fa8ea2c" ||
		got["Session label"] != "weekly_backup" ||
		got["Media size"] != "1234567 bytes" ||
		got["Status"] != "SUCCESS" {
		t.Fatalf("dump fields = %v", got)
	}

	// Missing utility mirrors Salt's guard text.
	noTool, _ := newRT(nil)
	savedLook2 := lookPath
	lookPath = func(name string) (string, error) { return "", context.Canceled }
	defer func() { lookPath = savedLook2 }()
	_, err = dumpFunc{}.Execute(context.Background(), noTool, &DumpArgs{
		Device: "/dev/sda1", Destination: "/backup/x"})
	if err == nil || !strings.Contains(err.Error(), "has to be installed or missing") {
		t.Fatalf("utility guard = %v", err)
	}
}

func TestInventoryAndPrune(t *testing.T) {
	inventoryOut := `xfsrestore: using file dump (drive_simple) strategy
session 0: b74a3586-e52e-4a4a-8775-c3334fa8ea2c
	start time: Mon Jan  1 00:00:00 2024
	end time: Mon Jan  1 01:00:00 2024
	label: weekly_backup
	stream 0:
		pathname: /dev/sda1
	restore status: SUCCESS
`
	rt, _ := newRT(map[string]process.CommandResult{
		"xfsrestore -I": {Stdout: []byte(inventoryOut)},
	})
	gotRaw, err := inventoryFunc{}.Execute(context.Background(), rt, &InventoryArgs{})
	if err != nil {
		t.Fatal(err)
	}
	got := gotRaw.(map[string]any)
	// Salt's parser keeps "key: value" rows in their enclosing dict and
	// opens nested dicts only for trailing-colon header lines.
	if got["session 0"] != "b74a3586-e52e-4a4a-8775-c3334fa8ea2c" ||
		got["label"] != "weekly_backup" {
		t.Fatalf("root keys = %v", got)
	}
	stream := got["stream 0"].(map[string]any)
	if stream["pathname"] != "/dev/sda1" {
		t.Fatalf("stream = %v", stream)
	}
	// Salt keeps the raw trailing inventory line.
	if got["restore_status"] != "\trestore status: SUCCESS" {
		t.Fatalf("status = %q", got["restore_status"])
	}

	// Single restore-status line short-circuits.
	rt2, _ := newRT(map[string]process.CommandResult{
		"xfsrestore -I": {Stdout: []byte("xfsrestore: Restore Status: INCOMPLETE\n")},
	})
	got2, err := inventoryFunc{}.Execute(context.Background(), rt2, &InventoryArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got2, map[string]any{
		"restore_status": "xfsrestore: Restore Status: INCOMPLETE",
	}) {
		t.Fatalf("short inventory = %v", got2)
	}

	pruneOut := `---------------------------
session 0
	uuid: b74a3586-e52e-4a4a-8775-c3334fa8ea2c
	label: weekly_backup
---------------------------
other output
`
	rt3, _ := newRT(map[string]process.CommandResult{
		"xfsinvutil -s b74a3586-e52e-4a4a-8775-c3334fa8ea2c -F": {
			Stdout: []byte(pruneOut),
		},
	})
	got3, err := pruneDumpFunc{}.Execute(context.Background(), rt3,
		&PruneDumpArgs{SessionID: "b74a3586-e52e-4a4a-8775-c3334fa8ea2c"})
	if err != nil {
		t.Fatal(err)
	}
	data := got3.(map[string]any)
	if data["uuid"] != "b74a3586-e52e-4a4a-8775-c3334fa8ea2c" || data["label"] != "weekly_backup" {
		t.Fatalf("prune = %v", data)
	}

	rt4, _ := newRT(map[string]process.CommandResult{
		"xfsinvutil -s missing-id -F": {Stdout: []byte("----------\nnothing\n")},
	})
	_, err = pruneDumpFunc{}.Execute(context.Background(), rt4, &PruneDumpArgs{SessionID: "missing-id"})
	if err == nil || !strings.Contains(err.Error(), `Session UUID "missing-id" was not found.`) {
		t.Fatalf("prune miss = %v", err)
	}
}

func TestEstimateMkfsModifyDefragment(t *testing.T) {
	rt, _ := newRT(map[string]process.CommandResult{
		"xfs_estimate -v /srv": {Stdout: []byte(
			"directory  bsize  blocks  megabytes  logsize\n" +
				"/srv       4096      16        1      1\n")},
	})
	if err := rt.FS.MkdirAll("/srv", 0o755); err != nil {
		t.Fatal(err)
	}

	estimateOut, err := estimateFunc{}.Execute(context.Background(), rt, &EstimateArgs{Path: "/srv"})
	if err != nil {
		t.Fatal(err)
	}
	row := estimateOut.(map[string]any)["/srv"].(map[string]any)
	if row["blocks"] != "16" || row["block _size"] != "4096" {
		t.Fatalf("estimate row = %v", row)
	}

	missing, _ := newRT(nil)
	_, err = estimateFunc{}.Execute(context.Background(), missing, &EstimateArgs{Path: "/nope"})
	if err == nil || !strings.Contains(err.Error(), `Path "/nope" was not found.`) {
		t.Fatalf("estimate path guard = %v", err)
	}

	mkfsOut := `meta-data=/dev/sda1 isize=512 agcount=4 agsize=1310720 blks
data = bsize=4096 blocks=5242880 imaxpct=25
realtime =none extsz=4096 blocks=0 rtextents=0
`
	mk, mkRunner := newRT(map[string]process.CommandResult{
		"mkfs.xfs -L backup -s size=4096 -d su=32k,sw=6 -l logdev=/dev/sda2,size=10000b -f /dev/sda1": {
			Stdout: []byte(mkfsOut),
		},
	})
	gotMk, err := mkfsFunc{}.Execute(context.Background(), mk, &MkfsArgs{
		Device: "/dev/sda1", Label: "backup", Ssize: "size=4096",
		Dso: "su=32k,sw=6", Lso: "logdev=/dev/sda2,size=10000b",
	})
	if err != nil {
		t.Fatal(err)
	}
	md := gotMk.(map[string]any)["meta-data"].(map[string]any)
	if md["section"] != "/dev/sda1" || md["isize"] != "512" {
		t.Fatalf("mkfs info = %v", md)
	}
	if !reflect.DeepEqual(mkRunner.calls[0], []string{
		"mkfs.xfs", "-L", "backup", "-s", "size=4096",
		"-d", "su=32k,sw=6", "-l", "logdev=/dev/sda2,size=10000b", "-f", "/dev/sda1"}) {
		t.Fatalf("mkfs argv = %v", mkRunner.calls[0])
	}

	// Invalid option string errors like Salt.
	_, err = mkfsFunc{}.Execute(context.Background(), mk, &MkfsArgs{
		Device: "/dev/sda1", Bso: "invalid",
	})
	if err == nil || !strings.Contains(err.Error(), `Wrong parameters "invalid" for option "-b"`) {
		t.Fatalf("mkfs opt error = %v", err)
	}

	mod, modRunner := newRT(map[string]process.CommandResult{
		"xfs_admin -L My backup -c 0 -U generate /dev/sda1": {},
		"blkid -o export /dev/sda1":                         {Stdout: []byte("DEVNAME=/dev/sda1\nTYPE=xfs\n")},
	})
	truth, falsity := true, false
	gotMod, err := modifyFunc{}.Execute(context.Background(), mod, &ModifyArgs{
		Device: "/dev/sda1", Label: "My backup", LazyCounting: &falsity, UUID: &truth,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := gotMod.(map[string]any)["/dev/sda1"]; !ok {
		t.Fatalf("modify result = %v", gotMod)
	}
	if !reflect.DeepEqual(modRunner.calls[0], []string{
		"xfs_admin", "-L", "My backup", "-c", "0", "-U", "generate", "/dev/sda1"}) {
		t.Fatalf("modify argv = %v", modRunner.calls[0])
	}

	// Nothing to modify errors.
	_, err = modifyFunc{}.Execute(context.Background(), mod, &ModifyArgs{Device: "/dev/sda1"})
	if err == nil || !strings.Contains(err.Error(), "Nothing specified for modification") {
		t.Fatalf("modify noop error = %v", err)
	}

	defr, defrRunner := newRT(map[string]process.CommandResult{
		"xfs_fsr /dev/sda1": {Stdout: []byte("done\n")},
	})
	defr.FS.MkdirAll("/proc", 0o755)
	defr.FS.WriteFile("/proc/mounts", []byte(
		"/dev/sda1 /srv xfs rw 0 0\n"), 0o600)
	gotDefr, err := defragmentFunc{}.Execute(context.Background(), defr, &DefragmentArgs{Device: "/dev/sda1"})
	if err != nil {
		t.Fatal(err)
	}
	if gotDefr.(map[string]any)["log"] != "done\n" {
		t.Fatalf("defrag = %v", gotDefr)
	}
	last := defrRunner.calls[len(defrRunner.calls)-1]
	if !reflect.DeepEqual(last, []string{"xfs_fsr", "/dev/sda1"}) {
		t.Fatalf("fsr argv = %v", last)
	}

	// Root and unmounted guards.
	_, err = defragmentFunc{}.Execute(context.Background(), defr, &DefragmentArgs{Device: "/"})
	if err == nil || err.Error() != "Root is not a device." {
		t.Fatalf("root guard = %v", err)
	}
	_, err = defragmentFunc{}.Execute(context.Background(), defr, &DefragmentArgs{Device: "/dev/sdb"})
	if err == nil || !strings.Contains(err.Error(), `Device "/dev/sdb" is not mounted`) {
		t.Fatalf("mount guard = %v", err)
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
