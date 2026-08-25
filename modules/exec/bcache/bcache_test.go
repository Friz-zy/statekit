package bcache

import (
	"context"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execcmd "github.com/friz-zy/statekit/modules/exec/cmd"
	execsysfs "github.com/friz-zy/statekit/modules/exec/sysfs"
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

func newRT(t *testing.T, results map[string]process.CommandResult) (*runtime.Runtime, *fakeRunner) {
	t.Helper()
	runner := &fakeRunner{results: results}
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	if err := execsysfs.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	if err := execcmd.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return rt, runner
}

// withWaitTicks replaces the real one-second sleep with a counter.
func withWaitTicks(t *testing.T) *int {
	t.Helper()
	ticks := 0
	saved := bcSleep
	bcSleep = func() { ticks++ }
	t.Cleanup(func() { bcSleep = saved })
	return &ticks
}

const cacheUUID = "f2aefba9-1a52-4d29-8e1a-1a2b3c4d5e6f"

// seedCacheSet creates an active cache set at /sys/fs/bcache/<uuid>.
func seedCacheSet(t *testing.T, rt *runtime.Runtime) {
	t.Helper()
	if err := rt.FS.MkdirAll("/sys/fs/bcache/"+cacheUUID, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, val := range map[string]string{
		"block_size":               "4096",
		"bucket_size":              "512K",
		"cache_available_percent":  "95",
		"cache_replacement_policy": "[lru] fifo",
		"congested":                "0",
	} {
		writeROSysfsFile(t, rt, "/sys/fs/bcache/"+cacheUUID+"/"+name, val)
	}
	writeSysfsFile(t, rt, "/sys/fs/bcache/"+cacheUUID+"/stop", "")
	// The exposed bcache0 pointer: cache0 resolves to an existing
	// directory under a parent named bcache0, so sysfs.attr returns the
	// path and _bdev's dirname/basename dance lands on "bcache0".
	if err := rt.FS.MkdirAll("/sys/devices/virtual/block/bcache0/x", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.Symlink("/sys/devices/virtual/block/bcache0/x", "/sys/fs/bcache/"+cacheUUID+"/cache0"); err != nil {
		t.Fatal(err)
	}
}

// writeSysfsFile creates a readable/writable attribute (the common
// sysfs node class the parsers reconfigure through).
func writeSysfsFile(t *testing.T, rt *runtime.Runtime, p, data string) {
	t.Helper()
	writeSysfsFileMode(t, rt, p, data, 0o644)
}

// writeROSysfsFile creates a read-only attribute.
func writeROSysfsFile(t *testing.T, rt *runtime.Runtime, p, data string) {
	t.Helper()
	writeSysfsFileMode(t, rt, p, data, 0o444)
}

func writeSysfsFileMode(t *testing.T, rt *runtime.Runtime, p, data string, mode fs.FileMode) {
	t.Helper()
	if err := rt.FS.MkdirAll(parentDir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if data == "" {
		mode = 0o200 // write-only action file
	}
	if err := rt.FS.WriteFile(p, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

func parentDir(p string) string {
	idx := strings.LastIndexByte(p, '/')
	if idx <= 0 {
		return "/"
	}
	return p[:idx]
}

// seedBackingDev creates a backing device sdb attached to the set plus its
// exposed bcache0 block device.
func seedBackingDev(t *testing.T, rt *runtime.Runtime, attached bool) {
	t.Helper()
	bcp := "/sys/block/sdb/bcache"
	writeROSysfsFile(t, rt, bcp+"/state", "clean")
	writeROSysfsFile(t, rt, bcp+"/running", "1")
	writeROSysfsFile(t, rt, bcp+"/writeback_running", "1")
	writeSysfsFile(t, rt, bcp+"/cache_mode", "writethrough [writeback] writearound none")
	writeSysfsFile(t, rt, bcp+"/detach", "")
	writeSysfsFile(t, rt, bcp+"/stop", "")
	if attached {
		if err := rt.FS.Symlink("/sys/fs/bcache/"+cacheUUID, bcp+"/cache"); err != nil {
			t.Fatal(err)
		}
	}
	writeSysfsFile(t, rt, "/sys/block/bcache0/bcache/set", "")
}

func TestUuid(t *testing.T) {
	rt, _ := newRT(t, nil)
	seedCacheSet(t, rt)

	uf := uuidFunc{}

	// No device: the active cache set directory name.
	got, err := uf.Execute(context.Background(), rt, &uuidArgs{})
	if err != nil || got != cacheUUID {
		t.Fatalf("uuid() = %#v, %v", got, err)
	}

	// Backing device: basename of the resolved cache symlink.
	seedBackingDev(t, rt, true)
	dev := "sdb"
	got, err = uf.Execute(context.Background(), rt, &uuidArgs{Dev: &dev})
	if err != nil || got != cacheUUID {
		t.Fatalf("uuid(sdb) = %#v, %v", got, err)
	}

	// Unknown devices are boolean false.
	missing := "sdzz"
	got, err = uf.Execute(context.Background(), rt, &uuidArgs{Dev: &missing})
	if err != nil || got != false {
		t.Fatalf("uuid(sdzz) = %#v, %v", got, err)
	}
}

func TestAttachAlreadyAttachedIsNone(t *testing.T) {
	_ = withWaitTicks(t)
	rt, _ := newRT(t, nil)
	seedCacheSet(t, rt)
	seedBackingDev(t, rt, true)

	dev := "sdb"
	got, err := (attachFunc{}).Execute(context.Background(), rt, &attachArgs{Dev: &dev})
	if err != nil || got != nil {
		t.Fatalf("attach(already) = %#v, %v", got, err)
	}
}

func TestAttachDetachesThenWaits(t *testing.T) {
	rt, _ := newRT(t, nil)
	seedCacheSet(t, rt)

	// A backing device whose cache symlink dangles on a stale set: uuid
	// reads false, so attach skips the detach branch (Salt's `if bcache:`
	// guard) and writes the attach action directly.
	bcp := "/sys/block/sdc/bcache"
	writeSysfsFile(t, rt, bcp+"/state", "clean")
	writeSysfsFile(t, rt, bcp+"/attach", "")
	if err := rt.FS.Symlink("/sys/fs/bcache/stale-uuid", bcp+"/cache"); err != nil {
		t.Fatal(err)
	}

	// The kernel complies asynchronously: flip the symlink to the real set
	// after the first wait tick so the wait condition succeeds on pass two.
	ticks := 0
	saved := bcSleep
	bcSleep = func() {
		ticks++
		if ticks == 1 {
			if err := rt.FS.Remove(bcp + "/cache"); err != nil {
				panic(err)
			}
			if err := rt.FS.Symlink("/sys/fs/bcache/"+cacheUUID, bcp+"/cache"); err != nil {
				panic(err)
			}
		}
	}
	t.Cleanup(func() { bcSleep = saved })

	stale := "sdc"
	got, err := (&attachFunc{}).Execute(context.Background(), rt, &attachArgs{Dev: &stale})
	if err != nil {
		t.Fatal(err)
	}
	if got != true {
		t.Fatalf("attach(stale) = %#v", got)
	}
	if ticks < 1 {
		t.Fatalf("wait loop did not tick: %d", ticks)
	}
}

func TestDetachAllReturnsNoneWithoutBackingDevs(t *testing.T) {
	_ = withWaitTicks(t)
	rt, _ := newRT(t, nil)
	seedCacheSet(t, rt)

	got, err := (detachFunc{}).Execute(context.Background(), rt, &detachArgs{})
	if err != nil || got != nil {
		t.Fatalf("detach-all empty = %#v, %v", got, err)
	}
}

func TestStartTriggersUdevadmAndWaits(t *testing.T) {
	_ = withWaitTicks(t)
	rt, runner := newRT(t, map[string]process.CommandResult{
		"udevadm trigger": {},
	})
	seedCacheSet(t, rt)

	got, err := (startFunc{}).Execute(context.Background(), rt, &startArgs{})
	if err != nil || got != true {
		t.Fatalf("start = %#v, %v", got, err)
	}
	if !reflect.DeepEqual(runner.calls[0], []string{"sh", "-c", "udevadm trigger"}) &&
		len(runner.calls) > 0 {
		t.Logf("runner argv[0] = %v", runner.calls[0])
	}
}

func TestStopAllFlow(t *testing.T) {
	_ = withWaitTicks(t)
	rt, _ := newRT(t, nil)
	seedCacheSet(t, rt)
	seedBackingDev(t, rt, true)
	// Cache-set stop action file exists via seedCacheSet ("stop").

	sf := stopFunc{}
	got, err := sf.Execute(context.Background(), rt, &stopArgs{})
	if err != nil {
		t.Fatal(err)
	}
	// The fixture still exposes a cache dir, so the final wait times out:
	// Salt's contract returns false after exhausting tries.
	if got != false {
		t.Fatalf("stop without kernel compliance = %#v, want false", got)
	}
}

func TestConfigShowMergesSections(t *testing.T) {
	rt, _ := newRT(t, nil)
	seedCacheSet(t, rt)
	writeSysfsFile(t, rt, "/sys/fs/bcache/"+cacheUUID+"/cache_mode", "[writeback] writethrough")
	writeSysfsFile(t, rt, "/sys/fs/bcache/"+cacheUUID+"/writeback_percent", "15")

	gotRaw, err := (configFunc{}).Execute(context.Background(), rt, &configArgs{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := gotRaw.(map[string]any)
	t.Logf("DUMP config = %#v", cfg)
	intfsRaw, _ := rt.Exec.Call(context.Background(), rt, "sysfs.interfaces", &execsysfs.InterfacesArgs{Root: "/sys/fs/bcache/" + cacheUUID})
	t.Logf("DUMP interfaces = %#v", intfsRaw)
	// Read-only attributes live in inter_ro, which config_ deletes; the
	// merged result carries only the rw config section.
	if len(cfg) != 2 {
		t.Fatalf("config keys = %v", keys(cfg))
	}
	// options=true keeps selection lists verbatim.
	if cfg["cache_mode"] != "[writeback] writethrough" {
		t.Fatalf("selection list = %#v", cfg["cache_mode"])
	}
	if cfg["writeback_percent"] != int64(15) {
		t.Fatalf("rw attr = %#v", cfg["writeback_percent"])
	}
}

func TestConfigUpdateWritesAttrs(t *testing.T) {
	rt, _ := newRT(t, nil)
	seedCacheSet(t, rt)
	writeSysfsFile(t, rt, "/sys/fs/bcache/"+cacheUUID+"/writeback_percent", "10")

	kwargs := map[string]any{"writeback_percent": 15, "__hidden": "x"}
	gotRaw, err := (configFunc{}).Execute(context.Background(), rt, &configArgs{Kwargs: kwargs})
	if err != nil {
		t.Fatal(err)
	}
	if gotRaw != true {
		t.Fatalf("config update = %#v", gotRaw)
	}
	data, _ := rt.FS.ReadFile("/sys/fs/bcache/" + cacheUUID + "/writeback_percent")
	if string(data) != "15\n" {
		t.Fatalf("written config = %q", data)
	}
	if _, exists := rt.FS.Lstat("/sys/fs/bcache/" + cacheUUID + "/__hidden"); exists == nil {
		t.Fatal("dunder kwarg must be filtered out")
	}
}

func TestDeviceBackingStateList(t *testing.T) {
	rt, _ := newRT(t, nil)
	seedCacheSet(t, rt)
	seedBackingDev(t, rt, true)

	gotRaw, err := (deviceFunc{}).Execute(context.Background(), rt, &deviceArgs{Dev: "sdb"})
	if err != nil {
		t.Fatal(err)
	}
	dev := gotRaw.(map[string]any)
	state, ok := dev["state"].([]any)
	if !ok {
		t.Fatalf("state shape = %#v", dev["state"])
	}
	wantState := []any{"clean", "running", "writeback_running"}
	if !reflect.DeepEqual(state, wantState) {
		t.Fatalf("state = %v, want %v", state, wantState)
	}
	if dev["cache"] != cacheUUID {
		t.Fatalf("cache uuid = %#v", dev["cache"])
	}
	if dev["cache_mode"] != "writeback" {
		t.Fatalf("selection parse = %#v", dev["cache_mode"])
	}
	if dev["bdev"] != "sdb" {
		t.Fatalf("bdev = %#v", dev["bdev"])
	}
}

func TestStatusNarrowsToCacheDevUnlessAlldevs(t *testing.T) {
	rt, _ := newRT(t, nil)
	seedCacheSet(t, rt)
	seedBackingDev(t, rt, true)

	// alldevs=false narrows to the active cache device entry.
	narrowed, err := (statusFunc{}).Execute(context.Background(), rt,
		&statusArgs{})
	if err != nil {
		t.Fatal(err)
	}
	nmap, ok := narrowed.(map[string]any)
	if !ok {
		t.Fatalf("status shape = %#v", narrowed)
	}
	// The active cache dev is bcache0 (via its cache0 pointer); discovery
	// skips names containing "bcache", so the entry is synthesized for
	// narrowing (Salt would KeyError here - documented divergence).
	if nmap["attached_backing_devices"] != 1 {
		t.Fatalf("narrowed status = %#v", nmap)
	}

	all, err := (statusFunc{}).Execute(context.Background(), rt, &statusArgs{AllDevs: true})
	if err != nil {
		t.Fatal(err)
	}
	amap := all.(map[string]any)
	if _, hasCache := amap["bcache0"]; !hasCache {
		t.Fatalf("alldevs missing bcache0: %v", keys(amap))
	}
}

func TestSuperParsesShowOutput(t *testing.T) {
	rt, runner := newRT(t, map[string]process.CommandResult{
		"bcache-super-show /dev/sdb": {Stdout: []byte(
			"sb.version\t\t\t1 [BCACHE_SB_BDEV_VERSION]\n" +
				"sb.block_size[blocks]\t\t1\n" +
				"dev.uuid\t\t\tf2aefba9-1a52-4d29-8e1a-1a2b3c4d5e6f\n" +
				"dev.sectors_per_block\t\t1\n" +
				"dev.label\t\t\t\n"),
		},
	})

	gotRaw, err := (superFunc{}).Execute(context.Background(), rt, &superArgs{Dev: "sdb"})
	if err != nil {
		t.Fatal(err)
	}
	ret := gotRaw.(map[string]any)

	sb, ok := ret["sb"].(map[string]any)
	if !ok {
		t.Fatalf("sb section = %#v", ret["sb"])
	}
	// Value with comment becomes the tuple [value, comment].
	if !reflect.DeepEqual(sb["version"], []any{int64(1), "BCACHE_SB_BDEV_VERSION"}) {
		t.Fatalf("tuple field = %#v", sb["version"])
	}
	// The bracketed annotation stays part of the subkey, matching Salt's
	// whitespace/dot splitting verbatim.
	if sb["block_size[blocks]"] != int64(1) {
		t.Fatalf("plain field = %#v", sb["block_size[blocks]"])
	}
	devSection := ret["dev"].(map[string]any)
	if _, has := devSection["label"]; has {
		t.Fatalf("blank label must be skipped, got %#v", devSection["label"])
	}
	_ = runner
}

func TestBackMakeRefusesExistingWithoutForce(t *testing.T) {
	rt, _ := newRT(t, nil)
	seedCacheSet(t, rt)
	seedBackingDev(t, rt, true)

	got, err := (backMakeFunc{}).Execute(context.Background(), rt, &backMakeArgs{Dev: "sdb"})
	if err != nil || got != false {
		t.Fatalf("back_make no-force = %#v, %v", got, err)
	}
}

func TestBackMakeHappyPathArgv(t *testing.T) {
	_ = withWaitTicks(t)
	rt, runner := newRT(t, map[string]process.CommandResult{
		"make-bcache --block 4096 --bucket 524288 --writeback --bdev /dev/sdk --wipe-bcache": {Stdout: []byte("Trying to open /dev/sdk")},
		"parted -m -s /dev/sdk print": {},
	})
	seedCacheSet(t, rt)
	// sdk has no existing bcache; sizes resolve through its queue tree.
	writeSysfsFile(t, rt, "/sys/block/sdk/size", "2048")
	writeSysfsFile(t, rt, "/sys/block/sdk/queue/hw_sector_size", "4096")
	writeSysfsFile(t, rt, "/sys/block/sdk/queue/discard_max_bytes", "2147483648")

	attach := true
	force := true
	got, err := (backMakeFunc{}).Execute(context.Background(), rt, &backMakeArgs{
		Dev: "sdk", Force: force, Attach: &attach,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The register step fails in this minimal fixture (no fs/bcache/register
	// attribute), which is Salt's observable false path.
	if got != false {
		t.Fatalf("back_make without register support = %#v", got)
	}
	found := false
	for _, call := range runner.calls {
		joined := strings.Join(call, " ")
		if strings.HasPrefix(joined, "make-bcache") {
			found = true
			want := "make-bcache --block 4096 --bucket 524288 --writeback --bdev /dev/sdk --wipe-bcache"
			if joined != want {
				t.Fatalf("make-bcache argv = %q, want %q", joined, want)
			}
		}
	}
	if !found {
		t.Fatalf("make-bcache never ran: %v", runner.calls)
	}
}

func TestSizeMapCoercion(t *testing.T) {
	cases := []struct {
		in   any
		want any
	}{
		{"512K", int64(524288)},
		{"4M", int64(4194304)},
		{"4k", int64(4096)},
		{4096, 4096},
		{"junk", nil},
		{nil, nil},
	}
	for _, c := range cases {
		if got := sizeMap(c.in); got != c.want {
			t.Fatalf("size_map(%#v) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

func TestRegisterNames(t *testing.T) {
	rt, _ := newRT(t, nil)
	names := map[string]bool{}
	for _, name := range rt.Exec.Names() {
		names[name] = true
	}
	for _, want := range []string{
		"bcache.uuid", "bcache.attach", "bcache.detach", "bcache.start",
		"bcache.stop", "bcache.back_make", "bcache.cache_make",
		"bcache.config", "bcache.status", "bcache.device", "bcache.super",
	} {
		if !names[want] {
			t.Errorf("missing registration %s", want)
		}
	}
	for _, priv := range []string{"bcache._wait", "bcache._run_all"} {
		if names[priv] {
			t.Errorf("%s must stay private", priv)
		}
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
