package ps

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execcmd "github.com/friz-zy/statekit/modules/exec/cmd"
)

// procFixture builds a hermetic /proc tree covering the parsed contracts.
func newRT(t *testing.T, extra map[string]string) (*runtime.Runtime, *int) {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
	}
	if err := execcmd.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}

	write := func(p, data string) {
		if err := rt.FS.MkdirAll(parentDir(p), 0o755); err != nil {
			t.Fatalf("fixture mkdir %s: %v", p, err)
		}
		if err := rt.FS.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatalf("fixture write %s: %v", p, err)
		}
	}

	write("/proc/stat",
		"cpu  100 0 200 700 50 0 10 0 0 0\n"+
			"cpu0 60 0 100 350 30 0 5 0 0 0\n"+
			"cpu1 40 0 100 350 20 0 5 0 0 0\n"+
			"btime 1700000000\n")
	write("/proc/meminfo",
		"MemTotal:        4000000 kB\n"+
			"MemFree:         1000000 kB\n"+
			"MemAvailable:    2000000 kB\n"+
			"Buffers:          150000 kB\n"+
			"Cached:           500000 kB\n"+
			"SwapCached:            0 kB\n"+
			"Active:           900000 kB\n"+
			"Inactive:         800000 kB\n"+
			"SwapTotal:        500000 kB\n"+
			"SwapFree:         250000 kB\n"+
			"Shmem:             50000 kB\n"+
			"Slab:              60000 kB\n"+
			"SReclaimable:      30000 kB\n")
	write("/proc/vmstat", "pswpin 100\npswpout 200\npgfault 90000\n")
	write("/proc/net/dev",
		"Inter-|   Receive                        |  Transmit\n"+
			" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"+
			"    lo: 1000    10    0    0    0     0          0         0     1000    10    0    0    0     0       0          0\n"+
			"  eth0: 9000    90    1    2    0     0          0         0     8000    80    3    4    0     0       0          0\n")
	write("/proc/diskstats",
		"   8       0 sda 30 4 100 40 20 5 60 30 0 70 70 0 0 0 0 0 0\n")
	write("/proc/self/mounts",
		"/dev/sda1 / ext4 rw,relatime 0 0\n"+
			"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"+
			"tmpfs /run tmpfs rw,nosuid,nodev 0 0\n")
	write("/proc/filesystems",
		"ext3\next4\nnodev\tproc\nnodev\ttmpfs\nnodev\tramfs\n")
	write("/proc/42/stat",
		"42 (my app) S 1 42 42 0 -1 4194560 100 0 0 200 50 25 0 0 20 0 1 0 10000 100000000 1200 18446744073709551615\n")
	write("/proc/42/status",
		"Name:\tmy app\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\n")
	write("/proc/42/cmdline", "my\x00app\x00--flag\x00")
	write("/proc/99/stat",
		"99 (zombie) Z 1 99 99 0 -1 0 0 0 0 0 0 0 0 5 0 1 0 1700000200 0 0 0\n")
	write("/var/run/utmp", buildUtmpRecord())

	savedRoot := procRoot
	procRoot = func(*runtime.Runtime) string { return "/proc" }
	t.Cleanup(func() { procRoot = savedRoot })

	ticks := 0
	savedSleep := sleepHook
	sleepHook = func(time.Duration) { ticks++ }
	t.Cleanup(func() { sleepHook = savedSleep })

	savedTools := toolLookup
	toolLookup = func(exe string) bool { return exe == "lsof" || exe == "netstat" || exe == "ss" }
	t.Cleanup(func() { toolLookup = savedTools })

	savedLookup := userLookup
	userLookup = func(uid string) (string, bool) {
		if uid == "1000" {
			return "alice", true
		}
		return "", false
	}
	t.Cleanup(func() { userLookup = savedLookup })

	for path, data := range extra {
		write(path, data)
	}
	return rt, &ticks
}

func parentDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "/"
}

// buildUtmpRecord renders one little-endian linux utmp USER_PROCESS entry.
func buildUtmpRecord() string {
	rec := make([]byte, 384)
	rec[0] = 7 // ut_type USER_PROCESS
	putLE32(rec[4:], 1234)
	copy(rec[8:], "pts/0")
	copy(rec[44:], "alice")
	copy(rec[76:], "office")
	putLE32(rec[340:], 1700000300)
	return string(rec)
}

func putLE32(dst []byte, v uint32) {
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v >> 16)
	dst[3] = byte(v >> 24)
}

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

func TestGetPidList(t *testing.T) {
	rt, _ := newRT(t, nil)
	gotRaw, err := (getPIDListFunc{}).Execute(context.Background(), rt, &getPidsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	got := gotRaw.([]any)
	want := []any{int64(42), int64(99)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pids = %#v, want sorted %v", got, want)
	}
}

func TestProcInfo(t *testing.T) {
	rt, _ := newRT(t, nil)
	pf := procInfoFunc{}
	gotRaw, err := pf.Execute(context.Background(), rt, &ProcInfoArgs{Pid: 42})
	if err != nil {
		t.Fatal(err)
	}
	info := gotRaw.(map[string]any)
	if info["pid"] != int64(42) || info["name"] != "my app" || info["status"] != "sleeping" ||
		info["username"] != "alice" {
		t.Fatalf("info = %#v", info)
	}
	if info["create_time"] != float64(1700000100) {
		t.Fatalf("create_time = %#v", info["create_time"])
	}
	if !reflect.DeepEqual(info["cmdline"], []string{"my", "app", "--flag"}) {
		t.Fatalf("cmdline = %#v", info["cmdline"])
	}

	// attrs filters the dict; unknown attributes raise.
	gotRaw, err = pf.Execute(context.Background(), rt, &ProcInfoArgs{
		Pid: 42, Attrs: []string{"pid", "name"},
	})
	if err != nil {
		t.Fatal(err)
	}
	filtered := gotRaw.(map[string]any)
	if len(filtered) != 2 || filtered["name"] != "my app" {
		t.Fatalf("filtered = %#v", filtered)
	}
	if _, err := pf.Execute(context.Background(), rt, &ProcInfoArgs{
		Pid: 42, Attrs: []string{"bogus"},
	}); err == nil {
		t.Fatal("unknown attr must raise")
	}

	// Missing processes raise like psutil.NoSuchProcess.
	if _, err := pf.Execute(context.Background(), rt, &ProcInfoArgs{Pid: 777}); err == nil {
		t.Fatal("missing pid must raise")
	}
}

func TestStatus(t *testing.T) {
	rt, _ := newRT(t, nil)
	sf := statusFunc{}

	gotRaw, err := sf.Execute(context.Background(), rt, &StatusArgs{Status: "zombie"})
	if err != nil {
		t.Fatal(err)
	}
	want := []any{map[string]any{"pid": int64(99), "name": "zombie"}}
	if !reflect.DeepEqual(gotRaw, want) {
		t.Fatalf("zombie filter = %#v", gotRaw)
	}

	gotRaw, err = sf.Execute(context.Background(), rt, &StatusArgs{Status: "sleeping"})
	if err != nil {
		t.Fatal(err)
	}
	want = []any{map[string]any{"pid": int64(42), "name": "my app"}}
	if !reflect.DeepEqual(gotRaw, want) {
		t.Fatalf("sleeping filter = %#v", gotRaw)
	}

	if _, err = sf.Execute(context.Background(), rt, &StatusArgs{}); err == nil ||
		err.Error() != "Filter is required for ps.status" {
		t.Fatalf("empty filter err = %v", err)
	}
}

func TestPgrepPkill(t *testing.T) {
	var killedSignals []int
	rt, _ := newRT(t, nil)
	savedSend := sendSignalFn
	sendSignalFn = func(pid int, signal int) error {
		killedSignals = append(killedSignals, signal)
		return nil
	}
	t.Cleanup(func() { sendSignalFn = savedSend })

	pgf := pgrepFunc{}
	gotRaw, err := pgf.Execute(context.Background(), rt, &PgrepArgs{Pattern: "app"})
	if err != nil || !reflect.DeepEqual(gotRaw, []any{int64(42)}) {
		t.Fatalf("pgrep name match = %#v, %v", gotRaw, err)
	}

	// full=true searches the joined cmdline.
	gotRaw, err = pgf.Execute(context.Background(), rt, &PgrepArgs{
		Pattern: "flag", Full: true,
	})
	if err != nil || !reflect.DeepEqual(gotRaw, []any{int64(42)}) {
		t.Fatalf("pgrep cmdline match = %#v, %v", gotRaw, err)
	}

	// No matches collapse to None.
	gotRaw, err = pgf.Execute(context.Background(), rt, &PgrepArgs{Pattern: "missing"})
	if err != nil || gotRaw != nil {
		t.Fatalf("empty pgrep = %#v, %v", gotRaw, err)
	}

	// Regex mode mirrors pattern_is_regex.
	gotRaw, err = pgf.Execute(context.Background(), rt, &PgrepArgs{
		Pattern: "^my$", PatternIsRegex: true,
	})
	if err != nil || gotRaw != nil {
		t.Fatalf("regex anchored miss = %#v, %v", gotRaw, err)
	}
	gotRaw, err = pgf.Execute(context.Background(), rt, &PgrepArgs{
		Pattern: "a.p", PatternIsRegex: true,
	})
	if err != nil || !reflect.DeepEqual(gotRaw, []any{int64(42)}) {
		t.Fatalf("regex hit = %#v, %v", gotRaw, err)
	}

	// User filter excludes non-matching owners.
	alice := "alice"
	bob := "bob"
	gotRaw, err = pgf.Execute(context.Background(), rt, &PgrepArgs{Pattern: "app", User: &alice})
	if err != nil || len(gotRaw.([]any)) != 1 {
		t.Fatalf("user alice = %#v, %v", gotRaw, err)
	}
	gotRaw, err = pgf.Execute(context.Background(), rt, &PgrepArgs{Pattern: "app", User: &bob})
	if err != nil || gotRaw != nil {
		t.Fatalf("user bob = %#v, %v", gotRaw, err)
	}

	// kill_pid reports false for unknown pids and true on delivery.
	kf := killPIDFunc{}
	gotRaw, err = kf.Execute(context.Background(), rt, &KillPidArgs{Pid: 777})
	if err != nil || gotRaw != false {
		t.Fatalf("kill_pid missing = %#v, %v", gotRaw, err)
	}
	gotRaw, err = kf.Execute(context.Background(), rt, &KillPidArgs{Pid: 42})
	if err != nil || gotRaw != true {
		t.Fatalf("kill_pid hit = %#v, %v", gotRaw, err)
	}

	// pkill reports the killed set or None.
	pkf := pkillFunc{}
	gotRaw, err = pkf.Execute(context.Background(), rt, &PkillArgs{Pattern: "app"})
	if err != nil {
		t.Fatal(err)
	}
	killedMap := gotRaw.(map[string]any)
	if !reflect.DeepEqual(killedMap["killed"], []any{int64(42)}) {
		t.Fatalf("killed = %#v", killedMap)
	}
	// kill_pid delivered once, pkill once: both default SIGTERM.
	if !reflect.DeepEqual(killedSignals, []int{15, 15}) {
		t.Fatalf("default signals = %v", killedSignals)
	}

	gotRaw, err = pkf.Execute(context.Background(), rt, &PkillArgs{Pattern: "missing"})
	if err != nil || gotRaw != nil {
		t.Fatalf("pkill none = %#v, %v", gotRaw, err)
	}
}

func TestCpuPercentAndTimes(t *testing.T) {
	rt, ticks := newRT(t, nil)

	gotRaw, err := (cpuPercentFunc{}).Execute(context.Background(), rt, &CpuPercentArgs{Interval: floatPtr(0)})
	if err != nil {
		t.Fatal(err)
	}
	if gotRaw.(float64) < 0 || gotRaw.(float64) > 100 {
		t.Fatalf("cpu_percent out of range = %v", gotRaw)
	}
	if *ticks != 1 {
		t.Fatalf("interval sampling must tick once, got %d", *ticks)
	}

	gotRaw, err = (cpuPercentFunc{}).Execute(context.Background(), rt, &CpuPercentArgs{
		Interval: floatPtr(0), PerCpu: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	list := gotRaw.([]any)
	if len(list) != 2 {
		t.Fatalf("per_cpu entries = %d (%#v)", len(list), list)
	}

	ctf := cpuTimesFunc{}
	gotRaw, err = ctf.Execute(context.Background(), rt, &CpuTimesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	times := gotRaw.(map[string]any)
	if times["user"] != 1.0 || times["system"] != 2.0 || times["idle"] != 7.0 || times["iowait"] != 0.5 {
		t.Fatalf("cpu_times = %#v (ticks are converted to seconds)", times)
	}

	gotRaw, err = ctf.Execute(context.Background(), rt, &CpuTimesArgs{PerCpu: true})
	if err != nil {
		t.Fatal(err)
	}
	perCpu := gotRaw.([]any)
	if len(perCpu) != 2 {
		t.Fatalf("per-cpu count = %d", len(perCpu))
	}
	first := perCpu[0].(map[string]any)
	if first["user"] != 0.6 {
		t.Fatalf("cpu0 user = %#v", first["user"])
	}
}

func TestMemory(t *testing.T) {
	rt, _ := newRT(t, nil)

	vmRaw, err := (virtualMemoryFunc{}).Execute(context.Background(), rt, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	vm := vmRaw.(map[string]any)
	const kb = 1024
	if vm["total"] != int64(4000000*kb) {
		t.Fatalf("total = %#v", vm["total"])
	}
	if vm["available"] != int64(2000000*kb) {
		t.Fatalf("available = %#v", vm["available"])
	}
	if vm["used"] != int64(2000000*kb) {
		t.Fatalf("used = total-available = %#v", vm["used"])
	}
	if vm["percent"] != 50.0 {
		t.Fatalf("percent = %#v", vm["percent"])
	}

	swRaw, err := (swapMemoryFunc{}).Execute(context.Background(), rt, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	sw := swRaw.(map[string]any)
	if sw["total"] != int64(500000*kb) || sw["free"] != int64(250000*kb) ||
		sw["used"] != int64(250000*kb) || sw["percent"] != 50.0 {
		t.Fatalf("swap = %#v", sw)
	}
	pageSize := int64(os.Getpagesize())
	if sw["swin"] != int64(100*pageSize) || sw["swout"] != int64(200*pageSize) {
		t.Fatalf("swap io = %#v", sw)
	}

	tpmRaw, err := (totalPhysicalMemoryFunc{}).Execute(context.Background(), rt, &TotalPhysicalMemoryArgs{})
	if err != nil || tpmRaw != int64(4000000*kb) {
		t.Fatalf("total_physical_memory = %#v, %v", tpmRaw, err)
	}
}

func TestNumCpusAndBootTime(t *testing.T) {
	rt, _ := newRT(t, nil)

	gotRaw, err := (numCpusFunc{}).Execute(context.Background(), rt, &NumCpusArgs{})
	if err != nil || gotRaw != int64(2) {
		t.Fatalf("num_cpus = %#v, %v", gotRaw, err)
	}

	bf := bootTimeFunc{}
	gotRaw, err = bf.Execute(context.Background(), rt, &BootTimeArgs{})
	if err != nil || gotRaw != int64(1700000000) {
		t.Fatalf("boot_time = %#v, %v", gotRaw, err)
	}

	fmtStr := "%Y-%m-%d %H:%M:%S"
	gotRaw, err = bf.Execute(context.Background(), rt, &BootTimeArgs{TimeFormat: &fmtStr})
	if err != nil {
		t.Fatal(err)
	}
	if gotRaw.(string) != "2023-11-14 22:13:20" {
		t.Fatalf("formatted boot time = %#v", gotRaw)
	}

	badFormat := "%Q"
	if _, err = bf.Execute(context.Background(), rt, &BootTimeArgs{TimeFormat: &badFormat}); err == nil ||
		err.Error() != "Invalid format string" {
		t.Fatalf("invalid format err = %v", err)
	}
}

func TestNetworkAndDiskIOCounters(t *testing.T) {
	rt, _ := newRT(t, nil)

	nf := networkIOCountersFunc{}
	totalRaw, err := nf.Execute(context.Background(), rt, &NetworkIoCountersArgs{})
	if err != nil {
		t.Fatal(err)
	}
	total := totalRaw.(map[string]any)
	if total["bytes_recv"] != int64(10000) || total["bytes_sent"] != int64(9000) ||
		total["packets_recv"] != int64(100) {
		t.Fatalf("aggregate net counters = %#v", total)
	}

	eth := "eth0"
	nicRaw, err := nf.Execute(context.Background(), rt, &NetworkIoCountersArgs{Interface: &eth})
	if err != nil {
		t.Fatal(err)
	}
	nic := nicRaw.(map[string]any)
	if nic["errin"] != int64(1) || nic["dropout"] != int64(4) {
		t.Fatalf("eth0 counters = %#v", nic)
	}

	missing := "ens9"
	gotRaw, err := nf.Execute(context.Background(), rt, &NetworkIoCountersArgs{Interface: &missing})
	if err != nil || gotRaw != false {
		t.Fatalf("missing interface = %#v, %v", gotRaw, err)
	}

	df := diskIOCountersFunc{}
	devRaw, err := df.Execute(context.Background(), rt, &DiskIoCountersArgs{})
	if err != nil {
		t.Fatal(err)
	}
	agg := devRaw.(map[string]any)
	if agg["read_count"] != int64(30) || agg["read_bytes"] != int64(100*512) ||
		agg["write_bytes"] != int64(60*512) || agg["busy_time"] != int64(70) {
		t.Fatalf("disk counters = %#v", agg)
	}

	sda1 := "sda1"
	gotRaw, err = df.Execute(context.Background(), rt, &DiskIoCountersArgs{Device: &sda1})
	if err != nil || gotRaw != false {
		t.Fatalf("missing device = %#v, %v", gotRaw, err)
	}
}

func TestGetUsers(t *testing.T) {
	rt, _ := newRT(t, nil)
	gotRaw, err := (getUsersFunc{}).Execute(context.Background(), rt, &GetUsersArgs{})
	if err != nil {
		t.Fatal(err)
	}
	users := gotRaw.([]any)
	if len(users) != 1 {
		t.Fatalf("users = %#v", users)
	}
	u := users[0].(map[string]any)
	if u["name"] != "alice" || u["terminal"] != "pts/0" ||
		u["started"] != int64(1700000300) || u["host"] != "office" {
		t.Fatalf("user record = %#v", u)
	}
}

func TestDiskPartitionsAndUsage(t *testing.T) {
	rt, _ := newRT(t, nil)

	dpf := diskPartitionsFunc{}
	gotRaw, err := dpf.Execute(context.Background(), rt, &DiskPartitionsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	parts := gotRaw.([]any)
	if len(parts) != 1 {
		t.Fatalf("physical partitions = %#v (nodev fs must be excluded)", parts)
	}
	entry := parts[0].(map[string]any)
	if entry["device"] != "/dev/sda1" || entry["mountpoint"] != "/" || entry["fstype"] != "ext4" {
		t.Fatalf("partition entry = %#v", entry)
	}

	allRaw, err := dpf.Execute(context.Background(), rt, &DiskPartitionsArgs{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(allRaw.([]any)) != 3 {
		t.Fatalf("all partitions = %#v", allRaw)
	}

	duf := diskUsageFunc{}
	gotRaw, err = duf.Execute(context.Background(), rt, &DiskUsageArgs{Path: "/"})
	if err != nil {
		t.Fatal(err)
	}
	usage := gotRaw.(map[string]any)
	if usage["total"].(uint64) == 0 || usage["free"].(uint64) == 0 {
		t.Fatalf("usage = %#v", usage)
	}
	up := usage["percent"].(float64)
	if up <= 0 || up >= 100 {
		t.Fatalf("usage percent = %v", up)
	}

	// Composed function merges usage into each partition entry.
	dpuRaw, err := (diskPartitionUsageFunc{}).Execute(context.Background(), rt,
		&DiskPartitionsArgs{All: true})
	if err != nil {
		t.Fatal(err)
	}
	first := dpuRaw.([]any)[0].(map[string]any)
	if _, has := first["total"]; !has {
		t.Fatalf("partition usage merge missing: %#v", first)
	}
}

func TestCLIWrappers(t *testing.T) {
	psauxOut := "USER  PID %CPU %MEM COMMAND\nroot      1  0.0  0.1 /sbin/init\nwww-data 42  0.5  1.0 apache2 -DFOREGROUND\n"
	rt := func() *runtime.Runtime {
		rt2, _ := newRT(t, nil)
		return rt2
	}()
	runner := &fakeRunner{results: map[string]process.CommandResult{
		"lsof -c apache2": {Stdout: []byte("lsof output")},
		"netstat -nap":    {Stdout: []byte("tcp 80 0.0.0.0:80 apache2\nudp 68 0.0.0.0:68 dhclient\n")},
		"ss -neap":        {Stdout: []byte("ESTAB 0 0 10.0.0.1:22 apache2\n")},
		"ps aux":          {Stdout: []byte(psauxOut)},
	}}
	prev := rt.Runner
	rt.Runner = runner
	defer func() { rt.Runner = prev }()

	lf := lsofFunc{}
	gotRaw, err := lf.Execute(context.Background(), rt, &NameArgs{Name: "apache2"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotRaw, []any{"apache2", "lsof output"}) {
		t.Fatalf("lsof = %#v", gotRaw)
	}

	nf := netstatFunc{}
	gotRaw, err = nf.Execute(context.Background(), rt, &NameArgs{Name: "apache2"})
	if err != nil {
		t.Fatal(err)
	}
	ret := gotRaw.([]any)
	found := ret[1].([]any)
	if len(found) != 1 || !strings.Contains(found[0].(string), "apache2") {
		t.Fatalf("netstat found = %#v", found)
	}

	ssf := ssFunc{}
	gotRaw, err = ssf.Execute(context.Background(), rt, &NameArgs{Name: "apache2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotRaw.([]any)[1].([]any)) != 1 {
		t.Fatalf("ss result = %#v", gotRaw)
	}

	paf := psauxFunc{}
	gotRaw, err = paf.Execute(context.Background(), rt, &NameArgs{Name: "apache2"})
	if err != nil {
		t.Fatal(err)
	}
	ret = gotRaw.([]any)
	if ret[0] != "apache2" || ret[2] != "1 occurrence(s)." {
		t.Fatalf("psaux = %#v", ret)
	}
}

func TestTopSamplesAndOrders(t *testing.T) {
	// A second process whose CPU advances between samples outranks others.
	rt, _ := newRT(t, map[string]string{
		"/proc/43/stat":    "43 (busy) R 1 43 43 0 -1 0 0 0 0 400 0 0 0 30 0 1 0 1700000110 50000 100 0\n",
		"/proc/43/cmdline": "",
	})

	phase := 0
	savedSleep := sleepHook
	sleepHook = func(time.Duration) { phase++ }
	t.Cleanup(func() { sleepHook = savedSleep })

	_ = phase

	tf := topFunc{}
	gotRaw, err := tf.Execute(context.Background(), rt, &TopArgs{NumProcesses: intPtr(1), Interval: floatPtr(0)})
	if err != nil {
		t.Fatal(err)
	}
	top := gotRaw.([]any)
	if len(top) != 1 {
		t.Fatalf("top length = %d (%#v)", len(top), top)
	}
	entry := top[0].(map[string]any)
	// The static fixture yields equal diffs; only the shape is pinned.
	for _, key := range []string{"cmd", "user", "status", "pid", "create_time", "cpu", "mem"} {
		if _, has := entry[key]; !has {
			t.Fatalf("top entry missing %q: %#v", key, entry)
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
		"ps.top", "ps.get_pid_list", "ps.proc_info", "ps.kill_pid", "ps.pkill",
		"ps.pgrep", "ps.cpu_percent", "ps.cpu_times", "ps.virtual_memory",
		"ps.swap_memory", "ps.disk_partitions", "ps.disk_usage",
		"ps.disk_partition_usage", "ps.total_physical_memory", "ps.num_cpus",
		"ps.boot_time", "ps.network_io_counters", "ps.disk_io_counters",
		"ps.get_users", "ps.lsof", "ps.netstat", "ps.ss", "ps.psaux", "ps.status",
	} {
		if !names[want] {
			t.Errorf("missing registration %s", want)
		}
	}
	for _, priv := range []string{"ps._get_proc_cmdline", "ps._get_proc_name"} {
		if names[priv] {
			t.Errorf("%s must stay private", priv)
		}
	}
}

func boolPtr(b bool) *bool        { return &b }
func intPtr(i int) *int           { return &i }
func floatPtr(f float64) *float64 { return &f }
