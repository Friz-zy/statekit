package status

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// R4.5 tests mapped onto the /proc parser behaviors read from
// saltstack/salt/modules/status.py @ pinned revision.

func stRT(t *testing.T, files map[string]string) *runtime.Runtime {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts:  facts.ForTesting(facts.Overrides{}),
	}
	for path, content := range files {
		if err := rt.FS.MkdirAll(parentOf(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return rt
}

func parentOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "/"
}

func TestCPUInfo(t *testing.T) {
	rt := stRT(t, map[string]string{"/proc/cpuinfo": strings.Join([]string{
		"processor\t: 0",
		"vendor_id\t: GenuineIntel",
		"flags\t\t: fpu sse avx2",
		"",
	}, "\n")})
	got, _ := cpuinfoFunc{}.Execute(context.Background(), rt, &cpuinfoArgs{})
	dict := got.(map[string]any)
	if dict["vendor_id"] != "GenuineIntel" {
		t.Fatalf("vendor = %#v", dict["vendor_id"])
	}
	flags, ok := dict["flags"].([]string)
	if !ok || !equalSlice(flags, []string{"fpu", "sse", "avx2"}) {
		t.Fatalf("flags = %#v", dict["flags"])
	}
}

func TestCPUStats(t *testing.T) {
	rt := stRT(t, map[string]string{"/proc/stat": strings.Join([]string{
		"cpu  100 20 300 40000 50 60 70 0 0 0",
		"intr 123456 1000 2000",
		"softirq 999 1 2 3",
		"ctxt 555555",
		"", "",
	}, "\n")})
	got, _ := cpustatsFunc{}.Execute(context.Background(), rt, &cpustatsArgs{})
	dict := got.(map[string]any)
	cpu := dict["cpu"].(map[string]any)
	if cpu["user"] != int64(100) || cpu["idle"] != int64(40000) ||
		cpu["iowait"] != int64(50) || cpu["steal"] != int64(0) {
		t.Fatalf("cpu = %#v", cpu)
	}
	intr := dict["intr"].(map[string]any)
	if intr["total"] != int64(123456) {
		t.Fatalf("intr total = %#v", intr["total"])
	}
	irqs := intr["irqs"].([]any)
	if len(irqs) != 2 || irqs[0] != int64(1000) {
		t.Fatalf("irqs = %#v", irqs)
	}
	if dict["ctxt"] != int64(555555) {
		t.Fatalf("ctxt = %#v", dict["ctxt"])
	}
}

func TestDiskStatsAndVMStats(t *testing.T) {
	rt := stRT(t, map[string]string{
		"/proc/diskstats": "   8       0 sda 100 20 300 400 500 60 700 800 90 100 110 0 0 0 0\n",
		"/proc/vmstat":    "pgpgin 1234\npgpgout 5678\npswpin 0\n",
	})

	dsRaw, _ := diskstatsFunc{}.Execute(context.Background(), rt, &diskstatsArgs{})
	ds := dsRaw.(map[string]any)["sda"].(map[string]any)
	if ds["reads_issued"] != int64(100) || ds["sectors_written"] != int64(700) {
		t.Fatalf("diskstats sda = %#v", ds)
	}

	vmRaw, _ := vmstatsFunc{}.Execute(context.Background(), rt, &vmstatsArgs{})
	vm := vmRaw.(map[string]any)
	if vm["pgpgin"] != int64(1234) || vm["pswpin"] != int64(0) {
		t.Fatalf("vmstats = %#v", vm)
	}
}

func TestNetDevAndNetStats(t *testing.T) {
	devLines := strings.Join([]string{
		"Inter-|   Receive                        |  Transmit",
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
		"  eth0: 1000 10 20 1 2 3 4 5 6 30 40 11 12 13 14 15 16 17",
	}, "\n")
	rt := stRT(t, map[string]string{"/proc/net/dev": devLines})

	got, _ := netdevFunc{}.Execute(context.Background(), rt, &netdevArgs{})
	eth := got.(map[string]any)["eth0"].(map[string]any)
	if eth["rx_bytes"] != int64(1000) || eth["rx_packets"] != int64(10) ||
		eth["tx_packets"] != int64(30) {
		t.Fatalf("eth0 = %#v", eth)
	}
	if eth["iface"] != "eth0" {
		t.Fatalf("iface = %#v", eth["iface"])
	}

	netstatLines := strings.Join([]string{
		"TcpExt: RcvPrune SndPrune",
		"TcpExt: 0 42",
		"IpExt: InNoRoutes",
		"IpExt: 7",
	}, "\n")
	rt.FS.WriteFile("/proc/net/netstat", []byte(netstatLines), 0o644)
	got, _ = netstatsFunc{}.Execute(context.Background(), rt, &netstatsArgs{})
	ns := got.(map[string]any)
	tcpext := ns["TcpExt"].(map[string]any)
	if tcpext["SndPrune"] != int64(42) {
		t.Fatalf("TcpExt = %#v", tcpext)
	}
	ipext := ns["IpExt"].(map[string]any)
	if ipext["InNoRoutes"] != int64(7) {
		t.Fatalf("IpExt = %#v", ipext)
	}
}

func TestNProcAndW(t *testing.T) {
	rt := stRT(t, nil)

	nprocFn := nprocFunc{}
	got, _ := nprocFn.Execute(context.Background(), rt, &nprocArgs{})
	if n, ok := got.(int); !ok || n < 1 {
		t.Fatalf("nproc = %#v", got)
	}

	wRunner := &fakeRunner{results: map[string]process.CommandResult{
		"w\x00-fh": {Stdout: []byte("alice pts/0 :0 10:00 5.00s 0.10s 0.05s bash\n")},
	}}
	rt.Runner = wRunner
	wFn := wFunc{}
	got, _ = wFn.Execute(context.Background(), rt, &wArgs{})
	list := got.([]map[string]any)
	if len(list) != 1 || list[0]["user"] != "alice" ||
		list[0]["tty"] != "pts/0" || list[0]["login"] != ":0" ||
		list[0]["what"] != "0.05s bash" {
		t.Fatalf("w = %#v", list)
	}
}

func TestProcsParsesHeaderIndices(t *testing.T) {
	psOut := strings.Join([]string{
		"UID PID PPID C STIME TTY TIME CMD",
		"root 1 0 0 10:00 ? 00:00:01 /sbin/init",
		"alice 42 1 0 10:01 ? 00:00:02 nginx: worker",
	}, "\n")
	runner := &fakeRunner{results: map[string]process.CommandResult{
		"ps\x00-ef": {Stdout: []byte(psOut)},
	}}
	savedPS := psCommand
	psCommand = func() string { return "ps -ef" }
	defer func() { psCommand = savedPS }()
	rt := stRT(t, nil)
	rt.Runner = runner

	got, _ := procsFunc{}.Execute(context.Background(), rt, &procsArgs{})
	procs := got.(map[string]any)
	p1 := procs["1"].(map[string]any)
	if p1["user"] != "root" || p1["cmd"] != "/sbin/init" {
		t.Fatalf("pid 1 = %#v", p1)
	}
	p42 := procs["42"].(map[string]any)
	if p42["user"] != "alice" || p42["cmd"] != "nginx: worker" {
		t.Fatalf("pid 42 = %#v", p42)
	}
}

func TestTimeFormatting(t *testing.T) {
	fn := timeFunc{}
	format := "%Y-%m-%d %H:%M:%S"
	got, _ := fn.Execute(context.Background(), nil, &timeArgs{Format: &format})
	s := got.(string)
	// Go layout conversion must produce digits in the expected positions.
	for _, part := range []string{"-", "-", " ", ":"} {
		if !strings.Contains(s, part) {
			t.Fatalf("formatted time %q lacks %q", s, part)
		}
	}
	if strings.Contains(s, "%") {
		t.Fatalf("unconverted directive remains: %q", s)
	}
}

type fakeRunner struct {
	calls   [][]string
	results map[string]process.CommandResult
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	f.calls = append(f.calls, argv)
	if res, ok := f.results[strings.Join(argv, "\x00")]; ok {
		return res
	}
	return process.CommandResult{}
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
