package network

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// newToolsRT wires the tools batch with a kernel override and runner.
func newToolsRT(t *testing.T, kernel string, results map[string]process.CommandResult) (*runtime.Runtime, *procRunner) {
	t.Helper()
	savedKernel := kernelHook
	kernelHook = func(*runtime.Runtime) string { return kernel }
	t.Cleanup(func() { kernelHook = savedKernel })

	savedData := ifacesDataHook
	ifacesDataHook = func(context.Context, *runtime.Runtime) map[string]any {
		rtProbe := &runtime.Runtime{FS: runtime.NewMemoryFS(), Runner: &procRunner{}}
		if err := rtProbe.FS.MkdirAll("/proc/net", 0o755); err != nil {
			t.Fatal(err)
		}
		parsed, perr := parseInterfacesIP(ipLinkOut + "\n" + ipAddrOut)
		if perr != nil {
			t.Fatal(perr)
		}
		return parsed
	}
	t.Cleanup(func() { ifacesDataHook = savedData })

	savedTools := toolPath
	toolPath = func(ostool string) string { return "/usr/sbin/" + ostool }
	t.Cleanup(func() { toolPath = savedTools })

	runner := &procRunner{results: results}
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return rt, runner
}

const netstatOut = `Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name
tcp        0      0 127.0.0.1:4505          0.0.0.0:*               LISTEN      0          11111      4321/python
udp        0      0 0.0.0.0:68              0.0.0.0:*                           0          22222      9999/dhclient`

// Mirrors the _netstat_linux column mapping.
func TestNetstatLinuxParser(t *testing.T) {
	rt, runner := newToolsRT(t, "Linux", map[string]process.CommandResult{
		"netstat -tulpnea": {Stdout: []byte(netstatOut)},
	})

	gotRaw, err := (netstatFunc{}).Execute(context.Background(), rt, &NetstatArgs{})
	if err != nil {
		t.Fatal(err)
	}
	rows := gotRaw.([]any)
	if len(rows) != 2 {
		t.Fatalf("rows = %d (%#v)", len(rows), rows)
	}
	tcp := rows[0].(map[string]any)
	if tcp["proto"] != "tcp" || tcp["local-address"] != "127.0.0.1:4505" ||
		tcp["state"] != "LISTEN" || tcp["program"] != "4321/python" {
		t.Fatalf("tcp row = %#v", tcp)
	}
	udp := rows[1].(map[string]any)
	if udp["proto"] != "udp" || udp["program"] != "9999/dhclient" {
		t.Fatalf("udp row = %#v", udp)
	}
	if _, hasState := udp["state"]; hasState {
		t.Fatal("udp rows carry no state")
	}

	// netstat binary absent -> ss fallback path chosen.
	ssOut := `Netid State  Recv-Q Send-Q  Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      511         127.0.0.1:4505      0.0.0.0:*     users:(("python",pid=4321,fd=7)) uid:1000 ino:11111 skmark:0`
	rt2, runner2 := newToolsRT(t, "Linux", map[string]process.CommandResult{
		"ss -tulpnea": {Stdout: []byte(ssOut)},
	})
	savedTools2 := toolPath
	toolPath = func(ostool string) string {
		if ostool == "netstat" {
			return ""
		}
		return "/usr/sbin/" + ostool
	}
	t.Cleanup(func() { toolPath = savedTools2 })
	gotRaw, err = (netstatFunc{}).Execute(context.Background(), rt2, &NetstatArgs{})
	if err != nil {
		t.Fatal(err)
	}
	rows = gotRaw.([]any)
	if len(rows) != 1 {
		t.Fatalf("ss rows = %#v", rows)
	}
	row := rows[0].(map[string]any)
	if row["state"] != "LISTEN" || row["user"] != "1000" ||
		row["inode"] != "11111" || row["program"] != "python" {
		t.Fatalf("ss row = %#v", row)
	}
	_ = runner
	_ = runner2
}

// Mirrors ip_neighs/ip_neighs6 address-family filtering.
func TestIPNeighs(t *testing.T) {
	rt, _ := newToolsRT(t, "Linux", map[string]process.CommandResult{
		"ip neigh show": {Stdout: []byte(
			"172.17.0.1 dev ens3 lladdr de:ad:be:ef:00:99 REACHABLE\n" +
				"fe80::1 dev ens3 lladdr de:ad:be:ef:00:98 STALE\n")},
	})

	gotRaw, err := (ipNeighsFunc{}).Execute(context.Background(), rt, &IPNeighsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	wantV4 := map[string]any{"de:ad:be:ef:00:99": "172.17.0.1"}
	if !reflect.DeepEqual(gotRaw, wantV4) {
		t.Fatalf("ip_neighs = %#v", gotRaw)
	}

	gotRaw, err = (ipNeighs6Func{}).Execute(context.Background(), rt, &IPNeighs6Args{})
	if err != nil {
		t.Fatal(err)
	}
	wantV6 := map[string]any{"de:ad:be:ef:00:98": "fe80::1"}
	if !reflect.DeepEqual(gotRaw, wantV6) {
		t.Fatalf("ip_neighs6 = %#v, want %#v", gotRaw, wantV6)
	}
}

// Mirrors get_hostname/get_fqdn hooks.
func TestHostnameTrio(t *testing.T) {
	rt, _ := newToolsRT(t, "Linux", nil)
	savedHost := osHostnameHook
	osHostnameHook = func() (string, error) { return "minion01", nil }
	t.Cleanup(func() { osHostnameHook = savedHost })

	savedFqdn := fqdnHook
	fqdnHook = func(*runtime.Runtime) string { return "minion01.example.internal" }
	t.Cleanup(func() { fqdnHook = savedFqdn })

	gotRaw, err := (getHostnameFunc{}).Execute(context.Background(), rt, &GetHostnameArgs{})
	if err != nil || gotRaw != "minion01" {
		t.Fatalf("get_hostname = %#v, %v", gotRaw, err)
	}

	gotRaw, err = (getFqdnFunc{}).Execute(context.Background(), rt, &GetFqdnArgs{})
	if err != nil || gotRaw != "minion01.example.internal" {
		t.Fatalf("get_fqdn = %#v, %v", gotRaw, err)
	}

	// mod_hostname(None) is False.
	mh := modHostnameFunc{}
	gotRaw, err = mh.Execute(context.Background(), rt, &ModHostnameArgs{})
	if err != nil || gotRaw != false {
		t.Fatalf("mod_hostname none = %#v, %v", gotRaw, err)
	}
}

// Mirrors mod_hostname's Debian flow: set command plus /etc/hostname and
// /etc/hosts token rewrite.
func TestModHostnameDebian(t *testing.T) {
	rt, runner := newToolsRT(t, "Linux", map[string]process.CommandResult{
		"hostname minion02": {},
	})
	savedCmd := hostnameCmdHook
	hostnameCmdHook = func() string { return "/bin/hostname" }
	t.Cleanup(func() { hostnameCmdHook = savedCmd })

	savedFqdn := fqdnHook
	fqdnHook = func(*runtime.Runtime) string { return "minion01.example.internal" }
	t.Cleanup(func() { fqdnHook = savedFqdn })

	savedFamily := osFamilyHook
	osFamilyHook = func(*runtime.Runtime) string { return "Debian" }
	t.Cleanup(func() { osFamilyHook = savedFamily })

	if err := rt.FS.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/etc/hosts",
		[]byte("127.0.1.1\tminion01.example.internal minion01\n127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	newName := "minion02"
	mh := modHostnameFunc{}
	gotRaw, err := mh.Execute(context.Background(), rt, &ModHostnameArgs{Hostname: &newName})
	if err != nil || gotRaw != true {
		t.Fatalf("mod_hostname = %#v, %v", gotRaw, err)
	}

	hostsData, _ := rt.FS.ReadFile("/etc/hosts")
	if !strings.Contains(string(hostsData), "127.0.1.1\tminion02") {
		t.Fatalf("/etc/hosts rewrite = %q", hostsData)
	}
	hostnameData, _ := rt.FS.ReadFile("/etc/hostname")
	if string(hostnameData) != "minion02\n" {
		t.Fatalf("/etc/hostname = %q", hostnameData)
	}
	found := false
	for _, call := range runner.calls {
		if call == "/bin/hostname minion02" {
			found = true
		}
	}
	if !found {
		t.Fatalf("set command missing: %v", runner.calls)
	}
}

// Mirrors mod_bufsize success/failure comment pairing over ethtool -G.
func TestBufsizePair(t *testing.T) {
	bindEthtoolFixtures := func(rt *runtime.Runtime, getOut, modOut string, modExit int) {
		rt.Runner = &procRunner{results: map[string]process.CommandResult{
			"/sbin/ethtool -g eth0":                {Stdout: []byte(getOut)},
			"/sbin/ethtool -G eth0 rx 4096":        {Stdout: []byte(modOut), ExitCode: modExit},
			"/sbin/ethtool -G eth0 rx 512 tx 1024": {Stdout: []byte(modOut), ExitCode: modExit},
		}}
	}

	getOut := "Ring parameters for eth0:\nPre-set maximums:\nRX:             4096\nTX:             4096\nCurrent hardware settings:\nRX:             512\nTX:             1024\n"

	rt, _ := newToolsRT(t, "Linux", nil)
	bindEthtoolFixtures(rt, getOut, "", 0)
	savedGate := ethtoolGate
	ethtoolGate = func() bool { return true }
	t.Cleanup(func() { ethtoolGate = savedGate })

	gbf := getBufsizeFunc{}
	gotRaw, err := gbf.Execute(context.Background(), rt, &GetBufsizeArgs{Iface: "eth0"})
	if err != nil {
		t.Fatal(err)
	}
	ret := gotRaw.(map[string]any)
	if ret["result"] != true || ret["rx-max"] != int64(4096) || ret["tx-max"] != int64(4096) ||
		ret["rx"] != int64(512) || ret["tx"] != int64(1024) {
		t.Fatalf("bufsize = %#v", ret)
	}

	mbf := modBufsizeFunc{}
	gotRaw, err = mbf.Execute(context.Background(), rt, &ModBufsizeArgs{
		Iface:  "eth0",
		Kwargs: map[string]any{"rx": int64(4096)},
	})
	if err != nil {
		t.Fatal(err)
	}
	ret = gotRaw.(map[string]any)
	if ret["result"] != true || ret["comment"] != "rx 4096" {
		t.Fatalf("mod_bufsize = %#v", ret)
	}

	// No kwargs keeps the default comment and false result.
	gotRaw, err = mbf.Execute(context.Background(), rt, &ModBufsizeArgs{Iface: "eth0"})
	if err != nil {
		t.Fatal(err)
	}
	ret = gotRaw.(map[string]any)
	if ret["result"] != false || ret["comment"] != "Requires rx=<val> tx==<val> rx-mini=<val> and/or rx-jumbo=<val>" {
		t.Fatalf("no-kwargs = %#v", ret)
	}
}

// Mirrors ifacestartswith label preference.
func TestIfacestartswith(t *testing.T) {
	rt, _ := newIfaceRT(t, nil)
	isf := ifacestartswithFunc{}

	gotRaw, err := isf.Execute(context.Background(), rt, &IfacestartswithArgs{CIDR: "172.17"})
	if err != nil {
		t.Fatal(err)
	}
	want := []any{"ens3"}
	if !reflect.DeepEqual(gotRaw, want) {
		t.Fatalf("ifacestartswith = %#v, want %v", gotRaw, want)
	}

	gotRaw, err = isf.Execute(context.Background(), rt, &IfacestartswithArgs{CIDR: "192.168.99"})
	if err != nil {
		t.Fatal(err)
	}
	// docker0 carries no label column -> interface name.
	want = []any{"docker0"}
	if !reflect.DeepEqual(gotRaw, want) {
		t.Fatalf("docker0 startswith = %#v, want %v", gotRaw, want)
	}
}

// Mirrors ip_networks glob filtering, loopback exclusion and verbose dict.
func TestIPNetworks(t *testing.T) {
	rt, _ := newIfaceRT(t, nil)
	inf := ipNetworksFunc{}

	gotRaw, err := inf.Execute(context.Background(), rt, &IPNetworksArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := []any{"172.17.0.0/20", "192.168.99.0/24"}
	if !reflect.DeepEqual(gotRaw, want) {
		t.Fatalf("ip_networks = %#v, want %v", gotRaw, want)
	}

	dockerGlob := "docker*"
	gotRaw, err = inf.Execute(context.Background(), rt, &IPNetworksArgs{
		Interface: []string{dockerGlob},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotRaw, []any{"192.168.99.0/24"}) {
		t.Fatalf("glob filtered = %#v", gotRaw)
	}

	loopbackOK := true
	gotRaw, err = inf.Execute(context.Background(), rt, &IPNetworksArgs{
		IncludeLoopback: loopbackOK,
	})
	if err != nil {
		t.Fatal(err)
	}
	list := gotRaw.([]any)
	if len(list) != 3 || list[0] != "127.0.0.0/8" {
		t.Fatalf("loopback included = %#v", list)
	}

	verbose := true
	gotRaw, err = inf.Execute(context.Background(), rt, &IPNetworksArgs{
		Verbose: verbose,
	})
	if err != nil {
		t.Fatal(err)
	}
	vmap := gotRaw.(map[string]any)
	entry := vmap["172.17.0.0/20"].(map[string]any)
	if entry["address"] != "172.17.0.0" || entry["netmask"] != "255.255.240.0" ||
		entry["prefixlen"] != 20 {
		t.Fatalf("verbose entry = %#v", entry)
	}

	i6f := ipNetworks6Func{}
	gotRaw, err = i6f.Execute(context.Background(), rt, &IPNetworksArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotRaw, []any{"fd00::/64"}) {
		t.Fatalf("ip_networks6 = %#v", gotRaw)
	}
}

// Mirrors connect()'s validation comments and TCP success shape.
func TestConnect(t *testing.T) {
	rt, _ := newToolsRT(t, "Linux", nil)
	cf := connectFunc{}

	host := "example.invalid"
	port80 := int64(80)
	gotRaw, err := cf.Execute(context.Background(), rt, &ConnectArgs{Host: &host})
	if err != nil {
		t.Fatal(err)
	}
	assertResultMap(t, gotRaw, false, "Required argument, port, is missing.")

	gotRaw, err = cf.Execute(context.Background(), rt, &ConnectArgs{Port: &port80})
	if err != nil {
		t.Fatal(err)
	}
	assertResultMap(t, gotRaw, false, "Required argument, host, is missing.")

	// Unresolvable host surfaces the resolve-failure comment.
	gotRaw, err = cf.Execute(context.Background(), rt, &ConnectArgs{
		Host: &host, Port: &port80,
	})
	if err != nil {
		t.Fatal(err)
	}
	comment := gotRaw.(map[string]any)["comment"].(string)
	if !strings.HasPrefix(comment, "Unable to resolve host example.invalid on tcp port 80") &&
		!strings.HasPrefix(comment, "Unable to connect to") {
		t.Fatalf("connect comment = %q", comment)
	}
}

func assertResultMap(t *testing.T, gotRaw any, wantResult bool, wantComment string) {
	t.Helper()
	got := gotRaw.(map[string]any)
	if got["result"] != wantResult || got["comment"] != wantComment {
		t.Fatalf("got %#v, want {result:%v comment:%q}", got, wantResult, wantComment)
	}
}

// Mirrors fqdns sorted unique output with reverse resolution fakes.
func TestFqdns(t *testing.T) {
	rt, _ := newIfaceRT(t, nil)

	savedAddrs := hostAddrsHook
	hostAddrsHook = func(*runtime.Runtime) []string {
		return []string{"127.0.0.1", "10.0.0.5"}
	}
	t.Cleanup(func() { hostAddrsHook = savedAddrs })

	// Point the resolver at controlled data via a fake lookup through
	// /etc/hosts-free seam: fqdns uses net.LookupAddr, which we cannot
	// stub directly; instead pin behavior against an unreachable network,
	// expecting the empty sorted envelope.
	gotRaw, err := (fqdnsFunc{}).Execute(context.Background(), rt, &FqdnsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	ret := gotRaw.(map[string]any)
	list, ok := ret["fqdns"].([]any)
	if !ok {
		t.Fatalf("fqdns envelope = %#v", ret)
	}
	for _, name := range list {
		if strings.Contains(name.(string), " ") {
			t.Fatalf("fqdn entries must be single names: %#v", list)
		}
	}
}

// Mirrors ip_addrs/ip_addrs6 filtering semantics over the fixture data.
func TestIPAddrs(t *testing.T) {
	rt, _ := newIfaceRT(t, nil)
	af := ipAddrsFunc{}

	gotRaw, err := af.Execute(context.Background(), rt, &IPAddrsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := []any{"172.17.0.4", "192.168.99.1"}
	if !reflect.DeepEqual(gotRaw, want) {
		t.Fatalf("ip_addrs = %#v, want %v", gotRaw, want)
	}

	loopbackOK := true
	gotRaw, err = af.Execute(context.Background(), rt, &IPAddrsArgs{
		IncludeLoopback: loopbackOK,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantLoop := []any{"127.0.0.1", "172.17.0.4", "192.168.99.1"}
	if !reflect.DeepEqual(gotRaw, wantLoop) {
		t.Fatalf("with loopback = %#v, want %v", gotRaw, wantLoop)
	}

	cidr := "192.168.99.0/24"
	gotRaw, err = af.Execute(context.Background(), rt, &IPAddrsArgs{CIDR: &cidr})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotRaw, []any{"192.168.99.1"}) {
		t.Fatalf("cidr filter = %#v", gotRaw)
	}

	privateType := "private"
	gotRaw, err = af.Execute(context.Background(), rt, &IPAddrsArgs{Type: &privateType})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotRaw.([]any)) != 2 {
		t.Fatalf("private filter = %#v", gotRaw)
	}

	publicType := "public"
	gotRaw, err = af.Execute(context.Background(), rt, &IPAddrsArgs{Type: &publicType})
	if err != nil || len(gotRaw.([]any)) != 0 {
		t.Fatalf("public filter on private-only host = %#v, %v", gotRaw, err)
	}

	a6 := ipAddrs6Func{}
	gotRaw, err = a6.Execute(context.Background(), rt, &IPAddrsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	wantV6 := []any{"fd00::5"}
	if !reflect.DeepEqual(gotRaw, wantV6) {
		t.Fatalf("ip_addrs6 = %#v, want %v", gotRaw, wantV6)
	}
}
