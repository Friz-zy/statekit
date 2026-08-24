package network

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// procRunner keys canned results by the joined argv.
type procRunner struct {
	results map[string]process.CommandResult
	calls   []string
}

func (f *procRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	joined := cmd.Name + " " + strings.Join(cmd.Args, " ")
	f.calls = append(f.calls, joined)
	if res, ok := f.results[joined]; ok {
		return res
	}
	return process.CommandResult{}
}

const ipLinkOut = `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether de:ad:be:ef:00:01 brd ff:ff:ff:ff:ff:ff
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default
    link/ether 02:42:b7:aa:bb:cc brd ff:ff:ff:ff:ff:ff`

const ipAddrOut = `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet 172.17.0.4/20 brd 172.17.15.255 scope global dynamic ens3
       valid_lft 86399sec preferred_lft 86399sec
    inet6 fd00::5/64 scope global
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    inet 192.168.99.1/24 brd 192.168.99.255 scope global docker0
       valid_lft forever preferred_lft forever`

// newIfaceRT builds the interface fixtures plus optional runner results.
func newIfaceRT(t *testing.T, results map[string]process.CommandResult) (*runtime.Runtime, *procRunner) {
	t.Helper()
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

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestInterfaces(t *testing.T) {
	rt, _ := newIfaceRT(t, nil)
	gotRaw, err := interfacesFunc{}.Execute(context.Background(), rt, &InterfacesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	ifaces := gotRaw.(map[string]any)
	for _, name := range []string{"lo", "ens3", "docker0"} {
		if _, has := ifaces[name]; !has {
			t.Fatalf("missing %s in %v", name, sortedKeys(ifaces))
		}
	}
	ens3 := ifaces["ens3"].(map[string]any)
	if ens3["up"] != true || ens3["hwaddr"] != "de:ad:be:ef:00:01" {
		t.Fatalf("ens3 = %#v", ens3)
	}
	inetList := ens3["inet"].([]any)
	first := inetList[0].(map[string]any)
	if first["address"] != "172.17.0.4" || first["netmask"] != "255.255.240.0" ||
		first["broadcast"] != "172.17.15.255" {
		t.Fatalf("ens3 inet[0] = %#v", first)
	}
	v6first := ens3["inet6"].([]any)[0].(map[string]any)
	if v6first["prefixlen"] != "64" || v6first["scope"] != "global" {
		t.Fatalf("ens3 inet6[0] = %#v", v6first)
	}
}

// Mirrors hw_addr/interface/interface_ip error strings for unknown ifaces.
func TestIfaceAccessors(t *testing.T) {
	rt, _ := newIfaceRT(t, nil)

	hf := hwAddrFunc{}
	gotRaw, err := hf.Execute(context.Background(), rt, &HwAddrArgs{Iface: "ens3"})
	dbg, _ := interfacesFunc{}.Execute(context.Background(), rt, &InterfacesArgs{})
	t.Logf("DBG ifaces=%#v", dbg)
	if err != nil || gotRaw != "de:ad:be:ef:00:01" {
		t.Fatalf("hw_addr = %#v, %v", gotRaw, err)
	}
	gotRaw, err = hf.Execute(context.Background(), rt, &HwAddrArgs{Iface: "missing"})
	if err != nil || !strings.HasPrefix(gotRaw.(string), `Interface "missing" not in available interfaces:`) {
		t.Fatalf("hw_addr missing = %#v, %v", gotRaw, err)
	}

	itf := interfaceFunc{}
	gotRaw, err = itf.Execute(context.Background(), rt, &InterfaceArgs{Iface: "ens3"})
	if err != nil {
		t.Fatal(err)
	}
	inetList := gotRaw.([]any)
	if len(inetList) != 1 {
		t.Fatalf("interface list = %#v", inetList)
	}

	iip := interfaceIPFunc{}
	gotRaw, err = iip.Execute(context.Background(), rt, &InterfaceIPArgs{Iface: "ens3"})
	if err != nil || gotRaw != "172.17.0.4" {
		t.Fatalf("interface_ip = %#v, %v", gotRaw, err)
	}
	gotRaw, err = iip.Execute(context.Background(), rt, &InterfaceIPArgs{Iface: "lo"})
	if err != nil || gotRaw != "127.0.0.1" {
		t.Fatalf("lo ip = %#v, %v", gotRaw, err)
	}
	gotRaw, err = iip.Execute(context.Background(), rt, &InterfaceIPArgs{Iface: "missing"})
	if err != nil || !strings.HasPrefix(gotRaw.(string), `Interface "missing"`) {
		t.Fatalf("interface_ip missing = %#v, %v", gotRaw, err)
	}
}

func TestSubnets(t *testing.T) {
	rt, _ := newIfaceRT(t, nil)

	sf := subnetsFunc{}
	gotRaw, err := sf.Execute(context.Background(), rt, &SubnetsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := []any{"172.17.0.0/20", "192.168.99.0/24"}
	if !reflect.DeepEqual(gotRaw, want) {
		t.Fatalf("subnets = %#v, want %v", gotRaw, want)
	}

	docker0 := "docker0"
	gotRaw, err = sf.Execute(context.Background(), rt, &SubnetsArgs{
		Interfaces: []string{docker0},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotRaw, []any{"192.168.99.0/24"}) {
		t.Fatalf("filtered subnets = %#v", gotRaw)
	}

	s6f := subnets6Func{}
	gotRaw, err = s6f.Execute(context.Background(), rt, &Subnets6Args{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotRaw, []any{"fd00::/64"}) {
		t.Fatalf("subnets6 = %#v", gotRaw)
	}
}

func TestRoutesAndDefaults(t *testing.T) {
	ipRouteV4 := "default via 172.17.0.1 dev ens3\n" +
		"172.17.0.0/20 dev ens3 proto kernel scope link src 172.17.0.4\n" +
		"unreachable 169.254.0.0/16 dev ens3 metric 1000\n"
	ipRouteV6 := "::1 dev lo proto kernel metric 256\n" +
		"default via fd00::1 dev ens3 metric 1024\n"
	rt, _ := newIfaceRT(t, map[string]process.CommandResult{
		"ip -4 route show table main": {Stdout: []byte(ipRouteV4)},
		"ip -6 route show table all":  {Stdout: []byte(ipRouteV6)},
	})

	rf := routesFunc{}
	gotRaw, err := rf.Execute(context.Background(), rt, &RoutesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	routes := gotRaw.([]any)
	if len(routes) != 4 {
		t.Fatalf("routes = %#v", routes)
	}
	def := routes[0].(map[string]any)
	if def["destination"] != "0.0.0.0" || def["gateway"] != "172.17.0.1" ||
		def["flags"] != "UG" || def["interface"] != "ens3" {
		t.Fatalf("default route entry = %#v", def)
	}
	netEntry := routes[1].(map[string]any)
	if netEntry["destination"] != "172.17.0.0" || netEntry["netmask"] != "255.255.240.0" ||
		netEntry["flags"] != "U" {
		t.Fatalf("network route = %#v", netEntry)
	}

	inet6 := "inet6"
	gotRaw, err = rf.Execute(context.Background(), rt, &RoutesArgs{Family: &inet6})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotRaw.([]any)) != 2 {
		t.Fatalf("inet6 routes = %#v", gotRaw)
	}

	bogusFamily := "ipx"
	if _, err = rf.Execute(context.Background(), rt, &RoutesArgs{Family: &bogusFamily}); err == nil ||
		err.Error() != "Invalid address family ipx" {
		t.Fatalf("invalid family err = %v", err)
	}

	drf := defaultRouteFunc{}
	gotRaw, err = drf.Execute(context.Background(), rt, &DefaultRouteArgs{})
	if err != nil {
		t.Fatal(err)
	}
	defaults := gotRaw.([]any)
	if len(defaults) != 2 {
		t.Fatalf("default routes = %#v", defaults)
	}
	first := defaults[0].(map[string]any)
	if first["gateway"] != "172.17.0.1" {
		t.Fatalf("default inet = %#v", first)
	}
	second := defaults[1].(map[string]any)
	if second["destination"] != "::/0" || second["gateway"] != "fd00::1" {
		t.Fatalf("default inet6 = %#v", second)
	}

	grf := getRouteFunc{}
	rtGet, _ := newIfaceRT(t, map[string]process.CommandResult{
		"ip route get 8.8.8.8": {Stdout: []byte(
			"8.8.8.8 via 172.17.0.1 dev ens3 src 172.17.0.4 uid 1000\n")},
	})
	dest := "8.8.8.8"
	gotRaw, err = grf.Execute(context.Background(), rtGet, &GetRouteArgs{IP: dest})
	if err != nil {
		t.Fatal(err)
	}
	ret := gotRaw.(map[string]any)
	if ret["gateway"] != "172.17.0.1" || ret["interface"] != "ens3" ||
		ret["source"] != "172.17.0.4" || ret["destination"] != "8.8.8.8" {
		t.Fatalf("get_route = %#v", ret)
	}
}

func TestActiveTCP(t *testing.T) {
	rt, _ := newIfaceRT(t, nil)
	if err := rt.FS.MkdirAll("/proc/net", 0o755); err != nil {
		t.Fatal(err)
	}
	tcpData := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt\n" +
		"   0: 0100007F:DEEE 0100007F:1199 01 00000000:00000000 00:00000000 00000000     0        0\n" +
		"   1: 65000FAC:0016 8C35A8C0:C350 06 00000000:00000000 00:00000000 00000000     0        0\n"
	if err := rt.FS.WriteFile("/proc/net/tcp", []byte(tcpData), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/proc/net/tcp6", []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	gotRaw, err := activeTCPFunc{}.Execute(context.Background(), rt, &ActiveTCPArgs{})
	if err != nil {
		t.Fatal(err)
	}
	ret := gotRaw.(map[string]any)
	if len(ret) != 1 {
		t.Fatalf("active_tcp = %#v", ret)
	}
	conn := ret["0"].(map[string]any)
	if conn["local_addr"] != "127.0.0.1" || conn["local_port"] != int64(57070) ||
		conn["remote_port"] != int64(4505) {
		t.Fatalf("connection = %#v", conn)
	}
	if _, hasState := conn["state"]; hasState {
		t.Fatal("state must be stripped for established entries")
	}
}

// Mirrors ping's argv shapes and boolean return.
func TestPing(t *testing.T) {
	okRunner := func(exitCode int) *procRunner {
		return &procRunner{results: map[string]process.CommandResult{
			"ping -c 4 example.com":      {ExitCode: exitCode, Stdout: []byte("ping output")},
			"ping -W 3 -c 4 example.com": {ExitCode: exitCode, Stdout: []byte("timed output")},
		}}
	}

	pf := pingFunc{}

	rt, _ := newIfaceRT(t, nil)
	rt.Runner = okRunner(0)
	gotRaw, err := pf.Execute(context.Background(), rt, &PingArgs{Host: "example.com"})
	if err != nil || gotRaw != "ping output" {
		t.Fatalf("ping text = %#v, %v", gotRaw, err)
	}

	timeout := int64(3)
	rt.Runner = okRunner(0)
	gotRaw, err = pf.Execute(context.Background(), rt, &PingArgs{
		Host: "example.com", Timeout: &timeout,
	})
	if err != nil || gotRaw != "timed output" {
		t.Fatalf("ping timeout text = %#v, %v", gotRaw, err)
	}

	boolean := true
	rt.Runner = okRunner(0)
	gotRaw, err = pf.Execute(context.Background(), rt, &PingArgs{
		Host: "example.com", ReturnBoolean: &boolean,
	})
	if err != nil || gotRaw != true {
		t.Fatalf("ping bool up = %#v, %v", gotRaw, err)
	}

	rt.Runner = okRunner(1)
	gotRaw, err = pf.Execute(context.Background(), rt, &PingArgs{
		Host: "example.com", ReturnBoolean: &boolean,
	})
	if err != nil || gotRaw != false {
		t.Fatalf("ping bool down = %#v, %v", gotRaw, err)
	}
}

// Mirrors arp()'s Linux column mapping.
func TestArp(t *testing.T) {
	rt, _ := newIfaceRT(t, map[string]process.CommandResult{
		"arp -an": {Stdout: []byte(
			"? (172.17.0.1) at de:ad:be:ef:00:99 [ether] on ens3\n? (10.0.0.1) at <incomplete> on eth0\n")},
	})
	gotRaw, err := arpFunc{}.Execute(context.Background(), rt, &ArpArgs{})
	if err != nil {
		t.Fatal(err)
	}
	// Upstream keys by comps[3] (the MAC column): mac -> ip.
	want := map[string]any{
		"de:ad:be:ef:00:99": "172.17.0.1",
		"<incomplete>":      "10.0.0.1",
	}
	if !reflect.DeepEqual(gotRaw, want) {
		t.Fatalf("arp = %#v, want %#v", gotRaw, want)
	}
}

// Mirrors traceroute/dig wrappers with sanitization.
func TestTracerouteAndDig(t *testing.T) {
	savedTools := toolPath
	toolPath = func(exe string) string { return "/usr/bin/" + exe }
	t.Cleanup(func() { toolPath = savedTools })

	rt, runner := newIfaceRT(t, map[string]process.CommandResult{
		"dig example.com": {},
	})

	trf := tracerouteFunc{}
	gotRaw, err := trf.Execute(context.Background(), rt, &TracerouteArgs{Host: "example.com"})
	if err != nil || gotRaw != "" {
		t.Fatalf("traceroute = %#v, %v", gotRaw, err)
	}

	df := digFunc{}
	gotRaw, err = df.Execute(context.Background(), rt, &DigArgs{Host: "example.com"})
	if err != nil || gotRaw != "" {
		t.Fatalf("dig = %#v, %v", gotRaw, err)
	}
	found := false
	for _, call := range runner.calls {
		if call == "dig example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("dig argv missing: %v", runner.calls)
	}
}
