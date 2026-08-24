package network

import (
	"context"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
)

func newRT(t *testing.T, addrs []string) *runtime.Runtime {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
	}
	savedAddrs := hostAddrsHook
	hostAddrsHook = func(*runtime.Runtime) []string { return addrs }
	t.Cleanup(func() { hostAddrsHook = savedAddrs })
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return rt
}

func strPtr(s string) *string { return &s }

// Mirrors the in_subnet/ip_in_subnet compute semantics from
// salt.utils.network.in_subnet.
func TestSubnetChecks(t *testing.T) {
	rt := newRT(t, nil)
	isf := inSubnetFunc{}
	iisf := ipInSubnetFunc{}

	gotRaw, err := isf.Execute(context.Background(), rt, &InSubnetArgs{CIDR: "10.0.0.0/16"})
	if err != nil || gotRaw != false {
		t.Fatalf("no host addrs = %#v, %v", gotRaw, err)
	}

	rtHosts := newRT(t, []string{"172.17.0.4", "10.1.2.3"})
	gotRaw, err = isf.Execute(context.Background(), rtHosts, &InSubnetArgs{CIDR: "10.0.0.0/8"})
	if err != nil || gotRaw != true {
		t.Fatalf("host addr inside = %#v, %v", gotRaw, err)
	}

	gotRaw, err = isf.Execute(context.Background(), rtHosts, &InSubnetArgs{CIDR: "192.168.0.0/16"})
	if err != nil || gotRaw != false {
		t.Fatalf("host addr outside = %#v, %v", gotRaw, err)
	}

	// Invalid CIDR logs and returns False.
	gotRaw, err = isf.Execute(context.Background(), rtHosts, &InSubnetArgs{CIDR: "not-a-cidr"})
	if err != nil || gotRaw != false {
		t.Fatalf("invalid cidr = %#v, %v", gotRaw, err)
	}

	cases := []struct {
		ip   string
		cidr string
		want bool
	}{
		{"172.17.0.4", "172.16.0.0/12", true},
		{"10.0.0.1", "10.0.0.0/8", true},
		{"192.168.1.1", "10.0.0.0/8", false},
		{"fd00::1", "fc00::/7", true},
		{"2001:db8::1", "2001:db8::/32", true},
		{"2001:db8::1", "fe80::/10", false},
	}
	for _, c := range cases {
		gotRaw, err := iisf.Execute(context.Background(), rt, &IPInSubnetArgs{
			IPAddr: c.ip, CIDR: c.cidr,
		})
		if err != nil || gotRaw != c.want {
			t.Fatalf("ip_in_subnet(%q,%q) = %#v, %v; want %v", c.ip, c.cidr, gotRaw, err, c.want)
		}
	}

	// Family mismatch never contains.
	gotRaw, err = iisf.Execute(context.Background(), rt, &IPInSubnetArgs{
		IPAddr: "10.0.0.1", CIDR: "fc00::/7",
	})
	if err != nil || gotRaw != false {
		t.Fatalf("family mismatch = %#v, %v", gotRaw, err)
	}
}

// Mirrors convert_cidr/calc_net semantics including IPv6 and netmask args.
func TestConvertCIDRAndCalcNet(t *testing.T) {
	rt := newRT(t, nil)
	ccf := convertCIDRFunc{}
	cnf := calcNetFunc{}

	gotRaw, err := ccf.Execute(context.Background(), rt, &ConvertCIDRArgs{CIDR: "172.31.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"network":   "172.31.0.0",
		"netmask":   "255.255.0.0",
		"broadcast": "172.31.255.255",
	}
	if !reflect.DeepEqual(gotRaw, want) {
		t.Fatalf("convert_cidr = %#v, want %#v", gotRaw, want)
	}

	// Host bits get masked away like ip_network(strict=False).
	gotRaw, err = cnf.Execute(context.Background(), rt, &CalcNetArgs{IPAddr: "172.17.0.5 255.255.255.240"})
	if err == nil {
		t.Fatal("space-separated input must fail typed decoding")
	}
	_ = gotRaw

	gotRaw, err = cnf.Execute(context.Background(), rt, &CalcNetArgs{IPAddr: "172.17.0.5/28"})
	if err != nil || gotRaw != "172.17.0.0/28" {
		t.Fatalf("calc_net cidr = %#v, %v", gotRaw, err)
	}

	netmask := "255.255.255.240"
	gotRaw, err = cnf.Execute(context.Background(), rt, &CalcNetArgs{
		IPAddr: "172.17.0.5", Netmask: &netmask,
	})
	if err != nil || gotRaw != "172.17.0.0/28" {
		t.Fatalf("calc_net dotted mask = %#v, %v", gotRaw, err)
	}

	v6 := "2a02:f6e:a000:80:84d8:8332:7866:4e07/64"
	gotRaw, err = cnf.Execute(context.Background(), rt, &CalcNetArgs{IPAddr: v6})
	if err != nil || gotRaw != "2a02:f6e:a000:80::/64" {
		t.Fatalf("calc_net v6 = %#v, %v", gotRaw, err)
	}

	prefixLen := "24"
	gotRaw, err = cnf.Execute(context.Background(), rt, &CalcNetArgs{
		IPAddr: "192.168.1.5", Netmask: &prefixLen,
	})
	if err != nil || gotRaw != "192.168.1.0/24" {
		t.Fatalf("calc_net prefix mask = %#v, %v", gotRaw, err)
	}

	// Non-contiguous masks are invalid under ipaddress semantics.
	bad := "255.0.255.0"
	if _, err = cnf.Execute(context.Background(), rt, &CalcNetArgs{
		IPAddr: "192.168.1.5", Netmask: &bad,
	}); err == nil {
		t.Fatal("non-contiguous mask must raise")
	}
}

// Mirrors test_is_private / test_is_loopback with real classifications.
func TestPrivateAndLoopback(t *testing.T) {
	rt := newRT(t, nil)
	pf := isPrivateFunc{}
	lf := isLoopbackFunc{}

	privates := []string{"10.0.0.3", "192.168.1.1", "172.31.255.255", "100.64.0.1", "fd00::1", "::1"}
	for _, ip := range privates {
		gotRaw, err := pf.Execute(context.Background(), rt, &IsPrivateArgs{IPAddr: ip})
		if err != nil || gotRaw != true {
			t.Fatalf("is_private(%q) = %#v, %v", ip, gotRaw, err)
		}
	}

	publics := []string{"8.8.8.8", "1.2.3.4", "2606:4700::1111"}
	for _, ip := range publics {
		gotRaw, err := pf.Execute(context.Background(), rt, &IsPrivateArgs{IPAddr: ip})
		if err != nil || gotRaw != false {
			t.Fatalf("is_private(%q) = %#v, %v", ip, gotRaw, err)
		}
	}

	loopbacks := []string{"127.0.0.1", "::1"}
	for _, ip := range loopbacks {
		gotRaw, err := lf.Execute(context.Background(), rt, &IsLoopbackArgs{IPAddr: ip})
		if err != nil || gotRaw != true {
			t.Fatalf("is_loopback(%q) = %#v, %v", ip, gotRaw, err)
		}
	}

	gotRaw, err := lf.Execute(context.Background(), rt, &IsLoopbackArgs{IPAddr: "8.8.8.8"})
	if err != nil || gotRaw != false {
		t.Fatalf("is_loopback public = %#v, %v", gotRaw, err)
	}
}

// Mirrors reverse_pointer semantics for v4 and v6.
func TestReverseIP(t *testing.T) {
	rt := newRT(t, nil)
	rf := reverseIPFunc{}

	cases := []struct{ in, want string }{
		{"172.17.0.4", "4.0.17.172.in-addr.arpa"},
		{"8.8.8.8", "8.8.8.8.in-addr.arpa"},
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"},
	}
	for _, c := range cases {
		gotRaw, err := rf.Execute(context.Background(), rt, &ReverseIPArgs{IPAddr: c.in})
		if err != nil || gotRaw != c.want {
			t.Fatalf("reverse_ip(%q) = %#v, %v; want %q", c.in, gotRaw, err, c.want)
		}
	}

	if _, err := rf.Execute(context.Background(), rt, &ReverseIPArgs{IPAddr: "bogus"}); err == nil {
		t.Fatal("invalid ip must raise")
	}
}

// Mirrors iphexval's uppercase octet concatenation.
func TestIphexval(t *testing.T) {
	rt := newRT(t, nil)
	hf := iphexvalFunc{}

	gotRaw, err := hf.Execute(context.Background(), rt, &IphexvalArgs{IP: "10.0.0.1"})
	if err != nil || gotRaw != "0A000001" {
		t.Fatalf("iphexval = %#v, %v", gotRaw, err)
	}

	if _, err = hf.Execute(context.Background(), rt, &IphexvalArgs{IP: "999.0.0.1"}); err == nil {
		t.Fatal("invalid octet must raise")
	}
}

// Mirrors test_wol_bad_mac / test_wol_success with a capturing socket hook.
func TestWol(t *testing.T) {
	rt := newRT(t, nil)
	wf := wolFunc{}

	if _, err := wf.Execute(context.Background(), rt, &WolArgs{Mac: strPtr("31337")}); err == nil ||
		err.Error() != "Invalid MAC address" {
		t.Fatalf("bad mac err = %v", err)
	}

	var payload []byte
	var target string
	savedSend := udpSendHook
	udpSendHook = func(p []byte, bcast string, port int) error {
		payload = p
		target = bcast + ":" + itoa(port)
		return nil
	}
	t.Cleanup(func() { udpSendHook = savedSend })

	mac := "080027136977"
	port := int64(7)
	gotRaw, err := wf.Execute(context.Background(), rt, &WolArgs{Mac: &mac, DestPort: &port})
	if err != nil || gotRaw != true {
		t.Fatalf("wol success = %#v, %v", gotRaw, err)
	}
	if len(payload) != 102 {
		t.Fatalf("payload length = %d", len(payload))
	}
	for i := 0; i < 6; i++ {
		if payload[i] != 0xff {
			t.Fatalf("magic prefix broken at %d", i)
		}
	}
	for i := 0; i < 16; i++ {
		chunk := payload[6+i*6 : 12+i*6]
		if !reflect.DeepEqual(chunk, []byte{0x08, 0x00, 0x27, 0x13, 0x69, 0x77}) {
			t.Fatalf("mac chunk %d = %v", i, chunk)
		}
	}
	if target != "255.255.255.255:9" && target != "255.255.255.255:7" {
		t.Fatalf("target = %q", target)
	}

	// Separator form parses identically.
	colon := "08:00:27:13:69:77"
	gotRaw, err = wf.Execute(context.Background(), rt, &WolArgs{Mac: &colon})
	if err != nil || gotRaw != true {
		t.Fatalf("wol colon mac = %#v, %v", gotRaw, err)
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	digits := ""
	for v > 0 {
		digits = string(rune('0'+v%10)) + digits
		v /= 10
	}
	return digits
}

func TestRegisterNames(t *testing.T) {
	rt := newRT(t, nil)
	names := map[string]bool{}
	for _, name := range rt.Exec.Names() {
		names[name] = true
	}
	for _, want := range []string{
		"network.wol", "network.in_subnet", "network.ip_in_subnet",
		"network.convert_cidr", "network.calc_net", "network.is_private",
		"network.is_loopback", "network.reverse_ip", "network.iphexval",
	} {
		if !names[want] {
			t.Errorf("missing registration %s", want)
		}
	}
	// The remaining pending functions (ip_addrs trio, hostname-adjacent
	// connect leftovers, ip_neighs aliases) are tracked in the handoff.
	for _, registered := range []string{"network.netstat", "network.get_bufsize", "network.fqdns"} {
		if !names[registered] {
			t.Errorf("missing registration %s", registered)
		}
	}
}
