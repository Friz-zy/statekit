// Package network implements Salt-compatible networking functions.
//
// Reference: saltstack/salt/modules/network.py @ pinned revision.
//
// Phase note (plans/porting.md section 6): this round ships the
// pure-compute surface first (subnet/CIDR math, private/loopback
// classification, reverse pointers, hex encoding, Wake-On-Lan); the
// tool-backed functions (ping/netstat/routes/interfaces/fqdns and the
// per-platform parsers) land in their own round off the same package.
package network

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxLike carries the platform constraints shared by the family.
type linuxLike struct{}

func (linuxLike) Platforms() []string { return []string{"linux"} }

// hostAddrsHook backs in_subnet's no-argument form, which scans the
// minion's own addresses (Salt reads its ip_addrs grains).
var hostAddrsHook = func(rt *runtime.Runtime) []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := addr.String()
			if idx := strings.IndexByte(ip, '/'); idx >= 0 {
				ip = ip[:idx]
			}
			out = append(out, ip)
		}
	}
	return out
}

// --- subnet math ------------------------------------------------------------

// parseNetwork mirrors ipaddress.ip_network(text, strict=False): host bits
// are masked away; invalid input reports failure so callers can mirror the
// ValueError paths.
func parseNetwork(text string) (netip.Prefix, bool) {
	text = strings.TrimSpace(text)
	if strings.Contains(text, "/") {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return netip.Prefix{}, false
		}
		return prefix.Masked(), true
	}
	addr, err := netip.ParseAddr(text)
	if err != nil || !addr.IsValid() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

func parseAddr(text string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil || !addr.IsValid() {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

type InSubnetArgs struct {
	CIDR string `statekit:"required,name=cidr"`
}

type inSubnetFunc struct{ linuxLike }

func (inSubnetFunc) Name() string { return "network.in_subnet" }
func (inSubnetFunc) Args() any    { return InSubnetArgs{} }

// Execute returns True when any of the host's addresses falls inside the
// given subnet (Salt's no-addr form).
func (inSubnetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InSubnetArgs)
	network, ok := parseNetwork(a.CIDR)
	if !ok {
		// Upstream logs 'Invalid CIDR' and returns False.
		return false, nil
	}
	for _, candidate := range hostAddrsHook(rt) {
		addr, ok := parseAddr(candidate)
		if !ok {
			continue
		}
		if networkContains(network, addr) {
			return true, nil
		}
	}
	return false, nil
}

type IPInSubnetArgs struct {
	IPAddr string `statekit:"required,name=ip_addr"`
	CIDR   string `statekit:"required,name=cidr"`
}

type ipInSubnetFunc struct{ linuxLike }

func (ipInSubnetFunc) Name() string { return "network.ip_in_subnet" }
func (ipInSubnetFunc) Args() any    { return IPInSubnetArgs{} }

// Execute mirrors utils.network.in_subnet(cidr, ip_addr).
func (ipInSubnetFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*IPInSubnetArgs)
	network, ok := parseNetwork(a.CIDR)
	if !ok {
		return false, nil
	}
	addr, ok := parseAddr(a.IPAddr)
	if !ok {
		return nil, fmt.Errorf("Invalid IP address %q", a.IPAddr)
	}
	return networkContains(network, addr), nil
}

// networkContains compares within the same address family only, like
// Python's `ip_address(item) in cidr`.
func networkContains(network netip.Prefix, addr netip.Addr) bool {
	if network.Addr().Is4() != addr.Is4() {
		return false
	}
	return network.Contains(addr)
}

type ConvertCIDRArgs struct {
	CIDR string `statekit:"required,name=cidr"`
}

type convertCIDRFunc struct{ linuxLike }

func (convertCIDRFunc) Name() string { return "network.convert_cidr" }
func (convertCIDRFunc) Args() any    { return ConvertCIDRArgs{} }

// Execute returns the network address, subnet mask and broadcast address
// of a CIDR address.
func (convertCIDRFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ConvertCIDRArgs)
	ret := map[string]any{"network": nil, "netmask": nil, "broadcast": nil}

	calcRaw, err := calcNetFunc{}.Execute(ctx, rt, &CalcNetArgs{IPAddr: a.CIDR})
	if err != nil {
		return ret, nil
	}
	calcText, _ := calcRaw.(string)
	network, ok := parseNetwork(calcText)
	if !ok {
		return ret, nil
	}
	ret["network"] = network.Addr().String()
	if network.Addr().Is4() {
		ret["netmask"] = v4MaskString(network.Bits())
		broadcast := broadcastAddr(network)
		ret["broadcast"] = broadcast.String()
	} else {
		ret["netmask"] = fmt.Sprintf("%d", network.Bits())
		// IPv6 networks carry no broadcast under ipaddress semantics.
	}
	return ret, nil
}

// v4MaskString renders a prefix length as a dotted-quad mask.
func v4MaskString(bits int) string {
	mask := net.CIDRMask(bits, 32)
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

func broadcastAddr(network netip.Prefix) netip.Addr {
	raw := network.Addr().As4()
	hostBits := 32 - network.Bits()
	var hostMask uint32
	if hostBits < 32 {
		hostMask = (uint32(1) << hostBits) - 1
	} else {
		hostMask = ^uint32(0)
	}
	base := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
	bcast := base | hostMask
	out, _ := netip.AddrFromSlice([]byte{
		byte(bcast >> 24), byte(bcast >> 16), byte(bcast >> 8), byte(bcast),
	})
	return out
}

type CalcNetArgs struct {
	IPAddr  string  `statekit:"required,name=ip_addr"`
	Netmask *string `statekit:"name=netmask"`
}

type calcNetFunc struct{ linuxLike }

func (calcNetFunc) Name() string { return "network.calc_net" }
func (calcNetFunc) Args() any    { return CalcNetArgs{} }

// Execute builds the CIDR notation for a subnet containing ip_addr,
// optionally from an explicit netmask (dotted quad or prefix length).
func (calcNetFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*CalcNetArgs)
	text := a.IPAddr
	if a.Netmask != nil && *a.Netmask != "" {
		netmask := *a.Netmask
		bits := -1
		if strings.Contains(netmask, ".") {
			maskAddr, err := netip.ParseAddr(netmask)
			if err != nil || !maskAddr.IsValid() || !maskAddr.Is4() {
				return nil, fmt.Errorf("invalid netmask %q", netmask)
			}
			raw := maskAddr.As4()
			var ones int
			doneZeros := false
			for _, b := range raw {
				for i := 7; i >= 0; i-- {
					bit := (b >> uint(i)) & 1
					if bit == 0 {
						doneZeros = true
					} else if doneZeros {
						return nil, fmt.Errorf("invalid netmask %q", netmask)
					} else {
						ones++
					}
				}
			}
			bits = ones
		} else {
			v, err := strconv.Atoi(netmask)
			if err != nil {
				return nil, fmt.Errorf("invalid netmask %q", netmask)
			}
			bits = v
		}
		text = fmt.Sprintf("%s/%d", text, bits)
	}

	prefix, err := netip.ParsePrefix(strings.TrimSpace(text))
	if err != nil {
		return nil, fmt.Errorf("invalid network %q", text)
	}
	masked := prefix.Masked()
	return masked.String(), nil
}

// --- classification -----------------------------------------------------------

// privateV4 / privateV6 mirror CPython's _constants_tables for
// ipaddress.is_private ("not globally reachable" ranges).
var privateV4 = []netip.Prefix{
	mustPrefix("0.0.0.0/8"),
	mustPrefix("10.0.0.0/8"),
	mustPrefix("100.64.0.0/10"),
	mustPrefix("127.0.0.0/8"),
	mustPrefix("169.254.0.0/16"),
	mustPrefix("172.16.0.0/12"),
	mustPrefix("192.0.0.0/29"),
	mustPrefix("192.0.2.0/24"),
	mustPrefix("192.168.0.0/16"),
	mustPrefix("198.18.0.0/15"),
	mustPrefix("198.51.100.0/24"),
	mustPrefix("203.0.113.0/24"),
	mustPrefix("240.0.0.0/4"),
	mustPrefix("255.255.255.255/32"),
}

var privateV6 = []netip.Prefix{
	mustPrefix("::1/128"),
	mustPrefix("::/128"),
	mustPrefix("::ffff:0:0/96"),
	mustPrefix("100::/64"),
	mustPrefix("2001::/23"),
	mustPrefix("2001:2::/48"),
	mustPrefix("2001:db8::/32"),
	mustPrefix("2001:10::/28"),
	mustPrefix("64:ff9b::/96"),
	mustPrefix("fc00::/7"),
	mustPrefix("fe80::/10"),
}

func mustPrefix(s string) netip.Prefix {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return prefix
}

type IsPrivateArgs struct {
	IPAddr string `statekit:"required,name=ip_addr"`
}

type isPrivateFunc struct{ linuxLike }

func (isPrivateFunc) Name() string { return "network.is_private" }
func (isPrivateFunc) Args() any    { return IsPrivateArgs{} }
func (isPrivateFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*IsPrivateArgs)
	addr, ok := parseAddr(a.IPAddr)
	if !ok {
		return nil, fmt.Errorf("%q does not appear to be an IPv4 or IPv6 address", a.IPAddr)
	}
	table := privateV4
	if !addr.Is4() {
		table = privateV6
	}
	for _, prefix := range table {
		if prefix.Contains(addr) {
			return true, nil
		}
	}
	return false, nil
}

type IsLoopbackArgs struct {
	IPAddr string `statekit:"required,name=ip_addr"`
}

type isLoopbackFunc struct{ linuxLike }

func (isLoopbackFunc) Name() string { return "network.is_loopback" }
func (isLoopbackFunc) Args() any    { return IsLoopbackArgs{} }
func (isLoopbackFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*IsLoopbackArgs)
	addr, ok := parseAddr(a.IPAddr)
	if !ok {
		return nil, fmt.Errorf("%q does not appear to be an IPv4 or IPv6 address", a.IPAddr)
	}
	return addr.IsLoopback(), nil
}

// --- encodings -----------------------------------------------------------------

type ReverseIPArgs struct {
	IPAddr string `statekit:"required,name=ip_addr"`
}

type reverseIPFunc struct{ linuxLike }

func (reverseIPFunc) Name() string { return "network.reverse_ip" }
func (reverseIPFunc) Args() any    { return ReverseIPArgs{} }

// Execute mirrors ipaddress.reverse_pointer: v4 reverses the octets into
// in-addr.arpa, v6 expands and reverses nibbles into ip6.arpa.
func (reverseIPFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*ReverseIPArgs)
	addr, ok := parseAddr(a.IPAddr)
	if !ok {
		return nil, fmt.Errorf("'%s' does not appear to be an IPv4 or IPv6 address", a.IPAddr)
	}
	if addr.Is4() {
		raw := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", raw[3], raw[2], raw[1], raw[0]), nil
	}
	raw := addr.As16()
	var nibbles []string
	for i := 15; i >= 0; i-- {
		hi := raw[i] >> 4
		lo := raw[i] & 0x0f
		nibbles = append(nibbles, hexDigit(lo), hexDigit(hi))
	}
	return strings.Join(nibbles, ".") + ".ip6.arpa", nil
}

func hexDigit(v byte) string {
	const digits = "0123456789abcdef"
	return string(digits[v])
}

type IphexvalArgs struct {
	IP string `statekit:"required,name=ip"`
}

type iphexvalFunc struct{ linuxLike }

func (iphexvalFunc) Name() string { return "network.iphexval" }
func (iphexvalFunc) Args() any    { return IphexvalArgs{} }

// Execute renders each dotted quad as two uppercase hex characters.
func (iphexvalFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*IphexvalArgs)
	var b strings.Builder
	for _, part := range strings.Split(a.IP, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("invalid octet %q", part)
		}
		fmt.Fprintf(&b, "%02X", n)
	}
	return b.String(), nil
}

// --- Wake-On-Lan ------------------------------------------------------------------

// macStrToBytes ports utils.network.mac_str_to_bytes: bare 12-hex form or
// 17-char form with any separator at index 2.
func macStrToBytes(macStr string) ([]byte, error) {
	switch len(macStr) {
	case 12:
	case 17:
		sep := macStr[2]
		macStr = strings.ReplaceAll(macStr, string(sep), "")
	default:
		return nil, fmt.Errorf("Invalid MAC address")
	}
	out := make([]byte, 6)
	for i := 0; i < 12; i += 2 {
		v, err := strconv.ParseUint(macStr[i:i+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("Invalid MAC address")
		}
		out[i/2] = byte(v)
	}
	return out, nil
}

// udpSendHook isolates the socket write for hermetic tests; the real
// implementation broadcasts the magic packet over UDP.
var udpSendHook = func(payload []byte, bcast string, destport int) error {
	conn, err := net.Dial("udp", net.JoinHostPort(bcast, strconv.Itoa(destport)))
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(payload)
	return err
}

type WolArgs struct {
	Mac      *string `statekit:"required,name=mac"`
	Bcast    *string `statekit:"name=bcast"`
	DestPort *int64  `statekit:"name=destport"`
}

type wolFunc struct{ linuxLike }

func (wolFunc) Name() string { return "network.wol" }
func (wolFunc) Args() any    { return WolArgs{} }

// Execute sends the Wake-On-Lan magic packet (six 0xff bytes plus the MAC
// repeated sixteen times).
func (wolFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*WolArgs)
	bcast := "255.255.255.255"
	if a.Bcast != nil && *a.Bcast != "" {
		fields := strings.Fields(*a.Bcast)
		if len(fields) > 0 {
			bcast = fields[0]
		}
	}
	destport := int64(9)
	if a.DestPort != nil {
		destport = *a.DestPort
	}
	dest, err := macStrToBytes(strArg(a.Mac))
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 6+len(dest)*16)
	for i := 0; i < 6; i++ {
		payload[i] = 0xff
	}
	for i := 0; i < 16; i++ {
		copy(payload[6+i*6:], dest)
	}
	if uerr := udpSendHook(payload, bcast, int(destport)); uerr != nil {
		return nil, uerr
	}
	return true, nil
}

// Register installs the network-module execution functions shipped this
// round; tool-backed functions join as their rounds land.
func Register(reg *runtime.ExecRegistry) error {
	if extraRegister != nil {
		if err := extraRegister(reg); err != nil {
			return err
		}
	}
	for _, fn := range []runtime.ExecFunction{
		wolFunc{},
		inSubnetFunc{},
		ipInSubnetFunc{},
		convertCIDRFunc{},
		calcNetFunc{},
		isPrivateFunc{},
		isLoopbackFunc{},
		reverseIPFunc{},
		iphexvalFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

func strArg(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
