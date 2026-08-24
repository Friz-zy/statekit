package network

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// ifacesDataHook backs the interface-info functions; the default
// implementation parses `ip link show` plus `ip addr show` like
// salt.utils.network.linux_interfaces. Suites inject parsed dicts.
var ifacesDataHook = func(ctx context.Context, rt *runtime.Runtime) map[string]any {
	link := runText(ctx, rt, []string{"ip", "link", "show"})
	addr := runText(ctx, rt, []string{"ip", "addr", "show"})
	parsed, err := parseInterfacesIP(link + "\n" + addr)
	if err != nil {
		return map[string]any{}
	}
	return parsed
}

func interfacesData(ctx context.Context, rt *runtime.Runtime) map[string]any {
	return ifacesDataHook(ctx, rt)
}

type InterfacesArgs struct{}

type interfacesFunc struct{ linuxLike }

func (interfacesFunc) Name() string { return "network.interfaces" }
func (interfacesFunc) Args() any    { return InterfacesArgs{} }
func (interfacesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return interfacesData(ctx, rt), nil
}

var ifaceHeaderRe = regexp.MustCompile(`^\d*:\s+([\w.\-]+)(?:@)?([\w.\-]+)?:\s+<(.+)>`)
var groupSplitRe = regexp.MustCompile(`\r?\n\d`)

// parseInterfacesIP ports _interfaces_ip over the joined ip link/addr
// output: groups start at a numeric line, inet/inet6 entries carry
// netmask/prefixlen, broadcast, scope and label, link lines carry
// hwaddr. Group results merge per interface so the link pass hwaddr
// survives the addr pass (the observable Salt behavior).
func parseInterfacesIP(out string) (map[string]any, error) {
	ret := map[string]any{}
	groups := groupSplitRe.Split(out, -1)
	for _, group := range groups {
		iface := ""
		data := map[string]any{}
		for _, line := range strings.Split(group, "\n") {
			if !strings.Contains(line, " ") {
				continue
			}
			if m := ifaceHeaderRe.FindStringSubmatch(line); m != nil {
				iface = m[1]
				parent := m[2]
				attrs := strings.Split(m[3], ",")
				up := false
				for _, attr := range attrs {
					if attr == "UP" {
						up = true
						break
					}
				}
				data["up"] = up
				if parent != "" && parent != iface {
					data["parent"] = parent
				}
				continue
			}
			cols := strings.Fields(line)
			if len(cols) < 2 || iface == "" {
				continue
			}
			typeName, value := cols[0], cols[1]
			switch {
			case typeName == "inet" || typeName == "inet6":
				ip, mask, broadcast, scope := parseNetworkCols(typeName, value, cols)
				entry := map[string]any{"address": ip}
				if typeName == "inet6" {
					entry["prefixlen"] = mask
				} else {
					entry["netmask"] = mask
				}
				if broadcast != nil {
					entry["broadcast"] = *broadcast
				}
				if scope != nil {
					entry["scope"] = *scope
				}
				label := cols[len(cols)-1]
				entry["label"] = label

				secondary := false
				for _, col := range cols {
					if col == "secondary" {
						secondary = true
					}
				}
				if secondary {
					secList, _ := data["secondary"].([]any)
					entry["type"] = typeName
					data["secondary"] = append(secList, entry)
					continue
				}
				listKey := typeName
				inetList, _ := data[listKey].([]any)
				data[listKey] = append(inetList, entry)
			case strings.HasPrefix(typeName, "link"):
				data["hwaddr"] = value
			}
		}
		if iface == "" {
			continue
		}
		merged := map[string]any{}
		if prev, ok := ret[iface].(map[string]any); ok {
			for k, v := range prev {
				merged[k] = v
			}
		}
		for k, v := range data {
			merged[k] = v
		}
		ret[iface] = merged
	}
	return ret, nil
}

// parseNetworkCols mirrors parse_network inside _interfaces_ip: CIDR or
// bare address, dotted netmask for inet, prefix length for inet6, brd and
// scope pulled from the trailing columns.
func parseNetworkCols(typeName, value string, cols []string) (string, any, *string, *string) {
	ip := value
	cidr := "32"
	var mask any
	var broadcast, scope *string
	if idx := strings.Index(value, "/"); idx >= 0 {
		ip = value[:idx]
		cidr = value[idx+1:]
	}
	bits, _ := strconv.Atoi(cidr)
	switch typeName {
	case "inet":
		mask = v4MaskString(bits)
		for i, col := range cols {
			if col == "brd" && i+1 < len(cols) {
				b := cols[i+1]
				broadcast = &b
			}
		}
	case "inet6":
		mask = cidr
		for i, col := range cols {
			if col == "scope" && i+1 < len(cols) {
				sc := cols[i+1]
				scope = &sc
			}
		}
	}
	return ip, mask, broadcast, scope
}

// getIfaceInfo ports utils _get_iface_info: data plus the verbatim error
// message when the interface is unknown.
func getIfaceInfo(ctx context.Context, rt *runtime.Runtime, iface string) (map[string]any, string, bool) {
	info := interfacesData(ctx, rt)
	if _, ok := info[iface]; ok {
		return info, "", true
	}
	names := make([]string, 0, len(info))
	for name := range info {
		names = append(names, name)
	}
	sortStrings(names)
	return nil, fmt.Sprintf("Interface %q not in available interfaces: \"%s\"",
		iface, strings.Join(names, "\", \"")), false
}

type HwAddrArgs struct {
	Iface string `statekit:"required,name=iface"`
}

type hwAddrFunc struct{ linuxLike }

func (hwAddrFunc) Name() string { return "network.hw_addr" }
func (hwAddrFunc) Args() any    { return HwAddrArgs{} }

func (hwAddrFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*HwAddrArgs)
	info, errMsg, ok := getIfaceInfo(ctx, rt, a.Iface)
	if !ok {
		return errMsg, nil
	}
	entry, _ := info[a.Iface].(map[string]any)
	hwaddr, _ := entry["hwaddr"].(string)
	return hwaddr, nil
}

type InterfaceArgs struct {
	Iface string `statekit:"required,name=iface"`
}

type interfaceFunc struct{ linuxLike }

func (interfaceFunc) Name() string { return "network.interface" }
func (interfaceFunc) Args() any    { return InterfaceArgs{} }

func (interfaceFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InterfaceArgs)
	info, errMsg, ok := getIfaceInfo(ctx, rt, a.Iface)
	if !ok {
		return errMsg, nil
	}
	entry, _ := info[a.Iface].(map[string]any)
	inet, has := entry["inet"]
	if !has {
		return "", nil
	}
	return inet, nil
}

type InterfaceIPArgs struct {
	Iface string `statekit:"required,name=iface"`
}

type interfaceIPFunc struct{ linuxLike }

func (interfaceIPFunc) Name() string { return "network.interface_ip" }
func (interfaceIPFunc) Args() any    { return InterfaceIPArgs{} }

func (interfaceIPFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InterfaceIPArgs)
	info, errMsg, ok := getIfaceInfo(ctx, rt, a.Iface)
	if !ok {
		return errMsg, nil
	}
	entry, _ := info[a.Iface].(map[string]any)
	inetRaw, has := entry["inet"]
	if !has {
		return "", nil
	}
	inet, _ := inetRaw.([]any)
	if len(inet) == 0 {
		return "", nil
	}
	first, _ := inet[0].(map[string]any)
	addr, _ := first["address"].(string)
	return addr, nil
}

// --- subnets -----------------------------------------------------------------

func subnetsImpl(ctx context.Context, rt *runtime.Runtime, proto string, filter []string) any {
	all := interfacesData(ctx, rt)
	ifaces := map[string]any{}
	if filter == nil {
		ifaces = all
	} else {
		for _, wanted := range filter {
			if entry, ok := all[wanted]; ok {
				ifaces[wanted] = entry
			}
		}
	}

	subnetKey := "netmask"
	defaultCidr := 32
	if proto == "inet6" {
		subnetKey = "prefixlen"
		defaultCidr = 128
	}

	seen := map[string]bool{}
	var out []string
	for _, ipInfoRaw := range ifaces {
		ipInfo, _ := ipInfoRaw.(map[string]any)
		addrs, _ := ipInfo[proto].([]any)
		for _, addrAny := range addrs {
			intf, ok := addrAny.(map[string]any)
			if !ok {
				continue
			}
			address, _ := intf["address"].(string)
			bits := defaultCidr
			if raw, has := intf[subnetKey]; has {
				resolved, cerr := resolveCidrBits(fmt.Sprintf("%v", raw))
				if cerr != nil {
					continue
				}
				bits = resolved
			}
			prefix, perr := netip.ParsePrefix(fmt.Sprintf("%s/%d", address, bits))
			if perr != nil {
				continue
			}
			masked := prefix.Masked()
			if masked.Addr().IsLoopback() {
				continue
			}
			key := masked.String()
			if !seen[key] {
				seen[key] = true
				out = append(out, key)
			}
		}
	}
	sortStrings(out)
	return toAnySlice(out)
}

type SubnetsArgs struct {
	Interfaces []string `statekit:"name=interfaces"`
}

type subnetsFunc struct{ linuxLike }

func (subnetsFunc) Name() string { return "network.subnets" }
func (subnetsFunc) Args() any    { return SubnetsArgs{} }

func (subnetsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SubnetsArgs)
	return subnetsImpl(ctx, rt, "inet", a.Interfaces), nil
}

type Subnets6Args struct{}

type subnets6Func struct{ linuxLike }

func (subnets6Func) Name() string { return "network.subnets6" }
func (subnets6Func) Args() any    { return Subnets6Args{} }

func (subnets6Func) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return subnetsImpl(ctx, rt, "inet6", nil), nil
}

// resolveCidrBits accepts a dotted quad mask or a plain prefix length.
func resolveCidrBits(mask string) (int, error) {
	if strings.Contains(mask, ".") {
		maskAddr, err := netip.ParseAddr(mask)
		if err != nil || !maskAddr.IsValid() || !maskAddr.Is4() {
			return 0, fmt.Errorf("invalid netmask %q", mask)
		}
		raw := maskAddr.As4()
		ones := 0
		doneZeros := false
		for _, b := range raw {
			for i := 7; i >= 0; i-- {
				bit := (b >> uint(i)) & 1
				if bit == 0 {
					doneZeros = true
				} else if doneZeros {
					return 0, fmt.Errorf("invalid netmask %q", mask)
				} else {
					ones++
				}
			}
		}
		return ones, nil
	}
	v, err := strconv.Atoi(mask)
	if err != nil {
		return 0, err
	}
	return v, nil
}

// --- routing -------------------------------------------------------------------

type RoutesArgs struct {
	Family *string `statekit:"name=family"`
}

type routesFunc struct{ linuxLike }

func (routesFunc) Name() string { return "network.routes" }
func (routesFunc) Args() any    { return RoutesArgs{} }

// ipRouteLinux ports _ip_route_linux over `ip -4 route show table main`
// and `ip -6 route show table all`.
func ipRouteLinux(ctx context.Context, rt *runtime.Runtime) ([]any, error) {
	var out []any

	v4 := runText(ctx, rt, []string{"ip", "-4", "route", "show", "table", "main"})
	for _, line := range strings.Split(v4, "\n") {
		comps := strings.Fields(line)
		if len(comps) == 0 {
			continue
		}
		switch comps[0] {
		case "unreachable":
			continue
		case "default":
			iface := ""
			if len(comps) > 3 && comps[3] == "dev" {
				iface = comps[4]
			}
			gateway := ""
			if len(comps) > 2 {
				gateway = comps[2]
			}
			out = append(out, map[string]any{
				"addr_family": "inet",
				"destination": "0.0.0.0",
				"gateway":     gateway,
				"netmask":     "0.0.0.0",
				"flags":       "UG",
				"interface":   iface,
			})
		default:
			addressMaskRaw, err := convertCIDRFunc{}.Execute(ctx, rt,
				&ConvertCIDRArgs{CIDR: comps[0]})
			if err != nil {
				continue
			}
			addressMask := addressMaskRaw.(map[string]any)
			iface := ""
			if len(comps) > 1 && comps[1] == "dev" {
				iface = comps[2]
			}
			netmask, _ := addressMask["netmask"]
			network, _ := addressMask["network"]
			out = append(out, map[string]any{
				"addr_family": "inet",
				"destination": network,
				"gateway":     "0.0.0.0",
				"netmask":     netmask,
				"flags":       "U",
				"interface":   iface,
			})
		}
	}

	v6 := runText(ctx, rt, []string{"ip", "-6", "route", "show", "table", "all"})
	skipV6 := map[string]bool{
		"unicast": true, "broadcast": true, "throw": true, "unreachable": true,
		"prohibit": true, "blackhole": true, "nat": true, "anycast": true,
		"multicast": true,
	}
	for _, line := range strings.Split(v6, "\n") {
		comps := strings.Fields(line)
		if len(comps) == 0 {
			continue
		}
		if skipV6[comps[0]] {
			continue
		}
		if comps[0] == "default" {
			iface := ""
			for i, comp := range comps {
				if comp == "dev" && i+1 < len(comps) {
					iface = comps[i+1]
					break
				}
			}
			gateway := "::"
			for i, comp := range comps {
				if comp == "via" && i+1 < len(comps) {
					gateway = comps[i+1]
					break
				}
			}
			out = append(out, map[string]any{
				"addr_family": "inet6",
				"destination": "::/0",
				"gateway":     gateway,
				"netmask":     "",
				"flags":       "UG",
				"interface":   iface,
			})
			continue
		}
		destination := comps[0]
		gateway := ""
		iface := ""
		for i, comp := range comps {
			switch comp {
			case "via":
				if i+1 < len(comps) {
					gateway = comps[i+1]
				}
			case "dev":
				if i+1 < len(comps) {
					iface = comps[i+1]
				}
			}
		}
		flags := "U"
		if gateway != "" {
			flags = "UG"
		}
		out = append(out, map[string]any{
			"addr_family": "inet6",
			"destination": destination,
			"gateway":     gateway,
			"netmask":     "",
			"flags":       flags,
			"interface":   iface,
		})
	}
	return out, nil
}

func (routesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RoutesArgs)
	family := strArg(a.Family)
	if family != "" && family != "inet" && family != "inet6" {
		return nil, fmt.Errorf("Invalid address family %s", family)
	}

	routes_, err := ipRouteLinux(ctx, rt)
	if err != nil {
		return nil, err
	}
	if family == "" {
		return routes_, nil
	}
	filtered := []any{}
	for _, routeRaw := range routes_ {
		route := routeRaw.(map[string]any)
		if route["addr_family"] == family {
			filtered = append(filtered, routeRaw)
		}
	}
	return filtered, nil
}

type DefaultRouteArgs struct {
	Family *string `statekit:"name=family"`
}

type defaultRouteFunc struct{ linuxLike }

func (defaultRouteFunc) Name() string { return "network.default_route" }
func (defaultRouteFunc) Args() any    { return DefaultRouteArgs{} }

func (defaultRouteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DefaultRouteArgs)
	family := strArg(a.Family)
	if family != "" && family != "inet" && family != "inet6" {
		return nil, fmt.Errorf("Invalid address family %s", family)
	}

	res, err := routesFunc{}.Execute(ctx, rt, &RoutesArgs{Family: a.Family})
	if err != nil {
		return nil, err
	}
	routes_ := res.([]any)

	linuxDefaults := map[string][]string{
		"inet":  {"0.0.0.0", "default"},
		"inet6": {"::/0", "default"},
	}

	ret := []any{}
	for _, routeRaw := range routes_ {
		route := routeRaw.(map[string]any)
		destination, _ := route["destination"].(string)
		if family != "" {
			if containsStr(linuxDefaults[family], destination) {
				ret = append(ret, routeRaw)
			}
			continue
		}
		if containsStr(linuxDefaults["inet"], destination) ||
			containsStr(linuxDefaults["inet6"], destination) {
			ret = append(ret, routeRaw)
		}
	}
	return ret, nil
}

type GetRouteArgs struct {
	IP string `statekit:"required,name=ip"`
}

type getRouteFunc struct{ linuxLike }

func (getRouteFunc) Name() string { return "network.get_route" }
func (getRouteFunc) Args() any    { return GetRouteArgs{} }

// routeGetRe mirrors upstream's extraction over `ip route get` output.
var routeGetRe = regexp.MustCompile(
	`(via\s+(?P<gateway>[\w\.:]+))?\s+dev\s+(?P<interface>[\w\.\:\-]+)\s+.*src\s+(?P<source>[\w\.:]+)`)

func (getRouteFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetRouteArgs)
	out := runText(context.Background(), rt, []string{"ip", "route", "get", a.IP})
	lines := strings.Split(out, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("no route found for %s", a.IP)
	}
	m := routeGetRe.FindStringSubmatch(lines[0])
	if m == nil {
		return nil, fmt.Errorf("could not parse routing information for %s", a.IP)
	}
	gateway, interfaceName, source := m[2], m[3], m[4]
	return map[string]any{
		"destination": a.IP,
		"gateway":     gateway,
		"interface":   interfaceName,
		"source":      source,
	}, nil
}

// --- connections / neighbors ----------------------------------------------------

type ActiveTCPArgs struct{}

type activeTCPFunc struct{ linuxLike }

func (activeTCPFunc) Name() string { return "network.active_tcp" }
func (activeTCPFunc) Args() any    { return ActiveTCPArgs{} }

// hexToIP converts /proc/net/tcp's little-endian hex address (8 or 32 hex
// characters) into its textual form.
func hexToIP(hexAddr string) string {
	switch len(hexAddr) {
	case 8:
		raw := make([]byte, 4)
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(hexAddr[i*2:i*2+2], 16, 8)
			if err != nil {
				return hexAddr
			}
			raw[3-i] = byte(v)
		}
		addr, ok := netip.AddrFromSlice(raw)
		if !ok {
			return hexAddr
		}
		return addr.String()
	case 32:
		raw := make([]byte, 16)
		for i := 0; i < 16; i++ {
			v, err := strconv.ParseUint(hexAddr[i*2:i*2+2], 16, 8)
			if err != nil {
				return hexAddr
			}
			raw[15-i] = byte(v)
		}
		addr, ok := netip.AddrFromSlice(raw)
		if !ok {
			return hexAddr
		}
		return addr.Unmap().String()
	default:
		return hexAddr
	}
}

func parseTCPLine(line string) (string, map[string]any) {
	comps := strings.Fields(strings.TrimSpace(line))
	if len(comps) < 4 {
		return "", nil
	}
	slot := strings.TrimSuffix(comps[0], ":")
	localParts := strings.Split(comps[1], ":")
	remoteParts := strings.Split(comps[2], ":")
	if len(localParts) != 2 || len(remoteParts) != 2 {
		return "", nil
	}
	lPort, _ := strconv.ParseInt(localParts[1], 16, 64)
	rPort, _ := strconv.ParseInt(remoteParts[1], 16, 64)
	state, _ := strconv.ParseInt(comps[3], 16, 64)
	return slot, map[string]any{
		"local_addr":  hexToIP(localParts[0]),
		"local_port":  lPort,
		"remote_addr": hexToIP(remoteParts[0]),
		"remote_port": rPort,
		"state":       state,
	}
}

func (activeTCPFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	ret := map[string]any{}
	slot := 0
	for _, statFile := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := rt.FS.ReadFile(statFile)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "sl") {
				continue
			}
			_, iret := parseTCPLine(line)
			if iret == nil {
				continue
			}
			if iret["state"] == int64(1) { // ESTABLISHED
				delete(iret, "state")
				ret[strconv.Itoa(slot)] = iret
				slot++
			}
		}
	}
	return ret, nil
}

// --- tool wrappers ---------------------------------------------------------------

// sanitizeHost mirrors utils.network.sanitize_host (RFC1123 characters).
func sanitizeHost(host string) string {
	host = host[:min(len(host), 255)]
	var b strings.Builder
	for _, c := range host {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type PingArgs struct {
	Host          string `statekit:"required,name=host"`
	Timeout       *int64 `statekit:"name=timeout"`
	ReturnBoolean *bool  `statekit:"name=return_boolean"`
}

type pingFunc struct{ linuxLike }

func (pingFunc) Name() string { return "network.ping" }
func (pingFunc) Args() any    { return PingArgs{} }

// Execute performs an ICMP ping through the central Runner.
func (pingFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PingArgs)
	host := sanitizeHost(a.Host)
	var argv []string
	if a.Timeout != nil && *a.Timeout != 0 {
		argv = []string{"ping", "-W", strconv.FormatInt(*a.Timeout, 10), "-c", "4", host}
	} else {
		argv = []string{"ping", "-c", "4", host}
	}
	if a.ReturnBoolean != nil && *a.ReturnBoolean {
		res := rt.Runner.Run(ctx0(), process.Command{Name: argv[0], Args: argv[1:]})
		if res.Err != nil {
			return false, nil
		}
		return res.ExitCode == 0, nil
	}
	return runText(context.Background(), rt, argv), nil
}

type TracerouteArgs struct {
	Host string `statekit:"required,name=host"`
}

type tracerouteFunc struct{ linuxLike }

func (tracerouteFunc) Name() string { return "network.traceroute" }
func (tracerouteFunc) Args() any    { return TracerouteArgs{} }

func (tracerouteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*TracerouteArgs)
	if toolPath("traceroute") == "" {
		return nil, &runtime.UnsupportedError{Kind: "binary", Name: "traceroute"}
	}
	host := sanitizeHost(a.Host)
	res := rt.Runner.Run(ctx, process.Command{Name: "traceroute", Args: []string{host}})
	if res.Err != nil {
		return nil, res.Err
	}
	return string(res.Stdout), nil
}

type DigArgs struct {
	Host string `statekit:"required,name=host"`
}

type digFunc struct{ linuxLike }

func (digFunc) Name() string { return "network.dig" }
func (digFunc) Args() any    { return DigArgs{} }

func (digFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DigArgs)
	return runText(ctx, rt, []string{"dig", sanitizeHost(a.Host)}), nil
}

type ArpArgs struct{}

type arpFunc struct{ linuxLike }

func (arpFunc) Name() string { return "network.arp" }
func (arpFunc) Args() any    { return ArpArgs{} }

// Execute parses `arp -an` with the Linux column mapping.
func (arpFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	out := runText(ctx, rt, []string{"arp", "-an"})
	ret := map[string]any{}
	for _, line := range strings.Split(out, "\n") {
		comps := strings.Fields(line)
		if len(comps) < 4 {
			continue
		}
		ret[comps[3]] = strings.TrimSuffix(strings.TrimPrefix(comps[1], "("), ")")
	}
	return ret, nil
}

func containsStr(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}

// Extend this round's registration with the tool-backed functions.
func init() {
	extraRegister = func(reg *runtime.ExecRegistry) error {
		for _, fn := range []runtime.ExecFunction{
			interfacesFunc{},
			hwAddrFunc{},
			interfaceFunc{},
			interfaceIPFunc{},
			subnetsFunc{},
			subnets6Func{},
			routesFunc{},
			defaultRouteFunc{},
			getRouteFunc{},
			activeTCPFunc{},
			pingFunc{},
			tracerouteFunc{},
			digFunc{},
			arpFunc{},
		} {
			if err := reg.Register(fn); err != nil {
				return err
			}
		}
		return nil
	}
}

var extraRegister func(reg *runtime.ExecRegistry) error
