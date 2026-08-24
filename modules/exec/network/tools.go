package network

import (
	"context"
	"crypto/md5"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// --- netstat / ss -----------------------------------------------------------

type NetstatArgs struct{}

type netstatFunc struct{ linuxLike }

func (netstatFunc) Name() string { return "network.netstat" }
func (netstatFunc) Args() any    { return NetstatArgs{} }

// Execute mirrors the Linux dispatch: netstat when available, ss fallback.
func (netstatFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if toolPath("netstat") != "" {
		return netstatLinux(ctx, rt), nil
	}
	return ssLinux(ctx, rt), nil
}

// netstatLinux ports _netstat_linux over `netstat -tulpnea`.
func netstatLinux(ctx context.Context, rt *runtime.Runtime) []any {
	out := runText(ctx, rt, []string{"netstat", "-tulpnea"})
	ret := []any{}
	for _, line := range strings.Split(out, "\n") {
		comps := strings.Fields(line)
		switch {
		case strings.HasPrefix(line, "tcp") && len(comps) >= 9:
			ret = append(ret, map[string]any{
				"proto":          comps[0],
				"recv-q":         comps[1],
				"send-q":         comps[2],
				"local-address":  comps[3],
				"remote-address": comps[4],
				"state":          comps[5],
				"user":           comps[6],
				"inode":          comps[7],
				"program":        comps[8],
			})
		case strings.HasPrefix(line, "udp") && len(comps) >= 8:
			ret = append(ret, map[string]any{
				"proto":          comps[0],
				"recv-q":         comps[1],
				"send-q":         comps[2],
				"local-address":  comps[3],
				"remote-address": comps[4],
				"user":           comps[5],
				"inode":          comps[6],
				"program":        comps[7],
			})
		}
	}
	return ret
}

// ssLinux ports _ss_linux over `ss -tulpnea`, including the users/uid/ino
// trailing-field extraction and the ESTAB -> ESTABLISHED rename.
func ssLinux(ctx context.Context, rt *runtime.Runtime) []any {
	out := runText(ctx, rt, []string{"ss", "-tulpnea"})
	ret := []any{}
	for _, line := range strings.Split(out, "\n") {
		comps := strings.Fields(line)
		if !strings.HasPrefix(line, "tcp") && !strings.HasPrefix(line, "udp") {
			continue
		}
		if len(comps) < 7 {
			continue
		}
		ssUser := "0"
		ssInode := "0"
		ssProgram := ""
		for i := 6; i < len(comps)-1; i++ {
			fields := strings.SplitN(comps[i], ":", 2)
			if len(fields) != 2 {
				continue
			}
			switch fields[0] {
			case "users":
				users := strings.Split(fields[1], ",")
				if quoted := strings.Split(users[0], "\""); len(quoted) > 1 {
					ssProgram = quoted[1]
				}
			case "uid":
				ssUser = fields[1]
			case "ino":
				ssInode = fields[1]
			}
		}
		state := ""
		if strings.HasPrefix(line, "tcp") {
			state = comps[1]
			if state == "ESTAB" {
				state = "ESTABLISHED"
			}
		}
		entry := map[string]any{
			"proto":          comps[0],
			"recv-q":         comps[2],
			"send-q":         comps[3],
			"local-address":  comps[4],
			"remote-address": comps[5],
			"user":           ssUser,
			"inode":          ssInode,
			"program":        ssProgram,
		}
		if strings.HasPrefix(line, "tcp") {
			entry["state"] = state
		}
		ret = append(ret, entry)
	}
	return ret
}

// --- neighbors -----------------------------------------------------------------

type IPNeighsArgs struct{}

type ipNeighsFunc struct{ linuxLike }

func (ipNeighsFunc) Name() string { return "network.ip_neighs" }
func (ipNeighsFunc) Args() any    { return IPNeighsArgs{} }

func (ipNeighsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return parseNeighs(ctx, rt, func(first string) bool { return strings.Contains(first, ".") }), nil
}

type IPNeighs6Args struct{}

type ipNeighs6Func struct{ linuxLike }

func (ipNeighs6Func) Name() string { return "network.ip_neighs6" }
func (ipNeighs6Func) Args() any    { return IPNeighs6Args{} }

func (ipNeighs6Func) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return parseNeighs(ctx, rt, func(first string) bool { return strings.Contains(first, ":") }), nil
}

// parseNeighs ports the shared `ip neigh show` walk: five columns minimum,
// keyed by the fifth column with the address as value.
func parseNeighs(ctx context.Context, rt *runtime.Runtime, want func(string) bool) map[string]any {
	out := runText(ctx, rt, []string{"ip", "neigh", "show"})
	ret := map[string]any{}
	for _, line := range strings.Split(out, "\n") {
		comps := strings.Fields(line)
		if len(comps) < 5 {
			continue
		}
		if want(comps[0]) {
			ret[comps[4]] = comps[0]
		}
	}
	return ret
}

// --- hostname trio ----------------------------------------------------------------

type GetHostnameArgs struct{}

type getHostnameFunc struct{ linuxLike }

var osHostnameHook = func() (string, error) { return os.Hostname() }

func (getHostnameFunc) Name() string { return "network.get_hostname" }
func (getHostnameFunc) Args() any    { return GetHostnameArgs{} }
func (getHostnameFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	host, err := osHostnameHook()
	if err != nil {
		return nil, err
	}
	return host, nil
}

// fqdnHook mirrors socket.getfqdn(): canonical name of the local host,
// falling back to the plain hostname when resolution fails.
var fqdnHook = func(rt *runtime.Runtime) string {
	host, err := osHostnameHook()
	if err != nil || host == "" {
		return ""
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return host
	}
	names, err := net.LookupAddr(addrs[0])
	if err != nil || len(names) == 0 {
		return host
	}
	return strings.TrimSuffix(names[0], ".")
}

type GetFqdnArgs struct{}

type getFqdnFunc struct{ linuxLike }

func (getFqdnFunc) Name() string { return "network.get_fqdn" }
func (getFqdnFunc) Args() any    { return GetFqdnArgs{} }
func (getFqdnFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return fqdnHook(rt), nil
}

// hostnameCmdHook resolves hostnamectl or hostname like utils.path.which.
var hostnameCmdHook = func() string {
	if toolPath("hostnamectl") != "" {
		return toolPath("hostnamectl")
	}
	return toolPath("hostname")
}

type ModHostnameArgs struct {
	Hostname *string `statekit:"required,name=hostname"`
}

type modHostnameFunc struct{ linuxLike }

func (modHostnameFunc) Name() string { return "network.mod_hostname" }
func (modHostnameFunc) Args() any    { return ModHostnameArgs{} }

// Execute mirrors mod_hostname for non-SunOS systems: set via
// hostnamectl/hostname then rewrite /etc/hosts tokens and the distro
// hostname file.
func (modHostnameFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ModHostnameArgs)
	if a.Hostname == nil || strArg(a.Hostname) == "" {
		return false, nil
	}
	newHostname := strArg(a.Hostname)
	hostnameCmd := hostnameCmdHook()

	oldHostname := ""
	if strings.HasSuffix(hostnameCmd, "hostnamectl") {
		res := rt.Runner.Run(ctx, process.Command{Name: hostnameCmd, Args: []string{"status"}})
		if res.Err == nil && res.ExitCode == 0 {
			for _, line := range strings.Split(string(res.Stdout), "\n") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 && strings.Contains(parts[0], "Static hostname") {
					oldHostname = strings.TrimSpace(parts[1])
				}
			}
		} else {
			fqRaw, ferr := getFqdnFunc{}.Execute(ctx, rt, &GetFqdnArgs{})
			if ferr == nil {
				oldHostname, _ = fqRaw.(string)
			}
		}
	} else {
		oldHostname = fqdnHook(rt)
	}

	if strings.HasSuffix(hostnameCmd, "hostnamectl") {
		res := rt.Runner.Run(ctx, process.Command{
			Name: hostnameCmd, Args: []string{"set-hostname", newHostname},
		})
		if res.Err != nil || res.ExitCode != 0 {
			return false, nil
		}
	} else {
		runText(ctx, rt, []string{hostnameCmd, newHostname})
	}

	hostsPath := "/etc/hosts"
	hostContent, rerr := rt.FS.ReadFile(hostsPath)
	if rerr != nil {
		return nil, rerr
	}
	var rewritten []string
	for _, line := range strings.Split(string(hostContent), "\n") {
		fields := strings.Fields(line)
		for i, field := range fields {
			if field == oldHostname {
				fields[i] = newHostname
			}
		}
		rewritten = append(rewritten, strings.Join(fields, "\t"))
	}
	if err := rt.FS.WriteFile(hostsPath, []byte(strings.Join(rewritten, "\n")), 0o644); err != nil {
		return nil, err
	}

	osFamily := osFamilyValue(rt)
	switch {
	case osFamily == "RedHat":
		netPath := "/etc/sysconfig/network"
		netContent, nerr := rt.FS.ReadFile(netPath)
		if nerr != nil {
			return nil, nerr
		}
		var outLines []string
		for _, line := range strings.Split(string(netContent), "\n") {
			if strings.HasPrefix(line, "HOSTNAME") {
				old := ""
				if eq := strings.Index(line, "="); eq >= 0 {
					old = strings.TrimSpace(line[eq+1:])
				}
				quote := ""
				if len(old) >= 2 && (old[0] == '"' || old[0] == '\'') {
					quote = string(old[0])
				}
				outLines = append(outLines, fmt.Sprintf("HOSTNAME=%s%s%s",
					quote, dequote(newHostname), quote))
				continue
			}
			outLines = append(outLines, line)
		}
		if werr := rt.FS.WriteFile(netPath, []byte(strings.Join(outLines, "\n")), 0o644); werr != nil {
			return nil, werr
		}
	case osFamily == "Debian" || osFamily == "NILinuxRT":
		if werr := rt.FS.WriteFile("/etc/hostname",
			[]byte(newHostname+"\n"), 0o644); werr != nil {
			return nil, werr
		}
	}
	return true, nil
}

func dequote(s string) string {
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// osFamilyValue reads through the same grain hook the iptables family uses.
func osFamilyValue(rt *runtime.Runtime) string { return osFamilyHook(rt) }

// --- connect ---------------------------------------------------------------------

type ConnectArgs struct {
	Host    *string `statekit:"required,name=host"`
	Port    *int64  `statekit:"name=port"`
	Proto   *string `statekit:"name=proto"`
	Timeout *int64  `statekit:"name=timeout"`
	Family  *string `statekit:"name=family"`
}

type connectFunc struct{ linuxLike }

func (connectFunc) Name() string { return "network.connect" }
func (connectFunc) Args() any    { return ConnectArgs{} }

// Execute tests connectivity to host:port mirroring upstream's comment
// dictionary verbatim.
func (connectFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ConnectArgs)
	ret := func(result bool, comment string) map[string]any {
		return map[string]any{"result": result, "comment": comment}
	}

	host := strArg(a.Host)
	port := int64(0)
	if a.Port != nil {
		port = *a.Port
	}
	if host == "" {
		return ret(false, "Required argument, host, is missing."), nil
	}
	if port == 0 {
		return ret(false, "Required argument, port, is missing."), nil
	}

	proto := "tcp"
	if a.Proto != nil && *a.Proto != "" {
		proto = *a.Proto
	}
	timeoutSeconds := int64(5)
	if a.Timeout != nil && *a.Timeout != 0 {
		timeoutSeconds = *a.Timeout
	}
	network := "tcp"
	switch proto {
	case "udp":
		network = "udp"
	default:
		proto = "tcp"
	}
	if a.Family != nil {
		switch *a.Family {
		case "ipv4":
			network = network + "4"
		case "ipv6":
			network = network + "6"
		}
	}

	address := sanitizeHost(host)
	if parsed, err := netip.ParseAddr(host); err == nil && parsed.IsValid() {
		address = host
	}

	resolved, rerr := net.ResolveTCPAddr("tcp", net.JoinHostPort(address, strconv.FormatInt(port, 10)))
	ipText := ""
	if resolved != nil && resolved.IP != nil {
		ipText = resolved.IP.String()
	}
	if rerr != nil {
		return ret(false, fmt.Sprintf("Unable to resolve host %s on %s port %d",
			host, proto, port)), nil
	}

	conn, cerr := net.DialTimeout(network,
		net.JoinHostPort(address, strconv.FormatInt(port, 10)),
		time.Duration(timeoutSeconds)*time.Second)
	if cerr != nil {
		return ret(false, fmt.Sprintf("Unable to connect to %s (%s) on %s port %d",
			host, ipText, proto, port)), nil
	}
	defer conn.Close()

	if proto == "udp" {
		msg := fmt.Sprintf("%x", md5.Sum([]byte(strconv.FormatInt(time.Now().Unix(), 10))))
		if _, werr := conn.Write([]byte(msg)); werr != nil {
			return ret(false, fmt.Sprintf("Unable to connect to %s (%s) on %s port %d",
				host, ipText, proto, port)), nil
		}
		buf := make([]byte, 255)
		conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutSeconds) * time.Second))
		if _, rrerr := conn.Read(buf); rrerr != nil {
			return ret(false, fmt.Sprintf("Unable to connect to %s (%s) on %s port %d",
				host, ipText, proto, port)), nil
		}
	} else if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}

	return ret(true, fmt.Sprintf("Successfully connected to %s (%s) on %s port %d",
		host, ipText, proto, port)), nil
}

// --- buffers -----------------------------------------------------------------------

type GetBufsizeArgs struct {
	Iface string `statekit:"required,name=iface"`
}

type getBufsizeFunc struct{ linuxLike }

func (getBufsizeFunc) Name() string { return "network.get_bufsize" }
func (getBufsizeFunc) Args() any    { return GetBufsizeArgs{} }

var bufsizePat = regexp.MustCompile(`^(.+):\s+(\d+)$`)

// getBufsizeLinux ports _get_bufsize_linux over the literal /sbin/ethtool
// command Salt builds.
func getBufsizeLinux(ctx context.Context, rt *runtime.Runtime, iface string) map[string]any {
	ret := map[string]any{"result": false}
	out := runText(ctx, rt, []string{"/sbin/ethtool", "-g", iface})
	suffix := "max-"
	for _, line := range strings.Split(out, "\n") {
		if m := bufsizePat.FindStringSubmatch(line); m != nil {
			key := strings.ToLower(strings.ReplaceAll(m[1], " ", "-")) + suffix
			val, verr := strconv.Atoi(m[2])
			if verr != nil {
				continue
			}
			ret[key] = int64(val)
			ret["result"] = true
		} else if strings.HasSuffix(line, "maximums:") {
			suffix = "-max"
		} else if strings.HasSuffix(line, "settings:") {
			suffix = ""
		}
	}
	if ret["result"] == false {
		parts := strings.Fields(out)
		if len(parts) > 0 && strings.HasSuffix(parts[0], "sh:") {
			out = strings.Join(parts[1:], " ")
		}
		ret["comment"] = strings.TrimSpace(out)
	}
	return ret
}

// ethtoolGate mirrors os.path.exists("/sbin/ethtool"); injectable.
var ethtoolGate = func() bool { return pathExists("/sbin/ethtool") }

func (getBufsizeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetBufsizeArgs)
	if kernelHook(rt) == "Linux" && ethtoolGate() {
		return getBufsizeLinux(ctx, rt, a.Iface), nil
	}
	return map[string]any{}, nil
}

type ModBufsizeArgs struct {
	Iface  string         `statekit:"required,name=iface"`
	Args   []string       `statekit:"name=args"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type modBufsizeFunc struct{ linuxLike }

func (modBufsizeFunc) Name() string { return "network.mod_bufsize" }
func (modBufsizeFunc) Args() any    { return ModBufsizeArgs{} }

// modBufsizeLinux ports _mod_bufsize_linux.
func modBufsizeLinux(ctx context.Context, rt *runtime.Runtime, iface string, extraArgs []string, kwargs map[string]any) map[string]any {
	ret := map[string]any{
		"result":  false,
		"comment": "Requires rx=<val> tx==<val> rx-mini=<val> and/or rx-jumbo=<val>",
	}
	if len(kwargs) == 0 {
		return ret
	}
	if len(extraArgs) > 0 {
		texts := make([]string, 0, len(extraArgs))
		for _, item := range extraArgs {
			texts = append(texts, fmt.Sprintf("%v", item))
		}
		ret["comment"] = "Unknown arguments: " + strings.Join(texts, " ")
		return ret
	}
	eargs := ""
	for _, kw := range []string{"rx", "tx", "rx-mini", "rx-jumbo"} {
		if val, ok := kwargs[kw]; ok && val != nil {
			eargs += " " + kw + " " + fmt.Sprintf("%v", val)
		}
	}
	if eargs == "" {
		return ret
	}
	res := rt.Runner.Run(ctx, process.Command{
		Name: "/sbin/ethtool",
		Args: append([]string{"-G", iface}, strings.Fields(eargs)...),
	})
	if res.Err == nil && strings.TrimSpace(string(res.Stdout)) == "" {
		ret["comment"] = strings.TrimSpace(eargs)
		ret["result"] = true
	} else {
		ret["comment"] = strings.TrimSpace(string(res.Stdout))
	}
	return ret
}

func (modBufsizeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ModBufsizeArgs)
	if kernelHook(rt) == "Linux" && ethtoolGate() {
		return modBufsizeLinux(ctx, rt, a.Iface, a.Args, a.Kwargs), nil
	}
	return false, nil
}

// --- networks / ifacestartswith / fqdns ----------------------------------------------

type IPNetworksArgs struct {
	Interface       []string `statekit:"name=interface"`
	IncludeLoopback bool     `statekit:"name=include_loopback"`
	Verbose         bool     `statekit:"name=verbose"`
}

type ipNetworksFunc struct{ linuxLike }

func (ipNetworksFunc) Name() string { return "network.ip_networks" }
func (ipNetworksFunc) Args() any    { return IPNetworksArgs{} }

type ipNetworks6Func struct{ linuxLike }

func (ipNetworks6Func) Name() string { return "network.ip_networks6" }
func (ipNetworks6Func) Args() any    { return IPNetworksArgs{} }

// ipNetworksImpl ports _ip_networks: gather addresses under the proto key,
// optionally glob-filtered by interface name, masked into networks.
func ipNetworksImpl(ctx context.Context, rt *runtime.Runtime, proto string, a *IPNetworksArgs) any {
	all := interfacesData(ctx, rt)
	selected := all
	if len(a.Interface) > 0 {
		selected = map[string]any{}
		for name, entry := range all {
			for _, pattern := range a.Interface {
				if matched, _ := path.Match(pattern, name); matched {
					selected[name] = entry
					break
				}
			}
		}
	}

	netKey := "netmask"
	if proto == "inet6" {
		netKey = "prefixlen"
	}

	type netKeyStruct struct {
		prefix netipPrefix
	}
	set := map[string]netipPrefix{}
	var verboseRet map[string]any

	for _, ipInfoRaw := range selected {
		ipInfo, ok := ipInfoRaw.(map[string]any)
		if !ok {
			continue
		}
		addrs, _ := ipInfo[proto].([]any)
		for _, addrAny := range addrs {
			addr, ok := addrAny.(map[string]any)
			if !ok {
				continue
			}
			ipText, _ := addr["address"].(string)
			maskText, _ := addr[netKey].(string)
			if ipText == "" || maskText == "" {
				continue
			}
			bits, berr := resolveCidrBits(maskText)
			if berr != nil {
				continue
			}
			base, aerr := netip.ParseAddr(ipText)
			if aerr != nil || !base.IsValid() {
				continue
			}
			prefix := netip.PrefixFrom(base, bits).Masked()
			if prefix.Addr().IsLoopback() && !a.IncludeLoopback {
				continue
			}
			set[prefix.String()] = netipPrefix{prefix}
		}
	}

	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	if a.Verbose {
		verboseRet = map[string]any{}
		for _, key := range keys {
			prefix := set[key].prefix
			entry := map[string]any{
				"address":       prefix.Addr().String(),
				"netmask":       maskOrLen(prefix),
				"num_addresses": numAddresses(prefix),
				"prefixlen":     prefix.Bits(),
			}
			verboseRet[key] = entry
		}
		return verboseRet
	}

	out := make([]any, 0, len(keys))
	for _, key := range keys {
		out = append(out, key)
	}
	return out
}

// netipPrefix wraps netip.Prefix for the verbose set above.
type netipPrefix struct{ prefix netipPrefixAlias }

func (n netipPrefix) String() string { return n.prefix.String() }

type netipPrefixAlias = netip.Prefix

func maskOrLen(prefix netip.Prefix) any {
	if prefix.Addr().Is4() {
		return v4MaskString(prefix.Bits())
	}
	return prefix.Bits()
}

func numAddresses(prefix netip.Prefix) uint64 {
	bits := uint(prefix.Addr().BitLen() - prefix.Bits())
	if bits >= 64 {
		return ^uint64(0)
	}
	return uint64(1) << bits
}

func (ipNetworksFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*IPNetworksArgs)
	return ipNetworksImpl(ctx, rt, "inet", a), nil
}

func (ipNetworks6Func) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*IPNetworksArgs)
	return ipNetworksImpl(ctx, rt, "inet6", a), nil
}

type IfacestartswithArgs struct {
	CIDR string `statekit:"required,name=cidr"`
}

type ifacestartswithFunc struct{ linuxLike }

func (ifacestartswithFunc) Name() string { return "network.ifacestartswith" }
func (ifacestartswithFunc) Args() any    { return IfacestartswithArgs{} }

// Execute matches interface addresses by string prefix, preferring labels.
func (ifacestartswithFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*IfacestartswithArgs)
	all := interfacesData(ctx, rt)
	pattern := a.CIDR
	size := len(pattern)
	intfnames := []any{}
	for ifname, ifvalRaw := range all {
		ifval, ok := ifvalRaw.(map[string]any)
		if !ok {
			continue
		}
		inetList, has := ifval["inet"].([]any)
		if !has {
			continue
		}
		for _, inetAny := range inetList {
			inet, ok := inetAny.(map[string]any)
			if !ok {
				continue
			}
			address, _ := inet["address"].(string)
			if len(address) >= size && address[:size] == pattern {
				if label, hasLabel := inet["label"].(string); hasLabel {
					intfnames = append(intfnames, label)
				} else {
					intfnames = append(intfnames, ifname)
				}
			}
		}
	}
	return intfnames, nil
}

type FqdnsArgs struct{}

type fqdnsFunc struct{ linuxLike }

func (fqdnsFunc) Name() string { return "network.fqdns" }
func (fqdnsFunc) Args() any    { return FqdnsArgs{} }

// Execute reverse-resolves every non-loopback address sequentially
// (upstream parallelizes with a thread pool; documented divergence).
func (fqdnsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	fqdnsSet := map[string]bool{}
	for _, addr := range hostAddrsHook(rt) {
		parsed, ok := parseAddr(addr)
		if !ok || parsed.IsLoopback() {
			continue
		}
		names, err := net.LookupAddr(addr)
		if err != nil {
			continue
		}
		for _, name := range names {
			canonical := strings.TrimSuffix(name, ".")
			if canonical != "" {
				fqdnsSet[canonical] = true
			}
		}
	}
	sortedFqdns := make([]string, 0, len(fqdnsSet))
	for name := range fqdnsSet {
		sortedFqdns = append(sortedFqdns, name)
	}
	sort.Strings(sortedFqdns)
	list := make([]any, 0, len(sortedFqdns))
	for _, name := range sortedFqdns {
		list = append(list, name)
	}
	return map[string]any{"fqdns": list}, nil
}

// Extend registration with this batch.
func init() {
	prev := extraRegister
	extraRegister = func(reg *runtime.ExecRegistry) error {
		if prev != nil {
			if err := prev(reg); err != nil {
				return err
			}
		}
		for _, fn := range []runtime.ExecFunction{
			netstatFunc{},
			ipNeighsFunc{},
			ipNeighs6Func{},
			getHostnameFunc{},
			getFqdnFunc{},
			modHostnameFunc{},
			connectFunc{},
			getBufsizeFunc{},
			modBufsizeFunc{},
			ipNetworksFunc{},
			ipNetworks6Func{},
			ifacestartswithFunc{},
			fqdnsFunc{},
		} {
			if err := reg.Register(fn); err != nil {
				return err
			}
		}
		return nil
	}
}
