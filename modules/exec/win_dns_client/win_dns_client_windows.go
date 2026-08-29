//go:build windows

// Package win_dns_client implements Salt's Windows DNS client module through
// netsh and encoded PowerShell NetTCPIP queries.
package win_dns_client

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func dnsInterface(value string) string { return strings.ReplaceAll(value, `\`, "") }

func dnsPS(script string) process.Command {
	units := make([]uint16, 0, len(script)+1)
	for _, r := range script + "\x00" {
		if r <= 0xffff {
			units = append(units, uint16(r))
		} else {
			r -= 0x10000
			units = append(units, uint16(0xd800+(r>>10)), uint16(0xdc00+(r&0x3ff)))
		}
	}
	raw := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], unit)
	}
	return process.Command{Name: "powershell.exe", Args: []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw)}}
}
func dnsPSLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
func dnsRun(ctx context.Context, rt *runtime.Runtime, argv ...string) process.CommandResult {
	return rt.Runner.Run(ctx, runtime.Command(argv...))
}
func dnsJSON(ctx context.Context, rt *runtime.Runtime, script string) (any, error) {
	r := rt.Runner.Run(ctx, dnsPS(script))
	if r.Err != nil && r.ExitCode == -1 {
		return nil, r.Err
	}
	if r.ExitCode != 0 {
		return nil, fmt.Errorf("PowerShell DNS query failed (exit code %d): %s", r.ExitCode, strings.TrimSpace(string(r.Stderr)))
	}
	if strings.TrimSpace(string(r.Stdout)) == "" || strings.TrimSpace(string(r.Stdout)) == "null" {
		return nil, nil
	}
	var v any
	if e := json.Unmarshal(r.Stdout, &v); e != nil {
		return nil, e
	}
	return v, nil
}
func dnsServers(ctx context.Context, rt *runtime.Runtime, interfaceName string) (any, error) {
	script := "@(Get-DnsClientServerAddress -InterfaceAlias " + dnsPSLiteral(interfaceName) + " -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses) | ConvertTo-Json -Compress"
	v, e := dnsJSON(ctx, rt, script)
	if e != nil {
		return false, e
	}
	if v == nil {
		return false, nil
	}
	switch x := v.(type) {
	case []any:
		out := []string{}
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out, nil
	case string:
		return []string{x}, nil
	default:
		return []string{}, nil
	}
}
func dnsSuccess(ctx context.Context, rt *runtime.Runtime, argv ...string) bool {
	r := dnsRun(ctx, rt, argv...)
	return r.Err == nil && r.ExitCode == 0
}

// ---------------------------------------------------------------------------

type getDNSServersArgs struct {
	Interface string `statekit:"name=interface"`
}
type getDNSServersFunc struct{}

func (getDNSServersFunc) Name() string        { return "win_dns_client.get_dns_servers" }
func (getDNSServersFunc) Args() any           { return getDNSServersArgs{} }
func (getDNSServersFunc) Platforms() []string { return []string{"windows"} }
func (getDNSServersFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverDNS(&res, &err)
	a := args.(*getDNSServersArgs)
	name := a.Interface
	if name == "" {
		name = "Local Area Connection"
	}
	return dnsServers(ctx, rt, dnsInterface(name))
}

type rmDNSArgs struct {
	IP        string `statekit:"required,name=ip"`
	Interface string `statekit:"name=interface"`
}
type rmDNSFunc struct{}

func (rmDNSFunc) Name() string        { return "win_dns_client.rm_dns" }
func (rmDNSFunc) Args() any           { return rmDNSArgs{} }
func (rmDNSFunc) Platforms() []string { return []string{"windows"} }
func (rmDNSFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*rmDNSArgs)
	name := a.Interface
	if name == "" {
		name = "Local Area Connection"
	}
	return dnsSuccess(ctx, rt, "netsh", "interface", "ip", "delete", "dns", dnsInterface(name), a.IP, "validate=no"), nil
}

type addDNSArgs struct {
	IP        string `statekit:"required,name=ip"`
	Interface string `statekit:"name=interface"`
	Index     *int   `statekit:"name=index"`
}
type addDNSFunc struct{}

func (addDNSFunc) Name() string        { return "win_dns_client.add_dns" }
func (addDNSFunc) Args() any           { return addDNSArgs{} }
func (addDNSFunc) Platforms() []string { return []string{"windows"} }
func (addDNSFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverDNS(&res, &err)
	a := args.(*addDNSArgs)
	name := a.Interface
	if name == "" {
		name = "Local Area Connection"
	}
	index := 1
	if a.Index != nil {
		index = *a.Index
	}
	servers, e := dnsServers(ctx, rt, dnsInterface(name))
	if e != nil {
		return nil, e
	}
	if servers == false {
		return false, nil
	}
	if values, ok := servers.([]string); ok {
		if index > 0 && index <= len(values) && values[index-1] == a.IP {
			return true, nil
		}
		for _, value := range values {
			if value == a.IP {
				_ = dnsSuccess(ctx, rt, "netsh", "interface", "ip", "delete", "dns", dnsInterface(name), a.IP, "validate=no")
			}
		}
	}
	return dnsSuccess(ctx, rt, "netsh", "interface", "ip", "add", "dns", dnsInterface(name), a.IP, fmt.Sprintf("index=%d", index), "validate=no"), nil
}

type dnsDHCPArgs struct {
	Interface string `statekit:"name=interface"`
}
type dnsDHCPFunc struct{}

func (dnsDHCPFunc) Name() string        { return "win_dns_client.dns_dhcp" }
func (dnsDHCPFunc) Args() any           { return dnsDHCPArgs{} }
func (dnsDHCPFunc) Platforms() []string { return []string{"windows"} }
func (dnsDHCPFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*dnsDHCPArgs)
	name := a.Interface
	if name == "" {
		name = "Local Area Connection"
	}
	return dnsSuccess(ctx, rt, "netsh", "interface", "ip", "set", "dns", dnsInterface(name), "source=dhcp"), nil
}

type getDNSConfigArgs struct {
	Interface string `statekit:"name=interface"`
}
type getDNSConfigFunc struct{}

func (getDNSConfigFunc) Name() string        { return "win_dns_client.get_dns_config" }
func (getDNSConfigFunc) Args() any           { return getDNSConfigArgs{} }
func (getDNSConfigFunc) Platforms() []string { return []string{"windows"} }
func (getDNSConfigFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverDNS(&res, &err)
	a := args.(*getDNSConfigArgs)
	name := a.Interface
	if name == "" {
		name = "Local Area Connection"
	}
	script := "Get-NetIPInterface -InterfaceAlias " + dnsPSLiteral(dnsInterface(name)) + " -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Dhcp | ConvertTo-Json -Compress"
	value, e := dnsJSON(ctx, rt, script)
	if e != nil {
		return nil, e
	}
	if value == nil {
		return nil, nil
	}
	return value, nil
}

func recoverDNS(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}

// Register installs the Windows DNS client functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{getDNSServersFunc{}, rmDNSFunc{}, addDNSFunc{}, dnsDHCPFunc{}, getDNSConfigFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
