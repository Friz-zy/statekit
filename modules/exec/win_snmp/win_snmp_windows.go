//go:build windows

// Package win_snmp implements Salt's Windows SNMP configuration module through
// encoded PowerShell registry cmdlets. It intentionally manages service keys,
// not SNMP network protocol traffic.
package win_snmp

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

const snmpKey = `HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters`
const agentKey = snmpKey + `\RFC1156Agent`
const communitiesKey = snmpKey + `\ValidCommunities`
const gpoCommunitiesKey = `HKLM:\SOFTWARE\Policies\SNMP\Parameters\ValidCommunities`

var snmpServiceTypes = map[string]int{"None": 0, "Physical": 1, "Datalink and subnetwork": 2, "Internet": 4, "End-to-end": 8, "Applications": 64}
var snmpPermissionTypes = map[string]int{"None": 1, "Notify": 2, "Read Only": 4, "Read Write": 8, "Read Create": 16}
var snmpServiceOrder = []string{"None", "Physical", "Datalink and subnetwork", "Internet", "End-to-end", "Applications"}
var snmpPermissionOrder = []string{"None", "Notify", "Read Only", "Read Write", "Read Create"}

func snmpLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
func snmpPS(script string) process.Command {
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
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], u)
	}
	return process.Command{Name: "powershell.exe", Args: []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw)}}
}
func snmpRun(ctx context.Context, rt *runtime.Runtime, script string) (string, error) {
	r := rt.Runner.Run(ctx, snmpPS(script))
	if r.Err != nil && r.ExitCode == -1 {
		return string(r.Stdout), r.Err
	}
	if r.ExitCode != 0 {
		return string(r.Stdout), fmt.Errorf("SNMP registry command failed (exit code %d): %s", r.ExitCode, strings.TrimSpace(string(r.Stderr)))
	}
	return string(r.Stdout), nil
}
func snmpJSON(ctx context.Context, rt *runtime.Runtime, script string) (any, error) {
	out, e := snmpRun(ctx, rt, script+" | ConvertTo-Json -Compress -Depth 4")
	if e != nil {
		return nil, e
	}
	if strings.TrimSpace(out) == "" || strings.TrimSpace(out) == "null" {
		return nil, nil
	}
	var v any
	if e = json.Unmarshal([]byte(out), &v); e != nil {
		return nil, e
	}
	return v, nil
}
func snmpMap(value any) map[string]any {
	if m, ok := value.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}
func snmpBitmask(value any) int {
	switch x := value.(type) {
	case float64:
		return int(x)
	case int:
		return x
	default:
		n := 0
		fmt.Sscanf(fmt.Sprint(x), "%d", &n)
		return n
	}
}
func snmpServices(mask int) []string {
	out := []string{}
	for name, bit := range snmpServiceTypes {
		if bit == 0 {
			continue
		}
		if mask&bit != 0 {
			out = append(out, name)
		}
	}
	if mask == 0 {
		out = []string{"None"}
	}
	sortSNMP(out)
	return out
}
func sortSNMP(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
func snmpRegistryValue(value any) string {
	switch x := value.(type) {
	case string:
		return snmpLiteral(x)
	case bool:
		if x {
			return "$true"
		}
		return "$false"
	default:
		return fmt.Sprint(snmpBitmask(x))
	}
}

// ---------------------------------------------------------------------------

type noArgs struct{}
type setAgentArgs struct {
	Contact  *string  `statekit:"name=contact"`
	Location *string  `statekit:"name=location"`
	Services []string `statekit:"name=services"`
}
type getAgentServiceTypesFunc struct{}

func (getAgentServiceTypesFunc) Name() string        { return "win_snmp.get_agent_service_types" }
func (getAgentServiceTypesFunc) Args() any           { return noArgs{} }
func (getAgentServiceTypesFunc) Platforms() []string { return []string{"windows"} }
func (getAgentServiceTypesFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return append([]string(nil), snmpServiceOrder...), nil
}

type getPermissionTypesFunc struct{}

func (getPermissionTypesFunc) Name() string        { return "win_snmp.get_permission_types" }
func (getPermissionTypesFunc) Args() any           { return noArgs{} }
func (getPermissionTypesFunc) Platforms() []string { return []string{"windows"} }
func (getPermissionTypesFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return append([]string(nil), snmpPermissionOrder...), nil
}

type getAgentSettingsFunc struct{}

func (getAgentSettingsFunc) Name() string        { return "win_snmp.get_agent_settings" }
func (getAgentSettingsFunc) Args() any           { return noArgs{} }
func (getAgentSettingsFunc) Platforms() []string { return []string{"windows"} }
func (getAgentSettingsFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverSNMP(&res, &err)
	value, e := snmpJSON(ctx, rt, "$p=Get-ItemProperty -Path "+snmpLiteral(agentKey)+" -ErrorAction SilentlyContinue;[ordered]@{contact=$p.sysContact;location=$p.sysLocation;services=$p.sysServices}")
	if e != nil {
		return nil, e
	}
	m := snmpMap(value)
	return map[string]any{"contact": m["contact"], "location": m["location"], "services": snmpServices(snmpBitmask(m["services"]))}, nil
}

type setAgentSettingsFunc struct{}

func (setAgentSettingsFunc) Name() string        { return "win_snmp.set_agent_settings" }
func (setAgentSettingsFunc) Args() any           { return setAgentArgs{} }
func (setAgentSettingsFunc) Platforms() []string { return []string{"windows"} }
func (setAgentSettingsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSNMP(&res, &err)
	a := args.(*setAgentArgs)
	if a.Services != nil {
		seen := map[string]bool{}
		services := []string{}
		for _, name := range a.Services {
			if _, ok := snmpServiceTypes[name]; !ok {
				return nil, fmt.Errorf("Invalid service '%s' specified", name)
			}
			if !seen[name] {
				seen[name] = true
				services = append(services, name)
			}
		}
		a.Services = services
	}
	script := ""
	if a.Contact != nil {
		script = "Set-ItemProperty -Path " + snmpLiteral(agentKey) + " -Name sysContact -Value " + snmpLiteral(*a.Contact) + ";"
	}
	if a.Location != nil {
		script += "Set-ItemProperty -Path " + snmpLiteral(agentKey) + " -Name sysLocation -Value " + snmpLiteral(*a.Location) + ";"
	}
	if a.Services != nil {
		mask := 0
		for _, name := range a.Services {
			mask += snmpServiceTypes[name]
		}
		script += fmt.Sprintf("Set-ItemProperty -Path %s -Name sysServices -Value %d -Type DWord;", snmpLiteral(agentKey), mask)
	}
	if script == "" {
		return true, nil
	}
	_, e := snmpRun(ctx, rt, script)
	return e == nil, e
}

type getAuthTrapsFunc struct{}

func (getAuthTrapsFunc) Name() string        { return "win_snmp.get_auth_traps_enabled" }
func (getAuthTrapsFunc) Args() any           { return noArgs{} }
func (getAuthTrapsFunc) Platforms() []string { return []string{"windows"} }
func (getAuthTrapsFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverSNMP(&res, &err)
	value, e := snmpJSON(ctx, rt, "(Get-ItemProperty -Path "+snmpLiteral(snmpKey)+" -Name EnableAuthenticationTraps -ErrorAction SilentlyContinue).EnableAuthenticationTraps")
	if e != nil {
		return nil, e
	}
	return snmpBitmask(value) != 0, nil
}

type setAuthTrapsArgs struct {
	Status *bool `statekit:"name=status"`
}
type setAuthTrapsFunc struct{}

func (setAuthTrapsFunc) Name() string        { return "win_snmp.set_auth_traps_enabled" }
func (setAuthTrapsFunc) Args() any           { return setAuthTrapsArgs{} }
func (setAuthTrapsFunc) Platforms() []string { return []string{"windows"} }
func (setAuthTrapsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*setAuthTrapsArgs)
	enabled := true
	if a.Status != nil {
		enabled = *a.Status
	}
	return snmpMutation(ctx, rt, fmt.Sprintf("Set-ItemProperty -Path %s -Name EnableAuthenticationTraps -Value %d -Type DWord", snmpLiteral(snmpKey), boolIntSNMP(enabled)))
}
func boolIntSNMP(value bool) int {
	if value {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// communities

type getCommunityNamesFunc struct{}

func (getCommunityNamesFunc) Name() string        { return "win_snmp.get_community_names" }
func (getCommunityNamesFunc) Args() any           { return noArgs{} }
func (getCommunityNamesFunc) Platforms() []string { return []string{"windows"} }
func (getCommunityNamesFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverSNMP(&res, &err)
	gpo, err := snmpJSON(ctx, rt, "if(Test-Path "+snmpLiteral(gpoCommunitiesKey)+"){$p=Get-ItemProperty -Path "+snmpLiteral(gpoCommunitiesKey)+";[ordered]@{present=$true;values=$p}}else{[ordered]@{present=$false}}")
	if err != nil {
		return nil, err
	}
	gm := snmpMap(gpo)
	if gm["present"] == true {
		out := map[string]string{}
		for key, value := range snmpMap(gm["values"]) {
			if strings.HasPrefix(key, "PS") || key == "PSDrive" || key == "Provider" {
				continue
			}
			out[fmt.Sprint(value)] = "Managed by GPO"
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	value, e := snmpJSON(ctx, rt, "$p=Get-ItemProperty -Path "+snmpLiteral(communitiesKey)+" -ErrorAction SilentlyContinue;[ordered]@{values=$p}")
	if e != nil {
		return nil, e
	}
	m := snmpMap(snmpMap(value)["values"])
	out := map[string]string{}
	for key, raw := range m {
		if strings.HasPrefix(key, "PS") || key == "PSDrive" || key == "Provider" {
			continue
		}
		for name, bit := range snmpPermissionTypes {
			if snmpBitmask(raw) == bit {
				out[key] = name
				break
			}
		}
	}
	return out, nil
}

type setCommunityArgs struct {
	Communities map[string]string `statekit:"required,name=communities"`
}
type setCommunityFunc struct{}

func (setCommunityFunc) Name() string        { return "win_snmp.set_community_names" }
func (setCommunityFunc) Args() any           { return setCommunityArgs{} }
func (setCommunityFunc) Platforms() []string { return []string{"windows"} }
func (setCommunityFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*setCommunityArgs)
	for _, permission := range a.Communities {
		if permission != "" {
			if _, ok := snmpPermissionTypes[permission]; !ok {
				return nil, fmt.Errorf("Invalid permission '%s' specified", permission)
			}
		}
	}
	present, e := snmpJSON(ctx, rt, "Test-Path "+snmpLiteral(gpoCommunitiesKey))
	if e != nil {
		return nil, e
	}
	if present == true {
		return nil, fmt.Errorf("Communities on this system are managed by Group Policy")
	}
	for name, permission := range a.Communities {
		if permission == "" {
			permission = "None"
		}
		script := fmt.Sprintf("New-Item -Path %s -Force | Out-Null;Set-ItemProperty -Path %s -Name %s -Value %d -Type DWord", snmpLiteral(communitiesKey), snmpLiteral(communitiesKey), snmpLiteral(name), snmpPermissionTypes[permission])
		if _, e := snmpRun(ctx, rt, script); e != nil {
			return false, e
		}
	}
	return true, nil
}
func snmpMutation(ctx context.Context, rt *runtime.Runtime, script string) (bool, error) {
	_, e := snmpRun(ctx, rt, script)
	return e == nil, e
}
func recoverSNMP(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{getAgentServiceTypesFunc{}, getPermissionTypesFunc{}, getAgentSettingsFunc{}, setAgentSettingsFunc{}, getAuthTrapsFunc{}, setAuthTrapsFunc{}, getCommunityNamesFunc{}, setCommunityFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
