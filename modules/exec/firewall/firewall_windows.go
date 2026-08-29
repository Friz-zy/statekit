//go:build windows

// Package firewall implements Salt's Windows firewall module through netsh and
// the NetSecurity PowerShell cmdlets. All commands run through the central
// Runner and structured settings remain JSON so localization does not alter
// field semantics.
package firewall

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func psFirewall(script string) process.Command {
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
func psFirewallLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func runFirewall(ctx context.Context, rt *runtime.Runtime, argv ...string) process.CommandResult {
	return rt.Runner.Run(ctx, runtime.Command(argv...))
}
func runFirewallPS(ctx context.Context, rt *runtime.Runtime, script string) (string, error) {
	result := rt.Runner.Run(ctx, psFirewall(script))
	if result.Err != nil && result.ExitCode == -1 {
		return string(result.Stdout), result.Err
	}
	if result.ExitCode != 0 {
		return string(result.Stdout), fmt.Errorf("PowerShell command failed (exit code %d): %s", result.ExitCode, strings.TrimSpace(string(result.Stderr)))
	}
	return string(result.Stdout), nil
}
func runFirewallJSON(ctx context.Context, rt *runtime.Runtime, script string) (any, error) {
	out, e := runFirewallPS(ctx, rt, script)
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
func firewallSuccess(ctx context.Context, rt *runtime.Runtime, argv ...string) error {
	result := runFirewall(ctx, rt, argv...)
	if result.Err != nil && result.ExitCode == -1 {
		return result.Err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("%s", strings.TrimSpace(string(result.Stdout)))
	}
	return nil
}

func profileName(value string) bool {
	switch strings.ToLower(value) {
	case "allprofiles", "domainprofile", "privateprofile", "publicprofile", "domain", "private", "public":
		return true
	}
	return false
}
func sectionName(value string) bool {
	switch strings.ToLower(value) {
	case "state", "firewallpolicy", "logging", "settings":
		return true
	}
	return false
}
func storeName(value string) bool {
	return strings.EqualFold(value, "local") || strings.EqualFold(value, "lgpo")
}

func parseProfileOutput(output string) map[string]bool {
	out := map[string]bool{}
	current := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if strings.HasSuffix(line, " Profile Settings:") {
			current = strings.TrimSuffix(line, " Profile Settings:")
			continue
		}
		if current != "" && strings.HasPrefix(strings.ToLower(line), "state") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				out[current] = strings.EqualFold(fields[1], "ON")
			}
			current = ""
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// profile/rule functions

type getConfigArgs struct{}
type getConfigFunc struct{}

func (getConfigFunc) Name() string        { return "firewall.get_config" }
func (getConfigFunc) Args() any           { return getConfigArgs{} }
func (getConfigFunc) Platforms() []string { return []string{"windows"} }
func (getConfigFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverFirewall(&res, &err)
	result := runFirewall(ctx, rt, "netsh", "advfirewall", "show", "allprofiles")
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("%s", result.Stdout)
	}
	return parseProfileOutput(string(result.Stdout)), nil
}

type profileArgs struct {
	Profile string `statekit:"name=profile"`
}
type disableFunc struct{}
type enableFunc struct{}

func (disableFunc) Name() string        { return "firewall.disable" }
func (disableFunc) Args() any           { return profileArgs{} }
func (disableFunc) Platforms() []string { return []string{"windows"} }
func (disableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*profileArgs)
	if a.Profile == "" {
		a.Profile = "allprofiles"
	}
	if !profileName(a.Profile) {
		return nil, fmt.Errorf("Invalid profile: %s", a.Profile)
	}
	if e := firewallSuccess(ctx, rt, "netsh", "advfirewall", "set", a.Profile, "state", "off"); e != nil {
		return nil, e
	}
	return true, nil
}
func (enableFunc) Name() string        { return "firewall.enable" }
func (enableFunc) Args() any           { return profileArgs{} }
func (enableFunc) Platforms() []string { return []string{"windows"} }
func (enableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*profileArgs)
	if a.Profile == "" {
		a.Profile = "allprofiles"
	}
	if !profileName(a.Profile) {
		return nil, fmt.Errorf("Invalid profile: %s", a.Profile)
	}
	if e := firewallSuccess(ctx, rt, "netsh", "advfirewall", "set", a.Profile, "state", "on"); e != nil {
		return nil, e
	}
	return true, nil
}

type getRuleArgs struct {
	Name string `statekit:"name=name"`
}
type getRuleFunc struct{}

func (getRuleFunc) Name() string        { return "firewall.get_rule" }
func (getRuleFunc) Args() any           { return getRuleArgs{} }
func (getRuleFunc) Platforms() []string { return []string{"windows"} }
func (getRuleFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverFirewall(&res, &err)
	a := args.(*getRuleArgs)
	if a.Name == "" {
		a.Name = "all"
	}
	result := runFirewall(ctx, rt, "netsh", "advfirewall", "firewall", "show", "rule", "name="+a.Name)
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("%s", result.Stdout)
	}
	return map[string]string{a.Name: string(result.Stdout)}, nil
}

type addRuleArgs struct {
	Name      string  `statekit:"required"`
	LocalPort string  `statekit:"required,name=localport"`
	Protocol  *string `statekit:"name=protocol"`
	Action    *string `statekit:"name=action"`
	Dir       *string `statekit:"name=dir"`
	RemoteIP  *string `statekit:"name=remoteip"`
}
type addRuleFunc struct{}

func (addRuleFunc) Name() string        { return "firewall.add_rule" }
func (addRuleFunc) Args() any           { return addRuleArgs{} }
func (addRuleFunc) Platforms() []string { return []string{"windows"} }
func (addRuleFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverFirewall(&res, &err)
	a := args.(*addRuleArgs)
	protocol := "tcp"
	if a.Protocol != nil {
		protocol = *a.Protocol
	}
	action := "allow"
	if a.Action != nil {
		action = *a.Action
	}
	direction := "in"
	if a.Dir != nil {
		direction = *a.Dir
	}
	remote := "any"
	if a.RemoteIP != nil {
		remote = *a.RemoteIP
	}
	argv := []string{"netsh", "advfirewall", "firewall", "add", "rule", "name=" + a.Name, "protocol=" + protocol, "dir=" + direction, "action=" + action, "remoteip=" + remote}
	if !strings.Contains(protocol, "icmpv4") && !strings.Contains(protocol, "icmpv6") {
		argv = append(argv, "localport="+a.LocalPort)
	}
	result := runFirewall(ctx, rt, argv...)
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("%s", result.Stdout)
	}
	return true, nil
}

type deleteRuleArgs struct {
	Name      *string `statekit:"name=name"`
	LocalPort *string `statekit:"name=localport"`
	Protocol  *string `statekit:"name=protocol"`
	Dir       *string `statekit:"name=dir"`
	RemoteIP  *string `statekit:"name=remoteip"`
}
type deleteRuleFunc struct{}

func (deleteRuleFunc) Name() string        { return "firewall.delete_rule" }
func (deleteRuleFunc) Args() any           { return deleteRuleArgs{} }
func (deleteRuleFunc) Platforms() []string { return []string{"windows"} }
func (deleteRuleFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverFirewall(&res, &err)
	a := args.(*deleteRuleArgs)
	argv := []string{"netsh", "advfirewall", "firewall", "delete", "rule"}
	if a.Name != nil && *a.Name != "" {
		argv = append(argv, "name="+*a.Name)
	}
	if a.Protocol != nil && *a.Protocol != "" {
		argv = append(argv, "protocol="+*a.Protocol)
	}
	if a.Dir != nil && *a.Dir != "" {
		argv = append(argv, "dir="+*a.Dir)
	}
	if a.RemoteIP != nil && *a.RemoteIP != "" {
		argv = append(argv, "remoteip="+*a.RemoteIP)
	}
	if a.LocalPort != nil && *a.LocalPort != "" {
		if a.Protocol == nil || *a.Protocol == "" {
			argv = append(argv, "protocol=tcp")
		}
		argv = append(argv, "localport="+*a.LocalPort)
	}
	result := runFirewall(ctx, rt, argv...)
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("%s", result.Stdout)
	}
	return true, nil
}

type ruleExistsArgs struct {
	Name string `statekit:"required"`
}
type ruleExistsFunc struct{}

func (ruleExistsFunc) Name() string        { return "firewall.rule_exists" }
func (ruleExistsFunc) Args() any           { return ruleExistsArgs{} }
func (ruleExistsFunc) Platforms() []string { return []string{"windows"} }
func (ruleExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ruleExistsArgs)
	v, e := getRuleFunc{}.Execute(ctx, rt, &getRuleArgs{Name: a.Name})
	return e == nil && v != nil, nil
}

// ---------------------------------------------------------------------------
// NetSecurity settings

func getFirewallProfile(ctx context.Context, rt *runtime.Runtime, profile, store string) (map[string]any, error) {
	if !profileName(profile) || strings.EqualFold(profile, "allprofiles") {
		return nil, fmt.Errorf("Incorrect profile: %s", profile)
	}
	if !storeName(store) {
		return nil, fmt.Errorf("Incorrect store: %s", store)
	}
	script := "$p=Get-NetFirewallProfile -Name " + psFirewallLiteral(profile)
	if strings.EqualFold(store, "lgpo") {
		script += " -PolicyStore 'localhost'"
	}
	script += "|Select-Object *|ConvertTo-Json -Compress"
	value, e := runFirewallJSON(ctx, rt, script)
	if e != nil {
		return nil, e
	}
	raw, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("LGPO NETSH: An unknown error occurred")
	}
	return raw, nil
}
func firewallSection(raw map[string]any, section string) map[string]any {
	get := func(key string) any { return raw[key] }
	switch strings.ToLower(section) {
	case "state":
		return map[string]any{"State": map[bool]string{true: "ON", false: "OFF"}[boolValueFirewall(get("Enabled"))]}
	case "firewallpolicy":
		return map[string]any{"Inbound": inboundTextFirewall(get("AllowInboundRules"), get("DefaultInboundAction")), "Outbound": outboundTextFirewall(get("DefaultOutboundAction"))}
	case "logging":
		return map[string]any{"FileName": get("LogFileName"), "LogAllowedConnections": enableTextFirewall(get("LogAllowed")), "LogDroppedConnections": enableTextFirewall(get("LogBlocked")), "MaxFileSize": get("LogMaxSizeKilobytes")}
	default:
		return map[string]any{"InboundUserNotification": enableTextFirewall(get("NotifyOnListen")), "LocalConSecRules": enableTextFirewall(get("AllowLocalIPsecRules")), "LocalFirewallRules": enableTextFirewall(get("AllowLocalFirewallRules")), "UnicastResponseToMulticast": enableTextFirewall(get("AllowUnicastResponseToMulticast"))}
	}
}
func intValueFirewall(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	default:
		n, _ := strconv.Atoi(fmt.Sprint(x))
		return n
	}
}
func boolValueFirewall(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case int:
		return x != 0
	default:
		return strings.EqualFold(fmt.Sprint(x), "true")
	}
}
func inboundTextFirewall(rule, action any) string {
	r, a := intValueFirewall(rule), intValueFirewall(action)
	if r == 0 && a == 4 {
		return "BlockInboundAlways"
	}
	if a == 0 {
		return "NotConfigured"
	}
	if a == 2 {
		return "AllowInbound"
	}
	return "BlockInbound"
}
func outboundTextFirewall(v any) string {
	switch intValueFirewall(v) {
	case 2:
		return "AllowOutbound"
	case 4:
		return "BlockOutbound"
	default:
		return "NotConfigured"
	}
}
func enableTextFirewall(v any) string {
	if boolValueFirewall(v) {
		return "Enable"
	}
	return "Disable"
}

type getSettingsArgs struct {
	Profile string  `statekit:"required"`
	Section string  `statekit:"required"`
	Store   *string `statekit:"name=store"`
}
type getSettingsFunc struct{}

func (getSettingsFunc) Name() string        { return "firewall.get_settings" }
func (getSettingsFunc) Args() any           { return getSettingsArgs{} }
func (getSettingsFunc) Platforms() []string { return []string{"windows"} }
func (getSettingsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverFirewall(&res, &err)
	a := args.(*getSettingsArgs)
	store := "local"
	if a.Store != nil {
		store = *a.Store
	}
	if !sectionName(a.Section) {
		return nil, fmt.Errorf("Incorrect section: %s", a.Section)
	}
	raw, e := getFirewallProfile(ctx, rt, a.Profile, store)
	if e != nil {
		return nil, e
	}
	return firewallSection(raw, a.Section), nil
}

type getAllSettingsArgs struct {
	Domain string  `statekit:"required"`
	Store  *string `statekit:"name=store"`
}
type getAllSettingsFunc struct{}

func (getAllSettingsFunc) Name() string        { return "firewall.get_all_settings" }
func (getAllSettingsFunc) Args() any           { return getAllSettingsArgs{} }
func (getAllSettingsFunc) Platforms() []string { return []string{"windows"} }
func (getAllSettingsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverFirewall(&res, &err)
	a := args.(*getAllSettingsArgs)
	store := "local"
	if a.Store != nil {
		store = *a.Store
	}
	raw, e := getFirewallProfile(ctx, rt, a.Domain, store)
	if e != nil {
		return nil, e
	}
	out := firewallSection(raw, "state")
	for k, v := range firewallSection(raw, "firewallpolicy") {
		out[k] = v
	}
	for k, v := range firewallSection(raw, "logging") {
		out[k] = v
	}
	for k, v := range firewallSection(raw, "settings") {
		out[k] = v
	}
	return out, nil
}

type getAllProfilesArgs struct {
	Store *string `statekit:"name=store"`
}
type getAllProfilesFunc struct{}

func (getAllProfilesFunc) Name() string        { return "firewall.get_all_profiles" }
func (getAllProfilesFunc) Args() any           { return getAllProfilesArgs{} }
func (getAllProfilesFunc) Platforms() []string { return []string{"windows"} }
func (getAllProfilesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverFirewall(&res, &err)
	a := args.(*getAllProfilesArgs)
	store := "local"
	if a.Store != nil {
		store = *a.Store
	}
	out := map[string]any{}
	for name, label := range map[string]string{"domain": "Domain Profile", "private": "Private Profile", "public": "Public Profile"} {
		v, e := getAllSettingsFunc{}.Execute(ctx, rt, &getAllSettingsArgs{Domain: name, Store: &store})
		if e != nil {
			return nil, e
		}
		out[label] = v
	}
	return out, nil
}

func settingStoreArgs(profile, setting, value, store string) (string, error) {
	if !profileName(profile) || strings.EqualFold(profile, "allprofiles") {
		return "", fmt.Errorf("Incorrect profile: %s", profile)
	}
	if !storeName(store) {
		return "", fmt.Errorf("Incorrect store: %s", store)
	}
	return "$p=@{Profile=" + psFirewallLiteral(profile) + "};", nil
}
func setFirewallPS(ctx context.Context, rt *runtime.Runtime, profile, store string, params string) error {
	script := "$p=@{Name=" + psFirewallLiteral(profile) + "};" + params + "Set-NetFirewallProfile @p"
	if strings.EqualFold(store, "lgpo") {
		script = "$p=@{PolicyStore='localhost';Name=" + psFirewallLiteral(profile) + "};" + params + "Set-NetFirewallProfile @p"
	}
	_, e := runFirewallPS(ctx, rt, script)
	return e
}

type setFirewallSettingsArgs struct {
	Profile  string  `statekit:"required"`
	Inbound  *string `statekit:"name=inbound"`
	Outbound *string `statekit:"name=outbound"`
	Store    *string `statekit:"name=store"`
}
type setFirewallSettingsFunc struct{}

func (setFirewallSettingsFunc) Name() string        { return "firewall.set_firewall_settings" }
func (setFirewallSettingsFunc) Args() any           { return setFirewallSettingsArgs{} }
func (setFirewallSettingsFunc) Platforms() []string { return []string{"windows"} }
func (setFirewallSettingsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverFirewall(&res, &err)
	a := args.(*setFirewallSettingsArgs)
	store := "local"
	if a.Store != nil {
		store = *a.Store
	}
	if a.Inbound == nil && a.Outbound == nil {
		return nil, fmt.Errorf("Must set inbound or outbound")
	}
	params := ""
	if a.Inbound != nil {
		switch strings.ToLower(*a.Inbound) {
		case "allowinbound":
			params += "$p.AllowInboundRules='NotConfigured';$p.DefaultInboundAction='Allow';"
		case "blockinbound", "blockinboundalways":
			params += "$p.DefaultInboundAction='Block';"
		case "notconfigured":
			if store == "local" {
				return nil, fmt.Errorf("Cannot set local inbound policies as NotConfigured")
			}
		default:
			return nil, fmt.Errorf("Incorrect inbound value: %s", *a.Inbound)
		}
	}
	if a.Outbound != nil {
		switch strings.ToLower(*a.Outbound) {
		case "allowoutbound":
			params += "$p.DefaultOutboundAction='Allow';"
		case "blockoutbound":
			params += "$p.DefaultOutboundAction='Block';"
		case "notconfigured":
			if store == "local" {
				return nil, fmt.Errorf("Cannot set local outbound policies as NotConfigured")
			}
		default:
			return nil, fmt.Errorf("Incorrect outbound value: %s", *a.Outbound)
		}
	}
	return true, setFirewallPS(ctx, rt, a.Profile, store, params)
}

type setLoggingSettingsArgs struct {
	Profile string  `statekit:"required"`
	Setting string  `statekit:"required"`
	Value   string  `statekit:"required"`
	Store   *string `statekit:"name=store"`
}
type setLoggingSettingsFunc struct{}

func (setLoggingSettingsFunc) Name() string        { return "firewall.set_logging_settings" }
func (setLoggingSettingsFunc) Args() any           { return setLoggingSettingsArgs{} }
func (setLoggingSettingsFunc) Platforms() []string { return []string{"windows"} }
func (setLoggingSettingsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverFirewall(&res, &err)
	a := args.(*setLoggingSettingsArgs)
	store := "local"
	if a.Store != nil {
		store = *a.Store
	}
	params := ""
	switch strings.ToLower(a.Setting) {
	case "allowedconnections":
		if !validEnableFirewall(a.Value) {
			return nil, fmt.Errorf("Incorrect value: %s", a.Value)
		}
		if strings.EqualFold(a.Value, "notconfigured") && store == "local" {
			return nil, fmt.Errorf("NotConfigured only valid when setting Group Policy")
		}
		params = fmt.Sprintf("$p.LogAllowed=%v;", strings.EqualFold(a.Value, "enable"))
	case "droppedconnections":
		if !validEnableFirewall(a.Value) {
			return nil, fmt.Errorf("Incorrect value: %s", a.Value)
		}
		if strings.EqualFold(a.Value, "notconfigured") && store == "local" {
			return nil, fmt.Errorf("NotConfigured only valid when setting Group Policy")
		}
		params = fmt.Sprintf("$p.LogBlocked=%v;", strings.EqualFold(a.Value, "enable"))
	case "filename":
		params = "$p.LogFileName=" + psFirewallLiteral(a.Value) + ";"
	case "maxfilesize":
		n, e := strconv.Atoi(a.Value)
		if strings.EqualFold(a.Value, "notconfigured") || e != nil || n < 1 || n > 32767 {
			return nil, fmt.Errorf("Incorrect value: %s", a.Value)
		}
		params = fmt.Sprintf("$p.LogMaxSizeKilobytes=%d;", n)
	default:
		return nil, fmt.Errorf("Incorrect setting: %s", a.Setting)
	}
	return true, setFirewallPS(ctx, rt, a.Profile, store, params)
}
func validEnableFirewall(v string) bool {
	v = strings.ToLower(v)
	return v == "enable" || v == "disable" || v == "notconfigured"
}

type setSettingsArgs struct {
	Profile string  `statekit:"required"`
	Setting string  `statekit:"required"`
	Value   string  `statekit:"required"`
	Store   *string `statekit:"name=store"`
}
type setSettingsFunc struct{}

func (setSettingsFunc) Name() string        { return "firewall.set_settings" }
func (setSettingsFunc) Args() any           { return setSettingsArgs{} }
func (setSettingsFunc) Platforms() []string { return []string{"windows"} }
func (setSettingsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverFirewall(&res, &err)
	a := args.(*setSettingsArgs)
	store := "local"
	if a.Store != nil {
		store = *a.Store
	}
	if !validEnableFirewall(a.Value) {
		return nil, fmt.Errorf("Incorrect value: %s", a.Value)
	}
	keys := map[string]string{"localfirewallrules": "AllowLocalFirewallRules", "localconsecrules": "AllowLocalIPsecRules", "inboundusernotification": "NotifyOnListen", "unicastresponsetomulticast": "AllowUnicastResponseToMulticast"}
	key, ok := keys[strings.ToLower(a.Setting)]
	if !ok {
		return nil, fmt.Errorf("Incorrect setting: %s", a.Setting)
	}
	if strings.EqualFold(a.Value, "notconfigured") && store == "local" {
		return nil, fmt.Errorf("NotConfigured is only valid when setting group policy")
	}
	params := fmt.Sprintf("$p.%s=%v;", key, strings.EqualFold(a.Value, "enable"))
	return true, setFirewallPS(ctx, rt, a.Profile, store, params)
}

type setStateArgs struct {
	Profile string  `statekit:"required"`
	State   string  `statekit:"required"`
	Store   *string `statekit:"name=store"`
}
type setStateFunc struct{}

func (setStateFunc) Name() string        { return "firewall.set_state" }
func (setStateFunc) Args() any           { return setStateArgs{} }
func (setStateFunc) Platforms() []string { return []string{"windows"} }
func (setStateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverFirewall(&res, &err)
	a := args.(*setStateArgs)
	state := strings.ToLower(a.State)
	if state != "on" && state != "off" && state != "notconfigured" {
		return nil, fmt.Errorf("Incorrect state: %s", a.State)
	}
	store := "local"
	if a.Store != nil {
		store = *a.Store
	}
	if state == "notconfigured" && store == "local" {
		return nil, fmt.Errorf("NotConfigured is only valid when setting group policy")
	}
	params := ""
	if state == "on" {
		params = "$p.Enabled=$true;"
	} else if state == "off" {
		params = "$p.Enabled=$false;"
	} else {
		params = "$p.Enabled='NotConfigured';"
	}
	return true, setFirewallPS(ctx, rt, a.Profile, store, params)
}

func recoverFirewall(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}

// Register installs Windows firewall functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{getConfigFunc{}, disableFunc{}, enableFunc{}, getRuleFunc{}, addRuleFunc{}, deleteRuleFunc{}, ruleExistsFunc{}, getSettingsFunc{}, getAllSettingsFunc{}, getAllProfilesFunc{}, setFirewallSettingsFunc{}, setLoggingSettingsFunc{}, setSettingsFunc{}, setStateFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
