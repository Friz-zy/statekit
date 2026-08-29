//go:build windows

// Package win_smtp_server implements Salt's legacy IIS SMTP module through
// the MicrosoftIISv2 CIM namespace. The WMI boundary is kept explicit because
// the SMTP service is optional and absent on modern client Windows editions.
package win_smtp_server

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

const defaultSMTPServer = "SmtpSvc/1"
const smtpNamespace = "root/MicrosoftIISv2"

func smtpLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
func smtpPS(script string) process.Command {
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
func smtpRun(ctx context.Context, rt *runtime.Runtime, script string) (string, error) {
	r := rt.Runner.Run(ctx, smtpPS(script))
	if r.Err != nil && r.ExitCode == -1 {
		return string(r.Stdout), r.Err
	}
	if r.ExitCode != 0 {
		return string(r.Stdout), fmt.Errorf("IIS SMTP CIM command failed (exit code %d): %s", r.ExitCode, strings.TrimSpace(string(r.Stderr)))
	}
	return string(r.Stdout), nil
}
func smtpJSON(ctx context.Context, rt *runtime.Runtime, script string) (any, error) {
	out, e := smtpRun(ctx, rt, script+" | ConvertTo-Json -Compress -Depth 6")
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
func smtpRows(value any) []map[string]any {
	switch x := value.(type) {
	case map[string]any:
		return []map[string]any{x}
	case []any:
		out := []map[string]any{}
		for _, v := range x {
			if row, ok := v.(map[string]any); ok {
				out = append(out, row)
			}
		}
		return out
	default:
		return []map[string]any{}
	}
}
func smtpServer(args *string) string {
	if args == nil || *args == "" {
		return defaultSMTPServer
	}
	return *args
}
func normalizeSMTP(value any) any {
	if m, ok := value.(map[string]any); ok {
		for key := range m {
			return "{" + key + "}"
		}
	}
	return value
}
func smtpValue(value any) string {
	value = normalizeSMTP(value)
	switch x := value.(type) {
	case string:
		return smtpLiteral(x)
	case bool:
		if x {
			return "$true"
		}
		return "$false"
	case []string:
		parts := make([]string, 0, len(x))
		for _, v := range x {
			parts = append(parts, smtpLiteral(v))
		}
		return "@(" + strings.Join(parts, ",") + ")"
	case []any:
		parts := make([]string, 0, len(x))
		for _, v := range x {
			parts = append(parts, smtpLiteral(fmt.Sprint(v)))
		}
		return "@(" + strings.Join(parts, ",") + ")"
	default:
		return smtpLiteral(fmt.Sprint(x))
	}
}
func setSMTPProperties(ctx context.Context, rt *runtime.Runtime, class, server string, settings map[string]any) error {
	parts := []string{}
	for key, value := range settings {
		parts = append(parts, key+"="+smtpValue(value))
	}
	script := "$p=@{" + strings.Join(parts, ";") + "};Get-CimInstance -Namespace " + smtpLiteral(smtpNamespace) + " -ClassName " + class + " -Filter \"Name='" + strings.ReplaceAll(server, "'", "''") + "'\" | Set-CimInstance -Property $p"
	_, e := smtpRun(ctx, rt, script)
	return e
}

// ---------------------------------------------------------------------------

type noArgs struct{}
type serverArg struct {
	Server *string `statekit:"name=server"`
}
type settingsArg struct {
	Settings []string `statekit:"required"`
	Server   *string  `statekit:"name=server"`
}
type getLogFormatTypesFunc struct{}

func (getLogFormatTypesFunc) Name() string        { return "win_smtp_server.get_log_format_types" }
func (getLogFormatTypesFunc) Args() any           { return noArgs{} }
func (getLogFormatTypesFunc) Platforms() []string { return []string{"windows"} }
func (getLogFormatTypesFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverSMTP(&res, &err)
	value, e := smtpJSON(ctx, rt, "@(Get-CimInstance -Namespace "+smtpLiteral(smtpNamespace)+" -ClassName IISLogModuleSetting)")
	if e != nil {
		return nil, e
	}
	out := map[string]string{}
	for _, row := range smtpRows(value) {
		name := strings.TrimPrefix(fmt.Sprint(row["Name"]), "logging/")
		if name != "" {
			out[name] = fmt.Sprint(row["LogModuleId"])
		}
	}
	return out, nil
}

type getServersFunc struct{}

func (getServersFunc) Name() string        { return "win_smtp_server.get_servers" }
func (getServersFunc) Args() any           { return noArgs{} }
func (getServersFunc) Platforms() []string { return []string{"windows"} }
func (getServersFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverSMTP(&res, &err)
	value, e := smtpJSON(ctx, rt, "@(Get-CimInstance -Namespace "+smtpLiteral(smtpNamespace)+" -ClassName IIsSmtpServerSetting | Select-Object Name)")
	if e != nil {
		return nil, e
	}
	out := []string{}
	for _, row := range smtpRows(value) {
		if name := fmt.Sprint(row["Name"]); name != "" {
			out = append(out, name)
		}
	}
	return out, nil
}

type getServerSettingFunc struct{}

func (getServerSettingFunc) Name() string        { return "win_smtp_server.get_server_setting" }
func (getServerSettingFunc) Args() any           { return settingsArg{} }
func (getServerSettingFunc) Platforms() []string { return []string{"windows"} }
func (getServerSettingFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSMTP(&res, &err)
	a := args.(*settingsArg)
	if len(a.Settings) == 0 {
		return map[string]string{}, nil
	}
	server := smtpServer(a.Server)
	selects := strings.Join(a.Settings, ",")
	value, e := smtpJSON(ctx, rt, "@(Get-CimInstance -Namespace "+smtpLiteral(smtpNamespace)+" -ClassName IIsSmtpServerSetting -Filter \"Name='"+strings.ReplaceAll(server, "'", "''")+"'\" | Select-Object "+selects+")")
	if e != nil {
		return nil, e
	}
	rows := smtpRows(value)
	out := map[string]string{}
	if len(rows) > 0 {
		for _, setting := range a.Settings {
			out[setting] = fmt.Sprint(rows[0][setting])
		}
	}
	return out, nil
}

type setServerSettingArgs struct {
	Settings map[string]any `statekit:"required"`
	Server   *string        `statekit:"name=server"`
}
type setServerSettingFunc struct{}

func (setServerSettingFunc) Name() string        { return "win_smtp_server.set_server_setting" }
func (setServerSettingFunc) Args() any           { return setServerSettingArgs{} }
func (setServerSettingFunc) Platforms() []string { return []string{"windows"} }
func (setServerSettingFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*setServerSettingArgs)
	if len(a.Settings) == 0 {
		return false, nil
	}
	server := smtpServer(a.Server)
	normalized := map[string]any{}
	for key, value := range a.Settings {
		normalized[key] = normalizeSMTP(value)
	}
	if e := setSMTPProperties(ctx, rt, "IIsSmtpServerSetting", server, normalized); e != nil {
		return false, e
	}
	return true, nil
}

type getLogFormatFunc struct{}

func (getLogFormatFunc) Name() string        { return "win_smtp_server.get_log_format" }
func (getLogFormatFunc) Args() any           { return serverArg{} }
func (getLogFormatFunc) Platforms() []string { return []string{"windows"} }
func (getLogFormatFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*serverArg)
	settings, err := getServerSettingFunc{}.Execute(ctx, rt, &settingsArg{Settings: []string{"LogPluginClsid"}, Server: a.Server})
	if err != nil {
		return nil, err
	}
	types, err := getLogFormatTypesFunc{}.Execute(ctx, rt, noArgs{})
	if err != nil {
		return nil, err
	}
	id := settings.(map[string]string)["LogPluginClsid"]
	for name, value := range types.(map[string]string) {
		if value == id {
			return name, nil
		}
	}
	return nil, nil
}

type setLogFormatArgs struct {
	LogFormat string  `statekit:"required,name=log_format"`
	Server    *string `statekit:"name=server"`
}
type setLogFormatFunc struct{}

func (setLogFormatFunc) Name() string        { return "win_smtp_server.set_log_format" }
func (setLogFormatFunc) Args() any           { return setLogFormatArgs{} }
func (setLogFormatFunc) Platforms() []string { return []string{"windows"} }
func (setLogFormatFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*setLogFormatArgs)
	types, err := getLogFormatTypesFunc{}.Execute(ctx, rt, noArgs{})
	if err != nil {
		return nil, err
	}
	id, ok := types.(map[string]string)[a.LogFormat]
	if !ok {
		return nil, fmt.Errorf("Invalid log format '%s' specified", a.LogFormat)
	}
	return setServerSettingFunc{}.Execute(ctx, rt, &setServerSettingArgs{Settings: map[string]any{"LogPluginClsid": id}, Server: a.Server})
}

// ---------------------------------------------------------------------------
// IP grant/relay conversions

type connectionArgs struct {
	AsWMIFormat *bool   `statekit:"name=as_wmi_format"`
	Server      *string `statekit:"name=server"`
}
type getConnectionIPListFunc struct{}

func (getConnectionIPListFunc) Name() string        { return "win_smtp_server.get_connection_ip_list" }
func (getConnectionIPListFunc) Args() any           { return connectionArgs{} }
func (getConnectionIPListFunc) Platforms() []string { return []string{"windows"} }
func (getConnectionIPListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSMTP(&res, &err)
	a := args.(*connectionArgs)
	server := smtpServer(a.Server)
	value, e := smtpJSON(ctx, rt, "@(Get-CimInstance -Namespace "+smtpLiteral(smtpNamespace)+" -ClassName IIsIPSecuritySetting -Filter \"Name='"+strings.ReplaceAll(server, "'", "''")+"'\" | Select-Object -ExpandProperty IPGrant)")
	if e != nil {
		return nil, e
	}
	wmi := a.AsWMIFormat != nil && *a.AsWMIFormat
	if wmi {
		out := []string{}
		for _, v := range smtpStringList(value) {
			parts := strings.SplitN(v, ",", 2)
			if len(parts) == 2 {
				out = append(out, strings.TrimSpace(parts[0])+", "+strings.TrimSpace(parts[1]))
			}
		}
		return out, nil
	}
	out := map[string]string{}
	for _, v := range smtpStringList(value) {
		parts := strings.SplitN(v, ",", 2)
		if len(parts) == 2 {
			out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return out, nil
}

type setConnectionArgs struct {
	Addresses      map[string]string `statekit:"name=addresses"`
	GrantByDefault *bool             `statekit:"name=grant_by_default"`
	Server         *string           `statekit:"name=server"`
}
type setConnectionIPListFunc struct{}

func (setConnectionIPListFunc) Name() string        { return "win_smtp_server.set_connection_ip_list" }
func (setConnectionIPListFunc) Args() any           { return setConnectionArgs{} }
func (setConnectionIPListFunc) Platforms() []string { return []string{"windows"} }
func (setConnectionIPListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*setConnectionArgs)
	server := smtpServer(a.Server)
	formatted := []string{}
	for ip, subnet := range a.Addresses {
		formatted = append(formatted, strings.TrimSpace(ip)+", "+strings.TrimSpace(subnet))
	}
	props := map[string]any{"IPGrant": formatted}
	if a.GrantByDefault != nil {
		props["GrantByDefault"] = *a.GrantByDefault
	}
	if e := setSMTPProperties(ctx, rt, "IIsIPSecuritySetting", server, props); e != nil {
		return false, e
	}
	return true, nil
}

type relayArgs struct {
	Addresses []any   `statekit:"name=addresses"`
	Server    *string `statekit:"name=server"`
}
type getRelayIPListFunc struct{}

func (getRelayIPListFunc) Name() string        { return "win_smtp_server.get_relay_ip_list" }
func (getRelayIPListFunc) Args() any           { return serverArg{} }
func (getRelayIPListFunc) Platforms() []string { return []string{"windows"} }
func (getRelayIPListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSMTP(&res, &err)
	a := args.(*serverArg)
	server := smtpServer(a.Server)
	value, e := smtpJSON(ctx, rt, "@(Get-CimInstance -Namespace "+smtpLiteral(smtpNamespace)+" -ClassName IIsSmtpServerSetting -Filter \"Name='"+strings.ReplaceAll(server, "'", "''")+"'\" | Select-Object -ExpandProperty RelayIpList)")
	if e != nil {
		return nil, e
	}
	bytes := smtpStringList(value)
	if len(bytes) == 0 {
		return []any{nil}, nil
	}
	out := []string{}
	for i := 0; i+3 < len(bytes); i += 4 {
		out = append(out, strings.Join(bytes[i:i+4], "."))
	}
	return out, nil
}

type setRelayIPListFunc struct{}

func (setRelayIPListFunc) Name() string        { return "win_smtp_server.set_relay_ip_list" }
func (setRelayIPListFunc) Args() any           { return relayArgs{} }
func (setRelayIPListFunc) Platforms() []string { return []string{"windows"} }
func (setRelayIPListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*relayArgs)
	server := smtpServer(a.Server)
	if len(a.Addresses) == 0 {
		return setSMTPProperties(ctx, rt, "IIsSmtpServerSetting", server, map[string]any{"RelayIpList": []string{}}) == nil, nil
	}
	if len(a.Addresses) == 1 && a.Addresses[0] == nil {
		return setSMTPProperties(ctx, rt, "IIsSmtpServerSetting", server, map[string]any{"RelayIpList": nil}) == nil, nil
	}
	octets := []string{}
	for _, raw := range a.Addresses {
		for _, part := range strings.Split(fmt.Sprint(raw), ".") {
			octets = append(octets, part)
		}
	}
	return setSMTPProperties(ctx, rt, "IIsSmtpServerSetting", server, map[string]any{"RelayIpList": octets}) == nil, nil
}
func smtpStringList(value any) []string {
	switch x := value.(type) {
	case string:
		return []string{x}
	case []any:
		out := []string{}
		for _, v := range x {
			out = append(out, fmt.Sprint(v))
		}
		return out
	case []string:
		return x
	default:
		return []string{}
	}
}
func recoverSMTP(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{getLogFormatTypesFunc{}, getServersFunc{}, getServerSettingFunc{}, setServerSettingFunc{}, getLogFormatFunc{}, setLogFormatFunc{}, getConnectionIPListFunc{}, setConnectionIPListFunc{}, getRelayIPListFunc{}, setRelayIPListFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
