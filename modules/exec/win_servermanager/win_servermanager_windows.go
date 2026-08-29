//go:build windows

// Package win_servermanager implements Salt's Windows ServerManager surface
// through encoded PowerShell. Reboot requests are reported, not executed, so
// a local-only runner cannot unexpectedly restart a host.
package win_servermanager

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

func featureLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
func featurePS(script string) process.Command {
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
func featureRun(ctx context.Context, rt *runtime.Runtime, script string) (string, error) {
	r := rt.Runner.Run(ctx, featurePS("Import-Module ServerManager; "+script))
	if r.Err != nil && r.ExitCode == -1 {
		return string(r.Stdout), r.Err
	}
	if r.ExitCode != 0 {
		return string(r.Stdout), fmt.Errorf("ServerManager command failed (exit code %d): %s", r.ExitCode, strings.TrimSpace(string(r.Stderr)))
	}
	return string(r.Stdout), nil
}
func featureJSON(ctx context.Context, rt *runtime.Runtime, script string) (any, error) {
	out, e := featureRun(ctx, rt, script+" | ConvertTo-Json -Compress -Depth 6")
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
func featureRows(value any) []map[string]any {
	switch x := value.(type) {
	case map[string]any:
		return []map[string]any{x}
	case []any:
		out := []map[string]any{}
		for _, item := range x {
			if row, ok := item.(map[string]any); ok {
				out = append(out, row)
			}
		}
		return out
	default:
		return []map[string]any{}
	}
}
func featureNames(value any) []string {
	switch x := value.(type) {
	case string:
		parts := strings.Split(x, ",")
		out := []string{}
		for _, p := range parts {
			if strings.TrimSpace(p) != "" {
				out = append(out, strings.TrimSpace(p))
			}
		}
		return out
	case []string:
		return x
	case []any:
		out := []string{}
		for _, p := range x {
			out = append(out, fmt.Sprint(p))
		}
		return out
	default:
		return []string{}
	}
}
func featureResult(value any, names []string) map[string]any {
	out := map[string]any{"ExitCode": 0, "RestartNeeded": false, "Restarted": false, "Features": map[string]any{}, "Success": true}
	if raw, ok := value.(map[string]any); ok {
		if v, ok := raw["ExitCode"]; ok {
			out["ExitCode"] = v
		}
		if v, ok := raw["Success"]; ok {
			out["Success"] = v
		}
		if v, ok := raw["RestartNeeded"]; ok {
			out["RestartNeeded"] = v
		}
		if entries, ok := raw["FeatureResult"]; ok {
			features := map[string]any{}
			for _, row := range featureRows(entries) {
				name := fmt.Sprint(row["Name"])
				features[name] = map[string]any{"DisplayName": row["DisplayName"], "Message": row["Message"], "RestartNeeded": row["RestartNeeded"], "SkipReason": row["SkipReason"], "Success": row["Success"]}
			}
			out["Features"] = features
		}
	}
	features := out["Features"].(map[string]any)
	for _, name := range names {
		if _, ok := features[name]; !ok {
			features[name] = map[string]any{"Message": "Already installed"}
		}
	}
	return out
}

// ---------------------------------------------------------------------------

type noArgs struct{}
type listAvailableFunc struct{}

func (listAvailableFunc) Name() string        { return "win_servermanager.list_available" }
func (listAvailableFunc) Args() any           { return noArgs{} }
func (listAvailableFunc) Platforms() []string { return []string{"windows"} }
func (listAvailableFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	return featureRun(ctx, rt, "Get-WindowsFeature -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-String")
}

type listInstalledFunc struct{}

func (listInstalledFunc) Name() string        { return "win_servermanager.list_installed" }
func (listInstalledFunc) Args() any           { return noArgs{} }
func (listInstalledFunc) Platforms() []string { return []string{"windows"} }
func (listInstalledFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverServerManager(&res, &err)
	value, e := featureJSON(ctx, rt, "@(Get-WindowsFeature -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Select-Object DisplayName,Name,Installed)")
	if e != nil {
		return nil, e
	}
	out := map[string]string{}
	for _, row := range featureRows(value) {
		if installed, ok := row["Installed"].(bool); ok && installed {
			out[fmt.Sprint(row["Name"])] = fmt.Sprint(row["DisplayName"])
		}
	}
	return out, nil
}

type installArgs struct {
	Feature any     `statekit:"required"`
	Recurse bool    `statekit:"name=recurse"`
	Restart bool    `statekit:"name=restart"`
	Source  *string `statekit:"name=source"`
	Exclude any     `statekit:"name=exclude"`
}
type installFunc struct{}

func (installFunc) Name() string        { return "win_servermanager.install" }
func (installFunc) Args() any           { return installArgs{} }
func (installFunc) Platforms() []string { return []string{"windows"} }
func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverServerManager(&res, &err)
	a := args.(*installArgs)
	names := featureNames(a.Feature)
	if len(names) == 0 {
		return nil, fmt.Errorf("feature is required")
	}
	script := "$r=Install-WindowsFeature -Name " + featureLiteral(strings.Join(names, ",")) + " -IncludeManagementTools"
	if a.Recurse {
		script += " -IncludeAllSubFeature"
	}
	if a.Source != nil && *a.Source != "" {
		script += " -Source " + featureLiteral(*a.Source)
	}
	script += " -WarningAction SilentlyContinue; $r"
	value, e := featureJSON(ctx, rt, script)
	if e != nil {
		return nil, e
	}
	out := featureResult(value, names)
	if a.Restart {
		out["Restarted"] = false
	}
	if len(featureNames(a.Exclude)) > 0 {
		excluded := featureNames(a.Exclude)
		removeValue, e := removeFeatures(ctx, rt, excluded, false, false)
		if e != nil {
			return nil, e
		}
		for _, name := range excluded {
			out["Features"].(map[string]any)[name] = map[string]any{"Message": "Removed after installation (exclude)"}
			if removeValue["RestartNeeded"] == true {
				out["RestartNeeded"] = true
			}
		}
	}
	return out, nil
}

type removeArgs struct {
	Feature       any  `statekit:"required"`
	RemovePayload bool `statekit:"name=remove_payload"`
	Restart       bool `statekit:"name=restart"`
}
type removeFunc struct{}

func (removeFunc) Name() string        { return "win_servermanager.remove" }
func (removeFunc) Args() any           { return removeArgs{} }
func (removeFunc) Platforms() []string { return []string{"windows"} }
func (removeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverServerManager(&res, &err)
	a := args.(*removeArgs)
	names := featureNames(a.Feature)
	return removeFeatures(ctx, rt, names, a.RemovePayload, a.Restart)
}
func removeFeatures(ctx context.Context, rt *runtime.Runtime, names []string, removePayload, restart bool) (map[string]any, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("feature is required")
	}
	script := "$r=Uninstall-WindowsFeature -Name " + featureLiteral(strings.Join(names, ",")) + " -IncludeManagementTools"
	if removePayload {
		script += " -Remove"
	}
	script += " -WarningAction SilentlyContinue; $r"
	value, e := featureJSON(ctx, rt, script)
	if e != nil {
		return nil, e
	}
	out := featureResult(value, names)
	features := out["Features"].(map[string]any)
	for _, name := range names {
		if _, ok := features[name]; !ok {
			features[name] = map[string]any{"Message": "Not installed"}
		}
	}
	out["Restarted"] = false
	return out, nil
}
func recoverServerManager(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{listAvailableFunc{}, listInstalledFunc{}, installFunc{}, removeFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
