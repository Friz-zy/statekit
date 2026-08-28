//go:build windows

package group

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

var (
	windowsGroupCache   []map[string]any
	windowsGroupCacheMu sync.Mutex
)

func registerWindows(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		winAddFunc{}, winDeleteFunc{}, winInfoFunc{}, winGetentFunc{},
		winAddUserFunc{}, winDelUserFunc{}, winMembersFunc{}, winListGroupsFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

func psGroupLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func groupUTF16(value string) []uint16 {
	out := make([]uint16, 0, len(value))
	for _, r := range value {
		if r <= 0xffff {
			out = append(out, uint16(r))
		} else {
			r -= 0x10000
			out = append(out, uint16(0xd800+(r>>10)), uint16(0xdc00+(r&0x3ff)))
		}
	}
	return out
}

func groupPowerShellCommand(script string) process.Command {
	units := groupUTF16(script + "\x00")
	raw := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], unit)
	}
	return process.Command{
		Name: "powershell.exe",
		Args: []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw)},
	}
}

func runGroupPS(ctx context.Context, rt *runtime.Runtime, script string) (string, error) {
	result := rt.Runner.Run(ctx, groupPowerShellCommand(script))
	if result.Err != nil && result.ExitCode == -1 {
		return string(result.Stdout), result.Err
	}
	if result.ExitCode != 0 {
		return string(result.Stdout), fmt.Errorf("PowerShell command failed (exit code %d): %s", result.ExitCode, strings.TrimSpace(string(result.Stderr)))
	}
	return string(result.Stdout), nil
}

func runGroupJSON(ctx context.Context, rt *runtime.Runtime, script string) (any, error) {
	out, err := runGroupPS(ctx, rt, script)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(out) == "" || strings.TrimSpace(out) == "null" {
		return nil, nil
	}
	var value any
	if err := json.Unmarshal([]byte(out), &value); err != nil {
		return nil, err
	}
	return value, nil
}

func groupStringList(value any) []string {
	switch item := value.(type) {
	case string:
		if item == "" {
			return []string{}
		}
		return []string{item}
	case []any:
		out := make([]string, 0, len(item))
		for _, entry := range item {
			if text, ok := entry.(string); ok {
				out = append(out, text)
			}
		}
		return out
	case []string:
		return append([]string(nil), item...)
	default:
		return []string{}
	}
}

func windowsGroupInfo(ctx context.Context, rt *runtime.Runtime, name string) (map[string]any, error) {
	script := "$g=Get-LocalGroup -Name " + psGroupLiteral(name) + " -ErrorAction SilentlyContinue; if($null -eq $g){exit 3}; $g | Select-Object @{n='name';e={$_.Name}},@{n='description';e={$_.Description}} | ConvertTo-Json -Compress"
	value, err := runGroupJSON(ctx, rt, script)
	if err != nil {
		if strings.Contains(err.Error(), "code 3") {
			return map[string]any{}, nil
		}
		return nil, err
	}
	if value == nil {
		return map[string]any{}, nil
	}
	raw, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected Get-LocalGroup response")
	}
	members, err := windowsGroupMembers(ctx, rt, name)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"name": raw["name"], "passwd": nil, "gid": nil, "members": members,
		"description": raw["description"],
	}, nil
}

func windowsGroupMembers(ctx context.Context, rt *runtime.Runtime, name string) ([]string, error) {
	script := "@(Get-LocalGroupMember -Group " + psGroupLiteral(name) + " -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) | ConvertTo-Json -Compress"
	value, err := runGroupJSON(ctx, rt, script)
	if err != nil {
		return nil, err
	}
	return groupStringList(value), nil
}

func windowsGroupExists(ctx context.Context, rt *runtime.Runtime, name string) bool {
	info, err := windowsGroupInfo(ctx, rt, name)
	return err == nil && len(info) > 0
}

// ---------------------------------------------------------------------------
// add/delete/info

type winAddArgs struct {
	Name string `statekit:"required"`
}
type winAddFunc struct{}

func (winAddFunc) Name() string        { return "group.add" }
func (winAddFunc) Args() any           { return winAddArgs{} }
func (winAddFunc) Platforms() []string { return []string{"windows"} }
func (winAddFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsGroup(&res, &err)
	a := args.(*winAddArgs)
	if windowsGroupExists(ctx, rt, a.Name) {
		return false, nil
	}
	script := "New-LocalGroup -Name " + psGroupLiteral(a.Name) + " -ErrorAction Stop | Out-Null"
	return runGroupMutation(ctx, rt, script)
}

type winDeleteArgs struct {
	Name string `statekit:"required"`
}
type winDeleteFunc struct{}

func (winDeleteFunc) Name() string        { return "group.delete" }
func (winDeleteFunc) Args() any           { return winDeleteArgs{} }
func (winDeleteFunc) Platforms() []string { return []string{"windows"} }
func (winDeleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsGroup(&res, &err)
	a := args.(*winDeleteArgs)
	if !windowsGroupExists(ctx, rt, a.Name) {
		return false, nil
	}
	return runGroupMutation(ctx, rt, "Remove-LocalGroup -Name "+psGroupLiteral(a.Name)+" -Confirm:$false -ErrorAction Stop")
}

type winInfoArgs struct {
	Name string `statekit:"required"`
}
type winInfoFunc struct{}

func (winInfoFunc) Name() string        { return "group.info" }
func (winInfoFunc) Args() any           { return winInfoArgs{} }
func (winInfoFunc) Platforms() []string { return []string{"windows"} }
func (winInfoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsGroup(&res, &err)
	return windowsGroupInfo(ctx, rt, args.(*winInfoArgs).Name)
}

// ---------------------------------------------------------------------------
// getent/list_groups

type winGetentArgs struct {
	Refresh bool `statekit:"name=refresh"`
}
type winGetentFunc struct{}

func (winGetentFunc) Name() string        { return "group.getent" }
func (winGetentFunc) Args() any           { return winGetentArgs{} }
func (winGetentFunc) Platforms() []string { return []string{"windows"} }
func (winGetentFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsGroup(&res, &err)
	a := args.(*winGetentArgs)
	windowsGroupCacheMu.Lock()
	cached := windowsGroupCache
	windowsGroupCacheMu.Unlock()
	if cached != nil && !a.Refresh {
		return cached, nil
	}
	names, err := windowsListGroups(ctx, rt)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(names))
	for _, name := range names {
		info, e := windowsGroupInfo(ctx, rt, name)
		if e != nil {
			return nil, e
		}
		if len(info) > 0 {
			out = append(out, info)
		}
	}
	windowsGroupCacheMu.Lock()
	windowsGroupCache = out
	windowsGroupCacheMu.Unlock()
	return out, nil
}

type winListGroupsArgs struct {
	Refresh bool `statekit:"name=refresh"`
}
type winListGroupsFunc struct{}

func (winListGroupsFunc) Name() string        { return "group.list_groups" }
func (winListGroupsFunc) Args() any           { return winListGroupsArgs{} }
func (winListGroupsFunc) Platforms() []string { return []string{"windows"} }
func (winListGroupsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsGroup(&res, &err)
	a := args.(*winListGroupsArgs)
	if !a.Refresh {
		windowsGroupCacheMu.Lock()
		if windowsGroupCache != nil {
			out := make([]string, 0, len(windowsGroupCache))
			for _, g := range windowsGroupCache {
				if n, ok := g["name"].(string); ok {
					out = append(out, n)
				}
			}
			windowsGroupCacheMu.Unlock()
			return out, nil
		}
		windowsGroupCacheMu.Unlock()
	}
	return windowsListGroups(ctx, rt)
}
func windowsListGroups(ctx context.Context, rt *runtime.Runtime) ([]string, error) {
	value, err := runGroupJSON(ctx, rt, "@(Get-LocalGroup | Select-Object -ExpandProperty Name) | ConvertTo-Json -Compress")
	if err != nil {
		return nil, err
	}
	return groupStringList(value), nil
}

// ---------------------------------------------------------------------------
// membership

type winMemberArgs struct {
	Name     string `statekit:"required"`
	Username string `statekit:"required,name=username"`
}
type winAddUserFunc struct{}
type winDelUserFunc struct{}

func (winAddUserFunc) Name() string        { return "group.adduser" }
func (winAddUserFunc) Args() any           { return winMemberArgs{} }
func (winAddUserFunc) Platforms() []string { return []string{"windows"} }
func (winAddUserFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsGroup(&res, &err)
	a := args.(*winMemberArgs)
	info, e := windowsGroupInfo(ctx, rt, a.Name)
	if e != nil || len(info) == 0 {
		return false, e
	}
	for _, m := range info["members"].([]string) {
		if m == a.Username {
			return false, nil
		}
	}
	return runGroupMutation(ctx, rt, "Add-LocalGroupMember -Group "+psGroupLiteral(a.Name)+" -Member "+psGroupLiteral(a.Username)+" -ErrorAction Stop")
}
func (winDelUserFunc) Name() string        { return "group.deluser" }
func (winDelUserFunc) Args() any           { return winMemberArgs{} }
func (winDelUserFunc) Platforms() []string { return []string{"windows"} }
func (winDelUserFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsGroup(&res, &err)
	a := args.(*winMemberArgs)
	info, e := windowsGroupInfo(ctx, rt, a.Name)
	if e != nil || len(info) == 0 {
		return false, e
	}
	found := false
	for _, m := range info["members"].([]string) {
		if m == a.Username {
			found = true
		}
	}
	if !found {
		return false, nil
	}
	return runGroupMutation(ctx, rt, "Remove-LocalGroupMember -Group "+psGroupLiteral(a.Name)+" -Member "+psGroupLiteral(a.Username)+" -Confirm:$false -ErrorAction Stop")
}

type winMembersArgs struct {
	Name        string   `statekit:"required"`
	MembersList []string `statekit:"required,name=members_list"`
}
type winMembersFunc struct{}

func (winMembersFunc) Name() string        { return "group.members" }
func (winMembersFunc) Args() any           { return winMembersArgs{} }
func (winMembersFunc) Platforms() []string { return []string{"windows"} }
func (winMembersFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsGroup(&res, &err)
	a := args.(*winMembersArgs)
	info, e := windowsGroupInfo(ctx, rt, a.Name)
	if e != nil || len(info) == 0 {
		return false, e
	}
	current := map[string]bool{}
	for _, m := range info["members"].([]string) {
		current[m] = true
	}
	desired := map[string]bool{}
	for _, m := range a.MembersList {
		desired[m] = true
	}
	script := ""
	for m := range desired {
		if !current[m] {
			script += "Add-LocalGroupMember -Group " + psGroupLiteral(a.Name) + " -Member " + psGroupLiteral(m) + " -ErrorAction Stop;"
		}
	}
	for m := range current {
		if !desired[m] {
			script += "Remove-LocalGroupMember -Group " + psGroupLiteral(a.Name) + " -Member " + psGroupLiteral(m) + " -Confirm:$false -ErrorAction Stop;"
		}
	}
	if script == "" {
		return true, nil
	}
	return runGroupMutation(ctx, rt, script)
}

func runGroupMutation(ctx context.Context, rt *runtime.Runtime, script string) (bool, error) {
	_, err := runGroupPS(ctx, rt, script)
	return err == nil, err
}
func recoverWindowsGroup(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}
