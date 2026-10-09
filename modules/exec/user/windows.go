//go:build windows

package user

// Windows implementation of Salt's win_useradd virtual provider. PowerShell
// scripts are UTF-16LE/base64 encoded before reaching the Runner, preventing
// account names and passwords from becoming shell syntax. The Linux and
// Darwin implementations remain selected by user.Register on their targets.

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
	windowsUserCache   []map[string]any
	windowsUserCacheMu sync.Mutex
)

func registerWindows(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		winAddFunc{}, winUpdateFunc{}, winDeleteFunc{}, winGetUserSIDAliasFunc{}, winGetUserSIDFunc{},
		winSetPasswordFunc{}, winAddGroupFunc{}, winRemoveGroupFunc{}, winChhomeFunc{},
		winChprofileFunc{}, winChfullnameFunc{}, winChgroupsFunc{}, winInfoFunc{},
		winListGroupsFunc{}, winGetentFunc{}, winListUsersFunc{}, winRenameFunc{}, winCurrentFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

func psLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func encodedPowerShell(script string, secrets []string) process.Command {
	units := utf16Units(script + "\x00")
	raw := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], unit)
	}
	return process.Command{
		Name:   "powershell.exe",
		Args:   []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw)},
		Redact: secrets,
	}
}

func utf16Units(value string) []uint16 {
	units := make([]uint16, 0, len(value))
	for _, r := range value {
		if r <= 0xffff {
			units = append(units, uint16(r))
			continue
		}
		r -= 0x10000
		units = append(units, uint16(0xd800+(r>>10)), uint16(0xdc00+(r&0x3ff)))
	}
	return units
}

func runWindowsPS(ctx context.Context, rt *runtime.Runtime, script string, secrets []string) (string, error) {
	result := rt.Runner.Run(ctx, encodedPowerShell(script, secrets))
	if result.Err != nil && result.ExitCode == -1 {
		return string(result.Stdout), result.Err
	}
	if result.ExitCode != 0 {
		return string(result.Stdout), fmt.Errorf("PowerShell command failed (exit code %d): %s", result.ExitCode, strings.TrimSpace(string(result.Stderr)))
	}
	return string(result.Stdout), nil
}

func runWindowsJSON(ctx context.Context, rt *runtime.Runtime, script string) (any, error) {
	out, err := runWindowsPS(ctx, rt, script, nil)
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

func psUserInfo(ctx context.Context, rt *runtime.Runtime, name string) (map[string]any, error) {
	script := "$u=Get-LocalUser -Name " + psLiteral(name) + " -ErrorAction SilentlyContinue; if($null -eq $u){exit 3}; $u | Select-Object @{n='name';e={$_.Name}},@{n='uid';e={$_.SID.Value}},@{n='fullname';e={$_.FullName}},@{n='description';e={$_.Description}},@{n='active';e={$_.Enabled}},@{n='profile';e={$_.ProfilePath}},@{n='home';e={$_.HomeDirectory}},@{n='password_never_expires';e={$_.PasswordNeverExpires}},@{n='account_locked';e={$_.LockedOut}},@{n='expiration_date';e={if($null -eq $_.AccountExpires){'Never'}else{$_.AccountExpires.ToString('yyyy-MM-dd HH:mm:ss')}}},@{n='password_changed';e={if($null -eq $_.PasswordLastSet){'Never'}else{$_.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss')}}} | ConvertTo-Json -Compress"
	value, err := runWindowsJSON(ctx, rt, script)
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
		return nil, fmt.Errorf("unexpected Get-LocalUser response")
	}
	return raw, nil
}

func psUserGroups(ctx context.Context, rt *runtime.Runtime, name string) ([]string, error) {
	script := "$n=" + psLiteral(name) + "; $out=@(Get-LocalGroup | ForEach-Object { $g=$_.Name; try { if(Get-LocalGroupMember -Group $g -ErrorAction Stop | Where-Object { $_.Name -eq $n -or $_.Name -eq ((hostname)+'\\'+$n) }){$g} } catch {} }); $out | ConvertTo-Json -Compress"
	value, err := runWindowsJSON(ctx, rt, script)
	if err != nil {
		return nil, err
	}
	return psStringList(value), nil
}

func psStringList(value any) []string {
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

func windowsInfo(ctx context.Context, rt *runtime.Runtime, name string) (map[string]any, error) {
	raw, err := psUserInfo(ctx, rt, name)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	groups, err := psUserGroups(ctx, rt, name)
	if err != nil {
		return nil, err
	}
	active, _ := raw["active"].(bool)
	out := map[string]any{
		"fullname": raw["fullname"], "name": raw["name"], "uid": raw["uid"],
		"passwd": nil, "comment": raw["description"], "description": raw["description"],
		"active": active, "logonscript": "", "profile": raw["profile"],
		"home": raw["home"], "homedrive": "", "groups": groups,
		"password_changed": raw["password_changed"], "successful_logon_attempts": 0,
		"failed_logon_attempts": 0, "last_logon": "Never", "account_disabled": !active,
		"account_locked": raw["account_locked"], "expiration_date": raw["expiration_date"],
		"expired": false, "password_never_expires": raw["password_never_expires"],
		"disallow_change_password": false, "gid": "",
	}
	return out, nil
}

func windowsUserExists(ctx context.Context, rt *runtime.Runtime, name string) bool {
	info, err := windowsInfo(ctx, rt, name)
	return err == nil && len(info) > 0
}

func windowsUserMutation(ctx context.Context, rt *runtime.Runtime, script string, secrets []string) (bool, error) {
	_, err := runWindowsPS(ctx, rt, script, secrets)
	return err == nil, err
}

// ---------------------------------------------------------------------------
// add/update/delete

type winAddArgs struct {
	Name        string   `statekit:"required"`
	Password    *string  `statekit:"name=password"`
	Fullname    *string  `statekit:"name=fullname"`
	Description *string  `statekit:"name=description"`
	Groups      []string `statekit:"name=groups"`
	Home        *string  `statekit:"name=home"`
	Homedrive   *string  `statekit:"name=homedrive"`
	Profile     *string  `statekit:"name=profile"`
	Logonscript *string  `statekit:"name=logonscript"`
}
type winAddFunc struct{}

func (winAddFunc) Name() string        { return "user.add" }
func (winAddFunc) Args() any           { return winAddArgs{} }
func (winAddFunc) Platforms() []string { return []string{"windows"} }
func (winAddFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsUser(&res, &err)
	a := args.(*winAddArgs)
	if a.Name == "" {
		return false, nil
	}
	params := "$p=@{Name=" + psLiteral(a.Name) + "};"
	secrets := []string{}
	if a.Password != nil {
		params += "$p.Password=(ConvertTo-SecureString " + psLiteral(*a.Password) + " -AsPlainText -Force);"
		secrets = []string{*a.Password}
	} else {
		params += "$p.NoPassword=$true;"
	}
	if a.Fullname != nil {
		params += "$p.FullName=" + psLiteral(*a.Fullname) + ";"
	}
	if a.Description != nil {
		params += "$p.Description=" + psLiteral(*a.Description) + ";"
	}
	script := params + "New-LocalUser @p -ErrorAction Stop | Out-Null;"
	if a.Home != nil {
		script += "Set-LocalUser -Name " + psLiteral(a.Name) + " -HomeDirectory " + psLiteral(*a.Home) + ";"
	}
	if a.Profile != nil {
		script += "Set-LocalUser -Name " + psLiteral(a.Name) + " -ProfilePath " + psLiteral(*a.Profile) + ";"
	}
	ok, e := windowsUserMutation(ctx, rt, script, secrets)
	if e != nil {
		return false, e
	}
	if len(a.Groups) > 0 {
		groupsOK, groupErr := windowsChgroups(ctx, rt, a.Name, a.Groups, true)
		if groupErr != nil {
			return false, groupErr
		}
		return ok && groupsOK, nil
	}
	return ok, nil
}

type winUpdateArgs struct {
	Name                   string  `statekit:"required"`
	Password               *string `statekit:"name=password"`
	Fullname               *string `statekit:"name=fullname"`
	Description            *string `statekit:"name=description"`
	Home                   *string `statekit:"name=home"`
	Homedrive              *string `statekit:"name=homedrive"`
	Logonscript            *string `statekit:"name=logonscript"`
	Profile                *string `statekit:"name=profile"`
	ExpirationDate         *string `statekit:"name=expiration_date"`
	Expired                *bool   `statekit:"name=expired"`
	AccountDisabled        *bool   `statekit:"name=account_disabled"`
	UnlockAccount          *bool   `statekit:"name=unlock_account"`
	PasswordNeverExpires   *bool   `statekit:"name=password_never_expires"`
	DisallowChangePassword *bool   `statekit:"name=disallow_change_password"`
}
type winUpdateFunc struct{}

func (winUpdateFunc) Name() string        { return "user.update" }
func (winUpdateFunc) Args() any           { return winUpdateArgs{} }
func (winUpdateFunc) Platforms() []string { return []string{"windows"} }
func (winUpdateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsUser(&res, &err)
	a := args.(*winUpdateArgs)
	if !windowsUserExists(ctx, rt, a.Name) {
		return false, fmt.Errorf("User '%s' does not exist", a.Name)
	}
	script := "$u=Get-LocalUser -Name " + psLiteral(a.Name) + " -ErrorAction Stop;"
	secrets := []string{}
	if a.Password != nil {
		script += "Set-LocalUser -Name " + psLiteral(a.Name) + " -Password (ConvertTo-SecureString " + psLiteral(*a.Password) + " -AsPlainText -Force);"
		secrets = []string{*a.Password}
	}
	if a.Fullname != nil {
		script += "Set-LocalUser -Name " + psLiteral(a.Name) + " -FullName " + psLiteral(*a.Fullname) + ";"
	}
	if a.Description != nil {
		script += "Set-LocalUser -Name " + psLiteral(a.Name) + " -Description " + psLiteral(*a.Description) + ";"
	}
	if a.Home != nil {
		script += "Set-LocalUser -Name " + psLiteral(a.Name) + " -HomeDirectory " + psLiteral(*a.Home) + ";"
	}
	if a.Profile != nil {
		script += "Set-LocalUser -Name " + psLiteral(a.Name) + " -ProfilePath " + psLiteral(*a.Profile) + ";"
	}
	if a.ExpirationDate != nil {
		if *a.ExpirationDate == "Never" {
			script += "Set-LocalUser -Name " + psLiteral(a.Name) + " -AccountExpires ([datetime]::MaxValue);"
		} else {
			script += "$d=Get-Date " + psLiteral(*a.ExpirationDate) + ";Set-LocalUser -Name " + psLiteral(a.Name) + " -AccountExpires $d;"
		}
	}
	if a.AccountDisabled != nil {
		if *a.AccountDisabled {
			script += "Disable-LocalUser -Name " + psLiteral(a.Name) + ";"
		} else {
			script += "Enable-LocalUser -Name " + psLiteral(a.Name) + ";"
		}
	}
	ok, e := windowsUserMutation(ctx, rt, script, secrets)
	if e != nil {
		return false, e
	}
	return ok, nil
}

type winDeleteArgs struct {
	Name  string `statekit:"required"`
	Purge bool   `statekit:"name=purge"`
	Force bool   `statekit:"name=force"`
}
type winDeleteFunc struct{}

func (winDeleteFunc) Name() string        { return "user.delete" }
func (winDeleteFunc) Args() any           { return winDeleteArgs{} }
func (winDeleteFunc) Platforms() []string { return []string{"windows"} }
func (winDeleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsUser(&res, &err)
	a := args.(*winDeleteArgs)
	info, _ := windowsInfo(ctx, rt, a.Name)
	if len(info) == 0 {
		return true, nil
	}
	script := "Remove-LocalUser -Name " + psLiteral(a.Name) + " -Confirm:$false -ErrorAction Stop;"
	if a.Purge {
		if home, ok := info["home"].(string); ok && home != "" {
			script += "Remove-Item -LiteralPath " + psLiteral(home) + " -Recurse -Force -ErrorAction SilentlyContinue;"
		}
	}
	return windowsUserMutation(ctx, rt, script, nil)
}

// ---------------------------------------------------------------------------
// SID/password/group/attributes

type winUserSIDArgs struct {
	Username string `statekit:"required,name=username"`
}
type winGetUserSIDFunc struct{}
type winGetUserSIDAliasFunc struct{}

func (winGetUserSIDFunc) Name() string        { return "user.get_user_sid" }
func (winGetUserSIDFunc) Args() any           { return winUserSIDArgs{} }
func (winGetUserSIDFunc) Platforms() []string { return []string{"windows"} }
func (winGetUserSIDFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsUser(&res, &err)
	a := args.(*winUserSIDArgs)
	script := "([System.Security.Principal.NTAccount]" + psLiteral(a.Username) + ").Translate([System.Security.Principal.SecurityIdentifier]).Value"
	out, sidErr := runWindowsPS(ctx, rt, script, nil)
	return strings.TrimSpace(out), sidErr
}
func (winGetUserSIDAliasFunc) Name() string        { return "user.getUserSid" }
func (winGetUserSIDAliasFunc) Args() any           { return winUserSIDArgs{} }
func (winGetUserSIDAliasFunc) Platforms() []string { return []string{"windows"} }
func (winGetUserSIDAliasFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return winGetUserSIDFunc{}.Execute(ctx, rt, args)
}

type winSetPasswordArgs struct {
	Name     string `statekit:"required"`
	Password string `statekit:"required"`
}
type winSetPasswordFunc struct{}

func (winSetPasswordFunc) Name() string        { return "user.setpassword" }
func (winSetPasswordFunc) Args() any           { return winSetPasswordArgs{} }
func (winSetPasswordFunc) Platforms() []string { return []string{"windows"} }
func (winSetPasswordFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsUser(&res, &err)
	a := args.(*winSetPasswordArgs)
	if !windowsUserExists(ctx, rt, a.Name) {
		return false, nil
	}
	ok, e := windowsUserMutation(ctx, rt, "Set-LocalUser -Name "+psLiteral(a.Name)+" -Password (ConvertTo-SecureString "+psLiteral(a.Password)+" -AsPlainText -Force)", []string{a.Password})
	return ok, e
}

type winGroupChangeArgs struct {
	Name  string `statekit:"required"`
	Group string `statekit:"required,name=group"`
}
type winAddGroupFunc struct{}
type winRemoveGroupFunc struct{}

func (winAddGroupFunc) Name() string        { return "user.addgroup" }
func (winAddGroupFunc) Args() any           { return winGroupChangeArgs{} }
func (winAddGroupFunc) Platforms() []string { return []string{"windows"} }
func (winAddGroupFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsUser(&res, &err)
	a := args.(*winGroupChangeArgs)
	if !windowsUserExists(ctx, rt, a.Name) {
		return false, nil
	}
	groups, e := psUserGroups(ctx, rt, a.Name)
	if e != nil {
		return nil, e
	}
	for _, g := range groups {
		if g == a.Group {
			return true, nil
		}
	}
	return windowsUserMutation(ctx, rt, "Add-LocalGroupMember -Group "+psLiteral(a.Group)+" -Member "+psLiteral(a.Name)+" -ErrorAction Stop", nil)
}
func (winRemoveGroupFunc) Name() string        { return "user.removegroup" }
func (winRemoveGroupFunc) Args() any           { return winGroupChangeArgs{} }
func (winRemoveGroupFunc) Platforms() []string { return []string{"windows"} }
func (winRemoveGroupFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsUser(&res, &err)
	a := args.(*winGroupChangeArgs)
	if !windowsUserExists(ctx, rt, a.Name) {
		return false, nil
	}
	groups, e := psUserGroups(ctx, rt, a.Name)
	if e != nil {
		return nil, e
	}
	found := false
	for _, g := range groups {
		if g == a.Group {
			found = true
		}
	}
	if !found {
		return true, nil
	}
	return windowsUserMutation(ctx, rt, "Remove-LocalGroupMember -Group "+psLiteral(a.Group)+" -Member "+psLiteral(a.Name)+" -Confirm:$false -ErrorAction Stop", nil)
}

type winChhomeArgs struct {
	Name    string `statekit:"required"`
	Home    string `statekit:"required,name=home"`
	Persist bool   `statekit:"name=persist"`
}
type winChhomeFunc struct{}

func (winChhomeFunc) Name() string        { return "user.chhome" }
func (winChhomeFunc) Args() any           { return winChhomeArgs{} }
func (winChhomeFunc) Platforms() []string { return []string{"windows"} }
func (winChhomeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsUser(&res, &err)
	a := args.(*winChhomeArgs)
	info, e := windowsInfo(ctx, rt, a.Name)
	if e != nil || len(info) == 0 {
		return false, e
	}
	if info["home"] == a.Home {
		return true, nil
	}
	ok, e := windowsUserMutation(ctx, rt, "Set-LocalUser -Name "+psLiteral(a.Name)+" -HomeDirectory "+psLiteral(a.Home), nil)
	if e != nil {
		return false, e
	}
	return ok, nil
}

type winChfullnameArgs struct {
	Name     string `statekit:"required"`
	Fullname string `statekit:"required,name=fullname"`
}
type winChfullnameFunc struct{}

func (winChfullnameFunc) Name() string        { return "user.chfullname" }
func (winChfullnameFunc) Args() any           { return winChfullnameArgs{} }
func (winChfullnameFunc) Platforms() []string { return []string{"windows"} }
func (winChfullnameFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*winChfullnameArgs)
	ok, e := windowsUserMutation(ctx, rt, "Set-LocalUser -Name "+psLiteral(a.Name)+" -FullName "+psLiteral(a.Fullname), nil)
	return ok, e
}

type winChgroupsArgs struct {
	Name   string   `statekit:"required"`
	Groups []string `statekit:"required,name=groups"`
	Append *bool    `statekit:"name=append"`
}
type winChgroupsFunc struct{}

func (winChgroupsFunc) Name() string        { return "user.chgroups" }
func (winChgroupsFunc) Args() any           { return winChgroupsArgs{} }
func (winChgroupsFunc) Platforms() []string { return []string{"windows"} }
func (winChgroupsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsUser(&res, &err)
	a := args.(*winChgroupsArgs)
	appendOnly := true
	if a.Append != nil {
		appendOnly = *a.Append
	}
	return windowsChgroups(ctx, rt, a.Name, a.Groups, appendOnly)
}
func windowsChgroups(ctx context.Context, rt *runtime.Runtime, name string, desired []string, appendOnly bool) (bool, error) {
	if !windowsUserExists(ctx, rt, name) {
		return false, nil
	}
	current, e := psUserGroups(ctx, rt, name)
	if e != nil {
		return false, e
	}
	want := map[string]bool{}
	for _, g := range desired {
		if strings.TrimSpace(g) != "" {
			want[strings.TrimSpace(g)] = true
		}
	}
	have := map[string]bool{}
	for _, g := range current {
		have[g] = true
	}
	script := ""
	if !appendOnly {
		for g := range have {
			if !want[g] {
				script += "Remove-LocalGroupMember -Group " + psLiteral(g) + " -Member " + psLiteral(name) + " -Confirm:$false -ErrorAction SilentlyContinue;"
			}
		}
	}
	for g := range want {
		if !have[g] {
			script += "Add-LocalGroupMember -Group " + psLiteral(g) + " -Member " + psLiteral(name) + " -ErrorAction Stop;"
		}
	}
	if script == "" {
		return true, nil
	}
	return windowsUserMutation(ctx, rt, script, nil)
}

// ---------------------------------------------------------------------------
// info/list/getent/rename/current

type winInfoArgs struct {
	Name string `statekit:"required"`
}
type winInfoFunc struct{}

func (winInfoFunc) Name() string        { return "user.info" }
func (winInfoFunc) Args() any           { return winInfoArgs{} }
func (winInfoFunc) Platforms() []string { return []string{"windows"} }
func (winInfoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsUser(&res, &err)
	return windowsInfo(ctx, rt, args.(*winInfoArgs).Name)
}

type winListGroupsArgs struct {
	Name string `statekit:"required"`
}
type winListGroupsFunc struct{}

func (winListGroupsFunc) Name() string        { return "user.list_groups" }
func (winListGroupsFunc) Args() any           { return winListGroupsArgs{} }
func (winListGroupsFunc) Platforms() []string { return []string{"windows"} }
func (winListGroupsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return psUserGroups(ctx, rt, args.(*winListGroupsArgs).Name)
}

type winGetentArgs struct {
	Refresh bool `statekit:"name=refresh"`
}
type winGetentFunc struct{}

func (winGetentFunc) Name() string        { return "user.getent" }
func (winGetentFunc) Args() any           { return winGetentArgs{} }
func (winGetentFunc) Platforms() []string { return []string{"windows"} }
func (winGetentFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsUser(&res, &err)
	a := args.(*winGetentArgs)
	windowsUserCacheMu.Lock()
	cached := windowsUserCache
	windowsUserCacheMu.Unlock()
	if cached != nil && !a.Refresh {
		return cached, nil
	}
	users, err := windowsListUsers(ctx, rt)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(users))
	for _, name := range users {
		info, e := windowsInfo(ctx, rt, name)
		if e != nil {
			return nil, e
		}
		if len(info) > 0 {
			out = append(out, map[string]any{"gid": "", "groups": info["groups"], "home": info["home"], "name": info["name"], "passwd": nil, "shell": "", "uid": info["uid"]})
		}
	}
	windowsUserCacheMu.Lock()
	windowsUserCache = out
	windowsUserCacheMu.Unlock()
	return out, nil
}

type winListUsersArgs struct{}
type winListUsersFunc struct{}

func (winListUsersFunc) Name() string        { return "user.list_users" }
func (winListUsersFunc) Args() any           { return winListUsersArgs{} }
func (winListUsersFunc) Platforms() []string { return []string{"windows"} }
func (winListUsersFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverWindowsUser(&res, &err)
	return windowsListUsers(ctx, rt)
}
func windowsListUsers(ctx context.Context, rt *runtime.Runtime) ([]string, error) {
	value, err := runWindowsJSON(ctx, rt, "@(Get-LocalUser | Select-Object -ExpandProperty Name) | ConvertTo-Json -Compress")
	if err != nil {
		return nil, err
	}
	return psStringList(value), nil
}

type winRenameArgs struct {
	Name    string `statekit:"required"`
	NewName string `statekit:"required,name=new_name"`
}
type winRenameFunc struct{}

func (winRenameFunc) Name() string        { return "user.rename" }
func (winRenameFunc) Args() any           { return winRenameArgs{} }
func (winRenameFunc) Platforms() []string { return []string{"windows"} }
func (winRenameFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsUser(&res, &err)
	a := args.(*winRenameArgs)
	if !windowsUserExists(ctx, rt, a.Name) {
		return nil, fmt.Errorf("User '%s' does not exist", a.Name)
	}
	if windowsUserExists(ctx, rt, a.NewName) {
		return nil, fmt.Errorf("User '%s' already exists", a.NewName)
	}
	script := "$u=Get-CimInstance Win32_UserAccount -Filter \"Name=" + strings.ReplaceAll(a.Name, `"`, `\"`) + "\";Invoke-CimMethod -InputObject $u -MethodName Rename -Arguments @{Name=" + psLiteral(a.NewName) + "} -ErrorAction Stop | Out-Null"
	return windowsUserMutation(ctx, rt, script, nil)
}

type winCurrentArgs struct {
	SAM bool `statekit:"name=sam"`
}
type winCurrentFunc struct{}

func (winCurrentFunc) Name() string        { return "user.current" }
func (winCurrentFunc) Args() any           { return winCurrentArgs{} }
func (winCurrentFunc) Platforms() []string { return []string{"windows"} }
func (winCurrentFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsUser(&res, &err)
	a := args.(*winCurrentArgs)
	script := "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name"
	out, e := runWindowsPS(ctx, rt, script, nil)
	if e != nil {
		return nil, e
	}
	out = strings.TrimSpace(out)
	if a.SAM {
		return out, nil
	}
	if i := strings.LastIndex(out, `\`); i >= 0 {
		return out[i+1:], nil
	}
	return out, nil
}

func recoverWindowsUser(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}
