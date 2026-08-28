//go:build darwin

package user

// Darwin implementation of Salt's mac_user virtual provider. It is kept in
// the existing user package so the public virtual names remain user.*; the
// package Register function selects this surface only when GOOS=darwin.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

var sleepMac = time.Sleep

func registerMac(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		macAddFunc{}, macDeleteFunc{}, macGetentFunc{}, macChuidFunc{},
		macChgidFunc{}, macChshellFunc{}, macChhomeFunc{}, macChfullnameFunc{},
		macChgroupsFunc{}, macInfoFunc{}, macPrimaryGroupFunc{}, macListGroupsFunc{},
		macListUsersFunc{}, macRenameFunc{}, macGetAutoLoginFunc{},
		macEnableAutoLoginFunc{}, macDisableAutoLoginFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

func runMac(ctx context.Context, rt *runtime.Runtime, command process.Command) process.CommandResult {
	return rt.Runner.Run(ctx, command)
}

func runMacArgv(ctx context.Context, rt *runtime.Runtime, argv ...string) process.CommandResult {
	return runMac(ctx, rt, runtime.Command(argv...))
}

func legacyDSCL(rt *runtime.Runtime) bool {
	if rt == nil || rt.Facts == nil {
		return false
	}
	version := rt.Facts.OS().Version
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 || parts[0] != "10" {
		return false
	}
	minor := 0
	if _, err := fmt.Sscanf(parts[1], "%d", &minor); err != nil {
		return false
	}
	return minor < 8
}

func dsclPath(rt *runtime.Runtime, path string) string {
	if !legacyDSCL(rt) && strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "/Local/Default/") {
		return "/Local/Default" + path
	}
	return path
}

func dscl(ctx context.Context, rt *runtime.Runtime, values []string, ctype string) process.CommandResult {
	if ctype == "" {
		ctype = "create"
	}
	source := "localhost"
	if legacyDSCL(rt) {
		source = "."
	}
	argv := []string{"dscl", source, "-" + ctype}
	for i, value := range values {
		if i == 0 {
			value = dsclPath(rt, value)
		}
		argv = append(argv, value)
	}
	return runMacArgv(ctx, rt, argv...)
}

func userWhitespace(name string) bool {
	return strings.IndexFunc(name, unicode.IsSpace) >= 0
}

func parseRecords(output string) []map[string]string {
	var records []map[string]string
	current := map[string]string{}
	flush := func() {
		if len(current) > 0 {
			records = append(records, current)
			current = map[string]string{}
		}
	}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		current[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	flush()
	return records
}

func recordInt(record map[string]string, key string) int {
	var value int
	_, _ = fmt.Sscanf(record[key], "%d", &value)
	return value
}

func userRecordInfo(record map[string]string) map[string]any {
	name := record["name"]
	if name == "" {
		name = record["RecordName"]
	}
	fullname := record["gecos"]
	if fullname == "" {
		fullname = record["RealName"]
	}
	return map[string]any{
		"gid":      recordInt(record, "gid"),
		"groups":   []string{},
		"home":     record["dir"],
		"name":     name,
		"shell":    record["shell"],
		"uid":      recordInt(record, "uid"),
		"fullname": fullname,
	}
}

func macUserInfo(ctx context.Context, rt *runtime.Runtime, name string) map[string]any {
	res := runMacArgv(ctx, rt, "dscacheutil", "-q", "user", "-a", "name", name)
	if res.Err != nil || res.ExitCode != 0 {
		return map[string]any{}
	}
	for _, record := range parseRecords(string(res.Stdout)) {
		if record["name"] == name || record["RecordName"] == name {
			info := userRecordInfo(record)
			groups := macUserGroups(ctx, rt, name)
			info["groups"] = groups
			return info
		}
	}
	return map[string]any{}
}

func macUserGroups(ctx context.Context, rt *runtime.Runtime, name string) []string {
	res := runMacArgv(ctx, rt, "id", "-Gn", name)
	if res.Err != nil || res.ExitCode != 0 {
		return []string{}
	}
	return strings.Fields(string(res.Stdout))
}

func macPrimaryGroup(ctx context.Context, rt *runtime.Runtime, name string) string {
	res := runMacArgv(ctx, rt, "id", "-g", "-n", name)
	if res.Err != nil || res.ExitCode != 0 {
		return ""
	}
	return strings.TrimSpace(string(res.Stdout))
}

func firstAvailableUID(ctx context.Context, rt *runtime.Runtime) int {
	res := runMacArgv(ctx, rt, "dscacheutil", "-q", "user")
	used := map[int]bool{}
	if res.Err == nil && res.ExitCode == 0 {
		for _, record := range parseRecords(string(res.Stdout)) {
			used[recordInt(record, "uid")] = true
		}
	}
	for uid := 501; uid < 1<<24; uid++ {
		if !used[uid] {
			return uid
		}
	}
	return 501
}

func macAllUsers(ctx context.Context, rt *runtime.Runtime) []map[string]any {
	res := runMacArgv(ctx, rt, "dscacheutil", "-q", "user")
	if res.Err != nil || res.ExitCode != 0 {
		return nil
	}
	var out []map[string]any
	for _, record := range parseRecords(string(res.Stdout)) {
		if record["name"] == "" {
			continue
		}
		info := userRecordInfo(record)
		info["groups"] = macUserGroups(ctx, rt, record["name"])
		out = append(out, info)
	}
	return out
}

// ---------------------------------------------------------------------------
// add/delete

type macAddArgs struct {
	Name       string   `statekit:"required"`
	UID        *int     `statekit:"name=uid"`
	GID        *int     `statekit:"name=gid"`
	Groups     []string `statekit:"name=groups"`
	Home       *string  `statekit:"name=home"`
	Shell      *string  `statekit:"name=shell"`
	Fullname   *string  `statekit:"name=fullname"`
	CreateHome *bool    `statekit:"name=createhome"`
}

type macAddFunc struct{}

func (macAddFunc) Name() string        { return "user.add" }
func (macAddFunc) Args() any           { return macAddArgs{} }
func (macAddFunc) Platforms() []string { return []string{"darwin"} }
func (macAddFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	a := args.(*macAddArgs)
	if len(macUserInfo(ctx, rt, a.Name)) > 0 {
		return nil, fmt.Errorf("User '%s' already exists", a.Name)
	}
	if userWhitespace(a.Name) {
		return nil, fmt.Errorf("Username cannot contain whitespace")
	}
	uid := firstAvailableUID(ctx, rt)
	if a.UID != nil {
		uid = *a.UID
	}
	gid := 20
	if a.GID != nil {
		gid = *a.GID
	}
	home := "/Users/" + a.Name
	if a.Home != nil {
		home = *a.Home
	}
	shell := "/bin/bash"
	if a.Shell != nil {
		shell = *a.Shell
	}
	fullname := ""
	if a.Fullname != nil {
		fullname = *a.Fullname
	}
	if uid < 0 {
		return nil, fmt.Errorf("uid must be an integer")
	}
	if gid < 0 {
		return nil, fmt.Errorf("gid must be an integer")
	}
	path := "/Users/" + a.Name
	_ = dscl(ctx, rt, []string{path, "UniqueID", fmt.Sprint(uid)}, "create")
	_ = dscl(ctx, rt, []string{path, "PrimaryGroupID", fmt.Sprint(gid)}, "create")
	_ = dscl(ctx, rt, []string{path, "UserShell", shell}, "create")
	_ = dscl(ctx, rt, []string{path, "NFSHomeDirectory", home}, "create")
	_ = dscl(ctx, rt, []string{path, "RealName", fullname}, "create")
	createHome := true
	if a.CreateHome != nil {
		createHome = *a.CreateHome
	}
	if createHome {
		if err := rt.FS.MkdirAll(home, 0o755); err != nil {
			return nil, err
		}
	}
	sleepMac(time.Second)
	if len(a.Groups) > 0 {
		_, err := macChgroupsImpl(ctx, rt, a.Name, a.Groups, false)
		if err != nil {
			return nil, err
		}
	}
	return true, nil
}

type macDeleteArgs struct {
	Name   string `statekit:"required"`
	Remove bool   `statekit:"name=remove"`
	Force  bool   `statekit:"name=force"`
}

type macDeleteFunc struct{}

func (macDeleteFunc) Name() string        { return "user.delete" }
func (macDeleteFunc) Args() any           { return macDeleteArgs{} }
func (macDeleteFunc) Platforms() []string { return []string{"darwin"} }
func (macDeleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	a := args.(*macDeleteArgs)
	if userWhitespace(a.Name) {
		return nil, fmt.Errorf("Username cannot contain whitespace")
	}
	info := macUserInfo(ctx, rt, a.Name)
	if len(info) == 0 {
		return true, nil
	}
	_, _ = macChgroupsImpl(ctx, rt, a.Name, []string{}, false)
	ret := dscl(ctx, rt, []string{"/Users/" + a.Name}, "delete")
	if ret.ExitCode == 0 && a.Remove {
		if home, ok := info["home"].(string); ok && home != "" {
			if err := rt.FS.RemoveAll(home); err != nil {
				return nil, err
			}
		}
	}
	return ret.ExitCode == 0, nil
}

// ---------------------------------------------------------------------------
// getent/info/listing

type macGetentArgs struct {
	Refresh bool `statekit:"name=refresh"`
}
type macGetentFunc struct{}

func (macGetentFunc) Name() string        { return "user.getent" }
func (macGetentFunc) Args() any           { return macGetentArgs{} }
func (macGetentFunc) Platforms() []string { return []string{"darwin"} }
func (macGetentFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	a := args.(*macGetentArgs)
	if !a.Refresh {
		macUserCacheMu.Lock()
		cached := macUserCache
		macUserCacheMu.Unlock()
		if cached != nil {
			return cached, nil
		}
	}
	users := macAllUsers(ctx, rt)
	macUserCacheMu.Lock()
	macUserCache = users
	macUserCacheMu.Unlock()
	return users, nil
}

var (
	macUserCache   []map[string]any
	macUserCacheMu sync.Mutex
)

type macInfoArgs struct {
	Name string `statekit:"required"`
}
type macInfoFunc struct{}

func (macInfoFunc) Name() string        { return "user.info" }
func (macInfoFunc) Args() any           { return macInfoArgs{} }
func (macInfoFunc) Platforms() []string { return []string{"darwin"} }
func (macInfoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	return macUserInfo(ctx, rt, args.(*macInfoArgs).Name), nil
}

type macListUsersArgs struct{}
type macListUsersFunc struct{}

func (macListUsersFunc) Name() string        { return "user.list_users" }
func (macListUsersFunc) Args() any           { return macListUsersArgs{} }
func (macListUsersFunc) Platforms() []string { return []string{"darwin"} }
func (macListUsersFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	ret := dscl(ctx, rt, []string{"/users"}, "list")
	if ret.Err != nil || ret.ExitCode != 0 {
		return []string{}, nil
	}
	return strings.Fields(string(ret.Stdout)), nil
}

// ---------------------------------------------------------------------------
// attribute changes

type macChuidArgs struct {
	Name string `statekit:"required"`
	UID  int    `statekit:"required,name=uid"`
}
type macChuidFunc struct{}

func (macChuidFunc) Name() string        { return "user.chuid" }
func (macChuidFunc) Args() any           { return macChuidArgs{} }
func (macChuidFunc) Platforms() []string { return []string{"darwin"} }
func (macChuidFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	a := args.(*macChuidArgs)
	info := macUserInfo(ctx, rt, a.Name)
	if len(info) == 0 {
		return nil, fmt.Errorf("User '%s' does not exist", a.Name)
	}
	if info["uid"] == a.UID {
		return true, nil
	}
	_ = dscl(ctx, rt, []string{"/Users/" + a.Name, "UniqueID", fmt.Sprint(info["uid"]), fmt.Sprint(a.UID)}, "change")
	sleepMac(time.Second)
	return macUserInfo(ctx, rt, a.Name)["uid"] == a.UID, nil
}

type macChgidArgs struct {
	Name string `statekit:"required"`
	GID  int    `statekit:"required,name=gid"`
}
type macChgidFunc struct{}

func (macChgidFunc) Name() string        { return "user.chgid" }
func (macChgidFunc) Args() any           { return macChgidArgs{} }
func (macChgidFunc) Platforms() []string { return []string{"darwin"} }
func (macChgidFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	a := args.(*macChgidArgs)
	info := macUserInfo(ctx, rt, a.Name)
	if len(info) == 0 {
		return nil, fmt.Errorf("User '%s' does not exist", a.Name)
	}
	if info["gid"] == a.GID {
		return true, nil
	}
	_ = dscl(ctx, rt, []string{"/Users/" + a.Name, "PrimaryGroupID", fmt.Sprint(info["gid"]), fmt.Sprint(a.GID)}, "change")
	sleepMac(time.Second)
	return macUserInfo(ctx, rt, a.Name)["gid"] == a.GID, nil
}

type macChshellArgs struct {
	Name  string `statekit:"required"`
	Shell string `statekit:"required,name=shell"`
}
type macChshellFunc struct{}

func (macChshellFunc) Name() string        { return "user.chshell" }
func (macChshellFunc) Args() any           { return macChshellArgs{} }
func (macChshellFunc) Platforms() []string { return []string{"darwin"} }
func (macChshellFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	a := args.(*macChshellArgs)
	info := macUserInfo(ctx, rt, a.Name)
	if len(info) == 0 {
		return nil, fmt.Errorf("User '%s' does not exist", a.Name)
	}
	if info["shell"] == a.Shell {
		return true, nil
	}
	_ = dscl(ctx, rt, []string{"/Users/" + a.Name, "UserShell", fmt.Sprint(info["shell"]), a.Shell}, "change")
	sleepMac(time.Second)
	return macUserInfo(ctx, rt, a.Name)["shell"] == a.Shell, nil
}

type macChhomeArgs struct {
	Name string `statekit:"required"`
	Home string `statekit:"required,name=home"`
}
type macChhomeFunc struct{}

func (macChhomeFunc) Name() string        { return "user.chhome" }
func (macChhomeFunc) Args() any           { return macChhomeArgs{} }
func (macChhomeFunc) Platforms() []string { return []string{"darwin"} }
func (macChhomeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	a := args.(*macChhomeArgs)
	info := macUserInfo(ctx, rt, a.Name)
	if len(info) == 0 {
		return nil, fmt.Errorf("User '%s' does not exist", a.Name)
	}
	if info["home"] == a.Home {
		return true, nil
	}
	_ = dscl(ctx, rt, []string{"/Users/" + a.Name, "NFSHomeDirectory", fmt.Sprint(info["home"]), a.Home}, "change")
	sleepMac(time.Second)
	return macUserInfo(ctx, rt, a.Name)["home"] == a.Home, nil
}

type macChfullnameArgs struct {
	Name     string `statekit:"required"`
	Fullname string `statekit:"required,name=fullname"`
}
type macChfullnameFunc struct{}

func (macChfullnameFunc) Name() string        { return "user.chfullname" }
func (macChfullnameFunc) Args() any           { return macChfullnameArgs{} }
func (macChfullnameFunc) Platforms() []string { return []string{"darwin"} }
func (macChfullnameFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	a := args.(*macChfullnameArgs)
	info := macUserInfo(ctx, rt, a.Name)
	if len(info) == 0 {
		return nil, fmt.Errorf("User '%s' does not exist", a.Name)
	}
	if info["fullname"] == a.Fullname {
		return true, nil
	}
	_ = dscl(ctx, rt, []string{"/Users/" + a.Name, "RealName", a.Fullname}, "create")
	sleepMac(time.Second)
	return macUserInfo(ctx, rt, a.Name)["fullname"] == a.Fullname, nil
}

// ---------------------------------------------------------------------------
// groups

type macChgroupsArgs struct {
	Name   string   `statekit:"required"`
	Groups []string `statekit:"required,name=groups"`
	Append bool     `statekit:"name=append"`
}
type macChgroupsFunc struct{}

func (macChgroupsFunc) Name() string        { return "user.chgroups" }
func (macChgroupsFunc) Args() any           { return macChgroupsArgs{} }
func (macChgroupsFunc) Platforms() []string { return []string{"darwin"} }
func (macChgroupsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	a := args.(*macChgroupsArgs)
	return macChgroupsImpl(ctx, rt, a.Name, a.Groups, a.Append)
}

func macChgroupsImpl(ctx context.Context, rt *runtime.Runtime, name string, groups []string, appendOnly bool) (bool, error) {
	uinfo := macUserInfo(ctx, rt, name)
	if len(uinfo) == 0 {
		return false, fmt.Errorf("User '%s' does not exist", name)
	}
	for _, group := range groups {
		if userWhitespace(group) {
			return false, fmt.Errorf("Invalid group name(s): %s", group)
		}
	}
	desired := map[string]bool{}
	for _, group := range groups {
		if group != "" {
			desired[group] = true
		}
	}
	if primary := macPrimaryGroup(ctx, rt, name); primary != "" {
		desired[primary] = true
	}
	current := map[string]bool{}
	for _, group := range macUserGroups(ctx, rt, name) {
		current[group] = true
	}
	same := len(current) == len(desired)
	if same {
		for group := range desired {
			if !current[group] {
				same = false
				break
			}
		}
	}
	if same {
		return true, nil
	}
	for group := range desired {
		if !current[group] {
			_ = dscl(ctx, rt, []string{"/Groups/" + group, "GroupMembership", name}, "append")
		}
	}
	if !appendOnly {
		for group := range current {
			if !desired[group] {
				_ = dscl(ctx, rt, []string{"/Groups/" + group, "GroupMembership", name}, "delete")
			}
		}
	}
	sleepMac(time.Second)
	final := map[string]bool{}
	for _, group := range macUserGroups(ctx, rt, name) {
		final[group] = true
	}
	if len(final) != len(desired) {
		return false, nil
	}
	for group := range desired {
		if !final[group] {
			return false, nil
		}
	}
	return true, nil
}

type macPrimaryGroupArgs struct {
	Name string `statekit:"required"`
}
type macPrimaryGroupFunc struct{}

func (macPrimaryGroupFunc) Name() string        { return "user.primary_group" }
func (macPrimaryGroupFunc) Args() any           { return macPrimaryGroupArgs{} }
func (macPrimaryGroupFunc) Platforms() []string { return []string{"darwin"} }
func (macPrimaryGroupFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	return macPrimaryGroup(ctx, rt, args.(*macPrimaryGroupArgs).Name), nil
}

type macListGroupsArgs struct {
	Name string `statekit:"required"`
}
type macListGroupsFunc struct{}

func (macListGroupsFunc) Name() string        { return "user.list_groups" }
func (macListGroupsFunc) Args() any           { return macListGroupsArgs{} }
func (macListGroupsFunc) Platforms() []string { return []string{"darwin"} }
func (macListGroupsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	return macUserGroups(ctx, rt, args.(*macListGroupsArgs).Name), nil
}

// ---------------------------------------------------------------------------
// rename and auto-login

type macRenameArgs struct {
	Name    string `statekit:"required"`
	NewName string `statekit:"required,name=new_name"`
}
type macRenameFunc struct{}

func (macRenameFunc) Name() string        { return "user.rename" }
func (macRenameFunc) Args() any           { return macRenameArgs{} }
func (macRenameFunc) Platforms() []string { return []string{"darwin"} }
func (macRenameFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	a := args.(*macRenameArgs)
	if len(macUserInfo(ctx, rt, a.Name)) == 0 {
		return nil, fmt.Errorf("User '%s' does not exist", a.Name)
	}
	if len(macUserInfo(ctx, rt, a.NewName)) > 0 {
		return nil, fmt.Errorf("User '%s' already exists", a.NewName)
	}
	_ = dscl(ctx, rt, []string{"/Users/" + a.Name, "RecordName", a.Name, a.NewName}, "change")
	sleepMac(time.Second)
	return macUserInfo(ctx, rt, a.NewName)["name"] == a.NewName, nil
}

type macGetAutoLoginArgs struct{}
type macGetAutoLoginFunc struct{}

func (macGetAutoLoginFunc) Name() string        { return "user.get_auto_login" }
func (macGetAutoLoginFunc) Args() any           { return macGetAutoLoginArgs{} }
func (macGetAutoLoginFunc) Platforms() []string { return []string{"darwin"} }
func (macGetAutoLoginFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	ret := runMacArgv(ctx, rt, "defaults", "read", "/Library/Preferences/com.apple.loginwindow.plist", "autoLoginUser")
	if ret.ExitCode != 0 || ret.Err != nil {
		return false, nil
	}
	return strings.TrimSpace(string(ret.Stdout)), nil
}

type macEnableAutoLoginArgs struct {
	Name     string `statekit:"required"`
	Password string `statekit:"required"`
}
type macEnableAutoLoginFunc struct{}

func (macEnableAutoLoginFunc) Name() string        { return "user.enable_auto_login" }
func (macEnableAutoLoginFunc) Args() any           { return macEnableAutoLoginArgs{} }
func (macEnableAutoLoginFunc) Platforms() []string { return []string{"darwin"} }
func (macEnableAutoLoginFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	a := args.(*macEnableAutoLoginArgs)
	_ = runMacArgv(ctx, rt, "defaults", "write", "/Library/Preferences/com.apple.loginwindow.plist", "autoLoginUser", a.Name)
	current, _ := macGetAutoLoginFunc{}.Execute(ctx, rt, macGetAutoLoginArgs{})
	password, err := kcpassword(a.Password)
	if err != nil {
		return nil, err
	}
	if err := rt.FS.WriteFile("/etc/kcpassword", password, 0o600); err != nil {
		return nil, err
	}
	if text, ok := current.(string); ok {
		return strings.EqualFold(text, a.Name), nil
	}
	return current, nil
}

func kcpassword(password string) ([]byte, error) {
	key := []byte{125, 137, 82, 35, 210, 188, 221, 234, 163, 185, 31}
	keyLen := len(key) + 1
	data := append([]byte(password), 0)
	if remainder := len(data) % keyLen; remainder > 0 {
		data = append(data, make([]byte, keyLen-remainder)...)
	}
	for chunk := 0; chunk < len(data); chunk += len(key) {
		for index := chunk; index < chunk+len(key) && index < len(data); index++ {
			data[index] ^= key[index-chunk]
		}
	}
	return data, nil
}

type macDisableAutoLoginArgs struct{}
type macDisableAutoLoginFunc struct{}

func (macDisableAutoLoginFunc) Name() string        { return "user.disable_auto_login" }
func (macDisableAutoLoginFunc) Args() any           { return macDisableAutoLoginArgs{} }
func (macDisableAutoLoginFunc) Platforms() []string { return []string{"darwin"} }
func (macDisableAutoLoginFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverMacUser(&res, &err)
	_ = runMac(ctx, rt, process.Command{Name: "rm -f /etc/kcpassword", Shell: true})
	_ = runMacArgv(ctx, rt, "defaults", "delete", "/Library/Preferences/com.apple.loginwindow.plist", "autoLoginUser")
	current, _ := macGetAutoLoginFunc{}.Execute(ctx, rt, macGetAutoLoginArgs{})
	if value, ok := current.(string); ok {
		return value == "", nil
	}
	return current == false || current == nil, nil
}

func recoverMacUser(res *any, errPtr *error) {
	if r := recover(); r != nil {
		if err, ok := r.(error); ok {
			*errPtr = err
			return
		}
		panic(r)
	}
}
