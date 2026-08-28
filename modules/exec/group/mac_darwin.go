//go:build darwin

package group

// Darwin implementation of Salt's mac_group virtual provider. It keeps the
// public virtual names group.* and is selected by group.Register only on
// GOOS=darwin.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"unicode"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func registerMac(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		macAddFunc{}, macDeleteFunc{}, macAddUserFunc{}, macDelUserFunc{},
		macMembersFunc{}, macInfoFunc{}, macGetentFunc{}, macChgidFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

func macGroupRun(ctx context.Context, rt *runtime.Runtime, argv ...string) process.CommandResult {
	return rt.Runner.Run(ctx, runtime.Command(argv...))
}

func groupWhitespace(name string) bool {
	return strings.IndexFunc(name, unicode.IsSpace) >= 0
}

func groupRecordInfo(record map[string]string) map[string]any {
	members := strings.Fields(record["users"])
	if record["users"] == "" {
		members = []string{}
	}
	gid := 0
	_, _ = fmt.Sscanf(record["gid"], "%d", &gid)
	return map[string]any{
		"name":    record["name"],
		"gid":     gid,
		"passwd":  record["password"],
		"members": members,
	}
}

func macGroupInfo(ctx context.Context, rt *runtime.Runtime, name string) map[string]any {
	result := macGroupRun(ctx, rt, "dscacheutil", "-q", "group", "-a", "name", name)
	if result.Err != nil || result.ExitCode != 0 {
		return map[string]any{}
	}
	for _, record := range parseGroupRecords(string(result.Stdout)) {
		if record["name"] == name {
			return groupRecordInfo(record)
		}
	}
	return map[string]any{}
}

func parseGroupRecords(output string) []map[string]string {
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

func macAllGroups(ctx context.Context, rt *runtime.Runtime) []map[string]any {
	result := macGroupRun(ctx, rt, "dscacheutil", "-q", "group")
	if result.Err != nil || result.ExitCode != 0 {
		return nil
	}
	var out []map[string]any
	for _, record := range parseGroupRecords(string(result.Stdout)) {
		if record["name"] == "" || strings.HasPrefix(record["name"], "_") {
			continue
		}
		out = append(out, groupRecordInfo(record))
	}
	return out
}

func macGroupIDs(ctx context.Context, rt *runtime.Runtime) map[string]bool {
	result := macGroupRun(ctx, rt, "dscacheutil", "-q", "group")
	ids := map[string]bool{}
	if result.Err != nil || result.ExitCode != 0 {
		return ids
	}
	for _, record := range parseGroupRecords(string(result.Stdout)) {
		if gid := record["gid"]; gid != "" {
			ids[gid] = true
		}
	}
	return ids
}

// ---------------------------------------------------------------------------
// add/delete

type macAddArgs struct {
	Name string `statekit:"required"`
	GID  *int   `statekit:"name=gid"`
}

type macAddFunc struct{}

func (macAddFunc) Name() string        { return "group.add" }
func (macAddFunc) Args() any           { return macAddArgs{} }
func (macAddFunc) Platforms() []string { return []string{"darwin"} }
func (macAddFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacGroup(&res, &err)
	a := args.(*macAddArgs)
	if len(macGroupInfo(ctx, rt, a.Name)) > 0 {
		return nil, fmt.Errorf("Group '%s' already exists", a.Name)
	}
	if groupWhitespace(a.Name) {
		return nil, fmt.Errorf("Group name cannot contain whitespace")
	}
	if strings.HasPrefix(a.Name, "_") {
		return nil, fmt.Errorf("Salt will not create groups beginning with underscores")
	}
	if a.GID != nil && *a.GID < 0 {
		return nil, fmt.Errorf("gid must be an integer")
	}
	gid := ""
	if a.GID != nil {
		gid = fmt.Sprint(*a.GID)
		if macGroupIDs(ctx, rt)[gid] {
			return nil, fmt.Errorf("gid '%s' already exists", gid)
		}
	}
	argv := []string{"dseditgroup", "-o", "create"}
	if gid != "" && gid != "0" {
		argv = append(argv, "-i", gid)
	}
	argv = append(argv, a.Name)
	return macGroupRun(ctx, rt, argv...).ExitCode == 0, nil
}

type macDeleteArgs struct {
	Name string `statekit:"required"`
}
type macDeleteFunc struct{}

func (macDeleteFunc) Name() string        { return "group.delete" }
func (macDeleteFunc) Args() any           { return macDeleteArgs{} }
func (macDeleteFunc) Platforms() []string { return []string{"darwin"} }
func (macDeleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacGroup(&res, &err)
	a := args.(*macDeleteArgs)
	if groupWhitespace(a.Name) {
		return nil, fmt.Errorf("Group name cannot contain whitespace")
	}
	if strings.HasPrefix(a.Name, "_") {
		return nil, fmt.Errorf("Salt will not remove groups beginning with underscores")
	}
	if len(macGroupInfo(ctx, rt, a.Name)) == 0 {
		return true, nil
	}
	return macGroupRun(ctx, rt, "dseditgroup", "-o", "delete", a.Name).ExitCode == 0, nil
}

// ---------------------------------------------------------------------------
// membership

type macAddUserArgs struct {
	Group string `statekit:"required,name=group"`
	Name  string `statekit:"required,name=name"`
}
type macAddUserFunc struct{}

func (macAddUserFunc) Name() string        { return "group.adduser" }
func (macAddUserFunc) Args() any           { return macAddUserArgs{} }
func (macAddUserFunc) Platforms() []string { return []string{"darwin"} }
func (macAddUserFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacGroup(&res, &err)
	a := args.(*macAddUserArgs)
	command := fmt.Sprintf("dscl . -merge /Groups/%s GroupMembership %s", a.Group, a.Name)
	return rt.Runner.Run(ctx, process.Command{Name: command, Shell: true}).ExitCode == 0, nil
}

type macDelUserFunc struct{}

func (macDelUserFunc) Name() string        { return "group.deluser" }
func (macDelUserFunc) Args() any           { return macAddUserArgs{} }
func (macDelUserFunc) Platforms() []string { return []string{"darwin"} }
func (macDelUserFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacGroup(&res, &err)
	a := args.(*macAddUserArgs)
	command := fmt.Sprintf("dscl . -delete /Groups/%s GroupMembership %s", a.Group, a.Name)
	return rt.Runner.Run(ctx, process.Command{Name: command, Shell: true}).ExitCode == 0, nil
}

type macMembersArgs struct {
	Name    string   `statekit:"required"`
	Members []string `statekit:"required,name=members_list"`
}
type macMembersFunc struct{}

func (macMembersFunc) Name() string        { return "group.members" }
func (macMembersFunc) Args() any           { return macMembersArgs{} }
func (macMembersFunc) Platforms() []string { return []string{"darwin"} }
func (macMembersFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacGroup(&res, &err)
	a := args.(*macMembersArgs)
	info := macGroupInfo(ctx, rt, a.Name)
	if name, ok := info["name"].(string); !ok || name != a.Name {
		return false, nil
	}
	deleteCommand := fmt.Sprintf("/usr/bin/dscl . -delete /Groups/%s GroupMembership", a.Name)
	if rt.Runner.Run(ctx, process.Command{Name: deleteCommand, Shell: true}).ExitCode != 0 {
		return false, nil
	}
	for _, member := range a.Members {
		command := fmt.Sprintf("/usr/bin/dscl . -merge /Groups/%s GroupMembership %s", a.Name, member)
		if rt.Runner.Run(ctx, process.Command{Name: command, Shell: true}).ExitCode != 0 {
			return false, nil
		}
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// info/getent/chgid

type macInfoArgs struct {
	Name string `statekit:"required"`
}
type macInfoFunc struct{}

func (macInfoFunc) Name() string        { return "group.info" }
func (macInfoFunc) Args() any           { return macInfoArgs{} }
func (macInfoFunc) Platforms() []string { return []string{"darwin"} }
func (macInfoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacGroup(&res, &err)
	a := args.(*macInfoArgs)
	if groupWhitespace(a.Name) {
		return nil, fmt.Errorf("Group name cannot contain whitespace")
	}
	return macGroupInfo(ctx, rt, a.Name), nil
}

type macGetentArgs struct {
	Refresh bool `statekit:"name=refresh"`
}
type macGetentFunc struct{}

var (
	macGroupCache   []map[string]any
	macGroupCacheMu sync.Mutex
)

func (macGetentFunc) Name() string        { return "group.getent" }
func (macGetentFunc) Args() any           { return macGetentArgs{} }
func (macGetentFunc) Platforms() []string { return []string{"darwin"} }
func (macGetentFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacGroup(&res, &err)
	a := args.(*macGetentArgs)
	if !a.Refresh {
		macGroupCacheMu.Lock()
		cached := macGroupCache
		macGroupCacheMu.Unlock()
		if cached != nil {
			return cached, nil
		}
	}
	groups := macAllGroups(ctx, rt)
	macGroupCacheMu.Lock()
	macGroupCache = groups
	macGroupCacheMu.Unlock()
	return groups, nil
}

type macChgidArgs struct {
	Name string `statekit:"required"`
	GID  int    `statekit:"required,name=gid"`
}
type macChgidFunc struct{}

func (macChgidFunc) Name() string        { return "group.chgid" }
func (macChgidFunc) Args() any           { return macChgidArgs{} }
func (macChgidFunc) Platforms() []string { return []string{"darwin"} }
func (macChgidFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacGroup(&res, &err)
	a := args.(*macChgidArgs)
	info := macGroupInfo(ctx, rt, a.Name)
	if len(info) == 0 {
		return nil, fmt.Errorf("Group '%s' does not exist", a.Name)
	}
	if info["gid"] == a.GID {
		return true, nil
	}
	return macGroupRun(ctx, rt, "dseditgroup", "-o", "edit", "-i", fmt.Sprint(a.GID), a.Name).ExitCode == 0, nil
}

func recoverMacGroup(res *any, errPtr *error) {
	if r := recover(); r != nil {
		if err, ok := r.(error); ok {
			*errPtr = err
			return
		}
		panic(r)
	}
}
