//go:build windows

package group

// R7.5 mock tests for the Windows group virtual provider, mapped onto
// saltstack/salt/modules/win_groupadd.py @ pinned revision 8b63e700637e
// and tests/unit/modules/test_win_groupadd.py: the add/delete ladder
// (exists short-circuit False, missing-group delete False), info shape
// (pytest "salt"/HOST\steve fixture) incl. the exit-3 missing sentinel
// and the one-member JSON string shape, getent/list_groups context
// caching with refresh, adduser/deluser idempotence (already-member
// and not-a-member False), the exact Add/Remove-LocalGroupMember
// cmdlet scripts with -Confirm:$false on removal and single-quote
// escaping, the members reconciliation (add-then-remove ordering,
// correct-membership True without mutation) and the registry matrix.
// PowerShell scripts are asserted after UTF-16LE/base64 decoding; no
// real powershell.exe runs. This file compiles and runs only on
// Windows (verified off-platform via GOOS=windows go test -c).

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func mustDecodeWinGroupScript(command process.Command) string {
	raw, err := base64.StdEncoding.DecodeString(command.Args[3])
	if err != nil {
		panic(err)
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	return strings.TrimSuffix(string(utf16.Decode(units)), "\x00")
}

// winGrpStoreRunner simulates the Get/New/Remove-LocalGroup( Member)
// cmdlet surface against a live group + membership store.
type winGrpStoreRunner struct {
	groups       map[string][]string // group name → members
	descriptions map[string]string
	failSubstr   string // decoded script substring forced to exit 1
	launchErr    error  // non-nil: powershell.exe fails to launch
	calls        []process.Command
	scripts      []string
}

func newWinGrpStoreRunner() *winGrpStoreRunner {
	return &winGrpStoreRunner{
		groups: map[string][]string{
			"Administrators": {"HOST\\Administrator"},
			"salt":           {"HOST\\steve"},
		},
		descriptions: map[string]string{"Administrators": "built-in", "salt": "salt group"},
	}
}

func (r *winGrpStoreRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if r.launchErr != nil {
		return process.CommandResult{ExitCode: -1, Err: r.launchErr}
	}
	script := mustDecodeWinGroupScript(command)
	r.scripts = append(r.scripts, script)
	if r.failSubstr != "" && strings.Contains(script, r.failSubstr) {
		return process.CommandResult{ExitCode: 1, Stderr: []byte("group store refused")}
	}
	switch {
	case strings.HasPrefix(script, "$g=Get-LocalGroup -Name "):
		name := winGrpQuoted(script, "$g=Get-LocalGroup -Name ")
		if _, ok := r.groups[name]; !ok {
			return process.CommandResult{ExitCode: 3, Stderr: []byte("group not found")}
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(`{"name":"` + name + `","description":"` + r.descriptions[name] + `"}`)}
	case strings.Contains(script, "Get-LocalGroupMember -Group "):
		group := winGrpQuoted(script, "Get-LocalGroupMember -Group ")
		members := r.groups[group]
		if len(members) == 0 {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(`[]`)}
		}
		if len(members) == 1 {
			// ConvertTo-Json collapses a one-element pipeline to a string.
			return process.CommandResult{ExitCode: 0, Stdout: []byte(`"` + members[0] + `"`)}
		}
		quoted := make([]string, 0, len(members))
		for _, member := range members {
			quoted = append(quoted, `"`+member+`"`)
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte("[" + strings.Join(quoted, ",") + "]")}
	case strings.Contains(script, "@(Get-LocalGroup | Select-Object -ExpandProperty Name)"):
		names := make([]string, 0, len(r.groups))
		for name := range r.groups {
			names = append(names, name)
		}
		sort.Strings(names)
		quoted := make([]string, 0, len(names))
		for _, name := range names {
			quoted = append(quoted, `"`+name+`"`)
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte("[" + strings.Join(quoted, ",") + "]")}
	case strings.Contains(script, "New-LocalGroup -Name "):
		name := winGrpQuoted(script, "New-LocalGroup -Name ")
		r.groups[name] = nil
		return process.CommandResult{ExitCode: 0}
	case strings.Contains(script, "Remove-LocalGroup -Name "):
		name := winGrpQuoted(script, "Remove-LocalGroup -Name ")
		delete(r.groups, name)
		return process.CommandResult{ExitCode: 0}
	case strings.Contains(script, "Add-LocalGroupMember -Group "):
		r.winGrpApplyMembership(script, true)
		return process.CommandResult{ExitCode: 0}
	case strings.Contains(script, "Remove-LocalGroupMember -Group "):
		r.winGrpApplyMembership(script, false)
		return process.CommandResult{ExitCode: 0}
	}
	return process.CommandResult{ExitCode: 0}
}

// winGrpApplyMembership handles multi-statement reconciliation scripts
// ("Add ...;Add ...;Remove ...") one cmdlet at a time.
func (r *winGrpStoreRunner) winGrpApplyMembership(script string, add bool) {
	for _, statement := range strings.Split(script, ";") {
		switch {
		case strings.Contains(statement, "Add-LocalGroupMember -Group "):
			group, member := winGrpGroupMember(statement, "Add-LocalGroupMember -Group ")
			r.groups[group] = append(r.groups[group], member)
		case strings.Contains(statement, "Remove-LocalGroupMember -Group "):
			group, member := winGrpGroupMember(statement, "Remove-LocalGroupMember -Group ")
			var kept []string
			for _, existing := range r.groups[group] {
				if existing != member {
					kept = append(kept, existing)
				}
			}
			r.groups[group] = kept
		}
	}
}

// winGrpQuoted extracts the ”-quoted literal following prefix,
// unescaping doubled single quotes.
func winGrpQuoted(script, prefix string) string {
	rest := script[strings.Index(script, prefix)+len(prefix):]
	if !strings.HasPrefix(rest, "'") {
		panic("winGrpQuoted: missing opening quote in " + rest)
	}
	rest = rest[1:]
	var out strings.Builder
	for i := 0; i < len(rest); i++ {
		if rest[i] == '\'' {
			if i+1 < len(rest) && rest[i+1] == '\'' {
				out.WriteByte('\'')
				i++
				continue
			}
			break
		}
		out.WriteByte(rest[i])
	}
	return out.String()
}

// winGrpGroupMember extracts the -Group/-Member quoted pair.
func winGrpGroupMember(statement, marker string) (string, string) {
	rest := statement[strings.Index(statement, marker)+len(marker):]
	group := winGrpQuoted(rest, "")
	rest = rest[strings.Index(rest, "-Member "):]
	return group, winGrpQuoted(rest, "-Member ")
}

func winGrpRT(runner *winGrpStoreRunner) *runtime.Runtime {
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
}

// winGrpResetCache isolates the package-global getent/list cache.
func winGrpResetCache(t *testing.T) {
	t.Helper()
	windowsGroupCacheMu.Lock()
	saved := windowsGroupCache
	windowsGroupCache = nil
	windowsGroupCacheMu.Unlock()
	t.Cleanup(func() {
		windowsGroupCacheMu.Lock()
		windowsGroupCache = saved
		windowsGroupCacheMu.Unlock()
	})
}

func TestWinGroupAddDeleteLadder(t *testing.T) {
	runner := newWinGrpStoreRunner()
	rt := winGrpRT(runner)
	// add on an existing group is a no-op False (pytest test_add_group_exists).
	res, err := (winAddFunc{}).Execute(context.Background(), rt, &winAddArgs{Name: "salt"})
	if err != nil || res != false {
		t.Fatalf("existing add = %v %v", res, err)
	}
	// add on a new group emits the exact New-LocalGroup cmdlet.
	res, err = (winAddFunc{}).Execute(context.Background(), rt, &winAddArgs{Name: "devs"})
	if err != nil || res != true {
		t.Fatalf("new add = %v %v", res, err)
	}
	if got := runner.scripts[len(runner.scripts)-1]; got != "New-LocalGroup -Name 'devs' -ErrorAction Stop | Out-Null" {
		t.Fatalf("add script = %q", got)
	}
	// A failing create returns False plus the PowerShell error shape
	// (pytest test_add_error).
	runner.failSubstr = "New-LocalGroup -Name 'ops'"
	res, err = (winAddFunc{}).Execute(context.Background(), rt, &winAddArgs{Name: "ops"})
	if err == nil || !strings.Contains(err.Error(), "PowerShell command failed (exit code 1)") || !strings.Contains(err.Error(), "group store refused") {
		t.Fatalf("failing add = %v %v", res, err)
	}
	runner.failSubstr = ""
	// delete on a missing group is False (pytest test_delete_no_group).
	res, err = (winDeleteFunc{}).Execute(context.Background(), rt, &winDeleteArgs{Name: "ghost"})
	if err != nil || res != false {
		t.Fatalf("missing delete = %v %v", res, err)
	}
	// delete on an existing group emits Remove-LocalGroup with -Confirm:$false.
	res, err = (winDeleteFunc{}).Execute(context.Background(), rt, &winDeleteArgs{Name: "devs"})
	if err != nil || res != true {
		t.Fatalf("existing delete = %v %v", res, err)
	}
	if got := runner.scripts[len(runner.scripts)-1]; got != "Remove-LocalGroup -Name 'devs' -Confirm:$false -ErrorAction Stop" {
		t.Fatalf("delete script = %q", got)
	}
	// Single quotes in names are doubled inside the literal.
	res, err = (winAddFunc{}).Execute(context.Background(), rt, &winAddArgs{Name: "it's"})
	if err != nil || res != true {
		t.Fatalf("quoted add = %v %v", res, err)
	}
	if got := runner.scripts[len(runner.scripts)-1]; got != "New-LocalGroup -Name 'it''s' -ErrorAction Stop | Out-Null" {
		t.Fatalf("escaped script = %q", got)
	}
}

func TestWinGroupInfoShapeAndSentinels(t *testing.T) {
	// pytest test_info fixture: group "salt" with member HOST\steve.
	runner := &winGrpStoreRunner{
		groups:       map[string][]string{"salt": {"HOST\\steve"}},
		descriptions: map[string]string{"salt": ""},
	}
	res, err := (winInfoFunc{}).Execute(context.Background(), winGrpRT(runner), &winInfoArgs{Name: "salt"})
	if err != nil {
		t.Fatal(err)
	}
	info := res.(map[string]any)
	if info["name"] != "salt" || info["passwd"] != nil || info["gid"] != nil {
		t.Fatalf("info = %#v", info)
	}
	if members := info["members"].([]string); len(members) != 1 || members[0] != "HOST\\steve" {
		t.Fatalf("members = %v", members)
	}
	// Two members parse as a JSON array; one member arrives as a string.
	runner.groups["salt"] = []string{"HOST\\steve", "HOST\\spongebob"}
	res2, err := (winInfoFunc{}).Execute(context.Background(), winGrpRT(runner), &winInfoArgs{Name: "salt"})
	if err != nil {
		t.Fatal(err)
	}
	info = res2.(map[string]any)
	if members := info["members"].([]string); len(members) != 2 {
		t.Fatalf("members = %v", members)
	}
	// Missing group: the exit-3 sentinel collapses to an empty map.
	res, err = (winInfoFunc{}).Execute(context.Background(), winGrpRT(runner), &winInfoArgs{Name: "ghost"})
	if err != nil || len(res.(map[string]any)) != 0 {
		t.Fatalf("missing info = %#v %v", res, err)
	}
	// Missing powershell.exe surfaces the launch error instead.
	missing := &winGrpStoreRunner{launchErr: errors.New("exec: \"powershell.exe\": executable file not found in %PATH%")}
	_, err = (winInfoFunc{}).Execute(context.Background(), winGrpRT(missing), &winInfoArgs{Name: "salt"})
	if err == nil || !strings.Contains(err.Error(), "executable file not found") {
		t.Fatalf("missing powershell = %v", err)
	}
}

func TestWinGroupGetentAndListCaching(t *testing.T) {
	winGrpResetCache(t)
	runner := newWinGrpStoreRunner()
	rt := winGrpRT(runner)
	res, err := (winGetentFunc{}).Execute(context.Background(), rt, &winGetentArgs{})
	if err != nil {
		t.Fatal(err)
	}
	entries := res.([]map[string]any)
	if len(entries) != 2 || entries[0]["name"] != "Administrators" || entries[1]["name"] != "salt" {
		t.Fatalf("getent = %#v", entries)
	}
	scripts := len(runner.scripts)
	// A second getent without refresh is served from the context cache.
	res, err = (winGetentFunc{}).Execute(context.Background(), rt, &winGetentArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.([]map[string]any)) != 2 || len(runner.scripts) != scripts {
		t.Fatalf("cached getent scripts %d → %d", scripts, len(runner.scripts))
	}
	// list_groups prefers cached names without refresh; refresh forces
	// a new Get-LocalGroup query.
	listed, err := (winListGroupsFunc{}).Execute(context.Background(), rt, &winListGroupsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got := listed.([]string); len(got) != 2 || got[0] != "Administrators" || len(runner.scripts) != scripts {
		t.Fatalf("cached list = %v", got)
	}
	listed, err = (winListGroupsFunc{}).Execute(context.Background(), rt, &winListGroupsArgs{Refresh: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := listed.([]string); len(got) != 2 || len(runner.scripts) <= scripts {
		t.Fatalf("refreshed list = %v", got)
	}
	if got := runner.scripts[len(runner.scripts)-1]; got != "@(Get-LocalGroup | Select-Object -ExpandProperty Name) | ConvertTo-Json -Compress" {
		t.Fatalf("list script = %q", got)
	}
	// getent refresh also re-queries.
	if _, err := (winGetentFunc{}).Execute(context.Background(), rt, &winGetentArgs{Refresh: true}); err != nil {
		t.Fatal(err)
	}
}

func TestWinGroupMembershipLadder(t *testing.T) {
	runner := &winGrpStoreRunner{
		groups:       map[string][]string{"foo": {"HOST\\steve"}},
		descriptions: map[string]string{"foo": ""},
	}
	rt := winGrpRT(runner)
	// adduser of a fresh member emits the exact cmdlet (pytest test_adduser).
	res, err := (winAddUserFunc{}).Execute(context.Background(), rt, &winMemberArgs{Name: "foo", Username: "HOST\\spongebob"})
	if err != nil || res != true {
		t.Fatalf("adduser = %v %v", res, err)
	}
	if got := runner.scripts[len(runner.scripts)-1]; got != "Add-LocalGroupMember -Group 'foo' -Member 'HOST\\spongebob' -ErrorAction Stop" {
		t.Fatalf("adduser script = %q", got)
	}
	// Already a member → False without mutation, but windowsGroupInfo
	// still probes (Get-LocalGroup + members read → scripts+2), the
	// same two-script read TestWinGroupMembersReconciliation observes
	// (test_adduser_already_exists).
	scripts := len(runner.scripts)
	res, err = (winAddUserFunc{}).Execute(context.Background(), rt, &winMemberArgs{Name: "foo", Username: "HOST\\spongebob"})
	if err != nil || res != false || len(runner.scripts) != scripts+2 {
		t.Fatalf("member adduser = %v %v scripts %d → %d", res, err, scripts, len(runner.scripts))
	}
	// deluser of a member emits Remove with -Confirm:$false (test_deluser).
	res, err = (winDelUserFunc{}).Execute(context.Background(), rt, &winMemberArgs{Name: "foo", Username: "HOST\\spongebob"})
	if err != nil || res != true {
		t.Fatalf("deluser = %v %v", res, err)
	}
	if got := runner.scripts[len(runner.scripts)-1]; got != "Remove-LocalGroupMember -Group 'foo' -Member 'HOST\\spongebob' -Confirm:$false -ErrorAction Stop" {
		t.Fatalf("deluser script = %q", got)
	}
	// Not a member → False after the same windowsGroupInfo probe pair
	// (scripts+2) (test_deluser_no_user).
	scripts = len(runner.scripts)
	res, err = (winDelUserFunc{}).Execute(context.Background(), rt, &winMemberArgs{Name: "foo", Username: "HOST\\spongebob"})
	if err != nil || res != false || len(runner.scripts) != scripts+2 {
		t.Fatalf("non-member deluser = %v %v scripts %d → %d", res, err, scripts, len(runner.scripts))
	}
	// Missing group → False for both directions (pytest
	// test_adduser_group_does_not_exist).
	res, err = (winAddUserFunc{}).Execute(context.Background(), rt, &winMemberArgs{Name: "ghost", Username: "HOST\\x"})
	if err != nil || res != false {
		t.Fatalf("missing group adduser = %v %v", res, err)
	}
	res, err = (winDelUserFunc{}).Execute(context.Background(), rt, &winMemberArgs{Name: "ghost", Username: "HOST\\x"})
	if err != nil || res != false {
		t.Fatalf("missing group deluser = %v %v", res, err)
	}
	// Post-mutation reads observe the store change.
	infoRes, err := (winInfoFunc{}).Execute(context.Background(), rt, &winInfoArgs{Name: "foo"})
	if err != nil {
		t.Fatal(err)
	}
	info := infoRes.(map[string]any)
	if members := info["members"].([]string); len(members) != 1 || members[0] != "HOST\\steve" {
		t.Fatalf("post-mutation members = %v", members)
	}
}

func TestWinGroupMembersReconciliation(t *testing.T) {
	runner := &winGrpStoreRunner{
		groups:       map[string][]string{"foo": {"HOST\\spongebob"}},
		descriptions: map[string]string{"foo": ""},
	}
	rt := winGrpRT(runner)
	// Correct membership → True with no mutation (pytest
	// test_members_correct_membership).
	res, err := (winMembersFunc{}).Execute(context.Background(), rt, &winMembersArgs{Name: "foo", MembersList: []string{"HOST\\spongebob"}})
	if err != nil || res != true || len(runner.scripts) != 2 {
		t.Fatalf("correct members = %v %v scripts=%d", res, err, len(runner.scripts))
	}
	// Reconciliation adds missing members first, then removes extras
	// (pytest test_members).
	res, err = (winMembersFunc{}).Execute(context.Background(), rt, &winMembersArgs{Name: "foo", MembersList: []string{"HOST\\patrick", "HOST\\squidward"}})
	if err != nil || res != true {
		t.Fatalf("reconcile = %v %v", res, err)
	}
	script := runner.scripts[len(runner.scripts)-1]
	wantAdd1 := "Add-LocalGroupMember -Group 'foo' -Member 'HOST\\patrick' -ErrorAction Stop;"
	wantAdd2 := "Add-LocalGroupMember -Group 'foo' -Member 'HOST\\squidward' -ErrorAction Stop;"
	wantRemove := "Remove-LocalGroupMember -Group 'foo' -Member 'HOST\\spongebob' -Confirm:$false -ErrorAction Stop;"
	if !strings.Contains(script, wantAdd1) || !strings.Contains(script, wantAdd2) || !strings.Contains(script, wantRemove) {
		t.Fatalf("reconcile script = %q", script)
	}
	add1 := strings.Index(script, "Add-LocalGroupMember")
	add2 := strings.LastIndex(script, "Add-LocalGroupMember")
	remove := strings.Index(script, "Remove-LocalGroupMember")
	if add1 < 0 || add2 < add1 || (remove != -1 && remove < add2) {
		t.Fatalf("reconcile ordering = %q", script)
	}
	// The store reflects the reconciled membership exactly.
	infoRes, err := (winInfoFunc{}).Execute(context.Background(), rt, &winInfoArgs{Name: "foo"})
	if err != nil {
		t.Fatal(err)
	}
	members := infoRes.(map[string]any)["members"].([]string)
	sort.Strings(members)
	if !reflect.DeepEqual(members, []string{"HOST\\patrick", "HOST\\squidward"}) {
		t.Fatalf("reconciled members = %v", members)
	}
	// Missing group → False (pytest test_members_group_does_not_exist).
	res, err = (winMembersFunc{}).Execute(context.Background(), rt, &winMembersArgs{Name: "ghost", MembersList: []string{"HOST\\x"}})
	if err != nil || res != false {
		t.Fatalf("missing group members = %v %v", res, err)
	}
}

func TestWinGroupRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerWindows(reg); err != nil {
		t.Fatal(err)
	}
	names := reg.Names()
	sort.Strings(names)
	want := []string{"group.add", "group.adduser", "group.delete", "group.deluser", "group.getent", "group.info", "group.list_groups", "group.members"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("registry = %v", names)
	}
	if platforms := (winAddFunc{}).Platforms(); len(platforms) != 1 || platforms[0] != "windows" {
		t.Fatalf("platforms = %v", platforms)
	}
}
