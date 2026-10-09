//go:build windows

package user

// R7.5 mock tests for the Windows user virtual provider, mapped onto
// saltstack/salt/modules/win_useradd.py @ pinned revision 8b63e700637e
// and tests/pytests/unit/modules/test_win_useradd.py: the add/update
// parameter ladder with exact New/Set-LocalUser cmdlet scripts and
// UTF-16LE EncodedCommand redaction of passwords, the setpassword
// missing-user regression (#68428: False, not a Win32 error string),
// addgroup/removegroup idempotence with the saltutils sam-name
// semantics, chhome same-value short-circuit, chgroups append vs
// replace reconciliation (removals first), the info shape mapping
// (account_disabled mirror, Never sentinels), getent/list_users JSON
// shapes with context caching, rename via Get-CimInstance/
// Invoke-CimMethod with both existence errors, current/get_user_sid
// and the registry matrix. PowerShell scripts are asserted after
// UTF-16LE/base64 decoding; no real powershell.exe runs. This file
// compiles and runs only on Windows (verified off-platform via
// GOOS=windows go test -c).

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func mustDecodeWinUserScript(command process.Command) string {
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

// winLusrQuoted extracts the ”-quoted literal following marker,
// unescaping doubled single quotes.
func winLusrQuoted(text, marker string) string {
	rest := text[strings.Index(text, marker)+len(marker):]
	if !strings.HasPrefix(rest, "'") {
		panic("winLusrQuoted: missing quote after " + marker)
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

// winLusrStoreRunner simulates the Get/New/Set/Remove-LocalUser( Member)
// cmdlet surface against a live user + group-membership store.
type winLusrStoreRunner struct {
	users     map[string]map[string]any // psUserInfo JSON shape per user
	groups    map[string][]string       // group → member users
	hostname  string
	launchErr error
	calls     []process.Command
	scripts   []string
}

func newWinLusrStoreRunner() *winLusrStoreRunner {
	return &winLusrStoreRunner{
		users: map[string]map[string]any{
			"alice": {
				"name": "alice", "uid": "S-1-5-21-1-2-3-1001", "fullname": "Alice Example",
				"description": "demo user", "active": true, "profile": "C:\\Users\\alice",
				"home": "C:\\Users\\alice", "password_never_expires": true, "account_locked": false,
				"expiration_date": "Never", "password_changed": "2026-01-02 03:04:05",
			},
		},
		groups: map[string][]string{
			"Users":          {"alice"},
			"Administrators": {"Administrator"},
		},
		hostname: "HOST",
	}
}

func (r *winLusrStoreRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if r.launchErr != nil {
		return process.CommandResult{ExitCode: -1, Err: r.launchErr}
	}
	script := mustDecodeWinUserScript(command)
	r.scripts = append(r.scripts, script)
	switch {
	case strings.Contains(script, "New-LocalUser @p"):
		name := winLusrQuoted(script, "$p=@{Name=")
		record := map[string]any{
			"name": name, "uid": "S-1-5-21-9-9-9-" + name, "fullname": "",
			"description": "", "active": true, "profile": "", "home": "",
			"password_never_expires": false, "account_locked": false,
			"expiration_date": "Never", "password_changed": "Never",
		}
		if strings.Contains(script, "$p.Password=") {
			record["password_seen"] = winLusrQuoted(script, "$p.Password=(ConvertTo-SecureString ")
		}
		if strings.Contains(script, "$p.FullName=") {
			record["fullname"] = winLusrQuoted(script, "$p.FullName=")
		}
		if strings.Contains(script, "$p.Description=") {
			record["description"] = winLusrQuoted(script, "$p.Description=")
		}
		r.users[name] = record
		// Trailing Set-LocalUser statements (home/profile) apply too.
		for _, statement := range strings.Split(script, ";") {
			r.winLusrApplyUserStatement(statement)
		}
		return process.CommandResult{ExitCode: 0}
	case strings.Contains(script, "Get-CimInstance Win32_UserAccount"):
		oldName := script[strings.Index(script, `Name=`)+len(`Name=`):]
		oldName = oldName[:strings.Index(oldName, `"`)]
		newName := winLusrQuoted(script, "-Arguments @{Name=")
		record, ok := r.users[oldName]
		if !ok {
			return process.CommandResult{ExitCode: 1, Stderr: []byte("user not found")}
		}
		delete(r.users, oldName)
		record["name"] = newName
		r.users[newName] = record
		return process.CommandResult{ExitCode: 0}
	case strings.Contains(script, "Remove-LocalUser -Name "):
		delete(r.users, winLusrQuoted(script, "Remove-LocalUser -Name "))
		return process.CommandResult{ExitCode: 0}
	case strings.Contains(script, "Set-LocalUser -Name ") || strings.Contains(script, "Disable-LocalUser") || strings.Contains(script, "Enable-LocalUser"):
		for _, statement := range strings.Split(script, ";") {
			r.winLusrApplyUserStatement(statement)
		}
		return process.CommandResult{ExitCode: 0}
	case strings.Contains(script, "Add-LocalGroupMember -Group ") || strings.Contains(script, "Remove-LocalGroupMember -Group "):
		for _, statement := range strings.Split(script, ";") {
			r.winLusrApplyMembership(statement)
		}
		return process.CommandResult{ExitCode: 0}
	case strings.Contains(script, "Remove-Item -LiteralPath "):
		return process.CommandResult{ExitCode: 0}
	case strings.HasPrefix(script, "$u=Get-LocalUser -Name "):
		name := winLusrQuoted(script, "$u=Get-LocalUser -Name ")
		record, ok := r.users[name]
		if !ok {
			return process.CommandResult{ExitCode: 3, Stderr: []byte("user not found")}
		}
		data, _ := json.Marshal(record)
		return process.CommandResult{ExitCode: 0, Stdout: data}
	case strings.HasPrefix(script, "$n="):
		name := winLusrQuoted(script, "$n=")
		var found []string
		for group, members := range r.groups {
			for _, member := range members {
				if member == name || member == r.hostname+"\\"+name {
					found = append(found, group)
					break
				}
			}
		}
		sort.Strings(found)
		if len(found) == 0 {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(`[]`)}
		}
		if len(found) == 1 {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(`"` + found[0] + `"`)}
		}
		quoted := make([]string, 0, len(found))
		for _, group := range found {
			quoted = append(quoted, `"`+group+`"`)
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte("[" + strings.Join(quoted, ",") + "]")}
	case strings.HasPrefix(script, "@(Get-LocalUser |"):
		names := make([]string, 0, len(r.users))
		for name := range r.users {
			names = append(names, name)
		}
		sort.Strings(names)
		if len(names) == 1 {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(`"` + names[0] + `"`)}
		}
		quoted := make([]string, 0, len(names))
		for _, name := range names {
			quoted = append(quoted, `"`+name+`"`)
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte("[" + strings.Join(quoted, ",") + "]")}
	case strings.Contains(script, "([System.Security.Principal.NTAccount]"):
		return process.CommandResult{ExitCode: 0, Stdout: []byte("S-1-5-21-1-2-3-1001\r\n")}
	case strings.Contains(script, "WindowsIdentity]::GetCurrent()"):
		return process.CommandResult{ExitCode: 0, Stdout: []byte(r.hostname + "\\alice\r\n")}
	}
	return process.CommandResult{ExitCode: 0}
}

func (r *winLusrStoreRunner) winLusrApplyUserStatement(statement string) {
	switch {
	case strings.Contains(statement, "Set-LocalUser -Name "):
		name := winLusrQuoted(statement, "Set-LocalUser -Name ")
		record, ok := r.users[name]
		if !ok {
			return
		}
		for marker, field := range map[string]string{
			" -FullName ":      "fullname",
			" -Description ":   "description",
			" -HomeDirectory ": "home",
			" -ProfilePath ":   "profile",
		} {
			if strings.Contains(statement, marker) {
				record[field] = winLusrQuoted(statement, marker)
			}
		}
		if strings.Contains(statement, " -Password (ConvertTo-SecureString ") {
			record["password_seen"] = winLusrQuoted(statement, " -Password (ConvertTo-SecureString ")
		}
		if strings.Contains(statement, " -AccountExpires $d") {
			record["expiration_date"] = "2026-12-31"
		}
		if strings.Contains(statement, " -AccountExpires ([datetime]::MaxValue)") {
			record["expiration_date"] = "Never"
		}
	case strings.Contains(statement, "Disable-LocalUser -Name "):
		if record, ok := r.users[winLusrQuoted(statement, "Disable-LocalUser -Name ")]; ok {
			record["active"] = false
		}
	case strings.Contains(statement, "Enable-LocalUser -Name "):
		if record, ok := r.users[winLusrQuoted(statement, "Enable-LocalUser -Name ")]; ok {
			record["active"] = true
		}
	}
}

func (r *winLusrStoreRunner) winLusrApplyMembership(statement string) {
	switch {
	case strings.Contains(statement, "Add-LocalGroupMember -Group "):
		group := winLusrQuoted(statement, "Add-LocalGroupMember -Group ")
		member := winLusrQuoted(statement, "-Member ")
		r.groups[group] = append(r.groups[group], member)
	case strings.Contains(statement, "Remove-LocalGroupMember -Group "):
		group := winLusrQuoted(statement, "Remove-LocalGroupMember -Group ")
		member := winLusrQuoted(statement, "-Member ")
		var kept []string
		for _, existing := range r.groups[group] {
			if existing != member {
				kept = append(kept, existing)
			}
		}
		r.groups[group] = kept
	}
}

func winLusrRT(runner *winLusrStoreRunner) *runtime.Runtime {
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
}

// winLusrResetCache isolates the package-global getent cache.
func winLusrResetCache(t *testing.T) {
	t.Helper()
	windowsUserCacheMu.Lock()
	saved := windowsUserCache
	windowsUserCache = nil
	windowsUserCacheMu.Unlock()
	t.Cleanup(func() {
		windowsUserCacheMu.Lock()
		windowsUserCache = saved
		windowsUserCacheMu.Unlock()
	})
}

func TestWinUserAddEncodesParamsAndRedactsSecret(t *testing.T) {
	runner := newWinLusrStoreRunner()
	rt := winLusrRT(runner)
	res, err := (winAddFunc{}).Execute(context.Background(), rt, &winAddArgs{
		Name: "bob", Password: winLusrPtr("S3cr3t!"), Fullname: winLusrPtr("Bob B"),
		Description: winLusrPtr("created"), Home: winLusrPtr(`C:\Users\bob`),
		Profile: winLusrPtr(`C:\Profiles\bob`), Groups: []string{"Users", "Admins"},
	})
	if err != nil || res != true {
		t.Fatalf("add = %v %v", res, err)
	}
	want := `$p=@{Name='bob'};$p.Password=(ConvertTo-SecureString 'S3cr3t!' -AsPlainText -Force);` +
		`$p.FullName='Bob B';$p.Description='created';New-LocalUser @p -ErrorAction Stop | Out-Null;` +
		`Set-LocalUser -Name 'bob' -HomeDirectory 'C:\Users\bob';` +
		`Set-LocalUser -Name 'bob' -ProfilePath 'C:\Profiles\bob';`
	if runner.scripts[0] != want {
		t.Fatalf("add script = %q", runner.scripts[0])
	}
	// The plaintext password must travel only in Redact, never in argv.
	redact := runner.calls[0].Redact
	if len(redact) != 1 || redact[0] != "S3cr3t!" {
		t.Fatalf("redact list = %d entries", len(redact))
	}
	if strings.Contains(strings.Join(runner.calls[0].Args, " "), "S3cr3t!") {
		t.Fatal("password leaked into argv")
	}
	// chgroups appended bob to both requested groups (scripts: create,
	// exists-check info+groups, chgroups groups query, mutation).
	mutation := runner.scripts[4]
	if !strings.Contains(mutation, "Add-LocalGroupMember -Group 'Users' -Member 'bob' -ErrorAction Stop;") ||
		!strings.Contains(mutation, "Add-LocalGroupMember -Group 'Admins' -Member 'bob' -ErrorAction Stop;") {
		t.Fatalf("chgroups script = %q", mutation)
	}
	// Post-change reads observe the created user (store-driven).
	infoRes, err := (winInfoFunc{}).Execute(context.Background(), rt, &winInfoArgs{Name: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	info := infoRes.(map[string]any)
	if info["fullname"] != "Bob B" || info["home"] != `C:\Users\bob` {
		t.Fatalf("created info = %#v", info)
	}
	groups, err := (winListGroupsFunc{}).Execute(context.Background(), rt, &winListGroupsArgs{Name: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(groups.([]string))
	if !reflect.DeepEqual(groups.([]string), []string{"Admins", "Users"}) {
		t.Fatalf("created groups = %v", groups)
	}
	// No password → NoPassword splat; empty name → False with no calls.
	noPw := newWinLusrStoreRunner()
	if _, err := (winAddFunc{}).Execute(context.Background(), winLusrRT(noPw), &winAddArgs{Name: "carol"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(noPw.scripts[0], "$p.NoPassword=$true;") {
		t.Fatalf("no-password script = %q", noPw.scripts[0])
	}
	empty := newWinLusrStoreRunner()
	res, err = (winAddFunc{}).Execute(context.Background(), winLusrRT(empty), &winAddArgs{})
	if err != nil || res != false || len(empty.calls) != 0 {
		t.Fatalf("empty add = %v %v %v", res, err, len(empty.calls))
	}
}

func winLusrPtr(value string) *string { return &value }

func winLusrBoolPtr(value bool) *bool { return &value }

func TestWinUserUpdateFlows(t *testing.T) {
	// Missing user keeps Salt's strerror-shaped message as an error.
	missing := newWinLusrStoreRunner()
	_, err := (winUpdateFunc{}).Execute(context.Background(), winLusrRT(missing), &winUpdateArgs{Name: "ghost"})
	if err == nil || err.Error() != "User 'ghost' does not exist" {
		t.Fatalf("missing update = %v", err)
	}
	if len(missing.scripts) != 1 {
		t.Fatalf("missing update scripts = %d", len(missing.scripts))
	}
	// Attribute ladder with the exact cmdlet sequence on a fresh store.
	runner := newWinLusrStoreRunner()
	rt := winLusrRT(runner)
	res, err := (winUpdateFunc{}).Execute(context.Background(), rt, &winUpdateArgs{
		Name: "alice", Password: winLusrPtr("NewPass1"), Fullname: winLusrPtr("Alice Renamed"),
		Description: winLusrPtr("updated"), Home: winLusrPtr(`C:\Home\alice`),
		Profile: winLusrPtr(`C:\Profiles\alice`), ExpirationDate: winLusrPtr("Never"),
		AccountDisabled: winLusrBoolPtr(true),
	})
	if err != nil || res != true {
		t.Fatalf("update = %v %v", res, err)
	}
	want := `$u=Get-LocalUser -Name 'alice' -ErrorAction Stop;` +
		`Set-LocalUser -Name 'alice' -Password (ConvertTo-SecureString 'NewPass1' -AsPlainText -Force);` +
		`Set-LocalUser -Name 'alice' -FullName 'Alice Renamed';` +
		`Set-LocalUser -Name 'alice' -Description 'updated';` +
		`Set-LocalUser -Name 'alice' -HomeDirectory 'C:\Home\alice';` +
		`Set-LocalUser -Name 'alice' -ProfilePath 'C:\Profiles\alice';` +
		`Set-LocalUser -Name 'alice' -AccountExpires ([datetime]::MaxValue);` +
		`Disable-LocalUser -Name 'alice';`
	// scripts[0..1] are the existence-check info+groups reads; the
	// update mutation itself is the third script.
	if runner.scripts[2] != want {
		t.Fatalf("update script = %q", runner.scripts[2])
	}
	if redact := runner.calls[2].Redact; len(redact) != 1 || redact[0] != "NewPass1" {
		t.Fatalf("update redact = %d entries", len(redact))
	}
	// Dated expiry uses Get-Date; enable mirrors disable.
	dated := newWinLusrStoreRunner()
	if _, err := (winUpdateFunc{}).Execute(context.Background(), winLusrRT(dated), &winUpdateArgs{
		Name: "alice", ExpirationDate: winLusrPtr("2026-12-31"), AccountDisabled: winLusrBoolPtr(false),
	}); err != nil {
		t.Fatal(err)
	}
	datedScript := dated.scripts[2]
	if !strings.Contains(datedScript, `$d=Get-Date '2026-12-31';Set-LocalUser -Name 'alice' -AccountExpires $d;`) {
		t.Fatalf("dated expiry = %q", datedScript)
	}
	if !strings.Contains(datedScript, "Enable-LocalUser -Name 'alice';") {
		t.Fatalf("enable statement = %q", datedScript)
	}
	// Store reflects the disable + expiry changes.
	infoRes, err := (winInfoFunc{}).Execute(context.Background(), rt, &winInfoArgs{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	info := infoRes.(map[string]any)
	if info["active"] != false || info["account_disabled"] != true {
		t.Fatalf("disabled info = %#v", info)
	}
}

func TestWinUserDeleteAndPurge(t *testing.T) {
	// Missing user deletes cleanly (Salt's idempotent-delete port):
	// windowsInfo still fires exactly one Get-LocalUser probe (the
	// exit-3 sentinel short-circuits before any groups read).
	missing := newWinLusrStoreRunner()
	res, err := (winDeleteFunc{}).Execute(context.Background(), winLusrRT(missing), &winDeleteArgs{Name: "ghost"})
	if err != nil || res != true || len(missing.calls) != 1 || len(missing.scripts) != 1 {
		t.Fatalf("missing delete = %v %v calls=%d scripts=%d", res, err, len(missing.calls), len(missing.scripts))
	}
	if !strings.HasPrefix(missing.scripts[0], "$u=Get-LocalUser -Name 'ghost'") {
		t.Fatalf("missing delete probe = %q", missing.scripts[0])
	}
	// Plain delete emits only Remove-LocalUser (after the info+groups
	// existence reads).
	runner := newWinLusrStoreRunner()
	if _, err := (winDeleteFunc{}).Execute(context.Background(), winLusrRT(runner), &winDeleteArgs{Name: "alice"}); err != nil {
		t.Fatal(err)
	}
	if got := runner.scripts[2]; got != "Remove-LocalUser -Name 'alice' -Confirm:$false -ErrorAction Stop;" {
		t.Fatalf("delete script = %q", got)
	}
	// purge=True with a home directory also removes the profile tree.
	purge := newWinLusrStoreRunner()
	if _, err := (winDeleteFunc{}).Execute(context.Background(), winLusrRT(purge), &winDeleteArgs{Name: "alice", Purge: true}); err != nil {
		t.Fatal(err)
	}
	want := `Remove-LocalUser -Name 'alice' -Confirm:$false -ErrorAction Stop;` +
		`Remove-Item -LiteralPath 'C:\Users\alice' -Recurse -Force -ErrorAction SilentlyContinue;`
	if purge.scripts[2] != want {
		t.Fatalf("purge script = %q", purge.scripts[2])
	}
	if _, ok := purge.users["alice"]; ok {
		t.Fatal("delete must remove the user from the store")
	}
}

func TestWinUserSetpasswordMissingUserReturnsFalse(t *testing.T) {
	// Pytest regression #68428: setpassword on a missing user must
	// return False (never a Win32 error string masquerading as True).
	runner := newWinLusrStoreRunner()
	res, err := (winSetPasswordFunc{}).Execute(context.Background(), winLusrRT(runner), &winSetPasswordArgs{Name: "ghost", Password: "P@ssw0rd"})
	if err != nil || res != false {
		t.Fatalf("missing setpassword = %v %v", res, err)
	}
	// Present user emits the exact cmdlet with the secret redacted.
	res, err = (winSetPasswordFunc{}).Execute(context.Background(), winLusrRT(runner), &winSetPasswordArgs{Name: "alice", Password: "P@ssw0rd"})
	if err != nil || res != true {
		t.Fatalf("setpassword = %v %v", res, err)
	}
	want := `Set-LocalUser -Name 'alice' -Password (ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force)`
	if got := runner.scripts[len(runner.scripts)-1]; got != want {
		t.Fatalf("setpassword script = %q", got)
	}
	redact := runner.calls[len(runner.calls)-1].Redact
	if len(redact) != 1 || redact[0] != "P@ssw0rd" {
		t.Fatalf("setpassword redact = %d entries", len(redact))
	}
}

func TestWinUserGroupMembershipLadder(t *testing.T) {
	runner := newWinLusrStoreRunner()
	rt := winLusrRT(runner)
	// addgroup of a fresh group emits the exact cmdlet (after the
	// exists-check info+groups reads and the membership query).
	res, err := (winAddGroupFunc{}).Execute(context.Background(), rt, &winGroupChangeArgs{Name: "alice", Group: "Admins"})
	if err != nil || res != true {
		t.Fatalf("addgroup = %v %v", res, err)
	}
	if len(runner.scripts) != 4 {
		t.Fatalf("addgroup scripts = %d: %q", len(runner.scripts), runner.scripts)
	}
	if got := runner.scripts[3]; got != "Add-LocalGroupMember -Group 'Admins' -Member 'alice' -ErrorAction Stop" {
		t.Fatalf("addgroup script = %q", got)
	}
	// Already a member → True without mutation (salt semantics), but
	// the ladder still probes: the exists info+groups reads (2) plus
	// the membership query (1) → scripts+3.
	scripts := len(runner.scripts)
	res, err = (winAddGroupFunc{}).Execute(context.Background(), rt, &winGroupChangeArgs{Name: "alice", Group: "Admins"})
	if err != nil || res != true || len(runner.scripts) != scripts+3 {
		t.Fatalf("member addgroup = %v %v scripts %d → %d", res, err, scripts, len(runner.scripts))
	}
	// removegroup of a member emits Remove with -Confirm:$false.
	res, err = (winRemoveGroupFunc{}).Execute(context.Background(), rt, &winGroupChangeArgs{Name: "alice", Group: "Admins"})
	if err != nil || res != true {
		t.Fatalf("removegroup = %v %v", res, err)
	}
	if got := runner.scripts[len(runner.scripts)-1]; got != "Remove-LocalGroupMember -Group 'Admins' -Member 'alice' -Confirm:$false -ErrorAction Stop" {
		t.Fatalf("removegroup script = %q", got)
	}
	// Not a member → True without mutation, through the same exists 2
	// + groups 1 probe ladder → scripts+3; missing user → False.
	scripts = len(runner.scripts)
	res, err = (winRemoveGroupFunc{}).Execute(context.Background(), rt, &winGroupChangeArgs{Name: "alice", Group: "Admins"})
	if err != nil || res != true || len(runner.scripts) != scripts+3 {
		t.Fatalf("non-member removegroup = %v %v scripts %d → %d", res, err, scripts, len(runner.scripts))
	}
	res, err = (winAddGroupFunc{}).Execute(context.Background(), rt, &winGroupChangeArgs{Name: "ghost", Group: "Users"})
	if err != nil || res != false {
		t.Fatalf("missing addgroup = %v %v", res, err)
	}
	res, err = (winRemoveGroupFunc{}).Execute(context.Background(), rt, &winGroupChangeArgs{Name: "ghost", Group: "Users"})
	if err != nil || res != false {
		t.Fatalf("missing removegroup = %v %v", res, err)
	}
}

func TestWinUserAttributeShortCircuits(t *testing.T) {
	runner := newWinLusrStoreRunner()
	rt := winLusrRT(runner)
	// chhome to the current value short-circuits (Salt chhome == True)
	// after the windowsInfo probe (info + groups reads → scripts+2).
	scripts := len(runner.scripts)
	res, err := (winChhomeFunc{}).Execute(context.Background(), rt, &winChhomeArgs{Name: "alice", Home: `C:\Users\alice`})
	if err != nil || res != true || len(runner.scripts) != scripts+2 {
		t.Fatalf("same chhome = %v %v scripts %d → %d", res, err, scripts, len(runner.scripts))
	}
	// A changed home emits the exact cmdlet.
	res, err = (winChhomeFunc{}).Execute(context.Background(), rt, &winChhomeArgs{Name: "alice", Home: `C:\New\home`})
	if err != nil || res != true {
		t.Fatalf("chhome = %v %v", res, err)
	}
	if got := runner.scripts[len(runner.scripts)-1]; got != `Set-LocalUser -Name 'alice' -HomeDirectory 'C:\New\home'` {
		t.Fatalf("chhome script = %q", got)
	}
	// chprofile is covered by the common fake-NetAPI tests, not cmdlets.
	if _, err := (winChfullnameFunc{}).Execute(context.Background(), rt, &winChfullnameArgs{Name: "alice", Fullname: "Alice Example"}); err != nil {
		t.Fatal(err)
	}
	if got := runner.scripts[len(runner.scripts)-1]; got != `Set-LocalUser -Name 'alice' -FullName 'Alice Example'` {
		t.Fatalf("chfullname script = %q", got)
	}
	// Missing user chhome → False.
	res, err = (winChhomeFunc{}).Execute(context.Background(), rt, &winChhomeArgs{Name: "ghost", Home: `C:\nope`})
	if err != nil || res != false {
		t.Fatalf("missing chhome = %v %v", res, err)
	}
}

func TestWinUserChgroupsAppendAndReplace(t *testing.T) {
	runner := newWinLusrStoreRunner()
	rt := winLusrRT(runner)
	// Append with the current set already matching → True, no mutation
	// (Salt: current_groups == set(groups) short-circuit). The three
	// reads are the exists-check info+groups and the chgroups query.
	res, err := (winChgroupsFunc{}).Execute(context.Background(), rt, &winChgroupsArgs{Name: "alice", Groups: []string{"Users"}, Append: winLusrBoolPtr(true)})
	if err != nil || res != true || len(runner.scripts) != 3 {
		t.Fatalf("append no-op = %v %v scripts=%d", res, err, len(runner.scripts))
	}
	// Append of a new group adds only the missing one.
	res, err = (winChgroupsFunc{}).Execute(context.Background(), rt, &winChgroupsArgs{Name: "alice", Groups: []string{"Users", "Admins"}, Append: winLusrBoolPtr(true)})
	if err != nil || res != true {
		t.Fatalf("append = %v %v", res, err)
	}
	script := runner.scripts[len(runner.scripts)-1]
	if !strings.Contains(script, "Add-LocalGroupMember -Group 'Admins' -Member 'alice' -ErrorAction Stop;") || strings.Contains(script, "Remove-LocalGroupMember") {
		t.Fatalf("append script = %q", script)
	}
	// Replace removes extras first (SilentlyContinue), then adds.
	res, err = (winChgroupsFunc{}).Execute(context.Background(), rt, &winChgroupsArgs{Name: "alice", Groups: []string{"Backup"}, Append: winLusrBoolPtr(false)})
	if err != nil || res != true {
		t.Fatalf("replace = %v %v", res, err)
	}
	script = runner.scripts[len(runner.scripts)-1]
	removeAt := strings.Index(script, "Remove-LocalGroupMember -Group 'Admins' -Member 'alice' -Confirm:$false -ErrorAction SilentlyContinue;")
	addAt := strings.Index(script, "Add-LocalGroupMember -Group 'Backup' -Member 'alice' -ErrorAction Stop;")
	if removeAt < 0 || addAt < 0 || removeAt > addAt {
		t.Fatalf("replace ordering = %q", script)
	}
	// The store reflects exact replacement.
	groups, err := (winListGroupsFunc{}).Execute(context.Background(), rt, &winListGroupsArgs{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if got := groups.([]string); len(got) != 1 || got[0] != "Backup" {
		t.Fatalf("replaced groups = %v", got)
	}
	// Missing user → False.
	res, err = (winChgroupsFunc{}).Execute(context.Background(), rt, &winChgroupsArgs{Name: "ghost", Groups: []string{"Users"}})
	if err != nil || res != false {
		t.Fatalf("missing chgroups = %v %v", res, err)
	}
}

func TestWinUserInfoShapeAndLists(t *testing.T) {
	runner := newWinLusrStoreRunner()
	rt := winLusrRT(runner)
	res, err := (winInfoFunc{}).Execute(context.Background(), rt, &winInfoArgs{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	info := res.(map[string]any)
	want := map[string]any{
		"fullname": "Alice Example", "name": "alice", "uid": "S-1-5-21-1-2-3-1001",
		"passwd": nil, "comment": "demo user", "description": "demo user",
		"active": true, "logonscript": "", "profile": "C:\\Users\\alice",
		"home": "C:\\Users\\alice", "homedrive": "", "groups": []string{"Users"},
		"password_changed": "2026-01-02 03:04:05", "successful_logon_attempts": 0,
		"failed_logon_attempts": 0, "last_logon": "Never", "account_disabled": false,
		"account_locked": false, "expiration_date": "Never",
		"expired": false, "password_never_expires": true,
		"disallow_change_password": false, "gid": "",
	}
	if !reflect.DeepEqual(info, want) {
		t.Fatalf("info = %#v", info)
	}
	if got := runner.scripts[0]; !strings.HasPrefix(got, "$u=Get-LocalUser -Name 'alice' -ErrorAction SilentlyContinue; if($null -eq $u){exit 3};") ||
		!strings.Contains(got, "ConvertTo-Json -Compress") {
		t.Fatalf("info script = %q", got)
	}
	// Missing user → empty map (exit-3 sentinel).
	res, err = (winInfoFunc{}).Execute(context.Background(), rt, &winInfoArgs{Name: "ghost"})
	if err != nil || len(res.(map[string]any)) != 0 {
		t.Fatalf("missing info = %#v %v", res, err)
	}
	// list_users: one user arrives as a JSON string, two as an array.
	listed, err := (winListUsersFunc{}).Execute(context.Background(), rt, &winListUsersArgs{})
	if err != nil || !reflect.DeepEqual(listed.([]string), []string{"alice"}) {
		t.Fatalf("single list_users = %#v %v", listed, err)
	}
	runner.users["bob"] = map[string]any{"name": "bob"}
	listed, err = (winListUsersFunc{}).Execute(context.Background(), rt, &winListUsersArgs{})
	if err != nil || !reflect.DeepEqual(listed.([]string), []string{"alice", "bob"}) {
		t.Fatalf("list_users = %#v %v", listed, err)
	}
	// getent caches per refresh and normalizes the passwd/getent shape.
	winLusrResetCache(t)
	entries, err := (winGetentFunc{}).Execute(context.Background(), rt, &winGetentArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries.([]map[string]any)) != 2 {
		t.Fatalf("getent = %#v", entries)
	}
	first := entries.([]map[string]any)[0]
	if first["name"] != "alice" || first["gid"] != "" || first["shell"] != "" || first["passwd"] != nil {
		t.Fatalf("getent entry = %#v", first)
	}
	cached, err := (winGetentFunc{}).Execute(context.Background(), rt, &winGetentArgs{})
	if err != nil || len(cached.([]map[string]any)) != 2 {
		t.Fatalf("cached getent = %#v %v", cached, err)
	}
}

func TestWinUserRenameCurrentSIDAndMissingBinary(t *testing.T) {
	runner := newWinLusrStoreRunner()
	rt := winLusrRT(runner)
	// rename missing → Salt's User-does-not-exist error.
	_, err := (winRenameFunc{}).Execute(context.Background(), rt, &winRenameArgs{Name: "ghost", NewName: "alice2"})
	if err == nil || err.Error() != "User 'ghost' does not exist" {
		t.Fatalf("missing rename = %v", err)
	}
	// rename onto an existing name → the already-exists error.
	runner.users["bob"] = map[string]any{"name": "bob"}
	_, err = (winRenameFunc{}).Execute(context.Background(), rt, &winRenameArgs{Name: "alice", NewName: "bob"})
	if err == nil || err.Error() != "User 'bob' already exists" {
		t.Fatalf("existing rename = %v", err)
	}
	// Successful rename emits the exact CIM script and moves the record.
	res, err := (winRenameFunc{}).Execute(context.Background(), rt, &winRenameArgs{Name: "alice", NewName: "alice2"})
	if err != nil || res != true {
		t.Fatalf("rename = %v %v", res, err)
	}
	want := `$u=Get-CimInstance Win32_UserAccount -Filter "Name=alice";` +
		`Invoke-CimMethod -InputObject $u -MethodName Rename -Arguments @{Name='alice2'} -ErrorAction Stop | Out-Null`
	if got := runner.scripts[len(runner.scripts)-1]; got != want {
		t.Fatalf("rename script = %q", got)
	}
	if _, ok := runner.users["alice"]; ok || runner.users["alice2"]["name"] != "alice2" {
		t.Fatalf("rename store = %#v", runner.users)
	}
	// get_user_sid + alias share the exact NTAccount translation script.
	res, err = (winGetUserSIDFunc{}).Execute(context.Background(), rt, &winUserSIDArgs{Username: "alice2"})
	if err != nil || res != "S-1-5-21-1-2-3-1001" {
		t.Fatalf("sid = %v %v", res, err)
	}
	wantSID := `([System.Security.Principal.NTAccount]'alice2').Translate([System.Security.Principal.SecurityIdentifier]).Value`
	if got := runner.scripts[len(runner.scripts)-1]; got != wantSID {
		t.Fatalf("sid script = %q", got)
	}
	res, err = (winGetUserSIDAliasFunc{}).Execute(context.Background(), rt, &winUserSIDArgs{Username: "alice2"})
	if err != nil || res != "S-1-5-21-1-2-3-1001" {
		t.Fatalf("alias sid = %v %v", res, err)
	}
	// current: plain strips the domain, SAM keeps it.
	res, err = (winCurrentFunc{}).Execute(context.Background(), rt, &winCurrentArgs{})
	if err != nil || res != "alice" {
		t.Fatalf("current = %v %v", res, err)
	}
	res, err = (winCurrentFunc{}).Execute(context.Background(), rt, &winCurrentArgs{SAM: true})
	if err != nil || res != "HOST\\alice" {
		t.Fatalf("sam current = %v %v", res, err)
	}
	// Missing powershell.exe surfaces the launch error from info.
	missing := &winLusrStoreRunner{launchErr: errors.New("exec: \"powershell.exe\": executable file not found in %PATH%")}
	_, err = (winInfoFunc{}).Execute(context.Background(), winLusrRT(missing), &winInfoArgs{Name: "alice"})
	if err == nil || !strings.Contains(err.Error(), "executable file not found") {
		t.Fatalf("missing powershell = %v", err)
	}
}

func TestWinUserRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerWindows(reg); err != nil {
		t.Fatal(err)
	}
	names := reg.Names()
	sort.Strings(names)
	want := []string{
		"user.add", "user.addgroup", "user.chfullname", "user.chgroups", "user.chhome",
		"user.chprofile", "user.current", "user.delete", "user.get_user_sid", "user.getent",
		"user.getUserSid", "user.info", "user.list_groups", "user.list_users", "user.rename",
		"user.removegroup", "user.setpassword", "user.update",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("registry = %v", names)
	}
	if platforms := (winAddFunc{}).Platforms(); len(platforms) != 1 || platforms[0] != "windows" {
		t.Fatalf("platforms = %v", platforms)
	}
}
