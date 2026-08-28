//go:build windows

package user

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type windowsUserRunner struct {
	calls int
	mode  string
}

func (r *windowsUserRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls++
	if r.mode == "missing" {
		return process.CommandResult{ExitCode: 3, Stderr: []byte("not found")}
	}
	if r.mode == "sid" {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("S-1-5-21-1-2-3-1001\r\n")}
	}
	if r.mode == "current" {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("ACME\\alice\r\n")}
	}
	if r.calls == 1 {
		data, _ := json.Marshal(map[string]any{
			"name": "alice", "uid": "S-1-5-21-1-2-3-1001", "fullname": "Alice",
			"description": "demo", "active": true, "home": "C:\\Users\\alice",
			"profile": "C:\\Users\\alice", "account_locked": false,
			"password_never_expires": true, "expiration_date": "Never", "password_changed": "Never",
		})
		return process.CommandResult{ExitCode: 0, Stdout: data}
	}
	if r.calls == 2 {
		return process.CommandResult{ExitCode: 0, Stdout: []byte(`["Users","Administrators"]`)}
	}
	return process.CommandResult{ExitCode: 0}
}

func TestWindowsUserEncodedScriptAndInfo(t *testing.T) {
	command := encodedPowerShell("Write-Output 'safe'", []string{"secret"})
	if command.Name != "powershell.exe" || len(command.Args) != 4 || len(command.Redact) != 1 {
		t.Fatalf("encoded command = %+v", command)
	}
	raw, err := base64.StdEncoding.DecodeString(command.Args[3])
	if err != nil || len(raw)%2 != 0 {
		t.Fatal(err)
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	var script strings.Builder
	for _, unit := range units {
		if unit != 0 {
			script.WriteRune(rune(unit))
		}
	}
	if script.String() != "Write-Output 'safe'" {
		t.Fatalf("decoded script = %q", script.String())
	}

	runner := &windowsUserRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := winInfoFunc{}.Execute(context.Background(), rt, &winInfoArgs{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	info := res.(map[string]any)
	if info["name"] != "alice" || info["uid"] != "S-1-5-21-1-2-3-1001" || info["active"] != true {
		t.Fatalf("info = %#v", info)
	}
	groups, _ := info["groups"].([]string)
	if len(groups) != 2 || groups[1] != "Administrators" {
		t.Fatalf("groups = %v", groups)
	}
}

func TestWindowsUserMissingSIDCurrent(t *testing.T) {
	missing := &runtime.Runtime{Runner: &windowsUserRunner{mode: "missing"}, FS: runtime.NewMemoryFS()}
	res, err := winInfoFunc{}.Execute(context.Background(), missing, &winInfoArgs{Name: "missing"})
	if err != nil || len(res.(map[string]any)) != 0 {
		t.Fatalf("missing info = %#v %v", res, err)
	}
	sidRT := &runtime.Runtime{Runner: &windowsUserRunner{mode: "sid"}, FS: runtime.NewMemoryFS()}
	res, err = winGetUserSIDFunc{}.Execute(context.Background(), sidRT, &winUserSIDArgs{Username: "alice"})
	if err != nil || res != "S-1-5-21-1-2-3-1001" {
		t.Fatalf("sid = %v %v", res, err)
	}
	currentRT := &runtime.Runtime{Runner: &windowsUserRunner{mode: "current"}, FS: runtime.NewMemoryFS()}
	res, err = winCurrentFunc{}.Execute(context.Background(), currentRT, &winCurrentArgs{})
	if err != nil || res != "alice" {
		t.Fatalf("current = %v %v", res, err)
	}
	res, err = winCurrentFunc{}.Execute(context.Background(), currentRT, &winCurrentArgs{SAM: true})
	if err != nil || res != "ACME\\alice" {
		t.Fatalf("SAM current = %v %v", res, err)
	}
}
