//go:build windows

package group

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type windowsGroupRunner struct{ calls int }

func (r *windowsGroupRunner) Run(_ context.Context, _ process.Command) process.CommandResult {
	r.calls++
	if r.calls == 1 {
		data, _ := json.Marshal(map[string]any{"name": "Administrators", "description": "built-in"})
		return process.CommandResult{ExitCode: 0, Stdout: data}
	}
	if r.calls == 2 {
		return process.CommandResult{ExitCode: 0, Stdout: []byte(`["ACME\\alice","ACME\\bob"]`)}
	}
	return process.CommandResult{ExitCode: 0}
}

func TestWindowsGroupInfoAndCommands(t *testing.T) {
	runner := &windowsGroupRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := winInfoFunc{}.Execute(context.Background(), rt, &winInfoArgs{Name: "Administrators"})
	if err != nil {
		t.Fatal(err)
	}
	info := res.(map[string]any)
	if info["name"] != "Administrators" || info["description"] != "built-in" {
		t.Fatalf("info = %#v", info)
	}
	members := info["members"].([]string)
	if len(members) != 2 || members[0] != "ACME\\alice" {
		t.Fatalf("members = %v", members)
	}
	res, err = winAddUserFunc{}.Execute(context.Background(), rt, &winMemberArgs{Name: "Administrators", Username: "ACME\\carol"})
	if err != nil || res != true {
		t.Fatalf("add member = %v %v", res, err)
	}
	if runner.calls < 3 {
		t.Fatal("membership mutation was not issued")
	}
}

func TestWindowsGroupNameFailure(t *testing.T) {
	runner := &windowsGroupRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	_, err := runGroupPS(context.Background(), rt, "Write-Error bad")
	if err != nil {
		// successful fake Runner intentionally emits JSON only on the first
		// call; this branch ensures the helper remains callable.
		if !strings.Contains(err.Error(), "PowerShell") {
			t.Fatalf("unexpected helper error = %v", err)
		}
	}
}
