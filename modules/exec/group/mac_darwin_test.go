//go:build darwin

package group

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type darwinGroupRunner struct {
	calls []process.Command
}

func (r *darwinGroupRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name == "dscacheutil" && strings.Contains(strings.Join(command.Args, " "), "-q group -a name staff") {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("name: staff\npassword: *\ngid: 20\nusers: alice bob\n")}
	}
	return process.CommandResult{ExitCode: 0}
}

func TestDarwinGroupInfoAndCommands(t *testing.T) {
	runner := &darwinGroupRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := macInfoFunc{}.Execute(context.Background(), rt, &macInfoArgs{Name: "staff"})
	if err != nil {
		t.Fatal(err)
	}
	info := res.(map[string]any)
	if info["name"] != "staff" || info["gid"] != 20 || info["passwd"] != "*" {
		t.Fatalf("group info = %#v", info)
	}
	members, _ := info["members"].([]string)
	if len(members) != 2 || members[0] != "alice" || members[1] != "bob" {
		t.Fatalf("members = %v", members)
	}
	res, err = macAddUserFunc{}.Execute(context.Background(), rt, &macAddUserArgs{Group: "staff", Name: "charlie"})
	if err != nil || res != true {
		t.Fatalf("adduser = %v %v", res, err)
	}
	if len(runner.calls) == 0 || !runner.calls[len(runner.calls)-1].Shell {
		t.Fatal("adduser must use shell command contract")
	}
}

func TestDarwinGroupValidation(t *testing.T) {
	runner := &darwinGroupRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	_, err := macAddFunc{}.Execute(context.Background(), rt, &macAddArgs{Name: "bad group"})
	if err == nil || !strings.Contains(err.Error(), "cannot contain whitespace") {
		t.Fatalf("whitespace validation = %v", err)
	}
	_, err = macDeleteFunc{}.Execute(context.Background(), rt, &macDeleteArgs{Name: "_hidden"})
	if err == nil || !strings.Contains(err.Error(), "beginning with underscores") {
		t.Fatalf("underscore validation = %v", err)
	}
}
