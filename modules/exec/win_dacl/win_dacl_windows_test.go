//go:build windows

package win_dacl

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type daclRunner struct{ calls []process.Command }

func (r *daclRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	return process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("C:\\Temp\\demo.txt\nACME\\alice:(I)(F)\nBUILTIN\\Users:(RX)\n"),
	}
}

func TestWindowsDACLGetAndChecks(t *testing.T) {
	runner := &daclRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := getFunc{}.Execute(context.Background(), rt, &getArgs{
		Path: "C:\\Temp\\demo.txt", ObjectType: "file", User: stringPtrDACL("alice"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]any)
	acls := got["ACLs"].([]string)
	if len(acls) != 1 || !strings.Contains(acls[0], "alice") {
		t.Fatalf("ACLs = %#v", got)
	}
	res, err = checkAceFunc{}.Execute(context.Background(), rt, &checkAceArgs{
		Path: "C:\\Temp\\demo.txt", ObjectType: "file", User: "alice", Permission: stringPtrDACL("full_control"),
	})
	if err != nil || res.(map[string]any)["Exists"] != true {
		t.Fatalf("check ace = %v %v", res, err)
	}
	res, err = checkInheritanceFunc{}.Execute(context.Background(), rt, &checkInheritanceArgs{
		Path: "C:\\Temp\\demo.txt", ObjectType: "file",
	})
	if err != nil || res.(map[string]any)["Inheritance"] != true {
		t.Fatalf("check inheritance = %v %v", res, err)
	}
}

func TestWindowsDACLMutationAndBoundaries(t *testing.T) {
	runner := &daclRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := addAceFunc{}.Execute(context.Background(), rt, &addAceArgs{
		Path: "C:\\Temp\\demo.txt", ObjectType: "file", User: "alice", Permission: "full_control", AceType: "allow", Propagation: "file",
	})
	if err != nil || res.(map[string]any)["result"] != true {
		t.Fatalf("add ace = %v %v", res, err)
	}
	res, err = rmAceFunc{}.Execute(context.Background(), rt, &rmAceArgs{
		Path: "C:\\Temp\\demo.txt", ObjectType: "file", User: "alice", AceType: stringPtrDACL("deny"),
	})
	if err != nil || res.(map[string]any)["result"] != true {
		t.Fatalf("remove ace = %v %v", res, err)
	}
	res, err = disableInheritanceFunc{}.Execute(context.Background(), rt, &inheritanceArgs{
		Path: "C:\\Temp\\demo.txt", ObjectType: "file", Copy: boolPtrDACL(false),
	})
	if err != nil || res.(map[string]any)["result"] != true {
		t.Fatalf("disable inheritance = %v %v", res, err)
	}
	if _, err := (getFunc{}).Execute(context.Background(), rt, &getArgs{
		Path: "HKLM\\Software\\Demo", ObjectType: "registry",
	}); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("registry boundary = %v", err)
	}
	if len(runner.calls) < 3 {
		t.Fatalf("calls = %+v", runner.calls)
	}
}

func stringPtrDACL(value string) *string { return &value }
func boolPtrDACL(value bool) *bool       { return &value }
