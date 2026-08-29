//go:build windows

package file

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type windowsFileRunner struct{ calls []process.Command }

func (r *windowsFileRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name == "attrib.exe" {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("A    R    C:\\tmp\\file.txt\r\n")}
	}
	if command.Name == "powershell.exe" {
		return process.CommandResult{ExitCode: 0, Stdout: []byte(`{"owner":"ACME\\alice","group":"ACME\\users"}`)}
	}
	return process.CommandResult{ExitCode: 0}
}

func TestWindowsFileAttributeAndPermissionHelpers(t *testing.T) {
	runner := &windowsFileRunner{}
	fs := runtime.NewMemoryFS()
	if err := fs.WriteFile("C:\\tmp\\file.txt", []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{Runner: runner, FS: fs}
	attrs, err := winGetAttributesFunc{}.Execute(context.Background(), rt, &winVersionArgs{Path: "C:\\tmp\\file.txt"})
	if err != nil {
		t.Fatal(err)
	}
	value := attrs.(map[string]any)
	if value["archive"] != true || value["readonly"] != true || value["directory"] != false {
		t.Fatalf("attributes = %#v", value)
	}
	res, err := winSetAttributesFunc{}.Execute(context.Background(), rt, &winSetAttributesArgs{
		Path: "C:\\tmp\\file.txt", Hidden: pbWinFile(true), Readonly: pbWinFile(false),
	})
	if err != nil || res != true {
		t.Fatalf("set attributes = %v %v", res, err)
	}
	if got := winPermText(map[string]any{"perms": "full_control"}); got != "F" {
		t.Fatalf("permission text = %q", got)
	}
	res, err = winSetPermsFunc{}.Execute(context.Background(), rt, &winPermsArgs{
		Path: "C:\\tmp\\file.txt", GrantPerms: map[string]any{
			"ACME\\alice": map[string]any{"perms": "read_execute"},
		},
	})
	if err != nil || res != true {
		t.Fatalf("set perms = %v %v", res, err)
	}
	if len(runner.calls) < 2 {
		t.Fatalf("runner calls = %+v", runner.calls)
	}
}

func pbWinFile(value bool) *bool { return &value }

func TestWindowsFileModeLinksAndErrors(t *testing.T) {
	runner := &windowsFileRunner{}
	fs := runtime.NewMemoryFS()
	if err := fs.WriteFile("C:\\tmp\\target", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{Runner: runner, FS: fs}
	res, err := winGetModeFunc{}.Execute(context.Background(), rt, &winPathFollowArgs{Path: "C:\\tmp\\target"})
	if err != nil || res != nil {
		t.Fatalf("get mode = %v %v", res, err)
	}
	res, err = winSymlinkFunc{}.Execute(context.Background(), rt, &winSymlinkArgs{
		Src: "C:\\tmp\\target", Link: "C:\\tmp\\link",
	})
	if err != nil || res != true {
		t.Fatalf("symlink = %v %v", res, err)
	}
	res, err = winIsLinkFunc{}.Execute(context.Background(), rt, &winIsLinkArgs{Path: "C:\\tmp\\link"})
	if err != nil || res != true {
		t.Fatalf("is link = %v %v", res, err)
	}
	_, err = winSymlinkFunc{}.Execute(context.Background(), rt, &winSymlinkArgs{
		Src: "C:\\tmp\\target", Link: "relative-link",
	})
	if err == nil || !strings.Contains(err.Error(), "Link path must be absolute") {
		t.Fatalf("relative link = %v", err)
	}
	res, err = winRemoveFunc{}.Execute(context.Background(), rt, &winRemoveArgs{Path: "C:\\tmp\\link"})
	if err != nil || res != true {
		t.Fatalf("remove link = %v %v", res, err)
	}
}
