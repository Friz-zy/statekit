package macpackage

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type macPackageRunner struct {
	calls []process.Command
}

func (r *macPackageRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	switch {
	case command.Name == "installer":
		return process.CommandResult{ExitCode: 0, Stdout: []byte("installed")}
	case command.Name == "rsync":
		return process.CommandResult{ExitCode: 0, Stdout: []byte("copied")}
	case command.Name == "hdiutil":
		return process.CommandResult{ExitCode: 0, Stdout: []byte("attached")}
	case command.Name == "pkgutil":
		return process.CommandResult{ExitCode: 0, Stdout: []byte("com.apple.base\ncom.example.app\n")}
	case strings.HasPrefix(command.Name, "xar -t"):
		return process.CommandResult{ExitCode: 1, Stdout: []byte("Error opening archive\n")}
	case strings.Contains(command.Name, "PlistBuddy"):
		return process.CommandResult{ExitCode: 0, Stdout: []byte("com.example.app\n")}
	case strings.HasPrefix(command.Name, "find "):
		return process.CommandResult{ExitCode: 0, Stdout: []byte("/tmp/bundle/app.pkg\n")}
	default:
		return process.CommandResult{ExitCode: 0}
	}
}

func macPackageRuntime(t *testing.T) (*runtime.Runtime, *macPackageRunner) {
	t.Helper()
	fs := runtime.NewMemoryFS()
	runner := &macPackageRunner{}
	return &runtime.Runtime{FS: fs, Runner: runner}, runner
}

func TestMacPackageNativeCommands(t *testing.T) {
	rt, runner := macPackageRuntime(t)
	res, err := installFunc{}.Execute(context.Background(), rt, &installArgs{
		Pkg: "/tmp/example.pkg", AllowUntrusted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]any); got["retcode"] != 0 || got["stdout"] != "installed" {
		t.Fatalf("install = %#v", res)
	}
	if len(runner.calls) == 0 || runner.calls[0].Shell {
		t.Fatalf("plain install command = %+v", runner.calls)
	}
	res, err = installFunc{}.Execute(context.Background(), rt, &installArgs{Pkg: "*.pkg", Target: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) < 2 || !runner.calls[1].Shell {
		t.Fatalf("wildcard install command = %+v", runner.calls[1])
	}
	res, err = installAppFunc{}.Execute(context.Background(), rt, &installAppArgs{App: "/tmp/Demo.app"})
	if err != nil || res != "copied" {
		t.Fatalf("install app = %#v %v", res, err)
	}
	res, err = mountFunc{}.Execute(context.Background(), rt, &mountArgs{DMG: "/tmp/demo.dmg"})
	if err != nil {
		t.Fatal(err)
	}
	mount := res.([]any)
	if mount[0] != "attached" || mount[1] == "" {
		t.Fatalf("mount = %#v", mount)
	}
	res, err = installedPkgsFunc{}.Execute(context.Background(), rt, installedPkgsArgs{})
	if err != nil || len(res.([]string)) != 3 {
		t.Fatalf("installed packages = %#v %v", res, err)
	}
}

func TestMacPackageIdentifiersAndCleanup(t *testing.T) {
	rt, runner := macPackageRuntime(t)
	res, err := getPkgIDFunc{}.Execute(context.Background(), rt, &getPkgIDArgs{Pkg: "/tmp/not-a-pkg"})
	if err != nil {
		t.Fatal(err)
	}
	ids := res.([]string)
	if len(ids) != 1 || ids[0] != "com.example.app" {
		t.Fatalf("directory package ids = %v", ids)
	}
	if len(runner.calls) == 0 || !strings.Contains(runner.calls[0].Name, "xar -t") {
		t.Fatalf("xar call missing = %+v", runner.calls)
	}
	if err := rt.FS.MkdirAll("/tmp/Demo.app", 0o755); err != nil {
		t.Fatal(err)
	}
	res, err = uninstallAppFunc{}.Execute(context.Background(), rt, &uninstallAppArgs{App: "/tmp/Demo.app"})
	if err != nil || res != true {
		t.Fatalf("uninstall = %#v %v", res, err)
	}
	if _, err := rt.FS.Stat("/tmp/Demo.app"); err == nil {
		t.Fatal("app directory remains")
	}
	res, err = getMpkgIDsFunc{}.Execute(context.Background(), rt, &getMpkgIDsArgs{MPKG: "/tmp/bundle"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.([]string); len(got) != 1 || got[0] != "com.example.app" {
		t.Fatalf("mpkg ids = %v", got)
	}
}

func TestMacPackagePlatform(t *testing.T) {
	platforms := (installFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "darwin" {
		t.Fatalf("platforms = %v", platforms)
	}
}
