package pkgutil

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type pkgutilRunner struct {
	installed []string
	installID string
	calls     []process.Command
}

func (r *pkgutilRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	switch command.Name {
	case "pkgutil":
		if len(command.Args) > 0 && command.Args[0] == "--pkgs" {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(strings.Join(r.installed, "\n"))}
		}
		if len(command.Args) > 0 && command.Args[0] == "--forget" && len(command.Args) > 1 {
			var kept []string
			for _, item := range r.installed {
				if item != command.Args[1] {
					kept = append(kept, item)
				}
			}
			r.installed = kept
		}
	case "installer":
		if r.installID != "" {
			r.installed = append(r.installed, r.installID)
		}
	}
	return process.CommandResult{ExitCode: 0}
}

func pkgutilTestRuntime(t *testing.T) (*runtime.Runtime, *pkgutilRunner) {
	t.Helper()
	fs := runtime.NewMemoryFS()
	runner := &pkgutilRunner{}
	return &runtime.Runtime{FS: fs, Runner: runner}, runner
}

func TestPkgutilListInstallForget(t *testing.T) {
	rt, runner := pkgutilTestRuntime(t)
	runner.installed = []string{"com.apple.base", "com.example.old"}
	res, err := listFunc{}.Execute(context.Background(), rt, listArgs{})
	if err != nil || !strings.Contains(strings.Join(res.([]string), ","), "com.apple.base") {
		t.Fatalf("list = %#v %v", res, err)
	}
	res, err = isInstalledFunc{}.Execute(context.Background(), rt, &isInstalledArgs{PackageID: "com.apple.base"})
	if err != nil || res != true {
		t.Fatalf("installed = %#v %v", res, err)
	}
	if err := rt.FS.WriteFile("/tmp/example.pkg", []byte("pkg"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner.installID = "com.example.new"
	res, err = installFunc{}.Execute(context.Background(), rt, &installArgs{
		Source: "/tmp/example.pkg", PackageID: "com.example.new",
	})
	if err != nil || res != true {
		t.Fatalf("install = %#v %v", res, err)
	}
	res, err = forgetFunc{}.Execute(context.Background(), rt, &forgetArgs{PackageID: "com.example.old"})
	if err != nil || res != true {
		t.Fatalf("forget = %#v %v", res, err)
	}
	if len(runner.calls) < 5 {
		t.Fatalf("calls = %+v", runner.calls)
	}
}

func TestPkgutilInstallGuardsAndPlatform(t *testing.T) {
	rt, _ := pkgutilTestRuntime(t)
	_, err := installFunc{}.Execute(context.Background(), rt, &installArgs{
		Source: "https://example.invalid/x.pkg", PackageID: "com.example.x",
	})
	if err == nil || !strings.Contains(err.Error(), "Unsupported scheme for source uri: https") {
		t.Fatalf("scheme guard = %v", err)
	}
	_, err = installFunc{}.Execute(context.Background(), rt, &installArgs{
		Source: "/tmp/missing.pkg", PackageID: "com.example.x",
	})
	if err == nil || !strings.Contains(err.Error(), "File not found") {
		t.Fatalf("path guard = %v", err)
	}
	platforms := (listFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "darwin" {
		t.Fatalf("platforms = %v", platforms)
	}
}
