//go:build windows

package pkg

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type windowsPkgRunner struct{ calls []process.Command }

func (r *windowsPkgRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name == "powershell.exe" {
		data, _ := json.Marshal([]map[string]any{
			{"Name": "Git.Git", "Version": "2.45.0", "ProviderName": "winget"},
			{"Name": "7zip", "Version": "24.1", "ProviderName": "winget"},
		})
		return process.CommandResult{ExitCode: 0, Stdout: data}
	}
	if command.Name == "winget" && len(command.Args) > 0 && command.Args[0] == "show" {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("Name: Git\nVersion: 2.46.0\n")}
	}
	return process.CommandResult{ExitCode: 0}
}

func TestWindowsPackageRecordsAndVersion(t *testing.T) {
	runner := &windowsPkgRunner{}
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{Package: "winget"}),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	listed, err := listPackages(context.Background(), rt, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := listed["Git.Git"].([]string); len(got) != 1 || got[0] != "2.45.0" {
		t.Fatalf("list = %#v", listed)
	}
	latest := managerVersion(context.Background(), rt, "Git.Git")
	if latest != "2.46.0" {
		t.Fatalf("latest = %q", latest)
	}
	if compareVersionStrings("latest", "999") <= 0 || compareVersionStrings("latest", "latest") != 0 || compareVersionStrings("bogus", "1") != -1 {
		t.Fatal("version comparator")
	}
}

func TestWindowsPackageBoundariesAndTargets(t *testing.T) {
	rt := &runtime.Runtime{Runner: &windowsPkgRunner{}, FS: runtime.NewMemoryFS()}
	if got := targetNamesWin(nil, []any{map[string]any{"name": "Git.Git", "version": "latest"}}); len(got) != 1 || got[0] != "Git.Git" {
		t.Fatalf("targets = %v", got)
	}
	_, err := winListAvailableFunc{}.Execute(context.Background(), rt, &winListAvailableArgs{})
	if err == nil || !strings.Contains(err.Error(), "winrepo/fileserver boundary") {
		t.Fatalf("list available boundary = %v", err)
	}
	_, err = winRefreshDBFunc{}.Execute(context.Background(), rt, &winRefreshDBArgs{})
	if err == nil || !strings.Contains(err.Error(), "winrepo/fileserver boundary") {
		t.Fatalf("refresh boundary = %v", err)
	}
}

func TestWindowsPackagePlatform(t *testing.T) {
	platforms := (winListPkgsFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "windows" {
		t.Fatalf("platforms = %v", platforms)
	}
}
