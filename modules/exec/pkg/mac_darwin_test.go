//go:build darwin

package pkg

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type darwinPkgRunner struct {
	calls []process.Command
}

func (r *darwinPkgRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name == "/opt/homebrew/bin/brew" && len(command.Args) >= 3 && command.Args[0] == "info" {
		return process.CommandResult{ExitCode: 0, Stdout: []byte(`{"formulae":[{"name":"wget","full_name":"wget","aliases":["gnu-wget"],"installed":[{"version":"1.2"}]}],"casks":[{"token":"iterm2","full_token":"homebrew/cask/iterm2","tap":"","installed":"3.5"}]}`)}
	}
	if command.Name == "/opt/homebrew/bin/brew" && len(command.Args) >= 2 && command.Args[0] == "list" {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("wget\n")}
	}
	if command.Name == "port" && len(command.Args) >= 1 && command.Args[0] == "installed" {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("curl @8.14.1_0 (active)\n")}
	}
	return process.CommandResult{ExitCode: 0}
}

func TestDarwinPackageManagerParsers(t *testing.T) {
	t.Setenv("HOMEBREW_PREFIX", "/opt/homebrew")
	runner := &darwinPkgRunner{}
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{Package: "brew"}),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	listed, err := packageList(context.Background(), rt, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if listed["wget"] != "1.2" || listed["gnu-wget"] != "1.2" ||
		listed["iterm2"] != "3.5" || listed["homebrew/cask/iterm2"] != "3.5" {
		t.Fatalf("brew packages = %#v", listed)
	}
	if got := homebrewPrefix(rt); got != "/opt/homebrew" || brewPath(rt) != "/opt/homebrew/bin/brew" {
		t.Fatalf("brew prefix/path = %q %q", got, brewPath(rt))
	}

	rt.Facts = facts.ForTesting(facts.Overrides{Package: "port"})
	listed, err = packageList(context.Background(), rt, false, nil)
	if err != nil || listed["curl"] != "8.14.1_0" {
		t.Fatalf("port packages = %#v %v", listed, err)
	}
}

func TestDarwinBrewInfoVersionAndTypeValidation(t *testing.T) {
	if got := brewInfoVersion(map[string]any{
		"versions": map[string]any{"stable": "1.0", "devel": "0.9"},
		"revision": float64(2),
	}); got != "1.0_2" {
		t.Fatalf("brew formula version = %q", got)
	}
	if got := brewInfoVersion(map[string]any{"version": "3.5"}); got != "3.5" {
		t.Fatalf("brew cask version = %q", got)
	}
	if !strings.Contains(homebrewTrustTypeList, "tap") {
		t.Fatal("trust type list missing tap")
	}
}
