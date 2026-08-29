package pkg

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// scriptRunner answers each invocation in order with scripted output.
type scriptRunner struct {
	script []process.CommandResult
	calls  [][]string
}

func (s *scriptRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	s.calls = append(s.calls, append([]string{cmd.Name}, cmd.Args...))
	if len(s.script) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	next := s.script[0]
	s.script = s.script[1:]
	return next
}

func newRT(manager string) (*runtime.Runtime, *scriptRunner) {
	runner := &scriptRunner{}
	rt := &runtime.Runtime{
		Facts: facts.ForTesting(facts.Overrides{
			Package: manager,
			OS:      &facts.OSFacts{Family: facts.FamilyDebian},
		}),
		Runner:    runner,
		FS:        runtime.NewMemoryFS(),
		Providers: runtime.NewProviderRegistry(),
	}
	if err := Register(rt.Providers); err != nil {
		panic(err)
	}
	return rt, runner
}

func TestSelectByPackageManager(t *testing.T) {
	for manager, want := range map[string]string{
		"apt": "apt", "dnf": "dnf", "yum": "yum", "zypper": "zypper",
		"pacman": "pacman", "apk": "apk", "brew": "brew", "port": "port",
	} {
		rt, _ := newRT(manager)
		name, err := Select(rt.Facts)
		if err != nil || name != want {
			t.Fatalf("Select(%q) = %q, %v", manager, name, err)
		}
	}
	rt, _ := newRT("")
	if _, err := Select(rt.Facts); err == nil {
		t.Fatal("missing package manager must fail")
	}
}

func TestDarwinProviderParsing(t *testing.T) {
	rt, runner := newRT("brew")
	provider, err := Resolve(rt)
	if err != nil || provider.Name() != "brew" {
		t.Fatalf("brew resolve = %v %v", provider, err)
	}
	runner.script = []process.CommandResult{{
		Stdout: []byte("curl 8.14.1\nvim 9.0\n"), ExitCode: 0,
	}}
	listed, err := provider.List(context.Background(), rt)
	if err != nil || listed["curl"] != "8.14.1" || listed["vim"] != "9.0" {
		t.Fatalf("brew list = %v %v", listed, err)
	}
	runner.script = []process.CommandResult{{Stdout: []byte("curl 8.14.1\n"), ExitCode: 0}}
	version, err := provider.Version(context.Background(), rt, "curl")
	if err != nil || version != "8.14.1" {
		t.Fatalf("brew version = %q %v", version, err)
	}
	if err := provider.Install(context.Background(), rt, "curl", "8.14.1"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "brew install curl@8.14.1" {
		t.Fatalf("brew install = %q", got)
	}

	rt, runner = newRT("port")
	provider, err = Resolve(rt)
	if err != nil || provider.Name() != "port" {
		t.Fatalf("port resolve = %v %v", provider, err)
	}
	runner.script = []process.CommandResult{{Stdout: []byte("curl @8.14.1_0 (active)\n"), ExitCode: 0}}
	listed, err = provider.List(context.Background(), rt)
	if err != nil || listed["curl"] != "8.14.1_0" {
		t.Fatalf("port list = %v %v", listed, err)
	}
}

func TestWindowsProviderVersionPin(t *testing.T) {
	rt, runner := newRT("winget")
	provider, err := Resolve(rt)
	if err != nil || provider.Name() != "winget" {
		t.Fatalf("winget resolve = %v %v", provider, err)
	}
	if err := provider.Install(context.Background(), rt, "Git.Git", "2.45.0"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "winget install --id Git.Git --silent --accept-package-agreements --accept-source-agreements --version 2.45.0" {
		t.Fatalf("winget install = %q", got)
	}
}

func TestAptVersionQuery(t *testing.T) {
	rt, runner := newRT("apt")
	provider, err := Resolve(rt)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	runner.script = []process.CommandResult{
		{Stdout: []byte("8.14.1\n"), ExitCode: 0},
	}
	version, err := provider.Version(context.Background(), rt, "curl")
	if err != nil || version != "8.14.1" {
		t.Fatalf("version = %q, %v", version, err)
	}
	want := "dpkg-query -W -f=${Version}\n curl"
	if strings.Join(runner.calls[len(runner.calls)-1], " ") != want {
		t.Fatalf("argv = %v", runner.calls[len(runner.calls)-1])
	}

	// Not installed: dpkg-query exits non-zero with empty output -> "" like Salt.
	runner.script = []process.CommandResult{{Stdout: []byte(""), ExitCode: 1}}
	version, _ = provider.Version(context.Background(), rt, "curl")
	if version != "" {
		t.Fatalf("uninstalled version must be empty, got %q", version)
	}
}

func TestInstallPinsVersion(t *testing.T) {
	rt, runner := newRT("apt")
	provider, _ := Resolve(rt)
	err := provider.Install(context.Background(), rt, "curl", "8.14.1")
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	got := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if got != "apt-get install -y curl=8.14.1" {
		t.Fatalf("install argv = %q", got)
	}
	err = provider.Install(context.Background(), rt, "curl", "")
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "apt-get install -y curl" {
		t.Fatalf("bare install argv = %q", got)
	}
}

func TestListParsing(t *testing.T) {
	rt, runner := newRT("apt")
	provider, _ := Resolve(rt)
	runner.script = []process.CommandResult{
		{Stdout: []byte("curl 8.14.1-1\nvim 9.0\n"), ExitCode: 0},
	}
	packages, err := provider.List(context.Background(), rt)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if packages["curl"] != "8.14.1-1" || packages["vim"] != "9.0" {
		t.Fatalf("parsed list wrong: %+v", packages)
	}
}

func TestRpmVersionIgnoresNotInstalled(t *testing.T) {
	rt, runner := newRT("dnf")
	provider, _ := Resolve(rt)
	runner.script = []process.CommandResult{
		{Stdout: []byte("package curl is not installed\n"), ExitCode: 1},
	}
	version, err := provider.Version(context.Background(), rt, "curl")
	if err != nil || version != "" {
		t.Fatalf("rpm uninstalled version = %q, %v", version, err)
	}
}
