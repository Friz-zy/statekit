package pkg

import (
	"context"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execpkg "github.com/friz-zy/statekit/modules/exec/pkg"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

// scriptRunner answers dpkg-query style calls in order.
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

func newRT(installedVersion string) (*runtime.Runtime, *scriptRunner) {
	runner := &scriptRunner{}
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{Package: "apt", OS: &facts.OSFacts{Family: facts.FamilyDebian}}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    runner,
		FS:        runtime.NewMemoryFS(),
	}
	if err := pkgprovider.Register(rt.Providers); err != nil {
		panic(err)
	}
	if err := execpkg.Register(rt.Exec); err != nil {
		panic(err)
	}
	if installedVersion != "" {
		runner.script = append(runner.script, process.CommandResult{
			Stdout: []byte(installedVersion + "\n"), ExitCode: 0,
		})
	}
	return rt, runner
}

func TestInstalledAlreadySatisfied(t *testing.T) {
	rt, _ := newRT("8.14.1")
	res := installedFunc{}.Apply(context.Background(), rt, &installedArgs{Name: "curl"})
	if !res.Succeeded() || res.Changed() {
		t.Fatalf("satisfied result wrong: %+v", res)
	}
	if res.Comment != "Package curl is already installed" {
		t.Fatalf("Salt comment mismatch: %q", res.Comment)
	}
}

func TestInstalledTestModePlanShape(t *testing.T) {
	// Plan section 12 contract: result null, changes old->new, would-comment.
	rt, runner := newRT("") // not installed; first query returns empty
	runner.script = nil     // all queries empty -> not installed

	res := installedFunc{}.Apply(context.Background(), rt, &installedArgs{Name: "curl", Test: true})
	if res.Result != nil {
		t.Fatal("test mode must carry null result")
	}
	delta := res.Changes["curl"].(map[string]any)
	if delta["old"] != "" || delta["new"] != "latest" {
		t.Fatalf("plan changes shape wrong: %+v", delta)
	}
	if res.Comment != "Package curl would be installed" {
		t.Fatalf("plan comment mismatch: %q", res.Comment)
	}
	for _, call := range runner.calls {
		if strings_contains(call, "install") {
			t.Fatal("test mode must not install anything")
		}
	}
}

func TestInstalledAppliesAndReportsDelta(t *testing.T) {
	rt, runner := newRT("")
	// Sequence per Apply: state old-version query -> exec pkg.install
	// (pre-check, apt-get install, post-check) -> state verification.
	runner.script = []process.CommandResult{
		{Stdout: []byte(""), ExitCode: 1},         // state: old version absent
		{Stdout: []byte(""), ExitCode: 1},         // exec install pre-check
		{Stdout: []byte(""), ExitCode: 0},         // apt-get install -y curl
		{Stdout: []byte("8.14.1\n"), ExitCode: 0}, // exec install post-check
		{Stdout: []byte("8.14.1\n"), ExitCode: 0}, // state: verify new version
	}
	res := installedFunc{}.Apply(context.Background(), rt, &installedArgs{Name: "curl"})
	if !res.Succeeded() || !res.Changed() {
		t.Fatalf("install state wrong: %+v", res)
	}
	delta := res.Changes["curl"].(map[string]any)
	if delta["new"] != "8.14.1" {
		t.Fatalf("delta new = %v", delta["new"])
	}
}

func strings_contains(argv []string, needle string) bool {
	for _, arg := range argv {
		if arg == needle {
			return true
		}
	}
	return false
}

func TestRemovedSemantics(t *testing.T) {
	rt, runner := newRT("")
	runner.script = []process.CommandResult{
		{Stdout: []byte(""), ExitCode: 1}, // absent
	}
	gone := removedFunc{}.Apply(context.Background(), rt, &removedArgs{Name: "curl"})
	if !gone.Succeeded() || gone.Changed() {
		t.Fatalf("already-removed wrong: %+v", gone)
	}

	rt2, runner2 := newRT("")
	runner2.script = []process.CommandResult{
		{Stdout: []byte("8.14.1\n"), ExitCode: 0}, // present
	}
	pending := removedFunc{}.Apply(context.Background(), rt2, &removedArgs{Name: "curl", Test: true})
	if pending.Result != nil {
		t.Fatal("remove test mode must pend")
	}
	delta := pending.Changes["curl"].(map[string]any)
	if delta["old"] != "8.14.1" || delta["new"] != "" {
		t.Fatalf("remove delta wrong: %+v", delta)
	}
	if pending.Comment != "Package curl would be removed" {
		t.Fatalf("comment = %q", pending.Comment)
	}
}
