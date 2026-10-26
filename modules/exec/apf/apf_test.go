package apf

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct {
	calls   []process.Command
	results []process.CommandResult
}

type availableRunner struct {
	*fakeRunner
	available map[string]bool
}

func (r *availableRunner) CommandAvailable(name string) bool { return r.available[name] }

func (f *fakeRunner) Run(_ context.Context, c process.Command) process.CommandResult {
	f.calls = append(f.calls, c)
	r := f.results[0]
	f.results = f.results[1:]
	return r
}

func TestActionsUseShellFreeArgv(t *testing.T) {
	checks := []struct {
		name string
		f    interface {
			Execute(context.Context, *runtime.Runtime, any) (any, error)
		}
		args any
		argv []string
	}{
		{"allow", allowFunc{}, &AllowArgs{IP: "192.0.2.1"}, []string{"apf", "-a", "192.0.2.1"}},
		{"deny", denyFunc{}, &IPArgs{IP: "192.0.2.1"}, []string{"apf", "-d", "192.0.2.1"}},
		{"remove", removeFunc{}, &IPArgs{IP: "192.0.2.1"}, []string{"apf", "-u", "192.0.2.1"}},
		{"refresh", refreshFunc{}, EmptyArgs{}, []string{"apf", "-e"}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			r := &fakeRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("done")}}}
			_, err := check.f.Execute(context.Background(), &runtime.Runtime{Runner: r}, check.args)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.calls) != 1 || r.calls[0].Shell || !reflect.DeepEqual(append([]string{r.calls[0].Name}, r.calls[0].Args...), check.argv) {
				t.Fatalf("command = %#v", r.calls)
			}
			if r.calls[0].Timeout <= 0 || r.calls[0].MaxStdoutBytes <= 0 {
				t.Fatal("command is not bounded")
			}
		})
	}
}

func TestRunningParsesFilterChain(t *testing.T) {
	r := &fakeRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("-P INPUT ACCEPT\n-N apf-sanity-check\n")}}}
	got, err := runningFunc{}.Execute(context.Background(), &runtime.Runtime{Runner: r}, EmptyArgs{})
	if err != nil || got != true {
		t.Fatalf("running = %v, %v", got, err)
	}
}

func TestAllowWithPortPreservesPinnedNoop(t *testing.T) {
	r := &fakeRunner{}
	port := "80"
	got, err := allowFunc{}.Execute(context.Background(), &runtime.Runtime{Runner: r}, &AllowArgs{IP: "192.0.2.1", Port: &port})
	if err != nil || got != nil || len(r.calls) != 0 {
		t.Fatalf("got %v, %v; calls %d", got, err, len(r.calls))
	}
}

func TestCommandFailureReturnsErrorPreferringStderr(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		stdout, stderr, want string
	}{
		{"stderr", "out", "err", "apf failed: err"},
		{"stdout fallback", "out", "", "apf failed: out"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeRunner{results: []process.CommandResult{{ExitCode: 1, Stdout: []byte(tc.stdout), Stderr: []byte(tc.stderr)}}}
			_, err := refreshFunc{}.Execute(context.Background(), &runtime.Runtime{Runner: r}, EmptyArgs{})
			if err == nil || err.Error() != tc.want {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLifecycleNoopsReturnNilAndDoNotMutate(t *testing.T) {
	checks := []struct {
		name string
		f    interface {
			Execute(context.Context, *runtime.Runtime, any) (any, error)
		}
		chains    string
		shouldRun bool
	}{
		{"disable stopped", disableFunc{}, "-P INPUT ACCEPT\n", false},
		{"enable running", enableFunc{}, "-N APF-Sanity\n", false},
		{"reload running", reloadFunc{}, "-N apf-sanity\n", false},
		{"reload stopped", reloadFunc{}, "", true},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte(tc.chains)}, {ExitCode: 0, Stdout: []byte("changed")}}}
			got, err := tc.f.Execute(context.Background(), &runtime.Runtime{Runner: r}, EmptyArgs{})
			if err != nil || (!tc.shouldRun && got != nil) || (tc.shouldRun && got != "changed") {
				t.Fatalf("got %v, %v", got, err)
			}
			wantCalls := 1
			if tc.shouldRun {
				wantCalls = 2
			}
			if len(r.calls) != wantCalls {
				t.Fatalf("calls = %d, want %d", len(r.calls), wantCalls)
			}
			if tc.shouldRun && r.calls[1].Name != "apf" {
				t.Fatalf("mutation command = %#v", r.calls[1])
			}
		})
	}
}

func TestLifecycleMutationsUseExactBoundedArgv(t *testing.T) {
	checks := []struct {
		name string
		f    interface {
			Execute(context.Context, *runtime.Runtime, any) (any, error)
		}
		status string
		argv   []string
	}{
		{"disable while running", disableFunc{}, "-N apf-sanity\n", []string{"apf", "-f"}},
		{"enable while stopped", enableFunc{}, "-N ordinary\n", []string{"apf", "-s"}},
		{"reload while stopped", reloadFunc{}, "-N ordinary\n", []string{"apf", "-r"}},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeRunner{results: []process.CommandResult{
				{ExitCode: 0, Stdout: []byte(tc.status)},
				{ExitCode: 0, Stdout: []byte("changed")},
			}}
			got, err := tc.f.Execute(context.Background(), &runtime.Runtime{Runner: r}, EmptyArgs{})
			if err != nil || got != "changed" {
				t.Fatalf("result = %v, error = %v", got, err)
			}
			if len(r.calls) != 2 {
				t.Fatalf("calls = %d, want one status and one mutation", len(r.calls))
			}
			mutation := r.calls[1]
			if mutation.Name != tc.argv[0] || !reflect.DeepEqual(mutation.Args, tc.argv[1:]) {
				t.Fatalf("mutation argv = %q %q, want %q", mutation.Name, mutation.Args, tc.argv)
			}
			if mutation.Shell {
				t.Fatal("mutation unexpectedly uses a shell")
			}
			if mutation.Timeout <= 0 || mutation.MaxStdoutBytes <= 0 || mutation.MaxStderrBytes <= 0 {
				t.Fatalf("mutation command is not bounded: timeout=%s stdout=%d stderr=%d", mutation.Timeout, mutation.MaxStdoutBytes, mutation.MaxStderrBytes)
			}
		})
	}
}

func TestRunningMissingAPFIsNotReportedRunning(t *testing.T) {
	r := &availableRunner{fakeRunner: &fakeRunner{}, available: map[string]bool{"iptables": true, "apf": false}}
	got, err := runningFunc{}.Execute(context.Background(), &runtime.Runtime{Runner: r}, EmptyArgs{})
	if err == nil || got != false || len(r.calls) != 0 {
		t.Fatalf("got %v, %v, calls %d", got, err, len(r.calls))
	}
}

func TestRunningNegativeCaseInsensitiveAndErrors(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		exit         int
		want         any
		wantError    string
	}{
		{"negative", "-N ordinary\n", 0, false, ""},
		{"case insensitive", "-N APF-SANITY\n", 0, true, ""},
		{"iptables error", "denied", 1, false, "apf: iptables status failed: denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeRunner{results: []process.CommandResult{{ExitCode: tc.exit, Stdout: []byte(tc.output)}}}
			got, err := runningFunc{}.Execute(context.Background(), &runtime.Runtime{Runner: r}, EmptyArgs{})
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			if tc.wantError == "" && err != nil || tc.wantError != "" && (err == nil || err.Error() != tc.wantError) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestUnavailableCommandAndAvailabilityCompatibility(t *testing.T) {
	missing := &availableRunner{fakeRunner: &fakeRunner{}, available: map[string]bool{"apf": false}}
	_, err := denyFunc{}.Execute(context.Background(), &runtime.Runtime{Runner: missing}, &IPArgs{IP: "host"})
	if err == nil || !strings.Contains(err.Error(), "command unavailable") {
		t.Fatalf("error = %v", err)
	}
	plain := &fakeRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("ok")}}}
	got, err := denyFunc{}.Execute(context.Background(), &runtime.Runtime{Runner: plain}, &IPArgs{IP: "host"})
	if err != nil || got != "ok" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestRegistrationContracts(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{"apf.allow", "apf.deny", "apf.disable", "apf.enable", "apf.refresh", "apf.reload", "apf.remove", "apf.running"}
	if !reflect.DeepEqual(reg.Names(), want) {
		t.Fatalf("names = %v", reg.Names())
	}
	for _, name := range want {
		f, ok := reg.Get(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		platform, ok := f.(interface{ Platforms() []string })
		if !ok || !reflect.DeepEqual(platform.Platforms(), []string{"linux"}) {
			t.Errorf("%s platform metadata missing or incorrect", name)
		}
	}
	allow, _ := reg.Get("apf.allow")
	allowArgs := reflect.TypeOf(allow.Args())
	if allowArgs.Field(0).Tag.Get("statekit") != "required,name=ip" || allowArgs.Field(1).Tag.Get("statekit") != "name=port" || allowArgs.Field(1).Type.Elem().Kind() != reflect.String {
		t.Fatalf("allow args do not preserve string ip/optional textual port contract: %v", allowArgs)
	}
	for _, name := range []string{"apf.deny", "apf.remove"} {
		f, _ := reg.Get(name)
		if reflect.TypeOf(f.Args()) != reflect.TypeOf(IPArgs{}) || reflect.TypeOf(f.Args()).Field(0).Tag.Get("statekit") != "required,name=ip" {
			t.Errorf("%s argument contract incorrect", name)
		}
	}
}
