package devmap

import (
	"context"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct {
	result process.CommandResult
	calls  [][]string
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	f.calls = append(f.calls, append([]string{cmd.Name}, cmd.Args...))
	return f.result
}

// TestMultipathList mirrors Salt's test_multipath_list.
func TestMultipathList(t *testing.T) {
	runner := &fakeRunner{result: process.CommandResult{Stdout: []byte("A\n")}}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	got, err := (multipathListFunc{}).Execute(context.Background(), rt, &MultipathListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"A"}) {
		t.Fatalf("list = %v", got)
	}
	if !reflect.DeepEqual(runner.calls, [][]string{{"multipath", "-l"}}) {
		t.Fatalf("argv = %v", runner.calls)
	}
}

// TestMultipathFlush mirrors Salt's test_multipath_flush.
func TestMultipathFlush(t *testing.T) {
	rt := &runtime.Runtime{Runner: &fakeRunner{}, FS: runtime.NewMemoryFS()}
	_, err := (multipathFlushFunc{}).Execute(context.Background(), rt,
		&MultipathFlushArgs{Device: "device"})
	if err == nil || err.Error() != "device does not exist" {
		t.Fatalf("missing device err = %v", err)
	}

	if err := rt.FS.MkdirAll("/dev", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/dev/mpath1", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{result: process.CommandResult{Stdout: []byte("A\n")}}
	rt.Runner = runner
	got, err := (multipathFlushFunc{}).Execute(context.Background(), rt,
		&MultipathFlushArgs{Device: "/dev/mpath1"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"A"}) {
		t.Fatalf("flush = %v", got)
	}
}

func TestPlatformConstraint(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, name := range reg.Names() {
		fn, _ := reg.Get(name)
		if c, ok := fn.(interface{ Platforms() []string }); !ok ||
			len(c.Platforms()) != 1 || c.Platforms()[0] != "linux" {
			t.Fatalf("%s not linux-constrained", name)
		}
	}
}
