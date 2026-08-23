package runtime

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/result"
)

type linuxOnlyExec struct{}

func (linuxOnlyExec) Name() string        { return "kmod.lsmod" }
func (linuxOnlyExec) Platforms() []string { return []string{"linux"} }
func (linuxOnlyExec) Args() any           { return struct{}{} }
func (linuxOnlyExec) Execute(_ context.Context, _ *Runtime, _ any) (any, error) {
	return true, nil
}

type anyPlatformState struct{}

func (anyPlatformState) Name() string { return "test.nop" }
func (anyPlatformState) Args() any    { return struct{}{} }
func (anyPlatformState) Apply(_ context.Context, _ *Runtime, _ any) result.StateResult {
	return result.Success("x", "")
}

func TestPlatformFiltering(t *testing.T) {
	reg := NewExecRegistry()
	if err := reg.Register(linuxOnlyExec{}); err != nil {
		t.Fatal(err)
	}

	names := reg.Names()
	goos := CurrentGOOS()
	if goos == "linux" {
		if len(names) != 1 || !strings.Contains(strings.Join(names, ","), "kmod.lsmod") {
			t.Fatalf("linux must see kmod: %v", names)
		}
		if _, err := reg.Call(context.Background(), &Runtime{}, "kmod.lsmod", nil); err != nil {
			t.Fatalf("call on linux failed: %v", err)
		}
		return
	}
	if len(names) != 0 {
		t.Fatalf("non-linux must hide constrained family: %v", names)
	}
	_, err := reg.Call(context.Background(), &Runtime{}, "kmod.lsmod", nil)
	var unsupported *UnsupportedError
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("cross-platform call must be unsupported, got %v", err)
	}
	_ = unsupported
}

func TestUnconstrainedVisibleEverywhere(t *testing.T) {
	sreg := NewStateRegistry()
	if err := sreg.Register(anyPlatformState{}); err != nil {
		t.Fatal(err)
	}
	if got := sreg.Names(); len(got) != 1 || got[0] != "test.nop" {
		t.Fatalf("names = %v", got)
	}
	res, err := sreg.Apply(context.Background(), &Runtime{}, "test.nop", nil)
	if err != nil || !res.Succeeded() {
		t.Fatalf("apply = %+v, %v", res, err)
	}
}
