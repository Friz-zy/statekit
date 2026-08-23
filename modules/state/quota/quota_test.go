package quota

import (
	"context"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
)

// stubFunc scripts quota.* execution results; the last value repeats.
type stubFunc struct {
	name    string
	results []any
	calls   []any
}

func (s *stubFunc) Name() string { return s.name }
func (s *stubFunc) Args() any    { return struct{}{} }
func (s *stubFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	s.calls = append(s.calls, args)
	if len(s.results) == 0 {
		return nil, nil
	}
	next := s.results[0]
	if len(s.results) > 1 {
		s.results = s.results[1:]
	}
	return next, nil
}

func newRT(stubs ...*stubFunc) *runtime.Runtime {
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		FS:        runtime.NewMemoryFS(),
	}
	for _, s := range stubs {
		if err := rt.Exec.Register(s); err != nil {
			panic(err)
		}
	}
	return rt
}

func TestModeAlreadySet(t *testing.T) {
	getMode := &stubFunc{name: "quota.get_mode", results: []any{map[string]any{
		"/": map[string]any{"user": "on"},
	}}}
	rt := newRT(getMode)
	res := modeFunc{}.Apply(context.Background(), rt,
		&modeArgs{Name: "/", Mode: "true", QuotaType: "user"})
	if !res.Succeeded() || res.Comment != "Quota for / already set to on" {
		t.Fatalf("already set = %+v", res)
	}
}

func TestModePendingAndApply(t *testing.T) {
	offMode := &stubFunc{name: "quota.get_mode", results: []any{map[string]any{
		"/": map[string]any{"user": "off"},
	}}}
	rt := newRT(offMode)
	pending := modeFunc{}.Apply(context.Background(), rt,
		&modeArgs{Name: "/", Mode: "true", QuotaType: "user", Test: true})
	if pending.Result != nil || pending.Comment != "Quota for / needs to be set to on" {
		t.Fatalf("pending = %+v", pending)
	}

	onFn := &stubFunc{name: "quota.on", results: []any{true}}
	getMode2 := &stubFunc{name: "quota.get_mode", results: []any{map[string]any{
		"/": map[string]any{"user": "off"},
	}}}
	rt2 := newRT(onFn, getMode2)
	done := modeFunc{}.Apply(context.Background(), rt2,
		&modeArgs{Name: "/", Mode: "on", QuotaType: "user"})
	if !done.Succeeded() || done.Comment != "Set quota for / to on" ||
		done.Changes["quota"] != "/" {
		t.Fatalf("applied = %+v", done)
	}
	if len(onFn.calls) != 1 {
		t.Fatal("quota.on not invoked")
	}
}

func TestModeFailurePath(t *testing.T) {
	failingOn := &stubFunc{name: "quota.on", results: []any{false}}
	getMode := &stubFunc{name: "quota.get_mode", results: []any{map[string]any{}}}
	rt := newRT(failingOn, getMode)
	res := modeFunc{}.Apply(context.Background(), rt,
		&modeArgs{Name: "/", Mode: "true", QuotaType: "user"})
	if res.Succeeded() || res.Comment != "Failed to set quota for / to on" {
		t.Fatalf("failure = %+v", res)
	}
}

func TestPlatformConstraint(t *testing.T) {
	reg := runtime.NewStateRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Names()) != 1 || reg.Names()[0] != "quota.mode" {
		t.Fatalf("states = %v", reg.Names())
	}
	fn, _ := reg.Get("quota.mode")
	if c, ok := fn.(interface{ Platforms() []string }); !ok ||
		c.Platforms()[0] != "linux" {
		t.Fatal("quota.mode not linux-constrained")
	}
}
