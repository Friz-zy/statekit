package win_firewall

import (
	"context"
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeExec struct {
	name string
	call func(any) (any, error)
}

func (f fakeExec) Name() string { return f.name }
func (f fakeExec) Args() any    { return map[string]any{} }
func (f fakeExec) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	return f.call(args)
}

func firewallStateRuntime(t *testing.T, ruleExists bool) *runtime.Runtime {
	t.Helper()
	exec := runtime.NewExecRegistry()
	register := func(name string, call func(any) (any, error)) {
		t.Helper()
		if err := exec.Register(fakeExec{name: name, call: call}); err != nil {
			t.Fatal(err)
		}
	}
	register("firewall.get_config", func(any) (any, error) {
		return map[string]bool{"Domain": true, "Private": false, "Public": true}, nil
	})
	register("firewall.enable", func(any) (any, error) { return true, nil })
	register("firewall.disable", func(any) (any, error) { return true, nil })
	register("firewall.rule_exists", func(any) (any, error) { return ruleExists, nil })
	register("firewall.add_rule", func(any) (any, error) { return true, nil })
	return &runtime.Runtime{Exec: exec}
}

func TestProfileStateTestModeAndIdempotence(t *testing.T) {
	rt := firewallStateRuntime(t, false)
	pending := disabledFunc{}.Apply(context.Background(), rt, &profileArgs{Name: "domainprofile", Test: true})
	if pending.Result != nil || pending.Changes["Domain"] != "disabled" {
		t.Fatalf("pending = %+v", pending)
	}
	applied := disabledFunc{}.Apply(context.Background(), rt, &profileArgs{Name: "domainprofile"})
	if !applied.Succeeded() || applied.Changes["Domain"] != "disabled" {
		t.Fatalf("applied = %+v", applied)
	}
	already := enabledFunc{}.Apply(context.Background(), rt, &profileArgs{Name: "domainprofile"})
	if !already.Succeeded() || len(already.Changes) != 0 {
		t.Fatalf("idempotent = %+v", already)
	}
}

func TestRuleStateAndInvalidProfile(t *testing.T) {
	rt := firewallStateRuntime(t, false)
	pending := addRuleFunc{}.Apply(context.Background(), rt, &addRuleArgs{Name: "HTTPS", LocalPort: "443", Test: true})
	if pending.Result != nil || pending.Changes["new rule"] != "HTTPS" {
		t.Fatalf("rule pending = %+v", pending)
	}
	applied := addRuleFunc{}.Apply(context.Background(), rt, &addRuleArgs{Name: "HTTPS", LocalPort: "443"})
	if !applied.Succeeded() {
		t.Fatalf("rule applied = %+v", applied)
	}
	invalid := enabledFunc{}.Apply(context.Background(), rt, &profileArgs{Name: "bad"})
	if invalid.Result == nil || *invalid.Result || invalid.Comment == "" {
		t.Fatalf("invalid profile = %+v", invalid)
	}
	if invalid.Changes == nil {
		t.Fatal("state result changes must be normalized")
	}
}
