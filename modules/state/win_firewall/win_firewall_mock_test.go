package win_firewall

// R7.5 mock tests for the win_firewall state functions, mapped onto
// saltstack/salt/states/win_firewall.py @ pinned revision 8b63e700637e:
// add_rule compiles absent rules to exact firewall.rule_exists +
// firewall.add_rule module calls with the documented defaults
// (protocol tcp, action allow, dir in, remoteip any), present rules
// short-circuit with Salt's "A rule with that name already exists"
// comment, test mode returns a pending result without mutation, and
// execution failures map to the "Could not add rule" comment; the
// enabled/disabled profile states compile to exact firewall.get_config
// + enable/disable calls keyed by the state-level profile name, with
// per-profile changes, missing-profile failures, invalid-profile
// SaltInvocationError mapping and no-change success comments. The exec
// functions are recording fakes so the assertions pin the exact typed
// arguments; this file is platform-neutral and runs on every GOOS.

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
	execfirewall "github.com/friz-zy/statekit/modules/exec/firewall"
)

// winFwStateCall records one execution-module invocation with the
// exact typed arguments the state compiled.
type winFwStateCall struct {
	name string
	args any
}

type winFwStateRec struct {
	name     string
	behavior func(args any) (any, error)
	calls    *[]winFwStateCall
}

func (f winFwStateRec) Name() string { return f.name }
func (f winFwStateRec) Args() any    { return map[string]any{} }
func (f winFwStateRec) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	*f.calls = append(*f.calls, winFwStateCall{name: f.name, args: args})
	return f.behavior(args)
}

// winFwStateConfig drives the recording registry.
type winFwStateConfig struct {
	config     map[string]bool
	ruleExists bool
	addRuleErr error
	configErr  error
	toggleErr  error
}

func winFwPtr(value string) *string { return &value }

func newWinFwStateRT(t *testing.T, cfg winFwStateConfig) (*runtime.Runtime, *[]winFwStateCall) {
	t.Helper()
	calls := &[]winFwStateCall{}
	exec := runtime.NewExecRegistry()
	register := func(name string, behavior func(args any) (any, error)) {
		t.Helper()
		if err := exec.Register(winFwStateRec{name: name, behavior: behavior, calls: calls}); err != nil {
			t.Fatal(err)
		}
	}
	register("firewall.get_config", func(any) (any, error) {
		if cfg.configErr != nil {
			return nil, cfg.configErr
		}
		if cfg.config == nil {
			return nil, nil
		}
		return cfg.config, nil
	})
	register("firewall.enable", func(any) (any, error) {
		if cfg.toggleErr != nil {
			return nil, cfg.toggleErr
		}
		return true, nil
	})
	register("firewall.disable", func(any) (any, error) {
		if cfg.toggleErr != nil {
			return nil, cfg.toggleErr
		}
		return true, nil
	})
	register("firewall.rule_exists", func(any) (any, error) { return cfg.ruleExists, nil })
	register("firewall.add_rule", func(any) (any, error) {
		if cfg.addRuleErr != nil {
			return nil, cfg.addRuleErr
		}
		return true, nil
	})
	return &runtime.Runtime{Exec: exec}, calls
}

func winFwStateNames(calls *[]winFwStateCall) []string {
	out := make([]string, 0, len(*calls))
	for _, call := range *calls {
		out = append(out, call.name)
	}
	return out
}

func TestWinFwStateAddRuleCompilesExactModuleCalls(t *testing.T) {
	// Absent rule with only required args: defaults compile to Salt's
	// documented protocol/action/dir/remoteip defaults.
	rt, calls := newWinFwStateRT(t, winFwStateConfig{ruleExists: false})
	ret := addRuleFunc{}.Apply(context.Background(), rt, &addRuleArgs{Name: "HTTPS", LocalPort: "443"})
	if !ret.Succeeded() || ret.Changes["new rule"] != "HTTPS" || ret.Comment != "" {
		t.Fatalf("add_rule result = %+v", ret)
	}
	wantCalls := []winFwStateCall{
		{name: "firewall.rule_exists", args: &execfirewall.RuleExistsArgs{Name: "HTTPS"}},
		{name: "firewall.add_rule", args: &execfirewall.AddRuleArgs{
			Name: "HTTPS", LocalPort: "443",
			Protocol: winFwPtr("tcp"), Action: winFwPtr("allow"),
			Dir: winFwPtr("in"), RemoteIP: winFwPtr("any"),
		}},
	}
	if !reflect.DeepEqual(*calls, wantCalls) {
		t.Fatalf("calls = %#v", *calls)
	}
	// Explicit overrides travel through unchanged.
	rt2, calls2 := newWinFwStateRT(t, winFwStateConfig{ruleExists: false})
	ret = addRuleFunc{}.Apply(context.Background(), rt2, &addRuleArgs{
		Name: "SMB (445)", LocalPort: "445", Protocol: "tcp", Action: "block", Dir: "out", RemoteIP: "localsubnet",
	})
	if !ret.Succeeded() {
		t.Fatalf("explicit add_rule = %+v", ret)
	}
	wantExplicit := &execfirewall.AddRuleArgs{
		Name: "SMB (445)", LocalPort: "445",
		Protocol: winFwPtr("tcp"), Action: winFwPtr("block"),
		Dir: winFwPtr("out"), RemoteIP: winFwPtr("localsubnet"),
	}
	if !reflect.DeepEqual((*calls2)[1].args, wantExplicit) {
		t.Fatalf("explicit args = %#v", (*calls2)[1].args)
	}
	// Present rule: only rule_exists runs and Salt's comment returns.
	rt3, calls3 := newWinFwStateRT(t, winFwStateConfig{ruleExists: true})
	ret = addRuleFunc{}.Apply(context.Background(), rt3, &addRuleArgs{Name: "HTTPS", LocalPort: "443"})
	if !ret.Succeeded() || ret.Comment != "A rule with that name already exists" || len(ret.Changes) != 0 {
		t.Fatalf("present rule = %+v", ret)
	}
	if names := winFwStateNames(calls3); !reflect.DeepEqual(names, []string{"firewall.rule_exists"}) {
		t.Fatalf("present calls = %v", names)
	}
	// Test mode: pending result, no add_rule call, change set kept.
	rt4, calls4 := newWinFwStateRT(t, winFwStateConfig{ruleExists: false})
	ret = addRuleFunc{}.Apply(context.Background(), rt4, &addRuleArgs{Name: "HTTPS", LocalPort: "443", Test: true})
	if ret.Result != nil || ret.Changes["new rule"] != "HTTPS" {
		t.Fatalf("test add_rule = %+v", ret)
	}
	if names := winFwStateNames(calls4); !reflect.DeepEqual(names, []string{"firewall.rule_exists"}) {
		t.Fatalf("test calls = %v", names)
	}
	// A failing add_rule keeps Salt's "Could not add rule" comment.
	rt5, _ := newWinFwStateRT(t, winFwStateConfig{ruleExists: false, addRuleErr: errors.New("netsh denied")})
	ret = addRuleFunc{}.Apply(context.Background(), rt5, &addRuleArgs{Name: "HTTPS", LocalPort: "443"})
	if ret.Succeeded() || ret.Comment != "Could not add rule" {
		t.Fatalf("failed add_rule = %+v", ret)
	}
}

func TestWinFwStateRuleExistsFailureSurfaces(t *testing.T) {
	// A rule_exists execution error must fail the state (Salt would
	// raise through the module call).
	calls := &[]winFwStateCall{}
	exec := runtime.NewExecRegistry()
	if err := exec.Register(winFwStateRec{
		name: "firewall.rule_exists", calls: calls,
		behavior: func(any) (any, error) { return false, errors.New("netsh unavailable") },
	}); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{Exec: exec}
	ret := addRuleFunc{}.Apply(context.Background(), rt, &addRuleArgs{Name: "HTTPS", LocalPort: "443"})
	if ret.Succeeded() || ret.Comment != "netsh unavailable" {
		t.Fatalf("rule_exists failure = %+v", ret)
	}
}

func TestWinFwStateProfileFlowsCompileExactModuleCalls(t *testing.T) {
	cfg := winFwStateConfig{config: map[string]bool{"Domain": true, "Private": false, "Public": true}}
	// disabled(domainprofile): Domain is on → one change + exact
	// firewall.disable call with the state-level profile name.
	rt, calls := newWinFwStateRT(t, cfg)
	ret := disabledFunc{}.Apply(context.Background(), rt, &profileArgs{Name: "domainprofile"})
	if !ret.Succeeded() || ret.Changes["Domain"] != "disabled" || len(ret.Changes) != 1 {
		t.Fatalf("disabled result = %+v", ret)
	}
	wantCalls := []winFwStateCall{
		{name: "firewall.get_config", args: &execfirewall.ConfigArgs{}},
		{name: "firewall.disable", args: &execfirewall.ProfileArgs{Profile: "domainprofile"}},
	}
	if !reflect.DeepEqual(*calls, wantCalls) {
		t.Fatalf("disabled calls = %#v", *calls)
	}
	// enabled(allprofiles): only Private is off → single aggregated
	// change and one enable call for allprofiles.
	rt2, calls2 := newWinFwStateRT(t, cfg)
	ret = enabledFunc{}.Apply(context.Background(), rt2, &profileArgs{})
	if !ret.Succeeded() || ret.Changes["Private"] != "enabled" || len(ret.Changes) != 1 {
		t.Fatalf("enabled result = %+v", ret)
	}
	wantEnabled := []winFwStateCall{
		{name: "firewall.get_config", args: &execfirewall.ConfigArgs{}},
		{name: "firewall.enable", args: &execfirewall.ProfileArgs{Profile: "allprofiles"}},
	}
	if !reflect.DeepEqual(*calls2, wantEnabled) {
		t.Fatalf("enabled calls = %#v", *calls2)
	}
	// No-change flows keep Salt's per-profile success comments and do
	// not call enable/disable.
	rt3, calls3 := newWinFwStateRT(t, cfg)
	ret = enabledFunc{}.Apply(context.Background(), rt3, &profileArgs{Name: "domainprofile"})
	if !ret.Succeeded() || ret.Comment != "Firewall profile domainprofile is enabled" || len(ret.Changes) != 0 {
		t.Fatalf("no-change enabled = %+v", ret)
	}
	if names := winFwStateNames(calls3); !reflect.DeepEqual(names, []string{"firewall.get_config"}) {
		t.Fatalf("no-change calls = %v", names)
	}
	// Test mode: pending with the would-be changes, no toggle call.
	rt4, calls4 := newWinFwStateRT(t, cfg)
	ret = disabledFunc{}.Apply(context.Background(), rt4, &profileArgs{Name: "publicprofile", Test: true})
	if ret.Result != nil || ret.Changes["Public"] != "disabled" {
		t.Fatalf("test disabled = %+v", ret)
	}
	if names := winFwStateNames(calls4); !reflect.DeepEqual(names, []string{"firewall.get_config"}) {
		t.Fatalf("test calls = %v", names)
	}
	// SaltInvocationError("Invalid profile name") maps to a failure
	// result without any module call.
	rt5, calls5 := newWinFwStateRT(t, cfg)
	ret = enabledFunc{}.Apply(context.Background(), rt5, &profileArgs{Name: "bad"})
	if ret.Succeeded() || ret.Comment != "Invalid profile name: bad" || ret.Changes == nil {
		t.Fatalf("invalid profile = %+v", ret)
	}
	if len(*calls5) != 0 {
		t.Fatalf("invalid profile calls = %v", winFwStateNames(calls5))
	}
	// A profile absent from get_config fails with Salt's message.
	partial := winFwStateConfig{config: map[string]bool{"Domain": true}}
	rt6, _ := newWinFwStateRT(t, partial)
	ret = disabledFunc{}.Apply(context.Background(), rt6, &profileArgs{Name: "privateprofile", Test: true})
	if ret.Succeeded() || ret.Comment != "Profile privateprofile does not exist in firewall.get_config" {
		t.Fatalf("missing profile = %+v", ret)
	}
	// get_config failure and invalid return shape fail the state.
	rt7, _ := newWinFwStateRT(t, winFwStateConfig{configErr: errors.New("netsh refused")})
	ret = disabledFunc{}.Apply(context.Background(), rt7, &profileArgs{Name: "domainprofile"})
	if ret.Succeeded() || ret.Comment != "netsh refused" {
		t.Fatalf("config failure = %+v", ret)
	}
	rt8, _ := newWinFwStateRT(t, winFwStateConfig{})
	ret = disabledFunc{}.Apply(context.Background(), rt8, &profileArgs{Name: "domainprofile"})
	if ret.Succeeded() || ret.Comment != "firewall.get_config returned an invalid result" {
		t.Fatalf("config shape = %+v", ret)
	}
	// A failing enable/disable surfaces the module error.
	rt9, _ := newWinFwStateRT(t, winFwStateConfig{config: map[string]bool{"Domain": false}, toggleErr: errors.New("netsh denied")})
	ret = enabledFunc{}.Apply(context.Background(), rt9, &profileArgs{Name: "domainprofile"})
	if ret.Succeeded() || ret.Comment != "netsh denied" {
		t.Fatalf("toggle failure = %+v", ret)
	}
}

func TestWinFwStateRegistryMatrix(t *testing.T) {
	reg := runtime.NewStateRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	names := reg.Names()
	sort.Strings(names)
	want := []string{"win_firewall.add_rule", "win_firewall.disabled", "win_firewall.enabled"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("registry = %v", names)
	}
}
