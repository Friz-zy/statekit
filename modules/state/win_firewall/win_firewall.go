// Package win_firewall implements Salt's Windows firewall state functions
// through the typed firewall execution bridge.
package win_firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execfirewall "github.com/friz-zy/statekit/modules/exec/firewall"
)

var profileMap = map[string]string{
	"domainprofile":  "Domain",
	"privateprofile": "Private",
	"publicprofile":  "Public",
	"allprofiles":    "All",
}

type profileArgs struct {
	Name string `statekit:"name=name"`
	Test bool   `statekit:"name=test"`
}

type addRuleArgs struct {
	Name      string `statekit:"required,name=name"`
	LocalPort string `statekit:"required,name=localport"`
	Protocol  string `statekit:"name=protocol"`
	Action    string `statekit:"name=action"`
	Dir       string `statekit:"name=dir"`
	RemoteIP  string `statekit:"name=remoteip"`
	Test      bool   `statekit:"name=test"`
}

type disabledFunc struct{}
type enabledFunc struct{}
type addRuleFunc struct{}

func (disabledFunc) Name() string { return "win_firewall.disabled" }
func (disabledFunc) Args() any    { return profileArgs{} }
func (disabledFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	return applyProfile(ctx, rt, args.(*profileArgs), false)
}

func (enabledFunc) Name() string { return "win_firewall.enabled" }
func (enabledFunc) Args() any    { return profileArgs{} }
func (enabledFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	return applyProfile(ctx, rt, args.(*profileArgs), true)
}

func (addRuleFunc) Name() string { return "win_firewall.add_rule" }
func (addRuleFunc) Args() any    { return addRuleArgs{} }
func (addRuleFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*addRuleArgs)
	ret := result.New(a.Name, "", result.Bool(true), nil)
	protocol, action, direction, remote := a.Protocol, a.Action, a.Dir, a.RemoteIP
	if protocol == "" {
		protocol = "tcp"
	}
	if action == "" {
		action = "allow"
	}
	if direction == "" {
		direction = "in"
	}
	if remote == "" {
		remote = "any"
	}
	existsValue, err := rt.Exec.Call(ctx, rt, "firewall.rule_exists", &execfirewall.RuleExistsArgs{Name: a.Name})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	exists, _ := existsValue.(bool)
	if exists {
		ret.Comment = "A rule with that name already exists"
		return ret
	}
	ret.Changes = map[string]any{"new rule": a.Name}
	if a.Test {
		return result.TestPending(a.Name, fmt.Sprint(ret.Changes), ret.Changes)
	}
	if _, err := rt.Exec.Call(ctx, rt, "firewall.add_rule", &execfirewall.AddRuleArgs{Name: a.Name, LocalPort: a.LocalPort, Protocol: &protocol, Action: &action, Dir: &direction, RemoteIP: &remote}); err != nil {
		return result.Failure(a.Name, "Could not add rule")
	}
	return ret
}

func applyProfile(ctx context.Context, rt *runtime.Runtime, args *profileArgs, enable bool) result.StateResult {
	name := strings.ToLower(args.Name)
	if name == "" {
		name = "allprofiles"
	}
	profile, ok := profileMap[name]
	if !ok {
		return result.Failure(args.Name, "Invalid profile name: "+args.Name)
	}
	configValue, err := rt.Exec.Call(ctx, rt, "firewall.get_config", &execfirewall.ConfigArgs{})
	if err != nil {
		return result.Failure(args.Name, err.Error())
	}
	config, _ := configValue.(map[string]bool)
	if config == nil {
		return result.Failure(args.Name, "firewall.get_config returned an invalid result")
	}
	if name != "allprofiles" {
		if _, exists := config[profile]; !exists {
			return result.Failure(args.Name, fmt.Sprintf("Profile %s does not exist in firewall.get_config", name))
		}
	}
	changes := map[string]any{}
	for currentProfile, currentEnabled := range config {
		if (enable && !currentEnabled) || (!enable && currentEnabled) {
			if name == "allprofiles" || currentProfile == profile {
				if enable {
					changes[currentProfile] = "enabled"
				} else {
					changes[currentProfile] = "disabled"
				}
			}
		}
	}
	if len(changes) == 0 {
		state := "enabled"
		if !enable {
			state = "disabled"
		}
		return result.Success(args.Name, fmt.Sprintf("Firewall profile %s is %s", name, state))
	}
	if args.Test {
		return result.TestPending(args.Name, fmt.Sprint(changes), changes)
	}
	var callErr error
	if enable {
		_, callErr = rt.Exec.Call(ctx, rt, "firewall.enable", &execfirewall.ProfileArgs{Profile: name})
	} else {
		_, callErr = rt.Exec.Call(ctx, rt, "firewall.disable", &execfirewall.ProfileArgs{Profile: name})
	}
	if callErr != nil {
		return result.Failure(args.Name, callErr.Error())
	}
	return result.New(args.Name, "", result.Bool(true), changes)
}

// Register installs the Windows firewall state wrapper. The execution bridge
// returns UnsupportedError on non-Windows, preserving platform behavior.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{disabledFunc{}, addRuleFunc{}, enabledFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
