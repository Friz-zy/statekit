//go:build !windows

package firewall

import "context"
import "github.com/friz-zy/statekit/internal/runtime"

// Register is empty outside Windows.
func Register(_ *runtime.ExecRegistry) error { return nil }

func GetConfig(context.Context, *runtime.Runtime) (map[string]bool, error) {
	return nil, &runtime.UnsupportedError{Kind: "function", Name: "firewall.get_config"}
}
func Disable(context.Context, *runtime.Runtime, string) (any, error) {
	return nil, &runtime.UnsupportedError{Kind: "function", Name: "firewall.disable"}
}
func Enable(context.Context, *runtime.Runtime, string) (any, error) {
	return nil, &runtime.UnsupportedError{Kind: "function", Name: "firewall.enable"}
}
func RuleExists(context.Context, *runtime.Runtime, string) (bool, error) {
	return false, &runtime.UnsupportedError{Kind: "function", Name: "firewall.rule_exists"}
}
func AddRule(context.Context, *runtime.Runtime, string, string, string, string, string, string) (any, error) {
	return nil, &runtime.UnsupportedError{Kind: "function", Name: "firewall.add_rule"}
}
