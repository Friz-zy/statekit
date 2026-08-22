// Package host implements the Salt-compatible host.present/host.absent
// states for /etc/hosts management.
//
// Reference: saltstack/salt/states/host.py @ pinned revision.
package host

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	exechosts "github.com/friz-zy/statekit/modules/exec/hosts"
)

type presentArgs struct {
	Name  string   `statekit:"name=name"`
	IP    string   `statekit:"required,name=ip"`
	Names []string `statekit:"required,name=names"`
	Test  bool     `statekit:"name=test"`
}

type presentFunc struct{}

func (presentFunc) Name() string { return "host.present" }
func (presentFunc) Args() any    { return presentArgs{} }
func (presentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*presentArgs)

	value, err := rt.Exec.Call(ctx, rt, "hosts.list_hosts", &exechosts.ListArgs{})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	byIP, _ := value.(map[string]any)
	current := toStrings(byIP[a.IP])

	var missing []string
	for _, name := range a.Names {
		found := false
		for _, existing := range current {
			if existing == name {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return result.Success(a.Name,
			fmt.Sprintf("Host %s already present for %s", strings.Join(a.Names, ", "), a.IP))
	}

	changes := map[string]any{
		a.IP: map[string]any{"old": current, "new": append(current, missing...)},
	}
	if a.Test {
		return result.TestPending(a.Name,
			fmt.Sprintf("Host entries for %s would be added to %s", strings.Join(missing, ", "), a.IP), changes)
	}
	if _, err := rt.Exec.Call(ctx, rt, "hosts.add_host", &exechosts.AddArgs{IP: a.IP, Aliases: missing}); err != nil {
		return result.Failure(a.Name, err.Error())
	}
	return result.New(a.Name, "", result.Bool(true), changes)
}

type absentArgs struct {
	Name  string   `statekit:"required"`
	IP    string   `statekit:"name=ip"`
	Names []string `statekit:"name=names"`
	Test  bool     `statekit:"name=test"`
}

type absentFunc struct{}

func (absentFunc) Name() string { return "host.absent" }
func (absentFunc) Args() any    { return absentArgs{} }
func (absentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*absentArgs)
	names := a.Names
	if len(names) == 0 {
		names = []string{a.Name}
	}
	ip := a.IP
	if ip == "" {
		value, err := rt.Exec.Call(ctx, rt, "hosts.get_ip", &exechosts.GetIPArgs{Name: names[0]})
		if err != nil {
			return result.Failure(a.Name, err.Error())
		}
		ip, _ = value.(string)
		if ip == "" {
			return result.Success(a.Name, fmt.Sprintf("Host %s already absent", names[0]))
		}
	}
	changes := map[string]any{"removed": strings.Join(names, ", ")}
	if a.Test {
		return result.TestPending(a.Name, fmt.Sprintf("Host %s would be removed from %s", names[0], ip), changes)
	}
	for _, name := range names {
		rt.Exec.Call(ctx, rt, "hosts.rm_host", &exechosts.RmArgs{IP: ip, Name: name})
	}
	return result.New(a.Name, "", result.Bool(true), changes)
}

func toStrings(v any) []string {
	list, _ := v.([]string)
	return list
}

// Register installs all host-module state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{presentFunc{}, absentFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
