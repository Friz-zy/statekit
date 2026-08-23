// Package iwtools implements Salt-compatible wireless tools queries
// through iwconfig and iwlist.
//
// Reference: saltstack/salt/modules/iwtools.py @ pinned revision.
//
// Contract note (init.md section 28): set_mode toggles the interface
// through Salt's ip.down/ip.up functions; those resolve through the
// registry and surface UnsupportedError until the ip family lands.
// The scan auto-up path uses a raw ip link command like upstream.
package iwtools

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// IfaceArgs is the canonical cross-family request for the planned
// ip.down/ip.up delegates.
type IfaceArgs struct {
	Iface string `statekit:"required,name=iface"`
}

// linuxOnly restricts this module to linux.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// runQuiet mirrors cmd.run for the raw tool invocations: stdout text,
// spawn failures raise.
func runQuiet(ctx context.Context, rt *runtime.Runtime, cmd string) (string, error) {
	res := rt.Runner.Run(ctx, process.Command{Name: cmd, Shell: true})
	if res.Err != nil {
		return "", res.Err
	}
	return string(res.Stdout), nil
}

var iwconfigBin = func() bool {
	_, err := exec.LookPath("iwconfig")
	return err == nil
}

// listInterfaces ports list_interfaces: parses the multi-space column
// layout of `iwconfig`, grouping continuation lines per interface.
func listInterfaces(rt *runtime.Runtime) (map[string]any, error) {
	out, err := runQuiet(context.Background(), rt, "iwconfig")
	if err != nil {
		return nil, err
	}
	ret := map[string]any{}
	var tmp map[string]any
	ifaceSet := false
	var iface string
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, "no wireless extensions") {
			continue
		}
		comps := strings.Split(strings.TrimSpace(line), "  ")
		if !strings.HasPrefix(line, " ") {
			if ifaceSet {
				ret[iface] = copyMap(tmp)
			}
			iface = comps[0]
			comps = comps[1:]
			tmp = map[string]any{"extra": []any{}}
			ifaceSet = true
		}
		for _, item := range comps {
			switch {
			case strings.Contains(item, ":"):
				parts := strings.SplitN(item, ":", 2)
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				if key == "ESSID" {
					value = strings.TrimSuffix(strings.TrimPrefix(value, "\""), "\"")
				}
				tmp[key] = value
			case strings.Contains(item, "="):
				parts := strings.SplitN(item, "=", 2)
				tmp[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			default:
				extra, _ := tmp["extra"].([]any)
				tmp["extra"] = append(extra, item)
			}
		}
	}
	if ifaceSet && tmp != nil {
		ret[iface] = copyMap(tmp)
	}
	return ret, nil
}

func copyMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src)+1)
	for k, v := range src {
		out[k] = v
	}
	return out
}

type ListInterfacesArgs struct {
	Style *string `statekit:"name=style"`
}

type listInterfacesFunc struct{ linuxOnly }

func (listInterfacesFunc) Name() string { return "iwtools.list_interfaces" }
func (listInterfacesFunc) Args() any    { return ListInterfacesArgs{} }
func (listInterfacesFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListInterfacesArgs)
	ret, err := listInterfaces(rt)
	if err != nil {
		return nil, err
	}
	if a.Style != nil && *a.Style == "list" {
		keys := make([]any, 0, len(ret))
		for key := range ret {
			keys = append(keys, key)
		}
		return keys, nil
	}
	return ret, nil
}

// validIface ports _valid_iface against the parsed interface table.
func validIface(rt *runtime.Runtime, iface string) bool {
	ret, err := listInterfaces(rt)
	if err != nil {
		return false
	}
	_, ok := ret[iface]
	return ok
}

type ScanArgs struct {
	Iface string  `statekit:"required,name=iface"`
	Style *string `statekit:"name=style"`
}

type scanFunc struct{ linuxOnly }

func (scanFunc) Name() string { return "iwtools.scan" }
func (scanFunc) Args() any    { return ScanArgs{} }

// Execute lists networks on a wireless interface, bringing it up first
// when scanning reports the network down.
func (scanFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ScanArgs)
	if !validIface(rt, a.Iface) {
		return nil, fmt.Errorf("The interface specified is not valid")
	}

	out, err := runQuiet(ctx, rt, fmt.Sprintf("iwlist %s scan", a.Iface))
	if err != nil {
		return nil, err
	}
	if strings.Contains(out, "Network is down") {
		if _, err := runQuiet(ctx, rt, fmt.Sprintf("ip link set %s up", a.Iface)); err != nil {
			return nil, err
		}
		out, err = runQuiet(ctx, rt, fmt.Sprintf("iwlist %s scan", a.Iface))
		if err != nil {
			return nil, err
		}
	}

	ret := map[string]any{}
	var tmp map[string]any
	flush := func() {
		if tmp != nil {
			if addr, ok := tmp["Address"].(string); ok {
				ret[addr] = tmp
			}
			tmp = nil
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.Contains(line, "Scan completed") {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "Cell") {
			comps := strings.Split(line, " - ")
			if len(comps) > 1 {
				line = comps[1]
			} else {
				continue
			}
			flush()
			tmp = map[string]any{}
		} else if tmp == nil {
			tmp = map[string]any{}
		}
		comps := strings.SplitN(line, ":", 2)
		if len(comps) != 2 {
			continue
		}
		key := strings.TrimSpace(comps[0])
		value := strings.TrimSpace(comps[1])
		if key == "Address" {
			value = strings.TrimSuffix(strings.TrimPrefix(value, "\""), "\"")
			tmp[key] = value
			continue
		}
		if key == "IE" {
			ie, _ := tmp["IE"].([]any)
			tmp["IE"] = append(ie, value)
			continue
		}
		tmp[key] = value
	}
	flush()

	if a.Style != nil && *a.Style == "list" {
		keys := make([]any, 0, len(ret))
		for key := range ret {
			keys = append(keys, key)
		}
		return keys, nil
	}
	return ret, nil
}

type SetModeArgs struct {
	Iface string `statekit:"required,name=iface"`
	Mode  string `statekit:"required,name=mode"`
}

type setModeFunc struct{ linuxOnly }

func (setModeFunc) Name() string { return "iwtools.set_mode" }
func (setModeFunc) Args() any    { return SetModeArgs{} }

// Execute changes the wireless mode; the ip.down/ip.up delegates resolve
// through the registry like Salt's __salt__ lookups.
func (setModeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetModeArgs)
	if !validIface(rt, a.Iface) {
		return nil, fmt.Errorf("The interface specified is not valid")
	}
	validModes := []string{"Managed", "Ad-Hoc", "Master", "Repeater", "Secondary", "Monitor", "Auto"}
	found := false
	for _, mode := range validModes {
		if mode == a.Mode {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("One of the following modes must be specified: %s",
			strings.Join(validModes, ", "))
	}

	if _, ok := rt.Exec.Get("ip.down"); !ok {
		return nil, &runtime.UnsupportedError{Kind: "function", Name: "ip.down"}
	}
	if _, err := rt.Exec.Call(ctx, rt, "ip.down", &IfaceArgs{Iface: a.Iface}); err != nil {
		return nil, err
	}
	_, err := runQuiet(ctx, rt, fmt.Sprintf("iwconfig %s mode %s", a.Iface, a.Mode))
	if err != nil {
		return nil, err
	}
	if _, ok := rt.Exec.Get("ip.up"); !ok {
		return nil, &runtime.UnsupportedError{Kind: "function", Name: "ip.up"}
	}
	if _, err := rt.Exec.Call(ctx, rt, "ip.up", &IfaceArgs{Iface: a.Iface}); err != nil {
		return nil, err
	}
	return a.Mode, nil
}

// Register installs all iwtools-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		scanFunc{},
		setModeFunc{},
		listInterfacesFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
