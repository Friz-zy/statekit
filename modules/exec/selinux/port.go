package selinux

// Port-policy port: saltstack/salt/modules/selinux.py @ pinned revision.
// name may carry the whole "(tcp|udp)/(port|range)" spec; otherwise the
// protocol/port arguments are validated through the same expression. The
// listing filter re-implements upstream's `semanage port --list | grep -E`
// in-process, and mutations return the cmd.run_all dict.

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// protocolPortRe mirrors r"^(tcp|udp)\/(([\d]+)\-?[\d]+)$": a protocol, a
// slash, and a port or range whose digits total at least two (a single-digit
// port never matches — upstream quirk preserved).
var protocolPortRe = regexp.MustCompile(`^(tcp|udp)/(([0-9]+)-?[0-9]+)$`)

// portParseRe mirrors r"^(\w+)[ ]+(\w+)[ ]+([\d\-, ]+)" over grep's output.
var portParseRe = regexp.MustCompile(`^(\w+)[ ]+(\w+)[ ]+([\d\-, ]+)`)

// parseProtocolPort mirrors _parse_protocol_port. A valid name wins and the
// separate arguments are ignored; otherwise the f"{protocol}/{port}"
// fallback is validated too (a missing half renders as "None" exactly like
// Python's f-string, so it never parses).
func parseProtocolPort(name string, protocol, port *string) (string, string, error) {
	protoStr, portStr := "None", "None"
	if protocol != nil {
		protoStr = *protocol
	}
	if port != nil {
		portStr = *port
	}
	if m := protocolPortRe.FindStringSubmatch(name); m != nil {
		return m[1], m[2], nil
	}
	if m := protocolPortRe.FindStringSubmatch(protoStr + "/" + portStr); m != nil {
		return m[1], m[2], nil
	}
	return "", "", fmt.Errorf(
		"Invalid name %q format and protocol and port not provided or invalid: %q %q.",
		name, protoStr, portStr)
}

type PortGetPolicyArgs struct {
	Name     string  `statekit:"required"`
	SelType  *string `statekit:"name=sel_type"`
	Protocol *string `statekit:"name=protocol"`
	Port     *string `statekit:"name=port"`
}

type portGetPolicyFunc struct {
	linuxOnly
}

func (portGetPolicyFunc) Name() string { return "selinux.port_get_policy" }
func (portGetPolicyFunc) Args() any    { return PortGetPolicyArgs{} }
func (portGetPolicyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PortGetPolicyArgs)
	if err := whichGuard("semanage"); err != nil {
		return nil, err
	}
	if err := validateArgRunes("name", a.Name); err != nil {
		return nil, err
	}
	protocol, port, err := parseProtocolPort(a.Name, a.Protocol, a.Port)
	if err != nil {
		return nil, err
	}
	// `sel_type if sel_type else r"\w+"`: empty falls back, a value
	// interpolates as a raw regex like upstream.
	selTypeRe := `\w+`
	if a.SelType != nil && *a.SelType != "" {
		selTypeRe = *a.SelType
	}
	res := rt.Runner.Run(ctx, runtime.Command("semanage", "port", "--list"))
	if res.Err != nil {
		return nil, res.Err
	}
	pattern := "^" + selTypeRe + `[ ]+` + protocol + `[ ]+((.*)*)[ ]` + port + `($|,)`
	portPolicy, gerr := grepOutput(string(res.Stdout), pattern)
	if gerr != nil {
		return nil, gerr
	}
	if portPolicy == "" {
		return nil, nil // Python None: no exact match
	}
	parts := portParseRe.FindStringSubmatch(portPolicy)
	if parts == nil {
		return nil, fmt.Errorf("Port policy %s did not match expected format", portPolicy)
	}
	return map[string]any{
		"sel_type": parts[1],
		"protocol": parts[2],
		"port":     strings.TrimSpace(parts[3]),
	}, nil
}

type PortAddPolicyArgs struct {
	Name     string  `statekit:"required"`
	SelType  *string `statekit:"name=sel_type"`
	Protocol *string `statekit:"name=protocol"`
	Port     *string `statekit:"name=port"`
	SelRange *string `statekit:"name=sel_range"`
}

type portAddPolicyFunc struct {
	linuxOnly
}

func (portAddPolicyFunc) Name() string { return "selinux.port_add_policy" }
func (portAddPolicyFunc) Args() any    { return PortAddPolicyArgs{} }
func (portAddPolicyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PortAddPolicyArgs)
	return portPolicyAction(ctx, rt, "add", a.Name, a.SelType, a.Protocol, a.Port, a.SelRange)
}

type PortModifyPolicyArgs struct {
	Name     string  `statekit:"required"`
	SelType  *string `statekit:"name=sel_type"`
	Protocol *string `statekit:"name=protocol"`
	Port     *string `statekit:"name=port"`
	SelRange *string `statekit:"name=sel_range"`
}

type portModifyPolicyFunc struct {
	linuxOnly
}

func (portModifyPolicyFunc) Name() string { return "selinux.port_modify_policy" }
func (portModifyPolicyFunc) Args() any    { return PortModifyPolicyArgs{} }
func (portModifyPolicyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PortModifyPolicyArgs)
	return portPolicyAction(ctx, rt, "modify", a.Name, a.SelType, a.Protocol, a.Port, a.SelRange)
}

type PortDeletePolicyArgs struct {
	Name     string  `statekit:"required"`
	Protocol *string `statekit:"name=protocol"`
	Port     *string `statekit:"name=port"`
}

type portDeletePolicyFunc struct {
	linuxOnly
}

func (portDeletePolicyFunc) Name() string { return "selinux.port_delete_policy" }
func (portDeletePolicyFunc) Args() any    { return PortDeletePolicyArgs{} }
func (portDeletePolicyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PortDeletePolicyArgs)
	// Upstream passes sel_type=None and sel_range=None for deletes.
	return portPolicyAction(ctx, rt, "delete", a.Name, nil, a.Protocol, a.Port, nil)
}

// portPolicyAction mirrors _port_add_or_delete_policy: add requires a
// SELinux type, flags mirror `--{action} --proto P [--type T] [--range R]
// PORT`, and the result is the cmd.run_all dict.
func portPolicyAction(ctx context.Context, rt *runtime.Runtime, action, name string,
	selType, protocol, port, selRange *string) (map[string]any, error) {
	if err := whichGuard("semanage"); err != nil {
		return nil, err
	}
	if err := validateArgRunes("name", name); err != nil {
		return nil, err
	}
	if action == "add" && (selType == nil || *selType == "") {
		return nil, fmt.Errorf("SELinux Type is required to add a policy")
	}
	proto, portSpec, err := parseProtocolPort(name, protocol, port)
	if err != nil {
		return nil, err
	}
	argv := []string{"semanage", "port", "--" + action, "--proto", proto}
	if selType != nil && *selType != "" {
		if err := validateArgRunes("sel_type", *selType); err != nil {
			return nil, err
		}
		argv = append(argv, "--type", *selType)
	}
	if selRange != nil && *selRange != "" {
		if err := validateArgRunes("sel_range", *selRange); err != nil {
			return nil, err
		}
		argv = append(argv, "--range", *selRange)
	}
	argv = append(argv, portSpec)
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	ret := runAllResult(res)
	if res.Err != nil {
		return ret, res.Err
	}
	return ret, nil
}
