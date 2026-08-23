// Package udev implements Salt-compatible udev query functions.
//
// Reference: saltstack/salt/modules/udev.py @ pinned revision.
//
// Scope note (handoff decision, plans/porting.md section 6): this phase
// ships the minimal surface bcache needs — udev.env — driven by the
// shared udevadm --export parser. info/name/path/links/exportdb reuse the
// same parser and can land later without new infrastructure; they stay
// unregistered until their round. All commands run through the central
// Runner as argv (Salt composes a shell string with no metacharacters).
package udev

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts this module to linux: udevadm is a Linux contract.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// parseInfo ports _parse_udevadm_info plus _normalize_info: blank-line
// separated device records, "X: data" lines, E-lines parsed as key=value
// with int/float coercion, and every single-element list collapsed to its
// element.
func parseInfo(udevInfo string) []map[string]any {
	var devices []map[string]any
	dev := map[string]any{}

	flush := func() {
		if len(dev) == 0 {
			return
		}
		for sect, val := range dev {
			if list, ok := val.([]any); ok && len(list) == 1 {
				dev[sect] = list[0]
			}
		}
		devices = append(devices, dev)
		dev = map[string]any{}
	}

	for _, raw := range strings.Split(udevInfo, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			flush()
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		query, data := parts[0], strings.TrimSpace(parts[1])
		if query == "E" {
			env, _ := dev["E"].(map[string]any)
			if env == nil {
				env = map[string]any{}
				dev["E"] = env
			}
			kv := strings.SplitN(data, "=", 2)
			if len(kv) != 2 {
				continue
			}
			env[kv[0]] = coerceNumber(kv[1])
			continue
		}
		list, _ := dev[query].([]any)
		dev[query] = append(list, data)
	}
	flush()
	return devices
}

// coerceNumber mirrors the int-then-float attempt chain of the Salt parser.
func coerceNumber(val string) any {
	if parsed, err := strconv.ParseInt(val, 10, 64); err == nil {
		return parsed
	}
	if parsed, err := strconv.ParseFloat(val, 64); err == nil {
		return parsed
	}
	return val
}

// EnvArgs mirrors Salt's env signature.
type EnvArgs struct {
	Dev string `statekit:"required"`
}

type envFunc struct {
	linuxOnly
}

func (envFunc) Name() string { return "udev.env" }
func (envFunc) Args() any    { return EnvArgs{} }

// Execute returns all environment variables udev has for dev, or nil when
// the record carries no E section (Salt's .get("E", None)).
func (envFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*EnvArgs)
	qtype := "name"
	if strings.Contains(a.Dev, "sys") {
		// Salt probes `"sys" in dev` to pick the udevadm query type.
		qtype = "path"
	}
	res := rt.Runner.Run(ctx, runtime.Command(
		"udevadm", "info", "--export", "--query=all", "--"+qtype+"="+a.Dev))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("%s", string(res.Stderr))
	}
	devices := parseInfo(string(res.Stdout))
	if len(devices) == 0 {
		return nil, fmt.Errorf("no device found for %s", a.Dev)
	}
	return devices[0]["E"], nil
}

// Register installs the udev-module execution functions shipped this round.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		envFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
