// Package quota implements Salt-compatible filesystem quota management
// through repquota, setquota, and the quota on/off tooling.
//
// Reference: saltstack/salt/modules/quota.py @ pinned revision.
//
// Contract notes (init.md section 28): Salt's quota.set_ checks membership
// of the user/group name against the wrong nesting level of the parsed
// report, so previously stored limits are effectively never picked up and
// unspecified limits fall back to 0. That observable behavior is mirrored
// here; a classified fix would be an intentional divergence.
package quota

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts every function of this module to linux: the quota
// toolchain is a POSIX/Linux contract in StateKit's ported scope.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

func stdoutOf(ctx context.Context, rt *runtime.Runtime, argv ...string) string {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return ""
	}
	return string(res.Stdout)
}

type ReportArgs struct {
	Mount string `statekit:"required,name=mount"`
}

type reportFunc struct {
	linuxOnly
}

func (reportFunc) Name() string { return "quota.report" }
func (reportFunc) Args() any    { return ReportArgs{} }
func (reportFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ReportArgs)
	ret := map[string]any{}
	mount := map[string]any{}
	mount["User Quotas"] = parseQuota(ctx, rt, a.Mount, "-u")
	mount["Group Quotas"] = parseQuota(ctx, rt, a.Mount, "-g")
	ret[a.Mount] = mount
	return ret, nil
}

// parseQuota mirrors Salt's _parse_quota output shape, including the
// single-element grace-time lists.
func parseQuota(ctx context.Context, rt *runtime.Runtime, mount, opts string) map[string]any {
	out := stdoutOf(ctx, rt, "repquota", "-vp", opts, mount)
	mode := "header"
	quotatype := "Users"
	if strings.Contains(opts, "-g") && !strings.Contains(opts, "-u") {
		quotatype = "Groups"
	}
	users := map[string]any{}
	ret := map[string]any{quotatype: users}

	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		comps := strings.Fields(line)
		if mode == "header" {
			switch {
			case strings.Contains(line, "Block grace time"):
				parts := strings.Split(line, ";")
				blockgc := strings.Split(parts[0], ": ")
				inodegc := strings.Split(parts[1], ": ")
				ret["Block Grace Time"] = []string{blockgc[len(blockgc)-1]}
				ret["Inode Grace Time"] = []string{inodegc[len(inodegc)-1]}
			case strings.HasPrefix(line, "-"):
				mode = "quotas"
			}
			continue
		}
		// quotas mode
		if len(comps) < 8 {
			continue
		}
		row, ok := users[comps[0]].(map[string]any)
		if !ok {
			row = map[string]any{}
			users[comps[0]] = row
		}
		get := func(i int) string {
			if i >= len(comps) {
				return ""
			}
			return comps[i]
		}
		row["block-used"] = get(2)
		row["block-soft-limit"] = get(3)
		row["block-hard-limit"] = get(4)
		row["block-grace"] = get(5)
		row["file-used"] = get(6)
		row["file-soft-limit"] = get(7)
		row["file-hard-limit"] = get(8)
		row["file-grace"] = get(9)
	}
	return ret
}

type SetArgs struct {
	Device         string `statekit:"required,name=device"`
	User           string `statekit:"name=user"`
	Group          string `statekit:"name=group"`
	BlockSoftLimit string `statekit:"name=block-soft-limit"`
	BlockHardLimit string `statekit:"name=block-hard-limit"`
	FileSoftLimit  string `statekit:"name=file-soft-limit"`
	FileHardLimit  string `statekit:"name=file-hard-limit"`
}

type setFunc struct {
	linuxOnly
}

func (setFunc) Name() string { return "quota.set" }
func (setFunc) Args() any    { return SetArgs{} }
func (setFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetArgs)

	current := func() map[string]any {
		return map[string]any{
			"block-soft-limit": 0,
			"block-hard-limit": 0,
			"file-soft-limit":  0,
			"file-hard-limit":  0,
		}
	}()

	var cmd []string
	var label string
	switch {
	case a.User != "" && a.Group != "":
		return nil, fmt.Errorf("Please specify a user or group, not both.")
	case a.User != "":
		cmd = []string{"setquota", "-u", a.User}
		label = fmt.Sprintf("User: %s", a.User)
	case a.Group != "":
		cmd = []string{"setquota", "-g", a.Group}
		label = fmt.Sprintf("Group: %s", a.Group)
	default:
		return nil, fmt.Errorf("A valid user or group was not found")
	}

	apply := func(key, value string) {
		if value != "" {
			current[key] = value
		}
	}
	apply("block-soft-limit", a.BlockSoftLimit)
	apply("block-hard-limit", a.BlockHardLimit)
	apply("file-soft-limit", a.FileSoftLimit)
	apply("file-hard-limit", a.FileHardLimit)

	cmd = append(cmd,
		fmt.Sprint(current["block-soft-limit"]),
		fmt.Sprint(current["block-hard-limit"]),
		fmt.Sprint(current["file-soft-limit"]),
		fmt.Sprint(current["file-hard-limit"]),
		a.Device,
	)

	res := rt.Runner.Run(ctx, runtime.Command(cmd...))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("Unable to set desired quota. Error follows: \n%s",
			strings.TrimSpace(string(res.Stderr)))
	}
	return map[string]any{label: current}, nil
}

type WarnArgs struct{}

type warnFunc struct {
	linuxOnly
}

func (warnFunc) Name() string { return "quota.warn" }
func (warnFunc) Args() any    { return WarnArgs{} }
func (warnFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	// Salt runs `quotawarn` here despite the docstring mentioning warnquota;
	// the code is the contract.
	res := rt.Runner.Run(ctx, runtime.Command("quotawarn"))
	return nil, res.Err
}

type StatsArgs struct{}

type statsFunc struct {
	linuxOnly
}

func (statsFunc) Name() string { return "quota.stats" }
func (statsFunc) Args() any    { return StatsArgs{} }
func (statsFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	ret := map[string]any{}
	for _, line := range strings.Split(stdoutOf(ctx, rt, "quotastats"), "\n") {
		if line == "" {
			continue
		}
		comps := strings.Split(line, ": ")
		if len(comps) < 2 {
			continue
		}
		ret[comps[0]] = comps[1]
	}
	return ret, nil
}

type OnArgs struct {
	Device string `statekit:"required,name=device"`
}

type onFunc struct {
	linuxOnly
}

func (onFunc) Name() string { return "quota.on" }
func (onFunc) Args() any    { return OnArgs{} }
func (onFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*OnArgs)
	res := rt.Runner.Run(ctx, runtime.Command("quotaon", a.Device))
	return true, res.Err
}

type OffArgs struct {
	Device string `statekit:"required,name=device"`
}

type offFunc struct {
	linuxOnly
}

func (offFunc) Name() string { return "quota.off" }
func (offFunc) Args() any    { return OffArgs{} }
func (offFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*OffArgs)
	res := rt.Runner.Run(ctx, runtime.Command("quotaoff", a.Device))
	return true, res.Err
}

type GetModeArgs struct {
	Device string `statekit:"required,name=device"`
}

type getModeFunc struct {
	linuxOnly
}

func (getModeFunc) Name() string { return "quota.get_mode" }
func (getModeFunc) Args() any    { return GetModeArgs{} }
func (getModeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetModeArgs)
	ret := map[string]any{}
	for _, line := range strings.Split(stdoutOf(ctx, rt, "quotaon", "-p", a.Device), "\n") {
		comps := strings.Fields(strings.TrimSpace(line))
		if len(comps) < 7 {
			continue
		}
		if _, seen := ret[comps[3]]; !seen {
			if strings.HasPrefix(comps[0], "quotaon") {
				switch {
				case strings.HasPrefix(comps[1], "Mountpoint"):
					ret[comps[4]] = "disabled"
					continue
				case strings.HasPrefix(comps[1], "Cannot"):
					return map[string]any{a.Device: "Not found"}, nil
				default:
					continue
				}
			}
			device := strings.TrimSuffix(strings.TrimPrefix(comps[4], "("), ")")
			ret[comps[3]] = map[string]any{"device": device}
		}
		bucket := ret[comps[3]].(map[string]any)
		bucket[comps[0]] = comps[6]
	}
	return ret, nil
}

// Register installs all quota-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		reportFunc{},
		setFunc{},
		warnFunc{},
		statsFunc{},
		onFunc{},
		offFunc{},
		getModeFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
