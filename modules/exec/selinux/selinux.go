// Package selinux implements Salt-compatible SELinux inspection and control.
//
// Reference: saltstack/salt/modules/selinux.py @ pinned revision. Ported
// surface: selinux_fs_path, getenforce, getconfig, setenforce (R5.2) plus
// the R5.3 policy subset — filetype translation, semanage-driven booleans,
// file-context and port policies, restorecon preview/apply, and semodule
// management. Shell pipelines of the source (semanage ... | grep -E) are
// re-implemented as in-process line filtering over the central Runner's
// bounded output.
package selinux

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts every function of this module to linux.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

const configPath = "/etc/selinux/config"

type FsPathArgs struct{}

type fsPathFunc struct {
	linuxOnly
}

func (fsPathFunc) Name() string { return "selinux.selinux_fs_path" }
func (fsPathFunc) Args() any    { return FsPathArgs{} }
func (fsPathFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return "/sys/fs/selinux", nil
}

type GetenforceArgs struct{}

type getenforceFunc struct {
	linuxOnly
}

func (getenforceFunc) Name() string { return "selinux.getenforce" }
func (getenforceFunc) Args() any    { return GetenforceArgs{} }
func (getenforceFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	res := rt.Runner.Run(ctx, runtime.Command("getenforce"))
	if res.Err != nil {
		// Salt returns Disabled when SELinux is not present.
		return "Disabled", nil
	}
	mode := strings.TrimSpace(string(res.Stdout))
	if mode == "" {
		return "Disabled", nil
	}
	return mode, nil
}

type GetConfigArgs struct{}

type getConfigFunc struct {
	linuxOnly
}

func (getConfigFunc) Name() string { return "selinux.getconfig" }
func (getConfigFunc) Args() any    { return GetConfigArgs{} }
func (getConfigFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	data, err := rt.FS.ReadFile(configPath)
	if err != nil {
		return "", nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if key, value, ok := strings.Cut(line, "="); ok &&
			strings.TrimSpace(key) == "SELINUX" {
			return strings.TrimSpace(value), nil
		}
	}
	return "", nil
}

type SetenforceArgs struct {
	Mode string `statekit:"required"`
}

type setenforceFunc struct {
	linuxOnly
}

func (setenforceFunc) Name() string { return "selinux.setenforce" }
func (setenforceFunc) Args() any    { return SetenforceArgs{} }
func (setenforceFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetenforceArgs)
	mode, err := NormalizeMode(a.Mode)
	if err != nil {
		return nil, err
	}
	if mode == "Disabled" {
		// Runtime switching into disabled is impossible; only the boot
		// configuration can disable SELinux.
		return nil, fmt.Errorf("setenforce cannot switch to Disabled at runtime")
	}
	res := rt.Runner.Run(ctx, runtime.Command("setenforce", map[bool]string{true: "1", false: "0"}[mode == "Enforcing"]))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("setenforce exited with code %d: %s", res.ExitCode, res.Stderr)
	}
	return mode, nil
}

// Register installs all selinux-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	fns := []runtime.ExecFunction{
		fsPathFunc{}, getenforceFunc{}, getConfigFunc{}, setenforceFunc{},
		filetypeIdToStringFunc{},
		listSeboolFunc{}, getseboolFunc{}, setseboolFunc{}, setseboolsFunc{},
		listSemodFunc{}, getsemodFunc{}, setsemodFunc{}, installSemodFunc{}, removeSemodFunc{},
		fcontextGetPolicyFunc{}, fcontextAddPolicyFunc{}, fcontextDeletePolicyFunc{},
		fcontextPolicyIsAppliedFunc{}, fcontextApplyPolicyFunc{},
		portGetPolicyFunc{}, portAddPolicyFunc{}, portModifyPolicyFunc{}, portDeletePolicyFunc{},
	}
	for _, fn := range fns {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
