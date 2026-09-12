// Package shadow implements Salt-compatible local shadow database inspection.
//
// Reference: saltstack/salt/modules/linux_shadow.py @ pinned revision.
// /etc/shadow is readable by root only; unprivileged calls fail normally
// (plan section 39).
package shadow

import (
	"context"
	"fmt"

	"github.com/friz-zy/statekit/internal/runtime"
	"github.com/friz-zy/statekit/internal/sysfiles"
)

// linuxOnly restricts every function of this module to linux.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

const shadowPath = "/etc/shadow"

type infoArgs struct {
	Name string `statekit:"required"`
}

type infoFunc struct {
	linuxOnly
}

func (infoFunc) Name() string { return "shadow.info" }
func (infoFunc) Args() any    { return infoArgs{} }
func (infoFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*infoArgs)
	data, err := rt.FS.ReadFile(shadowPath)
	if err != nil {
		return nil, fmt.Errorf("could not read %s (root privileges required): %w", shadowPath, err)
	}
	for _, entry := range sysfiles.ParseShadow(string(data)) {
		if entry.Name == a.Name {
			return map[string]any{
				"name":   entry.Name,
				"passwd": entry.Passwd,
				"lstchg": entry.Lstchg,
				"min":    entry.Min,
				"max":    entry.Max,
				"warn":   entry.Warn,
				"inact":  entry.Inact,
				"expire": entry.Expire,
			}, nil
		}
	}
	return nil, fmt.Errorf("user %q does not exist in the shadow database", a.Name)
}

// Register installs all shadow-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	// Official Go distributions list solaris/amd64 and illumos/amd64 compile
	// targets. This host has no native Solaris runtime runner; the branch keeps
	// dispatch exhaustive and registerSolaris is covered by the untagged mock
	// tests on the Linux host.
	if runtime.CurrentGOOS() == "solaris" {
		return registerSolaris(reg)
	}
	return reg.Register(infoFunc{})
}
