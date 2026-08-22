// Package mount implements Salt-compatible mount inspection and management.
//
// Reference: saltstack/salt/modules/mount.py @ pinned revision. /proc/mounts
// and /etc/fstab are parsed through the runtime FileSystem; kernel mounts and
// unmounts delegate to the central Runner.
package mount

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	procMounts = "/proc/mounts"
	fstabPath  = "/etc/fstab"
)

type activeEntry struct {
	Dev     string   `json:"dev" yaml:"dev"`
	Device  string   `json:"device" yaml:"device"`
	FsType  string   `json:"fstype" yaml:"fstype"`
	Opts    []string `json:"opts" yaml:"opts"`
	Mounted bool     `json:"mounted" yaml:"mounted"`
}

type activeArgs struct{}

type activeFunc struct{}

func (activeFunc) Name() string { return "mount.active" }
func (activeFunc) Args() any    { return activeArgs{} }
func (activeFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	data, err := rt.FS.ReadFile(procMounts)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		entry := map[string]any{
			"device":  fields[0],
			"fstype":  fields[2],
			"opts":    strings.Split(fields[3], ","),
			"mounted": true,
		}
		out[fields[1]] = entry
	}
	return out, nil
}

type isMountedArgs struct {
	Path string `statekit:"required,name=path"`
}

type isMountedFunc struct{}

func (isMountedFunc) Name() string { return "mount.is_mounted" }
func (isMountedFunc) Args() any    { return isMountedArgs{} }
func (isMountedFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*isMountedArgs)
	data, err := rt.FS.ReadFile(procMounts)
	if err != nil {
		return nil, err
	}
	want := strings.TrimSuffix(a.Path, "/")
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == want {
			return true, nil
		}
	}
	return false, nil
}

type fstabEntry struct {
	Device   string   `json:"device" yaml:"device"`
	MountPt  string   `json:"mount_point" yaml:"mount_point"`
	FsType   string   `json:"fstype" yaml:"fstype"`
	Opts     []string `json:"opts" yaml:"opts"`
	DumpFreq int      `json:"dump_freq" yaml:"dump_freq"`
	PassNo   int      `json:"pass_no" yaml:"pass_no"`
}

type fstabArgs struct{}

type fstabFunc struct{}

func (fstabFunc) Name() string { return "mount.fstab" }
func (fstabFunc) Args() any    { return fstabArgs{} }
func (fstabFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	data, err := rt.FS.ReadFile(fstabPath)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, line := range parseFstabLines(string(data)) {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		dump, pass := 0, 0
		if len(fields) >= 5 {
			fmt.Sscanf(fields[4], "%d", &dump)
		}
		if len(fields) >= 6 {
			fmt.Sscanf(fields[5], "%d", &pass)
		}
		opts := []string{}
		if fields[3] != "defaults" {
			opts = strings.Split(fields[3], ",")
		} else {
			opts = []string{"defaults"}
		}
		out[fields[1]] = map[string]any{
			"device":    fields[0],
			"fstype":    fields[2],
			"opts":      opts,
			"dump_freq": dump,
			"pass_no":   pass,
		}
	}
	return out, nil
}

func parseFstabLines(content string) []string {
	var lines []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

type mountArgs struct {
	Name   string `statekit:"required,name=name"`
	Device string `statekit:"required,name=device"`
	FsType string `statekit:"name=fstype"`
	Opts   string `statekit:"name=opts"`
}

type mountFunc struct{}

func (mountFunc) Name() string { return "mount.mount" }
func (mountFunc) Args() any    { return mountArgs{} }
func (mountFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*mountArgs)
	argv := []string{"mount"}
	if a.FsType != "" {
		argv = append(argv, "-t", a.FsType)
	}
	if a.Opts != "" {
		argv = append(argv, "-o", a.Opts)
	}
	argv = append(argv, a.Device, a.Name)
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("mount exited with code %d: %s", res.ExitCode, res.Stderr)
	}
	return true, nil
}

type umountArgs struct {
	Name string `statekit:"required,name=name"`
}

type umountFunc struct{}

func (umountFunc) Name() string { return "mount.umount" }
func (umountFunc) Args() any    { return umountArgs{} }
func (umountFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*umountArgs)
	res := rt.Runner.Run(ctx, runtime.Command("umount", a.Name))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("umount exited with code %d: %s", res.ExitCode, res.Stderr)
	}
	return true, nil
}

var _ = activeEntry{}
var _ = fstabEntry{}

// Register installs all mount-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{activeFunc{}, isMountedFunc{}, fstabFunc{}, mountFunc{}, umountFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
