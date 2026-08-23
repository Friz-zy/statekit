// Package lvm implements Salt-compatible Linux LVM2 management through the
// lvm2 userland binaries (pvdisplay, vgdisplay, lvdisplay, pvcreate, ...).
//
// Reference: saltstack/salt/modules/linux_lvm.py @ pinned revision
// (virtual name "lvm"). All external work runs through the central Runner;
// device existence and symlink dereferencing go through the FileSystem so
// suites stay hermetic.
//
// Contract notes (init.md section 28 classifications):
//   - Salt signals failures by returning message strings from several
//     functions (e.g. pvcreate). StateKit maps those to Go errors, which the
//     CLI reports as failed operations with the same text; success still
//     returns true. Documented divergence: transport only.
//   - vgremove/lvremove keep returning the message string as data, matching
//     Salt's observable output even on command failure (stderr text).
//   - lvresize/lvextend argument errors return an empty map like Salt.
package lvm

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts every function of this module to linux: the linux_lvm
// Salt module is a Linux LVM2 contract and its tools ship with lvm2 there.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// runAll executes one argv through the central Runner and returns captured
// output. Start failures become errors; exit codes stay data like Salt's
// cmd.run_all.
func runAll(ctx context.Context, rt *runtime.Runtime, argv ...string) (stdout, stderr string, code int, err error) {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return "", "", -1, res.Err
	}
	return string(res.Stdout), strings.TrimSpace(string(res.Stderr)), res.ExitCode, nil
}

type VersionArgs struct{}

type versionFunc struct {
	linuxOnly
}

func (versionFunc) Name() string { return "lvm.version" }
func (versionFunc) Args() any    { return VersionArgs{} }
func (versionFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	stdout, _, _, err := runAll(ctx, rt, "lvm", "version")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("unexpected lvm version output")
	}
	comps := strings.SplitN(lines[0], ": ", 2)
	if len(comps) < 2 {
		return nil, fmt.Errorf("unexpected lvm version output")
	}
	return strings.TrimSpace(comps[1]), nil
}

type FullVersionArgs struct{}

type fullversionFunc struct {
	linuxOnly
}

func (fullversionFunc) Name() string { return "lvm.fullversion" }
func (fullversionFunc) Args() any    { return FullVersionArgs{} }
func (fullversionFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	stdout, _, _, err := runAll(ctx, rt, "lvm", "version")
	if err != nil {
		return nil, err
	}
	ret := map[string]any{}
	for _, line := range strings.Split(stdout, "\n") {
		comps := strings.SplitN(line, ":", 2)
		if len(comps) < 2 {
			continue
		}
		ret[strings.TrimSpace(comps[0])] = strings.TrimSpace(comps[1])
	}
	return ret, nil
}

type PvDisplayArgs struct {
	PVName string `statekit:"name=pvname"`
	Real   bool   `statekit:"name=real"`
	Quiet  bool   `statekit:"name=quiet"`
}

type pvDisplayFunc struct {
	linuxOnly
}

func (pvDisplayFunc) Name() string { return "lvm.pvdisplay" }
func (pvDisplayFunc) Args() any    { return PvDisplayArgs{} }
func (pvDisplayFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PvDisplayArgs)
	return pvdisplay(ctx, rt, a.PVName, a.Real)
}

// pvdisplay mirrors Salt's colon-separated `pvdisplay -c` parsing. Non-zero
// exits yield an empty result; lines announcing fresh physical volumes are
// skipped. real=True dereferences symlinks for the result key.
func pvdisplay(ctx context.Context, rt *runtime.Runtime, pvname string, real bool) (map[string]any, error) {
	argv := []string{"pvdisplay", "-c"}
	if pvname != "" {
		argv = append(argv, pvname)
	}
	stdout, _, code, err := runAll(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return map[string]any{}, nil
	}
	ret := map[string]any{}
	for _, line := range strings.Split(stdout, "\n") {
		if line == "" || strings.Contains(line, "is a new physical volume") {
			continue
		}
		comps := strings.Split(strings.TrimSpace(line), ":")
		if len(comps) < 11 {
			continue
		}
		device := comps[0]
		key := device
		if real {
			key = resolvePath(rt, device)
		}
		entry := map[string]any{
			"Physical Volume Device":            comps[0],
			"Volume Group Name":                 comps[1],
			"Physical Volume Size (kB)":         comps[2],
			"Internal Physical Volume Number":   comps[3],
			"Physical Volume Status":            comps[4],
			"Physical Volume (not) Allocatable": comps[5],
			"Current Logical Volumes Here":      comps[6],
			"Physical Extent Size (kB)":         comps[7],
			"Total Physical Extents":            comps[8],
			"Free Physical Extents":             comps[9],
			"Allocated Physical Extents":        comps[10],
		}
		if real {
			entry["Real Physical Volume Device"] = key
		}
		ret[key] = entry
	}
	return ret, nil
}

type VgDisplayArgs struct {
	VGName string `statekit:"name=vgname"`
	Quiet  bool   `statekit:"name=quiet"`
}

type vgDisplayFunc struct {
	linuxOnly
}

func (vgDisplayFunc) Name() string { return "lvm.vgdisplay" }
func (vgDisplayFunc) Args() any    { return VgDisplayArgs{} }
func (vgDisplayFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*VgDisplayArgs)
	return vgdisplay(ctx, rt, a.VGName)
}

func vgdisplay(ctx context.Context, rt *runtime.Runtime, vgname string) (map[string]any, error) {
	argv := []string{"vgdisplay", "-c"}
	if vgname != "" {
		argv = append(argv, vgname)
	}
	stdout, _, code, err := runAll(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return map[string]any{}, nil
	}
	ret := map[string]any{}
	for _, line := range strings.Split(stdout, "\n") {
		comps := strings.Split(strings.TrimSpace(line), ":")
		if len(comps) < 17 || comps[0] == "" {
			continue
		}
		ret[comps[0]] = map[string]any{
			"Volume Group Name":            comps[0],
			"Volume Group Access":          comps[1],
			"Volume Group Status":          comps[2],
			"Internal Volume Group Number": comps[3],
			"Maximum Logical Volumes":      comps[4],
			"Current Logical Volumes":      comps[5],
			"Open Logical Volumes":         comps[6],
			"Maximum Logical Volume Size":  comps[7],
			"Maximum Physical Volumes":     comps[8],
			"Current Physical Volumes":     comps[9],
			"Actual Physical Volumes":      comps[10],
			"Volume Group Size (kB)":       comps[11],
			"Physical Extent Size (kB)":    comps[12],
			"Total Physical Extents":       comps[13],
			"Allocated Physical Extents":   comps[14],
			"Free Physical Extents":        comps[15],
			"UUID":                         comps[16],
		}
	}
	return ret, nil
}

type LvDisplayArgs struct {
	LVName string `statekit:"name=lvname"`
	Quiet  bool   `statekit:"name=quiet"`
}

type lvDisplayFunc struct {
	linuxOnly
}

func (lvDisplayFunc) Name() string { return "lvm.lvdisplay" }
func (lvDisplayFunc) Args() any    { return LvDisplayArgs{} }
func (lvDisplayFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*LvDisplayArgs)
	return lvdisplay(ctx, rt, a.LVName)
}

func lvdisplay(ctx context.Context, rt *runtime.Runtime, lvname string) (map[string]any, error) {
	argv := []string{"lvdisplay", "-c"}
	if lvname != "" {
		argv = append(argv, lvname)
	}
	stdout, _, code, err := runAll(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return map[string]any{}, nil
	}
	ret := map[string]any{}
	for _, line := range strings.Split(stdout, "\n") {
		comps := strings.Split(strings.TrimSpace(line), ":")
		if len(comps) < 13 || comps[0] == "" {
			continue
		}
		ret[comps[0]] = map[string]any{
			"Logical Volume Name":                comps[0],
			"Volume Group Name":                  comps[1],
			"Logical Volume Access":              comps[2],
			"Logical Volume Status":              comps[3],
			"Internal Logical Volume Number":     comps[4],
			"Open Logical Volumes":               comps[5],
			"Logical Volume Size":                comps[6],
			"Current Logical Extents Associated": comps[7],
			"Allocated Logical Extents":          comps[8],
			"Allocation Policy":                  comps[9],
			"Read Ahead Sectors":                 comps[10],
			"Major Device Number":                comps[11],
			"Minor Device Number":                comps[12],
		}
	}
	return ret, nil
}

// resolvePath dereferences symlinks through the FileSystem, falling back to
// the cleaned original like os.path.realpath does for missing paths.
func resolvePath(rt *runtime.Runtime, path string) string {
	current := path
	for hop := 0; hop < 8; hop++ {
		link, err := rt.FS.Readlink(current)
		if err != nil || link == "" {
			break
		}
		if !strings.HasPrefix(link, "/") {
			link = filepath.Join(filepath.Dir(current), link)
		}
		current = link
	}
	return current
}

// Register installs all lvm-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		versionFunc{},
		fullversionFunc{},
		pvDisplayFunc{},
		vgDisplayFunc{},
		lvDisplayFunc{},
		pvCreateFunc{},
		pvRemoveFunc{},
		vgCreateFunc{},
		vgExtendFunc{},
		lvCreateFunc{},
		vgRemoveFunc{},
		lvRemoveFunc{},
		lvResizeFunc{},
		lvExtendFunc{},
		pvResizeFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
