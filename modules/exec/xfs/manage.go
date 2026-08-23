// XFS dump inventory, prune, device listing, estimation, creation,
// modification and defragmentation functions.
package xfs

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

func exeLookPath(name string) (string, error) { return exec.LookPath(name) }

type InventoryArgs struct{}

type inventoryFunc struct {
	linuxOnly
}

func (inventoryFunc) Name() string { return "xfs.inventory" }
func (inventoryFunc) Args() any    { return InventoryArgs{} }
func (inventoryFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	stdout, stderr, code, err := runAll(ctx, rt, "xfsrestore", "-I")
	if err != nil {
		return nil, err
	}
	if err := verifyRun(stdout, stderr, code); err != nil {
		return nil, err
	}
	return xfsInventoryOutput(stdout), nil
}

var leadingTabs = regexp.MustCompile(`[^\t]`)

// xfsInventoryOutput transforms xfsrestore -I output into nested maps.
// Salt serializes the lines back into Python source and evals it; this
// parser walks the same colon/header structure with tab indentation and
// produces the equivalent nested map, with the trailing restore status
// line stored under "restore_status".
func xfsInventoryOutput(out string) map[string]any {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}

	ret := map[string]any{}
	if len(lines) == 1 && strings.Contains(strings.ToLower(lines[0]), "restore status") {
		ret["restore_status"] = lines[0]
		return ret
	}
	if len(lines) == 0 {
		return ret
	}

	type frame struct {
		indent int
		m      map[string]any
	}
	stack := []frame{{indent: -1, m: ret}}
	current := ret

	for _, line := range lines[:len(lines)-1] {
		stripped := strings.TrimSpace(line)
		parts := strings.Split(stripped, ":")
		nonEmpty := 0
		for _, p := range parts {
			if strings.TrimSpace(p) != "" {
				nonEmpty++
			}
		}
		indent := len(leadingTabs.ReplaceAllString(line, ""))

		if nonEmpty == 1 {
			key := strings.TrimSuffix(parts[0], ":")
			child := map[string]any{}
			for len(stack) > 0 && stack[len(stack)-1].indent >= indent && stack[len(stack)-1].indent >= 0 {
				stack = stack[:len(stack)-1]
			}
			parent := stack[len(stack)-1]
			if len(stack) == 1 {
				current = parent.m
			} else {
				current = parent.m
			}
			current[key] = child
			current = child
			stack = append(stack, frame{indent: indent, m: child})
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(strings.Join(parts[1:], ":"))
		current[key] = value
	}

	ret["restore_status"] = lines[len(lines)-1]
	return ret
}

type PruneDumpArgs struct {
	SessionID string `statekit:"required,name=sessionid"`
}

type pruneDumpFunc struct {
	linuxOnly
}

func (pruneDumpFunc) Name() string { return "xfs.prune_dump" }
func (pruneDumpFunc) Args() any    { return PruneDumpArgs{} }
func (pruneDumpFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PruneDumpArgs)
	stdout, stderr, code, err := runAll(ctx, rt, "xfsinvutil", "-s", a.SessionID, "-F")
	if err != nil {
		return nil, err
	}
	if err := verifyRun(stdout, stderr, code); err != nil {
		return nil, err
	}

	data := xfsPruneOutput(stdout, a.SessionID)
	if data != nil {
		return data, nil
	}
	return nil, fmt.Errorf("Session UUID %q was not found.", a.SessionID)
}

// xfsPruneOutput parses prune output between the dashed separator lines.
func xfsPruneOutput(out, uuid string) map[string]any {
	data := map[string]any{}
	var cnt []string
	cutpoint := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-") {
			if cutpoint {
				break
			}
			cutpoint = true
			continue
		}
		if cutpoint {
			cnt = append(cnt, line)
		}
	}
	for _, kset := range cnt {
		if !strings.Contains(kset, ":") {
			continue
		}
		key, val := strings.TrimSpace(kset), ""
		key, val, _ = strings.Cut(kset, ":")
		key = strings.ToLower(strings.ReplaceAll(key, " ", "_"))
		data[key] = strings.TrimSpace(val)
	}
	if got, _ := data["uuid"].(string); got != uuid {
		return nil
	}
	return data
}

// blkidOutput parses `blkid -o export` blocks; only xfs-typed devices are
// reported, keyed by DEVNAME, always carrying a label key (nil when absent).
func blkidOutput(rt *runtime.Runtime, out string) map[string]any {
	data := map[string]any{}
	for _, block := range strings.Split(out, "\n\n") {
		dev := map[string]any{}
		var devname, typ string
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			key, val, found := strings.Cut(line, "=")
			if !found {
				continue
			}
			key = strings.ToLower(key)
			switch key {
			case "devname":
				devname = val
			case "type":
				typ = val
				delete(dev, "type")
			default:
				dev[key] = val
			}
		}
		if typ != "xfs" || devname == "" {
			continue
		}
		if _, has := dev["label"]; !has {
			dev["label"] = nil
		}
		data[devname] = dev
	}

	for device, mount := range getMounts(rt) {
		if entry, ok := data[device].(map[string]any); ok {
			entry["mount_point"] = mount["mount_point"]
			entry["options"] = mount["options"]
		}
	}
	return data
}

type DevicesArgs struct{}

type devicesFunc struct {
	linuxOnly
}

func (devicesFunc) Name() string { return "xfs.devices" }
func (devicesFunc) Args() any    { return DevicesArgs{} }
func (devicesFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	stdout, stderr, code, err := runAll(ctx, rt, "blkid", "-o", "export")
	if err != nil {
		return nil, err
	}
	if err := verifyRun(stdout, stderr, code); err != nil {
		return nil, err
	}
	return blkidOutput(rt, stdout), nil
}

type EstimateArgs struct {
	Path string `statekit:"required,name=path"`
}

type estimateFunc struct {
	linuxOnly
}

func (estimateFunc) Name() string { return "xfs.estimate" }
func (estimateFunc) Args() any    { return EstimateArgs{} }
func (estimateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*EstimateArgs)
	if _, err := rt.FS.Stat(a.Path); err != nil {
		return nil, fmt.Errorf("Path %q was not found.", a.Path)
	}
	stdout, stderr, code, err := runAll(ctx, rt, "xfs_estimate", "-v", a.Path)
	if err != nil {
		return nil, err
	}
	if err := verifyRun(stdout, stderr, code); err != nil {
		return nil, err
	}
	return xfsEstimateOutput(stdout), nil
}

// xfsEstimateOutput parses xfs_estimate rows, skipping the header.
func xfsEstimateOutput(out string) map[string]any {
	spc := regexp.MustCompile(`\s+`)
	data := map[string]any{}
	rows := strings.Split(out, "\n")
	for i, line := range rows {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(spc.ReplaceAllString(line, " "), " ")
		if len(fields) < 5 {
			continue
		}
		data[fields[0]] = map[string]any{
			"block _size": fields[1],
			"blocks":      fields[2],
			"megabytes":   fields[3],
			"logsize":     fields[4],
		}
	}
	return data
}

type MkfsArgs struct {
	Device  string `statekit:"required,name=device"`
	Label   string `statekit:"name=label"`
	Ssize   string `statekit:"name=ssize"`
	NoForce bool   `statekit:"name=noforce"`
	Bso     string `statekit:"name=bso"`
	Gmo     string `statekit:"name=gmo"`
	Ino     string `statekit:"name=ino"`
	Lso     string `statekit:"name=lso"`
	Rso     string `statekit:"name=rso"`
	Nmo     string `statekit:"name=nmo"`
	Dso     string `statekit:"name=dso"`
}

type mkfsFunc struct {
	linuxOnly
}

func (mkfsFunc) Name() string { return "xfs.mkfs" }
func (mkfsFunc) Args() any    { return MkfsArgs{} }

// checkOpts mirrors Salt's getopts gate: an option string must carry "=".
func checkOpts(opts, switchName string) error {
	if opts != "" && !strings.Contains(opts, "=") {
		return fmt.Errorf("Wrong parameters %q for option %q", opts, switchName)
	}
	return nil
}

func (mkfsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*MkfsArgs)

	argv := []string{"mkfs.xfs"}
	if a.Label != "" {
		argv = append(argv, "-L", a.Label)
	}
	if a.Ssize != "" {
		argv = append(argv, "-s", a.Ssize)
	}
	for _, pair := range [][2]string{
		{"-b", a.Bso}, {"-m", a.Gmo}, {"-n", a.Nmo}, {"-i", a.Ino},
		{"-d", a.Dso}, {"-l", a.Lso}, {"-r", a.Rso},
	} {
		if err := checkOpts(pair[1], pair[0]); err != nil {
			return nil, err
		}
		if pair[1] != "" {
			argv = append(argv, pair[0], pair[1])
		}
	}
	if !a.NoForce {
		argv = append(argv, "-f")
	}
	argv = append(argv, a.Device)

	stdout, stderr, code, err := runAll(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	if err := verifyRun(stdout, stderr, code); err != nil {
		return nil, err
	}
	return parseXfsInfo(stdout), nil
}

type ModifyArgs struct {
	Device       string `statekit:"required,name=device"`
	Label        string `statekit:"name=label"`
	LazyCounting *bool  `statekit:"name=lazy_counting"`
	UUID         *bool  `statekit:"name=uuid"`
}

type modifyFunc struct {
	linuxOnly
}

func (modifyFunc) Name() string { return "xfs.modify" }
func (modifyFunc) Args() any    { return ModifyArgs{} }
func (modifyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ModifyArgs)

	if a.Label == "" && a.LazyCounting == nil && a.UUID == nil {
		return nil, fmt.Errorf("Nothing specified for modification for %q device", a.Device)
	}

	argv := []string{"xfs_admin"}
	if a.Label != "" {
		argv = append(argv, "-L", a.Label)
	}
	if a.LazyCounting != nil {
		if !*a.LazyCounting {
			argv = append(argv, "-c", "0")
		} else {
			argv = append(argv, "-c", "1")
		}
	}
	if a.UUID != nil {
		if !*a.UUID {
			argv = append(argv, "-U", "nil")
		} else {
			argv = append(argv, "-U", "generate")
		}
	}
	argv = append(argv, a.Device)

	stdout, stderr, code, err := runAll(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	if err := verifyRun(stdout, stderr, code); err != nil {
		return nil, err
	}

	out2, stderr2, code2, err := runAll(ctx, rt, "blkid", "-o", "export", a.Device)
	if err != nil {
		return nil, err
	}
	if err := verifyRun(out2, stderr2, code2); err != nil {
		return nil, err
	}
	return blkidOutput(rt, out2), nil
}

// getMounts lists mounted xfs filesystems from /proc/mounts through the
// runtime FileSystem so tests can inject the kernel view.
func getMounts(rt *runtime.Runtime) map[string]map[string]any {
	mounts := map[string]map[string]any{}
	data, err := rt.FS.ReadFile("/proc/mounts")
	if err != nil {
		return mounts
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 6 || fields[2] != "xfs" {
			continue
		}
		mounts[fields[0]] = map[string]any{
			"mount_point": fields[1],
			"options":     strings.Split(fields[3], ","),
		}
	}
	return mounts
}

type DefragmentArgs struct {
	Device string `statekit:"required,name=device"`
}

type defragmentFunc struct {
	linuxOnly
}

func (defragmentFunc) Name() string { return "xfs.defragment" }
func (defragmentFunc) Args() any    { return DefragmentArgs{} }
func (defragmentFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DefragmentArgs)
	if a.Device == "/" {
		return nil, fmt.Errorf("Root is not a device.")
	}
	if _, mounted := getMounts(rt)[a.Device]; !mounted {
		return nil, fmt.Errorf("Device %q is not mounted", a.Device)
	}
	stdout, stderr, code, err := runAll(ctx, rt, "xfs_fsr", a.Device)
	if err != nil {
		return nil, err
	}
	if err := verifyRun(stdout, stderr, code); err != nil {
		return nil, err
	}
	return map[string]any{"log": stdout}, nil
}

// Register installs all xfs-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		infoFunc{},
		dumpFunc{},
		inventoryFunc{},
		pruneDumpFunc{},
		devicesFunc{},
		estimateFunc{},
		mkfsFunc{},
		modifyFunc{},
		defragmentFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
