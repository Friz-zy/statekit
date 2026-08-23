// Package lvm implements Salt-compatible LVM desired-state management.
//
// Reference: saltstack/salt/states/lvm.py @ pinned revision. States drive
// the lvm execution functions through the runtime Exec registry, exactly
// like Salt's __salt__["lvm.*"] indirection.
package lvm

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execlvm "github.com/friz-zy/statekit/modules/exec/lvm"
)

// linuxOnly restricts every state of this module to linux, matching the
// lvm execution family contract.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// convertToMB mirrors Salt's _convert_to_mb: suffixes s/m/g/t/p with an
// optional trailing b, plain numbers treated as megabytes. Errors carry
// Salt's exact message text.
func convertToMB(size string) (float64, error) {
	strSize := strings.ToLower(size)
	unit := strSize[max(len(strSize)-1, 0):]
	switch {
	case unit >= "0" && unit <= "9":
		unit = "m"
	case unit == "b":
		if len(strSize) < 2 {
			return 0, fmt.Errorf("Size %s is invalid.", size)
		}
		unit = strSize[len(strSize)-2 : len(strSize)-1]
		strSize = strSize[:len(strSize)-2]
	default:
		strSize = strSize[:max(len(strSize)-1, 0)]
	}
	if strSize == "" {
		return 0, fmt.Errorf("Size %s is invalid.", size)
	}
	last := strSize[len(strSize)-1:]
	if last < "0" || last > "9" {
		return 0, fmt.Errorf("Size %s is invalid.", size)
	}
	sizeNum, err := strconv.ParseFloat(strSize, 64)
	if err != nil {
		return 0, fmt.Errorf("Size %s is invalid.", size)
	}
	switch unit {
	case "s":
		return sizeNum / 2048, nil
	case "m":
		return sizeNum, nil
	case "g":
		return sizeNum * 1024, nil
	case "t":
		return sizeNum * 1024 * 1024, nil
	case "p":
		return sizeNum * 1024 * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("Unit %s is invalid.", unit)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// resolvePathFS dereferences symlinks through the FileSystem like
// os.path.realpath, falling back to the cleaned original for missing paths.
func resolvePathFS(rt *runtime.Runtime, path string) string {
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

type pvPresentArgs struct {
	Name   string            `statekit:"required"`
	Test   bool              `statekit:"name=test"`
	Force  *bool             `statekit:"name=force"`
	Option map[string]string `statekit:"name=options"`
}

type pvPresentFunc struct {
	linuxOnly
}

func (pvPresentFunc) Name() string { return "lvm.pv_present" }
func (pvPresentFunc) Args() any    { return pvPresentArgs{} }
func (pvPresentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*pvPresentArgs)

	pvs, err := rt.Exec.Call(ctx, rt, "lvm.pvdisplay", &execlvm.PvDisplayArgs{PVName: a.Name, Quiet: true})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	if len(pvs.(map[string]any)) > 0 {
		return result.Success(a.Name, fmt.Sprintf("Physical Volume %s already present", a.Name))
	}
	if a.Test {
		return result.TestPending(a.Name,
			fmt.Sprintf("Physical Volume %s is set to be created", a.Name), nil)
	}

	create := &execlvm.PvCreateArgs{Devices: []string{a.Name}, Force: a.Force}
	for key, value := range a.Option {
		switch key {
		case "metadatasize":
			create.Metadatasize = value
		case "dataalignment":
			create.Dataalignment = value
		case "dataalignmentoffset":
			create.Dataalignmentoffset = value
		case "pvmetadatacopies":
			create.Pvmetadatacopies = value
		case "metadatacopies":
			create.Metadatacopies = value
		case "metadataignore":
			create.Metadataignore = value
		case "restorefile":
			create.Restorefile = value
		case "labelsector":
			create.Labelsector = value
		case "setphysicalvolumesize":
			create.Setphysicalvolumesize = value
		}
	}
	create.NoRestorefile = a.Option["norestorefile"] == "true"

	changes, err := rt.Exec.Call(ctx, rt, "lvm.pvcreate", create)
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	verify, err := rt.Exec.Call(ctx, rt, "lvm.pvdisplay", &execlvm.PvDisplayArgs{PVName: a.Name})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	if len(verify.(map[string]any)) > 0 {
		return result.New(a.Name,
			fmt.Sprintf("Created Physical Volume %s", a.Name),
			result.Bool(true),
			map[string]any{"created": changes})
	}
	return result.Failure(a.Name, fmt.Sprintf("Failed to create Physical Volume %s", a.Name))
}

type pvAbsentArgs struct {
	Name string `statekit:"required"`
	Test bool   `statekit:"name=test"`
}

type pvAbsentFunc struct {
	linuxOnly
}

func (pvAbsentFunc) Name() string { return "lvm.pv_absent" }
func (pvAbsentFunc) Args() any    { return pvAbsentArgs{} }
func (pvAbsentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*pvAbsentArgs)

	pvs, err := rt.Exec.Call(ctx, rt, "lvm.pvdisplay", &execlvm.PvDisplayArgs{PVName: a.Name, Quiet: true})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	if len(pvs.(map[string]any)) == 0 {
		return result.Success(a.Name, fmt.Sprintf("Physical Volume %s does not exist", a.Name))
	}
	if a.Test {
		return result.TestPending(a.Name,
			fmt.Sprintf("Physical Volume %s is set to be removed", a.Name), nil)
	}
	changes, err := rt.Exec.Call(ctx, rt, "lvm.pvremove", &execlvm.PvRemoveArgs{Devices: []string{a.Name}})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	still, err := rt.Exec.Call(ctx, rt, "lvm.pvdisplay", &execlvm.PvDisplayArgs{PVName: a.Name, Quiet: true})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	if len(still.(map[string]any)) > 0 {
		return result.Failure(a.Name, fmt.Sprintf("Failed to remove Physical Volume %s", a.Name))
	}
	return result.New(a.Name,
		fmt.Sprintf("Removed Physical Volume %s", a.Name),
		result.Bool(true),
		map[string]any{"removed": changes})
}

type vgPresentArgs struct {
	Name    string            `statekit:"required"`
	Devices []string          `statekit:"name=devices"`
	Test    bool              `statekit:"name=test"`
	Force   bool              `statekit:"name=force"`
	Option  map[string]string `statekit:"name=options"`
}

type vgPresentFunc struct {
	linuxOnly
}

func (vgPresentFunc) Name() string { return "lvm.vg_present" }
func (vgPresentFunc) Args() any    { return vgPresentArgs{} }

// vgGroupOf extracts the Volume Group Name field from a pvdisplay entry.
func vgGroupOf(entry any) (string, bool) {
	m, ok := entry.(map[string]any)
	if !ok {
		return "", false
	}
	name, _ := m["Volume Group Name"].(string)
	return name, true
}

func (vgPresentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*vgPresentArgs)
	ret := result.New(a.Name, "", result.Bool(true), map[string]any{})

	vgs, err := rt.Exec.Call(ctx, rt, "lvm.vgdisplay", &execlvm.VgDisplayArgs{VGName: a.Name, Quiet: true})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	comment := ""
	if len(vgs.(map[string]any)) > 0 {
		comment = fmt.Sprintf("Volume Group %s already present", a.Name)
		resultFalse := false
		for _, device := range a.Devices {
			realdev := resolvePathFS(rt, device)
			pvsRaw, err := rt.Exec.Call(ctx, rt, "lvm.pvdisplay",
				&execlvm.PvDisplayArgs{PVName: realdev, Real: true})
			if err != nil {
				return result.Failure(a.Name, err.Error())
			}
			pvs := pvsRaw.(map[string]any)
			entry, ok := pvs[realdev]
			switch {
			case ok && func() bool { _, known := vgGroupOf(entry); return known }():
				vgn, _ := vgGroupOf(entry)
				switch {
				case vgn == a.Name:
					comment = joinComment(comment, fmt.Sprintf("%s is part of Volume Group", device))
				case vgn == "" || vgn == "#orphans_lvm2":
					if _, err := rt.Exec.Call(ctx, rt, "lvm.vgextend",
						&execlvm.VgExtendArgs{VGName: a.Name, Devices: []string{device}}); err != nil {
						return result.Failure(a.Name, err.Error())
					}
					pvs2Raw, err := rt.Exec.Call(ctx, rt, "lvm.pvdisplay",
						&execlvm.PvDisplayArgs{PVName: realdev, Real: true})
					if err != nil {
						return result.Failure(a.Name, err.Error())
					}
					pvs2 := pvs2Raw.(map[string]any)
					if added, found := pvs2[realdev]; found {
						if vgnAfter, _ := vgGroupOf(added); vgnAfter == a.Name {
							ret.Changes[device] = fmt.Sprintf("added to %s", a.Name)
						} else {
							comment = joinComment(comment, fmt.Sprintf("%s could not be added", device))
							resultFalse = true
						}
					} else {
						comment = joinComment(comment, fmt.Sprintf("%s could not be added", device))
						resultFalse = true
					}
				default:
					comment = joinComment(comment,
						fmt.Sprintf("%s is part of %s", device, vgn))
					resultFalse = true
				}
			default:
				comment = joinComment(comment, fmt.Sprintf("pv %s is not present", device))
				resultFalse = true
			}
		}
		res := result.Bool(true)
		if resultFalse {
			res = result.Bool(false)
		}
		return result.New(a.Name, comment, res, ret.Changes)
	}
	if a.Test {
		return result.TestPending(a.Name,
			fmt.Sprintf("Volume Group %s is set to be created", a.Name), nil)
	}

	created, err := rt.Exec.Call(ctx, rt, "lvm.vgcreate", &execlvm.VgCreateArgs{
		VGName: a.Name, Devices: a.Devices, Force: a.Force,
	})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	check, err := rt.Exec.Call(ctx, rt, "lvm.vgdisplay", &execlvm.VgDisplayArgs{VGName: a.Name})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	if len(check.(map[string]any)) > 0 {
		return result.New(a.Name,
			fmt.Sprintf("Created Volume Group %s", a.Name),
			result.Bool(true),
			map[string]any{"created": created})
	}
	return result.Failure(a.Name, fmt.Sprintf("Failed to create Volume Group %s", a.Name))
}

// joinComment appends a line to an accumulating comment like Salt's
// "{}\n{}".format chain.
func joinComment(comment, addition string) string {
	if comment == "" {
		return addition
	}
	return comment + "\n" + addition
}

type vgAbsentArgs struct {
	Name string `statekit:"required"`
	Test bool   `statekit:"name=test"`
}

type vgAbsentFunc struct {
	linuxOnly
}

func (vgAbsentFunc) Name() string { return "lvm.vg_absent" }
func (vgAbsentFunc) Args() any    { return vgAbsentArgs{} }
func (vgAbsentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*vgAbsentArgs)

	vgs, err := rt.Exec.Call(ctx, rt, "lvm.vgdisplay", &execlvm.VgDisplayArgs{VGName: a.Name, Quiet: true})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	if len(vgs.(map[string]any)) == 0 {
		return result.Success(a.Name, fmt.Sprintf("Volume Group %s already absent", a.Name))
	}
	if a.Test {
		return result.TestPending(a.Name,
			fmt.Sprintf("Volume Group %s is set to be removed", a.Name), nil)
	}
	changes, err := rt.Exec.Call(ctx, rt, "lvm.vgremove", &execlvm.VgRemoveArgs{VGName: a.Name})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	still, err := rt.Exec.Call(ctx, rt, "lvm.vgdisplay", &execlvm.VgDisplayArgs{VGName: a.Name, Quiet: true})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	if len(still.(map[string]any)) > 0 {
		return result.Failure(a.Name, fmt.Sprintf("Failed to remove Volume Group %s", a.Name))
	}
	return result.New(a.Name,
		fmt.Sprintf("Removed Volume Group %s", a.Name),
		result.Bool(true),
		map[string]any{"removed": changes})
}

type lvPresentArgs struct {
	Name       string            `statekit:"required"`
	VGName     string            `statekit:"name=vgname"`
	Size       string            `statekit:"name=size"`
	Extents    string            `statekit:"name=extents"`
	Snapshot   string            `statekit:"name=snapshot"`
	PV         string            `statekit:"name=pv"`
	ThinVolume bool              `statekit:"name=thinvolume"`
	ThinPool   bool              `statekit:"name=thinpool"`
	Force      bool              `statekit:"name=force"`
	Resizefs   bool              `statekit:"name=resizefs"`
	Test       bool              `statekit:"name=test"`
	Option     map[string]string `statekit:"name=options"`
}

type lvPresentFunc struct {
	linuxOnly
}

func (lvPresentFunc) Name() string { return "lvm.lv_present" }
func (lvPresentFunc) Args() any    { return lvPresentArgs{} }

// outputOf extracts the Output from lvcreate payload used in failure text.
func outputOf(changes any) string {
	if m, ok := changes.(map[string]any); ok {
		if out, ok := m["Output from lvcreate"].(string); ok {
			return out
		}
	}
	return ""
}

func (lvPresentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*lvPresentArgs)
	name := a.Name

	var sizeMB float64
	if a.Size != "" && a.Extents != "" {
		return result.Failure(name, "Only one of extents or size can be specified.")
	}
	if a.Size != "" {
		parsed, err := convertToMB(a.Size)
		if err != nil {
			return result.Failure(name, err.Error())
		}
		sizeMB = parsed
	}

	snapshot := ""
	if a.Snapshot != "" {
		snapshot = a.Name
		name = a.Snapshot
	}

	vgPrefix := a.VGName
	if a.ThinVolume {
		if idx := strings.Index(a.VGName, "/"); idx >= 0 {
			vgPrefix = a.VGName[:idx]
		}
	}
	lvpath := fmt.Sprintf("/dev/%s/%s", vgPrefix, name)

	lvRaw, err := rt.Exec.Call(ctx, rt, "lvm.lvdisplay", &execlvm.LvDisplayArgs{LVName: lvpath, Quiet: true})
	if err != nil {
		return result.Failure(name, err.Error())
	}
	lvInfo := lvRaw.(map[string]any)
	lv, hadLV := lvInfo[lvpath]

	if !hadLV {
		if a.Test {
			return result.TestPending(name,
				fmt.Sprintf("Logical Volume %s is set to be created", name), nil)
		}
		created, err := rt.Exec.Call(ctx, rt, "lvm.lvcreate", &execlvm.LvCreateArgs{
			LVName: name, VGName: a.VGName, Size: a.Size, Extents: a.Extents,
			Snapshot: snapshot, PV: a.PV, ThinVolume: a.ThinVolume,
			ThinPool: a.ThinPool, Force: a.Force,
			Activate: a.Option["activate"], Chunksize: a.Option["chunksize"],
			Contiguous: a.Option["contiguous"], Discards: a.Option["discards"],
			Stripes: a.Option["stripes"], Stripesize: a.Option["stripesize"],
			Minor: a.Option["minor"], Persistent: a.Option["persistent"],
			Mirrors: a.Option["mirrors"], Monitor: a.Option["monitor"],
			Permission: a.Option["permission"], Poolmetadatasize: a.Option["poolmetadatasize"],
			Readahead: a.Option["readahead"], Regionsize: a.Option["regionsize"],
			Type: a.Option["type"], Virtualsize: a.Option["virtualsize"],
			Zero:             a.Option["zero"],
			NoSync:           a.Option["nosync"] == "true",
			NoUdevsync:       a.Option["noudevsync"] == "true",
			IgnoreMonitoring: a.Option["ignoremonitoring"] == "true",
			Thin:             a.Option["thin"] == "true",
		})
		if err != nil {
			return result.Failure(name,
				fmt.Sprintf("Failed to create Logical Volume %s. Error: %s", name, err.Error()))
		}
		recheck, err := rt.Exec.Call(ctx, rt, "lvm.lvdisplay", &execlvm.LvDisplayArgs{LVName: lvpath})
		if err != nil {
			return result.Failure(name, err.Error())
		}
		if _, present := recheck.(map[string]any)[lvpath]; present {
			return result.New(name,
				fmt.Sprintf("Created Logical Volume %s", name),
				result.Bool(true),
				map[string]any{"created": created})
		}
		return result.Failure(name,
			fmt.Sprintf("Failed to create Logical Volume %s. Error: %s", name, outputOf(created)))
	}

	entry, _ := lv.(map[string]any)
	comment := fmt.Sprintf("Logical Volume %s already present", name)

	if a.Size != "" || a.Extents != "" {
		oldExtentsStr, _ := entry["Current Logical Extents Associated"].(string)
		oldExtents, convErr := strconv.Atoi(strings.TrimSpace(oldExtentsStr))
		if convErr != nil {
			return result.Failure(name, "Failed to parse current logical volume extents.")
		}
		sizeField, _ := entry["Logical Volume Size"].(string)
		oldSizeMB, convErr := convertToMB(strings.TrimSpace(sizeField) + "s")
		if convErr != nil {
			return result.Failure(name, convErr.Error())
		}

		reqExtents := oldExtents
		if a.Size == "" {
			if strings.Contains(a.Extents, "%") {
				comment = fmt.Sprintf(
					"Logical Volume %s already present, %s won't be resized.", name, a.Extents)
			} else {
				parsed, parseErr := strconv.Atoi(strings.TrimSpace(a.Extents))
				if parseErr != nil {
					return result.Failure(name, fmt.Sprintf("Extents %s is invalid.", a.Extents))
				}
				reqExtents = parsed
			}
			sizeMB = oldSizeMB
		}

		if !a.Force && (sizeMB < oldSizeMB || reqExtents < oldExtents) {
			return result.Failure(name, "To reduce a Logical Volume option 'force' must be True.")
		}

		if sizeMB != oldSizeMB || reqExtents != oldExtents {
			if a.Test {
				return result.TestPending(name,
					fmt.Sprintf("Logical Volume %s is set to be resized", name), nil)
			}
			resizeArgs := &execlvm.LvResizeArgs{
				LVPath: lvpath, Resizefs: a.Resizefs, Force: a.Force,
			}
			if a.Size != "" {
				resizeArgs.Size = a.Size
			} else {
				resizeArgs.Extents = strconv.Itoa(reqExtents)
			}
			changes, err := rt.Exec.Call(ctx, rt, "lvm.lvresize", resizeArgs)
			if err != nil {
				return result.Failure(name, err.Error())
			}
			if changes == nil || len(changes.(map[string]any)) == 0 {
				return result.Failure(name, "Failed to resize Logical Volume. Unknown Error.")
			}
			recheckRaw, err := rt.Exec.Call(ctx, rt, "lvm.lvdisplay",
				&execlvm.LvDisplayArgs{LVName: lvpath, Quiet: true})
			if err != nil {
				return result.Failure(name, err.Error())
			}
			recheck, found := recheckRaw.(map[string]any)[lvpath]
			if !found {
				return result.Failure(name,
					fmt.Sprintf("Failed to resize Logical Volume %s.\nError: %s",
						name, outputOf(changes)))
			}
			newSizeField, _ := recheck.(map[string]any)["Logical Volume Size"].(string)
			newSizeMB, convErr := convertToMB(strings.TrimSpace(newSizeField) + "s")
			if convErr != nil {
				return result.Failure(name, convErr.Error())
			}
			if newSizeMB != oldSizeMB {
				return result.New(name,
					fmt.Sprintf("Resized Logical Volume %s", name),
					result.Bool(true),
					map[string]any{"resized": changes})
			}
			return result.Failure(name,
				fmt.Sprintf("Failed to resize Logical Volume %s.\nError: %s",
					name, outputOf(changes)))
		}
	}
	return result.Success(name, comment)
}

type lvAbsentArgs struct {
	Name   string `statekit:"required"`
	VGName string `statekit:"name=vgname"`
	Test   bool   `statekit:"name=test"`
}

type lvAbsentFunc struct {
	linuxOnly
}

func (lvAbsentFunc) Name() string { return "lvm.lv_absent" }
func (lvAbsentFunc) Args() any    { return lvAbsentArgs{} }
func (lvAbsentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*lvAbsentArgs)
	lvpath := fmt.Sprintf("/dev/%s/%s", a.VGName, a.Name)

	lvRaw, err := rt.Exec.Call(ctx, rt, "lvm.lvdisplay", &execlvm.LvDisplayArgs{LVName: lvpath, Quiet: true})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	if len(lvRaw.(map[string]any)) == 0 {
		return result.Success(a.Name, fmt.Sprintf("Logical Volume %s already absent", a.Name))
	}
	if a.Test {
		return result.TestPending(a.Name,
			fmt.Sprintf("Logical Volume %s is set to be removed", a.Name), nil)
	}
	changes, err := rt.Exec.Call(ctx, rt, "lvm.lvremove",
		&execlvm.LvRemoveArgs{LVName: a.Name, VGName: a.VGName})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	stillRaw, err := rt.Exec.Call(ctx, rt, "lvm.lvdisplay",
		&execlvm.LvDisplayArgs{LVName: lvpath, Quiet: true})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	if len(stillRaw.(map[string]any)) > 0 {
		return result.Failure(a.Name, fmt.Sprintf("Failed to remove Logical Volume %s", a.Name))
	}
	return result.New(a.Name,
		fmt.Sprintf("Removed Logical Volume %s", a.Name),
		result.Bool(true),
		map[string]any{"removed": changes})
}

// Register installs all lvm-module state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{
		pvPresentFunc{},
		pvAbsentFunc{},
		vgPresentFunc{},
		vgAbsentFunc{},
		lvPresentFunc{},
		lvAbsentFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
