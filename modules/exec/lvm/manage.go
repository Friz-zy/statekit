// LVM create/remove/resize functions mirroring Salt's argv construction
// exactly, including flag ordering and the --yes / -qq force split.
package lvm

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// boolOrDefault applies Salt's tri-state defaults: an absent *bool keeps the
// function's documented Salt default.
func boolOrDefault(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

// yesOrQuiet appends the shared force switch used by most lvm2 tools.
func yesOrQuiet(argv []string, force bool) []string {
	if force {
		return append(argv, "--yes")
	}
	return append(argv, "-qq")
}

type PvCreateArgs struct {
	Devices  []string `statekit:"required,name=devices"`
	Override *bool    `statekit:"name=override"`
	Force    *bool    `statekit:"name=force"`

	Metadatasize          string `statekit:"name=metadatasize"`
	Dataalignment         string `statekit:"name=dataalignment"`
	Dataalignmentoffset   string `statekit:"name=dataalignmentoffset"`
	Pvmetadatacopies      string `statekit:"name=pvmetadatacopies"`
	Metadatacopies        string `statekit:"name=metadatacopies"`
	Metadataignore        string `statekit:"name=metadataignore"`
	Restorefile           string `statekit:"name=restorefile"`
	Labelsector           string `statekit:"name=labelsector"`
	Setphysicalvolumesize string `statekit:"name=setphysicalvolumesize"`
	NoRestorefile         bool   `statekit:"name=norestorefile"`
}

type pvCreateFunc struct {
	linuxOnly
}

func (pvCreateFunc) Name() string { return "lvm.pvcreate" }
func (pvCreateFunc) Args() any    { return PvCreateArgs{} }

func (pvCreateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PvCreateArgs)
	override := boolOrDefault(a.Override, true)
	cmd := []string{"pvcreate"}
	cmd = yesOrQuiet(cmd, boolOrDefault(a.Force, true))

	for _, device := range a.Devices {
		if _, err := rt.FS.Stat(device); err != nil {
			return nil, fmt.Errorf("%s does not exist", device)
		}
		existing, err := pvdisplay(ctx, rt, device, false)
		if err != nil {
			return nil, err
		}
		if len(existing) == 0 {
			cmd = append(cmd, device)
		} else if !override {
			return nil, fmt.Errorf("Device %q is already an LVM physical volume.", device)
		}
	}
	if len(cmd) == 2 {
		// All specified devices are already LVM physical volumes.
		return true, nil
	}

	for _, pair := range [][2]string{
		{"metadatasize", a.Metadatasize},
		{"dataalignment", a.Dataalignment},
		{"dataalignmentoffset", a.Dataalignmentoffset},
		{"pvmetadatacopies", a.Pvmetadatacopies},
		{"metadatacopies", a.Metadatacopies},
		{"metadataignore", a.Metadataignore},
		{"restorefile", a.Restorefile},
		{"labelsector", a.Labelsector},
		{"setphysicalvolumesize", a.Setphysicalvolumesize},
	} {
		if pair[1] != "" {
			cmd = append(cmd, "--"+pair[0], pair[1])
		}
	}
	if a.NoRestorefile {
		cmd = append(cmd, "--norestorefile")
	}

	_, stderr, code, err := runAll(ctx, rt, cmd...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, errors.New(stderr)
	}

	for _, device := range a.Devices {
		existing, err := pvdisplay(ctx, rt, device, false)
		if err != nil {
			return nil, err
		}
		if len(existing) == 0 {
			return nil, fmt.Errorf("Device %q was not affected.", device)
		}
	}
	return true, nil
}

type PvRemoveArgs struct {
	Devices []string `statekit:"required,name=devices"`
	Force   *bool    `statekit:"name=force"`
}

type pvRemoveFunc struct {
	linuxOnly
}

func (pvRemoveFunc) Name() string { return "lvm.pvremove" }
func (pvRemoveFunc) Args() any    { return PvRemoveArgs{} }
func (pvRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PvRemoveArgs)
	cmd := []string{"pvremove"}
	cmd = yesOrQuiet(cmd, boolOrDefault(a.Force, true))

	for _, device := range a.Devices {
		existing, err := pvdisplay(ctx, rt, device, false)
		if err != nil {
			return nil, err
		}
		if len(existing) > 0 {
			cmd = append(cmd, device)
		}
	}
	if len(cmd) == 2 {
		// Nothing to do: none of the devices are physical volumes.
		return true, nil
	}

	_, stderr, code, err := runAll(ctx, rt, cmd...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, errors.New(stderr)
	}

	for _, device := range a.Devices {
		existing, err := pvdisplay(ctx, rt, device, false)
		if err != nil {
			return nil, err
		}
		if len(existing) > 0 {
			return nil, fmt.Errorf("Device %q was not affected.", device)
		}
	}
	return true, nil
}

type VgCreateArgs struct {
	VGName  string   `statekit:"required,name=vgname"`
	Devices []string `statekit:"required,name=devices"`
	Force   bool     `statekit:"name=force"`

	Addtag             string `statekit:"name=addtag"`
	Alloc              string `statekit:"name=alloc"`
	Autobackup         string `statekit:"name=autobackup"`
	Clustered          string `statekit:"name=clustered"`
	Maxlogicalvolumes  string `statekit:"name=maxlogicalvolumes"`
	Maxphysicalvolumes string `statekit:"name=maxphysicalvolumes"`
	Metadatatype       string `statekit:"name=metadatatype"`
	Vgmetadatacopies   string `statekit:"name=vgmetadatacopies"`
	Metadatacopies     string `statekit:"name=metadatacopies"`
	Physicalextentsize string `statekit:"name=physicalextentsize"`
	Zero               string `statekit:"name=zero"`
}

type vgCreateFunc struct {
	linuxOnly
}

func (vgCreateFunc) Name() string { return "lvm.vgcreate" }
func (vgCreateFunc) Args() any    { return VgCreateArgs{} }
func (vgCreateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*VgCreateArgs)

	cmd := []string{"vgcreate", a.VGName}
	cmd = append(cmd, a.Devices...)
	cmd = yesOrQuiet(cmd, a.Force)
	for _, pair := range [][2]string{
		{"addtag", a.Addtag},
		{"alloc", a.Alloc},
		{"autobackup", a.Autobackup},
		{"clustered", a.Clustered},
		{"maxlogicalvolumes", a.Maxlogicalvolumes},
		{"maxphysicalvolumes", a.Maxphysicalvolumes},
		{"metadatatype", a.Metadatatype},
		{"vgmetadatacopies", a.Vgmetadatacopies},
		{"metadatacopies", a.Metadatacopies},
		{"physicalextentsize", a.Physicalextentsize},
		{"zero", a.Zero},
	} {
		if pair[1] != "" {
			cmd = append(cmd, "--"+pair[0], pair[1])
		}
	}

	_, stderr, code, err := runAll(ctx, rt, cmd...)
	if err != nil {
		return nil, err
	}
	out := fmt.Sprintf("Volume group %q successfully created", a.VGName)
	if code != 0 {
		out = stderr
	}
	vgdata, err := vgdisplay(ctx, rt, a.VGName)
	if err != nil {
		return nil, err
	}
	ret := map[string]any{}
	for k, v := range vgdata {
		ret[k] = v
	}
	ret["Output from vgcreate"] = out
	return ret, nil
}

type VgExtendArgs struct {
	VGName  string   `statekit:"required,name=vgname"`
	Devices []string `statekit:"required,name=devices"`
	Force   bool     `statekit:"name=force"`
}

type vgExtendFunc struct {
	linuxOnly
}

func (vgExtendFunc) Name() string { return "lvm.vgextend" }
func (vgExtendFunc) Args() any    { return VgExtendArgs{} }
func (vgExtendFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*VgExtendArgs)

	cmd := []string{"vgextend", a.VGName}
	cmd = yesOrQuiet(cmd, a.Force)
	cmd = append(cmd, a.Devices...)

	_, stderr, code, err := runAll(ctx, rt, cmd...)
	if err != nil {
		return nil, err
	}
	out := fmt.Sprintf("Volume group %q successfully extended", a.VGName)
	if code != 0 {
		out = stderr
	}
	return map[string]any{"Output from vgextend": out}, nil
}

type LvCreateArgs struct {
	LVName   string `statekit:"required,name=lvname"`
	VGName   string `statekit:"required,name=vgname"`
	Size     string `statekit:"name=size"`
	Extents  string `statekit:"name=extents"`
	Snapshot string `statekit:"name=snapshot"`
	PV       string `statekit:"name=pv"`

	ThinVolume bool `statekit:"name=thinvolume"`
	ThinPool   bool `statekit:"name=thinpool"`
	Force      bool `statekit:"name=force"`

	Activate         string `statekit:"name=activate"`
	Chunksize        string `statekit:"name=chunksize"`
	Contiguous       string `statekit:"name=contiguous"`
	Discards         string `statekit:"name=discards"`
	Stripes          string `statekit:"name=stripes"`
	Stripesize       string `statekit:"name=stripesize"`
	Minor            string `statekit:"name=minor"`
	Persistent       string `statekit:"name=persistent"`
	Mirrors          string `statekit:"name=mirrors"`
	Monitor          string `statekit:"name=monitor"`
	Permission       string `statekit:"name=permission"`
	Poolmetadatasize string `statekit:"name=poolmetadatasize"`
	Readahead        string `statekit:"name=readahead"`
	Regionsize       string `statekit:"name=regionsize"`
	Type             string `statekit:"name=type"`
	Virtualsize      string `statekit:"name=virtualsize"`
	Zero             string `statekit:"name=zero"`

	NoSync           bool `statekit:"name=nosync"`
	NoUdevsync       bool `statekit:"name=noudevsync"`
	IgnoreMonitoring bool `statekit:"name=ignoremonitoring"`
	Thin             bool `statekit:"name=thin"`
}

type lvCreateFunc struct {
	linuxOnly
}

func (lvCreateFunc) Name() string { return "lvm.lvcreate" }
func (lvCreateFunc) Args() any    { return LvCreateArgs{} }
func (lvCreateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*LvCreateArgs)

	if a.Size != "" && a.Extents != "" {
		return nil, errors.New("Error: Please specify only one of size or extents")
	}
	if a.ThinVolume && a.ThinPool {
		return nil, errors.New("Error: Please set only one of thinvolume or thinpool to True")
	}

	var extra []string
	for _, p := range []struct {
		key   string
		value string
	}{
		{"activate", a.Activate}, {"chunksize", a.Chunksize},
		{"contiguous", a.Contiguous}, {"discards", a.Discards},
		{"stripes", a.Stripes}, {"stripesize", a.Stripesize},
		{"minor", a.Minor}, {"persistent", a.Persistent},
		{"mirrors", a.Mirrors}, {"monitor", a.Monitor},
		{"permission", a.Permission}, {"poolmetadatasize", a.Poolmetadatasize},
		{"readahead", a.Readahead}, {"regionsize", a.Regionsize},
		{"type", a.Type}, {"virtualsize", a.Virtualsize}, {"zero", a.Zero},
	} {
		if p.value != "" {
			extra = append(extra, "--"+p.key, p.value)
		}
	}
	for _, flag := range []struct {
		set  bool
		name string
	}{
		{a.NoSync, "nosync"}, {a.NoUdevsync, "noudevsync"},
		{a.IgnoreMonitoring, "ignoremonitoring"}, {a.Thin, "thin"},
	} {
		if flag.set {
			extra = append(extra, "--"+flag.name)
		}
	}

	cmd := []string{"lvcreate"}
	switch {
	case a.ThinVolume:
		cmd = append(cmd, "--thin", "-n", a.LVName)
	case a.ThinPool:
		cmd = append(cmd, "--thinpool", a.LVName)
	default:
		cmd = append(cmd, "-n", a.LVName)
	}

	if a.Snapshot != "" {
		cmd = append(cmd, "-s", a.VGName+"/"+a.Snapshot)
	} else {
		cmd = append(cmd, a.VGName)
	}

	switch {
	case a.Size != "" && a.ThinVolume:
		cmd = append(cmd, "-V", a.Size)
	case a.Extents != "" && a.ThinVolume:
		return nil, errors.New("Error: Thin volume size cannot be specified as extents")
	case a.Size != "":
		cmd = append(cmd, "-L", a.Size)
	case a.Extents != "":
		cmd = append(cmd, "-l", a.Extents)
	default:
		return nil, errors.New("Error: Either size or extents must be specified")
	}

	if a.PV != "" {
		cmd = append(cmd, a.PV)
	}
	cmd = append(cmd, extra...)
	cmd = yesOrQuiet(cmd, a.Force)

	_, stderr, code, err := runAll(ctx, rt, cmd...)
	if err != nil {
		return nil, err
	}
	out := fmt.Sprintf("Logical volume %q created.", a.LVName)
	if code != 0 {
		out = stderr
	}

	lvdata, err := lvdisplay(ctx, rt, "/dev/"+a.VGName+"/"+a.LVName)
	if err != nil {
		return nil, err
	}
	ret := map[string]any{}
	for k, v := range lvdata {
		ret[k] = v
	}
	ret["Output from lvcreate"] = out
	return ret, nil
}

type VgRemoveArgs struct {
	VGName string `statekit:"required,name=vgname"`
	Force  *bool  `statekit:"name=force"`
}

type vgRemoveFunc struct {
	linuxOnly
}

func (vgRemoveFunc) Name() string { return "lvm.vgremove" }
func (vgRemoveFunc) Args() any    { return VgRemoveArgs{} }
func (vgRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*VgRemoveArgs)
	cmd := yesOrQuiet([]string{"vgremove", a.VGName}, boolOrDefault(a.Force, true))
	_, stderr, code, err := runAll(ctx, rt, cmd...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return stderr, nil
	}
	return fmt.Sprintf("Volume group %q successfully removed", a.VGName), nil
}

type LvRemoveArgs struct {
	LVName string `statekit:"required,name=lvname"`
	VGName string `statekit:"required,name=vgname"`
	Force  *bool  `statekit:"name=force"`
}

type lvRemoveFunc struct {
	linuxOnly
}

func (lvRemoveFunc) Name() string { return "lvm.lvremove" }
func (lvRemoveFunc) Args() any    { return LvRemoveArgs{} }
func (lvRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*LvRemoveArgs)
	cmd := yesOrQuiet([]string{"lvremove", a.VGName + "/" + a.LVName}, boolOrDefault(a.Force, true))
	_, stderr, code, err := runAll(ctx, rt, cmd...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return stderr, nil
	}
	return fmt.Sprintf("Logical volume %q successfully removed", a.LVName), nil
}

type LvResizeArgs struct {
	Size     string `statekit:"name=size"`
	LVPath   string `statekit:"name=lvpath"`
	Extents  string `statekit:"name=extents"`
	Force    bool   `statekit:"name=force"`
	Resizefs bool   `statekit:"name=resizefs"`
}

type lvResizeFunc struct {
	linuxOnly
}

func (lvResizeFunc) Name() string { return "lvm.lvresize" }
func (lvResizeFunc) Args() any    { return LvResizeArgs{} }
func (lvResizeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return resizeExec(ctx, rt, "lvresize", args.(*LvResizeArgs))
}

type LvExtendArgs struct {
	Size     string `statekit:"name=size"`
	LVPath   string `statekit:"name=lvpath"`
	Extents  string `statekit:"name=extents"`
	Force    bool   `statekit:"name=force"`
	Resizefs bool   `statekit:"name=resizefs"`
}

type lvExtendFunc struct {
	linuxOnly
}

func (lvExtendFunc) Name() string { return "lvm.lvextend" }
func (lvExtendFunc) Args() any    { return LvExtendArgs{} }
func (lvExtendFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return resizeExec(ctx, rt, "lvextend", args.(*LvExtendArgs))
}

// resizeExec carries the shared lvresize/lvextend contract. Argument errors
// return an empty result like Salt instead of failing.
func resizeExec(ctx context.Context, rt *runtime.Runtime, tool string, a any) (any, error) {
	size, lvpath, extents, force, resizefs := "", "", "", false, false
	switch v := a.(type) {
	case *LvResizeArgs:
		size, lvpath, extents, force, resizefs = v.Size, v.LVPath, v.Extents, v.Force, v.Resizefs
	case *LvExtendArgs:
		size, lvpath, extents, force, resizefs = v.Size, v.LVPath, v.Extents, v.Force, v.Resizefs
	}

	if size != "" && extents != "" {
		return map[string]any{}, nil
	}
	cmd := []string{tool}
	if tool == "lvresize" {
		if force {
			cmd = append(cmd, "--force")
		} else {
			cmd = append(cmd, "-qq")
		}
	} else {
		cmd = yesOrQuiet(cmd, force)
	}
	if resizefs {
		cmd = append(cmd, "--resizefs")
	}
	switch {
	case size != "":
		cmd = append(cmd, "-L", size)
	case extents != "":
		cmd = append(cmd, "-l", extents)
	default:
		return map[string]any{}, nil
	}
	cmd = append(cmd, lvpath)

	_, stderr, code, err := runAll(ctx, rt, cmd...)
	if err != nil {
		return nil, err
	}
	out := fmt.Sprintf("Logical volume %q successfully resized.", lvpath)
	if tool == "lvextend" {
		out = fmt.Sprintf("Logical volume %q successfully extended.", lvpath)
	}
	if code != 0 {
		out = stderr
	}
	return map[string]any{"Output from " + tool: out}, nil
}

type PvResizeArgs struct {
	Devices []string `statekit:"required,name=devices"`
	Force   *bool    `statekit:"name=force"`
}

type pvResizeFunc struct {
	linuxOnly
}

func (pvResizeFunc) Name() string { return "lvm.pvresize" }
func (pvResizeFunc) Args() any    { return PvResizeArgs{} }
func (pvResizeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PvResizeArgs)
	cmd := []string{"pvresize"}
	cmd = yesOrQuiet(cmd, boolOrDefault(a.Force, true))

	for _, device := range a.Devices {
		existing, err := pvdisplay(ctx, rt, device, false)
		if err != nil {
			return nil, err
		}
		if len(existing) > 0 {
			cmd = append(cmd, device)
		}
	}
	if len(cmd) == 2 {
		// Nothing to do.
		return true, nil
	}

	_, stderr, code, err := runAll(ctx, rt, cmd...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, errors.New(strings.TrimSpace(stderr))
	}
	return true, nil
}
