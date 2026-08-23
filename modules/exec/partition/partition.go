// Package partition implements Salt-compatible disk partition management
// through parted, partprobe, lsblk and sfdisk (Salt virtual name
// "partition").
//
// Reference: saltstack/salt/modules/parted_partition.py @ pinned revision.
// Salt composes shell strings for most calls; StateKit emits argv through
// the central Runner. partition.name keeps Salt's quoted "'name'" argument
// verbatim, which the parted CLI expects after shell processing.
package partition

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts every function of this module to linux: parted and
// util-linux partitioning is a Linux contract in StateKit's scope.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// VALID_UNITS mirrors Salt's VALID_UNITS.
var validUnits = map[string]bool{
	"s": true, "B": true, "kB": true, "MB": true, "MiB": true,
	"GB": true, "GiB": true, "TB": true, "TiB": true, "%": true,
	"cyl": true, "chs": true, "compact": true,
}

// validDiskFlags mirrors VALID_DISK_FLAGS.
var validDiskFlags = map[string]bool{
	"cylinder_alignment": true, "pmbr_boot": true, "implicit_partition_table": true,
}

// validPartitionFlags mirrors VALID_PARTITION_FLAGS.
var validPartitionFlags = map[string]bool{
	"boot": true, "root": true, "swap": true, "hidden": true, "raid": true,
	"lvm": true, "lba": true, "hp-service": true, "palo": true, "prep": true,
	"msftres": true, "bios_grub": true, "atvrecv": true, "diag": true,
	"legacy_boot": true, "msftdata": true, "irst": true, "esp": true, "type": true,
}

// isBlockDev reports whether a filesystem entry is a block device. Split
// out for hermetic test injection, like Salt's os.stat patching; the
// platform check lives in blockdev_unix.go / blockdev_windows.go.
var isBlockDev = func(fi os.FileInfo) bool { return fileIsBlock(fi) }

// runLines executes argv and returns non-split stdout lines like Salt's
// cmd.run().splitlines().
func runLines(ctx context.Context, rt *runtime.Runtime, argv ...string) ([]string, error) {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return nil, res.Err
	}
	out := strings.TrimRight(string(res.Stdout), "\n")
	if out == "" {
		return []string{}, nil
	}
	return strings.Split(out, "\n"), nil
}

// validateDevice raises Salt's invalid-device error unless path exists and
// is a block device.
func validateDevice(rt *runtime.Runtime, device string) error {
	fi, err := rt.FS.Stat(device)
	if err == nil && isBlockDev(fi) {
		return nil
	}
	return fmt.Errorf("Invalid device passed to partition module.")
}

var boundaryRe = regexp.MustCompile(`^([\d.]+)(\D*)$`)

// validateBoundary ensures valid partition boundaries are supplied.
func validateBoundary(boundary string) error {
	m := boundaryRe.FindStringSubmatch(boundary)
	if m != nil {
		unit := m[2]
		if unit == "" || validUnits[unit] {
			return nil
		}
	}
	return fmt.Errorf("Invalid partition boundary passed: %q", boundary)
}

// validateInt mirrors the repeated int() casts with their exact messages.
func validateInt(value, function string) error {
	for _, r := range value {
		if r < '0' || r > '9' {
			return fmt.Errorf("Invalid minor number passed to partition.%s", function)
		}
	}
	if value == "" {
		return fmt.Errorf("Invalid minor number passed to partition.%s", function)
	}
	return nil
}

func stdoutOf(ctx context.Context, rt *runtime.Runtime, argv ...string) string {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return ""
	}
	return string(res.Stdout)
}

type ProbeArgs struct {
	Devices []string `statekit:"name=devices"`
}

type probeFunc struct {
	linuxOnly
}

func (probeFunc) Name() string { return "partition.probe" }
func (probeFunc) Args() any    { return ProbeArgs{} }
func (probeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ProbeArgs)
	for _, device := range a.Devices {
		if err := validateDevice(rt, device); err != nil {
			return nil, err
		}
	}
	argv := append([]string{"partprobe", "--"}, a.Devices...)
	return runLines(ctx, rt, argv...)
}

type ListArgs struct {
	Device string `statekit:"required,name=device"`
	Unit   string `statekit:"name=unit"`
}

type listFunc struct {
	linuxOnly
}

func (listFunc) Name() string { return "partition.list" }
func (listFunc) Args() any    { return ListArgs{} }

// listImpl holds the shared list_ parsing contract.
func listImpl(ctx context.Context, rt *runtime.Runtime, device, unit string) (any, error) {
	if err := validateDevice(rt, device); err != nil {
		return nil, err
	}
	argv := []string{"parted", "-m", "-s"}
	if unit != "" {
		if !validUnits[unit] {
			return nil, fmt.Errorf("Invalid unit passed to partition.part_list")
		}
		argv = append(argv, device, "unit", unit, "print")
	} else {
		argv = append(argv, device, "print")
	}

	lines, err := runLines(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}

	ret := map[string]any{
		"info":       map[string]any{},
		"partitions": map[string]any{},
	}
	mode := "info"
	for _, line := range lines {
		if line == "BYT;" || line == "CHS;" || line == "CYL;" {
			continue
		}
		cols := strings.Split(strings.TrimSuffix(line, ";"), ":")
		if mode == "info" {
			if len(cols) >= 7 && len(cols) <= 8 {
				info := map[string]any{
					"disk":            cols[0],
					"size":            cols[1],
					"interface":       cols[2],
					"logical sector":  cols[3],
					"physical sector": cols[4],
					"partition table": cols[5],
					"model":           cols[6],
				}
				if len(cols) == 8 {
					// Older parted (2.x) omits disk flags entirely.
					info["disk flags"] = cols[7]
				}
				ret["info"] = info
				mode = "partitions"
			} else {
				return nil, fmt.Errorf("Problem encountered while parsing output from parted")
			}
		} else {
			// Parted (v3.1) machine format:
			// number:start:end:[size:]([file system:name:flags;]|[free;])
			fields := []string{"number", "start", "end"}
			if unit != "chs" {
				fields = append(fields, "size")
			}
			if cols[len(cols)-1] == "free" {
				cols = cols[:len(cols)-1]
			} else {
				fields = append(fields, "file system", "name", "flags")
			}
			if len(fields) == len(cols) {
				row := map[string]any{}
				for i, f := range fields {
					row[f] = cols[i]
				}
				ret["partitions"].(map[string]any)[cols[0]] = row
			} else {
				return nil, fmt.Errorf("Problem encountered while parsing output from parted")
			}
		}
	}
	return ret, nil
}

func (listFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListArgs)
	return listImpl(ctx, rt, a.Device, a.Unit)
}

type AlignCheckArgs struct {
	Device    string `statekit:"required,name=device"`
	PartType  string `statekit:"required,name=part_type"`
	Partition string `statekit:"required,name=partition"`
}

type alignCheckFunc struct {
	linuxOnly
}

func (alignCheckFunc) Name() string { return "partition.align_check" }
func (alignCheckFunc) Args() any    { return AlignCheckArgs{} }
func (alignCheckFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AlignCheckArgs)
	if err := validateDevice(rt, a.Device); err != nil {
		return nil, err
	}
	if a.PartType != "minimal" && a.PartType != "optimal" {
		return nil, fmt.Errorf("Invalid part_type passed to partition.align_check")
	}
	if err := validateInt(a.Partition, "align_check"); err != nil {
		return nil, fmt.Errorf("Invalid partition passed to partition.align_check")
	}
	return runLines(ctx, rt, "parted", "-m", a.Device, "align-check", a.PartType, a.Partition)
}

type CheckArgs struct {
	Device string `statekit:"required,name=device"`
	Minor  string `statekit:"required,name=minor"`
}

type checkFunc struct {
	linuxOnly
}

func (checkFunc) Name() string { return "partition.check" }
func (checkFunc) Args() any    { return CheckArgs{} }
func (checkFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CheckArgs)
	if err := validateDevice(rt, a.Device); err != nil {
		return nil, err
	}
	if err := validateInt(a.Minor, "check"); err != nil {
		return nil, err
	}
	return runLines(ctx, rt, "parted", "-m", "-s", a.Device, "check", a.Minor)
}

type CpArgs struct {
	Device    string `statekit:"required,name=device"`
	FromMinor string `statekit:"required,name=from_minor"`
	ToMinor   string `statekit:"required,name=to_minor"`
}

type cpFunc struct {
	linuxOnly
}

func (cpFunc) Name() string { return "partition.cp" }
func (cpFunc) Args() any    { return CpArgs{} }
func (cpFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CpArgs)
	if err := validateDevice(rt, a.Device); err != nil {
		return nil, err
	}
	if err := validateInt(a.FromMinor, "cp"); err != nil {
		return nil, err
	}
	if err := validateInt(a.ToMinor, "cp"); err != nil {
		return nil, err
	}
	return runLines(ctx, rt, "parted", "-m", "-s", a.Device, "cp", a.FromMinor, a.ToMinor)
}

type GetIDArgs struct {
	Device string `statekit:"required,name=device"`
	Minor  string `statekit:"required,name=minor"`
}

type getIDFunc struct {
	linuxOnly
}

func (getIDFunc) Name() string { return "partition.get_id" }
func (getIDFunc) Args() any    { return GetIDArgs{} }
func (getIDFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetIDArgs)
	if err := validateDevice(rt, a.Device); err != nil {
		return nil, err
	}
	if err := validateInt(a.Minor, "get_id"); err != nil {
		return nil, err
	}
	return runLines(ctx, rt, "sfdisk", "--print-id", a.Device, a.Minor)
}

type SetIDArgs struct {
	Device   string `statekit:"required,name=device"`
	Minor    string `statekit:"required,name=minor"`
	SystemID string `statekit:"required,name=system_id"`
}

type setIDFunc struct {
	linuxOnly
}

func (setIDFunc) Name() string { return "partition.set_id" }
func (setIDFunc) Args() any    { return SetIDArgs{} }

// systemTypes lists sfdisk-supported system types.
func systemTypes(ctx context.Context, rt *runtime.Runtime) (map[string]any, error) {
	ret := map[string]any{}
	res := rt.Runner.Run(ctx, runtime.Command("sfdisk", "-T"))
	if res.Err != nil {
		return nil, res.Err
	}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if line == "" || strings.HasPrefix(line, "Id") {
			continue
		}
		comps := strings.Fields(line)
		if len(comps) < 2 {
			continue
		}
		ret[comps[0]] = comps[1]
	}
	return ret, nil
}

func (setIDFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetIDArgs)
	if err := validateDevice(rt, a.Device); err != nil {
		return nil, err
	}
	if err := validateInt(a.Minor, "set_id"); err != nil {
		return nil, err
	}
	types, err := systemTypes(ctx, rt)
	if err != nil {
		return nil, err
	}
	if _, ok := types[a.SystemID]; !ok {
		return nil, fmt.Errorf("Invalid system_id passed to partition.set_id")
	}
	return runLines(ctx, rt, "sfdisk", "--change-id", a.Device, a.Minor, a.SystemID)
}

type SystemTypesArgs struct{}

type systemTypesFunc struct {
	linuxOnly
}

func (systemTypesFunc) Name() string { return "partition.system_types" }
func (systemTypesFunc) Args() any    { return SystemTypesArgs{} }
func (systemTypesFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return systemTypes(ctx, rt)
}

// isFstype mirrors Salt's _is_fstype.
func isFstype(fsType string) bool {
	switch fsType {
	case "btrfs", "ext2", "ext3", "ext4", "fat", "fat32", "fat16",
		"linux-swap", "reiserfs", "hfs", "hfs+", "hfsx", "NTFS", "ntfs",
		"ufs", "xfs":
		return true
	}
	return false
}

type MkfsArgs struct {
	Device string `statekit:"required,name=device"`
	FsType string `statekit:"required,name=fs_type"`
}

type mkfsFunc struct {
	linuxOnly
}

func (mkfsFunc) Name() string { return "partition.mkfs" }
func (mkfsFunc) Args() any    { return MkfsArgs{} }
func (mkfsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*MkfsArgs)
	if err := validateDevice(rt, a.Device); err != nil {
		return nil, err
	}
	fsType := a.FsType
	if !isFstype(fsType) {
		return nil, fmt.Errorf("Invalid fs_type passed to partition.mkfs")
	}
	if fsType == "NTFS" {
		fsType = "ntfs"
	}
	mkfsCmd := "mkfs." + fsType
	if fsType == "linux-swap" {
		mkfsCmd = "mkswap"
	}
	if _, err := lookPath(mkfsCmd); err != nil {
		return nil, fmt.Errorf("Error: %s is unavailable.", mkfsCmd)
	}
	return runLines(ctx, rt, mkfsCmd, a.Device)
}

// lookPath resolves helper binaries without executing them; split out for
// test injection.
var lookPath = execLookPath

type MklabelArgs struct {
	Device    string `statekit:"required,name=device"`
	LabelType string `statekit:"required,name=label_type"`
}

type mklabelFunc struct {
	linuxOnly
}

func (mklabelFunc) Name() string { return "partition.mklabel" }
func (mklabelFunc) Args() any    { return MklabelArgs{} }
func (mklabelFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*MklabelArgs)
	switch a.LabelType {
	case "aix", "amiga", "bsd", "dvh", "gpt", "loop", "mac", "msdos", "pc98", "sun":
	default:
		return nil, fmt.Errorf("Invalid label_type passed to partition.mklabel")
	}
	return runLines(ctx, rt, "parted", "-m", "-s", a.Device, "mklabel", a.LabelType)
}

type MkpartArgs struct {
	Device   string `statekit:"required,name=device"`
	PartType string `statekit:"required,name=part_type"`
	FsType   string `statekit:"name=fs_type"`
	Start    string `statekit:"name=start"`
	End      string `statekit:"name=end"`
}

type mkpartFunc struct {
	linuxOnly
}

func (mkpartFunc) Name() string { return "partition.mkpart" }
func (mkpartFunc) Args() any    { return MkpartArgs{} }

// mkpartImpl carries the shared mkpart/mkpartfs contract.
func mkpartImpl(ctx context.Context, rt *runtime.Runtime, a *MkpartArgs) (any, error) {
	if err := validateDevice(rt, a.Device); err != nil {
		return nil, err
	}
	switch a.PartType {
	case "primary", "logical", "extended":
	default:
		return nil, fmt.Errorf("Invalid part_type passed to partition.mkpart")
	}
	if a.FsType != "" && !isFstype(a.FsType) {
		return nil, fmt.Errorf("Invalid fs_type passed to partition.mkpart")
	}
	if a.Start != "" && a.End != "" {
		if err := validateBoundary(a.Start); err != nil {
			return nil, err
		}
		if err := validateBoundary(a.End); err != nil {
			return nil, err
		}
	}
	start := a.Start
	end := a.End
	argv := []string{"parted", "-m", "-s", "--", a.Device, "mkpart", a.PartType}
	if a.FsType != "" {
		argv = append(argv, a.FsType)
	}
	argv = append(argv, start, end)
	return runLines(ctx, rt, argv...)
}

func (mkpartFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return mkpartImpl(ctx, rt, args.(*MkpartArgs))
}

type mkpartfsFunc struct {
	linuxOnly
}

func (mkpartfsFunc) Name() string { return "partition.mkpartfs" }
func (mkpartfsFunc) Args() any    { return MkpartArgs{} }
func (mkpartfsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	// mkpartfs is an alias to mkpart kept for compatibility.
	return mkpartImpl(ctx, rt, args.(*MkpartArgs))
}
