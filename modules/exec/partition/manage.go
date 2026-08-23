// Remaining partition functions: naming, rescue/resize/rm, flags, and
// device enumeration.
package partition

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

func execLookPath(name string) (string, error) { return exec.LookPath(name) }

type NameArgs struct {
	Device    string `statekit:"required,name=device"`
	Partition string `statekit:"required,name=partition"`
	Name      string `statekit:"required,name=name"`
}

type nameFunc struct {
	linuxOnly
}

func (nameFunc) Name() string { return "partition.name" }
func (nameFunc) Args() any    { return NameArgs{} }
func (nameFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*NameArgs)
	if err := validateDevice(rt, a.Device); err != nil {
		return nil, err
	}
	if err := validateInt(a.Partition, "name"); err != nil {
		return nil, fmt.Errorf("Invalid partition passed to partition.name")
	}
	valid := func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == ' ' || r == '_' || r == '-'
	}
	for _, letter := range a.Name {
		if !valid(letter) {
			return nil, fmt.Errorf("Invalid characters passed to partition.name")
		}
	}
	// Salt shells out with "'{name}'" so parted receives the quoted name;
	// argv passes the same quoted token verbatim.
	return runLines(ctx, rt, "parted", "-m", "-s", a.Device,
		"name", a.Partition, "'"+a.Name+"'")
}

type RescueArgs struct {
	Device string `statekit:"required,name=device"`
	Start  string `statekit:"required,name=start"`
	End    string `statekit:"required,name=end"`
}

type rescueFunc struct {
	linuxOnly
}

func (rescueFunc) Name() string { return "partition.rescue" }
func (rescueFunc) Args() any    { return RescueArgs{} }
func (rescueFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RescueArgs)
	if err := validateDevice(rt, a.Device); err != nil {
		return nil, err
	}
	if err := validateBoundary(a.Start); err != nil {
		return nil, err
	}
	if err := validateBoundary(a.End); err != nil {
		return nil, err
	}
	return runLines(ctx, rt, "parted", "-m", "-s", a.Device, "rescue", a.Start, a.End)
}

type ResizeArgs struct {
	Device string `statekit:"required,name=device"`
	Minor  string `statekit:"required,name=minor"`
	Start  string `statekit:"required,name=start"`
	End    string `statekit:"required,name=end"`
}

type resizeFunc struct {
	linuxOnly
}

func (resizeFunc) Name() string { return "partition.resize" }
func (resizeFunc) Args() any    { return ResizeArgs{} }
func (resizeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ResizeArgs)
	if err := validateDevice(rt, a.Device); err != nil {
		return nil, err
	}
	if err := validateInt(a.Minor, "resize"); err != nil {
		return nil, err
	}
	if err := validateBoundary(a.Start); err != nil {
		return nil, err
	}
	if err := validateBoundary(a.End); err != nil {
		return nil, err
	}
	return runLines(ctx, rt, "parted", "-m", "-s", "--", a.Device,
		"resize", a.Minor, a.Start, a.End)
}

type RmArgs struct {
	Device string `statekit:"required,name=device"`
	Minor  string `statekit:"required,name=minor"`
}

type rmFunc struct {
	linuxOnly
}

func (rmFunc) Name() string { return "partition.rm" }
func (rmFunc) Args() any    { return RmArgs{} }
func (rmFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RmArgs)
	if err := validateDevice(rt, a.Device); err != nil {
		return nil, err
	}
	if err := validateInt(a.Minor, "rm"); err != nil {
		return nil, err
	}
	return runLines(ctx, rt, "parted", "-m", "-s", a.Device, "rm", a.Minor)
}

type SetArgs struct {
	Device string `statekit:"required,name=device"`
	Minor  string `statekit:"required,name=minor"`
	Flag   string `statekit:"required,name=flag"`
	State  string `statekit:"required,name=state"`
}

type setFunc struct {
	linuxOnly
}

func (setFunc) Name() string { return "partition.set" }
func (setFunc) Args() any    { return SetArgs{} }

// setImpl carries the shared partition.set contract.
func setImpl(ctx context.Context, rt *runtime.Runtime, a *SetArgs) (any, error) {
	if err := validateDevice(rt, a.Device); err != nil {
		return nil, err
	}
	if err := validateInt(a.Minor, "set"); err != nil {
		return nil, err
	}
	if !validPartitionFlags[a.Flag] {
		return nil, fmt.Errorf("Invalid flag passed to partition.set")
	}
	if a.State != "on" && a.State != "off" {
		return nil, fmt.Errorf("Invalid state passed to partition.set")
	}
	return runLines(ctx, rt, "parted", "-m", "-s", a.Device,
		"set", a.Minor, a.Flag, a.State)
}

func (setFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return setImpl(ctx, rt, args.(*SetArgs))
}

type ToggleArgs struct {
	Device    string `statekit:"required,name=device"`
	Partition string `statekit:"required,name=partition"`
	Flag      string `statekit:"required,name=flag"`
}

type toggleFunc struct {
	linuxOnly
}

func (toggleFunc) Name() string { return "partition.toggle" }
func (toggleFunc) Args() any    { return ToggleArgs{} }
func (toggleFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ToggleArgs)
	if err := validateDevice(rt, a.Device); err != nil {
		return nil, err
	}
	if err := validateInt(a.Partition, "toggle"); err != nil {
		return nil, fmt.Errorf("Invalid partition number passed to partition.toggle")
	}
	if !validPartitionFlags[a.Flag] {
		return nil, fmt.Errorf("Invalid flag passed to partition.toggle")
	}
	return runLines(ctx, rt, "parted", "-m", "-s", a.Device,
		"toggle", a.Partition, a.Flag)
}

type DiskSetArgs struct {
	Device string `statekit:"required,name=device"`
	Flag   string `statekit:"required,name=flag"`
	State  string `statekit:"required,name=state"`
}

type diskSetFunc struct {
	linuxOnly
}

func (diskSetFunc) Name() string { return "partition.disk_set" }
func (diskSetFunc) Args() any    { return DiskSetArgs{} }
func (diskSetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DiskSetArgs)
	if err := validateDevice(rt, a.Device); err != nil {
		return nil, err
	}
	if !validDiskFlags[a.Flag] {
		return nil, fmt.Errorf("Invalid flag passed to partition.disk_set")
	}
	if a.State != "on" && a.State != "off" {
		return nil, fmt.Errorf("Invalid state passed to partition.disk_set")
	}
	return runLines(ctx, rt, "parted", "-m", "-s", a.Device,
		"disk_set", a.Flag, a.State)
}

type DiskToggleArgs struct {
	Device string `statekit:"required,name=device"`
	Flag   string `statekit:"required,name=flag"`
}

type diskToggleFunc struct {
	linuxOnly
}

func (diskToggleFunc) Name() string { return "partition.disk_toggle" }
func (diskToggleFunc) Args() any    { return DiskToggleArgs{} }
func (diskToggleFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DiskToggleArgs)
	if err := validateDevice(rt, a.Device); err != nil {
		return nil, err
	}
	if !validDiskFlags[a.Flag] {
		return nil, fmt.Errorf("Invalid flag passed to partition.disk_toggle")
	}
	return runLines(ctx, rt, "parted", "-m", "-s", a.Device, "disk_toggle", a.Flag)
}

type ExistsArgs struct {
	Device string `statekit:"name=device"`
}

type existsFunc struct {
	linuxOnly
}

func (existsFunc) Name() string { return "partition.exists" }
func (existsFunc) Args() any    { return ExistsArgs{} }
func (existsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ExistsArgs)
	fi, err := rt.FS.Stat(a.Device)
	if err == nil && isBlockDev(fi) {
		return true, nil
	}
	return false, nil
}

type GetBlockDeviceArgs struct{}

type getBlockDeviceFunc struct {
	linuxOnly
}

func (getBlockDeviceFunc) Name() string { return "partition.get_block_device" }
func (getBlockDeviceFunc) Args() any    { return GetBlockDeviceArgs{} }
func (getBlockDeviceFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	res := rt.Runner.Run(ctx, runtime.Command(
		"lsblk", "-n", "-io", "KNAME", "-d", "-e", "1,7,11", "-l"))
	if res.Err != nil {
		return nil, res.Err
	}
	out := strings.TrimRight(string(res.Stdout), "\n")
	if out == "" {
		return []string{}, nil
	}
	return strings.Split(out, "\n"), nil
}

// Register installs all partition-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		probeFunc{},
		listFunc{},
		alignCheckFunc{},
		checkFunc{},
		cpFunc{},
		getIDFunc{},
		setIDFunc{},
		systemTypesFunc{},
		mkfsFunc{},
		mklabelFunc{},
		mkpartFunc{},
		mkpartfsFunc{},
		nameFunc{},
		rescueFunc{},
		resizeFunc{},
		rmFunc{},
		setFunc{},
		toggleFunc{},
		diskSetFunc{},
		diskToggleFunc{},
		existsFunc{},
		getBlockDeviceFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
