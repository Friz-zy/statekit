package file

// Registry wiring for the R4.2 device family. The platform backends live
// in filedev_unix.go / filedev_other.go.

import (
	"context"
	"fmt"

	"github.com/friz-zy/statekit/internal/runtime"
)

type isChrdevArgs struct {
	Name string `statekit:"required,name=name"`
}

type isChrdevFunc struct{}

func (isChrdevFunc) Name() string { return "file.is_chrdev" }
func (isChrdevFunc) Args() any    { return isChrdevArgs{} }
func (isChrdevFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*isChrdevArgs)
	return isChrdev(expandUser(a.Name)), nil
}

type isBlkdevArgs struct {
	Name string `statekit:"required,name=name"`
}

type isBlkdevFunc struct{}

func (isBlkdevFunc) Name() string { return "file.is_blkdev" }
func (isBlkdevFunc) Args() any    { return isBlkdevArgs{} }
func (isBlkdevFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*isBlkdevArgs)
	return isBlkdev(expandUser(a.Name)), nil
}

type isFifoArgs struct {
	Name string `statekit:"required,name=name"`
}

type isFifoFunc struct{}

func (isFifoFunc) Name() string { return "file.is_fifo" }
func (isFifoFunc) Args() any    { return isFifoArgs{} }
func (isFifoFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*isFifoArgs)
	return isFifoDev(expandUser(a.Name)), nil
}

type getDevmmArgs struct {
	Name string `statekit:"required,name=name"`
}

type getDevmmFunc struct{}

func (getDevmmFunc) Name() string { return "file.get_devmm" }
func (getDevmmFunc) Args() any    { return getDevmmArgs{} }
func (getDevmmFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*getDevmmArgs)
	major, minor := devmm(expandUser(a.Name))
	return []int{major, minor}, nil
}

type mknodChrdevArgs struct {
	Name  string  `statekit:"required,name=name"`
	Major int     `statekit:"name=major"`
	Minor int     `statekit:"name=minor"`
	User  *string `statekit:"name=user"`
	Group *string `statekit:"name=group"`
	Mode  *string `statekit:"name=mode"`
}

type mknodChrdevFunc struct{}

func (mknodChrdevFunc) Name() string { return "file.mknod_chrdev" }
func (mknodChrdevFunc) Args() any    { return mknodChrdevArgs{} }
func (mknodChrdevFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*mknodChrdevArgs)
	mode := orDefault(a.Mode, "0660")
	ret, err := mknodUnix(expandUser(a.Name), "c", a.Major, a.Minor, parseMknodMode(mode))
	if err != nil {
		return nil, err
	}
	return ret["result"], nil
}

type mknodBlkdevArgs struct {
	Name  string  `statekit:"required,name=name"`
	Major int     `statekit:"name=major"`
	Minor int     `statekit:"name=minor"`
	User  *string `statekit:"name=user"`
	Group *string `statekit:"name=group"`
	Mode  *string `statekit:"name=mode"`
}

type mknodBlkdevFunc struct{}

func (mknodBlkdevFunc) Name() string { return "file.mknod_blkdev" }
func (mknodBlkdevFunc) Args() any    { return mknodBlkdevArgs{} }
func (mknodBlkdevFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*mknodBlkdevArgs)
	mode := orDefault(a.Mode, "0660")
	ret, err := mknodUnix(expandUser(a.Name), "b", a.Major, a.Minor, parseMknodMode(mode))
	if err != nil {
		return nil, err
	}
	return ret["result"], nil
}

type mknodFifoArgs struct {
	Name  string  `statekit:"required,name=name"`
	User  *string `statekit:"name=user"`
	Group *string `statekit:"name=group"`
	Mode  *string `statekit:"name=mode"`
}

type mknodFifoFunc struct{}

func (mknodFifoFunc) Name() string { return "file.mknod_fifo" }
func (mknodFifoFunc) Args() any    { return mknodFifoArgs{} }
func (mknodFifoFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*mknodFifoArgs)
	mode := orDefault(a.Mode, "0660")
	ret, err := mknodUnix(expandUser(a.Name), "p", 0, 0, parseMknodMode(mode))
	if err != nil {
		return nil, err
	}
	return ret["result"], nil
}

type mknodArgs struct {
	Name  string  `statekit:"required,name=name"`
	Ntype string  `statekit:"required,name=ntype"`
	Major int     `statekit:"name=major"`
	Minor int     `statekit:"name=minor"`
	User  *string `statekit:"name=user"`
	Group *string `statekit:"name=group"`
	Mode  *string `statekit:"name=mode"`
}

type mknodFunc struct{}

func (mknodFunc) Name() string { return "file.mknod" }
func (mknodFunc) Args() any    { return mknodArgs{} }
func (mknodFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*mknodArgs)
	switch a.Ntype {
	case "c", "b", "p":
	default:
		return nil, fmt.Errorf("Unknown nodetype '%s'. Valid types are 'c', 'p' and 'b'", a.Ntype)
	}
	if a.Ntype == "p" {
		fifo := mknodFifoFunc{}
		res, err := fifo.Execute(ctx, rt, &mknodFifoArgs{
			Name: a.Name, User: a.User, Group: a.Group, Mode: a.Mode,
		})
		if err != nil {
			return nil, err
		}
		return res, nil
	}
	mode := orDefault(a.Mode, "0600")
	ret, err := mknodUnix(expandUser(a.Name), a.Ntype, a.Major, a.Minor, parseMknodMode(mode))
	if err != nil {
		return nil, err
	}
	return ret["result"], nil
}

// RegisterDevices installs the R4.2 device functions.
func RegisterDevices(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		isChrdevFunc{},
		isBlkdevFunc{},
		isFifoFunc{},
		getDevmmFunc{},
		mknodChrdevFunc{},
		mknodBlkdevFunc{},
		mknodFifoFunc{},
		mknodFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
