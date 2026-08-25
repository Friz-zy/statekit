// Package ret dispatches job-return queries to returner plugins, mirroring
// saltstack/salt/modules/ret.py @ pinned revision. Returners are part of
// the master-minion job architecture which is permanently excluded, so
// every function surfaces that exclusion explicitly.
package ret

import (
	"context"

	"github.com/friz-zy/statekit/internal/runtime"
)

func returnerUnsupported(fn string) error {
	return &runtime.UnsupportedError{Kind: "function", Name: fn}
}

type GetJidArgs struct {
	Returner string `statekit:"required,name=returner"`
	Jid      string `statekit:"required,name=jid"`
}

type getJidFunc struct{}

func (getJidFunc) Name() string { return "ret.get_jid" }
func (getJidFunc) Args() any    { return GetJidArgs{} }
func (getJidFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return nil, returnerUnsupported("ret.get_jid")
}

type GetFunArgs struct {
	Returner string `statekit:"required,name=returner"`
	Fun      string `statekit:"required,name=fun"`
}

type getFunFunc struct{}

func (getFunFunc) Name() string { return "ret.get_fun" }
func (getFunFunc) Args() any    { return GetFunArgs{} }
func (getFunFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return nil, returnerUnsupported("ret.get_fun")
}

type GetJidsArgs struct {
	Returner string `statekit:"required,name=returner"`
}

type getJidsFunc struct{}

func (getJidsFunc) Name() string { return "ret.get_jids" }
func (getJidsFunc) Args() any    { return GetJidsArgs{} }
func (getJidsFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return nil, returnerUnsupported("ret.get_jids")
}

type GetMinionsArgs struct {
	Returner string `statekit:"required,name=returner"`
}

type getMinionsFunc struct{}

func (getMinionsFunc) Name() string { return "ret.get_minions" }
func (getMinionsFunc) Args() any    { return GetMinionsArgs{} }
func (getMinionsFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return nil, returnerUnsupported("ret.get_minions")
}

// Register installs all ret-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		getJidFunc{},
		getFunFunc{},
		getJidsFunc{},
		getMinionsFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
