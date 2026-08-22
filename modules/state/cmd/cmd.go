// Package cmd implements the Salt-compatible cmd.run state function.
//
// Reference: saltstack/salt/states/cmd.py @ pinned revision. The command
// runs unless every `creates` target already exists; execution results are
// reported in changes like Salt ({retcode, stdout, stderr}).
package cmd

import (
	"context"
	"fmt"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execcmd "github.com/friz-zy/statekit/modules/exec/cmd"
)

type runArgs struct {
	Name    string   `statekit:"required"`
	Cwd     string   `statekit:"name=cwd"`
	Creates []string `statekit:"name=creates"`
	Timeout int      `statekit:"name=timeout"`
	Test    bool     `statekit:"name=test"`
}

type runFunc struct{}

func (runFunc) Name() string { return "cmd.run" }
func (runFunc) Args() any    { return runArgs{} }
func (runFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*runArgs)

	for _, target := range a.Creates {
		if _, err := rt.FS.Stat(target); err == nil {
			return result.Success(a.Name,
				fmt.Sprintf("The file %s exists, so the command was not run", target))
		}
	}

	if a.Test {
		return result.TestPending(a.Name, "Command would be executed", map[string]any{
			"cmd": a.Name,
		})
	}

	value, err := rt.Exec.Call(ctx, rt, "cmd.run_all", &execcmd.RunAllArgs{
		Cmd: a.Name, Cwd: a.Cwd, Timeout: a.Timeout,
	})
	ret, _ := value.(map[string]any)
	retcode := -1
	if ret != nil {
		if code, ok := ret["retcode"].(int); ok {
			retcode = code
		}
	}
	changes := map[string]any{
		"cmd":     a.Name,
		"retcode": retcode,
		"stdout":  ret["stdout"],
		"stderr":  ret["stderr"],
	}
	if err != nil || retcode != 0 {
		comment := fmt.Sprintf("Command %q failed", a.Name)
		if err != nil {
			comment = err.Error()
		}
		return result.New(a.Name, comment, result.Bool(false), changes)
	}
	return result.New(a.Name, "", result.Bool(true), changes)
}

// Register installs all cmd-module state functions.
func Register(reg *runtime.StateRegistry) error {
	return reg.Register(runFunc{})
}
