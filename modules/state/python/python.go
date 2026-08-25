// Package python implements Salt's python state functions: run and
// script, delegating to the registered python.* execution functions.
//
// Reference: saltstack/salt/states/python.py @ pinned revision.
package python

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execpython "github.com/friz-zy/statekit/modules/exec/python"
)

type runArgs struct {
	Name            string   `statekit:"required"`
	Args            any      `statekit:"name=args"`
	Cwd             *string  `statekit:"name=cwd"`
	Runas           *string  `statekit:"name=runas"`
	HideOutput      bool     `statekit:"name=hide_output"`
	IgnoreTimeout   bool     `statekit:"name=ignore_timeout"`
	SuccessRetcodes []int    `statekit:"name=success_retcodes"`
	SuccessStdout   []string `statekit:"name=success_stdout"`
	SuccessStderr   []string `statekit:"name=success_stderr"`
	Test            bool     `statekit:"name=test"`
}

type runFunc struct{}

func (runFunc) Name() string { return "python.run" }
func (runFunc) Args() any    { return runArgs{} }

func (runFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*runArgs)
	ret := result.New(a.Name, "", result.Bool(false), map[string]any{})

	if a.Test {
		ret.Result = nil
		ret.Comment = fmt.Sprintf("Python code %q would have been executed", a.Name)
		return ret
	}
	if a.Cwd != nil && *a.Cwd != "" {
		if info, err := rt.FS.Stat(*a.Cwd); err != nil || !info.IsDir() {
			ret.Comment = fmt.Sprintf("Desired working directory %q is not available", *a.Cwd)
			return ret
		}
	}

	cmdAll, err := rt.Exec.Call(ctx, rt, "python.run", &execpython.RunArgs{
		Command:         strPtr(a.Name),
		Args:            a.Args,
		Cwd:             a.Cwd,
		Runas:           a.Runas,
		HideOutput:      a.HideOutput,
		SuccessRetcodes: a.SuccessRetcodes,
		SuccessStdout:   a.SuccessStdout,
		SuccessStderr:   a.SuccessStderr,
	})
	if err != nil {
		ret.Comment = err.Error()
		return ret
	}
	dict := map[string]any{}
	switch d := cmdAll.(type) {
	case execpython.RunResult:
		dict = d
	case map[string]any:
		dict = d
	}
	ret.Changes = dict
	retcode, _ := dict["retcode"].(int)
	ret.Result = result.Bool(retcode == 0)
	ret.Comment = fmt.Sprintf("Python code %q run", a.Name)

	if a.IgnoreTimeout && retcode == 1 {
		if stdout, _ := dict["stdout"].(string); strings.Contains(stdout, "Timed out after") {
			ret.Changes["retcode"] = 0
			ret.Result = result.Bool(true)
		}
	}
	return ret
}

type scriptArgs struct {
	Name            string         `statekit:"required"`
	Source          *string        `statekit:"name=source"`
	Template        *string        `statekit:"name=template"`
	Cwd             *string        `statekit:"name=cwd"`
	Runas           *string        `statekit:"name=runas"`
	Context         map[string]any `statekit:"name=context"`
	Defaults        map[string]any `statekit:"name=defaults"`
	HideOutput      bool           `statekit:"name=hide_output"`
	SuccessRetcodes []int          `statekit:"name=success_retcodes"`
	SuccessStdout   []string       `statekit:"name=success_stdout"`
	SuccessStderr   []string       `statekit:"name=success_stderr"`
	Saltenv         *string        `statekit:"name=saltenv"`
	Test            bool           `statekit:"name=test"`
}

type scriptFunc struct{}

func (scriptFunc) Name() string { return "python.script" }
func (scriptFunc) Args() any    { return scriptArgs{} }

func (scriptFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*scriptArgs)
	ret := result.New(a.Name, "", result.Bool(false), map[string]any{})

	if a.Context != nil && len(a.Context) > 0 {
		// Typed decoding yields maps; the upstream non-dict guard text is
		// unreachable through structured input (documented).
	}
	source := a.Name
	if a.Source != nil {
		source = *a.Source
	}

	var scriptArgs any
	if parts := strings.SplitN(a.Name, " ", 2); len(parts) > 1 {
		scriptArgs = parts[1]
	}

	saltenv := "base"
	if a.Saltenv != nil {
		saltenv = *a.Saltenv
	}

	if a.Test {
		ret.Result = nil
		ret.Comment = fmt.Sprintf("Python script '%s' would have been executed", a.Name)
		return ret
	}
	if a.Cwd != nil && *a.Cwd != "" {
		if info, err := rt.FS.Stat(*a.Cwd); err != nil || !info.IsDir() {
			ret.Comment = fmt.Sprintf("Desired working directory %q is not available", *a.Cwd)
			return ret
		}
	}

	res, err := rt.Exec.Call(ctx, rt, "python.script", &execpython.ScriptArgs{
		Source:          source,
		Args:            scriptArgs,
		Cwd:             a.Cwd,
		Runas:           a.Runas,
		Template:        a.Template,
		Saltenv:         &saltenv,
		HideOutput:      a.HideOutput,
		SuccessRetcodes: a.SuccessRetcodes,
		SuccessStdout:   a.SuccessStdout,
		SuccessStderr:   a.SuccessStderr,
	})
	if err != nil {
		ret.Comment = err.Error()
		return ret
	}
	dict := res.(execpython.RunResult)
	ret.Changes = dict
	retcode, _ := dict["retcode"].(int)
	ret.Result = result.Bool(retcode == 0)
	if cacheErr, ok := dict["cache_error"].(bool); ok && cacheErr {
		ret.Comment = fmt.Sprintf("Unable to cache script %s from saltenv '%s'", source, saltenv)
	} else {
		ret.Comment = fmt.Sprintf("Python script '%s' run", a.Name)
	}
	return ret
}

func strPtr(s string) *string { return &s }

// Register installs all python state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{
		runFunc{},
		scriptFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
