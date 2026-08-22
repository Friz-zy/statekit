// Package cmd implements Salt-compatible command execution functions.
//
// Reference: saltstack/salt/modules/cmdmod.py @ pinned revision
// (__virtualname__ = "cmd"). All subprocess execution flows through the
// central Runner; shell usage mirrors Salt's default shell behavior.
package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const defaultShell = "sh"

type RunArgs struct {
	Cmd     string   `statekit:"required"`
	Cwd     string   `statekit:"name=cwd"`
	Timeout int      `statekit:"name=timeout"` // seconds, matching Salt
	Shell   string   `statekit:"name=shell"`   // shell override; empty uses sh
	Env     []string `statekit:"name=env"`
	Runas   string   `statekit:"name=runas"`
}

func (a *RunArgs) timeoutDuration() time.Duration {
	if a.Timeout <= 0 {
		return 0
	}
	return time.Duration(a.Timeout) * time.Second
}

func (a *RunArgs) command() process.Command {
	return process.Command{
		Name:    a.Cmd,
		Dir:     a.Cwd,
		Env:     mergeEnv(a.Env),
		Timeout: a.timeoutDuration(),
		Shell:   true,
	}
}

// mergeEnv layers extra entries over the inherited environment like Salt.
func mergeEnv(extra []string) []string {
	if len(extra) == 0 {
		return nil
	}
	base := map[string]string{}
	for _, entry := range os.Environ() {
		if k, _, ok := strings.Cut(entry, "="); ok {
			base[k] = entry
		}
	}
	for _, entry := range extra {
		k, _, _ := strings.Cut(entry, "=")
		base[k] = entry
	}
	out := make([]string, 0, len(base))
	for _, entry := range base {
		out = append(out, entry)
	}
	return out
}

// validateRun rejects options StateKit intentionally does not implement.
func validateRun(a *RunArgs) error {
	if strings.TrimSpace(a.Cmd) == "" {
		return fmt.Errorf("command must not be empty")
	}
	if a.Runas != "" {
		// Intentional divergence (plan section 39): StateKit performs no
		// privilege escalation; use sudo externally.
		return fmt.Errorf("runas is not supported by statekit")
	}
	return nil
}

type runFunc struct{}

func (runFunc) Name() string { return "cmd.run" }
func (runFunc) Args() any    { return RunArgs{} }
func (runFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RunArgs)
	if err := validateRun(a); err != nil {
		return nil, err
	}
	res := rt.Runner.Run(ctx, a.command())
	if res.Err != nil {
		return nil, res.Err
	}
	return string(res.Stdout), nil
}

type RunAllArgs RunArgs

type runAllFunc struct{}

func (runAllFunc) Name() string { return "cmd.run_all" }
func (runAllFunc) Args() any    { return RunAllArgs{} }
func (runAllFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RunAllArgs)
	base := RunArgs(*a)
	if err := validateRun(&base); err != nil {
		return nil, err
	}
	res := rt.Runner.Run(ctx, base.command())
	ret := map[string]any{
		"retcode": res.ExitCode,
		"stdout":  string(res.Stdout),
		"stderr":  string(res.Stderr),
		"cmd":     base.command().RedactedString(),
	}
	if res.Err != nil {
		return ret, fmt.Errorf("command %q failed: %w", base.command().RedactedString(), res.Err)
	}
	return ret, nil
}

type runStdoutArgs RunArgs

type runStdoutFunc struct{}

func (runStdoutFunc) Name() string { return "cmd.run_stdout" }
func (runStdoutFunc) Args() any    { return runStdoutArgs{} }
func (runStdoutFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*runStdoutArgs)
	base := RunArgs(*a)
	if err := validateRun(&base); err != nil {
		return nil, err
	}
	res := rt.Runner.Run(ctx, base.command())
	if res.Err != nil {
		return nil, res.Err
	}
	return string(res.Stdout), nil
}

type retcodeArgs RunArgs

type retcodeFunc struct{}

func (retcodeFunc) Name() string { return "cmd.retcode" }
func (retcodeFunc) Args() any    { return retcodeArgs{} }
func (retcodeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*retcodeArgs)
	base := RunArgs(*a)
	if err := validateRun(&base); err != nil {
		return nil, err
	}
	res := rt.Runner.Run(ctx, base.command())
	if res.Err != nil && res.ExitCode == -1 {
		return nil, res.Err
	}
	return res.ExitCode, nil
}

type whichArgs struct {
	Name string `statekit:"required"`
}

type whichFunc struct{}

func (whichFunc) Name() string { return "cmd.which" }
func (whichFunc) Args() any    { return whichArgs{} }
func (whichFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*whichArgs)
	if path := whichBinary(a.Name); path != "" {
		return path, nil
	}
	return "", nil
}

// whichBinary walks PATH without spawning processes.
func whichBinary(name string) string {
	if name == "" || strings.ContainsRune(name, '/') {
		return ""
	}
	dirs := filepath.SplitList(os.Getenv("PATH"))
	for _, dir := range dirs {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate
		}
	}
	return ""
}

// Register installs all cmd-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		runFunc{}, runAllFunc{}, runStdoutFunc{}, retcodeFunc{}, whichFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
