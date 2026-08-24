// Package python implements Salt's python execution surface: run and
// script, executing snippets with a pinned interpreter over the central
// Runner.
//
// Reference: saltstack/salt/modules/python.py @ pinned revision
// (references/salt.lock).
//
// Contract notes (init.md section 28):
//
//   - Upstream targets sys.executable — the interpreter running the Salt
//     minion. StateKit is a single Go binary with no bundled interpreter,
//     so PythonExecutable resolves from PATH (python3, then python) and is
//     injectable for suites or deployments pinning an interpreter
//     (documented divergence).
//   - script's cp.cache_file accepts readable local absolute paths only;
//     remote and salt:// schemes surface UnsupportedError like the pkg
//     families. The template arm requires cp.get_template and surfaces
//     UnsupportedError until templating is scoped.
//   - runas stays accepted-but-single-user; ownership adjustments degrade.
package python

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type processResult = process.CommandResult

var scriptCounterN int64

func scriptCounter() int64 { return atomic.AddInt64(&scriptCounterN, 1) }

// pythonExecutable resolves the interpreter; injectable for suites.
var pythonExecutable = func() string {
	for _, name := range []string{"python3", "python"} {
		for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
			if dir == "" {
				continue
			}
			if _, err := os.Stat(dir + "/" + name); err == nil {
				return dir + "/" + name
			}
		}
	}
	return "python3"
}

var validProtoRe = func(path string) bool {
	return strings.HasPrefix(path, "salt://") ||
		strings.HasPrefix(path, "http://") ||
		strings.HasPrefix(path, "https://") ||
		strings.HasPrefix(path, "ftp://") ||
		strings.HasPrefix(path, "file://")
}

// shellSplit mirrors salt.utils.args.shlex_split for string args.
func shellSplit(cmd string) []string {
	var args []string
	var cur strings.Builder
	has := false
	inDouble := false
	inSingle := false
	escaped := false
	for _, c := range cmd {
		switch {
		case escaped:
			cur.WriteRune(c)
			escaped = false
		case c == '\\' && !inSingle && !inDouble:
			escaped = true
		case c == '"' && !inSingle:
			inDouble = !inDouble
			has = true
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			has = true
		case (c == ' ' || c == '\t') && !inSingle && !inDouble:
			if cur.Len() > 0 || has {
				args = append(args, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 || has {
		args = append(args, cur.String())
	}
	return args
}

type runResult map[string]any

func toRunResult(_ *runtime.Runtime, res processResult) runResult {
	exitCode := res.ExitCode
	if res.Err != nil {
		exitCode = -1
	}
	return runResult{
		"pid":     nil,
		"retcode": exitCode,
		"stdout":  string(res.Stdout),
		"stderr":  string(res.Stderr),
	}
}

func applySuccessOverrides(ret runResult, successRetcodes []int, successStdout, successStderr []string) {
	retcode := ret["retcode"].(int)
	if retcode != 0 {
		for _, code := range successRetcodes {
			if retcode == code {
				ret["retcode"] = 0
				retcode = 0
				break
			}
		}
	}
	stdout, _ := ret["stdout"].(string)
	stderr, _ := ret["stderr"].(string)
	if retcode != 0 {
		for _, needle := range successStdout {
			if needle != "" && strings.Contains(stdout, needle) {
				ret["retcode"] = 0
				break
			}
		}
	}
	if ret["retcode"].(int) != 0 {
		for _, needle := range successStderr {
			if needle != "" && strings.Contains(stderr, needle) {
				ret["retcode"] = 0
			}
		}
	}
}

func rstripOutput(ret runResult) {
	if s, ok := ret["stdout"].(string); ok {
		ret["stdout"] = strings.TrimRight(s, " \t\n\r")
	}
	if s, ok := ret["stderr"].(string); ok {
		ret["stderr"] = strings.TrimRight(s, " \t\n\r")
	}
}

type RunArgs struct {
	Command         *string        `statekit:"name=command"`
	Args            any            `statekit:"name=args"` // string or list
	Cwd             *string        `statekit:"name=cwd"`
	Stdin           *string        `statekit:"name=stdin"`
	Runas           *string        `statekit:"name=runas"`
	Group           *string        `statekit:"name=group"`
	Env             map[string]any `statekit:"name=env"`
	Rstrip          *bool          `statekit:"name=rstrip"`
	HideOutput      bool           `statekit:"name=hide_output"`
	SuccessRetcodes []int          `statekit:"name=success_retcodes"`
	SuccessStdout   []string       `statekit:"name=success_stdout"`
	SuccessStderr   []string       `statekit:"name=success_stderr"`
}

type runFunc struct{}

func (runFunc) Name() string { return "python.run" }
func (runFunc) Args() any    { return RunArgs{} }

func (runFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RunArgs)

	cmdList := []string{pythonExecutable()}
	if a.Command != nil {
		cmdList = append(cmdList, "-c", *a.Command)
	}
	var argItems []string
	switch v := a.Args.(type) {
	case nil:
	case string:
		argItems = shellSplit(v)
	case []string:
		argItems = v
	case []any:
		for _, item := range v {
			argItems = append(argItems, fmt.Sprintf("%v", item))
		}
	}
	cmdList = append(cmdList, argItems...)

	if len(cmdList) == 1 {
		return nil, fmt.Errorf("Must specify either 'command' or 'args'")
	}

	cwd := ""
	if a.Cwd != nil {
		cwd = *a.Cwd
	}
	var stdin []byte
	if a.Stdin != nil {
		stdin = []byte(*a.Stdin)
	}
	envArgs := buildEnvArgs(a.Env)

	cmd := runtime.Command(cmdList...)
	cmd.Dir = cwd
	cmd.Stdin = stdin
	cmd.Env = envArgs
	res := rt.Runner.Run(ctx, cmd)
	ret := toRunResult(rt, res)

	rstrip := true
	if a.Rstrip != nil {
		rstrip = *a.Rstrip
	}
	if rstrip {
		rstripOutput(ret)
	}
	applySuccessOverrides(ret, a.SuccessRetcodes, a.SuccessStdout, a.SuccessStderr)

	if a.HideOutput {
		ret["stdout"] = ""
		ret["stderr"] = ""
	}
	return ret, nil
}

type ScriptArgs struct {
	Source          string         `statekit:"required,name=source"`
	Args            any            `statekit:"name=args"`
	Cwd             *string        `statekit:"name=cwd"`
	Stdin           *string        `statekit:"name=stdin"`
	Runas           *string        `statekit:"name=runas"`
	Env             map[string]any `statekit:"name=env"`
	Template        *string        `statekit:"name=template"`
	Saltenv         *string        `statekit:"name=saltenv"`
	HideOutput      bool           `statekit:"name=hide_output"`
	SuccessRetcodes []int          `statekit:"name=success_retcodes"`
	SuccessStdout   []string       `statekit:"name=success_stdout"`
	SuccessStderr   []string       `statekit:"name=success_stderr"`
}

type scriptFunc struct{}

func (scriptFunc) Name() string { return "python.script" }
func (scriptFunc) Args() any    { return ScriptArgs{} }

// splitSourceEnv mirrors salt.utils.url.split_env(source)[0]: strips a
// trailing "?saltenv" designator.
func splitSourceEnv(source string) string {
	if idx := strings.LastIndex(source, "?"); idx >= 0 {
		return source[:idx]
	}
	return source
}

func (scriptFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ScriptArgs)
	cwd := "."
	if a.Cwd != nil && *a.Cwd != "" {
		cwd = *a.Cwd
	}

	if a.Template != nil && *a.Template != "" {
		return runResult{
			"pid": nil, "retcode": 1, "stdout": "", "stderr": "",
			"cache_error": true,
		}, &runtime.UnsupportedError{Kind: "function", Name: "cp.get_template"}
	}

	source := splitSourceEnv(a.Source)
	if validProtoRe(source) {
		return runResult{
			"pid": nil, "retcode": 1, "stdout": "", "stderr": "",
			"cache_error": true,
		}, &runtime.UnsupportedError{Kind: "function", Name: "cp.cache_file"}
	}

	ext := filepath.Ext(source)
	scriptPath := filepath.Join(cwd, fmt.Sprintf(".salt-script-%d%s", scriptCounter(), ext))
	cleanup := func() { rt.FS.Remove(scriptPath) }

	data, err := rt.FS.ReadFile(source)
	if err != nil {
		cleanup()
		return runResult{
			"pid": nil, "retcode": 1, "stdout": "", "stderr": "",
			"cache_error": true,
		}, nil
	}
	if werr := rt.FS.WriteFile(scriptPath, data, 0o755); werr != nil {
		return nil, werr
	}

	var argItems []string
	switch v := a.Args.(type) {
	case nil:
	case string:
		argItems = shellSplit(v)
	case []string:
		argItems = v
	case []any:
		for _, item := range v {
			argItems = append(argItems, fmt.Sprintf("%v", item))
		}
	}

	cmdList := append([]string{pythonExecutable(), scriptPath}, argItems...)
	var stdin []byte
	if a.Stdin != nil {
		stdin = []byte(*a.Stdin)
	}
	cmd := runtime.Command(cmdList...)
	cmd.Dir = cwd
	cmd.Stdin = stdin
	cmd.Env = buildEnvArgs(a.Env)
	res := rt.Runner.Run(ctx, cmd)
	ret := toRunResult(rt, res)

	cleanup()
	applySuccessOverrides(ret, a.SuccessRetcodes, a.SuccessStdout, a.SuccessStderr)

	if a.HideOutput {
		ret["stdout"] = ""
		ret["stderr"] = ""
	}
	return ret, nil
}

// Register installs all python execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		runFunc{},
		scriptFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// buildEnvArgs flattens the env dict into KEY=VALUE Runner entries.
func buildEnvArgs(env map[string]any) []string {
	if env == nil {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sortStrings(keys)
	var out []string
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s=%s", k, scalarString(env[k])))
	}
	return out
}

func sortStrings(items []string) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j] < items[j-1]; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

func scalarString(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	case int:
		return fmt.Sprintf("%d", x)
	}
	return fmt.Sprintf("%v", v)
}
