// Package pyenv implements Salt's pyenv management surface: installation,
// python version lifecycle, and shim execution, over the central Runner.
//
// Reference: saltstack/salt/modules/pyenv.py @ pinned revision
// (references/salt.lock). Behavioral tests mapped from
// saltstack/tests/pytests/unit/modules/test_pyenv.py.
//
// Contract notes (init.md section 28):
//
//   - config.option resolves through optional delegates exactly like the
//     pkg families: absent pyenv.root keeps the /usr/local/pyenv and
//     ~user/.pyenv defaults, absent pyenv.build_env adds nothing.
//   - Upstream builds shell strings; StateKit splits them shlex-style for
//     python_shell=False paths. The `cd X && git pull` compounds run as
//     ["git","-C",X,"pull"] (documented equivalence), and do()'s
//     python_shell=True PATH expansion happens in-process instead of a
//     shell (documented divergence).
//   - list_ registers under its CLI-facing alias pyenv.list.
package pyenv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

var whichBin = func(name string) string { return lookPathBin(name) }

func lookPathBin(exe string) string {
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(dir + "/" + exe); err == nil {
			return dir + "/" + exe
		}
	}
	return ""
}

// configOption mirrors __salt__["config.option"] with the module defaults.
func configOption(rt *runtime.Runtime, key string, def any) any {
	if _, ok := rt.Exec.Get("config.option"); !ok {
		return def
	}
	res, err := rt.Exec.Call(context.Background(), rt, "config.option",
		map[string]any{"key": key})
	if err != nil || res == nil {
		return def
	}
	return res
}

// homeOf mirrors expanduser("~"+runas).
func homeOf(runas string) string {
	if runas == "" || runas == "root" {
		return "/root"
	}
	return "/home/" + runas
}

// pyenvPath mirrors _pyenv_path with expanduser semantics.
func pyenvPath(rt *runtime.Runtime, runas string) string {
	var path string
	if cfg := scalarString(configOption(rt, "pyenv.root", nil)); cfg != "" && cfg != "None" {
		path = cfg
	} else if runas == "" || runas == "root" {
		path = "/usr/local/pyenv"
	} else {
		path = "~" + runas + "/.pyenv"
	}
	if strings.HasPrefix(path, "~") {
		rest := strings.TrimPrefix(path, "~")
		if rest == "" {
			path = homeOf("")
		} else if strings.HasPrefix(rest, "/") {
			user := rest[1:]
			path = homeOf(user)
		} else {
			user := rest[:strings.IndexByte(rest, '/')]
			path = homeOf(user) + rest[len(user):]
		}
	}
	return path
}

func pyenvBin(rt *runtime.Runtime, runas string) string {
	return filepath.Join(pyenvPath(rt, runas), "bin", "pyenv")
}

// isInstalled mirrors is_installed via cmd.has_exec on the binary path.
func isInstalled(ctx context.Context, rt *runtime.Runtime, runas string) bool {
	bin := pyenvBin(rt, runas)
	if info, err := rt.FS.Stat(bin); err == nil && !info.IsDir() {
		return true
	}
	return whichBin(bin) != ""
}

type envResult struct {
	retcode int
	stdout  string
	stderr  string
}

// pyenvExec mirrors _pyenv_exec: PYENV_ROOT-prefixed binary invocation.
// The ret parameter receives the full result when non-nil (install_python
// needs stderr even on success).
func pyenvExec(ctx context.Context, rt *runtime.Runtime, command, argsStr, envStr, runas string, full bool) (*envResult, bool) {
	if !isInstalled(ctx, rt, runas) {
		return nil, false
	}
	bin := fmt.Sprintf("env PYENV_ROOT=%s %s", pyenvPath(rt, runas), pyenvBin(rt, runas))
	cmdline := strings.TrimSpace(bin + " " + command + " " + argsStr)
	res := rt.Runner.Run(ctx, runtime.Command(shellSplit(cmdline)...))
	exitCode := res.ExitCode
	if res.Err != nil {
		exitCode = -1
	}
	out := &envResult{retcode: exitCode, stdout: string(res.Stdout), stderr: string(res.Stderr)}
	if full {
		return out, true
	}
	if out.retcode == 0 {
		return out, true
	}
	return nil, false
}

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

var pythonPrefixRe = regexp.MustCompile(`^python-`)

// stripPythonPrefix mirrors re.sub(r"^python-", "", python).
func stripPythonPrefix(python string) string { return pythonPrefixRe.ReplaceAllString(python, "") }

type InstallArgs struct {
	Runas *string `statekit:"name=runas"`
	Path  *string `statekit:"name=path"`
}

type installFunc struct{}

func (installFunc) Name() string { return "pyenv.install" }
func (installFunc) Args() any    { return InstallArgs{} }

func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InstallArgs)
	runas := strOr(a.Runas, "")
	path := ""
	if a.Path != nil {
		path = *a.Path
	}
	if path == "" {
		path = pyenvPath(rt, runas)
	}
	if info, err := rt.FS.Stat(path); err == nil && info.IsDir() {
		return true, nil
	}
	retcode := gitRetcode(ctx, rt, []string{"git", "clone",
		"https://github.com/yyuu/pyenv.git", path})
	return retcode == 0, nil
}

type UpdateArgs struct {
	Runas *string `statekit:"name=runas"`
	Path  *string `statekit:"name=path"`
}

type updateFunc struct{}

func (updateFunc) Name() string { return "pyenv.update" }
func (updateFunc) Args() any    { return UpdateArgs{} }

func (updateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*UpdateArgs)
	runas := strOr(a.Runas, "")
	path := ""
	if a.Path != nil {
		path = *a.Path
	}
	if path == "" {
		path = pyenvPath(rt, runas)
	}
	// `cd {path} && git pull` runs as an equivalent git -C invocation.
	if info, err := rt.FS.Stat(path); err != nil || !info.IsDir() {
		return false, nil
	}
	retcode := gitRetcode(ctx, rt, []string{"git", "-C", path, "pull"})
	return retcode == 0, nil
}

func gitRetcode(ctx context.Context, rt *runtime.Runtime, argv []string) int {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return -1
	}
	return res.ExitCode
}

type IsInstalledArgs struct {
	Runas *string `statekit:"name=runas"`
}

type isInstalledFunc struct{}

func (isInstalledFunc) Name() string { return "pyenv.is_installed" }
func (isInstalledFunc) Args() any    { return IsInstalledArgs{} }
func (isInstalledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*IsInstalledArgs)
	return isInstalled(ctx, rt, strOr(a.Runas, "")), nil
}

type InstallPythonArgs struct {
	Python string  `statekit:"required,name=python"`
	Runas  *string `statekit:"name=runas"`
}

type installPythonFunc struct{}

func (installPythonFunc) Name() string { return "pyenv.install_python" }
func (installPythonFunc) Args() any    { return InstallPythonArgs{} }

func (installPythonFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InstallPythonArgs)
	runas := strOr(a.Runas, "")
	python := stripPythonPrefix(a.Python)

	var envList []string
	if rt.Facts != nil {
		switch rt.Facts.OS().Name {
		case "FreeBSD", "NetBSD", "OpenBSD":
			envList = append(envList, "MAKE=gmake")
		}
	}
	if buildEnv := scalarString(configOption(rt, "pyenv.build_env", nil)); buildEnv != "" && buildEnv != "None" {
		envList = append(envList, buildEnv)
	}
	envStr := strings.Join(envList, " ")

	ret, ok := pyenvExec(ctx, rt, "install", python, envStr, runas, true)
	if ok && ret.retcode == 0 {
		rehashRun(ctx, rt, runas)
		return ret.stderr, nil
	}
	uninstallRun(ctx, rt, python, runas)
	return false, nil
}

type UninstallPythonArgs struct {
	Python string  `statekit:"required,name=python"`
	Runas  *string `statekit:"name=runas"`
}

type uninstallPythonFunc struct{}

func (uninstallPythonFunc) Name() string { return "pyenv.uninstall_python" }
func (uninstallPythonFunc) Args() any    { return UninstallPythonArgs{} }
func (uninstallPythonFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*UninstallPythonArgs)
	python := stripPythonPrefix(a.Python)
	uninstallRun(ctx, rt, python, strOr(a.Runas, ""))
	return true, nil
}

func uninstallRun(ctx context.Context, rt *runtime.Runtime, python, runas string) {
	pyenvExec(ctx, rt, "uninstall", "--force "+python, "", runas, false)
}

type VersionsArgs struct {
	Runas *string `statekit:"name=runas"`
}

type versionsFunc struct{}

func (versionsFunc) Name() string { return "pyenv.versions" }
func (versionsFunc) Args() any    { return VersionsArgs{} }
func (versionsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*VersionsArgs)
	out, ok := pyenvExec(ctx, rt, "versions", "--bare", "", strOr(a.Runas, ""), false)
	if !ok {
		return []string{}, nil
	}
	return strings.Split(strings.TrimRight(out.stdout, "\n"), "\n"), nil
}

type DefaultArgs struct {
	Python *string `statekit:"name=python"`
	Runas  *string `statekit:"name=runas"`
}

type defaultFunc struct{}

func (defaultFunc) Name() string { return "pyenv.default" }
func (defaultFunc) Args() any    { return DefaultArgs{} }
func (defaultFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DefaultArgs)
	runas := strOr(a.Runas, "")
	if a.Python != nil && *a.Python != "" {
		pyenvExec(ctx, rt, "global", *a.Python, "", runas, false)
		return true, nil
	}
	out, ok := pyenvExec(ctx, rt, "global", "", "", runas, false)
	if !ok {
		return "", nil
	}
	return strings.TrimSpace(out.stdout), nil
}

type ListArgs struct {
	Runas *string `statekit:"name=runas"`
}

type listFunc struct{}

// Name resolves through Salt's __func_alias__ ("list_" -> "list").
func (listFunc) Name() string { return "pyenv.list" }
func (listFunc) Args() any    { return ListArgs{} }
func (listFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListArgs)
	out, ok := pyenvExec(ctx, rt, "install", "--list", "", strOr(a.Runas, ""), false)
	if !ok {
		return []string{}, nil
	}
	var ret []string
	for _, line := range strings.Split(out.stdout, "\n") {
		if line == "Available versions:" {
			continue
		}
		if strings.TrimRight(line, "\r") == "" && line == "" {
			continue
		}
		ret = append(ret, strings.TrimSpace(line))
	}
	return ret, nil
}

type RehashArgs struct {
	Runas *string `statekit:"name=runas"`
}

type rehashFunc struct{}

func (rehashFunc) Name() string { return "pyenv.rehash" }
func (rehashFunc) Args() any    { return RehashArgs{} }
func (rehashFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RehashArgs)
	rehashRun(ctx, rt, strOr(a.Runas, ""))
	return true, nil
}

func rehashRun(ctx context.Context, rt *runtime.Runtime, runas string) {
	pyenvExec(ctx, rt, "rehash", "", "", runas, false)
}

type DoArgs struct {
	Cmdline string  `statekit:"required,name=cmdline"`
	Runas   *string `statekit:"name=runas"`
}

type doFunc struct{}

func (doFunc) Name() string { return "pyenv.do" }
func (doFunc) Args() any    { return DoArgs{} }

func (doFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DoArgs)
	runas := strOr(a.Runas, "")
	shims := filepath.Join(pyenvPath(rt, runas), "shims")
	// Upstream composes `env PATH={shims}:$PATH {quoted cmdline}` behind
	// python_shell=True; StateKit expands $PATH in-process and passes the
	// whitespace-split tokens directly (documented divergence).
	argv := append([]string{"env",
		fmt.Sprintf("PATH=%s:%s", shims, os.Getenv("PATH"))},
		strings.Fields(a.Cmdline)...)
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	exitCode := res.ExitCode
	if res.Err != nil {
		exitCode = -1
	}
	if exitCode == 0 {
		rehashRun(ctx, rt, runas)
		return string(res.Stdout), nil
	}
	return false, nil
}

type DoWithPythonArgs struct {
	Python  string  `statekit:"required,name=python"`
	Cmdline string  `statekit:"required,name=cmdline"`
	Runas   *string `statekit:"name=runas"`
}

type doWithPythonFunc struct{}

func (doWithPythonFunc) Name() string { return "pyenv.do_with_python" }
func (doWithPythonFunc) Args() any    { return DoWithPythonArgs{} }
func (doWithPythonFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DoWithPythonArgs)
	cmdline := a.Cmdline
	if a.Python != "" {
		cmdline = fmt.Sprintf("PYENV_VERSION=%s %s", a.Python, a.Cmdline)
	}
	return doFunc{}.Execute(ctx, rt, &DoArgs{Cmdline: cmdline, Runas: a.Runas})
}

func strOr(s *string, def string) string {
	if s != nil {
		return *s
	}
	return def
}

// Register installs all pyenv execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		installFunc{},
		updateFunc{},
		isInstalledFunc{},
		installPythonFunc{},
		uninstallPythonFunc{},
		versionsFunc{},
		defaultFunc{},
		listFunc{},
		rehashFunc{},
		doFunc{},
		doWithPythonFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
