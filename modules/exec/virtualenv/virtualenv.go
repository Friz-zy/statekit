// Package virtualenv manages Python virtual environments via the
// virtualenv/venv toolchain, mirroring saltstack/salt/modules/
// virtualenv_mod.py @ pinned revision (references/salt.lock).
//
// Contract notes (init.md section 28):
//
//   - venv_bin resolution mirrors __pillar__/__opts__: an optional pillar
//     delegate first, then which_bin(["virtualenv","venv"]), then "venv".
//     The "venv" branch targets the interpreter behind the same injectable
//     hook as the python family (no bundled runtime — documented
//     divergence).
//   - The pip/setuptools bootstrap scripts fetch through cp.cache_file;
//     the https:// URLs surface UnsupportedError until the cp family lands,
//     so create(pip=True) only completes when the environment already
//     provides pip (documented boundary).
//   - get_* introspection functions embed Python source strings verbatim,
//     including the pkg_resources/importlib.metadata split and the raw
//     '{}' interpolation for resources (guarded by safe_py_code).
package virtualenv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func atomicAdd(v *int64) int64 { return atomic.AddInt64(v, 1) }

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

// pythonExecutable resolves the interpreter for the "venv" branch; same
// injectable semantics as the python family.
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

// pillarGet resolves the optional pillar delegate for venv_bin.
func pillarGet(rt *runtime.Runtime, key string) any {
	if _, ok := rt.Exec.Get("pillar.get"); !ok {
		return nil
	}
	res, err := rt.Exec.Call(context.Background(), rt, "pillar.get",
		map[string]any{"key": key})
	if err != nil {
		return nil
	}
	return res
}

// defaultVenvBin mirrors __opts__["venv_bin"] construction.
func defaultVenvBin() string {
	if bin := whichBin("virtualenv"); bin != "" {
		return "virtualenv"
	}
	if bin := whichBin("venv"); bin != "" {
		return "venv"
	}
	return "venv"
}

func resolveVenvBin(rt *runtime.Runtime, explicit string) string {
	if explicit != "" {
		return explicit
	}
	if pv := scalarString(pillarGet(rt, "venv_bin")); pv != "" && pv != "None" {
		return pv
	}
	return defaultVenvBin()
}

// --- shared rendering helpers ---------------------------------------------------

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
	case []int:
		parts := make([]string, 0, len(x))
		for _, item := range x {
			parts = append(parts, strconv.Itoa(item))
		}
		return "(" + strings.Join(parts, ", ") + ")"
	}
	return fmt.Sprintf("%v", v)
}

// pyRepr renders a Go string like Python repr() (single quotes).
func pyRepr(s string) string {
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `'`, `\'`)
	return "'" + escaped + "'"
}

// pyDictRepr renders a cmd.run_all-shaped dict like "{}".format(ret) does
// upstream, for embedding inside error text.
func pyDictRepr(ret map[string]any) string {
	order := []string{"pid", "retcode", "stdout", "stderr"}
	parts := make([]string, 0, len(order))
	for _, key := range order {
		val, ok := ret[key]
		if !ok {
			continue
		}
		rendered := scalarString(val)
		if s, isStr := val.(string); isStr {
			rendered = pyRepr(s)
		}
		parts = append(parts, fmt.Sprintf("%s: %s", pyRepr(key), rendered))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func pyArgvRepr(argv []string) string {
	quoted := make([]string, 0, len(argv))
	for _, arg := range argv {
		q := arg
		if strings.Contains(q, `'`) && !strings.Contains(q, `"`) {
			q = `"` + q + `"`
		} else {
			q = "'" + strings.ReplaceAll(q, `\`, `\\`) + "'"
		}
		quoted = append(quoted, q)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func runAll(ctx context.Context, rt *runtime.Runtime, argv []string, env []string) map[string]any {
	cmd := runtime.Command(argv...)
	cmd.Env = env
	res := rt.Runner.Run(ctx, cmd)
	exitCode := res.ExitCode
	if res.Err != nil {
		exitCode = -1
	}
	return map[string]any{
		"pid":     nil,
		"retcode": exitCode,
		"stdout":  string(res.Stdout),
		"stderr":  string(res.Stderr),
	}
}

// --- virtualenv_ver -----------------------------------------------------------

var versionTokenRe = regexp.MustCompile(`^\d.\d*`)
var rcSuffixRe = regexp.MustCompile(`(rc|\+ds).*$`)

// virtualenvVer mirrors virtualenv_ver: the console arm parses the first
// version-looking token out of `--version` output.
func virtualenvVer(ctx context.Context, rt *runtime.Runtime, venvBin, user string, env map[string]any) ([]int, error) {
	versionCmd := []string{venvBin, "--version"}
	ret := runAll(ctx, rt, versionCmd, buildEnvArgs(env))
	stdout, _ := ret["stdout"].(string)
	if ret["retcode"].(int) > 0 || strings.TrimSpace(stdout) == "" {
		return nil, fmt.Errorf(
			"Unable to get the virtualenv version output using '%s'. Returned data: %s",
			pyArgvRepr(versionCmd), pyDictRepr(ret))
	}
	version := ""
	for _, token := range strings.Fields(strings.TrimSpace(stdout)) {
		if versionTokenRe.MatchString(token) {
			version += token
		}
	}
	stripped := rcSuffixRe.ReplaceAllString(version, "")
	var info []int
	for _, part := range strings.Split(stripped, ".") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("could not parse virtualenv version %q", version)
		}
		info = append(info, n)
	}
	return info, nil
}

// compareVersions mirrors tuple ordering for parsed version slices.
func compareVersions(a, b []int) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// --- create ---------------------------------------------------------------------

type CreateArgs struct {
	Path               string         `statekit:"required,name=path"`
	VenvBin            *string        `statekit:"name=venv_bin"`
	SystemSitePackages bool           `statekit:"name=system_site_packages"`
	Distribute         bool           `statekit:"name=distribute"`
	Clear              bool           `statekit:"name=clear"`
	Python             *string        `statekit:"name=python"`
	ExtraSearchDir     *string        `statekit:"name=extra_search_dir"`
	NeverDownload      *bool          `statekit:"name=never_download"`
	Prompt             *string        `statekit:"name=prompt"`
	Pip                bool           `statekit:"name=pip"`
	Symlinks           *bool          `statekit:"name=symlinks"`
	Upgrade            *bool          `statekit:"name=upgrade"`
	User               *string        `statekit:"name=user"`
	Saltenv            string         `statekit:"name=saltenv"`
	Env                map[string]any `statekit:"name=env"`
}

type createFunc struct{}

func (createFunc) Name() string { return "virtualenv.create" }
func (createFunc) Args() any    { return CreateArgs{} }

func (createFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CreateArgs)
	saltenv := a.Saltenv
	if saltenv == "" {
		saltenv = "base"
	}
	user := ""
	if a.User != nil {
		user = *a.User
	}

	venvBin := resolveVenvBin(rt, strOr(a.VenvBin))

	var cmd []string
	if venvBin == "venv" {
		cmd = []string{pythonExecutable(), "-m", "venv"}
	} else {
		cmd = []string{venvBin}
	}

	isVenv := strings.Contains(venvBin, "venv")
	if !isVenv {
		// virtualenv-only option guards.
		if a.Upgrade != nil {
			return nil, fmt.Errorf(
				"The `upgrade`(`--upgrade`) option is not supported by '%s'", venvBin)
		} else if a.Symlinks != nil {
			return nil, fmt.Errorf(
				"The `symlinks`(`--symlinks`) option is not supported by '%s'", venvBin)
		}

		versionInfo, err := virtualenvVer(ctx, rt, venvBin, user, a.Env)
		if err != nil {
			return nil, err
		}

		if a.Distribute {
			if compareVersions(versionInfo, []int{1, 10}) >= 0 {
				// Deprecated upstream; no flag emitted.
			} else {
				cmd = append(cmd, "--distribute")
			}
		}
		if a.Python != nil && strings.TrimSpace(*a.Python) != "" {
			if !pythonResolves(rt, *a.Python) {
				return nil, fmt.Errorf("Cannot find requested python (%s).", *a.Python)
			}
			cmd = append(cmd, "--python="+*a.Python)
		}
		if a.ExtraSearchDir != nil {
			var entries []string
			if strings.TrimSpace(*a.ExtraSearchDir) != "" {
				for _, e := range strings.Split(*a.ExtraSearchDir, ",") {
					entries = append(entries, strings.TrimSpace(e))
				}
			}
			for _, entry := range entries {
				cmd = append(cmd, "--extra-search-dir="+entry)
			}
		}
		if a.NeverDownload != nil && *a.NeverDownload {
			if compareVersions([]int{1, 10}, versionInfo) <= 0 &&
				compareVersions(versionInfo, []int{14, 0, 0}) < 0 {
				// Deprecated window; no flag emitted.
			} else {
				cmd = append(cmd, "--never-download")
			}
		} else if a.NeverDownload != nil && !*a.NeverDownload &&
			compareVersions(versionInfo, []int{20, 0}) >= 0 {
			cmd = append(cmd, "--download")
		}
		if a.Prompt != nil && strings.TrimSpace(*a.Prompt) != "" {
			cmd = append(cmd, fmt.Sprintf("--prompt='%s'", *a.Prompt))
		}
	} else {
		// venv-only option guards.
		if a.Python != nil && strings.TrimSpace(*a.Python) != "" {
			return nil, fmt.Errorf(
				"The `python`(`--python`) option is not supported by '%s'", venvBin)
		} else if a.ExtraSearchDir != nil && strings.TrimSpace(*a.ExtraSearchDir) != "" {
			return nil, fmt.Errorf(
				"The `extra_search_dir`(`--extra-search-dir`) option is not "+
					"supported by '%s'", venvBin)
		} else if a.NeverDownload != nil {
			return nil, fmt.Errorf(
				"The `never_download`(`--never-download`) option is not "+
					"supported by '%s'", venvBin)
		} else if a.Prompt != nil && strings.TrimSpace(*a.Prompt) != "" {
			return nil, fmt.Errorf(
				"The `prompt`(`--prompt`) option is not supported by '%s'", venvBin)
		}

		if a.Upgrade != nil && *a.Upgrade {
			cmd = append(cmd, "--upgrade")
		}
		if a.Symlinks != nil && *a.Symlinks {
			cmd = append(cmd, "--symlinks")
		}
	}

	// Common options.
	if a.Clear {
		cmd = append(cmd, "--clear")
	}
	if a.SystemSitePackages {
		cmd = append(cmd, "--system-site-packages")
	}
	cmd = append(cmd, a.Path)

	ret := runAll(ctx, rt, cmd, buildEnvArgs(a.Env))
	if ret["retcode"].(int) != 0 {
		return ret, nil
	}

	venvPython := filepath.Join(a.Path, "bin", "python")
	venvPip := filepath.Join(a.Path, "bin", "pip")
	venvSetuptools := filepath.Join(a.Path, "bin", "easy_install")

	// Bootstrap scripts fetch through cp.cache_file: the https URLs surface
	// UnsupportedError under StateKit's local-only cache stand-in.
	if (a.Pip || a.Distribute) && !fsExists(rt, venvSetuptools) {
		if _, err := installScript(ctx, rt,
			"https://bootstrap.pypa.io/ez_setup.py", a.Path, venvPython, user, saltenv, a.Env); err != nil {
			return nil, err
		}
	}

	if ret["retcode"].(int) != 0 {
		return ret, nil
	}

	if a.Pip && !fsExists(rt, venvPip) {
		pipRet, err := installScript(ctx, rt,
			"https://bootstrap.pypa.io/get-pip.py", a.Path, venvPython, user, saltenv, a.Env)
		if err != nil {
			return nil, err
		}
		baseStdout, _ := ret["stdout"].(string)
		baseStderr, _ := ret["stderr"].(string)
		ret["retcode"] = pipRet.retcode
		ret["stdout"] = strings.TrimRight(baseStdout+"\n"+pipRet.stdout, "\n")
		ret["stderr"] = strings.TrimRight(baseStderr+"\n"+pipRet.stderr, "\n")
	}

	return ret, nil
}

func fsExists(rt *runtime.Runtime, path string) bool {
	info, err := rt.FS.Stat(path)
	return err == nil && !info.IsDir()
}

// pythonResolves mirrors shutil.which for the --python guard: separator-
// bearing paths resolve against the filesystem, bare names walk PATH.
func pythonResolves(rt *runtime.Runtime, name string) bool {
	if strings.ContainsRune(name, '/') {
		return fsExists(rt, name)
	}
	return whichBin(name) != ""
}

// installScript mirrors _install_script minus the chown/chmod ownership
// adjustments (single-user model): the fetched script runs with
// VIRTUAL_ENV set and is removed afterwards. Remote sources hit the
// cp.cache_file boundary here.
func installScript(ctx context.Context, rt *runtime.Runtime, source, cwd, python, user, saltenv string, env map[string]any) (*envResult, error) {
	if validProto(source) {
		return nil, &runtime.UnsupportedError{Kind: "function", Name: "cp.cache_file"}
	}
	data, err := rt.FS.ReadFile(source)
	if err != nil {
		return nil, err
	}
	tmpPath := filepath.Join(cwd, fmt.Sprintf(".salt-bootstrap-%d.py", scriptCounter()))
	if werr := rt.FS.WriteFile(tmpPath, data, 0o500); werr != nil {
		return nil, werr
	}
	defer rt.FS.Remove(tmpPath)

	mergedEnv := buildEnvArgs(env)
	mergedEnv = append(mergedEnv, "VIRTUAL_ENV="+cwd)
	res := rt.Runner.Run(ctx, func() process.Command {
		c := runtime.Command(python, tmpPath)
		c.Dir = cwd
		c.Env = mergedEnv
		return c
	}())
	exitCode := res.ExitCode
	if res.Err != nil {
		exitCode = -1
	}
	return &envResult{retcode: exitCode, stdout: string(res.Stdout), stderr: string(res.Stderr)}, nil
}

var validProtoRe = regexp.MustCompile(`^(?:salt|https?|ftp|file)://`)

func validProto(s string) bool { return validProtoRe.MatchString(s) }

var scriptCounterN int64

func scriptCounter() int64 { return atomicAdd(&scriptCounterN) }

// --- introspection -----------------------------------------------------------------

type envResult struct {
	retcode int
	stdout  string
	stderr  string
}

// verifyVirtualenv mirrors _verify_virtualenv.
func verifyVirtualenv(rt *runtime.Runtime, venvPath string) (string, error) {
	binPath := filepath.Join(venvPath, "bin", "python")
	if !fsExists(rt, binPath) {
		return "", fmt.Errorf(
			"Path '%s' does not appear to be a virtualenv: '%s' not found.", venvPath, binPath)
	}
	return binPath, nil
}

// safePyCode mirrors salt.utils.verify.safe_py_code.
func safePyCode(code string) bool {
	for _, bad := range []string{"import", ";", "subprocess", "eval", "open", "file", "exec", "input"} {
		if strings.Contains(code, bad) {
			return false
		}
	}
	return true
}

func verifySafePyCode(args ...string) error {
	for _, arg := range args {
		if !safePyCode(arg) {
			return fmt.Errorf("Unsafe python code detected in '%s'", arg)
		}
	}
	return nil
}

type VirtualenvVerArgs struct {
	VenvBin string  `statekit:"required,name=venv_bin"`
	User    *string `statekit:"name=user"`
}

type virtualenvVerFunc struct{}

func (virtualenvVerFunc) Name() string { return "virtualenv.virtualenv_ver" }
func (virtualenvVerFunc) Args() any    { return VirtualenvVerArgs{} }
func (virtualenvVerFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*VirtualenvVerArgs)
	user := ""
	if a.User != nil {
		user = *a.User
	}
	return virtualenvVer(ctx, rt, a.VenvBin, user, nil)
}

type GetSitePackagesArgs struct {
	Venv string `statekit:"required,name=venv"`
}

type getSitePackagesFunc struct{}

func (getSitePackagesFunc) Name() string { return "virtualenv.get_site_packages" }
func (getSitePackagesFunc) Args() any    { return GetSitePackagesArgs{} }
func (getSitePackagesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetSitePackagesArgs)
	binPath, err := verifyVirtualenv(rt, a.Venv)
	if err != nil {
		return nil, err
	}
	ret := execCode(ctx, rt, binPath,
		`import sysconfig; print(sysconfig.get_path("purelib"))`)
	if ret.retcode != 0 {
		return nil, fmt.Errorf("%s\n%s", ret.stdout, ret.stderr)
	}
	return ret.stdout, nil
}

type GetDistributionPathArgs struct {
	Venv         string `statekit:"required,name=venv"`
	Distribution string `statekit:"required,name=distribution"`
}

type getDistributionPathFunc struct{}

func (getDistributionPathFunc) Name() string { return "virtualenv.get_distribution_path" }
func (getDistributionPathFunc) Args() any    { return GetDistributionPathArgs{} }
func (getDistributionPathFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetDistributionPathArgs)
	if err := verifySafePyCode(a.Distribution); err != nil {
		return nil, err
	}
	binPath, err := verifyVirtualenv(rt, a.Venv)
	if err != nil {
		return nil, err
	}
	distRepr := pyRepr(a.Distribution)
	code := fmt.Sprintf(`import sys
if sys.version_info >= (3, 12):
    import importlib.metadata as _im
    import sysconfig

    _im.distribution(%s)
    print(sysconfig.get_path("purelib"))
else:
    import pkg_resources

    print(pkg_resources.get_distribution(%s).location)
`, distRepr, distRepr)
	ret := execCode(ctx, rt, binPath, code)
	if ret.retcode != 0 {
		return nil, fmt.Errorf("%s\n%s", ret.stdout, ret.stderr)
	}
	return ret.stdout, nil
}

type GetResourceArgs struct {
	Venv     string  `statekit:"required,name=venv"`
	Package  *string `statekit:"name=package"`
	Resource *string `statekit:"name=resource"`
}

type getResourcePathFunc struct{}

func (getResourcePathFunc) Name() string { return "virtualenv.get_resource_path" }
func (getResourcePathFunc) Args() any    { return GetResourceArgs{} }
func (getResourcePathFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetResourceArgs)
	pkg := strOr(a.Package)
	res := strOr(a.Resource)
	if err := verifySafePyCode(pkg, res); err != nil {
		return nil, err
	}
	binPath, err := verifyVirtualenv(rt, a.Venv)
	if err != nil {
		return nil, err
	}
	code := fmt.Sprintf("import pkg_resources; "+
		"print(pkg_resources.resource_filename('%s', '%s'))", pkg, res)
	ret := execCode(ctx, rt, binPath, code)
	if ret.retcode != 0 {
		return nil, fmt.Errorf("%s\n%s", ret.stdout, ret.stderr)
	}
	return ret.stdout, nil
}

type getResourceContentFunc struct{}

func (getResourceContentFunc) Name() string { return "virtualenv.get_resource_content" }
func (getResourceContentFunc) Args() any    { return GetResourceArgs{} }
func (getResourceContentFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetResourceArgs)
	pkg := strOr(a.Package)
	res := strOr(a.Resource)
	if err := verifySafePyCode(pkg, res); err != nil {
		return nil, err
	}
	binPath, err := verifyVirtualenv(rt, a.Venv)
	if err != nil {
		return nil, err
	}
	code := fmt.Sprintf("import pkg_resources; print(pkg_resources.resource_string('%s', '%s'))",
		pkg, res)
	ret := execCode(ctx, rt, binPath, code)
	if ret.retcode != 0 {
		return nil, fmt.Errorf("%s\n%s", ret.stdout, ret.stderr)
	}
	return ret.stdout, nil
}

// execCode mirrors cmd.exec_code_all over the venv interpreter.
func execCode(ctx context.Context, rt *runtime.Runtime, binPath, code string) envResult {
	res := rt.Runner.Run(ctx, runtime.Command(binPath, "-c", code))
	exitCode := res.ExitCode
	if res.Err != nil {
		exitCode = -1
	}
	return envResult{retcode: exitCode, stdout: string(res.Stdout), stderr: string(res.Stderr)}
}

func strOr(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

// Register installs all virtualenv-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		createFunc{},
		virtualenvVerFunc{},
		getSitePackagesFunc{},
		getDistributionPathFunc{},
		getResourcePathFunc{},
		getResourceContentFunc{},
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
