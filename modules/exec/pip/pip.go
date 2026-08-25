// Package pip wraps the standard pip CLI, mirroring
// saltstack/salt/modules/pip.py @ pinned revision (references/salt.lock).
//
// Contract notes (init.md section 28):
//
//   - Without bin_env the upstream bundled-app branch does not apply to
//     StateKit (not a bundled Salt distribution); the currently-running
//     interpreter degrades to the pythonExecutable hook like the python
//     family (documented divergence).
//   - The user-scoped requirements tempdir copying is not reproduced:
//     StateKit executes single-user, so requirements pass straight through
//     (documented divergence). salt:// requirements surface the cp
//     boundary via UnsupportedError until the cp family lands.
//   - Version lookups are memoized per bin_env exactly like __context__
//     ("pip.version[.bin_env]"), cleared on mutating calls.
//   - --disable-pip-version-check placements follow issue #68214 fixes.
package pip

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/friz-zy/statekit/internal/runtime"
)

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

var validProtoRe = regexp.MustCompile(`^(?:https?|ftp|file)://`)

func urlValidate(link string) bool { return validProtoRe.MatchString(link) }

// --- version memoization -------------------------------------------------------

var (
	versionCacheMu sync.Mutex
	versionCache   = map[string]string{}
)

func clearContext(binEnv string) {
	versionCacheMu.Lock()
	defer versionCacheMu.Unlock()
	key := "pip.version"
	if binEnv != "" {
		key = "pip.version." + binEnv
	}
	delete(versionCache, key)
}

// --- binary resolution -----------------------------------------------------------

// getPipBin mirrors _get_pip_bin over the injectable filesystem view.
func getPipBin(rt *runtime.Runtime, binEnv string) ([]string, error) {
	pythonBin := "python"

	executable := func(path string) bool {
		info, err := rt.FS.Stat(path)
		return err == nil && !info.IsDir() && info.Mode().Perm()&0o100 != 0
	}

	if binEnv == "" {
		return []string{pythonExecutable(), "-m", "pip"}, nil
	}

	if info, err := rt.FS.Stat(binEnv); err == nil && info.IsDir() {
		for _, candidate := range []string{
			filepath.Join(binEnv, pythonBin),
			filepath.Join(binEnv, "bin", pythonBin),
			filepath.Join(binEnv, "Scripts", pythonBin),
		} {
			if executable(candidate) {
				return []string{filepath.Clean(candidate), "-m", "pip"}, nil
			}
		}
		bindir := filepath.Join(binEnv, "bin")
		if entries, derr := rt.FS.ReadDir(bindir); derr == nil {
			pyRe := regexp.MustCompile(`^python(\d+(\.\d+)?)?$`)
			type ranked struct {
				rank        int
				entry, full string
			}
			var rankedList []ranked
			names := make([]string, 0, len(entries))
			for _, entry := range entries {
				names = append(names, entry.Name())
			}
			sort.Strings(names)
			for _, entry := range names {
				if !pyRe.MatchString(entry) {
					continue
				}
				full := filepath.Join(bindir, entry)
				if executable(full) {
					rank := 2
					switch entry {
					case "python":
						rank = 0
					case "python3":
						rank = 1
					}
					rankedList = append(rankedList, ranked{rank, entry, full})
				}
			}
			sort.Slice(rankedList, func(i, j int) bool {
				if rankedList[i].rank != rankedList[j].rank {
					return rankedList[i].rank < rankedList[j].rank
				}
				return rankedList[i].entry < rankedList[j].entry
			})
			if len(rankedList) > 0 {
				return []string{filepath.Clean(rankedList[0].full), "-m", "pip"}, nil
			}
		}
		return nil, fmt.Errorf("Could not find a pip binary in virtualenv %s", binEnv)
	}

	info, err := rt.FS.Stat(binEnv)
	if err == nil && !info.IsDir() && info.Mode().Perm()&0o100 != 0 {
		if strings.Contains(filepath.Base(binEnv), "python") {
			return []string{filepath.Clean(binEnv), "-m", "pip"}, nil
		}
		return []string{filepath.Clean(binEnv)}, nil
	}
	if err == nil && !info.IsDir() {
		return nil, fmt.Errorf("Could not find a pip binary within %s", binEnv)
	}
	return nil, fmt.Errorf("Access denied to %s, could not find a pip binary", binEnv)
}

// --- version ----------------------------------------------------------------------

type VersionArgs struct {
	BinEnv *string `statekit:"name=bin_env"`
	Cwd    *string `statekit:"name=cwd"`
	User   *string `statekit:"name=user"`
}

type versionFunc struct{}

func (versionFunc) Name() string { return "pip.version" }
func (versionFunc) Args() any    { return VersionArgs{} }

func (versionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*VersionArgs)
	binEnv := strOr(a.BinEnv)
	cwd := strOr(a.Cwd)
	v, err := pipVersion(ctx, rt, binEnv, cwd, strOr(a.User))
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}
	return *v, nil
}

// pipVersion mirrors version() including the context memoization.
func pipVersion(ctx context.Context, rt *runtime.Runtime, binEnv, cwd, user string) (*string, error) {
	contextkey := "pip.version"
	if binEnv != "" {
		contextkey = "pip.version." + binEnv
	}
	versionCacheMu.Lock()
	if cached, ok := versionCache[contextkey]; ok {
		versionCacheMu.Unlock()
		val := cached
		return &val, nil
	}
	versionCacheMu.Unlock()

	cmd, err := getPipBin(rt, binEnv)
	if err != nil {
		return nil, err
	}
	cmd = append(cmd, "--version")
	res := runCmd(ctx, rt, cmd, cwd, nil, user)
	if res.retcode != 0 {
		return nil, fmt.Errorf("Could not find a `pip` binary")
	}
	m := pipVersionLineRe.FindStringSubmatch(res.stdout)
	var out *string
	if m != nil {
		out = &m[1]
	}
	versionCacheMu.Lock()
	versionCache[contextkey] = derefOrEmpty(out)
	versionCacheMu.Unlock()
	return out, nil
}

var pipVersionLineRe = regexp.MustCompile(`^pip (\S+)`)

func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// compareVersions mirrors salt.utils.versions.compare for dotted versions.
func compareVersions(ver1, oper, ver2 string) int {
	cmp := dottedCompare(ver1, ver2)
	switch oper {
	case "<":
		return boolToInt(cmp < 0)
	case "<=":
		return boolToInt(cmp <= 0)
	case ">":
		return boolToInt(cmp > 0)
	case ">=":
		return boolToInt(cmp >= 0)
	case "==":
		return boolToInt(cmp == 0)
	}
	return 0
}

func dottedCompare(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		ai, bi := 0, 0
		if i < len(as) {
			ai, _ = strconv.Atoi(strings.TrimSpace(as[i]))
		}
		if i < len(bs) {
			bi, _ = strconv.Atoi(strings.TrimSpace(bs[i]))
		}
		if ai != bi {
			if ai < bi {
				return -1
			}
			return 1
		}
	}
	return 0
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// normalize mirrors normalize(): PEP 503 name normalization.
func normalize(name string) string {
	re := regexp.MustCompile(`[-_.]+`)
	return strings.ToLower(re.ReplaceAllString(name, "-"))
}

func formatEnvVars(envVars map[string]any) map[string]any {
	ret := map[string]any{}
	for k, v := range envVars {
		ret[k] = scalarString(v)
	}
	return ret
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

type envResult struct {
	retcode int
	stdout  string
	stderr  string
}

func strOr(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

func strPtr(s string) *string { return &s }

func fsExists(rt *runtime.Runtime, path string) bool {
	info, err := rt.FS.Stat(path)
	return err == nil && !info.IsDir()
}

func runCmd(ctx context.Context, rt *runtime.Runtime, argv []string, cwd string, env []string, runas string) envResult {
	cmd := runtime.Command(argv...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	cmd.Env = env
	res := rt.Runner.Run(ctx, cmd)
	exitCode := res.ExitCode
	if res.Err != nil {
		exitCode = -1
	}
	return envResult{retcode: exitCode, stdout: string(res.Stdout), stderr: string(res.Stderr)}
}

func buildEnvArgs(env map[string]any) []string {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		out = append(out, k+"="+scalarString(env[k]))
	}
	return out
}

// --- requirements -------------------------------------------------------------------

var (
	reqsCommentRe  = regexp.MustCompile(`(?:^|\s+)#.*$`)
	reqsChainRe    = regexp.MustCompile(`(?:-r\s|--requirement[=\s])(.*)\n?`)
	eggMatchRe     = regexp.MustCompile(`(?:#|#.*?&)egg=([^&]*)`)
	pipVersionLine = regexp.MustCompile(`^pip (\S+)`)
)

// findReq mirrors _find_req: child -r/--requirement links inside a file.
func findReq(rt *runtime.Runtime, link string) []string {
	data, err := rt.FS.ReadFile(link)
	if err != nil {
		return nil
	}
	content := reqsCommentRe.ReplaceAllString(string(data), "")
	matches := reqsChainRe.FindAllStringSubmatch(content, -1)
	basePath := filepath.Dir(link)
	var out []string
	for _, m := range matches {
		out = append(out, filepath.Join(basePath, strings.TrimSpace(m[1])))
	}
	return out
}

// resolveRequirementsChain mirrors _resolve_requirements_chain.
func resolveRequirementsChain(rt *runtime.Runtime, requirements []string) []string {
	var chain []string
	for _, reqFile := range requirements {
		chain = append(chain, reqFile)
		chain = append(chain, resolveRequirementsChain(rt, findReq(rt, reqFile))...)
	}
	return chain
}

// processRequirements mirrors _process_requirements for the single-user
// model: no tempdir copying, salt:// surfaces the cp boundary.
func processRequirements(
	ctx context.Context,
	rt *runtime.Runtime,
	requirements any,
	cmd []string,
	saltenv string,
) ([]string, error) {
	if requirements == nil {
		return nil, nil
	}
	var reqs []string
	switch v := requirements.(type) {
	case string:
		for _, r := range strings.Split(v, ",") {
			reqs = append(reqs, strings.TrimSpace(r))
		}
	case []string:
		reqs = v
	case []any:
		for _, item := range v {
			reqs = append(reqs, scalarString(item))
		}
	default:
		return nil, fmt.Errorf("requirements must be a string or list")
	}

	for _, requirement := range reqs {
		if strings.HasPrefix(requirement, "salt://") {
			return nil, &runtime.UnsupportedError{Kind: "function", Name: "cp.cache_file"}
		}
		cmd = append(cmd, "--requirement", requirement)
	}
	return cmd[len(cmd):], nil
}

// --- install -------------------------------------------------------------------------

type InstallArgs struct {
	Pkgs                   any            `statekit:"name=pkgs"`
	Requirements           any            `statekit:"name=requirements"`
	BinEnv                 *string        `statekit:"name=bin_env"`
	UseWheel               bool           `statekit:"name=use_wheel"`
	NoUseWheel             bool           `statekit:"name=no_use_wheel"`
	Log                    *string        `statekit:"name=log"`
	Proxy                  any            `statekit:"name=proxy"`
	Timeout                any            `statekit:"name=timeout"`
	Editable               any            `statekit:"name=editable"`
	FindLinks              any            `statekit:"name=find_links"`
	IndexURL               *string        `statekit:"name=index_url"`
	ExtraIndexURL          *string        `statekit:"name=extra_index_url"`
	NoIndex                bool           `statekit:"name=no_index"`
	Mirrors                any            `statekit:"name=mirrors"`
	Build                  *string        `statekit:"name=build"`
	Target                 *string        `statekit:"name=target"`
	Download               *string        `statekit:"name=download"`
	DownloadCache          *string        `statekit:"name=download_cache"`
	Source                 *string        `statekit:"name=source"`
	Upgrade                bool           `statekit:"name=upgrade"`
	ForceReinstall         bool           `statekit:"name=force_reinstall"`
	IgnoreInstalled        bool           `statekit:"name=ignore_installed"`
	ExistsAction           *string        `statekit:"name=exists_action"`
	NoDeps                 bool           `statekit:"name=no_deps"`
	NoInstall              bool           `statekit:"name=no_install"`
	NoDownload             bool           `statekit:"name=no_download"`
	GlobalOptions          any            `statekit:"name=global_options"`
	InstallOptions         any            `statekit:"name=install_options"`
	User                   *string        `statekit:"name=user"`
	Cwd                    *string        `statekit:"name=cwd"`
	PreReleases            bool           `statekit:"name=pre_releases"`
	Cert                   *string        `statekit:"name=cert"`
	AllowAllExternal       bool           `statekit:"name=allow_all_external"`
	AllowExternal          any            `statekit:"name=allow_external"`
	AllowUnverified        any            `statekit:"name=allow_unverified"`
	ProcessDependencyLinks bool           `statekit:"name=process_dependency_links"`
	Saltenv                string         `statekit:"name=saltenv"`
	EnvVars                map[string]any `statekit:"name=env_vars"`
	TrustedHost            *string        `statekit:"name=trusted_host"`
	NoCacheDir             bool           `statekit:"name=no_cache_dir"`
	ExtraArgs              any            `statekit:"name=extra_args"`
	CacheDir               *string        `statekit:"name=cache_dir"`
	NoBinary               any            `statekit:"name=no_binary"`
	DisableVersionCheck    bool           `statekit:"name=disable_version_check"`
}

type installFunc struct{}

func (installFunc) Name() string { return "pip.install" }
func (installFunc) Args() any    { return InstallArgs{} }

func commaOrList(raw any) []string {
	switch v := raw.(type) {
	case nil:
		return nil
	case string:
		var out []string
		for _, part := range strings.Split(v, ",") {
			out = append(out, strings.TrimSpace(part))
		}
		return out
	case []string:
		return v
	case []any:
		var out []string
		for _, item := range v {
			out = append(out, scalarString(item))
		}
		return out
	}
	return []string{scalarString(raw)}
}

func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InstallArgs)
	cwd := strOr(a.Cwd)

	pipBin, err := getPipBin(rt, strOr(a.BinEnv))
	if err != nil {
		return nil, err
	}
	cmd := append([]string{}, pipBin...)
	cmd = append(cmd, "install")

	if a.Requirements != nil {
		reqArgs, rerr := processRequirements(ctx, rt, a.Requirements, cmd, a.Saltenv)
		if rerr != nil {
			return nil, rerr
		}
		cmd = append(cmd, reqArgs...)
	}

	curVersion := derefOrEmpty(mustVersion(ctx, rt, strOr(a.BinEnv), cwd, strOr(a.User)))

	if a.UseWheel || a.NoUseWheel {
		// Version-gated legacy flags: outside 1.4..9.0.3 they are dropped
		// with a log line upstream; mirrored as silent skips.
		tooLow := dottedCompare(curVersion, "1.4") < 0
		tooHigh := dottedCompare(curVersion, "9.0.3") > 0
		if !(tooLow || tooHigh) {
			if a.UseWheel {
				cmd = append(cmd, "--use-wheel")
			} else {
				cmd = append(cmd, "--no-use-wheel")
			}
		}
	}
	if a.NoBinary != nil {
		if dottedCompare(curVersion, "7.0.0") < 0 {
			// Dropped below 7.0.0 (logged upstream).
		} else {
			noBinary := ""
			switch v := a.NoBinary.(type) {
			case []any:
				var parts []string
				for _, item := range v {
					parts = append(parts, scalarString(item))
				}
				noBinary = strings.Join(parts, ",")
			default:
				noBinary = scalarString(v)
			}
			cmd = append(cmd, "--no-binary", noBinary)
		}
	}
	if a.Log != nil && *a.Log != "" {
		log := *a.Log
		if info, ierr := rt.FS.Stat(log); ierr == nil && info.IsDir() {
			return nil, fmt.Errorf("'%s' is a directory. Use --log path_to_file", log)
		}
		parent := filepath.Dir(log)
		if _, perr := rt.FS.Stat(parent); perr != nil {
			return nil, fmt.Errorf("Trying to create '%s' but parent directory '%s' does not exist.", log, parent)
		}
		cmd = append(cmd, "--log", log)
	}

	proxyText := ""
	switch v := a.Proxy.(type) {
	case nil:
	case bool:
		if !v {
			proxyText = "" // explicit False suppresses the global proxy
		}
	case string:
		proxyText = v
	}
	if proxyText != "" {
		cmd = append(cmd, "--proxy", proxyText)
	} else if a.Proxy == nil {
		if host := optConfig(rt, "proxy_host"); host != "" && optConfig(rt, "proxy_port") != "" {
			user := optConfig(rt, "proxy_username")
			pass := optConfig(rt, "proxy_password")
			httpProxy := ""
			if user != "" && pass != "" {
				httpProxy = fmt.Sprintf("http://%s:%s@%s:%s", user, pass, host, optConfig(rt, "proxy_port"))
			} else {
				httpProxy = fmt.Sprintf("http://%s:%s", host, optConfig(rt, "proxy_port"))
			}
			cmd = append(cmd, "--proxy", httpProxy)
		}
	}

	if a.Timeout != nil {
		timeout := scalarString(a.Timeout)
		if strings.Contains(timeout, ".") {
			return nil, fmt.Errorf("'%s' is not a valid timeout, must be an integer", timeout)
		}
		if _, terr := strconv.Atoi(timeout); terr != nil {
			return nil, fmt.Errorf("'%s' is not a valid timeout, must be an integer", timeout)
		}
		cmd = append(cmd, "--timeout", timeout)
	}

	if a.FindLinks != nil {
		for _, link := range commaOrList(a.FindLinks) {
			if !urlValidate(link) && !fsExists(rt, link) {
				return nil, fmt.Errorf("'%s' is not a valid URL or path", link)
			}
			cmd = append(cmd, "--find-links", link)
		}
	}

	if a.NoIndex && (a.IndexURL != nil || a.ExtraIndexURL != nil) {
		return nil, fmt.Errorf("'no_index' and ('index_url' or 'extra_index_url') are mutually exclusive.")
	}
	if a.IndexURL != nil {
		if !urlValidate(*a.IndexURL) {
			return nil, fmt.Errorf("'%s' is not a valid URL", *a.IndexURL)
		}
		cmd = append(cmd, "--index-url", *a.IndexURL)
	}
	if a.ExtraIndexURL != nil {
		if !urlValidate(*a.ExtraIndexURL) {
			return nil, fmt.Errorf("'%s' is not a valid URL", *a.ExtraIndexURL)
		}
		cmd = append(cmd, "--extra-index-url", *a.ExtraIndexURL)
	}
	if a.NoIndex {
		cmd = append(cmd, "--no-index")
	}
	if a.Mirrors != nil {
		if dottedCompare(curVersion, "7.0.0") >= 0 {
			return nil, fmt.Errorf(
				"pip >= 7.0.0 does not support mirror argument:" +
					" use index_url and/or extra_index_url instead")
		}
		cmd = append(cmd, "--use-mirrors")
		for _, mirror := range commaOrList(a.Mirrors) {
			if !strings.HasPrefix(mirror, "http://") {
				return nil, fmt.Errorf("'%s' is not a valid URL", mirror)
			}
			cmd = append(cmd, "--mirrors", mirror)
		}
	}
	if a.DisableVersionCheck {
		cmd = append(cmd, "--disable-pip-version-check")
	}
	if a.Build != nil {
		cmd = append(cmd, "--build", *a.Build)
	}

	target := a.Target
	if target == nil {
		if venvTarget := os.Getenv("VENV_PIP_TARGET"); venvTarget != "" && strOr(a.BinEnv) == "" {
			target = &venvTarget
		}
	}
	if target != nil && *target != "" {
		cmd = append(cmd, "--target", *target)
	}
	if a.Download != nil {
		cmd = append(cmd, "--download", *a.Download)
	}
	if (a.DownloadCache != nil && *a.DownloadCache != "") || (a.CacheDir != nil && *a.CacheDir != "") {
		flag := "--download-cache"
		if dottedCompare(curVersion, "6.0") >= 0 {
			flag = "--cache-dir"
		}
		value := ""
		if a.DownloadCache != nil {
			value = *a.DownloadCache
		} else {
			value = *a.CacheDir
		}
		cmd = append(cmd, flag, value)
	}
	if a.Source != nil {
		cmd = append(cmd, "--source", *a.Source)
	}
	if a.Upgrade {
		cmd = append(cmd, "--upgrade")
	}
	if a.ForceReinstall {
		cmd = append(cmd, "--force-reinstall")
	}
	if a.IgnoreInstalled {
		cmd = append(cmd, "--ignore-installed")
	}
	if a.ExistsAction != nil {
		action := strings.ToLower(*a.ExistsAction)
		valid := false
		for _, allowed := range []string{"s", "i", "w", "b"} {
			if action == allowed {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf(
				"The exists_action pip option only supports the values "+
					"s, i, w, and b. '%s' is not valid.", *a.ExistsAction)
		}
		cmd = append(cmd, "--exists-action", *a.ExistsAction)
	}
	if a.NoDeps {
		cmd = append(cmd, "--no-deps")
	}
	if a.NoInstall {
		cmd = append(cmd, "--no-install")
	}
	if a.NoDownload {
		cmd = append(cmd, "--no-download")
	}
	if a.NoCacheDir {
		cmd = append(cmd, "--no-cache-dir")
	}
	if a.PreReleases && dottedCompare(curVersion, "1.4") >= 0 {
		cmd = append(cmd, "--pre")
	}
	if a.Cert != nil {
		cmd = append(cmd, "--cert", *a.Cert)
	}
	for _, opt := range commaOrList(a.GlobalOptions) {
		cmd = append(cmd, "--global-option", opt)
	}
	for _, opt := range commaOrList(a.InstallOptions) {
		cmd = append(cmd, "--install-option", opt)
	}

	pkgs := commaOrList(a.Pkgs)
	if len(pkgs) > 0 {
		for _, p := range pkgs {
			cmd = append(cmd, strings.ReplaceAll(p, ";", ","))
		}
	} else if a.Requirements == nil && a.Editable == nil {
		return map[string]any{
			"retcode": 0,
			"stdout":  "No packages to install.",
		}, nil
	}

	if a.Editable != nil {
		for _, entry := range commaOrList(a.Editable) {
			if !(entry == "." || strings.HasPrefix(entry, "file://") || strings.HasPrefix(entry, "/")) {
				match := eggMatchRe.FindStringSubmatch(entry)
				if match == nil || match[1] == "" {
					return nil, fmt.Errorf("You must specify an egg for this editable")
				}
			}
			cmd = append(cmd, "--editable", entry)
		}
	}

	if a.AllowAllExternal {
		cmd = append(cmd, "--allow-all-external")
	}
	for _, pkgName := range commaOrList(a.AllowExternal) {
		cmd = append(cmd, "--allow-external", pkgName)
	}
	for _, pkgName := range commaOrList(a.AllowUnverified) {
		cmd = append(cmd, "--allow-unverified", pkgName)
	}
	if a.ProcessDependencyLinks {
		cmd = append(cmd, "--process-dependency-links")
	}
	if a.TrustedHost != nil {
		cmd = append(cmd, "--trusted-host", *a.TrustedHost)
	}

	env := buildEnvArgs(a.EnvVars)
	if strOr(a.BinEnv) != "" {
		if info, ierr := rt.FS.Stat(strOr(a.BinEnv)); ierr == nil && info.IsDir() {
			env = append(env, "VIRTUAL_ENV="+strOr(a.BinEnv))
		}
	}

	defer clearContext(strOr(a.BinEnv))
	res := runCmd(ctx, rt, cmd, cwd, env, strOr(a.User))
	return map[string]any{
		"pid":     nil,
		"retcode": res.retcode,
		"stdout":  res.stdout,
		"stderr":  res.stderr,
	}, nil
}

func mustVersion(ctx context.Context, rt *runtime.Runtime, binEnv, cwd, user string) *string {
	v, err := pipVersion(ctx, rt, binEnv, cwd, user)
	if err != nil {
		return nil
	}
	return v
}

func optConfig(rt *runtime.Runtime, key string) string {
	if _, ok := rt.Exec.Get("config.option"); !ok {
		return ""
	}
	res, err := rt.Exec.Call(context.Background(), rt, "config.option",
		map[string]any{"key": key})
	if err != nil || res == nil {
		return ""
	}
	return scalarString(res)
}

// --- uninstall ------------------------------------------------------------------------

type UninstallArgs struct {
	Pkgs         any     `statekit:"name=pkgs"`
	Requirements any     `statekit:"name=requirements"`
	BinEnv       *string `statekit:"name=bin_env"`
	Log          *string `statekit:"name=log"`
	Proxy        any     `statekit:"name=proxy"`
	Timeout      any     `statekit:"name=timeout"`
	User         *string `statekit:"name=user"`
	Cwd          *string `statekit:"name=cwd"`
	Saltenv      string  `statekit:"name=saltenv"`
	ExtraArgs    any     `statekit:"name=extra_args"`
}

type uninstallFunc struct{}

func (uninstallFunc) Name() string { return "pip.uninstall" }
func (uninstallFunc) Args() any    { return UninstallArgs{} }

func (uninstallFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*UninstallArgs)
	cwd := strOr(a.Cwd)
	pipBin, err := getPipBin(rt, strOr(a.BinEnv))
	if err != nil {
		return nil, err
	}
	cmd := append([]string{}, pipBin...)
	cmd = append(cmd, "uninstall", "-y")

	if a.Requirements != nil {
		reqArgs, rerr := processRequirements(ctx, rt, a.Requirements, cmd, a.Saltenv)
		if rerr != nil {
			return nil, rerr
		}
		cmd = append(cmd, reqArgs...)
	}

	if a.Log != nil && *a.Log != "" {
		cmd = append(cmd, "--log", *a.Log)
	}

	proxyText := ""
	switch v := a.Proxy.(type) {
	case nil:
	case bool:
		if !v {
			proxyText = ""
		}
	case string:
		proxyText = v
	}
	if proxyText != "" {
		cmd = append(cmd, "--proxy", proxyText)
	} else if a.Proxy == nil {
		if host := optConfig(rt, "proxy_host"); host != "" && optConfig(rt, "proxy_port") != "" {
			cmd = append(cmd, "--proxy",
				fmt.Sprintf("http://%s:%s", host, optConfig(rt, "proxy_port")))
		}
	}

	if a.Timeout != nil {
		timeout := scalarString(a.Timeout)
		if strings.Contains(timeout, ".") ||
			func() bool { _, terr := strconv.Atoi(timeout); return terr != nil }() {
			return nil, fmt.Errorf("'%s' is not a valid timeout, must be an integer", timeout)
		}
		cmd = append(cmd, "--timeout", timeout)
		cmd = append(cmd, "--timeout", timeout)
	}

	pkgs := commaOrList(a.Pkgs)
	if len(pkgs) > 0 {
		// Requirements listed with == are dropped from the uninstall set
		// (upstream reads each local requirements file for deduplication).
		if reqList := commaOrList(a.Requirements); len(reqList) > 0 {
			for _, reqFile := range reqList {
				data, rerr := rt.FS.ReadFile(reqFile)
				if rerr != nil {
					continue
				}
				for _, line := range strings.Split(string(data), "\n") {
					if reqPkg, _, found := strings.Cut(line, "=="); found {
						reqPkg = strings.TrimSpace(reqPkg)
						filtered := pkgs[:0]
						for _, existing := range pkgs {
							if existing != reqPkg {
								filtered = append(filtered, existing)
							}
						}
						pkgs = filtered
					}
				}
			}
		}
		cmd = append(cmd, pkgs...)
	}

	env := []string(nil)
	if strOr(a.BinEnv) != "" {
		if info, ierr := rt.FS.Stat(strOr(a.BinEnv)); ierr == nil && info.IsDir() {
			env = []string{"VIRTUAL_ENV=" + strOr(a.BinEnv)}
		}
	}
	defer clearContext(strOr(a.BinEnv))
	res := runCmd(ctx, rt, cmd, cwd, env, strOr(a.User))
	return map[string]any{
		"pid":     nil,
		"retcode": res.retcode,
		"stdout":  res.stdout,
		"stderr":  res.stderr,
	}, nil
}

// Register installs all pip-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		listFunc{},
		installFunc{},
		uninstallFunc{},
		freezeFunc{},
		listFreezeParseFunc{},
		versionFunc{},
		listUpgradesFunc{},
		isInstalledFunc{},
		upgradeAvailableFunc{},
		upgradeFunc{},
		listAllVersionsFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
