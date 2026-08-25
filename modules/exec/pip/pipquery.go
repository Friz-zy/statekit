package pip

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// Query-surface functions: freeze/list_freeze_parse/list_/list_upgrades/
// is_installed/upgrade_available/upgrade/list_all_versions.

type FreezeArgs struct {
	BinEnv  *string        `statekit:"name=bin_env"`
	User    *string        `statekit:"name=user"`
	Cwd     *string        `statekit:"name=cwd"`
	EnvVars map[string]any `statekit:"name=env_vars"`
}

type freezeFunc struct{}

func (freezeFunc) Name() string { return "pip.freeze" }
func (freezeFunc) Args() any    { return FreezeArgs{} }

func (freezeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*FreezeArgs)
	lines, err := pipFreeze(ctx, rt, strOr(a.BinEnv), strOr(a.User), strOr(a.Cwd), a.EnvVars)
	if err != nil {
		return nil, err
	}
	return lines, nil
}

func pipFreeze(ctx context.Context, rt *runtime.Runtime, binEnv, user, cwd string, envVars map[string]any) ([]string, error) {
	pipBin, err := getPipBin(rt, binEnv)
	if err != nil {
		return nil, err
	}
	cmd := append([]string{}, pipBin...)
	cmd = append(cmd, "freeze")

	curVersion := derefOrEmpty(mustVersion(ctx, rt, binEnv, cwd, ""))
	if dottedCompare(curVersion, "8.0.3") >= 0 {
		cmd = append(cmd, "--all")
	}
	// Airgapped minions block on the PyPI round-trip otherwise (#68214).
	cmd = append(cmd, "--disable-pip-version-check")

	env := buildEnvArgs(envVars)
	if binEnv != "" {
		if info, ierr := rt.FS.Stat(binEnv); ierr == nil && info.IsDir() {
			env = append(env, "VIRTUAL_ENV="+binEnv)
		}
	}
	res := runCmd(ctx, rt, cmd, cwd, env, user)
	if res.retcode != 0 {
		return nil, fmt.Errorf("%s", res.stderr)
	}
	defer clearContext(binEnv)
	return strings.Split(strings.TrimRight(res.stdout, "\n"), "\n"), nil
}

type ListFreezeParseArgs struct {
	Prefix  *string        `statekit:"name=prefix"`
	BinEnv  *string        `statekit:"name=bin_env"`
	User    *string        `statekit:"name=user"`
	Cwd     *string        `statekit:"name=cwd"`
	EnvVars map[string]any `statekit:"name=env_vars"`
}

type listFreezeParseFunc struct{}

func (listFreezeParseFunc) Name() string { return "pip.list_freeze_parse" }
func (listFreezeParseFunc) Args() any    { return ListFreezeParseArgs{} }
func (listFreezeParseFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListFreezeParseArgs)
	binEnv := strOr(a.BinEnv)
	cwd := strOr(a.Cwd)

	packages := map[string]string{}
	prefix := ""
	if a.Prefix != nil {
		prefix = *a.Prefix
	}
	if prefix == "" || strings.HasPrefix("pip", prefix) {
		v := derefOrEmpty(mustVersion(ctx, rt, binEnv, cwd, ""))
		packages["pip"] = v
	}

	lines, ferr := pipFreeze(ctx, rt, binEnv, strOr(a.User), cwd, a.EnvVars)
	if ferr != nil {
		return nil, ferr
	}
	for _, line := range lines {
		name, version2, ok := parseFreezeLine(line)
		if !ok {
			continue
		}
		if prefix != "" {
			if strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
				packages[name] = version2
			}
		} else {
			packages[name] = version2
		}
	}
	return packages, nil
}

// parseFreezeLine ports the freeze-line parser: -f/# skips, the
// "-e hg+not trust" workaround, -e #egg= splitting, === and == records.
func parseFreezeLine(line string) (string, string, bool) {
	switch {
	case strings.HasPrefix(line, "-f") || strings.HasPrefix(line, "#"):
		return "", "", false
	case strings.HasPrefix(line, "-e hg+not trust"):
		return "", "", false
	case strings.HasPrefix(line, "-e"):
		line = strings.SplitN(line, "-e ", 2)[1]
		var name, version2 string
		if strings.Contains(line, "#egg=") {
			parts := strings.Split(line, "#egg=")
			version2, name = parts[0], parts[1]
		} else if parts := strings.Split(line, "==="); len(parts) >= 2 {
			name, version2 = parts[0], parts[1]
		} else if parts := strings.Split(line, "=="); len(parts) >= 2 {
			name, version2 = parts[0], parts[1]
		}
		return name, version2, true
	case len(strings.Split(line, "===")) >= 2:
		parts := strings.Split(line, "===")
		return parts[0], parts[1], true
	case len(strings.Split(line, "==")) >= 2:
		parts := strings.Split(line, "==")
		return parts[0], parts[1], true
	}
	return "", "", false
}

type ListArgs struct {
	Prefix  *string        `statekit:"name=prefix"`
	BinEnv  *string        `statekit:"name=bin_env"`
	User    *string        `statekit:"name=user"`
	Cwd     *string        `statekit:"name=cwd"`
	EnvVars map[string]any `statekit:"name=env_vars"`
}

type listFunc struct{}

func (listFunc) Name() string { return "pip.list" }
func (listFunc) Args() any    { return ListArgs{} }

func (listFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListArgs)
	binEnv := strOr(a.BinEnv)
	cwd := strOr(a.Cwd)
	user := strOr(a.User)
	curVersion := derefOrEmpty(mustVersion(ctx, rt, binEnv, cwd, user))

	// JSON output arrived in pip 9.0; older pips fall back to freeze parse.
	if dottedCompare(curVersion, "9.0") < 0 {
		fallback := listFreezeParseFunc{}
		return fallback.Execute(ctx, rt, &ListFreezeParseArgs{
			Prefix: a.Prefix, BinEnv: a.BinEnv, User: a.User,
			Cwd: a.Cwd, EnvVars: a.EnvVars,
		})
	}

	pipBin, err := getPipBin(rt, binEnv)
	if err != nil {
		return nil, err
	}
	cmd := append([]string{}, pipBin...)
	cmd = append(cmd, "list", "--format=json", "--disable-pip-version-check")

	env := buildEnvArgs(a.EnvVars)
	if binEnv != "" {
		if info, ierr := rt.FS.Stat(binEnv); ierr == nil && info.IsDir() {
			env = append(env, "VIRTUAL_ENV="+binEnv)
		}
	}
	res := runCmd(ctx, rt, cmd, cwd, env, user)
	if res.retcode != 0 {
		return nil, fmt.Errorf("%s", res.stderr)
	}

	var pkgs []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if jerr := json.Unmarshal([]byte(res.stdout), &pkgs); jerr != nil {
		return nil, fmt.Errorf("Invalid JSON")
	}

	normalPrefix := ""
	if a.Prefix != nil && *a.Prefix != "" {
		normalPrefix = normalize(*a.Prefix)
	}
	packages := map[string]string{}
	for _, pkg := range pkgs {
		normalName := normalize(pkg.Name)
		if normalPrefix != "" {
			if strings.HasPrefix(normalName, normalPrefix) {
				packages[normalName] = pkg.Version
			}
		} else {
			packages[normalName] = pkg.Version
		}
	}
	return packages, nil
}

type ListUpgradesArgs struct {
	BinEnv *string `statekit:"name=bin_env"`
	User   *string `statekit:"name=user"`
	Cwd    *string `statekit:"name=cwd"`
}

type listUpgradesFunc struct{}

func (listUpgradesFunc) Name() string { return "pip.list_upgrades" }
func (listUpgradesFunc) Args() any    { return ListUpgradesArgs{} }
func (listUpgradesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListUpgradesArgs)
	upgrades, err := pipListUpgrades(ctx, rt, strOr(a.BinEnv), strOr(a.User), strOr(a.Cwd))
	if err != nil {
		return nil, err
	}
	return upgrades, nil
}

var (
	oldOutdatedRe = regexp.MustCompile(`(\S*)\s+\(.*Latest:\s+(.*)\)`)
	newOutdatedRe = regexp.MustCompile(`(\S*)\s+\(.*\)\s+-\s+Latest:\s+(.*)`)
	allVersionsRe = regexp.MustCompile(`\s*Available versions: (.*)`)
	noVersionsRe  = regexp.MustCompile(`\s*Could not find a version.* \(from versions: (.*)\)`)
)

func pipListUpgrades(ctx context.Context, rt *runtime.Runtime, binEnv, user, cwd string) (map[string]string, error) {
	pipBin, err := getPipBin(rt, binEnv)
	if err != nil {
		return nil, err
	}
	cmd := append([]string{}, pipBin...)
	cmd = append(cmd, "list", "--outdated", "--disable-pip-version-check")

	pipVersionStr := derefOrEmpty(mustVersion(ctx, rt, binEnv, cwd, user))
	jsonMode := dottedCompare(pipVersionStr, "9.0") >= 0
	if jsonMode {
		cmd = append(cmd, "--format=json")
	}

	env := []string(nil)
	if binEnv != "" {
		if info, ierr := rt.FS.Stat(binEnv); ierr == nil && info.IsDir() {
			env = []string{"VIRTUAL_ENV=" + binEnv}
		}
	}
	res := runCmd(ctx, rt, cmd, cwd, env, user)
	if res.retcode != 0 {
		return nil, fmt.Errorf("%s", res.stderr)
	}

	packages := map[string]string{}
	if dottedCompare(pipVersionStr, "9.0.0") < 0 {
		pattern := oldOutdatedRe // pip < 8.0.0 output shape
		if dottedCompare(pipVersionStr, "8.0.0") >= 0 {
			pattern = newOutdatedRe
		}
		for _, line := range strings.Split(res.stdout, "\n") {
			m := pattern.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			packages[m[1]] = m[2]
		}
		return packages, nil
	}

	var pkgs []struct {
		Name           string `json:"name"`
		LatestVersion  string `json:"latest_version"`
		LatestFiletype string `json:"latest_filetype"`
	}
	if jerr := json.Unmarshal([]byte(res.stdout), &pkgs); jerr != nil {
		return nil, fmt.Errorf("Invalid JSON")
	}
	for _, pkg := range pkgs {
		packages[pkg.Name] = fmt.Sprintf("%s [%s]", pkg.LatestVersion, pkg.LatestFiletype)
	}
	return packages, nil
}

type IsInstalledArgs struct {
	Pkgname string  `statekit:"required,name=pkgname"`
	BinEnv  *string `statekit:"name=bin_env"`
	User    *string `statekit:"name=user"`
	Cwd     *string `statekit:"name=cwd"`
}

type isInstalledFunc struct{}

func (isInstalledFunc) Name() string { return "pip.is_installed" }
func (isInstalledFunc) Args() any    { return IsInstalledArgs{} }
func (isInstalledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*IsInstalledArgs)
	pkgsAny, err := listFunc{}.Execute(ctx, rt, &ListArgs{
		Prefix: strPtr(a.Pkgname), BinEnv: a.BinEnv, User: a.User, Cwd: a.Cwd,
	})
	if err != nil {
		return false, nil
	}
	pkgs := pkgsAny.(map[string]string)
	for name := range pkgs {
		if strings.EqualFold(name, a.Pkgname) {
			return true, nil
		}
	}
	return false, nil
}

type UpgradeAvailableArgs struct {
	Pkg    string  `statekit:"required,name=pkg"`
	BinEnv *string `statekit:"name=bin_env"`
	User   *string `statekit:"name=user"`
	Cwd    *string `statekit:"name=cwd"`
}

type upgradeAvailableFunc struct{}

func (upgradeAvailableFunc) Name() string { return "pip.upgrade_available" }
func (upgradeAvailableFunc) Args() any    { return UpgradeAvailableArgs{} }
func (upgradeAvailableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*UpgradeAvailableArgs)
	upgrades, uerr := pipListUpgrades(ctx, rt, strOr(a.BinEnv), strOr(a.User), strOr(a.Cwd))
	if uerr != nil {
		return false, uerr
	}
	_, ok := upgrades[a.Pkg]
	return ok, nil
}

type UpgradeArgs struct {
	BinEnv *string `statekit:"name=bin_env"`
	User   *string `statekit:"name=user"`
	Cwd    *string `statekit:"name=cwd"`
}

type upgradeFunc struct{}

func (upgradeFunc) Name() string { return "pip.upgrade" }
func (upgradeFunc) Args() any    { return UpgradeArgs{} }

func (upgradeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*UpgradeArgs)
	binEnv := strOr(a.BinEnv)
	cwd := strOr(a.Cwd)
	user := strOr(a.User)

	ret := map[string]any{
		"changes": map[string]any{},
		"result":  true,
		"comment": "",
	}

	pipBin, err := getPipBin(rt, binEnv)
	if err != nil {
		return nil, err
	}
	cmd := append([]string{}, pipBin...)
	cmd = append(cmd, "install", "-U", "--disable-pip-version-check")

	oldRaw, lerr := listFunc{}.Execute(ctx, rt, &ListArgs{BinEnv: a.BinEnv, User: a.User, Cwd: a.Cwd})
	_ = lerr // ignored upstream too
	oldMap, _ := oldRaw.(map[string]string)

	upgrades, uerr := pipListUpgrades(ctx, rt, binEnv, user, cwd)
	if uerr != nil {
		return nil, uerr
	}
	errors := false
	comment := ""
	env := []string(nil)
	if binEnv != "" {
		if info, ierr := rt.FS.Stat(binEnv); ierr == nil && info.IsDir() {
			env = []string{"VIRTUAL_ENV=" + binEnv}
		}
	}
	for pkgName := range upgrades {
		if pkgName == "salt" {
			continue // Windows-only skip upstream; salt is never upgraded here
		}
		result := runCmd(ctx, rt, append(append([]string{}, cmd...), pkgName), cwd, env, user)
		if result.retcode != 0 {
			errors = true
		}
		comment += result.stderr
	}
	if errors {
		ret["result"] = false
	}
	clearContext(binEnv)

	newAny, _ := listFunc{}.Execute(ctx, rt, &ListArgs{BinEnv: a.BinEnv, User: a.User, Cwd: a.Cwd})
	newPkgMap, _ := newAny.(map[string]string)
	if oldMap == nil {
		oldMap = map[string]string{}
	}
	changes := map[string]any{}
	for name, newVal := range newPkgMap {
		if oldVal, seen := oldMap[name]; !seen || oldVal != newVal {
			changes[name] = map[string]any{"old": oldVal, "new": newVal}
		}
	}
	for name, oldVal := range oldMap {
		if _, still := newPkgMap[name]; !still {
			changes[name] = map[string]any{"old": oldVal, "new": nil}
		}
	}
	ret["changes"] = changes
	ret["comment"] = comment
	return ret, nil
}

type ListAllVersionsArgs struct {
	Pkg           string  `statekit:"required,name=pkg"`
	BinEnv        *string `statekit:"name=bin_env"`
	IncludeAlpha  bool    `statekit:"name=include_alpha"`
	IncludeBeta   bool    `statekit:"name=include_beta"`
	IncludeRC     bool    `statekit:"name=include_rc"`
	User          *string `statekit:"name=user"`
	Cwd           *string `statekit:"name=cwd"`
	IndexURL      *string `statekit:"name=index_url"`
	ExtraIndexURL *string `statekit:"name=extra_index_url"`
}

type listAllVersionsFunc struct{}

func (listAllVersionsFunc) Name() string { return "pip.list_all_versions" }
func (listAllVersionsFunc) Args() any    { return ListAllVersionsArgs{} }
func (listAllVersionsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListAllVersionsArgs)
	binEnv := strOr(a.BinEnv)
	cwd := strOr(a.Cwd)
	pipBin, err := getPipBin(rt, binEnv)
	if err != nil {
		return nil, err
	}
	cmd := append([]string{}, pipBin...)
	cmd = append(cmd, "--disable-pip-version-check")

	pipVersionStr := derefOrEmpty(mustVersion(ctx, rt, binEnv, cwd, strOr(a.User)))
	var lineRe *regexp.Regexp
	if dottedCompare(pipVersionStr, "21.2") >= 0 {
		lineRe = allVersionsRe
		cmd = append(cmd, "index", "versions", a.Pkg)
	} else {
		if dottedCompare(pipVersionStr, "20.3") >= 0 {
			cmd = append(cmd, "--use-deprecated=legacy-resolver")
		}
		lineRe = noVersionsRe
		cmd = append(cmd, "install", a.Pkg+"==versions")
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

	// redirect_stderr=True upstream merges stderr into stdout.
	res := runCmd(ctx, rt, cmd, cwd, nil, strOr(a.User))
	combined := res.stdout + res.stderr

	var filtered []string
	if !a.IncludeAlpha {
		filtered = append(filtered, "a")
	}
	if !a.IncludeBeta {
		filtered = append(filtered, "b")
	}
	if !a.IncludeRC {
		filtered = append(filtered, "rc")
	}
	var excludes *regexp.Regexp
	if len(filtered) > 0 {
		excludes = regexp.MustCompile(`^((?!` + strings.Join(filtered, "|") + `).)*$`)
	}

	var versions []string
	for _, line := range strings.Split(combined, "\n") {
		m := lineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		for _, v := range strings.Split(m[1], ", ") {
			if v != "" && (excludes == nil || excludes.MatchString(v)) {
				versions = append(versions, v)
			}
		}
		break
	}
	if len(versions) == 0 {
		return nil, nil
	}
	sortVersionStrings(versions)
	return versions, nil
}

// sortVersionStrings approximates salt.utils.versions.parse ordering.
func sortVersionStrings(items []string) {
	key := func(s string) string {
		var b strings.Builder
		for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' }) {
			num := ""
			alpha := ""
			for _, c := range part {
				if c >= '0' && c <= '9' {
					num += string(c)
				} else {
					alpha += string(c)
				}
			}
			for i := len(num); i < 6; i++ {
				b.WriteString("0")
			}
			b.WriteString(num)
			b.WriteString(alpha)
		}
		return b.String()
	}
	// insertion sort by key
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && key(items[j]) < key(items[j-1]); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}
