package pkg

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// yumUpgradeError preserves yumpkg.upgrade's completed-transaction details.
// Runner failures, cancellation, and clipped streams are returned directly and
// never reach the post-transaction package query.
type yumUpgradeError struct{ info map[string]any }

func (e *yumUpgradeError) Error() string { return "Problem encountered upgrading packages" }

func (e *yumUpgradeError) Info() map[string]any { return e.info }

type yumUpgradeRequest struct {
	refresh        bool
	checkUpdate    bool
	skipVerify     bool
	normalize      bool
	minimal        bool
	obsoletes      bool
	diffAttributes []string
	allAttributes  bool
	refreshOptions []string
	options        []string
	targets        []string
}

// RunnerAvailable reports whether r contains a usable Runner. An interface
// holding a typed-nil pointer is not itself nil, so callers must use this
// helper before invoking a Runner through an interface value.
func RunnerAvailable(r process.Runner) bool {
	if r == nil {
		return false
	}
	v := reflect.ValueOf(r)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !v.IsNil()
	default:
		return true
	}
}

// yumUpgrade mirrors yumpkg.upgrade/update at the command boundary. Every
// command uses yumUpgradeRun, which keeps post-query behavior safe and bounded.
func yumUpgrade(ctx context.Context, rt *runtime.Runtime, manager, function string, a map[string]any) (any, error) {
	if manager != "yum" && manager != "dnf" && manager != "dnf5" {
		return nil, ErrUnsupportedYUM
	}
	if ctx == nil {
		ctx = context.Background()
	}
	osarch, err := yumUpgradeRuntimeArch(rt)
	if err != nil {
		return nil, err
	}
	request, err := yumUpgradeRequestFromArgs(manager, function, a, osarch)
	if err != nil {
		return nil, err
	}
	if rt != nil && rt.Options.Test {
		// Process-wide execution test mode must not refresh or mutate packages.
		return map[string]any{}, nil
	}
	if rt == nil || rt.Runner == nil {
		return nil, errors.New("YUM upgrade requires a runner")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.refresh {
		if err := yumUpgradeRefreshDB(ctx, rt, manager, request.refreshOptions, request.checkUpdate); err != nil {
			return nil, err
		}
	}
	old, err := yumUpgradeListPackages(ctx, rt, osarch, request.diffAttributes, request.allAttributes)
	if err != nil {
		return nil, err
	}

	argv := append([]string{manager, "--quiet", "-y"}, request.options...)
	if request.skipVerify {
		argv = append(argv, "--nogpgcheck")
	}
	action := "upgrade"
	if request.minimal {
		action = "upgrade-minimal"
	}
	if !request.obsoletes && manager == "yum" {
		action = "update"
		if request.minimal {
			action = "update-minimal"
		}
	}
	argv = append(argv, action)
	argv = append(argv, request.targets...)
	result, err := yumUpgradeRun(ctx, rt, argv)
	if err != nil {
		return nil, err
	}

	// StateKit has no mutable pkg.list_pkgs context cache. A fresh bounded RPM
	// query is therefore the source-equivalent invalidation/readback boundary.
	newPackages, err := yumUpgradeListPackages(ctx, rt, osarch, request.diffAttributes, request.allAttributes)
	if err != nil {
		return nil, err
	}
	changes := yumUpgradeComparePackages(old, newPackages)
	if result.ExitCode != 0 {
		return changes, &yumUpgradeError{info: map[string]any{
			"changes": changes,
			"result": map[string]any{
				"retcode": result.ExitCode,
				"stdout":  string(result.Stdout),
				"stderr":  string(result.Stderr),
			},
		}}
	}
	return changes, nil
}

func yumUpgradeRequestFromArgs(manager, function string, a map[string]any, osarch string) (yumUpgradeRequest, error) {
	request := yumUpgradeRequest{}
	var err error
	if request.refresh, err = yumBoolArg(a, "refresh", true); err != nil {
		return request, err
	}
	// check_update belongs to refresh_db; its default is consumed only by the
	// refresh path and is never rendered as a transaction option.
	if request.checkUpdate, err = yumBoolArg(a, "check_update", true); err != nil {
		return request, err
	}
	if request.skipVerify, err = yumBoolArg(a, "skip_verify", false); err != nil {
		return request, err
	}
	if request.normalize, err = yumBoolArg(a, "normalize", true); err != nil {
		return request, err
	}
	if request.minimal, err = yumBoolArg(a, "minimal", false); err != nil {
		return request, err
	}
	if request.obsoletes, err = yumBoolArg(a, "obsoletes", function != "update"); err != nil {
		return request, err
	}
	if request.diffAttributes, request.allAttributes, err = yumUpgradeDiffAttributes(a["diff_attr"]); err != nil {
		return request, err
	}
	if request.targets, err = yumUpgradeTargets(a, osarch, request.normalize); err != nil {
		return request, err
	}
	if request.refreshOptions, request.options, err = yumUpgradeOptions(a, manager, request.obsoletes); err != nil {
		return request, err
	}
	return request, nil
}

func yumUpgradeHasPackageTargets(a map[string]any) bool {
	value, present := a["pkgs"]
	return present && sourceTargetTruthy(value)
}

func yumUpgradeTargets(a map[string]any, osarch string, normalize bool) ([]string, error) {
	value, present := a["pkgs"]
	if present && sourceTargetTruthy(value) {
		items, isList, _ := purgeItems(value)
		if !isList {
			return nil, errors.New(`argument "pkgs" must be a list`)
		}
		params := newPurgeTargetMap(len(items))
		for _, item := range items {
			target, err := purgeTargetFromItem(item, func(name string) string {
				if normalize {
					return yumNormalizeName(name, osarch)
				}
				return name
			})
			if err != nil {
				return nil, fmt.Errorf("pkg.upgrade pkgs: %w", err)
			}
			if params.has(target.name) {
				return nil, duplicatePurgeTargetsError(items)
			}
			params.put(target)
		}
		return yumUpgradeTargetNames(params.ordered())
	}

	value, present = a["name"]
	if !present || !sourceTargetTruthy(value) {
		return nil, nil
	}
	name, ok := yumStringArg(a, "name")
	if !ok {
		return nil, errors.New(`argument "name" must be a string`)
	}
	if name == "" {
		return nil, nil
	}
	parts := strings.Split(name, ",")
	targets := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if normalize {
			part = yumNormalizeName(part, osarch)
		}
		if _, exists := seen[part]; exists {
			continue
		}
		seen[part] = struct{}{}
		targets = append(targets, part)
	}
	for _, target := range targets {
		if err := validateYUMArgToken(target); err != nil {
			return nil, fmt.Errorf("invalid package upgrade target %q: %w", target, err)
		}
	}
	return targets, nil
}

func yumUpgradeTargetNames(params []purgeTarget) ([]string, error) {
	targets := make([]string, 0, len(params))
	for _, param := range params {
		// yumpkg.upgrade extends the parse_targets mapping itself, so a mapping
		// value is intentionally not rendered as a version-pinned argv suffix.
		if err := validateYUMArgToken(param.name); err != nil {
			return nil, fmt.Errorf("invalid package upgrade target %q: %w", param.name, err)
		}
		targets = append(targets, param.name)
	}
	return targets, nil
}

func yumUpgradeOptions(a map[string]any, manager string, obsoletes bool) ([]string, []string, error) {
	fromrepo, err := yumUpgradeStringOption(a, "fromrepo")
	if err != nil {
		return nil, nil, err
	}
	repo, err := yumUpgradeStringOption(a, "repo")
	if err != nil {
		return nil, nil, err
	}
	if fromrepo == "" {
		fromrepo = repo
	}
	disableexcludes, err := yumUpgradeStringOption(a, "disableexcludes")
	if err != nil {
		return nil, nil, err
	}
	branch, err := yumUpgradeStringOption(a, "branch")
	if err != nil {
		return nil, nil, err
	}
	setopts, err := yumUpgradeSetopts(a["setopt"])
	if err != nil {
		return nil, nil, err
	}
	if (manager == "dnf" || manager == "dnf5") && !obsoletes {
		filtered := make([]string, 0, len(setopts)+1)
		for _, value := range setopts {
			if !strings.HasPrefix(value, "obsoletes=") {
				filtered = append(filtered, value)
			}
		}
		setopts = append(filtered, "obsoletes=False")
	}

	options := []string{}
	if fromrepo != "" {
		options = append(options, "--disablerepo=*", "--enablerepo="+fromrepo)
	} else {
		for _, key := range []string{"disablerepo", "enablerepo"} {
			values, err := yumUpgradeRepoTargets(a[key])
			if err != nil {
				return nil, nil, fmt.Errorf("argument %q: %w", key, err)
			}
			for _, value := range values {
				if err := validateYUMOption(value); err != nil {
					return nil, nil, fmt.Errorf("argument %q: %w", key, err)
				}
				options = append(options, "--"+key+"="+value)
			}
		}
	}
	if disableexcludes != "" {
		options = append(options, "--disableexcludes="+disableexcludes)
	}
	if branch != "" {
		options = append(options, "--branch="+branch)
	}
	for _, value := range setopts {
		if err := validateYUMOption(value); err != nil {
			return nil, nil, fmt.Errorf("argument %q: %w", "setopt", err)
		}
		options = append(options, "--setopt="+value)
	}
	refreshOptions := append([]string(nil), options...)
	extras, err := yumUpgradeExtraOptions(a)
	if err != nil {
		return nil, nil, err
	}
	options = append(options, extras...)
	return refreshOptions, options, nil
}

func yumUpgradeStringOption(a map[string]any, key string) (string, error) {
	value, present := a[key]
	if !present || value == nil {
		return "", nil
	}
	text, ok := yumStringArg(a, key)
	if !ok {
		return "", fmt.Errorf("argument %q must be a string", key)
	}
	if text == "" {
		return "", nil
	}
	if err := validateYUMOption(text); err != nil {
		return "", fmt.Errorf("argument %q: %w", key, err)
	}
	return text, nil
}

func yumUpgradeRepoTargets(value any) ([]string, error) {
	value = yumRepoPkgDereference(value)
	if value == nil {
		return nil, nil
	}
	switch value := value.(type) {
	case string:
		if value == "" {
			return nil, nil
		}
		return []string{value}, nil
	case []string:
		return append([]string(nil), value...), nil
	case []any:
		values := make([]string, len(value))
		for i, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, errors.New("must be a string or string list")
			}
			values[i] = text
		}
		return values, nil
	default:
		return nil, errors.New("must be a string or string list")
	}
}

func yumUpgradeSetopts(value any) ([]string, error) {
	value = yumRepoPkgDereference(value)
	if value == nil {
		return nil, nil
	}
	switch value := value.(type) {
	case string:
		parts := strings.Split(value, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		return parts, nil
	case []string:
		return append([]string(nil), value...), nil
	case []any:
		parts := make([]string, len(value))
		for i, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, errors.New("must be a string or string list")
			}
			parts[i] = text
		}
		return parts, nil
	default:
		return nil, errors.New("must be a string or string list")
	}
}

func validateYUMUpgradeKwargs(value any) error {
	kwargs, ok := value.(map[string]any)
	if !ok {
		return errors.New(`argument "kwargs" must be an object`)
	}
	for key, item := range kwargs {
		if err := validateYUMUpgradeExtraOption(key, item); err != nil {
			return fmt.Errorf("argument %q: %w", key, err)
		}
	}
	return nil
}

func validateYUMUpgradeExtraOption(key string, value any) error {
	if key == "" || key == "get_extra_options" || strings.HasPrefix(key, "__") || strings.HasPrefix(key, "-") || strings.ContainsAny(key, "= \t\r\n") {
		return errors.New("unsupported extra option")
	}
	if err := validateYUMOption(key); err != nil {
		return err
	}
	switch value := value.(type) {
	case string:
		return validateYUMOption(value)
	case bool:
		if value {
			return nil
		}
	}
	return errors.New("must be a string or true")
}

func yumUpgradeExtraOptions(a map[string]any) ([]string, error) {
	known := map[string]bool{
		"name": true, "pkgs": true, "refresh": true, "check_update": true, "skip_verify": true,
		"normalize": true, "minimal": true, "obsoletes": true, "diff_attr": true,
		"repo": true, "fromrepo": true, "enablerepo": true, "disablerepo": true,
		"disableexcludes": true, "branch": true, "setopt": true, "kwargs": true,
	}
	extras := map[string]any{}
	for key, value := range a {
		if !known[key] {
			extras[key] = value
		}
	}
	if value, present := a["kwargs"]; present && value != nil {
		kwargs, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New(`argument "kwargs" must be an object`)
		}
		for key, item := range kwargs {
			if known[key] {
				return nil, fmt.Errorf("argument %q must use its dedicated field", key)
			}
			if _, exists := extras[key]; exists {
				return nil, fmt.Errorf("duplicate extra option %q", key)
			}
			extras[key] = item
		}
	}
	keys := make([]string, 0, len(extras))
	for key := range extras {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	options := make([]string, 0, len(keys))
	for _, key := range keys {
		value := extras[key]
		if err := validateYUMUpgradeExtraOption(key, value); err != nil {
			return nil, fmt.Errorf("argument %q: %w", key, err)
		}
		if text, ok := value.(string); ok {
			options = append(options, "--"+key+"="+text)
		} else {
			options = append(options, "--"+key)
		}
	}
	return options, nil
}

func yumUpgradeDiffAttributes(raw any) ([]string, bool, error) {
	value := yumRepoPkgDereference(raw)
	if value == nil {
		return nil, false, nil
	}
	var attributes []string
	switch value := value.(type) {
	case string:
		if value == "" {
			return nil, false, nil
		}
		if value == "all" {
			return nil, true, nil
		}
		attributes = strings.Split(value, ",")
		for i := range attributes {
			attributes[i] = strings.TrimSpace(attributes[i])
		}
	case []string:
		attributes = append([]string(nil), value...)
	case []any:
		attributes = make([]string, len(value))
		for i, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, false, errors.New(`argument "diff_attr" must be a string or string list`)
			}
			attributes[i] = text
		}
	default:
		return nil, false, errors.New(`argument "diff_attr" must be a string or string list`)
	}
	if len(attributes) == 0 {
		return nil, false, nil
	}
	if len(attributes) == 1 && attributes[0] == "all" {
		return nil, true, nil
	}
	allowed := map[string]bool{
		"epoch": true, "version": true, "release": true, "arch": true,
		"install_date": true, "install_date_time_t": true,
	}
	for _, attribute := range attributes {
		if !allowed[attribute] {
			return nil, false, fmt.Errorf("unsupported diff_attr %q", attribute)
		}
	}
	return attributes, false, nil
}

func yumUpgradeRefreshDB(ctx context.Context, rt *runtime.Runtime, manager string, options []string, checkUpdate bool) error {
	clean := append([]string{manager, "--quiet", "--assumeyes", "clean", "expire-cache"}, options...)
	commands := [][]string{clean}
	if checkUpdate {
		check := []string{manager, "--quiet", "--assumeyes", "check-update"}
		if yumRHEL7(rt) {
			check = append(check, "--setopt=autocheck_running_kernel=false")
		}
		commands = append(commands, append(check, options...))
	}
	for _, argv := range commands {
		if _, err := yumUpgradeRun(ctx, rt, argv); err != nil {
			return err
		}
	}
	return nil
}

func yumUpgradeRuntimeArch(rt *runtime.Runtime) (string, error) {
	if rt == nil {
		return "", errors.New("YUM upgrade requires a runtime")
	}
	if rt.Facts == nil {
		return "", errors.New("YUM upgrade requires CPU facts")
	}
	osarch := rt.Facts.CPU().Arch
	if osarch == "" || strings.TrimSpace(osarch) != osarch || strings.IndexByte(osarch, 0) >= 0 {
		return "", errors.New("YUM upgrade requires a valid CPU architecture")
	}
	if !yumUpgradeRunnerAvailable(rt.Runner) {
		return "", errors.New("YUM upgrade requires a runner")
	}
	return osarch, nil
}

func yumUpgradeRunnerAvailable(r process.Runner) bool {
	return RunnerAvailable(r)
}

func yumUpgradeRun(ctx context.Context, rt *runtime.Runtime, argv []string) (process.CommandResult, error) {
	if rt == nil || !yumUpgradeRunnerAvailable(rt.Runner) {
		return process.CommandResult{}, errors.New("YUM upgrade requires a runner")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{}, err
	}
	command := runtime.Command(argv...)
	command.Shell = false
	command.MaxStdoutBytes, command.MaxStderrBytes = yumUpgradeOutputLimit, yumUpgradeOutputLimit
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return result, result.Err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if result.StdoutTruncated || result.StderrTruncated || len(result.Stdout) > yumUpgradeOutputLimit || len(result.Stderr) > yumUpgradeOutputLimit {
		return result, process.ErrOutputLimit
	}
	return result, nil
}

type yumUpgradePackage struct {
	name            string
	epoch           any
	version         string
	release         any
	arch            string
	installDate     any
	installDateTime any
}

func yumUpgradeListPackages(ctx context.Context, rt *runtime.Runtime, osarch string, attributes []string, all bool) (map[string]any, error) {
	result, err := yumUpgradeRun(ctx, rt, []string{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", yumInstalledQueryFormat})
	if err != nil {
		return nil, err
	}
	packages, err := yumUpgradePackages(string(result.Stdout), osarch)
	if err != nil {
		return nil, err
	}
	grouped := map[string][]yumUpgradePackage{}
	order := []string{}
	for _, packageInfo := range packages {
		if _, exists := grouped[packageInfo.name]; !exists {
			order = append(order, packageInfo.name)
		}
		grouped[packageInfo.name] = append(grouped[packageInfo.name], packageInfo)
	}
	for _, name := range order {
		versions := grouped[name]
		sort.SliceStable(versions, func(i, j int) bool { return versions[i].version < versions[j].version })
		grouped[name] = versions
	}
	if len(attributes) == 0 && !all {
		ret := make(map[string]any, len(grouped))
		for _, name := range order {
			versions := grouped[name]
			formatted := make([]string, len(versions))
			for i, version := range versions {
				formatted[i] = yumUpgradeVersion(version)
			}
			ret[name] = strings.Join(formatted, ",")
		}
		return ret, nil
	}

	requested := map[string]bool{"version": true, "arch": true}
	if all {
		for _, attribute := range []string{"epoch", "version", "release", "arch", "install_date", "install_date_time_t"} {
			requested[attribute] = true
		}
	} else {
		for _, attribute := range attributes {
			requested[attribute] = true
		}
	}
	ret := map[string]any{}
	for _, name := range order {
		for _, packageInfo := range grouped[name] {
			value := yumUpgradePackageAttributes(packageInfo, requested)
			key := packageInfo.name
			if parsed := yumParseArch(packageInfo.name); parsed["name"] != "" && parsed["arch"] == packageInfo.arch {
				key = parsed["name"].(string)
			}
			values, _ := ret[key].([]map[string]any)
			ret[key] = append(values, value)
		}
	}
	return ret, nil
}

func yumUpgradePackageAttributes(packageInfo yumUpgradePackage, requested map[string]bool) map[string]any {
	value := map[string]any{}
	if requested["epoch"] {
		value["epoch"] = packageInfo.epoch
	}
	if requested["version"] {
		value["version"] = packageInfo.version
	}
	if requested["release"] {
		value["release"] = packageInfo.release
	}
	if requested["arch"] {
		value["arch"] = packageInfo.arch
	}
	if requested["install_date"] {
		value["install_date"] = packageInfo.installDate
	}
	if requested["install_date_time_t"] {
		value["install_date_time_t"] = packageInfo.installDateTime
	}
	return value
}

func yumUpgradePackages(output, osarch string) ([]yumUpgradePackage, error) {
	packages := []yumUpgradePackage{}
	for _, line := range sourceSplitLines(output) {
		fields := strings.Split(line, "_|-")
		if len(fields) != 7 {
			continue
		}
		name, epoch, version, release, arch, installTime := fields[0], fields[1], fields[2], fields[3], fields[4], fields[6]
		fullVersion := version
		if release != "" {
			fullVersion += "-" + release
		}
		if epoch != "(none)" && epoch != "0" {
			fullVersion = epoch + ":" + fullVersion
		}
		attributeEpoch, attributeVersion, attributeRelease := any(nil), fullVersion, any(nil)
		if before, after, ok := strings.Cut(attributeVersion, ":"); ok {
			attributeEpoch, attributeVersion = before, after
		}
		if before, after, ok := strings.Cut(attributeVersion, "-"); ok {
			attributeVersion, attributeRelease = before, after
		}
		installDate, installDateTime := any(nil), any(nil)
		if installTime != "(none)" && installTime != "0" {
			seconds, err := strconv.ParseInt(installTime, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("rpm: invalid install time %q", installTime)
			}
			installDate = time.Unix(seconds, 0).UTC().Format("2006-01-02T15:04:05+00:00Z")
			installDateTime = seconds
		}
		packages = append(packages, yumUpgradePackage{
			name: yumResolvedRecordName(name, arch, osarch), epoch: attributeEpoch,
			version: attributeVersion, release: attributeRelease, arch: arch,
			installDate: installDate, installDateTime: installDateTime,
		})
	}
	return packages, nil
}

func yumUpgradeVersion(packageInfo yumUpgradePackage) string {
	version := packageInfo.version
	if epoch, ok := packageInfo.epoch.(string); ok && epoch != "" {
		version = epoch + ":" + version
	}
	if release, ok := packageInfo.release.(string); ok && release != "" {
		version += "-" + release
	}
	return version
}

func yumUpgradeComparePackages(old, new map[string]any) map[string]any {
	changes := map[string]any{}
	for name, before := range old {
		after, present := new[name]
		if !present {
			changes[name] = map[string]any{"old": before, "new": ""}
			continue
		}
		if !reflect.DeepEqual(before, after) {
			changes[name] = map[string]any{"old": before, "new": after}
		}
	}
	for name, after := range new {
		if _, present := old[name]; !present {
			changes[name] = map[string]any{"old": "", "new": after}
		}
	}
	return changes
}
