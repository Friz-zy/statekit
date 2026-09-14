// Package solarispkg implements the legacy Solaris SVR4 pkgadd execution
// module from Salt's solarispkg.py surface.
//
// The module is deliberately kept separate from the IPS implementation. Both
// expose the canonical pkg.* names, but a runtime must select one provider
// rather than registering two implementations for the same name.
package solarispkg

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	commandTimeout = 30 * time.Second
	outputLimit    = 4 << 20
	fileLimit      = 1 << 20
	maxTargets     = 1024
)

var (
	errRunnerUnavailable = errors.New("solarispkg: runner unavailable")
	errFSUnavailable     = errors.New("solarispkg: filesystem unavailable")
)

type solarisOnly struct{}

func (solarisOnly) Platforms() []string { return []string{"solaris"} }

// run is the only subprocess boundary in this provider. The legacy Salt
// module uses shell-free cmd.run/cmd.run_all calls; keeping the same property
// here prevents package names and paths from becoming shell syntax.
func run(ctx context.Context, rt *runtime.Runtime, argv ...string) (process.CommandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if rt == nil || rt.Runner == nil {
		return process.CommandResult{ExitCode: -1}, errRunnerUnavailable
	}
	if err := validateArgv(argv); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	command := runtime.Command(argv...)
	command.Shell = false
	command.Timeout = commandTimeout
	command.MaxStdoutBytes = outputLimit
	command.MaxStderrBytes = outputLimit
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return result, result.Err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stdout) > outputLimit || len(result.Stderr) > outputLimit {
		return result, process.ErrOutputLimit
	}
	return result, nil
}

func validateArgv(argv []string) error {
	if len(argv) == 0 {
		return errors.New("solarispkg: empty command")
	}
	total := 0
	for _, arg := range argv {
		if strings.IndexByte(arg, 0) >= 0 {
			return errors.New("solarispkg: command argument contains NUL")
		}
		total += len(arg)
		if total > runtime.MaxCommandInputBytes {
			return runtime.ErrCommandInputLimit
		}
	}
	return nil
}

func option(options map[string]any, key string) any {
	if options == nil {
		return nil
	}
	return options[key]
}

func pythonTruthy(value any) bool {
	if value == nil {
		return false
	}
	switch value := value.(type) {
	case bool:
		return value
	case string:
		return value != ""
	case int:
		return value != 0
	case int8:
		return value != 0
	case int16:
		return value != 0
	case int32:
		return value != 0
	case int64:
		return value != 0
	case uint:
		return value != 0
	case uint8:
		return value != 0
	case uint16:
		return value != 0
	case uint32:
		return value != 0
	case uint64:
		return value != 0
	case float32:
		return value != 0
	case float64:
		return value != 0
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice:
		return reflected.Len() != 0
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Pointer:
		return !reflected.IsNil()
	default:
		return true
	}
}

// saltIsTrue mirrors the conversion sequence in the pinned
// salt.utils.data.is_true implementation. In particular, a numeric fraction
// is int-converted before float conversion: 0.5 therefore becomes 0 and is
// false, while the string "0.5" skips int conversion and is true as a float.
func saltIsTrue(value any) bool {
	if number, ok := saltIntConversion(value); ok {
		return number > 0
	}
	if number, ok := saltFloatConversion(value); ok {
		return number > 0
	}
	if text, ok := value.(string); ok {
		return strings.ToLower(text) == "true"
	}
	reflected := reflect.ValueOf(value)
	if reflected.IsValid() && (reflected.Kind() == reflect.Complex64 || reflected.Kind() == reflect.Complex128) {
		return reflected.Complex() != 0
	}
	return pythonTruthy(value)
}

func saltIntConversion(value any) (int64, bool) {
	switch value := value.(type) {
	case nil:
		return 0, false
	case bool:
		if value {
			return 1, true
		}
		return 0, true
	case string:
		number, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		return number, err == nil
	}
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() {
		return 0, false
	}
	switch reflected.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return reflected.Int(), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if reflected.Uint() == 0 {
			return 0, true
		}
		return 1, true
	case reflect.Float32, reflect.Float64:
		number := reflected.Float()
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return 0, false
		}
		if math.Trunc(number) > 0 {
			return 1, true
		}
		return 0, true
	default:
		return 0, false
	}
}

func saltFloatConversion(value any) (float64, bool) {
	if text, ok := value.(string); ok {
		number, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
		return number, err == nil
	}
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() {
		return 0, false
	}
	switch reflected.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(reflected.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return float64(reflected.Uint()), true
	case reflect.Float32, reflect.Float64:
		return reflected.Float(), true
	default:
		return 0, false
	}
}

// currentZoneOnly mirrors the source membership test instead of applying
// Salt's general boolean normalization. Python's True compares equal to the
// numeric value 1, but the string "1" is not a member of the tuple.
func currentZoneOnly(value any) bool {
	switch value := value.(type) {
	case bool:
		return value
	case string:
		return value == "True"
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return reflected.Int() == 1
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return reflected.Uint() == 1
	case reflect.Float32, reflect.Float64:
		return reflected.Float() == 1
	default:
		return false
	}
}

func optionString(options map[string]any, key, fallback string) string {
	if value, ok := options[key]; ok {
		return saltString(value)
	}
	return fallback
}

func saltString(value any) string {
	switch value := value.(type) {
	case nil:
		return "None"
	case bool:
		if value {
			return "True"
		}
		return "False"
	default:
		return fmt.Sprint(value)
	}
}

// parsePkginfo parses the two-line records emitted by `pkginfo -x`. The
// pinned Salt implementation indexes each pair directly; malformed records
// are errors here instead of panics or partial package state.
func parsePkginfo(output []byte) (map[string][]string, error) {
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	packages := make(map[string][]string)
	for index := 0; index < len(lines); index += 2 {
		if index+1 >= len(lines) {
			return nil, fmt.Errorf("solarispkg: pkginfo record %d has no version row", index/2+1)
		}
		nameFields := strings.Fields(lines[index])
		versionFields := strings.Fields(lines[index+1])
		if len(nameFields) < 1 || len(versionFields) < 2 {
			return nil, fmt.Errorf("solarispkg: malformed pkginfo record %d", index/2+1)
		}
		name := nameFields[0]
		version := versionFields[1]
		packages[name] = append(packages[name], version)
	}
	for name, versions := range packages {
		packages[name] = uniqueSorted(versions)
	}
	return packages, nil
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func stringifyVersions(packages map[string][]string, versionsAsList bool) map[string]any {
	result := make(map[string]any, len(packages))
	for name, versions := range packages {
		versions = uniqueSorted(versions)
		if versionsAsList {
			result[name] = append([]string(nil), versions...)
		} else {
			result[name] = strings.Join(versions, ",")
		}
	}
	return result
}

func listPackages(ctx context.Context, rt *runtime.Runtime, versionsAsList any, kwargs map[string]any) (map[string]any, error) {
	if saltIsTrue(option(kwargs, "removed")) || saltIsTrue(option(kwargs, "purge_desired")) {
		return map[string]any{}, nil
	}
	result, err := run(ctx, rt, "/usr/bin/pkginfo", "-x")
	if err != nil {
		return nil, err
	}
	packages, err := parsePkginfo(result.Stdout)
	if err != nil {
		return nil, err
	}
	return stringifyVersions(packages, saltIsTrue(versionsAsList)), nil
}

func listPackageVersions(ctx context.Context, rt *runtime.Runtime, kwargs map[string]any) (map[string][]string, error) {
	value, err := listPackages(ctx, rt, true, kwargs)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]string, len(value))
	for name, versions := range value {
		items, ok := versions.([]string)
		if !ok {
			return nil, fmt.Errorf("solarispkg: unexpected version type for %q", name)
		}
		result[name] = append([]string(nil), items...)
	}
	return result, nil
}

func matchPackageNames(packages map[string][]string, pattern string) []string {
	if !strings.Contains(pattern, "*") {
		return []string{pattern}
	}
	result := []string{}
	for name := range packages {
		matched, err := filepath.Match(pattern, name)
		if err == nil && matched {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result
}

func packageVersion(ctx context.Context, rt *runtime.Runtime, names []string, kwargs map[string]any) (any, error) {
	if len(names) == 0 {
		return map[string]any{}, nil
	}
	packages, err := listPackageVersions(ctx, rt, kwargs)
	if err != nil {
		return nil, err
	}
	result := make(map[string]any)
	pkgGlob := false
	for _, name := range names {
		if strings.Contains(name, "*") {
			pkgGlob = true
		}
		matches := matchPackageNames(packages, name)
		if !strings.Contains(name, "*") {
			matches = []string{name}
		}
		for _, match := range matches {
			versions := packages[match]
			if saltIsTrue(option(kwargs, "versions_as_list")) {
				result[match] = append([]string{}, versions...)
			} else {
				result[match] = strings.Join(versions, ",")
			}
		}
	}
	if len(result) == 1 && !pkgGlob {
		for _, version := range result {
			return version, nil
		}
	}
	return result, nil
}

func packageChanges(old, current map[string]any) map[string]any {
	changes := map[string]any{}
	for name, oldValue := range old {
		newValue, ok := current[name]
		if !ok {
			changes[name] = map[string]any{"old": fmt.Sprint(oldValue), "new": ""}
			continue
		}
		if fmt.Sprint(oldValue) != fmt.Sprint(newValue) {
			changes[name] = map[string]any{"old": fmt.Sprint(oldValue), "new": fmt.Sprint(newValue)}
		}
	}
	for name, newValue := range current {
		if _, ok := old[name]; !ok {
			changes[name] = map[string]any{"old": "", "new": fmt.Sprint(newValue)}
		}
	}
	return changes
}

// mapEntry accepts the one-element dictionaries used by Salt's pkgs/sources
// arguments without relying on map iteration order for malformed input.
func mapEntry(value any) (string, any, bool) {
	switch item := value.(type) {
	case map[string]any:
		if len(item) != 1 {
			return "", nil, false
		}
		keys := make([]string, 0, 1)
		for key := range item {
			keys = append(keys, key)
		}
		return keys[0], item[keys[0]], true
	case map[string]string:
		if len(item) != 1 {
			return "", nil, false
		}
		for key, entry := range item {
			return key, entry, true
		}
	}
	return "", nil, false
}

func valuesAsSlice(value any) []any {
	switch item := value.(type) {
	case nil:
		return nil
	case []any:
		return append([]any(nil), item...)
	case []string:
		result := make([]any, len(item))
		for index := range item {
			result[index] = item[index]
		}
		return result
	default:
		return []any{value}
	}
}

func packageTargets(name *string, pkgs any) ([]string, error) {
	if pkgs != nil {
		values := valuesAsSlice(pkgs)
		if len(values) == 0 {
			return nil, nil
		}
		result := make([]string, 0, len(values))
		for index, value := range values {
			if key, _, ok := mapEntry(value); ok {
				if key == "" {
					return nil, fmt.Errorf("solarispkg: empty package name at index %d", index)
				}
				result = append(result, key)
				continue
			}
			text := strings.TrimSpace(fmt.Sprint(value))
			if text == "" {
				return nil, fmt.Errorf("solarispkg: empty package name at index %d", index)
			}
			result = append(result, text)
		}
		if len(result) > maxTargets {
			return nil, fmt.Errorf("solarispkg: package target count exceeds %d", maxTargets)
		}
		return result, nil
	}
	if name == nil || strings.TrimSpace(*name) == "" {
		return nil, nil
	}
	parts := strings.Split(*name, ",")
	result := make([]string, 0, len(parts))
	for index, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("solarispkg: empty package name at index %d", index)
		}
		result = append(result, part)
	}
	if len(result) > maxTargets {
		return nil, fmt.Errorf("solarispkg: package target count exceeds %d", maxTargets)
	}
	return result, nil
}

func sourceTargets(sources any) ([]string, error) {
	values := valuesAsSlice(sources)
	if len(values) == 0 {
		return nil, nil
	}
	result := make([]string, 0, len(values))
	for index, value := range values {
		_, source, ok := mapEntry(value)
		if !ok {
			return nil, fmt.Errorf("solarispkg: source %d must be a one-element mapping", index)
		}
		text := strings.TrimSpace(fmt.Sprint(source))
		if text == "" {
			return nil, fmt.Errorf("solarispkg: source %d is empty", index)
		}
		// Remote protocols would require cp.cache_file and network access. The
		// isolated provider intentionally accepts only already-local payloads.
		if strings.Contains(text, "://") && !strings.HasPrefix(text, "file://") {
			return nil, fmt.Errorf("solarispkg: remote source %q is unsupported", text)
		}
		text = strings.TrimPrefix(text, "file://")
		if !path.IsAbs(text) {
			return nil, fmt.Errorf("solarispkg: source %q is not an absolute local path", text)
		}
		result = append(result, text)
	}
	if len(result) > maxTargets {
		return nil, fmt.Errorf("solarispkg: source count exceeds %d", maxTargets)
	}
	return result, nil
}

func adminFile(ctx context.Context, rt *runtime.Runtime, kwargs map[string]any) (string, func(), error) {
	if source, ok := kwargs["admin_source"]; ok && source != nil {
		text := strings.TrimSpace(fmt.Sprint(source))
		if text == "" {
			return "", func() {}, errors.New("solarispkg: admin_source is empty")
		}
		if strings.Contains(text, "://") && !strings.HasPrefix(text, "file://") {
			return "", func() {}, fmt.Errorf("solarispkg: remote admin_source %q is unsupported", text)
		}
		text = strings.TrimPrefix(text, "file://")
		if !path.IsAbs(text) {
			return "", func() {}, fmt.Errorf("solarispkg: admin_source %q is not an absolute local path", text)
		}
		return text, func() {}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", func() {}, err
	}
	if rt == nil || rt.FS == nil {
		return "", func() {}, errFSUnavailable
	}
	content := strings.Join([]string{
		"email=" + optionString(kwargs, "email", ""),
		"instance=" + optionString(kwargs, "instance", "quit"),
		"partial=" + optionString(kwargs, "partial", "nocheck"),
		"runlevel=" + optionString(kwargs, "runlevel", "nocheck"),
		"idepend=" + optionString(kwargs, "idepend", "nocheck"),
		"rdepend=" + optionString(kwargs, "rdepend", "nocheck"),
		"space=" + optionString(kwargs, "space", "nocheck"),
		"setuid=" + optionString(kwargs, "setuid", "nocheck"),
		"conflict=" + optionString(kwargs, "conflict", "nocheck"),
		"action=" + optionString(kwargs, "action", "nocheck"),
		"basedir=" + optionString(kwargs, "basedir", "default"),
	}, "\n") + "\n"
	if len(content) > fileLimit {
		return "", func() {}, runtime.ErrCommandInputLimit
	}
	directory, err := rt.FS.MkdirTemp("/tmp", "salt-")
	if err != nil {
		return "", func() {}, err
	}
	admin := path.Join(directory, "admin")
	if err := rt.FS.WriteFile(admin, []byte(content), 0o600); err != nil {
		_ = rt.FS.Remove(directory)
		return "", func() {}, err
	}
	cleanup := func() {
		_ = rt.FS.Remove(admin)
		_ = rt.FS.Remove(directory)
	}
	return admin, cleanup, nil
}

func commandFailure(operation string, errorsSeen []string, changes map[string]any) error {
	if len(errorsSeen) == 0 {
		return nil
	}
	return fmt.Errorf("Problem encountered %s package(s): %s (changes: %v)", operation, strings.Join(errorsSeen, "; "), changes)
}

// ---------------------------------------------------------------------------
// list/latest/upgrade/version

type ListPkgsArgs struct {
	VersionsAsList bool           `statekit:"name=versions_as_list"`
	Kwargs         map[string]any `statekit:"name=kwargs"`
}

type listPkgsFunc struct{ solarisOnly }

func (listPkgsFunc) Name() string { return "pkg.list_pkgs" }
func (listPkgsFunc) Args() any    { return ListPkgsArgs{} }
func (listPkgsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*ListPkgsArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.list_pkgs: expected *solarispkg.ListPkgsArgs, got %T", args)
	}
	return listPackages(ctx, rt, a.VersionsAsList, a.Kwargs)
}

type LatestVersionArgs struct {
	Names  []string       `statekit:"name=names"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type latestVersionFunc struct{ solarisOnly }

func (latestVersionFunc) Name() string { return "pkg.latest_version" }
func (latestVersionFunc) Args() any    { return LatestVersionArgs{} }
func (latestVersionFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*LatestVersionArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.latest_version: expected *solarispkg.LatestVersionArgs, got %T", args)
	}
	if len(a.Names) == 0 {
		return "", nil
	}
	if len(a.Names) == 1 {
		return "", nil
	}
	result := make(map[string]any, len(a.Names))
	for _, name := range a.Names {
		result[name] = ""
	}
	return result, nil
}

type UpgradeAvailableArgs struct {
	Name   string         `statekit:"required"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type upgradeAvailableFunc struct{ solarisOnly }

func (upgradeAvailableFunc) Name() string { return "pkg.upgrade_available" }
func (upgradeAvailableFunc) Args() any    { return UpgradeAvailableArgs{} }
func (upgradeAvailableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*UpgradeAvailableArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.upgrade_available: expected *solarispkg.UpgradeAvailableArgs, got %T", args)
	}
	value, err := (latestVersionFunc{}).Execute(ctx, rt, &LatestVersionArgs{Names: []string{a.Name}, Kwargs: a.Kwargs})
	if err != nil {
		return nil, err
	}
	return value.(string) != "", nil
}

type VersionArgs struct {
	Names  []string       `statekit:"name=names"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type versionFunc struct{ solarisOnly }

func (versionFunc) Name() string { return "pkg.version" }
func (versionFunc) Args() any    { return VersionArgs{} }
func (versionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*VersionArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.version: expected *solarispkg.VersionArgs, got %T", args)
	}
	return packageVersion(ctx, rt, a.Names, a.Kwargs)
}

// ---------------------------------------------------------------------------
// install/remove/purge

type InstallArgs struct {
	Name    *string        `statekit:"name=name"`
	Sources []any          `statekit:"name=sources"`
	Saltenv string         `statekit:"name=saltenv"`
	Kwargs  map[string]any `statekit:"name=kwargs"`
}

type installFunc struct{ solarisOnly }

func (installFunc) Name() string { return "pkg.install" }
func (installFunc) Args() any    { return InstallArgs{} }
func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (result any, err error) {
	a, ok := args.(*InstallArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.install: expected *solarispkg.InstallArgs, got %T", args)
	}
	if len(a.Sources) == 0 {
		return map[string]any{}, nil
	}
	targets, err := sourceTargets(a.Sources)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return map[string]any{}, nil
	}
	admin, cleanup, err := adminFile(ctx, rt, a.Kwargs)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	old, err := listPackages(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	prefix := []string{"/usr/sbin/pkgadd", "-n", "-a", admin}
	if currentZoneOnly(option(a.Kwargs, "current_zone_only")) {
		// The trailing space is intentional: it is the exact single argv
		// element appended by the pinned Python module.
		prefix = append(prefix, "-G ")
	}
	errorsSeen := []string{}
	for _, target := range targets {
		argv := append(append([]string(nil), prefix...), "-d", target, "all")
		commandResult, runErr := run(ctx, rt, argv...)
		if runErr != nil {
			return nil, runErr
		}
		if commandResult.ExitCode != 0 && len(commandResult.Stderr) != 0 {
			errorsSeen = append(errorsSeen, string(commandResult.Stderr))
		}
	}
	current, err := listPackages(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	changes := packageChanges(old, current)
	if err := commandFailure("installing", errorsSeen, changes); err != nil {
		return nil, err
	}
	return changes, nil
}

type RemoveArgs struct {
	Name    *string        `statekit:"name=name"`
	Pkgs    []any          `statekit:"name=pkgs"`
	Saltenv string         `statekit:"name=saltenv"`
	Kwargs  map[string]any `statekit:"name=kwargs"`
}

type removeFunc struct{ solarisOnly }

func (removeFunc) Name() string { return "pkg.remove" }
func (removeFunc) Args() any    { return RemoveArgs{} }
func (removeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (result any, err error) {
	a, ok := args.(*RemoveArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.remove: expected *solarispkg.RemoveArgs, got %T", args)
	}
	var rawPkgs any
	if len(a.Pkgs) > 0 {
		rawPkgs = a.Pkgs
	}
	targets, err := packageTargets(a.Name, rawPkgs)
	if err != nil {
		return nil, err
	}
	old, err := listPackages(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	installed := make([]string, 0, len(targets))
	for _, target := range targets {
		if _, ok := old[target]; ok {
			installed = append(installed, target)
		}
	}
	if len(installed) == 0 {
		return map[string]any{}, nil
	}
	admin, cleanup, err := adminFile(ctx, rt, a.Kwargs)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	argv := []string{"/usr/sbin/pkgrm", "-n", "-a", admin}
	argv = append(argv, installed...)
	commandResult, err := run(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	errorsSeen := []string{}
	if commandResult.ExitCode != 0 && len(commandResult.Stderr) != 0 {
		errorsSeen = append(errorsSeen, string(commandResult.Stderr))
	}
	current, err := listPackages(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	changes := packageChanges(old, current)
	if err := commandFailure("removing", errorsSeen, changes); err != nil {
		return nil, err
	}
	return changes, nil
}

type PurgeArgs struct {
	Name   *string        `statekit:"name=name"`
	Pkgs   []any          `statekit:"name=pkgs"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type purgeFunc struct{ solarisOnly }

func (purgeFunc) Name() string { return "pkg.purge" }
func (purgeFunc) Args() any    { return PurgeArgs{} }
func (purgeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*PurgeArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.purge: expected *solarispkg.PurgeArgs, got %T", args)
	}
	return (removeFunc{}).Execute(ctx, rt, &RemoveArgs{Name: a.Name, Pkgs: a.Pkgs, Kwargs: a.Kwargs})
}

// Register installs the complete public solarispkg surface. The functions
// carry their Solaris capability even when this helper is used by Linux-side
// registry tests; ExecRegistry then returns UnsupportedError without touching
// the Runner on Linux.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		listPkgsFunc{}, latestVersionFunc{}, upgradeAvailableFunc{}, versionFunc{},
		installFunc{}, removeFunc{}, purgeFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
