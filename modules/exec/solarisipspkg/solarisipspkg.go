// Package solarisipspkg implements Salt's Solaris 11+ IPS package execution
// module. It owns the canonical pkg.* functions when the runtime selects the
// IPS provider; the legacy SVR4 implementation is a separate package.
package solarisipspkg

import (
	"context"
	"errors"
	"fmt"
	"math"
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
	maxTargets     = 1024
)

var (
	errRunnerUnavailable = errors.New("solarisipspkg: runner unavailable")
	errIPSUnavailable    = errors.New("solarisipspkg: pkg command unavailable")
)

// The pinned module spells most commands /bin/pkg and uses PATH-resolved pkg
// for the operations that pass an argv list to Salt's cmd helpers. Keep both
// spellings: command paths are part of the provider contract.
const (
	ipsBinary     = "/bin/pkg"
	ipsPathBinary = "pkg"
)

type solarisOnly struct{}

func (solarisOnly) Platforms() []string { return []string{"solaris"} }

// run is the sole IPS subprocess boundary. It preserves completed retcodes as
// data because several Salt functions intentionally inspect them, while
// runner failures, cancellation, and bounded-output violations are errors.
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
	if available, ok := rt.Runner.(process.CommandAvailability); ok && !available.CommandAvailable("pkg") {
		return process.CommandResult{ExitCode: -1}, errIPSUnavailable
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
		return errors.New("solarisipspkg: empty command")
	}
	total := 0
	for _, arg := range argv {
		if strings.IndexByte(arg, 0) >= 0 {
			return errors.New("solarisipspkg: command argument contains NUL")
		}
		total += len(arg)
		if total > runtime.MaxCommandInputBytes {
			return runtime.ErrCommandInputLimit
		}
	}
	return nil
}

func truthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "y", "on", "t", "enabled":
			return true
		default:
			return false
		}
	case []any:
		return len(v) != 0
	case []string:
		return len(v) != 0
	default:
		return true
	}
}

// ips_pkg_return_values is the source module's retcode vocabulary. Unknown
// future codes are reported without indexing a map and panicking.
var ipsReturnValues = map[int]string{
	0: "Command succeeded.",
	1: "An error occurred.",
	2: "Invalid command line options were specified.",
	3: "Multiple operations were requested, but only some of them succeeded.",
	4: "No changes were made - nothing to do.",
	5: "The requested operation cannot be performed on a  live image.",
	6: "The requested operation cannot be completed because the licenses for the packages being installed or updated have not been accepted.",
	7: "The image is currently in use by another process and cannot be modified.",
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

func ipsRetcodeDescription(code int) string {
	if description, ok := ipsReturnValues[code]; ok {
		return description
	}
	return fmt.Sprintf("pkg exited with code %d", code)
}

type ipsRecord struct {
	Name    string
	Version string
}

// ipsGetPkgname and ipsGetPkgversion are strict, panic-free counterparts of
// the two source helpers. A line must have an FMRI token and an @ separator.
func ipsGetPkgname(line string) (string, error) {
	record, err := parseIPSRecord(line)
	if err != nil {
		return "", err
	}
	return record.Name, nil
}

func ipsGetPkgversion(line string) (string, error) {
	record, err := parseIPSRecord(line)
	if err != nil {
		return "", err
	}
	return record.Version, nil
}

func parseIPSRecord(line string) (ipsRecord, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ipsRecord{}, errors.New("solarisipspkg: empty IPS listing row")
	}
	parts := strings.SplitN(fields[0], "@", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return ipsRecord{}, fmt.Errorf("solarisipspkg: malformed IPS listing row %q", line)
	}
	return ipsRecord{Name: strings.TrimSpace(parts[0]), Version: strings.TrimSpace(parts[1])}, nil
}

func parseIPSRecords(output []byte) ([]ipsRecord, error) {
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	records := make([]ipsRecord, 0, len(lines))
	for index, line := range lines {
		record, err := parseIPSRecord(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", index+1, err)
		}
		records = append(records, record)
	}
	return records, nil
}

func recordsAsPackages(records []ipsRecord, versionsAsList bool, sortVersions bool) map[string]any {
	versions := make(map[string][]string)
	for _, record := range records {
		versions[record.Name] = append(versions[record.Name], record.Version)
	}
	result := make(map[string]any, len(versions))
	for name, values := range versions {
		if sortVersions {
			values = uniqueSorted(values)
		}
		if versionsAsList {
			result[name] = append([]string(nil), values...)
		} else {
			result[name] = strings.Join(values, ",")
		}
	}
	return result
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

func listPackages(ctx context.Context, rt *runtime.Runtime, versionsAsList any, kwargs map[string]any) (map[string]any, error) {
	if saltIsTrue(option(kwargs, "removed")) || saltIsTrue(option(kwargs, "purge_desired")) {
		return map[string]any{}, nil
	}
	result, err := run(ctx, rt, ipsBinary, "list", "-Hv")
	if err != nil {
		return nil, err
	}
	records, err := parseIPSRecords(result.Stdout)
	if err != nil {
		return nil, err
	}
	return recordsAsPackages(records, pythonTruthy(versionsAsList), true), nil
}

func listPackageVersions(ctx context.Context, rt *runtime.Runtime, names []string) ([]ipsRecord, error) {
	argv := []string{ipsBinary, "list", "-Hv"}
	argv = append(argv, names...)
	result, err := run(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	return parseIPSRecords(result.Stdout)
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

func versionMap(records []ipsRecord, names []string) (map[string]any, []string) {
	result := make(map[string]any, len(records)+len(names))
	order := make([]string, 0, len(records)+len(names))
	for _, record := range records {
		if _, seen := result[record.Name]; !seen {
			order = append(order, record.Name)
		}
		result[record.Name] = record.Version
	}
	for _, name := range names {
		if _, seen := result[name]; !seen {
			order = append(order, name)
			result[name] = ""
		}
	}
	return result, order
}

func singleVersion(result map[string]any, order []string) string {
	if len(order) == 0 {
		return ""
	}
	return fmt.Sprint(result[order[0]])
}

func commandError(operation string, result process.CommandResult, changes map[string]any) error {
	if result.ExitCode == 0 {
		return nil
	}
	stderr := strings.TrimSpace(string(result.Stderr))
	if stderr == "" {
		stderr = ipsRetcodeDescription(result.ExitCode)
	}
	return fmt.Errorf("Error occurred %s package(s): %s (retcode: %s; changes: %v)", operation, stderr, ipsRetcodeDescription(result.ExitCode), changes)
}

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
		sort.Strings(keys)
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

func installTargets(name *string, pkgs []any, version *string) ([]string, error) {
	if len(pkgs) > 0 {
		if len(pkgs) > maxTargets {
			return nil, fmt.Errorf("solarisipspkg: package target count exceeds %d", maxTargets)
		}
		result := make([]string, 0, len(pkgs))
		for index, value := range pkgs {
			if key, entry, ok := mapEntry(value); ok {
				if key == "" {
					return nil, fmt.Errorf("solarisipspkg: empty package name at index %d", index)
				}
				if pythonTruthy(entry) {
					result = append(result, key+"@"+saltString(entry))
				} else {
					result = append(result, key)
				}
				continue
			}
			text := strings.TrimSpace(fmt.Sprint(value))
			if text == "" {
				return nil, fmt.Errorf("solarisipspkg: empty package name at index %d", index)
			}
			result = append(result, text)
		}
		return result, nil
	}
	if name == nil || strings.TrimSpace(*name) == "" {
		return nil, nil
	}
	target := strings.TrimSpace(*name)
	if version != nil && *version != "" {
		target += "@" + *version
	}
	return []string{target}, nil
}

func removeTargets(name *string, pkgs []any) ([]string, error) {
	if len(pkgs) > 0 {
		if len(pkgs) > maxTargets {
			return nil, fmt.Errorf("solarisipspkg: package target count exceeds %d", maxTargets)
		}
		result := make([]string, 0, len(pkgs))
		for index, value := range pkgs {
			if key, _, ok := mapEntry(value); ok {
				if key == "" {
					return nil, fmt.Errorf("solarisipspkg: empty package name at index %d", index)
				}
				result = append(result, key)
				continue
			}
			text := strings.TrimSpace(fmt.Sprint(value))
			if text == "" {
				return nil, fmt.Errorf("solarisipspkg: empty package name at index %d", index)
			}
			result = append(result, text)
		}
		return result, nil
	}
	if name == nil || strings.TrimSpace(*name) == "" {
		return nil, nil
	}
	return []string{strings.TrimSpace(*name)}, nil
}

// ---------------------------------------------------------------------------
// refresh/upgrade/list/version

type RefreshDBArgs struct {
	Full   bool           `statekit:"name=full"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type refreshDBFunc struct{ solarisOnly }

func (refreshDBFunc) Name() string { return "pkg.refresh_db" }
func (refreshDBFunc) Args() any    { return RefreshDBArgs{} }
func (refreshDBFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*RefreshDBArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.refresh_db: expected *solarisipspkg.RefreshDBArgs, got %T", args)
	}
	argv := []string{ipsBinary, "refresh"}
	if truthy(a.Full) {
		argv = append(argv, "--full")
	}
	result, err := run(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
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
		return nil, fmt.Errorf("pkg.upgrade_available: expected *solarisipspkg.UpgradeAvailableArgs, got %T", args)
	}
	result, err := run(ctx, rt, ipsPathBinary, "list", "-Huv", a.Name)
	if err != nil {
		return nil, err
	}
	records, err := parseIPSRecords(result.Stdout)
	if err != nil {
		return nil, err
	}
	values, _ := versionMap(records, nil)
	return values, nil
}

type ListUpgradesArgs struct {
	Refresh *bool          `statekit:"name=refresh"`
	Kwargs  map[string]any `statekit:"name=kwargs"`
}

type listUpgradesFunc struct{ solarisOnly }

func (listUpgradesFunc) Name() string { return "pkg.list_upgrades" }
func (listUpgradesFunc) Args() any    { return ListUpgradesArgs{} }
func (listUpgradesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*ListUpgradesArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.list_upgrades: expected *solarisipspkg.ListUpgradesArgs, got %T", args)
	}
	refresh := true
	if a.Refresh != nil {
		refresh = *a.Refresh
	}
	if refresh {
		if _, err := (refreshDBFunc{}).Execute(ctx, rt, &RefreshDBArgs{Full: true}); err != nil {
			return nil, err
		}
	}
	result, err := run(ctx, rt, ipsBinary, "list", "-Huv")
	if err != nil {
		return nil, err
	}
	records, err := parseIPSRecords(result.Stdout)
	if err != nil {
		return nil, err
	}
	values, _ := versionMap(records, nil)
	return values, nil
}

type UpgradeArgs struct {
	Refresh *bool          `statekit:"name=refresh"`
	Kwargs  map[string]any `statekit:"name=kwargs"`
}

type upgradeFunc struct{ solarisOnly }

func (upgradeFunc) Name() string { return "pkg.upgrade" }
func (upgradeFunc) Args() any    { return UpgradeArgs{} }
func (upgradeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*UpgradeArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.upgrade: expected *solarisipspkg.UpgradeArgs, got %T", args)
	}
	if a.Refresh != nil && *a.Refresh {
		if _, err := (refreshDBFunc{}).Execute(ctx, rt, &RefreshDBArgs{}); err != nil {
			return nil, err
		}
	}
	old, err := listPackages(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	result, err := run(ctx, rt, ipsPathBinary, "update", "-v", "--accept")
	if err != nil {
		return nil, err
	}
	current, err := listPackages(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	changes := packageChanges(old, current)
	if err := commandError("upgrading", result, changes); err != nil {
		return nil, err
	}
	return changes, nil
}

type ListPkgsArgs struct {
	// IPS receives this value through ordinary Python truthiness. Keep the
	// decoded union intact so non-empty strings such as "False" remain true.
	VersionsAsList any            `statekit:"name=versions_as_list"`
	Kwargs         map[string]any `statekit:"name=kwargs"`
}

type listPkgsFunc struct{ solarisOnly }

func (listPkgsFunc) Name() string { return "pkg.list_pkgs" }
func (listPkgsFunc) Args() any    { return ListPkgsArgs{} }
func (listPkgsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*ListPkgsArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.list_pkgs: expected *solarisipspkg.ListPkgsArgs, got %T", args)
	}
	return listPackages(ctx, rt, a.VersionsAsList, a.Kwargs)
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
		return nil, fmt.Errorf("pkg.version: expected *solarisipspkg.VersionArgs, got %T", args)
	}
	if len(a.Names) == 0 {
		return "", nil
	}
	records, err := listPackageVersions(ctx, rt, a.Names)
	if err != nil {
		return nil, err
	}
	values, order := versionMap(records, a.Names)
	if len(a.Names) == 1 {
		return singleVersion(values, order), nil
	}
	return values, nil
}

type LatestVersionArgs struct {
	Names  []string       `statekit:"name=names"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type latestVersionFunc struct{ solarisOnly }

func (latestVersionFunc) Name() string { return "pkg.latest_version" }
func (latestVersionFunc) Args() any    { return LatestVersionArgs{} }
func (latestVersionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*LatestVersionArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.latest_version: expected *solarisipspkg.LatestVersionArgs, got %T", args)
	}
	if len(a.Names) == 0 {
		return "", nil
	}
	availableResult, err := run(ctx, rt, append([]string{ipsBinary, "list", "-Hnv"}, a.Names...)...)
	if err != nil {
		return nil, err
	}
	available, err := parseIPSRecords(availableResult.Stdout)
	if err != nil {
		return nil, err
	}
	installedRecords, err := listPackageVersions(ctx, rt, a.Names)
	if err != nil {
		return nil, err
	}
	installed, _ := versionMap(installedRecords, a.Names)
	availableValues, availableOrder := versionMap(available, nil)
	for _, name := range availableOrder {
		if current, ok := installed[name]; ok && fmt.Sprint(availableValues[name]) == fmt.Sprint(current) {
			availableValues[name] = ""
		}
	}
	for _, name := range a.Names {
		if _, ok := availableValues[name]; !ok {
			availableOrder = append(availableOrder, name)
			availableValues[name] = ""
		}
	}
	if len(a.Names) == 1 {
		return singleVersion(availableValues, availableOrder), nil
	}
	return availableValues, nil
}

// ---------------------------------------------------------------------------
// FMRI helpers, search, and install/remove

type NameArgs struct {
	Name   string         `statekit:"required"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type IsInstalledArgs = NameArgs

type getFMriFunc struct{ solarisOnly }

func (getFMriFunc) Name() string { return "pkg.get_fmri" }
func (getFMriFunc) Args() any    { return NameArgs{} }
func (getFMriFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*NameArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.get_fmri: expected *solarisipspkg.NameArgs, got %T", args)
	}
	if strings.HasPrefix(a.Name, "pkg://") {
		return a.Name, nil
	}
	result, err := run(ctx, rt, ipsBinary, "list", "-aHv", a.Name)
	if err != nil {
		return nil, err
	}
	records, err := parseIPSRecords(result.Stdout)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return "", nil
	}
	values := make([]string, 0, len(records))
	for _, record := range records {
		values = append(values, record.Name)
	}
	return values, nil
}

type normalizeNameFunc struct{ solarisOnly }

func (normalizeNameFunc) Name() string { return "pkg.normalize_name" }
func (normalizeNameFunc) Args() any    { return NameArgs{} }
func (normalizeNameFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*NameArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.normalize_name: expected *solarisipspkg.NameArgs, got %T", args)
	}
	if strings.HasPrefix(a.Name, "pkg://") {
		return a.Name, nil
	}
	result, err := run(ctx, rt, ipsBinary, "list", "-aHv", a.Name)
	if err != nil {
		return nil, err
	}
	records, err := parseIPSRecords(result.Stdout)
	if err != nil {
		return nil, err
	}
	if len(records) != 1 {
		return a.Name, nil
	}
	return records[0].Name, nil
}

type isInstalledFunc struct{ solarisOnly }

func (isInstalledFunc) Name() string { return "pkg.is_installed" }
func (isInstalledFunc) Args() any    { return IsInstalledArgs{} }
func (isInstalledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*IsInstalledArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.is_installed: expected *solarisipspkg.IsInstalledArgs, got %T", args)
	}
	result, err := run(ctx, rt, ipsBinary, "list", "-Hv", a.Name)
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
}

type SearchArgs struct {
	Name           string         `statekit:"required"`
	// See ListPkgsArgs.VersionsAsList: this is intentionally not bool.
	VersionsAsList any            `statekit:"name=versions_as_list"`
	Kwargs         map[string]any `statekit:"name=kwargs"`
}

type searchFunc struct{ solarisOnly }

func (searchFunc) Name() string { return "pkg.search" }
func (searchFunc) Args() any    { return SearchArgs{} }
func (searchFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*SearchArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.search: expected *solarisipspkg.SearchArgs, got %T", args)
	}
	result, err := run(ctx, rt, ipsBinary, "list", "-aHv", a.Name)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return map[string]any{}, nil
	}
	records, err := parseIPSRecords(result.Stdout)
	if err != nil {
		return nil, err
	}
	return recordsAsPackages(records, pythonTruthy(a.VersionsAsList), false), nil
}

type InstallArgs struct {
	Name    *string        `statekit:"name=name"`
	Refresh bool           `statekit:"name=refresh"`
	Pkgs    []any          `statekit:"name=pkgs"`
	Version *string        `statekit:"name=version"`
	Test    bool           `statekit:"name=test"`
	Kwargs  map[string]any `statekit:"name=kwargs"`
}

type installFunc struct{ solarisOnly }

func (installFunc) Name() string { return "pkg.install" }
func (installFunc) Args() any    { return InstallArgs{} }
func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*InstallArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.install: expected *solarisipspkg.InstallArgs, got %T", args)
	}
	targets, err := installTargets(a.Name, a.Pkgs, a.Version)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return map[string]any{}, nil
	}
	if len(a.Pkgs) == 0 {
		installedName := ""
		if a.Name != nil {
			installedName = *a.Name
		}
		installed, err := (isInstalledFunc{}).Execute(ctx, rt, &IsInstalledArgs{Name: installedName})
		if err != nil {
			return nil, err
		}
		if installed.(bool) {
			return map[string]any{}, nil
		}
	}
	if truthy(a.Refresh) {
		if _, err := (refreshDBFunc{}).Execute(ctx, rt, &RefreshDBArgs{Full: true}); err != nil {
			return nil, err
		}
	}
	old, err := listPackages(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	argv := []string{ipsPathBinary, "install", "-v", "--accept"}
	if truthy(a.Test) {
		argv = append(argv, "-n")
	}
	argv = append(argv, targets...)
	result, err := run(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	current, err := listPackages(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	changes := packageChanges(old, current)
	if err := commandError("installing", result, changes); err != nil {
		return nil, err
	}
	if truthy(a.Test) {
		return "Test succeeded.", nil
	}
	return changes, nil
}

type RemoveArgs struct {
	Name   *string        `statekit:"name=name"`
	Pkgs   []any          `statekit:"name=pkgs"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type removeFunc struct{ solarisOnly }

func (removeFunc) Name() string { return "pkg.remove" }
func (removeFunc) Args() any    { return RemoveArgs{} }
func (removeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*RemoveArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.remove: expected *solarisipspkg.RemoveArgs, got %T", args)
	}
	targets, err := removeTargets(a.Name, a.Pkgs)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return map[string]any{}, nil
	}
	old, err := listPackages(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	argv := append([]string{ipsBinary, "uninstall", "-v"}, targets...)
	result, err := run(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	current, err := listPackages(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	changes := packageChanges(old, current)
	if err := commandError("removing", result, changes); err != nil {
		return nil, err
	}
	return changes, nil
}

type PurgeArgs struct {
	Name   *string        `statekit:"required"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type purgeFunc struct{ solarisOnly }

func (purgeFunc) Name() string { return "pkg.purge" }
func (purgeFunc) Args() any    { return PurgeArgs{} }
func (purgeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*PurgeArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("pkg.purge: expected *solarisipspkg.PurgeArgs, got %T", args)
	}
	var pkgs []any
	if a.Kwargs != nil {
		if value, exists := a.Kwargs["pkgs"]; exists {
			pkgs = valuesAsSlice(value)
		}
	}
	return (removeFunc{}).Execute(ctx, rt, &RemoveArgs{Name: a.Name, Pkgs: pkgs, Kwargs: a.Kwargs})
}

// Register installs the 14 public IPS functions. The deprecated
// available_version alias is intentionally not a second registry name, just
// as the source catalog records only latest_version.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		refreshDBFunc{}, upgradeAvailableFunc{}, listUpgradesFunc{}, upgradeFunc{},
		listPkgsFunc{}, versionFunc{}, latestVersionFunc{}, getFMriFunc{},
		normalizeNameFunc{}, isInstalledFunc{}, searchFunc{}, installFunc{},
		removeFunc{}, purgeFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
