package rbac

// Solaris RBAC implementation for Salt's rbac_solaris.py at the pinned Salt
// revision. The source inventory is profile_list/profile_get/profile_add/
// profile_rm, role_list/role_get/role_add/role_rm, and
// auth_list/auth_get/auth_add/auth_rm. Database reads use the runtime
// filesystem; command-backed operations use the central shell-free Runner.
// No Solaris command or live RBAC database is required by the Linux mock
// tests.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	rbacCommandTimeout = 30 * time.Second
	rbacOutputLimit    = 4 << 20
	rbacFileLimit      = 1 << 20
)

var (
	errRBACRunnerUnavailable = errors.New("rbac: runner unavailable")
	errRBACFilesystemMissing = errors.New("rbac: filesystem unavailable")
)

type rbacSolarisOnly struct{}

func (rbacSolarisOnly) Platforms() []string { return []string{"solaris"} }

// rbacRun is the single command boundary for this family. Completed non-zero
// exits remain Salt-compatible command data; Runner failures, cancellation,
// and bounded-output failures are returned as Go errors.
func rbacRun(ctx context.Context, rt *runtime.Runtime, argv ...string) (process.CommandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if rt == nil || rt.Runner == nil {
		return process.CommandResult{ExitCode: -1}, errRBACRunnerUnavailable
	}
	command := runtime.Command(argv...)
	command.Shell = false
	command.Timeout = rbacCommandTimeout
	command.MaxStdoutBytes = rbacOutputLimit
	command.MaxStderrBytes = rbacOutputLimit
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return result, result.Err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stdout) > rbacOutputLimit || len(result.Stderr) > rbacOutputLimit {
		return result, process.ErrOutputLimit
	}
	return result, nil
}

func rbacReadFile(ctx context.Context, rt *runtime.Runtime, name string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if rt == nil || rt.FS == nil {
		return nil, errRBACFilesystemMissing
	}
	data, err := runtime.ReadFileBounded(rt.FS, name, rbacFileLimit)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	return data, err
}

func splitRBACLines(data []byte) []string { return strings.Split(string(data), "\n") }

// splitRBACAuthLines mirrors Python's str.splitlines() for auths output only.
// Unlike strings.Split, a final line boundary does not create a synthetic
// trailing item, while empty items between boundaries remain observable.
func splitRBACAuthLines(data []byte) []string {
	runes := []rune(string(data))
	lines := make([]string, 0)
	start := 0
	for index := 0; index < len(runes); index++ {
		width := 0
		switch runes[index] {
		case '\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029':
			width = 1
		case '\r':
			width = 1
			if index+1 < len(runes) && runes[index+1] == '\n' {
				width = 2
			}
		}
		if width == 0 {
			continue
		}
		lines = append(lines, string(runes[start:index]))
		index += width - 1
		start = index + 1
	}
	if start < len(runes) {
		lines = append(lines, string(runes[start:]))
	}
	return lines
}

func parseRBACAttrs(raw string) (map[string]any, error) {
	attrs := map[string]any{}
	for _, item := range strings.Split(strings.TrimSpace(raw), ";") {
		parts := strings.Split(strings.TrimSpace(item), "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("rbac: malformed attribute %q", item)
		}
		key := parts[0]
		value := parts[1]
		if key == "auths" || key == "profiles" || key == "roles" {
			attrs[key] = strings.Split(strings.TrimSpace(value), ",")
		} else {
			attrs[key] = value
		}
	}
	return attrs, nil
}

// splitRBACRecords preserves the newline retained by Python file iteration.
// Only role_list uses this contract; the user getters strip their records
// before parsing, as their pinned source does.
func splitRBACRecords(data []byte) []string {
	return strings.SplitAfter(string(data), "\n")
}

// parseRBACRoleAttrs intentionally performs no whitespace normalization. The
// pinned role_list parser splits role[4] directly, so a final newline remains
// part of type's value and type=role\n is not recognized as a role.
func parseRBACRoleAttrs(raw string) (map[string]any, error) {
	attrs := map[string]any{}
	for _, item := range strings.Split(raw, ";") {
		parts := strings.Split(item, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("rbac: malformed attribute %q", item)
		}
		key, value := parts[0], parts[1]
		if key == "auths" || key == "profiles" || key == "roles" {
			attrs[key] = strings.Split(value, ",")
		} else {
			attrs[key] = value
		}
	}
	return attrs, nil
}

func parseRBACPolicyDefaults(lines []string, defaults []string) ([]string, error) {
	for lineNumber, line := range lines {
		parts := strings.Split(line, "=")
		if len(parts) == 0 || strings.TrimSpace(parts[0]) != "PROFS_GRANTED" {
			continue
		}
		if len(parts) < 2 {
			return nil, fmt.Errorf("rbac: malformed policy.conf line %d", lineNumber+1)
		}
		defaults = append(defaults, strings.Split(strings.TrimSpace(parts[1]), ",")...)
	}
	return defaults, nil
}

func readRBACPolicy(ctx context.Context, rt *runtime.Runtime) ([]string, error) {
	data, err := rbacReadFile(ctx, rt, "/etc/security/policy.conf")
	if err != nil {
		return nil, err
	}
	return parseRBACPolicyDefaults(splitRBACLines(data), []string{"All"})
}

func rbacStringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func rbacUniqueSorted(values []string) []string {
	set := rbacStringSet(values)
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func rbacProfileList(ctx context.Context, rt *runtime.Runtime, defaultOnly bool) (map[string]string, error) {
	defaults, err := readRBACPolicy(ctx, rt)
	if err != nil {
		return nil, err
	}
	data, err := rbacReadFile(ctx, rt, "/etc/security/prof_attr")
	if err != nil {
		return nil, err
	}
	profiles := map[string]string{}
	for _, line := range splitRBACLines(data) {
		fields := strings.Split(line, ":")
		if len(fields) != 5 {
			continue
		}
		profiles[fields[0]] = fields[3]
	}
	if defaultOnly {
		knownDefaults := rbacStringSet(defaults)
		for name := range profiles {
			if _, ok := knownDefaults[name]; !ok {
				delete(profiles, name)
			}
		}
	}
	return profiles, nil
}

func rbacUserAttrs(ctx context.Context, rt *runtime.Runtime, user string) ([]map[string]any, error) {
	data, err := rbacReadFile(ctx, rt, "/etc/user_attr")
	if err != nil {
		return nil, err
	}
	var records []map[string]any
	for lineNumber, line := range splitRBACLines(data) {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) != 5 || fields[0] != user {
			continue
		}
		attrs, parseErr := parseRBACAttrs(strings.TrimSpace(fields[4]))
		if parseErr != nil {
			return nil, fmt.Errorf("rbac: user_attr line %d: %w", lineNumber+1, parseErr)
		}
		records = append(records, attrs)
	}
	return records, nil
}

func rbacUserValues(ctx context.Context, rt *runtime.Runtime, user, key string) ([]string, error) {
	records, err := rbacUserAttrs(ctx, rt, user)
	if err != nil {
		return nil, err
	}
	var values []string
	for _, attrs := range records {
		if raw, ok := attrs[key]; ok {
			if list, ok := raw.([]string); ok {
				values = append(values, list...)
			}
		}
	}
	return values, nil
}

func rbacProfileValues(ctx context.Context, rt *runtime.Runtime, user string, defaultHidden bool) ([]string, error) {
	values, err := rbacUserValues(ctx, rt, user, "profiles")
	if err != nil {
		return nil, err
	}
	if !defaultHidden {
		return values, nil
	}
	defaults, err := rbacProfileList(ctx, rt, true)
	if err != nil {
		return nil, err
	}
	defaultSet := make(map[string]struct{}, len(defaults))
	for name := range defaults {
		defaultSet[name] = struct{}{}
	}
	removed := map[string]struct{}{}
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		if _, isDefault := defaultSet[value]; isDefault {
			if _, alreadyRemoved := removed[value]; !alreadyRemoved {
				removed[value] = struct{}{}
				continue
			}
		}
		filtered = append(filtered, value)
	}
	return filtered, nil
}

func rbacRoleList(ctx context.Context, rt *runtime.Runtime) (map[string]map[string]any, error) {
	data, err := rbacReadFile(ctx, rt, "/etc/user_attr")
	if err != nil {
		return nil, err
	}
	roles := map[string]map[string]any{}
	for lineNumber, line := range splitRBACRecords(data) {
		fields := strings.Split(line, ":")
		if len(fields) != 5 {
			continue
		}
		attrs, parseErr := parseRBACRoleAttrs(fields[4])
		if parseErr != nil {
			return nil, fmt.Errorf("rbac: user_attr line %d: %w", lineNumber+1, parseErr)
		}
		if attrs["type"] != "role" {
			continue
		}
		delete(attrs, "type")
		roles[fields[0]] = attrs
	}
	return roles, nil
}

func rbacAuthList(ctx context.Context, rt *runtime.Runtime) (map[string]string, error) {
	data, err := rbacReadFile(ctx, rt, "/etc/security/auth_attr")
	if err != nil {
		return nil, err
	}
	auths := map[string]string{}
	for _, line := range splitRBACLines(data) {
		fields := strings.Split(line, ":")
		if len(fields) != 6 {
			continue
		}
		name := fields[0]
		if strings.HasSuffix(name, ".") {
			name += "*"
		}
		auths[name] = fields[3]
	}
	return auths, nil
}

func rbacCommandError(result process.CommandResult) map[string]any {
	return map[string]any{
		"Error": map[string]any{
			"retcode": result.ExitCode,
			"message": string(result.Stderr),
		},
	}
}

func rbacUsermod(ctx context.Context, rt *runtime.Runtime, flag, user string, values []string) (process.CommandResult, error) {
	return rbacRun(ctx, rt, "usermod", flag, strings.Join(rbacUniqueSorted(values), ","), user)
}

func rbacKnown(values map[string]string, requested []string) []string {
	valid := make([]string, 0, len(requested))
	for _, value := range requested {
		if _, ok := values[value]; ok {
			valid = append(valid, value)
		}
	}
	return valid
}

func rbacStatusMap(requested, valid, active []string, add bool) map[string]any {
	validSet := rbacStringSet(valid)
	activeSet := rbacStringSet(active)
	ret := map[string]any{}
	for _, value := range requested {
		if _, ok := validSet[value]; !ok {
			ret[value] = "Unknown"
			continue
		}
		_, present := activeSet[value]
		if add {
			if present {
				ret[value] = "Added"
			} else {
				ret[value] = "Failed"
			}
			continue
		}
		if present {
			ret[value] = "Failed"
		} else {
			ret[value] = "Remove"
		}
	}
	return ret
}

// ---------------------------------------------------------------------------
// profiles

type profileListArgs struct {
	DefaultOnly *bool `statekit:"name=default_only"`
}

type profileListFunc struct{ rbacSolarisOnly }

func (profileListFunc) Name() string { return "rbac.profile_list" }
func (profileListFunc) Args() any    { return profileListArgs{} }
func (profileListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*profileListArgs)
	defaultOnly := a.DefaultOnly != nil && *a.DefaultOnly
	return rbacProfileList(ctx, rt, defaultOnly)
}

type profileGetArgs struct {
	User          string `statekit:"required"`
	DefaultHidden *bool  `statekit:"name=default_hidden"`
}

type profileGetFunc struct{ rbacSolarisOnly }

func (profileGetFunc) Name() string { return "rbac.profile_get" }
func (profileGetFunc) Args() any    { return profileGetArgs{} }
func (profileGetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*profileGetArgs)
	defaultHidden := true
	if a.DefaultHidden != nil {
		defaultHidden = *a.DefaultHidden
	}
	values, err := rbacProfileValues(ctx, rt, a.User, defaultHidden)
	if err != nil {
		return nil, err
	}
	return rbacUniqueSorted(values), nil
}

type profileMutationArgs struct {
	User    string `statekit:"required"`
	Profile string `statekit:"required,name=profile"`
}

type profileAddFunc struct{ rbacSolarisOnly }

func (profileAddFunc) Name() string { return "rbac.profile_add" }
func (profileAddFunc) Args() any    { return profileMutationArgs{} }
func (profileAddFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*profileMutationArgs)
	requested := strings.Split(a.Profile, ",")
	known, err := rbacProfileList(ctx, rt, false)
	if err != nil {
		return nil, err
	}
	valid := rbacKnown(known, requested)
	if len(valid) > 0 {
		active, err := rbacProfileValues(ctx, rt, a.User, true)
		if err != nil {
			return nil, err
		}
		result, err := rbacUsermod(ctx, rt, "-P", a.User, append(active, valid...))
		if err != nil {
			return nil, err
		}
		if result.ExitCode > 0 {
			return rbacCommandError(result), nil
		}
	}
	active, err := rbacUserValues(ctx, rt, a.User, "profiles")
	if err != nil {
		return nil, err
	}
	return rbacStatusMap(requested, valid, active, true), nil
}

type profileRemoveFunc struct{ rbacSolarisOnly }

func (profileRemoveFunc) Name() string { return "rbac.profile_rm" }
func (profileRemoveFunc) Args() any    { return profileMutationArgs{} }
func (profileRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*profileMutationArgs)
	requested := strings.Split(a.Profile, ",")
	known, err := rbacProfileList(ctx, rt, false)
	if err != nil {
		return nil, err
	}
	valid := rbacKnown(known, requested)
	if len(valid) > 0 {
		active, err := rbacProfileValues(ctx, rt, a.User, true)
		if err != nil {
			return nil, err
		}
		kept := make([]string, 0, len(active))
		removeSet := rbacStringSet(valid)
		for _, value := range active {
			if _, remove := removeSet[value]; !remove {
				kept = append(kept, value)
			}
		}
		result, err := rbacUsermod(ctx, rt, "-P", a.User, kept)
		if err != nil {
			return nil, err
		}
		if result.ExitCode > 0 {
			return rbacCommandError(result), nil
		}
	}
	active, err := rbacUserValues(ctx, rt, a.User, "profiles")
	if err != nil {
		return nil, err
	}
	return rbacStatusMap(requested, valid, active, false), nil
}

// ---------------------------------------------------------------------------
// roles

type roleListArgs struct{}

type roleListFunc struct{ rbacSolarisOnly }

func (roleListFunc) Name() string { return "rbac.role_list" }
func (roleListFunc) Args() any    { return roleListArgs{} }
func (roleListFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return rbacRoleList(ctx, rt)
}

type roleGetArgs struct {
	User string `statekit:"required"`
}

type roleGetFunc struct{ rbacSolarisOnly }

func (roleGetFunc) Name() string { return "rbac.role_get" }
func (roleGetFunc) Args() any    { return roleGetArgs{} }
func (roleGetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	values, err := rbacUserValues(ctx, rt, args.(*roleGetArgs).User, "roles")
	if err != nil {
		return nil, err
	}
	return rbacUniqueSorted(values), nil
}

type roleMutationArgs struct {
	User string `statekit:"required"`
	Role string `statekit:"required,name=role"`
}

type roleAddFunc struct{ rbacSolarisOnly }

func (roleAddFunc) Name() string { return "rbac.role_add" }
func (roleAddFunc) Args() any    { return roleMutationArgs{} }
func (roleAddFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*roleMutationArgs)
	requested := strings.Split(a.Role, ",")
	known, err := rbacRoleList(ctx, rt)
	if err != nil {
		return nil, err
	}
	knownNames := make(map[string]string, len(known))
	for name := range known {
		knownNames[name] = name
	}
	valid := rbacKnown(knownNames, requested)
	if len(valid) > 0 {
		active, err := rbacUserValues(ctx, rt, a.User, "roles")
		if err != nil {
			return nil, err
		}
		result, err := rbacUsermod(ctx, rt, "-R", a.User, append(active, valid...))
		if err != nil {
			return nil, err
		}
		if result.ExitCode > 0 {
			return rbacCommandError(result), nil
		}
	}
	active, err := rbacUserValues(ctx, rt, a.User, "roles")
	if err != nil {
		return nil, err
	}
	return rbacStatusMap(requested, valid, active, true), nil
}

type roleRemoveFunc struct{ rbacSolarisOnly }

func (roleRemoveFunc) Name() string { return "rbac.role_rm" }
func (roleRemoveFunc) Args() any    { return roleMutationArgs{} }
func (roleRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*roleMutationArgs)
	requested := strings.Split(a.Role, ",")
	known, err := rbacRoleList(ctx, rt)
	if err != nil {
		return nil, err
	}
	knownNames := make(map[string]string, len(known))
	for name := range known {
		knownNames[name] = name
	}
	valid := rbacKnown(knownNames, requested)
	if len(valid) > 0 {
		active, err := rbacUserValues(ctx, rt, a.User, "roles")
		if err != nil {
			return nil, err
		}
		removeSet := rbacStringSet(valid)
		kept := make([]string, 0, len(active))
		for _, value := range active {
			if _, remove := removeSet[value]; !remove {
				kept = append(kept, value)
			}
		}
		result, err := rbacUsermod(ctx, rt, "-R", a.User, kept)
		if err != nil {
			return nil, err
		}
		if result.ExitCode > 0 {
			return rbacCommandError(result), nil
		}
	}
	active, err := rbacUserValues(ctx, rt, a.User, "roles")
	if err != nil {
		return nil, err
	}
	return rbacStatusMap(requested, valid, active, false), nil
}

// ---------------------------------------------------------------------------
// authorizations

type authListArgs struct{}

type authListFunc struct{ rbacSolarisOnly }

func (authListFunc) Name() string { return "rbac.auth_list" }
func (authListFunc) Args() any    { return authListArgs{} }
func (authListFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return rbacAuthList(ctx, rt)
}

type authGetArgs struct {
	User     string `statekit:"required"`
	Computed *bool  `statekit:"name=computed"`
}

type authGetFunc struct{ rbacSolarisOnly }

func (authGetFunc) Name() string { return "rbac.auth_get" }
func (authGetFunc) Args() any    { return authGetArgs{} }
func (authGetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*authGetArgs)
	computed := true
	if a.Computed != nil {
		computed = *a.Computed
	}
	values, err := rbacUserValues(ctx, rt, a.User, "auths")
	if err != nil {
		return nil, err
	}
	if computed {
		result, runErr := rbacRun(ctx, rt, "auths", a.User)
		if runErr != nil {
			return nil, runErr
		}
		if result.ExitCode == 0 {
			for _, line := range splitRBACAuthLines(result.Stdout) {
				line = strings.TrimSpace(line)
				if strings.Contains(line, ",") {
					values = append(values, strings.Split(line, ",")...)
				} else {
					values = append(values, line)
				}
			}
		}
	}
	return rbacUniqueSorted(values), nil
}

type authMutationArgs struct {
	User string `statekit:"required"`
	Auth string `statekit:"required,name=auth"`
}

type authAddFunc struct{ rbacSolarisOnly }

func (authAddFunc) Name() string { return "rbac.auth_add" }
func (authAddFunc) Args() any    { return authMutationArgs{} }
func (authAddFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*authMutationArgs)
	requested := strings.Split(a.Auth, ",")
	known, err := rbacAuthList(ctx, rt)
	if err != nil {
		return nil, err
	}
	valid := rbacKnown(known, requested)
	if len(valid) > 0 {
		active, err := rbacUserValues(ctx, rt, a.User, "auths")
		if err != nil {
			return nil, err
		}
		result, err := rbacUsermod(ctx, rt, "-A", a.User, append(active, valid...))
		if err != nil {
			return nil, err
		}
		if result.ExitCode > 0 {
			return rbacCommandError(result), nil
		}
	}
	active, err := rbacUserValues(ctx, rt, a.User, "auths")
	if err != nil {
		return nil, err
	}
	return rbacStatusMap(requested, valid, active, true), nil
}

type authRemoveFunc struct{ rbacSolarisOnly }

func (authRemoveFunc) Name() string { return "rbac.auth_rm" }
func (authRemoveFunc) Args() any    { return authMutationArgs{} }
func (authRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*authMutationArgs)
	requested := strings.Split(a.Auth, ",")
	known, err := rbacAuthList(ctx, rt)
	if err != nil {
		return nil, err
	}
	valid := rbacKnown(known, requested)
	if len(valid) > 0 {
		active, err := rbacUserValues(ctx, rt, a.User, "auths")
		if err != nil {
			return nil, err
		}
		removeSet := rbacStringSet(valid)
		kept := make([]string, 0, len(active))
		for _, value := range active {
			if _, remove := removeSet[value]; !remove {
				kept = append(kept, value)
			}
		}
		result, err := rbacUsermod(ctx, rt, "-A", a.User, kept)
		if err != nil {
			return nil, err
		}
		if result.ExitCode > 0 {
			return rbacCommandError(result), nil
		}
	}
	active, err := rbacUserValues(ctx, rt, a.User, "auths")
	if err != nil {
		return nil, err
	}
	return rbacStatusMap(requested, valid, active, false), nil
}
