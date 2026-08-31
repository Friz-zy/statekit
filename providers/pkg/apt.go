package pkg

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

var ErrUnsupportedAPT = errors.New("APT capability is not supported by this package provider")

func aptOnly(p *commandProvider) error {
	if p.spec.manager != "apt" {
		return ErrUnsupportedAPT
	}
	return nil
}
func aptRun(ctx context.Context, rt *runtime.Runtime, argv []string) (string, error) {
	return aptResult(ctx, rt, argv)
}
func aptRunChecked(ctx context.Context, rt *runtime.Runtime, argv []string) (string, error) {
	return aptResult(ctx, rt, argv)
}
func aptEmptyOnFailure(ctx context.Context, rt *runtime.Runtime, argv []string) (string, error) {
	r := rt.Runner.Run(ctx, runtime.Command(argv...))
	if r.Err != nil {
		return "", r.Err
	}
	if r.ExitCode != 0 {
		return "", nil
	}
	return string(r.Stdout), nil
}
func aptResult(ctx context.Context, rt *runtime.Runtime, argv []string) (string, error) {
	r := rt.Runner.Run(ctx, runtime.Command(argv...))
	if r.Err != nil {
		return "", r.Err
	}
	if r.ExitCode != 0 {
		return "", fmt.Errorf("%s exited with code %d: %s", argv[0], r.ExitCode, r.Stderr)
	}
	return string(r.Stdout), nil
}

// Apt exposes the APT long-tail execution functions through one capability.
func (p *commandProvider) Apt(ctx context.Context, rt *runtime.Runtime, function string, args any) (any, error) {
	if err := aptOnly(p); err != nil {
		return nil, err
	}
	a, ok := args.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("APT function %q: malformed arguments", function)
	}
	if err := validateAPTArgs(function, a); err != nil {
		return nil, err
	}
	switch function {
	case "normalize_name":
		n, ok := a["name"].(string)
		if !ok || invalidAPTToken(n) {
			return nil, errors.New("invalid package name")
		}
		return normalizeName(n, rt.Facts.CPU().Arch), nil
	case "parse_arch":
		n, ok := a["name"].(string)
		if !ok || invalidAPTToken(n) {
			return nil, errors.New("invalid package name")
		}
		return parseArch(n), nil
	case "version_cmp":
		p1, ok1 := a["pkg1"].(string)
		p2, ok2 := a["pkg2"].(string)
		if !ok1 || !ok2 || hasControl(p1) || hasControl(p2) {
			return nil, errors.New("invalid package version")
		}
		return p.versionCmp(ctx, rt, p1, p2, boolDefault(a, "ignore_epoch", false))
	case "get_selections":
		pattern := stringArg(a["pattern"])
		if pattern == "" {
			pattern = "*"
		}
		if pattern != "*" && invalidAPTToken(pattern) {
			return nil, errors.New("invalid selection pattern")
		}
		out, err := aptRun(ctx, rt, []string{"dpkg", "--get-selections", pattern})
		if err != nil {
			return nil, err
		}
		ret := parseSelections(out)
		if state := stringArg(a["state"]); state != "" {
			if invalidAPTToken(state) {
				return nil, errors.New("invalid selection state")
			}
			return map[string][]string{state: ret[state]}, nil
		}
		return ret, nil
	case "set_selections":
		return p.setSelections(ctx, rt, a)
	case "hold", "unhold":
		return p.hold(ctx, rt, function == "hold", a)
	case "autoremove":
		return p.autoremove(ctx, rt, boolDefault(a, "list_only", false), boolDefault(a, "purge", false))
	case "purge":
		return p.uninstall(ctx, rt, "purge", a)
	case "upgrade":
		return p.upgrade(ctx, rt, a)
	case "list_upgrades":
		return p.listUpgrades(ctx, rt, a)
	case "upgrade_available":
		n, ok := a["name"].(string)
		if !ok || invalidAPTToken(n) {
			return nil, errors.New("invalid package name")
		}
		installed, err := p.Version(ctx, rt, n)
		if err != nil {
			return nil, err
		}
		candidate, err := p.latestCandidate(ctx, rt, n)
		if err != nil {
			return nil, err
		}
		if installed == "" || candidate == "" {
			return false, nil
		}
		cmp, err := p.versionCmp(ctx, rt, installed, candidate, false)
		if err != nil {
			return nil, err
		}
		return cmp == 1, nil
	case "show":
		return p.show(ctx, rt, a)
	case "list_repo_pkgs":
		return p.listRepo(ctx, rt, a)
	case "owner":
		return p.owner(ctx, rt, a)
	case "which":
		if x := stringArg(a["path"]); x != "" && invalidAPTToken(x) {
			return nil, errors.New("invalid path")
		}
		return p.which(ctx, rt, stringArg(a["path"])), nil
	case "file_list", "file_dict":
		return p.files(ctx, rt, function, a)
	case "info_installed":
		return p.info(ctx, rt, a)
	case "list_downloaded":
		return p.downloaded(ctx, rt, a)
	case "services_need_restart":
		out, err := aptResult(ctx, rt, []string{"checkrestart", "--machine", "--package"})
		if err != nil {
			return nil, err
		}
		return services(out), nil
	default:
		return nil, fmt.Errorf("unknown APT function %q", function)
	}
}

func validateAPTArgs(function string, a map[string]any) error {
	allowed := map[string]bool{}
	switch function {
	case "normalize_name", "parse_arch", "upgrade_available":
		allowed = map[string]bool{"name": true}
	case "version_cmp":
		allowed = map[string]bool{"pkg1": true, "pkg2": true, "ignore_epoch": true}
	case "get_selections":
		allowed = map[string]bool{"pattern": true, "state": true}
	case "set_selections":
		allowed = map[string]bool{"path": true, "selection": true, "clear": true, "saltenv": true}
	case "hold", "unhold":
		allowed = map[string]bool{"name": true, "pkgs": true, "sources": true}
	case "purge":
		allowed = map[string]bool{"name": true, "pkgs": true}
	case "autoremove":
		allowed = map[string]bool{"list_only": true, "purge": true}
	case "upgrade":
		allowed = map[string]bool{"refresh": true, "dist_upgrade": true, "force_conf_new": true, "download_only": true, "downloadonly": true, "allow_downgrades": true, "force_yes": true, "skip_verify": true, "cache_valid_time": true}
	case "list_upgrades":
		allowed = map[string]bool{"refresh": true, "dist_upgrade": true, "cache_valid_time": true}
	case "show":
		allowed = map[string]bool{"names": true, "name": true, "filter": true, "refresh": true}
	case "list_repo_pkgs", "file_list", "file_dict":
		allowed = map[string]bool{"packages": true}
	case "owner":
		allowed = map[string]bool{"paths": true}
	case "which":
		allowed = map[string]bool{"path": true}
	case "info_installed":
		allowed = map[string]bool{"names": true, "failhard": true}
	case "list_downloaded":
		allowed = map[string]bool{"root": true}
	case "services_need_restart":
	default:
		return nil
	}
	for key := range a {
		if !allowed[key] {
			return fmt.Errorf("APT function %q: unsupported argument %q", function, key)
		}
	}
	boolKeys := map[string]bool{"ignore_epoch": true, "clear": true, "list_only": true, "purge": true, "refresh": true, "dist_upgrade": true, "force_conf_new": true, "download_only": true, "downloadonly": true, "allow_downgrades": true, "force_yes": true, "skip_verify": true, "failhard": true}
	for key, value := range a {
		if value == nil {
			continue
		}
		if boolKeys[key] {
			if _, ok := value.(bool); !ok {
				if _, ok := value.(*bool); !ok {
					return fmt.Errorf("argument %q must be a boolean", key)
				}
				// A typed nil pointer is the decoder's representation of omission.
			}
		}
	}
	for _, key := range []string{"name", "pattern", "state", "path", "filter", "root", "saltenv", "pkg1", "pkg2"} {
		if v, ok := a[key]; ok && v != nil {
			// parse_targets evaluates a truthy pkgs branch before it touches
			// name, including an otherwise malformed name value.
			if function == "purge" && key == "name" {
				continue
			}
			if _, good := v.(string); !good {
				if _, ok := v.(*string); !ok {
					return fmt.Errorf("argument %q must be a string", key)
				}
			}
		}
	}
	for _, key := range []string{"pkgs", "packages", "names", "paths"} {
		if v, ok := a[key]; ok && v != nil {
			// pkg_resource._repack_pkgs accepts a decoder-compatible list of
			// scalars and one-key mappings for purge. The target helper validates
			// that richer form after source precedence has been determined.
			if function == "purge" && key == "pkgs" {
				continue
			}
			if _, good := v.([]string); !good {
				return fmt.Errorf("argument %q must be a list of strings", key)
			}
		}
	}
	if v, ok := a["cache_valid_time"]; ok && v != nil {
		if _, good := v.(int); !good {
			if _, yes := v.(*int); !yes {
				return fmt.Errorf("argument %q must be an integer", "cache_valid_time")
			}
		}
	}
	if v, ok := a["sources"]; ok && v != nil {
		switch v.(type) {
		case []any, []map[string]any:
		default:
			return fmt.Errorf("argument %q must be a list", "sources")
		}
	}
	if v, ok := a["selection"]; ok && v != nil {
		if _, good := v.(map[string][]string); !good {
			if _, goodAny := v.(map[string]any); !goodAny {
				return fmt.Errorf("argument %q must be an object of state to package lists", "selection")
			}
		}
	}
	return nil
}

func intValue(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case *int:
		if n == nil {
			return 0, false
		}
		return *n, true
	default:
		return 0, false
	}
}
func boolDefault(a map[string]any, key string, def bool) bool {
	v, ok := a[key]
	if !ok || v == nil {
		return def
	}
	switch b := v.(type) {
	case bool:
		return b
	case *bool:
		return b != nil && *b
	default:
		// validateAPTArgs rejects this before any provider command is run.
		return def
	}
}
func stringArg(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case *string:
		if s != nil {
			return *s
		}
	}
	return ""
}
func names(a map[string]any) []string {
	if n := stringArg(a["name"]); n != "" {
		return []string{n}
	}
	if v, ok := a["pkgs"].([]string); ok {
		return append([]string(nil), v...)
	}
	if v, ok := a["packages"].([]string); ok {
		return append([]string(nil), v...)
	}
	return nil
}

func packageArgs(a map[string]any) ([]string, error) {
	if sources, ok := a["sources"]; ok && sources != nil {
		var targets []string
		var err error
		switch list := sources.(type) {
		case []any:
			targets, err = sourceTargets(list)
		case []map[string]any:
			out := make([]any, len(list))
			for i := range list {
				out[i] = list[i]
			}
			targets, err = sourceTargets(out)
		default:
			return nil, errors.New("argument \"sources\" must be a list")
		}
		if err != nil {
			return nil, err
		}
		if len(targets) > 0 {
			if pkgs, _ := packageList(a); len(pkgs) > 0 {
				return nil, errors.New("only one of pkgs or sources can be specified")
			}
			return targets, nil
		}
	}
	var result []string
	if _, pkgsSupplied := a["pkgs"]; pkgsSupplied && a["pkgs"] != nil {
		var err error
		result, err = packageList(a)
		if err != nil {
			return nil, err
		}
	}
	if len(result) == 0 {
		if n, ok := a["name"]; ok && n != nil {
			name, ok := n.(string)
			if !ok {
				if p, yes := n.(*string); yes && p != nil {
					name, ok = *p, true
				}
			}
			if !ok {
				return nil, fmt.Errorf("argument %q must be a string", "name")
			}
			if name != "" {
				result = []string{name}
			}
		}
	}
	for _, name := range result {
		if invalidAPTToken(name) {
			return nil, fmt.Errorf("invalid package name %q", name)
		}
	}
	return result, nil
}

func sourceTargets(values []any) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, value := range values {
		m, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("argument \"sources\" must contain mappings")
		}
		if len(m) != 1 {
			return nil, errors.New("argument \"sources\" entries must contain one package")
		}
		for name := range m {
			out = append(out, name)
		}
	}
	return out, nil
}

// invalidAPTToken is intentionally stricter than shell escaping: package
// identifiers are single argv/stdin tokens and must not contain whitespace or
// shell syntax. Debian's normal punctuation (+, ., ~, :, -) remains allowed.
func invalidAPTToken(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsSpace(r) || strings.ContainsRune(";&|$`<>\"'\\", r) {
			return true
		}
	}
	return false
}

func packageList(a map[string]any) ([]string, error) {
	return packageListNamed(a, "pkgs")
}
func packageListNamed(a map[string]any, key string) ([]string, error) {
	v, ok := a[key]
	if !ok {
		return nil, nil
	}
	packages, ok := v.([]string)
	if !ok {
		return nil, fmt.Errorf("argument %q must be a list of strings", key)
	}
	return append([]string(nil), packages...), nil
}

// filePackageArgs is deliberately separate from packageArgs: Salt's
// file_list, file_dict, and list_repo_pkgs APIs expose `packages`, while the
// mutating APIs expose `pkgs`. Do not make the public names interchangeable.
func filePackageArgs(a map[string]any) ([]string, error) {
	packages, err := packageListNamed(a, "packages")
	if err != nil {
		return nil, err
	}
	for _, name := range packages {
		if invalidAPTToken(name) {
			return nil, fmt.Errorf("invalid package name %q", name)
		}
	}
	return packages, nil
}
func normalizeName(n, arch string) string {
	x := strings.LastIndexByte(n, ':')
	if x < 0 {
		return n
	}
	a := n[x+1:]
	if a == arch || a == "all" || a == "any" {
		return n[:x]
	}
	return n
}
func parseArch(n string) map[string]any {
	x := strings.LastIndexByte(n, ':')
	if x < 0 {
		return map[string]any{"name": n, "arch": nil}
	}
	return map[string]any{"name": n[:x], "arch": n[x+1:]}
}
func parseSelections(s string) map[string][]string {
	r := map[string][]string{}
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 {
			r[f[1]] = append(r[f[1]], f[0])
		}
	}
	return r
}

func (p *commandProvider) autoremove(ctx context.Context, rt *runtime.Runtime, list, purge bool) (any, error) {
	cmd := []string{"apt-get"}
	if list {
		cmd = append(cmd, "--assume-no")
	} else {
		cmd = append(cmd, "--assume-yes")
	}
	if purge {
		cmd = append(cmd, "--purge")
	}
	cmd = append(cmd, "autoremove")
	if !list {
		old, err := installedPackages(ctx, rt)
		if err != nil {
			return nil, err
		}
		_, err = aptRunIgnoreExit(ctx, rt, cmd)
		if err != nil {
			return nil, err
		}
		new, err := installedPackages(ctx, rt)
		if err != nil {
			return nil, err
		}
		return comparePackages(old, new), nil
	}
	out, err := aptRunIgnoreExit(ctx, rt, cmd)
	if err != nil {
		return nil, err
	}
	var r []string
	on := false
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "The following packages will be REMOVED:") {
			on = true
			continue
		}
		if on && strings.HasPrefix(l, " ") {
			r = append(r, strings.Fields(l)...)
		} else if on {
			on = false
		}
	}
	sort.Strings(r)
	return r, nil
}

const aptPurgeOutputLimit = 1 << 20

const aptPurgeQueryFormat = "${Status} ${Package} ${Version} ${Architecture}\n"

// aptPurgeError is the CommandExecutionError-equivalent for aptpkg._uninstall.
// Salt returns the computed changes alongside the failure details after its
// readback, so callers can inspect both without treating a completed apt-get
// failure as a pre-mutation transport failure.
type aptPurgeError struct{ info map[string]any }

func (e *aptPurgeError) Error() string { return "Problem encountered removing package(s)" }

func (e *aptPurgeError) Info() map[string]any { return e.info }

func (p *commandProvider) uninstall(ctx context.Context, rt *runtime.Runtime, action string, a map[string]any) (any, error) {
	params, err := aptPurgeTargets(a, aptPurgeArch(rt))
	if err != nil {
		return nil, err
	}
	if len(params.index) == 0 {
		return map[string]any{}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	old, err := aptPurgeSnapshot(ctx, rt)
	if err != nil {
		return nil, err
	}

	// _uninstall calls match_wildcard on the same pkg_params mapping for the
	// installed and removed snapshots. Retain that mutation order exactly.
	matchPurgeWildcard(old.installed, old.installedOrder, params)
	targets, seen := aptPurgeMatchingTargets(old.installed, params, nil)
	if action == "purge" {
		matchPurgeWildcard(old.removed, old.removedOrder, params)
		removedTargets, _ := aptPurgeMatchingTargets(old.removed, params, seen)
		targets = append(targets, removedTargets...)
	}
	if len(targets) == 0 {
		return map[string]any{}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, target := range targets {
		if invalidAPTToken(target) {
			return nil, fmt.Errorf("invalid package name %q", target)
		}
	}

	cmd := append([]string{"apt-get", "-q", "-y", action}, targets...)
	removeResult, err := aptPurgeRun(ctx, rt, cmd)
	if err != nil {
		return nil, err
	}

	newSnapshot, err := aptPurgeSnapshot(ctx, rt)
	if err != nil {
		return nil, err
	}
	changes := comparePackages(old.installed, newSnapshot.installed)
	var ret any = changes
	if action == "purge" {
		ret = map[string]any{
			"removed":   comparePackages(old.removed, newSnapshot.removed),
			"installed": changes,
		}
	}
	if removeResult.ExitCode != 0 && len(removeResult.Stderr) != 0 {
		return ret, &aptPurgeError{info: map[string]any{
			"errors":  []string{string(removeResult.Stderr)},
			"changes": ret,
		}}
	}
	return ret, nil
}

func aptPurgeArch(rt *runtime.Runtime) string {
	if rt == nil || rt.Facts == nil {
		return ""
	}
	return rt.Facts.CPU().Arch
}

func aptPurgeTargets(a map[string]any, osarch string) (*purgeTargetMap, error) {
	value, supplied := a["pkgs"]
	if supplied && value != nil {
		items, isList, empty := purgeItems(value)
		if !isList {
			if !sourceTargetTruthy(value) {
				return aptPurgeTargetsFromName(a, osarch)
			}
			return nil, &runtime.UnsupportedError{Kind: "argument", Name: "pkg.purge pkgs"}
		}
		if !empty {
			targets := newPurgeTargetMap(len(items))
			for _, item := range items {
				target, err := purgeTargetFromItem(item, func(name string) string {
					return normalizeName(name, osarch)
				})
				if err != nil {
					return nil, &runtime.UnsupportedError{Kind: "argument", Name: "pkg.purge pkgs"}
				}
				if targets.has(target.name) {
					return nil, duplicatePurgeTargetsError(items)
				}
				targets.put(target)
			}
			return targets, nil
		}
	}

	return aptPurgeTargetsFromName(a, osarch)
}

func aptPurgeTargetsFromName(a map[string]any, osarch string) (*purgeTargetMap, error) {
	targets := newPurgeTargetMap(0)
	value, supplied := a["name"]
	if !supplied || value == nil {
		return targets, nil
	}
	name, ok := value.(string)
	if !ok {
		if pointer, isPointer := value.(*string); isPointer && pointer == nil {
			return targets, nil
		}
		return nil, fmt.Errorf("argument %q must be a string", "name")
	}
	if name == "" {
		return targets, nil
	}
	for _, component := range strings.Split(name, ",") {
		// The source name branch is a dict comprehension. It preserves an empty
		// comma component as a nonmatching key and overwrites normalized repeats
		// without moving their original insertion position.
		targets.put(purgeTarget{name: normalizeName(component, osarch)})
	}
	return targets, nil
}

func aptPurgeMatchingTargets(current map[string]string, params *purgeTargetMap, seen map[string]bool) ([]string, map[string]bool) {
	if seen == nil {
		seen = map[string]bool{}
	}
	targets := make([]string, 0, len(params.index))
	for _, target := range params.ordered() {
		if _, installed := current[target.name]; !installed || seen[target.name] {
			continue
		}
		seen[target.name] = true
		targets = append(targets, target.name)
	}
	return targets, seen
}

type aptPurgeSnapshotResult struct {
	installed      map[string]string
	removed        map[string]string
	installedOrder []string
	removedOrder   []string
}

type aptPurgePackageList struct {
	versions map[string][]string
	order    []string
}

func newAPTPurgePackageList() aptPurgePackageList {
	return aptPurgePackageList{versions: map[string][]string{}}
}

func (l *aptPurgePackageList) add(name, version string) {
	if _, exists := l.versions[name]; !exists {
		l.order = append(l.order, name)
	}
	l.versions[name] = append(l.versions[name], version)
}

func (l aptPurgePackageList) overlay(other aptPurgePackageList) aptPurgePackageList {
	ret := newAPTPurgePackageList()
	for _, name := range l.order {
		ret.add(name, "")
		ret.versions[name] = append([]string(nil), l.versions[name]...)
	}
	for _, name := range other.order {
		if _, exists := ret.versions[name]; !exists {
			ret.order = append(ret.order, name)
		}
		ret.versions[name] = append([]string(nil), other.versions[name]...)
	}
	return ret
}

func (l aptPurgePackageList) strings() map[string]string {
	ret := make(map[string]string, len(l.versions))
	for name, versions := range l.versions {
		ordered := append([]string(nil), versions...)
		sort.Strings(ordered)
		unique := ordered[:0]
		for _, version := range ordered {
			if len(unique) == 0 || unique[len(unique)-1] != version {
				unique = append(unique, version)
			}
		}
		ret[name] = strings.Join(unique, ",")
	}
	return ret
}

func aptPurgeSnapshot(ctx context.Context, rt *runtime.Runtime) (aptPurgeSnapshotResult, error) {
	result, err := aptPurgeRun(ctx, rt, []string{"dpkg-query", "--showformat", aptPurgeQueryFormat, "-W"})
	if err != nil {
		return aptPurgeSnapshotResult{}, err
	}
	if result.ExitCode != 0 {
		return aptPurgeSnapshotResult{}, fmt.Errorf("dpkg-query exited with code %d: %s", result.ExitCode, result.Stderr)
	}

	installed := newAPTPurgePackageList()
	removed := newAPTPurgePackageList()
	purgeDesired := newAPTPurgePackageList()
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		lineType, status, name, version, arch := fields[0], fields[2], fields[3], fields[4], fields[5]
		if aptPurgeArch(rt) == "amd64" && arch != "all" && arch != "amd64" {
			name += ":" + arch
		}
		switch {
		case (strings.Contains(lineType, "install") || strings.Contains(lineType, "hold")) && strings.Contains(status, "installed"):
			installed.add(name, version)
		case strings.Contains(lineType, "deinstall"):
			removed.add(name, version)
		case strings.Contains(lineType, "purge") && status == "installed":
			purgeDesired.add(name, version)
		}
	}
	effectiveInstalled := purgeDesired.overlay(installed)
	return aptPurgeSnapshotResult{
		installed:      effectiveInstalled.strings(),
		removed:        removed.strings(),
		installedOrder: append([]string(nil), effectiveInstalled.order...),
		removedOrder:   append([]string(nil), removed.order...),
	}, nil
}

// aptPurgeRun is the bounded shell-free subprocess boundary for every
// _uninstall readback and mutation. A completed nonzero result is returned to
// the caller because aptpkg._uninstall reads state before deciding whether an
// stderr-bearing apt failure becomes a CommandExecutionError.
func aptPurgeRun(ctx context.Context, rt *runtime.Runtime, argv []string) (process.CommandResult, error) {
	if rt == nil || rt.Runner == nil {
		return process.CommandResult{}, errors.New("APT purge requires a runner")
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{}, err
	}
	cmd := runtime.Command(argv...)
	cmd.Shell = false
	cmd.MaxStdoutBytes, cmd.MaxStderrBytes = aptPurgeOutputLimit, aptPurgeOutputLimit
	result := rt.Runner.Run(ctx, cmd)
	if result.Err != nil {
		return process.CommandResult{}, result.Err
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{}, err
	}
	if result.StdoutTruncated || result.StderrTruncated || len(result.Stdout) > aptPurgeOutputLimit || len(result.Stderr) > aptPurgeOutputLimit {
		return process.CommandResult{}, process.ErrOutputLimit
	}
	return result, nil
}

func aptRunIgnoreExit(ctx context.Context, rt *runtime.Runtime, argv []string) (string, error) {
	r := rt.Runner.Run(ctx, runtime.Command(argv...))
	if r.Err != nil {
		return "", r.Err
	}
	return string(r.Stdout), nil
}

func (p *commandProvider) hold(ctx context.Context, rt *runtime.Runtime, hold bool, a map[string]any) (any, error) {
	ns, err := packageArgs(a)
	if err != nil {
		return nil, err
	}
	if len(ns) == 0 {
		return nil, errors.New("one of name or pkgs must be specified")
	}
	state := "install"
	if hold {
		state = "hold"
	}
	ret := map[string]any{}
	for _, n := range ns {
		o, err := aptHoldResult(ctx, rt, []string{"dpkg", "--get-selections", n})
		if err != nil {
			if len(ret) > 0 {
				return ret, err
			}
			return nil, err
		}
		s := parseSelections(o)
		// Salt's get_selections(pattern=n, state="hold") returns an empty
		// mapping when dpkg has no readback for the target.  This is the
		// source-level "not currently held" branch: it must not be inferred
		// as an install state and must not reach set-selections.
		if len(s) == 0 {
			entry := map[string]any{"name": n, "changes": map[string]any{}, "result": false, "comment": ""}
			if hold {
				entry["comment"] = fmt.Sprintf("Package %s not currently held.", n)
			} else {
				entry["comment"] = fmt.Sprintf("Package %s does not have a state.", n)
			}
			ret[n] = entry
			continue
		}
		cur := ""
		present := false
		for k, v := range s {
			for _, x := range v {
				if x == n {
					cur = k
					present = true
				}
			}
		}
		entry := map[string]any{"name": n, "changes": map[string]any{}, "result": false, "comment": ""}
		if !present {
			if !hold {
				entry["comment"] = fmt.Sprintf("Package %s does not have a state.", n)
				ret[n] = entry
				continue
			}
			// A non-empty selection readback with an unrelated package is not
			// the empty source state; retain the existing transition behavior.
			cur = "install"
		}
		if cur == state {
			entry["result"] = true
			if hold {
				entry["comment"] = fmt.Sprintf("Package %s is already set to be held.", n)
			} else {
				entry["comment"] = fmt.Sprintf("Package %s is already set not to be held.", n)
			}
			ret[n] = entry
			continue
		}
		if hold && rt.Options.Test {
			entry["result"] = nil
			entry["comment"] = fmt.Sprintf("Package %s is set to be held.", n)
			ret[n] = entry
			continue
		}
		// Readback is deliberately completed before this second, immediate
		// cancellation check; no dpkg mutation may begin after cancellation.
		if err := ctx.Err(); err != nil {
			if len(ret) > 0 {
				return ret, err
			}
			return nil, err
		}
		in := n + " " + state + "\n"
		if _, err = aptHoldResultWithInput(ctx, rt, []string{"dpkg", "--set-selections"}, in); err != nil {
			if len(ret) > 0 {
				return ret, err
			}
			return nil, err
		}
		entry["changes"] = map[string]any{"old": cur, "new": state}
		entry["result"] = true
		if hold {
			entry["comment"] = fmt.Sprintf("Package %s is now being held.", n)
		} else {
			entry["comment"] = fmt.Sprintf("Package %s is no longer being held.", n)
		}
		ret[n] = entry
	}
	return ret, nil
}

const aptHoldOutputLimit = 1 << 20

// Hold uses a narrowly scoped bounded command path because both its dpkg
// readback and mutation consume package-derived data at the subprocess
// boundary. Other APT commands retain their existing capture semantics.
func aptHoldResult(ctx context.Context, rt *runtime.Runtime, argv []string) (string, error) {
	cmd := runtime.Command(argv...)
	cmd.Shell = false
	cmd.MaxStdoutBytes, cmd.MaxStderrBytes = aptHoldOutputLimit, aptHoldOutputLimit
	r := rt.Runner.Run(ctx, cmd)
	if r.Err != nil {
		return "", r.Err
	}
	if r.ExitCode != 0 {
		return "", fmt.Errorf("%s exited with code %d: %s", argv[0], r.ExitCode, r.Stderr)
	}
	return string(r.Stdout), nil
}

func aptHoldResultWithInput(ctx context.Context, rt *runtime.Runtime, argv []string, in string) (string, error) {
	cmd, err := runtime.CommandWithInputBounded(argv, in)
	if err != nil {
		return "", err
	}
	cmd.Shell = false
	cmd.MaxStdoutBytes, cmd.MaxStderrBytes = aptHoldOutputLimit, aptHoldOutputLimit
	r := rt.Runner.Run(ctx, cmd)
	if r.Err != nil {
		return "", r.Err
	}
	if r.ExitCode != 0 {
		return "", fmt.Errorf("%s exited with code %d: %s", argv[0], r.ExitCode, r.Stderr)
	}
	return string(r.Stdout), nil
}

func aptResultWithInput(ctx context.Context, rt *runtime.Runtime, argv []string, in string) (string, error) {
	cmd, err := runtime.CommandWithInputBounded(argv, in)
	if err != nil {
		return "", err
	}
	r := rt.Runner.Run(ctx, cmd)
	if r.Err != nil {
		return "", r.Err
	}
	if r.ExitCode != 0 {
		return "", fmt.Errorf("%s exited with code %d: %s", argv[0], r.ExitCode, r.Stderr)
	}
	return string(r.Stdout), nil
}

func (p *commandProvider) setSelections(ctx context.Context, rt *runtime.Runtime, a map[string]any) (any, error) {
	sel, ok, err := selectionValue(a["selection"])
	if err != nil {
		return nil, err
	}
	pathValue := stringArg(a["path"])
	if hasControl(pathValue) {
		return nil, errors.New("invalid selection path")
	}
	if env := stringArg(a["saltenv"]); env != "" && env != "base" {
		return nil, &runtime.UnsupportedError{Kind: "function", Name: "pkg.set_selections saltenv"}
	}
	if pathValue != "" && sel != nil && len(sel) != 0 {
		return nil, errors.New("selection and path are mutually exclusive")
	}
	if pathValue != "" {
		if strings.Contains(pathValue, "://") {
			return nil, &runtime.UnsupportedError{Kind: "function", Name: "pkg.set_selections path"}
		}
		data, err := runtime.ReadFileBounded(rt.FS, pathValue, maxAPTInputBytes)
		if err != nil {
			return nil, err
		}
		sel = map[string][]string{}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if len(fields) != 2 {
				return nil, errors.New("malformed selection file")
			}
			sel[fields[1]] = append(sel[fields[1]], fields[0])
		}
		ok = true
	}
	if !ok {
		if a["selection"] == nil {
			return map[string]any{}, nil
		}
		return nil, errors.New("argument \"selection\" must be an object of state to package lists")
	}
	validStates := map[string]bool{"install": true, "hold": true, "deinstall": true, "purge": true}
	keys := make([]string, 0, len(sel))
	ordered := make(map[string][]string, len(sel))
	for st, ns := range sel {
		if !validStates[st] || invalidAPTToken(st) {
			return nil, fmt.Errorf("invalid selection state %q", st)
		}
		keys = append(keys, st)
		ordered[st] = append([]string(nil), ns...)
		sort.Strings(ordered[st])
		for _, n := range ns {
			if invalidAPTToken(n) {
				return nil, fmt.Errorf("invalid package name %q", n)
			}
		}
	}
	sort.Strings(keys)
	var input strings.Builder
	for _, st := range keys {
		for _, n := range ordered[st] {
			input.WriteString(n)
			input.WriteByte(' ')
			input.WriteString(st)
			input.WriteByte('\n')
		}
	}
	if input.Len() > maxAPTInputBytes {
		return nil, fmt.Errorf("selection input exceeds %d bytes", maxAPTInputBytes)
	}
	ret := map[string]any{}
	if input.Len() == 0 {
		return ret, nil
	}
	// Read first, just as Salt does. This also makes clear safe: malformed
	// input and failed reads can never erase the existing selection database.
	oldOut, err := aptResult(ctx, rt, []string{"dpkg", "--get-selections", "*"})
	if err != nil {
		return nil, err
	}
	old := parseSelections(oldOut)
	oldState := map[string]string{}
	for st, ns := range old {
		for _, n := range ns {
			oldState[n] = st
		}
	}
	changed := make([]struct{ name, state string }, 0)
	for _, st := range keys {
		for _, n := range ordered[st] {
			if oldState[n] != st {
				changed = append(changed, struct{ name, state string }{n, st})
			}
		}
	}
	if len(changed) == 0 {
		return ret, nil
	}
	if boolDefault(a, "clear", false) {
		if _, err := aptResult(ctx, rt, []string{"dpkg", "--clear-selections"}); err != nil {
			return nil, err
		}
	}
	for _, item := range changed {
		if _, err := aptResultWithInput(ctx, rt, []string{"dpkg", "--set-selections"}, item.name+" "+item.state+"\n"); err != nil {
			return nil, err
		}
		ret[item.name] = map[string]any{"old": oldState[item.name], "new": item.state}
	}
	return ret, nil
}

func selectionValue(v any) (map[string][]string, bool, error) {
	if v == nil {
		return nil, false, nil
	}
	if typed, ok := v.(map[string][]string); ok {
		return typed, true, nil
	}
	raw, ok := v.(map[string]any)
	if !ok {
		return nil, false, errors.New("argument \"selection\" must be an object of state to package lists")
	}
	out := make(map[string][]string, len(raw))
	for state, value := range raw {
		items, ok := value.([]any)
		if !ok {
			if typed, yes := value.([]string); yes {
				out[state] = typed
				continue
			}
			return nil, false, fmt.Errorf("selection state %q must contain a list of strings", state)
		}
		for _, item := range items {
			name, ok := item.(string)
			if !ok {
				return nil, false, fmt.Errorf("selection state %q must contain a list of strings", state)
			}
			out[state] = append(out[state], name)
		}
	}
	return out, true, nil
}

const maxAPTInputBytes = 1 << 20

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
func (p *commandProvider) upgrade(ctx context.Context, rt *runtime.Runtime, a map[string]any) (any, error) {
	if cache, ok := a["cache_valid_time"]; ok && cache != nil {
		if n, good := intValue(cache); good && n != 0 {
			return nil, &runtime.UnsupportedError{Kind: "argument", Name: "pkg.upgrade cache_valid_time"}
		}
	}
	cmd := []string{"apt-get", "-q", "-y", "-o", "DPkg::Options::=--force-confold", "-o", "DPkg::Options::=--force-confdef"}
	if boolDefault(a, "refresh", true) {
		if err := p.Refresh(ctx, rt); err != nil {
			return nil, err
		}
	}
	if boolDefault(a, "force_conf_new", false) {
		cmd = []string{"apt-get", "-q", "-y", "-o", "DPkg::Options::=--force-confnew"}
	}
	if boolDefault(a, "download_only", false) {
		cmd = append(cmd, "--download-only")
	}
	if boolDefault(a, "downloadonly", false) && !boolDefault(a, "download_only", false) {
		cmd = append(cmd, "--download-only")
	}
	if boolDefault(a, "force_yes", false) {
		cmd = append(cmd, "--force-yes")
	}
	if boolDefault(a, "skip_verify", false) {
		cmd = append(cmd, "--allow-unauthenticated")
	}
	if boolDefault(a, "allow_downgrades", false) {
		cmd = append(cmd, "--allow-downgrades")
	}
	if boolDefault(a, "dist_upgrade", false) {
		cmd = append(cmd, "dist-upgrade")
	} else {
		cmd = append(cmd, "upgrade")
	}
	old, err := installedPackages(ctx, rt)
	if err != nil {
		return nil, err
	}
	_, runErr := aptResult(ctx, rt, cmd)
	if runErr != nil {
		return map[string]any{}, fmt.Errorf("problem encountered upgrading packages: %w", runErr)
	}
	new, readErr := installedPackages(ctx, rt)
	if readErr != nil {
		return nil, readErr
	}
	changes := comparePackages(old, new)
	return changes, nil
}

func installedPackages(ctx context.Context, rt *runtime.Runtime) (map[string]string, error) {
	o, err := aptResult(ctx, rt, []string{"dpkg-query", "-W", "-f=${Package} ${Version}\\n"})
	if err != nil {
		return nil, err
	}
	r := map[string]string{}
	for _, line := range nonEmptyLines(o) {
		f := strings.Fields(line)
		if len(f) >= 2 {
			r[f[0]] = f[1]
		}
	}
	return r, nil
}
func comparePackages(old, new map[string]string) map[string]any {
	r := map[string]any{}
	for n, ov := range old {
		if _, ok := new[n]; !ok {
			r[n] = map[string]any{"old": ov, "new": ""}
		}
	}
	for n, v := range new {
		if ov, ok := old[n]; !ok || ov != v {
			r[n] = map[string]any{"old": ov, "new": v}
		}
	}
	return r
}
func (p *commandProvider) listUpgrades(ctx context.Context, rt *runtime.Runtime, a map[string]any) (any, error) {
	if cache, ok := a["cache_valid_time"]; ok && cache != nil {
		if n, good := intValue(cache); good && n != 0 {
			return nil, &runtime.UnsupportedError{Kind: "argument", Name: "pkg.list_upgrades cache_valid_time"}
		}
	}
	cmd := []string{"apt-get", "--just-print"}
	if boolDefault(a, "refresh", true) {
		if err := p.Refresh(ctx, rt); err != nil {
			return nil, err
		}
	}
	if boolDefault(a, "dist_upgrade", true) {
		cmd = append(cmd, "dist-upgrade")
	} else {
		cmd = append(cmd, "upgrade")
	}
	o, e := aptResult(ctx, rt, cmd)
	if e != nil {
		return nil, e
	}
	r := map[string]string{}
	re := regexp.MustCompile(`(?m)^Conf ([^ ]+) \(([^ ]+)`)
	for _, m := range re.FindAllStringSubmatch(o, -1) {
		r[m[1]] = m[2]
	}
	return r, nil
}
func (p *commandProvider) latestCandidate(ctx context.Context, rt *runtime.Runtime, n string) (string, error) {
	o, e := aptResult(ctx, rt, []string{"apt-cache", "policy", n})
	if e != nil {
		return "", e
	}
	for _, l := range strings.Split(o, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "Candidate:" && f[1] != "(none)" {
			return f[1], nil
		}
	}
	return "", nil
}
func parseParagraphs(s string) []map[string]string {
	var r []map[string]string
	for _, p := range strings.Split(s, "\n\n") {
		m := map[string]string{}
		for _, l := range strings.Split(p, "\n") {
			if x := strings.IndexByte(l, ':'); x > 0 {
				m[l[:x]] = strings.TrimSpace(l[x+1:])
			}
		}
		if len(m) > 0 {
			r = append(r, m)
		}
	}
	return r
}
func (p *commandProvider) show(ctx context.Context, rt *runtime.Runtime, a map[string]any) (any, error) {
	ns, _ := a["names"].([]string)
	if len(ns) == 0 {
		if n, ok := a["name"].(string); ok && n != "" {
			ns = []string{n}
		}
	}
	for _, n := range ns {
		if invalidAPTToken(n) {
			return nil, fmt.Errorf("invalid package name %q", n)
		}
	}
	if len(ns) == 0 {
		return map[string]any{}, nil
	}
	if boolDefault(a, "refresh", false) {
		if err := p.Refresh(ctx, rt); err != nil {
			return nil, err
		}
	}
	allowed := map[string]bool{}
	if filter := strings.TrimSpace(stringArg(a["filter"])); filter != "" {
		for _, key := range strings.Split(filter, ",") {
			key = strings.TrimSpace(key)
			if key == "" || invalidAPTToken(key) {
				return nil, fmt.Errorf("invalid show filter %q", key)
			}
			allowed[strings.ToLower(key)] = true
		}
	}
	o, e := aptEmptyOnFailure(ctx, rt, append([]string{"apt-cache", "show"}, ns...))
	if e != nil {
		return nil, e
	}
	r := map[string]any{}
	for _, m := range parseParagraphs(o) {
		n, v := m["Package"], m["Version"]
		if n != "" && v != "" {
			delete(m, "Package")
			delete(m, "Version")
			if len(allowed) > 0 {
				for k := range m {
					if !allowed[strings.ToLower(k)] {
						delete(m, k)
					}
				}
			}
			r0, _ := r[n].(map[string]any)
			if r0 == nil {
				r0 = map[string]any{}
				r[n] = r0
			}
			r0[v] = m
		}
	}
	return r, nil
}
func (p *commandProvider) listRepo(ctx context.Context, rt *runtime.Runtime, a map[string]any) (any, error) {
	ns, err := filePackageArgs(a)
	if err != nil {
		return nil, err
	}
	cmd := []string{"apt-cache", "dump"}
	if len(ns) > 0 {
		cmd = append([]string{"apt-cache", "show"}, ns...)
	}
	o, e := aptEmptyOnFailure(ctx, rt, cmd)
	if e != nil {
		return nil, e
	}
	r := map[string][]string{}
	for _, m := range parseParagraphs(o) {
		if n, v := m["Package"], m["Version"]; n != "" && v != "" {
			r[n] = append(r[n], v)
		}
	}
	return r, nil
}
func (p *commandProvider) owner(ctx context.Context, rt *runtime.Runtime, a map[string]any) (any, error) {
	p0, _ := a["paths"].([]string)
	if len(p0) == 0 {
		return "", nil
	}
	r := map[string]string{}
	for _, x := range p0 {
		if invalidAPTToken(x) {
			return nil, fmt.Errorf("invalid path %q", x)
		}
		o, e := aptRun(ctx, rt, []string{"dpkg", "-S", x})
		if e != nil {
			r[x] = ""
			continue
		}
		if strings.Contains(strings.ToLower(o), "no path found") {
			r[x] = ""
			continue
		}
		if i := strings.IndexByte(o, ':'); i >= 0 {
			r[x] = o[:i]
		}
	}
	if len(r) == 1 {
		for _, v := range r {
			return v, nil
		}
	}
	return r, nil
}
func (p *commandProvider) which(ctx context.Context, rt *runtime.Runtime, x string) any {
	if !strings.HasPrefix(x, "/") {
		return false
	}
	if rt.FS != nil {
		if _, err := rt.FS.Stat(x); err != nil {
			return false
		}
	}
	o, e := aptRun(ctx, rt, []string{"dpkg", "-S", x})
	if e != nil {
		return false
	}
	if strings.Contains(strings.ToLower(o), "no path found") {
		return nil
	}
	if i := strings.IndexByte(o, ':'); i >= 0 {
		return o[:i]
	}
	return nil
}
func (p *commandProvider) files(ctx context.Context, rt *runtime.Runtime, fn string, a map[string]any) (any, error) {
	ns, err := filePackageArgs(a)
	if err != nil {
		return nil, err
	}
	query := []string{"dpkg-query", "-f=${db:Status-Status}\t${binary:Package}\n", "-W"}
	query = append(query, ns...)
	o, queryErr := aptResult(ctx, rt, query)
	if queryErr != nil {
		return nil, queryErr
	}
	ns = installedPackageNames(o)
	if fn == "file_dict" {
		r := map[string]any{}
		for _, n := range ns {
			o, e := aptRunChecked(ctx, rt, []string{"dpkg", "-L", n})
			if e != nil {
				return nil, e
			}
			r[n] = nonEmptyLines(o)
		}
		return map[string]any{"errors": []string{}, "packages": r}, nil
	}
	r := map[string]any{"errors": []string{}, "files": []string{}}
	for _, n := range ns {
		o, e := aptRunChecked(ctx, rt, []string{"dpkg", "-L", n})
		if e != nil {
			return nil, e
		}
		r["files"] = append(r["files"].([]string), nonEmptyLines(o)...)
	}
	files := r["files"].([]string)
	sort.Strings(files)
	uniq := files[:0]
	for _, f := range files {
		if len(uniq) == 0 || uniq[len(uniq)-1] != f {
			uniq = append(uniq, f)
		}
	}
	r["files"] = uniq
	return r, nil
}

func installedPackageNames(out string) []string {
	seen := map[string]bool{}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) == 2 && f[0] == "installed" && f[1] != "" && !seen[f[1]] {
			seen[f[1]] = true
			names = append(names, f[1])
		}
	}
	sort.Strings(names)
	return names
}
func (p *commandProvider) info(ctx context.Context, rt *runtime.Runtime, a map[string]any) (any, error) {
	ns, _ := a["names"].([]string)
	format := "package:${Package}\nrevision:${binary:Revision}\narchitecture:${Architecture}\nmaintainer:${Maintainer}\nsummary:${Summary}\nsource:${source:Package}\nversion:${Version}\nsection:${Section}\ninstalled_size:${Installed-size}\nsize:${Size}\nMD5:${MD5sum}\nSHA1:${SHA1}\nSHA256:${SHA256}\norigin:${Origin}\nhomepage:${Homepage}\nstatus:${db:Status-Abbrev}\ninstall_date:${db-fsys:Last-Modified}\ndescription:${Description}\n\n*/~^\\*\n"
	argv := append([]string{"dpkg-query", "-W", "-f=" + format}, ns...)
	runResult := rt.Runner.Run(ctx, runtime.Command(argv...))
	if runResult.Err != nil {
		return nil, runResult.Err
	}
	if runResult.ExitCode != 0 && boolDefault(a, "failhard", true) {
		return nil, fmt.Errorf("dpkg-query exited with code %d: %s", runResult.ExitCode, runResult.Stderr)
	}
	o := string(runResult.Stdout)
	r := map[string]any{}
	for _, block := range strings.Split(o, "\n*/~^\\*\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		m := map[string]any{}
		for _, line := range strings.Split(block, "\n") {
			i := strings.IndexByte(line, ':')
			if i < 1 {
				continue
			}
			key, val := line[:i], line[i+1:]
			if val == "" {
				continue
			}
			if key == "status" && (len(val) < 2 || val[1] != 'i') {
				m = nil
				break
			}
			switch key {
			case "package":
				m["name"] = val
			case "origin":
				m["vendor"] = val
			case "section":
				m["group"] = val
			case "maintainer":
				m["packager"] = val
			case "homepage":
				m["url"] = val
			case "status":
			default:
				m[key] = val
			}
		}
		if m != nil {
			if n, ok := m["name"].(string); ok && n != "" {
				r[n] = m
			}
		}
	}
	// Accept the compact fixture format used by older Runtime callers while
	// the provider's production query remains the lowpkg.info format above.
	if len(r) == 0 {
		for _, line := range strings.Split(o, "\n") {
			f := strings.Split(line, "\t")
			if len(f) >= 3 && strings.Contains(f[2], "installed") {
				r[f[0]] = map[string]any{"name": f[0], "version": f[1]}
			}
		}
	}
	if len(r) == 0 && boolDefault(a, "failhard", true) {
		return nil, errors.New("no installed packages matched")
	}
	return r, nil
}
func (p *commandProvider) downloaded(ctx context.Context, rt *runtime.Runtime, a map[string]any) (any, error) {
	if rt.FS == nil {
		return nil, &runtime.UnsupportedError{Kind: "function", Name: "pkg.list_downloaded filesystem"}
	}
	root := "/var/cache/apt/archives"
	if x := stringArg(a["root"]); x != "" {
		root = filepath.Join(x, "var/cache/apt/archives")
	}
	paths := []string{}
	queue := []string{root}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		entries, err := rt.FS.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			name := filepath.Join(dir, entry.Name())
			if entry.IsDir() {
				if len(queue)+len(paths) >= maxDownloadedEntries {
					return nil, errors.New("pkg.list_downloaded traversal limit exceeded")
				}
				queue = append(queue, name)
				continue
			}
			if strings.HasSuffix(entry.Name(), ".deb") {
				paths = append(paths, name)
			}
		}
	}
	sort.Strings(paths)
	r := map[string]any{}
	for _, x := range paths {
		info, err := rt.FS.Stat(x)
		if err != nil {
			return nil, err
		}
		metaOut, err := aptResult(ctx, rt, []string{"dpkg-deb", "-f", x, "Package", "Version"})
		if err != nil {
			return nil, err
		}
		fields := strings.Fields(metaOut)
		if len(fields) < 2 {
			continue
		}
		ts, ok := fileCTime(info)
		if !ok {
			return nil, &runtime.UnsupportedError{Kind: "function", Name: "pkg.list_downloaded ctime"}
		}
		// Salt's utcfromtimestamp returns a naive UTC datetime; isoformat()
		// therefore has no offset suffix.
		meta := map[string]any{"path": x, "size": info.Size(), "creation_date_time_t": ts.Unix(), "creation_date_time": ts.UTC().Format("2006-01-02T15:04:05")}
		versions, _ := r[fields[0]].(map[string]any)
		if versions == nil {
			versions = map[string]any{}
			r[fields[0]] = versions
		}
		versions[fields[1]] = meta
	}
	return r, nil
}

const maxDownloadedEntries = 10000

// fileCTime extracts the platform FileInfo ctime without substituting mtime.
// Reflection keeps the FileSystem contract portable across Unix and Windows.
func fileCTime(info interface{ Sys() interface{} }) (time.Time, bool) {
	if info == nil {
		return time.Time{}, false
	}
	s := info.Sys()
	if s == nil {
		return time.Time{}, false
	}
	v := reflect.ValueOf(s)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return time.Time{}, false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return time.Time{}, false
	}
	for _, name := range []string{"Ctim", "Birthtimespec", "CreationTime"} {
		f := v.FieldByName(name)
		if !f.IsValid() {
			continue
		}
		if f.Kind() == reflect.Struct {
			sec, sok := reflectIntField(f, "Sec")
			nsec, _ := reflectIntField(f, "Nsec")
			if sok {
				return time.Unix(sec, nsec), true
			}
		}
		if f.Kind() >= reflect.Int && f.Kind() <= reflect.Int64 {
			return time.Unix(f.Int(), 0), true
		}
	}
	return time.Time{}, false
}
func reflectIntField(v reflect.Value, name string) (int64, bool) {
	f := v.FieldByName(name)
	if !f.IsValid() || f.Kind() < reflect.Int || f.Kind() > reflect.Int64 {
		return 0, false
	}
	return f.Int(), true
}

func (p *commandProvider) versionCmp(ctx context.Context, rt *runtime.Runtime, a, b string, ignore bool) (any, error) {
	if ignore {
		if i := strings.IndexByte(a, ':'); i >= 0 {
			a = a[i+1:]
		}
		if i := strings.IndexByte(b, ':'); i >= 0 {
			b = b[i+1:]
		}
	}
	for _, item := range []struct {
		op    string
		value int
	}{{"lt", -1}, {"eq", 0}, {"gt", 1}} {
		r := rt.Runner.Run(ctx, runtime.Command("dpkg", "--compare-versions", a, item.op, b))
		if r.Err != nil {
			return nil, r.Err
		}
		if r.ExitCode == 0 {
			return item.value, nil
		}
		if r.ExitCode != 1 && r.ExitCode != 2 {
			return nil, fmt.Errorf("dpkg --compare-versions exited with code %d: %s", r.ExitCode, r.Stderr)
		}
		if r.ExitCode == 2 {
			return nil, nil
		}
	}
	return nil, nil
}

func services(s string) []string {
	r := []string{}
	seen := map[string]bool{}
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "SERVICE:") {
			x := strings.TrimPrefix(l, "SERVICE:")
			if i := strings.IndexByte(x, ','); i >= 0 {
				x = x[:i]
			}
			x = strings.TrimSpace(x)
			if x != "" && !seen[x] {
				seen[x] = true
				r = append(r, x)
			}
		}
	}
	return r
}

// Debian's ordering: epoch, upstream version, then revision; digits compare
// numerically and '~' sorts before every other character.
func debVersionCmp(a, b string, ignore bool) int {
	if ignore {
		if i := strings.IndexByte(a, ':'); i >= 0 {
			a = a[i+1:]
		}
		if i := strings.IndexByte(b, ':'); i >= 0 {
			b = b[i+1:]
		}
	}
	return debPart(a, b)
}
func debPart(a, b string) int {
	ea, ra := splitEpoch(a)
	eb, rb := splitEpoch(b)
	if ea != eb {
		return sign(ea - eb)
	}
	ua, da := splitRev(ra)
	ub, db := splitRev(rb)
	if c := debianSegment(ua, ub); c != 0 {
		return c
	}
	return debianSegment(da, db)
}
func splitEpoch(s string) (int, string) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return 0, s
	}
	n, e := strconv.Atoi(s[:i])
	if e != nil {
		return 0, s
	}
	return n, s[i+1:]
}
func splitRev(s string) (string, string) {
	i := strings.LastIndexByte(s, '-')
	if i < 0 {
		return s, "0"
	}
	return s[:i], s[i+1:]
}
func sign(x int) int {
	if x < 0 {
		return -1
	}
	if x > 0 {
		return 1
	}
	return 0
}
func debianSegment(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		for (len(a) > 0 && !isDigit(a[0])) || (len(b) > 0 && !isDigit(b[0])) {
			ca, cb := debChar(a), debChar(b)
			if ca != cb {
				return sign(ca - cb)
			}
			if len(a) > 0 && !isDigit(a[0]) {
				a = a[1:]
			}
			if len(b) > 0 && !isDigit(b[0]) {
				b = b[1:]
			}
		}
		if len(a) > 0 && a[0] >= '0' && a[0] <= '9' || len(b) > 0 && b[0] >= '0' && b[0] <= '9' {
			i, j := 0, 0
			for i < len(a) && a[i] >= '0' && a[i] <= '9' {
				i++
			}
			for j < len(b) && b[j] >= '0' && b[j] <= '9' {
				j++
			}
			x, y := strings.TrimLeft(a[:i], "0"), strings.TrimLeft(b[:j], "0")
			if len(x) != len(y) {
				return sign(len(x) - len(y))
			}
			if x != y {
				if x < y {
					return -1
				}
				return 1
			}
			a = a[i:]
			b = b[j:]
			continue
		}
		if len(a) == 0 && len(b) == 0 {
			return 0
		}
		if len(a) == 0 {
			return -1
		}
		if len(b) == 0 {
			return 1
		}
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// dpkg's order is '~', end, letters, then non-letters (ordered by byte).
func debChar(s string) int {
	if len(s) == 0 {
		return 0
	}
	if s[0] == '~' {
		return -1
	}
	if unicode.IsLetter(rune(s[0])) {
		return int(s[0])
	}
	return int(s[0]) + 256
}
