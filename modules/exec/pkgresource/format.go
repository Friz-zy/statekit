package pkgresource

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

type AddPkgArgs struct {
	Pkgs   map[string]any `statekit:"name=pkgs"`
	Name   string         `statekit:"required,name=name"`
	PkgVer string         `statekit:"name=pkgver"`
}

type addPkgFunc struct{}

func (addPkgFunc) Name() string { return "pkg_resource.add_pkg" }
func (addPkgFunc) Args() any    { return AddPkgArgs{} }

// Execute mirrors Salt's setdefault/append: a non-list existing value trips
// the swallowed AttributeError, leaving the dict unchanged.
func (addPkgFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*AddPkgArgs)
	if existing, ok := a.Pkgs[a.Name]; ok {
		list, isList := existing.([]any)
		if !isList {
			return nil, nil
		}
		a.Pkgs[a.Name] = append(list, a.PkgVer)
		return nil, nil
	}
	a.Pkgs[a.Name] = []any{a.PkgVer}
	return nil, nil
}

type SortPkglistArgs struct {
	Pkgs map[string]any `statekit:"name=pkgs"`
}

type sortPkglistFunc struct{}

func (sortPkglistFunc) Name() string { return "pkg_resource.sort_pkglist" }
func (sortPkglistFunc) Args() any    { return SortPkglistArgs{} }
func (sortPkglistFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*SortPkglistArgs)
	if err := sortInPlace(a.Pkgs); err != nil {
		return nil, err
	}
	return nil, nil
}

// versionListError documents the intentional divergence for non-list scalar
// values: Python silently decomposes strings into characters (and raises an
// uncaught TypeError for numbers); StateKit refuses both.
var versionListError = errors.New(
	"expected a list of package version strings; Salt's Python semantics would decompose scalar values")

func sortInPlace(pkgs map[string]any) error {
	for key, versions := range pkgs {
		items, err := versionStringList(versions)
		if err != nil {
			return fmt.Errorf("key %q: %w", key, err)
		}
		sort.Strings(items)
		pkgs[key] = toAnyStrings(deduplicate(items))
	}
	return nil
}

func deduplicate(items []string) []string {
	out := items[:0]
	var prev string
	for i, item := range items {
		if i == 0 || item != prev {
			out = append(out, item)
		}
		prev = item
	}
	return out
}

type StringifyArgs struct {
	Pkgs map[string]any `statekit:"name=pkgs"`
}

type stringifyFunc struct{}

func (stringifyFunc) Name() string { return "pkg_resource.stringify" }
func (stringifyFunc) Args() any    { return StringifyArgs{} }
func (stringifyFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*StringifyArgs)
	stringifyInPlace(a.Pkgs)
	return nil, nil
}

// stringifyInPlace joins each list of installed versions into one
// comma-separated string, mutating the passed dict like Salt does.
func stringifyInPlace(pkgs map[string]any) {
	for key, versions := range pkgs {
		switch t := versions.(type) {
		case []string:
			pkgs[key] = strings.Join(t, ",")
		case []any:
			items := make([]string, 0, len(t))
			for _, item := range t {
				items = append(items, plainScalar(item))
			}
			pkgs[key] = strings.Join(items, ",")
		case string:
			pkgs[key] = t
		default:
			pkgs[key] = plainScalar(t)
		}
	}
}

// versionStringList validates the list-shaped entries sort_pkglist and
// stringify consume; see the divergence note on versionListError.
func versionStringList(v any) ([]string, error) {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%w: %s", versionListError, pythonScalar(item))
			}
			out = append(out, s)
		}
		return out, nil
	case []string:
		return t, nil
	default:
		return nil, fmt.Errorf("%w: %s", versionListError, pythonScalar(v))
	}
}

// checkExtraRequirementsFunc consumes CheckExtraRequirementsArgs declared
// in pkgresource.go.

type checkExtraRequirementsFunc struct{}

func (checkExtraRequirementsFunc) Name() string { return "pkg_resource.check_extra_requirements" }
func (checkExtraRequirementsFunc) Args() any    { return CheckExtraRequirementsArgs{} }
func (checkExtraRequirementsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CheckExtraRequirementsArgs)
	if a.PkgVer != "" && lookup(rt, "pkg.check_extra_requirements") {
		return delegate(ctx, rt, "pkg.check_extra_requirements", &CheckExtraRequirementsArgs{
			PkgName: a.PkgName,
			PkgVer:  a.PkgVer,
		})
	}
	return true, nil
}

// attrKeys enumerates the install attributes list_pkgs may report.
var attrKeys = []string{"epoch", "version", "release", "arch", "install_date", "install_date_time_t"}

// requestedAttrs mirrors Salt's requested_attr set algebra: the full key
// set for the string form attr="all" (the decoder wraps `attr: all` into a
// one-element list), otherwise the intersection with the requested keys
// plus the always-kept version/arch pair.
func requestedAttrs(attr []string) map[string]bool {
	requested := map[string]bool{}
	for _, key := range attrKeys {
		requested[key] = true
	}
	if len(attr) == 1 && attr[0] == "all" {
		return requested
	}
	keep := map[string]bool{"version": true, "arch": true}
	for _, key := range attr {
		keep[key] = true
	}
	for key := range requested {
		if !keep[key] {
			delete(requested, key)
		}
	}
	return requested
}

type FormatPkgListArgs struct {
	Packages       map[string]any `statekit:"name=packages"`
	VersionsAsList bool           `statekit:"name=versions_as_list"`
	Attr           []string       `statekit:"name=attr"`
}

type formatPkgListFunc struct{}

func (formatPkgListFunc) Name() string { return "pkg_resource.format_pkg_list" }
func (formatPkgListFunc) Args() any    { return FormatPkgListArgs{} }

// parseArch resolves the optional pkg.parse_arch delegate; the fallback is
// Salt's {"name": name, "arch": None} identity shape.
func parseArch(ctx context.Context, rt *runtime.Runtime, name string) (parsedName string, parsedArch any) {
	parsedName = name
	if !lookup(rt, "pkg.parse_arch") {
		return parsedName, nil
	}
	res, err := delegate(ctx, rt, "pkg.parse_arch", &ParseArchArgs{Name: name})
	if err != nil {
		return name, nil
	}
	parsed, ok := res.(map[string]any)
	if !ok {
		return name, nil
	}
	if s, ok := parsed["name"].(string); ok && s != "" {
		parsedName = s
	} else {
		parsedName = ""
	}
	return parsedName, parsed["arch"]
}

func (formatPkgListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*FormatPkgListArgs)
	if len(a.Attr) > 0 {
		return formatWithAttr(ctx, rt, a.Packages, requestedAttrs(a.Attr))
	}

	ret := map[string]any{}
	for name, versions := range a.Packages {
		entries, err := attrEntries(versions)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", name, err)
		}
		formatted := make([]any, 0, len(entries))
		for _, entry := range entries {
			for _, required := range []string{"epoch", "version", "release"} {
				if _, ok := entry[required]; !ok {
					return nil, fmt.Errorf("key %q: entry is missing the %q attribute", name, required)
				}
			}
			formatted = append(formatted, formatVersion(
				entry["epoch"], entry["version"], entry["release"]))
		}
		ret[name] = formatted
	}
	if !a.VersionsAsList {
		stringifyInPlace(ret)
	}
	return ret, nil
}

// formatWithAttr mirrors the attr branch: filtered attribute dicts are
// re-keyed under the architecture-stripped name whenever an entry's arch
// matches the parsed arch of the package name.
func formatWithAttr(ctx context.Context, rt *runtime.Runtime, packages map[string]any, requested map[string]bool) (any, error) {
	retAttr := map[string]any{}
	for name, versions := range packages {
		parsedName, parsedArch := parseArch(ctx, rt, name)
		entries, err := attrEntries(versions)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", name, err)
		}
		filteredVersions := make([]any, 0, len(entries))
		pkgName := ""
		for _, entry := range entries {
			filtered := map[string]any{}
			for key := range requested {
				if value, ok := entry[key]; ok {
					filtered[key] = value
				}
			}
			filteredVersions = append(filteredVersions, filtered)
			if arch, ok := entry["arch"]; ok && parsedName != "" && arch == parsedArch {
				pkgName = parsedName
			}
		}
		key := pkgName
		if key == "" {
			key = name
		}
		existing, _ := retAttr[key].([]any)
		retAttr[key] = append(existing, filteredVersions...)
	}
	return retAttr, nil
}

// attrListError reports a non-list where package entries are required.
var attrListError = errors.New("expected a list of package attribute dicts")

// attrEntries validates one package's list of attribute dicts (Salt's
// KeyError on wrong shapes surfaces as a Go error).
func attrEntries(v any) ([]map[string]any, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s", attrListError, plainScalar(v))
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("entry %s is not an attribute dict", plainScalar(item))
		}
		out = append(out, entry)
	}
	return out, nil
}

type FormatVersionArgs struct {
	Epoch   string `statekit:"name=epoch"`
	Version string `statekit:"required,name=version"`
	Release string `statekit:"name=release"`
}

type formatVersionFunc struct{}

func (formatVersionFunc) Name() string { return "pkg_resource.format_version" }
func (formatVersionFunc) Args() any    { return FormatVersionArgs{} }
func (formatVersionFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*FormatVersionArgs)
	return formatVersion(a.Epoch, a.Version, a.Release), nil
}

// truthy mirrors Python truthiness for the epoch/release scalars.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	case int:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	default:
		return true
	}
}

// formatVersion renders "epoch:version-release" following Salt's falsiness
// rules for epoch and release.
func formatVersion(epoch, version, release any) string {
	var b strings.Builder
	if truthy(epoch) {
		b.WriteString(plainScalar(epoch))
		b.WriteString(":")
	}
	b.WriteString(plainScalar(version))
	if truthy(release) {
		b.WriteString("-")
		b.WriteString(plainScalar(release))
	}
	return b.String()
}
