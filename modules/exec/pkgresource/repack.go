package pkgresource

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// validFileprotoRe mirrors salt.modules.config.valid_fileproto; kept local
// until the config family is ported (see package notes).
var validFileprotoRe = regexp.MustCompile(`^(?:salt|https?|ftp|file)://`)

// repackDictlist ports salt.utils.data.repack_dictlist for the plain
// no-recurse call _repack_pkgs makes: scalars become keys with None values,
// one-element dicts contribute their pair, anything else logs and collapses
// to an empty result exactly like Salt's error path.
func repackDictlist(data []any) map[string]any {
	ret := map[string]any{}
	for _, element := range data {
		switch v := element.(type) {
		case map[string]any:
			if len(v) != 1 {
				return map[string]any{}
			}
			for key, val := range v {
				ret[key] = val
			}
		case string:
			ret[v] = nil
		case int:
			ret[strconv.Itoa(v)] = nil
		case int64:
			ret[strconv.FormatInt(v, 10)] = nil
		case float64:
			ret[strconv.FormatFloat(v, 'g', -1, 64)] = nil
		default:
			// Salt accepts only str/int/float scalars here.
			return map[string]any{}
		}
	}
	return ret
}

// plainScalar renders a value like Python's str(): strings stay unquoted,
// booleans become True/False, numbers keep their literal shape.
func plainScalar(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	default:
		return pythonScalar(t)
	}
}

// pythonScalar renders a scalar with Python repr formatting (strings
// quoted); used only inside mirrored error messages.
func pythonScalar(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return "'" + t + "'"
	case bool:
		if t {
			return "True"
		}
		return "False"
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	default:
		return fmt.Sprintf("%v", t)
	}
}

// pythonRepr renders a value like Python's repr for the shapes pkg inputs
// carry (lists of dicts/scalars); key order inside multi-key maps follows
// sorted order because structured input does not preserve mapping order.
func pythonRepr(v any) string {
	switch t := v.(type) {
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			parts = append(parts, pythonRepr(item))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		keys := make([]string, 0, len(t))
		for key := range t {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, pythonRepr(key)+": "+pythonRepr(t[key]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return pythonScalar(t)
	}
}

// stringifyValue mirrors `_normalize_name(str(x)): str(y) if y is not None`.
func stringifyValue(v any) any {
	if v == nil {
		return nil
	}
	return plainScalar(v)
}

// repackPkgs ports _repack_pkgs: normalize names, stringify non-None values,
// and raise on duplicated package names after the repack collapsed them.
func repackPkgs(ctx context.Context, rt *runtime.Runtime, pkgs []any, normalize bool) (map[string]any, error) {
	repacked := map[string]any{}
	norm := normalizer(ctx, rt, normalize)
	for name, value := range repackDictlist(pkgs) {
		repacked[norm(name)] = stringifyValue(value)
	}
	if len(pkgs) != len(repacked) {
		return nil, fmt.Errorf(
			"You are passing a list of packages that contains duplicated packages names: %s. "+
				"This cannot be processed. In case you are targeting different versions of the "+
				"same package, please target them individually",
			pythonRepr(pkgs),
		)
	}
	return repacked, nil
}

type PackSourcesArgs struct {
	Sources   []any `statekit:"name=sources"`
	Normalize *bool `statekit:"name=normalize"`
}

type packSourcesFunc struct{}

func (packSourcesFunc) Name() string { return "pkg_resource.pack_sources" }
func (packSourcesFunc) Args() any    { return PackSourcesArgs{} }

// packSource is one ordered key/value pair from a one-element dict entry.
type packSource struct {
	name  string
	value any
}

// packSourcesImpl packs a list of one-element dicts into a single dict,
// returning an empty dict on invalid input instead of an error (Salt's
// logged error path). Pair order follows the input list like Salt's
// insertion-ordered dict, which parse_targets relies on.
func packSourcesImpl(ctx context.Context, rt *runtime.Runtime, sources []any, normalize bool) []packSource {
	norm := normalizer(ctx, rt, normalize)
	packed := []packSource{}
	for _, source := range sources {
		entry, ok := source.(map[string]any)
		if !ok || len(entry) != 1 {
			return nil
		}
		for key, value := range entry {
			packed = append(packed, packSource{name: norm(key), value: value})
		}
	}
	return packed
}

// packSourcesMap renders the packed pairs as the plain dict contract.
func packSourcesMap(packed []packSource) map[string]any {
	ret := make(map[string]any, len(packed))
	for _, pair := range packed {
		ret[pair.name] = pair.value
	}
	return ret
}

func (packSourcesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PackSourcesArgs)
	normalize := true
	if a.Normalize != nil {
		normalize = *a.Normalize
	}
	return packSourcesMap(packSourcesImpl(ctx, rt, a.Sources, normalize)), nil
}

type ParseTargetsArgs struct {
	Name        string   `statekit:"name=name"`
	Pkgs        []any    `statekit:"name=pkgs"`
	Sources     []any    `statekit:"name=sources"`
	Saltenv     *string  `statekit:"name=saltenv"`
	Normalize   *bool    `statekit:"name=normalize"`
	Version     *string  `statekit:"name=version"`
	AdvisoryIds []string `statekit:"name=advisory_ids"`
}

type parseTargetsFunc struct{}

func (parseTargetsFunc) Name() string { return "pkg_resource.parse_targets" }
func (parseTargetsFunc) Args() any    { return ParseTargetsArgs{} }

// nonePair mirrors Salt's `(None, None)` failure pair in serialized output.
func nonePair() []any { return []any{nil, nil} }

func (parseTargetsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ParseTargetsArgs)
	normalize := true
	if a.Normalize != nil {
		normalize = *a.Normalize
	}
	// saltenv only feeds cp.cache_file in Salt; the delegate is not yet
	// available, so the documented "base" default stays inert here.

	macOS := isMacOS(ctx, rt)
	if macOS && a.Sources != nil {
		// Salt logs 'Parameter "sources" ignored on MacOS hosts.' but keeps
		// the argument set, so the pkgs+sources conflict check below still
		// fires exactly like upstream.
	}

	if a.Pkgs != nil && a.Sources != nil {
		// Salt logs 'Only one of "pkgs" and "sources" can be used.'
		return nonePair(), nil
	}

	if a.AdvisoryIds != nil {
		if a.Pkgs != nil {
			// Salt logs 'Cannot use "advisory_ids" and "pkgs" at the same time'
			return nonePair(), nil
		}
		if len(a.AdvisoryIds) > 0 {
			ids := make([]any, 0, len(a.AdvisoryIds))
			for _, id := range a.AdvisoryIds {
				ids = append(ids, id)
			}
			return []any{ids, "advisory"}, nil
		}
		var name any
		if a.Name != "" {
			name = a.Name
		}
		return []any{[]any{name}, "advisory"}, nil
	}

	if a.Pkgs != nil {
		if a.Version != nil {
			// Salt logs that 'version' is ignored for multiple targets.
		}
		pkgs, err := repackPkgs(ctx, rt, a.Pkgs, normalize)
		if err != nil {
			return nil, err
		}
		if len(pkgs) == 0 {
			return nonePair(), nil
		}
		return []any{pkgs, "repository"}, nil
	}

	if a.Sources != nil && !macOS {
		if a.Version != nil {
			// Salt logs that 'version' is ignored for multiple targets.
		}
		packed := packSourcesImpl(ctx, rt, a.Sources, normalize)
		if len(packed) == 0 {
			return nonePair(), nil
		}
		srcinfo := []any{}
		for _, pair := range packed {
			pkgSrc, ok := pair.value.(string)
			if !ok {
				return nil, fmt.Errorf("Path %s for package %s is either not absolute or an invalid protocol",
					pythonScalar(pair.value), pair.name)
			}
			if validFileprotoRe.MatchString(pkgSrc) {
				// Remote sources need cp.cache_file; unavailable until the
				// cp family lands (salt:// stays permanently excluded).
				return nil, &runtime.UnsupportedError{Kind: "function", Name: "cp.cache_file"}
			}
			if !filepath.IsAbs(pkgSrc) {
				return nil, fmt.Errorf("Path %s for package %s is either not absolute or an invalid protocol",
					pkgSrc, pair.name)
			}
			srcinfo = append(srcinfo, pkgSrc)
		}
		return []any{srcinfo, "file"}, nil
	}

	if a.Name != "" {
		norm := normalizer(ctx, rt, normalize)
		packed := map[string]any{}
		for _, part := range strings.Split(a.Name, ",") {
			var version any
			if a.Version != nil {
				version = *a.Version
			}
			packed[norm(part)] = version
		}
		return []any{packed, "repository"}, nil
	}

	// Salt logs 'No package sources provided'.
	return nonePair(), nil
}
