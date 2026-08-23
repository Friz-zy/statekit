package pkgresource

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
	"github.com/friz-zy/statekit/modules/exec/pkg"
)

type VersionArgs struct {
	Names          []string `statekit:"name=names"`
	VersionsAsList bool     `statekit:"name=versions_as_list"`
}

type versionFunc struct{}

func (versionFunc) Name() string { return "pkg_resource.version" }
func (versionFunc) Args() any    { return VersionArgs{} }

// fnmatchRegexp compiles a Python fnmatch.translate-equivalent pattern
// (*, ?, [seq], [!seq]) into an anchored regexp.
func fnmatchRegexp(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString(`(?s)^`)
	i, n := 0, len(pattern)
	for i < n {
		c := pattern[i]
		i++
		switch c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		case '[':
			j := i
			if j < n && pattern[j] == '!' {
				j++
			}
			if j < n && pattern[j] == ']' {
				j++
			}
			for j < n && pattern[j] != ']' {
				j++
			}
			if j >= n {
				// Unterminated class stays literal like fnmatch.translate.
				b.WriteString(`\[`)
				continue
			}
			stuff := pattern[i:j]
			negate := ""
			if strings.HasPrefix(stuff, "!") {
				negate = "^"
				stuff = stuff[1:]
			}
			b.WriteString("[" + negate + stuff + "]")
			i = j + 1
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// listPkgVersions calls pkg.list_pkgs(versions_as_list=True) through the
// registry and normalizes the reply to name -> []string.
func listPkgVersions(ctx context.Context, rt *runtime.Runtime) (map[string][]string, error) {
	res, err := delegate(ctx, rt, "pkg.list_pkgs", &pkg.ListPkgsArgs{VersionsAsList: true})
	if err != nil {
		return nil, err
	}
	listed, err := toNameVersionMap(res)
	if err != nil {
		return nil, err
	}
	pkgs := make(map[string][]string, len(listed))
	for name, versions := range listed {
		switch t := versions.(type) {
		case []string:
			pkgs[name] = t
		case []any:
			out := make([]string, 0, len(t))
			for _, item := range t {
				out = append(out, plainScalar(item))
			}
			pkgs[name] = out
		case string:
			pkgs[name] = []string{t}
		default:
			pkgs[name] = []string{}
		}
	}
	return pkgs, nil
}

// toNameVersionMap accepts both the joined-string and the versions-as-list
// shapes pkg.list_pkgs returns.
func toNameVersionMap(res any) (map[string]any, error) {
	switch t := res.(type) {
	case map[string]any:
		return t, nil
	case map[string]string:
		out := make(map[string]any, len(t))
		for name, version := range t {
			out[name] = version
		}
		return out, nil
	default:
		return nil, fmt.Errorf("pkg.list_pkgs returned unexpected shape %T", res)
	}
}

func (versionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*VersionArgs)
	ret := map[string]any{}
	pkgGlob := false
	if len(a.Names) > 0 {
		pkgs, err := listPkgVersions(ctx, rt)
		if err != nil {
			return nil, err
		}
		for _, name := range a.Names {
			if strings.Contains(name, "*") {
				pkgGlob = true
				re, err := fnmatchRegexp(name)
				if err != nil {
					return nil, err
				}
				for match, versions := range pkgs {
					if re.MatchString(match) {
						ret[match] = toAnyStrings(versions)
					}
				}
			} else {
				ret[name] = toAnyStrings(pkgs[name])
			}
		}
	}
	if !a.VersionsAsList {
		stringifyInPlace(ret)
	}
	// Return a bare value when no globbing is used and one item remains.
	if len(ret) == 1 && !pkgGlob {
		for _, value := range ret {
			return value, nil
		}
	}
	return ret, nil
}

func toAnyStrings(items []string) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	return out
}

// versionCleanFunc consumes VersionCleanArgs declared in pkgresource.go.

type versionCleanFunc struct{}

func (versionCleanFunc) Name() string { return "pkg_resource.version_clean" }
func (versionCleanFunc) Args() any    { return VersionCleanArgs{} }
func (versionCleanFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*VersionCleanArgs)
	if a.VerStr != "" && lookup(rt, "pkg.version_clean") {
		return delegate(ctx, rt, "pkg.version_clean", &VersionCleanArgs{VerStr: a.VerStr})
	}
	return a.VerStr, nil
}

type VersionCompareArgs struct {
	Ver1        string `statekit:"name=ver1"`
	Oper        string `statekit:"name=oper"`
	Ver2        string `statekit:"name=ver2"`
	IgnoreEpoch bool   `statekit:"name=ignore_epoch"`
}

type versionCompareFunc struct{}

func (versionCompareFunc) Name() string { return "pkg_resource.version_compare" }
func (versionCompareFunc) Args() any    { return VersionCompareArgs{} }
func (versionCompareFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*VersionCompareArgs)
	// No platform version_cmp is registered, so salt.utils.versions.compare
	// always runs its LooseVersion fallback here.
	return compare(a.Ver1, a.Oper, a.Ver2, a.IgnoreEpoch), nil
}

// compare ports salt.utils.versions.compare: invalid operators and failed
// comparisons return False rather than raising.
func compare(ver1, oper, ver2 string, ignoreEpoch bool) bool {
	cmpMap := map[string][]int{"<": {-1}, "<=": {-1, 0}, "==": {0}, ">=": {0, 1}, ">": {1}}
	members, known := cmpMap[oper]
	if oper != "!=" && !known {
		return false
	}
	cmpResult, ok := versionCmp(ver1, ver2, ignoreEpoch)
	if !ok {
		return false
	}
	if oper == "!=" {
		return cmpResult != 0
	}
	if cmpResult < -1 {
		cmpResult = -1
	} else if cmpResult > 1 {
		cmpResult = 1
	}
	for _, m := range members {
		if cmpResult == m {
			return true
		}
	}
	return false
}

// versionCmp ports salt.utils.versions.version_cmp without a cmp_func:
// returns -1/0/1 and ok=false where Salt's broad except yields None.
func versionCmp(pkg1, pkg2 string, ignoreEpoch bool) (int, bool) {
	normalize := func(v string) string {
		if ignoreEpoch {
			if idx := strings.Index(v, ":"); idx >= 0 {
				return v[idx+1:]
			}
		}
		return v
	}
	return looseCompare(normalize(pkg1), normalize(pkg2))
}

// looseComponent is one distutils LooseVersion token: either an integer run
// or a literal string piece.
type looseComponent struct {
	isInt bool
	num   int64
	str   string
}

var looseSplitRe = regexp.MustCompile(`(\d+|[a-z]+|\.)`)

// parseLooseVersion tokenizes like distutils LooseVersion.parse: digit runs
// become integers, [a-z]+ runs and '.' become strings, and every unmatched
// chunk between matches stays as a literal string piece.
func parseLooseVersion(vstring string) ([]looseComponent, error) {
	indices := looseSplitRe.FindAllStringIndex(vstring, -1)
	var raw []string
	prev := 0
	for _, loc := range indices {
		if loc[0] > prev {
			raw = append(raw, vstring[prev:loc[0]])
		}
		raw = append(raw, vstring[loc[0]:loc[1]])
		prev = loc[1]
	}
	if prev < len(vstring) {
		raw = append(raw, vstring[prev:])
	}
	components := make([]looseComponent, 0, len(raw))
	for _, piece := range raw {
		if piece == "" {
			continue
		}
		if num, err := strconv.ParseInt(piece, 10, 64); err == nil && isDigits(piece) {
			components = append(components, looseComponent{isInt: true, num: num})
			continue
		}
		components = append(components, looseComponent{str: piece})
	}
	return components, nil
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// looseCompare mirrors Python's list comparison over LooseVersion tokens:
// element-wise with ints compared numerically and strings lexically; mixed
// element types fail the comparison the way Python's TypeError does for
// Salt's caller.
func looseCompare(v1, v2 string) (int, bool) {
	c1, err := parseLooseVersion(v1)
	if err != nil {
		return 0, false
	}
	c2, err := parseLooseVersion(v2)
	if err != nil {
		return 0, false
	}
	n := len(c1)
	if len(c2) > n {
		n = len(c2)
	}
	for i := 0; i < n; i++ {
		var a, b looseComponent
		switch {
		case i >= len(c1):
			// Shorter list sorts first when it is a prefix.
			return -1, true
		case i >= len(c2):
			return 1, true
		default:
			a, b = c1[i], c2[i]
		}
		switch {
		case a.isInt && b.isInt:
			if a.num != b.num {
				if a.num < b.num {
					return -1, true
				}
				return 1, true
			}
		case !a.isInt && !b.isInt:
			if a.str != b.str {
				if a.str < b.str {
					return -1, true
				}
				return 1, true
			}
		default:
			return 0, false
		}
	}
	return 0, true
}
