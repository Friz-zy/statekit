package pkg

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

var errZypperRepoPkgsInvalidXML = errors.New("zypper: invalid repository packages XML")

// zypperRepoPkgsSet preserves first-seen insertion order while reproducing the
// pinned source's per-package version set semantics.
type zypperRepoPkgsSet struct {
	order    []string
	seen     map[string]struct{}
	versions map[string][]string
	seenVer  map[string]map[string]struct{}
}

func newZypperRepoPkgsSet() *zypperRepoPkgsSet {
	return &zypperRepoPkgsSet{
		seen:     map[string]struct{}{},
		versions: map[string][]string{},
		seenVer:  map[string]map[string]struct{}{},
	}
}

func (s *zypperRepoPkgsSet) packageNames() []string { return s.order }

func (s *zypperRepoPkgsSet) add(pkgname, version string) {
	if _, exists := s.seenVer[pkgname]; !exists {
		s.seenVer[pkgname] = map[string]struct{}{}
	}
	if _, duplicate := s.seenVer[pkgname][version]; duplicate {
		return
	}
	s.seenVer[pkgname][version] = struct{}{}
	if _, exists := s.seen[pkgname]; !exists {
		s.seen[pkgname] = struct{}{}
		s.order = append(s.order, pkgname)
	}
	s.versions[pkgname] = append(s.versions[pkgname], version)
}

func (s *zypperRepoPkgsSet) sortedVersions(pkgname string) []string {
	versions := append([]string(nil), s.versions[pkgname]...)
	// Python sorted(..., reverse=True) is stable, so equal LooseVersions keep
	// their source order while the sequence itself runs newest to oldest.
	sort.SliceStable(versions, func(i, j int) bool {
		return yumLooseVersionCmp(versions[i], versions[j]) > 0
	})
	return versions
}

// validateZypperRepoPkgsArgs mirrors list_repo_pkgs(*args, byrepo=False,
// fromrepo="", root=None). Repository names may contain spaces, so fromrepo
// keeps path-shaped validation instead of the package token grammar.
func validateZypperRepoPkgsArgs(args map[string]any) error {
	for key := range args {
		if key != "pkgs" && key != "byrepo" && key != "fromrepo" && key != "root" {
			return zypperUnsupportedArgument(key)
		}
	}
	if _, err := zypperPackageList(args, "pkgs"); err != nil {
		return err
	}
	if _, err := zypperBool(args, "byrepo"); err != nil {
		return err
	}
	if value, exists := args["fromrepo"]; exists && value != nil {
		var fromrepo string
		switch typed := value.(type) {
		case string:
			fromrepo = typed
		case *string:
			if typed == nil {
				fromrepo = ""
				break
			}
			fromrepo = *typed
		default:
			return errors.New(`argument "fromrepo" must be a string`)
		}
		if fromrepo != "" {
			if err := validateZypperPath(fromrepo, false); err != nil {
				return zypperUnsupportedArgument("fromrepo")
			}
		}
	}
	if _, err := zypperLowpkgRoot(args); err != nil {
		return err
	}
	return nil
}

// zypperListRepoPkgs ports list_repo_pkgs. The XML `se -s <targets>` search
// contributes kind=="package" solvables only; missing repository, name, or
// edition attributes skip the record exactly like the pinned KeyError
// handling, and fromrepo keeps only the exact repository-name match.
func zypperListRepoPkgs(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	targets, err := zypperPackageList(args, "pkgs")
	if err != nil {
		return nil, err
	}
	root, err := zypperLowpkgRoot(args)
	if err != nil {
		return nil, err
	}
	byrepo := boolDefault(args, "byrepo", false)
	fromrepo := ""
	if value, exists := args["fromrepo"]; exists && value != nil {
		switch typed := value.(type) {
		case string:
			fromrepo = typed
		case *string:
			if typed != nil {
				fromrepo = *typed
			}
		}
	}

	query := append([]string{"se", "-s"}, targets...)
	output, err := zypperQueryRun(ctx, rt, root, true, false, query)
	if err != nil {
		return nil, err
	}
	repos, err := zypperParseRepoPkgs(ctx, output, targets, fromrepo)
	if err != nil {
		return nil, err
	}

	if byrepo {
		ret := make(map[string]any, len(repos))
		for _, repo := range repos {
			packages := make(map[string]any, len(repo.packages.order))
			for _, pkgname := range repo.packages.packageNames() {
				packages[pkgname] = repo.packages.sortedVersions(pkgname)
			}
			ret[repo.name] = packages
		}
		return ret, nil
	}
	flattened := newZypperRepoPkgsSet()
	for _, repo := range repos {
		for _, pkgname := range repo.packages.packageNames() {
			for _, version := range repo.packages.versions[pkgname] {
				flattened.add(pkgname, version)
			}
		}
	}
	ret := make(map[string]any, len(flattened.order))
	for _, pkgname := range flattened.packageNames() {
		ret[pkgname] = flattened.sortedVersions(pkgname)
	}
	return ret, nil
}

type zypperRepoPkgsRepo struct {
	name     string
	packages *zypperRepoPkgsSet
}

// zypperParseRepoPkgs streams the solvable list with the same RawToken
// conventions as the patterns parser: only unprefixed solvable elements
// match, attribute presence reproduces the pinned dict-key KeyError skips,
// and fnmatch semantics come from the shared yum port of Python fnmatch.
func zypperParseRepoPkgs(ctx context.Context, output string, targets []string, fromrepo string) ([]zypperRepoPkgsRepo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(output) > zypperLowpkgOutputLimit {
		return nil, process.ErrOutputLimit
	}

	decoder := xml.NewDecoder(strings.NewReader(output))
	stack := make([]xml.Name, 0, 4)
	roots, elements, attributes, solvables := 0, 0, 0, 0
	repoIndex := map[string]*zypperRepoPkgsSet{}
	repos := make([]zypperRepoPkgsRepo, 0)

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		token, err := decoder.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errZypperRepoPkgsInvalidXML
		}

		switch node := token.(type) {
		case xml.StartElement:
			if len(stack) == 0 {
				roots++
				if roots > 1 {
					return nil, errZypperRepoPkgsInvalidXML
				}
			}
			if len(stack)+1 > zypperSearchMaxXMLDepth {
				return nil, process.ErrOutputLimit
			}
			elements++
			if elements > zypperLowpkgMaxItems {
				return nil, process.ErrOutputLimit
			}
			attributeBytes := 0
			if len(node.Attr) > zypperPatternsMaxAttributesPerElement {
				return nil, process.ErrOutputLimit
			}
			for _, attr := range node.Attr {
				attributes++
				if attributes > zypperLowpkgMaxItems {
					return nil, process.ErrOutputLimit
				}
				attrBytes := len(attr.Name.Space) + len(attr.Name.Local) + len(attr.Value)
				if attrBytes > zypperPatternsMaxAttributeBytes || attributeBytes > zypperPatternsMaxAttributeBytes-attrBytes {
					return nil, process.ErrOutputLimit
				}
				attributeBytes += attrBytes
			}

			if node.Name.Space == "" && node.Name.Local == "solvable" {
				solvables++
				if solvables > zypperLowpkgMaxItems {
					return nil, process.ErrOutputLimit
				}
				if record, ok := zypperRepoPkgsSolvable(node.Attr, targets, fromrepo); ok {
					packages, exists := repoIndex[record.reponame]
					if !exists {
						packages = newZypperRepoPkgsSet()
						repoIndex[record.reponame] = packages
						if len(repoIndex) > zypperLowpkgMaxItems {
							return nil, process.ErrOutputLimit
						}
						repos = append(repos, zypperRepoPkgsRepo{name: record.reponame, packages: packages})
					}
					packages.add(record.pkgname, record.version)
				}
			}
			stack = append(stack, node.Name)

		case xml.CharData:
			if len(stack) == 0 && strings.TrimSpace(string(node)) != "" {
				return nil, errZypperRepoPkgsInvalidXML
			}

		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != node.Name {
				return nil, errZypperRepoPkgsInvalidXML
			}
			stack = stack[:len(stack)-1]
		}
	}

	if roots != 1 || len(stack) != 0 {
		return nil, errZypperRepoPkgsInvalidXML
	}
	return repos, nil
}

// zypperRepoPkgsSolvable applies the pinned per-solvable filters. Attribute
// presence reproduces the source's dict-key KeyError skips: a solvable
// without kind, or kind != "package", or without repository/name/edition is
// skipped rather than recorded.
func zypperRepoPkgsSolvable(attrs []xml.Attr, targets []string, fromrepo string) (zypperRepoPkgsRecord, bool) {
	present := make(map[string]string, len(attrs))
	for _, attr := range attrs {
		if attr.Name.Space != "" {
			continue
		}
		present[attr.Name.Local] = attr.Value
	}
	record := zypperRepoPkgsRecord{
		reponame: present["repository"],
		pkgname:  present["name"],
		version:  present["edition"],
	}
	kind, kindPresent := present["kind"]
	_, repoPresent := present["repository"]
	_, namePresent := present["name"]
	_, editionPresent := present["edition"]
	if !kindPresent || kind != "package" {
		return record, false
	}
	if !repoPresent || !namePresent || !editionPresent {
		return record, false
	}
	if fromrepo != "" && record.reponame != fromrepo {
		return record, false
	}
	if !zypperRepoPkgsMatch(record.pkgname, targets) {
		return record, false
	}
	return record, true
}

type zypperRepoPkgsRecord struct {
	reponame string
	pkgname  string
	version  string
}

// zypperRepoPkgsMatch ports _is_match: without targets every package name
// matches; otherwise any fnmatch against a target accepts the name.
func zypperRepoPkgsMatch(pkgname string, targets []string) bool {
	if len(targets) == 0 {
		return true
	}
	for _, target := range targets {
		if yumFnmatch(target, pkgname) {
			return true
		}
	}
	return false
}
