package pkgresource

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
	"github.com/friz-zy/statekit/modules/exec/pkg"
)

// fakeFunc stands in for optional __salt__-style delegates.
type fakeFunc struct {
	name     string
	template any
	run      func(args any) (any, error)
}

func (f *fakeFunc) Name() string { return f.name }
func (f *fakeFunc) Args() any    { return f.template }
func (f *fakeFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	return f.run(args)
}

func newRT(t *testing.T, fakes ...*fakeFunc) *runtime.Runtime {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
	}
	for _, fake := range fakes {
		if err := rt.Exec.Register(fake); err != nil {
			t.Fatal(err)
		}
	}
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return rt
}

// withMacOS pins the grains probe override for the test scope.
func withMacOS(t *testing.T, value bool) {
	t.Helper()
	saved := isMacOS
	isMacOS = func(context.Context, *runtime.Runtime) bool { return value }
	t.Cleanup(func() { isMacOS = saved })
}

// TestPackSources mirrors tests/pytests/unit/modules/test_pkg_resource.py::
// test_pack_sources plus the normalization hook contract.
func TestPackSources(t *testing.T) {
	rt := newRT(t, &fakeFunc{
		name:     "pkg.normalize_name",
		template: NormalizeNameArgs{},
		run: func(args any) (any, error) {
			return strings.ToUpper(args.(*NormalizeNameArgs).Name), nil
		},
	})

	pf := packSourcesFunc{}

	// Invalid input shapes collapse to the empty dict like Salt's logged
	// error path: unparseable YAML strings and non-dict list elements.
	got, err := pf.Execute(context.Background(), rt, &PackSourcesArgs{Sources: []any{"sources"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("pack_sources(sources) = %v, %v", got, err)
	}
	got, err = pf.Execute(context.Background(), rt, &PackSourcesArgs{Sources: []any{"A", "a"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("pack_sources([A,a]) = %v, %v", got, err)
	}

	// A proper one-element dict list packs; keys go through the optional
	// pkg.normalize_name delegate.
	got, err = pf.Execute(context.Background(), rt, &PackSourcesArgs{
		Sources: []any{map[string]any{"foo": "salt://foo.rpm"}, map[string]any{"bar": "salt://bar.rpm"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"FOO": "salt://foo.rpm", "BAR": "salt://bar.rpm"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packed = %v, want %v", got, want)
	}

	// normalize=False keeps raw names (Salt 2015.8.0 behavior switch).
	got, err = pf.Execute(context.Background(), rt, &PackSourcesArgs{
		Sources:   []any{map[string]any{"foo": "x"}},
		Normalize: boolPtr(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.(map[string]any)["foo"]; !ok {
		t.Fatalf("normalize=false must keep raw names: %v", got)
	}

	// Multi-key entries are invalid input.
	got, err = pf.Execute(context.Background(), rt, &PackSourcesArgs{
		Sources: []any{map[string]any{"a": "1", "b": "2"}},
	})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("multi-key entry = %v, %v", got, err)
	}
}

// TestRepackPkgs mirrors test_repack_pkgs: repacking works and duplicated
// names raise Salt's verbatim invocation error with a Python-style repr.
func TestRepackPkgs(t *testing.T) {
	rt := newRT(t)

	repacked, err := repackPkgs(context.Background(), rt, []any{map[string]any{"A": "a"}}, true)
	if err != nil || !reflect.DeepEqual(repacked, map[string]any{"A": "a"}) {
		t.Fatalf("repack single = %v, %v", repacked, err)
	}

	repacked, err = repackPkgs(context.Background(), rt,
		[]any{map[string]any{"A": "a"}, map[string]any{"B": "b"}}, true)
	if err != nil || len(repacked) != 2 {
		t.Fatalf("repack pair = %v, %v", repacked, err)
	}

	_, err = repackPkgs(context.Background(), rt,
		[]any{map[string]any{"A": "a"}, map[string]any{"A": "c"}}, true)
	wantMsg := "You are passing a list of packages that contains duplicated packages names: " +
		"[{'A': 'a'}, {'A': 'c'}]. This cannot be processed. In case you are targeting different " +
		"versions of the same package, please target them individually"
	if err == nil || err.Error() != wantMsg {
		t.Fatalf("collision error = %v", err)
	}

	// Scalar entries become keys with None values; numeric versions are
	// stringified like str() would.
	repacked, err = repackPkgs(context.Background(), rt, []any{"curl", map[string]any{"vim": 5}}, true)
	if err != nil {
		t.Fatal(err)
	}
	wantScalar := map[string]any{"curl": nil, "vim": "5"}
	if !reflect.DeepEqual(repacked, wantScalar) {
		t.Fatalf("scalar/int repack = %v, want %v", repacked, wantScalar)
	}
}

// TestParseTargetsRepository mirrors repository-branch behavior including
// the advisory_ids branch that precedes it in Salt.
func TestParseTargets(t *testing.T) {
	rt := newRT(t)
	pt := parseTargetsFunc{}

	// pkgs+sources conflict.
	got, err := pt.Execute(context.Background(), rt, &ParseTargetsArgs{
		Pkgs: []any{map[string]any{"a": "1"}}, Sources: []any{map[string]any{"s": "/x"}},
	})
	if err != nil || !reflect.DeepEqual(got, nonePair()) {
		t.Fatalf("pkgs+sources = %v, %v", got, err)
	}

	// pkgs branch repacks into a repository target.
	got, err = pt.Execute(context.Background(), rt, &ParseTargetsArgs{
		Pkgs: []any{map[string]any{"A": "a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []any{map[string]any{"A": "a"}, "repository"}) {
		t.Fatalf("pkgs branch = %v", got)
	}

	// Empty repack result yields the None pair (invalid element collapses).
	got, err = pt.Execute(context.Background(), rt, &ParseTargetsArgs{
		Pkgs: []any{[]any{"nested"}},
	})
	if err == nil {
		t.Fatalf("invalid element must surface the collision error, got %v", got)
	}

	// advisory_ids wins over everything but the conflict above.
	got, err = pt.Execute(context.Background(), rt, &ParseTargetsArgs{
		AdvisoryIds: []string{"ALSA-2023:0001"},
	})
	if err != nil || !reflect.DeepEqual(got, []any{[]any{"ALSA-2023:0001"}, "advisory"}) {
		t.Fatalf("advisory = %v, %v", got, err)
	}
	got, err = pt.Execute(context.Background(), rt, &ParseTargetsArgs{
		AdvisoryIds: []string{}, Name: "openssl",
	})
	if err != nil || !reflect.DeepEqual(got, []any{[]any{"openssl"}, "advisory"}) {
		t.Fatalf("empty advisory + name = %v, %v", got, err)
	}
	got, err = pt.Execute(context.Background(), rt, &ParseTargetsArgs{
		Pkgs: []any{map[string]any{"a": "1"}}, AdvisoryIds: []string{"X"},
	})
	if err != nil || !reflect.DeepEqual(got, nonePair()) {
		t.Fatalf("advisory+pkgs = %v, %v", got, err)
	}

	// name branch splits on commas and attaches the version kwarg.
	got, err = pt.Execute(context.Background(), rt, &ParseTargetsArgs{Name: "curl,vim"})
	if err != nil || !reflect.DeepEqual(got, []any{map[string]any{"curl": nil, "vim": nil}, "repository"}) {
		t.Fatalf("name branch = %v, %v", got, err)
	}
	version := "8.14.1"
	got, err = pt.Execute(context.Background(), rt, &ParseTargetsArgs{Name: "curl", Version: &version})
	if err != nil || !reflect.DeepEqual(got, []any{map[string]any{"curl": version}, "repository"}) {
		t.Fatalf("name+version = %v, %v", got, err)
	}

	// Nothing provided.
	got, err = pt.Execute(context.Background(), rt, &ParseTargetsArgs{})
	if err != nil || !reflect.DeepEqual(got, nonePair()) {
		t.Fatalf("empty = %v, %v", got, err)
	}
}

// TestParseTargetsFileBranches pins local absolute paths, the relative-path
// invocation error, and the cp.cache_file unsupported error for remote
// sources.
func TestParseTargetsFileBranches(t *testing.T) {
	rt := newRT(t)
	pt := parseTargetsFunc{}

	got, err := pt.Execute(context.Background(), rt, &ParseTargetsArgs{
		Sources: []any{map[string]any{"foo": "/tmp/foo.rpm"}},
	})
	if err != nil || !reflect.DeepEqual(got, []any{[]any{"/tmp/foo.rpm"}, "file"}) {
		t.Fatalf("local file source = %v, %v", got, err)
	}

	_, err = pt.Execute(context.Background(), rt, &ParseTargetsArgs{
		Sources: []any{map[string]any{"foo": "foo.rpm"}},
	})
	wantMsg := "Path foo.rpm for package foo is either not absolute or an invalid protocol"
	if err == nil || err.Error() != wantMsg {
		t.Fatalf("relative path error = %v", err)
	}

	_, err = pt.Execute(context.Background(), rt, &ParseTargetsArgs{
		Sources: []any{map[string]any{"foo": "https://example.com/foo.rpm"}},
	})
	unsupported := &runtime.UnsupportedError{}
	if !errors.As(err, &unsupported) || unsupported.Name != "cp.cache_file" {
		t.Fatalf("remote source error = %v", err)
	}
}

// TestParseTargetsMacOSIgnoresSources mirrors the grains.os == MacOS guard:
// sources are skipped on processing but still trigger the conflict check.
func TestParseTargetsMacOSIgnoresSources(t *testing.T) {
	withMacOS(t, true)
	rt := newRT(t)
	pt := parseTargetsFunc{}

	// sources alone fall through to the no-targets pair.
	got, err := pt.Execute(context.Background(), rt, &ParseTargetsArgs{
		Sources: []any{map[string]any{"foo": "/tmp/foo.rpm"}},
	})
	if err != nil || !reflect.DeepEqual(got, nonePair()) {
		t.Fatalf("macos sources = %v, %v", got, err)
	}

	// sources+name: sources ignored, name branch still runs.
	got, err = pt.Execute(context.Background(), rt, &ParseTargetsArgs{
		Sources: []any{map[string]any{"foo": "/tmp/foo.rpm"}}, Name: "n",
	})
	if err != nil || !reflect.DeepEqual(got, []any{map[string]any{"n": nil}, "repository"}) {
		t.Fatalf("macos sources+name = %v, %v", got, err)
	}

	// sources+pkgs still conflicts before any macOS skipping matters.
	got, err = pt.Execute(context.Background(), rt, &ParseTargetsArgs{
		Sources: []any{map[string]any{"foo": "/tmp/f"}}, Pkgs: []any{map[string]any{"p": "1"}},
	})
	if err != nil || !reflect.DeepEqual(got, nonePair()) {
		t.Fatalf("macos sources+pkgs = %v, %v", got, err)
	}
}

// TestVersion mirrors test_version: single non-glob names return the bare
// value, empty queries return {}, and missing packages stringify to "".
func TestVersion(t *testing.T) {
	var seenArgs any
	listFake := &fakeFunc{
		name:     "pkg.list_pkgs",
		template: &pkg.ListPkgsArgs{},
		run: func(args any) (any, error) {
			seenArgs = args
			return map[string]any{"A": []string{"B"}}, nil
		},
	}
	rt := newRT(t, listFake)
	vf := versionFunc{}

	got, err := vf.Execute(context.Background(), rt, &VersionArgs{Names: []string{"A"}})
	if err != nil || got != "B" {
		t.Fatalf("version(A) = %#v, %v", got, err)
	}
	listArgs, ok := seenArgs.(*pkg.ListPkgsArgs)
	if !ok || !listArgs.VersionsAsList {
		t.Fatalf("list_pkgs must be called with versions_as_list=true, got %#v", seenArgs)
	}

	got, err = vf.Execute(context.Background(), rt, &VersionArgs{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("version() = %#v, %v", got, err)
	}

	emptyFake := &fakeFunc{
		name:     "pkg.list_pkgs",
		template: &pkg.ListPkgsArgs{},
		run:      func(any) (any, error) { return map[string]any{}, nil },
	}
	rt2 := newRT(t, emptyFake)
	got, err = vf.Execute(context.Background(), rt2, &VersionArgs{Names: []string{"A"}})
	if err != nil || got != "" {
		t.Fatalf("version(missing) = %#v, %v", got, err)
	}

	// versions_as_list skips stringify and returns lists.
	got, err = vf.Execute(context.Background(), rt, &VersionArgs{
		Names: []string{"A"}, VersionsAsList: true,
	})
	if err != nil || !reflect.DeepEqual(got, []any{"B"}) {
		t.Fatalf("versions_as_list = %#v, %v", got, err)
	}
}

// TestVersionGlob pins fnmatch semantics: globbed queries keep the dict
// shape even for a single match.
func TestVersionGlob(t *testing.T) {
	listFake := &fakeFunc{
		name:     "pkg.list_pkgs",
		template: &pkg.ListPkgsArgs{},
		run: func(any) (any, error) {
			return map[string]any{
				"python":  []string{"2.7"},
				"python3": []string{"3.12"},
				"vim":     []string{"9.0"},
			}, nil
		},
	}
	rt := newRT(t, listFake)

	gotRaw, err := (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{Names: []string{"python*"}})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := gotRaw.(map[string]any)
	if !ok {
		t.Fatalf("glob result shape = %#v", gotRaw)
	}
	want := map[string]any{"python": "2.7", "python3": "3.12"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("glob = %v, want %v", got, want)
	}
}

// TestVersionWithoutListPkgs pins the failure when the pkg module is absent.
func TestVersionWithoutListPkgs(t *testing.T) {
	rt := &runtime.Runtime{Exec: runtime.NewExecRegistry()}
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	_, err := (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{Names: []string{"A"}})
	if err == nil || !strings.Contains(err.Error(), "unsupported function") {
		t.Fatalf("missing list_pkgs error = %v", err)
	}
}

// TestAddPkg mirrors test_add_pkg plus append/create/no-op-on-scalar edges.
func TestAddPkg(t *testing.T) {
	rt := newRT(t)
	af := addPkgFunc{}

	pkgs := map[string]any{}
	got, err := af.Execute(context.Background(), rt, &AddPkgArgs{Pkgs: pkgs, Name: "bind", PkgVer: "9"})
	if err != nil || got != nil {
		t.Fatalf("add_pkg ret = %#v, %v", got, err)
	}
	if !reflect.DeepEqual(pkgs, map[string]any{"bind": []any{"9"}}) {
		t.Fatalf("pkgs = %v", pkgs)
	}

	pkgs = map[string]any{"bind": []any{"9"}}
	if _, err := af.Execute(context.Background(), rt, &AddPkgArgs{Pkgs: pkgs, Name: "bind", PkgVer: "9.10"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pkgs["bind"], []any{"9", "9.10"}) {
		t.Fatalf("append = %v", pkgs["bind"])
	}

	// A scalar existing value trips Salt's swallowed AttributeError: the
	// dict stays unchanged and the function succeeds.
	pkgs = map[string]any{"bind": "9"}
	if _, err := af.Execute(context.Background(), rt, &AddPkgArgs{Pkgs: pkgs, Name: "bind", PkgVer: "9.10"}); err != nil {
		t.Fatal(err)
	}
	if pkgs["bind"] != "9" {
		t.Fatalf("scalar value must stay untouched: %v", pkgs["bind"])
	}
}

// TestSortPkglist mirrors test_sort_pkglist plus dedupe/sort semantics.
func TestSortPkglist(t *testing.T) {
	rt := newRT(t)
	sf := sortPkglistFunc{}

	if _, err := sf.Execute(context.Background(), rt, &SortPkglistArgs{Pkgs: map[string]any{}}); err != nil {
		t.Fatal(err)
	}

	pkgs := map[string]any{
		"kernel": []any{"4.10", "3.45", "2.13", "4.10", "3.45"},
	}
	if _, err := sf.Execute(context.Background(), rt, &SortPkglistArgs{Pkgs: pkgs}); err != nil {
		t.Fatal(err)
	}
	want := []any{"2.13", "3.45", "4.10"}
	if !reflect.DeepEqual(pkgs["kernel"], want) {
		t.Fatalf("sorted = %v, want %v", pkgs["kernel"], want)
	}

	// Intentional divergence pinned: scalar values error instead of
	// Python's silent character decomposition.
	pkgs = map[string]any{"kernel": "4.10"}
	if _, err := sf.Execute(context.Background(), rt, &SortPkglistArgs{Pkgs: pkgs}); err == nil {
		t.Fatalf("scalar value must fail")
	}
}

// TestStringify mirrors test_stringify plus join semantics.
func TestStringify(t *testing.T) {
	rt := newRT(t)
	sf := stringifyFunc{}

	ret := map[string]any{}
	got, err := sf.Execute(context.Background(), rt, &StringifyArgs{Pkgs: ret})
	if err != nil || got != nil {
		t.Fatalf("stringify({}) = %#v, %v", got, err)
	}

	ret = map[string]any{
		"foobar": []any{"2:1.2.0-7", "2:1.2.3-27"},
		"single": []any{"1.0"},
	}
	if _, err := sf.Execute(context.Background(), rt, &StringifyArgs{Pkgs: ret}); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"foobar": "2:1.2.0-7,2:1.2.3-27", "single": "1.0"}
	if !reflect.DeepEqual(ret, want) {
		t.Fatalf("stringified = %v, want %v", ret, want)
	}
}

// TestVersionClean mirrors test_version_clean delegation both ways.
func TestVersionClean(t *testing.T) {
	cleanFake := &fakeFunc{
		name:     "pkg.version_clean",
		template: VersionCleanArgs{},
		run:      func(any) (any, error) { return "A", nil },
	}
	rt := newRT(t, cleanFake)
	vcf := versionCleanFunc{}

	got, err := vcf.Execute(context.Background(), rt, &VersionCleanArgs{VerStr: "version"})
	if err != nil || got != "A" {
		t.Fatalf("delegated clean = %#v, %v", got, err)
	}

	// Without the delegate registered the string passes through untouched.
	rt2 := newRT(t)
	got, err = vcf.Execute(context.Background(), rt2, &VersionCleanArgs{VerStr: "v"})
	if err != nil || got != "v" {
		t.Fatalf("passthrough clean = %#v, %v", got, err)
	}
}

// TestCheckExtraRequirements mirrors test_check_extra_requirements.
func TestCheckExtraRequirements(t *testing.T) {
	reqFake := &fakeFunc{
		name:     "pkg.check_extra_requirements",
		template: CheckExtraRequirementsArgs{},
		run:      func(any) (any, error) { return "A", nil },
	}
	rt := newRT(t, reqFake)
	cef := checkExtraRequirementsFunc{}

	got, err := cef.Execute(context.Background(), rt, &CheckExtraRequirementsArgs{PkgName: "a", PkgVer: "b"})
	if err != nil || got != "A" {
		t.Fatalf("delegated check = %#v, %v", got, err)
	}

	rt2 := newRT(t)
	got, err = cef.Execute(context.Background(), rt2, &CheckExtraRequirementsArgs{PkgName: "a", PkgVer: ""})
	if err != nil || got != true {
		t.Fatalf("default check = %#v, %v", got, err)
	}
}

var formatPackages = map[string]any{
	"glibc": []any{
		map[string]any{"version": "2.12", "epoch": nil, "release": "1.212.el6", "arch": "x86_64"},
	},
	"glibc.i686": []any{
		map[string]any{"version": "2.12", "epoch": nil, "release": "1.212.el6", "arch": "i686"},
	},
	"foobar": []any{
		map[string]any{"version": "1.2.0", "epoch": "2", "release": "7", "arch": "x86_64"},
		map[string]any{"version": "1.2.3", "epoch": "2", "release": "27", "arch": "x86_64"},
	},
	"foobar.something": []any{
		map[string]any{"version": "1.1", "epoch": "3", "release": "23.1", "arch": "i686"},
	},
	"foobar.": []any{
		map[string]any{"version": "1.1", "epoch": "3", "release": "23.1", "arch": "i686"},
	},
}

// TestFormatPkgListNoAttr mirrors test_format_pkg_list_no_attr exactly.
func TestFormatPkgListNoAttr(t *testing.T) {
	rt := newRT(t)
	ff := formatPkgListFunc{}

	gotRaw, err := ff.Execute(context.Background(), rt, &FormatPkgListArgs{Packages: formatPackages})
	if err != nil {
		t.Fatal(err)
	}
	got := gotRaw.(map[string]any)
	want := map[string]any{
		"glibc":            "2.12-1.212.el6",
		"glibc.i686":       "2.12-1.212.el6",
		"foobar":           "2:1.2.0-7,2:1.2.3-27",
		"foobar.something": "3:1.1-23.1",
		"foobar.":          "3:1.1-23.1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("format = %v, want %v", got, want)
	}
}

// TestFormatPkgListNoAttrAsList pins the versions_as_list escape hatch.
func TestFormatPkgListNoAttrAsList(t *testing.T) {
	rt := newRT(t)
	gotRaw, err := (formatPkgListFunc{}).Execute(context.Background(), rt, &FormatPkgListArgs{
		Packages:       map[string]any{"glibc": formatPackages["glibc"]},
		VersionsAsList: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"glibc": []any{"2.12-1.212.el6"}}
	if !reflect.DeepEqual(gotRaw, want) {
		t.Fatalf("as-list format = %v, want %v", gotRaw, want)
	}
}

// TestFormatPkgListWithAttr mirrors test_format_pkg_list_with_attr: arch
// suffixes fold into the bare package name when the entry arch matches.
func TestFormatPkgListWithAttr(t *testing.T) {
	nameArchMapping := map[string]any{
		"glibc":            map[string]any{"name": "glibc", "arch": nil},
		"glibc.i686":       map[string]any{"name": "glibc", "arch": "i686"},
		"foobar":           map[string]any{"name": "foobar", "arch": nil},
		"foobar.something": map[string]any{"name": "foobar.something", "arch": nil},
		"foobar.":          map[string]any{"name": "foobar.", "arch": nil},
	}
	parseArchFake := &fakeFunc{
		name:     "pkg.parse_arch",
		template: ParseArchArgs{},
		run: func(args any) (any, error) {
			return nameArchMapping[args.(*ParseArchArgs).Name], nil
		},
	}
	rt := newRT(t, parseArchFake)

	gotRaw, err := (formatPkgListFunc{}).Execute(context.Background(), rt, &FormatPkgListArgs{
		Packages: formatPackages,
		Attr:     []string{"epoch", "release"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := gotRaw.(map[string]any)

	wantKeys := []string{"glibc", "foobar", "foobar.", "foobar.something"}
	if len(got) != len(wantKeys) {
		t.Fatalf("attr keys = %v, want %v", keysOf(got), wantKeys)
	}

	// glibc.i686 folds under glibc, so glibc carries both entries.
	glibcEntries := len(got["glibc"].([]any))
	if glibcEntries != 2 {
		t.Fatalf("merged glibc entries = %d (%v)", glibcEntries, got["glibc"])
	}

	// Every filtered entry keeps only requested+always keys.
	for name, entriesRaw := range got {
		for _, entryAny := range entriesRaw.([]any) {
			entry := entryAny.(map[string]any)
			for key := range entry {
				switch key {
				case "epoch", "release", "version", "arch":
				default:
					t.Fatalf("%s entry has unexpected key %q: %v", name, key, entry)
				}
			}
			if entry["epoch"] == nil && name != "glibc" {
				t.Fatalf("%s lost its epoch through filtering: %v", name, entry)
			}
		}
	}
}

// TestFormatPkgListAttrAll pins attr=all keeping the full attribute set.
func TestFormatPkgListAttrAll(t *testing.T) {
	rt := newRT(t)
	gotRaw, err := (formatPkgListFunc{}).Execute(context.Background(), rt, &FormatPkgListArgs{
		Packages: map[string]any{"glibc": []any{
			map[string]any{"version": "2.12", "epoch": "", "release": "1", "arch": "x86_64",
				"install_date": "2023-01-01", "install_date_time_t": 1672531200},
		}},
		Attr: []string{"all"},
	})
	if err != nil {
		t.Fatal(err)
	}
	entry := gotRaw.(map[string]any)["glibc"].([]any)[0].(map[string]any)
	for _, key := range attrKeys {
		if _, ok := entry[key]; !ok {
			t.Fatalf("attr=all dropped %q: %v", key, entry)
		}
	}
}

// TestFormatVersion pins epoch/release formatting rules.
func TestFormatVersion(t *testing.T) {
	cases := []struct {
		epoch, version, release, want string
	}{
		{"", "1.2", "", "1.2"},
		{"2", "1.2.0", "7", "2:1.2.0-7"},
		{"", "1.2", "7", "1.2-7"},
		{"2", "1.2.0", "", "2:1.2.0"},
	}
	rt := newRT(t)
	for _, c := range cases {
		got, err := (formatVersionFunc{}).Execute(context.Background(), rt, &FormatVersionArgs{
			Epoch: c.epoch, Version: c.version, Release: c.release,
		})
		if err != nil || got != c.want {
			t.Fatalf("format_version(%q,%q,%q) = %#v, %v; want %q", c.epoch, c.version, c.release, got, err, c.want)
		}
	}
}

// TestVersionCompare mirrors test_version_compare and extends it across the
// operator matrix, epoch stripping, and LooseVersion tokenization.
func TestVersionCompare(t *testing.T) {
	rt := newRT(t)
	vcf := versionCompareFunc{}
	exec := func(ver1, oper, ver2 string, ignoreEpoch ...bool) bool {
		a := &VersionCompareArgs{Ver1: ver1, Oper: oper, Ver2: ver2}
		if len(ignoreEpoch) > 0 {
			a.IgnoreEpoch = ignoreEpoch[0]
		}
		got, err := vcf.Execute(context.Background(), rt, a)
		if err != nil {
			t.Fatal(err)
		}
		return got.(bool)
	}

	if !exec("2.0", "<", "3.0") {
		t.Fatal("2.0 < 3.0")
	}
	if exec("3.0", "<", "2.0") || exec("3.0", "==", "2.0") {
		t.Fatal("basic matrix")
	}
	if exec("2.0", "<>", "3.0") {
		t.Fatal("invalid operator must return false, not error")
	}
	if !exec("1:3.0", "==", "3.0", true) {
		t.Fatal("ignore_epoch strips prefixes")
	}
	if exec("1:3.0", "==", "3.0", false) {
		t.Fatal("epochs participate without ignore_epoch")
	}
	if !exec("3005", ">=", "3005") {
		t.Fatal(">= boundary")
	}
	if !exec("1.0rc1", ">", "1.0") {
		t.Fatal("letter tokens extend versions")
	}
	if !exec("1.0", "!=", "1.1") {
		t.Fatal("!= positive")
	}
	if exec("abc", "<", "1.0") {
		t.Fatal("mixed int/string tokens must return false")
	}
	if !exec("8.14.1", "==", "8.14.1") {
		t.Fatal("equality")
	}
}

// TestRegisterNames pins the CLI-facing registration surface: eleven public
// functions; _repack_pkgs intentionally has no registration because Salt's
// loader hides underscore-prefixed functions.
func TestRegisterNames(t *testing.T) {
	rt := newRT(t)
	names := map[string]bool{}
	for _, name := range rt.Exec.Names() {
		names[name] = true
	}
	for _, want := range []string{
		"pkg_resource.pack_sources",
		"pkg_resource.parse_targets",
		"pkg_resource.version",
		"pkg_resource.add_pkg",
		"pkg_resource.sort_pkglist",
		"pkg_resource.stringify",
		"pkg_resource.version_clean",
		"pkg_resource.version_compare",
		"pkg_resource.check_extra_requirements",
		"pkg_resource.format_pkg_list",
		"pkg_resource.format_version",
	} {
		if !names[want] {
			t.Errorf("missing registration %s", want)
		}
	}
	if names["pkg_resource._repack_pkgs"] {
		t.Error("_repack_pkgs must stay private")
	}
}

func boolPtr(b bool) *bool { return &b }

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
