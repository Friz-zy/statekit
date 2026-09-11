package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ReferenceInfo pins the scanned Salt revision.
type ReferenceInfo struct {
	Repository string `yaml:"repository"`
	Commit     string `yaml:"commit"`
	Version    string `yaml:"version"`
}

// FamilyCoverage summarizes one catalog family against StateKit.
type FamilyCoverage struct {
	SaltModules       int `yaml:"salt_modules"`
	SaltFunctions     int `yaml:"salt_functions"`
	RelevantFunctions int `yaml:"relevant_functions"`
	// SourceInventoryCount labels the raw Go Name() inventory; it is not a
	// catalog coverage count.
	SourceInventoryCount int `yaml:"source_inventory_count"`
	// CatalogIntersectionCount labels the implemented catalog intersection.
	CatalogIntersectionCount int `yaml:"catalog_intersection_count"`
	Implemented              int `yaml:"implemented"`
}

// Implemented lists StateKit functions detected in Go sources.
type Implemented struct {
	Exec  []string `yaml:"exec"`
	State []string `yaml:"state"`
}

// Coverage is the generated migration coverage report (plan section 30).
type Coverage struct {
	Reference   ReferenceInfo  `yaml:"reference"`
	Execution   FamilyCoverage `yaml:"execution"`
	State       FamilyCoverage `yaml:"state"`
	Implemented Implemented    `yaml:"implemented"`
}

// Index summarizes the generated catalog.
type Index struct {
	Reference ReferenceInfo      `yaml:"reference"`
	Execution FamilyModuleCounts `yaml:"execution"`
	State     FamilyModuleCounts `yaml:"state"`
	Modules   ModuleLists        `yaml:"modules"`
}

// FamilyModuleCounts counts modules and functions per family.
type FamilyModuleCounts struct {
	Modules   int `yaml:"modules"`
	Functions int `yaml:"functions"`
}

// ModuleLists enumerates public module names per family.
type ModuleLists struct {
	Exec  []string `yaml:"exec"`
	State []string `yaml:"state"`
}

// corePrefixes are the Phase 2/3 module families StateKit prioritizes
// (plan section 31); relevance is classified against them.
var corePrefixes = map[string]bool{
	"cmd": true, "file": true, "test": true, "status": true, "system": true,
	"user": true, "group": true, "shadow": true, "pkg": true, "service": true,
	"sysctl": true, "mount": true, "disk": true, "archive": true, "cron": true,
	"hosts": true, "timezone": true, "locale": true,
}

// familyAliases map platform-split Salt modules onto their virtual family so
// relevance classification covers aptpkg -> pkg, systemd_service -> service,
// and similar splits.
var familyAliases = map[string]string{
	"aptpkg": "pkg", "yumpkg": "pkg", "zypperpkg": "pkg", "pacmanpkg": "pkg",
	"apkpkg": "pkg", "ebuildpkg": "pkg", "opkgpkg": "pkg", "pkgin": "pkg",
	"pkgng": "pkg", "mac_brew_pkg": "pkg", "mac_ports_pkg": "pkg",
	"solarispkg": "pkg", "win_pkg": "pkg", "dpkg_lowpkg": "pkg",
	"rpm_lowpkg": "pkg", "lowpkg": "pkg", "dnfmodule": "pkg",
	"systemd_service": "service", "debian_service": "service",
	"rh_service": "service", "gentoo_service": "service",
	"openbsdservice": "service", "freebsdservice": "service",
	"netbsdservice": "service", "mac_service": "service", "win_service": "service",
	"linux_shadow": "shadow", "bsd_shadow": "shadow", "aix_shadow": "shadow",
	"mac_shadow":   "shadow",
	"linux_sysctl": "sysctl", "mac_sysctl": "sysctl", "bsd_sysctl": "sysctl",
	"solaris_sysctl": "sysctl",
}

// nameMethodRe matches the opening line of a Name() method declaration.
var nameMethodRe = regexp.MustCompile(`^func\s+\([^)]*\)\s+Name\(\)\s+string\s*\{$`)

// nameOneLineRe matches a one-line Name() method returning a literal.
var nameOneLineRe = regexp.MustCompile(
	`^func\s+\([^)]*\)\s+Name\(\)\s+string\s*\{\s*return\s+"([A-Za-z0-9_]+\.[A-Za-z0-9_]+)"`)

// returnNameRe matches a bare literal return inside Name().
var returnNameRe = regexp.MustCompile(`^\s*return\s+"([A-Za-z0-9_]+\.[A-Za-z0-9_]+)"\s*$`)

// scanSaltTree walks salt/modules and salt/states producing ModuleDocs.
func scanSaltTree(saltDir string) ([]ModuleDoc, []ModuleDoc, error) {
	execDocs, err := scanFamily(saltDir, "exec", filepath.Join("salt", "modules"))
	if err != nil {
		return nil, nil, err
	}
	stateDocs, err := scanFamily(saltDir, "state", filepath.Join("salt", "states"))
	if err != nil {
		return nil, nil, err
	}
	return execDocs, stateDocs, nil
}

func scanFamily(saltDir, kind, relDir string) ([]ModuleDoc, error) {
	full := filepath.Join(saltDir, filepath.FromSlash(relDir))
	entries, err := os.ReadDir(full)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", relDir, err)
	}
	var docs []ModuleDoc
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".py") || strings.HasPrefix(name, "_") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(full, name))
		if err != nil {
			return nil, err
		}
		stem := strings.TrimSuffix(name, ".py")
		doc := parseModule(kind, relDir+"/"+name, stem, string(content))
		tests := mapTests(saltDir, kind, stem)
		for i := range doc.Functions {
			doc.Functions[i].Tests = tests
		}
		docs = append(docs, doc)
	}
	sort.Slice(docs, func(i, j int) bool { return docs[i].SourceModule < docs[j].SourceModule })
	return docs, nil
}

// mapTests locates the standard Salt test files for a module stem and counts
// their test functions.
func mapTests(saltDir, kind, stem string) []TestRef {
	var dirs []string
	switch kind {
	case "exec":
		dirs = []string{filepath.Join("tests", "unit", "modules"), filepath.Join("tests", "pytests", "unit", "modules")}
	default:
		dirs = []string{filepath.Join("tests", "unit", "states"), filepath.Join("tests", "pytests", "unit", "states")}
	}
	var refs []TestRef
	for _, dir := range dirs {
		path := filepath.Join(dir, "test_"+stem+".py")
		data, err := os.ReadFile(filepath.Join(saltDir, path))
		if err != nil {
			continue
		}
		refs = append(refs, TestRef{Path: path, Functions: countTestFunctions(string(data))})
	}
	return refs
}

// publicModuleName resolves the family-facing module name using aliases.
func publicModuleName(doc ModuleDoc) string {
	if fam, ok := familyAliases[doc.SourceModule]; ok && fam != "" {
		return fam
	}
	return doc.Module
}

// isRelevant reports whether a module belongs to the core local-OS families.
func isRelevant(doc ModuleDoc) bool {
	return corePrefixes[publicModuleName(doc)]
}

// scanImplementedNames extracts registered function names from Go source by
// locating Name() methods and their literal returns.
func scanImplementedNames(src string) []string {
	var names []string
	lines := strings.Split(src, "\n")
	for i := 0; i < len(lines); i++ {
		if m := nameOneLineRe.FindStringSubmatch(lines[i]); m != nil {
			names = append(names, m[1])
			continue
		}
		if !nameMethodRe.MatchString(lines[i]) {
			continue
		}
		for j := i + 1; j < len(lines) && j <= i+3; j++ {
			if rm := returnNameRe.FindStringSubmatch(lines[j]); rm != nil {
				names = append(names, rm[1])
				break
			}
		}
	}
	return names
}

// detectImplemented scans Go module sources for registered function names.
func detectImplemented(srcRoot string) (Implemented, error) {
	out := Implemented{}
	kinds := map[string]*[]string{
		filepath.Join("modules", "exec"):  &out.Exec,
		filepath.Join("modules", "state"): &out.State,
	}
	for rel, sink := range kinds {
		seen := map[string]bool{}
		root := filepath.Join(srcRoot, rel)
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, name := range scanImplementedNames(string(data)) {
				if seen[name] {
					continue
				}
				seen[name] = true
				*sink = append(*sink, name)
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			return out, err
		}
	}
	sort.Strings(out.Exec)
	sort.Strings(out.State)
	return out, nil
}

// buildCoverage assembles the migration coverage report.
func buildCoverage(ref ReferenceInfo, execDocs, stateDocs []ModuleDoc, impl Implemented) Coverage {
	cov := Coverage{Reference: ref, Implemented: impl}
	cov.Execution = familyCoverage(execDocs, impl.Exec)
	cov.State = familyCoverage(stateDocs, impl.State)
	cov.Execution.SourceInventoryCount = len(impl.Exec)
	cov.Execution.CatalogIntersectionCount = cov.Execution.Implemented
	cov.State.SourceInventoryCount = len(impl.State)
	cov.State.CatalogIntersectionCount = cov.State.Implemented
	return cov
}

func familyCoverage(docs []ModuleDoc, implemented []string) FamilyCoverage {
	fc := FamilyCoverage{}
	set := map[string]bool{}
	for _, name := range implemented {
		set[name] = true
	}
	matched := map[string]bool{}
	for _, doc := range docs {
		fc.SaltModules++
		fc.SaltFunctions += len(doc.Functions)
		module := publicModuleName(doc)
		for _, fn := range doc.Functions {
			if isRelevant(doc) {
				fc.RelevantFunctions++
			}
			// __func_alias__ renames (e.g. set_ -> set) define the
			// CLI-facing name StateKit mirrors.
			name := fn.Function
			if public, ok := doc.FuncAliases[name]; ok {
				name = public
			}
			full := module + "." + name
			if set[full] && !matched[full] {
				// Platform-split docs redefine the same virtual function;
				// count each distinct Salt function once.
				matched[full] = true
				fc.Implemented++
			}
		}
	}
	return fc
}

// Compatibility is the generated family-classification manifest (ledger v2).
// Buckets: implemented, excluded (permanent ADR reason), planned (targeted by
// a porting round). Partial appears once per-family subset annotations land.
type Compatibility struct {
	Reference           ReferenceInfo `yaml:"reference"`
	Summary             CompatSummary `yaml:"summary"`
	ImplementedFamilies []string      `yaml:"implemented_families"`
	Excluded            []string      `yaml:"excluded"`
	Planned             []string      `yaml:"planned"`
	PartialFamilies     []string      `yaml:"partial,omitempty"`
}

// CompatSummary counts families per ledger bucket.
type CompatSummary struct {
	FamiliesTotal int `yaml:"families_total"`
	Implemented   int `yaml:"implemented"`
	Partial       int `yaml:"partial"`
	Excluded      int `yaml:"excluded"`
	Planned       int `yaml:"planned"`
}

// writeCatalog emits per-module YAML documents plus index and coverage.
func writeCatalog(outDir string, ref ReferenceInfo, execDocs, stateDocs []ModuleDoc, cov Coverage, impl Implemented) error {
	for _, group := range []struct {
		dir  string
		docs []ModuleDoc
	}{
		{"exec", execDocs},
		{"states", stateDocs},
	} {
		target := filepath.Join(outDir, group.dir)
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
		for _, doc := range group.docs {
			data, err := yaml.Marshal(&doc)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(target, doc.SourceModule+".yaml"), data, 0o644); err != nil {
				return err
			}
		}
	}

	index := Index{
		Reference: ref,
		Modules:   moduleLists(execDocs, stateDocs),
	}
	index.Execution = FamilyModuleCounts{Modules: len(execDocs), Functions: countFunctions(execDocs)}
	index.State = FamilyModuleCounts{Modules: len(stateDocs), Functions: countFunctions(stateDocs)}
	if err := writeYAML(filepath.Join(outDir, "index.yaml"), &index); err != nil {
		return err
	}
	// Family classification must see BOTH surfaces: state-led families
	// (e.g. pkgrepo, whose exec functions live under the virtual pkg
	// module) otherwise never flip terminal.
	classification := classifyFamilies(append(append([]ModuleDoc{}, execDocs...), stateDocs...),
		append(append([]string{}, impl.Exec...), impl.State...))
	compat := Compatibility{
		Reference: ref,
		Summary: CompatSummary{
			FamiliesTotal: len(classification["implemented"]) +
				len(classification["excluded"]) + len(classification["planned"]),
			Implemented: len(classification["implemented"]),
			Excluded:    len(classification["excluded"]),
			Planned:     len(classification["planned"]),
		},
		ImplementedFamilies: classification["implemented"],
		Excluded:            classification["excluded"],
		Planned:             classification["planned"],
	}
	if err := writeYAML(filepath.Join(outDir, "compatibility.yaml"), &compat); err != nil {
		return err
	}
	return writeYAML(filepath.Join(outDir, "coverage.yaml"), &cov)
}

func moduleLists(execDocs, stateDocs []ModuleDoc) ModuleLists {
	lists := ModuleLists{Exec: []string{}, State: []string{}}
	for _, d := range execDocs {
		lists.Exec = append(lists.Exec, d.Module)
	}
	for _, d := range stateDocs {
		lists.State = append(lists.State, d.Module)
	}
	sort.Strings(lists.Exec)
	sort.Strings(lists.State)
	return lists
}

func countFunctions(docs []ModuleDoc) int {
	total := 0
	for _, d := range docs {
		total += len(d.Functions)
	}
	return total
}

func writeYAML(path string, v any) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// resolveReference reads the pinned commit and version from the vendored
// Salt git tree.
// resolveReference pins the scanned Salt revision. The git subprocess is
// the primary source; no-git sandboxes fall back to the recorded pin in
// the lock file so regeneration stays deterministic without a git
// binary. The lock and the submodule it was written from are pinned
// together, so the fallback resolves to the same revision.
func resolveReference(saltDir, lockPath string) (ReferenceInfo, error) {
	ref := ReferenceInfo{Repository: "https://github.com/saltstack/salt"}
	commitBytes, err := exec.Command("git", "-C", saltDir, "rev-parse", "HEAD").Output()
	if err != nil {
		if locked, lockErr := readSaltLock(lockPath); lockErr == nil && locked.Commit != "" {
			return locked, nil
		}
		return ref, fmt.Errorf("resolve salt commit (is the submodule initialized?): %w", err)
	}
	ref.Commit = strings.TrimSpace(string(commitBytes))
	versionBytes, err := exec.Command("git", "-C", saltDir, "describe", "--tags").Output()
	if err == nil {
		ref.Version = strings.TrimSpace(string(versionBytes))
	}
	return ref, nil
}

// readSaltLock parses a previously written references/salt.lock pin.
func readSaltLock(path string) (ReferenceInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ReferenceInfo{}, err
	}
	var lock struct {
		Repository string `yaml:"repository"`
		Commit     string `yaml:"commit"`
		Version    string `yaml:"version"`
	}
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return ReferenceInfo{}, err
	}
	if lock.Repository == "" {
		lock.Repository = "https://github.com/saltstack/salt"
	}
	return ReferenceInfo{Repository: lock.Repository, Commit: lock.Commit, Version: lock.Version}, nil
}

// writeSaltLock persists references/salt.lock (plan section 21).
func writeSaltLock(path string, ref ReferenceInfo) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	type lockFile struct {
		Repository string `yaml:"repository"`
		Commit     string `yaml:"commit"`
		Version    string `yaml:"version"`
	}
	return writeYAML(path, lockFile{Repository: ref.Repository, Commit: ref.Commit, Version: ref.Version})
}
