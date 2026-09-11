package pkg

// FreeBSD virtual pkg implementation for Salt's pkgng module
// (saltstack/salt/modules/pkgng.py @ pinned revision 8b63e700637e,
// tests/pytests/unit/modules/test_pkgng.py). Unlike the darwin/windows
// providers this surface is intentionally untagged so the Linux test
// host can exercise every provider function directly with a recording
// fake Runner; the per-function Platforms() declarations provide the
// freebsd-only gating (registry filtering mirrors Salt's __virtual__
// kernel check). pkg.Register selects this surface on GOOS=freebsd.

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// pkgngScopeArgs mirrors _pkg(): -j jail, elif -c chroot, elif -r root.
func pkgngScopeArgs(jail, chroot, root string) []string {
	switch {
	case jail != "":
		return []string{"-j", jail}
	case chroot != "":
		return []string{"-c", chroot}
	case root != "":
		return []string{"-r", root}
	}
	return nil
}

func pkgngPrefix(jail, chroot, root string) []string {
	return append([]string{"pkg"}, pkgngScopeArgs(jail, chroot, root)...)
}

// pkgngRun is the bounded shell-free Runner bridge. Cancellation is
// checked before any process starts; Runner errors (including a missing
// pkg binary) surface as errors, never as fabricated success.
func pkgngRun(ctx context.Context, rt *runtime.Runtime, argv ...string) (process.CommandResult, error) {
	if err := ctx.Err(); err != nil {
		return process.CommandResult{}, err
	}
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return res, res.Err
	}
	return res, nil
}

func registerFreeBSD(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		pkgngRefreshDBFunc{}, pkgngVersionFunc{}, pkgngLatestVersionFunc{}, pkgngListPkgsFunc{},
		pkgngParseConfigFunc{}, pkgngUpdatePackageSiteFunc{}, pkgngStatsFunc{}, pkgngBackupFunc{},
		pkgngRestoreFunc{}, pkgngAuditFunc{}, pkgngInstallFunc{}, pkgngRemoveFunc{},
		pkgngUpgradeFunc{}, pkgngCleanFunc{}, pkgngAutoremoveFunc{}, pkgngCheckFunc{},
		pkgngWhichFunc{}, pkgngSearchFunc{}, pkgngFetchFunc{}, pkgngUpdatingFunc{},
		pkgngHoldFunc{}, pkgngUnholdFunc{}, pkgngListLockedFunc{}, pkgngLockedFunc{},
		pkgngLockFunc{}, pkgngUnlockFunc{}, pkgngListUpgradesFunc{}, pkgngVersionCmpFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// installed-package inventory (pkg info -ao, per list_pkgs)

type pkgngInstalledPkg struct {
	name    string
	version string
	origin  string
}

// pkgngListInstalled parses `pkg info -ao` output: "name-version origin"
// per line, mirroring the ValueError-skipping loop in list_pkgs.
func pkgngListInstalled(out string) ([]pkgngInstalledPkg, map[string]string) {
	var pkgs []pkgngInstalledPkg
	origins := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		idx := strings.LastIndex(fields[0], "-")
		if idx < 0 {
			continue
		}
		pkgs = append(pkgs, pkgngInstalledPkg{
			name:    fields[0][:idx],
			version: fields[0][idx+1:],
			origin:  fields[1],
		})
		origins[fields[0][:idx]] = fields[1]
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].name < pkgs[j].name })
	return pkgs, origins
}

func pkgngInstalledTable(pkgs []pkgngInstalledPkg) map[string]string {
	table := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		table[p.name] = p.version
	}
	return table
}

func pkgngListPkgsRaw(ctx context.Context, rt *runtime.Runtime, jail, chroot, root string) ([]pkgngInstalledPkg, map[string]string, error) {
	res, err := pkgngRun(ctx, rt, append(pkgngPrefix(jail, chroot, root), "info", "-ao")...)
	if err != nil {
		return nil, nil, err
	}
	pkgs, origins := pkgngListInstalled(string(res.Stdout))
	return pkgs, origins, nil
}

// pkgngVersionCompare is the FreeBSD version ordering used by
// latest_version's salt.utils.versions.compare(installed, ">=", pkgver)
// gate: numeric segments split on "." and "_", with a lexicographic
// fallback for non-numeric tails. It returns -1, 0, or 1.
func pkgngVersionCompare(a, b string) int {
	split := func(v string) []string {
		return strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '_' })
	}
	as, bs := split(a), split(b)
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])
		if aerr == nil && berr == nil {
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
			continue
		}
		if c := strings.Compare(as[i], bs[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// version / refresh_db / latest_version / list_pkgs

type PkgngVersionArgs struct {
	Names      []string `statekit:"required"`
	WithOrigin bool     `statekit:"name=with_origin"`
	Jail       string   `statekit:"name=jail"`
	Chroot     string   `statekit:"name=chroot"`
	Root       string   `statekit:"name=root"`
}

type pkgngVersionFunc struct{}

func (pkgngVersionFunc) Name() string        { return "pkg.version" }
func (pkgngVersionFunc) Args() any           { return PkgngVersionArgs{} }
func (pkgngVersionFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngVersionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngVersionArgs)
	pkgs, origins, err := pkgngListPkgsRaw(ctx, rt, a.Jail, a.Chroot, a.Root)
	if err != nil {
		return nil, err
	}
	table := pkgngInstalledTable(pkgs)
	if len(a.Names) == 1 {
		if !a.WithOrigin {
			return table[a.Names[0]], nil
		}
		return map[string]any{
			a.Names[0]: map[string]any{"origin": origins[a.Names[0]], "version": table[a.Names[0]]},
		}, nil
	}
	out := map[string]any{}
	for _, name := range a.Names {
		if a.WithOrigin {
			out[name] = map[string]any{"origin": origins[name], "version": table[name]}
			continue
		}
		out[name] = table[name]
	}
	return out, nil
}

type PkgngRefreshDBArgs struct {
	Force  bool   `statekit:"name=force"`
	Jail   string `statekit:"name=jail"`
	Chroot string `statekit:"name=chroot"`
	Root   string `statekit:"name=root"`
}

type pkgngRefreshDBFunc struct{}

func (pkgngRefreshDBFunc) Name() string        { return "pkg.refresh_db" }
func (pkgngRefreshDBFunc) Args() any           { return PkgngRefreshDBArgs{} }
func (pkgngRefreshDBFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngRefreshDBFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngRefreshDBArgs)
	argv := append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "update")
	if a.Force {
		argv = append(argv, "-f")
	}
	res, err := pkgngRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	return res.ExitCode == 0, nil
}

type PkgngLatestVersionArgs struct {
	Names   []string `statekit:"required"`
	Refresh bool     `statekit:"name=refresh"`
	Jail    string   `statekit:"name=jail"`
	Chroot  string   `statekit:"name=chroot"`
	Root    string   `statekit:"name=root"`
}

type pkgngLatestVersionFunc struct{}

func (pkgngLatestVersionFunc) Name() string        { return "pkg.latest_version" }
func (pkgngLatestVersionFunc) Args() any           { return PkgngLatestVersionArgs{} }
func (pkgngLatestVersionFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngLatestVersionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngLatestVersionArgs)
	if len(a.Names) == 0 {
		return "", nil
	}
	latest := map[string]string{}
	for _, name := range a.Names {
		latest[name] = ""
	}
	pkgs, _, err := pkgngListPkgsRaw(ctx, rt, a.Jail, a.Chroot, a.Root)
	if err != nil {
		return nil, err
	}
	table := pkgngInstalledTable(pkgs)
	for _, name := range a.Names {
		argv := append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "search", "-eqS")
		if strings.Contains(name, "/") {
			// FreeBSD's pkg supports searching by origin, like java/openjdk7.
			argv = append(argv, "origin")
		} else {
			argv = append(argv, "name")
		}
		if !a.Refresh {
			argv = append(argv, "-U")
		}
		argv = append(argv, name)
		res, err := pkgngRun(ctx, rt, argv...)
		if err != nil {
			return nil, err
		}
		output := strings.TrimSpace(string(res.Stdout))
		if output == "" {
			continue
		}
		idx := strings.LastIndex(output, "-")
		if idx < 0 {
			// pkg_output.rsplit("-", 1)[1] is an IndexError in the pinned
			// source when the search output carries no version.
			return nil, fmt.Errorf("pkg.latest_version: malformed search output %q", output)
		}
		candidate := output[idx+1:]
		current, isInstalled := table[name]
		if !isInstalled {
			latest[name] = candidate
			continue
		}
		if pkgngVersionCompare(current, candidate) < 0 {
			latest[name] = candidate
		}
	}
	if len(a.Names) == 1 {
		return latest[a.Names[0]], nil
	}
	out := map[string]any{}
	for _, name := range a.Names {
		out[name] = latest[name]
	}
	return out, nil
}

type PkgngListPkgsArgs struct {
	VersionsAsList bool   `statekit:"name=versions_as_list"`
	WithOrigin     bool   `statekit:"name=with_origin"`
	Removed        bool   `statekit:"name=removed"`
	PurgeDesired   bool   `statekit:"name=purge_desired"`
	Jail           string `statekit:"name=jail"`
	Chroot         string `statekit:"name=chroot"`
	Root           string `statekit:"name=root"`
}

type pkgngListPkgsFunc struct{}

func (pkgngListPkgsFunc) Name() string        { return "pkg.list_pkgs" }
func (pkgngListPkgsFunc) Args() any           { return PkgngListPkgsArgs{} }
func (pkgngListPkgsFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngListPkgsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngListPkgsArgs)
	// Not yet implemented or not applicable in the pinned source.
	if a.Removed || a.PurgeDesired {
		return map[string]any{}, nil
	}
	pkgs, origins, err := pkgngListPkgsRaw(ctx, rt, a.Jail, a.Chroot, a.Root)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, p := range pkgs {
		value := any(p.version)
		if a.VersionsAsList {
			value = []string{p.version}
		}
		if a.WithOrigin {
			out[p.name] = map[string]any{"origin": origins[p.name], "version": value}
			continue
		}
		out[p.name] = value
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// parse_config / update_package_site

type PkgngParseConfigArgs struct {
	FileName string `statekit:"name=file_name"`
}

type pkgngParseConfigFunc struct{}

func (pkgngParseConfigFunc) Name() string        { return "pkg.parse_config" }
func (pkgngParseConfigFunc) Args() any           { return PkgngParseConfigArgs{} }
func (pkgngParseConfigFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngParseConfigFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngParseConfigArgs)
	if a.FileName == "" {
		a.FileName = "/usr/local/etc/pkg.conf"
	}
	return pkgngParseConfig(rt, a.FileName)
}

// pkgngParseConfig mirrors parse_config: uncommented "key\tvalue" lines
// plus config_file. A missing file returns the literal status string (the
// pinned source returns it, not an error); a line without a tab is the
// upstream ValueError crash translated to an error.
func pkgngParseConfig(rt *runtime.Runtime, fileName string) (any, error) {
	data, err := rt.FS.ReadFile(fileName)
	if err != nil {
		return fmt.Sprintf("Unable to find %s on file system", fileName), nil
	}
	ret := map[string]any{}
	for _, line := range strings.Split(string(data), "\n") {
		// An empty element is the trailing-newline artifact or a bare
		// blank line; both are skipped exactly like the pinned source's
		// startswith("\n") filter over file iteration.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "\n") {
			continue
		}
		key, value, ok := strings.Cut(line, "\t")
		if !ok {
			return nil, fmt.Errorf("pkg.parse_config: malformed line %q", line)
		}
		ret[key] = value
	}
	ret["config_file"] = fileName
	return ret, nil
}

type PkgngUpdatePackageSiteArgs struct {
	NewURL string `statekit:"required,name=new_url"`
}

type pkgngUpdatePackageSiteFunc struct{}

var pkgngPackageSiteRe = regexp.MustCompile(`(?m)^PACKAGESITE.*$`)

func (pkgngUpdatePackageSiteFunc) Name() string        { return "pkg.update_package_site" }
func (pkgngUpdatePackageSiteFunc) Args() any           { return PkgngUpdatePackageSiteArgs{} }
func (pkgngUpdatePackageSiteFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngUpdatePackageSiteFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngUpdatePackageSiteArgs)
	parsed, err := pkgngParseConfig(rt, "/usr/local/etc/pkg.conf")
	if err != nil {
		return nil, err
	}
	// The pinned source dereferences parse_config()["config_file"]; a
	// non-dict return (missing file) is its KeyError crash, translated
	// here into an error instead of a panic.
	config, ok := parsed.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("pkg.update_package_site: pkg.conf not parseable")
	}
	configFile, _ := config["config_file"].(string)
	data, err := rt.FS.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	replacement := "PACKAGESITE\t : " + a.NewURL
	updated := pkgngPackageSiteRe.ReplaceAllString(string(data), replacement)
	mode := fs.FileMode(0o644)
	if info, statErr := rt.FS.Stat(configFile); statErr == nil {
		mode = info.Mode().Perm()
	}
	if err := rt.FS.WriteFile(configFile, []byte(updated), mode); err != nil {
		return nil, err
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// stats / backup / restore / audit

type PkgngStatsArgs struct {
	Local  bool   `statekit:"name=local"`
	Remote bool   `statekit:"name=remote"`
	Bytes  bool   `statekit:"name=bytes"`
	Jail   string `statekit:"name=jail"`
	Chroot string `statekit:"name=chroot"`
	Root   string `statekit:"name=root"`
}

type pkgngStatsFunc struct{}

func (pkgngStatsFunc) Name() string        { return "pkg.stats" }
func (pkgngStatsFunc) Args() any           { return PkgngStatsArgs{} }
func (pkgngStatsFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngStatsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngStatsArgs)
	opts := &strings.Builder{}
	if a.Local {
		opts.WriteString("l")
	}
	if a.Remote {
		opts.WriteString("r")
	}
	if a.Bytes {
		opts.WriteString("b")
	}
	argv := append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "stats")
	if opts.Len() > 0 {
		argv = append(argv, "-"+opts.String())
	}
	res, err := pkgngRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	// salt.utils.itertools.split("") yields no elements; each remaining
	// line is stripped of tab padding exactly like strip("\t").
	out := string(res.Stdout)
	if out == "" {
		return []string{}, nil
	}
	lines := []string{}
	for _, line := range strings.Split(out, "\n") {
		lines = append(lines, strings.Trim(line, "\t"))
	}
	return lines, nil
}

type PkgngBackupArgs struct {
	FileName string `statekit:"required,name=file_name"`
	Jail     string `statekit:"name=jail"`
	Chroot   string `statekit:"name=chroot"`
	Root     string `statekit:"name=root"`
}

type pkgngBackupFunc struct{}

func (pkgngBackupFunc) Name() string        { return "pkg.backup" }
func (pkgngBackupFunc) Args() any           { return PkgngBackupArgs{} }
func (pkgngBackupFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngBackupFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngBackupArgs)
	res, err := pkgngRun(ctx, rt, append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "backup", "-d", a.FileName)...)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(string(res.Stdout), "...")
	if len(parts) < 2 {
		// ret.split("...")[1] is an IndexError in the pinned source; the
		// marker-less output is surfaced as an error instead of a panic.
		return nil, fmt.Errorf("pkg.backup: output missing %q progress marker", "...")
	}
	return parts[1], nil
}

type PkgngRestoreArgs struct {
	FileName string `statekit:"required,name=file_name"`
	Jail     string `statekit:"name=jail"`
	Chroot   string `statekit:"name=chroot"`
	Root     string `statekit:"name=root"`
}

type pkgngRestoreFunc struct{}

func (pkgngRestoreFunc) Name() string        { return "pkg.restore" }
func (pkgngRestoreFunc) Args() any           { return PkgngRestoreArgs{} }
func (pkgngRestoreFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngRestoreFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngRestoreArgs)
	res, err := pkgngRun(ctx, rt, append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "backup", "-r", a.FileName)...)
	if err != nil {
		return nil, err
	}
	return string(res.Stdout), nil
}

type PkgngAuditArgs struct {
	Jail   string `statekit:"name=jail"`
	Chroot string `statekit:"name=chroot"`
	Root   string `statekit:"name=root"`
}

type pkgngAuditFunc struct{}

func (pkgngAuditFunc) Name() string        { return "pkg.audit" }
func (pkgngAuditFunc) Args() any           { return PkgngAuditArgs{} }
func (pkgngAuditFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngAuditFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngAuditArgs)
	res, err := pkgngRun(ctx, rt, append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "audit", "-F")...)
	if err != nil {
		return nil, err
	}
	return string(res.Stdout), nil
}

// ---------------------------------------------------------------------------
// install / remove / upgrade change accounting

type pkgngTarget struct {
	name    string
	version string
}

// pkgngParseTargets is the name/pkgs/sources subset of
// pkg_resource.parse_targets used by install/remove. Sources select the
// "file" flavor (`pkg add`); pkgs/name select "repository". Order is
// preserved for argv construction.
func pkgngParseTargets(name, version string, pkgs, sources []any) ([]pkgngTarget, string, error) {
	if len(sources) > 0 {
		targets := make([]pkgngTarget, 0, len(sources))
		for _, source := range sources {
			path, ok := source.(string)
			if !ok {
				return nil, "", fmt.Errorf("sources must be a list of file paths")
			}
			targets = append(targets, pkgngTarget{name: path})
		}
		return targets, "file", nil
	}
	if len(pkgs) > 0 {
		targets := make([]pkgngTarget, 0, len(pkgs))
		for _, item := range pkgs {
			switch typed := item.(type) {
			case string:
				targets = append(targets, pkgngTarget{name: typed})
			case map[string]any:
				if len(typed) != 1 {
					return nil, "", fmt.Errorf("Invalid input: pkgs mappings must have exactly one key")
				}
				for key, value := range typed {
					ver := ""
					if value != nil {
						text, ok := value.(string)
						if !ok {
							return nil, "", fmt.Errorf("Invalid input: pkgs mapping values must be version strings")
						}
						ver = text
					}
					targets = append(targets, pkgngTarget{name: key, version: ver})
				}
			default:
				return nil, "", fmt.Errorf("Invalid input: pkgs must be package names or one-key mappings")
			}
		}
		return targets, "repository", nil
	}
	if name != "" {
		names := strings.Split(name, ",")
		targets := make([]pkgngTarget, 0, len(names))
		for _, entry := range names {
			if version != "" && len(names) == 1 {
				targets = append(targets, pkgngTarget{name: entry, version: version})
				continue
			}
			targets = append(targets, pkgngTarget{name: entry})
		}
		return targets, "repository", nil
	}
	return nil, "", nil
}

// pkgngCompareDicts mirrors salt.utils.data.compare_dicts on the
// installed-package table: only changed keys survive, missing sides
// degrade to "".
func pkgngCompareDicts(oldPkgs, newPkgs map[string]string) map[string]any {
	changed := map[string]any{}
	for key, oldValue := range oldPkgs {
		newValue, ok := newPkgs[key]
		if ok && newValue == oldValue {
			continue
		}
		changed[key] = map[string]any{"new": newValue, "old": oldValue}
	}
	for key, newValue := range newPkgs {
		if _, ok := oldPkgs[key]; ok {
			continue
		}
		changed[key] = map[string]any{"new": newValue, "old": ""}
	}
	return changed
}

type PkgngInstallArgs struct {
	Name              string `statekit:"name=name"`
	Version           string `statekit:"name=version"`
	Pkgs              []any  `statekit:"name=pkgs"`
	Sources           []any  `statekit:"name=sources"`
	Fromrepo          string `statekit:"name=fromrepo"`
	Jail              string `statekit:"name=jail"`
	Chroot            string `statekit:"name=chroot"`
	Root              string `statekit:"name=root"`
	Orphan            bool   `statekit:"name=orphan"`
	Force             bool   `statekit:"name=force"`
	Glob              bool   `statekit:"name=glob"`
	Local             bool   `statekit:"name=local"`
	Dryrun            bool   `statekit:"name=dryrun"`
	Quiet             bool   `statekit:"name=quiet"`
	ReinstallRequires bool   `statekit:"name=reinstall_requires"`
	Regex             bool   `statekit:"name=regex"`
	Pcre              bool   `statekit:"name=pcre"`
	Batch             bool   `statekit:"name=batch"`
}

type pkgngInstallFunc struct{}

func (pkgngInstallFunc) Name() string        { return "pkg.install" }
func (pkgngInstallFunc) Args() any           { return PkgngInstallArgs{} }
func (pkgngInstallFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngInstallFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngInstallArgs)
	if a.Pkgs == nil {
		targets, flavor, err := pkgngParseTargets(a.Name, a.Version, nil, a.Sources)
		if err != nil {
			return nil, err
		}
		return pkgngInstallImpl(ctx, rt, targets, flavor, a)
	}
	targets, flavor, err := pkgngParseTargets("", "", a.Pkgs, a.Sources)
	if err != nil {
		return nil, err
	}
	return pkgngInstallImpl(ctx, rt, targets, flavor, a)
}

func pkgngInstallImpl(ctx context.Context, rt *runtime.Runtime, targets []pkgngTarget, flavor string, a *PkgngInstallArgs) (any, error) {
	if len(targets) == 0 {
		return map[string]any{}, nil
	}
	opts := &strings.Builder{}
	opts.WriteString("y")
	if a.Orphan {
		opts.WriteString("A")
	}
	if a.Force {
		opts.WriteString("f")
	}
	if a.Glob {
		opts.WriteString("g")
	}
	if a.Local {
		opts.WriteString("U")
	}
	if a.Dryrun {
		opts.WriteString("n")
	}
	if a.Quiet {
		opts.WriteString("q")
	}
	if a.ReinstallRequires {
		opts.WriteString("R")
	}
	if a.Regex {
		opts.WriteString("x")
	}
	if a.Pcre {
		opts.WriteString("X")
	}

	oldPkgs, _, err := pkgngListPkgsRaw(ctx, rt, a.Jail, a.Chroot, a.Root)
	if err != nil {
		return nil, err
	}
	oldTable := pkgngInstalledTable(oldPkgs)

	var argv []string
	switch flavor {
	case "file":
		// pkg add has a smaller option set (i.e. no -y or -n).
		filtered := &strings.Builder{}
		for _, opt := range opts.String() {
			if strings.ContainsRune("AfIMq", opt) {
				filtered.WriteRune(opt)
			}
		}
		argv = append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "add")
		if filtered.Len() > 0 {
			argv = append(argv, "-"+filtered.String())
		}
		for _, target := range targets {
			argv = append(argv, target.name)
		}
		if a.Dryrun {
			// pkg add doesn't have a dry-run mode, so echo out what will run.
			return strings.Join(argv, " "), nil
		}
	case "repository":
		argv = append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "install")
		if a.Fromrepo != "" {
			argv = append(argv, "-r", a.Fromrepo)
		}
		argv = append(argv, "-"+opts.String())
		for _, target := range targets {
			if target.version == "" {
				argv = append(argv, target.name)
				continue
			}
			argv = append(argv, target.name+"-"+target.version)
		}
	default:
		return nil, fmt.Errorf("Problem encountered installing package(s)")
	}

	command := runtime.Command(argv...)
	if a.Batch {
		// Salt merges the batch env over the inherited environment.
		command.Env = append(os.Environ(), "BATCH=true", "ASSUME_ALWAYS_YES=YES")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	res := rt.Runner.Run(ctx, command)
	if res.Err != nil {
		return nil, res.Err
	}
	errors := []string{}
	if res.ExitCode != 0 && len(res.Stderr) > 0 {
		errors = append(errors, string(res.Stderr))
	}

	newPkgs, _, err := pkgngListPkgsRaw(ctx, rt, a.Jail, a.Chroot, a.Root)
	if err != nil {
		return nil, err
	}
	changes := pkgngCompareDicts(oldTable, pkgngInstalledTable(newPkgs))
	if len(errors) > 0 {
		return nil, fmt.Errorf("Problem encountered installing package(s): %s", strings.Join(errors, "; "))
	}
	return changes, nil
}

type PkgngRemoveArgs struct {
	Name         string `statekit:"name=name"`
	Pkgs         []any  `statekit:"name=pkgs"`
	Jail         string `statekit:"name=jail"`
	Chroot       string `statekit:"name=chroot"`
	Root         string `statekit:"name=root"`
	AllInstalled bool   `statekit:"name=all_installed"`
	Force        bool   `statekit:"name=force"`
	Glob         bool   `statekit:"name=glob"`
	Dryrun       bool   `statekit:"name=dryrun"`
	Recurse      bool   `statekit:"name=recurse"`
	Regex        bool   `statekit:"name=regex"`
	Pcre         bool   `statekit:"name=pcre"`
}

type pkgngRemoveFunc struct{}

func (pkgngRemoveFunc) Name() string        { return "pkg.remove" }
func (pkgngRemoveFunc) Args() any           { return PkgngRemoveArgs{} }
func (pkgngRemoveFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngRemoveArgs)
	if a.Pkgs == nil {
		targets, _, err := pkgngParseTargets(a.Name, "", nil, nil)
		if err != nil {
			return nil, err
		}
		return pkgngRemoveImpl(ctx, rt, targets, a)
	}
	targets, _, err := pkgngParseTargets("", "", a.Pkgs, nil)
	if err != nil {
		return nil, err
	}
	return pkgngRemoveImpl(ctx, rt, targets, a)
}

func pkgngRemoveImpl(ctx context.Context, rt *runtime.Runtime, targets []pkgngTarget, a *PkgngRemoveArgs) (any, error) {
	oldPkgs, _, err := pkgngListPkgsRaw(ctx, rt, a.Jail, a.Chroot, a.Root)
	if err != nil {
		return nil, err
	}
	old := map[string]map[string]string{}
	for _, p := range oldPkgs {
		old[p.name] = map[string]string{"origin": p.origin, "version": p.version}
	}

	names := []string{}
	for _, target := range targets {
		name := target.name
		originResolved := false
		// FreeBSD pkg supports `openjdk` and `java/openjdk7` package names.
		if strings.Index(name, "/") > 0 {
			resolved := ""
			for _, p := range oldPkgs {
				if p.origin == name {
					resolved = p.name
					break
				}
			}
			if resolved == "" {
				// [k for k, v in old.items() if v["origin"] == origin][0]
				// is an IndexError in the pinned source.
				return nil, fmt.Errorf("pkg.remove: no installed package with origin %q", name)
			}
			name = resolved
			originResolved = true
		}
		// After the origin branch the pinned source reassigns pkg to the
		// bare name string, so its subsequent `pkg[0] in old` membership
		// test reads the FIRST CHARACTER of the resolved name. That
		// upstream quirk is mirrored exactly rather than silently fixed.
		lookup := name
		if originResolved {
			lookup = name[:1]
		}
		if _, ok := old[lookup]; ok {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return map[string]any{}, nil
	}

	opts := &strings.Builder{}
	if a.AllInstalled {
		opts.WriteString("a")
	}
	if a.Force {
		opts.WriteString("f")
	}
	if a.Glob {
		opts.WriteString("g")
	}
	if a.Dryrun {
		opts.WriteString("n")
	}
	if !a.Dryrun {
		opts.WriteString("y")
	}
	if a.Recurse {
		opts.WriteString("R")
	}
	if a.Regex {
		opts.WriteString("x")
	}
	if a.Pcre {
		opts.WriteString("X")
	}

	argv := append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "delete", "-"+opts.String())
	argv = append(argv, names...)
	res, err := pkgngRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	errors := []string{}
	if res.ExitCode != 0 && len(res.Stderr) > 0 {
		errors = append(errors, string(res.Stderr))
	}

	newPkgs, _, err := pkgngListPkgsRaw(ctx, rt, a.Jail, a.Chroot, a.Root)
	if err != nil {
		return nil, err
	}
	oldTable := map[string]string{}
	for name, entry := range old {
		oldTable[name] = entry["version"]
	}
	changes := pkgngCompareDicts(oldTable, pkgngInstalledTable(newPkgs))
	if len(errors) > 0 {
		return nil, fmt.Errorf("Problem encountered removing package(s): %s", strings.Join(errors, "; "))
	}
	return changes, nil
}

type PkgngUpgradeArgs struct {
	Names     []string `statekit:"name=names"`
	Pkgs      []string `statekit:"name=pkgs"`
	Force     bool     `statekit:"name=force"`
	Local     bool     `statekit:"name=local"`
	Dryrun    bool     `statekit:"name=dryrun"`
	Fetchonly bool     `statekit:"name=fetchonly"`
	Fromrepo  string   `statekit:"name=fromrepo"`
	Jail      string   `statekit:"name=jail"`
	Chroot    string   `statekit:"name=chroot"`
	Root      string   `statekit:"name=root"`
}

type pkgngUpgradeFunc struct{}

func (pkgngUpgradeFunc) Name() string        { return "pkg.upgrade" }
func (pkgngUpgradeFunc) Args() any           { return PkgngUpgradeArgs{} }
func (pkgngUpgradeFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngUpgradeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngUpgradeArgs)
	opts := &strings.Builder{}
	if a.Force {
		opts.WriteString("f")
	}
	if a.Local {
		opts.WriteString("U")
	}
	if a.Fetchonly {
		opts.WriteString("F")
	}
	if a.Dryrun {
		opts.WriteString("n")
	}
	if !a.Dryrun {
		opts.WriteString("y")
	}
	argv := append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "upgrade", "-"+opts.String())
	argv = append(argv, a.Names...)
	argv = append(argv, a.Pkgs...)
	if a.Fromrepo != "" {
		argv = append(argv, "--repository", a.Fromrepo)
	}

	oldPkgs, _, err := pkgngListPkgsRaw(ctx, rt, "", "", "")
	if err != nil {
		return nil, err
	}
	res, err := pkgngRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	newPkgs, _, err := pkgngListPkgsRaw(ctx, rt, "", "", "")
	if err != nil {
		return nil, err
	}
	changes := pkgngCompareDicts(pkgngInstalledTable(oldPkgs), pkgngInstalledTable(newPkgs))
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("Problem encountered upgrading packages (exit %d): %s", res.ExitCode, string(res.Stderr))
	}
	return changes, nil
}

// ---------------------------------------------------------------------------
// clean / autoremove / check / which / search / fetch / updating

type PkgngCleanArgs struct {
	CleanAll bool   `statekit:"name=clean_all"`
	Dryrun   bool   `statekit:"name=dryrun"`
	Jail     string `statekit:"name=jail"`
	Chroot   string `statekit:"name=chroot"`
	Root     string `statekit:"name=root"`
}

type pkgngCleanFunc struct{}

func (pkgngCleanFunc) Name() string        { return "pkg.clean" }
func (pkgngCleanFunc) Args() any           { return PkgngCleanArgs{} }
func (pkgngCleanFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngCleanFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngCleanArgs)
	opts := &strings.Builder{}
	if a.CleanAll {
		opts.WriteString("a")
	}
	if a.Dryrun {
		opts.WriteString("n")
	} else {
		opts.WriteString("y")
	}
	res, err := pkgngRun(ctx, rt, append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "clean", "-"+opts.String())...)
	if err != nil {
		return nil, err
	}
	return string(res.Stdout), nil
}

type PkgngAutoremoveArgs struct {
	Dryrun bool   `statekit:"name=dryrun"`
	Jail   string `statekit:"name=jail"`
	Chroot string `statekit:"name=chroot"`
	Root   string `statekit:"name=root"`
}

type pkgngAutoremoveFunc struct{}

func (pkgngAutoremoveFunc) Name() string        { return "pkg.autoremove" }
func (pkgngAutoremoveFunc) Args() any           { return PkgngAutoremoveArgs{} }
func (pkgngAutoremoveFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngAutoremoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngAutoremoveArgs)
	opts := "y"
	if a.Dryrun {
		opts = "n"
	}
	res, err := pkgngRun(ctx, rt, append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "autoremove", "-"+opts)...)
	if err != nil {
		return nil, err
	}
	return string(res.Stdout), nil
}

type PkgngCheckArgs struct {
	Depends   bool   `statekit:"name=depends"`
	Recompute bool   `statekit:"name=recompute"`
	Checksum  bool   `statekit:"name=checksum"`
	Checklibs bool   `statekit:"name=checklibs"`
	Jail      string `statekit:"name=jail"`
	Chroot    string `statekit:"name=chroot"`
	Root      string `statekit:"name=root"`
}

type pkgngCheckFunc struct{}

func (pkgngCheckFunc) Name() string        { return "pkg.check" }
func (pkgngCheckFunc) Args() any           { return PkgngCheckArgs{} }
func (pkgngCheckFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngCheckFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngCheckArgs)
	if !a.Depends && !a.Recompute && !a.Checksum && !a.Checklibs {
		return "One of depends, recompute, checksum or checklibs must be set to True", nil
	}
	opts := &strings.Builder{}
	if a.Depends {
		opts.WriteString("dy")
	}
	if a.Recompute {
		opts.WriteString("r")
	}
	if a.Checksum {
		opts.WriteString("s")
	}
	if a.Checklibs {
		opts.WriteString("B")
	}
	res, err := pkgngRun(ctx, rt, append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "check", "-"+opts.String())...)
	if err != nil {
		return nil, err
	}
	return string(res.Stdout), nil
}

type PkgngWhichArgs struct {
	Path   string `statekit:"required,name=path"`
	Origin bool   `statekit:"name=origin"`
	Quiet  bool   `statekit:"name=quiet"`
	Jail   string `statekit:"name=jail"`
	Chroot string `statekit:"name=chroot"`
	Root   string `statekit:"name=root"`
}

type pkgngWhichFunc struct{}

func (pkgngWhichFunc) Name() string        { return "pkg.which" }
func (pkgngWhichFunc) Args() any           { return PkgngWhichArgs{} }
func (pkgngWhichFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngWhichFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngWhichArgs)
	opts := &strings.Builder{}
	if a.Quiet {
		opts.WriteString("q")
	}
	if a.Origin {
		opts.WriteString("o")
	}
	argv := append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "which")
	if opts.Len() > 0 {
		argv = append(argv, "-"+opts.String())
	}
	argv = append(argv, a.Path)
	res, err := pkgngRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	return string(res.Stdout), nil
}

type PkgngSearchArgs struct {
	Name    string `statekit:"required,name=name"`
	Exact   bool   `statekit:"name=exact"`
	Glob    bool   `statekit:"name=glob"`
	Regex   bool   `statekit:"name=regex"`
	Pcre    bool   `statekit:"name=pcre"`
	Comment bool   `statekit:"name=comment"`
	Desc    bool   `statekit:"name=desc"`
	Full    bool   `statekit:"name=full"`
	Depends bool   `statekit:"name=depends"`
	Size    bool   `statekit:"name=size"`
	Quiet   bool   `statekit:"name=quiet"`
	Origin  bool   `statekit:"name=origin"`
	Prefix  bool   `statekit:"name=prefix"`
	Jail    string `statekit:"name=jail"`
	Chroot  string `statekit:"name=chroot"`
	Root    string `statekit:"name=root"`
}

type pkgngSearchFunc struct{}

func (pkgngSearchFunc) Name() string        { return "pkg.search" }
func (pkgngSearchFunc) Args() any           { return PkgngSearchArgs{} }
func (pkgngSearchFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngSearchFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngSearchArgs)
	opts := &strings.Builder{}
	if a.Exact {
		opts.WriteString("e")
	}
	if a.Glob {
		opts.WriteString("g")
	}
	if a.Regex {
		opts.WriteString("x")
	}
	if a.Pcre {
		opts.WriteString("X")
	}
	if a.Comment {
		opts.WriteString("c")
	}
	if a.Desc {
		opts.WriteString("D")
	}
	if a.Full {
		opts.WriteString("f")
	}
	if a.Depends {
		opts.WriteString("d")
	}
	if a.Size {
		opts.WriteString("s")
	}
	if a.Quiet {
		opts.WriteString("q")
	}
	if a.Origin {
		opts.WriteString("o")
	}
	if a.Prefix {
		opts.WriteString("p")
	}
	argv := append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "search")
	if opts.Len() > 0 {
		argv = append(argv, "-"+opts.String())
	}
	argv = append(argv, a.Name)
	res, err := pkgngRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	return string(res.Stdout), nil
}

type PkgngFetchArgs struct {
	Name     string `statekit:"required,name=name"`
	FetchAll bool   `statekit:"name=fetch_all"`
	Quiet    bool   `statekit:"name=quiet"`
	Fromrepo string `statekit:"name=fromrepo"`
	Glob     *bool  `statekit:"name=glob"`
	Regex    bool   `statekit:"name=regex"`
	Pcre     bool   `statekit:"name=pcre"`
	Local    bool   `statekit:"name=local"`
	Depends  bool   `statekit:"name=depends"`
	Jail     string `statekit:"name=jail"`
	Chroot   string `statekit:"name=chroot"`
	Root     string `statekit:"name=root"`
}

type pkgngFetchFunc struct{}

func (pkgngFetchFunc) Name() string        { return "pkg.fetch" }
func (pkgngFetchFunc) Args() any           { return PkgngFetchArgs{} }
func (pkgngFetchFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngFetchFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngFetchArgs)
	glob := true // Salt's fetch(glob=True) default
	if a.Glob != nil {
		glob = *a.Glob
	}
	opts := &strings.Builder{}
	if a.FetchAll {
		opts.WriteString("a")
	}
	if a.Quiet {
		opts.WriteString("q")
	}
	if glob {
		opts.WriteString("g")
	}
	if a.Regex {
		opts.WriteString("x")
	}
	if a.Pcre {
		opts.WriteString("X")
	}
	if a.Local {
		opts.WriteString("L")
	}
	if a.Depends {
		opts.WriteString("d")
	}
	argv := append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "fetch", "-y")
	if a.Fromrepo != "" {
		argv = append(argv, "-r", a.Fromrepo)
	}
	if opts.Len() > 0 {
		argv = append(argv, "-"+opts.String())
	}
	argv = append(argv, a.Name)
	res, err := pkgngRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	return string(res.Stdout), nil
}

type PkgngUpdatingArgs struct {
	Name     string `statekit:"required,name=name"`
	Filedate string `statekit:"name=filedate"`
	Filename string `statekit:"name=filename"`
	Jail     string `statekit:"name=jail"`
	Chroot   string `statekit:"name=chroot"`
	Root     string `statekit:"name=root"`
}

type pkgngUpdatingFunc struct{}

func (pkgngUpdatingFunc) Name() string        { return "pkg.updating" }
func (pkgngUpdatingFunc) Args() any           { return PkgngUpdatingArgs{} }
func (pkgngUpdatingFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngUpdatingFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngUpdatingArgs)
	// The pinned source builds "-d {filedate}" as one shell word; that
	// exact argv shape (flag and value inside one element) is preserved.
	opts := &strings.Builder{}
	if a.Filedate != "" {
		opts.WriteString("d " + a.Filedate)
	}
	if a.Filename != "" {
		opts.WriteString("f " + a.Filename)
	}
	argv := append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "updating")
	if opts.Len() > 0 {
		argv = append(argv, "-"+opts.String())
	}
	argv = append(argv, a.Name)
	res, err := pkgngRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	return string(res.Stdout), nil
}

// ---------------------------------------------------------------------------
// lock/unlock/locked/list_locked via _lockcmd

// pkgngLockCmd mirrors _lockcmd: run lock/unlock -y --quiet --show-locked
// (optionally scoped to one package) and strip the version suffix from
// every reported line. A non-zero exit is the source's
// CommandExecutionError.
func pkgngLockCmd(ctx context.Context, rt *runtime.Runtime, subcmd, pkgname, jail, chroot, root string) ([]string, error) {
	argv := append(pkgngPrefix(jail, chroot, root), subcmd, "-y", "--quiet", "--show-locked")
	if pkgname != "" {
		argv = append(argv, pkgname)
	}
	res, err := pkgngRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("Problem encountered %sing packages (exit %d): %s", subcmd, res.ExitCode, string(res.Stderr))
	}
	locked := []string{}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if line == "" {
			continue
		}
		idx := strings.LastIndex(line, "-")
		if idx < 0 {
			locked = append(locked, line)
			continue
		}
		locked = append(locked, line[:idx])
	}
	return locked, nil
}

func pkgngContains(list []string, name string) bool {
	for _, entry := range list {
		if entry == name {
			return true
		}
	}
	return false
}

type PkgngLockArgs struct {
	Name   string `statekit:"required,name=name"`
	Jail   string `statekit:"name=jail"`
	Chroot string `statekit:"name=chroot"`
	Root   string `statekit:"name=root"`
}

type pkgngLockFunc struct{}

func (pkgngLockFunc) Name() string        { return "pkg.lock" }
func (pkgngLockFunc) Args() any           { return PkgngLockArgs{} }
func (pkgngLockFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngLockFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngLockArgs)
	locked, err := pkgngLockCmd(ctx, rt, "lock", a.Name, a.Jail, a.Chroot, a.Root)
	if err != nil {
		return nil, err
	}
	return pkgngContains(locked, a.Name), nil
}

type pkgngUnlockFunc struct{}

func (pkgngUnlockFunc) Name() string        { return "pkg.unlock" }
func (pkgngUnlockFunc) Args() any           { return PkgngLockArgs{} }
func (pkgngUnlockFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngUnlockFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngLockArgs)
	unlocked, err := pkgngLockCmd(ctx, rt, "unlock", a.Name, a.Jail, a.Chroot, a.Root)
	if err != nil {
		return nil, err
	}
	return !pkgngContains(unlocked, a.Name), nil
}

type PkgngLockedArgs struct {
	Name   string `statekit:"required,name=name"`
	Jail   string `statekit:"name=jail"`
	Chroot string `statekit:"name=chroot"`
	Root   string `statekit:"name=root"`
}

type pkgngLockedFunc struct{}

func (pkgngLockedFunc) Name() string        { return "pkg.locked" }
func (pkgngLockedFunc) Args() any           { return PkgngLockedArgs{} }
func (pkgngLockedFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngLockedFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngLockedArgs)
	locked, err := pkgngLockCmd(ctx, rt, "lock", "", a.Jail, a.Chroot, a.Root)
	if err != nil {
		return nil, err
	}
	return pkgngContains(locked, a.Name), nil
}

type PkgngListLockedArgs struct {
	Jail   string `statekit:"name=jail"`
	Chroot string `statekit:"name=chroot"`
	Root   string `statekit:"name=root"`
}

type pkgngListLockedFunc struct{}

func (pkgngListLockedFunc) Name() string        { return "pkg.list_locked" }
func (pkgngListLockedFunc) Args() any           { return PkgngListLockedArgs{} }
func (pkgngListLockedFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngListLockedFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngListLockedArgs)
	locked, err := pkgngLockCmd(ctx, rt, "lock", "", a.Jail, a.Chroot, a.Root)
	if err != nil {
		return nil, err
	}
	pkgs, _, err := pkgngListPkgsRaw(ctx, rt, a.Jail, a.Chroot, a.Root)
	if err != nil {
		return nil, err
	}
	table := pkgngInstalledTable(pkgs)
	out := []string{}
	for _, name := range locked {
		out = append(out, name+"-"+table[name])
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// hold / unhold

type PkgngHoldArgs struct {
	Name   string `statekit:"name=name"`
	Pkgs   []any  `statekit:"name=pkgs"`
	Jail   string `statekit:"name=jail"`
	Chroot string `statekit:"name=chroot"`
	Root   string `statekit:"name=root"`
}

func pkgngHoldTargets(name string, pkgs []any) []string {
	targets := []string{}
	if len(pkgs) > 0 {
		for _, item := range pkgs {
			if mapping, ok := item.(map[string]any); ok {
				for key := range mapping {
					targets = append(targets, key)
					break
				}
				continue
			}
			targets = append(targets, fmt.Sprint(item))
		}
		return targets
	}
	return append(targets, name)
}

type pkgngHoldFunc struct{}

func (pkgngHoldFunc) Name() string        { return "pkg.hold" }
func (pkgngHoldFunc) Args() any           { return PkgngHoldArgs{} }
func (pkgngHoldFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngHoldFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngHoldArgs)
	targets := pkgngHoldTargets(a.Name, a.Pkgs)
	ret := map[string]any{}
	for _, target := range targets {
		entry := map[string]any{
			"name": target, "changes": map[string]any{}, "result": false, "comment": "",
		}
		lockedList, err := pkgngLockCmd(ctx, rt, "lock", "", a.Jail, a.Chroot, a.Root)
		if err != nil {
			return nil, err
		}
		if !pkgngContains(lockedList, target) {
			if rt.Options.Test {
				entry["result"] = nil
				entry["comment"] = fmt.Sprintf("Package %s is set to be held.", target)
			} else {
				lockList, err := pkgngLockCmd(ctx, rt, "lock", target, a.Jail, a.Chroot, a.Root)
				if err != nil {
					return nil, err
				}
				if pkgngContains(lockList, target) {
					entry["result"] = true
					entry["comment"] = fmt.Sprintf("Package %s is now being held.", target)
					entry["changes"] = map[string]any{"new": "hold", "old": ""}
				} else {
					entry["comment"] = fmt.Sprintf("Package %s was unable to be held.", target)
				}
			}
		} else {
			entry["result"] = true
			entry["comment"] = fmt.Sprintf("Package %s is already set to be held.", target)
		}
		ret[target] = entry
	}
	return ret, nil
}

type pkgngUnholdFunc struct{}

func (pkgngUnholdFunc) Name() string        { return "pkg.unhold" }
func (pkgngUnholdFunc) Args() any           { return PkgngHoldArgs{} }
func (pkgngUnholdFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngUnholdFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngHoldArgs)
	targets := pkgngHoldTargets(a.Name, a.Pkgs)
	ret := map[string]any{}
	for _, target := range targets {
		entry := map[string]any{
			"name": target, "changes": map[string]any{}, "result": false, "comment": "",
		}
		lockedList, err := pkgngLockCmd(ctx, rt, "lock", "", a.Jail, a.Chroot, a.Root)
		if err != nil {
			return nil, err
		}
		if pkgngContains(lockedList, target) {
			if rt.Options.Test {
				entry["result"] = nil
				entry["comment"] = fmt.Sprintf("Package %s is set to be unheld.", target)
			} else {
				unlockList, err := pkgngLockCmd(ctx, rt, "unlock", target, a.Jail, a.Chroot, a.Root)
				if err != nil {
					return nil, err
				}
				if !pkgngContains(unlockList, target) {
					entry["result"] = true
					entry["comment"] = fmt.Sprintf("Package %s is no longer held.", target)
					entry["changes"] = map[string]any{"new": "", "old": "hold"}
				} else {
					entry["comment"] = fmt.Sprintf("Package %s was unable to be unheld.", target)
				}
			}
		} else {
			entry["result"] = true
			entry["comment"] = fmt.Sprintf("Package %s is not being held.", target)
		}
		ret[target] = entry
	}
	return ret, nil
}

// ---------------------------------------------------------------------------
// list_upgrades / _parse_upgrade / version_cmp

type PkgngListUpgradesArgs struct {
	Refresh  *bool  `statekit:"name=refresh"`
	Fromrepo string `statekit:"name=fromrepo"`
	Jail     string `statekit:"name=jail"`
	Chroot   string `statekit:"name=chroot"`
	Root     string `statekit:"name=root"`
}

type pkgngListUpgradesFunc struct{}

func (pkgngListUpgradesFunc) Name() string        { return "pkg.list_upgrades" }
func (pkgngListUpgradesFunc) Args() any           { return PkgngListUpgradesArgs{} }
func (pkgngListUpgradesFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngListUpgradesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngListUpgradesArgs)
	refresh := true
	if a.Refresh != nil {
		refresh = *a.Refresh
	}
	argv := append(pkgngPrefix(a.Jail, a.Chroot, a.Root), "upgrade", "--dry-run", "--quiet")
	if !refresh {
		argv = append(argv, "--no-repo-update")
	}
	if a.Fromrepo != "" {
		argv = append(argv, "--repository", a.Fromrepo)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// ignore_retcode=True in the pinned source: exit codes are data.
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return nil, res.Err
	}
	parsed := pkgngParseUpgrade(string(res.Stdout))
	out := map[string]any{}
	for name, stat := range parsed["upgrade"] {
		entry, _ := stat.(map[string]any)
		if entry == nil {
			continue
		}
		version, _ := entry["version"].(map[string]any)
		if version == nil {
			continue
		}
		out[name] = version["new"]
	}
	return out, nil
}

var (
	pkgngUpgradeRe = regexp.MustCompile(
		`^\s+([^:]+):\s([0-9a-z_,.]+)\s+->\s+([0-9a-z_,.]+)\s*(?:\[([^\]]*)\])?\s*(?:\(([^)]*)\))?`)
	pkgngInstallRe = regexp.MustCompile(
		`^\s+([^:]+):\s+([0-9a-z_,.]+)\s*(?:\[([^\]]*)\])?\s*(?:\(([^)]*)\))?`)
	pkgngReinstallRe = regexp.MustCompile(
		`^\s+(\S+)-([0-9a-z_,.]+)\s*(?:\[([^\]]*)\])?\s*(?:\(([^)]*)\))?`)
)

// pkgngNilable maps an optional capture group to nil when it did not
// participate, mirroring Python's None for unmatched regex groups.
func pkgngNilable(match []int, group int, line string) any {
	start, end := match[group*2], match[group*2+1]
	if start < 0 || end < 0 {
		return nil
	}
	return line[start:end]
}

// pkgngParseUpgrade ports _parse_upgrade: section headers select the
// action, blank lines reset it, and per-action regexes build the
// repo/reason/version records. Unparseable action lines are skipped
// (the source logs an error).
func pkgngParseUpgrade(stdout string) map[string]map[string]any {
	result := map[string]map[string]any{
		"upgrade": {}, "install": {}, "reinstall": {}, "remove": {}, "downgrade": {},
	}
	action := ""
	for _, line := range strings.Split(stdout, "\n") {
		if line == "" {
			action = ""
			continue
		}
		switch line {
		case "Installed packages to be UPGRADED:":
			action = "upgrade"
			continue
		case "New packages to be INSTALLED:":
			action = "install"
			continue
		case "Installed packages to be REINSTALLED:":
			action = "reinstall"
			continue
		case "Installed packages to be REMOVED:":
			action = "remove"
			continue
		case "Installed packages to be DOWNGRADED:":
			action = "downgrade"
			continue
		}
		switch action {
		case "upgrade", "downgrade":
			if match := pkgngUpgradeRe.FindStringSubmatchIndex(line); match != nil {
				result[action][line[match[2]:match[3]]] = map[string]any{
					"version": map[string]any{"current": line[match[4]:match[5]], "new": line[match[6]:match[7]]},
					"repo":    pkgngNilable(match, 4, line),
					"reason":  pkgngNilable(match, 5, line),
				}
			}
		case "install":
			if match := pkgngInstallRe.FindStringSubmatchIndex(line); match != nil {
				result[action][line[match[2]:match[3]]] = map[string]any{
					"version": map[string]any{"current": line[match[4]:match[5]]},
					"repo":    pkgngNilable(match, 3, line),
					"reason":  pkgngNilable(match, 4, line),
				}
			}
		case "reinstall", "remove":
			if match := pkgngReinstallRe.FindStringSubmatchIndex(line); match != nil {
				result[action][line[match[2]:match[3]]] = map[string]any{
					"version": map[string]any{"current": line[match[4]:match[5]]},
					"repo":    pkgngNilable(match, 3, line),
					"reason":  pkgngNilable(match, 4, line),
				}
			}
		}
	}
	return result
}

type PkgngVersionCmpArgs struct {
	Pkg1        string `statekit:"required,name=pkg1"`
	Pkg2        string `statekit:"required,name=pkg2"`
	IgnoreEpoch bool   `statekit:"name=ignore_epoch"`
}

type pkgngVersionCmpFunc struct{}

func (pkgngVersionCmpFunc) Name() string        { return "pkg.version_cmp" }
func (pkgngVersionCmpFunc) Args() any           { return PkgngVersionCmpArgs{} }
func (pkgngVersionCmpFunc) Platforms() []string { return []string{"freebsd"} }
func (pkgngVersionCmpFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkgngVersionCmpArgs)
	// Don't worry about ignore_epoch since we're shelling out to pkg.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// ignore_retcode=True: exit codes are data, only stdout decides.
	res := rt.Runner.Run(ctx, runtime.Command("pkg", "version", "--test-version", a.Pkg1, a.Pkg2))
	if res.Err != nil {
		return nil, res.Err
	}
	switch string(res.Stdout) {
	case "<":
		return -1, nil
	case ">":
		return 1, nil
	case "=":
		return 0, nil
	}
	return nil, nil
}
