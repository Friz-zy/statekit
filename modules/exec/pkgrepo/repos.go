package pkgrepo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// Repository management surface for APT, mirroring the repo functions of
// saltstack/salt/modules/aptpkg.py @ pinned revision. CLI-facing names stay
// pkg.* because aptpkg registers under the virtual "pkg" module name.

// Launchpad source formats from aptpkg.py. del_repo passes its arguments to
// LP_PVT_SRC_FORMAT in a different order than get_repo/mod_repo; the swapped
// positions reproduce upstream verbatim.
const (
	lpSrcFormat    = "deb http://ppa.launchpad.net/%s/%s/ubuntu %s main"
	lpPvtSrcFormat = "deb https://%sprivate-ppa.launchpad.net/%s/%s/ubuntu %s main"
)

// modifyOK mirrors _MODIFY_OK (setattr allow-list for deb822 targets).
var modifyOK = map[string]bool{
	"uri": true, "uris": true, "comps": true, "architectures": true,
	"disabled": true, "file": true, "dist": true, "suites": true,
	"signedby": true, "trusted": true, "types": true,
}

// modifyOKLegacy mirrors _MODIFY_OK_LEGACY (classic entries). Keys outside
// this table are silently skipped by the setattr loop even when the entry
// exposes an attribute of that name.
var modifyOKLegacy = map[string]bool{
	"uri": true, "comps": true, "architectures": true, "disabled": true,
	"file": true, "dist": true, "signedby": true, "trusted": true,
}

var validFileprotoRe = regexp.MustCompile(`^(?:salt|https?|ftp|file)://`)
var schemeRe = regexp.MustCompile(`^(http[s]?://)(.+)`)

// --- injectable hooks -------------------------------------------------------

// whichBin resolves binaries like salt.utils.path.which; injectable.
var whichBin = func(name string) string { return lookPathBin(name) }

// lockSleep backs the dpkg-lock retry backoff; injectable for suites.
var lockSleep = func(seconds int) {}

// fetchLaunchpadPPA mirrors _get_ppa_info_from_launchpad: GET the Launchpad
// API archive record as JSON. Injectable so suites pin parse/error paths;
// HTTP failures surface as launchpadError so callers can reproduce Salt's
// HTTPError-specific handling.
var fetchLaunchpadPPA = func(owner, ppa string) (map[string]any, error) {
	return fetchLaunchpadPPANet(owner, ppa)
}

type launchpadError struct{ status int }

func (e *launchpadError) Error() string {
	reason := map[int]string{400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
		404: "Not Found", 410: "Gone", 500: "Internal Server Error"}[e.status]
	if reason == "" {
		reason = "Error"
	}
	return fmt.Sprintf("HTTP Error %d: %s", e.status, reason)
}

// cacheFile stands in for cp.cache_file: remote schemes surface
// UnsupportedError until the cp family lands (salt:// stays permanently
// excluded); readable absolute local paths pass through unchanged.
var cacheFileHook = func(_ context.Context, _ *runtime.Runtime, path, _ string) (string, error) {
	if validFileprotoRe.MatchString(path) {
		return "", &runtime.UnsupportedError{Kind: "function", Name: "cp.cache_file"}
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("Path %s is neither absolute nor a supported protocol", path)
	}
	return path, nil
}

// configOption resolves optional config.option delegates the way real Salt
// minions provide them; StateKit has no config hierarchy yet, so the default
// reads nothing and callers degrade exactly like minions lacking the module.
var configOption = func(rt *runtime.Runtime, key string) any {
	if _, ok := rt.Exec.Get("config.option"); !ok {
		return nil
	}
	res, err := rt.Exec.Call(context.Background(), rt, "config.option",
		map[string]any{"key": key})
	if err != nil {
		return nil
	}
	return res
}

// grains probes behind hooks so suites can pin Ubuntu-specific branches.
var (
	grainsOSName     = func(rt *runtime.Runtime) string { return rt.Facts.OS().Name }
	grainsOSID       = func(rt *runtime.Runtime) string { return rt.Facts.OS().ID }
	grainsOSCodename = func(rt *runtime.Runtime) string { return rt.Facts.OS().Codename }
	grainsOSRelease  = func(rt *runtime.Runtime) (float64, error) {
		v := rt.Facts.OS().Version
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("could not convert osrelease %q to float", v)
		}
		return f, nil
	}
	isUbuntuLike = func(rt *runtime.Runtime) bool {
		for _, candidate := range []string{grainsOSName(rt), grainsOSID(rt)} {
			switch strings.ToLower(candidate) {
			case "ubuntu", "mint", "neon":
				return true
			}
		}
		return false
	}
)

// callRefreshDB mirrors mod_repo/del_repo calling their module-local
// refresh_db(); StateKit resolves the registered pkg.refresh_db delegate.
func callRefreshDB(ctx context.Context, rt *runtime.Runtime) error {
	if _, ok := rt.Exec.Get("pkg.refresh_db"); !ok {
		return nil
	}
	_, err := rt.Exec.Call(ctx, rt, "pkg.refresh_db", &struct{}{})
	return err
}

// callApt mirrors _call_apt: argv through the central Runner with the
// dpkg-lock retry backoff (upstream logs "%s/100" but caps at ten tries —
// kept verbatim). Upstream wraps commands in systemd-run scopes when
// available; StateKit runs them directly (documented divergence).
func callApt(ctx context.Context, rt *runtime.Runtime, argv []string, stdin []byte) process.CommandResult {
	run := func() process.CommandResult {
		cmd := runtime.Command(argv...)
		cmd.Stdin = stdin
		return rt.Runner.Run(ctx, cmd)
	}
	ret := run()
	count := 0
	for strings.Contains(string(ret.Stderr), "Could not get lock") && count < 10 {
		count++
		lockSleep(1 << count)
		ret = run()
	}
	return ret
}

func lookPathBin(exe string) string {
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(dir + "/" + exe); err == nil {
			return dir + "/" + exe
		}
	}
	return ""
}

// --- shared repo-entry helpers ----------------------------------------------

// repoSource abstracts the attribute view mod_repo/del_repo exercise on
// either entry class (Salt relies on duck typing between SourceEntry and
// Deb822SourceEntry).
type repoSource interface {
	TypeRaw() string      // source.type text
	TypeFields() []string // source.type.split()
	URIsView() []string   // source.uris
	SuitesView() []string // source.suites
	SetSuitesView([]string) error
	CompsView() []string
	SetCompsView([]string)
	ArchitecturesView() []string
	File() string
	InvalidFlag() bool
}

func adapt(source any) repoSource {
	switch s := source.(type) {
	case *sourceEntry:
		return classicAdapter{s}
	case *deb822SourceEntry:
		return d822Adapter{s}
	}
	return nil
}

type classicAdapter struct{ e *sourceEntry }

func (a classicAdapter) TypeRaw() string                { return a.e.typ }
func (a classicAdapter) TypeFields() []string           { return strings.Fields(a.e.typ) }
func (a classicAdapter) URIsView() []string             { return a.e.URIs() }
func (a classicAdapter) SuitesView() []string           { return a.e.Suites() }
func (a classicAdapter) SetSuitesView(v []string) error { return a.e.SetSuites(v) }
func (a classicAdapter) CompsView() []string            { return a.e.comps }
func (a classicAdapter) SetCompsView(v []string)        { a.e.comps = v }
func (a classicAdapter) ArchitecturesView() []string    { return a.e.architectures }
func (a classicAdapter) File() string                   { return a.e.file }
func (a classicAdapter) InvalidFlag() bool              { return a.e.invalid }

type d822Adapter struct{ e *deb822SourceEntry }

func (a d822Adapter) TypeRaw() string {
	t, _ := a.e.Type()
	return t
}
func (a d822Adapter) TypeFields() []string { return strings.Fields(a.TypeRaw()) }
func (a d822Adapter) URIsView() []string   { return a.e.URIs() }
func (a d822Adapter) SuitesView() []string { return a.e.Suites() }
func (a d822Adapter) SetSuitesView(v []string) error {
	a.e.SetSuites(v)
	return nil
}
func (a d822Adapter) CompsView() []string         { return a.e.Comps() }
func (a d822Adapter) SetCompsView(v []string)     { a.e.SetComps(v) }
func (a d822Adapter) ArchitecturesView() []string { return a.e.Architectures() }
func (a d822Adapter) File() string                { return a.e.file }
func (a d822Adapter) InvalidFlag() bool           { return a.e.Invalid() }

// repoEntry mirrors the dict produced by _split_repo_str.
type repoEntry struct {
	invalid       bool
	typ           string
	architectures []string
	uri           string
	dist          string
	comps         []string
	signedby      string
	trusted       *bool
}

// splitRepoStr mirrors _split_repo_str over a classic SourceEntry parse.
func splitRepoStr(repo string) (*repoEntry, error) {
	entry, err := newSourceEntry(repo, "")
	if err != nil {
		return nil, err
	}
	return &repoEntry{
		invalid:       entry.invalid,
		typ:           entry.typ,
		architectures: entry.architectures,
		uri:           entry.uri,
		dist:          entry.dist,
		comps:         entry.comps,
		signedby:      entry.signedby,
		trusted:       entry.trusted,
	}, nil
}

// expandPPARepo rewrites a "ppa:owner/ppa" definition into its Launchpad
// deb line. The swapped variant reproduces del_repo's upstream argument-
// order bug verbatim.
func expandPPARepo(repo string, dist, ppaAuth string, swappedArgs bool) (string, error) {
	parts := strings.Split(repo[4:], "/")
	if len(parts) != 2 {
		return "", fmt.Errorf(
			`Unable to get PPA info from argument. Expected format "<PPA_OWNER>/<PPA_NAME>" (e.g. saltstack/salt) not found.  Received '%s' instead.`,
			repo[4:])
	}
	owner, ppa := parts[0], parts[1]
	authInfo := ""
	if ppaAuth != "" {
		authInfo = ppaAuth + "@"
	}
	if swappedArgs {
		// del_repo formats (auth, DIST, OWNER, PPA); kept verbatim.
		return fmt.Sprintf(lpPvtSrcFormat, authInfo, dist, owner, ppa), nil
	}
	if ppaAuth != "" {
		return fmt.Sprintf(lpPvtSrcFormat, authInfo, owner, ppa, dist), nil
	}
	return fmt.Sprintf(lpSrcFormat, owner, ppa, dist), nil
}

// skipSource mirrors _skip_source. The bracketed-options arm requires an
// entry marked invalid yet carrying URI/type; parsed classic entries never
// reach it (upstream would crash there on its own class), so
// split_source_line fills in deterministically.
func skipSource(source any) (bool, error) {
	var (
		invalid bool
		uri     string
		typ     string
		line    string
	)
	switch s := source.(type) {
	case *sourceEntry:
		invalid, uri, typ, line = s.invalid, s.uri, s.typ, s.line
	case *deb822SourceEntry:
		invalid = s.Invalid()
		typ = d822Adapter{s}.TypeRaw()
		if uris := s.URIs(); len(uris) > 0 {
			uri = uris[0]
		}
		line = s.String()
	default:
		return true, nil
	}
	if !invalid {
		return false, nil
	}
	if uri != "" && typ != "" &&
		(typ == "deb" || typ == "deb-src" || typ == "rpm" || typ == "rpm-src") {
		pieces := splitSourceLine(line)
		if len(pieces) > 1 && strings.HasPrefix(strings.TrimSpace(pieces[1]), "[") {
			options := strings.Fields(strings.Trim(pieces[1], "[]"))
			if len(options) > 0 {
				return false, nil
			}
		}
		return true, nil
	}
	return true, nil
}

// --- pkg.list_repos ----------------------------------------------------------

// listRepos mirrors aptpkg.list_repos: every non-skipped source expands into
// one repo dict per (uri, suite, type) combination, keyed by URI.
func listRepos(rt *runtime.Runtime) (map[string][]map[string]any, error) {
	repos := map[string][]map[string]any{}
	sources := newSourcesList(rt)
	for _, source := range sources.list {
		skip, err := skipSource(source)
		if err != nil {
			return nil, err
		}
		if skip {
			continue
		}
		switch src := source.(type) {
		case *deb822SourceEntry:
			disabled, err := src.Disabled()
			if err != nil {
				return nil, err
			}
			trusted, err := src.Trusted()
			if err != nil {
				return nil, err
			}
			comps := src.Comps()
			types := src.Types()
			uris := src.URIs()
			suites := src.Suites()
			archs := src.Architectures()
			signedby, _ := src.SignedBy()
			for _, uri := range uris {
				for _, suite := range suites {
					for _, stype := range types {
						compatLine := fmt.Sprintf("%s %s %s %s", stype, uri, suite, strings.Join(comps, " "))
						compat, err := newSourceEntry(compatLine, "")
						if err != nil {
							return nil, err
						}
						compat.disabled = disabled
						compat.architectures = append([]string{}, archs...)
						compat.signedby = signedby
						compat.trusted = trusted
						repo := map[string]any{
							"file":          src.file,
							"comps":         comps,
							"disabled":      disabled,
							"enabled":       !disabled,
							"dist":          suite,
							"suites":        suites,
							"type":          stype,
							"types":         types,
							"uri":           uri,
							"uris":          uris,
							"line":          compat.String(),
							"architectures": archs,
							"signedby":      signedByAny(signedby),
						}
						repos[uri] = append(repos[uri], repo)
					}
				}
			}
		case *sourceEntry:
			repo := map[string]any{
				"file":          src.file,
				"comps":         src.comps,
				"disabled":      src.disabled,
				"enabled":       !src.disabled,
				"dist":          src.dist,
				"suites":        src.Suites(),
				"type":          src.typ,
				"types":         src.Types(),
				"uri":           src.uri,
				"uris":          src.URIs(),
				"line":          strings.TrimSpace(src.line),
				"architectures": src.architectures,
				"signedby":      src.signedby,
			}
			repos[src.uri] = append(repos[src.uri], repo)
		}
	}
	return repos, nil
}

func signedByAny(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// --- kwarg helpers -------------------------------------------------------------

func hasKwarg(kwargs map[string]any, key string) bool {
	_, ok := kwargs[key]
	return ok
}

func kwargString(kwargs map[string]any, key string) string {
	if v, ok := kwargs[key].(string); ok {
		return v
	}
	return ""
}

func truthyKwarg(kwargs map[string]any, key string) bool {
	if v, ok := kwargs[key]; ok {
		t, _ := truthyAny(v)
		return t
	}
	return false
}

func commaList(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			out = append(out, scalarString(item))
		}
		return out
	case string:
		var out []string
		for _, part := range strings.Split(x, ",") {
			out = append(out, strings.TrimSpace(part))
		}
		return out
	}
	if v == nil {
		return nil
	}
	return []string{scalarString(v)}
}

// kwargKeyIDs normalizes the keyid kwarg: scalar or list, ints rendered hex
// like upstream's yaml-int fix-up.
func kwargKeyIDs(kwargs map[string]any) []string {
	v, ok := kwargs["keyid"]
	if !ok {
		return nil
	}
	switch items := v.(type) {
	case []any:
		var out []string
		for _, item := range items {
			out = append(out, keyIDString(item))
		}
		return out
	default:
		return []string{keyIDString(v)}
	}
}

func keyIDString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return fmt.Sprintf("%#x", x)
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%#x", int64(x))
		}
	}
	return scalarString(v)
}

// --- pkg.get_repo --------------------------------------------------------------

// getRepo mirrors aptpkg.get_repo including the ppa: expansion and the
// trailing-slash-insensitive match.
func getRepo(rt *runtime.Runtime, repo string, kwargs map[string]any) (map[string]any, error) {
	if kwargs == nil {
		kwargs = map[string]any{}
	}
	ppaAuth := kwargString(kwargs, "ppa_auth")
	if strings.HasPrefix(repo, "ppa:") && isUbuntuLike(rt) {
		var err error
		repo, err = expandPPARepo(repo, grainsOSCodename(rt), ppaAuth, false)
		if err != nil {
			return nil, err
		}
	}

	repos, err := listRepos(rt)
	if err != nil {
		return nil, err
	}
	if len(repos) > 0 {
		entry, err := splitRepoStr(repo)
		if err != nil {
			// At the pinned revision a malformed definition raises
			// SaltInvocationError out of SourceEntry.parse; the surrounding
			// SyntaxError handler is dead code upstream.
			return nil, err
		}
		uri := entry.uri
		if ppaAuth != "" {
			if m := schemeRe.FindStringSubmatch(uri); m != nil && !strings.HasPrefix(m[2], ppaAuth) {
				uri = m[1] + ppaAuth + "@" + m[2]
			}
		}
		for _, subs := range repos {
			for _, sub := range subs {
				subType, _ := sub["type"].(string)
				subURI, _ := sub["uri"].(string)
				subDist, _ := sub["dist"].(string)
				if subType == entry.typ &&
					strings.TrimRight(subURI, "/") == strings.TrimRight(uri, "/") &&
					subDist == entry.dist {
					if len(entry.comps) == 0 {
						return sub, nil
					}
					subComps, _ := sub["comps"].([]string)
					for _, comp := range entry.comps {
						if containsStr(subComps, comp) {
							return sub, nil
						}
					}
				}
			}
		}
	}
	return map[string]any{}, nil
}

func containsStr(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}

// --- pkg.del_repo ---------------------------------------------------------------

// delRepo mirrors aptpkg.del_repo: suite subtraction, comps subtraction, the
// part-file cleanup message, the deb-src PPA cleanup pass, and the
// post-delete refresh.
func delRepo(ctx context.Context, rt *runtime.Runtime, repo string, kwargs map[string]any) (string, error) {
	if kwargs == nil {
		kwargs = map[string]any{}
	}
	isPPA := false
	if strings.HasPrefix(repo, "ppa:") && isUbuntuLike(rt) {
		isPPA = true
		ppaAuth := ""
		if v, ok := kwargs["ppa_auth"]; ok {
			ppaAuth = scalarString(v)
		}
		var err error
		repo, err = expandPPARepo(repo, grainsOSCodename(rt), ppaAuth, true)
		if err != nil {
			return "", err
		}
	}

	sources := newSourcesList(rt)
	type candidate struct {
		src    repoSource
		target any // the underlying entry object, stable across mutations
	}
	var candidates []candidate
	for _, item := range sources.list {
		ad := adapt(item)
		if ad != nil && !ad.InvalidFlag() {
			candidates = append(candidates, candidate{ad, item})
		}
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("Repo %s doesn't exist in the sources.list(s)", repo)
	}

	entry, err := splitRepoStr(repo)
	if err != nil {
		return "", fmt.Errorf("Error: repo '%s' not a well formatted definition", repo)
	}

	type deletion struct {
		file  string
		count int
	}
	var order []string
	deletedFrom := map[string]*deletion{}
	noteDeleted := func(file string) {
		if _, seen := deletedFrom[file]; !seen {
			deletedFrom[file] = &deletion{file: file}
			order = append(order, file)
		}
	}

	matches := func(src repoSource) bool {
		rtrimmed := make([]string, 0, len(src.URIsView()))
		for _, u := range src.URIsView() {
			rtrimmed = append(rtrimmed, strings.TrimRight(u, "/"))
		}
		return containsStr(src.TypeFields(), entry.typ) &&
			equalSlices(src.ArchitecturesView(), entry.architectures) &&
			containsStr(rtrimmed, strings.TrimRight(entry.uri, "/")) &&
			containsStr(src.SuitesView(), entry.dist)
	}

	// removeMatching locates and drops the first entry comparing equal under
	// the class-specific __eq__, mirroring list.remove semantics.
	removeMatching := func(target any) {
		switch t := target.(type) {
		case *sourceEntry:
			for i, item := range sources.list {
				if se, ok := item.(*sourceEntry); ok && se.sameRepo(t) {
					sources.list = append(sources.list[:i], sources.list[i+1:]...)
					return
				}
			}
		case *deb822SourceEntry:
			tDisabled, _ := t.Disabled()
			for i, item := range sources.list {
				d822, ok := item.(*deb822SourceEntry)
				if !ok {
					continue
				}
				eq, err := d822.matchesDisabledTypeURIDistComps(
					tDisabled, mustType(t), t.URIs(), mustDist(t), t.Comps())
				if err == nil && eq {
					sources.list = append(sources.list[:i], sources.list[i+1:]...)
					return
				}
			}
		}
	}

	for _, cand := range candidates {
		src := cand.src
		target := cand.target

		subtractOrDiff := func() (continued bool) {
			sComps := src.CompsView()
			rComps := entry.comps
			exact := equalSets(toSet(sComps), toSet(rComps))
			intersects := setsIntersect(sComps, rComps) || (len(sComps) == 0 && len(rComps) == 0)
			if exact {
				rSuites := make([]string, 0, len(src.SuitesView()))
				for _, s := range src.SuitesView() {
					if s != entry.dist {
						rSuites = append(rSuites, s)
					}
				}
				if err := src.SetSuitesView(rSuites); err != nil {
					return false
				}
				noteDeleted(src.File())
				if len(rSuites) == 0 {
					removeMatching(target)
				}
				sources.save(rt)
				return true
			}
			if intersects {
				keep := make([]string, 0, len(sComps))
				for _, c := range sComps {
					if !containsStr(rComps, c) {
						keep = append(keep, c)
					}
				}
				// Upstream rebuilds through unordered set.difference; this
				// port keeps first-seen component order deterministically.
				src.SetCompsView(keep)
				noteDeleted(src.File())
				if len(keep) == 0 {
					removeMatching(target)
				}
			}
			return false
		}

		if matches(src) {
			if subtractOrDiff() {
				continue
			}
		}
		// PPAs are special and can add deb-src lines whose expanded form
		// differs; upstream cleans those up unconditionally for ppa targets.
		if isPPA && entry.typ == "deb" && src.TypeRaw() == "deb-src" &&
			containsStr(src.URIsView(), entry.uri) && containsStr(src.SuitesView(), entry.dist) {
			if subtractOrDiff() {
				continue
			}
		}
		sources.save(rt)
	}

	if len(deletedFrom) > 0 {
		ret := ""
		for _, item := range sources.list {
			file := ""
			invalid := true
			switch s := item.(type) {
			case *sourceEntry:
				file, invalid = s.file, s.invalid
			case *deb822SourceEntry:
				file, invalid = s.file, s.Invalid()
			}
			if invalid {
				continue
			}
			if d, ok := deletedFrom[file]; ok {
				d.count++
			}
		}
		for _, file := range order {
			d := deletedFrom[file]
			if d.count == 0 && strings.Contains(file, "sources.list.d/") {
				if info, err := rt.FS.Stat(file); err == nil && info.Mode().IsRegular() {
					rt.FS.Remove(file)
					ret += fmt.Sprintf("File %s containing repo '%s' has been removed.", file, repo)
					continue
				}
			}
			ret += fmt.Sprintf("Repo '%s' has been removed from %s.\n", repo, file)
		}
		if err := callRefreshDB(ctx, rt); err != nil {
			return ret, err
		}
		return ret, nil
	}

	return "", fmt.Errorf("Repo %s doesn't exist in the sources.list(s)", repo)
}

func mustType(e *deb822SourceEntry) string {
	t, _ := e.Type()
	return t
}

func mustDist(e *deb822SourceEntry) string {
	d, _ := e.Dist()
	return d
}

func toSet(items []string) map[string]bool {
	set := map[string]bool{}
	for _, i := range items {
		set[i] = true
	}
	return set
}

func setsIntersect(a, b []string) bool {
	bs := toSet(b)
	for _, item := range a {
		if bs[item] {
			return true
		}
	}
	return false
}

// --- pkg.mod_repo -----------------------------------------------------------------

// modRepo mirrors aptpkg.mod_repo: kwargs-driven repo creation/modification
// across classic and deb822 layouts, with the key-management side doors.
func modRepo(ctx context.Context, rt *runtime.Runtime, repo, saltenv string, aptkey bool, kwargs map[string]any) (map[string]any, error) {
	if kwargs == nil {
		kwargs = map[string]any{}
	}
	refresh := true
	if v, ok := kwargs["refresh_db"]; ok {
		refresh = isTrue(v)
	} else if v, ok := kwargs["refresh"]; ok {
		refresh = isTrue(v)
	}

	if whichBin("apt-key") == "" {
		aptkey = false
	}

	if strings.HasPrefix(repo, "ppa:") {
		if !isUbuntuLike(rt) {
			return nil, fmt.Errorf("cannot parse \"ppa:\" style repo definitions: %s", repo)
		}
		if whichBin("apt-add-repository") != "" {
			if _, hasAuth := kwargs["ppa_auth"]; !hasAuth {
				info, err := getRepo(rt, repo, nil)
				if err != nil {
					return nil, err
				}
				if len(info) > 0 {
					return map[string]any{repo: info}, nil
				}
				cmd := []string{"apt-add-repository", "-y", repo}
				if release, relErr := grainsOSRelease(rt); relErr == nil && release < 12.04 {
					cmd = []string{"apt-add-repository", repo}
				} else if relErr != nil {
					return nil, relErr
				}
				out := callApt(ctx, rt, cmd, nil)
				if out.ExitCode != 0 {
					return nil, fmt.Errorf(
						"Unable to add PPA '%s'. '%s' exited with status %d: '%s'",
						repo[4:], pyArgvRepr(cmd), out.ExitCode, string(out.Stderr))
				}
				if refresh {
					if err := callRefreshDB(ctx, rt); err != nil {
						return nil, err
					}
				}
				return map[string]any{repo: resultToMap(out)}, nil
			}
		}
		// urllib-style fallback through the Launchpad API.
		ppaAuth := kwargString(kwargs, "ppa_auth")
		newRepo, xerr := expandPPARepo(repo, grainsOSCodename(rt), ppaAuth, false)
		if xerr != nil {
			return nil, xerr
		}
		parts := strings.Split(repo[4:], "/")
		owner, ppa := parts[0], parts[1]
		dist := grainsOSCodename(rt)
		kwargs["dist"] = dist
		if _, hasFile := kwargs["file"]; !hasFile {
			kwargs["file"] = fmt.Sprintf("/etc/apt/sources.list.d/%s-%s-%s.list", owner, ppa, dist)
		}
		lpInfo, lpErr := fetchLaunchpadPPA(owner, ppa)
		if lpErr != nil {
			var le *launchpadError
			if errors.As(lpErr, &le) {
				return nil, fmt.Errorf("Launchpad does not know about %s/%s: %s", owner, ppa, lpErr.Error())
			}
			return nil, lpErr
		}
		fingerprintRaw, hasFingerprint := lpInfo["signing_key_fingerprint"]
		fingerprint, _ := fingerprintRaw.(string)
		if !hasFingerprint || fingerprint == "" {
			return nil, fmt.Errorf(
				"Launchpad knows about %s/%s but did not return a fingerprint. Please set keyid manually: list index out of range",
				owner, ppa)
		}
		if _, hasAuth := kwargs["ppa_auth"]; !hasAuth {
			kwargs["keyid"] = fingerprint
		} else if _, hasKeyid := kwargs["keyid"]; !hasKeyid {
			return nil, fmt.Errorf("Private PPAs require a keyid to be specified: %s/%s", owner, ppa)
		}
		if _, hasKeyserver := kwargs["keyserver"]; !hasKeyserver {
			kwargs["keyserver"] = "keyserver.ubuntu.com"
		}
		if _, hasAuth := kwargs["ppa_auth"]; hasAuth {
			private := false
			if v, ok := lpInfo["private"].(bool); ok {
				private = v
			}
			if !private {
				return nil, fmt.Errorf("PPA is not private but auth credentials passed: %s", repo)
			}
		}
		repo = newRepo
	}

	sources := newSourcesList(rt)
	if truthyKwarg(kwargs, "consolidate") {
		sources = consolidateRepoSources(rt, sources)
	}

	var repos []any
	for _, source := range sources.list {
		if d822, ok := source.(*deb822SourceEntry); ok {
			types := d822.Types()
			rawType, _ := d822.Type()
			if equalSlices(types, []string{""}) || len(types) == 0 || rawType == "" {
				continue
			}
		} else if se, ok := source.(*sourceEntry); ok {
			if se.invalid {
				continue
			}
		}
		repos = append(repos, source)
	}

	entry, err := splitRepoStr(repo)
	if err != nil {
		return nil, fmt.Errorf("Error: repo '%s' not a well formatted definition", repo)
	}
	if entry.invalid {
		return nil, fmt.Errorf(
			"Name %s is not valid. This must be the complete repo entry as seen in the sources file", repo)
	}

	fullCompList := make([]string, 0, len(entry.comps))
	for _, comp := range entry.comps {
		fullCompList = append(fullCompList, strings.TrimSpace(comp))
	}

	noProxyVal := configOption(rt, "no_proxy")

	signedbyPath := entry.signedby
	kwargs["signedby"] = signedbyPath

	// Key management side doors, evaluated in Salt's order.
	switch {
	case hasKwarg(kwargs, "keyid"):
		keyIDs := kwargKeyIDs(kwargs)
		keyserver := kwargString(kwargs, "keyserver")
		if len(keyIDs) == 0 || keyserver == "" {
			return nil, errors.New("both keyserver and keyid options required.")
		}
		for _, key := range keyIDs {
			imported := false
			if !aptkey {
				output, kerr := getRepoKeysInternal(ctx, rt, false, filepath.Dir(orDot(signedbyPath)))
				if kerr != nil {
					return nil, kerr
				}
				if m, ok := output.(map[string]map[string]any); ok {
					_, imported = m[key]
				}
			} else {
				out := callApt(ctx, rt, []string{"apt-key", "export", key}, nil)
				imported = strings.HasPrefix(string(out.Stdout), "-----BEGIN PGP")
			}
			if !imported {
				httpProxyURL := httpProxyURL(rt)
				if httpProxyURL != "" && !noProxyContains(noProxyVal, keyserver) {
					// Upstream builds this proxy variant regardless of the
					// aptkey flag; ported verbatim.
					_ = callApt(ctx, rt, []string{"apt-key", "adv", "--batch",
						"--keyserver-options", "http-proxy=" + httpProxyURL,
						"--keyserver", keyserver,
						"--logger-fd", "1",
						"--recv-keys", key}, nil)
				} else if !aptkey {
					ok, aerr := addRepoKeyInternal(ctx, rt, addRepoKeyRequest{
						keyid:     key,
						keyserver: keyserver,
						aptkey:    false,
						keydir:    filepath.Dir(orDot(signedbyPath)),
						keyfile:   signedbyPath,
					})
					if aerr != nil {
						return nil, aerr
					}
					if !ok {
						return nil, fmt.Errorf("Error: Could not add key: %s", key)
					}
				} else {
					ret := callApt(ctx, rt, []string{"apt-key", "adv", "--batch",
						"--keyserver", keyserver,
						"--logger-fd", "1",
						"--recv-keys", key}, nil)
					if ret.ExitCode != 0 {
						return nil, fmt.Errorf("Error: key retrieval failed: %s", string(ret.Stdout))
					}
				}
			}
		}
	case hasKwarg(kwargs, "key_url"):
		keyURL := kwargString(kwargs, "key_url")
		cached, cerr := cacheFileHook(ctx, rt, keyURL, saltenv)
		if cerr != nil {
			return nil, cerr
		}
		if cached == "" {
			return nil, fmt.Errorf("Error: file not found: %s", keyURL)
		}
		if signedbyPath != "" && filepath.Base(cached) != filepath.Base(signedbyPath) {
			newPath := filepath.Join(filepath.Dir(cached), filepath.Base(signedbyPath))
			if err := rt.FS.Rename(cached, newPath); err != nil {
				return nil, err
			}
			cached = newPath
		}
		if !aptkey {
			req := addRepoKeyRequest{path: cached, aptkey: false}
			if signedbyPath != "" {
				req.keydir = filepath.Dir(signedbyPath)
			}
			ok, aerr := addRepoKeyInternal(ctx, rt, req)
			if aerr != nil {
				return nil, aerr
			}
			if !ok {
				return nil, fmt.Errorf("Error: Could not add key: %s", cached)
			}
		} else {
			out := callApt(ctx, rt, []string{"apt-key", "add", cached}, nil)
			if !strings.HasPrefix(strings.ToUpper(string(out.Stdout)), "OK") {
				return nil, fmt.Errorf("Error: failed to add key from %s", keyURL)
			}
		}
	case hasKwarg(kwargs, "key_text"):
		keyText := scalarString(kwargs["key_text"])
		out := callApt(ctx, rt, []string{"apt-key", "add", "-"}, []byte(keyText))
		if !strings.HasPrefix(strings.ToUpper(string(out.Stdout)), "OK") {
			return nil, fmt.Errorf("Error: failed to add key:\n%s", keyText)
		}
	}

	if compsRaw, ok := kwargs["comps"]; ok {
		userComps := commaList(compsRaw)
		kwargs["comps"] = userComps
		for _, comp := range userComps {
			if !containsStr(fullCompList, comp) {
				fullCompList = append(fullCompList, comp)
			}
		}
	} else {
		kwargs["comps"] = append([]string{}, fullCompList...)
	}

	if archRaw, ok := kwargs["architectures"]; ok {
		kwargs["architectures"] = commaList(archRaw)
	} else {
		kwargs["architectures"] = append([]string{}, entry.architectures...)
	}

	if v, ok := kwargs["disabled"]; ok {
		kwargs["disabled"] = isTrue(v)
	} else if v, ok := kwargs["enabled"]; ok {
		kwargs["disabled"] = !isTrue(v)
	}

	kwType, hasKwType := kwargs["type"].(string)
	kwDist, hasKwDist := kwargs["dist"].(string)

	var modSource any
	for _, aptSource := range repos {
		src := adapt(aptSource)
		rtrimmed := make([]string, 0, len(src.URIsView()))
		for _, u := range src.URIsView() {
			rtrimmed = append(rtrimmed, strings.TrimRight(u, "/"))
		}
		repoMatches := containsStr(src.TypeFields(), entry.typ) &&
			containsStr(rtrimmed, strings.TrimRight(entry.uri, "/")) &&
			containsStr(src.SuitesView(), entry.dist)
		kwMatches := hasKwDist && containsStr(src.SuitesView(), kwDist) &&
			hasKwType && containsStr(src.TypeFields(), kwType)

		if repoMatches || kwMatches {
			sourceComps := src.CompsView()
			for _, comp := range fullCompList {
				if containsStr(sourceComps, comp) {
					modSource = aptSource
				}
			}
			if len(sourceComps) == 0 {
				modSource = aptSource
			}
			kwArchs, _ := kwargs["architectures"].([]string)
			if !equalSlices(kwArchs, src.ArchitecturesView()) {
				modSource = aptSource
			}
			if modSource != nil {
				break
			}
		}
	}

	if commentsRaw, ok := kwargs["comments"]; ok {
		kwargs["comments"] = combineComments(commentsRaw)
	}

	repoSourceEntry, err := newSourceEntry(repo, "")
	if err != nil {
		return nil, err
	}

	if modSource == nil {
		trustedTruthy, terr := stringToBoolKwarg(kwargs)
		if terr != nil {
			return nil, terr
		}
		if !aptkey && signedbyPath == "" && !trustedTruthy {
			return nil, errors.New("missing 'signedby' or 'trusted' option when apt-key is missing")
		}

		aptSourceFile := kwargString(kwargs, "file")
		if strings.HasSuffix(aptSourceFile, ".sources") {
			section := &deb822Section{}
			section.set("Types", entry.typ)
			section.set("URIs", entry.uri)
			section.set("Suites", entry.dist)
			section.set("Components", strings.Join(entry.comps, " "))
			trustedKwargs := false
			if b, ok := kwargs["trusted"].(bool); ok && b {
				trustedKwargs = true
			}
			if b, ok := kwargs["Trusted"].(bool); ok && b {
				trustedKwargs = true
			}
			entryTrustedTrue := entry.trusted != nil && *entry.trusted
			if trustedKwargs || (!hasKwarg(kwargs, "trusted") && entryTrustedTrue) {
				section.set("Trusted", "yes")
			}
			modSource = newDeb822SourceEntryFromSection(section, aptSourceFile)
		} else {
			se, serr := newSourceEntry(repo, aptSourceFile)
			if serr != nil {
				return nil, serr
			}
			modSource = se
		}
		if commentsVal, ok := kwargs["comments"]; ok {
			setComment(modSource, combineComments(commentsVal))
		}
		sources.list = append(sources.list, modSource)
	} else if commentsVal, ok := kwargs["comments"]; ok {
		setComment(modSource, combineComments(commentsVal))
	}

	if se, ok := modSource.(*sourceEntry); ok {
		se.line = repoSourceEntry.line
		if !strings.HasSuffix(se.line, "\n") {
			se.line += "\n"
		}
	}

	if kwArchs, _ := kwargs["architectures"].([]string); len(kwArchs) == 0 && entryArchEmpty(modSource) {
		delete(kwargs, "architectures")
	}

	// Snapshot iteration order for determinism: Go maps randomize while the
	// upstream dict preserves insertion order.
	for _, key := range sortedKeys(kwargs) {
		val := kwargs[key]
		if err := applyModify(modSource, key, val); err != nil {
			return nil, err
		}
	}

	if se, ok := modSource.(*sourceEntry); ok {
		if se.uri != entry.uri {
			se.uri = entry.uri
			se.line = se.String()
		}
	}

	sources.save(rt)
	if refresh {
		if err := callRefreshDB(ctx, rt); err != nil {
			return nil, err
		}
	}

	info, err := getRepo(rt, repo, nil)
	if err != nil {
		return nil, err
	}
	return map[string]any{repo: info}, nil
}

func orDot(p string) string {
	if p == "" {
		return "."
	}
	return p
}

// sortedKeys returns map keys in insertion-stable sorted order.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	return keys
}

func sortStrings(items []string) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j] < items[j-1]; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

// stringToBoolKwarg evaluates string_to_bool(kwargs.get("trusted", "no")),
// which raises for garbage scalars exactly like upstream.
func stringToBoolKwarg(kwargs map[string]any) (bool, error) {
	raw, has := kwargs["trusted"]
	if !has {
		raw = "no"
	}
	switch v := raw.(type) {
	case bool:
		return v, nil
	case string:
		return stringToBool(v)
	default:
		return stringToBool(scalarString(raw))
	}
}

func entryArchEmpty(modSource any) bool {
	switch s := modSource.(type) {
	case *sourceEntry:
		return len(s.architectures) == 0
	case *deb822SourceEntry:
		return len(s.Architectures()) == 0
	}
	return true
}

func setComment(modSource any, comment string) {
	switch s := modSource.(type) {
	case *sourceEntry:
		s.comment = comment
	case *deb822SourceEntry:
		s.SetComment(comment)
	}
}

// applyModify mirrors the _MODIFY_OK/_MODIFY_OK_LEGACY setattr loop. Keys
// outside the per-class allow-list are skipped even when an attribute of
// that name exists (upstream guards on the tables before hasattr).
func applyModify(modSource any, key string, val any) error {
	switch s := modSource.(type) {
	case *deb822SourceEntry:
		if !modifyOK[key] {
			return nil
		}
		switch key {
		case "uri":
			s.section.set("URIs", scalarString(val))
		case "uris":
			s.SetURIs(commaList(val))
		case "comps":
			s.SetComps(commaList(val))
		case "architectures":
			s.SetArchitectures(commaList(val))
		case "disabled":
			b, _ := val.(bool)
			s.SetDisabled(b)
		case "file":
			s.file = scalarString(val)
		case "dist":
			s.section.set("Suites", scalarString(val))
		case "suites":
			s.SetSuites(commaList(val))
		case "signedby":
			s.SetSignedBy(scalarString(val))
		case "trusted":
			if err := s.SetTrusted(val); err != nil {
				return err
			}
		case "types":
			s.SetTypes(commaList(val))
		}
		return nil
	case *sourceEntry:
		if !modifyOKLegacy[key] {
			return nil
		}
		switch key {
		case "uri":
			s.uri = scalarString(val)
		case "comps":
			s.comps = commaList(val)
		case "architectures":
			s.architectures = commaList(val)
		case "disabled":
			b, _ := val.(bool)
			s.disabled = b
		case "file":
			s.file = scalarString(val)
		case "dist":
			s.dist = scalarString(val)
		case "signedby":
			s.signedby = scalarString(val)
		case "trusted":
			b, err := coerceTrusted(val)
			if err != nil {
				return err
			}
			s.trusted = b
		}
		return nil
	}
	return nil
}

// noProxyContains evaluates `keyserver not in no_proxy` for string or list
// config values.
func noProxyContains(noProxy any, keyserver string) bool {
	switch v := noProxy.(type) {
	case nil:
		return false
	case string:
		return strings.Contains(v, keyserver)
	case []any:
		for _, item := range v {
			if scalarString(item) == keyserver {
				return true
			}
		}
		return false
	}
	return strings.Contains(scalarString(noProxy), keyserver)
}

// httpProxyURL mirrors _get_http_proxy_url over config.option delegates.
func httpProxyURL(rt *runtime.Runtime) string {
	host := optText(configOption(rt, "proxy_host"))
	port := optText(configOption(rt, "proxy_port"))
	username := optText(configOption(rt, "proxy_username"))
	password := optText(configOption(rt, "proxy_password"))
	if host == "" || port == "" {
		return ""
	}
	if username != "" && password != "" {
		return fmt.Sprintf("http://%s:%s@%s:%s", username, password, host, port)
	}
	return fmt.Sprintf("http://%s:%s", host, port)
}

func optText(v any) string {
	if v == nil {
		return ""
	}
	return scalarString(v)
}

// resultToMap renders a CommandResult like Salt's cmd.run_all dict.
func resultToMap(res process.CommandResult) map[string]any {
	return map[string]any{
		"pid":     nil,
		"retcode": res.ExitCode,
		"stdout":  string(res.Stdout),
		"stderr":  string(res.Stderr),
	}
}

// pyArgvRepr renders argv the way Python str(list) does inside error text.
func pyArgvRepr(argv []string) string {
	quoted := make([]string, 0, len(argv))
	for _, arg := range argv {
		q := arg
		if strings.Contains(q, `'`) && !strings.Contains(q, `"`) {
			q = `"` + q + `"`
		} else {
			q = "'" + strings.ReplaceAll(q, `\`, `\\`) + "'"
		}
		quoted = append(quoted, q)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// consolidateRepoSources mirrors _consolidate_repo_sources: dedupe entries
// onto sources.list, union their comps, drop the part files. Upstream unions
// through unordered sets; this port keeps first-seen component order.
func consolidateRepoSources(rt *runtime.Runtime, sources *sourcesList) *sourcesList {
	type keyStruct struct {
		architectures string
		disabled      bool
		typ           string
		uri           string
		dist          string
	}
	var keyOrder []keyStruct
	consolidated := map[keyStruct]*sourceEntry{}
	deleteFiles := map[string]bool{}

	for _, item := range sources.list {
		se, ok := item.(*sourceEntry)
		if !ok || se.invalid {
			continue
		}
		key := keyStruct{
			architectures: strings.Join(se.architectures, ","),
			disabled:      se.disabled,
			typ:           se.typ,
			uri:           se.uri,
			dist:          se.dist,
		}
		if existing, seen := consolidated[key]; seen {
			merged := append([]string{}, existing.comps...)
			for _, c := range se.comps {
				if !containsStr(merged, c) {
					merged = append(merged, c)
				}
			}
			existing.comps = merged
		} else {
			clone, err := newSourceEntry(se.line, "")
			if err != nil {
				continue
			}
			consolidated[key] = clone
			keyOrder = append(keyOrder, key)
		}
		if se.file != aptSourcesList {
			deleteFiles[se.file] = true
		}
	}

	sources.list = nil
	for _, key := range keyOrder {
		sources.list = append(sources.list, consolidated[key])
	}
	sources.save(rt)
	for file := range deleteFiles {
		rt.FS.Remove(file)
	}
	return sources
}

// expandRepoDef mirrors _expand_repo_def, the pkgrepo-state comparison
// helper. Private in Salt (loader-hidden underscore name); ported as an
// internal function consumed by the state module in a later phase.
func expandRepoDef(rt *runtime.Runtime, osName, osCodename string, kwargs map[string]any) (map[string]any, error) {
	repoRaw, hasRepo := kwargs["repo"]
	if !hasRepo {
		return nil, errors.New("missing 'repo' argument")
	}
	repoStr := scalarString(repoRaw)
	if strings.HasPrefix(repoStr, "ppa:") && ubuntuLikeName(osName) {
		parts := strings.Split(repoStr[4:], "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("Unable to expand PPA definition: %s", repoStr[4:])
		}
		owner, ppa := parts[0], parts[1]
		ppaAuth := kwargString(kwargs, "ppa_auth")
		authInfo := ""
		if ppaAuth != "" {
			authInfo = ppaAuth + "@"
		}
		if ppaAuth != "" {
			repoStr = fmt.Sprintf(lpPvtSrcFormat, authInfo, owner, ppa, osCodename)
		} else {
			repoStr = fmt.Sprintf(lpSrcFormat, owner, ppa, osCodename)
		}
		if _, hasFile := kwargs["file"]; !hasFile {
			kwargs["file"] = fmt.Sprintf("/etc/apt/sources.list.d/%s-%s-%s.list", owner, ppa, osCodename)
		}
	}

	sourceEntryObj, err := newSourceEntry(repoStr, "")
	if err != nil {
		return nil, err
	}
	for _, listKey := range []string{"architectures", "comps"} {
		if raw, ok := kwargs[listKey].(string); ok {
			kwargs[listKey] = commaList(raw)
		}
	}
	for _, legacyKey := range []string{"uri", "comps", "architectures", "disabled", "file", "dist", "signedby", "trusted"} {
		val, present := kwargs[legacyKey]
		if !present {
			continue
		}
		switch legacyKey {
		case "uri":
			sourceEntryObj.uri = scalarString(val)
		case "comps":
			sourceEntryObj.comps = commaList(val)
		case "architectures":
			sourceEntryObj.architectures = commaList(val)
		case "disabled":
			sourceEntryObj.disabled = isTrue(val)
		case "file":
			sourceEntryObj.file = scalarString(val)
		case "dist":
			sourceEntryObj.dist = scalarString(val)
		case "signedby":
			sourceEntryObj.signedby = scalarString(val)
		case "trusted":
			b, terr := coerceTrusted(val)
			if terr != nil {
				return nil, terr
			}
			sourceEntryObj.trusted = b
		}
	}

	sourceList := newSourcesList(rt)
	classic, d822, aerr := sourceList.add(
		sourceEntryObj.typ,
		sourceEntryObj.uri,
		sourceEntryObj.dist,
		sourceEntryObj.comps,
		"",
		-1,
		kwargString(kwargs, "file"),
		sourceEntryObj.architectures,
		sourceEntryObj.signedby,
		nil,
		false,
		nil,
		nil,
		nil,
	)
	if aerr != nil {
		return nil, aerr
	}

	if d822 != nil {
		d822.SetDisabled(sourceEntryObj.disabled)
		sb, _ := d822.SignedBy()
		return map[string]any{
			"file":          d822.file,
			"comps":         d822.Comps(),
			"disabled":      mustDisabledD822(d822),
			"dist":          mustDist(d822),
			"suites":        d822.Suites(),
			"type":          mustType(d822),
			"types":         d822.Types(),
			"uri":           firstURI(d822),
			"uris":          d822.URIs(),
			"line":          d822.String(),
			"architectures": d822.Architectures(),
			"signedby":      signedByAny(sb),
		}, nil
	}

	classic.disabled = sourceEntryObj.disabled
	classic.line = classic.RepoLine()
	return map[string]any{
		"file":          classic.file,
		"comps":         classic.comps,
		"disabled":      classic.disabled,
		"dist":          classic.dist,
		"suites":        classic.Suites(),
		"type":          classic.typ,
		"types":         classic.Types(),
		"uri":           classic.uri,
		"uris":          classic.URIs(),
		"line":          classic.String(),
		"architectures": classic.architectures,
		"signedby":      classic.signedby,
	}, nil
}

func ubuntuLikeName(name string) bool {
	switch strings.ToLower(name) {
	case "ubuntu", "mint", "neon":
		return true
	}
	return false
}

func mustDisabledD822(e *deb822SourceEntry) bool {
	d, err := e.Disabled()
	if err != nil {
		return false
	}
	return d
}

func firstURI(e *deb822SourceEntry) string {
	if uris := e.URIs(); len(uris) > 0 {
		return uris[0]
	}
	return ""
}
