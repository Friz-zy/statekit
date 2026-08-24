package pkgrepo

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// yum/dnf repository management, mirroring the repo functions of
// saltstack/salt/modules/yumpkg.py @ pinned revision.

type yumRepoSection struct {
	name     string
	options  []kvPair // lowercased keys, insertion order preserved
	comments []string
}

func (s *yumRepoSection) get(key string) (string, bool) {
	lower := strings.ToLower(key)
	for _, kv := range s.options {
		if kv.key == lower {
			return kv.value, true
		}
	}
	return "", false
}

func (s *yumRepoSection) set(key, value string) {
	lower := strings.ToLower(key)
	for i := range s.options {
		if s.options[i].key == lower {
			s.options[i].value = value
			return
		}
	}
	s.options = append(s.options, kvPair{lower, value})
}

func (s *yumRepoSection) delete(key string) {
	lower := strings.ToLower(key)
	for i := range s.options {
		if s.options[i].key == lower {
			s.options = append(s.options[:i], s.options[i+1:]...)
			return
		}
	}
}

type yumRepoFile struct {
	header   string
	sections []yumRepoSection
}

// parseYumRepoFile mirrors _parse_repo_file: configparser view plus the
// comment-extraction pass. MissingSectionHeaderError yields the empty
// ("", {}) pair instead of an error, exactly like upstream.
func parseYumRepoFile(rt *runtime.Runtime, filename string, strict bool) (*yumRepoFile, error) {
	data, err := rt.FS.ReadFile(filename)
	if err != nil {
		// configparser.read() silently skips unreadable files.
		return &yumRepoFile{}, nil
	}
	cfg, perr := parseConfigparser(string(data), strict)
	if perr != nil {
		if _, ok := perr.(*missingSectionHeaderError); ok {
			return &yumRepoFile{}, nil
		}
		return nil, perr
	}

	file := &yumRepoFile{}
	for _, sec := range cfg.sections {
		file.sections = append(file.sections,
			yumRepoSection{name: sec.name, options: append([]kvPair{}, sec.options...)})
	}

	// Single comment pass over the raw text: comments before the first
	// stanza become the header; later ones attach to their stanza when it
	// exists in the parsed view (upstream swallows stray-section KeyErrors).
	lead := []string{}
	current := ""
	seenSection := false
	for _, rawLine := range splitLinesKeep(string(data)) {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") && len(line) > 1 {
			seenSection = true
			current = line[1 : len(line)-1]
			continue
		}
		if !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, ";") {
			continue
		}
		if !seenSection {
			lead = append(lead, line)
			continue
		}
		text := strings.TrimLeft(strings.TrimLeft(line, "#;"), " ")
		for i := range file.sections {
			if file.sections[i].name == current {
				file.sections[i].comments = append(file.sections[i].comments, text)
				break
			}
		}
	}
	file.header = strings.Join(lead, "\n")
	return file, nil
}

// toAnyDict renders a section as the plain option map upstream hands back,
// optionally with the comments list attached.
func toAnyDict(sec *yumRepoSection, withComments bool) map[string]any {
	out := map[string]any{}
	for _, kv := range sec.options {
		out[kv.key] = kv.value
	}
	if withComments && len(sec.comments) > 0 {
		out["comments"] = append([]string{}, sec.comments...)
	}
	return out
}

func (f *yumRepoFile) find(name string) *yumRepoSection {
	for i := range f.sections {
		if f.sections[i].name == name {
			return &f.sections[i]
		}
	}
	return nil
}

// yumListRepos mirrors list_repos across the configured basedirs; later
// directories override earlier same-name stanzas like upstream's dict
// assignment.
func yumListRepos(rt *runtime.Runtime, basedir any, strict bool) (map[string]any, error) {
	basedirs, err := normalizeYumBasedir(rt, basedir, strict)
	if err != nil {
		return nil, err
	}
	repos := map[string]any{}
	for _, bdir := range basedirs {
		info, serr := rt.FS.Stat(bdir)
		if serr != nil || !info.IsDir() {
			continue
		}
		entries, rerr := rt.FS.ReadDir(bdir)
		if rerr != nil {
			continue
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		sort.Strings(names)
		for _, name := range names {
			if !strings.HasSuffix(name, ".repo") {
				continue
			}
			repopath := fmt.Sprintf("%s/%s", bdir, name)
			file, ferr := parseYumRepoFile(rt, repopath, strict)
			if ferr != nil {
				return nil, ferr
			}
			for i := range file.sections {
				repo := toAnyDict(&file.sections[i], true)
				repo["file"] = repopath
				repos[file.sections[i].name] = repo
			}
		}
	}
	return repos, nil
}

// renderOptionValue re-indents multiline values so the written line stays
// one logical entry, matching both upstream writers.
func renderOptionValue(value string) string {
	if strings.Contains(value, "\n") {
		return strings.Join(strings.Split(value, "\n"), "\n ")
	}
	return value
}

func boolToYumString(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// yumGetRepo mirrors get_repo: copr expansion plus the per-file rescan.
func yumGetRepo(rt *runtime.Runtime, repo string, basedir any, strict bool) (map[string]any, error) {
	if strings.HasPrefix(repo, "copr:") {
		repo = getCoprRepo(repo)
	}
	repos, err := yumListRepos(rt, basedir, strict)
	if err != nil {
		return nil, err
	}
	repofile := ""
	for name, value := range repos {
		if name == repo {
			dict := value.(map[string]any)
			repofile, _ = dict["file"].(string)
		}
	}
	if repofile == "" {
		return map[string]any{}, nil
	}
	file, err := parseYumRepoFile(rt, repofile, strict)
	if err != nil {
		return nil, err
	}
	sec := file.find(repo)
	if sec == nil {
		return map[string]any{}, nil
	}
	return toAnyDict(sec, true), nil
}

// yumDelRepo mirrors del_repo including the three message shapes.
func yumDelRepo(_ context.Context, rt *runtime.Runtime, repo string, basedir any, strict bool) (string, error) {
	if strings.HasPrefix(repo, "copr:") {
		repo = getCoprRepo(repo)
	}
	basedirs, err := normalizeYumBasedir(rt, basedir, strict)
	if err != nil {
		return "", err
	}
	repos, err := yumListRepos(rt, basedirs, strict)
	if err != nil {
		return "", err
	}
	if _, exists := repos[repo]; !exists {
		return fmt.Sprintf("Error: the %s repo does not exist in %s", repo, pyListRepr(basedirs)), nil
	}

	repofile := ""
	for name, value := range repos {
		if name == repo {
			dict := value.(map[string]any)
			repofile, _ = dict["file"].(string)
		}
	}

	onlyrepo := true
	for name, value := range repos {
		if name == repo {
			continue
		}
		dict := value.(map[string]any)
		if f, _ := dict["file"].(string); f == repofile {
			onlyrepo = false
		}
	}

	if onlyrepo {
		rt.FS.Remove(repofile)
		return fmt.Sprintf("File %s containing repo %s has been removed", repofile, repo), nil
	}

	file, err := parseYumRepoFile(rt, repofile, strict)
	if err != nil {
		return "", err
	}
	content := file.header
	for i := range file.sections {
		sec := &file.sections[i]
		if sec.name == repo {
			continue
		}
		comments := combineRpmComments(sec.comments)
		sec.comments = nil
		content += fmt.Sprintf("\n[%s]", sec.name)
		for _, kv := range sec.options {
			content += fmt.Sprintf("\n%s=%s", kv.key, renderOptionValue(kv.value))
		}
		content += fmt.Sprintf("\n%s\n", comments)
	}
	if werr := rt.FS.WriteFile(repofile, []byte(content), 0o644); werr != nil {
		return "", werr
	}
	return fmt.Sprintf("Repo %s has been removed from %s", repo, repofile), nil
}

// yumNotEqualZero evaluates Python `v != 0`, where booleans compare
// numerically (False equals zero).
func yumNotEqualZero(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int:
		return x != 0
	case float64:
		return x != 0
	}
	return true
}

// shouldDeleteBlank evaluates `v != 0 and not v`: empty strings, None and
// empty lists are deleted while False and numeric zero survive verbatim.
func shouldDeleteBlank(v any) bool {
	t, _ := truthyAny(v)
	return yumNotEqualZero(v) && !t
}

// yumModRepo mirrors mod_repo. Pinned behaviors: every kwarg outside
// dunders/saltenv lands in repo_opts (basedir included — upstream never
// filters it), blank values delete options while False and zero survive,
// booleans render as 1/0, and COPR creation goes through the plugin check
// plus `copr enable`.
func yumModRepo(ctx context.Context, rt *runtime.Runtime, repo string, basedirArg any, strict bool, kwargs map[string]any) (map[string]any, error) {
	linkTypes := []string{"baseurl", "mirrorlist", "metalink"}

	repoOpts := map[string]any{}
	var optOrder []string
	for _, key := range sortedKeys(kwargs) {
		if strings.HasPrefix(key, "__") || key == "saltenv" {
			continue
		}
		repoOpts[key] = kwargs[key]
		optOrder = append(optOrder, key)
	}

	linkCount := 0
	for _, lt := range linkTypes {
		if _, ok := repoOpts[lt]; ok {
			linkCount++
		}
	}
	if linkCount >= 2 {
		return nil, fmt.Errorf("One and only one of %s can be used", strings.Join(linkTypes, ", "))
	}

	useCopr := false
	coprName := ""
	if strings.HasPrefix(repo, "copr:") {
		coprName = strings.SplitN(repo, ":", 2)[1]
		repo = getCoprRepo(repo)
		useCopr = true
	}

	todelete := []string{}
	for _, key := range append([]string{}, optOrder...) {
		v, ok := repoOpts[key]
		if !ok {
			continue
		}
		if shouldDeleteBlank(v) {
			delete(repoOpts, key)
			todelete = append(todelete, key)
		}
	}

	// When one link type was supplied, the unused two join the deletion
	// list (first supplied wins).
	for _, provided := range linkTypes {
		if _, ok := repoOpts[provided]; ok {
			for _, other := range linkTypes {
				if other != provided {
					todelete = append(todelete, other)
				}
			}
			break
		}
	}

	if containsStr(todelete, "name") {
		return nil, fmt.Errorf("The repo name cannot be deleted")
	}

	basedirs, err := normalizeYumBasedir(rt, basedirArg, strict)
	if err != nil {
		return nil, err
	}
	repos, err := yumListRepos(rt, basedirs, strict)
	if err != nil {
		return nil, err
	}

	var (
		repofile string
		file     *yumRepoFile
	)
	if _, exists := repos[repo]; !exists {
		newdir := ""
		for _, d := range basedirs {
			if info, serr := rt.FS.Stat(d); serr == nil && info.IsDir() {
				newdir = d
				break
			}
		}
		if newdir == "" {
			return nil, fmt.Errorf(
				"The repo does not exist and needs to be created, but none of the following basedir directories exist: %s",
				pyListRepr(basedirs))
		}
		if useCopr {
			binary := yumBinaryName()
			plugin := "yum-plugin-copr"
			if binary == "dnf" || binary == "dnf5" {
				plugin = "dnf-plugins-core"
			}
			installed := ""
			if _, ok := rt.Exec.Get("pkg_resource.version"); ok {
				res, callErr := rt.Exec.Call(ctx, rt, "pkg_resource.version",
					map[string]any{"name": plugin})
				if callErr == nil {
					s, _ := res.(string)
					installed = s
				}
			}
			if installed == "" {
				return nil, fmt.Errorf("%s must be installed to use COPR", plugin)
			}
			out := callApt(ctx, rt, []string{binary, "copr", "enable", coprName, "-y"}, nil)
			if out.ExitCode != 0 {
				return nil, fmt.Errorf("Unable to add COPR '%s'. '%s' exited with status %d: '%s' ",
					coprName, binary, out.ExitCode, string(out.Stderr))
			}
			repos, err = yumListRepos(rt, basedirs, strict)
			if err != nil {
				return nil, err
			}
			dict, _ := repos[repo].(map[string]any)
			repofile, _ = dict["file"].(string)
			file, err = parseYumRepoFile(rt, repofile, strict)
			if err != nil {
				return nil, err
			}
		} else {
			repofile = fmt.Sprintf("%s/%s.repo", newdir, repo)
			if _, ok := repoOpts["name"]; !ok {
				return nil, fmt.Errorf(
					"The repo does not exist and needs to be created, but a name was not given")
			}
			hasLink := false
			for _, lt := range linkTypes {
				if _, ok := repoOpts[lt]; ok {
					hasLink = true
					break
				}
			}
			if !hasLink {
				return nil, fmt.Errorf(
					"The repo does not exist and needs to be created, but none of %s was given",
					strings.Join(linkTypes, ", "))
			}
			file = &yumRepoFile{sections: []yumRepoSection{{name: repo}}}
		}
	} else {
		dict, _ := repos[repo].(map[string]any)
		repofile, _ = dict["file"].(string)
		file, err = parseYumRepoFile(rt, repofile, strict)
		if err != nil {
			return nil, err
		}
	}
	target := file.find(repo)
	if target == nil {
		return nil, fmt.Errorf("Repository '%s' disappeared between scans", repo)
	}

	// Error out when a deletion would leave the repo without any link type.
	for _, linkType := range linkTypes {
		others := make([]string, 0, 2)
		for _, lt := range linkTypes {
			if lt != linkType {
				others = append(others, lt)
			}
		}
		allGone := true
		for _, other := range others {
			_, inOpts := repoOpts[other]
			_, inSection := target.get(other)
			if inOpts || inSection {
				allGone = false
				break
			}
		}
		if allGone && containsStr(todelete, linkType) {
			return nil, fmt.Errorf("Cannot delete %s without specifying %s",
				linkType, strings.Join(others, " or "))
		}
	}

	for _, key := range todelete {
		target.delete(key)
	}

	// Merge requested options into the stanza. Upstream preserves request
	// insertion order; Go map decoding loses it, so keys apply in sorted
	// order (documented divergence).
	mergedKeys := make([]string, 0, len(repoOpts))
	for key := range repoOpts {
		mergedKeys = append(mergedKeys, key)
	}
	sort.Strings(mergedKeys)
	for _, key := range mergedKeys {
		val := repoOpts[key]
		switch v := val.(type) {
		case bool:
			target.set(key, boolToYumString(v))
		default:
			target.set(key, scalarString(v))
		}
	}

	// Render the whole file; the reply keeps the target stanza's raw values
	// minus its comments.
	var body strings.Builder
	body.WriteString(file.header)
	reply := map[string]any{}
	for i := range file.sections {
		sec := &file.sections[i]
		comments := combineRpmComments(sec.comments)
		sec.comments = nil
		body.WriteString(fmt.Sprintf("[%s]\n", sec.name))
		for _, kv := range sec.options {
			body.WriteString(fmt.Sprintf("%s=%s\n", kv.key, renderOptionValue(kv.value)))
		}
		body.WriteString(comments + "\n")

		if sec.name == repo {
			for _, kv := range sec.options {
				reply[kv.key] = kv.value
			}
		}
	}
	if werr := rt.FS.WriteFile(repofile, []byte(body.String()), 0o644); werr != nil {
		return nil, werr
	}
	return map[string]any{repofile: reply}, nil
}

// yumBinaryName resolves the dnf/yum executable for COPR flows; injectable.
var yumBinaryName = func() string {
	if whichBin("dnf") != "" {
		return "dnf"
	}
	if whichBin("yum") != "" {
		return "yum"
	}
	return "dnf"
}
