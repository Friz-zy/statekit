package pkgrepo

import (
	"context"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// SUSE/zypper repository management, mirroring the repo functions and the
// _Zypper call wrapper of saltstack/salt/modules/zypperpkg.py @ pinned
// revision.

const zypperDefaultPriority = 99

// zypperReposDir mirrors ZYPP_HOME/repos.d; injectable.
var zypperReposDir = "/etc/zypp/repos.d"

// lockSleep reuses the shared injectable backoff hook (5s waits upstream).
var zypperLockWait = func() { /* replaced in tests */ }

// Zypper exit-code classification from _Zypper.SUCCESS_EXIT_CODES and
// WARNING_EXIT_CODES.
var (
	zypperSuccessExitCodes = map[int]bool{0: true, 100: true, 101: true, 102: true, 103: true}
	zypperWarningExitCodes = map[int]bool{6: true, 7: true, 106: true, 107: true}
)

// xmlNode is a minimal DOM node over encoding/xml supporting the
// getElementsByTagName lookups the repo surface performs.
type xmlNode struct {
	tag      string
	attrs    map[string]string
	children []*xmlNode
	text     strings.Builder
}

func parseXMLDocument(data string) (*xmlNode, error) {
	root := &xmlNode{tag: "#document"}
	decoder := xml.NewDecoder(strings.NewReader(data))
	stack := []*xmlNode{root}
	for {
		tok, err := decoder.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			node := &xmlNode{tag: t.Name.Local, attrs: map[string]string{}}
			for _, attr := range t.Attr {
				if attr.Name.Space == "" {
					node.attrs[attr.Name.Local] = attr.Value
				} else {
					node.attrs[attr.Name.Local] = attr.Value
				}
			}
			parent := stack[len(stack)-1]
			parent.children = append(parent.children, node)
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			cur := stack[len(stack)-1]
			cur.text.Write(t)
		}
	}
	return root, nil
}

// elementsByTagName collects descendant nodes by tag name recursively.
func (n *xmlNode) elementsByTagName(tag string) []*xmlNode {
	var out []*xmlNode
	var walk func(*xmlNode)
	walk = func(cur *xmlNode) {
		for _, child := range cur.children {
			if child.tag == tag {
				out = append(out, child)
			}
			walk(child)
		}
	}
	walk(n)
	return out
}

// textValue mirrors childNodes[0].nodeValue for simple text elements.
func (n *xmlNode) textValue() string { return n.text.String() }

// zypperCallOpts carries the __getattr__ configurator flags used by the
// repository surface (xml, refreshable, noraise plus call kwargs).
type zypperCallOpts struct {
	xml               bool
	refreshable       bool
	noRaise           bool
	ignoreRepoFailure bool
	root              string
	successRetcodes   []int
}

// zypperRun ports _Zypper.__call: argv assembly, execution through the
// central Runner, exit-code classification, XML error extraction, and the
// zypper-lock retry loop. systemd-run scoping is not reproduced and the
// event.fire_master notifications are dropped (master-minion architecture,
// excluded); the 5-second lock waits are kept behind an injectable hook.
func zypperRun(ctx context.Context, rt *runtime.Runtime, opts zypperCallOpts, args ...string) (string, *xmlNode, error) {
	for {
		cmd := []string{"zypper", "--non-interactive"}
		if opts.xml {
			cmd = append(cmd, "--xmlout")
		}
		if !opts.refreshable && !containsStr(args, "--no-refresh") {
			cmd = append(cmd, "--no-refresh")
		}
		if opts.root != "" {
			cmd = append(cmd, "--root", opts.root)
		}
		cmd = append(cmd, args...)

		res := rt.Runner.Run(ctx, runtime.Command(cmd...))
		exitCode := res.ExitCode
		if res.Err != nil {
			exitCode = -1
		}
		if opts.successRetcodes != nil {
			for _, code := range opts.successRetcodes {
				if exitCode == code {
					exitCode = 0
					break
				}
			}
		}

		errCode := !zypperSuccessExitCodes[exitCode] && !zypperWarningExitCodes[exitCode]
		errorMsg := ""
		if errCode {
			var messages []string
			if opts.xml {
				doc, perr := parseXMLDocument(string(res.Stdout))
				if perr == nil {
					for _, node := range doc.elementsByTagName("message") {
						if node.attrs["type"] == "error" {
							messages = append(messages, node.textValue())
						}
					}
				}
				if len(messages) == 0 && strings.TrimSpace(string(res.Stderr)) != "" {
					messages = append(messages, strings.TrimSpace(string(res.Stderr)))
				}
			} else {
				msg := strings.TrimSpace(string(res.Stderr)) + strings.TrimSpace(string(res.Stdout))
				if msg != "" {
					messages = append(messages, msg)
				}
			}
			if len(messages) > 0 {
				errorMsg = strings.Join(messages, "\n")
			} else {
				errorMsg = "Check Zypper's logs."
			}
		}

		if exitCode == 7 {
			// Zypper library locked: upstream waits five seconds and retries
			// until released.
			zypperLockWait()
			continue
		}

		if errorMsg != "" && !opts.noRaise && !opts.ignoreRepoFailure {
			return "", nil, fmt.Errorf("Zypper command failure: %s", errorMsg)
		}
		if opts.xml {
			doc, perr := parseXMLDocument(string(res.Stdout))
			if perr != nil {
				return string(res.Stdout), nil, fmt.Errorf("Zypper command failure: %s", perr.Error())
			}
			return string(res.Stdout), doc, nil
		}
		return string(res.Stdout), nil, nil
	}
}

// zypperReposCfgPath mirrors the root-aware repos directory resolution.
func zypperReposCfgPath(root string) string {
	if root == "" {
		return zypperReposDir
	}
	return filepath.Join(root, strings.TrimPrefix(zypperReposDir, "/"))
}

// zypperConfiguredRepos mirrors _get_configured_repos: every *.repo file
// in the repos dir parsed strict (configparser defaults).
func zypperConfiguredRepos(rt *runtime.Runtime, root string) (*iniConfig, error) {
	reposPath := zypperReposCfgPath(root)
	info, err := rt.FS.Stat(reposPath)
	if err != nil || !info.IsDir() {
		// Upstream warns about missing repositories and continues empty.
		return &iniConfig{}, nil
	}
	entries, err := rt.FS.ReadDir(reposPath)
	if err != nil {
		return &iniConfig{}, nil
	}
	cfg := &iniConfig{}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sortStrings(names)
	for _, name := range names {
		if !strings.HasSuffix(name, ".repo") {
			continue
		}
		data, rerr := rt.FS.ReadFile(filepath.Join(reposPath, name))
		if rerr != nil {
			continue
		}
		parsed, perr := parseConfigparser(string(data), true)
		if perr != nil {
			// configparser.read() collects errors per file and raises;
			// upstream would propagate. Mirror by failing the call.
			return nil, perr
		}
		cfg.sections = append(cfg.sections, parsed.sections...)
	}
	return cfg, nil
}

// zypperRepoInfo mirrors _get_repo_info: section options with 0/1 coerced
// to booleans, NONE to None, plus the injected alias key.
func zypperRepoInfo(rt *runtime.Runtime, alias string, cfg *iniConfig, root string) (map[string]any, error) {
	if cfg == nil {
		var err error
		cfg, err = zypperConfiguredRepos(rt, root)
		if err != nil {
			return nil, err
		}
	}
	section := cfg.find(alias)
	if section == nil {
		return map[string]any{}, nil
	}
	meta := map[string]any{}
	for _, kv := range section.options {
		switch kv.value {
		case "0":
			meta[kv.key] = false
		case "1":
			meta[kv.key] = true
		case "NONE":
			meta[kv.key] = nil
		default:
			meta[kv.key] = kv.value
		}
	}
	meta["alias"] = alias
	return meta, nil
}

// zypperListRepos mirrors list_repos.
func zypperListRepos(rt *runtime.Runtime, root string) (map[string]any, error) {
	cfg, err := zypperConfiguredRepos(rt, root)
	if err != nil {
		return nil, err
	}
	all := map[string]any{}
	for _, sec := range cfg.sections {
		meta, err := zypperRepoInfo(rt, sec.name, cfg, root)
		if err != nil {
			return nil, err
		}
		all[sec.name] = meta
	}
	return all, nil
}

// zypperGetRepo mirrors get_repo.
func zypperGetRepo(rt *runtime.Runtime, repo, root string) (map[string]any, error) {
	return zypperRepoInfo(rt, repo, nil, root)
}

// zypperDelRepo mirrors del_repo including the fall-through not-found raise
// when the removal produced no progress/message feedback.
func zypperDelRepo(ctx context.Context, rt *runtime.Runtime, repo, root string) (map[string]any, error) {
	cfg, err := zypperConfiguredRepos(rt, root)
	if err != nil {
		return nil, err
	}
	for _, sec := range cfg.sections {
		if sec.name != repo {
			continue
		}
		_, doc, err := zypperRun(ctx, rt, zypperCallOpts{xml: true, root: root},
			"rr", "--loose-auth", "--loose-query", repo)
		if err != nil {
			return nil, err
		}
		msg := doc.elementsByTagName("message")
		progress := doc.elementsByTagName("progress")
		if len(progress) > 0 && len(msg) > 0 {
			return map[string]any{
				repo:      true,
				"message": msg[0].textValue(),
			}, nil
		}
	}
	return nil, fmt.Errorf("Repository '%s' not found.", repo)
}

// urlResult mirrors urllib.parse.ParseResult six-tuple equality.
type urlResult struct {
	scheme   string
	netloc   string
	path     string
	params   string
	query    string
	fragment string
}

// pythonURLParse reproduces urlparse closely enough for the structural
// equality comparisons mod_repo performs, including the ";"-params split
// out of the final path segment.
func pythonURLParse(raw string) urlResult {
	rest := raw
	out := urlResult{}
	if idx := strings.Index(rest, "#"); idx >= 0 {
		out.fragment = rest[idx+1:]
		rest = rest[:idx]
	}
	if idx := strings.Index(rest, "?"); idx >= 0 {
		out.query = rest[idx+1:]
		rest = rest[:idx]
	}
	schemeEnd := strings.Index(rest, "://")
	if schemeEnd >= 0 {
		out.scheme = rest[:schemeEnd]
		rest = rest[schemeEnd+3:]
		out.netloc = rest
		if slash := strings.Index(rest, "/"); slash >= 0 {
			out.netloc = rest[:slash]
			out.path = rest[slash:]
		}
	} else {
		out.path = rest
	}
	// Params come from the last path segment's ";" suffix.
	if slash := strings.LastIndex(out.path, "/"); slash >= 0 {
		segment := out.path[slash+1:]
		if semi := strings.Index(segment, ";"); semi >= 0 {
			out.params = segment[semi+1:]
			out.path = out.path[:slash+1] + segment[:semi]
		}
	} else if semi := strings.Index(out.path, ";"); semi >= 0 {
		out.params = out.path[semi+1:]
		out.path = out.path[:semi]
	}
	return out
}

// zypperModRepo mirrors mod_repo: creation through `ar`, modification
// through `mr`, baseurl changes via remove-and-readd, and the no-op
// comment marker.
func zypperModRepo(ctx context.Context, rt *runtime.Runtime, repo string, root string, kwargs map[string]any) (map[string]any, error) {
	if kwargs == nil {
		kwargs = map[string]any{}
	}
	cfg, err := zypperConfiguredRepos(rt, root)
	if err != nil {
		return nil, err
	}
	added := false

	if !cfg.hasSection(repo) {
		url := ""
		for _, key := range []string{"url", "mirrorlist", "baseurl"} {
			if v, ok := kwargStringOK(kwargs, key); ok && v != "" {
				url = v
				break
			}
		}
		if url == "" {
			return nil, fmt.Errorf(
				"Repository '%s' not found, and neither 'baseurl' nor 'mirrorlist' was specified", repo)
		}
		parsed := pythonURLParse(url)
		if parsed.scheme == "" {
			return nil, fmt.Errorf(
				"Repository '%s' not found and URL for baseurl/mirrorlist is malformed", repo)
		}
		// Duplicate-URL probe across configured aliases.
		for _, sec := range cfg.sections {
			repoMeta, merr := zypperRepoInfo(rt, sec.name, cfg, root)
			if merr != nil {
				return nil, merr
			}
			newURL := pythonURLParse(url)
			if newURL.path == "" {
				newURL.path = "/"
			}
			baseRaw, _ := repoMeta["baseurl"].(string)
			baseURL := pythonURLParse(baseRaw)
			if newURL == baseURL {
				return nil, fmt.Errorf("Repository '%s' already exists as '%s'.", repo, sec.name)
			}
		}
		if _, _, err := zypperRun(ctx, rt, zypperCallOpts{xml: true, root: root}, "ar", url, repo); err != nil {
			return nil, err
		}
		cfg, err = zypperConfiguredRepos(rt, root)
		if err != nil {
			return nil, err
		}
		if !cfg.hasSection(repo) {
			return nil, fmt.Errorf(
				"Failed add new repository '%s' for unspecified reason. Please check zypper logs.", repo)
		}
		added = true
	}

	repoInfo, err := zypperRepoInfo(rt, repo, nil, root)
	if err != nil {
		return nil, err
	}
	if baseurlRaw, hasBaseurl := kwargs["baseurl"]; hasBaseurl && !added {
		currentBase, _ := repoInfo["baseurl"]
		if !equalAny(currentBase, baseurlRaw) {
			// zypper cannot change the baseurl: remove and re-add.
			merged := map[string]any{}
			for k, v := range repoInfo {
				merged[k] = v
			}
			for k, v := range kwargs {
				merged[k] = v
			}
			if _, ok := merged["cache"]; !ok {
				merged["cache"] = false
			}
			if _, derr := zypperDelRepo(ctx, rt, repo, root); derr != nil {
				return nil, derr
			}
			return zypperModRepo(ctx, rt, repo, root, merged)
		}
	}

	var cmdOpt []string
	callRefresh := false

	if v, ok := kwargs["enabled"]; ok {
		cmdOpt = append(cmdOpt, boolFlag(isTrue(v), "--enable", "--disable"))
	}
	if v, ok := kwargs["refresh"]; ok {
		cmdOpt = append(cmdOpt, boolFlag(isTrue(v), "--refresh", "--no-refresh"))
	}
	if v, ok := kwargs["cache"]; ok {
		cmdOpt = append(cmdOpt, boolFlag(isTrue(v), "--keep-packages", "--no-keep-packages"))
	}
	if v, ok := kwargs["gpgcheck"]; ok {
		cmdOpt = append(cmdOpt, boolFlag(isTrue(v), "--gpgcheck", "--no-gpgcheck"))
	}
	if v, ok := kwargs["priority"]; ok {
		priority := float64(zypperDefaultPriority)
		switch x := v.(type) {
		case int:
			priority = float64(x)
		case float64:
			priority = x
		}
		cmdOpt = append(cmdOpt, fmt.Sprintf("--priority=%d", int(priority)))
	}
	if v, ok := kwargStringOK(kwargs, "humanname"); ok {
		// Deprecated upstream but functional; the literal quoting inside the
		// argument is preserved verbatim.
		cmdOpt = append(cmdOpt, fmt.Sprintf("--name='%s'", v))
	}
	if v, ok := kwargStringOK(kwargs, "name"); ok {
		cmdOpt = append(cmdOpt, "--name", v)
	}
	if v, ok := kwargs["gpgautoimport"].(bool); ok && v {
		callRefresh = true
	}

	comment := ""
	if len(cmdOpt) > 0 {
		args := append([]string{"mr"}, cmdOpt...)
		args = append(args, repo)
		if _, _, err := zypperRun(ctx, rt, zypperCallOpts{xml: true, refreshable: true, root: root}, args...); err != nil {
			return nil, err
		}
	}

	if callRefresh {
		if _, rerr := zypperRefreshDB(ctx, rt, nil, root, true, repo); rerr != nil {
			return nil, rerr
		}
	} else if !added && len(cmdOpt) == 0 {
		comment = "Specified arguments did not result in modification of repo"
	}

	ret, err := zypperGetRepo(rt, repo, root)
	if err != nil {
		return nil, err
	}
	if comment != "" {
		ret["comment"] = comment
	}
	return ret, nil
}

func equalAny(a, b any) bool {
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok && bok {
		return as == bs
	}
	return a == b
}

func boolFlag(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

func (c *iniConfig) hasSection(name string) bool { return c.find(name) != nil }

// zypperRefreshDB mirrors refresh_db: `zypper refresh` through the
// refreshable (no --no-refresh) caller with retcode 6 tolerated, and the
// up-to-date/done line parsing.
func zypperRefreshDB(ctx context.Context, rt *runtime.Runtime, force *bool, root string, gpgautoimport bool, repos any) (map[string]any, error) {
	ret := map[string]any{}
	refreshOpts := []string{"refresh"}
	forceVal := true
	if force != nil {
		forceVal = *force
	}
	if forceVal {
		refreshOpts = append(refreshOpts, "--force")
	}
	switch r := repos.(type) {
	case nil:
	case string:
		if r != "" {
			refreshOpts = append(refreshOpts, r)
		}
	case []string:
		refreshOpts = append(refreshOpts, r...)
	case []any:
		for _, item := range r {
			refreshOpts = append(refreshOpts, scalarString(item))
		}
	}
	var globalOpts []string
	if gpgautoimport {
		globalOpts = append(globalOpts, "--gpg-auto-import-keys")
	}

	args := append(globalOpts, refreshOpts...)
	out, _, err := zypperRun(ctx, rt, zypperCallOpts{refreshable: true, root: root, successRetcodes: []int{0, 6}}, args...)
	if err != nil {
		return nil, err
	}

	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		stripped := strings.TrimSpace(line)
		if strings.HasPrefix(stripped, "Repository") && strings.Contains(stripped, "'") {
			parts := strings.Split(stripped, "'")
			if len(parts) < 2 {
				continue
			}
			key := strings.TrimSpace(parts[1])
			if strings.Contains(stripped, "is up to date") {
				ret[key] = false
			}
		} else if strings.HasPrefix(stripped, "Building") && strings.Contains(stripped, "'") {
			parts := strings.Split(stripped, "'")
			if len(parts) < 2 {
				continue
			}
			key := strings.TrimSpace(parts[1])
			if strings.Contains(stripped, "done") {
				ret[key] = true
			}
		}
	}
	return ret, nil
}
