// Package pkgrepo implements Salt's pkgrepo state functions: managed and
// absent, delegating to the pkg.* repository functions registered by
// modules/exec/pkgrepo.
//
// Reference: saltstack/salt/states/pkgrepo.py @ pinned revision
// (references/salt.lock).
//
// Contract notes (init.md section 28):
//
//   - Salt reaches into aptpkg's loader-hidden _expand_repo_def and
//     _split_repo_str from the state; StateKit exposes them as exported
//     helpers on the exec package with the same cross-module coupling.
//   - The already-configured comparison loop iterates keys in sorted order
//     where upstream relies on request insertion order (documented
//     divergence, consistent with the exec-side kwargs handling).
//   - The __opts__["test"] branch maps to the per-state --test flag.
package pkgrepo

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execpkgrepo "github.com/friz-zy/statekit/modules/exec/pkgrepo"
)

// familyOf resolves the OS family behind injectable-free fact access,
// mirroring the __grains__["os_family"] probes in the upstream state.
func familyOf(rt *runtime.Runtime) string {
	if rt.Facts == nil {
		return ""
	}
	return rt.Facts.OS().Family
}

func isTrueAny(v any) bool { return execpkgrepo.IsTrue(v) }

type managedArgs struct {
	Name             string         `statekit:"required"`
	Ppa              *string        `statekit:"name=ppa"`
	Copr             *string        `statekit:"name=copr"`
	Aptkey           *bool          `statekit:"name=aptkey"`
	Enabled          *bool          `statekit:"name=enabled"`
	Disabled         *bool          `statekit:"name=disabled"`
	Humanname        *string        `statekit:"name=humanname"`
	Baseurl          *string        `statekit:"name=baseurl"`
	Mirrorlist       *string        `statekit:"name=mirrorlist"`
	Metalink         *string        `statekit:"name=metalink"`
	Comments         any            `statekit:"name=comments"`
	Keyid            any            `statekit:"name=keyid"`
	Keyserver        *string        `statekit:"name=keyserver"`
	KeyURL           *string        `statekit:"name=key_url"`
	KeyText          *string        `statekit:"name=key_text"`
	Architectures    *string        `statekit:"name=architectures"`
	Comps            *string        `statekit:"name=comps"`
	File             *string        `statekit:"name=file"`
	Dist             *string        `statekit:"name=dist"`
	CleanFile        *bool          `statekit:"name=clean_file"`
	Refresh          *bool          `statekit:"name=refresh"`
	Consolidate      *bool          `statekit:"name=consolidate"`
	PpaAuth          *string        `statekit:"name=ppa_auth"`
	AllowInsecureKey *bool          `statekit:"name=allow_insecure_key"`
	Test             bool           `statekit:"name=test"`
	Kwargs           map[string]any `statekit:"name=kwargs"`
}

// buildKwargs assembles the flat kwarg dict upstream carries through the
// state, merging the free-form passthrough last.
func (a *managedArgs) buildKwargs() map[string]any {
	kw := map[string]any{}
	set := func(key string, v any) { kw[key] = v }
	if a.Ppa != nil {
		set("ppa", *a.Ppa)
	}
	if a.Copr != nil {
		set("copr", *a.Copr)
	}
	if a.Humanname != nil {
		set("humanname", *a.Humanname)
	}
	if a.Baseurl != nil {
		set("baseurl", *a.Baseurl)
	}
	if a.Mirrorlist != nil {
		set("mirrorlist", *a.Mirrorlist)
	}
	if a.Metalink != nil {
		set("metalink", *a.Metalink)
	}
	if a.Comments != nil {
		set("comments", a.Comments)
	}
	if a.Keyid != nil {
		set("keyid", a.Keyid)
	}
	if a.Keyserver != nil {
		set("keyserver", *a.Keyserver)
	}
	if a.KeyURL != nil {
		set("key_url", *a.KeyURL)
	}
	if a.KeyText != nil {
		set("key_text", *a.KeyText)
	}
	if a.Architectures != nil {
		set("architectures", *a.Architectures)
	}
	if a.Comps != nil {
		set("comps", *a.Comps)
	}
	if a.File != nil {
		set("file", *a.File)
	}
	if a.Dist != nil {
		set("dist", *a.Dist)
	}
	if a.CleanFile != nil {
		set("clean_file", *a.CleanFile)
	}
	if a.Refresh != nil {
		set("refresh", *a.Refresh)
	}
	if a.Consolidate != nil {
		set("consolidate", *a.Consolidate)
	}
	if a.PpaAuth != nil {
		set("ppa_auth", *a.PpaAuth)
	}
	if a.Enabled != nil {
		set("enabled", *a.Enabled)
	}
	if a.Disabled != nil {
		set("disabled", *a.Disabled)
	}
	if a.AllowInsecureKey != nil {
		set("allow_insecure_key", *a.AllowInsecureKey)
	}
	for key, val := range a.Kwargs {
		kw[key] = val
	}
	return kw
}

type managedFunc struct{}

func (managedFunc) Name() string { return "pkgrepo.managed" }
func (managedFunc) Args() any    { return managedArgs{} }

func (managedFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*managedArgs)
	family := familyOf(rt)
	name := a.Name

	ret := result.New(name, "", nil, map[string]any{})

	if _, ok := rt.Exec.Get("pkg.get_repo"); !ok {
		ret.Result = result.Bool(false)
		ret.Comment = "Repo management not implemented on this platform"
		return ret
	}

	kw := a.buildKwargs()

	hasKey := func(key string) bool { _, ok := kw[key]; return ok }
	if hasKey("key_url") && (hasKey("keyid") || hasKey("keyserver")) {
		ret.Result = result.Bool(false)
		ret.Comment = `You may not use both "keyid"/"keyserver" and "key_url" argument.`
	}
	if hasKey("key_text") && (hasKey("keyid") || hasKey("keyserver")) {
		ret.Result = result.Bool(false)
		ret.Comment = `You may not use both "keyid"/"keyserver" and "key_text" argument.`
	}
	if hasKey("key_text") && hasKey("key_url") {
		ret.Result = result.Bool(false)
		ret.Comment = `You may not use both "key_url" and "key_text" argument.`
	}
	if ret.Result != nil && !*ret.Result {
		return ret
	}

	if _, ok := kw["repo"]; ok {
		ret.Result = result.Bool(false)
		ret.Comment = "'repo' is not a supported argument for this " +
			"state. The 'name' argument is probably what was intended."
		return ret
	}

	enabledRaw, hasEnabled := kw["enabled"]
	disabledRaw, hasDisabled := kw["disabled"]
	delete(kw, "enabled")
	delete(kw, "disabled")

	var enabled, disabled any
	if hasEnabled {
		enabled = enabledRaw
	}
	if hasDisabled {
		disabled = disabledRaw
	}

	if hasEnabled && hasDisabled {
		ret.Result = result.Bool(false)
		ret.Comment = "Only one of enabled/disabled is allowed"
		return ret
	} else if !hasEnabled && !hasDisabled {
		enabled = true
	}

	allowInsecureKey := true
	if v, ok := kw["allow_insecure_key"]; ok {
		allowInsecureKey = execpkgrepo.IsTrue(v)
	}
	keyURLText, _ := kw["key_url"].(string)
	if strings.HasPrefix(strings.TrimSpace(keyURLText), "http:") && !allowInsecureKey {
		ret.Result = result.Bool(false)
		ret.Comment = "Cannot have 'key_url' using http with 'allow_insecure_key' set to True"
		return ret
	}

	repo := name
	kw["name"] = repo

	aptkey := true
	if a.Aptkey != nil {
		aptkey = *a.Aptkey
	}
	if _, ok := rt.Exec.Get("pkg.get_repo_keys"); !ok {
		// which("apt-key") absence flips aptkey off like the state prologue.
		if backend, berr := execpkgrepo.BackendOf(rt); berr == nil && backend != "apt" {
			aptkey = false
		} else if !execpkgrepo.WhichAptKey() {
			aptkey = false
		}
	}

	switch family {
	case "debian":
		if a.Ppa != nil {
			repo = "ppa:" + *a.Ppa
		}
		if hasEnabled {
			kw["disabled"] = !isTrueAny(enabled)
		} else {
			kw["disabled"] = isTrueAny(disabled)
		}
	case "redhat", "suse":
		if family == "redhat" && a.Copr != nil {
			repo = "copr:" + *a.Copr
			kw["name"] = name
		}
		if hn, ok := kwargPopString(kw, "humanname"); ok {
			kw["name"] = hn
		}
		if hasDisabled {
			kw["enabled"] = !isTrueAny(disabled)
		} else {
			kw["enabled"] = isTrueAny(enabled)
		}
	default:
		// NILinuxRT/Poky style families keep the enabled normalization.
		if hasDisabled {
			kw["enabled"] = !isTrueAny(disabled)
		} else {
			kw["enabled"] = isTrueAny(enabled)
		}
	}

	pre, err := callGetRepo(ctx, rt, repo, kw)
	if err != nil {
		ret.Result = result.Bool(false)
		ret.Comment = fmt.Sprintf("Failed to examine repo '%s': %v", name, err)
		return ret
	}

	sanitized := kw
	if family == "debian" {
		osName := ""
		osCodename := ""
		if rt.Facts != nil {
			osName = rt.Facts.OS().Name
			osCodename = rt.Facts.OS().Codename
		}
		// Upstream passes the repo definition explicitly alongside kwargs.
		expandKw := copyMap(kw)
		expandKw["repo"] = repo
		sanitized, err = execpkgrepo.ExpandRepoDef(rt, osName, osCodename, expandKw)
		if err != nil {
			ret.Result = result.Bool(false)
			ret.Comment = fmt.Sprintf("Failed to examine repo '%s': %v", name, err)
			return ret
		}
	}

	// clean_file staleness probe: non-blank lines other than the desired
	// entry force reconfiguration (issue #68208 port).
	cleanFileNeedsReconfigure := false
	if pre != nil && len(pre) > 0 {
		wantClean, _ := kw["clean_file"].(bool)
		filePath, hasFile := kw["file"].(string)
		if wantClean && hasFile {
			if info, ferr := rt.FS.Stat(filePath); ferr == nil && !info.IsDir() {
				data, rerr := rt.FS.ReadFile(filePath)
				if rerr == nil {
					for _, raw := range strings.Split(string(data), "\n") {
						line := strings.TrimSpace(raw)
						if line == "" || strings.HasPrefix(line, "#") ||
							line == strings.TrimSpace(name) {
							continue
						}
						cleanFileNeedsReconfigure = true
						break
					}
				}
			}
		}
	}

	if pre != nil && len(pre) > 0 && !cleanFileNeedsReconfigure {
		delete(pre, "file")
		delete(sanitized, "file")
		needsUpdate := comparisonNeedsUpdate(family, sanitized, pre, kw)
		if !needsUpdate {
			ret.Result = result.Bool(true)
			ret.Comment = fmt.Sprintf("Package repo '%s' already configured", name)
			return ret
		}
	}

	if family == "debian" {
		if _, hasURI := kw["uri"]; !hasURI {
			if uri, ok := sanitized["uri"]; ok {
				if preURI, ok := pre["uri"]; ok && !equalScalar(uri, preURI) {
					kw["uri"] = uri
				}
			}
		}
		if _, hasURIs := kw["uris"]; !hasURIs {
			if uris, ok := sanitized["uris"].([]string); ok && len(uris) > 0 {
				if preURIs, ok := pre["uris"].([]string); ok {
					if !containsStr(preURIs, uris[0]) {
						kw["uris"] = sanitized["uris"]
					}
				}
			}
		}
	}

	if a.Test {
		comment := fmt.Sprintf(
			"Package repo '%s' would be configured. This may cause pkg "+
				"states to behave differently than stated if this action is "+
				"repeated without test=True, due to the differences in the "+
				"configured repositories.", name)
		changes := map[string]any{}
		if pre != nil && len(pre) > 0 {
			for _, key := range sortedKeys(sanitized) {
				if !equalScalar(sanitized[key], pre[key]) {
					changes[key] = map[string]any{"new": sanitized[key], "old": pre[key]}
				}
			}
		} else {
			changes["repo"] = name
		}
		return result.TestPending(name, comment, changes)
	}

	if clean, _ := kw["clean_file"].(bool); clean {
		if filePath, ok := kw["file"].(string); ok {
			rt.FS.WriteFile(filePath, []byte{}, 0o644)
		}
	}

	modArgs := &execpkgrepo.ModRepoArgs{Repo: repo, Kwargs: copyMap(kw)}
	if family == "debian" {
		modArgs.Saltenv = strPtrState("base")
		modArgs.Aptkey = boolPtrState(aptkey)
	}
	if _, err := rt.Exec.Call(ctx, rt, "pkg.mod_repo", modArgs); err != nil {
		ret.Result = result.Bool(false)
		ret.Comment = fmt.Sprintf("Failed to configure repo '%s': %v", name, err)
		return ret
	}

	post, err := callGetRepo(ctx, rt, repo, kw)
	if err != nil {
		ret.Result = result.Bool(false)
		ret.Comment = fmt.Sprintf("Failed to confirm config of repo '%s': %v", name, err)
		return ret
	}
	changes := map[string]any{}
	if pre != nil && len(pre) > 0 {
		for _, key := range sortedKeys(sanitized) {
			if !equalScalar(post[key], pre[key]) {
				changes[key] = map[string]any{"new": post[key], "old": pre[key]}
			}
		}
	} else {
		changes["repo"] = repo
	}

	ret.Result = result.Bool(true)
	ret.Comment = fmt.Sprintf("Configured package repo '%s'", name)
	ret.Changes = changes
	return ret
}

// comparisonNeedsUpdate ports the already-configured for/else loop: true
// means the existing definition diverges and mod_repo must run.
func comparisonNeedsUpdate(family string, sanitized, pre map[string]any, kw map[string]any) bool {
	keys := make([]string, 0, len(sanitized))
	for key := range sanitized {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, kwarg := range keys {
		value := sanitized[kwarg]
		preValue, inPre := pre[kwarg]
		if !inPre {
			if kwarg == "enabled" {
				if family == "redhat" {
					if !execpkgrepo.IsTrue(value) {
						return true
					}
				} else {
					return true
				}
			} else {
				if kwarg == "comps" || kwarg == "key_url" {
					return true
				}
				continue
			}
			continue
		}
		switch {
		case kwarg == "comps" || kwarg == "key_url":
			a, aok := toStringSlice(value)
			b, bok := toStringSlice(preValue)
			if !aok || !bok || !sameSet(a, b) {
				return true
			}
		case kwarg == "line" && family == "debian":
			lineText, _ := value.(string)
			preLine, _ := preValue.(string)
			if aptLineDiffers(lineText, preLine, kw) {
				return true
			}
		case kwarg == "comments" && family == "redhat":
			preComments := execpkgrepo.CombineRpmComments(toStringSliceOrEmpty(preValue))
			kwComments := execpkgrepo.CombineRpmComments(toStringSliceOrEmpty(value))
			if preComments != kwComments {
				return true
			}
		case kwarg == "architectures" && value != nil:
			a, _ := toStringSlice(value)
			b, _ := toStringSlice(preValue)
			if !sameSet(a, b) {
				return true
			}
		default:
			if family == "redhat" || family == "suse" {
				if execpkgrepo.IsTrue(value) != execpkgrepo.IsTrue(preValue) {
					return true
				}
			} else if !equalScalar(value, preValue) {
				return true
			}
		}
	}
	return false
}

// aptLineDiffers mirrors the Debian line comparison including comment text.
func aptLineDiffers(sanitizedLine, preLine string, kw map[string]any) bool {
	split := strings.Fields(sanitizedLine)
	if len(split) > 3 {
		tail := append([]string{}, split[3:]...)
		sort.Strings(tail)
		split = append(append([]string{}, split[:3]...), tail...)
	}
	reposplitStr, preComments, _ := strings.Cut(strings.TrimSpace(preLine), "#")
	parts := strings.Fields(strings.TrimSpace(reposplitStr))
	if len(parts) > 3 {
		tail := append([]string{}, parts[3:]...)
		sort.Strings(tail)
		parts = append(append([]string{}, parts[:3]...), tail...)
	}
	if !equalSlicesGo(split, parts) {
		return true
	}
	if commentsRaw, ok := kw["comments"]; ok {
		want := execpkgrepo.CombineDebComments(commentsRaw)
		if strings.TrimSpace(preComments) != want {
			return true
		}
	}
	return false
}

type absentArgs struct {
	Name     string         `statekit:"required"`
	Ppa      *string        `statekit:"name=ppa"`
	Copr     *string        `statekit:"name=copr"`
	Keyid    *string        `statekit:"name=keyid"`
	KeyidPPa *bool          `statekit:"name=keyid_ppa"`
	Test     bool           `statekit:"name=test"`
	Kwargs   map[string]any `statekit:"name=kwargs"`
}

type absentFunc struct{}

func (absentFunc) Name() string { return "pkgrepo.absent" }
func (absentFunc) Args() any    { return absentArgs{} }

func (absentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*absentArgs)
	family := familyOf(rt)
	name := a.Name

	ret := result.New(name, "", nil, map[string]any{})
	kw := map[string]any{}
	for k, v := range a.Kwargs {
		kw[k] = v
	}

	if a.Ppa != nil && (rt.Facts != nil) &&
		(rt.Facts.OS().Name == "Ubuntu" || rt.Facts.OS().Name == "Mint") {
		name = *a.Ppa
		if !strings.HasPrefix(name, "ppa:") {
			name = "ppa:" + name
		}
	}
	if a.Copr != nil && family == "redhat" {
		name = *a.Copr
		if !strings.HasPrefix(name, "copr:") {
			name = "copr:" + name
		}
	}

	removeKey := false
	if a.Keyid != nil {
		removeKey = true
		kw["keyid"] = *a.Keyid
	}
	if a.KeyidPPa != nil {
		removeKey = true
		kw["keyid_ppa"] = *a.KeyidPPa
	}
	if removeKey {
		if _, ok := rt.Exec.Get("pkg.del_repo_key"); !ok {
			ret.Result = result.Bool(false)
			ret.Comment = "Repo key management is not implemented for this platform"
			return ret
		}
	}

	stripname := name
	if family == "debian" {
		stripname = execpkgrepo.StripURI(name)
	}

	repo, err := callGetRepo(ctx, rt, stripname, kw)
	if err != nil {
		ret.Result = result.Bool(false)
		ret.Comment = fmt.Sprintf("Failed to configure repo '%s': %v", name, err)
		return ret
	}

	if repo != nil && len(repo) > 0 && family == "debian" {
		entry, serr := execpkgrepo.SplitRepoStr(stripname)
		if serr == nil {
			archInRepo, _ := repo["architectures"].([]string)
			if !sameSet(entry.ArchitecturesView(), archInRepo) {
				repo = nil
			}
		}
	}

	if repo == nil || len(repo) == 0 {
		ret.Comment = fmt.Sprintf("Package repo %s is absent", name)
		ret.Result = result.Bool(true)
		return ret
	}

	if a.Test {
		ret.Comment = fmt.Sprintf(
			"Package repo '%s' will be removed. This may "+
				"cause pkg states to behave differently than stated "+
				"if this action is repeated without test=True, due "+
				"to the differences in the configured repositories.", name)
		return ret
	}

	delArgs := &execpkgrepo.DelRepoArgs{Repo: stripname, Kwargs: copyMap(kw)}
	if _, err := rt.Exec.Call(ctx, rt, "pkg.del_repo", delArgs); err != nil {
		ret.Result = result.Bool(false)
		ret.Comment = err.Error()
		return ret
	}

	listRes, lerr := rt.Exec.Call(ctx, rt, "pkg.list_repos", &execpkgrepo.ListReposArgs{})
	if lerr != nil {
		ret.Result = result.Bool(false)
		ret.Comment = fmt.Sprintf("Failed to remove repo %s", name)
		return ret
	}
	repos, _ := listRes.(map[string][]map[string]any)
	if _, stillThere := repos[stripname]; !stillThere {
		ret.Changes["repo"] = name
		ret.Comment = fmt.Sprintf("Removed repo %s", name)

		if !removeKey {
			ret.Result = result.Bool(true)
			return ret
		}
		keyid, kerr := rt.Exec.Call(ctx, rt, "pkg.del_repo_key",
			&execpkgrepo.DelRepoKeyArgs{
				Name:     strPtrState(stripname),
				Keyid:    optString(kw["keyid"]),
				KeyidPPa: optBool(kw["keyid_ppa"]),
			})
		if kerr != nil {
			ret.Result = result.Bool(false)
			ret.Comment += fmt.Sprintf(", but failed to remove key: %v", kerr)
			return ret
		}
		ret.Result = result.Bool(true)
		ret.Changes["keyid"] = keyid
		ret.Comment += fmt.Sprintf(", and keyid %v", keyid)
		return ret
	}

	ret.Result = result.Bool(false)
	ret.Comment = fmt.Sprintf("Failed to remove repo %s", name)
	return ret
}

// --- shared helpers -------------------------------------------------------------

func callGetRepo(ctx context.Context, rt *runtime.Runtime, repo string, kw map[string]any) (map[string]any, error) {
	res, err := rt.Exec.Call(ctx, rt, "pkg.get_repo", &execpkgrepo.GetRepoArgs{Repo: repo, Kwargs: copyMap(kw)})
	if err != nil {
		return nil, err
	}
	dict, _ := res.(map[string]any)
	return dict, nil
}

func kwargPopString(kw map[string]any, key string) (string, bool) {
	v, ok := kw[key].(string)
	if ok {
		delete(kw, key)
	}
	return v, ok
}

func copyMap(src map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range src {
		out[k] = v
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func containsStr(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}

func equalScalar(a, b any) bool {
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok && bok {
		return as == bs
	}
	ab, abok := a.(bool)
	bb, bbok := b.(bool)
	if abok && bbok {
		return ab == bb
	}
	af, affok := a.([]string)
	bf, bffok := b.([]string)
	if affok && bffok {
		return equalSlicesGo(af, bf)
	}
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func toStringSlice(v any) ([]string, bool) {
	switch x := v.(type) {
	case []string:
		return x, true
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out, true
	case string:
		if x == "" {
			return nil, true
		}
		return strings.Split(x, ","), true
	}
	return nil, false
}

func toStringSliceOrEmpty(v any) []string {
	s, _ := toStringSlice(v)
	return s
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, item := range a {
		set[item] = true
	}
	for _, item := range b {
		if !set[item] {
			return false
		}
	}
	return true
}

func equalSlicesGo(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func optString(v any) *string {
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

func optBool(v any) *bool {
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}

func strPtrState(s string) *string { return &s }

func boolPtrState(b bool) *bool { return &b }

// Register installs the pkgrepo state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{
		managedFunc{},
		absentFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
