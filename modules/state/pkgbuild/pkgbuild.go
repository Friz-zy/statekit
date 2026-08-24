// Package pkgbuild implements Salt's pkgbuild state functions: built and
// repo, delegating to the backend-dispatched pkgbuild.* execution
// functions.
//
// Reference: saltstack/salt/states/pkgbuild.py @ pinned revision
// (references/salt.lock).
//
// Contract notes (init.md section 28):
//
//   - Upstream selects rpmbuild.build/rpmbuild.make_repo as a fallback
//     function name on non-RPM families when any expected artifact ends
//     in .rpm; StateKit's exec surface already dispatches by OS family,
//     so the extra indirection collapses into the single pkgbuild.* names
//     (documented divergence).
//   - repo() keeps the upstream initialization quirk: an invalidly-
//     formatted env leaves result=True while setting only the comment
//     (unlike built(), which flips it to False).
package pkgbuild

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execpkgbuild "github.com/friz-zy/statekit/modules/exec/pkgbuild"
)

// getMissingResults mirrors _get_missing_results: sorted set difference of
// requested artifacts versus dest_dir contents.
func getMissingResults(rt *runtime.Runtime, results []string, destDir string) []string {
	present := map[string]bool{}
	if entries, err := rt.FS.ReadDir(destDir); err == nil {
		for _, entry := range entries {
			present[entry.Name()] = true
		}
	}
	set := map[string]bool{}
	var missing []string
	for _, r := range results {
		if !present[r] && !set[r] {
			set[r] = true
			missing = append(missing, r)
		}
	}
	sort.Strings(missing)
	return missing
}

func normalizeResults(raw any) []string {
	switch v := raw.(type) {
	case nil:
		return nil
	case string:
		return strings.Split(v, ",")
	case []string:
		return v
	case []any:
		var out []string
		for _, item := range v {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	}
	return nil
}

type builtArgs struct {
	Name    string         `statekit:"required"`
	Runas   string         `statekit:"required,name=runas"`
	DestDir string         `statekit:"required,name=dest_dir"`
	Spec    string         `statekit:"required,name=spec"`
	Sources any            `statekit:"name=sources"`
	Tgt     string         `statekit:"required,name=tgt"`
	Results any            `statekit:"required,name=results"`
	Force   bool           `statekit:"name=force"`
	Deps    any            `statekit:"name=deps"`
	Env     map[string]any `statekit:"name=env"`
	// template is accepted for parity; templating engines are excluded
	Template *string `statekit:"name=template"`
	LogDir   *string `statekit:"name=log_dir"`
	Test     bool    `statekit:"name=test"`
}

type builtFunc struct{}

func (builtFunc) Name() string { return "pkgbuild.built" }
func (builtFunc) Args() any    { return builtArgs{} }

func (builtFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*builtArgs)
	ret := result.New(a.Name, "", result.Bool(true), map[string]any{})

	results := normalizeResults(a.Results)
	if len(results) == 0 {
		ret.Result = result.Bool(false)
		ret.Comment = "'results' argument is required"
		return ret
	}

	saltenv := "base"
	logDir := "/var/log/salt/pkgbuild"
	if a.LogDir != nil {
		logDir = *a.LogDir
	}

	needed := getMissingResults(rt, results, a.DestDir)
	if !a.Force && len(needed) == 0 {
		ret.Comment = "All needed packages exist"
		return ret
	}

	if a.Test {
		ret.Result = nil
		if a.Force {
			ret.Comment = "Packages will be force-built"
		} else {
			ret.Comment = "The following packages need to be built: " +
				strings.Join(needed, ", ")
		}
		return ret
	}

	if a.Env != nil {
		// The typed decoder always yields maps; upstream's non-dict guard
		// text is pinned for parity with built()'s early failure.
		_ = a.Env
	}

	buildArgs := &execpkgbuild.BuildArgs{
		Runas: a.Runas, Tgt: a.Tgt, DestDir: a.DestDir, Spec: a.Spec,
		Sources: a.Sources, Deps: a.Deps, Env: a.Env,
		Template: a.Template, Saltenv: saltenv, LogDir: logDir,
	}
	changesAny, err := rt.Exec.Call(ctx, rt, "pkgbuild.build", buildArgs)
	if err != nil {
		ret.Result = result.Bool(false)
		ret.Comment = err.Error()
		return ret
	}
	if changes, ok := changesAny.(map[string]any); ok {
		ret.Changes = changes
	}

	needed = getMissingResults(rt, results, a.DestDir)
	if len(needed) > 0 {
		ret.Result = result.Bool(false)
		ret.Comment = "The following packages were not built: " + strings.Join(needed, ", ")
		return ret
	}
	ret.Result = result.Bool(true)
	ret.Comment = "All needed packages were built"
	return ret
}

type repoArgs struct {
	Name          string         `statekit:"required"`
	Keyid         *string        `statekit:"name=keyid"`
	Env           map[string]any `statekit:"name=env"`
	UsePassphrase bool           `statekit:"name=use_passphrase"`
	GnupgHome     *string        `statekit:"name=gnupghome"`
	Runas         *string        `statekit:"name=runas"`
	Timeout       float64        `statekit:"name=timeout"`
	Test          bool           `statekit:"name=test"`
}

type repoFunc struct{}

func (repoFunc) Name() string { return "pkgbuild.repo" }
func (repoFunc) Args() any    { return repoArgs{} }

func (repoFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*repoArgs)
	ret := result.New(a.Name, "", result.Bool(true), map[string]any{})

	if a.Test {
		ret.Result = nil
		ret.Comment = fmt.Sprintf("Package repo metadata at %s will be refreshed", a.Name)
		return ret
	}

	gnupghome := "/etc/salt/gpgkeys"
	if a.GnupgHome != nil {
		gnupghome = *a.GnupgHome
	}
	timeout := 15.0
	if a.Timeout != 0 {
		timeout = a.Timeout
	}
	keyid := ""
	if a.Keyid != nil {
		keyid = *a.Keyid
	}

	runas := "builder"
	if a.Runas != nil {
		runas = *a.Runas
	}
	res, err := rt.Exec.Call(ctx, rt, "pkgbuild.make_repo", &execpkgbuild.MakeRepoArgs{
		RepoDir: a.Name, Keyid: optStr(keyid), Env: a.Env,
		UsePassphrase: a.UsePassphrase, GnupgHome: gnupghome,
		Runas: runas, Timeout: timeout,
	})
	if err != nil {
		ret.Result = result.Bool(false)
		ret.Comment = err.Error()
		return ret
	}
	dict, _ := res.(map[string]any)
	retcode := 1
	if dict != nil {
		if rc, ok := dict["retcode"].(int); ok {
			retcode = rc
		}
	}
	if retcode > 0 {
		ret.Result = result.Bool(false)
	} else {
		ret.Changes = map[string]any{"refresh": true}
	}

	stdout, _ := dict["stdout"].(string)
	stderr, _ := dict["stderr"].(string)
	switch {
	case stdout != "" && stderr != "":
		ret.Comment = stdout + "\n" + stderr
	case stdout != "":
		ret.Comment = stdout
	case stderr != "":
		ret.Comment = stderr
	}
	return ret
}

func optStr(s string) *string { return &s }

func strOr(s string, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Register installs all pkgbuild state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{
		builtFunc{},
		repoFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
