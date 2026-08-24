// Package pkgrepo implements Salt's APT repository-management surface:
// sources.list / deb822 (.sources) handling plus the GPG key helpers, over
// the central Runner and the injectable filesystem.
//
// Reference: saltstack/salt/modules/aptpkg.py @ pinned revision
// (references/salt.lock); engine ported from saltstack/salt/utils/pkg/deb.py.
// Behavioral tests mapped from
// saltstack/tests/pytests/unit/modules/test_aptpkg.py.
//
// Contract notes (init.md section 28):
//
//   - aptpkg registers under Salt's virtual "pkg" module, so every function
//     keeps its CLI-facing pkg.* name while living in this package; the
//     coverage tooling attributes them to the pkg family like upstream's
//     loader does.
//   - The Launchpad PPA fallback keeps upstream's argument-order quirk in
//     del_repo (LP_PVT_SRC_FORMAT receives DIST before OWNER) verbatim;
//     mod_repo/get_repo use the correct order.
//   - _get_http_proxy_url reads minion config through config.option
//     delegates that StateKit does not ship yet, so proxy env injection for
//     apt-key calls stays inert unless a config.option function is
//     registered (same degradation model as pkg_resource).
//   - cp.cache_file is unavailable until the cp family lands: local absolute
//     paths pass through, remote schemes surface UnsupportedError, salt://
//     stays permanently excluded (master-minion architecture).
//   - systemd-run scoping from _call_apt is not reproduced; commands run
//     directly (documented divergence). The dpkg-lock retry backoff,
//     including its "%s/100"-versus-cap-at-ten mismatch, is preserved.
//   - Upstream bugs kept verbatim where observable: get_repo_keys returns an
//     undefined local on apt-key failure (StateKit raises an explicit error
//   - documented divergence), _decrypt_key returns the .decrypted path even
//     when dearmoring failed, del_repo_key formats LP_PVT_SRC_FORMAT with a
//     swapped argument order, and the SyntaxError guard around
//     _split_repo_str is dead code because parse raises SaltInvocationError.
//   - Truncated gpg --with-colons records crash upstream on blind indexing;
//     StateKit fills missing fields with None instead of raising.
//   - Set-difference rebuilds keep first-seen component order where Python's
//     set iteration is nondeterministic.
package pkgrepo

import (
	"context"

	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts this module to linux, mirroring aptpkg.__virtual__.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

type ListReposArgs struct{}

type listReposFunc struct{ linuxOnly }

func (listReposFunc) Name() string { return "pkg.list_repos" }
func (listReposFunc) Args() any    { return ListReposArgs{} }
func (listReposFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return listRepos(rt)
}

type GetRepoArgs struct {
	Repo   string         `statekit:"required"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type getRepoFunc struct{ linuxOnly }

func (getRepoFunc) Name() string { return "pkg.get_repo" }
func (getRepoFunc) Args() any    { return GetRepoArgs{} }
func (getRepoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetRepoArgs)
	return getRepo(rt, a.Repo, a.Kwargs)
}

type DelRepoArgs struct {
	Repo   string         `statekit:"required"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type delRepoFunc struct{ linuxOnly }

func (delRepoFunc) Name() string { return "pkg.del_repo" }
func (delRepoFunc) Args() any    { return DelRepoArgs{} }
func (delRepoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DelRepoArgs)
	return delRepo(ctx, rt, a.Repo, a.Kwargs)
}

type ModRepoArgs struct {
	Repo    string         `statekit:"required"`
	Saltenv *string        `statekit:"name=saltenv"`
	Aptkey  *bool          `statekit:"name=aptkey"`
	Kwargs  map[string]any `statekit:"name=kwargs"`
}

type modRepoFunc struct{ linuxOnly }

func (modRepoFunc) Name() string { return "pkg.mod_repo" }
func (modRepoFunc) Args() any    { return ModRepoArgs{} }
func (modRepoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ModRepoArgs)
	saltenv := "base"
	if a.Saltenv != nil {
		saltenv = *a.Saltenv
	}
	aptkey := true
	if a.Aptkey != nil {
		aptkey = *a.Aptkey
	}
	return modRepo(ctx, rt, a.Repo, saltenv, aptkey, a.Kwargs)
}

type GetRepoKeysArgs struct {
	Aptkey *bool   `statekit:"name=aptkey"`
	Keydir *string `statekit:"name=keydir"`
}

type getRepoKeysFunc struct{ linuxOnly }

func (getRepoKeysFunc) Name() string { return "pkg.get_repo_keys" }
func (getRepoKeysFunc) Args() any    { return GetRepoKeysArgs{} }
func (getRepoKeysFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetRepoKeysArgs)
	aptkey := true
	if a.Aptkey != nil {
		aptkey = *a.Aptkey
	}
	keydir := ""
	if a.Keydir != nil {
		keydir = *a.Keydir
	}
	return getRepoKeysInternal(ctx, rt, aptkey, keydir)
}

type AddRepoKeyArgs struct {
	Path      *string `statekit:"name=path"`
	Text      *string `statekit:"name=text"`
	Keyserver *string `statekit:"name=keyserver"`
	Keyid     *string `statekit:"name=keyid"`
	Saltenv   *string `statekit:"name=saltenv"`
	Aptkey    *bool   `statekit:"name=aptkey"`
	Keydir    *string `statekit:"name=keydir"`
	Keyfile   *string `statekit:"name=keyfile"`
}

type addRepoKeyFunc struct{ linuxOnly }

func (addRepoKeyFunc) Name() string { return "pkg.add_repo_key" }
func (addRepoKeyFunc) Args() any    { return AddRepoKeyArgs{} }
func (addRepoKeyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AddRepoKeyArgs)
	req := addRepoKeyRequest{aptkey: true, saltenv: "base"}
	if a.Path != nil {
		req.path = *a.Path
	}
	if a.Text != nil {
		req.text = *a.Text
	}
	if a.Keyserver != nil {
		req.keyserver = *a.Keyserver
	}
	if a.Keyid != nil {
		req.keyid = *a.Keyid
	}
	if a.Saltenv != nil {
		req.saltenv = *a.Saltenv
	}
	if a.Aptkey != nil {
		req.aptkey = *a.Aptkey
	}
	if a.Keydir != nil {
		req.keydir = *a.Keydir
	}
	if a.Keyfile != nil {
		req.keyfile = *a.Keyfile
	}
	ok, err := addRepoKeyInternal(ctx, rt, req)
	if err != nil {
		return nil, err
	}
	return ok, nil
}

type DelRepoKeyArgs struct {
	Name     *string `statekit:"name=name"`
	Aptkey   *bool   `statekit:"name=aptkey"`
	Keydir   *string `statekit:"name=keydir"`
	Keyid    *string `statekit:"name=keyid"`
	KeyidPPa *bool   `statekit:"name=keyid_ppa"`
}

type delRepoKeyFunc struct{ linuxOnly }

func (delRepoKeyFunc) Name() string { return "pkg.del_repo_key" }
func (delRepoKeyFunc) Args() any    { return DelRepoKeyArgs{} }
func (delRepoKeyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DelRepoKeyArgs)
	aptkey := true
	if a.Aptkey != nil {
		aptkey = *a.Aptkey
	}
	name := ""
	if a.Name != nil {
		name = *a.Name
	}
	keydir := ""
	if a.Keydir != nil {
		keydir = *a.Keydir
	}
	keyid := ""
	if a.Keyid != nil {
		keyid = *a.Keyid
	}
	keyidPPA := false
	if a.KeyidPPa != nil {
		keyidPPA = *a.KeyidPPa
	}
	return delRepoKeyInternal(ctx, rt, name, aptkey, keydir, keyid, keyidPPA)
}

// Register installs all pkgrepo-module execution functions under their
// CLI-facing pkg.* names.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		listReposFunc{},
		getRepoFunc{},
		delRepoFunc{},
		modRepoFunc{},
		getRepoKeysFunc{},
		addRepoKeyFunc{},
		delRepoKeyFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
