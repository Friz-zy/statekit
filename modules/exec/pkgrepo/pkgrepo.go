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
//   - Salt's virtual-module selection is mirrored: one set of pkg.* names
//     dispatches on OS family — aptpkg on Debian-family hosts,
//     yumpkg on RedHat-family hosts, zypperpkg on SUSE-family hosts. The
//     key trio exists only in the apt provider module and reports
//     unsupported elsewhere.
//   - The _Zypper wrapper ports argv assembly (--non-interactive, --xmlout,
//     --no-refresh unless refreshable, --root), exit-code classification
//     (success 0/100-103, warnings 6/7/106/107), XML <message type="error">
//     extraction, and the lock-7 retry loop with its five-second waits;
//     systemd-run scoping is not reproduced and event.fire_master
//     notifications are dropped (master-minion architecture, excluded).
//   - The yum INI machinery ports configparser semantics verbatim:
//     lowercased keys, first-occurring "=" / ":" delimiter, indented
//     continuation lines joined with "\n", strict duplicate detection,
//     MissingSectionHeaderError degrading _parse_repo_file to ("", {}).
//   - yumpkg.mod_repo writes every non-dunder kwarg into the stanza
//     (basedir included — upstream never filters it) and keeps False and
//     numeric zero through the blank-value deletion because Python
//     evaluates False == 0; both quirks pinned by tests. Option apply
//     order is sorted where upstream preserves request insertion order
//     (Go map decoding loses it — documented divergence).
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
	"fmt"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts this module to linux, mirroring the pkg providers'
// __virtual__ guards.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// backendOf mirrors Salt's virtual-module selection: one pkg.* surface,
// backed by aptpkg on Debian-family hosts, yumpkg on RedHat-family hosts,
// and zypperpkg on SUSE-family hosts.
func backendOf(rt *runtime.Runtime) (string, error) {
	if rt.Facts == nil {
		return "", fmt.Errorf("The pkg module could not be loaded: unsupported OS family")
	}
	switch rt.Facts.OS().Family {
	case facts.FamilyDebian:
		return "apt", nil
	case facts.FamilyRedHat:
		return "yum", nil
	case facts.FamilySuse:
		return "zypper", nil
	}
	return "", fmt.Errorf("The pkg module could not be loaded: unsupported OS family")
}

// kwargStrict extracts strict_config from kwargs (default true).
func kwargStrict(kwargs map[string]any) bool {
	if v, ok := kwargs["strict_config"]; ok {
		return isTrue(v)
	}
	return true
}

// kwargBasedir pulls the basedir value in string-or-list form.
func kwargBasedir(kwargs map[string]any) any {
	if v, ok := kwargs["basedir"]; ok {
		return v
	}
	return nil
}

// unsupportedOnBackend reports provider functions that exist only in one
// Salt provider module (the key trio is aptpkg-only).
func unsupportedOnBackend(fn, backend string) error {
	return &runtime.UnsupportedError{Kind: "function", Name: fn + " (" + backend + ")"}
}

type ListReposArgs struct {
	Basedir      *string `statekit:"name=basedir"`
	StrictConfig *bool   `statekit:"name=strict_config"`
	Root         *string `statekit:"name=root"`
}

type listReposFunc struct{ linuxOnly }

func (listReposFunc) Name() string { return "pkg.list_repos" }
func (listReposFunc) Args() any    { return ListReposArgs{} }
func (listReposFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListReposArgs)
	backend, err := backendOf(rt)
	if err != nil {
		return nil, err
	}
	switch backend {
	case "apt":
		return listRepos(rt)
	case "yum":
		basedir := any(nil)
		if a.Basedir != nil {
			basedir = *a.Basedir
		}
		strict := true
		if a.StrictConfig != nil {
			strict = *a.StrictConfig
		}
		return yumListRepos(rt, basedir, strict)
	default:
		root := ""
		if a.Root != nil {
			root = *a.Root
		}
		return zypperListRepos(rt, root)
	}
}

type GetRepoArgs struct {
	Repo         string         `statekit:"required"`
	Kwargs       map[string]any `statekit:"name=kwargs"`
	Basedir      *string        `statekit:"name=basedir"`
	StrictConfig *bool          `statekit:"name=strict_config"`
	Root         *string        `statekit:"name=root"`
}

type getRepoFunc struct{ linuxOnly }

func (getRepoFunc) Name() string { return "pkg.get_repo" }
func (getRepoFunc) Args() any    { return GetRepoArgs{} }
func (getRepoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetRepoArgs)
	backend, err := backendOf(rt)
	if err != nil {
		return nil, err
	}
	switch backend {
	case "apt":
		return getRepo(rt, a.Repo, a.Kwargs)
	case "yum":
		return yumGetRepo(rt, a.Repo, basedirOrKwarg(a.Basedir, a.Kwargs), strictOrKwarg(a.StrictConfig, a.Kwargs))
	default:
		root := ""
		if a.Root != nil {
			root = *a.Root
		}
		return zypperGetRepo(rt, a.Repo, root)
	}
}

// basedirOrKwarg prefers the named CLI field over the kwargs entry.
func basedirOrKwarg(field *string, kwargs map[string]any) any {
	if field != nil {
		return *field
	}
	return kwargBasedir(kwargs)
}

func strictOrKwarg(field *bool, kwargs map[string]any) bool {
	if field != nil {
		return *field
	}
	return kwargStrict(kwargs)
}

type DelRepoArgs struct {
	Repo         string         `statekit:"required"`
	Kwargs       map[string]any `statekit:"name=kwargs"`
	Basedir      *string        `statekit:"name=basedir"`
	StrictConfig *bool          `statekit:"name=strict_config"`
	Root         *string        `statekit:"name=root"`
}

type delRepoFunc struct{ linuxOnly }

func (delRepoFunc) Name() string { return "pkg.del_repo" }
func (delRepoFunc) Args() any    { return DelRepoArgs{} }
func (delRepoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DelRepoArgs)
	backend, err := backendOf(rt)
	if err != nil {
		return nil, err
	}
	switch backend {
	case "apt":
		return delRepo(ctx, rt, a.Repo, a.Kwargs)
	case "yum":
		ret, derr := yumDelRepo(ctx, rt, a.Repo,
			basedirOrKwarg(a.Basedir, a.Kwargs), strictOrKwarg(a.StrictConfig, a.Kwargs))
		if derr != nil {
			return nil, derr
		}
		return ret, nil
	default:
		root := ""
		if a.Root != nil {
			root = *a.Root
		}
		return zypperDelRepo(ctx, rt, a.Repo, root)
	}
}

type ModRepoArgs struct {
	Repo         string         `statekit:"required"`
	Kwargs       map[string]any `statekit:"name=kwargs"`
	Saltenv      *string        `statekit:"name=saltenv"`
	Aptkey       *bool          `statekit:"name=aptkey"`
	Basedir      *string        `statekit:"name=basedir"`
	StrictConfig *bool          `statekit:"name=strict_config"`
	Root         *string        `statekit:"name=root"`
}

type modRepoFunc struct{ linuxOnly }

func (modRepoFunc) Name() string { return "pkg.mod_repo" }
func (modRepoFunc) Args() any    { return ModRepoArgs{} }
func (modRepoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ModRepoArgs)
	backend, err := backendOf(rt)
	if err != nil {
		return nil, err
	}
	saltenv := "base"
	if a.Saltenv != nil {
		saltenv = *a.Saltenv
	}
	aptkey := true
	if a.Aptkey != nil {
		aptkey = *a.Aptkey
	}
	switch backend {
	case "apt":
		return modRepo(ctx, rt, a.Repo, saltenv, aptkey, a.Kwargs)
	case "yum":
		return yumModRepo(ctx, rt, a.Repo,
			basedirOrKwarg(a.Basedir, a.Kwargs), strictOrKwarg(a.StrictConfig, a.Kwargs), a.Kwargs)
	default:
		root := ""
		if a.Root != nil {
			root = *a.Root
		}
		return zypperModRepo(ctx, rt, a.Repo, root, a.Kwargs)
	}
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
	backend, err := backendOf(rt)
	if err != nil {
		return nil, err
	}
	if backend != "apt" {
		return nil, unsupportedOnBackend("pkg.get_repo_keys", backend)
	}
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
	backend, err := backendOf(rt)
	if err != nil {
		return nil, err
	}
	if backend != "apt" {
		return nil, unsupportedOnBackend("pkg.add_repo_key", backend)
	}
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
	backend, err := backendOf(rt)
	if err != nil {
		return nil, err
	}
	if backend != "apt" {
		return nil, unsupportedOnBackend("pkg.del_repo_key", backend)
	}
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
