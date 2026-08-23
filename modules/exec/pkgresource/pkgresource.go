// Package pkgresource implements the Salt-compatible pkg_resource helpers
// consumed by pkg providers and states: pkgs/sources repacking, install
// target parsing, version queries, and installed-package list formatting.
//
// Reference: saltstack/salt/modules/pkg_resource.py @ pinned revision
// (references/salt.lock). Local Salt tree used for the behavioral tests:
// tests/pytests/unit/modules/test_pkg_resource.py.
//
// Contract notes (init.md section 28):
//
//   - Salt resolves helpers through __salt__ lookups guarded by membership
//     checks; StateKit mirrors that with registry Get/Call so absent
//     providers degrade exactly like Salt minions whose pkg module lacks
//     the optional function (normalize_name, version_clean,
//     parse_arch, check_extra_requirements).
//   - _repack_pkgs stays unexported: Salt's loader never exposes
//     underscore-prefixed functions to the CLI, so the private helper is
//     ported as an internal implementation detail of parse_targets.
//   - Typed input replaces Python duck-typing: pkgs/sources accept real
//     lists (structured input) or YAML strings mirroring Salt's
//     utils.yaml.safe_load coercion; malformed strings degrade through the
//     same invalid-element path that makes Salt return an empty dict.
//   - The "__env__" kwarg that Salt pops defensively is rejected upstream
//     as an unknown argument; use saltenv.
//   - Remote package sources (salt|https?|ftp:// recognized by the
//     config.valid_fileproto regex, mirrored locally until the config
//     family lands) need cp.cache_file, which surfaces as
//     UnsupportedError until the cp family is ported; salt:// remains
//     permanently excluded (master-minion architecture).
//   - version_compare falls back to a Go port of distutils LooseVersion
//     tokenization because no platform version_cmp function is registered;
//     invalid operators and incomparable versions return False like
//     salt.utils.versions.compare, not an error.
//   - Intentional divergence: sort_pkglist/stringify raise an error for
//     non-list scalar values where Python would silently decompose strings
//     into characters (and fail on numbers); StateKit refuses the garbage
//     input instead of reproducing it.
//   - parse_targets ignores "sources" on macOS like Salt's grains check;
//     the grains.os == "MacOS" probe maps to GOOS == darwin behind an
//     injectable hook.
package pkgresource

import (
	"context"

	"github.com/friz-zy/statekit/internal/runtime"
)

// NormalizeNameArgs is the canonical request for the optional
// pkg.normalize_name delegate (provider-specific architecture-suffix
// normalization).
type NormalizeNameArgs struct {
	Name string `statekit:"required"`
}

// VersionCleanArgs is the canonical request for the optional
// pkg.version_clean delegate.
type VersionCleanArgs struct {
	VerStr string `statekit:"name=verstr"`
}

// ParseArchArgs is the canonical request for the optional pkg.parse_arch
// delegate; the reply is a map with "name" and "arch" keys.
type ParseArchArgs struct {
	Name string `statekit:"required"`
}

// CheckExtraRequirementsArgs is the canonical request for the optional
// pkg.check_extra_requirements delegate.
type CheckExtraRequirementsArgs struct {
	PkgName string `statekit:"name=pkgname"`
	PkgVer  string `statekit:"name=pkgver"`
}

// lookup reports whether an optional __salt__-style delegate is available,
// mirroring Salt's `"pkg.x" in __salt__` guards.
func lookup(rt *runtime.Runtime, name string) bool {
	_, ok := rt.Exec.Get(name)
	return ok
}

// delegate invokes an optional exec function; availability was checked with
// lookup beforehand, matching Salt's two-step guard.
func delegate(ctx context.Context, rt *runtime.Runtime, name string, args any) (any, error) {
	return rt.Exec.Call(ctx, rt, name, args)
}

// normalizer returns the name-normalization function Salt selects from
// __salt__ (identity when pkg.normalize_name is unavailable).
func normalizer(ctx context.Context, rt *runtime.Runtime, normalize bool) func(string) string {
	identity := func(pkgname string) string { return pkgname }
	if !normalize || !lookup(rt, "pkg.normalize_name") {
		return identity
	}
	return func(pkgname string) string {
		res, err := delegate(ctx, rt, "pkg.normalize_name", &NormalizeNameArgs{Name: pkgname})
		if err != nil {
			return pkgname
		}
		if s, ok := res.(string); ok {
			return s
		}
		return pkgname
	}
}

// isMacOS mirrors Salt's `__grains__["os"] == "MacOS"` probes.
var isMacOS = func(_ context.Context, _ *runtime.Runtime) bool {
	return runtime.CurrentGOOS() == "darwin"
}

// Register installs all pkg_resource-module execution functions. The private
// _repack_pkgs helper intentionally has no registration (see package notes).
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		packSourcesFunc{},
		parseTargetsFunc{},
		versionFunc{},
		addPkgFunc{},
		sortPkglistFunc{},
		stringifyFunc{},
		versionCleanFunc{},
		versionCompareFunc{},
		checkExtraRequirementsFunc{},
		formatPkgListFunc{},
		formatVersionFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
