package pkg

// R8.1 registry matrix for the FreeBSD pkgng surface: every catalog
// public name registers exactly once through registerFreeBSD, each
// function is PlatformConstrained to freebsd only, GOOS filtering hides
// the names on the Linux host (the fact-driven gating equivalent of
// Salt's __virtual__ check), the registry boundary rejects calls on
// non-freebsd hosts, and Register keeps the Linux surface canonical on
// Linux while the FreeBSD surface stays a separate registration path.

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
)

var pkgngRegistryNames = []string{
	"pkg.autoremove",
	"pkg.audit",
	"pkg.backup",
	"pkg.check",
	"pkg.clean",
	"pkg.fetch",
	"pkg.hold",
	"pkg.latest_version",
	"pkg.list_locked",
	"pkg.list_pkgs",
	"pkg.list_upgrades",
	"pkg.lock",
	"pkg.locked",
	"pkg.parse_config",
	"pkg.refresh_db",
	"pkg.remove",
	"pkg.restore",
	"pkg.search",
	"pkg.stats",
	"pkg.unhold",
	"pkg.unlock",
	"pkg.update_package_site",
	"pkg.upgrade",
	"pkg.updating",
	"pkg.version",
	"pkg.version_cmp",
	"pkg.which",
	"pkg.install",
}

func TestPkgngRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerFreeBSD(reg); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != len(pkgngRegistryNames) {
		t.Fatalf("registered %d functions, want %d", reg.Len(), len(pkgngRegistryNames))
	}
	for _, name := range pkgngRegistryNames {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing from freebsd registration", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok {
			t.Fatalf("%s is not platform-constrained", name)
		}
		platforms := constrained.Platforms()
		if len(platforms) != 1 || platforms[0] != "freebsd" {
			t.Fatalf("%s platforms = %v", name, platforms)
		}
		if !runtime.SupportsPlatform(fn, "freebsd") {
			t.Fatalf("%s does not support freebsd", name)
		}
		if runtime.CurrentGOOS() != "freebsd" && runtime.SupportsPlatform(fn, "linux") {
			t.Fatalf("%s must not support linux", name)
		}
	}

	// GOOS filtering: on the Linux test host the constrained names are
	// hidden from the registry enumeration; on a freebsd host they are
	// the canonical surface.
	names := reg.Names()
	if runtime.CurrentGOOS() != "freebsd" {
		if len(names) != 0 {
			t.Fatalf("linux registry leaked freebsd names: %v", names)
		}
	} else if !reflect.DeepEqual(names, pkgngRegistryNames) && !equalSets(names, pkgngRegistryNames) {
		t.Fatalf("freebsd registry names = %v", names)
	}

	// The registry boundary rejects a constrained function on a
	// non-freebsd host before any Runner interaction.
	if runtime.CurrentGOOS() != "freebsd" {
		_, err := reg.Call(context.Background(), &runtime.Runtime{}, "pkg.audit", &PkgngAuditArgs{})
		var unsupported *runtime.UnsupportedError
		if !errors.As(err, &unsupported) {
			t.Fatalf("pkg.audit on linux err=%v, want UnsupportedError", err)
		}
	}

	// Double registration is rejected: one canonical registration each.
	if err := registerFreeBSD(reg); err == nil {
		t.Fatalf("duplicate freebsd registration accepted")
	}
}

// TestPkgngRegisterKeepsLinuxSurfaceCanonical proves the freebsd file
// adds no duplicate pkg.* registration on the Linux host: Register
// produces exactly the historical Linux names, none of the
// freebsd-only additions.
func TestPkgngRegisterKeepsLinuxSurfaceCanonical(t *testing.T) {
	if runtime.CurrentGOOS() == "freebsd" {
		t.Skip("freebsd host registers the freebsd surface")
	}
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	// Only the names the Linux surface does not already register; the
	// shared virtual names (autoremove, search, which, version_cmp,
	// list_upgrades, hold/unhold, upgrade, ...) stay canonical through
	// the Linux providers and are re-registered per-platform on freebsd.
	for _, name := range []string{
		"pkg.audit", "pkg.backup", "pkg.check", "pkg.clean", "pkg.fetch",
		"pkg.list_locked", "pkg.locked", "pkg.lock", "pkg.unlock",
		"pkg.parse_config", "pkg.restore", "pkg.stats",
		"pkg.update_package_site", "pkg.updating",
	} {
		if _, exists := reg.Get(name); exists {
			t.Fatalf("linux registry unexpectedly carries freebsd-only %s", name)
		}
	}
	for _, name := range []string{"pkg.version", "pkg.list_pkgs", "pkg.install", "pkg.remove", "pkg.hold", "pkg.autoremove", "pkg.search", "pkg.which"} {
		count := 0
		for _, registered := range reg.Names() {
			if registered == name {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s registered %d times on linux", name, count)
		}
	}
}

func equalSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, name := range a {
		set[name] = true
	}
	for _, name := range b {
		if !set[name] {
			return false
		}
	}
	return true
}
