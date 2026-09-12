package user

// R8.2 registry matrix for the Solaris solaris_user surface: every
// catalog public name registers exactly once through registerSolaris,
// each function is PlatformConstrained to solaris only, GOOS filtering
// hides the names on the Linux host, the registry boundary rejects
// calls on non-solaris hosts, and the Linux user surface stays
// canonical with the solaris additions absent.

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
)

var sunRegistryNames = []string{
	"user.add",
	"user.chfullname",
	"user.chgid",
	"user.chgroups",
	"user.chhome",
	"user.chhomephone",
	"user.chroomnumber",
	"user.chshell",
	"user.chuid",
	"user.chworkphone",
	"user.delete",
	"user.getent",
	"user.info",
	"user.list_groups",
	"user.list_users",
	"user.rename",
}

func TestSunUserRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerSolaris(reg); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != len(sunRegistryNames) {
		t.Fatalf("registered %d functions, want %d", reg.Len(), len(sunRegistryNames))
	}
	for _, name := range sunRegistryNames {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing from solaris registration", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok {
			t.Fatalf("%s is not platform-constrained", name)
		}
		platforms := constrained.Platforms()
		if len(platforms) != 1 || platforms[0] != "solaris" {
			t.Fatalf("%s platforms = %v", name, platforms)
		}
		if !runtime.SupportsPlatform(fn, "solaris") {
			t.Fatalf("%s does not support solaris", name)
		}
		if runtime.SupportsPlatform(fn, "linux") {
			t.Fatalf("%s must not support linux", name)
		}
	}
	names := reg.Names()
	if runtime.CurrentGOOS() != "solaris" {
		if len(names) != 0 {
			t.Fatalf("host registry leaked solaris user names: %v", names)
		}
	} else if !reflect.DeepEqual(names, sunRegistryNames) {
		t.Fatalf("solaris registry names = %v", names)
	}
	if runtime.CurrentGOOS() != "solaris" {
		_, err := reg.Call(context.Background(), &runtime.Runtime{}, "user.chfullname", &sunChfullnameArgs{})
		var unsupported *runtime.UnsupportedError
		if !errors.As(err, &unsupported) {
			t.Fatalf("user.chfullname on host err=%v, want UnsupportedError", err)
		}
	}
	if err := registerSolaris(reg); err == nil {
		t.Fatalf("duplicate solaris registration accepted")
	}
}

// TestSunUserRegisterKeepsLinuxSurfaceCanonical proves the solaris
// dispatch adds no duplicate user.* registration on the Linux host.
func TestSunUserRegisterKeepsLinuxSurfaceCanonical(t *testing.T) {
	if runtime.CurrentGOOS() == "solaris" {
		t.Skip("solaris host registers the solaris surface")
	}
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"user.chfullname", "user.chgroups", "user.chhomephone", "user.chroomnumber",
		"user.chworkphone", "user.getent", "user.list_groups", "user.rename",
	} {
		if _, exists := reg.Get(name); exists {
			t.Fatalf("linux registry unexpectedly carries solaris-only %s", name)
		}
	}
	for _, name := range []string{"user.add", "user.delete", "user.info", "user.list_users"} {
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
