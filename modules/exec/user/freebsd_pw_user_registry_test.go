package user

// R8.1 registry matrix for the FreeBSD pw_user surface: every catalog
// public name registers exactly once through registerFreeBSD, each
// function is PlatformConstrained to freebsd only, GOOS filtering hides
// the names on the Linux host, the registry boundary rejects calls on
// non-freebsd hosts, and the Linux user surface stays canonical on
// Linux with the freebsd additions (loginclass/GECOS-phone getters)
// absent.

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
)

var pwRegistryNames = []string{
	"user.add",
	"user.chfullname",
	"user.chgid",
	"user.chgroups",
	"user.chhome",
	"user.chhomephone",
	"user.chloginclass",
	"user.chroomnumber",
	"user.chshell",
	"user.chuid",
	"user.chworkphone",
	"user.delete",
	"user.get_loginclass",
	"user.getent",
	"user.info",
	"user.list_groups",
	"user.list_users",
	"user.primary_group",
	"user.rename",
}

func TestPwUserRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerFreeBSD(reg); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != len(pwRegistryNames) {
		t.Fatalf("registered %d functions, want %d", reg.Len(), len(pwRegistryNames))
	}
	for _, name := range pwRegistryNames {
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
	names := reg.Names()
	if runtime.CurrentGOOS() != "freebsd" {
		if len(names) != 0 {
			t.Fatalf("linux registry leaked freebsd user names: %v", names)
		}
	} else if !reflect.DeepEqual(names, pwRegistryNames) {
		t.Fatalf("freebsd registry names = %v", names)
	}
	if runtime.CurrentGOOS() != "freebsd" {
		_, err := reg.Call(context.Background(), &runtime.Runtime{}, "user.chloginclass", &pwChloginclassArgs{})
		var unsupported *runtime.UnsupportedError
		if !errors.As(err, &unsupported) {
			t.Fatalf("user.chloginclass on linux err=%v, want UnsupportedError", err)
		}
	}
	if err := registerFreeBSD(reg); err == nil {
		t.Fatalf("duplicate freebsd registration accepted")
	}
}

// TestPwUserRegisterKeepsLinuxSurfaceCanonical proves the freebsd file
// adds no duplicate user.* registration on the Linux host.
func TestPwUserRegisterKeepsLinuxSurfaceCanonical(t *testing.T) {
	if runtime.CurrentGOOS() == "freebsd" {
		t.Skip("freebsd host registers the freebsd surface")
	}
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"user.chhomephone", "user.chloginclass", "user.chroomnumber", "user.chworkphone",
		"user.get_loginclass", "user.getent", "user.primary_group", "user.rename",
		"user.chgroups", "user.chfullname",
	} {
		if _, exists := reg.Get(name); exists {
			t.Fatalf("linux registry unexpectedly carries freebsd-only %s", name)
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
