package facts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseOSRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "os-release")
	content := `NAME="Ubuntu"
VERSION="24.04.1 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="24.04"
VERSION_CODENAME=noble
# a comment
BAD_LINE_WITHOUT_EQUALS
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	release := parseOSRelease(path)
	if release["NAME"] != "Ubuntu" || release["ID"] != "ubuntu" ||
		release["VERSION_ID"] != "24.04" || release["VERSION_CODENAME"] != "noble" {
		t.Fatalf("parsed = %v", release)
	}
	if _, present := release["BAD_LINE_WITHOUT_EQUALS"]; present {
		t.Fatal("malformed line must be skipped")
	}
	if got := versionCodename(release["VERSION"]); got != "Noble Numbat" {
		t.Fatalf("fallback codename = %q", got)
	}
}

func TestOSFamilyMapping(t *testing.T) {
	cases := map[string]string{
		"debian": FamilyDebian, "ubuntu": FamilyDebian,
		"fedora": FamilyRedHat, "rhel": FamilyRedHat, "amzn": FamilyRedHat,
		"opensuse-leap": FamilySuse, "sles": FamilySuse,
		"arch": FamilyArch, "alpine": FamilyAlpine, "gentoo": FamilyGentoo,
	}
	for id, want := range cases {
		if got := OSFamily(id, ""); got != want {
			t.Fatalf("OSFamily(%q) = %q, want %q", id, got, want)
		}
	}
	if got := OSFamily("unknownos", "debian somewhere"); got != FamilyDebian {
		t.Fatalf("ID_LIKE fallback failed: %q", got)
	}
	if got := OSFamily("unknownos", ""); got != FamilyUnknown {
		t.Fatalf("unknown family = %q", got)
	}
}

func TestForTestingOverridesAndMarshal(t *testing.T) {
	f := ForTesting(Overrides{
		OS:   &OSFacts{ID: "alpine", Name: "Alpine Linux", Family: FamilyAlpine, Version: "3.20"},
		Host: &HostFacts{Hostname: "test-host", Username: "tester", UID: 1000, GID: 1000},
	})
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var snap struct {
		OS   OSFacts   `json:"os"`
		Host HostFacts `json:"host"`
		Init InitFacts `json:"init"`
	}
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if snap.OS.ID != "alpine" || snap.Host.Hostname != "test-host" {
		t.Fatalf("snapshot lost injected values: %s", data)
	}
}

func TestDetectDoesNotPanic(t *testing.T) {
	f := Detect(nil)
	snap := f.snapshot()
	if f.PackageManager() != snap.Package.Manager {
		t.Fatal("lazy package manager cache inconsistent")
	}
	if f.InitSystem() != snap.Init.System {
		t.Fatal("lazy init cache inconsistent")
	}
	sec := f.Security()
	if sec.SELinux != snap.Security.SELinux || sec.AppArmor != snap.Security.AppArmor {
		t.Fatal("lazy security cache inconsistent")
	}
}
