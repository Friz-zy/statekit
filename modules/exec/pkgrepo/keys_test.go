package pkgrepo

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// Key-management tests mapped onto
// saltstack/tests/pytests/unit/modules/test_aptpkg.py:
// test_add_repo_key*, test_get_repo_keys, test__decrypt_key*,
// test_get_key_from_id_*, and test_del_repo_key_*.

const aptKeyList = `
pub:-:1024:17:46181433FBB75451:1104433784:::-:::scSC:
fpr:::::::::C5986B4F1257FFA86632CBA746181433FBB75451:
uid:-::::1104433784::B4D41942D4B35FF44182C7F9D00C99AF27B93AD0::Ubuntu CD Image Automatic Signing Key <cdimage@ubuntu.com>:
`

type fakeRunner struct {
	results map[string]process.CommandResult
	calls   [][]string
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	f.calls = append(f.calls, argv)
	if res, ok := f.results[strings.Join(argv, " ")]; ok {
		return res
	}
	return process.CommandResult{}
}

const aptKeyAdvArgv = "apt-key adv --batch --list-public-keys --with-fingerprint --with-fingerprint --with-colons --fixed-list-mode"

func keysRT(t *testing.T, results map[string]process.CommandResult) (*runtime.Runtime, *fakeRunner) {
	t.Helper()
	redirectPaths(t)
	runner := &fakeRunner{results: results}
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts:  factsForTesting(),
		Runner: runner,
	}
	mustWrite(rt, "/testbed/sources.list", "")
	return rt, runner
}

// Mirrors test_get_repo_keys via the repo_keys_var fixture.
func TestParseRepoKeysOutput(t *testing.T) {
	ret := parseRepoKeysOutput(aptKeyList)
	want := map[string]map[string]any{
		"46181433FBB75451": {
			"algorithm":       17,
			"bits":            1024,
			"capability":      "scSC",
			"date_creation":   1104433784,
			"date_expiration": nil,
			"fingerprint":     "C5986B4F1257FFA86632CBA746181433FBB75451",
			"keyid":           "46181433FBB75451",
			"uid":             "Ubuntu CD Image Automatic Signing Key <cdimage@ubuntu.com>",
			"uid_hash":        "B4D41942D4B35FF44182C7F9D00C99AF27B93AD0",
			"validity":        "-",
		},
	}
	if len(ret) != len(want) {
		t.Fatalf("keys = %#v", ret)
	}
	for keyid, props := range want {
		got, ok := ret[keyid]
		if !ok {
			t.Fatalf("missing key %s in %#v", keyid, ret)
		}
		for field, value := range props {
			if got[field] != value {
				t.Fatalf("%s.%s = %#v; want %#v", keyid, field, got[field], value)
			}
		}
	}
}

// Mirrors test_get_repo_keys (apt-key binary path).
func TestGetRepoKeysAptKeyPath(t *testing.T) {
	rt, _ := keysRT(t, map[string]process.CommandResult{
		aptKeyAdvArgv: {Stdout: []byte(aptKeyList)},
	})
	stubWhichBin(t, func(name string) string {
		if name == "apt-key" {
			return "/usr/bin/apt-key"
		}
		return ""
	})
	ret, err := getRepoKeysInternal(context.Background(), rt, true, "")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := ret.(map[string]map[string]any)
	if !ok || len(m) != 1 {
		t.Fatalf("keys = %#v", ret)
	}
	props := m["46181433FBB75451"]
	if props["fingerprint"] != "C5986B4F1257FFA86632CBA746181433FBB75451" ||
		props["algorithm"] != 17 {
		t.Fatalf("props = %#v", props)
	}
}

// Pins the divergence where upstream references an undefined local on the
// apt-key failure path.
func TestGetRepoKeysFailureDivergence(t *testing.T) {
	rt, _ := keysRT(t, map[string]process.CommandResult{
		aptKeyAdvArgv: {ExitCode: 2, Stderr: []byte("gpg error")},
	})
	stubWhichBin(t, func(name string) string {
		if name == "apt-key" {
			return "/usr/bin/apt-key"
		}
		return ""
	})
	if _, err := getRepoKeysInternal(context.Background(), rt, true, ""); err == nil {
		t.Fatalf("expected explicit error for apt-key failure")
	}
}

// Mirrors test_add_repo_key_none_specified.
func TestAddRepoKeyNoneSpecified(t *testing.T) {
	rt, _ := keysRT(t, nil)
	// aptkey defaults true upstream; the keydir check is skipped and the
	// which-flip happens before argument validation, so the TypeError fires.
	_, err := addRepoKeyInternal(context.Background(), rt, addRepoKeyRequest{aptkey: true})
	if err == nil || err.Error() != "add_repo_key() takes at least 1 argument (0 given)" {
		t.Fatalf("error = %v", err)
	}
}

// Mirrors the parametrized battery in
// test_add_repo_key_keyserver_keyid_not_sepcified.
func TestAddRepoKeyServerKeyidValidation(t *testing.T) {
	rt, _ := keysRT(t, nil)

	_, err := addRepoKeyInternal(context.Background(), rt, addRepoKeyRequest{
		keyid:   "0000AAAA",
		keyfile: "test-key.gpg",
		aptkey:  true,
	})
	if err == nil || !strings.HasPrefix(err.Error(), "No keyserver specified for keyid: 0000AAAA") {
		t.Fatalf("keyid-only error = %v", err)
	}

	_, err = addRepoKeyInternal(context.Background(), rt, addRepoKeyRequest{
		keyserver: "keyserver.example",
		keyfile:   "test-key.gpg",
		aptkey:    true,
	})
	if err == nil || !strings.Contains(err.Error(), "No keyid or keyid too short for keyserver") {
		t.Fatalf("server-only error = %v", err)
	}
}

// Mirrors test_add_repo_key_keydir_not_exists.
func TestAddRepoKeyKeydirMissing(t *testing.T) {
	rt, _ := keysRT(t, nil)
	ok, err := addRepoKeyInternal(context.Background(), rt, addRepoKeyRequest{
		keyserver: "keyserver.ubuntu.com",
		keyid:     "FBB75451",
		keyfile:   "test-key.gpg",
		aptkey:    false,
		keydir:    "/testbed/doesnotexist",
	})
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v; want false,nil", ok, err)
	}
}

// Mirrors test_add_repo_key_no_keyfile.
func TestAddRepoKeyNoKeyfile(t *testing.T) {
	rt, _ := keysRT(t, nil)
	if err := rt.FS.MkdirAll("/testbed/keyrings", 0o755); err != nil {
		t.Fatal(err)
	}
	ok, err := addRepoKeyInternal(context.Background(), rt, addRepoKeyRequest{
		keyserver: "keyserver.ubuntu.com",
		keyid:     "FBB75451",
		aptkey:    false,
		keydir:    "/testbed/keyrings",
	})
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v; want false,nil", ok, err)
	}
}

// Mirrors test_add_repo_key_ascii_armored_asc_keeps_armor_68464.
func TestAddRepoKeyAsciiArmorKeepsArmor(t *testing.T) {
	rt, runner := keysRT(t, nil)
	armored := strings.Join([]string{
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"",
		"mDMEY1m4AhYJKwYBBAHaRw8BAQdAabcdefg=",
		"-----END PGP PUBLIC KEY BLOCK-----",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"",
		"mDMEY1m4AhYJKwYBBAHaRw8BAQdAxyz1234=",
		"-----END PGP PUBLIC KEY BLOCK-----",
		"",
	}, "\n")
	mustWrite(rt, "/testbed/cached-unified-streaming.asc", armored)
	if err := rt.FS.MkdirAll("/testbed/keyrings", 0o755); err != nil {
		t.Fatal(err)
	}

	ok, err := addRepoKeyInternal(context.Background(), rt, addRepoKeyRequest{
		path:   "/testbed/cached-unified-streaming.asc",
		aptkey: false,
		keydir: "/testbed/keyrings",
	})
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	for _, call := range runner.calls {
		if containsStr(call, "--dearmor") {
			t.Fatalf("gpg --dearmor invoked: %v", call)
		}
	}
	dest := readAll(t, rt, "/testbed/keyrings/cached-unified-streaming.asc")
	if dest != armored {
		t.Fatalf("armor not preserved verbatim:\n%s", dest)
	}
}

// Mirrors test_decrypt_key_skips_dearmor_for_asc_destination_68464.
func TestDecryptKeySkipsDearmorForAscDestination(t *testing.T) {
	rt, runner := keysRT(t, nil)
	mustWrite(rt, "/testbed/unified-streaming.asc", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDME=\n-----END PGP PUBLIC KEY BLOCK-----\n")
	result, err := decryptKey(rt, "/testbed/unified-streaming.asc", "unified-streaming.asc")
	if err != nil || result != "/testbed/unified-streaming.asc" {
		t.Fatalf("decrypt = %q, %v", result, err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("gpg invoked: %v", runner.calls)
	}
}

// Pins the gpg-missing failure branch of _decrypt_key.
func TestDecryptKeyWithoutGpg(t *testing.T) {
	rt, _ := keysRT(t, nil)
	stubWhichBin(t, func(string) string { return "" })
	mustWrite(rt, "/testbed/key.gpg", "-----BEGIN PGP PUBLIC KEY BLOCK-----\nbody\n-----END PGP PUBLIC KEY BLOCK-----\n")
	result, err := decryptKey(rt, "/testbed/key.gpg", "key.gpg")
	if err != nil || result != "" {
		t.Fatalf("decrypt without gpg = %q, %v; want empty,false", result, err)
	}
}

// Mirrors test_get_key_from_id_keylength_not_valid /
// test_del_repo_key_keyid_doesnotexist.
func TestGetKeyFromIDValidation(t *testing.T) {
	rt, _ := keysRT(t, nil)
	if err := rt.FS.MkdirAll("/testbed/keyrings", 0o755); err != nil {
		t.Fatal(err)
	}
	if got := getKeyFromID(context.Background(), rt, "/testbed/keyrings", "SHORT"); got != "" {
		t.Fatalf("short keyid accepted: %q", got)
	}
	if got := getKeyFromID(context.Background(), rt, "/testbed/keyrings", "ABCD1234"); got != "" {
		t.Fatalf("unknown keyid resolved: %q", got)
	}
	ok, err := delRepoKeyInternal(context.Background(), rt, "", false, "/testbed/keyrings", "ABCD1234", false)
	if err != nil || ok != false {
		t.Fatalf("del with unknown keyid = %#v, %v; want false", ok, err)
	}
}

// Mirrors test_del_repo_key_keyid_ppa validation plus a successful del via
// an injected Launchpad record.
func TestDelRepoKeyFlows(t *testing.T) {
	rt, runner := keysRT(t, map[string]process.CommandResult{
		"apt-key del FBB75451": {Stdout: []byte("OK\n")},
	})
	stubWhichBin(t, func(name string) string {
		if name == "apt-key" {
			return "/usr/bin/apt-key"
		}
		return ""
	})

	if _, err := delRepoKeyInternal(context.Background(), rt, "not-a-ppa", true, "", "", true); err == nil ||
		err.Error() != "keyid_ppa requires that a PPA be passed" {
		t.Fatalf("non-ppa keyid_ppa error = %v", err)
	}

	if _, err := delRepoKeyInternal(context.Background(), rt, "", true, "", "", false); err == nil ||
		err.Error() != "keyid or keyid_ppa and PPA name must be passed" {
		t.Fatalf("no-keyid error = %v", err)
	}

	savedFetch := fetchLaunchpadPPA
	fetchLaunchpadPPA = func(owner, ppa string) (map[string]any, error) {
		return map[string]any{"signing_key_fingerprint": "C5986B4F1257FFA86632CBA746181433FBB75451"}, nil
	}
	t.Cleanup(func() { fetchLaunchpadPPA = savedFetch })

	ret, err := delRepoKeyInternal(context.Background(), rt, "ppa:foo/bar", true, "", "", true)
	if err != nil || ret != "FBB75451" {
		t.Fatalf("ppa del = %#v, %v", ret, err)
	}
	found := false
	for _, call := range runner.calls {
		if equalSlices(call, []string{"apt-key", "del", "FBB75451"}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("apt-key del argv missing: %v", runner.calls)
	}
}

// Pins the explicit-failure message when apt-key del fails.
func TestDelRepoKeyFailureMessage(t *testing.T) {
	rt, _ := keysRT(t, map[string]process.CommandResult{
		"apt-key del FBB75451": {ExitCode: 2, Stderr: []byte("boom")},
	})
	stubWhichBin(t, func(name string) string {
		if name == "apt-key" {
			return "/usr/bin/apt-key"
		}
		return ""
	})
	_, err := delRepoKeyInternal(context.Background(), rt, "", true, "", "FBB75451", false)
	if err == nil || err.Error() != "Failed to remove keyid FBB75451: boom" {
		t.Fatalf("del failure error = %v", err)
	}
}
