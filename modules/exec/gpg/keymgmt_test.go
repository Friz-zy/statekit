package gpg

// R5.7 tests for the gpg key-management tail, mapped onto the source
// contracts of saltstack/salt/modules/gpg.py @ pinned revision. The fake
// Runner replays --with-colons streams and --status-fd 2 lines.

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func keyRT(t *testing.T) (*runtime.Runtime, *gpgRunner) {
	t.Helper()
	reg := runtime.NewExecRegistry()
	for _, register := range []func(*runtime.ExecRegistry) error{Register, RegisterKeyMgmt} {
		if err := register(reg); err != nil {
			t.Fatal(err)
		}
	}
	if err := reg.Register(userStubG{}); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{
		Exec:    reg,
		States:  runtime.NewStateRegistry(),
		FS:      runtime.NewMemoryFS(),
		Runner:  nil,
		Options: runtime.RuntimeOptions{},
	}
	runner := &gpgRunner{}
	rt.Runner = runner
	orig := whichBin
	whichBin = func(exe string) string { return "/usr/bin/" + exe }
	t.Cleanup(func() { whichBin = orig })
	return rt, runner
}

const colonsSample = `pub:-:2048:1:ABCDEF0123456789:1700000000:1763072000::u::scESC:
fpr:::::::::AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111:
uid:::::::::Test User <test@example.com>:
sec:-:2048:1:ABCDEF0123456789:1700000000:1763072000::u::scE:
fpr:::::::::AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111:
pub:-:3072:1:FEDCBA0987654321:1700100000::::::e:
fpr:::::::::BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222:
`

func TestListKeysRendersColonStream(t *testing.T) {
	rt, runner := keyRT(t)
	runner.resp = func(c processCommandG) processResultG {
		if containsArg(c.Args, "--list-keys") && !containsArg(c.Args, "--list-secret-keys") {
			return gpgOut(colonsSample)
		}
		return processResultG{}
	}
	res := mustG(t, rt, "gpg.list_keys", &listKeysArgs{})
	keys := res.([]map[string]any)
	if len(keys) != 2 {
		t.Fatalf("keys = %#v", keys)
	}
	first := keys[0]
	if first["keyid"] != "ABCDEF0123456789" ||
		first["fingerprint"] != "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111" {
		t.Fatalf("first key = %#v", first)
	}
	if first["created"] != "2023-11-14" || first["expires"] != "2025-11-13" {
		t.Fatalf("dates = %#v", first)
	}
	if first["ownerTrust"] != "Ultimately Trusted" || first["keyLength"] != 2048 {
		t.Fatalf("trust/length = %#v", first)
	}

	// secret listing routes through --list-secret-keys.
	calledSecret := false
	runner.resp = func(c processCommandG) processResultG {
		if containsArg(c.Args, "--list-secret-keys") {
			calledSecret = true
			return gpgOut(colonsSample)
		}
		return processResultG{}
	}
	mustG(t, rt, "gpg.list_secret_keys", &listKeysArgs{})
	if !calledSecret {
		t.Fatal("secret listing did not use --list-secret-keys")
	}
}

type processCommandG = process.Command
type processResultG = process.CommandResult

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func gpgOut(s string) process.CommandResult {
	return process.CommandResult{Stdout: []byte(s), ExitCode: 0}
}

func outRes(stdout, stderr string, code int) process.CommandResult {
	return process.CommandResult{
		Stdout: []byte(stdout), Stderr: []byte(stderr), ExitCode: code,
	}
}

func TestGetKeyAndGuards(t *testing.T) {
	rt, runner := keyRT(t)
	runner.resp = func(c processCommandG) processResultG {
		if containsArg(c.Args, "--list-keys") || containsArg(c.Args, "--list-secret-keys") {
			return gpgOut(colonsSample)
		}
		return processResultG{}
	}

	short := "87654321" // short id slice quirk: long keyid's last 8 chars
	res := mustG(t, rt, "gpg.get_key", &getKeyArgs{Keyid: ptrG(short)})
	m := res.(map[string]any)
	if m["keyid"] != "FEDCBA0987654321" {
		t.Fatalf("short-id lookup = %#v", m)
	}

	res = mustG(t, rt, "gpg.get_key", &getKeyArgs{
		Fingerprint: ptrG("BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222"),
	})
	if res.(map[string]any)["keyid"] != "FEDCBA0987654321" {
		t.Fatalf("fp lookup = %#v", res)
	}

	res = mustG(t, rt, "gpg.get_key", &getKeyArgs{Keyid: ptrG("nope")})
	if res != false {
		t.Fatalf("missing key reply = %#v", res)
	}

	res = mustG(t, rt, "gpg.get_secret_key", &getKeyArgs{
		Fingerprint: ptrG("AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111"),
	})
	if _, ok := res.(map[string]any); !ok {
		t.Fatalf("secret lookup = %#v", res)
	}

	// trust_key guards.
	_, err := trustKeyFunc{}.Execute(context.Background(), rt, &trustKeyArgs{
		Keyid:       ptrG("X"),
		Fingerprint: ptrG("Y"),
		TrustLevel:  strPtrG("fully"),
	})
	if err == nil || err.Error() != "Exactly one of keyid or fingerprint is required" {
		t.Fatalf("exactly-one guard = %v", err)
	}
	_, err = trustKeyFunc{}.Execute(context.Background(), rt, &trustKeyArgs{
		Keyid:      ptrG("ABCDEF01"),
		TrustLevel: strPtrG("banana"),
	})
	wantNames := "ERROR: Valid trust levels - expired,unknown,not_trusted,marginally,fully,ultimately"
	if err == nil || err.Error() != wantNames {
		t.Fatalf("trust-level guard = %v", err)
	}

	// Unknown key -> verbatim message.
	runner.resp = func(c processCommandG) processResultG {
		if containsArg(c.Args, "--list-keys") {
			return gpgOut(colonsSample)
		}
		return processResultG{}
	}
	res = mustG(t, rt, "gpg.trust_key", &trustKeyArgs{
		Keyid:      ptrG("DEADBEEF"),
		TrustLevel: strPtrG("fully"),
	})
	m = res.(map[string]any)
	if m["res"] != false || m["message"] != "Key DEADBEEF not in GPG keychain" {
		t.Fatalf("unknown-key trust = %#v", m)
	}

	// Known key: ownertrust stdin file drives the from/to stderr digits.
	runner.resp = func(c processCommandG) processResultG {
		switch {
		case containsArg(c.Args, "--list-keys"):
			return gpgOut(colonsSample)
		case containsArg(c.Args, "--import-ownertrust"):
			i := indexOfArg(c.Args, "--import-ownertrust")
			paramPath := c.Args[i+1]
			data, rerr := rt.FS.ReadFile(paramPath)
			if rerr != nil {
				return outRes("", "", 2)
			}
			content := string(data)
			if !strings.HasPrefix(content, "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111:") {
				return outRes("", "", 2)
			}
			// Two digits on stderr drive the from/to rendering.
			return outRes("", "gpg: changing from 4 to 5\n", 0)
		}
		return processResultG{}
	}
	res = mustG(t, rt, "gpg.trust_key", &trustKeyArgs{
		Fingerprint: ptrG("AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111"),
		TrustLevel:  strPtrG("fully"),
	})
	m = res.(map[string]any)
	if m["res"] != true || m["fingerprint"] != "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111" {
		t.Fatalf("trust reply = %#v", m)
	}
}

func indexOfArg(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}

func TestCreateDeleteImportExportReadFlows(t *testing.T) {
	rt, runner := keyRT(t)
	var paramContent string
	runner.resp = func(c processCommandG) processResultG {
		switch {
		case containsArg(c.Args, "--list-keys"), containsArg(c.Args, "--list-secret-keys"):
			return gpgOut(colonsSample)
		case containsArg(c.Args, "--gen-key"):
			i := indexOfArg(c.Args, "--gen-key")
			data, _ := rt.FS.ReadFile(c.Args[i+1])
			paramContent = string(data)
			return processResultG{
				Stderr:   []byte("[GNUPG:] KEY_CREATED S AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111\n"),
				ExitCode: 0,
			}
		case containsArg(c.Args, "--delete-secret-keys"):
			return outRes("", "", 0)
		case containsArg(c.Args, "--delete-keys"):
			return outRes("", "", 0)
		case containsArg(c.Args, "--export-secret-keys"), containsArg(c.Args, "--export"):
			return processResultG{
				Stdout:   []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\nbody\n-----END PGP PUBLIC KEY BLOCK-----"),
				ExitCode: 0,
			}
		case containsArg(c.Args, "--import"):
			return processResultG{
				Stderr: []byte("[GNUPG:] IMPORTED AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111 Test <t@x>\n" +
					"[GNUPG:] IMPORT_RES 1 1 0 0 0 1 1 0 0 0 0 0 0 0\n"),
				ExitCode: 0,
			}
		case containsArg(c.Args, "--show-keys"):
			return gpgOut(colonsSample)
		case containsArg(c.Args, "--search-keys"):
			return gpgOut(colonsSample)
		case containsArg(c.Args, "--recv-keys"):
			return processResultG{
				Stderr:   []byte("[GNUPG:] IMPORT_OK 1 AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111\n"),
				ExitCode: 0,
			}
		}
		return processResultG{}
	}

	// create_key writes the parameter batch with %no-protection.
	res := mustG(t, rt, "gpg.create_key", &createKeyArgs{
		NameReal:  strPtrG("CI Key"),
		NameEmail: strPtrG("ci@example.com"),
	})
	m := res.(map[string]any)
	if m["res"] != true || m["fingerprint"] != "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111" {
		t.Fatalf("create reply = %#v", m)
	}
	if !strings.Contains(paramContent, "%no-protection") ||
		!strings.Contains(paramContent, "Name-Email: ci@example.com") ||
		!strings.Contains(paramContent, "%commit") {
		t.Fatalf("param batch = %q", paramContent)
	}

	// delete_key without secret present deletes the public part only.
	res = mustG(t, rt, "gpg.delete_key", &deleteKeyArgs{
		Fingerprint: strPtrG("BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222"),
	})
	m = res.(map[string]any)
	if m["res"] != true ||
		m["message"] != "Public key for BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222 deleted" {
		t.Fatalf("delete public reply = %#v", m)
	}

	// import_key via text reports fingerprints and the success message.
	block := "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"
	res = mustG(t, rt, "gpg.import_key", &importKeyArgs{Text: strPtrG(block)})
	m = res.(map[string]any)
	if m["res"] != true || m["message"] != "Successfully imported key(s)." {
		t.Fatalf("import reply = %#v", m)
	}
	fps := m["fingerprints"].([]string)
	if len(fps) != 1 || fps[0] != "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111" {
		t.Fatalf("fingerprints = %#v", fps)
	}

	// export_key bare returns the armored block.
	bare := true
	keyids := []any{"ABCDEF01"}
	res = mustG(t, rt, "gpg.export_key", &exportKeyArgs{
		Keyids: keyids, Bare: &bare,
	})
	s := res.(string)
	if !strings.HasPrefix(s, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		t.Fatalf("bare export = %#v", s)
	}

	// read_key parses a key file through --show-keys.
	if err := rt.FS.MkdirAll("/keys", 0o755); err != nil {
		t.Fatal(err)
	}
	rt.FS.WriteFile("/keys/a.asc", []byte(block), 0o600)
	res = mustG(t, rt, "gpg.read_key", &readKeyArgs{Path: strPtrG("/keys/a.asc")})
	list := res.([]map[string]any)
	if len(list) != 2 {
		t.Fatalf("read_key entries = %#v", list)
	}

	// receive_keys maps IMPORT_OK statuses to messages.
	res = mustG(t, rt, "gpg.receive_keys", &receiveKeysArgs{
		Keys: "AAAA1111",
	})
	m = res.(map[string]any)
	msgs := m["message"].([]string)
	if len(msgs) != 1 ||
		msgs[0] != "Key AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111 added to keychain" {
		t.Fatalf("receive messages = %#v", msgs)
	}

	// search_keys renders keyserver results.
	res = mustG(t, rt, "gpg.search_keys", &searchKeysArgs{Text: "test@example.com"})
	if len(res.([]map[string]any)) == 0 {
		t.Fatal("search returned nothing")
	}

	// input guards.
	_, err := importKeyFunc{}.Execute(context.Background(), rt, &importKeyArgs{})
	if err == nil || err.Error() != "filename or text must be passed." {
		t.Fatalf("import guard = %v", err)
	}
	_, err = readKeyFunc{}.Execute(context.Background(), rt, &readKeyArgs{})
	if err == nil || err.Error() != "Either `path` or `text` is required." {
		t.Fatalf("read guard = %v", err)
	}
	res = mustG(t, rt, "gpg.delete_key", &deleteKeyArgs{
		Keyid:       strPtrG("a"),
		Fingerprint: strPtrG("b"),
	})
	m = res.(map[string]any)
	if m["res"] != false || m["message"] != "Only specify one argument, fingerprint or keyid" {
		t.Fatalf("delete guard = %#v", m)
	}
}
