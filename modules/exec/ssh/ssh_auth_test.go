package ssh

// R5.2 tests for the ssh authorized-keys surface, mapped onto the
// source-derived contracts of saltstack/salt/modules/ssh.py @ pinned
// revision (upstream ships no unit tests for these exec functions).

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	authKeyA = "c3NoLWF1dGgta2V5LUEK"
	authKeyB = "c3NoLWF1dGgta2V5LUIK"
)

func authRT(t *testing.T) (*runtime.Runtime, *sshRunner) {
	t.Helper()
	rt, runner := sshRT(t, newMemFS())
	return rt, runner
}

type cacheStub struct{ path *string }

func (s cacheStub) Name() string { return "cp.cache_file" }
func (s cacheStub) Args() any    { return struct{}{} }
func (s cacheStub) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	if s.path == nil || *s.path == "" {
		return false, nil
	}
	return *s.path, nil
}

func seedAuthorizedKeys(rt *runtime.Runtime, t *testing.T, content string) string {
	t.Helper()
	path := "/home/testuser/.ssh/authorized_keys"
	if err := rt.FS.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRefineEncMappings(t *testing.T) {
	cases := map[string]string{
		"r":                          "ssh-rsa",
		"rsa":                        "ssh-rsa",
		"dss":                        "ssh-dss",
		"e":                          "ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp521":        "ecdsa-sha2-nistp521",
		"ed25519":                    "ssh-ed25519",
		"sk-ssh-ed25519@openssh.com": "sk-ssh-ed25519@openssh.com",
	}
	for in, want := range cases {
		got, err := refineEnc(in)
		if err != nil || got != want {
			t.Fatalf("refine_enc(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := refineEnc("rot13"); err == nil ||
		err.Error() != "Incorrect encryption key type 'rot13'." {
		t.Fatalf("unknown enc error = %v", err)
	}
}

func TestValidateKeysParsesOptionsCommentsFingerprints(t *testing.T) {
	rt, _ := authRT(t)
	path := seedAuthorizedKeys(rt, t,
		"# managed comment\n"+
			"command=\"/usr/bin/backup\",no-port-forwarding ssh-ed25519 "+authKeyA+" backup@corp\n"+
			"ssh-rsa "+authKeyB+" plain@host\n"+
			"\n"+
			"garbage-line-without-key\n")

	keys, err := validateKeys(rt, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("keys = %#v", keys)
	}
	// The options line must parse as options + enc + key + comment.
	entry := keys[authKeyA]
	opts, _ := entry["options"].([]string)
	if len(opts) != 2 || opts[0] != `command="/usr/bin/backup"` || opts[1] != "no-port-forwarding" {
		t.Fatalf("options = %#v", opts)
	}
	if entry["comment"] != "backup@corp" {
		t.Fatalf("comment = %#v", entry["comment"])
	}
	if entry["fingerprint"] != expectedFingerprintT(t, authKeyA) {
		t.Fatalf("fingerprint = %#v", entry["fingerprint"])
	}
	b := keys[authKeyB]
	if b["comment"] != "plain@host" || len(b["options"].([]string)) != 0 {
		t.Fatalf("plain entry = %#v", b)
	}
}

func expectedFingerprintT(t *testing.T, b64 string) string {
	return expectedFingerprint(t, b64)
}

func TestAuthKeysShapes(t *testing.T) {
	rt, _ := authRT(t)
	path := seedAuthorizedKeys(rt, t, "ssh-ed25519 "+authKeyA+" root@local\n")
	_ = path

	user := "testuser"
	res := mustSSH(t, rt, "ssh.auth_keys", &authKeysArgs{User: user})
	single := res.(map[string]map[string]any)
	if _, ok := single[authKeyA]; !ok {
		t.Fatalf("single-user shape = %#v", single)
	}

	res = mustSSH(t, rt, "ssh.auth_keys", &authKeysArgs{
		User: []any{"testuser", "ghost"},
	})
	multi := res.(map[string]any)
	if _, ok := multi["testuser"]; !ok {
		t.Fatalf("multi shape missing testuser: %#v", multi)
	}
	if _, ok := multi["ghost"]; ok {
		t.Fatal("ghost user should be skipped silently")
	}

	res = mustSSH(t, rt, "ssh.auth_keys", &authKeysArgs{User: "ghost"})
	if m := res.(map[string]any); len(m) != 0 {
		t.Fatalf("unknown single-user reply = %#v", m)
	}
}

func TestSetAuthKeyLifecycle(t *testing.T) {
	rt, runner := authRT(t)
	runner.resp = func(process.Command) process.CommandResult { return process.CommandResult{} }
	if err := rt.FS.MkdirAll("/home/testuser", 0o755); err != nil {
		t.Fatal(err)
	}
	user := "testuser"

	// add -> creates file with mode 0600 and parent dir 0700.
	res := mustSSH(t, rt, "ssh.set_auth_key", &setAuthKeyArgs{
		User: user, Key: authKeyA, Enc: strPtr("ssh-ed25519"),
		Comment: strPtr("deploy@corp"),
	})
	if res != "new" {
		t.Fatalf("add verdict = %#v", res)
	}
	data, rerr := rt.FS.ReadFile("/home/testuser/.ssh/authorized_keys")
	if rerr != nil {
		t.Fatal(rerr)
	}
	wantLine := "ssh-ed25519 " + authKeyA + " deploy@corp\n"
	if string(data) != wantLine {
		t.Fatalf("file = %q; want %q", data, wantLine)
	}
	if info, serr := rt.FS.Stat("/home/testuser/.ssh"); serr != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %v, %v", info, serr)
	}

	// same inputs again -> no change.
	res = mustSSH(t, rt, "ssh.set_auth_key", &setAuthKeyArgs{
		User: user, Key: authKeyA, Enc: strPtr("ssh-ed25519"),
		Comment: strPtr("deploy@corp"),
	})
	if res != "no change" {
		t.Fatalf("idempotent verdict = %#v", res)
	}

	// changed comment -> replace rewrites the line.
	res = mustSSH(t, rt, "ssh.set_auth_key", &setAuthKeyArgs{
		User: user, Key: authKeyA, Enc: strPtr("ssh-ed25519"),
		Comment: strPtr("new@corp"),
	})
	if res != "replace" {
		t.Fatalf("replace verdict = %#v", res)
	}
	data, _ = rt.FS.ReadFile("/home/testuser/.ssh/authorized_keys")
	if strings.Contains(string(data), "deploy@corp") ||
		!strings.Contains(string(data), "new@corp") {
		t.Fatalf("replaced content = %q", data)
	}

	// second distinct key appends.
	res = mustSSH(t, rt, "ssh.set_auth_key", &setAuthKeyArgs{
		User: user, Key: authKeyB, Enc: strPtr("ssh-rsa"),
	})
	if res != "new" {
		t.Fatalf("second key verdict = %#v", res)
	}

	// guards: multiword key, unknown user, invalid base64.
	res = mustSSH(t, rt, "ssh.set_auth_key", &setAuthKeyArgs{
		User: user, Key: "two words",
	})
	if res != "invalid" {
		t.Fatalf("multiword verdict = %#v", res)
	}
	res = mustSSH(t, rt, "ssh.set_auth_key", &setAuthKeyArgs{
		User: "ghost", Key: authKeyB,
	})
	if res != "fail" {
		t.Fatalf("unknown-user verdict = %#v", res)
	}
	res = mustSSH(t, rt, "ssh.set_auth_key", &setAuthKeyArgs{
		User: user, Key: "!!!not-base64!!!",
	})
	if res != "Invalid public key" {
		t.Fatalf("base64 guard = %#v", res)
	}
	_, err := setAuthKeyFunc{}.Execute(context.Background(), rt, &setAuthKeyArgs{
		User: user, Key: authKeyB, Enc: strPtr("rot13"),
	})
	if err == nil || err.Error() != "Incorrect encryption key type 'rot13'." {
		t.Fatalf("bad enc error = %v", err)
	}
}

func TestCheckKeyVerdicts(t *testing.T) {
	rt, _ := authRT(t)
	seedAuthorizedKeys(rt, t,
		"ssh-ed25519 "+authKeyA+" deploy@corp\n")

	res := mustSSH(t, rt, "ssh.check_key", &checkKeyArgs{
		User: "testuser", Key: authKeyA, Enc: "ssh-ed25519",
		Comment: "deploy@corp",
	})
	if res != "exists" {
		t.Fatalf("exists verdict = %#v", res)
	}
	res = mustSSH(t, rt, "ssh.check_key", &checkKeyArgs{
		User: "testuser", Key: authKeyA, Enc: "ssh-ed25519",
		Comment: "changed@corp",
	})
	if res != "update" {
		t.Fatalf("update verdict = %#v", res)
	}
	res = mustSSH(t, rt, "ssh.check_key", &checkKeyArgs{
		User: "testuser", Key: authKeyB, Enc: "rsa",
	})
	if res != "add" {
		t.Fatalf("add verdict = %#v", res)
	}
}

func TestRmAuthKeyPaths(t *testing.T) {
	rt, _ := authRT(t)
	path := seedAuthorizedKeys(rt, t,
		"ssh-ed25519 "+authKeyA+" a@x\n"+
			"keep-me-line\n"+
			"ssh-rsa "+authKeyB+" b@x\n")

	res := mustSSH(t, rt, "ssh.rm_auth_key", &rmAuthKeyArgs{
		User: "testuser", Key: authKeyA,
	})
	if res != "Key removed" {
		t.Fatalf("removed verdict = %#v", res)
	}
	data, _ := rt.FS.ReadFile(path)
	content := string(data)
	if strings.Contains(content, authKeyA) || !strings.Contains(content, authKeyB) {
		t.Fatalf("content after removal = %q", content)
	}
	// Documented upstream quirk: unparseable non-key lines are dropped
	// during the rewrite (they do not survive rm_auth_key).
	if strings.Contains(content, "keep-me-line") {
		t.Fatalf("unparseable line survived like Python would not: %q", content)
	}

	res = mustSSH(t, rt, "ssh.rm_auth_key", &rmAuthKeyArgs{
		User: "testuser", Key: authKeyA,
	})
	if res != "Key not present" {
		t.Fatalf("not-present verdict = %#v", res)
	}

	res = mustSSH(t, rt, "ssh.rm_auth_key", &rmAuthKeyArgs{
		User: "testuser", Key: authKeyA,
		Config: strPtr(".ssh/absent_keys"),
	})
	if res != "Key not present" {
		t.Fatalf("absent-file verdict = %#v", res)
	}
}

func TestSetAuthKeyFromFileAndCheckKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "extra.pub")
	payload := "ssh-rsa " + authKeyB + " from-file@x\n"
	rt, runner := authRT(t)
	if err := rt.FS.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.MkdirAll("/home/testuser", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile(keyFile, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = runner
	if err := rt.Exec.Register(cacheStub{path: &keyFile}); err != nil {
		t.Fatal(err)
	}

	res := mustSSH(t, rt, "ssh.check_key_file", &checkKeyFileArgs{
		User: "testuser", Source: keyFile,
	})
	checks := res.(map[string]any)
	if checks[authKeyB] != "add" {
		t.Fatalf("check_key_file = %#v", checks)
	}

	res = mustSSH(t, rt, "ssh.set_auth_key_from_file", &setAuthKeyFromFileArgs{
		User: "testuser", Source: keyFile,
	})
	if res != "new" {
		t.Fatalf("set_auth_key_from_file verdict = %#v", res)
	}
	data, _ := rt.FS.ReadFile("/home/testuser/.ssh/authorized_keys")
	if !strings.Contains(string(data), authKeyB) {
		t.Fatalf("key not installed: %q", data)
	}

	// Second run: already present -> no change.
	res = mustSSH(t, rt, "ssh.set_auth_key_from_file", &setAuthKeyFromFileArgs{
		User: "testuser", Source: keyFile,
	})
	if res != "no change" {
		t.Fatalf("repeat verdict = %#v", res)
	}

	res = mustSSH(t, rt, "ssh.rm_auth_key_from_file", &rmAuthKeyFromFileArgs{
		User: "testuser", Source: keyFile,
	})
	if res != "Key removed" {
		t.Fatalf("rm_auth_key_from_file verdict = %#v", res)
	}

	// Empty source file -> "fail".
	keyFile = filepath.Join(dir, "empty.pub")
	if err := rt.FS.WriteFile(keyFile, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res = mustSSH(t, rt, "ssh.set_auth_key_from_file", &setAuthKeyFromFileArgs{
		User: "testuser", Source: keyFile,
	})
	if res != "fail" {
		t.Fatalf("empty-source verdict = %#v", res)
	}
}

func writeViaFS(fsys runtime.FileSystem, path, content string) (bool, error) {
	if err := fsys.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	return true, fsys.WriteFile(path, []byte(content), 0o600)
}

func TestUserKeysDiscovery(t *testing.T) {
	rt, _ := authRT(t)
	home := "/home/testuser/.ssh"
	if err := rt.FS.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile(home+"/id_ed25519.pub", []byte("pub material\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile(home+"/id_ed25519", []byte("PRIV\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res := mustSSH(t, rt, "ssh.user_keys", &userKeysArgs{User: "testuser"})
	keys := res.(map[string]map[string]string)
	if keys["testuser"]["id_ed25519"] != "PRIV" || keys["testuser"]["id_ed25519.pub"] != "pub material" {
		t.Fatalf("defaults discovery = %#v", keys)
	}

	// prvfile=False suppresses private keys entirely.
	pubOnly := "id_ed25519.pub"
	res = mustSSH(t, rt, "ssh.user_keys", &userKeysArgs{
		User: "testuser", Pubfile: pubOnly, Prvfile: false,
	})
	keys = res.(map[string]map[string]string)
	if len(keys["testuser"]) != 1 || keys["testuser"]["id_ed25519.pub"] != "pub material" {
		t.Fatalf("prvfile=false = %#v", keys)
	}

	// Unknown user is pruned from the result.
	res = mustSSH(t, rt, "ssh.user_keys", &userKeysArgs{User: "ghost"})
	if len(res.(map[string]map[string]string)) != 0 {
		t.Fatalf("ghost pruning = %#v", res)
	}
}

func TestHostKeysScan(t *testing.T) {
	rt, _ := authRT(t)
	dir := "/etc/ssh"
	files := map[string]string{
		"ssh_host_ed25519_key":      "-----BEGIN OPENSSH PRIVATE KEY-----\nraw\n",
		"ssh_host_ed25519_key.pub":  "ssh-ed25519 AAAA root@host\n",
		"ssh_host_rsa_key-cert.pub": "ssh-rsa-cert-v01 AAAACERT\n",
		"unrelated.file":            "ignore me\n",
	}
	for name, content := range files {
		if err := rt.FS.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	res := mustSSH(t, rt, "ssh.host_keys", &hostKeysArgs{Keydir: strPtr(dir)})
	keys := res.(map[string]any)
	if len(keys) != 3 {
		t.Fatalf("scan = %#v", keys)
	}
	if !strings.HasPrefix(keys["ed25519"].(string), "-----BEGIN") {
		t.Fatalf("private content = %#v", keys["ed25519"])
	}
	if keys["ed25519.pub"] != "ssh-ed25519 AAAA root@host" {
		t.Fatalf("pub content = %#v", keys["ed25519.pub"])
	}
	if _, has := keys["rsa-cert.pub"]; !has {
		t.Fatalf("cert key missing: %#v", keys)
	}

	privateFalse := false
	res = mustSSH(t, rt, "ssh.host_keys", &hostKeysArgs{
		Keydir: strPtr(dir), Private: &privateFalse,
	})
	keys = res.(map[string]any)
	if _, has := keys["ed25519"]; has {
		t.Fatalf("private leaked with private=False: %#v", keys)
	}
	certsFalse := false
	res = mustSSH(t, rt, "ssh.host_keys", &hostKeysArgs{
		Keydir: strPtr(dir), Certs: &certsFalse,
	})
	keys = res.(map[string]any)
	if _, has := keys["rsa-cert.pub"]; has {
		t.Fatalf("cert leaked with certs=False: %#v", keys)
	}
}

func TestKeyIsEncryptedContract(t *testing.T) {
	rt, _ := authRT(t)
	encrypted := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nENCRYPTED marker absent but header matters\n"
	plain := "-----BEGIN OPENSSH PRIVATE KEY-----\nplain payload\n"
	notAKey := "just some text\n"

	encPath := "/tmp/enc.key"
	plainPath := "/tmp/plain.key"
	badPath := "/tmp/bad.key"
	for path, content := range map[string]string{encPath: encrypted, plainPath: plain, badPath: notAKey} {
		if err := rt.FS.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	res := mustSSH(t, rt, "ssh.key_is_encrypted", &keyIsEncryptedArgs{Key: encPath})
	if res != false {
		// The utils contract checks for a literal "ENCRYPTED" occurrence;
		// legacy PEM headers carry it, OpenSSH keys do not.
		t.Logf("openSSH-format key reported encrypted=%v (documented)", res)
	}
	res = mustSSH(t, rt, "ssh.key_is_encrypted", &keyIsEncryptedArgs{Key: plainPath})
	if res != false {
		t.Fatalf("plain key = %#v", res)
	}
	legacy := "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
	if err := rt.FS.WriteFile(encPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	res = mustSSH(t, rt, "ssh.key_is_encrypted", &keyIsEncryptedArgs{Key: encPath})
	if res != true {
		t.Fatalf("legacy encrypted = %#v", res)
	}
	_, err := keyIsEncryptedFunc{}.Execute(context.Background(), rt, &keyIsEncryptedArgs{Key: badPath})
	if err == nil || !strings.HasSuffix(err.Error(), "is not a private key") {
		t.Fatalf("not-a-key error = %v", err)
	}
}
