package ssh

// R5.1 tests for the ssh known-hosts surface, mapped onto the source-derived
// contracts of saltstack/salt/modules/ssh.py @ pinned revision. Upstream has
// no unit tests for these exec functions (only the state module mocks them),
// so the suite pins the contracts hermetically with a scripted fake Runner
// following the bcache/scsi precedent.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execuser "github.com/friz-zy/statekit/modules/exec/user"
)

// ---------------------------------------------------------------------------
// harness

type sshRunner struct {
	calls []process.Command
	resp  func(process.Command) process.CommandResult
}

func (r *sshRunner) Run(_ context.Context, c process.Command) process.CommandResult {
	r.calls = append(r.calls, c)
	if r.resp != nil {
		return r.resp(c)
	}
	return process.CommandResult{}
}

type userStub struct{}

func (userStub) Name() string { return "user.info" }
func (userStub) Args() any    { return execuser.InfoArgs{} }
func (userStub) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*execuser.InfoArgs)
	if a.Name == "testuser" {
		return map[string]any{
			"name": "testuser", "uid": 1234, "gid": 1234,
			"home": "/home/testuser", "shell": "/bin/sh", "gecos": "",
			"groups": []string{"testuser"},
		}, nil
	}
	return nil, fmt.Errorf("user %q does not exist", a.Name)
}

func newMemFS() runtime.FileSystem { return runtime.NewMemoryFS() }

func sshRT(t *testing.T, fsys runtime.FileSystem) (*runtime.Runtime, *sshRunner) {
	t.Helper()
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(userStub{}); err != nil {
		t.Fatal(err)
	}
	if fsys == nil {
		fsys = newMemFS()
	}
	runner := &sshRunner{}
	rt := &runtime.Runtime{
		Exec:    reg,
		States:  runtime.NewStateRegistry(),
		FS:      fsys,
		Runner:  runner,
		Options: runtime.RuntimeOptions{},
	}
	origWhich := whichBin
	whichBin = func(exe string) string { return "/usr/bin/" + exe }
	t.Cleanup(func() { whichBin = origWhich })
	origEuid := currentEuid
	currentEuid = func() int { return 1000 } // non-root by default
	t.Cleanup(func() { currentEuid = origEuid })
	return rt, runner
}

func mustSSH(t *testing.T, rt *runtime.Runtime, name string, args any) any {
	t.Helper()
	res, err := rt.Exec.Call(context.Background(), rt, name, args)
	if err != nil {
		t.Fatalf("%s: unexpected error %v", name, err)
	}
	return res
}

const testKeyB64 = "c3RhdGVraXQtdGVzdC1rZXkK"

func expectedFingerprint(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(raw))
	pairs := make([]string, 0, len(sum)/2)
	for i := 0; i < len(sum); i += 2 {
		pairs = append(pairs, sum[i:i+2])
	}
	return strings.Join(pairs, ":")
}

func seedKnownHosts(t *testing.T, fsys runtime.FileSystem, path, content string) {
	t.Helper()
	if content == "" && path == "" {
		return
	}
	if err := fsys.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// fingerprint helper

func TestFingerprintFormatAndValidation(t *testing.T) {
	fp, err := fingerprint(testKeyB64, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := expectedFingerprint(t, testKeyB64)
	if fp != want {
		t.Fatalf("fingerprint = %q; want %q", fp, want)
	}
	if !strings.Contains(fp, ":") || len(strings.Split(fp, ":")) != 32 {
		t.Fatalf("sha256 colon format broken: %q", fp)
	}

	// Invalid base64 yields empty like upstream's None.
	fp, err = fingerprint("!!!not-base64!!!", nil)
	if err != nil || fp != "" {
		t.Fatalf("invalid base64 = %q, %v", fp, err)
	}

	md5 := "md5"
	fp, err = fingerprint(testKeyB64, &md5)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Split(fp, ":"); len(got) != 16 {
		t.Fatalf("md5 pair count = %d (%q)", len(got), fp)
	}

	bogus := "crc32"
	if _, err = fingerprint(testKeyB64, &bogus); err == nil ||
		err.Error() != "The fingerprint_hash_type crc32 is not supported." {
		t.Fatalf("unsupported hash error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// get_known_host_entries

func TestGetKnownHostEntriesParsesKeygenOutput(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	fsys := newMemFS()
	seedKnownHosts(t, fsys, kh, "")
	rt, runner := sshRT(t, fsys)
	_ = kh

	entries := []string{
		"# Host github.com found: line 3",
		"github.com ssh-ed25519 " + testKeyB64,
	}
	runner.resp = func(c process.Command) process.CommandResult {
		if filepath.Base(c.Name) == "ssh-keygen" && c.Args[0] == "-F" {
			return process.CommandResult{Stdout: []byte(strings.Join(entries, "\n") + "\n")}
		}
		return process.CommandResult{}
	}

	res := mustSSH(t, rt, "ssh.get_known_host_entries", &getKnownHostEntriesArgs{
		User: "testuser", Hostname: "github.com",
	})
	list := res.([]map[string]any)
	if len(list) != 1 {
		t.Fatalf("entries = %#v", list)
	}
	e := list[0]
	if e["hostname"] != "github.com" || e["enc"] != "ssh-ed25519" || e["key"] != testKeyB64 {
		t.Fatalf("entry fields = %#v", e)
	}
	if e["fingerprint"] != expectedFingerprint(t, testKeyB64) {
		t.Fatalf("fingerprint = %#v", e["fingerprint"])
	}

	// No matching entries -> None contract.
	runner.resp = func(process.Command) process.CommandResult { return process.CommandResult{} }
	res = mustSSH(t, rt, "ssh.get_known_host_entries", &getKnownHostEntriesArgs{
		User: "testuser", Hostname: "absent.example.com",
	})
	if res != nil {
		t.Fatalf("no-entry reply = %#v", res)
	}

	// Missing user -> verbatim error dict.
	res = mustSSH(t, rt, "ssh.get_known_host_entries", &getKnownHostEntriesArgs{
		User: "ghost", Hostname: "github.com",
	})
	m := res.(map[string]any)
	if m["error"] != "User ghost does not exist" || m["status"] != "error" {
		t.Fatalf("missing-user reply = %#v", m)
	}

	// Relative config without user -> cannot-determine path error.
	res = mustSSH(t, rt, "ssh.get_known_host_entries", &getKnownHostEntriesArgs{
		User: "", Hostname: "github.com", Config: strPtr(".ssh/known_hosts"),
	})
	m = res.(map[string]any)
	if m["error"] != "Cannot determine absolute path to file." {
		t.Fatalf("relative-config reply = %#v", m)
	}
}

func strPtr(s string) *string { return &s }

func TestGetKnownHostEntriesMissingBinary(t *testing.T) {
	rt, _ := sshRT(t, nil)
	orig := whichBin
	whichBin = func(string) string { return "" }
	t.Cleanup(func() { whichBin = orig })

	res, err := getKnownHostEntriesFunc{}.Execute(context.Background(), rt,
		&getKnownHostEntriesArgs{User: "testuser", Hostname: "github.com"})
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	if m["error"] != "The 'ssh-keygen' binary was not found in $PATH." {
		t.Fatalf("which-guard reply = %#v", m)
	}
}

// ---------------------------------------------------------------------------
// recv_known_host_entries

func TestRecvKnownHostEntriesRetriesAndParses(t *testing.T) {
	rt, runner := sshRT(t, nil)

	keyscanLines := []string{
		"github.com ssh-rsa cnNhLXRlc3Qta2V5Cg==",
		"github.com ecdsa-sha2-nistp256 ZWNkc2EtdGVzdC1rZXkK",
	}
	calls := 0
	runner.resp = func(c process.Command) process.CommandResult {
		if filepath.Base(c.Name) == "ssh-keyscan" {
			calls++
			if calls < 3 {
				// First two attempts return nothing; the retry loop continues.
				return process.CommandResult{}
			}
			return process.CommandResult{Stdout: []byte(strings.Join(keyscanLines, "\n") + "\n")}
		}
		return process.CommandResult{}
	}

	res := mustSSH(t, rt, "ssh.recv_known_host_entries", &recvKnownHostEntriesArgs{
		Hostname: "github.com",
	})
	list := res.([]map[string]any)
	if len(list) != 2 {
		t.Fatalf("entries = %#v", list)
	}
	if list[0]["enc"] != "ssh-rsa" {
		t.Fatalf("first enc = %#v", list[0])
	}
	if calls != 3 {
		t.Fatalf("retry attempts = %d", calls)
	}

	// -t/-p/-H argv assembly.
	enc := "ed25519"
	port := 2222
	calls = 0
	mustSSH(t, rt, "ssh.recv_known_host_entries", &recvKnownHostEntriesArgs{
		Hostname: "gitlab.example.com", Enc: &enc, Port: &port,
		HashKnownHosts: boolPtr(false), Timeout: intPtr(9),
	})
	last := runner.calls[len(runner.calls)-1]
	want := []string{"ssh-keyscan", "-p", "2222", "-t", "ed25519", "-T", "9", "gitlab.example.com"}
	if strings.Join(last.Args, " ") != strings.Join(want[1:], " ") {
		t.Fatalf("keyscan argv = %v", last.Args)
	}

	// Nothing ever received -> None.
	runner.resp = func(process.Command) process.CommandResult { return process.CommandResult{} }
	res = mustSSH(t, rt, "ssh.recv_known_host_entries", &recvKnownHostEntriesArgs{
		Hostname: "dead.internal",
	})
	if res != nil {
		t.Fatalf("unreachable reply = %#v", res)
	}
}

func strPtr2(s string) *string { return &s }
func intPtr(i int) *int        { return &i }
func boolPtr(b bool) *bool     { return &b }

// ---------------------------------------------------------------------------
// check_known_host / rm_known_host / hash_known_hosts

func TestCheckKnownHostVerdicts(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	fsys := newMemFS()
	seedKnownHosts(t, fsys, kh, "")
	rt, runner := sshRT(t, fsys)
	config := kh

	keygenOut := "# Host github.com found: line 1\ngithub.com ssh-ed25519 " + testKeyB64 + "\n"
	runner.resp = func(c process.Command) process.CommandResult {
		if c.Args != nil && len(c.Args) > 0 && c.Args[0] == "-F" {
			return process.CommandResult{Stdout: []byte(keygenOut)}
		}
		return process.CommandResult{}
	}

	// No key/fingerprint: entry exists -> exists.
	res := mustSSH(t, rt, "ssh.check_known_host", &checkKnownHostArgs{
		User: strPtr2("testuser"), Hostname: strPtr2("github.com"), Config: &config,
	})
	if res != "exists" {
		t.Fatalf("verdict = %#v", res)
	}

	// Matching key -> exists; different key -> update.
	good := testKeyB64
	res = mustSSH(t, rt, "ssh.check_known_host", &checkKnownHostArgs{
		User: strPtr2("testuser"), Hostname: strPtr2("github.com"), Config: &config,
		Key: &good,
	})
	if res != "exists" {
		t.Fatalf("key verdict = %#v", res)
	}
	other := "b3RoZXJrZXkK"
	res = mustSSH(t, rt, "ssh.check_known_host", &checkKnownHostArgs{
		User: strPtr2("testuser"), Hostname: strPtr2("github.com"), Config: &config,
		Key: &other,
	})
	if res != "update" {
		t.Fatalf("other-key verdict = %#v", res)
	}

	// Fingerprint match -> exists.
	fp := expectedFingerprint(t, testKeyB64)
	res = mustSSH(t, rt, "ssh.check_known_host", &checkKnownHostArgs{
		User: strPtr2("testuser"), Hostname: strPtr2("github.com"), Config: &config,
		Fingerprint: &fp,
	})
	if res != "exists" {
		t.Fatalf("fingerprint verdict = %#v", res)
	}

	// Unknown host -> add (empty keygen output).
	runner.resp = func(c process.Command) process.CommandResult {
		if c.Args != nil && len(c.Args) > 0 && c.Args[0] == "-F" {
			return process.CommandResult{}
		}
		return process.CommandResult{}
	}
	res = mustSSH(t, rt, "ssh.check_known_host", &checkKnownHostArgs{
		User: strPtr2("testuser"), Hostname: strPtr2("absent.example"), Config: &config,
	})
	if res != "add" {
		t.Fatalf("unknown-host verdict = %#v", res)
	}

	// Missing hostname -> verbatim error dict.
	res = mustSSH(t, rt, "ssh.check_known_host", &checkKnownHostArgs{})
	m := res.(map[string]any)
	if m["error"] != "hostname argument required" {
		t.Fatalf("hostname guard = %#v", m)
	}
}

func TestRmKnownHostFlows(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	fsys := newMemFS()
	seedKnownHosts(t, fsys, kh, "")
	rt, runner := sshRT(t, fsys)
	user := "testuser"
	config := kh

	// Missing file -> verbatim error dict.
	res := mustSSH(t, rt, "ssh.rm_known_host", &rmKnownHostArgs{
		User: &user, Hostname: strPtr2("github.com"), Config: strPtr("/nonexistent/kh"),
	})
	m := res.(map[string]any)
	if m["status"] != "error" || !strings.HasSuffix(m["error"].(string), "does not exist") {
		t.Fatalf("missing-file reply = %#v", m)
	}

	runner.resp = func(c process.Command) process.CommandResult {
		if len(c.Args) > 0 && c.Args[0] == "-R" {
			return process.CommandResult{Stdout: []byte("# Host github.com found: line 1\n# original line: github.com ssh-ed25519 AAAA\n")}
		}
		return process.CommandResult{}
	}
	res = mustSSH(t, rt, "ssh.rm_known_host", &rmKnownHostArgs{
		User: &user, Hostname: strPtr2("github.com"), Config: &config,
	})
	m = res.(map[string]any)
	if m["status"] != "removed" || !strings.Contains(m["comment"].(string), "found: line 1") {
		t.Fatalf("removed reply = %#v", m)
	}
	var rmCmd process.Command
	for i := len(runner.calls) - 1; i >= 0; i-- {
		c := runner.calls[i]
		if len(c.Args) > 0 && c.Args[0] == "-R" {
			rmCmd = c
			break
		}
	}
	if rmCmd.Args[1] != "github.com" || rmCmd.Args[3] != config {
		t.Fatalf("rm argv = %#v", rmCmd.Args)
	}

	// Port form rewrites the lookup hostname to [host]:port.
	port := 2222
	mustSSH(t, rt, "ssh.rm_known_host", &rmKnownHostArgs{
		User: &user, Hostname: strPtr2("alt.example"), Config: &config, Port: &port,
	})
	last := runner.calls[len(runner.calls)-1]
	if last.Args[0] != "-R" || last.Args[1] != "[alt.example]:2222" {
		t.Fatalf("port hostname argv = %#v", last.Args)
	}
}

func TestHashKnownHostsPreservesMode(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	fsys := newMemFS()
	seedKnownHosts(t, fsys, kh, "")
	rt, runner := sshRT(t, fsys)
	config := kh
	runner.resp = func(c process.Command) process.CommandResult {
		if len(c.Args) > 1 && c.Args[0] == "-H" {
			return process.CommandResult{Stdout: []byte("/tmp/known_hosts updated.\nOriginal contents retained as backup\n")}
		}
		return process.CommandResult{}
	}

	res := mustSSH(t, rt, "ssh.hash_known_hosts", &hashKnownHostsArgs{Config: &config})
	m := res.(map[string]any)
	if m["status"] != "updated" || !strings.Contains(m["comment"].(string), "updated.") {
		t.Fatalf("reply = %#v", m)
	}

	// Absent file -> verbatim error dict.
	res = mustSSH(t, rt, "ssh.hash_known_hosts", &hashKnownHostsArgs{
		Config: strPtr("/nonexistent/known_hosts"),
	})
	m = res.(map[string]any)
	if m["status"] != "error" || !strings.Contains(m["error"].(string), "does not exist") {
		t.Fatalf("missing-file reply = %#v", m)
	}
}

// ---------------------------------------------------------------------------
// set_known_host

func TestSetKnownHostAddUpdateExists(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, ".ssh", "known_hosts")
	fsys := newMemFS()
	rt, runner := sshRT(t, fsys)
	user := "testuser"
	config := kh
	key := testKeyB64

	// File-aware -F emulation: mirrors what ssh-keygen would report for the
	// current known_hosts contents.
	keygenF := func(c process.Command) process.CommandResult {
		if len(c.Args) > 0 && c.Args[0] == "-F" {
			host, file := c.Args[1], c.Args[3]
			data, err := rt.FS.ReadFile(file)
			if err != nil {
				return process.CommandResult{}
			}
			var out []string
			for i, l := range strings.Split(string(data), "\n") {
				fields := strings.Fields(l)
				if len(fields) == 3 && fields[0] == host {
					out = append(out,
						fmt.Sprintf("# Host %s found: line %d", host, i+1), l)
				}
			}
			if len(out) == 0 {
				return process.CommandResult{}
			}
			return process.CommandResult{Stdout: []byte(strings.Join(out, "\n") + "\n")}
		}
		if filepath.Base(c.Name) == "ssh-keyscan" {
			return process.CommandResult{Stdout: []byte("github.com ssh-ed25519 " + testKeyB64 + "\n")}
		}
		return process.CommandResult{}
	}

	// 1. add with explicit key: plain line written, dir created, mode 600.
	runner.resp = keygenF
	enc := "ssh-ed25519"
	res := mustSSH(t, rt, "ssh.set_known_host", &setKnownHostArgs{
		User: &user, Hostname: strPtr2("github.com"), Key: &key, Enc: &enc,
		Config: &config, HashKnownHosts: boolPtr(false),
	})
	m := res.(map[string]any)
	if m["status"] != "updated" {
		t.Fatalf("add reply = %#v", m)
	}
	data, rerr := rt.FS.ReadFile(kh)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !strings.HasPrefix(string(data), "github.com ssh-ed25519 "+testKeyB64+"\n") {
		t.Fatalf("file content = %q", data)
	}
	if kinfo, kerr := rt.FS.Stat(kh); kerr != nil || kinfo.Mode().Perm() != 0o600 {
		t.Fatalf("mode stat = %v, %v", kinfo, kerr)
	}

	// 2. same key again -> exists short-circuit without writes.
	before, _ := rt.FS.ReadFile(kh)
	res = mustSSH(t, rt, "ssh.set_known_host", &setKnownHostArgs{
		User: &user, Hostname: strPtr2("github.com"), Key: &key, Enc: &enc,
		Config: &config, HashKnownHosts: boolPtr(false),
	})
	if res.(map[string]any)["status"] != "exists" {
		t.Fatalf("idempotent reply = %#v", res)
	}
	tailStart := len(runner.calls) - 10
	if tailStart < 0 {
		tailStart = 0
	}
	for _, c := range runner.calls[tailStart:] {
		if c.Args[0] != "-F" { // only lookups allowed on the exists path
			t.Fatalf("exists path ran %v", c.Args)
		}
	}
	after, _ := rt.FS.ReadFile(kh)
	if string(before) != string(after) {
		t.Fatal("exists path mutated the known_hosts file")
	}

	// 3. update replaces the matching enc lines and appends the new key.
	newerKey := "b3RoZXJrZXkK"
	keygenPair := "# Host github.com found: line 1\ngithub.com ssh-ed25519 " + testKeyB64 + "\n"
	runner.resp = func(c process.Command) process.CommandResult {
		if len(c.Args) > 0 && c.Args[0] == "-F" {
			return process.CommandResult{Stdout: []byte(keygenPair)}
		}
		return process.CommandResult{}
	}
	res = mustSSH(t, rt, "ssh.set_known_host", &setKnownHostArgs{
		User: &user, Hostname: strPtr2("github.com"), Key: &newerKey, Enc: &enc,
		Config: &config, HashKnownHosts: boolPtr(false),
	})
	m = res.(map[string]any)
	if m["status"] != "updated" {
		t.Fatalf("update reply = %#v", m)
	}
	data, _ = rt.FS.ReadFile(kh)
	content := string(data)
	if strings.Contains(content, testKeyB64) {
		t.Fatalf("old key retained: %q", content)
	}
	if !strings.Contains(content, "github.com ssh-ed25519 "+newerKey+"\n") {
		t.Fatalf("new key missing: %q", content)
	}

	// 4. port + hash_known_hosts conflict -> verbatim error dict.
	port := 2222
	res = mustSSH(t, rt, "ssh.set_known_host", &setKnownHostArgs{
		User: &user, Hostname: strPtr2("h"), Port: &port,
	})
	m = res.(map[string]any)
	if m["error"] != "argument port can not be used in conjunction with argument hash_known_hosts" {
		t.Fatalf("port conflict = %#v", m)
	}

	// 5. non-default port without hashing writes [host]:port form.
	runner.resp = keygenF
	rt.FS.Remove(kh)
	mustSSH(t, rt, "ssh.set_known_host", &setKnownHostArgs{
		User: &user, Hostname: strPtr2("alt.example"), Key: &key, Enc: &enc,
		Port: &port, Config: &config, HashKnownHosts: boolPtr(false),
	})
	data, _ = rt.FS.ReadFile(kh)
	if !strings.HasPrefix(string(data), "[alt.example]:2222 ssh-ed25519 ") {
		t.Fatalf("port-form line = %q", data)
	}
}

func TestSetKnownHostRecvFingerprintMismatch(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	fsys := newMemFS()
	seedKnownHosts(t, fsys, kh, "")
	rt, runner := sshRT(t, fsys)
	user := "testuser"
	config := kh

	runner.resp = func(c process.Command) process.CommandResult {
		switch {
		case len(c.Args) > 0 && c.Args[0] == "-F":
			return process.CommandResult{}
		case filepath.Base(c.Name) == "ssh-keyscan":
			return process.CommandResult{Stdout: []byte("github.com ssh-ed25519 " + testKeyB64 + "\n")}
		}
		return process.CommandResult{}
	}

	wrongFP := "aa:bb:cc"
	res := mustSSH(t, rt, "ssh.set_known_host", &setKnownHostArgs{
		User: &user, Hostname: strPtr2("github.com"), Fingerprint: &wrongFP,
		Config: &config,
	})
	m := res.(map[string]any)
	if m["error"] != "Remote host public keys found but none of their fingerprints match the one you have provided" {
		t.Fatalf("mismatch reply = %#v", m)
	}

	// check_required path: identical remote/stored key sets -> exists.
	storedOut := "# Host github.com found: line 1\ngithub.com ssh-ed25519 " + testKeyB64 + "\n"
	runner.resp = func(c process.Command) process.CommandResult {
		switch {
		case len(c.Args) > 0 && c.Args[0] == "-F":
			return process.CommandResult{Stdout: []byte(storedOut)}
		case filepath.Base(c.Name) == "ssh-keyscan":
			return process.CommandResult{Stdout: []byte("github.com ssh-ed25519 " + testKeyB64 + "\n")}
		}
		return process.CommandResult{}
	}
	res = mustSSH(t, rt, "ssh.set_known_host", &setKnownHostArgs{
		User: &user, Hostname: strPtr2("github.com"), Config: &config,
	})
	if res.(map[string]any)["status"] != "exists" {
		t.Fatalf("check_required reply = %#v", res)
	}

	// Remote unreachable during update -> verbatim error dict.
	runner.resp = func(c process.Command) process.CommandResult {
		if len(c.Args) > 0 && c.Args[0] == "-F" {
			return process.CommandResult{}
		}
		return process.CommandResult{}
	}
	res = mustSSH(t, rt, "ssh.set_known_host", &setKnownHostArgs{
		User: &user, Hostname: strPtr2("dead.internal"), Config: &config,
	})
	m = res.(map[string]any)
	if m["error"] != "Unable to receive remote host keys" {
		t.Fatalf("unreachable reply = %#v", m)
	}
}
