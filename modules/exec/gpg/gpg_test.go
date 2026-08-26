package gpg

// R5.6 tests for the gpg cryptographic core, mapped onto the source
// contracts of saltstack/salt/modules/gpg.py @ pinned revision. The fake
// Runner supplies gpg's stdout plus --status-fd 2 status lines on stderr.

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type gpgRunner struct {
	calls []process.Command
	resp  func(process.Command) process.CommandResult
}

func (r *gpgRunner) Run(_ context.Context, c process.Command) process.CommandResult {
	r.calls = append(r.calls, c)
	if r.resp != nil {
		return r.resp(c)
	}
	return process.CommandResult{}
}

func gpgRT(t *testing.T) (*runtime.Runtime, *gpgRunner) {
	t.Helper()
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
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

type userStubG struct{}

func (userStubG) Name() string { return "user.info" }
func (userStubG) Args() any    { return struct{}{} }
func (userStubG) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	type nameArgs struct {
		Name string `statekit:"required"`
	}
	a := &nameArgs{}
	if m, ok := args.(map[string]any); ok {
		if s, ok2 := m["name"].(string); ok2 {
			a.Name = s
		}
	}
	if a.Name == "" || a.Name == "testuser" {
		return map[string]any{
			"name": "testuser", "uid": 1234, "gid": 1234, "home": "/home/testuser",
			"shell": "/bin/sh", "gecos": "", "groups": []string{"testuser"},
		}, nil
	}
	return nil, context.Canceled
}

func mustG(t *testing.T, rt *runtime.Runtime, name string, args any) any {
	t.Helper()
	res, err := rt.Exec.Call(context.Background(), rt, name, args)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

const armored = "-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----\n"
const clearSigned = "-----BEGIN PGP SIGNED MESSAGE-----\nhash: sha256\nbody\n-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----\n"

func goodStatus(keyID, fpr string) string {
	return "[GNUPG:] GOODSIG " + keyID + " Test User <test@example.com>\n" +
		"[GNUPG:] VALIDSIG " + fpr + " 2026-01-01 1700000000 0 4 0 1 8  " + fpr + "\n" +
		"[GNUPG:] TRUST_FULLY \n"
}

func TestEncryptDecryptRoundtripShapes(t *testing.T) {
	rt, runner := gpgRT(t)
	runner.resp = func(c process.Command) process.CommandResult {
		for _, arg := range c.Args {
			if arg == "--encrypt" {
				return process.CommandResult{Stdout: []byte(armored)}
			}
			if arg == "--decrypt" {
				return process.CommandResult{Stdout: []byte("secret payload")}
			}
		}
		return process.CommandResult{ExitCode: 2}
	}

	res := mustG(t, rt, "gpg.encrypt", &encryptArgs{
		Text: strPtrG("secret payload"), Recipients: []string{"ops@example.com"},
	})
	m := res.(map[string]any)
	if m["res"] != true || m["comment"] != armored {
		t.Fatalf("encrypt reply = %#v", m)
	}

	res = mustG(t, rt, "gpg.decrypt", &decryptArgs{
		Text: ptrG(armored),
	})
	m = res.(map[string]any)
	if m["res"] != true || m["comment"] != "secret payload" {
		t.Fatalf("decrypt reply = %#v", m)
	}

	// bare mode returns the raw strings without the res dict.
	bare := true
	res = mustG(t, rt, "gpg.encrypt", &encryptArgs{
		Text: strPtrG("secret payload"), Recipients: []string{"ops@example.com"},
		Bare: &bare,
	})
	if res != armored {
		t.Fatalf("bare encrypt = %#v", res)
	}
	res = mustG(t, rt, "gpg.decrypt", &decryptArgs{Text: ptrG(armored), Bare: &bare})
	if res != "secret payload" {
		t.Fatalf("bare decrypt = %#v", res)
	}

	// output target switches the comment text.
	outPath := "/tmp/enc.out"
	res = mustG(t, rt, "gpg.encrypt", &encryptArgs{
		Text: strPtrG("x"), Recipients: []string{"ops@example.com"}, Output: ptrG(outPath),
	})
	m = res.(map[string]any)
	if m["comment"] != "Encrypted data has been written to "+outPath {
		t.Fatalf("output comment = %#v", m["comment"])
	}

	// Guards: missing input and missing binary.
	_, err := encryptFunc{}.Execute(context.Background(), rt, &encryptArgs{})
	if err == nil || err.Error() != "filename or text must be passed." {
		t.Fatalf("input guard = %v", err)
	}
	orig := whichBin
	whichBin = func(string) string { return "" }
	t.Cleanup(func() { whichBin = orig })
	_, err = decryptFunc{}.Execute(context.Background(), rt, &decryptArgs{
		Text: ptrG(armored),
	})
	if err == nil ||
		err.Error() != "The gpg execution module cannot be loaded: gpg binary is not in the path." {
		t.Fatalf("which-guard = %v", err)
	}
}

func ptrG(s string) *string { return &s }

func strPtrG(s string) *string { return &s }

func TestSignProducesArmoredData(t *testing.T) {
	rt, runner := gpgRT(t)
	runner.resp = func(c process.Command) process.CommandResult {
		for _, arg := range c.Args {
			if arg == "--sign" {
				return process.CommandResult{Stdout: []byte(clearSigned)}
			}
		}
		return process.CommandResult{ExitCode: 2}
	}

	keyid := "ABCDEF01"
	res := mustG(t, rt, "gpg.sign", &signArgs{
		Text: strPtrG("hello"), Keyid: &keyid,
	})
	if res != clearSigned {
		t.Fatalf("sign reply = %#v", res)
	}
	last := runner.calls[len(runner.calls)-1]
	foundLU, foundSign := false, false
	for i, arg := range last.Args {
		if arg == "--local-user" && i+1 < len(last.Args) && last.Args[i+1] == keyid {
			foundLU = true
		}
		if arg == "--sign" {
			foundSign = true
		}
	}
	if !foundLU || !foundSign {
		t.Fatalf("sign argv missing pieces: %v", last.Args)
	}

	// Signing failure surfaces the compact error.
	runner.resp = func(process.Command) process.CommandResult {
		return process.CommandResult{ExitCode: 2, Stderr: []byte("[GNUPG:] BAD_PASSPHRASE ABCDEF01\n")}
	}
	_, err := signFunc{}.Execute(context.Background(), rt, &signArgs{
		Text: strPtrG("hello"), Keyid: &keyid,
	})
	if err == nil || err.Error() != "Signing failed" {
		t.Fatalf("failure contract = %v", err)
	}
}

func TestVerifySingleAndMultiCheck(t *testing.T) {
	fprA := "AAAABBBBCCCCDDDD00001111222233334444AAAA"
	fprB := "BBBBCCCCDDDDEEEE11112222333344445555BBBB"
	rt, runner := gpgRT(t)

	// Single-key verification with trust.
	runner.resp = func(c process.Command) process.CommandResult {
		for _, arg := range c.Args {
			if arg == "--verify" {
				return process.CommandResult{
					Stderr:   []byte(goodStatus("ABCDEF01", fprA)),
					ExitCode: 0,
				}
			}
		}
		return process.CommandResult{}
	}
	res := mustG(t, rt, "gpg.verify", &verifyArgs{
		Text: strPtrG("signed body"),
	})
	m := res.(map[string]any)
	if m["res"] != true || m["message"] != "The signature is verified." {
		t.Fatalf("verify reply = %#v", m)
	}
	if m["trust_level"] != "Fully" || m["key_id"] != "ABCDEF01" {
		t.Fatalf("trust fields = %#v", m)
	}

	// Invalid signature -> false message.
	runner.resp = func(c process.Command) process.CommandResult {
		for _, arg := range c.Args {
			if arg == "--verify" {
				return process.CommandResult{
					Stderr:   []byte("[GNUPG:] BADSIG ABCDEF01 Test User\n"),
					ExitCode: 1,
				}
			}
		}
		return process.CommandResult{}
	}
	res = mustG(t, rt, "gpg.verify", &verifyArgs{Text: strPtrG("forged")})
	m = res.(map[string]any)
	if m["res"] != false || m["message"] != "The signature could not be verified." {
		t.Fatalf("invalid verify = %#v", m)
	}

	// Multi-check: signed_by_all requires every listed fingerprint.
	goodBoth := func(process.Command) process.CommandResult {
		return process.CommandResult{
			Stderr:   []byte(goodStatus("ABCDEF01", fprA) + goodStatus("BCDEFGH2", fprB)),
			ExitCode: 0,
		}
	}
	runner.resp = goodBoth
	res = mustG(t, rt, "gpg.verify", &verifyArgs{
		Text:        strPtrG("multi"),
		SignedByAll: []string{fprA, fprB},
	})
	m = res.(map[string]any)
	if m["res"] != true || m["message"] != "All required keys have provided a signature" {
		t.Fatalf("signed_by_all full = %#v", m)
	}

	runner.resp = func(c process.Command) process.CommandResult {
		for _, arg := range c.Args {
			if arg == "--verify" {
				return process.CommandResult{
					Stderr:   []byte(goodStatus("ABCDEF01", fprA)),
					ExitCode: 0,
				}
			}
		}
		return process.CommandResult{}
	}
	res = mustG(t, rt, "gpg.verify", &verifyArgs{
		Text:        strPtrG("partial"),
		SignedByAll: []string{fprA, fprB},
	})
	m = res.(map[string]any)
	if m["res"] != false ||
		m["message"] != "Public key "+fprB+" has not provided a valid signature, but was listed in signed_by_all" {
		t.Fatalf("signed_by_all partial = %#v", m)
	}

	// signed_by_any failure message.
	res = mustG(t, rt, "gpg.verify", &verifyArgs{
		Text:        strPtrG("solo"),
		SignedByAny: []string{fprB},
	})
	m = res.(map[string]any)
	if m["message"] != "None of the public keys listed in signed_by_any provided a valid signature" {
		t.Fatalf("signed_by_any = %#v", m)
	}

	// Invalid trustmodel short-circuits before execution.
	callsBefore := len(runner.calls)
	res = mustG(t, rt, "gpg.verify", &verifyArgs{
		Text: strPtrG("x"), Trustmodel: strPtrG("banana"),
	})
	m = res.(map[string]any)
	if m["res"] != false || !strings.Contains(m["message"].(string), "Invalid trustmodel defined: banana") {
		t.Fatalf("trustmodel guard = %#v", m)
	}
	if len(runner.calls) != callsBefore {
		t.Fatal("trustmodel guard ran gpg")
	}
}
