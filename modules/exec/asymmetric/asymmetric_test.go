package asymmetric

// R5.4 tests: sign/verify roundtrips across RSA, ECDSA and Ed25519 mapped
// onto the source contracts of saltstack/salt/modules/asymmetric.py and
// salt/utils/asymmetric.py @ pinned revision. Keys are generated at test
// time with the Go standard library; no external crypto dependencies.

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func asymRT(t *testing.T) *runtime.Runtime {
	t.Helper()
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	return &runtime.Runtime{
		Exec:    reg,
		States:  runtime.NewStateRegistry(),
		FS:      runtime.NewMemoryFS(),
		Runner:  nopRunner{},
		Options: runtime.RuntimeOptions{},
	}
}

type nopRunner struct{}

func (nopRunner) Run(_ context.Context, _ process.Command) process.CommandResult {
	return process.CommandResult{}
}

func mustASYM(t *testing.T, rt *runtime.Runtime, name string, args any) any {
	t.Helper()
	res, err := rt.Exec.Call(context.Background(), rt, name, args)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func pemEncode(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

func writeKey(t *testing.T, rt *runtime.Runtime, name, content string) string {
	t.Helper()
	path := "/" + name
	if err := rt.FS.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const sampleText = "statekit asymmetric roundtrip"

func TestSignVerifyRoundtripRSA(t *testing.T) {
	rt := asymRT(t)
	rsaKey, kerr := rsa.GenerateKey(rand.Reader, 2048)
	if kerr != nil {
		t.Fatal(kerr)
	}
	privPath := writeKey(t, rt, "rsa.key",
		pemEncode(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)))
	pubDER, perr := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if perr != nil {
		t.Fatal(perr)
	}
	pubPath := writeKey(t, rt, "rsa.pub", pemEncode(t, "PUBLIC KEY", pubDER))

	sig := mustASYM(t, rt, "asymmetric.sign", &signArgs{
		Privkey: strPtrAsym(privPath), Text: strPtrAsym(sampleText),
	}).(string)

	res := mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Pubkey: strPtrAsym(pubPath), Text: strPtrAsym(sampleText), Signature: sig,
	})
	v := res.(map[string]any)
	if v["res"] != true || v["message"] != "The signature is valid" {
		t.Fatalf("verify reply = %#v", v)
	}

	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Pubkey: strPtrAsym(pubPath), Text: strPtrAsym("tampered"), Signature: sig,
	})
	if res.(map[string]any)["res"] != false {
		t.Fatalf("tampered verify = %#v", res)
	}
}

func TestSignVerifyRoundtripECDSAAndEd25519(t *testing.T) {
	rt := asymRT(t)

	ecKey, kerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if kerr != nil {
		t.Fatal(kerr)
	}
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	ecPriv := writeKey(t, rt, "ec.key", pemEncode(t, "EC PRIVATE KEY", ecDER))
	ecPubDER, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	ecPub := writeKey(t, rt, "ec.pub", pemEncode(t, "PUBLIC KEY", ecPubDER))

	sig := mustASYM(t, rt, "asymmetric.sign", &signArgs{
		Privkey: strPtrAsym(ecPriv), Text: strPtrAsym(sampleText),
	}).(string)
	res := mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Pubkey: strPtrAsym(ecPub), Text: strPtrAsym(sampleText), Signature: sig,
	})
	if res.(map[string]any)["res"] != true {
		t.Fatalf("ecdsa verify = %#v", res)
	}

	edPub, edPriv, kerr2 := ed25519.GenerateKey(rand.Reader)
	if kerr2 != nil {
		t.Fatal(kerr2)
	}
	edDER, _ := x509.MarshalPKCS8PrivateKey(edPriv)
	edPrivPath := writeKey(t, rt, "ed.key", pemEncode(t, "PRIVATE KEY", edDER))
	edPubDER, _ := x509.MarshalPKIXPublicKey(edPub)
	edPubPath := writeKey(t, rt, "ed.pub", pemEncode(t, "PUBLIC KEY", edPubDER))

	sig = mustASYM(t, rt, "asymmetric.sign", &signArgs{
		Privkey: strPtrAsym(edPrivPath), Text: strPtrAsym(sampleText),
	}).(string)
	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Pubkey: strPtrAsym(edPubPath), Text: strPtrAsym(sampleText), Signature: sig,
	})
	if res.(map[string]any)["res"] != true {
		t.Fatalf("ed25519 verify = %#v", res)
	}
}

func TestSignFileInputWritesSignature(t *testing.T) {
	rt := asymRT(t)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edDER, _ := x509.MarshalPKCS8PrivateKey(edPriv)
	privPath := writeKey(t, rt, "ed.key", pemEncode(t, "PRIVATE KEY", edDER))
	pubDER, _ := x509.MarshalPKIXPublicKey(edPub)
	pubPath := writeKey(t, rt, "ed.pub", pemEncode(t, "PUBLIC KEY", pubDER))
	dataPath := "/data/blob"
	if err := rt.FS.MkdirAll("/data", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile(dataPath, []byte("file payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := mustASYM(t, rt, "asymmetric.sign", &signArgs{
		Privkey: strPtrAsym(privPath), Filename: strPtrAsym(dataPath),
		Path: strPtrAsym("/data/blob.sig"),
	})
	if res != "Signature written to '/data/blob.sig'" {
		t.Fatalf("write reply = %#v", res)
	}
	rawSig, rerr := rt.FS.ReadFile("/data/blob.sig")
	if rerr != nil || len(rawSig) != ed25519.SignatureSize {
		t.Fatalf("raw signature file = %d bytes, %v", len(rawSig), rerr)
	}

	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Pubkey:    strPtrAsym(pubPath),
		Filename:  strPtrAsym(dataPath),
		Signature: base64Std(rawSig),
	})
	if res.(map[string]any)["res"] != true {
		t.Fatalf("file verify = %#v", res)
	}
}

func strPtrAsym(s string) *string { return &s }

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestVerifyMultiCheckFlows(t *testing.T) {
	rt := asymRT(t)
	keyA, privA, _ := ed25519.GenerateKey(rand.Reader)
	keyB, privB, _ := ed25519.GenerateKey(rand.Reader)

	mk := func(name string, priv any, pub any) (string, string) {
		der, _ := x509.MarshalPKCS8PrivateKey(priv)
		privP := writeKey(t, rt, name+".key", pemEncode(t, "PRIVATE KEY", der))
		pubDER, _ := x509.MarshalPKIXPublicKey(pub)
		pubP := writeKey(t, rt, name+".pub", pemEncode(t, "PUBLIC KEY", pubDER))
		return privP, pubP
	}
	privAPath, pubAPath := mk("a", privA, keyA)
	privBPath, pubBPath := mk("b", privB, keyB)
	_ = privAPath

	sigA := mustASYM(t, rt, "asymmetric.sign", &signArgs{
		Privkey: strPtrAsym(privAPath), Text: strPtrAsym(sampleText),
	}).(string)
	sigB := mustASYM(t, rt, "asymmetric.sign", &signArgs{
		Privkey: strPtrAsym(privBPath), Text: strPtrAsym(sampleText),
	}).(string)

	// signed_by_any passes when one listed key signed.
	res := mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAny: []string{pubAPath, pubBPath},
		Signature:   []any{sigB},
	})
	m := res.(map[string]any)
	if m["res"] != true || m["message"] != "All required keys have provided a signature" {
		t.Fatalf("signed_by_any reply = %#v", m)
	}

	// signed_by_all fails until every key provides a signature.
	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAll: []string{pubAPath, pubBPath},
		Signature:   []any{sigB},
	})
	m = res.(map[string]any)
	if m["res"] != false ||
		m["message"] != "Failed while checking `signed_by_all`" {
		t.Fatalf("signed_by_all partial reply = %#v", m)
	}
	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAll: []string{pubAPath, pubBPath},
		Signature:   []any{sigA, sigB},
	})
	if res.(map[string]any)["res"] != true {
		t.Fatalf("signed_by_all full reply = %#v", res)
	}

	// pubkey + multi-check is mutually exclusive.
	_, err := verifyFunc{}.Execute(context.Background(), rt, &verifyArgs{
		Text:        strPtrAsym(sampleText),
		Pubkey:      strPtrAsym(pubAPath),
		SignedByAny: []string{pubBPath},
		Signature:   sigA,
	})
	if err == nil || err.Error() != "Either specify pubkey + signature or signed_by_(any|all)" {
		t.Fatalf("exclusivity guard = %v", err)
	}

	// Missing data / missing signature guards.
	_, err = verifyFunc{}.Execute(context.Background(), rt, &verifyArgs{
		Pubkey:    strPtrAsym(pubAPath),
		Signature: sigA,
	})
	if err == nil || err.Error() != "Missing data to verify. Either specify `text` or `filename`" {
		t.Fatalf("missing-data guard = %v", err)
	}
	_, err = signFunc{}.Execute(context.Background(), rt, &signArgs{
		Privkey: strPtrAsym(privAPath),
	})
	if err == nil || err.Error() != "Either `text` or `filename` is required" {
		t.Fatalf("sign data guard = %v", err)
	}
}
