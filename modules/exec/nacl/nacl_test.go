package nacl

// R5.5 tests for the NaCl surface, mapped onto the source contracts of
// saltstack/salt/modules/nacl.py and salt/utils/nacl.py @ pinned revision.
// The wire formats (crypto_box_seal and nonce-prefixed crypto_secretbox)
// are exercised through x/crypto's reference implementations so StateKit
// output stays interoperable with PyNaCl/libnacl.

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execcp "github.com/friz-zy/statekit/modules/exec/cp"
)

func naclRT(t *testing.T) *runtime.Runtime {
	t.Helper()
	reg := runtime.NewExecRegistry()
	for _, register := range []func(*runtime.ExecRegistry) error{Register, execcp.Register} {
		if err := register(reg); err != nil {
			t.Fatal(err)
		}
	}
	rt := &runtime.Runtime{
		Exec:    reg,
		States:  runtime.NewStateRegistry(),
		FS:      runtime.NewMemoryFS(),
		Runner:  fixedRunnerN{},
		Options: runtime.RuntimeOptions{},
	}
	return rt
}

type fixedRunnerN struct{}

func (fixedRunnerN) Run(_ context.Context, _ process.Command) process.CommandResult {
	return process.CommandResult{}
}

func mustNACL(t *testing.T, rt *runtime.Runtime, name string, args any) any {
	t.Helper()
	res, err := rt.Exec.Call(context.Background(), rt, name, args)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func ptrN(s string) *string { return &s }

func make32() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte('a' + i%26)
	}
	return k
}

func TestKeygenShapesAndFileLifecycle(t *testing.T) {
	rt := naclRT(t)

	// No files: returns the base64 keypair dict.
	res := mustNACL(t, rt, "nacl.keygen", &keygenArgs{})
	kp := res.(map[string]any)
	sk := kp["sk"].(string)
	pk := kp["pk"].(string)
	if len(sk) != 44 || len(pk) != 44 { // 32 bytes -> 44 base64 chars
		t.Fatalf("key lengths = %d/%d", len(sk), len(pk))
	}
	if _, derr := base64.StdEncoding.DecodeString(sk); derr != nil {
		t.Fatalf("sk not base64: %v", derr)
	}

	// sk_file only on a fresh path: writes the secret key with mode 0600.
	res = mustNACL(t, rt, "nacl.keygen", &keygenArgs{
		SkFile: strPtrN("/pki/nacl"),
	})
	if res != "saved sk_file: /pki/nacl" {
		t.Fatalf("sk-only reply = %#v", res)
	}
	info, serr := rt.FS.Stat("/pki/nacl")
	if serr != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("sk mode = %v, %v", info, serr)
	}

	// Existing sk without pk: derives the public key from it.
	res = mustNACL(t, rt, "nacl.keygen", &keygenArgs{SkFile: strPtrN("/pki/nacl")})
	if res != "saved pk_file: /pki/nacl.pub" {
		t.Fatalf("derive reply = %#v", res)
	}

	// Both present now -> verbatim error text.
	_, err := keygenFunc{}.Execute(context.Background(), rt, &keygenArgs{
		SkFile: strPtrN("/pki/nacl"), PkFile: strPtrN("/pki/nacl.pub"),
	})
	if err == nil ||
		err.Error() != "sk_file:/pki/nacl and pk_file:/pki/nacl.pub already exist." {
		t.Fatalf("both-exist error = %v", err)
	}

	// pk_file without sk_file -> verbatim error text.
	_, err = keygenFunc{}.Execute(context.Background(), rt, &keygenArgs{
		PkFile: strPtrN("/pki/x.pub"),
	})
	if err == nil ||
		err.Error() != "sk_file: Must be set inorder to generate a public key." {
		t.Fatalf("pk-without-sk error = %v", err)
	}

	// Fresh explicit pair -> the double-space message quirk is preserved.
	res = mustNACL(t, rt, "nacl.keygen", &keygenArgs{
		SkFile: strPtrN("/pki/pair"), PkFile: strPtrN("/pki/pair.pub"),
	})
	if res != "saved sk_file:/pki/pair  pk_file: /pki/pair.pub" {
		t.Fatalf("pair reply = %#v", res)
	}

	// Derived pk matches X25519(sk, basepoint): decrypt a sealed box made
	// for the pair's pk using the pair's sk.
	enc := mustNACL(t, rt, "nacl.sealedbox_encrypt", &sealedboxEncryptArgs{
		Data: "for-pair", PkFile: strPtrN("/pki/pair.pub"),
	}).(string)
	dec := mustNACL(t, rt, "nacl.sealedbox_decrypt", &sealedboxDecryptArgs{
		Data: ptrN(enc), SkFile: strPtrN("/pki/pair"),
	})
	if dec != "for-pair" {
		t.Fatalf("pair roundtrip = %#v", dec)
	}
}

func TestSecretboxWireFormatAndRoundtrip(t *testing.T) {
	rt := naclRT(t)

	// Deterministic nonce so the wire layout is assertable.
	fixed := [24]byte{}
	for i := range fixed {
		fixed[i] = byte(i)
	}
	origNonce := nonceSource
	nonceSource = func() [24]byte { return fixed }
	t.Cleanup(func() { nonceSource = origNonce })

	sk := base64.StdEncoding.EncodeToString(make32()[:])
	enc := mustNACL(t, rt, "nacl.secretbox_encrypt", &secretboxEncryptArgs{
		Data: "datatoenc", Sk: &sk,
	}).(string)

	raw, derr := base64.StdEncoding.DecodeString(enc)
	if derr != nil {
		t.Fatal(derr)
	}
	if string(raw[:24]) != string(fixed[:]) {
		t.Fatal("nonce is not prefixed to the secretbox payload")
	}
	if len(raw) < 24+16+len("datatoenc") {
		t.Fatalf("payload too short: %d", len(raw))
	}

	dec := mustNACL(t, rt, "nacl.secretbox_decrypt", &secretboxDecryptArgs{
		Data: ptrN(enc), Sk: &sk,
	})
	if dec != "datatoenc" {
		t.Fatalf("roundtrip = %#v", dec)
	}

	// Wrong key fails with the verbatim message.
	wrongBytes := make32()
	wrongBytes[0] ^= 1
	wrong := base64.StdEncoding.EncodeToString(wrongBytes)
	_, err := secretboxDecryptFunc{}.Execute(context.Background(), rt,
		&secretboxDecryptArgs{Data: ptrN(enc), Sk: &wrong})
	if err == nil ||
		err.Error() != "could not decrypt message with passed secret key" {
		t.Fatalf("wrong-key error = %v", err)
	}

	// Tampered ciphertext fails authentication.
	tampered := []byte(raw)
	tampered[30] ^= 0xFF
	_, err = secretboxDecryptFunc{}.Execute(context.Background(), rt,
		&secretboxDecryptArgs{
			Data: ptrN(base64.StdEncoding.EncodeToString(tampered)), Sk: &sk,
		})
	if err == nil {
		t.Fatal("tampered secretbox authenticated?!")
	}
}

func TestSealedboxAnonymousProperty(t *testing.T) {
	rt := naclRT(t)

	kp := mustNACL(t, rt, "nacl.keygen", &keygenArgs{}).(map[string]any)
	pk := kp["pk"].(string)
	sk := kp["sk"].(string)

	// Encryption needs only the public key; decryption needs the secret one.
	enc := mustNACL(t, rt, "nacl.sealedbox_encrypt", &sealedboxEncryptArgs{
		Data: "one-way secret", Pk: &pk,
	}).(string)
	raw, _ := base64.StdEncoding.DecodeString(enc)
	if len(raw) < 32+16+len("one-way secret") {
		t.Fatalf("sealed box too short: %d", len(raw))
	}

	dec := mustNACL(t, rt, "nacl.sealedbox_decrypt", &sealedboxDecryptArgs{
		Data: ptrN(enc), Sk: &sk,
	})
	if dec != "one-way secret" {
		t.Fatalf("sealed roundtrip = %#v", dec)
	}

	// A different secret key cannot open it.
	otherKp := mustNACL(t, rt, "nacl.keygen", &keygenArgs{}).(map[string]any)
	otherSk := otherKp["sk"].(string)
	_, err := sealedboxDecryptFunc{}.Execute(context.Background(), rt,
		&sealedboxDecryptArgs{Data: ptrN(enc), Sk: &otherSk})
	if err == nil ||
		err.Error() != "could not decrypt message with passed private key" {
		t.Fatalf("foreign-key error = %v", err)
	}
}

func TestEncDecRoutingAndConfigDefaults(t *testing.T) {
	rt := naclRT(t)
	kp := mustNACL(t, rt, "nacl.keygen", &keygenArgs{}).(map[string]any)
	pk := kp["pk"].(string)
	sk := kp["sk"].(string)

	// Default box_type is sealedbox.
	enc := mustNACL(t, rt, "nacl.enc", &encArgs{Data: "payload", Pk: &pk}).(string)
	dec := mustNACL(t, rt, "nacl.dec", &decArgs{Data: ptrN(enc), Sk: &sk})
	if dec != "payload" {
		t.Fatalf("default routing roundtrip = %#v", dec)
	}

	// Explicit secretbox routing.
	encSB := mustNACL(t, rt, "nacl.enc", &encArgs{
		Data: "sb", BoxType: strPtrN("secretbox"), Sk: &sk,
	}).(string)
	raw, _ := base64.StdEncoding.DecodeString(encSB)
	if len(raw) < 24 {
		t.Fatal("secretbox enc missing nonce prefix (routing broken)")
	}
	dec = mustNACL(t, rt, "nacl.dec", &decArgs{
		Data: ptrN(encSB), BoxType: strPtrN("secretbox"), Sk: &sk,
	})
	if dec != "sb" {
		t.Fatalf("secretbox routing roundtrip = %#v", dec)
	}

	// config.get delegate supplies nacl.config defaults (overridden by args).
	withCfg(rt, map[string]any{"nacl.config": map[string]any{
		"pk": pk, "sk": sk, "box_type": "sealedbox",
	}})
	encCfg := mustNACL(t, rt, "nacl.enc", &encArgs{Data: "via-config"}).(string)
	decCfg := mustNACL(t, rt, "nacl.dec", &decArgs{Data: ptrN(encCfg)})
	if decCfg != "via-config" {
		t.Fatalf("config-driven roundtrip = %#v", decCfg)
	}
}

type cfgStubN struct{ vals map[string]any }

func (s cfgStubN) Name() string { return "config.get" }
func (s cfgStubN) Args() any    { return struct{}{} }
func (s cfgStubN) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	m, _ := args.(map[string]any)
	key, _ := m["key"].(string)
	return s.vals[key], nil
}

func withCfg(rt *runtime.Runtime, vals map[string]any) {
	if err := rt.Exec.Register(cfgStubN{vals: vals}); err != nil {
		panic(err)
	}
}

func TestEncDecFileFlows(t *testing.T) {
	rt := naclRT(t)
	kp := mustNACL(t, rt, "nacl.keygen", &keygenArgs{}).(map[string]any)
	pk := kp["pk"].(string)
	sk := kp["sk"].(string)

	// Local file input through the FS fallback.
	if err := rt.FS.MkdirAll("/srv/certs", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/srv/certs/key.pem", []byte("PRIVATE MATERIAL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := mustNACL(t, rt, "nacl.enc_file", &encFileArgs{
		Name: "/srv/certs/key.pem", Out: ptrN("/srv/certs/key.nacl"),
		Pk: &pk,
	})
	if res != "Wrote: /srv/certs/key.nacl" {
		t.Fatalf("enc_file reply = %#v", res)
	}

	// Overwriting an existing out file raises the verbatim error.
	_, err := encFileFunc{}.Execute(context.Background(), rt, &encFileArgs{
		Name: "/srv/certs/key.pem", Out: ptrN("/srv/certs/key.nacl"), Pk: &pk,
	})
	if err == nil || err.Error() != "file:/srv/certs/key.nacl already exist." {
		t.Fatalf("out-exists error = %v", err)
	}

	dec := mustNACL(t, rt, "nacl.dec_file", &decFileArgs{
		Name: "/srv/certs/key.nacl", Sk: &sk,
	})
	if dec != "PRIVATE MATERIAL\n" {
		t.Fatalf("dec_file = %#v", dec)
	}

	// secretbox variant writes its own artifact and decrypts it back.
	res = mustNACL(t, rt, "nacl.enc_file", &encFileArgs{
		Name:    "/srv/certs/key.pem",
		Out:     ptrN("/srv/certs/key.sb.nacl"),
		Sk:      &sk,
		BoxType: strPtrN("secretbox"),
	})
	if res != "Wrote: /srv/certs/key.sb.nacl" {
		t.Fatalf("secretbox enc_file reply = %#v", res)
	}
	decRes := mustNACL(t, rt, "nacl.dec_file", &decFileArgs{
		Name:    "/srv/certs/key.sb.nacl",
		Sk:      &sk,
		BoxType: strPtrN("secretbox"),
	})
	if decRes != "PRIVATE MATERIAL\n" {
		t.Fatalf("secretbox dec_file = %#v", decRes)
	}
}

type cpStubN struct {
	content  string
	onlyPath string
}

func (s cpStubN) Name() string { return "cp.get_file_str" }
func (s cpStubN) Args() any    { return struct{}{} }
func (s cpStubN) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*execcp.GetFileStrArgs)
	if !ok {
		return nil, context.Canceled
	}
	if s.onlyPath != "" && a.Path != s.onlyPath {
		return nil, fmt.Errorf("file not found: %s", a.Path)
	}
	return s.content, nil
}
