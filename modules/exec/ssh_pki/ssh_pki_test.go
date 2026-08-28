package ssh_pki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	"golang.org/x/crypto/ssh"
)

type sshPkiRuntime struct {
	rt *runtime.Runtime
	fs *runtime.MemoryFS
}

type sshPkiConfigStub struct {
	values map[string]any
}

func (sshPkiConfigStub) Name() string { return "config.option" }
func (sshPkiConfigStub) Args() any    { return struct{}{} }
func (s sshPkiConfigStub) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	key := ""
	if m, ok := args.(map[string]any); ok {
		key, _ = m["key"].(string)
	}
	if value, ok := s.values[key]; ok {
		return value, nil
	}
	return nil, nil
}

type sshPkiPolicyStub struct {
	name     string
	policies map[string]any
}

func (s sshPkiPolicyStub) Name() string { return s.name }
func (s sshPkiPolicyStub) Args() any    { return struct{}{} }
func (s sshPkiPolicyStub) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return s.policies, nil
}

type noRunSSH struct{}

func (noRunSSH) Run(_ context.Context, _ process.Command) process.CommandResult {
	return process.CommandResult{ExitCode: 0}
}

func newSSHRuntime(t *testing.T) *sshPkiRuntime {
	t.Helper()
	fs := runtime.NewMemoryFS()
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(sshPkiConfigStub{values: map[string]any{"fips_mode": false}}); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{
		Exec:   reg,
		States: runtime.NewStateRegistry(),
		FS:     fs,
		Runner: noRunSSH{},
	}
	return &sshPkiRuntime{rt: rt, fs: fs}
}

func callSSH[T any](t *testing.T, rt *runtime.Runtime, name string, args T) (any, error) {
	t.Helper()
	fn, ok := rt.Exec.Get(name)
	if !ok {
		t.Fatalf("function %s is not registered", name)
	}
	return fn.Execute(context.Background(), rt, args)
}

func sshPrivatePEM(t *testing.T, key any, passphrase *string) string {
	t.Helper()
	data, err := marshalPrivateKey(key, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func newRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newEdKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func createLocalCertificate(t *testing.T, h *sshPkiRuntime, ca, subject any) string {
	t.Helper()
	res, err := callSSH(t, h.rt, "ssh_pki.create_certificate", &createCertificateArgs{
		Kwargs: map[string]any{
			"signing_private_key": sshPrivatePEM(t, ca, nil),
			"private_key":         sshPrivatePEM(t, subject, nil),
			"cert_type":           "user",
			"valid_principals":    []string{"alice", "web"},
			"key_id":              "test-id",
			"serial_number":       "0102",
			"ttl":                 "1h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, ok := res.(string)
	if !ok {
		t.Fatalf("certificate result type %T", res)
	}
	return out
}

func parseSSHCert(t *testing.T, encoded string) *ssh.Certificate {
	t.Helper()
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(encoded))
	if err != nil {
		t.Fatal(err)
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed %T, want *ssh.Certificate", key)
	}
	return cert
}

func TestCreatePrivateKeyAlgorithmsAndPath(t *testing.T) {
	h := newSSHRuntime(t)
	for _, tc := range []struct {
		name string
		algo string
		bits *int
		kind string
	}{
		{"rsa", "rsa", piSSH(1024), "ssh-rsa"},
		{"ec", "ec", piSSH(256), "ecdsa-sha2-nistp256"},
		{"ed25519", "ed25519", nil, "ssh-ed25519"},
	} {
		res, err := callSSH(t, h.rt, "ssh_pki.create_private_key", &createPrivateKeyArgs{
			Algo: tc.algo, Keysize: tc.bits,
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		value, ok := res.(map[string]any)
		if !ok {
			t.Fatalf("%s result type %T", tc.name, res)
		}
		privateText, _ := value["private_key"].(string)
		publicText, _ := value["public_key"].(string)
		if !strings.HasPrefix(privateText, "-----BEGIN OPENSSH PRIVATE KEY-----") {
			t.Fatalf("%s private PEM header missing", tc.name)
		}
		pub, err := loadPublicKey(h.rt, publicText)
		if err != nil {
			t.Fatalf("%s public parse: %v", tc.name, err)
		}
		if pub.Type() != tc.kind {
			t.Fatalf("%s key type %q, want %q", tc.name, pub.Type(), tc.kind)
		}
	}

	path := "/keys/id"
	if err := h.fs.MkdirAll("/keys", 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := callSSH(t, h.rt, "ssh_pki.create_private_key", &createPrivateKeyArgs{
		Algo: "ed25519", Path: &path,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res != "Private key written to "+path {
		t.Fatalf("path result = %v", res)
	}
	if !fileExists(h.rt, path) || !fileExists(h.rt, path+".pub") {
		t.Fatal("private/public path outputs missing")
	}
	if info, err := h.fs.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private mode: %v %v", info, err)
	}
	if info, err := h.fs.Stat(path + ".pub"); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("public mode: %v %v", info, err)
	}
	_, err = callSSH(t, h.rt, "ssh_pki.create_private_key", &createPrivateKeyArgs{
		Algo: "ed25519", Path: &path,
	})
	if err == nil || !strings.Contains(err.Error(), "overwrite was set to false") {
		t.Fatalf("overwrite guard = %v", err)
	}

	raw, err := callSSH(t, h.rt, "ssh_pki.create_private_key", &createPrivateKeyArgs{
		Algo: "ed25519", Raw: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if data, ok := raw.([]byte); !ok || !bytes.HasPrefix(data, []byte("-----BEGIN OPENSSH PRIVATE KEY-----")) {
		t.Fatalf("raw private result = %T", raw)
	}
}

func piSSH(v int) *int { return &v }

func TestEncodePrivateKeyAndPassphraseErrors(t *testing.T) {
	h := newSSHRuntime(t)
	key := newRSAKey(t, 1024)
	plain := sshPrivatePEM(t, key, nil)
	res, err := callSSH(t, h.rt, "ssh_pki.encode_private_key", &encodePrivateKeyArgs{
		PrivateKey: plain,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out, ok := res.(string); !ok || !strings.HasPrefix(out, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatalf("encoded result = %T", res)
	}

	pass := "secret"
	res, err = callSSH(t, h.rt, "ssh_pki.encode_private_key", &encodePrivateKeyArgs{
		PrivateKey: plain, Passphrase: &pass,
	})
	if err != nil {
		t.Fatal(err)
	}
	encrypted, _ := res.(string)
	if !strings.Contains(encrypted, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatal("encrypted output is not OpenSSH PEM")
	}
	_, err = callSSH(t, h.rt, "ssh_pki.get_private_key_size", &getPrivateKeySizeArgs{
		PrivateKey: encrypted,
	})
	if err == nil || !strings.Contains(err.Error(), "Private key is encrypted") {
		t.Fatalf("missing passphrase = %v", err)
	}
	wrong := "wrong"
	_, err = callSSH(t, h.rt, "ssh_pki.get_private_key_size", &getPrivateKeySizeArgs{
		PrivateKey: encrypted, Passphrase: &wrong,
	})
	if err == nil || !strings.Contains(err.Error(), "Bad decrypt") {
		t.Fatalf("wrong passphrase = %v", err)
	}
	_, err = callSSH(t, h.rt, "ssh_pki.encode_private_key", &encodePrivateKeyArgs{
		PrivateKey: plain, PrivateKeyPassphrase: &pass,
	})
	if err == nil || !strings.Contains(err.Error(), "Password was given but private key is not encrypted") {
		t.Fatalf("passphrase on plain key = %v", err)
	}

	res, err = callSSH(t, h.rt, "ssh_pki.encode_private_key", &encodePrivateKeyArgs{
		PrivateKey: encrypted, PrivateKeyPassphrase: &pass, Raw: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if data, ok := res.([]byte); !ok || !bytes.HasPrefix(data, []byte("-----BEGIN OPENSSH PRIVATE KEY-----")) {
		t.Fatalf("raw encoded result = %T", res)
	}
}

func TestCreateCertificateLocalAndPathOutputs(t *testing.T) {
	h := newSSHRuntime(t)
	ca := newRSAKey(t, 1024)
	subject := newEdKey(t)
	caPEM := sshPrivatePEM(t, ca, nil)
	subjectPEM := sshPrivatePEM(t, subject, nil)
	kwargs := map[string]any{
		"signing_private_key": caPEM,
		"private_key":         subjectPEM,
		"cert_type":           "user",
		"valid_principals":    []string{"alice", "web"},
		"key_id":              "test-id",
		"serial_number":       "0102",
		"ttl":                 "1h",
		"critical_options": map[string]any{
			"force-command":      "/bin/id",
			"no-port-forwarding": true,
			"dropped":            false,
		},
		"extensions": map[string]any{
			"permit-pty":        true,
			"custom-extension":  "value",
			"dropped-extension": false,
		},
	}
	res, err := callSSH(t, h.rt, "ssh_pki.create_certificate", &createCertificateArgs{Kwargs: kwargs})
	if err != nil {
		t.Fatal(err)
	}
	encoded, ok := res.(string)
	if !ok || strings.HasSuffix(encoded, "\n") {
		t.Fatalf("certificate encoding = %q", encoded)
	}
	cert := parseSSHCert(t, encoded)
	if cert.Serial != 0x102 || cert.CertType != ssh.UserCert || cert.KeyId != "test-id" {
		t.Fatalf("certificate metadata: serial=%d type=%d keyid=%q", cert.Serial, cert.CertType, cert.KeyId)
	}
	if !publicKeysEqual(cert.Key, compilePublicKeyLine(encodePublicKey(cert.Key))) {
		t.Fatal("subject public key did not round-trip")
	}
	if cert.Permissions.CriticalOptions["force-command"] != "/bin/id" ||
		cert.Permissions.CriticalOptions["no-port-forwarding"] != "" ||
		cert.Permissions.Extensions["permit-pty"] != "" ||
		cert.Permissions.Extensions["custom-extension"] != "value" {
		t.Fatalf("permissions: %+v", cert.Permissions)
	}
	if _, ok := cert.Permissions.CriticalOptions["dropped"]; ok {
		t.Fatal("false critical option was not dropped")
	}
	if err := verifyCertificateSignature(cert); err != nil {
		t.Fatal(err)
	}

	copyPath := "/issued"
	if err := h.fs.MkdirAll(copyPath, 0o755); err != nil {
		t.Fatal(err)
	}
	path := "/issued/result.cert"
	kwargs2 := cloneMap(kwargs)
	kwargs2["copypath"] = copyPath
	res, err = callSSH(t, h.rt, "ssh_pki.create_certificate", &createCertificateArgs{
		Kwargs: kwargs2, Path: &path,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res != "Certificate written to "+path || !fileExists(h.rt, path) ||
		!fileExists(h.rt, copyPath+"/102.crt") {
		t.Fatalf("path/copy result = %v", res)
	}
	overwrite := false
	_, err = callSSH(t, h.rt, "ssh_pki.create_certificate", &createCertificateArgs{
		Kwargs: kwargs2, Path: &path, Overwrite: overwrite,
	})
	if err == nil || !strings.Contains(err.Error(), "overwrite was set to false") {
		t.Fatalf("certificate overwrite guard = %v", err)
	}

	rawRes, err := callSSH(t, h.rt, "ssh_pki.create_certificate", &createCertificateArgs{
		Kwargs: kwargs, Raw: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if raw, ok := rawRes.([]byte); !ok || !bytes.Contains(raw, []byte("cert-v01@openssh.com")) {
		t.Fatalf("raw certificate result = %T", rawRes)
	}
}

func TestCreateCertificateValidationAndRemoteBoundary(t *testing.T) {
	h := newSSHRuntime(t)
	ca := sshPrivatePEM(t, newRSAKey(t, 1024), nil)
	subject := sshPrivatePEM(t, newEdKey(t), nil)
	_, err := callSSH(t, h.rt, "ssh_pki.create_certificate", &createCertificateArgs{})
	if err == nil || !strings.Contains(err.Error(), "at least requires a signing private key") {
		t.Fatalf("missing signer = %v", err)
	}
	_, err = callSSH(t, h.rt, "ssh_pki.create_certificate", &createCertificateArgs{
		CaServer: psSSH("ca"),
	})
	if err == nil || !strings.Contains(err.Error(), "signing_policy must be specified") {
		t.Fatalf("remote missing policy = %v", err)
	}
	_, err = callSSH(t, h.rt, "ssh_pki.create_certificate", &createCertificateArgs{
		CaServer: psSSH("ca"), SigningPolicy: psSSH("policy"),
	})
	if err == nil || !strings.Contains(err.Error(), "peer communication") {
		t.Fatalf("remote boundary = %v", err)
	}

	_, err = callSSH(t, h.rt, "ssh_pki.create_certificate", &createCertificateArgs{
		Kwargs: map[string]any{
			"signing_private_key": ca,
			"private_key":         subject,
			"cert_type":           "bad",
			"all_principals":      true,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "either `user` or `host`") {
		t.Fatalf("bad cert type = %v", err)
	}
	_, err = callSSH(t, h.rt, "ssh_pki.create_certificate", &createCertificateArgs{
		Kwargs: map[string]any{
			"signing_private_key": ca,
			"private_key":         subject,
			"cert_type":           "user",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "principals") {
		t.Fatalf("missing principals = %v", err)
	}
}

func psSSH(s string) *string { return &s }

func TestReadCertificateVerificationAndExpiry(t *testing.T) {
	h := newSSHRuntime(t)
	ca := newRSAKey(t, 1024)
	subject := newEdKey(t)
	encoded := createLocalCertificate(t, h, ca, subject)
	res, err := callSSH(t, h.rt, "ssh_pki.read_certificate", &readCertificateArgs{Certificate: encoded})
	if err != nil {
		t.Fatal(err)
	}
	info, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("read result type %T", res)
	}
	if info["cert_type"] != "user" || info["key_type"] != "ed25519" ||
		info["serial_number"] != "01:02" || info["key_id"] != "test-id" {
		t.Fatalf("read metadata = %v", info)
	}
	if info["valid_principals"] == "all" {
		t.Fatal("principals unexpectedly all")
	}
	if _, ok := info["issuer_public_key_fingerprints"].(map[string]string); !ok {
		t.Fatalf("issuer fingerprints = %T", info["issuer_public_key_fingerprints"])
	}
	pubLine := info["public_key"].(string)
	caLine := info["issuer_public_key"].(string)
	res, err = callSSH(t, h.rt, "ssh_pki.verify_private_key", &verifyPrivateKeyArgs{
		PrivateKey: sshPrivatePEM(t, subject, nil), PublicKey: pubLine,
	})
	if err != nil || res != true {
		t.Fatalf("verify pair = %v %v", res, err)
	}
	other := sshPrivatePEM(t, newEdKey(t), nil)
	res, err = callSSH(t, h.rt, "ssh_pki.verify_private_key", &verifyPrivateKeyArgs{
		PrivateKey: other, PublicKey: pubLine,
	})
	if err != nil || res != false {
		t.Fatalf("wrong pair = %v %v", res, err)
	}
	res, err = callSSH(t, h.rt, "ssh_pki.verify_signature", &verifySignatureArgs{
		Certificate: encoded, SigningPubKey: caLine,
	})
	if err != nil || res != true {
		t.Fatalf("verify signature = %v %v", res, err)
	}
	wrongCA := sshPrivatePEM(t, newRSAKey(t, 1024), nil)
	wrongCARes, err := callSSH(t, h.rt, "ssh_pki.get_public_key", &getPublicKeyArgs{Key: wrongCA})
	if err != nil {
		t.Fatal(err)
	}
	res, err = callSSH(t, h.rt, "ssh_pki.verify_signature", &verifySignatureArgs{
		Certificate: encoded, SigningPubKey: wrongCARes.(string),
	})
	if err != nil || res != false {
		t.Fatalf("wrong signature key = %v %v", res, err)
	}

	cert := parseSSHCert(t, encoded)
	cert.KeyId = "tampered"
	tampered := string(certBytes(cert))
	res, err = callSSH(t, h.rt, "ssh_pki.verify_signature", &verifySignatureArgs{
		Certificate: tampered, SigningPubKey: caLine,
	})
	if err != nil || res != false {
		t.Fatalf("tampered signature = %v %v", res, err)
	}

	res, err = callSSH(t, h.rt, "ssh_pki.expires", &expiresArgs{Certificate: encoded})
	if err != nil || res != false {
		t.Fatalf("fresh expires = %v %v", res, err)
	}
	res, err = callSSH(t, h.rt, "ssh_pki.expires", &expiresArgs{Certificate: encoded, TTL: "2h"})
	if err != nil || res != true {
		t.Fatalf("future expires = %v %v", res, err)
	}

	// A past certificate is still cryptographically loadable, but expires.
	past := time.Now().UTC().Add(-2 * time.Hour).Format(sshTimeFormat)
	res, err = callSSH(t, h.rt, "ssh_pki.create_certificate", &createCertificateArgs{
		Kwargs: map[string]any{
			"signing_private_key": sshPrivatePEM(t, ca, nil),
			"private_key":         sshPrivatePEM(t, subject, nil),
			"cert_type":           "user",
			"valid_principals":    []string{"alice"},
			"not_before":          past,
			"not_after":           past,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err = callSSH(t, h.rt, "ssh_pki.expires", &expiresArgs{Certificate: res.(string)})
	if err != nil || res != true {
		t.Fatalf("past expires = %v %v", res, err)
	}
}

func TestSigningPolicyAndRemoteHandler(t *testing.T) {
	h := newSSHRuntime(t)
	ca := newRSAKey(t, 1024)
	subject := newEdKey(t)
	policy := map[string]any{
		"cert_type":                "host",
		"signing_private_key":      sshPrivatePEM(t, ca, nil),
		"key_id":                   "forced-id",
		"valid_principals":         []string{"a", "b"},
		"default_critical_options": map[string]any{"source-address": "10.0.0.0/8"},
		"allowed_critical_options": []any{"source-address", "force-command"},
		"critical_options":         map[string]any{"force-command": "/bin/true"},
		"default_extensions":       map[string]any{"permit-pty": true},
		"allowed_extensions":       []any{"permit-pty", "permit-agent-forwarding"},
		"ttl":                      "2h",
		"max_ttl":                  "3h",
	}
	if err := h.rt.Exec.Register(sshPkiPolicyStub{
		name: "pillar.get", policies: map[string]any{"policy": policy},
	}); err != nil {
		t.Fatal(err)
	}

	// create_certificate performs the source's pre-policy signer check, so
	// supply the signer in the request too; policy still wins over metadata.
	res, err := callSSH(t, h.rt, "ssh_pki.create_certificate", &createCertificateArgs{
		SigningPolicy: psSSH("policy"),
		Kwargs: map[string]any{
			"signing_private_key": sshPrivatePEM(t, ca, nil),
			"private_key":         sshPrivatePEM(t, subject, nil),
			"cert_type":           "user",
			"valid_principals":    []string{"b", "not-allowed"},
			"key_id":              "request-id",
			"ttl":                 "10h",
			"critical_options":    map[string]any{"source-address": "192.0.2.0/24", "ignored": true},
			"extensions":          map[string]any{"permit-agent-forwarding": true, "ignored": true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cert := parseSSHCert(t, res.(string))
	if cert.CertType != ssh.HostCert || cert.KeyId != "forced-id" ||
		len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "b" {
		t.Fatalf("policy metadata: %+v", cert)
	}
	if cert.Permissions.CriticalOptions["force-command"] != "/bin/true" ||
		cert.Permissions.CriticalOptions["source-address"] != "192.0.2.0/24" ||
		cert.Permissions.Extensions["permit-pty"] != "" ||
		cert.Permissions.Extensions["permit-agent-forwarding"] != "" {
		t.Fatalf("policy permissions: %+v", cert.Permissions)
	}
	if _, ok := cert.Permissions.CriticalOptions["ignored"]; ok {
		t.Fatal("disallowed critical option survived")
	}
	if _, ok := cert.Permissions.Extensions["ignored"]; ok {
		t.Fatal("disallowed extension survived")
	}

	res, err = callSSH(t, h.rt, "ssh_pki.get_signing_policy",
		&getSigningPolicyArgs{SigningPolicy: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := res.(map[string]any); !ok || got["key_id"] != "forced-id" {
		t.Fatalf("local policy = %v", res)
	}

	res, err = callSSH(t, h.rt, "ssh_pki.sign_remote_certificate", &signRemoteCertificateArgs{
		SigningPolicy: "policy", GetSigningPolicyOnly: true, Kwargs: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	remotePolicy := res.(map[string]any)
	data := remotePolicy["data"].(map[string]any)
	if _, ok := data["signing_private_key"]; ok {
		t.Fatal("private key leaked from policy-only response")
	}
	if _, ok := data["signing_public_key"].(string); !ok {
		t.Fatalf("signing public key = %T", data["signing_public_key"])
	}

	res, err = callSSH(t, h.rt, "ssh_pki.sign_remote_certificate", &signRemoteCertificateArgs{
		SigningPolicy: "policy", Kwargs: map[string]any{
			"private_key":      sshPrivatePEM(t, subject, nil),
			"valid_principals": []string{"a"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	remote := res.(map[string]any)
	if len(remote["errors"].([]string)) != 0 {
		t.Fatalf("remote errors = %v", remote["errors"])
	}
	if _, ok := remote["data"].([]byte); !ok {
		t.Fatalf("remote data type = %T", remote["data"])
	}

	// A policy with a requester matcher cannot be evaluated without the
	// master-provided __pub_id in a local-only runtime.
	if err := h.rt.Exec.Register(sshPkiPolicyStub{
		name: "config.get", policies: map[string]any{"matched": map[string]any{
			"minions": "host*", "cert_type": "host", "signing_private_key": sshPrivatePEM(t, ca, nil),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	res, err = callSSH(t, h.rt, "ssh_pki.sign_remote_certificate", &signRemoteCertificateArgs{
		SigningPolicy: "matched", Kwargs: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]any)["errors"].([]string); len(got) != 1 ||
		got[0] != "minion sending this request could not be identified" {
		t.Fatalf("matcher response = %v", res)
	}

	remoteName := "ca"
	_, err = callSSH(t, h.rt, "ssh_pki.get_signing_policy", &getSigningPolicyArgs{
		SigningPolicy: "policy", CaServer: &remoteName,
	})
	if err == nil || !strings.Contains(err.Error(), "peer communication") {
		t.Fatalf("remote policy boundary = %v", err)
	}
}

func TestSigningPolicyMissingAndTimeParser(t *testing.T) {
	h := newSSHRuntime(t)
	res, err := callSSH(t, h.rt, "ssh_pki.sign_remote_certificate", &signRemoteCertificateArgs{
		SigningPolicy: "missing", Kwargs: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]any)["errors"].([]string); len(got) != 1 ||
		got[0] != "signing_policy must be specified and defined on signing minion" {
		t.Fatalf("missing policy = %v", res)
	}
	for _, tc := range []struct {
		input any
		want  float64
	}{
		{"30d", 30 * 24 * 60 * 60},
		{"1.5h", 1.5 * 60 * 60},
		{"12", 12},
	} {
		got, err := timeStringMap(tc.input)
		if err != nil || got == nil || *got != tc.want {
			t.Fatalf("timeStringMap(%v) = %v %v", tc.input, got, err)
		}
	}
	if _, err := timeStringMap("bogus"); err == nil {
		t.Fatal("invalid time string accepted")
	}
}

func TestKeyTypeAndPublicKeyFailure(t *testing.T) {
	h := newSSHRuntime(t)
	_, err := callSSH(t, h.rt, "ssh_pki.get_public_key", &getPublicKeyArgs{Key: "not-a-key"})
	if err == nil || !strings.Contains(err.Error(), "Could not load key as certificate, public key or private key") {
		t.Fatalf("bad public key = %v", err)
	}
	key := newEdKey(t)
	line := encodePublicKey(compilePublicKeyLine(encodePublicKey(mustSignerPublic(t, key))))
	res, err := callSSH(t, h.rt, "ssh_pki.get_public_key", &getPublicKeyArgs{Key: line})
	if err != nil || res != line {
		t.Fatalf("public key identity = %v %v", res, err)
	}
}

func mustSignerPublic(t *testing.T, key ed25519.PrivateKey) ssh.PublicKey {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}

func TestCertificatePublicBytesRoundTrip(t *testing.T) {
	h := newSSHRuntime(t)
	encoded := createLocalCertificate(t, h, newRSAKey(t, 1024), newEdKey(t))
	cert := parseSSHCert(t, encoded)
	if string(certBytes(cert)) != encoded {
		t.Fatal("certificate public bytes changed during round trip")
	}
	// The x/crypto parser accepts a trailing newline too, as OpenSSH does.
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(encoded + "\n"))
	if err != nil || parsed.(*ssh.Certificate).KeyId != "test-id" {
		t.Fatalf("newline parse = %v %v", parsed, err)
	}
	_ = fmt.Sprint(cert)
}
