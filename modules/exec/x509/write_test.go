package x509

// R5.2b tests for the x509 write-side subset, mapped onto the source
// contracts of saltstack/salt/modules/x509.py @ pinned revision and
// the behaviors pinned by tests/unit/modules/test_x509.py (the CA
// kwargs, the not_before/not_after error strings, the CRL revocation
// flow and the encrypted create_private_key output). All PKI material
// is generated inside the tests; no openssl binary, no network.

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/cli"
	"github.com/friz-zy/statekit/internal/runtime"
)

// dhParamsPEM is a normalized DH PARAMETERS block (only the PEM-entry
// regex sees it; nothing parses the numbers).
const dhParamsPEM = `-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA9xXPyDAeK0FZgIwoGRb8bw0cFT9W5U2IPrLbLbnCPqu9qA3B0YJE
Zm0u8nDZRyjvhLc6dFf9qseLfgUK8c5NmoKZB0s5SjKeHcw9nQ9amnbtvWmBCZAh
HXeZmQOmHCwXiCoLeMta8iZI6k9bw0Yf8pGi3C9DwYzSfJ7f6C2gQIynDWcq9X7x
kQIDAQAB
-----END DH PARAMETERS-----
`

// caKwargs mirrors the pinned Salt unit-test x509_args_ca fixture.
func caKwargs(signingPrivateKey string) *createCertificateArgs {
	return &createCertificateArgs{
		Text:                   true,
		CN:                     ps("Redacted Root CA"),
		O:                      ps("Redacted"),
		C:                      ps("BE"),
		ST:                     ps("Antwerp"),
		L:                      ps("Local Town"),
		Email:                  ps("certadm@example.org"),
		BasicConstraints:       ps("critical CA:true"),
		KeyUsage:               ps("critical cRLSign, keyCertSign"),
		SubjectKeyIdentifier:   ps("hash"),
		AuthorityKeyIdentifier: ps("keyid,issuer:always"),
		DaysValid:              pi(3650),
		SigningPrivateKey:      ps(signingPrivateKey),
	}
}

// createCA issues a self-signed CA through the ported surface.
func createCA(t *testing.T, rt *runtime.Runtime, keyPEM string) string {
	t.Helper()
	res, err := callX509(t, rt, "x509.create_certificate", caKwargs(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	certPEM, ok := res.(string)
	if !ok || !strings.Contains(certPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("create_certificate ca = %#v", res)
	}
	return certPEM
}

func parseCertPEM(t *testing.T, pemText string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// ---------------------------------------------------------------------------
// write_pem

func TestWritePemNormalizesAndWrites(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	if err := rt.FS.MkdirAll("/pki", 0o755); err != nil {
		t.Fatal(err)
	}
	mangled := strings.ReplaceAll(fixtureCert, "\n", "")
	res, err := callX509(t, rt, "x509.write_pem", &writePemArgs{
		Text: mangled, Path: "/pki/one.crt", PemType: ps("CERTIFICATE"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res != "PEM written to /pki/one.crt" {
		t.Fatalf("reply = %v", res)
	}
	data, rerr := rt.FS.ReadFile("/pki/one.crt")
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(data) != fixtureCert {
		t.Fatalf("file not normalized:\n%s", data)
	}
	info, serr := rt.FS.Stat("/pki/one.crt")
	if serr != nil {
		t.Fatal(serr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %o, want 0600 (set_umask(0o077))", info.Mode().Perm())
	}
}

func TestWritePemSelectsTypeFromBundle(t *testing.T) {
	keyPEM, _ := rsaKeyPEM(t, 2048)
	rt, _ := x509RT(t, nil, nil)
	if err := rt.FS.MkdirAll("/pki", 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := callX509(t, rt, "x509.write_pem", &writePemArgs{
		Text: fixtureCert + keyPEM, Path: "/pki/cert.crt", PemType: ps("CERTIFICATE"),
	}); err != nil {
		t.Fatal(err)
	}
	data, _ := rt.FS.ReadFile("/pki/cert.crt")
	if string(data) != fixtureCert {
		t.Fatalf("pem_type filter failed:\n%s", data)
	}
}

func TestWritePemPreservesKeyAndDHParams(t *testing.T) {
	keyPEM, _ := rsaKeyPEM(t, 2048)
	rt, _ := x509RT(t, nil, nil)
	if err := rt.FS.MkdirAll("/pki", 0o755); err != nil {
		t.Fatal(err)
	}
	bundle := fixtureCert + keyPEM + dhParamsPEM
	if err := rt.FS.WriteFile("/pki/ca.crt", []byte(bundle), 0o600); err != nil {
		t.Fatal(err)
	}

	// overwrite=False keeps the existing key and DH parameters and
	// rewrites the certificate between them.
	newCert := strings.ReplaceAll(fixtureCert, "\n", "") // force re-normalization
	if _, err := callX509(t, rt, "x509.write_pem", &writePemArgs{
		Text: newCert, Path: "/pki/ca.crt", Overwrite: pb(false), PemType: ps("CERTIFICATE"),
	}); err != nil {
		t.Fatal(err)
	}
	data, _ := rt.FS.ReadFile("/pki/ca.crt")
	normKey, _ := getPemEntryImpl(rt, keyPEM, "(?:RSA )?PRIVATE KEY")
	normDH, _ := getPemEntryImpl(rt, dhParamsPEM, "DH PARAMETERS")
	want := normKey + fixtureCert + normDH
	if string(data) != want {
		t.Fatalf("preserve layout =\n%s\nwant\n%s", data, want)
	}

	// overwrite=True (the default) replaces the whole file.
	if _, err := callX509(t, rt, "x509.write_pem", &writePemArgs{
		Text: newCert, Path: "/pki/ca.crt", PemType: ps("CERTIFICATE"),
	}); err != nil {
		t.Fatal(err)
	}
	data, _ = rt.FS.ReadFile("/pki/ca.crt")
	if string(data) != fixtureCert {
		t.Fatalf("overwrite default replaced =\n%s", data)
	}
}

func TestWritePemMissingParentDir(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	// v1 write_pem has no os.makedirs: a missing parent is an error.
	_, err := callX509(t, rt, "x509.write_pem", &writePemArgs{
		Text: fixtureCert, Path: "/missing/dir/ca.crt", PemType: ps("CERTIFICATE"),
	})
	if err == nil || !strings.Contains(err.Error(), "Could not write to") {
		t.Fatalf("missing parent error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// create_private_key

func TestCreatePrivateKeyText(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	res, err := callX509(t, rt, "x509.create_private_key", &createPrivateKeyArgs{Text: true})
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := res.(string)
	// Documented divergence: PKCS#8 "BEGIN PRIVATE KEY" where M2Crypto
	// wrote PKCS#1.
	if !strings.HasPrefix(keyPEM, "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("container = %.40s", keyPEM)
	}
	sizeRes, serr := callX509(t, rt, "x509.get_private_key_size",
		&getPrivateKeySizeArgs{PrivateKey: keyPEM})
	if serr != nil {
		t.Fatal(serr)
	}
	if sizeRes.(int) != 2048 {
		t.Fatalf("default bits = %v", sizeRes)
	}
}

func TestCreatePrivateKeyPathAndBits(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	if err := rt.FS.MkdirAll("/pki", 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := callX509(t, rt, "x509.create_private_key", &createPrivateKeyArgs{
		Path: ps("/pki/own.key"), Bits: pi(1024),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res != "PEM written to /pki/own.key" {
		t.Fatalf("reply = %v", res)
	}
	info, serr := rt.FS.Stat("/pki/own.key")
	if serr != nil {
		t.Fatal(serr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key perm = %o, want 0600", info.Mode().Perm())
	}
	sizeRes, serr := callX509(t, rt, "x509.get_private_key_size",
		&getPrivateKeySizeArgs{PrivateKey: "/pki/own.key"})
	if serr != nil {
		t.Fatal(serr)
	}
	if sizeRes.(int) != 1024 {
		t.Fatalf("bits = %v", sizeRes)
	}
}

func TestCreatePrivateKeyPassphraseEncryption(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	res, err := callX509(t, rt, "x509.create_private_key", &createPrivateKeyArgs{
		Text: true, Bits: pi(1024), Passphrase: ps("super_secret_passphrase"),
	})
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := res.(string)
	// The upstream envelope: PKCS#1 block with legacy headers.
	if !strings.Contains(keyPEM, "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("encrypted container = %.40s", keyPEM)
	}
	if !strings.Contains(keyPEM, "Proc-Type: 4,ENCRYPTED") ||
		!strings.Contains(keyPEM, "DEK-Info: AES-128-CBC,") {
		t.Fatalf("missing encryption headers:\n%s", keyPEM)
	}
	sizeRes, serr := callX509(t, rt, "x509.get_private_key_size",
		&getPrivateKeySizeArgs{PrivateKey: keyPEM, Passphrase: ps("super_secret_passphrase")})
	if serr != nil {
		t.Fatal(serr)
	}
	if sizeRes.(int) != 1024 {
		t.Fatalf("roundtrip size = %v", sizeRes)
	}
	if _, serr = callX509(t, rt, "x509.get_private_key_size",
		&getPrivateKeySizeArgs{PrivateKey: keyPEM, Passphrase: ps("wrong")}); serr == nil {
		t.Fatal("wrong passphrase must fail")
	}
	// The plaintext branch never emits encryption headers.
	plain, _ := callX509(t, rt, "x509.create_private_key", &createPrivateKeyArgs{Text: true})
	if strings.Contains(plain.(string), "DEK-Info") {
		t.Fatal("plain key unexpectedly encrypted")
	}
}

func TestCreatePrivateKeyErrors(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	cases := []struct {
		name string
		args *createPrivateKeyArgs
		want string
	}{
		{"no target", &createPrivateKeyArgs{}, "Either path or text must be specified."},
		{"both targets", &createPrivateKeyArgs{Path: ps("/pki/k"), Text: true},
			"Either path or text must be specified, not both."},
		{"small bits", &createPrivateKeyArgs{Text: true, Bits: pi(256)}, "bits must be at least 512"},
		{"bad cipher", &createPrivateKeyArgs{
			Text: true, Bits: pi(1024), Passphrase: ps("x"), Cipher: ps("rot13"),
		}, "unsupported cipher"},
	}
	for _, tc := range cases {
		_, err := callX509(t, rt, "x509.create_private_key", tc.args)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s error = %v, want %q", tc.name, err, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// get_signing_policy

func TestGetSigningPolicy(t *testing.T) {
	caKey, _ := rsaKeyPEM(t, 2048)
	rt, _ := x509RT(t, nil, map[string]any{
		"x509_signing_policies": map[string]any{
			"www": map[string]any{
				"minions":             "www*",
				"signing_private_key": caKey,
				"signing_cert":        fixtureCert,
				"C":                   "US",
				"basicConstraints":    "critical CA:false",
				"days_valid":          90,
			},
		},
	})
	res, err := callX509(t, rt, "x509.get_signing_policy", &getSigningPolicyArgs{
		SigningPolicyName: "www",
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := res.(map[string]any)
	if _, has := policy["signing_private_key"]; has {
		t.Fatal("signing_private_key must be stripped")
	}
	if policy["signing_cert"] != fixtureCert {
		t.Fatalf("signing_cert = %#v", policy["signing_cert"])
	}
	if policy["days_valid"] != 90 {
		t.Fatalf("days_valid = %v", policy["days_valid"])
	}

	missing, err := callX509(t, rt, "x509.get_signing_policy", &getSigningPolicyArgs{
		SigningPolicyName: "nope",
	})
	if err != nil {
		t.Fatal(err)
	}
	if missing != "Signing policy nope does not exist." {
		t.Fatalf("missing reply = %v", missing)
	}
}

func TestGetSigningPolicyListForm(t *testing.T) {
	rt, _ := x509RT(t, nil, map[string]any{
		"x509_signing_policies": map[string]any{
			"ca": []any{
				map[string]any{"minions": "ca*"},
				map[string]any{"signing_cert": fixtureCert},
				map[string]any{"days_valid": 30},
			},
		},
	})
	res, err := callX509(t, rt, "x509.get_signing_policy", &getSigningPolicyArgs{
		SigningPolicyName: "ca",
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := res.(map[string]any)
	if policy["minions"] != "ca*" || policy["days_valid"] != 30 ||
		policy["signing_cert"] != fixtureCert {
		t.Fatalf("list merge = %#v", policy)
	}
}

func TestGetSigningPolicyAbsentConfig(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	res, err := callX509(t, rt, "x509.get_signing_policy", &getSigningPolicyArgs{
		SigningPolicyName: "www",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res != "Signing policy www does not exist." {
		t.Fatalf("no-config reply = %v", res)
	}
}

// ---------------------------------------------------------------------------
// create_certificate

func TestCreateCertificateSelfSignedCA(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	keyPEM, key := rsaKeyPEM(t, 2048)
	caPEM := createCA(t, rt, keyPEM)
	cert := parseCertPEM(t, caPEM)

	props, err := callX509(t, rt, "x509.read_certificate", &readCertificateArgs{Certificate: caPEM})
	if err != nil {
		t.Fatal(err)
	}
	details := props.(map[string]any)
	subject := details["Subject"].(map[string]string)
	for k, v := range map[string]string{
		"CN": "Redacted Root CA", "O": "Redacted", "C": "BE",
		"ST": "Antwerp", "L": "Local Town", "emailAddress": "certadm@example.org",
	} {
		if subject[k] != v {
			t.Fatalf("subject[%s] = %q, want %q", k, subject[k], v)
		}
	}
	if details["Version"] != 3 {
		t.Fatalf("version = %v", details["Version"])
	}
	// days_valid=3650 lands within the same day window.
	notAfter, _ := time.Parse(dateTimeLayout, details["Not After"].(string))
	years := notAfter.Sub(cert.NotBefore).Hours() / 24 / 365
	if years < 9.9 || years > 10.1 {
		t.Fatalf("validity = %.1f years", years)
	}
	// Serial is a random pretty-hex value.
	serial := details["Serial Number"].(string)
	if !strings.Contains(serial, ":") || len(serial) < 20 {
		t.Fatalf("serial = %q", serial)
	}
	exts := details["X509v3 Extensions"].(map[string]string)
	if exts["basicConstraints"] != "critical CA:TRUE" {
		t.Fatalf("basicConstraints = %q", exts["basicConstraints"])
	}
	if exts["keyUsage"] != "critical Certificate Sign, CRL Sign" {
		t.Fatalf("keyUsage = %q", exts["keyUsage"])
	}
	// SKI "hash" is the pretty-hex SHA-1 of the RSA modulus.
	sum := sha1.Sum(key.N.Bytes())
	wantSKI := prettyHex(sum[:])
	if exts["subjectKeyIdentifier"] != wantSKI {
		t.Fatalf("SKI = %q, want %q", exts["subjectKeyIdentifier"], wantSKI)
	}
	// Self-signed AKI keyid equals the same hash.
	if !strings.HasPrefix(exts["authorityKeyIdentifier"], "keyid:"+wantSKI) {
		t.Fatalf("AKI = %q, want keyid:%s", exts["authorityKeyIdentifier"], wantSKI)
	}
	// Issuer equals subject on the self-signed certificate.
	issuer := details["Issuer"].(map[string]string)
	if issuer["CN"] != "Redacted Root CA" {
		t.Fatalf("issuer = %#v", issuer)
	}
}

func TestCreateCertificateCASignedLeafLifecycle(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	caKeyPEM, _ := rsaKeyPEM(t, 2048)
	caCertPEM := createCA(t, rt, caKeyPEM)

	leafKeyPEM, _ := rsaKeyPEM(t, 2048)
	// CSR carries subject and a subjectAltName; authorityKeyIdentifier
	// is skipped in the CSR flow.
	csrRes, err := callX509(t, rt, "x509.create_csr", &createCsrArgs{
		Text:                   true,
		PrivateKey:             ps(leafKeyPEM),
		CN:                     ps("www.example.org"),
		O:                      ps("Redacted"),
		SubjectAltName:         ps("DNS:www.example.org, IP Address:10.0.0.1"),
		AuthorityKeyIdentifier: ps("keyid,issuer:always"),
	})
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := csrRes.(string)
	if !strings.Contains(csrPEM, "BEGIN CERTIFICATE REQUEST") {
		t.Fatalf("csr = %.40s", csrPEM)
	}

	leafRes, err := callX509(t, rt, "x509.create_certificate", &createCertificateArgs{
		Text:                   true,
		SigningPrivateKey:      ps(caKeyPEM),
		SigningCert:            ps(caCertPEM),
		CSR:                    ps(csrPEM),
		BasicConstraints:       ps("critical CA:false"),
		KeyUsage:               ps("critical keyEncipherment"),
		SubjectKeyIdentifier:   ps("hash"),
		AuthorityKeyIdentifier: ps("keyid,issuer:always"),
	})
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := leafRes.(string)
	leaf := parseCertPEM(t, leafPEM)

	props, _ := callX509(t, rt, "x509.read_certificate", &readCertificateArgs{Certificate: leafPEM})
	details := props.(map[string]any)
	subject := details["Subject"].(map[string]string)
	if subject["CN"] != "www.example.org" || subject["O"] != "Redacted" {
		t.Fatalf("leaf subject = %#v", subject)
	}
	issuer := details["Issuer"].(map[string]string)
	if issuer["CN"] != "Redacted Root CA" {
		t.Fatalf("leaf issuer = %#v", issuer)
	}
	exts := details["X509v3 Extensions"].(map[string]string)
	if exts["subjectAltName"] != "DNS:www.example.org, IP Address:10.0.0.1" {
		t.Fatalf("SAN = %q (IP Address quirk must round-trip)", exts["subjectAltName"])
	}
	if exts["basicConstraints"] != "critical CA:FALSE" {
		t.Fatalf("leaf basicConstraints = %q", exts["basicConstraints"])
	}
	caCert := parseCertPEM(t, caCertPEM)
	if !strings.HasPrefix(exts["authorityKeyIdentifier"], "keyid:"+prettyHex(caCert.SubjectKeyId)) {
		t.Fatalf("leaf AKI = %q", exts["authorityKeyIdentifier"])
	}
	if leaf.CheckSignatureFrom(caCert) != nil {
		t.Fatal("leaf not signed by the CA")
	}

	// verify_signature against the CA and against a stranger.
	ok, err := callX509(t, rt, "x509.verify_signature", &verifySignatureArgs{
		Certificate: leafPEM, SigningPubKey: ps(caCertPEM),
	})
	if err != nil || !ok.(bool) {
		t.Fatalf("verify_signature(ca) = %v %v", ok, err)
	}
	otherKeyPEM, _ := rsaKeyPEM(t, 2048)
	otherCA := createCA(t, rt, otherKeyPEM)
	ok, err = callX509(t, rt, "x509.verify_signature", &verifySignatureArgs{
		Certificate: leafPEM, SigningPubKey: ps(otherCA),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok.(bool) {
		t.Fatal("verify_signature must be false for a foreign signer")
	}
}

func TestCreateCertificateValidityAndSerial(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	keyPEM, _ := rsaKeyPEM(t, 2048)
	notBefore := "2030-01-02 03:04:05"
	notAfter := "2030-01-07 03:04:05"
	res, err := callX509(t, rt, "x509.create_certificate", &createCertificateArgs{
		Text:              true,
		SigningPrivateKey: ps(keyPEM),
		CN:                ps("dated"),
		NotBefore:         ps(notBefore),
		NotAfter:          ps(notAfter),
		SerialNumberHex:   ps("DE:CA:FB:AD:00:00:00:00"),
	})
	if err != nil {
		t.Fatal(err)
	}
	props, _ := callX509(t, rt, "x509.read_certificate", &readCertificateArgs{Certificate: res.(string)})
	details := props.(map[string]any)
	if details["Not Before"] != notBefore || details["Not After"] != notAfter {
		t.Fatalf("validity = %v..%v", details["Not Before"], details["Not After"])
	}
	if details["Serial Number"] != "DE:CA:FB:AD:00:00:00:00" {
		t.Fatalf("serial = %v", details["Serial Number"])
	}

	// Explicit not_before with the dynamic not_after stays anchored at
	// now + days_valid (the v1 quirk).
	res, err = callX509(t, rt, "x509.create_certificate", &createCertificateArgs{
		Text: true, SigningPrivateKey: ps(keyPEM), CN: ps("quirk"),
		NotBefore: ps(notBefore), DaysValid: pi(5),
	})
	if err != nil {
		t.Fatal(err)
	}
	props, _ = callX509(t, rt, "x509.read_certificate", &readCertificateArgs{Certificate: res.(string)})
	details = props.(map[string]any)
	after, _ := time.Parse(dateTimeLayout, details["Not After"].(string))
	if d := time.Until(after); d < 4*24*time.Hour || d > 6*24*time.Hour {
		t.Fatalf("quirk not_after = %v (%v away)", details["Not After"], d)
	}

	// Expired certificates surface through x509.expired.
	res, err = callX509(t, rt, "x509.create_certificate", &createCertificateArgs{
		Text: true, SigningPrivateKey: ps(keyPEM), CN: ps("old"),
		NotAfter: ps("2001-01-01 00:00:00"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if werr := rt.FS.MkdirAll("/pki", 0o755); werr != nil {
		t.Fatal(werr)
	}
	if werr := rt.FS.WriteFile("/pki/old.crt", []byte(res.(string)), 0o644); werr != nil {
		t.Fatal(werr)
	}
	exp, err := callX509(t, rt, "x509.expired", &expiredArgs{Certificate: "/pki/old.crt"})
	if err != nil {
		t.Fatal(err)
	}
	if !exp.(map[string]any)["expired"].(bool) {
		t.Fatal("expired() must be true for a past not_after")
	}
}

func TestCreateCertificateDateFormatErrors(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	keyPEM, _ := rsaKeyPEM(t, 2048)
	bad := "this is an intentionally wrong format"
	_, err := callX509(t, rt, "x509.create_certificate", &createCertificateArgs{
		Text: true, SigningPrivateKey: ps(keyPEM), NotBefore: ps(bad),
	})
	want := "not_before: this is an intentionally wrong format is not in required format %Y-%m-%d %H:%M:%S"
	if err == nil || err.Error() != want {
		t.Fatalf("not_before error = %v, want %q", err, want)
	}
	_, err = callX509(t, rt, "x509.create_certificate", &createCertificateArgs{
		Text: true, SigningPrivateKey: ps(keyPEM), NotAfter: ps(bad),
	})
	want = "not_after: this is an intentionally wrong format is not in required format %Y-%m-%d %H:%M:%S"
	if err == nil || err.Error() != want {
		t.Fatalf("not_after error = %v, want %q", err, want)
	}
}

func TestCreateCertificateTargetErrors(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	keyPEM, _ := rsaKeyPEM(t, 2048)
	if _, err := callX509(t, rt, "x509.create_certificate", &createCertificateArgs{}); err == nil ||
		err.Error() != "Either path or text must be specified." {
		t.Fatalf("no-target error = %v", err)
	}
	if _, err := callX509(t, rt, "x509.create_certificate", &createCertificateArgs{
		Path: ps("/pki/c.crt"), Text: true, SigningPrivateKey: ps(keyPEM),
	}); err == nil || err.Error() != "Either path or text must be specified, not both." {
		t.Fatalf("both-target error = %v", err)
	}
}

func TestCreateCertificateCAServerExclusion(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	_, err := callX509(t, rt, "x509.create_certificate", &createCertificateArgs{
		Text: true, CAServer: ps("ca-master"),
	})
	want := "signing_policy must be specifiedif requesting remote certificate from ca_server ca-master."
	if err == nil || err.Error() != want {
		t.Fatalf("ca_server without policy = %v, want %q", err, want)
	}
	_, err = callX509(t, rt, "x509.create_certificate", &createCertificateArgs{
		Text: true, CAServer: ps("ca-master"), SigningPolicy: ps("www"),
	})
	if err == nil || !strings.Contains(err.Error(), "master-surface") {
		t.Fatalf("ca_server exclusion = %v", err)
	}
	if _, ok := err.(*runtime.UnsupportedError); !ok {
		t.Fatalf("exclusion error type = %T", err)
	}
}

func TestCreateCertificateSigningPolicyMerge(t *testing.T) {
	keyPEM, _ := rsaKeyPEM(t, 2048)
	rt, _ := x509RT(t, nil, map[string]any{
		"x509_signing_policies": map[string]any{
			"www": []any{
				map[string]any{"signing_cert": fixtureCert},
				map[string]any{"C": "US", "ST": "Utah", "L": "Salt Lake City"},
				map[string]any{"basicConstraints": "critical CA:false"},
				map[string]any{"keyUsage": "critical cRLSign, keyCertSign"},
				map[string]any{"subjectKeyIdentifier": "hash"},
				map[string]any{"authorityKeyIdentifier": "keyid,issuer:always"},
				map[string]any{"days_valid": 90},
			},
		},
	})
	// CN from kwargs; every other property rides the policy (the
	// fixture certificate's key does not match keyPEM, so this also
	// exercises the mismatch error path with redaction).
	_, err := callX509(t, rt, "x509.create_certificate", &createCertificateArgs{
		Text: true, SigningPolicy: ps("www"), SigningPrivateKey: ps(keyPEM),
		CN: ps("policy-cert"),
	})
	if err == nil || !strings.Contains(err.Error(), "does no match signing_cert:") {
		t.Fatalf("mismatch error = %v", err)
	}
	if strings.Contains(err.Error(), "-----BEGIN") {
		t.Fatalf("mismatch error leaks PEM material: %v", err)
	}
}

func TestCreateCertificatePolicyHappyPathAndCopypath(t *testing.T) {
	keyPEM, _ := rsaKeyPEM(t, 2048)
	rt, _ := x509RT(t, nil, map[string]any{
		"x509_signing_policies": map[string]any{
			"www": map[string]any{
				"signing_private_key": keyPEM, // policy is self-signed
				"C":                   "US",
				"days_valid":          90,
			},
		},
	})
	if err := rt.FS.MkdirAll("/etc/pki/issued_certs", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.MkdirAll("/pki", 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := callX509(t, rt, "x509.create_certificate", &createCertificateArgs{
		Path:            ps("/pki/policy.crt"),
		SigningPolicy:   ps("www"),
		CN:              ps("policy-cert"),
		Copypath:        ps("/etc/pki/issued_certs"),
		PrependCN:       pb(true),
		SerialNumberHex: ps("00:0A:0B"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res != "PEM written to /pki/policy.crt" {
		t.Fatalf("reply = %v", res)
	}
	entries, rerr := rt.FS.ReadDir("/etc/pki/issued_certs")
	if rerr != nil || len(entries) != 1 {
		t.Fatalf("copypath entries = %v %v", entries, rerr)
	}
	want := "policy-cert-00:0A:0B.crt"
	if entries[0].Name() != want {
		t.Fatalf("copypath name = %q, want %q", entries[0].Name(), want)
	}
	props, _ := callX509(t, rt, "x509.read_certificate", &readCertificateArgs{Certificate: "/pki/policy.crt"})
	details := props.(map[string]any)
	if details["Subject"].(map[string]string)["C"] != "US" {
		t.Fatalf("policy subject = %#v", details["Subject"])
	}
	after, _ := time.Parse(dateTimeLayout, details["Not After"].(string))
	if d := time.Until(after); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Fatalf("policy days_valid = %v", details["Not After"])
	}
}

func TestCreateCertificatePublicKeyInputs(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	caKeyPEM, _ := rsaKeyPEM(t, 2048)
	caCertPEM := createCA(t, rt, caKeyPEM)

	leafKeyPEM, leafKey := rsaKeyPEM(t, 2048)
	// public_key may be a private key (only its public half is used).
	res, err := callX509(t, rt, "x509.create_certificate", &createCertificateArgs{
		Text: true, SigningPrivateKey: ps(caKeyPEM), SigningCert: ps(caCertPEM),
		PublicKey: ps(leafKeyPEM), CN: ps("pub-from-priv"),
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseCertPEM(t, res.(string))
	if leaf.PublicKey.(*rsa.PublicKey).N.Cmp(leafKey.N) != 0 {
		t.Fatal("public_key=private_key did not derive the public half")
	}
}

// ---------------------------------------------------------------------------
// create_csr

func TestCreateCsrSubjectAndExtensions(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	keyPEM, _ := rsaKeyPEM(t, 2048)
	res, err := callX509(t, rt, "x509.create_csr", &createCsrArgs{
		Text:                 true,
		PrivateKey:           ps(keyPEM),
		CN:                   ps("www.example.org"),
		C:                    ps("BE"),
		O:                    ps("Redacted"),
		KeyUsage:             ps("critical keyEncipherment"),
		SubjectAltName:       ps("DNS:www.example.org, IP Address:10.0.0.1"),
		SubjectKeyIdentifier: ps("hash"),
		NsComment:            ps("hello world"),
		NsCertType:           ps("client, server"),
	})
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := res.(string)
	if !strings.Contains(csrPEM, "BEGIN CERTIFICATE REQUEST") {
		t.Fatalf("csr = %.40s", csrPEM)
	}

	props, err := callX509(t, rt, "x509.read_csr", &readCsrArgs{Csr: csrPEM})
	if err != nil {
		t.Fatal(err)
	}
	details := props.(map[string]any)
	subject := details["Subject"].(map[string]string)
	if subject["CN"] != "www.example.org" || subject["C"] != "BE" || subject["O"] != "Redacted" {
		t.Fatalf("csr subject = %#v", subject)
	}
	exts := details["X509v3 Extensions"].(map[string]string)
	if exts["keyUsage"] != "critical Key Encipherment" {
		t.Fatalf("csr keyUsage = %q", exts["keyUsage"])
	}
	if exts["subjectAltName"] != "DNS:www.example.org, IP Address:10.0.0.1" {
		t.Fatalf("csr SAN = %q", exts["subjectAltName"])
	}
	if _, has := exts["authorityKeyIdentifier"]; has {
		t.Fatal("authorityKeyIdentifier must be skipped in CSRs")
	}

	block, _ := pem.Decode([]byte(csrPEM))
	req, perr := x509.ParseCertificateRequest(block.Bytes)
	if perr != nil {
		t.Fatal(perr)
	}
	if req.CheckSignature() != nil {
		t.Fatal("csr signature invalid")
	}
}

func TestCreateCsrKeyFallbacksAndErrors(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	keyPEM, _ := rsaKeyPEM(t, 2048)
	// public_key without private_key: v1 falls back to it with a
	// warning.
	res, err := callX509(t, rt, "x509.create_csr", &createCsrArgs{
		Text: true, PublicKey: ps(keyPEM), CN: ps("fallback"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.(string), "BEGIN CERTIFICATE REQUEST") {
		t.Fatalf("fallback csr = %.40s", res.(string))
	}

	if _, err = callX509(t, rt, "x509.create_csr", &createCsrArgs{Text: true}); err == nil ||
		err.Error() != "private_key is required" {
		t.Fatalf("no-key error = %v", err)
	}
	if _, err = callX509(t, rt, "x509.create_csr", &createCsrArgs{}); err == nil ||
		err.Error() != "Either path or text must be specified." {
		t.Fatalf("no-target error = %v", err)
	}

	if werr := rt.FS.MkdirAll("/pki", 0o755); werr != nil {
		t.Fatal(werr)
	}
	reply, err := callX509(t, rt, "x509.create_csr", &createCsrArgs{
		Path: ps("/pki/req.csr"), PrivateKey: ps(keyPEM), CN: ps("written"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if reply != "PEM written to /pki/req.csr" {
		t.Fatalf("reply = %v", reply)
	}
}

func TestCreateCsrPassphraseRoundtrip(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	encRes, err := callX509(t, rt, "x509.create_private_key", &createPrivateKeyArgs{
		Text: true, Bits: pi(1024), Passphrase: ps("csr-secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	encKey := encRes.(string)
	res, err := callX509(t, rt, "x509.create_csr", &createCsrArgs{
		Text: true, PrivateKey: ps(encKey),
		PrivateKeyPassphrase: ps("csr-secret"), PublicKeyPassphrase: ps("csr-secret"),
		CN: ps("locked"),
	})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(res.(string)))
	if _, perr := x509.ParseCertificateRequest(block.Bytes); perr != nil {
		t.Fatal(perr)
	}
}

// ---------------------------------------------------------------------------
// create_crl

func TestCreateCrlLifecycle(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	caKeyPEM, _ := rsaKeyPEM(t, 2048)
	caCertPEM := createCA(t, rt, caKeyPEM)
	if err := rt.FS.MkdirAll("/pki", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/pki/ca.key", []byte(caKeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/pki/ca.crt", []byte(caCertPEM), 0o644); err != nil {
		t.Fatal(err)
	}

	// Issue a leaf to revoke.
	leafKeyPEM, _ := rsaKeyPEM(t, 2048)
	leafRes, err := callX509(t, rt, "x509.create_certificate", &createCertificateArgs{
		Text: true, SigningPrivateKey: ps(caKeyPEM), SigningCert: ps(caCertPEM),
		PublicKey: ps(leafKeyPEM), CN: ps("revokeme"),
		SerialNumberHex: ps("AA:BB:CC"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/pki/leaf.crt", []byte(leafRes.(string)), 0o644); err != nil {
		t.Fatal(err)
	}

	past := time.Now().UTC().Add(-24 * time.Hour).Format(dateTimeLayout)
	res, err := callX509(t, rt, "x509.create_crl", &createCrlArgs{
		Text:              true,
		SigningPrivateKey: ps("/pki/ca.key"),
		SigningCert:       ps("/pki/ca.crt"),
		DaysValid:         pi(100),
		Digest:            ps("sha512"),
		Revoked: []map[string]any{
			{"certificate": "/pki/leaf.crt", "revocation_date": "2015-03-01 00:00:00"},
			{"serial_number": "12:34", "revocation_date": past, "reason": "keyCompromise"},
			{"serial_number": "9988", "not_after": "2001-01-01 00:00:00"}, // expired: filtered
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	crlPEM := res.(string)
	if !strings.Contains(crlPEM, "BEGIN X509 CRL") {
		t.Fatalf("crl = %.40s", crlPEM)
	}
	block, _ := pem.Decode([]byte(crlPEM))
	list, perr := x509.ParseRevocationList(block.Bytes)
	if perr != nil {
		t.Fatal(perr)
	}
	if len(list.RevokedCertificates) != 2 {
		t.Fatalf("revoked entries = %d, want 2 (expired filtered)", len(list.RevokedCertificates))
	}
	found := map[string]bool{}
	for _, entry := range list.RevokedCertificates {
		found[entry.SerialNumber.Text(16)] = true
	}
	if !found["aabbcc"] || !found["1234"] {
		t.Fatalf("revoked serials = %v", found)
	}
	if d := time.Until(list.NextUpdate); d < 99*24*time.Hour || d > 101*24*time.Hour {
		t.Fatalf("nextUpdate = %v", list.NextUpdate)
	}

	// verify_crl true/false pair.
	ok, err := callX509(t, rt, "x509.verify_crl", &verifyCrlArgs{Crl: crlPEM, Cert: "/pki/ca.crt"})
	if err != nil || !ok.(bool) {
		t.Fatalf("verify_crl = %v %v", ok, err)
	}
	otherKey, _ := rsaKeyPEM(t, 2048)
	otherCA := createCA(t, rt, otherKey)
	ok, err = callX509(t, rt, "x509.verify_crl", &verifyCrlArgs{Crl: crlPEM, Cert: otherCA})
	if err != nil {
		t.Fatal(err)
	}
	if ok.(bool) {
		t.Fatal("verify_crl must be false for a foreign CA")
	}

	// include_expired keeps the expired entry.
	res, err = callX509(t, rt, "x509.create_crl", &createCrlArgs{
		Text: true, SigningPrivateKey: ps(caKeyPEM), SigningCert: ps(caCertPEM),
		IncludeExpired: pb(true),
		Revoked:        []map[string]any{{"serial_number": "9988", "not_after": "2001-01-01 00:00:00"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode([]byte(res.(string)))
	list, _ = x509.ParseRevocationList(block.Bytes)
	if len(list.RevokedCertificates) != 1 {
		t.Fatalf("include_expired entries = %d", len(list.RevokedCertificates))
	}

	// path mode writes through write_pem.
	reply, err := callX509(t, rt, "x509.create_crl", &createCrlArgs{
		Path: ps("/pki/ca.crl"), SigningPrivateKey: ps(caKeyPEM), SigningCert: ps(caCertPEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	if reply != "PEM written to /pki/ca.crl" {
		t.Fatalf("reply = %v", reply)
	}
	data, _ := rt.FS.ReadFile("/pki/ca.crl")
	if !strings.Contains(string(data), "BEGIN X509 CRL") {
		t.Fatalf("file = %.40s", data)
	}
}

func TestCreateCrlErrors(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	if _, err := callX509(t, rt, "x509.create_crl", &createCrlArgs{}); err == nil ||
		err.Error() != "Either path or text must be specified." {
		t.Fatalf("no-target error = %v", err)
	}
	caKeyPEM, _ := rsaKeyPEM(t, 2048)
	rt2, _ := x509RT(t, nil, nil)
	caCertPEM := createCA(t, rt2, caKeyPEM)
	_, err := callX509(t, rt, "x509.create_crl", &createCrlArgs{
		Text: true, SigningPrivateKey: ps(caKeyPEM), SigningCert: ps(caCertPEM),
		Revoked: []map[string]any{{"serial_number": "xyz"}},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid serial_number") {
		t.Fatalf("bad serial error = %v", err)
	}
	_, err = callX509(t, rt, "x509.create_crl", &createCrlArgs{
		Text: true, SigningPrivateKey: ps(caKeyPEM), SigningCert: ps(caCertPEM),
		Revoked: []map[string]any{{"serial_number": "11", "reason": "bogusReason"}},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid reason") {
		t.Fatalf("bad reason error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// verify_signature

func TestVerifySignatureInputs(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	caKeyPEM, _ := rsaKeyPEM(t, 2048)
	caCertPEM := createCA(t, rt, caKeyPEM)
	leafKeyPEM, _ := rsaKeyPEM(t, 2048)
	leafRes, err := callX509(t, rt, "x509.create_certificate", &createCertificateArgs{
		Text: true, SigningPrivateKey: ps(caKeyPEM), SigningCert: ps(caCertPEM),
		PublicKey: ps(leafKeyPEM), CN: ps("verified"),
	})
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := leafRes.(string)

	// signing_pub_key accepts a certificate...
	ok, err := callX509(t, rt, "x509.verify_signature", &verifySignatureArgs{
		Certificate: leafPEM, SigningPubKey: ps(caCertPEM)})
	if err != nil || !ok.(bool) {
		t.Fatalf("cert input = %v %v", ok, err)
	}
	// ...a public key...
	pubRes, _ := callX509(t, rt, "x509.get_public_key", &getPublicKeyArgs{Key: caCertPEM})
	ok, _ = callX509(t, rt, "x509.verify_signature", &verifySignatureArgs{
		Certificate: leafPEM, SigningPubKey: ps(pubRes.(string))})
	if !ok.(bool) {
		t.Fatal("public key input failed")
	}
	// ...and a private key.
	ok, _ = callX509(t, rt, "x509.verify_signature", &verifySignatureArgs{
		Certificate: leafPEM, SigningPubKey: ps(caKeyPEM)})
	if !ok.(bool) {
		t.Fatal("private key input failed")
	}

	// Omitted signing key self-checks with the certificate's OWN
	// public key (M2Crypto X509.verify with pkey=None): False for a
	// CA-signed leaf whose signature came from another key.
	ok, _ = callX509(t, rt, "x509.verify_signature", &verifySignatureArgs{Certificate: leafPEM})
	if ok.(bool) {
		t.Fatal("leaf self-check must be false (own key is not the signer)")
	}
	// Self-signed CA self-check.
	ok, _ = callX509(t, rt, "x509.verify_signature", &verifySignatureArgs{Certificate: caCertPEM})
	if !ok.(bool) {
		t.Fatal("CA self-check failed")
	}
}

func TestVerifyCrlBadInputs(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	caKeyPEM, _ := rsaKeyPEM(t, 2048)
	caCertPEM := createCA(t, rt, caKeyPEM)
	// Structurally valid PEM, unloadable DER: False (the CLI fallback
	// also failed to print "verify OK").
	garbage := "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n"
	ok, err := callX509(t, rt, "x509.verify_crl", &verifyCrlArgs{Crl: garbage, Cert: caCertPEM})
	if err != nil || ok.(bool) {
		t.Fatalf("garbage DER = %v %v", ok, err)
	}
	// A broken PEM entry raises through get_pem_entry.
	_, err = callX509(t, rt, "x509.verify_crl", &verifyCrlArgs{Crl: "not a pem", Cert: caCertPEM})
	if err == nil || !strings.Contains(err.Error(), "PEM does not contain a single entry of type X509 CRL") {
		t.Fatalf("garbage PEM error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// registry, CLI and isolation

func TestWriteSideRegistryCallPaths(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	res, err := rt.Exec.Call(context.Background(), rt, "x509.create_private_key",
		&createPrivateKeyArgs{Text: true, Bits: pi(1024)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.(string), "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("registry create_private_key = %.30s", res.(string))
	}
	_, err = rt.Exec.Call(context.Background(), rt, "x509.create_certificate",
		&createCertificateArgs{})
	if err == nil || err.Error() != "Either path or text must be specified." {
		t.Fatalf("registry create_certificate error = %v", err)
	}
}

func TestWriteSideCLISurface(t *testing.T) {
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
	}
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.MkdirAll("/pki", 0o755); err != nil {
		t.Fatal(err)
	}
	// One shared runtime instance keeps the CLI-written files visible
	// across commands.
	app := cli.NewApp("test", func() (*runtime.Runtime, error) { return rt, nil })

	if code := app.Run([]string{"exec", "x509.create_private_key", "--text", "-o", "json"}); code != 0 {
		t.Fatalf("create_private_key exit = %d", code)
	}
	if code := app.Run([]string{"exec", "x509.write_pem", "--text", fixtureCert,
		"--path", "/pki/cli.crt", "--pem_type", "CERTIFICATE"}); code != 0 {
		t.Fatalf("write_pem exit = %d", code)
	}
	data, err := rt.FS.ReadFile("/pki/cli.crt")
	if err != nil || string(data) != fixtureCert {
		t.Fatalf("cli write_pem file = %v %v", err, data)
	}
	if code := app.Run([]string{"exec", "x509.verify_signature", "--certificate", "/pki/cli.crt"}); code != 0 {
		t.Fatalf("verify_signature exit = %d", code)
	}
	if code := app.Run([]string{"exec", "x509.write_pem"}); code != 2 {
		t.Fatalf("missing required exit = %d, want 2", code)
	}
}

func TestWriteSideNoRunnerSpawns(t *testing.T) {
	rt, runner := x509RT(t, nil, nil)
	keyPEM, _ := rsaKeyPEM(t, 2048)
	if err := rt.FS.MkdirAll("/pki", 0o755); err != nil {
		t.Fatal(err)
	}
	caCertPEM := createCA(t, rt, keyPEM)
	calls := []struct {
		name string
		args any
	}{
		{"x509.write_pem", &writePemArgs{Text: caCertPEM, Path: "/pki/w.crt", PemType: ps("CERTIFICATE")}},
		{"x509.create_private_key", &createPrivateKeyArgs{Text: true, Bits: pi(1024)}},
		{"x509.get_signing_policy", &getSigningPolicyArgs{SigningPolicyName: "www"}},
		{"x509.verify_signature", &verifySignatureArgs{Certificate: caCertPEM}},
		{"x509.verify_crl", &verifyCrlArgs{Crl: "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n", Cert: caCertPEM}},
	}
	for _, call := range calls {
		if _, err := callX509(t, rt, call.name, call.args); err != nil {
			t.Fatalf("%s: %v", call.name, err)
		}
	}
	if runner.calls != 0 {
		t.Fatalf("runner invoked %d times; the write surface must not spawn processes", runner.calls)
	}
}

// pb boxes a bool for optional argument structs.
func pb(b bool) *bool { return &b }
