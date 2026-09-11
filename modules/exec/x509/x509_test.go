package x509

// R5.2a tests for the x509 read-only subset, mapped onto the source
// contracts of saltstack/salt/modules/x509.py @ pinned revision and the
// behaviors pinned by tests/unit/modules/test_x509.py. The upstream
// fixture certificate ("Super Widgets") pins independently computed
// goldens (fingerprints, serial, subject hash, validity); key material
// for the remaining cases is generated inside the tests with
// crypto/x509 — no external CA, no openssl binary.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/cli"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// fixtureCert is the pinned Salt unit-test certificate (subject
// C=US/ST=Arizona/L=Scottsdale/O=Super Widgits, RSA 1024, self-signed,
// valid 2021-03-23..2022-03-23, extensions SKI/AKI keyid + critical
// basicConstraints CA:TRUE).
const fixtureCert = `-----BEGIN CERTIFICATE-----
MIICdDCCAd2gAwIBAgIUH6g+PC0bGKSY4LMq7PISP09M5B4wDQYJKoZIhvcNAQEL
BQAwTDELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0FyaXpvbmExEzARBgNVBAcMClNj
b3R0c2RhbGUxFjAUBgNVBAoMDVN1cGVyIFdpZGdpdHMwHhcNMjEwMzIzMDExNDE2
WhcNMjIwMzIzMDExNDE2WjBMMQswCQYDVQQGEwJVUzEQMA4GA1UECAwHQXJpem9u
YTETMBEGA1UEBwwKU2NvdHRzZGFsZTEWMBQGA1UECgwNU3VwZXIgV2lkZ2l0czCB
nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAvtFFZP47UkzyAmVWtBnVHuXwe7iK
yu19c3qx59KPVAMHkMKgCew4S2KBMDHySBVnspiEz1peP1ywozcP1tIeWHG6aY/7
j2ewzl5bJ4HZPDBnEOYzGsC/NM8YY3qFlrteda/awvwoF99MkpVlrcLBMJzjt/c8
HjuBb0zTlnm4r7ECAwEAAaNTMFEwHQYDVR0OBBYEFJwdb0PKsvu3dU0j3kx3uP4B
NGpfMB8GA1UdIwQYMBaAFJwdb0PKsvu3dU0j3kx3uP4BNGpfMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADgYEAZblVv70rSk6+7ti3mYxVo48VLf3hG5R/
rMd434WYTeDOWlvl5GSklrBc4ToBW5GsJe/+JaFbUFo9YB+a0K0xjyNZ5CWWiaxg
3lwqTx6vwK1ucS18B+nt2qqyq9hL0UvpSB7gH4KeCwCMDIfRMsrPi32jg1RyKftD
B+O0S5LeuJw=
-----END CERTIFICATE-----
`

// fixtureGoldens were computed independently of this package (digests
// over the DER at the pinned revision's fixture).
const (
	fixtureSerial    = "1F:A8:3E:3C:2D:1B:18:A4:98:E0:B3:2A:EC:F2:12:3F:4F:4C:E4:1E"
	fixtureSHA1      = "A3:AD:4F:55:24:C1:77:6C:D8:EE:28:07:71:AF:2F:D2:9B:B0:DE:40"
	fixtureSHA256    = "C8:A7:D5:B1:59:36:2D:15:C3:AD:0E:19:A1:CB:D3:D8:65:2D:B8:C8:63:92:42:48:4B:BC:C6:53:19:F1:92:F9"
	fixtureMD5       = "1A:0D:B6:C2:5E:FD:B8:DE:B2:D2:E5:54:02:03:99:FA"
	fixtureNameHash  = "E1:8E:17:B2"
	fixtureNotBefore = "2021-03-23 01:14:16"
	fixtureNotAfter  = "2022-03-23 01:14:16"
)

// ---------------------------------------------------------------------------
// harness

type recordingRunner struct{ calls int }

func (r *recordingRunner) Run(_ context.Context, _ process.Command) process.CommandResult {
	r.calls++
	return process.CommandResult{ExitCode: -1}
}

type cfgStub struct{ values map[string]any }

func (cfgStub) Name() string { return "config.option" }
func (cfgStub) Args() any    { return struct{}{} }
func (s cfgStub) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	key := ""
	if m, ok := args.(map[string]any); ok {
		if k, ok2 := m["key"].(string); ok2 {
			key = k
		}
	}
	if v, ok := s.values[key]; ok {
		return v, nil
	}
	return nil, nil
}

func x509RT(t *testing.T, files map[string]string, cfg map[string]any) (*runtime.Runtime, *recordingRunner) {
	t.Helper()
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		if err := reg.Register(cfgStub{values: cfg}); err != nil {
			t.Fatal(err)
		}
	}
	rt := &runtime.Runtime{
		Exec:   reg,
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Runner: &recordingRunner{},
	}
	for path, content := range files {
		dir := filepath.Dir(path)
		if werr := rt.FS.MkdirAll(dir, 0o755); werr != nil {
			t.Fatal(werr)
		}
		if werr := rt.FS.WriteFile(path, []byte(content), 0o644); werr != nil {
			t.Fatal(werr)
		}
	}
	return rt, rt.Runner.(*recordingRunner)
}

func callX509[T any](t *testing.T, rt *runtime.Runtime, name string, args T) (any, error) {
	t.Helper()
	fn, ok := rt.Exec.Get(name)
	if !ok {
		t.Fatalf("%s not registered", name)
	}
	return fn.Execute(context.Background(), rt, args)
}

func ps(s string) *string { return &s }
func pi(i int) *int       { return &i }

// ---------------------------------------------------------------------------
// in-test PKI material

type testCA struct {
	certPEM string
	keyPEM  string
	tmpl    *x509.Certificate
	parsed  *x509.Certificate
	key     *rsa.PrivateKey
}

func newTestCA(t *testing.T, cn string, notAfter time.Time) *testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x2A),
		Subject: pkix.Name{
			Country:      []string{"BE"},
			Province:     []string{"Antwerp"},
			Locality:     []string{"Local Town"},
			Organization: []string{"Redacted"},
			CommonName:   cn,
		},
		NotBefore:             time.Now().UTC().Add(-time.Hour).Truncate(time.Second),
		NotAfter:              notAfter.Truncate(time.Second),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, perr := x509.ParseCertificate(der)
	if perr != nil {
		t.Fatal(perr)
	}
	return &testCA{
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		keyPEM: string(pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		tmpl:   tmpl,
		parsed: parsed,
		key:    key,
	}
}

// leafPEM signs a certificate for key with ca. Extensions ride
// ExtraExtensions so criticality is fully test-controlled.
func leafPEM(t *testing.T, ca *testCA, key any, cn string, notAfter time.Time, exts []pkix.Extension, serial *big.Int) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:            []string{"BE"},
			Province:           []string{"Antwerp"},
			Locality:           []string{"Local Town"},
			Organization:       []string{"Redacted"},
			OrganizationalUnit: []string{"Unit"},
			CommonName:         cn,
		},
		NotBefore:       time.Now().UTC().Add(-time.Hour).Truncate(time.Second),
		NotAfter:        notAfter.Truncate(time.Second),
		ExtraExtensions: exts,
	}
	var pub any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	case ed25519.PrivateKey:
		pub = k.Public()
	default:
		pub = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.parsed, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func rsaKeyPEM(t *testing.T, bits int) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), key
}

func pkcs8KeyPEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func sec1ECKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func mustEC(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// v1CertPEM strips the explicit [0] version element from a generated
// leaf TBS, re-signs it, and returns a genuine v1 certificate (Go's
// builder only emits v3).
func v1CertPEM(t *testing.T, ca *testCA) string {
	t.Helper()
	v3 := leafPEM(t, ca, ca.key, "Plain V1", time.Now().UTC().Add(24*time.Hour), nil, big.NewInt(7))
	block, _ := pem.Decode([]byte(v3))
	cert, cerr := x509.ParseCertificate(block.Bytes)
	if cerr != nil {
		t.Fatal(cerr)
	}
	outer, oerr := walkTLV(cert.Raw, 0)
	if oerr != nil || outer.id != 0x30 {
		t.Fatalf("certificate walk: %v", oerr)
	}
	tbs, terr := walkTLV(outer.content, 0)
	if terr != nil || tbs.id != 0x30 {
		t.Fatalf("tbs walk: %v", terr)
	}
	var content []byte
	off, first := 0, true
	for off < len(tbs.content) {
		child, cerr2 := walkTLV(tbs.content, off)
		if cerr2 != nil {
			t.Fatal(cerr2)
		}
		off = child.next
		if first && child.id == 0xa0 {
			first = false
			continue // drop the explicit version element
		}
		first = false
		content = append(content, child.full...)
	}
	newTBS := derTestHeader(0x30, content)
	digest := sha256.Sum256(newTBS)
	sig, serr := rsa.SignPKCS1v15(rand.Reader, ca.key, crypto.SHA256, digest[:])
	if serr != nil {
		t.Fatal(serr)
	}
	sigAlg, _ := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
		Parameters: asn1.NullRawValue,
	})
	sigBits, _ := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: len(sig) * 8})
	rebuilt := derTestHeader(0x30, append(append(append([]byte{}, newTBS...), sigAlg...), sigBits...))
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rebuilt}))
}

// derTestHeader is a test-side DER header builder.
func derTestHeader(tag byte, content []byte) []byte {
	if len(content) < 0x80 {
		return append([]byte{tag, byte(len(content))}, content...)
	}
	l := len(content)
	var lenBytes []byte
	for l > 0 {
		lenBytes = append([]byte{byte(l & 0xff)}, lenBytes...)
		l >>= 8
	}
	return append(append([]byte{tag, 0x80 | byte(len(lenBytes))}, lenBytes...), content...)
}

// basicConstraintsDER renders CA:FALSE / CA:TRUE with the pathlen form.
func basicConstraintsDER(ca bool) []byte {
	if ca {
		return []byte{0x30, 0x03, 0x01, 0x01, 0xff}
	}
	return []byte{0x30, 0x00}
}

// derContent prepends a DER header (tag, constructed flag, length).
func derHeader(tag byte, content []byte) []byte {
	if len(content) < 0x80 {
		return append([]byte{tag, byte(len(content))}, content...)
	}
	l := len(content)
	var lenBytes []byte
	for l > 0 {
		lenBytes = append([]byte{byte(l & 0xff)}, lenBytes...)
		l >>= 8
	}
	return append(append([]byte{tag, 0x80 | byte(len(lenBytes))}, lenBytes...), content...)
}

// ctxName builds one GeneralName (implicit context tag, primitive).
func ctxName(tag byte, value []byte) []byte {
	return derHeader(0x80|tag, value)
}

// sanDER builds a subjectAltName extension value from GeneralNames.
func sanDER(names []byte) []byte {
	return derHeader(0x30, names)
}

// ---------------------------------------------------------------------------
// get_pem_entry

func TestGetPemEntryNormalizes(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	res, err := callX509(t, rt, "x509.get_pem_entry", &getPemEntryArgs{Text: fixtureCert})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(string); got != fixtureCert {
		t.Fatalf("roundtrip mismatch:\n%q\n%q", fixtureCert, got)
	}
}

func TestGetPemEntryRewrapsMangledInput(t *testing.T) {
	block, _ := pem.Decode([]byte(fixtureCert))
	body := base64.StdEncoding.EncodeToString(block.Bytes)
	oneLine := "-----BEGIN CERTIFICATE-----" + body + "-----END CERTIFICATE-----"
	rt, _ := x509RT(t, nil, nil)
	res, err := callX509(t, rt, "x509.get_pem_entry", &getPemEntryArgs{Text: oneLine})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(string); got != fixtureCert {
		t.Fatalf("single-line repair mismatch:\n%q", got)
	}

	// escaped newlines repair to the canonical layout
	joined := strings.ReplaceAll(fixtureCert, "\n", `\n`)
	res, err = callX509(t, rt, "x509.get_pem_entry", &getPemEntryArgs{Text: joined})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(string); got != fixtureCert {
		t.Fatalf("escaped-newline repair mismatch:\n%q", got)
	}
}

func TestGetPemEntryTypeFilterAndErrors(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	res, err := callX509(t, rt, "x509.get_pem_entry", &getPemEntryArgs{Text: fixtureCert, PemType: ps("CERTIFICATE")})
	if err != nil {
		t.Fatal(err)
	}
	if res.(string) != fixtureCert {
		t.Fatal("typed extraction mismatch")
	}

	_, err = callX509(t, rt, "x509.get_pem_entry", &getPemEntryArgs{Text: fixtureCert, PemType: ps("PRIVATE KEY")})
	if err == nil || err.Error() != "PEM does not contain a single entry of type PRIVATE KEY" {
		t.Fatalf("wrong-type error = %v", err)
	}

	_, err = callX509(t, rt, "x509.get_pem_entry", &getPemEntryArgs{Text: "not a pem at all"})
	if err == nil || err.Error() != "PEM text not valid" {
		t.Fatalf("invalid error = %v", err)
	}

	// the source's own key-type regex fragment
	keyPEM, _ := rsaKeyPEM(t, 1024)
	res, err = callX509(t, rt, "x509.get_pem_entry", &getPemEntryArgs{Text: keyPEM, PemType: ps("(?:RSA )?PRIVATE KEY")})
	if err != nil {
		t.Fatal(err)
	}
	if res.(string) != keyPEM {
		t.Fatal("key extraction mismatch")
	}

	// path input is read through the bounded FS
	rt2, _ := x509RT(t, map[string]string{"/work/ca.key": keyPEM}, nil)
	res, err = callX509(t, rt2, "x509.get_pem_entry", &getPemEntryArgs{Text: "/work/ca.key"})
	if err != nil {
		t.Fatal(err)
	}
	if res.(string) != keyPEM {
		t.Fatal("path read mismatch")
	}
}

// encryptKeyPEM wraps a PKCS#1 key in legacy DEK-Info encryption with
// the OpenSSL-style uppercase hex IV the pinned regex accepts (Go's
// helper writes lowercase).
func encryptKeyPEM(t *testing.T, keyPEM string, passphrase string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(keyPEM))
	enc, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", block.Bytes,
		[]byte(passphrase), x509.PEMCipherDES)
	if err != nil {
		t.Fatal(err)
	}
	if iv, ok := enc.Headers["DEK-Info"]; ok {
		if idx := strings.IndexByte(iv, ','); idx >= 0 {
			enc.Headers["DEK-Info"] = iv[:idx+1] + strings.ToUpper(iv[idx+1:])
		}
	}
	return string(pem.EncodeToMemory(enc))
}

func TestGetPemEntryEncryptedHeaders(t *testing.T) {
	keyPEM, _ := rsaKeyPEM(t, 1024)
	encPEM := encryptKeyPEM(t, keyPEM, "secret-passphrase")
	rt, _ := x509RT(t, nil, nil)
	res, err := callX509(t, rt, "x509.get_pem_entry", &getPemEntryArgs{Text: encPEM})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(string)
	if !strings.Contains(got, "Proc-Type: 4,ENCRYPTED\n") || !strings.Contains(got, "DEK-Info: DES-") {
		t.Fatalf("encryption headers not preserved:\n%s", got)
	}
	if strings.Contains(got, "\n\n") == false {
		t.Fatal("DEK-Info blank separator missing")
	}
	if rebuilt, _ := pem.Decode([]byte(got)); rebuilt == nil {
		t.Fatal("rebuilt PEM does not decode")
	}
}

// ---------------------------------------------------------------------------
// get_pem_entries

func TestGetPemEntriesGlob(t *testing.T) {
	keyPEM, _ := rsaKeyPEM(t, 1024)
	rt, _ := x509RT(t, map[string]string{
		"/pki/a.crt": fixtureCert,
		"/pki/b.key": keyPEM,
	}, nil)
	// a directory entry the glob must skip
	if err := rt.FS.MkdirAll("/pki/dir", 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := callX509(t, rt, "x509.get_pem_entries", &getPemEntriesArgs{GlobPath: "/pki/*"})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]string)
	if len(got) != 2 || got["/pki/a.crt"] != fixtureCert || got["/pki/b.key"] != keyPEM {
		t.Fatalf("glob result = %#v", got)
	}

	// upstream's except ValueError is dead for PEM failures: a garbage
	// regular file makes the whole call raise
	rt2, _ := x509RT(t, map[string]string{"/other/x.crt": "garbage"}, nil)
	if _, err = callX509(t, rt2, "x509.get_pem_entries", &getPemEntriesArgs{GlobPath: "/other/*.crt"}); err == nil {
		t.Fatal("expected PEM error to propagate")
	}

	// no matches -> empty dict
	rt3, _ := x509RT(t, nil, nil)
	res, err = callX509(t, rt3, "x509.get_pem_entries", &getPemEntriesArgs{GlobPath: "/nowhere/*.crt"})
	if err != nil {
		t.Fatal(err)
	}
	if m := res.(map[string]string); len(m) != 0 {
		t.Fatalf("expected empty map, got %#v", m)
	}
}

// ---------------------------------------------------------------------------
// get_private_key_size

func TestGetPrivateKeySize(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	rsa1024, _ := rsaKeyPEM(t, 1024)
	rsa2048, key2048 := rsaKeyPEM(t, 2048)
	ecKey := mustEC(t, elliptic.P256())
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name, input string
		want        int
	}{
		{"rsa1024-pkcs1", rsa1024, 1024},
		{"rsa2048-pkcs1", rsa2048, 2048},
		{"rsa2048-pkcs8", pkcs8KeyPEM(t, key2048), 2048},
		{"ec-p256-pkcs8", pkcs8KeyPEM(t, ecKey), 256},
		{"ec-p384-sec1", sec1ECKeyPEM(t, mustEC(t, elliptic.P384())), 384},
		{"ed25519-pkcs8", pkcs8KeyPEM(t, edPriv), 256},
	}
	for _, tc := range cases {
		res, err := callX509(t, rt, "x509.get_private_key_size", &getPrivateKeySizeArgs{PrivateKey: tc.input})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := res.(int); got != tc.want {
			t.Fatalf("%s = %d, want %d", tc.name, got, tc.want)
		}
	}

	// key bundled behind unrelated PEM junk still extracts
	bundle := "leading noise\n" + rsa1024
	res, err := callX509(t, rt, "x509.get_private_key_size", &getPrivateKeySizeArgs{PrivateKey: bundle})
	if err != nil {
		t.Fatal(err)
	}
	if res.(int) != 1024 {
		t.Fatalf("bundle = %v", res)
	}

	// unsupported / invalid inputs
	if _, err = callX509(t, rt, "x509.get_private_key_size", &getPrivateKeySizeArgs{PrivateKey: fixtureCert}); err == nil {
		t.Fatal("expected error for certificate input")
	}
	if _, err = callX509(t, rt, "x509.get_private_key_size", &getPrivateKeySizeArgs{PrivateKey: "no key"}); err == nil {
		t.Fatal("expected error for garbage input")
	}

	// encrypted key with passphrase
	keyPEM2, _ := rsaKeyPEM(t, 1024)
	res, err = callX509(t, rt, "x509.get_private_key_size", &getPrivateKeySizeArgs{
		PrivateKey: encryptKeyPEM(t, keyPEM2, "pw"), Passphrase: ps("pw"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.(int) != 1024 {
		t.Fatalf("encrypted = %v", res)
	}
	if _, err = callX509(t, rt, "x509.get_private_key_size", &getPrivateKeySizeArgs{
		PrivateKey: encryptKeyPEM(t, keyPEM2, "pw"),
	}); err == nil {
		t.Fatal("expected passphrase-required error")
	}
}

// ---------------------------------------------------------------------------
// read_certificate

func TestReadCertificateFixtureGoldens(t *testing.T) {
	rt, _ := x509RT(t, map[string]string{"/etc/pki/fixture.crt": fixtureCert}, nil)
	res, err := callX509(t, rt, "x509.read_certificate", &readCertificateArgs{Certificate: "/etc/pki/fixture.crt"})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]any)
	want := map[string]any{
		"Version":              3,
		"Key Size":             1024,
		"Serial Number":        fixtureSerial,
		"SHA-256 Finger Print": fixtureSHA256,
		"SHA1 Finger Print":    fixtureSHA1,
		"MD5 Finger Print":     fixtureMD5,
		"Subject Hash":         fixtureNameHash,
		"Issuer Hash":          fixtureNameHash,
		"Not Before":           fixtureNotBefore,
		"Not After":            fixtureNotAfter,
		"Subject":              map[string]string{"C": "US", "ST": "Arizona", "L": "Scottsdale", "O": "Super Widgits"},
		"Issuer":               map[string]string{"C": "US", "ST": "Arizona", "L": "Scottsdale", "O": "Super Widgits"},
	}
	for key, wantVal := range want {
		switch typed := wantVal.(type) {
		case map[string]string:
			if !reflect.DeepEqual(got[key], typed) {
				t.Errorf("%s = %#v, want %#v", key, got[key], typed)
			}
		default:
			if got[key] != wantVal {
				t.Errorf("%s = %v, want %v", key, got[key], wantVal)
			}
		}
	}
	exts, ok := got["X509v3 Extensions"].(map[string]string)
	if !ok {
		t.Fatalf("extensions missing: %#v", got["X509v3 Extensions"])
	}
	if exts["basicConstraints"] != "critical CA:TRUE" {
		t.Errorf("basicConstraints = %q", exts["basicConstraints"])
	}
	if !strings.HasPrefix(exts["subjectKeyIdentifier"], "9C:1D:6F:") {
		t.Errorf("subjectKeyIdentifier = %q", exts["subjectKeyIdentifier"])
	}
	if !strings.HasPrefix(exts["authorityKeyIdentifier"], "keyid:9C:1D:6F:") {
		t.Errorf("authorityKeyIdentifier = %q", exts["authorityKeyIdentifier"])
	}
	pubKey, ok := got["Public Key"].(string)
	if !ok || !strings.HasPrefix(pubKey, "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("Public Key = %q", got["Public Key"])
	}
	block, _ := pem.Decode([]byte(pubKey))
	if block == nil {
		t.Fatal("Public Key does not decode")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		t.Fatalf("Public Key does not parse as SPKI: %v", err)
	}
}

func TestReadCertificateFipsModeDropsMD5(t *testing.T) {
	rt, _ := x509RT(t, nil, map[string]any{"fips_mode": true})
	res, err := callX509(t, rt, "x509.read_certificate", &readCertificateArgs{Certificate: fixtureCert})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]any)
	if _, has := got["MD5 Finger Print"]; has {
		t.Fatal("fips_mode=True must omit MD5 Finger Print")
	}
	if _, has := got["SHA1 Finger Print"]; !has {
		t.Fatal("SHA1 still present under fips_mode")
	}
}

func TestReadCertificateGenerated(t *testing.T) {
	ca := newTestCA(t, "Redacted Root CA", time.Now().UTC().Add(3650*24*time.Hour))
	san := sanDER(bytes.Join([][]byte{
		ctxName(2, []byte("example.com")),
		ctxName(2, []byte("www.example.com")),
		ctxName(7, net.IPv4(10, 0, 0, 1).To4()),
		ctxName(1, []byte("certadm@example.org")),
		ctxName(6, []byte("https://example.com/")),
	}, nil))
	leaf := leafPEM(t, ca, ca.key, "Redacted Normal Certificate",
		time.Now().UTC().Add(90*24*time.Hour),
		[]pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: san},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: basicConstraintsDER(false)},
		},
		big.NewInt(0x1234567890))

	rt, _ := x509RT(t, nil, nil)
	res, err := callX509(t, rt, "x509.read_certificate", &readCertificateArgs{Certificate: leaf})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]any)
	if got["Version"] != 3 {
		t.Errorf("Version = %v", got["Version"])
	}
	if got["Key Size"] != 2048 {
		t.Errorf("Key Size = %v", got["Key Size"])
	}
	if got["Serial Number"] != "12:34:56:78:90" {
		t.Errorf("Serial Number = %v", got["Serial Number"])
	}
	subj := got["Subject"].(map[string]string)
	for k, v := range map[string]string{
		"C": "BE", "ST": "Antwerp", "L": "Local Town", "O": "Redacted",
		"OU": "Unit", "CN": "Redacted Normal Certificate",
	} {
		if subj[k] != v {
			t.Errorf("Subject[%s] = %q, want %q", k, subj[k], v)
		}
	}
	issuer := got["Issuer"].(map[string]string)
	if issuer["CN"] != "Redacted Root CA" {
		t.Errorf("Issuer = %#v", issuer)
	}
	if _, has := issuer["OU"]; has {
		t.Errorf("issuer OU leaked: %#v", issuer)
	}
	exts := got["X509v3 Extensions"].(map[string]string)
	if want := "critical DNS:example.com, DNS:www.example.com, IP Address:10.0.0.1, email:certadm@example.org, URI:https://example.com/"; exts["subjectAltName"] != want {
		t.Errorf("subjectAltName = %q, want %q", exts["subjectAltName"], want)
	}
	if exts["basicConstraints"] != "critical CA:FALSE" {
		t.Errorf("basicConstraints = %q", exts["basicConstraints"])
	}
	if !strings.HasPrefix(exts["authorityKeyIdentifier"], "keyid:") {
		t.Errorf("authorityKeyIdentifier = %q", exts["authorityKeyIdentifier"])
	}
	if _, err := time.Parse(dateTimeLayout, got["Not Before"].(string)); err != nil {
		t.Errorf("Not Before = %v", got["Not Before"])
	}

	// v1 certificate (no extensions, no explicit version field): Go's
	// builder always writes v3, so the TBS is rebuilt without the [0]
	// version element and re-signed.
	v1PEM := v1CertPEM(t, ca)
	res, err = callX509(t, rt, "x509.read_certificate", &readCertificateArgs{Certificate: v1PEM})
	if err != nil {
		t.Fatal(err)
	}
	v1got := res.(map[string]any)
	if v1got["Version"] != 1 {
		t.Fatalf("v1 Version = %v", v1got["Version"])
	}
	if _, hasExt := v1got["X509v3 Extensions"]; hasExt {
		t.Fatal("v1 certificate must not report extensions")
	}

	// EC and Ed25519 certificates surface the documented key sizes
	ecKey := mustEC(t, elliptic.P256())
	ecCert := leafPEM(t, ca, ecKey, "EC Leaf", time.Now().UTC().Add(24*time.Hour), nil, big.NewInt(11))
	res, err = callX509(t, rt, "x509.read_certificate", &readCertificateArgs{Certificate: ecCert})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["Key Size"] != 256 {
		t.Fatalf("EC Key Size = %v", res.(map[string]any)["Key Size"])
	}

	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edCert := leafPEM(t, ca, edPriv, "Ed Leaf", time.Now().UTC().Add(24*time.Hour), nil, big.NewInt(12))
	res, err = callX509(t, rt, "x509.read_certificate", &readCertificateArgs{Certificate: edCert})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["Key Size"] != 256 {
		t.Fatalf("Ed25519 Key Size = %v", res.(map[string]any)["Key Size"])
	}

	// non-PEM / non-certificate errors
	if _, err = callX509(t, rt, "x509.read_certificate", &readCertificateArgs{Certificate: "garbage"}); err == nil {
		t.Fatal("expected error for garbage input")
	}
	keyPEM, _ := rsaKeyPEM(t, 1024)
	if _, err = callX509(t, rt, "x509.read_certificate", &readCertificateArgs{Certificate: keyPEM}); err == nil {
		t.Fatal("expected type error for key input")
	}
}

// ---------------------------------------------------------------------------
// read_certificates

func TestReadCertificatesGlob(t *testing.T) {
	ca := newTestCA(t, "Redacted Root CA", time.Now().UTC().Add(3650*24*time.Hour))
	leaf1 := leafPEM(t, ca, ca.key, "First", time.Now().UTC().Add(24*time.Hour), nil, big.NewInt(101))
	leaf2 := leafPEM(t, ca, ca.key, "Second", time.Now().UTC().Add(48*time.Hour), nil, big.NewInt(102))
	rt, _ := x509RT(t, map[string]string{
		"/bundle/one.crt": leaf1,
		"/bundle/two.crt": leaf2,
		"/bundle/key.bin": "not a certificate",
	}, nil)

	// garbage file in the glob: parse error propagates (dead except)
	if _, err := callX509(t, rt, "x509.read_certificates", &readCertificatesArgs{GlobPath: "/bundle/*"}); err == nil {
		t.Fatal("expected parse error to propagate from the garbage file")
	}
	if rerr := rt.FS.Remove("/bundle/key.bin"); rerr != nil {
		t.Fatal(rerr)
	}

	res, err := callX509(t, rt, "x509.read_certificates", &readCertificatesArgs{GlobPath: "/bundle/*.crt"})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]any)
	if len(got) != 2 {
		t.Fatalf("glob size = %d", len(got))
	}
	first := got["/bundle/one.crt"].(map[string]any)
	if first["Subject"].(map[string]string)["CN"] != "First" {
		t.Errorf("one.crt subject = %#v", first["Subject"])
	}
	if first["Serial Number"] != "65" {
		t.Errorf("serial 101 = %v", first["Serial Number"])
	}
	second := got["/bundle/two.crt"].(map[string]any)
	if second["Serial Number"] != "66" {
		t.Errorf("serial 102 = %v", second["Serial Number"])
	}
}

// ---------------------------------------------------------------------------
// read_csr

func TestReadCsr(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	san := sanDER(ctxName(2, []byte("csr.example.com")))
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"BE"},
			Organization:       []string{"Redacted"},
			OrganizationalUnit: []string{"Unit"},
			CommonName:         "Redacted CSR",
		},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: basicConstraintsDER(true)},
		},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))

	rt, _ := x509RT(t, map[string]string{"/work/request.csr": csrPEM}, nil)
	res, err := callX509(t, rt, "x509.read_csr", &readCsrArgs{Csr: "/work/request.csr"})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]any)
	if got["Version"] != 1 {
		t.Errorf("Version = %v", got["Version"])
	}
	subj := got["Subject"].(map[string]string)
	if subj["CN"] != "Redacted CSR" || subj["O"] != "Redacted" || subj["OU"] != "Unit" {
		t.Errorf("Subject = %#v", subj)
	}
	// Public Key Hash: sha1 over the minimal big-endian modulus
	wantHash := fmt.Sprintf("%x", sha1.Sum(key.PublicKey.N.Bytes()))
	if got["Public Key Hash"] != wantHash {
		t.Errorf("Public Key Hash = %v, want %v", got["Public Key Hash"], wantHash)
	}
	if got["Subject Hash"] == "" {
		t.Error("Subject Hash missing")
	}
	exts := got["X509v3 Extensions"].(map[string]string)
	if exts["subjectAltName"] != "DNS:csr.example.com" {
		t.Errorf("subjectAltName = %q", exts["subjectAltName"])
	}
	if exts["basicConstraints"] != "critical CA:TRUE" {
		t.Errorf("basicConstraints = %q", exts["basicConstraints"])
	}

	// wrong type and garbage inputs
	if _, err = callX509(t, rt, "x509.read_csr", &readCsrArgs{Csr: fixtureCert}); err == nil {
		t.Fatal("expected type error for certificate input")
	}
	if _, err = callX509(t, rt, "x509.read_csr", &readCsrArgs{Csr: "garbage"}); err == nil {
		t.Fatal("expected error for garbage input")
	}
}

// ---------------------------------------------------------------------------
// expired / will_expire

func TestExpiredAndWillExpire(t *testing.T) {
	pastCA := newTestCA(t, "Expired CA", time.Now().UTC().Add(-24*time.Hour))
	futureCA := newTestCA(t, "Fresh CA", time.Now().UTC().Add(365*24*time.Hour))
	soonCA := newTestCA(t, "Soon CA", time.Now().UTC().Add(2*24*time.Hour))

	files := map[string]string{
		"/pki/expired.crt": pastCA.certPEM,
		"/pki/fresh.crt":   futureCA.certPEM,
		"/pki/soon.crt":    soonCA.certPEM,
		"/pki/garbage.crt": "not a certificate",
	}
	rt, _ := x509RT(t, files, nil)

	res, err := callX509(t, rt, "x509.expired", &expiredArgs{Certificate: "/pki/expired.crt"})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]any)
	if got["path"] != "/pki/expired.crt" || got["cn"] != "Expired CA" || got["expired"] != true {
		t.Fatalf("expired = %#v", got)
	}

	res, err = callX509(t, rt, "x509.expired", &expiredArgs{Certificate: "/pki/fresh.crt"})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["expired"] != false {
		t.Fatalf("fresh = %#v", res)
	}

	// inline PEM input is not a file: upstream returns {}
	res, err = callX509(t, rt, "x509.expired", &expiredArgs{Certificate: futureCA.certPEM})
	if err != nil {
		t.Fatal(err)
	}
	if m := res.(map[string]any); len(m) != 0 {
		t.Fatalf("inline input = %#v, want {}", m)
	}

	// missing file is not a file either
	res, err = callX509(t, rt, "x509.expired", &expiredArgs{Certificate: "/pki/nope.crt"})
	if err != nil {
		t.Fatal(err)
	}
	if m := res.(map[string]any); len(m) != 0 {
		t.Fatalf("missing input = %#v, want {}", m)
	}

	// unparseable file keeps the partial {"path"} shape
	res, err = callX509(t, rt, "x509.expired", &expiredArgs{Certificate: "/pki/garbage.crt"})
	if err != nil {
		t.Fatal(err)
	}
	if m := res.(map[string]any); len(m) != 1 || m["path"] != "/pki/garbage.crt" {
		t.Fatalf("garbage = %#v, want {path}", m)
	}

	// certificate without CN raises the KeyError shape
	noCN := &x509.Certificate{
		SerialNumber: big.NewInt(9),
		Subject:      pkix.Name{Organization: []string{"No CN Corp"}},
		NotBefore:    time.Now().UTC().Add(-time.Hour),
		NotAfter:     time.Now().UTC().Add(24 * time.Hour),
	}
	der, cerr := x509.CreateCertificate(rand.Reader, noCN, noCN, &futureCA.key.PublicKey, futureCA.key)
	if cerr != nil {
		t.Fatal(cerr)
	}
	noCNPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if werr := rt.FS.WriteFile("/pki/nocn.crt", []byte(noCNPEM), 0o644); werr != nil {
		t.Fatal(werr)
	}
	if _, err = callX509(t, rt, "x509.expired", &expiredArgs{Certificate: "/pki/nocn.crt"}); err == nil ||
		err.Error() != "KeyError: 'CN'" {
		t.Fatalf("no-CN error = %v", err)
	}

	// will_expire: cert valid two more days
	res, err = callX509(t, rt, "x509.will_expire", &willExpireArgs{Certificate: "/pki/soon.crt", Days: pi(1)})
	if err != nil {
		t.Fatal(err)
	}
	got = res.(map[string]any)
	if got["check_days"] != 1 || got["will_expire"] != false {
		t.Fatalf("soon/1 = %#v", got)
	}
	res, err = callX509(t, rt, "x509.will_expire", &willExpireArgs{Certificate: "/pki/soon.crt", Days: pi(5)})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["will_expire"] != true {
		t.Fatalf("soon/5 = %#v", res)
	}
	res, err = callX509(t, rt, "x509.will_expire", &willExpireArgs{Certificate: "/pki/fresh.crt", Days: pi(0)})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["will_expire"] != false {
		t.Fatalf("fresh/0 = %#v", res)
	}
	// an already-expired cert reports will_expire=True for any horizon
	res, err = callX509(t, rt, "x509.will_expire", &willExpireArgs{Certificate: "/pki/expired.crt", Days: pi(30)})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["will_expire"] != true {
		t.Fatalf("expired/30 = %#v", res)
	}
}

// ---------------------------------------------------------------------------
// verify_private_key / get_public_key

func TestVerifyPrivateKey(t *testing.T) {
	ca := newTestCA(t, "Redacted Root CA", time.Now().UTC().Add(3650*24*time.Hour))
	otherPEM, _ := rsaKeyPEM(t, 2048)
	rt, _ := x509RT(t, map[string]string{
		"/pki/ca.key":    ca.keyPEM,
		"/pki/ca.crt":    ca.certPEM,
		"/pki/other.key": otherPEM,
	}, nil)

	cases := []struct {
		name      string
		priv, pub string
		want      bool
	}{
		{"key-vs-cert", "/pki/ca.key", "/pki/ca.crt", true},
		{"key-vs-key", "/pki/ca.key", "/pki/ca.key", true},
		{"mismatch", "/pki/ca.key", "/pki/other.key", false},
		{"inline-cert", "/pki/ca.key", ca.certPEM, true},
	}
	for _, tc := range cases {
		res, err := callX509(t, rt, "x509.verify_private_key", &verifyPrivateKeyArgs{
			PrivateKey: tc.priv, PublicKey: tc.pub,
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if res.(bool) != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, res, tc.want)
		}
	}

	// absent key errors through the get_pem_entry contract
	if _, err := callX509(t, rt, "x509.verify_private_key", &verifyPrivateKeyArgs{
		PrivateKey: "/pki/absent.key", PublicKey: "/pki/ca.crt",
	}); err == nil {
		t.Fatal("expected error for absent key path")
	}
}

func TestGetPublicKey(t *testing.T) {
	ca := newTestCA(t, "Redacted Root CA", time.Now().UTC().Add(3650*24*time.Hour))
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey := mustEC(t, elliptic.P256())
	rt, _ := x509RT(t, nil, nil)

	// certificate -> SPKI public key
	res, err := callX509(t, rt, "x509.get_public_key", &getPublicKeyArgs{Key: ca.certPEM})
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := res.(string)
	if !strings.HasPrefix(pubPEM, "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("cert pubkey = %q", pubPEM)
	}
	wantDER, _ := x509.MarshalPKIXPublicKey(&ca.key.PublicKey)
	wantPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: wantDER}))
	if pubPEM != wantPEM {
		t.Fatal("cert pubkey SPKI mismatch")
	}

	// private key -> public key (RSA and EC)
	res, err = callX509(t, rt, "x509.get_public_key", &getPublicKeyArgs{Key: pkcs8KeyPEM(t, key)})
	if err != nil {
		t.Fatal(err)
	}
	wantRSADER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if res.(string) != string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: wantRSADER})) {
		t.Fatal("rsa key -> pubkey mismatch")
	}
	res, err = callX509(t, rt, "x509.get_public_key", &getPublicKeyArgs{Key: sec1ECKeyPEM(t, ecKey)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.(string), "-----BEGIN PUBLIC KEY-----") {
		t.Fatal("ec key -> pubkey mismatch")
	}

	// already-public input passes through normalized
	res, err = callX509(t, rt, "x509.get_public_key", &getPublicKeyArgs{Key: wantPEM})
	if err != nil {
		t.Fatal(err)
	}
	if res.(string) != wantPEM {
		t.Fatal("public key passthrough mismatch")
	}

	// first-entry extraction: key first in a bundle
	bundle := ca.keyPEM + ca.certPEM
	res, err = callX509(t, rt, "x509.get_public_key", &getPublicKeyArgs{Key: bundle})
	if err != nil {
		t.Fatal(err)
	}
	caDER, _ := x509.MarshalPKIXPublicKey(&ca.key.PublicKey)
	if res.(string) != string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: caDER})) {
		t.Fatal("bundle first-entry mismatch")
	}

	// unsupported PEM type errors cleanly (upstream crashes on it)
	if _, err = callX509(t, rt, "x509.get_public_key", &getPublicKeyArgs{
		Key: "-----BEGIN DH PARAMETERS-----\nAAAA\n-----END DH PARAMETERS-----\n",
	}); err == nil {
		t.Fatal("expected unsupported PEM type error")
	}
}

// ---------------------------------------------------------------------------
// registry, CLI and sandbox contracts

func TestRegistryCallPaths(t *testing.T) {
	rt, _ := x509RT(t, map[string]string{"/pki/ca.crt": fixtureCert}, nil)
	// registry-level dispatch through rt.Exec.Call with typed args
	res, err := rt.Exec.Call(context.Background(), rt, "x509.read_certificate", &readCertificateArgs{
		Certificate: "/pki/ca.crt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["Serial Number"] != fixtureSerial {
		t.Fatalf("registry call = %#v", res)
	}

	want := []string{
		"x509.create_certificate", "x509.create_crl", "x509.create_csr",
		"x509.create_private_key", "x509.encode_certificate", "x509.encode_crl",
		"x509.encode_csr", "x509.encode_private_key", "x509.expired",
		"x509.expires", "x509.get_pem_entries", "x509.get_pem_entry",
		"x509.get_private_key_size", "x509.get_public_key", "x509.get_signing_policy",
		"x509.read_certificate", "x509.read_certificates", "x509.read_crl",
		"x509.read_csr", "x509.verify_crl", "x509.verify_private_key",
		"x509.verify_signature", "x509.will_expire", "x509.write_pem",
	}
	names := rt.Exec.Names()
	if len(names) != len(want) {
		t.Fatalf("registered %d functions (%v), want %d", len(names), names, len(want))
	}
	set := map[string]bool{}
	for _, name := range names {
		set[name] = true
	}
	for _, name := range want {
		if !set[name] {
			t.Errorf("%s not registered", name)
		}
	}
}

func TestCLISurface(t *testing.T) {
	ca := newTestCA(t, "CLI CA", time.Now().UTC().Add(365*24*time.Hour))
	build := func() (*runtime.Runtime, error) {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			return nil, err
		}
		rt := &runtime.Runtime{
			Exec:   reg,
			States: runtime.NewStateRegistry(),
			FS:     runtime.NewMemoryFS(),
		}
		if err := rt.FS.MkdirAll("/pki", 0o755); err != nil {
			return nil, err
		}
		if err := rt.FS.WriteFile("/pki/ca.crt", []byte(fixtureCert), 0o644); err != nil {
			return nil, err
		}
		if err := rt.FS.WriteFile("/pki/cli.crt", []byte(ca.certPEM), 0o644); err != nil {
			return nil, err
		}
		return rt, nil
	}
	app := cli.NewApp("test", build)

	if code := app.Run([]string{"exec", "x509.read_certificate", "--certificate", "/pki/ca.crt", "-o", "json"}); code != 0 {
		t.Fatalf("read_certificate exit = %d", code)
	}
	if code := app.Run([]string{"exec", "x509.expired", "--certificate", "/pki/cli.crt", "-o", "json"}); code != 0 {
		t.Fatalf("expired exit = %d", code)
	}
	if code := app.Run([]string{"exec", "x509.will_expire", "--certificate", "/pki/cli.crt", "--days", "30", "-o", "json"}); code != 0 {
		t.Fatalf("will_expire exit = %d", code)
	}
	if code := app.Run([]string{"exec", "x509.read_certificate"}); code != 2 {
		t.Fatalf("missing required exit = %d, want 2", code)
	}
	// create_certificate is registered by R5.2b; with no path/text
	// targets it fails as a SaltInvocationError (exit 1).
	if code := app.Run([]string{"exec", "x509.create_certificate"}); code != 1 {
		t.Fatalf("create_certificate no-target exit = %d, want 1", code)
	}
}

func TestNoRunnerAndNoMutation(t *testing.T) {
	ca := newTestCA(t, "Bundle CA", time.Now().UTC().Add(24*time.Hour))
	rt, runner := x509RT(t, map[string]string{
		"/pki/ca.crt": ca.certPEM,
		"/pki/bundle": ca.keyPEM,
	}, nil)

	calls := []struct {
		name string
		args any
	}{
		{"x509.read_certificate", &readCertificateArgs{Certificate: "/pki/ca.crt"}},
		{"x509.read_certificates", &readCertificatesArgs{GlobPath: "/pki/*.crt"}},
		{"x509.get_pem_entries", &getPemEntriesArgs{GlobPath: "/pki/*"}},
		{"x509.expired", &expiredArgs{Certificate: "/pki/ca.crt"}},
		{"x509.will_expire", &willExpireArgs{Certificate: "/pki/ca.crt", Days: pi(3)}},
		{"x509.get_private_key_size", &getPrivateKeySizeArgs{PrivateKey: "/pki/bundle"}},
		{"x509.get_public_key", &getPublicKeyArgs{Key: "/pki/bundle"}},
	}
	for _, call := range calls {
		if _, err := callX509(t, rt, call.name, call.args); err != nil {
			t.Fatalf("%s: %v", call.name, err)
		}
	}
	if runner.calls != 0 {
		t.Fatalf("runner invoked %d times; the read-only surface must not spawn processes", runner.calls)
	}

	after, err := rt.FS.ReadFile("/pki/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != ca.certPEM {
		t.Fatal("input file mutated")
	}
	if entries, rerr := rt.FS.ReadDir("/pki"); rerr != nil || len(entries) != 2 {
		t.Fatalf("unexpected directory writes: %v %v", entries, rerr)
	}
}

func TestInputBoundsAndSymlinks(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	// oversized file input exceeds the bounded reader
	big := strings.Repeat("A", int(maxPEMBytes)+2)
	payload := "-----BEGIN CERTIFICATE-----\n" + big + "\n-----END CERTIFICATE-----\n"
	if werr := rt.FS.MkdirAll("/pki", 0o755); werr != nil {
		t.Fatal(werr)
	}
	if werr := rt.FS.WriteFile("/pki/huge.crt", []byte(payload), 0o644); werr != nil {
		t.Fatal(werr)
	}
	_, err := callX509(t, rt, "x509.read_certificate", &readCertificateArgs{Certificate: "/pki/huge.crt"})
	if err == nil || !strings.Contains(err.Error(), "read limit") {
		t.Fatalf("oversized read error = %v", err)
	}

	// symlinked input is rejected by the bounded reader
	if werr := rt.FS.WriteFile("/pki/real.crt", []byte(fixtureCert), 0o644); werr != nil {
		t.Fatal(werr)
	}
	if serr := rt.FS.Symlink("/pki/real.crt", "/pki/link.crt"); serr != nil {
		t.Fatal(serr)
	}
	if _, err = callX509(t, rt, "x509.read_certificate", &readCertificateArgs{Certificate: "/pki/link.crt"}); err == nil {
		t.Fatal("expected symlink rejection")
	}

	// directory input behaves like inline text -> PEM invalid
	if _, err = callX509(t, rt, "x509.get_pem_entry", &getPemEntryArgs{Text: "/pki"}); err == nil ||
		err.Error() != "PEM text not valid" {
		t.Fatalf("directory input error = %v", err)
	}
	// expired() treats a directory as not-a-file
	if _, err = callX509(t, rt, "x509.expired", &expiredArgs{Certificate: "/pki"}); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// canonical name hash unit checks

func TestCanonicalNameHash(t *testing.T) {
	// whitespace canonicalization
	nameDER, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "  Multiple   Spaces "}},
	})
	if err != nil {
		t.Fatal(err)
	}
	canon, cerr := canonicalNameDER(nameDER)
	if cerr != nil {
		t.Fatal(cerr)
	}
	if bytes.Contains(canon, []byte("  ")) {
		t.Fatal("internal whitespace not collapsed")
	}
	if bytes.Contains(canon, []byte("  Multiple   Spaces ")) {
		t.Fatal("raw value survived canonicalization")
	}

	// multi-valued RDN members are sorted by encoding
	multi, err := asn1.Marshal(pkix.RDNSequence{
		{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "zz"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "aa"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	canon2, cerr := canonicalNameDER(multi)
	if cerr != nil {
		t.Fatal(cerr)
	}
	ouAt := bytes.Index(canon2, []byte{0x55, 0x04, 0x0b}) // 2.5.4.11 OU
	cnAt := bytes.Index(canon2, []byte{0x55, 0x04, 0x03}) // 2.5.4.3 CN
	// DER byte comparison sorts by the OID: CN (…03) sorts before
	// OU (…0b) regardless of the attribute values.
	if ouAt < 0 || cnAt < 0 || cnAt > ouAt {
		t.Fatalf("RDN members not sorted: OU@%d CN@%d", ouAt, cnAt)
	}

	// fixture golden: the wire subject hashes to the pinned value
	der, _ := pem.Decode([]byte(fixtureCert))
	cert, perr := x509.ParseCertificate(der.Bytes)
	if perr != nil {
		t.Fatal(perr)
	}
	hash, herr := nameHashHex(cert.RawSubject)
	if herr != nil {
		t.Fatal(herr)
	}
	if hash != fixtureNameHash {
		t.Fatalf("fixture name hash = %s, want %s", hash, fixtureNameHash)
	}
}
