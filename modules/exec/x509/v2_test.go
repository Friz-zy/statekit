package x509

// R5.4 tests for the x509_v2 round, mapped onto the contracts of
// saltstack/salt/modules/x509_v2.py and salt/utils/x509.py @ pinned
// revision and the behaviors pinned by tests/pytests/functional/
// modules/test_x509_v2.py (read_crl/encode_private_key/expires
// shapes). All PKI material is generated inside the tests with
// crypto/x509 — no external CA, no openssl binary, no Runner spawns.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/cli"
	"github.com/friz-zy/statekit/internal/runtime"
)

// ---------------------------------------------------------------------------
// in-test PKI material

type v2CA struct {
	cert    *x509.Certificate
	certPEM string
	key     *rsa.PrivateKey
}

// newV2CA builds a CA with a SubjectKeyId so stdlib CRLs carry an
// authorityKeyIdentifier extension.
func newV2CA(t *testing.T) *v2CA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ski := sha1.Sum(spki)
	now := time.Date(2022, 11, 16, 4, 10, 8, 0, time.UTC)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x2A),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Salt"},
			OrganizationalUnit: []string{"Unit"},
			CommonName:         "Test",
			StreetAddress:      []string{"123 Street"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "ca@example.com"},
				{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: "cauid"},
			},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &v2CA{
		cert:    cert,
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		key:     key,
	}
}

// v2CRLPEM signs a CRL with entries; extra rides template.ExtraExtensions.
func v2CRLPEM(t *testing.T, ca *v2CA, entries []x509.RevocationListEntry, extra []pkix.Extension, sigAlg x509.SignatureAlgorithm) string {
	t.Helper()
	this := time.Date(2022, 11, 16, 4, 10, 8, 0, time.UTC)
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(3),
		ThisUpdate:                this,
		NextUpdate:                this.Add(100 * 24 * time.Hour),
		RevokedCertificateEntries: entries,
		ExtraExtensions:           extra,
		SignatureAlgorithm:        sigAlg,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))
}

func v2CsrPEM(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "csr.example.com"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

func v2PKCS8PEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func v2EncryptedKeyPEM(t *testing.T, key *rsa.PrivateKey, passphrase string) string {
	t.Helper()
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY",
		x509.MarshalPKCS1PrivateKey(key), []byte(passphrase), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

// ---------------------------------------------------------------------------
// encode_certificate

func TestV2EncodeCertificate(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	ca := newV2CA(t)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca.cert, &ca.key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))

	// pem identity: encode_certificate re-emits the canonical PEM
	res, err := callX509(t, rt, "x509.encode_certificate", &encodeCertificateArgs{Certificate: leafPEM})
	if err != nil {
		t.Fatal(err)
	}
	if res.(string) != leafPEM {
		t.Fatalf("pem encode = %q, want identity", res.(string))
	}

	// der raw returns the exact certificate DER bytes
	res, err = callX509(t, rt, "x509.encode_certificate",
		&encodeCertificateArgs{Certificate: leafPEM, Encoding: ps("der"), Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.([]byte), leafDER) {
		t.Fatalf("der raw = %v, want certificate DER", res)
	}

	// non-raw der is standard base64
	res, err = callX509(t, rt, "x509.encode_certificate",
		&encodeCertificateArgs{Certificate: leafPEM, Encoding: ps("der")})
	if err != nil {
		t.Fatal(err)
	}
	wantB64 := base64.StdEncoding.EncodeToString(leafDER)
	if res.(string) != wantB64 {
		t.Fatalf("der b64 = %q, want %q", res.(string), wantB64)
	}

	// path input, hex/base64/b64: inline DER strings
	if werr := rt.FS.MkdirAll("/pki", 0o755); werr != nil {
		t.Fatal(werr)
	}
	if werr := rt.FS.WriteFile("/pki/leaf.crt", []byte(leafPEM), 0o644); werr != nil {
		t.Fatal(werr)
	}
	res, err = callX509(t, rt, "x509.encode_certificate",
		&encodeCertificateArgs{Certificate: "/pki/leaf.crt", Encoding: ps("der"), Raw: true})
	if err != nil || !bytes.Equal(res.([]byte), leafDER) {
		t.Fatalf("path input = %v %v", res, err)
	}
	for name, inline := range map[string]string{
		"hex": hex.EncodeToString(leafDER),
		"b64": base64.StdEncoding.EncodeToString(leafDER),
	} {
		res, err = callX509(t, rt, "x509.encode_certificate",
			&encodeCertificateArgs{Certificate: inline, Encoding: ps("der"), Raw: true})
		if err != nil || !bytes.Equal(res.([]byte), leafDER) {
			t.Fatalf("%s inline = %v %v", name, res, err)
		}
	}
	res, err = callX509(t, rt, "x509.encode_certificate",
		&encodeCertificateArgs{Certificate: "b64:" + base64.StdEncoding.EncodeToString(leafDER), Raw: true})
	if err != nil || !bytes.Equal(res.([]byte), []byte(leafPEM)) {
		t.Fatalf("b64: prefix = %v %v", res, err)
	}

	// append_certs joins the chain with a newline for pem
	res, err = callX509(t, rt, "x509.encode_certificate", &encodeCertificateArgs{
		Certificate: leafPEM, AppendCerts: []string{ca.certPEM}})
	if err != nil {
		t.Fatal(err)
	}
	if res.(string) != leafPEM+"\n"+ca.certPEM {
		t.Fatalf("chain encode = %q", res.(string))
	}

	// pinned validation errors, in the pinned order
	cases := []struct {
		name string
		args encodeCertificateArgs
		want string
	}{
		{"invalid encoding", encodeCertificateArgs{Certificate: leafPEM, Encoding: ps("pemx")},
			"Invalid value 'pemx' for encoding. Valid: der, pem, pkcs7_der, pkcs7_pem, pkcs12"},
		{"der chain", encodeCertificateArgs{Certificate: leafPEM, Encoding: ps("der"),
			AppendCerts: []string{ca.certPEM}}, "Cannot encode a certificate chain in DER"},
		{"key outside pkcs12", encodeCertificateArgs{Certificate: leafPEM,
			PrivateKey: ps("-----BEGIN PRIVATE KEY-----")},
			"Embedding private keys is only supported for pkcs12 encoding"},
		{"pkcs12 without key", encodeCertificateArgs{Certificate: leafPEM, Encoding: ps("pkcs12")},
			"Creating a PKCS12-encoded certificate without embedded private key is unsupported"},
		{"pem garbage", encodeCertificateArgs{Certificate: "-----BEGIN CERTIFICATE-----\nAAAA\n"},
			"Could not load PEM-encoded certificate."},
		{"der garbage", encodeCertificateArgs{Certificate: "zzzz"},
			"Could not deserialize binary data, neither as DER nor PKCS#7, PKCS#12."},
		{"unloadable source", encodeCertificateArgs{Certificate: "not a certificate!"}, couldNotLoadSource},
	}
	for _, tc := range cases {
		_, err = callX509(t, rt, "x509.encode_certificate", &tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s error = %v, want %q", tc.name, err, tc.want)
		}
	}

	// container boundary: pkcs7/pkcs12 encodings and PKCS7-PEM inputs
	for _, enc := range []string{"pkcs7_der", "pkcs7_pem"} {
		_, err = callX509(t, rt, "x509.encode_certificate",
			&encodeCertificateArgs{Certificate: leafPEM, Encoding: ps(enc)})
		if _, ok := err.(*runtime.UnsupportedError); !ok {
			t.Fatalf("%s error = %v, want container UnsupportedError", enc, err)
		}
	}
	_, err = callX509(t, rt, "x509.encode_certificate", &encodeCertificateArgs{
		Certificate: leafPEM, Encoding: ps("pkcs12"), PrivateKey: ps("/pki/ca.key")})
	if _, ok := err.(*runtime.UnsupportedError); !ok {
		t.Fatalf("pkcs12 error = %v, want container UnsupportedError", err)
	}
	_, err = callX509(t, rt, "x509.encode_certificate", &encodeCertificateArgs{
		Certificate: "-----BEGIN PKCS7-----\nAAAA\n-----END PKCS7-----\n"})
	if _, ok := err.(*runtime.UnsupportedError); !ok {
		t.Fatalf("pkcs7 input error = %v, want container UnsupportedError", err)
	}
}

// ---------------------------------------------------------------------------
// encode_crl / encode_csr

func TestV2EncodeCrl(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	ca := newV2CA(t)
	crlPEM := v2CRLPEM(t, ca, []x509.RevocationListEntry{{
		SerialNumber:   big.NewInt(0x147947),
		RevocationTime: time.Date(2022, 11, 16, 3, 10, 8, 0, time.UTC),
		ReasonCode:     1,
	}}, nil, x509.SHA256WithRSA)

	res, err := callX509(t, rt, "x509.encode_crl", &encodeCrlArgs{Crl: crlPEM})
	if err != nil {
		t.Fatal(err)
	}
	if res.(string) != crlPEM {
		t.Fatalf("pem encode = %q, want identity", res.(string))
	}

	block, _ := pem.Decode([]byte(crlPEM))
	if block == nil {
		t.Fatal("fixture CRL undecodable")
	}
	res, err = callX509(t, rt, "x509.encode_crl",
		&encodeCrlArgs{Crl: crlPEM, Encoding: ps("der"), Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.([]byte), block.Bytes) {
		t.Fatal("der raw roundtrip mismatch")
	}
	res, err = callX509(t, rt, "x509.encode_crl", &encodeCrlArgs{Crl: crlPEM, Encoding: ps("der")})
	if err != nil {
		t.Fatal(err)
	}
	if res.(string) != base64.StdEncoding.EncodeToString(block.Bytes) {
		t.Fatal("der base64 mismatch")
	}

	// hex-inline DER input round-trips to PEM
	res, err = callX509(t, rt, "x509.encode_crl",
		&encodeCrlArgs{Crl: hex.EncodeToString(block.Bytes)})
	if err != nil || res.(string) != crlPEM {
		t.Fatalf("hex inline = %v %v", res, err)
	}

	cases := []struct {
		name string
		args encodeCrlArgs
		want string
	}{
		{"invalid encoding", encodeCrlArgs{Crl: crlPEM, Encoding: ps("pemx")},
			"Invalid value 'pemx' for encoding. Valid: der, pem"},
		{"pem wrong type", encodeCrlArgs{Crl: ca.certPEM},
			"Could not load PEM-encoded certificate revocation list."},
		{"der garbage", encodeCrlArgs{Crl: "zzzz"},
			"Could not load DER-encoded certificate revocation list."},
	}
	for _, tc := range cases {
		_, err = callX509(t, rt, "x509.encode_crl", &tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s error = %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestV2EncodeCsr(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	csrPEM, _ := v2CsrPEM(t)

	res, err := callX509(t, rt, "x509.encode_csr", &encodeCsrArgs{Csr: csrPEM})
	if err != nil {
		t.Fatal(err)
	}
	if res.(string) != csrPEM {
		t.Fatalf("pem encode = %q, want identity", res.(string))
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("fixture CSR undecodable")
	}
	res, err = callX509(t, rt, "x509.encode_csr",
		&encodeCsrArgs{Csr: csrPEM, Encoding: ps("der"), Raw: true})
	if err != nil || !bytes.Equal(res.([]byte), block.Bytes) {
		t.Fatalf("der raw = %v %v", res, err)
	}
	if werr := rt.FS.MkdirAll("/pki", 0o755); werr != nil {
		t.Fatal(werr)
	}
	if werr := rt.FS.WriteFile("/pki/req.csr", []byte(csrPEM), 0o644); werr != nil {
		t.Fatal(werr)
	}
	res, err = callX509(t, rt, "x509.encode_csr", &encodeCsrArgs{Csr: "/pki/req.csr"})
	if err != nil || res.(string) != csrPEM {
		t.Fatalf("path input = %v %v", res, err)
	}

	cases := []struct {
		name string
		args encodeCsrArgs
		want string
	}{
		{"invalid encoding", encodeCsrArgs{Csr: csrPEM, Encoding: ps("pemx")},
			"Invalid value 'pemx' for encoding. Valid: der, pem"},
		{"pem wrong type", encodeCsrArgs{Csr: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"},
			"Could not load PEM-encoded certificate signing request."},
		{"der garbage", encodeCsrArgs{Csr: "zzzz"},
			"Could not load DER-encoded certificate signing request."},
	}
	for _, tc := range cases {
		_, err = callX509(t, rt, "x509.encode_csr", &tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s error = %v, want %q", tc.name, err, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// encode_private_key

func TestV2EncodePrivateKey(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := v2PKCS8PEM(t, rsaKey)
	pkcs1PEM := string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))
	pkcs8DER, _ := pem.Decode([]byte(pkcs8PEM))

	// PKCS#8 input re-encodes identically (v2 always PKCS#8)
	res, err := callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: pkcs8PEM})
	if err != nil {
		t.Fatal(err)
	}
	if res.(string) != pkcs8PEM {
		t.Fatalf("pkcs8 identity = %q", res.(string))
	}

	// PKCS#1 input is re-encoded as PKCS#8
	res, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: pkcs1PEM})
	if err != nil {
		t.Fatal(err)
	}
	if res.(string) != pkcs8PEM {
		t.Fatalf("pkcs1 -> pkcs8 = %q", res.(string))
	}

	// der/raw tails
	res, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: pkcs1PEM, Encoding: ps("der"), Raw: true})
	if err != nil || !bytes.Equal(res.([]byte), pkcs8DER.Bytes) {
		t.Fatalf("der raw = %v %v", res, err)
	}
	res, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: pkcs1PEM, Encoding: ps("der")})
	if err != nil || res.(string) != base64.StdEncoding.EncodeToString(pkcs8DER.Bytes) {
		t.Fatalf("der b64 = %v %v", res, err)
	}

	// EC (SEC1 container) and Ed25519 (PKCS#8 only)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	sec1PEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))
	res, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: sec1PEM})
	if err != nil {
		t.Fatal(err)
	}
	if res.(string) != v2PKCS8PEM(t, ecKey) {
		t.Fatal("ec sec1 -> pkcs8 mismatch")
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	res, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: v2PKCS8PEM(t, edPriv)})
	if err != nil {
		t.Fatal(err)
	}
	if res.(string) != v2PKCS8PEM(t, edPriv) {
		t.Fatal("ed25519 pkcs8 mismatch")
	}

	// encrypted legacy input decrypts with private_key_passphrase and
	// re-encodes unencrypted (pinned test_expires/encode behavior)
	encPEM := v2EncryptedKeyPEM(t, rsaKey, "hunter1")
	res, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: encPEM, PrivateKeyPassphrase: ps("hunter1")})
	if err != nil {
		t.Fatal(err)
	}
	if res.(string) != pkcs8PEM {
		t.Fatalf("encrypted -> pkcs8 = %q", res.(string))
	}

	// exact password error shapes
	_, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: encPEM})
	if err == nil || err.Error() != "Private key is encrypted. Please provide a password." {
		t.Fatalf("missing password = %v", err)
	}
	_, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: encPEM, PrivateKeyPassphrase: ps("wrong")})
	if err == nil || err.Error() != "Bad decrypt - is the password correct?" {
		t.Fatalf("bad password = %v", err)
	}
	_, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: pkcs8PEM, PrivateKeyPassphrase: ps("extra")})
	if err == nil || err.Error() != "Private key is unencrypted. Please remove the password." {
		t.Fatalf("superfluous password = %v", err)
	}

	// container boundaries
	_, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: pkcs8PEM, Passphrase: ps("hunter1")})
	if _, ok := err.(*runtime.UnsupportedError); !ok {
		t.Fatalf("best-available encryption = %v, want UnsupportedError", err)
	}
	_, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: pkcs8PEM, Encoding: ps("pkcs12")})
	if _, ok := err.(*runtime.UnsupportedError); !ok {
		t.Fatalf("pkcs12 = %v, want UnsupportedError", err)
	}
	_, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"})
	if _, ok := err.(*runtime.UnsupportedError); !ok {
		t.Fatalf("encrypted pkcs8 input = %v, want UnsupportedError", err)
	}

	// pinned validation and load errors
	_, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: pkcs8PEM, Encoding: ps("pemx")})
	if err == nil || err.Error() != "Invalid value 'pemx' for encoding. Valid: der, pem, pkcs12" {
		t.Fatalf("invalid encoding = %v", err)
	}
	_, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: "-----BEGIN PRIVATE KEY-----\nAAAA\n"})
	if err == nil || err.Error() != "Could not load PEM-encoded private key" {
		t.Fatalf("pem garbage = %v", err)
	}
	_, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: "not a certificate!"})
	if err == nil || err.Error() != couldNotLoadSource {
		t.Fatalf("unloadable = %v", err)
	}
	_, err = callX509(t, rt, "x509.encode_private_key",
		&encodePrivateKeyArgs{PrivateKey: "zzzz"})
	if err == nil || err.Error() != "Could not deserialize binary data, neither as DER nor PKCS#12." {
		t.Fatalf("der garbage = %v", err)
	}
}

// ---------------------------------------------------------------------------
// expires

func TestV2Expires(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	fresh := leafCertPEM(t, time.Now().UTC().Add(24*time.Hour))
	old := leafCertPEM(t, time.Date(2000, 1, 1, 13, 37, 42, 0, time.UTC))

	// days=0: fresh is not expiring, old is expired
	res, err := callX509(t, rt, "x509.expires", &expiresArgs{Certificate: fresh})
	if err != nil {
		t.Fatal(err)
	}
	if res.(bool) {
		t.Fatal("fresh cert expires() = true, want false")
	}
	res, err = callX509(t, rt, "x509.expires", &expiresArgs{Certificate: old})
	if err != nil {
		t.Fatal(err)
	}
	if !res.(bool) {
		t.Fatal("old cert expires() = false, want true")
	}

	// days=2 (pinned test_expires contract)
	res, err = callX509(t, rt, "x509.expires", &expiresArgs{Certificate: fresh, Days: pi(2)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.(bool) {
		t.Fatal("fresh cert expires(days=2) = false, want true")
	}

	// negative days shrinks the window
	res, err = callX509(t, rt, "x509.expires", &expiresArgs{Certificate: fresh, Days: pi(-3)})
	if err != nil {
		t.Fatal(err)
	}
	if res.(bool) {
		t.Fatal("fresh cert expires(days=-3) = true, want false")
	}

	// path input and load errors
	if werr := rt.FS.MkdirAll("/pki", 0o755); werr != nil {
		t.Fatal(werr)
	}
	if werr := rt.FS.WriteFile("/pki/fresh.crt", []byte(fresh), 0o644); werr != nil {
		t.Fatal(werr)
	}
	res, err = callX509(t, rt, "x509.expires", &expiresArgs{Certificate: "/pki/fresh.crt"})
	if err != nil || res.(bool) {
		t.Fatalf("path expires() = %v %v", res, err)
	}
	_, err = callX509(t, rt, "x509.expires", &expiresArgs{Certificate: "not a certificate!"})
	if err == nil || err.Error() != couldNotLoadSource {
		t.Fatalf("unloadable = %v", err)
	}
}

func leafCertPEM(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// ---------------------------------------------------------------------------
// read_crl

func TestV2ReadCrl(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	ca := newV2CA(t)
	crlPEM := v2CRLPEM(t, ca, []x509.RevocationListEntry{
		{
			SerialNumber:   big.NewInt(0x147947),
			RevocationTime: time.Date(2022, 11, 16, 3, 10, 8, 0, time.UTC),
			ReasonCode:     3,
		},
		{
			// no reason: Go omits the CRLReason extension for code 0
			SerialNumber:   big.NewInt(0xDEADBEEF),
			RevocationTime: time.Date(2022, 11, 16, 3, 11, 9, 0, time.UTC),
		},
	}, nil, x509.SHA256WithRSA)

	res, err := callX509(t, rt, "x509.read_crl", &readCrlArgs{Crl: crlPEM})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]any)

	wantIssuer := map[string]string{
		"C": "US", "O": "Salt", "OU": "Unit", "CN": "Test",
		"STREET": "123 Street", "MAIL": "ca@example.com", "UID": "cauid",
	}
	if issuer := got["issuer"].(map[string]string); !reflect.DeepEqual(issuer, wantIssuer) {
		t.Fatalf("issuer = %v", issuer)
	}
	if got["last_update"] != "2022-11-16 04:10:08" {
		t.Fatalf("last_update = %v", got["last_update"])
	}
	// 100 days after thisUpdate
	if got["next_update"] != "2023-02-24 04:10:08" {
		t.Fatalf("next_update = %v", got["next_update"])
	}
	if got["signature_algorithm"] != "sha256WithRSAEncryption" {
		t.Fatalf("signature_algorithm = %v", got["signature_algorithm"])
	}

	revoked := got["revoked_certificates"].(map[string]any)
	if len(revoked) != 2 {
		t.Fatalf("revoked = %v", revoked)
	}
	first, ok := revoked["147947"].(map[string]any)
	if !ok {
		t.Fatalf("revoked keys = %v", revoked)
	}
	if first["revocation_date"] != "2022-11-16 03:10:08" {
		t.Fatalf("revocation_date = %v", first["revocation_date"])
	}
	reasonExt, ok := first["extensions"].(map[string]any)["CRLReason"].(map[string]any)
	if !ok {
		t.Fatalf("CRLReason missing: %v", first["extensions"])
	}
	if reasonExt["critical"] != false || reasonExt["value"] != "affiliationChanged" {
		t.Fatalf("CRLReason = %v", reasonExt)
	}
	second, ok := revoked["DEADBEEF"].(map[string]any)
	if !ok {
		t.Fatalf("revoked keys = %v", revoked)
	}
	if len(second["extensions"].(map[string]any)) != 0 {
		t.Fatalf("no-reason extensions = %v", second["extensions"])
	}

	exts := got["extensions"].(map[string]any)
	aki, ok := exts["authorityKeyIdentifier"].(map[string]any)
	if !ok {
		t.Fatalf("extensions = %v", exts)
	}
	if aki["critical"] != false || aki["issuer"] != nil || aki["issuer_sn"] != nil {
		t.Fatalf("AKI = %v", aki)
	}
	if want := prettyHex(ca.cert.SubjectKeyId); aki["keyid"] != want {
		t.Fatalf("AKI keyid = %v, want %v", aki["keyid"], want)
	}
	crlNum, ok := exts["cRLNumber"].(map[string]any)
	if !ok || crlNum["critical"] != false || crlNum["value"] != 3 {
		t.Fatalf("cRLNumber = %v", exts["cRLNumber"])
	}

	// empty CRL and load errors
	empty := v2CRLPEM(t, ca, nil, nil, x509.SHA256WithRSA)
	res, err = callX509(t, rt, "x509.read_crl", &readCrlArgs{Crl: empty})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.(map[string]any)["revoked_certificates"].(map[string]any)) != 0 {
		t.Fatal("empty CRL revoked_certificates not empty")
	}
	_, err = callX509(t, rt, "x509.read_crl", &readCrlArgs{Crl: ca.certPEM})
	if err == nil || err.Error() != "Could not load PEM-encoded certificate revocation list." {
		t.Fatalf("wrong type = %v", err)
	}
}

// TestV2ReadCrlInjectedExtensions renders the CRL-profile extension
// families through ExtraExtensions on a signed CRL.
func TestV2ReadCrlInjectedExtensions(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	ca := newV2CA(t)

	gn := func(tag int, value string) []byte {
		return derEncode(2, tag, false, []byte(value))
	}
	gnIP := func(octets ...byte) []byte {
		return derEncode(2, 7, false, octets)
	}
	gnStream := func(members ...[]byte) []byte {
		var content []byte
		for _, m := range members {
			content = append(content, m...)
		}
		return content
	}
	// GeneralNames is a SEQUENCE OF GeneralName (extension values)
	generalNames := func(members ...[]byte) []byte {
		return derEncode(0, 16, true, gnStream(members...))
	}
	// fullName is the [0] IMPLICIT GeneralNames CHOICE; the
	// distributionPoint field wraps it [0] EXPLICIT
	dpName := func(members ...[]byte) []byte {
		return derEncode(2, 0, true, derEncode(2, 0, true, gnStream(members...)))
	}
	// IMPLICIT BIT STRING body: unused-bits octet + MSB-first bytes
	bitString := func(bits ...int) []byte {
		if len(bits) == 0 {
			return []byte{0, 0}
		}
		maxBit := 0
		for _, b := range bits {
			if b > maxBit {
				maxBit = b
			}
		}
		size := (maxBit + 8) / 8
		body := make([]byte, size)
		for _, b := range bits {
			body[b/8] |= 1 << (7 - b%8)
		}
		return append([]byte{byte(size*8 - (maxBit + 1))}, body...)
	}
	concat := func(parts ...[]byte) []byte {
		var out []byte
		for _, part := range parts {
			out = append(out, part...)
		}
		return out
	}
	accessDesc := func(method asn1.ObjectIdentifier, uri string) []byte {
		methodDER, merr := asn1.Marshal(method)
		if merr != nil {
			t.Fatal(merr)
		}
		return derEncode(0, 16, true, concat(methodDER, gn(6, uri)))
	}
	// fullName + onlySomeReasons + onlyContainsUserCerts + indirectCRL
	idpBody := concat(
		dpName(gn(2, "dp.example.com")),
		derEncode(2, 1, false, bitString(0, 4)),
		derEncode(2, 2, false, []byte{0xff}),
		derEncode(2, 5, false, []byte{0xff}))
	// SEQUENCE OF { DistributionPoint SEQUENCE { [0] name, [1] reasons, [2] issuer } }
	freshestBody := derEncode(0, 16, true, derEncode(0, 16, true, concat(
		dpName(gn(2, "fresh.example.com")),
		derEncode(2, 1, false, bitString(1, 3)),
		derEncode(2, 2, true, gnStream(gn(6, "http://fresh.example.com"))))))

	crlPEM := v2CRLPEM(t, ca, nil, []pkix.Extension{
		{Id: oidV2IssuerAltName, Value: generalNames(
			gn(2, "crl.example.com"), gn(1, "crl@example.com"),
			gn(6, "http://crl.example.com/x.crl"), gnIP(192, 0, 2, 1))},
		{Id: oidV2AIA, Value: derEncode(0, 16, true, concat(
			accessDesc(oidV2OCSP, "http://ocsp.example.com"),
			accessDesc(oidV2CAIssuers, "http://aia.example.com/ca.crt")))},
		{Id: oidV2IDP, Value: derEncode(0, 16, true, idpBody)},
		{Id: oidV2FreshestCRL, Value: freshestBody},
		{Id: oidV2DeltaCRL, Value: derEncode(0, 2, false, []byte{0x02})},
	}, x509.SHA256WithRSA)

	res, err := callX509(t, rt, "x509.read_crl", &readCrlArgs{Crl: crlPEM})
	if err != nil {
		t.Fatal(err)
	}
	exts := res.(map[string]any)["extensions"].(map[string]any)

	ian := exts["issuerAltName"].(map[string]any)
	if ian["critical"] != false {
		t.Fatalf("issuerAltName = %v", ian)
	}
	if !reflect.DeepEqual(ian["value"], []string{
		"DNS:crl.example.com", "mail:crl@example.com",
		"URI:http://crl.example.com/x.crl", "IP:192.0.2.1"}) {
		t.Fatalf("issuerAltName value = %v", ian["value"])
	}

	aia := exts["authorityInfoAccess"].(map[string]any)
	wantAIA := []map[string]string{
		{"OCSP": "URI:http://ocsp.example.com"},
		{"caIssuers": "URI:http://aia.example.com/ca.crt"},
	}
	if !reflect.DeepEqual(aia["value"], wantAIA) {
		t.Fatalf("AIA value = %#v", aia["value"])
	}

	idp := exts["issuingDistributionPoint"].(map[string]any)
	if idp["critical"] != false || idp["onlyuser"] != true || idp["onlyCA"] != false ||
		idp["onlyAA"] != false || idp["indirectCRL"] != true {
		t.Fatalf("IDP = %v", idp)
	}
	if !reflect.DeepEqual(idp["fullname"], []string{"DNS:dp.example.com"}) {
		t.Fatalf("IDP fullname = %v", idp["fullname"])
	}
	if !reflect.DeepEqual(idp["onysomereasons"], []string{"cessationOfOperation", "keyCompromise"}) {
		t.Fatalf("IDP onysomereasons = %v", idp["onysomereasons"])
	}

	freshest := exts["freshestCRL"].(map[string]any)
	dp := freshest["value"].([]map[string]any)[0]
	if !reflect.DeepEqual(dp["fullname"], []string{"DNS:fresh.example.com"}) ||
		!reflect.DeepEqual(dp["reasons"], []string{"cACompromise", "superseded"}) ||
		!reflect.DeepEqual(dp["crlissuer"], []string{"URI:http://fresh.example.com"}) ||
		dp["relativename"] != nil {
		t.Fatalf("freshestCRL dp = %v", dp)
	}

	delta := exts["deltaCRLIndicator"].(map[string]any)
	if delta["value"] != 2 {
		t.Fatalf("deltaCRLIndicator = %v", delta)
	}
}

// TestV2ReadCrlEntryExtensionRenderers covers the invalidityDate and
// certificateIssuer entry renderers with synthetic extension DER
// (Go's CRL builder cannot author them).
func TestV2ReadCrlEntryExtensionRenderers(t *testing.T) {
	name, value, err := renderV2CRLEntryExtension(pkix.Extension{
		Id:    oidV2InvalidityDate,
		Value: derEncode(0, 24, false, []byte("20130218102200Z")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if name != "invalidityDate" || value["critical"] != false ||
		value["value"] != "2013-02-18 10:22:00" {
		t.Fatalf("invalidityDate = %s %v", name, value)
	}

	name, value, err = renderV2CRLEntryExtension(pkix.Extension{
		Id:    oidV2CertIssuer,
		Value: derEncode(0, 16, true, derEncode(2, 2, false, []byte("issuer.example.com"))),
	})
	if err != nil {
		t.Fatal(err)
	}
	if name != "certificateIssuer" ||
		!reflect.DeepEqual(value["value"], []string{"DNS:issuer.example.com"}) {
		t.Fatalf("certificateIssuer = %s %v", name, value)
	}

	// unknown reason code and malformed values raise deterministically
	if _, _, err = renderV2CRLEntryExtension(pkix.Extension{
		Id: oidV2CRLReason, Value: derEncode(0, 10, false, []byte{7})}); err == nil {
		t.Fatal("reason 7 accepted")
	}
	if _, _, err = renderV2CRLEntryExtension(pkix.Extension{
		Id: oidV2CRLReason, Value: []byte{}}); err == nil {
		t.Fatal("empty CRLReason accepted")
	}
}

// TestV2ReadCrlCertProfileBoundary pins the deterministic profile
// error for certificate-profile extensions on a CRL.
func TestV2ReadCrlCertProfileBoundary(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	ca := newV2CA(t)
	crlPEM := v2CRLPEM(t, ca, nil, []pkix.Extension{
		{Id: oidBasicConstraints, Value: derEncode(0, 16, true, nil)},
	}, x509.SHA256WithRSA)
	_, err := callX509(t, rt, "x509.read_crl", &readCrlArgs{Crl: crlPEM})
	if err == nil || !strings.HasPrefix(err.Error(), "unsupported extension 2.5.29.19 on CRL") {
		t.Fatalf("cert-profile boundary = %v", err)
	}
}

// ---------------------------------------------------------------------------
// registry / CLI / hygiene

func TestV2RegistryCallPaths(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	ca := newV2CA(t)
	crlPEM := v2CRLPEM(t, ca, nil, nil, x509.SHA256WithRSA)

	if _, err := rt.Exec.Call(context.Background(), rt, "x509.encode_crl",
		&encodeCrlArgs{Crl: crlPEM}); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Exec.Call(context.Background(), rt, "x509.read_crl",
		&readCrlArgs{Crl: crlPEM}); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Exec.Call(context.Background(), rt, "x509.encode_certificate",
		&encodeCertificateArgs{Certificate: ca.certPEM, Encoding: ps("zzz")}); err == nil ||
		err.Error() != "Invalid value 'zzz' for encoding. Valid: der, pem, pkcs7_der, pkcs7_pem, pkcs12" {
		t.Fatalf("registry encode_certificate error = %v", err)
	}
}

func TestV2CLISurface(t *testing.T) {
	ca := newV2CA(t)
	crlPEM := v2CRLPEM(t, ca, []x509.RevocationListEntry{{
		SerialNumber:   big.NewInt(1),
		RevocationTime: time.Date(2022, 11, 16, 3, 10, 8, 0, time.UTC),
		ReasonCode:     1,
	}}, nil, x509.SHA256WithRSA)
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
	if err := rt.FS.WriteFile("/pki/ca.crt", []byte(ca.certPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/pki/ca.crl", []byte(crlPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	app := cli.NewApp("test", func() (*runtime.Runtime, error) { return rt, nil })

	if code := app.Run([]string{"exec", "x509.encode_certificate",
		"--certificate", "/pki/ca.crt", "-o", "json"}); code != 0 {
		t.Fatalf("encode_certificate exit = %d", code)
	}
	if code := app.Run([]string{"exec", "x509.encode_certificate",
		"--certificate", "/pki/ca.crt", "--encoding", "der", "-o", "json"}); code != 0 {
		t.Fatalf("encode_certificate der exit = %d", code)
	}
	if code := app.Run([]string{"exec", "x509.encode_crl",
		"--crl", "/pki/ca.crl", "-o", "json"}); code != 0 {
		t.Fatalf("encode_crl exit = %d", code)
	}
	if code := app.Run([]string{"exec", "x509.read_crl",
		"--crl", "/pki/ca.crl", "-o", "json"}); code != 0 {
		t.Fatalf("read_crl exit = %d", code)
	}
	if code := app.Run([]string{"exec", "x509.expires",
		"--certificate", "/pki/ca.crt", "--days", "2", "-o", "json"}); code != 0 {
		t.Fatalf("expires exit = %d", code)
	}
	if code := app.Run([]string{"exec", "x509.encode_certificate"}); code != 2 {
		t.Fatalf("missing required exit = %d, want 2", code)
	}
	if code := app.Run([]string{"exec", "x509.encode_certificate",
		"--certificate", "/pki/ca.crt", "--encoding", "pkcs12"}); code != 1 {
		t.Fatalf("pkcs12 validation exit = %d, want 1", code)
	}
}

func TestV2NoRunnerNoMutation(t *testing.T) {
	ca := newV2CA(t)
	crlPEM := v2CRLPEM(t, ca, nil, nil, x509.SHA256WithRSA)
	csrPEM, _ := v2CsrPEM(t)
	keyPEM := v2PKCS8PEM(t, ca.key)
	rt, runner := x509RT(t, map[string]string{
		"/pki/ca.crt":  ca.certPEM,
		"/pki/ca.crl":  crlPEM,
		"/pki/req.csr": csrPEM,
		"/pki/ca.key":  keyPEM,
	}, nil)

	calls := []struct {
		name string
		args any
	}{
		{"x509.encode_certificate", &encodeCertificateArgs{Certificate: "/pki/ca.crt"}},
		{"x509.encode_certificate", &encodeCertificateArgs{
			Certificate: "/pki/ca.crt", AppendCerts: []string{"/pki/ca.crt"}}},
		{"x509.encode_crl", &encodeCrlArgs{Crl: "/pki/ca.crl", Encoding: ps("der"), Raw: true}},
		{"x509.encode_csr", &encodeCsrArgs{Csr: "/pki/req.csr", Encoding: ps("der")}},
		{"x509.encode_private_key", &encodePrivateKeyArgs{PrivateKey: "/pki/ca.key"}},
		{"x509.expires", &expiresArgs{Certificate: "/pki/ca.crt", Days: pi(30)}},
		{"x509.read_crl", &readCrlArgs{Crl: "/pki/ca.crl"}},
	}
	for _, call := range calls {
		if _, err := callX509(t, rt, call.name, call.args); err != nil {
			t.Fatalf("%s: %v", call.name, err)
		}
	}
	if runner.calls != 0 {
		t.Fatalf("runner spawned %d processes", runner.calls)
	}
	for path, want := range map[string]string{
		"/pki/ca.crt":  ca.certPEM,
		"/pki/ca.crl":  crlPEM,
		"/pki/req.csr": csrPEM,
		"/pki/ca.key":  keyPEM,
	} {
		got, err := rt.FS.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("%s mutated: %v", path, err)
		}
	}
	if entries, err := rt.FS.ReadDir("/pki"); err != nil || len(entries) != 4 {
		t.Fatalf("unexpected directory writes: %v %v", entries, err)
	}
}

func TestV2InputBoundsAndSymlinks(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	if werr := rt.FS.MkdirAll("/pki", 0o755); werr != nil {
		t.Fatal(werr)
	}
	// oversized file input exceeds the bounded reader
	big := strings.Repeat("A", int(maxPEMBytes)+2)
	payload := "-----BEGIN CERTIFICATE-----\n" + big + "\n-----END CERTIFICATE-----\n"
	if werr := rt.FS.WriteFile("/pki/huge.crt", []byte(payload), 0o644); werr != nil {
		t.Fatal(werr)
	}
	for _, call := range []struct {
		name string
		args any
	}{
		{"x509.encode_certificate", &encodeCertificateArgs{Certificate: "/pki/huge.crt"}},
		{"x509.encode_crl", &encodeCrlArgs{Crl: "/pki/huge.crt"}},
		{"x509.encode_csr", &encodeCsrArgs{Csr: "/pki/huge.crt"}},
		{"x509.encode_private_key", &encodePrivateKeyArgs{PrivateKey: "/pki/huge.crt"}},
		{"x509.expires", &expiresArgs{Certificate: "/pki/huge.crt"}},
		{"x509.read_crl", &readCrlArgs{Crl: "/pki/huge.crt"}},
	} {
		_, err := callX509(t, rt, call.name, call.args)
		if err == nil || !strings.Contains(err.Error(), "read limit") {
			t.Fatalf("%s oversized read error = %v", call.name, err)
		}
	}

	// symlinked input is rejected by the bounded reader (the path
	// falls through to the string branch and raises the loader error)
	if werr := rt.FS.WriteFile("/pki/real.crt", []byte(newV2CA(t).certPEM), 0o644); werr != nil {
		t.Fatal(werr)
	}
	if serr := rt.FS.Symlink("/pki/real.crt", "/pki/link.crt"); serr != nil {
		t.Fatal(serr)
	}
	if _, err := callX509(t, rt, "x509.encode_certificate",
		&encodeCertificateArgs{Certificate: "/pki/link.crt"}); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestV2GeneralNameEdgeShapes(t *testing.T) {
	// RegisteredID and DirectoryName general names
	cnOID, merr := asn1.Marshal(asn1.ObjectIdentifier{2, 5, 4, 3})
	if merr != nil {
		t.Fatal(merr)
	}
	dirDER := derEncode(0, 16, true, derEncode(0, 17, true, derEncode(0, 16, true, append(
		cnOID, derEncode(0, 12, false, []byte("Dir CA"))...))))
	gn, err := renderV2GeneralName(derTLV{
		id: 0x88, content: []byte{0x2a, 0x03, 0x04},
	})
	if err != nil || gn != "RID:1.2.3.4" {
		t.Fatalf("RID = %q %v", gn, err)
	}
	gn, err = renderV2GeneralName(derTLV{id: 0x84, content: dirDER})
	if err != nil || gn != "dirName:CN=Dir CA" {
		t.Fatalf("dirName = %q %v", gn, err)
	}
	// IPv6 exploded form
	gn, err = renderV2GeneralName(derTLV{
		id:      0x87,
		content: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	})
	if err != nil || gn != "IP:2001:db8:0:0:0:0:0:1" {
		t.Fatalf("ipv6 = %q %v", gn, err)
	}
	// unsupported CHOICE tag raises the profile error
	if _, err = renderV2GeneralName(derTLV{id: 0xa0, content: []byte{}}); err == nil {
		t.Fatal("otherName accepted")
	}
	if _, ok := err.(*invocationErr); !ok {
		t.Fatalf("otherName error type = %T", err)
	}
}

func TestV2SigAlgFallbacks(t *testing.T) {
	rt, _ := x509RT(t, nil, nil)
	// SHA-1 signed CRL names sha1WithRSAEncryption
	ca := newV2CA(t)
	crlPEM := v2CRLPEM(t, ca, nil, nil, x509.SHA1WithRSA)
	res, err := callX509(t, rt, "x509.read_crl", &readCrlArgs{Crl: crlPEM})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["signature_algorithm"] != "sha1WithRSAEncryption" {
		t.Fatalf("sha1 name = %v", res.(map[string]any)["signature_algorithm"])
	}
	// unknown OID falls back to the dotted string
	if name := v2SignatureAlgorithmName(&x509.RevocationList{Raw: []byte{0x30, 0x03, 0x02, 0x01, 0x00}}); name == "" {
		t.Fatal("dotted fallback empty")
	}
	if oid, ok := crlSigAlgOID([]byte{0x30, 0x03, 0x02, 0x01, 0x00}); ok {
		t.Fatalf("garbage raw crl oid = %v", oid)
	}
	if _, ok := pyHexDecode("zz"); ok {
		t.Fatal("pyHexDecode accepted non-hex")
	}
	if dec, ok := pyB64Decode("!!!!"); !ok || len(dec) != 0 {
		t.Fatal("pyB64Decode did not mirror the discard-then-decode default")
	}
	if _, ok := pyB64Decode("abc"); ok {
		t.Fatal("pyB64Decode accepted bad padding")
	}
	if _, ok := pyHexDecode("de ad be ef 42"); !ok {
		t.Fatal("pyHexDecode rejected whitespace hex")
	}
	if dec, ok := pyB64Decode("Zm9vYmFy"); !ok || string(dec) != "foobar" {
		t.Fatal("pyB64Decode rejected valid base64")
	}
}
