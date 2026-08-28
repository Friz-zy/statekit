package tls

// R5.8 tests for the tls family, mapped onto the source contracts of
// saltstack/salt/modules/tls.py and the behaviors pinned by
// tests/pytests/unit/modules/test_tls.py @ pinned revision. The
// upstream fixture CA certificate pins OpenSSL-computed golden values
// (fingerprint, serial, epoch dates, signature algorithm).

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const fixtureCA = `-----BEGIN CERTIFICATE-----
MIIEejCCA2KgAwIBAgIRANW6IUG5rMez0vPi3cSmS3QwDQYJKoZIhvcNAQELBQAw
eTELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxFzAVBgNVBAcMDlNhbHQgTGFr
ZSBDaXR5MRIwEAYDVQQKDAlTYWx0U3RhY2sxEjAQBgNVBAMMCWxvY2FsaG9zdDEa
MBgGCSqGSIb3DQEJARYLeHl6QHBkcS5uZXQwHhcNMTUwNTA1MTYzOTIxWhcNMTYw
NTA0MTYzOTIxWjB5MQswCQYDVQQGEwJVUzENMAsGA1UECAwEVXRhaDEXMBUGA1UE
BwwOU2FsdCBMYWtlIENpdHkxEjAQBgNVBAoMCVNhbHRTdGFjazESMBAGA1UEAwwJ
bG9jYWxob3N0MRowGAYJKoZIhvcNAQkBFgt4eXpAcGRxLm5ldDCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMNvHc8LwpI5/NiwRTWYG34WQ5vau8gkj+8p
5KehXDNmDcCY8QW9xNaCxY6Atg2Dwh5vEacubKRcnQL9SFKYHa4ddtnkISzSkdZN
ImY7ZVQteDIVNJmy7DrZ4RvWTr2ezXYLv8oNkqrKhynt5xIBXZWslWUav1pOp8z8
N+LeXaASVyajqB5TiN8HJR/up9MlSfy/zhtm6x6SIUsEZa+zK7m06/Glrr4WZFOV
LbOwxl36JpjywWTNcrXJd052U/377tUATXpepALBUUOIvWeGF7mrSTZkdhqRZRTe
Jr2+48zIuyMeB+JlY4UpR04pQNqstHimkyjxFfN/TKFqlhYqYjkCAwEAAaOB/DCB
+TASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU
WBvk3qjnltkxKtEQxqYn5+KwYWkwgbMGA1UdIwSBqzCBqIAUWBvk3qjnltkxKtEQ
xqYn5+KwYWmhfaR7MHkxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARVdGFoMRcwFQYD
VQQHDA5TYWx0IExha2UgQ2l0eTESMBAGA1UECgwJU2FsdFN0YWNrMRIwEAYDVQQD
DAlsb2NhbGhvc3QxGjAYBgkqhkiG9w0BCQEWC3h5ekBwZHEubmV0ghEA1bohQbms
x7PS8+LdxKZLdDANBgkqhkiG9w0BAQsFAAOCAQEALe312Oe8e+VjhnItcjQFuwcP
TaLf3+DTWaQLU1C8H78E75WE9UiRiVCyTpOLt/nONFkIKE275nCLPGCXn5JTZYVB
CxGFTRqnQ+8bdhZA6LYQPXieGikjTy+P2oiKOvPnYsATUXLbZ3ee+zEgBFGbbxNX
Argd3Vahg7Onu3ynsJz9a+hmwVqTX70Ykrrm+b/YtwKPfHeXTMxkX23jc4R7D+ED
VvROFJ27hFPLVaJrsq3EHb8ZkQHmRCzK2sMIPyJb2e0BOKDEZEphNxiIjerDnH7n
xDSMW0jK9FEv/W/sSBwoEolh3Q2e0gfd2vo7bEGvNF4eTqFsoAfeiAjWk65q0Q==
-----END CERTIFICATE-----`

// ---------------------------------------------------------------------------
// harness

type tlsRunner struct{ retcode int }

func (r *tlsRunner) Run(_ context.Context, _ process.Command) process.CommandResult {
	return process.CommandResult{ExitCode: r.retcode}
}

type cfgStubT struct {
	fallback any
	values   map[string]any
}

func (cfgStubT) Name() string { return "config.option" }
func (cfgStubT) Args() any    { return struct{}{} }
func (s cfgStubT) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	key := ""
	if m, ok := args.(map[string]any); ok {
		if k, ok2 := m["key"].(string); ok2 {
			key = k
		}
	}
	if v, ok := s.values[key]; ok {
		return v, nil
	}
	return s.fallback, nil
}

type pillarStubT struct{ values map[string]any }

func (pillarStubT) Name() string { return "pillar.get" }
func (pillarStubT) Args() any    { return struct{}{} }
func (s pillarStubT) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	key := ""
	if m, ok := args.(map[string]any); ok {
		if k, ok2 := m["key"].(string); ok2 {
			key = k
		}
	}
	if v, ok := s.values[key]; ok {
		return v, nil
	}
	return false, nil
}

func resetTLSContext() {
	contextMu.Lock()
	contextState = map[string]any{}
	contextMu.Unlock()
}

func callTLS[T any](t *testing.T, rt *runtime.Runtime, name string, args T) (any, error) {
	t.Helper()
	fn, ok := rt.Exec.Get(name)
	if !ok {
		t.Fatalf("%s not registered", name)
	}
	return fn.Execute(context.Background(), rt, args)
}

func tlsRT(t *testing.T, base string) *runtime.Runtime {
	t.Helper()
	return tlsRTCfg(t, base, nil)
}

func tlsRTCfg(t *testing.T, base string, cfg map[string]any) *runtime.Runtime {
	t.Helper()
	resetTLSContext()
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(cfgStubT{fallback: base, values: cfg}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(pillarStubT{}); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{
		Exec:    reg,
		States:  runtime.NewStateRegistry(),
		FS:      runtime.NewMemoryFS(),
		Runner:  &tlsRunner{},
		Options: runtime.RuntimeOptions{},
	}
	t.Cleanup(resetTLSContext)
	return rt
}

func mustCreateCA(t *testing.T, rt *runtime.Runtime, caName string) string {
	t.Helper()
	res, err := callTLS(t, rt, "tls.create_ca", &createCaArgs{
		CaName: caName, OU: ps("Test Unit"), EmailAddress: ps("xyz@pdq.net"),
	})
	if err != nil {
		t.Fatalf("create_ca: %v", err)
	}
	msg, _ := res.(string)
	return msg
}

func ps(s string) *string { return &s }

func pb(b bool) *bool { return &b }

func pi(i int) *int { return &i }

func statMode(t *testing.T, rt *runtime.Runtime, path string) uint32 {
	t.Helper()
	info, err := rt.FS.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return uint32(info.Mode().Perm())
}

// ---------------------------------------------------------------------------
// cert_base_path / set_ca_path (upstream parametrize tables)

func TestCertBasePathResolution(t *testing.T) {
	cases := []struct {
		expect string
		arg    *string
		cfg    map[string]any
	}{
		{"fnord", ps("fnord"), nil},
		{"", ps(""), nil},
		{"fnord", ps("fnord"), map[string]any{
			"ca.contextual_cert_base_path": "not fnord",
			"ca.cert_base_path":            "also not fnord",
		}},
		{"pick me", nil, map[string]any{
			"ca.contextual_cert_base_path": "pick me",
			"ca.cert_base_path":            "also not fnord",
		}},
		{"now pick me!", nil, map[string]any{
			"ca.contextual_cert_base_path": "",
			"ca.cert_base_path":            "now pick me!",
		}},
		{"me three", nil, map[string]any{"ca.cert_base_path": "me three"}},
	}
	for _, tc := range cases {
		resetTLSContext()
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		if err := reg.Register(cfgStubT{values: tc.cfg}); err != nil {
			t.Fatal(err)
		}
		rt := &runtime.Runtime{Exec: reg, FS: runtime.NewMemoryFS()}
		res, err := callTLS(t, rt, "tls.cert_base_path", &certBasePathArgs{CacertPath: tc.arg})
		if err != nil {
			t.Fatalf("cert_base_path(%v): %v", tc.arg, err)
		}
		if got, _ := res.(string); got != tc.expect {
			t.Errorf("cert_base_path(%v) = %q, want %q", tc.arg, got, tc.expect)
		}
	}
	resetTLSContext()
}

func TestCertBasePathNoneWithoutConfig(t *testing.T) {
	resetTLSContext()
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(cfgStubT{}); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{Exec: reg, FS: runtime.NewMemoryFS()}
	res, err := callTLS(t, rt, "tls.cert_base_path", &certBasePathArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		t.Fatalf("expected nil base path, got %v", res)
	}
}

func TestSetCaPath(t *testing.T) {
	cases := []struct {
		expect  string
		newPath *string
		cfg     map[string]any
	}{
		{"", nil, map[string]any{}},
		{"fnord", nil, map[string]any{"ca.cert_base_path": "fnord"}},
		{"fnord", nil, map[string]any{
			"ca.contextual_cert_base_path": "fnord",
			"ca.cert_base_path":            "not fnord",
		}},
		{"fnord", ps("fnord"), map[string]any{
			"ca.contextual_cert_base_path": "not fnord",
			"ca.cert_base_path":            "not fnord",
		}},
	}
	for _, tc := range cases {
		resetTLSContext()
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		if err := reg.Register(cfgStubT{values: tc.cfg}); err != nil {
			t.Fatal(err)
		}
		rt := &runtime.Runtime{Exec: reg, FS: runtime.NewMemoryFS()}
		if _, err := callTLS(t, rt, "tls.set_ca_path", &setCAPathArgs{CacertPath: tc.newPath}); err != nil {
			t.Fatal(err)
		}
		res, err := callTLS(t, rt, "tls.cert_base_path", &certBasePathArgs{})
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := res.(string); got != tc.expect {
			t.Errorf("set_ca_path(%v) -> %q, want %q", tc.newPath, got, tc.expect)
		}
	}
	resetTLSContext()
}

// ---------------------------------------------------------------------------
// ca_exists / get_ca family

func TestRawVersionOnOwnCA(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)
	mustCreateCA(t, rt, "test_ca")
	pemData, err := rt.FS.ReadFile(base + "/test_ca/test_ca_ca_cert.crt")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	v, verr := rawVersion(block.Bytes)
	if verr != nil || v != 2 {
		t.Fatalf("rawVersion = %d err=%v", v, verr)
	}
}

func TestCaExists(t *testing.T) {
	rt := tlsRT(t, "/tmp/tls-a")
	res, err := callTLS(t, rt, "tls.ca_exists", &caExistsArgs{CaName: "test_ca"})
	if err != nil {
		t.Fatal(err)
	}
	if res != false {
		t.Fatalf("expected false, got %v", res)
	}
	mustCreateCA(t, rt, "test_ca")
	res, err = callTLS(t, rt, "tls.ca_exists", &caExistsArgs{CaName: "test_ca"})
	if err != nil {
		t.Fatal(err)
	}
	if res != true {
		t.Fatalf("expected true, got %v", res)
	}
}

func TestGetCaFailPathAndText(t *testing.T) {
	base := "/tmp/tls-b"
	rt := tlsRT(t, base)
	_, err := callTLS(t, rt, "tls.get_ca", &getCaArgs{CaName: "test_ca"})
	if err == nil || !strings.Contains(err.Error(), "Certificate does not exist for test_ca") {
		t.Fatalf("expected ValueError reply, got %v", err)
	}
	mustCreateCA(t, rt, "test_ca")
	res, err := callTLS(t, rt, "tls.get_ca", &getCaArgs{CaName: "test_ca"})
	if err != nil {
		t.Fatal(err)
	}
	if res != base+"/test_ca/test_ca_ca_cert.crt" {
		t.Fatalf("path = %v", res)
	}
	res, err = callTLS(t, rt, "tls.get_ca", &getCaArgs{CaName: "test_ca", AsText: true})
	if err != nil {
		t.Fatal(err)
	}
	text, _ := res.(string)
	if !strings.Contains(text, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("as_text returned no PEM: %.40s", text)
	}
}

func TestGetCaSignedCertAndKey(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)
	cn := "www.example.com"

	_, err := callTLS(t, rt, "tls.get_ca_signed_cert",
		&getCaSignedCertArgs{CaName: "ca1", CN: ps(cn)})
	if err == nil || !strings.Contains(err.Error(), "Certificate does not exists for "+cn) {
		t.Fatalf("expected typo reply, got %v", err)
	}

	mustCreateCA(t, rt, "ca1")
	if _, err := callTLS(t, rt, "tls.create_csr", &createCsrArgs{CaName: "ca1", CN: ps(cn)}); err != nil {
		t.Fatal(err)
	}
	if _, err := callTLS(t, rt, "tls.create_ca_signed_cert",
		&createCaSignedArgs{CaName: "ca1", CN: cn}); err != nil {
		t.Fatal(err)
	}
	res, err := callTLS(t, rt, "tls.get_ca_signed_cert",
		&getCaSignedCertArgs{CaName: "ca1", CN: ps(cn)})
	if err != nil {
		t.Fatal(err)
	}
	if res != base+"/ca1/certs/"+cn+".crt" {
		t.Fatalf("cert path = %v", res)
	}
	res, err = callTLS(t, rt, "tls.get_ca_signed_key",
		&getCaSignedKeyArgs{CaName: "ca1", CN: ps(cn)})
	if err != nil {
		t.Fatal(err)
	}
	if res != base+"/ca1/certs/"+cn+".key" {
		t.Fatalf("key path = %v", res)
	}
}

// ---------------------------------------------------------------------------
// fixture-driven readers

func TestGetExpirationDateFixture(t *testing.T) {
	rt := tlsRT(t, "/tmp/unused")
	res, err := callTLS(t, rt, "tls.get_expiration_date",
		&getExpirationDateArgs{Cert: fixtureCA})
	if err != nil {
		t.Fatal(err)
	}
	if res != "2016-05-04" {
		t.Fatalf("expiration = %v", res)
	}
	res, err = callTLS(t, rt, "tls.get_expiration_date",
		&getExpirationDateArgs{Cert: fixtureCA, DateFormat: ps("%d/%m/%Y")})
	if err != nil {
		t.Fatal(err)
	}
	if res != "04/05/2016" {
		t.Fatalf("custom format = %v", res)
	}
}

func TestGetExpirationDateMissing(t *testing.T) {
	rt := tlsRT(t, "/tmp/unused")
	_, err := callTLS(t, rt, "tls.get_expiration_date",
		&getExpirationDateArgs{Cert: "/nonexistent.crt"})
	if err == nil || !strings.Contains(err.Error(),
		"Failed to read cert from /nonexistent.crt, see log for details") {
		t.Fatalf("expected CommandExecutionError text, got %v", err)
	}
}

func TestCertInfoFixture(t *testing.T) {
	rt := tlsRT(t, "/tmp/unused")
	res, err := callTLS(t, rt, "tls.cert_info", &certInfoArgs{Cert: fixtureCA})
	if err != nil {
		t.Fatal(err)
	}
	info, _ := res.(map[string]any)

	if got := info["fingerprint"]; got != "96:72:B3:0A:1D:34:37:05:75:57:44:7E:08:81:A7:09:0C:E1:8F:5F:4D:0C:49:CE:5B:D2:6B:45:D3:4D:FF:31" {
		t.Fatalf("fingerprint = %v", got)
	}
	serial, ok := info["serial_number"].(*big.Int)
	if !ok {
		t.Fatalf("serial type %T", info["serial_number"])
	}
	wantSerial := new(big.Int)
	wantSerial.SetString("284092004844685647925744086791559203700", 10)
	if serial.Cmp(wantSerial) != 0 {
		t.Fatalf("serial = %v", serial)
	}
	if info["not_before"] != int64(1430843961) {
		t.Fatalf("not_before = %v", info["not_before"])
	}
	if info["not_after"] != int64(1462379961) {
		t.Fatalf("not_after = %v", info["not_after"])
	}
	if got := info["signature_algorithm"]; got != "sha256WithRSAEncryption" {
		t.Fatalf("signature_algorithm = %v", got)
	}
	wantSubject := map[string]string{
		"C": "US", "CN": "localhost", "L": "Salt Lake City",
		"O": "SaltStack", "ST": "Utah", "emailAddress": "xyz@pdq.net",
	}
	subject, _ := info["subject"].(map[string]string)
	if fmt.Sprint(subject) != fmt.Sprint(wantSubject) {
		t.Fatalf("subject = %v", subject)
	}
	issuer, _ := info["issuer"].(map[string]string)
	if fmt.Sprint(issuer) != fmt.Sprint(wantSubject) {
		t.Fatalf("issuer = %v", issuer)
	}
	exts, _ := info["extensions"].(map[string]string)
	if exts["basicConstraints"] != "CA:TRUE, pathlen:0" {
		t.Fatalf("basicConstraints = %v", exts["basicConstraints"])
	}
	for _, name := range []string{"keyUsage", "subjectKeyIdentifier", "authorityKeyIdentifier"} {
		if _, ok := exts[name]; !ok {
			t.Fatalf("extension %s missing from %v", name, exts)
		}
	}
}

// ---------------------------------------------------------------------------
// get_extensions

func TestGetExtensionsProfiles(t *testing.T) {
	rt := tlsRT(t, "/tmp/unused")
	res, err := callTLS(t, rt, "tls.get_extensions", &getExtensionsArgs{CertType: "server"})
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := res.(map[string]map[string]string)
	if profile["csr"]["basicConstraints"] != "CA:FALSE" ||
		profile["csr"]["extendedKeyUsage"] != "serverAuth" ||
		profile["csr"]["keyUsage"] != "digitalSignature, keyEncipherment" {
		t.Fatalf("server profile = %v", profile)
	}
	if profile["cert"]["authorityKeyIdentifier"] != "keyid,issuer:always" ||
		profile["cert"]["subjectKeyIdentifier"] != "hash" {
		t.Fatalf("cert profile = %v", profile)
	}

	res, err = callTLS(t, rt, "tls.get_extensions", &getExtensionsArgs{CertType: "client"})
	if err != nil {
		t.Fatal(err)
	}
	profile, _ = res.(map[string]map[string]string)
	if profile["csr"]["extendedKeyUsage"] != "clientAuth" ||
		profile["csr"]["keyUsage"] != "nonRepudiation, digitalSignature, keyEncipherment" {
		t.Fatalf("client profile = %v", profile)
	}

	// empty cert_type falls back to server
	res, err = callTLS(t, rt, "tls.get_extensions", &getExtensionsArgs{CertType: ""})
	if err != nil {
		t.Fatal(err)
	}
	profile, _ = res.(map[string]map[string]string)
	if profile["csr"]["extendedKeyUsage"] != "serverAuth" {
		t.Fatalf("empty cert_type profile = %v", profile)
	}

	// unknown profile without pillar surfaces the KeyError upstream
	// raises through the merge
	_, err = callTLS(t, rt, "tls.get_extensions", &getExtensionsArgs{CertType: "fnord"})
	if err == nil || !strings.Contains(err.Error(), "KeyError: 'fnord'") {
		t.Fatalf("expected KeyError for unknown profile, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// create_ca

func TestCreateCAFilesMessageAndDatabase(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)
	msg := mustCreateCA(t, rt, "test_ca")

	certk := base + "/test_ca/test_ca_ca_cert.key"
	certp := base + "/test_ca/test_ca_ca_cert.crt"
	want := fmt.Sprintf("Created Private Key: %q ", certk) +
		fmt.Sprintf("Created CA %q: %q", "test_ca", certp)
	if msg != want {
		t.Fatalf("message =\n  %s\nwant\n  %s", msg, want)
	}
	if m := statMode(t, rt, certp); m != 0o644 {
		t.Fatalf("cert mode = %o", m)
	}
	if m := statMode(t, rt, certk); m != 0o600 {
		t.Fatalf("key mode = %o", m)
	}

	pemData, err := rt.FS.ReadFile(certp)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.IsCA || cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Fatalf("CA constraints wrong: isCA=%v pathlen=%v/%v",
			cert.IsCA, cert.MaxPathLen, cert.MaxPathLenZero)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 || cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Fatalf("keyUsage = %v", cert.KeyUsage)
	}
	// wire order follows upstream's set order
	wantOrder := []string{"C", "ST", "L", "O", "OU", "CN", "emailAddress"}
	values, err := subjectValues(cert.RawSubject)
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range wantOrder {
		if i >= len(values) || values[i].Short != name {
			t.Fatalf("subject order = %v", values)
		}
	}

	index, err := rt.FS.ReadFile(base + "/test_ca/index.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(index), "V\t") {
		t.Fatalf("index = %q", string(index))
	}
	if !strings.Contains(string(index),
		"\tunknown\t/C=US/ST=Utah/L=Salt Lake City/O=SaltStack/OU=Test Unit/CN=localhost/emailAddress=xyz@pdq.net\n") {
		t.Fatalf("index = %q", string(index))
	}
	// serial counter lands in the resolved cachedir (the stub answers
	// the config fallback for every key)
	if _, err := rt.FS.Stat(base + "/test_ca.serial"); err != nil {
		t.Fatalf("serial file: %v", err)
	}
}

func TestCreateCAAlreadyExistsAndReplace(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)
	mustCreateCA(t, rt, "test_ca")

	res, err := callTLS(t, rt, "tls.create_ca", &createCaArgs{CaName: "test_ca"})
	if err != nil {
		t.Fatal(err)
	}
	if res != `Certificate for CA named "test_ca" already exists` {
		t.Fatalf("already exists = %v", res)
	}

	replace := true
	res, err = callTLS(t, rt, "tls.create_ca",
		&createCaArgs{CaName: "test_ca", Replace: &replace})
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := res.(string)
	if !strings.Contains(msg, `Created CA "test_ca"`) {
		t.Fatalf("replace message = %v", msg)
	}
}

func TestCreateCAOnlyifUnless(t *testing.T) {
	base := t.TempDir()

	mkRT := func(retcode int) *runtime.Runtime {
		resetTLSContext()
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		if err := reg.Register(cfgStubT{fallback: base}); err != nil {
			t.Fatal(err)
		}
		return &runtime.Runtime{
			Exec:   reg,
			FS:     runtime.NewMemoryFS(),
			Runner: &tlsRunner{retcode: retcode},
		}
	}

	// onlyif string condition with non-zero retcode short-circuits
	rt := mkRT(1)
	res, err := callTLS(t, rt, "tls.create_ca",
		&createCaArgs{CaName: "test_ca", Onlyif: "false-test"})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		t.Fatalf("onlyif short-circuit: %v", res)
	}

	// falsy non-string onlyif (empty list) short-circuits
	res, err = callTLS(t, rt, "tls.create_ca",
		&createCaArgs{CaName: "test_ca", Onlyif: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		t.Fatalf("onlyif truthiness: %v", res)
	}

	// zero-retcode onlyif proceeds with creation
	rt = mkRT(0)
	if res, err = callTLS(t, rt, "tls.create_ca",
		&createCaArgs{CaName: "test_ca", Onlyif: "true-test"}); err != nil {
		t.Fatal(err)
	}
	if res == nil {
		t.Fatal("onlyif with retcode 0 must not short-circuit")
	}

	// unless string condition with zero retcode short-circuits
	rt = mkRT(0)
	if res, err = callTLS(t, rt, "tls.create_ca",
		&createCaArgs{CaName: "test_ca2", Unless: "true-test"}); err != nil {
		t.Fatal(err)
	}
	if res != nil {
		t.Fatalf("unless short-circuit: %v", res)
	}

	// falsy non-string unless proceeds
	rt = mkRT(0)
	if res, err = callTLS(t, rt, "tls.create_ca",
		&createCaArgs{CaName: "test_ca3", Unless: []string{}}); err != nil {
		t.Fatal(err)
	}
	if res == nil {
		t.Fatal("falsy unless must not short-circuit")
	}
}

func TestCreateCAKeyReuseAndUnloadable(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)
	mustCreateCA(t, rt, "test_ca")

	// identical-key rewrite skips and no unloadable/backup appears
	entries, err := rt.FS.ReadDir(base + "/test_ca")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.Contains(name, "unloadable") || isTSBackup(name, "test_ca_ca_cert.key.") {
			t.Fatalf("unexpected backup %s", name)
		}
	}

	// a corrupt key moves aside under the .unloadable suffix
	ca2 := base + "/koji"
	if err := rt.FS.MkdirAll(ca2, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile(ca2+"/koji_ca_cert.key", []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := callTLS(t, rt, "tls.create_ca", &createCaArgs{CaName: "koji"}); err != nil {
		t.Fatal(err)
	}
	found := false
	names, _ := rt.FS.ReadDir(ca2)
	for _, e := range names {
		if strings.HasPrefix(e.Name(), "koji_ca_cert.key.unloadable.") {
			found = true
		}
	}
	if !found {
		t.Fatal("unloadable backup not created")
	}
}

func isTSBackup(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, prefix)
	if len(suffix) != len("20060102150405") {
		return false
	}
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// create_csr

func TestCreateCSRFlow(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)
	mustCreateCA(t, rt, "test_ca")

	cn := "www.example.com"
	res, err := callTLS(t, rt, "tls.create_csr",
		&createCsrArgs{CaName: "test_ca", CN: ps(cn), OU: ps("Test Unit")})
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := res.(string)
	want := fmt.Sprintf("Created Private Key: %q ", base+"/test_ca/certs/"+cn+".key") +
		fmt.Sprintf("Created CSR for %q: %q", cn, base+"/test_ca/certs/"+cn+".csr")
	if msg != want {
		t.Fatalf("message =\n  %s\nwant\n  %s", msg, want)
	}
	if m := statMode(t, rt, base+"/test_ca/certs/"+cn+".csr"); m != 0o644 {
		t.Fatalf("csr mode = %o", m)
	}
	if m := statMode(t, rt, base+"/test_ca/certs/"+cn+".key"); m != 0o600 {
		t.Fatalf("key mode = %o", m)
	}

	csrPEM, err := rt.FS.ReadFile(base + "/test_ca/certs/" + cn + ".csr")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != cn || len(csr.Subject.OrganizationalUnit) != 1 ||
		csr.Subject.OrganizationalUnit[0] != "Test Unit" {
		t.Fatalf("subject = %v", csr.Subject)
	}
	var foundBC, foundKU, foundEKU bool
	for _, ext := range csr.Extensions {
		if ext.Critical {
			t.Fatalf("CSR extensions must be non-critical: %v", ext.Id)
		}
		switch {
		case ext.Id.Equal(oidBasicConstraints):
			foundBC = true
			if bc, _ := decodeBasicConstraints(ext.Value); bc != "CA:FALSE" {
				t.Fatalf("basicConstraints = %v", bc)
			}
		case ext.Id.Equal(oidKeyUsage):
			foundKU = true
		case ext.Id.Equal(oidExtendedKeyUsage):
			foundEKU = true
		}
	}
	if !foundBC || !foundKU || !foundEKU {
		t.Fatalf("extensions = %v", csr.Extensions)
	}

	// recreate guard reports the on-disk (double-separator) path
	res, err = callTLS(t, rt, "tls.create_csr",
		&createCsrArgs{CaName: "test_ca", CN: ps(cn)})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := res.(string); got != fmt.Sprintf("Certificate Request %q already exists",
		base+"/test_ca/certs//"+cn+".csr") {
		t.Fatalf("recreate = %v", got)
	}

	replace := true
	if _, err := callTLS(t, rt, "tls.create_csr",
		&createCsrArgs{CaName: "test_ca", CN: ps(cn), Replace: &replace}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateCSRMissingCA(t *testing.T) {
	rt := tlsRT(t, t.TempDir())
	res, err := callTLS(t, rt, "tls.create_csr", &createCsrArgs{CaName: "nothere"})
	if err != nil || res == nil {
		t.Fatalf("missing-ca: %v %v", res, err)
	}
	if got, _ := res.(string); got != "Certificate for CA named \"nothere\" does not exist, please create it first." {
		t.Fatalf("missing-ca reply = %v", res)
	}
}

func TestCreateCSRClientTypeExtAndSAN(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)
	mustCreateCA(t, rt, "test_ca")

	if _, err := callTLS(t, rt, "tls.create_csr", &createCsrArgs{
		CaName: "test_ca", CN: ps("db.replica"), CertType: "client", TypeExt: true,
	}); err != nil {
		t.Fatal(err)
	}
	csrPEM, err := rt.FS.ReadFile(base + "/test_ca/certs/db.replica_client.csr")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidExtendedKeyUsage) {
			eku, _ := decodeExtendedKeyUsage(ext.Value)
			if eku != "TLS Web Client Authentication" {
				t.Fatalf("client EKU = %v", eku)
			}
		}
	}

	for _, san := range [][]string{
		{"DNS:alt1.example.com", "DNS:alt2.example.com"},
		{"DNS:alt1.example.com, IP:10.0.0.1"},
	} {
		if _, err := callTLS(t, rt, "tls.create_csr", &createCsrArgs{
			CaName: "test_ca", CN: ps("sans.example.com"),
			SubjectAltName: san, CertType: "client", TypeExt: true,
		}); err != nil {
			t.Fatal(err)
		}
		csrPEM, err := rt.FS.ReadFile(base + "/test_ca/certs/sans.example.com_client.csr")
		if err != nil {
			t.Fatal(err)
		}
		block, _ = pem.Decode(csrPEM)
		csr, err = x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		var sanText string
		for _, ext := range csr.Extensions {
			if ext.Id.Equal(oidSubjectAltName) {
				sanText, _ = decodeSubjectAltName(ext.Value)
			}
		}
		if !strings.Contains(sanText, "DNS:alt1.example.com") {
			t.Fatalf("SAN = %q", sanText)
		}
	}
}

// ---------------------------------------------------------------------------
// create_self_signed_cert

func TestCreateSelfSigned(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)
	cn := "self.example.com"
	res, err := callTLS(t, rt, "tls.create_self_signed_cert",
		&createSelfSignedArgs{TlsDir: "tls", CN: ps(cn), OU: ps("Test Unit")})
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := res.(string)
	want := fmt.Sprintf("Created Private Key: %q ", base+"/tls/certs/"+cn+".key") +
		fmt.Sprintf("Created Certificate: %q", base+"/tls/certs/"+cn+".crt")
	if msg != want {
		t.Fatalf("message =\n  %s\nwant\n  %s", msg, want)
	}
	if m := statMode(t, rt, base+"/tls/certs/"+cn+".crt"); m != 0o644 {
		t.Fatalf("cert mode = %o", m)
	}
	if m := statMode(t, rt, base+"/tls/certs/"+cn+".key"); m != 0o600 {
		t.Fatalf("key mode = %o", m)
	}
	// self-signed certs stay extension-free like upstream
	pemData, _ := rt.FS.ReadFile(base + "/tls/certs/" + cn + ".crt")
	block, _ := pem.Decode(pemData)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Extensions) != 0 {
		t.Fatalf("expected bare cert, extensions = %v", cert.Extensions)
	}

	res, err = callTLS(t, rt, "tls.create_self_signed_cert",
		&createSelfSignedArgs{TlsDir: "tls", CN: ps(cn)})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := res.(string); got != fmt.Sprintf("Certificate %q already exists", cn) {
		t.Fatalf("recreate = %v", got)
	}
}

// ---------------------------------------------------------------------------
// create_ca_signed_cert

func TestCreateCASignedCertFlow(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)
	mustCreateCA(t, rt, "test_ca")
	cn := "www.example.com"
	if _, err := callTLS(t, rt, "tls.create_csr",
		&createCsrArgs{CaName: "test_ca", CN: ps(cn)}); err != nil {
		t.Fatal(err)
	}
	res, err := callTLS(t, rt, "tls.create_ca_signed_cert",
		&createCaSignedArgs{CaName: "test_ca", CN: cn})
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("Created Certificate for %q: %q", cn, base+"/test_ca/certs/"+cn+".crt")
	if res != want {
		t.Fatalf("message =\n  %v\nwant\n  %s", res, want)
	}

	pemData, _ := rt.FS.ReadFile(base + "/test_ca/certs/" + cn + ".crt")
	block, _ := pem.Decode(pemData)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	caPEM, _ := rt.FS.ReadFile(base + "/test_ca/test_ca_ca_cert.crt")
	caBlock, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(leaf.RawIssuer, ca.RawSubject) {
		t.Fatal("issuer mismatch")
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("signature: %v", err)
	}
	// the CSR's extension block carries over verbatim
	foundBC := false
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidBasicConstraints) {
			foundBC = true
		}
	}
	if !foundBC {
		t.Fatalf("leaf extensions = %v", leaf.Extensions)
	}

	res, err = callTLS(t, rt, "tls.create_ca_signed_cert",
		&createCaSignedArgs{CaName: "test_ca", CN: cn})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := res.(string); got != fmt.Sprintf("Certificate %q already exists", cn) {
		t.Fatalf("recreate = %v", got)
	}
	res, err = callTLS(t, rt, "tls.create_ca_signed_cert",
		&createCaSignedArgs{CaName: "test_ca", CN: "other.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	gotMap, _ := res.(map[string]any)
	if gotMap["retcode"] != 1 ||
		!strings.Contains(gotMap["comment"].(string), "There is no CSR that matches the CN") {
		t.Fatalf("no-CSR reply = %v", res)
	}
}

func TestCreateCASignedNoCAAndTypeExtGuard(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)
	res, err := callTLS(t, rt, "tls.create_ca_signed_cert",
		&createCaSignedArgs{CaName: "nothere", CN: "x.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	gotMap, _ := res.(map[string]any)
	if gotMap["retcode"] != 1 ||
		!strings.Contains(gotMap["comment"].(string), "There is no CA named") {
		t.Fatalf("no-CA reply = %v", res)
	}

	mustCreateCA(t, rt, "test_ca")
	// type_ext without cert_type yields the empty dict upstream logs
	res, err = callTLS(t, rt, "tls.create_ca_signed_cert",
		&createCaSignedArgs{CaName: "test_ca", CN: "x.example.com", TypeExt: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotMap) >= 0 && res != nil {
		if m, ok := res.(map[string]any); !ok || len(m) != 0 {
			t.Fatalf("type_ext guard = %v", res)
		}
	}
}

// ---------------------------------------------------------------------------
// maybe_fix_ssl_version

func TestMaybeFixSSLVersion(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)
	mustCreateCA(t, rt, "buggy")

	// rewrite the CA cert with the illegal version literal 3 the way
	// old salt wrote it
	certp := base + "/buggy/buggy_ca_cert.crt"
	pemData, _ := rt.FS.ReadFile(certp)
	block, _ := pem.Decode(pemData)
	patched := append([]byte{}, block.Bytes...)
	patched[12] = 0x03
	if err := rt.FS.WriteFile(certp, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: patched,
	}), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificate(patched); err == nil {
		t.Fatal("probe self-check: patched cert should fail to parse")
	}

	res, err := callTLS(t, rt, "tls.maybe_fix_ssl_version",
		&maybeFixSSLVersionArgs{CaName: "buggy"})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		t.Fatalf("maybe_fix reply = %v", res)
	}

	fixed, _ := rt.FS.ReadFile(certp)
	fixedBlock, _ := pem.Decode(fixed)
	cert, err := x509.ParseCertificate(fixedBlock.Bytes)
	if err != nil {
		t.Fatalf("fix failed: %v", err)
	}
	if cert.Version != 3 {
		t.Fatalf("version = %d", cert.Version)
	}
	if cert.Subject.CommonName != "localhost" {
		t.Fatalf("subject lost: %v", cert.Subject)
	}
}

func TestMaybeFixSSLVersionFixmodeMissing(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)
	mustCreateCA(t, rt, "test_ca")
	_, err := callTLS(t, rt, "tls.create_ca",
		&createCaArgs{CaName: "ghost", Fixmode: pb(true)})
	if err == nil || !strings.Contains(err.Error(), "does not exists, can't fix") {
		t.Fatalf("fixmode missing reply = %v", err)
	}
}

// ---------------------------------------------------------------------------
// create_pkcs12 boundary

func TestCreatePkcs12Boundary(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)

	// no CA: the file checks reply before the serialization boundary
	res, err := callTLS(t, rt, "tls.create_pkcs12",
		&createPkcs12Args{CaName: "ca", CN: "x.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := res.(string); got != "There is no CA named \"ca\"" {
		t.Fatalf("no-CA reply = %v", res)
	}

	mustCreateCA(t, rt, "ca")
	if _, err := callTLS(t, rt, "tls.create_csr",
		&createCsrArgs{CaName: "ca", CN: ps("x.example.com")}); err != nil {
		t.Fatal(err)
	}
	if _, err := callTLS(t, rt, "tls.create_ca_signed_cert",
		&createCaSignedArgs{CaName: "ca", CN: "x.example.com"}); err != nil {
		t.Fatal(err)
	}

	res, err = callTLS(t, rt, "tls.create_pkcs12",
		&createPkcs12Args{CaName: "ca", CN: "missing.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := res.(string); got != "There is no certificate that matches the CN \"missing.example.com\"" {
		t.Fatalf("no-cert reply = %v", res)
	}

	// existing reply trumps serialization
	if err := rt.FS.WriteFile(base+"/ca/certs/x.example.com.p12",
		[]byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = callTLS(t, rt, "tls.create_pkcs12",
		&createPkcs12Args{CaName: "ca", CN: "x.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := res.(string); got != "Certificate \"x.example.com\" already exists" {
		t.Fatalf("exists reply = %v", res)
	}

	// serialization boundary surfaces as the documented error
	_, err = callTLS(t, rt, "tls.create_pkcs12",
		&createPkcs12Args{CaName: "ca", CN: "x.example.com", Replace: pb(true)})
	if err == nil || !strings.Contains(err.Error(), "pkcs12 encoder pending") {
		t.Fatalf("boundary reply = %v", err)
	}
}

// ---------------------------------------------------------------------------
// create_empty_crl / revoke_cert / validate

func TestCreateEmptyCRL(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)

	res, err := callTLS(t, rt, "tls.create_empty_crl",
		&createEmptyCrlArgs{CaName: "ca"})
	if err != nil || res == nil {
		t.Fatalf("no-CA reply: %v %v", res, err)
	}
	if got, _ := res.(string); got != "There is no CA named \"ca\"" {
		t.Fatalf("no-CA reply = %v", res)
	}

	mustCreateCA(t, rt, "ca")
	res, err = callTLS(t, rt, "tls.create_empty_crl",
		&createEmptyCrlArgs{CaName: "ca"})
	if err != nil {
		t.Fatal(err)
	}
	crlPath := base + "/ca/crl.pem"
	if got, _ := res.(string); got != fmt.Sprintf("Created an empty CRL: %q", crlPath) {
		t.Fatalf("created reply = %v", res)
	}
	// the CRL parses, is issued by the CA, and verifies
	crlPEM, err := rt.FS.ReadFile(crlPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(crlPEM)
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := rt.FS.ReadFile(base + "/ca/ca_ca_cert.crt")
	caBlock, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if serr := crl.CheckSignatureFrom(ca); serr != nil {
		t.Fatalf("CRL signature: %v", serr)
	}
	if len(crl.RevokedCertificates) != 0 {
		t.Fatalf("expected empty CRL, revoked=%d", len(crl.RevokedCertificates))
	}

	// exists guard
	res, err = callTLS(t, rt, "tls.create_empty_crl",
		&createEmptyCrlArgs{CaName: "ca"})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := res.(string); got != fmt.Sprintf("CRL %q already exists", crlPath) {
		t.Fatalf("exists reply = %v", res)
	}
}

func TestRevokeCertFlow(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)
	mustCreateCA(t, rt, "ca")
	cn := "www.example.com"
	if _, err := callTLS(t, rt, "tls.create_csr",
		&createCsrArgs{CaName: "ca", CN: ps(cn)}); err != nil {
		t.Fatal(err)
	}
	if _, err := callTLS(t, rt, "tls.create_ca_signed_cert",
		&createCaSignedArgs{CaName: "ca", CN: cn}); err != nil {
		t.Fatal(err)
	}

	// no-CA and no-client replies
	res, err := callTLS(t, rt, "tls.revoke_cert",
		&revokeCertArgs{CaName: "ghost", CN: cn})
	if err != nil || res == nil {
		t.Fatalf("no-CA: %v %v", res, err)
	}
	if got, _ := res.(string); got != "There is no CA named \"ghost\"" {
		t.Fatalf("no-CA reply = %v", res)
	}
	res, err = callTLS(t, rt, "tls.revoke_cert",
		&revokeCertArgs{CaName: "ca", CN: "missing.example.com"})
	if err != nil || res == nil {
		t.Fatalf("no-client: %v %v", res, err)
	}
	if got, _ := res.(string); got != "There is no client certificate named \"missing.example.com\"" {
		t.Fatalf("no-client reply = %v", res)
	}

	// happy path: the V row flips to R and the CRL carries the serial
	leafPath := base + "/ca/certs/" + cn + ".crt"
	pemData, _ := rt.FS.ReadFile(leafPath)
	block, _ := pem.Decode(pemData)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	serialHex := strings.ToUpper(leaf.SerialNumber.Text(16))

	res, err = callTLS(t, rt, "tls.revoke_cert",
		&revokeCertArgs{CaName: "ca", CN: cn})
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("Revoked Certificate: %q, serial number: %s", leafPath, serialHex)
	if res != want {
		t.Fatalf("revoked reply =\n  %v\nwant\n  %s", res, want)
	}

	index, _ := rt.FS.ReadFile(base + "/ca/index.txt")
	if !strings.Contains(string(index), "\nR\t") && !strings.HasPrefix(string(index), "R\t") {
		t.Fatalf("index rows missing R status: %q", string(index))
	}

	crlPEM, _ := rt.FS.ReadFile(base + "/ca/crl.pem")
	crlBlock, _ := pem.Decode(crlPEM)
	crl, err := x509.ParseRevocationList(crlBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// the CRL carries the serial truncated to 159 bits exactly like
	// upstream's cryptography builder
	wantSerial := leaf.SerialNumber
	if wantSerial.BitLen() >= 160 {
		mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 159), big.NewInt(1))
		wantSerial = new(big.Int).And(wantSerial, mask)
	}
	found := false
	for _, entry := range crl.RevokedCertificates {
		if entry.SerialNumber.Cmp(wantSerial) == 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("serial %s missing from CRL", wantSerial.Text(16))
	}

	// already-revoked reply
	res, err = callTLS(t, rt, "tls.revoke_cert",
		&revokeCertArgs{CaName: "ca", CN: cn})
	if err != nil {
		t.Fatal(err)
	}
	want = fmt.Sprintf("%q was already revoked, serial number: %s", leafPath, serialHex)
	if res != want {
		t.Fatalf("already-revoked reply =\n  %v\nwant\n  %s", res, want)
	}

	// crl_file pointing at a directory surfaces the error dict on a
	// cert that is not recorded as revoked yet
	cn2 := "novel.example.com"
	if _, err := callTLS(t, rt, "tls.create_csr",
		&createCsrArgs{CaName: "ca", CN: ps(cn2)}); err != nil {
		t.Fatal(err)
	}
	if _, err := callTLS(t, rt, "tls.create_ca_signed_cert",
		&createCaSignedArgs{CaName: "ca", CN: cn2}); err != nil {
		t.Fatal(err)
	}
	res, err = callTLS(t, rt, "tls.revoke_cert",
		&revokeCertArgs{CaName: "ca", CN: cn2, CrlFile: ps(base)})
	if err != nil {
		t.Fatal(err)
	}
	gotMap, _ := res.(map[string]any)
	if gotMap["retcode"] != 1 ||
		!strings.Contains(gotMap["comment"].(string), "is an existing directory") {
		t.Fatalf("dir reply = %v", res)
	}
}

func TestValidateLifecycle(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)
	mustCreateCA(t, rt, "ca")
	cn := "www.example.com"
	if _, err := callTLS(t, rt, "tls.create_csr",
		&createCsrArgs{CaName: "ca", CN: ps(cn)}); err != nil {
		t.Fatal(err)
	}
	if _, err := callTLS(t, rt, "tls.create_ca_signed_cert",
		&createCaSignedArgs{CaName: "ca", CN: cn}); err != nil {
		t.Fatal(err)
	}
	leafPath := base + "/ca/certs/" + cn + ".crt"

	// crl_file=None path with the CA key present: valid
	res, err := callTLS(t, rt, "tls.validate",
		&validateArgs{Cert: leafPath, CaName: "ca"})
	if err != nil {
		t.Fatal(err)
	}
	if gotMap, _ := res.(map[string]any); gotMap["valid"] != true {
		t.Fatalf("valid = %v", res)
	}

	// explicit CRL file: valid while unrevoked
	res, err = callTLS(t, rt, "tls.create_empty_crl", &createEmptyCrlArgs{CaName: "ca"})
	if err != nil {
		t.Fatal(err)
	}
	res, err = callTLS(t, rt, "tls.validate",
		&validateArgs{Cert: leafPath, CaName: "ca", CrlFile: ps(base + "/ca/crl.pem")})
	if err != nil {
		t.Fatal(err)
	}
	if gotMap, _ := res.(map[string]any); gotMap["valid"] != true {
		t.Fatalf("crl-file valid = %v", res)
	}

	// revoke, then validate reports the revoked pre-check
	if _, err := callTLS(t, rt, "tls.revoke_cert",
		&revokeCertArgs{CaName: "ca", CN: cn}); err != nil {
		t.Fatal(err)
	}
	res, err = callTLS(t, rt, "tls.validate",
		&validateArgs{Cert: leafPath, CaName: "ca"})
	if err != nil {
		t.Fatal(err)
	}
	gotMap, _ := res.(map[string]any)
	if gotMap["valid"] != false || gotMap["error"] != "certificate revoked" {
		t.Fatalf("revoked = %v", res)
	}
	if pemText, ok := gotMap["error_cert"].(string); !ok ||
		!strings.Contains(pemText, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("error_cert = %v", gotMap["error_cert"])
	}

	// expired leaf surfaces the OpenSSL reason string
	if _, err := callTLS(t, rt, "tls.create_csr",
		&createCsrArgs{CaName: "ca", CN: ps("expired.example.com")}); err != nil {
		t.Fatal(err)
	}
	if _, err := callTLS(t, rt, "tls.create_ca_signed_cert",
		&createCaSignedArgs{CaName: "ca", CN: "expired.example.com", Days: pi(-1)}); err != nil {
		t.Fatal(err)
	}
	res, err = callTLS(t, rt, "tls.validate",
		&validateArgs{Cert: base + "/ca/certs/expired.example.com.crt", CaName: "ca"})
	if err != nil {
		t.Fatal(err)
	}
	if gotMap, _ := res.(map[string]any); gotMap["valid"] != false ||
		gotMap["error"] != "certificate has expired" {
		t.Fatalf("expired = %v", res)
	}

	// cert from another CA fails chain validation
	if _, err := callTLS(t, rt, "tls.create_self_signed_cert",
		&createSelfSignedArgs{TlsDir: "other", CN: ps("rogue.example.com")}); err != nil {
		t.Fatal(err)
	}
	res, err = callTLS(t, rt, "tls.validate",
		&validateArgs{Cert: base + "/other/certs/rogue.example.com.crt", CaName: "ca"})
	if err != nil {
		t.Fatal(err)
	}
	if gotMap, _ := res.(map[string]any); gotMap["valid"] != false {
		t.Fatalf("rogue = %v", res)
	}

	// unreadable cert surfaces the CommandExecutionError text
	_, err = callTLS(t, rt, "tls.validate",
		&validateArgs{Cert: "/nonexistent.crt", CaName: "ca"})
	if err == nil || !strings.Contains(err.Error(),
		"Failed to read cert from /nonexistent.crt, see log for details") {
		t.Fatalf("unreadable reply = %v", err)
	}
}

func TestValidateEmptyCRLKeyMissing(t *testing.T) {
	base := t.TempDir()
	rt := tlsRT(t, base)
	mustCreateCA(t, rt, "ca")
	cn := "www.example.com"
	if _, err := callTLS(t, rt, "tls.create_csr",
		&createCsrArgs{CaName: "ca", CN: ps(cn)}); err != nil {
		t.Fatal(err)
	}
	if _, err := callTLS(t, rt, "tls.create_ca_signed_cert",
		&createCaSignedArgs{CaName: "ca", CN: cn}); err != nil {
		t.Fatal(err)
	}
	// remove the CA key: the empty-CRL path mirrors upstream's error dict
	if err := rt.FS.Remove(base + "/ca/ca_ca_cert.key"); err != nil {
		t.Fatal(err)
	}
	res, err := callTLS(t, rt, "tls.validate",
		&validateArgs{Cert: base + "/ca/certs/" + cn + ".crt", CaName: "ca"})
	if err != nil {
		t.Fatal(err)
	}
	if gotMap, _ := res.(map[string]any); gotMap["valid"] != false ||
		gotMap["error"] != "Empty CRL requested but CA key missing or invalid" {
		t.Fatalf("key-missing = %v", res)
	}
}
