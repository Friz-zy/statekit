package x509

// R5.4 ports the x509_v2 round of Salt's cryptography-based x509
// family: encode_certificate, encode_crl, encode_csr,
// encode_private_key, expires and read_crl from saltstack/salt/
// modules/x509_v2.py @ the pinned revision. Like R5.2a/b the substrate
// is library-to-library: the pinned source rides the cryptography
// library and the Go standard library (crypto/x509, encoding/pem,
// encoding/asn1, encoding/base64) replaces it; the openssl binary is
// never spawned and no Runner call is made.
//
// Input handling ports salt/utils/x509.py load_file_or_bytes plus the
// load_cert/load_crl/load_csr/load_privkey helpers: an existing
// regular file is read (bounded 16 MiB, no symlinks, exactly like the
// R5.2a convention where upstream's os.path.isfile would follow
// symlinks); otherwise the string content is interpreted as a "b64:"
// prefix, inline PEM ("-----BEGIN"), hex or base64-encoded DER, and
// anything else raises the exact "Could not load provided source.
// You need to pass an existing file, (PEM|hex|base64)-encoded string
// or raw bytes." invocation error. A file's raw bytes are used as-is
// where inline strings get the hex/base64 decoding (upstream applies
// the string conversions only to non-file input).
//
// Documented boundaries (observable shapes stay identical unless
// noted):
//   - encode_certificate keeps the pinned validation order: the
//     encoding whitelist (exact CommandExecutionError text), the
//     der+append_certs SaltInvocationError, the non-pkcs12 private_key
//     SaltInvocationError and the pkcs12-without-key
//     SaltInvocationError all fire before any parsing. pem/der output
//     is byte-exact (re-encoded from the parsed structure, 64-column
//     PEM, "\n"-joined chains); non-raw der is base64 exactly like the
//     source.
//   - pkcs7_der/pkcs7_pem/pkcs12 encodings, PKCS#7-PEM certificate
//     inputs, encrypted-PKCS#8 key inputs and BestAvailableEncryption
//     output resolve to a deterministic runtime.UnsupportedError: the
//     Go standard library cannot serialize or parse those containers
//     and no new dependency is allowed (the x509-v2 differential
//     scenario pins this container boundary). Everything before the
//     container step still raises the exact pinned texts.
//   - encode_private_key always re-encodes as PKCS#8 (the pinned v2
//     behavior; there is no cipher parameter in x509_v2 — the `cipher`
//     keyword only appears in create_private_key's deprecated kwargs
//     ignore list, so the pinned "cipher validation list" is empty).
//     Plain output is unencrypted PKCS#8 ("PRIVATE KEY"). Legacy
//     Proc-Type/DEK-Info encrypted inputs decrypt through the
//     deprecated stdlib x509.DecryptPEMBlock with the exact password
//     error texts (Bad decrypt / encrypted, provide / unencrypted,
//     remove).
//   - expires ports the v2 bool contract: not_valid_after <= now +
//     days, days defaulting to 0 (the source has no string coercion;
//     timedelta(days=days) requires a number, which the CLI arg
//     decoder provides).
//   - read_crl ports the v2 dict shape (the v1 openssl-CLI-text shape
//     is subsumed; ADR 0003 keeps the CLI parser excluded): issuer
//     keyed by the v2 NAME_ATTRS_OID short names (C/ST/L/STREET/O/OU/
//     CN/MAIL/SN/GN/UID/SERIALNUMBER, first value per OID),
//     last_update/next_update/revocation_date as "%Y-%m-%d %H:%M:%S"
//     UTC strings, revoked_certificates keyed by dec2hex(serial)
//     without the colons, the pinned extension renderers (including
//     the "onysomereasons" issuingDistributionPoint typo) and
//     signature_algorithm as the OpenSSL-style OID name with the
//     dotted-string fallback. The renderer covers the CRL extension
//     profile (authorityKeyIdentifier, cRLNumber, deltaCRLIndicator,
//     freshestCRL, issuerAltName, authorityInfoAccess,
//     issuingDistributionPoint) and the CRL entry profile (CRLReason,
//     invalidityDate, certificateIssuer); certificate-profile
//     extension families on a CRL raise a deterministic error where
//     the source would render them (the same profile-boundary
//     convention as R5.2b). A nextUpdate-less CRL formats the zero
//     time where the source would crash on None.strftime.

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

// ---------------------------------------------------------------------------
// load_file_or_bytes and the load_* helpers

const couldNotLoadSource = "Could not load provided source. You need to pass an existing file, (PEM|hex|base64)-encoded string or raw bytes."

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// pyHexDecode mirrors bytes.fromhex: ASCII whitespace is tolerated,
// everything else must be an even number of hex digits.
func pyHexDecode(s string) ([]byte, bool) {
	var clean strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			continue
		}
		clean.WriteByte(s[i])
	}
	t := clean.String()
	if len(t)%2 != 0 {
		return nil, false
	}
	out := make([]byte, len(t)/2)
	for i := 0; i < len(t); i += 2 {
		hi, ok1 := hexVal(t[i])
		lo, ok2 := hexVal(t[i+1])
		if !ok1 || !ok2 {
			return nil, false
		}
		out[i/2] = hi<<4 | lo
	}
	return out, true
}

// pyB64Decode mirrors base64.b64decode's default leniency: bytes that
// are neither in the standard alphabet nor padding are discarded
// before a strict decode.
func pyB64Decode(s string) ([]byte, bool) {
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '+', c == '/', c == '=':
			clean = append(clean, c)
		}
	}
	if len(clean)%4 != 0 {
		return nil, false
	}
	out := make([]byte, base64.StdEncoding.DecodedLen(len(clean)))
	n, err := base64.StdEncoding.Decode(out, clean)
	if err != nil {
		return nil, false
	}
	return out[:n], true
}

// v2InputBytes ports load_file_or_bytes: a regular file is read
// bounded; a "b64:" prefix decodes; inline PEM passes through; then
// hex and base64-encoded DER are tried; when nothing matches the exact
// SaltInvocationError text raises.
func v2InputBytes(rt *runtime.Runtime, input string) ([]byte, error) {
	if info, err := rt.FS.Stat(input); err == nil && info != nil && info.Mode().IsRegular() {
		data, rerr := runtime.ReadFileBounded(rt.FS, input, maxPEMBytes)
		if rerr != nil {
			return nil, stableReadError(rerr)
		}
		return data, nil
	}
	if rest, ok := strings.CutPrefix(input, "b64:"); ok {
		// An undecodable b64: string escapes upstream as an uncaught
		// binascii.Error; the port keeps it in the invocation-error
		// family with the loader's stable text.
		if dec, ok := pyB64Decode(rest); ok {
			return dec, nil
		}
		return nil, &invocationErr{msg: couldNotLoadSource}
	}
	if strings.Contains(input, "-----BEGIN") {
		return []byte(input), nil
	}
	if dec, ok := pyHexDecode(input); ok {
		return dec, nil
	}
	if dec, ok := pyB64Decode(input); ok {
		return dec, nil
	}
	return nil, &invocationErr{msg: couldNotLoadSource}
}

// v2LoadCertificate ports load_cert for the stdlib-expressible
// surface: the first PEM entry or raw DER.
func v2LoadCertificate(rt *runtime.Runtime, input string) (*x509.Certificate, error) {
	data, err := v2InputBytes(rt, input)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(data, []byte("-----BEGIN")) {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, &invocationErr{msg: "Could not load PEM-encoded certificate."}
		}
		if block.Type == "PKCS7" || block.Type == "PKCS7 SIGNED" {
			return nil, &runtime.UnsupportedError{Kind: "container", Name: "pkcs7"}
		}
		cert, perr := x509.ParseCertificate(block.Bytes)
		if perr != nil {
			return nil, &invocationErr{msg: "Could not load PEM-encoded certificate."}
		}
		return cert, nil
	}
	cert, perr := x509.ParseCertificate(data)
	if perr != nil {
		return nil, &invocationErr{msg: "Could not deserialize binary data, neither as DER nor PKCS#7, PKCS#12."}
	}
	return cert, nil
}

// v2LoadCRL ports load_crl.
func v2LoadCRL(rt *runtime.Runtime, input string) (*x509.RevocationList, error) {
	data, err := v2InputBytes(rt, input)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(data, []byte("-----BEGIN")) {
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "X509 CRL" {
			return nil, &invocationErr{msg: "Could not load PEM-encoded certificate revocation list."}
		}
		list, perr := x509.ParseRevocationList(block.Bytes)
		if perr != nil {
			return nil, &invocationErr{msg: "Could not load PEM-encoded certificate revocation list."}
		}
		return list, nil
	}
	list, perr := x509.ParseRevocationList(data)
	if perr != nil {
		return nil, &invocationErr{msg: "Could not load DER-encoded certificate revocation list."}
	}
	return list, nil
}

// v2LoadCSR ports load_csr.
func v2LoadCSR(rt *runtime.Runtime, input string) (*x509.CertificateRequest, error) {
	data, err := v2InputBytes(rt, input)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(data, []byte("-----BEGIN")) {
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			return nil, &invocationErr{msg: "Could not load PEM-encoded certificate signing request."}
		}
		req, perr := x509.ParseCertificateRequest(block.Bytes)
		if perr != nil {
			return nil, &invocationErr{msg: "Could not load PEM-encoded certificate signing request."}
		}
		return req, nil
	}
	req, perr := x509.ParseCertificateRequest(data)
	if perr != nil {
		return nil, &invocationErr{msg: "Could not load DER-encoded certificate signing request."}
	}
	return req, nil
}

// parsePEMKeyBody parses a private-key DER by its PEM block type.
func parsePEMKeyBody(pemType string, raw []byte) (any, error) {
	switch pemType {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(raw)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(raw)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(raw)
	}
	return nil, fmt.Errorf("unsupported PEM key type %q", pemType)
}

// parseDERPrivateKeyBody tries the unencrypted PKCS#8, PKCS#1 and
// SEC1 containers in order (cryptography's load_der_private_key
// auto-detects the same set).
func parseDERPrivateKeyBody(der []byte) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return x509.ParseECPrivateKey(der)
}

// sniffDERKeyContainer separates encrypted PKCS#8 and PKCS#12 DER
// containers (first inner element an AlgorithmIdentifier SEQUENCE or
// a contentType OID) from the parseable PKCS#8 (leading INTEGER 0)
// and PKCS#1/SEC1 bodies (leading INTEGER modulus).
func sniffDERKeyContainer(der []byte) (string, bool) {
	outer, err := walkTLV(der, 0)
	if err != nil || outer.id != 0x30 {
		return "", false
	}
	first, err := walkTLV(outer.content, 0)
	if err != nil {
		return "", false
	}
	switch first.id {
	case 0x06: // contentType OID of a PKCS#12 PFX authSafe
		return "pkcs12", true
	case 0x30: // AlgorithmIdentifier of an EncryptedPrivateKeyInfo
		return "pkcs8-encryption", true
	}
	return "", false
}

// v2LoadPrivateKey ports load_privkey for the stdlib-expressible
// surface with the exact password error texts.
func v2LoadPrivateKey(rt *runtime.Runtime, input string, passphrase *string) (any, error) {
	data, err := v2InputBytes(rt, input)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(data, []byte("-----BEGIN")) {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, &invocationErr{msg: "Could not load PEM-encoded private key"}
		}
		if block.Type == "ENCRYPTED PRIVATE KEY" {
			return nil, &runtime.UnsupportedError{Kind: "container", Name: "pkcs8-encryption"}
		}
		if _, encrypted := block.Headers["DEK-Info"]; encrypted {
			if passphrase == nil {
				return nil, &invocationErr{msg: "Private key is encrypted. Please provide a password."}
			}
			// Deprecated stdlib API: the only stdlib decryptor for the
			// legacy OpenSSL envelope the source transparently handles.
			clear, derr := x509.DecryptPEMBlock(block, []byte(*passphrase))
			if derr != nil {
				return nil, &invocationErr{msg: "Bad decrypt - is the password correct?"}
			}
			key, perr := parsePEMKeyBody(block.Type, clear)
			if perr != nil {
				return nil, &invocationErr{msg: "Could not load PEM-encoded private key"}
			}
			return key, nil
		}
		key, perr := parsePEMKeyBody(block.Type, block.Bytes)
		if perr != nil {
			return nil, &invocationErr{msg: "Could not load PEM-encoded private key"}
		}
		if passphrase != nil {
			return nil, &invocationErr{msg: "Private key is unencrypted. Please remove the password."}
		}
		return key, nil
	}
	if container, ok := sniffDERKeyContainer(data); ok {
		return nil, &runtime.UnsupportedError{Kind: "container", Name: container}
	}
	key, perr := parseDERPrivateKeyBody(data)
	if perr != nil {
		return nil, &invocationErr{msg: "Could not deserialize binary data, neither as DER nor PKCS#12."}
	}
	if passphrase != nil {
		return nil, &invocationErr{msg: "Private key is unencrypted. Please remove the password."}
	}
	return key, nil
}

// ---------------------------------------------------------------------------
// encode_certificate

type encodeCertificateArgs struct {
	Certificate            string   `statekit:"required"`
	Encoding               *string  `statekit:"name=encoding"`
	AppendCerts            []string `statekit:"name=append_certs"`
	PrivateKey             *string  `statekit:"name=private_key"`
	PrivateKeyPassphrase   *string  `statekit:"name=private_key_passphrase"`
	Pkcs12Passphrase       *string  `statekit:"name=pkcs12_passphrase"`
	Pkcs12EncryptionCompat *bool    `statekit:"name=pkcs12_encryption_compat"`
	Pkcs12Friendlyname     *string  `statekit:"name=pkcs12_friendlyname"`
	Raw                    bool     `statekit:"name=raw"`
}

type encodeCertificateFunc struct{}

func (encodeCertificateFunc) Name() string { return "x509.encode_certificate" }
func (encodeCertificateFunc) Args() any    { return encodeCertificateArgs{} }
func (encodeCertificateFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*encodeCertificateArgs)
	encoding := "pem"
	if a.Encoding != nil {
		encoding = *a.Encoding
	}
	if encoding != "der" && encoding != "pem" && encoding != "pkcs7_der" &&
		encoding != "pkcs7_pem" && encoding != "pkcs12" {
		return nil, &invocationErr{msg: fmt.Sprintf(
			"Invalid value '%s' for encoding. Valid: der, pem, pkcs7_der, pkcs7_pem, pkcs12", encoding)}
	}
	if encoding == "der" && len(a.AppendCerts) > 0 {
		return nil, &invocationErr{msg: "Cannot encode a certificate chain in DER"}
	}
	if encoding != "pkcs12" && a.PrivateKey != nil && *a.PrivateKey != "" {
		return nil, &invocationErr{msg: "Embedding private keys is only supported for pkcs12 encoding"}
	}
	if encoding == "pkcs12" && (a.PrivateKey == nil || *a.PrivateKey == "") {
		return nil, &invocationErr{msg: "Creating a PKCS12-encoded certificate without embedded private key is unsupported"}
	}

	cert, err := v2LoadCertificate(rt, a.Certificate)
	if err != nil {
		return nil, err
	}
	appendCerts := make([]*x509.Certificate, 0, len(a.AppendCerts))
	for _, item := range a.AppendCerts {
		appendCert, lerr := v2LoadCertificate(rt, item)
		if lerr != nil {
			return nil, lerr
		}
		appendCerts = append(appendCerts, appendCert)
	}

	var out []byte
	switch encoding {
	case "pem":
		out = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		for _, appendCert := range appendCerts {
			out = append(out, '\n')
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: appendCert.Raw})...)
		}
	case "der":
		out = cert.Raw
	default:
		return nil, &runtime.UnsupportedError{Kind: "container", Name: encoding}
	}
	return v2EncodedResult(out, encoding, a.Raw)
}

// v2EncodedResult applies the pinned raw/string/base64 tail shared by
// the encoders: raw returns bytes, pem decodes to text and everything
// else renders standard base64.
func v2EncodedResult(data []byte, encoding string, raw bool) (any, error) {
	if raw {
		return data, nil
	}
	if encoding == "pem" {
		return string(data), nil
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// ---------------------------------------------------------------------------
// encode_crl

type encodeCrlArgs struct {
	Crl      string  `statekit:"required"`
	Encoding *string `statekit:"name=encoding"`
	Raw      bool    `statekit:"name=raw"`
}

type encodeCrlFunc struct{}

func (encodeCrlFunc) Name() string { return "x509.encode_crl" }
func (encodeCrlFunc) Args() any    { return encodeCrlArgs{} }
func (encodeCrlFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*encodeCrlArgs)
	encoding := "pem"
	if a.Encoding != nil {
		encoding = *a.Encoding
	}
	if encoding != "der" && encoding != "pem" {
		return nil, &invocationErr{msg: fmt.Sprintf(
			"Invalid value '%s' for encoding. Valid: der, pem", encoding)}
	}
	list, err := v2LoadCRL(rt, a.Crl)
	if err != nil {
		return nil, err
	}
	var out []byte
	if encoding == "pem" {
		out = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: list.Raw})
	} else {
		out = list.Raw
	}
	return v2EncodedResult(out, encoding, a.Raw)
}

// ---------------------------------------------------------------------------
// encode_csr

type encodeCsrArgs struct {
	Csr      string  `statekit:"required"`
	Encoding *string `statekit:"name=encoding"`
	Raw      bool    `statekit:"name=raw"`
}

type encodeCsrFunc struct{}

func (encodeCsrFunc) Name() string { return "x509.encode_csr" }
func (encodeCsrFunc) Args() any    { return encodeCsrArgs{} }
func (encodeCsrFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*encodeCsrArgs)
	encoding := "pem"
	if a.Encoding != nil {
		encoding = *a.Encoding
	}
	if encoding != "der" && encoding != "pem" {
		return nil, &invocationErr{msg: fmt.Sprintf(
			"Invalid value '%s' for encoding. Valid: der, pem", encoding)}
	}
	req, err := v2LoadCSR(rt, a.Csr)
	if err != nil {
		return nil, err
	}
	var out []byte
	if encoding == "pem" {
		out = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.Raw})
	} else {
		out = req.Raw
	}
	return v2EncodedResult(out, encoding, a.Raw)
}

// ---------------------------------------------------------------------------
// encode_private_key

type encodePrivateKeyArgs struct {
	PrivateKey             string  `statekit:"required"`
	Encoding               *string `statekit:"name=encoding"`
	Passphrase             *string `statekit:"name=passphrase"`
	PrivateKeyPassphrase   *string `statekit:"name=private_key_passphrase"`
	Pkcs12EncryptionCompat *bool   `statekit:"name=pkcs12_encryption_compat"`
	Raw                    bool    `statekit:"name=raw"`
}

type encodePrivateKeyFunc struct{}

func (encodePrivateKeyFunc) Name() string { return "x509.encode_private_key" }
func (encodePrivateKeyFunc) Args() any    { return encodePrivateKeyArgs{} }
func (encodePrivateKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*encodePrivateKeyArgs)
	encoding := "pem"
	if a.Encoding != nil {
		encoding = *a.Encoding
	}
	if encoding != "der" && encoding != "pem" && encoding != "pkcs12" {
		return nil, &invocationErr{msg: fmt.Sprintf(
			"Invalid value '%s' for encoding. Valid: der, pem, pkcs12", encoding)}
	}
	key, err := v2LoadPrivateKey(rt, a.PrivateKey, a.PrivateKeyPassphrase)
	if err != nil {
		return nil, err
	}
	if encoding == "pkcs12" {
		return nil, &runtime.UnsupportedError{Kind: "container", Name: "pkcs12"}
	}
	// BestAvailableEncryption produces encrypted PKCS#8, which the Go
	// standard library cannot marshal; the deterministic container
	// boundary replaces it.
	if a.Passphrase != nil {
		return nil, &runtime.UnsupportedError{Kind: "container", Name: "pkcs8-encryption"}
	}
	der, merr := x509.MarshalPKCS8PrivateKey(key)
	if merr != nil {
		return nil, &invocationErr{msg: "Could not encode private key"}
	}
	var out []byte
	if encoding == "pem" {
		out = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	} else {
		out = der
	}
	return v2EncodedResult(out, encoding, a.Raw)
}

// ---------------------------------------------------------------------------
// expires

type expiresArgs struct {
	Certificate string `statekit:"required"`
	Days        *int   `statekit:"name=days"`
}

type expiresFunc struct{}

func (expiresFunc) Name() string { return "x509.expires" }
func (expiresFunc) Args() any    { return expiresArgs{} }
func (expiresFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*expiresArgs)
	cert, err := v2LoadCertificate(rt, a.Certificate)
	if err != nil {
		return nil, err
	}
	days := 0
	if a.Days != nil {
		days = *a.Days
	}
	return cert.NotAfter.UTC().Compare(
		time.Now().UTC().Add(time.Duration(days)*24*time.Hour)) <= 0, nil
}

// ---------------------------------------------------------------------------
// read_crl

type readCrlArgs struct {
	Crl string `statekit:"required"`
}

type readCrlFunc struct{}

func (readCrlFunc) Name() string { return "x509.read_crl" }
func (readCrlFunc) Args() any    { return readCrlArgs{} }
func (readCrlFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*readCrlArgs)
	return readCrlImpl(rt, a.Crl)
}

// v2NameOIDKeys is the v2 NAME_ATTRS_OID table keyed by its own short
// names (MAIL is emailAddress, SERIALNUMBER is serialNumber).
var v2NameOIDKeys = []struct {
	key string
	oid asn1.ObjectIdentifier
}{
	{"C", asn1.ObjectIdentifier{2, 5, 4, 6}},
	{"ST", asn1.ObjectIdentifier{2, 5, 4, 8}},
	{"L", asn1.ObjectIdentifier{2, 5, 4, 7}},
	{"STREET", asn1.ObjectIdentifier{2, 5, 4, 9}},
	{"O", asn1.ObjectIdentifier{2, 5, 4, 10}},
	{"OU", asn1.ObjectIdentifier{2, 5, 4, 11}},
	{"CN", asn1.ObjectIdentifier{2, 5, 4, 3}},
	{"MAIL", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}},
	{"SN", asn1.ObjectIdentifier{2, 5, 4, 4}},
	{"GN", asn1.ObjectIdentifier{2, 5, 4, 42}},
	{"UID", asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}},
	{"SERIALNUMBER", asn1.ObjectIdentifier{2, 5, 4, 5}},
}

// v2ParseNameDict ports _parse_dn: the first value per NAME_ATTRS_OID
// OID, keyed by the v2 short name.
func v2ParseNameDict(raw []byte) (map[string]string, error) {
	rdns, err := unmarshalRDNs(raw)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, set := range rdns {
		for _, atv := range set {
			if !isStringTag(atv.Value.Tag) {
				continue
			}
			for _, def := range v2NameOIDKeys {
				if atv.Type.Equal(def.oid) {
					if _, exists := out[def.key]; !exists {
						out[def.key] = string(atv.Value.Bytes)
					}
					break
				}
			}
		}
	}
	return out, nil
}

func readCrlImpl(rt *runtime.Runtime, crl string) (map[string]any, error) {
	list, err := v2LoadCRL(rt, crl)
	if err != nil {
		return nil, err
	}
	issuer, ierr := v2ParseNameDict(list.RawIssuer)
	if ierr != nil {
		return nil, ierr
	}
	ret := map[string]any{
		"issuer":      issuer,
		"last_update": list.ThisUpdate.UTC().Format(dateTimeLayout),
		"next_update": list.NextUpdate.UTC().Format(dateTimeLayout),
	}
	exts := map[string]any{}
	for _, ext := range list.Extensions {
		name, rendered, rerr := renderV2CRLExtension(ext)
		if rerr != nil {
			return nil, rerr
		}
		if rendered == nil {
			continue
		}
		exts[name] = rendered
	}
	ret["extensions"] = exts
	ret["signature_algorithm"] = v2SignatureAlgorithmName(list)

	revoked := map[string]any{}
	for _, entry := range list.RevokedCertificateEntries {
		entryExts := map[string]any{}
		for _, ext := range entry.Extensions {
			name, rendered, rerr := renderV2CRLEntryExtension(ext)
			if rerr != nil {
				return nil, rerr
			}
			if rendered == nil {
				continue
			}
			entryExts[name] = rendered
		}
		revoked[strings.ReplaceAll(dec2hexBig(entry.SerialNumber), ":", "")] = map[string]any{
			"revocation_date": entry.RevocationTime.UTC().Format(dateTimeLayout),
			"extensions":      entryExts,
		}
	}
	ret["revoked_certificates"] = revoked
	return ret, nil
}

// ---------------------------------------------------------------------------
// v2 extension rendering (render_extension + the v2 renderers)

var (
	oidV2CRLNumber       = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidV2DeltaCRL        = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidV2FreshestCRL     = asn1.ObjectIdentifier{2, 5, 29, 46}
	oidV2IssuerAltName   = asn1.ObjectIdentifier{2, 5, 29, 18}
	oidV2AIA             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidV2IDP             = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidV2CRLReason       = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidV2InvalidityDate  = asn1.ObjectIdentifier{2, 5, 29, 24}
	oidV2CertIssuer      = asn1.ObjectIdentifier{2, 5, 29, 29}
	oidV2OCSP            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidV2CAIssuers       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
	oidV2CRLDistPoints   = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidV2CertPolicies    = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidV2NameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidV2PolicyConstr    = asn1.ObjectIdentifier{2, 5, 29, 36}
	oidV2InhibitAny      = asn1.ObjectIdentifier{2, 5, 29, 54}
	oidV2TLSFeature      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	oidV2NoCheck         = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 25}
)

// renderV2CRLExtension renders one CRL-level extension. A nil value
// means the family stays invisible (extensions outside the
// EXTENSIONS_OID table are never iterated upstream); an error marks
// the deterministic profile boundary.
func renderV2CRLExtension(ext pkix.Extension) (string, map[string]any, error) {
	switch {
	case ext.Id.Equal(oidAuthorityKeyIdent):
		value, err := decodeV2AKI(ext.Value)
		if err != nil {
			return "", nil, err
		}
		value["critical"] = ext.Critical
		return "authorityKeyIdentifier", value, nil
	case ext.Id.Equal(oidV2CRLNumber), ext.Id.Equal(oidV2DeltaCRL):
		n, err := decodeV2Integer(ext.Value)
		if err != nil {
			return "", nil, err
		}
		name := "cRLNumber"
		if ext.Id.Equal(oidV2DeltaCRL) {
			name = "deltaCRLIndicator"
		}
		return name, map[string]any{"critical": ext.Critical, "value": n}, nil
	case ext.Id.Equal(oidV2FreshestCRL):
		dps, err := decodeV2DistributionPoints(ext.Value)
		if err != nil {
			return "", nil, err
		}
		return "freshestCRL", map[string]any{"critical": ext.Critical, "value": dps}, nil
	case ext.Id.Equal(oidV2IssuerAltName):
		names, err := renderV2GeneralNamesDER(ext.Value)
		if err != nil {
			return "", nil, err
		}
		return "issuerAltName", map[string]any{"critical": ext.Critical, "value": names}, nil
	case ext.Id.Equal(oidV2AIA):
		descs, err := decodeV2AIA(ext.Value)
		if err != nil {
			return "", nil, err
		}
		return "authorityInfoAccess", map[string]any{"critical": ext.Critical, "value": descs}, nil
	case ext.Id.Equal(oidV2IDP):
		value, err := decodeV2IDP(ext.Value)
		if err != nil {
			return "", nil, err
		}
		value["critical"] = ext.Critical
		return "issuingDistributionPoint", value, nil
	}
	if v2KnownCertProfileExtension(ext.Id) {
		// Certificate-profile families raise where the source renders
		// them: the deterministic profile boundary.
		return "", nil, &invocationErr{msg: fmt.Sprintf(
			"unsupported extension %s on CRL", ext.Id.String())}
	}
	return "", nil, nil
}

// renderV2CRLEntryExtension renders one CRL-entry extension. A nil
// value means the family stays invisible.
func renderV2CRLEntryExtension(ext pkix.Extension) (string, map[string]any, error) {
	switch {
	case ext.Id.Equal(oidV2CRLReason):
		t, err := walkTLV(ext.Value, 0)
		if err != nil || t.id != 0x0a || len(t.content) == 0 || t.next != len(ext.Value) {
			return "", nil, &invocationErr{msg: "invalid CRLReason extension"}
		}
		name, ok := crlReasonNames[int(t.content[0])]
		if !ok {
			return "", nil, &invocationErr{msg: fmt.Sprintf(
				"invalid CRLReason code %d", t.content[0])}
		}
		return "CRLReason", map[string]any{"critical": ext.Critical, "value": name}, nil
	case ext.Id.Equal(oidV2InvalidityDate):
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &raw); err != nil {
			return "", nil, &invocationErr{msg: "invalid invalidityDate extension"}
		}
		parsed, perr := time.Parse("20060102150405Z0700", string(raw.Bytes))
		if perr != nil {
			return "", nil, &invocationErr{msg: "invalid invalidityDate extension"}
		}
		return "invalidityDate", map[string]any{
			"critical": ext.Critical,
			"value":    parsed.UTC().Format(dateTimeLayout),
		}, nil
	case ext.Id.Equal(oidV2CertIssuer):
		names, err := renderV2GeneralNamesDER(ext.Value)
		if err != nil {
			return "", nil, err
		}
		return "certificateIssuer", map[string]any{"critical": ext.Critical, "value": names}, nil
	}
	return "", nil, nil
}

// crlReasonNames maps RFC 5280 reason codes onto the ReasonFlags
// values the pinned renderer reports.
var crlReasonNames = map[int]string{
	0:  "unspecified",
	1:  "keyCompromise",
	2:  "cACompromise",
	3:  "affiliationChanged",
	4:  "superseded",
	5:  "cessationOfOperation",
	6:  "certificateHold",
	8:  "removeFromCRL",
	9:  "privilegeWithdrawn",
	10: "aACompromise",
}

// v2KnownCertProfileExtension reports whether the OID is one of the
// EXTENSIONS_OID certificate families the renderer deliberately does
// not reproduce on CRLs.
func v2KnownCertProfileExtension(oid asn1.ObjectIdentifier) bool {
	for _, known := range []asn1.ObjectIdentifier{
		oidBasicConstraints, oidKeyUsage, oidExtendedKeyUsage, oidSubjectKeyIdent,
		oidSubjectAltName, oidV2CRLDistPoints, oidV2CertPolicies,
		oidV2NameConstraints, oidV2PolicyConstr, oidV2InhibitAny,
		oidV2TLSFeature, oidV2NoCheck,
	} {
		if oid.Equal(known) {
			return true
		}
	}
	return false
}

func decodeV2Integer(der []byte) (int, error) {
	t, err := walkTLV(der, 0)
	if err != nil || t.id != 0x02 || len(t.content) == 0 || t.next != len(der) {
		return 0, &invocationErr{msg: "invalid integer extension"}
	}
	n := new(big.Int).SetBytes(t.content)
	return int(n.Int64()), nil
}

// decodeV2AKI ports _render_authority_key_identifier.
func decodeV2AKI(der []byte) (map[string]any, error) {
	value := map[string]any{
		"keyid":     nil,
		"issuer":    nil,
		"issuer_sn": nil,
	}
	outer, err := walkTLV(der, 0)
	if err != nil {
		return nil, &invocationErr{msg: "invalid authorityKeyIdentifier extension"}
	}
	content := outer.content
	if outer.id != 0x30 { // tolerate unwrapped forms like the v1 renderer
		content = der
	}
	off := 0
	for off < len(content) {
		t, terr := walkTLV(content, off)
		if terr != nil {
			return nil, &invocationErr{msg: "invalid authorityKeyIdentifier extension"}
		}
		off = t.next
		switch t.id {
		case 0x80: // [0] IMPLICIT keyIdentifier
			if len(t.content) > 0 {
				value["keyid"] = prettyHex(t.content)
			}
		case 0xa1: // [1] IMPLICIT GeneralNames
			names, gerr := renderV2GeneralNamesContent(t.content)
			if gerr != nil {
				return nil, gerr
			}
			value["issuer"] = names
		case 0x82: // [2] IMPLICIT serialNumber
			value["issuer_sn"] = dec2hexBig(new(big.Int).SetBytes(t.content))
		}
	}
	return value, nil
}

// renderV2GeneralNamesDER renders a SEQUENCE OF GeneralName.
func renderV2GeneralNamesDER(der []byte) ([]string, error) {
	outer, err := walkTLV(der, 0)
	if err != nil || outer.id != 0x30 {
		return nil, &invocationErr{msg: "invalid general names extension"}
	}
	return renderV2GeneralNamesContent(outer.content)
}

// renderV2GeneralNamesContent renders a GeneralName TLV stream.
func renderV2GeneralNamesContent(content []byte) ([]string, error) {
	var out []string
	off := 0
	for off < len(content) {
		gn, err := walkTLV(content, off)
		if err != nil {
			return nil, &invocationErr{msg: "invalid general names extension"}
		}
		off = gn.next
		rendered, rerr := renderV2GeneralName(gn)
		if rerr != nil {
			return nil, rerr
		}
		out = append(out, rendered)
	}
	return out, nil
}

// renderV2GeneralName ports render_gn for the GeneralName families
// the DER walkers can decode; the remaining CHOICE tags (otherName
// and friends) hit the deterministic profile boundary.
func renderV2GeneralName(gn derTLV) (string, error) {
	switch gn.id {
	case 0x81: // [1] RFC822Name
		return "mail:" + string(gn.content), nil
	case 0x82: // [2] DNSName
		return "DNS:" + string(gn.content), nil
	case 0x84: // [4] DirectoryName
		name, err := rfc4514String(gn.content)
		if err != nil {
			return "", err
		}
		return "dirName:" + name, nil
	case 0x86: // [6] UniformResourceIdentifier
		return "URI:" + string(gn.content), nil
	case 0x87: // [7] IPAddress
		return "IP:" + pyExplodedIP(gn.content), nil
	case 0x88: // [8] RegisteredID
		oid, err := decodeOIDContent(gn.content)
		if err != nil {
			return "", err
		}
		return "RID:" + oid.String(), nil
	}
	return "", &invocationErr{msg: fmt.Sprintf(
		"unsupported general name tag %d", gn.id&0x1f)}
}

// pyExplodedIP renders net.IP the way ipaddress's exploded attribute
// does: full hexadecimal groups for IPv6, plain dotted IPv4.
func pyExplodedIP(b []byte) string {
	ip := net.IP(b)
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if v6 := ip.To16(); v6 != nil {
		var groups []string
		for i := 0; i < len(v6); i += 2 {
			groups = append(groups, fmt.Sprintf("%x", (int(v6[i])<<8)|int(v6[i+1])))
		}
		return strings.Join(groups, ":")
	}
	return ip.String()
}

// rfc4514AttrNames maps the directory attribute OIDs onto their
// RFC 4514 short names.
var rfc4514AttrNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.9":                    "STREET",
	"2.5.4.4":                    "SN",
	"2.5.4.42":                   "GN",
	"2.5.4.5":                    "serialNumber",
	"0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1":  "UID",
	"1.2.840.113549.1.9.1":       "emailAddress",
}

// rfc4514Escape escapes the RFC 4514 specials and leading/trailing
// space/hash octets.
func rfc4514Escape(s string) string {
	runes := []rune(s)
	var out strings.Builder
	for i, r := range runes {
		escaped := r == ',' || r == '+' || r == '"' || r == '\\' || r == '<' ||
			r == '>' || r == ';'
		if (i == 0 || i == len(runes)-1) && (r == ' ' || r == '#') {
			escaped = true
		}
		if escaped {
			out.WriteByte('\\')
		}
		out.WriteRune(r)
	}
	return out.String()
}

// rfc4514String renders an X.501 Name in RFC 4514 form: RDNs in
// reverse order, "+"-joined multi-valued RDNs.
func rfc4514String(raw []byte) (string, error) {
	rdns, err := unmarshalRDNs(raw)
	if err != nil {
		return "", err
	}
	var parts []string
	for i := len(rdns) - 1; i >= 0; i-- {
		var avas []string
		for _, atv := range rdns[i] {
			name := atv.Type.String()
			if short, ok := rfc4514AttrNames[name]; ok {
				name = short
			}
			avas = append(avas, name+"="+rfc4514Escape(string(atv.Value.Bytes)))
		}
		parts = append(parts, strings.Join(avas, "+"))
	}
	return strings.Join(parts, ","), nil
}

// decodeV2AIA ports _render_authority_info_access.
func decodeV2AIA(der []byte) ([]map[string]string, error) {
	outer, err := walkTLV(der, 0)
	if err != nil || outer.id != 0x30 {
		return nil, &invocationErr{msg: "invalid authorityInfoAccess extension"}
	}
	var out []map[string]string
	off := 0
	for off < len(outer.content) {
		desc, derr := walkTLV(outer.content, off)
		if derr != nil || desc.id != 0x30 {
			return nil, &invocationErr{msg: "invalid authorityInfoAccess extension"}
		}
		off = desc.next
		method, merr := walkTLV(desc.content, 0)
		if merr != nil || method.id != 0x06 {
			return nil, &invocationErr{msg: "invalid authorityInfoAccess extension"}
		}
		oid, oerr := decodeOIDContent(method.content)
		if oerr != nil {
			return nil, oerr
		}
		gn, gerr := walkTLV(desc.content, method.next)
		if gerr != nil || gn.next != len(desc.content) {
			return nil, &invocationErr{msg: "invalid authorityInfoAccess extension"}
		}
		rendered, rerr := renderV2GeneralName(gn)
		if rerr != nil {
			return nil, rerr
		}
		name := oid.String()
		switch {
		case oid.Equal(oidV2OCSP):
			name = "OCSP"
		case oid.Equal(oidV2CAIssuers):
			name = "caIssuers"
		}
		out = append(out, map[string]string{name: rendered})
	}
	return out, nil
}

// v2ReasonFlagNames are the ReasonFlags values in bit order.
var v2ReasonFlagNames = []string{
	"keyCompromise", "cACompromise", "affiliationChanged", "superseded",
	"cessationOfOperation", "certificateHold", "privilegeWithdrawn", "aACompromise",
}

// decodeV2ReasonBits renders the sorted ReasonFlags names of a BIT
// STRING body (the leading unused-bits octet included).
func decodeV2ReasonBits(content []byte) ([]string, error) {
	if len(content) == 0 || int(content[0]) >= 8 {
		return nil, &invocationErr{msg: "invalid reason flags"}
	}
	unused := int(content[0])
	bits := content[1:]
	total := len(bits)*8 - unused
	var names []string
	for bit := 0; bit < total && bit < len(v2ReasonFlagNames); bit++ {
		if bits[bit/8]&(1<<(7-bit%8)) != 0 {
			names = append(names, v2ReasonFlagNames[bit])
		}
	}
	sort.Strings(names)
	return names, nil
}

// decodeV2DistributionPoints ports _render_distribution_points.
func decodeV2DistributionPoints(der []byte) ([]map[string]any, error) {
	outer, err := walkTLV(der, 0)
	if err != nil || outer.id != 0x30 {
		return nil, &invocationErr{msg: "invalid distribution points extension"}
	}
	var out []map[string]any
	off := 0
	for off < len(outer.content) {
		dp, derr := walkTLV(outer.content, off)
		if derr != nil || dp.id != 0x30 {
			return nil, &invocationErr{msg: "invalid distribution points extension"}
		}
		off = dp.next
		value := map[string]any{
			"crlissuer":    []string{},
			"fullname":     []string{},
			"reasons":      []string{},
			"relativename": nil,
		}
		doff := 0
		for doff < len(dp.content) {
			field, ferr := walkTLV(dp.content, doff)
			if ferr != nil {
				return nil, &invocationErr{msg: "invalid distribution points extension"}
			}
			doff = field.next
			switch field.id {
			case 0xa0: // [0] EXPLICIT DistributionPointName
				inner, ierr := walkTLV(field.content, 0)
				if ierr != nil {
					return nil, &invocationErr{msg: "invalid distribution points extension"}
				}
				switch inner.id {
				case 0xa0: // fullName GeneralNames
					names, gerr := renderV2GeneralNamesContent(inner.content)
					if gerr != nil {
						return nil, gerr
					}
					value["fullname"] = names
				case 0xa1: // nameRelativeToCRLIssuer
					name, rerr := rfc4514String(derEncode(0, 16, true, inner.content))
					if rerr != nil {
						return nil, rerr
					}
					value["relativename"] = name
				}
			case 0x81: // [1] IMPLICIT reasons BIT STRING
				names, rerr := decodeV2ReasonBits(field.content)
				if rerr != nil {
					return nil, rerr
				}
				value["reasons"] = names
			case 0xa2: // [2] IMPLICIT cRLIssuer GeneralNames
				names, gerr := renderV2GeneralNamesContent(field.content)
				if gerr != nil {
					return nil, gerr
				}
				value["crlissuer"] = names
			}
		}
		out = append(out, value)
	}
	return out, nil
}

// decodeV2IDP ports _render_issuing_distribution_point (including the
// pinned "onysomereasons" typo key).
func decodeV2IDP(der []byte) (map[string]any, error) {
	outer, err := walkTLV(der, 0)
	if err != nil || outer.id != 0x30 {
		return nil, &invocationErr{msg: "invalid issuingDistributionPoint extension"}
	}
	value := map[string]any{
		"fullname":       []string{},
		"onysomereasons": []string{},
		"relativename":   nil,
		"onlyuser":       false,
		"onlyCA":         false,
		"onlyAA":         false,
		"indirectCRL":    false,
	}
	off := 0
	for off < len(outer.content) {
		field, ferr := walkTLV(outer.content, off)
		if ferr != nil {
			return nil, &invocationErr{msg: "invalid issuingDistributionPoint extension"}
		}
		off = field.next
		switch field.id {
		case 0xa0: // [0] EXPLICIT DistributionPointName
			inner, ierr := walkTLV(field.content, 0)
			if ierr != nil {
				return nil, &invocationErr{msg: "invalid issuingDistributionPoint extension"}
			}
			switch inner.id {
			case 0xa0:
				names, gerr := renderV2GeneralNamesContent(inner.content)
				if gerr != nil {
					return nil, gerr
				}
				value["fullname"] = names
			case 0xa1:
				name, rerr := rfc4514String(derEncode(0, 16, true, inner.content))
				if rerr != nil {
					return nil, rerr
				}
				value["relativename"] = name
			}
		case 0x81: // [1] IMPLICIT onlySomeReasons BIT STRING
			names, rerr := decodeV2ReasonBits(field.content)
			if rerr != nil {
				return nil, rerr
			}
			value["onysomereasons"] = names
		case 0x82: // [2] onlyContainsUserCerts
			value["onlyuser"] = len(field.content) > 0 && field.content[0] != 0
		case 0x83: // [3] onlyContainsCACerts
			value["onlyCA"] = len(field.content) > 0 && field.content[0] != 0
		case 0x85: // [5] indirectCRL
			value["indirectCRL"] = len(field.content) > 0 && field.content[0] != 0
		case 0x86: // [6] onlyContainsAttributeCerts
			value["onlyAA"] = len(field.content) > 0 && field.content[0] != 0
		}
	}
	return value, nil
}

// ---------------------------------------------------------------------------
// signature_algorithm naming

// v2SigAlgNames maps signature-algorithm OIDs onto the names the
// pinned signature_algorithm_oid._name reporting yields for the
// algorithm families the stdlib produces.
var v2SigAlgNames = []struct {
	oid  asn1.ObjectIdentifier
	name string
}{
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}, "md5WithRSAEncryption"},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}, "sha1WithRSAEncryption"},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, "sha256WithRSAEncryption"},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}, "sha384WithRSAEncryption"},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}, "sha512WithRSAEncryption"},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}, "RSASSA-PSS"},
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}, "ecdsa-with-SHA1"},
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, "ecdsa-with-SHA256"},
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, "ecdsa-with-SHA384"},
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}, "ecdsa-with-SHA512"},
	{asn1.ObjectIdentifier{1, 3, 101, 112}, "ED25519"},
}

// crlSigAlgOID extracts the signature-algorithm OID from the raw CRL.
func crlSigAlgOID(raw []byte) (asn1.ObjectIdentifier, bool) {
	outer, err := walkTLV(raw, 0)
	if err != nil || outer.id != 0x30 {
		return nil, false
	}
	tbs, err := walkTLV(outer.content, 0)
	if err != nil || tbs.id != 0x30 {
		return nil, false
	}
	alg, err := walkTLV(outer.content, tbs.next)
	if err != nil || alg.id != 0x30 {
		return nil, false
	}
	oidTLV, err := walkTLV(alg.content, 0)
	if err != nil || oidTLV.id != 0x06 {
		return nil, false
	}
	oid, err := decodeOIDContent(oidTLV.content)
	if err != nil {
		return nil, false
	}
	return oid, true
}

// v2SignatureAlgorithmName resolves signature_algorithm: the mapped
// name or the dotted-string fallback.
func v2SignatureAlgorithmName(list *x509.RevocationList) string {
	if oid, ok := crlSigAlgOID(list.Raw); ok {
		for _, entry := range v2SigAlgNames {
			if oid.Equal(entry.oid) {
				return entry.name
			}
		}
		return oid.String()
	}
	return list.SignatureAlgorithm.String()
}
