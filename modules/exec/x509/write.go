package x509

// R5.2b write-side subset of Salt's legacy x509 v1 family, pinned to
// saltstack/salt/modules/x509.py @ the workspace pin: write_pem,
// create_private_key, create_crl, get_signing_policy,
// create_certificate, create_csr, verify_signature and verify_crl.
// Like R5.2a the substrate is library-to-library (M2Crypto/pyOpenSSL
// are libssl bindings; the Go standard library replaces them) and the
// openssl binary is never spawned.
//
// Documented boundaries (v1 exact contracts unless noted):
//   - write_pem keeps the v1 preserve quirk: only pem_type
//     "CERTIFICATE" with overwrite=false salvages the existing
//     "(?:RSA )?PRIVATE KEY" and "DH PARAMETERS" entries and rewrites
//     the file as private_key + new certificate + dhparams. Files are
//     created 0600 (the source's set_umask(0o077) over fopen("w"));
//     there is no os.makedirs in the v1 source, so a missing parent
//     directory is a write error, not an implicit create.
//   - create_private_key generates RSA only (v1 is M2Crypto
//     RSA.gen_key; there is no algo parameter). Plain output is PKCS#8
//     "BEGIN PRIVATE KEY" via x509.MarshalPKCS8PrivateKey where the
//     pinned M2Crypto wrote PKCS#1 "BEGIN RSA PRIVATE KEY"; encrypted
//     output (passphrase set) keeps the upstream envelope: PKCS#1
//     block with Proc-Type/DEK-Info headers through the deprecated
//     stdlib x509.EncryptPEMBlock (cipher names aes_128_cbc default,
//     aes_192_cbc, aes_256_cbc, des_cbc, des_ede3_cbc). bits < 512
//     fails (the OpenSSL RSA floor); verbose is accepted and ignored
//     (M2Crypto printed keygen dots to stdout; exec functions return
//     values).
//   - create_crl mirrors the pyOpenSSL flow on
//     x509.CreateCertificateRevocationList: revoked entries carry
//     serial (pretty-hex or bare hex, optionally read from
//     "certificate" via read_certificate), revocation_date
//     ("%Y-%m-%d %H:%M:%S", default now), not_after expiry filtering
//     unless include_expired, and the reason codes. Go requires a CRL
//     number; 1 is emitted (same documented choice as the tls
//     family). digest "" falls back to SHA-256 where the pinned
//     pyOpenSSL default was md5 (documented divergence; md5 conflicts
//     with every modern profile). The Windows/sys.maxsize serial
//     reduction in the source is an M2Crypto C-long overflow guard
//     with no big.Int equivalent.
//   - get_signing_policy resolves x509_signing_policies through the
//     optional pillar.get then config.option delegates (degrading to
//     absent, exactly like a minion without configuration), merges the
//     list-of-dicts form, drops signing_private_key and normalizes
//     signing_cert to a single CERTIFICATE PEM entry. A missing policy
//     returns the exact string "Signing policy X does not exist.".
//   - create_certificate: ca_server with signing_policy resolves to a
//     deterministic UnsupportedError (master-surface exclusion; the
//     v1 publish.publish call and sign_remote_certificate stay
//     excluded per ADR 0003); ca_server without signing_policy keeps
//     the exact v1 SaltInvocationError text (including the missing
//     space). A named-but-missing signing_policy is a stable error
//     where v1 crashed on kwargs.update(None). The subject is one RDN
//     per attribute in the alphabetical attribute-name order of the
//     source's sorted(subject.nid) loop (Email aliases emailAddress);
//     CSR subjects keep their wire order and kwargs override in
//     place. Extensions accept the v1 openssl text forms for
//     basicConstraints (DER DEFAULT omission: CA:FALSE encodes as an
//     empty SEQUENCE), keyUsage, extendedKeyUsage,
//     subjectKeyIdentifier ("hash" substitutes the pretty-hex SHA-1 of
//     the RSA modulus, or of the SPKI DER for the EC/Ed25519 keys v1
//     never generated), authorityKeyIdentifier (keyid form only: the
//     issuer's subjectKeyIdentifier or the SHA-1 of its public key;
//     "issuer:always" DirName+serial material is not representable in
//     Go's flat field, the same boundary the tls family documents),
//     subjectAltName (DNS/IP/email/URI; "IP Address:" is rewritten to
//     "IP:" like the source), nsComment and nsCertType; extension
//     families outside this profile raise where the source would ask
//     openssl to encode them. Serial numbers come from crypto/rand
//     (v1 used random.getrandbits) and render as _dec2hex pretty hex.
//     Go always emits X.509 v3 TBSees, so a version kwarg other than 3
//     is accepted but the certificate still reports Version 3. When
//     not_after is omitted it is anchored at now (not at not_before),
//     reproducing the v1 quirk. copypath writes {copypath}/
//     ({CN}-)?{serial_pretty_hex}.crt. The mismatch error keeps the
//     v1 text "does no match" with PEM bodies redacted.
//   - create_csr: private_key defaults from public_key and vice versa
//     (passphrases cross-default), authorityKeyIdentifier is skipped
//     entirely, subjectKeyIdentifier "hash" uses the CSR key. Go's
//     CreateCertificateRequest always writes PKCS#10 version 0, so the
//     version kwarg cannot lower it (documented divergence).
//   - verify_signature resolves the signing public key as an object
//     (public key, certificate, CSR or private key PEM/path) and
//     checks the signature with cert.CheckSignature; without
//     signing_pub_key it self-checks against the certificate's own
//     key (M2Crypto X509.verify with pkey=None). Mismatches return
//     False, never raise.
//   - verify_crl parses the X509 CRL entry and the certificate and
//     returns CheckSignatureFrom == nil. Mechanism divergence: the
//     source shelled out to `openssl crl -CAfile` and grepped stderr
//     for "verify OK"; a structurally valid PEM whose DER is not a
//     CRL therefore returns False here (the CLI also failed without
//     printing "verify OK") while PEM-entry failures keep raising.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

// pyDateTimeFormat is the Python strftime literal the source
// interpolates into its error messages.
const pyDateTimeFormat = "%Y-%m-%d %H:%M:%S"

// hexDecode is the lowercase/uppercase-tolerant hex decoder for the
// precomputed-hash extension values.
func hexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// ---------------------------------------------------------------------------
// write_pem

type writePemArgs struct {
	Text      string  `statekit:"required"`
	Path      string  `statekit:"required"`
	Overwrite *bool   `statekit:"name=overwrite"`
	PemType   *string `statekit:"name=pem_type"`
}

type writePemFunc struct{}

func (writePemFunc) Name() string { return "x509.write_pem" }
func (writePemFunc) Args() any    { return writePemArgs{} }
func (writePemFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*writePemArgs)
	overwrite := true
	if a.Overwrite != nil {
		overwrite = *a.Overwrite
	}
	pemType := ""
	if a.PemType != nil {
		pemType = *a.PemType
	}
	return writePemImpl(rt, a.Text, a.Path, overwrite, pemType)
}

// writePemImpl ports write_pem: normalize the entry, optionally
// salvage existing private key / DH parameters blocks, write with
// 0600 (the set_umask(0o077) creation mode) and return the verbatim
// reply string.
func writePemImpl(rt *runtime.Runtime, text, dest string, overwrite bool, pemType string) (string, error) {
	normalized, err := getPemEntryImpl(rt, text, pemType)
	if err != nil {
		return "", err
	}

	// v1 preserves pre-existing key material only when replacing a
	// CERTIFICATE with overwrite=False.
	var privateKeyPEM, dhParams string
	if pemType == "CERTIFICATE" && !overwrite {
		if info, serr := rt.FS.Stat(dest); serr == nil && info != nil && info.Mode().IsRegular() {
			contents, rerr := runtime.ReadFileBounded(rt.FS, dest, maxPEMBytes)
			if rerr != nil {
				return "", stableReadError(rerr)
			}
			if v, derr := getPemEntryImpl(rt, string(contents), "DH PARAMETERS"); derr == nil {
				dhParams = v
			}
			if v, derr := getPemEntryImpl(rt, string(contents), "(?:RSA )?PRIVATE KEY"); derr == nil {
				privateKeyPEM = v
			}
		}
	}

	var out strings.Builder
	if privateKeyPEM != "" {
		out.WriteString(privateKeyPEM)
	}
	out.WriteString(normalized)
	if dhParams != "" {
		out.WriteString(dhParams)
	}
	if werr := rt.FS.WriteFile(dest, []byte(out.String()), 0o600); werr != nil {
		return "", &invocationErr{msg: fmt.Sprintf("Could not write to %s", dest)}
	}
	return fmt.Sprintf("PEM written to %s", dest), nil
}

// ---------------------------------------------------------------------------
// create_private_key

type createPrivateKeyArgs struct {
	Path       *string `statekit:"name=path"`
	Text       bool    `statekit:"name=text"`
	Bits       *int    `statekit:"name=bits"`
	Passphrase *string `statekit:"name=passphrase"`
	Cipher     *string `statekit:"name=cipher"`
	Verbose    *bool   `statekit:"name=verbose"`
}

type createPrivateKeyFunc struct{}

func (createPrivateKeyFunc) Name() string { return "x509.create_private_key" }
func (createPrivateKeyFunc) Args() any    { return createPrivateKeyArgs{} }
func (createPrivateKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*createPrivateKeyArgs)
	bits := 2048
	if a.Bits != nil {
		bits = *a.Bits
	}
	cipher := "aes_128_cbc"
	if a.Cipher != nil && *a.Cipher != "" {
		cipher = *a.Cipher
	}
	return createPrivateKeyImpl(rt, a.Path, a.Text, bits, a.Passphrase, cipher)
}

// pemCipherFor maps the M2Crypto cipher names onto the stdlib
// EncryptPEMBlock cipher values.
func pemCipherFor(name string) (x509.PEMCipher, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "aes_128_cbc", "aes-128-cbc":
		return x509.PEMCipherAES128, true
	case "aes_192_cbc", "aes-192-cbc":
		return x509.PEMCipherAES192, true
	case "aes_256_cbc", "aes-256-cbc":
		return x509.PEMCipherAES256, true
	case "des_cbc", "des-cbc":
		return x509.PEMCipherDES, true
	case "des_ede3_cbc", "des-ede3-cbc":
		return x509.PEMCipher3DES, true
	}
	return 0, false
}

func createPrivateKeyImpl(rt *runtime.Runtime, dest *string, asText bool, bits int, passphrase *string, cipher string) (any, error) {
	if dest == nil && !asText {
		return nil, &invocationErr{msg: "Either path or text must be specified."}
	}
	if dest != nil && asText {
		return nil, &invocationErr{msg: "Either path or text must be specified, not both."}
	}
	// M2Crypto rides OpenSSL's RSA generator, whose floor is 512 bits.
	if bits < 512 {
		return nil, &invocationErr{msg: "bits must be at least 512"}
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, &invocationErr{msg: "Could not generate private key"}
	}

	var pemBytes []byte
	if passphrase != nil {
		cipherEnum, ok := pemCipherFor(cipher)
		if !ok {
			return nil, &invocationErr{msg: fmt.Sprintf("unsupported cipher %q", cipher)}
		}
		// Deprecated stdlib API, retained because it is the only
		// stdlib producer of the legacy Proc-Type/DEK-Info envelope
		// M2Crypto's save_key_bio(cipher=...) writes.
		block, eerr := x509.EncryptPEMBlock(
			rand.Reader, "RSA PRIVATE KEY",
			x509.MarshalPKCS1PrivateKey(key), []byte(*passphrase), cipherEnum)
		if eerr != nil {
			return nil, &invocationErr{msg: "Could not encrypt private key"}
		}
		// Go renders the DEK-Info IV in lowercase hex; OpenSSL (and
		// Salt's PEM-entry regex) only recognize uppercase, so the
		// header is normalized to the upstream convention.
		if dek, ok := block.Headers["DEK-Info"]; ok {
			if idx := strings.Index(dek, ","); idx >= 0 {
				block.Headers["DEK-Info"] =
					dek[:idx+1] + strings.ToUpper(dek[idx+1:])
			}
		}
		pemBytes = pem.EncodeToMemory(block)
	} else {
		der, derr := x509.MarshalPKCS8PrivateKey(key)
		if derr != nil {
			return nil, &invocationErr{msg: "Could not encode private key"}
		}
		pemBytes = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}

	if dest != nil {
		return writePemImpl(rt, string(pemBytes), *dest, true, "(?:RSA )?PRIVATE KEY")
	}
	return string(pemBytes), nil
}

// ---------------------------------------------------------------------------
// create_crl

type createCrlArgs struct {
	Path                        *string          `statekit:"name=path"`
	Text                        bool             `statekit:"name=text"`
	SigningPrivateKey           *string          `statekit:"name=signing_private_key"`
	SigningPrivateKeyPassphrase *string          `statekit:"name=signing_private_key_passphrase"`
	SigningCert                 *string          `statekit:"name=signing_cert"`
	Revoked                     []map[string]any `statekit:"name=revoked"`
	IncludeExpired              *bool            `statekit:"name=include_expired"`
	DaysValid                   *int             `statekit:"name=days_valid"`
	Digest                      *string          `statekit:"name=digest"`
}

type createCrlFunc struct{}

func (createCrlFunc) Name() string { return "x509.create_crl" }
func (createCrlFunc) Args() any    { return createCrlArgs{} }
func (createCrlFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*createCrlArgs)
	return createCrlImpl(rt, a)
}

// crlReasonCodes maps the source's reason names onto RFC 5280
// CRLReason codes (Go rejects 7 and anything above 10).
var crlReasonCodes = map[string]int{
	"unspecified":          0,
	"keyCompromise":        1,
	"CACompromise":         2,
	"affiliationChanged":   3,
	"superseded":           4,
	"cessationOfOperation": 5,
	"certificateHold":      6,
	"removeFromCRL":        8,
	"privilegeWithdrawn":   9,
	"aACompromise":         10,
}

func createCrlImpl(rt *runtime.Runtime, a *createCrlArgs) (any, error) {
	if a.Path == nil && !a.Text {
		// v1 crashes writing to a None path; the deterministic port
		// reuses the family's target error.
		return nil, &invocationErr{msg: "Either path or text must be specified."}
	}
	if a.Path != nil && a.Text {
		return nil, &invocationErr{msg: "Either path or text must be specified, not both."}
	}
	daysValid := 100
	if a.DaysValid != nil {
		daysValid = *a.DaysValid
	}
	includeExpired := a.IncludeExpired != nil && *a.IncludeExpired

	cert, err := getCertificateObj(rt, strOrEmpty(a.SigningCert))
	if err != nil {
		return nil, err
	}
	priv, err := loadSigningKey(rt, a.SigningPrivateKey, a.SigningPrivateKeyPassphrase)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	var entries []x509.RevocationListEntry
	for _, item := range a.Revoked {
		entry, perr := parseRevokedEntry(rt, item, includeExpired, now)
		if perr != nil {
			return nil, perr
		}
		if entry == nil {
			continue // expired-and-filtered, the source's `continue`
		}
		entries = append(entries, *entry)
	}

	sigAlg, aerr := signatureAlgorithmForWrite(crlDigest(a.Digest), priv)
	if aerr != nil {
		return nil, aerr
	}
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                now,
		NextUpdate:                now.Add(time.Duration(daysValid) * 24 * time.Hour),
		RevokedCertificateEntries: entries,
		SignatureAlgorithm:        sigAlg,
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, &invocationErr{msg: fmt.Sprintf("unsupported signing key type %T", priv)}
	}
	der, cerr := x509.CreateRevocationList(rand.Reader, tmpl, cert, signer)
	if cerr != nil {
		return nil, &invocationErr{msg: fmt.Sprintf("Could not create CRL: %v", cerr)}
	}
	crlPEM := string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))

	if a.Text {
		return crlPEM, nil
	}
	return writePemImpl(rt, crlPEM, *a.Path, true, "X509 CRL")
}

// crlDigest resolves the digest kwarg; the empty digest selects the
// SHA-256 default (documented divergence from pyOpenSSL's md5).
func crlDigest(d *string) string {
	if d != nil && *d != "" {
		return *d
	}
	return "sha256"
}

// parseRevokedEntry ports one revoked-list dict. A nil entry means the
// certificate was expired and filtered out.
func parseRevokedEntry(rt *runtime.Runtime, item map[string]any, includeExpired bool, now time.Time) (*x509.RevocationListEntry, error) {
	if certRef, ok := item["certificate"]; ok {
		props, err := readCertificateImpl(rt, pyRender(certRef))
		if err != nil {
			return nil, err
		}
		item["serial_number"] = props["Serial Number"]
		item["not_after"] = props["Not After"]
	}
	rawSerial, ok := item["serial_number"]
	if !ok || rawSerial == nil {
		return nil, &invocationErr{msg: "revoked entry requires serial_number or certificate"}
	}
	serial, ok := new(big.Int).SetString(strings.ReplaceAll(pyRender(rawSerial), ":", ""), 16)
	if !ok {
		return nil, &invocationErr{msg: fmt.Sprintf("invalid serial_number %q", pyRender(rawSerial))}
	}

	if notAfter, has := item["not_after"]; has && !includeExpired {
		expiry, perr := time.Parse(dateTimeLayout, pyRender(notAfter))
		if perr != nil {
			return nil, &invocationErr{msg: fmt.Sprintf(
				"not_after: %s is not in required format %s", pyRender(notAfter), dateTimeLayout)}
		}
		if now.After(expiry) {
			return nil, nil
		}
	}

	revocationDate := now
	if raw, has := item["revocation_date"]; has {
		parsed, perr := time.Parse(dateTimeLayout, pyRender(raw))
		if perr != nil {
			return nil, &invocationErr{msg: fmt.Sprintf(
				"revocation_date: %s is not in required format %s", pyRender(raw), pyDateTimeFormat)}
		}
		revocationDate = parsed
	}

	entry := &x509.RevocationListEntry{
		SerialNumber:   serial,
		RevocationTime: revocationDate,
	}
	if raw, has := item["reason"]; has {
		code, known := crlReasonCodes[pyRender(raw)]
		if !known {
			return nil, &invocationErr{msg: fmt.Sprintf("invalid reason %q", pyRender(raw))}
		}
		entry.ReasonCode = code
	}
	return entry, nil
}

// loadSigningKey resolves the signing private key through the v1
// private-key loader ((?:RSA )?PRIVATE KEY PEM entry + optional
// passphrase).
func loadSigningKey(rt *runtime.Runtime, key, passphrase *string) (any, error) {
	entry, err := getPemEntryImpl(rt, strOrEmpty(key), "(?:RSA )?PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	return parsePrivateKeyPEM([]byte(entry), passphrase)
}

// ---------------------------------------------------------------------------
// get_signing_policy

type getSigningPolicyArgs struct {
	SigningPolicyName string `statekit:"required,name=signing_policy_name"`
}

type getSigningPolicyFunc struct{}

func (getSigningPolicyFunc) Name() string { return "x509.get_signing_policy" }
func (getSigningPolicyFunc) Args() any    { return getSigningPolicyArgs{} }
func (getSigningPolicyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*getSigningPolicyArgs)
	return getSigningPolicyImpl(rt, a.SigningPolicyName)
}

// delegatePolicies resolves the x509_signing_policies mapping through
// pillar.get and then config.option, degrading to nil when neither
// delegate is registered (a minion without configuration).
func delegatePolicies(rt *runtime.Runtime) map[string]any {
	for _, delegate := range []string{"pillar.get", "config.option"} {
		res, err := callDelegate(rt, delegate,
			map[string]any{"key": "x509_signing_policies", "default": nil})
		if err != nil {
			continue
		}
		if m, ok := res.(map[string]any); ok {
			return m
		}
	}
	return nil
}

// lookupSigningPolicy ports _get_signing_policy, including the
// list-of-dicts merge.
func lookupSigningPolicy(rt *runtime.Runtime, name string) (map[string]any, bool) {
	policies := delegatePolicies(rt)
	if policies == nil {
		return nil, false
	}
	raw, ok := policies[name]
	if !ok {
		return nil, false
	}
	switch v := raw.(type) {
	case map[string]any:
		return v, true
	case []any:
		merged := map[string]any{}
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				for key, val := range m {
					merged[key] = val
				}
			}
		}
		return merged, true
	}
	return nil, false
}

func getSigningPolicyImpl(rt *runtime.Runtime, name string) (any, error) {
	policy, ok := lookupSigningPolicy(rt, name)
	if !ok {
		return fmt.Sprintf("Signing policy %s does not exist.", name), nil
	}
	delete(policy, "signing_private_key")
	if raw, has := policy["signing_cert"]; has && raw != nil {
		entry, err := getPemEntryImpl(rt, pyRender(raw), "CERTIFICATE")
		if err != nil {
			return nil, err
		}
		policy["signing_cert"] = entry
	}
	return policy, nil
}

// ---------------------------------------------------------------------------
// create_certificate

type createCertificateArgs struct {
	Path          *string `statekit:"name=path"`
	Text          bool    `statekit:"name=text"`
	Overwrite     *bool   `statekit:"name=overwrite"`
	CAServer      *string `statekit:"name=ca_server"`
	SigningPolicy *string `statekit:"name=signing_policy"`

	SigningPrivateKey           *string `statekit:"name=signing_private_key"`
	SigningPrivateKeyPassphrase *string `statekit:"name=signing_private_key_passphrase"`
	SigningCert                 *string `statekit:"name=signing_cert"`
	PublicKey                   *string `statekit:"name=public_key"`
	PublicKeyPassphrase         *string `statekit:"name=public_key_passphrase"`
	CSR                         *string `statekit:"name=csr"`

	CN           *string `statekit:"name=CN"`
	C            *string `statekit:"name=C"`
	ST           *string `statekit:"name=ST"`
	L            *string `statekit:"name=L"`
	O            *string `statekit:"name=O"`
	OU           *string `statekit:"name=OU"`
	SN           *string `statekit:"name=SN"`
	GN           *string `statekit:"name=GN"`
	Email        *string `statekit:"name=Email"`
	EmailAddress *string `statekit:"name=emailAddress"`
	SerialNumber *string `statekit:"name=serialNumber"`
	Street       *string `statekit:"name=street"`
	PostalCode   *string `statekit:"name=postalCode"`
	DC           *string `statekit:"name=DC"`
	UID          *string `statekit:"name=UID"`

	BasicConstraints       *string `statekit:"name=basicConstraints"`
	KeyUsage               *string `statekit:"name=keyUsage"`
	ExtendedKeyUsage       *string `statekit:"name=extendedKeyUsage"`
	SubjectKeyIdentifier   *string `statekit:"name=subjectKeyIdentifier"`
	AuthorityKeyIdentifier *string `statekit:"name=authorityKeyIdentifier"`
	SubjectAltName         *string `statekit:"name=subjectAltName"`
	NsComment              *string `statekit:"name=nsComment"`
	NsCertType             *string `statekit:"name=nsCertType"`

	DaysValid       *int    `statekit:"name=days_valid"`
	Version         *int    `statekit:"name=version"`
	SerialNumberHex *string `statekit:"name=serial_number"`
	SerialBits      *int    `statekit:"name=serial_bits"`
	Algorithm       *string `statekit:"name=algorithm"`
	NotBefore       *string `statekit:"name=not_before"`
	NotAfter        *string `statekit:"name=not_after"`
	Copypath        *string `statekit:"name=copypath"`
	PrependCN       *bool   `statekit:"name=prepend_cn"`
}

type createCertificateFunc struct{}

func (createCertificateFunc) Name() string { return "x509.create_certificate" }
func (createCertificateFunc) Args() any    { return createCertificateArgs{} }
func (createCertificateFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*createCertificateArgs)
	return createCertificateImpl(rt, a)
}

// kwargs renders the non-nil kwarg fields as the effective kwargs map
// the source would have received.
func (a *createCertificateArgs) kwargs() map[string]any {
	m := map[string]any{}
	putS := func(k string, v *string) {
		if v != nil {
			m[k] = *v
		}
	}
	putI := func(k string, v *int) {
		if v != nil {
			m[k] = *v
		}
	}
	putB := func(k string, v *bool) {
		if v != nil {
			m[k] = *v
		}
	}
	putS("signing_private_key", a.SigningPrivateKey)
	putS("signing_private_key_passphrase", a.SigningPrivateKeyPassphrase)
	putS("signing_cert", a.SigningCert)
	putS("signing_policy", a.SigningPolicy)
	putS("public_key", a.PublicKey)
	putS("public_key_passphrase", a.PublicKeyPassphrase)
	putS("csr", a.CSR)
	putS("CN", a.CN)
	putS("C", a.C)
	putS("ST", a.ST)
	putS("L", a.L)
	putS("O", a.O)
	putS("OU", a.OU)
	putS("SN", a.SN)
	putS("GN", a.GN)
	putS("Email", a.Email)
	putS("emailAddress", a.EmailAddress)
	putS("serialNumber", a.SerialNumber)
	putS("street", a.Street)
	putS("postalCode", a.PostalCode)
	putS("DC", a.DC)
	putS("UID", a.UID)
	putS("basicConstraints", a.BasicConstraints)
	putS("keyUsage", a.KeyUsage)
	putS("extendedKeyUsage", a.ExtendedKeyUsage)
	putS("subjectKeyIdentifier", a.SubjectKeyIdentifier)
	putS("authorityKeyIdentifier", a.AuthorityKeyIdentifier)
	putS("subjectAltName", a.SubjectAltName)
	putS("nsComment", a.NsComment)
	putS("nsCertType", a.NsCertType)
	putI("days_valid", a.DaysValid)
	putI("version", a.Version)
	putS("serial_number", a.SerialNumberHex)
	putI("serial_bits", a.SerialBits)
	putS("algorithm", a.Algorithm)
	putS("not_before", a.NotBefore)
	putS("not_after", a.NotAfter)
	putS("copypath", a.Copypath)
	putB("prepend_cn", a.PrependCN)
	return m
}

func createCertificateImpl(rt *runtime.Runtime, a *createCertificateArgs) (any, error) {
	if a.Path == nil && !a.Text {
		return nil, &invocationErr{msg: "Either path or text must be specified."}
	}
	if a.Path != nil && a.Text {
		return nil, &invocationErr{msg: "Either path or text must be specified, not both."}
	}
	overwrite := true
	if a.Overwrite != nil {
		overwrite = *a.Overwrite
	}

	kwargs := a.kwargs()
	if a.CAServer != nil && *a.CAServer != "" {
		if _, ok := kwargs["signing_policy"]; !ok {
			return nil, &invocationErr{msg: fmt.Sprintf(
				"signing_policy must be specifiedif requesting remote certificate from ca_server %s.",
				*a.CAServer)}
		}
		// The master-minion publish surface stays excluded (ADR 0003);
		// the deterministic mapping is an unsupported error.
		return nil, &runtime.UnsupportedError{
			Kind: "master-surface",
			Name: fmt.Sprintf("x509.sign_remote_certificate (ca_server %s)", *a.CAServer),
		}
	}

	if raw, ok := kwargs["signing_policy"]; ok {
		name := pyRender(raw)
		policy, found := lookupSigningPolicy(rt, name)
		if !found {
			// v1 crashed on kwargs.update(None); the port fails with
			// the family's stable policy-missing text.
			return nil, &invocationErr{msg: fmt.Sprintf("Signing policy %s does not exist.", name)}
		}
		for key, val := range policy {
			kwargs[key] = val
		}
	}

	// CERT_DEFAULTS
	daysValid := 365
	if v, ok := kwInt(kwargs, "days_valid"); ok {
		daysValid = v
	}
	serialBits := 64
	if v, ok := kwInt(kwargs, "serial_bits"); ok {
		serialBits = v
	}
	algorithm := "sha256"
	if v, ok := kwString(kwargs, "algorithm"); ok {
		algorithm = v
	}

	// Serial number: explicit pretty/plain hex, or crypto/rand bits.
	serialPretty := ""
	if v, ok := kwString(kwargs, "serial_number"); ok {
		serialPretty = v
	} else {
		random, rerr := randomSerialHex(serialBits)
		if rerr != nil {
			return nil, rerr
		}
		serialPretty = random
	}
	serial, ok := new(big.Int).SetString(strings.ReplaceAll(serialPretty, ":", ""), 16)
	if !ok {
		return nil, &invocationErr{msg: fmt.Sprintf("invalid serial_number %q", serialPretty)}
	}

	// Validity: explicit boundaries win; the dynamic not_after is
	// anchored at now (v1 quirk, not at not_before).
	notBefore := time.Now().UTC().Truncate(time.Second)
	if v, ok := kwString(kwargs, "not_before"); ok {
		parsed, perr := time.Parse(dateTimeLayout, v)
		if perr != nil {
			return nil, &invocationErr{msg: fmt.Sprintf(
				"not_before: %s is not in required format %s", v, pyDateTimeFormat)}
		}
		notBefore = parsed
	}
	notAfter := time.Now().UTC().Truncate(time.Second).Add(time.Duration(daysValid) * 24 * time.Hour)
	if v, ok := kwString(kwargs, "not_after"); ok {
		parsed, perr := time.Parse(dateTimeLayout, v)
		if perr != nil {
			return nil, &invocationErr{msg: fmt.Sprintf(
				"not_after: %s is not in required format %s", v, pyDateTimeFormat)}
		}
		notAfter = parsed
	}

	// Public key: csr, explicit public_key, or self-signed fallback.
	publicKey, hasPub := kwString(kwargs, "public_key")
	csrText, hasCSR := kwString(kwargs, "csr")
	if !hasPub && !hasCSR {
		v, ok := kwString(kwargs, "signing_private_key")
		if !ok {
			return nil, &invocationErr{msg: "signing_private_key is required"}
		}
		publicKey = v
		if pass, ok := kwString(kwargs, "signing_private_key_passphrase"); ok {
			kwargs["public_key_passphrase"] = pass
		}
	}

	csrexts := map[string]string{}
	var subjectAttrs []nameAttr
	if hasCSR {
		publicKey = csrText
		req, rerr := getRequestObj(rt, csrText)
		if rerr != nil {
			return nil, rerr
		}
		attrs, serr := subjectFromRaw(req.RawSubject)
		if serr != nil {
			return nil, serr
		}
		subjectAttrs = attrs
		props, perr := readCsrImpl(rt, csrText)
		if perr != nil {
			return nil, perr
		}
		if exts, ok := props["X509v3 Extensions"].(map[string]string); ok {
			csrexts = exts
		}
	}

	pubPass := ""
	if v, ok := kwString(kwargs, "public_key_passphrase"); ok {
		pubPass = v
	}
	pub, err := getPublicKeyObj(rt, publicKey, pubPass)
	if err != nil {
		return nil, err
	}

	subjectAttrs = applySubjectOverrides(subjectAttrs, kwargs)
	subjectDER, err := buildSubjectDER(subjectAttrs)
	if err != nil {
		return nil, err
	}

	var signingCert *x509.Certificate
	if v, ok := kwString(kwargs, "signing_cert"); ok {
		signingCert, err = getCertificateObj(rt, v)
		if err != nil {
			return nil, err
		}
	}

	exts, err := buildCertificateExtensions(kwargs, csrexts, signingCert, pub, false)
	if err != nil {
		return nil, err
	}

	privPass := ""
	if v, ok := kwString(kwargs, "signing_private_key_passphrase"); ok {
		privPass = v
	}
	priv, err := loadSigningKey(rt, stringPtr(kwargs["signing_private_key"]), stringPtr(privPass))
	if err != nil {
		return nil, err
	}

	// verify_private_key: the signing key must match the signing
	// certificate (or the new self-signed public key).
	var signingPub any = pub
	if signingCert != nil {
		signingPub = signingCert.PublicKey
	}
	privPubPEM, perr := publicKeyPEMOf(publicOf(priv))
	if perr != nil {
		return nil, perr
	}
	certPubPEM, perr := publicKeyPEMOf(signingPub)
	if perr != nil {
		return nil, perr
	}
	if privPubPEM != certPubPEM {
		return nil, &invocationErr{msg: fmt.Sprintf(
			"signing_private_key: %s does no match signing_cert: %s",
			redactMaterial(pyRender(kwargs["signing_private_key"])),
			redactMaterial(pyRender(kwargs["signing_cert"])))}
	}

	sigAlg, aerr := signatureAlgorithmForWrite(algorithm, priv)
	if aerr != nil {
		return nil, aerr
	}
	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		RawSubject:         subjectDER,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		ExtraExtensions:    exts,
		SignatureAlgorithm: sigAlg,
	}
	parent := tmpl
	if signingCert != nil {
		parent = signingCert
	}
	der, cerr := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if cerr != nil {
		return nil, &invocationErr{msg: fmt.Sprintf("Could not create certificate: %v", cerr)}
	}
	created, cerr2 := x509.ParseCertificate(der)
	if cerr2 != nil {
		return nil, &invocationErr{msg: "Could not parse created certificate"}
	}
	if !verifyCertSignature(created, signingPub) {
		return nil, &invocationErr{msg: "failed to verify certificate signature"}
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	if copypath, ok := kwString(kwargs, "copypath"); ok {
		prepend := ""
		if v, ok := kwBool(kwargs, "prepend_cn"); ok && v {
			cn, ok := kwString(kwargs, "CN")
			if !ok {
				return nil, &invocationErr{msg: "KeyError: 'CN'"}
			}
			prepend = cn + "-"
		}
		if _, werr := writePemImpl(rt, certPEM,
			path.Join(copypath, prepend+serialPretty+".crt"), true, "CERTIFICATE"); werr != nil {
			return nil, werr
		}
	}

	if a.Path != nil {
		return writePemImpl(rt, certPEM, *a.Path, overwrite, "CERTIFICATE")
	}
	return certPEM, nil
}

// ---------------------------------------------------------------------------
// create_csr

type createCsrArgs struct {
	Path      *string `statekit:"name=path"`
	Text      bool    `statekit:"name=text"`
	Algorithm *string `statekit:"name=algorithm"`
	Version   *int    `statekit:"name=version"`

	PrivateKey           *string `statekit:"name=private_key"`
	PrivateKeyPassphrase *string `statekit:"name=private_key_passphrase"`
	PublicKey            *string `statekit:"name=public_key"`
	PublicKeyPassphrase  *string `statekit:"name=public_key_passphrase"`

	CN           *string `statekit:"name=CN"`
	C            *string `statekit:"name=C"`
	ST           *string `statekit:"name=ST"`
	L            *string `statekit:"name=L"`
	O            *string `statekit:"name=O"`
	OU           *string `statekit:"name=OU"`
	SN           *string `statekit:"name=SN"`
	GN           *string `statekit:"name=GN"`
	Email        *string `statekit:"name=Email"`
	EmailAddress *string `statekit:"name=emailAddress"`
	SerialNumber *string `statekit:"name=serialNumber"`
	Street       *string `statekit:"name=street"`
	PostalCode   *string `statekit:"name=postalCode"`
	DC           *string `statekit:"name=DC"`
	UID          *string `statekit:"name=UID"`

	BasicConstraints       *string `statekit:"name=basicConstraints"`
	KeyUsage               *string `statekit:"name=keyUsage"`
	ExtendedKeyUsage       *string `statekit:"name=extendedKeyUsage"`
	SubjectKeyIdentifier   *string `statekit:"name=subjectKeyIdentifier"`
	AuthorityKeyIdentifier *string `statekit:"name=authorityKeyIdentifier"`
	SubjectAltName         *string `statekit:"name=subjectAltName"`
	NsComment              *string `statekit:"name=nsComment"`
	NsCertType             *string `statekit:"name=nsCertType"`
}

type createCsrFunc struct{}

func (createCsrFunc) Name() string { return "x509.create_csr" }
func (createCsrFunc) Args() any    { return createCsrArgs{} }
func (createCsrFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*createCsrArgs)
	return createCsrImpl(rt, a)
}

func (a *createCsrArgs) kwargs() map[string]any {
	m := map[string]any{}
	putS := func(k string, v *string) {
		if v != nil {
			m[k] = *v
		}
	}
	putS("private_key", a.PrivateKey)
	putS("private_key_passphrase", a.PrivateKeyPassphrase)
	putS("public_key", a.PublicKey)
	putS("public_key_passphrase", a.PublicKeyPassphrase)
	putS("CN", a.CN)
	putS("C", a.C)
	putS("ST", a.ST)
	putS("L", a.L)
	putS("O", a.O)
	putS("OU", a.OU)
	putS("SN", a.SN)
	putS("GN", a.GN)
	putS("Email", a.Email)
	putS("emailAddress", a.EmailAddress)
	putS("serialNumber", a.SerialNumber)
	putS("street", a.Street)
	putS("postalCode", a.PostalCode)
	putS("DC", a.DC)
	putS("UID", a.UID)
	putS("basicConstraints", a.BasicConstraints)
	putS("keyUsage", a.KeyUsage)
	putS("extendedKeyUsage", a.ExtendedKeyUsage)
	putS("subjectKeyIdentifier", a.SubjectKeyIdentifier)
	putS("authorityKeyIdentifier", a.AuthorityKeyIdentifier)
	putS("subjectAltName", a.SubjectAltName)
	putS("nsComment", a.NsComment)
	putS("nsCertType", a.NsCertType)
	return m
}

func createCsrImpl(rt *runtime.Runtime, a *createCsrArgs) (any, error) {
	if a.Path == nil && !a.Text {
		return nil, &invocationErr{msg: "Either path or text must be specified."}
	}
	if a.Path != nil && a.Text {
		return nil, &invocationErr{msg: "Either path or text must be specified, not both."}
	}

	kwargs := a.kwargs()
	algorithm := "sha256"
	if v, ok := kwString(kwargs, "algorithm"); ok {
		algorithm = v
	}

	// private_key falls back to public_key (v1 logs a warning); the
	// public key falls back to the private key; passphrases
	// cross-default.
	privateKey, hasPriv := kwString(kwargs, "private_key")
	if !hasPriv {
		if v, ok := kwString(kwargs, "public_key"); ok {
			privateKey = v
			hasPriv = true
		}
	}
	if !hasPriv {
		return nil, &invocationErr{msg: "private_key is required"}
	}
	publicKey, hasPublic := kwString(kwargs, "public_key")
	if !hasPublic {
		publicKey = privateKey
	}
	privPass, hasPrivPass := kwString(kwargs, "private_key_passphrase")
	pubPass, hasPubPass := kwString(kwargs, "public_key_passphrase")
	if hasPubPass && !hasPrivPass {
		privPass = pubPass
	}
	if hasPrivPass && !hasPubPass {
		pubPass = privPass
	}

	pub, err := getPublicKeyObj(rt, publicKey, pubPass)
	if err != nil {
		return nil, err
	}
	subjectAttrs := applySubjectOverrides(nil, kwargs)
	subjectDER, err := buildSubjectDER(subjectAttrs)
	if err != nil {
		return nil, err
	}

	exts, err := buildCertificateExtensions(kwargs, nil, nil, pub, true)
	if err != nil {
		return nil, err
	}

	priv, err := loadSigningKey(rt, &privateKey, &privPass)
	if err != nil {
		return nil, err
	}
	sigAlg, aerr := signatureAlgorithmForWrite(algorithm, priv)
	if aerr != nil {
		return nil, aerr
	}
	req := &x509.CertificateRequest{
		RawSubject:         subjectDER,
		SignatureAlgorithm: sigAlg,
		ExtraExtensions:    exts,
	}
	der, cerr := x509.CreateCertificateRequest(rand.Reader, req, priv)
	if cerr != nil {
		return nil, &invocationErr{msg: fmt.Sprintf("Could not create certificate request: %v", cerr)}
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))

	if a.Path != nil {
		return writePemImpl(rt, csrPEM, *a.Path, true, "CERTIFICATE REQUEST")
	}
	return csrPEM, nil
}

// ---------------------------------------------------------------------------
// verify_signature / verify_crl

type verifySignatureArgs struct {
	Certificate             string  `statekit:"required"`
	SigningPubKey           *string `statekit:"name=signing_pub_key"`
	SigningPubKeyPassphrase *string `statekit:"name=signing_pub_key_passphrase"`
}

type verifySignatureFunc struct{}

func (verifySignatureFunc) Name() string { return "x509.verify_signature" }
func (verifySignatureFunc) Args() any    { return verifySignatureArgs{} }
func (verifySignatureFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*verifySignatureArgs)
	return verifySignatureImpl(rt, a.Certificate, a.SigningPubKey, a.SigningPubKeyPassphrase)
}

// getPublicKeyObj is the asObj=True form of get_public_key: it
// resolves a public key, certificate, CSR or private key PEM/path to
// the parsed public key object.
func getPublicKeyObj(rt *runtime.Runtime, key, passphrase string) (any, error) {
	spkiPEM, err := getPublicKeyImpl(rt, key, &passphrase)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(spkiPEM))
	if block == nil {
		return nil, &invocationErr{msg: "Could not decode public key"}
	}
	pub, perr := x509.ParsePKIXPublicKey(block.Bytes)
	if perr != nil {
		return nil, &invocationErr{msg: "Could not load public key"}
	}
	return pub, nil
}

// verifyCertSignature is the bool(cert.verify(pkey) == 1) shape: the
// signature is checked against the signer's public key (M2Crypto's
// X509.verify), not the certificate's own key; a failed check is
// False, never an error.
func verifyCertSignature(cert *x509.Certificate, pub any) bool {
	return checkSignatureWithKey(pub, cert.SignatureAlgorithm,
		cert.RawTBSCertificate, cert.Signature)
}

// checkSignatureWithKey verifies one signature with an arbitrary
// public key across the key families this module signs with.
func checkSignatureWithKey(pub any, algo x509.SignatureAlgorithm, signed, signature []byte) bool {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		hash, ok := signatureHash(algo)
		if !ok {
			return false
		}
		h := hash.New()
		h.Write(signed)
		digest := h.Sum(nil)
		switch algo {
		case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
			return rsa.VerifyPSS(key, hash, digest, signature, nil) == nil
		default:
			return rsa.VerifyPKCS1v15(key, hash, digest, signature) == nil
		}
	case *ecdsa.PublicKey:
		hash, ok := signatureHash(algo)
		if !ok {
			return false
		}
		h := hash.New()
		h.Write(signed)
		return ecdsa.VerifyASN1(key, h.Sum(nil), signature)
	case ed25519.PublicKey:
		return ed25519.Verify(key, signed, signature)
	}
	return false
}

// signatureHash maps the signature algorithms onto their digest.
func signatureHash(algo x509.SignatureAlgorithm) (crypto.Hash, bool) {
	switch algo {
	case x509.MD5WithRSA:
		return crypto.MD5, true
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return crypto.SHA1, true
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.ECDSAWithSHA256:
		return crypto.SHA256, true
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		return crypto.SHA384, true
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		return crypto.SHA512, true
	case x509.PureEd25519:
		return crypto.Hash(0), true
	}
	return crypto.Hash(0), false
}

func verifySignatureImpl(rt *runtime.Runtime, certificate string, signingPubKey, passphrase *string) (bool, error) {
	cert, err := getCertificateObj(rt, certificate)
	if err != nil {
		return false, err
	}
	pub := cert.PublicKey
	if signingPubKey != nil && *signingPubKey != "" {
		pass := ""
		if passphrase != nil {
			pass = *passphrase
		}
		pub, err = getPublicKeyObj(rt, *signingPubKey, pass)
		if err != nil {
			return false, err
		}
	}
	return verifyCertSignature(cert, pub), nil
}

type verifyCrlArgs struct {
	Crl  string `statekit:"required"`
	Cert string `statekit:"required"`
}

type verifyCrlFunc struct{}

func (verifyCrlFunc) Name() string { return "x509.verify_crl" }
func (verifyCrlFunc) Args() any    { return verifyCrlArgs{} }
func (verifyCrlFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*verifyCrlArgs)
	return verifyCrlImpl(rt, a.Crl, a.Cert)
}

func verifyCrlImpl(rt *runtime.Runtime, crl, cert string) (bool, error) {
	crlText, err := getPemEntryImpl(rt, crl, "X509 CRL")
	if err != nil {
		return false, err
	}
	certObj, err := getCertificateObj(rt, cert)
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode([]byte(crlText))
	if block == nil {
		return false, nil
	}
	list, perr := x509.ParseRevocationList(block.Bytes)
	if perr != nil {
		// The CLI fallback upstream also failed without printing
		// "verify OK", so an unloadable DER is False rather than an
		// error.
		return false, nil
	}
	return list.CheckSignatureFrom(certObj) == nil, nil
}

// ---------------------------------------------------------------------------
// shared helpers

// strOrEmpty renders an optional string argument.
func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// stringPtr boxes a value that may be absent.
func stringPtr(v any) *string {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
}

// pyRender formats a config/kwargs value the way Python str() would
// for the scalar types that reach these code paths.
func pyRender(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	default:
		return fmt.Sprintf("%v", t)
	}
}

func kwString(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return "", false
	}
	if s, ok := v.(string); ok {
		return s, true
	}
	return pyRender(v), true
}

func kwInt(m map[string]any, key string) (int, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return 0, false
	}
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
		return int(t), true
	case string:
		var n int
		if _, err := fmt.Sscanf(t, "%d", &n); err == nil {
			return n, true
		}
	}
	return 0, false
}

func kwBool(m map[string]any, key string) (bool, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return false, false
	}
	if b, ok := v.(bool); ok {
		return b, true
	}
	return false, false
}

// redactMaterial keeps PEM bodies out of error text while preserving
// path-like inputs.
func redactMaterial(v string) string {
	if strings.Contains(v, "-----BEGIN") {
		return "[redacted pem]"
	}
	if v == "" {
		return "None"
	}
	return v
}

// randomSerialHex ports random.getrandbits(serial_bits) rendered
// through _dec2hex, sourcing entropy from crypto/rand.
func randomSerialHex(serialBits int) (string, error) {
	if serialBits <= 0 || serialBits > 1024 {
		return "", &invocationErr{msg: "serial_bits must be between 1 and 1024"}
	}
	bytesLen := (serialBits + 7) / 8
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return "", &invocationErr{msg: "Could not generate serial number"}
	}
	n := new(big.Int).SetBytes(buf)
	// Keep the value inside the requested bit width.
	n.Rsh(n, uint(bytesLen*8-serialBits))
	return dec2hexBig(n), nil
}

// signatureAlgorithmForWrite maps the v1 algorithm kwarg onto Go
// signature algorithms for the signing key type.
func signatureAlgorithmForWrite(algorithm string, key any) (x509.SignatureAlgorithm, error) {
	if _, ok := key.(ed25519.PrivateKey); ok {
		return x509.PureEd25519, nil
	}
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "md5":
		if _, ok := key.(*rsa.PrivateKey); ok {
			return x509.MD5WithRSA, nil
		}
	case "sha1":
		switch key.(type) {
		case *rsa.PrivateKey:
			return x509.SHA1WithRSA, nil
		case *ecdsa.PrivateKey:
			return x509.ECDSAWithSHA1, nil
		}
	case "sha224":
		switch key.(type) {
		case *rsa.PrivateKey:
			return x509.SHA256WithRSA, nil // no SHA224WithRSA in stdlib
		case *ecdsa.PrivateKey:
			return x509.ECDSAWithSHA256, nil
		}
	case "sha256":
		switch key.(type) {
		case *rsa.PrivateKey:
			return x509.SHA256WithRSA, nil
		case *ecdsa.PrivateKey:
			return x509.ECDSAWithSHA256, nil
		}
	case "sha384":
		switch key.(type) {
		case *rsa.PrivateKey:
			return x509.SHA384WithRSA, nil
		case *ecdsa.PrivateKey:
			return x509.ECDSAWithSHA384, nil
		}
	case "sha512":
		switch key.(type) {
		case *rsa.PrivateKey:
			return x509.SHA512WithRSA, nil
		case *ecdsa.PrivateKey:
			return x509.ECDSAWithSHA512, nil
		}
	default:
		return 0, &invocationErr{msg: fmt.Sprintf("unsupported algorithm %q", algorithm)}
	}
	return 0, &invocationErr{msg: fmt.Sprintf("unsupported key type %T for %q", key, algorithm)}
}

// getRequestObj ports _get_request_obj.
func getRequestObj(rt *runtime.Runtime, csr string) (*x509.CertificateRequest, error) {
	text, err := getPemEntryImpl(rt, csr, "CERTIFICATE REQUEST")
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, &invocationErr{msg: "Could not decode PEM certificate request"}
	}
	req, perr := x509.ParseCertificateRequest(block.Bytes)
	if perr != nil {
		return nil, &invocationErr{msg: "Could not load certificate request"}
	}
	return req, nil
}

// ---------------------------------------------------------------------------
// subject assembly (sorted(subject.nid) setattr order)

// subjectAttrDefs maps the M2Crypto subject attribute names Salt sets
// onto OIDs and the DER string tag OpenSSL's NID table assigns. The
// "Email" alias carries the emailAddress NID the Salt fixtures rely
// on.
var subjectAttrDefs = map[string]struct {
	oid asn1.ObjectIdentifier
	tag int
}{
	"C":            {asn1.ObjectIdentifier{2, 5, 4, 6}, 19},
	"CN":           {asn1.ObjectIdentifier{2, 5, 4, 3}, 12},
	"DC":           {asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, 22},
	"Email":        {asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, 22},
	"emailAddress": {asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, 22},
	"GN":           {asn1.ObjectIdentifier{2, 5, 4, 42}, 12},
	"L":            {asn1.ObjectIdentifier{2, 5, 4, 7}, 12},
	"O":            {asn1.ObjectIdentifier{2, 5, 4, 10}, 12},
	"OU":           {asn1.ObjectIdentifier{2, 5, 4, 11}, 12},
	"SN":           {asn1.ObjectIdentifier{2, 5, 4, 4}, 12},
	"ST":           {asn1.ObjectIdentifier{2, 5, 4, 8}, 12},
	"UID":          {asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, 12},
	"postalCode":   {asn1.ObjectIdentifier{2, 5, 4, 17}, 12},
	"serialNumber": {asn1.ObjectIdentifier{2, 5, 4, 5}, 19},
	"street":       {asn1.ObjectIdentifier{2, 5, 4, 9}, 12},
}

type nameAttr struct {
	name  string
	oid   asn1.ObjectIdentifier
	tag   int
	value string
}

// subjectFromRaw keeps a wire-order attribute list of an existing
// subject (the CSR branch).
func subjectFromRaw(raw []byte) ([]nameAttr, error) {
	rdns, err := unmarshalRDNs(raw)
	if err != nil {
		return nil, err
	}
	var out []nameAttr
	for _, set := range rdns {
		for _, atv := range set {
			name := shortNameFor(atv.Type)
			tag := 12
			if !isStringTag(atv.Value.Tag) {
				continue
			}
			if atv.Value.Tag != 0 {
				tag = atv.Value.Tag
			}
			out = append(out, nameAttr{name: name, oid: atv.Type, tag: tag, value: string(atv.Value.Bytes)})
		}
	}
	return out, nil
}

// applySubjectOverrides ports `for entry in sorted(subject.nid): if
// entry in kwargs: setattr(subject, entry, kwargs[entry])`: present
// attributes are replaced in place, new ones append in alphabetical
// name order.
func applySubjectOverrides(attrs []nameAttr, kwargs map[string]any) []nameAttr {
	var names []string
	for name := range kwargs {
		if _, ok := subjectAttrDefs[name]; ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		def := subjectAttrDefs[name]
		value := pyRender(kwargs[name])
		replaced := false
		for i := range attrs {
			if attrs[i].oid.Equal(def.oid) {
				attrs[i].value = value
				attrs[i].tag = def.tag
				replaced = true
				break
			}
		}
		if !replaced {
			attrs = append(attrs, nameAttr{name: name, oid: def.oid, tag: def.tag, value: value})
		}
	}
	return attrs
}

// buildSubjectDER renders one RDN per attribute (M2Crypto appends each
// setattr as its own RDN).
func buildSubjectDER(attrs []nameAttr) ([]byte, error) {
	var name []byte
	for _, attr := range attrs {
		if attr.value == "" {
			continue
		}
		oidDER, err := asn1.Marshal(attr.oid)
		if err != nil {
			return nil, err
		}
		atv := append(append([]byte{}, oidDER...), derEncode(0, attr.tag, false, []byte(attr.value))...)
		rdn := derEncode(0, 17, true, derEncode(0, 16, true, atv))
		name = append(name, rdn...)
	}
	return derEncode(0, 16, true, name), nil
}

// ---------------------------------------------------------------------------
// extension assembly (EXT_NAME_MAPPINGS iteration order)

// extMappings reproduces the EXT_NAME_MAPPINGS order, including the
// upstream "issuserAltName" typo key.
var extMappings = []struct{ short, long string }{
	{"basicConstraints", "X509v3 Basic Constraints"},
	{"keyUsage", "X509v3 Key Usage"},
	{"extendedKeyUsage", "X509v3 Extended Key Usage"},
	{"subjectKeyIdentifier", "X509v3 Subject Key Identifier"},
	{"authorityKeyIdentifier", "X509v3 Authority Key Identifier"},
	{"issuserAltName", "X509v3 Issuer Alternative Name"},
	{"authorityInfoAccess", "X509v3 Authority Info Access"},
	{"subjectAltName", "X509v3 Subject Alternative Name"},
	{"crlDistributionPoints", "X509v3 CRL Distribution Points"},
	{"issuingDistributionPoint", "X509v3 Issuing Distribution Point"},
	{"certificatePolicies", "X509v3 Certificate Policies"},
	{"policyConstraints", "X509v3 Policy Constraints"},
	{"inhibitAnyPolicy", "X509v3 Inhibit Any Policy"},
	{"nameConstraints", "X509v3 Name Constraints"},
	{"noCheck", "X509v3 OCSP No Check"},
	{"nsComment", "Netscape Comment"},
	{"nsCertType", "Netscape Certificate Type"},
}

// writeKeyUsageBits maps the OpenSSL keyUsage names (short conf form
// and the long text read_csr renders) onto KU bits.
var writeKeyUsageBits = []struct {
	name string
	bit  int
}{
	{"digitalSignature", 0}, {"nonRepudiation", 1}, {"keyEncipherment", 2},
	{"dataEncipherment", 3}, {"keyAgreement", 4}, {"keyCertSign", 5},
	{"cRLSign", 6}, {"encipherOnly", 7}, {"decipherOnly", 8},
	{"Digital Signature", 0}, {"Non Repudiation", 1}, {"Key Encipherment", 2},
	{"Data Encipherment", 3}, {"Key Agreement", 4}, {"Certificate Sign", 5},
	{"CRL Sign", 6}, {"Encipher Only", 7}, {"Decipher Only", 8},
}

// writeEKUEntries maps Eku short conf names and the long text forms
// onto OIDs.
var writeEKUEntries = []struct {
	short string
	long  string
	oid   asn1.ObjectIdentifier
}{
	{"serverAuth", "TLS Web Server Authentication", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}},
	{"clientAuth", "TLS Web Client Authentication", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}},
	{"codeSigning", "Code Signing", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}},
	{"emailProtection", "E-mail Protection", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}},
	{"timeStamping", "Time Stamping", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}},
	{"OCSPSigning", "OCSP Signing", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}},
	{"anyExtendedKeyUsage", "Any Extended Key Usage", asn1.ObjectIdentifier{2, 5, 29, 37, 0}},
}

// writeNsCertTypeBits maps nsCertType names (conf short forms and the
// long text forms) onto the Netscape bit positions.
var writeNsCertTypeBits = []struct {
	name string
	bit  int
}{
	{"client", 0}, {"SSL Client", 0},
	{"server", 1}, {"SSL Server", 1},
	{"email", 2}, {"SMIME", 2}, {"Object Signing", 3}, {"objsign", 3},
	{"reserved", 4}, {"Unused", 4},
	{"sslCA", 5}, {"SSL CA", 5},
	{"emailCA", 6}, {"SMIME CA", 6},
	{"objCA", 7}, {"Object Signing CA", 7},
}

// buildCertificateExtensions assembles the extension sequence in
// EXT_NAME_MAPPINGS order. In the CSR variant authorityKeyIdentifier
// is skipped entirely (v1 `continue`).
func buildCertificateExtensions(kwargs map[string]any, csrexts map[string]string,
	signingCert *x509.Certificate, pub any, isCSR bool) ([]pkix.Extension, error) {
	var exts []pkix.Extension
	for _, mapping := range extMappings {
		value := firstTruthy(kwargs[mapping.short], kwargs[mapping.long],
			csrexts[mapping.short], csrexts[mapping.long])
		if value == nil {
			continue
		}
		extval, ok := value.(string)
		if !ok {
			extval = pyRender(value)
		}
		if mapping.short == "authorityKeyIdentifier" && isCSR {
			continue
		}

		critical := false
		if strings.HasPrefix(extval, "critical ") {
			critical = true
			extval = strings.TrimPrefix(extval, "critical ")
		}

		var oid asn1.ObjectIdentifier
		var der []byte
		var err error
		switch mapping.short {
		case "basicConstraints":
			oid = oidBasicConstraints
			der, err = encodeBasicConstraintsWrite(extval)
		case "keyUsage":
			oid = oidKeyUsage
			der, err = encodeKeyUsageWrite(extval)
		case "extendedKeyUsage":
			oid = oidExtendedKeyUsage
			der, err = encodeExtendedKeyUsageWrite(extval)
		case "subjectKeyIdentifier":
			oid = oidSubjectKeyIdent
			if strings.Contains(extval, "hash") {
				extval = strings.ReplaceAll(extval, "hash", pubkeyHashPretty(pub))
			}
			der, err = encodeSubjectKeyIdentifierWrite(extval)
		case "authorityKeyIdentifier":
			oid = oidAuthorityKeyIdent
			der, err = encodeAuthorityKeyIdentifierWrite(extval, signingCert, pub)
		case "subjectAltName":
			oid = oidSubjectAltName
			extval = strings.ReplaceAll(extval, "IP Address", "IP")
			der, err = encodeSubjectAltNameWrite(extval)
		case "nsComment":
			oid = oidNsComment
			der = derEncode(0, 22, false, []byte(extval))
		case "nsCertType":
			oid = oidNsCertType
			der, err = encodeNsCertTypeWrite(extval)
		default:
			return nil, &invocationErr{msg: fmt.Sprintf(
				"extension %s is not supported by this port (documented boundary)", mapping.short)}
		}
		if err != nil {
			// Stable invocation errors (the "value must be precomputed
			// hash" guard) pass through; encoder failures become the
			// X509Error-shaped text the source raises.
			var inv *invocationErr
			if errors.As(err, &inv) {
				return nil, err
			}
			return nil, &invocationErr{msg: fmt.Sprintf(
				"Invalid X509v3 Extension. %s: %s", mapping.short, extval)}
		}
		exts = append(exts, pkix.Extension{Id: oid, Critical: critical, Value: der})
	}
	return exts, nil
}

// firstTruthy mirrors Python's `or` chain over the candidate values.
func firstTruthy(values ...any) any {
	for _, v := range values {
		switch t := v.(type) {
		case nil:
			continue
		case string:
			if t != "" {
				return t
			}
		case *string:
			if t != nil && *t != "" {
				return *t
			}
		default:
			return v
		}
	}
	return nil
}

// pubkeyHashPretty ports _get_pubkey_hash: the pretty-hex SHA-1 of the
// RSA modulus (SPKI DER for the key types v1 never generated).
func pubkeyHashPretty(pub any) string {
	var material []byte
	switch k := pub.(type) {
	case *rsa.PublicKey:
		material = k.N.Bytes()
	default:
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return ""
		}
		material = der
	}
	sum := sha1.Sum(material)
	return prettyHex(sum[:])
}

// integerContent renders a small non-negative DER INTEGER body.
func integerContent(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	bigN := new(big.Int).SetInt64(int64(n))
	body := bigN.Bytes()
	if body[0]&0x80 != 0 {
		return append([]byte{0}, body...)
	}
	return body
}

func encodeBasicConstraintsWrite(text string) ([]byte, error) {
	ca := false
	pathLen := -1
	for _, part := range strings.Split(text, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		switch {
		case strings.HasPrefix(strings.ToLower(part), "ca:"):
			switch strings.ToLower(part[len("CA:"):]) {
			case "true", "yes":
				ca = true
			case "false", "no":
				ca = false
			default:
				return nil, fmt.Errorf("invalid CA flag")
			}
		case strings.HasPrefix(strings.ToLower(part), "pathlen:"):
			var n int
			if _, serr := fmt.Sscanf(part[len("pathlen:"):], "%d", &n); serr != nil {
				return nil, fmt.Errorf("invalid pathlen")
			}
			pathLen = n
		default:
			return nil, fmt.Errorf("unsupported component %q", part)
		}
	}
	// DER DEFAULT omission: cA=FALSE disappears, as in OpenSSL output.
	var content []byte
	if ca {
		content = append(content, derEncode(0, 1, false, []byte{0xff})...)
	}
	if pathLen >= 0 {
		content = append(content, derEncode(0, 2, false, integerContent(pathLen))...)
	}
	return derEncode(0, 16, true, content), nil
}

func encodeKeyUsageWrite(text string) ([]byte, error) {
	bits := [2]byte{}
	highest := -1
	for _, part := range strings.Split(text, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		matched := false
		for _, bit := range writeKeyUsageBits {
			if strings.EqualFold(bit.name, part) {
				bits[bit.bit/8] |= 1 << (7 - bit.bit%8)
				if bit.bit > highest {
					highest = bit.bit
				}
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("unsupported keyUsage %q", part)
		}
	}
	if highest < 0 {
		return nil, fmt.Errorf("empty keyUsage")
	}
	length := (highest + 8) / 8
	return asn1.Marshal(asn1.BitString{Bytes: bits[:length], BitLength: highest + 1})
}

func parseOIDWrite(s string) asn1.ObjectIdentifier {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) < 2 {
		return nil
	}
	var oid asn1.ObjectIdentifier
	for _, p := range parts {
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &n); err != nil || n < 0 {
			return nil
		}
		oid = append(oid, n)
	}
	return oid
}

func encodeExtendedKeyUsageWrite(text string) ([]byte, error) {
	var oids []asn1.ObjectIdentifier
	for _, part := range strings.Split(text, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		matched := false
		for _, entry := range writeEKUEntries {
			if strings.EqualFold(entry.short, part) || strings.EqualFold(entry.long, part) {
				oids = append(oids, entry.oid)
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		if oid := parseOIDWrite(part); oid != nil {
			oids = append(oids, oid)
			continue
		}
		return nil, fmt.Errorf("unsupported extendedKeyUsage %q", part)
	}
	if len(oids) == 0 {
		return nil, fmt.Errorf("empty extendedKeyUsage")
	}
	return asn1.Marshal(oids)
}

func encodeSubjectAltNameWrite(text string) ([]byte, error) {
	var body []byte
	for _, part := range strings.Split(text, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, ":")
		if idx <= 0 {
			return nil, fmt.Errorf("unsupported subjectAltName entry %q", part)
		}
		kind, value := part[:idx], part[idx+1:]
		switch kind {
		case "DNS":
			body = append(body, contextTLV(2, []byte(value))...)
		case "IP":
			ip := net.ParseIP(value)
			if ip == nil {
				return nil, fmt.Errorf("invalid subjectAltName IP %q", value)
			}
			raw := ip.To4()
			if raw == nil {
				raw = ip.To16()
			}
			body = append(body, contextTLV(7, raw)...)
		case "email":
			body = append(body, contextTLV(1, []byte(value))...)
		case "URI":
			if _, uerr := url.Parse(value); uerr != nil {
				return nil, uerr
			}
			body = append(body, contextTLV(6, []byte(value))...)
		default:
			return nil, fmt.Errorf("unsupported subjectAltName entry %q", part)
		}
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("empty subjectAltName")
	}
	return derEncode(0, 16, true, body), nil
}

// contextTLV wraps a GeneralName in its implicit context tag.
func contextTLV(tag int, value []byte) []byte {
	return derEncode(2, tag, false, value)
}

// encodeSubjectKeyIdentifierWrite validates the precomputed-hash form
// (the source's "value must be precomputed hash" guard) and wraps the
// bytes in the extension's OCTET STRING.
func encodeSubjectKeyIdentifierWrite(text string) ([]byte, error) {
	if strings.Trim(text, "0123456789abcdefABCDEF:") != "" {
		return nil, &invocationErr{msg: "value must be precomputed hash"}
	}
	clean := strings.ReplaceAll(text, ":", "")
	raw, err := hexDecode(clean)
	if err != nil || len(raw) == 0 {
		return nil, &invocationErr{msg: "value must be precomputed hash"}
	}
	return derEncode(0, 4, false, raw), nil
}

// encodeAuthorityKeyIdentifierWrite renders the keyid form: the
// issuer's subjectKeyIdentifier when present, else the SHA-1 of its
// public key (the `issuer:always` DirName+serial material is not
// representable; see the package boundary notes).
func encodeAuthorityKeyIdentifierWrite(text string, signingCert *x509.Certificate, pub any) ([]byte, error) {
	explicit := ""
	for _, part := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' }) {
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "keyid:") && len(part) > 6 {
			explicit = strings.TrimPrefix(part, "keyid:")
			break
		}
		if strings.EqualFold(part, "keyid") || strings.HasPrefix(part, "keyid") ||
			strings.EqualFold(part, "issuer") || strings.HasPrefix(part, "issuer:") ||
			strings.EqualFold(part, "always") {
			continue
		}
		return nil, fmt.Errorf("unsupported authorityKeyIdentifier component %q", part)
	}

	var keyid []byte
	if explicit != "" {
		if strings.Trim(explicit, "0123456789abcdefABCDEF:") != "" {
			return nil, fmt.Errorf("invalid authorityKeyIdentifier keyid %q", explicit)
		}
		raw, err := hexDecode(strings.ReplaceAll(explicit, ":", ""))
		if err != nil {
			return nil, err
		}
		keyid = raw
	} else if signingCert != nil {
		keyid = signingCert.SubjectKeyId
		if len(keyid) == 0 {
			keyid = rawSKIFromPublicKey(signingCert.PublicKey)
		}
	} else {
		keyid = rawSKIFromPublicKey(pub)
	}
	return derEncode(0, 16, true, derEncode(2, 0, false, keyid)), nil
}

// rawSKIFromPublicKey is the OpenSSL keyid fallback: SHA-1 of the
// subject public key.
func rawSKIFromPublicKey(pub any) []byte {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		sum := sha1.Sum(k.N.Bytes())
		return sum[:]
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	sum := sha1.Sum(der)
	return sum[:]
}

func encodeNsCertTypeWrite(text string) ([]byte, error) {
	bits := [1]byte{}
	highest := -1
	for _, part := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' }) {
		if part == "" {
			continue
		}
		matched := false
		for _, bit := range writeNsCertTypeBits {
			if strings.EqualFold(bit.name, part) {
				bits[0] |= 1 << (7 - bit.bit)
				if bit.bit > highest {
					highest = bit.bit
				}
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("unsupported nsCertType %q", part)
		}
	}
	if highest < 0 {
		return nil, fmt.Errorf("empty nsCertType")
	}
	return asn1.Marshal(asn1.BitString{Bytes: bits[:], BitLength: highest + 1})
}
