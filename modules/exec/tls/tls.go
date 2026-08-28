// Package tls ports Salt's PKI management family (R5.8):
// saltstack/salt/modules/tls.py @ pinned revision, backed by the Go
// standard library (crypto/x509, crypto/rsa, encoding/asn1) instead of
// pyOpenSSL. Same observable contracts: the OpenSSL-style CA directory
// layout (index.txt V/R rows, .serial counter), file modes 0600/0644,
// verbatim reply strings, and the Python path-joining quirks.
//
// Documented boundaries:
//   - create_pkcs12 surfaces an explicit unsupported-serialization error:
//     golang.org/x/crypto v0.55.0 ships pkcs12 decoding only (the
//     encoder subpackage is unreleased). Wire-stable PKCS#12 envelopes
//     are not hand-rolled; once x/crypto publishes the encoder this
//     function flips to it (ADR 0002 dependency ceiling).
//   - upstream rides pyOpenSSL (a libssl binding), so the substrate
//     mapping is library-to-library. The openssl CLI is never spawned.
//   - extensions created by this family are limited to its own profile
//     (basicConstraints, keyUsage, extendedKeyUsage, subjectAltName,
//     subjectKeyIdentifier, authorityKeyIdentifier); the OpenSSL
//     textual rendering for cert_info is reproduced for those families
//     and falls back to raw data otherwise.
//   - CA certificates carry authorityKeyIdentifier keyid only (Go has a
//     flat key id field); upstream's issuer:always added DirName+serial.
//   - leaf certificates gain an authorityKeyIdentifier that upstream
//     omitted (Go emits it whenever the issuer has a subjectKeyIdentifier).
//   - Go rejects X.509 version fields >2 on parse, so the raw version is
//     probed through ASN.1 for maybe_fix_ssl_version (old-salt buggy
//     certs with version literal 3 can never round-trip through
//     x509.ParseCertificate; subject/expiry come from the raw TBS).
//   - config.option and pillar.get resolve through optional registry
//     delegates and degrade to None/False when absent, exactly like a
//     minion without pillar; cmd.retcode for onlyif/unless is executed
//     through the central Runner (shell) mirroring the delegate.
//   - serial numbers exceeding int64 render as exact JSON numbers but
//     quoted scalars under YAML (encoding ceiling documented here once).
//   - Python f-string None rendering quirk kept: an unconfigured base
//     path yields literal "None/..." relative directories.
package tls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math"
	"math/big"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

// ---------------------------------------------------------------------------
// small runtime helpers (python semantics)

func recoverTLS(res *any, errPtr *error) {
	if r := recover(); r != nil {
		switch e := r.(type) {
		case error:
			*errPtr = e
		default:
			panic(r)
		}
	}
}

type invocationErr struct{ msg string }

func (e *invocationErr) Error() string { return e.msg }

func callDelegateT(rt *runtime.Runtime, name string, args any) (any, error) {
	if _, ok := rt.Exec.Get(name); !ok {
		return nil, fmt.Errorf("%s is not available", name)
	}
	return rt.Exec.Call(context.Background(), rt, name, args)
}

// pyTruthy mirrors Python truthiness for the option values this family
// handles (None, "", booleans, everything else truthy).
func pyTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case *string:
		// typed nil pointers arrive from omitted-pointer arguments and
		// are Python's None
		return t != nil && *t != ""
	case bool:
		return t
	case []string:
		return len(t) > 0
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		return true
	}
}

// pyStr renders a value the way an f"{x}" would, including the None
// quirk that produces literal "None" path heads upstream.
func pyStr(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}

// contextState emulates __context__ storage for set_ca_path. The keys
// match upstream's own context strings.
var (
	contextState = map[string]any{}
	contextMu    sync.Mutex
)

// optsString resolves __opts__-style scalars through the config.option
// delegate with a workspace-local default.
func optsString(rt *runtime.Runtime, key, fallback string) string {
	if res, err := callDelegateT(rt, "config.option",
		map[string]any{"key": key, "default": nil}); err == nil {
		if s, ok := res.(string); ok && s != "" {
			return s
		}
	}
	return fallback
}

// contextOrConfig ports _context_or_config: context value when the key
// is present (even empty), else config.option.
func contextOrConfig(rt *runtime.Runtime, key string) any {
	contextMu.Lock()
	v, ok := contextState[key]
	contextMu.Unlock()
	if ok {
		return v
	}
	res, err := callDelegateT(rt, "config.option",
		map[string]any{"key": key, "default": nil})
	if err != nil {
		return nil
	}
	return res
}

// baseOr joins the resolved base path (any-typed, Python str() quirks
// included) with the remaining literal components.
func baseJoin(base any, parts ...string) string {
	out := pyStr(base)
	for _, p := range parts {
		out += "/" + p
	}
	return out
}

// strftimeT pairs mirror the documented Python strftime subset ported
// for status.time_ (the same directives apply here).
var strftimePairsT = []struct{ py, goFmt string }{
	{"%A", "Monday"}, {"%a", "Mon"}, {"%B", "January"}, {"%b", "Jan"},
	{"%d", "02"}, {"%H", "15"}, {"%I", "03"}, {"%M", "04"}, {"%m", "01"},
	{"%p", "PM"}, {"%S", "05"}, {"%Y", "2006"}, {"%y", "06"}, {"%%", "%"},
}

func strftimeToGoT(format string) string {
	out := format
	for _, pair := range strftimePairsT {
		out = strings.ReplaceAll(out, pair.py, "\x00"+pair.goFmt+"\x00")
	}
	return strings.ReplaceAll(strings.ReplaceAll(out, "\x00", ""), "%", "%%")
}

var twoDigitYearFmt = "060102150405Z" // python %y%m%d%H%M%SZ
var fourDigitYearFmt = "20060102150405Z"

// ---------------------------------------------------------------------------
// serial machinery (_microtime / _new_serial)

func microtime() string {
	now := float64(time.Now().UnixNano()) / 1e9
	frac, sec := math.Modf(now)
	return fmt.Sprintf("%f%d", frac, int64(sec))
}

// urandom5 ports os.urandom(5).
func urandom5() []byte {
	buf := make([]byte, 5)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// newSerial ports _new_serial: hexlify(microtime + "_" + urandom(5))
// parsed as a big integer, then appended to <cachedir>/<ca>.serial in
// decimal form.
func newSerial(rt *runtime.Runtime, caName string) (*big.Int, error) {
	buf := append([]byte(microtime()), '_')
	buf = append(buf, urandom5()...)
	num := new(big.Int)
	if _, ok := num.SetString(hex.EncodeToString(buf), 16); !ok {
		return nil, fmt.Errorf("could not compute serial number")
	}

	cachedir := optsString(rt, "cachedir", ".statekit")
	if err := rt.FS.MkdirAll(cachedir, 0o755); err != nil {
		return nil, err
	}
	serialFile := cachedir + "/" + caName + ".serial"
	_, statErr := rt.FS.Stat(serialFile)
	data := []byte(num.String())
	if statErr != nil {
		if err := rt.FS.WriteFile(serialFile, data, 0o644); err != nil {
			return nil, err
		}
	} else if old, rerr := rt.FS.ReadFile(serialFile); rerr == nil {
		if err := rt.FS.WriteFile(serialFile, append(old, data...), 0o644); err != nil {
			return nil, err
		}
	}
	return num, nil
}

// ---------------------------------------------------------------------------
// certificate reading (_read_cert) and raw probes

// readCert ports _read_cert's string branch: PEM text or a path to a
// PEM file. Object handles do not cross the Go boundary (upstream's
// non-string cert objects stay internal to a single Python call).
func readCert(rt *runtime.Runtime, cert string) (*x509.Certificate, error) {
	if strings.Contains(cert, "-----BEGIN") {
		return parseCertPEM([]byte(cert))
	}
	data, err := rt.FS.ReadFile(cert)
	if err != nil {
		return nil, err
	}
	return parseCertPEM(data)
}

func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("could not decode PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// tbsPeek decodes enough of the raw TBS structure to expose the
// version literal and the wire-order subject without requiring the
// certificate to satisfy x509.ParseCertificate (old salt wrote an
// illegal version field of 3).
type tbsPeek struct {
	Version        int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber   *big.Int
	SignatureAlgo  pkix.AlgorithmIdentifier
	Issuer         asn1.RawValue
	Validity       asn1.RawValue
	Subject        asn1.RawValue
	SPKI           spkiPeek
	ExtensionsOnly []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

// spkiPeek wraps the SubjectPublicKeyInfo sequence as one field per
// crypto/x509's own parser layout.
type spkiPeek struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func peekTBS(der []byte) (*tbsPeek, error) {
	var outer struct {
		TBS      asn1.RawValue
		SigAlgo  pkix.AlgorithmIdentifier
		SignBits asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return nil, err
	}
	tbs := &tbsPeek{}
	if _, err := asn1.Unmarshal(outer.TBS.FullBytes, tbs); err != nil {
		return nil, err
	}
	return tbs, nil
}

// rawVersion probes the literal X.509 version field (2 == v3, the
// old-salt bug wrote 3).
func rawVersion(der []byte) (int, error) {
	tbs, err := peekTBS(der)
	if err != nil {
		return -1, err
	}
	return tbs.Version, nil
}

// subjectComponents flattens a raw subject in wire order.
type subjComponent struct {
	Short string
	Value string
}

// ldapShortName maps the X.509 attribute OIDs this family (and the
// upstream fixtures) use onto the pyOpenSSL get_components short names.
var ldapShortName = map[string]string{
	"2.5.4.6":                    "C",
	"2.5.4.8":                    "ST",
	"2.5.4.7":                    "L",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SN",
	"2.5.4.42":                   "GN",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.9":                    "street",
	"2.5.4.17":                   "postalCode",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1":  "UID",
}

func shortName(oid asn1.ObjectIdentifier) string {
	key := oid.String()
	if name, ok := ldapShortName[key]; ok {
		return name
	}
	return key
}

func subjectValues(raw []byte) ([]subjComponent, error) {
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &rdn); err != nil {
		return nil, err
	}
	var out []subjComponent
	for _, set := range rdn {
		for _, atv := range set {
			out = append(out, subjComponent{
				Short: shortName(atv.Type),
				Value: pyStr(atv.Value),
			})
		}
	}
	return out, nil
}

// subjectAttribute extracts one attribute by short name from raw DER.
func subjectAttribute(raw []byte, name string) (string, bool) {
	comps, err := subjectValues(raw)
	if err != nil {
		return "", false
	}
	for _, c := range comps {
		if c.Short == name {
			return c.Value, true
		}
	}
	return "", false
}

// buildSubject assembles the pkix.Name upstream would have produced by
// setting C, ST, L, O, [OU], CN, [emailAddress] in that order; since Go
// marshals typed fields before ExtraNames, the resulting wire order
// matches pyOpenSSL's append order.
func buildSubject(C, ST, L, O, OU, CN, emailAddress string) pkix.Name {
	name := pkix.Name{
		Country:      []string{C},
		Province:     []string{ST},
		Locality:     []string{L},
		Organization: []string{O},
		CommonName:   CN,
	}
	if OU != "" {
		name.OrganizationalUnit = []string{OU}
	}
	if emailAddress != "" {
		emailOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
		name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  emailOID,
			Value: emailAddress,
		})
	}
	return name
}

// ---------------------------------------------------------------------------
// index.txt database (_get_basic_info / _write_cert_to_database)

type basicInfo struct {
	IndexFile string
	Expire    string
	Serial    string
	Subject   string
}

func getBasicInfo(rt *runtime.Runtime, caDir string, cert *x509.Certificate) (basicInfo, error) {
	info := basicInfo{
		IndexFile: caDir + "/index.txt",
		Expire:    cert.NotAfter.UTC().Format(twoDigitYearFmt),
		Serial:    strings.ToUpper(cert.SerialNumber.Text(16)),
	}
	comps, err := subjectValues(cert.RawSubject)
	if err != nil {
		return info, err
	}
	var parts []string
	for _, c := range comps {
		parts = append(parts, c.Short+"="+c.Value)
	}
	// upstream prepends "/" then joins components with "/", trailing \n
	info.Subject = "/" + strings.Join(parts, "/") + "\n"
	return info, nil
}

func writeCertToDatabase(rt *runtime.Runtime, caName string, cert *x509.Certificate, cacertPath *string, status string) error {
	if status == "" {
		status = "V"
	}
	if err := setCAPathImpl(rt, cacertPath); err != nil {
		return err
	}
	caDir := baseJoin(certBasePathImpl(rt, nil), caName)
	info, err := getBasicInfo(rt, caDir, cert)
	if err != nil {
		return err
	}
	indexData := fmt.Sprintf("%s\t%s\t\t%s\tunknown\t%s", status, info.Expire, info.Serial, info.Subject)
	if old, rerr := rt.FS.ReadFile(info.IndexFile); rerr == nil {
		return rt.FS.WriteFile(info.IndexFile, append(old, []byte(indexData)...), 0o644)
	}
	return rt.FS.WriteFile(info.IndexFile, []byte(indexData), 0o644)
}

// ---------------------------------------------------------------------------
// digest plumbing

var digestHashes map[string]crypto.Hash

func init() {
	digestHashes = map[string]crypto.Hash{
		"md5": crypto.MD5, "sha1": crypto.SHA1, "sha224": crypto.SHA224,
		"sha256": crypto.SHA256, "sha384": crypto.SHA384,
		"sha512": crypto.SHA512,
	}
}

func digestHash(name string) (crypto.Hash, bool) {
	h, ok := digestHashes[strings.ToLower(strings.TrimSpace(name))]
	return h, ok
}

// signatureAlgorithmFor maps the openssl digest names this module
// accepts onto Go signature algorithms for the given key type.
func signatureAlgorithmFor(digest string, key any) (x509.SignatureAlgorithm, error) {
	switch strings.ToLower(digest) {
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
		return 0, fmt.Errorf("unknown digest %q", digest)
	}
	return 0, fmt.Errorf("unsupported key type %T for signing", key)
}

// loadPrivateKeyPEM accepts both the PKCS#1 container this module
// writes and the PKCS#8 container the upstream fixture uses.
func loadPrivateKeyPEM(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("could not decode private key PEM")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unknown private key PEM type %q", block.Type)
	}
}

// loadCACertKey fetches the CA certificate and key pair the
// CA-signing/CRL flows need; missing files surface as the OSError
// equivalents the callers translate.
func loadCACertKey(rt *runtime.Runtime, certPath, keyPath string) (*x509.Certificate, any, error) {
	certPEM, err := rt.FS.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	caCert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := rt.FS.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	key, err := loadPrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, err
	}
	return caCert, key, nil
}

// skiFromKey computes the subjectKeyIdentifier "hash" form (SHA-1 of
// the subject public key) the way OpenSSL does.
func skiFromKey(pub any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := crypto.SHA1.New()
	sum.Write(der)
	return sum.Sum(nil), nil
}

// ---------------------------------------------------------------------------
// onlyif/unless (_check_onlyif_unless)

// checkOnlyifUnless ports _check_onlyif_unless; non-string values ride
// Python truthiness while strings are executed through the central
// Runner's shell and judged by exit code, exactly like a
// cmd.retcode delegate call upstream.
func checkOnlyifUnless(ctx context.Context, rt *runtime.Runtime, onlyif, unless any) (map[string]any, error) {
	if onlyif != nil {
		if s, ok := onlyif.(string); ok {
			code, err := shellRetcode(ctx, rt, s)
			if err != nil {
				return nil, err
			}
			if code != 0 {
				return map[string]any{"comment": "onlyif condition is false", "result": true}, nil
			}
		} else if !pyTruthy(onlyif) {
			return map[string]any{"comment": "onlyif condition is false", "result": true}, nil
		}
	}
	if unless != nil {
		if s, ok := unless.(string); ok {
			code, err := shellRetcode(ctx, rt, s)
			if err != nil {
				return nil, err
			}
			if code == 0 {
				return map[string]any{"comment": "unless condition is true", "result": true}, nil
			}
		} else if pyTruthy(unless) {
			return map[string]any{"comment": "unless condition is true", "result": true}, nil
		}
	}
	return nil, nil
}

func shellRetcode(ctx context.Context, rt *runtime.Runtime, cmd string) (int, error) {
	res := rt.Runner.Run(ctx, runtime.Command(cmd))
	if res.Err != nil && res.ExitCode == -1 {
		return -1, res.Err
	}
	return res.ExitCode, nil
}

// ---------------------------------------------------------------------------
// filesystem probes

// pathExists keeps the os.path.exists probes on the runtime FS.
func pathExists(rt *runtime.Runtime, path string) bool {
	_, err := rt.FS.Stat(path)
	return err == nil
}

// fileReplaceLiteral mirrors salt's file.replace(pattern, repl) with
// backup=False for literal strings compiled as regexes (upstream
// passes the index rows straight into a regex-engine replace).
func fileReplaceLiteral(rt *runtime.Runtime, path, pattern, repl string) error {
	re, err := regexp.Compile(regexp.QuoteMeta(pattern))
	if err != nil {
		return err
	}
	data, err := rt.FS.ReadFile(path)
	if err != nil {
		return err
	}
	mode := 0o644
	if info, statErr := rt.FS.Stat(path); statErr == nil {
		mode = int(info.Mode().Perm())
	}
	return rt.FS.WriteFile(path, re.ReplaceAll(data, []byte(repl)), fs.FileMode(mode))
}

// strArg applies a Python default for omitted (None) arguments.
func strArg(s *string, def string) string {
	if s == nil {
		return def
	}
	return *s
}
