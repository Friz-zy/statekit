// Package x509 ports the read-only subset of Salt's legacy x509 v1
// family (R5.2a) plus the R5.2b write-side subset: saltstack/salt/
// modules/x509.py @ pinned revision. R5.2a registered get_pem_entry,
// get_pem_entries, get_private_key_size, read_certificate,
// read_certificates, read_csr, expired, will_expire,
// verify_private_key and get_public_key; R5.2b adds write_pem,
// create_private_key, create_crl, get_signing_policy,
// create_certificate, create_csr, verify_signature and verify_crl
// (see write.go for their documented boundaries). R5.4 adds the
// x509_v2 round (see v2.go): encode_certificate, encode_crl,
// encode_csr, encode_private_key, expires and read_crl (the v2
// cryptography dict shape; the v1 openssl-CLI-text shape is subsumed
// by it). sign_remote_certificate stays pending: the excluded
// master-minion publish surface; the legacy M2Crypto surface keeps its
// ADR 0003 terminal-exclusion boundary for everything that requires
// the ctypes ABI or the openssl CLI parser.
//
// The substrate mapping is library-to-library like R5.4/R5.8 (the
// pinned source rides M2Crypto/pyOpenSSL, both libssl bindings): the
// Go standard library (crypto/x509, encoding/pem, encoding/asn1)
// replaces them and the openssl binary is never spawned.
//
// Documented boundaries (observable shapes stay identical unless
// noted):
//   - get_pem_entry returns the PEM as a string; upstream returns the
//     same ASCII content as bytes. Errors are stable and redacted
//     ("PEM text not valid", "PEM does not contain a single entry of
//     type X") instead of echoing the whole input text the way the
//     SaltInvocationError message does.
//   - get_pem_entries/read_certificates keep the upstream dead
//     `except ValueError` quirk: PEM-structure failures raise (the
//     source's ValueError catch can never catch SaltInvocationError).
//   - read_certificate mirrors the exact v1 keys: Version, Key Size,
//     Serial Number (_dec2hex pretty hex), SHA-256 Finger Print, SHA1
//     Finger Print, Subject, Subject Hash, Issuer, Issuer Hash, Not
//     Before, Not After, Public Key, MD5 Finger Print (only when
//     fips_mode is false, resolved through config.option) and, when
//     present, X509v3 Extensions keyed by the openssl short names
//     with the "critical " value prefix. Dict key order is not
//     observable through the map-based result encoding.
//   - Subject/Issuer Hash reproduce the OpenSSL name hash: SHA-1 over
//     the canonical DER (whitespace stripped/collapsed, AVAs sorted
//     inside each RDN), first four bytes little-endian, rendered via
//     _dec2hex. For ordinary single-valued RDNs the canonical form is
//     the wire DER.
//   - Key Size uses the modulus bit length for RSA (upstream
//     multiplied the byte size by eight), the curve bit size for EC
//     and 256 for Ed25519; v1 was RSA-only, EC/Ed25519 keys are a
//     stdlib-era extension of the same observable shape.
//   - Public Key material is emitted as SPKI ("-----BEGIN PUBLIC KEY
//     -----" via x509.MarshalPKIXPublicKey) for every key type.
//     M2Crypto wrote the RSA PKCS#1 body under the same header; the
//     key material is identical, the DER container is not.
//   - get_private_key_size/get_public_key accept RSA (PKCS#1 and
//     PKCS#8), EC (SEC1 and PKCS#8) and Ed25519 (PKCS#8) containers;
//     only legacy OpenSSL DEK-Info encryption is decryptable (with a
//     passphrase), encrypted PKCS#8 surfaces an unsupported error.
//   - read_csr "Public Key Hash" is the plain lowercase sha1 hex of
//     the RSA modulus bytes (minimal big-endian); for EC/Ed25519
//     CSRs it is the sha1 of the SPKI DER (v1 never reached those
//     keys). Extension values render in the openssl text forms for
//     the families this renderer knows and fall back to lowercase
//     hex otherwise.
//   - expired/will_expire keep the v1 dict contracts: {"path", "cn",
//     "expired"} and {"path", "check_days", "cn", "will_expire"}.
//     Non-file input returns {} (the source checks os.path.isfile
//     first), a readable-but-unparseable file returns the partial
//     {"path"} entry (the source's swallowed ValueError branch), and
//     a certificate without a CN raises the KeyError shape. Dates
//     compare as "%Y-%m-%d %H:%M:%S" UTC strings exactly like the
//     source.
//   - verify_private_key compares the normalized public-key PEM of
//     both sides (upstream compares the M2Crypto PEM bytes).
//   - filesystem inputs resolve like _text_or_file: an existing
//     regular file is read, anything else is treated as inline text.
//     Reads are bounded (16 MiB) and reject symlinked paths and
//     non-regular files, where upstream's os.path.isfile would follow
//     symlinks.
package x509

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

// dateTimeLayout is Salt's "%Y-%m-%d %H:%M:%S" rendering of validity.
const dateTimeLayout = "2006-01-02 15:04:05"

// maxPEMBytes bounds every PEM/certificate/key input before parsing.
const maxPEMBytes int64 = 16 << 20

// recoverX509 turns residual panics into errors, mirroring the tls and
// asymmetric families.
func recoverX509(res *any, errPtr *error) {
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

// stableReadError exposes only stable text for bounded-read failures;
// the underlying sentinel stays wrapped for classification.
func stableReadError(err error) error {
	msg := "Could not read input file"
	if errors.Is(err, runtime.ErrReadLimit) {
		return fmt.Errorf("%s: file exceeds read limit", msg)
	}
	if errors.Is(err, runtime.ErrNonRegularFile) {
		return fmt.Errorf("%s: not a regular file", msg)
	}
	return errors.New(msg)
}

// callDelegate resolves __opts__-style values through config.option,
// degrading to the default when the delegate is absent (a minion
// without configuration).
func callDelegate(rt *runtime.Runtime, name string, args any) (any, error) {
	if rt == nil || rt.Exec == nil {
		return nil, fmt.Errorf("%s is not available", name)
	}
	if _, ok := rt.Exec.Get(name); !ok {
		return nil, fmt.Errorf("%s is not available", name)
	}
	return rt.Exec.Call(context.Background(), rt, name, args)
}

// fipsMode ports __opts__["fips_mode"]; the Salt default is False.
func fipsMode(rt *runtime.Runtime) bool {
	res, err := callDelegate(rt, "config.option",
		map[string]any{"key": "fips_mode", "default": false})
	if err != nil {
		return false
	}
	b, ok := res.(bool)
	return ok && b
}

// ---------------------------------------------------------------------------
// _text_or_file / _make_regex / _valid_pem

// textOrFile ports _text_or_file: an existing regular file is read
// (bounded, no symlinks), anything else is inline text.
func textOrFile(rt *runtime.Runtime, input string) (string, error) {
	info, err := rt.FS.Stat(input)
	if err != nil || info == nil || !info.Mode().IsRegular() {
		return input, nil
	}
	data, rerr := runtime.ReadFileBounded(rt.FS, input, maxPEMBytes)
	if rerr != nil {
		return "", stableReadError(rerr)
	}
	return string(data), nil
}

// makePEMRegex ports _make_regex verbatim (DOTALL included). pemType
// is a regex fragment, exactly like the source's "(?:RSA )?PRIVATE KEY".
func makePEMRegex(pemType string) (*regexp.Regexp, error) {
	if pemType == "" {
		pemType = "[0-9A-Z ]+"
	}
	pattern := `(?s)\s*(?P<pem_header>-----BEGIN ` + pemType + `-----)\s+` +
		`(?:(?P<proc_type>Proc-Type: 4,ENCRYPTED)\s*)?` +
		`(?:(?P<dek_info>DEK-Info: (?:DES-[3A-Z\-]+,[0-9A-F]{16}|[0-9A-Z\-]+,[0-9A-F]{32}))\s*)?` +
		`(?P<pem_body>.+?)\s+(?P<pem_footer>-----END ` + pemType + `-----)\s*`
	return regexp.Compile(pattern)
}

// ---------------------------------------------------------------------------
// get_pem_entry

type getPemEntryArgs struct {
	Text    string  `statekit:"required"`
	PemType *string `statekit:"name=pem_type"`
}

type getPemEntryFunc struct{}

func (getPemEntryFunc) Name() string { return "x509.get_pem_entry" }
func (getPemEntryFunc) Args() any    { return getPemEntryArgs{} }
func (getPemEntryFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*getPemEntryArgs)
	pemType := ""
	if a.PemType != nil {
		pemType = *a.PemType
	}
	return getPemEntryImpl(rt, a.Text, pemType)
}

// getPemEntryImpl ports get_pem_entry: load text-or-file, repair
// escaped newlines and mine.get single-line PEMs, validate against the
// (optional) type regex, then rebuild the canonical 64-column PEM.
func getPemEntryImpl(rt *runtime.Runtime, text, pemType string) (string, error) {
	loaded, err := textOrFile(rt, text)
	if err != nil {
		return "", err
	}
	text = strings.ReplaceAll(loaded, `\n`, "\n")

	if pySplitLinesCount(text) == 1 && strings.HasPrefix(text, "-----") && strings.HasSuffix(text, "-----") {
		fixed, ferr := fixSingleLinePEM(text)
		if ferr != nil {
			return "", ferr
		}
		text = fixed
	}

	re, cerr := makePEMRegex(pemType)
	if cerr != nil {
		return "", &invocationErr{msg: fmt.Sprintf("invalid pem_type %q", pemType)}
	}
	m := re.FindStringSubmatch(text)
	if m == nil {
		if pemType != "" {
			return "", &invocationErr{msg: fmt.Sprintf(
				"PEM does not contain a single entry of type %s", pemType)}
		}
		return "", &invocationErr{msg: "PEM text not valid"}
	}
	header := m[re.SubexpIndex("pem_header")]
	procType := m[re.SubexpIndex("proc_type")]
	dekInfo := m[re.SubexpIndex("dek_info")]
	footer := m[re.SubexpIndex("pem_footer")]
	body := m[re.SubexpIndex("pem_body")]

	// Remove all whitespace from the body, then rewrap at 64 columns.
	body = strings.Join(strings.Fields(body), "")

	var out strings.Builder
	out.WriteString(header)
	out.WriteByte('\n')
	if procType != "" {
		out.WriteString(procType)
		out.WriteByte('\n')
	}
	if dekInfo != "" {
		out.WriteString(dekInfo)
		out.WriteString("\n\n")
	}
	for i := 0; i < len(body); i += 64 {
		end := i + 64
		if end > len(body) {
			end = len(body)
		}
		out.WriteString(body[i:end])
		out.WriteByte('\n')
	}
	out.WriteString(footer)
	out.WriteByte('\n')
	return out.String(), nil
}

// pySplitLinesCount counts line boundaries the way Python's
// str.splitlines does for the separators relevant to PEM text.
func pySplitLinesCount(text string) int {
	count := 1
	for _, r := range text {
		switch r {
		case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			count++
		}
	}
	return count
}

// fixSingleLinePEM ports the mine.get single-line repair: headers stay
// intact while base64 material splits into 64-character chunks.
func fixSingleLinePEM(text string) (string, error) {
	var fixed []string
	rest := text
	for rest != "" {
		if strings.HasPrefix(rest, "-----") {
			idx := strings.Index(rest[5:], "-----")
			if idx < 0 {
				return "", &invocationErr{msg: "PEM text not valid"}
			}
			cut := idx + 5 + 5
			fixed = append(fixed, rest[:cut])
			rest = rest[cut:]
			continue
		}
		chunk := rest
		if len(rest) > 64 {
			chunk = rest[:64]
		}
		if !strings.Contains(chunk, "-") {
			fixed = append(fixed, chunk)
			rest = rest[len(chunk):]
			continue
		}
		idx := strings.IndexByte(rest, '-')
		if idx < 0 {
			return "", &invocationErr{msg: "PEM text not valid"}
		}
		fixed = append(fixed, rest[:idx])
		rest = rest[idx:]
	}
	return strings.Join(fixed, "\n"), nil
}

// ---------------------------------------------------------------------------
// get_pem_entries

type getPemEntriesArgs struct {
	GlobPath string `statekit:"required,name=glob_path"`
}

type getPemEntriesFunc struct{}

func (getPemEntriesFunc) Name() string { return "x509.get_pem_entries" }
func (getPemEntriesFunc) Args() any    { return getPemEntriesArgs{} }
func (getPemEntriesFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*getPemEntriesArgs)
	return getPemEntriesImpl(rt, a.GlobPath)
}

func getPemEntriesImpl(rt *runtime.Runtime, globPath string) (map[string]string, error) {
	paths, gerr := rt.FS.Glob(globPath)
	if gerr != nil {
		return nil, gerr
	}
	out := map[string]string{}
	for _, path := range paths {
		if info, serr := rt.FS.Stat(path); serr != nil || info == nil || !info.Mode().IsRegular() {
			continue
		}
		entry, err := getPemEntryImpl(rt, path, "")
		if err != nil {
			// Upstream's `except ValueError: pass` never catches the
			// SaltInvocationError get_pem_entry raises, so the failure
			// propagates out of the glob loop.
			return nil, err
		}
		out[path] = entry
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// key loading (_get_private_key_obj extension)

// parsePrivateKeyPEM accepts the PKCS#1/PKCS#8/SEC1 containers with
// optional legacy DEK-Info encryption.
func parsePrivateKeyPEM(data []byte, passphrase *string) (any, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, &invocationErr{msg: "Could not parse private key"}
	}
	raw := block.Bytes
	if _, encrypted := block.Headers["DEK-Info"]; encrypted {
		if passphrase == nil || *passphrase == "" {
			return nil, &invocationErr{msg: "Private key passphrase required"}
		}
		clear, derr := x509.DecryptPEMBlock(block, []byte(*passphrase))
		if derr != nil {
			return nil, &invocationErr{msg: "Could not decrypt private key"}
		}
		raw = clear
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(raw)
		if err != nil {
			return nil, &invocationErr{msg: "Could not parse private key"}
		}
		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(raw)
		if err != nil {
			return nil, &invocationErr{msg: "Could not parse private key"}
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(raw)
		if err != nil {
			return nil, &invocationErr{msg: "Could not parse private key"}
		}
		return key, nil
	case "ENCRYPTED PRIVATE KEY":
		return nil, &invocationErr{msg: "unsupported encrypted PKCS#8 private key"}
	default:
		return nil, &invocationErr{msg: "Could not parse private key"}
	}
}

// privateKeyBitSize reports the bit length the family surfaces for
// each supported key type.
func privateKeyBitSize(key any) (int, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k.PublicKey.N.BitLen(), nil
	case *ecdsa.PrivateKey:
		return k.PublicKey.Curve.Params().BitSize, nil
	case ed25519.PrivateKey:
		return 256, nil
	default:
		return 0, &invocationErr{msg: "unsupported private key type"}
	}
}

// publicKeyBitSize mirrors the same sizes for parsed public keys.
func publicKeyBitSize(pub any) (int, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen(), nil
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize, nil
	case ed25519.PublicKey:
		return 256, nil
	default:
		return 0, &invocationErr{msg: "unsupported public key type"}
	}
}

// get_private_key_size

type getPrivateKeySizeArgs struct {
	PrivateKey string  `statekit:"required,name=private_key"`
	Passphrase *string `statekit:"name=passphrase"`
}

type getPrivateKeySizeFunc struct{}

func (getPrivateKeySizeFunc) Name() string { return "x509.get_private_key_size" }
func (getPrivateKeySizeFunc) Args() any    { return getPrivateKeySizeArgs{} }
func (getPrivateKeySizeFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*getPrivateKeySizeArgs)
	entry, err := getPemEntryImpl(rt, a.PrivateKey, "(?:RSA |EC )?PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	key, kerr := parsePrivateKeyPEM([]byte(entry), a.Passphrase)
	if kerr != nil {
		return nil, kerr
	}
	return privateKeyBitSize(key)
}

// ---------------------------------------------------------------------------
// hex helpers (_pretty_hex / _dec2hex)

func prettyHexPairs(evenHex string) string {
	var parts []string
	for i := 0; i+2 <= len(evenHex); i += 2 {
		parts = append(parts, evenHex[i:i+2])
	}
	return strings.Join(parts, ":")
}

func prettyHex(data []byte) string {
	return prettyHexPairs(strings.ToUpper(hex.EncodeToString(data)))
}

// dec2hexBig ports _dec2hex(_pretty_hex(f"{n:X}")).
func dec2hexBig(n *big.Int) string {
	s := strings.ToUpper(n.Text(16))
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return prettyHexPairs(s)
}

// ---------------------------------------------------------------------------
// subject parsing (_parse_subject) and the OpenSSL name hash

// rawATV keeps the original value encoding so canonical re-encoding
// preserves the wire string types.
type rawATV struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

var oidShortNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.4":                    "SN",
	"2.5.4.42":                   "GN",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.9":                    "street",
	"2.5.4.17":                   "postalCode",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1":  "UID",
}

func shortNameFor(oid asn1.ObjectIdentifier) string {
	key := oid.String()
	if name, ok := oidShortNames[key]; ok {
		return name
	}
	return key
}

func isStringTag(tag int) bool {
	switch tag {
	case 12, 19, 20, 21, 22, 25, 26, 27, 28, 30: // UTF8String .. BMPString
		return true
	}
	return false
}

// unmarshalRDNs walks the raw X.509 Name DER (SEQUENCE OF SET OF
// SEQ{OID, value}) manually; encoding/asn1's slice decoder does not
// accept the nested SET OF shape.
func unmarshalRDNs(raw []byte) ([][]rawATV, error) {
	outer, err := walkTLV(raw, 0)
	if err != nil {
		return nil, err
	}
	if outer.id != 0x30 {
		return nil, &invocationErr{msg: "name is not a sequence"}
	}
	var rdns [][]rawATV
	setOff := 0
	for setOff < len(outer.content) {
		set, serr := walkTLV(outer.content, setOff)
		if serr != nil {
			return nil, serr
		}
		setOff = set.next
		if set.id != 0x31 {
			return nil, &invocationErr{msg: "RDN is not a set"}
		}
		var atvs []rawATV
		atvOff := 0
		for atvOff < len(set.content) {
			atv, aerr := walkTLV(set.content, atvOff)
			if aerr != nil {
				return nil, aerr
			}
			atvOff = atv.next
			if atv.id != 0x30 {
				return nil, &invocationErr{msg: "attribute is not a sequence"}
			}
			oidTLV, oerr := walkTLV(atv.content, 0)
			if oerr != nil {
				return nil, oerr
			}
			if oidTLV.id != 0x06 {
				return nil, &invocationErr{msg: "attribute type is not an OID"}
			}
			oid, derr := decodeOIDContent(oidTLV.content)
			if derr != nil {
				return nil, derr
			}
			valTLV, verr := walkTLV(atv.content, oidTLV.next)
			if verr != nil {
				return nil, verr
			}
			if valTLV.next != len(atv.content) {
				return nil, &invocationErr{msg: "trailing attribute bytes"}
			}
			atvs = append(atvs, rawATV{Type: oid, Value: rawValueOf(valTLV)})
		}
		rdns = append(rdns, atvs)
	}
	if setOff != len(outer.content) || outer.next != len(raw) {
		return nil, &invocationErr{msg: "trailing name bytes"}
	}
	return rdns, nil
}

// parseSubjectDict ports _parse_subject: short-name keyed dict; the
// source sorts by OpenSSL NID before assignment, which is equivalent
// to last-assignment-wins in wire order for the map-based result.
func parseSubjectDict(raw []byte) (map[string]string, error) {
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
			value := string(atv.Value.Bytes)
			if value == "" {
				// `if val:` drops empty attribute values upstream.
				continue
			}
			out[shortNameFor(atv.Type)] = value
		}
	}
	return out, nil
}

// derEncode prepends a DER header to content.
func derEncode(class, tag int, compound bool, content []byte) []byte {
	first := byte(class << 6)
	if compound {
		first |= 0x20
	}
	if tag >= 31 {
		// High tag numbers never occur in X.509 names.
		first |= 0x1f
	} else {
		first |= byte(tag)
	}
	var head []byte
	if len(content) < 0x80 {
		head = []byte{first, byte(len(content))}
	} else {
		l := len(content)
		var lenBytes []byte
		for l > 0 {
			lenBytes = append([]byte{byte(l & 0xff)}, lenBytes...)
			l >>= 8
		}
		head = append([]byte{first, 0x80 | byte(len(lenBytes))}, lenBytes...)
	}
	return append(head, content...)
}

// canonSpace applies the OpenSSL canonical whitespace rules: strip
// leading/trailing 0x20 and collapse internal runs to one space.
func canonSpace(b []byte) []byte {
	var out []byte
	i := 0
	for i < len(b) {
		if b[i] == ' ' {
			start := i
			for i < len(b) && b[i] == ' ' {
				i++
			}
			if i < len(b) && start > 0 && len(out) > 0 {
				out = append(out, ' ')
			}
			continue
		}
		out = append(out, b[i])
		i++
	}
	return out
}

// canonicalNameDER renders the OpenSSL canonical DER of an X.509 Name:
// string values whitespace-canonicalized, AVAs sorted inside each RDN.
func canonicalNameDER(raw []byte) ([]byte, error) {
	rdns, err := unmarshalRDNs(raw)
	if err != nil {
		return nil, err
	}
	var nameContent []byte
	for _, set := range rdns {
		var members [][]byte
		for _, atv := range set {
			oidDER, oerr := asn1.Marshal(atv.Type)
			if oerr != nil {
				return nil, oerr
			}
			valueEnc := atv.Value.FullBytes
			if valueEnc == nil {
				valueEnc = derEncode(atv.Value.Class, atv.Value.Tag, atv.Value.IsCompound, atv.Value.Bytes)
			}
			if isStringTag(atv.Value.Tag) && !atv.Value.IsCompound {
				valueEnc = derEncode(0, atv.Value.Tag, false, canonSpace(atv.Value.Bytes))
			}
			atvContent := append(append([]byte{}, oidDER...), valueEnc...)
			members = append(members, derEncode(0, 16, true, atvContent))
		}
		sort.Slice(members, func(i, j int) bool {
			return bytes.Compare(members[i], members[j]) < 0
		})
		var setContent []byte
		for _, m := range members {
			setContent = append(setContent, m...)
		}
		nameContent = append(nameContent, derEncode(0, 17, true, setContent)...)
	}
	return derEncode(0, 16, true, nameContent), nil
}

// nameHash is the OpenSSL X509_NAME_hash: SHA-1 over the canonical
// DER, first four bytes little-endian.
func nameHash(raw []byte) (uint32, error) {
	canon, err := canonicalNameDER(raw)
	if err != nil {
		return 0, err
	}
	sum := sha1.Sum(canon)
	return binary.LittleEndian.Uint32(sum[:4]), nil
}

func nameHashHex(raw []byte) (string, error) {
	h, err := nameHash(raw)
	if err != nil {
		return "", err
	}
	return dec2hexBig(new(big.Int).SetUint64(uint64(h))), nil
}

// ---------------------------------------------------------------------------
// certificate reading (_get_certificate_obj / read_certificate)

func parseCertificatePEMText(text string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, &invocationErr{msg: "Could not decode PEM certificate"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &invocationErr{msg: "Could not load certificate"}
	}
	return cert, nil
}

// getCertificateObj ports _get_certificate_obj.
func getCertificateObj(rt *runtime.Runtime, certificate string) (*x509.Certificate, error) {
	text, err := getPemEntryImpl(rt, certificate, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	return parseCertificatePEMText(text)
}

// certVersionOf normalizes the X.509 version the way
// get_version()+1 does (raw field 0 → v1).
func certVersionOf(cert *x509.Certificate) int {
	if cert.Version < 1 {
		return 1
	}
	return cert.Version
}

type readCertificateArgs struct {
	Certificate string `statekit:"required"`
}

type readCertificateFunc struct{}

func (readCertificateFunc) Name() string { return "x509.read_certificate" }
func (readCertificateFunc) Args() any    { return readCertificateArgs{} }
func (readCertificateFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*readCertificateArgs)
	return readCertificateImpl(rt, a.Certificate)
}

func readCertificateImpl(rt *runtime.Runtime, certificate string) (map[string]any, error) {
	cert, err := getCertificateObj(rt, certificate)
	if err != nil {
		return nil, err
	}
	subject, serr := parseSubjectDict(cert.RawSubject)
	if serr != nil {
		return nil, serr
	}
	issuer, ierr := parseSubjectDict(cert.RawIssuer)
	if ierr != nil {
		return nil, ierr
	}
	keySize, kerr := publicKeyBitSize(cert.PublicKey)
	if kerr != nil {
		return nil, kerr
	}
	subjectHash, sherr := nameHashHex(cert.RawSubject)
	if sherr != nil {
		return nil, sherr
	}
	issuerHash, iherr := nameHashHex(cert.RawIssuer)
	if iherr != nil {
		return nil, iherr
	}
	pubPEM, perr := publicKeyPEMOf(cert.PublicKey)
	if perr != nil {
		return nil, perr
	}

	sha1FP := sha1.Sum(cert.Raw)
	sha256FP := sha256.Sum256(cert.Raw)
	ret := map[string]any{
		"Version":              certVersionOf(cert),
		"Key Size":             keySize,
		"Serial Number":        dec2hexBig(cert.SerialNumber),
		"SHA-256 Finger Print": prettyHex(sha256FP[:]),
		"SHA1 Finger Print":    prettyHex(sha1FP[:]),
		"Subject":              subject,
		"Subject Hash":         subjectHash,
		"Issuer":               issuer,
		"Issuer Hash":          issuerHash,
		"Not Before":           cert.NotBefore.UTC().Format(dateTimeLayout),
		"Not After":            cert.NotAfter.UTC().Format(dateTimeLayout),
		"Public Key":           pubPEM,
	}
	if !fipsMode(rt) {
		md5FP := md5.Sum(cert.Raw)
		ret["MD5 Finger Print"] = prettyHex(md5FP[:])
	}

	exts := map[string]string{}
	for _, ext := range cert.Extensions {
		name, value, rerr := renderExtension(ext)
		if rerr != nil {
			continue
		}
		if ext.Critical {
			value = "critical " + value
		}
		exts[name] = value
	}
	if len(exts) > 0 {
		ret["X509v3 Extensions"] = exts
	}
	return ret, nil
}

// ---------------------------------------------------------------------------
// read_certificates

type readCertificatesArgs struct {
	GlobPath string `statekit:"required,name=glob_path"`
}

type readCertificatesFunc struct{}

func (readCertificatesFunc) Name() string { return "x509.read_certificates" }
func (readCertificatesFunc) Args() any    { return readCertificatesArgs{} }
func (readCertificatesFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*readCertificatesArgs)
	paths, gerr := rt.FS.Glob(a.GlobPath)
	if gerr != nil {
		return nil, gerr
	}
	out := map[string]any{}
	for _, path := range paths {
		if info, serr := rt.FS.Stat(path); serr != nil || info == nil || !info.Mode().IsRegular() {
			continue
		}
		entry, err := readCertificateImpl(rt, path)
		if err != nil {
			// Same dead `except ValueError` as upstream: parse
			// failures propagate.
			return nil, err
		}
		out[path] = entry
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// CSR reading (_get_request_obj / read_csr)

type readCsrArgs struct {
	Csr string `statekit:"required"`
}

type readCsrFunc struct{}

func (readCsrFunc) Name() string { return "x509.read_csr" }
func (readCsrFunc) Args() any    { return readCsrArgs{} }
func (readCsrFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*readCsrArgs)
	return readCsrImpl(rt, a.Csr)
}

func readCsrImpl(rt *runtime.Runtime, csr string) (map[string]any, error) {
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
	version := csrVersion(block.Bytes)
	subject, serr := parseSubjectDict(req.RawSubject)
	if serr != nil {
		return nil, serr
	}
	subjectHash, sherr := nameHashHex(req.RawSubject)
	if sherr != nil {
		return nil, sherr
	}
	pubHash := publicKeyHash(req.PublicKey)

	exts := map[string]string{}
	for _, ext := range req.Extensions {
		name, ok := csrExtensionName(ext.Id)
		if !ok {
			continue
		}
		_, value, rerr := renderExtension(ext)
		if rerr != nil {
			continue
		}
		if ext.Critical {
			value = "critical " + value
		}
		exts[name] = value
	}

	return map[string]any{
		"Version":           version,
		"Subject":           subject,
		"Subject Hash":      subjectHash,
		"Public Key Hash":   pubHash,
		"X509v3 Extensions": exts,
	}, nil
}

// csrVersion peeks the raw PKCS#10 version field (get_version()+1).
func csrVersion(der []byte) int {
	var outer struct {
		CRI    asn1.RawValue
		SigAlg pkix.AlgorithmIdentifier
		Sig    asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return 1
	}
	var cri struct {
		Version    int
		Subject    asn1.RawValue
		SPKI       asn1.RawValue
		Attributes asn1.RawValue `asn1:"optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(outer.CRI.FullBytes, &cri); err != nil {
		return 1
	}
	return cri.Version + 1
}

// publicKeyHash ports sha1(get_modulus()).hexdigest(): the plain
// lowercase hex digest of the minimal big-endian RSA modulus, or of
// the SPKI DER for the key types v1 never loaded.
func publicKeyHash(pub any) string {
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
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// expired / will_expire

type expiredArgs struct {
	Certificate string `statekit:"required"`
}

type expiredFunc struct{}

func (expiredFunc) Name() string { return "x509.expired" }
func (expiredFunc) Args() any    { return expiredArgs{} }
func (expiredFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*expiredArgs)
	return expiryReport(rt, a.Certificate, nil)
}

type willExpireArgs struct {
	Certificate string `statekit:"required"`
	Days        *int   `statekit:"required"`
}

type willExpireFunc struct{}

func (willExpireFunc) Name() string { return "x509.will_expire" }
func (willExpireFunc) Args() any    { return willExpireArgs{} }
func (willExpireFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*willExpireArgs)
	return expiryReport(rt, a.Certificate, a.Days)
}

// expiryReport ports the shared shape of expired/will_expire: non-file
// input returns {}, an unparseable file returns the partial {"path"}
// entry, and the comparison renders both sides as "%Y-%m-%d %H:%M:%S"
// UTC strings exactly like the source.
func expiryReport(rt *runtime.Runtime, certificate string, days *int) (map[string]any, error) {
	info, err := rt.FS.Stat(certificate)
	if err != nil || info == nil || !info.Mode().IsRegular() {
		return map[string]any{}, nil
	}
	ret := map[string]any{"path": certificate}
	if days != nil {
		ret["check_days"] = *days
	}
	cert, cerr := getCertificateObj(rt, certificate)
	if cerr != nil {
		// The source's swallowed ValueError branch keeps the partial
		// result (path, and check_days when set).
		return ret, nil
	}
	subject, serr := parseSubjectDict(cert.RawSubject)
	if serr != nil {
		return ret, nil
	}
	cn, ok := subject["CN"]
	if !ok {
		return nil, &invocationErr{msg: "KeyError: 'CN'"}
	}
	ret["cn"] = cn

	check := time.Now().UTC()
	if days != nil {
		check = check.Add(time.Duration(*days) * 24 * time.Hour)
	}
	expiration := cert.NotAfter.UTC().Format(dateTimeLayout)
	flag := "expired"
	if days != nil {
		flag = "will_expire"
	}
	ret[flag] = expiration <= check.Format(dateTimeLayout)
	return ret, nil
}

// ---------------------------------------------------------------------------
// get_public_key / verify_private_key

type getPublicKeyArgs struct {
	Key        string  `statekit:"required"`
	Passphrase *string `statekit:"name=passphrase"`
}

type getPublicKeyFunc struct{}

func (getPublicKeyFunc) Name() string { return "x509.get_public_key" }
func (getPublicKeyFunc) Args() any    { return getPublicKeyArgs{} }
func (getPublicKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*getPublicKeyArgs)
	return getPublicKeyImpl(rt, a.Key, a.Passphrase)
}

// publicKeyPEMOf marshals any supported public key to SPKI PEM text.
func publicKeyPEMOf(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", &invocationErr{msg: "Could not encode public key"}
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

// getPublicKeyImpl ports get_public_key: the first PEM entry decides
// the source (public key passthrough, certificate, CSR, private key).
func getPublicKeyImpl(rt *runtime.Runtime, key string, passphrase *string) (string, error) {
	text, err := getPemEntryImpl(rt, key, "")
	if err != nil {
		return "", err
	}
	switch {
	case strings.HasPrefix(text, "-----BEGIN PUBLIC KEY-----"):
		return text, nil
	case strings.HasPrefix(text, "-----BEGIN CERTIFICATE-----"):
		cert, cerr := parseCertificatePEMText(text)
		if cerr != nil {
			return "", cerr
		}
		return publicKeyPEMOf(cert.PublicKey)
	case strings.HasPrefix(text, "-----BEGIN CERTIFICATE REQUEST-----"):
		block, _ := pem.Decode([]byte(text))
		if block == nil {
			return "", &invocationErr{msg: "Could not decode PEM certificate request"}
		}
		req, perr := x509.ParseCertificateRequest(block.Bytes)
		if perr != nil {
			return "", &invocationErr{msg: "Could not load certificate request"}
		}
		return publicKeyPEMOf(req.PublicKey)
	case strings.HasPrefix(text, "-----BEGIN PRIVATE KEY-----"),
		strings.HasPrefix(text, "-----BEGIN RSA PRIVATE KEY-----"),
		strings.HasPrefix(text, "-----BEGIN EC PRIVATE KEY-----"):
		priv, lerr := parsePrivateKeyPEM([]byte(text), passphrase)
		if lerr != nil {
			return "", lerr
		}
		return publicKeyPEMOf(publicOf(priv))
	default:
		return "", &invocationErr{msg: "unsupported PEM type"}
	}
}

// publicOf extracts the crypto.PublicKey of a parsed private key.
func publicOf(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public()
	}
	return nil
}

type verifyPrivateKeyArgs struct {
	PrivateKey string  `statekit:"required,name=private_key"`
	PublicKey  string  `statekit:"required,name=public_key"`
	Passphrase *string `statekit:"name=passphrase"`
}

type verifyPrivateKeyFunc struct{}

func (verifyPrivateKeyFunc) Name() string { return "x509.verify_private_key" }
func (verifyPrivateKeyFunc) Args() any    { return verifyPrivateKeyArgs{} }
func (verifyPrivateKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverX509(&res, &err)
	a := args.(*verifyPrivateKeyArgs)
	privPEM, err := getPublicKeyImpl(rt, a.PrivateKey, a.Passphrase)
	if err != nil {
		return nil, err
	}
	pubPEM, err := getPublicKeyImpl(rt, a.PublicKey, nil)
	if err != nil {
		return nil, err
	}
	return privPEM == pubPEM, nil
}

// ---------------------------------------------------------------------------
// openssl-text extension rendering (shared by read_certificate and
// read_csr, mirroring the tls family's renderer shapes)

var (
	oidBasicConstraints  = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage          = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtendedKeyUsage  = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidSubjectKeyIdent   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAuthorityKeyIdent = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidSubjectAltName    = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidNsComment         = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13}
	oidNsCertType        = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}
)

// extShortNames maps the rendered extension families onto the short
// names M2Crypto's get_name() reports.
var extShortNames = []struct {
	oid  asn1.ObjectIdentifier
	name string
}{
	{oidBasicConstraints, "basicConstraints"},
	{oidKeyUsage, "keyUsage"},
	{oidExtendedKeyUsage, "extendedKeyUsage"},
	{oidSubjectKeyIdent, "subjectKeyIdentifier"},
	{oidAuthorityKeyIdent, "authorityKeyIdentifier"},
	{oidSubjectAltName, "subjectAltName"},
	{asn1.ObjectIdentifier{2, 5, 29, 31}, "crlDistributionPoints"},
	{asn1.ObjectIdentifier{2, 5, 29, 30}, "nameConstraints"},
	{asn1.ObjectIdentifier{2, 5, 29, 32}, "certificatePolicies"},
	{asn1.ObjectIdentifier{2, 5, 29, 36}, "policyConstraints"},
	{asn1.ObjectIdentifier{2, 5, 29, 54}, "inhibitAnyPolicy"},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}, "authorityInfoAccess"},
	{asn1.ObjectIdentifier{2, 5, 29, 28}, "issuingDistributionPoint"},
	{oidNsComment, "nsComment"},
	{oidNsCertType, "nsCertType"},
}

func extShortName(oid asn1.ObjectIdentifier) (string, bool) {
	for _, entry := range extShortNames {
		if oid.Equal(entry.oid) {
			return entry.name, true
		}
	}
	return "", false
}

// csrExtensionName restricts read_csr output to the EXT_NAME_MAPPINGS
// families the upstream YAML hack recognizes.
func csrExtensionName(oid asn1.ObjectIdentifier) (string, bool) {
	return extShortName(oid)
}

var keyUsageNames = []struct {
	name string
	bit  int
}{
	{"Digital Signature", 0}, {"Non Repudiation", 1}, {"Key Encipherment", 2},
	{"Data Encipherment", 3}, {"Key Agreement", 4}, {"Certificate Sign", 5},
	{"CRL Sign", 6}, {"Encipher Only", 7}, {"Decipher Only", 8},
}

var ekuNames = []struct {
	oid  asn1.ObjectIdentifier
	long string
}{
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}, "TLS Web Server Authentication"},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}, "TLS Web Client Authentication"},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}, "Code Signing"},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}, "E-mail Protection"},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}, "Time Stamping"},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}, "OCSP Signing"},
	{asn1.ObjectIdentifier{2, 5, 29, 37, 0}, "Any Extended Key Usage"},
}

// renderExtension returns the short name and the openssl text value
// of one extension; unknown families fall back to lowercase hex like
// the tls renderer.
func renderExtension(ext pkix.Extension) (string, string, error) {
	name, ok := extShortName(ext.Id)
	if !ok {
		return ext.Id.String(), strings.ToLower(hex.EncodeToString(ext.Value)), nil
	}
	var value string
	var err error
	switch {
	case ext.Id.Equal(oidBasicConstraints):
		value, err = decodeBasicConstraints(ext.Value)
	case ext.Id.Equal(oidKeyUsage):
		value, err = decodeKeyUsageText(ext.Value)
	case ext.Id.Equal(oidExtendedKeyUsage):
		value, err = decodeExtendedKeyUsageText(ext.Value)
	case ext.Id.Equal(oidSubjectKeyIdent):
		// The extension value wraps the key identifier in an OCTET
		// STRING; openssl prints the inner bytes.
		if t, terr := walkTLV(ext.Value, 0); terr == nil && t.id == 0x04 {
			value = prettyHex(t.content)
		} else {
			value = prettyHex(ext.Value)
		}
	case ext.Id.Equal(oidAuthorityKeyIdent):
		value, err = decodeAuthorityKeyIdentifierText(ext.Value)
	case ext.Id.Equal(oidSubjectAltName):
		value, err = decodeSubjectAltNameText(ext.Value)
	case ext.Id.Equal(oidNsComment):
		value = string(ext.Value)
	case ext.Id.Equal(oidNsCertType):
		value, err = decodeNsCertType(ext.Value)
	default:
		value = strings.ToLower(hex.EncodeToString(ext.Value))
	}
	if err != nil {
		return "", "", err
	}
	return name, value, nil
}

func decodeBasicConstraints(der []byte) (string, error) {
	var fields []asn1.RawValue
	if _, err := asn1.Unmarshal(der, &fields); err != nil {
		return "", err
	}
	ca := false
	pathLen, hasPathLen := -1, false
	for _, f := range fields {
		if f.Class == 0 && f.Tag == 1 {
			ca = len(f.Bytes) > 0 && f.Bytes[0] != 0
		}
		if f.Class == 0 && f.Tag == 2 {
			n := new(big.Int).SetBytes(f.Bytes)
			pathLen = int(n.Int64())
			hasPathLen = true
		}
	}
	out := "CA:FALSE"
	if ca {
		out = "CA:TRUE"
	}
	if hasPathLen {
		out += fmt.Sprintf(", pathlen:%d", pathLen)
	}
	return out, nil
}

func decodeKeyUsageText(der []byte) (string, error) {
	var bs asn1.BitString
	if _, err := asn1.Unmarshal(der, &bs); err != nil {
		return "", err
	}
	var names []string
	for _, bit := range keyUsageNames {
		if bit.bit < bs.BitLength && bs.Bytes[bit.bit/8]&(1<<(7-bit.bit%8)) != 0 {
			names = append(names, bit.name)
		}
	}
	return strings.Join(names, ", "), nil
}

func decodeExtendedKeyUsageText(der []byte) (string, error) {
	var oids []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(der, &oids); err != nil {
		return "", err
	}
	strs := make([]string, 0, len(oids))
	for _, oid := range oids {
		matched := false
		for _, entry := range ekuNames {
			if oid.Equal(entry.oid) {
				strs = append(strs, entry.long)
				matched = true
				break
			}
		}
		if !matched {
			strs = append(strs, oid.String())
		}
	}
	return strings.Join(strs, ", "), nil
}

// walkTLV splits one DER TLV at off into its identifier, content, and
// the full verbatim encoding.
type derTLV struct {
	id      byte
	content []byte
	full    []byte
	next    int
}

func walkTLV(der []byte, off int) (derTLV, error) {
	if off >= len(der) {
		return derTLV{}, &invocationErr{msg: "truncated DER"}
	}
	id := der[off]
	pos := off + 1
	if pos >= len(der) {
		return derTLV{}, &invocationErr{msg: "truncated DER"}
	}
	length := int(der[pos])
	pos++
	if length&0x80 != 0 {
		n := length & 0x7f
		if n == 0 || pos+n > len(der) {
			return derTLV{}, &invocationErr{msg: "truncated DER"}
		}
		length = 0
		for i := 0; i < n; i++ {
			length = length<<8 | int(der[pos+i])
		}
		pos += n
	}
	if pos+length > len(der) {
		return derTLV{}, &invocationErr{msg: "truncated DER"}
	}
	return derTLV{
		id:      id,
		content: der[pos : pos+length],
		full:    der[off : pos+length],
		next:    pos + length,
	}, nil
}

// decodeOIDContent decodes DER OBJECT IDENTIFIER content bytes.
func decodeOIDContent(content []byte) (asn1.ObjectIdentifier, error) {
	if len(content) == 0 {
		return nil, &invocationErr{msg: "empty object identifier"}
	}
	var oid asn1.ObjectIdentifier
	val := 0
	first := true
	for _, b := range content {
		val = val<<7 | int(b&0x7f)
		if b&0x80 != 0 {
			continue
		}
		if first {
			switch {
			case val < 40:
				oid = append(oid, 0, val)
			case val < 80:
				oid = append(oid, 1, val-40)
			default:
				oid = append(oid, 2, val-80)
			}
			first = false
		} else {
			oid = append(oid, val)
		}
		val = 0
	}
	if first || val != 0 {
		return nil, &invocationErr{msg: "truncated object identifier"}
	}
	return oid, nil
}

func rawValueOf(t derTLV) asn1.RawValue {
	return asn1.RawValue{
		Class:      int(t.id >> 6),
		Tag:        int(t.id & 0x1f),
		IsCompound: t.id&0x20 != 0,
		Bytes:      t.content,
		FullBytes:  t.full,
	}
}

func decodeAuthorityKeyIdentifierText(der []byte) (string, error) {
	var lines []string
	outer, err := walkTLV(der, 0)
	if err != nil {
		return "", err
	}
	content := outer.content
	if outer.id != 0x30 { // tolerate unwrapped forms
		content = der
	}
	off := 0
	for off < len(content) {
		t, terr := walkTLV(content, off)
		if terr != nil {
			return "", terr
		}
		off = t.next
		switch t.id {
		case 0x80: // [0] IMPLICIT keyIdentifier
			if len(t.content) > 0 {
				lines = append(lines, "keyid:"+prettyHex(t.content))
			}
		case 0xa1: // [1] IMPLICIT GeneralNames
			inner := 0
			for inner < len(t.content) {
				gn, gerr := walkTLV(t.content, inner)
				if gerr != nil {
					break
				}
				inner = gn.next
				if gn.id != 0xa4 { // [4] directoryName
					continue
				}
				rdns, rerr := unmarshalRDNs(gn.content)
				if rerr != nil {
					continue
				}
				var parts []string
				for _, set := range rdns {
					for _, atv := range set {
						parts = append(parts,
							"/"+shortNameFor(atv.Type)+"="+string(atv.Value.Bytes))
					}
				}
				lines = append(lines, "DirName:"+strings.Join(parts, ""))
			}
		case 0x82: // [2] IMPLICIT serialNumber
			lines = append(lines, "serial:"+dec2hexBig(new(big.Int).SetBytes(t.content)))
		}
	}
	return strings.Join(lines, "\n"), nil
}

func decodeSubjectAltNameText(der []byte) (string, error) {
	var entries []asn1.RawValue
	if _, err := asn1.Unmarshal(der, &entries); err != nil {
		return "", err
	}
	var parts []string
	for _, entry := range entries {
		value := entry.Bytes
		switch entry.Tag {
		case 1:
			parts = append(parts, "email:"+string(value))
		case 2:
			parts = append(parts, "DNS:"+string(value))
		case 6:
			parts = append(parts, "URI:"+string(value))
		case 7:
			parts = append(parts, "IP Address:"+net.IP(value).String())
		default:
			parts = append(parts, fmt.Sprintf("other:%X", entry.Tag))
		}
	}
	return strings.Join(parts, ", "), nil
}

var nsCertTypeBits = []struct {
	name string
	bit  int
}{
	{"SSL Client", 0}, {"SSL Server", 1}, {"SMIME", 2}, {"Object Signing", 3},
	{"Unused", 4}, {"SSL CA", 5}, {"SMIME CA", 6}, {"Object Signing CA", 7},
}

func decodeNsCertType(der []byte) (string, error) {
	var bs asn1.BitString
	if _, err := asn1.Unmarshal(der, &bs); err != nil {
		return "", err
	}
	var names []string
	for _, bit := range nsCertTypeBits {
		if bit.bit < bs.BitLength && bs.Bytes[bit.bit/8]&(1<<(7-bit.bit%8)) != 0 {
			names = append(names, bit.name)
		}
	}
	return strings.Join(names, ", "), nil
}

// Register installs the x509 surface: the R5.2a read-only subset, the
// R5.2b write-side subset and the R5.4 x509_v2 round (one canonical
// registration per public name, 24 total).
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		getPemEntryFunc{},
		getPemEntriesFunc{},
		getPrivateKeySizeFunc{},
		readCertificateFunc{},
		readCertificatesFunc{},
		readCsrFunc{},
		expiredFunc{},
		willExpireFunc{},
		verifyPrivateKeyFunc{},
		getPublicKeyFunc{},
		writePemFunc{},
		createPrivateKeyFunc{},
		createCrlFunc{},
		getSigningPolicyFunc{},
		createCertificateFunc{},
		createCsrFunc{},
		verifySignatureFunc{},
		verifyCrlFunc{},
		encodeCertificateFunc{},
		encodeCrlFunc{},
		encodeCsrFunc{},
		encodePrivateKeyFunc{},
		expiresFunc{},
		readCrlFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
