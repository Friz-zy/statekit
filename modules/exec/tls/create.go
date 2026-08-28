package tls

// Certificate and CSR creation flows mirroring
// salt.modules.tls.create_ca, create_csr, create_self_signed_cert,
// create_ca_signed_cert, create_pkcs12 and cert_info @ pinned
// revision. pyOpenSSL's X509Extension text forms are encoded onto DER
// for the profile this family emits, and cert_info renders the same
// profile back into OpenSSL's textual forms.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

// ---------------------------------------------------------------------------
// extension text -> DER encoders (X509Extension equivalents)

var (
	oidBasicConstraints  = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage          = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtendedKeyUsage  = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidSubjectAltName    = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidSubjectKeyIdent   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAuthorityKeyIdent = asn1.ObjectIdentifier{2, 5, 29, 35}
)

// encodeBasicConstraints renders "CA:TRUE, pathlen:0" / "CA:FALSE"
// onto the RFC 5280 SEQUENCE; the cA boolean is always explicit.
func encodeBasicConstraints(text string) ([]byte, error) {
	ca := false
	pathLen := -1
	for _, part := range strings.Split(text, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "CA:"):
			on, err := parseBool(strings.TrimPrefix(part, "CA:"))
			if err != nil {
				return nil, err
			}
			ca = on
		case strings.HasPrefix(part, "pathlen:"):
			n, err := parseAAtoi(strings.TrimPrefix(part, "pathlen:"))
			if err != nil {
				return nil, err
			}
			pathLen = n
		case part != "":
			return nil, fmt.Errorf("unsupported basicConstraints component %q", part)
		}
	}
	if pathLen >= 0 {
		value, err := asn1.Marshal(struct {
			IsCA    bool
			PathLen int
		}{ca, pathLen})
		return value, err
	}
	value, err := asn1.Marshal(struct{ IsCA bool }{ca})
	return value, err
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("invalid boolean %q", s)
}

var keyUsageBits = []struct {
	name string
	bit  int
}{
	{"digitalSignature", 0}, {"nonRepudiation", 1}, {"keyEncipherment", 2},
	{"dataEncipherment", 3}, {"keyAgreement", 4}, {"keyCertSign", 5},
	{"cRLSign", 6}, {"encipherOnly", 7}, {"decipherOnly", 8},
}

// encodeKeyUsage renders the OpenSSL keyUsage names onto the KU bit
// string.
func encodeKeyUsage(text string) ([]byte, error) {
	bits := [2]byte{}
	highest := -1
	for _, part := range strings.Split(text, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		matched := false
		for _, bit := range keyUsageBits {
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
	return asn1.Marshal(asn1.BitString{
		Bytes:     bits[:length],
		BitLength: highest + 1,
	})
}

// extKeyUsageTable maps the OpenSSL short names onto OIDs and the
// long names OpenSSL prints for cert_info.
var extKeyUsageTable = []struct {
	short string
	oid   asn1.ObjectIdentifier
	long  string
}{
	{"serverAuth", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1},
		"TLS Web Server Authentication"},
	{"clientAuth", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2},
		"TLS Web Client Authentication"},
	{"codeSigning", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3},
		"Code Signing"},
	{"emailProtection", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4},
		"E-mail Protection"},
	{"timeStamping", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8},
		"Time Stamping"},
	{"OCSPSigning", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9},
		"OCSP Signing"},
	{"anyExtendedKeyUsage", asn1.ObjectIdentifier{2, 5, 29, 37, 0},
		"anyExtendedKeyUsage"},
}

func encodeExtendedKeyUsage(text string) ([]byte, error) {
	var oids []asn1.ObjectIdentifier
	for _, part := range strings.Split(text, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		matched := false
		for _, entry := range extKeyUsageTable {
			if strings.EqualFold(entry.short, part) || strings.EqualFold(entry.long, part) {
				oids = append(oids, entry.oid)
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		if oid := parseOID(part); oid != nil {
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

func parseOID(s string) asn1.ObjectIdentifier {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil
	}
	oid := asn1.ObjectIdentifier{}
	for _, p := range parts {
		n, err := parseAAtoi(p)
		if err != nil || n < 0 {
			return nil
		}
		oid = append(oid, n)
	}
	return oid
}

// encodeSubjectAltName renders "DNS:foo, IP:1.2.3.4, email:x, URI:u"
// onto the GeneralNames sequence (implicit context-tagged primitives
// wrapped in one SEQUENCE).
func encodeSubjectAltName(text string) ([]byte, error) {
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
			body = append(body, generalName(2, []byte(value))...)
		case "IP", "IP Address":
			ip := net.ParseIP(value)
			if ip == nil {
				return nil, fmt.Errorf("invalid subjectAltName IP %q", value)
			}
			raw := ip.To4()
			if raw == nil {
				raw = ip.To16()
			}
			body = append(body, generalName(7, raw)...)
		case "email":
			body = append(body, generalName(1, []byte(value))...)
		case "URI":
			if _, uerr := url.Parse(value); uerr != nil {
				return nil, uerr
			}
			body = append(body, generalName(6, []byte(value))...)
		default:
			return nil, fmt.Errorf("unsupported subjectAltName entry %q", part)
		}
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("empty subjectAltName")
	}
	return derTLV(0x30, body), nil
}

// generalName wraps the value in the tagged implicit primitive
// ([context class] | tag, len, bytes).
func generalName(tag int, value []byte) []byte {
	return derTLV(0x80|byte(tag), value)
}

// derTLV renders tag-length-value with DER long-form lengths.
func derTLV(tag byte, content []byte) []byte {
	out := []byte{tag}
	switch n := len(content); {
	case n < 128:
		out = append(out, byte(n))
	case n < 256:
		out = append(out, 0x81, byte(n))
	case n < 65536:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, content...)
}

func parseAAtoi(s string) (int, error) {
	n := 0
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("invalid number")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid number %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// encodeNamedExtension turns one (name, openssl text) pair from an
// extension profile into a non-critical pkix.Extension. Returns
// handled=false for names outside the supported profile.
func encodeNamedExtension(name, text string) (pkix.Extension, bool, error) {
	switch name {
	case "basicConstraints":
		der, err := encodeBasicConstraints(text)
		if err != nil {
			return pkix.Extension{}, false, err
		}
		return pkix.Extension{Id: oidBasicConstraints, Critical: false, Value: der}, true, nil
	case "keyUsage":
		der, err := encodeKeyUsage(text)
		if err != nil {
			return pkix.Extension{}, false, err
		}
		return pkix.Extension{Id: oidKeyUsage, Critical: false, Value: der}, true, nil
	case "extendedKeyUsage":
		der, err := encodeExtendedKeyUsage(text)
		if err != nil {
			return pkix.Extension{}, false, err
		}
		return pkix.Extension{Id: oidExtendedKeyUsage, Critical: false, Value: der}, true, nil
	case "subjectAltName":
		der, err := encodeSubjectAltName(text)
		if err != nil {
			return pkix.Extension{}, false, err
		}
		return pkix.Extension{Id: oidSubjectAltName, Critical: false, Value: der}, true, nil
	default:
		return pkix.Extension{}, false, nil
	}
}

// ---------------------------------------------------------------------------
// create_ca

type createCAParams struct {
	CaName       string
	Bits         *int
	Days         *int
	CN           *string
	C            *string
	ST           *string
	L            *string
	O            *string
	OU           *string
	EmailAddress *string
	Fixmode      *bool
	CacertPath   *string
	CaFilename   *string
	Digest       *string
	Onlyif       any
	Unless       any
	Replace      *bool
}

type createCaArgs struct {
	CaName       string  `statekit:"required,name=ca_name"`
	Bits         *int    `statekit:"name=bits"`
	Days         *int    `statekit:"name=days"`
	CN           *string `statekit:"name=CN"`
	C            *string `statekit:"name=C"`
	ST           *string `statekit:"name=ST"`
	L            *string `statekit:"name=L"`
	O            *string `statekit:"name=O"`
	OU           *string `statekit:"name=OU"`
	EmailAddress *string `statekit:"name=emailAddress"`
	Fixmode      *bool   `statekit:"name=fixmode"`
	CacertPath   *string `statekit:"name=cacert_path"`
	CaFilename   *string `statekit:"name=ca_filename"`
	Digest       *string `statekit:"name=digest"`
	Onlyif       any     `statekit:"name=onlyif"`
	Unless       any     `statekit:"name=unless"`
	Replace      *bool   `statekit:"name=replace"`
}

type createCaFunc struct{}

func (createCaFunc) Name() string { return "tls.create_ca" }
func (createCaFunc) Args() any    { return createCaArgs{} }
func (createCaFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*createCaArgs)
	return createCAImpl(ctx, rt, createCAParams{
		CaName:       a.CaName,
		Bits:         a.Bits,
		Days:         a.Days,
		CN:           a.CN,
		C:            a.C,
		ST:           a.ST,
		L:            a.L,
		O:            a.O,
		OU:           a.OU,
		EmailAddress: a.EmailAddress,
		Fixmode:      a.Fixmode,
		CacertPath:   a.CacertPath,
		CaFilename:   a.CaFilename,
		Digest:       a.Digest,
		Onlyif:       a.Onlyif,
		Unless:       a.Unless,
		Replace:      a.Replace,
	})
}

func createCAImpl(ctx context.Context, rt *runtime.Runtime, p createCAParams) (res any, err error) {
	defer recoverTLS(&res, &err)

	status, serr := checkOnlyifUnless(ctx, rt, p.Onlyif, p.Unless)
	if serr != nil {
		return nil, serr
	}
	if status != nil {
		return nil, nil
	}

	if err := setCAPathImpl(rt, p.CacertPath); err != nil {
		return nil, err
	}

	caFilename := strArg(p.CaFilename, p.CaName+"_ca_cert")
	base := certBasePathImpl(rt, nil)
	certp := baseJoin(base, p.CaName, caFilename+".crt")
	caKeyp := baseJoin(base, p.CaName, caFilename+".key")

	replace := p.Replace != nil && *p.Replace
	fixmode := p.Fixmode != nil && *p.Fixmode
	if !replace && !fixmode {
		existsArgs := &caExistsArgs{CaName: p.CaName, CaFilename: &caFilename}
		exists, eerr := caExistsImpl(rt, existsArgs)
		if eerr == nil {
			if truthy, ok := exists.(bool); ok && truthy {
				return fmt.Sprintf("Certificate for CA named %q already exists", p.CaName), nil
			}
		}
	}
	if fixmode && !pathExists(rt, certp) {
		return nil, &invocationErr{msg: fmt.Sprintf("%s does not exists, can't fix", certp)}
	}

	if err := rt.FS.MkdirAll(baseJoin(base, p.CaName), 0o755); err != nil {
		return nil, err
	}

	bits := 2048
	if p.Bits != nil {
		bits = *p.Bits
	}
	days := 365
	if p.Days != nil {
		days = *p.Days
	}
	digest := "sha256"
	if p.Digest != nil && *p.Digest != "" {
		digest = *p.Digest
	}

	// try to reuse an existing key; unloadable material is set aside
	// with the .unloadable.<ts> backup name upstream uses
	var key *rsa.PrivateKey
	var keyErr error
	if pathExists(rt, caKeyp) {
		keyPEM, rerr := rt.FS.ReadFile(caKeyp)
		if rerr == nil {
			loaded, lerr := loadPrivateKeyPEM(keyPEM)
			if lerr == nil {
				if rk, ok := loaded.(*rsa.PrivateKey); ok {
					key = rk
				} else {
					keyErr = fmt.Errorf("non-RSA key")
				}
			} else {
				keyErr = lerr
			}
		} else {
			keyErr = rerr
		}
		if keyErr != nil {
			bck := caKeyp + ".unloadable." + time.Now().UTC().Format("20060102150405")
			if err := rt.FS.Rename(caKeyp, bck); err != nil {
				return nil, err
			}
		}
	}
	if key == nil {
		generated, gerr := rsa.GenerateKey(rand.Reader, bits)
		if gerr != nil {
			return nil, gerr
		}
		key = generated
	}

	serial, serialErr := newSerial(rt, p.CaName)
	if serialErr != nil {
		return nil, serialErr
	}
	sigAlg, err := signatureAlgorithmFor(digest, key)
	if err != nil {
		return nil, err
	}
	ski, err := skiFromKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	subject := buildSubject(strArg(p.C, "US"), strArg(p.ST, "Utah"),
		strArg(p.L, "Salt Lake City"), strArg(p.O, "SaltStack"),
		strArg(p.OU, ""), strArg(p.CN, "localhost"), strArg(p.EmailAddress, ""))

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(days) * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          ski,
		AuthorityKeyId:        ski, // keyid form only (see package notes)
		SignatureAlgorithm:    sigAlg,
	}
	caDER, cerr := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if cerr != nil {
		return nil, cerr
	}
	caCert, perr := x509.ParseCertificate(caDER)
	if perr != nil {
		return nil, perr
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	// upstream skips the rewrite when the stored key is identical and
	// otherwise saves the previous material aside
	writeKey := true
	if pathExists(rt, caKeyp) {
		oldData, rerr := rt.FS.ReadFile(caKeyp)
		if rerr == nil {
			if strings.TrimSpace(string(oldData)) == strings.TrimSpace(string(keyPEM)) {
				writeKey = false
			} else {
				bck := caKeyp + "." + time.Now().UTC().Format("20060102150405")
				if werr := rt.FS.WriteFile(bck, oldData, 0o600); werr != nil {
					return nil, werr
				}
			}
		}
	}
	if writeKey {
		if werr := rt.FS.WriteFile(caKeyp, keyPEM, 0o600); werr != nil {
			return nil, werr
		}
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if werr := rt.FS.WriteFile(certp, certPEM, 0o644); werr != nil {
		return nil, werr
	}

	if derr := writeCertToDatabase(rt, p.CaName, caCert, nil, "V"); derr != nil {
		return nil, derr
	}

	ret := fmt.Sprintf("Created Private Key: %q ", baseJoin(base, p.CaName, caFilename+".key"))
	ret += fmt.Sprintf("Created CA %q: %q", p.CaName, baseJoin(base, p.CaName, caFilename+".crt"))
	return ret, nil
}

// ---------------------------------------------------------------------------
// create_csr

type createCsrArgs struct {
	CaName         string   `statekit:"required,name=ca_name"`
	Bits           *int     `statekit:"name=bits"`
	CN             *string  `statekit:"name=CN"`
	C              *string  `statekit:"name=C"`
	ST             *string  `statekit:"name=ST"`
	L              *string  `statekit:"name=L"`
	O              *string  `statekit:"name=O"`
	OU             *string  `statekit:"name=OU"`
	EmailAddress   *string  `statekit:"name=emailAddress"`
	SubjectAltName []string `statekit:"name=subjectAltName"`
	CacertPath     *string  `statekit:"name=cacert_path"`
	CaFilename     *string  `statekit:"name=ca_filename"`
	CsrPath        *string  `statekit:"name=csr_path"`
	CsrFilename    *string  `statekit:"name=csr_filename"`
	Digest         *string  `statekit:"name=digest"`
	TypeExt        bool     `statekit:"name=type_ext"`
	CertType       string   `statekit:"name=cert_type"`
	Replace        *bool    `statekit:"name=replace"`
}

type createCsrFunc struct{}

func (createCsrFunc) Name() string { return "tls.create_csr" }
func (createCsrFunc) Args() any    { return createCsrArgs{} }
func (createCsrFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*createCsrArgs)

	if err := setCAPathImpl(rt, a.CacertPath); err != nil {
		return nil, err
	}
	base := certBasePathImpl(rt, nil)
	caFilename := strArg(a.CaFilename, a.CaName+"_ca_cert")

	exists, eerr := caExistsImpl(rt, &caExistsArgs{CaName: a.CaName, CaFilename: &caFilename})
	if eerr != nil {
		return nil, eerr
	}
	if truthy, ok := exists.(bool); !ok || !truthy {
		return fmt.Sprintf("Certificate for CA named %q does not exist, please create it first.", a.CaName), nil
	}

	csrPath := strArg(a.CsrPath, baseJoin(base, a.CaName, "certs/"))
	if merr := rt.FS.MkdirAll(csrPath, 0o755); merr != nil {
		return nil, merr
	}

	certType := a.CertType
	if certType == "" {
		certType = "server"
	}
	cn := strArg(a.CN, "localhost")
	cnExt := ""
	if a.TypeExt {
		cnExt = "_" + certType
	}
	csrFilename := strArg(a.CsrFilename, cn+cnExt)

	csrF := csrPath + "/" + csrFilename + ".csr"
	replace := a.Replace != nil && *a.Replace
	if !replace && pathExists(rt, csrF) {
		return fmt.Sprintf("Certificate Request %q already exists", csrF), nil
	}

	bits := 2048
	if a.Bits != nil {
		bits = *a.Bits
	}
	digest := "sha256"
	if a.Digest != nil && *a.Digest != "" {
		digest = *a.Digest
	}
	key, gerr := rsa.GenerateKey(rand.Reader, bits)
	if gerr != nil {
		return nil, gerr
	}
	sig, sigErr := signatureAlgorithmFor(digest, key)
	if sigErr != nil {
		return nil, sigErr
	}

	profile, perr := getExtensionsImpl(rt, certType)
	if perr != nil {
		return nil, perr
	}
	var extra []pkix.Extension
	for _, name := range sortedKeys(profile["csr"]) {
		ext, handled, eerr := encodeNamedExtension(name, profile["csr"][name])
		if eerr != nil {
			return nil, eerr
		}
		if !handled {
			return nil, fmt.Errorf("pillar extension %q is not supported by this port (documented boundary)", name)
		}
		extra = append(extra, ext)
	}
	if len(a.SubjectAltName) > 0 {
		// upstream normalizes a bare string into a one-entry list, then
		// comma-joins; OpenSSL parses the joined form
		entries := a.SubjectAltName
		san, serr := encodeSubjectAltName(strings.Join(entries, ", "))
		if serr != nil {
			return nil, serr
		}
		extra = append(extra, pkix.Extension{
			Id: oidSubjectAltName, Critical: false, Value: san,
		})
	}

	subject := buildSubject(strArg(a.C, "US"), strArg(a.ST, "Utah"),
		strArg(a.L, "Salt Lake City"), strArg(a.O, "SaltStack"),
		strArg(a.OU, ""), cn, strArg(a.EmailAddress, ""))

	req := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: sig,
		ExtraExtensions:    extra,
	}
	csrDER, cerr := x509.CreateCertificateRequest(rand.Reader, req, key)
	if cerr != nil {
		return nil, cerr
	}

	privKeyPath := csrPath + "/" + csrFilename + ".key"
	if werr := rt.FS.WriteFile(privKeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0o600); werr != nil {
		return nil, werr
	}
	if werr := rt.FS.WriteFile(csrF, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}), 0o644); werr != nil {
		return nil, werr
	}

	// upstream reports os.path.join paths (single separator) while the
	// files themselves live under the double-separator path
	msgPath := strings.TrimSuffix(csrPath, "/") + "/" + csrFilename
	ret := fmt.Sprintf("Created Private Key: %q ", msgPath+".key")
	ret += fmt.Sprintf("Created CSR for %q: %q", cn, msgPath+".csr")
	return ret, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// create_self_signed_cert

type createSelfSignedArgs struct {
	TlsDir       string  `statekit:"name=tls_dir"`
	Bits         *int    `statekit:"name=bits"`
	Days         *int    `statekit:"name=days"`
	CN           *string `statekit:"name=CN"`
	C            *string `statekit:"name=C"`
	ST           *string `statekit:"name=ST"`
	L            *string `statekit:"name=L"`
	O            *string `statekit:"name=O"`
	OU           *string `statekit:"name=OU"`
	EmailAddress *string `statekit:"name=emailAddress"`
	CacertPath   *string `statekit:"name=cacert_path"`
	CertFilename *string `statekit:"name=cert_filename"`
	Digest       *string `statekit:"name=digest"`
	Replace      *bool   `statekit:"name=replace"`
}

type createSelfSignedFunc struct{}

func (createSelfSignedFunc) Name() string { return "tls.create_self_signed_cert" }
func (createSelfSignedFunc) Args() any    { return createSelfSignedArgs{} }
func (createSelfSignedFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*createSelfSignedArgs)

	if err := setCAPathImpl(rt, a.CacertPath); err != nil {
		return nil, err
	}
	base := certBasePathImpl(rt, nil)
	tlsDir := a.TlsDir
	if tlsDir == "" {
		tlsDir = "tls"
	}
	if merr := rt.FS.MkdirAll(baseJoin(base, tlsDir, "certs"), 0o755); merr != nil {
		return nil, merr
	}

	cn := strArg(a.CN, "localhost")
	certFilename := strArg(a.CertFilename, cn)
	certp := baseJoin(base, tlsDir, "certs", certFilename+".crt")
	replace := a.Replace != nil && *a.Replace
	if !replace && pathExists(rt, certp) {
		return fmt.Sprintf("Certificate %q already exists", certFilename), nil
	}

	bits := 2048
	if a.Bits != nil {
		bits = *a.Bits
	}
	days := 365
	if a.Days != nil {
		days = *a.Days
	}
	digest := "sha256"
	if a.Digest != nil && *a.Digest != "" {
		digest = *a.Digest
	}
	key, gerr := rsa.GenerateKey(rand.Reader, bits)
	if gerr != nil {
		return nil, gerr
	}
	sig, sigErr := signatureAlgorithmFor(digest, key)
	if sigErr != nil {
		return nil, sigErr
	}
	serial, serialErr := newSerial(rt, tlsDir)
	if serialErr != nil {
		return nil, serialErr
	}

	subject := buildSubject(strArg(a.C, "US"), strArg(a.ST, "Utah"),
		strArg(a.L, "Salt Lake City"), strArg(a.O, "SaltStack"),
		strArg(a.OU, ""), cn, strArg(a.EmailAddress, ""))

	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            subject,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(time.Duration(days) * 24 * time.Hour),
		SignatureAlgorithm: sig,
	}
	der, cerr := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if cerr != nil {
		return nil, cerr
	}
	cert, perr := x509.ParseCertificate(der)
	if perr != nil {
		return nil, perr
	}

	privKeyPath := baseJoin(base, tlsDir, "certs", certFilename+".key")
	if werr := rt.FS.WriteFile(privKeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0o600); werr != nil {
		return nil, werr
	}
	if werr := rt.FS.WriteFile(certp, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: der,
	}), 0o644); werr != nil {
		return nil, werr
	}

	if derr := writeCertToDatabase(rt, tlsDir, cert, nil, "V"); derr != nil {
		return nil, derr
	}

	ret := fmt.Sprintf("Created Private Key: %q ",
		baseJoin(base, tlsDir, "certs", certFilename+".key"))
	ret += fmt.Sprintf("Created Certificate: %q",
		baseJoin(base, tlsDir, "certs", certFilename+".crt"))
	return ret, nil
}

// ---------------------------------------------------------------------------
// create_ca_signed_cert

type createCaSignedArgs struct {
	CaName       string  `statekit:"required,name=ca_name"`
	CN           string  `statekit:"required,name=CN"`
	Days         *int    `statekit:"name=days"`
	CacertPath   *string `statekit:"name=cacert_path"`
	CaFilename   *string `statekit:"name=ca_filename"`
	CertPath     *string `statekit:"name=cert_path"`
	CertFilename *string `statekit:"name=cert_filename"`
	Digest       *string `statekit:"name=digest"`
	CertType     *string `statekit:"name=cert_type"`
	TypeExt      bool    `statekit:"name=type_ext"`
	Replace      *bool   `statekit:"name=replace"`
}

type createCaSignedFunc struct{}

func (createCaSignedFunc) Name() string { return "tls.create_ca_signed_cert" }
func (createCaSignedFunc) Args() any    { return createCaSignedArgs{} }
func (createCaSignedFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*createCaSignedArgs)

	if err := setCAPathImpl(rt, a.CacertPath); err != nil {
		return nil, err
	}
	base := certBasePathImpl(rt, nil)
	caFilename := strArg(a.CaFilename, a.CaName+"_ca_cert")
	certPath := strArg(a.CertPath, baseJoin(base, a.CaName, "certs"))

	cnExt := ""
	if a.TypeExt {
		if a.CertType == nil || *a.CertType == "" {
			// upstream logs the condition and returns the empty dict
			return map[string]any{}, nil
		}
		cnExt = "_" + *a.CertType
	}
	csrFilename := a.CN + cnExt
	certFilename := strArg(a.CertFilename, a.CN+cnExt)

	certFull := baseJoin(base, a.CaName, "certs", certFilename+".crt")
	replace := a.Replace != nil && *a.Replace
	if !replace && pathExists(rt, certFull) {
		return fmt.Sprintf("Certificate %q already exists", certFilename), nil
	}

	if _, fixerr := maybeFixImpl(rt, &maybeFixSSLVersionArgs{
		CaName: a.CaName, CacertPath: a.CacertPath, CaFilename: &caFilename}); fixerr != nil {
		// upstream wraps maybe_fix + the CA loads in one try block and
		// reports any OSError there as the no-CA reply
		if errors.Is(fixerr, errTLSUnreadable) {
			return map[string]any{
				"retcode": 1,
				"comment": fmt.Sprintf("There is no CA named %q", a.CaName),
			}, nil
		}
		return nil, fixerr
	}

	caCert, caKey, caErr := loadCACertKey(rt,
		baseJoin(base, a.CaName, caFilename+".crt"),
		baseJoin(base, a.CaName, caFilename+".key"))
	if caErr != nil {
		return map[string]any{
			"retcode": 1,
			"comment": fmt.Sprintf("There is no CA named %q", a.CaName),
		}, nil
	}

	csrPath := certPath + "/" + csrFilename + ".csr"
	csrPEM, csrErr := rt.FS.ReadFile(csrPath)
	if csrErr != nil {
		return map[string]any{
			"retcode": 1,
			"comment": fmt.Sprintf("There is no CSR that matches the CN %q", certFilename),
		}, nil
	}
	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil {
		return nil, fmt.Errorf("unable to load CSR %s", csrPath)
	}
	csr, perr := x509.ParseCertificateRequest(csrBlock.Bytes)
	if perr != nil {
		return nil, perr
	}

	days := 365
	if a.Days != nil {
		days = *a.Days
	}
	digest := "sha256"
	if a.Digest != nil && *a.Digest != "" {
		digest = *a.Digest
	}
	sig, sigErr := signatureAlgorithmFor(digest, caKey)
	if sigErr != nil {
		return nil, sigErr
	}
	serial, serialErr := newSerial(rt, a.CaName)
	if serialErr != nil {
		return nil, serialErr
	}

	cert := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            csr.Subject,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(time.Duration(days) * 24 * time.Hour),
		ExtraExtensions:    append([]pkix.Extension{}, csr.Extensions...),
		SignatureAlgorithm: sig,
	}
	certDER, cerr := x509.CreateCertificate(rand.Reader, cert, caCert, csr.PublicKey, caKey)
	if cerr != nil {
		return nil, cerr
	}
	parsed, pperr := x509.ParseCertificate(certDER)
	if pperr != nil {
		return nil, pperr
	}

	certOut := certPath + "/" + certFilename + ".crt"
	if werr := rt.FS.WriteFile(certOut, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: certDER,
	}), 0o644); werr != nil {
		return nil, werr
	}

	if derr := writeCertToDatabase(rt, a.CaName, parsed, nil, "V"); derr != nil {
		return nil, derr
	}

	return fmt.Sprintf("Created Certificate for %q: %q",
		a.CN, certPath+"/"+certFilename+".crt"), nil
}

// ---------------------------------------------------------------------------
// create_pkcs12 (documented boundary)

type createPkcs12Args struct {
	CaName     string  `statekit:"required,name=ca_name"`
	CN         string  `statekit:"required,name=CN"`
	Passphrase *string `statekit:"name=passphrase"`
	CacertPath *string `statekit:"name=cacert_path"`
	Replace    *bool   `statekit:"name=replace"`
}

type createPkcs12Func struct{}

func (createPkcs12Func) Name() string { return "tls.create_pkcs12" }
func (createPkcs12Func) Args() any    { return createPkcs12Args{} }
func (createPkcs12Func) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*createPkcs12Args)

	if err := setCAPathImpl(rt, a.CacertPath); err != nil {
		return nil, err
	}
	base := certBasePathImpl(rt, nil)
	if a.Replace == nil || !*a.Replace {
		if pathExists(rt, baseJoin(base, a.CaName, "certs", a.CN+".p12")) {
			return fmt.Sprintf("Certificate %q already exists", a.CN), nil
		}
	}
	if !pathExists(rt, baseJoin(base, a.CaName, a.CaName+"_ca_cert.crt")) {
		return fmt.Sprintf("There is no CA named %q", a.CaName), nil
	}
	if !pathExists(rt, baseJoin(base, a.CaName, "certs", a.CN+".crt")) ||
		!pathExists(rt, baseJoin(base, a.CaName, "certs", a.CN+".key")) {
		return fmt.Sprintf("There is no certificate that matches the CN %q", a.CN), nil
	}

	// The PKCS#12 serialization itself awaits the x/crypto encoder
	// release (see package notes); the boundary stays explicit rather
	// than hand-rolled.
	return nil, &runtime.UnsupportedError{
		Kind: "serialization",
		Name: "tls.create_pkcs12(pkcs12 encoder pending in golang.org/x/crypto)",
	}
}

// ---------------------------------------------------------------------------
// cert_info

type certInfoArgs struct {
	Cert   string  `statekit:"required,name=cert"`
	Digest *string `statekit:"name=digest"`
}

type certInfoFunc struct{}

func (certInfoFunc) Name() string { return "tls.cert_info" }
func (certInfoFunc) Args() any    { return certInfoArgs{} }
func (certInfoFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*certInfoArgs)
	digest := "sha256"
	if a.Digest != nil && *a.Digest != "" {
		digest = *a.Digest
	}
	cert, cerr := readCert(rt, a.Cert)
	if cerr != nil {
		return nil, cerr
	}
	return certInfoOf(cert, digest)
}

func certInfoOf(cert *x509.Certificate, digest string) (map[string]any, error) {
	hash, ok := digestHash(digest)
	if !ok {
		return nil, fmt.Errorf("No such digest algorithm: '%s'", digest)
	}

	h := hash.New()
	h.Write(cert.Raw)
	out := map[string]any{
		"subject":             attributeDict(cert.RawSubject),
		"issuer":              attributeDict(cert.RawIssuer),
		"serial_number":       cert.SerialNumber,
		"not_before":          cert.NotBefore.UTC().Unix(),
		"not_after":           cert.NotAfter.UTC().Unix(),
		"signature_algorithm": opensslSigAlgName(cert.SignatureAlgorithm),
		"fingerprint":         colonHex(h.Sum(nil)),
	}

	exts := map[string]string{}
	for _, ext := range cert.Extensions {
		name, value, rerr := renderExtension(cert, ext)
		if rerr != nil {
			continue
		}
		exts[name] = value
	}
	out["extensions"] = exts

	if san, ok := exts["subjectAltName"]; ok {
		var names []string
		for _, entry := range strings.Split(san, ", ") {
			idx := strings.Index(entry, ":")
			if idx <= 0 {
				continue
			}
			kind, value := entry[:idx], entry[idx+1:]
			if kind == "DNS" || kind == "IP Address" {
				names = append(names, value)
			}
		}
		sortStrings(names)
		out["subject_alt_names"] = names
	}
	return out, nil
}

func attributeDict(raw []byte) map[string]string {
	out := map[string]string{}
	comps, err := subjectValues(raw)
	if err != nil {
		return out
	}
	for _, c := range comps {
		out[c.Short] = c.Value
	}
	return out
}

func colonHex(data []byte) string {
	raw := strings.ToUpper(hex.EncodeToString(data))
	var parts []string
	for i := 0; i+2 <= len(raw); i += 2 {
		parts = append(parts, raw[i:i+2])
	}
	return strings.Join(parts, ":")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// opensslSigAlgName maps Go's signature algorithms onto the long names
// pyOpenSSL's get_signature_algorithm reports.
func opensslSigAlgName(alg x509.SignatureAlgorithm) string {
	switch alg {
	case x509.MD5WithRSA:
		return "md5WithRSAEncryption"
	case x509.SHA1WithRSA:
		return "sha1WithRSAEncryption"
	case x509.SHA256WithRSA:
		return "sha256WithRSAEncryption"
	case x509.SHA384WithRSA:
		return "sha384WithRSAEncryption"
	case x509.SHA512WithRSA:
		return "sha512WithRSAEncryption"
	case x509.SHA256WithRSAPSS:
		return "rsassaPss"
	case x509.ECDSAWithSHA1:
		return "ecdsa-with-SHA1"
	case x509.ECDSAWithSHA256:
		return "ecdsa-with-SHA256"
	case x509.ECDSAWithSHA384:
		return "ecdsa-with-SHA384"
	case x509.ECDSAWithSHA512:
		return "ecdsa-with-SHA512"
	case x509.PureEd25519:
		return "ED25519"
	default:
		return alg.String()
	}
}

// ---------------------------------------------------------------------------
// extension rendering for cert_info (OpenSSL textual forms)

func renderExtension(_ *x509.Certificate, ext pkix.Extension) (string, string, error) {
	switch {
	case ext.Id.Equal(oidBasicConstraints):
		value, err := decodeBasicConstraints(ext.Value)
		if err != nil {
			return "", "", err
		}
		return "basicConstraints", value, nil
	case ext.Id.Equal(oidKeyUsage):
		value, err := decodeKeyUsage(ext.Value)
		if err != nil {
			return "", "", err
		}
		return "keyUsage", value, nil
	case ext.Id.Equal(oidExtendedKeyUsage):
		value, err := decodeExtendedKeyUsage(ext.Value)
		if err != nil {
			return "", "", err
		}
		return "extendedKeyUsage", value, nil
	case ext.Id.Equal(oidSubjectAltName):
		value, err := decodeSubjectAltName(ext.Value)
		if err != nil {
			return "", "", err
		}
		return "subjectAltName", value, nil
	case ext.Id.Equal(oidSubjectKeyIdent):
		return "subjectKeyIdentifier", colonHex(ext.Value), nil
	case ext.Id.Equal(oidAuthorityKeyIdent):
		value, err := decodeAuthorityKeyIdentifier(ext.Value)
		if err != nil {
			return "", "", err
		}
		return "authorityKeyIdentifier", value, nil
	default:
		return ext.Id.String(), strings.ToLower(hex.EncodeToString(ext.Value)), nil
	}
}

func decodeBasicConstraints(der []byte) (string, error) {
	var fields []asn1.RawValue
	if _, err := asn1.Unmarshal(der, &fields); err != nil {
		return "", err
	}
	ca := false
	pathLen, hasPathLen := -1, false
	for i, f := range fields {
		_ = i
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

var keyUsageNames = []struct {
	name string
	bit  int
}{
	{"Digital Signature", 0}, {"Non Repudiation", 1}, {"Key Encipherment", 2},
	{"Data Encipherment", 3}, {"Key Agreement", 4}, {"Certificate Sign", 5},
	{"CRL Sign", 6}, {"Encipher Only", 7}, {"Decipher Only", 8},
}

func decodeKeyUsage(der []byte) (string, error) {
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

func decodeExtendedKeyUsage(der []byte) (string, error) {
	var oids []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(der, &oids); err != nil {
		return "", err
	}
	strs := make([]string, 0, len(oids))
	for _, oid := range oids {
		matched := false
		for _, entry := range extKeyUsageTable {
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

func decodeSubjectAltName(der []byte) (string, error) {
	var entries []asn1.RawValue
	if _, err := asn1.Unmarshal(der, &entries); err != nil {
		return "", err
	}
	var parts []string
	for _, entry := range entries {
		// GeneralNames are implicit context tags; the bytes follow the
		// header stripped of its tag
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

func decodeAuthorityKeyIdentifier(der []byte) (string, error) {
	var aki struct {
		KeyID []byte `asn1:"optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &aki); err != nil {
		var alt struct {
			KeyID             []byte        `asn1:"optional,explicit,tag:0"`
			AuthorityCertName asn1.RawValue `asn1:"optional,explicit,tag:1"`
			AuthorityCertSN   *big.Int      `asn1:"optional,explicit,tag:2"`
		}
		if _, err2 := asn1.Unmarshal(der, &alt); err2 != nil {
			return "", err2
		}
		if len(alt.KeyID) > 0 {
			return "keyid:" + colonHex(alt.KeyID), nil
		}
		return "keyid:", nil
	}
	if len(aki.KeyID) > 0 {
		return "keyid:" + colonHex(aki.KeyID), nil
	}
	return "keyid:", nil
}
