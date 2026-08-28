package tls

// CRL flows mirroring salt.modules.tls.validate, create_empty_crl and
// revoke_cert @ pinned revision, backed by crypto/x509's revocation
// list support.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

// crlNextUpdate mirrors upstream's 36500-day (100 year) horizon.
const crlNextUpdateDays = 36500

// indexRevocation is one R row of the index.txt database.
type indexRevocation struct {
	Serial *big.Int
	Date   time.Time
}

// parseIndexRevocations scans index.txt R rows the way upstream's
// cryptography branch does, including the 159-bit serial truncation.
func parseIndexRevocations(rt *runtime.Runtime, indexFile string) ([]indexRevocation, error) {
	data, err := rt.FS.ReadFile(indexFile)
	if err != nil {
		return nil, err
	}
	var out []indexRevocation
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "R") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}
		serial, ok := new(big.Int).SetString(fields[3], 16)
		if !ok {
			return nil, fmt.Errorf("invalid serial %q in %s", fields[3], indexFile)
		}
		if serial.BitLen() >= 160 {
			// cryptography's CRL builder caps serials at 159 bits
			mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 159), big.NewInt(1))
			serial = new(big.Int).And(serial, mask)
		}
		date, derr := time.Parse(twoDigitYearFmt, fields[2])
		if derr != nil {
			return nil, derr
		}
		out = append(out, indexRevocation{Serial: serial, Date: date})
	}
	return out, nil
}

// buildCRL assembles a signed revocation list from the ca pair.
func buildCRL(issuer *x509.Certificate, key any, digest string, revocations []indexRevocation) ([]byte, error) {
	sigAlg, err := signatureAlgorithmFor(digest, key)
	if err != nil {
		// upstream's CRL builders fall back to SHA256 for unknown
		// digest names (getattr default)
		fallback, ferr := signatureAlgorithmFor("sha256", key)
		if ferr != nil {
			return nil, ferr
		}
		sigAlg = fallback
	}
	tmpl := &x509.RevocationList{
		Number:             big.NewInt(1), // Go requires a CRL number; upstream omits it
		ThisUpdate:         time.Now(),
		NextUpdate:         time.Now().Add(crlNextUpdateDays * 24 * time.Hour),
		SignatureAlgorithm: sigAlg,
	}
	for _, rev := range revocations {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries,
			x509.RevocationListEntry{
				SerialNumber:   rev.Serial,
				RevocationTime: rev.Date,
			})
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported CA key type %T for CRL signing", key)
	}
	return x509.CreateRevocationList(rand.Reader, tmpl, issuer, signer)
}

// ---------------------------------------------------------------------------
// validate

type validateArgs struct {
	Cert    string  `statekit:"required,name=cert"`
	CaName  string  `statekit:"required,name=ca_name"`
	CrlFile *string `statekit:"name=crl_file"`
}

type validateFunc struct{}

func (validateFunc) Name() string { return "tls.validate" }
func (validateFunc) Args() any    { return validateArgs{} }
func (validateFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*validateArgs)

	if err := setCAPathImpl(rt, nil); err != nil {
		return nil, err
	}
	cert, cerr := readCert(rt, a.Cert)
	if cerr != nil {
		return nil, &invocationErr{
			msg: fmt.Sprintf("Failed to read cert from %s, see log for details", a.Cert),
		}
	}
	base := certBasePathImpl(rt, nil)
	caDir := baseJoin(base, a.CaName)
	caCert, rerr := readCert(rt, caDir+"/"+a.CaName+"_ca_cert.crt")
	if rerr != nil {
		return nil, &invocationErr{
			msg: fmt.Sprintf("Failed to read CA cert for %s, see log for details", a.CaName),
		}
	}

	// revocation surface: a CRL file, or the index.txt R rows like
	// upstream's on-the-fly empty-CRL path
	var crlSerials map[string]bool = map[string]bool{}
	if a.CrlFile != nil {
		crlPEM, crlErr := rt.FS.ReadFile(*a.CrlFile)
		if crlErr != nil {
			return nil, crlErr
		}
		block, _ := pem.Decode(crlPEM)
		if block == nil {
			return nil, fmt.Errorf("unable to load CRL %s", *a.CrlFile)
		}
		crl, perr := x509.ParseRevocationList(block.Bytes)
		if perr != nil {
			return nil, perr
		}
		if serr := crl.CheckSignatureFrom(caCert); serr != nil {
			return map[string]any{
				"valid": false,
				"error": "CRL signature verification failed",
			}, nil
		}
		if !crl.NextUpdate.IsZero() && crl.NextUpdate.Before(time.Now()) {
			return map[string]any{"valid": false, "error": "CRL has expired"}, nil
		}
		for _, entry := range crl.RevokedCertificates {
			crlSerials[entry.SerialNumber.String()] = true
		}
	} else {
		// the empty-CRL path still needs the CA key upstream; a missing
		// or unreadable key mirrors the upstream error dict
		keyPEM, kerr := rt.FS.ReadFile(caDir + "/" + a.CaName + "_ca_cert.key")
		if kerr != nil {
			return map[string]any{
				"valid": false,
				"error": "Empty CRL requested but CA key missing or invalid",
			}, nil
		}
		if _, lerr := loadPrivateKeyPEM(keyPEM); lerr != nil {
			return map[string]any{
				"valid": false,
				"error": "Empty CRL requested but CA key missing or invalid",
			}, nil
		}
		revocations, ierr := parseIndexRevocations(rt, caDir+"/index.txt")
		if ierr == nil {
			for _, rev := range revocations {
				crlSerials[rev.Serial.String()] = true
			}
		}
	}

	// upstream's HAS_CRYPTOGRAPHY pre-check reports the leaf serial
	// against the CRL before chain validation; serials at or beyond
	// 160 bits are truncated to 159 bits on the lookup key the same way
	serialCheck := cert.SerialNumber
	if serialCheck.BitLen() >= 160 {
		mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 159), big.NewInt(1))
		serialCheck = new(big.Int).And(cert.SerialNumber, mask)
	}
	if crlSerials[serialCheck.String()] {
		return map[string]any{
			"valid":      false,
			"error":      "certificate revoked",
			"error_cert": pemEncodeCert(cert.Raw),
		}, nil
	}

	// chain validation mirrors X509StoreContext for the single-CA
	// hierarchies this module creates; the OpenSSL reason strings are
	// reused for the failure modes ported here and error_cert carries
	// the PEM text of the failing certificate (object handles do not
	// cross the Go boundary)
	leafPEM := pemEncodeCert(cert.Raw)
	caPEM := pemEncodeCert(caCert.Raw)
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return map[string]any{
			"valid": false, "error": "certificate is not yet valid",
			"error_cert": leafPEM,
		}, nil
	}
	if now.After(cert.NotAfter) {
		return map[string]any{
			"valid": false, "error": "certificate has expired",
			"error_cert": leafPEM,
		}, nil
	}
	if now.Before(caCert.NotBefore) {
		return map[string]any{
			"valid": false, "error": "certificate is not yet valid",
			"error_cert": caPEM,
		}, nil
	}
	if now.After(caCert.NotAfter) {
		return map[string]any{
			"valid": false, "error": "certificate has expired",
			"error_cert": caPEM,
		}, nil
	}
	if !bytesEqual(cert.RawIssuer, caCert.RawSubject) {
		return map[string]any{
			"valid":      false,
			"error":      "unable to get local issuer certificate",
			"error_cert": leafPEM,
		}, nil
	}
	if serr := cert.CheckSignatureFrom(caCert); serr != nil {
		return map[string]any{
			"valid":      false,
			"error":      "certificate signature failure",
			"error_cert": leafPEM,
		}, nil
	}
	return map[string]any{"valid": true}, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func pemEncodeCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// ---------------------------------------------------------------------------
// create_empty_crl

type createEmptyCrlArgs struct {
	CaName     string  `statekit:"required,name=ca_name"`
	CacertPath *string `statekit:"name=cacert_path"`
	CaFilename *string `statekit:"name=ca_filename"`
	CrlFile    *string `statekit:"name=crl_file"`
	Digest     *string `statekit:"name=digest"`
}

type createEmptyCrlFunc struct{}

func (createEmptyCrlFunc) Name() string { return "tls.create_empty_crl" }
func (createEmptyCrlFunc) Args() any    { return createEmptyCrlArgs{} }
func (createEmptyCrlFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*createEmptyCrlArgs)

	if err := setCAPathImpl(rt, a.CacertPath); err != nil {
		return nil, err
	}
	base := certBasePathImpl(rt, nil)
	caFilename := strArg(a.CaFilename, a.CaName+"_ca_cert")
	crlFile := strArg(a.CrlFile, baseJoin(base, a.CaName, "crl.pem"))

	if pathExists(rt, crlFile) {
		return fmt.Sprintf("CRL %q already exists", crlFile), nil
	}

	caCert, caKey, caErr := loadCACertKey(rt,
		baseJoin(base, a.CaName, caFilename+".crt"),
		baseJoin(base, a.CaName, caFilename+".key"))
	if caErr != nil {
		return fmt.Sprintf("There is no CA named %q", a.CaName), nil
	}

	digest := "sha256"
	if a.Digest != nil && *a.Digest != "" {
		digest = *a.Digest
	}
	der, berr := buildCRL(caCert, caKey, digest, nil)
	if berr != nil {
		return nil, berr
	}
	if werr := rt.FS.WriteFile(crlFile, pem.EncodeToMemory(&pem.Block{
		Type: "X509 CRL", Bytes: der,
	}), 0o644); werr != nil {
		return nil, werr
	}
	return fmt.Sprintf("Created an empty CRL: %q", crlFile), nil
}

// ---------------------------------------------------------------------------
// revoke_cert

type revokeCertArgs struct {
	CaName       string  `statekit:"required,name=ca_name"`
	CN           string  `statekit:"required,name=CN"`
	CacertPath   *string `statekit:"name=cacert_path"`
	CaFilename   *string `statekit:"name=ca_filename"`
	CertPath     *string `statekit:"name=cert_path"`
	CertFilename *string `statekit:"name=cert_filename"`
	CrlFile      *string `statekit:"name=crl_file"`
	Digest       *string `statekit:"name=digest"`
}

type revokeCertFunc struct{}

func (revokeCertFunc) Name() string { return "tls.revoke_cert" }
func (revokeCertFunc) Args() any    { return revokeCertArgs{} }
func (revokeCertFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*revokeCertArgs)

	if err := setCAPathImpl(rt, a.CacertPath); err != nil {
		return nil, err
	}
	base := certBasePathImpl(rt, nil)
	caDir := baseJoin(base, a.CaName)

	caFilename := strArg(a.CaFilename, a.CaName+"_ca_cert")
	certPath := strArg(a.CertPath, baseJoin(base, a.CaName, "certs"))
	certFilename := strArg(a.CertFilename, a.CN)

	caCert, caKey, caErr := loadCACertKey(rt,
		baseJoin(base, a.CaName, caFilename+".crt"),
		baseJoin(base, a.CaName, caFilename+".key"))
	if caErr != nil {
		return fmt.Sprintf("There is no CA named %q", a.CaName), nil
	}

	clientCert, cerr := readCert(rt, certPath+"/"+certFilename+".crt")
	if cerr != nil {
		return fmt.Sprintf("There is no client certificate named %q", a.CN), nil
	}

	info, ierr := getBasicInfo(rt, caDir, clientCert)
	if ierr != nil {
		return nil, ierr
	}

	// upstream builds the V and R index rows and the already-revoked
	// detection pattern verbatim from these fields
	indexSerialSubject := fmt.Sprintf("%s\tunknown\t%s", info.Serial, info.Subject)
	indexVData := fmt.Sprintf("V\t%s\t\t%s", info.Expire, indexSerialSubject)
	index_r_data_pattern := regexp.MustCompile(
		"R\t" + info.Expire + `\t\d{12}Z\t` + regexp.QuoteMeta(indexSerialSubject))
	indexRData := fmt.Sprintf("R\t%s\t%s\t%s",
		info.Expire,
		time.Now().UTC().Format(twoDigitYearFmt),
		indexSerialSubject)

	// scan the index for prior revocations or the live V row; SplitAfter
	// keeps the trailing newline per line the way Python's file
	// iteration does, which upstream's substring match depends on
	alreadyRevoked := false
	indexData, rerr := rt.FS.ReadFile(info.IndexFile)
	if rerr != nil {
		return nil, rerr
	}
	for _, line := range strings.SplitAfter(string(indexData), "\n") {
		if index_r_data_pattern.MatchString(line) {
			revokeDate := strings.Split(line, "\t")[2]
			if _, derr := time.Parse(twoDigitYearFmt, revokeDate); derr == nil {
				return fmt.Sprintf("%q was already revoked, serial number: %s",
					certPath+"/"+certFilename+".crt", info.Serial), nil
			}
			return map[string]any{
				"retcode": 1,
				"comment": fmt.Sprintf("Revocation date '%s' does not matchformat '%s'",
					revokeDate, twoDigitYearFmt),
			}, nil
		}
		if strings.Contains(line, indexSerialSubject) {
			if ferr := fileReplaceLiteral(rt, info.IndexFile, indexVData, indexRData); ferr != nil {
				return nil, ferr
			}
			_ = alreadyRevoked
			break
		}
	}

	// rebuild the CRL from every R row now present in the index
	revocations, perr := parseIndexRevocations(rt, info.IndexFile)
	if perr != nil {
		return nil, perr
	}
	digest := "sha256"
	if a.Digest != nil && *a.Digest != "" {
		digest = *a.Digest
	}
	crlDER, berr := buildCRL(caCert, caKey, digest, revocations)
	if berr != nil {
		return nil, berr
	}

	crlFile := strArg(a.CrlFile, baseJoin(base, a.CaName, "crl.pem"))
	if info, serr := rt.FS.Stat(crlFile); serr == nil && info.IsDir() {
		return map[string]any{
			"retcode": 1,
			"comment": fmt.Sprintf("crl_file %q is an existing directory", crlFile),
		}, nil
	}
	if werr := rt.FS.WriteFile(crlFile, pem.EncodeToMemory(&pem.Block{
		Type: "X509 CRL", Bytes: crlDER,
	}), 0o644); werr != nil {
		return nil, werr
	}

	return fmt.Sprintf("Revoked Certificate: %q, serial number: %s",
		certPath+"/"+certFilename+".crt", info.Serial), nil
}

// ---------------------------------------------------------------------------
// registration

// Register installs the tls family's execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		certBasePathFunc{},
		setCAPathFunc{},
		maybeFixSSLVersionFunc{},
		caExistsFunc{},
		getCaFunc{},
		getCaSignedCertFunc{},
		getCaSignedKeyFunc{},
		validateFunc{},
		getExpirationDateFunc{},
		createCaFunc{},
		getExtensionsFunc{},
		createCsrFunc{},
		createSelfSignedFunc{},
		createCaSignedFunc{},
		createPkcs12Func{},
		certInfoFunc{},
		createEmptyCrlFunc{},
		revokeCertFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
