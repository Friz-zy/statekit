package tls

// Core path/context functions and readers, mirroring
// salt.modules.tls._context_or_config, cert_base_path, set_ca_path,
// maybe_fix_ssl_version, ca_exists, get_ca, get_ca_signed_cert/key,
// get_expiration_date and get_extensions @ pinned revision.

import (
	"context"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

// errTLSUnreadable marks OSError-like failures upstream catches while
// loading CA material (its callers translate it to the no-CA replies).
var errTLSUnreadable = errors.New("tls: CA material unreadable")

// ---------------------------------------------------------------------------
// cert_base_path / set_ca_path

// certBasePathImpl implements the upstream resolution chain:
// cacert_path, then context/config ca.contextual_cert_base_path, then
// ca.cert_base_path — None when nothing is configured.
func certBasePathImpl(rt *runtime.Runtime, cacertPath any) any {
	if pyTruthy(cacertPath) {
		if s, ok := cacertPath.(string); ok {
			return s
		}
		if s, ok := cacertPath.(*string); ok {
			return *s
		}
		return cacertPath
	}
	if v := contextOrConfig(rt, "ca.contextual_cert_base_path"); pyTruthy(v) {
		return v
	}
	return contextOrConfig(rt, "ca.cert_base_path")
}

// setCAPathImpl ports set_ca_path: a truthy path is stored into the
// context slot before the base path resolves again.
func setCAPathImpl(rt *runtime.Runtime, cacertPath *string) error {
	if cacertPath != nil && *cacertPath != "" {
		contextMu.Lock()
		contextState["ca.contextual_cert_base_path"] = *cacertPath
		contextMu.Unlock()
	}
	return nil
}

type certBasePathArgs struct {
	CacertPath *string `statekit:"name=cacert_path"`
}

type certBasePathFunc struct{}

func (certBasePathFunc) Name() string { return "tls.cert_base_path" }
func (certBasePathFunc) Args() any    { return certBasePathArgs{} }
func (certBasePathFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*certBasePathArgs)
	return certBasePathImpl(rt, a.CacertPath), nil
}

type setCAPathArgs struct {
	CacertPath *string `statekit:"name=cacert_path"`
}

type setCAPathFunc struct{}

func (setCAPathFunc) Name() string { return "tls.set_ca_path" }
func (setCAPathFunc) Args() any    { return setCAPathArgs{} }
func (setCAPathFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*setCAPathArgs)
	if err := setCAPathImpl(rt, a.CacertPath); err != nil {
		return nil, err
	}
	return certBasePathImpl(rt, nil), nil
}

// ---------------------------------------------------------------------------
// maybe_fix_ssl_version

type maybeFixSSLVersionArgs struct {
	CaName     string  `statekit:"required,name=ca_name"`
	CacertPath *string `statekit:"name=cacert_path"`
	CaFilename *string `statekit:"name=ca_filename"`
}

type maybeFixSSLVersionFunc struct{}

func (maybeFixSSLVersionFunc) Name() string { return "tls.maybe_fix_ssl_version" }
func (maybeFixSSLVersionFunc) Args() any    { return maybeFixSSLVersionArgs{} }
func (maybeFixSSLVersionFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*maybeFixSSLVersionArgs)
	return maybeFixImpl(rt, a)
}

func maybeFixImpl(rt *runtime.Runtime, a *maybeFixSSLVersionArgs) (res any, err error) {
	defer recoverTLS(&res, &err)
	if err := setCAPathImpl(rt, a.CacertPath); err != nil {
		return nil, err
	}
	caFilename := strArg(a.CaFilename, a.CaName+"_ca_cert")

	certp := baseJoin(certBasePathImpl(rt, nil), a.CaName, caFilename+".crt")
	caKeyp := baseJoin(certBasePathImpl(rt, nil), a.CaName, caFilename+".key")

	certPEM, rerr := rt.FS.ReadFile(certp)
	if rerr != nil {
		return nil, errTLSUnreadable
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errTLSUnreadable
	}
	der := certBlock.Bytes
	version, verr := rawVersion(der)
	if verr != nil {
		// upstream raises through OpenSSL on unloadable material; the
		// create_ca_signed_cert caller treats that as no-CA as well
		return nil, errTLSUnreadable
	}
	if version != 3 {
		return nil, nil
	}

	// the OpenSSL fix path opens the key unconditionally; a missing key
	// surfaces as the OSError the callers translate
	bits := 2048
	keyPEM, kerr := rt.FS.ReadFile(caKeyp)
	if kerr != nil {
		return nil, errTLSUnreadable
	}
	if key, lerr := loadPrivateKeyPEM(keyPEM); lerr == nil {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			bits = k.N.BitLen()
		}
	}

	// remaining days from the raw validity window (fallback 365)
	days := 365
	tbs, terr := peekTBS(der)
	if terr == nil {
		var validity struct {
			NotBefore, NotAfter time.Time
		}
		if _, verr := asn1.Unmarshal(tbs.Validity.FullBytes, &validity); verr == nil {
			diff := validity.NotAfter.Sub(time.Now().UTC())
			if diff >= 0 {
				days = int(diff / (24 * time.Hour))
			} else {
				days = -int(-diff/(24*time.Hour) + 1)
			}
		}
	}

	C, _ := subjectAttribute(tbs.Subject.FullBytes, "C")
	ST, _ := subjectAttribute(tbs.Subject.FullBytes, "ST")
	L, _ := subjectAttribute(tbs.Subject.FullBytes, "L")
	O, _ := subjectAttribute(tbs.Subject.FullBytes, "O")
	OU, _ := subjectAttribute(tbs.Subject.FullBytes, "OU")
	CN, _ := subjectAttribute(tbs.Subject.FullBytes, "CN")
	email, _ := subjectAttribute(tbs.Subject.FullBytes, "emailAddress")

	fixmode := true
	// upstream discards the create_ca reply inside maybe_fix (no
	// return statement); only failures propagate
	_, err = createCAImpl(context.Background(), rt, createCAParams{
		CaName:       a.CaName,
		Bits:         &bits,
		Days:         &days,
		C:            &C,
		ST:           &ST,
		L:            &L,
		O:            &O,
		OU:           &OU,
		EmailAddress: &email,
		CN:           &CN,
		Fixmode:      &fixmode,
		CaFilename:   &caFilename,
	})
	return nil, err
}

// ---------------------------------------------------------------------------
// ca_exists / get_ca / get_ca_signed_cert / get_ca_signed_key

type caExistsArgs struct {
	CaName     string  `statekit:"required,name=ca_name"`
	CacertPath *string `statekit:"name=cacert_path"`
	CaFilename *string `statekit:"name=ca_filename"`
}

type caExistsFunc struct{}

func (caExistsFunc) Name() string { return "tls.ca_exists" }
func (caExistsFunc) Args() any    { return caExistsArgs{} }
func (caExistsFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	return caExistsImpl(rt, args.(*caExistsArgs))
}

func caExistsImpl(rt *runtime.Runtime, a *caExistsArgs) (res any, err error) {
	defer recoverTLS(&res, &err)
	if err := setCAPathImpl(rt, a.CacertPath); err != nil {
		return nil, err
	}
	caFilename := strArg(a.CaFilename, a.CaName+"_ca_cert")
	certp := baseJoin(certBasePathImpl(rt, nil), a.CaName, caFilename+".crt")
	if !pathExists(rt, certp) {
		return false, nil
	}
	fixArgs := &maybeFixSSLVersionArgs{
		CaName:     a.CaName,
		CacertPath: a.CacertPath,
		CaFilename: a.CaFilename,
	}
	if _, fixerr := maybeFixImpl(rt, fixArgs); fixerr != nil {
		return false, fixerr
	}
	return true, nil
}

type getCaArgs struct {
	CaName     string  `statekit:"required,name=ca_name"`
	AsText     bool    `statekit:"name=as_text"`
	CacertPath *string `statekit:"name=cacert_path"`
}

type getCaFunc struct{}

func (getCaFunc) Name() string { return "tls.get_ca" }
func (getCaFunc) Args() any    { return getCaArgs{} }
func (getCaFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*getCaArgs)
	if err := setCAPathImpl(rt, a.CacertPath); err != nil {
		return nil, err
	}
	base := certBasePathImpl(rt, nil)
	certp := baseJoin(base, a.CaName, a.CaName+"_ca_cert.crt")
	if !pathExists(rt, certp) {
		return nil, &invocationErr{msg: fmt.Sprintf("Certificate does not exist for %s", a.CaName)}
	}
	if a.AsText {
		data, rerr := rt.FS.ReadFile(certp)
		if rerr != nil {
			return nil, rerr
		}
		return string(data), nil
	}
	return certp, nil
}

type getCaSignedCertArgs struct {
	CaName       string  `statekit:"required,name=ca_name"`
	CN           *string `statekit:"name=CN"`
	AsText       bool    `statekit:"name=as_text"`
	CacertPath   *string `statekit:"name=cacert_path"`
	CertFilename *string `statekit:"name=cert_filename"`
}

type getCaSignedCertFunc struct{}

func (getCaSignedCertFunc) Name() string { return "tls.get_ca_signed_cert" }
func (getCaSignedCertFunc) Args() any    { return getCaSignedCertArgs{} }
func (getCaSignedCertFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*getCaSignedCertArgs)
	if err := setCAPathImpl(rt, a.CacertPath); err != nil {
		return nil, err
	}
	cn := strArg(a.CN, "localhost")
	certFilename := strArg(a.CertFilename, cn)
	certp := baseJoin(certBasePathImpl(rt, nil), a.CaName, "certs", certFilename+".crt")
	if !pathExists(rt, certp) {
		return nil, &invocationErr{msg: fmt.Sprintf("Certificate does not exists for %s", cn)}
	}
	if a.AsText {
		data, rerr := rt.FS.ReadFile(certp)
		if rerr != nil {
			return nil, rerr
		}
		return string(data), nil
	}
	return certp, nil
}

type getCaSignedKeyArgs struct {
	CaName      string  `statekit:"required,name=ca_name"`
	CN          *string `statekit:"name=CN"`
	AsText      bool    `statekit:"name=as_text"`
	CacertPath  *string `statekit:"name=cacert_path"`
	KeyFilename *string `statekit:"name=key_filename"`
}

type getCaSignedKeyFunc struct{}

func (getCaSignedKeyFunc) Name() string { return "tls.get_ca_signed_key" }
func (getCaSignedKeyFunc) Args() any    { return getCaSignedKeyArgs{} }
func (getCaSignedKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*getCaSignedKeyArgs)
	if err := setCAPathImpl(rt, a.CacertPath); err != nil {
		return nil, err
	}
	cn := strArg(a.CN, "localhost")
	keyFilename := strArg(a.KeyFilename, cn)
	keyp := baseJoin(certBasePathImpl(rt, nil), a.CaName, "certs", keyFilename+".key")
	if !pathExists(rt, keyp) {
		return nil, &invocationErr{msg: fmt.Sprintf("Certificate does not exists for %s", cn)}
	}
	if a.AsText {
		data, rerr := rt.FS.ReadFile(keyp)
		if rerr != nil {
			return nil, rerr
		}
		return string(data), nil
	}
	return keyp, nil
}

// ---------------------------------------------------------------------------
// get_expiration_date

type getExpirationDateArgs struct {
	Cert       string  `statekit:"required,name=cert"`
	DateFormat *string `statekit:"name=date_format"`
}

type getExpirationDateFunc struct{}

func (getExpirationDateFunc) Name() string { return "tls.get_expiration_date" }
func (getExpirationDateFunc) Args() any    { return getExpirationDateArgs{} }
func (getExpirationDateFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*getExpirationDateArgs)
	format := "%Y-%m-%d"
	if a.DateFormat != nil {
		format = *a.DateFormat
	}
	cert, cerr := readCert(rt, a.Cert)
	if cerr != nil {
		return nil, &invocationErr{
			msg: fmt.Sprintf("Failed to read cert from %s, see log for details", a.Cert),
		}
	}
	return cert.NotAfter.UTC().Format(strftimeToGoT(format)), nil
}

// ---------------------------------------------------------------------------
// get_extensions

type getExtensionsArgs struct {
	CertType string `statekit:"required,name=cert_type"`
}

type getExtensionsFunc struct{}

func (getExtensionsFunc) Name() string { return "tls.get_extensions" }
func (getExtensionsFunc) Args() any    { return getExtensionsArgs{} }
func (getExtensionsFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverTLS(&res, &err)
	a := args.(*getExtensionsArgs)
	out, gerr := getExtensionsImpl(rt, a.CertType)
	if gerr != nil {
		return nil, gerr
	}
	return out, nil
}

// extProfile is one tls:extensions pillar entry: {csr: {...}, cert: {...}}.
func extProfile(rt *runtime.Runtime, key string) (map[string]map[string]string, bool, error) {
	res, err := callDelegateT(rt, "pillar.get",
		map[string]any{"key": key, "default": false})
	if err != nil || !pyTruthy(res) {
		return nil, false, nil
	}
	raw, ok := res.(map[string]any)
	if !ok {
		return nil, false, fmt.Errorf("%s must be a mapping", key)
	}
	profile := map[string]map[string]string{}
	for side, value := range raw {
		fields, ok := value.(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("%s.%s must be a mapping", key, side)
		}
		profile[side] = map[string]string{}
		for name, text := range fields {
			profile[side][name] = pyStr(text)
		}
	}
	return profile, true, nil
}

func defaultExtProfile(csr, cert map[string]string) map[string]map[string]string {
	return map[string]map[string]string{"csr": csr, "cert": cert}
}

var (
	defaultCommonProfile = defaultExtProfile(
		map[string]string{"basicConstraints": "CA:FALSE"},
		map[string]string{
			"authorityKeyIdentifier": "keyid,issuer:always",
			"subjectKeyIdentifier":   "hash",
		},
	)
	defaultServerProfile = defaultExtProfile(
		map[string]string{
			"extendedKeyUsage": "serverAuth",
			"keyUsage":         "digitalSignature, keyEncipherment",
		},
		map[string]string{},
	)
	defaultClientProfile = defaultExtProfile(
		map[string]string{
			"extendedKeyUsage": "clientAuth",
			"keyUsage":         "nonRepudiation, digitalSignature, keyEncipherment",
		},
		map[string]string{},
	)
)

// getExtensionsImpl ports get_extensions: defaults merged with the
// requested profile; pillar entries override; unknown profiles error.
func getExtensionsImpl(rt *runtime.Runtime, certType string) (map[string]map[string]string, error) {
	if certType == "" {
		certType = "server"
	}

	profiles := map[string]map[string]map[string]string{
		"common": defaultCommonProfile,
	}
	customCommon, has, err := extProfile(rt, "tls.extensions:common")
	if err != nil {
		return nil, err
	}
	if has && pyTruthy(customCommon) {
		profiles["common"] = customCommon
	}
	server, has, err := extProfile(rt, "tls.extensions:server")
	if err != nil {
		return nil, err
	}
	if has && pyTruthy(server) {
		profiles["server"] = server
	} else {
		profiles["server"] = defaultServerProfile
	}
	client, has, err := extProfile(rt, "tls.extensions:client")
	if err != nil {
		return nil, err
	}
	if has && pyTruthy(client) {
		profiles["client"] = client
	} else {
		profiles["client"] = defaultClientProfile
	}

	typed, ok := profiles[certType]
	if !ok {
		custom, has, err := extProfile(rt, "tls.extensions:"+certType)
		if err != nil {
			return nil, err
		}
		if !has {
			// upstream raises KeyError when the profile is neither a
			// builtin nor provided by pillar
			return nil, &invocationErr{msg: fmt.Sprintf("KeyError: '%s'", certType)}
		}
		profiles[certType] = custom
		typed = custom
	}

	retval := map[string]map[string]string{}
	for side, fields := range profiles["common"] {
		retval[side] = map[string]string{}
		for name, value := range fields {
			retval[side][name] = value
		}
	}
	for side, fields := range typed {
		if retval[side] == nil {
			retval[side] = map[string]string{}
		}
		for name, value := range fields {
			retval[side][name] = value
		}
	}
	return retval, nil
}
