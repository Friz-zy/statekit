package ssh_pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"path/filepath"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
	"golang.org/x/crypto/ssh"
)

const remoteBoundary = "peer communication is part of the master-minion architecture and is excluded from StateKit's local-only runtime"

func certBytes(cert *ssh.Certificate) []byte {
	return bytes.TrimSuffix(ssh.MarshalAuthorizedKey(cert), []byte("\n"))
}

func certBytesForSigning(cert *ssh.Certificate) ([]byte, error) {
	copyCert := *cert
	copyCert.Signature = nil
	out := copyCert.Marshal()
	if len(out) < 4 {
		return nil, fmt.Errorf("invalid SSH certificate signing payload")
	}
	return out[:len(out)-4], nil
}

func verifyCertificateSignature(cert *ssh.Certificate) error {
	if cert == nil || cert.SignatureKey == nil || cert.Signature == nil {
		return fmt.Errorf("The signature on the SSH certificate was invalid")
	}
	payload, err := certBytesForSigning(cert)
	if err != nil {
		return err
	}
	if err := cert.SignatureKey.Verify(payload, cert.Signature); err != nil {
		return fmt.Errorf("The signature on the SSH certificate was invalid")
	}
	return nil
}

// ---------------------------------------------------------------------------
// create_certificate

type createCertificateArgs struct {
	CaServer                    *string        `statekit:"name=ca_server"`
	SigningPolicy               *string        `statekit:"name=signing_policy"`
	Path                        *string        `statekit:"name=path"`
	Overwrite                   bool           `statekit:"name=overwrite"`
	Raw                         bool           `statekit:"name=raw"`
	Kwargs                      map[string]any `statekit:"name=kwargs"`
	PrivateKey                  *string        `statekit:"name=private_key"`
	PrivateKeyPassphrase        *string        `statekit:"name=private_key_passphrase"`
	PublicKey                   *string        `statekit:"name=public_key"`
	SigningPrivateKey           *string        `statekit:"name=signing_private_key"`
	SigningPrivateKeyPassphrase *string        `statekit:"name=signing_private_key_passphrase"`
	CertType                    *string        `statekit:"name=cert_type"`
	SerialNumber                *string        `statekit:"name=serial_number"`
	KeyID                       *string        `statekit:"name=key_id"`
	NotBefore                   *string        `statekit:"name=not_before"`
	NotAfter                    *string        `statekit:"name=not_after"`
	TTL                         *string        `statekit:"name=ttl"`
	CriticalOptions             map[string]any `statekit:"name=critical_options"`
	Extensions                  map[string]any `statekit:"name=extensions"`
	ValidPrincipals             []string       `statekit:"name=valid_principals"`
	AllPrincipals               bool           `statekit:"name=all_principals"`
	CopyPath                    *string        `statekit:"name=copypath"`
}

type createCertificateFunc struct{}

type createCertificateAliasFunc struct{}

func (createCertificateFunc) Name() string { return "ssh_pki.create_certificate" }
func (createCertificateFunc) Args() any    { return createCertificateArgs{} }
func (createCertificateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*createCertificateArgs)
	return createCertificateImpl(ctx, rt, a)
}

func (createCertificateAliasFunc) Name() string { return "ssh_pki.create_certificate_ssh" }
func (createCertificateAliasFunc) Args() any    { return createCertificateArgs{} }
func (createCertificateAliasFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	return createCertificateImpl(ctx, rt, args.(*createCertificateArgs))
}

func createCertificateImpl(_ context.Context, rt *runtime.Runtime, a *createCertificateArgs) (any, error) {
	kwargs := cloneMap(a.Kwargs)
	if kwargs == nil {
		kwargs = map[string]any{}
	}
	putString := func(key string, value *string) {
		if value != nil {
			kwargs[key] = *value
		}
	}
	putString("private_key", a.PrivateKey)
	putString("private_key_passphrase", a.PrivateKeyPassphrase)
	putString("public_key", a.PublicKey)
	putString("signing_private_key", a.SigningPrivateKey)
	putString("signing_private_key_passphrase", a.SigningPrivateKeyPassphrase)
	putString("cert_type", a.CertType)
	putString("serial_number", a.SerialNumber)
	putString("key_id", a.KeyID)
	putString("not_before", a.NotBefore)
	putString("not_after", a.NotAfter)
	putString("ttl", a.TTL)
	putString("copypath", a.CopyPath)
	if a.CriticalOptions != nil {
		kwargs["critical_options"] = cloneAny(a.CriticalOptions)
	}
	if a.Extensions != nil {
		kwargs["extensions"] = cloneAny(a.Extensions)
	}
	if a.ValidPrincipals != nil {
		kwargs["valid_principals"] = append([]string(nil), a.ValidPrincipals...)
	}
	if a.AllPrincipals {
		kwargs["all_principals"] = true
	}

	caServer := a.CaServer != nil && *a.CaServer != ""
	if !valueTruthy(kwargs["signing_private_key"]) && !caServer {
		return nil, &invocationErr{msg: "Creating a certificate locally at least requires a signing private key."}
	}
	if a.Path != nil && *a.Path != "" && !a.Overwrite && fileExists(rt, *a.Path) {
		return nil, &invocationErr{msg: fmt.Sprintf(
			"The file at %s exists and overwrite was set to false", *a.Path)}
	}
	if caServer {
		if a.SigningPolicy == nil || *a.SigningPolicy == "" {
			return nil, &invocationErr{msg: "signing_policy must be specified to request a certificate from a remote ca_server"}
		}
		return nil, fmt.Errorf("ca_server %q is unsupported: %s", *a.CaServer, remoteBoundary)
	}

	policyName := ""
	if a.SigningPolicy != nil {
		policyName = *a.SigningPolicy
	}
	kwargs = mergeSigningPolicy(getSigningPolicy(rt, policyName), kwargs)
	cert, _, err := buildCertificate(rt, kwargs)
	if err != nil {
		return nil, err
	}
	out := certBytes(cert)
	if copyPath := optionalString(kwargs, "copypath"); copyPath != "" {
		copyName := filepath.Join(copyPath, fmt.Sprintf("%x.crt", cert.Serial))
		if err := rt.FS.WriteFile(copyName, out, 0o644); err != nil {
			return nil, err
		}
	}
	if a.Path == nil || *a.Path == "" {
		if a.Raw {
			return out, nil
		}
		return string(out), nil
	}
	if err := rt.FS.WriteFile(*a.Path, out, 0o644); err != nil {
		return nil, err
	}
	return fmt.Sprintf("Certificate written to %s", *a.Path), nil
}

// ---------------------------------------------------------------------------
// create_private_key

type createPrivateKeyArgs struct {
	Algo         string  `statekit:"name=algo"`
	Keysize      *int    `statekit:"name=keysize"`
	Passphrase   *string `statekit:"name=passphrase"`
	Path         *string `statekit:"name=path"`
	PubkeySuffix *string `statekit:"name=pubkey_suffix"`
	Overwrite    bool    `statekit:"name=overwrite"`
	Raw          bool    `statekit:"name=raw"`
}

type createPrivateKeyFunc struct{}

func (createPrivateKeyFunc) Name() string { return "ssh_pki.create_private_key" }
func (createPrivateKeyFunc) Args() any    { return createPrivateKeyArgs{} }
func (createPrivateKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*createPrivateKeyArgs)
	algo := a.Algo
	if algo == "" {
		algo = "rsa"
	}
	if a.Path != nil && *a.Path != "" && !a.Overwrite && fileExists(rt, *a.Path) {
		return nil, &invocationErr{msg: fmt.Sprintf(
			"The file at %s exists and overwrite was set to false", *a.Path)}
	}
	keysize := 0
	if a.Keysize != nil {
		keysize = *a.Keysize
	} else if algo == "rsa" {
		keysize = 3072
	} else if algo == "ec" {
		keysize = 256
	}
	key, gerr := generatePrivateKey(algo, keysize)
	if gerr != nil {
		return nil, gerr
	}
	privateBytes, merr := marshalPrivateKey(key, a.Passphrase)
	if merr != nil {
		return nil, merr
	}
	signer, serr := signerFromPrivate(key)
	if serr != nil {
		return nil, serr
	}
	public := encodePublicKey(signer.PublicKey())

	if a.Path == nil || *a.Path == "" {
		if a.Raw {
			return privateBytes, nil
		}
		return map[string]any{"private_key": string(privateBytes), "public_key": public}, nil
	}
	if err := rt.FS.WriteFile(*a.Path, privateBytes, 0o600); err != nil {
		return nil, err
	}
	suffix := ".pub"
	if a.PubkeySuffix != nil {
		suffix = *a.PubkeySuffix
	}
	if suffix != "" {
		if err := rt.FS.WriteFile(*a.Path+suffix, []byte(public), 0o644); err != nil {
			return nil, err
		}
	}
	return fmt.Sprintf("Private key written to %s", *a.Path), nil
}

func signerFromPrivate(key any) (ssh.Signer, error) {
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, &invocationErr{msg: "Could not load OpenSSH private key"}
	}
	return signer, nil
}

// ---------------------------------------------------------------------------
// encode_private_key

type encodePrivateKeyArgs struct {
	PrivateKey           string  `statekit:"required,name=private_key"`
	PrivateKeyPassphrase *string `statekit:"name=private_key_passphrase"`
	Passphrase           *string `statekit:"name=passphrase"`
	Raw                  bool    `statekit:"name=raw"`
}

type encodePrivateKeyFunc struct{}

func (encodePrivateKeyFunc) Name() string { return "ssh_pki.encode_private_key" }
func (encodePrivateKeyFunc) Args() any    { return encodePrivateKeyArgs{} }
func (encodePrivateKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*encodePrivateKeyArgs)
	key, err := loadRawPrivateKey(rt, a.PrivateKey, a.PrivateKeyPassphrase)
	if err != nil {
		return nil, err
	}
	out, err := marshalPrivateKey(key, a.Passphrase)
	if err != nil {
		return nil, err
	}
	if a.Raw {
		return out, nil
	}
	return string(out), nil
}

// ---------------------------------------------------------------------------
// expires

type expiresArgs struct {
	Certificate string `statekit:"required,name=certificate"`
	TTL         string `statekit:"name=ttl"`
}

type expiresFunc struct{}

func (expiresFunc) Name() string { return "ssh_pki.expires" }
func (expiresFunc) Args() any    { return expiresArgs{} }
func (expiresFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*expiresArgs)
	cert, err := loadCertificate(rt, a.Certificate, true)
	if err != nil {
		return nil, err
	}
	extra := 0.0
	if a.TTL != "" {
		seconds, perr := timeStringMap(a.TTL)
		if perr != nil {
			return nil, perr
		}
		if seconds != nil {
			extra = *seconds
		}
	}
	if cert.ValidBefore == ssh.CertTimeInfinity {
		return false, nil
	}
	return int64(cert.ValidBefore) <= time.Now().UTC().Unix()+int64(extra), nil
}

// ---------------------------------------------------------------------------
// get_private_key_size

type getPrivateKeySizeArgs struct {
	PrivateKey string  `statekit:"required,name=private_key"`
	Passphrase *string `statekit:"name=passphrase"`
}

type getPrivateKeySizeFunc struct{}

func (getPrivateKeySizeFunc) Name() string { return "ssh_pki.get_private_key_size" }
func (getPrivateKeySizeFunc) Args() any    { return getPrivateKeySizeArgs{} }
func (getPrivateKeySizeFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*getPrivateKeySizeArgs)
	key, err := loadRawPrivateKey(rt, a.PrivateKey, a.Passphrase)
	if err != nil {
		return nil, err
	}
	switch k := key.(type) {
	case interface{ Public() crypto.PublicKey }:
		return keySizeFromCrypto(k.Public()), nil
	default:
		return nil, nil
	}
}

func keySizeFromCrypto(key any) any {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		if k.Curve != nil && k.Curve.Params() != nil {
			return k.Curve.Params().BitSize
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// get_public_key

type getPublicKeyArgs struct {
	Key        string  `statekit:"required,name=key"`
	Passphrase *string `statekit:"name=passphrase"`
}

type getPublicKeyFunc struct{}

func (getPublicKeyFunc) Name() string { return "ssh_pki.get_public_key" }
func (getPublicKeyFunc) Args() any    { return getPublicKeyArgs{} }
func (getPublicKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*getPublicKeyArgs)
	return getPublicKeyString(rt, a.Key, a.Passphrase)
}

func getPublicKeyString(rt *runtime.Runtime, value any, passphrase *string) (string, error) {
	if key, err := loadPublicKey(rt, value); err == nil {
		if _, isCert := key.(*ssh.Certificate); !isCert {
			return encodePublicKey(key), nil
		}
	}
	if cert, err := loadCertificate(rt, value, false); err == nil {
		return encodePublicKey(cert.Key), nil
	}
	if key, err := loadSigner(rt, value, passphrase); err == nil {
		return encodePublicKey(key.PublicKey()), nil
	}
	return "", &invocationErr{msg: "Could not load key as certificate, public key or private key"}
}

func loadCertificate(rt *runtime.Runtime, value any, verify bool) (*ssh.Certificate, error) {
	if cert, ok := value.(*ssh.Certificate); ok {
		if verify {
			return cert, verifyCertificateSignature(cert)
		}
		return cert, nil
	}
	key, err := loadPublicKey(rt, value)
	if err != nil {
		return nil, &invocationErr{msg: "Could not load OpenSSH certificate."}
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, &invocationErr{msg: fmt.Sprintf(
			"The data decoded to a %T, not SSHCertificate", key)}
	}
	if verify {
		if err := verifyCertificateSignature(cert); err != nil {
			return nil, err
		}
	}
	return cert, nil
}

// ---------------------------------------------------------------------------
// get_signing_policy

type getSigningPolicyArgs struct {
	SigningPolicy string  `statekit:"required,name=signing_policy"`
	CaServer      *string `statekit:"name=ca_server"`
}

type getSigningPolicyFunc struct{}

func (getSigningPolicyFunc) Name() string { return "ssh_pki.get_signing_policy" }
func (getSigningPolicyFunc) Args() any    { return getSigningPolicyArgs{} }
func (getSigningPolicyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*getSigningPolicyArgs)
	if a.CaServer != nil && *a.CaServer != "" {
		return nil, fmt.Errorf("ca_server %q is unsupported: %s", *a.CaServer, remoteBoundary)
	}
	return getSigningPolicy(rt, a.SigningPolicy), nil
}

// ---------------------------------------------------------------------------
// read_certificate

type readCertificateArgs struct {
	Certificate string `statekit:"required,name=certificate"`
}

type readCertificateFunc struct{}

func (readCertificateFunc) Name() string { return "ssh_pki.read_certificate" }
func (readCertificateFunc) Args() any    { return readCertificateArgs{} }
func (readCertificateFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*readCertificateArgs)
	cert, err := loadCertificate(rt, a.Certificate, true)
	if err != nil {
		return nil, err
	}
	pub := cert.Key
	issuer := cert.SignatureKey
	certType := any(nil)
	if cert.CertType == ssh.UserCert {
		certType = "user"
	} else if cert.CertType == ssh.HostCert {
		certType = "host"
	}
	principals := any("all")
	if len(cert.ValidPrincipals) > 0 {
		principals = append([]string(nil), cert.ValidPrincipals...)
	}
	result := map[string]any{
		"cert_type":         certType,
		"valid_principals":  principals,
		"key_id":            cert.KeyId,
		"key_size":          keySize(pub),
		"key_type":          keyType(pub),
		"serial_number":     serialHex(cert.Serial),
		"issuer_public_key": encodePublicKey(issuer),
		"not_before":        unixSSHTime(cert.ValidAfter),
		"not_after":         unixSSHTime(cert.ValidBefore),
		"public_key":        encodePublicKey(pub),
		"critical_options":  parsedOptions(cert.Permissions.CriticalOptions),
		"extensions":        parsedOptions(cert.Permissions.Extensions),
	}
	result["issuer_public_key_fingerprints"] = fingerprintMap(issuer, fipsMode(rt))
	result["public_key_fingerprints"] = fingerprintMap(pub, fipsMode(rt))
	return result, nil
}

func unixSSHTime(value uint64) string {
	if value == ssh.CertTimeInfinity {
		return "9999-12-31 23:59:59"
	}
	return time.Unix(int64(value), 0).UTC().Format(sshTimeFormat)
}

func parsedOptions(values map[string]string) map[string]any {
	out := map[string]any{}
	for key, value := range values {
		if value == "" {
			out[key] = true
		} else {
			out[key] = value
		}
	}
	return out
}

func fingerprintMap(key ssh.PublicKey, fips bool) map[string]string {
	out := map[string]string{"sha256": sha256Fingerprint(key)}
	if !fips {
		out["md5"] = md5Fingerprint(key)
	}
	return out
}

// ---------------------------------------------------------------------------
// sign_remote_certificate

type signRemoteCertificateArgs struct {
	SigningPolicy        string         `statekit:"required,name=signing_policy"`
	Kwargs               map[string]any `statekit:"required,name=kwargs"`
	GetSigningPolicyOnly bool           `statekit:"name=get_signing_policy_only"`
}

type signRemoteCertificateFunc struct{}

func (signRemoteCertificateFunc) Name() string { return "ssh_pki.sign_remote_certificate" }
func (signRemoteCertificateFunc) Args() any    { return signRemoteCertificateArgs{} }
func (signRemoteCertificateFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*signRemoteCertificateArgs)
	ret := map[string]any{"data": nil, "errors": []string{}}
	policy := getSigningPolicy(rt, a.SigningPolicy)
	if len(policy) == 0 {
		ret["errors"] = []string{"signing_policy must be specified and defined on signing minion"}
		return ret, nil
	}
	if _, restricted := policy["minions"]; restricted {
		ret["errors"] = []string{"minion sending this request could not be identified"}
		return ret, nil
	}
	if a.GetSigningPolicyOnly {
		policyOnly := cloneMap(policy)
		privateKey := policyOnly["signing_private_key"]
		passphrase := stringPointer(policyOnly["signing_private_key_passphrase"])
		delete(policyOnly, "signing_private_key")
		delete(policyOnly, "signing_private_key_passphrase")
		if privateKey != nil {
			key, kerr := loadSigner(rt, privateKey, passphrase)
			if kerr != nil {
				ret["errors"] = []string{kerr.Error()}
				return ret, nil
			}
			policyOnly["signing_public_key"] = encodePublicKey(key.PublicKey())
		}
		ret["data"] = policyOnly
		return ret, nil
	}
	kwargs := cloneMap(a.Kwargs)
	if kwargs == nil {
		kwargs = map[string]any{}
	}
	kwargs = mergeSigningPolicy(policy, kwargs)
	delete(kwargs, "ca_server")
	cert, _, berr := buildCertificate(rt, kwargs)
	if berr != nil {
		ret["errors"] = []string{berr.Error()}
		return ret, nil
	}
	ret["data"] = certBytes(cert)
	return ret, nil
}

// ---------------------------------------------------------------------------
// verify_private_key / verify_signature

type verifyPrivateKeyArgs struct {
	PrivateKey string  `statekit:"required,name=private_key"`
	PublicKey  string  `statekit:"required,name=public_key"`
	Passphrase *string `statekit:"name=passphrase"`
}

type verifyPrivateKeyFunc struct{}

func (verifyPrivateKeyFunc) Name() string { return "ssh_pki.verify_private_key" }
func (verifyPrivateKeyFunc) Args() any    { return verifyPrivateKeyArgs{} }
func (verifyPrivateKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*verifyPrivateKeyArgs)
	privateSigner, err := loadSigner(rt, a.PrivateKey, a.Passphrase)
	if err != nil {
		return nil, err
	}
	publicLine, err := getPublicKeyString(rt, a.PublicKey, nil)
	if err != nil {
		return nil, err
	}
	public, err := loadPublicKey(rt, publicLine)
	if err != nil {
		return nil, err
	}
	return publicKeysEqual(public, privateSigner.PublicKey()), nil
}

type verifySignatureArgs struct {
	Certificate             string  `statekit:"required,name=certificate"`
	SigningPubKey           string  `statekit:"required,name=signing_pub_key"`
	SigningPubKeyPassphrase *string `statekit:"name=signing_pub_key_passphrase"`
}

type verifySignatureFunc struct{}

func (verifySignatureFunc) Name() string { return "ssh_pki.verify_signature" }
func (verifySignatureFunc) Args() any    { return verifySignatureArgs{} }
func (verifySignatureFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*verifySignatureArgs)
	cert, err := loadCertificate(rt, a.Certificate, false)
	if err != nil {
		return nil, err
	}
	pubLine, err := getPublicKeyString(rt, a.SigningPubKey, a.SigningPubKeyPassphrase)
	if err != nil {
		return nil, err
	}
	pub, err := loadPublicKey(rt, pubLine)
	if err != nil {
		return nil, err
	}
	if err := verifyCertificateSignature(cert); err != nil {
		return false, nil
	}
	return publicKeysEqual(cert.SignatureKey, pub), nil
}

// ---------------------------------------------------------------------------
// Register

// Register installs the ssh_pki execution surface. Remote peer operations
// are exposed as explicit errors from the functions rather than silently
// pretending that a local runtime can publish to a Salt master.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		createCertificateFunc{},
		createCertificateAliasFunc{},
		createPrivateKeyFunc{},
		encodePrivateKeyFunc{},
		expiresFunc{},
		getPrivateKeySizeFunc{},
		getPublicKeyFunc{},
		getSigningPolicyFunc{},
		readCertificateFunc{},
		signRemoteCertificateFunc{},
		verifyPrivateKeyFunc{},
		verifySignatureFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
