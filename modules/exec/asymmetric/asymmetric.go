// Package asymmetric implements Salt's low-level asymmetric cryptography
// surface (R5.4): saltstack/salt/modules/asymmetric.py @ pinned revision,
// backed by the Go standard library instead of python-cryptography
// (crypto/rsa, crypto/ecdsa, crypto/ed25519, encoding/pem, crypto/x509).
// No new module dependencies are introduced (go.mod stays frozen).
//
// Key/signature references follow upstream: PEM text or paths for keys;
// base64 strings, base64/raw files or cp.cache_file URLs for signatures.
//
// Documented boundaries:
//   - Ed448 and OpenSSH-container private keys surface unsupported-
//     algorithm errors (stdlib has no ed448);
//   - encrypted PKCS#8 is not decryptable without a KDF stack — only legacy
//     OpenSSL DEK-Info PEM encryption is supported with a passphrase;
//   - hex-encoded key material outside PEM/base64 is rejected explicitly.
package asymmetric

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

const defaultDigest = "sha256"

func recoverASYM(res *any, errPtr *error) {
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

func unsupported(name string) error {
	return &runtime.UnsupportedError{Kind: "algorithm", Name: name}
}

func strDerefA(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ---------------------------------------------------------------------------
// key loading

type privateKey struct {
	key any // *rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
	alg string
}

func loadPrivateKey(rt *runtime.Runtime, ref, passphrase *string) (*privateKey, error) {
	data, err := resolveRef(rt, ref)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("Could not decode private key PEM")
	}
	switch block.Type {
	case "PRIVATE KEY":
		key, derr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if derr != nil {
			return nil, fmt.Errorf("Could not parse private key: %s", derr.Error())
		}
		return wrapPrivate(key)
	case "RSA PRIVATE KEY":
		raw := block.Bytes
		if isEncryptedPEM(block) {
			clear, derr := decryptPEM(block, passphrase)
			if derr != nil {
				return nil, derr
			}
			raw = clear
		}
		key, perr := x509.ParsePKCS1PrivateKey(raw)
		if perr != nil {
			return nil, fmt.Errorf("Could not parse private key: %s", perr.Error())
		}
		return wrapPrivate(key)
	case "EC PRIVATE KEY":
		raw := block.Bytes
		if isEncryptedPEM(block) {
			clear, derr := decryptPEM(block, passphrase)
			if derr != nil {
				return nil, derr
			}
			raw = clear
		}
		key, perr := x509.ParseECPrivateKey(raw)
		if perr != nil {
			return nil, fmt.Errorf("Could not parse private key: %s", perr.Error())
		}
		return wrapPrivate(key)
	case "OPENSSH PRIVATE KEY":
		return nil, unsupported("OpenSSH private key container")
	default:
		return nil, fmt.Errorf("Unknown private key PEM type '%s'", block.Type)
	}
}

func isEncryptedPEM(block *pem.Block) bool {
	_, has := block.Headers["DEK-Info"]
	return has
}

func decryptPEM(block *pem.Block, passphrase *string) ([]byte, error) {
	if passphrase == nil || *passphrase == "" {
		return nil, fmt.Errorf("Private key is encrypted, but no passphrase provided")
	}
	clear, derr := x509.DecryptPEMBlock(block, []byte(*passphrase))
	if derr != nil {
		return nil, fmt.Errorf("Could not decrypt private key: %s", derr.Error())
	}
	return clear, nil
}

func wrapPrivate(key any) (*privateKey, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &privateKey{key: k, alg: "RSA"}, nil
	case *ecdsa.PrivateKey:
		return &privateKey{key: k, alg: "EC"}, nil
	case ed25519.PrivateKey:
		return &privateKey{key: k, alg: "ED25519"}, nil
	default:
		return nil, unsupported(fmt.Sprintf("%T", key))
	}
}

func loadPublicKey(rt *runtime.Runtime, ref *string) (any, error) {
	data, err := resolveRef(rt, ref)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(data); block != nil {
		switch block.Type {
		case "PUBLIC KEY":
			return x509.ParsePKIXPublicKey(block.Bytes)
		case "RSA PUBLIC KEY":
			return x509.ParsePKCS1PublicKey(block.Bytes)
		default:
			return nil, fmt.Errorf("Unknown public key PEM type '%s'", block.Type)
		}
	}
	der, berr := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(data)), ""))
	if berr == nil {
		if key, perr := x509.ParsePKIXPublicKey(der); perr == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("Could not parse public key")
}

// resolveRef reads a key reference: inline PEM material or a filesystem
// path (file:// included). Remote schemes are out of scope for keys.
func resolveRef(rt *runtime.Runtime, ref *string) ([]byte, error) {
	if ref == nil || *ref == "" {
		return nil, &invocationErr{msg: "Missing key reference"}
	}
	val := *ref
	if !strings.HasPrefix(val, "/") && !strings.HasPrefix(val, "file://") &&
		!strings.Contains(val, "-----BEGIN") {
		return []byte(val), nil
	}
	path := strings.TrimPrefix(val, "file://")
	data, rerr := rt.FS.ReadFile(path)
	if rerr != nil {
		return nil, fmt.Errorf("Could not read key from '%s'", val)
	}
	return data, nil
}

// ---------------------------------------------------------------------------
// primitives

func digestHash(name string) (crypto.Hash, error) {
	switch strings.ToLower(name) {
	case "sha224":
		return crypto.SHA224, nil
	case "", defaultDigest:
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("Unsupported digest algorithm '%s'", name)
}

func sumOf(data []byte, h crypto.Hash) []byte {
	hw := h.New()
	hw.Write(data)
	return hw.Sum(nil)
}

func signPrimitive(key *privateKey, data []byte, digest string, prehashed bool) ([]byte, error) {
	digest = orDefault(digest)
	switch key.alg {
	case "RSA":
		rsaKey := key.key.(*rsa.PrivateKey)
		h, herr := digestHash(digest)
		if herr != nil {
			return nil, herr
		}
		payload := data
		if !prehashed {
			payload = sumOf(data, h)
		}
		return rsa.SignPKCS1v15(rand.Reader, rsaKey, h, payload)
	case "EC":
		ecKey := key.key.(*ecdsa.PrivateKey)
		payload := data
		if !prehashed {
			h, herr := digestHash(digest)
			if herr != nil {
				return nil, herr
			}
			payload = sumOf(data, h)
		}
		return ecdsa.SignASN1(rand.Reader, ecKey, payload)
	case "ED25519":
		priv := key.key.(ed25519.PrivateKey)
		return ed25519.Sign(priv, data), nil
	}
	return nil, unsupported(key.alg)
}

func verifyPrimitive(pub any, signature, data []byte, digest string, prehashed bool) bool {
	digest = orDefault(digest)
	switch key := pub.(type) {
	case *rsa.PublicKey:
		h, herr := digestHash(digest)
		if herr != nil {
			return false
		}
		payload := data
		if !prehashed {
			payload = sumOf(data, h)
		}
		return rsa.VerifyPKCS1v15(key, h, payload, signature) == nil
	case *ecdsa.PublicKey:
		payload := data
		if !prehashed {
			h, herr := digestHash(digest)
			if herr != nil {
				return false
			}
			payload = sumOf(data, h)
		}
		return ecdsa.VerifyASN1(key, payload, signature)
	case ed25519.PublicKey:
		return ed25519.Verify(key, data, signature)
	default:
		return false
	}
}

func publicKeyFingerprint(pub any) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return fmt.Sprintf("%x", sum)
}

func orDefault(digest string) string {
	if digest == "" {
		return defaultDigest
	}
	return digest
}

type sigFetch struct {
	raw    []byte
	source string
}

// fetchSig ports _fetch for signatures: bare base64 strings pass through,
// local paths/file:// are read from the FS, remote schemes go through the
// cp.cache_file delegate.
func fetchSig(rt *runtime.Runtime, ref any) (*sigFetch, error) {
	var text string
	var isPathLike bool
	switch t := ref.(type) {
	case string:
		text = t
	default:
		text = fmt.Sprintf("%v", t)
	}
	scheme := ""
	path := text
	if idx := strings.Index(text, "://"); idx > 0 {
		scheme = text[:idx]
		path = text[idx+3:]
		isPathLike = true
	} else if strings.HasPrefix(text, "/") {
		isPathLike = true
	}
	if !isPathLike {
		if raw, derr := base64.StdEncoding.DecodeString(text); derr == nil {
			return &sigFetch{raw: raw, source: "inline"}, nil
		}
		return nil, fmt.Errorf("Failed loading signature as file and/or base64 string")
	}
	candidate := path
	if scheme != "" && scheme != "file" {
		res, err := callDelegateASYM(rt, "cp.cache_file",
			map[string]any{"path": text})
		if err != nil || res == nil || res.(string) == "" {
			return nil, fmt.Errorf("Failed fetching '%s'", text)
		}
		candidate = res.(string)
	}
	data, rerr := rt.FS.ReadFile(candidate)
	if rerr != nil {
		return nil, fmt.Errorf("Failed fetching '%s'", text)
	}
	// File content may be raw bytes or a base64 encoding of them.
	if raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); derr == nil {
		return &sigFetch{raw: raw, source: candidate}, nil
	}
	return &sigFetch{raw: data, source: candidate}, nil
}

func callDelegateASYM(rt *runtime.Runtime, name string, args any) (any, error) {
	if _, ok := rt.Exec.Get(name); !ok {
		return nil, fmt.Errorf("%s is not available", name)
	}
	return rt.Exec.Call(context.Background(), rt, name, args)
}

// ---------------------------------------------------------------------------
// asymmetric.sign

type signArgs struct {
	Privkey    *string `statekit:"required,name=privkey"`
	Passphrase *string `statekit:"name=passphrase"`
	Text       *string `statekit:"name=text"`
	Filename   *string `statekit:"name=filename"`
	Digest     *string `statekit:"name=digest"`
	Raw        *bool   `statekit:"name=raw"`
	Path       *string `statekit:"name=path"`
}

type signFunc struct{}

func (signFunc) Name() string { return "asymmetric.sign" }
func (signFunc) Args() any    { return signArgs{} }
func (signFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverASYM(&res, &err)
	a := args.(*signArgs)

	var data []byte
	var isFile bool
	switch {
	case a.Text != nil && *a.Text != "":
		data = []byte(*a.Text)
	case a.Filename != nil && *a.Filename != "":
		fdata, rerr := rt.FS.ReadFile(*a.Filename)
		if rerr != nil {
			return nil, fmt.Errorf("Could not read '%s'", *a.Filename)
		}
		data = fdata
		isFile = true
	default:
		return nil, &invocationErr{msg: "Either `text` or `filename` is required"}
	}

	key, kerr := loadPrivateKey(rt, a.Privkey, a.Passphrase)
	if kerr != nil {
		return nil, kerr
	}
	digest := strDerefA(a.Digest)
	// File inputs are digested once for RSA/EC (prehashed); Ed25519 signs the
	// raw bytes like upstream.
	prehashed := false
	payload := data
	if isFile && key.alg != "ED25519" {
		h, herr := digestHash(digest)
		if herr != nil {
			return nil, herr
		}
		payload = sumOf(data, h)
		prehashed = true
	}
	sig, serr := signPrimitive(key, payload, digest, prehashed)
	if serr != nil {
		return nil, serr
	}

	// Upstream defaults raw to bool(path) when the flag is omitted.
	var rawOut bool
	if a.Raw != nil {
		rawOut = *a.Raw
	} else {
		rawOut = strDerefA(a.Path) != ""
	}
	writeTo := strDerefA(a.Path)
	var encoded string
	if !rawOut {
		encoded = base64.StdEncoding.EncodeToString(sig)
	}
	if writeTo != "" {
		payload := encoded
		if rawOut {
			payload = string(sig)
		}
		if werr := rt.FS.WriteFile(writeTo, []byte(payload), 0o600); werr != nil {
			return nil, fmt.Errorf("Could not write signature to '%s'", writeTo)
		}
		return fmt.Sprintf("Signature written to '%s'", writeTo), nil
	}
	if rawOut {
		return sig, nil
	}
	return encoded, nil
}

// ---------------------------------------------------------------------------
// asymmetric.verify

type verifyArgs struct {
	Text        *string  `statekit:"name=text"`
	Filename    *string  `statekit:"name=filename"`
	Pubkey      *string  `statekit:"name=pubkey"`
	Signature   any      `statekit:"name=signature"`
	Digest      *string  `statekit:"name=digest"`
	SignedByAny []string `statekit:"name=signed_by_any"`
	SignedByAll []string `statekit:"name=signed_by_all"`
}

type verifyFunc struct{}

func (verifyFunc) Name() string { return "asymmetric.verify" }
func (verifyFunc) Args() any    { return verifyArgs{} }
func (verifyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverASYM(&res, &err)
	a := args.(*verifyArgs)

	ret := map[string]any{"res": false, "message": "internal error"}
	signedByAny := a.SignedByAny
	signedByAll := a.SignedByAll

	if a.Text != nil && *a.Text != "" && a.Filename != nil && *a.Filename != "" {
		panic(&invocationErr{msg: "`text` and `filename` arguments are mutually exclusive"})
	}
	sigProvided := signatureProvided(a.Signature)
	if !sigProvided {
		panic(&invocationErr{msg: "Missing `signature` parameter"})
	}
	multiCheck := len(signedByAny) > 0 || len(signedByAll) > 0
	pubkeySet := strDerefA(a.Pubkey) != ""
	switch {
	case multiCheck && pubkeySet:
		panic(&invocationErr{msg: "Either specify pubkey + signature or signed_by_(any|all)"})
	case !multiCheck && !pubkeySet:
		panic(&invocationErr{msg: "Missing pubkey(s) to check against"})
	case !multiCheck && pubkeySet:
		signedByAll = []string{*a.Pubkey}
	}

	var data []byte
	var isFile bool
	switch {
	case a.Text != nil && *a.Text != "":
		data = []byte(*a.Text)
	case a.Filename != nil && *a.Filename != "":
		fdata, rerr := rt.FS.ReadFile(*a.Filename)
		if rerr != nil {
			panic(fmt.Errorf("Path '%s' does not exist", *a.Filename))
		}
		data = fdata
		isFile = true
	default:
		panic(&invocationErr{msg: "Missing data to verify. Either specify `text` or `filename`"})
	}

	var sigRefs []any
	if list, ok := a.Signature.([]any); ok {
		sigRefs = list
	} else {
		sigRefs = []any{a.Signature}
	}
	var sigs []*sigFetch
	for _, ref := range sigRefs {
		sf, ferr := fetchSig(rt, ref)
		if ferr != nil {
			if pubkeySet {
				ret["message"] = ferr.Error()
				return ret, nil
			}
			continue // multi-check mode skips unfetchable signatures
		}
		sigs = append(sigs, sf)
	}
	if len(sigs) == 0 {
		panic(fmt.Errorf("Unable to locate any of the provided signatures"))
	}

	fileDigest := []byte(nil)
	digestCache := map[string][]byte{}
	cachedDigest := func() ([]byte, error) {
		if d, ok := digestCache["file"]; ok {
			return d, nil
		}
		h, herr := digestHash(orDefault(strDerefA(a.Digest)))
		if herr != nil {
			return nil, herr
		}
		d := sumOf(data, h)
		digestCache["file"] = d
		return d, nil
	}

	verifyOne := func(pubRef string, sf *sigFetch) (bool, error) {
		pub, lerr := loadPublicKey(rt, &pubRef)
		if lerr != nil {
			return false, lerr
		}
		algErr := keyAlgName(pub)
		if algErr == "ED25519" {
			return verifyPrimitive(pub, sf.raw, data, "", false), nil
		}
		payload := data
		prehashed := false
		if isFile {
			d, derr := cachedDigest()
			if derr != nil {
				return false, derr
			}
			payload, prehashed = d, true
		} else if fileDigest != nil {
			payload, prehashed = fileDigest, true
		}
		ok := verifyPrimitive(pub, sf.raw, payload, orDefault(strDerefA(a.Digest)), prehashed)
		return ok, nil
	}

	anyCheck := false
	allCheck := false

	if len(signedByAny) > 0 {
		matched := false
		for _, signer := range signedByAny {
			for _, sf := range sigs {
				ok, verr := verifyOne(signer, sf)
				if verr == nil && ok {
					matched = true
					break
				}
				if verr != nil {
					if d, ok2 := digestCache["file"]; ok2 {
						fileDigest = d
					}
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			ret["message"] = "None of the public keys listed in signed_by_any provided a valid signature"
			return ret, nil
		}
		anyCheck = true
	}

	if len(signedByAll) > 0 {
		remaining := append([]*sigFetch{}, sigs...)
		for _, signer := range signedByAll {
			consumed := false
			var leftover []*sigFetch
			for _, sf := range remaining {
				ok, verr := verifyOne(signer, sf)
				if verr == nil && ok && !consumed {
					consumed = true // one signature per key
					continue
				}
				leftover = append(leftover, sf)
			}
			if !consumed {
				ret["res"] = false
				if pubkeySet {
					ret["message"] = "Failed checking signature"
				} else {
					ret["message"] = "Failed while checking `signed_by_all`"
				}
				return ret, nil
			}
			remaining = leftover
		}
		allCheck = true
	}

	if boolOf(len(signedByAny) > 0) == anyCheck && boolOf(len(signedByAll) > 0) == allCheck {
		ret["res"] = true
		if pubkeySet {
			ret["message"] = "The signature is valid"
		} else {
			ret["message"] = "All required keys have provided a signature"
		}
		return ret, nil
	}
	ret["res"] = false
	return ret, nil
}

func boolOf(b bool) bool { return b }

func signatureProvided(sig any) bool {
	switch t := sig.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	}
	return true
}

func keyAlgName(pub any) string {
	switch pub.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "EC"
	case ed25519.PublicKey:
		return "ED25519"
	}
	return "UNKNOWN"
}

// Register installs the R5.4 asymmetric surface.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		signFunc{},
		verifyFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
