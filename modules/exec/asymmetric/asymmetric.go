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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	"crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
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

var (
	keyReadError         = errors.New("Could not read key")
	privateKeyParseError = errors.New("Could not parse private key")
	publicKeyParseError  = errors.New("Could not parse public key")
	dataReadError        = errors.New("Could not read data")
)

// maxDataBytes is the finite ceiling for filename inputs. The bounded runtime
// reader validates the limit before allocation and reads only regular files.
const maxDataBytes int64 = runtime.MaxBoundedReadLimit

// classifiedASYMError deliberately exposes only stable text while retaining
// safe, non-sensitive sentinel classification for callers.
type classifiedASYMError struct {
	msg   string
	cause error
}

func (e *classifiedASYMError) Error() string { return e.msg }
func (e *classifiedASYMError) Unwrap() error { return e.cause }

func stableASYMError(msg string, err error) error {
	if err == nil {
		return errors.New(msg)
	}
	if errors.Is(err, runtime.ErrReadLimit) ||
		errors.Is(err, runtime.ErrInvalidReadLimit) ||
		errors.Is(err, runtime.ErrNonRegularFile) ||
		errors.Is(err, runtime.ErrUnsafePathRead) ||
		errors.Is(err, fs.ErrNotExist) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return &classifiedASYMError{msg: msg, cause: err}
	}
	var unsupportedErr *runtime.UnsupportedError
	if errors.As(err, &unsupportedErr) {
		// Only the fixed delegate name is safe to expose; a delegate must not
		// be able to turn an untrusted URI into public error text.
		return &runtime.UnsupportedError{Kind: "function", Name: "cp.cache_file"}
	}
	return errors.New(msg)
}

type unsupportedDigestError struct{ name string }

func (e *unsupportedDigestError) Error() string {
	return fmt.Sprintf("Unsupported digest algorithm '%s'", e.name)
}

func unsupported(name string) error {
	return &runtime.UnsupportedError{Kind: "algorithm", Name: name}
}

func strDerefA(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// fileURLPath keeps the URL parser's escaped path spelling. In particular,
// %2f must remain part of one filename component rather than becoming a path
// separator. RawPath is populated by net/url when the input used an escaped
// spelling; Path is retained for ordinary unescaped paths. The host is
// intentionally ignored to match Salt's parsed.path handling.
func fileURLPath(parsed *url.URL) string {
	if parsed.RawPath != "" {
		return parsed.EscapedPath()
	}
	if parsed.Path != "" {
		return parsed.Path
	}
	return parsed.Opaque
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
		return nil, privateKeyParseError
	}
	switch block.Type {
	case "PRIVATE KEY":
		key, derr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if derr != nil {
			return nil, privateKeyParseError
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
			return nil, privateKeyParseError
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
			return nil, privateKeyParseError
		}
		return wrapPrivate(key)
	case "OPENSSH PRIVATE KEY":
		return nil, unsupported("OpenSSH private key container")
	default:
		return nil, privateKeyParseError
	}
}

func isEncryptedPEM(block *pem.Block) bool {
	_, has := block.Headers["DEK-Info"]
	return has
}

func decryptPEM(block *pem.Block, passphrase *string) ([]byte, error) {
	if passphrase == nil || *passphrase == "" {
		return nil, errors.New("Private key passphrase required")
	}
	clear, derr := x509.DecryptPEMBlock(block, []byte(*passphrase))
	if derr != nil {
		return nil, errors.New("Could not decrypt private key")
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
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, publicKeyParseError
			}
			return key, nil
		case "RSA PUBLIC KEY":
			key, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return nil, publicKeyParseError
			}
			return key, nil
		default:
			return nil, publicKeyParseError
		}
	}
	der, berr := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(data)), ""))
	if berr == nil {
		if key, perr := x509.ParsePKIXPublicKey(der); perr == nil {
			return key, nil
		}
	}
	return nil, publicKeyParseError
}

// resolveRef reads a key reference: inline PEM material or a filesystem
// path. URL parsing intentionally follows Salt's _fetch: file URLs use their
// parsed path (the host is ignored), while every other scheme delegates the
// original URI. All filesystem reads are bounded and descriptor-safe.
func resolveRef(rt *runtime.Runtime, ref *string) ([]byte, error) {
	if ref == nil || *ref == "" {
		return nil, &invocationErr{msg: "Missing key reference"}
	}
	val := *ref
	parsed, parseErr := url.Parse(val)
	if parseErr != nil {
		// Salt treats malformed URL input as an inline key candidate.
		return []byte(val), nil
	}
	if parsed.Scheme != "" && parsed.Scheme != "file" {
		res, derr := callDelegateASYM(rt, "cp.cache_file", map[string]any{"path": val})
		if derr != nil {
			return nil, stableASYMError("Could not read key", derr)
		}
		cached, ok := res.(string)
		if !ok || cached == "" {
			return nil, keyReadError
		}
		return readASYMFile(rt, cached, keyReadError)
	}

	path := val
	if parsed.Scheme == "file" {
		path = fileURLPath(parsed)
	}
	if parsed.Scheme == "" {
		// Existing bare paths have precedence over inline material, as in
		// x509.load_file_or_bytes. A missing non-absolute value remains inline.
		info, statErr := rt.FS.Stat(path)
		if statErr != nil {
			if strings.HasPrefix(path, "/") {
				return nil, stableASYMError(keyReadError.Error(), statErr)
			}
			return []byte(val), nil
		}
		if info == nil || !info.Mode().IsRegular() {
			return nil, keyReadError
		}
	}
	return readASYMFile(rt, path, keyReadError)
}

// maxPrivateKeyBytes bounds key references before PEM/X.509 parsing.
const maxPrivateKeyBytes int64 = 16 << 20

func readASYMFile(rt *runtime.Runtime, name string, failure error) ([]byte, error) {
	data, err := runtime.ReadFileBounded(rt.FS, name, maxPrivateKeyBytes)
	if err != nil {
		return nil, stableASYMError(failure.Error(), err)
	}
	return data, nil
}

// ---------------------------------------------------------------------------
// primitives

func digestHash(name string) (crypto.Hash, error) {
	var h crypto.Hash
	switch strings.ToLower(name) {
	case "sha1":
		h = crypto.SHA1
	case "sha224":
		h = crypto.SHA224
	case "", defaultDigest:
		h = crypto.SHA256
	case "sha384":
		h = crypto.SHA384
	case "sha512":
		h = crypto.SHA512
	case "sha3_224":
		h = crypto.SHA3_224
	case "sha3_256":
		h = crypto.SHA3_256
	case "sha3_384":
		h = crypto.SHA3_384
	case "sha3_512":
		h = crypto.SHA3_512
	case "sha512_224":
		h = crypto.SHA512_224
	case "sha512_256":
		h = crypto.SHA512_256
	default:
		return 0, &unsupportedDigestError{name: name}
	}
	if !h.Available() {
		return 0, &unsupportedDigestError{name: name}
	}
	return h, nil
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
		return rsa.SignPSS(rand.Reader, rsaKey, h, payload, &rsa.PSSOptions{
			Hash: h,
			// Go's Auto means the largest permitted salt while signing,
			// matching cryptography's PSS.MAX_LENGTH in Salt.
			SaltLength: rsa.PSSSaltLengthAuto,
		})
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

func verifyPrimitive(pub any, signature, data []byte, digest string, prehashed bool) (bool, error) {
	digest = orDefault(digest)
	switch key := pub.(type) {
	case *rsa.PublicKey:
		h, herr := digestHash(digest)
		if herr != nil {
			return false, herr
		}
		payload := data
		if !prehashed {
			payload = sumOf(data, h)
		}
		err := rsa.VerifyPSS(key, h, payload, signature, &rsa.PSSOptions{
			Hash:       h,
			SaltLength: rsa.PSSSaltLengthAuto,
		})
		return err == nil, nil
	case *ecdsa.PublicKey:
		payload := data
		if !prehashed {
			h, herr := digestHash(digest)
			if herr != nil {
				return false, herr
			}
			payload = sumOf(data, h)
		}
		return ecdsa.VerifyASN1(key, payload, signature), nil
	case ed25519.PublicKey:
		return ed25519.Verify(key, data, signature), nil
	default:
		return false, nil
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

const maxSignatureBytes int64 = 1 << 20
const maxSignatureTextBytes int = int(maxSignatureBytes*4/3 + 4)

const (
	signatureLoadError  = "Failed loading signature as file and/or base64 string"
	signatureFetchError = "Failed fetching signature"
)

func decodeSignatureText(data []byte) ([]byte, bool) {
	// Salt's try_base64 removes LF bytes only, then requires the decoded data
	// to re-encode byte-for-byte. Strict decoding additionally rejects altered
	// pad bits; other whitespace remains invalid instead of being trimmed.
	if len(data) > maxSignatureTextBytes {
		return nil, false
	}
	normalized := bytes.ReplaceAll(data, []byte{'\n'}, nil)
	if bytes.Contains(normalized, []byte{'\r'}) {
		return nil, false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(string(normalized))
	if err == nil && len(raw) <= int(maxSignatureBytes) &&
		bytes.Equal([]byte(base64.StdEncoding.EncodeToString(raw)), normalized) {
		return raw, true
	}
	return nil, false
}

func readSignatureFile(rt *runtime.Runtime, candidate string) ([]byte, error) {
	data, err := runtime.ReadFileBounded(rt.FS, candidate, maxSignatureBytes)
	if err != nil {
		return nil, stableASYMError(signatureFetchError, err)
	}
	if raw, ok := decodeSignatureText(data); ok {
		return raw, nil
	}
	return data, nil
}

// fetchSig ports _fetch for signatures: bare base64 strings pass through,
// local paths/file:// are read from the FS, remote schemes go through the
// cp.cache_file delegate.
func fetchSig(rt *runtime.Runtime, ref any) (*sigFetch, error) {
	var text string
	var rawRef []byte
	var isBytes bool
	switch t := ref.(type) {
	case string:
		text = t
	case []byte:
		rawRef = append([]byte(nil), t...)
		isBytes = true
	default:
		text = fmt.Sprintf("%v", t)
	}
	if isBytes {
		if raw, ok := decodeSignatureText(rawRef); ok {
			return &sigFetch{raw: raw, source: "inline"}, nil
		}
		if len(rawRef) != 0 && len(rawRef) <= int(maxSignatureBytes) {
			return &sigFetch{raw: rawRef, source: "inline"}, nil
		}
		return nil, fmt.Errorf("%s", signatureLoadError)
	}

	parsed, parseErr := url.Parse(text)
	scheme := ""
	path := text
	if parseErr == nil {
		scheme = parsed.Scheme
		if scheme == "file" {
			path = fileURLPath(parsed)
		}
	}

	// A local path wins only when it is an existing regular file. In
	// particular, a leading '/' is not sufficient to classify a value as a
	// path: '/' is a valid base64 alphabet character and may begin a signature.
	explicitFile := scheme == "file"
	if scheme == "" || explicitFile {
		info, statErr := rt.FS.Stat(path)
		if statErr == nil {
			if info == nil || !info.Mode().IsRegular() {
				return nil, fmt.Errorf("%s", signatureFetchError)
			}
			raw, rerr := readSignatureFile(rt, path)
			if rerr != nil {
				return nil, rerr
			}
			return &sigFetch{raw: raw, source: path}, nil
		}
		if explicitFile {
			return nil, errors.New(signatureFetchError)
		}
	}

	candidate := path
	if scheme != "" && scheme != "file" {
		res, err := callDelegateASYM(rt, "cp.cache_file",
			map[string]any{"path": text})
		cached, ok := res.(string)
		if err != nil || !ok || cached == "" {
			if err != nil {
				return nil, stableASYMError(signatureFetchError, err)
			}
			return nil, errors.New(signatureFetchError)
		}
		candidate = cached
		if info, statErr := rt.FS.Stat(candidate); statErr != nil || info == nil || !info.Mode().IsRegular() {
			if statErr != nil {
				return nil, stableASYMError(signatureFetchError, statErr)
			}
			return nil, errors.New(signatureFetchError)
		}
		raw, rerr := readSignatureFile(rt, candidate)
		if rerr != nil {
			return nil, rerr
		}
		return &sigFetch{raw: raw, source: candidate}, nil
	}

	if raw, ok := decodeSignatureText([]byte(text)); ok {
		return &sigFetch{raw: raw, source: "inline"}, nil
	}
	return nil, fmt.Errorf("%s", signatureLoadError)
}

func callDelegateASYM(rt *runtime.Runtime, name string, args any) (any, error) {
	if _, ok := rt.Exec.Get(name); !ok {
		return nil, &runtime.UnsupportedError{Kind: "function", Name: name}
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
		fdata, rerr := runtime.ReadFileBounded(rt.FS, *a.Filename, maxDataBytes)
		if rerr != nil {
			return nil, stableASYMError(dataReadError.Error(), rerr)
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
			return nil, errors.New("Could not write signature")
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
		switch a.Signature.(type) {
		case string, []byte:
		default:
			panic(&invocationErr{msg: "`signature` must be a string or bytes when verifying a single signing `pubkey`"})
		}
		signedByAll = []string{*a.Pubkey}
	}

	var data []byte
	var isFile bool
	switch {
	case a.Text != nil && *a.Text != "":
		data = []byte(*a.Text)
	case a.Filename != nil && *a.Filename != "":
		fdata, rerr := runtime.ReadFileBounded(rt.FS, *a.Filename, maxDataBytes)
		if rerr != nil {
			panic(stableASYMError(dataReadError.Error(), rerr))
		}
		data = fdata
		isFile = true
	default:
		panic(&invocationErr{msg: "Missing data to verify. Either specify `text` or `filename`"})
	}

	var sigRefs []any
	switch list := a.Signature.(type) {
	case []any:
		sigRefs = list
	case []string:
		for _, ref := range list {
			sigRefs = append(sigRefs, ref)
		}
	default:
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
			return verifyPrimitive(pub, sf.raw, data, "", false)
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
		return verifyPrimitive(pub, sf.raw, payload, orDefault(strDerefA(a.Digest)), prehashed)
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
					if isUnsupportedDigest(verr) {
						return nil, verr
					}
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
			matched := false
			var leftover []*sigFetch
			for _, sf := range remaining {
				ok, verr := verifyOne(signer, sf)
				if verr != nil && isUnsupportedDigest(verr) {
					return nil, verr
				}
				if verr == nil && ok {
					// Salt removes every signature matched by this key. This is
					// significant for duplicate signatures and repeated policies.
					matched = true
					continue
				}
				leftover = append(leftover, sf)
			}
			if !matched {
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

func isUnsupportedDigest(err error) bool {
	_, ok := err.(*unsupportedDigestError)
	return ok
}

func signatureProvided(sig any) bool {
	switch t := sig.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case []string:
		return len(t) > 0
	case []byte:
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
