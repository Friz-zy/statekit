// Package nacl implements Salt's NaCl encryption surface (R5.5):
// saltstack/salt/modules/nacl.py and salt/utils/nacl.py @ pinned revision,
// backed by golang.org/x/crypto/nacl (see docs/adr/0002-nacl-x-crypto.md)
// for wire-compatible interoperation with PyNaCl/libnacl:
//
//   - sealed boxes follow crypto_box_seal (anonymous X25519 + XSalsa20-
//     Poly1305, output prefixed with the ephemeral public key);
//   - secret boxes follow libnacl's SecretBox layout (24-byte nonce
//     prepended to crypto_secretbox_easy output);
//   - keys are 32 raw bytes carried as base64 strings or single-line files.
//
// Documented boundaries: the deprecated keyfile/key spellings from
// upstream's **kwargs are not accepted (the CLI schema exposes sk_file/sk);
// configuration defaults resolve through the optional config.get delegate
// with a workspace-local pki_dir fallback instead of Salt's master opts.
package nacl

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/friz-zy/statekit/internal/runtime"
	"github.com/friz-zy/statekit/modules/exec/cp"
)

func recoverNACL(res *any, errPtr *error) {
	if r := recover(); r != nil {
		switch e := r.(type) {
		case error:
			*errPtr = e
		default:
			panic(r)
		}
	}
}

var nonceSource = func() [24]byte {
	var nonce [24]byte
	if _, err := cryptorand.Read(nonce[:]); err != nil {
		panic(err)
	}
	return nonce
}

type keyRef struct {
	boxType string
	sk      *string
	pk      *string
	skFile  string
	pkFile  string
}

func strDerefN(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// configOf ports _get_config with StateKit's optional-config degradation.
func configOf(rt *runtime.Runtime, boxType, sk, pk, skFile, pkFile *string) keyRef {
	pkiDir := ".statekit/pki/master"
	res, err := callDelegateN(rt, "config.get", map[string]any{"key": "pki_dir"})
	if err == nil {
		if s, ok := res.(string); ok && s != "" {
			pkiDir = s
		}
	}
	cfg := keyRef{
		boxType: "sealedbox",
		skFile:  filepath.Join(pkiDir, "master", "nacl"),
		pkFile:  filepath.Join(pkiDir, "master", "nacl.pub"),
	}
	if m, ok := configOptionMapN(rt, "nacl.config"); ok {
		applyCfgMap(&cfg, m)
	}
	applyArgs(&cfg, boxType, sk, pk, skFile, pkFile)
	return cfg
}

func applyCfgMap(cfg *keyRef, m map[string]any) {
	if v, ok := m["box_type"].(string); ok && v != "" {
		cfg.boxType = v
	}
	setPtr := func(key string, dst **string) {
		if v, ok := m[key].(string); ok && v != "" {
			s := v
			*dst = &s
		}
	}
	setPtr("sk", &cfg.sk)
	setPtr("pk", &cfg.pk)
	setStr := func(key string, dst *string) {
		if v, ok := m[key].(string); ok && v != "" {
			*dst = v
		}
	}
	setStr("sk_file", &cfg.skFile)
	setStr("pk_file", &cfg.pkFile)
}

func applyArgs(cfg *keyRef, boxType, sk, pk, skFile, pkFile *string) {
	if boxType != nil && *boxType != "" {
		cfg.boxType = *boxType
	}
	if sk != nil && *sk != "" {
		cfg.sk = sk
	}
	if pk != nil && *pk != "" {
		cfg.pk = pk
	}
	if skFile != nil && *skFile != "" {
		cfg.skFile = *skFile
	}
	if pkFile != nil && *pkFile != "" {
		cfg.pkFile = *pkFile
	}
}

func configOptionMapN(rt *runtime.Runtime, key string) (map[string]any, bool) {
	if _, ok := rt.Exec.Get("config.get"); !ok {
		return nil, false
	}
	res, err := rt.Exec.Call(context.Background(), rt, "config.get",
		map[string]any{"key": key})
	if err != nil {
		return nil, false
	}
	m, _ := res.(map[string]any)
	return m, m != nil
}

func callDelegateN(rt *runtime.Runtime, name string, args any) (any, error) {
	if _, ok := rt.Exec.Get(name); !ok {
		return nil, fmt.Errorf("%s is not available", name)
	}
	return rt.Exec.Call(context.Background(), rt, name, args)
}

func getSK(rt *runtime.Runtime, cfg keyRef) ([32]byte, error) {
	var key [32]byte
	var encoded string
	if cfg.sk != nil && *cfg.sk != "" {
		encoded = *cfg.sk
	} else {
		data, rerr := rt.FS.ReadFile(cfg.skFile)
		if rerr != nil {
			return key, fmt.Errorf("no key or sk_file found")
		}
		encoded = strings.TrimRight(string(data), "\n")
	}
	raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if derr != nil || len(raw) != 32 {
		return key, fmt.Errorf("invalid secret key material")
	}
	copy(key[:], raw)
	return key, nil
}

func getPK(rt *runtime.Runtime, cfg keyRef) ([32]byte, error) {
	var key [32]byte
	var encoded string
	if cfg.pk != nil && *cfg.pk != "" {
		encoded = *cfg.pk
	} else {
		data, rerr := rt.FS.ReadFile(cfg.pkFile)
		if rerr != nil {
			return key, fmt.Errorf("no pubkey or pk_file found")
		}
		encoded = strings.TrimRight(string(data), "\n")
	}
	raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if derr != nil || len(raw) != 32 {
		return key, fmt.Errorf("invalid public key material")
	}
	copy(key[:], raw)
	return key, nil
}

func fipsBlocked(rt *runtime.Runtime) bool {
	res, err := callDelegateN(rt, "config.get", map[string]any{"key": "fips_mode"})
	if err != nil || res == nil {
		return false
	}
	b, ok := res.(bool)
	return ok && b
}

func ensureNotFIPS(rt *runtime.Runtime) {
	if fipsBlocked(rt) {
		panic(fmt.Errorf("nacl module not available in FIPS mode"))
	}
}

// ---------------------------------------------------------------------------
// nacl.keygen

type keygenArgs struct {
	SkFile *string `statekit:"name=sk_file"`
	PkFile *string `statekit:"name=pk_file"`
}

type keygenFunc struct{}

func (keygenFunc) Name() string { return "nacl.keygen" }
func (keygenFunc) Args() any    { return keygenArgs{} }
func (keygenFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverNACL(&res, &err)
	a := args.(*keygenArgs)
	ensureNotFIPS(rt)
	return keygenImpl(rt, strDerefN(a.SkFile), strDerefN(a.PkFile))
}

func generateKeypair() (skB64, pkB64 string, skRaw [32]byte, err error) {
	var sk [32]byte
	if _, rerr := cryptorand.Read(sk[:]); rerr != nil {
		return "", "", sk, rerr
	}
	pk, cerr := curve25519.X25519(sk[:], curve25519.Basepoint)
	if cerr != nil {
		return "", "", sk, cerr
	}
	var pkArr [32]byte
	copy(pkArr[:], pk)
	return base64.StdEncoding.EncodeToString(sk[:]),
		base64.StdEncoding.EncodeToString(pk[:]), sk, nil
}

func writeSkFile(rt *runtime.Runtime, path string, skB64 string) error {
	rt.FS.MkdirAll(filepath.Dir(path), 0o700)
	if werr := rt.FS.WriteFile(path, []byte(skB64), 0o600); werr != nil {
		return werr
	}
	rt.FS.Chmod(path, 0o600)
	return nil
}

func writePkFile(rt *runtime.Runtime, path string, pkB64 string) error {
	rt.FS.MkdirAll(filepath.Dir(path), 0o700)
	return rt.FS.WriteFile(path, []byte(pkB64), 0o644)
}

func keygenImpl(rt *runtime.Runtime, skFileArg, pkFileArg string) (any, error) {
	explicitPk := pkFileArg != ""
	skFile, pkFile := skFileArg, pkFileArg
	if skFile == "" && pkFile == "" {
		skB64, pkB64, _, err := generateKeypair()
		if err != nil {
			return nil, err
		}
		return map[string]any{"sk": skB64, "pk": pkB64}, nil
	}
	if skFile == "" && pkFile != "" {
		return nil, fmt.Errorf("sk_file: Must be set inorder to generate a public key.")
	}
	if pkFile == "" {
		pkFile = skFile + ".pub"
	}
	skExists := fileExistsN(rt, skFile)
	pkExists := fileExistsN(rt, pkFile)

	switch {
	case skExists && pkExists:
		return nil, fmt.Errorf("sk_file:%s and pk_file:%s already exist.", skFile, pkFile)
	case skExists:
		// Derive the public key from the stored secret key.
		sk, err := getSK(rt, keyRef{skFile: skFile})
		if err != nil {
			return nil, err
		}
		pk, cerr := curve25519.X25519(sk[:], curve25519.Basepoint)
		if cerr != nil {
			return nil, cerr
		}
		if werr := writePkFile(rt, pkFile,
			base64.StdEncoding.EncodeToString(pk)); werr != nil {
			return nil, werr
		}
		return fmt.Sprintf("saved pk_file: %s", pkFile), nil
	case !skExists && !explicitPk:
		// sk_file alone on a fresh path: create only the secret key file.
		skB64, _, _, gerr := generateKeypair()
		if gerr != nil {
			return nil, gerr
		}
		if werr := writeSkFile(rt, skFile, skB64); werr != nil {
			return nil, werr
		}
		return fmt.Sprintf("saved sk_file: %s", skFile), nil
	default:
		skB64, pkB64, _, gerr := generateKeypair()
		if gerr != nil {
			return nil, gerr
		}
		if werr := writeSkFile(rt, skFile, skB64); werr != nil {
			return nil, werr
		}
		if werr := writePkFile(rt, pkFile, pkB64); werr != nil {
			return nil, werr
		}
		return fmt.Sprintf("saved sk_file:%s  pk_file: %s", skFile, pkFile), nil
	}
}
func fileExistsN(rt *runtime.Runtime, path string) bool {
	info, err := rt.FS.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// ---------------------------------------------------------------------------
// primitives

func sealedboxEncryptImpl(rt *runtime.Runtime, data []byte, cfg keyRef) (string, error) {
	pk, err := getPK(rt, cfg)
	if err != nil {
		return "", err
	}
	sealed, serr := box.SealAnonymous(nil, data, &pk, cryptorand.Reader)
	if serr != nil {
		return "", serr
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

func sealedboxDecryptImpl(rt *runtime.Runtime, data []byte, cfg keyRef) ([]byte, error) {
	sk, err := getSK(rt, cfg)
	if err != nil {
		return nil, err
	}
	raw, derr := base64.StdEncoding.DecodeString(string(data))
	if derr != nil {
		return nil, derr
	}
	// Recipient pk participates in the blake2b nonce derivation, so it is
	// derived from sk like PyNaCl does internally.
	pk, perr := curve25519.X25519(sk[:], curve25519.Basepoint)
	if perr != nil {
		return nil, perr
	}
	var pkArr [32]byte
	copy(pkArr[:], pk)
	decrypted, ok := box.OpenAnonymous(nil, raw, &pkArr, &sk)
	if !ok {
		return nil, fmt.Errorf("could not decrypt message with passed private key")
	}
	return decrypted, nil
}

func secretboxEncryptImpl(rt *runtime.Runtime, data []byte, cfg keyRef) (string, error) {
	sk, err := getSK(rt, cfg)
	if err != nil {
		return "", err
	}
	nonce := nonceSource()
	sealed := secretbox.Seal(nil, data, &nonce, &sk)
	out := append(nonce[:], sealed...)
	return base64.StdEncoding.EncodeToString(out), nil
}

func secretboxDecryptImpl(rt *runtime.Runtime, data []byte, cfg keyRef) ([]byte, error) {
	sk, err := getSK(rt, cfg)
	if err != nil {
		return nil, err
	}
	raw, derr := base64.StdEncoding.DecodeString(string(data))
	if derr != nil {
		return nil, derr
	}
	if len(raw) < 24 {
		return nil, fmt.Errorf("could not decrypt message with passed secret key")
	}
	var nonce [24]byte
	copy(nonce[:], raw[:24])
	decrypted, ok := secretbox.Open(nil, raw[24:], &nonce, &sk)
	if !ok {
		return nil, fmt.Errorf("could not decrypt message with passed secret key")
	}
	return decrypted, nil
}

// ---------------------------------------------------------------------------
// nacl.enc / nacl.dec

type encArgs struct {
	Data    string  `statekit:"required,name=data"`
	BoxType *string `statekit:"name=box_type"`
	Sk      *string `statekit:"name=sk"`
	Pk      *string `statekit:"name=pk"`
	SkFile  *string `statekit:"name=sk_file"`
	PkFile  *string `statekit:"name=pk_file"`
}

type encFunc struct{}

func (encFunc) Name() string { return "nacl.enc" }
func (encFunc) Args() any    { return encArgs{} }
func (encFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverNACL(&res, &err)
	a := args.(*encArgs)
	ensureNotFIPS(rt)
	cfg := configOf(rt, a.BoxType, a.Sk, a.Pk, a.SkFile, a.PkFile)
	var out string
	var oerr error
	if cfg.boxType == "secretbox" {
		out, oerr = secretboxEncryptImpl(rt, []byte(a.Data), cfg)
	} else {
		out, oerr = sealedboxEncryptImpl(rt, []byte(a.Data), cfg)
	}
	if oerr != nil {
		return nil, oerr
	}
	return out, nil
}

type decArgs struct {
	Data    *string `statekit:"name=data"`
	BoxType *string `statekit:"name=box_type"`
	Sk      *string `statekit:"name=sk"`
	Pk      *string `statekit:"name=pk"`
	SkFile  *string `statekit:"name=sk_file"`
	PkFile  *string `statekit:"name=pk_file"`
}

type decFunc struct{}

func (decFunc) Name() string { return "nacl.dec" }
func (decFunc) Args() any    { return decArgs{} }
func (decFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverNACL(&res, &err)
	a := args.(*decArgs)
	ensureNotFIPS(rt)
	if a.Data == nil {
		return nil, nil // upstream returns None for None input
	}
	cfg := configOf(rt, a.BoxType, a.Sk, a.Pk, a.SkFile, a.PkFile)
	var plain []byte
	var derr error
	if cfg.boxType == "secretbox" {
		plain, derr = secretboxDecryptImpl(rt, []byte(*a.Data), cfg)
	} else {
		plain, derr = sealedboxDecryptImpl(rt, []byte(*a.Data), cfg)
	}
	if derr != nil {
		return nil, derr
	}
	return string(plain), nil
}

// ---------------------------------------------------------------------------
// nacl.sealedbox_* / nacl.secretbox_*

type sealedboxEncryptArgs struct {
	Data   string  `statekit:"required,name=data"`
	Pk     *string `statekit:"name=pk"`
	PkFile *string `statekit:"name=pk_file"`
}

type sealedboxEncryptFunc struct{}

func (sealedboxEncryptFunc) Name() string { return "nacl.sealedbox_encrypt" }
func (sealedboxEncryptFunc) Args() any    { return sealedboxEncryptArgs{} }
func (sealedboxEncryptFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverNACL(&res, &err)
	a := args.(*sealedboxEncryptArgs)
	ensureNotFIPS(rt)
	cfg := configOf(rt, nil, nil, a.Pk, nil, a.PkFile)
	return sealedboxEncryptImpl(rt, []byte(a.Data), cfg)
}

type sealedboxDecryptArgs struct {
	Data   *string `statekit:"required,name=data"`
	Sk     *string `statekit:"name=sk"`
	SkFile *string `statekit:"name=sk_file"`
}

type sealedboxDecryptFunc struct{}

func (sealedboxDecryptFunc) Name() string { return "nacl.sealedbox_decrypt" }
func (sealedboxDecryptFunc) Args() any    { return sealedboxDecryptArgs{} }
func (sealedboxDecryptFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverNACL(&res, &err)
	a := args.(*sealedboxDecryptArgs)
	ensureNotFIPS(rt)
	if a.Data == nil {
		return nil, nil
	}
	cfg := configOf(rt, nil, a.Sk, nil, a.SkFile, nil)
	plain, derr := sealedboxDecryptImpl(rt, []byte(*a.Data), cfg)
	if derr != nil {
		return nil, derr
	}
	return string(plain), nil
}

type secretboxEncryptArgs struct {
	Data   string  `statekit:"required,name=data"`
	Sk     *string `statekit:"name=sk"`
	SkFile *string `statekit:"name=sk_file"`
}

type secretboxEncryptFunc struct{}

func (secretboxEncryptFunc) Name() string { return "nacl.secretbox_encrypt" }
func (secretboxEncryptFunc) Args() any    { return secretboxEncryptArgs{} }
func (secretboxEncryptFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverNACL(&res, &err)
	a := args.(*secretboxEncryptArgs)
	ensureNotFIPS(rt)
	cfg := configOf(rt, strPtrN("secretbox"), a.Sk, nil, a.SkFile, nil)
	return secretboxEncryptImpl(rt, []byte(a.Data), cfg)
}

type secretboxDecryptArgs struct {
	Data   *string `statekit:"required,name=data"`
	Sk     *string `statekit:"name=sk"`
	SkFile *string `statekit:"name=sk_file"`
}

type secretboxDecryptFunc struct{}

func (secretboxDecryptFunc) Name() string { return "nacl.secretbox_decrypt" }
func (secretboxDecryptFunc) Args() any    { return secretboxDecryptArgs{} }
func (secretboxDecryptFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverNACL(&res, &err)
	a := args.(*secretboxDecryptArgs)
	ensureNotFIPS(rt)
	if a.Data == nil {
		return nil, nil
	}
	cfg := configOf(rt, strPtrN("secretbox"), a.Sk, nil, a.SkFile, nil)
	plain, derr := secretboxDecryptImpl(rt, []byte(*a.Data), cfg)
	if derr != nil {
		return nil, derr
	}
	return string(plain), nil
}

func strPtrN(s string) *string { return &s }

// ---------------------------------------------------------------------------
// nacl.enc_file / nacl.dec_file

type encFileArgs struct {
	Name    string  `statekit:"required,name=name"`
	Out     *string `statekit:"name=out"`
	BoxType *string `statekit:"name=box_type"`
	Sk      *string `statekit:"name=sk"`
	Pk      *string `statekit:"name=pk"`
	SkFile  *string `statekit:"name=sk_file"`
	PkFile  *string `statekit:"name=pk_file"`
}

type encFileFunc struct{}

func (encFileFunc) Name() string { return "nacl.enc_file" }
func (encFileFunc) Args() any    { return encFileArgs{} }
func (encFileFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverNACL(&res, &err)
	a := args.(*encFileArgs)
	ensureNotFIPS(rt)
	data, derr := readFileViaCP(rt, a.Name)
	if derr != nil {
		return nil, derr
	}
	cfg := configOf(rt, a.BoxType, a.Sk, a.Pk, a.SkFile, a.PkFile)
	var out string
	var oerr error
	if cfg.boxType == "secretbox" {
		out, oerr = secretboxEncryptImpl(rt, data, cfg)
	} else {
		out, oerr = sealedboxEncryptImpl(rt, data, cfg)
	}
	if oerr != nil {
		return nil, oerr
	}
	return finishWithOut(rt, out, a.Out)
}

type decFileArgs struct {
	Name    string  `statekit:"required,name=name"`
	Out     *string `statekit:"name=out"`
	BoxType *string `statekit:"name=box_type"`
	Sk      *string `statekit:"name=sk"`
	Pk      *string `statekit:"name=pk"`
	SkFile  *string `statekit:"name=sk_file"`
	PkFile  *string `statekit:"name=pk_file"`
}

type decFileFunc struct{}

func (decFileFunc) Name() string { return "nacl.dec_file" }
func (decFileFunc) Args() any    { return decFileArgs{} }
func (decFileFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverNACL(&res, &err)
	a := args.(*decFileArgs)
	ensureNotFIPS(rt)
	data, derr := readFileViaCP(rt, a.Name)
	if derr != nil {
		return nil, derr
	}
	cfg := configOf(rt, a.BoxType, a.Sk, a.Pk, a.SkFile, a.PkFile)
	var plain []byte
	var oerr error
	if cfg.boxType == "secretbox" {
		plain, oerr = secretboxDecryptImpl(rt, data, cfg)
	} else {
		plain, oerr = sealedboxDecryptImpl(rt, data, cfg)
	}
	if oerr != nil {
		return nil, oerr
	}
	return finishWithOut(rt, string(plain), a.Out)
}

// readFileViaCP mirrors enc_file/dec_file input handling: cp.get_file_str
// first (covers salt:// etc.), falling back to the local filesystem.
func readFileViaCP(rt *runtime.Runtime, name string) ([]byte, error) {
	if _, ok := rt.Exec.Get("cp.get_file_str"); ok {
		res, err := rt.Exec.Call(context.Background(), rt, "cp.get_file_str",
			&cp.GetFileStrArgs{Path: name})
		if err == nil {
			if s, ok := res.(string); ok {
				return []byte(s), nil
			}
		}
	}
	data, rerr := rt.FS.ReadFile(name)
	if rerr != nil {
		return nil, rerr
	}
	return data, nil
}

func finishWithOut(rt *runtime.Runtime, payload string, out *string) (any, error) {
	if out == nil || *out == "" {
		return payload, nil
	}
	if fileExistsN(rt, *out) {
		return nil, fmt.Errorf("file:%s already exist.", *out)
	}
	if werr := rt.FS.WriteFile(*out, []byte(payload), 0o644); werr != nil {
		return nil, werr
	}
	return fmt.Sprintf("Wrote: %s", *out), nil
}

// Register installs the R5.5 NaCl surface.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		keygenFunc{},
		encFunc{},
		decFunc{},
		encFileFunc{},
		decFileFunc{},
		sealedboxEncryptFunc{},
		sealedboxDecryptFunc{},
		secretboxEncryptFunc{},
		secretboxDecryptFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
