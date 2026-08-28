// Package ssh_pki implements Salt's local OpenSSH PKI surface from
// salt/modules/ssh_pki.py at the pinned revision. It uses the already
// approved golang.org/x/crypto/ssh dependency for OpenSSH certificate wire
// encoding, key parsing, encrypted private-key handling, and signatures.
//
// The peer/ca_server path is intentionally not implemented: peer publish,
// __pub_id, match.compound and the remote query are master-minion machinery,
// permanently outside StateKit's local-only boundary. Local certificate
// issuance, key management, policy merging, inspection and verification are
// kept contract-compatible.
package ssh_pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5" // used only for Salt's non-FIPS fingerprint field
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
	"golang.org/x/crypto/ssh"
)

// invocationErr is used for SaltInvocationError/CommandExecutionError-like
// messages that are part of the execution contract.
type invocationErr struct{ msg string }

func (e *invocationErr) Error() string { return e.msg }

func recoverSSH(res *any, errPtr *error) {
	if r := recover(); r != nil {
		switch e := r.(type) {
		case error:
			*errPtr = e
		default:
			panic(r)
		}
	}
}

func valueTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case *string:
		return x != nil && *x != ""
	case bool:
		return x
	case []string:
		return len(x) > 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	case map[string]string:
		return len(x) > 0
	default:
		return true
	}
}

func stringValue(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case *string:
		if x == nil {
			return "", false
		}
		return *x, true
	case []byte:
		return string(x), true
	default:
		return "", false
	}
}

func boolValue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	default:
		return false
	}
}

// loadFileOrBytes mirrors sshpki.load_file_or_bytes. A string that names an
// existing runtime file is read; otherwise it is treated as inline OpenSSH
// material. This keeps tests hermetic through Runtime.FS.
func loadFileOrBytes(rt *runtime.Runtime, value any) ([]byte, error) {
	switch x := value.(type) {
	case []byte:
		return append([]byte(nil), x...), nil
	case string:
		if info, err := rt.FS.Stat(x); err == nil && !info.IsDir() {
			data, rerr := rt.FS.ReadFile(x)
			if rerr != nil {
				return nil, rerr
			}
			return data, nil
		}
		return []byte(x), nil
	default:
		return nil, &invocationErr{msg: "Could not load provided source. You need to pass an existing file, string or raw bytes."}
	}
}

func privateKeyError(err error, passphraseGiven bool) error {
	if err == nil {
		return nil
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) || strings.Contains(err.Error(), "passphrase protected") {
		return &invocationErr{msg: "Private key is encrypted. Please provide a password."}
	}
	if passphraseGiven {
		if errors.Is(err, x509.IncorrectPasswordError) ||
			strings.Contains(strings.ToLower(err.Error()), "broken checksum") ||
			strings.Contains(strings.ToLower(err.Error()), "incorrect password") {
			return &invocationErr{msg: "Bad decrypt - is the password correct?"}
		}
		if strings.Contains(strings.ToLower(err.Error()), "not an encrypted key") ||
			strings.Contains(strings.ToLower(err.Error()), "not password protected") {
			return &invocationErr{msg: "Password was given but private key is not encrypted"}
		}
	}
	return &invocationErr{msg: "Could not load OpenSSH private key"}
}

func loadRawPrivateKey(rt *runtime.Runtime, value any, passphrase *string) (any, error) {
	switch value.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, crypto.Signer:
		return value, nil
	}
	data, err := loadFileOrBytes(rt, value)
	if err != nil {
		return nil, err
	}
	if passphrase != nil {
		key, perr := ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(*passphrase))
		if perr != nil {
			return nil, privateKeyError(perr, true)
		}
		return key, nil
	}
	key, perr := ssh.ParseRawPrivateKey(data)
	if perr != nil {
		return nil, privateKeyError(perr, false)
	}
	return key, nil
}

func loadSigner(rt *runtime.Runtime, value any, passphrase *string) (ssh.Signer, error) {
	if signer, ok := value.(ssh.Signer); ok {
		return signer, nil
	}
	if signer, ok := value.(crypto.Signer); ok {
		return ssh.NewSignerFromKey(signer)
	}
	key, err := loadRawPrivateKey(rt, value, passphrase)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, &invocationErr{msg: "Could not load OpenSSH private key"}
	}
	return signer, nil
}

func parsePublicKeyData(data []byte) (ssh.PublicKey, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err == nil {
		return key, nil
	}
	key, err = ssh.ParsePublicKey(data)
	if err == nil {
		return key, nil
	}
	return nil, err
}

func loadPublicKey(rt *runtime.Runtime, value any) (ssh.PublicKey, error) {
	if key, ok := value.(ssh.PublicKey); ok {
		return key, nil
	}
	if key, ok := value.(*ssh.Certificate); ok {
		return key, nil
	}
	data, err := loadFileOrBytes(rt, value)
	if err != nil {
		return nil, err
	}
	key, err := parsePublicKeyData(data)
	if err != nil {
		return nil, &invocationErr{msg: "Could not load OpenSSH public key."}
	}
	return key, nil
}

func certPublicKey(key ssh.PublicKey) ssh.PublicKey {
	if cert, ok := key.(*ssh.Certificate); ok {
		return cert.Key
	}
	return key
}

func encodePublicKey(key ssh.PublicKey) string {
	if key == nil {
		return ""
	}
	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(key)), "\n")
}

func keyType(key ssh.PublicKey) string {
	key = certPublicKey(key)
	if cpk, ok := key.(ssh.CryptoPublicKey); ok {
		switch cpk.CryptoPublicKey().(type) {
		case *rsa.PublicKey:
			return "rsa"
		case *ecdsa.PublicKey:
			return "ec"
		case ed25519.PublicKey:
			return "ed25519"
		}
	}
	switch {
	case strings.Contains(key.Type(), "rsa"):
		return "rsa"
	case strings.Contains(key.Type(), "ecdsa"):
		return "ec"
	case strings.Contains(key.Type(), "ed25519"):
		return "ed25519"
	default:
		return key.Type()
	}
}

func keySize(key ssh.PublicKey) any {
	key = certPublicKey(key)
	if cpk, ok := key.(ssh.CryptoPublicKey); ok {
		switch k := cpk.CryptoPublicKey().(type) {
		case *rsa.PublicKey:
			return k.N.BitLen()
		case *ecdsa.PublicKey:
			if k.Curve != nil && k.Curve.Params() != nil {
				return k.Curve.Params().BitSize
			}
		}
	}
	return nil
}

func publicKeysEqual(a, b ssh.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	a = certPublicKey(a)
	b = certPublicKey(b)
	return a.Type() == b.Type() && bytes.Equal(a.Marshal(), b.Marshal())
}

func prettyHex(s string) string {
	s = strings.ToUpper(s)
	if len(s)%2 != 0 {
		s = "0" + s
	}
	var out []string
	for i := 0; i < len(s); i += 2 {
		out = append(out, s[i:i+2])
	}
	return strings.Join(out, ":")
}

func serialHex(serial uint64) string { return prettyHex(fmt.Sprintf("%X", serial)) }

func randomSerial() (uint64, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(raw[:]) >> 1, nil
}

func serialNumber(value any) (uint64, error) {
	if value == nil {
		return randomSerial()
	}
	switch x := value.(type) {
	case uint64:
		return x, nil
	case uint:
		return uint64(x), nil
	case uint32:
		return uint64(x), nil
	case int:
		if x >= 0 {
			return uint64(x), nil
		}
	case int64:
		if x >= 0 {
			return uint64(x), nil
		}
	case int32:
		if x >= 0 {
			return uint64(x), nil
		}
	case float64:
		if x >= 0 && x <= float64(^uint64(0)) {
			return uint64(x), nil
		}
	case string:
		clean := strings.ReplaceAll(x, ":", "")
		if clean == "" || len(clean)%2 != 0 {
			return 0, &invocationErr{msg: fmt.Sprintf("Could not parse serial number %v", value)}
		}
		buf, err := fmtHexDecode(clean)
		if err == nil && len(buf) <= 8 {
			var raw [8]byte
			copy(raw[8-len(buf):], buf)
			return binary.BigEndian.Uint64(raw[:]), nil
		}
	case []byte:
		if len(x) <= 8 {
			var raw [8]byte
			copy(raw[8-len(x):], x)
			return binary.BigEndian.Uint64(raw[:]), nil
		}
	}
	return 0, &invocationErr{msg: fmt.Sprintf("Could not parse serial number %v", value)}
}

func fmtHexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex length")
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		hi, ok := hexNibble(s[2*i])
		if !ok {
			return nil, fmt.Errorf("invalid hex")
		}
		lo, ok := hexNibble(s[2*i+1])
		if !ok {
			return nil, fmt.Errorf("invalid hex")
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func generatePrivateKey(algo string, keysize int) (crypto.PrivateKey, error) {
	switch algo {
	case "rsa":
		if keysize <= 0 {
			keysize = 2048
		}
		return rsa.GenerateKey(rand.Reader, keysize)
	case "ec":
		var curve elliptic.Curve
		switch keysize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, &invocationErr{msg: fmt.Sprintf("Invalid EC key size: %d", keysize)}
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case "ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	default:
		return nil, &invocationErr{msg: fmt.Sprintf(
			"Invalid algorithm specified for generating private key: %s. Valid: rsa, ec, ed25519, ed448", algo)}
	}
}

func marshalPrivateKey(key crypto.PrivateKey, passphrase *string) ([]byte, error) {
	var block *pem.Block
	var err error
	if passphrase == nil {
		block, err = ssh.MarshalPrivateKey(key, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte(*passphrase))
	}
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

func sha256Fingerprint(key ssh.PublicKey) string {
	sum := crypto.SHA256.New()
	_, _ = sum.Write(certPublicKey(key).Marshal())
	return base64.StdEncoding.EncodeToString(sum.Sum(nil))
}

func md5Fingerprint(key ssh.PublicKey) string {
	var h hash.Hash = md5.New() // #nosec G401 -- Salt explicitly exposes MD5 in non-FIPS mode.
	_, _ = h.Write(certPublicKey(key).Marshal())
	return strings.ToLower(prettyHex(fmt.Sprintf("%x", h.Sum(nil))))
}

func fipsMode(rt *runtime.Runtime) bool {
	if rt == nil || rt.Exec == nil {
		return false
	}
	fn, ok := rt.Exec.Get("config.option")
	if !ok {
		return false
	}
	res, err := fn.Execute(context.Background(), rt,
		map[string]any{"key": "fips_mode", "default": false})
	return err == nil && boolValue(res)
}

func fileExists(rt *runtime.Runtime, path string) bool {
	info, err := rt.FS.Stat(path)
	return err == nil && !info.IsDir()
}

func cloneAny(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, value := range x {
			out[k] = cloneAny(value)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(x))
		for k, value := range x {
			out[k] = value
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, value := range x {
			out[i] = cloneAny(value)
		}
		return out
	case []string:
		return append([]string(nil), x...)
	default:
		return v
	}
}

func asStringMap(v any) map[string]any {
	switch x := v.(type) {
	case map[string]any:
		return x
	case map[string]string:
		out := make(map[string]any, len(x))
		for k, value := range x {
			out[k] = value
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, value := range x {
			if s, ok := k.(string); ok {
				out[s] = value
			}
		}
		return out
	default:
		return nil
	}
}

func stringSlice(v any) []string {
	switch x := v.(type) {
	case []string:
		return append([]string(nil), x...)
	case []any:
		out := make([]string, 0, len(x))
		for _, value := range x {
			if s, ok := stringValue(value); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	default:
		return nil
	}
}

func optionsMap(v any) map[string]string {
	raw := asStringMap(v)
	if raw == nil {
		return nil
	}
	out := map[string]string{}
	for key, value := range raw {
		if !valueTruthy(value) {
			continue
		}
		if b, ok := value.(bool); ok && b {
			out[key] = ""
			continue
		}
		out[key] = fmt.Sprint(value)
	}
	return out
}

func compilePublicKeyLine(line string) ssh.PublicKey {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil
	}
	return key
}
