package shadow

// Pure-Go ports of the crypt(3C) hash families solaris_shadow's
// gen_password reaches through salt.utils.pycrypto.gen_hash: the
// Drepper sha256/sha512-crypt constructions, Poul-Henning Kamp's
// md5-crypt, and the crypt_blowfish $2b$ variant built on the
// golang.org/x/crypto/blowfish public API. The traditional DES "crypt"
// algorithm needs a salted expansion permutation that neither the Go
// standard library nor the pinned x/crypto module exposes, so it stays
// unported (documented boundary; Solaris defaults to sha512). Output
// vectors are pinned in the tests from
// tests/pytests/unit/utils/test_pycrypto.py and Drepper's crypt
// reference examples.

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/blowfish"
)

// cryptB64t is the crypt(3) base64 alphabet shared by the md5 and sha
// constructions.
const cryptB64t = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// bcryptB64t is the base64 alphabet of the bcrypt family (digits sort
// last, unlike cryptB64t).
const bcryptB64t = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// ResourceLimitError is returned before crypt work starts when an input would
// exceed one of the finite work or input ceilings below. Its message contains
// only the resource name and numeric bounds; password material is never
// included.
type ResourceLimitError struct {
	Resource string
	Value    int
	Limit    int
}

func (e *ResourceLimitError) Error() string {
	return fmt.Sprintf("shadow: %s %d exceeds maximum %d", e.Resource, e.Value, e.Limit)
}

// crypt consumes byte strings. Four KiB is a deliberately finite input
// ceiling that keeps the repeated digest inputs bounded without changing the
// normal crypt password vectors.
const sunCryptPasswordMaxBytes = 4 << 10

// sunGenHash ports salt.utils.pycrypto.gen_hash for the algorithms the
// pure-Go substrate covers. An empty cryptSalt generates a random salt
// of the algorithm-appropriate shape, matching crypt.crypt's behavior
// of deriving one from the method ident.
func sunGenHash(password, cryptSalt, algorithm string) (string, error) {
	return sunGenHashContext(context.Background(), password, cryptSalt, algorithm)
}

func sunGenHashContext(ctx context.Context, password, cryptSalt, algorithm string) (string, error) {
	ctx = sunCryptContext(ctx)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := sunValidateCryptPassword(password); err != nil {
		return "", err
	}
	switch algorithm {
	case "sha512":
		return sunSHACryptContext(ctx, password, cryptSalt, "$6$", 64, sha512.New, sunSHA512Permutation)
	case "sha256":
		return sunSHACryptContext(ctx, password, cryptSalt, "$5$", 32, sha256.New, sunSHA256Permutation)
	case "md5":
		return sunMD5CryptContext(ctx, password, cryptSalt)
	case "blowfish":
		return sunBlowfishCryptContext(ctx, password, cryptSalt)
	default:
		return "", fmt.Errorf(
			"Cannot hash using '%s' hash algorithm. Natively supported algorithms are: ['sha512', 'sha256', 'blowfish', 'md5'].",
			algorithm)
	}
}

// cryptTo64 emits n base64 characters from the 24-bit big-endian value,
// least significant six bits first (crypt's b64_from_24bit).
func cryptTo64(b2, b1, b0 byte, n int) string {
	w := uint32(b2)<<16 | uint32(b1)<<8 | uint32(b0)
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteByte(cryptB64t[w&0x3f])
		w >>= 6
	}
	return sb.String()
}

// sunSHAPermutation reproduces glibc's digest-to-output ordering: the
// digest bytes are consumed as three interleaved streams (offsets 0,
// groups, 2*groups) and group k is rotated left by (k*rotMul) mod 3.
// sha512-crypt rotates by k, sha256-crypt by 2k (both derived against
// the glibc reference vectors pinned in the tests).
func sunSHAPermutation(groups, rotMul int) [][3]int {
	out := make([][3]int, 0, groups)
	for k := 0; k < groups; k++ {
		triple := [3]int{k, groups + k, 2*groups + k}
		for r := 0; r < (k*rotMul)%3; r++ {
			triple = [3]int{triple[1], triple[2], triple[0]}
		}
		out = append(out, triple)
	}
	return out
}

var sunSHA512Permutation = sunSHAPermutation(21, 1)

var sunSHA256Permutation = sunSHAPermutation(10, 2)

const sunSHARoundsDefault = 5000
const sunSHARoundsMin = 1000
const sunSHARoundsMax = 1_000_000

// sunSHACrypt implements the Drepper sha-crypt construction shared by
// $5$ and $6$: parameterized by digest constructor and size and the
// output permutation. The tail encodes the final digest bytes
// (byte 63 alone for sha512; bytes 31 and 30 for sha256, both derived
// against the glibc reference vectors).
func sunSHACrypt(password, cryptSalt, prefix string, size int, newHash func() hash.Hash, perm [][3]int) (string, error) {
	return sunSHACryptContext(context.Background(), password, cryptSalt, prefix, size, newHash, perm)
}

func sunSHACryptContext(ctx context.Context, password, cryptSalt, prefix string, size int, newHash func() hash.Hash, perm [][3]int) (string, error) {
	ctx = sunCryptContext(ctx)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := sunValidateCryptPassword(password); err != nil {
		return "", err
	}
	rounds := sunSHARoundsDefault
	roundsExplicit := false
	salt := cryptSalt
	if rest, ok := strings.CutPrefix(salt, "rounds="); ok {
		digits, delim, found := strings.Cut(rest, "$")
		if !found || digits == "" {
			return "", fmt.Errorf("sha-crypt: invalid rounds %q", digits)
		}
		parsed, err := strconv.Atoi(digits)
		if err != nil {
			if sunNumericRangeError(err) {
				return "", sunResourceLimitError("sha rounds", sunSHARoundsMax+1, sunSHARoundsMax)
			}
			return "", fmt.Errorf("sha-crypt: invalid rounds %q", digits)
		}
		if parsed > sunSHARoundsMax {
			return "", sunResourceLimitError("sha rounds", parsed, sunSHARoundsMax)
		}
		rounds = parsed
		roundsExplicit = true
		salt = delim
	}
	if rounds < sunSHARoundsMin {
		rounds = sunSHARoundsMin
	}
	if len(salt) > 16 {
		salt = salt[:16]
	}
	if salt == "" {
		generated, err := sunRandomString(cryptB64t, 16)
		if err != nil {
			return "", err
		}
		salt = generated
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	plen, slen := len(password), len(salt)

	// Alternate digest B = H(password || salt || password).
	bDigest := newHash()
	bDigest.Write([]byte(password))
	bDigest.Write([]byte(salt))
	bDigest.Write([]byte(password))
	b := bDigest.Sum(nil)

	// Digest A: password, salt, then password-length bytes of B and the
	// length bit walk.
	a := newHash()
	a.Write([]byte(password))
	a.Write([]byte(salt))
	remaining := plen
	for ; remaining > size; remaining -= size {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		a.Write(b)
	}
	a.Write(b[:min(remaining, size)])
	for cnt := plen; cnt > 0; cnt >>= 1 {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if cnt&1 != 0 {
			a.Write(b)
		} else {
			a.Write([]byte(password))
		}
	}
	sum := a.Sum(nil)

	// P = password-length bytes of DP = H(password repeated plen times).
	dp := newHash()
	for i := 0; i < plen; i++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		dp.Write([]byte(password))
	}
	p := sunRepeatTo(dp.Sum(nil), plen)

	// S = salt-length bytes of DS = H(salt repeated 16+sum[0] times).
	ds := newHash()
	for i := 0; i < 16+int(sum[0]); i++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		ds.Write([]byte(salt))
	}
	s := sunRepeatTo(ds.Sum(nil), slen)

	for cnt := 0; cnt < rounds; cnt++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		c := newHash()
		if cnt&1 != 0 {
			c.Write(p)
		} else {
			c.Write(sum)
		}
		if cnt%3 != 0 {
			c.Write(s)
		}
		if cnt%7 != 0 {
			c.Write(p)
		}
		if cnt&1 != 0 {
			c.Write(sum)
		} else {
			c.Write(p)
		}
		sum = c.Sum(nil)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.WriteString(prefix)
	if roundsExplicit {
		fmt.Fprintf(&sb, "rounds=%d$", rounds)
	}
	sb.WriteString(salt)
	sb.WriteByte('$')
	for _, triple := range perm {
		sb.WriteString(cryptTo64(sum[triple[0]], sum[triple[1]], sum[triple[2]], 4))
	}
	if size == 64 {
		sb.WriteString(cryptTo64(0, 0, sum[63], 2))
	} else {
		sb.WriteString(cryptTo64(0, sum[31], sum[30], 3))
	}
	return sb.String(), nil
}

func sunRepeatTo(digest []byte, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, digest...)
	}
	return out[:n]
}

// sunMD5Crypt implements Poul-Henning Kamp's $1$ construction.
func sunMD5Crypt(password, cryptSalt string) (string, error) {
	return sunMD5CryptContext(context.Background(), password, cryptSalt)
}

const sunMD5Rounds = 1000

func sunMD5CryptContext(ctx context.Context, password, cryptSalt string) (string, error) {
	ctx = sunCryptContext(ctx)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := sunValidateCryptPassword(password); err != nil {
		return "", err
	}
	salt := cryptSalt
	if len(salt) > 8 {
		salt = salt[:8]
	}
	if salt == "" {
		generated, err := sunRandomString(cryptB64t, 8)
		if err != nil {
			return "", err
		}
		salt = generated
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	a := md5.New()
	a.Write([]byte(password))
	a.Write([]byte("$1$"))
	a.Write([]byte(salt))

	b := md5.Sum(append(append([]byte(password), []byte(salt)...), []byte(password)...))
	for pl := len(password); pl > 0; pl -= 16 {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if pl < 16 {
			a.Write(b[:pl])
		} else {
			a.Write(b[:])
		}
	}
	// PHK's "something really weird" loop runs after memset(final, 0):
	// a set bit feeds one ZERO byte, a clear bit the first password
	// byte.
	for i := len(password); i != 0; i >>= 1 {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if i&1 != 0 {
			a.Write([]byte{0})
		} else {
			a.Write([]byte{password[0]})
		}
	}
	sum := a.Sum(nil)

	for i := 0; i < sunMD5Rounds; i++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		c := md5.New()
		if i&1 != 0 {
			c.Write([]byte(password))
		} else {
			c.Write(sum)
		}
		if i%3 != 0 {
			c.Write([]byte(salt))
		}
		if i%7 != 0 {
			c.Write([]byte(password))
		}
		if i&1 != 0 {
			c.Write(sum)
		} else {
			c.Write([]byte(password))
		}
		sum = c.Sum(nil)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	triples := [][3]int{{0, 6, 12}, {1, 7, 13}, {2, 8, 14}, {3, 9, 15}, {4, 10, 5}}
	var sb strings.Builder
	sb.WriteString("$1$")
	sb.WriteString(salt)
	sb.WriteByte('$')
	for _, triple := range triples {
		sb.WriteString(cryptTo64(sum[triple[0]], sum[triple[1]], sum[triple[2]], 4))
	}
	sb.WriteString(cryptTo64(0, 0, sum[11], 2))
	return sb.String(), nil
}

// sunBlowfishCrypt implements the crypt_blowfish $2b$ hash over the
// public x/crypto/blowfish API: the salted "expensive key schedule"
// with the trailing NUL bug-compatibility byte, 64 ECB passes over the
// OrpheanBeholderScryDoubt ciphertext, and the bcrypt base64 encoding
// of its first 23 bytes.
func sunBlowfishCrypt(password, cryptSalt string) (string, error) {
	return sunBlowfishCryptContext(context.Background(), password, cryptSalt)
}

const (
	sunBcryptCostMin       = 4
	sunBcryptCostDefault   = 10
	sunBcryptCostMax       = 16
	sunBcryptIterationsMax = uint64(1) << sunBcryptCostMax
	sunBcryptSaltBytes     = 16
	sunBcryptSaltChars     = 22
)

func sunBlowfishCryptContext(ctx context.Context, password, cryptSalt string) (string, error) {
	ctx = sunCryptContext(ctx)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := sunValidateCryptPassword(password); err != nil {
		return "", err
	}
	cost := sunBcryptCostDefault
	salt := cryptSalt
	if head, rest, found := strings.Cut(cryptSalt, "$"); found && head != "" {
		parsed, err := strconv.Atoi(head)
		if err != nil {
			if sunNumericRangeError(err) {
				return "", sunResourceLimitError("bcrypt cost", sunBcryptCostMax+1, sunBcryptCostMax)
			}
			return "", fmt.Errorf("blowfish: invalid cost %q", head)
		}
		cost = parsed
		salt = rest
	}
	if cost < sunBcryptCostMin {
		return "", fmt.Errorf("blowfish: cost %d out of range %d..%d", cost, sunBcryptCostMin, sunBcryptCostMax)
	}
	if cost > sunBcryptCostMax {
		return "", sunResourceLimitError("bcrypt cost", cost, sunBcryptCostMax)
	}
	if salt == "" {
		generated, err := sunRandomString(bcryptB64t, 22)
		if err != nil {
			return "", err
		}
		salt = generated
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	csalt, err := bcryptB64Decode(salt)
	if err != nil {
		return "", err
	}
	// crypt(3) echoes the canonical encoding of the decoded 16-byte
	// salt: a non-canonical final input character (its low four bits
	// fall outside the 128 salt bits) is re-encoded from the data,
	// e.g. "goodsaltgoodsaltgoodsa" prints as "...goodsO".
	salt = bcryptB64Encode(csalt)

	ckey := append(append([]byte(nil), []byte(password)...), 0)
	c, err := blowfish.NewSaltedCipher(ckey, csalt)
	if err != nil {
		return "", err
	}
	rounds := uint64(1) << uint(cost)
	if rounds > sunBcryptIterationsMax {
		return "", sunResourceLimitError("bcrypt iterations", int(rounds), int(sunBcryptIterationsMax))
	}
	for i := uint64(0); i < rounds; i++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		blowfish.ExpandKey(ckey, c)
		blowfish.ExpandKey(csalt, c)
	}
	data := []byte("OrpheanBeholderScryDoubt")
	for i := 0; i < 24; i += 8 {
		for j := 0; j < 64; j++ {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			c.Encrypt(data[i:i+8], data[i:i+8])
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "$2b$%02d$%s%s", cost, salt, bcryptB64Encode(data[:23]))
	return sb.String(), nil
}

func bcryptB64Encode(src []byte) string {
	var sb strings.Builder
	var buf uint32
	var bits uint
	for _, b := range src {
		buf = buf<<8 | uint32(b)
		bits += 8
		for bits >= 6 {
			bits -= 6
			sb.WriteByte(bcryptB64t[(buf>>bits)&0x3f])
		}
	}
	if bits > 0 {
		sb.WriteByte(bcryptB64t[(buf<<(6-bits))&0x3f])
	}
	return sb.String()
}

func bcryptB64Decode(s string) ([]byte, error) {
	if len(s) != sunBcryptSaltChars {
		return nil, fmt.Errorf("blowfish: invalid salt length %d, want %d", len(s), sunBcryptSaltChars)
	}
	var out []byte
	var buf uint32
	var bits uint
	for i := 0; i < len(s); i++ {
		idx := strings.IndexByte(bcryptB64t, s[i])
		if idx < 0 {
			return nil, fmt.Errorf("blowfish: invalid salt character %q", s[i])
		}
		buf = buf<<6 | uint32(idx)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>bits))
		}
	}
	if len(out) != sunBcryptSaltBytes {
		return nil, fmt.Errorf("blowfish: decoded salt length %d, want %d", len(out), sunBcryptSaltBytes)
	}
	return out, nil
}

func sunCryptContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func sunValidateCryptPassword(password string) error {
	if len(password) > sunCryptPasswordMaxBytes {
		return sunResourceLimitError("password length", len(password), sunCryptPasswordMaxBytes)
	}
	return nil
}

func sunResourceLimitError(resource string, value, limit int) error {
	return &ResourceLimitError{Resource: resource, Value: value, Limit: limit}
}

func sunNumericRangeError(err error) bool {
	numErr, ok := err.(*strconv.NumError)
	return ok && numErr.Err == strconv.ErrRange
}

// sunRandomString draws n alphabet characters from crypto/rand.
func sunRandomString(alphabet string, n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range raw {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out), nil
}
