// Package hashutil implements Salt-compatible hashing helpers using only
// the Go standard library.
//
// Reference: saltstack/salt/modules/hashutil.py @ pinned revision.
package hashutil

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

func newHash(checksum string) (hash.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(checksum)) {
	case "md5":
		return md5.New(), nil
	case "sha1":
		return sha1.New(), nil
	case "sha224":
		return sha256.New224(), nil
	case "sha256":
		return sha256.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("invalid checksum type %q", checksum)
	}
}

type DigestArgs struct {
	Instr    string `statekit:"required"`
	Checksum string `statekit:"name=checksum"`
}

type digestFunc struct{}

func (digestFunc) Name() string { return "hashutil.digest" }
func (digestFunc) Args() any    { return DigestArgs{} }
func (digestFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*DigestArgs)
	checksum := a.Checksum
	if checksum == "" {
		checksum = "md5"
	}
	h, err := newHash(checksum)
	if err != nil {
		return nil, err
	}
	h.Write([]byte(a.Instr))
	return hex.EncodeToString(h.Sum(nil)), nil
}

type DigestFileArgs struct {
	Infile   string `statekit:"required,name=infile"`
	Checksum string `statekit:"name=checksum"`
}

type digestFileFunc struct{}

func (digestFileFunc) Name() string { return "hashutil.digest_file" }
func (digestFileFunc) Args() any    { return DigestFileArgs{} }
func (digestFileFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DigestFileArgs)
	checksum := a.Checksum
	if checksum == "" {
		checksum = "md5"
	}
	h, err := newHash(checksum)
	if err != nil {
		return nil, err
	}
	data, err := rt.FS.ReadFile(a.Infile)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

type Base64EncodeArgs struct {
	Instr string `statekit:"required"`
}

type base64EncodeFunc struct{}

func (base64EncodeFunc) Name() string { return "hashutil.base64_encodestring" }
func (base64EncodeFunc) Args() any    { return Base64EncodeArgs{} }
func (base64EncodeFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*Base64EncodeArgs)
	return base64.StdEncoding.EncodeToString([]byte(a.Instr)), nil
}

type Base64DecodeArgs struct {
	B64Instr string `statekit:"required,name=b64instr"`
}

type base64DecodeFunc struct{}

func (base64DecodeFunc) Name() string { return "hashutil.base64_decodestring" }
func (base64DecodeFunc) Args() any    { return Base64DecodeArgs{} }
func (base64DecodeFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*Base64DecodeArgs)
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(a.B64Instr))
	if err != nil {
		return nil, err
	}
	return string(decoded), nil
}

// macBuilder resolves an HMAC hash constructor by name.
func macBuilder(macType string) (func() hash.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(macType)) {
	case "", "sha256":
		return sha256.New, nil
	case "md5":
		return md5.New, nil
	case "sha1":
		return sha1.New, nil
	case "sha224":
		return sha256.New224, nil
	case "sha384":
		return sha512.New384, nil
	case "sha512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("invalid hmac type %q", macType)
	}
}

type HmacComputeArgs struct {
	String       string `statekit:"required"`
	SharedSecret string `statekit:"required,name=shared_secret"`
	HmacType     string `statekit:"name=hmac_type"`
}

type hmacComputeFunc struct{}

func (hmacComputeFunc) Name() string { return "hashutil.hmac_compute" }
func (hmacComputeFunc) Args() any    { return HmacComputeArgs{} }
func (hmacComputeFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*HmacComputeArgs)
	builder, err := macBuilder(a.HmacType)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(builder, []byte(a.SharedSecret))
	io.WriteString(mac, a.String)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

type HmacVerifyArgs struct {
	String        string `statekit:"required"`
	SharedSecret  string `statekit:"required,name=shared_secret"`
	ChallengeHMAC string `statekit:"required,name=challenge_hmac"`
	HmacType      string `statekit:"name=hmac_type"`
}

type hmacSignatureFunc struct{}

func (hmacSignatureFunc) Name() string { return "hashutil.hmac_signature" }
func (hmacSignatureFunc) Args() any    { return HmacVerifyArgs{} }
func (hmacSignatureFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*HmacVerifyArgs)
	computed, err := hmacComputeFunc{}.Execute(ctx, rt, &HmacComputeArgs{
		String: a.String, SharedSecret: a.SharedSecret, HmacType: a.HmacType,
	})
	if err != nil {
		return false, nil
	}
	return hmac.Equal([]byte(computed.(string)), []byte(a.ChallengeHMAC)), nil
}

type GithubVerifyArgs struct {
	String        string `statekit:"required"`
	SharedSecret  string `statekit:"required,name=shared_secret"`
	ChallengeHMAC string `statekit:"required,name=challenge_hmac"`
}

type githubSignatureFunc struct{}

// github_signature verifies X-Hub-Signature style values which prefix the
// digest with the algorithm name ("sha1=...").
func (githubSignatureFunc) Name() string { return "hashutil.github_signature" }
func (githubSignatureFunc) Args() any    { return GithubVerifyArgs{} }
func (githubSignatureFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GithubVerifyArgs)
	algo := "sha1"
	challenge := a.ChallengeHMAC
	if idx := strings.IndexByte(challenge, '='); idx > 0 {
		algo = strings.ToLower(challenge[:idx])
		challenge = challenge[idx+1:]
	}
	computed, err := hmacComputeFunc{}.Execute(ctx, rt, &HmacComputeArgs{
		String: a.String, SharedSecret: a.SharedSecret, HmacType: algo,
	})
	if err != nil {
		return false, nil
	}
	return hmac.Equal([]byte(computed.(string)), []byte(challenge)), nil
}

// Register installs all hashutil-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		digestFunc{}, digestFileFunc{}, base64EncodeFunc{}, base64DecodeFunc{},
		hmacComputeFunc{}, hmacSignatureFunc{}, githubSignatureFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
