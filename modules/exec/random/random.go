// Package random implements Salt-compatible randomness helpers using only
// the Go standard library.
//
// Reference: saltstack/salt/modules/mod_random.py @ pinned revision
// (__virtualname__ = "mod_random"). Ported subset: hash, str_encode,
// get_str, rand_int.
package random

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

func hashBuilder(algorithm string) (hash.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "md5":
		return md5.New(), nil
	case "sha1":
		return sha1.New(), nil
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("invalid hash algorithm %q", algorithm)
	}
}

type HashArgs struct {
	Value     string `statekit:"required"`
	Algorithm string `statekit:"name=algorithm"`
}

type hashFunc struct{}

func (hashFunc) Name() string { return "mod_random.hash" }
func (hashFunc) Args() any    { return HashArgs{} }
func (hashFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*HashArgs)
	algorithm := a.Algorithm
	if algorithm == "" {
		algorithm = "sha512"
	}
	h, err := hashBuilder(algorithm)
	if err != nil {
		return nil, err
	}
	h.Write([]byte(a.Value))
	return hex.EncodeToString(h.Sum(nil)), nil
}

type StrEncodeArgs struct {
	Value   string `statekit:"required"`
	Encoder string `statekit:"name=encoder"`
}

type strEncodeFunc struct{}

func (strEncodeFunc) Name() string { return "mod_random.str_encode" }
func (strEncodeFunc) Args() any    { return StrEncodeArgs{} }
func (strEncodeFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*StrEncodeArgs)
	switch strings.ToLower(a.Encoder) {
	case "", "base64":
		return base64.StdEncoding.EncodeToString([]byte(a.Value)), nil
	default:
		return nil, fmt.Errorf("invalid encoder %q", a.Encoder)
	}
}

type GetStrArgs struct {
	Length      int    `statekit:"name=length"`
	Chars       string `statekit:"name=chars"`
	Lowercase   bool   `statekit:"name=lowercase"`
	Uppercase   bool   `statekit:"name=uppercase"`
	Digits      bool   `statekit:"name=digits"`
	Punctuation bool   `statekit:"name=punctuation"`
	Whitespace  bool   `statekit:"name=whitespace"`
	Printable   bool   `statekit:"name=printable"`
}

type getStrFunc struct{}

const (
	lowerChars   = "abcdefghijklmnopqrstuvwxyz"
	upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars   = "0123456789"
	punctChars   = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
	whitespaceCh = " \t"
	printableAdd = "`~\\\"'"
)

func (getStrFunc) Name() string { return "mod_random.get_str" }
func (getStrFunc) Args() any    { return GetStrArgs{} }
func (getStrFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*GetStrArgs)
	length := a.Length
	if length <= 0 {
		length = 20
	}
	alphabet := a.Chars
	if alphabet == "" {
		var b strings.Builder
		if a.Printable || a.Lowercase {
			b.WriteString(lowerChars)
		}
		if a.Printable || a.Uppercase {
			b.WriteString(upperChars)
		}
		if a.Printable || a.Digits {
			b.WriteString(digitChars)
		}
		if a.Printable || a.Punctuation {
			b.WriteString(punctChars)
		}
		if a.Printable {
			b.WriteString(printableAdd)
		}
		if a.Whitespace {
			b.WriteString(whitespaceCh)
		}
		if b.Len() == 0 {
			b.WriteString(lowerChars + upperChars + digitChars + punctChars)
		}
		alphabet = b.String()
	}

	out := make([]byte, length)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}
		out[i] = alphabet[idx.Int64()]
	}
	return string(out), nil
}

type RandIntArgs struct {
	Start int `statekit:"name=start"`
	End   int `statekit:"name=end"`
}

type randIntFunc struct{}

func (randIntFunc) Name() string { return "mod_random.rand_int" }
func (randIntFunc) Args() any    { return RandIntArgs{} }
func (randIntFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*RandIntArgs)
	start, end := a.Start, a.End
	if start == 0 && end == 0 {
		start, end = 1, 10
	}
	if end < start {
		return nil, fmt.Errorf("end %d is less than start %d", end, start)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(end-start+1)))
	if err != nil {
		return nil, err
	}
	return int(start + int(n.Int64())), nil
}

// Register installs all random-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{hashFunc{}, strEncodeFunc{}, getStrFunc{}, randIntFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
