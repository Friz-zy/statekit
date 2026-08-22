package random

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func newRT() *runtime.Runtime {
	return &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: process.NewRunner(),
		FS:     runtime.NewMemoryFS(),
	}
}

func TestHashDeterministic(t *testing.T) {
	first, err := (hashFunc{}).Execute(context.Background(), newRT(), &HashArgs{Value: "salt", Algorithm: "sha256"})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	second, _ := hashFunc{}.Execute(context.Background(), newRT(), &HashArgs{Value: "salt", Algorithm: "sha256"})
	if first != second || len(first.(string)) != 64 {
		t.Fatalf("sha256 hash wrong: %v", first)
	}
	if _, err := (hashFunc{}).Execute(context.Background(), newRT(), &HashArgs{Value: "x", Algorithm: "md6"}); err == nil {
		t.Fatal("unknown algorithm must fail")
	}
}

func TestStrEncodeBase64(t *testing.T) {
	value, err := (strEncodeFunc{}).Execute(context.Background(), newRT(), &StrEncodeArgs{Value: "abc"})
	if err != nil || value != "YWJj" {
		t.Fatalf("str_encode = %v, %v", value, err)
	}
}

func TestGetStrLengthAndCharset(t *testing.T) {
	value, err := (getStrFunc{}).Execute(context.Background(), newRT(), &GetStrArgs{
		Length: 32, Lowercase: true, Uppercase: true, Digits: true,
	})
	if err != nil {
		t.Fatalf("get_str: %v", err)
	}
	out := value.(string)
	if len(out) != 32 {
		t.Fatalf("length = %d", len(out))
	}
	for _, ch := range out {
		switch {
		case strings.ContainsRune(lowerChars, ch):
		case strings.ContainsRune(upperChars, ch):
		case strings.ContainsRune(digitChars, ch):
		default:
			t.Fatalf("character %q outside requested charset", ch)
		}
	}
}

func TestRandIntRange(t *testing.T) {
	seen := map[int]bool{}
	for range [50]int{} {
		value, err := (randIntFunc{}).Execute(context.Background(), newRT(), &RandIntArgs{Start: 3, End: 7})
		if err != nil {
			t.Fatalf("rand_int: %v", err)
		}
		n := value.(int)
		if n < 3 || n > 7 {
			t.Fatalf("out of range: %d", n)
		}
		seen[n] = true
	}
	if len(seen) < 2 {
		t.Fatalf("suspiciously narrow distribution: %v", keys(seen))
	}
	if _, err := (randIntFunc{}).Execute(context.Background(), newRT(), &RandIntArgs{Start: 9, End: 2}); err == nil {
		t.Fatal("end<start must fail")
	}
}

func keys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
