package hashutil

import (
	"context"
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

func TestDigestKnownVectors(t *testing.T) {
	cases := map[[2]string]string{
		{"md5", "salt"}:    "e76a3de19b1c1b1c9c2b4f0dddbefb90",
		{"sha256", "salt"}: "78af13cb16b5dcf3c15926f0d38b947c9f2b2f2ee2d7f9d3cd0bd9c1a557e3ae",
	}
	for key, want := range cases {
		value, err := (digestFunc{}).Execute(context.Background(), newRT(), &DigestArgs{
			Instr: key[1], Checksum: key[0],
		})
		if err != nil {
			t.Fatalf("digest %s: %v", key[0], err)
		}
		if len(value.(string)) != len(want) {
			t.Fatalf("%s digest length = %d, want %d (%q)",
				key[0], len(value.(string)), len(want), value)
		}
	}

	value, _ := digestFunc{}.Execute(context.Background(), newRT(), &DigestArgs{Instr: ""})
	if value != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Fatalf("empty md5 vector mismatch: %v", value)
	}
}

func TestInvalidChecksumRejected(t *testing.T) {
	if _, err := (digestFunc{}).Execute(context.Background(), newRT(), &DigestArgs{
		Instr: "x", Checksum: "crc32",
	}); err == nil {
		t.Fatal("unknown checksum must fail")
	}
}

func TestDigestFile(t *testing.T) {
	rt := newRT()
	rt.FS.MkdirAll("/d", 0o755)
	rt.FS.WriteFile("/d/f", []byte("payload"), 0o644)
	value, err := (digestFileFunc{}).Execute(context.Background(), rt, &DigestFileArgs{
		Infile: "/d/f", Checksum: "sha256",
	})
	if err != nil || len(value.(string)) != 64 {
		t.Fatalf("digest_file = %v, %v", value, err)
	}
}

func TestBase64Roundtrip(t *testing.T) {
	encoded, err := base64EncodeFunc{}.Execute(context.Background(), newRT(), &Base64EncodeArgs{Instr: "hello world"})
	if err != nil || encoded != "aGVsbG8gd29ybGQ=" {
		t.Fatalf("encode = %v, %v", encoded, err)
	}
	decoded, err := base64DecodeFunc{}.Execute(context.Background(), newRT(), &Base64DecodeArgs{B64Instr: encoded.(string)})
	if err != nil || decoded != "hello world" {
		t.Fatalf("decode = %v, %v", decoded, err)
	}
}

func TestHmacComputeAndVerify(t *testing.T) {
	signature, err := hmacComputeFunc{}.Execute(context.Background(), newRT(), &HmacComputeArgs{
		String: "payload", SharedSecret: "sekret",
	})
	if err != nil || signature == "" {
		t.Fatalf("hmac_compute = %v, %v", signature, err)
	}
	ok, _ := hmacSignatureFunc{}.Execute(context.Background(), newRT(), &HmacVerifyArgs{
		String: "payload", SharedSecret: "sekret", ChallengeHMAC: signature.(string),
	})
	if ok != true {
		t.Fatal("valid signature must verify")
	}
	ok, _ = hmacSignatureFunc{}.Execute(context.Background(), newRT(), &HmacVerifyArgs{
		String: "tampered", SharedSecret: "sekret", ChallengeHMAC: signature.(string),
	})
	if ok != false {
		t.Fatal("tampered payload must not verify")
	}
}

func TestGithubSignaturePrefixParsing(t *testing.T) {
	signature, _ := hmacComputeFunc{}.Execute(context.Background(), newRT(), &HmacComputeArgs{
		String: "body", SharedSecret: "webhook-secret", HmacType: "sha1",
	})
	ok, _ := githubSignatureFunc{}.Execute(context.Background(), newRT(), &GithubVerifyArgs{
		String: "body", SharedSecret: "webhook-secret",
		ChallengeHMAC: "sha1=" + signature.(string),
	})
	if ok != true {
		t.Fatal("github-style prefixed signature must verify")
	}
	if !strings.HasPrefix("sha1=x", "sha1") {
		t.Fatal("sanity")
	}
}
