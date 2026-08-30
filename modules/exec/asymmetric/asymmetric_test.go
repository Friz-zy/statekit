package asymmetric

// R5.4 tests: sign/verify roundtrips across RSA, ECDSA and Ed25519 mapped
// onto the source contracts of saltstack/salt/modules/asymmetric.py and
// salt/utils/asymmetric.py @ pinned revision. Keys are generated at test
// time with the Go standard library; no external crypto dependencies.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func asymRT(t *testing.T) *runtime.Runtime {
	t.Helper()
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	return &runtime.Runtime{
		Exec:    reg,
		States:  runtime.NewStateRegistry(),
		FS:      runtime.NewMemoryFS(),
		Runner:  nopRunner{},
		Options: runtime.RuntimeOptions{},
	}
}

type nopRunner struct{}

func (nopRunner) Run(_ context.Context, _ process.Command) process.CommandResult {
	return process.CommandResult{}
}

func mustASYM(t *testing.T, rt *runtime.Runtime, name string, args any) any {
	t.Helper()
	res, err := rt.Exec.Call(context.Background(), rt, name, args)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func pemEncode(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

func writeKey(t *testing.T, rt *runtime.Runtime, name, content string) string {
	t.Helper()
	path := "/" + name
	if err := rt.FS.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const sampleText = "statekit asymmetric roundtrip"

func TestSignVerifyRoundtripRSA(t *testing.T) {
	rt := asymRT(t)
	rsaKey, kerr := rsa.GenerateKey(rand.Reader, 2048)
	if kerr != nil {
		t.Fatal(kerr)
	}
	privPath := writeKey(t, rt, "rsa.key",
		pemEncode(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)))
	pubDER, perr := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if perr != nil {
		t.Fatal(perr)
	}
	pubPath := writeKey(t, rt, "rsa.pub", pemEncode(t, "PUBLIC KEY", pubDER))

	sig := mustASYM(t, rt, "asymmetric.sign", &signArgs{
		Privkey: strPtrAsym(privPath), Text: strPtrAsym(sampleText),
	}).(string)

	res := mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Pubkey: strPtrAsym(pubPath), Text: strPtrAsym(sampleText), Signature: sig,
	})
	v := res.(map[string]any)
	if v["res"] != true || v["message"] != "The signature is valid" {
		t.Fatalf("verify reply = %#v", v)
	}

	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Pubkey: strPtrAsym(pubPath), Text: strPtrAsym("tampered"), Signature: sig,
	})
	if res.(map[string]any)["res"] != false {
		t.Fatalf("tampered verify = %#v", res)
	}
}

func TestVerifyFixedSaltRSAPSSVector(t *testing.T) {
	rt := asymRT(t)
	if !strings.Contains(saltRSAPublicKey, "-----BEGIN") {
		t.Fatal("fixed public key is not PEM")
	}
	pub, err := loadPublicKey(rt, strPtrAsym(saltRSAPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(saltRSASignature, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	digest := sumOf([]byte("I am an important message"), crypto.SHA256)
	rsaPub := pub.(*rsa.PublicKey)
	if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, digest, sig, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
		t.Fatalf("direct Salt RSA-PSS vector verify = %v", err)
	}
	res := mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Pubkey:    strPtrAsym(saltRSAPublicKey),
		Text:      strPtrAsym("I am an important message"),
		Signature: saltRSASignature,
	})
	if res.(map[string]any)["res"] != true {
		t.Fatalf("Salt RSA-PSS vector verify = %#v", res)
	}

	bad := "K" + saltRSASignature[1:]
	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Pubkey:    strPtrAsym(saltRSAPublicKey),
		Text:      strPtrAsym("I am an important message"),
		Signature: bad,
	})
	if res.(map[string]any)["res"] != false {
		t.Fatalf("tampered Salt RSA-PSS vector verify = %#v", res)
	}
}

func TestFetchSigDeterministicSourceSelection(t *testing.T) {
	rt := asymRT(t)

	// '/' is a valid base64 alphabet character, not a path discriminator.
	sf, err := fetchSig(rt, "/w==")
	if err != nil || len(sf.raw) != 1 || sf.raw[0] != 0xff || sf.source != "inline" {
		t.Fatalf("leading-slash base64 = %#v, %v", sf, err)
	}

	if err := rt.FS.WriteFile("/w==", []byte("raw file signature"), 0o600); err != nil {
		t.Fatal(err)
	}
	sf, err = fetchSig(rt, "/w==")
	if err != nil || string(sf.raw) != "raw file signature" || sf.source != "/w==" {
		t.Fatalf("existing file precedence = %#v, %v", sf, err)
	}

	if _, err = fetchSig(rt, "/missing-signature"); err == nil ||
		err.Error() != signatureLoadError || strings.Contains(err.Error(), "/missing-signature") {
		t.Fatalf("missing signature error = %v", err)
	}
	if _, err = fetchSig(rt, "file:///missing-signature"); err == nil ||
		err.Error() != signatureFetchError || strings.Contains(err.Error(), "/missing-signature") {
		t.Fatalf("file signature error = %v", err)
	}
	if _, err = fetchSig(rt, "not a base64 signature"); err == nil || err.Error() != signatureLoadError {
		t.Fatalf("malformed signature error = %v", err)
	}

	oversized := make([]byte, maxSignatureBytes+1)
	if err := rt.FS.WriteFile("/oversized.sig", oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = fetchSig(rt, "/oversized.sig"); err == nil || err.Error() != signatureFetchError {
		t.Fatalf("bounded signature error = %v", err)
	}
}

type recordingAsymCacheFileFunc struct {
	result any
	paths  []string
}

func (f *recordingAsymCacheFileFunc) Name() string { return "cp.cache_file" }
func (f *recordingAsymCacheFileFunc) Args() any    { return struct{}{} }
func (f *recordingAsymCacheFileFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	if values, ok := args.(map[string]any); ok {
		if path, ok := values["path"].(string); ok {
			f.paths = append(f.paths, path)
		}
	}
	return f.result, nil
}

func TestFetchSigUsesSaltURLPathRulesAndDelegatesRemote(t *testing.T) {
	rt := asymRT(t)
	for _, path := range []string{"/path", "/relative.sig", "/absolute.sig", "/escaped%2f.sig", "/cached.sig"} {
		if err := rt.FS.WriteFile(path, []byte("raw signature"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cache := &recordingAsymCacheFileFunc{result: "/cached.sig"}
	if err := rt.Exec.Register(cache); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		ref  string
		want string
	}{
		{name: "file host", ref: "file://host/path", want: "/path"},
		{name: "file relative", ref: "file:relative.sig", want: "relative.sig"},
		{name: "file absolute", ref: "file:///absolute.sig", want: "/absolute.sig"},
		{name: "escaped separator remains filename data", ref: "file:///escaped%2f.sig", want: "/escaped%2f.sig"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sf, err := fetchSig(rt, tc.ref)
			if err != nil || string(sf.raw) != "raw signature" || sf.source != tc.want {
				t.Fatalf("fetchSig(%q) = %#v, %v", tc.ref, sf, err)
			}
		})
	}

	for _, ref := range []string{"https:/path", "https://host/path", "s3://bucket/object"} {
		sf, err := fetchSig(rt, ref)
		if err != nil || string(sf.raw) != "raw signature" {
			t.Fatalf("delegated fetchSig(%q) = %#v, %v", ref, sf, err)
		}
	}
	if len(cache.paths) != 3 || cache.paths[0] != "https:/path" || cache.paths[1] != "https://host/path" || cache.paths[2] != "s3://bucket/object" {
		t.Fatalf("cache_file paths = %#v", cache.paths)
	}

	if _, err := fetchSig(rt, "https://bad%zz/path"); err == nil || err.Error() != signatureLoadError || strings.Contains(err.Error(), "bad%zz") {
		t.Fatalf("malformed URL error = %v", err)
	}
	for _, ref := range []string{"file://bad%zz/path", "file:///bad%zz/path"} {
		if _, err := fetchSig(rt, ref); err == nil || err.Error() != signatureLoadError || strings.Contains(err.Error(), ref) {
			t.Fatalf("malformed file URL %q error = %v", ref, err)
		}
	}
	if len(cache.paths) != 3 {
		t.Fatalf("malformed URL unexpectedly delegated: %#v", cache.paths)
	}
}

func TestResolveRefPreservesEscapedFilePathAndSourcePrecedence(t *testing.T) {
	rt := asymRT(t)
	if err := rt.FS.WriteFile("/key%2fpart.pem", []byte("escaped-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := resolveRef(rt, strPtrAsym("file:///key%2fpart.pem"))
	if err != nil || string(data) != "escaped-key" {
		t.Fatalf("escaped key path = %q, %v", data, err)
	}

	// An existing bare path wins over treating the same value as inline data.
	if err := rt.FS.WriteFile("/inline-or-file", []byte("file-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err = resolveRef(rt, strPtrAsym("/inline-or-file"))
	if err != nil || string(data) != "file-key" {
		t.Fatalf("bare path precedence = %q, %v", data, err)
	}
}

type rejectingBoundedAsymFS struct {
	*runtime.MemoryFS
	plainReads   int
	boundedReads int
}

func (f *rejectingBoundedAsymFS) Stat(string) (fs.FileInfo, error) {
	return stubAsymFileInfo{mode: 0o600}, nil
}

func (f *rejectingBoundedAsymFS) ReadFile(string) ([]byte, error) {
	f.plainReads++
	return nil, errors.New("unbounded read was called")
}

func (f *rejectingBoundedAsymFS) ReadFileBounded(string, int64) ([]byte, error) {
	f.boundedReads++
	return nil, runtime.ErrReadLimit
}

func TestAsymmetricRejectsOversizedFileInputsWithoutUnboundedReads(t *testing.T) {
	fsys := &rejectingBoundedAsymFS{MemoryFS: runtime.NewMemoryFS()}
	rt := asymRT(t)
	rt.FS = fsys

	_, err := signFunc{}.Execute(context.Background(), rt, &signArgs{
		Privkey: strPtrAsym("/secret/private-key.pem"),
		Text:    strPtrAsym("small input"),
	})
	if err == nil || !errors.Is(err, runtime.ErrReadLimit) || strings.Contains(err.Error(), "private-key") {
		t.Fatalf("oversized key error = %v", err)
	}

	_, err = signFunc{}.Execute(context.Background(), rt, &signArgs{
		Privkey:  strPtrAsym("inline-key"),
		Filename: strPtrAsym("/secret/data.bin"),
	})
	if err == nil || !errors.Is(err, runtime.ErrReadLimit) || strings.Contains(err.Error(), "data.bin") {
		t.Fatalf("oversized signing data error = %v", err)
	}

	_, err = fetchSig(rt, "/secret/signature.bin")
	if err == nil || !errors.Is(err, runtime.ErrReadLimit) || strings.Contains(err.Error(), "signature.bin") {
		t.Fatalf("oversized signature error = %v", err)
	}
	if fsys.plainReads != 0 {
		t.Fatalf("unbounded reads = %d", fsys.plainReads)
	}
	if fsys.boundedReads != 3 {
		t.Fatalf("bounded reads = %d, want 3", fsys.boundedReads)
	}
}

func TestAsymmetricErrorsDoNotExposeSecretReferences(t *testing.T) {
	rt := asymRT(t)
	privatePath := "/secret/private-key.pem"
	publicPath := "/secret/public-key.pem"
	if err := rt.FS.MkdirAll("/secret", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile(privatePath, []byte("not a private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile(publicPath, []byte("not a public key"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := signFunc{}.Execute(context.Background(), rt, &signArgs{
		Privkey: strPtrAsym(privatePath), Text: strPtrAsym("data"),
	})
	if err == nil || err.Error() != privateKeyParseError.Error() || strings.Contains(err.Error(), privatePath) {
		t.Fatalf("private-key error = %v", err)
	}

	res, err := verifyFunc{}.Execute(context.Background(), rt, &verifyArgs{
		Pubkey: strPtrAsym(publicPath), Text: strPtrAsym("data"), Signature: []byte{0},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]any)["message"].(string); got != "Failed checking signature" || strings.Contains(got, publicPath) {
		t.Fatalf("public-key reply = %q", got)
	}

	_, err = signFunc{}.Execute(context.Background(), rt, &signArgs{
		Privkey: strPtrAsym("inline-key"), Filename: strPtrAsym("/secret/data.bin"),
	})
	if err == nil || err.Error() != dataReadError.Error() || strings.Contains(err.Error(), "/secret/data.bin") {
		t.Fatalf("data-read error = %v", err)
	}
}

func TestOSBoundedReadRejectsSymlinkAndFIFOWithoutBlocking(t *testing.T) {
	if err := os.MkdirAll(".gotmp", 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(".gotmp", "asym-os-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	fifo := filepath.Join(dir, "fifo")
	if err := os.WriteFile(target, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.ReadFileBounded(runtime.NewOSFileSystem(), link, 16); err == nil {
		t.Fatal("symlink was accepted by bounded reader")
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.ReadFileBounded(runtime.NewOSFileSystem(), fifo, 16); !errors.Is(err, runtime.ErrNonRegularFile) {
		t.Fatalf("FIFO error = %v", err)
	}
}

type stubAsymFileInfo struct{ mode fs.FileMode }

func (i stubAsymFileInfo) Name() string       { return "signature" }
func (i stubAsymFileInfo) Size() int64        { return 1 }
func (i stubAsymFileInfo) Mode() fs.FileMode  { return i.mode }
func (i stubAsymFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (i stubAsymFileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i stubAsymFileInfo) Sys() any           { return nil }

type nonRegularAsymFS struct {
	*runtime.MemoryFS
	info         fs.FileInfo
	boundedReads int
}

func (f *nonRegularAsymFS) Stat(string) (fs.FileInfo, error) { return f.info, nil }

func (f *nonRegularAsymFS) ReadFileBounded(string, int64) ([]byte, error) {
	f.boundedReads++
	return nil, errors.New("unexpected bounded signature read")
}

type asymCacheFileFunc struct{ result any }

func (asymCacheFileFunc) Name() string { return "cp.cache_file" }
func (asymCacheFileFunc) Args() any    { return struct{}{} }
func (f asymCacheFileFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return f.result, nil
}

func TestFetchSigRejectsNonRegularCandidatesWithoutReading(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode fs.FileMode
	}{
		{name: "fifo", mode: fs.ModeNamedPipe},
		{name: "device", mode: fs.ModeDevice},
		{name: "socket", mode: fs.ModeSocket},
		{name: "symlink", mode: fs.ModeSymlink},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := runtime.NewMemoryFS()
			fsys := &nonRegularAsymFS{
				MemoryFS: base,
				info:     stubAsymFileInfo{mode: tc.mode},
			}
			rt := asymRT(t)
			rt.FS = fsys
			if _, err := fetchSig(rt, "/w=="); err == nil || err.Error() != signatureFetchError {
				t.Fatalf("non-regular local signature error = %v", err)
			}
			if fsys.boundedReads != 0 {
				t.Fatalf("non-regular local candidate was read %d times", fsys.boundedReads)
			}

			if err := rt.Exec.Register(asymCacheFileFunc{result: "/cached.sig"}); err != nil {
				t.Fatal(err)
			}
			if _, err := fetchSig(rt, "https://example.invalid/signature"); err == nil || err.Error() != signatureFetchError {
				t.Fatalf("non-regular cached signature error = %v", err)
			}
			if fsys.boundedReads != 0 {
				t.Fatalf("non-regular cached candidate was read %d times", fsys.boundedReads)
			}
		})
	}
}

func TestDecodeSignatureTextMatchesSaltCanonicalBase64(t *testing.T) {
	canonical := base64.StdEncoding.EncodeToString([]byte{0x00, 0xff, 0x10})
	tests := []struct {
		name string
		text string
		want []byte
		ok   bool
	}{
		{name: "leading slash canonical", text: "/w==", want: []byte{0xff}, ok: true},
		{name: "lf within encoding", text: "/w\n==", want: []byte{0xff}, ok: true},
		{name: "multiple lf", text: "\n/w==\n", want: []byte{0xff}, ok: true},
		{name: "canonical roundtrip", text: canonical, want: []byte{0x00, 0xff, 0x10}, ok: true},
		{name: "cr rejected", text: "/w\r\n==", ok: false},
		{name: "space rejected", text: "/w ==", ok: false},
		{name: "tab rejected", text: "/w\t==", ok: false},
		{name: "leading space rejected", text: " /w==", ok: false},
		{name: "trailing space rejected", text: "/w== ", ok: false},
		{name: "bad pad bits rejected", text: "/x==", ok: false},
		{name: "bad padding rejected", text: "/w=", ok: false},
		{name: "extra padding rejected", text: "/w===", ok: false},
		{name: "unpadded rejected", text: "/w", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := decodeSignatureText([]byte(tc.text))
			if ok != tc.ok || (ok && string(got) != string(tc.want)) {
				t.Fatalf("decodeSignatureText(%q) = %x, %v; want %x, %v", tc.text, got, ok, tc.want, tc.ok)
			}
		})
	}
}

type deterministicAsymReader struct {
	seed    []byte
	counter uint64
	buffer  []byte
}

func (r *deterministicAsymReader) Read(out []byte) (int, error) {
	for len(r.buffer) < len(out) {
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], r.counter)
		input := make([]byte, 0, len(r.seed)+len(counter))
		input = append(input, r.seed...)
		input = append(input, counter[:]...)
		block := sha256.Sum256(input)
		r.buffer = append(r.buffer, block[:]...)
		r.counter++
	}
	copy(out, r.buffer[:len(out)])
	r.buffer = r.buffer[len(out):]
	return len(out), nil
}

func TestRSAPSSSupportsSaltDigestNames(t *testing.T) {
	key, err := rsa.GenerateKey(&deterministicAsymReader{seed: []byte("asymmetric-rsa-test-key")}, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := &privateKey{key: key, alg: "RSA"}
	message := []byte("Salt digest compatibility")
	digests := []string{
		"sha1", "sha224", "sha256", "sha384", "sha512",
		"sha3_224", "sha3_256", "sha3_384", "sha3_512",
		"sha512_224", "sha512_256",
	}
	for _, digest := range digests {
		t.Run(digest, func(t *testing.T) {
			sig, serr := signPrimitive(private, message, digest, false)
			if serr != nil {
				t.Fatal(serr)
			}
			valid, verr := verifyPrimitive(&key.PublicKey, sig, message, strings.ToUpper(digest), false)
			if verr != nil || !valid {
				t.Fatalf("verify %s = %v, %v", digest, valid, verr)
			}

			wrongDigest := "sha256"
			if digest == wrongDigest {
				wrongDigest = "sha1"
			}
			if valid, verr = verifyPrimitive(&key.PublicKey, sig, message, wrongDigest, false); verr != nil || valid {
				t.Fatalf("wrong digest %s = %v, %v", wrongDigest, valid, verr)
			}

			wrongKey, kerr := rsa.GenerateKey(&deterministicAsymReader{seed: []byte("wrong-rsa-test-key")}, 2048)
			if kerr != nil {
				t.Fatal(kerr)
			}
			if valid, verr = verifyPrimitive(&wrongKey.PublicKey, sig, message, digest, false); verr != nil || valid {
				t.Fatalf("wrong key = %v, %v", valid, verr)
			}
			badSig := append([]byte(nil), sig...)
			badSig[0] ^= 1
			if valid, verr = verifyPrimitive(&key.PublicKey, badSig, message, digest, false); verr != nil || valid {
				t.Fatalf("bad signature = %v, %v", valid, verr)
			}
		})
	}

	for _, digest := range []string{"", "SHA1", "SHA3_256", "sha3-256", "sm3"} {
		if _, err := digestHash(digest); digest == "sha3-256" || digest == "sm3" {
			if err == nil || err.Error() != "Unsupported digest algorithm '"+digest+"'" {
				t.Fatalf("unsupported digest %q = %v", digest, err)
			}
		} else if err != nil {
			t.Fatalf("supported digest %q = %v", digest, err)
		}
	}
}

func TestSignVerifyRoundtripECDSAAndEd25519(t *testing.T) {
	rt := asymRT(t)

	ecKey, kerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if kerr != nil {
		t.Fatal(kerr)
	}
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	ecPriv := writeKey(t, rt, "ec.key", pemEncode(t, "EC PRIVATE KEY", ecDER))
	ecPubDER, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	ecPub := writeKey(t, rt, "ec.pub", pemEncode(t, "PUBLIC KEY", ecPubDER))

	sig := mustASYM(t, rt, "asymmetric.sign", &signArgs{
		Privkey: strPtrAsym(ecPriv), Text: strPtrAsym(sampleText),
	}).(string)
	res := mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Pubkey: strPtrAsym(ecPub), Text: strPtrAsym(sampleText), Signature: sig,
	})
	if res.(map[string]any)["res"] != true {
		t.Fatalf("ecdsa verify = %#v", res)
	}

	edPub, edPriv, kerr2 := ed25519.GenerateKey(rand.Reader)
	if kerr2 != nil {
		t.Fatal(kerr2)
	}
	edDER, _ := x509.MarshalPKCS8PrivateKey(edPriv)
	edPrivPath := writeKey(t, rt, "ed.key", pemEncode(t, "PRIVATE KEY", edDER))
	edPubDER, _ := x509.MarshalPKIXPublicKey(edPub)
	edPubPath := writeKey(t, rt, "ed.pub", pemEncode(t, "PUBLIC KEY", edPubDER))

	sig = mustASYM(t, rt, "asymmetric.sign", &signArgs{
		Privkey: strPtrAsym(edPrivPath), Text: strPtrAsym(sampleText),
	}).(string)
	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Pubkey: strPtrAsym(edPubPath), Text: strPtrAsym(sampleText), Signature: sig,
	})
	if res.(map[string]any)["res"] != true {
		t.Fatalf("ed25519 verify = %#v", res)
	}
}

func TestSignFileInputWritesSignature(t *testing.T) {
	rt := asymRT(t)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edDER, _ := x509.MarshalPKCS8PrivateKey(edPriv)
	privPath := writeKey(t, rt, "ed.key", pemEncode(t, "PRIVATE KEY", edDER))
	pubDER, _ := x509.MarshalPKIXPublicKey(edPub)
	pubPath := writeKey(t, rt, "ed.pub", pemEncode(t, "PUBLIC KEY", pubDER))
	dataPath := "/data/blob"
	if err := rt.FS.MkdirAll("/data", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile(dataPath, []byte("file payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := mustASYM(t, rt, "asymmetric.sign", &signArgs{
		Privkey: strPtrAsym(privPath), Filename: strPtrAsym(dataPath),
		Path: strPtrAsym("/data/blob.sig"),
	})
	if res != "Signature written to '/data/blob.sig'" {
		t.Fatalf("write reply = %#v", res)
	}
	rawSig, rerr := runtime.ReadFileBounded(rt.FS, "/data/blob.sig", maxSignatureBytes)
	if rerr != nil || len(rawSig) != ed25519.SignatureSize {
		t.Fatalf("raw signature file = %d bytes, %v", len(rawSig), rerr)
	}

	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Pubkey:    strPtrAsym(pubPath),
		Filename:  strPtrAsym(dataPath),
		Signature: base64Std(rawSig),
	})
	if res.(map[string]any)["res"] != true {
		t.Fatalf("file verify = %#v", res)
	}
}

func strPtrAsym(s string) *string { return &s }

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestVerifyMultiCheckFlows(t *testing.T) {
	rt := asymRT(t)
	keyA, privA, _ := ed25519.GenerateKey(rand.Reader)
	keyB, privB, _ := ed25519.GenerateKey(rand.Reader)

	mk := func(name string, priv any, pub any) (string, string) {
		der, _ := x509.MarshalPKCS8PrivateKey(priv)
		privP := writeKey(t, rt, name+".key", pemEncode(t, "PRIVATE KEY", der))
		pubDER, _ := x509.MarshalPKIXPublicKey(pub)
		pubP := writeKey(t, rt, name+".pub", pemEncode(t, "PUBLIC KEY", pubDER))
		return privP, pubP
	}
	privAPath, pubAPath := mk("a", privA, keyA)
	privBPath, pubBPath := mk("b", privB, keyB)
	_ = privAPath

	sigA := mustASYM(t, rt, "asymmetric.sign", &signArgs{
		Privkey: strPtrAsym(privAPath), Text: strPtrAsym(sampleText),
	}).(string)
	sigB := mustASYM(t, rt, "asymmetric.sign", &signArgs{
		Privkey: strPtrAsym(privBPath), Text: strPtrAsym(sampleText),
	}).(string)

	// signed_by_any passes when one listed key signed.
	res := mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAny: []string{pubAPath, pubBPath},
		Signature:   []any{sigB},
	})
	m := res.(map[string]any)
	if m["res"] != true || m["message"] != "All required keys have provided a signature" {
		t.Fatalf("signed_by_any reply = %#v", m)
	}

	// signed_by_all fails until every key provides a signature.
	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAll: []string{pubAPath, pubBPath},
		Signature:   []any{sigB},
	})
	m = res.(map[string]any)
	if m["res"] != false ||
		m["message"] != "Failed while checking `signed_by_all`" {
		t.Fatalf("signed_by_all partial reply = %#v", m)
	}
	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAll: []string{pubAPath, pubBPath},
		Signature:   []any{sigA, sigB},
	})
	if res.(map[string]any)["res"] != true {
		t.Fatalf("signed_by_all full reply = %#v", res)
	}

	// Salt consumes every signature matched by a signer. Therefore duplicate
	// signatures cannot satisfy a repeated signed_by_all policy.
	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAll: []string{pubAPath, pubAPath},
		Signature:   []any{sigA, sigA},
	})
	if got := res.(map[string]any); got["res"] != false || got["message"] != "Failed while checking `signed_by_all`" {
		t.Fatalf("signed_by_all duplicate policy reply = %#v", got)
	}
	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAll: []string{pubAPath, pubBPath},
		Signature:   []any{sigA, sigA},
	})
	if got := res.(map[string]any); got["res"] != false || got["message"] != "Failed while checking `signed_by_all`" {
		t.Fatalf("signed_by_all duplicate signature reply = %#v", got)
	}

	// Both policy and signature order are irrelevant to the result.
	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAll: []string{pubBPath, pubAPath},
		Signature:   []any{sigA, sigB},
	})
	if got := res.(map[string]any); got["res"] != true || got["message"] != "All required keys have provided a signature" {
		t.Fatalf("signed_by_all order permutation reply = %#v", got)
	}
	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAny: []string{pubBPath, pubAPath},
		Signature:   []any{sigA, sigA},
	})
	if got := res.(map[string]any); got["res"] != true || got["message"] != "All required keys have provided a signature" {
		t.Fatalf("signed_by_any duplicate/order reply = %#v", got)
	}

	// Unfetchable signatures are skipped in multi-check mode, but an entirely
	// missing source is the same deterministic error as Salt.
	_, err := verifyFunc{}.Execute(context.Background(), rt, &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAny: []string{pubAPath},
		Signature:   []any{"/missing-signature"},
	})
	if err == nil || err.Error() != "Unable to locate any of the provided signatures" {
		t.Fatalf("missing signature source error = %v", err)
	}
	_, err = verifyFunc{}.Execute(context.Background(), rt, &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAny: []string{pubAPath},
		Signature:   []any{},
	})
	if err == nil || err.Error() != "Missing `signature` parameter" {
		t.Fatalf("missing signature list error = %v", err)
	}

	// Unknown and wrong keys are verification failures, not panics, and do not
	// poison the following successful verification.
	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAny: []string{"/unknown-key.pub"},
		Signature:   sigA,
	})
	if got := res.(map[string]any); got["res"] != false || got["message"] != "None of the public keys listed in signed_by_any provided a valid signature" {
		t.Fatalf("unknown signed_by_any key reply = %#v", got)
	}
	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAny: []string{pubBPath},
		Signature:   sigA,
	})
	if got := res.(map[string]any); got["res"] != false || got["message"] != "None of the public keys listed in signed_by_any provided a valid signature" {
		t.Fatalf("wrong signed_by_any key reply = %#v", got)
	}
	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAll: []string{""},
		Signature:   sigA,
	})
	if got := res.(map[string]any); got["res"] != false || got["message"] != "Failed while checking `signed_by_all`" {
		t.Fatalf("malformed signed_by_all policy reply = %#v", got)
	}
	_, err = verifyFunc{}.Execute(context.Background(), rt, &verifyArgs{
		Pubkey:    strPtrAsym(pubAPath),
		Text:      strPtrAsym(sampleText),
		Signature: []any{sigA},
	})
	if err == nil || err.Error() != "`signature` must be a string or bytes when verifying a single signing `pubkey`" {
		t.Fatalf("malformed single signature policy error = %v", err)
	}
	res = mustASYM(t, rt, "asymmetric.verify", &verifyArgs{
		Text:        strPtrAsym(sampleText),
		SignedByAll: []string{pubAPath, pubBPath},
		Signature:   []any{sigA, sigB},
	})
	if got := res.(map[string]any); got["res"] != true {
		t.Fatalf("post-failure signed_by_all reply = %#v", got)
	}

	// pubkey + multi-check is mutually exclusive.
	_, err = verifyFunc{}.Execute(context.Background(), rt, &verifyArgs{
		Text:        strPtrAsym(sampleText),
		Pubkey:      strPtrAsym(pubAPath),
		SignedByAny: []string{pubBPath},
		Signature:   sigA,
	})
	if err == nil || err.Error() != "Either specify pubkey + signature or signed_by_(any|all)" {
		t.Fatalf("exclusivity guard = %v", err)
	}

	// Missing data / missing signature guards.
	_, err = verifyFunc{}.Execute(context.Background(), rt, &verifyArgs{
		Pubkey:    strPtrAsym(pubAPath),
		Signature: sigA,
	})
	if err == nil || err.Error() != "Missing data to verify. Either specify `text` or `filename`" {
		t.Fatalf("missing-data guard = %v", err)
	}
	_, err = signFunc{}.Execute(context.Background(), rt, &signArgs{
		Privkey: strPtrAsym(privAPath),
	})
	if err == nil || err.Error() != "Either `text` or `filename` is required" {
		t.Fatalf("sign data guard = %v", err)
	}
}

const saltRSAPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuX/Th24GXF86sWXx+Q0o
nGmAk63mARrfoEAApbnyHa5fk7teO6Nv7VyUDRVo78pfhSV2g2E49j3WaX3TzVsO
JO7+Z3asFXXr2Rg/56483fXl9Flzfzjzyppy3u6VWDjte/YyhBliIG3sLwfVYTaH
b2C2xpoB0gwPYo8rc4U1e4CRLMDfPb4YtKL1Ud7shDmA171gpJBuVCHSc3CmvAx0
S3fiaGmeROYt1bVIKp/MFUM1vAivBXDPxnWDJnGx3+WDWlgmeQ2ZTPvN4YIFDa57
CGqNMeS4xUPbioGy1LyZ0AUZiPpynecYcjLcDInU8TI+UJa9BN45UQSNZCZU/gQw
mwIDAQAB
-----END PUBLIC KEY-----`

const saltRSASignature = `JQcgQPkK4ys7Nfipn/lZvVvXd4xSRKhgd+Z/zmwB25z9uAXLFB0nVUgIUUk+r2eP8H7LX9lWqNO3
hNRwkEaEijnnCILW8YezgBXpmKccG7Or50Us3okp52aTvxrCb0BK7CA0h/Tg+aRxNYmM+3RAgttk
QGSKEkEHHZ2X0DEr8BDPb2bm27ghy5HPYB7DeFb+vJBWn2gCHbIaXy3nNCahApU+UnstdB6Cbe78
A3TmOoPSVsdekV31FYztb3RBsjnlx76/t2zZ7B9BH1HsbFkz4fSblWJR+W36vg9gpKH4Ife82NlM
YOhJapxsaXtAfxDlwMGk7NUacj66d0EJ+NJpUg==`
