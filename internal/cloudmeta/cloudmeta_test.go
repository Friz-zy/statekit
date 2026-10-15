package cloudmeta

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestCollectInvalidProvider(t *testing.T) {
	for _, name := range []string{"", "AWS", "aws ", " Aws", "rackspace", "digitalocean", "oracle", "openstack "} {
		result, err, rt := runProvider(name, nil)
		if !errors.Is(err, ErrInvalidProvider) {
			t.Fatalf("%q: err=%v, want %v", name, err, ErrInvalidProvider)
		}
		if result != nil {
			t.Fatalf("%q: result=%+v, want nil", name, result)
		}
		if len(rt.calls) != 0 {
			t.Fatalf("%q: %d requests issued, want 0", name, len(rt.calls))
		}
	}
}

func TestDeferredProvidersFailBeforeAnyRequest(t *testing.T) {
	for _, name := range []string{"ibm", "linode", "hetzner", "ovh", "scaleway", "vultr", "vsphere"} {
		result, err, rt := runProvider(name, nil)
		if !errors.Is(err, ErrDeferredProvider) {
			t.Fatalf("%q: err=%v, want %v", name, err, ErrDeferredProvider)
		}
		if result != nil {
			t.Fatalf("%q: result=%+v, want nil", name, result)
		}
		if len(rt.calls) != 0 {
			t.Fatalf("%q: %d requests issued, want 0", name, len(rt.calls))
		}
	}
}

// TestBuildDisabledSeam pins the compiled-out-provider behavior without a
// tagged build: every per-provider _disabled stub returns exactly this.
// The actual -tags profile runs happen in the sandbox.
func TestBuildDisabledSeam(t *testing.T) {
	result, err := buildDisabled()
	if result != nil || !errors.Is(err, ErrBuildDisabled) || err != ErrBuildDisabled {
		t.Fatalf("buildDisabled() = (%+v, %v), want (nil, exact ErrBuildDisabled)", result, err)
	}
}

func TestDialGuardRejectsNonLiteralAddress(t *testing.T) {
	stub := &stubDial{}
	guard := dialGuard(stub.dial)
	ctx := context.Background()
	for _, tc := range []struct {
		network string
		addr    string
	}{
		{"tcp", "10.0.0.1:80"},
		{"tcp", "169.254.169.254:443"},
		{"tcp4", "169.254.169.254:80"},
		{"udp", "169.254.169.254:80"},
		{"tcp", "metadata.example.internal:80"},
		{"tcp", "169.254.170.2:80"},
	} {
		conn, err := guard(ctx, tc.network, tc.addr)
		if !errors.Is(err, ErrUnreachable) || conn != nil {
			t.Fatalf("guard(%s, %s) = (%v, %v), want (nil, %v)", tc.network, tc.addr, conn, err, ErrUnreachable)
		}
		if len(stub.calls) != 0 {
			t.Fatalf("guard(%s, %s) reached the dialer: %+v", tc.network, tc.addr, stub.calls)
		}
	}

	conn, err := guard(ctx, "tcp", "169.254.169.254:80")
	if !errors.Is(err, errStubDial) || conn != nil {
		t.Fatalf("literal dial = (%v, %v), want (nil, %v)", conn, err, errStubDial)
	}
	if len(stub.calls) != 1 || stub.calls[0] != (dialCall{network: "tcp", addr: "169.254.169.254:80"}) {
		t.Fatalf("literal dial args = %+v, want exactly one tcp 169.254.169.254:80", stub.calls)
	}
}

func TestTransportHardeningConfiguration(t *testing.T) {
	transport := newHardenedTransport()
	if transport.Proxy != nil {
		t.Fatal("Proxy must be explicitly nil")
	}
	if !transport.DisableCompression {
		t.Fatal("DisableCompression must be set")
	}
	if !transport.DisableKeepAlives {
		t.Fatal("DisableKeepAlives must be set (no stdlib auto-retry over reused connections)")
	}
	if transport.DialContext == nil {
		t.Fatal("DialContext must be set")
	}
	if transport.ResponseHeaderTimeout != 500*time.Millisecond {
		t.Fatalf("ResponseHeaderTimeout = %v, want 500ms", transport.ResponseHeaderTimeout)
	}
	if transport.MaxResponseHeaderBytes != 8192 {
		t.Fatalf("MaxResponseHeaderBytes = %d, want 8192", transport.MaxResponseHeaderBytes)
	}
	client := newClient(transport)
	if client.Jar != nil {
		t.Fatal("Jar must be nil")
	}
	if client.CheckRedirect == nil {
		t.Fatal("CheckRedirect must be set")
	}
	if err := client.CheckRedirect(&http.Request{}, nil); !errors.Is(err, ErrRedirect) {
		t.Fatalf("CheckRedirect error = %v, want %v (every redirect denied, same-origin included)", err, ErrRedirect)
	}
}

// TestFieldValidatorBoundaries pins the per-field validators: one valid
// and one invalid example per field plus the documented length
// boundaries (azure vmSize 64, oci ociAdName 32 — hyphenated AD names
// such as EU-FRANKFURT-1-AD-1 are valid — openstack instance_type 64,
// gcp/do id 20 digits, aws instance-id hex width).
func TestFieldValidatorBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name     string
		validate func(string) error
		valid    string
		invalid  string
	}{
		{"aws instance_id", validateAWSInstanceID, "i-0abc123def456", "i-0abc123"},
		{"aws region", validateAWSRegion, "us-east-1", "us-east"},
		{"aws zone", validateAWSZone, "us-east-1a", "us-east-1z"},
		{"aws instance_type", validateAWSInstanceType, "t3.micro", "t3micro"},
		{"aws image", validateAWSAMI, "ami-0fedcba987", "ami-xyz"},
		{"azure location", validateAzureLocation, "westeurope", "West Europe"},
		{"azure zone", validateAzureZone, "2", "22"},
		{"azure vm_size", validateAzureVMSize, "Standard_D2s_v5", "standard"},
		{"gcp instance_id", validateGCPInstanceID, "834170998498", "834170998498a"},
		{"do id", validateDOID, "175501237", "droplet-1"},
		{"do region", validateDORegion, "fra1", "FRA1"},
		{"oci id", validateOCIID, "ocid1.instance.oc1..exampleinstance", "ocid1.instance"},
		{"oci region", validateOCIRegion, "eu-frankfurt-1", "eu-frankfurt"},
		{"oci ad name", validateOCIADName, "EU-FRANKFURT-1-AD-1", "-AD-1"},
		{"oci shape", validateOCIShape, "VM.Standard.A1.Flex", "VM Standard"},
		{"oci image", validateOCIImage, "ocid1.image.oc1..exampleimage", "ocid1.image"},
		{"openstack instance_id", validateOpenStackInstanceID, "i-0000abcd", "0000abcd"},
		{"openstack zone", validateOpenStackZone, "nova", "nova-1!"},
		{"openstack instance_type", validateOpenStackInstanceType, "m1.small", "m1 small"},
		{"openstack image", validateOpenStackAMI, "ami-00000042", "ami-42"},
	} {
		if err := tc.validate(tc.valid); err != nil {
			t.Fatalf("%s: valid %q rejected: %v", tc.name, tc.valid, err)
		}
		if err := tc.validate(tc.invalid); err != ErrMalformed {
			t.Fatalf("%s: invalid %q = %v, want %v", tc.name, tc.invalid, err, ErrMalformed)
		}
	}
	// Length boundaries: pattern-matching values at exactly the cap are
	// accepted; one character more is rejected.
	boundaries := []struct {
		name     string
		validate func(string) error
		atCap    string
		overCap  string
	}{
		{"azure vm_size 64", validateAzureVMSize, "A" + strings.Repeat("B", 61) + "_C", "A" + strings.Repeat("B", 62) + "_C"},
		{"oci ad name 32", validateOCIADName, "A" + strings.Repeat("b", 29) + "-C", "A" + strings.Repeat("b", 30) + "-C"},
		{"openstack instance_type 64", validateOpenStackInstanceType, strings.Repeat("m", 64), strings.Repeat("m", 65)},
		{"gcp instance_id 20 digits", validateGCPInstanceID, strings.Repeat("1", 20), strings.Repeat("1", 21)},
		{"do id 20 digits", validateDOID, strings.Repeat("1", 20), strings.Repeat("1", 21)},
	}
	for _, b := range boundaries {
		if err := b.validate(b.atCap); err != nil {
			t.Fatalf("%s: at-cap value rejected: %v", b.name, err)
		}
		if err := b.validate(b.overCap); err != ErrMalformed {
			t.Fatalf("%s: over-cap value = %v, want %v", b.name, err, ErrMalformed)
		}
	}
}

type fakeTimeoutError struct{}

func (fakeTimeoutError) Error() string { return "net/http: fake timeout " + canaryMarker }
func (fakeTimeoutError) Timeout() bool { return true }

func TestClassifyTransportError(t *testing.T) {
	wrapped := func(inner error) error {
		return &url.Error{Op: "Get", URL: metadataBase + "/" + canaryMarker, Err: inner}
	}
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{"deadline", wrapped(context.DeadlineExceeded), ErrDeadline},
		{"canceled", wrapped(context.Canceled), ErrDeadline},
		{"timeout", wrapped(fakeTimeoutError{}), ErrDeadline},
		{"redirect-policy", wrapped(ErrRedirect), ErrRedirect},
		{"dial-guard", wrapped(ErrUnreachable), ErrUnreachable},
		{"generic", wrapped(errors.New("connection refused " + canaryMarker)), ErrUnreachable},
	} {
		got := classifyTransportError(tc.err)
		if got != tc.want {
			t.Fatalf("%s: classify = %v, want %v", tc.name, got, tc.want)
		}
		if strings.Contains(got.Error(), canaryMarker) {
			t.Fatalf("%s: canary leaked into classified error: %q", tc.name, got.Error())
		}
	}
}

func TestForbiddenPathGuard(t *testing.T) {
	for _, path := range forbiddenPathList {
		if err := assertPathAllowed(path); !errors.Is(err, ErrForbiddenPath) {
			t.Fatalf("path %q allowed, want %v", path, ErrForbiddenPath)
		}
	}
	for _, path := range []string{
		"/openstack/latest/meta_data.json",
		"/latest/meta_data.json",
		"/2009-04-04/meta_data.json",
	} {
		if err := assertPathAllowed(path); !errors.Is(err, ErrForbiddenPath) {
			t.Fatalf("bulk path %q allowed, want %v", path, ErrForbiddenPath)
		}
	}
	for _, path := range []string{
		// aws
		"/latest/api/token",
		"/latest/meta-data/instance-id",
		"/latest/meta-data/placement/region",
		"/latest/meta-data/placement/availability-zone",
		"/latest/meta-data/instance-type",
		"/latest/meta-data/ami-id",
		// azure
		"/metadata/instance/compute/vmId",
		"/metadata/instance/compute/location",
		"/metadata/instance/compute/zone",
		"/metadata/instance/compute/vmSize",
		// gcp
		"/computeMetadata/v1/instance/id",
		// oci
		"/opc/v2/instance/id",
		"/opc/v2/instance/canonicalRegionName",
		"/opc/v2/instance/ociAdName",
		"/opc/v2/instance/shape",
		"/opc/v2/instance/image",
		// do
		"/metadata/v1/id",
		"/metadata/v1/region",
		// openstack
		"/2009-04-04/meta-data/instance-id",
		"/2009-04-04/meta-data/placement/availability-zone",
		"/2009-04-04/meta-data/instance-type",
		"/2009-04-04/meta-data/ami-id",
	} {
		if err := assertPathAllowed(path); err != nil {
			t.Fatalf("approved path %q rejected: %v", path, err)
		}
	}
}

func TestAggregateBodyBudget(t *testing.T) {
	c := newCollector(&recordingTransport{})
	if err := c.charge(maxAggregateBodyBytes); err != nil {
		t.Fatalf("charging the full budget: %v", err)
	}
	if err := c.charge(1); !errors.Is(err, ErrOversize) {
		t.Fatalf("over-budget charge = %v, want %v", err, ErrOversize)
	}
}

// fuzzGrammarProperties holds the shared leaf-grammar invariants: no
// panics; accepted values are bounded, control-free, valid UTF-8, and
// byte-exact stable under re-parsing; rejected inputs never produce a
// value.
func fuzzGrammarProperties(t *testing.T, body []byte) string {
	t.Helper()
	value, err := parseLeafValue(body)
	if err != nil {
		return ""
	}
	if len(value) > maxLeafValueBytes {
		t.Fatalf("oversize accepted: %d bytes", len(value))
	}
	if !utf8.ValidString(value) {
		t.Fatalf("invalid UTF-8 accepted: %q", value)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("control char accepted: %q", value)
		}
	}
	again, aerr := parseLeafValue([]byte(value))
	if aerr != nil || again != value {
		t.Fatalf("round trip %q -> (%q, %v)", value, again, aerr)
	}
	return value
}

func FuzzParseLeafValue(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("i-123\n"),
		[]byte(""),
		[]byte("\n"),
		[]byte("a\x01b"),
		[]byte{0xff, 0xfe},
		[]byte(strings.Repeat("a", 2000)),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		fuzzGrammarProperties(t, body)
	})
}

// fuzzValidators exercises field validators on grammar-accepted values:
// no panics, deterministic verdicts, and every rejection is exactly the
// value-free malformed sentinel — never another error, never a value.
func fuzzValidators(t *testing.T, value string, validators ...func(string) error) {
	t.Helper()
	for _, validate := range validators {
		err := validate(value)
		if err != nil && err != ErrMalformed {
			t.Fatalf("validator returned %v, want nil or %v", err, ErrMalformed)
		}
		if err == nil && validate(value) != nil {
			t.Fatal("validator verdict not deterministic")
		}
	}
}

func FuzzAWSLeafValue(f *testing.F) {
	f.Add([]byte("i-0abc123def456\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		value := fuzzGrammarProperties(t, body)
		fuzzValidators(t, value,
			validateAWSInstanceID,
			validateAWSRegion,
			validateAWSZone,
			validateAWSInstanceType,
			validateAWSAMI,
		)
	})
}

func FuzzAzureLeafValue(f *testing.F) {
	f.Add([]byte("33abcd12-90bf-4d8e-a1de-1234567890ab\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		value := fuzzGrammarProperties(t, body)
		fuzzValidators(t, value,
			azureVMIDShape,
			validateAzureLocation,
			validateAzureZone,
			validateAzureVMSize,
		)
		// Shape acceptance must be stable: a vmId-shaped value stays
		// vmId-shaped after re-parsing.
		if value != "" && azureVMIDShape(value) == nil {
			if again, err := parseLeafValue([]byte(value)); err != nil || again != value || azureVMIDShape(again) != nil {
				t.Fatalf("GUID round trip %q -> (%q, %v)", value, again, err)
			}
		}
	})
}

func FuzzGCPLeafValue(f *testing.F) {
	f.Add([]byte("834170998498\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		value := fuzzGrammarProperties(t, body)
		fuzzValidators(t, value, validateGCPInstanceID)
	})
}

func FuzzOCILeafValue(f *testing.F) {
	f.Add([]byte("ocid1.instance.oc1..example\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		value := fuzzGrammarProperties(t, body)
		fuzzValidators(t, value,
			validateOCIID,
			validateOCIRegion,
			validateOCIADName,
			validateOCIShape,
			validateOCIImage,
		)
	})
}

func FuzzDOLeafValue(f *testing.F) {
	f.Add([]byte("175501237\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		value := fuzzGrammarProperties(t, body)
		fuzzValidators(t, value, validateDOID, validateDORegion)
	})
}

func FuzzOpenStackLeafValue(f *testing.F) {
	f.Add([]byte("i-0000abcd\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		value := fuzzGrammarProperties(t, body)
		fuzzValidators(t, value,
			validateOpenStackInstanceID,
			validateOpenStackZone,
			validateOpenStackInstanceType,
			validateOpenStackAMI,
		)
	})
}
