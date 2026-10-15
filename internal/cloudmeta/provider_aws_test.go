//go:build !statekit_no_metadata_aws && !statekit_no_metadata && !statekit_no_cloud_extras

package cloudmeta

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

const awsTestToken = "IMDS2-OPAQUE-TOKEN"

func awsFixture() providerFixture {
	return providerFixture{
		provider: "aws",
		happy: []cannedResponse{
			{status: http.StatusOK, body: awsTestToken + "\n"},
			{status: http.StatusOK, body: "i-0abc123def456\n"},
			{status: http.StatusOK, body: "us-east-1\n"},
			{status: http.StatusOK, body: "us-east-1a\n"},
			{status: http.StatusOK, body: "t3.micro\n"},
			{status: http.StatusOK, body: "ami-0fedcba987\n"},
		},
		requiredIdx:   1,
		requiredField: fieldInstanceID,
		optionalIdx:   5,
		optionalField: fieldImageID,
	}
}

func TestAWSHappyPathExactRequests(t *testing.T) {
	result, err, rt := runProvider("aws", nil, awsFixture().happy...)
	if err != nil {
		t.Fatalf("err=%v, want nil", err)
	}
	ttlHeaders := map[string]string{"x-aws-ec2-metadata-token-ttl-seconds": "30"}
	tokenHeader := map[string]string{"x-aws-ec2-metadata-token": awsTestToken}
	want := []struct {
		method  string
		path    string
		query   string
		headers map[string]string
	}{
		{"PUT", "/latest/api/token", "", ttlHeaders},
		{"GET", "/latest/meta-data/instance-id", "", tokenHeader},
		{"GET", "/latest/meta-data/placement/region", "", tokenHeader},
		{"GET", "/latest/meta-data/placement/availability-zone", "", tokenHeader},
		{"GET", "/latest/meta-data/instance-type", "", tokenHeader},
		{"GET", "/latest/meta-data/ami-id", "", tokenHeader},
	}
	if len(rt.calls) != len(want) {
		t.Fatalf("calls=%d, want %d: %+v", len(rt.calls), len(want), rt.calls)
	}
	for i, w := range want {
		assertCall(t, i, rt.calls[i], w.method, w.path, w.query, w.headers)
	}
	if result.Provider != "aws" || result.Status != statusOK ||
		result.Verification != verificationUnverified ||
		result.InstanceID != "i-0abc123def456" || result.Region != "us-east-1" ||
		result.Zone != "us-east-1a" || result.InstanceType != "t3.micro" ||
		result.ImageID != "ami-0fedcba987" || result.Provenance != "" ||
		result.FieldsNotCollected != nil {
		t.Fatalf("result=%+v", result)
	}
	// The IMDSv2 token is transient: it must never serialize.
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatalf("marshal: %v", marshalErr)
	}
	if strings.Contains(string(encoded), awsTestToken) {
		t.Fatalf("token leaked into result JSON: %s", encoded)
	}
}

// TestAWSTokenStepIsMandatory pins IMDSv2-only behavior: any token-step
// failure fails the whole collection with no leaf request and no v1
// fallback.
func TestAWSTokenStepIsMandatory(t *testing.T) {
	fx := awsFixture()
	for _, tc := range []struct {
		name   string
		mutate func(*cannedResponse)
		want   error
	}{
		{"token-404", func(r *cannedResponse) { r.status = http.StatusNotFound }, ErrProtocol},
		{"token-500", func(r *cannedResponse) { r.status = http.StatusInternalServerError }, ErrProtocol},
		{"token-empty", func(r *cannedResponse) { r.body = "" }, ErrMalformed},
		{"token-oversize", func(r *cannedResponse) { r.body = strings.Repeat("t", maxLeafBodyBytes+1) }, ErrOversize},
		{
			"token-redirect",
			func(r *cannedResponse) {
				r.status = http.StatusFound
				r.header = map[string]string{"Location": metadataBase + "/latest/api/token"}
			},
			ErrRedirect,
		},
		{"token-unreachable", func(r *cannedResponse) { r.roundTripErr = errors.New("dial failed") }, ErrUnreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err, rt := runProvider("aws", nil, withMutation(fx.happy, 0, tc.mutate)...)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v, want %v", err, tc.want)
			}
			if result != nil {
				t.Fatalf("result=%+v, want nil", result)
			}
			if len(rt.calls) != 1 {
				t.Fatalf("calls=%d, want 1 (no leaf request, no v1 fallback)", len(rt.calls))
			}
		})
	}
}

// TestAWSTokenEchoDiscardsResult pins the token-echo guard: a 200-status
// leaf whose value equals the IMDSv2 token is malformed and discards the
// whole result; the token never serializes and never reaches an error.
func TestAWSTokenEchoDiscardsResult(t *testing.T) {
	fx := awsFixture()
	// An opaque token fails every field validator as well; the outcome is
	// the same whole-result discard. Production fails fast at the mutated
	// leaf, so exactly token + leaves up to and including that leaf are
	// requested (response index leafIdx ⇒ leafIdx+1 calls).
	for _, leafIdx := range []int{1, 2, 3, 4, 5} {
		responses := withMutation(fx.happy, leafIdx, func(r *cannedResponse) {
			r.body = awsTestToken + "\n"
		})
		result, err, rt := runProvider("aws", nil, responses...)
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("leaf %d: err=%v, want %v", leafIdx, err, ErrMalformed)
		}
		if result != nil {
			t.Fatalf("leaf %d: result=%+v, want nil", leafIdx, result)
		}
		if strings.Contains(err.Error(), awsTestToken) {
			t.Fatalf("leaf %d: token leaked into error: %q", leafIdx, err.Error())
		}
		if len(rt.calls) != leafIdx+1 {
			t.Fatalf("leaf %d: calls=%d, want %d (fail fast at the mutated leaf)", leafIdx, len(rt.calls), leafIdx+1)
		}
	}

	// Guard-hit case: the token is validator-compatible for the zone
	// leaf, so only the token-echo guard rejects the echo.
	responses := []cannedResponse{
		{status: http.StatusOK, body: "us-east-1a\n"}, // token: passes the zone grammar+validator
		{status: http.StatusOK, body: "i-0abc123def456\n"},
		{status: http.StatusOK, body: "us-east-1\n"},
		{status: http.StatusOK, body: "us-east-1a\n"}, // echoes the token
		{status: http.StatusOK, body: "t3.micro\n"},
		{status: http.StatusOK, body: "ami-0fedcba987\n"},
	}
	result, err, rt := runProvider("aws", nil, responses...)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("guard-hit: err=%v, want %v", err, ErrMalformed)
	}
	if result != nil {
		t.Fatalf("guard-hit: result=%+v, want nil", result)
	}
	if len(rt.calls) != len(responses) {
		t.Fatalf("guard-hit: calls=%d, want %d", len(rt.calls), len(responses))
	}
}

func TestAWSFailureMatrix(t *testing.T) {
	runFailureMatrix(t, awsFixture())
}
