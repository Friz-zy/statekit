//go:build !statekit_no_sdk_aws && !statekit_no_sdks

package cloudsecret

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/smithy-go/logging"
)

type fakeSecretsManager struct {
	calls  int
	input  *secretsmanager.GetSecretValueInput
	output *secretsmanager.GetSecretValueOutput
	err    error
}

func (f *fakeSecretsManager) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.calls++
	f.input = input
	return f.output, f.err
}

type fakeSSM struct {
	calls  int
	input  *ssm.GetParameterInput
	output *ssm.GetParameterOutput
	err    error
}

func (f *fakeSSM) GetParameter(_ context.Context, input *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	f.calls++
	f.input = input
	return f.output, f.err
}

func TestReadSecretsManagerMakesOnePinnedVersionCall(t *testing.T) {
	value := "synthetic-secret-canary"
	client := &fakeSecretsManager{output: &secretsmanager.GetSecretValueOutput{SecretString: &value}}
	source := Source{Provider: "aws", Backend: "secretsmanager", Region: "us-east-1", Resource: "db", VersionAlias: "AWSCURRENT"}
	got, err := readSecretsManager(context.Background(), client, source)
	if err != nil || string(got) != value || client.calls != 1 || client.input == nil {
		t.Fatal("Secrets Manager read did not perform exactly one successful call")
	}
	if aws.ToString(client.input.SecretId) != "db" || aws.ToString(client.input.VersionStage) != "AWSCURRENT" || client.input.VersionId != nil {
		t.Fatal("Secrets Manager selector mapping was incorrect")
	}
	versionID := "0123456789abcdef0123456789abcdef"
	source.VersionAlias = ""
	source.VersionID = versionID
	client = &fakeSecretsManager{output: &secretsmanager.GetSecretValueOutput{SecretString: &value}}
	if _, err := readSecretsManager(context.Background(), client, source); err != nil || client.calls != 1 || aws.ToString(client.input.VersionId) != versionID || client.input.VersionStage != nil {
		t.Fatal("Secrets Manager version ID was not mapped to exactly one read")
	}
}

func TestReadSecretsManagerPassesFullCrossAccountARNUnchanged(t *testing.T) {
	value := "synthetic-cross-account-secret"
	arn := "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-AbCdEf"
	client := &fakeSecretsManager{output: &secretsmanager.GetSecretValueOutput{SecretString: &value}}
	source := Source{Provider: "aws", Backend: "secretsmanager", Region: "us-east-1", Resource: arn}
	if _, err := readSecretsManager(context.Background(), client, source); err != nil || client.calls != 1 || aws.ToString(client.input.SecretId) != arn {
		t.Fatal("full cross-account Secrets Manager ARN was not passed unchanged to GetSecretValue")
	}
}

func TestReadSecretsManagerMapsFailureAndAcceptsBinaryBytes(t *testing.T) {
	const providerDetailCanary = "SYNTHETIC_PROVIDER_DETAIL_CANARY"
	client := &fakeSecretsManager{err: errors.New(providerDetailCanary)}
	source := Source{Provider: "aws", Backend: "secretsmanager", Region: "us-east-1", Resource: "db"}
	if _, err := readSecretsManager(context.Background(), client, source); err != ErrProvider || strings.Contains(err.Error(), providerDetailCanary) || client.calls != 1 {
		t.Fatal("provider failure was not sanitized after exactly one request")
	}
	binaryValue := []byte{0x00, 0xff, 0x0a}
	client = &fakeSecretsManager{output: &secretsmanager.GetSecretValueOutput{SecretBinary: binaryValue}}
	got, err := readSecretsManager(context.Background(), client, source)
	if err != nil || len(got) != len(binaryValue) || got[0] != 0 || got[1] != 0xff || got[2] != 0x0a {
		t.Fatal("binary secret payload was not returned byte-exactly")
	}
	oversized := strings.Repeat("x", MaxPayloadBytes+1)
	client = &fakeSecretsManager{output: &secretsmanager.GetSecretValueOutput{SecretString: &oversized}}
	if _, err := readSecretsManager(context.Background(), client, source); !errors.Is(err, ErrInvalidPayload) || client.calls != 1 {
		t.Fatal("oversized provider payload was not rejected after one read")
	}
}

func TestReadSSMUsesSingleDecryptedPinnedParameterCall(t *testing.T) {
	value := "synthetic-parameter-canary"
	client := &fakeSSM{output: &ssm.GetParameterOutput{Parameter: &types.Parameter{Value: &value}}}
	source := Source{Provider: "aws", Backend: "ssm", Region: "us-east-1", Resource: "/prod/database", VersionID: "12"}
	got, err := readSSM(context.Background(), client, source)
	if err != nil || string(got) != value || client.calls != 1 || client.input == nil {
		t.Fatal("SSM read did not perform exactly one successful call")
	}
	if aws.ToString(client.input.Name) != "/prod/database:12" || aws.ToBool(client.input.WithDecryption) != true {
		t.Fatal("SSM did not use the pinned decrypted parameter contract")
	}
}

func TestReadSSMMapsProviderErrorToClosedSentinel(t *testing.T) {
	const providerDetailCanary = "SYNTHETIC_SSM_PROVIDER_DETAIL_CANARY"
	client := &fakeSSM{err: errors.New(providerDetailCanary)}
	source := Source{Provider: "aws", Backend: "ssm", Region: "us-east-1", Resource: "/prod/key"}
	if _, err := readSSM(context.Background(), client, source); err != ErrProvider || strings.Contains(err.Error(), providerDetailCanary) || client.calls != 1 {
		t.Fatal("SSM provider error was not mapped to a value-free sentinel")
	}
}

func TestReadSSMPassesFullSharedParameterARNWithDecryption(t *testing.T) {
	value := "synthetic-cross-account-parameter"
	arn := "arn:aws:ssm:us-east-1:123456789012:parameter/prod/database"
	client := &fakeSSM{output: &ssm.GetParameterOutput{Parameter: &types.Parameter{Value: &value}}}
	source := Source{Provider: "aws", Backend: "ssm", Region: "us-east-1", Resource: arn}
	if _, err := readSSM(context.Background(), client, source); err != nil || client.calls != 1 || aws.ToString(client.input.Name) != arn || !aws.ToBool(client.input.WithDecryption) {
		t.Fatal("full shared SSM parameter ARN was not passed to one decrypted GetParameter call")
	}
}

type fakeMetadata struct {
	calls []string
	role  string
}

func (f *fakeMetadata) GetMetadata(_ context.Context, input *imds.GetMetadataInput, _ ...func(*imds.Options)) (*imds.GetMetadataOutput, error) {
	f.calls = append(f.calls, input.Path)
	switch input.Path {
	case "/iam/security-credentials/":
		return &imds.GetMetadataOutput{Content: io.NopCloser(strings.NewReader(f.role + "\n"))}, nil
	case "/iam/security-credentials/role-one":
		body := `{"Code":"Success","AccessKeyId":"SYNTHETIC_KEY","SecretAccessKey":"SYNTHETIC_VALUE","Token":"SYNTHETIC_TOKEN","Expiration":"` + time.Now().UTC().Add(time.Hour).Format(time.RFC3339) + `"}`
		return &imds.GetMetadataOutput{Content: io.NopCloser(strings.NewReader(body))}, nil
	default:
		return nil, errors.New("synthetic metadata error")
	}
}

func TestInstanceProfileRejectsRoleAmbiguityAndMapsErrors(t *testing.T) {
	client := &fakeMetadata{role: "role-one\nrole-two"}
	if _, err := instanceProfileCredentials(context.Background(), client); !errors.Is(err, ErrCredentials) || len(client.calls) != 1 {
		t.Fatal("multiple instance roles were not rejected before credential retrieval")
	}
	client = &fakeMetadata{role: "role-one"}
	creds, err := instanceProfileCredentials(context.Background(), client)
	if err != nil || !creds.CanExpire || !creds.Expires.After(time.Now()) || len(client.calls) != 2 {
		t.Fatal("synthetic instance-profile credentials were not retrieved directly")
	}
	client = &fakeMetadata{role: "../role-one"}
	if _, err := instanceProfileCredentials(context.Background(), client); !errors.Is(err, ErrCredentials) || len(client.calls) != 1 {
		t.Fatal("unsafe role path was not rejected")
	}
}

type fakeIMDSHTTP struct {
	calls   int
	request *http.Request
}

func (f *fakeIMDSHTTP) Do(request *http.Request) (*http.Response, error) {
	f.calls++
	f.request = request
	return &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("synthetic failure")),
		Request:    request,
	}, nil
}

func TestIMDSClientPinsEndpointAndDoesNotFallbackOrRetry(t *testing.T) {
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://127.0.0.1:1234")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	client := &fakeIMDSHTTP{}
	metadata := newIMDSClientWithHTTPClient(client)
	_, err := metadata.GetMetadata(context.Background(), &imds.GetMetadataInput{Path: metadataListPath})
	if err == nil || client.calls != 1 || client.request == nil || client.request.Method != http.MethodPut || client.request.URL.String() != metadataEndpoint+"/latest/api/token" {
		t.Fatal("IMDS client did not pin IMDSv2 to the fixed endpoint without fallback or retry")
	}
}

type roleFlowHTTP struct {
	requests  []*http.Request
	failToken bool
}

func (f *roleFlowHTTP) Do(request *http.Request) (*http.Response, error) {
	f.requests = append(f.requests, request)
	status := http.StatusOK
	body := ""
	switch {
	case request.Method == http.MethodPut && request.URL.Path == "/latest/api/token":
		if f.failToken {
			status = http.StatusForbidden
			body = "SYNTHETIC_METADATA_ERROR_CANARY"
		} else {
			body = "SYNTHETIC_IMDSV2_TOKEN"
		}
	case request.Method == http.MethodGet && request.URL.Path == "/latest/meta-data/iam/security-credentials/":
		body = "role-one\n"
	case request.Method == http.MethodGet && request.URL.Path == "/latest/meta-data/iam/security-credentials/role-one":
		body = `{"Code":"Success","AccessKeyId":"SYNTHETIC_KEY","SecretAccessKey":"SYNTHETIC_VALUE","Token":"SYNTHETIC_SESSION","Expiration":"` + time.Now().UTC().Add(time.Hour).Format(time.RFC3339) + `","LastUpdated":"` + time.Now().UTC().Format(time.RFC3339) + `","Type":"AWS-HMAC"}`
	default:
		return nil, errors.New("unexpected synthetic IMDS request")
	}
	header := make(http.Header)
	if request.Method == http.MethodPut {
		header.Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "21600")
	}
	return &http.Response{
		StatusCode: status,
		Status:     strconv.Itoa(status) + " " + http.StatusText(status),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}, nil
}

func TestInstanceProfileCredentialsUseOneIMDSv2Flow(t *testing.T) {
	httpClient := &roleFlowHTTP{}
	client := newIMDSClientWithHTTPClient(httpClient)
	credentials, err := instanceProfileCredentials(context.Background(), client)
	if err != nil || credentials.AccessKeyID != "SYNTHETIC_KEY" || len(httpClient.requests) != 3 {
		t.Fatal("synthetic IMDSv2 credential flow did not complete exactly three requests")
	}
	if httpClient.requests[0].Method != http.MethodPut || httpClient.requests[0].URL.Path != "/latest/api/token" {
		t.Fatal("IMDSv2 token request was not first")
	}
	if httpClient.requests[1].Method != http.MethodGet || httpClient.requests[1].URL.Path != "/latest/meta-data/iam/security-credentials/" ||
		httpClient.requests[2].Method != http.MethodGet || httpClient.requests[2].URL.Path != "/latest/meta-data/iam/security-credentials/role-one" {
		t.Fatal("metadata role-list and role-credential requests were not exact")
	}
	for _, request := range httpClient.requests[1:] {
		if request.Header.Get("X-aws-ec2-metadata-token") != "SYNTHETIC_IMDSV2_TOKEN" {
			t.Fatal("metadata request did not carry the synthetic IMDSv2 token")
		}
	}
}

type countingLogger struct{ calls int }

func (l *countingLogger) Logf(logging.Classification, string, ...interface{}) { l.calls++ }

func TestIMDSCredentialFlowKeepsSDKLoggingDisabled(t *testing.T) {
	httpClient := &roleFlowHTTP{}
	logger := &countingLogger{}
	client := newIMDSClientWithLogger(httpClient, logger)
	_, err := instanceProfileCredentials(context.Background(), client)
	if err != nil || len(httpClient.requests) != 3 || logger.calls != 0 {
		t.Fatal("synthetic IMDSv2 flow emitted SDK logs or failed")
	}
}

func TestIMDSCredentialFailureIsValueFreeWithoutV1Fallback(t *testing.T) {
	httpClient := &roleFlowHTTP{failToken: true}
	_, err := instanceProfileCredentials(context.Background(), newIMDSClientWithHTTPClient(httpClient))
	if !errors.Is(err, ErrCredentials) || strings.Contains(err.Error(), "SYNTHETIC_METADATA_ERROR_CANARY") || len(httpClient.requests) != 1 {
		t.Fatal("IMDSv2 failure leaked provider details or attempted a fallback")
	}
}

func TestHTTPClientsDisableProxyCompressionAndRedirectFollowing(t *testing.T) {
	for _, client := range []*http.Client{newIMDSHTTPClient(), newServiceHTTPClient("us-east-1", "secretsmanager")} {
		if client.Timeout <= 0 || client.CheckRedirect == nil || !errors.Is(client.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
			t.Fatal("HTTP client is missing bounded timeouts or redirect rejection")
		}
		var transport *http.Transport
		switch wrapper := client.Transport.(type) {
		case *imdsRoundTripper:
			transport, _ = wrapper.next.(*http.Transport)
		case *serviceRoundTripper:
			transport, _ = wrapper.next.(*http.Transport)
		}
		if transport == nil || transport.Proxy != nil || !transport.DisableCompression || !transport.DisableKeepAlives {
			t.Fatal("HTTP client inherited proxy, compression, or connection reuse")
		}
	}
	service := newServiceHTTPClient("us-east-1", "ssm")
	called := false
	service.Transport = &serviceRoundTripper{
		host: "ssm.us-east-1.amazonaws.com", backend: "ssm",
		next: fakeRoundTripper(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, nil
		}),
	}
	request, err := http.NewRequest(http.MethodPost, "https://attacker.invalid/", strings.NewReader("{}"))
	if err != nil {
		t.Fatal("synthetic request construction failed")
	}
	request.Header.Set("X-Amz-Target", "AmazonSSM.GetParameter")
	if _, err := service.Transport.RoundTrip(request); !errors.Is(err, ErrProvider) || called {
		t.Fatal("service transport permitted a caller-selected endpoint")
	}
}

type fakeRoundTripper func(*http.Request) (*http.Response, error)

func (f fakeRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type fakeCredentialProvider struct{}

func (fakeCredentialProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "SYNTHETIC_KEY", SecretAccessKey: "SYNTHETIC_SECRET", SessionToken: "SYNTHETIC_TOKEN"}, nil
}

func TestServiceRoundTripperAcceptsCanonicalRootPath(t *testing.T) {
	for _, rawPath := range []string{"", "/"} {
		request := newServiceRoundTripperTestRequest(t)
		request.URL.RawPath = rawPath
		if request.URL.Path != "/" || request.URL.EscapedPath() != "/" {
			t.Fatal("root-path fixture is not canonical")
		}
		calls := 0
		client := &serviceRoundTripper{
			next: fakeRoundTripper(func(request *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{
					StatusCode:    http.StatusOK,
					Header:        make(http.Header),
					Body:          io.NopCloser(strings.NewReader("{}")),
					ContentLength: 2,
					Request:       request,
				}, nil
			}),
			host:    serviceEndpointHost("us-east-1", "ssm"),
			backend: "ssm",
		}
		response, err := client.RoundTrip(request)
		if err != nil || response == nil || calls != 1 {
			t.Fatal("canonical root path did not reach the single fake service transport")
		}
		_ = response.Body.Close()
	}
}

func TestServiceRoundTripperRejectsNoncanonicalPathsBeforeTransport(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*url.URL)
	}{
		{name: "non-root path", mutate: func(u *url.URL) { u.Path = "/health" }},
		{name: "parent traversal path", mutate: func(u *url.URL) { u.Path = "/../secret" }},
		{name: "encoded slash path", mutate: func(u *url.URL) { u.Path = "//"; u.RawPath = "/%2F" }},
		{name: "mismatched raw path", mutate: func(u *url.URL) { u.RawPath = "/%2F" }},
		{name: "invalid raw path", mutate: func(u *url.URL) { u.RawPath = "/%ZZ" }},
		{name: "query", mutate: func(u *url.URL) { u.RawQuery = "x=1" }},
		{name: "fragment", mutate: func(u *url.URL) { u.Fragment = "fragment" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newServiceRoundTripperTestRequest(t)
			test.mutate(request.URL)
			calls := 0
			client := &serviceRoundTripper{
				next: fakeRoundTripper(func(*http.Request) (*http.Response, error) {
					calls++
					return nil, nil
				}),
				host:    serviceEndpointHost("us-east-1", "ssm"),
				backend: "ssm",
			}
			if _, err := client.RoundTrip(request); !errors.Is(err, ErrProvider) || calls != 0 {
				t.Fatal("noncanonical request reached the fake service transport")
			}
		})
	}
}

func TestServiceRoundTripperRejectsWrongServiceTargetBeforeTransport(t *testing.T) {
	request := newServiceRoundTripperTestRequest(t)
	request.URL.Host = serviceEndpointHost("us-east-1", "secretsmanager")
	request.Header.Set("X-Amz-Target", "AmazonSSM.GetParameter")
	calls := 0
	client := &serviceRoundTripper{
		next: fakeRoundTripper(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, nil
		}),
		host:    serviceEndpointHost("us-east-1", "secretsmanager"),
		backend: "secretsmanager",
	}
	if _, err := client.RoundTrip(request); !errors.Is(err, ErrProvider) || calls != 0 {
		t.Fatal("wrong service target reached the fake transport")
	}
}

func newServiceRoundTripperTestRequest(t *testing.T) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://ssm.us-east-1.amazonaws.com/", strings.NewReader("{}"))
	if err != nil {
		t.Fatal("synthetic service request construction failed")
	}
	request.Header.Set("X-Amz-Target", "AmazonSSM.GetParameter")
	return request
}

func hasCanonicalRootRequestPath(request *http.Request) bool {
	return request != nil && request.URL != nil && request.URL.Path == "/" && request.URL.EscapedPath() == "/" && (request.URL.RawPath == "" || request.URL.RawPath == "/")
}

func TestServiceClientsMakeOneReadAttemptWithoutSDKRetries(t *testing.T) {
	for _, backend := range []string{"secretsmanager", "ssm"} {
		calls := 0
		canonicalRootCalls := 0
		nonCanonicalRootCalls := 0
		body := `{"__type":"SyntheticFailure","message":"synthetic"}`
		transport := fakeRoundTripper(func(request *http.Request) (*http.Response, error) {
			calls++
			if hasCanonicalRootRequestPath(request) {
				canonicalRootCalls++
			} else {
				nonCanonicalRootCalls++
			}
			if request.Method != http.MethodPost || request.URL.Host != serviceEndpointHost("us-east-1", backend) || request.URL.Scheme != "https" {
				t.Fatal("service request escaped its fixed AWS HTTPS endpoint")
			}
			return &http.Response{
				StatusCode:    http.StatusInternalServerError,
				Status:        "500 synthetic",
				Header:        make(http.Header),
				Body:          io.NopCloser(strings.NewReader(body)),
				ContentLength: int64(len(body)),
				Request:       request,
			}, nil
		})
		httpClient := newServiceHTTPClientWithRoundTripper("us-east-1", backend, transport)
		if backend == "secretsmanager" {
			service := secretsmanager.New(secretsmanager.Options{
				Region: "us-east-1", Credentials: fakeCredentialProvider{}, HTTPClient: httpClient,
				Retryer: aws.NopRetryer{}, RetryMaxAttempts: 1,
				ClientLogMode: 0, Logger: logging.Nop{},
			})
			_, _ = service.GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{SecretId: aws.String("synthetic")})
		} else {
			service := ssm.New(ssm.Options{
				Region: "us-east-1", Credentials: fakeCredentialProvider{}, HTTPClient: httpClient,
				Retryer: aws.NopRetryer{}, RetryMaxAttempts: 1,
				ClientLogMode: 0, Logger: logging.Nop{},
			})
			withDecryption := true
			_, _ = service.GetParameter(context.Background(), &ssm.GetParameterInput{Name: aws.String("synthetic"), WithDecryption: &withDecryption})
		}
		if calls != 1 {
			t.Fatalf("expected one service transport call, observed %d", calls)
		}
		if canonicalRootCalls != calls || nonCanonicalRootCalls != 0 {
			t.Fatal("SDK-backed service request did not use a canonical root path")
		}
	}
}

func TestSuccessfulSDKPayloadsAreNotSentToRecordingLogger(t *testing.T) {
	const payloadCanary = "SYNTHETIC_SECRET_LOG_CANARY"
	for _, backend := range []string{"secretsmanager", "ssm"} {
		logger := &countingLogger{}
		calls := 0
		canonicalRootCalls := 0
		nonCanonicalRootCalls := 0
		transport := fakeRoundTripper(func(request *http.Request) (*http.Response, error) {
			calls++
			if hasCanonicalRootRequestPath(request) {
				canonicalRootCalls++
			} else {
				nonCanonicalRootCalls++
			}
			body := `{"SecretString":"` + payloadCanary + `"}`
			if backend == "ssm" {
				body = `{"Parameter":{"Name":"/synthetic","Type":"SecureString","Value":"` + payloadCanary + `","Version":7}}`
			}
			header := make(http.Header)
			header.Set("Content-Type", "application/x-amz-json-1.1")
			return &http.Response{
				StatusCode:    http.StatusOK,
				Status:        "200 OK",
				Header:        header,
				Body:          io.NopCloser(strings.NewReader(body)),
				ContentLength: int64(len(body)),
				Request:       request,
			}, nil
		})
		httpClient := newServiceHTTPClientWithRoundTripper("us-east-1", backend, transport)
		var value string
		if backend == "secretsmanager" {
			service := secretsmanager.New(secretsmanager.Options{
				Region: "us-east-1", Credentials: fakeCredentialProvider{}, HTTPClient: httpClient,
				Retryer: aws.NopRetryer{}, RetryMaxAttempts: 1, ClientLogMode: 0, Logger: logger,
			})
			output, err := service.GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{SecretId: aws.String("synthetic")})
			fieldPresent := output != nil && output.SecretString != nil
			fieldLength := 0
			if fieldPresent {
				fieldLength = len(*output.SecretString)
			}
			if err != nil || !fieldPresent || fieldLength != len(payloadCanary) || *output.SecretString != payloadCanary {
				t.Fatalf("synthetic Secrets Manager response decode failed: error_type=%T provider_error=%t credentials_error=%t field_present=%t field_length=%d logger_calls=%d", err, errors.Is(err, ErrProvider), errors.Is(err, ErrCredentials), fieldPresent, fieldLength, logger.calls)
			}
			value = *output.SecretString
		} else {
			service := ssm.New(ssm.Options{
				Region: "us-east-1", Credentials: fakeCredentialProvider{}, HTTPClient: httpClient,
				Retryer: aws.NopRetryer{}, RetryMaxAttempts: 1, ClientLogMode: 0, Logger: logger,
			})
			output, err := service.GetParameter(context.Background(), &ssm.GetParameterInput{Name: aws.String("/synthetic")})
			fieldPresent := output != nil && output.Parameter != nil && output.Parameter.Value != nil
			fieldLength := 0
			if fieldPresent {
				fieldLength = len(*output.Parameter.Value)
			}
			if err != nil || !fieldPresent || fieldLength != len(payloadCanary) || *output.Parameter.Value != payloadCanary {
				t.Fatalf("synthetic SSM response decode failed: error_type=%T provider_error=%t credentials_error=%t field_present=%t field_length=%d logger_calls=%d", err, errors.Is(err, ErrProvider), errors.Is(err, ErrCredentials), fieldPresent, fieldLength, logger.calls)
			}
			value = *output.Parameter.Value
		}
		if canonicalRootCalls != calls || nonCanonicalRootCalls != 0 {
			t.Fatal("SDK-backed service request did not use a canonical root path")
		}
		if value != payloadCanary || logger.calls != 0 {
			t.Fatal("SDK logging received the synthetic secret response")
		}
	}
}

func TestTransportsRejectUnexpectedContentEncoding(t *testing.T) {
	encodedResponse := func(request *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("Content-Encoding", "gzip")
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader("synthetic")), Request: request}, nil
	}
	imdsRequest, err := http.NewRequest(http.MethodGet, metadataEndpoint+"/latest/meta-data/iam/security-credentials/", nil)
	if err != nil {
		t.Fatal("synthetic metadata request construction failed")
	}
	if _, err := (&imdsRoundTripper{next: fakeRoundTripper(encodedResponse)}).RoundTrip(imdsRequest); !errors.Is(err, errUnexpectedEncoding) {
		t.Fatal("IMDS transport accepted unexpected content encoding")
	}
	serviceRequest, err := http.NewRequest(http.MethodPost, "https://ssm.us-east-1.amazonaws.com/", strings.NewReader("{}"))
	if err != nil {
		t.Fatal("synthetic service request construction failed")
	}
	serviceRequest.Header.Set("X-Amz-Target", "AmazonSSM.GetParameter")
	if _, err := (&serviceRoundTripper{next: fakeRoundTripper(encodedResponse), host: "ssm.us-east-1.amazonaws.com", backend: "ssm"}).RoundTrip(serviceRequest); !errors.Is(err, errUnexpectedEncoding) {
		t.Fatal("service transport accepted unexpected content encoding")
	}
}
