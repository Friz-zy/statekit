//go:build !statekit_no_sdk_aws && !statekit_no_sdks

package cloudsecret

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/smithy-go/logging"
)

const (
	metadataEndpoint       = "http://169.254.169.254"
	metadataListPath       = "/iam/security-credentials/"
	maxRoleListBytes       = 4096
	maxRoleCredBytes       = 16 << 10
	maxServiceReply        = 2*MaxPayloadBytes + (64 << 10)
	awsCallTimeout         = 15 * time.Second
	credentialSafetyWindow = 30 * time.Second
)

type secretManagerAPI interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type parameterStoreAPI interface {
	GetParameter(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// AWSAvailable reports whether the AWS SDK adapter was compiled in. The
// statekit_no_sdk_aws tag disables AWS; statekit_no_sdks disables all optional SDK adapters.
func AWSAvailable() bool { return true }

// FetchAWS performs one source read using only current EC2 instance-profile
// credentials. It deliberately does not create an SDK default configuration or
// credentials cache.
func FetchAWS(ctx context.Context, source Source) (payload []byte, err error) {
	defer func() {
		if recover() != nil {
			payload = nil
			err = ErrProvider
		}
	}()
	if err := ValidateSource(source); err != nil {
		return nil, err
	}
	if source.Provider != "aws" {
		return nil, ErrUnsupported
	}
	callCtx, cancel := context.WithTimeout(ctx, awsCallTimeout)
	defer cancel()
	credentials, err := instanceProfileCredentials(callCtx, newIMDSClient())
	if err != nil {
		return nil, ErrCredentials
	}
	credentialProvider := &credentialSnapshot{value: credentials}
	switch source.Backend {
	case "secretsmanager":
		client := secretsmanager.New(secretsmanager.Options{
			Region:                     source.Region,
			Credentials:                credentialProvider,
			HTTPClient:                 newServiceHTTPClient(source.Region, source.Backend),
			Retryer:                    aws.NopRetryer{},
			RetryMaxAttempts:           1,
			DisableClockSkewCorrection: true,
			ClientLogMode:              0,
			Logger:                     logging.Nop{},
		})
		return readSecretsManager(callCtx, client, source)
	case "ssm":
		client := ssm.New(ssm.Options{
			Region:                     source.Region,
			Credentials:                credentialProvider,
			HTTPClient:                 newServiceHTTPClient(source.Region, source.Backend),
			Retryer:                    aws.NopRetryer{},
			RetryMaxAttempts:           1,
			DisableClockSkewCorrection: true,
			ClientLogMode:              0,
			Logger:                     logging.Nop{},
		})
		return readSSM(callCtx, client, source)
	default:
		return nil, ErrUnsupported
	}
}

func readSecretsManager(ctx context.Context, client secretManagerAPI, source Source) ([]byte, error) {
	if client == nil || ValidateSource(source) != nil || source.Backend != "secretsmanager" {
		return nil, ErrInvalidSource
	}
	input := &secretsmanager.GetSecretValueInput{SecretId: aws.String(source.Resource)}
	if source.VersionID != "" {
		input.VersionId = aws.String(source.VersionID)
	}
	if source.VersionAlias != "" {
		input.VersionStage = aws.String(source.VersionAlias)
	}
	output, err := client.GetSecretValue(ctx, input)
	if err != nil {
		if errors.Is(err, ErrCredentials) || errors.Is(err, errCredentialExpired) {
			return nil, ErrCredentials
		}
		return nil, ErrProvider
	}
	if output == nil || (output.SecretString != nil && output.SecretBinary != nil) {
		return nil, ErrProvider
	}
	if output.SecretString != nil {
		if len(*output.SecretString) > MaxPayloadBytes {
			return nil, ErrInvalidPayload
		}
		return []byte(*output.SecretString), nil
	}
	if output.SecretBinary != nil {
		if len(output.SecretBinary) > MaxPayloadBytes {
			return nil, ErrInvalidPayload
		}
		return append([]byte(nil), output.SecretBinary...), nil
	}
	return nil, ErrProvider
}

func readSSM(ctx context.Context, client parameterStoreAPI, source Source) ([]byte, error) {
	if client == nil || ValidateSource(source) != nil || source.Backend != "ssm" {
		return nil, ErrInvalidSource
	}
	name := source.Resource
	if source.VersionID != "" {
		name += ":" + source.VersionID
	}
	withDecryption := true
	output, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: &withDecryption,
	})
	if err != nil {
		if errors.Is(err, ErrCredentials) || errors.Is(err, errCredentialExpired) {
			return nil, ErrCredentials
		}
		return nil, ErrProvider
	}
	if output == nil || output.Parameter == nil || output.Parameter.Value == nil {
		return nil, ErrProvider
	}
	if len(*output.Parameter.Value) > MaxPayloadBytes {
		return nil, ErrInvalidPayload
	}
	return []byte(*output.Parameter.Value), nil
}

type credentialSnapshot struct{ value aws.Credentials }

func (p *credentialSnapshot) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if err := ctx.Err(); err != nil {
		return aws.Credentials{}, ErrCredentials
	}
	if !p.value.CanExpire || !p.value.Expires.After(time.Now().Add(credentialSafetyWindow)) || p.value.AccessKeyID == "" || p.value.SecretAccessKey == "" || p.value.SessionToken == "" {
		return aws.Credentials{}, errCredentialExpired
	}
	return p.value, nil
}

func instanceProfileCredentials(ctx context.Context, client ec2rolecreds.GetMetadataAPIClient) (aws.Credentials, error) {
	if client == nil {
		return aws.Credentials{}, ErrCredentials
	}
	guarded := &singleRoleMetadata{client: client}
	provider := ec2rolecreds.New(func(options *ec2rolecreds.Options) {
		options.Client = guarded
	})
	credentials, err := provider.Retrieve(ctx)
	if err != nil || !credentials.CanExpire || !credentials.Expires.After(time.Now().Add(credentialSafetyWindow)) || credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" || credentials.SessionToken == "" {
		return aws.Credentials{}, ErrCredentials
	}
	return credentials, nil
}

type singleRoleMetadata struct {
	client          ec2rolecreds.GetMetadataAPIClient
	role            string
	listRead        bool
	credentialsRead bool
}

func (m *singleRoleMetadata) GetMetadata(ctx context.Context, input *imds.GetMetadataInput, options ...func(*imds.Options)) (*imds.GetMetadataOutput, error) {
	if input == nil {
		return nil, ErrCredentials
	}
	if input.Path == metadataListPath && !m.listRead {
		response, err := m.client.GetMetadata(ctx, input, options...)
		if err != nil || response == nil || response.Content == nil {
			return nil, ErrCredentials
		}
		body, err := readAndCloseBounded(response.Content, maxRoleListBytes)
		if err != nil {
			return nil, ErrCredentials
		}
		role := strings.TrimSuffix(string(body), "\n")
		if !validRole(role) || strings.ContainsAny(role, "\r\n") {
			return nil, ErrCredentials
		}
		m.role = role
		m.listRead = true
		return &imds.GetMetadataOutput{Content: io.NopCloser(bytes.NewReader([]byte(role)))}, nil
	}
	if m.listRead && !m.credentialsRead && input.Path == metadataListPath+m.role {
		response, err := m.client.GetMetadata(ctx, input, options...)
		if err != nil || response == nil || response.Content == nil {
			return nil, ErrCredentials
		}
		body, err := readAndCloseBounded(response.Content, maxRoleCredBytes)
		if err != nil || !validRoleCredentialDocument(body) {
			return nil, ErrCredentials
		}
		m.credentialsRead = true
		return &imds.GetMetadataOutput{Content: io.NopCloser(bytes.NewReader(body))}, nil
	}
	return nil, ErrCredentials
}

func validRole(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("+=,.@_-", rune(c))) {
			return false
		}
	}
	return true
}

func validRoleCredentialDocument(body []byte) bool {
	value, err := parseJSON(body)
	if err != nil {
		return false
	}
	document, ok := value.(map[string]any)
	if !ok {
		return false
	}
	allowed := map[string]bool{
		"Code": true, "AccessKeyId": true, "SecretAccessKey": true, "Token": true,
		"Expiration": true, "LastUpdated": true, "Type": true,
	}
	for key, value := range document {
		if !allowed[key] {
			return false
		}
		if _, ok := value.(string); !ok {
			return false
		}
	}
	stringField := func(name string) string {
		value, _ := document[name].(string)
		return value
	}
	if stringField("Code") != "Success" || stringField("AccessKeyId") == "" || stringField("SecretAccessKey") == "" || stringField("Token") == "" {
		return false
	}
	expires, err := time.Parse(time.RFC3339, stringField("Expiration"))
	return err == nil && expires.After(time.Now())
}

func readAndCloseBounded(reader io.ReadCloser, limit int) ([]byte, error) {
	defer reader.Close()
	body, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil || len(body) > limit {
		return nil, ErrCredentials
	}
	return body, nil
}

func newIMDSClient() *imds.Client {
	return newIMDSClientWithHTTPClient(newIMDSHTTPClient())
}

func newIMDSClientWithHTTPClient(client imds.HTTPClient) *imds.Client {
	return newIMDSClientWithLogger(client, logging.Nop{})
}

func newIMDSClientWithLogger(client imds.HTTPClient, logger logging.Logger) *imds.Client {
	if client == nil || logger == nil {
		return nil
	}
	return imds.New(imds.Options{
		Endpoint:                 metadataEndpoint,
		HTTPClient:               client,
		ClientLogMode:            0,
		Logger:                   logger,
		Retryer:                  aws.NopRetryer{},
		ClientEnableState:        imds.ClientEnabled,
		EnableFallback:           aws.FalseTernary,
		DisableDefaultMaxBackoff: true,
		DisableDefaultTimeout:    false,
	})
}

func newIMDSHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		DisableCompression:    true,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 2 * time.Second,
		TLSHandshakeTimeout:   2 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if (network != "tcp" && network != "tcp4") || address != "169.254.169.254:80" {
				return nil, ErrCredentials
			}
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, address)
		},
	}
	return &http.Client{
		Transport: &imdsRoundTripper{next: transport},
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type imdsRoundTripper struct{ next http.RoundTripper }

func (t *imdsRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.URL.Scheme != "http" || request.URL.Host != "169.254.169.254" || request.URL.User != nil || request.URL.RawPath != "" || request.URL.Opaque != "" || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.Fragment != "" {
		return nil, ErrCredentials
	}
	max := maxRoleCredBytes
	switch {
	case request.Method == http.MethodPut && request.URL.Path == "/latest/api/token":
		max = 2048
	case request.Method == http.MethodGet && request.URL.Path == "/latest/meta-data/iam/security-credentials/":
		max = maxRoleListBytes
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/latest/meta-data/iam/security-credentials/"):
		role := strings.TrimPrefix(request.URL.Path, "/latest/meta-data/iam/security-credentials/")
		if !validRole(role) {
			return nil, ErrCredentials
		}
	default:
		return nil, ErrCredentials
	}
	response, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, ErrCredentials
	}
	if response == nil || response.Body == nil || response.Header.Get("Content-Encoding") != "" {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, errUnexpectedEncoding
	}
	response.Body = &boundedReadCloser{ReadCloser: response.Body, remaining: int64(max)}
	return response, nil
}

func newServiceHTTPClient(region, backend string) *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		DisableCompression:    true,
		DisableKeepAlives:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return newServiceHTTPClientWithRoundTripper(region, backend, transport)
}

func newServiceHTTPClientWithRoundTripper(region, backend string, next http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: &serviceRoundTripper{next: next, host: serviceEndpointHost(region, backend), backend: backend},
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type serviceRoundTripper struct {
	next    http.RoundTripper
	host    string
	backend string
}

func (t *serviceRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	target := "secretsmanager.GetSecretValue"
	if t.backend == "ssm" {
		target = "AmazonSSM.GetParameter"
	}
	if request == nil || request.URL == nil || request.Method != http.MethodPost || request.URL.Scheme != "https" || request.URL.Host != t.host || request.URL.User != nil || !canonicalServiceRootPath(request.URL.Path, request.URL.RawPath, request.URL.EscapedPath()) || request.URL.Opaque != "" || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.Fragment != "" || request.Header.Get("X-Amz-Target") != target || request.Header.Get("Content-Encoding") != "" {
		return nil, ErrProvider
	}
	response, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, ErrProvider
	}
	if response == nil || response.Body == nil || response.Header.Get("Content-Encoding") != "" {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, errUnexpectedEncoding
	}
	response.Body = &boundedReadCloser{ReadCloser: response.Body, remaining: maxServiceReply}
	return response, nil
}

// The pinned AWS SDK v2 can represent the root path with RawPath="/"; accept
// only that form or an empty RawPath when both paths resolve exactly to "/".
func canonicalServiceRootPath(path, rawPath, escapedPath string) bool {
	if path != "/" || escapedPath != "/" {
		return false
	}
	return rawPath == "" || rawPath == "/"
}

type boundedReadCloser struct {
	io.ReadCloser
	remaining int64
	checked   bool
}

func (r *boundedReadCloser) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		if r.checked {
			return 0, errResponseTooLarge
		}
		r.checked = true
		var extra [1]byte
		n, err := r.ReadCloser.Read(extra[:])
		if n > 0 {
			return 0, errResponseTooLarge
		}
		if err != nil {
			return 0, err
		}
		return 0, errResponseTooLarge
	}
	if int64(len(p)) > r.remaining {
		p = p[:int(r.remaining)]
	}
	n, err := r.ReadCloser.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func serviceEndpointHost(region, backend string) string {
	partitionSuffix := "amazonaws.com"
	switch {
	case strings.HasPrefix(region, "cn-"):
		partitionSuffix = "amazonaws.com.cn"
	case strings.HasPrefix(region, "us-isob-"):
		partitionSuffix = "sc2s.sgov.gov"
	case strings.HasPrefix(region, "us-iso-"):
		partitionSuffix = "c2s.ic.gov"
	}
	return backend + "." + region + "." + partitionSuffix
}
