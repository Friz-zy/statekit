//go:build !statekit_no_sdk_gcp && !statekit_no_sdks

package cloudsecret

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"hash/crc32"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	gcpMetadataEndpoint = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?enforce_scopes=true&scopes=https://www.googleapis.com/auth/cloud-platform"
	gcpAuthority        = "secretmanager.googleapis.com:443"
	gcpAccessAudience   = "https://secretmanager.googleapis.com/google.cloud.secretmanager.v1.SecretManagerService"
	gcpAccessMethod     = "/google.cloud.secretmanager.v1.SecretManagerService/AccessSecretVersion"
	gcpCallTimeout      = 15 * time.Second
	gcpMetadataTimeout  = 2 * time.Second
	gcpMaxTokenReply    = 16 << 10
	gcpMaxTokenHeaders  = 8 << 10
	gcpMaxRPCReply      = MaxPayloadBytes + (64 << 10)
)

type gcpAccessAPI interface {
	AccessSecretVersion(context.Context, *secretmanagerpb.AccessSecretVersionRequest, ...grpc.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
}

type gcpFetchDependencies struct {
	systemRoots func() (*x509.CertPool, error)
	fetchToken  func(context.Context) (string, error)
	newClient   func(context.Context, string, *x509.CertPool) (gcpAccessAPI, func(), error)
}

// GCPAvailable reports whether the GCP Secret Manager adapter is compiled in.
func GCPAvailable() bool { return true }

// FetchGCP performs one bounded AccessSecretVersion using an operation-scoped
// token obtained only from the fixed GCE metadata endpoint.
func FetchGCP(ctx context.Context, source Source) ([]byte, error) {
	return fetchGCPWith(ctx, source, gcpFetchDependencies{
		systemRoots: x509.SystemCertPool,
		fetchToken:  func(ctx context.Context) (string, error) { return fetchGCPToken(ctx, newGCPMetadataClient()) },
		newClient:   newGCPAccessClient,
	})
}

// fetchGCPWith is private dependency injection for side-effect-order tests;
// production supplies only the fixed metadata and gRPC factories above.
func fetchGCPWith(ctx context.Context, source Source, dependencies gcpFetchDependencies) ([]byte, error) {
	if err := ValidateSource(source); err != nil {
		return nil, err
	}
	if source.Provider != "gcp" {
		return nil, ErrUnsupported
	}
	if dependencies.systemRoots == nil || dependencies.fetchToken == nil || dependencies.newClient == nil {
		return nil, ErrProvider
	}
	callCtx, cancel := context.WithTimeout(ctx, gcpCallTimeout)
	defer cancel()
	roots, err := dependencies.systemRoots()
	if err != nil || roots == nil {
		return nil, ErrProvider
	}
	token, err := dependencies.fetchToken(callCtx)
	if err != nil || token == "" {
		return nil, ErrCredentials
	}
	client, closeClient, err := dependencies.newClient(callCtx, token, roots)
	if err != nil || client == nil {
		if closeClient != nil {
			closeClient()
		}
		return nil, ErrProvider
	}
	if closeClient != nil {
		defer closeClient()
	}
	return readGCPSecret(callCtx, client, source, token)
}

func newGCPAccessClient(ctx context.Context, token string, roots *x509.CertPool) (gcpAccessAPI, func(), error) {
	conn, err := newGCPConnection(ctx, token, roots, gcpAuthority, gcpAccessMethod)
	if err != nil {
		return nil, nil, err
	}
	return secretmanagerpb.NewSecretManagerServiceClient(conn), func() { _ = conn.Close() }, nil
}

// newGCPConnection and the metadata identity helper below are shared by the two
// bounded GCP reads. Neither uses ADC, GAPIC defaults, mTLS or certificate discovery.
func newGCPConnection(ctx context.Context, token string, roots *x509.CertPool, authority, method string) (*grpc.ClientConn, error) {
	if roots == nil || token == "" {
		return nil, ErrProvider
	}
	creds := gcpTokenCredentials{token: token, authority: authority, method: method}
	if !creds.validScope() {
		return nil, ErrProvider
	}
	conn, err := grpc.DialContext(ctx, authority,
		grpc.WithBlock(), grpc.WithNoProxy(), grpc.WithDisableServiceConfig(), grpc.WithDisableRetry(),
		grpc.WithPerRPCCredentials(creds),
		grpc.WithMaxHeaderListSize(16<<10),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: strings.TrimSuffix(authority, ":443"),
		})),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(gcpMaxRPCReply)),
	)
	if err != nil {
		return nil, ErrProvider
	}
	return conn, nil
}

func readGCPSecret(ctx context.Context, client gcpAccessAPI, source Source, token string) ([]byte, error) {
	if client == nil || token == "" || ValidateSource(source) != nil || source.Provider != "gcp" {
		return nil, ErrInvalidSource
	}
	selector := source.VersionID
	if selector == "" {
		selector = source.VersionAlias
	}
	if selector == "" {
		// latest is mutable; callers that need a stable version must pin VersionID.
		selector = "latest"
	}
	name := source.Resource + "/versions/" + selector
	response, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: name})
	if err != nil || response == nil || !validGCPResponseName(response.Name, source.Resource, selector) || response.Payload == nil {
		return nil, ErrProvider
	}
	data := response.Payload.Data
	if len(data) > MaxPayloadBytes {
		return nil, ErrInvalidPayload
	}
	if response.Payload.DataCrc32C == nil || *response.Payload.DataCrc32C < 0 || uint64(*response.Payload.DataCrc32C) > uint64(^uint32(0)) || uint32(*response.Payload.DataCrc32C) != crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)) {
		return nil, ErrInvalidPayload
	}
	return data, nil
}

func validGCPResponseName(name, parent, selector string) bool {
	prefix := parent + "/versions/"
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	version := strings.TrimPrefix(name, prefix)
	if validGCPVersionID(selector) {
		return version == selector
	}
	// latest is mutable; require the API to identify the concrete numeric version it read.
	return selector == "latest" && validGCPVersionID(version)
}

type gcpTokenCredentials struct{ token, authority, method string }

func (c gcpTokenCredentials) scope() (string, string) {
	if c.authority == "" && c.method == "" {
		return gcpAuthority, gcpAccessMethod
	}
	return c.authority, c.method
}

func (c gcpTokenCredentials) validScope() bool {
	authority, method := c.scope()
	if method == gcpAccessMethod {
		return authority == gcpAuthority
	}
	if method != gcpParameterMethod {
		return false
	}
	if authority == "parametermanager.googleapis.com:443" {
		return true
	}
	location := strings.TrimSuffix(strings.TrimPrefix(authority, "parametermanager."), ".rep.googleapis.com:443")
	expected, err := parameterAuthority(location)
	return err == nil && authority == expected
}

func (c gcpTokenCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	// grpc-go passes the service audience in uri and the full RPC method in
	// RequestInfo.Method; require both so the token is not reusable elsewhere.
	requestInfo, ok := credentials.RequestInfoFromContext(ctx)
	authority, method := c.scope()
	service, _, _ := strings.Cut(strings.TrimPrefix(method, "/"), "/")
	audience := "https://" + strings.TrimSuffix(authority, ":443") + "/" + service
	if err := ctx.Err(); err != nil || c.token == "" || !c.validScope() || len(uri) != 1 || uri[0] != audience || !ok || requestInfo.Method != method {
		return nil, ErrCredentials
	}
	return map[string]string{"authorization": "Bearer " + c.token}, nil
}

func (gcpTokenCredentials) RequireTransportSecurity() bool { return true }

func newGCPMetadataClient() *http.Client {
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		ResponseHeaderTimeout: gcpMetadataTimeout, MaxResponseHeaderBytes: gcpMaxTokenHeaders,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "metadata.google.internal:80" {
				return nil, ErrCredentials
			}
			return (&net.Dialer{Timeout: gcpMetadataTimeout}).DialContext(ctx, "tcp4", "169.254.169.254:80")
		},
	}
	return &http.Client{Transport: &gcpMetadataRoundTripper{next: transport}, Timeout: gcpMetadataTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type gcpMetadataRoundTripper struct{ next http.RoundTripper }

func (t *gcpMetadataRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	// This guard wraps the transport, so it sees only explicit request headers;
	// transport-generated User-Agent fields are added only after this check.
	if t == nil || t.next == nil || request == nil || request.URL == nil || request.Method != http.MethodGet || request.URL.Scheme != "http" || request.URL.Host != "metadata.google.internal" || request.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/token" || request.URL.RawPath != "" || request.URL.RawQuery != "enforce_scopes=true&scopes=https://www.googleapis.com/auth/cloud-platform" || request.URL.ForceQuery || request.URL.User != nil || request.URL.Fragment != "" || request.URL.RawFragment != "" || request.URL.Opaque != "" || request.Host != "metadata.google.internal" || request.RequestURI != "" || request.Body != nil || request.GetBody != nil || request.ContentLength != 0 || len(request.TransferEncoding) != 0 || len(request.Trailer) != 0 || request.Close || len(request.Header) != 1 || len(request.Header["Metadata-Flavor"]) != 1 || request.Header["Metadata-Flavor"][0] != "Google" {
		return nil, ErrCredentials
	}
	response, err := t.next.RoundTrip(request)
	if err != nil || response == nil {
		return nil, ErrCredentials
	}
	return response, nil
}

func fetchGCPToken(ctx context.Context, client *http.Client) (string, error) {
	if client == nil {
		return "", ErrCredentials
	}
	defer client.CloseIdleConnections()
	requestCtx, cancel := context.WithTimeout(ctx, gcpMetadataTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, gcpMetadataEndpoint, nil)
	if err != nil {
		return "", ErrCredentials
	}
	request.Header.Set("Metadata-Flavor", "Google")
	response, err := client.Do(request)
	if err != nil || response == nil || response.Body == nil {
		return "", ErrCredentials
	}
	defer response.Body.Close()
	mediaType, _, mediaTypeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || len(response.Header.Values("Metadata-Flavor")) != 1 || response.Header.Get("Metadata-Flavor") != "Google" || len(response.Header.Values("Content-Type")) != 1 || mediaTypeErr != nil || mediaType != "application/json" || len(response.Header.Values("Content-Encoding")) != 0 || response.ContentLength > gcpMaxTokenReply {
		return "", ErrCredentials
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, gcpMaxTokenReply+1))
	if err != nil || len(body) == 0 || len(body) > gcpMaxTokenReply {
		return "", ErrCredentials
	}
	parsed, err := parseJSON(body)
	if err != nil {
		return "", ErrCredentials
	}
	fields, ok := parsed.(map[string]any)
	if !ok || len(fields) != 3 {
		return "", ErrCredentials
	}
	accessToken, tokenOK := fields["access_token"].(string)
	tokenType, typeOK := fields["token_type"].(string)
	expiresText, expiresOK := fields["expires_in"].(json.Number)
	expiresIn, expiresErr := expiresText.Int64()
	if !tokenOK || !typeOK || !expiresOK || expiresErr != nil || accessToken == "" || tokenType != "Bearer" || expiresIn <= int64((gcpCallTimeout+2*time.Second)/time.Second) || expiresIn > int64((24*time.Hour)/time.Second) {
		return "", ErrCredentials
	}
	if !validGCPAccessToken(accessToken) {
		return "", ErrCredentials
	}
	return accessToken, nil
}

func validGCPAccessToken(token string) bool {
	if token == "" || token[0] == '=' {
		return false
	}
	padding := false
	for i := 0; i < len(token); i++ {
		c := token[i]
		if c == '=' {
			padding = true
			continue
		}
		if padding || !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~+/", rune(c))) {
			return false
		}
	}
	return true
}

var _ credentials.PerRPCCredentials = gcpTokenCredentials{}
