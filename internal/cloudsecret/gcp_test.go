//go:build !statekit_no_sdk_gcp && !statekit_no_sdks

package cloudsecret

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type fakeGCPAccess struct {
	calls int
	name  string
	resp  *secretmanagerpb.AccessSecretVersionResponse
	err   error
}

func TestFetchGCPRejectsInvalidSourceBeforeCredentialOrClientConstruction(t *testing.T) {
	if !GCPAvailable() {
		t.Fatal("GCP adapter unexpectedly unavailable in SDK-enabled build")
	}
	source := Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/INVALID/secrets/db"}
	calls := 0
	dependencies := gcpFetchDependencies{
		systemRoots: func() (*x509.CertPool, error) { calls++; return nil, ErrProvider },
		fetchToken:  func(context.Context) (string, error) { calls++; return "", ErrCredentials },
		newClient: func(context.Context, string, *x509.CertPool) (gcpAccessAPI, func(), error) {
			calls++
			return nil, nil, ErrProvider
		},
	}
	if payload, err := fetchGCPWith(context.Background(), source, dependencies); err != ErrInvalidSource || payload != nil || calls != 0 {
		t.Fatal("invalid source reached credentials/client path or returned payload")
	}
}

func TestFetchGCPRootFailurePrecedesTokenFactory(t *testing.T) {
	source := Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/db"}
	tokenCalls, clientCalls := 0, 0
	dependencies := gcpFetchDependencies{
		systemRoots: func() (*x509.CertPool, error) { return nil, ErrProvider },
		fetchToken:  func(context.Context) (string, error) { tokenCalls++; return "synthetic", nil },
		newClient: func(context.Context, string, *x509.CertPool) (gcpAccessAPI, func(), error) {
			clientCalls++
			return nil, nil, ErrProvider
		},
	}
	if payload, err := fetchGCPWith(context.Background(), source, dependencies); err != ErrProvider || payload != nil || tokenCalls != 0 || clientCalls != 0 {
		t.Fatal("TLS root failure did not stop before identity and client creation")
	}
}

func (f *fakeGCPAccess) AccessSecretVersion(_ context.Context, request *secretmanagerpb.AccessSecretVersionRequest, _ ...grpc.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	f.calls++
	if request != nil {
		f.name = request.Name
	}
	return f.resp, f.err
}

func TestReadGCPSecretMapsOneExactVersionAndValidatesCRC(t *testing.T) {
	payload := []byte("synthetic-gcp-secret")
	checksum := int64(crc32.Checksum(payload, crc32.MakeTable(crc32.Castagnoli)))
	source := Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/db", VersionID: "7"}
	client := &fakeGCPAccess{resp: &secretmanagerpb.AccessSecretVersionResponse{
		Name:    source.Resource + "/versions/7",
		Payload: &secretmanagerpb.SecretPayload{Data: payload, DataCrc32C: &checksum},
	}}
	got, err := readGCPSecret(context.Background(), client, source, "synthetic-token")
	if err != nil || string(got) != string(payload) || client.calls != 1 || client.name != source.Resource+"/versions/7" {
		t.Fatal("GCP adapter did not issue one exact-version read")
	}
}

func TestReadGCPSecretEnforcesPayloadSizeBoundary(t *testing.T) {
	source := Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/db", VersionID: "7"}
	for _, test := range []struct {
		name string
		size int
		ok   bool
	}{
		{name: "maximum accepted", size: MaxPayloadBytes, ok: true},
		{name: "over maximum rejected", size: MaxPayloadBytes + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := make([]byte, test.size)
			checksum := int64(crc32.Checksum(payload, crc32.MakeTable(crc32.Castagnoli)))
			client := &fakeGCPAccess{resp: &secretmanagerpb.AccessSecretVersionResponse{
				Name: source.Resource + "/versions/7", Payload: &secretmanagerpb.SecretPayload{Data: payload, DataCrc32C: &checksum},
			}}
			got, err := readGCPSecret(context.Background(), client, source, "synthetic-token")
			if test.ok && (err != nil || len(got) != MaxPayloadBytes) || !test.ok && (err != ErrInvalidPayload || got != nil) {
				t.Fatal("GCP payload size boundary was not enforced")
			}
		})
	}
}

func TestReadGCPSecretRejectsInvalidResponseWithoutLeakingDetails(t *testing.T) {
	const marker = "SYNTHETIC_GCP_PROVIDER_ERROR_CANARY"
	payload := []byte("synthetic")
	checksum := int64(crc32.Checksum(payload, crc32.MakeTable(crc32.Castagnoli)))
	source := Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/db", VersionAlias: "latest"}
	for _, test := range []struct {
		name string
		resp *secretmanagerpb.AccessSecretVersionResponse
		err  error
	}{
		{name: "provider error", err: errors.New(marker)},
		{name: "missing response", resp: nil},
		{name: "wrong name", resp: &secretmanagerpb.AccessSecretVersionResponse{Name: marker, Payload: &secretmanagerpb.SecretPayload{Data: payload, DataCrc32C: &checksum}}},
		{name: "missing checksum", resp: &secretmanagerpb.AccessSecretVersionResponse{Name: source.Resource + "/versions/9", Payload: &secretmanagerpb.SecretPayload{Data: payload}}},
		{name: "bad checksum", resp: &secretmanagerpb.AccessSecretVersionResponse{Name: source.Resource + "/versions/9", Payload: &secretmanagerpb.SecretPayload{Data: payload, DataCrc32C: new(int64)}}},
		{name: "missing payload", resp: &secretmanagerpb.AccessSecretVersionResponse{Name: source.Resource + "/versions/9"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeGCPAccess{resp: test.resp, err: test.err}
			_, err := readGCPSecret(context.Background(), client, source, "synthetic-token")
			if err == nil || strings.Contains(err.Error(), marker) || client.calls != 1 || client.name != source.Resource+"/versions/latest" {
				t.Fatal("GCP provider failure escaped closed error handling or version mapping")
			}
		})
	}
}

func TestReadGCPSecretAcceptsConcreteResponseForAlias(t *testing.T) {
	payload := []byte("synthetic")
	checksum := int64(crc32.Checksum(payload, crc32.MakeTable(crc32.Castagnoli)))
	source := Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/db", VersionAlias: "latest"}
	client := &fakeGCPAccess{resp: &secretmanagerpb.AccessSecretVersionResponse{
		Name: source.Resource + "/versions/42", Payload: &secretmanagerpb.SecretPayload{Data: payload, DataCrc32C: &checksum},
	}}
	if _, err := readGCPSecret(context.Background(), client, source, "synthetic-token"); err != nil || client.calls != 1 {
		t.Fatal("API response resolving an alias to its concrete version was rejected")
	}
}

func TestReadGCPSecretDefaultsToMutableLatest(t *testing.T) {
	payload := []byte("synthetic-latest")
	checksum := int64(crc32.Checksum(payload, crc32.MakeTable(crc32.Castagnoli)))
	source := Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/db"}
	client := &fakeGCPAccess{resp: &secretmanagerpb.AccessSecretVersionResponse{
		Name: source.Resource + "/versions/21", Payload: &secretmanagerpb.SecretPayload{Data: payload, DataCrc32C: &checksum},
	}}
	if _, err := readGCPSecret(context.Background(), client, source, "synthetic-token"); err != nil || client.calls != 1 || client.name != source.Resource+"/versions/latest" {
		t.Fatal("omitted selector did not map to one documented mutable latest read")
	}
}

type bufconnSecretManager struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer
	calls int
	name  string
	data  []byte
}

func (s *bufconnSecretManager) AccessSecretVersion(_ context.Context, request *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	s.calls++
	s.name = request.GetName()
	checksum := int64(crc32.Checksum(s.data, crc32.MakeTable(crc32.Castagnoli)))
	return &secretmanagerpb.AccessSecretVersionResponse{
		Name:    s.name,
		Payload: &secretmanagerpb.SecretPayload{Data: append([]byte(nil), s.data...), DataCrc32C: &checksum},
	}, nil
}

func TestReadGCPSecretUsesGeneratedRPCOverInMemoryBufconn(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	fake := &bufconnSecretManager{data: []byte("bufconn-secret")}
	secretmanagerpb.RegisterSecretManagerServiceServer(server, fake)
	go server.Serve(listener)
	defer server.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, "passthrough:///secretmanager-test",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock(),
	)
	if err != nil {
		t.Fatal("in-memory gRPC test connection failed")
	}
	defer conn.Close()
	source := Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/db", VersionID: "12"}
	got, err := readGCPSecret(ctx, secretmanagerpb.NewSecretManagerServiceClient(conn), source, "synthetic-token")
	wantName := source.Resource + "/versions/12"
	if err != nil || string(got) != "bufconn-secret" || fake.calls != 1 || fake.name != wantName {
		t.Fatal("generated GCP RPC did not make one exact in-memory read")
	}
}

type fakeGCPMetadataRoundTripper func(*http.Request) (*http.Response, error)

func (f fakeGCPMetadataRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestFetchGCPTokenUsesFixedMetadataRequestAndStrictResponse(t *testing.T) {
	calls := 0
	client := newGCPMetadataClient()
	guard := client.Transport.(*gcpMetadataRoundTripper)
	guard.next = fakeGCPMetadataRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodGet || request.URL.String() != gcpMetadataEndpoint || request.Header.Get("Metadata-Flavor") != "Google" || len(request.Header) != 1 || request.Body != nil || len(request.TransferEncoding) != 0 || request.Host != "metadata.google.internal" {
			t.Fatal("GCP token request did not match fixed metadata contract")
		}
		deadline, ok := request.Context().Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > gcpMetadataTimeout {
			t.Fatal("GCP token request lacked its bounded operation context")
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Metadata-Flavor": []string{"Google"}, "Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"access_token":"synthetic-token","token_type":"Bearer","expires_in":3600}`)),
		}, nil
	})
	token, err := fetchGCPToken(context.Background(), client)
	if err != nil || token != "synthetic-token" || calls != 1 {
		t.Fatal("valid synthetic token response was not accepted exactly once")
	}
}

func TestFetchGCPTokenRejectsRedirectsMalformedOrOversizedReplies(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		header http.Header
		body   string
	}{
		{name: "redirect", status: http.StatusFound, header: http.Header{"Metadata-Flavor": []string{"Google"}, "Content-Type": []string{"application/json"}}, body: `{"access_token":"synthetic","token_type":"Bearer","expires_in":3600}`},
		{name: "missing metadata response header", status: http.StatusOK, body: `{"access_token":"synthetic","token_type":"Bearer","expires_in":3600}`},
		{name: "malformed token", status: http.StatusOK, header: http.Header{"Metadata-Flavor": []string{"Google"}, "Content-Type": []string{"application/json"}}, body: `{"access_token":"synthetic","token_type":"Bearer","expires_in":0}`},
		{name: "unknown field", status: http.StatusOK, header: http.Header{"Metadata-Flavor": []string{"Google"}, "Content-Type": []string{"application/json"}}, body: `{"access_token":"synthetic","token_type":"Bearer","expires_in":3600,"extra":"x"}`},
		{name: "duplicate field", status: http.StatusOK, header: http.Header{"Metadata-Flavor": []string{"Google"}, "Content-Type": []string{"application/json"}}, body: `{"access_token":"synthetic","access_token":"other","token_type":"Bearer","expires_in":3600}`},
		{name: "wrong content type", status: http.StatusOK, header: http.Header{"Metadata-Flavor": []string{"Google"}, "Content-Type": []string{"text/plain"}}, body: `{"access_token":"synthetic","token_type":"Bearer","expires_in":3600}`},
		{name: "duplicate content type", status: http.StatusOK, header: http.Header{"Metadata-Flavor": []string{"Google"}, "Content-Type": []string{"application/json", "application/json"}}, body: `{"access_token":"synthetic","token_type":"Bearer","expires_in":3600}`},
		{name: "duplicate content encoding", status: http.StatusOK, header: http.Header{"Metadata-Flavor": []string{"Google"}, "Content-Type": []string{"application/json"}, "Content-Encoding": []string{"gzip", "identity"}}, body: `{"access_token":"synthetic","token_type":"Bearer","expires_in":3600}`},
		{name: "oversized", status: http.StatusOK, header: http.Header{"Metadata-Flavor": []string{"Google"}, "Content-Type": []string{"application/json"}}, body: strings.Repeat("x", gcpMaxTokenReply+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: fakeGCPMetadataRoundTripper(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: test.status, Header: test.header, Body: io.NopCloser(strings.NewReader(test.body))}, nil
			})}
			if token, err := fetchGCPToken(context.Background(), client); err == nil || token != "" || calls != 1 {
				t.Fatal("unsafe synthetic metadata response was accepted or retried")
			}
		})
	}
}

func TestFetchGCPTokenExpiryAndCharacterBoundaries(t *testing.T) {
	for _, test := range []struct {
		name   string
		token  string
		expiry int
		accept bool
	}{
		{name: "minimum rejected", token: "synthetic", expiry: int((gcpCallTimeout + 2*time.Second) / time.Second)},
		{name: "minimum accepted", token: "synthetic", expiry: int((gcpCallTimeout+2*time.Second)/time.Second) + 1, accept: true},
		{name: "maximum accepted", token: "synthetic", expiry: int((24 * time.Hour) / time.Second), accept: true},
		{name: "maximum exceeded", token: "synthetic", expiry: int((24*time.Hour)/time.Second) + 1},
		{name: "space in token", token: "bad token", expiry: 3600},
		{name: "newline in token", token: "bad\ntoken", expiry: 3600},
		{name: "non ASCII token", token: "bad-☃", expiry: 3600},
		{name: "comma in token", token: "bad,token", expiry: 3600},
		{name: "colon in token", token: "bad:token", expiry: 3600},
		{name: "interior padding", token: "bad=token", expiry: 3600},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"access_token": test.token, "token_type": "Bearer", "expires_in": test.expiry})
			if err != nil {
				t.Fatal("synthetic token response encoding failed")
			}
			client := &http.Client{Transport: fakeGCPMetadataRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Metadata-Flavor": []string{"Google"}, "Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})}
			got, err := fetchGCPToken(context.Background(), client)
			if test.accept && (err != nil || got != test.token) || !test.accept && (err == nil || got != "" || strings.Contains(err.Error(), test.token)) {
				t.Fatal("metadata token expiry or character boundary was not enforced")
			}
		})
	}
}

func TestGCPTokenCredentialsAreScopedToSecureTransport(t *testing.T) {
	creds := gcpTokenCredentials{token: "synthetic-token"}
	if !creds.RequireTransportSecurity() {
		t.Fatal("GCP token credentials did not require transport security")
	}
	requestContext := credentials.NewContextWithRequestInfo(context.Background(), credentials.RequestInfo{Method: gcpAccessMethod})
	metadata, err := creds.GetRequestMetadata(requestContext, gcpAccessAudience)
	if err != nil || metadata["authorization"] != "Bearer synthetic-token" {
		t.Fatal("GCP token was not exposed solely as bearer request metadata")
	}
	for _, test := range []struct {
		name string
		ctx  context.Context
		uri  []string
	}{
		{name: "missing URI", ctx: requestContext},
		{name: "duplicate URI", ctx: requestContext, uri: []string{gcpAccessAudience, gcpAccessAudience}},
		{name: "wrong host", ctx: requestContext, uri: []string{"https://attacker.invalid/google.cloud.secretmanager.v1.SecretManagerService"}},
		{name: "noncanonical port", ctx: requestContext, uri: []string{"https://secretmanager.googleapis.com:443/google.cloud.secretmanager.v1.SecretManagerService"}},
		{name: "wrong service", ctx: requestContext, uri: []string{"https://secretmanager.googleapis.com/other.Service"}},
		{name: "wrong method", ctx: credentials.NewContextWithRequestInfo(context.Background(), credentials.RequestInfo{Method: "/google.cloud.secretmanager.v1.SecretManagerService/GetSecret"}), uri: []string{gcpAccessAudience}},
		{name: "missing request info", ctx: context.Background(), uri: []string{gcpAccessAudience}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := creds.GetRequestMetadata(test.ctx, test.uri...); err == nil {
				t.Fatal("GCP bearer token was returned for a noncanonical RPC target")
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	cancel()
	ctx = credentials.NewContextWithRequestInfo(ctx, credentials.RequestInfo{Method: gcpAccessMethod})
	if _, err := creds.GetRequestMetadata(ctx, gcpAccessAudience); err == nil {
		t.Fatal("canceled operation context was ignored")
	}
}

func TestGCPMetadataClientPinsHostIPHeadersBoundsAndNoProxy(t *testing.T) {
	client := newGCPMetadataClient()
	if client.Timeout != gcpMetadataTimeout || client.CheckRedirect == nil || !errors.Is(client.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
		t.Fatal("metadata HTTP client is missing its deadline or redirect rejection")
	}
	wrapper, ok := client.Transport.(*gcpMetadataRoundTripper)
	if !ok {
		t.Fatal("metadata transport guard is missing")
	}
	transport, ok := wrapper.next.(*http.Transport)
	if !ok || transport.Proxy != nil || !transport.DisableCompression || !transport.DisableKeepAlives || transport.MaxResponseHeaderBytes != gcpMaxTokenHeaders {
		t.Fatal("metadata transport inherited proxy/compression/keepalive or lacks response header bound")
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "attacker.invalid:80"); err == nil {
		t.Fatal("metadata dialer accepted a noncanonical destination")
	}
	calls := 0
	wrapper.next = fakeGCPMetadataRoundTripper(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, nil
	})
	request, err := http.NewRequest(http.MethodGet, "http://attacker.invalid/", nil)
	if err != nil {
		t.Fatal("synthetic request construction failed")
	}
	if _, err := wrapper.RoundTrip(request); err == nil || calls != 0 {
		t.Fatal("metadata guard forwarded an alternate endpoint")
	}
}

func TestGCPMetadataGuardRejectsNoncanonicalRequestFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "host override", mutate: func(request *http.Request) { request.Host = "attacker.invalid" }},
		{name: "host header override", mutate: func(request *http.Request) { request.Header.Set("Host", "attacker.invalid") }},
		{name: "duplicate flavor", mutate: func(request *http.Request) { request.Header.Add("Metadata-Flavor", "Google") }},
		{name: "noncanonical duplicate flavor key", mutate: func(request *http.Request) { request.Header["metadata-flavor"] = []string{"Google"} }},
		{name: "unexpected header", mutate: func(request *http.Request) { request.Header.Set("Accept", "application/json") }},
		{name: "body", mutate: func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader("body"))
			request.ContentLength = 4
		}},
		{name: "transfer encoding", mutate: func(request *http.Request) { request.TransferEncoding = []string{"chunked"} }},
		{name: "query", mutate: func(request *http.Request) { request.URL.RawQuery += "&other=value" }},
		{name: "fragment", mutate: func(request *http.Request) { request.URL.Fragment = "unexpected" }},
		{name: "port", mutate: func(request *http.Request) { request.URL.Host = "metadata.google.internal:80" }},
		{name: "path", mutate: func(request *http.Request) { request.URL.Path += "/extra" }},
		{name: "trailer", mutate: func(request *http.Request) { request.Trailer = http.Header{"X-Trailer": []string{"x"}} }},
		{name: "request URI", mutate: func(request *http.Request) { request.RequestURI = "/unexpected" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			guard := &gcpMetadataRoundTripper{next: fakeGCPMetadataRoundTripper(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, nil
			})}
			request, err := http.NewRequest(http.MethodGet, gcpMetadataEndpoint, nil)
			if err != nil {
				t.Fatal("synthetic request setup failed")
			}
			request.Header.Set("Metadata-Flavor", "Google")
			test.mutate(request)
			if _, err := guard.RoundTrip(request); err == nil || calls != 0 {
				t.Fatal("noncanonical metadata request reached transport")
			}
		})
	}
}
