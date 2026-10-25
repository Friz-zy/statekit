//go:build !statekit_no_sdk_azure && !statekit_no_sdks

package cloudsecret

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azappconfig "github.com/Azure/azure-sdk-for-go/sdk/data/azappconfig/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// Everything in this file runs offline against fakes: no socket is opened
// to IMDS or Azure, no real identity is consulted, and every payload is a
// synthetic canary, never a real secret.

const azureIMDSBodyMarker = "AZURE_IMDS_CANARY_NOT_FOR_ERRORS"

type fakeAzureHTTPResponse struct {
	status int
	header http.Header
	body   string
	err    error
}

type fakeAzureRoundTripper struct {
	calls     int
	requests  []*http.Request
	responses []fakeAzureHTTPResponse
}

func (f *fakeAzureRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	f.calls++
	f.requests = append(f.requests, request.Clone(request.Context()))
	if len(f.responses) == 0 {
		return nil, ErrCredentials
	}
	next := f.responses[0]
	f.responses = f.responses[1:]
	if next.err != nil {
		return nil, next.err
	}
	header := next.header
	if header == nil {
		header = http.Header{"Content-Type": []string{"application/json"}}
	}
	return &http.Response{
		StatusCode:    next.status,
		Header:        header.Clone(),
		Body:          io.NopCloser(strings.NewReader(next.body)),
		ContentLength: int64(len(next.body)),
	}, nil
}

func newAzureTestCredential(fake *fakeAzureRoundTripper, clientID string) *azureIMDSCredential {
	return &azureIMDSCredential{
		clientID: clientID,
		client: &http.Client{
			Transport: fake,
			Timeout:   5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func azureTokenDocument(token, tokenType, expiresIn, clientID string) string {
	document := `{"access_token":"` + token + `","token_type":"` + tokenType + `","expires_in":"` + expiresIn + `"`
	if clientID != "" {
		document += `,"client_id":"` + clientID + `"`
	}
	return document + "}"
}

// azureChallengeHeader returns a response header carrying the given
// WWW-Authenticate challenge under the canonical MIME key the pinned Key
// Vault challenge policy reads: Header.Get canonicalizes its lookup key to
// "Www-Authenticate", while literal map keys and Header.Clone are stored
// and copied verbatim.
func azureChallengeHeader(challenge string) http.Header {
	header := http.Header{}
	header.Set("WWW-Authenticate", challenge)
	return header
}

func TestAzureAvailableInSDKBuild(t *testing.T) {
	if !AzureAvailable() {
		t.Fatal("Azure adapter unexpectedly unavailable in SDK-enabled build")
	}
}

func TestAzureIMDSCredentialRequestsFixedVaultResource(t *testing.T) {
	fake := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{status: http.StatusOK, body: azureTokenDocument("synthetic-token", "Bearer", "3599", "")},
	}}
	credential := newAzureTestCredential(fake, "")
	token, err := credential.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{azureKeyVaultScope}})
	if err != nil || token.Token != "synthetic-token" {
		t.Fatalf("fixed-IMDS credential did not return the synthetic token: %v", err)
	}
	if fake.calls != 1 {
		t.Fatalf("expected exactly one IMDS request, got %d", fake.calls)
	}
	request := fake.requests[0]
	if request.Method != http.MethodGet || request.URL.Scheme != "http" || request.URL.Host != "169.254.169.254" || request.URL.Path != "/metadata/identity/oauth2/token" {
		t.Fatal("IMDS request target deviated from the fixed contract")
	}
	if query := request.URL.Query().Encode(); query != "api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net" {
		t.Fatalf("IMDS query deviated from the fixed contract: %q", query)
	}
	if len(request.Header.Values("Metadata")) != 1 || request.Header.Get("Metadata") != "true" {
		t.Fatal("IMDS request must carry exactly one Metadata: true header")
	}
	if !token.ExpiresOn.After(time.Now()) {
		t.Fatal("returned token is already expired")
	}
}

func TestAzureIMDSCredentialRequestsAppConfigResourceWithClientID(t *testing.T) {
	const clientID = "11111111-2222-3333-4444-555555555555"
	fake := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{status: http.StatusOK, body: azureTokenDocument("synthetic-token", "Bearer", "3599", clientID)},
	}}
	credential := newAzureTestCredential(fake, clientID)
	if _, err := credential.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{azureAppConfigScope}}); err != nil {
		t.Fatalf("appconfig scope was rejected by the fixed-IMDS credential: %v", err)
	}
	query := fake.requests[0].URL.Query().Encode()
	if query != "api-version=2018-02-01&client_id=11111111-2222-3333-4444-555555555555&resource=https%3A%2F%2Fazconfig.io" {
		t.Fatalf("user-assigned identity IMDS query deviated: %q", query)
	}
}

func TestAzureIMDSCredentialRejectsForeignScopesBeforeHTTP(t *testing.T) {
	fake := &fakeAzureRoundTripper{}
	credential := newAzureTestCredential(fake, "")
	for _, scopes := range [][]string{
		nil,
		{},
		{""},
		{"https://management.azure.com/.default"},
		{"https://vault.azure.us/.default"},
		{"https://appconfig.azure.com/.default"},
		{azureKeyVaultScope, azureAppConfigScope},
	} {
		if _, err := credential.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: scopes}); !errors.Is(err, ErrCredentials) {
			t.Fatalf("scope set %v must fail closed", scopes)
		}
	}
	if fake.calls != 0 {
		t.Fatal("scope rejection must precede any HTTP activity")
	}
}

func TestAzureIMDSCredentialRejectsInvalidClientIDBeforeHTTP(t *testing.T) {
	fake := &fakeAzureRoundTripper{}
	credential := newAzureTestCredential(fake, "not-a-guid")
	if _, err := credential.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{azureKeyVaultScope}}); !errors.Is(err, ErrCredentials) {
		t.Fatal("malformed user-assigned client id must fail closed")
	}
	if fake.calls != 0 {
		t.Fatal("client id rejection must precede any HTTP activity")
	}
}

func TestAzureIMDSCredentialHonorsContextCancellation(t *testing.T) {
	fake := &fakeAzureRoundTripper{}
	credential := newAzureTestCredential(fake, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureKeyVaultScope}}); !errors.Is(err, ErrCredentials) {
		t.Fatal("cancelled context must fail closed")
	}
	if fake.calls != 0 {
		t.Fatal("cancelled context must not reach HTTP")
	}
}

func TestAzureIMDSCredentialRejectsBadTokenDocuments(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response fakeAzureHTTPResponse
	}{
		{name: "unauthorized status", response: fakeAzureHTTPResponse{status: http.StatusUnauthorized, body: azureIMDSBodyMarker}},
		{name: "server error status", response: fakeAzureHTTPResponse{status: http.StatusServiceUnavailable, body: azureIMDSBodyMarker}},
		{name: "non-json content type", response: fakeAzureHTTPResponse{status: http.StatusOK, header: http.Header{"Content-Type": []string{"text/plain"}}, body: azureIMDSBodyMarker}},
		{name: "compressed body", response: fakeAzureHTTPResponse{status: http.StatusOK, header: http.Header{"Content-Type": []string{"application/json"}, "Content-Encoding": []string{"gzip"}}, body: azureIMDSBodyMarker}},
		{name: "malformed json", response: fakeAzureHTTPResponse{status: http.StatusOK, body: azureIMDSBodyMarker}},
		{name: "wrong token type", response: fakeAzureHTTPResponse{status: http.StatusOK, body: azureTokenDocument("synthetic-token", "basic", "3599", "")}},
		{name: "empty token", response: fakeAzureHTTPResponse{status: http.StatusOK, body: azureTokenDocument("", "Bearer", "3599", "")}},
		{name: "invalid token charset", response: fakeAzureHTTPResponse{status: http.StatusOK, body: azureTokenDocument("synthetic token with spaces", "Bearer", "3599", "")}},
		{name: "expires too soon", response: fakeAzureHTTPResponse{status: http.StatusOK, body: azureTokenDocument("synthetic-token", "Bearer", "10", "")}},
		{name: "expires too far out", response: fakeAzureHTTPResponse{status: http.StatusOK, body: azureTokenDocument("synthetic-token", "Bearer", "900000", "")}},
		{name: "oversized body", response: fakeAzureHTTPResponse{status: http.StatusOK, body: azureTokenDocument("synthetic-token", "Bearer", "3599", "") + strings.Repeat(" ", azureIMDSReplyLimit)}},
		{name: "client id echo mismatch", response: fakeAzureHTTPResponse{status: http.StatusOK, body: azureTokenDocument("synthetic-token", "Bearer", "3599", "99999999-9999-9999-9999-999999999999")}},
		{name: "client id echo wrong type", response: fakeAzureHTTPResponse{status: http.StatusOK, body: `{"access_token":"synthetic-token","token_type":"Bearer","expires_in":"3599","client_id":123}`}},
		{name: "client id echo malformed guid", response: fakeAzureHTTPResponse{status: http.StatusOK, body: azureTokenDocument("synthetic-token", "Bearer", "3599", "not-a-guid")}},
		{name: "resource echo mismatch", response: fakeAzureHTTPResponse{status: http.StatusOK, body: `{"access_token":"synthetic-token","token_type":"Bearer","expires_in":"3599","resource":"https://azconfig.io"}`}},
		{name: "resource echo wrong type", response: fakeAzureHTTPResponse{status: http.StatusOK, body: `{"access_token":"synthetic-token","token_type":"Bearer","expires_in":"3599","resource":42}`}},
		{name: "expires_on malformed", response: fakeAzureHTTPResponse{status: http.StatusOK, body: `{"access_token":"synthetic-token","token_type":"Bearer","expires_in":"3599","expires_on":"not-a-time"}`}},
		{name: "expires_on inconsistent", response: fakeAzureHTTPResponse{status: http.StatusOK, body: `{"access_token":"synthetic-token","token_type":"Bearer","expires_in":"3599","expires_on":"` + strconv.FormatInt(time.Now().Unix()-86400, 10) + `"}`}},
		{name: "expires_on wrong type", response: fakeAzureHTTPResponse{status: http.StatusOK, body: `{"access_token":"synthetic-token","token_type":"Bearer","expires_in":"3599","expires_on":42}`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{tc.response}}
			credential := newAzureTestCredential(fake, "11111111-2222-3333-4444-555555555555")
			_, err := credential.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{azureKeyVaultScope}})
			if !errors.Is(err, ErrCredentials) {
				t.Fatalf("bad IMDS document must map to the closed credential sentinel, got %v", err)
			}
			if err != nil && strings.Contains(err.Error(), azureIMDSBodyMarker) {
				t.Fatal("IMDS body content leaked into the error")
			}
		})
	}
}

func TestAzureIMDSRoundTripperRejectsTamperedRequests(t *testing.T) {
	inner := &fakeAzureRoundTripper{}
	guard := &azureIMDSRoundTripper{next: inner}
	newRequest := func(method, rawurl string) *http.Request {
		request, err := http.NewRequest(method, rawurl, nil)
		if err != nil {
			t.Fatalf("bad test url %q: %v", rawurl, err)
		}
		return request
	}
	for _, request := range []*http.Request{
		newRequest(http.MethodGet, "https://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net"),
		newRequest(http.MethodPost, "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net"),
		newRequest(http.MethodGet, "http://169.254.170.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net"),
		newRequest(http.MethodGet, "http://user@169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net"),
		newRequest(http.MethodGet, "http://169.254.169.254/metadata/identity/oauth2/token"),
		newRequest(http.MethodGet, "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https%3A%2F%2Fvault.azure.net"),
		newRequest(http.MethodGet, "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com"),
		newRequest(http.MethodGet, "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net%2F.default"),
		newRequest(http.MethodGet, "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net&extra=1"),
		newRequest(http.MethodGet, "http://169.254.169.254/computeMetadata/v1/instance"),
	} {
		if _, err := guard.RoundTrip(request); !errors.Is(err, ErrCredentials) {
			t.Fatalf("tampered IMDS request %v must be rejected before the wire", request.URL)
		}
	}
	if inner.calls != 0 {
		t.Fatal("tampered IMDS requests must never reach the transport")
	}
}

func TestAzureServiceDialRejectsNonPublicOrForeignAddresses(t *testing.T) {
	// Fail-fast fake dialer: if a validation regression ever reaches the
	// dial layer, it returns immediately with no socket; the counter turns
	// any invocation into a test failure. No production dial fallback here.
	dials := 0
	failFastDial := func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, ErrProvider
	}
	for _, tc := range []struct {
		name    string
		address string
		ips     []net.IPAddr
	}{
		{name: "private ipv4", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("10.1.2.3")}}},
		{name: "loopback", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}},
		{name: "imds link-local", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}},
		{name: "link-local ipv6", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("fe80::1")}}},
		{name: "multicast", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("224.0.0.1")}}},
		{name: "private among public", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("20.3.4.5")}, {IP: net.ParseIP("192.168.1.1")}}},
		{name: "empty resolution", address: "prod-vault.vault.azure.net:443", ips: nil},
		{name: "cgnat shared range", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("100.64.1.2")}}},
		{name: "cgnat among public", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("20.3.4.5")}, {IP: net.ParseIP("100.127.255.254")}}},
		{name: "ietf protocol assignments", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("192.0.0.8")}}},
		{name: "documentation test-net-1", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}},
		{name: "documentation test-net-2", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("198.51.100.7")}}},
		{name: "documentation test-net-3", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("203.0.113.9")}}},
		{name: "benchmarking range", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("198.18.5.4")}}},
		{name: "deprecated 6to4 relay", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("192.88.99.1")}}},
		{name: "reserved ipv4 space", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("240.1.2.3")}}},
		{name: "broadcast address", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("255.255.255.255")}}},
		{name: "ipv6 documentation range", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}}},
		{name: "ipv6 6to4 range", address: "prod-vault.vault.azure.net:443", ips: []net.IPAddr{{IP: net.ParseIP("2002:c000:204::1")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dial := azureServiceDialContext("prod-vault.vault.azure.net", func(context.Context, string) ([]net.IPAddr, error) { return tc.ips, nil }, failFastDial)
			conn, err := dial(context.Background(), "tcp", tc.address)
			if conn != nil || !errors.Is(err, ErrProvider) {
				t.Fatalf("non-public resolution must fail closed before dialing, got %v", err)
			}
			if dials != 0 {
				t.Fatal("non-public resolution must fail closed before any dial callback invocation")
			}
		})
	}
	resolved := 0
	dial := azureServiceDialContext("prod-vault.vault.azure.net", func(context.Context, string) ([]net.IPAddr, error) {
		resolved++
		return nil, ErrProvider
	}, failFastDial)
	for _, address := range []string{"evil.example:443", "prod-vault.vault.azure.net:8443", "prod-vault.vault.azure.net:80"} {
		if conn, err := dial(context.Background(), "tcp", address); conn != nil || !errors.Is(err, ErrProvider) {
			t.Fatalf("foreign dial target %s must fail before resolution", address)
		}
	}
	if resolved != 0 {
		t.Fatal("foreign dial targets must never reach the resolver")
	}
	if dials != 0 {
		t.Fatal("rejected resolutions and foreign targets must never invoke the dial callback")
	}
}

func TestAzureServiceDialDialsFirstPublicIPv4Literal(t *testing.T) {
	var dialed []string
	dial := azureServiceDialContext("prod-vault.vault.azure.net",
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("2603:1020:10:4::5")}, {IP: net.ParseIP("20.3.4.5")}, {IP: net.ParseIP("20.3.4.6")}}, nil
		},
		func(_ context.Context, _, address string) (net.Conn, error) {
			dialed = append(dialed, address)
			conn, _ := net.Pipe()
			return conn, nil
		},
	)
	conn, err := dial(context.Background(), "tcp", "prod-vault.vault.azure.net:443")
	if err != nil || conn == nil {
		t.Fatalf("validated public resolution must dial, got %v", err)
	}
	_ = conn.Close()
	if len(dialed) != 1 || dialed[0] != "20.3.4.5:443" {
		t.Fatalf("dial must target the first validated public IPv4 literal, got %v", dialed)
	}
}

func TestAzureServiceRoundTripperPinsVaultRequestShape(t *testing.T) {
	inner := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{status: http.StatusOK, body: "{}"},
		{status: http.StatusOK, body: "{}"},
	}}
	guard := &azureServiceRoundTripper{next: inner, kind: azureKeyVaultService, host: "prod-vault.vault.azure.net"}
	valid, err := http.NewRequest(http.MethodGet, "https://prod-vault.vault.azure.net/secrets/db-password?api-version=2025-07-01", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.RoundTrip(valid); err != nil || inner.calls != 1 {
		t.Fatalf("canonical Key Vault request was rejected: %v", err)
	}
	latest, err := http.NewRequest(http.MethodGet, "https://prod-vault.vault.azure.net/secrets/db-password/?api-version=2025-07-01", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.RoundTrip(latest); err != nil || inner.calls != 2 {
		t.Fatalf("SDK latest-selector trailing slash was rejected: %v", err)
	}
	for _, rawurl := range []string{
		"http://prod-vault.vault.azure.net/secrets/db-password?api-version=2025-07-01",
		"https://evil.example/secrets/db-password?api-version=2025-07-01",
		"https://user@prod-vault.vault.azure.net/secrets/db-password?api-version=2025-07-01",
		"https://prod-vault.vault.azure.net/keys/db-password?api-version=2025-07-01",
		"https://prod-vault.vault.azure.net/secrets/db%2Fpassword?api-version=2025-07-01",
		"https://prod-vault.vault.azure.net/secrets/db-password",
		"https://prod-vault.vault.azure.net/secrets/db-password?api-version=2025-07-01&label=production",
	} {
		request, err := http.NewRequest(http.MethodGet, rawurl, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := guard.RoundTrip(request); !errors.Is(err, ErrProvider) {
			t.Fatalf("off-contract Key Vault request %s must fail before the wire", rawurl)
		}
	}
	post, err := http.NewRequest(http.MethodPost, "https://prod-vault.vault.azure.net/secrets/db-password?api-version=2025-07-01", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.RoundTrip(post); !errors.Is(err, ErrProvider) {
		t.Fatal("non-GET Key Vault request must fail")
	}
	if inner.calls != 2 {
		t.Fatal("off-contract requests must never reach the transport")
	}
}

func TestAzureServiceRoundTripperPinsAppConfigRequestShape(t *testing.T) {
	inner := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{{status: http.StatusOK, body: "{}"}}}
	guard := &azureServiceRoundTripper{next: inner, kind: azureAppConfigService, host: "prod-store.azconfig.io", label: "production"}
	valid, err := http.NewRequest(http.MethodGet, "https://prod-store.azconfig.io/kv/app.setting?api-version=2026-04-01&label=production", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.RoundTrip(valid); err != nil || inner.calls != 1 {
		t.Fatalf("canonical App Config request was rejected: %v", err)
	}
	for _, rawurl := range []string{
		"https://prod-store.azconfig.io/kv/app.setting?api-version=2026-04-01",
		"https://prod-store.azconfig.io/kv/app.setting?api-version=2026-04-01&label=staging",
		"https://prod-store.azconfig.io/kv/app.setting?label=production",
		"https://prod-store.azconfig.io/kv/.hidden?api-version=2026-04-01&label=production",
		"https://prod-store.azconfig.io/revisions?api-version=2026-04-01&label=production",
	} {
		request, err := http.NewRequest(http.MethodGet, rawurl, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := guard.RoundTrip(request); !errors.Is(err, ErrProvider) {
			t.Fatalf("off-contract App Config request %s must fail before the wire", rawurl)
		}
	}
	if inner.calls != 1 {
		t.Fatal("off-contract requests must never reach the transport")
	}
}

func TestAzureServiceRoundTripperRejectsRedirectsEncodingsAndOversize(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response fakeAzureHTTPResponse
		want     error
	}{
		{
			name:     "redirect denied",
			response: fakeAzureHTTPResponse{status: http.StatusFound, header: http.Header{"Content-Type": []string{"application/json"}, "Location": []string{"https://evil.example/"}}, body: "{}"},
			want:     ErrProvider,
		},
		{
			name:     "compressed response denied",
			response: fakeAzureHTTPResponse{status: http.StatusOK, header: http.Header{"Content-Type": []string{"application/json"}, "Content-Encoding": []string{"gzip"}}, body: "{}"},
			want:     errUnexpectedEncoding,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{tc.response}}
			guard := &azureServiceRoundTripper{next: inner, kind: azureKeyVaultService, host: "prod-vault.vault.azure.net"}
			request, err := http.NewRequest(http.MethodGet, "https://prod-vault.vault.azure.net/secrets/db-password?api-version=2025-07-01", nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := guard.RoundTrip(request); !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
	inner := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{{status: http.StatusOK, body: strings.Repeat("a", azureMaxServiceReply+1)}}}
	guard := &azureServiceRoundTripper{next: inner, kind: azureKeyVaultService, host: "prod-vault.vault.azure.net"}
	request, err := http.NewRequest(http.MethodGet, "https://prod-vault.vault.azure.net/secrets/db-password?api-version=2025-07-01", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := guard.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(response.Body); !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("oversized service body must stop at the bound, got %v", err)
	}
}

type fakeAzureCredential struct{}

func (fakeAzureCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, ErrCredentials
}

type fakeAzureSecrets struct {
	calls    int
	name     string
	version  string
	response azsecrets.GetSecretResponse
	err      error
}

func (f *fakeAzureSecrets) GetSecret(_ context.Context, name, version string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	f.calls++
	f.name, f.version = name, version
	return f.response, f.err
}

func azureSecretResponse(vault, name, version, value string, enabled *bool) azsecrets.GetSecretResponse {
	id := azsecrets.ID("https://" + vault + ".vault.azure.net/secrets/" + name + "/" + version)
	var attributes *azsecrets.SecretAttributes
	if enabled != nil {
		attributes = &azsecrets.SecretAttributes{Enabled: enabled}
	}
	return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{ID: &id, Value: &value, Attributes: attributes}}
}

func TestReadAzureSecretValidatesIdentityAndVersion(t *testing.T) {
	const pinned = "0123456789abcdef0123456789abcdef"
	const latest = "fedcba9876543210fedcba9876543210"
	pinnedSource := Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db-password", VersionID: pinned}
	latestSource := Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db-password"}

	enabled := true
	happy := &fakeAzureSecrets{response: azureSecretResponse("prod-vault", "db-password", pinned, "synthetic", &enabled)}
	payload, err := readAzureSecret(context.Background(), happy, pinnedSource)
	if err != nil || string(payload) != "synthetic" || happy.calls != 1 || happy.name != "db-password" || happy.version != pinned {
		t.Fatalf("pinned Key Vault read did not map one exact version: %v", err)
	}

	latestOK := &fakeAzureSecrets{response: azureSecretResponse("prod-vault", "DB-Password", latest, "synthetic", &enabled)}
	if payload, err := readAzureSecret(context.Background(), latestOK, latestSource); err != nil || string(payload) != "synthetic" || latestOK.version != "" {
		t.Fatalf("latest Key Vault read did not pass the empty version selector: %v", err)
	}

	const providerErrorCanary = "AZURE_KV_PROVIDER_ERROR_CANARY"
	for _, tc := range []struct {
		name   string
		source Source
		secret azsecrets.Secret
		err    error
	}{
		{name: "provider error", source: latestSource, err: errors.New(providerErrorCanary)},
		{name: "missing identity", source: latestSource},
		{
			name:   "foreign vault in identity",
			source: latestSource,
			secret: azureSecretResponse("other-vault", "db-password", latest, "synthetic", nil).Secret,
		},
		{
			name:   "wrong name in identity",
			source: latestSource,
			secret: azureSecretResponse("prod-vault", "other-secret", latest, "synthetic", nil).Secret,
		},
		{
			name:   "non-hex latest version",
			source: latestSource,
			secret: azureSecretResponse("prod-vault", "db-password", "not-a-concrete-version", "synthetic", nil).Secret,
		},
		{
			name:   "pinned version mismatch",
			source: pinnedSource,
			secret: azureSecretResponse("prod-vault", "db-password", latest, "synthetic", nil).Secret,
		},
		{
			name:   "disabled secret",
			source: latestSource,
			secret: azureSecretResponse("prod-vault", "db-password", latest, "synthetic", &[]bool{false}[0]).Secret,
		},
		{
			name:   "missing value",
			source: latestSource,
			secret: func() azsecrets.Secret {
				id := azsecrets.ID("https://prod-vault.vault.azure.net/secrets/db-password/" + latest)
				return azsecrets.Secret{ID: &id}
			}(),
		},
		{
			name:   "identity with userinfo",
			source: latestSource,
			secret: func() azsecrets.Secret {
				id := azsecrets.ID("https://user@prod-vault.vault.azure.net/secrets/db-password/" + latest)
				return azsecrets.Secret{ID: &id, Value: &[]string{"synthetic"}[0]}
			}(),
		},
		{
			name:   "identity with query",
			source: latestSource,
			secret: func() azsecrets.Secret {
				id := azsecrets.ID("https://prod-vault.vault.azure.net/secrets/db-password/" + latest + "?extra=1")
				return azsecrets.Secret{ID: &id, Value: &[]string{"synthetic"}[0]}
			}(),
		},
		{
			name:   "identity with fragment",
			source: latestSource,
			secret: func() azsecrets.Secret {
				id := azsecrets.ID("https://prod-vault.vault.azure.net/secrets/db-password/" + latest + "#section")
				return azsecrets.Secret{ID: &id, Value: &[]string{"synthetic"}[0]}
			}(),
		},
		{
			name:   "identity with noncanonical escaped path",
			source: latestSource,
			secret: func() azsecrets.Secret {
				id := azsecrets.ID("https://prod-vault.vault.azure.net/secrets/db%2Dpassword/" + latest)
				return azsecrets.Secret{ID: &id, Value: &[]string{"synthetic"}[0]}
			}(),
		},
		{
			name:   "identity with extra segments",
			source: latestSource,
			secret: func() azsecrets.Secret {
				id := azsecrets.ID("https://prod-vault.vault.azure.net/secrets/db-password/" + latest + "/extra")
				return azsecrets.Secret{ID: &id, Value: &[]string{"synthetic"}[0]}
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeAzureSecrets{response: azsecrets.GetSecretResponse{Secret: tc.secret}, err: tc.err}
			payload, err := readAzureSecret(context.Background(), client, tc.source)
			if payload != nil || !errors.Is(err, ErrProvider) {
				t.Fatalf("invalid Key Vault response must fail closed, got %v", err)
			}
			if err != nil && strings.Contains(err.Error(), providerErrorCanary) {
				t.Fatal("provider error text leaked into the application error")
			}
		})
	}
}

func TestReadAzureSecretEnforcesPayloadSizeBoundary(t *testing.T) {
	const latest = "fedcba9876543210fedcba9876543210"
	source := Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db-password"}
	for _, tc := range []struct {
		name string
		size int
		ok   bool
	}{
		{name: "maximum accepted", size: MaxPayloadBytes, ok: true},
		{name: "over maximum rejected", size: MaxPayloadBytes + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeAzureSecrets{response: azureSecretResponse("prod-vault", "db-password", latest, strings.Repeat("a", tc.size), nil)}
			payload, err := readAzureSecret(context.Background(), client, source)
			if tc.ok && (err != nil || len(payload) != MaxPayloadBytes) || !tc.ok && (err != ErrInvalidPayload || payload != nil) {
				t.Fatalf("Key Vault payload boundary not enforced for size %d: %v", tc.size, err)
			}
		})
	}
}

type fakeAzureSettings struct {
	calls    int
	key      string
	label    *string
	response azappconfig.GetSettingResponse
	err      error
}

func (f *fakeAzureSettings) GetSetting(_ context.Context, key string, options *azappconfig.GetSettingOptions) (azappconfig.GetSettingResponse, error) {
	f.calls++
	f.key = key
	f.label = nil
	if options != nil {
		f.label = options.Label
	}
	return f.response, f.err
}

func azureSettingResponse(key, label, value string) azappconfig.GetSettingResponse {
	return azappconfig.GetSettingResponse{Setting: azappconfig.Setting{Key: &key, Label: &label, Value: &value}}
}

func TestReadAzureSettingRequiresExactLabeledEcho(t *testing.T) {
	source := Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", Label: "production"}

	happy := &fakeAzureSettings{response: azureSettingResponse("app.setting", "production", "synthetic")}
	payload, err := readAzureSetting(context.Background(), happy, source)
	if err != nil || string(payload) != "synthetic" || happy.calls != 1 || happy.key != "app.setting" || happy.label == nil || *happy.label != "production" {
		t.Fatalf("labeled App Config read did not request the exact label: %v", err)
	}

	// A Key Vault reference payload is ordinary data: it must be delivered
	// verbatim with no reference resolution call of any kind.
	reference := `{"uri":"https://prod-vault.vault.azure.net/secrets/ref","contentType":"application/vnd.microsoft.appconfig.keyvaultref+json"}`
	referencing := &fakeAzureSettings{response: azureSettingResponse("app.setting", "production", reference)}
	payload, err = readAzureSetting(context.Background(), referencing, source)
	if err != nil || string(payload) != reference || referencing.calls != 1 {
		t.Fatalf("Key Vault reference value must pass through unresolved: %v", err)
	}

	const providerErrorCanary = "AZURE_APPCONFIG_PROVIDER_ERROR_CANARY"
	for _, tc := range []struct {
		name     string
		response azappconfig.GetSettingResponse
		err      error
	}{
		{name: "provider error", err: errors.New(providerErrorCanary)},
		{name: "missing key echo", response: azappconfig.GetSettingResponse{Setting: azappconfig.Setting{Label: &source.Label, Value: &[]string{"synthetic"}[0]}}},
		{name: "wrong key echo", response: azureSettingResponse("other.setting", "production", "synthetic")},
		{name: "wrong label echo", response: azureSettingResponse("app.setting", "staging", "synthetic")},
		{name: "unlabeled echo", response: func() azappconfig.GetSettingResponse {
			key, value := "app.setting", "synthetic"
			return azappconfig.GetSettingResponse{Setting: azappconfig.Setting{Key: &key, Value: &value}}
		}()},
		{name: "missing value", response: func() azappconfig.GetSettingResponse {
			key, label := "app.setting", "production"
			return azappconfig.GetSettingResponse{Setting: azappconfig.Setting{Key: &key, Label: &label}}
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeAzureSettings{response: tc.response, err: tc.err}
			payload, err := readAzureSetting(context.Background(), client, source)
			if payload != nil || !errors.Is(err, ErrProvider) {
				t.Fatalf("invalid App Config response must fail closed, got %v", err)
			}
			if err != nil && strings.Contains(err.Error(), providerErrorCanary) {
				t.Fatal("provider error text leaked into the application error")
			}
		})
	}
}

func TestReadAzureSettingEnforcesPayloadSizeBoundary(t *testing.T) {
	source := Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", Label: "production"}
	for _, tc := range []struct {
		name string
		size int
		ok   bool
	}{
		{name: "maximum accepted", size: MaxPayloadBytes, ok: true},
		{name: "over maximum rejected", size: MaxPayloadBytes + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeAzureSettings{response: azureSettingResponse("app.setting", "production", strings.Repeat("a", tc.size))}
			payload, err := readAzureSetting(context.Background(), client, source)
			if tc.ok && (err != nil || len(payload) != MaxPayloadBytes) || !tc.ok && (err != ErrInvalidPayload || payload != nil) {
				t.Fatalf("App Config payload boundary not enforced for size %d: %v", tc.size, err)
			}
		})
	}
}

func TestFetchAzureKeyVaultRejectsInvalidSourceBeforeCredentialAndClient(t *testing.T) {
	credCalls, clientCalls := 0, 0
	dependencies := azureFetchDependencies{
		newCredential: func() azcore.TokenCredential {
			credCalls++
			return newAzureTestCredential(&fakeAzureRoundTripper{}, "")
		},
		newKeyVault: func(string, azcore.TokenCredential) (azureSecretsAPI, func(), error) {
			clientCalls++
			return nil, nil, ErrProvider
		},
	}
	for _, tc := range []struct {
		name   string
		source Source
		want   error
	}{
		{
			name:   "dot-in-vault-name",
			source: Source{Provider: "azure", Backend: "keyvault", Region: "prod.vault.example", Resource: "db"},
			want:   ErrInvalidSource,
		},
		{
			name:   "wrong backend",
			source: Source{Provider: "azure", Backend: "managedhsm", Region: "prod-vault", Resource: "db"},
			want:   ErrUnsupported,
		},
		{
			name:   "foreign provider",
			source: Source{Provider: "gcp", Backend: "keyvault", Region: "prod-vault", Resource: "db"},
			want:   ErrUnsupported,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := fetchAzureKeyVaultWith(context.Background(), tc.source, dependencies)
			if payload != nil || !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
	if credCalls != 0 || clientCalls != 0 {
		t.Fatal("invalid sources must never reach the credential or client factories")
	}
}

func TestFetchAzureKeyVaultUsesOneCredentialAndClientPerOperation(t *testing.T) {
	credCalls, clientCalls, closes := 0, 0, 0
	const latest = "fedcba9876543210fedcba9876543210"
	client := &fakeAzureSecrets{response: azureSecretResponse("prod-vault", "db-password", latest, "synthetic", nil)}
	dependencies := azureFetchDependencies{
		newCredential: func() azcore.TokenCredential {
			credCalls++
			return fakeAzureCredential{}
		},
		newKeyVault: func(authority string, credential azcore.TokenCredential) (azureSecretsAPI, func(), error) {
			clientCalls++
			if authority != "prod-vault.vault.azure.net" || credential == nil {
				return nil, nil, ErrProvider
			}
			return client, func() { closes++ }, nil
		},
	}
	source := Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db-password"}
	for i := 0; i < 2; i++ {
		payload, err := fetchAzureKeyVaultWith(context.Background(), source, dependencies)
		if err != nil || string(payload) != "synthetic" {
			t.Fatalf("operation %d failed: %v", i, err)
		}
	}
	if credCalls != 2 || clientCalls != 2 || closes != 2 || client.calls != 2 {
		t.Fatalf("per-operation isolation broken: credentials=%d clients=%d closes=%d reads=%d", credCalls, clientCalls, closes, client.calls)
	}
}

func TestFetchAzureAppConfigurationBuildsLabeledRead(t *testing.T) {
	credCalls, clientCalls := 0, 0
	client := &fakeAzureSettings{response: azureSettingResponse("app.setting", "production", "synthetic")}
	var authority, label string
	dependencies := azureFetchDependencies{
		newCredential: func() azcore.TokenCredential {
			credCalls++
			return fakeAzureCredential{}
		},
		newAppConfig: func(endpoint, requestLabel string, credential azcore.TokenCredential) (azureSettingsAPI, func(), error) {
			clientCalls++
			authority, label = endpoint, requestLabel
			if credential == nil {
				return nil, nil, ErrProvider
			}
			return client, func() {}, nil
		},
	}
	source := Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", Label: "production"}
	payload, err := fetchAzureAppConfigurationWith(context.Background(), source, dependencies)
	if err != nil || string(payload) != "synthetic" {
		t.Fatalf("labeled appconfig fetch failed: %v", err)
	}
	if authority != "prod-store.azconfig.io" || label != "production" {
		t.Fatalf("appconfig client built for %q label %q", authority, label)
	}
	if credCalls != 1 || clientCalls != 1 || client.calls != 1 {
		t.Fatal("appconfig fetch must use exactly one credential and one client")
	}

	unlabeled := source
	unlabeled.Label = ""
	if payload, err := fetchAzureAppConfigurationWith(context.Background(), unlabeled, dependencies); payload != nil || !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("unlabeled appconfig request must be rejected before any activity, got %v", err)
	}
	if credCalls != 1 || clientCalls != 1 {
		t.Fatal("unlabeled rejection must not construct credentials or clients")
	}
}

func TestAzurePanicInProviderPathMapsToValueFreeFailure(t *testing.T) {
	panicking := &panickingAzureSecrets{}
	dependencies := azureFetchDependencies{
		newCredential: func() azcore.TokenCredential { return fakeAzureCredential{} },
		newKeyVault: func(string, azcore.TokenCredential) (azureSecretsAPI, func(), error) {
			return panicking, func() {}, nil
		},
	}
	source := Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db-password"}
	payload, err := fetchAzureKeyVaultWith(context.Background(), source, dependencies)
	if payload != nil || !errors.Is(err, ErrProvider) {
		t.Fatalf("provider panic must map to the closed sentinel, got %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "PANIC") {
		t.Fatal("panic value leaked into the application error")
	}
}

type panickingAzureSecrets struct{}

func (panickingAzureSecrets) GetSecret(context.Context, string, string, *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	panic("AZURE_PANIC_CANARY")
}

// TestAzureIMDSProductionGuardAdmitsExactResources runs the real production
// IMDS request guard with only the wire beneath it replaced: both admitted
// resources pass with consistent echo fields, and an unknown resource fails
// before the upstream call.
func TestAzureIMDSProductionGuardAdmitsExactResources(t *testing.T) {
	for _, tc := range []struct {
		name         string
		scope        string
		clientID     string
		wantResource string
		body         string
	}{
		{
			name:         "key vault resource with consistent echoes",
			scope:        azureKeyVaultScope,
			wantResource: azureKeyVaultResource,
			body: `{"access_token":"synthetic-token","token_type":"Bearer","expires_in":"3599",` +
				`"resource":"https://vault.azure.net","expires_on":"` + strconv.FormatInt(time.Now().Unix()+3400, 10) + `"}`,
		},
		{
			name:         "app config resource with consistent client id echo",
			scope:        azureAppConfigScope,
			clientID:     "11111111-2222-3333-4444-555555555555",
			wantResource: azureAppConfigResource,
			body: `{"access_token":"synthetic-token","token_type":"Bearer","expires_in":"3599",` +
				`"resource":"https://azconfig.io","client_id":"11111111-2222-3333-4444-555555555555"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{{status: http.StatusOK, body: tc.body}}}
			credential := &azureIMDSCredential{clientID: tc.clientID, client: newAzureIMDSClientWithTransport(wire)}
			token, err := credential.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{tc.scope}})
			if err != nil || token.Token != "synthetic-token" {
				t.Fatalf("production guard rejected an exact admitted resource: %v", err)
			}
			if wire.calls != 1 {
				t.Fatalf("expected exactly one wire request, got %d", wire.calls)
			}
			if resource := wire.requests[0].URL.Query().Get("resource"); resource != tc.wantResource {
				t.Fatalf("wire saw resource %q, want %q", resource, tc.wantResource)
			}
		})
	}
}

func TestAzureIMDSProductionGuardRejectsUnknownResourceBeforeUpstream(t *testing.T) {
	wire := &fakeAzureRoundTripper{}
	credential := &azureIMDSCredential{client: newAzureIMDSClientWithTransport(wire)}
	// A tampered credential that put a scope string into the resource
	// parameter must still be stopped by the resource allowlist.
	request, err := http.NewRequest(http.MethodGet, azureIMDSEndpoint+"?api-version=2018-02-01&resource="+url.QueryEscape(azureKeyVaultScope), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Metadata", "true")
	if _, err := credential.client.Do(request); !errors.Is(err, ErrCredentials) {
		t.Fatalf("scope-as-resource must fail closed under the production guard, got %v", err)
	}
	if wire.calls != 0 {
		t.Fatal("unknown resource must fail before the upstream call")
	}
}

// TestAzureKeyVaultPipelineThroughRealClientAndGuards drives the production
// azsecrets client and both production request guards with only the wires
// replaced: an unauthenticated GetSecret elicits the 401 challenge, the
// fixed-IMDS credential answers it for the exact vault audience, and the
// authenticated replay is validated against the exact response identity.
func TestAzureKeyVaultPipelineThroughRealClientAndGuards(t *testing.T) {
	const authority = "prod-vault.vault.azure.net"
	const version = "0123456789abcdef0123456789abcdef"
	imdsWire := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{status: http.StatusOK, body: azureTokenDocument("synthetic-imds-token", "Bearer", "3599", "")},
	}}
	credential := &azureIMDSCredential{client: newAzureIMDSClientWithTransport(imdsWire)}
	vaultWire := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{
			status: http.StatusUnauthorized,
			header: azureChallengeHeader(`Bearer authorization="https://login.windows.net/11111111-1111-1111-1111-111111111111", resource="https://vault.azure.net"`),
			body:   `{"error":{"code":"Unauthorized"}}`,
		},
		{
			status: http.StatusOK,
			header: http.Header{"Content-Type": []string{"application/json"}},
			body:   `{"id":"https://prod-vault.vault.azure.net/secrets/db-password/` + version + `","value":"synthetic-kv-secret","attributes":{"enabled":true}}`,
		},
	}}
	client, closeClient, err := newAzureKeyVaultClientWithHTTPClient(authority, credential, newAzureServiceClientWithTransport(azureKeyVaultService, authority, "", vaultWire))
	if closeClient != nil {
		defer closeClient()
	}
	if err != nil {
		t.Fatalf("real Key Vault client construction failed: %v", err)
	}
	source := Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db-password"}
	payload, err := readAzureSecret(context.Background(), client, source)
	if err != nil || string(payload) != "synthetic-kv-secret" {
		t.Fatalf("real pipeline read failed: %v", err)
	}
	if vaultWire.calls != 2 || imdsWire.calls != 1 {
		t.Fatalf("expected one challenge exchange and one token request, got vault=%d imds=%d", vaultWire.calls, imdsWire.calls)
	}
	if auth := vaultWire.requests[0].Header.Get("Authorization"); auth != "" {
		t.Fatal("challenge-eliciting request must be unauthenticated")
	}
	if !strings.HasPrefix(vaultWire.requests[0].URL.Path, "/secrets/db-password") {
		t.Fatalf("unexpected secret request path %q", vaultWire.requests[0].URL.Path)
	}
	if auth := vaultWire.requests[1].Header.Get("Authorization"); auth != "Bearer synthetic-imds-token" {
		t.Fatalf("replayed request must carry the IMDS bearer token, got %q", auth)
	}
	if query := imdsWire.requests[0].URL.Query().Encode(); query != "api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net" {
		t.Fatalf("challenge answered for the wrong resource: %q", query)
	}
}

func TestAzureKeyVaultPipelineRejectsForeignChallengeResource(t *testing.T) {
	const authority = "prod-vault.vault.azure.net"
	imdsWire := &fakeAzureRoundTripper{}
	credential := &azureIMDSCredential{client: newAzureIMDSClientWithTransport(imdsWire)}
	vaultWire := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{
			status: http.StatusUnauthorized,
			header: azureChallengeHeader(`Bearer authorization="https://login.windows.net/11111111-1111-1111-1111-111111111111", resource="https://management.azure.com"`),
			body:   "{}",
		},
	}}
	client, closeClient, err := newAzureKeyVaultClientWithHTTPClient(authority, credential, newAzureServiceClientWithTransport(azureKeyVaultService, authority, "", vaultWire))
	if closeClient != nil {
		defer closeClient()
	}
	if err != nil {
		t.Fatalf("real Key Vault client construction failed: %v", err)
	}
	source := Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db-password"}
	payload, err := readAzureSecret(context.Background(), client, source)
	if payload != nil || !errors.Is(err, ErrProvider) {
		t.Fatalf("foreign challenge audience must fail closed to the provider sentinel, got %v", err)
	}
	// Explicit counters: the rejection must be the foreign audience seen in
	// the parsed challenge, not a missing or unparsed challenge. Exactly one
	// unauthenticated service request may go out and no token may be issued.
	if vaultWire.calls != 1 || imdsWire.calls != 0 {
		t.Fatalf("foreign challenge must be rejected after one unauthenticated service request and before any token issuance, got vault=%d imds=%d", vaultWire.calls, imdsWire.calls)
	}
	if auth := vaultWire.requests[0].Header.Get("Authorization"); auth != "" {
		t.Fatal("challenge-eliciting request must be unauthenticated")
	}
}

// TestAzureAppConfigPipelineThroughRealClientAndGuards drives the production
// azappconfig client and both production request guards with only the wires
// replaced: the exact GetSetting URL and label serialization cross the guard,
// the fixed-IMDS credential is consulted once for the azconfig.io audience,
// and the response echoes are validated.
func TestAzureAppConfigPipelineThroughRealClientAndGuards(t *testing.T) {
	const authority = "prod-store.azconfig.io"
	imdsWire := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{status: http.StatusOK, body: azureTokenDocument("synthetic-imds-token", "Bearer", "3599", "")},
	}}
	credential := &azureIMDSCredential{client: newAzureIMDSClientWithTransport(imdsWire)}
	settingWire := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{
			status: http.StatusOK,
			header: http.Header{"Content-Type": []string{"application/vnd.microsoft.appconfig.kv+json"}, "Sync-Token": []string{"synthetic=dmFsaWQ;sn=1"}},
			body:   `{"etag":"e1","key":"app.setting","label":"production","value":"synthetic-setting","locked":false}`,
		},
	}}
	client, closeClient, err := newAzureAppConfigClientWithHTTPClient(authority, "production", credential, newAzureServiceClientWithTransport(azureAppConfigService, authority, "production", settingWire))
	if closeClient != nil {
		defer closeClient()
	}
	if err != nil {
		t.Fatalf("real App Configuration client construction failed: %v", err)
	}
	source := Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", Label: "production"}
	payload, err := readAzureSetting(context.Background(), client, source)
	if err != nil || string(payload) != "synthetic-setting" {
		t.Fatalf("real pipeline labeled read failed: %v", err)
	}
	if settingWire.calls != 1 || imdsWire.calls != 1 {
		t.Fatalf("expected one setting request and one token request, got setting=%d imds=%d", settingWire.calls, imdsWire.calls)
	}
	request := settingWire.requests[0]
	if request.Method != http.MethodGet || request.URL.Scheme != "https" || request.URL.Host != authority {
		t.Fatalf("unexpected setting request target %v", request.URL)
	}
	if request.URL.Path != "/kv/app.setting" {
		t.Fatalf("setting request path deviated: %q", request.URL.Path)
	}
	if query := request.URL.Query().Encode(); query != "api-version=2026-04-01&label=production" {
		t.Fatalf("setting request must serialize the exact label, got %q", query)
	}
	if auth := request.Header.Get("Authorization"); auth != "Bearer synthetic-imds-token" {
		t.Fatalf("setting request must carry the IMDS bearer token, got %q", auth)
	}
	if resource := imdsWire.requests[0].URL.Query().Get("resource"); resource != azureAppConfigResource {
		t.Fatalf("token requested for the wrong resource %q", resource)
	}
}

func TestAzureAppConfigPipelineRejectsLabelEchoMismatch(t *testing.T) {
	const authority = "prod-store.azconfig.io"
	imdsWire := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{status: http.StatusOK, body: azureTokenDocument("synthetic-imds-token", "Bearer", "3599", "")},
	}}
	credential := &azureIMDSCredential{client: newAzureIMDSClientWithTransport(imdsWire)}
	settingWire := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{
			status: http.StatusOK,
			header: http.Header{"Content-Type": []string{"application/vnd.microsoft.appconfig.kv+json"}, "Sync-Token": []string{"synthetic=dmFsaWQ;sn=1"}},
			body:   `{"etag":"e1","key":"app.setting","label":"staging","value":"synthetic-setting","locked":false}`,
		},
	}}
	client, closeClient, err := newAzureAppConfigClientWithHTTPClient(authority, "production", credential, newAzureServiceClientWithTransport(azureAppConfigService, authority, "production", settingWire))
	if closeClient != nil {
		defer closeClient()
	}
	if err != nil {
		t.Fatalf("real App Configuration client construction failed: %v", err)
	}
	source := Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", Label: "production"}
	payload, err := readAzureSetting(context.Background(), client, source)
	if payload != nil || !errors.Is(err, ErrProvider) {
		t.Fatalf("label echo mismatch must fail closed to the provider sentinel, got %v", err)
	}
}

// TestAzurePipelineKeepsMarkersOutOfApplicationErrors drives the pinned
// SDK pipeline end to end over fake wires — Key Vault challenge, fixed-IMDS
// token, authenticated replay, and a labeled App Configuration read — with
// synthetic marker values in every sensitive position (IMDS bearer token,
// secret value, setting value, non-success error body, and label). The
// markers may surface only as the delivered payload bytes; every failure
// stays the closed value-free sentinel, so no marker can become
// application error text. This file deliberately registers no azcore/log
// listener and touches no process stream: the SEC-R01 logging-environment
// boundary is enforced by the production guard in azure.go and exercised
// only through the isolated child processes in azure_logging_test.go.
func TestAzurePipelineKeepsMarkersOutOfApplicationErrors(t *testing.T) {
	const tokenMarker = "MARKER-IMDS-TOKEN"
	const secretMarker = "marker-kv-secret-value"
	const settingMarker = "marker-setting-value"
	const errorBodyMarker = "MARKER-ERROR-BODY"
	const labelMarker = "marker-label"
	const version = "0123456789abcdef0123456789abcdef"

	// Key Vault success path: challenge, fixed-IMDS token, authenticated
	// read whose response value carries the secret marker.
	kvIMDS := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{status: http.StatusOK, body: azureTokenDocument(tokenMarker, "Bearer", "3599", "")},
	}}
	kvCredential := &azureIMDSCredential{client: newAzureIMDSClientWithTransport(kvIMDS)}
	kvWire := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{
			status: http.StatusUnauthorized,
			header: azureChallengeHeader(`Bearer authorization="https://login.windows.net/11111111-1111-1111-1111-111111111111", resource="https://vault.azure.net"`),
			body:   "{}",
		},
		{
			status: http.StatusOK,
			header: http.Header{"Content-Type": []string{"application/json"}},
			body:   `{"id":"https://prod-vault.vault.azure.net/secrets/db-password/` + version + `","value":"` + secretMarker + `","attributes":{"enabled":true}}`,
		},
	}}
	kvClient, kvClose, err := newAzureKeyVaultClientWithHTTPClient("prod-vault.vault.azure.net", kvCredential, newAzureServiceClientWithTransport(azureKeyVaultService, "prod-vault.vault.azure.net", "", kvWire))
	if kvClose != nil {
		defer kvClose()
	}
	if err != nil {
		t.Fatalf("Key Vault client construction failed: %v", err)
	}
	kvSource := Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db-password"}
	payload, err := readAzureSecret(context.Background(), kvClient, kvSource)
	if err != nil || string(payload) != secretMarker {
		t.Fatalf("Key Vault success path must deliver the marker payload unchanged: %v", err)
	}

	// Key Vault error path: the non-success body carries an error marker
	// that must be stripped before any ResponseError text can be emitted.
	errWire := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{
			status: http.StatusUnauthorized,
			header: azureChallengeHeader(`Bearer authorization="https://login.windows.net/11111111-1111-1111-1111-111111111111", resource="https://vault.azure.net"`),
			body:   "{}",
		},
		{
			status: http.StatusTooManyRequests,
			header: http.Header{"Content-Type": []string{"application/json"}},
			body:   `{"error":{"code":"` + errorBodyMarker + `"}}`,
		},
	}}
	errCredential := &azureIMDSCredential{client: newAzureIMDSClientWithTransport(&fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{status: http.StatusOK, body: azureTokenDocument(tokenMarker, "Bearer", "3599", "")},
	}})}
	errClient, errClose, err := newAzureKeyVaultClientWithHTTPClient("prod-vault.vault.azure.net", errCredential, newAzureServiceClientWithTransport(azureKeyVaultService, "prod-vault.vault.azure.net", "", errWire))
	if errClose != nil {
		defer errClose()
	}
	if err != nil {
		t.Fatalf("Key Vault error-path client construction failed: %v", err)
	}
	payload, err = readAzureSecret(context.Background(), errClient, kvSource)
	if payload != nil || !errors.Is(err, ErrProvider) {
		t.Fatalf("Key Vault error path must fail closed to the sentinel, got %v", err)
	}
	for _, marker := range []string{tokenMarker, secretMarker, settingMarker, errorBodyMarker, labelMarker} {
		if err != nil && strings.Contains(err.Error(), marker) {
			t.Fatalf("marker %q leaked into the application error", marker)
		}
	}

	// App Configuration labeled read carrying the setting and label markers.
	acIMDS := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{status: http.StatusOK, body: azureTokenDocument(tokenMarker, "Bearer", "3599", "")},
	}}
	acCredential := &azureIMDSCredential{client: newAzureIMDSClientWithTransport(acIMDS)}
	acWire := &fakeAzureRoundTripper{responses: []fakeAzureHTTPResponse{
		{
			status: http.StatusOK,
			header: http.Header{"Content-Type": []string{"application/vnd.microsoft.appconfig.kv+json"}, "Sync-Token": []string{"synthetic=dmFsaWQ;sn=1"}},
			body:   `{"etag":"e1","key":"app.setting","label":"` + labelMarker + `","value":"` + settingMarker + `","locked":false}`,
		},
	}}
	acClient, acClose, err := newAzureAppConfigClientWithHTTPClient("prod-store.azconfig.io", labelMarker, acCredential, newAzureServiceClientWithTransport(azureAppConfigService, "prod-store.azconfig.io", labelMarker, acWire))
	if acClose != nil {
		defer acClose()
	}
	if err != nil {
		t.Fatalf("App Configuration client construction failed: %v", err)
	}
	acSource := Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", Label: labelMarker}
	payload, err = readAzureSetting(context.Background(), acClient, acSource)
	if err != nil || string(payload) != settingMarker {
		t.Fatalf("App Configuration success path must deliver the marker payload unchanged: %v", err)
	}
}
