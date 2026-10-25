//go:build !statekit_no_sdk_azure && !statekit_no_sdks

package cloudsecret

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azappconfig "github.com/Azure/azure-sdk-for-go/sdk/data/azappconfig/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

const (
	azureIMDSEndpoint      = "http://169.254.169.254/metadata/identity/oauth2/token"
	azureIMDSAPIVersion    = "2018-02-01"
	azureIMDSAuthority     = "169.254.169.254"
	azureIMDSReplyLimit    = 16 << 10
	azureIMDSMaxHeaders    = 8 << 10
	azureIMDSTimeout       = 5 * time.Second
	azureCallTimeout       = 15 * time.Second
	azureServiceTimeout    = 10 * time.Second
	azureServiceMaxHeaders = 16 << 10
	azureMaxServiceReply   = 2*MaxPayloadBytes + (64 << 10)
	azureMaxAddresses      = 8
	azureExpiryTolerance   = 10 * time.Minute

	// The closed scope set this adapter may ever authenticate for.
	// azsecrets derives the Key Vault scope from the vault URL (requests are
	// pinned to the public <vault>.vault.azure.net authority) and
	// azappconfig derives the azconfig.io scope for *.azconfig.io endpoints,
	// so any other requested scope is foreign and fails closed.
	azureKeyVaultScope     = "https://vault.azure.net/.default"
	azureKeyVaultResource  = "https://vault.azure.net"
	azureAppConfigScope    = "https://azconfig.io/.default"
	azureAppConfigResource = "https://azconfig.io"

	azureVaultSuffix     = ".vault.azure.net"
	azureAppConfigSuffix = ".azconfig.io"
)

// Only these two generated read methods are admitted. Writes, enumeration,
// Key Vault reference resolution, rendering, and every administrative
// surface are deliberately absent from these interfaces.
type azureSecretsAPI interface {
	GetSecret(context.Context, string, string, *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
}

type azureSettingsAPI interface {
	GetSetting(context.Context, string, *azappconfig.GetSettingOptions) (azappconfig.GetSettingResponse, error)
}

type azureFetchDependencies struct {
	newCredential func() azcore.TokenCredential
	newKeyVault   func(string, azcore.TokenCredential) (azureSecretsAPI, func(), error)
	newAppConfig  func(string, string, azcore.TokenCredential) (azureSettingsAPI, func(), error)
}

// SEC-R01 conditional remediation, scoped to the StateKit standalone CLI
// only. The pinned azcore pipeline always installs its HTTP logging
// policy and the Azure SDK's logging configuration is process-global with
// no supported per-client or per-operation disable, so first-attempt and
// retry request events would flow through that global plumbing. Instead
// of suppressing, filtering, or sanitizing SDK output — no azcore/log
// global setter is called, the environment is never mutated, process
// streams are never redirected, and SDK payloads are never filtered here —
// both Azure reads refuse to run while Azure SDK logging may be
// configured. Narrow ceiling: this protects only the standalone CLI
// process whose startup environment StateKit controls; it is not logging
// isolation for arbitrary hosts embedding this package, which can
// register azcore/log listeners programmatically at any time, and no
// protection is claimed for embedded use. Existing payload minimization
// (redacted headers and query parameters, bounded non-success bodies)
// stays what it is: defense-in-depth, not logging isolation.
const azureSDKLoggingEnv = "AZURE_SDK_GO_LOGGING"

// azureStartupSDKLogging captures the SDK logging environment variable at
// this package's initialization, not at literal process start. Go
// initializes every imported SDK package before this package's variables,
// so the capture equals the value the imported SDKs observed during their
// own initialization only under the standalone CLI invariant that the
// environment is not mutated between SDK initialization and this package's
// initialization. No such equivalence and no logging isolation is claimed
// for arbitrary hosts embedding this package.
var azureStartupSDKLogging = os.Getenv(azureSDKLoggingEnv)

// azureSDKLoggingConfigured reports whether an Azure read must be refused
// because SDK logging may be active: any nonempty process-start value or
// any nonempty value visible now. Unrecognized, differently cased, and
// whitespace-only values all refuse — interpreting them would reintroduce
// a configuration cliff — while empty and unset pass.
func azureSDKLoggingConfigured(startup, current string) bool {
	return startup != "" || current != ""
}

// AzureAvailable reports whether the Azure SDK adapters were compiled in.
// The statekit_no_sdk_azure tag disables Azure; statekit_no_sdks disables
// all optional SDK adapters.
func AzureAvailable() bool { return true }

// FetchAzureKeyVault reads exactly one Key Vault secret version using one
// per-operation SDK client and a private fixed-IMDS managed-identity
// credential. There is no azidentity chain and no default credential.
func FetchAzureKeyVault(ctx context.Context, source Source) ([]byte, error) {
	return fetchAzureKeyVaultWith(ctx, source, newAzureDependencies())
}

// FetchAzureAppConfiguration reads exactly one explicitly labeled App
// Configuration setting using one per-operation SDK client and the same
// private fixed-IMDS credential contract.
func FetchAzureAppConfiguration(ctx context.Context, source Source) ([]byte, error) {
	return fetchAzureAppConfigurationWith(ctx, source, newAzureDependencies())
}

func fetchAzureKeyVaultWith(ctx context.Context, source Source, dependencies azureFetchDependencies) (payload []byte, err error) {
	defer func() {
		if recover() != nil {
			payload, err = nil, ErrProvider
		}
	}()
	if err := ValidateSource(source); err != nil {
		return nil, err
	}
	if source.Provider != "azure" || source.Backend != "keyvault" {
		return nil, ErrUnsupported
	}
	// SEC-R01: the standalone-CLI logging guard precedes every credential,
	// client, DNS, and transport step; see the azureSDKLoggingEnv contract.
	if azureSDKLoggingConfigured(azureStartupSDKLogging, os.Getenv(azureSDKLoggingEnv)) {
		return nil, ErrProvider
	}
	if dependencies.newCredential == nil || dependencies.newKeyVault == nil {
		return nil, ErrProvider
	}
	callCtx, cancel := context.WithTimeout(ctx, azureCallTimeout)
	defer cancel()
	// One credential and one client per operation: the SDK bearer-token
	// cache lives inside this client and is never reused across operations.
	credential := dependencies.newCredential()
	if credential == nil {
		return nil, ErrProvider
	}
	client, closeClient, err := dependencies.newKeyVault(source.Region+azureVaultSuffix, credential)
	if closeClient != nil {
		defer closeClient()
	}
	if err != nil || client == nil {
		return nil, ErrProvider
	}
	return readAzureSecret(callCtx, client, source)
}

func fetchAzureAppConfigurationWith(ctx context.Context, source Source, dependencies azureFetchDependencies) (payload []byte, err error) {
	defer func() {
		if recover() != nil {
			payload, err = nil, ErrProvider
		}
	}()
	if err := ValidateSource(source); err != nil {
		return nil, err
	}
	if source.Provider != "azure" || source.Backend != "appconfiguration" {
		return nil, ErrUnsupported
	}
	// SEC-R01: the standalone-CLI logging guard precedes every credential,
	// client, DNS, and transport step; see the azureSDKLoggingEnv contract.
	if azureSDKLoggingConfigured(azureStartupSDKLogging, os.Getenv(azureSDKLoggingEnv)) {
		return nil, ErrProvider
	}
	if dependencies.newCredential == nil || dependencies.newAppConfig == nil {
		return nil, ErrProvider
	}
	callCtx, cancel := context.WithTimeout(ctx, azureCallTimeout)
	defer cancel()
	credential := dependencies.newCredential()
	if credential == nil {
		return nil, ErrProvider
	}
	client, closeClient, err := dependencies.newAppConfig(source.Region+azureAppConfigSuffix, source.Label, credential)
	if closeClient != nil {
		defer closeClient()
	}
	if err != nil || client == nil {
		return nil, ErrProvider
	}
	return readAzureSetting(callCtx, client, source)
}

func readAzureSecret(ctx context.Context, client azureSecretsAPI, source Source) ([]byte, error) {
	if client == nil || ValidateSource(source) != nil || source.Provider != "azure" || source.Backend != "keyvault" {
		return nil, ErrInvalidSource
	}
	response, err := client.GetSecret(ctx, source.Resource, source.VersionID, nil)
	if err != nil {
		return nil, ErrProvider
	}
	if response.ID == nil || !validAzureSecretID(string(*response.ID), source) {
		return nil, ErrProvider
	}
	if response.Attributes != nil && response.Attributes.Enabled != nil && !*response.Attributes.Enabled {
		return nil, ErrProvider
	}
	if response.Value == nil {
		return nil, ErrProvider
	}
	if len(*response.Value) > MaxPayloadBytes {
		return nil, ErrInvalidPayload
	}
	return []byte(*response.Value), nil
}

// readAzureSetting performs one labeled read. The label is the mandatory,
// first-class source field naming the exact setting version: there is no
// fallback to an unlabeled setting and no reference resolution, so a Key
// Vault reference payload is delivered as ordinary raw bytes.
func readAzureSetting(ctx context.Context, client azureSettingsAPI, source Source) ([]byte, error) {
	if client == nil || ValidateSource(source) != nil || source.Provider != "azure" || source.Backend != "appconfiguration" {
		return nil, ErrInvalidSource
	}
	label := source.Label
	response, err := client.GetSetting(ctx, source.Resource, &azappconfig.GetSettingOptions{Label: &label})
	if err != nil {
		return nil, ErrProvider
	}
	if response.Key == nil || *response.Key != source.Resource || response.Label == nil || *response.Label != label {
		return nil, ErrProvider
	}
	if response.Value == nil {
		return nil, ErrProvider
	}
	if len(*response.Value) > MaxPayloadBytes {
		return nil, ErrInvalidPayload
	}
	return []byte(*response.Value), nil
}

// validAzureSecretID pins the returned identity to the exact vault, secret
// name, and version requested. Userinfo, query, fragment, noncanonical
// escaped paths, extra segments, and any other host are rejected; a latest
// read must still resolve to a concrete 32-hex version, and a pinned read
// must echo that exact version.
func validAzureSecretID(identity string, source Source) bool {
	parsed, err := url.Parse(identity)
	if err != nil || parsed.Scheme != "https" || parsed.Host != source.Region+azureVaultSuffix {
		return false
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" {
		return false
	}
	path := strings.TrimSuffix(parsed.Path, "/")
	rest, ok := strings.CutPrefix(path, "/secrets/")
	if !ok {
		return false
	}
	name, version, hasVersion := strings.Cut(rest, "/")
	if !strings.EqualFold(name, source.Resource) {
		return false
	}
	if strings.Contains(version, "/") {
		return false
	}
	if source.VersionID != "" {
		return version == source.VersionID
	}
	return hasVersion && validAzureSecretVersion(version)
}

func newAzureDependencies() azureFetchDependencies {
	return azureFetchDependencies{
		newCredential: func() azcore.TokenCredential { return newAzureIMDSCredential("") },
		newKeyVault:   newAzureKeyVaultClient,
		newAppConfig:  newAzureAppConfigClient,
	}
}

// newAzureKeyVaultClient builds one Key Vault client whose bearer-token
// cache, credential, and transport are scoped to this operation. The SDK's
// challenge resource verification stays enabled (DisableChallengeResourceVerification
// is false); the fixed-IMDS credential additionally rejects every scope
// except the public-cloud vault audience.
func newAzureKeyVaultClient(authority string, credential azcore.TokenCredential) (azureSecretsAPI, func(), error) {
	return newAzureKeyVaultClientWithHTTPClient(authority, credential, nil)
}

// newAzureKeyVaultClientWithHTTPClient keeps the production SDK client and
// pipeline; a non-nil httpClient replaces only the wire beneath the service
// request guard, never the guard itself.
func newAzureKeyVaultClientWithHTTPClient(authority string, credential azcore.TokenCredential, httpClient *http.Client) (azureSecretsAPI, func(), error) {
	if httpClient == nil {
		httpClient = newAzureServiceClient(azureKeyVaultService, authority, "", nil, nil)
	}
	client, err := azsecrets.NewClient("https://"+authority, credential, &azsecrets.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: httpClient,
			Retry:     policy.RetryOptions{MaxRetries: -1},
		},
	})
	if err != nil {
		httpClient.CloseIdleConnections()
		return nil, nil, ErrProvider
	}
	return client, func() { httpClient.CloseIdleConnections() }, nil
}

func newAzureAppConfigClient(authority, label string, credential azcore.TokenCredential) (azureSettingsAPI, func(), error) {
	return newAzureAppConfigClientWithHTTPClient(authority, label, credential, nil)
}

// newAzureAppConfigClientWithHTTPClient keeps the production SDK client and
// pipeline; a non-nil httpClient replaces only the wire beneath the service
// request guard, never the guard itself.
func newAzureAppConfigClientWithHTTPClient(authority, label string, credential azcore.TokenCredential, httpClient *http.Client) (azureSettingsAPI, func(), error) {
	if httpClient == nil {
		httpClient = newAzureServiceClient(azureAppConfigService, authority, label, nil, nil)
	}
	client, err := azappconfig.NewClient("https://"+authority, credential, &azappconfig.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: httpClient,
			Retry:     policy.RetryOptions{MaxRetries: -1},
		},
	})
	if err != nil {
		httpClient.CloseIdleConnections()
		return nil, nil, ErrProvider
	}
	return client, func() { httpClient.CloseIdleConnections() }, nil
}

// azureIMDSCredential is the private fixed-IMDS TokenCredential required by
// the approved design. Unlike azidentity.ManagedIdentityCredential it never
// probes for App Service, Arc, Cloud Shell, or other environment-specific
// endpoints and has no environment, CLI, profile, token-file, or fallback
// source: it dials one fixed link-local address with one fixed API version
// and accepts exactly the two admitted service scopes.
type azureIMDSCredential struct {
	clientID string
	client   *http.Client
}

var _ azcore.TokenCredential = (*azureIMDSCredential)(nil)

func newAzureIMDSCredential(clientID string) *azureIMDSCredential {
	return &azureIMDSCredential{clientID: clientID, client: newAzureIMDSClient()}
}

func (c *azureIMDSCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if c == nil || c.client == nil {
		return azcore.AccessToken{}, ErrCredentials
	}
	if c.clientID != "" && !validAzureClientID(c.clientID) {
		return azcore.AccessToken{}, ErrCredentials
	}
	resource, ok := azureScopeResource(azurePermittedScope(options.Scopes))
	if !ok {
		return azcore.AccessToken{}, ErrCredentials
	}
	if err := ctx.Err(); err != nil {
		return azcore.AccessToken{}, ErrCredentials
	}
	query := url.Values{}
	query.Set("api-version", azureIMDSAPIVersion)
	query.Set("resource", resource)
	if c.clientID != "" {
		query.Set("client_id", c.clientID)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, azureIMDSEndpoint+"?"+query.Encode(), nil)
	if err != nil {
		return azcore.AccessToken{}, ErrCredentials
	}
	request.Header.Set("Metadata", "true")
	response, err := c.client.Do(request)
	if err != nil {
		return azcore.AccessToken{}, ErrCredentials
	}
	defer response.Body.Close()
	mediaType, _, mediaTypeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || len(response.Header.Values("Content-Type")) != 1 || mediaTypeErr != nil || mediaType != "application/json" || len(response.Header.Values("Content-Encoding")) != 0 || response.ContentLength > azureIMDSReplyLimit {
		return azcore.AccessToken{}, ErrCredentials
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, azureIMDSReplyLimit+1))
	if err != nil || len(body) == 0 || len(body) > azureIMDSReplyLimit {
		return azcore.AccessToken{}, ErrCredentials
	}
	parsed, err := parseJSON(body)
	if err != nil {
		return azcore.AccessToken{}, ErrCredentials
	}
	fields, ok := parsed.(map[string]any)
	if !ok {
		return azcore.AccessToken{}, ErrCredentials
	}
	accessToken, tokenOK := fields["access_token"].(string)
	tokenType, typeOK := fields["token_type"].(string)
	if !tokenOK || !typeOK || tokenType != "Bearer" || !validAzureAccessToken(accessToken) {
		return azcore.AccessToken{}, ErrCredentials
	}
	expiresIn, ok := azureExpiresInSeconds(fields["expires_in"])
	if !ok || expiresIn <= int64((azureCallTimeout+2*time.Second)/time.Second) || expiresIn > 86400 {
		return azcore.AccessToken{}, ErrCredentials
	}
	// Optional echo fields fail closed: a present resource must name the
	// exact resource requested, a present client_id must be a GUID string
	// matching the requested user-assigned identity, and a present
	// expires_on must parse and agree with expires_in.
	if echoed, present := fields["resource"]; present {
		text, echoOK := echoed.(string)
		if !echoOK || text != resource {
			return azcore.AccessToken{}, ErrCredentials
		}
	}
	if echoed, present := fields["client_id"]; present {
		text, echoOK := echoed.(string)
		if !echoOK || !validAzureClientID(text) || c.clientID != "" && text != c.clientID {
			return azcore.AccessToken{}, ErrCredentials
		}
	}
	if expiry, present := fields["expires_on"]; present {
		text, echoOK := expiry.(string)
		if !echoOK || !validAzureExpiresOn(text, time.Now().Add(time.Duration(expiresIn)*time.Second)) {
			return azcore.AccessToken{}, ErrCredentials
		}
	}
	return azcore.AccessToken{Token: accessToken, ExpiresOn: time.Now().Add(time.Duration(expiresIn) * time.Second)}, nil
}

// validAzureExpiresOn accepts an IMDS expiry echo only when it parses as an
// epoch-seconds integer or one of the documented datetime forms and agrees
// with the expires_in-derived expectation within ten minutes.
func validAzureExpiresOn(value string, expected time.Time) bool {
	if value == "" {
		return false
	}
	if seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
		parsed := time.Unix(seconds, 0)
		return azureWithinExpiryTolerance(parsed, expected)
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, strings.TrimSpace(value)); err == nil {
			return azureWithinExpiryTolerance(parsed, expected)
		}
	}
	return false
}

func azureWithinExpiryTolerance(parsed, expected time.Time) bool {
	return parsed.Sub(expected) <= azureExpiryTolerance && expected.Sub(parsed) <= azureExpiryTolerance
}

func azurePermittedScope(scopes []string) string {
	if len(scopes) != 1 {
		return ""
	}
	return scopes[0]
}

func azureScopeResource(scope string) (string, bool) {
	switch scope {
	case azureKeyVaultScope:
		return azureKeyVaultResource, true
	case azureAppConfigScope:
		return azureAppConfigResource, true
	default:
		return "", false
	}
}

// azurePermittedResource is the exact IMDS resource allowlist, the image of
// azureScopeResource. It is deliberately a separate set from the scope
// allowlist so a resource can never be validated as a scope or vice versa.
func azurePermittedResource(resource string) bool {
	return resource == azureKeyVaultResource || resource == azureAppConfigResource
}

func azureExpiresInSeconds(value any) (int64, bool) {
	switch typed := value.(type) {
	case string:
		parsed, err := strconv.ParseInt(typed, 10, 64)
		return parsed, err == nil
	case json.Number:
		parsed, err := typed.Int64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func validAzureClientID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		dash := i == 8 || i == 13 || i == 18 || i == 23
		hexDigit := c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
		if dash != (c == '-') || !dash && !hexDigit {
			return false
		}
	}
	return true
}

func validAzureAccessToken(token string) bool {
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

func newAzureIMDSTransport() *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: azureIMDSMaxHeaders,
		ResponseHeaderTimeout:  2 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if (network != "tcp" && network != "tcp4") || address != azureIMDSAuthority+":80" {
				return nil, ErrCredentials
			}
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, address)
		},
	}
}

func newAzureIMDSClient() *http.Client {
	return newAzureIMDSClientWithTransport(newAzureIMDSTransport())
}

// newAzureIMDSClientWithTransport keeps the production IMDS request guard;
// a test replaces only the wire beneath it.
func newAzureIMDSClientWithTransport(next http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: &azureIMDSRoundTripper{next: next},
		Timeout:   azureIMDSTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type azureIMDSRoundTripper struct{ next http.RoundTripper }

func (t *azureIMDSRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.Method != http.MethodGet || request.URL.Scheme != "http" || request.URL.Host != azureIMDSAuthority || request.URL.User != nil || request.URL.Path != "/metadata/identity/oauth2/token" || request.URL.RawPath != "" || request.URL.Opaque != "" || request.URL.ForceQuery || request.URL.Fragment != "" || request.Body != nil {
		return nil, ErrCredentials
	}
	query := request.URL.Query()
	if !azurePermittedResource(query.Get("resource")) || query.Get("api-version") != azureIMDSAPIVersion || len(query) != 2 && len(query) != 3 {
		return nil, ErrCredentials
	}
	if clientID := query.Get("client_id"); len(query) == 3 && !validAzureClientID(clientID) || len(query) == 2 && clientID != "" {
		return nil, ErrCredentials
	}
	response, err := t.next.RoundTrip(request)
	if err != nil || response == nil || response.Body == nil || response.Header.Get("Content-Encoding") != "" {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrCredentials
	}
	response.Body = &azureBoundedReadCloser{ReadCloser: response.Body, remaining: azureIMDSReplyLimit}
	return response, nil
}

type azureServiceKind int

const (
	azureKeyVaultService azureServiceKind = iota
	azureAppConfigService
)

type (
	azureResolveFunc func(context.Context, string) ([]net.IPAddr, error)
	azureDialFunc    func(context.Context, string, string) (net.Conn, error)
)

// azureServiceDialContext resolves the pinned authority, requires every
// resolved address to be public unicast, and dials the first validated IPv4
// literal. TLS hostname verification is unaffected: the transport derives
// the server name from the URL authority, not from the dialed IP.
func azureServiceDialContext(authority string, resolve azureResolveFunc, dial azureDialFunc) func(context.Context, string, string) (net.Conn, error) {
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return net.DefaultResolver.LookupIPAddr(ctx, host)
		}
	}
	if dial == nil {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		dial = dialer.DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || port != "443" || host != authority || network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, ErrProvider
		}
		addresses, err := resolve(ctx, host)
		if err != nil || len(addresses) == 0 || len(addresses) > azureMaxAddresses {
			return nil, ErrProvider
		}
		primary := ""
		for _, candidate := range addresses {
			if !isPublicAzureAddress(candidate.IP) {
				return nil, ErrProvider
			}
			if primary == "" && candidate.IP.To4() != nil {
				primary = candidate.IP.String()
			}
		}
		if primary == "" {
			return nil, ErrProvider
		}
		return dial(ctx, network, net.JoinHostPort(primary, port))
	}
}

// azureBlockedAddressPrefixes lists IANA special-purpose ranges that Go's
// IsGlobalUnicast still classifies as public: shared CGNAT space, IETF
// protocol assignments, documentation ranges, benchmarking, the deprecated
// 6to4 relay, the reserved IPv4 space (including the broadcast address),
// and the IPv6 documentation and 6to4 prefixes.
var azureBlockedAddressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

func isPublicAzureAddress(ip net.IP) bool {
	if ip == nil ||
		!ip.IsGlobalUnicast() ||
		ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() {
		return false
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	if address.Is4In6() {
		address = address.Unmap()
	}
	for _, blocked := range azureBlockedAddressPrefixes {
		if blocked.Contains(address) {
			return false
		}
	}
	return true
}

func newAzureServiceTransport(authority string, resolve azureResolveFunc, dial azureDialFunc) *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: azureServiceMaxHeaders,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		ExpectContinueTimeout:  time.Second,
		DialContext:            azureServiceDialContext(authority, resolve, dial),
	}
}

func newAzureServiceClient(kind azureServiceKind, authority, label string, resolve azureResolveFunc, dial azureDialFunc) *http.Client {
	return newAzureServiceClientWithTransport(kind, authority, label, newAzureServiceTransport(authority, resolve, dial))
}

// newAzureServiceClientWithTransport keeps the production service request
// guard; a test replaces only the wire beneath it. TLS hostname
// verification stays bound to the URL authority because the guard, not the
// dial layer, is the component being exercised.
func newAzureServiceClientWithTransport(kind azureServiceKind, authority, label string, next http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: &azureServiceRoundTripper{next: next, kind: kind, host: authority, label: label},
		Timeout:   azureServiceTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type azureServiceRoundTripper struct {
	next  http.RoundTripper
	kind  azureServiceKind
	host  string
	label string
}

func (t *azureServiceRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.Method != http.MethodGet || request.URL.Scheme != "https" || request.URL.Host != t.host || request.URL.User != nil || request.URL.Opaque != "" || request.URL.ForceQuery || request.URL.Fragment != "" {
		return nil, ErrProvider
	}
	query := request.URL.Query()
	switch t.kind {
	case azureKeyVaultService:
		if !validAzureVaultRequestPath(request.URL.Path) || len(query) != 1 || query.Get("api-version") == "" {
			return nil, ErrProvider
		}
	case azureAppConfigService:
		if !validAzureSettingRequestPath(request.URL.Path) || len(query) != 2 || query.Get("api-version") == "" || query.Get("label") != t.label {
			return nil, ErrProvider
		}
	default:
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
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		_ = response.Body.Close()
		return nil, ErrProvider
	}
	if response.StatusCode != http.StatusOK {
		// Both admitted operations accept only 200. Drain and discard the
		// bounded non-success body so the SDK's ResponseError text can never
		// embed provider diagnostics; challenge negotiation reads only the
		// WWW-Authenticate header, which is retained untouched.
		_, _ = io.Copy(io.Discard, &azureBoundedReadCloser{ReadCloser: response.Body, remaining: azureMaxServiceReply})
		_ = response.Body.Close()
		response.Body = io.NopCloser(strings.NewReader(""))
		response.ContentLength = 0
	}
	response.Body = &azureBoundedReadCloser{ReadCloser: response.Body, remaining: azureMaxServiceReply}
	return response, nil
}

// validAzureVaultRequestPath admits only /secrets/<name> or
// /secrets/<name>/<version> (plus the trailing slash the pinned SDK emits
// for the empty latest selector). No other vault object family is reachable.
func validAzureVaultRequestPath(path string) bool {
	rest, ok := strings.CutPrefix(strings.TrimSuffix(path, "/"), "/secrets/")
	if !ok {
		return false
	}
	name, version, hasVersion := strings.Cut(rest, "/")
	if !validAzureSecretName(name) {
		return false
	}
	return !hasVersion || validAzureSecretVersion(version)
}

func validAzureSettingRequestPath(path string) bool {
	key, ok := strings.CutPrefix(path, "/kv/")
	return ok && validAzureSettingKey(key) && !strings.Contains(key, "/")
}

type azureBoundedReadCloser struct {
	io.ReadCloser
	remaining int64
	checked   bool
}

func (r *azureBoundedReadCloser) Read(p []byte) (int, error) {
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
