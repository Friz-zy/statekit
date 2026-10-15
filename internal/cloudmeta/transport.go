package cloudmeta

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// The metadata endpoint is a single literal; nothing else is ever dialed.
const (
	metadataNetwork = "tcp"
	metadataAddr    = "169.254.169.254:80"
	metadataBase    = "http://" + metadataAddr
)

// Bounds (binding; see package doc): 5 s overall collection deadline,
// 1 s per request, 250 ms dial timeout, 500 ms response-header timeout,
// 8 KiB response-header budget, 1 KiB per leaf/token body, and a 32 KiB
// aggregate body budget per invocation.
const (
	collectDeadline        = 5 * time.Second
	requestDeadline        = 1 * time.Second
	dialDeadline           = 250 * time.Millisecond
	responseHeaderDeadline = 500 * time.Millisecond
	maxResponseHeaderBytes = 8 << 10
	maxLeafBodyBytes       = 1 << 10
	maxAggregateBodyBytes  = 32 << 10
)

// forbiddenPathList enumerates exact path literals that must never be
// requested: bulk metadata documents and identity-bearing leaves excluded
// by the approved contract (GCP zone/machine-type/image transport project
// identifiers; OCI availabilityDomain carries a tenancy prefix; OpenStack
// meta_data.json carries project/key/name material). The descriptors are
// compile-time constants and never reach this set; the guard is defense
// in depth for future edits.
var forbiddenPathList = []string{
	// AWS bulk listing
	"/latest/meta-data",
	"/latest/meta-data/",
	// Azure full instance document
	"/metadata/instance",
	"/metadata/instance/",
	// GCP root/bulk listings
	"/computeMetadata/v1",
	"/computeMetadata/v1/",
	"/computeMetadata/v1/instance",
	"/computeMetadata/v1/instance/",
	// GCP leaves excluded as project-identifier carriers
	"/computeMetadata/v1/instance/zone",
	"/computeMetadata/v1/instance/machine-type",
	"/computeMetadata/v1/instance/image",
	// OCI bulk document
	"/opc/v2/instance",
	"/opc/v2/instance/",
	// tenancy-prefixed AD leaf; the contract uses ociAdName instead
	"/opc/v2/instance/availabilityDomain",
	// OpenStack bulk listing
	"/2009-04-04/meta-data",
	"/2009-04-04/meta-data/",
}

// forbiddenPaths is the lookup set built from forbiddenPathList.
var forbiddenPaths = func() map[string]bool {
	set := make(map[string]bool, len(forbiddenPathList))
	for _, path := range forbiddenPathList {
		set[path] = true
	}
	return set
}()

// assertPathAllowed is the internal forbidden-path assertion applied to
// every request before it is built.
func assertPathAllowed(path string) error {
	if forbiddenPaths[path] || strings.Contains(path, "meta_data.json") {
		return ErrForbiddenPath
	}
	return nil
}

// innerDial performs the bounded production dial. The address is an IP
// literal, so the resolver is never consulted.
func innerDial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	d.Timeout = dialDeadline
	return d.DialContext(ctx, network, addr)
}

// dialGuard wraps a dial function with the single-dial invariant: the
// network must be tcp and the address must be EXACTLY the metadata
// literal. Anything else is rejected before the inner dial runs (no DNS,
// no link-local range matching, no surprises).
func dialGuard(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != metadataNetwork || addr != metadataAddr {
			return nil, ErrUnreachable
		}
		return dial(ctx, network, addr)
	}
}

// newHardenedTransport returns the production transport.
func newHardenedTransport() *http.Transport {
	return newTransport(dialGuard(innerDial))
}

// newTransport wires the hardening invariants around the given dial
// function (tests inject a recording stub): Proxy is nil explicitly so
// metadata requests are never routed through an environment-configured
// proxy, compression is disabled so fixed-format plaintext leaves arrive
// as the exact bytes inspected (and no Accept-Encoding is advertised),
// keep-alives are disabled so the standard library never auto-retries a
// request over a reused connection, and header reads are time- and
// size-bounded.
func newTransport(dial func(context.Context, string, string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		DialContext:            dial,
		ResponseHeaderTimeout:  responseHeaderDeadline,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
	}
}

// denyRedirect is the client redirect policy: every redirect — including
// same-origin — is a failure, because the fixed contracts have no redirect
// semantics (a redirect could otherwise move the AWS token header into
// another path).
func denyRedirect(*http.Request, []*http.Request) error { return ErrRedirect }

// newClient returns the single client used for one invocation. The
// redirect policy denies every redirect — including same-origin — because
// the fixed contracts have no redirect semantics (a redirect could
// otherwise move the AWS token header into another path), and Jar is nil
// explicitly: no cookie storage, ever.
func newClient(rt http.RoundTripper) *http.Client {
	return &http.Client{
		Transport:     rt,
		CheckRedirect: denyRedirect,
		Jar:           nil,
	}
}

// classifyTransportError collapses every transport-level failure into the
// closed error set, discarding url.Error text (which embeds the URL and
// the underlying error string).
func classifyTransportError(err error) error {
	switch {
	case errors.Is(err, ErrRedirect):
		return ErrRedirect
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return ErrDeadline
	case os.IsTimeout(err):
		return ErrDeadline
	default:
		return ErrUnreachable
	}
}

// leafSpec is one fixed leaf of a provider's request descriptor. query
// is the literal raw query ("" for none); validate is an optional
// syntactic, value-free field check (nil means grammar only).
type leafSpec struct {
	field    string
	path     string
	query    string
	required bool
	validate func(string) error
}

// tokenSpec describes a token-acquisition step preceding the leaves
// (AWS IMDSv2 only).
type tokenSpec struct {
	method      string
	path        string
	ttlHeader   string
	ttlValue    string
	tokenHeader string
}

// providerPlan is one provider's compile-time request descriptor.
// excluded maps result fields to their not-collected reasons;
// requiredRespHeaders pins response headers that must be echoed exactly
// before any leaf of the plan is accepted (the GCP metadata flavor).
type providerPlan struct {
	provider            Provider
	headers             map[string]string
	token               *tokenSpec
	leaves              []leafSpec
	excluded            map[string]string
	requiredRespHeaders map[string]string
	provenance          string
}

// collector carries the per-invocation state: one client shared by every
// request of the collection and the shared aggregate body budget.
type collector struct {
	client *http.Client
	budget int
}

// newCollector builds the invocation collector. A nil rt selects the
// hardened production transport; tests inject a fake RoundTripper.
func newCollector(rt http.RoundTripper) *collector {
	if rt == nil {
		rt = newHardenedTransport()
	}
	return &collector{client: newClient(rt)}
}

// charge accounts body bytes against the per-invocation aggregate budget.
func (c *collector) charge(n int) error {
	c.budget += n
	if c.budget > maxAggregateBodyBytes {
		return ErrOversize
	}
	return nil
}

// request performs exactly one bounded request: forbidden-path assertion,
// literal URL, per-request deadline, fixed headers, redirect/encoding/
// response-marker/status policing, and bounded body reads charged to the
// aggregate budget. Only 200 and 404 reach the caller; every other
// outcome is an error. There is no retry.
func (c *collector) request(ctx context.Context, method, path, query string, headers, wantRespHeaders map[string]string, bodyLimit int) ([]byte, int, error) {
	if err := assertPathAllowed(path); err != nil {
		return nil, 0, err
	}
	target := metadataBase + path
	if query != "" {
		target += "?" + query
	}
	reqCtx, cancel := context.WithTimeout(ctx, requestDeadline)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, target, nil)
	if err != nil {
		return nil, 0, ErrProtocol
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, classifyTransportError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// Redirects without a Location never reach CheckRedirect.
		return nil, 0, ErrRedirect
	}
	if resp.Header.Get("Content-Encoding") != "" {
		return nil, 0, ErrProtocol
	}
	for name, want := range wantRespHeaders {
		if resp.Header.Get(name) != want {
			// The endpoint must echo the exact documented marker before
			// any leaf of the plan is accepted.
			return nil, 0, ErrProtocol
		}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return nil, 0, ErrProtocol
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(bodyLimit)+1))
	if err != nil {
		return nil, 0, ErrProtocol
	}
	if len(body) > bodyLimit {
		return nil, 0, ErrOversize
	}
	if err := c.charge(len(body)); err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}

// fetchToken performs the token step. The returned token is a transient
// protocol value: it lives only in this collection's request headers and
// is never persisted, logged, or included in any Result or error. Any
// failure fails the whole collection (IMDSv2 only: no v1 fallback).
func (c *collector) fetchToken(ctx context.Context, spec *tokenSpec) (string, error) {
	headers := map[string]string{spec.ttlHeader: spec.ttlValue}
	body, status, err := c.request(ctx, spec.method, spec.path, "", headers, nil, maxLeafBodyBytes)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", ErrProtocol
	}
	token, err := parseLeafValue(body)
	if err != nil {
		if errors.Is(err, errEmptyLeaf) {
			return "", ErrMalformed
		}
		return "", err
	}
	return token, nil
}

// fetchLeaf performs one leaf request and applies the failure semantics:
// 404 or empty-after-trim on an optional leaf omits the field; every other
// failure propagates and discards the whole result.
func (c *collector) fetchLeaf(ctx context.Context, plan providerPlan, token string, leaf leafSpec) (value string, omitted bool, err error) {
	headers := make(map[string]string, len(plan.headers)+1)
	for name, headerValue := range plan.headers {
		headers[name] = headerValue
	}
	if plan.token != nil {
		headers[plan.token.tokenHeader] = token
	}
	body, status, err := c.request(ctx, http.MethodGet, leaf.path, leaf.query, headers, plan.requiredRespHeaders, maxLeafBodyBytes)
	if err != nil {
		return "", false, err
	}
	if status == http.StatusNotFound {
		if leaf.required {
			return "", false, ErrProtocol
		}
		return "", true, nil
	}
	value, perr := parseLeafValue(body)
	if perr != nil {
		if errors.Is(perr, errEmptyLeaf) {
			if leaf.required {
				return "", false, ErrMalformed
			}
			return "", true, nil
		}
		return "", false, perr
	}
	if leaf.validate != nil {
		if verr := leaf.validate(value); verr != nil {
			return "", false, verr
		}
	}
	return value, false, nil
}

// collectPlan executes one provider plan against the shared client.
func (c *collector) collectPlan(ctx context.Context, plan providerPlan) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, collectDeadline)
	defer cancel()
	// End-of-collection cleanup: the production transport disables
	// keep-alives, and any connection the standard library still holds is
	// released when the plan finishes, success or failure.
	defer func() {
		if transport, ok := c.client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}()

	result := &Result{
		Provider:     string(plan.provider),
		Status:       statusOK,
		Verification: verificationUnverified,
		Provenance:   plan.provenance,
	}
	for field, reason := range plan.excluded {
		if result.FieldsNotCollected == nil {
			result.FieldsNotCollected = make(map[string]string, len(plan.excluded))
		}
		result.FieldsNotCollected[field] = reason
	}

	token := ""
	if plan.token != nil {
		var err error
		if token, err = c.fetchToken(ctx, plan.token); err != nil {
			return nil, err
		}
	}

	values := make(map[string]string, len(plan.leaves))
	for _, leaf := range plan.leaves {
		value, omitted, err := c.fetchLeaf(ctx, plan, token, leaf)
		if err != nil {
			return nil, err
		}
		if omitted {
			result.Status = statusPartial
			if result.FieldsNotCollected == nil {
				result.FieldsNotCollected = make(map[string]string)
			}
			result.FieldsNotCollected[leaf.field] = reasonNotPresent
			continue
		}
		values[leaf.field] = value
	}

	// Token-echo guard: no accepted leaf value may equal the IMDSv2
	// token; an echo is never a legitimate field value and the whole
	// result is discarded. The token itself is never serialized.
	if token != "" {
		for _, value := range values {
			if value == token {
				return nil, ErrMalformed
			}
		}
	}

	result.InstanceID = values[fieldInstanceID]
	result.Region = values[fieldRegion]
	result.Zone = values[fieldZone]
	result.InstanceType = values[fieldInstanceType]
	result.ImageID = values[fieldImageID]
	return result, nil
}

// buildDisabled is the single compiled-out-provider response shared by
// every build-tag stub (and by tests, which pin its behavior without
// running tagged builds; the tagged profile runs happen in the sandbox).
func buildDisabled() (*Result, error) { return nil, ErrBuildDisabled }
