// Package slack implements the pinned Salt slack execution module
// (saltstack/salt/modules/slack_notify.py @
// 8b63e700637e40d76f80a00d95c60471797c73b9, virtual name "slack") over a
// single bounded stdlib HTTP transport.
//
// R10.1 registers the family's complete public catalog: list_rooms,
// list_users, find_room, find_user, post_message, and call_hook. The
// pinned private helpers _get_api_key and _get_hook_id (slack_notify.py:
// 39-55) are ported as internal ladders over the optional config.get
// delegate — the StateKit config-input boundary already used by gpg,
// nacl, file, and ssh_pki. There is no production config module, so an
// absent delegate resolves fail-closed with the pinned SaltInvocationError
// texts (value-free: neither error names the missing value), and callers
// pass api_key/identifier explicitly exactly like the pinned signatures
// allow.
//
// Transport contract (salt/utils/slack.py query + salt/utils/http.py
// query @ pinned revision): the API family GETs/POSTs
// https://slack.com/api/<method> with the token in the Authorization
// Bearer header only — never a query parameter or body field, per the
// pinned 2020-11 no-tokens-in-querystrings change — Accept:
// application/json on non-POST, the pinned urlencoded Content-Type on
// POST, and the pinned 200/204/else result ladder ("error"-key miss,
// response-key extraction, Unknown response, invalid_auth). call_hook
// POSTs beneath the fixed https://hooks.slack.com/services/ origin with
// the single form field payload=<json> and the pinned status<=201
// boolean plus body-or-status failure dict.
//
// Documented boundaries and deliberate safe divergences from the pinned
// source, each asserted by direct, registry, and CLI mock tests:
//   - the pinned module inherits the minion http_request_timeout default
//     (one hour) and a 100 GB max_body; StateKit bounds every exchange at
//     a fixed 30s deadline carried on the request context (so it holds
//     for the module-owned client and any test-injected transport
//     alike), 1 MiB request body, 4 MiB response body, and an
//     exact-origin https redirect policy — the pinned tornado client
//     follows redirects with no scheme restriction;
//   - call_hook validates the hook identifier against the fixed origin
//     (SEC-001): a path-style token is joined beneath
//     https://hooks.slack.com/services/ with traversal and
//     decoded-backslash rejection (encoded separators like %5C included),
//     and a full-URL identifier must already be exactly that origin
//     (https, exact host, no userinfo, default-or-absent port, path
//     under /services/ with the same decoded-path rejection, no query or
//     fragment). The pinned urllib.parse.urljoin
//     accepts any absolute URL — an unrestricted destination — so this
//     is a security divergence, not a parity claim;
//   - redirects repeat the exact origin of the first request (scheme,
//     host, and port identical — subdomains and port changes included)
//     and fail closed otherwise, the Referer header is stripped on every
//     followed hop so the credential-bearing path can never leak to
//     another origin, and exactly 3 redirects are followed (4 exchanges
//     total including the original request; the 4th redirect fails
//     closed) — which also keeps 307/308 body replay inside the original
//     TLS endpoint;
//   - the pinned query maps socket-level failures to the status-0 ladder
//     ("invalid_auth" for the API family, a successful True for
//     call_hook); StateKit fails closed on transport errors with
//     value-free sentinels because a network fault must not masquerade as
//     an authentication failure or a delivered notification;
//   - the pinned post_message stringifies non-string form values with
//     Python str() (single-quoted reprs, invalid JSON for attachments);
//     StateKit renders composite values as compact JSON — every
//     Python-falsy attachments/blocks input (nil, empty string, false,
//     zero, empty map, empty array) renders "[]" exactly like the pinned
//     `attachments or []` truthiness — keeping the urlencoded
//     field-per-parameter shape;
//   - the pinned decode is content-type-dispatched; StateKit always
//     strict-JSON-decodes the fixed endpoints and requires a top-level
//     object (the stdlib decoder bounds nesting depth), mapping malformed
//     or non-object bodies to fixed value-free errors;
//   - the pinned TypeError/KeyError crash positions (a 204 boolean fed to
//     find_room/post_message, and the non-200/204 error-dict branch
//     reading a key the http layer never set) are mapped to one fixed
//     value-free unexpected-response error; the rest of the pinned else
//     ladder is reproduced (dict body without "error" answers the pinned
//     "Unknown response", anything that does not decode to an object
//     answers the pinned "invalid_auth").
//
// Secrets: the api key and the hook identifier join the module's redaction
// inventory — decoded server objects are recursively redacted in both
// KEYS and VALUES (each secret matched in raw, percent-encoded, and
// JSON-escaped normalized forms, covering both Go's encoder and Python
// json.dumps ASCII escaping), failure bodies are redacted before they
// become the message field against the identifier AND its canonical
// forms (decoded path token, normalized default-port-removed URL,
// path-only echo), a key-redaction collision fails closed with a
// value-free error instead of overwriting a key (the mysql
// header-collision precedent), and every transport/config error is
// a value-free sentinel so no URL, header, or body bytes can carry the
// token or hook path into a rendered command, log, report, or error. No
// SQL or shell is involved, and no new dependency is linked: net/http +
// encoding/json only.
package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	// requestTimeout bounds every slack HTTP exchange. The pinned source
	// inherits the minion http_request_timeout default (3600s); StateKit
	// keeps the finite 30s ceiling as a resource control, matching the R9
	// commandTimeout precedent.
	requestTimeout = 30 * time.Second
	// maxRequestBytes bounds the outgoing body (urlencoded form or
	// payload) before any transport dispatch.
	maxRequestBytes = 1 << 20
	// maxResponseBytes bounds the decoded response body.
	maxResponseBytes = 4 << 20
	// maxRedirects is the exact number of redirects the transport may
	// follow: the original request plus at most 3 redirect hops (4
	// exchanges total); the 4th redirect fails closed.
	maxRedirects = 3
	// apiURLBase is the pinned urljoin("https://slack.com", "/api/") base
	// of salt/utils/slack.py.
	apiURLBase = "https://slack.com/api/"
	// hookURLBase is the pinned call_hook base URL.
	hookURLBase = "https://hooks.slack.com/services/"
	// hookHost is the exact pinned webhook origin host (case-sensitive).
	hookHost = "hooks.slack.com"
	// hookPathPrefix is the path beneath which every hook URL lives.
	hookPathPrefix = "/services/"
	// userAgent ports the pinned salt.utils.http.query default User-agent
	// (Salt/{salt.version.__version__} http.query()) with __version__
	// derived from references/salt.lock (v3008.2-180-g8b63e70063).
	userAgent = "Salt/3008.2+180.g8b63e70063 http.query()"
	// bearerPrefix is the pinned token transport: the Authorization
	// header only, never a query parameter or form field.
	bearerPrefix = "Bearer "
	// formContentType is the pinned post_message header_dict value.
	formContentType = "application/x-www-form-urlencoded"
)

var (
	// errSlackNoAPIKey and errSlackNoHook port the pinned
	// SaltInvocationError texts of _get_api_key/_get_hook_id verbatim
	// (byte-including the pinned period asymmetry); neither names a
	// caller value, so the missing secret cannot leak through them.
	errSlackNoAPIKey = errors.New("No Slack API key found.")
	errSlackNoHook   = errors.New("No Slack WebHook url found")
	// errSlackInvalidHook rejects a hook identifier that cannot resolve
	// beneath the fixed https://hooks.slack.com/services/ origin; the
	// rejected identifier (the webhook credential) never enters the
	// error.
	errSlackInvalidHook = errors.New("slack: invalid hook identifier")
	// errSlackRedactionCollision fails closed when renaming a
	// secret-bearing map key would collide with an existing (or already
	// produced) key — the mysql F1 header-collision precedent: an
	// explicit value-free error instead of a silent overwrite.
	errSlackRedactionCollision = errors.New("slack: redacted key collision")
	// errSlackTransport is the value-free transport-failure sentinel: the
	// underlying url.Error would carry the full hook URL (and therefore
	// the identifier), so only the stable category travels onward.
	errSlackTransport = errors.New("slack: request failed")
	// errSlackTimeout classifies deadline exhaustion while remaining
	// errors.Is-compatible with context.DeadlineExceeded.
	errSlackTimeout = fmt.Errorf("slack: request timed out: %w", context.DeadlineExceeded)
	// errSlackRedirect fails closed on redirect chains that leave the
	// exact origin of the first request, leave https, or would exceed
	// the documented number of followed redirects.
	errSlackRedirect = errors.New("slack: unsafe redirect")
	// errSlackRequestLimit and errSlackResponseLimit are the fixed
	// size-bound rejections, raised before any body traversal completes.
	errSlackRequestLimit  = errors.New("slack: request exceeds size limit")
	errSlackResponseLimit = errors.New("slack: response exceeds size limit")
	// errSlackDecode is the strict-JSON rejection for malformed bodies.
	errSlackDecode = errors.New("slack: malformed response")
	// errSlackResponseShape is the fixed mapping of the pinned TypeError
	// and KeyError crash positions (a 204 boolean consumed as the query
	// result map, a non-object 200 body, and the non-200/204 error-dict
	// branch reading result["error"] — a key the http layer never set).
	errSlackResponseShape = errors.New("slack: unexpected response")
)

// ---------------------------------------------------------------------------
// bounded shared transport

// HTTPDoer is the slack HTTP transport boundary. Production uses one
// module-owned bounded stdlib client; tests inject fakes through the
// testing-scoped seam below so no real DNS or network resolution ever
// happens.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// slackHTTPClient is the module-owned bounded production doer; it is
// never mutated (R10.1 SEC-004). testDoer, when non-nil, substitutes for
// it for the lifetime of exactly one test.
var (
	slackHTTPClient HTTPDoer = newSlackClient()
	testDoer        HTTPDoer
)

// SetTestHTTPClient installs a test-only transport for the lifetime of tb
// (R10.1 SEC-004). It exists so cross-package tests (CLI, differential)
// can fake the HTTP boundary without DNS or network; the testing.TB
// requirement keeps the seam out of production code paths and the
// install reverts automatically at cleanup.
//
// TRUST LIMITS: the injected transport bypasses the module-owned bounded
// stdlib client — it must honor request contexts (the fixed 30s exchange
// deadline is applied to every request context in slackDo, not just to
// the production client's Timeout) and it models single-exchange
// responses; redirect following belongs to the module client and is
// enforced end-to-end by the loopback redirect tests. The seam is one
// package-level slot: tests using it must not run in parallel.
func SetTestHTTPClient(tb testing.TB, doer HTTPDoer) {
	tb.Helper()
	if doer == nil {
		tb.Fatal("slack: SetTestHTTPClient requires a transport")
	}
	previous := testDoer
	testDoer = doer
	tb.Cleanup(func() { testDoer = previous })
}

// newSlackClient builds the bounded stdlib client shared by every slack
// exchange.
func newSlackClient() *http.Client {
	return &http.Client{
		Timeout:       requestTimeout,
		CheckRedirect: slackRedirectPolicy,
	}
}

// slackRedirectPolicy bounds the pinned tornado redirect-following
// behavior (R10.1 F1/SEC-002/F5): at most maxRedirects (exactly 3)
// redirects are followed — CheckRedirect sees via holding every request
// already sent INCLUDING the original, so the guard is len(via) >
// maxRedirects, rejecting the 4th redirect — every followed hop must
// repeat the exact origin of the first request (scheme https and
// identical host including port, so a subdomain, a port change, an http
// downgrade, or any other origin change fails closed), and the Referer
// header is stripped (set to "") on every followed hop so the
// credential-bearing path of the original request can never leak to any
// other origin. Because only the identical origin may be followed,
// 307/308 body replay stays inside the original TLS endpoint.
func slackRedirectPolicy(req *http.Request, via []*http.Request) error {
	if req.URL == nil || len(via) == 0 || via[0].URL == nil {
		return errSlackRedirect
	}
	if len(via) > maxRedirects {
		return errSlackRedirect
	}
	if req.URL.Scheme != "https" || via[0].URL.Scheme != "https" {
		return errSlackRedirect
	}
	if req.URL.Host != via[0].URL.Host {
		return errSlackRedirect
	}
	req.Header.Set("Referer", "")
	return nil
}

// slackExchange is one bounded HTTP exchange.
type slackExchange struct {
	status int
	body   []byte
}

// slackDo performs one bounded exchange. Every returned error is
// value-free: transport failures never include the URL (the call_hook URL
// embeds the hook identifier), the body, or any header value. The fixed
// exchange deadline is carried on the request context so it holds for the
// module-owned client and any test-injected transport alike (SEC-004).
func slackDo(ctx context.Context, method, target string, headers map[string]string, body []byte) (slackExchange, error) {
	if len(body) > maxRequestBytes {
		return slackExchange{}, errSlackRequestLimit
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return slackExchange{}, errSlackTransport
	}
	req.Header.Set("User-Agent", userAgent)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	doer := slackHTTPClient
	if testDoer != nil {
		doer = testDoer
	}
	resp, err := doer.Do(req)
	if err != nil {
		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
			_ = resp.Body.Close()
		}
		return slackExchange{}, classifyTransportError(err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return slackExchange{}, classifyTransportError(err)
	}
	if len(payload) > maxResponseBytes {
		return slackExchange{}, errSlackResponseLimit
	}
	return slackExchange{status: resp.StatusCode, body: payload}, nil
}

// classifyTransportError maps a raw transport error onto the value-free
// sentinel set while keeping cancellation and deadline identities through
// errors.Is.
func classifyTransportError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return errSlackTimeout
	case errors.Is(err, errSlackRedirect):
		return errSlackRedirect
	default:
		return errSlackTransport
	}
}

// ---------------------------------------------------------------------------
// _get_api_key / _get_hook_id — slack_notify.py:39-55 @ pinned revision.

// slackConfigGet consults the optional config.get delegate registered in
// the Exec registry — the module-local form of Salt's config.get boundary
// (gpg/nacl/file/ssh_pki precedent). An absent delegate, an absent
// function result, or a non-string result resolves to "" so the pinned
// two-spelling ladder keeps its fail-closed tail error.
func slackConfigGet(ctx context.Context, rt *runtime.Runtime, key string) string {
	if rt == nil || rt.Exec == nil {
		return ""
	}
	fn, ok := rt.Exec.Get("config.get")
	if !ok {
		return ""
	}
	res, err := rt.Exec.Call(ctx, rt, fn.Name(), map[string]any{"key": key})
	if err != nil {
		return ""
	}
	s, _ := res.(string)
	return s
}

// getAPIKey ports _get_api_key: the pinned "slack.api_key" then
// "slack:api_key" ladder with the pinned SaltInvocationError tail.
func getAPIKey(ctx context.Context, rt *runtime.Runtime) (string, error) {
	if v := slackConfigGet(ctx, rt, "slack.api_key"); v != "" {
		return v, nil
	}
	if v := slackConfigGet(ctx, rt, "slack:api_key"); v != "" {
		return v, nil
	}
	return "", errSlackNoAPIKey
}

// getHookID ports _get_hook_id: the pinned "slack.hook" then "slack:hook"
// ladder with the pinned SaltInvocationError tail.
func getHookID(ctx context.Context, rt *runtime.Runtime) (string, error) {
	if v := slackConfigGet(ctx, rt, "slack.hook"); v != "" {
		return v, nil
	}
	if v := slackConfigGet(ctx, rt, "slack:hook"); v != "" {
		return v, nil
	}
	return "", errSlackNoHook
}

// resolveAPIKey keeps the pinned `if not api_key` head: an empty or absent
// explicit key falls through to the config ladder.
func resolveAPIKey(ctx context.Context, rt *runtime.Runtime, explicit *string) (string, error) {
	if value := pointerString(explicit); value != "" {
		return value, nil
	}
	return getAPIKey(ctx, rt)
}

// ---------------------------------------------------------------------------
// salt/utils/slack.py query — pinned revision.

// slackAPISpec maps the pinned function table to its request path and
// response-extraction key.
type slackAPISpec struct {
	request  string
	response string
}

var slackAPIEndpoints = map[string]slackAPISpec{
	"rooms":   {"conversations.list", "channels"},
	"users":   {"users.list", "members"},
	"message": {"chat.postMessage", "channel"},
}

// slackQuery ports salt/utils/slack.py query(): the fixed
// https://slack.com/api/<request> URL, the token in the Authorization
// Bearer header only, Accept: application/json on non-POST (the pinned
// header_dict postconditions), and the pinned result ladder — 200 decodes
// strictly and extracts the response key (an "error" key flips res to
// false with the error as the message), 204 answers the bare boolean
// true, and every other status dispatches on the decoded body shape: an
// object WITH an "error" key reaches the pinned result["error"] KeyError
// crash position and maps to the fixed value-free unexpected-response
// sentinel, an object without one answers the pinned "Unknown response",
// and anything else (no body, malformed, or non-object) answers the
// pinned "invalid_auth". Decoded values are redacted against the token
// before the result is built.
func slackQuery(ctx context.Context, function, apiKey, method string, body []byte) (any, error) {
	spec, ok := slackAPIEndpoints[function]
	if !ok {
		return nil, errSlackResponseShape
	}
	headers := map[string]string{"Authorization": bearerPrefix + apiKey}
	if method != http.MethodPost {
		headers["Accept"] = "application/json"
	} else {
		headers["Content-Type"] = formContentType
	}
	exchange, err := slackDo(ctx, method, apiURLBase+spec.request, headers, body)
	if err != nil {
		return nil, err
	}
	switch {
	case exchange.status == http.StatusOK:
		var decoded any
		if err := json.Unmarshal(exchange.body, &decoded); err != nil {
			return nil, errSlackDecode
		}
		obj, ok := decoded.(map[string]any)
		if !ok {
			return nil, errSlackResponseShape
		}
		if err := redactInPlace(secretVariants(apiKey), obj); err != nil {
			return nil, err
		}
		if errValue, present := obj["error"]; present {
			return map[string]any{"message": errValue, "res": false}, nil
		}
		return map[string]any{"message": obj[spec.response], "res": true}, nil
	case exchange.status == http.StatusNoContent:
		return true, nil
	default:
		// The pinned else ladder (salt/utils/slack.py:111-127): a body
		// that decodes to an object WITH an "error" key reaches the
		// pinned `result["error"]` KeyError crash position — a key the
		// http layer never set — which maps to the fixed value-free
		// unexpected-response sentinel (R10.1 F4); an object without
		// "error" answers the pinned "Unknown response"; anything else
		// (no body, malformed, or non-object) answers the pinned
		// "invalid_auth".
		var decoded any
		if err := json.Unmarshal(exchange.body, &decoded); err == nil {
			if obj, ok := decoded.(map[string]any); ok {
				if _, present := obj["error"]; present {
					return nil, errSlackResponseShape
				}
				return map[string]any{"message": "Unknown response", "res": false}, nil
			}
		}
		return map[string]any{"message": "invalid_auth", "res": false}, nil
	}
}

// ---------------------------------------------------------------------------
// shared helpers

func pointerString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// marshalJSONValue renders one JSON value without HTML escaping so the
// payload matches the pinned json.dumps rendering for characters like <
// in Slack mentions.
func marshalJSONValue(value any) (string, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// redactString replaces every secret substring with the shared
// placeholder. The secret list carries the normalized variants built by
// secretVariants so encoded echoes are redacted too.
func redactString(secrets []string, s string) string {
	for _, secret := range secrets {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, process.RedactedPlaceholder)
		}
	}
	return s
}

// secretVariants returns the secret together with the normalized forms
// under which the same credential can reappear inside decoded keys and
// values and inside raw failure bodies (R10.1 F2/SEC-003): the raw
// string, the url query- and path-escaped forms, the Go JSON
// string-escaped form (the HTML-escaping encoding/json encoder), the
// Python json.dumps default form (ensure_ascii: \\ and \" escapes, the
// \b \t \n \f \r short control escapes, and \uXXXX for every other
// character below 0x20, for DEL, and for every non-ASCII rune — astral
// runes as surrogate pairs; forward slashes are not escaped), and a
// defensive forward-slash-escaped JSON form (some encoders emit \/).
func secretVariants(secret string) []string {
	if secret == "" {
		return nil
	}
	variants := []string{secret}
	add := func(candidate string) {
		if candidate == "" || candidate == secret {
			return
		}
		for _, existing := range variants {
			if existing == candidate {
				return
			}
		}
		variants = append(variants, candidate)
	}
	add(url.QueryEscape(secret))
	add(url.PathEscape(secret))
	if quoted, err := json.Marshal(secret); err == nil {
		add(strings.Trim(string(quoted), `"`))
	}
	add(pythonJSONEscaped(secret))
	add(strings.NewReplacer(`\`, `\\`, `"`, `\"`, `/`, `\/`).Replace(secret))
	return variants
}

// pythonJSONEscaped renders secret as the inner text of a Python
// json.dumps string with default settings (ensure_ascii=True, matching
// CPython's ESCAPE_ASCII set `([\\"]|[^\ -~])`): backslash and double
// quote are backslash-escaped, the five named control characters use
// their short \b \t \n \f \r escapes, and every other character below
// 0x20, DEL (0x7f), and every non-ASCII rune renders as lowercase
// \uXXXX — astral runes as their UTF-16 surrogate pair, exactly like
// CPython. Forward slashes are not escaped.
func pythonJSONEscaped(secret string) string {
	var b strings.Builder
	for _, unit := range utf16.Encode([]rune(secret)) {
		switch unit {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if unit < 0x20 || unit >= 0x7f {
				fmt.Fprintf(&b, `\u%04x`, unit)
			} else {
				b.WriteRune(rune(unit))
			}
		}
	}
	return b.String()
}

// hookSecretVariants builds the webhook failure-body redaction inventory
// from BOTH the validated original identifier and its canonical forms
// (R10.1 SEC-003 residual): the decoded path token beneath /services/
// (the credential-bearing path actually dispatched, which differs from
// the raw identifier whenever the caller percent-encoded it), the
// normalized full URL (default port removed), and the decoded path-only
// echo of a full-URL identifier. Every form contributes its raw,
// percent-encoded, and JSON-escaped variants, deduplicated.
func hookSecretVariants(identifier string, canonical ...string) []string {
	variants := secretVariants(identifier)
	seen := make(map[string]struct{}, len(variants))
	for _, variant := range variants {
		seen[variant] = struct{}{}
	}
	for _, form := range canonical {
		for _, candidate := range secretVariants(form) {
			if _, dup := seen[candidate]; dup {
				continue
			}
			seen[candidate] = struct{}{}
			variants = append(variants, candidate)
		}
	}
	return variants
}

// redactInPlace recursively redacts secret substrings from decoded
// objects in both values and KEYS (R10.1 F2/SEC-003): a key containing a
// secret in raw or normalized form is renamed to its redacted form, and
// ordinary keys keep their exact inventory. A rename that would collide
// with an existing (or already-produced) key fails closed with the
// value-free errSlackRedactionCollision instead of overwriting (the
// mysql F1 header-collision precedent). Keys are collected before any
// assignment so the collision decision is independent of map iteration
// order.
func redactInPlace(secrets []string, value any) error {
	switch typed := value.(type) {
	case map[string]any:
		renames := make(map[string]string)
		for key, item := range typed {
			if s, ok := item.(string); ok {
				typed[key] = redactString(secrets, s)
			} else if err := redactInPlace(secrets, item); err != nil {
				return err
			}
			if renamed := redactString(secrets, key); renamed != key {
				renames[key] = renamed
			}
		}
		targets := make(map[string]struct{}, len(renames))
		for _, newKey := range renames {
			if _, dup := targets[newKey]; dup {
				return errSlackRedactionCollision
			}
			targets[newKey] = struct{}{}
			if _, exists := typed[newKey]; exists {
				return errSlackRedactionCollision
			}
		}
		for oldKey, newKey := range renames {
			item := typed[oldKey]
			delete(typed, oldKey)
			typed[newKey] = item
		}
	case []any:
		for index, item := range typed {
			if s, ok := item.(string); ok {
				typed[index] = redactString(secrets, s)
			} else if err := redactInPlace(secrets, item); err != nil {
				return err
			}
		}
	}
	return nil
}

// orEmptyList ports the pinned `attachments or []` / `blocks or []`
// truthiness (R10.1 F3): every Python-falsy input — nil (None), empty
// string, false, zero number (int/int64/float64 cover the typed-arg and
// JSON-decoded surfaces), empty map, empty array — becomes the empty
// list; every truthy value passes through unchanged.
func orEmptyList(value any) any {
	switch typed := value.(type) {
	case nil:
		return []any{}
	case string:
		if typed == "" {
			return []any{}
		}
	case bool:
		if !typed {
			return []any{}
		}
	case int:
		if typed == 0 {
			return []any{}
		}
	case int64:
		if typed == 0 {
			return []any{}
		}
	case float64:
		if typed == 0 {
			return []any{}
		}
	case []any:
		if len(typed) == 0 {
			return []any{}
		}
	case map[string]any:
		if len(typed) == 0 {
			return []any{}
		}
	}
	return value
}

// formPair keeps the pinned parameter insertion order.
type formPair struct {
	key   string
	value any
}

// renderFormValue renders one urlencoded form value: strings pass through
// verbatim; composite values render as compact JSON. The pinned source
// stringifies composites with Python str() (single-quoted reprs), which
// is not valid JSON for structured attachments — StateKit renders JSON,
// and the empty list still renders "[]" exactly like the pinned source.
func renderFormValue(value any) (string, error) {
	if s, ok := value.(string); ok {
		return s, nil
	}
	return marshalJSONValue(value)
}

// encodeForm renders the ordered pairs with Go's query escaping, which
// matches urllib.parse.urlencode's quote_plus for ASCII and UTF-8.
func encodeForm(pairs []formPair) (string, error) {
	var b strings.Builder
	for index, pair := range pairs {
		if index > 0 {
			b.WriteByte('&')
		}
		value, err := renderFormValue(pair.value)
		if err != nil {
			return "", err
		}
		b.WriteString(url.QueryEscape(pair.key))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(value))
	}
	return b.String(), nil
}

// ---------------------------------------------------------------------------
// slack.list_rooms / slack.list_users — slack_notify.py:58-95.

// ListRoomsArgs mirrors the pinned list_rooms(api_key=None) signature.
type ListRoomsArgs struct {
	APIKey *string `statekit:"name=api_key"`
}

type listRoomsFunc struct{}

func (listRoomsFunc) Name() string { return "slack.list_rooms" }
func (listRoomsFunc) Args() any    { return ListRoomsArgs{} }

func (listRoomsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListRoomsArgs](args, "slack.list_rooms")
	if err != nil {
		return nil, err
	}
	return listRooms(ctx, rt, a.APIKey)
}

func listRooms(ctx context.Context, rt *runtime.Runtime, apiKey *string) (any, error) {
	key, err := resolveAPIKey(ctx, rt, apiKey)
	if err != nil {
		return nil, err
	}
	return slackQuery(ctx, "rooms", key, http.MethodGet, nil)
}

// ListUsersArgs mirrors the pinned list_users(api_key=None) signature.
type ListUsersArgs struct {
	APIKey *string `statekit:"name=api_key"`
}

type listUsersFunc struct{}

func (listUsersFunc) Name() string { return "slack.list_users" }
func (listUsersFunc) Args() any    { return ListUsersArgs{} }

func (listUsersFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListUsersArgs](args, "slack.list_users")
	if err != nil {
		return nil, err
	}
	return listUsers(ctx, rt, a.APIKey)
}

func listUsers(ctx context.Context, rt *runtime.Runtime, apiKey *string) (any, error) {
	key, err := resolveAPIKey(ctx, rt, apiKey)
	if err != nil {
		return nil, err
	}
	return slackQuery(ctx, "users", key, http.MethodGet, nil)
}

// ---------------------------------------------------------------------------
// slack.find_room / slack.find_user — slack_notify.py:98-158.

// FindRoomArgs mirrors the pinned find_room(name, api_key=None)
// signature.
type FindRoomArgs struct {
	Name   string  `statekit:"required,name=name"`
	APIKey *string `statekit:"name=api_key"`
}

type findRoomFunc struct{}

func (findRoomFunc) Name() string { return "slack.find_room" }
func (findRoomFunc) Args() any    { return FindRoomArgs{} }

func (findRoomFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[FindRoomArgs](args, "slack.find_room")
	if err != nil {
		return nil, err
	}
	// The pinned source strips a leading hash before matching because
	// search results carry unhashed channel names.
	name := a.Name
	if strings.HasPrefix(name, "#") {
		name = name[1:]
	}
	return findEntry(ctx, rt, a.APIKey, "rooms", name)
}

// FindUserArgs mirrors the pinned find_user(name, api_key=None)
// signature.
type FindUserArgs struct {
	Name   string  `statekit:"required,name=name"`
	APIKey *string `statekit:"name=api_key"`
}

type findUserFunc struct{}

func (findUserFunc) Name() string { return "slack.find_user" }
func (findUserFunc) Args() any    { return FindUserArgs{} }

func (findUserFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[FindUserArgs](args, "slack.find_user")
	if err != nil {
		return nil, err
	}
	return findEntry(ctx, rt, a.APIKey, "users", a.Name)
}

// findEntry ports the shared find_room/find_user body: run the listing,
// keep the first exact name match, and answer the pinned False miss. The
// pinned `ret["res"]` on a 204 boolean raises TypeError; that position is
// the fixed errSlackResponseShape here, and a non-object entry in the
// list is skipped rather than raising (the defensive mysql short-row
// precedent).
func findEntry(ctx context.Context, rt *runtime.Runtime, apiKey *string, function, name string) (any, error) {
	var result any
	var err error
	if function == "rooms" {
		result, err = listRooms(ctx, rt, apiKey)
	} else {
		result, err = listUsers(ctx, rt, apiKey)
	}
	if err != nil {
		return nil, err
	}
	res, ok := result.(map[string]any)
	if !ok {
		return nil, errSlackResponseShape
	}
	if succeeded, _ := res["res"].(bool); succeeded {
		if entries, ok := res["message"].([]any); ok {
			for _, entry := range entries {
				m, ok := entry.(map[string]any)
				if !ok {
					continue
				}
				if entryName, _ := m["name"].(string); entryName == name {
					return m, nil
				}
			}
		}
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// slack.post_message — slack_notify.py:161-242.

// PostMessageArgs mirrors the pinned post_message(channel, message,
// from_name, api_key=None, icon=None, attachments=None, blocks=None)
// signature.
type PostMessageArgs struct {
	Channel     string  `statekit:"required,name=channel"`
	Message     string  `statekit:"required,name=message"`
	FromName    string  `statekit:"required,name=from_name"`
	APIKey      *string `statekit:"name=api_key"`
	Icon        *string `statekit:"name=icon"`
	Attachments any     `statekit:"name=attachments"`
	Blocks      any     `statekit:"name=blocks"`
}

type postMessageFunc struct{}

func (postMessageFunc) Name() string { return "slack.post_message" }
func (postMessageFunc) Args() any    { return PostMessageArgs{} }

func (postMessageFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[PostMessageArgs](args, "slack.post_message")
	if err != nil {
		return nil, err
	}
	key, err := resolveAPIKey(ctx, rt, a.APIKey)
	if err != nil {
		return nil, err
	}
	// The pinned source only logs missing channel/message/from_name and
	// proceeds; the channel keeps its pinned hash/@ normalization with
	// the pinned "#" + "" result for an explicit empty channel.
	channel := a.Channel
	if !strings.HasPrefix(channel, "#") && !strings.HasPrefix(channel, "@") {
		channel = "#" + channel
	}
	pairs := []formPair{
		{"channel", channel},
		{"username", a.FromName},
		{"text", a.Message},
		{"attachments", orEmptyList(a.Attachments)},
		{"blocks", orEmptyList(a.Blocks)},
	}
	if a.Icon != nil {
		pairs = append(pairs, formPair{key: "icon_url", value: *a.Icon})
	}
	body, err := encodeForm(pairs)
	if err != nil {
		return nil, errSlackRequestLimit
	}
	result, err := slackQuery(ctx, "message", key, http.MethodPost, []byte(body))
	if err != nil {
		return nil, err
	}
	res, ok := result.(map[string]any)
	if !ok {
		// The pinned `result["res"]` on a 204 boolean raises TypeError.
		return nil, errSlackResponseShape
	}
	if succeeded, _ := res["res"].(bool); succeeded {
		return true, nil
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// slack.call_hook — slack_notify.py:245-316.

// CallHookArgs mirrors the pinned call_hook(message, attachment=None,
// color="good", short=False, identifier=None, channel=None, username=None,
// icon_emoji=None) signature.
type CallHookArgs struct {
	Message    string  `statekit:"required,name=message"`
	Attachment *string `statekit:"name=attachment"`
	Color      *string `statekit:"name=color"`
	Short      *bool   `statekit:"name=short"`
	Identifier *string `statekit:"name=identifier"`
	Channel    *string `statekit:"name=channel"`
	Username   *string `statekit:"name=username"`
	IconEmoji  *string `statekit:"name=icon_emoji"`
}

type callHookFunc struct{}

func (callHookFunc) Name() string { return "slack.call_hook" }
func (callHookFunc) Args() any    { return CallHookArgs{} }

func (callHookFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[CallHookArgs](args, "slack.call_hook")
	if err != nil {
		return nil, err
	}
	identifier := pointerString(a.Identifier)
	if identifier == "" {
		identifier, err = getHookID(ctx, rt)
		if err != nil {
			return nil, err
		}
	}
	target, hookSecrets, err := hookURL(identifier)
	if err != nil {
		return nil, err
	}
	color := "good"
	if a.Color != nil {
		color = *a.Color
	}
	short := a.Short != nil && *a.Short
	payload, err := hookPayload(a.Message, pointerString(a.Attachment), color, short,
		pointerString(a.Channel), pointerString(a.Username), pointerString(a.IconEmoji))
	if err != nil {
		return nil, errSlackRequestLimit
	}
	form := url.Values{"payload": []string{payload}}.Encode()
	exchange, err := slackDo(ctx, http.MethodPost, target, nil, []byte(form))
	if err != nil {
		return nil, err
	}
	if exchange.status <= 201 {
		return true, nil
	}
	// The pinned failure dict keeps result.get("body", status): the read
	// body when present (even empty), the numeric status otherwise. The
	// body is redacted against the identifier's full canonical inventory
	// (R10.1 F2/SEC-003): the validated identifier AND its canonical
	// forms — decoded path token, normalized default-port-removed URL,
	// path-only echo — each in raw, percent-encoded, and JSON-escaped
	// (Go and Python json.dumps) variants — before it becomes the
	// message.
	return map[string]any{"res": false, "message": redactString(hookSecrets, string(exchange.body))}, nil
}

// hookURL resolves the hook identifier against the fixed
// https://hooks.slack.com/services/ origin (R10.1 SEC-001) and returns
// the dispatch target together with the identifier's redaction
// inventory (R10.1 SEC-003 residual). Two forms are accepted:
//
//   - a path-style token (one or more segments, e.g. "T00/B00/XX"):
//     segments are validated on the DECODED path — every segment must be
//     non-empty, neither "." nor "..", and free of backslashes (so the
//     encoded separators "%5C"/"%5c" and mixed forms like "%2e%5C.."
//     fail closed exactly like a plaintext backslash) — the identifier
//     must not be rooted, and the token is joined beneath the base
//     path, never resolving above it;
//   - a full URL for compatibility with the pinned absolute-identifier
//     behavior, restricted to exactly the pinned origin: scheme https,
//     exact host "hooks.slack.com", no userinfo, default-or-absent port,
//     a path strictly under /services/ with the same traversal and
//     backslash rejection, and no query or fragment.
//
// Every other form — a foreign host, plaintext http, a scheme-relative
// "//host" authority, a rooted or dot-dot path escaping /services, an
// encoded traversal, an encoded or mixed backslash separator, a
// non-default port, userinfo, or query/fragment injection — is rejected
// with the value-free errSlackInvalidHook before any transport
// dispatch. This deliberately diverges from the pinned
// urllib.parse.urljoin, which lets an absolute identifier replace the
// base entirely (an unrestricted destination).
//
// The returned secret list is hookSecretVariants over the validated
// identifier AND its canonical forms — the decoded path token beneath
// /services/, the normalized full URL (default port removed), and the
// decoded path-only echo — so a failure body echoing the credential in
// any of those shapes is redacted (SEC-003 residual).
func hookURL(identifier string) (string, []string, error) {
	if identifier == "" || strings.Contains(identifier, `\`) ||
		strings.ContainsAny(identifier, "?#") {
		return "", nil, errSlackInvalidHook
	}
	ref, err := url.Parse(identifier)
	if err != nil {
		return "", nil, errSlackInvalidHook
	}
	path := ref.Path
	if strings.HasPrefix(path, "/") {
		// Full-URL form (or a rooted path): require the exact pinned
		// origin and a path strictly under /services/. Hostname()
		// ignores an explicit default :443; any other explicit port is
		// rejected.
		if ref.Scheme != "https" || ref.Hostname() != hookHost ||
			ref.User != nil || ref.Opaque != "" ||
			(ref.Port() != "" && ref.Port() != "443") ||
			!strings.HasPrefix(path, hookPathPrefix) ||
			len(path) <= len(hookPathPrefix) {
			return "", nil, errSlackInvalidHook
		}
	} else if ref.Scheme != "" || ref.Host != "" || ref.Opaque != "" {
		// A scheme, authority, or opaque form without a usable path can
		// never be a token beneath the base.
		return "", nil, errSlackInvalidHook
	} else {
		// Path-style token: joined beneath the base path.
		path = hookPathPrefix + path
	}
	// The decoded path is scanned segment-by-segment so percent-encoded
	// and nested traversals fail closed, and so a backslash surviving
	// percent-decoding ("%5C", "%5c", or mixed encoded separators) is
	// rejected exactly like a literal one — no decoded segment may
	// carry an alternative separator character.
	for index, segment := range strings.Split(path, "/") {
		if index == 0 && segment == "" {
			continue // the leading separator of a rooted path
		}
		if segment == "" || segment == "." || segment == ".." ||
			strings.Contains(segment, `\`) {
			return "", nil, errSlackInvalidHook
		}
	}
	target := &url.URL{Scheme: "https", Host: hookHost, Path: path}
	secrets := hookSecretVariants(identifier,
		strings.TrimPrefix(path, hookPathPrefix), // decoded path token
		target.String(),                          // normalized full URL
		path,                                     // path-only echo
	)
	return target.String(), secrets, nil
}

// hookPayload builds the pinned payload dict in its pinned insertion
// order — text or the attachment quad first, then the optional channel,
// username, and icon_emoji — rendered as JSON.
func hookPayload(message, attachment, color string, short bool, channel, username, iconEmoji string) (string, error) {
	fields := make([][2]any, 0, 4)
	if attachment != "" {
		fields = append(fields, [2]any{"attachments", []any{map[string]any{
			"fallback": message,
			"color":    color,
			"pretext":  message,
			"fields":   []any{map[string]any{"value": attachment, "short": short}},
		}}})
	} else {
		fields = append(fields, [2]any{"text", message})
	}
	if channel != "" {
		fields = append(fields, [2]any{"channel", channel})
	}
	if username != "" {
		fields = append(fields, [2]any{"username", username})
	}
	if iconEmoji != "" {
		fields = append(fields, [2]any{"icon_emoji", iconEmoji})
	}
	var b strings.Builder
	b.WriteByte('{')
	for index, field := range fields {
		if index > 0 {
			b.WriteByte(',')
		}
		key, err := marshalJSONValue(field[0])
		if err != nil {
			return "", err
		}
		value, err := marshalJSONValue(field[1])
		if err != nil {
			return "", err
		}
		b.WriteString(key)
		b.WriteByte(':')
		b.WriteString(value)
	}
	b.WriteByte('}')
	return b.String(), nil
}

// ---------------------------------------------------------------------------
// registration

func typedArgs[T any](args any, name string) (*T, error) {
	value, ok := args.(*T)
	if !ok || value == nil {
		return nil, fmt.Errorf("%s: expected *arguments, got %T", name, args)
	}
	return value, nil
}

// Register installs the complete public slack catalog (6 functions).
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		listRoomsFunc{},
		listUsersFunc{},
		findRoomFunc{},
		findUserFunc{},
		postMessageFunc{},
		callHookFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
