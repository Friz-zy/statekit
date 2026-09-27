package slack

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

const redactedMarker = "***REDACTED***"

// fakeRequest captures one dispatched HTTP exchange.
type fakeRequest struct {
	method        string
	url           string
	authorization string
	accept        string
	contentType   string
	userAgent     string
	body          string
}

// fakeResult is one canned transport reply.
type fakeResult struct {
	status int
	body   string
	err    error
}

// fakeTransport is the injectable HTTP boundary: no DNS, no network.
type fakeTransport struct {
	requests  []fakeRequest
	responses []fakeResult
}

func (f *fakeTransport) Do(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	f.requests = append(f.requests, fakeRequest{
		method:        req.Method,
		url:           req.URL.String(),
		authorization: req.Header.Get("Authorization"),
		accept:        req.Header.Get("Accept"),
		contentType:   req.Header.Get("Content-Type"),
		userAgent:     req.Header.Get("User-Agent"),
		body:          string(body),
	})
	if len(f.responses) == 0 {
		return nil, errSlackTransport
	}
	result := f.responses[0]
	f.responses = f.responses[1:]
	if result.err != nil {
		return nil, result.err
	}
	return &http.Response{
		StatusCode: result.status,
		Body:       io.NopCloser(strings.NewReader(result.body)),
		Header:     make(http.Header),
	}, nil
}

func withFakeTransport(t *testing.T, transport *fakeTransport) {
	t.Helper()
	SetTestHTTPClient(t, transport)
}

func slackRT(t *testing.T) (*runtime.ExecRegistry, *runtime.Runtime) {
	t.Helper()
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	return reg, &runtime.Runtime{Exec: reg}
}

// slackCfgStub is the config.get delegate stub (the nacl/filemeta
// precedent): raw key lookup over a flat map.
type slackCfgStub struct{ vals map[string]any }

func (s slackCfgStub) Name() string { return "config.get" }
func (s slackCfgStub) Args() any    { return struct{}{} }
func (s slackCfgStub) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	m, _ := args.(map[string]any)
	key, _ := m["key"].(string)
	return s.vals[key], nil
}

func keyPtr(v string) *string { return &v }

// ---------------------------------------------------------------------------
// list_rooms / list_users transport contract

func TestSlackListRoomsListUsersTransport(t *testing.T) {
	reg, rt := slackRT(t)
	transport := &fakeTransport{responses: []fakeResult{
		{status: 200, body: `{"ok": true, "channels": [{"id": "C1", "name": "general"}]}`},
		{status: 200, body: `{"ok": true, "members": [{"id": "U1", "name": "thatch"}]}`},
	}}
	withFakeTransport(t, transport)

	value, err := reg.Call(context.Background(), rt, "slack.list_rooms", &ListRoomsArgs{APIKey: keyPtr("xoxp-test-key")})
	if err != nil {
		t.Fatalf("list_rooms: %v", err)
	}
	want := map[string]any{
		"message": []any{map[string]any{"id": "C1", "name": "general"}},
		"res":     true,
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("list_rooms value = %#v, want %#v", value, want)
	}

	value, err = reg.Call(context.Background(), rt, "slack.list_users", &ListUsersArgs{APIKey: keyPtr("xoxp-test-key")})
	if err != nil {
		t.Fatalf("list_users: %v", err)
	}
	want = map[string]any{
		"message": []any{map[string]any{"id": "U1", "name": "thatch"}},
		"res":     true,
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("list_users value = %#v, want %#v", value, want)
	}

	if len(transport.requests) != 2 {
		t.Fatalf("dispatch count = %d, want 2", len(transport.requests))
	}
	rooms, users := transport.requests[0], transport.requests[1]
	if rooms.method != http.MethodGet || rooms.url != "https://slack.com/api/conversations.list" {
		t.Fatalf("rooms request method=%q url=%q", rooms.method, rooms.url)
	}
	if users.method != http.MethodGet || users.url != "https://slack.com/api/users.list" {
		t.Fatalf("users request method=%q url=%q", users.method, users.url)
	}
	for _, req := range transport.requests {
		if req.authorization != "Bearer xoxp-test-key" {
			t.Fatalf("authorization = %q, want pinned Bearer header", req.authorization)
		}
		if req.accept != "application/json" {
			t.Fatalf("accept = %q, want pinned GET header", req.accept)
		}
		if req.contentType != "" {
			t.Fatalf("GET content-type = %q, want none", req.contentType)
		}
		if req.userAgent != userAgent {
			t.Fatalf("user agent = %q, want %q", req.userAgent, userAgent)
		}
		if req.body != "" {
			t.Fatalf("GET body = %q, want empty", req.body)
		}
		if strings.Contains(req.url, "xoxp-test-key") || strings.Contains(req.body, "xoxp-test-key") {
			t.Fatalf("token escaped the header boundary: %#v", req)
		}
	}
}

// TestSlackListResponseKeyMissing keeps the pinned .get(response) None
// shape: a 200 body without the extraction key answers message nil with
// res true.
func TestSlackListResponseKeyMissing(t *testing.T) {
	reg, rt := slackRT(t)
	transport := &fakeTransport{responses: []fakeResult{
		{status: 200, body: `{"ok": true}`},
	}}
	withFakeTransport(t, transport)

	value, err := reg.Call(context.Background(), rt, "slack.list_rooms", &ListRoomsArgs{APIKey: keyPtr("xoxp-test-key")})
	if err != nil {
		t.Fatalf("list_rooms: %v", err)
	}
	result, ok := value.(map[string]any)
	if !ok || result["res"] != true || result["message"] != nil {
		t.Fatalf("missing-key value = %#v", value)
	}
}

// ---------------------------------------------------------------------------
// pinned result ladder (salt/utils/slack.py + tests/pytests/unit/utils/test_slack.py)

func TestSlackQueryResultLadder(t *testing.T) {
	reg, rt := slackRT(t)
	call := func(response fakeResult) (any, error) {
		transport := &fakeTransport{responses: []fakeResult{response}}
		withFakeTransport(t, transport)
		return reg.Call(context.Background(), rt, "slack.list_rooms", &ListRoomsArgs{APIKey: keyPtr("xoxp-key")})
	}

	// The pinned 200-with-error vector: {"message": "token_revoked", "res": False}.
	value, err := call(fakeResult{status: 200, body: `{"ok": false, "error": "token_revoked"}`})
	if err != nil {
		t.Fatalf("error vector: %v", err)
	}
	if !reflect.DeepEqual(value, map[string]any{"message": "token_revoked", "res": false}) {
		t.Fatalf("error vector value = %#v", value)
	}

	// 204 answers the bare boolean true.
	value, err = call(fakeResult{status: 204})
	if err != nil || value != true {
		t.Fatalf("204 value = %#v err=%v", value, err)
	}

	// The pinned dict-without-error branch: "Unknown response".
	value, err = call(fakeResult{status: 201, body: `{}`})
	if err != nil {
		t.Fatalf("201 vector: %v", err)
	}
	if !reflect.DeepEqual(value, map[string]any{"message": "Unknown response", "res": false}) {
		t.Fatalf("201 value = %#v", value)
	}

	// The pinned error-dict branch (non-200/204, 2xx included): the
	// source's `result["error"]` KeyError crash position maps to the
	// fixed value-free unexpected-response sentinel (R10.1 F4).
	for _, status := range []int{201, 202, 302, 400, 404, 500} {
		_, err = call(fakeResult{status: status, body: `{"error": "nope"}`})
		if !errors.Is(err, errSlackResponseShape) {
			t.Fatalf("error-dict status %d err = %v, want unexpected-response sentinel", status, err)
		}
		if strings.Contains(err.Error(), "nope") || strings.Contains(err.Error(), "xoxp-key") {
			t.Fatalf("error-dict status %d error leaks body or token: %v", status, err)
		}
	}

	// The pinned no-dict branch: anything that does not decode to an
	// object (empty, malformed, arrays, scalars) answers "invalid_auth".
	for _, status := range []int{201, 302, 400, 401, 404, 429, 500} {
		for _, body := range []string{"", "not json{", `[]`, `"string"`, `null`} {
			value, err = call(fakeResult{status: status, body: body})
			if err != nil {
				t.Fatalf("status %d body %q: %v", status, body, err)
			}
			if !reflect.DeepEqual(value, map[string]any{"message": "invalid_auth", "res": false}) {
				t.Fatalf("status %d body %q value = %#v", status, body, value)
			}
		}
	}

	// Malformed and non-object 200 bodies are fixed value-free errors
	// (the pinned json.loads failure and non-dict attribute failures map
	// to stable errors instead of propagating Python exceptions).
	for _, body := range []string{`not json{`, `[]`, `"string"`, `null`} {
		_, err = call(fakeResult{status: 200, body: body})
		if err == nil || errors.Is(err, errSlackTransport) {
			t.Fatalf("body %q err = %v, want decode/shape error", body, err)
		}
		if strings.Contains(err.Error(), "xoxp-key") || strings.Contains(err.Error(), "slack.com") {
			t.Fatalf("body %q error leaks value or URL: %v", body, err)
		}
	}
}

// TestSlackTransportFailuresFailClosed pins the documented safe
// divergence from the pinned status-0 mappings: transport failures are
// value-free errors, never the pinned "invalid_auth" false result (API
// family) and never the pinned successful True (call_hook).
func TestSlackTransportFailuresFailClosed(t *testing.T) {
	reg, rt := slackRT(t)

	cases := []struct {
		name string
		err  error
		want error
	}{
		{name: "dns", err: errSlackTransport, want: errSlackTransport},
		{name: "deadline", err: context.DeadlineExceeded, want: errSlackTimeout},
		{name: "canceled", err: context.Canceled, want: context.Canceled},
		{name: "redirect", err: errSlackRedirect, want: errSlackRedirect},
	}
	for _, tc := range cases {
		transport := &fakeTransport{responses: []fakeResult{{err: tc.err}}}
		withFakeTransport(t, transport)
		_, err := reg.Call(context.Background(), rt, "slack.list_rooms", &ListRoomsArgs{APIKey: keyPtr("xoxp-key")})
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
		if strings.Contains(err.Error(), "xoxp-key") || strings.Contains(err.Error(), "http") {
			t.Fatalf("%s: error not value-free: %v", tc.name, err)
		}

		transport = &fakeTransport{responses: []fakeResult{{err: tc.err}}}
		withFakeTransport(t, transport)
		_, err = reg.Call(context.Background(), rt, "slack.call_hook", &CallHookArgs{Message: "hi", Identifier: keyPtr("T00/B00/XX")})
		if !errors.Is(err, tc.want) {
			t.Fatalf("call_hook %s: err = %v, want %v", tc.name, err, tc.want)
		}
		if strings.Contains(err.Error(), "T00/B00/XX") {
			t.Fatalf("call_hook %s: identifier leaked: %v", tc.name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// transport bounds and redirect policy

func TestSlackTransportBounds(t *testing.T) {
	reg, rt := slackRT(t)

	// A response body above the 4 MiB ceiling is refused value-free.
	transport := &fakeTransport{responses: []fakeResult{
		{status: 200, body: strings.Repeat("a", maxResponseBytes+1)},
	}}
	withFakeTransport(t, transport)
	_, err := reg.Call(context.Background(), rt, "slack.list_rooms", &ListRoomsArgs{APIKey: keyPtr("k")})
	if !errors.Is(err, errSlackResponseLimit) {
		t.Fatalf("oversize response err = %v", err)
	}

	// A call_hook payload above the 1 MiB request ceiling is refused
	// before any transport dispatch.
	transport = &fakeTransport{}
	withFakeTransport(t, transport)
	_, err = reg.Call(context.Background(), rt, "slack.call_hook", &CallHookArgs{
		Message:    strings.Repeat("a", maxRequestBytes),
		Identifier: keyPtr("T00/B00/XX"),
	})
	if !errors.Is(err, errSlackRequestLimit) {
		t.Fatalf("oversize request err = %v", err)
	}
	if len(transport.requests) != 0 {
		t.Fatalf("oversize request dispatched %d exchanges", len(transport.requests))
	}
}

// TestSlackRedirectPolicy pins the exact-origin redirect contract at the
// policy level (R10.1 F1/SEC-002/F5): scheme https, identical host
// including port (exact, not suffix), the Referer stripped on every
// followed hop, and exactly maxRedirects (3) redirects followed.
func TestSlackRedirectPolicy(t *testing.T) {
	origin := redirectHop(t, "https://slack.com/api/x")

	// First redirect from the original request: allowed, Referer cleared.
	first := redirectHop(t, "https://slack.com/api/y")
	first.Header.Set("Referer", "https://slack.com/api/x")
	if err := slackRedirectPolicy(first, []*http.Request{origin}); err != nil {
		t.Fatalf("first same-origin https hop rejected: %v", err)
	}
	if got := first.Header.Get("Referer"); got != "" {
		t.Fatalf("followed hop Referer = %q, want stripped", got)
	}

	// Exactly 3 redirects are followed. CheckRedirect's via carries
	// every request already sent including the original, so the 3rd
	// redirect sees via length 3 and passes...
	third := redirectHop(t, "https://slack.com/api/z")
	if err := slackRedirectPolicy(third, []*http.Request{origin, origin, origin}); err != nil {
		t.Fatalf("third hop rejected: %v", err)
	}
	// ...and the 4th (via length 4, the N+1 chain tail) fails closed.
	if err := slackRedirectPolicy(redirectHop(t, "https://slack.com/api/z"),
		[]*http.Request{origin, origin, origin, origin}); !errors.Is(err, errSlackRedirect) {
		t.Fatalf("fourth hop err = %v, want errSlackRedirect", err)
	}

	// Any origin change on a followed hop fails closed: plaintext
	// downgrade, foreign host, subdomain (exact, not suffix), and port
	// change.
	for _, target := range []string{
		"http://slack.com/api/y",
		"https://evil.example/api/y",
		"https://slack.com.evil.example/api/y",
		"https://hooks.slack.com/api/y",
		"https://slack.com:8443/api/y",
		"https://slack.com:443/api/y",
	} {
		if err := slackRedirectPolicy(redirectHop(t, target), []*http.Request{origin}); !errors.Is(err, errSlackRedirect) {
			t.Fatalf("redirect to %s err = %v, want errSlackRedirect", target, err)
		}
	}

	// Degenerate inputs fail closed rather than following blindly.
	if err := slackRedirectPolicy(redirectHop(t, "https://slack.com/api/y"), nil); !errors.Is(err, errSlackRedirect) {
		t.Fatalf("empty via err = %v, want errSlackRedirect", err)
	}
}

func redirectHop(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// loopbackTLSClient builds a client that applies the module redirect
// policy while dialing the loopback-only httptest TLS server for any
// host: request URLs keep their production origins (slack.com) so the
// policy decisions under test are the production ones, while no DNS
// resolution or external network happens.
func loopbackTLSClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	return &http.Client{
		Timeout:       requestTimeout,
		CheckRedirect: slackRedirectPolicy,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
				if err != nil {
					return nil, err
				}
				return tls.Client(raw, &tls.Config{
					InsecureSkipVerify: true, // ephemeral loopback test certificate only
					ServerName:         "slack.com",
				}), nil
			},
		},
	}
}

// TestSlackRedirectChainLoopback drives the module redirect policy
// end-to-end over loopback TLS: a full same-origin chain of exactly 3
// followed redirects succeeds with an empty Referer on every hop, a
// 307 hop replays the body inside the identical origin, the N+1 chain
// (4th redirect) and every origin change fail closed after the first
// exchange. httptest binds 127.0.0.1 only; no external network.
func TestSlackRedirectChainLoopback(t *testing.T) {
	newChain := func(t *testing.T, redirects []string) (*httptest.Server, *[]string, *[]string, *string) {
		t.Helper()
		var hits, referers []string
		var finalBody string
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits = append(hits, r.URL.String())
			referers = append(referers, r.Header.Get("Referer"))
			for index, location := range redirects {
				if r.URL.Path == fmt.Sprintf("/api/step%d", index+1) {
					w.Header().Set("Location", location)
					// 307 at every hop keeps method+body replay in
					// play; the policy must still allow the chain
					// because the origin never changes.
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
			}
			raw, _ := io.ReadAll(r.Body)
			finalBody = string(raw)
			_, _ = w.Write([]byte("final"))
		}))
		t.Cleanup(server.Close)
		return server, &hits, &referers, &finalBody
	}
	post := func(t *testing.T, client *http.Client, url string) (*http.Response, error) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, url, strings.NewReader("body-bytes"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Referer", "https://slack.com/api/step1")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "final" {
			t.Fatalf("final body = %q", body)
		}
		return resp, nil
	}

	// Full same-origin N chain (3 redirects): the final hop answers 200.
	t.Run("exact-three-redirects", func(t *testing.T) {
		server, hits, referers, finalBody := newChain(t, []string{
			"https://slack.com/api/step2",
			"https://slack.com/api/step3",
			"https://slack.com/api/final", // 307: method+body replay inside the identical origin
		})
		resp, err := post(t, loopbackTLSClient(t, server), "https://slack.com/api/step1")
		if err != nil {
			t.Fatalf("three-redirect chain: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("chain status = %d", resp.StatusCode)
		}
		if len(*hits) != maxRedirects+1 {
			t.Fatalf("chain exchanges = %d, want %d", len(*hits), maxRedirects+1)
		}
		// Only the original request carries its own Referer; every
		// followed hop is stripped by the policy.
		for index, referer := range (*referers)[1:] {
			if referer != "" {
				t.Fatalf("followed hop %d Referer = %q, want stripped", index+2, referer)
			}
		}
		if last := (*hits)[len(*hits)-1]; last != "/api/final" {
			t.Fatalf("final hit = %q", last)
		}
		if *finalBody != "body-bytes" {
			t.Fatalf("307 replay body = %q", *finalBody)
		}
	})

	// Full N+1 chain: the 4th redirect fails closed after exactly 4
	// exchanges.
	t.Run("fourth-redirect-fails", func(t *testing.T) {
		server, hits, _, _ := newChain(t, []string{
			"https://slack.com/api/step2",
			"https://slack.com/api/step3",
			"https://slack.com/api/step4",
			"https://slack.com/api/final",
		})
		_, err := post(t, loopbackTLSClient(t, server), "https://slack.com/api/step1")
		if !errors.Is(err, errSlackRedirect) {
			t.Fatalf("N+1 chain err = %v, want errSlackRedirect", err)
		}
		if len(*hits) != maxRedirects+1 {
			t.Fatalf("N+1 chain exchanges = %d, want %d", len(*hits), maxRedirects+1)
		}
		if strings.Contains(fmt.Sprint(err), "body-bytes") {
			t.Fatalf("redirect error carries body bytes: %v", err)
		}
	})

	// Every origin change on the first hop fails closed with exactly one
	// exchange and no Referer leakage.
	for name, target := range map[string]string{
		"plaintext-downgrade": "http://slack.com/api/evil",
		"foreign-host":        "https://evil.example/api/evil",
		"subdomain":           "https://evil.slack.com/api/evil",
		"port-change":         "https://slack.com:8443/api/evil",
	} {
		t.Run("reject-"+name, func(t *testing.T) {
			server, hits, _, _ := newChain(t, []string{target, "https://slack.com/api/step3"})
			_, err := post(t, loopbackTLSClient(t, server), "https://slack.com/api/step1")
			if !errors.Is(err, errSlackRedirect) {
				t.Fatalf("cross-origin redirect err = %v, want errSlackRedirect", err)
			}
			if len(*hits) != 1 {
				t.Fatalf("cross-origin exchanges = %d, want 1", len(*hits))
			}
		})
	}
}

// TestSlackProductionClientBounds pins the module-owned production
// doer: a bounded stdlib client (30s timeout, redirect policy) that the
// test seam never mutates.
func TestSlackProductionClientBounds(t *testing.T) {
	client, ok := slackHTTPClient.(*http.Client)
	if !ok {
		t.Fatalf("production client is %T", slackHTTPClient)
	}
	if client.Timeout != 30*time.Second {
		t.Fatalf("client timeout = %v, want 30s", client.Timeout)
	}
	if client.CheckRedirect == nil {
		t.Fatal("client has no redirect policy")
	}
	if testDoer != nil {
		t.Fatal("production doer mutated outside the test seam")
	}
}

// ---------------------------------------------------------------------------
// find_room / find_user shapes

func TestSlackFindRoomFindUser(t *testing.T) {
	reg, rt := slackRT(t)

	listAndFind := func(listBody string, target string, args any) (any, error) {
		transport := &fakeTransport{responses: []fakeResult{{status: 200, body: listBody}}}
		withFakeTransport(t, transport)
		return reg.Call(context.Background(), rt, target, args)
	}

	// Hit: the matching room map comes back with the pinned hash
	// stripping applied to the requested name.
	value, err := listAndFind(
		`{"ok": true, "channels": [{"id": "C1", "name": "general"}, {"id": "C2", "name": "random"}]}`,
		"slack.find_room",
		&FindRoomArgs{Name: "#random", APIKey: keyPtr("xoxp-key")})
	if err != nil {
		t.Fatalf("find_room: %v", err)
	}
	if !reflect.DeepEqual(value, map[string]any{"id": "C2", "name": "random"}) {
		t.Fatalf("find_room hit = %#v", value)
	}

	// Miss answers the pinned False.
	value, err = listAndFind(
		`{"ok": true, "channels": [{"id": "C1", "name": "general"}]}`,
		"slack.find_room", &FindRoomArgs{Name: "absent", APIKey: keyPtr("xoxp-key")})
	if err != nil || value != false {
		t.Fatalf("find_room miss = %#v err=%v", value, err)
	}

	// Empty list answers the pinned falsy False.
	value, err = listAndFind(`{"ok": true, "channels": []}`,
		"slack.find_room", &FindRoomArgs{Name: "general", APIKey: keyPtr("xoxp-key")})
	if err != nil || value != false {
		t.Fatalf("find_room empty = %#v err=%v", value, err)
	}

	// A res=false listing (server error key) answers False, not a crash.
	value, err = listAndFind(`{"ok": false, "error": "channel_not_found"}`,
		"slack.find_room", &FindRoomArgs{Name: "general", APIKey: keyPtr("xoxp-key")})
	if err != nil || value != false {
		t.Fatalf("find_room failed listing = %#v err=%v", value, err)
	}

	// find_user keeps the same contract over members.
	value, err = listAndFind(
		`{"ok": true, "members": [{"id": "U1", "name": "thatch"}]}`,
		"slack.find_user", &FindUserArgs{Name: "thatch", APIKey: keyPtr("xoxp-key")})
	if err != nil {
		t.Fatalf("find_user: %v", err)
	}
	if !reflect.DeepEqual(value, map[string]any{"id": "U1", "name": "thatch"}) {
		t.Fatalf("find_user hit = %#v", value)
	}

	// The pinned TypeError position: a 204 listing consumed by find_room
	// is the fixed value-free unexpected-response error.
	transport := &fakeTransport{responses: []fakeResult{{status: 204}}}
	withFakeTransport(t, transport)
	_, err = reg.Call(context.Background(), rt, "slack.find_room", &FindRoomArgs{Name: "general", APIKey: keyPtr("xoxp-key")})
	if !errors.Is(err, errSlackResponseShape) {
		t.Fatalf("find_room 204 err = %v", err)
	}
}

// ---------------------------------------------------------------------------
// post_message (tests/pytests/unit/modules/test_slack.py vectors)

func TestSlackPostMessageBareVector(t *testing.T) {
	reg, rt := slackRT(t)
	transport := &fakeTransport{responses: []fakeResult{
		{status: 200, body: `{"ok": true, "channel": "C1"}`},
	}}
	withFakeTransport(t, transport)

	value, err := reg.Call(context.Background(), rt, "slack.post_message", &PostMessageArgs{
		Channel:  "fake_channel",
		FromName: "salt server",
		Message:  "test message",
		APIKey:   keyPtr("xxx-xx-xxx"),
	})
	if err != nil || value != true {
		t.Fatalf("post_message value = %#v err = %v", value, err)
	}

	if len(transport.requests) != 1 {
		t.Fatalf("dispatch count = %d", len(transport.requests))
	}
	req := transport.requests[0]
	if req.method != http.MethodPost || req.url != "https://slack.com/api/chat.postMessage" {
		t.Fatalf("post_message method=%q url=%q", req.method, req.url)
	}
	if req.authorization != "Bearer xxx-xx-xxx" {
		t.Fatalf("post_message authorization = %q", req.authorization)
	}
	if req.contentType != formContentType {
		t.Fatalf("post_message content-type = %q", req.contentType)
	}
	if req.accept != "" {
		t.Fatalf("post_message accept = %q, want none on POST", req.accept)
	}
	// The pinned bare-minimum urlencoded body byte-for-byte (Python
	// str([]) and Go's empty-list JSON both render "[]").
	wantBody := "channel=%23fake_channel&username=salt+server&text=test+message&attachments=%5B%5D&blocks=%5B%5D"
	if req.body != wantBody {
		t.Fatalf("post_message body = %q, want %q", req.body, wantBody)
	}
}

func TestSlackPostMessageAttachmentsBlocksVector(t *testing.T) {
	reg, rt := slackRT(t)
	transport := &fakeTransport{responses: []fakeResult{
		{status: 200, body: `{"ok": true}`},
	}}
	withFakeTransport(t, transport)

	_, err := reg.Call(context.Background(), rt, "slack.post_message", &PostMessageArgs{
		Channel:     "fake_channel",
		FromName:    "salt server",
		Message:     "test message",
		APIKey:      keyPtr("xxx-xx-xxx"),
		Attachments: []any{map[string]any{"text": "And heres an attachment!"}},
		Blocks: []any{map[string]any{
			"type": "header",
			"text": map[string]any{"type": "plain_text", "text": "New request"},
		}},
	})
	if err != nil {
		t.Fatalf("post_message: %v", err)
	}

	body := transport.requests[0].body
	// Order keeps the pinned parameter insertion; composite values render
	// as compact JSON (the documented str()-repr divergence: Go-sorted
	// object keys instead of Python dict insertion order).
	prefix := "channel=%23fake_channel&username=salt+server&text=test+message"
	if !strings.HasPrefix(body, prefix+"&") {
		t.Fatalf("post_message parameter order = %q", body)
	}
	attachmentsAt := strings.Index(body, "&attachments=")
	blocksAt := strings.Index(body, "&blocks=")
	if attachmentsAt < 0 || blocksAt <= attachmentsAt {
		t.Fatalf("post_message parameter order = %q", body)
	}
	form, err := url.ParseQuery(body)
	if err != nil {
		t.Fatalf("post_message form decode: %v", err)
	}
	for _, field := range []struct {
		key  string
		want any
	}{
		{"attachments", []any{map[string]any{"text": "And heres an attachment!"}}},
		{"blocks", []any{map[string]any{
			"type": "header",
			"text": map[string]any{"type": "plain_text", "text": "New request"},
		}}},
	} {
		values := form[field.key]
		if len(values) != 1 {
			t.Fatalf("post_message %s = %#v", field.key, values)
		}
		var decoded any
		if err := json.Unmarshal([]byte(values[0]), &decoded); err != nil {
			t.Fatalf("post_message %s json: %v (%q)", field.key, err, values[0])
		}
		if !reflect.DeepEqual(decoded, field.want) {
			t.Fatalf("post_message %s = %#v, want %#v", field.key, decoded, field.want)
		}
	}
	if strings.Contains(body, "xxx-xx-xxx") {
		t.Fatalf("token in post body: %q", body)
	}
}

func TestSlackPostMessageShapes(t *testing.T) {
	reg, rt := slackRT(t)

	// @-prefixed direct channels are not double-prefixed; icon adds the
	// pinned icon_url parameter last.
	transport := &fakeTransport{responses: []fakeResult{{status: 200, body: `{"ok": true}`}}}
	withFakeTransport(t, transport)
	_, err := reg.Call(context.Background(), rt, "slack.post_message", &PostMessageArgs{
		Channel: "@direct", FromName: "bot", Message: "hi",
		APIKey: keyPtr("k"), Icon: keyPtr("https://example/icon.png"),
	})
	if err != nil {
		t.Fatalf("post_message: %v", err)
	}
	body := transport.requests[0].body
	if !strings.HasPrefix(body, "channel=%40direct&") {
		t.Fatalf("@ channel body = %q", body)
	}
	if !strings.HasSuffix(body, "&icon_url=https%3A%2F%2Fexample%2Ficon.png") {
		t.Fatalf("icon_url body = %q", body)
	}

	// A failed result returns the pinned {message, res} dict.
	transport = &fakeTransport{responses: []fakeResult{{status: 200, body: `{"ok": false, "error": "not_in_channel"}`}}}
	withFakeTransport(t, transport)
	value, err := reg.Call(context.Background(), rt, "slack.post_message", &PostMessageArgs{
		Channel: "general", FromName: "bot", Message: "hi", APIKey: keyPtr("k"),
	})
	if err != nil {
		t.Fatalf("post_message failure: %v", err)
	}
	if !reflect.DeepEqual(value, map[string]any{"message": "not_in_channel", "res": false}) {
		t.Fatalf("post_message failure value = %#v", value)
	}

	// The pinned TypeError position: a 204 result is the fixed
	// value-free unexpected-response error.
	transport = &fakeTransport{responses: []fakeResult{{status: 204}}}
	withFakeTransport(t, transport)
	_, err = reg.Call(context.Background(), rt, "slack.post_message", &PostMessageArgs{
		Channel: "general", FromName: "bot", Message: "hi", APIKey: keyPtr("k"),
	})
	if !errors.Is(err, errSlackResponseShape) {
		t.Fatalf("post_message 204 err = %v", err)
	}
}

// TestSlackPostMessageFalsyDefaults pins the `attachments or []` /
// `blocks or []` truthiness for every Python-falsy input (R10.1 F3):
// nil, empty string, false, zero (int/int64/float64), empty map, and
// empty array all render [] exactly like the pinned source; truthy
// values pass through unchanged.
func TestSlackPostMessageFalsyDefaults(t *testing.T) {
	reg, rt := slackRT(t)
	falsy := map[string]any{
		"nil":          nil,
		"empty-string": "",
		"false":        false,
		"int-zero":     0,
		"int64-zero":   int64(0),
		"float-zero":   float64(0),
		"empty-array":  []any{},
		"empty-map":    map[string]any{},
	}
	for name, value := range falsy {
		transport := &fakeTransport{responses: []fakeResult{{status: 200, body: `{"ok": true}`}}}
		withFakeTransport(t, transport)
		_, err := reg.Call(context.Background(), rt, "slack.post_message", &PostMessageArgs{
			Channel: "general", FromName: "bot", Message: "hi", APIKey: keyPtr("k"),
			Attachments: value,
		})
		if err != nil {
			t.Fatalf("falsy %s: %v", name, err)
		}
		body := transport.requests[0].body
		if !strings.Contains(body, "&attachments=%5B%5D&blocks=%5B%5D") {
			t.Fatalf("falsy %s body = %q, want [] rendering for both fields", name, body)
		}
	}

	// Truthy values pass through: a non-empty string stays verbatim and
	// a non-empty number renders its JSON form.
	for name, tc := range map[string]struct {
		value any
		want  string
	}{
		"string":    {"a note", "a+note"},
		"int":       {2, "2"},
		"float":     {1.5, "1.5"},
		"true-bool": {true, "true"},
	} {
		transport := &fakeTransport{responses: []fakeResult{{status: 200, body: `{"ok": true}`}}}
		withFakeTransport(t, transport)
		_, err := reg.Call(context.Background(), rt, "slack.post_message", &PostMessageArgs{
			Channel: "general", FromName: "bot", Message: "hi", APIKey: keyPtr("k"),
			Attachments: tc.value,
		})
		if err != nil {
			t.Fatalf("truthy %s: %v", name, err)
		}
		if !strings.Contains(transport.requests[0].body, "&attachments="+tc.want+"&") {
			t.Fatalf("truthy %s body = %q, want passthrough %q", name, transport.requests[0].body, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// call_hook

func TestSlackCallHookTextPayload(t *testing.T) {
	reg, rt := slackRT(t)
	transport := &fakeTransport{responses: []fakeResult{{status: 200, body: "ok"}}}
	withFakeTransport(t, transport)

	value, err := reg.Call(context.Background(), rt, "slack.call_hook", &CallHookArgs{
		Message:    "Hello, from StateKit",
		Identifier: keyPtr("T00/B00/XX"),
	})
	if err != nil || value != true {
		t.Fatalf("call_hook value = %#v err = %v", value, err)
	}

	req := transport.requests[0]
	if req.method != http.MethodPost || req.url != "https://hooks.slack.com/services/T00/B00/XX" {
		t.Fatalf("call_hook method=%q url=%q", req.method, req.url)
	}
	if req.authorization != "" {
		t.Fatalf("call_hook authorization = %q, want none (hook credential is the URL path)", req.authorization)
	}
	if req.userAgent != userAgent {
		t.Fatalf("call_hook user agent = %q", req.userAgent)
	}
	form, err := url.ParseQuery(req.body)
	if err != nil || len(form) != 1 || form["payload"] == nil {
		t.Fatalf("call_hook body = %q err=%v", req.body, err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(form["payload"][0]), &payload); err != nil {
		t.Fatalf("payload decode: %v (%q)", err, form["payload"][0])
	}
	if payload["text"] != "Hello, from StateKit" || len(payload) != 1 {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestSlackCallHookAttachmentPayloadDefaults(t *testing.T) {
	reg, rt := slackRT(t)
	transport := &fakeTransport{responses: []fakeResult{{status: 200, body: "ok"}}}
	withFakeTransport(t, transport)

	_, err := reg.Call(context.Background(), rt, "slack.call_hook", &CallHookArgs{
		Message:    "topic",
		Attachment: keyPtr("attached message"),
		Identifier: keyPtr("T00/B00/XX"),
	})
	if err != nil {
		t.Fatalf("call_hook: %v", err)
	}
	form, _ := url.ParseQuery(transport.requests[0].body)
	var payload map[string]any
	if err := json.Unmarshal([]byte(form["payload"][0]), &payload); err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	attachments, ok := payload["attachments"].([]any)
	if !ok || len(attachments) != 1 {
		t.Fatalf("payload = %#v", payload)
	}
	attachment, _ := attachments[0].(map[string]any)
	want := map[string]any{
		"fallback": "topic",
		"color":    "good", // pinned default
		"pretext":  "topic",
		"fields":   []any{map[string]any{"value": "attached message", "short": false}},
	}
	if !reflect.DeepEqual(attachment, want) {
		t.Fatalf("attachment = %#v, want %#v", attachment, want)
	}

	// Explicit color/short/channel/username/icon_emoji keep their pinned
	// payload positions.
	transport = &fakeTransport{responses: []fakeResult{{status: 200, body: "ok"}}}
	withFakeTransport(t, transport)
	short := true
	_, err = reg.Call(context.Background(), rt, "slack.call_hook", &CallHookArgs{
		Message: "m", Attachment: keyPtr("a"), Color: keyPtr("danger"), Short: &short,
		Identifier: keyPtr("T00/B00/XX"), Channel: keyPtr("#alerts"),
		Username: keyPtr("monitor"), IconEmoji: keyPtr(":fire:"),
	})
	if err != nil {
		t.Fatalf("call_hook explicit: %v", err)
	}
	form, _ = url.ParseQuery(transport.requests[0].body)
	payload = map[string]any{}
	if err := json.Unmarshal([]byte(form["payload"][0]), &payload); err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	if payload["channel"] != "#alerts" || payload["username"] != "monitor" || payload["icon_emoji"] != ":fire:" {
		t.Fatalf("payload optional fields = %#v", payload)
	}
	attachment, _ = payload["attachments"].([]any)[0].(map[string]any)
	if attachment["color"] != "danger" {
		t.Fatalf("color = %#v", attachment["color"])
	}
	fields, _ := attachment["fields"].([]any)
	field, _ := fields[0].(map[string]any)
	if field["short"] != true {
		t.Fatalf("short = %#v", field["short"])
	}
}

func TestSlackCallHookStatusLadder(t *testing.T) {
	reg, rt := slackRT(t)
	call := func(status int, body string) (any, error) {
		transport := &fakeTransport{responses: []fakeResult{{status: status, body: body}}}
		withFakeTransport(t, transport)
		return reg.Call(context.Background(), rt, "slack.call_hook", &CallHookArgs{
			Message: "m", Identifier: keyPtr("T00/B00/XX"),
		})
	}

	// The pinned status<=201 success window.
	for _, status := range []int{200, 201} {
		value, err := call(status, "ok")
		if err != nil || value != true {
			t.Fatalf("status %d value = %#v err = %v", status, value, err)
		}
	}

	// Above the window the pinned {res: False, message: body-or-status}
	// dict comes back, redacted against the hook identifier.
	value, err := call(404, "no_hook T00/B00/XX found")
	if err != nil {
		t.Fatalf("404: %v", err)
	}
	if !reflect.DeepEqual(value, map[string]any{
		"res":     false,
		"message": "no_hook " + redactedMarker + " found",
	}) {
		t.Fatalf("404 value = %#v", value)
	}

	// An empty failure body keeps the pinned body-string shape.
	value, err = call(500, "")
	if err != nil {
		t.Fatalf("500: %v", err)
	}
	if !reflect.DeepEqual(value, map[string]any{"res": false, "message": ""}) {
		t.Fatalf("500 value = %#v", value)
	}

	// Failure bodies carrying the credential in NORMALIZED forms —
	// percent-encoded and JSON-escaped variants of the identifier — are
	// redacted too (R10.1 F2/SEC-003).
	for name, body := range map[string]string{
		"percent-encoded": "hook T00%2FB00%2FXX invalid",
		"json-escaped":    `hook "T00\/B00\/XX" invalid`,
		"raw":             "hook T00/B00/XX invalid",
	} {
		value, err = call(502, body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rendered, _ := json.Marshal(value)
		if strings.Contains(string(rendered), "T00") || strings.Contains(string(rendered), "B00") {
			t.Fatalf("%s failure body leaked identifier: %s", name, rendered)
		}
		if !strings.Contains(string(rendered), redactedMarker) {
			t.Fatalf("%s failure body missing marker: %s", name, rendered)
		}
	}
}

// TestSlackCallHookFailureBodyCanonicalForms pins the SEC-003 residual:
// a webhook failure body echoing the credential through any CANONICAL
// form of the identifier — the decoded path token (when the caller
// percent-encoded the token), the normalized full URL (default port
// removed), the path-only echo, or the Python json.dumps ASCII escape —
// is redacted against the full canonical inventory with zero
// unredacted credential bytes in the rendered result.
func TestSlackCallHookFailureBodyCanonicalForms(t *testing.T) {
	reg, rt := slackRT(t)
	vectors := []struct {
		name       string
		identifier string
		forbidden  []string
		bodies     []string
	}{
		{
			name:       "encoded-token-decoded-echo",
			identifier: "T00%2FB00%2Fsec",
			forbidden:  []string{"T00/B00/sec", "T00%2FB00%2Fsec", "/services/T00"},
			bodies: []string{
				"hook T00/B00/sec invalid",                                  // decoded token
				"hook https://hooks.slack.com/services/T00/B00/sec invalid", // normalized URL
				"hook /services/T00/B00/sec invalid",                        // path-only echo
			},
		},
		{
			name:       "default-port-normalized-echo",
			identifier: "https://hooks.slack.com:443/services/T00/B00/port",
			forbidden:  []string{"T00/B00/port", "https://hooks.slack.com:443/services/T00/B00/port", "/services/T00/B00/port"},
			bodies: []string{
				"hook https://hooks.slack.com/services/T00/B00/port invalid", // port removed
				"hook /services/T00/B00/port invalid",                        // path-only echo
				"hook T00/B00/port invalid",                                  // decoded token
			},
		},
		{
			name:       "python-escaped-echo",
			identifier: "T00/B00/ÜÜ",
			forbidden:  []string{"T00/B00/ÜÜ", `T00/B00/\u00dc`, "T00/B00/%C3%9C"},
			bodies: []string{
				`hook T00/B00/\u00dc\u00dc invalid`,                                  // Python json.dumps ASCII echo
				"hook https://hooks.slack.com/services/T00/B00/%C3%9C%C3%9C invalid", // normalized URL echo
			},
		},
	}
	for _, v := range vectors {
		// The dispatched target is always the decoded canonical URL.
		for _, body := range v.bodies {
			transport := &fakeTransport{responses: []fakeResult{{status: 500, body: body}}}
			withFakeTransport(t, transport)
			value, err := reg.Call(context.Background(), rt, "slack.call_hook", &CallHookArgs{
				Message: "m", Identifier: keyPtr(v.identifier),
			})
			if err != nil {
				t.Fatalf("%s body %q: %v", v.name, body, err)
			}
			rendered, _ := json.Marshal(value)
			for _, leak := range v.forbidden {
				if strings.Contains(string(rendered), leak) {
					t.Fatalf("%s body %q leaked credential form %q: %s", v.name, body, leak, rendered)
				}
			}
			if !strings.Contains(string(rendered), redactedMarker) {
				t.Fatalf("%s body %q missing marker: %s", v.name, body, rendered)
			}
		}
	}
}

// TestSlackCallHookRejectsForeignOrigin replaces the pre-remediation
// loopback-acceptance vector: an absolute http loopback identifier — the
// shape the pinned urljoin accepted — is now rejected value-free before
// any transport dispatch, and the loopback server is never contacted.
func TestSlackCallHookRejectsForeignOrigin(t *testing.T) {
	reg, rt := slackRT(t)
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	defer server.Close()
	transport := &fakeTransport{}
	withFakeTransport(t, transport)

	_, err := reg.Call(context.Background(), rt, "slack.call_hook", &CallHookArgs{
		Message:    "must not dispatch",
		Identifier: keyPtr(server.URL + "/hook"),
	})
	if !errors.Is(err, errSlackInvalidHook) {
		t.Fatalf("foreign-origin identifier err = %v, want errSlackInvalidHook", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("rejection error carries the destination: %v", err)
	}
	if hits != 0 {
		t.Fatalf("loopback server contacted %d times", hits)
	}
	if len(transport.requests) != 0 {
		t.Fatalf("rejected identifier dispatched %d exchanges", len(transport.requests))
	}

	// A plaintext identifier and an arbitrary https origin are rejected
	// identically with zero dispatch.
	for _, identifier := range []string{"http://127.0.0.1:1/x", "https://evil.example/T00/B00/XX"} {
		_, err = reg.Call(context.Background(), rt, "slack.call_hook", &CallHookArgs{
			Message: "m", Identifier: keyPtr(identifier),
		})
		if !errors.Is(err, errSlackInvalidHook) {
			t.Fatalf("identifier %q err = %v", identifier, err)
		}
	}

	// The compatibility form still dispatches: a full pinned-origin URL
	// reaches exactly https://hooks.slack.com/services/....
	transport = &fakeTransport{responses: []fakeResult{{status: 200, body: "ok"}}}
	withFakeTransport(t, transport)
	value, err := reg.Call(context.Background(), rt, "slack.call_hook", &CallHookArgs{
		Message:    "compat",
		Identifier: keyPtr("https://hooks.slack.com/services/T00/B00/compat"),
	})
	if err != nil || value != true {
		t.Fatalf("full-origin identifier value = %#v err = %v", value, err)
	}
	if got := transport.requests[0].url; got != "https://hooks.slack.com/services/T00/B00/compat" {
		t.Fatalf("full-origin identifier url = %q", got)
	}
}

// TestSlackHookURLOriginValidation pins the fixed-origin identifier
// contract (R10.1 SEC-001): path-style tokens join beneath
// https://hooks.slack.com/services/ with traversal rejection, and the
// only accepted full URL is exactly that origin — every foreign,
// plaintext, scheme-relative, rooted, traversal, port, userinfo, or
// query/fragment form is rejected with the value-free sentinel.
func TestSlackHookURLOriginValidation(t *testing.T) {
	valid := map[string]string{
		"T00/B00/XX":                                      "https://hooks.slack.com/services/T00/B00/XX",
		"T00/B00/XX/with/more/segments":                   "https://hooks.slack.com/services/T00/B00/XX/with/more/segments",
		"token-alphanumeric":                              "https://hooks.slack.com/services/token-alphanumeric",
		"https://hooks.slack.com/services/T00/B00/XX":     "https://hooks.slack.com/services/T00/B00/XX",
		"https://hooks.slack.com:443/services/T00/B00/XX": "https://hooks.slack.com/services/T00/B00/XX",
	}
	for identifier, want := range valid {
		got, secrets, err := hookURL(identifier)
		if err != nil || got != want {
			t.Fatalf("hookURL(%q) = %q err=%v, want %q", identifier, got, err, want)
		}
		if len(secrets) == 0 {
			t.Fatalf("hookURL(%q) returned an empty redaction inventory", identifier)
		}
	}
	invalid := []string{
		"",
		// tokens that escape or degrade the base join
		"/T00/B00/XX",
		"../T00/B00/XX",
		"T00/../B00",
		"T00/./B00",
		"T00//B00",
		"T00/B00/XX/",
		".",
		"..",
		// percent-encoded traversals (decoded path scans)
		"%2e%2e/T00/B00/XX",
		"T00/%2e%2e/B00",
		"https://hooks.slack.com/services/%2e%2e/T00",
		// foreign origins and authority replacement
		"https://other.example/x",
		"http://hooks.slack.com/services/T00/B00/XX",
		"//hooks.slack.com/services/T00/B00/XX",
		"//evil.example/x",
		"https://hooks.slack.com.evil.example/services/T00",
		"https://hooks.slack.com@evil.example/services/T00",
		"https://user@hooks.slack.com/services/T00",
		"https://user:pass@hooks.slack.com/services/T00",
		// pinned origin, wrong path or port
		"https://hooks.slack.com/T00/B00/XX",
		"https://hooks.slack.com/services/",
		"https://hooks.slack.com/services/../T00",
		"https://hooks.slack.com:8443/services/T00/B00/XX",
		"https://hooks.slack.com//services/T00",
		// query/fragment injection
		"https://hooks.slack.com/services/T00?x=1",
		"https://hooks.slack.com/services/T00#f",
		"T00/B00/XX?x=1",
		"T00/B00/XX#f",
		"T00/B00/XX?",
		// backslash and control bytes
		`..\T00`,
		`T00\B00`,
		"T00/B00/\x7f",
	}
	for _, identifier := range invalid {
		got, secrets, err := hookURL(identifier)
		if !errors.Is(err, errSlackInvalidHook) || got != "" || secrets != nil {
			t.Fatalf("hookURL(%q) = %q secrets=%d err=%v, want rejection", identifier, got, len(secrets), err)
		}
		if identifier != "" && strings.Contains(err.Error(), identifier) {
			t.Fatalf("hookURL(%q) error carries the credential path: %v", identifier, err)
		}
	}
}

// TestSlackHookURLRejectsDecodedBackslash pins the SEC-001 residual:
// after url.Parse percent-decodes the identifier, no decoded path
// segment may contain a backslash — in the token form, the full-URL
// form, uppercase or lowercase hex, or mixed encoded separators — so an
// encoded separator cannot smuggle traversal past the dot-dot scan.
func TestSlackHookURLRejectsDecodedBackslash(t *testing.T) {
	invalid := []string{
		// token form, encoded backslash (both hex cases)
		"T00%5CB00",
		"T00%5cB00",
		"%5C",
		// mixed encoded separators and traversals
		"%2e%5C..",
		"T00/%2e%5C../B00",
		"T00%2e%5C%2e%2e/B00",
		// full-URL form with an encoded backslash in the path
		"https://hooks.slack.com/services/T00%5CB00",
		"https://hooks.slack.com:443/services/T00%5cB00/XX",
	}
	for _, identifier := range invalid {
		got, secrets, err := hookURL(identifier)
		if !errors.Is(err, errSlackInvalidHook) || got != "" || secrets != nil {
			t.Fatalf("hookURL(%q) = %q err=%v, want decoded-backslash rejection", identifier, got, err)
		}
		if strings.Contains(err.Error(), identifier) {
			t.Fatalf("hookURL(%q) error carries the credential path: %v", identifier, err)
		}
	}

	// The plaintext-equivalent forms are rejected identically, and a
	// clean token containing no separator lookalike still resolves.
	if got, _, err := hookURL("T00/B00/ok"); err != nil ||
		got != "https://hooks.slack.com/services/T00/B00/ok" {
		t.Fatalf("clean token rejected: %q err=%v", got, err)
	}
}

// ---------------------------------------------------------------------------
// config resolution (_get_api_key / _get_hook_id)

func TestSlackConfigResolution(t *testing.T) {
	reg, rt := slackRT(t)

	// Without a delegate: an explicit key wins; a missing key fails with
	// the pinned text and zero transport dispatch.
	transport := &fakeTransport{responses: []fakeResult{{status: 204}}}
	withFakeTransport(t, transport)
	_, err := reg.Call(context.Background(), rt, "slack.list_rooms", &ListRoomsArgs{APIKey: keyPtr("explicit")})
	if err != nil {
		t.Fatalf("explicit key: %v", err)
	}

	transport = &fakeTransport{}
	withFakeTransport(t, transport)
	_, err = reg.Call(context.Background(), rt, "slack.list_rooms", &ListRoomsArgs{})
	if !errors.Is(err, errSlackNoAPIKey) || err.Error() != "No Slack API key found." {
		t.Fatalf("missing key err = %v", err)
	}
	if len(transport.requests) != 0 {
		t.Fatalf("missing key dispatched %d exchanges", len(transport.requests))
	}

	// The pinned falsy-empty-string head also resolves through config.
	_, err = reg.Call(context.Background(), rt, "slack.list_rooms", &ListRoomsArgs{APIKey: keyPtr("")})
	if !errors.Is(err, errSlackNoAPIKey) {
		t.Fatalf("empty key err = %v", err)
	}

	// The delegate ladder: first spelling wins over the second.
	if err := rt.Exec.Register(slackCfgStub{vals: map[string]any{
		"slack.api_key": "first",
		"slack:api_key": "second",
	}}); err != nil {
		t.Fatal(err)
	}
	transport = &fakeTransport{responses: []fakeResult{{status: 204}}}
	withFakeTransport(t, transport)
	_, err = reg.Call(context.Background(), rt, "slack.list_rooms", &ListRoomsArgs{})
	if err != nil {
		t.Fatalf("delegate key: %v", err)
	}
	if transport.requests[0].authorization != "Bearer first" {
		t.Fatalf("delegate key = %q", transport.requests[0].authorization)
	}

	// Only the colon spelling present: the second lookup hits.
	colonReg := runtime.NewExecRegistry()
	if err := Register(colonReg); err != nil {
		t.Fatal(err)
	}
	colonRT := &runtime.Runtime{Exec: colonReg}
	if err := colonReg.Register(slackCfgStub{vals: map[string]any{
		"slack:api_key": "colon",
	}}); err != nil {
		t.Fatal(err)
	}
	transport = &fakeTransport{responses: []fakeResult{{status: 204}}}
	withFakeTransport(t, transport)
	_, err = colonReg.Call(context.Background(), colonRT, "slack.list_rooms", &ListRoomsArgs{})
	if err != nil {
		t.Fatalf("colon key: %v", err)
	}
	if transport.requests[0].authorization != "Bearer colon" {
		t.Fatalf("colon key = %q", transport.requests[0].authorization)
	}

	// The hook ladder with its pinned text and zero dispatch on failure.
	transport = &fakeTransport{}
	withFakeTransport(t, transport)
	_, err = reg.Call(context.Background(), rt, "slack.call_hook", &CallHookArgs{Message: "m"})
	if !errors.Is(err, errSlackNoHook) || err.Error() != "No Slack WebHook url found" {
		t.Fatalf("missing hook err = %v", err)
	}
	if len(transport.requests) != 0 {
		t.Fatalf("missing hook dispatched %d exchanges", len(transport.requests))
	}

	hookReg := runtime.NewExecRegistry()
	if err := Register(hookReg); err != nil {
		t.Fatal(err)
	}
	hookRT := &runtime.Runtime{Exec: hookReg}
	if err := hookReg.Register(slackCfgStub{vals: map[string]any{
		"slack:hook": "T00/B00/configured",
	}}); err != nil {
		t.Fatal(err)
	}
	transport = &fakeTransport{responses: []fakeResult{{status: 200, body: "ok"}}}
	withFakeTransport(t, transport)
	value, err := hookReg.Call(context.Background(), hookRT, "slack.call_hook", &CallHookArgs{Message: "m"})
	if err != nil || value != true {
		t.Fatalf("config hook value = %#v err = %v", value, err)
	}
	if transport.requests[0].url != "https://hooks.slack.com/services/T00/B00/configured" {
		t.Fatalf("config hook url = %q", transport.requests[0].url)
	}
}

// ---------------------------------------------------------------------------
// redaction inventory

func TestSlackRedactionInventory(t *testing.T) {
	reg, rt := slackRT(t)

	// Server data echoing the token is redacted before returning.
	transport := &fakeTransport{responses: []fakeResult{
		{status: 200, body: `{"ok": false, "error": "token xoxp-secret revoked"}`},
	}}
	withFakeTransport(t, transport)
	value, err := reg.Call(context.Background(), rt, "slack.list_rooms", &ListRoomsArgs{APIKey: keyPtr("xoxp-secret")})
	if err != nil {
		t.Fatalf("list_rooms: %v", err)
	}
	rendered, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rendered), "xoxp-secret") {
		t.Fatalf("token in result: %s", rendered)
	}
	if !strings.Contains(string(rendered), redactedMarker) {
		t.Fatalf("redaction marker missing: %s", rendered)
	}

	// Nested room values are redacted too.
	transport = &fakeTransport{responses: []fakeResult{
		{status: 200, body: `{"channels": [{"id": "xoxp-secret", "name": "general"}]}`},
	}}
	withFakeTransport(t, transport)
	value, err = reg.Call(context.Background(), rt, "slack.find_room", &FindRoomArgs{Name: "general", APIKey: keyPtr("xoxp-secret")})
	if err != nil {
		t.Fatalf("find_room: %v", err)
	}
	rendered, _ = json.Marshal(value)
	if strings.Contains(string(rendered), "xoxp-secret") {
		t.Fatalf("token in room map: %s", rendered)
	}

	// call_hook failure bodies are redacted against the identifier.
	transport = &fakeTransport{responses: []fakeResult{
		{status: 500, body: "hook T00/B00/XX invalid"},
	}}
	withFakeTransport(t, transport)
	value, err = reg.Call(context.Background(), rt, "slack.call_hook", &CallHookArgs{
		Message: "m", Identifier: keyPtr("T00/B00/XX"),
	})
	if err != nil {
		t.Fatalf("call_hook: %v", err)
	}
	rendered, _ = json.Marshal(value)
	if strings.Contains(string(rendered), "T00/B00/XX") {
		t.Fatalf("identifier in failure body: %s", rendered)
	}

	// Ordinary keys keep their exact inventory; only secret-bearing
	// values are replaced (the key side is covered below).
	transport = &fakeTransport{responses: []fakeResult{
		{status: 200, body: `{"channels": [{"name": "xoxp-secret"}]}`},
	}}
	withFakeTransport(t, transport)
	value, err = reg.Call(context.Background(), rt, "slack.list_rooms", &ListRoomsArgs{APIKey: keyPtr("xoxp-secret")})
	if err != nil {
		t.Fatalf("list_rooms keys: %v", err)
	}
	result := value.(map[string]any)
	rooms := result["message"].([]any)
	if _, ok := rooms[0].(map[string]any)["name"]; !ok {
		t.Fatalf("name key dropped by redaction: %#v", rooms[0])
	}
	if rooms[0].(map[string]any)["name"] != redactedMarker {
		t.Fatalf("name value not redacted: %#v", rooms[0])
	}
}

// TestSlackKeyRedaction pins the key-aware redaction guarantee
// (R10.1 F2/SEC-003): object keys containing the credential in raw,
// percent-encoded, or JSON-escaped normalized form are redacted in
// nested objects and arrays, ordinary keys are untouched, and a
// rename collision fails closed with the value-free sentinel instead of
// overwriting a key. The api key "xoxp</red>" yields distinct
// normalized variants (raw, query/path-escaped, Go JSON-escaped, and
// the defensive slash-escaped JSON form; the Python json.dumps form
// collapses into raw for printable-ASCII secrets and is covered
// separately by TestSlackPythonEscapedRedaction).
func TestSlackKeyRedaction(t *testing.T) {
	reg, rt := slackRT(t)
	apiKey := "xoxp</red>"

	// Credential-bearing KEYS in every normalized form, nested in
	// objects and arrays: all redacted, ordinary inventory kept.
	for name, body := range map[string]string{
		"raw-key":             `{"ok": true, "channels": [{"note xoxp</red> here": "kept", "name": "general"}]}`,
		"percent-key":         `{"ok": true, "channels": [{"echo=xoxp%3C%2Fred%3E": "kept", "name": "general"}]}`,
		"go-json-escaped-key": `{"ok": true, "channels": [{"xoxp\\u003c/red\\u003e": "kept", "name": "general"}]}`,
		"slash-escaped-key":   `{"ok": true, "channels": [{"xoxp<\\/red>": "kept", "name": "general"}]}`,
	} {
		transport := &fakeTransport{responses: []fakeResult{{status: 200, body: body}}}
		withFakeTransport(t, transport)
		value, err := reg.Call(context.Background(), rt, "slack.list_rooms", &ListRoomsArgs{APIKey: keyPtr(apiKey)})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rendered, _ := json.Marshal(value)
		for _, leak := range []string{apiKey, "xoxp%3C", "xoxp\\u003c", `xoxp<\/`} {
			if strings.Contains(string(rendered), leak) {
				t.Fatalf("%s: credential form %q leaked: %s", name, leak, rendered)
			}
		}
		if !strings.Contains(string(rendered), redactedMarker) {
			t.Fatalf("%s: marker missing: %s", name, rendered)
		}
		// Ordinary keys survive and the value under the renamed key is
		// kept.
		if !strings.Contains(string(rendered), `"name":"general"`) ||
			!strings.Contains(string(rendered), `"kept"`) {
			t.Fatalf("%s: ordinary inventory damaged: %s", name, rendered)
		}
	}

	// A percent-encoded credential inside a VALUE is redacted too.
	transport := &fakeTransport{responses: []fakeResult{
		{status: 200, body: `{"ok": true, "channels": [{"name": "echo xoxp%3C%2Fred%3E seen"}]}`},
	}}
	withFakeTransport(t, transport)
	value, err := reg.Call(context.Background(), rt, "slack.list_rooms", &ListRoomsArgs{APIKey: keyPtr(apiKey)})
	if err != nil {
		t.Fatalf("percent-value: %v", err)
	}
	rendered, _ := json.Marshal(value)
	if strings.Contains(string(rendered), "xoxp%3C") {
		t.Fatalf("percent-value leaked: %s", rendered)
	}
	if !strings.Contains(string(rendered), `"name":"echo `+redactedMarker+` seen"`) {
		t.Fatalf("percent-value not marker-replaced: %s", rendered)
	}

	// A key renaming onto an existing key, or two distinct keys
	// collapsing onto one redacted target, fails closed value-free.
	for name, body := range map[string]string{
		"existing-placeholder-key": `{"ok": true, "channels": [], "xoxp</red>": 1, "***REDACTED***": 2}`,
		"two-keys-collapse":        `{"ok": true, "channels": [], "xoxp</red>": 1, "xoxp%3C%2Fred%3E": 2}`,
	} {
		transport := &fakeTransport{responses: []fakeResult{{status: 200, body: body}}}
		withFakeTransport(t, transport)
		value, err := reg.Call(context.Background(), rt, "slack.list_rooms", &ListRoomsArgs{APIKey: keyPtr(apiKey)})
		if !errors.Is(err, errSlackRedactionCollision) {
			t.Fatalf("%s: err = %v, want errSlackRedactionCollision", name, err)
		}
		if value != nil {
			t.Fatalf("%s: value = %#v, want nil", name, value)
		}
		if strings.Contains(err.Error(), apiKey) {
			t.Fatalf("%s: collision error carries the credential: %v", name, err)
		}
	}
}

// TestSlackPythonJSONEscaped pins the Python json.dumps default
// (ensure_ascii=True) string rendering used by secretVariants: backslash
// and double-quote escapes, the five short control escapes, \uXXXX for
// every other control character and for DEL, lowercase \uXXXX for
// non-ASCII with astral runes as surrogate pairs — and NO forward-slash
// escaping (CPython's ESCAPE_ASCII set `([\\"]|[^\ -~])`).
func TestSlackPythonJSONEscaped(t *testing.T) {
	for value, want := range map[string]string{
		"plain":        "plain",
		`a\b`:          `a\\b`,
		`a"b`:          `a\"b`,
		"a/b":          "a/b",
		"a\x00b":       `a\u0000b`,
		"a\x01b":       `a\u0001b`,
		"a\x08b":       `a\bb`,
		"a\x09b":       `a\tb`,
		"a\nb":         `a\nb`,
		"a\x0cb":       `a\fb`,
		"a\rb":         `a\rb`,
		"a\x1fb":       `a\u001fb`,
		"a\x7fb":       `a\u007fb`,
		"aéb":          `a\u00e9b`,
		"aключb":       `a\u043a\u043b\u044e\u0447b`,
		"a\U0001F600b": `a\ud83d\ude00b`,
	} {
		if got := pythonJSONEscaped(value); got != want {
			t.Fatalf("pythonJSONEscaped(%q) = %q, want %q", value, got, want)
		}
	}
}

// TestSlackPythonEscapedRedaction pins the SEC-003 Python json.dumps
// claim end to end: a credential containing control characters, DEL, or
// non-ASCII runes, echoed by the server in \uXXXX (or short \b \t \n \f
// \r) escaped text — in object KEYS and in VALUES — is redacted, with
// ordinary inventory kept and the marker present.
func TestSlackPythonEscapedRedaction(t *testing.T) {
	reg, rt := slackRT(t)
	// literalJSON embeds escaped credential text into a JSON body so the
	// DECODED string carries the backslash escapes literally.
	literalJSON := func(s string) string {
		return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
	}
	for name, apiKey := range map[string]string{
		"control-char": "xoxp-a\x01ctl",
		"short-escape": "xoxp-b\nkey",
		"del":          "xoxp-c\x7fkey",
		"non-ascii":    "xoxp-ключ",
		"astral":       "xoxp-\U0001F600key",
	} {
		escaped := pythonJSONEscaped(apiKey)
		if escaped == apiKey {
			t.Fatalf("%s: secret produced no python escapes", name)
		}
		for surface, body := range map[string]string{
			// KEY echo: the decoded object key is the escaped text.
			"key": `{"ok": true, "channels": [{"` + literalJSON(escaped) + `": "kept", "name": "general"}]}`,
			// VALUE echo: the decoded error value is the escaped text.
			"value": `{"ok": false, "error": "bad ` + literalJSON(escaped) + ` token"}`,
		} {
			transport := &fakeTransport{responses: []fakeResult{{status: 200, body: body}}}
			withFakeTransport(t, transport)
			value, err := reg.Call(context.Background(), rt, "slack.list_rooms", &ListRoomsArgs{APIKey: keyPtr(apiKey)})
			if err != nil {
				t.Fatalf("%s %s: %v", name, surface, err)
			}
			rendered, _ := json.Marshal(value)
			for _, leak := range []string{apiKey, escaped} {
				if strings.Contains(string(rendered), leak) {
					t.Fatalf("%s %s leaked credential form %q: %s", name, surface, leak, rendered)
				}
			}
			if !strings.Contains(string(rendered), redactedMarker) {
				t.Fatalf("%s %s missing marker: %s", name, surface, rendered)
			}
			if surface == "key" &&
				(!strings.Contains(string(rendered), `"name":"general"`) ||
					!strings.Contains(string(rendered), `"kept"`)) {
				t.Fatalf("%s key surface damaged ordinary inventory: %s", name, rendered)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// registry surface

func TestSlackRegistrySurface(t *testing.T) {
	reg, rt := slackRT(t)
	wantNames := []string{
		"slack.call_hook",
		"slack.find_room",
		"slack.find_user",
		"slack.list_rooms",
		"slack.list_users",
		"slack.post_message",
	}
	names := reg.Names()
	if len(names) != len(wantNames) {
		t.Fatalf("registered names = %#v", names)
	}
	for index, name := range wantNames {
		if names[index] != name {
			t.Fatalf("name[%d] = %q, want %q", index, names[index], name)
		}
	}

	prototypes := map[string]any{
		"slack.list_rooms":   ListRoomsArgs{},
		"slack.list_users":   ListUsersArgs{},
		"slack.find_room":    FindRoomArgs{},
		"slack.find_user":    FindUserArgs{},
		"slack.post_message": PostMessageArgs{},
		"slack.call_hook":    CallHookArgs{},
	}
	for name, prototype := range prototypes {
		fn, ok := rt.Exec.Get(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if reflect.TypeOf(fn.Args()) != reflect.TypeOf(prototype) {
			t.Fatalf("%s prototype = %T", name, fn.Args())
		}
	}
}
