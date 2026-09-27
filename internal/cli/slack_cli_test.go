package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
	execslack "github.com/friz-zy/statekit/modules/exec/slack"
)

// slackCLIRequest captures one dispatched slack exchange.
type slackCLIRequest struct {
	method        string
	url           string
	authorization string
	contentType   string
	body          string
}

// slackCLITransport is the fake HTTP boundary injected through the slack
// package's testing-scoped transport seam (SetTestHTTPClient): no DNS,
// no network.
type slackCLITransport struct {
	requests  []slackCLIRequest
	responses []slackCLIResponse
}

type slackCLIResponse struct {
	status int
	body   string
}

func (f *slackCLITransport) Do(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	f.requests = append(f.requests, slackCLIRequest{
		method:        req.Method,
		url:           req.URL.String(),
		authorization: req.Header.Get("Authorization"),
		contentType:   req.Header.Get("Content-Type"),
		body:          string(body),
	})
	if len(f.responses) == 0 {
		return nil, errFakeSlackTransport
	}
	result := f.responses[0]
	f.responses = f.responses[1:]
	return &http.Response{
		StatusCode: result.status,
		Body:       io.NopCloser(strings.NewReader(result.body)),
		Header:     make(http.Header),
	}, nil
}

var errFakeSlackTransport = errors.New("fake slack transport exhausted")

// slackCLIApp builds a CLI app whose runtime registers only the slack
// module plus the injected fake transport.
func slackCLIApp(t *testing.T, transport *slackCLITransport) *App {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts:  facts.ForTesting(facts.Overrides{}),
		FS:     runtime.NewMemoryFS(),
	}
	if err := execslack.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	execslack.SetTestHTTPClient(t, transport)
	return NewApp("test-version", func() (*runtime.Runtime, error) { return rt, nil })
}

// TestSlackCLIListRooms drives slack.list_rooms end to end: the explicit
// api key travels only in the Authorization header, and the pinned
// {message, res} JSON shape reaches stdout.
func TestSlackCLIListRooms(t *testing.T) {
	transport := &slackCLITransport{responses: []slackCLIResponse{
		{status: 200, body: `{"ok": true, "channels": [{"id": "C1", "name": "general"}]}`},
	}}
	app := slackCLIApp(t, transport)

	code, out, errS := captureCode(t, app, "exec", "slack.list_rooms", "--api-key", "xoxp-cli-key", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("list_rooms code=%d out=%q err=%q", code, out, errS)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("list_rooms json: %v (%q)", err, out)
	}
	if result["res"] != true {
		t.Fatalf("list_rooms result = %#v", result)
	}
	rooms, ok := result["message"].([]any)
	if !ok || len(rooms) != 1 {
		t.Fatalf("list_rooms message = %#v", result["message"])
	}
	if len(transport.requests) != 1 {
		t.Fatalf("list_rooms dispatches = %d", len(transport.requests))
	}
	req := transport.requests[0]
	if req.method != http.MethodGet || req.url != "https://slack.com/api/conversations.list" ||
		req.authorization != "Bearer xoxp-cli-key" {
		t.Fatalf("list_rooms request = %#v", req)
	}
	if strings.Contains(out, "xoxp-cli-key") || strings.Contains(errS, "xoxp-cli-key") {
		t.Fatalf("api key in CLI output: %q %q", out, errS)
	}
}

// TestSlackCLIMissingKey keeps the pinned SaltInvocationError surface:
// without a config delegate the missing api key fails with the pinned
// text and no transport dispatch.
func TestSlackCLIMissingKey(t *testing.T) {
	transport := &slackCLITransport{}
	app := slackCLIApp(t, transport)

	code, out, errS := captureCode(t, app, "exec", "slack.list_rooms", "-o", "json")
	if code != ExitFailed {
		t.Fatalf("missing key code=%d, want ExitFailed", code)
	}
	if !strings.Contains(errS, "No Slack API key found.") {
		t.Fatalf("missing key stderr = %q", errS)
	}
	if out != "" || len(transport.requests) != 0 {
		t.Fatalf("missing key out=%q dispatches=%d", out, len(transport.requests))
	}

	code, _, errS = captureCode(t, app, "exec", "slack.call_hook", "--message", "hi", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "No Slack WebHook url found") {
		t.Fatalf("missing hook code=%d err=%q", code, errS)
	}
}

// TestSlackCLICallHook drives the webhook success and failure shapes,
// including redaction of the hook identifier — raw and normalized
// (percent-encoded) forms — in the CLI-visible failure body.
func TestSlackCLICallHook(t *testing.T) {
	transport := &slackCLITransport{responses: []slackCLIResponse{
		{status: 200, body: "ok"},
		{status: 500, body: "hook T00/B00/cli invalid"},
		{status: 500, body: "hook T00%2FB00%2Fcli invalid"},
	}}
	app := slackCLIApp(t, transport)

	code, out, errS := captureCode(t, app, "exec", "slack.call_hook",
		"--message", "build done", "--identifier", "T00/B00/cli", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" {
		t.Fatalf("call_hook code=%d out=%q err=%q", code, out, errS)
	}
	req := transport.requests[0]
	if req.method != http.MethodPost || req.url != "https://hooks.slack.com/services/T00/B00/cli" {
		t.Fatalf("call_hook request = %#v", req)
	}
	if !strings.HasPrefix(req.body, "payload=") {
		t.Fatalf("call_hook body = %q", req.body)
	}

	code, out, errS = captureCode(t, app, "exec", "slack.call_hook",
		"--message", "build done", "--identifier", "T00/B00/cli", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("call_hook failure code=%d out=%q err=%q", code, out, errS)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("call_hook failure json: %v (%q)", err, out)
	}
	if result["res"] != false || result["message"] != "hook ***REDACTED*** invalid" {
		t.Fatalf("call_hook failure result = %#v", result)
	}
	if strings.Contains(out, "T00/B00/cli") || strings.Contains(errS, "T00/B00/cli") {
		t.Fatalf("identifier in CLI output: %q %q", out, errS)
	}

	// A percent-encoded echo of the identifier is redacted identically.
	code, out, errS = captureCode(t, app, "exec", "slack.call_hook",
		"--message", "build done", "--identifier", "T00/B00/cli", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("call_hook normalized failure code=%d out=%q err=%q", code, out, errS)
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("call_hook normalized failure json: %v (%q)", err, out)
	}
	if result["res"] != false || result["message"] != "hook ***REDACTED*** invalid" {
		t.Fatalf("call_hook normalized failure result = %#v", result)
	}
	if strings.Contains(out, "T00") || strings.Contains(errS, "T00") {
		t.Fatalf("normalized identifier echo in CLI output: %q %q", out, errS)
	}
}

// TestSlackCLICallHookForeignOriginRejection keeps the fixed-origin
// identifier boundary visible at the CLI: an absolute foreign/loopback
// identifier fails value-free with zero transport dispatch.
func TestSlackCLICallHookForeignOriginRejection(t *testing.T) {
	transport := &slackCLITransport{}
	app := slackCLIApp(t, transport)

	code, out, errS := captureCode(t, app, "exec", "slack.call_hook",
		"--message", "m", "--identifier", "http://127.0.0.1:9/hook", "-o", "json")
	if code != ExitFailed {
		t.Fatalf("foreign-origin code=%d, want ExitFailed", code)
	}
	if !strings.Contains(errS, "slack: invalid hook identifier") {
		t.Fatalf("foreign-origin stderr = %q", errS)
	}
	if strings.Contains(errS, "127.0.0.1") || out != "" || len(transport.requests) != 0 {
		t.Fatalf("foreign-origin leaked destination or dispatched: out=%q err=%q dispatches=%d",
			out, errS, len(transport.requests))
	}
}

// TestSlackCLIPostMessageStructuredInput drives post_message through the
// structured --config channel with attachments, asserting the urlencoded
// transport body and the true result.
func TestSlackCLIPostMessageStructuredInput(t *testing.T) {
	transport := &slackCLITransport{responses: []slackCLIResponse{
		{status: 200, body: `{"ok": true, "channel": "C1"}`},
	}}
	app := slackCLIApp(t, transport)

	code, out, errS := captureCode(t, app, "exec", "slack.post_message", "-o", "json",
		"--config", `{"channel": "fake_channel", "message": "test message", "from_name": "salt server", "api_key": "xxx-xx-xxx"}`)
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" {
		t.Fatalf("post_message code=%d out=%q err=%q", code, out, errS)
	}
	req := transport.requests[0]
	if req.method != http.MethodPost || req.url != "https://slack.com/api/chat.postMessage" ||
		req.authorization != "Bearer xxx-xx-xxx" ||
		req.contentType != "application/x-www-form-urlencoded" {
		t.Fatalf("post_message request = %#v", req)
	}
	wantBody := "channel=%23fake_channel&username=salt+server&text=test+message&attachments=%5B%5D&blocks=%5B%5D"
	if req.body != wantBody {
		t.Fatalf("post_message body = %q, want %q", req.body, wantBody)
	}
}

// TestSlackCLIRedactedServerEcho injects a server response that echoes
// the api key and asserts it never reaches CLI stdout or stderr.
func TestSlackCLIRedactedServerEcho(t *testing.T) {
	transport := &slackCLITransport{responses: []slackCLIResponse{
		{status: 200, body: `{"ok": false, "error": "bad xoxp-cli-secret token"}`},
	}}
	app := slackCLIApp(t, transport)

	code, out, errS := captureCode(t, app, "exec", "slack.list_rooms",
		"--api-key", "xoxp-cli-secret", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("echo code=%d out=%q err=%q", code, out, errS)
	}
	if strings.Contains(out, "xoxp-cli-secret") || strings.Contains(errS, "xoxp-cli-secret") {
		t.Fatalf("api key echoed into CLI output: %q %q", out, errS)
	}
	if !strings.Contains(out, "***REDACTED***") {
		t.Fatalf("redaction marker missing: %q", out)
	}
}

// TestSlackCLIMissingRequiredArgument keeps required-argument validation
// at the invalid-input exit code.
func TestSlackCLIMissingRequiredArgument(t *testing.T) {
	transport := &slackCLITransport{}
	app := slackCLIApp(t, transport)

	code, _, errS := captureCode(t, app, "exec", "slack.find_room", "--api-key", "k", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "name") {
		t.Fatalf("missing name code=%d err=%q", code, errS)
	}
	code, _, errS = captureCode(t, app, "exec", "slack.post_message", "--message", "m", "-o", "json")
	if code != ExitInvalidInput {
		t.Fatalf("missing channel code=%d err=%q", code, errS)
	}
	if len(transport.requests) != 0 {
		t.Fatalf("invalid input dispatched %d exchanges", len(transport.requests))
	}
}

// TestSlackCLICallHookCanonicalRedaction keeps the SEC-003 residual at
// the CLI surface: failure bodies echoing the credential through its
// canonical forms — the decoded path token of a percent-encoded
// identifier and the normalized default-port-removed URL — are redacted
// before reaching stdout.
func TestSlackCLICallHookCanonicalRedaction(t *testing.T) {
	transport := &slackCLITransport{responses: []slackCLIResponse{
		{status: 500, body: "hook T00/B00/can invalid"},
		{status: 500, body: "hook https://hooks.slack.com/services/T00/B00/can invalid"},
	}}
	app := slackCLIApp(t, transport)

	// A percent-encoded identifier dispatches the decoded canonical URL;
	// the failure body echoing the decoded token is redacted.
	code, out, errS := captureCode(t, app, "exec", "slack.call_hook",
		"--message", "m", "--identifier", "T00%2FB00%2Fcan", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("encoded-identifier code=%d out=%q err=%q", code, out, errS)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("encoded-identifier json: %v (%q)", err, out)
	}
	if result["res"] != false || result["message"] != "hook ***REDACTED*** invalid" {
		t.Fatalf("encoded-identifier result = %#v", result)
	}
	if strings.Contains(out, "T00") || strings.Contains(errS, "T00") {
		t.Fatalf("decoded echo leaked: out=%q err=%q", out, errS)
	}
	if req := transport.requests[0]; req.url != "https://hooks.slack.com/services/T00/B00/can" {
		t.Fatalf("encoded-identifier dispatch url = %q", req.url)
	}

	// A default-port full-URL identifier: the normalized (port-removed)
	// echo is redacted identically — no credential bytes (token,
	// :443 form) survive, only the fixed origin prefix may remain.
	code, out, errS = captureCode(t, app, "exec", "slack.call_hook",
		"--message", "m", "--identifier", "https://hooks.slack.com:443/services/T00/B00/can", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("default-port code=%d out=%q err=%q", code, out, errS)
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("default-port json: %v (%q)", err, out)
	}
	if result["res"] != false || !strings.Contains(fmt.Sprint(result["message"]), "***REDACTED***") {
		t.Fatalf("default-port result = %#v", result)
	}
	for _, leak := range []string{"T00", "B00/can", ":443"} {
		if strings.Contains(out, leak) || strings.Contains(errS, leak) {
			t.Fatalf("normalized echo leaked %q: out=%q err=%q", leak, out, errS)
		}
	}
}

// TestSlackCLICallHookEncodedBackslashRejection keeps the SEC-001
// residual at the CLI boundary: an identifier whose DECODED path
// carries a backslash — a percent-encoded separator, in the token or
// full-URL form — is rejected value-free with exactly empty stdout and
// zero transport dispatch.
func TestSlackCLICallHookEncodedBackslashRejection(t *testing.T) {
	transport := &slackCLITransport{}
	app := slackCLIApp(t, transport)
	for _, identifier := range []string{
		"T00%5CB00/cli",
		"https://hooks.slack.com:443/services/T00%5cB00/cli",
		// Mixed encoding: literal separators around a decoded dot and
		// backslash (%2e%5C) — the decoded path .\.. must be rejected
		// exactly like the fully-encoded form.
		"T00/%2e%5C../B00",
	} {
		code, out, errS := captureCode(t, app, "exec", "slack.call_hook",
			"--message", "m", "--identifier", identifier, "-o", "json")
		if code != ExitFailed || !strings.Contains(errS, "slack: invalid hook identifier") {
			t.Fatalf("identifier %q code=%d err=%q, want value-free rejection", identifier, code, errS)
		}
		// Rejection happens before any dispatch or stdout write:
		// stdout is asserted exactly empty, not merely token-absent.
		if out != "" {
			t.Fatalf("identifier %q stdout = %q, want exactly empty", identifier, out)
		}
		if strings.Contains(out, "B00") || strings.Contains(errS, "B00") ||
			strings.Contains(errS, "%5C") || strings.Contains(errS, "%5c") {
			t.Fatalf("identifier %q leaked credential bytes: out=%q err=%q", identifier, out, errS)
		}
		if len(transport.requests) != 0 {
			t.Fatalf("identifier %q dispatched %d exchanges", identifier, len(transport.requests))
		}
	}
}

// TestSlackCLIInputErrorDisclosure pins SEC-006 at the CLI boundary:
// slack parse, positional, output-format, and unknown-key diagnostics
// are value-free — a synthetic secret supplied as a malformed flag
// value, as a short (spaced) boolean value, as an unexpected
// positional, as an invalid output-format value (on either side of the
// target token), or as an unknown structured key never reaches stdout
// or stderr (stdout asserted exactly empty), the fixed diagnostic
// category is reported, and zero transport dispatch happens.
func TestSlackCLIInputErrorDisclosure(t *testing.T) {
	secret := "xoxp-cli-malformed"
	vectors := []struct {
		name     string
		argv     []string
		wantText string
	}{
		{"malformed flag value", []string{"exec", "slack.call_hook", "--message", "m", "--short=" + secret, "-o", "json"}, "invalid command-line arguments"},
		{"spaced boolean value", []string{"exec", "slack.call_hook", "--message", "m", "--short", secret, "-o", "json"}, "invalid command-line arguments"},
		{"unexpected positional", []string{"exec", "slack.list_rooms", secret, "-o", "json"}, "unexpected positional argument"},
		{"invalid output format", []string{"exec", "slack.call_hook", "--message", "m", "-o", secret}, "invalid output format"},
		{"invalid output format before target", []string{"exec", "-o", secret, "slack.call_hook", "--message", "m"}, "invalid output format"},
		{"unknown structured key", []string{"exec", "slack.post_message", "--config", `{"channel": "c", "message": "m", "` + secret + `": "v"}`, "-o", "json"}, "unknown argument"},
	}
	for _, v := range vectors {
		transport := &slackCLITransport{}
		app := slackCLIApp(t, transport)
		code, out, errS := captureCode(t, app, v.argv...)
		if code != ExitInvalidInput {
			t.Fatalf("%s code=%d, want ExitInvalidInput (err=%q)", v.name, code, errS)
		}
		if !strings.Contains(errS, v.wantText) {
			t.Fatalf("%s diagnostic = %q, want fixed category %q", v.name, errS, v.wantText)
		}
		// Pre-dispatch failure paths write only to stderr: stdout is
		// asserted exactly empty, not merely secret-absent.
		if out != "" {
			t.Fatalf("%s stdout = %q, want exactly empty", v.name, out)
		}
		if strings.Contains(out, secret) || strings.Contains(errS, secret) {
			t.Fatalf("%s leaked secret bytes: out=%q err=%q", v.name, out, errS)
		}
		if len(transport.requests) != 0 {
			t.Fatalf("%s dispatched %d exchanges", v.name, len(transport.requests))
		}
	}
}

// TestSlackCLITransportError keeps transport failures value-free at the
// CLI boundary.
func TestSlackCLITransportError(t *testing.T) {
	transport := &slackCLITransport{}
	app := slackCLIApp(t, transport)

	code, out, errS := captureCode(t, app, "exec", "slack.list_rooms", "--api-key", "xoxp-cli-secret", "-o", "json")
	if code != ExitFailed {
		t.Fatalf("transport error code=%d, want ExitFailed", code)
	}
	if !strings.Contains(errS, "slack:") {
		t.Fatalf("transport error stderr = %q", errS)
	}
	if strings.Contains(errS, "xoxp-cli-secret") || strings.Contains(out, "xoxp-cli-secret") ||
		strings.Contains(errS, "http") {
		t.Fatalf("transport error not value-free: out=%q err=%q", out, errS)
	}
}
