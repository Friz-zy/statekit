package cloudmeta

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// canaryMarker is the single leak marker planted in scripted statuses,
// bodies, headers, and URL texts; it must never appear in any error
// string or Result JSON.
const canaryMarker = "CANARY_LEAK_MARKER"

// recordedRequest is one observed request tuple.
type recordedRequest struct {
	method string
	path   string
	query  string
	header http.Header
}

// cannedResponse is one scripted response. statusText and header values
// may carry canary markers that must never leak.
type cannedResponse struct {
	status       int
	statusText   string
	body         string
	header       map[string]string
	roundTripErr error
}

// recordingTransport is the fake http.RoundTripper used by every test: it
// records each request tuple in order, trips on forbidden paths, and
// answers from the scripted queue. No socket is ever opened.
type recordingTransport struct {
	responses []cannedResponse
	calls     []recordedRequest
	violation string
	forbidden map[string]bool
}

var errUnexpectedRequest = errors.New("fake transport: unexpected extra request")

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.forbidden != nil && t.forbidden[req.URL.Path] {
		if t.violation == "" {
			t.violation = req.URL.Path
		}
	}
	header := req.Header.Clone()
	if header == nil {
		header = http.Header{}
	}
	t.calls = append(t.calls, recordedRequest{
		method: req.Method,
		path:   req.URL.Path,
		query:  req.URL.RawQuery,
		header: header,
	})
	if len(t.responses) == 0 {
		return nil, errUnexpectedRequest
	}
	canned := t.responses[0]
	t.responses = t.responses[1:]
	if canned.roundTripErr != nil {
		return nil, canned.roundTripErr
	}
	respHeader := http.Header{}
	for name, value := range canned.header {
		respHeader.Set(name, value)
	}
	statusText := canned.statusText
	if statusText == "" {
		statusText = http.StatusText(canned.status)
	}
	return &http.Response{
		Status:     statusText,
		StatusCode: canned.status,
		Header:     respHeader,
		Body:       io.NopCloser(strings.NewReader(canned.body)),
		Request:    req,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}, nil
}

// dialCall is one observed dial attempt.
type dialCall struct {
	network string
	addr    string
}

// stubDial records dial attempts without opening a connection; tests
// assert it is never called with a non-literal address.
type stubDial struct {
	calls []dialCall
}

var errStubDial = errors.New("stub dial: no real connections in tests")

func (d *stubDial) dial(_ context.Context, network, addr string) (net.Conn, error) {
	d.calls = append(d.calls, dialCall{network: network, addr: addr})
	return nil, errStubDial
}

// runProvider dispatches one provider against a fake transport.
func runProvider(provider string, forbidden map[string]bool, responses ...cannedResponse) (*Result, error, *recordingTransport) {
	rt := &recordingTransport{
		responses: append([]cannedResponse(nil), responses...),
		forbidden: forbidden,
	}
	result, err := collectDispatch(context.Background(), Provider(provider), rt)
	return result, err, rt
}

// assertCall pins one exact request tuple. The expected headers are given
// in plain string form and canonicalized through http.Header.Set — the
// same canonicalization req.Header.Set applies — so the comparison never
// depends on hand-written canonical key spelling while still rejecting
// any extra or missing header.
func assertCall(t *testing.T, index int, got recordedRequest, method, path, query string, wantHeaders map[string]string) {
	t.Helper()
	if got.method != method || got.path != path || got.query != query {
		t.Fatalf("call[%d] = %s %s?%s, want %s %s?%s", index, got.method, got.path, got.query, method, path, query)
	}
	want := http.Header{}
	for name, value := range wantHeaders {
		want.Set(name, value)
	}
	if !reflect.DeepEqual(got.header, want) {
		t.Fatalf("call[%d] headers = %v, want %v", index, got.header, want)
	}
}

// fieldValue reads one result field by descriptor name.
func fieldValue(r *Result, field string) string {
	switch field {
	case fieldInstanceID:
		return r.InstanceID
	case fieldRegion:
		return r.Region
	case fieldZone:
		return r.Zone
	case fieldInstanceType:
		return r.InstanceType
	case fieldImageID:
		return r.ImageID
	}
	return ""
}

// providerFixture drives the shared failure matrix for one provider. The
// index fields address the scripted response sequence (the AWS token
// response first, then leaves in plan order).
type providerFixture struct {
	provider      string
	forbidden     map[string]bool
	happy         []cannedResponse
	requiredIdx   int
	requiredField string
	optionalIdx   int // -1 when the provider has no optional leaves
	optionalField string
}

func withMutation(responses []cannedResponse, index int, mutate func(*cannedResponse)) []cannedResponse {
	out := append([]cannedResponse(nil), responses...)
	mutate(&out[index])
	return out
}

// assertNoLeak sweeps an error and a result for the canary marker.
func assertNoLeak(t *testing.T, err error, result *Result) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), canaryMarker) {
		t.Fatalf("canary leaked into error: %q", err.Error())
	}
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatalf("marshal result: %v", marshalErr)
	}
	if strings.Contains(string(encoded), canaryMarker) {
		t.Fatalf("canary leaked into result JSON: %s", encoded)
	}
}

// runFailureMatrix exercises the shared failure semantics against one
// provider fixture: optional 404/empty omit the field with partial
// status; every other optional failure, every required-leaf failure, and
// every adversarial 200-status body discards the whole result; nothing
// retries. NOTE: the fake transport's call counts pin that THIS collector
// issues exactly one request per leaf — they do not by themselves prove
// the production transport never retries; that is pinned separately by
// DisableKeepAlives and the end-of-collection CloseIdleConnections in
// the transport-configuration test.
func runFailureMatrix(t *testing.T, fx providerFixture) {
	t.Helper()

	partial := func(t *testing.T, name string, mutate func(*cannedResponse)) {
		t.Helper()
		result, err, rt := runProvider(fx.provider, fx.forbidden, withMutation(fx.happy, fx.optionalIdx, mutate)...)
		if err != nil {
			t.Fatalf("%s: err=%v, want nil", name, err)
		}
		if result == nil || result.Status != statusPartial {
			t.Fatalf("%s: result=%+v, want partial", name, result)
		}
		if result.Verification != verificationUnverified {
			t.Fatalf("%s: verification=%q, want %q", name, result.Verification, verificationUnverified)
		}
		if got := fieldValue(result, fx.optionalField); got != "" {
			t.Fatalf("%s: omitted field has value %q", name, got)
		}
		if result.FieldsNotCollected[fx.optionalField] != reasonNotPresent {
			t.Fatalf("%s: fields_not_collected[%s]=%q, want %q", name, fx.optionalField, result.FieldsNotCollected[fx.optionalField], reasonNotPresent)
		}
		if len(rt.calls) != len(fx.happy) {
			t.Fatalf("%s: calls=%d, want %d (no retries)", name, len(rt.calls), len(fx.happy))
		}
		assertNoLeak(t, err, result)
	}

	discard := func(t *testing.T, name string, index int, mutate func(*cannedResponse), want error) {
		t.Helper()
		result, err, rt := runProvider(fx.provider, fx.forbidden, withMutation(fx.happy, index, mutate)...)
		if !errors.Is(err, want) {
			t.Fatalf("%s: err=%v, want %v", name, err, want)
		}
		if result != nil {
			t.Fatalf("%s: result=%+v, want nil (atomic discard)", name, result)
		}
		assertNoLeak(t, err, result)
		if len(rt.calls) != index+1 {
			t.Fatalf("%s: calls=%d, want %d (halt at failure, no retries)", name, len(rt.calls), index+1)
		}
	}

	if fx.optionalIdx >= 0 {
		t.Run("optional-404-omits", func(t *testing.T) {
			partial(t, "404", func(r *cannedResponse) { r.status = http.StatusNotFound })
		})
		t.Run("optional-empty-omits", func(t *testing.T) {
			partial(t, "empty", func(r *cannedResponse) { r.body = "" })
		})
		t.Run("optional-500-discards", func(t *testing.T) {
			discard(t, "500", fx.optionalIdx, func(r *cannedResponse) {
				r.status = http.StatusInternalServerError
				r.statusText = "500 " + canaryMarker
			}, ErrProtocol)
		})
		t.Run("optional-control-char-discards", func(t *testing.T) {
			discard(t, "control", fx.optionalIdx, func(r *cannedResponse) {
				r.body = "a\x01b\n"
			}, ErrMalformed)
		})
		t.Run("optional-invalid-utf8-discards", func(t *testing.T) {
			discard(t, "utf8", fx.optionalIdx, func(r *cannedResponse) {
				r.body = "\xff\xfe\n"
			}, ErrEncoding)
		})
		t.Run("optional-oversize-discards", func(t *testing.T) {
			discard(t, "oversize", fx.optionalIdx, func(r *cannedResponse) {
				r.body = strings.Repeat("a", maxLeafBodyBytes+1)
			}, ErrOversize)
		})
		t.Run("optional-same-origin-redirect-discards", func(t *testing.T) {
			discard(t, "redirect", fx.optionalIdx, func(r *cannedResponse) {
				r.status = http.StatusFound
				r.header = map[string]string{"Location": metadataBase + "/latest/api/token"}
			}, ErrRedirect)
		})
		t.Run("optional-content-encoding-discards", func(t *testing.T) {
			discard(t, "encoding", fx.optionalIdx, func(r *cannedResponse) {
				r.header = map[string]string{"Content-Encoding": "gzip", "X-Canary": canaryMarker}
			}, ErrProtocol)
		})
		t.Run("optional-deadline-discards", func(t *testing.T) {
			discard(t, "deadline", fx.optionalIdx, func(r *cannedResponse) {
				r.roundTripErr = &url.Error{
					Op:  "Get",
					URL: metadataBase + "/" + canaryMarker,
					Err: context.DeadlineExceeded,
				}
			}, ErrDeadline)
		})
	}

	t.Run("required-404-discards", func(t *testing.T) {
		discard(t, "404", fx.requiredIdx, func(r *cannedResponse) {
			r.status = http.StatusNotFound
		}, ErrProtocol)
	})
	t.Run("required-500-discards", func(t *testing.T) {
		discard(t, "500", fx.requiredIdx, func(r *cannedResponse) {
			r.status = http.StatusInternalServerError
			r.statusText = "500 " + canaryMarker
		}, ErrProtocol)
	})
	t.Run("required-empty-discards", func(t *testing.T) {
		discard(t, "empty", fx.requiredIdx, func(r *cannedResponse) {
			r.body = ""
		}, ErrMalformed)
	})
	t.Run("required-control-char-discards", func(t *testing.T) {
		discard(t, "control", fx.requiredIdx, func(r *cannedResponse) {
			r.body = "a\x1fb"
		}, ErrMalformed)
	})
	t.Run("required-invalid-utf8-discards", func(t *testing.T) {
		discard(t, "utf8", fx.requiredIdx, func(r *cannedResponse) {
			r.body = "\xff"
		}, ErrEncoding)
	})
	t.Run("required-3xx-discards", func(t *testing.T) {
		discard(t, "3xx", fx.requiredIdx, func(r *cannedResponse) {
			r.status = http.StatusSeeOther
		}, ErrRedirect)
	})
	t.Run("required-unreachable-discards", func(t *testing.T) {
		discard(t, "unreachable", fx.requiredIdx, func(r *cannedResponse) {
			r.roundTripErr = &url.Error{
				Op:  "Get",
				URL: metadataBase + "/" + canaryMarker,
				Err: errors.New("connection refused " + canaryMarker),
			}
		}, ErrUnreachable)
	})

	// Successful-status adversarial bodies: a 200 response whose body is
	// not exactly one valid leaf value must be rejected by the per-field
	// validator, discarding the whole result.
	negativeBodies := []struct {
		name string
		body string
	}{
		{"compact-json", `{"instance_id":"i-0abc123def456","zone":"us-east-1a"}`},
		{"html", "<html><body>instance metadata</body></html>"},
		{"excluded-identifier", "projects/415170998498/zones/europe-west1-b"},
	}
	for _, negative := range negativeBodies {
		t.Run("required-adversarial-"+negative.name, func(t *testing.T) {
			discard(t, negative.name, fx.requiredIdx, func(r *cannedResponse) {
				r.body = negative.body
			}, ErrMalformed)
		})
	}
	if fx.optionalIdx >= 0 {
		for _, negative := range negativeBodies {
			negative := negative
			t.Run("optional-adversarial-"+negative.name, func(t *testing.T) {
				discard(t, negative.name, fx.optionalIdx, func(r *cannedResponse) {
					r.body = negative.body
				}, ErrMalformed)
			})
		}
	}
}
