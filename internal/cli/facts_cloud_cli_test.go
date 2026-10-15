package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/cloudmeta"
)

func cloudFactsApp(collect cloudCollectFunc) *App {
	app := NewApp("test-version", testRuntime)
	app.CloudCollect = collect
	return app
}

func TestFactsCloudFlagsMustBePaired(t *testing.T) {
	for _, argv := range [][]string{
		{"facts", "--cloud"},
		{"facts", "--provider", "aws"},
		{"facts", "--provider=do"},
		{"facts", "--provider="},
		{"facts", "--cloud", "--provider="},
	} {
		called := false
		app := cloudFactsApp(func(context.Context, string) (*cloudmeta.Result, error) {
			called = true
			return nil, nil
		})
		code, out, errS := captureCode(t, app, argv...)
		if code != ExitInvalidInput || out != "" || called {
			t.Fatalf("%v: code=%d out=%q err=%q collectorCalled=%v", argv, code, out, errS, called)
		}
	}
}

func TestFactsCloudRejectsPositionalArguments(t *testing.T) {
	called := false
	app := cloudFactsApp(func(context.Context, string) (*cloudmeta.Result, error) {
		called = true
		return nil, nil
	})
	code, out, errS := captureCode(t, app, "facts", "--cloud", "--provider", "do", "extra")
	if code != ExitInvalidInput || out != "" || called {
		t.Fatalf("code=%d out=%q err=%q collectorCalled=%v", code, out, errS, called)
	}
}

// An explicitly false --cloud value never dispatches, even when --provider
// is present: invalid input, collector not invoked, no request.
func TestFactsCloudExplicitFalseValueNeverDispatches(t *testing.T) {
	for _, argv := range [][]string{
		{"facts", "--cloud=false", "--provider", "aws"},
		{"facts", "--cloud=0", "--provider", "aws"},
		{"facts", "--cloud", "--cloud=false", "--provider", "aws"},
	} {
		called := false
		app := cloudFactsApp(func(context.Context, string) (*cloudmeta.Result, error) {
			called = true
			return nil, nil
		})
		code, out, errS := captureCode(t, app, argv...)
		if code != ExitInvalidInput || out != "" || called {
			t.Fatalf("%v: code=%d out=%q err=%q collectorCalled=%v", argv, code, out, errS, called)
		}
	}
}

// Unknown providers use the real collector: ErrInvalidProvider is
// returned before any client or request construction, so this stays
// offline.
func TestFactsCloudUnknownProviderExitsTwo(t *testing.T) {
	code, out, errS := captureCode(t, cloudFactsApp(nil), "facts", "--cloud", "--provider", "rackspace")
	if code != ExitInvalidInput || out != "" || errS != "statekit: cloud_meta_invalid_provider\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errS)
	}
}

// Deferred providers also fail before any network use, so the real
// collector is safe here too.
func TestFactsCloudDeferredProviderExitsThreeWithoutRequest(t *testing.T) {
	code, out, errS := captureCode(t, cloudFactsApp(nil), "facts", "--cloud", "--provider", "ibm")
	if code != ExitUnsupported || out != "" || errS != "statekit: cloud_meta_deferred_provider\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errS)
	}
}

func TestFactsCloudBuildDisabledExitsThree(t *testing.T) {
	app := cloudFactsApp(func(context.Context, string) (*cloudmeta.Result, error) {
		return nil, cloudmeta.ErrBuildDisabled
	})
	code, out, errS := captureCode(t, app, "facts", "--cloud", "--provider", "aws")
	if code != ExitUnsupported || out != "" || errS != "statekit: cloud_meta_build_disabled\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errS)
	}
}

// stderr carries only mapped sentinel codes: a wrapped sentinel prints
// the sentinel text, never the wrapper's value text.
func TestFactsCloudWrappedSentinelPrintsOnlyCode(t *testing.T) {
	app := cloudFactsApp(func(context.Context, string) (*cloudmeta.Result, error) {
		return nil, fmt.Errorf("wrapped failure detail CANARY_LEAK: %w", cloudmeta.ErrUnreachable)
	})
	code, out, errS := captureCode(t, app, "facts", "--cloud", "--provider", "aws")
	if code != ExitFailed || out != "" || errS != "statekit: cloud_meta_unreachable\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errS)
	}
	if strings.Contains(errS, "CANARY_LEAK") {
		t.Fatalf("non-sentinel text leaked into stderr: %q", errS)
	}
}

// A non-sentinel error never reaches stderr raw: the fixed
// cloud_meta_internal fallback code is printed instead.
func TestFactsCloudArbitraryErrorPrintsInternalFallback(t *testing.T) {
	app := cloudFactsApp(func(context.Context, string) (*cloudmeta.Result, error) {
		return nil, errors.New("strange failure CANARY_LEAK detail")
	})
	code, out, errS := captureCode(t, app, "facts", "--cloud", "--provider", "aws")
	if code != ExitFailed || out != "" || errS != "statekit: cloud_meta_internal\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errS)
	}
	if strings.Contains(errS, "CANARY_LEAK") {
		t.Fatalf("arbitrary error text leaked into stderr: %q", errS)
	}
}

func TestFactsCloudSuccessPrintsOnlyCloudEnvelope(t *testing.T) {
	app := cloudFactsApp(func(_ context.Context, provider string) (*cloudmeta.Result, error) {
		if provider != "do" {
			t.Fatalf("provider=%q, want do", provider)
		}
		return &cloudmeta.Result{
			Provider:     "do",
			Status:       "ok",
			Verification: "unverified",
			InstanceID:   "175501237",
			Region:       "fra1",
		}, nil
	})
	code, out, errS := captureCode(t, app, "facts", "--cloud", "--provider", "do")
	if code != ExitOK || errS != "" {
		t.Fatalf("code=%d err=%q", code, errS)
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		t.Fatalf("decode envelope: %v (%q)", err, out)
	}
	if len(envelope) != 1 {
		t.Fatalf("envelope keys=%v, want only cloud", envelope)
	}
	cloud, ok := envelope["cloud"].(map[string]any)
	if !ok {
		t.Fatalf("envelope=%v, want cloud object", envelope)
	}
	if cloud["provider"] != "do" || cloud["status"] != "ok" ||
		cloud["verification"] != "unverified" ||
		cloud["instance_id"] != "175501237" || cloud["region"] != "fra1" {
		t.Fatalf("cloud payload=%v", cloud)
	}
	if _, hasLocalFacts := cloud["os"]; hasLocalFacts {
		t.Fatalf("local facts leaked into cloud envelope: %v", cloud)
	}
	if strings.Contains(out, `"os"`) {
		t.Fatalf("local facts leaked into envelope output: %q", out)
	}
}

// A partial result (documented optional leaf omitted) is still a
// success: exit 0 with the verification marker and the not-present
// reason in the envelope.
func TestFactsCloudPartialStatusStillSucceeds(t *testing.T) {
	app := cloudFactsApp(func(context.Context, string) (*cloudmeta.Result, error) {
		return &cloudmeta.Result{
			Provider:           "do",
			Status:             "partial",
			Verification:       "unverified",
			InstanceID:         "175501237",
			FieldsNotCollected: map[string]string{"region": "not_present"},
		}, nil
	})
	code, out, errS := captureCode(t, app, "facts", "--cloud", "--provider", "do")
	if code != ExitOK || errS != "" {
		t.Fatalf("code=%d err=%q out=%q", code, errS, out)
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		t.Fatalf("decode envelope: %v (%q)", err, out)
	}
	cloud, ok := envelope["cloud"].(map[string]any)
	if !ok || cloud["status"] != "partial" || cloud["verification"] != "unverified" {
		t.Fatalf("cloud payload=%v", cloud)
	}
	notCollected, ok := cloud["fields_not_collected"].(map[string]any)
	if !ok || notCollected["region"] != "not_present" {
		t.Fatalf("fields_not_collected=%v", cloud["fields_not_collected"])
	}
}

func TestFactsCloudCollectionErrorExitsOneWithoutPayload(t *testing.T) {
	app := cloudFactsApp(func(context.Context, string) (*cloudmeta.Result, error) {
		return nil, cloudmeta.ErrUnreachable
	})
	code, out, errS := captureCode(t, app, "facts", "--cloud", "--provider", "aws")
	if code != ExitFailed || out != "" || errS != "statekit: cloud_meta_unreachable\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errS)
	}
}

func TestFactsDefaultOutputUnchangedAndNetworkFree(t *testing.T) {
	called := false
	app := cloudFactsApp(func(context.Context, string) (*cloudmeta.Result, error) {
		called = true
		return nil, nil
	})
	code, out, errS := captureCode(t, app, "facts", "-o", "json")
	if code != ExitOK || errS != "" || called {
		t.Fatalf("code=%d err=%q collectorCalled=%v", code, errS, called)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("decode facts: %v (%q)", err, out)
	}
	osFacts, ok := parsed["os"].(map[string]any)
	if !ok || osFacts["id"] != "alpine" {
		t.Fatalf("facts payload wrong: %v", parsed["os"])
	}
	if strings.Contains(out, "cloud") {
		t.Fatalf("cloud data leaked into default facts output: %q", out)
	}
}
