//go:build statekit_no_sdk_gcp || statekit_no_sdks

package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/cloudsecret"
)

func TestParameterGetDisabledProfileFailsBeforeFetch(t *testing.T) {
	app := NewApp("test", nil)
	fetched := false
	app.parameterFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		fetched = true
		return []byte("unexpected"), nil
	}
	code, stdout, stderr := captureCode(t, app, "exec", "cloud.param.get", "--provider", "gcp", "--backend", "parametermanager", "--region", "global", "--resource", "projects/project-123/locations/global/parameters/config", "--version-alias", "latest")
	if code != ExitUnsupported || stdout != "" || fetched || strings.Contains(stderr, "project-123") {
		t.Fatal("disabled GCP profile must fail unsupported before fetch")
	}
}

func TestParameterGetDisabledProfilePreservesInvalidInputPreflight(t *testing.T) {
	app := NewApp("test", nil)
	fetched := false
	app.parameterFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		fetched = true
		return nil, nil
	}
	code, stdout, _ := captureCode(t, app, "exec", "cloud.param.get", "--provider", "gcp", "--backend", "parametermanager", "--region", "global", "--resource", "projects/project-123/locations/global/parameters/config", "--version-alias", "invalid")
	if code == ExitUnsupported || code == ExitOK || stdout != "" || fetched {
		t.Fatal("invalid input must be rejected during preflight before runtime")
	}
}
