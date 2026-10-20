//go:build statekit_no_sdk_gcp || statekit_no_sdks

package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/cloudsecret"
)

func TestGCPDisabledCLIExitsBeforeFetch(t *testing.T) {
	calls := 0
	app := NewApp("test-version", nil)
	app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		calls++
		return []byte("synthetic"), nil
	}
	app.parameterFetch = app.secretFetch
	for _, args := range [][]string{
		{"exec", "cloud.param.get", "--provider", "gcp", "--backend", "parametermanager", "--region", "global", "--resource", "projects/project-123/locations/global/parameters/config"},
		{"exec", "cloud.secret.get", "--source-uri", "secret://gcp/secretmanager/global/projects%2Fproject-123%2Fsecrets%2Fdb"},
		{"exec", "cloud.secret.get", "--provider", "gcp", "--backend", "secretmanager", "--region", "global", "--resource", "projects/project-123/secrets/db"},
	} {
		code, stdout, stderr := captureCode(t, app, args...)
		if code != ExitUnsupported || stdout != "" || calls != 0 || strings.Contains(stderr, "project-123") {
			t.Fatal("disabled GCP CLI path did not fail before fetch with value-free output")
		}
	}
}
