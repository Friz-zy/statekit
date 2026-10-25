//go:build statekit_no_sdk_azure || statekit_no_sdks

package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/cloudsecret"
)

// Disabled Azure routes must fail closed before any injected reader could
// run, with the fixed value-free diagnostics and no source values echoed.
func TestAzureDisabledRoutesFailClosedBeforeFetch(t *testing.T) {
	calls := 0
	app := NewApp("test-version", nil)
	app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		calls++
		return []byte("synthetic"), nil
	}
	for _, tc := range []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
	}{
		{
			name:       "keyvault-disabled",
			args:       []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db-password"},
			wantCode:   ExitUnsupported,
			wantStderr: "statekit: unsupported secret provider, service, or sink\n",
		},
		{
			name:       "appconfiguration-disabled",
			args:       []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "production"},
			wantCode:   ExitUnsupported,
			wantStderr: "statekit: unsupported secret provider, service, or sink\n",
		},
		{
			name:       "unlabeled-still-invalid",
			args:       []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting"},
			wantCode:   ExitInvalidInput,
			wantStderr: "statekit: invalid secret request\n",
		},
		{
			name:       "text-format-still-unauthorized",
			args:       []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db-password", "--format", "text"},
			wantCode:   ExitUnsupported,
			wantStderr: "statekit: unsupported secret provider, service, or sink\n",
		},
		{
			name:       "unix-sink-still-unauthorized",
			args:       []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db-password", "--sink", "unix", "--target", "/tmp/statekit-azure-uds-test"},
			wantCode:   ExitUnsupported,
			wantStderr: "statekit: unsupported secret provider, service, or sink\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := captureCode(t, app, tc.args...)
			if code != tc.wantCode || stdout != "" || calls != 0 || stderr != tc.wantStderr {
				t.Fatalf("disabled Azure route deviated: code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			for _, leaked := range tc.args[2:] {
				if strings.HasPrefix(leaked, "--") {
					continue
				}
				if strings.Contains(stderr, leaked) {
					t.Fatalf("disabled Azure route diagnostic leaked the source value %q", leaked)
				}
			}
		})
	}
}
