package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/cloudsecret"
	"github.com/friz-zy/statekit/internal/runtime"
)

// azureRouteCanary marks raw caller values that must never reach stdout,
// stderr, or the reader while route requests are rejected.
const azureRouteCanary = "AZURE_ROUTE_CANARY_NOT_FOR_OUTPUT"

const azureLoggingChildEnv = "STATEKIT_TEST_AZURE_CLI_LOGGING_CHILD"

// TestAzureLoggingGuardComposedWithCLISinks starts with the SDK logging
// variable present before package initialization, then exercises the real
// CLI dispatch and production cloudsecret entry points. No fetch may proceed
// when startup logging is configured; stderr-sink failures remain silent.
func TestAzureLoggingGuardComposedWithCLISinks(t *testing.T) {
	if !cloudsecret.AzureAvailable() {
		t.Skip("Azure SDK adapter is disabled in this build profile")
	}
	if os.Getenv(azureLoggingChildEnv) == "1" {
		azureLoggingCLIChild()
		os.Exit(0)
	}
	for _, tc := range []struct {
		route string
		sink  string
		args  []string
	}{
		{route: "keyvault", sink: "stdout", args: []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db-password"}},
		{route: "keyvault", sink: "stderr", args: []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db-password", "--sink", "stderr"}},
		{route: "appconfiguration", sink: "stdout", args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "production"}},
		{route: "appconfiguration", sink: "stderr", args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "production", "--sink", "stderr"}},
	} {
		t.Run(tc.route+"-"+tc.sink, func(t *testing.T) {
			tempDir := t.TempDir()
			resultPath := filepath.Join(tempDir, "result")
			argsJSON, _ := json.Marshal(tc.args)
			executable, err := os.Executable()
			if err != nil {
				t.Fatalf("resolve test executable: %v", err)
			}
			executable, err = filepath.Abs(executable)
			if err != nil {
				t.Fatalf("make test executable path absolute: %v", err)
			}
			command := exec.Command(executable, "-test.run=^TestAzureLoggingGuardComposedWithCLISinks$")
			// Keep child authority minimal: these are only the guard trigger,
			// test protocol, and private temporary directories. In particular,
			// do not propagate PATH, cloud configuration, or credentials.
			command.Env = []string{
				"AZURE_SDK_GO_LOGGING=all",
				azureLoggingChildEnv + "=1",
				"STATEKIT_TEST_AZURE_CLI_RESULT=" + resultPath,
				"STATEKIT_TEST_AZURE_CLI_ARGS=" + string(argsJSON),
				"HOME=" + tempDir,
				"TMPDIR=" + tempDir,
			}
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			if err := command.Run(); err != nil {
				t.Fatalf("child failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
			}
			codeBytes, err := os.ReadFile(resultPath)
			if err != nil {
				t.Fatalf("child result missing: %v", err)
			}
			if string(codeBytes) != fmt.Sprint(ExitFailed) {
				t.Fatalf("unexpected CLI exit code %q", codeBytes)
			}
			if tc.sink == "stdout" {
				if stdout.Len() != 0 || stderr.String() != "statekit: secret provider read failed\n" {
					t.Fatalf("stdout-sink refusal must emit only the fixed CLI diagnostic on stderr: stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
			} else if stdout.Len() != 0 || stderr.Len() != 0 {
				t.Fatalf("stderr-sink refusal must be silent, got stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func azureLoggingCLIChild() {
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("STATEKIT_TEST_AZURE_CLI_ARGS")), &args); err != nil {
		os.Exit(2)
	}
	app := NewApp("test-version", func() (*runtime.Runtime, error) { return nil, errors.New("runtime must not be built") })
	code := app.Run(args)
	if err := os.WriteFile(os.Getenv("STATEKIT_TEST_AZURE_CLI_RESULT"), []byte(fmt.Sprint(code)), 0o600); err != nil {
		os.Exit(3)
	}
}

func newAzureRouteApp(t *testing.T) (*App, *int, *int) {
	t.Helper()
	calls, builds := 0, 0
	app := NewApp("test-version", func() (*runtime.Runtime, error) {
		builds++
		return nil, errors.New("runtime must not be built")
	})
	app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		calls++
		return []byte("synthetic-azure-value"), nil
	}
	return app, &calls, &builds
}

// TestAzureRoutesDispatchThroughSensitiveSinkPath pins that both exact
// hierarchical Azure routes reach the dedicated sensitive-value path — the
// injected secret reader, never generic exec — pin the routed provider and
// backend, carry the typed identity/version fields, and keep stdout payload
// byte-exact with empty stderr.
func TestAzureRoutesDispatchThroughSensitiveSinkPath(t *testing.T) {
	if !cloudsecret.AzureAvailable() {
		t.Skip("Azure SDK adapter is disabled in this build profile")
	}
	for _, tc := range []struct {
		name          string
		args          []string
		provider      string
		backend       string
		region        string
		resource      string
		versionID     string
		versionAlias  string
		label         string
		wantStdout    string
		wantStderrOut bool
	}{
		{
			name:          "keyvault-structured",
			args:          []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db-password"},
			provider:      "azure",
			backend:       "keyvault",
			region:        "prod-vault",
			resource:      "db-password",
			wantStdout:    "synthetic-azure-value",
			wantStderrOut: false,
		},
		{
			name:          "keyvault-pinned-version",
			args:          []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db-password", "--version-id", "0123456789abcdef0123456789abcdef"},
			provider:      "azure",
			backend:       "keyvault",
			region:        "prod-vault",
			resource:      "db-password",
			versionID:     "0123456789abcdef0123456789abcdef",
			wantStdout:    "synthetic-azure-value",
			wantStderrOut: false,
		},
		{
			name:          "keyvault-source-uri",
			args:          []string{"exec", "azure.keyvault.get", "--source-uri", "secret://azure/keyvault/prod-vault/db-password"},
			provider:      "azure",
			backend:       "keyvault",
			region:        "prod-vault",
			resource:      "db-password",
			wantStdout:    "synthetic-azure-value",
			wantStderrOut: false,
		},
		{
			name:          "keyvault-config-channel",
			args:          []string{"exec", "azure.keyvault.get", "--config", "region: prod-vault\nresource: db-password\n"},
			provider:      "azure",
			backend:       "keyvault",
			region:        "prod-vault",
			resource:      "db-password",
			wantStdout:    "synthetic-azure-value",
			wantStderrOut: false,
		},
		{
			name:          "appconfiguration-labeled",
			args:          []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "production"},
			provider:      "azure",
			backend:       "appconfiguration",
			region:        "prod-store",
			resource:      "app.setting",
			label:         "production",
			wantStdout:    "synthetic-azure-value",
			wantStderrOut: false,
		},
		{
			name:          "appconfiguration-uri-composed-with-label",
			args:          []string{"exec", "azure.appconfiguration.get", "--source-uri", "secret://azure/appconfiguration/prod-store/app.setting", "--label", "production"},
			provider:      "azure",
			backend:       "appconfiguration",
			region:        "prod-store",
			resource:      "app.setting",
			label:         "production",
			wantStdout:    "synthetic-azure-value",
			wantStderrOut: false,
		},
		{
			name:          "appconfiguration-structured-label-field",
			args:          []string{"exec", "azure.appconfiguration.get", "--config", "region: prod-store\nresource: app.setting\nlabel: production\n"},
			provider:      "azure",
			backend:       "appconfiguration",
			region:        "prod-store",
			resource:      "app.setting",
			label:         "production",
			wantStdout:    "synthetic-azure-value",
			wantStderrOut: false,
		},
		{
			name:          "appconfiguration-stderr-sink",
			args:          []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "production", "--sink", "stderr"},
			provider:      "azure",
			backend:       "appconfiguration",
			region:        "prod-store",
			resource:      "app.setting",
			label:         "production",
			wantStderrOut: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, calls, builds := newAzureRouteApp(t)
			var seen cloudsecret.Source
			app.secretFetch = func(_ context.Context, source cloudsecret.Source) ([]byte, error) {
				*calls++
				seen = source
				return []byte("synthetic-azure-value"), nil
			}
			code, stdout, stderr := captureCode(t, app, tc.args...)
			if code != ExitOK || *builds != 0 || *calls != 1 {
				t.Fatalf("azure route did not dispatch exactly once through the sensitive path: code=%d calls=%d", code, *calls)
			}
			if seen.Provider != tc.provider || seen.Backend != tc.backend || seen.Region != tc.region || seen.Resource != tc.resource || seen.VersionID != tc.versionID || seen.VersionAlias != tc.versionAlias || seen.Label != tc.label {
				t.Fatalf("dispatched source deviated from the route contract: %+v", seen)
			}
			if tc.wantStderrOut {
				if stdout != "" || stderr != "synthetic-azure-value" {
					t.Fatalf("stderr sink must carry the payload alone, got stdout=%q stderr=%q", stdout, stderr)
				}
			} else if stdout != tc.wantStdout || stderr != "" {
				t.Fatalf("stdout sink must carry the payload byte-exact, got stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}

// TestAzureRoutesRejectMismatchedSourceBeforeFetch keeps the route pinning
// contract: explicit provider, backend, or URI values naming anything other
// than the routed provider and backend are rejected with the fixed
// value-free diagnostic before the runtime, credentials, or reader.
func TestAzureRoutesRejectMismatchedSourceBeforeFetch(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{
			name: "keyvault-provider-mismatch",
			args: []string{"exec", "azure.keyvault.get", "--provider", "gcp", "--region", "prod-vault", "--resource", "db"},
		},
		{
			name: "keyvault-backend-mismatch",
			args: []string{"exec", "azure.keyvault.get", "--backend", "appconfiguration", "--region", "prod-vault", "--resource", "db"},
		},
		{
			name: "keyvault-uri-provider-mismatch",
			args: []string{"exec", "azure.keyvault.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db"},
		},
		{
			name: "keyvault-uri-backend-mismatch",
			args: []string{"exec", "azure.keyvault.get", "--source-uri", "secret://azure/appconfiguration/prod-store/app.setting"},
		},
		{
			name: "appconfiguration-provider-mismatch",
			args: []string{"exec", "azure.appconfiguration.get", "--provider", "aws", "--region", "prod-store", "--resource", "app.setting", "--label", "production"},
		},
		{
			name: "appconfiguration-backend-mismatch",
			args: []string{"exec", "azure.appconfiguration.get", "--backend", "keyvault", "--region", "prod-store", "--resource", "app.setting", "--label", "production"},
		},
		{
			name: "appconfiguration-uri-backend-mismatch",
			args: []string{"exec", "azure.appconfiguration.get", "--source-uri", "secret://azure/keyvault/prod-vault/db-password", "--label", "production"},
		},
		{
			name: "appconfiguration-mixed-uri-and-structured",
			args: []string{"exec", "azure.appconfiguration.get", "--source-uri", "secret://azure/appconfiguration/prod-store/app.setting", "--region", azureRouteCanary},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, calls, builds := newAzureRouteApp(t)
			code, stdout, stderr := captureCode(t, app, tc.args...)
			if code != ExitInvalidInput || stdout != "" || stderr != "statekit: invalid secret request\n" || *calls != 0 || *builds != 0 {
				t.Fatalf("mismatch was not rejected before fetch with the fixed diagnostic: code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if strings.Contains(stdout, azureRouteCanary) || strings.Contains(stderr, azureRouteCanary) {
				t.Fatal("mismatched route input value reached CLI output")
			}
		})
	}
}

// TestAzureKeyVaultRouteContract pins the typed Key Vault request rules at
// the CLI surface: exact public vault-name grammar, secret-name grammar,
// and a 32-hex version selector or latest — never an alias.
func TestAzureKeyVaultRouteContract(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "vault-name-with-dot", args: []string{"exec", "azure.keyvault.get", "--region", "prod.vault.example", "--resource", "db"}},
		{name: "vault-name-uppercase", args: []string{"exec", "azure.keyvault.get", "--region", "ProdVault", "--resource", "db"}},
		{name: "secret-name-with-slash", args: []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db/password"}},
		{name: "version-not-hex", args: []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db", "--version-id", "zz" + strings.Repeat("a", 30)}},
		{name: "version-too-short", args: []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db", "--version-id", strings.Repeat("a", 31)}},
		{name: "alias-rejected", args: []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db", "--version-alias", "latest"}},
		{name: "label-rejected", args: []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db", "--label", "production"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, calls, builds := newAzureRouteApp(t)
			code, stdout, stderr := captureCode(t, app, tc.args...)
			if code != ExitInvalidInput || stdout != "" || stderr != "statekit: invalid secret request\n" || *calls != 0 || *builds != 0 {
				t.Fatalf("invalid keyvault request was not rejected value-free: code=%d stderr=%q", code, stderr)
			}
		})
	}
}

// TestAzureAppConfigurationRouteContract pins the explicit-label rule: a
// request without a first-class label never dispatches, the retired
// version-alias and version-id selectors are rejected for App Configuration,
// and off-grammar labels and identities fail value-free.
func TestAzureAppConfigurationRouteContract(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "missing-label", args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting"}},
		{name: "empty-label", args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label="}},
		{name: "wildcard-label", args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "*"}},
		{name: "space-label", args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "prod uction"}},
		{name: "label-too-long", args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", strings.Repeat("l", 256)}},
		{name: "version-alias-rejected", args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "production", "--version-alias", "production"}},
		{name: "version-alias-alone-rejected", args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--version-alias", "production"}},
		{name: "version-id-rejected", args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "production", "--version-id", "1"}},
		{name: "leading-dot-key", args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", ".app.setting", "--label", "production"}},
		{name: "store-with-dot", args: []string{"exec", "azure.appconfiguration.get", "--region", "prod.store.example", "--resource", "app.setting", "--label", "production"}},
		{name: "uri-without-label", args: []string{"exec", "azure.appconfiguration.get", "--source-uri", "secret://azure/appconfiguration/prod-store/app.setting"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, calls, builds := newAzureRouteApp(t)
			code, stdout, stderr := captureCode(t, app, tc.args...)
			if code != ExitInvalidInput || stdout != "" || stderr != "statekit: invalid secret request\n" || *calls != 0 || *builds != 0 {
				t.Fatalf("unlabeled or off-grammar appconfig request was not rejected value-free: code=%d stderr=%q", code, stderr)
			}
			if strings.Contains(stdout, azureRouteCanary) || strings.Contains(stderr, azureRouteCanary) {
				t.Fatal("rejected appconfig value reached CLI output")
			}
		})
	}
}

// TestAzureRouteStructuredJSONOutputKeepsSinkByteExact pins that the
// sensitive path bypasses the generic serializer on both Azure routes and
// both authorized streams: a JSON payload is re-encoded once and written
// byte-exact to the selected stream alone — stdout or stderr — with no
// trailing newline mixing and the other stream empty.
func TestAzureRouteStructuredJSONOutputKeepsSinkByteExact(t *testing.T) {
	if !cloudsecret.AzureAvailable() {
		t.Skip("Azure SDK adapter is disabled in this build profile")
	}
	for _, tc := range []struct {
		name string
		args []string
		sink string
	}{
		{
			name: "keyvault-stdout",
			args: []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db-password", "--format", "json"},
			sink: "stdout",
		},
		{
			name: "appconfiguration-stdout",
			args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "production", "--format", "json"},
			sink: "stdout",
		},
		{
			name: "keyvault-stderr",
			args: []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db-password", "--format", "json", "--sink", "stderr"},
			sink: "stderr",
		},
		{
			name: "appconfiguration-stderr",
			args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "production", "--format", "json", "--sink", "stderr"},
			sink: "stderr",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, calls, builds := newAzureRouteApp(t)
			app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
				*calls++
				return []byte(`{"token":"synthetic"}`), nil
			}
			code, stdout, stderr := captureCode(t, app, tc.args...)
			if code != ExitOK || *builds != 0 || *calls != 1 {
				t.Fatalf("json-format azure route failed: code=%d", code)
			}
			if tc.sink == "stderr" {
				if stdout != "" || stderr != `{"token":"synthetic"}` {
					t.Fatalf("json stderr sink must carry the payload byte-exact alone: stdout=%q stderr=%q", stdout, stderr)
				}
				return
			}
			if stdout != `{"token":"synthetic"}` || stderr != "" {
				t.Fatalf("json sink output was not byte-exact: stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}

// TestAzureRouteRawStderrByteExact adds the missing raw stderr coverage:
// both Azure routes deliver the fetched bytes verbatim to stderr alone —
// including the tab, newline, NUL, and non-UTF-8 bytes the raw FormatPayload
// contract copies byte-exact — while stdout stays empty.
func TestAzureRouteRawStderrByteExact(t *testing.T) {
	if !cloudsecret.AzureAvailable() {
		t.Skip("Azure SDK adapter is disabled in this build profile")
	}
	want := "synthetic\tvalue\n\x00\xff"
	for _, tc := range []struct {
		name string
		args []string
	}{
		{
			name: "keyvault",
			args: []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db-password", "--sink", "stderr"},
		},
		{
			name: "appconfiguration",
			args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "production", "--sink", "stderr"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, calls, builds := newAzureRouteApp(t)
			app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
				*calls++
				return []byte(want), nil
			}
			code, stdout, stderr := captureCode(t, app, tc.args...)
			if code != ExitOK || *builds != 0 || *calls != 1 {
				t.Fatalf("raw stderr azure route failed: code=%d", code)
			}
			if stdout != "" || stderr != want {
				t.Fatalf("raw stderr sink was not byte-exact and exclusive: stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}

// TestAzureRouteRawStdoutByteExact closes the raw stdout asymmetry: both
// Azure routes deliver the same torture bytes verbatim to stdout alone —
// including the tab, newline, NUL, and non-UTF-8 bytes the raw
// FormatPayload contract copies byte-exact — complementing the plain raw
// stdout cases in the dispatch test and the stderr coverage above.
func TestAzureRouteRawStdoutByteExact(t *testing.T) {
	if !cloudsecret.AzureAvailable() {
		t.Skip("Azure SDK adapter is disabled in this build profile")
	}
	want := "synthetic\tvalue\n\x00\xff"
	for _, tc := range []struct {
		name string
		args []string
	}{
		{
			name: "keyvault",
			args: []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db-password"},
		},
		{
			name: "appconfiguration",
			args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "production"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, calls, builds := newAzureRouteApp(t)
			app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
				*calls++
				return []byte(want), nil
			}
			code, stdout, stderr := captureCode(t, app, tc.args...)
			if code != ExitOK || *builds != 0 || *calls != 1 {
				t.Fatalf("raw stdout azure route failed: code=%d", code)
			}
			if stdout != want || stderr != "" {
				t.Fatalf("raw stdout sink was not byte-exact and exclusive: stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}

// TestAzureRouteStructuredYAMLOutputKeepsSinkByteExact pins the exact
// structured YAML bytes on both Azure routes and both authorized streams:
// the flow-mapping payload is parsed once and remarshalized as a block
// mapping with the yaml.v3 trailing newline (the same serializer contract
// the FormatPayload YAML tests pin for maps), delivered to the selected
// stream alone with the other stream empty.
func TestAzureRouteStructuredYAMLOutputKeepsSinkByteExact(t *testing.T) {
	if !cloudsecret.AzureAvailable() {
		t.Skip("Azure SDK adapter is disabled in this build profile")
	}
	for _, tc := range []struct {
		name string
		args []string
		sink string
	}{
		{
			name: "keyvault-stdout",
			args: []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db-password", "--format", "yaml"},
			sink: "stdout",
		},
		{
			name: "appconfiguration-stdout",
			args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "production", "--format", "yaml"},
			sink: "stdout",
		},
		{
			name: "keyvault-stderr",
			args: []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db-password", "--format", "yaml", "--sink", "stderr"},
			sink: "stderr",
		},
		{
			name: "appconfiguration-stderr",
			args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "production", "--format", "yaml", "--sink", "stderr"},
			sink: "stderr",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, calls, builds := newAzureRouteApp(t)
			app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
				*calls++
				return []byte(`{"token":"synthetic"}`), nil
			}
			code, stdout, stderr := captureCode(t, app, tc.args...)
			if code != ExitOK || *builds != 0 || *calls != 1 {
				t.Fatalf("yaml-format azure route failed: code=%d", code)
			}
			if tc.sink == "stderr" {
				if stdout != "" || stderr != "token: synthetic\n" {
					t.Fatalf("yaml stderr sink must carry the payload byte-exact alone: stdout=%q stderr=%q", stdout, stderr)
				}
				return
			}
			if stdout != "token: synthetic\n" || stderr != "" {
				t.Fatalf("yaml sink output was not byte-exact: stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}

// TestAzureSinkAndFormatAuthorization pins A03: Azure routes deliver only
// raw or structured JSON/YAML payloads to stdout or stderr. The unix sink
// and the text format are rejected before any connection, credential, or
// fetch, while other providers keep their sink and format behavior.
func TestAzureSinkAndFormatAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{
			name: "unix-sink-rejected",
			args: []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db-password", "--sink", "unix", "--target", "/tmp/statekit-azure-uds-test"},
		},
		{
			name: "text-format-rejected",
			args: []string{"exec", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db-password", "--format", "text"},
		},
		{
			name: "appconfig-text-format-rejected",
			args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "production", "--format", "text"},
		},
		{
			name: "appconfig-unix-sink-rejected",
			args: []string{"exec", "azure.appconfiguration.get", "--region", "prod-store", "--resource", "app.setting", "--label", "production", "--sink", "unix", "--target", "/tmp/statekit-azure-uds-test"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, calls, builds := newAzureRouteApp(t)
			code, stdout, stderr := captureCode(t, app, tc.args...)
			if code != ExitUnsupported || stdout != "" || *calls != 0 || *builds != 0 || stderr != "statekit: unsupported secret provider, service, or sink\n" {
				t.Fatalf("unauthorized Azure sink/format must fail before fetch with the fixed diagnostic: code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// TestAzureSinkGatePreservesOtherProviders keeps the provider gate honest:
// the AWS route still accepts the text format and the Parameter Manager
// route still rejects a label before any fetch.
func TestAzureSinkGatePreservesOtherProviders(t *testing.T) {
	if !cloudsecret.AWSAvailable() {
		t.Skip("AWS SDK adapter is disabled in this build profile")
	}
	app, calls, builds := newAzureRouteApp(t)
	code, stdout, stderr := captureCode(t, app, "exec", "aws.secretsmanager.get", "--region", "us-east-1", "--resource", "db", "--format", "text")
	if code != ExitOK || *builds != 0 || *calls != 1 || stdout != "synthetic-azure-value" || stderr != "" {
		t.Fatalf("AWS text format must keep working outside the Azure gate: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	app, calls, builds = newAzureRouteApp(t)
	paramCalls := 0
	app.parameterFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		paramCalls++
		return nil, nil
	}
	code, _, _ = captureCode(t, app, "exec", "gcp.parametermanager.get", "--provider", "gcp", "--backend", "parametermanager", "--region", "global", "--resource", "projects/project-123/locations/global/parameters/config", "--label", "production")
	if code != ExitInvalidInput || *calls != 0 || paramCalls != 0 || *builds != 0 {
		t.Fatalf("Parameter Manager must reject the label selector before fetch: code=%d", code)
	}
}

// TestUsageDocumentsAzureRoutes keeps the help surface exact: both Azure
// routes are documented, the appconfig route documents the mandatory label
// with no version selectors, Azure lines advertise only authorized formats
// and sinks, and no one-dot Azure token exists.
func TestUsageDocumentsAzureRoutes(t *testing.T) {
	for _, route := range []string{"azure.keyvault.get", "azure.appconfiguration.get"} {
		if !strings.Contains(usageText, "statekit exec "+route+" ") {
			t.Fatal("help does not document the Azure route " + route)
		}
	}
	for _, line := range strings.Split(usageText, "\n") {
		if strings.Contains(line, "azure.appconfiguration.get ") {
			if !strings.Contains(line, "--label LABEL") {
				t.Fatal("appconfig usage line does not document the mandatory label")
			}
			if strings.Contains(line, "--version-id") || strings.Contains(line, "--version-alias") {
				t.Fatal("appconfig usage line advertises a version selector it must reject")
			}
		}
		if strings.Contains(line, "azure.keyvault.get ") && strings.Contains(line, "--version-alias") {
			t.Fatal("keyvault usage line advertises an alias it must reject")
		}
		if !strings.HasPrefix(strings.TrimSpace(line), "statekit exec azure.") {
			continue
		}
		if strings.Contains(line, "text") {
			t.Fatal("Azure usage line advertises the unauthorized text format")
		}
		if strings.Contains(line, "unix") || strings.Contains(line, "--target") {
			t.Fatal("Azure usage line advertises the unauthorized unix sink")
		}
	}
	for _, retired := range []string{"azure.keyvault_get", "azure.appconfiguration_get", "cloud.secret.get"} {
		if strings.Contains(usageText, retired) {
			t.Fatal("help documents a nonexistent Azure or generic route " + retired)
		}
	}
}

// TestAzureRoutesClassifiedAsSensitiveInvocations pins panic containment
// classification for the new routes.
func TestAzureRoutesClassifiedAsSensitiveInvocations(t *testing.T) {
	if _, ok := secretInvocationArgs([]string{"exec", "azure.keyvault.get", "--sink", "stderr", "--region", "prod-vault", "--resource", "db"}); !ok {
		t.Fatal("azure.keyvault.get was not classified as a sensitive invocation")
	}
	if _, ok := secretInvocationArgs([]string{"exec", "azure.appconfiguration.get", "--label", "production"}); !ok {
		t.Fatal("azure.appconfiguration.get was not classified as a sensitive invocation")
	}
	for _, argv := range [][]string{
		{"exec", "azure.keyvault.list", "--region", "prod-vault", "--resource", "db"},
		{"exec", "azure.keyvault_get", "--region", "prod-vault", "--resource", "db"},
		{"state", "azure.keyvault.get", "--region", "prod-vault", "--resource", "db"},
	} {
		if _, ok := secretInvocationArgs(argv); ok {
			t.Fatalf("non-route invocation %q was classified as sensitive", argv[1])
		}
	}
}
