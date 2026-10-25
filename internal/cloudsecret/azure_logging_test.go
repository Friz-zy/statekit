//go:build !statekit_no_sdk_azure && !statekit_no_sdks

package cloudsecret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azappconfig "github.com/Azure/azure-sdk-for-go/sdk/data/azappconfig/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// SEC-R01 guard tests. The startup half of the guard can only be observed
// in a process whose AZURE_SDK_GO_LOGGING value was fixed before package
// initialization, so every startup case re-execs this test binary as a
// fresh child with the value baked into its environment at exec time.
// Setting the variable from a test after package init would prove nothing
// and is never done in the parent process; the runtime cases mutate the
// variable only inside their own disposable child to exercise the
// fetch-time recheck and the immutability of the startup capture.
// Everything runs offline against fakes: no listener, socket, credential,
// or live service is involved, and no azcore/log global is touched.

const (
	azureLogGuardChildModeEnv  = "STATEKIT_TEST_AZURE_LOG_GUARD_CHILD_MODE"
	azureLogGuardCaseEnv       = "STATEKIT_TEST_AZURE_LOG_GUARD_CASE"
	azureLogGuardRuntimeOpEnv  = "STATEKIT_TEST_AZURE_LOG_GUARD_RUNTIME_OP"
	azureLogGuardRuntimeValEnv = "STATEKIT_TEST_AZURE_LOG_GUARD_RUNTIME_VALUE"
	azureLogGuardResultEnv     = "STATEKIT_TEST_AZURE_LOG_GUARD_RESULT"
	azureLogGuardChildModeOn   = "1"
	azureLogGuardVault         = "prod-vault"
	azureLogGuardStore         = "prod-store"
	azureLogGuardLabel         = "production"
	azureLogGuardPayload       = "azure-log-guard-synthetic-payload"
	azureLogGuardVersion       = "0123456789abcdef0123456789abcdef"
)

// TestAzureSDKLoggingConfiguredPolicy pins the fail-closed interpretation
// of the guard predicate: every nonempty startup or current value refuses,
// including casing, whitespace, and values the SDK would not recognize;
// only empty and unset pass.
func TestAzureSDKLoggingConfiguredPolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		startup string
		current string
		want    bool
	}{
		{name: "unset at start and now", startup: "", current: "", want: false},
		{name: "startup all", startup: "all", current: "", want: true},
		{name: "startup uppercase all", startup: "ALL", current: "", want: true},
		{name: "startup whitespace", startup: " ", current: "", want: true},
		{name: "startup unrecognized", startup: "verbose", current: "", want: true},
		{name: "current all", startup: "", current: "all", want: true},
		{name: "current whitespace", startup: "", current: " ", want: true},
		{name: "current unrecognized", startup: "", current: "x", want: true},
		{name: "startup and current", startup: "all", current: "all", want: true},
	} {
		if got := azureSDKLoggingConfigured(tc.startup, tc.current); got != tc.want {
			t.Fatalf("%s: azureSDKLoggingConfigured(%q, %q) = %v, want %v", tc.name, tc.startup, tc.current, got, tc.want)
		}
	}
}

type azureLogGuardCredential struct{}

func (azureLogGuardCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, ErrCredentials
}

type azureLogGuardSecrets struct{ calls int }

func (f *azureLogGuardSecrets) GetSecret(context.Context, string, string, *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	f.calls++
	identity := azsecrets.ID("https://" + azureLogGuardVault + ".vault.azure.net/secrets/db-password/" + azureLogGuardVersion)
	value := azureLogGuardPayload
	return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{ID: &identity, Value: &value}}, nil
}

type azureLogGuardSettings struct{ calls int }

func (f *azureLogGuardSettings) GetSetting(_ context.Context, key string, _ *azappconfig.GetSettingOptions) (azappconfig.GetSettingResponse, error) {
	f.calls++
	label := azureLogGuardLabel
	value := azureLogGuardPayload
	return azappconfig.GetSettingResponse{Setting: azappconfig.Setting{Key: &key, Label: &label, Value: &value}}, nil
}

// TestAzureSDKLoggingGuardRefusesConfiguredLogging runs each case in a
// fresh child process whose startup AZURE_SDK_GO_LOGGING state is exact.
// Refused cases must return the closed provider sentinel with no payload
// bytes and must never reach the credential or client factories; clean
// cases must keep the pre-guard successful read byte-for-byte. The child's
// stdout must be exactly "PASS" and its stderr must stay empty: no SDK
// logs and no diagnostics beyond the CLI's existing fixed error.
func TestAzureSDKLoggingGuardRefusesConfiguredLogging(t *testing.T) {
	if os.Getenv(azureLogGuardChildModeEnv) == azureLogGuardChildModeOn {
		azureLogGuardChildFixture()
		return
	}
	for _, tc := range []struct {
		name         string
		loggingSet   bool // variable present in the child's startup environment
		loggingValue string
		runtimeOp    string // "", "set", or "unset": post-init mutation inside the child only
		runtimeValue string
		wantRefused  bool
	}{
		{name: "keyvault-startup-all", loggingSet: true, loggingValue: "all", wantRefused: true},
		{name: "keyvault-startup-uppercase", loggingSet: true, loggingValue: "ALL", wantRefused: true},
		{name: "keyvault-startup-whitespace", loggingSet: true, loggingValue: " ", wantRefused: true},
		{name: "keyvault-startup-unrecognized", loggingSet: true, loggingValue: "verbose", wantRefused: true},
		{name: "keyvault-startup-all-cleared-at-runtime", loggingSet: true, loggingValue: "all", runtimeOp: "unset", wantRefused: true},
		{name: "keyvault-runtime-set-after-init", loggingSet: false, runtimeOp: "set", runtimeValue: "all", wantRefused: true},
		{name: "keyvault-empty-at-startup", loggingSet: true, loggingValue: "", wantRefused: false},
		{name: "keyvault-unset-at-startup", loggingSet: false, wantRefused: false},
		{name: "appconfig-startup-all", loggingSet: true, loggingValue: "all", wantRefused: true},
		{name: "appconfig-startup-whitespace", loggingSet: true, loggingValue: "\t", wantRefused: true},
		{name: "appconfig-runtime-set-after-init", loggingSet: false, runtimeOp: "set", runtimeValue: "unexpected", wantRefused: true},
		{name: "appconfig-unset-at-startup", loggingSet: false, wantRefused: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, stdout, stderr, exitCode := azureLogGuardRunChild(t, tc.name, tc.loggingSet, tc.loggingValue, tc.runtimeOp, tc.runtimeValue)
			if exitCode != 0 {
				t.Fatalf("child exited with code %d\nchild stdout:\n%s\nchild stderr:\n%s", exitCode, stdout, stderr)
			}
			if stderr != "" {
				t.Fatalf("child stderr must be empty (no SDK logs, no extra diagnostics), got:\n%s", stderr)
			}
			if stdout != "PASS\n" {
				t.Fatalf("child stdout must be exactly %q, got %q", "PASS\n", stdout)
			}
			if tc.wantRefused {
				if result["err"] != "provider" {
					t.Fatalf("configured SDK logging must fail closed with the provider sentinel, got err=%s", result["err"])
				}
				if result["credential_calls"] != "0" || result["client_calls"] != "0" {
					t.Fatalf("refusal must precede credential and client factories, got credential=%s client=%s", result["credential_calls"], result["client_calls"])
				}
				if result["payload_len"] != "0" || result["payload_value"] != "" {
					t.Fatalf("refusal must return no payload bytes, got len=%s value=%q", result["payload_len"], result["payload_value"])
				}
				return
			}
			if result["err"] != "nil" || result["payload_value"] != azureLogGuardPayload || result["payload_len"] != fmt.Sprint(len(azureLogGuardPayload)) {
				t.Fatalf("clean startup environment must keep the existing successful read, got err=%s payload=%q len=%s", result["err"], result["payload_value"], result["payload_len"])
			}
			if result["credential_calls"] != "1" || result["client_calls"] != "1" {
				t.Fatalf("clean startup environment must still build exactly one credential and one client, got credential=%s client=%s", result["credential_calls"], result["client_calls"])
			}
		})
	}
}

// azureLogGuardRunChild execs this test binary in child mode with an exact
// startup environment: AZURE_SDK_GO_LOGGING and every fixture variable are
// stripped from the inherited environment and rebuilt from the case, so a
// developer machine carrying any of them cannot skew the result.
func azureLogGuardRunChild(t *testing.T, caseName string, loggingSet bool, loggingValue, runtimeOp, runtimeValue string) (result map[string]string, stdout, stderr string, exitCode int) {
	t.Helper()
	resultPath := filepath.Join(t.TempDir(), "result")
	env := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case azureSDKLoggingEnv, azureLogGuardChildModeEnv, azureLogGuardCaseEnv, azureLogGuardRuntimeOpEnv, azureLogGuardRuntimeValEnv, azureLogGuardResultEnv:
			// Rebuilt below so the child's startup environment is exact.
		default:
			env = append(env, entry)
		}
	}
	if loggingSet {
		env = append(env, azureSDKLoggingEnv+"="+loggingValue)
	}
	env = append(env,
		azureLogGuardChildModeEnv+"="+azureLogGuardChildModeOn,
		azureLogGuardCaseEnv+"="+caseName,
	)
	if runtimeOp != "" {
		env = append(env, azureLogGuardRuntimeOpEnv+"="+runtimeOp)
	}
	if runtimeValue != "" {
		env = append(env, azureLogGuardRuntimeValEnv+"="+runtimeValue)
	}
	env = append(env, azureLogGuardResultEnv+"="+resultPath)

	command := exec.Command(os.Args[0], "-test.run=^TestAzureSDKLoggingGuardRefusesConfiguredLogging$", "-test.timeout=60s")
	command.Env = env
	var out, errOut bytes.Buffer
	command.Stdout = &out
	command.Stderr = &errOut
	runErr := command.Run()
	exitCode = 0
	if runErr != nil {
		exitCode = 1
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) && exitErr.ExitCode() >= 0 {
			exitCode = exitErr.ExitCode()
		}
	}
	result = map[string]string{}
	raw, readErr := os.ReadFile(resultPath)
	if readErr != nil {
		t.Fatalf("child produced no result file (exit code %d)\nchild stdout:\n%s\nchild stderr:\n%s", exitCode, out.String(), errOut.String())
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			result[key] = value
		}
	}
	return result, out.String(), errOut.String(), exitCode
}

// azureLogGuardChildFixture performs one fetch against counting fakes and
// records the outcome for the parent. It never fails the test itself: the
// parent owns every assertion, including that the child's streams carry
// nothing but the test framework's own output.
func azureLogGuardChildFixture() {
	caseName := os.Getenv(azureLogGuardCaseEnv)
	resultPath := os.Getenv(azureLogGuardResultEnv)
	if caseName == "" || resultPath == "" {
		return
	}
	// Runtime-branch cases only: mutate the variable after package
	// initialization inside this disposable child. The startup cases never
	// reach this code; their value arrives at exec time.
	switch os.Getenv(azureLogGuardRuntimeOpEnv) {
	case "set":
		if err := os.Setenv(azureSDKLoggingEnv, os.Getenv(azureLogGuardRuntimeValEnv)); err != nil {
			fmt.Fprintf(os.Stderr, "azure log guard child: setenv failed: %v\n", err)
			os.Exit(1)
		}
	case "unset":
		if err := os.Unsetenv(azureSDKLoggingEnv); err != nil {
			fmt.Fprintf(os.Stderr, "azure log guard child: unsetenv failed: %v\n", err)
			os.Exit(1)
		}
	}
	credentialCalls, clientCalls := 0, 0
	dependencies := azureFetchDependencies{
		newCredential: func() azcore.TokenCredential {
			credentialCalls++
			return azureLogGuardCredential{}
		},
	}
	var payload []byte
	var err error
	if strings.HasPrefix(caseName, "appconfig") {
		source := Source{Provider: "azure", Backend: "appconfiguration", Region: azureLogGuardStore, Resource: "app.setting", Label: azureLogGuardLabel}
		dependencies.newAppConfig = func(string, string, azcore.TokenCredential) (azureSettingsAPI, func(), error) {
			clientCalls++
			return &azureLogGuardSettings{}, func() {}, nil
		}
		payload, err = fetchAzureAppConfigurationWith(context.Background(), source, dependencies)
	} else {
		source := Source{Provider: "azure", Backend: "keyvault", Region: azureLogGuardVault, Resource: "db-password"}
		dependencies.newKeyVault = func(string, azcore.TokenCredential) (azureSecretsAPI, func(), error) {
			clientCalls++
			return &azureLogGuardSecrets{}, func() {}, nil
		}
		payload, err = fetchAzureKeyVaultWith(context.Background(), source, dependencies)
	}
	report := fmt.Sprintf("credential_calls=%d\nclient_calls=%d\npayload_len=%d\npayload_value=%s\nerr=%s\n",
		credentialCalls, clientCalls, len(payload), string(payload), azureLogGuardErrorKind(err))
	if writeErr := os.WriteFile(resultPath, []byte(report), 0o600); writeErr != nil {
		fmt.Fprintf(os.Stderr, "azure log guard child: result write failed: %v\n", writeErr)
		os.Exit(1)
	}
}

func azureLogGuardErrorKind(err error) string {
	switch {
	case err == nil:
		return "nil"
	case errors.Is(err, ErrProvider):
		return "provider"
	case errors.Is(err, ErrUnsupported):
		return "unsupported"
	case errors.Is(err, ErrInvalidSource):
		return "invalid-source"
	case errors.Is(err, ErrInvalidPayload):
		return "invalid-payload"
	case errors.Is(err, ErrCredentials):
		return "credentials"
	default:
		return "other"
	}
}
