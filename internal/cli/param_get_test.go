//go:build !statekit_no_sdk_gcp && !statekit_no_sdks

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/cloudsecret"
)

func TestParameterHelpDocumentsURIAndRetryContract(t *testing.T) {
	if !strings.Contains(usageText, "percent-encode the complete provider-native resource") || !strings.Contains(usageText, "literal slash-expanded resource paths are rejected") || !strings.Contains(usageText, "no application-level retry or fallback") || !strings.Contains(usageText, "gRPC may transparently retry/reconnect the same call") {
		t.Fatal("Parameter Manager help does not document its URI and retry contract")
	}
}

func TestParameterGetRejectsFileBeforeRuntime(t *testing.T) {
	app := NewApp("test", nil)
	app.parameterFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		t.Fatal("file sink fetched")
		return nil, nil
	}
	code, stdout, stderr := captureCode(t, app, "exec", "cloud.param.get", "--source-uri", "param://gcp/parametermanager/global/projects%2Fproject-123%2Flocations%2Fglobal%2Fparameters%2Fconfig", "--sink", "file")
	if code != ExitUnsupported || stdout != "" || strings.Contains(stderr, "project-123") {
		t.Fatal("parameter file sink must fail closed before runtime or identity")
	}
}

func TestParameterRequestRejectsMixedUnknownDuplicate(t *testing.T) {
	for _, argv := range [][]string{
		{"--source-uri", "param://gcp/parametermanager/global/projects%2Fproject-123%2Flocations%2Fglobal%2Fparameters%2Fconfig", "--provider", "gcp"},
		{"--provider", "gcp"}, {"--endpoint", "bad"}, {"--provider", "gcp", "--provider", "gcp"},
		{"--config", `{"provider":"gcp","provider":"gcp"}`},
	} {
		parsed, err := parseSecretArgs(argv, strings.NewReader(""))
		if err == nil {
			_, err = makeSensitiveRequest(parsed, true)
		}
		if err == nil {
			t.Fatal("invalid parameter request accepted")
		}
	}
}

func TestParameterFormatsAndRedaction(t *testing.T) {
	if !cloudsecret.GCPAvailable() {
		t.Skip("GCP disabled")
	}
	for _, tc := range []struct{ format, payload, key, want string }{
		{"raw", "__REF__(unresolved)", "", "__REF__(unresolved)"},
		{"text", "synthetic", "", "synthetic"},
		{"json", `{"a":"synthetic"}`, "/a", `"synthetic"`},
		{"yaml", "a: synthetic\n", "/a", "synthetic\n"},
	} {
		app := NewApp("test", nil)
		app.parameterFetch = func(context.Context, cloudsecret.Source) ([]byte, error) { return []byte(tc.payload), nil }
		args := []string{"exec", "cloud.param.get", "--provider", "gcp", "--backend", "parametermanager", "--region", "global", "--resource", "projects/project-123/locations/global/parameters/config", "--format", tc.format}
		if tc.key != "" {
			args = append(args, "--key-path", tc.key)
		}
		code, out, diagnostic := captureCode(t, app, args...)
		if code != ExitOK || out != tc.want || diagnostic != "" {
			t.Fatal("parameter format delivery failed")
		}
		app.parameterFetch = func(context.Context, cloudsecret.Source) ([]byte, error) { return nil, errors.New("sensitive-canary") }
		code, out, diagnostic = captureCode(t, app, args...)
		if code != ExitFailed || out != "" || strings.Contains(diagnostic, "sensitive-canary") {
			t.Fatal("parameter error leaked")
		}
	}
}

func TestParameterGetRejectsSecretBackend(t *testing.T) {
	app := NewApp("test", nil)
	code, stdout, stderr := captureCode(t, app, "exec", "cloud.param.get", "--provider", "gcp", "--backend", "secretmanager", "--region", "global", "--resource", "projects/project-123/secrets/config")
	if code != ExitUnsupported || stdout != "" || strings.Contains(stderr, "project-123") {
		t.Fatal("parameter command must not dispatch to a secret backend")
	}
}

func TestParameterGetPassesExplicitLatestAliasToReader(t *testing.T) {
	app := NewApp("test", nil)
	app.parameterFetch = func(_ context.Context, source cloudsecret.Source) ([]byte, error) {
		if source.Provider != "gcp" || source.Backend != "parametermanager" || source.Region != "global" || source.Resource != "projects/project-123/locations/global/parameters/config" || source.VersionID != "" || source.VersionAlias != "latest" {
			t.Fatal("explicit latest alias did not reach Parameter Manager reader")
		}
		return []byte("synthetic"), nil
	}
	code, stdout, stderr := captureCode(t, app, "exec", "cloud.param.get", "--provider", "gcp", "--backend", "parametermanager", "--region", "global", "--resource", "projects/project-123/locations/global/parameters/config", "--version-alias", "latest")
	if code != ExitOK || stdout != "synthetic" || stderr != "" {
		t.Fatal("explicit latest alias request failed")
	}
}
