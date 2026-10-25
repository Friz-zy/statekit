package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/cloudsecret"
	"github.com/friz-zy/statekit/internal/runtime"
)

// routeMismatchCanary marks input values that must never reach stderr,
// stdout, or the fetcher during route validation failures.
const routeMismatchCanary = "ROUTE_MISMATCH_CANARY_NOT_FOR_LOGS"

func newRouteProbeApp(t *testing.T) (*App, *int, *int) {
	t.Helper()
	calls, builds := 0, 0
	app := NewApp("test-version", func() (*runtime.Runtime, error) {
		builds++
		return nil, errors.New("runtime must not be built")
	})
	app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		calls++
		return nil, nil
	}
	return app, &calls, &builds
}

// TestRetiredCloudTargetsRejectedByNormalParsingBeforeRuntimeAndFetch pins
// the removal of the generic cloud.* interface: both retired targets are no
// longer routed, hinted, or aliased; they fail ordinary <module>.<function>
// parsing (two dots are not a valid target) before any input channel is
// read, runtime is built, credential is consulted, or fetch runs.
func TestRetiredCloudTargetsRejectedByNormalParsingBeforeRuntimeAndFetch(t *testing.T) {
	app, calls, builds := newRouteProbeApp(t)
	paramCalls := 0
	app.parameterFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		paramCalls++
		return nil, nil
	}
	for _, args := range [][]string{
		{"exec", "cloud.secret.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db"},
		{"exec", "cloud.secret.get", "--provider", "aws", "--backend", "secretsmanager", "--region", "us-east-1", "--resource", "db"},
		{"exec", "cloud.param.get", "--source-uri", "param://gcp/parametermanager/global/projects%2Fproject-123%2Flocations%2Fglobal%2Fparameters%2Fconfig"},
		{"exec", "cloud.param.get", "--provider", "gcp", "--backend", "parametermanager", "--region", "global", "--resource", "projects/project-123/locations/global/parameters/config"},
		{"exec", "cloud.param.get", "--sink", "stderr", "--source-uri", "param://gcp/parametermanager/global/projects%2Fproject-123%2Flocations%2Fglobal%2Fparameters%2Fconfig"},
		{"exec", "--file", "/nonexistent/statekit-route-test", "cloud.secret.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db"},
	} {
		code, stdout, stderr := captureCode(t, app, args...)
		if code != ExitInvalidInput || stdout != "" || *calls != 0 || paramCalls != 0 || *builds != 0 {
			t.Fatal("retired cloud target was not rejected by normal parsing before runtime and fetch")
		}
		if strings.Contains(stderr, "retired") || strings.Contains(stderr, "use aws.secretsmanager.get") {
			t.Fatal("retired cloud target received a dedicated tombstone diagnostic")
		}
		if !strings.Contains(stderr, "function must be <module>.<function>") {
			t.Fatal("retired cloud target did not fail with the normal CLI parse diagnostic")
		}
	}
}

// TestUsageDocumentsOnlyProviderServiceRoutes keeps the CLI help free of
// every generic cloud.* root and of every retired one-dot route token.
func TestUsageDocumentsOnlyProviderServiceRoutes(t *testing.T) {
	for _, route := range []string{"aws.secretsmanager.get", "aws.ssm.get", "gcp.secretmanager.get", "gcp.parametermanager.get"} {
		if !strings.Contains(usageText, route) {
			t.Fatal("help does not document the provider-first service route " + route)
		}
	}
	for _, retired := range []string{"aws.secretsmanager_get", "aws.ssm_get", "gcp.secretmanager_get", "gcp.parametermanager_get"} {
		if strings.Contains(usageText, retired) {
			t.Fatal("help still documents the retired one-dot route " + retired)
		}
	}
	if strings.Contains(usageText, "cloud.secret.get") || strings.Contains(usageText, "cloud.param.get") {
		t.Fatal("help still exposes a generic cloud interface")
	}
}

// TestUsageVersionSelectorHelpMatchesRouteContracts pins the help-text
// contract for version selectors on the exact `statekit exec` usage lines:
// both GCP routes advertise only the `latest` alias (request validation
// rejects every other GCP alias), the AWS Secrets Manager route keeps its
// free-form stage alias, and the SSM route admits no alias at all. This
// constrains help text only; dispatch and validation behavior are unchanged.
func TestUsageVersionSelectorHelpMatchesRouteContracts(t *testing.T) {
	usage := map[string]string{}
	for _, line := range strings.Split(usageText, "\n") {
		if !strings.HasPrefix(line, "  statekit exec ") {
			continue
		}
		for _, route := range []string{"aws.secretsmanager.get", "aws.ssm.get", "gcp.secretmanager.get", "gcp.parametermanager.get"} {
			if !strings.Contains(line, "statekit exec "+route+" ") {
				continue
			}
			if _, duplicate := usage[route]; duplicate {
				t.Fatal("duplicate usage line for route " + route)
			}
			usage[route] = line
		}
	}
	for _, route := range []string{"aws.secretsmanager.get", "aws.ssm.get", "gcp.secretmanager.get", "gcp.parametermanager.get"} {
		if usage[route] == "" {
			t.Fatal("usage line missing for route " + route)
		}
	}
	for _, route := range []string{"gcp.secretmanager.get", "gcp.parametermanager.get"} {
		if !strings.Contains(usage[route], "[--version-id ID | --version-alias latest]") {
			t.Fatal("help does not advertise --version-alias latest as the only alias for GCP route " + route)
		}
		if strings.Contains(usage[route], "--version-alias ALIAS") {
			t.Fatal("help still advertises a free-form alias for GCP route " + route)
		}
	}
	if !strings.Contains(usage["aws.secretsmanager.get"], "[--version-id ID | --version-alias ALIAS]") {
		t.Fatal("help no longer advertises the free-form AWS Secrets Manager stage alias")
	}
	if strings.Contains(usage["aws.ssm.get"], "--version-alias") {
		t.Fatal("help advertises an alias for the SSM route, which is version-id only")
	}
}

func TestSecretRoutesRejectMismatchedExplicitSourceBeforeFetch(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{
			name: "secretsmanager-provider-mismatch",
			args: []string{"exec", "aws.secretsmanager.get", "--provider", "gcp", "--region", "us-east-1", "--resource", "db"},
		},
		{
			name: "secretsmanager-backend-mismatch",
			args: []string{"exec", "aws.secretsmanager.get", "--provider", "aws", "--backend", "ssm", "--region", "us-east-1", "--resource", "db"},
		},
		{
			name: "secretsmanager-uri-backend-mismatch",
			args: []string{"exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/ssm/us-east-1/db"},
		},
		{
			name: "secretsmanager-uri-provider-mismatch",
			args: []string{"exec", "aws.secretsmanager.get", "--source-uri", "secret://gcp/secretmanager/global/projects%2Fproject-123%2Fsecrets%2Fdb"},
		},
		{
			name: "secretsmanager-config-provider-mismatch",
			args: []string{"exec", "aws.secretsmanager.get", "--config", "provider: gcp\nregion: us-east-1\nresource: db\n"},
		},
		{
			name: "ssm-backend-mismatch",
			args: []string{"exec", "aws.ssm.get", "--backend", "secretsmanager", "--region", "us-east-1", "--resource", "/prod/key"},
		},
		{
			name: "ssm-uri-backend-mismatch",
			args: []string{"exec", "aws.ssm.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db"},
		},
		{
			name: "gcp-provider-mismatch",
			args: []string{"exec", "gcp.secretmanager.get", "--provider", "aws", "--region", "global", "--resource", "projects/project-123/secrets/db"},
		},
		{
			name: "gcp-backend-mismatch",
			args: []string{"exec", "gcp.secretmanager.get", "--backend", "ssm", "--region", "global", "--resource", "projects/project-123/secrets/db"},
		},
		{
			name: "gcp-uri-provider-mismatch",
			args: []string{"exec", "gcp.secretmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, calls, builds := newRouteProbeApp(t)
			code, stdout, stderr := captureCode(t, app, tc.args...)
			if code != ExitInvalidInput || stdout != "" || stderr != "statekit: invalid secret request\n" || *calls != 0 || *builds != 0 {
				t.Fatal("route/source mismatch was not rejected before fetch with the fixed value-free diagnostic")
			}
			if strings.Contains(stdout, routeMismatchCanary) || strings.Contains(stderr, routeMismatchCanary) {
				t.Fatal("mismatched route input value reached CLI output")
			}
		})
	}
}

// TestParameterManagerRouteRejectsMismatchedSourceBeforeFetch preserves the
// exact request/source validation semantics of the former parameter route:
// the URI form excludes every structured source field, the structured form
// requires all four, and only the param:// scheme is accepted. Provider or
// backend mismatches keep the dedicated unsupported-provider classification.
func TestParameterManagerRouteRejectsMismatchedSourceBeforeFetch(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{
			name: "uri-scheme-mismatch",
			args: []string{"--source-uri", "secret://gcp/parametermanager/global/projects%2Fproject-123%2Flocations%2Fglobal%2Fparameters%2Fconfig"},
			code: ExitInvalidInput,
		},
		{
			name: "mixed-uri-and-structured-field",
			args: []string{"--source-uri", "param://gcp/parametermanager/global/projects%2Fproject-123%2Flocations%2Fglobal%2Fparameters%2Fconfig", "--region", "global", "--resource", routeMismatchCanary},
			code: ExitInvalidInput,
		},
		{
			name: "provider-mismatch",
			args: []string{"--provider", "aws", "--backend", "parametermanager", "--region", "us-east-1", "--resource", "projects/project-123/locations/us-east-1/parameters/config"},
			code: ExitUnsupported,
		},
		{
			name: "backend-mismatch",
			args: []string{"--provider", "gcp", "--backend", "secretmanager", "--region", "global", "--resource", "projects/project-123/secrets/db"},
			code: ExitUnsupported,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, calls, builds := newRouteProbeApp(t)
			paramCalls := 0
			app.parameterFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
				paramCalls++
				return nil, nil
			}
			code, stdout, stderr := captureCode(t, app, append([]string{"exec", "gcp.parametermanager.get"}, tc.args...)...)
			if code != tc.code || stdout != "" || *calls != 0 || paramCalls != 0 || *builds != 0 {
				t.Fatal("parameter route source mismatch was not rejected before runtime and fetch")
			}
			if strings.Contains(stdout, routeMismatchCanary) || strings.Contains(stderr, routeMismatchCanary) {
				t.Fatal("mismatched parameter route input value reached CLI output")
			}
		})
	}
}

func TestSecretRoutesMalformedInvocationsDoNotReachGenericExec(t *testing.T) {
	for _, args := range [][]string{
		{"exec", "aws.secretsmanager.get"},
		{"exec", "aws.ssm.get", "--region", "us-east-1"},
		{"exec", "gcp.secretmanager.get", "--region", "global", "--resource", "projects/project-123/secrets/db", "--unknown-flag", routeMismatchCanary},
		{"exec", "gcp.parametermanager.get"},
	} {
		app, calls, builds := newRouteProbeApp(t)
		code, stdout, stderr := captureCode(t, app, args...)
		if code != ExitInvalidInput || stdout != "" || stderr != "statekit: invalid secret request\n" || *calls != 0 || *builds != 0 {
			t.Fatal("malformed route invocation fell through to generic exec or reached the fetcher")
		}
	}
}

// TestParameterManagerRouteRejectsSecretBackend keeps the parameter route
// from ever dispatching to a secret backend.
func TestParameterManagerRouteRejectsSecretBackend(t *testing.T) {
	app, _, builds := newRouteProbeApp(t)
	app.parameterFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		t.Error("gcp.parametermanager.get must not dispatch to a secret backend")
		return nil, nil
	}
	code, stdout, stderr := captureCode(t, app, "exec", "gcp.parametermanager.get", "--provider", "gcp", "--backend", "secretmanager", "--region", "global", "--resource", "projects/project-123/secrets/db")
	if code != ExitUnsupported || stdout != "" || *builds != 0 || strings.Contains(stderr, "project-123") {
		t.Fatal("parameter route secret-backend rejection changed after route registration")
	}
}

// TestHierarchicalRoutesDispatchToCorrectFetcher pins that each exact
// hierarchical provider.service.get route dispatches to the reader of its
// own contract — the secret reader for the three secret routes and the
// Parameter Manager reader for gcp.parametermanager.get — with the
// route-pinned provider and backend, and that neither the other reader
// nor the generic runtime is consulted.
func TestHierarchicalRoutesDispatchToCorrectFetcher(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      []string
		provider  string
		backend   string
		parameter bool
	}{
		{
			name:     "aws-secretsmanager",
			args:     []string{"exec", "aws.secretsmanager.get", "--region", "us-east-1", "--resource", "db"},
			provider: "aws", backend: "secretsmanager",
		},
		{
			name:     "aws-ssm",
			args:     []string{"exec", "aws.ssm.get", "--region", "us-east-1", "--resource", "/prod/key"},
			provider: "aws", backend: "ssm",
		},
		{
			name:     "gcp-secretmanager",
			args:     []string{"exec", "gcp.secretmanager.get", "--region", "global", "--resource", "projects/project-123/secrets/db"},
			provider: "gcp", backend: "secretmanager",
		},
		{
			name: "gcp-parametermanager",
			args: []string{"exec", "gcp.parametermanager.get", "--provider", "gcp", "--backend", "parametermanager", "--region", "global", "--resource", "projects/project-123/locations/global/parameters/config"},
			provider: "gcp", backend: "parametermanager", parameter: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.provider == "aws" && !cloudsecret.AWSAvailable() || tc.provider == "gcp" && !cloudsecret.GCPAvailable() {
				t.Skip("provider SDK is disabled in this build profile")
			}
			app, _, builds := newRouteProbeApp(t)
			secretCalls, parameterCalls := 0, 0
			app.secretFetch = func(_ context.Context, source cloudsecret.Source) ([]byte, error) {
				secretCalls++
				if source.Provider != tc.provider || source.Backend != tc.backend {
					t.Fatal("secret route did not pin the routed provider and backend")
				}
				return []byte("synthetic"), nil
			}
			app.parameterFetch = func(_ context.Context, source cloudsecret.Source) ([]byte, error) {
				parameterCalls++
				if source.Provider != tc.provider || source.Backend != tc.backend {
					t.Fatal("parameter route did not pin the routed provider and backend")
				}
				return []byte("synthetic"), nil
			}
			code, stdout, stderr := captureCode(t, app, tc.args...)
			if code != ExitOK || stdout != "synthetic" || stderr != "" || *builds != 0 {
				t.Fatal("hierarchical route did not dispatch to its injected reader")
			}
			if tc.parameter {
				if secretCalls != 0 || parameterCalls != 1 {
					t.Fatal("parameter route did not dispatch to the parameter reader")
				}
			} else if secretCalls != 1 || parameterCalls != 0 {
				t.Fatal("secret route did not dispatch to the secret reader")
			}
		})
	}
}

// TestRetiredOneDotCommandsRejectedBeforeRuntimeInputAndFetch pins the
// retirement of the former one-dot route tokens: they match no live route,
// receive no alias, and are rejected before any input channel is read,
// runtime is built, credential is consulted, or fetch runs. The diagnostic
// names only the fixed retired token, never a caller-supplied value.
func TestRetiredOneDotCommandsRejectedBeforeRuntimeInputAndFetch(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		wantStderr string
	}{
		{
			name:       "aws-secretsmanager",
			args:       []string{"exec", "aws.secretsmanager_get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db"},
			wantStderr: "statekit: retired command \"aws.secretsmanager_get\"; use the <provider>.<service>.get form\n",
		},
		{
			name:       "aws-ssm",
			args:       []string{"exec", "aws.ssm_get", "--region", "us-east-1", "--resource", "/prod/key"},
			wantStderr: "statekit: retired command \"aws.ssm_get\"; use the <provider>.<service>.get form\n",
		},
		{
			name:       "gcp-secretmanager",
			args:       []string{"exec", "gcp.secretmanager_get", "--region", "global", "--resource", "projects/project-123/secrets/db"},
			wantStderr: "statekit: retired command \"gcp.secretmanager_get\"; use the <provider>.<service>.get form\n",
		},
		{
			name:       "gcp-parametermanager",
			args:       []string{"exec", "gcp.parametermanager_get", "--provider", "gcp", "--backend", "parametermanager", "--region", "global", "--resource", "projects/project-123/locations/global/parameters/config"},
			wantStderr: "statekit: retired command \"gcp.parametermanager_get\"; use the <provider>.<service>.get form\n",
		},
		{
			name:       "bare-command",
			args:       []string{"exec", "gcp.parametermanager_get"},
			wantStderr: "statekit: retired command \"gcp.parametermanager_get\"; use the <provider>.<service>.get form\n",
		},
		{
			name:       "after-config-channel-prefix",
			args:       []string{"exec", "--config", "region: us-east-1\nresource: db\n", "aws.secretsmanager_get", "--region", "us-east-1", "--resource", "db"},
			wantStderr: "statekit: retired command \"aws.secretsmanager_get\"; use the <provider>.<service>.get form\n",
		},
		{
			name:       "after-file-channel-prefix",
			args:       []string{"exec", "--file", "/nonexistent/statekit-route-test", "aws.ssm_get", "--region", "us-east-1", "--resource", "/prod/key"},
			wantStderr: "statekit: retired command \"aws.ssm_get\"; use the <provider>.<service>.get form\n",
		},
		{
			name:       "with-stderr-sink",
			args:       []string{"exec", "aws.ssm_get", "--sink", "stderr", "--region", "us-east-1", "--resource", "/prod/key"},
			wantStderr: "statekit: retired command \"aws.ssm_get\"; use the <provider>.<service>.get form\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, calls, builds := newRouteProbeApp(t)
			paramCalls := 0
			app.parameterFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
				paramCalls++
				return nil, nil
			}
			code, stdout, stderr := captureCode(t, app, tc.args...)
			if code != ExitInvalidInput || stdout != "" || *calls != 0 || paramCalls != 0 || *builds != 0 {
				t.Fatal("retired one-dot command was not rejected before runtime, input, and fetch")
			}
			if stderr != tc.wantStderr {
				t.Fatal("retired one-dot command did not produce the fixed retirement diagnostic")
			}
		})
	}
}

// TestRetiredCommandValuesNeverReachOutput pins that a retired one-dot
// command is rejected on its fixed command token alone, so raw caller
// values in the remaining arguments never reach stdout or stderr.
func TestRetiredCommandValuesNeverReachOutput(t *testing.T) {
	app, calls, builds := newRouteProbeApp(t)
	paramCalls := 0
	app.parameterFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		paramCalls++
		return nil, nil
	}
	code, stdout, stderr := captureCode(t, app, "exec", "aws.ssm_get", "--region", routeMismatchCanary, "--resource", routeMismatchCanary, "--target", routeMismatchCanary)
	if code != ExitInvalidInput || stdout != "" || *calls != 0 || paramCalls != 0 || *builds != 0 {
		t.Fatal("retired one-dot command with raw values was not rejected before runtime and fetch")
	}
	if strings.Contains(stdout, routeMismatchCanary) || strings.Contains(stderr, routeMismatchCanary) {
		t.Fatal("retired command input value reached CLI output")
	}
}

// TestUnknownThreeSegmentPathsDoNotReachGenericExec pins that the
// hierarchical form is a fixed exact-route table, not a generalized
// nested grammar: unknown three-segment targets fail ordinary
// <module>.<function> parsing before the runtime is built or any module
// resolves.
func TestUnknownThreeSegmentPathsDoNotReachGenericExec(t *testing.T) {
	for _, args := range [][]string{
		{"exec", "aws.secretsmanager.get.extra", "--region", "us-east-1", "--resource", "db"},
		{"exec", "aws.secretsmanager.list", "--region", "us-east-1", "--resource", "db"},
		{"exec", "aws.secretsmanager.getter", "--region", "us-east-1", "--resource", "db"},
		{"exec", "gcp.secretmanager.access", "--region", "global", "--resource", "projects/project-123/secrets/db"},
		{"exec", "gcp.parametermanager.get.latest", "--provider", "gcp", "--backend", "parametermanager", "--region", "global", "--resource", "projects/project-123/locations/global/parameters/config"},
	} {
		app, calls, builds := newRouteProbeApp(t)
		code, stdout, stderr := captureCode(t, app, args...)
		if code != ExitInvalidInput || stdout != "" || *calls != 0 || *builds != 0 {
			t.Fatal("unknown three-segment path reached generic exec or built the runtime")
		}
		if !strings.Contains(stderr, "function must be <module>.<function>") {
			t.Fatal("unknown three-segment path did not fail with the ordinary parse diagnostic")
		}
	}
}

// TestSensitiveInvocationClassificationUsesHierarchicalRoutesOnly pins
// panic/sensitive-invocation classification: only the exact hierarchical
// routes classify an invocation as a sensitive secret operation. Retired
// one-dot tokens, unknown three-segment paths, the state namespace, and
// generic cloud.* targets never do.
func TestSensitiveInvocationClassificationUsesHierarchicalRoutesOnly(t *testing.T) {
	args, ok := secretInvocationArgs([]string{"exec", "aws.secretsmanager.get", "--sink", "stderr", "--region", "us-east-1", "--resource", "db"})
	if !ok || len(args) == 0 {
		t.Fatal("hierarchical secret route was not classified as a sensitive invocation")
	}
	if _, ok := secretInvocationArgs([]string{"exec", "gcp.parametermanager.get", "--provider", "gcp"}); !ok {
		t.Fatal("hierarchical parameter route was not classified as a sensitive invocation")
	}
	for _, argv := range [][]string{
		{"exec", "aws.secretsmanager_get", "--sink", "stderr", "--region", "us-east-1", "--resource", "db"},
		{"exec", "aws.ssm_get", "--region", "us-east-1", "--resource", "/prod/key"},
		{"exec", "gcp.secretmanager_get", "--region", "global", "--resource", "projects/project-123/secrets/db"},
		{"exec", "gcp.parametermanager_get"},
		{"exec", "aws.secretsmanager.getter", "--region", "us-east-1", "--resource", "db"},
		{"exec", "cloud.secret.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db"},
		{"state", "aws.secretsmanager.get", "--region", "us-east-1", "--resource", "db"},
	} {
		if _, ok := secretInvocationArgs(argv); ok {
			t.Fatalf("non-route invocation %q was classified as a sensitive secret operation", argv[1])
		}
	}
}
