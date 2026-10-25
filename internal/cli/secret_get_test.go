//go:build !statekit_no_sdk_aws && !statekit_no_sdks

package cli

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/cloudsecret"
)

const secretCanary = "SYNTHETIC_SECRET_CANARY_NOT_FOR_LOGS"

func secretTestApp(fetch secretFetchFunc) *App {
	app := NewApp("test-version", nil)
	app.secretFetch = fetch
	return app
}

func TestSecretManagerGetRouteDeliversByteExactPayload(t *testing.T) {
	calls := 0
	app := secretTestApp(func(_ context.Context, source cloudsecret.Source) ([]byte, error) {
		calls++
		if source.Provider != "aws" || source.Backend != "secretsmanager" || source.Region != "us-east-1" || source.Resource != "db" {
			t.Fatal("secretsmanager route passed an unexpected source")
		}
		return []byte(secretCanary), nil
	})
	code, stdout, stderr := captureCode(t, app, "exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db")
	if code != ExitOK || stdout != secretCanary || stderr != "" || calls != 1 {
		t.Fatal("secretsmanager route did not deliver exactly one byte-exact payload")
	}
	code, stdout, stderr = captureCode(t, app, "exec", "aws.secretsmanager.get", "--region", "us-east-1", "--resource", "db")
	if code != ExitOK || stdout != secretCanary || stderr != "" || calls != 2 {
		t.Fatal("secretsmanager route did not infer provider and backend from structured input")
	}
	code, stdout, stderr = captureCode(t, app, "exec", "aws.secretsmanager.get", "--provider", "aws", "--backend", "secretsmanager", "--region", "us-east-1", "--resource", "db")
	if code != ExitOK || stdout != secretCanary || stderr != "" || calls != 3 {
		t.Fatal("secretsmanager route did not accept explicit source fields matching the route")
	}
}

func TestSecretManagerGetRoutePassesVersionAliasToFetcher(t *testing.T) {
	app := secretTestApp(func(_ context.Context, source cloudsecret.Source) ([]byte, error) {
		if source.Provider != "aws" || source.Backend != "secretsmanager" || source.Region != "us-east-1" || source.Resource != "db" || source.VersionID != "" || source.VersionAlias != "AWSCURRENT" {
			t.Fatal("secretsmanager route did not pass --version-alias as the source version alias")
		}
		return []byte(secretCanary), nil
	})
	code, stdout, stderr := captureCode(t, app, "exec", "aws.secretsmanager.get", "--region", "us-east-1", "--resource", "db", "--version-alias", "AWSCURRENT")
	if code != ExitOK || stdout != secretCanary || stderr != "" {
		t.Fatal("secretsmanager route did not deliver the byte-exact payload for the version-alias request")
	}
}

func TestSSMGetRouteAcceptsOneCompleteStructuredSource(t *testing.T) {
	calls := 0
	app := secretTestApp(func(_ context.Context, source cloudsecret.Source) ([]byte, error) {
		calls++
		if source.Provider != "aws" || source.Backend != "ssm" || source.Region != "us-east-1" || source.Resource != "/prod/key" || source.VersionID != "7" {
			t.Fatal("structured source fields were not normalized")
		}
		return []byte("synthetic"), nil
	})
	code, stdout, stderr := captureCode(t, app, "exec", "aws.ssm.get", "--config", "region: us-east-1\nresource: /prod/key\nversion_id: '7'\n")
	if code != ExitOK || stdout != "synthetic" || stderr != "" || calls != 1 {
		t.Fatal("complete structured source was not accepted")
	}
	calls = 0
	code, stdout, stderr = captureCode(t, app, "exec", "aws.ssm.get", "--config", `{"region":"us-east-1","region":"us-east-1","resource":"/prod/key"}`)
	if code != ExitInvalidInput || stdout != "" || strings.Contains(stderr, secretCanary) || calls != 0 {
		t.Fatal("duplicate structured source field reached the reader")
	}
	code, stdout, stderr = captureCode(t, app, "exec", "aws.ssm.get", "--config", `{"source_uri":"secret://aws/ssm/us-east-1/%2Fprod%2Fkey","region":"us-east-1","resource":"/prod/key"}`)
	if code != ExitInvalidInput || stdout != "" || stderr == "" || calls != 0 {
		t.Fatal("URI and structured source fields were accepted together")
	}
	app.secretFetch = func(_ context.Context, source cloudsecret.Source) ([]byte, error) {
		calls++
		if source.Provider != "aws" || source.Backend != "ssm" || source.Region != "us-east-1" || source.Resource != "/prod/key" || source.VersionID != "" || source.VersionAlias != "" {
			t.Fatal("SSM URI request did not map to the route-pinned source")
		}
		return []byte("synthetic"), nil
	}
	code, stdout, stderr = captureCode(t, app, "exec", "aws.ssm.get", "--source-uri", "secret://aws/ssm/us-east-1/%2Fprod%2Fkey")
	if code != ExitOK || stdout != "synthetic" || stderr != "" || calls != 1 {
		t.Fatal("percent-encoded SSM URI was not accepted by the route")
	}
}

func TestSecretRoutesValidateBeforeFetchAndFileSinkIsDeferred(t *testing.T) {
	calls := 0
	app := secretTestApp(func(context.Context, cloudsecret.Source) ([]byte, error) {
		calls++
		return []byte(secretCanary), nil
	})
	for _, args := range [][]string{
		{"exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db", "--source-uri", "secret://aws/secretsmanager/us-east-1/other"},
		{"exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db", "--unknown", secretCanary},
		{"exec", "aws.ssm.get", "--region", "us-east-1"},
		{"exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db", "--format", "json", "--key-path", "/bad~2pointer"},
		{"exec", "aws.ssm.get", "--region", "us-east-1", "--resource", "/prod/key", "--version-id", "+1"},
		{"exec", "aws.secretsmanager.get", "--region", "us-east-1", "--resource", "db", "--version-id", "too-short"},
	} {
		code, stdout, stderr := captureCode(t, app, args...)
		if code != ExitInvalidInput || stdout != "" || strings.Contains(stderr, secretCanary) || calls != 0 {
			t.Fatal("invalid secret request reached the reader or leaked an input value")
		}
	}
	code, stdout, stderr := captureCode(t, app, "exec", "aws.secretsmanager.get", "--region", "us-east-1", "--resource", "db", "--sink", "bogus")
	if code != ExitUnsupported || stdout != "" || stderr == "" || calls != 0 {
		t.Fatal("unsupported sink was not rejected before provider retrieval")
	}
	path := filepath.Join(t.TempDir(), "secret-output")
	code, stdout, stderr = captureCode(t, app, "exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db", "--sink", "file", "--target", path)
	if code != ExitUnsupported || stdout != "" || !strings.Contains(stderr, "file sink deferred by policy") || calls != 0 {
		t.Fatal("file sink was not rejected before retrieval with a clear policy diagnostic")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("deferred file sink created an output file")
	}
}

func TestSecretRouteAuthenticatesUDSSinkBeforeFetch(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("peer credential enforcement is enabled on Linux only")
	}
	calls := 0
	app := secretTestApp(func(context.Context, cloudsecret.Source) ([]byte, error) {
		calls++
		return []byte(secretCanary), nil
	})
	code, stdout, stderr := captureCode(t, app, "exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db", "--sink", "unix", "--target", filepath.Join(t.TempDir(), "missing.sock"))
	if code != ExitFailed || stdout != "" || calls != 0 || !strings.Contains(stderr, "secret sink failed") {
		t.Fatal("UDS sink failure was not detected before provider retrieval")
	}
}

func TestClosedAndReadOnlyStdoutStderrFailBeforeFetch(t *testing.T) {
	switch goruntime.GOOS {
	case "linux", "darwin", "dragonfly", "freebsd", "netbsd":
	default:
		t.Skip("access-mode preflight is enabled on Linux and supported BSD targets")
	}
	for _, sink := range []string{"stdout", "stderr"} {
		for _, descriptorMode := range []string{"closed", "read-only"} {
			t.Run(sink+"/"+descriptorMode, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "descriptor-target")
				var descriptor *os.File
				if descriptorMode == "closed" {
					var err error
					descriptor, err = os.Create(path)
					if err != nil {
						t.Fatal("closed-descriptor setup failed")
					}
					if err := descriptor.Close(); err != nil {
						t.Fatal("closed-descriptor setup failed")
					}
				} else {
					seed, err := os.Create(path)
					if err != nil {
						t.Fatal("read-only-descriptor setup failed")
					}
					_ = seed.Close()
					descriptor, err = os.Open(path)
					if err != nil {
						t.Fatal("read-only-descriptor setup failed")
					}
					defer descriptor.Close()
				}
				diagnostic, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal("diagnostic descriptor setup failed")
				}
				defer diagnostic.Close()

				calls := 0
				app := secretTestApp(func(context.Context, cloudsecret.Source) ([]byte, error) {
					calls++
					return []byte(secretCanary), nil
				})
				stdout, stderr := diagnostic, diagnostic
				if sink == "stdout" {
					stdout = descriptor
				} else {
					stderr = descriptor
				}
				code := runWithStdio(stdout, stderr, func() int {
					return app.Run([]string{"exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db", "--sink", sink})
				})
				if code != ExitFailed || calls != 0 {
					t.Fatal("invalid selected descriptor reached the secret fetch")
				}
				contents, err := os.ReadFile(path)
				if err != nil || len(contents) != 0 {
					t.Fatal("descriptor preflight wrote payload bytes")
				}
			})
		}
	}
}

func runWithStdio(stdout, stderr *os.File, run func() int) int {
	oldStdout, oldStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdout, stderr
	defer func() {
		os.Stdout, os.Stderr = oldStdout, oldStderr
	}()
	return run()
}

func TestSecretRouteStderrSinkSuppressesDiagnostics(t *testing.T) {
	app := secretTestApp(func(context.Context, cloudsecret.Source) ([]byte, error) {
		return []byte(secretCanary), nil
	})
	code, stdout, stderr := captureCode(t, app, "exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db", "--sink", "stderr")
	if code != ExitOK || stdout != "" || stderr != secretCanary {
		t.Fatal("stderr sink was not payload-only")
	}
	app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		return nil, errors.New(secretCanary)
	}
	code, stdout, stderr = captureCode(t, app, "exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db", "--sink", "stderr")
	if code != ExitFailed || stdout != "" || stderr != "" {
		t.Fatal("stderr-sink failure emitted diagnostics to a data descriptor")
	}
	app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		panic(secretCanary)
	}
	code, stdout, stderr = captureCode(t, app, "exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db", "--sink", "stderr")
	if code != ExitFailed || stdout != "" || stderr != "" {
		t.Fatal("stderr-sink panic leaked a diagnostic")
	}
}

func TestSecretRouteMapsProviderErrorsAndPanicsWithoutValues(t *testing.T) {
	app := secretTestApp(func(context.Context, cloudsecret.Source) ([]byte, error) {
		return nil, errors.New(secretCanary)
	})
	args := []string{"exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db"}
	code, stdout, stderr := captureCode(t, app, args...)
	if code != ExitFailed || stdout != "" || stderr == "" || strings.Contains(stderr, secretCanary) {
		t.Fatal("provider error leaked through ordinary CLI output")
	}
	app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		panic(secretCanary)
	}
	code, stdout, stderr = captureCode(t, app, args...)
	if code != ExitFailed || stdout != "" || stderr == "" || strings.Contains(stderr, secretCanary) {
		t.Fatal("panic value leaked through ordinary CLI output")
	}
	app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		return []byte(secretCanary), nil
	}
	code, stdout, stderr = captureCode(t, app, append(args, "--format", "json")...)
	if code != ExitFailed || stdout != "" || stderr == "" || strings.Contains(stderr, secretCanary) {
		t.Fatal("provider payload parser failure leaked data or used the invalid-request exit code")
	}
}

func TestSecretRouteFormatFlagUsesDedicatedSerializer(t *testing.T) {
	app := secretTestApp(func(context.Context, cloudsecret.Source) ([]byte, error) {
		return []byte(`{"value":"synthetic"}`), nil
	})
	code, stdout, stderr := captureCode(t, app, "exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db", "--format", "json", "--key-path", "/value")
	if code != ExitOK || stdout != `"synthetic"` || stderr != "" {
		t.Fatal("--format json did not use the dedicated structured serializer")
	}
	code, stdout, stderr = captureCode(t, app, "exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db", "--format", "yaml", "--key-path", "/value")
	if code != ExitOK || stdout != "synthetic\n" || stderr != "" {
		t.Fatal("--format yaml did not use the dedicated structured serializer")
	}
	app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		return []byte("plain"), nil
	}
	code, stdout, stderr = captureCode(t, app, "exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db", "--format", "text")
	if code != ExitOK || stdout != "plain" || stderr != "" {
		t.Fatal("--format text did not preserve the dedicated byte contract")
	}
}

func TestSecretRouteRejectsGenericOutputAliasesBeforeFetchAndSink(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("UDS connection preflight assertion is enabled on Linux")
	}
	aliases := []struct {
		name  string
		flags []string
	}{
		{name: "short separated", flags: []string{"-o", "text"}},
		{name: "short inline", flags: []string{"-o=text"}},
		{name: "short inline json", flags: []string{"-o=json"}},
		{name: "long separated", flags: []string{"--output", "text"}},
		{name: "long inline", flags: []string{"--output=text"}},
		{name: "long inline json", flags: []string{"--output=json"}},
	}
	for _, alias := range aliases {
		t.Run(alias.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "consumer.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal("synthetic UDS listener setup failed")
			}
			defer listener.Close()
			if err := listener.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
				t.Fatal("synthetic UDS listener deadline setup failed")
			}

			calls := 0
			app := secretTestApp(func(context.Context, cloudsecret.Source) ([]byte, error) {
				calls++
				return []byte(secretCanary), nil
			})
			args := []string{
				"exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/" + secretCanary,
				"--sink", "unix", "--target", path,
			}
			args = append(args, alias.flags...)
			code, stdout, stderr := captureCode(t, app, args...)
			if code != ExitInvalidInput || stdout != "" || strings.Contains(stdout, secretCanary) || strings.Contains(stderr, secretCanary) || calls != 0 {
				t.Fatal("generic output alias was not rejected before fetch or sink activity")
			}
			connection, err := listener.AcceptUnix()
			if err == nil {
				_ = connection.Close()
				t.Fatal("generic output alias opened the selected UDS sink")
			}
			if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
				t.Fatal("UDS listener did not time out after output-alias rejection")
			}
		})
	}
}

func TestSecretRouteRejectsGenericOutputAliasesOnStdout(t *testing.T) {
	aliases := [][]string{
		{"-o", "text"},
		{"-o=text"},
		{"-o=json"},
		{"--output", "text"},
		{"--output=text"},
		{"--output=json"},
	}
	for _, flags := range aliases {
		calls := 0
		app := secretTestApp(func(context.Context, cloudsecret.Source) ([]byte, error) {
			calls++
			return []byte(secretCanary), nil
		})
		args := []string{"exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/" + secretCanary}
		args = append(args, flags...)
		code, stdout, stderr := captureCode(t, app, args...)
		if code != ExitInvalidInput || stdout != "" || stderr != "statekit: invalid secret request\n" || strings.Contains(stdout, secretCanary) || strings.Contains(stderr, secretCanary) || calls != 0 {
			t.Fatal("generic output alias was not rejected with a fixed value-free diagnostic")
		}
	}
}

func TestSecretRouteRejectsGenericOutputAliasesWithStderrSink(t *testing.T) {
	aliases := []struct {
		name  string
		flags []string
	}{
		{name: "short separated", flags: []string{"-o", "text"}},
		{name: "short inline", flags: []string{"-o=text"}},
		{name: "short inline json", flags: []string{"-o=json"}},
		{name: "long separated", flags: []string{"--output", "text"}},
		{name: "long inline", flags: []string{"--output=text"}},
		{name: "long inline json", flags: []string{"--output=json"}},
	}
	for _, alias := range aliases {
		for _, sinkFirst := range []bool{false, true} {
			order := "alias-before-sink"
			if sinkFirst {
				order = "sink-before-alias"
			}
			t.Run(alias.name+"/"+order, func(t *testing.T) {
				calls := 0
				app := secretTestApp(func(context.Context, cloudsecret.Source) ([]byte, error) {
					calls++
					return []byte(secretCanary), nil
				})
				args := []string{"exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/" + secretCanary}
				if sinkFirst {
					args = append(args, "--sink", "stderr")
				}
				args = append(args, alias.flags...)
				if !sinkFirst {
					args = append(args, "--sink", "stderr")
				}
				code, stdout, stderr := captureCode(t, app, args...)
				if code != ExitInvalidInput || stdout != "" || stderr != "" || strings.Contains(stdout, secretCanary) || strings.Contains(stderr, secretCanary) || calls != 0 {
					t.Fatal("generic output alias did not fail silently for the stderr payload sink")
				}
			})
		}
	}
}

func TestSecretRouteGenericOutputAliasBeforeStderrSinkDoesNotPreflight(t *testing.T) {
	path := filepath.Join(t.TempDir(), "closed-stderr")
	closed, err := os.Create(path)
	if err != nil {
		t.Fatal("closed stderr descriptor setup failed")
	}
	if err := closed.Close(); err != nil {
		t.Fatal("closed stderr descriptor setup failed")
	}
	diagnostic, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal("diagnostic descriptor setup failed")
	}
	defer diagnostic.Close()

	calls := 0
	app := secretTestApp(func(context.Context, cloudsecret.Source) ([]byte, error) {
		calls++
		return []byte(secretCanary), nil
	})
	code := runWithStdio(diagnostic, closed, func() int {
		return app.Run([]string{
			"exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/" + secretCanary,
			"-o", "text", "--sink", "stderr",
		})
	})
	if code != ExitInvalidInput || calls != 0 {
		t.Fatal("generic output alias did not fail before stderr preflight or fetch")
	}
}

func TestOrdinaryExecOutputSerializerRemainsUnchanged(t *testing.T) {
	code, stdout, stderr := runApp(t, "exec", "test.echo", "--text", "ordinary", "-o", "json")
	if code != ExitOK || stdout != `"ordinary"`+"\n" || stderr != "" {
		t.Fatal("ordinary exec output serializer changed")
	}
}
