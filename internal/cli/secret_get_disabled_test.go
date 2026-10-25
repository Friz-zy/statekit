//go:build statekit_no_sdk_aws || statekit_no_sdks

package cli

import (
	"context"
	"net"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/cloudsecret"
)

const disabledSourceMarker = "secret-marker-disabled-test"

func TestDisabledAWSRoutesValidateInputThenRejectBeforeInjectedFetch(t *testing.T) {
	calls := 0
	app := NewApp("test-version", nil)
	app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		calls++
		return []byte(disabledSourceMarker), nil
	}
	for _, sourceArgs := range [][]string{
		{"exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/" + disabledSourceMarker},
		{"exec", "aws.ssm.get", "--source-uri", "secret://aws/ssm/us-east-1/" + disabledSourceMarker},
	} {
		valid := append(append([]string{}, sourceArgs...), "--format", "text")
		code, stdout, stderr := captureCode(t, app, valid...)
		if code != ExitUnsupported || stdout != "" || (stderr != "" && stderr != "statekit: unsupported secret provider, service, or sink\n") || strings.Contains(stdout, disabledSourceMarker) || strings.Contains(stderr, disabledSourceMarker) || calls != 0 {
			t.Fatal("disabled AWS route reached the injected fetcher")
		}
		stderrSink := append(append([]string{}, valid...), "--sink", "stderr")
		code, stdout, stderr = captureCode(t, app, stderrSink...)
		if code != ExitUnsupported || stdout != "" || stderr != "" || strings.Contains(stdout, disabledSourceMarker) || strings.Contains(stderr, disabledSourceMarker) || calls != 0 {
			t.Fatal("disabled stderr-sink request did not suppress diagnostics or stop the injected fetch")
		}
		for _, outputFlags := range [][]string{
			{"-o", "text"},
			{"-o=text"},
			{"-o=json"},
			{"--output", "text"},
			{"--output=text"},
			{"--output=json"},
		} {
			args := append(append([]string{}, sourceArgs...), outputFlags...)
			code, stdout, stderr = captureCode(t, app, args...)
			if code != ExitInvalidInput || stdout != "" || stderr != "statekit: invalid secret request\n" || strings.Contains(stdout, disabledSourceMarker) || strings.Contains(stderr, disabledSourceMarker) || calls != 0 {
				t.Fatal("disabled default-stdout alias rejection was not fixed and value-free")
			}
		}
		invalidFormat := append(append([]string{}, sourceArgs...), "--format", "invalid")
		code, stdout, stderr = captureCode(t, app, invalidFormat...)
		if code != ExitInvalidInput || stdout != "" || stderr == "" || strings.Contains(stderr, disabledSourceMarker) || calls != 0 {
			t.Fatal("invalid format did not retain invalid-input precedence in the disabled build")
		}
		invalidSource := append(append([]string{}, sourceArgs[:2]...), "--source-uri", "not-a-secret-uri", "--format", "json")
		code, stdout, stderr = captureCode(t, app, invalidSource...)
		if code != ExitInvalidInput || stdout != "" || stderr == "" || strings.Contains(stderr, disabledSourceMarker) || calls != 0 {
			t.Fatal("invalid source did not retain invalid-input precedence in the disabled build")
		}
		invalidUDS := append(valid, "--sink", "unix", "--target", "relative.sock")
		code, stdout, stderr = captureCode(t, app, invalidUDS...)
		if code != ExitInvalidInput || stdout != "" || stderr == "" || strings.Contains(stderr, disabledSourceMarker) || calls != 0 {
			t.Fatal("invalid UDS target did not retain invalid-input precedence in the disabled build")
		}
		fileTarget := filepath.Join(t.TempDir(), "not-written")
		fileSink := append(valid, "--sink", "file", "--target", fileTarget)
		code, stdout, stderr = captureCode(t, app, fileSink...)
		if code != ExitUnsupported || stdout != "" || !strings.Contains(stderr, "file sink deferred by policy") || strings.Contains(stderr, disabledSourceMarker) || calls != 0 {
			t.Fatal("deferred file sink did not remain unsupported before fetch in the disabled build")
		}
		if _, err := os.Stat(fileTarget); !os.IsNotExist(err) {
			t.Fatal("disabled file-sink request created an output file")
		}
	}
	code, stdout, stderr := runApp(t, "exec", "test.echo", "--text", "ordinary", "-o", "json")
	if code != ExitOK || stdout != `"ordinary"`+"\n" || stderr != "" {
		t.Fatal("ordinary exec output serialization changed in the disabled build")
	}
}

func TestDisabledAWSRouteRejectsGenericOutputAliasesBeforeFetchOrSink(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("UDS connection check is enabled on Linux")
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
			app := NewApp("test-version", nil)
			app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
				calls++
				return []byte(disabledSourceMarker), nil
			}
			args := []string{
				"exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/" + disabledSourceMarker,
				"--sink", "unix", "--target", path,
			}
			args = append(args, alias.flags...)
			code, stdout, stderr := captureCode(t, app, args...)
			if code != ExitInvalidInput || stdout != "" || strings.Contains(stdout, disabledSourceMarker) || strings.Contains(stderr, disabledSourceMarker) || calls != 0 {
				t.Fatal("generic output alias was not rejected before fetch or sink activity")
			}
			connection, err := listener.AcceptUnix()
			if err == nil {
				_ = connection.Close()
				t.Fatal("generic output alias opened the UDS sink")
			}
			if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
				t.Fatal("UDS listener did not time out after output-alias rejection")
			}
		})
	}
}

func TestDisabledAWSRouteRejectsGenericOutputAliasesWithStderrSink(t *testing.T) {
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
				app := NewApp("test-version", nil)
				app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
					calls++
					return []byte(disabledSourceMarker), nil
				}
				args := []string{"exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/" + disabledSourceMarker}
				if sinkFirst {
					args = append(args, "--sink", "stderr")
				}
				args = append(args, alias.flags...)
				if !sinkFirst {
					args = append(args, "--sink", "stderr")
				}
				code, stdout, stderr := captureCode(t, app, args...)
				if code != ExitInvalidInput || stdout != "" || stderr != "" || strings.Contains(stdout, disabledSourceMarker) || strings.Contains(stderr, disabledSourceMarker) || calls != 0 {
					t.Fatal("generic output alias did not fail silently in the disabled stderr-sink build")
				}
			})
		}
	}
}

func TestDisabledAWSRouteDoesNotRunSelectedStdioPreflight(t *testing.T) {
	for _, sink := range []string{"stdout", "stderr"} {
		t.Run(sink, func(t *testing.T) {
			closed, err := os.CreateTemp(t.TempDir(), "closed-descriptor-")
			if err != nil {
				t.Fatal("synthetic closed descriptor setup failed")
			}
			path := closed.Name()
			if err := closed.Close(); err != nil {
				t.Fatal("synthetic closed descriptor setup failed")
			}
			diagnostic, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal("diagnostic descriptor setup failed")
			}
			defer diagnostic.Close()

			calls := 0
			app := NewApp("test-version", nil)
			app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
				calls++
				return []byte("synthetic"), nil
			}
			stdout, stderr := diagnostic, diagnostic
			if sink == "stdout" {
				stdout = closed
			} else {
				stderr = closed
			}
			code := runDisabledWithStdio(stdout, stderr, func() int {
				return app.Run([]string{"exec", "aws.secretsmanager.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db", "--sink", sink})
			})
			if code != ExitUnsupported || calls != 0 {
				t.Fatal("disabled AWS route reached fetch or selected-descriptor preflight")
			}
			contents, err := os.ReadFile(path)
			if err != nil || len(contents) != 0 || strings.Contains(string(contents), "synthetic") {
				t.Fatal("disabled AWS route wrote data to the selected descriptor")
			}
		})
	}
}

func runDisabledWithStdio(stdout, stderr *os.File, run func() int) int {
	oldStdout, oldStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdout, stderr
	defer func() {
		os.Stdout, os.Stderr = oldStdout, oldStderr
	}()
	return run()
}
