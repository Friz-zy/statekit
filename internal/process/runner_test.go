package process

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRunEcho(t *testing.T) {
	res := NewRunner().Run(context.Background(), Command{
		Name: "echo", Args: []string{"hello"},
	})
	if !res.OK() || res.ExitCode != 0 {
		t.Fatalf("echo failed: %+v", res)
	}
	if strings.TrimSpace(string(res.Stdout)) != "hello" {
		t.Fatalf("stdout = %q", string(res.Stdout))
	}
}

func TestNonZeroExitIsDataNotError(t *testing.T) {
	res := NewRunner().Run(context.Background(), Command{
		Name: "sh", Args: []string{"-c", "exit 7"},
	})
	if res.Err != nil {
		t.Fatalf("non-zero exit must not set Err: %v", res.Err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7", res.ExitCode)
	}
	if res.OK() {
		t.Fatal("OK must be false for non-zero exit")
	}
}

func TestStdinAndStderrCapture(t *testing.T) {
	res := NewRunner().Run(context.Background(), Command{
		Name:  "cat",
		Stdin: []byte("piped-data"),
	})
	if !res.OK() || string(res.Stdout) != "piped-data" {
		t.Fatalf("stdin piping broken: %+v", res)
	}

	res = NewRunner().Run(context.Background(), Command{
		Name: "sh", Args: []string{"-c", "echo oops 1>&2; exit 1"},
	})
	if string(res.Stderr) != "oops\n" {
		t.Fatalf("stderr capture = %q", string(res.Stderr))
	}
}

func TestTimeout(t *testing.T) {
	res := NewRunner().Run(context.Background(), Command{
		Name: "sleep", Args: []string{"5"},
		Timeout: 100 * time.Millisecond,
	})
	if res.Err == nil || !strings.Contains(res.Err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", res.Err)
	}
	if res.Duration > time.Second {
		t.Fatalf("timeout did not fire early enough: %s", res.Duration)
	}
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	res := NewRunner().Run(ctx, Command{Name: "sleep", Args: []string{"5"}})
	if res.Err == nil || !errors.Is(res.Err, context.Canceled) && !strings.Contains(res.Err.Error(), "canceled") {
		t.Fatalf("expected cancellation error, got %v", res.Err)
	}
}

func TestRedaction(t *testing.T) {
	res := NewRunner().Run(context.Background(), Command{
		Name:   "echo",
		Args:   []string{"token=supersecret"},
		Redact: []string{"supersecret"},
	})
	if !res.OK() || strings.Contains(string(res.Stdout), "supersecret") {
		t.Fatalf("output leaked secret: %q (err %v)", string(res.Stdout), res.Err)
	}
	if !strings.Contains(string(res.Stdout), RedactedPlaceholder) {
		t.Fatalf("placeholder missing in output %q", string(res.Stdout))
	}
	rendered := (Command{Name: "echo", Args: []string{"token=supersecret"}, Redact: []string{"supersecret"}}).RedactedString()
	if strings.Contains(rendered, "supersecret") {
		t.Fatal("rendered command leaked secret")
	}
	if !strings.Contains(rendered, RedactedPlaceholder) {
		t.Fatalf("placeholder missing in %q", rendered)
	}
}

func TestShellRequiresExplicitOptIn(t *testing.T) {
	res := NewRunner().Run(context.Background(), Command{
		Name: "echo hi && echo injected",
	})
	if res.Err == nil {
		t.Fatal("shell syntax must fail without explicit Shell=true")
	}
	res = NewRunner().Run(context.Background(), Command{
		Name: "echo hi && echo injected", Shell: true,
	})
	if !res.OK() || strings.Count(strings.TrimSpace(string(res.Stdout)), "\n") != 1 {
		t.Fatalf("explicit shell run broken: %+v", res)
	}
}

func TestEmptyCommandRejected(t *testing.T) {
	res := NewRunner().Run(context.Background(), Command{})
	if res.Err == nil {
		t.Fatal("empty command must fail")
	}
}

func TestWorkingDirAndEnv(t *testing.T) {
	res := NewRunner().Run(context.Background(), Command{
		Name: "pwd",
		Dir:  "/tmp",
	})
	if !res.OK() {
		t.Fatalf("pwd failed: %v", res.Err)
	}
	res = NewRunner().Run(context.Background(), Command{
		Name: "sh",
		Args: []string{"-c", "printf %s $STATEKIT_TEST_VAR"},
		Env:  []string{"STATEKIT_TEST_VAR=injected"},
	})
	if !res.OK() || string(res.Stdout) != "injected" {
		t.Fatalf("env override broken: %+v (%q)", res, string(res.Stdout))
	}
}
