package process

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func TestRunEcho(t *testing.T) {
	res := NewRunner().Run(context.Background(), Command{
		Name: "echo", Args: []string{"hello"},
	})
	if !res.OK() || res.ExitCode != 0 || !res.Started {
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
	if res.ExitCode != 7 || !res.Started {
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
	if res.Err == nil || !errors.Is(res.Err, context.DeadlineExceeded) || !strings.Contains(res.Err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", res.Err)
	}
	if !res.Started {
		t.Fatalf("timeout should report a started process: %+v", res)
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
	if res.Err == nil || !errors.Is(res.Err, context.Canceled) || !strings.Contains(res.Err.Error(), "canceled") {
		t.Fatalf("expected cancellation error, got %v", res.Err)
	}
	if !res.Started {
		t.Fatalf("cancellation should report a started process: %+v", res)
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

type runnerSensitiveCause struct {
	secret string
}

func (e *runnerSensitiveCause) Error() string {
	if e.secret != "" {
		return "private-cause: " + e.secret
	}
	return "private-cause"
}

type runnerSafeOuterError struct {
	cause error
}

func (*runnerSafeOuterError) Error() string { return "safe runner diagnostic" }

func (e *runnerSafeOuterError) Unwrap() error { return e.cause }

func TestRedactedErrorAlwaysOpaqueAndPreservesOnlyControlIdentities(t *testing.T) {
	secret := "runner-secret"
	cause := &runnerSensitiveCause{secret: secret}
	outer := &runnerSafeOuterError{cause: fmt.Errorf("typed wrapper: %w", cause)}
	redacted := RedactedError(outer, secret)
	if redacted == nil || redacted == outer || redacted.Error() != outer.Error() || strings.Contains(redacted.Error(), secret) {
		t.Fatalf("redacted error = %v", redacted)
	}
	if errors.Unwrap(redacted) != nil {
		t.Fatalf("redacted error unexpectedly unwraps: %v", redacted)
	}
	var got *runnerSensitiveCause
	if errors.As(redacted, &got) {
		t.Fatalf("redacted error exposed sensitive cause: %T", got)
	}
	if errors.Is(redacted, cause) {
		t.Fatalf("redacted error preserved arbitrary cause identity: %v", redacted)
	}

	arbitrary := errors.New("arbitrary cause")
	joined := errors.Join(
		&runnerSafeOuterError{cause: context.Canceled},
		fmt.Errorf("deadline detail: %w", context.DeadlineExceeded),
		fmt.Errorf("output detail: %w", ErrOutputLimit),
		fmt.Errorf("input detail: %w", ErrCommandInputLimit),
		cause,
		arbitrary,
	)
	redacted = RedactedError(joined, secret)
	if redacted == joined || strings.Contains(redacted.Error(), secret) || errors.Unwrap(redacted) != nil {
		t.Fatalf("multi-error was not opaque: %v", redacted)
	}
	for _, identity := range []error{
		context.Canceled,
		context.DeadlineExceeded,
		ErrOutputLimit,
		ErrCommandInputLimit,
	} {
		if !errors.Is(redacted, identity) {
			t.Fatalf("canonical identity %v was lost: %v", identity, redacted)
		}
	}
	if errors.Is(redacted, arbitrary) || errors.Is(redacted, cause) {
		t.Fatalf("multi-error exposed a non-canonical cause: %v", redacted)
	}
	got = nil
	if errors.As(redacted, &got) {
		t.Fatalf("multi-error exposed sensitive cause: %T", got)
	}

	bounded := RedactedError(errors.New(strings.Repeat("s", maxDisplayBytes+1)), secret)
	if bounded == nil || len(bounded.Error()) > maxDisplayBytes {
		t.Fatalf("redacted diagnostic exceeded bound: len=%d", len(bounded.Error()))
	}
}

func TestPreserveStdoutKeepsInternalFixedMarkerRaw(t *testing.T) {
	res := NewRunner().Run(context.Background(), Command{
		Name:           "printf",
		Args:           []string{"1"},
		Redact:         []string{"1"},
		PreserveStdout: true,
	})
	if !res.OK() || string(res.Stdout) != "1" {
		t.Fatalf("preserved stdout=%q err=%v", res.Stdout, res.Err)
	}
	if strings.Contains((Command{Name: "printf", Args: []string{"1"}, Redact: []string{"1"}}).RedactedString(), "1") {
		t.Fatal("command display leaked preserved marker")
	}
	res = NewRunner().Run(context.Background(), Command{
		Name:           "sh",
		Args:           []string{"-c", "printf 1 >&2"},
		Redact:         []string{"1"},
		PreserveStdout: true,
	})
	if strings.Contains(string(res.Stderr), "1") {
		t.Fatalf("stderr leaked preserved marker: %q", res.Stderr)
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
	if res.Err == nil || res.Started {
		t.Fatal("empty command must fail")
	}
	res = NewRunner().Run(context.Background(), Command{Name: "definitely-not-started"})
	if res.Err == nil || res.Started {
		t.Fatalf("missing executable must not report started: %+v", res)
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

func TestOutputLimitsRetainTruncatedOutput(t *testing.T) {
	res := NewRunner().Run(context.Background(), Command{
		Name: "sh", Args: []string{"-c", "printf 123456; printf abcdef >&2"},
		MaxStdoutBytes: 3, MaxStderrBytes: 3,
	})
	if !errors.Is(res.Err, ErrOutputLimit) {
		t.Fatalf("expected output limit error, got %#v", res)
	}
	if res.ExitCode != 0 || !res.StdoutTruncated || !res.StderrTruncated {
		t.Fatalf("limit status = %+v", res)
	}
	if string(res.Stdout) != "123" || string(res.Stderr) != "abc" {
		t.Fatalf("truncated output = %q, %q", res.Stdout, res.Stderr)
	}
}

func TestOutputLimitDoesNotReplaceNonZeroExit(t *testing.T) {
	res := NewRunner().Run(context.Background(), Command{
		Name: "sh", Args: []string{"-c", "printf 123456; exit 7"}, MaxStdoutBytes: 3,
	})
	if res.ExitCode != 7 || !errors.Is(res.Err, ErrOutputLimit) {
		t.Fatalf("result = %+v", res)
	}
}

func TestDefaultAndInvalidOutputLimits(t *testing.T) {
	res := NewRunner().Run(context.Background(), Command{Name: "sh", Args: []string{"-c", "printf %*s 1048577 x"}})
	if !res.StdoutTruncated || len(res.Stdout) != DefaultCaptureLimit || !errors.Is(res.Err, ErrOutputLimit) {
		t.Fatalf("default limit result = %+v", res)
	}
	res = NewRunner().Run(context.Background(), Command{Name: "definitely-not-started", MaxStdoutBytes: -1})
	if !errors.Is(res.Err, ErrInvalidOutputLimit) || res.ExitCode != -1 {
		t.Fatalf("invalid limit result = %+v", res)
	}
	if res.Started {
		t.Fatal("invalid limit must not report a started process")
	}
	for _, limit := range []int{MaxCaptureLimit + 1, int(^uint(0) >> 1)} {
		res = NewRunner().Run(context.Background(), Command{Name: "definitely-not-started", MaxStdoutBytes: limit})
		if !errors.Is(res.Err, ErrInvalidOutputLimit) || res.ExitCode != -1 {
			t.Fatalf("invalid maximum limit %d: %+v", limit, res)
		}
	}
	for _, limit := range []int{1, MaxCaptureLimit} {
		res = NewRunner().Run(context.Background(), Command{Name: "printf", Args: []string{"x"}, MaxStdoutBytes: limit})
		if res.Err != nil || len(res.Stdout) != 1 || res.StdoutTruncated {
			t.Fatalf("valid limit %d: %+v", limit, res)
		}
	}
}

func TestCaptureRetainedLimitIsFinite(t *testing.T) {
	secrets := []string{strings.Repeat("x", maxRedactionSecret)}
	retained := captureRetainedLimit(MaxCaptureLimit, secrets)
	if retained != MaxCaptureLimit+maxRedactionOverlap || retained < MaxCaptureLimit {
		t.Fatalf("retained limit = %d", retained)
	}
	if captureRetainedLimit(int(^uint(0)>>1), secrets) > MaxCaptureLimit+maxRedactionOverlap {
		t.Fatal("retained limit is not finite")
	}
}

func TestRedactionExpansionAndBoundaryAreBounded(t *testing.T) {
	secret := "secret"
	res := NewRunner().Run(context.Background(), Command{
		Name: "printf", Args: []string{"prefix-secret-suffix"}, Redact: []string{secret}, MaxStdoutBytes: 10,
	})
	if len(res.Stdout) > 10 || strings.Contains(string(res.Stdout), secret) {
		t.Fatalf("redacted output = %q", res.Stdout)
	}
	res = NewRunner().Run(context.Background(), Command{
		Name: "printf", Args: []string{"12345secret"}, Redact: []string{secret}, MaxStdoutBytes: 10,
	})
	if len(res.Stdout) > 10 || strings.Contains(string(res.Stdout), secret) {
		t.Fatalf("boundary output leaked or exceeded limit: %q", res.Stdout)
	}
}

func TestRedactionExpansionSetsOutputLimitAndPreservesExitCode(t *testing.T) {
	const limit = 10
	const secret = "secret"
	res := NewRunner().Run(context.Background(), Command{
		Name: "sh", Args: []string{"-c", "printf 12345secret; printf 12345secret >&2; exit 7"},
		Redact: []string{secret}, MaxStdoutBytes: limit, MaxStderrBytes: limit,
	})
	if res.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7", res.ExitCode)
	}
	if !errors.Is(res.Err, ErrOutputLimit) {
		t.Fatalf("expected output limit error, got %v", res.Err)
	}
	if !res.StdoutTruncated || !res.StderrTruncated {
		t.Fatalf("truncation flags = stdout:%t stderr:%t", res.StdoutTruncated, res.StderrTruncated)
	}
	for name, output := range map[string][]byte{"stdout": res.Stdout, "stderr": res.Stderr} {
		if len(output) > limit || strings.Contains(string(output), secret) {
			t.Fatalf("%s output leaked or exceeded limit: %q", name, output)
		}
	}
}

func TestOversizedRedactionRejectedBeforeStart(t *testing.T) {
	res := NewRunner().Run(context.Background(), Command{Name: "definitely-not-started", Redact: []string{strings.Repeat("x", 1<<20+1)}})
	if !errors.Is(res.Err, ErrInvalidRedaction) || res.ExitCode != -1 {
		t.Fatalf("result = %+v", res)
	}
}

func TestRedactionBudgetRejectsManySecretsBeforeStart(t *testing.T) {
	secrets := make([]string, maxRedactionSecrets+1)
	for i := range secrets {
		secrets[i] = "x"
	}
	res := NewRunner().Run(context.Background(), Command{Name: "definitely-not-started", Redact: secrets})
	if !errors.Is(res.Err, ErrInvalidRedaction) || res.ExitCode != -1 {
		t.Fatalf("result = %+v", res)
	}
}

func TestRedactionExpansionDoesNotExceedFiniteMemoryBound(t *testing.T) {
	input := bytes.Repeat([]byte("x"), 1<<20)
	output, clipped := redactAndLimit([]string{"x"}, input, 64)
	if !clipped || len(output) > 64 || strings.Contains(string(output), "x") {
		t.Fatalf("output leaked or exceeded bound: clipped=%t len=%d", clipped, len(output))
	}
}

func TestDisplayRedactionIsBoundedForOversizedInputs(t *testing.T) {
	secret := "SECRET"
	oversized := strings.Repeat("x", maxDisplayBytes*2) + secret
	if got := RedactString([]string{secret}, oversized); len(got) > maxDisplayBytes || strings.Contains(got, secret) {
		t.Fatalf("oversized RedactString leaked or exceeded bound: len=%d", len(got))
	}
	cmd := Command{Name: oversized, Args: []string{oversized}, Redact: []string{secret}}
	got := cmd.RedactedString()
	if len(got) > maxDisplayBytes || strings.Contains(got, secret) {
		t.Fatalf("oversized command display leaked or exceeded bound: len=%d", len(got))
	}
	if got := RedactString([]string{secret}, "prefix-SECRET-suffix"); got != "prefix-***REDACTED***-suffix" {
		t.Fatalf("ordinary redaction = %q", got)
	}
}

func TestDisplayRedactionBoundaryDoesNotExposeSecretFragment(t *testing.T) {
	secret := strings.Repeat("s", 128)
	input := strings.Repeat("x", maxDisplayBytes-len(secret)+1) + secret
	got := RedactString([]string{secret}, input)
	if len(got) > maxDisplayBytes || strings.Contains(got, "s") {
		t.Fatalf("boundary display leaked secret fragment or exceeded bound: len=%d", len(got))
	}
}

func TestBuildRabbitMQCommandWindowsBatchVectors(t *testing.T) {
	path := `C:\Program Files\RabbitMQ Server\rabbitmq_server-3.12.0\sbin\rabbitmqctl.bat`
	command, err := BuildRabbitMQCommand("windows", path, []string{"add_user", "alice", "safe value"})
	if err != nil {
		t.Fatal(err)
	}
	if command.Name != "cmd.exe" || command.Shell || len(command.Args) != 4 ||
		command.Args[0] != "/D" || command.Args[1] != "/S" || command.Args[2] != "/C" {
		t.Fatalf("batch command wrapper=%#v", command)
	}
	want := `""C:\Program Files\RabbitMQ Server\rabbitmq_server-3.12.0\sbin\rabbitmqctl.bat" "add_user" "alice" "safe value""`
	if command.Args[3] != want || command.WindowsCmdLine != "cmd.exe /D /S /C "+want {
		t.Fatalf("batch command line=%q want %q", command.Args[3], want)
	}

	direct, err := BuildRabbitMQCommand("windows", `C:\RabbitMQ\rabbitmqctl.exe`, []string{"add_user", "alice"})
	if err != nil || direct.WindowsCmdLine != "" || direct.Name != `C:\RabbitMQ\rabbitmqctl.exe` || direct.Shell || strings.Join(direct.Args, "|") != "add_user|alice" {
		t.Fatalf("native helper command=%#v err=%v", direct, err)
	}

	unix, err := BuildRabbitMQCommand("linux", `C:\RabbitMQ\rabbitmqctl.bat`, []string{"status"})
	if err != nil || unix.Name != `C:\RabbitMQ\rabbitmqctl.bat` || unix.Shell {
		t.Fatalf("unix batch-looking command=%#v err=%v", unix, err)
	}
}

func TestBuildRabbitMQCommandRejectsInjectionAndBounds(t *testing.T) {
	path := `C:\RabbitMQ\rabbitmqctl.bat`
	for name, args := range map[string][]string{
		"control":           {"add_user", "bad\nname"},
		"percent-expansion": {"add_user", "%PATH%"},
		"delayed-expansion": {"add_user", "!cmd!"},
		"embedded-quote":    {"add_user", `bad"name`},
		"pipe":              {"add_user", "safe|whoami"},
		"ampersand":         {"add_user", "safe&whoami"},
		"carriage-return":   {"add_user", "bad\rname"},
		"nul":               {"add_user", "bad\x00name"},
		"overlong":          {"add_user", strings.Repeat("x", 1<<20)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildRabbitMQCommand("windows", path, args); !errors.Is(err, ErrInvalidRabbitMQCommand) {
				t.Fatalf("err=%v, want ErrInvalidRabbitMQCommand", err)
			}
		})
	}
}

func TestRabbitMQFinalWindowsCommandLineBoundary(t *testing.T) {
	path := `C:\Rabbit MQ\rabbitmqctl.bat`
	base, err := BuildRabbitMQCommand("windows", path, []string{"status", ""})
	if err != nil {
		t.Fatal(err)
	}
	overhead := len(utf16.Encode([]rune(base.WindowsCmdLine)))
	for _, text := range []string{"x", "界", "😀", " ", `\`} {
		for _, units := range []int{8190, 8191, 8192} {
			budget := units - overhead
			cost := len(utf16.Encode([]rune(text)))
			// A trailing backslash is doubled before the closing quote.
			if text == `\` {
				cost = 2
			}
			value := strings.Repeat("x", budget%cost) + strings.Repeat(text, budget/cost)
			command, err := BuildRabbitMQCommand("windows", path, []string{"status", value})
			if units > 8191 {
				if !errors.Is(err, ErrInvalidRabbitMQCommand) {
					t.Fatal("overlong final line accepted")
				}
				continue
			}
			if err != nil || len(utf16.Encode([]rune(command.WindowsCmdLine))) != units {
				t.Fatalf("boundary units=%d error=%v", units, err)
			}
		}
	}
}

func TestRabbitMQFinalWindowsCommandLineTransport(t *testing.T) {
	command, err := BuildRabbitMQCommand("windows", `C:\Rabbit MQ\rabbitmqctl.bat`, []string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(command.Name, command.Args...)
	err = configureWindowsCommandLine(child, command)
	if runtime.GOOS != "windows" {
		if !errors.Is(err, ErrInvalidRabbitMQCommand) {
			t.Fatal("Windows line accepted on non-Windows")
		}
		return
	}
	if err != nil || child.SysProcAttr == nil {
		t.Fatal("missing native command-line transport")
	}
	if reflect.ValueOf(child.SysProcAttr).Elem().FieldByName("CmdLine").String() != command.WindowsCmdLine {
		t.Fatal("CreateProcess command line was reserialized")
	}
}

func TestRedactionPreservesLeftmostListOrderWithOverlaps(t *testing.T) {
	for _, tc := range []struct {
		secrets []string
		input   string
		want    string
	}{
		{[]string{"ab", "abc"}, "xabcab", "x***REDACTED***c***REDACTED***"},
		{[]string{"abc", "ab"}, "xabcab", "x***REDACTED******REDACTED***"},
		{[]string{"aaaaab", "aaaab", "aaab"}, "zaaaaabz", "z***REDACTED***z"},
	} {
		if got := RedactString(tc.secrets, tc.input); got != tc.want {
			t.Fatalf("RedactString(%q, %q) = %q, want %q", tc.secrets, tc.input, got, tc.want)
		}
		if got := string(RedactBytes(tc.secrets, []byte(tc.input))); got != tc.want {
			t.Fatalf("RedactBytes(%q, %q) = %q, want %q", tc.secrets, tc.input, got, tc.want)
		}
	}
}
