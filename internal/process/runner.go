// Package process centralizes all subprocess execution behind the Runner
// interface.
//
// Reference: plans/init.md section 37. Commands run via argv without a shell
// by default; shell execution is an explicit opt-in. Non-zero exit codes are
// data on CommandResult (ExitCode), not Runner errors. Err also reports
// ErrOutputLimit when captured output is truncated.
package process

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// RedactedPlaceholder replaces redacted secrets in rendered commands and
// captured output.
const RedactedPlaceholder = "***REDACTED***"

var redactedPlaceholderBytes = []byte(RedactedPlaceholder)

// ErrOutputLimit reports that bounded command output exceeded a configured
// capture limit. CommandResult retains the captured prefix in this case.
var ErrOutputLimit = errors.New("process: output limit exceeded")

// ErrInvalidOutputLimit reports a negative output capture limit.
var ErrInvalidOutputLimit = errors.New("process: invalid output limit")

// ErrInvalidRedaction reports a secret too large to support bounded boundary
// redaction. Rejecting it before start keeps the accepted capture policy finite.
var ErrInvalidRedaction = errors.New("process: invalid redaction secret")

// ErrInvalidRabbitMQCommand reports a command that cannot be represented by
// the shell-free Runner contract.  It is also returned for a batch helper
// whose command line would cross the finite Windows command budget.
var ErrInvalidRabbitMQCommand = errors.New("process: invalid RabbitMQ command")

// DefaultCaptureLimit bounds output when a Command does not provide a limit.
const DefaultCaptureLimit = 1 << 20

// MaxCaptureLimit is the largest finite per-stream output capture limit.
// Values above it are rejected before a child process starts. The retained
// boundary overlap is separately capped at maxRedactionOverlap.
const MaxCaptureLimit = 64 << 20

const (
	maxRedactionSecret  = 1 << 20
	maxRedactionOverlap = maxRedactionSecret - 1
	maxRedactionSecrets = 256
	maxRedactionBytes   = 4 << 20
	maxRedactionOutput  = MaxCaptureLimit + maxRedactionOverlap
	// maxDisplayBytes bounds command/error displays and RedactString. Inputs
	// beyond this budget are omitted; the overlap protects a token fragment at
	// the cutoff. These helpers are diagnostic displays, not data transport.
	maxDisplayBytes = 1 << 20
)

// waitDelay bounds the SIGTERM-to-SIGKILL grace period after cancellation.
const waitDelay = 5 * time.Second

// Command describes one subprocess execution. Commands use argv directly
// unless Shell is explicitly true. Output limits are independent per stream;
// zero selects DefaultCaptureLimit. Redaction preserves a bounded overlap so
// secrets crossing a read boundary are not exposed.
type Command struct {
	// WindowsCmdLine is the complete, already-quoted CreateProcess command line.
	// It is used only for the validated RabbitMQ batch wrapper, never reserialized.
	WindowsCmdLine string
	Name           string   // executable path or shell script when Shell is true
	Args           []string // argv tail; ignored when Shell is true beyond extra sh args
	Dir            string   // working directory; empty = inherit
	Env            []string // nil = inherit parent environment
	Stdin          []byte   // optional bytes piped to stdin
	Timeout        time.Duration
	Shell          bool     // explicit opt-in: run Name via "sh -c"
	Redact         []string // secret substrings scrubbed from output and rendering
	// MaxStdoutBytes and MaxStderrBytes bound captured output. Zero selects
	// DefaultCaptureLimit; positive values override it. Negative values are
	// rejected before the process is started. MaxCaptureLimit is the largest
	// accepted positive value.
	MaxStdoutBytes int
	MaxStderrBytes int
}

const maxRabbitMQCommandBytes = 1 << 20

// BuildRabbitMQCommand builds the command used by the RabbitMQ execution
// module.  Normal executables remain direct argv commands.  The two fixed
// RabbitMQ batch helpers are the one Windows exception: cmd.exe is invoked
// directly (Shell remains false) and receives a fully quoted /C argument.
//
// The target GOOS parameter makes the Windows quoting contract testable from
// non-Windows hosts and prevents a .bat-looking test fixture from changing
// Unix command behavior.
func BuildRabbitMQCommand(goos, executable string, args []string) (Command, error) {
	if err := validateRabbitMQCommandParts(executable, args); err != nil {
		return Command{}, err
	}
	if goos != "windows" || !isRabbitMQBatchExecutable(executable) {
		return Command{
			Name:  executable,
			Args:  append([]string(nil), args...),
			Shell: false,
		}, nil
	}

	commandLine, err := windowsRabbitMQBatchCommandLine(executable, args)
	if err != nil {
		return Command{}, err
	}
	return Command{
		Name:           "cmd.exe",
		Args:           []string{"/D", "/S", "/C", commandLine},
		WindowsCmdLine: "cmd.exe /D /S /C " + commandLine,
		Shell:          false,
	}, nil
}

func validateRabbitMQCommandParts(executable string, args []string) error {
	total := len(executable)
	if total > maxRabbitMQCommandBytes {
		return ErrInvalidRabbitMQCommand
	}
	if err := validateRabbitMQCommandPart(executable); err != nil {
		return err
	}
	for _, arg := range args {
		if err := validateRabbitMQCommandPart(arg); err != nil {
			return err
		}
		total += len(arg) + 1
		if total > maxRabbitMQCommandBytes {
			return ErrInvalidRabbitMQCommand
		}
	}
	return nil
}

func validateRabbitMQCommandPart(value string) error {
	if !utf8.ValidString(value) {
		return ErrInvalidRabbitMQCommand
	}
	for _, char := range value {
		if char == 0 || unicode.IsControl(char) {
			return ErrInvalidRabbitMQCommand
		}
	}
	return nil
}

func isRabbitMQBatchExecutable(executable string) bool {
	base := executable
	if index := strings.LastIndexAny(base, `/\\`); index >= 0 {
		base = base[index+1:]
	}
	base = strings.ToLower(base)
	return base == "rabbitmqctl.bat" || base == "rabbitmq-plugins.bat"
}

func windowsRabbitMQBatchCommandLine(executable string, args []string) (string, error) {
	parts := make([]string, 0, len(args)+1)
	for _, value := range append([]string{executable}, args...) {
		quoted, err := quoteWindowsBatchArgument(value)
		if err != nil {
			return "", err
		}
		parts = append(parts, quoted)
	}
	// /S /C has special handling for the first and last quote.  The outer
	// pair preserves the quoted batch path as one command while the inner
	// pairs preserve each argv value. Shell metacharacters are rejected because
	// the batch helper may expand arguments again.
	commandLine := `"` + strings.Join(parts, " ") + `"`
	if len(utf16.Encode([]rune("cmd.exe /D /S /C "+commandLine))) > 8191 {
		return "", ErrInvalidRabbitMQCommand
	}
	return commandLine, nil
}

func quoteWindowsBatchArgument(value string) (string, error) {
	// cmd.exe expands percent variables even inside double quotes, and delayed
	// expansion can make exclamation marks executable data when the caller's
	// environment enables it.  Rejecting both is safer than trying to infer the
	// caller's cmd.exe mode.  Embedded quotes are likewise rejected because a
	// batch wrapper receives %* and cannot provide a stable argv boundary for
	// them.  These are validation failures, not shell fallbacks.
	if strings.ContainsAny(value, `%!"|&<>^`) {
		return "", ErrInvalidRabbitMQCommand
	}
	trailingSlashes := 0
	for index := len(value) - 1; index >= 0 && value[index] == '\\'; index-- {
		trailingSlashes++
	}
	if trailingSlashes > 0 {
		value += strings.Repeat(`\`, trailingSlashes)
	}
	return `"` + value + `"`, nil
}

// RedactedString renders the command for comments and logs with every
// Redact entry replaced by RedactedPlaceholder.
func (c Command) RedactedString() string {
	var raw boundedString
	raw.write(c.Name)
	for _, arg := range c.Args {
		raw.write(" ")
		raw.write(arg)
	}
	return redactStringLimited(c.Redact, raw.string(), maxDisplayBytes)
}

// CommandResult carries captured output, exit status, timing, and errors.
// Stdout and Stderr are independently capped prefixes after redaction, and
// their Truncated flags indicate discarded child output. ErrOutputLimit takes
// precedence over a non-zero exit status, but start, timeout, and cancellation
// errors take precedence over ErrOutputLimit. A non-zero exit without those
// errors remains compatibility data in ExitCode and leaves Err nil.
type CommandResult struct {
	Stdout          []byte
	Stderr          []byte
	ExitCode        int  // -1 when terminated by signal or never started
	Started         bool // true when the child reached ProcessState
	Duration        time.Duration
	Err             error
	StdoutTruncated bool
	StderrTruncated bool
}

// OK reports a zero exit status without runner errors.
func (r CommandResult) OK() bool { return r.Err == nil && r.ExitCode == 0 }

// RedactBytes returns b with each secret substring replaced.
func RedactBytes(secrets []string, b []byte) []byte {
	if err := validateRedaction(secrets); err != nil {
		return []byte(RedactedPlaceholder)
	}
	if len(b) > maxRedactionBytes {
		b = b[:maxRedactionBytes]
		// The unavailable suffix could complete a token beginning in this
		// prefix. Do not return its raw boundary fragment.
		if len(b) > maxRedactionOverlap {
			b = b[:len(b)-maxRedactionOverlap]
		}
	}
	out, _ := redactLimited(secrets, b, maxRedactionOutput)
	return out
}

// RedactString applies RedactBytes to a string value.
func RedactString(secrets []string, s string) string {
	return redactStringLimited(secrets, s, maxDisplayBytes)
}

// boundedString constructs a command display without allocating for arbitrary
// Name or Args values. Its raw budget is finite and intentionally shared by
// all arguments, so the result is deterministic for oversized commands.
type boundedString struct {
	b strings.Builder
}

func (b *boundedString) write(s string) {
	remaining := maxDisplayBytes - b.b.Len()
	if remaining <= 0 {
		return
	}
	if len(s) > remaining {
		s = s[:remaining]
	}
	_, _ = b.b.WriteString(s)
}

func (b *boundedString) string() string { return b.b.String() }

func redactStringLimited(secrets []string, s string, limit int) string {
	if validateRedaction(secrets) != nil {
		return RedactedPlaceholder
	}
	if len(s) >= maxDisplayBytes {
		s = s[:maxDisplayBytes]
		overlap := maxSecretLength(secrets) - 1
		if overlap < 0 {
			overlap = 0
		}
		if overlap > maxDisplayBytes {
			overlap = maxDisplayBytes
		}
		s = s[:len(s)-overlap]
	}
	matcher := newRedactionMatcher(secrets)
	var out strings.Builder
	if limit > 0 {
		out.Grow(minInt(limit, len(s)))
	}
	for pos := 0; pos < len(s); {
		match := matcher.findString(s[pos:])
		if match == nil {
			_ = appendLimitedString(&out, s[pos:], limit)
			break
		}
		start, end := pos+match[0], pos+match[1]
		if !appendLimitedString(&out, s[pos:start], limit) || !appendLimitedString(&out, RedactedPlaceholder, limit) {
			break
		}
		pos = end
	}
	return out.String()
}

func appendLimitedString(out *strings.Builder, text string, limit int) bool {
	if len(text) > limit-out.Len() {
		return false
	}
	_, _ = out.WriteString(text)
	return true
}

func maxSecretLength(secrets []string) int {
	max := 0
	for _, secret := range secrets {
		if len(secret) > max {
			max = len(secret)
		}
	}
	return max
}

// Runner executes commands centrally for every module.
type Runner interface {
	Run(ctx context.Context, cmd Command) CommandResult
}

// CommandAvailability is the optional, shell-free capability for checking a
// helper before a command that relies on it mutates local state.
type CommandAvailability interface {
	CommandAvailable(name string) bool
}

// DefaultRunner is the production Runner backed by os/exec.
type DefaultRunner struct {
	model ShellModel
}

// NewRunner returns the default Runner implementation using the compiling
// platform's shell model.
func NewRunner() *DefaultRunner { return &DefaultRunner{model: DefaultShellModel()} }

// NewRunnerWithModel overrides the shell model (platform portability tests,
// cross-OS tooling).
func NewRunnerWithModel(m ShellModel) *DefaultRunner { return &DefaultRunner{model: m} }

// CommandAvailable resolves a helper without starting a process or a shell.
func (DefaultRunner) CommandAvailable(name string) bool {
	if runtime.GOOS == "windows" && isRabbitMQBatchExecutable(name) {
		info, err := os.Stat(name)
		return err == nil && !info.IsDir()
	}
	_, err := exec.LookPath(name)
	return err == nil
}

// Run executes cmd without a shell unless Shell is explicitly set.
func (r DefaultRunner) Run(ctx context.Context, c Command) CommandResult {
	start := time.Now()
	res := CommandResult{}
	res.ExitCode = -1
	if ctx == nil {
		ctx = context.Background()
	}
	stdoutLimit, err := captureLimit(c.MaxStdoutBytes)
	if err != nil {
		res.Err = err
		res.Duration = time.Since(start)
		return res
	}
	stderrLimit, err := captureLimit(c.MaxStderrBytes)
	if err != nil {
		res.Err = err
		res.Duration = time.Since(start)
		return res
	}
	if c.Name == "" {
		res.Err = errors.New("process: empty command name")
		res.Duration = time.Since(start)
		return res
	}
	if err := validateRedaction(c.Redact); err != nil {
		res.Err = err
		res.Duration = time.Since(start)
		return res
	}

	runCtx, cancel := context.WithCancel(ctx)
	if c.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, c.Timeout)
	}
	defer cancel()

	name, argv := c.Name, append([]string{}, c.Args...)
	if c.Shell {
		shellName, shellArgv := r.model.WrapShell(c.Name)
		name = shellName
		argv = append(shellArgv, argv...)
	}

	cmd := exec.CommandContext(runCtx, name, argv...)
	if err := configureWindowsCommandLine(cmd, c); err != nil {
		return CommandResult{ExitCode: -1, Err: err}
	}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return cmd.Process.Signal(syscall.SIGTERM)
		}
		return os.ErrProcessDone
	}
	cmd.WaitDelay = waitDelay
	if c.Dir != "" {
		cmd.Dir = c.Dir
	}
	if c.Env != nil {
		cmd.Env = c.Env
	} else {
		cmd.Env = os.Environ()
	}
	if len(c.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}

	stdout := boundedBuffer{limit: stdoutLimit, retainedLimit: captureRetainedLimit(stdoutLimit, c.Redact)}
	stderr := boundedBuffer{limit: stderrLimit, retainedLimit: captureRetainedLimit(stderrLimit, c.Redact)}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	res.Duration = time.Since(start)
	var stdoutClipped, stderrClipped bool
	res.Stdout, stdoutClipped = redactAndLimit(c.Redact, stdout.buf.Bytes(), stdoutLimit)
	res.Stderr, stderrClipped = redactAndLimit(c.Redact, stderr.buf.Bytes(), stderrLimit)
	res.StdoutTruncated = stdout.overflow || stdoutClipped
	res.StderrTruncated = stderr.overflow || stderrClipped
	if ps := cmd.ProcessState; ps != nil {
		res.Started = true
		res.ExitCode = ps.ExitCode()
	} else {
		res.ExitCode = -1
	}

	display := c.RedactedString()
	switch {
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		res.Err = fmt.Errorf("%s timed out after %s", display, c.Timeout)
	case errors.Is(runCtx.Err(), context.Canceled):
		res.Err = fmt.Errorf("%s canceled", display)
	case err != nil && cmd.ProcessState == nil:
		res.Err = fmt.Errorf("%s: %w", display, err)
	case res.StdoutTruncated || res.StderrTruncated:
		res.Err = fmt.Errorf("%s: %w", display, ErrOutputLimit)
	}
	return res
}

func captureLimit(limit int) (int, error) {
	if limit < 0 || limit > MaxCaptureLimit {
		return 0, ErrInvalidOutputLimit
	}
	if limit == 0 {
		return DefaultCaptureLimit, nil
	}
	return limit, nil
}

func captureRetainedLimit(limit int, secrets []string) int {
	// A secret longer than this cannot be retained safely without making the
	// capture bound depend on untrusted input. Redaction still works for the
	// command display; output capture uses a finite fixed overlap.
	if limit < 0 {
		return 0
	}
	if limit > MaxCaptureLimit {
		limit = MaxCaptureLimit
	}
	overlap := 0
	for _, secret := range secrets {
		if len(secret) > overlap {
			overlap = len(secret)
		}
	}
	if overlap > 0 {
		overlap--
	}
	if overlap > maxRedactionOverlap {
		overlap = maxRedactionOverlap
	}
	return limit + overlap
}

func validateRedaction(secrets []string) error {
	if len(secrets) > maxRedactionSecrets {
		return fmt.Errorf("%w: too many secrets", ErrInvalidRedaction)
	}
	total := 0
	for _, secret := range secrets {
		if len(secret) > maxRedactionSecret {
			return fmt.Errorf("%w: secret exceeds %d bytes", ErrInvalidRedaction, maxRedactionSecret)
		}
		if len(secret) > maxRedactionBytes-total {
			return fmt.Errorf("%w: aggregate secret budget exceeded", ErrInvalidRedaction)
		}
		total += len(secret)
	}
	return nil
}

// redactAndLimit redacts before applying the public limit. The writer retains
// enough overlap to detect a secret crossing the raw capture boundary.
func redactAndLimit(secrets []string, b []byte, limit int) ([]byte, bool) {
	// boundedBuffer retains maxSecret-1 bytes past the raw limit. The scanner
	// therefore sees every token crossing that boundary without expanding an
	// untrusted replacement stream. Once the public limit is reached, scanning
	// stops because all retained output has already been redacted.
	return redactLimited(secrets, b, limit)
}

// redactLimited performs a single bounded scan. The first matching secret at
// each input position gives the historical list-order behavior for ordinary
// inputs, while the finite output cap prevents replacement amplification.
func redactLimited(secrets []string, b []byte, limit int) ([]byte, bool) {
	if limit < 0 {
		return nil, true
	}
	out := make([]byte, 0, minInt(limit, len(b)))
	matcher := newRedactionMatcher(secrets)
	clipped := false
	for pos := 0; pos < len(b); {
		match := matcher.findBytes(b[pos:])
		if match == nil {
			if len(b)-pos > limit-len(out) {
				clipped = true
				break
			}
			out = append(out, b[pos:]...)
			break
		}
		start, end := pos+match[0], pos+match[1]
		if len(b[pos:start])+len(redactedPlaceholderBytes) > limit-len(out) {
			clipped = true
			break
		}
		out = append(out, b[pos:start]...)
		out = append(out, redactedPlaceholderBytes...)
		pos = end
	}
	return out, clipped
}

type redactionMatcher struct{ re *regexp.Regexp }

func newRedactionMatcher(secrets []string) redactionMatcher {
	patterns := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if secret != "" {
			patterns = append(patterns, regexp.QuoteMeta(secret))
		}
	}
	if len(patterns) == 0 {
		return redactionMatcher{}
	}
	return redactionMatcher{re: regexp.MustCompile("(?:" + strings.Join(patterns, "|") + ")")}
}

func (m redactionMatcher) findString(s string) []int {
	if m.re == nil {
		return nil
	}
	return m.re.FindStringIndex(s)
}

func (m redactionMatcher) findBytes(b []byte) []int {
	if m.re == nil {
		return nil
	}
	return m.re.FindIndex(b)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// boundedBuffer retains a bounded prefix and discards excess while reporting
// overflow out-of-band. Returning len(p), nil is required so os/exec can let
// the child finish and preserve its actual exit code.
type boundedBuffer struct {
	buf           bytes.Buffer
	limit         int
	retainedLimit int
	overflow      bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := b.retainedLimit - b.buf.Len()
	if remaining <= 0 {
		b.overflow = true
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.overflow = true
		return len(p), nil
	}
	return b.buf.Write(p)
}
