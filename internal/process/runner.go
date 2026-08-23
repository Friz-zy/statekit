// Package process centralizes all subprocess execution behind the Runner
// interface.
//
// Reference: plans/init.md section 37. Commands run via argv without a shell
// by default; shell execution is an explicit opt-in. Non-zero exit codes are
// data on CommandResult (ExitCode), not Runner errors: Err is reserved for
// start failures, timeouts, and cancellation.
package process

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// RedactedPlaceholder replaces redacted secrets in rendered commands and
// captured output.
const RedactedPlaceholder = "***REDACTED***"

// waitDelay bounds the SIGTERM-to-SIGKILL grace period after cancellation.
const waitDelay = 5 * time.Second

// Command describes one subprocess execution.
type Command struct {
	Name    string   // executable path or shell script when Shell is true
	Args    []string // argv tail; ignored when Shell is true beyond extra sh args
	Dir     string   // working directory; empty = inherit
	Env     []string // nil = inherit parent environment
	Stdin   []byte   // optional bytes piped to stdin
	Timeout time.Duration
	Shell   bool     // explicit opt-in: run Name via "sh -c"
	Redact  []string // secret substrings scrubbed from output and rendering
}

// RedactedString renders the command for comments and logs with every
// Redact entry replaced by RedactedPlaceholder.
func (c Command) RedactedString() string {
	parts := append([]string{c.Name}, c.Args...)
	return string(RedactBytes(c.Redact, []byte(strings.Join(parts, " "))))
}

// CommandResult carries captured output, exit status, timing, and any
// start/timeout/cancel error.
type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int // -1 when terminated by signal or never started
	Duration time.Duration
	Err      error
}

// OK reports a zero exit status without runner errors.
func (r CommandResult) OK() bool { return r.Err == nil && r.ExitCode == 0 }

// RedactBytes returns b with each secret substring replaced.
func RedactBytes(secrets []string, b []byte) []byte {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		b = bytes.ReplaceAll(b, []byte(secret), []byte(RedactedPlaceholder))
	}
	return b
}

// RedactString applies RedactBytes to a string value.
func RedactString(secrets []string, s string) string {
	return string(RedactBytes(secrets, []byte(s)))
}

// Runner executes commands centrally for every module.
type Runner interface {
	Run(ctx context.Context, cmd Command) CommandResult
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

// Run executes cmd without a shell unless Shell is explicitly set.
func (r DefaultRunner) Run(ctx context.Context, c Command) CommandResult {
	start := time.Now()
	res := CommandResult{}
	if ctx == nil {
		ctx = context.Background()
	}
	if c.Name == "" {
		res.Err = errors.New("process: empty command name")
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

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res.Duration = time.Since(start)
	res.Stdout = RedactBytes(c.Redact, stdout.Bytes())
	res.Stderr = RedactBytes(c.Redact, stderr.Bytes())
	if ps := cmd.ProcessState; ps != nil {
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
	}
	return res
}
