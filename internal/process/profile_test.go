package process

import (
	"context"
	"strings"
	"testing"
)

func TestShellModelFor(t *testing.T) {
	unix := ShellModelFor("linux")
	if unix.Program != "sh" || len(unix.PrefixArgs) != 1 || unix.PrefixArgs[0] != "-c" {
		t.Fatalf("unix model wrong: %+v", unix)
	}
	win := ShellModelFor("windows")
	if win.Program != "powershell" ||
		strings.Join(win.PrefixArgs, " ") != "-NoProfile -NonInteractive -Command" {
		t.Fatalf("windows model wrong: %+v", win)
	}
}

func TestWrapShell(t *testing.T) {
	script, argv := ShellModelFor("linux").WrapShell("echo hi")
	if script != "sh" || strings.Join(argv, "|") != "-c|echo hi" {
		t.Fatalf("posix wrap = %q %v", script, argv)
	}
	name, pargv := ShellModelFor("windows").WrapShell("Get-Process")
	if name != "powershell" ||
		strings.Join(pargv, "|") != "-NoProfile|-NonInteractive|-Command|Get-Process" {
		t.Fatalf("ps wrap = %q %v", name, pargv)
	}
}

func TestExecutableName(t *testing.T) {
	cases := [][3]string{
		{"statekit", "linux", "statekit"},
		{"statekit", "darwin", "statekit"},
		{"statekit", "windows", "statekit.exe"},
		{"statekit.exe", "windows", "statekit.exe"},
		{"StateKit.EXE", "windows", "StateKit.EXE"},
	}
	for _, tc := range cases {
		if got := ExecutableName(tc[0], tc[1]); got != tc[2] {
			t.Fatalf("ExecutableName(%q,%q) = %q want %q", tc[0], tc[1], got, tc[2])
		}
	}
}

func TestQuoteArg(t *testing.T) {
	if got := QuoteArg("linux", "it's"); got != `'it'\''s'` {
		t.Fatalf("posix quote = %q", got)
	}
	if got := QuoteArg("windows", "it's"); got != "'it''s'" {
		t.Fatalf("ps quote = %q", got)
	}
}

// The default POSIX path must stay byte-compatible with pre-E1 behavior.
func TestRunnerPOSIXShellUnchanged(t *testing.T) {
	res := NewRunner().Run(context.Background(), Command{
		Name: "printf hello", Shell: true,
	})
	if !res.OK() || strings.TrimSpace(string(res.Stdout)) != "hello" {
		t.Fatalf("posix shell run broken: %+v (%q)", res, string(res.Stdout))
	}
}
