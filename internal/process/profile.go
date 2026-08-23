// OS execution profiles for the Runner (plans/porting.md enabler E1).
//
// A ShellModel describes how a shell-script command is wrapped on each
// target operating system, plus argv-quoting rules and executable naming.
package process

import "runtime"

// ShellModel wraps shell scripts for one OS family.
type ShellModel struct {
	// Program is the shell binary ("sh", "powershell", ...).
	Program string
	// PrefixArgs precede the script text (e.g. ["-c"], PowerShell switches).
	PrefixArgs []string
}

// ShellModelFor returns the default model for a GOOS value. Unix families
// use POSIX sh; Windows uses Windows PowerShell, which ships with every
// supported release (pwsh 7 is preferred when present at runtime).
func ShellModelFor(goos string) ShellModel {
	if goos == "windows" {
		return ShellModel{
			Program:    "powershell",
			PrefixArgs: []string{"-NoProfile", "-NonInteractive", "-Command"},
		}
	}
	return ShellModel{Program: "sh", PrefixArgs: []string{"-c"}}
}

// DefaultShellModel returns the model for the compiling platform.
func DefaultShellModel() ShellModel { return ShellModelFor(runtime.GOOS) }

// WrapShell turns a script string into (executable, argv) for this model.
func (m ShellModel) WrapShell(script string) (string, []string) {
	argv := append([]string{}, m.PrefixArgs...)
	argv = append(argv, script)
	return m.Program, argv
}

// ExecutableName appends the platform binary suffix (".exe" on windows).
func ExecutableName(base, goos string) string {
	if goos == "windows" && !hasSuffixFold(base, ".exe") {
		return base + ".exe"
	}
	return base
}

func hasSuffixFold(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	s = s[len(s)-len(suffix):]
	for i := 0; i < len(suffix); i++ {
		low := lowerByte(s[i])
		lows := lowerByte(suffix[i])
		if low != lows {
			return false
		}
	}
	return true
}

func lowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// QuoteArg quotes one argument for the target shell's command string.
//
//	POSIX:      single quotes, '\'' escaping; safe inside -c scripts.
//	PowerShell: single quotes with '' doubling.
func QuoteArg(goos, arg string) string {
	if goos == "windows" {
		return "'" + stringsReplaceAll(arg, "'", "''") + "'"
	}
	return "'" + stringsReplaceAll(arg, "'", `'\''`) + "'"
}

// stringsReplaceAll avoids importing strings solely for this helper chain in
// hot paths; kept local for clarity.
func stringsReplaceAll(s, old, new string) string {
	out := ""
	for {
		idx := indexOf(s, old)
		if idx < 0 {
			return out + s
		}
		out += s[:idx] + new
		s = s[idx+len(old):]
	}
}

func indexOf(s, sub string) int {
	n, m := len(s), len(sub)
	if m == 0 {
		return 0
	}
	for i := 0; i+m <= n; i++ {
		match := true
		for j := 0; j < m; j++ {
			if s[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
