package selinux

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

// whichGuard mirrors salt.utils.decorators.path.which and the module
// __virtual__ command check: functions fail with upstream's verbatim
// CommandNotFoundError text when their tool is missing from $PATH.
func whichGuard(exe string) error {
	if toolLookup(exe) {
		return nil
	}
	return fmt.Errorf("The '%s' binary was not found in $PATH.", exe)
}

// toolLookup mirrors salt.utils.path.which; injectable for tests.
var toolLookup = func(exe string) bool {
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		if dir == "" {
			continue
		}
		if info, err := os.Stat(dir + "/" + exe); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

// validateArgRunes rejects control runes and invalid UTF-8 in strings that
// become argv elements or line-parse inputs. The pinned source passes the
// same values through single-quoted shell strings; the shell-free Runner
// cannot express NUL bytes and no SELinux identifier contains control
// runes, so such inputs fail up front instead of at exec time.
func validateArgRunes(label, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("invalid %s: not valid UTF-8", label)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid %s %q: control runes are not allowed", label, value)
		}
	}
	return nil
}
