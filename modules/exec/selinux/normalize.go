package selinux

import (
	"fmt"
	"strings"
)

// normalizeMode maps user-facing mode spellings onto canonical names.
func NormalizeMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "enforcing", "1":
		return "Enforcing", nil
	case "permissive", "0":
		return "Permissive", nil
	case "disabled":
		return "Disabled", nil
	default:
		return "", fmt.Errorf("invalid mode %q (want enforcing, permissive, or disabled)", mode)
	}
}
