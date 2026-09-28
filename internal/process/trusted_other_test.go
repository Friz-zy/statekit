//go:build !unix

package process

// Fail-closed coverage for platforms without the unix ownership
// metadata the trust check requires (R102-FINAL-02): resolution must
// reject every name — including the canonical dig helper — with
// ErrTrustedCommandUnsupported, answer an empty path, and never fall
// back to PATH or start a process.

import (
	"errors"
	"testing"
)

func TestTrustedCommandUnsupportedPlatformFailsClosed(t *testing.T) {
	runner := DefaultRunner{}
	for _, name := range []string{"dig", "ps", "mysql", "dig.sh", "", "./dig", "/usr/bin/dig"} {
		path, err := runner.ResolveTrustedCommand(name)
		if path != "" {
			t.Fatalf("ResolveTrustedCommand(%q) = %q; want empty path", name, path)
		}
		if !errors.Is(err, ErrTrustedCommandUnsupported) {
			t.Fatalf("ResolveTrustedCommand(%q) err = %v, want ErrTrustedCommandUnsupported", name, err)
		}
	}
}
