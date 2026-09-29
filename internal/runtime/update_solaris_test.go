//go:build solaris

package runtime

// R103B-GATE-01/R103B-SEC-01 platform-native fail-closed pin for
// solaris: the pinned x/sys surface has no linkat, so an
// initially-absent target has no atomic no-replace publication
// primitive. This source exists so a native solaris test run (or the
// GOOS=solaris compile gate — the binary is not executed on this host,
// which is not solaris) proves the fail-closed contract directly on
// the platform: creation fails closed with the fixed
// ErrUpdateCreateUnsupported BEFORE anything is staged, the target
// stays absent, and no staging residue can exist, while the
// genuinely-atomic existing-target rename path remains fully
// available.

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestSolarisUpdateAbsentTargetFailsClosed(t *testing.T) {
	if updateNoReplaceSupported {
		t.Fatal("solaris must not claim the atomic no-replace primitive")
	}

	// The defensive seam answers the same fixed sentinel (it must
	// never run, because the transaction fails closed before staging).
	if err := publishStagedNoReplace(-1, "staging", "fresh"); !errors.Is(err, ErrUpdateCreateUnsupported) {
		t.Fatalf("defensive no-replace publish err = %v, want ErrUpdateCreateUnsupported", err)
	}

	// An initially-absent target fails closed before anything is
	// staged: the fixed sentinel, an empty directory, no target.
	dir := t.TempDir()
	target := filepath.Join(dir, "fresh")
	called := false
	transform := func(existing []byte, exists bool) ([]byte, error) {
		called = true
		if exists {
			t.Fatal("absent target reported exists=true")
		}
		return []byte("replacement"), nil
	}
	var fsys OSFileSystem
	err := fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{64, 64}, true, transform)
	if !errors.Is(err, ErrUpdateCreateUnsupported) {
		t.Fatalf("absent-target err = %v, want ErrUpdateCreateUnsupported", err)
	}
	if called {
		t.Fatal("fail-closed creation ran the transform before failing")
	}
	if _, statErr := os.Lstat(target); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("fail-closed create left the target behind: %v", statErr)
	}
	if entries, readErr := os.ReadDir(dir); readErr != nil || len(entries) != 0 {
		t.Fatalf("fail-closed create left files behind: %v (err %v)", entries, readErr)
	}

	// The existing-target path stays available: rename over an
	// identity-revalidated inode is genuinely atomic on solaris.
	existing := filepath.Join(dir, "hosts")
	if err := os.WriteFile(existing, []byte("orig"), 0o644); err != nil {
		t.Fatal(err)
	}
	replace := func(existing []byte, exists bool) ([]byte, error) {
		if !exists || string(existing) != "orig" {
			t.Fatalf("transform saw %q exists=%v", existing, exists)
		}
		return []byte("replacement"), nil
	}
	if err := fsys.UpdateFileBounded(context.Background(), existing, UpdateLimits{64, 64}, false, replace); err != nil {
		t.Fatalf("existing-target update err = %v", err)
	}
	data, err := os.ReadFile(existing)
	if err != nil || string(data) != "replacement" {
		t.Fatalf("existing-target content = %q (err %v)", data, err)
	}
}
