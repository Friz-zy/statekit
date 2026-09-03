//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReadFileBoundedOSWalksComponentsAndRejectsSpecialFiles(t *testing.T) {
	if err := os.MkdirAll(".gotmp", 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(".gotmp", "bounded-walk-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	nested := filepath.Join(root, "one", "two")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(nested, "value")
	if err := os.WriteFile(target, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readFileBoundedOS(target, 16)
	if err != nil || string(data) != "safe" {
		t.Fatalf("nested regular read = %q, %v", data, err)
	}

	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	outsideTarget := filepath.Join(outside, "value")
	if err := os.WriteFile(outsideTarget, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(root, "one", "redirect")
	if err := os.Symlink(outside, parentLink); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileBoundedOS(filepath.Join(parentLink, "value"), 16); err == nil {
		t.Fatal("parent symlink was accepted")
	}

	finalLink := filepath.Join(root, "final-link")
	if err := os.Symlink(target, finalLink); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileBoundedOS(finalLink, 16); err == nil {
		t.Fatal("final symlink was accepted")
	}

	fifo := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileBoundedOS(fifo, 16); !errors.Is(err, ErrNonRegularFile) {
		t.Fatalf("FIFO error = %v", err)
	}
}

func TestReadFileBoundedOSRejectsCharacterDeviceWithoutBlocking(t *testing.T) {
	info, err := os.Lstat("/dev/null")
	if err != nil {
		t.Fatalf("lstat container character device: %v", err)
	}
	if info.Mode().IsRegular() || info.Mode()&os.ModeCharDevice == 0 {
		t.Fatalf("/dev/null mode = %v, want character device", info.Mode())
	}

	done := make(chan error, 1)
	go func() {
		_, err := readFileBoundedOS("/dev/null", 16)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNonRegularFile) {
			t.Fatalf("character device error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("character device read blocked")
	}
}

func TestReadBoundedDescriptorUsesOpenedFileAfterReplacement(t *testing.T) {
	if err := os.MkdirAll(".gotmp", 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(".gotmp", "bounded-replacement-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	name := filepath.Join(root, "value")
	replacement := filepath.Join(root, "replacement")
	if err := os.WriteFile(name, []byte("opened"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := os.Rename(replacement, name); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	data, err := readBoundedDescriptor(f, 32)
	if err != nil || string(data) != "opened" {
		t.Fatalf("opened descriptor read = %q, %v", data, err)
	}
}
