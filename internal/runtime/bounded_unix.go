//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package runtime

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const boundedOpenFlags = unix.O_RDONLY | unix.O_CLOEXEC

// readFileBoundedOS walks each path component through a directory descriptor.
// Every parent is opened with O_DIRECTORY|O_NOFOLLOW, and the final component
// is opened with O_NOFOLLOW. This prevents an intermediate symlink from
// redirecting the read outside the path selected by the caller. O_NONBLOCK is
// used only for the final open so special files cannot make validation block.
func readFileBoundedOS(name string, limit int64) ([]byte, error) {
	if err := validateBoundedReadLimit(limit); err != nil {
		return nil, err
	}

	cleaned := filepath.Clean(name)
	base := "."
	if filepath.IsAbs(cleaned) {
		base = string(filepath.Separator)
	}
	parts := strings.Split(cleaned, string(filepath.Separator))
	if filepath.IsAbs(cleaned) && len(parts) > 0 && parts[0] == "" {
		parts = parts[1:]
	}
	parts = compactPathComponents(parts)

	dirfd, err := unix.Open(base, boundedOpenFlags|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dirfd) }()

	if len(parts) == 0 {
		return nil, syscall.EISDIR
	}
	for index, part := range parts {
		if index < len(parts)-1 {
			next, openErr := unix.Openat(dirfd, part,
				boundedOpenFlags|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
			if openErr != nil {
				return nil, openErr
			}
			_ = unix.Close(dirfd)
			dirfd = next
			continue
		}

		fd, openErr := unix.Openat(dirfd, part,
			boundedOpenFlags|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if openErr != nil {
			return nil, openErr
		}
		f := os.NewFile(uintptr(fd), name)
		if f == nil {
			_ = unix.Close(fd)
			return nil, errors.New("runtime: unable to create file descriptor")
		}
		return readBoundedDescriptor(f, limit)
	}
	return nil, syscall.EISDIR
}

// compactPathComponents removes components already normalized by filepath.Clean
// while retaining ordinary names. It keeps the descriptor walk independent of
// path-string resolution after the initial normalization.
func compactPathComponents(parts []string) []string {
	out := parts[:0]
	for _, part := range parts {
		if part != "" && part != "." {
			out = append(out, part)
		}
	}
	return out
}

func readBoundedDescriptor(f *os.File, limit int64) ([]byte, error) {
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, syscall.EISDIR
	}
	if !info.Mode().IsRegular() {
		return nil, ErrNonRegularFile
	}
	if info.Size() > limit {
		return nil, ErrReadLimit
	}

	// The validated finite limit makes this conversion and sentinel allocation
	// safe. One extra byte detects oversized input without allocating it.
	data := make([]byte, int(limit)+1)
	n, err := io.ReadFull(f, data)
	if n == len(data) {
		return nil, ErrReadLimit
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	return data[:n], nil
}
