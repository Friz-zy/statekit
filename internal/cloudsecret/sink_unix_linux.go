//go:build linux

package cloudsecret

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func openUnixSink(ctx context.Context, target string) (io.WriteCloser, error) {
	return openUnixSinkWithPeerUID(ctx, target, uint32(os.Geteuid()), peerUID)
}

func openUnixSinkWithPeerUID(ctx context.Context, target string, expectedUID uint32, getPeerUID func(*net.UnixConn) (uint32, error)) (io.WriteCloser, error) {
	if !filepath.IsAbs(target) || filepath.Clean(target) != target || strings.ContainsRune(target, 0) {
		return nil, ErrInvalidSource
	}
	if getPeerUID == nil {
		return nil, ErrSink
	}
	for _, runtimeDir := range []string{
		"/run/docker", "/var/run/docker", "/run/podman", "/var/run/podman",
		"/run/containerd", "/var/run/containerd", "/run/crio", "/var/run/crio",
	} {
		relative, err := filepath.Rel(runtimeDir, target)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil, ErrUnsupported
		}
	}
	switch filepath.Base(target) {
	case "docker.sock", "podman.sock", "containerd.sock", "crio.sock":
		return nil, ErrUnsupported
	}
	info, err := os.Lstat(target)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return nil, ErrSink
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", target)
	if err != nil {
		return nil, ErrSink
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, ErrSink
	}
	uid, err := getPeerUID(unixConnection)
	if err != nil || uid != expectedUID {
		_ = connection.Close()
		return nil, ErrSink
	}
	return unixConnection, nil
}

func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, ErrSink
	}
	var credentials *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || controlErr != nil || credentials == nil {
		return 0, ErrSink
	}
	return credentials.Uid, nil
}
