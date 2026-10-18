//go:build linux

package cloudsecret

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenUnixSinkAuthenticatesSameUIDAndSendsOneFrame(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal("synthetic UDS listener setup failed")
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal("synthetic UDS listener deadline setup failed")
	}
	received := make(chan []byte, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			received <- nil
			return
		}
		defer connection.Close()
		var header [8]byte
		if _, err := io.ReadFull(connection, header[:]); err != nil {
			received <- nil
			return
		}
		length := binary.BigEndian.Uint64(header[:])
		if length > MaxPayloadBytes {
			received <- nil
			return
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(connection, payload); err != nil {
			received <- nil
			return
		}
		var extra [1]byte
		if n, err := connection.Read(extra[:]); n != 0 || err != io.EOF {
			received <- nil
			return
		}
		received <- payload
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := OpenUnixSink(ctx, path)
	if err != nil {
		t.Fatal("same-UID synthetic UDS peer was not authenticated")
	}
	if err := WriteFrame(connection, []byte("synthetic-payload")); err != nil {
		_ = connection.Close()
		t.Fatal("synthetic UDS frame write failed")
	}
	if err := connection.Close(); err != nil {
		t.Fatal("synthetic UDS close failed")
	}
	select {
	case payload := <-received:
		if string(payload) != "synthetic-payload" {
			t.Fatal("synthetic UDS peer received an unexpected frame")
		}
	case <-ctx.Done():
		t.Fatal("synthetic UDS peer did not receive its one frame")
	}
}

func TestOpenUnixSinkRejectsKnownRuntimeSocketNames(t *testing.T) {
	_, err := OpenUnixSink(context.Background(), filepath.Join(t.TempDir(), "docker.sock"))
	if !errors.Is(err, ErrUnsupported) {
		t.Fatal("known runtime socket name was not rejected")
	}
}

func TestOpenUnixSinkRejectsMismatchedPeerUIDBeforeAnyWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal("synthetic UDS listener setup failed")
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal("synthetic UDS listener deadline setup failed")
	}
	observedNoData := make(chan bool, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			observedNoData <- false
			return
		}
		defer connection.Close()
		var value [1]byte
		n, readErr := connection.Read(value[:])
		observedNoData <- n == 0 && readErr == io.EOF
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	currentUID := uint32(os.Geteuid())
	wrongUID := currentUID ^ 1
	_, err = openUnixSinkWithPeerUID(ctx, path, currentUID, func(*net.UnixConn) (uint32, error) {
		return wrongUID, nil
	})
	if !errors.Is(err, ErrSink) {
		t.Fatal("mismatched peer UID was accepted")
	}
	select {
	case noData := <-observedNoData:
		if !noData {
			t.Fatal("mismatched peer received payload bytes")
		}
	case <-ctx.Done():
		t.Fatal("synthetic peer did not observe authenticated connection close")
	}
}
