//go:build linux && (statekit_no_sdk_aws || statekit_no_sdks)

package cli

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/cloudsecret"
)

func TestDisabledAWSDoesNotConnectUnixSinkOrFetch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal("synthetic UDS listener setup failed")
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal("synthetic UDS listener deadline setup failed")
	}

	calls := 0
	app := NewApp("test-version", nil)
	app.secretFetch = func(context.Context, cloudsecret.Source) ([]byte, error) {
		calls++
		return []byte("synthetic"), nil
	}
	code, stdout, stderr := captureCode(t, app,
		"exec", "cloud.secret.get", "--source-uri", "secret://aws/secretsmanager/us-east-1/db",
		"--sink", "unix", "--target", path,
	)
	if code != ExitUnsupported || stdout != "" || stderr == "" || calls != 0 {
		t.Fatal("disabled AWS request reached the fetcher or opened the UDS sink")
	}
	connection, err := listener.AcceptUnix()
	if err == nil {
		_ = connection.Close()
		t.Fatal("disabled AWS request connected to the UDS sink")
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatal("UDS listener did not time out while waiting for the disabled request")
	}
}
