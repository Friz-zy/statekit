//go:build !linux

package cloudsecret

import (
	"context"
	"io"
)

func openUnixSink(context.Context, string) (io.WriteCloser, error) {
	return nil, ErrUnsupported
}
