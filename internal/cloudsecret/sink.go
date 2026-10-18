package cloudsecret

import (
	"context"
	"encoding/binary"
	"io"
)

// WritePayload delivers a single byte-exact payload to one already-selected
// stream. Partial writes are reported as delivery-uncertain and are never
// retried or redirected to another sink.
func WritePayload(writer io.Writer, payload []byte) error {
	if len(payload) > MaxPayloadBytes {
		return ErrInvalidPayload
	}
	return writeAll(writer, payload, 0)
}

// WriteFrame writes one 8-byte unsigned big-endian length and one payload.
func WriteFrame(writer io.Writer, payload []byte) error {
	if len(payload) > MaxPayloadBytes {
		return ErrInvalidPayload
	}
	var header [8]byte
	binary.BigEndian.PutUint64(header[:], uint64(len(payload)))
	if err := writeAll(writer, header[:], 0); err != nil {
		return err
	}
	return writeAll(writer, payload, len(header))
}

// WriteFrameAndClose completes one frame and closes its connection exactly
// once. A close failure after all frame bytes were accepted is delivery-uncertain.
func WriteFrameAndClose(writer io.WriteCloser, payload []byte) error {
	closed := false
	defer func() {
		if !closed {
			_ = closeSink(writer)
		}
	}()
	if err := WriteFrame(writer, payload); err != nil {
		return err
	}
	closed = true
	if closeSink(writer) != nil {
		return ErrDeliveryUncertain
	}
	return nil
}

func closeSink(writer io.Closer) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrSink
		}
	}()
	return writer.Close()
}

func writeAll(writer io.Writer, payload []byte, previouslyDelivered int) error {
	written := 0
	for written < len(payload) {
		n, err := writer.Write(payload[written:])
		if n < 0 || n > len(payload)-written {
			if previouslyDelivered+written > 0 {
				return ErrDeliveryUncertain
			}
			return ErrSink
		}
		written += n
		if err != nil {
			if previouslyDelivered+written > 0 {
				return ErrDeliveryUncertain
			}
			return ErrSink
		}
		if n == 0 {
			if previouslyDelivered+written > 0 {
				return ErrDeliveryUncertain
			}
			return ErrSink
		}
	}
	return nil
}

// OpenUnixSink connects once and authenticates the peer before returning a
// writable connection. Non-Linux builds deliberately fail closed.
func OpenUnixSink(ctx context.Context, target string) (io.WriteCloser, error) {
	return openUnixSink(ctx, target)
}
