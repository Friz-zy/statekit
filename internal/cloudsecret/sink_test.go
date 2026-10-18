package cloudsecret

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

type shortWriter struct {
	max         int
	bytes       bytes.Buffer
	fail        bool
	partialFail bool
}

type closeErrorWriter struct {
	bytes.Buffer
	closeCalls int
}

func (w *closeErrorWriter) Close() error {
	w.closeCalls++
	return errors.New("synthetic close failure")
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if w.fail {
		return 0, errors.New("synthetic write failure")
	}
	if w.partialFail {
		w.partialFail = false
		if len(p) > w.max {
			p = p[:w.max]
		}
		n, _ := w.bytes.Write(p)
		return n, errors.New("synthetic partial write failure")
	}
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.bytes.Write(p)
}

func TestWriteFrameUsesOneBigEndianPayloadLength(t *testing.T) {
	var got bytes.Buffer
	if err := WriteFrame(&got, []byte("payload")); err != nil {
		t.Fatal("valid frame write failed")
	}
	frame := got.Bytes()
	if len(frame) != 8+len("payload") || binary.BigEndian.Uint64(frame[:8]) != uint64(len("payload")) || string(frame[8:]) != "payload" {
		t.Fatal("frame did not match the byte-length wire contract")
	}
}

func TestWriteFrameReportsUncertainAfterPartialDelivery(t *testing.T) {
	writer := &shortWriter{max: 3, partialFail: true}
	err := WriteFrame(writer, []byte("synthetic"))
	if !errors.Is(err, ErrDeliveryUncertain) || writer.bytes.Len() == 0 {
		t.Fatal("partial frame did not return delivery uncertainty")
	}
}

func TestWriteFrameFailsWithoutAnyDelivery(t *testing.T) {
	writer := &shortWriter{fail: true}
	err := WriteFrame(writer, []byte("synthetic"))
	if !errors.Is(err, ErrSink) || writer.bytes.Len() != 0 {
		t.Fatal("undelivered frame did not return the sink failure category")
	}
}

func TestWriteFrameAndCloseReportsUncertaintyWithoutResending(t *testing.T) {
	writer := &closeErrorWriter{}
	payload := []byte("synthetic-payload")
	err := WriteFrameAndClose(writer, payload)
	if !errors.Is(err, ErrDeliveryUncertain) || writer.closeCalls != 1 || writer.Len() != 8+len(payload) || string(writer.Bytes()[8:]) != string(payload) {
		t.Fatal("close failure was not delivery-uncertain after one frame")
	}
}

func TestOversizedFrameIsRejectedBeforeAnyWrite(t *testing.T) {
	writer := &closeErrorWriter{}
	err := WriteFrameAndClose(writer, make([]byte, MaxPayloadBytes+1))
	if !errors.Is(err, ErrInvalidPayload) || writer.Len() != 0 || writer.closeCalls != 1 {
		t.Fatal("oversized frame wrote bytes or failed to close the connection")
	}
}
