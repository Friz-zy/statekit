//go:build windows

package ps

import (
	"errors"
	"time"
)

type statfsResult struct {
	blocks uint64
	bfree  uint64
	bsize  int64
}

func statfs(string, *statfsResult) error {
	return errors.New("not supported on windows")
}

func sendSignal(int, int) error {
	return errors.New("not supported on windows")
}

func timeFromUnix(sec int64) time.Time { return time.Unix(sec, 0).UTC() }

func durationSeconds(v float64) time.Duration {
	return time.Duration(v * float64(time.Second))
}
