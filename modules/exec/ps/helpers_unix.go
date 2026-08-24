//go:build !windows

package ps

import (
	"syscall"
	"time"
)

type statfsResult struct {
	blocks uint64
	bfree  uint64
	bsize  int64
}

func statfs(path string, out *statfsResult) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return err
	}
	out.blocks = st.Blocks
	out.bfree = st.Bfree
	out.bsize = int64(st.Bsize)
	return nil
}

func sendSignal(pid, signal int) error {
	return syscall.Kill(pid, syscall.Signal(signal))
}

func timeFromUnix(sec int64) time.Time { return time.Unix(sec, 0).UTC() }

func durationSeconds(v float64) time.Duration {
	return time.Duration(v * float64(time.Second))
}
