//go:build linux || darwin || freebsd || netbsd || openbsd || solaris

package file

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Device-node probing and creation against the real OS filesystem. Device
// metadata cannot be represented by the memory filesystem, so these
// functions bypass the injectable FS (documented divergence).

func isChrdev(name string) bool {
	info, err := os.Stat(name)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func isBlkdev(name string) bool {
	info, err := os.Stat(name)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeDevice != 0 && info.Mode()&os.ModeCharDevice == 0
}

func isFifoDev(name string) bool {
	info, err := os.Stat(name)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeNamedPipe != 0
}

func devmm(name string) (int, int) {
	if !isChrdev(name) && !isBlkdev(name) {
		return 0, 0
	}
	info, err := os.Stat(name)
	if err != nil {
		return 0, 0
	}
	rdev := rdevOf(info)
	return int(minor64(rdev)), int(major64(rdev))
}

func major64(rdev uint64) uint64 {
	return uint64(((rdev >> 8) & 0xfff) | ((rdev >> 32) &^ 0xfff))
}

func minor64(rdev uint64) uint64 {
	return uint64((rdev & 0xff) | ((rdev >> 12) &^ 0xff))
}

// mknodUnix creates the node; EEXIST surfaces as the upstream comment path.
func mknodUnix(name, ntype string, major, minor int, mode string) (map[string]any, error) {
	ret := map[string]any{"name": name, "changes": map[string]any{}, "comment": "", "result": false}
	modeBits, perr := strconv.ParseUint(strings.TrimLeft(mode, "0Oo"), 8, 32)
	if perr != nil {
		modeBits = 0o600
	}
	dev := mkdev(major, minor)
	var err error
	switch ntype {
	case "c":
		err = mknodCall(name, uint32(modeBits)|syscall.S_IFCHR, dev)
	case "b":
		err = mknodCall(name, uint32(modeBits)|syscall.S_IFBLK, dev)
	case "p":
		err = syscall.Mkfifo(name, uint32(modeBits))
	default:
		return ret, fmt.Errorf("Unknown nodetype '%s'. Valid types are 'c', 'p' and 'b'", ntype)
	}
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.EEXIST {
			ret["comment"] = fmt.Sprintf("File %s exists and cannot be overwritten", name)
			return ret, nil
		}
		return ret, err
	}
	label := map[string]string{
		"c": "Character device",
		"b": "Block device",
		"p": "Fifo pipe",
	}[ntype]
	ret["changes"] = map[string]any{"new": fmt.Sprintf("%s %s created.", label, name)}
	ret["result"] = true
	return ret, nil
}

func mkdev(major, minor int) uint64 {
	return uint64(uint64(minor)&0xff | (uint64(major)&0xfff)<<8 | (uint64(minor)&^0xff)<<12)
}

// statRdev extracts the raw device id from a syscall stat structure.
func statRdev(st *syscall.Stat_t) uint64 { return uint64(st.Rdev) }

// rdevOf reads the raw device id from the stat structure.
func rdevOf(info interface{ Sys() any }) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return statRdev(st)
	}
	return 0
}

// parseMknodMode normalizes the octal mode strings like the int(f"{mode}")
// conversions upstream.
func parseMknodMode(mode string) string { return strings.TrimLeft(mode, "0Oo") }
