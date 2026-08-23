// Package bcache implements Salt-compatible BCache set management through
// make-bcache, blkdiscard/dd, bcache-super-show, and the SysFS interface.
//
// Reference: saltstack/salt/modules/bcache.py @ pinned revision.
//
// Contract notes (init.md section 28):
//   - Salt has no unit tests for this module; the StateKit suite pins the
//     source-derived contract hermetically (MemoryFS sysfs trees + fake
//     runner + injected clock), which is the fixture mapping required by
//     plan principle 2.
//   - Missing tools surface boolean false instead of Salt's raised
//     exceptions (transport-level divergence, same observable terminal
//     state for CLI users).
//   - _wait counts tries, sleeping one second before each check exactly
//     like Salt; the sleep goes through an injectable hook so suites stay
//     hermetic. detach/stop pass tries=300, mirroring upstream verbatim.
//   - Shell-string commands are handed to the central cmd.run_all verbatim
//     (no metacharacters are involved upstream either).
//   - cache_make carries Salt's bucket-size quirk: without an explicit
//     bucket_size argument the computed value is immediately overwritten
//     with False upstream (their own TODO marks it broken), so the
//     --bucket flag is omitted unless requested explicitly.
package bcache

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
	execcmd "github.com/friz-zy/statekit/modules/exec/cmd"
	execsysfs "github.com/friz-zy/statekit/modules/exec/sysfs"
)

// linuxOnly restricts this module to linux: every contract runs through
// SysFS and Linux block-device tooling.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// bcSleep is the injectable one-second wait tick used by waitLoop.
var bcSleep = func() { time.Sleep(time.Second) }

// hasBlkdiscard mirrors the module-level HAS_BLKDISCARD probe.
var hasBlkdiscard = func() bool {
	_, err := exec.LookPath("blkdiscard")
	return err == nil
}

// sysfsAttr ports _sysfs_attr: joins the path segments, calls sysfs.attr
// through the registry, and returns false for failures.
func sysfsAttr(ctx context.Context, rt *runtime.Runtime, name []string, value *string) any {
	joined := path.Join(name...)
	res, err := rt.Exec.Call(ctx, rt, "sysfs.attr", &execsysfs.AttrArgs{Key: joined, Value: value})
	if err != nil {
		return false
	}
	return res
}

// devbase ports _devbase: expanded realpath basename.
func devbase(rt *runtime.Runtime, dev string) string {
	if strings.HasPrefix(dev, "$") || strings.Contains(dev, "${") {
		dev = os.ExpandEnv(dev)
	}
	resolved, ok := resolveDevicePath(rt, dev)
	if !ok {
		resolved = dev
	}
	return filepath.Base(resolved)
}

// resolveDevicePath resolves symlink chains like os.path.realpath using the
// runtime FileSystem (best-effort on dangling tails).
func resolveDevicePath(rt *runtime.Runtime, target string) (string, bool) {
	if !filepath.IsAbs(target) {
		target = filepath.Join("/dev", target)
	}
	pending := strings.Split(target, "/")
	cur := ""
	for len(pending) > 0 {
		seg := pending[0]
		pending = pending[1:]
		switch seg {
		case "", ".":
			continue
		case "..":
			if idx := strings.LastIndexByte(cur, '/'); idx > 0 {
				cur = cur[:idx]
			} else {
				cur = ""
			}
			continue
		}
		next := cur + "/" + seg
		info, err := rt.FS.Lstat(next)
		if err != nil {
			cur = next
			continue
		}
		if info.Mode()&os.ModeSymlink == 0 {
			cur = next
			continue
		}
		link, err := rt.FS.Readlink(next)
		if err != nil {
			return "", false
		}
		if filepath.IsAbs(link) {
			cur = ""
			pending = append(strings.Split(link, "/"), pending...)
			continue
		}
		base := ""
		if idx := strings.LastIndexByte(cur, '/'); idx > 0 {
			base = cur[:idx]
		}
		pending = append(strings.Split(filepath.Join(base, link), "/"), pending...)
	}
	if cur == "" {
		cur = "/"
	}
	return cur, true
}

// devpath ports _devpath: /dev/<basename>.
func devpath(rt *runtime.Runtime, dev string) string {
	return path.Join("/dev", devbase(rt, dev))
}

var syspathRe = regexp.MustCompile(`^([vhs][a-z]+)([0-9]+)`)

// syspath ports _syspath: full SysFS path of a device, inserting the
// intermediate directory for disk partitions (sda1 -> sda/sda1).
func syspath(rt *runtime.Runtime, dev string) string {
	base := devbase(rt, dev)
	if m := syspathRe.FindStringSubmatch(base); m != nil {
		base = m[1] + "/" + m[1] + m[2]
	}
	return path.Join("/sys/block/", base)
}

// bcpath ports _bcpath: full SysFS path of a bcache device.
func bcpath(rt *runtime.Runtime, dev string) string {
	return path.Join(syspath(rt, dev), "bcache")
}

// fspath ports _fspath: path of the active cache set.
func fspath(ctx context.Context, rt *runtime.Runtime) string {
	cuuid := uuid(ctx, rt, nil)
	if cuuid == false {
		return ""
	}
	return path.Join("/sys/fs/bcache/", cuuid.(string))
}

// fssys ports _fssys: wrapper around the cache-set SysFS subtree.
func fssys(ctx context.Context, rt *runtime.Runtime, name string, value *string) any {
	fsp := fspath(ctx, rt)
	if fsp == "" {
		return false
	}
	return sysfsAttr(ctx, rt, []string{fsp, name}, value)
}

// bcsys ports _bcsys: wrapper around a backing device's SysFS subtree.
func bcsys(ctx context.Context, rt *runtime.Runtime, dev, name string, value *string) any {
	return sysfsAttr(ctx, rt, []string{bcpath(rt, dev), name}, value)
}

// bdev ports _bdev: resolve a bcacheX (or the active cache) to a real dev.
func bdev(ctx context.Context, rt *runtime.Runtime, dev *string) any {
	var target string
	if dev == nil {
		target = fssysStr(ctx, rt, "cache0")
	} else {
		target = bcpath(rt, *dev)
	}
	if target == "" {
		return false
	}
	return filepath.Base(path.Dir(target))
}

// fssysStr reads an attribute from the cache-set subtree as a string,
// "" standing in for Salt's False.
func fssysStr(ctx context.Context, rt *runtime.Runtime, name string) string {
	res := fssys(ctx, rt, name, nil)
	if s, ok := res.(string); ok {
		return s
	}
	return ""
}

// uuidImpl resolves the bcache UUID; the registered contract lives in
// bcache.go. Without a device it takes the first directory in
// /sys/fs/bcache; with one, the basename of the cache symlink target.
func uuidImpl(ctx context.Context, rt *runtime.Runtime, dev *string) any {
	if dev == nil {
		entries, err := rt.FS.ReadDir("/sys/fs/bcache/")
		if err != nil {
			return false
		}
		for _, entry := range entries {
			if entry.IsDir() {
				return entry.Name()
			}
		}
		return false
	}
	res := bcsys(ctx, rt, *dev, "cache", nil)
	s, ok := res.(string)
	if !ok {
		return false
	}
	return filepath.Base(s)
}

// runAll ports _run_all over the registry's cmd.run_all: True when stdout
// is empty, stdout otherwise, false on a non-matching retcode.
func runAll(ctx context.Context, rt *runtime.Runtime, cmd string, exitcode int) any {
	resRaw, err := rt.Exec.Call(ctx, rt, "cmd.run_all", &execcmd.RunAllArgs{Cmd: cmd})
	if err != nil {
		return false
	}
	res, ok := resRaw.(map[string]any)
	if !ok {
		return false
	}
	retcode, _ := res["retcode"].(int)
	stdout, _ := res["stdout"].(string)
	if retcode == exitcode {
		if stdout != "" {
			return stdout
		}
		return true
	}
	return false
}

// waitLoop ports _wait: sleeps before each check, counting tries.
func waitLoop(cond func() bool, tries int) bool {
	for i := 0; i < tries; i++ {
		bcSleep()
		if cond() {
			return true
		}
	}
	return false
}

// alltrue ports _alltrue: None means nothing to do (success); otherwise at
// least one truthy value is required.
func alltrue(resdict any) bool {
	if resdict == nil {
		return true
	}
	m, ok := resdict.(map[string]any)
	if !ok {
		return false
	}
	for _, val := range m {
		if val != nil && val != false && val != "" {
			return true
		}
	}
	return false
}

var sizeSuffixRe = regexp.MustCompile(`[KkMm]`)

// sizeMap ports _size_map: K/M-suffixed strings to bytes, ints untouched,
// everything unparseable becomes nil.
func sizeMap(size any) any {
	switch t := size.(type) {
	case int:
		return t
	case int64:
		return t
	case string:
		num := sizeSuffixRe.ReplaceAllString(t, "")
		f, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return nil
		}
		if strings.ContainsAny(t, "Kk") {
			f *= 1024
		} else if strings.ContainsAny(t, "Mm") {
			f *= 1024 * 1024
		}
		return int64(f)
	default:
		return nil
	}
}

// sizes ports _sizes: (total size in blocks, blocksize, max discard bytes).
func sizes(ctx context.Context, rt *runtime.Runtime, dev string) (int64, any, any, error) {
	base := devbase(rt, dev)
	keys := []any{
		"size",
		"queue/hw_sector_size",
		"../queue/hw_sector_size",
		"queue/discard_max_bytes",
		"../queue/discard_max_bytes",
	}
	resRaw, err := rt.Exec.Call(ctx, rt, "sysfs.read", &execsysfs.ReadArgs{Key: keys, Root: syspath(rt, base)})
	if err != nil {
		return 0, nil, nil, err
	}
	res, ok := resRaw.(map[string]any)
	if !ok {
		return 0, nil, nil, fmt.Errorf("unable to read SysFS properties for %s", base)
	}
	sizeVal, ok := res["size"].(int64)
	if !ok {
		return 0, nil, nil, fmt.Errorf("unable to read SysFS properties for %s", base)
	}
	discard := pickAlt(res, "queue/discard_max_bytes", "../queue/discard_max_bytes")
	block := pickAlt(res, "queue/hw_sector_size", "../queue/hw_sector_size")
	return 512 * sizeVal, block, discard, nil
}

func pickAlt(m map[string]any, primary, fallback string) any {
	if v, ok := m[primary]; ok {
		return v
	}
	return m[fallback]
}

// wipe ports _wipe: REALLY DESTRUCTIVE STUFF RIGHT AHEAD. Returns whether
// any wiping attempt was made; unreadable SysFS props yield false (Salt's
// None is falsy at every call site).
func wipe(ctx context.Context, rt *runtime.Runtime, dev string) bool {
	base := devbase(rt, dev)
	size, _, discard, err := sizes(ctx, rt, base)
	endres := 0
	if err != nil || discard == nil {
		return false
	}
	discardNum, _ := toInt(discard)
	wiper := ""
	switch {
	case discardNum == 0:
		wiper = "dd"
	case !hasBlkdiscard():
		wiper = "dd"
	default:
		wiper = "blkdiscard"
	}

	switch wiper {
	case "dd":
		const blocks = 4
		cmd := fmt.Sprintf("dd if=/dev/zero of=/dev/%s bs=1M count=%d", base, blocks)
		if runAll(ctx, rt, cmd, 0) != false {
			endres++
		}
		seekCmd := fmt.Sprintf("%s seek=%d", cmd, size/(1024*1024)-blocks)
		if runAll(ctx, rt, seekCmd, 0) != false {
			endres++
		}
	case "blkdiscard":
		cmd := fmt.Sprintf("blkdiscard /dev/%s", base)
		if runAll(ctx, rt, cmd, 0) != false {
			endres++
		}
		// Upstream bug mirrored: the accumulated result is overwritten.
		endres = 1
	}
	return endres > 0
}

func toInt(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		return int64(t), true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}
