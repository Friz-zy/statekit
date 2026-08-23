package bcache

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
	execsysfs "github.com/friz-zy/statekit/modules/exec/sysfs"
	execudev "github.com/friz-zy/statekit/modules/exec/udev"
)

// wsSplitRe mirrors re.split(r"[\s]+", s, maxsplit=n).
var wsSplitRe = regexp.MustCompile(`[\s]+`)

// uuidArgs mirrors Salt's uuid signature; the omitted device queries the
// active cache set (tri-state pointer preserving value=None).
type uuidArgs struct {
	Dev *string `statekit:"name=dev"`
}

type uuidFunc struct {
	linuxOnly
}

func (uuidFunc) Name() string { return "bcache.uuid" }
func (uuidFunc) Args() any    { return uuidArgs{} }
func (uuidFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return uuid(ctx, rt, args.(*uuidArgs).Dev), nil
}

// uuid resolves the bcache UUID of a device or the active cache set;
// failures are boolean false like Salt's broad except.
func uuid(ctx context.Context, rt *runtime.Runtime, dev *string) any {
	return uuidImpl(ctx, rt, dev)
}

type attachArgs struct {
	Dev *string `statekit:"name=dev"`
}

type attachFunc struct {
	linuxOnly
}

func (attachFunc) Name() string { return "bcache.attach" }
func (attachFunc) Args() any    { return attachArgs{} }

// Execute attaches a backing device to a cache set; without dev all
// backing devices are attached. None (nil) means nothing happened.
func (attachFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*attachArgs)

	cache := uuid(ctx, rt, nil)
	if cache == false {
		return false, nil
	}

	if a.Dev == nil {
		res := map[string]any{}
		statusAll, _ := statusMap(ctx, rt, false, false, false, false, true).(map[string]any)
		for devName, dataRaw := range statusAll {
			data, ok := dataRaw.(map[string]any)
			if !ok {
				continue
			}
			if _, hasCache := data["cache"]; hasCache {
				devCopy := devName
				res[devName] = attachOne(ctx, rt, &devCopy, cache.(string))
			}
		}
		if len(res) == 0 {
			return nil, nil
		}
		return res, nil
	}
	return attachOne(ctx, rt, a.Dev, cache.(string)), nil
}

func attachOne(ctx context.Context, rt *runtime.Runtime, dev *string, cache string) any {
	bcacheUUID := uuid(ctx, rt, dev)
	if bcacheUUID != false {
		if bcacheUUID == cache {
			return nil
		}
		df := detachFunc{}
		if detached, _ := df.Execute(ctx, rt, &detachArgs{Dev: dev}); detached == false {
			return false
		}
	}
	cacheVal := cache
	if sysfsAttr(ctx, rt, []string{bcpath(rt, *dev), "attach"}, &cacheVal) == false {
		return false
	}
	return waitLoop(func() bool { return uuid(ctx, rt, dev) == cache }, 10)
}

type detachArgs struct {
	Dev *string `statekit:"name=dev"`
}

type detachFunc struct {
	linuxOnly
}

func (detachFunc) Name() string { return "bcache.detach" }
func (detachFunc) Args() any    { return detachArgs{} }

func (detachFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*detachArgs)
	if a.Dev == nil {
		res := map[string]any{}
		statusAll, _ := statusMap(ctx, rt, false, false, false, false, true).(map[string]any)
		for devName, dataRaw := range statusAll {
			data, ok := dataRaw.(map[string]any)
			if !ok {
				continue
			}
			if _, hasCache := data["cache"]; hasCache {
				devCopy := devName
				res[devName] = detachOne(ctx, rt, &devCopy)
			}
		}
		if len(res) == 0 {
			return nil, nil
		}
		return res, nil
	}
	return detachOne(ctx, rt, a.Dev), nil
}

func detachOne(ctx context.Context, rt *runtime.Runtime, dev *string) any {
	goaway := "goaway"
	if sysfsAttr(ctx, rt, []string{bcpath(rt, *dev), "detach"}, &goaway) == false {
		return false
	}
	return waitLoop(func() bool { return uuid(ctx, rt, dev) == false }, 300)
}

type startArgs struct{}

type startFunc struct {
	linuxOnly
}

func (startFunc) Name() string { return "bcache.start" }
func (startFunc) Args() any    { return startArgs{} }
func (startFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	if runAll(ctx, rt, "udevadm trigger", 0) == false {
		return false, nil
	}
	if !waitLoop(func() bool { return uuid(ctx, rt, nil) != false }, 10) {
		return false, nil
	}
	return true, nil
}

type stopArgs struct {
	Dev *string `statekit:"name=dev"`
}

type stopFunc struct {
	linuxOnly
}

func (stopFunc) Name() string { return "bcache.stop" }
func (stopFunc) Args() any    { return stopArgs{} }

func (stopFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*stopArgs)
	if a.Dev != nil {
		goaway := "goaway"
		if sysfsAttr(ctx, rt, []string{bcpath(rt, *a.Dev), "stop"}, &goaway) == false {
			return false, nil
		}
		return waitLoop(func() bool { return sysfsAttr(ctx, rt, []string{bcpath(rt, *a.Dev)}, nil) == false }, 300), nil
	}

	cache := uuid(ctx, rt, nil)
	if cache == false {
		return nil, nil
	}

	df := detachFunc{}
	detached, err := df.Execute(ctx, rt, &detachArgs{})
	if err != nil || !alltrue(detached) {
		return false, nil
	}
	goaway := "goaway"
	if fssys(ctx, rt, "stop", &goaway) == false {
		return false, nil
	}
	return waitLoop(func() bool { return uuid(ctx, rt, nil) == false }, 300), nil
}

type backMakeArgs struct {
	Dev        string  `statekit:"required,name=dev"`
	CacheMode  *string `statekit:"name=cache_mode"`
	Force      bool    `statekit:"name=force"`
	Attach     *bool   `statekit:"name=attach"`
	BucketSize *string `statekit:"name=bucket_size"`
}

type backMakeFunc struct {
	linuxOnly
}

func (backMakeFunc) Name() string { return "bcache.back_make" }
func (backMakeFunc) Args() any    { return backMakeArgs{} }

// Execute creates a backing device for attachment to an existing set.
func (backMakeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*backMakeArgs)
	cacheMode := "writeback"
	if a.CacheMode != nil {
		cacheMode = *a.CacheMode
	}
	attach := true
	if a.Attach != nil {
		attach = *a.Attach
	}

	cache := uuid(ctx, rt, nil)
	if cache == false {
		return false, nil
	}
	if existing := sysfsAttr(ctx, rt, []string{bcpath(rt, a.Dev)}, nil); existing != false {
		if !a.Force {
			return false, nil
		}
		if u := uuid(ctx, rt, &a.Dev); u != false {
			df := detachFunc{}
			if d, err := df.Execute(ctx, rt, &detachArgs{Dev: &a.Dev}); err != nil || d == false {
				return false, nil
			}
		}
		sf := stopFunc{}
		if stopped, err := sf.Execute(ctx, rt, &stopArgs{Dev: &a.Dev}); err != nil || stopped == false {
			return false, nil
		}
	}

	dev := devpath(rt, a.Dev)
	blockSize := sizeMap(fssys(ctx, rt, "block_size", nil))
	bucketSize := sizeMap(fssys(ctx, rt, "bucket_size", nil))
	if a.BucketSize != nil {
		bucketSize = sizeMap(*a.BucketSize)
	}

	cmd := fmt.Sprintf("make-bcache --block %s --bucket %s --%s --bdev %s",
		formatSize(blockSize), formatSize(bucketSize), cacheMode, dev)
	if a.Force {
		cmd += " --wipe-bcache"
	}
	if runAll(ctx, rt, cmd, 0) == false {
		return false, nil
	}
	registerVal := dev
	if sysfsAttr(ctx, rt, []string{"fs/bcache/register"}, &registerVal) == false {
		return false, nil
	}
	if !waitLoop(func() bool { return sysfsAttr(ctx, rt, []string{bcpath(rt, dev)}, nil) != false }, 10) {
		return false, nil
	}
	if attach {
		af := attachFunc{}
		return af.Execute(ctx, rt, &attachArgs{Dev: &dev})
	}
	return true, nil
}

// formatSize renders size values into the shell command like Salt's str().
func formatSize(v any) string {
	switch t := v.(type) {
	case bool:
		if t {
			return "True"
		}
		return "False"
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	default:
		return fmt.Sprintf("%v", t)
	}
}

type cacheMakeArgs struct {
	Dev        string  `statekit:"required,name=dev"`
	Reserved   *string `statekit:"name=reserved"`
	Force      bool    `statekit:"name=force"`
	BlockSize  *string `statekit:"name=block_size"`
	BucketSize *string `statekit:"name=bucket_size"`
	Attach     *bool   `statekit:"name=attach"`
}

type cacheMakeFunc struct {
	linuxOnly
}

func (cacheMakeFunc) Name() string { return "bcache.cache_make" }
func (cacheMakeFunc) Args() any    { return cacheMakeArgs{} }

// Execute creates a BCache cache on a block device.
func (cacheMakeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*cacheMakeArgs)
	attach := true
	if a.Attach != nil {
		attach = *a.Attach
	}

	cache := uuid(ctx, rt, nil)
	if cache != false {
		if !a.Force {
			return false, nil
		}
		cache = bdev(ctx, rt, nil)
	}

	dev := devbase(rt, a.Dev)

	envRaw, err := rt.Exec.Call(ctx, rt, "udev.env", &execudev.EnvArgs{Dev: "/dev/" + dev})
	if err != nil {
		return nil, err
	}
	udev, _ := envRaw.(map[string]any)
	if udev == nil {
		udev = map[string]any{}
	}

	devtype, hasDevtype := udev["DEVTYPE"].(string)
	if _, hasFSType := udev["ID_FS_TYPE"]; hasFSType {
		if !a.Force {
			return false, nil
		}
	} else if (!hasDevtype || devtype != "partition") && func() bool {
		_, has := udev["ID_PART_TABLE_TYPE"]
		return has
	}() && !a.Force {
		return false, nil
	}
	if a.Reserved != nil && (!hasDevtype || devtype != "disk") {
		return false, nil
	}

	_, block, _, err := sizes(ctx, rt, dev)
	if err != nil {
		return false, nil
	}

	// Upstream quirk mirrored: the computed bucket is immediately
	// discarded, so --bucket only appears when explicitly requested.
	effectiveBucket := ""
	if a.BucketSize != nil {
		effectiveBucket = *a.BucketSize
	}
	blockSize := ""
	if a.BlockSize != nil {
		blockSize = *a.BlockSize
	} else {
		blockSize = fmt.Sprintf("%v", block)
	}

	if cache != false {
		sf := stopFunc{}
		if stopped, serr := sf.Execute(ctx, rt, &stopArgs{}); serr != nil || stopped == false {
			return false, nil
		}
		if !wipe(ctx, rt, cache.(string)) {
			return false, nil
		}
	}

	if !wipe(ctx, rt, dev) {
		return false, nil
	}

	if a.Reserved != nil {
		cmd := fmt.Sprintf(
			"parted -m -s -a optimal -- /dev/%s mklabel gpt mkpart bcache-reserved 1M %s mkpart bcache %s 100%%",
			dev, *a.Reserved, *a.Reserved)
		if runAll(ctx, rt, cmd, 0) == false {
			return false, nil
		}
		dev = dev + "2"
	}

	cmd := fmt.Sprintf("make-bcache --cache /dev/%s --block %s --wipe-bcache", dev, blockSize)
	if effectiveBucket != "" && effectiveBucket != "False" {
		cmd += " --bucket " + effectiveBucket
	}
	if runAll(ctx, rt, cmd, 0) == false {
		return false, nil
	}
	if !waitLoop(func() bool { return uuid(ctx, rt, nil) != false }, 10) {
		return false, nil
	}

	if attach {
		af := attachFunc{}
		res, aerr := af.Execute(ctx, rt, &attachArgs{})
		if aerr != nil {
			return false, nil
		}
		return alltrue(res), nil
	}
	return true, nil
}

type configArgs struct {
	Dev    *string        `statekit:"name=dev"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type configFunc struct {
	linuxOnly
}

func (configFunc) Name() string { return "bcache.config" }
func (configFunc) Args() any    { return configArgs{} }

// Execute shows or updates the config of a bcache device; kwargs are only
// reachable through structured input.
func (configFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*configArgs)
	var spath string
	if a.Dev == nil {
		spath = fspath(ctx, rt)
	} else {
		spath = bcpath(rt, *a.Dev)
	}

	updates := map[string]string{}
	for key, val := range a.Kwargs {
		if strings.HasPrefix(key, "__") {
			continue
		}
		updates[key] = fmt.Sprintf("%v", val)
	}

	if len(updates) > 0 {
		endres := 0
		for key, val := range updates {
			res := sysfsAttr(ctx, rt, []string{spath, key}, &val)
			if res != false {
				endres++
			}
		}
		return endres > 0, nil
	}

	data := sysfsParse(ctx, rt, spath, nil, false, true, true, true)
	delete(data, "other_ro")
	delete(data, "inter_ro")

	result := map[string]any{}
	for _, sectionRaw := range data {
		section, ok := sectionRaw.(map[string]any)
		if !ok {
			continue
		}
		for key, val := range section {
			result[key] = val
		}
	}
	return result, nil
}

type statusArgs struct {
	Stats      bool `statekit:"name=stats"`
	Config     bool `statekit:"name=config"`
	Internals  bool `statekit:"name=internals"`
	Superblock bool `statekit:"name=superblock"`
	AllDevs    bool `statekit:"name=alldevs"`
}

type statusFunc struct {
	linuxOnly
}

func (statusFunc) Name() string { return "bcache.status" }
func (statusFunc) Args() any    { return statusArgs{} }
func (statusFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*statusArgs)
	res := statusMap(ctx, rt, a.Stats, a.Config, a.Internals, a.Superblock, a.AllDevs)
	return res, nil
}

// statusMap ports bcache.status: discovers bcache devices under /sys/block,
// reports each via device(), and narrows to the active cache device unless
// alldevs requests everything.
func statusMap(ctx context.Context, rt *runtime.Runtime, stats, config, internals, superblock, alldevs bool) any {
	var bdevs []string
	if entries, err := rt.FS.ReadDir("/sys/block/"); err == nil {
		for _, entry := range entries {
			block := entry.Name()
			if strings.Contains(block, "bcache") {
				continue
			}
			walkBlockDirs(rt, path.Join("/sys/block/", block), func(spath string, sdirs []string) {
				for _, sdir := range sdirs {
					if strings.Contains(sdir, "bcache") {
						bdevs = append(bdevs, filepath.Base(spath))
						return
					}
				}
			})
		}
	}

	statii := map[string]any{}
	for _, bcache := range bdevs {
		statii[bcache] = deviceImpl(ctx, rt, bcache, stats, config, internals, superblock)
	}

	cuuid := uuid(ctx, rt, nil)
	cdevRaw := bdev(ctx, rt, nil)
	cdev, cdevOK := cdevRaw.(string)
	if cdevOK {
		count := 0
		for dev, dataRaw := range statii {
			if dev == cdev {
				continue
			}
			data, ok := dataRaw.(map[string]any)
			if !ok {
				continue
			}
			if data["cache"] == cuuid {
				count++
			}
		}
		// Discovery skips names containing "bcache", so the cache device
		// itself is absent from statii; Salt's unconditional index would
		// KeyError here. StateKit synthesizes the entry instead
		// (documented divergence).
		cdata, ok := statii[cdev].(map[string]any)
		if !ok {
			cdata = map[string]any{}
			statii[cdev] = cdata
		}
		cdata["attached_backing_devices"] = count
		if !alldevs {
			return statii[cdev]
		}
	}
	return statii
}

// walkBlockDirs mirrors salt.utils.path.os_walk(followlinks=False): the
// callback receives each directory and its immediate subdirectory names.
// Symlinked subdirectories appear in the names but are not descended,
// matching scandir's follow-symlinks dir classification.
func walkBlockDirs(rt *runtime.Runtime, root string, fn func(spath string, sdirs []string)) {
	entries, err := rt.FS.ReadDir(root)
	if err != nil {
		return
	}
	var sdirs []string
	var descend []string
	for _, entry := range entries {
		full := root + "/" + entry.Name()
		isSymlink := entry.Type()&fs.ModeSymlink != 0
		isDirEntry := false
		if isSymlink {
			if info, serr := rt.FS.Stat(full); serr == nil && info.IsDir() {
				isDirEntry = true
			}
		} else if entry.IsDir() {
			isDirEntry = true
		}
		if !isDirEntry {
			continue
		}
		sdirs = append(sdirs, entry.Name())
		if !isSymlink {
			descend = append(descend, entry.Name())
		}
	}
	fn(root, sdirs)
	for _, name := range descend {
		walkBlockDirs(rt, root+"/"+name, fn)
	}
}

type deviceArgs struct {
	Dev        string `statekit:"required,name=dev"`
	Stats      bool   `statekit:"name=stats"`
	Config     bool   `statekit:"name=config"`
	Internals  bool   `statekit:"name=internals"`
	Superblock bool   `statekit:"name=superblock"`
}

type deviceFunc struct {
	linuxOnly
}

func (deviceFunc) Name() string { return "bcache.device" }
func (deviceFunc) Args() any    { return deviceArgs{} }
func (deviceFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*deviceArgs)
	return deviceImpl(ctx, rt, a.Dev, a.Stats, a.Config, a.Internals, a.Superblock), nil
}

var statsPrefixRe = regexp.MustCompile(`(stats|cache)_`)
var internalPrefixRe = regexp.MustCompile(`^internal[s/]*`)

// deviceImpl ports bcache.device: distinguishes cache sets from backing
// devices, then applies the stats/internals/config/superblock reshaping.
func deviceImpl(ctx context.Context, rt *runtime.Runtime, dev string, stats, config, internals, superblock bool) any {
	result := map[string]any{}

	if sysfsAttr(ctx, rt, []string{bcpath(rt, dev)}, nil) == false {
		return false
	}
	if setRes := bcsys(ctx, rt, dev, "set", nil); setRes != false {
		// The device is the cache itself.
		result["uuid"] = uuid(ctx, rt, nil)
		baseAttr := []string{
			"block_size",
			"bucket_size",
			"cache_available_percent",
			"cache_replacement_policy",
			"congested",
		}
		mergeInto(result, sysfsParse(ctx, rt, bcpath(rt, dev), baseAttr, stats, config, internals, false))
		mergeInto(result, sysfsParse(ctx, rt, fspath(ctx, rt), baseAttr, stats, config, internals, false))
		if base, ok := result["base"].(map[string]any); ok {
			mergeInto(result, base)
			delete(result, "base")
		}
	} else {
		// It's a backing device. uuid() never returns None upstream, so
		// the cache key is set unconditionally (False included).
		result["cache"] = uuid(ctx, rt, &dev)
		if devRes := bcsys(ctx, rt, dev, "dev", nil); devRes != false {
			if s, ok := devRes.(string); ok {
				result["dev"] = filepath.Base(s)
			}
		}
		result["bdev"] = bdev(ctx, rt, &dev)

		baseAttr := []string{"cache_mode", "running", "state", "writeback_running"}
		basePath := bcpath(rt, dev)
		mergeInto(result, sysfsParse(ctx, rt, basePath, baseAttr, stats, config, internals, false))
		if base, ok := result["base"].(map[string]any); ok {
			mergeInto(result, base)
			delete(result, "base")
		}

		state := []any{result["state"]}
		if running, _ := result["running"].(bool); running {
			state = append(state, "running")
		} else {
			state = append(state, "stopped")
		}
		delete(result, "running")
		if wbRaw, has := result["writeback_running"]; has {
			wb, _ := wbRaw.(bool)
			delete(result, "writeback_running")
			if wb {
				state = append(state, "writeback_running")
			} else {
				state = append(state, "writeback_stopped")
			}
		}
		result["state"] = state
	}

	// Statistics re-keying.
	if rawStats, has := result["stats"]; has {
		statres := map[string]any{}
		if m, ok := rawStats.(map[string]any); ok {
			for attr, val := range m {
				if !strings.Contains(attr, "/") {
					statres[statsPrefixRe.ReplaceAllString(attr, "")] = val
					continue
				}
				parts := strings.SplitN(attr, "/", 2)
				group := statsPrefixRe.ReplaceAllString(parts[0], "")
				key := statsPrefixRe.ReplaceAllString(parts[1], "")
				sub, _ := statres[group].(map[string]any)
				if sub == nil {
					sub = map[string]any{}
					statres[group] = sub
				}
				sub[key] = val
			}
		}
		result["stats"] = statres
	}

	// Internals regrouping.
	if internals {
		interres, _ := result["inter_ro"].(map[string]any)
		if interres == nil {
			interres = map[string]any{}
		}
		delete(result, "inter_ro")
		if rw, ok := result["inter_rw"].(map[string]any); ok {
			for k, v := range rw {
				interres[k] = v
			}
		}
		delete(result, "inter_rw")
		if len(interres) > 0 {
			// First pass normalizes keys on a copy so no map is mutated while
			// being ranged over; second pass nests btree_*/writeback_* groups.
			flat := make(map[string]any, len(interres))
			for key, val := range interres {
				flat[internalPrefixRe.ReplaceAllString(key, "")] = val
			}
			interres = map[string]any{}
			for key, val := range flat {
				nested := false
				for _, prefix := range []string{"btree", "writeback"} {
					if strings.HasPrefix(key, prefix+"_") {
						skey := strings.SplitN(key, "_", 2)[1]
						m, _ := interres[prefix].(map[string]any)
						if m == nil {
							m = map[string]any{}
							interres[prefix] = m
						}
						m[skey] = val
						nested = true
						break
					}
				}
				if !nested {
					interres[key] = val
				}
			}
			result["internals"] = interres
		}
	}

	// Config regrouping.
	if config {
		configres, _ := result["config"].(map[string]any)
		if configres != nil {
			for key, val := range configres {
				if strings.HasPrefix(key, "writeback_") {
					parts := strings.SplitN(key, "_", 2)
					m, _ := configres[parts[0]].(map[string]any)
					if m == nil {
						m = map[string]any{}
						configres[parts[0]] = m
					}
					m[parts[1]] = val
					delete(configres, key)
				}
			}
			result["config"] = configres
		}
	}

	if superblock {
		sf := superFunc{}
		res, _ := sf.Execute(ctx, rt, &superArgs{Dev: dev})
		result["superblock"] = res
	}

	return result
}

func mergeInto(dst, src map[string]any) {
	for k, v := range src {
		dst[k] = v
	}
}

type superArgs struct {
	Dev string `statekit:"required,name=dev"`
}

type superFunc struct {
	linuxOnly
}

func (superFunc) Name() string { return "bcache.super" }
func (superFunc) Args() any    { return superArgs{} }

// Execute reads out the BCache superblock through bcache-super-show.
func (superFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*superArgs)
	dev := devpath(rt, a.Dev)
	res := runAll(ctx, rt, "bcache-super-show "+dev, 0)
	if res == false {
		return false, nil
	}
	ret := map[string]any{}
	for _, line := range strings.Split(res.(string), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := splitMax(line, 1)
		if len(fields) != 2 {
			continue
		}
		key := strings.TrimSpace(fields[0])
		val := strings.TrimSpace(fields[1])
		if key == "" || val == "" {
			continue
		}

		var mval string
		hasMval := false
		rval := val
		if strings.Contains(val, " ") {
			parts := splitMax(val, 1)
			rval = strings.TrimSpace(parts[0])
			if len(parts) == 2 {
				mval = strings.TrimSpace(parts[1])
				mval = strings.TrimSuffix(strings.TrimPrefix(mval, "["), "]")
				hasMval = true
			}
		}

		coerced := coerceSuperValue(rval)

		// The key hierarchy splits on DOTS (re.split(r"\.", key,
		// maxsplit=1)), unlike the whitespace split above.
		dotParts := strings.SplitN(key, ".", 2)
		if len(dotParts) != 2 {
			continue
		}
		pkey, skey := dotParts[0], dotParts[1]
		section, _ := ret[pkey].(map[string]any)
		if section == nil {
			section = map[string]any{}
			ret[pkey] = section
		}
		if hasMval {
			section[skey] = []any{coerced, mval}
		} else {
			section[skey] = coerced
		}
	}
	return ret, nil
}

// splitMax splits on runs of whitespace with at most n splits, mirroring
// re.split(r"[\s]+", s, maxsplit=n).
func splitMax(s string, n int) []string {
	return wsSplitRe.Split(s, n+1)
}

func coerceSuperValue(val string) any {
	if parsed, err := strconv.ParseInt(val, 10, 64); err == nil {
		return parsed
	}
	if parsed, err := strconv.ParseFloat(val, 64); err == nil {
		return parsed
	}
	switch val {
	case "yes":
		return true
	case "no":
		return false
	default:
		return val
	}
}

// sysfsParse ports _sysfs_parse: classifies the interface list, fetches
// values in one read, and applies the well-known coercions.
func sysfsParse(ctx context.Context, rt *runtime.Runtime, spath string, baseAttr []string, stats, config, internals, options bool) map[string]any {
	result := map[string]any{}

	intfsRaw, err := rt.Exec.Call(ctx, rt, "sysfs.interfaces", &execsysfs.InterfacesArgs{Root: spath})
	intfs := map[string][]string{}
	if err == nil {
		if m, ok := intfsRaw.(map[string]any); ok {
			for _, group := range []string{"r", "rw", "w"} {
				list, _ := m[group].([]any)
				names := make([]string, 0, len(list))
				for _, item := range list {
					names = append(names, item.(string))
				}
				intfs[group] = names
			}
		}
	}
	// Actions are ignored.

	binkeys := []string{}
	if internals {
		binkeys = append(binkeys, "inter_ro", "inter_rw")
	}
	if config {
		binkeys = append(binkeys, "config")
	}
	if stats {
		binkeys = append(binkeys, "stats")
	}
	bintf := map[string][]string{}
	for _, key := range binkeys {
		bintf[key] = []string{}
	}

	for _, intf := range intfs["r"] {
		var key string
		switch {
		case strings.HasPrefix(intf, "internal"):
			key = "inter_ro"
		case strings.Contains(intf, "stats"):
			key = "stats"
		default:
			key = "inter_ro"
		}
		if _, known := bintf[key]; known {
			bintf[key] = append(bintf[key], intf)
		}
	}
	for _, intf := range intfs["rw"] {
		key := "config"
		if strings.HasPrefix(intf, "internal") {
			key = "inter_rw"
		}
		if _, known := bintf[key]; known {
			bintf[key] = append(bintf[key], intf)
		}
	}

	if baseAttr != nil {
		for key := range bintf {
			filtered := bintf[key][:0]
			for _, sintf := range bintf[key] {
				keep := true
				for _, base := range baseAttr {
					if sintf == base {
						keep = false
						break
					}
				}
				if keep {
					filtered = append(filtered, sintf)
				}
			}
			bintf[key] = filtered
		}
		bintf["base"] = baseAttr
	}

	// Move well-known statistics keys into the stats bucket.
	mods := []string{
		"internal/bset_tree_stats",
		"writeback_rate_debug",
		"metadata_written",
		"nbuckets",
		"written",
		"average_key_size",
		"btree_cache_size",
	}
	if _, hasStats := bintf["stats"]; hasStats {
		var found []string
		for _, mod := range mods {
			for key, intflist := range bintf {
				for i, intf := range intflist {
					if intf == mod {
						found = append(found, mod)
						bintf[key] = append(intflist[:i], intflist[i+1:]...)
						break
					}
				}
			}
		}
		bintf["stats"] = append(bintf["stats"], found...)
	}

	// Fetch SysFS values in one read over every classified interface.
	keys := []any{}
	for _, intflist := range bintf {
		for _, intf := range intflist {
			keys = append(keys, intf)
		}
	}
	readRes, rerr := rt.Exec.Call(ctx, rt, "sysfs.read", &execsysfs.ReadArgs{Key: keys, Root: spath})
	if rerr == nil {
		if m, ok := readRes.(map[string]any); ok {
			for k, v := range m {
				result[k] = v
			}
		}
	}

	// Well-known multi-line string lists become key/value maps.
	for _, strlist := range []string{"writeback_rate_debug", "internal/bset_tree_stats", "priority_stats"} {
		raw, ok := result[strlist].(string)
		if !ok {
			continue
		}
		listres := map[string]any{}
		for _, line := range strings.Split(raw, "\n") {
			kv := strings.SplitN(line, ":", 2)
			if len(kv) != 2 {
				continue
			}
			listres[strings.TrimSpace(kv[0])] = coerceNumberUdev(strings.TrimSpace(kv[1]))
		}
		result[strlist] = listres
	}

	// Selection lists keep only the bracketed selection.
	if !options {
		for _, sellist := range []string{"cache_mode", "cache_replacement_policy", "errors"} {
			if raw, ok := result[sellist].(string); ok {
				if m := regexp.MustCompile(`\[(.+)\]`).FindStringSubmatch(raw); m != nil {
					result[sellist] = m[1]
				}
			}
		}
	}

	// Well-known bools.
	for _, boolkey := range []string{"running", "writeback_running", "congested"} {
		if raw, ok := result[boolkey]; ok {
			result[boolkey] = truthyNum(raw)
		}
	}

	// Recategorize results by interface type.
	bresult := map[string]any{}
	for iftype, intflist := range bintf {
		ifres := map[string]any{}
		for _, intf := range intflist {
			if val, ok := result[intf]; ok {
				ifres[intf] = val
				delete(result, intf)
			}
		}
		if len(ifres) > 0 {
			bresult[iftype] = ifres
		}
	}
	return bresult
}

// coerceNumberUdev shares the int-then-float coercion used across parsers.
func coerceNumberUdev(val string) any {
	if parsed, err := strconv.ParseInt(val, 10, 64); err == nil {
		return parsed
	}
	if parsed, err := strconv.ParseFloat(val, 64); err == nil {
		return parsed
	}
	return val
}

// truthyNum mirrors bool(result[n]) for numeric attribute values.
func truthyNum(v any) bool {
	switch t := v.(type) {
	case int64:
		return t != 0
	case int:
		return t != 0
	case float64:
		return t != 0
	case string:
		return t != "" && t != "0"
	case bool:
		return t
	default:
		return v != nil
	}
}

// Register installs all bcache-module execution functions under their
// CLI-facing __func_alias__ names (attach_/config_/super_ -> attach,
// config, super).
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		uuidFunc{},
		attachFunc{},
		detachFunc{},
		startFunc{},
		stopFunc{},
		backMakeFunc{},
		cacheMakeFunc{},
		configFunc{},
		statusFunc{},
		deviceFunc{},
		superFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
