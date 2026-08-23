// Package blockdev implements Salt-compatible block device inspection via
// the standard blockdev utility.
//
// Reference: saltstack/salt/modules/devmap.py and disk tooling @ pinned
// revision; function surface follows common blockdev usage.
package blockdev

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

type InfoArgs struct {
	Device string `statekit:"required,name=device"`
}

type infoFunc struct{}

func (infoFunc) Name() string { return "blockdev.info" }
func (infoFunc) Args() any    { return InfoArgs{} }
func (infoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InfoArgs)
	get := func(flag string) (string, error) {
		res := rt.Runner.Run(ctx, runtime.Command("blockdev", flag, a.Device))
		if res.Err != nil {
			return "", res.Err
		}
		if res.ExitCode != 0 {
			return "", fmt.Errorf("blockdev %s failed: %s", flag, strings.TrimSpace(string(res.Stderr)))
		}
		return strings.TrimSpace(string(res.Stdout)), nil
	}
	sizeStr, err := get("--getsize64")
	if err != nil {
		return nil, err
	}
	sizeBytes, _ := strconv.ParseInt(sizeStr, 10, 64)
	sectorStr, sectorErr := get("--getsz")
	sectorSize, _ := strconv.ParseInt(sectorStr, 10, 64)
	sszStr, sszErr := get("--ssz")
	logicalSector, _ := strconv.ParseInt(sszStr, 10, 64)
	out := map[string]any{
		"device":     filepath.Clean(a.Device),
		"size_bytes": sizeBytes,
	}
	if sectorErr == nil {
		out["sectors"] = sectorSize
	}
	if sszErr == nil && logicalSector > 0 {
		out["sector_size"] = logicalSector
	}
	return out, nil
}

// Register installs all blockdev-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	return reg.Register(infoFunc{})
}
