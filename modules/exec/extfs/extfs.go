// Package extfs implements Salt-compatible ext2/3/4 filesystem management
// through mke2fs, tune2fs, and dumpe2fs.
//
// Reference: saltstack/salt/modules/extfs.py @ pinned revision. Salt builds
// shell strings; StateKit emits argv through the central Runner with the
// same flag semantics. Free-form kwargs arrive as the `options` map using
// Salt's original key names; unknown keys are ignored like in Salt.
package extfs

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts every function of this module to linux: the ext
// toolchain is a Linux contract in StateKit's ported scope.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// mkfsFlagMap mirrors extfs.mkfs kwarg_map.
var mkfsFlagMap = map[string]string{
	"block_size": "b", "check": "c", "direct": "D", "ext_opts": "E",
	"fragment_size": "f", "force": "F", "blocks_per_group": "g",
	"number_of_groups": "G", "bytes_per_inode": "i", "inode_size": "I",
	"journal": "j", "journal_opts": "J", "blocks_file": "l", "label": "L",
	"reserved": "m", "last_dir": "M", "test": "n", "number_of_inodes": "N",
	"creator_os": "o", "opts": "O", "revision": "r", "super": "S",
	"usage_type": "T", "uuid": "U", "cluster_size": "C",
	"root_directory": "d", "errors_behavior": "e",
}

// tuneFlagMap mirrors extfs.tune kwarg_map.
var tuneFlagMap = map[string]string{
	"max": "c", "count": "C", "error": "e", "extended_opts": "E",
	"force": "f", "group": "g", "interval": "i", "journal": "j",
	"journal_opts": "J", "label": "L", "last_dir": "M", "opts": "o",
	"feature": "O", "mmp_check": "p", "reserved": "r",
	"reserved_percentage": "m", "quota_opts": "Q", "time": "T",
	"user": "u", "uuid": "U",
}

// appendOpts translates the options map into argv flags. A value of
// "true" (case-insensitive) becomes a bare flag, matching Salt's
// str(value).lower() == "true" branch. Keys are sorted for deterministic
// argv (Salt inherits caller dict order).
func appendOpts(argv []string, flagMap map[string]string, opts map[string]string) []string {
	keys := make([]string, 0, len(opts))
	for key := range opts {
		if _, known := flagMap[key]; known {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		flag := "-" + flagMap[key]
		if strings.EqualFold(opts[key], "true") {
			argv = append(argv, flag)
			continue
		}
		argv = append(argv, flag, opts[key])
	}
	return argv
}

type MkfsArgs struct {
	Device     string            `statekit:"required,name=device"`
	FsType     string            `statekit:"required,name=fs_type"`
	FullReturn bool              `statekit:"name=full_return"`
	Option     map[string]string `statekit:"name=options"`
}

type mkfsFunc struct {
	linuxOnly
}

func (mkfsFunc) Name() string { return "extfs.mkfs" }
func (mkfsFunc) Args() any    { return MkfsArgs{} }
func (mkfsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*MkfsArgs)
	argv := append([]string{"mke2fs", "-F", "-t", a.FsType},
		appendOpts([]string{}, mkfsFlagMap, a.Option)...)
	argv = append(argv, a.Device)
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return nil, res.Err
	}
	comment := filterMkfsLines(res.Stdout, res.Stderr)
	if a.FullReturn {
		return map[string]any{
			"retcode": res.ExitCode,
			"stdout":  string(res.Stdout),
			"stderr":  string(res.Stderr),
			"comment": comment,
		}, nil
	}
	return comment, nil
}

// filterMkfsLines drops progress chatter from combined stdout/stderr like
// Salt does before returning the remaining lines.
func filterMkfsLines(stdout, stderr []byte) []string {
	var ret []string
	for _, line := range strings.Split(
		strings.TrimRight(string(stdout)+"\n"+string(stderr), "\n"), "\n") {
		switch {
		case line == "",
			strings.HasPrefix(line, "mke2fs"),
			strings.HasPrefix(line, "Discarding device blocks"),
			strings.HasPrefix(line, "Allocating group tables"),
			strings.HasPrefix(line, "Writing inode tables"),
			strings.HasPrefix(line, "Creating journal"),
			strings.HasPrefix(line, "Writing superblocks"):
			continue
		}
		ret = append(ret, line)
	}
	if ret == nil {
		ret = []string{}
	}
	return ret
}

type TuneArgs struct {
	Device     string            `statekit:"required,name=device"`
	FullReturn bool              `statekit:"name=full_return"`
	Option     map[string]string `statekit:"name=options"`
}

type tuneFunc struct {
	linuxOnly
}

func (tuneFunc) Name() string { return "extfs.tune" }
func (tuneFunc) Args() any    { return TuneArgs{} }
func (tuneFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*TuneArgs)
	argv := appendOpts([]string{"tune2fs"}, tuneFlagMap, a.Option)
	argv = append(argv, a.Device)
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return nil, res.Err
	}
	out := splitNonEmpty(string(res.Stdout), string(res.Stderr))
	if a.FullReturn {
		return map[string]any{
			"retcode": res.ExitCode,
			"stdout":  string(res.Stdout),
			"stderr":  string(res.Stderr),
			"comment": out,
		}, nil
	}
	return out, nil
}

// splitNonEmpty joins stdout and stderr and returns non-empty lines.
func splitNonEmpty(stdout, stderr string) []string {
	out := []string{}
	for _, line := range strings.Split(strings.TrimRight(stdout+"\n"+stderr, "\n"), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

type DumpArgs struct {
	Device string `statekit:"required,name=device"`
	Args   string `statekit:"name=args"`
}

type dumpFunc struct {
	linuxOnly
}

func (dumpFunc) Name() string { return "extfs.dump" }
func (dumpFunc) Args() any    { return DumpArgs{} }

// fsDump is the shared dump result shape: attributes keyed by header name,
// blocks grouped per block group, mirroring Salt's dict layout.
type fsDump struct {
	Attributes map[string]any `json:"attributes" yaml:"attributes"`
	Blocks     map[string]any `json:"blocks" yaml:"blocks"`
}

func dump(ctx context.Context, rt *runtime.Runtime, device, extraArgs string) (*fsDump, error) {
	argv := []string{"dumpe2fs", device}
	if extraArgs != "" {
		argv = append(argv, "-"+extraArgs)
	}
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return nil, res.Err
	}
	ret := &fsDump{Attributes: map[string]any{}, Blocks: map[string]any{}}
	mode := "opts"
	group := ""

	for _, rawLine := range strings.Split(string(res.Stdout), "\n") {
		line := rawLine
		if line == "" || strings.HasPrefix(line, "dumpe2fs") {
			continue
		}
		if mode == "opts" {
			line = strings.ReplaceAll(line, "\t", " ")
			comps := strings.Split(line, ": ")
			switch {
			case strings.HasPrefix(line, "Filesystem features"):
				ret.Attributes[comps[0]] = strings.Fields(comps[1])
			case strings.HasPrefix(line, "Group") && !strings.HasPrefix(line, "Group descriptor size"):
				mode = "blocks"
			default:
				if len(comps) < 2 {
					continue
				}
				ret.Attributes[comps[0]] = strings.TrimSpace(comps[1])
			}
		}
		if mode == "blocks" {
			if group == "" && !strings.HasPrefix(line, "Group") {
				continue
			}
			if strings.HasPrefix(line, "Group") {
				clean := strings.NewReplacer(":", "", "(", "", ")", "", "[", "", "]", "").Replace(line)
				comps := strings.Fields(clean)
				if len(comps) < 4 {
					continue
				}
				group = fmt.Sprintf("Group %s", comps[1])
				ret.Blocks[group] = map[string]any{
					"group": comps[1],
					"range": comps[3],
					"extra": []string{},
				}
				continue
			}
			bucket := ret.Blocks[group].(map[string]any)
			switch {
			case strings.Contains(line, "Free blocks:"):
				comps := strings.Split(line, ": ")
				bucket["free blocks"] = strings.Split(comps[1], ", ")
			case strings.Contains(line, "Free inodes:"):
				comps := strings.Split(line, ": ")
				bucket["free inodes"] = strings.Split(comps[1], ", ")
			default:
				extra := bucket["extra"].([]string)
				bucket["extra"] = append(extra, strings.TrimSpace(line))
			}
		}
	}
	return ret, nil
}

func (dumpFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DumpArgs)
	return dump(ctx, rt, a.Device, a.Args)
}

type AttributesArgs struct {
	Device string `statekit:"required,name=device"`
	Args   string `statekit:"name=args"`
}

type attributesFunc struct {
	linuxOnly
}

func (attributesFunc) Name() string { return "extfs.attributes" }
func (attributesFunc) Args() any    { return AttributesArgs{} }
func (attributesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AttributesArgs)
	fsdump, err := dump(ctx, rt, a.Device, a.Args)
	if err != nil {
		return nil, err
	}
	return fsdump.Attributes, nil
}

type BlocksArgs struct {
	Device string `statekit:"required,name=device"`
	Args   string `statekit:"name=args"`
}

type blocksFunc struct {
	linuxOnly
}

func (blocksFunc) Name() string { return "extfs.blocks" }
func (blocksFunc) Args() any    { return BlocksArgs{} }
func (blocksFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*BlocksArgs)
	fsdump, err := dump(ctx, rt, a.Device, a.Args)
	if err != nil {
		return nil, err
	}
	return fsdump.Blocks, nil
}

// Register installs all extfs-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		mkfsFunc{},
		tuneFunc{},
		dumpFunc{},
		attributesFunc{},
		blocksFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
