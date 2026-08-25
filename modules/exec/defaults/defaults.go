// Package defaults implements Salt's defaults module: deep copy and
// recursive merge over plain structures, mirroring saltstack/salt/modules/
// defaults.py @ pinned revision.
//
// Contract notes (init.md section 28): defaults.get requires the master
// fileserver (salt://formula/defaults.yaml) — it surfaces the cp boundary
// like every other family. The salt.utils.dictupdate.update semantics are
// ported: recursion only when keys overlap, merge_lists concatenates
// deduplicated, non-overlapping keys replace wholesale.
package defaults

import (
	"context"
	"fmt"

	"github.com/friz-zy/statekit/internal/runtime"
)

type DeepcopyArgs struct {
	Source map[string]any `statekit:"required,name=source"`
}

type DeepcopyFunc struct{}

func (DeepcopyFunc) Name() string { return "defaults.deepcopy" }
func (DeepcopyFunc) Args() any    { return DeepcopyArgs{} }
func (DeepcopyFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*DeepcopyArgs)
	return deepCopyMap(a.Source), nil
}

func deepCopyMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = deepCopyValue(v)
	}
	return out
}

func deepCopyValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return deepCopyMap(x)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = deepCopyValue(item)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = item
		}
		return out
	}
	return v
}

type MergeArgs struct {
	Dest        map[string]any `statekit:"required,name=dest"`
	Src         map[string]any `statekit:"required,name=src"`
	MergeLists  bool           `statekit:"name=merge_lists"`
	InPlace     bool           `statekit:"name=in_place"`
	ConvertNone bool           `statekit:"name=convert_none"`
}

type MergeFunc struct{}

// Merge mirrors defaults.merge: with in_place=True dest mutates and
// returns; otherwise a deep-copied result returns.
func (MergeFunc) Name() string { return "defaults.merge" }
func (MergeFunc) Args() any    { return MergeArgs{} }
func (MergeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*MergeArgs)
	dest := a.Dest
	if !a.InPlace {
		dest = deepCopyMap(a.Dest)
	}
	src := a.Src
	if a.ConvertNone {
		src = convertNoneMap(src)
	}
	dictUpdate(dest, src, a.MergeLists)
	return dest, nil
}

type UpdateArgs struct {
	Dest        map[string]any `statekit:"required,name=dest"`
	Defaults    map[string]any `statekit:"required,name=defaults"`
	MergeLists  bool           `statekit:"name=merge_lists"`
	InPlace     *bool          `statekit:"name=in_place"`
	ConvertNone bool           `statekit:"name=convert_none"`
}

type UpdateFunc struct{}

// Update mirrors defaults.update: in_place defaults to True upstream.
func (UpdateFunc) Name() string { return "defaults.update" }
func (UpdateFunc) Args() any    { return UpdateArgs{} }
func (UpdateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*UpdateArgs)
	inPlace := true
	if a.InPlace != nil {
		inPlace = *a.InPlace
	}
	dest := a.Dest
	if !inPlace {
		dest = deepCopyMap(a.Dest)
	}
	defaultsSrc := a.Defaults
	if a.ConvertNone {
		defaultsSrc = convertNoneMap(defaultsSrc)
	}
	dictUpdate(dest, defaultsSrc, a.MergeLists)
	return dest, nil
}

type GetArgs struct {
	Key     string         `statekit:"required,name=key"`
	Default string         `statekit:"name=default"`
	Context map[string]any `statekit:"name=context"`
}

type GetFunc struct{}

func (GetFunc) Name() string { return "defaults.get" }
func (GetFunc) Args() any    { return GetArgs{} }
func (GetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetArgs)
	// The key's first segment selects the formula namespace; _load would
	// fetch salt://<namespace>/defaults.(yaml|json) through the file
	// client: the master-minion boundary.
	_ = indexByte(a.Key, ':')
	return nil, fmt.Errorf(
		"defaults.get requires a Salt master fileserver (master-minion architecture excluded)")
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// dictUpdate mirrors salt.utils.dictupdate.update.
func dictUpdate(dest, upd map[string]any, mergeLists bool) {
	updKeys := make([]string, 0, len(upd))
	for k := range upd {
		updKeys = append(updKeys, k)
	}
	sortStrings(updKeys)

	overlap := false
	for _, k := range updKeys {
		if _, exists := dest[k]; exists {
			overlap = true
			break
		}
	}
	if !overlap {
		for k, v := range upd {
			dest[k] = v
		}
		return
	}
	for _, k := range updKeys {
		val := upd[k]
		destSub, hasDest := dest[k]
		destSubMap, destIsMap := asMap(destSub)
		valMap, valIsMap := asMap(val)
		switch {
		case destIsMap && valIsMap:
			dictUpdate(destSubMap, valMap, mergeLists)
			dest[k] = destSubMap
		case hasDest && isList(destSub) && isList(val):
			if mergeLists {
				merged := append([]any{}, toList(destSub)...)
				for _, item := range toList(val) {
					if !containsItem(merged, item) {
						merged = append(merged, item)
					}
				}
				dest[k] = merged
			} else {
				dest[k] = val
			}
		default:
			dest[k] = val
		}
	}
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func isList(v any) bool {
	switch v.(type) {
	case []any, []string:
		return true
	}
	return false
}

func toList(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case []string:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = item
		}
		return out
	}
	return nil
}

func containsItem(list []any, item any) bool {
	for _, existing := range list {
		if equalAny(existing, item) {
			return true
		}
	}
	return false
}

// convertNoneMap replaces None values with empty maps upstream's
// convert_none handling produces before merging.
func convertNoneMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		if v == nil {
			out[k] = map[string]any{}
			continue
		}
		if m, ok := v.(map[string]any); ok {
			out[k] = convertNoneMap(m)
			continue
		}
		out[k] = v
	}
	return out
}

func equalAny(a, b any) bool {
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok && bok {
		return as == bs
	}
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func sortStrings(items []string) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j] < items[j-1]; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

// Register installs all defaults-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		DeepcopyFunc{},
		MergeFunc{},
		UpdateFunc{},
		GetFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
