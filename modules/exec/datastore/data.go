// Package data implements the StateKit persistent datastore over a JSON
// file at an injectable cache directory, mirroring saltstack/salt/modules/
// data.py @ pinned revision (upstream calls it the minion datastore).
//
// Contract notes (init.md section 28): upstream serializes through
// salt.payload (msgpack); StateKit persists JSON — same structure,
// different wire format (documented divergence).
package data

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/friz-zy/statekit/internal/runtime"
)

// dataDir is injectable so suites run hermetically. Upstream reads
// __opts__["cachedir"] (default /var/cache/salt/minion); StateKit keeps
// all writes inside the project workspace by default (.statekit/data)
// and never touches system cache directories.
var dataDir = filepath.Join(".statekit", "data")

func datastorePath() string { return dataDir + "/datastore.json" }

func load(rt *runtime.Runtime) map[string]any {
	store := map[string]any{}
	data, err := rt.FS.ReadFile(datastorePath())
	if err != nil {
		return store
	}
	_ = json.Unmarshal(data, &store)
	return store
}

func ensureDataDir(rt *runtime.Runtime) { rt.FS.MkdirAll(dataDir, 0o700) }

func dumpStore(rt *runtime.Runtime, store map[string]any) error {
	data, err := json.Marshal(store)
	if err != nil {
		return err
	}
	// Upstream assumes cachedir exists; StateKit creates it on demand.
	ensureDataDir(rt)
	return rt.FS.WriteFile(datastorePath(), data, 0o600)
}

type ClearArgs struct{}

type ClearFunc struct{}

func (ClearFunc) Name() string { return "data.clear" }
func (ClearFunc) Args() any    { return ClearArgs{} }
func (ClearFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	rt.FS.Remove(datastorePath())
	return true, nil
}

type LoadArgs struct{}

type LoadFunc struct{}

func (LoadFunc) Name() string { return "data.load" }
func (LoadFunc) Args() any    { return LoadArgs{} }
func (LoadFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return load(rt), nil
}

type DumpArgs struct {
	NewData map[string]any `statekit:"required,name=new_data"`
}

type DumpFunc struct{}

func (DumpFunc) Name() string { return "data.dump" }
func (DumpFunc) Args() any    { return DumpArgs{} }
func (DumpFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DumpArgs)
	if err := dumpStore(rt, a.NewData); err != nil {
		return false, nil
	}
	return true, nil
}

type UpdateArgs struct {
	Key   string `statekit:"required,name=key"`
	Value any    `statekit:"name=value"`
}

type UpdateFunc struct{}

func (UpdateFunc) Name() string { return "data.update" }
func (UpdateFunc) Args() any    { return UpdateArgs{} }
func (UpdateFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*UpdateArgs)
	store := load(rt)
	store[a.Key] = a.Value
	if err := dumpStore(rt, store); err != nil {
		return false, nil
	}
	return true, nil
}

type CasArgs struct {
	Key      string `statekit:"required,name=key"`
	Value    any    `statekit:"name=value"`
	OldValue any    `statekit:"name=old_value"`
}

type CasFunc struct{}

// Cas mirrors cas: fails when the key is absent or its current value does
// not equal old_value.
func (CasFunc) Name() string { return "data.cas" }
func (CasFunc) Args() any    { return CasArgs{} }
func (CasFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CasArgs)
	store := load(rt)
	current, ok := store[a.Key]
	if !ok {
		return false, nil
	}
	if !equalAny(current, a.OldValue) {
		return false, nil
	}
	store[a.Key] = a.Value
	if err := dumpStore(rt, store); err != nil {
		return false, nil
	}
	return true, nil
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

type PopArgs struct {
	Key     string `statekit:"required,name=key"`
	Default any    `statekit:"name=default"`
}

type PopFunc struct{}

func (PopFunc) Name() string { return "data.pop" }
func (PopFunc) Args() any    { return PopArgs{} }
func (PopFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PopArgs)
	store := load(rt)
	val, ok := store[a.Key]
	if !ok {
		return a.Default, nil
	}
	delete(store, a.Key)
	_ = dumpStore(rt, store)
	return val, nil
}

type GetArgs struct {
	Key     any `statekit:"required,name=key"`
	Default any `statekit:"name=default"`
}

type GetFunc struct{}

// Get mirrors get: a string key returns one value (or default); a list key
// returns the values present in the store (or defaults when given).
func (GetFunc) Name() string { return "data.get" }
func (GetFunc) Args() any    { return GetArgs{} }
func (GetFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetArgs)
	store := load(rt)

	switch key := a.Key.(type) {
	case string:
		if v, ok := store[key]; ok {
			return v, nil
		}
		return a.Default, nil
	case []any:
		out := []any{}
		for _, k := range key {
			ks := fmt.Sprintf("%v", k)
			v, ok := store[ks]
			switch {
			case ok:
				out = append(out, v)
			case a.Default != nil:
				out = append(out, a.Default)
			}
		}
		return out, nil
	case []string:
		out := []any{}
		for _, ks := range key {
			v, ok := store[ks]
			switch {
			case ok:
				out = append(out, v)
			case a.Default != nil:
				out = append(out, a.Default)
			}
		}
		return out, nil
	}
	return a.Default, nil
}

type KeysArgs struct{}

type KeysFunc struct{}

func (KeysFunc) Name() string { return "data.keys" }
func (KeysFunc) Args() any    { return KeysArgs{} }
func (KeysFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	store := load(rt)
	out := make([]string, 0, len(store))
	for k := range store {
		out = append(out, k)
	}
	sortStrings(out)
	return out, nil
}

type ValuesArgs struct{}

type ValuesFunc struct{}

func (ValuesFunc) Name() string { return "data.values" }
func (ValuesFunc) Args() any    { return ValuesArgs{} }
func (ValuesFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	store := load(rt)
	out := make([]any, 0, len(store))
	for _, v := range store {
		out = append(out, v)
	}
	return out, nil
}

type ItemsArgs struct{}

type ItemsFunc struct{}

func (ItemsFunc) Name() string { return "data.items" }
func (ItemsFunc) Args() any    { return ItemsArgs{} }
func (ItemsFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return load(rt), nil
}

type HasKeyArgs struct {
	Key string `statekit:"required,name=key"`
}

type HasKeyFunc struct{}

func (HasKeyFunc) Name() string { return "data.has_key" }
func (HasKeyFunc) Args() any    { return HasKeyArgs{} }
func (HasKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*HasKeyArgs)
	store := load(rt)
	_, ok := store[a.Key]
	return ok, nil
}

func sortStrings(items []string) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j] < items[j-1]; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

// SetDataDir overrides the datastore directory (for tests).
func SetDataDir(dir string) { dataDir = dir }

// Register installs all data-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		ClearFunc{},
		LoadFunc{},
		DumpFunc{},
		UpdateFunc{},
		CasFunc{},
		PopFunc{},
		GetFunc{},
		KeysFunc{},
		ValuesFunc{},
		ItemsFunc{},
		HasKeyFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// ExportDataDir returns the current datastore directory (for test
// save/restore).
func ExportDataDir() string { return dataDir }
