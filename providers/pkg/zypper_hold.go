package pkg

import (
	"context"
	"errors"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// errZypperHoldTargetsRequired mirrors the CommandExecutionError raised by
// zypperpkg.hold/unhold when neither name nor pkgs was supplied. The check
// runs before any lock read or zypper call.
var errZypperHoldTargetsRequired = errors.New("Name or packages must be specified.")

// zypperHoldTarget is one resolved pkg target from name/pkgs: a bare package
// name, or a one-key mapping whose single key is the package name and whose
// value is the requested version ("" when unpinned).
type zypperHoldTarget struct {
	name    string
	version string
}

// zypperHoldInputEmpty mirrors `if not name and not pkgs`: a missing, nil,
// or empty-string name together with a missing, nil, or empty pkgs list is
// the empty-input path. A non-list pkgs value is truthy in Python and is
// left for the strict parser to reject.
func zypperHoldInputEmpty(args map[string]any) bool {
	name := ""
	switch value := args["name"].(type) {
	case string:
		name = value
	case *string:
		if value != nil {
			name = *value
		}
	}
	if name != "" {
		return false
	}
	switch value := args["pkgs"].(type) {
	case []any:
		return len(value) == 0
	case []string:
		return len(value) == 0
	default:
		return false
	}
}

// validateZypperHoldArgs accepts exactly name, pkgs, and root, and fully
// parses the target list so every malformed shape fails before the lock
// file is read or the Runner is invoked.
func validateZypperHoldArgs(function string, args map[string]any) error {
	for key := range args {
		if key != "name" && key != "pkgs" && key != "root" {
			return zypperUnsupportedArgument(key)
		}
	}
	if _, err := zypperLocksRoot(args); err != nil {
		return err
	}
	_, err := zypperHoldTargets(function, args)
	return err
}

// zypperHoldTargets reproduces `targets = pkgs or [name]`: a non-empty pkgs
// list takes precedence over name, otherwise the whole name string is one
// target (the source performs no comma splitting). Mapping entries support
// only the one-key shape whose meaning is unambiguous in Go; Python's
// next(iter(mapping)) first-key selection relies on insertion order Go maps
// cannot preserve, so multi-key mappings are rejected instead of silently
// picking an arbitrary key.
func zypperHoldTargets(function string, args map[string]any) ([]zypperHoldTarget, error) {
	name := ""
	if value, exists := args["name"]; exists && value != nil {
		switch typed := value.(type) {
		case string:
			name = typed
		case *string:
			if typed != nil {
				name = *typed
			}
		default:
			return nil, errors.New(`argument "name" must be a string`)
		}
	}

	var items []any
	if value, exists := args["pkgs"]; exists && value != nil {
		switch typed := value.(type) {
		case []any:
			items = typed
		case []string:
			items = make([]any, len(typed))
			for i, item := range typed {
				items[i] = item
			}
		default:
			return nil, errors.New(`argument "pkgs" must be a list`)
		}
	}

	if len(items) == 0 {
		if name == "" {
			return nil, errZypperHoldTargetsRequired
		}
		items = []any{name}
	}

	if len(items) > zypperLowpkgMaxItems {
		return nil, zypperUnsupportedArgument("pkgs")
	}

	targets := make([]zypperHoldTarget, 0, len(items))
	for _, item := range items {
		var target zypperHoldTarget
		switch typed := item.(type) {
		case string:
			target = zypperHoldTarget{name: typed}
		case map[string]any:
			mapping, err := zypperHoldMappingTarget(function, typed)
			if err != nil {
				return nil, err
			}
			target = mapping
		case map[string]string:
			converted := make(map[string]any, len(typed))
			for key, value := range typed {
				converted[key] = value
			}
			mapping, err := zypperHoldMappingTarget(function, converted)
			if err != nil {
				return nil, err
			}
			target = mapping
		default:
			return nil, errors.New(`argument "pkgs" must be a list of package names or one-key mappings`)
		}
		if !validZypperToken(target.name, false) || strings.HasPrefix(target.name, "-") {
			return nil, zypperUnsupportedArgument("pkgs")
		}
		if target.version != "" && !validZypperVersionToken(target.version) {
			return nil, zypperUnsupportedArgument("pkgs")
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func zypperHoldMappingTarget(function string, mapping map[string]any) (zypperHoldTarget, error) {
	if len(mapping) > 1 {
		return zypperHoldTarget{}, &runtime.UnsupportedError{Kind: "argument", Name: "pkg." + function + " pkgs multi-key mapping"}
	}
	if len(mapping) == 0 {
		return zypperHoldTarget{}, errors.New(`argument "pkgs" must be a list of package names or one-key mappings`)
	}
	for key, value := range mapping {
		version := ""
		switch typed := value.(type) {
		case string:
			version = typed
		default:
			return zypperHoldTarget{}, errors.New(`argument "pkgs" mapping values must be version strings`)
		}
		return zypperHoldTarget{name: key, version: version}, nil
	}
	return zypperHoldTarget{}, errors.New(`argument "pkgs" must be a list of package names or one-key mappings`)
}

// zypperHoldIsLocked keeps Python's `if locks.get(target)` truthiness: a
// lock entry exists and its attribute dict is non-empty. An attribute-less
// lock record parses to an empty dict, which is falsy in the source.
func zypperHoldIsLocked(locks zypperOrderedMap, name string) bool {
	value, ok := locks.get(name)
	if !ok {
		return false
	}
	fields, isFields := value.(zypperOrderedMap)
	return isFields && len(fields.entries) > 0
}

// zypperLockVersion reads a lock's "version" attribute with the source's
// lstrip("= ") normalization applied.
func zypperLockVersion(locks zypperOrderedMap, name string) (string, bool) {
	value, ok := locks.get(name)
	if !ok {
		return "", false
	}
	fields, isFields := value.(zypperOrderedMap)
	if !isFields {
		return "", false
	}
	version, has := fields.get("version")
	if !has {
		return "", false
	}
	text, isString := version.(string)
	if !isString {
		return "", false
	}
	return strings.TrimLeft(text, "= "), true
}

// zypperLockMutationCall runs the zypper add-lock (al) / remove-lock (rl)
// batch through the central bounded Runner, mirroring
// __zypper__(root=root).call(...): text mode (no --xmlout), --no-refresh,
// no ZYPP_READONLY_HACK, and Salt's success/warning exit-code set. Any other
// exit, a Runner error, output truncation, or cancellation fails the call
// after the per-target results were computed; success is never fabricated.
// Exit 7 (ZYPP library lock) fails promptly instead of reproducing the
// source's unbounded retry polling, matching the existing zypper boundary.
func zypperLockMutationCall(ctx context.Context, rt *runtime.Runtime, root string, args []string) error {
	_, err := zypperXMLRun(ctx, rt, root, false, false, args, false, false)
	return err
}

func zypperHoldEntry(name string, changes zypperOrderedMap, result bool, comment string) zypperOrderedMap {
	entry := newZypperOrderedMap(4)
	entry.set("name", name)
	entry.set("changes", changes)
	entry.set("result", result)
	entry.set("comment", comment)
	return entry
}

// zypperHold ports zypperpkg.hold: locks are read once, every target gets
// its entry in preserved order, and the batch `al` call happens only when at
// least one new lock was collected.
func zypperHold(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	targets, err := zypperHoldTargets("hold", args)
	if err != nil {
		return nil, err
	}
	root, err := zypperLocksRoot(args)
	if err != nil {
		return nil, err
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	locks, err := zypperListLocks(ctx, rt, args)
	if err != nil {
		return nil, err
	}
	ret := newZypperOrderedMap(len(targets))
	added := make([]string, 0, len(targets))
	for _, target := range targets {
		if err := contextErr(ctx); err != nil {
			return nil, err
		}
		if !zypperHoldIsLocked(locks, target.name) {
			added = append(added, target.name)
			if target.version != "" {
				added[len(added)-1] = target.name + "=" + target.version
			}
			changes := newZypperOrderedMap(0)
			changes.set("new", "hold")
			changes.set("old", "")
			ret.set(target.name, zypperHoldEntry(target.name, changes, true, "Package "+target.name+" is now being held."))
			continue
		}
		ret.set(target.name, zypperHoldEntry(target.name, newZypperOrderedMap(0), true, "Package "+target.name+" is already set to be held."))
	}
	if len(added) > 0 {
		if err := zypperLockMutationCall(ctx, rt, root, append([]string{"al"}, added...)); err != nil {
			return nil, err
		}
	}
	return ret, nil
}

// zypperUnhold ports zypperpkg.unhold: a requested version that differs
// from the lock's version attribute fails that target without a batch
// entry; matched and unversioned locks collect into one `rl` call.
func zypperUnhold(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	targets, err := zypperHoldTargets("unhold", args)
	if err != nil {
		return nil, err
	}
	root, err := zypperLocksRoot(args)
	if err != nil {
		return nil, err
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	locks, err := zypperListLocks(ctx, rt, args)
	if err != nil {
		return nil, err
	}
	ret := newZypperOrderedMap(len(targets))
	removed := make([]string, 0, len(targets))
	for _, target := range targets {
		if err := contextErr(ctx); err != nil {
			return nil, err
		}
		if !zypperHoldIsLocked(locks, target.name) {
			ret.set(target.name, zypperHoldEntry(target.name, newZypperOrderedMap(0), true, "Package "+target.name+" was already unheld."))
			continue
		}
		lockVersion, _ := zypperLockVersion(locks, target.name)
		if target.version != "" && lockVersion != target.version {
			ret.set(target.name, zypperHoldEntry(target.name, newZypperOrderedMap(0), false, "Unable to unhold package "+target.name+" as it is held with the other version."))
			continue
		}
		spec := target.name
		if lockVersion != "" {
			spec = target.name + "=" + lockVersion
		}
		removed = append(removed, spec)
		changes := newZypperOrderedMap(0)
		changes.set("new", "")
		changes.set("old", "hold")
		ret.set(target.name, zypperHoldEntry(target.name, changes, true, "Package "+target.name+" is no longer held."))
	}
	if len(removed) > 0 {
		if err := zypperLockMutationCall(ctx, rt, root, append([]string{"rl"}, removed...)); err != nil {
			return nil, err
		}
	}
	return ret, nil
}
