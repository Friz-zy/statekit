package pkg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// zypperPurgeTargetsForArch is the pkg_resource.parse_targets subset shared by
// zypperpkg purge and upgrade: pkgs entries are repacked through the
// _repack_pkgs-compatible path (zypper normalize_name, duplicate rejection),
// while name is comma-split and normalized without a duplicate error, like
// the source's dict comprehension. Sources are not part of the zypper
// signatures and are rejected by argument validation instead.
func zypperPurgeTargetsForArch(a map[string]any, osarch string) ([]purgeTarget, error) {
	value, supplied := a["pkgs"]
	if supplied && value != nil {
		items, isList, empty := purgeItems(value)
		if !isList {
			if !sourceTargetTruthy(value) {
				return zypperPurgeNameTargets(a, osarch)
			}
			return nil, errors.New(`argument "pkgs" must be a list`)
		}
		if !empty {
			targets := newPurgeTargetMap(len(items))
			for _, item := range items {
				target, err := purgeTargetFromItem(item, func(name string) string {
					return zypperNormalizeName(name, osarch)
				})
				if err != nil {
					return nil, fmt.Errorf("pkgs: %w", err)
				}
				if targets.has(target.name) {
					return nil, duplicatePurgeTargetsError(items)
				}
				targets.put(target)
			}
			return targets.ordered(), nil
		}
	}
	return zypperPurgeNameTargets(a, osarch)
}

func zypperPurgeNameTargets(a map[string]any, osarch string) ([]purgeTarget, error) {
	value, supplied := a["name"]
	if !supplied || value == nil {
		return nil, nil
	}
	var name string
	switch typed := value.(type) {
	case string:
		name = typed
	case *string:
		if typed == nil {
			return nil, nil
		}
		name = *typed
	default:
		return nil, errors.New(`argument "name" must be a string`)
	}
	if name == "" {
		return nil, nil
	}
	parts := strings.Split(name, ",")
	targets := newPurgeTargetMap(len(parts))
	for _, part := range parts {
		// The name branch is a dict comprehension: normalized repeats replace
		// the value in place without a duplicate error and empty components
		// stay as keys that cannot match an installed package.
		targets.put(purgeTarget{name: zypperNormalizeName(part, osarch)})
	}
	return targets.ordered(), nil
}

// zypperPkgsPresent reports the `if name or pkgs:` truthiness gate of
// zypperpkg.upgrade for the decoder-compatible argument shapes.
func zypperPkgsPresent(a map[string]any, name string) bool {
	if name != "" {
		return true
	}
	value, supplied := a["pkgs"]
	return supplied && sourceTargetTruthy(value)
}

// zypperPurge ports zypperpkg._uninstall for pkg.purge. Batched `remove`
// calls take at most 500 targets per call and ptf packages are removed
// separately through `removeptf --allow-downgrade`, also 500 per call. The
// source declares an errors list that its call wrapper never appends to: a
// failed batch raises directly, so batching stops at the first failure and
// the trailing "Problem encountered removing package(s)" branch is
// unreachable. This port keeps that observable contract: the first failing
// batch returns immediately and no post-removal snapshot is taken.
func zypperPurge(ctx context.Context, rt *runtime.Runtime, a map[string]any) (any, error) {
	osarch := zypperOSArch(rt)
	targets, err := zypperPurgeTargetsForArch(a, osarch)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return map[string]any{}, nil
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	root, err := zypperLowpkgRoot(a)
	if err != nil {
		return nil, err
	}

	names := make([]string, len(targets))
	for i, target := range targets {
		names[i] = target.name
	}
	ptfpackages, err := zypperFindPTFPackages(ctx, rt, root, names)
	if err != nil {
		return nil, err
	}
	ptfSet := make(map[string]bool, len(ptfpackages))
	for _, name := range ptfpackages {
		ptfSet[name] = true
	}
	includes := zypperFindTypes(names)
	oldSnapshot, err := zypperListPkgsSnapshot(ctx, rt, root, osarch, includes)
	if err != nil {
		return nil, err
	}
	old := zypperListPkgsStrings(oldSnapshot)

	// ptf packages are skipped by the remove batches; a version-qualified
	// target becomes "name-version" only when that version is installed,
	// otherwise a bare target is removed only when the package is installed
	// without a requested version.
	remove := make([]string, 0, len(targets))
	for _, target := range targets {
		if ptfSet[target.name] {
			continue
		}
		installed, exists := old[target.name]
		switch {
		case exists && target.version != "" && zypperVersionInstalled(installed, target.version):
			remove = append(remove, target.name+"-"+target.version)
		case exists && target.version == "":
			remove = append(remove, target.name)
		}
	}
	if len(remove) == 0 && len(ptfpackages) == 0 {
		return map[string]any{}, nil
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	for start := 0; start < len(remove); start += zypperPurgeBatchSize {
		end := start + zypperPurgeBatchSize
		if end > len(remove) {
			end = len(remove)
		}
		if err := zypperPurgeCall(ctx, rt, root, append([]string{"remove"}, remove[start:end]...)); err != nil {
			return nil, err
		}
	}
	for start := 0; start < len(ptfpackages); start += zypperPurgeBatchSize {
		end := start + zypperPurgeBatchSize
		if end > len(ptfpackages) {
			end = len(ptfpackages)
		}
		call := append([]string{"removeptf", "--allow-downgrade"}, ptfpackages[start:end]...)
		if err := zypperPurgeCall(ctx, rt, root, call); err != nil {
			return nil, err
		}
	}

	newSnapshot, err := zypperListPkgsSnapshot(ctx, rt, root, osarch, includes)
	if err != nil {
		return nil, err
	}
	return comparePackages(old, zypperListPkgsStrings(newSnapshot)), nil
}

// zypperPurgeBatchSize is the pinned 500-target batch limit of
// zypperpkg._uninstall's remove and removeptf loops.
const zypperPurgeBatchSize = 500

func zypperVersionInstalled(installed, wanted string) bool {
	for _, version := range strings.Split(installed, ",") {
		if version == wanted {
			return true
		}
	}
	return false
}
