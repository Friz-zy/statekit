package pkg

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// zypperListHolds mirrors zypperpkg.list_holds by composing the already
// ported internal building blocks: list_locks for the lock file, search for
// each package lock, and info_installed for the installed editions. The
// registry layer stays a thin dispatcher; all source semantics live here.
//
// Documented Go-port hardenings, each of which fails closed instead of
// approximating Salt behavior:
//   - an invalid pattern regex is rejected before the lock file or the
//     Runner is touched, while Salt compiles it only after all queries;
//   - the pattern is compiled by Go's RE2, so Python-only constructs such as
//     backreferences or lookaround are rejected deterministically;
//   - search results are iterated in sorted name order because the committed
//     search implementation returns a map, unlike Python's ordered dict;
//   - the collected result is bounded by zypperLowpkgMaxResultItems.
func zypperListHolds(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	ptrn, err := zypperListHoldsPattern(args)
	if err != nil {
		return nil, err
	}
	full := true
	if value, exists := args["full"]; exists && value != nil {
		full, _ = zypperBool(args, "full")
	}
	locksArgs := map[string]any{}
	if value, exists := args["root"]; exists && value != nil {
		locksArgs["root"] = value
	}
	locks, err := zypperListLocks(ctx, rt, locksArgs)
	if err != nil {
		return nil, err
	}

	searchArgs := map[string]any{
		"installed_only": true,
		"details":        true,
		// Salt passes case_sensitive as a kwarg on every call regardless of
		// its value, and zypperpkg.search maps kwarg presence to the flag.
		"case_sensitive": true,
	}
	for key, value := range locksArgs {
		searchArgs[key] = value
	}
	instPkgs := newZypperOrderedMap(0)
	for _, lock := range locks.entries {
		if err := contextErr(ctx); err != nil {
			return nil, err
		}
		fields, _ := lock.value.(zypperOrderedMap)
		if typeValue, ok := fields.get("type"); ok {
			typeName, _ := typeValue.(string)
			if typeName != "package" {
				continue
			}
		}
		caseSensitive := true
		if csValue, ok := fields.get("case_sensitive"); ok {
			csName, _ := csValue.(string)
			caseSensitive = csName == "on"
		}
		searchArgs["criteria"] = lock.key
		if strings.Contains(lock.key, "*") {
			delete(searchArgs, "match")
		} else {
			searchArgs["match"] = "exact"
		}
		searchArgs["case_sensitive"] = caseSensitive
		foundResult, err := zypperSearch(ctx, rt, searchArgs)
		if err != nil {
			// Salt skips only the CommandExecutionError category: a lock
			// whose exact search has no installed results, or a failed
			// zypper invocation. Runner errors, cancellation, output-limit
			// violations, XML errors, and validation errors all propagate.
			var noResults *zypperSearchNoResultsError
			var exitCode *zypperExitCodeError
			if errors.As(err, &noResults) || errors.As(err, &exitCode) {
				continue
			}
			return nil, err
		}
		found, _ := foundResult.(map[string]map[string]string)
		names := make([]string, 0, len(found))
		for name := range found {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, pkg := range names {
			if _, exists := instPkgs.get(pkg); exists {
				continue
			}
			infoResult, err := zypperInfoInstalled(ctx, rt, zypperListHoldsInfoArgs(locksArgs, pkg))
			if err != nil {
				return nil, err
			}
			info, _ := infoResult.(map[string]any)
			// Salt merges the whole returned mapping with dict.update. The
			// queried name is the only key in practice; any additional keys
			// merge in sorted order to stay deterministic.
			keys := make([]string, 0, len(info))
			for key := range info {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if len(instPkgs.entries) >= zypperLowpkgMaxResultItems {
					return nil, process.ErrOutputLimit
				}
				instPkgs.set(key, info[key])
			}
		}
	}

	ret := []string{}
	seen := map[string]bool{}
	for _, instPkg := range instPkgs.entries {
		editions, _ := instPkg.value.([]any)
		for _, editionValue := range editions {
			fields, _ := editionValue.(map[string]any)
			pkgRet := instPkg.key
			if full {
				pkgRet = fmt.Sprintf(
					"%s-%s:%s.*",
					instPkg.key,
					zypperListHoldsEdition(fields, "epoch", "0"),
					zypperListHoldsEdition(fields, "edition", ""),
				)
			}
			if seen[pkgRet] {
				continue
			}
			if ptrn != nil && !zypperListHoldsPatternMatches(ptrn, pkgRet) {
				continue
			}
			if len(ret) >= zypperLowpkgMaxResultItems {
				return nil, process.ErrOutputLimit
			}
			seen[pkgRet] = true
			ret = append(ret, pkgRet)
		}
	}
	return ret, nil
}

// validateZypperListHoldsArgs accepts exactly pattern, full, and root, and
// compiles the optional pattern so every malformed value fails before the
// lock file read or the first Runner call. An unknown key keeps the shared
// argument-unsupported classification but is reported without the key
// itself: like the pattern value, the key is caller input and must not be
// reflected back in diagnostics.
func validateZypperListHoldsArgs(args map[string]any) error {
	for key := range args {
		if key != "pattern" && key != "full" && key != "root" {
			return &runtime.UnsupportedError{Kind: "argument", Name: ""}
		}
	}
	if _, err := zypperBool(args, "full"); err != nil {
		return err
	}
	if _, err := zypperLocksRoot(args); err != nil {
		return err
	}
	_, err := zypperListHoldsPattern(args)
	return err
}

// zypperListHoldsPattern compiles Salt's rf"{pattern}-\S+" matcher. An empty
// pattern, like Python's falsy None or "", disables matching entirely. A
// malformed pattern is reported as a stable sanitized category: the compile
// error is deliberately not wrapped because Go's parser echoes the offending
// expression, which would reflect caller input in diagnostics.
func zypperListHoldsPattern(args map[string]any) (*regexp.Regexp, error) {
	pattern := ""
	if value, exists := args["pattern"]; exists && value != nil {
		switch typed := value.(type) {
		case string:
			pattern = typed
		case *string:
			if typed != nil {
				pattern = *typed
			}
		default:
			return nil, errors.New(`argument "pattern" must be a string`)
		}
	}
	if pattern == "" {
		return nil, nil
	}
	re, err := regexp.Compile(pattern + `-\S+`)
	if err != nil {
		return nil, errors.New(`argument "pattern": invalid hold pattern`)
	}
	return re, nil
}

// zypperListHoldsPatternMatches reproduces Python re.match: the match must
// start at the beginning of the value without being anchored to its end.
func zypperListHoldsPatternMatches(re *regexp.Regexp, value string) bool {
	location := re.FindStringIndex(value)
	return location != nil && location[0] == 0
}

// zypperListHoldsInfoArgs is the fixed info_installed call shape pinned by
// list_holds: one package, edition and epoch attributes, every edition.
func zypperListHoldsInfoArgs(rootArgs map[string]any, pkg string) map[string]any {
	infoArgs := map[string]any{
		"names":        []string{pkg},
		"attr":         "edition,epoch",
		"all_versions": true,
	}
	for key, value := range rootArgs {
		infoArgs[key] = value
	}
	return infoArgs
}

// zypperListHoldsEdition reads one edition attribute with Salt's defaults:
// a missing epoch formats as 0 and a missing edition as an empty string.
func zypperListHoldsEdition(fields map[string]any, key, fallback string) string {
	if value, ok := fields[key]; ok {
		if text, ok := value.(string); ok && text != "" {
			return text
		}
	}
	return fallback
}
