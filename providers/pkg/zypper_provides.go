package pkg

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func validateZypperListProvidesArgs(args map[string]any) error {
	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key != "root" {
			return zypperUnsupportedArgument(key)
		}
	}
	_, err := zypperLowpkgRoot(args)
	return err
}

// zypperListProvides mirrors zypperpkg.list_provides. Salt caches the result
// in __context__ for the lifetime of one minion call; StateKit invocations
// are single-shot with no cross-call context, so the mapping is recomputed on
// every call — a documented divergence without an observable result
// difference for a single invocation.
func zypperListProvides(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	root, err := zypperLowpkgRoot(args)
	if err != nil {
		return nil, err
	}
	argv := []string{"rpm"}
	if root != "" {
		argv = append(argv, "--root", root)
	}
	argv = append(argv, "-qa", "--queryformat", "%{PROVIDES}_|-%{NAME}\\n")
	result, err := zypperRPMRun(ctx, rt, argv, nil)
	if err != nil {
		return nil, err
	}
	// Salt drives rpm through cmd.run without ignore_retcode: a nonzero
	// retcode raises CommandExecutionError before any parsing. The port
	// keeps that failure mode without reflecting rpm output in diagnostics.
	if result.ExitCode != 0 {
		return nil, errors.New("zypper: rpm provides query failed")
	}
	return zypperParseProvides(string(result.Stdout))
}

// zypperParseProvides builds the ordered provide-to-packages mapping. Each
// line splits on the literal "_|-" separator into exactly a provide and a
// real name; a provide equal to its real name is skipped. Salt's two-name
// unpack would crash on a malformed line — the port skips such lines safely
// instead of failing the whole listing.
func zypperParseProvides(output string) (map[string]any, error) {
	ret := map[string]any{}
	if output == "" {
		return ret, nil
	}
	lines := strings.Split(output, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > zypperLowpkgMaxItems {
		return nil, process.ErrOutputLimit
	}
	entries := 0
	for _, line := range lines {
		parts := strings.Split(line, "_|-")
		if len(parts) != 2 {
			continue
		}
		provide, realname := parts[0], parts[1]
		if provide == realname {
			continue
		}
		existing, _ := ret[provide].([]string)
		ret[provide] = append(existing, realname)
		entries++
		if entries > zypperLowpkgMaxItems {
			return nil, process.ErrOutputLimit
		}
	}
	return ret, nil
}
