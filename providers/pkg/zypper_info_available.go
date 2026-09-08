package pkg

import (
	"context"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const zypperInfoAvailableBatchSize = 200

type zypperInfoAvailableRecord struct {
	name   string
	fields map[string]any
}

func validateZypperInfoAvailableArgs(args map[string]any) error {
	allowed := map[string]bool{
		"names": true, "refresh": true, "root": true, "repos": true,
		"gpgautoimport": true,
	}
	for key := range args {
		if !allowed[key] {
			return zypperUnsupportedArgument(key)
		}
	}
	if _, err := zypperPackageList(args, "names"); err != nil {
		return err
	}
	if _, err := zypperBool(args, "refresh"); err != nil {
		return err
	}
	if _, err := zypperBool(args, "gpgautoimport"); err != nil {
		return err
	}
	if _, err := zypperLowpkgRoot(args); err != nil {
		return err
	}
	_, err := zypperUpgradeRepos(args, "repos")
	return err
}

func zypperInfoAvailable(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	names, err := zypperPackageList(args, "names")
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return map[string]any{}, nil
	}

	// The pinned source applies set(), then sorted(), before the first refresh
	// or query. Keep a private slice so caller-owned argument data is untouched.
	sort.Strings(names)
	names = zypperUniqueNames(names)
	root, err := zypperLowpkgRoot(args)
	if err != nil {
		return nil, err
	}
	refresh := boolDefault(args, "refresh", true)
	gpgAutoImport, err := zypperBool(args, "gpgautoimport")
	if err != nil {
		return nil, err
	}
	repos, err := zypperUpgradeRepos(args, "repos")
	if err != nil {
		return nil, err
	}

	// Validate every query before refresh. This prevents a malformed later
	// batch from causing a metadata mutation before the eventual error.
	for start := 0; start < len(names); start += zypperInfoAvailableBatchSize {
		end := start + zypperInfoAvailableBatchSize
		if end > len(names) {
			end = len(names)
		}
		argv := []string{"zypper", "--non-interactive", "--no-refresh"}
		if root != "" {
			argv = append(argv, "--root", root)
		}
		argv = append(argv, "info", "-t", "package")
		argv = append(argv, names[start:end]...)
		if err := zypperValidateArgv(argv); err != nil {
			return nil, err
		}
	}

	if refresh {
		if err := zypperInfoAvailableRefreshDB(ctx, rt, root, args, repos, gpgAutoImport); err != nil {
			return nil, err
		}
	}

	ret := make(map[string]any)
	for start := 0; start < len(names); start += zypperInfoAvailableBatchSize {
		if err := contextErr(ctx); err != nil {
			return nil, err
		}
		end := start + zypperInfoAvailableBatchSize
		if end > len(names) {
			end = len(names)
		}
		query := []string{"info", "-t", "package"}
		query = append(query, names[start:end]...)
		output, err := zypperQueryRun(ctx, rt, root, false, false, query)
		if err != nil {
			return nil, err
		}
		records, err := zypperParseInfoAvailable(ctx, output)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			// Assignment order deliberately follows zypper's output order;
			// duplicate package records therefore retain source last-wins.
			ret[record.name] = record.fields
		}
	}
	return ret, nil
}

func zypperUniqueNames(names []string) []string {
	if len(names) < 2 {
		return names
	}
	unique := names[:0]
	for _, name := range names {
		if len(unique) == 0 || unique[len(unique)-1] != name {
			unique = append(unique, name)
		}
	}
	return unique
}

func zypperInfoAvailableRefreshDB(ctx context.Context, rt *runtime.Runtime, root string, args map[string]any, repos []string, gpgAutoImport bool) error {
	refreshArgs := []string{"refresh"}
	// info_available calls refresh_db(root, **kwargs). In the pinned Python
	// signature root consequently occupies refresh_db's force position. An
	// omitted root uses the normal force default; an explicitly empty root is
	// false, while a non-empty root is truthy and also selects --root.
	force := true
	switch typed := args["root"].(type) {
	case string:
		force = typed != ""
	case *string:
		if typed != nil {
			force = *typed != ""
		}
	}
	if force {
		refreshArgs = append(refreshArgs, "--force")
	}
	refreshArgs = append(refreshArgs, repos...)
	if gpgAutoImport {
		refreshArgs = append([]string{"--gpg-auto-import-keys"}, refreshArgs...)
	}
	argv := []string{"zypper", "--non-interactive"}
	if root != "" {
		argv = append(argv, "--root", root)
	}
	argv = append(argv, refreshArgs...)
	if err := zypperValidateArgv(argv); err != nil {
		return err
	}
	_, err := zypperQueryRun(ctx, rt, root, false, true, refreshArgs)
	return err
}

func zypperParseInfoAvailable(ctx context.Context, output string) ([]zypperInfoAvailableRecord, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if len(output) > zypperLowpkgOutputLimit {
		return nil, process.ErrOutputLimit
	}
	blocks := zypperInfoSeparator.Split(output, -1)
	if len(blocks) > zypperLowpkgMaxItems {
		return nil, process.ErrOutputLimit
	}
	records := make([]zypperInfoAvailableRecord, 0, len(blocks))
	for _, block := range blocks {
		if err := contextErr(ctx); err != nil {
			return nil, err
		}
		fields := map[string]any{}
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "-----") {
				continue
			}
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			key = strings.ToLower(strings.TrimSpace(key))
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			fields[key] = value
		}
		name, ok := fields["name"].(string)
		if !ok || name == "" {
			continue
		}
		delete(fields, "name")
		if installed, ok := fields["installed"].(string); ok {
			fields["installed"] = strings.HasPrefix(strings.ToLower(installed), "yes")
		}
		records = append(records, zypperInfoAvailableRecord{name: name, fields: fields})
	}
	return records, nil
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
