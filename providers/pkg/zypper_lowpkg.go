package pkg

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	zypperLowpkgOutputLimit        = 1 << 20
	zypperLowpkgMaxItems           = 4096
	zypperLowpkgMaxArgBytes        = 64 << 10
	zypperLowpkgMaxResultItems     = zypperLowpkgMaxItems
	zypperLowpkgMaxResultBytes     = 8 << 20
	zypperLowpkgResultReserveBytes = 2 * zypperLowpkgOutputLimit
)

var zypperInfoRecordSeparator = regexp.MustCompile(`----*`)

var errZypperLowpkgResultBudget = errors.New("zypper lowpkg result budget exceeded")

// rpm_lowpkg prepends every verify_options value with "--" before passing it
// to rpm. The pinned source accepts arbitrary strings, but a read-only
// provider cannot safely expose rpm's global, macro, or pipe options through
// that permissive boundary. Keep only switches that control RPM file
// verification itself. The provider also forces --noscripts as a documented
// security hardening: verification must never be allowed to re-enable script
// processing, even when callers provide other verification options.
var zypperRPMVerifyOptions = map[string]struct{}{
	"nodeps":       {},
	"nodigest":     {},
	"nofiles":      {},
	"noscripts":    {},
	"nosignature":  {},
	"nofiledigest": {},
	"nomd5":        {},
	"nosize":       {},
	"nomtime":      {},
	"nouser":       {},
	"nogroup":      {},
	"nomode":       {},
	"nordev":       {},
	"nolinkto":     {},
	"nocaps":       {},
	"noconfig":     {},
	"noghost":      {},
}

func zypperLowpkgFunction(function string) bool {
	switch function {
	case "file_dict", "file_list", "info_installed", "modified", "owner", "verify":
		return true
	default:
		return false
	}
}

func validateZypperLowpkgArgs(function string, args map[string]any) error {
	allowed := map[string]bool{}
	switch function {
	case "file_dict", "file_list":
		allowed["packages"], allowed["root"] = true, true
	case "info_installed":
		allowed["names"], allowed["root"] = true, true
		allowed["attr"], allowed["all_versions"], allowed["errors"] = true, true, true
	case "modified":
		allowed["packages"], allowed["root"] = true, true
		for _, name := range zypperModifiedFlagNames {
			allowed[name] = true
		}
	case "owner":
		allowed["paths"], allowed["root"] = true, true
	case "verify":
		allowed["names"], allowed["root"] = true, true
		allowed["verify_options"], allowed["ignore_types"] = true, true
	default:
		return &runtime.UnsupportedError{Kind: "function", Name: function}
	}
	for key := range args {
		if !allowed[key] {
			return zypperUnsupportedArgument(key)
		}
	}
	return nil
}

func zypperRPMRun(ctx context.Context, rt *runtime.Runtime, argv []string, env []string) (process.CommandResult, error) {
	if rt == nil || !pkgRunnerAvailable(rt.Runner) {
		return process.CommandResult{}, errors.New("Zypper lowpkg function requires a runner")
	}
	if err := zypperValidateArgv(argv); err != nil {
		return process.CommandResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	command := runtime.Command(argv...)
	command.Shell = false
	command.Env = append([]string(nil), env...)
	command.MaxStdoutBytes = zypperLowpkgOutputLimit
	command.MaxStderrBytes = zypperLowpkgOutputLimit
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return process.CommandResult{}, result.Err
	}
	if result.StdoutTruncated || result.StderrTruncated || len(result.Stdout) > zypperLowpkgOutputLimit || len(result.Stderr) > zypperLowpkgOutputLimit {
		return process.CommandResult{}, process.ErrOutputLimit
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{}, err
	}
	return result, nil
}

func pkgRunnerAvailable(r process.Runner) bool {
	return r != nil && RunnerAvailable(r)
}

func zypperValidateArgv(argv []string) error {
	if len(argv) == 0 {
		return errors.New("Zypper lowpkg function requires a command")
	}
	total := 0
	for _, arg := range argv {
		if !utf8.ValidString(arg) {
			return &runtime.UnsupportedError{Kind: "argument", Name: "zypper lowpkg argv"}
		}
		total += len(arg) + 1
		if total > zypperLowpkgMaxArgBytes {
			return &runtime.UnsupportedError{Kind: "argument", Name: "zypper lowpkg argv"}
		}
	}
	return nil
}

func zypperLowpkgRoot(args map[string]any) (string, error) {
	value, exists := args["root"]
	if !exists || value == nil {
		return "", nil
	}
	var root string
	switch typed := value.(type) {
	case string:
		root = typed
	case *string:
		if typed == nil {
			return "", nil
		}
		root = *typed
	default:
		return "", errors.New(`argument "root" must be a string`)
	}
	if root == "" {
		return "", nil
	}
	if err := validateZypperPath(root, true); err != nil {
		return "", zypperUnsupportedArgument("root")
	}
	return root, nil
}

func zypperPackageList(args map[string]any, key string) ([]string, error) {
	value, exists := args[key]
	if !exists || value == nil {
		return nil, nil
	}
	items, ok := value.([]string)
	if !ok {
		return nil, fmt.Errorf(`argument %q must be a string list`, key)
	}
	if len(items) > zypperLowpkgMaxItems {
		return nil, zypperUnsupportedArgument(key)
	}
	ret := append([]string(nil), items...)
	for _, item := range ret {
		if !validZypperToken(item, false) || strings.HasPrefix(item, "-") {
			return nil, zypperUnsupportedArgument(key)
		}
	}
	return ret, nil
}

func zypperPathList(args map[string]any) ([]string, error) {
	value, exists := args["paths"]
	if !exists || value == nil {
		return nil, nil
	}
	items, ok := value.([]string)
	if !ok {
		return nil, errors.New(`argument "paths" must be a string list`)
	}
	if len(items) > zypperLowpkgMaxItems {
		return nil, zypperUnsupportedArgument("paths")
	}
	ret := append([]string(nil), items...)
	for _, item := range ret {
		if err := validateZypperPath(item, false); err != nil {
			return nil, zypperUnsupportedArgument("paths")
		}
		if strings.HasPrefix(item, "-") {
			return nil, zypperUnsupportedArgument("paths")
		}
	}
	return ret, nil
}

func validateZypperPath(value string, allowEmpty bool) error {
	if !allowEmpty && value == "" {
		return errors.New("must not be empty")
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxZypperTokenRunes {
		return errors.New("contains invalid or oversized path data")
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return errors.New("must not contain control characters")
		}
	}
	return nil
}

func zypperUnsupportedArgument(name string) error {
	return &runtime.UnsupportedError{Kind: "argument", Name: name}
}

func zypperFileList(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	packages, err := zypperPackageList(args, "packages")
	if err != nil {
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
	if len(packages) == 0 {
		argv = append(argv, "-qla")
	} else {
		argv = append(argv, "-ql")
		argv = append(argv, packages...)
	}
	result, err := zypperRPMRun(ctx, rt, argv, nil)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"errors": []string{},
		"files":  sourceSplitLines(string(result.Stdout)),
	}, nil
}

func zypperFileDict(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	packages, err := zypperPackageList(args, "packages")
	if err != nil {
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
	if len(packages) == 0 {
		argv = append(argv, "-qa")
	} else {
		argv = append(argv, "-q")
	}
	argv = append(argv, "--queryformat", "%{NAME} %{VERSION}\\n")
	argv = append(argv, packages...)
	result, err := zypperRPMRun(ctx, rt, argv, nil)
	if err != nil {
		return nil, err
	}
	ordered, errorsFound, err := zypperFileDictPackages(string(result.Stdout))
	if err != nil {
		return nil, err
	}
	aggregateBytes := zypperLowpkgResultBytes(result)
	if err := zypperLowpkgCheckResultBudget(aggregateBytes, len(ordered)+len(errorsFound), false); err != nil {
		return nil, err
	}
	ret := make(map[string]any, len(ordered))
	for _, name := range ordered {
		if err := zypperLowpkgCheckResultBudget(aggregateBytes, len(ret)+1, true); err != nil {
			return nil, err
		}
		// This deliberately mirrors the pinned rpm_lowpkg.py quirk: the
		// initial grouping query honors root, but the per-package command is
		// literally built as rpm -ql <package> without --root.
		filesResult, runErr := zypperRPMRun(ctx, rt, []string{"rpm", "-ql", name}, nil)
		if runErr != nil {
			return nil, runErr
		}
		aggregateBytes += zypperLowpkgResultBytes(filesResult)
		if err := zypperLowpkgCheckResultBudget(aggregateBytes, len(ret)+1, false); err != nil {
			return nil, err
		}
		ret[name] = sourceSplitLines(string(filesResult.Stdout))
	}
	return map[string]any{"errors": errorsFound, "packages": ret}, nil
}

func zypperLowpkgResultBytes(result process.CommandResult) int {
	return len(result.Stdout) + len(result.Stderr)
}

func zypperLowpkgCheckResultBudget(bytes, items int, reserveNext bool) error {
	if items > zypperLowpkgMaxResultItems || bytes > zypperLowpkgMaxResultBytes {
		return errZypperLowpkgResultBudget
	}
	if reserveNext && bytes > zypperLowpkgMaxResultBytes-zypperLowpkgResultReserveBytes {
		return errZypperLowpkgResultBudget
	}
	return nil
}

func zypperFileDictPackages(output string) ([]string, []string, error) {
	if output == "" {
		return []string{}, []string{}, nil
	}
	lines := strings.Split(output, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	ordered := make([]string, 0, len(lines))
	seen := make(map[string]bool, len(lines))
	errorsFound := []string{}
	for lineNo, line := range lines {
		if strings.Contains(line, "is not installed") {
			errorsFound = append(errorsFound, line)
			if len(ordered)+len(errorsFound) > zypperLowpkgMaxResultItems {
				return nil, nil, errZypperLowpkgResultBudget
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, nil, fmt.Errorf("Zypper file_dict: malformed record on line %d", lineNo+1)
		}
		if err := validateZypperResponsePackageName(fields[0]); err != nil {
			return nil, nil, fmt.Errorf("Zypper file_dict: invalid package name in RPM response on line %d: %w", lineNo+1, err)
		}
		if !seen[fields[0]] {
			seen[fields[0]] = true
			ordered = append(ordered, fields[0])
			if len(ordered)+len(errorsFound) > zypperLowpkgMaxResultItems {
				return nil, nil, errZypperLowpkgResultBudget
			}
		}
	}
	return ordered, errorsFound, nil
}

func validateZypperResponsePackageName(name string) error {
	if !validZypperToken(name, false) || strings.HasPrefix(name, "-") {
		return zypperUnsupportedArgument("file_dict response package name")
	}
	return nil
}

func zypperInfoInstalled(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	names, err := zypperPackageList(args, "names")
	if err != nil {
		return nil, err
	}
	root, err := zypperLowpkgRoot(args)
	if err != nil {
		return nil, err
	}
	allVersions, err := zypperBool(args, "all_versions")
	if err != nil {
		return nil, err
	}
	attr, err := zypperInfoAttr(args)
	if err != nil {
		return nil, err
	}
	errorsMode, err := zypperInfoErrors(args)
	if err != nil {
		return nil, err
	}
	tagsResult, err := zypperRPMRun(ctx, rt, []string{"rpm", "--querytags"}, nil)
	if err != nil {
		return nil, err
	}
	sizeTag := "%{SIZE}"
	for _, tag := range sourceSplitLines(string(tagsResult.Stdout)) {
		if tag == "LONGSIZE" {
			sizeTag = "%{LONGSIZE}"
			break
		}
	}
	formatArgs := map[string]any{}
	if attr != "" {
		formatArgs["attr"] = attr
	}
	format, err := yumInfoQueryFormat(formatArgs, sizeTag)
	if err != nil {
		return nil, err
	}
	argv := []string{"rpm"}
	if root != "" {
		argv = append(argv, "--root", root)
	}
	if len(names) == 0 {
		argv = append(argv, "-qa")
	} else {
		argv = append(argv, "-q")
		argv = append(argv, names...)
	}
	argv = append(argv, "--queryformat", format)
	result, err := zypperRPMRun(ctx, rt, argv, []string{"TZ=UTC"})
	if err != nil {
		return nil, err
	}
	return zypperTranslateInfoSource(zypperParseInfo(string(result.Stdout), attr, errorsMode, allVersions)), nil
}

func zypperBool(args map[string]any, key string) (bool, error) {
	value, exists := args[key]
	if !exists || value == nil {
		return false, nil
	}
	switch typed := value.(type) {
	case bool:
		return typed, nil
	case *bool:
		if typed == nil {
			return false, nil
		}
		return *typed, nil
	default:
		return false, fmt.Errorf(`argument %q must be a boolean`, key)
	}
}

func zypperInfoAttr(args map[string]any) (string, error) {
	value, exists := args["attr"]
	if !exists || value == nil {
		return "", nil
	}
	var attr string
	switch typed := value.(type) {
	case string:
		attr = typed
	case *string:
		if typed == nil {
			return "", nil
		}
		attr = *typed
	default:
		return "", errors.New(`argument "attr" must be a string`)
	}
	if strings.TrimSpace(attr) == "" {
		return "", nil
	}
	valid := make(map[string]bool, len(yumInfoAttributes))
	for _, item := range yumInfoAttributes {
		valid[item.name] = true
	}
	for _, item := range strings.Split(attr, ",") {
		if valid[strings.TrimSpace(item)] {
			return attr, nil
		}
	}
	return "", errors.New("No valid attributes found.")
}

func zypperInfoErrors(args map[string]any) (string, error) {
	value, exists := args["errors"]
	if !exists || value == nil {
		return "ignore", nil
	}
	var mode string
	switch typed := value.(type) {
	case string:
		mode = typed
	case *string:
		if typed == nil {
			return "ignore", nil
		}
		mode = *typed
	default:
		return "", errors.New(`argument "errors" must be a string`)
	}
	switch mode {
	case "ignore", "report":
		return mode, nil
	default:
		return "", errors.New(`argument "errors" must be "ignore" or "report"`)
	}
}

type zypperInfoPackageRecord struct {
	name    string
	fields  map[string]any
	edition string
}

func zypperParseInfo(output, attr, _ string, allVersions bool) map[string]any {
	ret := map[string]any{}
	records := make([]zypperInfoPackageRecord, 0)
	for _, record := range zypperInfoRecordSeparator.Split(output, -1) {
		record = strings.TrimSpace(record)
		if record == "" {
			continue
		}
		lines := strings.Split(record, "\n")
		if len(lines) > 0 && strings.HasPrefix(strings.ToLower(lines[len(lines)-1]), "distribution") {
			lines = lines[:len(lines)-1]
		}
		fields := map[string]any{}
		name := ""
		description := []string{}
		inDescription := false
		for _, line := range lines {
			if inDescription {
				description = append(description, line)
				continue
			}
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			if key == "description" {
				inDescription = true
				continue
			}
			if key == "name" {
				name = value
				continue
			}
			if value == "" {
				continue
			}
			switch key {
			case "source_rpm":
				fields[key] = value
			case "build_date", "install_date":
				date, ok := zypperInfoDate(value)
				if !ok {
					continue
				}
				fields[key] = date
			case "build_date_time_t", "install_date_time_t":
				seconds, err := strconv.ParseInt(value, 10, 64)
				if err != nil {
					continue
				}
				fields[key] = seconds
			default:
				fields[key] = value
			}
		}
		if name == "" || strings.HasPrefix(name, "gpg-pubkey") {
			continue
		}
		// rpm_lowpkg adds the name only as an internal grouping field, then pops
		// it before returning each metadata object.  zypperpkg.info_installed
		// uses the map key for identity and does not add it back.
		fields["name"] = name
		if zypperInfoDescriptionRequested(attr) {
			fields["description"] = strings.Join(description, "\n")
		}
		if strings.TrimSpace(attr) != "" {
			wanted := map[string]bool{"name": true, "edition": true}
			for _, key := range strings.Split(attr, ",") {
				key = strings.TrimSpace(key)
				wanted[key] = true
			}
			for key := range fields {
				if !wanted[key] {
					delete(fields, key)
				}
			}
		}
		edition, _ := fields["edition"].(string)
		records = append(records, zypperInfoPackageRecord{name: name, fields: fields, edition: edition})
	}
	sort.SliceStable(records, func(i, j int) bool {
		return yumLooseVersionCmp(records[i].edition, records[j].edition) < 0
	})
	// The pinned source is reversed(sorted(..., LooseVersion)), not a stable
	// descending sort.  Iterating the stable ascending result backwards also
	// reproduces its reverse-input tie breaking for equal editions.
	for index := len(records) - 1; index >= 0; index-- {
		record := records[index]
		if allVersions {
			fields := cloneZypperInfoFields(record.fields)
			delete(fields, "name")
			prior, _ := ret[record.name].([]any)
			ret[record.name] = append(prior, fields)
			continue
		}
		if _, exists := ret[record.name]; exists {
			continue
		}
		fields := cloneZypperInfoFields(record.fields)
		delete(fields, "name")
		delete(fields, "edition")
		ret[record.name] = fields
	}
	return ret
}

func zypperTranslateInfoSource(info map[string]any) map[string]any {
	ret := make(map[string]any, len(info))
	for name, value := range info {
		switch versions := value.(type) {
		case map[string]any:
			ret[name] = zypperTranslateInfoFields(versions)
		case []any:
			translated := make([]any, 0, len(versions))
			for _, item := range versions {
				fields, ok := item.(map[string]any)
				if !ok {
					translated = append(translated, item)
					continue
				}
				translated = append(translated, zypperTranslateInfoFields(fields))
			}
			ret[name] = translated
		default:
			ret[name] = value
		}
	}
	return ret
}

func zypperTranslateInfoFields(fields map[string]any) map[string]any {
	ret := cloneZypperInfoFields(fields)
	if value, exists := ret["source_rpm"]; exists {
		delete(ret, "source_rpm")
		ret["source"] = value
	}
	return ret
}

func zypperInfoDate(value string) (string, bool) {
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return "", false
	}
	date := time.Unix(seconds, 0).UTC()
	if date.Year() < 1 || date.Year() > 9999 {
		return "", false
	}
	return date.Format("2006-01-02T15:04:05Z"), true
}

func cloneZypperInfoFields(fields map[string]any) map[string]any {
	ret := make(map[string]any, len(fields))
	for key, value := range fields {
		ret[key] = value
	}
	return ret
}

func zypperInfoDescriptionRequested(attr string) bool {
	if strings.TrimSpace(attr) == "" {
		return true
	}
	for _, item := range strings.Split(attr, ",") {
		if strings.TrimSpace(item) == "description" {
			return true
		}
	}
	return false
}

func zypperVerify(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	names, err := zypperPackageList(args, "names")
	if err != nil {
		return nil, err
	}
	root, err := zypperLowpkgRoot(args)
	if err != nil {
		return nil, err
	}
	options, err := zypperVerifyOptions(args)
	if err != nil {
		return nil, err
	}
	options = zypperForceNoScripts(options)
	ignoreTypes, err := zypperIgnoreTypes(args)
	if err != nil {
		return nil, err
	}
	argv := []string{"rpm"}
	if root != "" {
		argv = append(argv, "--root", root)
	}
	for _, option := range options {
		argv = append(argv, "--"+option)
	}
	if len(names) == 0 {
		argv = append(argv, "-Va")
	} else {
		argv = append(argv, "-V")
		argv = append(argv, names...)
	}
	result, err := zypperRPMRun(ctx, rt, argv, nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(result.Stdout)) == "" && result.ExitCode != 0 {
		message := "Failed to verify package(s)"
		if len(result.Stderr) != 0 {
			message += ": " + string(result.Stderr)
		}
		return nil, errors.New(message)
	}
	ignored := make(map[string]bool, len(ignoreTypes))
	for _, item := range ignoreTypes {
		ignored[item] = true
	}
	return parseYumVerify(string(result.Stdout), ignored), nil
}

func zypperVerifyOptions(args map[string]any) ([]string, error) {
	values, err := zypperVerifyValues(args, "verify_options", true)
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		if _, ok := zypperRPMVerifyOptions[value]; !ok {
			return nil, zypperUnsupportedArgument("verify_options")
		}
	}
	return values, nil
}

func zypperForceNoScripts(options []string) []string {
	forced := make([]string, 0, len(options)+1)
	hasNoScripts := false
	for _, option := range options {
		if option == "noscripts" {
			if hasNoScripts {
				continue
			}
			hasNoScripts = true
		}
		forced = append(forced, option)
	}
	if !hasNoScripts {
		forced = append(forced, "noscripts")
	}
	return forced
}

func zypperVerifyValues(args map[string]any, key string, rejectEmpty bool) ([]string, error) {
	value, exists := args[key]
	if !exists || value == nil {
		return nil, nil
	}
	var values []string
	switch typed := value.(type) {
	case string:
		for _, item := range strings.Split(typed, ",") {
			values = append(values, strings.TrimSpace(item))
		}
	case *string:
		if typed == nil {
			return nil, nil
		}
		for _, item := range strings.Split(*typed, ",") {
			values = append(values, strings.TrimSpace(item))
		}
	case []string:
		values = append(values, typed...)
	case []any:
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil, zypperUnsupportedArgument(key)
			}
			values = append(values, text)
		}
	default:
		return nil, fmt.Errorf(`argument %q must be a string or string list`, key)
	}
	if len(values) > zypperLowpkgMaxItems {
		return nil, zypperUnsupportedArgument(key)
	}
	for _, item := range values {
		if rejectEmpty && item == "" {
			return nil, zypperUnsupportedArgument(key)
		}
		if !validZypperToken(item, !rejectEmpty) || strings.HasPrefix(item, "-") {
			return nil, zypperUnsupportedArgument(key)
		}
	}
	return append([]string(nil), values...), nil
}

// ignore_types is a source-side list filter, not an argv option.  Preserve
// Salt's list semantics: non-string list members cannot match an RPM type and
// are therefore ignored rather than being treated as verification switches.
func zypperIgnoreTypes(args map[string]any) ([]string, error) {
	value, exists := args["ignore_types"]
	if !exists || value == nil {
		return nil, nil
	}
	var values []string
	switch typed := value.(type) {
	case string:
		values = strings.Split(typed, ",")
		for index := range values {
			values[index] = strings.TrimSpace(values[index])
		}
	case *string:
		if typed == nil {
			return nil, nil
		}
		values = strings.Split(*typed, ",")
		for index := range values {
			values[index] = strings.TrimSpace(values[index])
		}
	case []string:
		values = append(values, typed...)
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok {
				values = append(values, text)
			}
		}
	default:
		return nil, fmt.Errorf(`argument %q must be a string or string list`, "ignore_types")
	}
	if len(values) > zypperLowpkgMaxItems {
		return nil, zypperUnsupportedArgument("ignore_types")
	}
	return values, nil
}

func zypperModified(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	packages, err := zypperPackageList(args, "packages")
	if err != nil {
		return nil, err
	}
	root, err := zypperLowpkgRoot(args)
	if err != nil {
		return nil, err
	}
	flags := make(map[string]any, len(zypperModifiedFlagNames)+1)
	for _, name := range zypperModifiedFlagNames {
		if value, exists := args[name]; exists {
			if _, err := zypperBool(args, name); err != nil {
				return nil, err
			}
			flags[name] = value
		}
	}
	argv := []string{"rpm"}
	if root != "" {
		argv = append(argv, "--root", root)
	}
	argv = append(argv, "--noscripts", "-Va")
	argv = append(argv, packages...)
	result, err := zypperRPMRun(ctx, rt, argv, nil)
	if err != nil {
		return nil, err
	}
	if result.ExitCode > 1 {
		return map[string]any{"retcode": result.ExitCode, "stderr": string(result.Stderr)}, nil
	}
	if result.ExitCode == 0 {
		return map[string]any{}, nil
	}
	parseArgs := make(map[string]any, len(flags)+1)
	parseArgs["names"] = append([]string(nil), packages...)
	for key, value := range flags {
		parseArgs[key] = value
	}
	return parseYumModified(string(result.Stdout), parseArgs)
}

var zypperModifiedFlagNames = []string{
	"size", "mode", "checksum", "device", "symlink", "owner", "group", "time", "capabilities",
}

func zypperOwner(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	paths, err := zypperPathList(args)
	if err != nil {
		return nil, err
	}
	root, err := zypperLowpkgRoot(args)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return "", nil
	}
	ret := make(map[string]any, len(paths))
	aggregateBytes := 0
	for _, path := range paths {
		if err := zypperLowpkgCheckResultBudget(aggregateBytes, len(ret)+1, true); err != nil {
			return nil, err
		}
		argv := []string{"rpm"}
		if root != "" {
			argv = append(argv, "--root", root)
		}
		argv = append(argv, "-qf", "--queryformat", "%{name}", path)
		result, runErr := zypperRPMRun(ctx, rt, argv, nil)
		if runErr != nil {
			return nil, runErr
		}
		aggregateBytes += zypperLowpkgResultBytes(result)
		if err := zypperLowpkgCheckResultBudget(aggregateBytes, len(ret)+1, false); err != nil {
			return nil, err
		}
		owner := string(result.Stdout)
		if strings.Contains(strings.ToLower(owner), "not owned") {
			owner = ""
		}
		ret[path] = owner
	}
	if len(ret) == 1 {
		for _, value := range ret {
			return value, nil
		}
	}
	return ret, nil
}
