// Package zonecfg implements the public Solaris zonecfg surface from the
// pinned Salt module.  It uses zonecfg's command language through bounded
// stdin rather than creating an untracked temporary command file.  The source
// import_ function remains a direct -f invocation because zonecfg, not the
// caller, owns the import-file grammar.
//
// Reference: saltstack/salt/modules/zonecfg.py at
// 8b63e700637e40d76f80a00d95c60471797c73b9.  Salt's import_ alias is exposed
// under the single canonical name import.
package zonecfg

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	zonecfgCommandTimeout = 30 * time.Second
	zonecfgOutputLimit    = 4 << 20
	zonecfgMaxNameBytes   = 64
	zonecfgConfigMaxBytes = 1 << 20
)

var (
	errZonecfgRunnerUnavailable = errors.New("zonecfg: runner unavailable")
	errZonecfgFilesystemMissing = errors.New("zonecfg: filesystem unavailable")
	errZonecfgInvalidArgument   = errors.New("zonecfg: invalid argument")
	errZonecfgMissingSelector   = errors.New("zonecfg: resource_key and resource_value are required")
	errZonecfgMalformedInfo     = errors.New("zonecfg: malformed info output")
)

type solarisOnly struct{}

func (solarisOnly) Platforms() []string { return []string{"solaris"} }

var zoneNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var zonecfgKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*(?: [A-Za-z][A-Za-z0-9_.-]*)?$`)
var zonecfgResourcePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

// CreateArgs mirrors create(zone, brand, zonepath, force=False).
type CreateArgs struct {
	Zone     string `statekit:"required"`
	Brand    string `statekit:"required"`
	Zonepath string `statekit:"required"`
	Force    bool   `statekit:"name=force"`
}

type CreateFromTemplateArgs struct {
	Zone     string `statekit:"required"`
	Template string `statekit:"required"`
}

type DeleteArgs struct {
	Zone string `statekit:"required"`
}

type ExportArgs struct {
	Zone string  `statekit:"required"`
	Path *string `statekit:"name=path"`
}

type ImportArgs struct {
	Zone string `statekit:"required"`
	Path string `statekit:"required"`
}

type SetPropertyArgs struct {
	Zone  string `statekit:"required"`
	Key   string `statekit:"required"`
	Value any    `statekit:"required"`
}

type ClearPropertyArgs struct {
	Zone string `statekit:"required"`
	Key  string `statekit:"required"`
}

type AddResourceArgs struct {
	Zone         string         `statekit:"required"`
	ResourceType string         `statekit:"name=resource_type,required"`
	Kwargs       map[string]any `statekit:"name=kwargs"`
}

// ResourceSelector is intentionally any: Salt documents None for resources
// without a selector, while normal calls use a property-name string.
type UpdateResourceArgs struct {
	Zone             string         `statekit:"required"`
	ResourceType     string         `statekit:"name=resource_type,required"`
	ResourceSelector any            `statekit:"name=resource_selector"`
	Kwargs           map[string]any `statekit:"name=kwargs"`
}

type RemoveResourceArgs struct {
	Zone          string  `statekit:"required"`
	ResourceType  string  `statekit:"name=resource_type,required"`
	ResourceKey   *string `statekit:"name=resource_key"`
	ResourceValue *string `statekit:"name=resource_value"`
}

type InfoArgs struct {
	Zone    string `statekit:"required"`
	ShowAll bool   `statekit:"name=show_all"`
}

// zonecfgRun is the only subprocess boundary.  Every invocation is direct,
// has a finite stdin/output budget, and leaves exit status as data for the
// source-compatible result parser.
func zonecfgRun(ctx context.Context, rt *runtime.Runtime, stdin string, argv ...string) (process.CommandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if rt == nil || rt.Runner == nil {
		return process.CommandResult{ExitCode: -1}, errZonecfgRunnerUnavailable
	}
	if err := validateArgv(argv); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	command, err := runtime.CommandWithInputBounded(argv, stdin)
	if err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	command.Shell = false
	command.Timeout = zonecfgCommandTimeout
	command.MaxStdoutBytes = zonecfgOutputLimit
	command.MaxStderrBytes = zonecfgOutputLimit
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return result, result.Err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stdout) > zonecfgOutputLimit || len(result.Stderr) > zonecfgOutputLimit {
		return result, process.ErrOutputLimit
	}
	return result, nil
}

func validateArgv(argv []string) error {
	if len(argv) == 0 {
		return errZonecfgInvalidArgument
	}
	total := 0
	for _, arg := range argv {
		if strings.IndexByte(arg, 0) >= 0 {
			return errZonecfgInvalidArgument
		}
		if len(arg) > runtime.MaxCommandInputBytes-total {
			return runtime.ErrCommandInputLimit
		}
		total += len(arg)
	}
	return nil
}

func validateZoneName(zone string) error {
	if len(zone) > zonecfgMaxNameBytes || !zoneNamePattern.MatchString(zone) {
		return errZonecfgInvalidArgument
	}
	return nil
}

func validateKey(key string) error {
	if !zonecfgKeyPattern.MatchString(key) {
		return errZonecfgInvalidArgument
	}
	return nil
}

func validateResourceType(resourceType string) error {
	if !zonecfgResourcePattern.MatchString(resourceType) {
		return errZonecfgInvalidArgument
	}
	if _, ok := resourceSetters[resourceType]; !ok {
		return errZonecfgInvalidArgument
	}
	return nil
}

func validatePath(path string) error {
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return errZonecfgInvalidArgument
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f || r == ';' || r == '|' || r == '&' ||
			r == '$' || r == '`' || r == '\'' || r == '"' || r == '\\' {
			return errZonecfgInvalidArgument
		}
	}
	return nil
}

func commandStream(commands ...string) (string, error) {
	if len(commands) == 0 {
		return "", errZonecfgInvalidArgument
	}
	var builder strings.Builder
	for _, command := range commands {
		if command == "" || strings.IndexByte(command, 0) >= 0 ||
			strings.ContainsAny(command, "\r\n") {
			return "", errZonecfgInvalidArgument
		}
		builder.WriteString(command)
		builder.WriteByte('\n')
	}
	if builder.Len() > runtime.MaxCommandInputBytes {
		return "", runtime.ErrCommandInputLimit
	}
	return builder.String(), nil
}

func validateStringValue(value string, allowEmpty bool) error {
	if !allowEmpty && value == "" {
		return errZonecfgInvalidArgument
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == ';' || r == '|' || r == '&' ||
			r == '$' || r == '`' || r == '\'' || r == '"' || r == '\\' {
			return errZonecfgInvalidArgument
		}
	}
	return nil
}

func quoteZonecfgString(value string) (string, error) {
	if err := validateStringValue(value, true); err != nil {
		return "", err
	}
	if strings.Contains(value, " ") {
		return `"` + value + `"`, nil
	}
	return value, nil
}

// sanitizeValue is the shell-free equivalent of the value handling in Salt's
// _property/_resource callers and _sanitize_value.  Collection members are
// emitted as raw zonecfg tokens; if a collection contains whitespace, the
// complete parenthesized value is quoted, just as the source's second
// _sanitize_value call does.  Map keys are sorted because Go maps have no
// source-order guarantee.
func sanitizeValue(value any) (string, error) {
	switch v := value.(type) {
	case nil:
		// _property/_resource stringify None before calling _sanitize_value.
		return "None", nil
	case string:
		return quoteZonecfgString(v)
	case bool:
		if v {
			return "true", nil
		}
		return "false", nil
	case int:
		return strconv.Itoa(v), nil
	case int8:
		return strconv.FormatInt(int64(v), 10), nil
	case int16:
		return strconv.FormatInt(int64(v), 10), nil
	case int32:
		return strconv.FormatInt(int64(v), 10), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case uint:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint8:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint16:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint32:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint64:
		return strconv.FormatUint(v, 10), nil
	case float32:
		return formatFloat(float64(v))
	case float64:
		return formatFloat(v)
	case []string:
		items := make([]string, len(v))
		for i := range v {
			item, err := sanitizeCollectionScalar(v[i])
			if err != nil {
				return "", err
			}
			items[i] = item
		}
		return quoteZonecfgCollection(items)
	case []any:
		items := make([]string, len(v))
		for i := range v {
			item, err := sanitizeCollectionScalar(v[i])
			if err != nil {
				return "", err
			}
			items[i] = item
		}
		return quoteZonecfgCollection(items)
	case map[string]string:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			if err := validateKey(key); err != nil {
				return "", err
			}
			item, err := sanitizeCollectionScalar(v[key])
			if err != nil {
				return "", err
			}
			parts = append(parts, key+"="+item)
		}
		return quoteZonecfgCollection(parts)
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			if err := validateKey(key); err != nil {
				return "", err
			}
			item, err := sanitizeCollectionScalar(v[key])
			if err != nil {
				return "", err
			}
			parts = append(parts, key+"="+item)
		}
		return quoteZonecfgCollection(parts)
	default:
		return "", fmt.Errorf("%w: unsupported value type %T", errZonecfgInvalidArgument, value)
	}
}

// sanitizeCollectionScalar mirrors Python str() for the scalar members that
// can be represented safely inside zonecfg's compact collection grammar.  In
// particular, Python retains True/False capitalization when _sanitize_value
// formats a list or dict member.
func sanitizeCollectionScalar(value any) (string, error) {
	switch v := value.(type) {
	case nil:
		return "None", nil
	case string:
		if err := validateStringValue(v, true); err != nil {
			return "", err
		}
		return v, nil
	case bool:
		if v {
			return "True", nil
		}
		return "False", nil
	case int:
		return strconv.Itoa(v), nil
	case int8:
		return strconv.FormatInt(int64(v), 10), nil
	case int16:
		return strconv.FormatInt(int64(v), 10), nil
	case int32:
		return strconv.FormatInt(int64(v), 10), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case uint:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint8:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint16:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint32:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint64:
		return strconv.FormatUint(v, 10), nil
	case float32:
		return formatFloat(float64(v))
	case float64:
		return formatFloat(v)
	default:
		return "", fmt.Errorf("%w: unsupported collection member type %T", errZonecfgInvalidArgument, value)
	}
}

func quoteZonecfgCollection(items []string) (string, error) {
	return quoteZonecfgString("(" + strings.Join(items, ",") + ")")
}

func formatFloat(value float64) (string, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "", errZonecfgInvalidArgument
	}
	formatted := strconv.FormatFloat(value, 'g', -1, 64)
	if !strings.ContainsAny(formatted, ".eE") {
		// Python's str(float) keeps the decimal marker for integral floats;
		// retain that observable source representation in config values.
		formatted += ".0"
	}
	return formatted, nil
}

// resourceSetters is the exact pinned _zonecfg_resource_setters map.
var resourceSetters = map[string]map[string]bool{
	"fs": {
		"dir": true, "special": true, "raw": true, "type": true, "options": true,
	},
	"net": {
		"address": true, "allowed-address": true, "global-nic": true,
		"mac-addr": true, "physical": true, "property": true,
		"vlan-id defrouter": true,
	},
	"device":        {"match": true, "property": true},
	"rctl":          {"name": true, "value": true},
	"attr":          {"name": true, "type": true, "value": true},
	"dataset":       {"name": true},
	"dedicated-cpu": {"ncpus": true, "importance": true},
	"capped-cpu":    {"ncpus": true},
	"capped-memory": {"physical": true, "swap": true, "locked": true},
	"admin":         {"user": true, "auths": true},
}

func zonecfgResult(result process.CommandResult) map[string]any {
	ret := map[string]any{"status": result.ExitCode == 0}
	message := result.Stdout
	if result.ExitCode != 0 {
		message = result.Stderr
	}
	if len(message) == 0 {
		return ret
	}
	// Salt removes the message only when the selected stream is empty.  A
	// stream containing only an "On line" diagnostic therefore retains an
	// empty message after _clean_message, which is observable in the return
	// mapping and is kept here deliberately.
	ret["message"] = cleanMessage(string(message))
	return ret
}

func cleanMessage(message string) string {
	message = strings.ReplaceAll(message, "zonecfg: ", "")
	message = strings.ReplaceAll(message, "\r\n", "\n")
	message = strings.ReplaceAll(message, "\r", "\n")
	lines := strings.Split(message, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	kept := lines[:0]
	for _, line := range lines {
		if strings.HasPrefix(line, "On line") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

func interactiveInvocation(zone string, commands ...string) ([]string, string, error) {
	if err := validateZoneName(zone); err != nil {
		return nil, "", err
	}
	stdin, err := commandStream(commands...)
	if err != nil {
		return nil, "", err
	}
	return []string{"zonecfg", "-z", zone}, stdin, nil
}

func optionalConfigPath(path *string) (string, bool, error) {
	if path == nil || *path == "" {
		return "", false, nil
	}
	if err := validatePath(*path); err != nil {
		return "", false, err
	}
	return *path, true, nil
}

// ensureZonepath mirrors create's file.directory_exists/makedirs_perms
// dependency through the injected filesystem.  It never falls back to the
// process filesystem, and a cancelled request must not create a directory.
func ensureZonepath(ctx context.Context, rt *runtime.Runtime, zonepath string) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if rt == nil || rt.FS == nil {
		return errZonecfgFilesystemMissing
	}
	info, err := rt.FS.Stat(zonepath)
	if err == nil {
		if info == nil || !info.IsDir() {
			return fmt.Errorf("%w: zonepath exists and is not a directory", errZonecfgInvalidArgument)
		}
		return nil
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return rt.FS.MkdirAll(zonepath, 0o700)
}

// createConfigStream builds the same ordered command file as Salt's create
// implementation, without making a host temporary file.
func createConfigStream(a *CreateArgs) ([]string, string, error) {
	if err := validateZoneName(a.Zone); err != nil {
		return nil, "", err
	}
	if err := validateStringValue(a.Brand, false); err != nil {
		return nil, "", err
	}
	if err := validatePath(a.Zonepath); err != nil || !strings.HasPrefix(a.Zonepath, "/") {
		return nil, "", errZonecfgInvalidArgument
	}
	create := "create -b"
	if a.Force {
		create += " -F"
	}
	brand, err := sanitizeValue(a.Brand)
	if err != nil {
		return nil, "", err
	}
	zonepath, err := quoteZonecfgString(a.Zonepath)
	if err != nil {
		return nil, "", err
	}
	commands := []string{create, "set brand=" + brand, "set zonepath=" + zonepath}
	return interactiveInvocation(a.Zone, commands...)
}

type createFunc struct{ solarisOnly }

func (createFunc) Name() string { return "zonecfg.create" }
func (createFunc) Args() any    { return CreateArgs{} }
func (createFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CreateArgs)
	argv, stdin, err := createConfigStream(a)
	if err != nil {
		return nil, err
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if rt == nil || rt.Runner == nil {
		return nil, errZonecfgRunnerUnavailable
	}
	if err := ensureZonepath(ctx, rt, a.Zonepath); err != nil {
		return nil, err
	}
	result, err := zonecfgRun(ctx, rt, stdin, argv...)
	if err != nil {
		return nil, err
	}
	return zonecfgResult(result), nil
}

type createFromTemplateFunc struct{ solarisOnly }

func (createFromTemplateFunc) Name() string { return "zonecfg.create_from_template" }
func (createFromTemplateFunc) Args() any    { return CreateFromTemplateArgs{} }
func (createFromTemplateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CreateFromTemplateArgs)
	if err := validateZoneName(a.Zone); err != nil {
		return nil, err
	}
	if err := validatePath(a.Template); err != nil {
		return nil, err
	}
	template, err := quoteZonecfgString(a.Template)
	if err != nil {
		return nil, err
	}
	argv, stdin, err := interactiveInvocation(a.Zone, "create -t "+template+" -F")
	if err != nil {
		return nil, err
	}
	result, err := zonecfgRun(ctx, rt, stdin, argv...)
	if err != nil {
		return nil, err
	}
	return zonecfgResult(result), nil
}

type deleteFunc struct{ solarisOnly }

func (deleteFunc) Name() string { return "zonecfg.delete" }
func (deleteFunc) Args() any    { return DeleteArgs{} }
func (deleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DeleteArgs)
	argv, stdin, err := interactiveInvocation(a.Zone, "delete -F")
	if err != nil {
		return nil, err
	}
	result, err := zonecfgRun(ctx, rt, stdin, argv...)
	if err != nil {
		return nil, err
	}
	return zonecfgResult(result), nil
}

type exportFunc struct{ solarisOnly }

func (exportFunc) Name() string { return "zonecfg.export" }
func (exportFunc) Args() any    { return ExportArgs{} }
func (exportFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ExportArgs)
	path, ok, err := optionalConfigPath(a.Path)
	if err != nil {
		return nil, err
	}
	command := "export"
	if ok {
		pathToken, pathErr := quoteZonecfgString(path)
		if pathErr != nil {
			return nil, pathErr
		}
		command += " -f " + pathToken
	}
	argv, stdin, err := interactiveInvocation(a.Zone, command)
	if err != nil {
		return nil, err
	}
	result, err := zonecfgRun(ctx, rt, stdin, argv...)
	if err != nil {
		return nil, err
	}
	return zonecfgResult(result), nil
}

type importFunc struct{ solarisOnly }

func (importFunc) Name() string { return "zonecfg.import" }
func (importFunc) Args() any    { return ImportArgs{} }
func (importFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ImportArgs)
	if err := validateZoneName(a.Zone); err != nil {
		return nil, err
	}
	if err := validatePath(a.Path); err != nil {
		return nil, err
	}
	// The pinned source delegates reading the file to zonecfg -f.  No Go
	// filesystem call or temporary file is needed, so this remains a direct
	// shell-free argv operation and cannot mutate a host file from Go code.
	result, err := zonecfgRun(ctx, rt, "", "zonecfg", "-z", a.Zone, "-f", a.Path)
	if err != nil {
		return nil, err
	}
	return zonecfgResult(result), nil
}

type setPropertyFunc struct{ solarisOnly }

func (setPropertyFunc) Name() string { return "zonecfg.set_property" }
func (setPropertyFunc) Args() any    { return SetPropertyArgs{} }
func (setPropertyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetPropertyArgs)
	if err := validateZoneName(a.Zone); err != nil {
		return nil, err
	}
	if err := validateKey(a.Key); err != nil {
		return nil, err
	}
	value, err := sanitizeValue(a.Value)
	if err != nil {
		return nil, err
	}
	argv, stdin, err := interactiveInvocation(a.Zone, "set "+a.Key+"="+value)
	if err != nil {
		return nil, err
	}
	result, err := zonecfgRun(ctx, rt, stdin, argv...)
	if err != nil {
		return nil, err
	}
	return zonecfgResult(result), nil
}

type clearPropertyFunc struct{ solarisOnly }

func (clearPropertyFunc) Name() string { return "zonecfg.clear_property" }
func (clearPropertyFunc) Args() any    { return ClearPropertyArgs{} }
func (clearPropertyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ClearPropertyArgs)
	if err := validateZoneName(a.Zone); err != nil {
		return nil, err
	}
	if err := validateKey(a.Key); err != nil {
		return nil, err
	}
	argv, stdin, err := interactiveInvocation(a.Zone, "clear "+a.Key)
	if err != nil {
		return nil, err
	}
	result, err := zonecfgRun(ctx, rt, stdin, argv...)
	if err != nil {
		return nil, err
	}
	return zonecfgResult(result), nil
}

func selectorString(value any) (string, bool, error) {
	if value == nil {
		return "", false, nil
	}
	selector, ok := value.(string)
	if !ok {
		return "", false, errZonecfgInvalidArgument
	}
	if selector == "" {
		return "", false, nil
	}
	if err := validateKey(selector); err != nil {
		return "", false, err
	}
	return selector, true, nil
}

func resourceCommands(method, resourceType string, selector any, kwargs map[string]any) ([]string, error) {
	if err := validateResourceType(resourceType); err != nil {
		return nil, err
	}
	selectorName, hasSelector, err := selectorString(selector)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(kwargs))
	for key := range kwargs {
		if err := validateKey(key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if method == "update" && hasSelector {
		if _, ok := kwargs[selectorName]; !ok {
			return nil, fmt.Errorf("resource selector %s not found in parameters", selectorName)
		}
	}
	commands := make([]string, 0, len(keys)+2)
	if method == "add" {
		commands = append(commands, "add "+resourceType)
	} else if method == "update" {
		if hasSelector {
			value, err := sanitizeValue(kwargs[selectorName])
			if err != nil {
				return nil, err
			}
			commands = append(commands, "select "+resourceType+" "+selectorName+"="+value)
		} else {
			commands = append(commands, "select "+resourceType)
		}
	} else {
		return nil, errZonecfgInvalidArgument
	}
	for _, key := range keys {
		if method == "update" && hasSelector && key == selectorName {
			continue
		}
		value, err := sanitizeValue(kwargs[key])
		if err != nil {
			return nil, err
		}
		if resourceSetters[resourceType][key] {
			commands = append(commands, "set "+key+"="+value)
		} else {
			commands = append(commands, "add "+key+" "+value)
		}
	}
	commands = append(commands, "end")
	return commands, nil
}

type addResourceFunc struct{ solarisOnly }

func (addResourceFunc) Name() string { return "zonecfg.add_resource" }
func (addResourceFunc) Args() any    { return AddResourceArgs{} }
func (addResourceFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AddResourceArgs)
	if err := validateZoneName(a.Zone); err != nil {
		return nil, err
	}
	commands, err := resourceCommands("add", a.ResourceType, nil, a.Kwargs)
	if err != nil {
		return nil, err
	}
	argv, stdin, err := interactiveInvocation(a.Zone, commands...)
	if err != nil {
		return nil, err
	}
	result, err := zonecfgRun(ctx, rt, stdin, argv...)
	if err != nil {
		return nil, err
	}
	return zonecfgResult(result), nil
}

type updateResourceFunc struct{ solarisOnly }

func (updateResourceFunc) Name() string { return "zonecfg.update_resource" }
func (updateResourceFunc) Args() any    { return UpdateResourceArgs{} }
func (updateResourceFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*UpdateResourceArgs)
	if err := validateZoneName(a.Zone); err != nil {
		return nil, err
	}
	commands, err := resourceCommands("update", a.ResourceType, a.ResourceSelector, a.Kwargs)
	if err != nil {
		// Salt returns this specific selector miss as a failed result rather
		// than invoking cmd.run_all; keep that no-mutation behavior.
		if strings.HasPrefix(err.Error(), "resource selector ") {
			return map[string]any{"status": false, "message": err.Error()}, nil
		}
		return nil, err
	}
	argv, stdin, err := interactiveInvocation(a.Zone, commands...)
	if err != nil {
		return nil, err
	}
	result, err := zonecfgRun(ctx, rt, stdin, argv...)
	if err != nil {
		return nil, err
	}
	return zonecfgResult(result), nil
}

type removeResourceFunc struct{ solarisOnly }

func (removeResourceFunc) Name() string { return "zonecfg.remove_resource" }
func (removeResourceFunc) Args() any    { return RemoveResourceArgs{} }
func (removeResourceFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*RemoveResourceArgs)
	if !ok || a == nil {
		return nil, errZonecfgInvalidArgument
	}
	if err := validateZoneName(a.Zone); err != nil {
		return nil, err
	}
	if err := validateResourceType(a.ResourceType); err != nil {
		return nil, err
	}
	if a.ResourceValue == nil {
		return nil, errZonecfgMissingSelector
	}
	value, err := sanitizeValue(*a.ResourceValue)
	if err != nil {
		return nil, err
	}
	if a.ResourceKey == nil {
		return nil, errZonecfgMissingSelector
	}
	if *a.ResourceKey != "" {
		if err := validateKey(*a.ResourceKey); err != nil {
			return nil, err
		}
		command := "remove " + a.ResourceType + " " + *a.ResourceKey + "=" + value
		argv, stdin, err := interactiveInvocation(a.Zone, command)
		if err != nil {
			return nil, err
		}
		result, err := zonecfgRun(ctx, rt, stdin, argv...)
		if err != nil {
			return nil, err
		}
		return zonecfgResult(result), nil
	}
	argv, stdin, err := interactiveInvocation(a.Zone, "remove "+a.ResourceType)
	if err != nil {
		return nil, err
	}
	result, err := zonecfgRun(ctx, rt, stdin, argv...)
	if err != nil {
		return nil, err
	}
	return zonecfgResult(result), nil
}

var infoResources = map[string]bool{
	"rctl": true, "net": true, "fs": true, "device": true,
	"dedicated-cpu": true, "dataset": true, "attr": true,
}

var calculatedInfoResources = map[string]bool{
	"capped-cpu": true, "capped-memory": true,
}

func splitZonecfgValues(value string) []string {
	var values []string
	start := 0
	var quote rune
	for i, r := range value {
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
		} else if r == ',' {
			values = append(values, value[start:i])
			start = i + 1
		}
	}
	values = append(values, value[start:])
	return values
}

func asciiDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func parseZonecfgValue(value string) (any, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		inside := value[1 : len(value)-1]
		if inside == "" {
			return []string{}, nil
		}
		parts := splitZonecfgValues(inside)
		return parts, nil
	}
	if strings.HasPrefix(value, "(") && strings.HasSuffix(value, ")") {
		result := map[string]any{}
		inside := value[1 : len(value)-1]
		if inside == "" {
			return result, nil
		}
		for _, pair := range splitZonecfgValues(inside) {
			keyValue := strings.SplitN(pair, "=", 2)
			if len(keyValue) != 2 || keyValue[0] == "" {
				return nil, errZonecfgMalformedInfo
			}
			item := strings.ReplaceAll(keyValue[1], `"`, "")
			if asciiDigits(item) {
				number, err := strconv.Atoi(item)
				if err != nil {
					result[keyValue[0]] = item
					continue
				}
				result[keyValue[0]] = number
			} else if item == "true" {
				result[keyValue[0]] = true
			} else if item == "false" {
				result[keyValue[0]] = false
			} else {
				result[keyValue[0]] = item
			}
		}
		return result, nil
	}
	value = strings.ReplaceAll(value, `"`, "")
	if asciiDigits(value) {
		number, err := strconv.Atoi(value)
		if err == nil {
			return number, nil
		}
		return value, nil
	}
	if value == "true" {
		return true, nil
	}
	if value == "false" {
		return false, nil
	}
	return value, nil
}

func appendInfoResource(ret map[string]any, name string, data map[string]any) {
	items, ok := ret[name].([]map[string]any)
	if ok {
		ret[name] = append(items, data)
		return
	}
	if existing, ok := ret[name].([]any); ok {
		ret[name] = append(existing, data)
		return
	}
	ret[name] = []any{data}
}

func parseZonecfgInfo(output string, showAll bool) (map[string]any, error) {
	return parseZonecfgInfoCompat(output, showAll)
}

// parseZonecfgInfoCompat follows zonecfg's compact resource display while
// treating malformed command output as an error instead of panicking like the
// original Python helper can.  Calculated resources are emitted in a bracketed
// block on the supported Solaris implementations (for example
// "[capped-cpu:" followed by properties and a closing "]").
func parseZonecfgInfoCompat(output string, showAll bool) (map[string]any, error) {
	ret := map[string]any{}
	var resourceName string
	resourceData := map[string]any{}
	hiddenCalculated := false
	flush := func() {
		if resourceName != "" {
			appendInfoResource(ret, resourceName, resourceData)
		}
		resourceName = ""
		resourceData = map[string]any{}
	}
	parseLine := func(line string) (string, string) {
		trimmed := strings.TrimSpace(line)
		key, value := trimmed, ""
		if colon := strings.IndexByte(trimmed, ':'); colon >= 0 {
			key, value = trimmed[:colon], trimmed[colon+1:]
		}
		if strings.HasPrefix(key, "[") {
			key = key[1:]
		}
		return key, value
	}
	for lineNumber, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSuffix(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if hiddenCalculated {
			if trimmed == "]" {
				hiddenCalculated = false
			}
			continue
		}
		if trimmed == "]" {
			continue
		}
		if !strings.Contains(line, ":") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			line = strings.TrimRight(line, " \t")
			singleLineCalculated := strings.HasSuffix(line, "]")
			if !showAll {
				if !singleLineCalculated {
					flush()
					hiddenCalculated = true
				}
				// A one-line calculated field is complete on this line. Do
				// not enter block-skipping mode, so later resources and
				// properties are still parsed.
				continue
			}
			if len(line) < 2 {
				return nil, fmt.Errorf("%w at line %d", errZonecfgMalformedInfo, lineNumber+1)
			}
			line = line[1 : len(line)-1]
		}
		key, valueText := parseLine(line)
		if calculatedInfoResources[key] {
			flush()
			if showAll {
				resourceName = key
				ret[key] = ensureInfoSlice(ret[key])
			}
			continue
		}
		if infoResources[key] {
			flush()
			resourceName = key
			ret[key] = ensureInfoSlice(ret[key])
			continue
		}
		if strings.HasPrefix(line, "\t") {
			if strings.HasPrefix(strings.TrimSpace(line), "[") {
				if !showAll {
					continue
				}
				line = strings.TrimSpace(line)
				if len(line) < 2 {
					return nil, fmt.Errorf("%w at line %d", errZonecfgMalformedInfo, lineNumber+1)
				}
				line = line[1 : len(line)-1]
				key, valueText = parseLine(line)
			}
			parsed, err := parseZonecfgValue(valueText)
			if err != nil {
				return nil, fmt.Errorf("%w at line %d: %v", errZonecfgMalformedInfo, lineNumber+1, err)
			}
			if key == "property" {
				property, ok := parsed.(map[string]any)
				if !ok {
					continue
				}
				properties, ok := resourceData["property"].(map[string]any)
				if !ok {
					properties = map[string]any{}
					resourceData["property"] = properties
				}
				if name, ok := property["name"]; ok {
					if value, ok := property["value"]; ok {
						properties[fmt.Sprint(name)] = value
					}
				}
			} else if resourceName != "" {
				resourceData[key] = parsed
			}
			continue
		}
		flush()
		parsed, err := parseZonecfgValue(valueText)
		if err != nil {
			return nil, fmt.Errorf("%w at line %d: %v", errZonecfgMalformedInfo, lineNumber+1, err)
		}
		if key == "property" {
			property, ok := parsed.(map[string]any)
			if !ok {
				continue
			}
			properties, ok := ret["property"].(map[string]any)
			if !ok {
				properties = map[string]any{}
				ret["property"] = properties
			}
			if name, ok := property["name"]; ok {
				if value, ok := property["value"]; ok {
					properties[fmt.Sprint(name)] = value
				}
			}
		} else {
			ret[key] = parsed
		}
	}
	flush()
	return ret, nil
}

func ensureInfoSlice(value any) []any {
	if items, ok := value.([]any); ok {
		return items
	}
	return []any{}
}

type infoFunc struct{ solarisOnly }

func (infoFunc) Name() string { return "zonecfg.info" }
func (infoFunc) Args() any    { return InfoArgs{} }
func (infoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InfoArgs)
	if err := validateZoneName(a.Zone); err != nil {
		return nil, err
	}
	argv, stdin, err := interactiveInvocation(a.Zone, "info")
	if err != nil {
		return nil, err
	}
	result, err := zonecfgRun(ctx, rt, stdin, argv...)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return map[string]any{}, nil
	}
	parsed, err := parseZonecfgInfo(string(result.Stdout), a.ShowAll)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

// Register installs exactly the 11 public zonecfg functions.  Platform gating
// remains in each function rather than relying on build tags.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		createFunc{}, createFromTemplateFunc{}, deleteFunc{}, exportFunc{}, importFunc{},
		setPropertyFunc{}, clearPropertyFunc{}, addResourceFunc{}, updateResourceFunc{},
		removeResourceFunc{}, infoFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
