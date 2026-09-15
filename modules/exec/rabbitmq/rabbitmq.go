// Package rabbitmq implements the pinned Salt rabbitmq execution surface.
//
// RabbitMQ is virtualized by Salt on both Windows and non-Windows systems. The
// StateKit port therefore remains platform-neutral and uses the canonical
// rabbitmqctl/rabbitmq-plugins executables rather than adding a Windows-only
// registry gate. Every helper invocation is an explicit argv command through
// the central Runner; no shell, broker connection, or filesystem access is
// performed here.
package rabbitmq

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execpkg "github.com/friz-zy/statekit/modules/exec/pkg"
)

const (
	rabbitmqctlCommand     = "rabbitmqctl"
	rabbitmqPluginsCommand = "rabbitmq-plugins"
	commandTimeout         = 30 * time.Second
	outputLimit            = 4 << 20
	defaultVhost           = "/"
	defaultRabbitUser      = "rabbit"
)

var (
	errRabbitMQRunnerUnavailable  = errors.New("rabbitmq: runner unavailable")
	errRabbitMQCtlUnavailable     = errors.New("rabbitmq: rabbitmqctl is unavailable")
	errRabbitMQPluginsUnavailable = errors.New("rabbitmq: rabbitmq-plugins is unavailable")
	errRabbitMQRunas              = errors.New("rabbitmq: runas is not supported by statekit")
	errRabbitMQInvalidArgument    = errors.New("rabbitmq: invalid argument")
	errRabbitMQPolicyLayout       = errors.New("rabbitmq: ambiguous policy layout requires broker version")
	errRabbitMQRecovery           = errors.New("rabbitmq: temporary-user recovery is indeterminate")
	errRabbitMQPackageVersion     = errors.New("rabbitmq: package version is unavailable")
	errRabbitMQCommand            = errors.New("RabbitMQ command failed")

	oldRabbitVersionRE = regexp.MustCompile(`\{rabbit,"RabbitMQ","(.+)"\}`)
	newRabbitVersionRE = regexp.MustCompile(`RabbitMQ version:\s*(.+)`)
	policyVersionRE    = regexp.MustCompile(`^([0-9]+)\.([0-9]+)(?:\.([0-9]+))?`)
	// PEP 440 grammar, including the legacy spelling aliases accepted by Version.
	packageVersionRE = regexp.MustCompile(`(?i)^v?(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)(?:[-_.]?(alpha|beta|preview|pre|a|b|rc|c)[-_.]?[0-9]*)?(?:(-[0-9]+)|(?:[-_.]?(post|rev|r)[-_.]?[0-9]*))?(?:[-_.]?(dev)[-_.]?[0-9]*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)
	amqpCredentialRE = regexp.MustCompile(`(?i)(amqps?:)((?:\\?/){2})([^/@:\s"]+):((?:\\.|[^@/\s"])*)@`)
	amqpUserInfoRE   = regexp.MustCompile(`(?i)(amqps?:)((?:\\?/){2})((?:\\.|[^/@\s"])*)@`)
)

// rabbitmqRun is the sole subprocess boundary for this package. A completed
// non-zero exit remains compatibility data so callers can apply Salt's
// function-specific response handling. Runner failures, cancellation, and
// output-limit violations are errors.
func rabbitmqRun(ctx context.Context, rt *runtime.Runtime, executable string, argv []string, secrets ...string) (process.CommandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if rt == nil || rt.Runner == nil {
		return process.CommandResult{ExitCode: -1}, errRabbitMQRunnerUnavailable
	}
	if executable == "" || len(argv) == 0 {
		return process.CommandResult{ExitCode: -1}, errRabbitMQInvalidArgument
	}
	if err := validateArgv(executable, argv); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if available, ok := rt.Runner.(process.CommandAvailability); ok && !available.CommandAvailable(executable) {
		if isRabbitMQPluginExecutable(executable) {
			return process.CommandResult{ExitCode: -1}, errRabbitMQPluginsUnavailable
		}
		return process.CommandResult{ExitCode: -1}, errRabbitMQCtlUnavailable
	}

	command, buildErr := process.BuildRabbitMQCommand(runtime.CurrentGOOS(), executable, argv)
	if buildErr != nil {
		return process.CommandResult{ExitCode: -1}, buildErr
	}
	command.Timeout = commandTimeout
	command.MaxStdoutBytes = outputLimit
	command.MaxStderrBytes = outputLimit
	command.Redact = secretList(secrets...)
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return result, redactedError(result.Err, secrets...)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stdout) > outputLimit || len(result.Stderr) > outputLimit {
		return result, process.ErrOutputLimit
	}
	return result, nil
}

func isRabbitMQPluginExecutable(executable string) bool {
	lower := strings.ToLower(executable)
	return lower == rabbitmqPluginsCommand ||
		strings.HasSuffix(lower, "/"+rabbitmqPluginsCommand) ||
		strings.HasSuffix(lower, "\\"+rabbitmqPluginsCommand) ||
		strings.HasSuffix(lower, "/"+rabbitmqPluginsCommand+".bat") ||
		strings.HasSuffix(lower, "\\"+rabbitmqPluginsCommand+".bat")
}

func redactedError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	if len(secrets) == 0 {
		return err
	}
	message := process.RedactString(secretList(secrets...), err.Error())
	if message == err.Error() {
		return err
	}
	return errors.New(message)
}

func validateArgv(executable string, argv []string) error {
	total := len(executable)
	if strings.IndexByte(executable, 0) >= 0 || strings.ContainsAny(executable, "\r\n") {
		return errRabbitMQInvalidArgument
	}
	for _, arg := range argv {
		if strings.IndexByte(arg, 0) >= 0 || strings.ContainsAny(arg, "\r\n") {
			return errRabbitMQInvalidArgument
		}
		total += len(arg)
		if total > runtime.MaxCommandInputBytes {
			return runtime.ErrCommandInputLimit
		}
	}
	return nil
}

func validateText(value, name string, required bool) error {
	if required && value == "" {
		return fmt.Errorf("rabbitmq: %s must not be empty", name)
	}
	if strings.IndexByte(value, 0) >= 0 || strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("rabbitmq: %s contains invalid control characters", name)
	}
	return nil
}

func rejectRunas(runas *string) error {
	if runas == nil || *runas == "" {
		return nil
	}
	if err := validateText(*runas, "runas", false); err != nil {
		return err
	}
	return errRabbitMQRunas
}

func secretList(values ...string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func upstreamCredentialSecrets(uri string) []string {
	secrets := []string{uri}
	for _, match := range amqpCredentialRE.FindAllStringSubmatch(uri, -1) {
		if len(match) != 5 {
			continue
		}
		secrets = append(secrets, match[0], match[3]+":"+match[4], match[4])
	}
	for _, match := range amqpUserInfoRE.FindAllStringSubmatch(uri, -1) {
		if len(match) == 4 {
			secrets = append(secrets, match[0], match[3])
		}
	}
	return secretList(secrets...)
}

func redactUpstreamCredentials(value string) string {
	redacted := amqpCredentialRE.ReplaceAllString(value, `${1}***REDACTED***@`)
	redacted = amqpUserInfoRE.ReplaceAllString(redacted, `${1}***REDACTED***@`)
	var decoded any
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		return redacted
	}
	decoded, changed := redactJSONUpstreamValue(decoded)
	if !changed {
		return redacted
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		return redacted
	}
	return string(encoded)
}

func redactJSONUpstreamValue(value any) (any, bool) {
	switch typed := value.(type) {
	case string:
		redacted := redactUpstreamCredentials(typed)
		return redacted, redacted != typed
	case []any:
		changed := false
		for i, item := range typed {
			redacted, itemChanged := redactJSONUpstreamValue(item)
			typed[i] = redacted
			changed = changed || itemChanged
		}
		return typed, changed
	case map[string]any:
		changed := false
		for key, item := range typed {
			redacted, itemChanged := redactJSONUpstreamValue(item)
			typed[key] = redacted
			changed = changed || itemChanged
		}
		return typed, changed
	default:
		return value, false
	}
}

func runCtl(ctx context.Context, rt *runtime.Runtime, runas *string, argv []string, secrets ...string) (process.CommandResult, error) {
	if err := rejectRunas(runas); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	return rabbitmqRun(ctx, rt, rabbitmqCtlExecutable(rt), argv, secrets...)
}

// RabbitMQCtlCommandResolver is an optional Runner capability for resolving
// the Salt-selected rabbitmqctl path (including Windows registry installs).
type RabbitMQCtlCommandResolver interface {
	RabbitMQCtlCommand() (command string, ok bool)
}

func rabbitmqCtlExecutable(rt *runtime.Runtime) string {
	if rt != nil && rt.Runner != nil {
		if resolver, ok := rt.Runner.(RabbitMQCtlCommandResolver); ok {
			if command, resolved := resolver.RabbitMQCtlCommand(); resolved && command != "" {
				return command
			}
		}
	}
	return rabbitmqctlCommand
}

func runPlugins(ctx context.Context, rt *runtime.Runtime, runas *string, argv []string) (process.CommandResult, error) {
	if err := rejectRunas(runas); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	executable, err := pluginExecutable(ctx, rt)
	if err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	return rabbitmqRun(ctx, rt, executable, argv)
}

// RabbitMQPluginCommandResolver is an optional Runner capability for package
// installs that expose rabbitmq-plugins outside PATH (including a Windows
// batch wrapper). The default remains the canonical shell-free executable.
type RabbitMQPluginCommandResolver interface {
	RabbitMQPluginCommand() (command string, ok bool)
}

// RabbitMQPluginPackageFallback is implemented by the production Unix
// resolver.  It marks the exact Salt _get_rabbitmq_plugin fallback as
// available without allowing arbitrary test runners to claim a package query
// occurred.
type RabbitMQPluginPackageFallback interface {
	RabbitMQPluginCommandRequiresPackage() bool
}

// RabbitMQPackageVersionResolver is an optional hermetic capability for tests
// and embedding callers.  Production runtimes use the registered pkg.version
// function when the resolver is not supplied.
type RabbitMQPackageVersionResolver interface {
	RabbitMQPackageVersion(ctx context.Context, packageName string) (string, error)
}

// RabbitMQPolicyVersionResolver is an optional capability for callers that
// already know the broker version. It preserves Salt's version-selected
// policy column order without spawning an extra package/version probe.
type RabbitMQPolicyVersionResolver interface {
	RabbitMQPolicyVersion() (major, minor, patch int, ok bool)
}

func pluginExecutable(ctx context.Context, rt *runtime.Runtime) (string, error) {
	if rt != nil && rt.Runner != nil {
		if resolver, ok := rt.Runner.(RabbitMQPluginCommandResolver); ok {
			if command, resolved := resolver.RabbitMQPluginCommand(); resolved && command != "" {
				return command, nil
			}
			if fallback, ok := rt.Runner.(RabbitMQPluginPackageFallback); !ok || !fallback.RabbitMQPluginCommandRequiresPackage() {
				return rabbitmqPluginsCommand, nil
			}
		} else {
			return rabbitmqPluginsCommand, nil
		}
	}
	if runtime.CurrentGOOS() == "windows" {
		return rabbitmqPluginsCommand, nil
	}
	version, err := rabbitmqPackageVersion(ctx, rt, "rabbitmq-server")
	if err != nil {
		return "", errors.Join(errRabbitMQPluginsUnavailable, err)
	}
	path, err := rabbitmqPluginPackagePath(version)
	if err != nil {
		return "", errors.Join(errRabbitMQPluginsUnavailable, err)
	}
	return path, nil
}

func rabbitmqPackageVersion(ctx context.Context, rt *runtime.Runtime, packageName string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateText(packageName, "package", true); err != nil {
		return "", errors.Join(errRabbitMQPackageVersion, err)
	}
	if rt != nil && rt.Runner != nil {
		if resolver, ok := rt.Runner.(RabbitMQPackageVersionResolver); ok {
			version, err := resolver.RabbitMQPackageVersion(ctx, packageName)
			if err != nil {
				return "", errors.Join(errRabbitMQPackageVersion, err)
			}
			if strings.TrimSpace(version) == "" {
				return "", errRabbitMQPackageVersion
			}
			return version, nil
		}
	}
	if rt == nil || rt.Exec == nil {
		return "", errRabbitMQPackageVersion
	}
	value, err := rt.Exec.Call(ctx, rt, "pkg.version", &execpkg.VersionArgs{Name: packageName})
	if err != nil {
		return "", errors.Join(errRabbitMQPackageVersion, err)
	}
	version, ok := value.(string)
	if !ok || strings.TrimSpace(version) == "" {
		return "", errRabbitMQPackageVersion
	}
	return version, nil
}

func rabbitmqPluginPackagePath(packageVersion string) (string, error) {
	version := strings.TrimSpace(strings.SplitN(packageVersion, "-", 2)[0])
	if version == "" || !policyVersionRE.MatchString(version) || strings.IndexByte(version, 0) >= 0 || strings.ContainsAny(version, "/\\\r\n\t ") {
		return "", errRabbitMQPackageVersion
	}
	return "/usr/lib/rabbitmq/lib/rabbitmq_server-" + version + "/sbin/rabbitmq-plugins", nil
}

func rabbitmqPolicyPackageName(rt *runtime.Runtime) string {
	if rt != nil && rt.Facts != nil && rt.Facts.OS().Family == facts.FamilyFreeBSD {
		return "rabbitmq"
	}
	return "rabbitmq-server"
}

func commandResponse(result process.CommandResult) map[string]any {
	return map[string]any{
		"retcode": result.ExitCode,
		"stdout":  string(result.Stdout),
		"stderr":  string(result.Stderr),
	}
}

func typedArgs[T any](args any, name string) (*T, error) {
	value, ok := args.(*T)
	if !ok || value == nil {
		return nil, fmt.Errorf("%s: expected *arguments, got %T", name, args)
	}
	return value, nil
}

func pointerString(value *string, fallback string) string {
	if value == nil {
		return fallback
	}
	return *value
}

func pointerInt(value *int) (int, bool) {
	if value == nil || *value == 0 {
		return 0, false
	}
	return *value, true
}

func pointerBool(value *bool) bool { return value != nil && *value }

func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), commandTimeout)
}

// _safe_output mirrors Salt's _safe_output exactly. RabbitMQ's listing and
// warning decorations are intentionally filtered before any field parsing.
func _safe_output(line string) bool {
	return !(strings.HasPrefix(line, "Listing") && strings.HasSuffix(line, "...")) &&
		!(strings.HasPrefix(line, "Listing") && !strings.Contains(line, "\t")) &&
		!strings.Contains(line, "...done") &&
		!strings.HasPrefix(line, "WARNING:") &&
		line != ""
}

func splitRabbitLines(output string) []string {
	parts := strings.Split(output, "\n")
	for i := range parts {
		parts[i] = strings.TrimSuffix(parts[i], "\r")
	}
	return parts
}

func _strip_listing_to_done(outputList []string) []string {
	out := make([]string, 0, len(outputList))
	for _, line := range outputList {
		if _safe_output(line) {
			out = append(out, line)
		}
	}
	return out
}

func responseMap(response any) (map[string]any, error) {
	switch value := response.(type) {
	case map[string]any:
		return value, nil
	case process.CommandResult:
		return commandResponse(value), nil
	default:
		return nil, errRabbitMQInvalidArgument
	}
}

func responseString(value any) (string, error) {
	switch text := value.(type) {
	case string:
		return text, nil
	case []byte:
		return string(text), nil
	default:
		return "", errRabbitMQInvalidArgument
	}
}

func responseRetcode(value any) (int, error) {
	switch code := value.(type) {
	case int:
		return code, nil
	case int64:
		return int(code), nil
	case float64:
		return int(code), nil
	case string:
		var parsed int
		if _, err := fmt.Sscanf(code, "%d", &parsed); err != nil {
			return 0, errRabbitMQInvalidArgument
		}
		return parsed, nil
	default:
		return 0, errRabbitMQInvalidArgument
	}
}

func responseFields(response any) (stdout, stderr string, retcode int, err error) {
	mapped, err := responseMap(response)
	if err != nil {
		return "", "", 0, err
	}
	stdoutValue, ok := mapped["stdout"]
	if !ok {
		return "", "", 0, errRabbitMQInvalidArgument
	}
	stderrValue, ok := mapped["stderr"]
	if !ok {
		return "", "", 0, errRabbitMQInvalidArgument
	}
	retcodeValue, ok := mapped["retcode"]
	if !ok {
		return "", "", 0, errRabbitMQInvalidArgument
	}
	stdout, err = responseString(stdoutValue)
	if err != nil {
		return "", "", 0, err
	}
	stderr, err = responseString(stderrValue)
	if err != nil {
		return "", "", 0, err
	}
	retcode, err = responseRetcode(retcodeValue)
	return stdout, stderr, retcode, err
}

func _check_response(response any) error {
	if mapped, ok := response.(map[string]any); ok {
		_, stderr, retcode, err := responseFields(mapped)
		if err != nil {
			return err
		}
		if retcode != 0 || stderr != "" {
			return errRabbitMQCommand
		}
		return nil
	}
	if result, ok := response.(process.CommandResult); ok {
		if result.ExitCode != 0 || len(result.Stderr) != 0 {
			return errRabbitMQCommand
		}
		return nil
	}
	if text, ok := response.(string); ok {
		if strings.Contains(text, "Error") {
			return errRabbitMQCommand
		}
		return nil
	}
	return errRabbitMQInvalidArgument
}

func _format_response(response any, message string) (map[string]any, error) {
	if mapped, ok := response.(map[string]any); ok {
		stdout, stderr, retcode, err := responseFields(mapped)
		if err != nil {
			return nil, err
		}
		if retcode != 0 || stderr != "" {
			return nil, errRabbitMQCommand
		}
		return map[string]any{message: stdout}, nil
	}
	if result, ok := response.(process.CommandResult); ok {
		return _format_response(commandResponse(result), message)
	}
	if text, ok := response.(string); ok {
		if strings.Contains(text, "Error") {
			return nil, errRabbitMQCommand
		}
		return map[string]any{message: text}, nil
	}
	return nil, errRabbitMQInvalidArgument
}

// _output_to_dict mirrors Salt's tab-delimited parser. The variadic mapper is
// only a Go representation of Salt's optional callback; omitting it uses the
// default tab split.
func _output_to_dict(cmdoutput any, mappers ...func(string) any) (map[string]any, error) {
	var output string
	if mapped, ok := cmdoutput.(map[string]any); ok {
		var err error
		output, _, _, err = responseFields(mapped)
		if err != nil {
			return nil, err
		}
		if err := _check_response(mapped); err != nil {
			return nil, err
		}
	} else {
		var err error
		output, err = responseString(cmdoutput)
		if err != nil {
			return nil, err
		}
	}
	mapper := func(value string) any { return strings.Split(value, "\t") }
	if len(mappers) > 0 && mappers[0] != nil {
		mapper = mappers[0]
	}
	ret := map[string]any{}
	for _, row := range _strip_listing_to_done(splitRabbitLines(output)) {
		key, values, ok := strings.Cut(row, "\t")
		if !ok {
			ret[row] = ""
			continue
		}
		ret[key] = mapper(values)
	}
	return ret, nil
}

func _output_to_list(cmdoutput any) ([]string, error) {
	output, err := responseString(cmdoutput)
	if err != nil {
		return nil, err
	}
	ret := []string{}
	for _, line := range splitRabbitLines(output) {
		if !_safe_output(line) {
			continue
		}
		ret = append(ret, strings.Fields(line)...)
	}
	return ret, nil
}

func _output_lines_to_list(cmdoutput any) ([]string, error) {
	output, err := responseString(cmdoutput)
	if err != nil {
		return nil, err
	}
	ret := []string{}
	for _, line := range splitRabbitLines(output) {
		if _safe_output(line) {
			ret = append(ret, strings.TrimSpace(line))
		}
	}
	return ret, nil
}

// ---------------------------------------------------------------------------
// User, vhost, permission, status, and queue functions.

type ListUsersArgs struct {
	Runas *string `statekit:"name=runas"`
}
type listUsersFunc struct{}

func (listUsersFunc) Name() string { return "rabbitmq.list_users" }
func (listUsersFunc) Args() any    { return ListUsersArgs{} }
func (listUsersFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListUsersArgs](args, "rabbitmq.list_users")
	if err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"list_users", "-q"})
	if err != nil {
		return nil, err
	}
	return _output_to_dict(commandResponse(result), func(value string) any {
		inner := value
		if len(inner) >= 2 {
			inner = inner[1 : len(inner)-1]
		} else {
			inner = ""
		}
		if strings.Contains(value, ",") {
			parts := strings.Split(inner, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			return parts
		}
		return strings.Split(inner, " ")
	})
}

type ListVhostsArgs struct {
	Runas *string `statekit:"name=runas"`
}
type listVhostsFunc struct{}

func (listVhostsFunc) Name() string { return "rabbitmq.list_vhosts" }
func (listVhostsFunc) Args() any    { return ListVhostsArgs{} }
func (listVhostsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListVhostsArgs](args, "rabbitmq.list_vhosts")
	if err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"list_vhosts", "-q"})
	if err != nil {
		return nil, err
	}
	if err := _check_response(commandResponse(result)); err != nil {
		return nil, err
	}
	return _output_to_list(string(result.Stdout))
}

type ListUpstreamsArgs struct {
	Runas *string `statekit:"name=runas"`
}
type listUpstreamsFunc struct{}

func (listUpstreamsFunc) Name() string { return "rabbitmq.list_upstreams" }
func (listUpstreamsFunc) Args() any    { return ListUpstreamsArgs{} }
func (listUpstreamsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListUpstreamsArgs](args, "rabbitmq.list_upstreams")
	if err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"list_parameters", "-q"})
	if err != nil {
		return nil, err
	}
	ret := map[string]any{}
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		if !_safe_output(line) {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			return nil, errRabbitMQInvalidArgument
		}
		// list_parameters can contain an AMQP URI. It is data returned to the
		// CLI, so sanitize user-info before it becomes CLI-visible output.
		ret[parts[1]] = redactUpstreamCredentials(parts[2])
	}
	return ret, nil
}

type UserExistsArgs struct {
	Name  string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type userExistsFunc struct{}

func (userExistsFunc) Name() string { return "rabbitmq.user_exists" }
func (userExistsFunc) Args() any    { return UserExistsArgs{} }
func (userExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[UserExistsArgs](args, "rabbitmq.user_exists")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Name, "name", true); err != nil {
		return nil, err
	}
	values, err := listUsersFunc{}.Execute(ctx, rt, &ListUsersArgs{Runas: a.Runas})
	if err != nil {
		return nil, err
	}
	users, ok := values.(map[string]any)
	if !ok {
		return nil, errRabbitMQInvalidArgument
	}
	_, exists := users[a.Name]
	return exists, nil
}

type VhostExistsArgs struct {
	Name  string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type vhostExistsFunc struct{}

func (vhostExistsFunc) Name() string { return "rabbitmq.vhost_exists" }
func (vhostExistsFunc) Args() any    { return VhostExistsArgs{} }
func (vhostExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[VhostExistsArgs](args, "rabbitmq.vhost_exists")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Name, "name", true); err != nil {
		return nil, err
	}
	values, err := listVhostsFunc{}.Execute(ctx, rt, &ListVhostsArgs{Runas: a.Runas})
	if err != nil {
		return nil, err
	}
	for _, value := range values.([]string) {
		if value == a.Name {
			return true, nil
		}
	}
	return false, nil
}

type UpstreamExistsArgs struct {
	Name  string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type upstreamExistsFunc struct{}

func (upstreamExistsFunc) Name() string { return "rabbitmq.upstream_exists" }
func (upstreamExistsFunc) Args() any    { return UpstreamExistsArgs{} }
func (upstreamExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[UpstreamExistsArgs](args, "rabbitmq.upstream_exists")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Name, "name", true); err != nil {
		return nil, err
	}
	values, err := listUpstreamsFunc{}.Execute(ctx, rt, &ListUpstreamsArgs{Runas: a.Runas})
	if err != nil {
		return nil, err
	}
	upstreams, ok := values.(map[string]any)
	if !ok {
		return nil, errRabbitMQInvalidArgument
	}
	_, exists := upstreams[a.Name]
	return exists, nil
}

type AddUserArgs struct {
	Name     string  `statekit:"required"`
	Password *string `statekit:"name=password"`
	Runas    *string `statekit:"name=runas"`
}
type addUserFunc struct{}

// temporaryUserState is an invocation-local ownership record.  The random
// password is the ownership token; the absent-before-add and add-completed
// bits are deliberately separate so a started, interrupted, or non-zero add
// can never be mistaken for a confirmed creation.
type temporaryUserState struct {
	name            string
	password        string
	absentBeforeAdd bool
	addCompleted    bool
}

func (addUserFunc) Name() string { return "rabbitmq.add_user" }
func (addUserFunc) Args() any    { return AddUserArgs{} }
func (addUserFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[AddUserArgs](args, "rabbitmq.add_user")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Name, "name", true); err != nil {
		return nil, err
	}
	if a.Password != nil {
		if err := validateText(*a.Password, "password", false); err != nil {
			return nil, err
		}
	}
	if err := rejectRunas(a.Runas); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	candidatePassword := strings.Repeat("X", 15)
	if a.Password != nil {
		candidatePassword = *a.Password
	}
	if err := validateArgv(rabbitmqctlCommand, []string{"add_user", a.Name, candidatePassword}); err != nil {
		return nil, err
	}
	if a.Password == nil {
		// Authentication and deletion/clearing are separate broker operations.
		// No ownership-conditioned atomic cleanup exists: reject before creation.
		return nil, &runtime.UnsupportedError{Kind: "workflow", Name: "rabbitmq.add_user without password: atomic temporary-user cleanup unavailable"}
	}
	password := *a.Password
	result, err := runCtl(ctx, rt, a.Runas, []string{"add_user", a.Name, password}, password)
	if err != nil {
		return nil, err
	}
	return _format_response(commandResponse(result), "Added")
}

func verifyTemporaryUserOwnership(ctx context.Context, rt *runtime.Runtime, runas *string, ownership temporaryUserState) error {
	if !ownership.absentBeforeAdd || !ownership.addCompleted {
		return errRabbitMQRecovery
	}
	ownershipCtx, cancelOwnership := cleanupContext(ctx)
	defer cancelOwnership()
	value, err := (listUsersFunc{}).Execute(ownershipCtx, rt, &ListUsersArgs{Runas: runas})
	if err != nil {
		return errRabbitMQRecovery
	}
	users, ok := value.(map[string]any)
	if !ok {
		return errRabbitMQRecovery
	}
	if _, exists := users[ownership.name]; !exists {
		return errRabbitMQRecovery
	}
	// Authentication is observational only. Success never authorizes mutation:
	// another actor can replace the account immediately after authentication.
	value, err = (checkPasswordFunc{}).Execute(ownershipCtx, rt, &CheckPasswordArgs{
		Name: ownership.name, Password: ownership.password, Runas: runas,
	})
	if err != nil {
		return errRabbitMQRecovery
	}
	owned, ok := value.(bool)
	if !ok || !owned {
		return errRabbitMQRecovery
	}
	return nil
}

func cleanupTemporaryUser(ctx context.Context, rt *runtime.Runtime, runas *string, ownership temporaryUserState) error {
	// Even a successful non-atomic recheck cannot establish ownership at the
	// instant of mutation. Do not clear or delete, and never reflect diagnostics.
	return errRabbitMQRecovery
}

type DeleteUserArgs struct {
	Name  string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type deleteUserFunc struct{}

func (deleteUserFunc) Name() string { return "rabbitmq.delete_user" }
func (deleteUserFunc) Args() any    { return DeleteUserArgs{} }
func (deleteUserFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DeleteUserArgs](args, "rabbitmq.delete_user")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Name, "name", true); err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"delete_user", a.Name})
	if err != nil {
		return nil, err
	}
	return _format_response(commandResponse(result), "Deleted")
}

type ChangePasswordArgs struct {
	Name     string  `statekit:"required"`
	Password string  `statekit:"required"`
	Runas    *string `statekit:"name=runas"`
}
type changePasswordFunc struct{}

func (changePasswordFunc) Name() string { return "rabbitmq.change_password" }
func (changePasswordFunc) Args() any    { return ChangePasswordArgs{} }
func (changePasswordFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ChangePasswordArgs](args, "rabbitmq.change_password")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Name, "name", true); err != nil {
		return nil, err
	}
	if err := validateText(a.Password, "password", false); err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"change_password", a.Name, a.Password}, a.Password)
	if err != nil {
		return nil, err
	}
	return _format_response(commandResponse(result), "Password Changed")
}

type ClearPasswordArgs struct {
	Name  string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type clearPasswordFunc struct{}

func (clearPasswordFunc) Name() string { return "rabbitmq.clear_password" }
func (clearPasswordFunc) Args() any    { return ClearPasswordArgs{} }
func (clearPasswordFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ClearPasswordArgs](args, "rabbitmq.clear_password")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Name, "name", true); err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"clear_password", a.Name})
	if err != nil {
		return nil, err
	}
	return _format_response(commandResponse(result), "Password Cleared")
}

type CheckPasswordArgs struct {
	Name     string  `statekit:"required"`
	Password string  `statekit:"required"`
	Runas    *string `statekit:"name=runas"`
}
type checkPasswordFunc struct{}

func (checkPasswordFunc) Name() string { return "rabbitmq.check_password" }
func (checkPasswordFunc) Args() any    { return CheckPasswordArgs{} }
func (checkPasswordFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[CheckPasswordArgs](args, "rabbitmq.check_password")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Name, "name", true); err != nil {
		return nil, err
	}
	if err := validateText(a.Password, "password", false); err != nil {
		return nil, err
	}
	if err := rejectRunas(a.Runas); err != nil {
		return nil, err
	}
	// Both version branches have a complete command target. Validate both
	// before status so oversized credentials cannot cause a preliminary call.
	authArgv := []string{"authenticate_user", a.Name, a.Password}
	if err := validateArgv(rabbitmqctlCommand, authArgv); err != nil {
		return nil, err
	}
	escapedName := escapeErlangBinary(a.Name)
	escapedPassword := escapeErlangBinary(a.Password)
	eval := fmt.Sprintf(
		`rabbit_auth_backend_internal:check_user_login(<<"%s">>, [{password, <<"%s">>}]).`,
		escapedName, escapedPassword,
	)
	evalArgv := []string{"eval", eval}
	if err := validateArgv(rabbitmqctlCommand, evalArgv); err != nil {
		return nil, err
	}
	statusResult, err := runCtl(ctx, rt, a.Runas, []string{"status"})
	if err != nil {
		return nil, err
	}
	version := rabbitVersion(string(statusResult.Stdout))
	if versionAtLeast(version, 3, 5, 7) {
		authResult, err := runCtl(ctx, rt, a.Runas, authArgv, a.Password)
		if err != nil {
			return nil, err
		}
		return authResult.ExitCode == 0 && len(authResult.Stderr) == 0, nil
	}

	evalResult, err := runCtl(ctx, rt, a.Runas, evalArgv, a.Password, escapedPassword)
	if err != nil {
		return nil, err
	}
	formatted, err := _format_response(commandResponse(evalResult), "password-check")
	if err != nil {
		return nil, err
	}
	value, _ := formatted["password-check"].(string)
	return !strings.Contains(value, "invalid credentials"), nil
}

func escapeErlangBinary(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func rabbitVersion(output string) [3]int {
	match := oldRabbitVersionRE.FindStringSubmatch(output)
	if len(match) == 0 {
		match = newRabbitVersionRE.FindStringSubmatch(output)
	}
	if len(match) < 2 {
		return [3]int{}
	}
	version := strings.Split(strings.Split(match[1], "-")[0], ".")
	if len(version) < 3 {
		return [3]int{}
	}
	var parsed [3]int
	for i := range parsed {
		value, err := strconv.Atoi(version[i])
		if err != nil {
			return [3]int{}
		}
		parsed[i] = value
	}
	return parsed
}

func versionAtLeast(version [3]int, major, minor, patch int) bool {
	want := [3]int{major, minor, patch}
	for i := range version {
		if version[i] != want[i] {
			return version[i] > want[i]
		}
	}
	return true
}

type AddVhostArgs struct {
	Vhost string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type addVhostFunc struct{}

func (addVhostFunc) Name() string { return "rabbitmq.add_vhost" }
func (addVhostFunc) Args() any    { return AddVhostArgs{} }
func (addVhostFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[AddVhostArgs](args, "rabbitmq.add_vhost")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Vhost, "vhost", true); err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"add_vhost", a.Vhost})
	if err != nil {
		return nil, err
	}
	return _format_response(commandResponse(result), "Added")
}

type DeleteVhostArgs struct {
	Vhost string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type deleteVhostFunc struct{}

func (deleteVhostFunc) Name() string { return "rabbitmq.delete_vhost" }
func (deleteVhostFunc) Args() any    { return DeleteVhostArgs{} }
func (deleteVhostFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DeleteVhostArgs](args, "rabbitmq.delete_vhost")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Vhost, "vhost", true); err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"delete_vhost", a.Vhost})
	if err != nil {
		return nil, err
	}
	return _format_response(commandResponse(result), "Deleted")
}

type SetPermissionsArgs struct {
	Vhost string  `statekit:"required,name=vhost"`
	User  string  `statekit:"required,name=user"`
	Conf  *string `statekit:"name=conf"`
	Write *string `statekit:"name=write"`
	Read  *string `statekit:"name=read"`
	Runas *string `statekit:"name=runas"`
}
type setPermissionsFunc struct{}

func (setPermissionsFunc) Name() string { return "rabbitmq.set_permissions" }
func (setPermissionsFunc) Args() any    { return SetPermissionsArgs{} }
func (setPermissionsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[SetPermissionsArgs](args, "rabbitmq.set_permissions")
	if err != nil {
		return nil, err
	}
	for name, value := range map[string]string{"vhost": a.Vhost, "user": a.User} {
		if err := validateText(value, name, true); err != nil {
			return nil, err
		}
	}
	conf := pointerString(a.Conf, ".*")
	write := pointerString(a.Write, ".*")
	read := pointerString(a.Read, ".*")
	for name, value := range map[string]string{"conf": conf, "write": write, "read": read} {
		if err := validateText(value, name, false); err != nil {
			return nil, err
		}
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"set_permissions", "-p", a.Vhost, a.User, conf, write, read})
	if err != nil {
		return nil, err
	}
	return _format_response(commandResponse(result), "Permissions Set")
}

type ListPermissionsArgs struct {
	Vhost string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type listPermissionsFunc struct{}

func (listPermissionsFunc) Name() string { return "rabbitmq.list_permissions" }
func (listPermissionsFunc) Args() any    { return ListPermissionsArgs{} }
func (listPermissionsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListPermissionsArgs](args, "rabbitmq.list_permissions")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Vhost, "vhost", true); err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"list_permissions", "--formatter=json", "-p", a.Vhost})
	if err != nil {
		return nil, err
	}
	return permissionMap(string(result.Stdout), "user")
}

type ListUserPermissionsArgs struct {
	Name  string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type listUserPermissionsFunc struct{}

func (listUserPermissionsFunc) Name() string { return "rabbitmq.list_user_permissions" }
func (listUserPermissionsFunc) Args() any    { return ListUserPermissionsArgs{} }
func (listUserPermissionsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListUserPermissionsArgs](args, "rabbitmq.list_user_permissions")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Name, "name", true); err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"list_user_permissions", a.Name, "--formatter=json"})
	if err != nil {
		return nil, err
	}
	return permissionMap(string(result.Stdout), "vhost")
}

func permissionMap(output, key string) (map[string]any, error) {
	var permissions []map[string]any
	if err := json.Unmarshal([]byte(output), &permissions); err != nil {
		return nil, err
	}
	ret := map[string]any{}
	for _, permission := range permissions {
		value, ok := permission[key]
		name, okString := value.(string)
		if !ok || !okString {
			return nil, errRabbitMQInvalidArgument
		}
		copyPermission := make(map[string]any, len(permission)-1)
		for field, fieldValue := range permission {
			if field != key {
				copyPermission[field] = fieldValue
			}
		}
		ret[name] = copyPermission
	}
	return ret, nil
}

type SetUserTagsArgs struct {
	Name  string  `statekit:"required"`
	Tags  any     `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type setUserTagsFunc struct{}

func (setUserTagsFunc) Name() string { return "rabbitmq.set_user_tags" }
func (setUserTagsFunc) Args() any    { return SetUserTagsArgs{} }
func (setUserTagsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[SetUserTagsArgs](args, "rabbitmq.set_user_tags")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Name, "name", true); err != nil {
		return nil, err
	}
	if a.Tags == nil {
		return nil, errRabbitMQInvalidArgument
	}
	tags, err := stringList(a.Tags)
	if err != nil {
		return nil, errRabbitMQInvalidArgument
	}
	for _, tag := range tags {
		if err := validateText(tag, "tag", false); err != nil {
			return nil, err
		}
	}
	argv := append([]string{"set_user_tags", a.Name}, tags...)
	result, err := runCtl(ctx, rt, a.Runas, argv)
	if err != nil {
		return nil, err
	}
	return _format_response(commandResponse(result), "Tag(s) set")
}

func stringList(value any) ([]string, error) {
	scalar := func(item any) (string, error) {
		switch typed := item.(type) {
		case string:
			return typed, nil
		case bool:
			if typed {
				return "true", nil
			}
			return "false", nil
		case int:
			return fmt.Sprint(typed), nil
		case int64:
			return fmt.Sprint(typed), nil
		case float64:
			return fmt.Sprint(typed), nil
		default:
			return "", errRabbitMQInvalidArgument
		}
	}
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...), nil
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text, err := scalar(item)
			if err != nil {
				return nil, err
			}
			out = append(out, text)
		}
		return out, nil
	default:
		text, err := scalar(value)
		if err != nil {
			return nil, err
		}
		return []string{text}, nil
	}
}

type StatusArgs struct {
	Runas *string `statekit:"name=runas"`
}
type statusFunc struct{}

func (statusFunc) Name() string { return "rabbitmq.status" }
func (statusFunc) Args() any    { return StatusArgs{} }
func (statusFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[StatusArgs](args, "rabbitmq.status")
	if err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"status"})
	if err != nil {
		return nil, err
	}
	if err := _check_response(commandResponse(result)); err != nil {
		return nil, err
	}
	return string(result.Stdout), nil
}

type ClusterStatusArgs struct {
	Runas *string `statekit:"name=runas"`
}
type clusterStatusFunc struct{}

func (clusterStatusFunc) Name() string { return "rabbitmq.cluster_status" }
func (clusterStatusFunc) Args() any    { return ClusterStatusArgs{} }
func (clusterStatusFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ClusterStatusArgs](args, "rabbitmq.cluster_status")
	if err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"cluster_status"})
	if err != nil {
		return nil, err
	}
	if err := _check_response(commandResponse(result)); err != nil {
		return nil, err
	}
	return string(result.Stdout), nil
}

type JoinClusterArgs struct {
	Host    string  `statekit:"required"`
	User    *string `statekit:"name=user"`
	RamNode *bool   `statekit:"name=ram_node"`
	Runas   *string `statekit:"name=runas"`
}
type joinClusterFunc struct{}

func (joinClusterFunc) Name() string { return "rabbitmq.join_cluster" }
func (joinClusterFunc) Args() any    { return JoinClusterArgs{} }
func (joinClusterFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[JoinClusterArgs](args, "rabbitmq.join_cluster")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Host, "host", true); err != nil {
		return nil, err
	}
	user := pointerString(a.User, defaultRabbitUser)
	if err := validateText(user, "user", true); err != nil {
		return nil, err
	}
	if err := rejectRunas(a.Runas); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	argv := []string{"join_cluster"}
	if pointerBool(a.RamNode) {
		argv = append(argv, "--ram")
	}
	argv = append(argv, user+"@"+a.Host)
	// Validate the complete mutating operation before stop_app. This prevents
	// an oversized join target from leaving the node stopped.
	if err := validateArgv(rabbitmqctlCommand, argv); err != nil {
		return nil, err
	}
	if _, err := process.BuildRabbitMQCommand(runtime.CurrentGOOS(), rabbitmqCtlExecutable(rt), argv); err != nil {
		return nil, err
	}
	stopResult, err := runCtl(ctx, rt, a.Runas, []string{"stop_app"})
	if err != nil {
		// The Runner may report cancellation after stop_app has completed. A
		// best-effort restart is safe here and keeps the node recoverable.
		if stopResult.Started {
			cleanupCtx, cancelCleanup := cleanupContext(ctx)
			_, _ = runCtl(cleanupCtx, rt, a.Runas, []string{"start_app"})
			cancelCleanup()
		}
		return nil, err
	}
	if !stopResult.Started {
		return nil, errRabbitMQCommand
	}
	stopErr := _check_response(commandResponse(stopResult))
	var joinResult process.CommandResult
	var joinErr error
	if stopErr == nil {
		joinResult, joinErr = runCtl(ctx, rt, a.Runas, argv)
	}
	// Once stop_app has completed, use a bounded cleanup context even when the
	// caller cancels the join. The application must be restarted after every
	// completed stop attempt; the original error remains the primary result.
	cleanupCtx, cancelCleanup := cleanupContext(ctx)
	startResult, startErr := runCtl(cleanupCtx, rt, a.Runas, []string{"start_app"})
	cancelCleanup()
	if joinErr != nil {
		return nil, joinErr
	}
	if stopErr != nil {
		return nil, stopErr
	}
	if startErr != nil {
		return nil, startErr
	}
	if err := _check_response(commandResponse(startResult)); err != nil {
		return nil, err
	}
	return _format_response(commandResponse(joinResult), "Join")
}

type StopAppArgs struct {
	Runas *string `statekit:"name=runas"`
}
type stopAppFunc struct{}

func (stopAppFunc) Name() string { return "rabbitmq.stop_app" }
func (stopAppFunc) Args() any    { return StopAppArgs{} }
func (stopAppFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[StopAppArgs](args, "rabbitmq.stop_app")
	if err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"stop_app"})
	if err != nil {
		return nil, err
	}
	if err := _check_response(commandResponse(result)); err != nil {
		return nil, err
	}
	return string(result.Stdout), nil
}

type StartAppArgs struct {
	Runas *string `statekit:"name=runas"`
}
type startAppFunc struct{}

func (startAppFunc) Name() string { return "rabbitmq.start_app" }
func (startAppFunc) Args() any    { return StartAppArgs{} }
func (startAppFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[StartAppArgs](args, "rabbitmq.start_app")
	if err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"start_app"})
	if err != nil {
		return nil, err
	}
	if err := _check_response(commandResponse(result)); err != nil {
		return nil, err
	}
	return string(result.Stdout), nil
}

type ResetArgs struct {
	Runas *string `statekit:"name=runas"`
}
type resetFunc struct{}

func (resetFunc) Name() string { return "rabbitmq.reset" }
func (resetFunc) Args() any    { return ResetArgs{} }
func (resetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ResetArgs](args, "rabbitmq.reset")
	if err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"reset"})
	if err != nil {
		return nil, err
	}
	if err := _check_response(commandResponse(result)); err != nil {
		return nil, err
	}
	return string(result.Stdout), nil
}

type ForceResetArgs struct {
	Runas *string `statekit:"name=runas"`
}
type forceResetFunc struct{}

func (forceResetFunc) Name() string { return "rabbitmq.force_reset" }
func (forceResetFunc) Args() any    { return ForceResetArgs{} }
func (forceResetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ForceResetArgs](args, "rabbitmq.force_reset")
	if err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"force_reset"})
	if err != nil {
		return nil, err
	}
	if err := _check_response(commandResponse(result)); err != nil {
		return nil, err
	}
	return string(result.Stdout), nil
}

type ListQueuesArgs struct {
	Runas *string  `statekit:"name=runas"`
	Args  []string `statekit:"name=args"`
}
type listQueuesFunc struct{}

func (listQueuesFunc) Name() string { return "rabbitmq.list_queues" }
func (listQueuesFunc) Args() any    { return ListQueuesArgs{} }
func (listQueuesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListQueuesArgs](args, "rabbitmq.list_queues")
	if err != nil {
		return nil, err
	}
	for _, value := range a.Args {
		if err := validateText(value, "args", false); err != nil {
			return nil, err
		}
	}
	argv := append([]string{"list_queues", "-q"}, append([]string(nil), a.Args...)...)
	result, err := runCtl(ctx, rt, a.Runas, argv)
	if err != nil {
		return nil, err
	}
	if err := _check_response(commandResponse(result)); err != nil {
		return nil, err
	}
	return _output_to_dict(string(result.Stdout))
}

type ListQueuesVhostArgs struct {
	Vhost string   `statekit:"required"`
	Runas *string  `statekit:"name=runas"`
	Args  []string `statekit:"name=args"`
}
type listQueuesVhostFunc struct{}

func (listQueuesVhostFunc) Name() string { return "rabbitmq.list_queues_vhost" }
func (listQueuesVhostFunc) Args() any    { return ListQueuesVhostArgs{} }
func (listQueuesVhostFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListQueuesVhostArgs](args, "rabbitmq.list_queues_vhost")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Vhost, "vhost", true); err != nil {
		return nil, err
	}
	for _, value := range a.Args {
		if err := validateText(value, "args", false); err != nil {
			return nil, err
		}
	}
	argv := []string{"list_queues", "-q", "-p", a.Vhost}
	argv = append(argv, a.Args...)
	result, err := runCtl(ctx, rt, a.Runas, argv)
	if err != nil {
		return nil, err
	}
	if err := _check_response(commandResponse(result)); err != nil {
		return nil, err
	}
	return _output_to_dict(string(result.Stdout))
}

// ---------------------------------------------------------------------------
// Policy functions.

type ListPoliciesArgs struct {
	Vhost *string `statekit:"name=vhost"`
	Runas *string `statekit:"name=runas"`
}
type listPoliciesFunc struct{}

func (listPoliciesFunc) Name() string { return "rabbitmq.list_policies" }
func (listPoliciesFunc) Args() any    { return ListPoliciesArgs{} }
func (listPoliciesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListPoliciesArgs](args, "rabbitmq.list_policies")
	if err != nil {
		return nil, err
	}
	vhost := pointerString(a.Vhost, defaultVhost)
	if err := validateText(vhost, "vhost", true); err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"list_policies", "-q", "-p", vhost})
	if err != nil {
		return nil, err
	}
	if err := _check_response(commandResponse(result)); err != nil {
		return nil, err
	}
	version, versionKnown := rabbitmqPolicyVersion(rt)
	if !versionKnown {
		// Salt always obtains this version through pkg.version.  Do not use
		// broker status or a glob-selected install as a substitute: either the
		// exact package query or an explicit embedding resolver must establish
		// the layout.
		packageVersion, err := rabbitmqPackageVersion(ctx, rt, rabbitmqPolicyPackageName(rt))
		if err != nil {
			return nil, errors.Join(errRabbitMQPolicyLayout, err)
		}
		version, err = rabbitmqPolicyVersionFromPackage(packageVersion)
		if err != nil {
			return nil, errors.Join(errRabbitMQPolicyLayout, err)
		}
		versionKnown = true
	}
	return parsePoliciesForVersion(string(result.Stdout), version, true)
}

func parsePolicies(output string) (map[string]any, error) {
	return parsePoliciesForVersion(output, [3]int{}, false)
}

func rabbitmqPolicyVersion(rt *runtime.Runtime) ([3]int, bool) {
	if rt != nil && rt.Runner != nil {
		if resolver, ok := rt.Runner.(RabbitMQPolicyVersionResolver); ok {
			major, minor, patch, resolved := resolver.RabbitMQPolicyVersion()
			return [3]int{major, minor, patch}, resolved
		}
	}
	return [3]int{}, false
}

func rabbitmqPolicyVersionFromPackage(packageVersion string) ([3]int, error) {
	version := strings.TrimSpace(strings.SplitN(packageVersion, "-", 2)[0])
	match := packageVersionRE.FindStringSubmatch(version)
	if match == nil {
		return [3]int{}, errRabbitMQPackageVersion
	}
	// Only the comparison with Version("3.7") is needed. Return a layout
	// sentinel, not a lossy numeric prefix. Decimal-string comparisons avoid
	// overflow for PEP 440's arbitrary-size epoch and release integers.
	modern := strings.TrimLeft(match[1], "0") != ""
	if !modern {
		release := strings.Split(match[2], ".")
		comparison := 0
		for i := 0; i < len(release) || i < 2; i++ {
			part := ""
			if i < len(release) {
				part = strings.TrimLeft(release[i], "0")
			}
			target := ""
			if i == 0 {
				target = "3"
			}
			if i == 1 {
				target = "7"
			}
			if len(part) != len(target) {
				if len(part) > len(target) {
					comparison = 1
				} else {
					comparison = -1
				}
			} else {
				comparison = strings.Compare(part, target)
			}
			if comparison != 0 {
				break
			}
		}
		// At an equal release, any prerelease precedes the final release.
		// A dev release without a post release also precedes it; post.dev is
		// after the final release. Local identifiers cannot reverse this order.
		modern = comparison > 0 || comparison == 0 && match[3] == "" &&
			(match[6] == "" || match[4] != "" || match[5] != "")
	}
	if modern {
		return [3]int{3, 7, 0}, nil
	}
	return [3]int{3, 6, 0}, nil
}

func parsePoliciesForVersion(output string, version [3]int, versionKnown bool) (map[string]any, error) {
	ret := map[string]any{}
	lines, err := _output_lines_to_list(output)
	if err != nil {
		return nil, err
	}
	for _, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) != 5 && len(parts) != 6 {
			continue
		}
		if len(parts) == 6 && !versionKnown && isPolicyApplyTo(parts[2]) && isPolicyApplyTo(parts[3]) {
			return nil, errRabbitMQPolicyLayout
		}
		if len(parts) == 5 && versionKnown && versionAtLeast(version, 3, 7, 0) {
			return nil, errRabbitMQPolicyLayout
		}
		vhost, name := parts[0], parts[1]
		if _, ok := ret[vhost]; !ok {
			ret[vhost] = map[string]any{}
		}
		policies := ret[vhost].(map[string]any)
		policy := map[string]any{}
		legacyLayout := len(parts) == 6 && isPolicyApplyTo(parts[2]) && !isPolicyApplyTo(parts[3])
		if len(parts) == 6 && versionKnown {
			legacyLayout = !versionAtLeast(version, 3, 7, 0)
		}
		if legacyLayout {
			// RabbitMQ < 3.7 emitted apply_to before pattern.
			policy["apply_to"] = parts[2]
			policy["pattern"] = parts[3]
			policy["definition"] = parts[4]
			policy["priority"] = parts[5]
		} else if len(parts) == 6 {
			// RabbitMQ >= 3.7 switched pattern and apply_to. An ambiguous
			// line was rejected above unless the optional version resolver made
			// the layout explicit.
			policy["pattern"] = parts[2]
			policy["apply_to"] = parts[3]
			policy["definition"] = parts[4]
			policy["priority"] = parts[5]
		} else {
			policy["pattern"] = parts[2]
			policy["definition"] = parts[3]
			policy["priority"] = parts[4]
		}
		policies[name] = policy
	}
	return ret, nil
}

func isPolicyApplyTo(value string) bool {
	switch value {
	case "all", "exchanges", "queues":
		return true
	default:
		return false
	}
}

type SetPolicyArgs struct {
	Vhost      string  `statekit:"required"`
	Name       string  `statekit:"required"`
	Pattern    string  `statekit:"required"`
	Definition any     `statekit:"required"`
	Priority   *string `statekit:"name=priority"`
	Runas      *string `statekit:"name=runas"`
	ApplyTo    *string `statekit:"name=apply_to"`
}
type setPolicyFunc struct{}

func (setPolicyFunc) Name() string { return "rabbitmq.set_policy" }
func (setPolicyFunc) Args() any    { return SetPolicyArgs{} }
func (setPolicyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[SetPolicyArgs](args, "rabbitmq.set_policy")
	if err != nil {
		return nil, err
	}
	for name, value := range map[string]string{"vhost": a.Vhost, "name": a.Name, "pattern": a.Pattern} {
		if err := validateText(value, name, true); err != nil {
			return nil, err
		}
	}
	definition, err := policyDefinition(a.Definition)
	if err != nil {
		return nil, err
	}
	if err := validateText(definition, "definition", true); err != nil {
		return nil, err
	}
	argv := []string{"set_policy", "-p", a.Vhost}
	if a.Priority != nil && *a.Priority != "" {
		if err := validateText(*a.Priority, "priority", false); err != nil {
			return nil, err
		}
		argv = append(argv, "--priority", *a.Priority)
	}
	if a.ApplyTo != nil && *a.ApplyTo != "" {
		if err := validateText(*a.ApplyTo, "apply_to", false); err != nil {
			return nil, err
		}
		argv = append(argv, "--apply-to", *a.ApplyTo)
	}
	argv = append(argv, a.Name, a.Pattern, definition)
	result, err := runCtl(ctx, rt, a.Runas, argv, definition)
	if err != nil {
		return nil, err
	}
	return _format_response(commandResponse(result), "Set")
}

func policyDefinition(value any) (string, error) {
	switch definition := value.(type) {
	case string:
		return definition, nil
	case map[string]any:
		encoded, err := marshalSaltJSONDocument(definition)
		if err != nil {
			return "", err
		}
		return encoded, nil
	case map[string]string:
		encoded, err := marshalSaltJSONDocument(definition)
		if err != nil {
			return "", err
		}
		return encoded, nil
	default:
		return "", fmt.Errorf("rabbitmq: the definition argument must be a dictionary or JSON string")
	}
}

func marshalSaltJSONDocument(value any) (string, error) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			encodedKey, err := marshalSaltJSONValue(key)
			if err != nil {
				return "", err
			}
			encodedValue, err := marshalSaltJSONDocument(typed[key])
			if err != nil {
				return "", err
			}
			parts = append(parts, encodedKey+": "+encodedValue)
		}
		return "{" + strings.Join(parts, ", ") + "}", nil
	case map[string]string:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			encodedKey, err := marshalSaltJSONValue(key)
			if err != nil {
				return "", err
			}
			encodedValue, err := marshalSaltJSONValue(typed[key])
			if err != nil {
				return "", err
			}
			parts = append(parts, encodedKey+": "+encodedValue)
		}
		return "{" + strings.Join(parts, ", ") + "}", nil
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			encoded, err := marshalSaltJSONDocument(item)
			if err != nil {
				return "", err
			}
			parts = append(parts, encoded)
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	case []string:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			encoded, err := marshalSaltJSONValue(item)
			if err != nil {
				return "", err
			}
			parts = append(parts, encoded)
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	default:
		return marshalSaltJSONValue(value)
	}
}

type DeletePolicyArgs struct {
	Vhost string  `statekit:"required"`
	Name  string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type deletePolicyFunc struct{}

func (deletePolicyFunc) Name() string { return "rabbitmq.delete_policy" }
func (deletePolicyFunc) Args() any    { return DeletePolicyArgs{} }
func (deletePolicyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DeletePolicyArgs](args, "rabbitmq.delete_policy")
	if err != nil {
		return nil, err
	}
	for name, value := range map[string]string{"vhost": a.Vhost, "name": a.Name} {
		if err := validateText(value, name, true); err != nil {
			return nil, err
		}
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"clear_policy", "-p", a.Vhost, a.Name})
	if err != nil {
		return nil, err
	}
	return _format_response(commandResponse(result), "Deleted")
}

type PolicyExistsArgs struct {
	Vhost string  `statekit:"required"`
	Name  string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type policyExistsFunc struct{}

func (policyExistsFunc) Name() string { return "rabbitmq.policy_exists" }
func (policyExistsFunc) Args() any    { return PolicyExistsArgs{} }
func (policyExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[PolicyExistsArgs](args, "rabbitmq.policy_exists")
	if err != nil {
		return nil, err
	}
	for name, value := range map[string]string{"vhost": a.Vhost, "name": a.Name} {
		if err := validateText(value, name, true); err != nil {
			return nil, err
		}
	}
	// Match Salt's pinned implementation: policy_exists calls list_policies
	// without forwarding vhost, so list_policies applies its default "/".
	values, err := listPoliciesFunc{}.Execute(ctx, rt, &ListPoliciesArgs{Runas: a.Runas})
	if err != nil {
		return nil, err
	}
	policies, ok := values.(map[string]any)
	if !ok {
		return nil, errRabbitMQInvalidArgument
	}
	vhost, ok := policies[a.Vhost].(map[string]any)
	if !ok {
		return false, nil
	}
	_, exists := vhost[a.Name]
	return exists, nil
}

// ---------------------------------------------------------------------------
// Plugin functions.

type ListAvailablePluginsArgs struct {
	Runas *string `statekit:"name=runas"`
}
type listAvailablePluginsFunc struct{}

func (listAvailablePluginsFunc) Name() string { return "rabbitmq.list_available_plugins" }
func (listAvailablePluginsFunc) Args() any    { return ListAvailablePluginsArgs{} }
func (listAvailablePluginsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListAvailablePluginsArgs](args, "rabbitmq.list_available_plugins")
	if err != nil {
		return nil, err
	}
	result, err := runPlugins(ctx, rt, a.Runas, []string{"list", "-m"})
	if err != nil {
		return nil, err
	}
	if err := _check_response(commandResponse(result)); err != nil {
		return nil, err
	}
	return _output_to_list(string(result.Stdout))
}

type ListEnabledPluginsArgs struct {
	Runas *string `statekit:"name=runas"`
}
type listEnabledPluginsFunc struct{}

func (listEnabledPluginsFunc) Name() string { return "rabbitmq.list_enabled_plugins" }
func (listEnabledPluginsFunc) Args() any    { return ListEnabledPluginsArgs{} }
func (listEnabledPluginsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListEnabledPluginsArgs](args, "rabbitmq.list_enabled_plugins")
	if err != nil {
		return nil, err
	}
	result, err := runPlugins(ctx, rt, a.Runas, []string{"list", "-m", "-e"})
	if err != nil {
		return nil, err
	}
	if err := _check_response(commandResponse(result)); err != nil {
		return nil, err
	}
	return _output_to_list(string(result.Stdout))
}

type PluginIsEnabledArgs struct {
	Name  string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type pluginIsEnabledFunc struct{}

func (pluginIsEnabledFunc) Name() string { return "rabbitmq.plugin_is_enabled" }
func (pluginIsEnabledFunc) Args() any    { return PluginIsEnabledArgs{} }
func (pluginIsEnabledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[PluginIsEnabledArgs](args, "rabbitmq.plugin_is_enabled")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Name, "name", true); err != nil {
		return nil, err
	}
	values, err := listEnabledPluginsFunc{}.Execute(ctx, rt, &ListEnabledPluginsArgs{Runas: a.Runas})
	if err != nil {
		return nil, err
	}
	for _, value := range values.([]string) {
		if value == a.Name {
			return true, nil
		}
	}
	return false, nil
}

type EnablePluginArgs struct {
	Name  string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type enablePluginFunc struct{}

func (enablePluginFunc) Name() string { return "rabbitmq.enable_plugin" }
func (enablePluginFunc) Args() any    { return EnablePluginArgs{} }
func (enablePluginFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[EnablePluginArgs](args, "rabbitmq.enable_plugin")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Name, "name", true); err != nil {
		return nil, err
	}
	result, err := runPlugins(ctx, rt, a.Runas, []string{"enable", a.Name})
	if err != nil {
		return nil, err
	}
	return _format_response(commandResponse(result), "Enabled")
}

type DisablePluginArgs struct {
	Name  string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type disablePluginFunc struct{}

func (disablePluginFunc) Name() string { return "rabbitmq.disable_plugin" }
func (disablePluginFunc) Args() any    { return DisablePluginArgs{} }
func (disablePluginFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DisablePluginArgs](args, "rabbitmq.disable_plugin")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Name, "name", true); err != nil {
		return nil, err
	}
	result, err := runPlugins(ctx, rt, a.Runas, []string{"disable", a.Name})
	if err != nil {
		return nil, err
	}
	return _format_response(commandResponse(result), "Disabled")
}

// ---------------------------------------------------------------------------
// Federation upstream functions.

type SetUpstreamArgs struct {
	Name           string  `statekit:"required"`
	URI            string  `statekit:"required,name=uri"`
	PrefetchCount  *int    `statekit:"name=prefetch_count"`
	ReconnectDelay *int    `statekit:"name=reconnect_delay"`
	AckMode        *string `statekit:"name=ack_mode"`
	TrustUserID    *bool   `statekit:"name=trust_user_id"`
	Exchange       *string `statekit:"name=exchange"`
	MaxHops        *int    `statekit:"name=max_hops"`
	Expires        *int    `statekit:"name=expires"`
	MessageTTL     *int    `statekit:"name=message_ttl"`
	HAPolicy       *string `statekit:"name=ha_policy"`
	Queue          *string `statekit:"name=queue"`
	Runas          *string `statekit:"name=runas"`
}
type setUpstreamFunc struct{}

func (setUpstreamFunc) Name() string { return "rabbitmq.set_upstream" }
func (setUpstreamFunc) Args() any    { return SetUpstreamArgs{} }
func (setUpstreamFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[SetUpstreamArgs](args, "rabbitmq.set_upstream")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Name, "name", true); err != nil {
		return nil, err
	}
	if err := validateText(a.URI, "uri", true); err != nil {
		return nil, err
	}
	for name, value := range map[string]string{"ack_mode": pointerString(a.AckMode, ""), "exchange": pointerString(a.Exchange, ""), "ha_policy": pointerString(a.HAPolicy, ""), "queue": pointerString(a.Queue, "")} {
		if err := validateText(value, name, false); err != nil {
			return nil, err
		}
	}
	params := upstreamParams{
		URI:            a.URI,
		PrefetchCount:  pointerValue(a.PrefetchCount),
		ReconnectDelay: pointerValue(a.ReconnectDelay),
		AckMode:        pointerString(a.AckMode, ""),
		TrustUserID:    pointerBool(a.TrustUserID),
		Exchange:       pointerString(a.Exchange, ""),
		MaxHops:        pointerValue(a.MaxHops),
		Expires:        pointerValue(a.Expires),
		MessageTTL:     pointerValue(a.MessageTTL),
		HAPolicy:       pointerString(a.HAPolicy, ""),
		Queue:          pointerString(a.Queue, ""),
	}
	payload, err := params.saltJSON()
	if err != nil {
		return nil, err
	}
	secrets := upstreamCredentialSecrets(a.URI)
	secrets = append(secrets, string(payload))
	result, err := runCtl(ctx, rt, a.Runas, []string{"set_parameter", "federation-upstream", a.Name, string(payload)}, secrets...)
	if err != nil {
		return nil, err
	}
	if err := _check_response(commandResponse(result)); err != nil {
		return nil, err
	}
	return true, nil
}

func pointerValue(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

type upstreamParams struct {
	URI            string `json:"uri,omitempty"`
	PrefetchCount  int    `json:"prefetch-count,omitempty"`
	ReconnectDelay int    `json:"reconnect-delay,omitempty"`
	AckMode        string `json:"ack-mode,omitempty"`
	TrustUserID    bool   `json:"trust-user-id,omitempty"`
	Exchange       string `json:"exchange,omitempty"`
	MaxHops        int    `json:"max-hops,omitempty"`
	Expires        int    `json:"expires,omitempty"`
	MessageTTL     int    `json:"message-ttl,omitempty"`
	HAPolicy       string `json:"ha-policy,omitempty"`
	Queue          string `json:"queue,omitempty"`
}

func (p upstreamParams) saltJSON() (string, error) {
	fields := []struct {
		name    string
		value   any
		include bool
	}{
		{"uri", p.URI, p.URI != ""},
		{"prefetch-count", p.PrefetchCount, p.PrefetchCount != 0},
		{"reconnect-delay", p.ReconnectDelay, p.ReconnectDelay != 0},
		{"ack-mode", p.AckMode, p.AckMode != ""},
		{"trust-user-id", p.TrustUserID, p.TrustUserID},
		{"exchange", p.Exchange, p.Exchange != ""},
		{"max-hops", p.MaxHops, p.MaxHops != 0},
		{"expires", p.Expires, p.Expires != 0},
		{"message-ttl", p.MessageTTL, p.MessageTTL != 0},
		{"ha-policy", p.HAPolicy, p.HAPolicy != ""},
		{"queue", p.Queue, p.Queue != ""},
	}
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		if !field.include {
			continue
		}
		encoded, err := marshalSaltJSONValue(field.value)
		if err != nil {
			return "", err
		}
		parts = append(parts, fmt.Sprintf("%q: %s", field.name, encoded))
	}
	return "{" + strings.Join(parts, ", ") + "}", nil
}

func marshalSaltJSONValue(value any) (string, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buffer.String(), "\n"), nil
}

type DeleteUpstreamArgs struct {
	Name  string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type deleteUpstreamFunc struct{}

func (deleteUpstreamFunc) Name() string { return "rabbitmq.delete_upstream" }
func (deleteUpstreamFunc) Args() any    { return DeleteUpstreamArgs{} }
func (deleteUpstreamFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DeleteUpstreamArgs](args, "rabbitmq.delete_upstream")
	if err != nil {
		return nil, err
	}
	if err := validateText(a.Name, "name", true); err != nil {
		return nil, err
	}
	result, err := runCtl(ctx, rt, a.Runas, []string{"clear_parameter", "federation-upstream", a.Name})
	if err != nil {
		return nil, err
	}
	if err := _check_response(commandResponse(result)); err != nil {
		return nil, err
	}
	return true, nil
}

// Register installs the complete public rabbitmq catalog surface. The pinned
// module's private helpers remain package-internal parser/response helpers and
// are deliberately not registry entries.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		listUsersFunc{}, listVhostsFunc{}, listUpstreamsFunc{},
		userExistsFunc{}, vhostExistsFunc{}, upstreamExistsFunc{},
		addUserFunc{}, deleteUserFunc{}, changePasswordFunc{}, clearPasswordFunc{},
		checkPasswordFunc{}, addVhostFunc{}, deleteVhostFunc{}, setPermissionsFunc{},
		listPermissionsFunc{}, listUserPermissionsFunc{}, setUserTagsFunc{},
		statusFunc{}, clusterStatusFunc{}, joinClusterFunc{}, stopAppFunc{}, startAppFunc{},
		resetFunc{}, forceResetFunc{}, listQueuesFunc{}, listQueuesVhostFunc{},
		listPoliciesFunc{}, setPolicyFunc{}, deletePolicyFunc{}, policyExistsFunc{},
		listAvailablePluginsFunc{}, listEnabledPluginsFunc{}, pluginIsEnabledFunc{},
		enablePluginFunc{}, disablePluginFunc{}, setUpstreamFunc{}, deleteUpstreamFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
