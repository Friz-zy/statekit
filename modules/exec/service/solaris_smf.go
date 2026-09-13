package service

// Solaris SMF implementation for Salt's smf_service.py at the pinned Salt
// revision. The source uses svcs/svcadm/svccfg; every invocation below crosses
// the central shell-free Runner with finite output and timeout bounds.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	smfCommandTimeout = 30 * time.Second
	smfOutputLimit    = 4 << 20
)

var errSMFRunnerUnavailable = errors.New("smf: runner unavailable")

var smfGlobbingPattern = regexp.MustCompile(`\*|\?|\[.+\]`)

type smfSolarisOnly struct{}

func (smfSolarisOnly) Platforms() []string { return []string{"solaris"} }

func registerSolaris(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		smfGetRunningFunc{}, smfGetStoppedFunc{}, smfAvailableFunc{}, smfMissingFunc{},
		smfGetAllFunc{}, smfStartFunc{}, smfStopFunc{}, smfRestartFunc{}, smfReloadFunc{},
		smfStatusFunc{}, smfEnableFunc{}, smfDisableFunc{}, smfEnabledFunc{}, smfDisabledFunc{},
		smfGetEnabledFunc{}, smfGetDisabledFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// smfRun is the sole SMF subprocess boundary. Non-zero exits are preserved in
// CommandResult for Salt's retcode-oriented functions; only Runner failures,
// cancellation, and output limits become Go errors.
func smfRun(ctx context.Context, rt *runtime.Runtime, argv ...string) (process.CommandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if rt == nil || rt.Runner == nil {
		return process.CommandResult{ExitCode: -1}, errSMFRunnerUnavailable
	}
	command := runtime.Command(argv...)
	command.Shell = false
	command.Timeout = smfCommandTimeout
	command.MaxStdoutBytes = smfOutputLimit
	command.MaxStderrBytes = smfOutputLimit
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return result, result.Err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stdout) > smfOutputLimit || len(result.Stderr) > smfOutputLimit {
		return result, process.ErrOutputLimit
	}
	return result, nil
}

func smfNameOutput(result process.CommandResult) string {
	return strings.TrimSpace(string(result.Stdout))
}

func smfList(ctx context.Context, rt *runtime.Runtime, argv ...string) ([]string, error) {
	result, err := smfRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	values := []string{}
	seen := map[string]struct{}{}
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if _, ok := seen[fields[0]]; ok {
			continue
		}
		seen[fields[0]] = struct{}{}
		values = append(values, fields[0])
	}
	sort.Strings(values)
	return values, nil
}

func smfState(ctx context.Context, rt *runtime.Runtime, name string) (bool, error) {
	result, err := smfRun(ctx, rt, "/usr/bin/svcs", "-H", "-o", "STATE", name)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(result.Stdout)) == "online", nil
}

func smfRetcode(ctx context.Context, rt *runtime.Runtime, argv ...string) (int, error) {
	result, err := smfRun(ctx, rt, argv...)
	if err != nil {
		return -1, err
	}
	return result.ExitCode, nil
}

func smfGetEnabledDisabled(ctx context.Context, rt *runtime.Runtime, enabledProp string) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	result, err := smfRun(ctx, rt, "/usr/bin/svcprop", "-c", "-p", "general/enabled", "*")
	if err != nil {
		return nil, err
	}
	values := []string{}
	seen := map[string]struct{}{}
	for lineNumber, line := range strings.Split(string(result.Stdout), "\n") {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 3 {
			return nil, fmt.Errorf("smf: malformed svcprop row %d", lineNumber+1)
		}
		if fields[2] != enabledProp {
			continue
		}
		fmri := strings.SplitN(fields[0], "/:properties", 2)[0]
		if _, ok := seen[fmri]; ok {
			continue
		}
		seen[fmri] = struct{}{}
		values = append(values, fmri)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Salt's ret is a set followed by sorted(ret).
	sort.Strings(values)
	return values, nil
}

// ---------------------------------------------------------------------------
// listing and availability

type smfNoArgs struct{}

type smfGetRunningFunc struct{ smfSolarisOnly }

func (smfGetRunningFunc) Name() string { return "service.get_running" }
func (smfGetRunningFunc) Args() any    { return smfNoArgs{} }
func (smfGetRunningFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	raw, err := smfRun(ctx, rt, "/usr/bin/svcs", "-H", "-o", "FMRI,STATE", "-s", "FMRI")
	if err != nil {
		return nil, err
	}
	values := []string{}
	seen := map[string]struct{}{}
	for _, line := range strings.Split(string(raw.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.Contains(line, "online") {
			continue
		}
		if _, ok := seen[fields[0]]; !ok {
			seen[fields[0]] = struct{}{}
			values = append(values, fields[0])
		}
	}
	sort.Strings(values)
	return values, nil
}

type smfGetStoppedFunc struct{ smfSolarisOnly }

func (smfGetStoppedFunc) Name() string { return "service.get_stopped" }
func (smfGetStoppedFunc) Args() any    { return smfNoArgs{} }
func (smfGetStoppedFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	result, err := smfRun(ctx, rt, "/usr/bin/svcs", "-aH", "-o", "FMRI,STATE", "-s", "FMRI")
	if err != nil {
		return nil, err
	}
	values := []string{}
	seen := map[string]struct{}{}
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.Contains(line, "online") || strings.Contains(line, "legacy_run") {
			continue
		}
		if _, ok := seen[fields[0]]; !ok {
			seen[fields[0]] = struct{}{}
			values = append(values, fields[0])
		}
	}
	sort.Strings(values)
	return values, nil
}

type smfNameArgs struct {
	Name string `statekit:"required"`
}

// smfNameKwargsArgs preserves the source functions' **kwargs contract. The
// pinned Solaris implementation ignores those options, but accepting the
// structured map is part of the public argument surface and keeps Decode from
// rejecting otherwise valid Salt calls.
type smfNameKwargsArgs struct {
	Name   string         `statekit:"required"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type smfAvailableFunc struct{ smfSolarisOnly }

func (smfAvailableFunc) Name() string { return "service.available" }
func (smfAvailableFunc) Args() any    { return smfNameArgs{} }
func (smfAvailableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*smfNameArgs)
	result, err := smfRun(ctx, rt, "/usr/bin/svcs", "-H", "-o", "FMRI", a.Name)
	if err != nil {
		return nil, err
	}
	services, err := smfGetAllFunc{}.Execute(ctx, rt, smfNoArgs{})
	if err != nil {
		return nil, err
	}
	return containsString(services.([]string), smfNameOutput(result)), nil
}

type smfMissingFunc struct{ smfSolarisOnly }

func (smfMissingFunc) Name() string { return "service.missing" }
func (smfMissingFunc) Args() any    { return smfNameArgs{} }
func (smfMissingFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*smfNameArgs)
	result, err := smfRun(ctx, rt, "/usr/bin/svcs", "-H", "-o", "FMRI", a.Name)
	if err != nil {
		return nil, err
	}
	services, err := smfGetAllFunc{}.Execute(ctx, rt, smfNoArgs{})
	if err != nil {
		return nil, err
	}
	return !containsString(services.([]string), smfNameOutput(result)), nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func smfContainsGlobbing(name string) bool {
	return smfGlobbingPattern.MatchString(name)
}

func smfGlobMatch(pattern, name string) bool {
	const (
		maxLength       = 4096
		maxRegexpLength = 1 << 20
	)
	if len(pattern) > maxLength || len(name) > maxLength {
		return false
	}
	tokens := smfFnmatchTokens([]rune(pattern))
	nameRunes := []rune(name)
	if len(tokens) > maxLength || len(nameRunes) > maxLength {
		return false
	}
	translated, ok := smfFnmatchRegexp(tokens, maxRegexpLength)
	if !ok {
		return false
	}
	re, err := regexp.Compile(translated)
	return err == nil && re.MatchString(name)
}

// smfFnmatchRegexp translates the bounded token stream into a RE2 expression.
// RE2 guarantees linear-time matching; the input and translated expression are
// both bounded before compilation, so malformed or adversarial globs cannot
// trigger regex or dynamic-programming denial of service.
func smfFnmatchRegexp(tokens []smfFnmatchToken, maxLength int) (string, bool) {
	var b strings.Builder
	b.WriteString("(?s)^") // dot must also match newlines, as in Python fnmatch.
	for _, token := range tokens {
		var part string
		switch token.kind {
		case '*':
			part = ".*"
		case '?':
			part = "."
		default:
			part = smfFnmatchClassRegexp(token.class)
			if part == "" {
				// A positive class containing only descending ranges never matches.
				if !token.class.negated {
					return "", false
				}
				part = "." // Negation of an empty class matches every rune.
			}
		}
		if b.Len()+len(part)+2 > maxLength {
			return "", false
		}
		b.WriteString(part)
	}
	b.WriteString(`\z`)
	return b.String(), true
}

type smfFnmatchClass struct {
	negated bool
	chars   []rune
	ranges  [][2]rune
}

type smfFnmatchToken struct {
	kind  rune
	class smfFnmatchClass
}

func smfFnmatchClassRegexp(class smfFnmatchClass) string {
	var b strings.Builder
	b.WriteByte('[')
	if class.negated {
		b.WriteByte('^')
	}
	for _, ch := range class.chars {
		b.WriteString(fmt.Sprintf(`\x{%x}`, ch))
	}
	for _, pair := range class.ranges {
		if pair[0] <= pair[1] {
			b.WriteString(fmt.Sprintf(`\x{%x}-\x{%x}`, pair[0], pair[1]))
		}
	}
	if b.Len() == 1 || (class.negated && b.Len() == 2) {
		return ""
	}
	b.WriteByte(']')
	return b.String()
}

func smfFnmatchTokens(pattern []rune) []smfFnmatchToken {
	tokens := make([]smfFnmatchToken, 0, len(pattern))
	// Index the next closing bracket once so malformed opening brackets cannot
	// repeatedly rescan the remaining pattern.
	nextClose := smfFnmatchNextClose(pattern)
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*', '?':
			tokens = append(tokens, smfFnmatchToken{kind: pattern[i]})
		case '[':
			class, end, ok := smfFnmatchClassAt(pattern, i, nextClose)
			if !ok {
				tokens = append(tokens, smfFnmatchLiteral('['))
				continue
			}
			tokens = append(tokens, smfFnmatchToken{class: class})
			i = end
		default:
			tokens = append(tokens, smfFnmatchLiteral(pattern[i]))
		}
	}
	return tokens
}

func smfFnmatchNextClose(pattern []rune) []int {
	nextClose := make([]int, len(pattern))
	next := len(pattern)
	for i := len(pattern) - 1; i >= 0; i-- {
		if pattern[i] == ']' {
			next = i
		}
		nextClose[i] = next
	}
	return nextClose
}

func smfFnmatchLiteral(r rune) smfFnmatchToken {
	return smfFnmatchToken{class: smfFnmatchClass{chars: []rune{r}}}
}

func smfFnmatchClassAt(pattern []rune, start int, nextClose []int) (smfFnmatchClass, int, bool) {
	i := start + 1
	// Python fnmatch recognizes only ! as class negation. A leading ^ is
	// ordinary class data and must not be treated as a negation marker.
	negated := i < len(pattern) && pattern[i] == '!'
	if negated {
		i++
	}
	// A leading ']' is data in Python's bracket expression syntax.
	leadingClose := i < len(pattern) && pattern[i] == ']'
	if leadingClose {
		i++
	}
	contentStart := i
	if i >= len(pattern) {
		return smfFnmatchClass{}, start, false
	}
	end := nextClose[contentStart]
	if end >= len(pattern) || (end == contentStart && !leadingClose) {
		return smfFnmatchClass{}, start, false
	}
	content := pattern[contentStart:end]
	class := smfFnmatchClass{negated: negated}
	if leadingClose {
		class.chars = append(class.chars, ']')
	}
	// Python's translator consumes a range endpoint once it has been used.
	// Consequently the hyphen in a-b-c is literal, while the second hyphen in
	// --0 forms the range - through 0. A hyphen without both endpoints stays
	// literal; descending ranges are retained and deliberately match nothing.
	endpointAvailable := leadingClose
	for j := 0; j < len(content); j++ {
		if content[j] == '-' && endpointAvailable && j+1 < len(content) {
			hi := content[j+1]
			lo := ']'
			if j == 0 {
				// A leading literal ] is also the left endpoint when the
				// following token is a range. Keep []a] as ]/a, but make
				// []-a] the range ] through a, as Python's regex class does.
				lo = ']'
				if len(class.chars) > 0 && class.chars[len(class.chars)-1] == ']' {
					class.chars = class.chars[:len(class.chars)-1]
				}
			} else {
				lo = content[j-1]
			}
			// A leading hyphen is emitted as a literal by Python when the
			// following hyphen starts a valid range (as in --0). CPython's
			// range cleanup consumes it too when that range is descending,
			// as in --!, so an invalid range cannot retain '-' as a literal.
			if j > 0 && len(class.chars) > 0 && (lo != '-' || lo > hi) {
				class.chars = class.chars[:len(class.chars)-1]
			}
			class.ranges = append(class.ranges, [2]rune{lo, hi})
			endpointAvailable = false
			j++
			continue
		}
		class.chars = append(class.chars, content[j])
		endpointAvailable = true
	}
	return class, end, true
}

type smfGetAllFunc struct{ smfSolarisOnly }

func (smfGetAllFunc) Name() string { return "service.get_all" }
func (smfGetAllFunc) Args() any    { return smfNoArgs{} }
func (smfGetAllFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return smfList(ctx, rt, "/usr/bin/svcs", "-aH", "-o", "FMRI,STATE", "-s", "FMRI")
}

// ---------------------------------------------------------------------------
// lifecycle

type smfStartFunc struct{ smfSolarisOnly }

func (smfStartFunc) Name() string { return "service.start" }
func (smfStartFunc) Args() any    { return smfNameArgs{} }
func (smfStartFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*smfNameArgs)
	retcode, err := smfRetcode(ctx, rt, "/usr/sbin/svcadm", "enable", "-s", "-t", a.Name)
	if err != nil {
		return nil, err
	}
	if retcode == 0 {
		return true, nil
	}
	if retcode != 3 {
		return false, nil
	}
	if _, err := smfRetcode(ctx, rt, "/usr/sbin/svcadm", "clear", a.Name); err != nil {
		return nil, err
	}
	retry, err := smfRetcode(ctx, rt, "/usr/sbin/svcadm", "enable", "-s", "-t", a.Name)
	if err != nil {
		return nil, err
	}
	return retry == 0, nil
}

type smfStopFunc struct{ smfSolarisOnly }

func (smfStopFunc) Name() string { return "service.stop" }
func (smfStopFunc) Args() any    { return smfNameArgs{} }
func (smfStopFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*smfNameArgs)
	retcode, err := smfRetcode(ctx, rt, "/usr/sbin/svcadm", "disable", "-s", "-t", a.Name)
	if err != nil {
		return nil, err
	}
	return retcode == 0, nil
}

type smfRestartFunc struct{ smfSolarisOnly }

func (smfRestartFunc) Name() string { return "service.restart" }
func (smfRestartFunc) Args() any    { return smfNameArgs{} }
func (smfRestartFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*smfNameArgs)
	retcode, err := smfRetcode(ctx, rt, "/usr/sbin/svcadm", "restart", a.Name)
	if err != nil {
		return nil, err
	}
	if retcode != 0 {
		return false, nil
	}
	return smfStartFunc{}.Execute(ctx, rt, a)
}

type smfReloadFunc struct{ smfSolarisOnly }

func (smfReloadFunc) Name() string { return "service.reload" }
func (smfReloadFunc) Args() any    { return smfNameArgs{} }
func (smfReloadFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*smfNameArgs)
	retcode, err := smfRetcode(ctx, rt, "/usr/sbin/svcadm", "refresh", a.Name)
	if err != nil {
		return nil, err
	}
	if retcode != 0 {
		return false, nil
	}
	return smfStartFunc{}.Execute(ctx, rt, a)
}

type smfStatusArgs struct {
	Name string  `statekit:"required"`
	Sig  *string `statekit:"name=sig"`
}

type smfStatusFunc struct{ smfSolarisOnly }

func (smfStatusFunc) Name() string { return "service.status" }
func (smfStatusFunc) Args() any    { return smfStatusArgs{} }
func (smfStatusFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*smfStatusArgs)
	containsGlobbing := smfContainsGlobbing(a.Name)
	services := []string{a.Name}
	if containsGlobbing {
		all, err := smfGetAllFunc{}.Execute(ctx, rt, smfNoArgs{})
		if err != nil {
			return nil, err
		}
		services = []string{}
		for _, serviceName := range all.([]string) {
			if smfGlobMatch(a.Name, serviceName) {
				services = append(services, serviceName)
			}
		}
	}
	results := map[string]bool{}
	for _, serviceName := range services {
		running, err := smfState(ctx, rt, serviceName)
		if err != nil {
			return nil, err
		}
		results[serviceName] = running
	}
	if containsGlobbing {
		return results, nil
	}
	return results[a.Name], nil
}

type smfEnableFunc struct{ smfSolarisOnly }

func (smfEnableFunc) Name() string { return "service.enable" }
func (smfEnableFunc) Args() any    { return smfNameKwargsArgs{} }
func (smfEnableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*smfNameKwargsArgs)
	retcode, err := smfRetcode(ctx, rt, "/usr/sbin/svcadm", "enable", a.Name)
	if err != nil {
		return nil, err
	}
	return retcode == 0, nil
}

type smfDisableFunc struct{ smfSolarisOnly }

func (smfDisableFunc) Name() string { return "service.disable" }
func (smfDisableFunc) Args() any    { return smfNameKwargsArgs{} }
func (smfDisableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*smfNameKwargsArgs)
	retcode, err := smfRetcode(ctx, rt, "/usr/sbin/svcadm", "disable", a.Name)
	if err != nil {
		return nil, err
	}
	return retcode == 0, nil
}

type smfEnabledFunc struct{ smfSolarisOnly }

func (smfEnabledFunc) Name() string { return "service.enabled" }
func (smfEnabledFunc) Args() any    { return smfNameKwargsArgs{} }
func (smfEnabledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*smfNameKwargsArgs)
	fmri, err := smfRun(ctx, rt, "/usr/bin/svcs", "-H", "-o", "FMRI", a.Name)
	if err != nil {
		return nil, err
	}
	result, err := smfRun(ctx, rt, "/usr/sbin/svccfg", "-s", smfNameOutput(fmri), "listprop", "general/enabled")
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(result.Stdout))
	if len(fields) < 3 {
		return nil, fmt.Errorf("smf: malformed general/enabled property output")
	}
	return fields[2] == "true", nil
}

type smfDisabledFunc struct{ smfSolarisOnly }

func (smfDisabledFunc) Name() string { return "service.disabled" }
func (smfDisabledFunc) Args() any    { return smfNameArgs{} }
func (smfDisabledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*smfNameArgs)
	value, err := smfEnabledFunc{}.Execute(ctx, rt, &smfNameKwargsArgs{Name: a.Name})
	if err != nil {
		return nil, err
	}
	return !value.(bool), nil
}

type smfGetEnabledFunc struct{ smfSolarisOnly }

func (smfGetEnabledFunc) Name() string { return "service.get_enabled" }
func (smfGetEnabledFunc) Args() any    { return smfNoArgs{} }
func (smfGetEnabledFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return smfGetEnabledDisabled(ctx, rt, "true")
}

type smfGetDisabledFunc struct{ smfSolarisOnly }

func (smfGetDisabledFunc) Name() string { return "service.get_disabled" }
func (smfGetDisabledFunc) Args() any    { return smfNoArgs{} }
func (smfGetDisabledFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return smfGetEnabledDisabled(ctx, rt, "false")
}
