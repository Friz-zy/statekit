package at

// Solaris' at module is a platform-specific implementation of the same
// virtual `at` family as the generic module.  The public names intentionally
// remain the catalog names (including `_atq`); Register selects one provider
// for a GOOS so the family never exposes duplicate registrations.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	solarisAtCommandTimeout = 30 * time.Second
	solarisAtOutputLimit    = 4 << 20
	solarisAtJobFileLimit   = 1 << 20
	solarisAtMaxTokenBytes  = 128

	solarisAtJobDirectory = "/var/spool/cron/atjobs"
)

var (
	errSolarisAtRunnerUnavailable = errors.New("at: runner unavailable")
	errSolarisAtToolsUnavailable  = errors.New("at: at, atq, and atrm are required on Solaris")
	errSolarisAtFilesystemMissing = errors.New("at: filesystem unavailable")

	solarisAtJobIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	solarisAtTagPattern   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	solarisAtTagLine      = regexp.MustCompile(`^### SALT: ([A-Za-z0-9_]+)`)
)

// solarisAtOnly mirrors at_solaris.__virtual__.  The functions are registered
// in the underlying registry on every build when tests call registerSolaris,
// but the registry filters them and returns UnsupportedError on non-Solaris.
type solarisAtOnly struct{}

func (solarisAtOnly) Platforms() []string { return []string{"solaris"} }

// solarisAtRun is the only subprocess boundary in this provider.  It keeps
// argv shell-free, bounds both output streams and stdin, checks cancellation
// before and after Runner.Run, and leaves completed non-zero statuses as data.
func solarisAtRun(ctx context.Context, rt *runtime.Runtime, stdin string, argv ...string) (process.CommandResult, error) {
	if rt == nil || rt.Runner == nil {
		return process.CommandResult{ExitCode: -1}, errSolarisAtRunnerUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if err := requireSolarisAtTools(rt); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	command, err := runtime.CommandWithInputBounded(argv, stdin)
	if err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	command.Shell = false
	command.Timeout = solarisAtCommandTimeout
	command.MaxStdoutBytes = solarisAtOutputLimit
	command.MaxStderrBytes = solarisAtOutputLimit
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return result, result.Err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stdout) > solarisAtOutputLimit || len(result.Stderr) > solarisAtOutputLimit {
		return result, process.ErrOutputLimit
	}
	return result, nil
}

// requireSolarisAtTools uses the Runner's optional shell-free availability
// probe.  A recording-only fake without that capability is treated as
// available, preserving hermetic provider tests without consulting host PATH.
func requireSolarisAtTools(rt *runtime.Runtime) error {
	available, ok := rt.Runner.(process.CommandAvailability)
	if !ok {
		return nil
	}
	if !available.CommandAvailable("at") ||
		!available.CommandAvailable("atq") ||
		!available.CommandAvailable("atrm") {
		return errSolarisAtToolsUnavailable
	}
	return nil
}

func validateSolarisAtJobID(jobID string) error {
	if !solarisAtJobIDPattern.MatchString(jobID) || len(jobID) > solarisAtMaxTokenBytes {
		return errors.New("at: invalid job id")
	}
	return nil
}

func validateSolarisAtTag(tag string) error {
	if !solarisAtTagPattern.MatchString(tag) || len(tag) > solarisAtMaxTokenBytes {
		return errors.New("at: invalid tag")
	}
	return nil
}

func validateSolarisAtTimespec(spec string) error {
	if err := validateAtTimespecOperand(spec); err != nil {
		return err
	}
	if strings.TrimSpace(spec) == "" || len(spec) > solarisAtMaxTokenBytes {
		return errors.New("at: invalid timespec")
	}
	for i := 0; i < len(spec); i++ {
		if spec[i] == 0 || spec[i] == '\n' || spec[i] == '\r' || spec[i] == 0x7f || spec[i] < 0x20 {
			return errors.New("at: invalid timespec")
		}
	}
	return nil
}

func solarisAtJobPath(jobID string) string {
	// validateSolarisAtJobID is required by every caller before this join.
	return path.Join(solarisAtJobDirectory, jobID)
}

// solarisAtJobTag mirrors the source's file.file_exists plus file read while
// refusing symlinks/special files and requiring the runtime's bounded reader.
func solarisAtJobTag(ctx context.Context, rt *runtime.Runtime, jobID string) (string, error) {
	if rt == nil || rt.FS == nil {
		return "", errSolarisAtFilesystemMissing
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	jobPath := solarisAtJobPath(jobID)
	info, err := rt.FS.Lstat(jobPath)
	if err != nil || info == nil || !info.Mode().IsRegular() {
		// file.file_exists returns false for missing paths and directories.
		return "", nil
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	data, err := runtime.ReadFileBounded(rt.FS, jobPath, solarisAtJobFileLimit)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	jobTag := ""
	for _, line := range strings.Split(string(data), "\n") {
		if match := solarisAtTagLine.FindStringSubmatch(strings.TrimSuffix(line, "\r")); match != nil {
			jobTag = match[1]
		}
	}
	return jobTag, nil
}

func solarisAtEmptyJobs() map[string]any {
	return map[string]any{"jobs": []map[string]any{}}
}

func parseSolarisAtQueue(ctx context.Context, rt *runtime.Runtime, output, filterTag string) ([]map[string]any, error) {
	jobs := make([]map[string]any, 0)
	trimmed := strings.TrimSpace(output)
	if trimmed == "" || trimmed == "no files in queue." {
		return jobs, nil
	}

	for lineIndex, raw := range strings.Split(output, "\n") {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		line := strings.TrimSuffix(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Solaris emits a leading-space Rank header.  Accept the unindented
		// spelling as well so a harmless formatter change cannot panic the
		// parser.
		if strings.HasPrefix(line, " Rank") || strings.TrimSpace(line) == "Rank" ||
			strings.HasPrefix(strings.TrimSpace(line), "Rank ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			return nil, fmt.Errorf("at: malformed atq row %d", lineIndex+1)
		}
		timestr := strings.Join(fields[1:5], " ")
		parsed, err := time.Parse("Jan 2, 2006 15:04", timestr)
		if err != nil {
			return nil, fmt.Errorf("at: invalid atq date on row %d", lineIndex+1)
		}
		jobID := fields[6]
		if err := validateSolarisAtJobID(jobID); err != nil {
			return nil, fmt.Errorf("at: invalid atq job id on row %d", lineIndex+1)
		}
		jobTag, err := solarisAtJobTag(ctx, rt, jobID)
		if err != nil {
			return nil, err
		}
		job := map[string]any{
			"job":   jobID,
			"date":  parsed.Format("2006-01-02"),
			"time":  parsed.Format("15:04:05"),
			"queue": fields[7],
			"user":  fields[5],
			"tag":   jobTag,
		}
		if filterTag == "" || filterTag == jobTag || filterTag == jobID {
			jobs = append(jobs, job)
		}
	}
	return jobs, nil
}

func solarisAtq(ctx context.Context, rt *runtime.Runtime, filterTag string) (any, error) {
	if filterTag != "" {
		if err := validateSolarisAtTag(filterTag); err != nil {
			return nil, err
		}
	}
	result, err := solarisAtRun(ctx, rt, "", "atq")
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return map[string]any{"error": string(result.Stderr)}, nil
	}
	jobs, err := parseSolarisAtQueue(ctx, rt, string(result.Stdout), filterTag)
	if err != nil {
		return nil, err
	}
	return map[string]any{"jobs": jobs}, nil
}

type solarisAtqArgs struct {
	Tag *string `statekit:"name=tag"`
}

type solarisAtqFunc struct{ solarisAtOnly }

func (solarisAtqFunc) Name() string { return "at.atq" }
func (solarisAtqFunc) Args() any    { return solarisAtqArgs{} }
func (solarisAtqFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*solarisAtqArgs)
	if !ok || a == nil {
		return nil, errors.New("at.atq: invalid arguments")
	}
	filterTag := ""
	if a.Tag != nil {
		filterTag = *a.Tag
	}
	return solarisAtq(ctx, rt, filterTag)
}

type solarisAtrmArgs struct {
	Args []string `statekit:"name=args"`
}

type solarisAtrmFunc struct{ solarisAtOnly }

func (solarisAtrmFunc) Name() string { return "at.atrm" }
func (solarisAtrmFunc) Args() any    { return solarisAtrmArgs{} }
func (solarisAtrmFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*solarisAtrmArgs)
	if !ok || a == nil {
		return nil, errors.New("at.atrm: invalid arguments")
	}
	if len(a.Args) == 0 {
		return map[string]any{"jobs": map[string]any{"removed": []string{}, "tag": nil}}, nil
	}

	all := a.Args[0] == "all"
	if all {
		if len(a.Args) > 1 && a.Args[1] != "" {
			if err := validateSolarisAtTag(a.Args[1]); err != nil {
				return nil, err
			}
		}
	} else {
		for _, jobID := range a.Args {
			if err := validateSolarisAtJobID(jobID); err != nil {
				return nil, err
			}
		}
	}

	filterTag := ""
	if all && len(a.Args) > 1 {
		filterTag = a.Args[1]
	}
	queue, err := solarisAtq(ctx, rt, filterTag)
	if err != nil {
		return nil, err
	}
	queueMap, ok := queue.(map[string]any)
	if !ok {
		return nil, errors.New("at.atrm: invalid atq result")
	}
	if _, hasJobs := queueMap["jobs"]; !hasJobs {
		// atq's completed non-zero status is compatibility data.  Do not
		// fabricate removals or issue atrm when there is no queue payload.
		return queue, nil
	}
	rows, ok := queueMap["jobs"].([]map[string]any)
	if !ok {
		return nil, errors.New("at.atrm: invalid atq jobs result")
	}

	removed := make([]string, 0, len(rows))
	for _, row := range rows {
		jobID, ok := row["job"].(string)
		if !ok {
			return nil, errors.New("at.atrm: invalid atq job id")
		}
		if all || containsSolarisAtString(a.Args, jobID) {
			if err := validateSolarisAtJobID(jobID); err != nil {
				return nil, err
			}
			removed = append(removed, jobID)
		}
	}

	jobResult := map[string]any{"removed": removed, "tag": nil}
	if all && len(a.Args) > 1 {
		jobResult["tag"] = a.Args[1]
	}
	if len(removed) == 0 {
		return map[string]any{"jobs": jobResult}, nil
	}

	failed := map[string]any{}
	for _, jobID := range removed {
		result, runErr := solarisAtRun(ctx, rt, "", "atrm", jobID)
		if runErr != nil {
			return nil, runErr
		}
		if result.ExitCode != 0 {
			failed[jobID] = string(result.Stderr)
		}
	}
	if len(failed) > 0 {
		jobResult["failed"] = failed
		surviving := make([]string, 0, len(removed))
		for _, jobID := range removed {
			if _, didFail := failed[jobID]; !didFail {
				surviving = append(surviving, jobID)
			}
		}
		jobResult["removed"] = surviving
	}
	return map[string]any{"jobs": jobResult}, nil
}

func containsSolarisAtString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func joinSolarisAtScript(parts []string) (string, error) {
	var script strings.Builder
	for index, part := range parts {
		if strings.IndexByte(part, 0) >= 0 {
			return "", errors.New("at: command contains NUL")
		}
		extra := len(part)
		if index > 0 {
			extra++
		}
		if script.Len() > runtime.MaxCommandInputBytes ||
			extra > runtime.MaxCommandInputBytes-script.Len() {
			return "", runtime.ErrCommandInputLimit
		}
		if index > 0 {
			script.WriteByte(' ')
		}
		script.WriteString(part)
	}
	return script.String(), nil
}

func solarisAtKwargString(kwargs map[string]any, name string) (string, bool, error) {
	raw, ok := kwargs[name]
	if !ok || raw == nil {
		return "", ok, nil
	}
	value, ok := raw.(string)
	if !ok {
		return "", true, fmt.Errorf("at: %s must be a string", name)
	}
	return value, true, nil
}

type solarisAtArgs struct {
	Args   []string       `statekit:"name=args"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type solarisAtFunc struct{ solarisAtOnly }

func (solarisAtFunc) Name() string { return "at.at" }
func (solarisAtFunc) Args() any    { return solarisAtArgs{} }
func (solarisAtFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*solarisAtArgs)
	if !ok || a == nil {
		return nil, errors.New("at.at: invalid arguments")
	}
	if err := rejectAtRunas(a.Kwargs); err != nil {
		return nil, err
	}
	if len(a.Args) < 2 {
		return solarisAtEmptyJobs(), nil
	}
	if err := validateSolarisAtTimespec(a.Args[0]); err != nil {
		return nil, err
	}
	script, err := joinSolarisAtScript(a.Args[1:])
	if err != nil {
		return nil, err
	}

	tag, hasTag, err := solarisAtKwargString(a.Kwargs, "tag")
	if err != nil {
		return nil, err
	}
	if hasTag {
		if tag != "" {
			if err := validateSolarisAtTag(tag); err != nil {
				return nil, err
			}
		}
		script = "### SALT: " + tag + "\n" + script
	}

	result, err := solarisAtRun(ctx, rt, script, "at", a.Args[0])
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		if strings.Contains(string(result.Stderr), "bad time specification") {
			return map[string]any{"jobs": []map[string]any{}, "error": "invalid timespec"}, nil
		}
		return map[string]any{"jobs": []map[string]any{}, "error": string(result.Stderr)}, nil
	}
	jobID, err := parseSolarisAtJobID(result.Stderr)
	if err != nil {
		return nil, err
	}
	return solarisAtq(ctx, rt, jobID)
}

// parseSolarisAtJobID preserves at_solaris' exact second-line/second-field
// contract while validating the result before it becomes a path or argv.
func parseSolarisAtJobID(stderr []byte) (string, error) {
	lines := strings.Split(string(stderr), "\n")
	if len(lines) < 2 {
		return "", errors.New("at: malformed job creation response")
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 2 {
		return "", errors.New("at: malformed job creation response")
	}
	jobID := fields[1]
	if err := validateSolarisAtJobID(jobID); err != nil {
		return "", errors.New("at: malformed job creation response")
	}
	return jobID, nil
}

type solarisAtcArgs struct {
	JobID string `statekit:"required,name=jobid"`
}

type solarisAtcFunc struct{ solarisAtOnly }

func (solarisAtcFunc) Name() string { return "at.atc" }
func (solarisAtcFunc) Args() any    { return solarisAtcArgs{} }
func (solarisAtcFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*solarisAtcArgs)
	if !ok || a == nil {
		return nil, errors.New("at.atc: invalid arguments")
	}
	if err := validateSolarisAtJobID(a.JobID); err != nil {
		return nil, err
	}
	if rt == nil || rt.Runner == nil {
		return nil, errSolarisAtRunnerUnavailable
	}
	if err := requireSolarisAtTools(rt); err != nil {
		return nil, err
	}
	if rt.FS == nil {
		return nil, errSolarisAtFilesystemMissing
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	jobPath := solarisAtJobPath(a.JobID)
	info, err := rt.FS.Lstat(jobPath)
	if err != nil || info == nil || !info.Mode().IsRegular() {
		return map[string]any{"error": fmt.Sprintf("invalid job id '%s'", a.JobID)}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := runtime.ReadFileBounded(rt.FS, jobPath, solarisAtJobFileLimit)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return string(data), nil
}

type solarisAtKwargsArgs struct {
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type solarisAtqFilterFunc struct{ solarisAtOnly }

func (solarisAtqFilterFunc) Name() string { return "at._atq" }
func (solarisAtqFilterFunc) Args() any    { return solarisAtKwargsArgs{} }
func (solarisAtqFilterFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*solarisAtKwargsArgs)
	if !ok || a == nil {
		return nil, errors.New("at._atq: invalid arguments")
	}
	return solarisAtFilter(ctx, rt, a.Kwargs)
}

type solarisAtJobcheckFunc struct{ solarisAtOnly }

func (solarisAtJobcheckFunc) Name() string { return "at.jobcheck" }
func (solarisAtJobcheckFunc) Args() any    { return solarisAtKwargsArgs{} }
func (solarisAtJobcheckFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*solarisAtKwargsArgs)
	if !ok || a == nil {
		return nil, errors.New("at.jobcheck: invalid arguments")
	}
	if len(a.Kwargs) == 0 {
		return map[string]any{"error": "You have given a condition"}, nil
	}
	return solarisAtFilter(ctx, rt, a.Kwargs)
}

type solarisAtFilters struct {
	runas  string
	tag    string
	hour   *int
	minute *int
	day    *int
	month  *int
	year   any
}

func solarisAtTruthy(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return typed != ""
	case bool:
		return typed
	case int:
		return typed != 0
	case int64:
		return typed != 0
	case float64:
		return typed != 0
	case []any:
		return len(typed) > 0
	case []string:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	default:
		return true
	}
}

func solarisAtInt(value any, name string, min, max int) (*int, error) {
	if !solarisAtTruthy(value) {
		return nil, nil
	}
	var number int64
	switch typed := value.(type) {
	case int:
		number = int64(typed)
	case int64:
		number = typed
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) ||
			typed != math.Trunc(typed) || typed < float64(min) || typed > float64(max) {
			return nil, fmt.Errorf("at: invalid %s filter", name)
		}
		number = int64(typed)
	case string:
		if len(typed) > 16 {
			return nil, fmt.Errorf("at: invalid %s filter", name)
		}
		parsed, err := strconv.ParseInt(typed, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("at: invalid %s filter", name)
		}
		number = parsed
	default:
		return nil, fmt.Errorf("at: invalid %s filter", name)
	}
	if number < int64(min) || number > int64(max) {
		return nil, fmt.Errorf("at: invalid %s filter", name)
	}
	converted := int(number)
	return &converted, nil
}

// solarisAtYear mirrors the pinned _atq conversion without erasing the
// Python value type.  Only a two-digit numeric value is converted to a string
// year; a four-digit numeric value remains numeric and therefore cannot equal
// the parsed date's string year.  String years retain their string comparison
// behavior.  JSON numbers arrive here as float64, so exact integral floats use
// the same numeric-year path without being stringified wholesale.
func solarisAtYear(value any) (any, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		if typed == "" {
			return nil, nil
		}
		year := typed
		if len(year) == 2 {
			year = "20" + year
		}
		if len(year) != 4 || !solarisAtDigits(year) {
			return nil, errors.New("at: invalid year filter")
		}
		return year, nil
	case int:
		if typed == 0 {
			return nil, nil
		}
		return solarisAtIntegerYear(int64(typed), typed)
	case int64:
		if typed == 0 {
			return nil, nil
		}
		return solarisAtIntegerYear(typed, typed)
	case float64:
		if typed == 0 {
			return nil, nil
		}
		if math.IsNaN(typed) || math.IsInf(typed, 0) || typed != math.Trunc(typed) ||
			typed < 0 || typed > 9999 {
			return nil, errors.New("at: invalid year filter")
		}
		// ParseStructured decodes JSON numbers as float64.  An exact integral
		// value is still numeric input: two digits get the source conversion,
		// while four digits remain float64 and cannot match a date string.
		return solarisAtIntegerYear(int64(typed), typed)
	default:
		return nil, errors.New("at: invalid year filter")
	}
}

func solarisAtIntegerYear(value int64, original any) (any, error) {
	if value < 0 || value > 9999 {
		return nil, errors.New("at: invalid year filter")
	}
	text := strconv.FormatInt(value, 10)
	switch len(text) {
	case 2:
		return "20" + text, nil
	case 4:
		// Do not stringify four-digit integers: the source compares this
		// numeric value with the parsed date's string year and does not match.
		return original, nil
	default:
		return nil, errors.New("at: invalid year filter")
	}
}

func solarisAtDigits(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func solarisAtFiltersFrom(kwargs map[string]any) (solarisAtFilters, error) {
	filters := solarisAtFilters{}
	if value, ok, err := solarisAtKwargString(kwargs, "runas"); err != nil {
		return filters, err
	} else if ok && value != "" {
		filters.runas = value
	}
	if value, ok, err := solarisAtKwargString(kwargs, "tag"); err != nil {
		return filters, err
	} else if ok && value != "" {
		if err := validateSolarisAtTag(value); err != nil {
			return filters, err
		}
		filters.tag = value
	}
	var err error
	if filters.hour, err = solarisAtInt(kwargs["hour"], "hour", 0, 23); err != nil {
		return filters, err
	}
	if filters.minute, err = solarisAtInt(kwargs["minute"], "minute", 0, 59); err != nil {
		return filters, err
	}
	if filters.day, err = solarisAtInt(kwargs["day"], "day", 1, 31); err != nil {
		return filters, err
	}
	if filters.month, err = solarisAtInt(kwargs["month"], "month", 1, 12); err != nil {
		return filters, err
	}
	if filters.year, err = solarisAtYear(kwargs["year"]); err != nil {
		return filters, err
	}
	return filters, nil
}

func solarisAtJobMatches(job map[string]any, filters solarisAtFilters) bool {
	if filters.runas != "" && filters.runas != job["user"] {
		return false
	}
	if filters.tag != "" && filters.tag != job["tag"] {
		return false
	}
	date, _ := job["date"].(string)
	timeValue, _ := job["time"].(string)
	dateParts := strings.Split(date, "-")
	timeParts := strings.Split(timeValue, ":")
	if len(dateParts) != 3 || len(timeParts) < 2 {
		return false
	}
	if filters.hour != nil && fmt.Sprintf("%02d", *filters.hour) != timeParts[0] {
		return false
	}
	if filters.minute != nil && fmt.Sprintf("%02d", *filters.minute) != timeParts[1] {
		return false
	}
	if filters.day != nil && fmt.Sprintf("%02d", *filters.day) != dateParts[2] {
		return false
	}
	if filters.month != nil && fmt.Sprintf("%02d", *filters.month) != dateParts[1] {
		return false
	}
	if filters.year != nil {
		year, ok := filters.year.(string)
		if !ok || year != dateParts[0] {
			return false
		}
	}
	return true
}

func solarisAtFilter(ctx context.Context, rt *runtime.Runtime, kwargs map[string]any) (any, error) {
	filters, err := solarisAtFiltersFrom(kwargs)
	if err != nil {
		return nil, err
	}
	queue, err := solarisAtq(ctx, rt, "")
	if err != nil {
		return nil, err
	}
	queueMap, ok := queue.(map[string]any)
	if !ok {
		return nil, errors.New("at: invalid atq result")
	}
	rows, hasJobs := queueMap["jobs"]
	if !hasJobs {
		return queue, nil
	}
	jobs, ok := rows.([]map[string]any)
	if !ok {
		return nil, errors.New("at: invalid atq jobs result")
	}
	if len(jobs) == 0 {
		return solarisAtEmptyJobs(), nil
	}
	matched := make([]map[string]any, 0, len(jobs))
	for _, job := range jobs {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if solarisAtJobMatches(job, filters) {
			matched = append(matched, job)
		}
	}
	if len(matched) == 0 {
		return map[string]any{
			"jobs": matched,
			"note": "No match jobs or time format error",
		}, nil
	}
	return map[string]any{"jobs": matched}, nil
}

// registerSolaris installs the six catalog functions exactly once.  The
// shared names at.atq, at.atrm, and at.at replace their generic counterparts
// only on a Solaris build; at.atc, at._atq, and at.jobcheck are Solaris-only
// additions.
func registerSolaris(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		solarisAtqFunc{}, solarisAtrmFunc{}, solarisAtFunc{}, solarisAtcFunc{},
		solarisAtqFilterFunc{}, solarisAtJobcheckFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
