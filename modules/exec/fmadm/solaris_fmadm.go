// Package fmadm implements Salt's Solaris fmadm execution family.
//
// The source module is virtualized as fmadm and requires both fmadm and
// fmdump on Solaris. Commands are always sent to the central Runner as an
// explicit argv without a shell; output and execution are bounded so the
// parser never consumes untrusted unbounded command output.
package fmadm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	fmadmCommandTimeout = 30 * time.Second
	fmadmOutputLimit    = 4 << 20
)

var (
	errFmadmRunnerUnavailable = errors.New("fmadm: runner unavailable")
	errFmadmToolsUnavailable  = errors.New("fmadm module can only be loaded on Solaris with the fault management installed")
)

// solarisOnly mirrors the source module's is_sunos virtual-module gate. The
// registry still stores the function on every build so non-Solaris calls
// become runtime.UnsupportedError and do not reach a Runner.
type solarisOnly struct{}

func (solarisOnly) Platforms() []string { return []string{"solaris"} }

// fmadmRun is the one subprocess boundary for this family. Non-zero command
// statuses remain compatibility data in CommandResult; runner failures,
// cancellation, and output-limit failures are returned as Go errors.
func fmadmRun(ctx context.Context, rt *runtime.Runtime, argv ...string) (process.CommandResult, error) {
	if rt == nil || rt.Runner == nil {
		return process.CommandResult{ExitCode: -1}, errFmadmRunnerUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if err := requireFmadmTools(rt); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}

	command := runtime.Command(argv...)
	command.Shell = false
	command.Timeout = fmadmCommandTimeout
	command.MaxStdoutBytes = fmadmOutputLimit
	command.MaxStderrBytes = fmadmOutputLimit
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return result, result.Err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stdout) > fmadmOutputLimit || len(result.Stderr) > fmadmOutputLimit {
		return result, process.ErrOutputLimit
	}
	return result, nil
}

// requireFmadmTools uses the Runner's optional shell-free availability probe.
// DefaultRunner resolves the same PATH names without starting a process. A
// plain fake Runner is treated as available so direct provider tests can
// script command results without reproducing host PATH state.
func requireFmadmTools(rt *runtime.Runtime) error {
	available, ok := rt.Runner.(process.CommandAvailability)
	if !ok {
		return nil
	}
	// Preserve __virtual__'s short-circuit order: fmadm is checked before
	// fmdump, and fmdump is not probed when fmadm is absent.
	if !available.CommandAvailable("fmadm") || !available.CommandAvailable("fmdump") {
		return errFmadmToolsUnavailable
	}
	return nil
}

func fmdumpFailure() map[string]any {
	return map[string]any{"Error": "error executing fmdump"}
}

func fmadmConfigFailure() map[string]any {
	return map[string]any{"Error": "error executing fmadm config"}
}

func commandFailure(stderr []byte) map[string]any {
	return map[string]any{"Error": string(stderr)}
}

// splitSpaceFields matches the source parser's literal " ".split(" ") plus
// empty-field filtering rather than changing the format with shell-like
// tokenization.
func splitSpaceFields(line string) []string {
	parts := strings.Split(line, " ")
	fields := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			fields = append(fields, part)
		}
	}
	return fields
}

func parseFmdump(output string) ([]map[string]any, error) {
	if output == "" {
		return []map[string]any{}, nil
	}
	lines := strings.Split(output, "\n")
	header := splitSpaceFields(strings.TrimSuffix(lines[0], "\r"))
	if len(header) == 0 {
		return []map[string]any{}, nil
	}
	result := make([]map[string]any, 0, len(lines)-1)
	for index, raw := range lines[1:] {
		line := strings.TrimSuffix(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := splitSpaceFields(line)
		if len(fields) < 3 {
			return nil, fmt.Errorf("fmadm: malformed fmdump row %d", index+2)
		}
		row := append([]string{strings.Join(fields[:3], " ")}, fields[3:]...)
		if len(row) < len(header) {
			return nil, fmt.Errorf("fmadm: malformed fmdump row %d: got %d fields, want %d", index+2, len(row), len(header))
		}
		fault := make(map[string]any, len(header))
		for fieldIndex, field := range header {
			fault[strings.ToLower(field)] = row[fieldIndex]
		}
		result = append(result, fault)
	}
	return result, nil
}

func parseFmdumpVerbose(output string) ([]map[string]any, error) {
	if output == "" {
		return []map[string]any{}, nil
	}
	result := []map[string]any{}
	var faultLines []string
	var verboseFault map[string]any
	for lineIndex, raw := range strings.Split(output, "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if strings.HasPrefix(line, "TIME") {
			faultLines = append(faultLines, line)
			if len(verboseFault) > 0 {
				result = append(result, verboseFault)
				verboseFault = nil
			}
			continue
		}
		if len(faultLines) == 1 {
			faultLines = append(faultLines, line)
			parsed, err := parseFmdump(strings.Join(faultLines, "\n"))
			if err != nil {
				return nil, fmt.Errorf("fmadm: malformed verbose fmdump record at line %d: %w", lineIndex+1, err)
			}
			if len(parsed) == 0 {
				return nil, fmt.Errorf("fmadm: verbose fmdump record at line %d has no data", lineIndex+1)
			}
			verboseFault = parsed[0]
			faultLines = nil
			continue
		}
		if len(verboseFault) > 0 {
			if _, present := verboseFault["details"]; !present {
				verboseFault["details"] = ""
			}
			if strings.TrimSpace(line) == "" {
				continue
			}
			verboseFault["details"] = fmt.Sprintf("%s%s\n", verboseFault["details"], line)
		}
	}
	if len(verboseFault) > 0 {
		result = append(result, verboseFault)
	}
	return result, nil
}

func parseFmadmConfig(output string) (map[string]any, error) {
	if output == "" {
		return map[string]any{}, nil
	}
	lines := strings.Split(output, "\n")
	headerFields := splitSpaceFields(strings.TrimSuffix(lines[0], "\r"))
	if len(headerFields) == 0 {
		return map[string]any{}, nil
	}
	moduleIndex := -1
	for index, field := range headerFields {
		if strings.EqualFold(field, "module") {
			moduleIndex = index
			break
		}
	}
	if moduleIndex < 0 {
		return nil, errors.New("fmadm: fmadm config header has no module field")
	}
	result := make(map[string]any)
	for index, raw := range lines[1:] {
		line := strings.TrimSuffix(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := splitSpaceFields(line)
		if len(fields) < 3 {
			return nil, fmt.Errorf("fmadm: malformed fmadm config row %d", index+2)
		}
		row := append(append([]string{}, fields[:minInt(3, len(fields))]...), strings.Join(fields[3:], " "))
		if len(row) < len(headerFields) {
			return nil, fmt.Errorf("fmadm: malformed fmadm config row %d: got %d fields, want %d", index+2, len(row), len(headerFields))
		}
		component := make(map[string]any, len(headerFields)-1)
		for fieldIndex, field := range headerFields {
			if fieldIndex == moduleIndex {
				continue
			}
			component[strings.ToLower(field)] = row[fieldIndex]
		}
		module, ok := row[moduleIndex], true
		if !ok || module == "" {
			return nil, fmt.Errorf("fmadm: empty module in config row %d", index+2)
		}
		result[module] = component
	}
	return result, nil
}

func parseFmadmFaulty(output string) (map[string]any, error) {
	result := map[string]any{}
	var summaryLines []string
	var summaryData map[string]any
	faultData := map[string]any{}
	dataKey := ""

	merge := func() error {
		if len(summaryData) == 0 || len(faultData) == 0 {
			return errors.New("fmadm: incomplete faulty record")
		}
		eventIDValue, present := summaryData["event-id"]
		if !present {
			return errors.New("fmadm: faulty record has no event-id")
		}
		eventID, ok := eventIDValue.(string)
		if !ok {
			return errors.New("fmadm: faulty record event-id is not a string")
		}
		summary := make(map[string]any, len(summaryData)-1)
		for key, value := range summaryData {
			if key != "event-id" {
				summary[key] = value
			}
		}
		fault := make(map[string]any, len(faultData))
		for key, value := range faultData {
			fault[key] = value
		}
		result[eventID] = map[string]any{"summary": summary, "fault": fault}
		return nil
	}

	for lineIndex, raw := range strings.Split(output, "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if strings.HasPrefix(line, "-") {
			if len(summaryLines) > 0 && len(summaryData) > 0 && len(faultData) > 0 {
				if err := merge(); err != nil {
					return nil, fmt.Errorf("fmadm: malformed faulty record at line %d: %w", lineIndex+1, err)
				}
				summaryLines = nil
				summaryData = nil
				faultData = map[string]any{}
				continue
			}
			continue
		}
		if len(summaryLines) == 0 {
			if strings.TrimSpace(line) == "" {
				continue
			}
			summaryLines = []string{line}
			continue
		}
		if len(summaryData) == 0 {
			summaryLines = append(summaryLines, line)
			parsed, err := parseFmdump(strings.Join(summaryLines, "\n"))
			if err != nil {
				return nil, fmt.Errorf("fmadm: malformed faulty summary at line %d: %w", lineIndex+1, err)
			}
			if len(parsed) == 0 {
				return nil, fmt.Errorf("fmadm: faulty summary at line %d has no data", lineIndex+1)
			}
			summaryData = parsed[0]
			continue
		}
		if strings.HasPrefix(line, " ") && dataKey != "" {
			previous, _ := faultData[dataKey].(string)
			faultData[dataKey] = previous + "\n" + strings.TrimSpace(line)
			continue
		}
		if colon := strings.IndexByte(line, ':'); colon >= 0 {
			dataKey = strings.TrimSpace(line[:colon])
			value := strings.TrimSpace(line[colon+1:])
			faultData[dataKey] = value
			if dataKey == "Platform" {
				chassisIndex := strings.Index(value, "Chassis_id")
				if chassisIndex < 0 {
					return nil, fmt.Errorf("fmadm: Platform field at line %d has no Chassis_id", lineIndex+1)
				}
				chassis := strings.TrimSpace(value[chassisIndex:])
				if separator := strings.LastIndexByte(chassis, ':'); separator >= 0 {
					chassis = strings.TrimSpace(chassis[separator+1:])
				}
				faultData["Chassis_id"] = chassis
				faultData[dataKey] = strings.TrimSpace(value[:chassisIndex])
			}
		}
	}

	if len(summaryData) > 0 || len(faultData) > 0 {
		if err := merge(); err != nil {
			return nil, fmt.Errorf("fmadm: malformed final faulty record: %w", err)
		}
	} else if len(result) == 0 {
		return nil, errors.New("fmadm: faulty output has no record")
	}
	return result, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type ListArgs struct {
	After  *string `statekit:"name=after"`
	Before *string `statekit:"name=before"`
}

type listFunc struct{ solarisOnly }

func (listFunc) Name() string { return "fmadm.list" }
func (listFunc) Args() any    { return ListArgs{} }
func (listFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListArgs)
	argv := []string{"fmdump"}
	if a.After != nil && *a.After != "" {
		argv = append(argv, "-t", *a.After)
	}
	if a.Before != nil && *a.Before != "" {
		argv = append(argv, "-T", *a.Before)
	}
	result, err := fmadmRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return fmdumpFailure(), nil
	}
	return parseFmdump(string(result.Stdout))
}

type ShowArgs struct {
	UUID string `statekit:"required,name=uuid"`
}

type showFunc struct{ solarisOnly }

func (showFunc) Name() string { return "fmadm.show" }
func (showFunc) Args() any    { return ShowArgs{} }
func (showFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ShowArgs)
	result, err := fmadmRun(ctx, rt, "fmdump", "-u", a.UUID, "-V")
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return fmdumpFailure(), nil
	}
	return parseFmdumpVerbose(string(result.Stdout))
}

type ConfigArgs struct{}
type configFunc struct{ solarisOnly }

func (configFunc) Name() string { return "fmadm.config" }
func (configFunc) Args() any    { return ConfigArgs{} }
func (configFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	result, err := fmadmRun(ctx, rt, "fmadm", "config")
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return fmadmConfigFailure(), nil
	}
	return parseFmadmConfig(string(result.Stdout))
}

type LoadArgs struct {
	Path string `statekit:"required,name=path"`
}
type loadFunc struct{ solarisOnly }

func (loadFunc) Name() string { return "fmadm.load" }
func (loadFunc) Args() any    { return LoadArgs{} }
func (loadFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*LoadArgs)
	result, err := fmadmRun(ctx, rt, "fmadm", "load", a.Path)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return commandFailure(result.Stderr), nil
	}
	return true, nil
}

type UnloadArgs struct {
	Module string `statekit:"required,name=module"`
}
type unloadFunc struct{ solarisOnly }

func (unloadFunc) Name() string { return "fmadm.unload" }
func (unloadFunc) Args() any    { return UnloadArgs{} }
func (unloadFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*UnloadArgs)
	result, err := fmadmRun(ctx, rt, "fmadm", "unload", a.Module)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return commandFailure(result.Stderr), nil
	}
	return true, nil
}

type ResetArgs struct {
	Module string  `statekit:"required,name=module"`
	Serd   *string `statekit:"name=serd"`
}
type resetFunc struct{ solarisOnly }

func (resetFunc) Name() string { return "fmadm.reset" }
func (resetFunc) Args() any    { return ResetArgs{} }
func (resetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ResetArgs)
	argv := []string{"fmadm", "reset"}
	if a.Serd != nil && *a.Serd != "" {
		argv = append(argv, "-s", *a.Serd)
	}
	argv = append(argv, a.Module)
	result, err := fmadmRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return commandFailure(result.Stderr), nil
	}
	return true, nil
}

type FmriArgs struct {
	Fmri string `statekit:"required,name=fmri"`
}

type flushFunc struct{ solarisOnly }

func (flushFunc) Name() string { return "fmadm.flush" }
func (flushFunc) Args() any    { return FmriArgs{} }
func (flushFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return fmadmAction(ctx, rt, "flush", args.(*FmriArgs).Fmri)
}

type repairedFunc struct{ solarisOnly }

func (repairedFunc) Name() string { return "fmadm.repaired" }
func (repairedFunc) Args() any    { return FmriArgs{} }
func (repairedFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return fmadmAction(ctx, rt, "repaired", args.(*FmriArgs).Fmri)
}

type replacedFunc struct{ solarisOnly }

func (replacedFunc) Name() string { return "fmadm.replaced" }
func (replacedFunc) Args() any    { return FmriArgs{} }
func (replacedFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return fmadmAction(ctx, rt, "replaced", args.(*FmriArgs).Fmri)
}

type acquitFunc struct{ solarisOnly }

func (acquitFunc) Name() string { return "fmadm.acquit" }
func (acquitFunc) Args() any    { return FmriArgs{} }
func (acquitFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return fmadmAction(ctx, rt, "acquit", args.(*FmriArgs).Fmri)
}

func fmadmAction(ctx context.Context, rt *runtime.Runtime, action, fmri string) (any, error) {
	result, err := fmadmRun(ctx, rt, "fmadm", action, fmri)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return commandFailure(result.Stderr), nil
	}
	return true, nil
}

type FaultyArgs struct{}
type faultyFunc struct{ solarisOnly }

func (faultyFunc) Name() string { return "fmadm.faulty" }
func (faultyFunc) Args() any    { return FaultyArgs{} }
func (faultyFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	result, err := fmadmRun(ctx, rt, "fmadm", "faulty")
	if err != nil {
		return nil, err
	}
	// The pinned source intentionally ignores retcode for faulty(): empty
	// stdout is False, while non-empty stdout is parsed even on non-zero exit.
	if len(result.Stdout) == 0 {
		return false, nil
	}
	return parseFmadmFaulty(string(result.Stdout))
}

type HealthyArgs struct{}
type healthyFunc struct{ solarisOnly }

func (healthyFunc) Name() string { return "fmadm.healthy" }
func (healthyFunc) Args() any    { return HealthyArgs{} }
func (healthyFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	value, err := faultyFunc{}.Execute(ctx, rt, nil)
	if err != nil {
		return nil, err
	}
	return !pythonTruthy(value), nil
}

func pythonTruthy(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case string:
		return typed != ""
	case []map[string]any:
		return len(typed) > 0
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	default:
		return true
	}
}
