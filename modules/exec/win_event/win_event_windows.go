//go:build windows

// Package win_event implements Salt's Windows event-log surface through
// Get-WinEvent and wevtutil. PowerShell scripts are encoded before reaching
// the Runner; event queries return JSON projections or raw XML as requested.
package win_event

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func eventPS(script string, secrets []string) process.Command {
	units := make([]uint16, 0, len(script)+1)
	for _, r := range script + "\x00" {
		if r <= 0xffff {
			units = append(units, uint16(r))
		} else {
			r -= 0x10000
			units = append(units, uint16(0xd800+(r>>10)), uint16(0xdc00+(r&0x3ff)))
		}
	}
	raw := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], unit)
	}
	return process.Command{Name: "powershell.exe", Args: []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw)}, Redact: secrets}
}
func eventLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
func eventRun(ctx context.Context, rt *runtime.Runtime, argv ...string) process.CommandResult {
	return rt.Runner.Run(ctx, runtime.Command(argv...))
}
func eventPSRun(ctx context.Context, rt *runtime.Runtime, script string, secrets []string) (string, error) {
	r := rt.Runner.Run(ctx, eventPS(script, secrets))
	if r.Err != nil && r.ExitCode == -1 {
		return string(r.Stdout), r.Err
	}
	if r.ExitCode != 0 {
		return string(r.Stdout), fmt.Errorf("PowerShell event command failed (exit code %d): %s", r.ExitCode, strings.TrimSpace(string(r.Stderr)))
	}
	return string(r.Stdout), nil
}
func eventJSON(ctx context.Context, rt *runtime.Runtime, script string) (any, error) {
	out, e := eventPSRun(ctx, rt, script+" | ConvertTo-Json -Compress -Depth 5", nil)
	if e != nil {
		return nil, e
	}
	if strings.TrimSpace(out) == "" || strings.TrimSpace(out) == "null" {
		return nil, nil
	}
	var v any
	if e = json.Unmarshal([]byte(out), &v); e != nil {
		return nil, e
	}
	return v, nil
}
func eventRows(value any) []map[string]any {
	switch x := value.(type) {
	case map[string]any:
		return []map[string]any{x}
	case []any:
		out := []map[string]any{}
		for _, v := range x {
			if row, ok := v.(map[string]any); ok {
				out = append(out, row)
			}
		}
		return out
	default:
		return []map[string]any{}
	}
}
func eventProjectionScript(logName, query string, records int, latest bool, raw bool) string {
	direction := "-Oldest"
	if latest {
		direction = ""
	}
	max := records
	if max <= 0 {
		max = 2147483647
	}
	script := "$events=Get-WinEvent -LogName " + eventLiteral(logName) + " -MaxEvents " + strconv.Itoa(max)
	if direction != "" {
		script += " " + direction
	}
	if query != "" {
		script = "$events=Get-WinEvent -LogName " + eventLiteral(logName) + " -FilterXPath " + eventLiteral(query) + " -MaxEvents " + strconv.Itoa(max)
		if direction != "" {
			script += " " + direction
		}
	}
	if raw {
		return "@( $events | ForEach-Object { $_.ToXml() } )"
	}
	return "@( $events | Select-Object @{n='eventID';e={$_.Id}},@{n='eventType';e={$_.Level}},@{n='sourceName';e={$_.ProviderName}},@{n='recordNumber';e={$_.RecordId}},@{n='computerName';e={$_.MachineName}},@{n='timeGenerated';e={$_.TimeCreated.ToString('o')}},@{n='data';e={$_.Message}},@{n='logName';e={$_.LogName}} )"
}

// ---------------------------------------------------------------------------

type getArgs struct {
	LogName string `statekit:"required,name=log_name"`
}
type getFunc struct{}

func (getFunc) Name() string        { return "win_event.get" }
func (getFunc) Args() any           { return getArgs{} }
func (getFunc) Platforms() []string { return []string{"windows"} }
func (getFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverEvent(&res, &err)
	a := args.(*getArgs)
	value, e := eventJSON(ctx, rt, eventProjectionScript(a.LogName, "", 0, true, false))
	if e != nil {
		return nil, e
	}
	out := []map[string]any{}
	for _, row := range eventRows(value) {
		out = append(out, row)
	}
	return out, nil
}

type queryArgs struct {
	LogName   string  `statekit:"required,name=log_name"`
	QueryText *string `statekit:"name=query_text"`
	Records   *int    `statekit:"name=records"`
	Latest    *bool   `statekit:"name=latest"`
	Raw       *bool   `statekit:"name=raw"`
}
type queryFunc struct{}

func (queryFunc) Name() string        { return "win_event.query" }
func (queryFunc) Args() any           { return queryArgs{} }
func (queryFunc) Platforms() []string { return []string{"windows"} }
func (queryFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverEvent(&res, &err)
	a := args.(*queryArgs)
	records := 20
	if a.Records != nil {
		records = *a.Records
	}
	latest := true
	if a.Latest != nil {
		latest = *a.Latest
	}
	raw := false
	if a.Raw != nil {
		raw = *a.Raw
	}
	query := ""
	if a.QueryText != nil {
		query = *a.QueryText
	}
	value, e := eventJSON(ctx, rt, eventProjectionScript(a.LogName, query, records, latest, raw))
	if e != nil {
		return nil, e
	}
	if raw {
		out := []string{}
		switch x := value.(type) {
		case []any:
			for _, v := range x {
				out = append(out, fmt.Sprint(v))
			}
		case string:
			out = []string{x}
		}
		return out, nil
	}
	return eventRows(value), nil
}

type filteredArgs struct {
	LogName         string         `statekit:"required,name=log_name"`
	AllRequirements *bool          `statekit:"name=all_requirements"`
	Filters         map[string]any `statekit:"name=kwargs"`
}
type filteredFunc struct{}

func (filteredFunc) Name() string        { return "win_event.get_filtered" }
func (filteredFunc) Args() any           { return filteredArgs{} }
func (filteredFunc) Platforms() []string { return []string{"windows"} }
func (filteredFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverEvent(&res, &err)
	a := args.(*filteredArgs)
	value, e := getFunc{}.Execute(ctx, rt, &getArgs{LogName: a.LogName})
	if e != nil {
		return nil, e
	}
	all := true
	if a.AllRequirements != nil {
		all = *a.AllRequirements
	}
	rows, ok := value.([]map[string]any)
	if !ok {
		return []map[string]any{}, nil
	}
	out := []map[string]any{}
	for _, row := range rows {
		matches := 0
		for key, want := range a.Filters {
			if fmt.Sprint(row[key]) == fmt.Sprint(want) {
				matches++
			}
		}
		if (all && matches == len(a.Filters)) || (!all && matches > 0) {
			out = append(out, row)
		}
	}
	return out, nil
}

type namesArgs struct{}
type getLogNamesFunc struct{}

func (getLogNamesFunc) Name() string        { return "win_event.get_log_names" }
func (getLogNamesFunc) Args() any           { return namesArgs{} }
func (getLogNamesFunc) Platforms() []string { return []string{"windows"} }
func (getLogNamesFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverEvent(&res, &err)
	r := eventRun(ctx, rt, "wevtutil", "el")
	if r.Err != nil && r.ExitCode == -1 {
		return nil, r.Err
	}
	if r.ExitCode != 0 {
		return nil, fmt.Errorf("wevtutil el failed: %s", r.Stderr)
	}
	out := []string{}
	for _, line := range strings.Split(string(r.Stdout), "\n") {
		if line = strings.TrimSpace(strings.TrimSuffix(line, "\r")); line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

type addArgs struct {
	LogName       string  `statekit:"required,name=log_name"`
	EventID       int     `statekit:"required,name=event_id"`
	EventCategory *int    `statekit:"name=event_category"`
	EventType     any     `statekit:"name=event_type"`
	EventStrings  any     `statekit:"name=event_strings"`
	EventData     any     `statekit:"name=event_data"`
	EventSID      *string `statekit:"name=event_sid"`
}
type addFunc struct{}

func (addFunc) Name() string        { return "win_event.add" }
func (addFunc) Args() any           { return addArgs{} }
func (addFunc) Platforms() []string { return []string{"windows"} }
func (addFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverEvent(&res, &err)
	a := args.(*addArgs)
	types := map[string]string{"success": "Success", "error": "Error", "warning": "Warning", "information": "Information", "auditsuccess": "SuccessAudit", "auditfailure": "FailureAudit"}
	entry := "Error"
	if a.EventType != nil {
		mapped := ""
		ok := false
		switch value := a.EventType.(type) {
		case string:
			mapped, ok = types[strings.ToLower(value)]
		case int:
			mapped, ok = map[int]string{0: "Success", 1: "Error", 2: "Warning", 4: "Information", 8: "SuccessAudit", 16: "FailureAudit"}[value]
		case float64:
			mapped, ok = map[int]string{0: "Success", 1: "Error", 2: "Warning", 4: "Information", 8: "SuccessAudit", 16: "FailureAudit"}[int(value)]
		}
		if !ok {
			return nil, fmt.Errorf("Incorrect event type: %v", a.EventType)
		}
		entry = mapped
	}
	category := 0
	if a.EventCategory != nil {
		category = *a.EventCategory
	}
	message := eventMessage(a.EventStrings)
	script := "Write-EventLog -LogName " + eventLiteral(a.LogName) + " -Source " + eventLiteral(a.LogName) + " -EventId " + strconv.Itoa(a.EventID) + " -EntryType " + entry + " -Category " + strconv.Itoa(category) + " -Message " + eventLiteral(message)
	if raw := eventRawData(a.EventData); raw != "" {
		script += " -RawData ([byte[]](" + raw + "))"
	}
	_, e := eventPSRun(ctx, rt, script, nil)
	if e != nil {
		return nil, e
	}
	return nil, nil
}

func eventMessage(value any) string {
	switch item := value.(type) {
	case string:
		return item
	case []string:
		return strings.Join(item, " ")
	case []any:
		parts := make([]string, 0, len(item))
		for _, part := range item {
			parts = append(parts, fmt.Sprint(part))
		}
		return strings.Join(parts, " ")
	default:
		return ""
	}
}

func eventRawData(value any) string {
	var values []int
	switch item := value.(type) {
	case []byte:
		for _, byteValue := range item {
			values = append(values, int(byteValue))
		}
	case string:
		for _, byteValue := range []byte(item) {
			values = append(values, int(byteValue))
		}
	case []any:
		for _, byteValue := range item {
			values = append(values, intValueEvent(byteValue))
		}
	default:
		return ""
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ",")
}

func intValueEvent(value any) int {
	switch item := value.(type) {
	case float64:
		return int(item)
	case int:
		return item
	default:
		value, _ := strconv.Atoi(fmt.Sprint(item))
		return value
	}
}

type clearArgs struct {
	LogName string  `statekit:"required,name=log_name"`
	Backup  *string `statekit:"name=backup"`
}
type clearFunc struct{}

func (clearFunc) Name() string        { return "win_event.clear" }
func (clearFunc) Args() any           { return clearArgs{} }
func (clearFunc) Platforms() []string { return []string{"windows"} }
func (clearFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*clearArgs)
	argv := []string{"wevtutil", "cl", a.LogName}
	if a.Backup != nil && *a.Backup != "" {
		argv = append(argv, "/bu:"+*a.Backup)
	}
	r := eventRun(ctx, rt, argv...)
	if r.Err != nil && r.ExitCode == -1 {
		return nil, r.Err
	}
	if r.ExitCode != 0 {
		return nil, fmt.Errorf("wevtutil clear failed: %s", r.Stderr)
	}
	return nil, nil
}

type countArgs struct {
	LogName string `statekit:"required,name=log_name"`
}
type countFunc struct{}

func (countFunc) Name() string        { return "win_event.count" }
func (countFunc) Args() any           { return countArgs{} }
func (countFunc) Platforms() []string { return []string{"windows"} }
func (countFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverEvent(&res, &err)
	a := args.(*countArgs)
	value, e := eventJSON(ctx, rt, "(Get-WinEvent -ListLog "+eventLiteral(a.LogName)+").RecordCount")
	if e != nil {
		return nil, e
	}
	switch x := value.(type) {
	case float64:
		return int(x), nil
	case int:
		return x, nil
	default:
		n, _ := strconv.Atoi(fmt.Sprint(x))
		return n, nil
	}
}

func recoverEvent(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{getFunc{}, queryFunc{}, filteredFunc{}, getLogNamesFunc{}, addFunc{}, clearFunc{}, countFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
