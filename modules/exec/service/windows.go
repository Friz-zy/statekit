//go:build windows

package service

// Windows Service Control Manager implementation for win_service.py. The
// native sc.exe/schtasks.exe commands are kept behind the central Runner;
// Linux and Darwin provider trees remain selected by service.Register.

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

var sleepWindowsService = time.Sleep

var (
	serviceTypeNames      = map[string]string{"kernel": "kernel", "filesystem": "filesys", "adapter": "adapter", "recognizer": "recognizer", "own": "own", "share": "share"}
	startTypeNames        = map[string]string{"boot": "boot", "system": "system", "auto": "auto", "manual": "demand", "disabled": "disabled"}
	errorControlNames     = map[string]string{"normal": "normal", "severe": "severe", "critical": "critical", "ignore": "ignore"}
	windowsServiceCache   map[*runtime.Runtime][]string
	windowsServiceCacheMu sync.Mutex
)

func registerWindows(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		winGetEnabledFunc{}, winGetDisabledFunc{}, winAvailableFunc{}, winMissingFunc{}, winGetAllFunc{},
		winGetServiceNameFunc{}, winInfoFunc{}, winStartFunc{}, winStopFunc{}, winRestartFunc{},
		winCreateRestartTaskFunc{}, winExecuteRestartTaskFunc{}, winStatusFunc{}, winGetSIDFunc{},
		winModifyFunc{}, winEnableFunc{}, winDisableFunc{}, winEnabledFunc{}, winDisabledFunc{},
		winCreateFunc{}, winDeleteFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

func runSC(ctx context.Context, rt *runtime.Runtime, args ...string) process.CommandResult {
	return rt.Runner.Run(ctx, runtime.Command(append([]string{"sc.exe"}, args...)...))
}

func scOK(result process.CommandResult) bool { return result.Err == nil && result.ExitCode == 0 }

func scFields(output string) map[string]string {
	fields := map[string]string{}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return fields
}

func serviceNames(ctx context.Context, rt *runtime.Runtime, refresh bool) ([]string, error) {
	windowsServiceCacheMu.Lock()
	if !refresh && windowsServiceCache[rt] != nil {
		out := append([]string(nil), windowsServiceCache[rt]...)
		windowsServiceCacheMu.Unlock()
		return out, nil
	}
	windowsServiceCacheMu.Unlock()
	result := runSC(ctx, rt, "query", "type=", "service", "state=", "all")
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("sc.exe query failed: %s", strings.TrimSpace(string(result.Stderr)))
	}
	seen := map[string]bool{}
	var names []string
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "SERVICE_NAME:") {
			name := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "SERVICE_NAME:"), "SERVICE_NAME :"))
			if name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sortWindowsStrings(names)
	windowsServiceCacheMu.Lock()
	windowsServiceCache[rt] = append([]string(nil), names...)
	windowsServiceCacheMu.Unlock()
	return names, nil
}

func serviceInfo(ctx context.Context, rt *runtime.Runtime, name string) (map[string]any, error) {
	query := runSC(ctx, rt, "queryex", name)
	if query.Err != nil && query.ExitCode == -1 {
		return nil, query.Err
	}
	if query.ExitCode != 0 {
		return nil, fmt.Errorf("Service %s not found", name)
	}
	qc := runSC(ctx, rt, "qc", name)
	if qc.Err != nil && qc.ExitCode == -1 {
		return nil, qc.Err
	}
	if qc.ExitCode != 0 {
		return nil, fmt.Errorf("Service %s not found", name)
	}
	q := scFields(string(query.Stdout))
	c := scFields(string(qc.Stdout))
	state := parseState(q["STATE"])
	start := parseStartType(c["START_TYPE"])
	info := map[string]any{
		"ServiceName": name, "DisplayName": c["DISPLAY_NAME"], "Status": state, "Status_WaitHint": parseFirstInt(q["WAIT_HINT"]), "CheckPoint": parseFirstInt(q["CHECKPOINT"]), "Win32_ExitCode": parseFirstInt(q["WIN32_EXIT_CODE"]),
		"ServiceType": c["TYPE"], "StartType": start, "StartTypeDelayed": false, "ErrorControl": c["ERROR_CONTROL"], "BinaryPath": c["BINARY_PATH_NAME"], "LoadOrderGroup": c["LOAD_ORDER_GROUP"], "Dependencies": splitDependencies(c["DEPENDENCIES"]), "ServiceAccount": c["SERVICE_START_NAME"], "Description": "", "sid": "",
	}
	return info, nil
}

func parseFirstInt(value string) int {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimPrefix(fields[0], "0x"))
	return n
}
func parseState(value string) string {
	upper := strings.ToUpper(value)
	switch {
	case strings.Contains(upper, "RUNNING"):
		return "Running"
	case strings.Contains(upper, "STOP_PENDING"):
		return "Stop Pending"
	case strings.Contains(upper, "START_PENDING"):
		return "Start Pending"
	case strings.Contains(upper, "STOPPED"):
		return "Stopped"
	default:
		return strings.TrimSpace(value)
	}
}
func parseStartType(value string) string {
	upper := strings.ToUpper(value)
	switch {
	case strings.Contains(upper, "AUTO_START"):
		return "Auto"
	case strings.Contains(upper, "DEMAND_START"):
		return "Manual"
	case strings.Contains(upper, "DISABLED"):
		return "Disabled"
	case strings.Contains(upper, "BOOT_START"):
		return "Boot"
	case strings.Contains(upper, "SYSTEM_START"):
		return "System"
	default:
		return strings.TrimSpace(value)
	}
}
func splitDependencies(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "(none)") {
		return []string{}
	}
	return strings.Fields(value)
}

func serviceRunning(ctx context.Context, rt *runtime.Runtime, name string) (bool, error) {
	info, err := serviceInfo(ctx, rt, name)
	if err != nil {
		return false, err
	}
	status, _ := info["Status"].(string)
	return status == "Running" || status == "Stop Pending", nil
}

func modifyService(ctx context.Context, rt *runtime.Runtime, name string, changes map[string]string, secret *string) (map[string]any, error) {
	args := []string{"config", name}
	for key, value := range changes {
		args = append(args, key+"=", value)
	}
	result := runSC(ctx, rt, args...)
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("Failed to modify %s: %s", name, strings.TrimSpace(string(result.Stderr)))
	}
	out := map[string]any{}
	for key, value := range changes {
		out[key] = value
	}
	_ = secret // reserved for Runner redaction when sc.exe receives a password
	return out, nil
}
func waitService(ctx context.Context, rt *runtime.Runtime, name string, want []string, timeout int) map[string]any {
	end := time.Now().Add(time.Duration(timeout) * time.Second)
	for {
		info, err := serviceInfo(ctx, rt, name)
		if err != nil {
			return map[string]any{"Status": "Not Found"}
		}
		status, _ := info["Status"].(string)
		matched := false
		for _, candidate := range want {
			if status == candidate {
				matched = true
			}
		}
		if !matched || time.Now().After(end) {
			return info
		}
		sleepWindowsService(time.Second)
	}
}

// ---------------------------------------------------------------------------
// listing/status

type winNoArgs struct{}
type winGetEnabledFunc struct{}

func (winGetEnabledFunc) Name() string        { return "service.get_enabled" }
func (winGetEnabledFunc) Args() any           { return winNoArgs{} }
func (winGetEnabledFunc) Platforms() []string { return []string{"windows"} }
func (winGetEnabledFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverWindowsService(&res, &err)
	names, e := serviceNames(ctx, rt, false)
	if e != nil {
		return nil, e
	}
	var out []string
	for _, name := range names {
		info, e := serviceInfo(ctx, rt, name)
		if e == nil && info["StartType"] == "Auto" {
			out = append(out, name)
		}
	}
	return out, nil
}

type winGetDisabledFunc struct{}

func (winGetDisabledFunc) Name() string        { return "service.get_disabled" }
func (winGetDisabledFunc) Args() any           { return winNoArgs{} }
func (winGetDisabledFunc) Platforms() []string { return []string{"windows"} }
func (winGetDisabledFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverWindowsService(&res, &err)
	names, e := serviceNames(ctx, rt, false)
	if e != nil {
		return nil, e
	}
	var out []string
	for _, name := range names {
		info, e := serviceInfo(ctx, rt, name)
		if e == nil && (info["StartType"] == "Auto" || info["StartType"] == "Disabled" || info["StartType"] == "Manual") {
			if info["StartType"] != "Auto" {
				out = append(out, name)
			}
		}
	}
	return out, nil
}

type winAvailableArgs struct {
	Name string `statekit:"required"`
}
type winAvailableFunc struct{}

func (winAvailableFunc) Name() string        { return "service.available" }
func (winAvailableFunc) Args() any           { return winAvailableArgs{} }
func (winAvailableFunc) Platforms() []string { return []string{"windows"} }
func (winAvailableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsService(&res, &err)
	names, e := serviceNames(ctx, rt, false)
	if e != nil {
		return false, nil
	}
	a := args.(*winAvailableArgs)
	for _, name := range names {
		if strings.EqualFold(name, a.Name) {
			return true, nil
		}
	}
	return false, nil
}

type winMissingFunc struct{}

func (winMissingFunc) Name() string        { return "service.missing" }
func (winMissingFunc) Args() any           { return winAvailableArgs{} }
func (winMissingFunc) Platforms() []string { return []string{"windows"} }
func (winMissingFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	v, e := winAvailableFunc{}.Execute(ctx, rt, args)
	return !v.(bool), e
}

type winGetAllFunc struct{}

func (winGetAllFunc) Name() string        { return "service.get_all" }
func (winGetAllFunc) Args() any           { return winNoArgs{} }
func (winGetAllFunc) Platforms() []string { return []string{"windows"} }
func (winGetAllFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverWindowsService(&res, &err)
	return serviceNames(ctx, rt, false)
}

type winGetServiceNameArgs struct {
	Names []string `statekit:"name=names"`
}
type winGetServiceNameFunc struct{}

func (winGetServiceNameFunc) Name() string        { return "service.get_service_name" }
func (winGetServiceNameFunc) Args() any           { return winGetServiceNameArgs{} }
func (winGetServiceNameFunc) Platforms() []string { return []string{"windows"} }
func (winGetServiceNameFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsService(&res, &err)
	a := args.(*winGetServiceNameArgs)
	names, e := serviceNames(ctx, rt, false)
	if e != nil {
		return nil, e
	}
	wanted := map[string]bool{}
	for _, name := range a.Names {
		wanted[name] = true
		wanted[strings.ToLower(name)] = true
	}
	out := map[string]string{}
	for _, name := range names {
		info, e := serviceInfo(ctx, rt, name)
		if e != nil {
			continue
		}
		display, _ := info["DisplayName"].(string)
		if len(a.Names) == 0 || wanted[display] || wanted[name] || wanted[strings.ToLower(name)] {
			out[display] = name
		}
	}
	return out, nil
}

type winInfoArgs struct {
	Name string `statekit:"required"`
}
type winInfoFunc struct{}

func (winInfoFunc) Name() string        { return "service.info" }
func (winInfoFunc) Args() any           { return winInfoArgs{} }
func (winInfoFunc) Platforms() []string { return []string{"windows"} }
func (winInfoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsService(&res, &err)
	return serviceInfo(ctx, rt, args.(*winInfoArgs).Name)
}

// ---------------------------------------------------------------------------
// start/stop/restart/status

type winLifecycleArgs struct {
	Name    string `statekit:"required"`
	Timeout *int   `statekit:"name=timeout"`
}
type winStartFunc struct{}
type winStopFunc struct{}
type winRestartFunc struct{}

func (winStartFunc) Name() string        { return "service.start" }
func (winStartFunc) Args() any           { return winLifecycleArgs{} }
func (winStartFunc) Platforms() []string { return []string{"windows"} }
func (winStartFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsService(&res, &err)
	a := args.(*winLifecycleArgs)
	info, e := serviceInfo(ctx, rt, a.Name)
	if e != nil {
		return nil, e
	}
	if info["StartType"] == "Disabled" {
		_, e = modifyService(ctx, rt, a.Name, map[string]string{"start": "demand"}, nil)
		if e != nil {
			return false, e
		}
	}
	result := runSC(ctx, rt, "start", a.Name)
	if result.ExitCode != 0 && !strings.Contains(strings.ToLower(string(result.Stderr)), "already been started") {
		return false, fmt.Errorf("Failed To Start %s: %s", a.Name, strings.TrimSpace(string(result.Stderr)))
	}
	timeout := 90
	if a.Timeout != nil {
		timeout = *a.Timeout
	}
	return waitService(ctx, rt, a.Name, []string{"Start Pending", "Stopped"}, timeout)["Status"] == "Running", nil
}
func (winStopFunc) Name() string        { return "service.stop" }
func (winStopFunc) Args() any           { return winLifecycleArgs{} }
func (winStopFunc) Platforms() []string { return []string{"windows"} }
func (winStopFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsService(&res, &err)
	a := args.(*winLifecycleArgs)
	result := runSC(ctx, rt, "stop", a.Name)
	if result.ExitCode != 0 && !strings.Contains(strings.ToLower(string(result.Stderr)), "not started") {
		return false, fmt.Errorf("Failed To Stop %s: %s", a.Name, strings.TrimSpace(string(result.Stderr)))
	}
	timeout := 90
	if a.Timeout != nil {
		timeout = *a.Timeout
	}
	return waitService(ctx, rt, a.Name, []string{"Running", "Stop Pending"}, timeout)["Status"] == "Stopped", nil
}
func (winRestartFunc) Name() string        { return "service.restart" }
func (winRestartFunc) Args() any           { return winLifecycleArgs{} }
func (winRestartFunc) Platforms() []string { return []string{"windows"} }
func (winRestartFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*winLifecycleArgs)
	if strings.Contains(a.Name, "salt-minion") {
		if _, err := (winCreateRestartTaskFunc{}).Execute(ctx, rt, winNoArgs{}); err != nil {
			return nil, err
		}
		return winExecuteRestartTaskFunc{}.Execute(ctx, rt, winNoArgs{})
	}
	st, err := winStopFunc{}.Execute(ctx, rt, args)
	if err != nil || st != true {
		return st, err
	}
	return winStartFunc{}.Execute(ctx, rt, args)
}

type winStatusArgs struct {
	Name string  `statekit:"required"`
	Sig  *string `statekit:"name=sig"`
}
type winStatusFunc struct{}

func (winStatusFunc) Name() string        { return "service.status" }
func (winStatusFunc) Args() any           { return winStatusArgs{} }
func (winStatusFunc) Platforms() []string { return []string{"windows"} }
func (winStatusFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsService(&res, &err)
	a := args.(*winStatusArgs)
	names, e := serviceNames(ctx, rt, false)
	if e != nil {
		return nil, e
	}
	contains := strings.ContainsAny(a.Name, "*?") || regexp.MustCompile(`\[.+\]`).MatchString(a.Name)
	if contains {
		out := map[string]any{}
		for _, name := range names {
			matched, _ := path.Match(a.Name, name)
			if matched {
				running, _ := serviceRunning(ctx, rt, name)
				out[name] = running
			}
		}
		return out, nil
	}
	for _, name := range names {
		if strings.EqualFold(name, a.Name) {
			running, _ := serviceRunning(ctx, rt, name)
			return running, nil
		}
	}
	return "Not Found", nil
}

type winGetSIDArgs struct {
	Name string `statekit:"required"`
}
type winGetSIDFunc struct{}

func (winGetSIDFunc) Name() string        { return "service.getsid" }
func (winGetSIDFunc) Args() any           { return winGetSIDArgs{} }
func (winGetSIDFunc) Platforms() []string { return []string{"windows"} }
func (winGetSIDFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	info, err := serviceInfo(ctx, rt, args.(*winGetSIDArgs).Name)
	if err != nil {
		return nil, err
	}
	return info["sid"], nil
}

// ---------------------------------------------------------------------------
// config/create/delete

type winModifyArgs struct {
	Name            string   `statekit:"required"`
	BinPath         *string  `statekit:"name=bin_path"`
	ExeArgs         *string  `statekit:"name=exe_args"`
	DisplayName     *string  `statekit:"name=display_name"`
	Description     *string  `statekit:"name=description"`
	ServiceType     *string  `statekit:"name=service_type"`
	StartType       *string  `statekit:"name=start_type"`
	StartDelayed    *bool    `statekit:"name=start_delayed"`
	ErrorControl    *string  `statekit:"name=error_control"`
	LoadOrderGroup  *string  `statekit:"name=load_order_group"`
	Dependencies    []string `statekit:"name=dependencies"`
	AccountName     *string  `statekit:"name=account_name"`
	AccountPassword *string  `statekit:"name=account_password"`
	RunInteractive  *bool    `statekit:"name=run_interactive"`
}
type winModifyFunc struct{}

func (winModifyFunc) Name() string        { return "service.modify" }
func (winModifyFunc) Args() any           { return winModifyArgs{} }
func (winModifyFunc) Platforms() []string { return []string{"windows"} }
func (winModifyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsService(&res, &err)
	a := args.(*winModifyArgs)
	if _, e := serviceInfo(ctx, rt, a.Name); e != nil {
		return nil, e
	}
	changes := map[string]any{}
	argv := []string{"config", a.Name}
	if a.BinPath != nil {
		bin := cmdQuote(*a.BinPath)
		if a.ExeArgs != nil {
			bin += " " + *a.ExeArgs
		}
		argv = append(argv, "binPath=", bin)
		changes["BinaryPath"] = bin
	}
	if a.DisplayName != nil {
		argv = append(argv, "DisplayName=", *a.DisplayName)
		changes["DisplayName"] = *a.DisplayName
	}
	if a.StartType != nil {
		start, ok := startTypeNames[strings.ToLower(*a.StartType)]
		if !ok {
			return nil, fmt.Errorf("Invalid Start Type: %s", *a.StartType)
		}
		argv = append(argv, "start=", start)
		changes["StartType"] = strings.Title(strings.ToLower(*a.StartType))
	}
	if a.ServiceType != nil {
		typ, ok := serviceTypeNames[strings.ToLower(*a.ServiceType)]
		if !ok {
			return nil, fmt.Errorf("Invalid Service Type: %s", *a.ServiceType)
		}
		argv = append(argv, "type=", typ)
		changes["ServiceType"] = *a.ServiceType
	}
	if a.ErrorControl != nil {
		ec, ok := errorControlNames[strings.ToLower(*a.ErrorControl)]
		if !ok {
			return nil, fmt.Errorf("Invalid Error Control: %s", *a.ErrorControl)
		}
		argv = append(argv, "error=", ec)
		changes["ErrorControl"] = *a.ErrorControl
	}
	if a.LoadOrderGroup != nil {
		argv = append(argv, "group=", *a.LoadOrderGroup)
		changes["LoadOrderGroup"] = *a.LoadOrderGroup
	}
	if len(a.Dependencies) > 0 {
		argv = append(argv, "depend=", strings.Join(a.Dependencies, "/"))
		changes["Dependencies"] = a.Dependencies
	}
	if a.AccountName != nil {
		argv = append(argv, "obj=", *a.AccountName)
		changes["ServiceAccount"] = *a.AccountName
	}
	if a.AccountPassword != nil {
		argv = append(argv, "password=", *a.AccountPassword)
		changes["ServiceAccountPassword"] = "XXX-REDACTED-XXX"
	}
	if len(argv) > 2 {
		result := runSC(ctx, rt, argv...)
		if result.Err != nil && result.ExitCode == -1 {
			return nil, result.Err
		}
		if result.ExitCode != 0 {
			return nil, fmt.Errorf("Failed to modify %s: %s", a.Name, strings.TrimSpace(string(result.Stderr)))
		}
	}
	if a.Description != nil {
		result := runSC(ctx, rt, "description", a.Name, *a.Description)
		if result.ExitCode != 0 {
			return nil, fmt.Errorf("Failed to modify %s: %s", a.Name, strings.TrimSpace(string(result.Stderr)))
		}
		changes["Description"] = *a.Description
	}
	if a.StartDelayed != nil {
		changes["StartTypeDelayed"] = *a.StartDelayed
		if a.StartType == nil || strings.ToLower(*a.StartType) != "auto" {
			changes["Warning"] = `start_delayed: Requires start_type "auto"`
		}
	}
	return changes, nil
}
func cmdQuote(value string) string {
	return `"` + strings.ReplaceAll(strings.Trim(value, `"'`), `"`, `\"`) + `"`
}

type winEnableArgs struct {
	Name         string  `statekit:"required"`
	StartType    *string `statekit:"name=start_type"`
	StartDelayed *bool   `statekit:"name=start_delayed"`
}
type winEnableFunc struct{}

func (winEnableFunc) Name() string        { return "service.enable" }
func (winEnableFunc) Args() any           { return winEnableArgs{} }
func (winEnableFunc) Platforms() []string { return []string{"windows"} }
func (winEnableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsService(&res, &err)
	a := args.(*winEnableArgs)
	typ := "auto"
	if a.StartType != nil {
		typ = *a.StartType
	}
	_, err = winModifyFunc{}.Execute(ctx, rt, &winModifyArgs{Name: a.Name, StartType: &typ, StartDelayed: a.StartDelayed})
	if err != nil {
		return false, err
	}
	info, err := serviceInfo(ctx, rt, a.Name)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(info["StartType"].(string), typ), nil
}

type winDisableFunc struct{}

func (winDisableFunc) Name() string        { return "service.disable" }
func (winDisableFunc) Args() any           { return winInfoArgs{} }
func (winDisableFunc) Platforms() []string { return []string{"windows"} }
func (winDisableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsService(&res, &err)
	a := args.(*winInfoArgs)
	typ := "disabled"
	if _, err := (winModifyFunc{}).Execute(ctx, rt, &winModifyArgs{Name: a.Name, StartType: &typ}); err != nil {
		return false, err
	}
	info, err := serviceInfo(ctx, rt, a.Name)
	if err != nil {
		return false, err
	}
	return info["StartType"] == "Disabled", nil
}

type winEnabledFunc struct{}

func (winEnabledFunc) Name() string        { return "service.enabled" }
func (winEnabledFunc) Args() any           { return winInfoArgs{} }
func (winEnabledFunc) Platforms() []string { return []string{"windows"} }
func (winEnabledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	info, err := winInfoFunc{}.Execute(ctx, rt, args)
	if err != nil {
		return false, err
	}
	return info.(map[string]any)["StartType"] == "Auto", nil
}

type winDisabledFunc struct{}

func (winDisabledFunc) Name() string        { return "service.disabled" }
func (winDisabledFunc) Args() any           { return winInfoArgs{} }
func (winDisabledFunc) Platforms() []string { return []string{"windows"} }
func (winDisabledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	v, err := winEnabledFunc{}.Execute(ctx, rt, args)
	return !v.(bool), err
}

type winCreateRestartTaskFunc struct{}

func (winCreateRestartTaskFunc) Name() string        { return "service.create_win_salt_restart_task" }
func (winCreateRestartTaskFunc) Args() any           { return winNoArgs{} }
func (winCreateRestartTaskFunc) Platforms() []string { return []string{"windows"} }
func (winCreateRestartTaskFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	result := runSC(ctx, rt, "schtasks.exe", "/Create", "/TN", "restart-salt-minion", "/TR", "cmd /c ping -n 3 127.0.0.1 && net stop salt-minion && net start salt-minion", "/SC", "ONCE", "/ST", "01:00", "/RU", "SYSTEM", "/F")
	return scOK(result), nil
}

type winExecuteRestartTaskFunc struct{}

func (winExecuteRestartTaskFunc) Name() string        { return "service.execute_salt_restart_task" }
func (winExecuteRestartTaskFunc) Args() any           { return winNoArgs{} }
func (winExecuteRestartTaskFunc) Platforms() []string { return []string{"windows"} }
func (winExecuteRestartTaskFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	result := runSC(ctx, rt, "schtasks.exe", "/Run", "/TN", "restart-salt-minion")
	return scOK(result), nil
}

type winCreateArgs struct {
	Name            string   `statekit:"required"`
	BinPath         string   `statekit:"required,name=bin_path"`
	ExeArgs         *string  `statekit:"name=exe_args"`
	DisplayName     *string  `statekit:"name=display_name"`
	Description     *string  `statekit:"name=description"`
	ServiceType     *string  `statekit:"name=service_type"`
	StartType       *string  `statekit:"name=start_type"`
	StartDelayed    *bool    `statekit:"name=start_delayed"`
	ErrorControl    *string  `statekit:"name=error_control"`
	LoadOrderGroup  *string  `statekit:"name=load_order_group"`
	Dependencies    []string `statekit:"name=dependencies"`
	AccountName     *string  `statekit:"name=account_name"`
	AccountPassword *string  `statekit:"name=account_password"`
	RunInteractive  bool     `statekit:"name=run_interactive"`
}
type winCreateFunc struct{}

func (winCreateFunc) Name() string        { return "service.create" }
func (winCreateFunc) Args() any           { return winCreateArgs{} }
func (winCreateFunc) Platforms() []string { return []string{"windows"} }
func (winCreateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsService(&res, &err)
	a := args.(*winCreateArgs)
	if avail, _ := (winAvailableFunc{}).Execute(ctx, rt, &winAvailableArgs{Name: a.Name}); avail == true {
		return nil, fmt.Errorf("Service Already Exists: %s", a.Name)
	}
	start := "manual"
	if a.StartType != nil {
		start = *a.StartType
	}
	if _, ok := startTypeNames[strings.ToLower(start)]; !ok {
		return nil, fmt.Errorf("Invalid Start Type: %s", start)
	}
	display := a.Name
	if a.DisplayName != nil {
		display = *a.DisplayName
	}
	account := ".\\LocalSystem"
	if a.AccountName != nil {
		account = *a.AccountName
	}
	bin := cmdQuote(a.BinPath)
	if a.ExeArgs != nil {
		bin += " " + *a.ExeArgs
	}
	argv := []string{"create", a.Name, "binPath=", bin, "DisplayName=", display, "start=", startTypeNames[strings.ToLower(start)], "obj=", account}
	if len(a.Dependencies) > 0 {
		argv = append(argv, "depend=", strings.Join(a.Dependencies, "/"))
	}
	result := runSC(ctx, rt, argv...)
	if !scOK(result) {
		return nil, fmt.Errorf("Failed to create %s: %s", a.Name, strings.TrimSpace(string(result.Stderr)))
	}
	if a.Description != nil {
		_ = runSC(ctx, rt, "description", a.Name, *a.Description)
	}
	return serviceInfo(ctx, rt, a.Name)
}

type winDeleteFunc struct{}

func (winDeleteFunc) Name() string        { return "service.delete" }
func (winDeleteFunc) Args() any           { return winLifecycleArgs{} }
func (winDeleteFunc) Platforms() []string { return []string{"windows"} }
func (winDeleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWindowsService(&res, &err)
	a := args.(*winLifecycleArgs)
	result := runSC(ctx, rt, "delete", a.Name)
	if result.ExitCode != 0 && strings.Contains(strings.ToLower(string(result.Stderr)), "does not exist") {
		return true, nil
	}
	return scOK(result), nil
}

func sortWindowsStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
func recoverWindowsService(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}
