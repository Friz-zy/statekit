//go:build darwin

package service

// Darwin launchd implementation of Salt's mac_service virtual provider. The
// existing service package selects this file on GOOS=darwin; Linux keeps the
// generic provider-backed implementation.

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/friz-zy/statekit/internal/runtime"
)

var saltMacServices = map[string]string{
	"salt-minion": "com.saltstack.salt.minion",
	"salt-master": "com.saltstack.salt.master",
	"salt-api":    "com.saltstack.salt.api",
	"salt-syndic": "com.saltstack.salt.syndic",
}

var (
	serviceCaches  = map[*runtime.Runtime]map[string]map[string]any{}
	serviceCacheMu sync.Mutex
)

func registerMac(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		macShowFunc{}, macLaunchctlFunc{}, macListFunc{}, macEnableFunc{}, macDisableFunc{},
		macStartFunc{}, macStopFunc{}, macRestartFunc{}, macStatusFunc{}, macAvailableFunc{},
		macMissingFunc{}, macEnabledFunc{}, macDisabledFunc{}, macGetAllFunc{},
		macGetEnabledFunc{}, macLoadedFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

func parseServicePlist(data []byte) (map[string]any, error) {
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if start, ok := token.(xml.StartElement); ok && start.Name.Local == "dict" {
			value, err := parseServiceElement(decoder, start)
			if err != nil {
				return nil, err
			}
			result, ok := value.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("service plist root is not a dictionary")
			}
			return result, nil
		}
	}
}

func parseServiceElement(decoder *xml.Decoder, start xml.StartElement) (any, error) {
	switch start.Name.Local {
	case "dict":
		result := map[string]any{}
		key := ""
		for {
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			switch item := token.(type) {
			case xml.StartElement:
				if item.Name.Local == "key" {
					if err := decoder.DecodeElement(&key, &item); err != nil {
						return nil, err
					}
					continue
				}
				if key == "" {
					return nil, fmt.Errorf("service plist value has no key")
				}
				value, err := parseServiceElement(decoder, item)
				if err != nil {
					return nil, err
				}
				result[key] = value
				key = ""
			case xml.EndElement:
				if item.Name.Local == "dict" {
					return result, nil
				}
			}
		}
	case "array":
		var result []any
		for {
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			switch item := token.(type) {
			case xml.StartElement:
				value, err := parseServiceElement(decoder, item)
				if err != nil {
					return nil, err
				}
				result = append(result, value)
			case xml.EndElement:
				if item.Name.Local == "array" {
					return result, nil
				}
			}
		}
	case "string":
		var result string
		return result, decoder.DecodeElement(&result, &start)
	case "integer":
		var result string
		if err := decoder.DecodeElement(&result, &start); err != nil {
			return nil, err
		}
		value, err := strconv.ParseInt(strings.TrimSpace(result), 10, 64)
		return value, err
	case "true":
		if err := decoder.Skip(); err != nil {
			return nil, err
		}
		return true, nil
	case "false":
		if err := decoder.Skip(); err != nil {
			return nil, err
		}
		return false, nil
	default:
		if err := decoder.Skip(); err != nil && err != io.EOF {
			return nil, err
		}
		return nil, fmt.Errorf("unsupported service plist element <%s>", start.Name.Local)
	}
}

func serviceRoots(rt *runtime.Runtime) []string {
	roots := []string{
		"/Library/LaunchAgents", "/Library/LaunchDaemons",
		"/System/Library/LaunchAgents", "/System/Library/LaunchDaemons",
	}
	if entries, err := rt.FS.ReadDir("/Users"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				roots = append(roots, filepath.Join("/Users", entry.Name(), "Library/LaunchAgents"))
			}
		}
	}
	return roots
}

func walkServiceRoot(rt *runtime.Runtime, root string, services map[string]map[string]any) {
	entries, err := rt.FS.ReadDir(root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		if entry.IsDir() {
			walkServiceRoot(rt, path, services)
			continue
		}
		if !strings.HasSuffix(strings.ToLower(path), ".plist") {
			continue
		}
		data, err := rt.FS.ReadFile(path)
		if err != nil {
			continue
		}
		plist, err := parseServicePlist(data)
		if err != nil {
			continue
		}
		label, ok := plist["Label"].(string)
		if !ok || label == "" {
			continue
		}
		services[strings.ToLower(label)] = map[string]any{
			"file_name": entry.Name(), "file_path": path, "plist": plist,
		}
	}
}

func availableServices(rt *runtime.Runtime, refresh bool) map[string]map[string]any {
	serviceCacheMu.Lock()
	if !refresh {
		if cached := serviceCaches[rt]; cached != nil {
			serviceCacheMu.Unlock()
			return cached
		}
	}
	serviceCacheMu.Unlock()
	services := map[string]map[string]any{}
	for _, root := range serviceRoots(rt) {
		walkServiceRoot(rt, root, services)
	}
	serviceCacheMu.Lock()
	serviceCaches[rt] = services
	serviceCacheMu.Unlock()
	return services
}

func nameInServices(name string, services map[string]map[string]any) map[string]any {
	if value, ok := services[name]; ok {
		return value
	}
	for _, value := range services {
		path, _ := value["file_path"].(string)
		if strings.EqualFold(path, name) {
			return value
		}
		file, _ := value["file_name"].(string)
		base := strings.TrimSuffix(file, filepath.Ext(file))
		if strings.EqualFold(base, name) {
			return value
		}
	}
	return map[string]any{}
}

func getService(rt *runtime.Runtime, name string) (map[string]any, error) {
	if mapped, ok := saltMacServices[name]; ok {
		name = mapped
	}
	name = strings.ToLower(name)
	service := nameInServices(name, availableServices(rt, false))
	if len(service) == 0 {
		service = nameInServices(name, availableServices(rt, true))
	}
	if len(service) == 0 {
		return nil, fmt.Errorf("Service not found: %s", name)
	}
	return service, nil
}

func launchAgent(service map[string]any) bool {
	path, _ := service["file_path"].(string)
	return strings.Contains(path, "LaunchAgents")
}

func consoleUID(rt *runtime.Runtime) string {
	if rt != nil && rt.Exec != nil {
		if fn, ok := rt.Exec.Get("config.option"); ok {
			value, err := fn.Execute(context.Background(), rt, map[string]any{"key": "console_uid", "default": "0"})
			if err == nil && value != nil {
				return fmt.Sprint(value)
			}
		}
	}
	return "0"
}

func domainTarget(rt *runtime.Runtime, name string, full bool) (string, string, error) {
	service, err := getService(rt, name)
	if err != nil {
		return "", "", err
	}
	path := service["file_path"].(string)
	domain := "system"
	if launchAgent(service) {
		domain = "gui/" + consoleUID(rt)
	}
	if full {
		plist := service["plist"].(map[string]any)
		label, _ := plist["Label"].(string)
		domain += "/" + label
	}
	return domain, path, nil
}

func alwaysRunning(rt *runtime.Runtime, name string) bool {
	service, err := getService(rt, name)
	if err != nil {
		return false
	}
	plist, _ := service["plist"].(map[string]any)
	keepAlive, ok := plist["KeepAlive"]
	if !ok {
		return false
	}
	if value, ok := keepAlive.(bool); ok {
		return value
	}
	if values, ok := keepAlive.(map[string]any); ok {
		pathState, _ := values["PathState"].(map[string]any)
		for path, value := range pathState {
			on, _ := value.(bool)
			_, err := rt.FS.Stat(path)
			exists := err == nil
			if (on && exists) || (!on && !exists) {
				return true
			}
		}
	}
	return false
}

func launchctlImpl(ctx context.Context, rt *runtime.Runtime, sub string, args []string, returnStdout bool, runas *string) (any, error) {
	if runas != nil && *runas != "" {
		return nil, fmt.Errorf("runas is not supported by statekit")
	}
	argv := append([]string{"launchctl", sub}, args...)
	result := rt.Runner.Run(ctx, runtime.Command(argv...))
	ok := result.Err == nil && result.ExitCode == 0
	if sub == "bootout" && result.ExitCode == 36 && result.Err == nil {
		ok = true
	}
	if !ok {
		return nil, fmt.Errorf("Failed to %s service:\nstdout: %s\nstderr: %s\nretcode: %d", sub, result.Stdout, result.Stderr, result.ExitCode)
	}
	if returnStdout {
		return string(result.Stdout), nil
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// show/launchctl/list

type macShowArgs struct {
	Name string `statekit:"required"`
}
type macShowFunc struct{}

func (macShowFunc) Name() string        { return "service.show" }
func (macShowFunc) Args() any           { return macShowArgs{} }
func (macShowFunc) Platforms() []string { return []string{"darwin"} }
func (macShowFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacService(&res, &err)
	return getService(rt, args.(*macShowArgs).Name)
}

type macLaunchctlArgs struct {
	SubCmd       string   `statekit:"required,name=sub_cmd"`
	Args         []string `statekit:"name=args"`
	ReturnStdout bool     `statekit:"name=return_stdout"`
	Runas        *string  `statekit:"name=runas"`
}
type macLaunchctlFunc struct{}

func (macLaunchctlFunc) Name() string        { return "service.launchctl" }
func (macLaunchctlFunc) Args() any           { return macLaunchctlArgs{} }
func (macLaunchctlFunc) Platforms() []string { return []string{"darwin"} }
func (macLaunchctlFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacService(&res, &err)
	a := args.(*macLaunchctlArgs)
	return launchctlImpl(ctx, rt, a.SubCmd, a.Args, a.ReturnStdout, a.Runas)
}

type macListArgs struct {
	Name  *string `statekit:"name=name"`
	Runas *string `statekit:"name=runas"`
}
type macListFunc struct{}

func (macListFunc) Name() string        { return "service.list" }
func (macListFunc) Args() any           { return macListArgs{} }
func (macListFunc) Platforms() []string { return []string{"darwin"} }
func (macListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacService(&res, &err)
	a := args.(*macListArgs)
	if a.Name != nil && *a.Name != "" {
		service, e := getService(rt, *a.Name)
		if e != nil {
			return nil, e
		}
		label := service["plist"].(map[string]any)["Label"].(string)
		return launchctlImpl(ctx, rt, "list", []string{label}, true, a.Runas)
	}
	return launchctlImpl(ctx, rt, "list", nil, true, a.Runas)
}

// ---------------------------------------------------------------------------
// lifecycle

type macNameRunasArgs struct {
	Name  string  `statekit:"required"`
	Runas *string `statekit:"name=runas"`
}
type macEnableFunc struct{}
type macDisableFunc struct{}
type macStartFunc struct{}
type macStopFunc struct{}
type macRestartFunc struct{}

func (macEnableFunc) Name() string        { return "service.enable" }
func (macEnableFunc) Args() any           { return macNameRunasArgs{} }
func (macEnableFunc) Platforms() []string { return []string{"darwin"} }
func (macEnableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*macNameRunasArgs)
	domain, _, err := domainTarget(rt, a.Name, true)
	if err != nil {
		return nil, err
	}
	return launchctlImpl(ctx, rt, "enable", []string{domain}, false, a.Runas)
}
func (macDisableFunc) Name() string        { return "service.disable" }
func (macDisableFunc) Args() any           { return macNameRunasArgs{} }
func (macDisableFunc) Platforms() []string { return []string{"darwin"} }
func (macDisableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*macNameRunasArgs)
	domain, _, err := domainTarget(rt, a.Name, true)
	if err != nil {
		return nil, err
	}
	return launchctlImpl(ctx, rt, "disable", []string{domain}, false, a.Runas)
}
func (macStartFunc) Name() string        { return "service.start" }
func (macStartFunc) Args() any           { return macNameRunasArgs{} }
func (macStartFunc) Platforms() []string { return []string{"darwin"} }
func (macStartFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*macNameRunasArgs)
	domain, path, err := domainTarget(rt, a.Name, false)
	if err != nil {
		return nil, err
	}
	return launchctlImpl(ctx, rt, "bootstrap", []string{domain, path}, false, a.Runas)
}
func (macStopFunc) Name() string        { return "service.stop" }
func (macStopFunc) Args() any           { return macNameRunasArgs{} }
func (macStopFunc) Platforms() []string { return []string{"darwin"} }
func (macStopFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*macNameRunasArgs)
	domain, path, err := domainTarget(rt, a.Name, false)
	if err != nil {
		return nil, err
	}
	return launchctlImpl(ctx, rt, "bootout", []string{domain, path}, false, a.Runas)
}
func (macRestartFunc) Name() string        { return "service.restart" }
func (macRestartFunc) Args() any           { return macNameRunasArgs{} }
func (macRestartFunc) Platforms() []string { return []string{"darwin"} }
func (macRestartFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*macNameRunasArgs)
	loaded, _ := loadedImpl(ctx, rt, a.Name, a.Runas)
	if loaded {
		if _, err := (macStopFunc{}).Execute(ctx, rt, a); err != nil {
			return nil, err
		}
	}
	return macStartFunc{}.Execute(ctx, rt, a)
}

// ---------------------------------------------------------------------------
// status/availability

type macStatusArgs struct {
	Name  string  `statekit:"required"`
	Sig   *string `statekit:"name=sig"`
	Runas *string `statekit:"name=runas"`
}
type macStatusFunc struct{}

func (macStatusFunc) Name() string        { return "service.status" }
func (macStatusFunc) Args() any           { return macStatusArgs{} }
func (macStatusFunc) Platforms() []string { return []string{"darwin"} }
func (macStatusFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacService(&res, &err)
	a := args.(*macStatusArgs)
	if a.Sig != nil && *a.Sig != "" {
		return nil, fmt.Errorf("service.status sig lookup is not supported by statekit")
	}
	if _, e := getService(rt, a.Name); e != nil {
		return false, nil
	}
	output, e := macListFunc{}.Execute(ctx, rt, &macListArgs{Name: &a.Name, Runas: a.Runas})
	if e != nil {
		return false, nil
	}
	if alwaysRunning(rt, a.Name) {
		return strings.Contains(output.(string), `"PID" =`), nil
	}
	return true, nil
}

type macAvailableArgs struct {
	Name string `statekit:"required"`
}
type macAvailableFunc struct{}

func (macAvailableFunc) Name() string        { return "service.available" }
func (macAvailableFunc) Args() any           { return macAvailableArgs{} }
func (macAvailableFunc) Platforms() []string { return []string{"darwin"} }
func (macAvailableFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	_, err := getService(rt, args.(*macAvailableArgs).Name)
	return err == nil, nil
}

type macMissingFunc struct{}

func (macMissingFunc) Name() string        { return "service.missing" }
func (macMissingFunc) Args() any           { return macAvailableArgs{} }
func (macMissingFunc) Platforms() []string { return []string{"darwin"} }
func (macMissingFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	value, err := macAvailableFunc{}.Execute(ctx, rt, args)
	return !value.(bool), err
}

type macEnabledFunc struct{}

func (macEnabledFunc) Name() string        { return "service.enabled" }
func (macEnabledFunc) Args() any           { return macNameRunasArgs{} }
func (macEnabledFunc) Platforms() []string { return []string{"darwin"} }
func (macEnabledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*macNameRunasArgs)
	return disabledImpl(ctx, rt, a.Name, a.Runas).MapBool(func(v bool) bool { return !v })
}

type macDisabledFunc struct{}

func (macDisabledFunc) Name() string        { return "service.disabled" }
func (macDisabledFunc) Args() any           { return macNameRunasArgs{} }
func (macDisabledFunc) Platforms() []string { return []string{"darwin"} }
func (macDisabledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*macNameRunasArgs)
	return disabledImpl(ctx, rt, a.Name, a.Runas).MapBool(func(v bool) bool { return v })
}

type boolResult struct {
	value bool
	err   error
}

func (b boolResult) MapBool(fn func(bool) bool) (any, error) { return fn(b.value), b.err }
func disabledImpl(ctx context.Context, rt *runtime.Runtime, name string, runas *string) boolResult {
	domain, _, err := domainTarget(rt, name, true)
	if err != nil {
		return boolResult{err: err}
	}
	output, err := launchctlImpl(ctx, rt, "print-disabled", []string{domain}, true, runas)
	if err != nil {
		return boolResult{err: err}
	}
	for _, line := range strings.Split(output.(string), "\n") {
		if !strings.Contains(line, `"`+name+`"`) {
			continue
		}
		parts := strings.SplitN(line, "=>", 2)
		if len(parts) == 2 {
			state := strings.ToLower(parts[1])
			return boolResult{value: strings.Contains(state, "true") || strings.Contains(state, "disabled")}
		}
	}
	return boolResult{value: false}
}

// ---------------------------------------------------------------------------
// aggregate/listed state

type macGetAllArgs struct {
	Runas *string `statekit:"name=runas"`
}
type macGetAllFunc struct{}

func (macGetAllFunc) Name() string        { return "service.get_all" }
func (macGetAllFunc) Args() any           { return macGetAllArgs{} }
func (macGetAllFunc) Platforms() []string { return []string{"darwin"} }
func (macGetAllFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*macGetAllArgs)
	enabled, err := getEnabledImpl(ctx, rt, a.Runas)
	if err != nil {
		return nil, err
	}
	for label := range availableServices(rt, false) {
		enabled = append(enabled, label)
	}
	sort.Strings(enabled)
	return uniqueStrings(enabled), nil
}

type macGetEnabledArgs struct {
	Runas *string `statekit:"name=runas"`
}
type macGetEnabledFunc struct{}

func (macGetEnabledFunc) Name() string        { return "service.get_enabled" }
func (macGetEnabledFunc) Args() any           { return macGetEnabledArgs{} }
func (macGetEnabledFunc) Platforms() []string { return []string{"darwin"} }
func (macGetEnabledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return getEnabledImpl(ctx, rt, args.(*macGetEnabledArgs).Runas)
}
func getEnabledImpl(ctx context.Context, rt *runtime.Runtime, runas *string) ([]string, error) {
	output, err := launchctlImpl(ctx, rt, "list", nil, true, runas)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, line := range strings.Split(output.(string), "\n") {
		if strings.HasPrefix(line, "PID") || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) >= 3 {
			result = append(result, fields[2])
		}
	}
	return uniqueStrings(result), nil
}
func uniqueStrings(values []string) []string {
	set := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if !set[value] && value != "" {
			set[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

type macLoadedFunc struct{}

func (macLoadedFunc) Name() string        { return "service.loaded" }
func (macLoadedFunc) Args() any           { return macNameRunasArgs{} }
func (macLoadedFunc) Platforms() []string { return []string{"darwin"} }
func (macLoadedFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*macNameRunasArgs)
	return loadedImpl(ctx, rt, a.Name, a.Runas)
}
func loadedImpl(ctx context.Context, rt *runtime.Runtime, name string, runas *string) (bool, error) {
	value, err := macListFunc{}.Execute(ctx, rt, &macListArgs{Name: &name, Runas: runas})
	if err != nil {
		return false, nil
	}
	return value != nil, nil
}

func recoverMacService(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}
