// Package softwareupdate implements Salt's Darwin softwareupdate module.
// The command is reached through the central Runner and its human-readable
// update-list output is parsed without requiring macOS during tests.
package softwareupdate

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

func run(ctx context.Context, rt *runtime.Runtime, argv ...string) (string, int, error) {
	result := rt.Runner.Run(ctx, runtime.Command(argv...))
	if result.Err != nil && result.ExitCode == -1 {
		return string(result.Stdout), result.ExitCode, result.Err
	}
	return string(result.Stdout), result.ExitCode, nil
}

func runSuccess(ctx context.Context, rt *runtime.Runtime, argv ...string) error {
	stdout, code, err := run(ctx, rt, argv...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%s exited with code %d: %s", argv[0], code, stdout)
	}
	return nil
}

func darwinVersionModern(rt *runtime.Runtime) bool {
	if rt == nil || rt.Facts == nil {
		return true
	}
	parts := strings.SplitN(rt.Facts.OS().Version, ".", 3)
	if len(parts) < 2 {
		return true
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return true
	}
	return major > 10 || (major == 10 && minor >= 15)
}

var (
	modernLabel = regexp.MustCompile(`^\s*[*-] Label: ([^\r\n]+)\s*$`)
	modernVer   = regexp.MustCompile(`Version: ([^,]+),`)
	oldMarker   = regexp.MustCompile(`^\s+[*-] (.+)\s*$`)
	oldVer      = regexp.MustCompile(`\(([^ )]+)\)`)
)

func availableUpdates(rt *runtime.Runtime, recommended, restart, shutDown bool, ctx context.Context) map[string]string {
	out, _, _ := run(ctx, rt, "softwareupdate", "--list")
	if darwinVersionModern(rt) {
		return parseModern(out, recommended, restart, shutDown)
	}
	return parseLegacy(out, recommended, restart, shutDown)
}

func includeUpdate(recommended, restart, shutDown bool, isRecommended, needsRestart, needsShutdown bool) bool {
	if recommended && !isRecommended {
		return false
	}
	if restart && !needsRestart {
		return false
	}
	if shutDown && !needsShutdown {
		return false
	}
	return true
}

func parseModern(out string, recommended, restart, shutDown bool) map[string]string {
	updates := map[string]string{}
	name := ""
	version := ""
	isRecommended, needsRestart, needsShutdown := false, false, false
	flush := func() {
		if name != "" && version != "" && includeUpdate(recommended, restart, shutDown, isRecommended, needsRestart, needsShutdown) {
			updates[name] = version
		}
		name, version = "", ""
		isRecommended, needsRestart, needsShutdown = false, false, false
	}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if match := modernLabel.FindStringSubmatch(line); match != nil {
			flush()
			name = match[1]
			continue
		}
		if name == "" {
			continue
		}
		if match := modernVer.FindStringSubmatch(line); match != nil {
			version = strings.TrimSpace(match[1])
		}
		if strings.Contains(line, "Recommended: YES") {
			isRecommended = true
		}
		if strings.Contains(line, "Action: restart") {
			needsRestart = true
		}
		if strings.Contains(line, "Action: shut down") {
			needsShutdown = true
		}
	}
	flush()
	return updates
}

func parseLegacy(out string, recommended, restart, shutDown bool) map[string]string {
	updates := map[string]string{}
	name := ""
	isRecommended, needsRestart, needsShutdown := false, false, false
	flush := func(version string) {
		if name != "" && version != "" && includeUpdate(recommended, restart, shutDown, isRecommended, needsRestart, needsShutdown) {
			updates[name] = version
		}
		name = ""
		isRecommended, needsRestart, needsShutdown = false, false, false
	}
	lines := strings.Split(out, "\n")
	for index, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")
		if match := oldMarker.FindStringSubmatch(line); match != nil {
			if name != "" {
				flush("")
			}
			name = strings.TrimSpace(match[1])
			if index+1 < len(lines) {
				next := lines[index+1]
				if match := oldVer.FindStringSubmatch(next); match != nil {
					isRecommended = strings.Contains(next, "[recommended]")
					needsRestart = strings.Contains(next, "[restart]")
					needsShutdown = strings.Contains(next, "[shut down]")
					flush(strings.TrimSpace(match[1]))
				}
			}
		}
	}
	return updates
}

func ignoredUpdates(ctx context.Context, rt *runtime.Runtime) []string {
	out, _, _ := run(ctx, rt, "softwareupdate", "--list", "--ignore")
	var result []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		line = strings.Trim(line, `",`)
		if line == "" || strings.Contains(line, "Software Update") || strings.Contains(line, "Finding ") {
			continue
		}
		result = append(result, line)
	}
	return result
}

func enabledValue(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "yes", "true", "1":
		return "on", nil
	case "off", "no", "false", "0":
		return "off", nil
	default:
		return "", fmt.Errorf("Invalid value for enabled: %s", value)
	}
}

func availableDownloads(rt *runtime.Runtime, updates map[string]string) []string {
	var files []string
	var walk func(string)
	walk = func(path string) {
		entries, err := rt.FS.ReadDir(path)
		if err != nil {
			return
		}
		for _, entry := range entries {
			child := filepath.Join(path, entry.Name())
			if entry.IsDir() {
				walk(child)
				continue
			}
			if strings.HasSuffix(entry.Name(), ".dist") {
				files = append(files, child)
			}
		}
	}
	walk("/Library/Updates")
	var result []string
	for update := range updates {
		prefix := strings.TrimSuffix(update, "")
		if index := strings.LastIndex(prefix, "-"); index >= 0 {
			prefix = prefix[:index]
		}
		for _, file := range files {
			data, err := rt.FS.ReadFile(file)
			if err == nil && strings.Contains(string(data), prefix) {
				result = append(result, update)
				break
			}
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// list_available / ignore / ignored

type listAvailableArgs struct {
	Recommended bool `statekit:"name=recommended"`
	Restart     bool `statekit:"name=restart"`
	ShutDown    bool `statekit:"name=shut_down"`
}
type listAvailableFunc struct{}

func (listAvailableFunc) Name() string        { return "softwareupdate.list_available" }
func (listAvailableFunc) Args() any           { return listAvailableArgs{} }
func (listAvailableFunc) Platforms() []string { return []string{"darwin"} }
func (listAvailableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSoftwareUpdate(&res, &err)
	a := args.(*listAvailableArgs)
	return availableUpdates(rt, a.Recommended, a.Restart, a.ShutDown, ctx), nil
}

type ignoreArgs struct {
	Name string `statekit:"required"`
}
type ignoreFunc struct{}

func (ignoreFunc) Name() string        { return "softwareupdate.ignore" }
func (ignoreFunc) Args() any           { return ignoreArgs{} }
func (ignoreFunc) Platforms() []string { return []string{"darwin"} }
func (ignoreFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSoftwareUpdate(&res, &err)
	a := args.(*ignoreArgs)
	toIgnore := a.Name
	if index := strings.LastIndex(toIgnore, "-"); index >= 0 {
		toIgnore = toIgnore[:index]
	}
	if err := runSuccess(ctx, rt, "softwareupdate", "--ignore", toIgnore); err != nil {
		return nil, err
	}
	for _, name := range ignoredUpdates(ctx, rt) {
		if name == toIgnore {
			return true, nil
		}
	}
	return false, nil
}

type listIgnoredArgs struct{}
type listIgnoredFunc struct{}

func (listIgnoredFunc) Name() string        { return "softwareupdate.list_ignored" }
func (listIgnoredFunc) Args() any           { return listIgnoredArgs{} }
func (listIgnoredFunc) Platforms() []string { return []string{"darwin"} }
func (listIgnoredFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverSoftwareUpdate(&res, &err)
	return ignoredUpdates(ctx, rt), nil
}

type resetIgnoredArgs struct{}
type resetIgnoredFunc struct{}

func (resetIgnoredFunc) Name() string        { return "softwareupdate.reset_ignored" }
func (resetIgnoredFunc) Args() any           { return resetIgnoredArgs{} }
func (resetIgnoredFunc) Platforms() []string { return []string{"darwin"} }
func (resetIgnoredFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverSoftwareUpdate(&res, &err)
	if err := runSuccess(ctx, rt, "softwareupdate", "--reset-ignored"); err != nil {
		return nil, err
	}
	return len(ignoredUpdates(ctx, rt)) == 0, nil
}

// ---------------------------------------------------------------------------
// schedule

type scheduleEnabledArgs struct{}
type scheduleEnabledFunc struct{}

func (scheduleEnabledFunc) Name() string        { return "softwareupdate.schedule_enabled" }
func (scheduleEnabledFunc) Args() any           { return scheduleEnabledArgs{} }
func (scheduleEnabledFunc) Platforms() []string { return []string{"darwin"} }
func (scheduleEnabledFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverSoftwareUpdate(&res, &err)
	out, _, runErr := run(ctx, rt, "softwareupdate", "--schedule")
	if runErr != nil {
		return nil, runErr
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return false, nil
	}
	value, verr := enabledValue(fields[len(fields)-1])
	if verr != nil {
		return false, nil
	}
	return value == "on", nil
}

type scheduleEnableArgs struct {
	Enable string `statekit:"required,name=enable"`
}
type scheduleEnableFunc struct{}

func (scheduleEnableFunc) Name() string        { return "softwareupdate.schedule_enable" }
func (scheduleEnableFunc) Args() any           { return scheduleEnableArgs{} }
func (scheduleEnableFunc) Platforms() []string { return []string{"darwin"} }
func (scheduleEnableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSoftwareUpdate(&res, &err)
	a := args.(*scheduleEnableArgs)
	if strings.TrimSpace(a.Enable) == "" {
		return scheduleEnabledFunc{}.Execute(ctx, rt, scheduleEnabledArgs{})
	}
	status, err := enabledValue(a.Enable)
	if err != nil {
		return nil, err
	}
	if err := runSuccess(ctx, rt, "softwareupdate", "--schedule", status); err != nil {
		return nil, err
	}
	enabled, err := scheduleEnabledFunc{}.Execute(ctx, rt, scheduleEnabledArgs{})
	if err != nil {
		return nil, err
	}
	return enabled == (status == "on"), nil
}

// ---------------------------------------------------------------------------
// install/download/update flows

type updateAllArgs struct {
	Recommended bool  `statekit:"name=recommended"`
	Restart     *bool `statekit:"name=restart"`
}
type updateAllFunc struct{}

func (updateAllFunc) Name() string        { return "softwareupdate.update_all" }
func (updateAllFunc) Args() any           { return updateAllArgs{} }
func (updateAllFunc) Platforms() []string { return []string{"darwin"} }
func (updateAllFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSoftwareUpdate(&res, &err)
	a := args.(*updateAllArgs)
	restart := true
	if a.Restart != nil {
		restart = *a.Restart
	}
	toUpdate := availableUpdates(rt, a.Recommended, restart, false, ctx)
	if len(toUpdate) == 0 {
		return map[string]any{}, nil
	}
	for name := range toUpdate {
		_ = runSuccess(ctx, rt, "softwareupdate", "--install", name)
	}
	left := availableUpdates(rt, false, false, false, ctx)
	result := map[string]bool{}
	for name := range toUpdate {
		_, result[name] = left[name]
		result[name] = !result[name]
	}
	return result, nil
}

type updateArgs struct {
	Name string `statekit:"required"`
}
type updateFunc struct{}

func (updateFunc) Name() string        { return "softwareupdate.update" }
func (updateFunc) Args() any           { return updateArgs{} }
func (updateFunc) Platforms() []string { return []string{"darwin"} }
func (updateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSoftwareUpdate(&res, &err)
	a := args.(*updateArgs)
	if available, _ := (updateAvailableFunc{}).Execute(ctx, rt, &updateAvailableArgs{Name: a.Name}); available != true {
		return nil, fmt.Errorf("Update not available: %s", a.Name)
	}
	if err := runSuccess(ctx, rt, "softwareupdate", "--install", a.Name); err != nil {
		return nil, err
	}
	available, err := updateAvailableFunc{}.Execute(ctx, rt, &updateAvailableArgs{Name: a.Name})
	if err != nil {
		return nil, err
	}
	return available != true, nil
}

type updateAvailableArgs struct {
	Name string `statekit:"required"`
}
type updateAvailableFunc struct{}

func (updateAvailableFunc) Name() string        { return "softwareupdate.update_available" }
func (updateAvailableFunc) Args() any           { return updateAvailableArgs{} }
func (updateAvailableFunc) Platforms() []string { return []string{"darwin"} }
func (updateAvailableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSoftwareUpdate(&res, &err)
	a := args.(*updateAvailableArgs)
	updates := availableUpdates(rt, false, false, false, ctx)
	_, ok := updates[a.Name]
	return ok, nil
}

type listDownloadsArgs struct{}
type listDownloadsFunc struct{}

func (listDownloadsFunc) Name() string        { return "softwareupdate.list_downloads" }
func (listDownloadsFunc) Args() any           { return listDownloadsArgs{} }
func (listDownloadsFunc) Platforms() []string { return []string{"darwin"} }
func (listDownloadsFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverSoftwareUpdate(&res, &err)
	return availableDownloads(rt, availableUpdates(rt, false, false, false, ctx)), nil
}

type downloadArgs struct {
	Name string `statekit:"required"`
}
type downloadFunc struct{}

func (downloadFunc) Name() string        { return "softwareupdate.download" }
func (downloadFunc) Args() any           { return downloadArgs{} }
func (downloadFunc) Platforms() []string { return []string{"darwin"} }
func (downloadFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSoftwareUpdate(&res, &err)
	a := args.(*downloadArgs)
	available, _ := updateAvailableFunc{}.Execute(ctx, rt, &updateAvailableArgs{Name: a.Name})
	if available != true {
		return nil, fmt.Errorf("Update not available: %s", a.Name)
	}
	downloaded, _ := listDownloadsFunc{}.Execute(ctx, rt, listDownloadsArgs{})
	for _, item := range downloaded.([]string) {
		if item == a.Name {
			return true, nil
		}
	}
	if err := runSuccess(ctx, rt, "softwareupdate", "--download", a.Name); err != nil {
		return nil, err
	}
	downloaded, err = listDownloadsFunc{}.Execute(ctx, rt, listDownloadsArgs{})
	if err != nil {
		return nil, err
	}
	for _, item := range downloaded.([]string) {
		if item == a.Name {
			return true, nil
		}
	}
	return false, nil
}

type downloadAllArgs struct {
	Recommended bool  `statekit:"name=recommended"`
	Restart     *bool `statekit:"name=restart"`
}
type downloadAllFunc struct{}

func (downloadAllFunc) Name() string        { return "softwareupdate.download_all" }
func (downloadAllFunc) Args() any           { return downloadAllArgs{} }
func (downloadAllFunc) Platforms() []string { return []string{"darwin"} }
func (downloadAllFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSoftwareUpdate(&res, &err)
	a := args.(*downloadAllArgs)
	restart := true
	if a.Restart != nil {
		restart = *a.Restart
	}
	toDownload := availableUpdates(rt, a.Recommended, restart, false, ctx)
	for name := range toDownload {
		_, _ = downloadFunc{}.Execute(ctx, rt, &downloadArgs{Name: name})
	}
	return listDownloadsFunc{}.Execute(ctx, rt, listDownloadsArgs{})
}

// ---------------------------------------------------------------------------
// catalog

type getCatalogArgs struct{}
type getCatalogFunc struct{}

func (getCatalogFunc) Name() string        { return "softwareupdate.get_catalog" }
func (getCatalogFunc) Args() any           { return getCatalogArgs{} }
func (getCatalogFunc) Platforms() []string { return []string{"darwin"} }
func (getCatalogFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverSoftwareUpdate(&res, &err)
	out, _, runErr := run(ctx, rt, "defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate.plist")
	if runErr != nil {
		return nil, runErr
	}
	if strings.Contains(out, "AppleCatalogURL") {
		value, _, err := run(ctx, rt, "defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate.plist", "AppleCatalogURL")
		return strings.TrimSpace(value), err
	}
	if strings.Contains(out, "CatalogURL") {
		value, _, err := run(ctx, rt, "defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate.plist", "CatalogURL")
		return strings.TrimSpace(value), err
	}
	return "Default", nil
}

type setCatalogArgs struct {
	URL string `statekit:"required,name=url"`
}
type setCatalogFunc struct{}

func (setCatalogFunc) Name() string        { return "softwareupdate.set_catalog" }
func (setCatalogFunc) Args() any           { return setCatalogArgs{} }
func (setCatalogFunc) Platforms() []string { return []string{"darwin"} }
func (setCatalogFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSoftwareUpdate(&res, &err)
	a := args.(*setCatalogArgs)
	_, _, _ = run(ctx, rt, "softwareupdate", "--set-catalog", a.URL)
	current, err := getCatalogFunc{}.Execute(ctx, rt, getCatalogArgs{})
	return current == a.URL, err
}

type resetCatalogArgs struct{}
type resetCatalogFunc struct{}

func (resetCatalogFunc) Name() string        { return "softwareupdate.reset_catalog" }
func (resetCatalogFunc) Args() any           { return resetCatalogArgs{} }
func (resetCatalogFunc) Platforms() []string { return []string{"darwin"} }
func (resetCatalogFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverSoftwareUpdate(&res, &err)
	_, _, _ = run(ctx, rt, "softwareupdate", "--clear-catalog")
	current, err := getCatalogFunc{}.Execute(ctx, rt, getCatalogArgs{})
	return current == "Default", err
}

func recoverSoftwareUpdate(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}

// Register installs the Darwin softwareupdate public surface.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		listAvailableFunc{}, ignoreFunc{}, listIgnoredFunc{}, resetIgnoredFunc{},
		scheduleEnabledFunc{}, scheduleEnableFunc{}, updateAllFunc{}, updateFunc{},
		updateAvailableFunc{}, listDownloadsFunc{}, downloadFunc{}, downloadAllFunc{},
		getCatalogFunc{}, setCatalogFunc{}, resetCatalogFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
