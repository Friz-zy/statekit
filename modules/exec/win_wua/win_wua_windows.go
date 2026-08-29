//go:build windows

// Package win_wua implements Salt's Windows Update Agent surface through
// encoded PowerShell COM calls. Update search and mutation stay behind Runner;
// no network client or implicit reboot is added to StateKit.
package win_wua

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func wuaLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
func wuaPS(script string) process.Command {
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
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], u)
	}
	return process.Command{Name: "powershell.exe", Args: []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw)}}
}
func wuaRun(ctx context.Context, rt *runtime.Runtime, script string) (string, error) {
	r := rt.Runner.Run(ctx, wuaPS(script))
	if r.Err != nil && r.ExitCode == -1 {
		return string(r.Stdout), r.Err
	}
	if r.ExitCode != 0 {
		return string(r.Stdout), fmt.Errorf("Windows Update command failed (exit code %d): %s", r.ExitCode, strings.TrimSpace(string(r.Stderr)))
	}
	return string(r.Stdout), nil
}
func wuaJSON(ctx context.Context, rt *runtime.Runtime, script string) (any, error) {
	out, e := wuaRun(ctx, rt, script+" | ConvertTo-Json -Compress -Depth 8")
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
func wuaRows(value any) []map[string]any {
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
func wuaNames(value any) []string {
	switch x := value.(type) {
	case string:
		return []string{x}
	case []string:
		return x
	case []any:
		out := []string{}
		for _, v := range x {
			out = append(out, fmt.Sprint(v))
		}
		return out
	default:
		return []string{}
	}
}

const wuaUpdateProjection = `ForEach-Object { [ordered]@{Title=$_.Title;KBs=@($_.KBArticleIDs);GUID=$_.Identity.UpdateID;Description=$_.Description;Downloaded=$_.IsDownloaded;Installed=$_.IsInstalled;Mandatory=$_.IsMandatory;UserInput=$_.InstallationBehavior.CanRequestUserInput;EULAAccepted=$_.EulaAccepted;Severity=$_.MsrcSeverity;NeedsReboot=$false;RebootBehavior=$_.InstallationBehavior.RebootBehavior;Categories=@($_.Categories | ForEach-Object {$_.Name})} }`

func wuaSearchScript(criteria string, online bool) string {
	onlineValue := "$false"
	if online {
		onlineValue = "$true"
	}
	return "$s=New-Object -ComObject Microsoft.Update.Session;$q=$s.CreateUpdateSearcher();$q.Online=" + onlineValue + ";$r=$q.Search(" + wuaLiteral(criteria) + ");@($r.Updates | " + wuaUpdateProjection + ")"
}
func wuaUpdateMap(value any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, row := range wuaRows(value) {
		guid := fmt.Sprint(row["GUID"])
		if guid != "" {
			out[guid] = row
		}
	}
	return out
}
func wuaCriteria(skipInstalled bool, skipHidden bool) string {
	parts := []string{}
	if skipInstalled {
		parts = append(parts, "IsInstalled=0")
	}
	if skipHidden {
		parts = append(parts, "IsHidden=0")
	}
	if len(parts) == 0 {
		return "1=1"
	}
	return strings.Join(parts, " and ")
}
func wuaFilter(updates map[string]map[string]any, categories, severities []string) map[string]map[string]any {
	if len(categories) == 0 && len(severities) == 0 {
		return updates
	}
	wantCat, wantSev := map[string]bool{}, map[string]bool{}
	for _, v := range categories {
		wantCat[strings.ToLower(v)] = true
	}
	for _, v := range severities {
		wantSev[strings.ToLower(v)] = true
	}
	out := map[string]map[string]any{}
	for guid, row := range updates {
		ok := true
		if len(wantCat) > 0 {
			ok = false
			for _, v := range wuaNames(row["Categories"]) {
				if wantCat[strings.ToLower(v)] {
					ok = true
				}
			}
		}
		if ok && len(wantSev) > 0 {
			ok = wantSev[strings.ToLower(fmt.Sprint(row["Severity"]))]
		}
		if ok {
			out[guid] = row
		}
	}
	return out
}
func wuaSummary(updates map[string]map[string]any) map[string]any {
	categories := map[string]int{}
	available, downloaded, installed := 0, 0, 0
	for _, row := range updates {
		if row["Installed"] == true {
			installed++
		} else if row["Downloaded"] == true {
			downloaded++
		} else {
			available++
		}
		for _, cat := range wuaNames(row["Categories"]) {
			categories[cat]++
		}
	}
	return map[string]any{"Total": len(updates), "Available": available, "Downloaded": downloaded, "Installed": installed, "Categories": categories}
}

// ---------------------------------------------------------------------------

type availableArgs struct {
	Software      *bool    `statekit:"name=software"`
	Drivers       *bool    `statekit:"name=drivers"`
	Summary       *bool    `statekit:"name=summary"`
	SkipInstalled *bool    `statekit:"name=skip_installed"`
	SkipHidden    *bool    `statekit:"name=skip_hidden"`
	SkipMandatory *bool    `statekit:"name=skip_mandatory"`
	SkipReboot    *bool    `statekit:"name=skip_reboot"`
	Categories    []string `statekit:"name=categories"`
	Severities    []string `statekit:"name=severities"`
	Online        *bool    `statekit:"name=online"`
}
type availableFunc struct{}

func (availableFunc) Name() string        { return "win_wua.available" }
func (availableFunc) Args() any           { return availableArgs{} }
func (availableFunc) Platforms() []string { return []string{"windows"} }
func (availableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWUA(&res, &err)
	a := args.(*availableArgs)
	skipInstalled, skipHidden, online := true, true, true
	if a.SkipInstalled != nil {
		skipInstalled = *a.SkipInstalled
	}
	if a.SkipHidden != nil {
		skipHidden = *a.SkipHidden
	}
	if a.Online != nil {
		online = *a.Online
	}
	value, e := wuaJSON(ctx, rt, wuaSearchScript(wuaCriteria(skipInstalled, skipHidden), online))
	if e != nil {
		return nil, e
	}
	updates := wuaFilter(wuaUpdateMap(value), a.Categories, a.Severities)
	if a.Summary != nil && *a.Summary {
		return wuaSummary(updates), nil
	}
	return updates, nil
}

type getArgs struct {
	Name     string `statekit:"required"`
	Download bool   `statekit:"name=download"`
	Install  bool   `statekit:"name=install"`
	Online   *bool  `statekit:"name=online"`
}
type getFunc struct{}

func (getFunc) Name() string        { return "win_wua.get" }
func (getFunc) Args() any           { return getArgs{} }
func (getFunc) Platforms() []string { return []string{"windows"} }
func (getFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWUA(&res, &err)
	a := args.(*getArgs)
	online := true
	if a.Online != nil {
		online = *a.Online
	}
	value, e := wuaJSON(ctx, rt, wuaSearchScript("IsInstalled=0", online))
	if e != nil {
		return nil, e
	}
	updates := wuaUpdateMap(value)
	filtered := map[string]map[string]any{}
	needle := strings.ToLower(a.Name)
	for guid, row := range updates {
		if strings.Contains(strings.ToLower(guid), needle) || strings.Contains(strings.ToLower(fmt.Sprint(row["Title"])), needle) {
			for _, kb := range wuaNames(row["KBs"]) {
				if strings.Contains(strings.ToLower(kb), needle) {
					filtered[guid] = row
				}
			}
			if _, ok := filtered[guid]; !ok {
				filtered[guid] = row
			}
		}
	}
	if !a.Download && !a.Install {
		return filtered, nil
	}
	result := map[string]any{}
	download, actionErr := wuaAction(ctx, rt, a.Name, false)
	if actionErr != nil {
		return nil, actionErr
	}
	result["Download"] = download
	if a.Install {
		install, actionErr := wuaAction(ctx, rt, a.Name, true)
		if actionErr != nil {
			return nil, actionErr
		}
		result["Install"] = install
	}
	return result, nil
}

type listArgs struct {
	Software      *bool    `statekit:"name=software"`
	Drivers       *bool    `statekit:"name=drivers"`
	Summary       *bool    `statekit:"name=summary"`
	SkipInstalled *bool    `statekit:"name=skip_installed"`
	Categories    []string `statekit:"name=categories"`
	Severities    []string `statekit:"name=severities"`
	Download      bool     `statekit:"name=download"`
	Install       bool     `statekit:"name=install"`
	Online        *bool    `statekit:"name=online"`
}
type listFunc struct{}

func (listFunc) Name() string        { return "win_wua.list" }
func (listFunc) Args() any           { return listArgs{} }
func (listFunc) Platforms() []string { return []string{"windows"} }
func (listFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWUA(&res, &err)
	a := args.(*listArgs)
	if a.Download || a.Install {
		result := map[string]any{}
		download, actionErr := wuaAction(ctx, rt, "", false)
		if actionErr != nil {
			return nil, actionErr
		}
		result["Download"] = download
		if a.Install {
			install, actionErr := wuaAction(ctx, rt, "", true)
			if actionErr != nil {
				return nil, actionErr
			}
			result["Install"] = install
		}
		return result, nil
	}
	return availableFunc{}.Execute(ctx, rt, &availableArgs{Summary: a.Summary, SkipInstalled: a.SkipInstalled, Categories: a.Categories, Severities: a.Severities, Online: a.Online})
}

type installedArgs struct {
	Summary bool `statekit:"name=summary"`
	KBsOnly bool `statekit:"name=kbs_only"`
}
type installedFunc struct{}

func (installedFunc) Name() string        { return "win_wua.installed" }
func (installedFunc) Args() any           { return installedArgs{} }
func (installedFunc) Platforms() []string { return []string{"windows"} }
func (installedFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWUA(&res, &err)
	a := args.(*installedArgs)
	value, e := wuaJSON(ctx, rt, wuaSearchScript("IsInstalled=1", false))
	if e != nil {
		return nil, e
	}
	updates := wuaUpdateMap(value)
	if a.KBsOnly {
		set := map[string]bool{}
		for _, row := range updates {
			for _, kb := range wuaNames(row["KBs"]) {
				set[kb] = true
			}
		}
		out := []string{}
		for kb := range set {
			out = append(out, kb)
		}
		sort.Strings(out)
		return out, nil
	}
	if a.Summary {
		return wuaSummary(updates), nil
	}
	return updates, nil
}

func wuaAction(ctx context.Context, rt *runtime.Runtime, name string, install bool) (any, error) {
	names := []string{}
	if name != "" {
		for _, value := range strings.Split(name, ",") {
			if value = strings.TrimSpace(value); value != "" {
				names = append(names, value)
			}
		}
	}
	encoded := []string{}
	for _, v := range names {
		encoded = append(encoded, wuaLiteral(v))
	}
	selector := "$names=@(" + strings.Join(encoded, ",") + ");$s=New-Object -ComObject Microsoft.Update.Session;$q=$s.CreateUpdateSearcher();$r=$q.Search('IsInstalled=0 and IsHidden=0');$c=New-Object -ComObject Microsoft.Update.UpdateColl;foreach($u in $r.Updates){$hit=($names.Count -eq 0);foreach($n in $names){if($u.Identity.UpdateID -like \"*$n*\" -or $u.Title -like \"*$n*\" -or @($u.KBArticleIDs) -contains $n){$hit=$true}};if($hit){[void]$c.Add($u)}};if($c.Count -eq 0){throw 'No updates found'};"
	if install {
		selector += "$i=$s.CreateUpdateInstaller();$i.Updates=$c;$r=$i.Install();$r | Select-Object ResultCode,RebootRequired,Updates"
	} else {
		selector += "$d=$s.CreateUpdateDownloader();$d.Updates=$c;$r=$d.Download();$r | Select-Object ResultCode,Updates"
	}
	return wuaJSON(ctx, rt, selector)
}

func wuaUninstallAction(ctx context.Context, rt *runtime.Runtime, name string) (any, error) {
	names := []string{}
	for _, value := range strings.Split(name, ",") {
		if value = strings.TrimSpace(value); value != "" {
			names = append(names, value)
		}
	}
	literals := make([]string, 0, len(names))
	for _, value := range names {
		literals = append(literals, wuaLiteral(value))
	}
	script := "$names=@(" + strings.Join(literals, ",") + ");$s=New-Object -ComObject Microsoft.Update.Session;$q=$s.CreateUpdateSearcher();$r=$q.Search('IsInstalled=1');$c=New-Object -ComObject Microsoft.Update.UpdateColl;foreach($u in $r.Updates){$hit=($names.Count -eq 0);foreach($n in $names){if($u.Identity.UpdateID -like \"*$n*\" -or $u.Title -like \"*$n*\" -or @($u.KBArticleIDs) -contains $n){$hit=$true}};if($hit){[void]$c.Add($u)}};if($c.Count -eq 0){throw 'No updates found'};$i=$s.CreateUpdateInstaller();$i.Updates=$c;$result=$i.Uninstall();$result | Select-Object ResultCode,RebootRequired,Updates"
	return wuaJSON(ctx, rt, script)
}

type namesArgs struct {
	Names any `statekit:"required"`
}
type downloadFunc struct{}
type installFunc struct{}
type uninstallFunc struct{}

func (downloadFunc) Name() string        { return "win_wua.download" }
func (downloadFunc) Args() any           { return namesArgs{} }
func (downloadFunc) Platforms() []string { return []string{"windows"} }
func (downloadFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return wuaAction(ctx, rt, strings.Join(wuaNames(args.(*namesArgs).Names), ","), false)
}
func (installFunc) Name() string        { return "win_wua.install" }
func (installFunc) Args() any           { return namesArgs{} }
func (installFunc) Platforms() []string { return []string{"windows"} }
func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return wuaAction(ctx, rt, strings.Join(wuaNames(args.(*namesArgs).Names), ","), true)
}
func (uninstallFunc) Name() string        { return "win_wua.uninstall" }
func (uninstallFunc) Args() any           { return namesArgs{} }
func (uninstallFunc) Platforms() []string { return []string{"windows"} }
func (uninstallFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return wuaUninstallAction(ctx, rt, strings.Join(wuaNames(args.(*namesArgs).Names), ","))
}

// ---------------------------------------------------------------------------
// AutoUpdate settings and reboot state

type settingsArgs struct {
	Level       *int    `statekit:"name=level"`
	Recommended *bool   `statekit:"name=recommended"`
	Featured    *bool   `statekit:"name=featured"`
	Elevated    *bool   `statekit:"name=elevated"`
	MSUpdate    *bool   `statekit:"name=msupdate"`
	Day         *string `statekit:"name=day"`
	Time        *string `statekit:"name=time"`
}
type setSettingsFunc struct{}

func (setSettingsFunc) Name() string        { return "win_wua.set_wu_settings" }
func (setSettingsFunc) Args() any           { return settingsArgs{} }
func (setSettingsFunc) Platforms() []string { return []string{"windows"} }
func (setSettingsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWUA(&res, &err)
	a := args.(*settingsArgs)
	out := map[string]any{"Success": true}
	if a.Level != nil && (*a.Level < 1 || *a.Level > 4) {
		return map[string]any{"Success": false, "Comment": "Level needs to be between 1 and 4"}, nil
	}
	if a.Day != nil {
		valid := map[string]bool{"Everyday": true, "Sunday": true, "Monday": true, "Tuesday": true, "Wednesday": true, "Thursday": true, "Friday": true, "Saturday": true}
		if !valid[*a.Day] {
			return map[string]any{"Success": false, "Comment": "Day needs to be one of the following: Everyday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday"}, nil
		}
	}
	if a.Time != nil && !strings.Contains(*a.Time, ":") {
		return map[string]any{"Success": false, "Comment": "Time argument needs to be in 00:00 format"}, nil
	}
	script := "$s=(New-Object -ComObject Microsoft.Update.AutoUpdate).Settings;"
	if a.Level != nil {
		script += fmt.Sprintf("$s.NotificationLevel=%d;", *a.Level)
	}
	if a.Recommended != nil {
		script += fmt.Sprintf("$s.IncludeRecommendedUpdates=%v;", *a.Recommended)
	}
	if a.Featured != nil {
		script += fmt.Sprintf("$s.FeaturedUpdatesEnabled=%v;", *a.Featured)
	}
	if a.Elevated != nil {
		script += fmt.Sprintf("$s.NonAdministratorsElevated=%v;", *a.Elevated)
	}
	if script != "$s=(New-Object -ComObject Microsoft.Update.AutoUpdate).Settings;" {
		script += "$s.Save()"
		if _, e := wuaRun(ctx, rt, script); e != nil {
			return map[string]any{"Success": false, "Comment": e.Error()}, nil
		}
	}
	if a.Level != nil {
		out["Level"] = *a.Level
	}
	if a.Recommended != nil {
		out["Recommended"] = *a.Recommended
	}
	if a.Featured != nil {
		out["Featured"] = *a.Featured
	}
	if a.Elevated != nil {
		out["Elevated"] = *a.Elevated
	}
	out["Reboot"] = false
	return out, nil
}

type getSettingsFunc struct{}

func (getSettingsFunc) Name() string        { return "win_wua.get_wu_settings" }
func (getSettingsFunc) Args() any           { return noArgsWUA{} }
func (getSettingsFunc) Platforms() []string { return []string{"windows"} }
func (getSettingsFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverWUA(&res, &err)
	script := "$s=(New-Object -ComObject Microsoft.Update.AutoUpdate).Settings;[ordered]@{'Featured Updates'=$s.FeaturedUpdatesEnabled;'Group Policy Required'=$s.Required;'Microsoft Update'=$false;'Needs Reboot'=$false;'Non Admins Elevated'=$s.NonAdministratorsElevated;'Notification Level'=$s.NotificationLevel;'Read Only'=$s.ReadOnly;'Recommended Updates'=$s.IncludeRecommendedUpdates;'Scheduled Day'=$s.ScheduledInstallationDay;'Scheduled Time'=($s.ScheduledInstallationTime.ToString('00')+':00')}"
	return wuaJSON(ctx, rt, script)
}

type needsRebootFunc struct{}
type noArgsWUA struct{}

func (needsRebootFunc) Name() string        { return "win_wua.get_needs_reboot" }
func (needsRebootFunc) Args() any           { return noArgsWUA{} }
func (needsRebootFunc) Platforms() []string { return []string{"windows"} }
func (needsRebootFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverWUA(&res, &err)
	value, e := wuaJSON(ctx, rt, "[bool](Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired')")
	if e != nil {
		return nil, e
	}
	if b, ok := value.(bool); ok {
		return b, nil
	}
	return false, nil
}
func recoverWUA(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{availableFunc{}, getFunc{}, listFunc{}, installedFunc{}, downloadFunc{}, installFunc{}, uninstallFunc{}, setSettingsFunc{}, getSettingsFunc{}, needsRebootFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
