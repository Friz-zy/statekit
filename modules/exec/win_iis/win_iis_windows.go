//go:build windows

// Package win_iis implements the operational core of Salt's win_iis module
// through encoded WebAdministration PowerShell. Collection-setting APIs whose
// schema depends on caller-specific IIS filters are kept as explicit errors
// rather than silently guessing a configuration path.
package win_iis

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

func iisLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
func iisCommand(script string) process.Command {
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
func iisRun(ctx context.Context, rt *runtime.Runtime, script string) (string, error) {
	r := rt.Runner.Run(ctx, iisCommand("Import-Module WebAdministration; "+script))
	if r.Err != nil && r.ExitCode == -1 {
		return string(r.Stdout), r.Err
	}
	if r.ExitCode != 0 {
		return string(r.Stdout), fmt.Errorf("WebAdministration command failed (exit code %d): %s", r.ExitCode, strings.TrimSpace(string(r.Stderr)))
	}
	return string(r.Stdout), nil
}
func iisJSON(ctx context.Context, rt *runtime.Runtime, script string) (any, error) {
	out, e := iisRun(ctx, rt, script+" | ConvertTo-Json -Compress -Depth 8")
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
func iisRows(value any) []map[string]any {
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
func iisSuccess(ctx context.Context, rt *runtime.Runtime, script string) (bool, error) {
	_, e := iisRun(ctx, rt, script)
	return e == nil, e
}

func registerWindows(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		listSitesFunc{}, createSiteFunc{}, modifySiteFunc{}, removeSiteFunc{}, stopSiteFunc{}, startSiteFunc{}, restartSiteFunc{},
		listBindingsFunc{}, createBindingFunc{}, modifyBindingFunc{}, removeBindingFunc{}, listCertBindingsFunc{}, createCertBindingFunc{}, removeCertBindingFunc{},
		listAppPoolsFunc{}, createAppPoolFunc{}, removeAppPoolFunc{}, stopAppPoolFunc{}, startAppPoolFunc{}, restartAppPoolFunc{},
		getContainerSettingFunc{}, setContainerSettingFunc{}, listAppsFunc{}, createAppFunc{}, removeAppFunc{}, listVDirsFunc{}, createVDirFunc{}, removeVDirFunc{},
		listBackupsFunc{}, createBackupFunc{}, removeBackupFunc{}, listWorkerProcessesFunc{}, getWebAppSettingsFunc{}, setWebAppSettingsFunc{}, getWebConfigurationSettingsFunc{}, setWebConfigurationSettingsFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// sites and bindings

type noArgs struct{}
type siteNameArgs struct {
	Name string `statekit:"required"`
}
type siteArgs struct {
	Name       string  `statekit:"required"`
	SourcePath string  `statekit:"required,name=sourcepath"`
	AppPool    *string `statekit:"name=apppool"`
	HostHeader *string `statekit:"name=hostheader"`
	IPAddress  *string `statekit:"name=ipaddress"`
	Port       *int    `statekit:"name=port"`
	Protocol   *string `statekit:"name=protocol"`
}
type listSitesFunc struct{}

func (listSitesFunc) Name() string        { return "win_iis.list_sites" }
func (listSitesFunc) Args() any           { return noArgs{} }
func (listSitesFunc) Platforms() []string { return []string{"windows"} }
func (listSitesFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverIIS(&res, &err)
	value, e := iisJSON(ctx, rt, "@(Get-Website | ForEach-Object {$s=$_;[ordered]@{name=$s.Name;id=$s.Id;state=$s.State;apppool=$s.ApplicationPool;sourcepath=$s.PhysicalPath;bindings=@(Get-WebBinding -Name $s.Name | Select-Object bindingInformation,certificateHash,certificateStoreName,protocol,sslFlags)}})")
	if e != nil {
		return nil, e
	}
	out := map[string]any{}
	for _, row := range iisRows(value) {
		name := fmt.Sprint(row["name"])
		if name != "" {
			out[name] = row
		}
	}
	return out, nil
}

type createSiteFunc struct{}

func (createSiteFunc) Name() string        { return "win_iis.create_site" }
func (createSiteFunc) Args() any           { return siteArgs{} }
func (createSiteFunc) Platforms() []string { return []string{"windows"} }
func (createSiteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverIIS(&res, &err)
	a := args.(*siteArgs)
	protocol := "http"
	if a.Protocol != nil && *a.Protocol != "" {
		protocol = strings.ToLower(*a.Protocol)
	}
	if protocol != "http" && protocol != "https" && protocol != "ftp" {
		return nil, fmt.Errorf("Invalid protocol '%s' specified", protocol)
	}
	sites, e := listSitesFunc{}.Execute(ctx, rt, noArgs{})
	if e != nil {
		return nil, e
	}
	if _, ok := sites.(map[string]any)[a.Name]; ok {
		return true, nil
	}
	ip := "*"
	if a.IPAddress != nil {
		ip = *a.IPAddress
	}
	port := 80
	if a.Port != nil {
		port = *a.Port
	}
	host := ""
	if a.HostHeader != nil {
		host = *a.HostHeader
	}
	pool := ""
	if a.AppPool != nil {
		pool = *a.AppPool
	}
	script := "if(-not (Get-Website -Name " + iisLiteral(a.Name) + " -ErrorAction SilentlyContinue)){New-Website -Name " + iisLiteral(a.Name) + " -PhysicalPath " + iisLiteral(a.SourcePath) + " -Port " + strconv.Itoa(port) + " -IPAddress " + iisLiteral(ip) + " -HostHeader " + iisLiteral(host) + " -Force;"
	if pool != "" {
		script += "if(-not (Get-IISAppPool -Name " + iisLiteral(pool) + " -ErrorAction SilentlyContinue)){New-WebAppPool -Name " + iisLiteral(pool) + "};Set-ItemProperty -Path 'IIS:\\Sites\\" + strings.ReplaceAll(a.Name, "'", "''") + "' -Name ApplicationPool -Value " + iisLiteral(pool) + ";"
	}
	script += "}"
	return iisSuccess(ctx, rt, script)
}

type modifySiteFunc struct{}

func (modifySiteFunc) Name() string        { return "win_iis.modify_site" }
func (modifySiteFunc) Args() any           { return siteArgs{} }
func (modifySiteFunc) Platforms() []string { return []string{"windows"} }
func (modifySiteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*siteArgs)
	script := ""
	if a.SourcePath != "" {
		script += "Set-ItemProperty -Path 'IIS:\\Sites\\" + strings.ReplaceAll(a.Name, "'", "''") + "' -Name PhysicalPath -Value " + iisLiteral(a.SourcePath) + ";"
	}
	if a.AppPool != nil {
		script += "Set-ItemProperty -Path 'IIS:\\Sites\\" + strings.ReplaceAll(a.Name, "'", "''") + "' -Name ApplicationPool -Value " + iisLiteral(*a.AppPool) + ";"
	}
	if script == "" {
		return true, nil
	}
	return iisSuccess(ctx, rt, script)
}

type removeSiteFunc struct{}

func (removeSiteFunc) Name() string        { return "win_iis.remove_site" }
func (removeSiteFunc) Args() any           { return siteNameArgs{} }
func (removeSiteFunc) Platforms() []string { return []string{"windows"} }
func (removeSiteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*siteNameArgs)
	return iisSuccess(ctx, rt, "Remove-Website -Name "+iisLiteral(a.Name))
}

type stopSiteFunc struct{}

func (stopSiteFunc) Name() string        { return "win_iis.stop_site" }
func (stopSiteFunc) Args() any           { return siteNameArgs{} }
func (stopSiteFunc) Platforms() []string { return []string{"windows"} }
func (stopSiteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return iisSuccess(ctx, rt, "Stop-Website -Name "+iisLiteral(args.(*siteNameArgs).Name))
}

type startSiteFunc struct{}

func (startSiteFunc) Name() string        { return "win_iis.start_site" }
func (startSiteFunc) Args() any           { return siteNameArgs{} }
func (startSiteFunc) Platforms() []string { return []string{"windows"} }
func (startSiteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return iisSuccess(ctx, rt, "Start-Website -Name "+iisLiteral(args.(*siteNameArgs).Name))
}

type restartSiteFunc struct{}

func (restartSiteFunc) Name() string        { return "win_iis.restart_site" }
func (restartSiteFunc) Args() any           { return siteNameArgs{} }
func (restartSiteFunc) Platforms() []string { return []string{"windows"} }
func (restartSiteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*siteNameArgs)
	if _, e := (stopSiteFunc{}).Execute(ctx, rt, a); e != nil {
		return false, e
	}
	return startSiteFunc{}.Execute(ctx, rt, a)
}

type bindingArgs struct {
	Site       string  `statekit:"required"`
	HostHeader *string `statekit:"name=hostheader"`
	IPAddress  *string `statekit:"name=ipaddress"`
	Port       *int    `statekit:"name=port"`
	Protocol   *string `statekit:"name=protocol"`
	SSLFlags   *int    `statekit:"name=sslflags"`
}
type listBindingsFunc struct{}

func (listBindingsFunc) Name() string        { return "win_iis.list_bindings" }
func (listBindingsFunc) Args() any           { return bindingArgs{} }
func (listBindingsFunc) Platforms() []string { return []string{"windows"} }
func (listBindingsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverIIS(&res, &err)
	a := args.(*bindingArgs)
	value, e := iisJSON(ctx, rt, "@(Get-WebBinding -Name "+iisLiteral(a.Site)+" | Select-Object bindingInformation,certificateHash,certificateStoreName,protocol,sslFlags)")
	if e != nil {
		return nil, e
	}
	out := map[string]any{}
	for _, row := range iisRows(value) {
		out[fmt.Sprint(row["bindingInformation"])] = row
	}
	return out, nil
}

type createBindingFunc struct{}

func (createBindingFunc) Name() string        { return "win_iis.create_binding" }
func (createBindingFunc) Args() any           { return bindingArgs{} }
func (createBindingFunc) Platforms() []string { return []string{"windows"} }
func (createBindingFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*bindingArgs)
	proto := "http"
	if a.Protocol != nil {
		proto = *a.Protocol
	}
	ip := "*"
	if a.IPAddress != nil {
		ip = *a.IPAddress
	}
	port := 80
	if a.Port != nil {
		port = *a.Port
	}
	host := ""
	if a.HostHeader != nil {
		host = *a.HostHeader
	}
	return iisSuccess(ctx, rt, "New-WebBinding -Name "+iisLiteral(a.Site)+" -Protocol "+iisLiteral(proto)+" -IPAddress "+iisLiteral(ip)+" -Port "+strconv.Itoa(port)+" -HostHeader "+iisLiteral(host))
}

type modifyBindingFunc struct{}

func (modifyBindingFunc) Name() string        { return "win_iis.modify_binding" }
func (modifyBindingFunc) Args() any           { return bindingArgs{} }
func (modifyBindingFunc) Platforms() []string { return []string{"windows"} }
func (modifyBindingFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*bindingArgs)
	return iisSuccess(ctx, rt, "Set-WebBinding -Name "+iisLiteral(a.Site)+" -BindingInformation *:"+strconv.Itoa(intValueIIS(a.Port))+":"+stringValueIIS(a.HostHeader)+" -PropertyName Protocol -Value "+stringValueIIS(a.Protocol))
}

type removeBindingFunc struct{}

func (removeBindingFunc) Name() string        { return "win_iis.remove_binding" }
func (removeBindingFunc) Args() any           { return bindingArgs{} }
func (removeBindingFunc) Platforms() []string { return []string{"windows"} }
func (removeBindingFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*bindingArgs)
	proto := "http"
	if a.Protocol != nil {
		proto = *a.Protocol
	}
	ip := "*"
	if a.IPAddress != nil {
		ip = *a.IPAddress
	}
	port := 80
	if a.Port != nil {
		port = *a.Port
	}
	host := ""
	if a.HostHeader != nil {
		host = *a.HostHeader
	}
	return iisSuccess(ctx, rt, "Remove-WebBinding -Name "+iisLiteral(a.Site)+" -Protocol "+iisLiteral(proto)+" -IPAddress "+iisLiteral(ip)+" -Port "+strconv.Itoa(port)+" -HostHeader "+iisLiteral(host))
}
func intValueIIS(v *int) int {
	if v == nil {
		return 80
	}
	return *v
}
func stringValueIIS(v *string) string {
	if v == nil {
		return "''"
	}
	return iisLiteral(*v)
}

type certBindingArgs struct {
	Name       string  `statekit:"required"`
	Site       string  `statekit:"required"`
	HostHeader *string `statekit:"name=hostheader"`
	IPAddress  *string `statekit:"name=ipaddress"`
	Port       *int    `statekit:"name=port"`
	SSLFlags   *int    `statekit:"name=sslflags"`
}
type listCertBindingsFunc struct{}

func (listCertBindingsFunc) Name() string        { return "win_iis.list_cert_bindings" }
func (listCertBindingsFunc) Args() any           { return certBindingArgs{} }
func (listCertBindingsFunc) Platforms() []string { return []string{"windows"} }
func (listCertBindingsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*certBindingArgs)
	return listBindingsFunc{}.Execute(ctx, rt, &bindingArgs{Site: a.Site, Protocol: stringPtrIIS("https")})
}

type createCertBindingFunc struct{}

func (createCertBindingFunc) Name() string        { return "win_iis.create_cert_binding" }
func (createCertBindingFunc) Args() any           { return certBindingArgs{} }
func (createCertBindingFunc) Platforms() []string { return []string{"windows"} }
func (createCertBindingFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*certBindingArgs)
	port := 443
	if a.Port != nil {
		port = *a.Port
	}
	ip := "*"
	if a.IPAddress != nil {
		ip = *a.IPAddress
	}
	host := ""
	if a.HostHeader != nil {
		host = *a.HostHeader
	}
	script := "New-WebBinding -Name " + iisLiteral(a.Site) + " -Protocol https -IPAddress " + iisLiteral(ip) + " -Port " + strconv.Itoa(port) + " -HostHeader " + iisLiteral(host) + ";Get-WebBinding -Name " + iisLiteral(a.Site) + " -Protocol https | Where-Object {$_.bindingInformation -eq '" + ip + ":" + strconv.Itoa(port) + ":" + host + "'} | ForEach-Object {$_.AddSslCertificate('" + strings.ToUpper(a.Name) + "','My')}"
	return iisSuccess(ctx, rt, script)
}

type removeCertBindingFunc struct{}

func (removeCertBindingFunc) Name() string        { return "win_iis.remove_cert_binding" }
func (removeCertBindingFunc) Args() any           { return certBindingArgs{} }
func (removeCertBindingFunc) Platforms() []string { return []string{"windows"} }
func (removeCertBindingFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*certBindingArgs)
	return removeBindingFunc{}.Execute(ctx, rt, &bindingArgs{Site: a.Site, HostHeader: a.HostHeader, IPAddress: a.IPAddress, Port: a.Port, Protocol: stringPtrIIS("https")})
}
func stringPtrIIS(v string) *string { return &v }

// ---------------------------------------------------------------------------
// app pools/apps/vdirs/backups/workers

type appPoolArgs struct {
	Name string `statekit:"required"`
}
type listAppPoolsFunc struct{}

func (listAppPoolsFunc) Name() string        { return "win_iis.list_apppools" }
func (listAppPoolsFunc) Args() any           { return noArgs{} }
func (listAppPoolsFunc) Platforms() []string { return []string{"windows"} }
func (listAppPoolsFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return iisJSON(ctx, rt, "@(Get-IISAppPool | Select-Object Name,State,ManagedRuntimeVersion,ManagedPipelineMode)")
}

type createAppPoolFunc struct{}

func (createAppPoolFunc) Name() string        { return "win_iis.create_apppool" }
func (createAppPoolFunc) Args() any           { return appPoolArgs{} }
func (createAppPoolFunc) Platforms() []string { return []string{"windows"} }
func (createAppPoolFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return iisSuccess(ctx, rt, "if(-not (Get-IISAppPool -Name "+iisLiteral(args.(*appPoolArgs).Name)+" -ErrorAction SilentlyContinue)){New-WebAppPool -Name "+iisLiteral(args.(*appPoolArgs).Name)+"}")
}

type removeAppPoolFunc struct{}

func (removeAppPoolFunc) Name() string        { return "win_iis.remove_apppool" }
func (removeAppPoolFunc) Args() any           { return appPoolArgs{} }
func (removeAppPoolFunc) Platforms() []string { return []string{"windows"} }
func (removeAppPoolFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return iisSuccess(ctx, rt, "Remove-WebAppPool -Name "+iisLiteral(args.(*appPoolArgs).Name))
}

type stopAppPoolFunc struct{}

func (stopAppPoolFunc) Name() string        { return "win_iis.stop_apppool" }
func (stopAppPoolFunc) Args() any           { return appPoolArgs{} }
func (stopAppPoolFunc) Platforms() []string { return []string{"windows"} }
func (stopAppPoolFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return iisSuccess(ctx, rt, "Stop-WebAppPool -Name "+iisLiteral(args.(*appPoolArgs).Name))
}

type startAppPoolFunc struct{}

func (startAppPoolFunc) Name() string        { return "win_iis.start_apppool" }
func (startAppPoolFunc) Args() any           { return appPoolArgs{} }
func (startAppPoolFunc) Platforms() []string { return []string{"windows"} }
func (startAppPoolFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return iisSuccess(ctx, rt, "Start-WebAppPool -Name "+iisLiteral(args.(*appPoolArgs).Name))
}

type restartAppPoolFunc struct{}

func (restartAppPoolFunc) Name() string        { return "win_iis.restart_apppool" }
func (restartAppPoolFunc) Args() any           { return appPoolArgs{} }
func (restartAppPoolFunc) Platforms() []string { return []string{"windows"} }
func (restartAppPoolFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*appPoolArgs)
	if _, e := (stopAppPoolFunc{}).Execute(ctx, rt, a); e != nil {
		return false, e
	}
	return startAppPoolFunc{}.Execute(ctx, rt, a)
}

type appArgs struct {
	Name       string  `statekit:"required"`
	Site       string  `statekit:"required"`
	SourcePath string  `statekit:"required,name=sourcepath"`
	AppPool    *string `statekit:"name=apppool"`
}
type listAppsFunc struct{}

func (listAppsFunc) Name() string        { return "win_iis.list_apps" }
func (listAppsFunc) Args() any           { return siteNameArgs{} }
func (listAppsFunc) Platforms() []string { return []string{"windows"} }
func (listAppsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return iisJSON(ctx, rt, "@(Get-WebApplication -Site "+iisLiteral(args.(*siteNameArgs).Name)+" | Select-Object Path,ApplicationPool,PhysicalPath)")
}

type createAppFunc struct{}

func (createAppFunc) Name() string        { return "win_iis.create_app" }
func (createAppFunc) Args() any           { return appArgs{} }
func (createAppFunc) Platforms() []string { return []string{"windows"} }
func (createAppFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*appArgs)
	pool := ""
	if a.AppPool != nil {
		pool = " -ApplicationPool " + iisLiteral(*a.AppPool)
	}
	return iisSuccess(ctx, rt, "New-WebApplication -Site "+iisLiteral(a.Site)+" -Name "+iisLiteral(a.Name)+" -PhysicalPath "+iisLiteral(a.SourcePath)+pool)
}

type removeAppFunc struct{}

func (removeAppFunc) Name() string        { return "win_iis.remove_app" }
func (removeAppFunc) Args() any           { return siteNameArgs{} }
func (removeAppFunc) Platforms() []string { return []string{"windows"} }
func (removeAppFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*siteNameArgs)
	return iisSuccess(ctx, rt, "Remove-WebApplication -Site "+iisLiteral(a.Name))
}

type vdirArgs struct {
	Name       string `statekit:"required"`
	Site       string `statekit:"required"`
	SourcePath string `statekit:"required,name=sourcepath"`
	App        string `statekit:"name=app"`
}
type listVDirsFunc struct{}

func (listVDirsFunc) Name() string        { return "win_iis.list_vdirs" }
func (listVDirsFunc) Args() any           { return siteNameArgs{} }
func (listVDirsFunc) Platforms() []string { return []string{"windows"} }
func (listVDirsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return iisJSON(ctx, rt, "@(Get-WebVirtualDirectory -Site "+iisLiteral(args.(*siteNameArgs).Name)+" | Select-Object Path,PhysicalPath)")
}

type createVDirFunc struct{}

func (createVDirFunc) Name() string        { return "win_iis.create_vdir" }
func (createVDirFunc) Args() any           { return vdirArgs{} }
func (createVDirFunc) Platforms() []string { return []string{"windows"} }
func (createVDirFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*vdirArgs)
	return iisSuccess(ctx, rt, "New-WebVirtualDirectory -Site "+iisLiteral(a.Site)+" -Name "+iisLiteral(a.Name)+" -PhysicalPath "+iisLiteral(a.SourcePath)+" -Application "+iisLiteral(a.App))
}

type removeVDirFunc struct{}

func (removeVDirFunc) Name() string        { return "win_iis.remove_vdir" }
func (removeVDirFunc) Args() any           { return vdirArgs{} }
func (removeVDirFunc) Platforms() []string { return []string{"windows"} }
func (removeVDirFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*vdirArgs)
	return iisSuccess(ctx, rt, "Remove-WebVirtualDirectory -Site "+iisLiteral(a.Site)+" -Name "+iisLiteral(a.Name)+" -Application "+iisLiteral(a.App))
}

type backupArgs struct {
	Name string `statekit:"required"`
}
type listBackupsFunc struct{}

func (listBackupsFunc) Name() string        { return "win_iis.list_backups" }
func (listBackupsFunc) Args() any           { return noArgs{} }
func (listBackupsFunc) Platforms() []string { return []string{"windows"} }
func (listBackupsFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return iisJSON(ctx, rt, "@(Get-WebConfigBackup | Select-Object Name,Path)")
}

type createBackupFunc struct{}

func (createBackupFunc) Name() string        { return "win_iis.create_backup" }
func (createBackupFunc) Args() any           { return backupArgs{} }
func (createBackupFunc) Platforms() []string { return []string{"windows"} }
func (createBackupFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return iisSuccess(ctx, rt, "New-WebConfigBackup -Name "+iisLiteral(args.(*backupArgs).Name))
}

type removeBackupFunc struct{}

func (removeBackupFunc) Name() string        { return "win_iis.remove_backup" }
func (removeBackupFunc) Args() any           { return backupArgs{} }
func (removeBackupFunc) Platforms() []string { return []string{"windows"} }
func (removeBackupFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return iisSuccess(ctx, rt, "Remove-WebConfigBackup -Name "+iisLiteral(args.(*backupArgs).Name))
}

type workerArgs struct {
	AppPool string `statekit:"required,name=apppool"`
}
type listWorkerProcessesFunc struct{}

func (listWorkerProcessesFunc) Name() string        { return "win_iis.list_worker_processes" }
func (listWorkerProcessesFunc) Args() any           { return workerArgs{} }
func (listWorkerProcessesFunc) Platforms() []string { return []string{"windows"} }
func (listWorkerProcessesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return iisJSON(ctx, rt, "@(Get-WorkerProcess -AppPoolName "+iisLiteral(args.(*workerArgs).AppPool)+")")
}

// ---------------------------------------------------------------------------
// caller-specific collection settings: explicit boundary

type settingsArgs struct {
	Name      string `statekit:"required"`
	Container string `statekit:"required"`
	Settings  any    `statekit:"name=settings"`
}
type getContainerSettingFunc struct{}

func (getContainerSettingFunc) Name() string        { return "win_iis.get_container_setting" }
func (getContainerSettingFunc) Args() any           { return settingsArgs{} }
func (getContainerSettingFunc) Platforms() []string { return []string{"windows"} }
func (getContainerSettingFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return nil, fmt.Errorf("win_iis container setting schema requires an explicit WebAdministration filter mapping")
}

type setContainerSettingFunc struct{}

func (setContainerSettingFunc) Name() string        { return "win_iis.set_container_setting" }
func (setContainerSettingFunc) Args() any           { return settingsArgs{} }
func (setContainerSettingFunc) Platforms() []string { return []string{"windows"} }
func (setContainerSettingFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return nil, fmt.Errorf("win_iis container setting schema requires an explicit WebAdministration filter mapping")
}

type getWebAppSettingsFunc struct{}

func (getWebAppSettingsFunc) Name() string        { return "win_iis.get_webapp_settings" }
func (getWebAppSettingsFunc) Args() any           { return settingsArgs{} }
func (getWebAppSettingsFunc) Platforms() []string { return []string{"windows"} }
func (getWebAppSettingsFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return nil, fmt.Errorf("win_iis webapp settings require an explicit WebAdministration filter mapping")
}

type setWebAppSettingsFunc struct{}

func (setWebAppSettingsFunc) Name() string        { return "win_iis.set_webapp_settings" }
func (setWebAppSettingsFunc) Args() any           { return settingsArgs{} }
func (setWebAppSettingsFunc) Platforms() []string { return []string{"windows"} }
func (setWebAppSettingsFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return nil, fmt.Errorf("win_iis webapp settings require an explicit WebAdministration filter mapping")
}

type getWebConfigurationSettingsFunc struct{}

func (getWebConfigurationSettingsFunc) Name() string        { return "win_iis.get_webconfiguration_settings" }
func (getWebConfigurationSettingsFunc) Args() any           { return settingsArgs{} }
func (getWebConfigurationSettingsFunc) Platforms() []string { return []string{"windows"} }
func (getWebConfigurationSettingsFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return nil, fmt.Errorf("win_iis WebConfiguration settings require an explicit filter mapping")
}

type setWebConfigurationSettingsFunc struct{}

func (setWebConfigurationSettingsFunc) Name() string        { return "win_iis.set_webconfiguration_settings" }
func (setWebConfigurationSettingsFunc) Args() any           { return settingsArgs{} }
func (setWebConfigurationSettingsFunc) Platforms() []string { return []string{"windows"} }
func (setWebConfigurationSettingsFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return nil, fmt.Errorf("win_iis WebConfiguration settings require an explicit filter mapping")
}

func recoverIIS(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}

// Register installs the Windows IIS surface.
func Register(reg *runtime.ExecRegistry) error { return registerWindows(reg) }
