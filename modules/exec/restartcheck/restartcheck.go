// Package restartcheck analyzes files opened by running processes and
// seeks packages which need restarting, mirroring saltstack/salt/modules/
// restartcheck.py @ pinned revision.
//
// Contract notes (init.md section 28): the /proc scanner reads the real
// filesystem (deleted-file detection cannot be modeled by the memory FS);
// pkg.owner and service.get_running/show resolve through registry
// delegates and degrade exactly like minions lacking those modules;
// dpkg-query/repoquery run through the central Runner. Only Debian,
// Red Hat and NI Linux Real-Time families are supported (verbatim error
// dict otherwise). ExecMainPID-based service correlation requires the
// service family's delegates.
package restartcheck

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

var listDirs = []string{
	"^/var/log/", "^/var/local/log/",
	"^/var/run/", "^/var/local/run/",
	"^/tmp/", "^/dev/shm/", "^/run/", "^/drm",
	"^/var/tmp/", "^/var/local/tmp/",
}

var (
	mapLineRe   = regexp.MustCompile(`^[\da-f]+-[\da-f]+ [r-][w-][x-][sp-] [\da-f]+ [\da-f]{2}:[\da-f]{2} (\d+) *(.+)( \(deleted\))?\n$`)
	pathInodeRe = regexp.MustCompile(`\(path inode=[0-9]+\)$`)
	listDirsRe  = regexp.MustCompile(strings.Join(listDirs, "|"))
	hexPrefixRe = regexp.MustCompile(`^[a-f0-9]+$`)
)

type deletedFile struct {
	name string
	pid  int
	path string
}

func validDeletedFile(path string) bool {
	ret := false
	if strings.HasSuffix(path, " (deleted)") {
		ret = true
	}
	if pathInodeRe.MatchString(path) {
		ret = true
	}
	if listDirsRe.MatchString(path) {
		ret = false
	}
	return ret
}

// deletedFiles scans /proc/PID/maps for deleted mappings. It reads the
// real /proc tree through os rather than rt.FS because deleted-library
// detection is inherently a live-kernel view.
func deletedFiles() ([]deletedFile, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, false
	}
	var out []deletedFile
	for _, entry := range entries {
		if !hexPrefixRe.MatchString(entry.Name()) {
			continue
		}
		pid, perr := strconv.Atoi(entry.Name())
		if perr != nil {
			continue
		}
		nameBytes, nerr := os.ReadFile("/proc/" + entry.Name() + "/comm")
		name := ""
		if nerr == nil {
			name = strings.TrimSpace(string(nameBytes))
		}
		mapsData, merr := os.ReadFile("/proc/" + entry.Name() + "/maps")
		if merr != nil {
			continue
		}
		fdDir := "/proc/" + entry.Name() + "/fd/"
		if _, derr := os.ReadDir(fdDir); derr != nil {
			continue
		}
		for _, mapLine := range strings.Split(string(mapsData), "\n") {
			matched := mapLineRe.FindStringSubmatch(mapLine + "\n")
			if matched == nil {
				continue
			}
			path := matched[2]
			if path == "" {
				continue
			}
			if !validDeletedFile(path) {
				continue
			}
			out = append(out, deletedFile{name: name, pid: pid, path: path})
		}
	}
	return out, true
}

type kernelVersionsFn func(ctx context.Context, rt *runtime.Runtime) []string

func kernelVersionsDebian(ctx context.Context, rt *runtime.Runtime) []string {
	sel := rt.Runner.Run(ctx, runtime.Command(
		"dpkg", "--get-selections", "linux-image-*"))
	kernels := strings.Split(strings.TrimRight(resText(sel), "\n"), "\n")
	var kernel string
	switch {
	case len(kernels) >= 2:
		kernel = kernels[len(kernels)-2]
	default:
		kernel = kernels[0]
	}
	kernel = strings.TrimRight(kernel, "\t\tinstall")
	// Upstream then runs apt-cache policy <kernel> and extracts the
	// "  Installed: " version.
	pol := rt.Runner.Run(ctx, runtime.Command("apt-cache", "policy", kernel))
	var versions []string
	for _, line := range strings.Split(string(pol.Stdout), "\n") {
		if strings.HasPrefix(line, "  Installed: ") {
			versions = append(versions,
				strings.TrimPrefix(strings.TrimLeft(line, " "), "Installed: "))
			break
		}
	}
	return versions
}

func resText(res process.CommandResult) string { return string(res.Stdout) }

func kernelVersionsRedhat(ctx context.Context, rt *runtime.Runtime) []string {
	res := rt.Runner.Run(ctx, runtime.Command("rpm", "-q", "kernel"))
	out := strings.TrimRight(string(res.Stdout), "\n")
	var versions []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "package") {
			continue
		}
		versions = append(versions, "vmlinuz-"+line)
	}
	return versions
}

type checkTimeout struct {
	start time.Time
	limit time.Duration
}

func newCheckTimeout(timeoutMinutes int) *checkTimeout {
	return &checkTimeout{start: time.Now(), limit: time.Duration(timeoutMinutes) * time.Minute}
}

func (c *checkTimeout) expired() error {
	if c.limit < time.Since(c.start) {
		return fmt.Errorf("Timeout expired.")
	}
	return nil
}

func scalarText(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return x
	}
	return fmt.Sprintf("%v", v)
}

type RestartCheckArgs struct {
	IgnoreList any   `statekit:"name=ignorelist"`
	Blacklist  any   `statekit:"name=blacklist"`
	ExcludePid any   `statekit:"name=excludepid"`
	Verbose    *bool `statekit:"name=verbose"`
	Timeout    *int  `statekit:"name=timeout"`
}

type restartCheckFunc struct{}

func (restartCheckFunc) Name() string { return "restartcheck.restartcheck" }
func (restartCheckFunc) Args() any    { return RestartCheckArgs{} }

// toStrList mirrors upstream's str-or-list normalization.
func toStrList(raw any) []string {
	switch v := raw.(type) {
	case nil:
		return nil
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	}
	return nil
}

// RestartCheck mirrors restartcheck(): the full pipeline — running-service
// correlation via service delegates, deleted-file scanning over /proc,
// package ownership via the pkg.owner delegate with process-name fallback,
// init.d/systemd classification through dpkg-query/repoquery, and the
// verbose/non-verbose formatters.
func (restartCheckFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RestartCheckArgs)
	startTime := newCheckTimeout(5)
	if a.Timeout != nil && *a.Timeout > 0 {
		startTime = newCheckTimeout(*a.Timeout)
	}
	verbose := true
	if a.Verbose != nil {
		verbose = *a.Verbose
	}

	family := "debian"
	if rt.Facts != nil {
		switch rt.Facts.OS().Family {
		case "debian":
			family = "debian"
		case "redhat":
			family = "redhat"
		default:
			return map[string]any{
				"result":  false,
				"comment": "Only available on Debian, Red Hat and NI Linux Real-Time based systems.",
			}, nil
		}
	}

	var cmdPkgQuery []string
	systemdFolder := ""
	systemdBin := ""
	var kernelVersions []string
	switch family {
	case "debian":
		cmdPkgQuery = []string{"dpkg-query", "--listfiles"}
		systemdFolder = "/lib/systemd/system/"
		systemdBin = "/bin/systemd"
		kernelVersions = kernelVersionsDebian(ctx, rt)
	case "redhat":
		cmdPkgQuery = []string{"repoquery", "-l"}
		systemdFolder = "/usr/lib/systemd/system/"
		systemdBin = "/usr/bin/systemctl"
		kernelVersions = kernelVersionsRedhat(ctx, rt)
	}

	kernelCurrentRes := rt.Runner.Run(ctx, runtime.Command("uname", "-a"))
	kernelCurrent := string(kernelCurrentRes.Stdout)
	kernelRestart := true
	for _, kernel := range kernelVersions {
		if terr := startTime.expired(); terr != nil {
			return nil, terr
		}
		if strings.Contains(kernelCurrent, kernel) {
			kernelRestart = false
			break
		}
	}

	ignorelist := toStrList(a.IgnoreList)
	if len(ignorelist) == 0 {
		ignorelist = []string{"screen", "systemd"}
	}
	blacklist := toStrList(a.Blacklist)
	excludepidRaw := toStrList(a.ExcludePid)
	excludepid := map[string]bool{}
	for _, pid := range excludepidRaw {
		excludepid[pid] = true
	}

	runningServices := map[string]int{}
	if getRunning, ok := rt.Exec.Get("service.get_running"); ok {
		if res, serr := getRunning.Execute(
			ctx, rt, map[string]any{}); serr == nil {
			if services, ok := res.([]string); ok {
				showFn, hasShow := rt.Exec.Get("service.show")
				for _, service := range services {
					if terr := startTime.expired(); terr != nil {
						return nil, terr
					}
					if !hasShow {
						continue
					}
					showRes, sherr := showFn.Execute(
						ctx, rt, map[string]any{"name": service})
					if sherr != nil {
						continue
					}
					if showMap, ok := showRes.(map[string]any); ok {
						if pidVal, has := showMap["ExecMainPID"]; has {
							if pidNum, ok := toInt(pidVal); ok {
								runningServices[service] = pidNum
							}
						}
					}
				}
			}
		}
	}

	packages := map[string]*pkgInfo{}
	restartServices := []string{}

	ownersCache := map[string]string{}
	pkgOwner, hasOwner := rt.Exec.Get("pkg.owner")

	deleted, ok := deletedFiles()
	if !ok {
		return map[string]any{
			"result":  false,
			"comment": "Could not get list of processes. (Do you have root access?)",
		}, nil
	}

	for _, df := range deleted {
		if terr := startTime.expired(); terr != nil {
			return nil, terr
		}
		if containsStr(blacklist, df.path) || excludepid[strconv.Itoa(df.pid)] {
			continue
		}
		readlink, rerr := os.Readlink(fmt.Sprintf("/proc/%d/exe", df.pid))
		if rerr != nil {
			excludepid[strconv.Itoa(df.pid)] = true
			continue
		}
		packagename, cached := ownersCache[readlink]
		if !cached {
			if hasOwner {
				if res, oerr := pkgOwner.Execute(
					ctx, rt, map[string]any{"path": readlink}); oerr == nil {
					packagename = scalarText(res)
				}
			}
			if packagename == "" {
				packagename = df.name
			}
			ownersCache[readlink] = packagename
		}
		for service, spid := range runningServices {
			if terr := startTime.expired(); terr != nil {
				return nil, terr
			}
			if !containsStr(restartServices, service) && df.pid == spid {
				if packagename != "" && !containsStr(ignorelist, packagename) {
					restartServices = append(restartServices, service)
					df.name = service
				}
			}
		}
		if packagename != "" && !containsStr(ignorelist, packagename) {
			program := "\t" + strconv.Itoa(df.pid) + " " + readlink +
				" (file: " + df.path + ")"
			info, seen := packages[packagename]
			if !seen {
				packages[packagename] = &pkgInfo{
					Processes:   []string{program},
					ProcessName: df.name,
				}
			} else if !containsStr(info.Processes, program) {
				info.Processes = append(info.Processes, program)
			}
		}
	}

	if len(packages) == 0 && !kernelRestart {
		return "No packages seem to need to be restarted.", nil
	}

	serviceAvailable, hasAvailable := rt.Exec.Get("service.available")
	for pkgName := range packages {
		if terr := startTime.expired(); terr != nil {
			return nil, terr
		}
		cmd := append([]string{}, cmdPkgQuery...)
		cmd = append(cmd, pkgName)
		res := rt.Runner.Run(ctx, runtime.Command(cmd...))
		for _, line := range strings.Split(strings.TrimRight(string(res.Stdout), "\n"), "\n") {
			if line == "" {
				continue
			}
			pth := line
			if strings.HasPrefix(pth, "/etc/init.d/") && !strings.HasSuffix(pth, ".sh") {
				packages[pkgName].InitScripts = append(
					packages[pkgName].InitScripts, strings.TrimPrefix(pth, "/etc/init.d/"))
			}
			if systemdBin != "" && strings.HasPrefix(pth, systemdFolder) &&
				strings.HasSuffix(pth, ".service") && !strings.Contains(pth, ".wants") {
				isOneshot := false
				if svcData, serr := os.ReadFile(pth); serr == nil {
					for _, svcLine := range strings.Split(string(svcData), "\n") {
						if strings.Contains(svcLine, "Type=oneshot") {
							isOneshot = true
						}
					}
				}
				if !isOneshot {
					packages[pkgName].SystemdService = append(
						packages[pkgName].SystemdService,
						strings.TrimPrefix(pth, systemdFolder))
				}
			}
		}

		if len(packages[pkgName].SystemdService) == 0 &&
			len(packages[pkgName].InitScripts) == 0 && hasAvailable {
			res, serr := serviceAvailable.Execute(
				ctx, rt, map[string]any{"name": packages[pkgName].ProcessName})
			if serr == nil {
				available := false
				if b, isBool := res.(bool); isBool {
					available = b
				} else if s, isStr := res.(string); isStr {
					available = s != "" && s != "False"
				}
				if available {
					initPath := "/etc/init.d/" + packages[pkgName].ProcessName
					if info, ierr := os.Stat(initPath); ierr == nil && !info.IsDir() {
						packages[pkgName].InitScripts = append(
							packages[pkgName].InitScripts, packages[pkgName].ProcessName)
					} else {
						packages[pkgName].SystemdService = append(
							packages[pkgName].SystemdService, packages[pkgName].ProcessName)
					}
				}
			}
		}
		if terr := startTime.expired(); terr != nil {
			return nil, terr
		}
	}

	restartable := []string{}
	nonrestartable := []string{}
	restartInitCommands := []string{}
	restartServiceCommands := []string{}

	pkgNames := make([]string, 0, len(packages))
	for name := range packages {
		pkgNames = append(pkgNames, name)
	}
	sortStrings(pkgNames)
	for _, pkgName := range pkgNames {
		info := packages[pkgName]
		if terr := startTime.expired(); terr != nil {
			return nil, terr
		}
		switch {
		case len(info.InitScripts) > 0:
			restartable = append(restartable, pkgName)
			for _, script := range info.InitScripts {
				restartInitCommands = append(restartInitCommands, "service "+script+" restart")
			}
		case len(info.SystemdService) > 0:
			restartable = append(restartable, pkgName)
			for _, svc := range info.SystemdService {
				restartServiceCommands = append(restartServiceCommands, "systemctl restart "+svc)
			}
		default:
			nonrestartable = append(nonrestartable, pkgName)
		}
		if containsStr(restartServices, info.ProcessName) {
			restartServices = removeStr(restartServices, info.ProcessName)
		}
	}
	for _, svc := range restartServices {
		restartServiceCommands = append(restartServiceCommands, "systemctl restart "+svc)
	}

	if !verbose {
		list := append(append([]string{}, restartable...), nonrestartable...)
		if kernelRestart {
			list = append(list, "System restart required.")
		}
		return list, nil
	}

	ret := ""
	if kernelRestart {
		ret = "System restart required.\n\n"
	}
	if len(packages) > 0 {
		ret += fmt.Sprintf("Found %d processes using old versions of upgraded files.\n",
			len(packages))
		ret += "These are the packages:\n"
	}
	if len(restartable) > 0 {
		ret += fmt.Sprintf("Of these, %d seem to contain systemd service definitions "+
			"or init scripts which can be used to restart them:\n", len(restartable))
		for _, pkgName := range restartable {
			ret += pkgName + ":\n"
			for _, program := range packages[pkgName].Processes {
				ret += program + "\n"
			}
		}
		if len(restartServiceCommands) > 0 {
			ret += "\n\nThese are the systemd services:\n"
			ret += strings.Join(restartServiceCommands, "\n")
		}
		if len(restartInitCommands) > 0 {
			ret += "\n\nThese are the initd scripts:\n"
			ret += strings.Join(restartInitCommands, "\n")
		}
	}
	if len(nonrestartable) > 0 {
		plural := "processes do"
		if len(nonrestartable) == 1 {
			plural = "process does"
		}
		ret += fmt.Sprintf("\n\nThese processes %s not seem to have an associated "+
			"init script to restart them:\n", plural)
		for _, pkgName := range nonrestartable {
			ret += pkgName + ":\n"
			for _, program := range packages[pkgName].Processes {
				ret += program + "\n"
			}
		}
	}
	return ret, nil
}

type pkgInfo struct {
	InitScripts    []string
	SystemdService []string
	Processes      []string
	ProcessName    string
}

func containsStr(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}

func removeStr(list []string, needle string) []string {
	out := make([]string, 0, len(list))
	for _, item := range list {
		if item != needle {
			out = append(out, item)
		}
	}
	return out
}

func sortStrings(items []string) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j] < items[j-1]; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

func toInt(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case float64:
		return int(x), true
	case string:
		n, err := strconv.Atoi(x)
		return n, err == nil
	}
	return 0, false
}

// FormatOutput mirrors _format_output: non-verbose returns a flat package
// name list (with the kernel banner appended); verbose builds the full
// multi-section report.
func FormatOutput(
	kernelRestart bool,
	packages map[string]*pkgInfo,
	verbose bool,
	restartable []string,
	nonrestartable []string,
	restartServiceCommands []string,
	restartInitCommands []string,
) any {
	if !verbose {
		list := append(append([]string{}, restartable...), nonrestartable...)
		if kernelRestart {
			list = append(list, "System restart required.")
		}
		return list
	}
	ret := ""
	if kernelRestart {
		ret = "System restart required.\n\n"
	}
	if len(packages) > 0 {
		ret += fmt.Sprintf("Found %d processes using old versions of upgraded files.\n",
			len(packages))
		ret += "These are the packages:\n"
	}
	if len(restartable) > 0 {
		ret += fmt.Sprintf("Of these, %d seem to contain systemd service definitions "+
			"or init scripts which can be used to restart them:\n", len(restartable))
		for _, pkgName := range restartable {
			ret += pkgName + ":\n"
			for _, program := range packages[pkgName].Processes {
				ret += program + "\n"
			}
		}
		if len(restartServiceCommands) > 0 {
			ret += "\n\nThese are the systemd services:\n"
			ret += strings.Join(restartServiceCommands, "\n")
		}
		if len(restartInitCommands) > 0 {
			ret += "\n\nThese are the initd scripts:\n"
			ret += strings.Join(restartInitCommands, "\n")
		}
	}
	if len(nonrestartable) > 0 {
		ret += fmt.Sprintf("\n\nThese processes %d do not seem to have an associated "+
			"init script to restart them:\n", len(nonrestartable))
		for _, pkgName := range nonrestartable {
			ret += pkgName + ":\n"
			for _, program := range packages[pkgName].Processes {
				ret += program + "\n"
			}
		}
	}
	return ret
}

// Register installs the restartcheck execution function.
func Register(reg *runtime.ExecRegistry) error {
	return reg.Register(restartCheckFunc{})
}
