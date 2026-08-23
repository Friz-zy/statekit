//go:build linux

package facts

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
)

// detectOS reads /etc/os-release; the runner is unused on linux, where all
// probes are plain filesystem checks.
func detectOS(_ process.Runner) OSFacts {
	release := parseOSRelease("/etc/os-release")
	id := release["ID"]
	name := release["NAME"]
	version := release["VERSION_ID"]
	codename := release["VERSION_CODENAME"]
	if codename == "" {
		codename = versionCodename(release["VERSION"])
	}
	return OSFacts{
		ID:       id,
		Name:     name,
		Family:   OSFamily(id, release["ID_LIKE"]),
		Version:  version,
		Codename: codename,
	}
}

// parseOSRelease parses an os-release style file into a key/value map,
// stripping surrounding quotes from values.
func parseOSRelease(path string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		out[strings.TrimSpace(key)] = value
	}
	return out
}

// versionCodename extracts a codename from a VERSION string like
// "12 (bookworm)".
func versionCodename(version string) string {
	open := strings.IndexByte(version, '(')
	close := strings.LastIndexByte(version, ')')
	if open < 0 || close <= open+1 {
		return ""
	}
	return version[open+1 : close]
}

func detectInitSystem() string {
	switch {
	case fileExists("/run/systemd/system"):
		return "systemd"
	case fileExists("/run/openrc"), fileExists("/sbin/openrc"):
		return "openrc"
	}
	if data, err := os.ReadFile("/proc/1/comm"); err == nil {
		if comm := strings.TrimSpace(string(data)); comm != "" {
			return filepath.Base(comm)
		}
	}
	return ""
}

func detectSecurity() SecurityFacts {
	return SecurityFacts{
		SELinux:  dirExists("/sys/fs/selinux"),
		AppArmor: dirExists("/sys/module/apparmor") || dirExists("/sys/kernel/security/apparmor"),
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
