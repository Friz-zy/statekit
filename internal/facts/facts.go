// Package facts implements minimal read-only local system detection.
//
// Reference: plans/init.md sections 14-15; behavior derived from
// saltstack/salt/grains/core.py where applicable.
//
// Facts are local, automatically detected, typed internally, and cached only
// for process lifetime. Cheap facts are detected eagerly at Detect(); init
// system, package manager, and security module status are resolved lazily
// on first access.
package facts

import (
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const (
	FamilyDebian  = "debian"
	FamilyRedHat  = "redhat"
	FamilySuse    = "suse"
	FamilyArch    = "arch"
	FamilyAlpine  = "alpine"
	FamilyGentoo  = "gentoo"
	FamilyUnknown = ""
)

// OSFacts describes the operating system from /etc/os-release.
type OSFacts struct {
	ID       string `json:"id" yaml:"id"`
	Name     string `json:"name" yaml:"name"`
	Family   string `json:"family" yaml:"family"`
	Version  string `json:"version" yaml:"version"`
	Codename string `json:"codename,omitempty" yaml:"codename,omitempty"`
}

// KernelFacts describes the running kernel.
type KernelFacts struct {
	Name    string `json:"name" yaml:"name"`
	Release string `json:"release" yaml:"release"`
	Machine string `json:"machine" yaml:"machine"`
}

// CPUFacts describes the CPU architecture.
type CPUFacts struct {
	Arch  string `json:"arch" yaml:"arch"`
	Count int    `json:"count" yaml:"count"`
}

// HostFacts describes the local host identity and effective user.
type HostFacts struct {
	Hostname string `json:"hostname" yaml:"hostname"`
	Username string `json:"username" yaml:"username"`
	UID      int    `json:"uid" yaml:"uid"`
	GID      int    `json:"gid" yaml:"gid"`
}

// InitFacts names the detected init system.
type InitFacts struct {
	System string `json:"system,omitempty" yaml:"system,omitempty"`
}

// PackageFacts names the detected package manager.
type PackageFacts struct {
	Manager string `json:"manager,omitempty" yaml:"manager,omitempty"`
}

// SecurityFacts reports mandatory access control module presence.
type SecurityFacts struct {
	SELinux  bool `json:"selinux" yaml:"selinux"`
	AppArmor bool `json:"apparmor" yaml:"apparmor"`
}

// Facts is the typed system-detection cache for one process lifetime.
// The zero value is valid and reports empty facts.
type Facts struct {
	os     OSFacts
	kernel KernelFacts
	cpu    CPUFacts
	host   HostFacts

	initOnce sync.Once
	initSys  string

	pkgOnce sync.Once
	pkgMgr  string

	secOnce sync.Once
	sec     SecurityFacts
}

// Detect performs eager detection of cheap facts. Init system, package
// manager, and security status stay lazy until first queried.
func Detect() *Facts {
	return &Facts{
		os:     detectOS("/etc/os-release"),
		kernel: detectKernel(),
		cpu:    CPUFacts{Arch: runtime.GOARCH, Count: runtime.NumCPU()},
		host:   detectHost(),
	}
}

// Overrides carries injectable fact values for hermetic tests; nil pointers
// leave the corresponding group empty.
type Overrides struct {
	OS      *OSFacts
	Kernel  *KernelFacts
	CPU     *CPUFacts
	Host    *HostFacts
	Init    string
	Package string
}

// ForTesting builds an empty Facts value with the given overrides applied.
// Lazy resolvers are pre-marked resolved so injected values win over real
// detection.
func ForTesting(o Overrides) *Facts {
	f := &Facts{}
	f.initOnce.Do(func() {})
	f.pkgOnce.Do(func() {})
	f.secOnce.Do(func() {})
	if o.OS != nil {
		f.os = *o.OS
	}
	if o.Kernel != nil {
		f.kernel = *o.Kernel
	}
	if o.CPU != nil {
		f.cpu = *o.CPU
	}
	if o.Host != nil {
		f.host = *o.Host
	}
	f.initSys = o.Init
	f.pkgMgr = o.Package
	return f
}

// OS returns operating system facts.
func (f *Facts) OS() OSFacts { return f.os }

// Kernel returns kernel facts.
func (f *Facts) Kernel() KernelFacts { return f.kernel }

// CPU returns CPU facts.
func (f *Facts) CPU() CPUFacts { return f.cpu }

// Host returns host identity facts.
func (f *Facts) Host() HostFacts { return f.host }

// InitSystem returns the detected init system name, e.g. systemd or openrc;
// empty when unknown.
func (f *Facts) InitSystem() string {
	f.initOnce.Do(func() { f.initSys = detectInitSystem() })
	return f.initSys
}

// PackageManager returns the detected package manager binary name,
// e.g. apt, dnf, yum, zypper, pacman, apk; empty when unknown.
func (f *Facts) PackageManager() string {
	f.pkgOnce.Do(func() { f.pkgMgr = detectPackageManager(f.os.Family) })
	return f.pkgMgr
}

// Security returns MAC module presence facts.
func (f *Facts) Security() SecurityFacts {
	f.secOnce.Do(func() { f.sec = detectSecurity() })
	return f.sec
}

type snapshot struct {
	OS       OSFacts       `json:"os" yaml:"os"`
	Kernel   KernelFacts   `json:"kernel" yaml:"kernel"`
	CPU      CPUFacts      `json:"cpu" yaml:"cpu"`
	Host     HostFacts     `json:"host" yaml:"host"`
	Init     InitFacts     `json:"init" yaml:"init"`
	Package  PackageFacts  `json:"package" yaml:"package"`
	Security SecurityFacts `json:"security" yaml:"security"`
}

func (f *Facts) snapshot() snapshot {
	return snapshot{
		OS:       f.OS(),
		Kernel:   f.Kernel(),
		CPU:      f.CPU(),
		Host:     f.Host(),
		Init:     InitFacts{System: f.InitSystem()},
		Package:  PackageFacts{Manager: f.PackageManager()},
		Security: f.Security(),
	}
}

// MarshalJSON resolves lazy facts and emits the full typed snapshot.
func (f *Facts) MarshalJSON() ([]byte, error) { return json.Marshal(f.snapshot()) }

// MarshalYAML resolves lazy facts and emits the full typed snapshot.
func (f *Facts) MarshalYAML() (any, error) { return f.snapshot(), nil }

func detectOS(path string) OSFacts {
	release := parseOSRelease(path)
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

var familyByID = map[string]string{
	"debian": FamilyDebian, "ubuntu": FamilyDebian, "linuxmint": FamilyDebian,
	"kali": FamilyDebian, "pop": FamilyDebian, "raspbian": FamilyDebian,
	"devuan": FamilyDebian,
	"fedora": FamilyRedHat, "rhel": FamilyRedHat, "centos": FamilyRedHat,
	"rocky": FamilyRedHat, "almalinux": FamilyRedHat, "ol": FamilyRedHat,
	"amzn": FamilyRedHat, "scientific": FamilyRedHat, "sangoma": FamilyRedHat,
	"opensuse-leap": FamilySuse, "opensuse-tumbleweed": FamilySuse,
	"sles": FamilySuse, "sled": FamilySuse, "opensuse": FamilySuse,
	"arch": FamilyArch, "manjaro": FamilyArch, "endeavouros": FamilyArch,
	"archarm": FamilyArch,
	"alpine":  FamilyAlpine,
	"gentoo":  FamilyGentoo, "funtoo": FamilyGentoo,
}

// OSFamily maps an os-release ID (with ID_LIKE fallback) onto a coarse
// family constant used for provider selection.
func OSFamily(id, idLike string) string {
	if fam, ok := familyByID[id]; ok {
		return fam
	}
	for _, like := range strings.Fields(idLike) {
		if fam, ok := familyByID[like]; ok {
			return fam
		}
	}
	return FamilyUnknown
}

func detectKernel() KernelFacts {
	k := KernelFacts{Name: runtime.GOOS}
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return k
	}
	k.Name = int8SliceString(uts.Sysname[:])
	k.Release = int8SliceString(uts.Release[:])
	k.Machine = int8SliceString(uts.Machine[:])
	return k
}

func int8SliceString(chars []int8) string {
	b := make([]byte, 0, len(chars))
	for _, c := range chars {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func detectHost() HostFacts {
	h := HostFacts{}
	if hostname, err := os.Hostname(); err == nil {
		h.Hostname = hostname
	}
	if u, err := user.Current(); err == nil {
		h.Username = u.Username
		h.UID, _ = strconv.Atoi(u.Uid)
		h.GID, _ = strconv.Atoi(u.Gid)
	}
	return h
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

var managerCandidates = map[string][]string{
	FamilyDebian: {"apt", "dpkg"},
	FamilyRedHat: {"dnf", "yum"},
	FamilySuse:   {"zypper"},
	FamilyArch:   {"pacman"},
	FamilyAlpine: {"apk"},
	FamilyGentoo: {"emerge"},
}

func detectPackageManager(family string) string {
	for _, candidate := range managerCandidates[family] {
		if _, err := lookPath(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// lookPath is split out for test injection.
var lookPath = exec.LookPath

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
