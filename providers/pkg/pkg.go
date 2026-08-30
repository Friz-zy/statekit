// Package pkg implements Salt's virtual package-manager module concept.
//
// Reference: saltstack/salt/modules/aptpkg.py, yumpkg.py, zypperpkg.py,
// pacmanpkg.py, apkpkg.py @ pinned revision. One command-driven provider
// covers every supported manager through per-manager argv templates; the
// fact-driven selector resolves the active provider at runtime.
package pkg

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
)

// Provider is the virtual pkg interface consumed by exec and state modules.
type Provider interface {
	// Name reports the concrete manager name, e.g. apt, dnf.
	Name() string
	Refresh(ctx context.Context, rt *runtime.Runtime) error
	Install(ctx context.Context, rt *runtime.Runtime, name, version string) error
	Remove(ctx context.Context, rt *runtime.Runtime, name string) error
	Version(ctx context.Context, rt *runtime.Runtime, name string) (string, error)
	LatestVersion(ctx context.Context, rt *runtime.Runtime, name string) (string, error)
	List(ctx context.Context, rt *runtime.Runtime) (map[string]string, error)
}

// AptProvider is an optional capability.  It deliberately is not part of
// Provider: RPM and other providers must not gain an accidental APT command
// path when the virtual pkg module is extended.
type AptProvider interface {
	Provider
	Apt(ctx context.Context, rt *runtime.Runtime, function string, args any) (any, error)
}

// spec drives one manager implementation with argv templates; {name} and
// {version} placeholders expand to the requested values.
type spec struct {
	manager       string   // canonical provider name reported via Name()
	binary        string   // executable that must exist on PATH
	refresh       []string // refresh database argv
	install       []string // install argv (name appended)
	remove        []string // remove argv (name appended)
	versionQuery  []string // installed-version query argv (name appended)
	candidateVer  []string // latest-candidate query argv (name appended)
	listInstalled []string // list all installed packages argv
	parseVersion  func(out string) string
	parseList     func(out string) map[string]string
}

func run(ctx context.Context, rt *runtime.Runtime, argv []string) (string, error) {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return "", res.Err
	}
	return string(res.Stdout), nil
}

func runOK(ctx context.Context, rt *runtime.Runtime, argv []string) error {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return res.Err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s exited with code %d: %s", argv[0], res.ExitCode, res.Stderr)
	}
	return nil
}

func expand(template []string, pairs ...string) []string {
	out := make([]string, 0, len(template)+2)
	for _, arg := range template {
		for i := 0; i < len(pairs); i += 2 {
			arg = strings.ReplaceAll(arg, "{"+pairs[i]+"}", pairs[i+1])
		}
		out = append(out, arg)
	}
	return out
}

// aptSpec queries installed versions via dpkg-query like Salt's aptpkg.
var aptSpec = spec{
	manager:       "apt",
	binary:        "apt-get",
	refresh:       []string{"apt-get", "update"},
	install:       []string{"apt-get", "install", "-y", "{name}"},
	remove:        []string{"apt-get", "remove", "-y", "{name}"},
	versionQuery:  []string{"dpkg-query", "-W", "-f=${Version}\n"},
	listInstalled: []string{"dpkg-query", "-W", "-f=${Package} ${Version}\n"},
}

// rpmLikeSpec covers yum/dnf/zypper variants sharing RPM queries.
var dnfSpec = rpmSpec("dnf")
var yumSpec = rpmSpec("yum")
var zypperSpec = rpmSpec("zypper")

func rpmSpec(manager string) spec {
	s := spec{manager: manager}
	switch manager {
	case "dnf":
		s.binary = "dnf"
		s.refresh = []string{"dnf", "makecache", "--timer"}
	case "yum":
		s.binary = "yum"
		s.refresh = []string{"yum", "-q", "makecache"}
	case "zypper":
		s.binary = "zypper"
		s.refresh = []string{"zypper", "--non-interactive", "refresh"}
	}
	confirm := "--assumeyes"
	if manager == "zypper" {
		confirm = "--non-interactive"
	}
	s.install = []string{s.binary, confirm, "install", "{name}"}
	s.remove = []string{s.binary, confirm, "remove", "{name}"}
	s.versionQuery = []string{"rpm", "-q", "--qf", "%{VERSION}\n"}
	s.listInstalled = []string{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}
	s.candidateVer = []string{s.binary, "list", "--showduplicates"}
	if manager == "zypper" {
		s.candidateVer = []string{"zypper", "search", "--match-exact"}
	}
	return s
}

var pacmanSpec = spec{
	manager:       "pacman",
	binary:        "pacman",
	refresh:       []string{"pacman", "-Sy"},
	install:       []string{"pacman", "-S", "--noconfirm", "{name}"},
	remove:        []string{"pacman", "-R", "--noconfirm", "{name}"},
	versionQuery:  []string{"pacman", "-Q"},
	listInstalled: []string{"pacman", "-Q"},
}

var apkSpec = spec{
	manager:       "apk",
	binary:        "apk",
	refresh:       []string{"apk", "update"},
	install:       []string{"apk", "add", "{name}"},
	remove:        []string{"apk", "del", "{name}"},
	versionQuery:  []string{"apk", "info", "-e"},
	listInstalled: []string{"apk", "info", "-v"},
}

var brewSpec = spec{
	manager:       "brew",
	binary:        "brew",
	refresh:       []string{"brew", "update"},
	install:       []string{"brew", "install", "{name}"},
	remove:        []string{"brew", "uninstall", "{name}"},
	versionQuery:  []string{"brew", "list", "--versions"},
	listInstalled: []string{"brew", "list", "--versions"},
}

var portSpec = spec{
	manager:       "port",
	binary:        "port",
	refresh:       []string{"port", "selfupdate"},
	install:       []string{"port", "install", "{name}"},
	remove:        []string{"port", "uninstall", "{name}"},
	versionQuery:  []string{"port", "installed"},
	listInstalled: []string{"port", "installed"},
}

var wingetSpec = spec{
	manager:       "winget",
	binary:        "winget",
	refresh:       []string{"winget", "source", "update"},
	install:       []string{"winget", "install", "--id", "{name}", "--silent", "--accept-package-agreements", "--accept-source-agreements"},
	remove:        []string{"winget", "uninstall", "--id", "{name}", "--silent", "--accept-source-agreements"},
	versionQuery:  []string{"winget", "show", "--id"},
	listInstalled: []string{"winget", "list"},
}

var chocoSpec = spec{
	manager:       "choco",
	binary:        "choco",
	refresh:       []string{"choco", "outdated", "--limit-output"},
	install:       []string{"choco", "install", "{name}", "-y"},
	remove:        []string{"choco", "uninstall", "{name}", "-y"},
	versionQuery:  []string{"choco", "info"},
	listInstalled: []string{"choco", "list", "--local-only", "--limit-output"},
}

var scoopSpec = spec{
	manager:       "scoop",
	binary:        "scoop",
	refresh:       []string{"scoop", "update"},
	install:       []string{"scoop", "install", "{name}"},
	remove:        []string{"scoop", "uninstall", "{name}"},
	versionQuery:  []string{"scoop", "info"},
	listInstalled: []string{"scoop", "list"},
}

// commandProvider executes a spec against the central Runner.
type commandProvider struct {
	spec spec
}

func (p *commandProvider) Name() string { return p.spec.manager }

func (p *commandProvider) Refresh(ctx context.Context, rt *runtime.Runtime) error {
	return runOK(ctx, rt, p.spec.refresh)
}

func (p *commandProvider) Install(ctx context.Context, rt *runtime.Runtime, name, version string) error {
	if version != "" && version != "latest" && (p.spec.manager == "winget" || p.spec.manager == "choco") {
		args := expand(p.spec.install, "name", name)
		args = append(args, "--version", version)
		return runOK(ctx, rt, args)
	}
	target := name
	if version != "" && version != "latest" {
		target = name + versionSuffix(p.spec.manager, version)
	}
	return runOK(ctx, rt, expand(p.spec.install, "name", target))
}

// versionSuffix formats version pinning per manager conventions.
func versionSuffix(manager, version string) string {
	switch manager {
	case "apt":
		return "=" + version
	case "dnf", "yum":
		return "-" + version
	case "zypper":
		return "=" + version
	case "pacman":
		// Pacman pins versions only from repository metadata; plain install
		// targets latest available.
		return ""
	case "apk":
		return "=" + version
	case "brew", "port", "scoop":
		return "@" + version
	default:
		return "=" + version
	}
}

func (p *commandProvider) Remove(ctx context.Context, rt *runtime.Runtime, name string) error {
	return runOK(ctx, rt, expand(p.spec.remove, "name", name))
}

func (p *commandProvider) Version(ctx context.Context, rt *runtime.Runtime, name string) (string, error) {
	switch p.spec.manager {
	case "brew":
		out, err := run(ctx, rt, append(p.spec.versionQuery, name))
		if err != nil {
			return "", nil
		}
		for _, line := range nonEmptyLines(out) {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == name {
				return strings.Join(fields[1:], ", "), nil
			}
		}
		return "", nil
	case "port":
		out, err := run(ctx, rt, append(p.spec.versionQuery, name))
		if err != nil {
			return "", nil
		}
		for _, line := range nonEmptyLines(out) {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == name && fields[2] == "(active)" {
				return strings.TrimPrefix(fields[1], "@"), nil
			}
		}
		return "", nil
	case "apt":
		out, err := run(ctx, rt, append(p.spec.versionQuery, name))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(out), nil
	case "pacman":
		out, err := run(ctx, rt, append(p.spec.versionQuery, name))
		if err != nil || strings.TrimSpace(out) == "" {
			return "", nil
		}
		fields := strings.Fields(strings.TrimSpace(out))
		if len(fields) >= 2 {
			return fields[len(fields)-1], nil
		}
		return "", nil
	case "apk":
		// apk info -e only reports presence; read full info for version.
		out, err := run(ctx, rt, []string{"apk", "info", name})
		if err != nil {
			return "", nil
		}
		lines := nonEmptyLines(out)
		if len(lines) == 0 {
			return "", nil
		}
		parts := strings.SplitN(lines[0], "-", 2)
		if len(parts) == 2 {
			return parts[1], nil
		}
		return "", nil
	default:
		out, err := run(ctx, rt, append(p.spec.versionQuery, name))
		if err != nil {
			return "", nil
		}
		line := strings.TrimSpace(out)
		if strings.Contains(line, "not installed") || strings.Contains(line, "not compatible") {
			return "", nil
		}
		return line, nil
	}
}

func (p *commandProvider) LatestVersion(ctx context.Context, rt *runtime.Runtime, name string) (string, error) {
	if len(p.spec.candidateVer) == 0 {
		// pacman and apk resolve latest at install time; the installed
		// version is the best available answer without repository parsing.
		return p.Version(ctx, rt, name)
	}
	out, err := run(ctx, rt, expand(p.spec.candidateVer, "name", name))
	if err != nil {
		return "", err
	}
	var best string
	for _, line := range nonEmptyLines(out) {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], name+".") && fields[0] != name {
			continue
		}
		if len(fields) >= 2 {
			best = fields[1]
		}
	}
	return best, nil
}

func (p *commandProvider) List(ctx context.Context, rt *runtime.Runtime) (map[string]string, error) {
	out, err := run(ctx, rt, p.spec.listInstalled)
	if err != nil {
		return map[string]string{}, err
	}
	packages := map[string]string{}
	for _, line := range nonEmptyLines(out) {
		if p.spec.manager == "brew" {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				packages[fields[0]] = strings.Join(fields[1:], ", ")
			}
			continue
		}
		if p.spec.manager == "port" {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[2] == "(active)" {
				packages[fields[0]] = strings.TrimPrefix(fields[1], "@")
			}
			continue
		}
		name, version, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		if _, seen := packages[name]; !seen {
			packages[name] = strings.TrimSpace(version)
		}
	}
	return packages, nil
}

func nonEmptyLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// specsByPreference orders providers for deterministic selection when facts
// leave ambiguity.
var specsByPreference = []spec{aptSpec, dnfSpec, yumSpec, zypperSpec, pacmanSpec, apkSpec, brewSpec, portSpec, wingetSpec, chocoSpec, scoopSpec}

// Register installs every manager provider plus the fact-driven selector.
func Register(registry *runtime.ProviderRegistry) error {
	for _, s := range specsByPreference {
		if err := registry.Register("pkg", s.manager, &commandProvider{spec: s}); err != nil {
			return err
		}
	}
	registry.SetSelector("pkg", Select)
	return nil
}

// Select resolves the pkg provider from local facts.
func Select(f *facts.Facts) (string, error) {
	manager := f.PackageManager()
	if manager == "" {
		return "", fmt.Errorf("no supported package manager detected for family %q", f.OS().Family)
	}
	switch {
	case manager == "apt":
		return "apt", nil
	case manager == "dnf":
		return "dnf", nil
	case manager == "yum":
		return "yum", nil
	case manager == "zypper":
		return "zypper", nil
	case manager == "pacman":
		return "pacman", nil
	case manager == "apk":
		return "apk", nil
	case manager == "brew":
		return "brew", nil
	case manager == "port":
		return "port", nil
	case manager == "winget":
		return "winget", nil
	case manager == "choco":
		return "choco", nil
	case manager == "scoop":
		return "scoop", nil
	default:
		return "", fmt.Errorf("unsupported package manager %q", manager)
	}
}

// Resolve returns the active pkg provider for this host.
func Resolve(rt *runtime.Runtime) (Provider, error) {
	value, name, err := rt.Providers.Resolve(rt.Facts, "pkg")
	if err != nil {
		return nil, err
	}
	provider, ok := value.(Provider)
	if !ok {
		return nil, fmt.Errorf("provider %s does not implement pkg.Provider", name)
	}
	return provider, nil
}

// SortedNames lists provider names deterministically for diagnostics.
func SortedNames(registry *runtime.ProviderRegistry) []string {
	names := registry.Names("pkg")
	sort.Strings(names)
	return names
}
