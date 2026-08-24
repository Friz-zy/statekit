// Package pkgbuild implements Salt's package-builder surface:
// pkgbuild.make_src_pkg, pkgbuild.build, and pkgbuild.make_repo, with the
// rpm backend (rpmbuild/mock/createrepo) on RedHat/SUSE families and the
// deb backend (pbuilder/debuild/reprepro) on Debian-family hosts.
//
// Reference: saltstack/salt/modules/rpmbuild_pkgbuild.py and
// saltstack/salt/modules/debuild_pkgbuild.py @ pinned revision
// (references/salt.lock).
//
// Contract notes (init.md section 28):
//
//   - Both backends select through the same OS-family dispatch used by the
//     pkg repo functions, mirroring __virtual__.
//   - cp.get_url is unavailable until the cp family lands: readable local
//     absolute paths pass through unchanged; remote and salt:// schemes
//     surface UnsupportedError (salt:// permanently excluded,
//     master-minion architecture).
//   - GPG signing keyed by `keyid` depends on pillar data for the key
//     material; StateKit has no pillar hierarchy, so keyid flows raise the
//     verbatim upstream invocation error unless a pillar.get delegate is
//     registered. The interactive salt.utils.vt passphrase loops are
//     therefore unreachable and not ported; non-interactive signing argv
//     (rpmsign/rpm --addsign/debsign) is preserved as contracts.
//   - runas is accepted for parity but StateKit executes single-user;
//     ownership adjustments are best-effort no-ops rather than chugid
//     switches (documented divergence).
package pkgbuild

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
)

// --- hooks -------------------------------------------------------------------

// whichBin resolves build utilities like salt.utils.path.which; injectable.
var whichBin = func(name string) string { return lookPathBin(name) }

// homeOf mirrors os.path.expanduser("~"+runas); injectable for suites.
var homeOf = func(runas string) string {
	if runas == "" || runas == "root" {
		if h, err := os.UserHomeDir(); err == nil && runas == "" {
			return h
		}
		return "/root"
	}
	return "/home/" + runas
}

// cpGetURL stands in for cp.get_url: remote schemes surface
// UnsupportedError until the cp family lands; readable absolute local
// paths are copied to dest by the caller-side helper.
var cpGetURL = func(_ context.Context, _ *runtime.Runtime, path, dest, _ string) (string, error) {
	if validProtoRe.MatchString(path) {
		return "", &runtime.UnsupportedError{Kind: "function", Name: "cp.get_url"}
	}
	return path, nil
}

// validProtoRe mirrors salt.modules.config.valid_fileproto.
var validProtoRe = regexp.MustCompile(`^(?:salt|https?|ftp|file)://`)

// backendOf mirrors the two __virtual__ guards: rpm toolchain on
// RedHat/SUSE families, deb toolchain on Debian family.
func backendOf(rt *runtime.Runtime) (string, error) {
	if rt.Facts == nil {
		return "", fmt.Errorf("The pkgbuild module could not be loaded: unsupported OS family")
	}
	switch rt.Facts.OS().Family {
	case facts.FamilyRedHat, facts.FamilySuse:
		return "rpm", nil
	case facts.FamilyDebian:
		return "deb", nil
	}
	return "", fmt.Errorf("The pkgbuild module could not be loaded: unsupported OS family")
}

func lookPathBin(exe string) string {
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(dir + "/" + exe); err == nil {
			return dir + "/" + exe
		}
	}
	return ""
}

// osMajorRelease mirrors the osmajorrelease grain probe used by the gpg
// agent selection; best-effort parse of the OS version prefix.
func osMajorRelease(rt *runtime.Runtime) int {
	version := rt.Facts.OS().Version
	for i := 0; i < len(version); i++ {
		if version[i] < '0' || version[i] > '9' {
			var n int
			fmt.Sscanf(version[:i], "%d", &n)
			return n
		}
	}
	var n int
	fmt.Sscanf(version, "%d", &n)
	return n
}

// shellSplit mirrors salt.utils.shlex.split for string commands passed to
// cmd.run_all with python_shell=False: whitespace separation honoring
// double/single quotes and backslash escapes outside quotes.
func shellSplit(cmd string) []string {
	var args []string
	var cur strings.Builder
	has := false
	inDouble := false
	inSingle := false
	escaped := false
	for _, c := range cmd {
		switch {
		case escaped:
			cur.WriteRune(c)
			escaped = false
		case c == '\\' && !inSingle && !inDouble:
			escaped = true
		case c == '"' && !inSingle:
			inDouble = !inDouble
			has = true
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			has = true
		case (c == ' ' || c == '\t') && !inSingle && !inDouble:
			if cur.Len() > 0 || has {
				args = append(args, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 || has {
		args = append(args, cur.String())
	}
	return args
}

// runRetcode executes a command string through the central Runner after
// shlex splitting, returning its exit code like cmd.retcode.
func runRetcode(ctx context.Context, rt *runtime.Runtime, cwd string, env []string, cmd string) int {
	argv := shellSplit(cmd)
	if len(argv) == 0 {
		return 0
	}
	c := runtime.Command(argv...)
	c.Dir = cwd
	c.Env = env
	res := rt.Runner.Run(ctx, c)
	if res.Err != nil {
		return -1
	}
	return res.ExitCode
}

// runAll executes a command string returning the cmd.run_all-shaped dict.
func runAll(ctx context.Context, rt *runtime.Runtime, cwd string, env []string, cmd string) map[string]any {
	argv := shellSplit(cmd)
	c := runtime.Command(argv...)
	c.Dir = cwd
	c.Env = env
	res := rt.Runner.Run(ctx, c)
	exitCode := res.ExitCode
	if res.Err != nil {
		exitCode = -1
	}
	return map[string]any{
		"pid":     nil,
		"retcode": exitCode,
		"stdout":  string(res.Stdout),
		"stderr":  string(res.Stderr),
	}
}

// copyLocal copies one readable local file to dest through the injectable
// filesystem, standing in for shutil.copy.
func copyLocal(rt *runtime.Runtime, src, dest string) error {
	data, err := rt.FS.ReadFile(src)
	if err != nil {
		return err
	}
	return rt.FS.WriteFile(dest, data, 0o644)
}

// --- registered functions ------------------------------------------------------

type MakeSrcPkgArgs struct {
	DestDir string         `statekit:"required,name=dest_dir"`
	Spec    string         `statekit:"required"`
	Sources any            `statekit:"name=sources"` // string or list
	Env     map[string]any `statekit:"name=env"`
	// template is accepted for parity; templating engines are excluded
	Template *string `statekit:"name=template"`
	Saltenv  string  `statekit:"name=saltenv"`
	Runas    string  `statekit:"name=runas"`
}

type makeSrcPkgFunc struct{}

func (makeSrcPkgFunc) Name() string { return "pkgbuild.make_src_pkg" }
func (makeSrcPkgFunc) Args() any    { return MakeSrcPkgArgs{} }

func (makeSrcPkgFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*MakeSrcPkgArgs)
	saltenv := a.Saltenv
	if saltenv == "" {
		saltenv = "base"
	}
	runas := a.Runas
	if runas == "" {
		runas = "root"
	}
	backend, err := backendOf(rt)
	if err != nil {
		return nil, err
	}
	if backend == "rpm" {
		return rpmMakeSrcPkg(ctx, rt, a.DestDir, a.Spec, a.Sources, a.Env, saltenv, runas)
	}
	return debMakeSrcPkg(ctx, rt, a.DestDir, a.Spec, a.Sources, a.Env, saltenv, runas)
}

type BuildArgs struct {
	Runas   string         `statekit:"required,name=runas"`
	Tgt     string         `statekit:"required,name=tgt"`
	DestDir string         `statekit:"required,name=dest_dir"`
	Spec    string         `statekit:"required,name=spec"`
	Sources any            `statekit:"name=sources"`
	Deps    any            `statekit:"name=deps"`
	Env     map[string]any `statekit:"name=env"`
	// template is accepted for parity; templating engines are excluded
	Template *string `statekit:"name=template"`
	Saltenv  string  `statekit:"name=saltenv"`
	LogDir   string  `statekit:"name=log_dir"`
}

type buildFunc struct{}

func (buildFunc) Name() string { return "pkgbuild.build" }
func (buildFunc) Args() any    { return BuildArgs{} }

func (buildFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*BuildArgs)
	saltenv := a.Saltenv
	if saltenv == "" {
		saltenv = "base"
	}
	runas := a.Runas
	if runas == "" {
		runas = "root"
	}
	logDir := a.LogDir
	if logDir == "" {
		logDir = "/var/log/salt/pkgbuild"
	}
	backend, err := backendOf(rt)
	if err != nil {
		return nil, err
	}
	if backend == "rpm" {
		return rpmBuild(ctx, rt, runas, a.Tgt, a.DestDir, a.Spec, a.Sources, a.Deps, a.Env, saltenv, logDir)
	}
	return debBuild(ctx, rt, runas, a.Tgt, a.DestDir, a.Spec, a.Sources, a.Deps, a.Env, saltenv, logDir)
}

type MakeRepoArgs struct {
	RepoDir       string         `statekit:"required,name=repodir"`
	Keyid         *string        `statekit:"name=keyid"`
	Env           map[string]any `statekit:"name=env"`
	UsePassphrase bool           `statekit:"name=use_passphrase"`
	GnupgHome     string         `statekit:"name=gnupghome"`
	Runas         string         `statekit:"name=runas"`
	Timeout       float64        `statekit:"name=timeout"`
}

type makeRepoFunc struct{}

func (makeRepoFunc) Name() string { return "pkgbuild.make_repo" }
func (makeRepoFunc) Args() any    { return MakeRepoArgs{} }

func (makeRepoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*MakeRepoArgs)
	gnupghome := a.GnupgHome
	if gnupghome == "" {
		gnupghome = "/etc/salt/gpgkeys"
	}
	timeout := a.Timeout
	if timeout == 0 {
		timeout = 15.0
	}
	keyid := ""
	if a.Keyid != nil {
		keyid = *a.Keyid
	}
	backend, err := backendOf(rt)
	if err != nil {
		return nil, err
	}
	if backend == "rpm" {
		return rpmMakeRepo(ctx, rt, a.RepoDir, keyid, a.Env, a.UsePassphrase, gnupghome, timeout)
	}
	return debMakeRepo(ctx, rt, a.RepoDir, keyid, a.Env, a.UsePassphrase, gnupghome, timeout)
}

// Register installs all pkgbuild execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		makeSrcPkgFunc{},
		buildFunc{},
		makeRepoFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
