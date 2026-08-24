package pkgbuild

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// RPM backend: rpmbuild/mock/createrepo orchestration mirroring
// saltstack/salt/modules/rpmbuild_pkgbuild.py @ pinned revision.

// pillarGet resolves optional pillar.get delegates; StateKit has no pillar
// hierarchy, so the default yields the Python str(None) rendering upstream
// produces through its format strings.
var pillarGet = func(rt *runtime.Runtime, key string, def any) any {
	if _, ok := rt.Exec.Get("pillar.get"); !ok {
		return def
	}
	res, err := rt.Exec.Call(context.Background(), rt, "pillar.get",
		map[string]any{"key": key})
	if err != nil {
		return def
	}
	return res
}

func validProtoReCheck(path string) bool { return validProtoRe.MatchString(path) }

// createRpmmacros mirrors _create_rpmmacros: ~/.rpmmacros with the fixed
// digest/signature definitions plus the rpmbuild/mock directories.
func createRpmmacros(rt *runtime.Runtime, runas string) {
	home := homeOf(runas)
	rpmbuilddir := filepath.Join(home, "rpmbuild")
	mkDirs(rt, rpmbuilddir)
	mockdir := filepath.Join(home, "mock")
	mkDirs(rt, mockdir)

	rpmmacros := filepath.Join(home, ".rpmmacros")
	content := fmt.Sprintf("%%_topdir %s\n", rpmbuilddir) +
		"%signature gpg\n" +
		"%_source_filedigest_algorithm 8\n" +
		"%_binary_filedigest_algorithm 8\n" +
		"%_gpg_name packaging@saltstack.com\n"
	rt.FS.WriteFile(rpmmacros, []byte(content), 0o644)
}

// mkDirs creates a directory tree, standing in for file.makedirs_perms
// (group ownership adjustments degrade under the single-user model).
func mkDirs(rt *runtime.Runtime, path string) {
	rt.FS.MkdirAll(path, 0o755)
}

// mkTree mirrors _mk_tree: a temp base with the five rpm subdirectories.
func mkTree(rt *runtime.Runtime) (string, error) {
	basedir, err := rt.FS.MkdirTemp("", "")
	if err != nil {
		return "", err
	}
	for _, path := range []string{"BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS"} {
		if err := rt.FS.MkdirAll(filepath.Join(basedir, path), 0o755); err != nil {
			return "", err
		}
	}
	return basedir, nil
}

// fetchInto mirrors cp.get_url usage in _get_spec/_get_src: local paths are
// copied to dest, remote schemes surface UnsupportedError. Returns dest.
func fetchInto(ctx context.Context, rt *runtime.Runtime, src, dest, saltenv string) (string, error) {
	resolved, err := cpGetURL(ctx, rt, src, dest, saltenv)
	if err != nil {
		return "", err
	}
	if err := copyLocal(rt, resolved, dest); err != nil {
		return "", err
	}
	return dest, nil
}

// hasURLScheme mirrors urllib.parse.urlparse(source).scheme probes.
func hasURLScheme(source string) bool {
	for i := 0; i < len(source); i++ {
		c := source[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9', c == '+', c == '-', c == '.':
			continue
		case c == ':':
			return i > 0
		default:
			return false
		}
	}
	return false
}

// getDistset mirrors _get_distset's el/amzn2 dist defines.
func getDistset(tgt string) string {
	tgtattrs := strings.Split(tgt, "-")
	dist := ""
	if len(tgtattrs) > 0 && tgtattrs[0] == "amzn2" {
		dist = fmt.Sprintf("--define \"dist .%s\"", tgtattrs[0])
	} else if len(tgtattrs) > 1 {
		switch tgtattrs[1] {
		case "6", "7", "8":
			dist = fmt.Sprintf("--define \"dist .el%s\"", tgtattrs[1])
		}
	}
	return dist
}

// getDeps mirrors _get_deps: local/remote dep rpms staged into tree_base,
// returning the space-joined absolute list.
func getDeps(ctx context.Context, rt *runtime.Runtime, deps any, treeBase, saltenv string) (string, error) {
	if deps == nil {
		return "", nil
	}
	var items []string
	switch v := deps.(type) {
	case []string:
		items = v
	case []any:
		for _, item := range v {
			items = append(items, scalarString(item))
		}
	case string:
		items = strings.Split(v, ",")
	default:
		return "", fmt.Errorf("'deps' must be a Python list or comma-separated string")
	}
	depsList := ""
	for _, deprpm := range items {
		dest := filepath.Join(treeBase, filepath.Base(deprpm))
		if hasURLScheme(deprpm) {
			if _, err := fetchInto(ctx, rt, deprpm, dest, saltenv); err != nil {
				return "", err
			}
		} else if err := copyLocal(rt, deprpm, dest); err != nil {
			return "", err
		}
		depsList += " " + dest
	}
	return depsList, nil
}

// sourcesList normalizes the sources kwarg: comma-string or list.
func sourcesList(sources any) []string {
	switch v := sources.(type) {
	case nil:
		return nil
	case string:
		return strings.Split(v, ",")
	case []string:
		return v
	case []any:
		var out []string
		for _, item := range v {
			out = append(out, scalarString(item))
		}
		return out
	}
	return []string{scalarString(sources)}
}

// rpmMakeSrcPkg mirrors make_src_pkg: spec+sources staged into an rpm tree,
// then `rpmbuild -bs` with the pinned dist .el6 define; SRPMS copied out.
func rpmMakeSrcPkg(
	ctx context.Context,
	rt *runtime.Runtime,
	destDir, spec string,
	sources any,
	env map[string]any,
	saltenv, runas string,
) (any, error) {
	envArgs := buildEnvArgs(env)
	createRpmmacros(rt, runas)
	treeBase, err := mkTree(rt)
	if err != nil {
		return nil, err
	}
	specPath, err := fetchInto(ctx, rt, spec, filepath.Join(treeBase, "SPECS", filepath.Base(spec)), saltenv)
	if err != nil {
		return nil, err
	}

	for _, src := range sourcesList(sources) {
		dest := filepath.Join(treeBase, "SOURCES", filepath.Base(src))
		if hasURLScheme(src) {
			if _, err := fetchInto(ctx, rt, src, dest, saltenv); err != nil {
				return nil, err
			}
		} else if err := copyLocal(rt, src, dest); err != nil {
			return nil, err
		}
	}

	cmd := fmt.Sprintf("rpmbuild --verbose --define \"_topdir %s\" -bs --define \"dist .el6\" %s",
		treeBase, specPath)
	retrc := runRetcode(ctx, rt, "", envArgs, cmd)
	if retrc != 0 {
		return nil, fmt.Errorf(
			"Make source package for destination directory %s, spec %s, sources %v,"+
				" failed with return error %d, check logs for further details",
			destDir, spec, sourcesList(sources), retrc)
	}

	srpms := filepath.Join(treeBase, "SRPMS")
	ret := []string{}
	mkDirs(rt, destDir)
	entries, _ := rt.FS.ReadDir(srpms)
	for _, entry := range entries {
		full := filepath.Join(srpms, entry.Name())
		tgt := filepath.Join(destDir, entry.Name())
		data, rerr := rt.FS.ReadFile(full)
		if rerr != nil {
			return nil, rerr
		}
		if werr := rt.FS.WriteFile(tgt, data, 0o644); werr != nil {
			return nil, werr
		}
		ret = append(ret, tgt)
	}
	return ret, nil
}

// rpmBuild mirrors build: SRPM creation followed by the mock
// init/install/build cycle per SRPM, classifying results into source
// packages, binary packages, and logs.
func rpmBuild(
	ctx context.Context,
	rt *runtime.Runtime,
	runas, tgt, destDir, spec string,
	sources, deps any,
	env map[string]any,
	saltenv, logDir string,
) (any, error) {
	ret := map[string]any{}
	mkDirs(rt, destDir)
	srpmDir := filepath.Join(destDir, "SRPMS")
	srpmBuildDir, err := rt.FS.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}
	srpmsAny, err := rpmMakeSrcPkg(ctx, rt, srpmBuildDir, spec, sources, env, saltenv, runas)
	if err != nil {
		rt.FS.RemoveAll(srpmBuildDir)
		return ret, nil
	}
	srpms, _ := srpmsAny.([]string)

	distset := getDistset(tgt)

	noclean := ""
	depsDir, derr := rt.FS.MkdirTemp("", "")
	if derr != nil {
		return nil, derr
	}
	depsList, err := getDeps(ctx, rt, deps, depsDir, saltenv)
	if err != nil {
		return nil, err
	}

	retrc := 0
	envArgs := buildEnvArgs(env)
	for _, srpm := range srpms {
		resultsDir, rerr := rt.FS.MkdirTemp("", "")
		if rerr != nil {
			return nil, rerr
		}
		func() {
			cmd := fmt.Sprintf("mock --root=%s --resultdir=%s --init", tgt, resultsDir)
			retrc |= runRetcode(ctx, rt, "", envArgs, cmd)
			if depsList != "" && !isSpaceOnly(depsList) {
				cmd = fmt.Sprintf("mock --root=%s --resultdir=%s --install %s %s",
					tgt, resultsDir, depsList, noclean)
				retrc |= runRetcode(ctx, rt, "", envArgs, cmd)
				noclean += " --no-clean"
			}
			cmd = fmt.Sprintf("mock --root=%s --resultdir=%s %s %s %s",
				tgt, resultsDir, distset, noclean, srpm)
			retrc |= runRetcode(ctx, rt, "", envArgs, cmd)
			logQuery := []string{"rpm", "-qp", "--queryformat",
				fmt.Sprintf("%s/%%{name}/%%{version}-%%{release}", logDir), srpm}
			logCmd := runtime.Command(logQuery...)
			logRes := rt.Runner.Run(ctx, logCmd)
			logDest := strings.TrimSpace(string(logRes.Stdout))
			entries, _ := rt.FS.ReadDir(resultsDir)
			for _, entry := range entries {
				filename := entry.Name()
				full := filepath.Join(resultsDir, filename)
				data, rerr := rt.FS.ReadFile(full)
				if rerr != nil {
					continue
				}
				switch {
				case strings.HasSuffix(filename, "src.rpm"):
					sdest := filepath.Join(srpmDir, filename)
					mkDirs(rt, srpmDir)
					rt.FS.WriteFile(sdest, data, 0o644)
					ret["Source Packages"] = appendStringList(ret, "Source Packages", sdest)
				case strings.HasSuffix(filename, ".rpm"):
					bdist := filepath.Join(destDir, filename)
					rt.FS.WriteFile(bdist, data, 0o644)
					ret["Packages"] = appendStringList(ret, "Packages", bdist)
				default:
					logFile := filepath.Join(logDest, filename)
					mkDirs(rt, logDest)
					rt.FS.WriteFile(logFile, data, 0o644)
					ret["Log Files"] = appendStringList(ret, "Log Files", logFile)
				}
			}
			rt.FS.RemoveAll(resultsDir)
		}()
	}
	if retrc != 0 {
		return nil, fmt.Errorf(
			"Building packages for destination directory %s, spec %s, sources %v,"+
				" failed with return error %d, check logs for further details",
			destDir, spec, sourcesList(sources), retrc)
	}
	rt.FS.RemoveAll(depsDir)
	rt.FS.RemoveAll(srpmBuildDir)
	return ret, nil
}

func appendStringList(ret map[string]any, key, value string) []string {
	list, _ := ret[key].([]string)
	list = append(list, value)
	return list
}

func isSpaceOnly(s string) bool { return strings.TrimSpace(s) == "" }

// buildEnvArgs flattens the env dict into KEY=VALUE Runner entries.
func buildEnvArgs(env map[string]any) []string {
	if env == nil {
		return nil
	}
	var out []string
	for _, key := range sortedEnvKeys(env) {
		out = append(out, fmt.Sprintf("%s=%s", key, scalarString(env[key])))
	}
	return out
}

func sortedEnvKeys(env map[string]any) []string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sortStrings(keys)
	return keys
}

func sortStrings(items []string) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j] < items[j-1]; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

// scalarString renders values like Python str() for env/command assembly.
func scalarString(v any) string {
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
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	case int:
		return fmt.Sprintf("%d", x)
	}
	return fmt.Sprintf("%v", v)
}

// getGPGKeyResources mirrors _get_gpg_key_resources. Without a pillar.get
// delegate the key filenames render as <gnupghome>/None exactly like
// upstream's format strings, and the gpg.import_key delegate absence maps
// onto the caught-SaltInvocationError re-raise.
func getGPGKeyResources(ctx context.Context, rt *runtime.Runtime, keyid string, env map[string]any, usePassphrase bool, gnupghome, runas string) (bool, string, string, string, error) {
	useGPGAgent := rt.Facts.OS().Family == "redhat" && osMajorRelease(rt) >= 8

	localKeyid := ""
	defineGPGName := ""
	phrase := ""
	keygrip := ""
	fingerprint := ""

	if keyid == "" {
		return useGPGAgent, "", "", "", nil
	}

	pubName := scalarString(pillarGet(rt, "gpg_pkg_pub_keyname", nil))
	privName := scalarString(pillarGet(rt, "gpg_pkg_priv_keyname", nil))
	pkgPubKeyFile := fmt.Sprintf("%s/%s", gnupghome, pubName)
	pkgPrivKeyFile := fmt.Sprintf("%s/%s", gnupghome, privName)

	importOK := true
	if _, ok := rt.Exec.Get("gpg.import_key"); ok {
		for _, filename := range []string{pkgPubKeyFile, pkgPrivKeyFile} {
			if _, err := rt.Exec.Call(ctx, rt, "gpg.import_key", map[string]any{
				"user": runas, "filename": filename, "gnupghome": gnupghome,
			}); err != nil {
				importOK = false
				break
			}
		}
	} else {
		importOK = false
	}
	if !importOK {
		return false, "", "", "", fmt.Errorf(
			"Public and Private key files associated with Pillar data and 'keyid' "+
				"%s could not be found", keyid)
	}

	if _, ok := rt.Exec.Get("gpg.list_keys"); ok {
		res, err := rt.Exec.Call(ctx, rt, "gpg.list_keys", map[string]any{
			"user": runas, "gnupghome": gnupghome,
		})
		if err == nil {
			if keys, ok := res.([]any); ok {
				for _, raw := range keys {
					gpgKey, ok := raw.(map[string]any)
					if !ok {
						continue
					}
					keyidFull, _ := gpgKey["keyid"].(string)
					if len(keyidFull) > 8 && keyid == keyidFull[8:] {
						localKeyid = keyidFull
						if fp, ok := gpgKey["fingerprint"].(string); ok {
							fingerprint = fp
							if useGPGAgent {
								keygrip = fp
							}
						}
						break
					}
				}
			}
		}
	}

	if useGPGAgent {
		out := runAll(ctx, rt, "", buildEnvArgs(env), "gpg --with-keygrip --list-secret-keys")
		lines := strings.Split(out["stdout"].(string), "\n")
		found := false
		for i := 0; i < len(lines)-2; i++ {
			if strings.HasPrefix(lines[i], "sec") &&
				strings.TrimSpace(lines[i+1]) == fingerprint {
				parts := strings.Split(lines[i+2], "=")
				if len(parts) > 1 {
					keygrip = strings.TrimSpace(parts[1])
					found = true
				}
				break
			}
		}
		if !found {
			return false, "", "", "", fmt.Errorf(
				"unable to find keygrip associated with fingerprint '%s' for keyid '%s'",
				fingerprint, localKeyid)
		}
	}

	if localKeyid == "" {
		return false, "", "", "", fmt.Errorf(
			"The key ID '%s' was not found in GnuPG keyring at '%s'", keyid, gnupghome)
	}

	if usePassphrase {
		phrase = scalarString(pillarGet(rt, "gpg_passphrase", nil))
		if useGPGAgent {
			utilName := "/usr/libexec/gpg-preset-passphrase"
			if info, err := rt.FS.Stat(utilName); err != nil || info.IsDir() {
				return false, "", "", "", fmt.Errorf("utility '%s' needs to be installed", utilName)
			}
			cmd := fmt.Sprintf("/usr/libexec/gpg-preset-passphrase --verbose --preset "+
				"--passphrase \"%s\" %s", phrase, keygrip)
			if runRetcode(ctx, rt, "", buildEnvArgs(env), cmd) != 0 {
				return false, "", "", "", fmt.Errorf(
					"Failed to preset passphrase, error %d, check logs for further details", 1)
			}
		}
	}

	// Upstream builds the addsign defines from the first uid; StateKit has
	// no gpg module yet, so the definition stays empty unless a future phase
	// supplies uid resolution (documented divergence).
	_ = defineGPGName

	cmd := fmt.Sprintf("rpm --import %s", pkgPubKeyFile)
	if runRetcode(ctx, rt, "", nil, cmd) != 0 {
		return false, "", "", "", fmt.Errorf(
			"Failed to import public key from file %s with return "+
				"error %d, check logs for further details", pkgPubKeyFile, 1)
	}

	return useGPGAgent, localKeyid, defineGPGName, phrase, nil
}

// signFileWithDefines mirrors the non-interactive arm of _sign_file: direct
// `rpm --addsign` execution. The interactive passphrase prompt loop is not
// ported (salt.utils.vt is unavailable and unreachable without pillar).
func signFileWithDefines(ctx context.Context, rt *runtime.Runtime, defineGPGName, absFile string) error {
	exitCode := runRetcode(ctx, rt, "", nil,
		fmt.Sprintf("rpm %s --addsign %s", defineGPGName, absFile))
	if exitCode != 0 {
		return fmt.Errorf("Signing file %s failed with proc.status %d", absFile, exitCode)
	}
	return nil
}

// signFileWithGPGAgent mirrors _sign_files_with_gpg_agent.
func signFileWithGPGAgent(ctx context.Context, rt *runtime.Runtime, localKeyid, absFile, repoDir string, env map[string]any) error {
	cmd := fmt.Sprintf("rpmsign --verbose  --key-id=%s --addsign %s", localKeyid, absFile)
	if runRetcode(ctx, rt, repoDir, buildEnvArgs(env), cmd) != 0 {
		return fmt.Errorf("Signing encountered errors for command '%s', "+
			"return error %d, check logs for further details", cmd, 1)
	}
	return nil
}

// rpmMakeRepo mirrors make_repo: optional signing of every rpm followed by
// `createrepo --update`, returning the full result dict.
func rpmMakeRepo(
	ctx context.Context,
	rt *runtime.Runtime,
	repoDir, keyid string,
	env map[string]any,
	usePassphrase bool,
	gnupghome string,
	timeout float64,
) (map[string]any, error) {
	runas := "root"
	home := homeOf(runas)
	rpmmacros := filepath.Join(home, ".rpmmacros")
	if _, err := rt.FS.Stat(rpmmacros); err != nil {
		createRpmmacros(rt, runas)
	}

	if gnupghome != "" && env == nil {
		env = map[string]any{"GNUPGHOME": gnupghome}
	}

	useGPGAgent, localKeyid, defineGPGName, _, err :=
		getGPGKeyResources(ctx, rt, keyid, env, usePassphrase, gnupghome, runas)
	if err != nil {
		return nil, err
	}
	_ = timeout

	entries, _ := rt.FS.ReadDir(repoDir)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".rpm") {
			continue
		}
		absFile := filepath.Join(repoDir, entry.Name())
		var serr error
		if useGPGAgent {
			serr = signFileWithGPGAgent(ctx, rt, localKeyid, absFile, repoDir, env)
		} else {
			serr = signFileWithDefines(ctx, rt, defineGPGName, absFile)
		}
		if serr != nil {
			return nil, serr
		}
	}

	cmd := fmt.Sprintf("createrepo --update %s", repoDir)
	result := runAll(ctx, rt, "", buildEnvArgs(env), cmd)
	return result, nil
}

// ensure os stays referenced for future user lookups.
var _ = os.Getenv
