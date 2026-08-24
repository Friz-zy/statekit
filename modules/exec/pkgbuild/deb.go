package pkgbuild

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// Debian backend: pbuilder/debuild/reprepro orchestration mirroring
// saltstack/salt/modules/debuild_pkgbuild.py @ pinned revision.

// getBuildEnv mirrors _get_build_env: KEY=VALUE plus export lines.
func getBuildEnv(env map[string]any) string {
	out := ""
	if env == nil {
		return out
	}
	for _, key := range sortedEnvKeys(env) {
		out += fmt.Sprintf("%s=%s\n", key, scalarString(env[key]))
		out += fmt.Sprintf("export %s\n", key)
	}
	return out
}

// getRepoOptionsEnv mirrors _get_repo_options_env: only OPTIONS values.
func getRepoOptionsEnv(env map[string]any) string {
	out := ""
	if env == nil {
		return out
	}
	for _, key := range sortedEnvKeys(env) {
		if key == "OPTIONS" {
			out += fmt.Sprintf("%s\n", scalarString(env[key]))
		}
	}
	return out
}

// repoDistField describes one env key's control tuple from the upstream
// dflts_dict: kind (Mandatory/Optional/Ignore), field label, default.
type repoDistField struct {
	kind  byte // 'M', 'O', 'I'
	label string
	def   string
}

var repoDistDefaults = map[string]repoDistField{
	"OPTIONS":     {'I', "", "processed by getRepoOptionsEnv"},
	"ORIGIN":      {'O', "Origin", "SaltStack"},
	"LABEL":       {'O', "Label", "salt_debian"},
	"SUITE":       {'O', "Suite", "stable"},
	"VERSION":     {'O', "Version", "9.0"},
	"CODENAME":    {'M', "Codename", "stretch"},
	"ARCHS":       {'M', "Architectures", "i386 amd64 source"},
	"COMPONENTS":  {'M', "Components", "main"},
	"DESCRIPTION": {'O', "Description", "SaltStack debian package repo"},
}

// getRepoDistsEnv mirrors _get_repo_dists_env. Upstream quirks preserved:
// with env=None every Mandatory default renders; with an env dict, absent
// mandatory keys are silently dropped (the back-fill loop is dead code
// because it iterates the same keys that were already recorded), leaving
// codename empty; unknown keys pass through verbatim. Field order follows
// sorted keys where Python preserves request order (documented divergence).
func getRepoDistsEnv(env map[string]any) (string, string) {
	envDists := ""
	codename := ""
	if env == nil {
		keys := make([]string, 0, len(repoDistDefaults))
		for key, field := range repoDistDefaults {
			if field.kind == 'M' {
				keys = append(keys, key)
			}
		}
		sortStrings(keys)
		for _, key := range keys {
			field := repoDistDefaults[key]
			envDists += fmt.Sprintf("%s: %s\n", field.label, field.def)
			if key == "CODENAME" {
				codename = field.def
			}
		}
		return codename, envDists
	}
	for _, key := range sortedEnvKeys(env) {
		value := scalarString(env[key])
		if field, known := repoDistDefaults[key]; known {
			if field.kind == 'M' && key == "CODENAME" {
				codename = value
			}
			if field.kind != 'I' {
				envDists += fmt.Sprintf("%s: %s\n", field.label, value)
			}
		} else {
			envDists += fmt.Sprintf("%s: %s\n", key, value)
		}
	}
	return codename, envDists
}

// createPbuilders mirrors _create_pbuilders: ~/.pbuilderrc must already
// exist; env overrides are appended.
func createPbuilders(ctx context.Context, rt *runtime.Runtime, env map[string]any, runas string) error {
	pbuilderrc := filepath.Join(homeOf(runas), ".pbuilderrc")
	if info, err := rt.FS.Stat(pbuilderrc); err != nil || info.IsDir() {
		return fmt.Errorf("pbuilderrc environment is incorrectly setup")
	}
	envOverrides := getBuildEnv(env)
	if strings.TrimSpace(envOverrides) != "" {
		existing, err := rt.FS.ReadFile(pbuilderrc)
		if err != nil {
			return err
		}
		rt.FS.WriteFile(pbuilderrc, append(existing, []byte(envOverrides)...), 0o644)
	}
	return nil
}

func debMkTree(rt *runtime.Runtime) (string, error) {
	return rt.FS.MkdirTemp("", "")
}

// debGetSpec mirrors the deb _get_spec: spec staged at tree base.
func debGetSpec(ctx context.Context, rt *runtime.Runtime, treeBase, spec, saltenv string) (string, error) {
	dest := filepath.Join(treeBase, filepath.Base(spec))
	return fetchInto(ctx, rt, spec, dest, saltenv)
}

// debGetSrc mirrors the deb _get_src.
func debGetSrc(ctx context.Context, rt *runtime.Runtime, treeBase, source, saltenv string) error {
	dest := filepath.Join(treeBase, filepath.Base(source))
	if hasURLScheme(source) {
		_, err := fetchInto(ctx, rt, source, dest, saltenv)
		return err
	}
	return copyLocal(rt, source, dest)
}

// debMakeSrcPkg mirrors make_src_pkg: pbuilder env prep, the salt-tarball
// rename dance (- to _ plus the "+ds" suffix), debian tarball repack, and
// `debuild -S -uc -us -sa`. A .dsc spec passes the whole tree through.
func debMakeSrcPkg(
	ctx context.Context,
	rt *runtime.Runtime,
	destDir, spec string,
	sources any,
	env map[string]any,
	saltenv, runas string,
) (any, error) {
	runas = "root"
	if err := createPbuilders(ctx, rt, env, runas); err != nil {
		return nil, err
	}
	treeBase, err := debMkTree(rt)
	if err != nil {
		return nil, err
	}
	ret := []string{}
	mkDirs(rt, destDir)

	envArgs := buildEnvArgs(env)
	specPathfile, err := debGetSpec(ctx, rt, treeBase, spec, saltenv)
	if err != nil {
		return nil, err
	}

	for _, src := range sourcesList(sources) {
		if err := debGetSrc(ctx, rt, treeBase, src, saltenv); err != nil {
			return nil, err
		}
	}

	// A .dsc spec assumes sources are pre-built: pass everything through.
	if strings.HasSuffix(specPathfile, ".dsc") {
		entries, _ := rt.FS.ReadDir(treeBase)
		for _, entry := range entries {
			full := filepath.Join(treeBase, entry.Name())
			trgt := filepath.Join(destDir, entry.Name())
			data, rerr := rt.FS.ReadFile(full)
			if rerr != nil {
				return nil, rerr
			}
			if werr := rt.FS.WriteFile(trgt, data, 0o644); werr != nil {
				return nil, werr
			}
			ret = append(ret, trgt)
		}
		return ret, nil
	}

	// Locate the salt sdist tarball and derive the debian name.
	saltTarball := ""
	entries, _ := rt.FS.ReadDir(treeBase)
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "salt-") && strings.HasSuffix(name, ".tar.gz") {
			saltTarball = name
			break
		}
	}
	if saltTarball == "" {
		return ret, nil
	}

	frontname := strings.Split(saltTarball, ".tar.gz")[0]
	k := strings.LastIndex(frontname, "-")
	debname := frontname[:k] + "_" + frontname[k+1:]
	debname += "+ds"
	debnameOrig := debname + ".orig.tar.gz"
	absPathDebname := filepath.Join(treeBase, debname)

	retrc := 0
	retrc |= runRetcode(ctx, rt, treeBase, envArgs, fmt.Sprintf("tar -xvzf %s", saltTarball))
	retrc |= runRetcode(ctx, rt, treeBase, envArgs, fmt.Sprintf("mv %s %s", frontname, debname))
	retrc |= runRetcode(ctx, rt, treeBase, envArgs, fmt.Sprintf("tar -cvzf %s %s", filepath.Join(treeBase, debnameOrig), debname))
	retrc |= runRetcode(ctx, rt, treeBase, envArgs, fmt.Sprintf("rm -f %s", saltTarball))
	retrc |= runRetcode(ctx, rt, absPathDebname, envArgs, fmt.Sprintf("cp %s  %s", specPathfile, absPathDebname))
	retrc |= runRetcode(ctx, rt, absPathDebname, envArgs, fmt.Sprintf("tar -xvJf %s", specPathfile))
	retrc |= runRetcode(ctx, rt, absPathDebname, envArgs, fmt.Sprintf("rm -f %s", filepath.Base(specPathfile)))
	retrc |= runRetcode(ctx, rt, absPathDebname, envArgs, "debuild -S -uc -us -sa")
	retrc |= runRetcode(ctx, rt, "", envArgs, fmt.Sprintf("rm -fR %s", absPathDebname))
	if retrc != 0 {
		return nil, fmt.Errorf(
			"Make source package for destination directory %s, spec %s, sources %v,"+
				" failed with return error %d, check logs for further details",
			destDir, spec, sourcesList(sources), retrc)
	}

	entries, _ = rt.FS.ReadDir(treeBase)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sortStrings(names)
	for _, dfile := range names {
		if strings.HasSuffix(dfile, ".build") {
			continue
		}
		full := filepath.Join(treeBase, dfile)
		trgt := filepath.Join(destDir, dfile)
		data, rerr := rt.FS.ReadFile(full)
		if rerr != nil {
			return nil, rerr
		}
		if werr := rt.FS.WriteFile(trgt, data, 0o644); werr != nil {
			return nil, werr
		}
		ret = append(ret, trgt)
	}
	return ret, nil
}

// debBuild mirrors build: DSC creation followed by the pbuilder
// create/update/build cycle with results copied out of
// /var/cache/pbuilder/result.
func debBuild(
	ctx context.Context,
	rt *runtime.Runtime,
	runas, tgt, destDir, spec string,
	sources, deps any,
	env map[string]any,
	saltenv, logDir string,
) (any, error) {
	ret := map[string]any{}
	retrc := 0
	mkDirs(rt, destDir)
	dscDir, err := rt.FS.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}
	envArgs := buildEnvArgs(env)
	dscsAny, err := debMakeSrcPkg(ctx, rt, dscDir, spec, sources, env, saltenv, runas)
	if err != nil {
		rt.FS.RemoveAll(dscDir)
		return ret, nil
	}
	dscs, _ := dscsAny.([]string)

	if runas != "root" {
		userHome := homeOf(runas)
		rootHome := homeOf("root")
		retrc |= runRetcode(ctx, rt, "", envArgs,
			fmt.Sprintf("cp %s/.pbuilderrc %s/", userHome, rootHome))
		retrc |= runRetcode(ctx, rt, "", envArgs,
			fmt.Sprintf("cp -R %s/.pbuilder-hooks %s/", userHome, rootHome))
		if retrc != 0 {
			return nil, fmt.Errorf(
				"build copy pbuilder files from '%s' to '%s' returned error '%d', "+
					"check logs for further details", userHome, rootHome, retrc)
		}
	}

	retrc |= runRetcode(ctx, rt, "", envArgs, "/usr/sbin/pbuilder --create")
	if retrc != 0 {
		return nil, fmt.Errorf("pbuilder create failed with return error '%d', "+
			"check logs for further details", retrc)
	}

	resultsDir := "/var/cache/pbuilder/result"
	retrc |= runRetcode(ctx, rt, "", envArgs, fmt.Sprintf("rm -fR %s", resultsDir))

	for _, dsc := range dscs {
		if !strings.HasSuffix(dsc, ".dsc") {
			continue
		}
		dbase := filepath.Dir(dsc)
		retrc |= runRetcode(ctx, rt, "", envArgs,
			fmt.Sprintf("chown %s:%s -R %s", runas, runas, dbase))
		retrc |= runRetcode(ctx, rt, "", envArgs, "/usr/sbin/pbuilder update --override-config")
		retrc |= runRetcode(ctx, rt, "", envArgs,
			fmt.Sprintf("/usr/sbin/pbuilder build --debbuildopts \"-sa\" %s", dsc))
		if retrc != 0 {
			return nil, fmt.Errorf("pbuilder build or update failed with return error %d, "+
				"check logs for further details", retrc)
		}
		bentries, _ := rt.FS.ReadDir(resultsDir)
		for _, bentry := range bentries {
			if bentry.Name() == "Packages" {
				continue
			}
			full := filepath.Join(resultsDir, bentry.Name())
			bdist := filepath.Join(destDir, bentry.Name())
			data, rerr := rt.FS.ReadFile(full)
			if rerr != nil {
				continue
			}
			rt.FS.WriteFile(bdist, data, 0o644)
			ret["Packages"] = appendStringList(ret, "Packages", bdist)
		}
	}

	// Remove any Packages file created for local dependency processing.
	pentries, _ := rt.FS.ReadDir(destDir)
	for _, pentry := range pentries {
		if pentry.Name() == "Packages" {
			rt.FS.Remove(filepath.Join(destDir, pentry.Name()))
		}
	}

	rt.FS.RemoveAll(dscDir)
	return ret, nil
}

// debOldGnuPG reports whether the legacy gpg-agent-info file exists.
func debOldGnuPG(rt *runtime.Runtime, gnupghome string) bool {
	info, err := rt.FS.Stat(filepath.Join(gnupghome, "gpg-agent-info-salt"))
	return err == nil && !info.IsDir()
}

// debLegacyPromptOS mirrors the Ubuntu<18 / Debian<=8 probes selecting the
// interactive passphrase variants (direct runs here; salt.utils.vt loops
// unported).
func debLegacyPromptOS(rt *runtime.Runtime) bool {
	name := strings.ToLower(rt.Facts.OS().ID)
	major := osMajorRelease(rt)
	switch name {
	case "ubuntu":
		return major < 18
	case "debian":
		return major <= 8
	}
	return false
}

func checkSignUtilSupport(exe string) error {
	if whichBin(exe) == "" {
		return fmt.Errorf("utility '%s' needs to be installed or made available in search path", exe)
	}
	return nil
}

// debMakeRepo mirrors make_repo: conf/distributions + conf/options
// rendering, the SignWith append before the pillar gate (upstream ordering),
// changes/dsc/deb processing through debsign and reprepro.
func debMakeRepo(
	ctx context.Context,
	rt *runtime.Runtime,
	repoDir, keyid string,
	env map[string]any,
	usePassphrase bool,
	gnupghome string,
	timeout float64,
) (map[string]any, error) {
	runas := "root"
	res := map[string]any{"retcode": 1, "stdout": "", "stderr": "initialization value"}
	retrc := 0

	if gnupghome != "" && env == nil {
		env = map[string]any{"GNUPGHOME": gnupghome}
	}
	envArgs := buildEnvArgs(env)

	repoconf := filepath.Join(repoDir, "conf")
	mkDirs(rt, repoconf)

	codename, repocfgDists := getRepoDistsEnv(env)
	repoconfdist := filepath.Join(repoconf, "distributions")
	rt.FS.WriteFile(repoconfdist, []byte(repocfgDists), 0o644)

	repocfgOpts := getRepoOptionsEnv(env)
	repoconfopts := filepath.Join(repoconf, "options")
	rt.FS.WriteFile(repoconfopts, []byte(repocfgOpts), 0o644)

	localKeygrip := ""
	localKeyFingerprint := ""
	localKeyid := ""
	phrase := ""

	olderGnuPG := debOldGnuPG(rt, gnupghome)

	if keyid != "" {
		f, err := rt.FS.ReadFile(repoconfdist)
		if err != nil {
			f = []byte{}
		}
		rt.FS.WriteFile(repoconfdist, append(f, []byte(fmt.Sprintf("SignWith: %s\n", keyid))...), 0o644)

		pubName := scalarString(pillarGet(rt, "gpg_pkg_pub_keyname", nil))
		privName := scalarString(pillarGet(rt, "gpg_pkg_priv_keyname", nil))
		pkgPubKeyFile := fmt.Sprintf("%s/%s", gnupghome, pubName)
		pkgPrivKeyFile := fmt.Sprintf("%s/%s", gnupghome, privName)

		importOK := false
		if _, ok := rt.Exec.Get("gpg.import_key"); ok {
			importOK = true
			for _, filename := range []string{pkgPubKeyFile, pkgPrivKeyFile} {
				if _, err := rt.Exec.Call(ctx, rt, "gpg.import_key", map[string]any{
					"user": runas, "filename": filename, "gnupghome": gnupghome,
				}); err != nil {
					importOK = false
					break
				}
			}
		}
		if !importOK {
			return nil, fmt.Errorf(
				"Public and Private key files associated with Pillar data and 'keyid' "+
					"%s could not be found", keyid)
		}

		if _, ok := rt.Exec.Get("gpg.list_keys"); ok {
			res, lerr := rt.Exec.Call(ctx, rt, "gpg.list_keys", map[string]any{
				"user": runas, "gnupghome": gnupghome,
			})
			if lerr == nil {
				if keys, ok := res.([]any); ok {
					for _, raw := range keys {
						gpgKey, ok := raw.(map[string]any)
						if !ok {
							continue
						}
						keyidFull, _ := gpgKey["keyid"].(string)
						if len(keyidFull) > 8 && keyid == keyidFull[8:] {
							if fp, ok := gpgKey["fingerprint"].(string); ok {
								localKeygrip = fp
								localKeyFingerprint = fp
							}
							localKeyid = keyidFull
							break
						}
					}
				}
			}
		}

		if !olderGnuPG {
			listCmd := "gpg2 --with-keygrip --list-secret-keys"
			if err := checkSignUtilSupport("gpg2"); err != nil {
				listCmd = "gpg --with-keygrip --list-secret-keys"
			}
			out := runAll(ctx, rt, "", envArgs, listCmd)
			lines := strings.Split(out["stdout"].(string), "\n")
			found := false
			for i := 0; i < len(lines)-2; i++ {
				if strings.HasPrefix(lines[i], "sec") &&
					strings.TrimSpace(lines[i+1]) == localKeyFingerprint {
					parts := strings.Split(lines[i+2], "=")
					if len(parts) > 1 {
						localKeygrip = strings.TrimSpace(parts[1])
						found = true
					}
					break
				}
			}
			_ = found
		}

		if localKeyid == "" {
			return nil, fmt.Errorf(
				"The key ID '%s' was not found in GnuPG keyring at '%s'", keyid, gnupghome)
		}

		if err := checkSignUtilSupport("debsign"); err != nil {
			return nil, err
		}

		if olderGnuPG {
			raw, rerr := rt.FS.ReadFile(filepath.Join(gnupghome, "gpg-agent-info-salt"))
			if rerr == nil {
				lines := strings.Split(string(raw), "\n")
				if len(lines) > 0 {
					parts := strings.Split(lines[0], "=")
					if len(parts) > 1 {
						env[parts[0]] = parts[1]
					}
				}
			}
		} else {
			raw, rerr := rt.FS.ReadFile(filepath.Join(gnupghome, "gpg-tty-info-salt"))
			if rerr == nil {
				lines := strings.Split(string(raw), "\n")
				if len(lines) > 0 {
					parts := strings.Split(lines[0], "=")
					if len(parts) > 1 {
						env[parts[0]] = parts[1]
					}
				}
			}
		}

		if usePassphrase {
			utilName := "/usr/lib/gnupg2/gpg-preset-passphrase"
			if info, serr := rt.FS.Stat(utilName); serr != nil || info.IsDir() {
				return nil, fmt.Errorf("utility '%s' needs to be installed", utilName)
			}
			phrase = scalarString(pillarGet(rt, "gpg_passphrase", nil))
			cmd := fmt.Sprintf("/usr/lib/gnupg2/gpg-preset-passphrase --verbose --preset"+
				" --passphrase \"%s\" %s", phrase, localKeygrip)
			retrc |= runRetcode(ctx, rt, "", buildEnvArgs(env), cmd)
		}
	}

	entries, _ := rt.FS.ReadDir(repoDir)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sortStrings(names)

	for _, debfile := range names {
		absFile := filepath.Join(repoDir, debfile)
		if strings.HasSuffix(debfile, ".changes") {
			rt.FS.Remove(absFile)
		}

		if strings.HasSuffix(debfile, ".dsc") {
			if olderGnuPG {
				if localKeyid != "" {
					retrc |= runRetcode(ctx, rt, repoDir, envArgs,
						fmt.Sprintf("debsign --re-sign -k %s %s", keyid, absFile))
				}
				retrc |= runRetcode(ctx, rt, repoDir, envArgs,
					fmt.Sprintf("reprepro --ignore=wrongdistribution --component=main -Vb . includedsc %s %s",
						codename, absFile))
			} else {
				if localKeyid != "" {
					if debLegacyPromptOS(rt) {
						retrc |= runRetcode(ctx, rt, repoDir, envArgs,
							fmt.Sprintf("debsign --re-sign -k %s %s", keyid, absFile))
					} else {
						retrc |= runRetcode(ctx, rt, repoDir, envArgs,
							fmt.Sprintf("debsign --re-sign -k %s %s", localKeyFingerprint, absFile))
					}
				}
				retrc |= runRetcode(ctx, rt, repoDir, envArgs,
					fmt.Sprintf("reprepro --ignore=wrongdistribution --component=main -Vb . includedsc %s %s",
						codename, absFile))
			}
			if retrc != 0 {
				return nil, fmt.Errorf(
					"Making a repo encountered errors, return error %d, check logs for"+
						" further details", retrc)
			}
		}

		if strings.HasSuffix(debfile, ".deb") {
			res = runAll(ctx, rt, repoDir, envArgs,
				fmt.Sprintf("reprepro --ignore=wrongdistribution --component=main -Vb . includedeb %s %s",
					codename, absFile))
		}
	}

	return res, nil
}
