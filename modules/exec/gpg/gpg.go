// Package gpg implements the cryptographic core of Salt's gpg module
// (R5.6): saltstack/salt/modules/gpg.py @ pinned revision — encrypt,
// decrypt, sign, verify — driving the real `gpg` binary through the central
// Runner instead of python-gnupg (same wire behavior: armored output,
// --status-fd 2 status lines, GNUPGHOME resolution).
//
// Documented boundaries:
//   - key management functions (create/delete/list/search/trust/import/
//     export/receive) stay pending for their own slice;
//   - the ownership restore dance of _restore_ownership degrades under the
//     StateKit single-user model: the GnuPG home is created 0700 and chown
//     fix-ups apply only when running as root;
//   - passphrases resolve from config.get("gpg_passphrase") instead of the
//     pillar.
package gpg

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

var verifyTrustLevels = map[string]string{
	"0": "Expired",
	"1": "Undefined",
	"2": "Never",
	"3": "Marginal",
	"4": "Fully",
	"5": "Ultimate",
}

func execLookPathG(exe string) (string, error) { return exec.LookPath(exe) }

var whichBin = func(exe string) string {
	p, err := execLookPathG(exe)
	if err != nil {
		return ""
	}
	return p
}

func requireGPG() error {
	if whichBin("gpg") == "" {
		return fmt.Errorf(
			"The gpg execution module cannot be loaded: gpg binary is not in the path.")
	}
	return nil
}

func recoverG(res *any, errPtr *error) {
	if r := recover(); r != nil {
		switch e := r.(type) {
		case error:
			*errPtr = e
		default:
			panic(r)
		}
	}
}

type invocationErr struct{ msg string }

func (e *invocationErr) Error() string { return e.msg }

// ---------------------------------------------------------------------------
// homedir machinery (_get_user_info / _get_user_gnupghome / _create_gnupghome)

func callDelegateG(rt *runtime.Runtime, name string, args any) (any, error) {
	if _, ok := rt.Exec.Get(name); !ok {
		return nil, fmt.Errorf("%s is not available", name)
	}
	return rt.Exec.Call(context.Background(), rt, name, args)
}

func strDerefG(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// getUserInfo ports _get_user_info through user.info with the config-user
// fallback.
func getUserInfo(rt *runtime.Runtime, user *string) (map[string]any, error) {
	name := ""
	if user != nil {
		name = *user
	}
	if name == "" || name == "salt" && !userSetByCaller(user) {
		if res, err := callDelegateG(rt, "config.get", map[string]any{"key": "user"}); err == nil {
			if s, ok := res.(string); ok && s != "" {
				name = s
			}
		}
	}
	res, err := callDelegateG(rt, "user.info", map[string]any{"name": name})
	if err != nil || res == nil {
		return nil, &invocationErr{msg: fmt.Sprintf("User %s does not exist", name)}
	}
	info, _ := res.(map[string]any)
	return info, nil
}

func userSetByCaller(*string) bool { return false }

// getUserGnupghome ports _get_user_gnupghome: the "salt" user maps to
// <config_dir>/gpgkeys; GNUPGHOME comes through environ.get; otherwise the
// user's ~/.gnupg.
func getUserGnupghome(rt *runtime.Runtime, user *string) (string, error) {
	name := strDerefG(user)
	if name == "salt" {
		configDir := ".statekit"
		if res, err := callDelegateG(rt, "config.get", map[string]any{"key": "config_dir"}); err == nil {
			if s, ok := res.(string); ok && s != "" {
				configDir = s
			}
		}
		return filepath.Join(configDir, "gpgkeys"), nil
	}
	if res, err := callDelegateG(rt, "environ.get",
		map[string]any{"name": "GNUPGHOME"}); err == nil {
		if s, ok := res.(string); ok && strings.TrimSpace(s) != "" &&
			!strings.HasPrefix(strings.TrimSpace(s), "~") {
			return strings.TrimSpace(s), nil
		}
	}
	info, uerr := getUserInfo(rt, user)
	if uerr != nil {
		return "", uerr
	}
	home, _ := info["home"].(string)
	return filepath.Join(home, ".gnupg"), nil
}

// createGnupghome ports _create_gnupghome (mode 0700).
func createGnupghome(rt *runtime.Runtime, gnupghome string, info map[string]any) error {
	rt.FS.MkdirAll(gnupghome, 0o700)
	rt.FS.Chmod(gnupghome, 0o700)
	chownToUserG(rt, gnupghome, info)
	return nil
}

func chownToUserG(rt *runtime.Runtime, path string, info map[string]any) {
	if currentEuidG() != 0 || info == nil {
		return
	}
	uid, _ := info["uid"].(int)
	gid, _ := info["gid"].(int)
	rt.FS.Chown(path, uid, gid)
}

func currentEuidG() int { return procEuidG() }

// createGPG resolves the homedir and guarantees it exists (the python-gnupg
// ValueError("gnupghome should be a directory") recovery path).
func createGPG(rt *runtime.Runtime, user *string, gnupghome *string, keyring *string) (string, error) {
	home := strDerefG(gnupghome)
	if home == "" {
		var herr error
		home, herr = getUserGnupghome(rt, user)
		if herr != nil {
			return "", herr
		}
	}
	if kr := strDerefG(keyring); kr != "" && !strings.HasPrefix(kr, "/") {
		return "", &invocationErr{
			msg: "Please pass keyring as a string. Multiple keyrings are not allowed"}
	}
	if info, serr := rt.FS.Stat(home); serr != nil || !info.IsDir() {
		info2, uerr := getUserInfo(rt, user)
		if uerr == nil {
			createGnupghome(rt, home, info2)
		} else {
			createGnupghome(rt, home, nil)
		}
	}
	return home, nil
}

func passphraseOf(rt *runtime.Runtime, usePassphrase bool) (string, error) {
	if !usePassphrase {
		return "", nil
	}
	res, err := callDelegateG(rt, "config.get", map[string]any{"key": "gpg_passphrase"})
	if err != nil || res == nil {
		panic(&invocationErr{msg: "gpg_passphrase not available in pillar."})
	}
	s, _ := res.(string)
	if s == "" {
		panic(&invocationErr{msg: "gpg_passphrase not available in pillar."})
	}
	return s, nil
}

// runGPG executes the binary and returns stdout plus stderr (status lines
// arrive on fd 2 via --status-fd 2).
func runGPG(rt *runtime.Runtime, argv []string) (stdout, stderr string, exitCode int) {
	res := rt.Runner.Run(context.Background(), runtime.Command(argv...))
	return string(res.Stdout), string(res.Stderr), res.ExitCode
}

// ---------------------------------------------------------------------------
// gpg.encrypt

type encryptArgs struct {
	User          *string  `statekit:"name=user"`
	Recipients    []string `statekit:"name=recipients"`
	Text          *string  `statekit:"name=text"`
	Filename      *string  `statekit:"name=filename"`
	Output        *string  `statekit:"name=output"`
	Sign          any      `statekit:"name=sign"`
	UsePassphrase *bool    `statekit:"name=use_passphrase"`
	AlwaysTrust   *bool    `statekit:"name=always_trust"`
	Gnupghome     *string  `statekit:"name=gnupghome"`
	Bare          *bool    `statekit:"name=bare"`
	Keyring       *string  `statekit:"name=keyring"`
}

type encryptFunc struct{}

func (encryptFunc) Name() string { return "gpg.encrypt" }
func (encryptFunc) Args() any    { return encryptArgs{} }
func (encryptFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*encryptArgs)
	ensureGPGReady(rt)
	ret := map[string]any{"res": true, "comment": ""}
	passphrase, perr := passphraseOf(rt, a.UsePassphrase != nil && *a.UsePassphrase)
	_ = passphrase
	if perr != nil {
		return nil, perr
	}
	home, herr := createGPG(rt, a.User, a.Gnupghome, a.Keyring)
	if herr != nil {
		return nil, herr
	}

	signKeyID := ""
	doSign := false
	switch v := a.Sign.(type) {
	case bool:
		doSign = v
	case string:
		if v != "" && v != "False" {
			doSign = true
			signKeyID = v
		}
	}

	inputFile := ""
	if a.Text != nil && *a.Text != "" {
		tmpIn := filepath.Join(home, ".statekit-encrypt-text")
		rt.FS.WriteFile(tmpIn, []byte(*a.Text), 0o600)
		defer rt.FS.Remove(tmpIn)
		inputFile = tmpIn
	} else if a.Filename != nil && *a.Filename != "" {
		inputFile = *a.Filename
	} else {
		panic(&invocationErr{msg: "filename or text must be passed."})
	}

	argv := []string{"gpg", "--homedir", home, "--batch", "--yes", "--armor",
		"--status-fd", "2"}
	for _, r := range a.Recipients {
		argv = append(argv, "-r", r)
	}
	if doSign {
		argv = append(argv, "--sign")
		if signKeyID != "" {
			argv = append(argv, "--local-user", signKeyID)
		}
		if passphrase != "" {
			argv = append(argv, "--pinentry-mode", "loopback", "--passphrase", passphrase)
		}
	}
	if a.AlwaysTrust != nil && *a.AlwaysTrust {
		argv = append(argv, "--trust-model", "always")
	}
	output := strDerefG(a.Output)
	if output != "" {
		argv = append(argv, "--output", output)
	}
	argv = append(argv, "--encrypt")
	if inputFile != "" {
		argv = append(argv, inputFile)
	}

	stdout, _, exitCode := runGPG(rt, argv)
	ok := exitCode == 0 && (output != "" || strings.Contains(stdout, "BEGIN PGP MESSAGE"))
	bare := a.Bare != nil && *a.Bare

	if bare {
		if !ok {
			return false, nil
		}
		if output != "" {
			return "", nil // upstream returns result.data (empty when written)
		}
		return stdout, nil
	}
	if ok {
		if output != "" {
			ret["comment"] = fmt.Sprintf("Encrypted data has been written to %s", output)
		} else {
			ret["comment"] = stdout
		}
	} else {
		ret["res"] = false
		ret["comment"] = "encryption failed.\nPlease check the salt-minion log."
	}
	return ret, nil
}

func ensureGPGReady(rt *runtime.Runtime) {
	if gerr := requireGPG(); gerr != nil {
		panic(gerr)
	}
}

// ---------------------------------------------------------------------------
// gpg.decrypt

type decryptArgs struct {
	User          *string `statekit:"name=user"`
	Text          *string `statekit:"name=text"`
	Filename      *string `statekit:"name=filename"`
	Output        *string `statekit:"name=output"`
	UsePassphrase *bool   `statekit:"name=use_passphrase"`
	Gnupghome     *string `statekit:"name=gnupghome"`
	Bare          *bool   `statekit:"name=bare"`
	Keyring       *string `statekit:"name=keyring"`
}

type decryptFunc struct{}

func (decryptFunc) Name() string { return "gpg.decrypt" }
func (decryptFunc) Args() any    { return decryptArgs{} }
func (decryptFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*decryptArgs)
	ensureGPGReady(rt)
	ret := map[string]any{"res": true, "comment": ""}
	passphrase, perr := passphraseOf(rt, a.UsePassphrase != nil && *a.UsePassphrase)
	if perr != nil {
		return nil, perr
	}
	home, herr := createGPG(rt, a.User, a.Gnupghome, a.Keyring)
	if herr != nil {
		return nil, herr
	}

	inputFile := ""
	if a.Text != nil && *a.Text != "" {
		tmpIn := filepath.Join(home, ".statekit-decrypt-text")
		rt.FS.WriteFile(tmpIn, []byte(*a.Text), 0o600)
		defer rt.FS.Remove(tmpIn)
		inputFile = tmpIn
	} else if a.Filename != nil && *a.Filename != "" {
		inputFile = *a.Filename
	} else {
		panic(&invocationErr{msg: "filename or text must be passed."})
	}
	output := strDerefG(a.Output)

	argv := []string{"gpg", "--homedir", home, "--batch", "--yes",
		"--status-fd", "2"}
	if passphrase != "" {
		argv = append(argv, "--pinentry-mode", "loopback", "--passphrase", passphrase)
	}
	if output != "" {
		argv = append(argv, "--output", output)
	}
	argv = append(argv, "--decrypt", inputFile)

	stdout, _, exitCode := runGPG(rt, argv)
	ok := exitCode == 0 && output == ""
	bare := a.Bare != nil && *a.Bare
	if bare {
		if !ok {
			return false, nil
		}
		return stdout, nil
	}
	if ok {
		if output != "" {
			ret["comment"] = fmt.Sprintf("Decrypted data has been written to %s", output)
		} else {
			ret["comment"] = stdout
		}
	} else {
		ret["res"] = false
		ret["comment"] = "decryption failed.\nPlease check the salt-minion log."
	}
	return ret, nil
}

// ---------------------------------------------------------------------------
// gpg.sign

type signArgs struct {
	User          *string `statekit:"name=user"`
	Keyid         *string `statekit:"name=keyid"`
	Text          *string `statekit:"name=text"`
	Filename      *string `statekit:"name=filename"`
	Output        *string `statekit:"name=output"`
	UsePassphrase *bool   `statekit:"name=use_passphrase"`
	Gnupghome     *string `statekit:"name=gnupghome"`
	Keyring       *string `statekit:"name=keyring"`
}

type signFunc struct{}

func (signFunc) Name() string { return "gpg.sign" }
func (signFunc) Args() any    { return signArgs{} }
func (signFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*signArgs)
	ensureGPGReady(rt)
	passphrase, perr := passphraseOf(rt, a.UsePassphrase != nil && *a.UsePassphrase)
	if perr != nil {
		return nil, perr
	}
	home, herr := createGPG(rt, a.User, a.Gnupghome, a.Keyring)
	if herr != nil {
		return nil, herr
	}

	inputFile := ""
	if a.Text != nil && *a.Text != "" {
		tmpIn := filepath.Join(home, ".statekit-sign-text")
		rt.FS.WriteFile(tmpIn, []byte(*a.Text), 0o600)
		defer rt.FS.Remove(tmpIn)
		inputFile = tmpIn
	} else if a.Filename != nil && *a.Filename != "" {
		inputFile = *a.Filename
	} else {
		panic(&invocationErr{msg: "filename or text must be passed."})
	}

	argv := []string{"gpg", "--homedir", home, "--batch", "--yes", "--armor",
		"--status-fd", "2"}
	if k := strDerefG(a.Keyid); k != "" {
		argv = append(argv, "--local-user", k)
	}
	if passphrase != "" {
		argv = append(argv, "--pinentry-mode", "loopback", "--passphrase", passphrase)
	}
	argv = append(argv, "--sign")

	out, _, code := runGPG(rt, append(argv, inputFile))
	if code != 0 || strings.TrimSpace(out) == "" {
		return nil, fmt.Errorf("Signing failed")
	}
	if output := strDerefG(a.Output); output != "" {
		rt.FS.WriteFile(output, []byte(out), 0o644)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// gpg.verify

type verifyArgs struct {
	Text        *string  `statekit:"name=text"`
	User        *string  `statekit:"name=user"`
	Filename    *string  `statekit:"name=filename"`
	Gnupghome   *string  `statekit:"name=gnupghome"`
	Signature   *string  `statekit:"name=signature"`
	Trustmodel  *string  `statekit:"name=trustmodel"`
	SignedByAny []string `statekit:"name=signed_by_any"`
	SignedByAll []string `statekit:"name=signed_by_all"`
	Keyring     *string  `statekit:"name=keyring"`
}

type verifyFunc struct{}

func (verifyFunc) Name() string { return "gpg.verify" }
func (verifyFunc) Args() any    { return verifyArgs{} }
func (verifyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*verifyArgs)
	ensureGPGReady(rt)

	trustmodels := "pgp, classic, tofu, tofu+pgp, direct, always, auto"
	tm := strDerefG(a.Trustmodel)
	if tm != "" && !strings.Contains(","+trustmodels+",", ","+tm+",") {
		return map[string]any{
			"res":     false,
			"message": fmt.Sprintf("Invalid trustmodel defined: %s. Use one of: %s", tm, trustmodels),
		}, nil
	}
	home, herr := createGPG(rt, a.User, a.Gnupghome, a.Keyring)
	if herr != nil {
		return nil, herr
	}

	argv := []string{"gpg", "--homedir", home, "--batch", "--yes",
		"--status-fd", "2"}
	if tm != "" {
		argv = append(argv, "--trust-model", tm)
	}
	multiCheck := len(a.SignedByAny) > 0 || len(a.SignedByAll) > 0
	if multiCheck {
		argv = append(argv, "--no-batch")
	}

	switch {
	case a.Text != nil && *a.Text != "":
		tmpIn := filepath.Join(home, ".statekit-verify-text")
		rt.FS.WriteFile(tmpIn, []byte(*a.Text), 0o600)
		defer rt.FS.Remove(tmpIn)
		argv = append(argv, "--verify", tmpIn)
	case a.Filename != nil && *a.Filename != "":
		if sig := strDerefG(a.Signature); sig != "" {
			argv = append(argv, "--verify", sig, *a.Filename)
		} else {
			argv = append(argv, "--verify", *a.Filename)
		}
	default:
		panic(&invocationErr{msg: "filename or text must be passed."})
	}

	_, stderr, exitCode := runGPG(rt, argv)
	signatures := parseStatusLines(stderr)
	validSigs := []map[string]any{}
	for _, sig := range signatures {
		if sig["trust_level_name"] != nil || sig["valid"] == true {
			validSigs = append(validSigs, sig)
			break
		}
	}
	_ = validSigs

	if !multiCheck {
		ret := map[string]any{}
		best := bestSignature(signatures)
		if best != nil && exitCode == 0 {
			ret["res"] = true
			ret["username"] = best["username"]
			ret["key_id"] = best["key_id"]
			ret["trust_level"] = best["trust_level"]
			ret["message"] = "The signature is verified."
		} else {
			ret["res"] = false
			ret["message"] = "The signature could not be verified."
		}
		return ret, nil
	}

	sigList := []map[string]any{}
	for _, sig := range signatures {
		entry := map[string]any{
			"username":    sig["username"],
			"key_id":      sig["key_id"],
			"fingerprint": sig["fingerprint"],
			"trust_level": sig["trust_level"],
			"status":      sig["status"],
		}
		sigList = append(sigList, entry)
	}
	ret := map[string]any{"res": false, "message": "", "signatures": sigList}
	fingerprintSet := map[string]bool{}
	for _, sig := range signatures {
		if fp, ok := sig["fingerprint"].(string); ok && sig["trust_level"] != nil {
			fingerprintSet[fp] = true
		}
	}
	anyCheck := false
	allCheck := false
	if len(a.SignedByAny) > 0 {
		okAny := false
		for _, signer := range a.SignedByAny {
			if fingerprintSet[signer] {
				okAny = true
				break
			}
		}
		if !okAny {
			ret["message"] = "None of the public keys listed in signed_by_any provided a valid signature"
			return ret, nil
		}
		anyCheck = true
	}
	if len(a.SignedByAll) > 0 {
		for _, signer := range a.SignedByAll {
			if !fingerprintSet[signer] {
				ret["message"] = fmt.Sprintf(
					"Public key %s has not provided a valid signature, but was listed in signed_by_all", signer)
				return ret, nil
			}
		}
		allCheck = true
	}
	if boolOfG(len(a.SignedByAny) > 0) == anyCheck && boolOfG(len(a.SignedByAll) > 0) == allCheck {
		ret["res"] = true
		ret["message"] = "All required keys have provided a signature"
		return ret, nil
	}
	ret["message"] = "Something went wrong while checking for specific signers. This is most likely a bug"
	return ret, nil
}

func boolOfG(b bool) bool { return b }

// parseStatusLines extracts GOODSIG/VALIDSIG/TRUST_/ERRSIG entries from
// gpg's --status-fd 2 output.
func parseStatusLines(stderr string) []map[string]any {
	var order []string
	byKey := map[string]map[string]any{}

	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[GNUPG:] ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "[GNUPG:] "))
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "TRUST_ULTIMATE" || fields[0] == "TRUST_FULLY" ||
			fields[0] == "TRUST_MARGINAL" || fields[0] == "TRUST_UNDEFINED" ||
			fields[0] == "TRUST_NEVER" || fields[0] == "TRUST_EXPIRED" {
			applyTrust(byKey, &order, fields[0], trustNumFor(fields[0]))
			continue
		}
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "GOODSIG":
			keyID := fields[1]
			username := strings.Join(fields[2:], " ")
			e := entryFor(byKey, &order, keyID)
			e["key_id"] = keyID
			e["username"] = username
			e["status"] = "goodsig"
		case "EXPKEYSIG":
			keyID := fields[1]
			username := strings.Join(fields[2:], " ")
			e := entryFor(byKey, &order, keyID)
			e["key_id"] = keyID
			e["username"] = username
			e["status"] = "expkeysig"
		case "VALIDSIG":
			if len(fields) >= 3 {
				fpr := fields[1]
				// VALIDSIG follows GOODSIG for the same key.
				if len(order) > 0 {
					if e, okLast2 := byKey[order[len(order)-1]]; okLast2 && e != nil {
						e["fingerprint"] = fpr
						e["valid"] = true
					}
				}
			}
		case "TRUST_ULTIMATE":
			applyTrust(byKey, &order, "TRUST_ULTIMATE", "5")
		case "TRUST_FULLY":
			applyTrust(byKey, &order, "TRUST_FULLY", "4")
		case "TRUST_MARGINAL":
			applyTrust(byKey, &order, "TRUST_MARGINAL", "3")
		case "TRUST_UNDEFINED":
			applyTrust(byKey, &order, "TRUST_UNDEFINED", "1")
		case "TRUST_NEVER":
			applyTrust(byKey, &order, "TRUST_NEVER", "2")
		case "TRUST_EXPIRED":
			applyTrust(byKey, &order, "TRUST_EXPIRED", "0")
		case "ERRSIG":
			if len(fields) >= 7 {
				e := entryFor(byKey, &order, fields[1])
				e["key_id"] = fields[1]
				e["status"] = "errsig"
				e["username"] = nil
			}
		}
	}

	out := make([]map[string]any, 0, len(order))
	for _, keyID := range order {
		e := byKey[keyID]
		if tlNum, ok := e["_trust_num"].(string); ok {
			name, has := verifyTrustLevels[tlNum]
			if has {
				e["trust_level"] = name
				e["trust_level_name"] = name
			}
		}
		delete(e, "_trust_num")
		delete(e, "valid")
		out = append(out, e)
	}
	return out
}

func trustNumFor(status string) string {
	switch status {
	case "TRUST_EXPIRED":
		return "0"
	case "TRUST_UNDEFINED":
		return "1"
	case "TRUST_NEVER":
		return "2"
	case "TRUST_MARGINAL":
		return "3"
	case "TRUST_FULLY":
		return "4"
	case "TRUST_ULTIMATE":
		return "5"
	}
	return ""
}

func applyTrust(byKey map[string]map[string]any, order *[]string, status, num string) {
	if len(*order) == 0 {
		return
	}
	last, okLast := byKey[(*order)[len(*order)-1]]
	if !okLast || last == nil {
		return
	}
	last["status"] = status
	last["_trust_num"] = num
}

func entryFor(byKey map[string]map[string]any, order *[]string, keyID string) map[string]any {
	if e, ok := byKey[keyID]; ok {
		return e
	}
	m := map[string]any{}
	byKey[keyID] = m
	*order = append(*order, keyID)
	return m
}

func bestSignature(sigs []map[string]any) map[string]any {
	for _, sig := range sigs {
		if sig["trust_level"] != nil {
			return sig
		}
	}
	return nil
}

// Register installs the R5.6 gpg cryptographic core.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		encryptFunc{},
		decryptFunc{},
		signFunc{},
		verifyFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
