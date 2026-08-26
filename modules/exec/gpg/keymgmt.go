package gpg

// R5.7: the gpg key-management tail — saltstack/salt/modules/gpg.py @
// pinned revision, driven through the gpg CLI with --with-colons parsing.
//
// Documented boundaries:
//   - python-gnupg's subkey_info tree is not reproduced (subkeys render as
//     an absent field when the colon stream carries no sub records);
//   - import_key's select filter uses the temp.file delegate plus a
//     throwaway keyring exactly like upstream;
//   - trust_key uses the deterministic --import-ownertrust stdin path and
//     parses the "from X to Y" stderr digits like the python-gnupg<0.4.2
//     fallback upstream keeps for old libraries.

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

var letterTrust = map[string]string{
	"e": "Expired",
	"q": "Unknown",
	"n": "Not Trusted",
	"f": "Fully Trusted",
	"m": "Marginally Trusted",
	"u": "Ultimately Trusted",
	"r": "Revoked",
	"-": "Unknown",
}

var numTrust = map[string]string{
	"expired":     "1",
	"unknown":     "2",
	"not_trusted": "3",
	"marginally":  "4",
	"fully":       "5",
	"ultimately":  "6",
}

var invNumTrust = map[string]string{
	"1": "Expired",
	"2": "Unknown",
	"3": "Not Trusted",
	"4": "Marginally",
	"5": "Fully Trusted",
	"6": "Ultimately Trusted",
}

const defaultKeyServer = "keys.openpgp.org"

// ---------------------------------------------------------------------------
// --with-colons parsing shared by list/read/search

type rawKey struct {
	keyid       string
	fingerprint string
	uids        []string
	date        string // epoch seconds or ""
	expires     string
	length      string
	ownertrust  string
	trust       string
}

// parseColonKeys keeps pub records for public listings and sec records for
// secret ones, mirroring which stream each gpg mode emits.
func parseColonKeysMode(out string, secret bool) []rawKey {
	var keys []rawKey
	var cur *rawKey
	accept := func(recType string) bool {
		if secret {
			return recType == "sec"
		}
		return recType == "pub"
	}
	flush := func() {
		if cur != nil {
			keys = append(keys, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), ":")
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "pub", "sec":
			flush()
			if !accept(fields[0]) {
				continue
			}
			cur = &rawKey{}
			if len(fields) > 4 {
				cur.keyid = fields[4]
			}
			if len(fields) > 5 {
				cur.date = fields[5]
			}
			if len(fields) > 6 {
				cur.expires = fields[6]
			}
			if len(fields) > 8 {
				cur.ownertrust = fields[8]
			}
			if len(fields) > 9 {
				cur.trust = fields[9]
			}
			if len(fields) > 2 {
				cur.length = fields[2]
			}
		case "fpr":
			if cur != nil && len(fields) > 9 {
				cur.fingerprint = fields[9]
			}
		case "uid":
			if cur != nil && len(fields) > 9 {
				cur.uids = append(cur.uids, fields[9])
			}
		case "sub":
			flush()
		}
	}
	flush()
	return keys
}

var renderNow = time.Now

// renderKey ports _render_key.
func renderKey(k rawKey) map[string]any {
	tmp := map[string]any{"keyid": k.keyid}
	if len(k.uids) > 0 {
		tmp["uids"] = k.uids
	}
	if k.fingerprint != "" {
		tmp["fingerprint"] = k.fingerprint
	}
	if k.expires != "" {
		if epoch, err := strconv.ParseInt(k.expires, 10, 64); err == nil && epoch > 0 {
			tmp["expires"] = time.Unix(epoch, 0).Format("2006-01-02")
			tmp["expired"] = renderNow().Unix() >= epoch
		}
	}
	if k.date != "" {
		if epoch, err := strconv.ParseInt(k.date, 10, 64); err == nil && epoch > 0 {
			tmp["created"] = time.Unix(epoch, 0).Format("2006-01-02")
		}
	}
	if k.length != "" {
		if n, err := strconv.Atoi(k.length); err == nil && n > 0 {
			tmp["keyLength"] = n
		}
	}
	if v, ok := letterTrust[k.ownertrust]; ok && k.ownertrust != "-" {
		tmp["ownerTrust"] = v
	}
	if v, ok := letterTrust[k.trust]; ok && k.trust != "-" {
		tmp["trust"] = v
	}
	return tmp
}

func listKeysImpl(rt *runtime.Runtime, secret bool, user *string, gnupghome, keyring *string) ([]map[string]any, error) {
	home, err := createGPG(rt, user, gnupghome, keyring)
	if err != nil {
		return nil, err
	}
	mode := "--list-keys"
	if secret {
		mode = "--list-secret-keys"
	}
	argv := []string{"gpg", "--homedir", home, "--batch", "--with-colons", "--fingerprint"}
	if kr := strDerefG(keyring); kr != "" {
		argv = append(argv, "--no-default-keyring", "--keyring", kr)
	}
	argv = append(argv, mode)
	stdout, _, code := runGPG(rt, argv)
	if code != 0 {
		return []map[string]any{}, nil
	}
	out := []map[string]any{}
	for _, k := range parseColonKeysMode(stdout, secret) {
		out = append(out, renderKey(k))
	}
	return out, nil
}

func matchKey(k rawKey, keyid, fingerprint *string) bool {
	wantFp := strDerefG(fingerprint)
	wantID := strDerefG(keyid)
	if wantFp != "" && k.fingerprint == wantFp {
		return true
	}
	if wantID != "" && (k.keyid == wantID || shortID(k.keyid) == wantID) {
		return true
	}
	return false
}

// shortID mirrors upstream's _key["keyid"][8:] slice on long IDs.
func shortID(longID string) string {
	if len(longID) > 8 {
		return longID[8:]
	}
	return ""
}

// ---------------------------------------------------------------------------
// gpg.list_keys / list_secret_keys / get_key / get_secret_key

type listKeysArgs struct {
	User      *string `statekit:"name=user"`
	Gnupghome *string `statekit:"name=gnupghome"`
	Keyring   *string `statekit:"name=keyring"`
}

type listKeysFunc struct{}

func (listKeysFunc) Name() string { return "gpg.list_keys" }
func (listKeysFunc) Args() any    { return listKeysArgs{} }
func (listKeysFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*listKeysArgs)
	ensureGPGReady(rt)
	return listKeysImpl(rt, false, a.User, a.Gnupghome, a.Keyring)
}

type listSecretKeysFunc struct{}

func (listSecretKeysFunc) Name() string { return "gpg.list_secret_keys" }
func (listSecretKeysFunc) Args() any    { return listKeysArgs{} }
func (listSecretKeysFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*listKeysArgs)
	ensureGPGReady(rt)
	return listKeysImpl(rt, true, a.User, a.Gnupghome, a.Keyring)
}

type getKeyArgs struct {
	Keyid       *string `statekit:"name=keyid"`
	Fingerprint *string `statekit:"name=fingerprint"`
	User        *string `statekit:"name=user"`
	Gnupghome   *string `statekit:"name=gnupghome"`
	Keyring     *string `statekit:"name=keyring"`
}

type getKeyFunc struct{}

func (getKeyFunc) Name() string { return "gpg.get_key" }
func (getKeyFunc) Args() any    { return getKeyArgs{} }
func (getKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*getKeyArgs)
	ensureGPGReady(rt)
	keys, kerr := listKeysRaw(rt, a.User, a.Gnupghome, a.Keyring, false)
	if kerr != nil {
		return nil, kerr
	}
	for _, k := range keys {
		if matchKey(k, a.Keyid, a.Fingerprint) {
			return renderKey(k), nil
		}
	}
	return false, nil
}

type getSecretKeyFunc struct{}

func (getSecretKeyFunc) Name() string { return "gpg.get_secret_key" }
func (getSecretKeyFunc) Args() any    { return getKeyArgs{} }
func (getSecretKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*getKeyArgs)
	ensureGPGReady(rt)
	keys, kerr := listKeysRaw(rt, a.User, a.Gnupghome, a.Keyring, true)
	if kerr != nil {
		return nil, kerr
	}
	for _, k := range keys {
		if matchKey(k, a.Keyid, a.Fingerprint) {
			return renderKey(k), nil
		}
	}
	return false, nil
}

func listKeysRaw(rt *runtime.Runtime, user, gnupghome, keyring *string, secret bool) ([]rawKey, error) {
	home, err := createGPG(rt, user, gnupghome, keyring)
	if err != nil {
		return nil, err
	}
	mode := "--list-keys"
	if secret {
		mode = "--list-secret-keys"
	}
	argv := []string{"gpg", "--homedir", home, "--batch", "--with-colons", "--fingerprint"}
	if kr := strDerefG(keyring); kr != "" {
		argv = append(argv, "--no-default-keyring", "--keyring", kr)
	}
	argv = append(argv, mode)
	stdout, _, _ := runGPG(rt, argv)
	return parseColonKeysMode(stdout, secret), nil
}

// ---------------------------------------------------------------------------
// gpg.search_keys / receive_keys

type searchKeysArgs struct {
	Text      string  `statekit:"required,name=text"`
	Keyserver *string `statekit:"name=keyserver"`
	User      *string `statekit:"name=user"`
	Gnupghome *string `statekit:"name=gnupghome"`
}

type searchKeysFunc struct{}

func (searchKeysFunc) Name() string { return "gpg.search_keys" }
func (searchKeysFunc) Args() any    { return searchKeysArgs{} }
func (searchKeysFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*searchKeysArgs)
	ensureGPGReady(rt)
	home, herr := createGPG(rt, a.User, a.Gnupghome, nil)
	if herr != nil {
		return nil, herr
	}
	keyserver := defaultKeyServer
	if a.Keyserver != nil && *a.Keyserver != "" {
		keyserver = *a.Keyserver
	}
	argv := []string{"gpg", "--homedir", home, "--batch", "--with-colons",
		"--keyserver", keyserver, "--search-keys", a.Text}
	stdout, _, _ := runGPG(rt, argv)
	out := []map[string]any{}
	for _, k := range parseColonKeysMode(stdout, false) {
		out = append(out, renderKey(k))
	}
	return out, nil
}

type receiveKeysArgs struct {
	Keyserver *string `statekit:"name=keyserver"`
	Keys      any     `statekit:"required,name=keys"`
	User      *string `statekit:"name=user"`
	Gnupghome *string `statekit:"name=gnupghome"`
	Keyring   *string `statekit:"name=keyring"`
}

type receiveKeysFunc struct{}

func (receiveKeysFunc) Name() string { return "gpg.receive_keys" }
func (receiveKeysFunc) Args() any    { return receiveKeysArgs{} }
func (receiveKeysFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*receiveKeysArgs)
	ensureGPGReady(rt)
	ret := map[string]any{"res": true, "message": []string{}}
	home, herr := createGPG(rt, a.User, a.Gnupghome, a.Keyring)
	if herr != nil {
		return nil, herr
	}
	keyserver := defaultKeyServer
	if a.Keyserver != nil && *a.Keyserver != "" {
		keyserver = *a.Keyserver
	}
	var ids []string
	switch t := a.Keys.(type) {
	case string:
		ids = strings.Split(t, ",")
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok {
				ids = append(ids, s)
			}
		}
	}
	argv := []string{"gpg", "--homedir", home, "--batch", "--status-fd", "2",
		"--keyserver", keyserver, "--recv-keys"}
	argv = append(argv, ids...)
	_, stderr, exitCode := runGPG(rt, argv)
	messages := []string{}
	okAny := false
	for _, line := range statusFields(stderr, "IMPORT_OK") {
		fields := line
		if len(fields) < 2 {
			continue
		}
		okAny = true
		fp := fields[1]
		switch fields[0] {
		case "0":
			messages = append(messages, fmt.Sprintf("Key %s already exists in keychain", fp))
		case "1":
			messages = append(messages, fmt.Sprintf("Key %s added to keychain", fp))
		case "4":
			messages = append(messages, fmt.Sprintf("Key %s updated: new signatures", fp))
		case "8":
			messages = append(messages, fmt.Sprintf("Key %s updated: new subkeys", fp))
		default:
			messages = append(messages, fmt.Sprintf("Key %s imported", fp))
		}
	}
	if !okAny {
		for _, fields := range statusFields(stderr, "IMPORT_PROBLEM") {
			rest := strings.Join(fields, " ")
			messages = append(messages,
				fmt.Sprintf("Unable to add key to keychain: %s", rest))
		}
	}
	if exitCode != 0 && !okAny {
		ret["res"] = false
		messages = append(messages, "GPG reported failure")
	}
	ret["message"] = messages
	return ret, nil
}

// ---------------------------------------------------------------------------
// gpg.import_key / export_key / read_key

type importKeyArgs struct {
	Text      *string `statekit:"name=text"`
	Filename  *string `statekit:"name=filename"`
	User      *string `statekit:"name=user"`
	Gnupghome *string `statekit:"name=gnupghome"`
	Keyring   *string `statekit:"name=keyring"`
	Select    any     `statekit:"name=select"`
}

type importKeyFunc struct{}

func (importKeyFunc) Name() string { return "gpg.import_key" }
func (importKeyFunc) Args() any    { return importKeyArgs{} }
func (importKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*importKeyArgs)
	ensureGPGReady(rt)
	text := strDerefG(a.Text)
	filename := strDerefG(a.Filename)
	if text == "" && filename == "" {
		panic(&invocationErr{msg: "filename or text must be passed."})
	}
	if text != "" && filename != "" {
		panic(&invocationErr{msg: "filename and text are mutually exclusive."})
	}
	selectors := selectorList(a.Select)

	home, herr := createGPG(rt, a.User, a.Gnupghome, a.Keyring)
	if herr != nil {
		return nil, herr
	}

	importRun := func(importHome, fromPath, dataText string) (fingerprints []string, message string, resOK bool) {
		argv := []string{"gpg", "--homedir", importHome, "--batch", "--yes",
			"--status-fd", "2", "--import"}
		var payload []byte
		path := fromPath
		if dataText != "" {
			payload = []byte(dataText)
			path = filepath.Join(importHome, ".statekit-import.asc")
		}
		if payload != nil {
			rt.FS.WriteFile(path, payload, 0o600)
			defer rt.FS.Remove(path)
		}
		argv = append(argv, path)
		_, stderr, exitCode := runGPG(rt, argv)
		var fps []string
		countImported := 0
		countUnchanged := 0
		for _, fields := range statusFields(stderr, "IMPORTED") {
			if len(fields) >= 1 {
				fps = append(fps, fields[0]) // IMPORTED <fingerprint> <userid>
			}
			countImported++
		}
		for _, fields := range statusFields(stderr, "IMPORT_RES") {
			if len(fields) >= 1 {
				if n, perr := strconv.Atoi(fields[0]); perr == nil && n > countImported {
					countImported = n
				}
			}
		}
		if exitCode == 0 && countImported == 0 {
			countUnchanged = 1
		}
		switch {
		case countImported > 0:
			return fps, "Successfully imported key(s).", true
		case countUnchanged > 0:
			return fps, "Key(s) already exist in keychain.", true
		default:
			return nil, "Unable to import key.", false
		}
	}

	if len(selectors) > 0 {
		// Import everything into a throwaway keyring, then export only the
		// selected identities back into text.
		tmpRes, terr := callDelegateG(rt, "temp.file", struct{}{})
		if terr != nil {
			return nil, terr
		}
		tmpKeyring, _ := tmpRes.(string)
		defer rt.FS.Remove(tmpKeyring)
		fps, msg, ok := importRun(home, filename, text)
		if !ok {
			return map[string]any{"res": false, "message": msg, "fingerprints": nil}, nil
		}
		exportArgv := []string{"gpg", "--homedir", home, "--batch", "--armor",
			"--export"}
		exportArgv = append(exportArgv, selectors...)
		stdout, _, ecode := runGPG(rt, exportArgv)
		if ecode != 0 || strings.TrimSpace(stdout) == "" {
			return map[string]any{
				"res":          true,
				"message":      "After filtering, no keys to import were left.",
				"fingerprints": []any{},
			}, nil
		}
		text = stdout
		filename = ""
		_ = fps
	}

	fps, msg, ok := importRun(home, filename, text)
	out := map[string]any{"res": ok, "message": msg, "fingerprints": fps}
	if fps == nil {
		out["fingerprints"] = []any{}
	}
	return out, nil
}

func selectorList(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

type exportKeyArgs struct {
	Keyids        any     `statekit:"name=keyids"`
	Secret        *bool   `statekit:"name=secret"`
	User          *string `statekit:"name=user"`
	Gnupghome     *string `statekit:"name=gnupghome"`
	UsePassphrase *bool   `statekit:"name=use_passphrase"`
	Output        *string `statekit:"name=output"`
	Bare          *bool   `statekit:"name=bare"`
	Keyring       *string `statekit:"name=keyring"`
}

type exportKeyFunc struct{}

func (exportKeyFunc) Name() string { return "gpg.export_key" }
func (exportKeyFunc) Args() any    { return exportKeyArgs{} }
func (exportKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*exportKeyArgs)
	ensureGPGReady(rt)
	ret := map[string]any{"res": true}
	home, herr := createGPG(rt, a.User, a.Gnupghome, a.Keyring)
	if herr != nil {
		return nil, herr
	}
	passphrase, perr := passphraseOf(rt, a.UsePassphrase != nil && *a.UsePassphrase)
	if perr != nil {
		return nil, perr
	}
	argv := []string{"gpg", "--homedir", home, "--batch", "--armor",
		"--status-fd", "2"}
	if passphrase != "" {
		argv = append(argv, "--pinentry-mode", "loopback", "--passphrase", passphrase)
	}
	if a.Secret != nil && *a.Secret {
		argv = append(argv, "--export-secret-keys")
	} else {
		argv = append(argv, "--export")
	}
	switch t := a.Keyids.(type) {
	case string:
		if t != "" {
			argv = append(argv, strings.Split(t, ",")...)
		}
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok {
				argv = append(argv, s)
			}
		}
	}
	stdout, _, exitCode := runGPG(rt, argv)
	result := ""
	if exitCode == 0 && strings.Contains(stdout, "BEGIN PGP") {
		result = stdout + "\n"
	}
	bare := a.Bare != nil && *a.Bare
	output := strDerefG(a.Output)

	if result != "" && output != "" {
		rt.FS.WriteFile(output, []byte(result), 0o600)
	}
	if result != "" {
		if bare {
			return result, nil
		}
		if output != "" {
			ret["comment"] = fmt.Sprintf("Exported key data has been written to %s", output)
		} else {
			ret["comment"] = result
		}
		return ret, nil
	}
	if bare {
		return false, nil
	}
	ret["res"] = false
	return ret, nil
}

type readKeyArgs struct {
	Path        *string `statekit:"name=path"`
	Text        *string `statekit:"name=text"`
	Fingerprint *string `statekit:"name=fingerprint"`
	Keyid       *string `statekit:"name=keyid"`
	User        *string `statekit:"name=user"`
	Gnupghome   *string `statekit:"name=gnupghome"`
}

type readKeyFunc struct{}

func (readKeyFunc) Name() string { return "gpg.read_key" }
func (readKeyFunc) Args() any    { return readKeyArgs{} }
func (readKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*readKeyArgs)
	ensureGPGReady(rt)
	path := strDerefG(a.Path)
	text := strDerefG(a.Text)
	if path == "" && text == "" {
		panic(&invocationErr{msg: "Either `path` or `text` is required."})
	}
	if path != "" && text != "" {
		panic(&invocationErr{msg: "`path` and `text` are mutually exclusive."})
	}
	home, herr := createGPG(rt, a.User, a.Gnupghome, nil)
	if herr != nil {
		return nil, herr
	}
	target := path
	if target == "" {
		target = filepath.Join(home, ".statekit-read.asc")
		rt.FS.WriteFile(target, []byte(text), 0o600)
		defer rt.FS.Remove(target)
	}
	argv := []string{"gpg", "--homedir", home, "--batch", "--with-colons",
		"--show-keys", target}
	stdout, _, _ := runGPG(rt, argv)
	rets := []map[string]any{}
	for _, k := range parseColonKeysMode(stdout, false) {
		if strDerefG(a.Fingerprint) != "" || strDerefG(a.Keyid) != "" {
			if !matchKey(k, a.Keyid, a.Fingerprint) {
				continue
			}
		}
		rets = append(rets, renderKey(k))
	}
	return rets, nil
}

// ---------------------------------------------------------------------------
// gpg.create_key / delete_key / trust_key

type createKeyArgs struct {
	KeyType       *string `statekit:"name=key_type"`
	KeyLength     *int    `statekit:"name=key_length"`
	NameReal      *string `statekit:"name=name_real"`
	NameComment   *string `statekit:"name=name_comment"`
	NameEmail     *string `statekit:"name=name_email"`
	SubkeyType    *string `statekit:"name=subkey_type"`
	SubkeyLength  *int    `statekit:"name=subkey_length"`
	ExpireDate    *string `statekit:"name=expire_date"`
	UsePassphrase *bool   `statekit:"name=use_passphrase"`
	User          *string `statekit:"name=user"`
	Gnupghome     *string `statekit:"name=gnupghome"`
	Keyring       *string `statekit:"name=keyring"`
}

type createKeyFunc struct{}

func (createKeyFunc) Name() string { return "gpg.create_key" }
func (createKeyFunc) Args() any    { return createKeyArgs{} }
func (createKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*createKeyArgs)
	ensureGPGReady(rt)
	ret := map[string]any{"res": true, "fingerprint": "", "message": ""}
	home, herr := createGPG(rt, a.User, a.Gnupghome, a.Keyring)
	if herr != nil {
		return nil, herr
	}

	keyType := orDefaultA(a.KeyType, "RSA")
	keyLength := 1024
	if a.KeyLength != nil && *a.KeyLength > 0 {
		keyLength = *a.KeyLength
	}
	nameReal := orDefaultA(a.NameReal, "Autogenerated Key")

	var params []string
	addParam := func(line string) { params = append(params, line) }
	addParam("Key-Type: " + keyType)
	addParam(fmt.Sprintf("Key-Length: %d", keyLength))
	addParam("Name-Real: " + nameReal)
	if nc := strDerefG(a.NameComment); nc != "" {
		addParam("Name-Comment: " + nc)
	}
	if ne := strDerefG(a.NameEmail); ne != "" {
		addParam("Name-Email: " + ne)
	}
	if st := strDerefG(a.SubkeyType); st != "" {
		addParam("Subkey-Type: " + st)
		if sl := a.SubkeyLength; sl != nil && *sl > 0 {
			addParam(fmt.Sprintf("Subkey-Length: %d", *sl))
		}
	}
	if ed := strDerefG(a.ExpireDate); ed != "" {
		addParam("Expire-Date: " + ed)
	}
	usePass := a.UsePassphrase != nil && *a.UsePassphrase
	resolvedPass, perr := passphraseOf(rt, usePass)
	if perr != nil {
		ret["res"] = false
		ret["message"] = "gpg_passphrase not available in pillar."
		return ret, nil
	}
	if usePass {
		params = append(params, "Passphrase: "+resolvedPass)
	} else {
		addParam("%no-protection")
	}
	addParam("%commit")

	paramFile := filepath.Join(home, ".statekit-genkey-params")
	rt.FS.WriteFile(paramFile, []byte(strings.Join(params, "\n")+"\n"), 0o600)
	defer rt.FS.Remove(paramFile)

	argv := []string{"gpg", "--homedir", home, "--batch", "--status-fd", "2",
		"--gen-key", paramFile}
	_, stderr, _ := runGPG(rt, argv)
	fingerprint := ""
	fingerprint = parseKeyCreated(stderr)
	if fingerprint != "" {
		ret["fingerprint"] = fingerprint
		ret["message"] = "GPG key pair successfully generated."
	} else {
		ret["res"] = false
		ret["message"] = "Unable to generate GPG key pair."
	}
	return ret, nil
}

func orDefaultA(s *string, def string) string {
	v := strDerefG(s)
	if v == "" {
		return def
	}
	return v
}

type deleteKeyArgs struct {
	Keyid         *string `statekit:"name=keyid"`
	Fingerprint   *string `statekit:"name=fingerprint"`
	DeleteSecret  *bool   `statekit:"name=delete_secret"`
	User          *string `statekit:"name=user"`
	Gnupghome     *string `statekit:"name=gnupghome"`
	UsePassphrase *bool   `statekit:"name=use_passphrase"`
	Keyring       *string `statekit:"name=keyring"`
}

type deleteKeyFunc struct{}

func (deleteKeyFunc) Name() string { return "gpg.delete_key" }
func (deleteKeyFunc) Args() any    { return deleteKeyArgs{} }
func (deleteKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*deleteKeyArgs)
	ensureGPGReady(rt)
	ret := map[string]any{"res": true, "message": ""}
	if strDerefG(a.Fingerprint) != "" && strDerefG(a.Keyid) != "" {
		ret["res"] = false
		ret["message"] = "Only specify one argument, fingerprint or keyid"
		return ret, nil
	}
	if strDerefG(a.Fingerprint) == "" && strDerefG(a.Keyid) == "" {
		ret["res"] = false
		ret["message"] = "Required argument, fingerprint or keyid"
		return ret, nil
	}

	pubKeys, kerr := listKeysRaw(rt, a.User, a.Gnupghome, a.Keyring, false)
	if kerr != nil {
		return nil, kerr
	}
	var matched *rawKey
	for i := range pubKeys {
		if matchKey(pubKeys[i], a.Keyid, a.Fingerprint) {
			matched = &pubKeys[i]
			break
		}
	}
	if matched == nil {
		ret["res"] = false
		ret["message"] = "Key not available in keychain."
		return ret, nil
	}
	fpr := matched.fingerprint

	deleteOne := func(secret bool) string {
		home, herr := getUserGnupghome(rt, a.User)
		if herr != nil {
			home = strDerefG(a.Gnupghome)
		}
		mode := "--delete-keys"
		if secret {
			mode = "--delete-secret-keys"
		}
		argv := []string{"gpg", "--homedir", home, "--batch", "--yes", mode, fpr}
		_, _, code := runGPG(rt, argv)
		if code == 0 {
			return "ok"
		}
		return "failed"
	}

	secKeys, serr := listKeysRaw(rt, a.User, a.Gnupghome, a.Keyring, true)
	if serr != nil {
		return nil, serr
	}
	hasSecret := false
	for _, k := range secKeys {
		if k.fingerprint == fpr {
			hasSecret = true
			break
		}
	}
	if hasSecret {
		if a.DeleteSecret == nil || !*a.DeleteSecret {
			ret["res"] = false
			ret["message"] = "Secret key exists, delete first or pass delete_secret=True."
			return ret, nil
		}
		if out := deleteOne(true); out == "ok" {
			ret["message"] = fmt.Sprintf("Secret key for %s deleted\n", fpr)
		} else {
			ret["res"] = false
			ret["message"] = fmt.Sprintf("Failed to delete secret key for %s: %s", fpr, out)
			return ret, nil
		}
	}
	if out := deleteOne(false); out == "ok" {
		ret["message"] = ret["message"].(string) + fmt.Sprintf("Public key for %s deleted", fpr)
	} else {
		ret["res"] = false
		ret["message"] = ret["message"].(string) +
			fmt.Sprintf("Failed to delete public key for %s: %s", fpr, out)
	}
	return ret, nil
}

type trustKeyArgs struct {
	Keyid       *string `statekit:"name=keyid"`
	Fingerprint *string `statekit:"name=fingerprint"`
	TrustLevel  *string `statekit:"name=trust_level"`
	User        *string `statekit:"name=user"`
	Gnupghome   *string `statekit:"name=gnupghome"`
	Keyring     *string `statekit:"name=keyring"`
}

type trustKeyFunc struct{}

func (trustKeyFunc) Name() string { return "gpg.trust_key" }
func (trustKeyFunc) Args() any    { return trustKeyArgs{} }
func (trustKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverG(&res, &err)
	a := args.(*trustKeyArgs)
	ensureGPGReady(rt)
	ret := map[string]any{"res": true, "message": ""}
	exactlyOne := (strDerefG(a.Keyid) != "") != (strDerefG(a.Fingerprint) != "")
	if !exactlyOne {
		panic(&invocationErr{msg: "Exactly one of keyid or fingerprint is required"})
	}
	tl := strDerefG(a.TrustLevel)
	num, known := numTrust[tl]
	if !known {
		// Upstream message preserves dict insertion order.
		order := []string{"expired", "unknown", "not_trusted", "marginally", "fully", "ultimately"}
		panic(&invocationErr{
			msg: fmt.Sprintf("ERROR: Valid trust levels - %s", strings.Join(order, ","))})
	}
	keys, kerr := listKeysRaw(rt, a.User, a.Gnupghome, a.Keyring, false)
	if kerr != nil {
		return nil, kerr
	}
	var matched *rawKey
	for i := range keys {
		if matchKey(keys[i], a.Keyid, a.Fingerprint) {
			matched = &keys[i]
			break
		}
	}
	if matched == nil {
		ret["res"] = false
		ret["message"] = fmt.Sprintf("Key %s not in GPG keychain", orDefaultA(a.Keyid, strDerefG(a.Fingerprint)))
		return ret, nil
	}
	if strDerefG(a.Fingerprint) == "" && matched.fingerprint == "" {
		ret["res"] = false
		ret["message"] = fmt.Sprintf("Fingerprint not found for keyID %s", strDerefG(a.Keyid))
		return ret, nil
	}
	fpr := strDerefG(a.Fingerprint)
	if fpr == "" {
		fpr = matched.fingerprint
	}
	home, herr := getUserGnupghome(rt, a.User)
	if herr != nil {
		return nil, herr
	}
	kr := strDerefG(a.Keyring)
	stdin := fmt.Sprintf("%s:%s\n", fpr, num)
	argv := []string{"gpg", "--homedir", home, "--import-ownertrust"}
	if kr != "" {
		argv = append(argv, "--no-default-keyring", "--keyring", kr)
	}
	// The Runner carries no stdin channel; ownertrust input flows through a
	// temp file consumed by --import-ownertrust.
	paramFile := filepath.Join(home, ".statekit-ownertrust")
	rt.FS.WriteFile(paramFile, []byte(stdin), 0o600)
	defer rt.FS.Remove(paramFile)
	argv = append(argv, paramFile)
	_, stderr, exitCode := runGPG(rt, argv)
	_ = exitCode
	digits := collectDigits(stderr)
	switch len(digits) {
	case 2:
		ret["fingerprint"] = fpr
		ret["message"] = fmt.Sprintf("Changing ownership trust from %s to %s.",
			invNumTrust[digits[0]], invNumTrust[digits[1]])
	case 1:
		ret["fingerprint"] = fpr
		ret["message"] = fmt.Sprintf("Setting ownership trust to %s.", invNumTrust[digits[0]])
	default:
		ret["message"] = strings.TrimSpace(stderr)
	}
	return ret, nil
}

// statusFields returns the argument vectors of every --status-fd line with
// the given keyword, prefix already stripped.
func statusFields(stderr, keyword string) [][]string {
	out := [][]string{}
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		prefix := "[GNUPG:] " + keyword + " "
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		out = append(out, strings.Fields(strings.TrimPrefix(line, prefix)))
	}
	return out
}

func parseKeyCreated(stderr string) string {
	for _, fields := range statusFields(stderr, "KEY_CREATED") {
		if len(fields) >= 2 {
			return fields[1]
		}
	}
	return ""
}

func collectDigits(stderr string) []string {
	var digits []string
	inDigits := false
	cur := ""
	flushCur := func() {
		if cur != "" {
			digits = append(digits, cur)
			cur = ""
		}
	}
	for _, r := range stderr {
		if r >= '0' && r <= '9' {
			inDigits = true
			cur += string(r)
			continue
		}
		if inDigits {
			inDigits = false
			flushCur()
		}
	}
	flushCur()
	return digits
}

// RegisterKeyMgmt installs the R5.7 gpg key-management surface.
func RegisterKeyMgmt(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		listKeysFunc{},
		listSecretKeysFunc{},
		getKeyFunc{},
		getSecretKeyFunc{},
		searchKeysFunc{},
		receiveKeysFunc{},
		importKeyFunc{},
		exportKeyFunc{},
		readKeyFunc{},
		createKeyFunc{},
		deleteKeyFunc{},
		trustKeyFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
