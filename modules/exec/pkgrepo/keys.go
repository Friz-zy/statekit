package pkgrepo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// APT repository key management, mirroring the key functions of
// saltstack/salt/modules/aptpkg.py @ pinned revision.

// convertIfInt mirrors _convert_if_int: numeric strings become ints,
// everything else passes through untouched.
func convertIfInt(value string) any {
	if v, err := strconvInt(value); err == nil {
		return v
	}
	return value
}

func strconvInt(s string) (int, error) {
	n := 0
	digits := false
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	neg := false
	for i, c := range s {
		switch {
		case c == '-' && i == 0:
			neg = true
		case c >= '0' && c <= '9':
			digits = true
			n = n*10 + int(c-'0')
		default:
			return 0, fmt.Errorf("not int")
		}
	}
	if !digits {
		// Python's int("-") raises ValueError; "-" alone is not a number.
		return 0, fmt.Errorf("no digits")
	}
	if neg {
		n = -n
	}
	return n, nil
}

// itemAt indexes the colon-record safely. Upstream indexes blindly and
// crashes on truncated records; StateKit degrades those to None
// (documented divergence).
func itemAt(items []any, idx int) any {
	if idx < len(items) {
		return items[idx]
	}
	return nil
}

// parseRepoKeysOutput ports _parse_repo_keys_output over gpg
// --with-colons records.
func parseRepoKeysOutput(cmdRet string) map[string]map[string]any {
	ret := map[string]map[string]any{}
	var repoKeys []map[string]any

	for _, line := range strings.Split(cmdRet, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var items []any
		for _, raw := range strings.Split(line, ":") {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" {
				items = append(items, nil)
				continue
			}
			items = append(items, convertIfInt(trimmed))
		}
		if len(items) < 2 {
			continue
		}
		kind, _ := items[0].(string)
		switch kind {
		case "pub", "sub":
			keyProps := map[string]any{
				"algorithm":       itemAt(items, 3),
				"bits":            itemAt(items, 2),
				"capability":      itemAt(items, 11),
				"date_creation":   itemAt(items, 5),
				"date_expiration": itemAt(items, 6),
				"keyid":           scalarString(itemAt(items, 4)),
				"validity":        itemAt(items, 1),
			}
			if kind == "pub" {
				repoKeys = append(repoKeys, keyProps)
			} else if len(repoKeys) > 0 {
				repoKeys[len(repoKeys)-1]["subkey"] = keyProps
			}
		case "fpr":
			if len(repoKeys) == 0 {
				continue
			}
			last := repoKeys[len(repoKeys)-1]
			if sub, ok := last["subkey"].(map[string]any); ok {
				sub["fingerprint"] = itemAt(items, 9)
			} else {
				last["fingerprint"] = itemAt(items, 9)
			}
		case "uid":
			if len(repoKeys) == 0 {
				continue
			}
			last := repoKeys[len(repoKeys)-1]
			last["uid"] = itemAt(items, 9)
			last["uid_hash"] = itemAt(items, 7)
		}
	}

	for _, key := range repoKeys {
		keyid, _ := key["keyid"].(string)
		ret[keyid] = key
	}
	return ret
}

// getRepoKeysInternal mirrors get_repo_keys. Returns map[string]map[string]any
// on success or the untyped false when the keydir is missing (upstream
// returns False there).
func getRepoKeysInternal(ctx context.Context, rt *runtime.Runtime, aptkey bool, keydir string) (any, error) {
	if whichBin("apt-key") == "" {
		aptkey = false
	}
	if !aptkey {
		if keydir == "" {
			keydir = aptKeyringDir
		}
		info, err := rt.FS.Stat(keydir)
		if err != nil || !info.IsDir() {
			// Upstream logs "The directory %s does not exist. Please create
			// this directory only writable by root".
			return false, nil
		}
		entries, err := rt.FS.ReadDir(keydir)
		if err != nil {
			return false, nil
		}
		var outputs []string
		for _, entry := range entries {
			keyFile := filepath.Join(keydir, entry.Name())
			out := callApt(ctx, rt, []string{
				"gpg",
				"--no-default-keyring",
				"--keyring", keyFile,
				"--list-keys",
				"--with-colons",
			}, nil)
			outputs = append(outputs, string(out.Stdout))
		}
		return parseRepoKeysOutput(strings.Join(outputs, " ")), nil
	}
	cmd := []string{
		"apt-key",
		"adv",
		"--batch",
		"--list-public-keys",
		"--with-fingerprint",
		"--with-fingerprint",
		"--with-colons",
		"--fixed-list-mode",
	}
	cmdRet := callApt(ctx, rt, cmd, nil)
	if cmdRet.ExitCode != 0 {
		// Upstream returns an undefined local here (NameError at runtime);
		// StateKit surfaces the failure explicitly instead.
		return nil, fmt.Errorf("apt-key failed: %s", string(cmdRet.Stderr))
	}
	return parseRepoKeysOutput(string(cmdRet.Stdout)), nil
}

// decryptKey mirrors _decrypt_key: ASCII-armored keys are dearmored through
// gpg unless the destination keeps the .asc extension (apt-secure accepts
// armored .asc keyrings; regression #68464).
func decryptKey(rt *runtime.Runtime, key, keyfile string) (string, error) {
	data, err := rt.FS.ReadFile(key)
	if err != nil {
		// UnicodeDecodeError/read problems mean "not ASCII Armored".
		return key, nil
	}
	content := strings.Trim(string(data), "-")
	if !strings.HasPrefix(content, "BEGIN PGP") {
		return key, nil
	}
	if strings.HasSuffix(keyfile, ".asc") {
		// Leave the key ASCII-armored per the apt-secure(8) spec.
		return key, nil
	}
	if whichBin("gpg") == "" {
		// Upstream logs "Detected an ASCII armored key %s and the gpg
		// binary is not available. Not decrypting the key."
		return "", nil
	}
	decryptedKey := key + ".decrypted"
	out := callApt(context.Background(), rt, []string{
		"gpg", "--yes", "--output", decryptedKey, "--dearmor", key,
	}, nil)
	if out.ExitCode != 0 {
		// Upstream logs the failure yet still returns the .decrypted path;
		// quirk preserved.
	}
	return decryptedKey, nil
}

// addRepoKeyRequest carries the pkg.add_repo_key arguments.
type addRepoKeyRequest struct {
	path      string
	text      string
	keyserver string
	keyid     string
	saltenv   string
	aptkey    bool
	keydir    string
	keyfile   string
}

// addRepoKeyInternal mirrors add_repo_key. The bool reply matches upstream's
// boolean return; raised Salt errors surface as non-nil errors.
func addRepoKeyInternal(ctx context.Context, rt *runtime.Runtime, req addRepoKeyRequest) (bool, error) {
	if req.keydir == "" {
		req.keydir = aptKeyringDir
	}
	if !req.aptkey {
		info, err := rt.FS.Stat(req.keydir)
		if err != nil || !info.IsDir() {
			// Upstream logs "The directory %s does not exist. Please create
			// this directory only writable by root".
			return false, nil
		}
	}
	if whichBin("apt-key") == "" {
		req.aptkey = false
	}

	// Check the requested id against the known ids before importing.
	if req.keyid != "" {
		keys, kerr := getRepoKeysInternal(ctx, rt, req.aptkey, req.keydir)
		if kerr != nil {
			return false, kerr
		}
		if m, ok := keys.(map[string]map[string]any); ok {
			for currentKeyid := range m {
				if strings.HasSuffix(currentKeyid, req.keyid) {
					return true, nil
				}
			}
		}
	}

	var cmd []string
	var stdin []byte
	switch {
	case req.path != "":
		cached, cerr := cacheFileHook(ctx, rt, req.path, req.saltenv)
		if cerr != nil {
			return false, cerr
		}
		if cached == "" {
			// Upstream logs "Unable to get cached copy of file: %s".
			return false, nil
		}
		if !req.aptkey {
			destKeyfile := filepath.Base(cached)
			if req.keyfile != "" {
				destKeyfile = req.keyfile
			}
			key, derr := decryptKey(rt, cached, destKeyfile)
			if derr != nil {
				return false, derr
			}
			if key == "" {
				return false, nil
			}
			finalName := req.keyfile
			if finalName == "" {
				finalName = filepath.Base(key)
				finalName = strings.TrimSuffix(finalName, ".decrypted")
			}
			data, rerr := rt.FS.ReadFile(key)
			if rerr != nil {
				return false, rerr
			}
			if werr := rt.FS.WriteFile(filepath.Join(req.keydir, finalName), data, 0o644); werr != nil {
				return false, werr
			}
			return true, nil
		}
		cmd = []string{"apt-key", "add", cached}
	case req.text != "":
		cmd = []string{"apt-key", "add", "-"}
		stdin = []byte(req.text)
	case req.keyserver != "":
		if req.keyid == "" {
			return false, fmt.Errorf("No keyid or keyid too short for keyserver: %s", req.keyserver)
		}
		if !req.aptkey {
			if req.keyfile == "" {
				// Upstream logs "You must define the name of the key file to
				// save the key. See keyfile argument".
				return false, nil
			}
			cmd = []string{
				"gpg",
				"--no-default-keyring",
				"--keyring", filepath.Join(req.keydir, req.keyfile),
				"--keyserver", req.keyserver,
				"--recv-keys", req.keyid,
			}
		} else {
			cmd = []string{"apt-key", "adv", "--batch",
				"--keyserver", req.keyserver, "--recv", req.keyid}
		}
	case req.keyid != "":
		return false, fmt.Errorf("No keyserver specified for keyid: %s", req.keyid)
	default:
		return false, fmt.Errorf("%s() takes at least 1 argument (0 given)", "add_repo_key")
	}

	cmdRet := callApt(ctx, rt, cmd, stdin)
	if cmdRet.ExitCode == 0 {
		return true, nil
	}
	// Upstream logs "Unable to add repo key: %s".
	return false, nil
}

// getKeyFromID mirrors _get_key_from_id: locate the keyring file holding
// the requested (short or long) key id.
func getKeyFromID(ctx context.Context, rt *runtime.Runtime, keydir, keyid string) string {
	if len(keyid) != 8 && len(keyid) != 16 {
		// Upstream logs "The keyid needs to be either 8 or 16 characters".
		return ""
	}
	entries, err := rt.FS.ReadDir(keydir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		keyFile := filepath.Join(keydir, entry.Name())
		out := callApt(ctx, rt, []string{
			"gpg",
			"--no-default-keyring",
			"--keyring", keyFile,
			"--list-keys",
			"--with-colons",
		}, nil)
		ret := parseRepoKeysOutput(string(out.Stdout))
		for _, key := range ret {
			kid, _ := key["keyid"].(string)
			if strings.HasSuffix(kid, keyid) {
				return keyFile
			}
		}
	}
	// Upstream logs "Could not find the key file for keyid: %s".
	return ""
}

// delRepoKeyInternal mirrors del_repo_key; returns False (nil, no error) on
// the boolean-failure paths and the keyid string on success.
func delRepoKeyInternal(ctx context.Context, rt *runtime.Runtime, name string, aptkey bool, keydir string, keyid string, keyidPPA bool) (any, error) {
	if keydir == "" {
		keydir = aptKeyringDir
	}
	if !aptkey {
		info, err := rt.FS.Stat(keydir)
		if err != nil || !info.IsDir() {
			return false, nil
		}
	}
	if whichBin("apt-key") == "" {
		aptkey = false
	}

	if keyidPPA {
		if !strings.HasPrefix(name, "ppa:") {
			return nil, fmt.Errorf("keyid_ppa requires that a PPA be passed")
		}
		parts := strings.Split(name[4:], "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("ValueError unpacking PPA name: %s", name[4:])
		}
		ppaInfo, err := fetchLaunchpadPPA(parts[0], parts[1])
		if err != nil {
			return nil, err
		}
		fingerprint, _ := ppaInfo["signing_key_fingerprint"].(string)
		if len(fingerprint) > 8 {
			keyid = fingerprint[len(fingerprint)-8:]
		} else {
			keyid = fingerprint
		}
	} else if keyid == "" {
		return nil, fmt.Errorf("keyid or keyid_ppa and PPA name must be passed")
	}

	if !aptkey {
		keyFile := getKeyFromID(ctx, rt, keydir, keyid)
		if keyFile == "" {
			return false, nil
		}
		if err := rt.FS.Remove(keyFile); err != nil {
			return false, err
		}
		return keyid, nil
	}
	result := callApt(ctx, rt, []string{"apt-key", "del", keyid}, nil)
	if result.ExitCode != 0 {
		msg := fmt.Sprintf("Failed to remove keyid %s", keyid)
		if len(result.Stderr) > 0 {
			msg += fmt.Sprintf(": %s", string(result.Stderr))
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return keyid, nil
}

// fetchLaunchpadPPANet performs the real Launchpad API GET behind the
// injectable hook, mirroring _get_ppa_info_from_launchpad.
func fetchLaunchpadPPANet(owner, ppa string) (map[string]any, error) {
	url := fmt.Sprintf("https://launchpad.net/api/1.0/~%s/+archive/%s", owner, ppa)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, &launchpadError{status: resp.StatusCode}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}
