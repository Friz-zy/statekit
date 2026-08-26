// Package ssh implements Salt's ssh execution module, starting with the
// known-hosts surface (R5.1): get/recv/check/rm/set known-host entries and
// hash_known_hosts, mirroring saltstack/salt/modules/ssh.py @ pinned
// revision.
//
// External binaries (ssh-keygen, ssh-keyscan) run through the central
// Runner with which-guards carrying upstream's verbatim
// CommandNotFoundError texts. Known-hosts files are manipulated through
// the FileSystem abstraction so both OS and memory trees are testable.
//
// Documented boundaries:
//   - the CentOS-5 ssh-keyscan "-t rsa" legacy branch keys off an
//     injectable osfinger probe that defaults to empty (the distro is EOL);
//   - user resolution goes through the optional user.info delegate exactly
//     like Salt's __salt__ lookup;
//   - auth-keys surface (auth_keys/set_auth_key/user_keys/...) stays
//     pending for its own phase.
package ssh

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/filesum"
	"github.com/friz-zy/statekit/internal/runtime"
	"github.com/friz-zy/statekit/modules/exec/cp"
	execuser "github.com/friz-zy/statekit/modules/exec/user"
)

func execLookPath(exe string) (string, error) { return exec.LookPath(exe) }

const defaultSSHPort = 22

var (
	whichBin = func(exe string) string {
		p, err := execLookPath(exe)
		if err != nil {
			return ""
		}
		return p
	}
	currentEuid = func() int { return procEuid() }
	osFinger    = func(rt *runtime.Runtime) string { return "" }
)

// ---------------------------------------------------------------------------
// low-level helpers

func cmdRun(rt *runtime.Runtime, ignoreRetcode bool, argv ...string) string {
	res := rt.Runner.Run(context.Background(), runtime.Command(argv...))
	return strings.TrimRight(string(res.Stdout), "\n")
}

func requireBinary(exe string) error {
	if whichBin(exe) == "" {
		return fmt.Errorf("The '%s' binary was not found in $PATH.", exe)
	}
	return nil
}

// fingerprint mirrors _fingerprint: RFC 4716 colon-separated hex digest of
// the strict-base64-decoded public key. Invalid base64 yields "" (upstream
// returns None); an unsupported hash type raises.
func fingerprint(publicKey string, fingerprintHashType *string) (string, error) {
	hashType := "sha256"
	if fingerprintHashType != nil && *fingerprintHashType != "" {
		hashType = strings.ToLower(*fingerprintHashType)
	}
	h, err := filesum.New(hashType)
	if err != nil {
		return "", fmt.Errorf("The fingerprint_hash_type %s is not supported.", hashType)
	}
	raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKey))
	if derr != nil {
		return "", nil
	}
	h.Write(raw)
	digest := fmt.Sprintf("%x", h.Sum(nil))
	chunks := make([]string, 0, len(digest)/2)
	for i := 0; i < len(digest); i += 2 {
		end := i + 2
		if end > len(digest) {
			end = len(digest)
		}
		chunks = append(chunks, digest[i:end])
	}
	return strings.Join(chunks, ":"), nil
}

type errMap struct{ msg string }

func (e *errMap) Error() string { return e.msg }

func statusError(msg string) map[string]any {
	return map[string]any{"status": "error", "error": msg}
}

// getKnownHostsFile ports _get_known_hosts_file; the upstream error-dict
// contract surfaces as a *errMap so callers can convert it into the
// {"status": "error", ...} reply.
func getKnownHostsFile(rt *runtime.Runtime, config, user *string) (string, error) {
	cfg := ""
	if config != nil {
		cfg = *config
	}
	var usr string
	if user != nil {
		usr = *user
	}
	if cfg == "" {
		if usr != "" {
			cfg = ".ssh/known_hosts"
		} else {
			cfg = "/etc/ssh/ssh_known_hosts"
		}
	}
	if filepath.IsAbs(cfg) {
		return cfg, nil
	}
	if usr == "" {
		return "", &errMap{msg: "Cannot determine absolute path to file."}
	}
	res, cerr := callUserInfo(rt, usr)
	if cerr != nil {
		return "", &errMap{msg: fmt.Sprintf("User %s does not exist", usr)}
	}
	info, _ := res.(map[string]any)
	home, _ := info["home"].(string)
	return filepath.Join(home, cfg), nil
}

func callUserInfo(rt *runtime.Runtime, user string) (any, error) {
	if _, ok := rt.Exec.Get("user.info"); !ok {
		return nil, fmt.Errorf("user.info is not available")
	}
	return rt.Exec.Call(context.Background(), rt, "user.info", &execuser.InfoArgs{Name: user})
}

func hostnameAndPortToSSHHostname(hostname string, port *int) string {
	if port == nil || *port == 0 || *port == defaultSSHPort {
		return hostname
	}
	return fmt.Sprintf("[%s]:%d", hostname, *port)
}

// parseOpensshOutput ports _parse_openssh_output over ssh-keygen -F /
// ssh-keyscan lines.
func parseOpensshOutput(lines []string, fingerprintHashType *string) ([]map[string]any, error) {
	var out []map[string]any
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		line += "\n"
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue // incorrect format
		}
		fp, ferr := fingerprint(fields[2], fingerprintHashType)
		if ferr != nil {
			return nil, ferr
		}
		if fp == "" {
			continue
		}
		out = append(out, map[string]any{
			"hostname":    fields[0],
			"key":         fields[2],
			"enc":         fields[1],
			"fingerprint": fp,
		})
	}
	return out, nil
}

// matchedHostLineNumbers ports _get_matched_host_line_numbers over the
// paired ssh-keygen -F output (even lines carry the line number, odd lines
// carry the entry whose second-to-last field is the enc type).
func matchedHostLineNumbers(lines []string, enc *string) []int {
	var out []int
	for i, line := range lines {
		if i%2 != 0 || i+1 >= len(lines) {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		lineNo, aerr := strconv.Atoi(fields[len(fields)-1])
		if aerr != nil {
			continue
		}
		entryFields := strings.Fields(strings.TrimSpace(lines[i+1]))
		if len(entryFields) < 2 {
			continue
		}
		lineEnc := entryFields[len(entryFields)-2]
		if enc != nil && *enc != "" && lineEnc != *enc {
			continue
		}
		out = append(out, lineNo)
	}
	return out
}

func knownHostEntriesFrom(rt *runtime.Runtime, out string, fingerprintHashType *string) ([]map[string]any, error) {
	entries, perr := parseOpensshOutput(strings.Split(out, "\n"), fingerprintHashType)
	if perr != nil {
		return nil, perr
	}
	return entries, nil
}

func chownToUser(rt *runtime.Runtime, full string, user *string) {
	if currentEuid() != 0 || user == nil || *user == "" {
		return
	}
	res, err := callUserInfo(rt, *user)
	if err != nil {
		return
	}
	info, _ := res.(map[string]any)
	uid, _ := info["uid"].(int)
	gid, _ := info["gid"].(int)
	rt.FS.Chown(full, uid, gid)
}

func callDelegate(rt *runtime.Runtime, name string, args any) (any, error) {
	if _, ok := rt.Exec.Get(name); !ok {
		return nil, fmt.Errorf("%s is not available", name)
	}
	return rt.Exec.Call(context.Background(), rt, name, args)
}

func cacheFileDelegate(rt *runtime.Runtime, source, saltenv string) (string, error) {
	env := saltenv
	res, err := callDelegate(rt, "cp.cache_file", &cp.CacheFileArgs{
		Path: source, Saltenv: &env,
	})
	if err != nil {
		return "", err
	}
	switch v := res.(type) {
	case string:
		return v, nil
	case bool:
		if !v {
			return "", nil
		}
	}
	return "", nil
}

func splitCmdLines(out string) []string {
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

func recoverSSH(res *any, errPtr *error) {
	if r := recover(); r != nil {
		switch e := r.(type) {
		case error:
			*errPtr = e
		default:
			panic(r)
		}
	}
}

// ---------------------------------------------------------------------------
// ssh.get_known_host_entries

type getKnownHostEntriesArgs struct {
	User                string  `statekit:"required"`
	Hostname            string  `statekit:"required,name=hostname"`
	Config              *string `statekit:"name=config"`
	Port                *int    `statekit:"name=port"`
	FingerprintHashType *string `statekit:"name=fingerprint_hash_type"`
}

type getKnownHostEntriesFunc struct{}

func (getKnownHostEntriesFunc) Name() string { return "ssh.get_known_host_entries" }
func (getKnownHostEntriesFunc) Args() any    { return getKnownHostEntriesArgs{} }
func (getKnownHostEntriesFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*getKnownHostEntriesArgs)
	entries, errReply := getKnownHostEntriesImpl(rt, a.User, a.Hostname,
		a.Config, a.Port, a.FingerprintHashType)
	if errReply != nil {
		return errReply, nil
	}
	if len(entries) == 0 {
		return nil, nil // upstream's None reply
	}
	return entries, nil
}

func getKnownHostEntriesImpl(rt *runtime.Runtime, user, hostname string,
	config *string, port *int, fingerprintHashType *string) ([]map[string]any, map[string]any) {

	if gerr := requireBinary("ssh-keygen"); gerr != nil {
		return nil, statusError(gerr.Error())
	}
	full, ferr := getKnownHostsFile(rt, config, &user)
	if ferr != nil {
		return nil, statusError(ferr.Error())
	}
	sshHostname := hostnameAndPortToSSHHostname(hostname, port)
	out := cmdRun(rt, true, "ssh-keygen", "-F", sshHostname, "-f", full)
	entries, perr := knownHostEntriesFrom(rt, out, fingerprintHashType)
	if perr != nil {
		panic(perr)
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return entries, nil
}

// ---------------------------------------------------------------------------
// ssh.recv_known_host_entries

type recvKnownHostEntriesArgs struct {
	Hostname            string  `statekit:"required,name=hostname"`
	Enc                 *string `statekit:"name=enc"`
	Port                *int    `statekit:"name=port"`
	HashKnownHosts      *bool   `statekit:"name=hash_known_hosts"`
	Timeout             *int    `statekit:"name=timeout"`
	FingerprintHashType *string `statekit:"name=fingerprint_hash_type"`
}

type recvKnownHostEntriesFunc struct{}

func (recvKnownHostEntriesFunc) Name() string { return "ssh.recv_known_host_entries" }
func (recvKnownHostEntriesFunc) Args() any    { return recvKnownHostEntriesArgs{} }
func (recvKnownHostEntriesFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*recvKnownHostEntriesArgs)
	entries, errReply := recvKnownHostEntriesImpl(rt, a.Hostname,
		strDeref(a.Enc), a.Port,
		a.HashKnownHosts == nil || *a.HashKnownHosts,
		intOr(a.Timeout, 5), a.FingerprintHashType)
	if errReply != nil {
		return errReply, nil
	}
	if len(entries) == 0 {
		return nil, nil // upstream's None reply
	}
	return entries, nil
}

func strDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func intOr(v *int, def int) int {
	if v == nil || *v == 0 {
		return def
	}
	return *v
}

func recvKnownHostEntriesImpl(rt *runtime.Runtime, hostname, enc string, port *int,
	hashKnown bool, timeout int, fingerprintHashType *string) ([]map[string]any, map[string]any) {

	if gerr := requireBinary("ssh-keyscan"); gerr != nil {
		return nil, statusError(gerr.Error())
	}
	cmd := []string{"ssh-keyscan"}
	if port != nil && *port != 0 && *port != defaultSSHPort {
		cmd = append(cmd, "-p", strconv.Itoa(*port))
	}
	if enc != "" {
		cmd = append(cmd, "-t", enc)
	} else if osFinger(rt) == "CentOS-5" {
		// Legacy openssh-clients requires the -t option; the distro is EOL
		// so the injectable probe defaults to empty.
		cmd = append(cmd, "-t", "rsa")
	}
	if hashKnown {
		cmd = append(cmd, "-H")
	}
	cmd = append(cmd, "-T", strconv.Itoa(timeout))
	cmd = append(cmd, hostname)

	var out string
	for attempts := 5; attempts > 0 && out == ""; attempts-- {
		out = cmdRun(rt, false, cmd...)
	}
	entries, perr := knownHostEntriesFrom(rt, out, fingerprintHashType)
	if perr != nil {
		panic(perr)
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return entries, nil
}

// ---------------------------------------------------------------------------
// ssh.check_known_host

type checkKnownHostArgs struct {
	User                *string `statekit:"name=user"`
	Hostname            *string `statekit:"name=hostname"`
	Key                 *string `statekit:"name=key"`
	Fingerprint         *string `statekit:"name=fingerprint"`
	Config              *string `statekit:"name=config"`
	Port                *int    `statekit:"name=port"`
	FingerprintHashType *string `statekit:"name=fingerprint_hash_type"`
}

type checkKnownHostFunc struct{}

func (checkKnownHostFunc) Name() string { return "ssh.check_known_host" }
func (checkKnownHostFunc) Args() any    { return checkKnownHostArgs{} }
func (checkKnownHostFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*checkKnownHostArgs)
	return checkKnownHostImpl(rt, a), nil
}

func checkKnownHostImpl(rt *runtime.Runtime, a *checkKnownHostArgs) any {
	hostname := strDeref(a.Hostname)
	if hostname == "" {
		return statusError("hostname argument required")
	}
	user := strDeref(a.User)
	config := a.Config
	if user == "" && config == nil {
		def := "/etc/ssh/ssh_known_hosts"
		config = &def
	} else if user != "" && config == nil {
		def := ".ssh/known_hosts"
		config = &def
	}

	entries, errReply := getKnownHostEntriesImpl(rt, user, hostname,
		a.Config, a.Port, a.FingerprintHashType)
	if errReply != nil {
		return errReply
	}
	var knownKeys, knownFingerprints []string
	for _, h := range entries {
		knownKeys = append(knownKeys, h["key"].(string))
		knownFingerprints = append(knownFingerprints, h["fingerprint"].(string))
	}
	if len(entries) == 0 {
		return "add"
	}
	if a.Key != nil && *a.Key != "" {
		for _, k := range knownKeys {
			if k == *a.Key {
				return "exists"
			}
		}
		return "update"
	} else if a.Fingerprint != nil && *a.Fingerprint != "" {
		for _, f := range knownFingerprints {
			if f == *a.Fingerprint {
				return "exists"
			}
		}
		return "update"
	}
	return "exists"
}

// ---------------------------------------------------------------------------
// ssh.rm_known_host

type rmKnownHostArgs struct {
	User     *string `statekit:"name=user"`
	Hostname *string `statekit:"name=hostname"`
	Config   *string `statekit:"name=config"`
	Port     *int    `statekit:"name=port"`
}

type rmKnownHostFunc struct{}

func (rmKnownHostFunc) Name() string { return "ssh.rm_known_host" }
func (rmKnownHostFunc) Args() any    { return rmKnownHostArgs{} }
func (rmKnownHostFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*rmKnownHostArgs)
	return rmKnownHostImpl(rt, a), nil
}

func rmKnownHostImpl(rt *runtime.Runtime, a *rmKnownHostArgs) any {
	hostname := strDeref(a.Hostname)
	if hostname == "" {
		return statusError("hostname argument required")
	}
	full, ferr := getKnownHostsFile(rt, a.Config, a.User)
	if ferr != nil {
		return statusError(ferr.Error())
	}
	if _, serr := rt.FS.Stat(full); serr != nil {
		return statusError(fmt.Sprintf("Known hosts file %s does not exist", full))
	}
	sshHostname := hostnameAndPortToSSHHostname(hostname, a.Port)
	out := cmdRun(rt, false, "ssh-keygen", "-R", sshHostname, "-f", full)
	chownToUser(rt, full, a.User)
	return map[string]any{"status": "removed", "comment": out}
}

// ---------------------------------------------------------------------------
// ssh.set_known_host

type setKnownHostArgs struct {
	User                *string `statekit:"name=user"`
	Hostname            *string `statekit:"name=hostname"`
	Fingerprint         *string `statekit:"name=fingerprint"`
	Key                 *string `statekit:"name=key"`
	Port                *int    `statekit:"name=port"`
	Enc                 *string `statekit:"name=enc"`
	Config              *string `statekit:"name=config"`
	HashKnownHosts      *bool   `statekit:"name=hash_known_hosts"`
	Timeout             *int    `statekit:"name=timeout"`
	FingerprintHashType *string `statekit:"name=fingerprint_hash_type"`
}

type setKnownHostFunc struct{}

func (setKnownHostFunc) Name() string { return "ssh.set_known_host" }
func (setKnownHostFunc) Args() any    { return setKnownHostArgs{} }
func (setKnownHostFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*setKnownHostArgs)
	return setKnownHostImpl(rt, a), nil
}

func setKnownHostImpl(rt *runtime.Runtime, a *setKnownHostArgs) any {
	hostname := strDeref(a.Hostname)
	if hostname == "" {
		return statusError("hostname argument required")
	}
	hashKnown := a.HashKnownHosts == nil || *a.HashKnownHosts
	timeout := intOr(a.Timeout, 5)
	enc := strDeref(a.Enc)
	user := strDeref(a.User)

	if a.Port != nil && *a.Port != defaultSSHPort && hashKnown {
		return statusError(
			"argument port can not be used in conjunction with argument hash_known_hosts")
	}

	updateRequired := false
	checkRequired := false
	stored, errReply := getKnownHostEntriesImpl(rt, user, hostname,
		a.Config, a.Port, a.FingerprintHashType)
	if errReply != nil {
		return errReply
	}

	var storedKeys, storedFingerprints []string
	for _, h := range stored {
		if enc == "" || h["enc"] == enc {
			storedKeys = append(storedKeys, h["key"].(string))
		}
		storedFingerprints = append(storedFingerprints, h["fingerprint"].(string))
	}

	switch {
	case len(stored) == 0:
		updateRequired = true
	case a.Fingerprint != nil && *a.Fingerprint != "" && !containsStr(storedFingerprints, *a.Fingerprint):
		updateRequired = true
	case a.Key != nil && *a.Key != "" && !containsStr(storedKeys, *a.Key):
		updateRequired = true
	case a.Key == nil && a.Fingerprint == nil:
		checkRequired = true
	}

	if !updateRequired && !checkRequired {
		return map[string]any{"status": "exists", "keys": storedKeys}
	}

	var remote []map[string]any
	if a.Key == nil || *a.Key == "" {
		var errReply2 map[string]any
		remote, errReply2 = recvKnownHostEntriesImpl(rt, hostname, enc, a.Port,
			hashKnown, timeout, a.FingerprintHashType)
		if errReply2 != nil {
			return errReply2
		}
		var knownKeys, knownFingerprints []string
		for _, h := range remote {
			knownKeys = append(knownKeys, h["key"].(string))
			knownFingerprints = append(knownFingerprints, h["fingerprint"].(string))
		}
		if len(remote) == 0 {
			return statusError("Unable to receive remote host keys")
		}
		if a.Fingerprint != nil && *a.Fingerprint != "" && !containsStr(knownFingerprints, *a.Fingerprint) {
			return statusError(
				"Remote host public keys found but none of their fingerprints match the one you have provided")
		}
		if checkRequired && equalStringSets(knownKeys, storedKeys) {
			return map[string]any{"status": "exists", "keys": storedKeys}
		}
	}

	full, ferr := getKnownHostsFile(rt, a.Config, a.User)
	if ferr != nil {
		return statusError(ferr.Error())
	}

	var origMode any
	if info, serr := rt.FS.Stat(full); serr == nil {
		origMode = info.Mode()
		// Remove existing known_host entries matching hostname + enc via the
		// ssh-keygen -F line-number pairs.
		sshHostname := hostnameAndPortToSSHHostname(hostname, a.Port)
		fout := cmdRun(rt, true, "ssh-keygen", "-F", sshHostname, "-f", full)
		removeLines := matchedHostLineNumbers(splitCmdLines(fout), &enc)
		if len(removeLines) > 0 {
			data, rerr := rt.FS.ReadFile(full)
			if rerr != nil {
				panic(fmt.Errorf("Couldn't remove old entry(ies) from known hosts file: '%s'", rerr.Error()))
			}
			knownLines := strings.Split(string(data), "\n")
			// Delete from last line to first to avoid invalidating indexes.
			sortedDesc := append([]int{}, removeLines...)
			for i := 0; i < len(sortedDesc); i++ {
				for j := i + 1; j < len(sortedDesc); j++ {
					if sortedDesc[j] > sortedDesc[i] {
						sortedDesc[i], sortedDesc[j] = sortedDesc[j], sortedDesc[i]
					}
				}
			}
			for _, lineNo := range sortedDesc {
				if lineNo-1 >= 0 && lineNo-1 < len(knownLines) {
					knownLines = append(knownLines[:lineNo-1], knownLines[lineNo:]...)
				}
			}
			out := strings.Join(knownLines, "\n")
			if werr := rt.FS.WriteFile(full, []byte(out), 0o600); werr != nil {
				panic(fmt.Errorf("Couldn't remove old entry(ies) from known hosts file: '%s'", werr.Error()))
			}
		}
	}

	// Set up the new value.
	if a.Key != nil && *a.Key != "" {
		remote = []map[string]any{{"hostname": hostname, "enc": enc, "key": *a.Key}}
	}

	portVal := 0
	if a.Port != nil {
		portVal = *a.Port
	}
	// Divergence note: with an explicit key but no enc, Python would render
	// the literal "None" placeholder into the file; StateKit writes the empty
	// enc field instead and callers pass enc alongside key (the state layer
	// always does).
	lines := make([]string, 0, len(remote))
	for _, entry := range remote {
		entryHost, _ := entry["hostname"].(string)
		entryEnc, _ := entry["enc"].(string)
		entryKey, _ := entry["key"].(string)
		if hashKnown || portVal == defaultSSHPort || portVal == 0 || strings.Contains(entryHost, ":") {
			lines = append(lines, fmt.Sprintf("%s %s %s\n", entryHost, entryEnc, entryKey))
		} else {
			lines = append(lines, fmt.Sprintf("[%s]:%d %s %s\n", entryHost, portVal, entryEnc, entryKey))
		}
	}

	// Ensure the ssh config dir exists (upstream logs mkdir failures and
	// continues; the append below surfaces real failures).
	sshDir := filepath.Dir(full)
	_ = rt.FS.MkdirAll(sshDir, 0o700)

	payload := strings.Join(lines, "")
	data, _ := rt.FS.ReadFile(full)
	newData := string(data) + payload
	if werr := rt.FS.WriteFile(full, []byte(newData), 0o600); werr != nil {
		panic(fmt.Errorf("Couldn't append to known hosts file: '%s'", werr.Error()))
	}

	chownToUser(rt, full, a.User)
	if origMode != nil {
		rt.FS.Chmod(full, origMode.(os.FileMode))
	} else {
		rt.FS.Chmod(full, 0o600)
	}

	if (a.Key != nil && *a.Key != "") && hashKnown {
		cfgAbs := full
		_ = hashKnownHostsImpl(rt, &user, &cfgAbs)
	}

	return map[string]any{"status": "updated", "old": storedOrNil(stored), "new": remote}
}

func storedOrNil(stored []map[string]any) any {
	if len(stored) == 0 {
		return nil
	}
	return stored
}

func containsStr(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, item := range a {
		seen[item]++
	}
	for _, item := range b {
		seen[item]--
		if seen[item] < 0 {
			return false
		}
	}
	for _, count := range seen {
		if count != 0 {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// ssh.hash_known_hosts

type hashKnownHostsArgs struct {
	User   *string `statekit:"name=user"`
	Config *string `statekit:"name=config"`
}

type hashKnownHostsFunc struct{}

func (hashKnownHostsFunc) Name() string { return "ssh.hash_known_hosts" }
func (hashKnownHostsFunc) Args() any    { return hashKnownHostsArgs{} }
func (hashKnownHostsFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*hashKnownHostsArgs)
	return hashKnownHostsImpl(rt, a.User, a.Config), nil
}

func hashKnownHostsImpl(rt *runtime.Runtime, user, config *string) any {
	if gerr := requireBinary("ssh-keygen"); gerr != nil {
		return statusError(gerr.Error())
	}
	full, ferr := getKnownHostsFile(rt, config, user)
	if ferr != nil {
		return statusError(ferr.Error())
	}
	if _, serr := rt.FS.Stat(full); serr != nil {
		return statusError(fmt.Sprintf("Known hosts file %s does not exist", full))
	}
	info, _ := rt.FS.Stat(full)
	origPerm := info.Mode().Perm()
	out := cmdRun(rt, false, "ssh-keygen", "-H", "-f", full)
	rt.FS.Chmod(full, origPerm)
	chownToUser(rt, full, user)
	return map[string]any{"status": "updated", "comment": out}
}

// Register installs the R5.1 known-hosts surface of the ssh module.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		getKnownHostEntriesFunc{},
		recvKnownHostEntriesFunc{},
		checkKnownHostFunc{},
		rmKnownHostFunc{},
		setKnownHostFunc{},
		hashKnownHostsFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// R5.2: authorized-keys surface

// refineEnc ports _refine_enc; unknown types raise upstream's verbatim
// CommandExecutionError.
func refineEnc(enc string) (string, error) {
	rsa := []string{"r", "rsa", "ssh-rsa"}
	dss := []string{"d", "dsa", "dss", "ssh-dss"}
	ecdsa := []string{
		"e", "ecdsa", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp256",
	}
	ed25519 := []string{"ed25519", "ssh-ed25519"}
	alsoAllowed := []string{
		"rsa-sha2-512", "rsa-sha2-256",
		"rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com",
		"ssh-rsa-cert-v01@openssh.com",
		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
		"sk-ecdsa-sha2-nistp256@openssh.com",
		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		"ssh-ed25519-cert-v01@openssh.com",
		"sk-ssh-ed25519@openssh.com", "sk-ssh-ed25519-cert-v01@openssh.com",
	}
	switch {
	case containsStr(rsa, enc):
		return "ssh-rsa", nil
	case containsStr(dss, enc):
		return "ssh-dss", nil
	case containsStr(ecdsa, enc):
		if enc == "e" || enc == "ecdsa" {
			return "ecdsa-sha2-nistp256", nil
		}
		return enc, nil
	case containsStr(ed25519, enc):
		return "ssh-ed25519", nil
	case containsStr(alsoAllowed, enc):
		return enc, nil
	}
	return "", fmt.Errorf("Incorrect encryption key type '%s'.", enc)
}

func formatAuthLine(key, enc, comment string, options []string) string {
	line := ""
	if len(options) > 0 {
		line += strings.Join(options, ",") + " "
	}
	line += fmt.Sprintf("%s %s %s\n", enc, key, comment)
	return line
}

// expandAuthorizedKeysPath ports the sshd_config(5) AuthorizedKeysFile
// token expansion (%u/%h/%%).
func expandAuthorizedKeysPath(path, user, home string) (string, error) {
	var out strings.Builder
	hadEscape := false
	for _, ch := range path {
		if hadEscape {
			hadEscape = false
			switch ch {
			case '%':
				out.WriteRune(ch)
			case 'u':
				out.WriteString(user)
			case 'h':
				out.WriteString(home)
			default:
				return "", fmt.Errorf(
					"AuthorizedKeysFile path: unknown token character \"%%%c\"", ch)
			}
			continue
		}
		if ch == '%' {
			hadEscape = true
			continue
		}
		out.WriteRune(ch)
	}
	if hadEscape {
		return "", fmt.Errorf("AuthorizedKeysFile path: Last character can't be escape character")
	}
	return out.String(), nil
}

// getConfigFile ports _get_config_file via the user.info delegate.
func getConfigFile(rt *runtime.Runtime, user, config string) (string, error) {
	res, err := callUserInfo(rt, user)
	if err != nil || res == nil {
		return "", fmt.Errorf("User '%s' does not exist", user)
	}
	info, _ := res.(map[string]any)
	home, _ := info["home"].(string)
	config, eerr := expandAuthorizedKeysPath(config, user, home)
	if eerr != nil {
		return "", eerr
	}
	if !filepath.IsAbs(config) {
		config = filepath.Join(home, config)
	}
	return config, nil
}

var validateLineRe = regexp.MustCompile(`^(.*?)\s?((?:sk-)?(?:ssh\-|ecds)[\w@.-]+\s.+)$`)

var replaceLineRe = regexp.MustCompile(`((.*)\s)?((?:sk-)?(?:ssh|ecdsa)-[a-z0-9@.-]+)\s([a-zA-Z0-9+/]+={0,2})(\s(.*))?`)

// validateKeys ports _validate_keys over an authorized-keys style file.
func validateKeys(rt *runtime.Runtime, keyFile string, fingerprintHashType *string) (map[string]map[string]any, error) {
	ret := map[string]map[string]any{}
	data, rerr := rt.FS.ReadFile(keyFile)
	if rerr != nil {
		return nil, fmt.Errorf("Problem reading ssh key file %s", keyFile)
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		search := validateLineRe.FindStringSubmatch(line)
		if search == nil {
			continue
		}
		opts := search[1]
		comps := strings.Fields(search[2])
		if len(comps) < 2 {
			continue
		}
		var options []string
		if opts != "" {
			options = strings.Split(opts, ",")
		}
		enc, key := comps[0], comps[1]
		comment := strings.Join(comps[2:], " ")
		fp, ferr := fingerprint(key, fingerprintHashType)
		if ferr != nil {
			return nil, ferr
		}
		if fp == "" {
			continue
		}
		ret[key] = map[string]any{
			"enc":         enc,
			"comment":     comment,
			"options":     options,
			"fingerprint": fp,
		}
	}
	return ret, nil
}

// replaceAuthKey ports _replace_auth_key: rewrite the file replacing every
// line whose key component matches.
func replaceAuthKey(rt *runtime.Runtime, user, key, enc, comment string, options []string, config string) error {
	authLine := formatAuthLine(key, enc, comment, options)
	full, cerr := getConfigFile(rt, user, config)
	if cerr != nil {
		return cerr
	}
	data, rerr := rt.FS.ReadFile(full)
	if rerr != nil {
		return fmt.Errorf("Problem reading or writing to key file: %s", rerr.Error())
	}
	var lines []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		stored := line + "\n"
		if strings.HasPrefix(stored, "#") {
			lines = append(lines, stored)
			continue
		}
		comps := replaceLineRe.FindStringSubmatch(line)
		if comps != nil && len(comps) > 3 && comps[4] == key {
			lines = append(lines, authLine)
		} else {
			lines = append(lines, stored)
		}
	}
	if werr := rt.FS.WriteFile(full, []byte(strings.Join(lines, "")), 0o600); werr != nil {
		return fmt.Errorf("Problem reading or writing to key file: %s", werr.Error())
	}
	return nil
}

type authKeysArgs struct {
	User                any     `statekit:"name=user"`
	Config              *string `statekit:"name=config"`
	FingerprintHashType *string `statekit:"name=fingerprint_hash_type"`
}

type authKeysFunc struct{}

func (authKeysFunc) Name() string { return "ssh.auth_keys" }
func (authKeysFunc) Args() any    { return authKeysArgs{} }
func (authKeysFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*authKeysArgs)
	users := []string{}
	oldOutputWhenOneUser := false
	switch u := a.User.(type) {
	case nil:
		list, lerr := callDelegateStrings(rt, "user.list_users")
		if lerr != nil {
			panic(lerr)
		}
		users = list
	case string:
		if u == "" {
			list, lerr := callDelegateStrings(rt, "user.list_users")
			if lerr != nil {
				panic(lerr)
			}
			users = list
		} else {
			users = []string{u}
			oldOutputWhenOneUser = true
		}
	case []any:
		for _, item := range u {
			if s, ok := item.(string); ok {
				users = append(users, s)
			}
		}
	}

	keys := map[string]any{}
	for _, u := range users {
		cfg := strDeref(a.Config)
		if cfg == "" {
			cfg = ".ssh/authorized_keys"
		}
		full, cerr := getConfigFile(rt, u, cfg)
		if cerr != nil {
			continue // upstream swallows the per-user resolution errors
		}
		if info, serr := rt.FS.Stat(full); serr == nil && info.Mode().IsRegular() {
			validated, verr := validateKeys(rt, full, a.FingerprintHashType)
			if verr != nil {
				panic(verr)
			}
			keys[u] = validated
		}
	}
	if oldOutputWhenOneUser {
		if single, ok := keys[users[0]]; ok {
			return single, nil
		}
		return map[string]any{}, nil
	}
	return keys, nil
}

func callDelegateStrings(rt *runtime.Runtime, name string) ([]string, error) {
	res, err := callDelegate(rt, name, struct{}{})
	if err != nil {
		return nil, err
	}
	list, _ := res.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out, nil
}

// hostKeys ports host_keys: scan a directory for ssh_host_*_key files.
func hostKeysImpl(rt *runtime.Runtime, keydir string, private, certs bool) map[string]any {
	fnRe := regexp.MustCompile(`ssh_host_(?P<type>.+)_key(?P<pub>(?P<cert>-cert)?\.pub)?`)
	keys := map[string]any{}
	entries, derr := rt.FS.ReadDir(keydir)
	if derr != nil {
		return keys
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, fn := range names {
		m := fnRe.FindStringSubmatch(fn)
		if m == nil {
			continue
		}
		idx := fnRe.SubexpIndex
		pub, cert := m[idx("pub")], m[idx("cert")]
		if pub == "" && !private {
			continue
		}
		if cert != "" && !certs {
			continue
		}
		kname := m[idx("type")]
		if pub != "" {
			kname += pub
		}
		data, rerr := rt.FS.ReadFile(filepath.Join(keydir, fn))
		if rerr != nil {
			keys[kname] = ""
			continue
		}
		content := string(data)
		first := content
		if i := strings.IndexByte(content, '\n'); i >= 0 {
			first = content[:i+1]
		}
		if first != "SSH PRIVATE KEY FILE FORMAT 1.1\n" {
			first += content[len(first):]
		}
		keys[kname] = strings.TrimSpace(first)
	}
	return keys
}

type hostKeysArgs struct {
	Keydir  *string `statekit:"name=keydir"`
	Private *bool   `statekit:"name=private"`
	Certs   *bool   `statekit:"name=certs"`
}

type hostKeysFunc struct{}

func (hostKeysFunc) Name() string { return "ssh.host_keys" }
func (hostKeysFunc) Args() any    { return hostKeysArgs{} }
func (hostKeysFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*hostKeysArgs)
	keydir := strDeref(a.Keydir)
	if keydir == "" {
		keydir = "/etc/ssh" // Linux grain path; non-Linux requires keydir
	}
	private := a.Private == nil || *a.Private
	certs := a.Certs == nil || *a.Certs
	return hostKeysImpl(rt, keydir, private, certs), nil
}

// ---------------------------------------------------------------------------
// ssh.check_key / check_key_file

type checkKeyArgs struct {
	User                string   `statekit:"required"`
	Key                 string   `statekit:"required,name=key"`
	Enc                 string   `statekit:"required,name=enc"`
	Comment             string   `statekit:"name=comment"`
	Options             []string `statekit:"name=options"`
	Config              *string  `statekit:"name=config"`
	CacheKeys           []string `statekit:"name=cache_keys"`
	FingerprintHashType *string  `statekit:"name=fingerprint_hash_type"`
}

type checkKeyFunc struct{}

func (checkKeyFunc) Name() string { return "ssh.check_key" }
func (checkKeyFunc) Args() any    { return checkKeyArgs{} }
func (checkKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*checkKeyArgs)
	return checkKeyImpl(rt, a.User, a.Key, a.Enc, a.Comment, a.Options,
		strDeref(a.Config), a.FingerprintHashType)
}

func authKeysConfigDefault(config *string) string {
	if config == nil || *config == "" {
		return ".ssh/authorized_keys"
	}
	return *config
}

func checkKeyImpl(rt *runtime.Runtime, user, key, enc, comment string, options []string,
	config string, fingerprintHashType *string) (string, error) {

	config = authKeysConfigDefault(&config)
	refined, rerr := refineEnc(enc)
	if rerr != nil {
		return "", rerr
	}
	current, cerr := validatedKeysForUser(rt, user, config, fingerprintHashType)
	if cerr != nil {
		return "", cerr
	}
	nline := formatAuthLine(key, refined, comment, options)
	if cur, ok := current[key]; ok {
		curEnc, _ := cur["enc"].(string)
		curComment, _ := cur["comment"].(string)
		curOptions, _ := cur["options"].([]string)
		cline := formatAuthLine(key, curEnc, curComment, curOptions)
		if cline != nline {
			return "update", nil
		}
		return "exists", nil
	}
	return "add", nil
}

// validatedKeysForUser resolves the user's authorized_keys file and parses
// it (the shared body of upstream's auth_keys()).
func validatedKeysForUser(rt *runtime.Runtime, user, config string, fingerprintHashType *string) (map[string]map[string]any, error) {
	full, err := getConfigFile(rt, user, config)
	if err != nil {
		return nil, err
	}
	info, serr := rt.FS.Stat(full)
	if serr != nil || !info.Mode().IsRegular() {
		return map[string]map[string]any{}, nil
	}
	return validateKeys(rt, full, fingerprintHashType)
}

type checkKeyFileArgs struct {
	User                string  `statekit:"required,name=user"`
	Source              string  `statekit:"required,name=source"`
	Config              *string `statekit:"name=config"`
	Saltenv             *string `statekit:"name=saltenv"`
	FingerprintHashType *string `statekit:"name=fingerprint_hash_type"`
}

type checkKeyFileFunc struct{}

func (checkKeyFileFunc) Name() string { return "ssh.check_key_file" }
func (checkKeyFileFunc) Args() any    { return checkKeyFileArgs{} }
func (checkKeyFileFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*checkKeyFileArgs)
	ret := map[string]any{}
	saltenv := strDeref(a.Saltenv)
	keyfile, ferr := cacheFileDelegate(rt, a.Source, saltenv)
	if ferr != nil || keyfile == "" {
		return ret, nil
	}
	sKeys, verr := validateKeys(rt, keyfile, a.FingerprintHashType)
	if verr != nil {
		panic(verr)
	}
	if len(sKeys) == 0 {
		return ret, nil // "No keys detected" context flag stays module-local
	}
	cfg := authKeysConfigDefault(a.Config)
	for key, meta := range sKeys {
		enc, _ := meta["enc"].(string)
		comment, _ := meta["comment"].(string)
		options, _ := meta["options"].([]string)
		verdict, kerr := checkKeyImpl(rt, a.User, key, enc, comment, options,
			cfg, a.FingerprintHashType)
		if kerr != nil {
			panic(kerr)
		}
		ret[key] = verdict
	}
	return ret, nil
}

// ---------------------------------------------------------------------------
// ssh.set_auth_key / set_auth_key_from_file

type setAuthKeyArgs struct {
	User                string   `statekit:"required,name=user"`
	Key                 string   `statekit:"required,name=key"`
	Enc                 *string  `statekit:"name=enc"`
	Comment             *string  `statekit:"name=comment"`
	Options             []string `statekit:"name=options"`
	Config              *string  `statekit:"name=config"`
	CacheKeys           []string `statekit:"name=cache_keys"`
	FingerprintHashType *string  `statekit:"name=fingerprint_hash_type"`
}

type setAuthKeyFunc struct{}

func (setAuthKeyFunc) Name() string { return "ssh.set_auth_key" }
func (setAuthKeyFunc) Args() any    { return setAuthKeyArgs{} }
func (setAuthKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*setAuthKeyArgs)
	out, serr := setAuthKeyImpl(rt, a)
	if serr != nil {
		panic(serr)
	}
	return out, nil
}

func setAuthKeyImpl(rt *runtime.Runtime, a *setAuthKeyArgs) (any, error) {
	config := authKeysConfigDefault(a.Config)
	enc := strDeref(a.Enc)
	if enc == "" {
		enc = "ssh-rsa"
	}
	comment := strDeref(a.Comment)

	if len(strings.Fields(a.Key)) > 1 {
		return "invalid", nil
	}
	refined, rerr := refineEnc(enc)
	if rerr != nil {
		return nil, rerr
	}
	uinfoRes, uerr := callUserInfo(rt, a.User)
	if uerr != nil || uinfoRes == nil {
		return "fail", nil
	}
	uinfo, _ := uinfoRes.(map[string]any)
	fp, ferr := fingerprint(a.Key, a.FingerprintHashType)
	if ferr != nil {
		return nil, ferr
	}
	if fp == "" {
		return "Invalid public key", nil
	}

	status, kerr := checkKeyImpl(rt, a.User, a.Key, refined, comment,
		a.Options, config, a.FingerprintHashType)
	if kerr != nil {
		return nil, kerr
	}
	switch status {
	case "update":
		opts := a.Options
		if opts == nil {
			opts = []string{}
		}
		if rerr := replaceAuthKey(rt, a.User, a.Key, refined, comment, opts, config); rerr != nil {
			return nil, rerr
		}
		return "replace", nil
	case "exists":
		return "no change", nil
	}

	authLine := formatAuthLine(a.Key, refined, comment, a.Options)
	fconfig, gerr := getConfigFile(rt, a.User, config)
	if gerr != nil {
		return nil, gerr
	}
	home, _ := uinfo["home"].(string)
	if strings.HasPrefix(fconfig, home) && home != "" {
		if info, derr := rt.FS.Stat(home); derr != nil || !info.IsDir() {
			return "fail", nil
		}
	}
	dir := filepath.Dir(fconfig)
	if info, derr := rt.FS.Stat(dir); derr != nil || !info.IsDir() {
		if merr := rt.FS.MkdirAll(dir, 0o700); merr != nil {
			return nil, fmt.Errorf("Could not write to key file: %s", merr.Error())
		}
		chownToUIDGID(rt, dir, intFromAny(uinfo["uid"]), intFromAny(uinfo["gid"]))
		rt.FS.Chmod(dir, 0o700)
		restoreconBestEffort(rt, dir)
	}

	newFile := false
	var existing []byte
	if info, serr := rt.FS.Stat(fconfig); serr == nil && info.Mode().IsRegular() {
		existing, _ = rt.FS.ReadFile(fconfig)
	} else {
		newFile = true
	}
	out := string(existing)
	if !newFile && len(out) > 0 && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	out += authLine
	if werr := rt.FS.WriteFile(fconfig, []byte(out), 0o600); werr != nil {
		return nil, fmt.Errorf("Could not write to key file: %s", werr.Error())
	}
	if newFile {
		chownToUIDGID(rt, fconfig, intFromAny(uinfo["uid"]), intFromAny(uinfo["gid"]))
		rt.FS.Chmod(fconfig, 0o600)
		restoreconBestEffort(rt, fconfig)
	}
	return "new", nil
}

func chownToUIDGID(rt *runtime.Runtime, path string, uid, gid int) {
	if currentEuid() != 0 {
		return
	}
	rt.FS.Chown(path, uid, gid)
}

func intFromAny(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	}
	return -1
}

func restoreconBestEffort(rt *runtime.Runtime, path string) {
	if whichBin("restorecon") == "" {
		return
	}
	rt.Runner.Run(context.Background(), runtime.Command("restorecon", path))
}

type setAuthKeyFromFileArgs struct {
	User                string  `statekit:"required,name=user"`
	Source              string  `statekit:"required,name=source"`
	Config              *string `statekit:"name=config"`
	Saltenv             *string `statekit:"name=saltenv"`
	FingerprintHashType *string `statekit:"name=fingerprint_hash_type"`
}

type setAuthKeyFromFileFunc struct{}

func (setAuthKeyFromFileFunc) Name() string { return "ssh.set_auth_key_from_file" }
func (setAuthKeyFromFileFunc) Args() any    { return setAuthKeyFromFileArgs{} }
func (setAuthKeyFromFileFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*setAuthKeyFromFileArgs)
	lfile, ferr := cacheFileDelegate(rt, a.Source, strDeref(a.Saltenv))
	if ferr != nil {
		panic(fmt.Errorf("Failed to pull key file from salt file server"))
	}
	if info, serr := rt.FS.Stat(lfile); serr != nil || !info.Mode().IsRegular() {
		panic(fmt.Errorf("Failed to pull key file from salt file server"))
	}
	sKeys, verr := validateKeys(rt, lfile, a.FingerprintHashType)
	if verr != nil {
		panic(verr)
	}
	if len(sKeys) == 0 {
		return "fail", nil
	}
	rval := ""
	cacheKeys := make([]string, 0, len(sKeys))
	for k := range sKeys {
		cacheKeys = append(cacheKeys, k)
	}
	sort.Strings(cacheKeys)
	for _, key := range cacheKeys {
		meta := sKeys[key]
		enc, _ := meta["enc"].(string)
		comment, _ := meta["comment"].(string)
		options, _ := meta["options"].([]string)
		out, serr := setAuthKeyImpl(rt, &setAuthKeyArgs{
			User: a.User, Key: key, Enc: &enc, Comment: &comment,
			Options: options, Config: a.Config, CacheKeys: cacheKeys,
			FingerprintHashType: a.FingerprintHashType,
		})
		if serr != nil {
			panic(serr)
		}
		rval += out.(string)
	}
	switch {
	case strings.Contains(rval, "fail"):
		return "fail", nil
	case strings.Contains(rval, "replace"):
		return "replace", nil
	case strings.Contains(rval, "new"):
		return "new", nil
	}
	return "no change", nil
}

// ---------------------------------------------------------------------------
// ssh.rm_auth_key / rm_auth_key_from_file

type rmAuthKeyArgs struct {
	User                string  `statekit:"required,name=user"`
	Key                 string  `statekit:"required,name=key"`
	Config              *string `statekit:"name=config"`
	FingerprintHashType *string `statekit:"name=fingerprint_hash_type"`
}

type rmAuthKeyFunc struct{}

func (rmAuthKeyFunc) Name() string { return "ssh.rm_auth_key" }
func (rmAuthKeyFunc) Args() any    { return rmAuthKeyArgs{} }
func (rmAuthKeyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*rmAuthKeyArgs)
	out, serr := rmAuthKeyImpl(rt, a.User, a.Key, authKeysConfigDefault(a.Config),
		a.FingerprintHashType)
	if serr != nil {
		panic(serr)
	}
	return out, nil
}

func rmAuthKeyImpl(rt *runtime.Runtime, user, key, config string, fingerprintHashType *string) (string, error) {
	current, cerr := validatedKeysForUser(rt, user, config, fingerprintHashType)
	if cerr != nil {
		return "", cerr
	}
	if _, present := current[key]; !present {
		return "Key not present", nil
	}
	full, gerr := getConfigFile(rt, user, config)
	if gerr != nil {
		return "", gerr
	}
	if info, serr := rt.FS.Stat(full); serr != nil || !info.Mode().IsRegular() {
		return fmt.Sprintf("Authorized keys file %s not present", full), nil
	}
	data, rerr := rt.FS.ReadFile(full)
	if rerr != nil {
		return "Key not removed", nil
	}
	var lines []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		stored := line + "\n"
		if strings.HasPrefix(stored, "#") {
			lines = append(lines, stored)
			continue
		}
		search := validateLineRe.FindStringSubmatch(line)
		if search == nil {
			continue // unparseable lines are dropped like upstream
		}
		comps := strings.Fields(search[2])
		if len(comps) < 2 {
			lines = append(lines, stored)
			continue
		}
		if comps[1] == key {
			continue // the deletion target
		}
		lines = append(lines, stored)
	}
	if werr := rt.FS.WriteFile(full, []byte(strings.Join(lines, "")), 0o600); werr != nil {
		return "Key not removed", nil
	}
	return "Key removed", nil
}

type rmAuthKeyFromFileArgs struct {
	User                string  `statekit:"required,name=user"`
	Source              string  `statekit:"required,name=source"`
	Config              *string `statekit:"name=config"`
	Saltenv             *string `statekit:"name=saltenv"`
	FingerprintHashType *string `statekit:"name=fingerprint_hash_type"`
}

type rmAuthKeyFromFileFunc struct{}

func (rmAuthKeyFromFileFunc) Name() string { return "ssh.rm_auth_key_from_file" }
func (rmAuthKeyFromFileFunc) Args() any    { return rmAuthKeyFromFileArgs{} }
func (rmAuthKeyFromFileFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*rmAuthKeyFromFileArgs)
	lfile, ferr := cacheFileDelegate(rt, a.Source, strDeref(a.Saltenv))
	if ferr != nil {
		panic(fmt.Errorf("Failed to pull key file from salt file server"))
	}
	if info, serr := rt.FS.Stat(lfile); serr != nil || !info.Mode().IsRegular() {
		panic(fmt.Errorf("Failed to pull key file from salt file server"))
	}
	sKeys, verr := validateKeys(rt, lfile, a.FingerprintHashType)
	if verr != nil {
		panic(verr)
	}
	if len(sKeys) == 0 {
		return "fail", nil
	}
	keys := make([]string, 0, len(sKeys))
	for k := range sKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rval := ""
	for _, key := range keys {
		out, serr := rmAuthKeyImpl(rt, a.User, key,
			authKeysConfigDefault(a.Config), a.FingerprintHashType)
		if serr != nil {
			panic(serr)
		}
		rval += out
	}
	switch {
	case strings.Contains(rval, "Key not removed"):
		return "Key not removed", nil
	case strings.Contains(rval, "Key removed"):
		return "Key removed", nil
	}
	return "Key not present", nil
}

// ---------------------------------------------------------------------------
// ssh.user_keys / ssh.key_is_encrypted

type userKeysArgs struct {
	User    any     `statekit:"name=user"`
	Pubfile any     `statekit:"name=pubfile"`
	Prvfile any     `statekit:"name=prvfile"`
	Saltenv *string `statekit:"name=saltenv"`
}

type userKeysFunc struct{}

func (userKeysFunc) Name() string { return "ssh.user_keys" }
func (userKeysFunc) Args() any    { return userKeysArgs{} }
func (userKeysFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*userKeysArgs)
	users := []string{}
	switch u := a.User.(type) {
	case nil:
		users, _ = callDelegateStrings(rt, "user.list_users")
	case string:
		if u != "" {
			users = []string{u}
		} else {
			users, _ = callDelegateStrings(rt, "user.list_users")
		}
	case []any:
		for _, item := range u {
			if s, ok := item.(string); ok {
				users = append(users, s)
			}
		}
	}

	// boolish classifies the tri-state pubfile/prvfile parameters:
	// (path, explicitlyProvided, enabled). Absent parameters fall back to
	// the default key-name lists; an explicit False disables the half.
	boolish := func(v any) (string, bool, bool) {
		switch t := v.(type) {
		case nil:
			return "", false, false
		case string:
			if t == "" {
				return "", false, false // falsy -> defaults like upstream
			}
			return t, true, true
		case bool:
			return "", true, t
		}
		return "", false, false
	}
	pubPath, pubSet, pubVal := boolish(a.Pubfile)
	prvPath, prvSet, prvVal := boolish(a.Prvfile)

	keys := map[string]map[string]string{}
	for _, u := range users {
		keys[u] = map[string]string{}
		res, uerr := callUserInfo(rt, u)
		if uerr != nil || res == nil {
			continue
		}
		info, _ := res.(map[string]any)
		home, ok := info["home"].(string)
		if !ok || home == "" {
			continue
		}
		var userFiles []struct{ name, path string }
		if pubSet {
			if pubVal && pubPath != "" {
				userFiles = append(userFiles, fileRef(pubPath))
			}
		} else {
			for _, def := range []string{"id_rsa.pub", "id_dsa.pub", "id_ecdsa.pub", "id_ed25519.pub"} {
				userFiles = append(userFiles, fileRef(def))
			}
		}
		if prvSet {
			if prvVal && prvPath != "" {
				userFiles = append(userFiles, fileRef(prvPath))
			}
		} else {
			for _, def := range []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"} {
				userFiles = append(userFiles, fileRef(def))
			}
		}
		for _, ref := range userFiles {
			fn := ref.path
			if !strings.HasPrefix(fn, "/") {
				fn = home + "/.ssh/" + fn
			}
			data, rerr := rt.FS.ReadFile(fn)
			if rerr != nil {
				continue
			}
			keys[u][ref.name] = strings.TrimSpace(string(data))
		}
	}
	out := map[string]map[string]string{}
	for u, m := range keys {
		if len(m) > 0 {
			out[u] = m
		}
	}
	return out, nil
}

func fileRef(path string) struct{ name, path string } {
	name := filepath.Base(path)
	return struct{ name, path string }{name, path}
}

type keyIsEncryptedArgs struct {
	Key string `statekit:"required,name=key"`
}

type keyIsEncryptedFunc struct{}

func (keyIsEncryptedFunc) Name() string { return "ssh.key_is_encrypted" }
func (keyIsEncryptedFunc) Args() any    { return keyIsEncryptedArgs{} }
func (keyIsEncryptedFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverSSH(&res, &err)
	a := args.(*keyIsEncryptedArgs)
	data, rerr := rt.FS.ReadFile(expandUserTilde(a.Key))
	if rerr != nil {
		panic(fmt.Errorf("Could not read key file %s", a.Key))
	}
	content := string(data)
	if !regexp.MustCompile(`BEGIN (?:\w+\s)*PRIVATE KEY`).MatchString(content) {
		panic(fmt.Errorf("%s is not a private key", a.Key))
	}
	return strings.Contains(content, "ENCRYPTED"), nil
}

func expandUserTilde(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// RegisterAuth installs the R5.2 authorized-keys surface.
func RegisterAuth(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		authKeysFunc{},
		hostKeysFunc{},
		checkKeyFunc{},
		checkKeyFileFunc{},
		setAuthKeyFunc{},
		setAuthKeyFromFileFunc{},
		rmAuthKeyFunc{},
		rmAuthKeyFromFileFunc{},
		userKeysFunc{},
		keyIsEncryptedFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
