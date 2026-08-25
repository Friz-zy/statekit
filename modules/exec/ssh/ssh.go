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
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/filesum"
	"github.com/friz-zy/statekit/internal/runtime"
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
