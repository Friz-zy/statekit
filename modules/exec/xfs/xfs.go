// Package xfs implements Salt-compatible XFS filesystem management through
// xfs_info, mkfs.xfs, xfs_admin, xfsdump/xfsrestore, xfs_fsr and blkid.
//
// Reference: saltstack/salt/modules/xfs.py @ pinned revision. Salt composes
// shell strings; StateKit emits shell-free argv through the central Runner,
// so quoted arguments (labels) are passed as single argv elements with the
// same observable effect. /proc/mounts reads go through the runtime
// FileSystem for hermetic suites.
//
// Contract notes (init.md section 28): Salt's modify() maps any truthy
// uuid argument (including explicit UUID strings) to "-U generate"; the
// tri-state *bool keeps the three observable behaviors (omitted / nil /
// generate) without pretending string UUIDs are honored upstream.
package xfs

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts every function of this module to linux: the XFS
// toolchain is a Linux contract.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// lookPath is split out for test injection.
var lookPath = func(name string) (string, error) {
	// Delegates to PATH resolution without executing anything; mirrors
	// Salt.utils.path.which guards.
	return exeLookPath(name)
}

func runAll(ctx context.Context, rt *runtime.Runtime, argv ...string) (stdout, stderr string, code int, err error) {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return "", "", -1, res.Err
	}
	return string(res.Stdout), strings.TrimSpace(string(res.Stderr)), res.ExitCode, nil
}

// verifyRun raises Salt's CommandExecutionError equivalent when the tool
// failed with stderr content.
func verifyRun(stdout, stderr string, code int) error {
	if code != 0 && stderr != "" {
		return fmt.Errorf("%s", stderr)
	}
	return nil
}

type InfoArgs struct {
	Device string `statekit:"required,name=device"`
}

type infoFunc struct {
	linuxOnly
}

func (infoFunc) Name() string { return "xfs.info" }
func (infoFunc) Args() any    { return InfoArgs{} }
func (infoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InfoArgs)
	stdout, stderr, code, err := runAll(ctx, rt, "xfs_info", a.Device)
	if err != nil {
		return nil, err
	}
	if err := verifyRun(stdout, stderr, code); err != nil {
		return nil, fmt.Errorf("%s",
			strings.TrimPrefix(strings.TrimSpace(err.Error()), "xfs_info:"))
	}
	return parseXfsInfo(stdout), nil
}

// xfsInfoGetKv parses one line of XFS info output into ordered key/value
// pairs, mirroring Salt's "=*** " continuation marker trick.
func xfsInfoGetKv(serialized string) [][2]string {
	serialized = strings.TrimPrefix(serialized, "=")
	serialized = strings.TrimLeft(serialized, " ")
	serialized = strings.ReplaceAll(serialized, " = ", "=*** ")
	serialized = strings.ReplaceAll(serialized, " =", "=")

	var opt []string
	for _, tkn := range strings.Split(serialized, " ") {
		if len(opt) == 0 || strings.Contains(tkn, "=") {
			opt = append(opt, tkn)
		} else {
			opt[len(opt)-1] = opt[len(opt)-1] + " " + tkn
		}
	}
	out := make([][2]string, 0, len(opt))
	for _, item := range opt {
		key, value, found := strings.Cut(item, "=")
		if !found {
			continue
		}
		out = append(out, [2]string{key, value})
	}
	return out
}

var spacesRe = regexp.MustCompile(`\s+`)

// parseXfsInfo parses output of "xfs_info" or "xfs_growfs -n".
func parseXfsInfo(data string) map[string]any {
	ret := map[string]any{}
	entryKey := ""
	for _, raw := range strings.Split(data, "\n") {
		line := strings.TrimSpace(spacesRe.ReplaceAllString(raw, " "))
		line = strings.ReplaceAll(line, ", ", " ")
		if line == "" || !strings.Contains(line, "=") {
			continue
		}
		nfo := xfsInfoGetKv(line)
		if !strings.HasPrefix(line, "=") && len(nfo) > 0 {
			entry := nfo[0]
			nfo = nfo[1:]
			entryKey = entry[0]
			section := entry[0]
			if entry[1] != "***" {
				section = entry[1]
			}
			ret[entryKey] = map[string]any{"section": section}
		}
		if entryKey == "" {
			continue
		}
		bucket := ret[entryKey].(map[string]any)
		for _, kv := range nfo {
			bucket[kv[0]] = kv[1]
		}
	}
	return ret
}

type DumpArgs struct {
	Device      string `statekit:"required,name=device"`
	Destination string `statekit:"required,name=destination"`
	Level       string `statekit:"name=level"`
	Label       string `statekit:"name=label"`
	NoErase     bool   `statekit:"name=noerase"`
}

type dumpFunc struct {
	linuxOnly
}

func (dumpFunc) Name() string { return "xfs.dump" }
func (dumpFunc) Args() any    { return DumpArgs{} }
func (dumpFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DumpArgs)

	if _, err := lookPath("xfsdump"); err != nil {
		return nil, fmt.Errorf("Utility %q has to be installed or missing.", "xfsdump")
	}

	level := a.Level
	if level == "" {
		level = "0"
	}
	label := a.Label
	if label == "" {
		label = strings.ReplaceAll(time.Now().Format(
			fmt.Sprintf(`XFS dump for %q of 2006.01.02, 15:04`, a.Device)), "'", `"`)
	}

	argv := []string{"xfsdump", "-F"}
	if !a.NoErase {
		argv = append(argv, "-E")
	}
	argv = append(argv, "-L", label, "-l", level, "-f", a.Destination, a.Device)

	stdout, stderr, code, err := runAll(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	if err := verifyRun(stdout, stderr, code); err != nil {
		return nil, err
	}
	return xfsdumpOutput(stdout), nil
}

// xfsdumpOutput parses CLI output of the xfsdump utility. Salt's Summary
// collection is unreachable there (lines are stripped before the
// leading-space test), so only the scalar fields are observable contract.
func xfsdumpOutput(data string) map[string]any {
	out := map[string]any{}
	mediaSize := regexp.MustCompile(`^media file size\s+`)
	dumpComplete := regexp.MustCompile(`^dump complete:\s+`)
	dumpStatus := regexp.MustCompile(`^Dump Status:\s+`)

	for _, raw := range strings.Split(data, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		line = strings.TrimPrefix(line, "xfsdump: ")
		switch {
		case strings.HasPrefix(line, "session id:"):
			tkns := strings.Fields(line)
			out["Session ID"] = tkns[len(tkns)-1]
		case strings.HasPrefix(line, "session label: "):
			out["Session label"] = strings.TrimPrefix(line, "session label: ")
		case mediaSize.MatchString(line):
			out["Media size"] = mediaSize.ReplaceAllString(line, "")
		case dumpComplete.MatchString(line):
			out["Dump complete"] = dumpComplete.ReplaceAllString(line, "")
		case dumpStatus.MatchString(line):
			out["Status"] = dumpStatus.ReplaceAllString(line, "")
		}
	}
	return out
}
