// Package cryptdev implements Salt-compatible cryptsetup management and
// crypttab editing.
//
// Reference: saltstack/salt/modules/cryptdev.py @ pinned revision.
// File access goes through the runtime FileSystem so suites stay hermetic;
// cryptsetup/dmsetup run through the central Runner.
package cryptdev

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts every function of this module to linux; Salt loads
// the module on POSIX-like systems only and StateKit targets Linux here.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

const defaultCrypttab = "/etc/crypttab"

// crypttabKeys is the fixed field order of a crypttab line.
var crypttabKeys = [4]string{"name", "device", "password", "options"}

// entry is one parsed crypttab line.
type entry map[string]string

// dictFromLine mirrors _crypttab_entry.dict_from_line: comments and
// malformed lines are parse errors, three-field lines gain empty options.
func dictFromLine(line string) (entry, error) {
	if strings.HasPrefix(line, "#") {
		return nil, fmt.Errorf("comment")
	}
	comps := strings.Fields(line)
	if len(comps) == 3 {
		comps = append(comps, "")
	}
	if len(comps) != 4 {
		return nil, fmt.Errorf("invalid entry")
	}
	e := entry{}
	for i, key := range crypttabKeys {
		e[key] = comps[i]
	}
	return e, nil
}

// format renders an entry using Salt's fixed-width crypttab layout
// ("{name: <12} {device: <44} {password: <22} {options}\n").
func format(e entry) string {
	return fmt.Sprintf("%-12s %-44s %-22s %s\n",
		e["name"], e["device"], e["password"], e["options"])
}

// match reports whether the parsed line satisfies every non-empty criterion
// field, mirroring _crypttab_entry.match (empty criteria are ignored).
func match(criteria entry, line string) bool {
	parsed, err := dictFromLine(line)
	if err != nil {
		return false
	}
	for _, key := range crypttabKeys {
		want, ok := criteria[key]
		if !ok || want == "" {
			continue
		}
		if parsed[key] != want {
			return false
		}
	}
	return true
}

type ActiveArgs struct{}

type activeFunc struct {
	linuxOnly
}

func (activeFunc) Name() string { return "cryptdev.active" }
func (activeFunc) Args() any    { return ActiveArgs{} }
func (activeFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	res := rt.Runner.Run(ctx, runtime.Command("dmsetup", "ls", "--target", "crypt"))
	if res.Err != nil {
		return nil, res.Err
	}
	re := regexp.MustCompile(`^(\S+)\s+\((\d+), (\d+)\)`)
	ret := map[string]any{}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ret[m[1]] = map[string]string{"devname": m[1], "major": m[2], "minor": m[3]}
	}
	return ret, nil
}

type CrypttabArgs struct {
	Config string `statekit:"name=config"`
}

type crypttabFunc struct {
	linuxOnly
}

func (crypttabFunc) Name() string { return "cryptdev.crypttab" }
func (crypttabFunc) Args() any    { return CrypttabArgs{} }
func (crypttabFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CrypttabArgs)
	config := a.Config
	if config == "" {
		config = defaultCrypttab
	}
	ret := map[string]any{}
	info, err := rt.FS.Stat(config)
	if err != nil || info.IsDir() {
		return ret, nil
	}
	data, err := rt.FS.ReadFile(config)
	if err != nil {
		return ret, nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\n")
		e, perr := dictFromLine(line)
		if perr != nil {
			continue
		}
		opts := strings.Split(e["options"], ",")
		name := e["name"]
		for {
			if _, dup := ret[name]; !dup {
				break
			}
			// Handle duplicate names by appending `_`.
			name += "_"
		}
		ret[name] = map[string]any{
			"device":   e["device"],
			"password": e["password"],
			"options":  opts,
		}
	}
	return ret, nil
}

type RmCrypttabArgs struct {
	Name   string `statekit:"required"`
	Config string `statekit:"name=config"`
}

type rmCrypttabFunc struct {
	linuxOnly
}

func (rmCrypttabFunc) Name() string { return "cryptdev.rm_crypttab" }
func (rmCrypttabFunc) Args() any    { return RmCrypttabArgs{} }
func (rmCrypttabFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RmCrypttabArgs)
	config := a.Config
	if config == "" {
		config = defaultCrypttab
	}
	criteria := entry{"name": a.Name}

	data, err := rt.FS.ReadFile(config)
	if err != nil {
		return nil, fmt.Errorf("Could not read from %s: %s", config, err)
	}
	modified := false
	var kept []string
	for _, line := range strings.SplitAfter(string(data), "\n") {
		if line == "" {
			continue
		}
		stripped := strings.TrimSuffix(line, "\n")
		matches := match(criteria, stripped)
		switch {
		case matches:
			modified = true
		default:
			kept = append(kept, line)
		}
	}
	if modified {
		if err := rt.FS.WriteFile(config, []byte(strings.Join(kept, "")), 0o644); err != nil {
			return nil, fmt.Errorf("Could not write to %s: %s", config, err)
		}
	}
	if modified {
		return "change", nil
	}
	return "absent", nil
}

type SetCrypttabArgs struct {
	Name     string   `statekit:"required"`
	Device   string   `statekit:"required"`
	Password *string  `statekit:"name=password"` // Salt default: "none"
	Options  []string `statekit:"name=options"`
	Config   string   `statekit:"name=config"`
	Test     bool     `statekit:"name=test"`
	MatchOn  []string `statekit:"name=match_on"`
}

type setCrypttabFunc struct {
	linuxOnly
}

func (setCrypttabFunc) Name() string { return "cryptdev.set_crypttab" }
func (setCrypttabFunc) Args() any    { return SetCrypttabArgs{} }
func (setCrypttabFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetCrypttabArgs)
	config := a.Config
	if config == "" {
		config = defaultCrypttab
	}
	password := "none"
	if a.Password != nil {
		password = *a.Password
	}
	options := strings.Join(a.Options, ",")

	matchOn := a.MatchOn
	if len(matchOn) == 0 {
		matchOn = []string{"name"}
	}
	validKeys := map[string]bool{"name": true, "device": true, "password": true, "options": true}
	for _, key := range matchOn {
		if !validKeys[key] {
			return nil, fmt.Errorf("Unrecognized keys in match_on: %q", matchOn)
		}
	}

	full := entry{"name": a.Name, "device": a.Device, "password": password, "options": options}
	entryLine := format(full)

	// Criteria keep only match_on keys, dropping empties like Salt does.
	criteria := entry{}
	for _, key := range matchOn {
		if full[key] != "" {
			criteria[key] = full[key]
		}
	}

	info, err := rt.FS.Stat(config)
	if err != nil || info.IsDir() {
		return nil, fmt.Errorf("Bad config file %q", config)
	}
	raw, err := rt.FS.ReadFile(config)
	if err != nil {
		return nil, fmt.Errorf("Couldn't read from %s: %s", config, err)
	}

	status := ""
	var kept []string
	for _, line := range strings.SplitAfter(string(raw), "\n") {
		if line == "" {
			continue
		}
		stripped := strings.TrimSuffix(line, "\n")
		if _, perr := dictFromLine(stripped); perr != nil {
			kept = append(kept, line)
			continue
		}
		if match(criteria, stripped) {
			status = "present"
			if match(full, stripped) {
				kept = append(kept, line)
			} else {
				status = "change"
				kept = append(kept, entryLine)
			}
		} else {
			kept = append(kept, line)
		}
	}
	if status == "" {
		kept = append(kept, entryLine)
		status = "new"
	}

	if status != "present" && !a.Test {
		out := strings.Join(kept, "")
		if err := rt.FS.WriteFile(config, []byte(out), 0o644); err != nil {
			return nil, fmt.Errorf("File not writable %s", config)
		}
	}
	return status, nil
}

type OpenArgs struct {
	Name    string `statekit:"required,name=name"`
	Device  string `statekit:"required,name=device"`
	Keyfile string `statekit:"required,name=keyfile"`
}

type openFunc struct {
	linuxOnly
}

func (openFunc) Name() string { return "cryptdev.open" }
func (openFunc) Args() any    { return OpenArgs{} }
func (openFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*OpenArgs)
	if a.Keyfile == "" || a.Keyfile == "none" || a.Keyfile == "-" {
		return nil, fmt.Errorf("For immediate crypt device mapping, keyfile must not be none")
	}
	res := rt.Runner.Run(ctx, runtime.Command(
		"cryptsetup", "open", "--key-file", a.Keyfile, a.Device, a.Name))
	return res.ExitCode == 0 && res.Err == nil, nil
}

type CloseArgs struct {
	Name string `statekit:"required,name=name"`
}

type closeFunc struct {
	linuxOnly
}

func (closeFunc) Name() string { return "cryptdev.close" }
func (closeFunc) Args() any    { return CloseArgs{} }
func (closeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CloseArgs)
	res := rt.Runner.Run(ctx, runtime.Command("cryptsetup", "close", a.Name))
	return res.ExitCode == 0 && res.Err == nil, nil
}

// Register installs all cryptdev-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		activeFunc{},
		crypttabFunc{},
		rmCrypttabFunc{},
		setCrypttabFunc{},
		openFunc{},
		closeFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
