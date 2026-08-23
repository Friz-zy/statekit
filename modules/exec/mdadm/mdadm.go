// Package mdadm implements Salt-compatible Linux software RAID management
// through mdadm (Salt virtual name "raid").
//
// Reference: saltstack/salt/modules/mdadm_raid.py @ pinned revision.
// Config-file edits go through the runtime FileSystem; mdadm runs through
// the central Runner. Array config paths follow the detected OS family,
// the first facts-driven branch outside provider selection.
package mdadm

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts every function of this module to linux; Salt refuses
// to load mdadm anywhere else.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

func stdoutOf(ctx context.Context, rt *runtime.Runtime, argv ...string) string {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return ""
	}
	return string(res.Stdout)
}

func retcode(ctx context.Context, rt *runtime.Runtime, argv ...string) int {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return -1
	}
	return res.ExitCode
}

// configFile picks the mdadm config path by OS family, mirroring Salt's
// __grains__ os_family branch.
func configFile(rt *runtime.Runtime) string {
	if rt.Facts != nil && rt.Facts.OS().Family == "debian" {
		return "/etc/mdadm/mdadm.conf"
	}
	return "/etc/mdadm.conf"
}

type ListArgs struct{}

type listFunc struct {
	linuxOnly
}

func (listFunc) Name() string { return "raid.list" }
func (listFunc) Args() any    { return ListArgs{} }

// list scans `mdadm --detail --scan` output.
func list(ctx context.Context, rt *runtime.Runtime) map[string]any {
	ret := map[string]any{}
	for _, line := range strings.Split(stdoutOf(ctx, rt, "mdadm", "--detail", "--scan"), "\n") {
		if !strings.Contains(line, " ") {
			continue
		}
		comps := strings.Fields(line)
		if len(comps) < 2 {
			continue
		}
		device := comps[1]
		row := map[string]any{"device": device}
		for _, comp := range comps[2:] {
			kv := strings.SplitN(comp, "=", 2)
			if len(kv) < 2 {
				continue
			}
			row[strings.ToLower(kv[0])] = kv[1]
		}
		ret[device] = row
	}
	return ret
}

func (listFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return list(ctx, rt), nil
}

type DetailArgs struct {
	Device string `statekit:"name=device"` // Salt default: /dev/md0
}

type detailFunc struct {
	linuxOnly
}

func (detailFunc) Name() string { return "raid.detail" }
func (detailFunc) Args() any    { return DetailArgs{} }

// detail parses `mdadm --detail <device>`: colon headers become keys,
// /dev/ rows become members.
func detail(ctx context.Context, rt *runtime.Runtime, device string) (map[string]any, error) {
	if device == "" {
		device = "/dev/md0"
	}
	if _, err := rt.FS.Stat(device); err != nil {
		return nil, fmt.Errorf("Device %s doesn't exist!", device)
	}
	ret := map[string]any{}
	members := map[string]any{}
	ret["members"] = members

	for _, line := range strings.Split(stdoutOf(ctx, rt, "mdadm", "--detail", device), "\n") {
		if strings.HasPrefix(line, device) || !strings.Contains(line, " ") {
			continue
		}
		if !strings.Contains(line, ":") {
			if strings.Contains(line, "/dev/") {
				comps := strings.Fields(line)
				if len(comps) < 6 {
					continue
				}
				state := strings.Join(comps[4:len(comps)-1], " ")
				members[comps[0]] = map[string]any{
					"device":     comps[len(comps)-1],
					"major":      comps[1],
					"minor":      comps[2],
					"number":     comps[0],
					"raiddevice": comps[3],
					"state":      state,
				}
			}
			continue
		}
		comps := strings.SplitN(line, " : ", 2)
		if len(comps) < 2 {
			continue
		}
		key := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(comps[0])), " ", "_")
		ret[key] = strings.TrimSpace(comps[1])
	}
	return ret, nil
}

func (detailFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DetailArgs)
	return detail(ctx, rt, a.Device)
}

type DestroyArgs struct {
	Device string `statekit:"required,name=device"`
}

type destroyFunc struct {
	linuxOnly
}

func (destroyFunc) Name() string { return "raid.destroy" }
func (destroyFunc) Args() any    { return DestroyArgs{} }
func (destroyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DestroyArgs)

	details, err := detail(ctx, rt, a.Device)
	if err != nil {
		return false, nil
	}

	stop := []string{"mdadm", "--stop", a.Device}
	if code := retcode(ctx, rt, stop...); code == 0 {
		zero := []string{"mdadm", "--zero-superblock"}
		members := details["members"].(map[string]any)
		numbers := make([]string, 0, len(members))
		for number := range members {
			numbers = append(numbers, number)
		}
		sort.Strings(numbers)
		for _, number := range numbers {
			row := members[number].(map[string]any)
			zero = append(zero, row["device"].(string))
		}
		retcode(ctx, rt, zero...)
	}

	removeArrayLine(rt, configFile(rt), a.Device)

	arrays := list(ctx, rt)
	if _, still := arrays[a.Device]; still {
		return false, nil
	}
	return true, nil
}

// removeArrayLine deletes the ARRAY entry for device from the config file,
// the equivalent of Salt's file.replace call. A missing file is a no-op.
func removeArrayLine(rt *runtime.Runtime, cfgFile, device string) {
	data, err := rt.FS.ReadFile(cfgFile)
	if err != nil {
		return
	}
	pattern := regexp.MustCompile(`(?m)^ARRAY ` + regexp.QuoteMeta(device) + ` .*\n?`)
	updated := pattern.ReplaceAllString(string(data), "")
	if updated != string(data) {
		rt.FS.WriteFile(cfgFile, []byte(updated), 0o644)
	}
}

type StopArgs struct{}

type stopFunc struct {
	linuxOnly
}

func (stopFunc) Name() string { return "raid.stop" }
func (stopFunc) Args() any    { return StopArgs{} }
func (stopFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	code := retcode(ctx, rt, "mdadm", "--stop", "--scan")
	// Mirrors Salt's `if __salt__["cmd.retcode"](cmd): return True` — the
	// truthiness check treats a non-zero exit as success (upstream quirk,
	// kept observable-contract compatible).
	if code != 0 {
		return true, nil
	}
	return false, nil
}

type CreateArgs struct {
	Name     string            `statekit:"required,name=name"`
	Level    string            `statekit:"required,name=level"`
	Devices  []string          `statekit:"required,name=devices"`
	Metadata string            `statekit:"name=metadata"`
	TestMode bool              `statekit:"name=test_mode"`
	Option   map[string]string `statekit:"name=options"`
}

type createFunc struct {
	linuxOnly
}

func (createFunc) Name() string { return "raid.create" }
func (createFunc) Args() any    { return CreateArgs{} }
func (createFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CreateArgs)

	opts := []string{}
	raidDevices := len(a.Devices)
	keys := make([]string, 0, len(a.Option))
	for key := range a.Option {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		opts = append(opts, "--"+key)
		value := a.Option[key]
		if value != "true" {
			opts = append(opts, value)
		}
		if key == "spare-devices" {
			n := 0
			fmt.Sscanf(value, "%d", &n)
			raidDevices -= n
		}
	}

	metadata := a.Metadata
	if metadata == "" {
		metadata = "default"
	}

	cmd := []string{"mdadm", "-C", a.Name, "-R", "-v", "-l", a.Level}
	cmd = append(cmd, opts...)
	cmd = append(cmd, "-e", metadata, "-n", fmt.Sprint(raidDevices))
	cmd = append(cmd, a.Devices...)

	if a.TestMode {
		return strings.Join(cmd, " "), nil
	}
	res := rt.Runner.Run(ctx, runtime.Command(cmd...))
	if res.Err != nil {
		return nil, res.Err
	}
	return strings.TrimRight(string(res.Stdout), "\n"), nil
}

type SaveConfigArgs struct{}

type saveConfigFunc struct {
	linuxOnly
}

func (saveConfigFunc) Name() string { return "raid.save_config" }
func (saveConfigFunc) Args() any    { return SaveConfigArgs{} }
func (saveConfigFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	scanLines := strings.Split(
		strings.TrimRight(stdoutOf(ctx, rt, "mdadm", "--detail", "--scan"), "\n"), "\n")

	family := ""
	osID := ""
	if rt.Facts != nil {
		family = rt.Facts.OS().Family
		osID = rt.Facts.OS().ID
	}
	if osID == "ubuntu" {
		badTag := regexp.MustCompile(`(?i)\s(name|metadata)=\S+`)
		for i, line := range scanLines {
			scanLines[i] = badTag.ReplaceAllString(line, "")
		}
	}

	cfgFile := configFile(rt)
	existing, statErr := rt.FS.ReadFile(cfgFile)
	content := string(existing)
	for _, line := range scanLines {
		comps := strings.Fields(line)
		if len(comps) < 2 {
			continue
		}
		vol := comps[1]
		pattern := regexp.MustCompile(`(?m)^ARRAY ` + regexp.QuoteMeta(vol) + ` .*$\n?`)
		if pattern.MatchString(content) {
			content = pattern.ReplaceAllString(content, line+"\n")
		} else {
			content = strings.TrimRight(content, "\n")
			if content != "" {
				content += "\n"
			}
			content += line + "\n"
		}
	}
	if statErr != nil || content != string(existing) {
		if err := rt.FS.WriteFile(cfgFile, []byte(content), 0o644); err != nil {
			return nil, err
		}
	}

	switch family {
	case "debian":
		res := rt.Runner.Run(ctx, runtime.Command("update-initramfs", "-u"))
		if res.Err != nil {
			return nil, res.Err
		}
		return strings.TrimRight(string(res.Stdout), "\n"), nil
	case "redhat":
		res := rt.Runner.Run(ctx, runtime.Command("dracut", "--force"))
		if res.Err != nil {
			return nil, res.Err
		}
		return strings.TrimRight(string(res.Stdout), "\n"), nil
	default:
		return nil, nil
	}
}

type AssembleArgs struct {
	Name     string            `statekit:"required,name=name"`
	Devices  []string          `statekit:"required,name=devices"`
	TestMode bool              `statekit:"name=test_mode"`
	Option   map[string]string `statekit:"name=options"`
}

type assembleFunc struct {
	linuxOnly
}

func (assembleFunc) Name() string { return "raid.assemble" }
func (assembleFunc) Args() any    { return AssembleArgs{} }
func (assembleFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AssembleArgs)

	opts := []string{}
	keys := make([]string, 0, len(a.Option))
	for key := range a.Option {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		opts = append(opts, "--"+key)
		if v := a.Option[key]; v != "true" {
			opts = append(opts, v)
		}
	}

	cmd := []string{"mdadm", "-A", a.Name, "-v"}
	cmd = append(cmd, opts...)
	cmd = append(cmd, a.Devices...)

	if a.TestMode {
		return cmd, nil
	}
	res := rt.Runner.Run(ctx, runtime.Command(cmd...))
	if res.Err != nil {
		return nil, res.Err
	}
	return strings.TrimRight(string(res.Stdout), "\n"), nil
}

type ExamineArgs struct {
	Device string `statekit:"required,name=device"`
	Quiet  bool   `statekit:"name=quiet"`
}

type examineFunc struct {
	linuxOnly
}

func (examineFunc) Name() string { return "raid.examine" }
func (examineFunc) Args() any    { return ExamineArgs{} }
func (examineFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ExamineArgs)
	res := rt.Runner.Run(ctx, runtime.Command("mdadm", "-Y", "-E", a.Device))
	if res.Err != nil {
		return nil, res.Err
	}
	ret := map[string]any{}
	for _, line := range strings.Split(strings.TrimRight(string(res.Stdout), "\n"), "\n") {
		if line == "" {
			continue
		}
		name, varPart, _ := strings.Cut(line, "=")
		ret[name] = varPart
	}
	return ret, nil
}

type AddArgs struct {
	Name   string `statekit:"required,name=name"`
	Device string `statekit:"required,name=device"`
}

type addFunc struct {
	linuxOnly
}

func (addFunc) Name() string { return "raid.add" }
func (addFunc) Args() any    { return AddArgs{} }
func (addFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AddArgs)
	code := retcode(ctx, rt, "mdadm", "--manage", a.Name, "--add", a.Device)
	return code == 0, nil
}

// Register installs all raid-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		listFunc{},
		detailFunc{},
		destroyFunc{},
		stopFunc{},
		createFunc{},
		saveConfigFunc{},
		assembleFunc{},
		examineFunc{},
		addFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
