// Package scsi implements Salt-compatible SCSI device listing and
// rescanning through lsscsi and the SCSI host sysfs tree.
//
// Reference: saltstack/salt/modules/scsi.py @ pinned revision.
package scsi

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
	cmdmod "github.com/friz-zy/statekit/modules/exec/cmd"
)

// linuxOnly restricts this module to linux.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

var lsscsiBin = func() string {
	path, err := exec.LookPath("lsscsi")
	if err != nil {
		return ""
	}
	return path
}

type LsArgs struct {
	GetSize *bool `statekit:"name=get_size"`
}

type lsFunc struct{ linuxOnly }

func (lsFunc) Name() string { return "scsi.ls" }
func (lsFunc) Args() any    { return LsArgs{} }

// Execute lists SCSI devices with details. Availability problems and
// command errors surface as strings exactly like Salt's return values.
func (lsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*LsArgs)
	getSize := true
	if a.GetSize != nil {
		getSize = *a.GetSize
	}

	if lsscsiBin() == "" {
		return "scsi.ls not available - lsscsi command not found", nil
	}

	cmdStr := "lsscsi -dLv"
	if getSize {
		cmdStr = "lsscsi -dLsv"
	}
	resRaw, err := rt.Exec.Call(ctx, rt, "cmd.run_all", &cmdmod.RunAllArgs{Cmd: cmdStr})
	if err != nil {
		return "", nil
	}
	res, ok := resRaw.(map[string]any)
	if !ok {
		return "", nil
	}
	retcode, _ := res["retcode"].(int)
	stderr, _ := res["stderr"].(string)
	stdout, _ := res["stdout"].(string)
	if retcode != 0 {
		firstLine := strings.Split(stderr, "\n")[0]
		if firstLine == "lsscsi: invalid option -- 's'" {
			return firstLine + " - try get_size=False", nil
		}
		return firstLine, nil
	}

	ret := map[string]any{}
	key := ""
	for _, line := range strings.Split(stdout, "\n") {
		switch {
		case strings.HasPrefix(line, "["):
			comps := strings.Fields(strings.TrimSpace(line))
			key = comps[0]
			var size, major, minor any
			device := ""
			if getSize {
				size = comps[len(comps)-1]
				comps = comps[:len(comps)-1]
			} else {
				size = nil
			}
			majmin := comps[len(comps)-1]
			comps = comps[:len(comps)-1]
			if strings.HasPrefix(majmin, "[") {
				parts := strings.Split(strings.NewReplacer("[", "", "]", "").Replace(majmin), ":")
				if len(parts) == 2 {
					major, minor = parts[0], parts[1]
				}
			}
			device = comps[len(comps)-1]
			comps = comps[:len(comps)-1]
			model := strings.Join(comps[3:], " ")
			ret[key] = map[string]any{
				"lun":    strings.ReplaceAll(strings.ReplaceAll(key, "[", ""), "]", ""),
				"size":   size,
				"major":  major,
				"minor":  minor,
				"device": device,
				"model":  model,
			}
		case strings.HasPrefix(line, " ") && key != "":
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "dir") {
				comps := strings.Fields(trimmed)
				if len(comps) >= 3 {
					dirEntry, _ := ret[key].(map[string]any)
					dirEntry["dir"] = []any{comps[1], strings.ReplaceAll(strings.ReplaceAll(comps[2], "[", ""), "]", "")}
				}
			} else if strings.Contains(trimmed, "=") {
				kv := strings.SplitN(trimmed, "=", 2)
				entry, _ := ret[key].(map[string]any)
				entry[kv[0]] = kv[1]
			}
		}
	}
	return ret, nil
}

type RescanAllArgs struct {
	Host string `statekit:"required,name=host"`
}

type rescanAllFunc struct{ linuxOnly }

func (rescanAllFunc) Name() string { return "scsi.rescan_all" }
func (rescanAllFunc) Args() any    { return RescanAllArgs{} }

func (rescanAllFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RescanAllArgs)
	scanDir := fmt.Sprintf("/sys/class/scsi_host/host%s", a.Host)
	if info, err := rt.FS.Stat(scanDir); err != nil || !info.IsDir() {
		return fmt.Sprintf("Host %s does not exist", a.Host), nil
	}
	cmd := fmt.Sprintf(`echo "- - -" > /sys/class/scsi_host/host%s/scan`, a.Host)
	resRaw, err := rt.Exec.Call(ctx, rt, "cmd.run", &cmdmod.RunArgs{Cmd: cmd})
	if err != nil {
		return nil, err
	}
	out, _ := resRaw.(string)
	list := []any{}
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if line == "" && len(list) == 0 {
			continue
		}
		list = append(list, line)
	}
	return list, nil
}

// Register installs all scsi-module execution functions under their
// CLI-facing __func_alias__ names (ls_ -> ls).
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		lsFunc{},
		rescanAllFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
