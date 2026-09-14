// Package zoneadm implements the Solaris zoneadm execution module surface
// from the pinned Salt source.  The package is intentionally untagged so its
// parsers and command builders can be tested on Linux; every execution
// function is platform-gated to Solaris by the registry.
//
// Reference: saltstack/salt/modules/zoneadm.py at
// 8b63e700637e40d76f80a00d95c60471797c73b9.  list_zones is registered under
// Salt's loader alias, list.  No source functions outside the 13 public
// functions are registered here.
package zoneadm

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	zoneadmCommandTimeout = 30 * time.Second
	zoneadmOutputLimit    = 4 << 20
	zoneadmMaxNameBytes   = 64
)

var (
	errZoneadmRunnerUnavailable = errors.New("zoneadm: runner unavailable")
	errZoneadmInvalidArgument   = errors.New("zoneadm: invalid argument")
	errZoneadmMalformedList     = errors.New("zoneadm: malformed list output")
)

// solarisOnly mirrors the source module's Solaris-only virtual-module
// boundary.  The registry stores these functions on all builds and turns
// calls on other GOOS values into runtime.UnsupportedError before Execute.
type solarisOnly struct{}

func (solarisOnly) Platforms() []string { return []string{"solaris"} }

var zoneNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// ListZonesArgs mirrors list_zones(verbose=True, installed=False,
// configured=False, hide_global=True).  Pointers preserve Salt's true
// defaults while still allowing an explicit false from structured input.
type ListZonesArgs struct {
	Verbose    *bool `statekit:"name=verbose"`
	Installed  bool  `statekit:"name=installed"`
	Configured bool  `statekit:"name=configured"`
	HideGlobal *bool `statekit:"name=hide_global"`
}

type BootArgs struct {
	Zone       string  `statekit:"required"`
	Single     bool    `statekit:"name=single"`
	Altinit    *string `statekit:"name=altinit"`
	SmfOptions *string `statekit:"name=smf_options"`
}

type RebootArgs struct {
	Zone       string  `statekit:"required"`
	Single     bool    `statekit:"name=single"`
	Altinit    *string `statekit:"name=altinit"`
	SmfOptions *string `statekit:"name=smf_options"`
}

type HaltArgs struct {
	Zone string `statekit:"required"`
}

type ShutdownArgs struct {
	Zone       string  `statekit:"required"`
	Reboot     bool    `statekit:"name=reboot"`
	Single     bool    `statekit:"name=single"`
	Altinit    *string `statekit:"name=altinit"`
	SmfOptions *string `statekit:"name=smf_options"`
}

type DetachArgs struct {
	Zone string `statekit:"required"`
}

type AttachArgs struct {
	Zone      string  `statekit:"required"`
	Force     bool    `statekit:"name=force"`
	BrandOpts *string `statekit:"name=brand_opts"`
}

type ReadyArgs struct {
	Zone string `statekit:"required"`
}

type VerifyArgs struct {
	Zone string `statekit:"required"`
}

type MoveArgs struct {
	Zone     string `statekit:"required"`
	Zonepath string `statekit:"required"`
}

type UninstallArgs struct {
	Zone string `statekit:"required"`
}

type InstallArgs struct {
	Zone      string  `statekit:"required"`
	Nodataset bool    `statekit:"name=nodataset"`
	BrandOpts *string `statekit:"name=brand_opts"`
}

type CloneArgs struct {
	Zone     string  `statekit:"required"`
	Source   string  `statekit:"required"`
	Snapshot *string `statekit:"name=snapshot"`
}

// zoneadmRun is the only subprocess boundary in this package.  It always
// uses direct argv, applies finite stdin/output bounds, and treats a
// completed non-zero exit as compatibility data for the caller to parse.
func zoneadmRun(ctx context.Context, rt *runtime.Runtime, argv ...string) (process.CommandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if rt == nil || rt.Runner == nil {
		return process.CommandResult{ExitCode: -1}, errZoneadmRunnerUnavailable
	}
	if err := validateArgv(argv); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	command, err := runtime.CommandWithInputBounded(argv, "")
	if err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	command.Shell = false
	command.Timeout = zoneadmCommandTimeout
	command.MaxStdoutBytes = zoneadmOutputLimit
	command.MaxStderrBytes = zoneadmOutputLimit
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return result, result.Err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stdout) > zoneadmOutputLimit || len(result.Stderr) > zoneadmOutputLimit {
		return result, process.ErrOutputLimit
	}
	return result, nil
}

func validateArgv(argv []string) error {
	if len(argv) == 0 {
		return errZoneadmInvalidArgument
	}
	total := 0
	for _, arg := range argv {
		if strings.IndexByte(arg, 0) >= 0 {
			return errZoneadmInvalidArgument
		}
		if len(arg) > runtime.MaxCommandInputBytes-total {
			return runtime.ErrCommandInputLimit
		}
		total += len(arg)
	}
	return nil
}

func validateZoneName(zone string) error {
	if len(zone) > zoneadmMaxNameBytes || !zoneNamePattern.MatchString(zone) {
		return errZoneadmInvalidArgument
	}
	return nil
}

func validateSafeWord(value string) error {
	if value == "" || strings.IndexByte(value, 0) >= 0 {
		return errZoneadmInvalidArgument
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == ';' || r == '|' || r == '&' ||
			r == '$' || r == '`' || r == '\'' || r == '"' || r == '\\' {
			return errZoneadmInvalidArgument
		}
	}
	return nil
}

func validatePath(value string, absolute bool) error {
	if value == "" || strings.IndexByte(value, 0) >= 0 {
		return errZoneadmInvalidArgument
	}
	if absolute && !strings.HasPrefix(value, "/") {
		return errZoneadmInvalidArgument
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == ';' || r == '|' || r == '&' ||
			r == '$' || r == '`' || r == '\'' || r == '"' || r == '\\' {
			return errZoneadmInvalidArgument
		}
	}
	if strings.IndexAny(value, " \t\r\n") >= 0 {
		return errZoneadmInvalidArgument
	}
	return nil
}

// safeWords is the shell-free equivalent of the source's whitespace-separated
// option fragments.  It deliberately does not interpret quotes or escapes.
func safeWords(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == ';' || r == '|' || r == '&' ||
			r == '$' || r == '`' || r == '\'' || r == '"' || r == '\\' {
			return nil, errZoneadmInvalidArgument
		}
	}
	words := strings.Fields(value)
	for _, word := range words {
		if err := validateSafeWord(word); err != nil {
			return nil, err
		}
	}
	return words, nil
}

// uuidTarget mirrors _is_uuid exactly for valid safe zone identifiers: Salt
// checks the exact length and the position of the first hyphen, not UUID hex
// groups.
func uuidTarget(zone string, uuidAware bool) ([]string, error) {
	if err := validateZoneName(zone); err != nil {
		return nil, err
	}
	flag := "-z"
	if uuidAware && len(zone) == 36 && strings.IndexByte(zone, '-') == 8 {
		flag = "-u"
	}
	return []string{flag, zone}, nil
}

func brandArgs(value *string) ([]string, error) {
	if value == nil || *value == "" {
		return nil, nil
	}
	return safeWords(*value)
}

func bootOptions(single bool, altinit, smfOptions *string) ([]string, error) {
	// zoneadm.py prepends each later option, resulting in -m, -i, -s order.
	var options []string
	if single {
		options = append(options, "-s")
	}
	if altinit != nil && *altinit != "" {
		if err := validatePath(*altinit, false); err != nil {
			return nil, err
		}
		options = append([]string{"-i", *altinit}, options...)
	}
	if smfOptions != nil && *smfOptions != "" {
		words, err := safeWords(*smfOptions)
		if err != nil {
			return nil, err
		}
		options = append(append([]string{"-m"}, words...), options...)
	}
	if len(options) == 0 {
		return nil, nil
	}
	return append([]string{"--"}, options...), nil
}

func zoneadmAction(ctx context.Context, rt *runtime.Runtime, argv []string) (any, error) {
	result, err := zoneadmRun(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	ret := map[string]any{"status": result.ExitCode == 0}
	message := result.Stdout
	if result.ExitCode != 0 {
		message = result.Stderr
	}
	cleaned := strings.ReplaceAll(string(message), "zoneadm: ", "")
	if cleaned != "" {
		ret["message"] = cleaned
	}
	return ret, nil
}

func listZonesOutput(output string, installed, configured, hideGlobal, verbose bool) (any, error) {
	zones := map[string]any{}
	const columns = 7
	for lineNumber, line := range strings.Split(output, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < columns {
			return nil, fmt.Errorf("%w at line %d", errZoneadmMalformedList, lineNumber+1)
		}
		zone := map[string]any{
			"zoneid":   fields[0],
			"zonename": fields[1],
			"state":    fields[2],
			"zonepath": fields[3],
			"uuid":     fields[4],
			"brand":    fields[5],
			"ip-type":  fields[6],
		}
		name := fields[1]
		if hideGlobal && name == "global" {
			continue
		}
		if !installed && fields[2] == "installed" {
			continue
		}
		if !configured && fields[2] == "configured" {
			continue
		}
		delete(zone, "zonename")
		zones[name] = zone
	}
	if verbose {
		return zones, nil
	}
	names := make([]string, 0, len(zones))
	for name := range zones {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

type listFunc struct{ solarisOnly }

func (listFunc) Name() string { return "zoneadm.list" }
func (listFunc) Args() any    { return ListZonesArgs{} }
func (listFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListZonesArgs)
	verbose := true
	if a.Verbose != nil {
		verbose = *a.Verbose
	}
	hideGlobal := true
	if a.HideGlobal != nil {
		hideGlobal = *a.HideGlobal
	}
	result, err := zoneadmRun(ctx, rt, "zoneadm", "list", "-p", "-c")
	if err != nil {
		return nil, err
	}
	// list_zones intentionally ignores a completed non-zero retcode and
	// returns the empty collection, matching the pinned source.
	if result.ExitCode != 0 {
		if verbose {
			return map[string]any{}, nil
		}
		return []string{}, nil
	}
	return listZonesOutput(string(result.Stdout), a.Installed, a.Configured, hideGlobal, verbose)
}

type bootFunc struct{ solarisOnly }

func (bootFunc) Name() string { return "zoneadm.boot" }
func (bootFunc) Args() any    { return BootArgs{} }
func (bootFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*BootArgs)
	target, err := uuidTarget(a.Zone, true)
	if err != nil {
		return nil, err
	}
	options, err := bootOptions(a.Single, a.Altinit, a.SmfOptions)
	if err != nil {
		return nil, err
	}
	argv := append([]string{"zoneadm"}, target...)
	argv = append(argv, "boot")
	argv = append(argv, options...)
	return zoneadmAction(ctx, rt, argv)
}

type rebootFunc struct{ solarisOnly }

func (rebootFunc) Name() string { return "zoneadm.reboot" }
func (rebootFunc) Args() any    { return RebootArgs{} }
func (rebootFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RebootArgs)
	target, err := uuidTarget(a.Zone, true)
	if err != nil {
		return nil, err
	}
	options, err := bootOptions(a.Single, a.Altinit, a.SmfOptions)
	if err != nil {
		return nil, err
	}
	argv := append([]string{"zoneadm"}, target...)
	argv = append(argv, "reboot")
	argv = append(argv, options...)
	return zoneadmAction(ctx, rt, argv)
}

type haltFunc struct{ solarisOnly }

func (haltFunc) Name() string { return "zoneadm.halt" }
func (haltFunc) Args() any    { return HaltArgs{} }
func (haltFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*HaltArgs)
	target, err := uuidTarget(a.Zone, true)
	if err != nil {
		return nil, err
	}
	return zoneadmAction(ctx, rt, append(append([]string{"zoneadm"}, target...), "halt"))
}

type shutdownFunc struct{ solarisOnly }

func (shutdownFunc) Name() string { return "zoneadm.shutdown" }
func (shutdownFunc) Args() any    { return ShutdownArgs{} }
func (shutdownFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ShutdownArgs)
	target, err := uuidTarget(a.Zone, true)
	if err != nil {
		return nil, err
	}
	options, err := bootOptions(a.Single, a.Altinit, a.SmfOptions)
	if err != nil {
		return nil, err
	}
	argv := append([]string{"zoneadm"}, target...)
	argv = append(argv, "shutdown")
	if a.Reboot {
		argv = append(argv, "-r")
	}
	argv = append(argv, options...)
	return zoneadmAction(ctx, rt, argv)
}

type detachFunc struct{ solarisOnly }

func (detachFunc) Name() string { return "zoneadm.detach" }
func (detachFunc) Args() any    { return DetachArgs{} }
func (detachFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DetachArgs)
	target, err := uuidTarget(a.Zone, true)
	if err != nil {
		return nil, err
	}
	return zoneadmAction(ctx, rt, append(append([]string{"zoneadm"}, target...), "detach"))
}

type attachFunc struct{ solarisOnly }

func (attachFunc) Name() string { return "zoneadm.attach" }
func (attachFunc) Args() any    { return AttachArgs{} }
func (attachFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AttachArgs)
	if err := validateZoneName(a.Zone); err != nil {
		return nil, err
	}
	brand, err := brandArgs(a.BrandOpts)
	if err != nil {
		return nil, err
	}
	argv := []string{"zoneadm", "-z", a.Zone, "attach"}
	if a.Force {
		argv = append(argv, "-F")
	}
	argv = append(argv, brand...)
	return zoneadmAction(ctx, rt, argv)
}

type readyFunc struct{ solarisOnly }

func (readyFunc) Name() string { return "zoneadm.ready" }
func (readyFunc) Args() any    { return ReadyArgs{} }
func (readyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ReadyArgs)
	target, err := uuidTarget(a.Zone, true)
	if err != nil {
		return nil, err
	}
	return zoneadmAction(ctx, rt, append(append([]string{"zoneadm"}, target...), "ready"))
}

type verifyFunc struct{ solarisOnly }

func (verifyFunc) Name() string { return "zoneadm.verify" }
func (verifyFunc) Args() any    { return VerifyArgs{} }
func (verifyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*VerifyArgs)
	if err := validateZoneName(a.Zone); err != nil {
		return nil, err
	}
	return zoneadmAction(ctx, rt, []string{"zoneadm", "-z", a.Zone, "verify"})
}

type moveFunc struct{ solarisOnly }

func (moveFunc) Name() string { return "zoneadm.move" }
func (moveFunc) Args() any    { return MoveArgs{} }
func (moveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*MoveArgs)
	target, err := uuidTarget(a.Zone, true)
	if err != nil {
		return nil, err
	}
	if err := validatePath(a.Zonepath, true); err != nil {
		return nil, err
	}
	argv := append([]string{"zoneadm"}, target...)
	argv = append(argv, "move", a.Zonepath)
	return zoneadmAction(ctx, rt, argv)
}

type uninstallFunc struct{ solarisOnly }

func (uninstallFunc) Name() string { return "zoneadm.uninstall" }
func (uninstallFunc) Args() any    { return UninstallArgs{} }
func (uninstallFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*UninstallArgs)
	target, err := uuidTarget(a.Zone, true)
	if err != nil {
		return nil, err
	}
	argv := append([]string{"zoneadm"}, target...)
	argv = append(argv, "uninstall", "-F")
	return zoneadmAction(ctx, rt, argv)
}

type installFunc struct{ solarisOnly }

func (installFunc) Name() string { return "zoneadm.install" }
func (installFunc) Args() any    { return InstallArgs{} }
func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InstallArgs)
	if err := validateZoneName(a.Zone); err != nil {
		return nil, err
	}
	brand, err := brandArgs(a.BrandOpts)
	if err != nil {
		return nil, err
	}
	argv := []string{"zoneadm", "-z", a.Zone, "install"}
	if a.Nodataset {
		argv = append(argv, "-x", "nodataset")
	}
	argv = append(argv, brand...)
	return zoneadmAction(ctx, rt, argv)
}

type cloneFunc struct{ solarisOnly }

func (cloneFunc) Name() string { return "zoneadm.clone" }
func (cloneFunc) Args() any    { return CloneArgs{} }
func (cloneFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CloneArgs)
	if err := validateZoneName(a.Zone); err != nil {
		return nil, err
	}
	if err := validateZoneName(a.Source); err != nil {
		return nil, err
	}
	argv := []string{"zoneadm", "-z", a.Zone, "clone"}
	if a.Snapshot != nil && *a.Snapshot != "" {
		if err := validateSafeWord(*a.Snapshot); err != nil {
			return nil, err
		}
		argv = append(argv, "-s", *a.Snapshot)
	}
	argv = append(argv, a.Source)
	return zoneadmAction(ctx, rt, argv)
}

// Register installs the complete public zoneadm surface.  Registration is
// intentionally unconditional; Platforms() supplies the runtime gate.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		listFunc{}, bootFunc{}, rebootFunc{}, haltFunc{}, shutdownFunc{},
		detachFunc{}, attachFunc{}, readyFunc{}, verifyFunc{}, moveFunc{},
		uninstallFunc{}, installFunc{}, cloneFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
