// Package udev implements Salt-compatible udev query functions.
//
// Reference: saltstack/salt/modules/udev.py @ pinned revision.
//
// Scope note (handoff decision, plans/porting.md section 6): this phase
// started with the minimal surface bcache needs — udev.env — driven by
// the shared udevadm --export parser. info/exportdb and the name/path/
// links wrappers over info reuse the same parser; the family is fully
// registered as of PTD-EXEC-1639/1640/1641/1642. All commands run
// through the central Runner as argv (Salt composes a shell string with
// no metacharacters).
package udev

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts this module to linux: udevadm is a Linux contract.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// Finite parser controls. These are explicit compatibility and safety
// ceilings, not fleet capacity guarantees: parse work stays O(input bytes +
// records + fields) and every limit fails closed with no partial records.
// Divergence from Salt: upstream parses unbounded output with no line,
// record, or field limits.
const (
	// udevMaxOutputBytes bounds the export-db stdout a caller may hand to
	// the shared parser (16 MiB, matching the exportdb capture budget).
	udevMaxOutputBytes = 16 << 20
	// udevMaxLineBytes bounds one raw line, checked before trimming.
	udevMaxLineBytes = 64 << 10
	// udevMaxRecords bounds the total parsed records.
	udevMaxRecords = 65536
	// udevMaxRecordFields bounds parsed field occurrences per record,
	// counting duplicate keys.
	udevMaxRecordFields = 1024
)

// Fixed, value-free parser errors: no raw stdout, error causes, or caller
// paths travel in the error text.
var (
	errUdevOutputTooLarge = errors.New("udev: udevadm output exceeds limit")
	errUdevLineTooLong    = errors.New("udev: udevadm output line exceeds limit")
	errUdevTooManyRecords = errors.New("udev: udevadm output record count exceeds limit")
	errUdevTooManyFields  = errors.New("udev: udevadm output record fields exceed limit")
	errUdevMalformedELine = errors.New("udev: malformed E line in udevadm output")
)

// parseInfo ports _parse_udevadm_info plus _normalize_info: blank-line
// separated device records, "X: data" lines, E-lines parsed as key=value
// with int/float coercion, and every single-element list collapsed to its
// element. Lines without ':' stay skipped; an E line without '=' fails the
// whole parse (upstream raises ValueError) with no partial records. Input
// is scanned incrementally line by line (single pass, no upfront split of
// the whole output) with the raw line length checked before any trimming
// or splitting.
//
// Divergences from Salt, pinned by tests: lines split on LF only (Python
// splitlines also splits lone CR and Unicode boundaries), int64-backed
// numbers with float64 fallback beyond int64 (Python ints are unbounded),
// and a singleton E map is kept instead of upstream _normalize_info's [0]
// indexing, which raises KeyError on a one-entry dict.
func parseInfo(udevInfo string) ([]map[string]any, error) {
	if len(udevInfo) > udevMaxOutputBytes {
		return nil, errUdevOutputTooLarge
	}
	devices := []map[string]any{}
	dev := map[string]any{}
	fields := 0

	flush := func() error {
		if len(dev) == 0 {
			return nil
		}
		// No record ceiling here: the cap is enforced on the first valid
		// field of a new record, so devices never exceeds the ceiling by
		// the time a record is appended.
		for sect, val := range dev {
			if list, ok := val.([]any); ok && len(list) == 1 {
				dev[sect] = list[0]
			}
		}
		devices = append(devices, dev)
		dev = map[string]any{}
		fields = 0
		return nil
	}

	for lenRemaining := udevInfo; ; {
		lineEnd := strings.IndexByte(lenRemaining, '\n')
		var raw string
		if lineEnd >= 0 {
			raw = lenRemaining[:lineEnd]
			lenRemaining = lenRemaining[lineEnd+1:]
		} else {
			raw = lenRemaining
			lenRemaining = ""
		}
		// The raw length is checked on the untrimmed segment before any
		// trimming or splitting work, and lines are scanned incrementally
		// so no per-line descriptors are allocated up front for
		// newline-heavy input (SEC-01).
		if len(raw) > udevMaxLineBytes {
			return nil, errUdevLineTooLong
		}
		line := strings.TrimSpace(raw)
		if line == "" {
			if err := flush(); err != nil {
				return nil, err
			}
		} else {
			// Inspect the section separator without allocating a split
			// slice; the field budget is checked before any parse
			// structure is built (CQ-4).
			if sep := strings.IndexByte(line, ':'); sep >= 0 {
				query, data := line[:sep], strings.TrimSpace(line[sep+1:])
				if fields+1 > udevMaxRecordFields {
					return nil, errUdevTooManyFields
				}
				if query == "E" {
					eq := strings.IndexByte(data, '=')
					if eq < 0 {
						return nil, errUdevMalformedELine
					}
					if len(dev) == 0 && len(devices) >= udevMaxRecords {
						// The record ceiling is checked on the first
						// valid field of a new record, before the record
						// is initialized or populated (CQ-4). flush can
						// therefore never append past the ceiling.
						return nil, errUdevTooManyRecords
					}
					env, _ := dev["E"].(map[string]any)
					if env == nil {
						env = map[string]any{}
						dev["E"] = env
					}
					env[data[:eq]] = coerceNumber(data[eq+1:])
					fields++
				} else {
					if len(dev) == 0 && len(devices) >= udevMaxRecords {
						return nil, errUdevTooManyRecords
					}
					list, _ := dev[query].([]any)
					dev[query] = append(list, data)
					fields++
				}
			}
			// Lines without ':' are skipped silently (upstream continue).
		}
		if lineEnd < 0 {
			break
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return devices, nil
}

// coerceNumber mirrors the int-then-float attempt chain of the Salt parser.
func coerceNumber(val string) any {
	if parsed, err := strconv.ParseInt(val, 10, 64); err == nil {
		return parsed
	}
	if parsed, err := strconv.ParseFloat(val, 64); err == nil {
		return parsed
	}
	return val
}

// EnvArgs mirrors Salt's env signature.
type EnvArgs struct {
	Dev string `statekit:"required"`
}

type envFunc struct {
	linuxOnly
}

func (envFunc) Name() string { return "udev.env" }
func (envFunc) Args() any    { return EnvArgs{} }

// Execute returns all environment variables udev has for dev, or nil when
// the record carries no E section (Salt's .get("E", None)).
func (envFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*EnvArgs)
	qtype := "name"
	if strings.Contains(a.Dev, "sys") {
		// Salt probes `"sys" in dev` to pick the udevadm query type.
		qtype = "path"
	}
	res := rt.Runner.Run(ctx, runtime.Command(
		"udevadm", "info", "--export", "--query=all", "--"+qtype+"="+a.Dev))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("%s", string(res.Stderr))
	}
	devices, err := parseInfo(string(res.Stdout))
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("no device found for %s", a.Dev)
	}
	return devices[0]["E"], nil
}

// InfoArgs mirrors Salt's info signature.
type InfoArgs struct {
	Dev string `statekit:"required"`
}

type infoFunc struct {
	linuxOnly
}

func (infoFunc) Name() string { return "udev.info" }
func (infoFunc) Args() any    { return InfoArgs{} }

// Execute extracts the full udevadm record for dev: sections P, N, S and
// E keyed like Salt's parser output. Failures raise like Salt's
// CommandExecutionError.
func (infoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InfoArgs)
	qtype := "name"
	if strings.Contains(a.Dev, "sys") {
		// Salt probes `"sys" in dev` to pick the udevadm query type.
		qtype = "path"
	}
	res := rt.Runner.Run(ctx, runtime.Command(
		"udevadm", "info", "--export", "--query=all", "--"+qtype+"="+a.Dev))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("%s", string(res.Stderr))
	}
	devices, err := parseInfo(string(res.Stdout))
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("no device found for %s", a.Dev)
	}
	return devices[0], nil
}

// NameArgs mirrors Salt's name signature.
type NameArgs struct {
	Dev string `statekit:"required"`
}

type nameFunc struct {
	linuxOnly
}

func (nameFunc) Name() string { return "udev.name" }
func (nameFunc) Args() any    { return NameArgs{} }

// Execute returns the actual dev name(s?) according to udev for dev, or
// nil when the record carries no N section (Salt's .get("N", None)).
func (nameFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*NameArgs)
	record, err := (infoFunc{}).Execute(ctx, rt, &InfoArgs{Dev: a.Dev})
	if err != nil {
		return nil, err
	}
	return record.(map[string]any)["N"], nil
}

// PathArgs mirrors Salt's path signature.
type PathArgs struct {
	Dev string `statekit:"required"`
}

type pathFunc struct {
	linuxOnly
}

func (pathFunc) Name() string { return "udev.path" }
func (pathFunc) Args() any    { return PathArgs{} }

// Execute returns the physical device path(s?) according to udev for dev,
// or nil when the record carries no P section (Salt's .get("P", None)).
func (pathFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PathArgs)
	record, err := (infoFunc{}).Execute(ctx, rt, &InfoArgs{Dev: a.Dev})
	if err != nil {
		return nil, err
	}
	return record.(map[string]any)["P"], nil
}

// LinksArgs mirrors Salt's links signature.
type LinksArgs struct {
	Dev string `statekit:"required"`
}

type linksFunc struct {
	linuxOnly
}

func (linksFunc) Name() string { return "udev.links" }
func (linksFunc) Args() any    { return LinksArgs{} }

// Execute returns all udev-created device symlinks, or nil when the
// record carries no S section (Salt's .get("S", None)).
func (linksFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*LinksArgs)
	record, err := (infoFunc{}).Execute(ctx, rt, &InfoArgs{Dev: a.Dev})
	if err != nil {
		return nil, err
	}
	return record.(map[string]any)["S"], nil
}

// Finite filter ceilings for exportdb, validated before any dispatch.
// Like the parser limits these are explicit compatibility/safety ceilings,
// not fleet capacity guarantees.
const (
	exportdbFilterMaxEntries = 256
	exportdbFilterMaxBytes   = 256
	exportdbFilterMaxTotal   = 64 << 10
	exportdbTimeout          = 30 * time.Second
	exportdbMaxStdoutCapture = 16 << 20
	exportdbMaxStderrCapture = 64 << 10
)

// Fixed, value-free exportdb errors. Divergence from Salt: nonzero exits
// and arbitrary Runner failures map to fixed errors instead of echoing
// udevadm's stderr; only the context.Canceled, context.DeadlineExceeded,
// and process.ErrOutputLimit identities survive via errors.Is.
var (
	errExportdbCommand   = errors.New("udev.exportdb: command failed")
	errExportdbCanceled  = errors.New("udev.exportdb: command canceled")
	errExportdbDeadline  = errors.New("udev.exportdb: command deadline exceeded")
	errExportdbLimit     = errors.New("udev.exportdb: command output exceeded limit")
	errExportdbParse     = errors.New("udev.exportdb: failed to parse udev database")
	errExportdbFilter    = errors.New("udev.exportdb: subsystem filter failed")
	errExportdbFilterMax = errors.New("udev.exportdb: subsystems exceed filter limit")
	errExportdbTooLarge  = errors.New("udev.exportdb: udev database output exceeds limit")
)

// ExportdbArgs mirrors Salt's exportdb signature: subsystems=None means
// unfiltered; an explicitly empty list selects no subsystem. The tag's
// list ceilings bound the caller-supplied filter at input-decode time,
// before any destination list is materialized; validateExportdbFilter
// re-checks the same ceilings as an explicit invariant for callers that
// bypass the decoder (direct registry/typed-args dispatch).
type ExportdbArgs struct {
	Subsystems *[]string `statekit:"name=subsystems,maxentries=256,maxentrybytes=256,maxtotalbytes=65536"`
}

type exportdbFunc struct {
	linuxOnly
}

func (exportdbFunc) Name() string { return "udev.exportdb" }
func (exportdbFunc) Args() any    { return ExportdbArgs{} }

// validateExportdbFilter re-checks the finite filter ceilings inside the
// module boundary. It is the second layer behind the decoder's
// pre-materialization limits (same constants, declared on the Subsystems
// tag) and is reachable through direct registry or typed-args dispatch
// that never passes through Decode. The aggregate check is an explicit
// invariant: with 256 entries x 256 bytes the aggregate ceiling of 64 KiB
// is exactly reachable and can never be exceeded while the other two
// ceilings hold, so the branch is defense in depth against future ceiling
// drift, not a routinely reachable rejection.
func validateExportdbFilter(subsystems []string) error {
	if len(subsystems) > exportdbFilterMaxEntries {
		return errExportdbFilterMax
	}
	total := 0
	for _, subsystem := range subsystems {
		if len(subsystem) > exportdbFilterMaxBytes {
			return errExportdbFilterMax
		}
		total += len(subsystem)
		if total > exportdbFilterMaxTotal {
			return errExportdbFilterMax
		}
	}
	return nil
}

// exportdbCommandError maps a Runner failure onto the fixed value-free
// errors, preserving errors.Is only for the three safe sentinel identities
// (cancellation, deadline, output limit). Like process.RedactedError, the
// error deliberately does not unwrap: an arbitrary Runner cause can carry
// paths, arguments, or captured credentials even under a redacted prefix.
func exportdbCommandError(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return &exportdbError{message: errExportdbDeadline.Error(), identities: []error{context.DeadlineExceeded}}
	case errors.Is(err, context.Canceled):
		return &exportdbError{message: errExportdbCanceled.Error(), identities: []error{context.Canceled}}
	case errors.Is(err, process.ErrOutputLimit):
		return &exportdbError{message: errExportdbLimit.Error(), identities: []error{process.ErrOutputLimit}}
	default:
		return errExportdbCommand
	}
}

// exportdbError is the fixed-text, identity-preserving error class for
// exportdb Runner failures. Is exposes only the safe sentinel identities
// collected at construction; there is intentionally no Unwrap.
type exportdbError struct {
	message    string
	identities []error
}

func (e *exportdbError) Error() string { return e.message }

func (e *exportdbError) Is(target error) bool {
	for _, identity := range e.identities {
		if identity == target {
			return true
		}
	}
	return false
}

// filterExportdbSubsystems ports _filter_subsystems: exact, case-sensitive
// client-side matching after complete parsing, with a set so repeated
// filter values cannot duplicate records and the whole pass stays
// O(records + filters). Like the source's direct indexing, a filtered
// record missing E or SUBSYSTEM fails the whole call with no partial
// result; a non-string SUBSYSTEM (numeric coercion) simply never matches,
// mirroring Python's `in` over a list of strings.
func filterExportdbSubsystems(records []map[string]any, subsystems []string) ([]map[string]any, error) {
	wanted := make(map[string]struct{}, len(subsystems))
	for _, subsystem := range subsystems {
		wanted[subsystem] = struct{}{}
	}
	out := make([]map[string]any, 0, len(records))
	for _, record := range records {
		env, ok := record["E"].(map[string]any)
		if !ok {
			return nil, errExportdbFilter
		}
		value, present := env["SUBSYSTEM"]
		if !present {
			return nil, errExportdbFilter
		}
		if subsystem, isString := value.(string); isString {
			if _, match := wanted[subsystem]; match {
				out = append(out, record)
			}
		}
	}
	return out, nil
}

// Execute returns the complete udev database as parsed records. The
// udevadm dispatch is one fixed shell-free command with a pinned locale,
// timeout, and capture budgets; filter validation precedes the dispatch,
// and every failure — Runner error, nonzero exit, either truncation,
// cancellation, deadline, parse error, oversized output, or a filtered
// record missing E/SUBSYSTEM — returns a fixed value-free error with a
// nil result.
func (exportdbFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ExportdbArgs)
	if a.Subsystems != nil {
		if err := validateExportdbFilter(*a.Subsystems); err != nil {
			return nil, err
		}
	}

	cmd := process.Command{
		Name:           "udevadm",
		Args:           []string{"info", "--export-db"},
		Env:            []string{"LC_ALL=C"},
		Timeout:        exportdbTimeout,
		Shell:          false,
		MaxStdoutBytes: exportdbMaxStdoutCapture,
		MaxStderrBytes: exportdbMaxStderrCapture,
	}
	res := rt.Runner.Run(ctx, cmd)

	if res.Err != nil {
		return nil, exportdbCommandError(res.Err)
	}
	if res.ExitCode != 0 {
		return nil, errExportdbCommand
	}
	if res.StdoutTruncated || res.StderrTruncated {
		return nil, &exportdbError{
			message:    errExportdbLimit.Error(),
			identities: []error{process.ErrOutputLimit},
		}
	}
	if len(res.Stdout) > udevMaxOutputBytes {
		return nil, errExportdbTooLarge
	}
	records, err := parseInfo(string(res.Stdout))
	if err != nil {
		return nil, errExportdbParse
	}
	if a.Subsystems != nil {
		filtered, err := filterExportdbSubsystems(records, *a.Subsystems)
		if err != nil {
			return nil, err
		}
		records = filtered
	}
	return records, nil
}

// Register installs the udev-module execution functions shipped so far.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		envFunc{},
		infoFunc{},
		exportdbFunc{},
		nameFunc{},
		pathFunc{},
		linksFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
