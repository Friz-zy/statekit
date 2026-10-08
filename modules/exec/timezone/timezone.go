// Package timezone implements Salt-compatible timezone inspection and
// management.
//
// Reference: saltstack/salt/modules/timezone.py @ pinned revision.
package timezone

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func fsPerm(mode uint32) fs.FileMode { return fs.FileMode(mode) }

// rtcValue maps a clock name onto timedatectl's set-local-rtc boolean.
func rtcValue(clock string) string {
	if clock == "UTC" {
		return "0"
	}
	return "1"
}

const (
	timezoneFile   = "/etc/timezone"
	localtimePath  = "/etc/localtime"
	zoneinfoPrefix = "/usr/share/zoneinfo/"
)

// Fixed, value-free zone_compare errors (PTD-EXEC-1638 contract): no
// raw input, path, error, or errno travels in the text.
var (
	// ErrUnknownUnsafeZone is the invocation-category failure (the
	// SaltInvocationError analog): the requested zone name is invalid,
	// or no regular zoneinfo file resolves from it.
	ErrUnknownUnsafeZone = errors.New("unknown/unsafe zone")
	// ErrCannotDetermineZone is the execution-category failure (the
	// CommandExecutionError analog): the current zone cannot be
	// detected or its localtime content cannot be read.
	ErrCannotDetermineZone = errors.New("cannot determine current zone")
	// ErrZoneConfigRead is the fixed Solaris configuration-read failure.
	// It is distinct from a readable file that has no TZ= marker, which
	// follows Solaris zone_compare's command-error byte fallback.
	ErrZoneConfigRead = errors.New("cannot read Solaris timezone configuration")
	// ErrInvalidWindowsZone is the Windows execution-category
	// invalid-requested-name failure (the analog of win_timezone.py's
	// CommandExecutionError for an unlisted timezone, kept value-free):
	// the requested name is missing, empty, or absent from the pinned
	// 134-pair table.
	ErrInvalidWindowsZone = errors.New("invalid Windows timezone")
)

type zoneCompareArgs struct {
	TimeZone string `statekit:"required,name=timezone"`
}

// zoneCompareFunc implements timezone.zone_compare for the Linux
// generic filesystem contract.
type zoneCompareFunc struct{}

func (zoneCompareFunc) Name() string { return "timezone.zone_compare" }

// Platforms restricts zone_compare to linux: this type is Linux-only;
// macOS, Windows, and Solaris have separate GOOS implementations, while
// AIX and NILinuxRT remain deferred.
func (zoneCompareFunc) Platforms() []string { return []string{"linux"} }

func (zoneCompareFunc) Args() any { return zoneCompareArgs{} }

// Finite zone_compare controls. These are explicit compatibility and
// safety ceilings, not fleet capacity guarantees; every limit fails
// closed with a fixed value-free error and no partial reads.
const (
	// zoneCompareReadLimit bounds each timezone content read (1 MiB).
	zoneCompareReadLimit = 1 << 20
	// zoneCompareMaxHops bounds total symlink hops per resolution.
	zoneCompareMaxHops = 8
	// zoneCompareMaxComponents bounds cumulative path components
	// processed per resolution, including the zoneinfo prefix.
	zoneCompareMaxComponents = 64
	// zoneNameMaxBytes bounds the requested zone name.
	zoneNameMaxBytes = 1024
	// zoneNameMaxSegmentBytes bounds one requested name segment.
	zoneNameMaxSegmentBytes = 255
	// zoneNameMaxComponents bounds requested name segments.
	zoneNameMaxComponents = 64
	// zoneinfoDir is the fixed, admin-controlled zone database root.
	zoneinfoDir = "/usr/share/zoneinfo"
)

// zoneNameByte reports whether b is an allowed zone-name byte:
// [A-Za-z0-9_+-]. Everything else — including separators, whitespace,
// controls, NUL, backslash, and any non-ASCII byte — is rejected.
func zoneNameByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '_' || b == '+' || b == '-':
		return true
	}
	return false
}

// validateZoneName accepts only a nonempty relative name of slash-
// separated ASCII components (UTC, Etc/GMT+5, Etc/GMT-14, US/Eastern,
// America/Argentina/Buenos_Aires, EST5EDT). Absolute names, empty or
// dot components (repeated/trailing slash, ".", ".."), backslashes,
// controls, NUL, non-ASCII bytes, and over-ceiling names are rejected
// before any filesystem operation. The input is never trimmed or
// normalized into validity.
func validateZoneName(zone string) error {
	reject := func() error { return ErrUnknownUnsafeZone }
	if zone == "" || len(zone) > zoneNameMaxBytes || strings.HasPrefix(zone, "/") {
		return reject()
	}
	segments := strings.Split(zone, "/")
	if len(segments) > zoneNameMaxComponents {
		return reject()
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || len(segment) > zoneNameMaxSegmentBytes {
			return reject()
		}
		for i := 0; i < len(segment); i++ {
			if !zoneNameByte(segment[i]) {
				return reject()
			}
		}
	}
	return nil
}

// underZoneinfoDir reports whether the resolved component stack (a
// clean absolute path split on "/") is inside the zoneinfo root.
func underZoneinfoDir(cur []string) bool {
	if len(cur) < 3 || cur[0] != "usr" || cur[1] != "share" || cur[2] != "zoneinfo" {
		return false
	}
	return true
}

// errZoneResolution is the internal resolution failure: dangling,
// looping, escaping, special, and over-budget chains all collapse to
// this sentinel and never carry the offending path or errno.
var errZoneResolution = errors.New("timezone: zone file resolution failed")

// resolveZoneinfoFile resolves start (an absolute path, either
// /etc/localtime or inside the zoneinfo root) to a regular file,
// following symlinks component-wise with Lstat/Readlink only. Every
// symlink target must resolve under the fixed zoneinfo root: absolute
// targets are lexically prechecked against it, and ".." may never pop
// above the root once the walk is inside it (kernel ".."-at-root
// semantics apply outside it). Resolution is bounded by
// zoneCompareMaxHops total symlink hops and zoneCompareMaxComponents
// cumulative components. Dangling links, non-directory intermediates,
// special files, and directories as the final component are rejected.
// The parent directories /etc and /usr/share/zoneinfo are assumed
// admin-controlled; no atomic snapshot across the walk is guaranteed.
func resolveZoneinfoFile(fsys runtime.FileSystem, start string) (string, error) {
	queue := strings.Split(strings.TrimPrefix(start, "/"), "/")
	cur := make([]string, 0, zoneCompareMaxComponents)
	hops, processed := 0, 0
	for len(queue) > 0 {
		component := queue[0]
		queue = queue[1:]
		processed++
		if processed > zoneCompareMaxComponents {
			return "", errZoneResolution
		}
		switch component {
		case "", ".":
			continue
		case "..":
			if len(cur) == 0 {
				continue // "/.." resolves to "/" (kernel semantics)
			}
			if underZoneinfoDir(cur) && len(cur) == 3 {
				return "", errZoneResolution // would leave the zoneinfo root
			}
			cur = cur[:len(cur)-1]
		default:
			cur = append(cur, component)
			pathName := "/" + strings.Join(cur, "/")
			info, err := fsys.Lstat(pathName)
			if err != nil {
				return "", errZoneResolution
			}
			mode := info.Mode()
			switch {
			case mode&fs.ModeSymlink != 0:
				hops++
				if hops > zoneCompareMaxHops {
					return "", errZoneResolution
				}
				target, err := fsys.Readlink(pathName)
				if err != nil {
					return "", errZoneResolution
				}
				if strings.HasPrefix(target, "/") {
					clean := path.Clean(target)
					if !strings.HasPrefix(clean, zoneinfoDir+"/") {
						return "", errZoneResolution
					}
					cur = cur[:0]
					queue = append(strings.Split(strings.TrimPrefix(target, "/"), "/"), queue...)
				} else {
					// Relative target: relative to the link's directory.
					cur = cur[:len(cur)-1]
					queue = append(strings.Split(target, "/"), queue...)
				}
			case mode.IsDir():
				// Intermediate directory; keep descending.
			default:
				if len(queue) != 0 {
					// Regular or special file used as an intermediate
					// component: nothing can live below it.
					return "", errZoneResolution
				}
				if !mode.IsRegular() || !underZoneinfoDir(cur) {
					return "", errZoneResolution
				}
				return pathName, nil
			}
		}
	}
	// The queue exhausted on a directory (or the root): not a file.
	return "", errZoneResolution
}

// detectCurrentZone mirrors the Linux filesystem zone detectors of the
// pinned get_zone: /etc/timezone participates only as a regular file
// read through the bounded no-follow API (symlinks, special files, and
// oversize contents are skipped), and a contained /etc/localtime
// symlink yields the exact zone name from the initial target —
// preserving aliases like US/Eastern — once the full chain resolves to
// a regular file under the zoneinfo root. ok=false means detection
// failed and the caller must fall back to the bounded byte comparison.
func detectCurrentZone(fsys runtime.FileSystem) (string, bool) {
	if info, err := fsys.Lstat(timezoneFile); err == nil && info.Mode().IsRegular() {
		if data, err := runtime.ReadFileBounded(fsys, timezoneFile, zoneCompareReadLimit); err == nil {
			return strings.TrimSpace(string(data)), true
		}
	}
	info, err := fsys.Lstat(localtimePath)
	if err != nil || info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink == 0 {
		return "", false
	}
	target, err := fsys.Readlink(localtimePath)
	if err != nil {
		return "", false
	}
	lexical := target
	if !strings.HasPrefix(lexical, "/") {
		lexical = path.Join("/etc", lexical)
	}
	lexical = path.Clean(lexical)
	if !strings.HasPrefix(lexical, zoneinfoDir+"/") {
		return "", false
	}
	name := strings.TrimPrefix(lexical, zoneinfoDir+"/")
	if name == "" {
		return "", false
	}
	if _, err := resolveZoneinfoFile(fsys, localtimePath); err != nil {
		return "", false
	}
	return name, true
}

// currentZoneBytes reads the current zone content for the byte
// fallback: /etc/localtime directly when regular, otherwise through
// the contained bounded symlink resolution. The current file is read
// before the requested zone so its failure category wins.
func currentZoneBytes(fsys runtime.FileSystem) ([]byte, error) {
	info, err := fsys.Lstat(localtimePath)
	if err != nil {
		return nil, errZoneResolution
	}
	if info.Mode().IsRegular() {
		return runtime.ReadFileBounded(fsys, localtimePath, zoneCompareReadLimit)
	}
	if info.Mode()&fs.ModeSymlink == 0 {
		return nil, errZoneResolution
	}
	resolved, err := resolveZoneinfoFile(fsys, localtimePath)
	if err != nil {
		return nil, err
	}
	return runtime.ReadFileBounded(fsys, resolved, zoneCompareReadLimit)
}

// zoneinfoZoneBytes reads the requested zone's file for the byte
// fallback through the contained bounded symlink resolution.
func zoneinfoZoneBytes(fsys runtime.FileSystem, zone string) ([]byte, error) {
	resolved, err := resolveZoneinfoFile(fsys, zoneinfoDir+"/"+zone)
	if err != nil {
		return nil, err
	}
	return runtime.ReadFileBounded(fsys, resolved, zoneCompareReadLimit)
}

// Execute ports timezone.zone_compare (pinned revision lines 331-372)
// for the Linux generic filesystem contract: an exact, case-sensitive
// name comparison against the detected current zone when detection
// succeeds (unequal names answer false with no byte fallback), and only
// on detection failure a bounded byte comparison of /etc/localtime
// (read first) against /usr/share/zoneinfo/<timezone>. An unusable
// requested zone fails with ErrUnknownUnsafeZone (SaltInvocationError
// analog); an unreadable current zone fails with
// ErrCannotDetermineZone (CommandExecutionError analog). The function
// issues no commands, no Runner calls, and no writes.
func (zoneCompareFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*zoneCompareArgs)
	if err := validateZoneName(a.TimeZone); err != nil {
		return nil, err
	}
	if name, ok := detectCurrentZone(rt.FS); ok {
		return a.TimeZone == name, nil
	}
	current, err := currentZoneBytes(rt.FS)
	if err != nil {
		return nil, ErrCannotDetermineZone
	}
	requested, err := zoneinfoZoneBytes(rt.FS, a.TimeZone)
	if err != nil {
		return nil, ErrUnknownUnsafeZone
	}
	return bytes.Equal(current, requested), nil
}

// solarisZoneCompareArgs is the Solaris timezone.zone_compare argument
// contract. The required pointer distinguishes an omitted timezone from
// an explicit empty value, which remains valid for exact string equality.
type solarisZoneCompareArgs struct {
	TimeZone *string `statekit:"required,name=timezone"`
}

// solarisZoneCompareFunc implements the Solaris get_zone order: use
// timedatectl when available, otherwise parse /etc/TIMEZONE. Only a
// command-execution failure or a readable config without TZ= reaches the
// bounded byte fallback; config read failures remain distinct.
type solarisZoneCompareFunc struct{}

func (solarisZoneCompareFunc) Name() string { return "timezone.zone_compare" }

func (solarisZoneCompareFunc) Platforms() []string { return []string{"solaris"} }

func (solarisZoneCompareFunc) Args() any { return solarisZoneCompareArgs{} }

const (
	solarisTimezoneFile       = "/etc/TIMEZONE"
	solarisConfigReadLimit    = 64 << 10
	solarisTimedatectlTimeout = 30 * time.Second
	solarisTimedatectlMax     = 64 << 10
)

var (
	errSolarisZoneInvalidArgs = errors.New("invalid zone_compare arguments")
	errSolarisZoneNoMarker    = errors.New("timezone: Solaris configuration has no TZ setting")
	errSolarisZoneCommand     = errors.New("timezone: timedatectl query failed")
)

// parseSolarisTimezoneConfig mirrors fopen(..., newline="") record
// boundaries while preserving each original terminator. Salt then applies
// line.rstrip("\\n"), which removes LF but leaves CR from CRLF or bare-CR
// records in the selected value. Only the first TZ= record is used, with
// quote characters trimmed from the selected value's actual edges.
func parseSolarisTimezoneConfig(data []byte) (string, bool) {
	for start := 0; start <= len(data); {
		end := start
		for end < len(data) && data[end] != '\n' && data[end] != '\r' {
			end++
		}
		recordEnd := end
		if end < len(data) {
			if data[end] == '\r' && end+1 < len(data) && data[end+1] == '\n' {
				recordEnd = end + 2
			} else {
				recordEnd = end + 1
			}
		}
		line := bytes.TrimRight(data[start:recordEnd], "\n")
		if bytes.Contains(line, []byte("TZ=")) {
			lastEquals := bytes.LastIndexByte(line, '=')
			value := strings.Trim(string(line[lastEquals+1:]), `"'`)
			if value == "" {
				return "UTC", true
			}
			return value, true
		}
		if recordEnd == len(data) {
			break
		}
		start = recordEnd
	}
	return "", false
}

// readSolarisConfiguredZone reads only the fixed Solaris configuration
// through the existing bounded no-follow API. The data buffer is cleared
// on both parse and no-marker exits; read failures are value-free and are
// never eligible for the byte fallback.
func readSolarisConfiguredZone(fsys runtime.FileSystem) (string, error) {
	if fsys == nil {
		return "", ErrZoneConfigRead
	}
	data, err := runtime.ReadFileBounded(fsys, solarisTimezoneFile, solarisConfigReadLimit)
	if err != nil {
		clear(data)
		return "", ErrZoneConfigRead
	}
	defer clear(data)
	if zone, ok := parseSolarisTimezoneConfig(data); ok {
		return zone, nil
	}
	return "", errSolarisZoneNoMarker
}

// parseSolarisTimedatectlZone mirrors Salt's literal-LF record splitting,
// Python strip(), and first case-sensitive anchored `Time ?zone:\s+(\S+)`
// match. A bare CR inside a record is whitespace for matching but does not
// create a record boundary; Python whitespace helpers preserve the source
// semantics rather than Go's ASCII-only regexp \s behavior.
func parseSolarisTimedatectlZone(stdout []byte) (string, bool) {
	for _, line := range strings.Split(string(stdout), "\n") {
		line = pythonStrip(line)
		headerLength := 0
		switch {
		case strings.HasPrefix(line, "Time zone:"):
			headerLength = len("Time zone:")
		case strings.HasPrefix(line, "Timezone:"):
			headerLength = len("Timezone:")
		default:
			continue
		}

		valueStart := headerLength
		cursor := valueStart
		for cursor < len(line) {
			r, size := utf8.DecodeRuneInString(line[cursor:])
			if !pythonSpace(r) {
				break
			}
			cursor += size
		}
		if cursor <= valueStart || cursor == len(line) {
			continue
		}
		valueEnd := cursor
		for valueEnd < len(line) {
			r, size := utf8.DecodeRuneInString(line[valueEnd:])
			if pythonSpace(r) {
				break
			}
			valueEnd += size
		}
		if valueEnd > cursor {
			return line[cursor:valueEnd], true
		}
	}
	return "", false
}

// runSolarisTimedatectl maps every command or parse failure to one fixed
// source error, keeping command causes and output private while leaving
// the caller to decide whether the source failure permits fallback.
func runSolarisTimedatectl(ctx context.Context, runner process.Runner) (string, error) {
	res := runner.Run(ctx, process.Command{
		Name:           "timedatectl",
		Args:           nil,
		Env:            []string{"LC_ALL=C"},
		Timeout:        solarisTimedatectlTimeout,
		MaxStdoutBytes: solarisTimedatectlMax,
		MaxStderrBytes: solarisTimedatectlMax,
	})
	if res.Err != nil || !res.Started || res.ExitCode != 0 || res.StdoutTruncated || res.StderrTruncated ||
		len(res.Stdout) > solarisTimedatectlMax || len(res.Stderr) > solarisTimedatectlMax {
		return "", errSolarisZoneCommand
	}
	zone, ok := parseSolarisTimedatectlZone(res.Stdout)
	if !ok {
		return "", errSolarisZoneCommand
	}
	return zone, nil
}

// solarisContextBoundedFS checks caller cancellation around each bounded
// read while preserving the underlying filesystem's no-follow behavior.
// Context errors are returned without retaining any bytes read meanwhile.
type solarisContextBoundedFS struct {
	runtime.FileSystem
	ctx context.Context
}

func (f solarisContextBoundedFS) ReadFileBounded(name string, limit int64) ([]byte, error) {
	if err := f.ctx.Err(); err != nil {
		return nil, err
	}
	data, err := runtime.ReadFileBounded(f.FileSystem, name, limit)
	if ctxErr := f.ctx.Err(); ctxErr != nil {
		clear(data)
		return nil, ctxErr
	}
	return data, err
}

// solarisZoneCompareFallback validates the caller-controlled zone only
// after current-zone discovery has failed, then preserves the established
// current-side-first bounded no-follow byte comparison and fixed error
// categories used by the generic filesystem variant. Context checks before
// and after each bounded read give caller cancellation precedence over
// source-file failures and prevent reading the requested side afterward.
func solarisZoneCompareFallback(ctx context.Context, fsys runtime.FileSystem, zone string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := validateZoneName(zone); err != nil {
		return false, err
	}
	if fsys == nil {
		return false, ErrCannotDetermineZone
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	boundedFS := solarisContextBoundedFS{FileSystem: fsys, ctx: ctx}
	current, err := currentZoneBytes(boundedFS)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}
	if err != nil {
		return false, ErrCannotDetermineZone
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	requested, err := zoneinfoZoneBytes(boundedFS, zone)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}
	if err != nil {
		return false, ErrUnknownUnsafeZone
	}
	return bytes.Equal(current, requested), nil
}

// Execute ports the Solaris timezone.zone_compare source contract. It
// checks command availability before any filesystem access, executes at
// most one fixed shell-free timedatectl query, and otherwise reads only
// the bounded /etc/TIMEZONE file. Successful string discovery compares
// exactly and never falls back on mismatch. Caller context cancellation
// and deadlines are preserved as static context errors and never become
// fallback triggers; command failures use only the bounded, no-follow
// localtime/zoneinfo byte path. No command output, config bytes, paths,
// or underlying causes are logged or returned.
func (solarisZoneCompareFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*solarisZoneCompareArgs)
	if !ok || a == nil {
		return nil, errSolarisZoneInvalidArgs
	}
	if a.TimeZone == nil {
		if err := config.ValidateRequired(a); err != nil {
			return nil, err
		}
		return nil, errSolarisZoneInvalidArgs
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if rt == nil || rt.Runner == nil {
		return nil, ErrCannotDetermineZone
	}
	availability, ok := rt.Runner.(process.CommandAvailability)
	if !ok {
		return nil, ErrCannotDetermineZone
	}
	available := availability.CommandAvailable("timedatectl")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !available {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		zone, err := readSolarisConfiguredZone(rt.FS)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if err == nil {
			return *a.TimeZone == zone, nil
		}
		if !errors.Is(err, errSolarisZoneNoMarker) {
			return nil, ErrZoneConfigRead
		}
		matched, fallbackErr := solarisZoneCompareFallback(ctx, rt.FS, *a.TimeZone)
		if fallbackErr != nil {
			return nil, fallbackErr
		}
		return matched, nil
	}

	zone, commandErr := runSolarisTimedatectl(ctx, rt.Runner)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if commandErr == nil {
		return *a.TimeZone == zone, nil
	}

	matched, err := solarisZoneCompareFallback(ctx, rt.FS, *a.TimeZone)
	if err != nil {
		return nil, err
	}
	return matched, nil
}

// macZoneCompareArgs is the mac_timezone.zone_compare argument
// contract. The required POINTER distinguishes an omitted time_zone
// (nil, rejected by the required gate before any dispatch) from an
// explicit empty string, which is valid and compares exactly.
type macZoneCompareArgs struct {
	TimeZone *string `statekit:"required,name=time_zone"`
}

// macZoneCompareFunc implements timezone.zone_compare for the pinned
// mac_timezone.py contract: get_zone (lines 151-165) shells out to
// `systemsetup -gettimezone` through mac_utils, and zone_compare
// (lines 247-260) answers an exact, case-sensitive string equality
// against the parsed output.
type macZoneCompareFunc struct{}

func (macZoneCompareFunc) Name() string { return "timezone.zone_compare" }

// Platforms restricts the mac variant to darwin; the AIX and NILinuxRT
// rows of PTD-EXEC-1638 stay open.
func (macZoneCompareFunc) Platforms() []string { return []string{"darwin"} }

func (macZoneCompareFunc) Args() any { return macZoneCompareArgs{} }

// Fixed mac zone_compare invocation controls: the absolute
// admin-controlled systemsetup path (no PATH lookup), exactly one argv
// flag, a locale-only child environment, a bounded wall clock, and
// equal 64 KiB capture ceilings per stream.
const (
	macZoneSystemsetup = "/usr/sbin/systemsetup"
	macZoneTimeout     = 30 * time.Second
	macZoneStreamMax   = 64 << 10
)

// pythonSpace reports whether r is Python str.isspace whitespace:
// unicode.IsSpace plus the U+001C..U+001F file/group/record/unit
// separators, which Python strips but Go's unicode.IsSpace does not.
func pythonSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// pythonRStrip strips trailing Python whitespace only, mirroring the
// str.rstrip() that mac_utils._run_all applies to stdout and stderr;
// leading whitespace is never touched.
func pythonRStrip(s string) string {
	end := len(s)
	for end > 0 {
		r, size := utf8.DecodeLastRuneInString(s[:end])
		if !pythonSpace(r) {
			break
		}
		end -= size
	}
	return s[:end]
}

// macParseReturn ports mac_utils.parse_return source-exactly: the
// first ": " delimiter wins and returns the segment after its first
// occurrence (later segments are discarded), then ":\n", otherwise the
// whole raw string returns with no further trimming.
func macParseReturn(data string) string {
	if strings.Contains(data, ": ") {
		return strings.Split(data, ": ")[1]
	}
	if strings.Contains(data, ":\n") {
		return strings.Split(data, ":\n")[1]
	}
	return data
}

// pythonStrip strips leading and trailing Python whitespace only
// (pythonSpace: unicode.IsSpace plus U+001C..U+001F), mirroring the
// str.strip() that each mac_timezone.list_zones splitlines line
// applies; interior whitespace is never touched. The trailing half
// reuses pythonRStrip.
func pythonStrip(s string) string {
	start := 0
	for start < len(s) {
		r, size := utf8.DecodeRuneInString(s[start:])
		if !pythonSpace(r) {
			break
		}
		start += size
	}
	return pythonRStrip(s[start:])
}

// pythonSplitlines splits on the exact Python str.splitlines()
// boundaries needed by mac_timezone.list_zones: \n, \r, \r\n (one
// boundary), \v, \f, U+001C..U+001E, U+0085, and U+2028/U+2029.
// U+001F is Python strip whitespace but NOT a line boundary. A
// trailing boundary yields no trailing empty element; interior
// boundaries preserve interior empty lines in order. Each line is
// sliced at the SOURCE boundary index — for CRLF at the CR — so the
// boundary bytes never leak into the preceding line.
func pythonSplitlines(s string) []string {
	var lines []string
	start := 0
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		boundaryEnd := 0
		switch runes[i] {
		case '\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029':
			boundaryEnd = i + 1
		case '\r':
			boundaryEnd = i + 1
			if i+1 < len(runes) && runes[i+1] == '\n' {
				boundaryEnd = i + 2 // CRLF is one boundary
			}
		default:
			continue
		}
		// The slice always ends at the source boundary index i (the CR
		// itself for CRLF); only `start` advances over the whole
		// boundary, so a preceding line can never retain the CR
		// (F-01: slicing after advancing i kept the CR).
		lines = append(lines, string(runes[start:i]))
		start = boundaryEnd
		i = boundaryEnd - 1 // the loop's i++ resumes after the boundary
	}
	if start < len(runes) {
		lines = append(lines, string(runes[start:]))
	}
	return lines
}

// errMacZoneInvalidArgs is the fixed, value-free invocation error for
// arguments that cannot be the mac zone_compare contract at all (a
// wrong dynamic type or a typed-nil pointer); it never formats or
// echoes the raw args value or an underlying cause.
var errMacZoneInvalidArgs = errors.New("invalid zone_compare arguments")

// Execute ports mac_timezone.zone_compare for the macOS variant
// (PTD-EXEC-1638 Mac partial): one fixed, shell-free
// `/usr/sbin/systemsetup -gettimezone` dispatch with LC_ALL=C, a 30s
// timeout, and 64 KiB capture ceilings per stream. Boundary guards
// first (architecture gate): direct callers bypassing the registry's
// required-args gate fail safely before any Runner dispatch — a wrong
// argument type or typed-nil pointer returns errMacZoneInvalidArgs, a
// nonnil struct with a nil TimeZone reuses the decoder's fixed
// missing-required error, and a nil Runtime or Runner returns
// ErrCannotDetermineZone — never a panic, never a filesystem access,
// never raw args formatted into the error. Then any Runner error,
// nonzero exit, truncation flag, or over-cap stream — and any rstripped
// stdout containing case-insensitive "not supported", mirroring Salt's
// execute_return_result — fails with the single fixed
// ErrCannotDetermineZone; no raw cause, output, stderr, or exit status
// travels in the error and nothing is logged. Successful output is
// parsed source-exactly (Python trailing-rstrip, then parse_return)
// and compared exactly against the requested time_zone; empty or
// malformed output simply compares, with no added input validation.
// Residual trust assumption: /usr/sbin and systemsetup are
// admin-controlled; binary authenticity is out of scope.
func (macZoneCompareFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*macZoneCompareArgs)
	if !ok || a == nil {
		return nil, errMacZoneInvalidArgs
	}
	if a.TimeZone == nil {
		// Reuse the decoder's fixed required-argument error so direct
		// callers see the same missing-time_zone failure the registry
		// gate produces; the defensive fallback keeps a future tag
		// change from re-opening a nil dereference.
		if err := config.ValidateRequired(a); err != nil {
			return nil, err
		}
		return nil, errMacZoneInvalidArgs
	}
	if rt == nil || rt.Runner == nil {
		return nil, ErrCannotDetermineZone
	}
	res := rt.Runner.Run(ctx, process.Command{
		Name:           macZoneSystemsetup,
		Args:           []string{"-gettimezone"},
		Env:            []string{"LC_ALL=C"},
		Timeout:        macZoneTimeout,
		MaxStdoutBytes: macZoneStreamMax,
		MaxStderrBytes: macZoneStreamMax,
	})
	if res.Err != nil || res.ExitCode != 0 ||
		res.StdoutTruncated || res.StderrTruncated ||
		len(res.Stdout) > macZoneStreamMax || len(res.Stderr) > macZoneStreamMax {
		return nil, ErrCannotDetermineZone
	}
	stdout := pythonRStrip(string(res.Stdout))
	if strings.Contains(strings.ToLower(stdout), "not supported") {
		return nil, ErrCannotDetermineZone
	}
	return *a.TimeZone == macParseReturn(stdout), nil
}

type getZoneArgs struct{}

// ErrMacSystemsetupQuery is the fixed, value-free execution failure
// for the Mac systemsetup getters (the mac_timezone
// get_date/get_time/get_using_network_time/get_time_server/list_zones
// CommandExecutionError analog): the query could not be completed. It
// is distinct from ErrCannotDetermineZone and from
// ErrMacNetworkTimeStateInvalid; errors.Is matches only this
// sentinel and no raw cause, output, stderr, or exit status ever
// travels in the error.
var ErrMacSystemsetupQuery = errors.New("macOS systemsetup query failed")

// errMacGetterInvalidArgs is the fixed, value-free invocation error
// for getter arguments that cannot be the contract at all (a wrong
// dynamic type or a typed-nil pointer); it never formats or echoes the
// raw args value or an underlying cause.
var errMacGetterInvalidArgs = errors.New("invalid timezone getter arguments")

// errMacSystemsetupUnknownGetter is the fixed, value-free internal
// rejection for a macSystemsetupGetter value outside the closed enum.
var errMacSystemsetupUnknownGetter = errors.New("unknown systemsetup getter")

// macSystemsetupGetter is the private closed selector for the only
// five read-only systemsetup queries the module may run. Values never
// come from user input: each maps to exactly one fixed argv flag, and
// any other value is rejected before the Runner is touched — arbitrary
// argv, zone flags, and setter flags cannot be expressed through it.
// macSystemsetupListTimezones is pinned to the explicit value 5 so the
// historically invalid out-of-enum value 4 stays invalid (the -1, 4,
// and 99 rejection pins do not move).
type macSystemsetupGetter int

const (
	macSystemsetupGetDate macSystemsetupGetter = iota
	macSystemsetupGetTime
	macSystemsetupGetUsingNetworkTime
	macSystemsetupGetTimeServer
	macSystemsetupListTimezones macSystemsetupGetter = 5
)

// flag returns the single fixed argv flag for the closed enum value:
// -getdate for the date query, -gettime for the time query,
// -getusingnetworktime for the network-time state query,
// -getnetworktimeserver for the time-server query, -listtimezones for
// the read-only zone-list query, and the fixed unknown-getter
// rejection for anything else (including the unassigned value 4).
func (g macSystemsetupGetter) flag() (string, error) {
	switch g {
	case macSystemsetupGetDate:
		return "-getdate", nil
	case macSystemsetupGetTime:
		return "-gettime", nil
	case macSystemsetupGetUsingNetworkTime:
		return "-getusingnetworktime", nil
	case macSystemsetupGetTimeServer:
		return "-getnetworktimeserver", nil
	case macSystemsetupListTimezones:
		return "-listtimezones", nil
	}
	return "", errMacSystemsetupUnknownGetter
}

// Fixed Mac getter invocation controls: the absolute admin-controlled
// systemsetup path (no PATH lookup), exactly one argv flag, a
// locale-only child environment, a bounded wall clock, and equal 64
// KiB capture ceilings per stream.
const (
	macSystemsetupPath = "/usr/sbin/systemsetup"
	macGetterTimeout   = 30 * time.Second
	macGetterStreamMax = 64 << 10
)

// macSystemsetupQuery runs the one fixed shell-free systemsetup query
// selected by the closed enum (pinned mac_timezone.py get_date lines
// 60-74 / get_time lines 107-121 through mac_utils): an unknown enum
// value is rejected before the Runner, a nil Runtime or Runner fails
// fixed with ErrMacSystemsetupQuery, and any Runner error, nonzero
// exit, truncation flag, or over-cap stream — and any rstripped stdout
// containing case-insensitive "not supported", mirroring Salt's
// execute_return_result — fails with the same single fixed
// ErrMacSystemsetupQuery; no raw cause, output, stderr, or exit status
// travels in the error and nothing is logged. Successful output is
// parsed source-exactly (Python trailing-rstrip, then parse_return) —
// an empty or whitespace-rstripped stdout yields the empty string.
// Residual trust assumption: /usr/sbin and systemsetup are
// admin-controlled; binary authenticity is out of scope.
func macSystemsetupQuery(ctx context.Context, rt *runtime.Runtime, getter macSystemsetupGetter) (string, error) {
	flag, err := getter.flag()
	if err != nil {
		return "", err
	}
	if rt == nil || rt.Runner == nil {
		return "", ErrMacSystemsetupQuery
	}
	res := rt.Runner.Run(ctx, process.Command{
		Name:           macSystemsetupPath,
		Args:           []string{flag},
		Env:            []string{"LC_ALL=C"},
		Timeout:        macGetterTimeout,
		MaxStdoutBytes: macGetterStreamMax,
		MaxStderrBytes: macGetterStreamMax,
	})
	if res.Err != nil || res.ExitCode != 0 ||
		res.StdoutTruncated || res.StderrTruncated ||
		len(res.Stdout) > macGetterStreamMax || len(res.Stderr) > macGetterStreamMax {
		return "", ErrMacSystemsetupQuery
	}
	stdout := pythonRStrip(string(res.Stdout))
	if strings.Contains(strings.ToLower(stdout), "not supported") {
		return "", ErrMacSystemsetupQuery
	}
	return macParseReturn(stdout), nil
}

// macGetDateArgs is the zero-field Mac get_date argument contract: the
// catalog declares no parameters for get_date.
type macGetDateArgs struct{}

// macGetTimeArgs is the zero-field Mac get_time argument contract: the
// catalog declares no parameters for get_time.
type macGetTimeArgs struct{}

// macGetDateFunc implements timezone.get_date for the pinned
// mac_timezone.py contract.
type macGetDateFunc struct{}

func (macGetDateFunc) Name() string        { return "timezone.get_date" }
func (macGetDateFunc) Platforms() []string { return []string{"darwin"} }
func (macGetDateFunc) Args() any           { return macGetDateArgs{} }

// Execute ports mac_timezone.get_date (pinned revision lines 60-74):
// boundary guards first (architecture gate) — a wrong argument type or
// typed-nil pointer returns the fixed errMacGetterInvalidArgs before
// any dispatch, never a panic and never raw args formatted into the
// error — then exactly one fixed shell-free
// `/usr/sbin/systemsetup -getdate` dispatch through the shared closed
// enum query; the date string (or "" for empty successful output) is
// returned with a nil value on every error, and every query failure
// maps to ErrMacSystemsetupQuery.
func (macGetDateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if a, ok := args.(*macGetDateArgs); !ok || a == nil {
		return nil, errMacGetterInvalidArgs
	}
	value, err := macSystemsetupQuery(ctx, rt, macSystemsetupGetDate)
	if err != nil {
		return nil, err
	}
	return value, nil
}

// macGetTimeFunc implements timezone.get_time for the pinned
// mac_timezone.py contract.
type macGetTimeFunc struct{}

func (macGetTimeFunc) Name() string        { return "timezone.get_time" }
func (macGetTimeFunc) Platforms() []string { return []string{"darwin"} }
func (macGetTimeFunc) Args() any           { return macGetTimeArgs{} }

// Execute ports mac_timezone.get_time (pinned revision lines 107-121):
// boundary guards first (architecture gate) — a wrong argument type or
// typed-nil pointer returns the fixed errMacGetterInvalidArgs before
// any dispatch, never a panic and never raw args formatted into the
// error — then exactly one fixed shell-free
// `/usr/sbin/systemsetup -gettime` dispatch through the shared closed
// enum query; the time string (or "" for empty successful output) is
// returned with a nil value on every error, and every query failure
// maps to ErrMacSystemsetupQuery.
func (macGetTimeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if a, ok := args.(*macGetTimeArgs); !ok || a == nil {
		return nil, errMacGetterInvalidArgs
	}
	value, err := macSystemsetupQuery(ctx, rt, macSystemsetupGetTime)
	if err != nil {
		return nil, err
	}
	return value, nil
}

// ErrMacNetworkTimeStateInvalid is the fixed, value-free invocation
// failure for the network-time state getter (the SaltInvocationError
// analog of mac_utils.validate_enabled): the parsed systemsetup answer
// is not one of the case-insensitive on/yes/off/no aliases. It is
// distinct from ErrMacSystemsetupQuery; errors.Is matches only this
// sentinel and the raw parsed value never travels in the error.
var ErrMacNetworkTimeStateInvalid = errors.New("macOS network time state invalid")

// macValidateEnabled ports the string branch of
// mac_utils.validate_enabled source-exactly over the already-parsed
// getter answer: case-insensitive on/yes => true, off/no => false, and
// every other string — including the empty string — fails with the
// fixed ErrMacNetworkTimeStateInvalid (the SaltInvocationError
// analog). No trimming happens here; the value is exactly what
// parse_return produced after the command's Python stdout rstrip.
func macValidateEnabled(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "on", "yes":
		return true, nil
	case "off", "no":
		return false, nil
	}
	return false, ErrMacNetworkTimeStateInvalid
}

// macGetUsingNetworkTimeArgs is the zero-field argument contract: the
// catalog declares no parameters for get_using_network_time.
type macGetUsingNetworkTimeArgs struct{}

// macGetTimeServerArgs is the zero-field argument contract: the
// catalog declares no parameters for get_time_server.
type macGetTimeServerArgs struct{}

// macGetUsingNetworkTimeFunc implements timezone.get_using_network_time
// for the pinned mac_timezone.py contract.
type macGetUsingNetworkTimeFunc struct{}

func (macGetUsingNetworkTimeFunc) Name() string        { return "timezone.get_using_network_time" }
func (macGetUsingNetworkTimeFunc) Platforms() []string { return []string{"darwin"} }
func (macGetUsingNetworkTimeFunc) Args() any           { return macGetUsingNetworkTimeArgs{} }

// Execute ports mac_timezone.get_using_network_time (pinned revision
// lines 263-281): boundary guards first (architecture gate) — a wrong
// argument type or typed-nil pointer returns the fixed
// errMacGetterInvalidArgs before any dispatch, never a panic and never
// raw args formatted into the error — then exactly one fixed
// shell-free `/usr/sbin/systemsetup -getusingnetworktime` dispatch
// through the shared closed enum query; the parsed answer is validated
// exactly like the string branch of mac_utils.validate_enabled —
// case-insensitive on/yes => true, off/no => false, anything else
// (including the empty string) fails with the fixed value-free
// ErrMacNetworkTimeStateInvalid, never false — and no raw value,
// output, or cause travels in any error. Every query failure maps to
// ErrMacSystemsetupQuery with a nil result value.
func (macGetUsingNetworkTimeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if a, ok := args.(*macGetUsingNetworkTimeArgs); !ok || a == nil {
		return nil, errMacGetterInvalidArgs
	}
	value, err := macSystemsetupQuery(ctx, rt, macSystemsetupGetUsingNetworkTime)
	if err != nil {
		return nil, err
	}
	enabled, err := macValidateEnabled(value)
	if err != nil {
		return nil, err
	}
	return enabled, nil
}

// macGetTimeServerFunc implements timezone.get_time_server for the
// pinned mac_timezone.py contract.
type macGetTimeServerFunc struct{}

func (macGetTimeServerFunc) Name() string        { return "timezone.get_time_server" }
func (macGetTimeServerFunc) Platforms() []string { return []string{"darwin"} }
func (macGetTimeServerFunc) Args() any           { return macGetTimeServerArgs{} }

// Execute ports mac_timezone.get_time_server (pinned revision lines
// 310-326): boundary guards first (architecture gate) — a wrong
// argument type or typed-nil pointer returns the fixed
// errMacGetterInvalidArgs before any dispatch, never a panic and never
// raw args formatted into the error — then exactly one fixed
// shell-free `/usr/sbin/systemsetup -getnetworktimeserver` dispatch
// through the shared closed enum query; the parsed server text (or ""
// for empty successful output) is returned with a nil value on every
// error, and every query failure maps to ErrMacSystemsetupQuery.
func (macGetTimeServerFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if a, ok := args.(*macGetTimeServerArgs); !ok || a == nil {
		return nil, errMacGetterInvalidArgs
	}
	value, err := macSystemsetupQuery(ctx, rt, macSystemsetupGetTimeServer)
	if err != nil {
		return nil, err
	}
	return value, nil
}

// macListZonesArgs is the zero-field Mac list_zones argument contract:
// docs/catalog/exec/mac_timezone.yaml declares list_zones with no
// parameters.
type macListZonesArgs struct{}

// macListZonesFunc implements timezone.list_zones for the pinned
// mac_timezone.py contract.
type macListZonesFunc struct{}

func (macListZonesFunc) Name() string { return "timezone.list_zones" }

// Platforms restricts the zone list to darwin; the Windows
// ZoneInfo/TzMapper timezone.list of PTD-EXEC-1632 is its own
// windows-only registration.
func (macListZonesFunc) Platforms() []string { return []string{"darwin"} }

func (macListZonesFunc) Args() any { return macListZonesArgs{} }

// Execute ports mac_timezone.list_zones (pinned revision lines 200-217)
// for the macOS variant (PTD-EXEC-1633 Mac partial): boundary guards
// first (architecture gate) — a wrong argument type or typed-nil
// pointer returns the fixed errMacGetterInvalidArgs before any
// dispatch, never a panic and never raw args formatted into the error
// — then exactly one fixed shell-free
// `/usr/sbin/systemsetup -listtimezones` dispatch through the shared
// closed enum query, the existing macSystemsetupQuery (the
// execute_return_result + parse_return analog); no second systemsetup
// invocation contract is added. Successful output is split on the
// exact Python str.splitlines() boundaries (LF, CR, CRLF as one
// boundary, VT, FF, U+001C..U+001E, NEL, LS, PS — U+001F is never a
// boundary) and each line is str.strip()ped on both ends
// (pythonSpace: unicode.IsSpace plus U+001C..U+001F); output order,
// duplicates, and interior empty values are preserved, a trailing
// boundary yields no trailing element, and empty successful output
// returns a nonnil empty []string. Every query failure maps to
// ErrMacSystemsetupQuery with a nil value; no raw cause, output,
// stderr, or exit status travels in any error and nothing is logged.
// Residual trust assumption: /usr/sbin and systemsetup are
// admin-controlled; binary authenticity is out of scope.
func (macListZonesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if a, ok := args.(*macListZonesArgs); !ok || a == nil {
		return nil, errMacGetterInvalidArgs
	}
	parsed, err := macSystemsetupQuery(ctx, rt, macSystemsetupListTimezones)
	if err != nil {
		return nil, err
	}
	zones := pythonSplitlines(parsed)
	out := make([]string, 0, len(zones))
	for _, zone := range zones {
		out = append(out, pythonStrip(zone))
	}
	return out, nil
}

// ErrMacDateTimeInvalid is the fixed, value-free invocation failure
// shared by the Mac date/time setters (the SaltInvocationError analog
// of mac_timezone._get_date_time_format): no format in the pinned
// ordered family parses the input, or a matched shape cannot
// construct a datetime (calendar validity, leap-second seconds, year
// range). It is distinct from ErrMacSystemsetupSet and from every
// other module sentinel; errors.Is matches only this sentinel, the
// raw input never travels in the error, and Python's message that
// embeds the input ("Invalid Date/Time Format: <input>") is
// deliberately not reproduced.
var ErrMacDateTimeInvalid = errors.New("macOS date/time format invalid")

// ErrMacSystemsetupSet is the fixed, value-free execution failure for
// the Mac systemsetup setters (the mac_utils.execute_return_success
// CommandExecutionError analog): the single set attempt could not be
// completed. It is distinct from ErrMacDateTimeInvalid,
// ErrMacSystemsetupQuery, and every other module sentinel; errors.Is
// matches only this sentinel and no raw cause, output, stderr, or
// exit status ever travels in the error.
var ErrMacSystemsetupSet = errors.New("macOS systemsetup set failed")

// errMacSetterInvalidArgs is the fixed, value-free invocation error
// for setter arguments that cannot be the contract at all (a wrong
// dynamic type or a typed-nil pointer); it never formats or echoes
// the raw args value or an underlying cause.
var errMacSetterInvalidArgs = errors.New("invalid timezone setter arguments")

// errMacSystemsetupUnknownSetter is the fixed, value-free internal
// rejection for a macSystemsetupSetter value outside the closed enum.
var errMacSystemsetupUnknownSetter = errors.New("unknown systemsetup setter")

// macASCIIDigit returns the numeric value of ASCII digit b, or -1 for
// any other byte. It backs only the ASCII-literal digit classes of
// the _strptime branches below (2[0-3], [0-1], [0-5], 6[0-1], 1[0-2],
// 0[1-9], [1-9], [01], and the space-prefixed " [1-9]"); the \d
// positions go through macDigitAt.
func macASCIIDigit(b byte) int {
	if b >= '0' && b <= '9' {
		return int(b - '0')
	}
	return -1
}

// macUnicodeDigit returns the decimal value of a Unicode Nd digit,
// mirroring the proven pythonDecimalDigit mapping of
// modules/exec/dig/dig.go over the same stdlib tables: every Nd
// range in the Unicode data is a contiguous run of exactly ten code
// points ordered by digit value and starting at the digit-zero code
// point, so the value is the offset within the run. No new
// dependency or vendored table is introduced.
func macUnicodeDigit(r rune) (int, bool) {
	if r >= '0' && r <= '9' {
		return int(r - '0'), true
	}
	table := unicode.Categories["Nd"]
	for _, rng := range table.R16 {
		if r >= rune(rng.Lo) && r <= rune(rng.Hi) {
			if rng.Stride != 1 {
				return 0, false
			}
			return int((uint32(r) - uint32(rng.Lo)) % 10), true
		}
	}
	for _, rng := range table.R32 {
		if uint32(r) >= rng.Lo && uint32(r) <= rng.Hi {
			if rng.Stride != 1 {
				return 0, false
			}
			return int((uint32(r) - uint32(rng.Lo)) % 10), true
		}
	}
	return 0, false
}

// macDigitAt decodes the rune at byte offset i of s and returns its
// Nd decimal value together with the rune's UTF-8 byte length — the
// CPython \d semantics of the _strptime branches, where any Unicode
// Nd decimal digit matches and int() converts it positionally.
// Invalid UTF-8 and every non-Nd rune answer ok=false, so such input
// fails closed.
func macDigitAt(s string, i int) (value, width int, ok bool) {
	if i < 0 || i >= len(s) {
		return 0, 0, false
	}
	r, size := utf8.DecodeRuneInString(s[i:])
	v, isDigit := macUnicodeDigit(r)
	if !isDigit {
		return 0, 0, false
	}
	return v, size, true
}

// macFieldAlt is one ordered alternative of a CPython _strptime
// numeric field regex: the field value it contributes and the number
// of input bytes it consumes.
type macFieldAlt struct {
	value int
	n     int
}

// macFieldAlternatives enumerates the ordered regex alternatives of
// one field at s[i:], transcribing the CPython _strptime base
// patterns exactly — hour 2[0-3]|[0-1]\d|\d, minute [0-5]\d|\d,
// second 6[0-1]|[0-5]\d|\d, month 1[0-2]|0[1-9]|[1-9], day
// 3[01]|[12]\d|0[1-9]|[1-9]| [1-9]. The \d positions — and only
// those — accept any Unicode Nd decimal digit exactly as CPython's
// Unicode \d does, consuming the rune's UTF-8 byte length, and the
// digits combine positionally like Python int() ("17:3４" is minute
// 34, "1/1٢/16" is day 12). The bracketed ASCII literals (2[0-3],
// [0-1], [0-5], 6[0-1], 1[0-2], 0[1-9], [1-9], [01], and the
// space-prefixed " [1-9]") match ASCII bytes only, so a fullwidth
// month or a two-rune fullwidth hour can enter through no literal
// branch and the single-\d alternative leaves the extra rune
// unconverted.
func macFieldAlternatives(s string, i int, field byte) []macFieldAlt {
	// lit decodes the ASCII-literal digit at byte offset i+k.
	lit := func(k int) int {
		if i+k < len(s) {
			return macASCIIDigit(s[i+k])
		}
		return -1
	}
	// uni decodes the Unicode Nd digit at byte offset i+k (a \d
	// position), returning its value and byte width.
	uni := func(k int) (int, int) {
		if v, w, ok := macDigitAt(s, i+k); ok {
			return v, w
		}
		return -1, 0
	}
	var alts []macFieldAlt
	add2 := func(d0, d1, w1 int) { alts = append(alts, macFieldAlt{value: d0*10 + d1, n: 1 + w1}) }
	switch field {
	case 'H': // 2[0-3]|[0-1]\d|\d
		if d0, d1 := lit(0), lit(1); d0 == 2 && d1 >= 0 && d1 <= 3 {
			add2(d0, d1, 1)
		}
		if d0 := lit(0); d0 == 0 || d0 == 1 {
			if d1, w1 := uni(1); d1 >= 0 {
				add2(d0, d1, w1)
			}
		}
		if d0, w0 := uni(0); d0 >= 0 {
			alts = append(alts, macFieldAlt{value: d0, n: w0})
		}
	case 'M': // [0-5]\d|\d
		if d0 := lit(0); d0 >= 0 && d0 <= 5 {
			if d1, w1 := uni(1); d1 >= 0 {
				add2(d0, d1, w1)
			}
		}
		if d0, w0 := uni(0); d0 >= 0 {
			alts = append(alts, macFieldAlt{value: d0, n: w0})
		}
	case 'S': // 6[0-1]|[0-5]\d|\d
		if d0, d1 := lit(0), lit(1); d0 == 6 && (d1 == 0 || d1 == 1) {
			add2(d0, d1, 1)
		}
		if d0 := lit(0); d0 >= 0 && d0 <= 5 {
			if d1, w1 := uni(1); d1 >= 0 {
				add2(d0, d1, w1)
			}
		}
		if d0, w0 := uni(0); d0 >= 0 {
			alts = append(alts, macFieldAlt{value: d0, n: w0})
		}
	case 'm': // 1[0-2]|0[1-9]|[1-9]
		if d0, d1 := lit(0), lit(1); d0 == 1 && d1 >= 0 && d1 <= 2 {
			add2(d0, d1, 1)
		}
		if d0, d1 := lit(0), lit(1); d0 == 0 && d1 >= 1 {
			add2(d0, d1, 1)
		}
		if d0 := lit(0); d0 >= 1 {
			alts = append(alts, macFieldAlt{value: d0, n: 1})
		}
	case 'd': // 3[01]|[12]\d|0[1-9]|[1-9]| [1-9]
		if d0, d1 := lit(0), lit(1); d0 == 3 && (d1 == 0 || d1 == 1) {
			add2(d0, d1, 1)
		}
		if d0 := lit(0); d0 == 1 || d0 == 2 {
			if d1, w1 := uni(1); d1 >= 0 {
				add2(d0, d1, w1)
			}
		}
		if d0, d1 := lit(0), lit(1); d0 == 0 && d1 >= 1 {
			add2(d0, d1, 1)
		}
		if d0 := lit(0); d0 >= 1 {
			alts = append(alts, macFieldAlt{value: d0, n: 1})
		}
		if i+1 < len(s) && s[i] == ' ' && macASCIIDigit(s[i+1]) >= 1 {
			// The " [1-9]" alternative _strptime keeps for %c
			// compatibility: the space is part of the match and
			// Python int() strips it.
			alts = append(alts, macFieldAlt{value: macASCIIDigit(s[i+1]), n: 2})
		}
	}
	return alts
}

// macMatchField selects the first alternative whose consumed length
// leaves exactly the expected next separator (or the end of the
// input when wantSep is zero), mirroring Python regex backtracking
// across the fixed single-separator patterns of the six-format
// family: no alternative can consume a separator byte — including
// the multi-byte Unicode Nd digits, whose UTF-8 encodings contain no
// ASCII bytes — so the one-character lookahead is the whole
// remainder constraint for the field and per-field ordered choice is
// equivalent to the engine's cross-field backtracking. next is the
// index after the separator (after the field itself when wantSep is
// zero).
func macMatchField(s string, i int, field, wantSep byte) (value, next int, ok bool) {
	for _, alt := range macFieldAlternatives(s, i, field) {
		j := i + alt.n
		if wantSep == 0 {
			if j == len(s) {
				return alt.value, j, true
			}
			continue
		}
		if j < len(s) && s[j] == wantSep {
			return alt.value, j + 1, true
		}
	}
	return 0, 0, false
}

// macMatchDigits consumes exactly n Unicode Nd digits (the \d\d of
// %y and \d\d\d\d of %Y), each contributing its UTF-8 byte length;
// value combines them positionally like Python int(), so mixed
// decimal scripts are accepted. Invalid UTF-8 fails like any
// non-digit.
func macMatchDigits(s string, i, n int) (value, next int, ok bool) {
	value = 0
	j := i
	for k := 0; k < n; k++ {
		d, w, isDigit := macDigitAt(s, j)
		if !isDigit {
			return 0, 0, false
		}
		value = value*10 + d
		j += w
	}
	return value, j, true
}

// macDaysInMonth answers the proleptic-Gregorian day count of month,
// the same calendar Python's datetime.date construction enforces
// (century years are leap only when divisible by 400).
func macDaysInMonth(year, month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	}
	if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
		return 29
	}
	return 28
}

// macDateTime is the datetime analog the setters dispatch from: the
// six components with the Python strptime defaults already applied —
// 1900-01-01 for time-only formats, midnight for date-only formats.
type macDateTime struct {
	year, month, day     int
	hour, minute, second int
}

// dateCanonical renders the set_date dispatch value: the exact
// strftime("%m:%d:%Y") of the parsed datetime. Years are always four
// zero-padded digits — deterministic in Go where CPython's strftime
// is platform-dependent below year 1000 (documented boundary; the
// family never produces years outside 1..9999).
func (dt macDateTime) dateCanonical() string {
	return fmt.Sprintf("%02d:%02d:%04d", dt.month, dt.day, dt.year)
}

// timeCanonical renders the set_time dispatch value: the exact
// strftime("%H:%M:%S") of the parsed datetime.
func (dt macDateTime) timeCanonical() string {
	return fmt.Sprintf("%02d:%02d:%02d", dt.hour, dt.minute, dt.second)
}

// macParseDateTime ports mac_timezone._get_date_time_format (pinned
// revision lines 42-60) together with the strptime construction both
// setters perform: the six ordered formats %H:%M, %H:%M:%S,
// %m:%d:%y, %m:%d:%Y, %m/%d/%y, and %m/%d/%Y are tried in order
// with first-success-wins; the input is
// never trimmed or normalized; and BOTH setters accept all six
// formats — cross-kind inputs are source behavior and keep Python's
// default components (a time-only input to set_date targets
// 1900-01-01, a date-only input to set_time targets midnight; the
// setters' docstrings understate the shared code). Construction
// mirrors CPython exactly: leap-second seconds 60/61 match the %S
// regex shape but fail time construction, so detection falls through
// to the date formats (12:31:60 => 2060-12-31, 12:31:61 =>
// 2061-12-31, while 12:31:59 succeeds as a time); two-digit years
// pivot 00-68 => 2000-2068 and 69-99 => 1969-1999; %Y is exactly
// four digits with year 0 out of datetime range; calendar validity
// is proleptic Gregorian; and any unconverted remainder rejects the
// format.
//
// Unicode semantics, nuanced per branch: CPython compiles the
// _strptime patterns with Unicode \d, so every \d position — the
// trailing digit of [0-1]\d, [0-5]\d, and [12]\d, every
// single-digit alternative, and the all-\d %y/%Y year fields —
// matches any Unicode Nd decimal digit, and int() converts such
// matches positionally ("１:３" parses as 01:03, "01/01/２０１６"
// as January 1st 2016, and mixed decimal scripts combine). The
// bracketed ASCII literals (2[0-3], [0-1], [0-5], 6[0-1], 1[0-2],
// 0[1-9], [1-9], [01], and the " [1-9]" day alternative) and the
// fixed separators stay ASCII exactly as written, so a fullwidth
// month ("２/1/16") or a two-rune fullwidth hour ("２３:01")
// matches nothing, and invalid UTF-8 fails closed like any
// non-digit. macUnicodeDigit reads Go's stdlib unicode tables, so
// Nd scripts newly assigned in later Unicode versions track the Go
// release rather than the CPython build's unicodedata — the one
// residual difference.
func macParseDateTime(s string) (macDateTime, bool) {
	// %H:%M
	if h, i, ok := macMatchField(s, 0, 'H', ':'); ok {
		if m, _, ok := macMatchField(s, i, 'M', 0); ok {
			return macDateTime{year: 1900, month: 1, day: 1, hour: h, minute: m}, true
		}
	}
	// %H:%M:%S — seconds 60/61 match the %S shape but fail time
	// construction, falling through to the date formats below.
	if h, i, ok := macMatchField(s, 0, 'H', ':'); ok {
		if m, j, ok := macMatchField(s, i, 'M', ':'); ok {
			if sec, _, ok := macMatchField(s, j, 'S', 0); ok && sec <= 59 {
				return macDateTime{year: 1900, month: 1, day: 1, hour: h, minute: m, second: sec}, true
			}
		}
	}
	// %m:%d:%y, %m:%d:%Y, %m/%d/%y, %m/%d/%Y — colon pair first,
	// preserving the pinned format order.
	for _, sep := range []byte{':', '/'} {
		if mo, i, ok := macMatchField(s, 0, 'm', sep); ok {
			if d, j, ok := macMatchField(s, i, 'd', sep); ok {
				if yy, end, ok := macMatchDigits(s, j, 2); ok && end == len(s) {
					year := 2000 + yy
					if yy > 68 {
						year = 1900 + yy
					}
					if d <= macDaysInMonth(year, mo) {
						return macDateTime{year: year, month: mo, day: d}, true
					}
				}
				if yyyy, end, ok := macMatchDigits(s, j, 4); ok && end == len(s) && yyyy >= 1 {
					if d <= macDaysInMonth(yyyy, mo) {
						return macDateTime{year: yyyy, month: mo, day: d}, true
					}
				}
			}
		}
	}
	return macDateTime{}, false
}

// macSystemsetupSetter is the private closed selector for the three
// systemsetup mutations the module may run (PTD-EXEC-1634/1635/1637).
// Values never come from user input: each maps to exactly one fixed
// argv flag, and any other value is rejected before the Runner is
// touched — arbitrary argv, zone flags, and every read-only getter
// flag are inexpressible through it. The read-only
// macSystemsetupGetter enum is untouched by this type: its
// historically invalid value 4 remains invalid and no getter flag is
// a setter flag.
type macSystemsetupSetter int

const (
	macSystemsetupSetDate macSystemsetupSetter = iota
	macSystemsetupSetTime
	macSystemsetupSetUsingNetworkTime
)

// flag returns one of the closed flags -setdate, -settime, or
// -setusingnetworktime; the latter takes the canonical on/off operand.
// Unknown enum values are rejected.
func (s macSystemsetupSetter) flag() (string, error) {
	switch s {
	case macSystemsetupSetDate:
		return "-setdate", nil
	case macSystemsetupSetTime:
		return "-settime", nil
	case macSystemsetupSetUsingNetworkTime:
		return "-setusingnetworktime", nil
	}
	return "", errMacSystemsetupUnknownSetter
}

// Fixed Mac setter invocation controls (mirroring the getter
// contract): the absolute admin-controlled systemsetup path (no PATH
// lookup, no sudo, no elevation change), exactly two argv entries
// (the fixed setter flag and canonical operand), a
// locale-only child environment, a bounded wall clock, and equal
// 64 KiB capture ceilings per stream.
const (
	macSetterSystemsetup = "/usr/sbin/systemsetup"
	macSetterTimeout     = 30 * time.Second
	macSetterStreamMax   = 64 << 10
)

// macSystemsetupSet runs the one fixed shell-free systemsetup
// mutation selected by the closed enum (pinned mac_timezone.py
// set_date lines 77-104 / set_time lines 124-148 /
// set_using_network_time lines 284-307 through
// mac_utils.execute_return_success): an unknown enum value is
// rejected before the Runner, a nil Runtime or Runner fails fixed
// with ErrMacSystemsetupSet, and exactly one dispatch happens with
// the canonical setter operand — never the raw user value — as the
// only variable. Any Runner error, nonzero exit, truncation flag, or
// over-cap stream, and any rstripped stdout containing
// case-insensitive "not supported" (the execute_return_success gate;
// a marker on stderr alone never fails), returns the single fixed
// value-free ErrMacSystemsetupSet; no raw cause, output, stderr, or
// exit status travels in the error and nothing is logged. After any
// post-dispatch failure the requested system state is unknown: no retry,
// readback, rollback, or follow-up is attempted. Residual trust
// assumption: /usr/sbin and systemsetup are admin-controlled;
// binary authenticity is out of scope.
func macSystemsetupSet(ctx context.Context, rt *runtime.Runtime, setter macSystemsetupSetter, canonical string) error {
	flag, err := setter.flag()
	if err != nil {
		return err
	}
	if rt == nil || rt.Runner == nil {
		return ErrMacSystemsetupSet
	}
	res := rt.Runner.Run(ctx, process.Command{
		Name:           macSetterSystemsetup,
		Args:           []string{flag, canonical},
		Env:            []string{"LC_ALL=C"},
		Timeout:        macSetterTimeout,
		MaxStdoutBytes: macSetterStreamMax,
		MaxStderrBytes: macSetterStreamMax,
	})
	if res.Err != nil || res.ExitCode != 0 ||
		res.StdoutTruncated || res.StderrTruncated ||
		len(res.Stdout) > macSetterStreamMax || len(res.Stderr) > macSetterStreamMax {
		return ErrMacSystemsetupSet
	}
	if strings.Contains(strings.ToLower(pythonRStrip(string(res.Stdout))), "not supported") {
		return ErrMacSystemsetupSet
	}
	return nil
}

// macSetDateArgs is the Mac set_date argument contract: exactly one
// required *string date (docs/catalog/exec/mac_timezone.yaml declares
// set_date(date) with no default). The required POINTER makes a
// missing argument (nil, rejected by the required gate before any
// dispatch) distinguishable from an explicit empty string (nonnil,
// gate passes, rejected by the format family with the fixed invalid
// sentinel and zero dispatch).
type macSetDateArgs struct {
	Date *string `statekit:"required,name=date"`
}

// macSetTimeArgs is the Mac set_time argument contract: exactly one
// required *string time (docs/catalog/exec/mac_timezone.yaml declares
// set_time(time) with no default), with the same missing-vs-explicit
// distinction as macSetDateArgs.
type macSetTimeArgs struct {
	Time *string `statekit:"required,name=time"`
}

// macSetDateFunc implements timezone.set_date for the pinned
// mac_timezone.py contract.
type macSetDateFunc struct{}

func (macSetDateFunc) Name() string        { return "timezone.set_date" }
func (macSetDateFunc) Platforms() []string { return []string{"darwin"} }
func (macSetDateFunc) Args() any           { return macSetDateArgs{} }

// Execute ports mac_timezone.set_date (pinned revision lines 77-104):
// boundary guards first (architecture gate) — a wrong argument type
// or typed-nil pointer returns the fixed errMacSetterInvalidArgs
// before any dispatch, never a panic and never raw args formatted
// into the error, and a nonnil struct with a nil Date reuses the
// decoder's fixed missing-required error. The shared parser family
// then validates the input completely (format shape, calendar, year
// range) BEFORE the single dispatch, so every invalid input makes
// zero Runner calls; both setters accept all six pinned formats, and
// a time-only input canonically targets 1900-01-01 (preserved
// cross-kind source behavior). A valid input dispatches exactly one
// fixed shell-free `/usr/sbin/systemsetup -setdate <canonical>` whose
// only variable is the canonical %m:%d:%Y parser rendering — never
// the raw user string — and success answers true. The two failure
// categories are fixed, value-free, and distinct:
// ErrMacDateTimeInvalid for invalid inputs and ErrMacSystemsetupSet
// for execution failures. If an execution error occurs after
// dispatch the system clock state is unknown; no retry, readback,
// rollback, or follow-up happens.
func (macSetDateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*macSetDateArgs)
	if !ok || a == nil {
		return nil, errMacSetterInvalidArgs
	}
	if a.Date == nil {
		// Registry gate parity: a direct caller bypassing the
		// decoder sees the same fixed missing-required failure; the
		// defensive fallback keeps a future tag change from
		// re-opening a nil dereference.
		if err := config.ValidateRequired(a); err != nil {
			return nil, err
		}
		return nil, errMacSetterInvalidArgs
	}
	dt, ok := macParseDateTime(*a.Date)
	if !ok {
		return nil, ErrMacDateTimeInvalid
	}
	if err := macSystemsetupSet(ctx, rt, macSystemsetupSetDate, dt.dateCanonical()); err != nil {
		return nil, err
	}
	return true, nil
}

// macSetTimeFunc implements timezone.set_time for the pinned
// mac_timezone.py contract.
type macSetTimeFunc struct{}

func (macSetTimeFunc) Name() string        { return "timezone.set_time" }
func (macSetTimeFunc) Platforms() []string { return []string{"darwin"} }
func (macSetTimeFunc) Args() any           { return macSetTimeArgs{} }

// Execute ports mac_timezone.set_time (pinned revision lines
// 124-148) with the same boundary-guard, validate-before-dispatch,
// and fixed-failure contracts as macSetDateFunc.Execute: a wrong
// argument type or typed-nil pointer returns the fixed
// errMacSetterInvalidArgs before any dispatch, a nonnil struct with
// a nil Time reuses the decoder's fixed missing-required error, the
// shared parser family validates completely before the single
// dispatch (invalid input => zero Runner calls; both setters accept
// all six pinned formats, a date-only input canonically targets
// midnight — preserved cross-kind source behavior), and a valid
// input dispatches exactly one fixed shell-free
// `/usr/sbin/systemsetup -settime <canonical>` whose only variable
// is the canonical %H:%M:%S parser rendering. Success answers true;
// failures use the distinct fixed value-free ErrMacDateTimeInvalid
// and ErrMacSystemsetupSet; an execution error after dispatch leaves
// the system clock state unknown with no retry, readback, rollback,
// or follow-up.
func (macSetTimeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*macSetTimeArgs)
	if !ok || a == nil {
		return nil, errMacSetterInvalidArgs
	}
	if a.Time == nil {
		// Registry gate parity, as in macSetDateFunc.Execute.
		if err := config.ValidateRequired(a); err != nil {
			return nil, err
		}
		return nil, errMacSetterInvalidArgs
	}
	dt, ok := macParseDateTime(*a.Time)
	if !ok {
		return nil, ErrMacDateTimeInvalid
	}
	if err := macSystemsetupSet(ctx, rt, macSystemsetupSetTime, dt.timeCanonical()); err != nil {
		return nil, err
	}
	return true, nil
}

// macSetUsingNetworkTimeArgs is the Mac set_using_network_time
// argument contract: one required union-valued enable argument. The
// empty interface preserves decoder-supported Python truthiness inputs;
// because the interface itself is nonnil when it contains bool(false),
// false still passes the required gate. Omitted and structured-null
// inputs leave the interface nil and fail that gate before Execute.
type macSetUsingNetworkTimeArgs struct {
	Enable any `statekit:"required,name=enable"`
}

// macNetworkTimeEnabled ports mac_utils.validate_enabled for the setter:
// strings accept only exact case-insensitive on/off/yes/no tokens (never
// trimmed), while decoder-supported non-string booleans, numbers, arrays,
// slices, and maps use Python-compatible truthiness. Unsupported direct
// Go values fail with the fixed setter-arguments sentinel rather than
// invoking arbitrary methods or panicking.
func macNetworkTimeEnabled(value any) (bool, error) {
	if value == nil {
		return false, errMacSetterInvalidArgs
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.String:
		return macValidateEnabled(v.String())
	case reflect.Bool:
		return v.Bool(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() != 0, nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() != 0, nil
	case reflect.Float32, reflect.Float64:
		// NaN compares unequal to zero, matching Python's truthy float.
		return v.Float() != 0, nil
	case reflect.Complex64, reflect.Complex128:
		return v.Complex() != 0, nil
	case reflect.Array, reflect.Slice, reflect.Map:
		return v.Len() != 0, nil
	default:
		return false, errMacSetterInvalidArgs
	}
}

// macSetUsingNetworkTimeFunc implements timezone.set_using_network_time
// for mac_timezone.py (pinned revision lines 284-307).
type macSetUsingNetworkTimeFunc struct{}

func (macSetUsingNetworkTimeFunc) Name() string        { return "timezone.set_using_network_time" }
func (macSetUsingNetworkTimeFunc) Platforms() []string { return []string{"darwin"} }
func (macSetUsingNetworkTimeFunc) Args() any           { return macSetUsingNetworkTimeArgs{} }

// Execute validates enable before dispatch and maps only canonical on/off
// values to one shell-free systemsetup setter attempt. A failed attempt
// returns the fixed setter error and suppresses readback. Only a
// successful attempt is followed by exactly one existing
// get_using_network_time query; the result is whether that state equals
// the requested boolean, so a mismatch is false despite a possible host
// mutation. Getter errors remain visible as their existing fixed query
// or invalid-state errors. No retry, rollback, or additional mutation is
// attempted, and no claim is made that the host remains unchanged after
// dispatch.
func (macSetUsingNetworkTimeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*macSetUsingNetworkTimeArgs)
	if !ok || a == nil || a.Enable == nil {
		return nil, errMacSetterInvalidArgs
	}
	enabled, err := macNetworkTimeEnabled(a.Enable)
	if err != nil {
		return nil, err
	}
	canonical := "off"
	if enabled {
		canonical = "on"
	}
	if err := macSystemsetupSet(ctx, rt, macSystemsetupSetUsingNetworkTime, canonical); err != nil {
		return nil, err
	}
	actual, err := (macGetUsingNetworkTimeFunc{}).Execute(ctx, rt, &macGetUsingNetworkTimeArgs{})
	if err != nil {
		return nil, err
	}
	actualEnabled, ok := actual.(bool)
	if !ok {
		return nil, ErrMacNetworkTimeStateInvalid
	}
	return enabled == actualEnabled, nil
}

// winZoneCompareArgs is the win_timezone.zone_compare argument
// contract: one required *string timezone (docs/catalog/exec/
// win_timezone.yaml declares zone_compare(timezone) with no default).
// The required POINTER (WZC-BACKEND-01) makes a missing argument (nil,
// rejected by the required-Args gate before the function runs)
// distinguishable from an explicit empty string (nonnil, gate passes,
// rejected by Execute's name gate with the invalid-zone sentinel).
type winZoneCompareArgs struct {
	TimeZone *string `statekit:"required,name=timezone"`
}

// winZoneCompareFunc implements timezone.zone_compare for the pinned
// win_timezone.py contract (lines 305-337): the requested name is
// resolved case-insensitively in the 134-pair table (Windows or IANA
// form, never trimmed), the current zone is queried with exactly one
// shell-free `tzutil.exe /g` from the API-derived system directory,
// and the answer compares the two canonical IANA names; an unknown
// nonempty current zone answers false.
type winZoneCompareFunc struct{}

func (winZoneCompareFunc) Name() string { return "timezone.zone_compare" }

// Platforms restricts the windows variant to windows; the Linux, mac,
// Solaris, and AIX rows of PTD-EXEC-1638 stay tracked separately.
func (winZoneCompareFunc) Platforms() []string { return []string{"windows"} }

func (winZoneCompareFunc) Args() any { return winZoneCompareArgs{} }

// Execute ports win_timezone.zone_compare for the Windows variant
// (PTD-EXEC-1638 Windows partial). Boundary guards first: a wrong
// argument type or typed-nil argument returns the fixed value-free
// ErrInvalidWindowsZone, and a nonnil struct with a nil timezone
// pointer reuses the decoder's fixed missing-required error — both
// before any dereference, resolver work, Lstat precheck, or dispatch
// (WZC-BACKEND-01). The requested-name gate then runs strictly first
// once the pointer is nonnil: an explicit empty string or any nonempty
// name without a case-insensitive match in the pinned 134-pair table
// (input never trimmed or normalized) returns only the fixed
// value-free ErrInvalidWindowsZone before any resolver work, Lstat
// precheck, or dispatch. Every query/execution failure — resolver API
// error, malformed system tree, precheck failure, Runner error, nonzero
// exit, cancellation/deadline, truncation, over-cap, or an
// empty-after-rstrip current-zone answer — returns only the fixed
// value-free ErrCannotDetermineZone with zero retry. A successful
// query rstrips Python-trailing whitespace from stdout, lowercases,
// strips exactly one terminal _dstoff, and answers whether the
// current zone maps to the same canonical IANA name as the request;
// an unknown nonempty current zone answers false.
func (winZoneCompareFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*winZoneCompareArgs)
	if !ok || a == nil {
		return nil, ErrInvalidWindowsZone
	}
	if a.TimeZone == nil {
		// Registry gate parity: a direct caller bypassing the decoder
		// sees the same fixed missing-required failure; the defensive
		// fallback keeps a future tag change from re-opening a nil
		// dereference.
		if err := config.ValidateRequired(a); err != nil {
			return nil, err
		}
		return nil, ErrInvalidWindowsZone
	}
	// Requested-name gate, strictly before any resolver API call,
	// Lstat precheck, or dispatch (WZC-01): the input is matched
	// case-insensitively in the 134-pair table without trimming or
	// normalization, so an explicit empty or unlisted name fails with
	// only the invalid-zone sentinel and zero work.
	canonical, ok := winZoneCanonicalUnix(*a.TimeZone)
	if !ok {
		return nil, ErrInvalidWindowsZone
	}
	if rt == nil || rt.Runner == nil || rt.FS == nil {
		return nil, ErrCannotDetermineZone
	}
	sysdir, windir, err := winSystemTree()
	if err != nil || !validateWindowsSystemTree(sysdir, windir) {
		return nil, ErrCannotDetermineZone
	}
	// Exact-executable precheck immediately before dispatch (WZC-09):
	// Go still consults the parent PATHEXT even for an absolute
	// executable name, so the exact regular non-reparse file must be
	// present at that instant or nothing dispatches. This defeats
	// PATHEXT suffix fallback only under the stable
	// administrator-controlled-system-tree assumption (no
	// unprivileged replacement); the TOCTOU window between this Lstat
	// and process start remains and is accepted as documented — no
	// unconditional exact-exec claim is made.
	exe := sysdir + `\` + winZoneExeName
	info, err := rt.FS.Lstat(exe)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrCannotDetermineZone
	}
	res := rt.Runner.Run(ctx, process.Command{
		Name:           exe,
		Args:           []string{"/g"},
		Dir:            sysdir,
		Env:            []string{"SYSTEMROOT=" + windir, "WINDIR=" + windir},
		Timeout:        winZoneTimeout,
		MaxStdoutBytes: winZoneStreamMax,
		MaxStderrBytes: winZoneStreamMax,
	})
	if res.Err != nil || res.ExitCode != 0 ||
		res.StdoutTruncated || res.StderrTruncated ||
		len(res.Stdout) > winZoneStreamMax || len(res.Stderr) > winZoneStreamMax {
		return nil, ErrCannotDetermineZone
	}
	// Output processing ports the pinned get_zone (lines 197-223):
	// Python str.rstrip trailing whitespace (leading preserved),
	// lowercase, then exactly one terminal _dstoff strip. An
	// empty-after-rstrip answer is an execution failure, and an
	// unlisted nonempty answer is the mapper's "Unknown" default —
	// unequal to any canonical name, so the comparison answers false.
	current := strings.ToLower(pythonRStrip(string(res.Stdout)))
	if current == "" {
		return nil, ErrCannotDetermineZone
	}
	current = strings.TrimSuffix(current, "_dstoff")
	currentUnix, ok := winZoneToUnix[current]
	if !ok {
		return false, nil
	}
	return currentUnix == canonical, nil
}

// winSystemTree resolves the machine system tree through the platform
// resolver: GetSystemDirectory plus machine-wide
// GetSystemWindowsDirectory on windows, a fail-closed stub anywhere
// else. The var is the injection seam for hermetic tests faking the OS
// path API; production code never mutates it.
var winSystemTree = defaultWinSystemTree

// winZone invocation controls (WZC-11/WZC-13): one shell-free tzutil
// dispatch with a 30s cancellation deadline (not a strict end-to-end
// cap: the Runner's WaitDelay grace extends past it) and equal 64 KiB
// capture ceilings per stream.
const (
	winZoneTimeout   = 30 * time.Second
	winZoneStreamMax = 64 << 10
)

// winZoneExeName is the only executable this variant may dispatch.
const winZoneExeName = "tzutil.exe"

// isASCIILetter reports whether b is an ASCII drive-letter byte.
func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// validWindowsDrivePath reports whether p is an absolute, lexically
// clean local drive path: an ASCII drive letter, `:\`, then nonempty
// backslash-separated components free of ".", "..", colons (NTFS
// alternate data streams), and control characters, with no forward
// slashes, repeated separators, or trailing separator. Volume roots
// (`C:\`), UNC/device/extended-length prefixes, drive-relative
// (`C:x`), root-relative (`\x`), and relative forms are rejected.
func validWindowsDrivePath(p string) bool {
	if len(p) < 4 || !isASCIILetter(p[0]) || p[1] != ':' || p[2] != '\\' {
		return false
	}
	rest := p[3:]
	if strings.ContainsRune(rest, '/') || rest == "" {
		return false
	}
	for _, comp := range strings.Split(rest, `\`) {
		if comp == "" || comp == "." || comp == ".." {
			return false
		}
		for i := 0; i < len(comp); i++ {
			if comp[i] < 0x20 || comp[i] == ':' {
				return false
			}
		}
	}
	return true
}

// validateWindowsSystemTree enforces the WZC-07/WZC-08 resolver
// contract: both API answers must be absolute, lexically clean local
// drive paths, and the system directory must be exactly the
// case-insensitive System32/SysWOW64 immediate child of the
// machine-wide windows directory — rejecting UNC, device,
// extended-length, drive-relative, root-relative, traversal, sibling,
// deeper, ADS, and control-character answers. Malformed results fail
// closed at the caller with ErrCannotDetermineZone.
func validateWindowsSystemTree(sysdir, windir string) bool {
	if !validWindowsDrivePath(sysdir) || !validWindowsDrivePath(windir) {
		return false
	}
	sep := strings.LastIndexByte(sysdir, '\\')
	child := sysdir[sep+1:]
	if !strings.EqualFold(child, "System32") && !strings.EqualFold(child, "SysWOW64") {
		return false
	}
	return strings.EqualFold(sysdir, windir+`\`+child)
}

// winZoneListArgs is the win_timezone.list argument contract: exactly
// one optional tri-state unix_style pointer (docs/catalog/exec/
// win_timezone.yaml declares list(unix_style) with default "True").
// A nil pointer — the key omitted entirely — selects the pinned source
// default true; an explicit nonnil pointer follows the caller. The
// field is deliberately NOT required: an omitted argument is valid.
//
// Structured null is not nil: config.Decode's *bool branch has no null
// early-out (only *[]string clears on null), so unix_style:null fails
// fixed decoder validation before this function can run — a safe,
// documented divergence from Salt, where Python's falsey None would
// select the Windows list.
type winZoneListArgs struct {
	UnixStyle *bool `statekit:"name=unix_style"`
}

// winZoneListFunc implements timezone.list for the pinned
// win_timezone.py contract (lines 340-372 over the TzMapper dicts of
// lines 21-43): a static, read-only enumeration of the pinned
// 134-pair table — mapper.list_unix() (sorted Windows->IANA dict
// values) for true/omitted unix_style, mapper.list_win() (sorted
// IANA->Windows dict values) for false.
type winZoneListFunc struct{}

func (winZoneListFunc) Name() string { return "timezone.list" }

// Platforms restricts the list variant to windows, matching the
// win_timezone.py source module this contract is transcribed from
// (PTD-EXEC-1632 Windows partial; other platform variants stay open
// rows).
func (winZoneListFunc) Platforms() []string { return []string{"windows"} }

func (winZoneListFunc) Args() any { return winZoneListArgs{} }

// errWinZoneListInvalidArgs is the fixed, value-free invocation error
// for list arguments that cannot be the contract at all (a wrong
// dynamic type or a typed-nil pointer); it never formats or echoes
// the raw args value or an underlying cause.
var errWinZoneListInvalidArgs = errors.New("invalid timezone list arguments")

// Execute ports win_timezone.list (pinned revision lines 340-372) for
// the Windows variant (PTD-EXEC-1632 Windows partial). Boundary guard
// first (architecture gate): a wrong argument type or typed-nil
// argument returns the fixed value-free errWinZoneListInvalidArgs —
// never a panic, never raw args formatted into the error. The answer
// is static table output: nil/unix_style-omitted and explicit true
// return the sorted values of the Windows->IANA dict (the IANA list),
// explicit false the sorted values of the IANA->Windows dict (the
// Windows list), exactly like the pinned mapper.list_unix/list_win —
// original spelling preserved, source dict-value duplicates preserved
// as the dict semantics dictate (the pinned table has none). A fresh
// []string is allocated per call and the shared lookup maps are never
// mutated. The catalogued dependencies (cmd.run_all, path.which,
// platform.is_windows) are not exercised: there is no Runner,
// filesystem, registry, network, or tzutil access on any path — the
// Runtime argument is unused and may be nil.
func (winZoneListFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*winZoneListArgs)
	if !ok || a == nil {
		return nil, errWinZoneListInvalidArgs
	}
	// Pinned list() branch: truthy (true or the omitted default) takes
	// mapper.list_unix() — sorted(win_to_unix.values()) — and false
	// takes mapper.list_win() — sorted(unix_to_win.values()). The Go
	// dicts are the tested transcription of exactly those dicts, so
	// their VALUES (original spelling, duplicates as the dict
	// semantics dictate) are enumerated fresh into a per-call slice,
	// sorted, and returned; the shared maps are never written.
	dict := unixZoneToWin
	if a.UnixStyle == nil || *a.UnixStyle {
		dict = winZoneToUnix
	}
	out := make([]string, 0, len(dict))
	for _, name := range dict {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// getZonecodeArgs is the zero-field Linux get_zonecode argument
// contract: docs/catalog/exec/timezone.yaml declares get_zonecode with
// no parameters.
type getZonecodeArgs struct{}

// ErrZonecodeQuery is the fixed, value-free execution failure for the
// Linux generic get_zonecode: the `date +%Z` query could not be
// completed. errors.Is matches only this sentinel; no raw cause,
// output, stderr, or exit status ever travels in the error and
// nothing is logged.
var ErrZonecodeQuery = errors.New("timezone zonecode query failed")

// errZonecodeInvalidArgs is the fixed, value-free invocation error for
// get_zonecode arguments that cannot be the contract at all (a wrong
// dynamic type or a typed-nil pointer); it never formats or echoes
// the raw args value or an underlying cause.
var errZonecodeInvalidArgs = errors.New("invalid timezone zonecode arguments")

type getZonecodeFunc struct{}

func (getZonecodeFunc) Name() string { return "timezone.get_zonecode" }

// Platforms restricts get_zonecode to linux: the reviewed contract is
// the Linux generic slice of the pinned timezone.py only (the mac
// `date` variant is its own darwin-only macZonecodeFunc registration;
// the Windows ZoneInfo/TzMapper variant stays an open row).
func (getZonecodeFunc) Platforms() []string { return []string{"linux"} }

func (getZonecodeFunc) Args() any { return getZonecodeArgs{} }

// Fixed get_zonecode invocation controls shared by the Linux generic
// and Mac variants: one shell-free date dispatch whose executable name
// is resolved by the Runner through the parent PATH (explicitly
// authorized by the user for exactly this read-only fixed call —
// caller/deployment trust, no binary identity verification and no
// TrustedCommandResolver entry), the fixed root working directory, a
// bounded wall clock, and equal 64 KiB capture ceilings per stream.
const (
	zonecodeTimeout   = 30 * time.Second
	zonecodeStreamMax = 64 << 10
	zonecodeDir       = "/"
)

// Execute ports timezone.get_zonecode (pinned revision lines 222-232)
// for the Linux generic contract: exactly one fixed shell-free
// `date +%Z` dispatch. Boundary guards first (architecture gate): a
// wrong argument type or typed-nil pointer returns the fixed
// errZonecodeInvalidArgs before any dispatch, and a nil Runtime or
// Runner fails fixed with ErrZonecodeQuery — never a panic. The child
// environment is exactly LC_ALL=C plus the caller's TZ only when
// os.LookupEnv reports it set (a set-but-empty TZ forwards as `TZ=`);
// nothing else is inherited, TZDIR is never set, and there is no user
// input anywhere in the command. Documented fail-closed divergence
// from Salt's cmd.run: any Runner error, nonzero exit, truncation
// flag, over-cap stream, cancellation, or deadline returns only the
// fixed value-free ErrZonecodeQuery with a nil value and no wrapped
// cause — Salt returns stdout even on nonzero and merges stderr,
// StateKit fails closed and drops stderr. Successful output is
// trailing-rstripped exactly like cmd.run (Python str.rstrip through
// the shared pythonRStrip); leading whitespace, numeric offsets, the
// empty value, and any abbreviation text pass through with no
// normalization or validation.
func (getZonecodeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if a, ok := args.(*getZonecodeArgs); !ok || a == nil {
		return nil, errZonecodeInvalidArgs
	}
	if rt == nil || rt.Runner == nil {
		return nil, ErrZonecodeQuery
	}
	env := []string{"LC_ALL=C"}
	if tz, ok := os.LookupEnv("TZ"); ok {
		env = append(env, "TZ="+tz)
	}
	res := rt.Runner.Run(ctx, process.Command{
		Name:           "date",
		Args:           []string{"+%Z"},
		Dir:            zonecodeDir,
		Env:            env,
		Timeout:        zonecodeTimeout,
		MaxStdoutBytes: zonecodeStreamMax,
		MaxStderrBytes: zonecodeStreamMax,
	})
	if res.Err != nil || res.ExitCode != 0 ||
		res.StdoutTruncated || res.StderrTruncated ||
		len(res.Stdout) > zonecodeStreamMax || len(res.Stderr) > zonecodeStreamMax {
		return nil, ErrZonecodeQuery
	}
	return pythonRStrip(string(res.Stdout)), nil
}

// macZonecodeArgs is the zero-field Mac get_zonecode argument
// contract: docs/catalog/exec/mac_timezone.yaml declares get_zonecode
// with no parameters.
type macZonecodeArgs struct{}

// ErrMacZoneCodeQuery is the fixed, value-free execution failure for
// the Mac get_zonecode: the `date +%Z` query could not be completed.
// It is distinct from the Linux ErrZonecodeQuery and from every other
// module sentinel; errors.Is matches only this sentinel and no raw
// cause, output, stderr, or exit status ever travels in the error.
var ErrMacZoneCodeQuery = errors.New("macOS zonecode query failed")

// errMacZonecodeInvalidArgs is the fixed, value-free invocation error
// for Mac get_zonecode arguments that cannot be the contract at all
// (a wrong dynamic type or a typed-nil pointer); it never formats or
// echoes the raw args value or an underlying cause.
var errMacZonecodeInvalidArgs = errors.New("invalid macOS zonecode arguments")

// macZonecodeFunc implements timezone.get_zonecode for the pinned
// mac_timezone.py contract.
type macZonecodeFunc struct{}

func (macZonecodeFunc) Name() string { return "timezone.get_zonecode" }

// Platforms restricts the mac variant to darwin; the Windows
// ZoneInfo/TzMapper variant and the other GOOS rows of PTD-EXEC-1631
// stay open.
func (macZonecodeFunc) Platforms() []string { return []string{"darwin"} }

func (macZonecodeFunc) Args() any { return macZonecodeArgs{} }

// Execute ports mac_timezone.get_zonecode (pinned revision lines
// 168-182: `return mac_utils.execute_return_result("date +%Z")` with
// NO parse_return) for the macOS variant (PTD-EXEC-1631 Mac partial):
// exactly one fixed shell-free `date +%Z` dispatch whose executable
// name resolves through the Runner and the parent PATH per the user's
// caller-PATH authorization for exactly this read-only query (no
// resolver, no identity check — caller/deployment trust). Boundary
// guards first (architecture gate): a wrong argument type or typed-nil
// pointer returns the fixed errMacZonecodeInvalidArgs before any
// dispatch, and a nil Runtime or Runner fails fixed with
// ErrMacZoneCodeQuery — never a panic. The child environment is
// exactly LC_ALL=C plus the caller's TZ only when os.LookupEnv
// reports it set (a set-but-empty TZ forwards as `TZ=`); nothing else
// is inherited, TZDIR is never set, and there is no user input
// anywhere in the command. Documented fail-closed divergences from
// Salt's mac_utils._run_all: any Runner error, nonzero exit,
// truncation flag, over-cap stream, cancellation, or deadline returns
// only the fixed value-free ErrMacZoneCodeQuery with a nil value and
// no wrapped cause — Salt raises CommandExecutionError with the full
// command, output, and stderr in the message, runs through the
// DEFAULT_SHELL, inherits the whole os.environ, and sets no timeout.
// Mirroring execute_return_result exactly: any rstripped stdout
// containing case-insensitive "not supported" fails with the same
// single sentinel (a marker on stderr alone never fails), and success
// returns the raw Python-rstripped stdout with no parse_return —
// leading whitespace, numeric offsets, the empty value, and any
// abbreviation text pass through with no normalization or validation.
func (macZonecodeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if a, ok := args.(*macZonecodeArgs); !ok || a == nil {
		return nil, errMacZonecodeInvalidArgs
	}
	if rt == nil || rt.Runner == nil {
		return nil, ErrMacZoneCodeQuery
	}
	env := []string{"LC_ALL=C"}
	if tz, ok := os.LookupEnv("TZ"); ok {
		env = append(env, "TZ="+tz)
	}
	res := rt.Runner.Run(ctx, process.Command{
		Name:           "date",
		Args:           []string{"+%Z"},
		Dir:            zonecodeDir,
		Env:            env,
		Timeout:        zonecodeTimeout,
		MaxStdoutBytes: zonecodeStreamMax,
		MaxStderrBytes: zonecodeStreamMax,
	})
	if res.Err != nil || res.ExitCode != 0 ||
		res.StdoutTruncated || res.StderrTruncated ||
		len(res.Stdout) > zonecodeStreamMax || len(res.Stderr) > zonecodeStreamMax {
		return nil, ErrMacZoneCodeQuery
	}
	stdout := pythonRStrip(string(res.Stdout))
	if strings.Contains(strings.ToLower(stdout), "not supported") {
		return nil, ErrMacZoneCodeQuery
	}
	return stdout, nil
}

type getZoneFunc struct{}

func (getZoneFunc) Name() string { return "timezone.get_zone" }
func (getZoneFunc) Args() any    { return getZoneArgs{} }
func (getZoneFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	if data, err := rt.FS.ReadFile(timezoneFile); err == nil {
		return strings.TrimSpace(string(data)), nil
	}
	target, err := rt.FS.Readlink(localtimePath)
	if err != nil {
		return nil, fmt.Errorf("could not determine timezone: %w", err)
	}
	return strings.TrimPrefix(target, zoneinfoPrefix), nil
}

type setZoneArgs struct {
	TimeZone string `statekit:"required,name=time_zone"`
}

type setZoneFunc struct{}

func (setZoneFunc) Name() string { return "timezone.set_zone" }
func (setZoneFunc) Args() any    { return setZoneArgs{} }
func (setZoneFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*setZoneArgs)
	zone := strings.TrimPrefix(a.TimeZone, zoneinfoPrefix)
	source := zoneinfoPrefix + zone
	if _, err := rt.FS.Stat(source); err != nil {
		return nil, fmt.Errorf("unknown time zone %q", zone)
	}
	mode := fs.FileMode(0o644)
	if info, err := rt.FS.Stat(timezoneFile); err == nil {
		mode = info.Mode().Perm()
	}
	rt.FS.Remove(localtimePath)
	if err := rt.FS.Symlink(source, localtimePath); err != nil {
		return nil, err
	}
	if err := rt.FS.WriteFile(timezoneFile, []byte(zone+"\n"), mode); err != nil {
		return nil, err
	}
	return true, nil
}

type getOffsetArgs struct{}

type getOffsetFunc struct{}

func (getOffsetFunc) Name() string { return "timezone.get_offset" }
func (getOffsetFunc) Args() any    { return getOffsetArgs{} }
func (getOffsetFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return time.Now().Format("-0700"), nil
}

type getHwclockArgs struct{}

type getHwclockFunc struct{}

func (getHwclockFunc) Name() string { return "timezone.get_hwclock" }
func (getHwclockFunc) Args() any    { return getHwclockArgs{} }
func (getHwclockFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	res := rt.Runner.Run(ctx, runtime.Command("timedatectl", "show", "-p", "Clock"))
	if res.Err == nil && res.ExitCode == 0 {
		line := strings.TrimSpace(string(res.Stdout))
		if _, value, ok := strings.Cut(line, "="); ok {
			return value, nil
		}
	}
	data, err := rt.FS.ReadFile("/etc/adjtime")
	if err != nil {
		return nil, fmt.Errorf("could not determine hwclock: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) >= 3 {
		return strings.TrimSpace(lines[2]), nil
	}
	return "", fmt.Errorf("could not determine hwclock")
}

type setHwclockArgs struct {
	Clock string `statekit:"required,name=clock"`
}

type setHwclockFunc struct{}

func (setHwclockFunc) Name() string { return "timezone.set_hwclock" }
func (setHwclockFunc) Args() any    { return setHwclockArgs{} }
func (setHwclockFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*setHwclockArgs)
	clock := a.Clock
	switch clock {
	case "UTC":
	case "localtime", "local":
		clock = "localtime"
	default:
		return nil, fmt.Errorf("clock must be UTC or localtime, got %q", a.Clock)
	}
	res := rt.Runner.Run(ctx, runtime.Command("timedatectl", "set-local-rtc", rtcValue(clock)))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("timedatectl exited with code %d: %s", res.ExitCode, res.Stderr)
	}
	return true, nil
}

// Register installs all timezone-module execution functions. The
// zone_compare variant is selected per GOOS: the Linux generic
// filesystem contract on linux, the mac systemsetup contract on darwin,
// the windows tzutil contract on windows. The Mac systemsetup getters
// timezone.get_date, timezone.get_time, timezone.get_using_network_time,
// and timezone.get_time_server, the Mac date-getter variant of
// timezone.get_zonecode, and the Mac zone lister timezone.list_zones
// are darwin-only; the Mac systemsetup setters timezone.set_date,
// timezone.set_time, and timezone.set_using_network_time are darwin-only
// through their own seam; the Linux
// generic getter timezone.get_zonecode is linux-only; the Windows
// static-table lister timezone.list is windows-only.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{getZoneFunc{}, setZoneFunc{}, getOffsetFunc{}, getHwclockFunc{}, setHwclockFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	if err := registerZoneCompareForGOOS(reg, runtime.CurrentGOOS()); err != nil {
		return err
	}
	if err := registerMacGettersForGOOS(reg, runtime.CurrentGOOS()); err != nil {
		return err
	}
	if err := registerMacSettersForGOOS(reg, runtime.CurrentGOOS()); err != nil {
		return err
	}
	if err := registerLinuxGettersForGOOS(reg, runtime.CurrentGOOS()); err != nil {
		return err
	}
	return registerWindowsGettersForGOOS(reg, runtime.CurrentGOOS())
}

// registerLinuxGettersForGOOS installs the Linux-only generic getter
// timezone.get_zonecode on linux only, and nothing on any other GOOS,
// where the name stays unregistered rather than
// registered-but-unsupported. The registry keys by name, so registering
// the getter onto one registry twice fails as a duplicate.
func registerLinuxGettersForGOOS(reg *runtime.ExecRegistry, goos string) error {
	if goos != "linux" {
		return nil
	}
	return reg.Register(getZonecodeFunc{})
}

// registerWindowsGettersForGOOS installs the Windows-only static-table
// lister timezone.list on windows only, and nothing on any other GOOS,
// where the name stays unregistered rather than
// registered-but-unsupported (the established
// registerLinuxGettersForGOOS/registerMacGettersForGOOS pattern). The
// registry keys by name, so registering the lister onto one registry
// twice fails as a duplicate.
func registerWindowsGettersForGOOS(reg *runtime.ExecRegistry, goos string) error {
	if goos != "windows" {
		return nil
	}
	return reg.Register(winZoneListFunc{})
}

// registerMacGettersForGOOS installs the Mac-only systemsetup getters
// timezone.get_date, timezone.get_time, timezone.get_using_network_time,
// and timezone.get_time_server, the Mac-only date-getter variant of
// timezone.get_zonecode, and the Mac-only zone lister
// timezone.list_zones on darwin only, and nothing on any other GOOS,
// where the names stay unregistered rather than
// registered-but-unsupported. The registry keys by name, so registering
// a getter onto one registry twice fails as a duplicate.
func registerMacGettersForGOOS(reg *runtime.ExecRegistry, goos string) error {
	if goos != "darwin" {
		return nil
	}
	for _, fn := range []runtime.ExecFunction{macGetDateFunc{}, macGetTimeFunc{}, macGetUsingNetworkTimeFunc{}, macGetTimeServerFunc{}, macZonecodeFunc{}, macListZonesFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// registerMacSettersForGOOS installs the Mac-only systemsetup setters
// timezone.set_date, timezone.set_time, and
// timezone.set_using_network_time on darwin only, and nothing
// on any other GOOS, where the names stay unregistered rather than
// registered-but-unsupported (the established
// registerMacGettersForGOOS pattern, kept as a separate seam so the
// read-only getter helper and the mutation helper stay distinct).
// The registry keys by name, so registering a setter onto one
// registry twice fails as a duplicate.
func registerMacSettersForGOOS(reg *runtime.ExecRegistry, goos string) error {
	if goos != "darwin" {
		return nil
	}
	for _, fn := range []runtime.ExecFunction{macSetDateFunc{}, macSetTimeFunc{}, macSetUsingNetworkTimeFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// registerZoneCompareForGOOS installs exactly one
// timezone.zone_compare implementation for the given GOOS — the Linux
// generic filesystem contract on linux, the mac systemsetup contract on
// darwin, the windows tzutil contract on windows, or the Solaris
// timedatectl/TIMEZONE contract on solaris — and nothing on any other
// GOOS, where the name stays unregistered rather than
// registered-but-unsupported. The registry keys by name, so registering
// a second variant onto one registry fails as a duplicate.
func registerZoneCompareForGOOS(reg *runtime.ExecRegistry, goos string) error {
	switch goos {
	case "linux":
		return reg.Register(zoneCompareFunc{})
	case "darwin":
		return reg.Register(macZoneCompareFunc{})
	case "windows":
		return reg.Register(winZoneCompareFunc{})
	case "solaris":
		return reg.Register(solarisZoneCompareFunc{})
	}
	return nil
}
