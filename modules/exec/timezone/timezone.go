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
	"path"
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

// Platforms restricts zone_compare to linux: the reviewed contract is
// the Linux generic filesystem slice only (nilrt, mac, win, Solaris and
// AIX variants stay open rows).
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

// Platforms restricts the mac variant to darwin; the Windows, Solaris,
// AIX, and NILinuxRT rows of PTD-EXEC-1638 stay open.
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
// the windows tzutil contract on windows.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{getZoneFunc{}, setZoneFunc{}, getOffsetFunc{}, getHwclockFunc{}, setHwclockFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return registerZoneCompareForGOOS(reg, runtime.CurrentGOOS())
}

// registerZoneCompareForGOOS installs exactly one
// timezone.zone_compare implementation for the given GOOS — the Linux
// generic filesystem contract on linux, the mac systemsetup contract on
// darwin, the windows tzutil contract on windows — and nothing on any
// other GOOS, where the name stays unregistered rather than
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
	}
	return nil
}
