// Package user implements Salt-compatible local account inspection and
// management on Linux.
//
// Reference: saltstack/salt/modules/useradd.py @ pinned revision. Database
// reads go through the runtime FileSystem (/etc/passwd, /etc/group);
// mutations delegate to useradd/userdel/usermod via the central Runner.
package user

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	"github.com/friz-zy/statekit/internal/sysfiles"
)

const passwdPath = "/etc/passwd"
const groupPath = "/etc/group"

const (
	maxLocalPasswdBytes  = 1 << 20
	maxAccountFieldBytes = 4096
	userModTimeout       = 30 * time.Second
	userModCaptureBytes  = 4096
)

var (
	errChotherInvalidArguments           = errors.New("user.chother: invalid arguments")
	errChotherUnsupported                = errors.New("user.chother: unsupported platform")
	errChotherUnsupportedRoot            = errors.New("user.chother: unsupported root")
	errChotherInvalidName                = errors.New("user.chother: invalid name")
	errChotherInvalidOther               = errors.New("user.chother: invalid other")
	errChotherOtherTooLong               = errors.New("user.chother: other exceeds limit")
	errChotherInvalidOtherType           = errors.New("user.chother: invalid other type")
	errChotherOtherOutOfRange            = errors.New("user.chother: other integer out of range")
	errChotherExistingTooLong            = errors.New("user.chother: existing GECOS exceeds limit")
	errChotherBuiltTooLong               = errors.New("user.chother: built GECOS exceeds limit")
	errChotherUnverified                 = errors.New("user.chother: unverified executable")
	errChotherHelperUnavailable          = errors.New("user.chother: trusted helper unavailable")
	errChotherCommandFailed              = errors.New("user.chother: command failed")
	errChotherCommandCanceled            = errors.New("user.chother: command canceled")
	errChotherCommandTimedOut            = errors.New("user.chother: command timed out")
	errChotherOutputLimit                = errors.New("user.chother: command output limit exceeded")
	errChotherUnconfirmed                = errors.New("user.chother: state unconfirmed")
	errLocalPasswdFSUnsupported          = errors.New("user.chother: bounded passwd reads unsupported")
	errLocalPasswdRead                   = errors.New("user.chother: passwd read failed")
	errLocalPasswdTooLarge               = errors.New("user.chother: passwd exceeds limit")
	errLocalPasswdMalformed              = errors.New("user.chother: malformed passwd data")
	errLocalPasswdMissing                = errors.New("user.chother: account not found")
	errLocalPasswdDuplicate              = errors.New("user.chother: duplicate account")
	errChroomnumberInvalidArguments      = errors.New("user.chroomnumber: invalid arguments")
	errChroomnumberUnsupported           = errors.New("user.chroomnumber: unsupported platform")
	errChroomnumberUnsupportedRoot       = errors.New("user.chroomnumber: unsupported root")
	errChroomnumberInvalidName           = errors.New("user.chroomnumber: invalid name")
	errChroomnumberInvalidRoomnumber     = errors.New("user.chroomnumber: invalid roomnumber")
	errChroomnumberComma                 = errors.New("user.chroomnumber: comma in roomnumber is not allowed")
	errChroomnumberRoomnumberTooLong     = errors.New("user.chroomnumber: roomnumber exceeds limit")
	errChroomnumberInvalidRoomnumberType = errors.New("user.chroomnumber: invalid roomnumber type")
	errChroomnumberRoomnumberOutOfRange  = errors.New("user.chroomnumber: roomnumber integer out of range")
	errChroomnumberExistingTooLong       = errors.New("user.chroomnumber: existing GECOS exceeds limit")
	errChroomnumberBuiltTooLong          = errors.New("user.chroomnumber: built GECOS exceeds limit")
	errChroomnumberPreservation          = errors.New("user.chroomnumber: room update would alter unmanaged GECOS fields")
	errChroomnumberUnverified            = errors.New("user.chroomnumber: unverified executable")
	errChroomnumberHelperUnavailable     = errors.New("user.chroomnumber: trusted helper unavailable")
	errChroomnumberCommandFailed         = errors.New("user.chroomnumber: command failed")
	errChroomnumberCommandCanceled       = errors.New("user.chroomnumber: command canceled")
	errChroomnumberCommandTimedOut       = errors.New("user.chroomnumber: command timed out")
	errChroomnumberOutputLimit           = errors.New("user.chroomnumber: command output limit exceeded")
	errChroomnumberUnconfirmed           = errors.New("user.chroomnumber: state unconfirmed")
	errChroomnumberFSUnsupported         = errors.New("user.chroomnumber: bounded passwd reads unsupported")
	errChroomnumberPasswdRead            = errors.New("user.chroomnumber: passwd read failed")
	errChroomnumberPasswdTooLarge        = errors.New("user.chroomnumber: passwd exceeds limit")
	errChroomnumberPasswdMalformed       = errors.New("user.chroomnumber: malformed passwd data")
	errChroomnumberAccountMissing        = errors.New("user.chroomnumber: account not found")
	errChroomnumberAccountDuplicate      = errors.New("user.chroomnumber: duplicate account")
)

const (
	localGecosFieldCount = 5
	roomNumberGecosIndex = 1
	otherGecosIndex      = 4
)

// LocalPasswdEntry contains only bounded fields needed by GECOS account
// mutations and their state companions. The passwd password field is never retained.
type LocalPasswdEntry struct {
	Name  string
	UID   string
	GID   string
	Home  string
	Shell string
	gecos string
}

// OtherMatches compares only the fifth comma-split GECOS field. The complete
// existing comment remains private to this package.
func (e LocalPasswdEntry) OtherMatches(value string) bool { return gecosOther(e.gecos) == value }

// RoomNumberMatches compares only the second comma-split GECOS field.
func (e LocalPasswdEntry) RoomNumberMatches(value string) bool {
	return splitGecos(e.gecos)[roomNumberGecosIndex] == value
}

// ValidateOtherBuild checks the full prospective comment and all GECOS caps
// without exposing the existing or constructed comment to another package.
func (e LocalPasswdEntry) ValidateOtherBuild(value string) error {
	_, err := buildGecos(e.gecos, value)
	return err
}

// ValidateRoomNumberBuild checks the full prospective comment and ensures
// source-compatible trailing trimming would not alter any unmanaged field.
func (e LocalPasswdEntry) ValidateRoomNumberBuild(value string) error {
	_, err := buildRoomGecos(e.gecos, value)
	return err
}

// ValidateProspectiveGecos validates the requested GECOS mutations together
// against this bounded passwd snapshot without exposing a constructed record.
func (e LocalPasswdEntry) ValidateProspectiveGecos(room, other *string) error {
	if len(e.gecos) > maxAccountFieldBytes {
		return errChotherExistingTooLong
	}
	if !validLocalText(e.gecos, true) {
		return errLocalPasswdMalformed
	}
	if room != nil {
		if _, err := normalizeRoomNumber(*room); err != nil {
			return err
		}
	}
	if other != nil {
		if err := validateOther(*other); err != nil {
			return err
		}
	}

	original := splitGecos(e.gecos)
	prospective := e.gecos
	if room != nil && original[roomNumberGecosIndex] != *room {
		built, err := buildRoomGecos(prospective, *room)
		if err != nil {
			return err
		}
		prospective = built
	}
	if other != nil && splitGecos(prospective)[otherGecosIndex] != *other {
		built, err := buildGecos(prospective, *other)
		if err != nil {
			return err
		}
		prospective = built
	}
	if len(prospective) > maxAccountFieldBytes {
		return errChotherBuiltTooLong
	}
	if !validLocalText(prospective, true) {
		return errLocalPasswdMalformed
	}

	final := splitGecos(prospective)
	if final[0] != original[0] || final[2] != original[2] || final[3] != original[3] ||
		(room == nil || original[roomNumberGecosIndex] == *room) && final[roomNumberGecosIndex] != original[roomNumberGecosIndex] ||
		(other == nil || original[otherGecosIndex] == *other) && final[otherGecosIndex] != original[otherGecosIndex] {
		return errChroomnumberPreservation
	}
	return nil
}

// ReadLocalPasswd reads and strictly parses the bounded local /etc/passwd
// record for name. It never falls back to an unbounded filesystem read or NSS.
func ReadLocalPasswd(rt *runtime.Runtime, name string) (LocalPasswdEntry, error) {
	if !validLocalAccountName(name) {
		return LocalPasswdEntry{}, errChotherInvalidName
	}
	if rt == nil || rt.FS == nil {
		return LocalPasswdEntry{}, errLocalPasswdFSUnsupported
	}
	if _, ok := rt.FS.(runtime.BoundedFileSystem); !ok {
		return LocalPasswdEntry{}, errLocalPasswdFSUnsupported
	}
	data, err := runtime.ReadFileBounded(rt.FS, passwdPath, maxLocalPasswdBytes)
	if err != nil {
		if errors.Is(err, runtime.ErrReadLimit) {
			return LocalPasswdEntry{}, errLocalPasswdTooLarge
		}
		return LocalPasswdEntry{}, errLocalPasswdRead
	}
	if len(data) > maxLocalPasswdBytes {
		return LocalPasswdEntry{}, errLocalPasswdTooLarge
	}
	return parseLocalPasswd(data, name)
}

func parseLocalPasswd(data []byte, target string) (LocalPasswdEntry, error) {
	if !validLocalAccountName(target) {
		return LocalPasswdEntry{}, errChotherInvalidName
	}
	if len(data) > maxLocalPasswdBytes {
		return LocalPasswdEntry{}, errLocalPasswdTooLarge
	}
	if !utf8.Valid(data) {
		return LocalPasswdEntry{}, errLocalPasswdMalformed
	}

	var matched LocalPasswdEntry
	matches := 0
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		for _, b := range []byte(line) {
			if b < 0x20 || b == 0x7f {
				return LocalPasswdEntry{}, errLocalPasswdMalformed
			}
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 || !validLocalAccountName(fields[0]) ||
			!validLocalID(fields[2]) || !validLocalID(fields[3]) {
			return LocalPasswdEntry{}, errLocalPasswdMalformed
		}
		if len(fields[4]) > maxAccountFieldBytes {
			return LocalPasswdEntry{}, errChotherExistingTooLong
		}
		if !validLocalText(fields[4], true) {
			return LocalPasswdEntry{}, errLocalPasswdMalformed
		}
		if fields[0] == target {
			matches++
			if matches == 1 {
				matched = LocalPasswdEntry{
					Name:  fields[0],
					UID:   fields[2],
					GID:   fields[3],
					gecos: fields[4],
					Home:  fields[5],
					Shell: fields[6],
				}
			}
		}
	}
	if matches == 0 {
		return LocalPasswdEntry{}, errLocalPasswdMissing
	}
	if matches > 1 {
		return LocalPasswdEntry{}, errLocalPasswdDuplicate
	}
	return matched, nil
}

func validLocalID(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(value, 10, 32)
	return err == nil && n <= 4294967294
}

func validLocalAccountName(value string) bool {
	return value != "" && value[0] != '-' && len(value) <= maxAccountFieldBytes && validLocalText(value, true)
}

func validLocalText(value string, rejectColon bool) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b == 0 || b < 0x20 || b == 0x7f || (rejectColon && b == ':') {
			return false
		}
	}
	return true
}

func mapChotherErrorToRoomNumber(err error) error {
	switch err {
	case errChotherInvalidArguments:
		return errChroomnumberInvalidArguments
	case errChotherUnsupported:
		return errChroomnumberUnsupported
	case errChotherUnsupportedRoot:
		return errChroomnumberUnsupportedRoot
	case errChotherInvalidName:
		return errChroomnumberInvalidName
	case errChotherInvalidOther:
		return errChroomnumberInvalidRoomnumber
	case errChotherOtherTooLong:
		return errChroomnumberRoomnumberTooLong
	case errChotherInvalidOtherType:
		return errChroomnumberInvalidRoomnumberType
	case errChotherOtherOutOfRange:
		return errChroomnumberRoomnumberOutOfRange
	case errChotherExistingTooLong:
		return errChroomnumberExistingTooLong
	case errChotherBuiltTooLong:
		return errChroomnumberBuiltTooLong
	case errChotherUnverified:
		return errChroomnumberUnverified
	case errChotherHelperUnavailable:
		return errChroomnumberHelperUnavailable
	case errChotherCommandFailed:
		return errChroomnumberCommandFailed
	case errChotherCommandCanceled:
		return errChroomnumberCommandCanceled
	case errChotherCommandTimedOut:
		return errChroomnumberCommandTimedOut
	case errChotherOutputLimit:
		return errChroomnumberOutputLimit
	case errChotherUnconfirmed:
		return errChroomnumberUnconfirmed
	case errLocalPasswdFSUnsupported:
		return errChroomnumberFSUnsupported
	case errLocalPasswdRead:
		return errChroomnumberPasswdRead
	case errLocalPasswdTooLarge:
		return errChroomnumberPasswdTooLarge
	case errLocalPasswdMalformed:
		return errChroomnumberPasswdMalformed
	case errLocalPasswdMissing:
		return errChroomnumberAccountMissing
	case errLocalPasswdDuplicate:
		return errChroomnumberAccountDuplicate
	default:
		return errChroomnumberInvalidRoomnumber
	}
}

func normalizeRoomNumber(value any) (string, error) {
	normalized, err := normalizeOther(value)
	if err != nil {
		return "", mapChotherErrorToRoomNumber(err)
	}
	if strings.Contains(normalized, ",") {
		return "", errChroomnumberComma
	}
	return normalized, nil
}

// NormalizeRoomNumber applies the committed scalar/range subset and rejects
// commas before callers perform account reads or dispatch.
func NormalizeRoomNumber(value any) (string, error) { return normalizeRoomNumber(value) }

func readLocalPasswdForRoomNumber(rt *runtime.Runtime, name string) (LocalPasswdEntry, error) {
	entry, err := ReadLocalPasswd(rt, name)
	if err != nil {
		return LocalPasswdEntry{}, mapChotherErrorToRoomNumber(err)
	}
	return entry, nil
}

func validateOther(value string) error {
	if len(value) > maxAccountFieldBytes {
		return errChotherOtherTooLong
	}
	if !validLocalText(value, true) {
		return errChotherInvalidOther
	}
	return nil
}

func normalizeOther(value any) (string, error) {
	var normalized string
	switch v := value.(type) {
	case nil:
		normalized = ""
	case string:
		if err := validateOther(v); err != nil {
			return "", err
		}
		normalized = v
	case int:
		normalized = strconv.FormatInt(int64(v), 10)
	case int8:
		normalized = strconv.FormatInt(int64(v), 10)
	case int16:
		normalized = strconv.FormatInt(int64(v), 10)
	case int32:
		normalized = strconv.FormatInt(int64(v), 10)
	case int64:
		normalized = strconv.FormatInt(v, 10)
	case uint:
		if uint64(v) > 9223372036854775807 {
			return "", errChotherOtherOutOfRange
		}
		normalized = strconv.FormatUint(uint64(v), 10)
	case uint8:
		normalized = strconv.FormatUint(uint64(v), 10)
	case uint16:
		normalized = strconv.FormatUint(uint64(v), 10)
	case uint32:
		normalized = strconv.FormatUint(uint64(v), 10)
	case uint64:
		if v > 9223372036854775807 {
			return "", errChotherOtherOutOfRange
		}
		normalized = strconv.FormatUint(v, 10)
	default:
		return "", errChotherInvalidOtherType
	}
	if err := validateOther(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

// NormalizeOther applies the exact scalar and range subset shared by the
// execution function and its managed state companion.
func NormalizeOther(value any) (string, error) { return normalizeOther(value) }

func splitGecos(gecos string) []string {
	fields := strings.SplitN(gecos, ",", 5)
	for len(fields) < localGecosFieldCount {
		fields = append(fields, "")
	}
	return fields
}

func gecosOther(gecos string) string { return splitGecos(gecos)[otherGecosIndex] }

func buildGecos(existing, other string) (string, error) {
	return buildGecosAt(existing, other, otherGecosIndex)
}

func buildGecosAt(existing, value string, fieldIndex int) (string, error) {
	if len(existing) > maxAccountFieldBytes {
		return "", errChotherExistingTooLong
	}
	if !validLocalText(existing, true) {
		return "", errLocalPasswdMalformed
	}
	if err := validateOther(value); err != nil {
		return "", err
	}
	fields := splitGecos(existing)
	fields[fieldIndex] = value
	built := strings.TrimRight(strings.Join(fields, ","), ",")
	if len(built) > maxAccountFieldBytes {
		return "", errChotherBuiltTooLong
	}
	if !validLocalText(built, true) {
		return "", errChotherInvalidOther
	}
	return built, nil
}

func buildRoomGecos(existing, room string) (string, error) {
	if _, err := normalizeRoomNumber(room); err != nil {
		return "", err
	}
	original := splitGecos(existing)
	built, err := buildGecosAt(existing, room, roomNumberGecosIndex)
	if err != nil {
		return "", mapChotherErrorToRoomNumber(err)
	}
	readback := splitGecos(built)
	for index := 0; index < localGecosFieldCount; index++ {
		if index != roomNumberGecosIndex && readback[index] != original[index] {
			return "", errChroomnumberPreservation
		}
	}
	return built, nil
}

type ChOtherArgs struct {
	Name  string `statekit:"required"`
	Other *any   `statekit:"required,name=other"`
	Root  any    `statekit:"name=root"`
}

type ChRoomNumberArgs struct {
	Name       string `statekit:"required"`
	RoomNumber *any   `statekit:"required,name=roomnumber"`
	Root       any    `statekit:"name=root"`
}

type chOtherFunc struct{}

func (chOtherFunc) Name() string        { return "user.chother" }
func (chOtherFunc) Args() any           { return ChOtherArgs{} }
func (chOtherFunc) Platforms() []string { return []string{"linux"} }
func (chOtherFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return executeChotherForGOOS(ctx, rt, args, runtime.CurrentGOOS())
}

func executeChotherForGOOS(ctx context.Context, rt *runtime.Runtime, args any, goos string) (any, error) {
	a, ok := args.(*ChOtherArgs)
	if !ok || a == nil {
		return nil, errChotherInvalidArguments
	}
	if err := config.ValidateRequired(a); err != nil {
		return nil, err
	}
	if a.Root != nil {
		return nil, errChotherUnsupportedRoot
	}
	if !validLocalAccountName(a.Name) {
		return nil, errChotherInvalidName
	}
	desired, err := normalizeOther(*a.Other)
	if err != nil {
		return nil, err
	}
	if goos != "linux" {
		return nil, errChotherUnsupported
	}

	current, err := ReadLocalPasswd(rt, a.Name)
	if err != nil {
		return nil, err
	}
	built, err := buildGecos(current.gecos, desired)
	if err != nil {
		return nil, err
	}
	if current.OtherMatches(desired) {
		return true, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, classifyChotherContext(err)
	}
	if rt == nil || rt.Runner == nil {
		return nil, errChotherUnverified
	}
	resolver, ok := rt.Runner.(process.TrustedCommandResolver)
	if !ok {
		return nil, errChotherUnverified
	}
	path, err := resolver.ResolveTrustedCommand("usermod")
	if err != nil || !trustedUsermodPath(path) {
		return nil, errChotherHelperUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, classifyChotherContext(err)
	}
	command := process.Command{
		Name:           path,
		Args:           []string{"-c", built, a.Name},
		Dir:            "/",
		Env:            []string{"PATH=/usr/sbin:/usr/bin:/bin", "LANG=C", "LC_ALL=C"},
		Timeout:        userModTimeout,
		Shell:          false,
		Redact:         redactChotherValues(built, a.Name, desired),
		PreserveStdout: false,
		MaxStdoutBytes: userModCaptureBytes,
		MaxStderrBytes: userModCaptureBytes,
	}
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return nil, classifyChotherRunnerError(result.Err)
	}
	if result.ExitCode != 0 {
		return nil, errChotherCommandFailed
	}
	if result.StdoutTruncated || result.StderrTruncated || len(result.Stdout) > userModCaptureBytes || len(result.Stderr) > userModCaptureBytes {
		return nil, errChotherOutputLimit
	}
	verified, err := ReadLocalPasswd(rt, a.Name)
	if err != nil {
		return nil, errChotherUnconfirmed
	}
	return verified.OtherMatches(desired), nil
}

type chRoomNumberFunc struct{}

func (chRoomNumberFunc) Name() string        { return "user.chroomnumber" }
func (chRoomNumberFunc) Args() any           { return ChRoomNumberArgs{} }
func (chRoomNumberFunc) Platforms() []string { return []string{"linux"} }
func (chRoomNumberFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return executeChroomnumberForGOOS(ctx, rt, args, runtime.CurrentGOOS())
}

func executeChroomnumberForGOOS(ctx context.Context, rt *runtime.Runtime, args any, goos string) (any, error) {
	a, ok := args.(*ChRoomNumberArgs)
	if !ok || a == nil {
		return nil, errChroomnumberInvalidArguments
	}
	if err := config.ValidateRequired(a); err != nil {
		return nil, err
	}
	if a.Root != nil {
		return nil, errChroomnumberUnsupportedRoot
	}
	if !validLocalAccountName(a.Name) {
		return nil, errChroomnumberInvalidName
	}
	desired, err := normalizeRoomNumber(*a.RoomNumber)
	if err != nil {
		return nil, err
	}
	if goos != "linux" {
		return nil, errChroomnumberUnsupported
	}

	current, err := readLocalPasswdForRoomNumber(rt, a.Name)
	if err != nil {
		return nil, err
	}
	if current.RoomNumberMatches(desired) {
		return true, nil
	}
	built, err := buildRoomGecos(current.gecos, desired)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, mapChotherErrorToRoomNumber(classifyChotherContext(err))
	}
	if rt == nil || rt.Runner == nil {
		return nil, errChroomnumberUnverified
	}
	resolver, ok := rt.Runner.(process.TrustedCommandResolver)
	if !ok {
		return nil, errChroomnumberUnverified
	}
	path, err := resolver.ResolveTrustedCommand("usermod")
	if err != nil || !trustedUsermodPath(path) {
		return nil, errChroomnumberHelperUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, mapChotherErrorToRoomNumber(classifyChotherContext(err))
	}
	command := process.Command{
		Name:           path,
		Args:           []string{"-c", built, a.Name},
		Dir:            "/",
		Env:            []string{"PATH=/usr/sbin:/usr/bin:/bin", "LANG=C", "LC_ALL=C"},
		Timeout:        userModTimeout,
		Shell:          false,
		Redact:         redactChotherValues(built, a.Name, desired),
		PreserveStdout: false,
		MaxStdoutBytes: userModCaptureBytes,
		MaxStderrBytes: userModCaptureBytes,
	}
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return nil, mapChotherErrorToRoomNumber(classifyChotherRunnerError(result.Err))
	}
	if result.ExitCode != 0 {
		return nil, errChroomnumberCommandFailed
	}
	if result.StdoutTruncated || result.StderrTruncated || len(result.Stdout) > userModCaptureBytes || len(result.Stderr) > userModCaptureBytes {
		return nil, errChroomnumberOutputLimit
	}
	verified, err := readLocalPasswdForRoomNumber(rt, a.Name)
	if err != nil {
		return nil, errChroomnumberUnconfirmed
	}
	return verified.RoomNumberMatches(desired), nil
}

func trustedUsermodPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return false
	}
	for _, root := range []string{"/bin", "/usr", "/usr/local"} {
		if strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

func redactChotherValues(values ...string) []string {
	redact := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		duplicate := false
		for _, prior := range redact {
			if prior == value {
				duplicate = true
				break
			}
		}
		if !duplicate {
			redact = append(redact, value)
		}
	}
	return redact
}

func classifyChotherContext(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return errChotherCommandTimedOut
	}
	return errChotherCommandCanceled
}

func classifyChotherRunnerError(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return errChotherCommandTimedOut
	case errors.Is(err, context.Canceled):
		return errChotherCommandCanceled
	case errors.Is(err, process.ErrOutputLimit):
		return errChotherOutputLimit
	default:
		return errChotherCommandFailed
	}
}

func readPasswd(rt *runtime.Runtime) []sysfiles.PasswdEntry {
	data, err := rt.FS.ReadFile(passwdPath)
	if err != nil {
		return nil
	}
	return sysfiles.ParsePasswd(string(data))
}

func readGroups(rt *runtime.Runtime) []sysfiles.GroupEntry {
	data, err := rt.FS.ReadFile(groupPath)
	if err != nil {
		return nil
	}
	return sysfiles.ParseGroup(string(data))
}

func groupsOfUser(rt *runtime.Runtime, name string) []string {
	groups := []string{}
	for _, group := range readGroups(rt) {
		for _, member := range group.Members {
			if member == name {
				groups = append(groups, group.Name)
				break
			}
		}
	}
	return groups
}

type InfoArgs struct {
	Name string `statekit:"required"`
}

type infoFunc struct{}

func (infoFunc) Name() string { return "user.info" }
func (infoFunc) Args() any    { return InfoArgs{} }
func (infoFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InfoArgs)
	for _, entry := range readPasswd(rt) {
		if entry.Name != a.Name {
			continue
		}
		return map[string]any{
			"name":   entry.Name,
			"uid":    entry.UID,
			"gid":    entry.GID,
			"home":   entry.Home,
			"shell":  entry.Shell,
			"gecos":  entry.Gecos,
			"groups": groupsOfUser(rt, entry.Name),
		}, nil
	}
	return nil, fmt.Errorf("user %q does not exist", a.Name)
}

type ListUsersArgs struct{}

type listUsersFunc struct{}

func (listUsersFunc) Name() string { return "user.list_users" }
func (listUsersFunc) Args() any    { return ListUsersArgs{} }
func (listUsersFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	names := []string{}
	for _, entry := range readPasswd(rt) {
		names = append(names, entry.Name)
	}
	return names, nil
}

func run(ctx context.Context, rt *runtime.Runtime, argv ...string) error {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return res.Err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s exited with code %d: %s", argv[0], res.ExitCode, res.Stderr)
	}
	return nil
}

func done(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return true, nil
}

type AddArgs struct {
	Name   string `statekit:"required"`
	UID    string `statekit:"name=uid"`
	GID    string `statekit:"name=gid"`
	Home   string `statekit:"name=home"`
	Shell  string `statekit:"name=shell"`
	Create bool   `statekit:"name=createhome"`
}

type addFunc struct{}

func (addFunc) Name() string { return "user.add" }
func (addFunc) Args() any    { return AddArgs{} }
func (addFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AddArgs)
	argv := []string{"useradd"}
	if a.UID != "" {
		argv = append(argv, "-u", a.UID)
	}
	if a.GID != "" {
		argv = append(argv, "-g", a.GID)
	}
	if a.Home != "" {
		argv = append(argv, "-d", a.Home)
	}
	if a.Shell != "" {
		argv = append(argv, "-s", a.Shell)
	}
	if !a.Create {
		argv = append(argv, "-M")
	} else {
		argv = append(argv, "-m")
	}
	argv = append(argv, a.Name)
	return done(run(ctx, rt, argv...))
}

type DeleteArgs struct {
	Name   string `statekit:"required"`
	Remove bool   `statekit:"name=remove"`
	Force  bool   `statekit:"name=force"`
}

type deleteFunc struct{}

func (deleteFunc) Name() string { return "user.delete" }
func (deleteFunc) Args() any    { return DeleteArgs{} }
func (deleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DeleteArgs)
	argv := []string{"userdel"}
	if a.Remove {
		argv = append(argv, "-r")
	}
	if a.Force {
		argv = append(argv, "-f")
	}
	argv = append(argv, a.Name)
	return done(run(ctx, rt, argv...))
}

type ChUIDArgs struct {
	Name string `statekit:"required"`
	UID  string `statekit:"required,name=uid"`
}

type chUIDFunc struct{}

func (chUIDFunc) Name() string { return "user.chuid" }
func (chUIDFunc) Args() any    { return ChUIDArgs{} }
func (chUIDFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ChUIDArgs)
	return done(run(ctx, rt, "usermod", "-u", a.UID, a.Name))
}

type ChGIDArgs struct {
	Name string `statekit:"required"`
	GID  string `statekit:"required,name=gid"`
}

type chGIDFunc struct{}

func (chGIDFunc) Name() string { return "user.chgid" }
func (chGIDFunc) Args() any    { return ChGIDArgs{} }
func (chGIDFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ChGIDArgs)
	return done(run(ctx, rt, "usermod", "-g", a.GID, a.Name))
}

type ChShellArgs struct {
	Name  string `statekit:"required"`
	Shell string `statekit:"required,name=shell"`
}

type chShellFunc struct{}

func (chShellFunc) Name() string { return "user.chshell" }
func (chShellFunc) Args() any    { return ChShellArgs{} }
func (chShellFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ChShellArgs)
	return done(run(ctx, rt, "usermod", "-s", a.Shell, a.Name))
}

type ChHomeArgs struct {
	Name string `statekit:"required"`
	Home string `statekit:"required,name=home"`
	Move bool   `statekit:"name=move_current"`
}

type chHomeFunc struct{}

func (chHomeFunc) Name() string { return "user.chhome" }
func (chHomeFunc) Args() any    { return ChHomeArgs{} }
func (chHomeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ChHomeArgs)
	argv := []string{"usermod"}
	if a.Move {
		argv = append(argv, "-m")
	}
	argv = append(argv, "-d", a.Home, a.Name)
	return done(run(ctx, rt, argv...))
}

// currentUID resolves the numeric uid of a passwd entry when available.
func currentUID(entries []sysfiles.PasswdEntry, name string) (int, bool) {
	for _, entry := range entries {
		if entry.Name == name {
			uid, err := strconv.Atoi(entry.UID)
			if err != nil {
				return 0, false
			}
			return uid, true
		}
	}
	return 0, false
}

// Register installs all user-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	return registerUserForGOOS(reg, runtime.CurrentGOOS())
}

func registerUserForGOOS(reg *runtime.ExecRegistry, goos string) error {
	if goos == "freebsd" {
		return registerFreeBSD(reg)
	}
	// Official Go distributions list solaris/amd64 and illumos/amd64 compile
	// targets. This host has no native Solaris runtime runner; the branch keeps
	// dispatch exhaustive and registerSolaris is covered by the untagged mock
	// tests on the Linux host.
	if goos == "solaris" {
		return registerSolaris(reg)
	}
	if goos == "darwin" {
		return registerMac(reg)
	}
	if goos == "windows" {
		return registerWindows(reg)
	}
	functions := []runtime.ExecFunction{
		infoFunc{}, listUsersFunc{}, addFunc{}, deleteFunc{},
		chUIDFunc{}, chGIDFunc{}, chShellFunc{}, chHomeFunc{},
	}
	if goos == "linux" {
		functions = append(functions, chOtherFunc{}, chRoomNumberFunc{})
	}
	for _, fn := range functions {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	if goos == "openbsd" {
		return registerOpenBSDLoginclass(reg)
	}
	return nil
}
