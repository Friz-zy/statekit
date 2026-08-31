package pkg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

var ErrUnsupportedYUM = errors.New("YUM capability is not supported by this package provider")

const yumPatchesOutputLimit = 1 << 20
const yumServicesOutputLimit = 1 << 20
const yumGroupsOutputLimit = 1 << 20
const yumGroupInfoOutputLimit = 1 << 20
const yumUpgradeOutputLimit = 1 << 20
const yumVerifyOutputLimit = 1 << 20
const yumModifiedOutputLimit = 1 << 20
const yumDownloadedMetadataLimit = 4096
const yumDownloadedPathLimit = 4096

var errYUMGroupNotFound = errors.New("YUM group not found")

type yumGroupNotFoundError struct {
	name string
}

func (e *yumGroupNotFoundError) Error() string {
	return fmt.Sprintf("Group '%s' not found", e.name)
}

func (e *yumGroupNotFoundError) Unwrap() error {
	return errYUMGroupNotFound
}

const (
	yumGroupMaxDepth = 32
	yumGroupMaxNodes = 256
)

var yumPatchesLine = regexp.MustCompile(`^([i|\s])? ?([^\s]+) +([^\s]+) +([^\s]+)`)
var yumLanguageGroupLine = regexp.MustCompile(`^(.+) \[(.+)\]`)

var yumArchitectures = map[string]struct{}{
	"x86_64": {}, "x86_64_v2": {}, "athlon": {}, "amd64": {}, "ia32e": {}, "ia64": {}, "geode": {},
	"i386": {}, "i486": {}, "i586": {}, "i686": {},
	"ppc": {}, "ppc64": {}, "ppc64le": {}, "ppc64iseries": {}, "ppc64pseries": {},
	"s390": {}, "s390x": {},
	"alpha": {}, "alphaev4": {}, "alphaev45": {}, "alphaev5": {}, "alphaev56": {}, "alphapca56": {}, "alphaev6": {}, "alphaev67": {}, "alphaev68": {}, "alphaev7": {},
	"armv5tel": {}, "armv5tejl": {}, "armv6l": {}, "armv6hl": {}, "armv7l": {}, "armv7hl": {}, "armv7hnl": {},
	"aarch64": {}, "sh3": {}, "sh4": {}, "sh4a": {}, "noarch": {},
}

// yumRequestedArchitectures mirrors salt.utils.pkg.rpm.ARCHES.  Unlike the
// parser's architecture set, ARCHES intentionally excludes the noarch
// package marker.
var yumRequestedArchitectures = map[string]struct{}{
	"x86_64": {}, "x86_64_v2": {}, "athlon": {}, "amd64": {}, "ia32e": {}, "ia64": {}, "geode": {},
	"i386": {}, "i486": {}, "i586": {}, "i686": {},
	"ppc": {}, "ppc64": {}, "ppc64le": {}, "ppc64iseries": {}, "ppc64pseries": {},
	"s390": {}, "s390x": {},
	"alpha": {}, "alphaev4": {}, "alphaev45": {}, "alphaev5": {}, "alphaev56": {}, "alphapca56": {}, "alphaev6": {}, "alphaev67": {}, "alphaev68": {}, "alphaev7": {},
	"armv5tel": {}, "armv5tejl": {}, "armv6l": {}, "armv6hl": {}, "armv7l": {}, "armv7hl": {}, "armv7hnl": {},
	"aarch64": {}, "sh3": {}, "sh4": {}, "sh4a": {},
}

func yumArch(name string) (string, bool) {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return "", false
	}
	arch := name[i+1:]
	_, ok := yumArchitectures[arch]
	return arch, ok
}

func yumNormalizeName(name, osarch string) string {
	arch, known := yumArch(name)
	if !known {
		return name
	}
	base := name[:len(name)-len(arch)-1]
	// Salt's rpm.resolve_name keeps the suffix only for an architecture that
	// is distinct from the OS architecture and not a compatible 32-bit arch.
	if arch == "noarch" || arch == osarch || (arch == "x86_64_v2" && osarch == "x86_64") || (arch == "x86_64" && osarch == "x86_64_v2") || (is32RPMArch(arch) && is32RPMArch(osarch)) || (is32ARMArch(arch) && is32ARMArch(osarch)) {
		return base
	}
	return name
}

func is32RPMArch(arch string) bool {
	switch arch {
	case "i386", "i486", "i586", "i686":
		return true
	}
	return false
}
func is32ARMArch(arch string) bool {
	switch arch {
	case "armv5tel", "armv5tejl", "armv6l", "armv6hl", "armv7l", "armv7hl", "armv7hnl":
		return true
	}
	return false
}

func yumParseArch(name string) map[string]any {
	arch, known := yumArch(name)
	if !known {
		return map[string]any{"name": name, "arch": nil}
	}
	return map[string]any{"name": name[:len(name)-len(arch)-1], "arch": arch}
}

// yumRecordNameArch follows yumpkg._yum_pkginfo's record parsing. Unlike the
// public parse_arch operation, record parsing treats every final-dot suffix as
// an architecture; rpm.resolve_name then retains unknown architectures.
func yumRecordNameArch(value, osarch string) (string, string) {
	if i := strings.LastIndexByte(value, '.'); i >= 0 {
		return value[:i], value[i+1:]
	}
	return value, osarch
}

func yumResolvedRecordName(base, arch, osarch string) string {
	if arch == "" {
		return base
	}
	return yumNormalizeName(base+"."+arch, osarch)
}

// yumVersionCmp implements the pure-Python fallback used by Salt's
// salt.utils.pkg.rpm.evr_compare. The pinned source does not validate version
// strings before parsing them: version_to_evr supplies empty/fallback fields,
// and evr_compare compares the resulting triple.
func yumVersionCmp(pkg1, pkg2 string, ignoreEpoch bool) int {
	if ignoreEpoch {
		if i := strings.IndexByte(pkg1, ':'); i >= 0 {
			pkg1 = pkg1[i+1:]
		}
		if i := strings.IndexByte(pkg2, ':'); i >= 0 {
			pkg2 = pkg2[i+1:]
		}
	}
	e1, v1, r1 := yumVersionToEVR(pkg1)
	e2, v2, r2 := yumVersionToEVR(pkg2)
	// evr_compare converts epochs to integers before comparing them.
	n1, _ := new(big.Int).SetString(e1, 10)
	n2, _ := new(big.Int).SetString(e2, 10)
	if epochCompare := n1.Cmp(n2); epochCompare != 0 {
		if epochCompare < 0 {
			return -1
		}
		return 1
	}
	if c := rpmVerCmp(v1, v2); c != 0 {
		return c
	}
	return rpmVerCmp(r1, r2)
}

// yumLooseVersionCmp is the equivalent of Salt's versions.LooseVersion
// used by yumpkg._yum_pkginfo. The pinned implementation inherits
// distutils.LooseVersion's tokenizer: runs of ASCII digits, lowercase ASCII
// letters, and dots are matched; dots are separators and unmatched runs are
// retained as string components. Numeric tokens are parsed as integers,
// converted to decimal,
// then zfilled to width 8. If either version has a string component, the
// resulting string-token lists are compared lexicographically (the Salt
// override's Python-3-safe _str_version path); otherwise numeric ordering is
// used. Provider commands enforce yumUpgradeOutputLimit before this parser is
// called, so comparison remains bounded without changing LooseVersion values.
func yumLooseVersionCmp(left, right string) int {
	l, lHasString := yumLooseVersionParts(left)
	r, rHasString := yumLooseVersionParts(right)
	if !lHasString && !rHasString {
		return yumLooseNumericPartsCmp(l, r)
	}
	for i := 0; i < len(l) && i < len(r); i++ {
		if l[i] < r[i] {
			return -1
		}
		if l[i] > r[i] {
			return 1
		}
	}
	if len(l) < len(r) {
		return -1
	}
	if len(l) > len(r) {
		return 1
	}
	return 0
}

func yumLooseNumericPartsCmp(left, right []string) int {
	for i := 0; i < len(left) && i < len(right); i++ {
		l, r := strings.TrimLeft(left[i], "0"), strings.TrimLeft(right[i], "0")
		if l == "" {
			l = "0"
		}
		if r == "" {
			r = "0"
		}
		if len(l) != len(r) {
			if len(l) < len(r) {
				return -1
			}
			return 1
		}
		if l < r {
			return -1
		}
		if l > r {
			return 1
		}
	}
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	return 0
}

func yumLooseVersionParts(version string) ([]string, bool) {
	parts := make([]string, 0, 8)
	hasString := false
	for i := 0; i < len(version); {
		c := version[i]
		switch {
		case c >= '0' && c <= '9':
			start := i
			for i < len(version) && version[i] >= '0' && version[i] <= '9' {
				i++
			}
			n := strings.TrimLeft(version[start:i], "0")
			if n == "" {
				n = "0"
			}
			if len(n) < 8 {
				n = strings.Repeat("0", 8-len(n)) + n
			}
			parts = append(parts, n)
		case c >= 'a' && c <= 'z':
			start := i
			for i < len(version) && version[i] >= 'a' && version[i] <= 'z' {
				i++
			}
			parts = append(parts, version[start:i])
			hasString = true
		case c == '.':
			// The delimiter itself is discarded by component_re.split().
			i++
		default:
			// Unmatched runs are retained as string components by
			// distutils.LooseVersion (not discarded). This includes release
			// punctuation and uppercase text.
			start := i
			for i < len(version) {
				c = version[i]
				if c == '.' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') {
					break
				}
				i++
			}
			parts = append(parts, version[start:i])
			hasString = true
		}
	}
	return parts, hasString
}

func yumSign(v int) int {
	if v < 0 {
		return -1
	}
	if v > 0 {
		return 1
	}
	return 0
}

func yumVersionToEVR(s string) (epoch, version, release string) {
	epoch = "0"
	epochIndex := strings.IndexByte(s, ':')
	if epochIndex >= 0 {
		if n := s[:epochIndex]; n != "" {
			// Python int() accepts surrounding whitespace, an optional sign,
			// and Unicode decimal (Nd) digits. Do not use SetString here:
			// it only accepts ASCII digits and does not model Python's input.
			if parsed, ok := pythonIntDecimal(n); ok {
				epoch = parsed
			}
		}
	}
	releaseIndex := strings.IndexByte(s, '-')
	versionStart := epochIndex + 1
	if releaseIndex >= 0 {
		version := ""
		if releaseIndex >= versionStart {
			version = s[versionStart:releaseIndex]
		}
		return epoch, version, s[releaseIndex+1:]
	}
	return epoch, s[versionStart:], ""
}

func pythonIntDecimal(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	negative := false
	switch s[0] {
	case '+', '-':
		negative = s[0] == '-'
		s = s[1:]
	}
	if s == "" {
		return "", false
	}

	value := new(big.Int)
	ten := big.NewInt(10)
	for _, r := range s {
		digit, ok := unicodeDecimalValue(r)
		if !ok {
			return "", false
		}
		value.Mul(value, ten)
		value.Add(value, new(big.Int).SetInt64(int64(digit)))
	}
	if negative && value.Sign() != 0 {
		value.Neg(value)
	}
	return value.String(), true
}

// unicodeDecimalValue is the Go equivalent of Python's decimal-digit test
// (unicode.Digit(r, 10) >= 0 in runtimes exposing that API). Go exposes the
// Nd range table rather than a digit-value function.
func unicodeDecimalValue(r rune) (int, bool) {
	if r >= '0' && r <= '9' {
		return int(r - '0'), true
	}
	for _, rr := range unicode.Digit.R16 {
		if r >= rune(rr.Lo) && r <= rune(rr.Hi) {
			return int((r-rune(rr.Lo))/rune(rr.Stride)) % 10, true
		}
	}
	for _, rr := range unicode.Digit.R32 {
		lo, hi := rune(rr.Lo), rune(rr.Hi)
		if r >= lo && r <= hi {
			return int((r-lo)/rune(rr.Stride)) % 10, true
		}
	}
	return 0, false
}

func rpmVerCmp(a, b string) int {
	if a == b {
		return 0
	}
	ar, br := []rune(a), []rune(b)
	i, j := 0, 0
	for i < len(ar) || j < len(br) {
		for i < len(ar) && !rpmSpecial(ar[i]) && !rpmAlnum(ar[i]) {
			i++
		}
		for j < len(br) && !rpmSpecial(br[j]) && !rpmAlnum(br[j]) {
			j++
		}
		if (i < len(ar) && ar[i] == '~') || (j < len(br) && br[j] == '~') {
			if i >= len(ar) || ar[i] != '~' {
				return 1
			}
			if j >= len(br) || br[j] != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		if (i < len(ar) && ar[i] == '^') || (j < len(br) && br[j] == '^') {
			if i >= len(ar) {
				return -1
			}
			if j >= len(br) {
				return 1
			}
			if ar[i] != '^' {
				return 1
			}
			if br[j] != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(ar) || j >= len(br) {
			break
		}
		ai, bj := i, j
		numeric := pythonDigit(ar[i])
		if numeric {
			for i < len(ar) && pythonDigit(ar[i]) {
				i++
			}
			for j < len(br) && pythonDigit(br[j]) {
				j++
			}
		} else {
			for i < len(ar) && unicode.IsLetter(ar[i]) {
				i++
			}
			for j < len(br) && unicode.IsLetter(br[j]) {
				j++
			}
		}
		if j == bj {
			if numeric {
				return 1
			}
			return -1
		}
		x, y := string(ar[ai:i]), string(br[bj:j])
		if numeric {
			x = strings.TrimLeft(x, "0")
			y = strings.TrimLeft(y, "0")
			if utf8.RuneCountInString(x) != utf8.RuneCountInString(y) {
				return yumSign(utf8.RuneCountInString(x) - utf8.RuneCountInString(y))
			}
		}
		if c := rpmRuneCompare([]rune(x), []rune(y)); c != 0 {
			return c
		}
	}
	if i >= len(ar) && j >= len(br) {
		return 0
	}
	if i >= len(ar) {
		return -1
	}
	return 1
}

// pythonOtherDigit is the Other_Digit portion of Python's Unicode 16.0
// str.isdigit() predicate. unicode.IsDigit supplies the Nd portion; these
// ranges are intentionally not replaced with unicode.IsNumber, which would
// incorrectly classify numeric letters such as Roman numerals as digits.
var pythonOtherDigit = [...]rune{
	0x00B2, 0x00B3, 0x00B9, 0x00B9,
	0x1369, 0x1371, 0x19DA, 0x19DA,
	0x2070, 0x2070, 0x2074, 0x2079,
	0x2080, 0x2089,
	0x2460, 0x2468, 0x2474, 0x247C, 0x2488, 0x2490,
	0x24EA, 0x24F5, 0x24FD, 0x24FF,
	0x2776, 0x277E, 0x2780, 0x2788, 0x278A, 0x2792,
	0x10A40, 0x10A43, 0x10E60, 0x10E68,
	0x11052, 0x1105A, 0x1F100, 0x1F10A,
}

func pythonDigit(r rune) bool {
	if unicode.IsDigit(r) {
		return true
	}
	for i := 0; i < len(pythonOtherDigit); i += 2 {
		if r >= pythonOtherDigit[i] && r <= pythonOtherDigit[i+1] {
			return true
		}
	}
	return false
}

func rpmRuneCompare(a, b []rune) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return yumSign(len(a) - len(b))
}

// Python's isalnum gate also recognizes numeric characters such as Roman
// numerals. They remain non-digit/non-alpha for segment classification, as in
// the pinned source's separate isdigit/isalpha checks.
func rpmAlnum(r rune) bool {
	return pythonDigit(r) || unicode.IsLetter(r) || unicode.IsNumber(r)
}
func rpmSpecial(r rune) bool { return r == '~' || r == '^' }

func (p *commandProvider) Yum(ctx context.Context, rt *runtime.Runtime, function string, args any) (any, error) {
	// tdnf is intentionally not a supported provider, but list_holds must
	// fail like Salt before attempting any command rather than falling through
	// to a manager-specific implementation.
	if p.spec.manager == "tdnf" && function == "list_holds" {
		return nil, errors.New("Cannot proceed, no versionlock for tdnf")
	}
	if p.spec.manager != "yum" && p.spec.manager != "dnf" && p.spec.manager != "dnf5" {
		return nil, ErrUnsupportedYUM
	}
	a, ok := args.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("YUM function %q: malformed arguments", function)
	}
	if err := validateYUMArgs(function, a); err != nil {
		return nil, err
	}
	switch function {
	case "verify":
		return yumVerify(ctx, rt, p.spec.manager, a)
	case "modified":
		return yumModified(ctx, rt, a)
	case "list_downloaded":
		return yumDownloaded(ctx, rt, p.spec.manager)
	case "list_upgrades":
		return yumListUpgrades(ctx, rt, p.spec.manager, a)
	case "upgrade_available":
		return yumUpgradeAvailable(ctx, rt, p.spec.manager, a)
	case "list_patches", "list_installed_patches":
		return yumListPatches(ctx, rt, p.spec.manager, function == "list_installed_patches", a)
	case "list_holds":
		return yumListHolds(ctx, rt, p.spec.manager, a)
	case "services_need_restart":
		return yumServicesNeedRestart(ctx, rt, p.spec.manager)
	case "group_list":
		return yumGroupList(ctx, rt, p.spec.manager)
	case "group_info":
		return yumGroupInfo(ctx, rt, p.spec.manager, a)
	case "group_diff":
		return yumGroupDiff(ctx, rt, p, a)
	case "clean_metadata":
		return yumCleanMetadata(ctx, rt, p.spec.manager, a)
	case "file_list":
		packages, root, err := yumFilesArgs(a)
		if err != nil {
			return nil, err
		}
		cmd := []string{"rpm"}
		if root != "" {
			cmd = append(cmd, "--root", root)
		}
		if len(packages) == 0 {
			cmd = append(cmd, "-qla")
		} else {
			cmd = append(cmd, "-ql")
			cmd = append(cmd, packages...)
		}
		res := rt.Runner.Run(ctx, runtime.Command(cmd...))
		if res.Err != nil {
			return nil, res.Err
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("rpm exited with code %d: %s", res.ExitCode, res.Stderr)
		}
		// Salt's cmd.run(...).splitlines() preserves source order, duplicates,
		// and whitespace; do not normalize the rpm stream here.
		files := sourceSplitLines(string(res.Stdout))
		return map[string]any{"errors": []string{}, "files": files}, nil
	case "file_dict":
		packages, root, err := yumFilesArgs(a)
		if err != nil {
			return nil, err
		}
		cmd := []string{"rpm"}
		if root != "" {
			cmd = append(cmd, "--root", root)
		}
		if len(packages) == 0 {
			cmd = append(cmd, "-qa")
		} else {
			cmd = append(cmd, "-q")
		}
		cmd = append(cmd, "--queryformat", "%{NAME} %{VERSION}\\n")
		// rpm_lowpkg.file_dict places package operands after --queryformat;
		// preserve that exact argv ordering (including its per-package -ql
		// invocation quirk below).
		if len(packages) > 0 {
			cmd = append(cmd, packages...)
		}
		res := rt.Runner.Run(ctx, runtime.Command(cmd...))
		if res.Err != nil {
			return nil, res.Err
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("rpm exited with code %d: %s", res.ExitCode, res.Stderr)
		}
		errorsOut := []string{}
		versions := map[string]struct{ version string }{}
		order := []string{}
		for _, line := range sourceSplitLines(string(res.Stdout)) {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.Contains(line, "is not installed") {
				errorsOut = append(errorsOut, line)
				continue
			}
			f := strings.Fields(line)
			if len(f) < 2 {
				return nil, fmt.Errorf("rpm: malformed package output")
			}
			if _, exists := versions[f[0]]; !exists {
				order = append(order, f[0])
			}
			versions[f[0]] = struct{ version string }{version: f[1]}
		}
		ret := map[string]any{}
		for _, pkg := range order {
			q := []string{"rpm"}
			// Pinned salt rpm_lowpkg.py constructs a rooted `cmd` but invokes
			// cmd.run(["rpm", "-ql", pkg]); preserve that source quirk exactly.
			q = append(q, "-ql", pkg)
			r := rt.Runner.Run(ctx, runtime.Command(q...))
			if r.Err != nil {
				return nil, r.Err
			}
			if r.ExitCode != 0 {
				return nil, fmt.Errorf("rpm exited with code %d: %s", r.ExitCode, r.Stderr)
			}
			ret[pkg] = sourceSplitLines(string(r.Stdout))
		}
		return map[string]any{"errors": errorsOut, "packages": ret}, nil
	case "owner":
		paths, root, err := yumOwnerArgs(a)
		if err != nil {
			return nil, err
		}
		if len(paths) == 0 {
			return "", nil
		}
		ret := map[string]any{}
		for _, file := range paths {
			if strings.IndexByte(file, 0) >= 0 {
				return nil, errors.New("argument path contains NUL")
			}
			cmd := []string{"rpm"}
			if root != "" {
				cmd = append(cmd, "--root", root)
			}
			cmd = append(cmd, "-qf", "--queryformat", "%{name}", file)
			r := rt.Runner.Run(ctx, runtime.Command(cmd...))
			if r.Err != nil {
				return nil, r.Err
			}
			// cmd.run_stdout returns stdout independently of retcode. Salt then
			// translates the rpm "not owned" diagnostic to an empty value.
			if strings.Contains(strings.ToLower(string(r.Stdout)), "not owned") || r.ExitCode != 0 {
				ret[file] = ""
			} else {
				ret[file] = string(r.Stdout)
			}
		}
		if len(paths) == 1 {
			return ret[paths[0]], nil
		}
		return ret, nil
	case "info_installed":
		return yumInfoInstalled(ctx, rt, a)
	case "normalize_name":
		name, ok := a["name"].(string)
		if !ok {
			return nil, errors.New("argument \"name\" must be a string")
		}
		return yumNormalizeName(name, rt.Facts.CPU().Arch), nil
	case "parse_arch":
		name, ok := a["name"].(string)
		if !ok {
			return nil, errors.New("argument \"name\" must be a string")
		}
		return yumParseArch(name), nil
	case "version_cmp":
		p1, ok1 := a["pkg1"].(string)
		p2, ok2 := a["pkg2"].(string)
		if !ok1 || !ok2 {
			return nil, errors.New("argument \"pkg1\" and \"pkg2\" must be strings")
		}
		ignore := false
		if value, exists := a["ignore_epoch"]; exists {
			switch v := value.(type) {
			case bool:
				ignore = v
			case *bool:
				if v != nil {
					ignore = *v
				}
			default:
				return nil, errors.New("argument \"ignore_epoch\" must be a boolean")
			}
		}
		return yumVersionCmp(p1, p2, ignore), nil
	default:
		return nil, fmt.Errorf("unknown YUM function %q", function)
	}
}

// yumDownloaded mirrors yumpkg.list_downloaded exactly: the cache is always
// rooted at /var/cache/<provider>, and the RPM header is obtained through the
// lowpkg.bin_pkg_info query rather than by reading or executing locally.
func yumDownloaded(ctx context.Context, rt *runtime.Runtime, manager string) (any, error) {
	if rt == nil || rt.FS == nil {
		return nil, &runtime.UnsupportedError{Kind: "function", Name: "pkg.list_downloaded filesystem"}
	}
	if rt.Runner == nil {
		return nil, errors.New("pkg.list_downloaded runner is unavailable")
	}
	root := filepath.Join("/var/cache", manager)
	ret := map[string]any{}
	queue := []string{root}
	seen := 0
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if seen >= maxDownloadedEntries {
			return nil, errors.New("pkg.list_downloaded traversal limit exceeded")
		}
		dir := queue[0]
		queue = queue[1:]
		entries, err := runtime.ReadDirBounded(rt.FS, dir, maxDownloadedEntries-seen)
		if err != nil {
			if errors.Is(err, runtime.ErrDirReadLimit) {
				return nil, errors.New("pkg.list_downloaded traversal limit exceeded")
			}
			if errors.Is(err, runtime.ErrBoundedDirUnsupported) {
				return nil, err
			}
			// os.walk(..., onerror=None) abandons unreadable directories.
			continue
		}
		seen += len(entries)
		if seen > maxDownloadedEntries {
			return nil, errors.New("pkg.list_downloaded traversal limit exceeded")
		}
		for _, entry := range entries {
			name := entry.Name()
			candidate := filepath.Join(dir, name)
			if len(candidate) > yumDownloadedPathLimit {
				return nil, errors.New("pkg.list_downloaded path limit exceeded")
			}
			if entry.IsDir() {
				queue = append(queue, candidate)
				continue
			}
			// Reject every known nonregular final candidate before any operation
			// that could follow it. Type()==0 is intentionally retained for Lstat
			// validation.
			if entry.Type()&fs.ModeType != 0 {
				continue
			}
			if !strings.HasSuffix(name, ".rpm") {
				continue
			}
			// Lstat is deliberately used for both validation and metadata: the
			// package-info command accepts only the path, so there is no existing
			// descriptor-relative/no-follow query capability to close the check-
			// to-query replacement window. Never downgrade to Stat here.
			info, err := rt.FS.Lstat(candidate)
			if err != nil {
				// os.walk(..., onerror=None) skips entries it cannot inspect.
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				continue
			}
			query := []string{"rpm", "-qp", "--queryformat", "%{NAME}_|-%{EPOCH}_|-%{VERSION}_|-%{RELEASE}_|-%{ARCH}_|-none_|-%{INSTALLTIME}", candidate}
			cmd := runtime.Command(query...)
			cmd.MaxStdoutBytes, cmd.MaxStderrBytes = yumDownloadedMetadataLimit, yumDownloadedMetadataLimit
			result := rt.Runner.Run(ctx, cmd)
			if result.Err != nil {
				return nil, result.Err
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if result.ExitCode != 0 {
				return nil, fmt.Errorf("rpm exited with code %d: %s", result.ExitCode, result.Stderr)
			}
			if len(result.Stdout) > yumDownloadedMetadataLimit {
				return nil, errors.New("pkg.list_downloaded package metadata limit exceeded")
			}
			fields := strings.Split(strings.TrimSuffix(string(result.Stdout), "\n"), "_|-")
			osarch := ""
			if rt.Facts != nil {
				osarch = rt.Facts.CPU().Arch
			}
			pkgInfo, valid := yumDownloadedPackage(fields, osarch)
			if !valid {
				// bin_pkg_info returns None for malformed headers; yumpkg skips it.
				continue
			}
			ts, ok := fileCTime(info)
			if !ok {
				return nil, &runtime.UnsupportedError{Kind: "function", Name: "pkg.list_downloaded ctime"}
			}
			pkgTimestamp := ts.Unix()
			meta := map[string]any{
				"path": candidate, "size": info.Size(),
				"creation_date_time_t": pkgTimestamp,
				// datetime.fromtimestamp(...).isoformat() is timezone-naive;
				// Local matches Python's runtime timezone (UTC in supported builds).
				"creation_date_time": time.Unix(pkgTimestamp, 0).Local().Format("2006-01-02T15:04:05"),
			}
			versions, _ := ret[pkgInfo.name].(map[string]any)
			if versions == nil {
				versions = map[string]any{}
				ret[pkgInfo.name] = versions
			}
			versions[pkgInfo.version] = meta // source walk order gives last-wins duplicates.
		}
	}
	return ret, nil
}

// yumDownloadedPackage projects rpm_lowpkg.bin_pkg_info into yumpkg's
// name -> EVR result shape. Epoch zero is omitted from the public key.
func yumDownloadedPackage(fields []string, osarch string) (yumPackageInfo, bool) {
	if len(fields) != 7 || fields[0] == "" || fields[2] == "" || fields[4] == "" {
		return yumPackageInfo{}, false
	}
	epoch := fields[1]
	if epoch == "" || epoch == "(none)" {
		epoch = "0"
	}
	version := fields[2]
	if epoch != "0" {
		version = epoch + ":" + version
	}
	if fields[3] != "" && fields[3] != "(none)" {
		version += "-" + fields[3]
	}
	if osarch == "" {
		// Hermetic callers may omit facts; resolve_name treats the package
		// architecture as the local architecture in that compatibility case.
		osarch = fields[4]
	}
	return yumPackageInfo{name: yumResolvedRecordName(fields[0], fields[4], osarch), base: fields[0], arch: fields[4], version: version, repoid: fields[5]}, true
}

func validateYUMArgs(function string, a map[string]any) error {
	allowed := map[string]bool{}
	switch function {
	case "file_list", "file_dict":
		allowed = map[string]bool{"packages": true, "root": true}
	case "owner":
		allowed = map[string]bool{"paths": true, "root": true}
	case "info_installed":
		allowed = map[string]bool{"names": true, "all_versions": true, "root": true, "attr": true}
	case "normalize_name", "parse_arch":
		allowed = map[string]bool{"name": true}
	case "version_cmp":
		allowed = map[string]bool{"pkg1": true, "pkg2": true, "ignore_epoch": true}
	case "clean_metadata":
		allowed = map[string]bool{"repo": true, "fromrepo": true, "enablerepo": true, "disablerepo": true, "branch": true, "disableexcludes": true, "setopt": true, "check_update": true}
	case "list_upgrades", "upgrade_available":
		allowed = map[string]bool{"refresh": true, "repo": true, "fromrepo": true, "enablerepo": true, "disablerepo": true, "branch": true, "disableexcludes": true, "setopt": true}
		if function == "upgrade_available" {
			allowed["name"] = true
		}
	case "list_holds":
		allowed = map[string]bool{"pattern": true, "full": true}
	case "list_patches":
		allowed = map[string]bool{"refresh": true}
	case "list_installed_patches":
		allowed = map[string]bool{}
	case "services_need_restart":
		allowed = map[string]bool{}
	case "group_list":
		allowed = map[string]bool{}
	case "group_info":
		allowed = map[string]bool{"name": true, "expand": true, "ignore_groups": true, "fromrepo": true, "enablerepo": true, "disablerepo": true}
	case "group_diff":
		allowed = map[string]bool{"name": true, "fromrepo": true, "enablerepo": true, "disablerepo": true}
	case "verify":
		allowed = map[string]bool{"names": true, "root": true, "verify_options": true, "ignore_types": true}
	case "modified":
		allowed = map[string]bool{"names": true, "root": true, "size": true, "mode": true, "checksum": true, "device": true, "symlink": true, "owner": true, "group": true, "time": true, "capabilities": true}
	case "list_downloaded":
		// Salt's list_downloaded accepts **kwargs but does not consume any;
		// keep this provider contract explicit rather than inventing root remapping.
		return nil
	default:
		return nil
	}
	for key := range a {
		if !allowed[key] {
			return fmt.Errorf("YUM function %q: unsupported argument %q", function, key)
		}
	}
	for _, key := range []string{"packages", "paths", "names"} {
		if v, present := a[key]; present && v != nil {
			if function == "verify" && key == "names" {
				continue
			}
			if _, ok := v.([]string); !ok {
				return fmt.Errorf("argument %q must be a string list", key)
			}
		}
	}
	for _, key := range []string{"root", "attr", "pkg1", "pkg2", "name"} {
		if v, present := a[key]; present && v != nil {
			switch v.(type) {
			case string, *string:
			default:
				return fmt.Errorf("argument %q must be a string", key)
			}
		}
	}
	if function == "modified" {
		for _, key := range []string{"size", "mode", "checksum", "device", "symlink", "owner", "group", "time", "capabilities"} {
			if v, present := a[key]; present && v != nil {
				switch v.(type) {
				case bool, *bool:
				default:
					return fmt.Errorf("argument %q must be a boolean", key)
				}
			}
		}
	}
	if v, present := a["verify_options"]; present && v != nil {
		if _, err := yumVerifyValues(v); err != nil {
			return err
		}
	}
	if v, present := a["ignore_types"]; present && v != nil {
		if _, err := yumVerifyValues(v); err != nil {
			return err
		}
	}
	for _, key := range []string{"all_versions", "ignore_epoch"} {
		if v, present := a[key]; present && v != nil {
			switch v.(type) {
			case bool, *bool:
			default:
				return fmt.Errorf("argument %q must be a boolean", key)
			}
		}
	}
	if v, present := a["expand"]; present && v != nil {
		switch v.(type) {
		case bool, *bool:
		default:
			return errors.New(`argument "expand" must be a boolean`)
		}
	}
	if v, present := a["ignore_groups"]; present && v != nil {
		if _, ok := v.([]string); !ok {
			return errors.New(`argument "ignore_groups" must be a string list`)
		}
	}
	if v, present := a["refresh"]; present && v != nil {
		switch v.(type) {
		case bool, *bool:
		default:
			return errors.New(`argument "refresh" must be a boolean`)
		}
	}
	if v, present := a["full"]; present && v != nil {
		switch v.(type) {
		case bool, *bool:
		default:
			return errors.New(`argument "full" must be a boolean`)
		}
	}
	if v, present := a["pattern"]; present && v != nil {
		switch v.(type) {
		case string, *string:
		default:
			return errors.New(`argument "pattern" must be a string`)
		}
	}
	for _, key := range []string{"repo", "fromrepo", "branch", "disableexcludes"} {
		if v, present := a[key]; present && v != nil {
			if _, ok := yumStringArg(a, key); !ok {
				return fmt.Errorf("argument %q must be a string", key)
			}
		}
	}
	for _, key := range []string{"enablerepo", "disablerepo", "setopt"} {
		if v, present := a[key]; present && v != nil {
			if _, err := yumStringListArg(a, key); err != nil {
				return err
			}
		}
	}
	if function == "group_info" {
		for _, key := range []string{"fromrepo"} {
			if v, present := a[key]; present && v != nil {
				if _, ok := yumStringArg(a, key); !ok {
					return fmt.Errorf("argument %q must be a string", key)
				}
			}
		}
		for _, key := range []string{"enablerepo", "disablerepo"} {
			if v, present := a[key]; present && v != nil {
				if _, err := yumStringListArg(a, key); err != nil {
					return err
				}
			}
		}
	}
	if function == "group_diff" {
		name, ok := yumStringArg(a, "name")
		if !ok || name == "" {
			return errors.New(`argument "name" must be a non-empty string`)
		}
		if err := validateYUMGroupToken(name); err != nil {
			return fmt.Errorf(`argument "name": %w`, err)
		}
	}
	if v, present := a["check_update"]; present && v != nil {
		switch v.(type) {
		case bool, *bool:
		default:
			return errors.New(`argument "check_update" must be a boolean`)
		}
	}
	if function == "upgrade_available" {
		name, ok := yumStringArg(a, "name")
		if !ok || name == "" {
			return errors.New(`argument "name" must be a non-empty string`)
		}
		if err := validateYUMOption(name); err != nil {
			return fmt.Errorf(`argument "name": %w`, err)
		}
	}
	return nil
}

// yumVerifyValues follows saltstack/salt/modules/rpm_lowpkg.py:180-205:
// strings are comma-separated while list elements are passed through as-is.
// The source accepts arbitrary option/type values; only argv-token safety is
// enforced here because the command is executed without a shell.
func yumVerifyValues(value any) ([]string, error) {
	var values []string
	switch v := value.(type) {
	case string:
		for _, item := range strings.Split(v, ",") {
			values = append(values, strings.TrimSpace(item))
		}
	case []string:
		values = append(values, v...)
	default:
		return nil, errors.New("verify options and types must be a string or string list")
	}
	for _, item := range values {
		if err := validateYUMArgToken(item); err != nil {
			return nil, fmt.Errorf("invalid rpm verify value %q: %w", item, err)
		}
	}
	return values, nil
}

func validateYUMArgToken(value string) error {
	if value == "" {
		return errors.New("must not be empty")
	}
	if strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f || unicode.IsSpace(r) }) >= 0 {
		return errors.New("must not contain control characters or whitespace")
	}
	if strings.HasPrefix(value, "-") {
		return errors.New("must not begin with '-'")
	}
	return nil
}

func yumVerify(ctx context.Context, rt *runtime.Runtime, manager string, a map[string]any) (any, error) {
	if manager != "yum" && manager != "dnf" && manager != "dnf5" {
		return nil, ErrUnsupportedYUM
	}
	if rt == nil || rt.Runner == nil {
		return nil, errors.New("YUM verify requires a runner")
	}
	names, err := yumVerifyNames(a["names"])
	if err != nil {
		return nil, err
	}
	cmd := []string{"rpm"}
	if root := stringArg(a["root"]); root != "" {
		if err := validateYUMArgToken(root); err != nil {
			return nil, fmt.Errorf("argument \"root\": %w", err)
		}
		cmd = append(cmd, "--root", root)
	}
	options, err := yumVerifyValuesDefault(a["verify_options"])
	if err != nil {
		return nil, err
	}
	ignore, err := yumVerifyValuesDefault(a["ignore_types"])
	if err != nil {
		return nil, err
	}
	for _, option := range options {
		cmd = append(cmd, "--"+option)
	}
	if len(names) == 0 {
		cmd = append(cmd, "-Va")
	} else {
		cmd = append(cmd, "-V")
		cmd = append(cmd, names...)
	}
	command := runtime.Command(cmd...)
	command.Shell = false
	command.MaxStdoutBytes, command.MaxStderrBytes = yumVerifyOutputLimit, yumVerifyOutputLimit
	res := rt.Runner.Run(ctx, command)
	if res.Err != nil {
		return nil, res.Err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stdout := strings.TrimSpace(string(res.Stdout))
	if stdout == "" && res.ExitCode != 0 {
		msg := "Failed to verify package(s)"
		if len(res.Stderr) != 0 {
			msg += ": " + string(res.Stderr)
		}
		return nil, errors.New(msg)
	}
	ignored := make(map[string]bool, len(ignore))
	for _, item := range ignore {
		ignored[item] = true
	}
	return parseYumVerify(string(res.Stdout), ignored), nil
}

var yumModifiedFlags = []struct {
	status byte
	name   string
}{
	{'S', "size"}, {'M', "mode"}, {'5', "checksum"}, {'D', "device"},
	{'L', "symlink"}, {'U', "owner"}, {'G', "group"}, {'T', "time"}, {'P', "capabilities"},
}

func yumModified(ctx context.Context, rt *runtime.Runtime, a map[string]any) (any, error) {
	if rt == nil || rt.Runner == nil {
		return nil, errors.New("YUM modified requires a runner")
	}
	names, err := yumModifiedNames(a["names"])
	if err != nil {
		return nil, err
	}
	root := stringArg(a["root"])
	if root != "" {
		if err := validateYUMArgToken(root); err != nil {
			return nil, fmt.Errorf("argument \"root\": %w", err)
		}
	}
	cmd := []string{"rpm"}
	if root != "" {
		cmd = append(cmd, "--root", root)
	}
	cmd = append(cmd, "-Va")
	cmd = append(cmd, names...)
	command := runtime.Command(cmd...)
	command.MaxStdoutBytes, command.MaxStderrBytes = yumModifiedOutputLimit, yumModifiedOutputLimit
	res := rt.Runner.Run(ctx, command)
	if res.Err != nil {
		return nil, res.Err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if res.ExitCode > 1 {
		return map[string]any{"retcode": res.ExitCode, "stderr": string(res.Stderr)}, nil
	}
	if res.ExitCode == 0 {
		return map[string]any{}, nil
	}
	parsed, err := parseYumModified(string(res.Stdout), a)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

func yumModifiedNames(value any) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	names, ok := value.([]string)
	if !ok {
		return nil, errors.New(`argument "names" must be a string list`)
	}
	for _, name := range names {
		if err := validateYUMArgToken(name); err != nil {
			return nil, fmt.Errorf("invalid package name %q: %w", name, err)
		}
	}
	return append([]string(nil), names...), nil
}

var yumModifiedSplit = regexp.MustCompile(`\s+`)

func parseYumModified(output string, args map[string]any) (map[string]any, error) {
	all := make(map[string]any)
	lines := strings.Split(output, "\n")
	// salt.utils.itertools.split suppresses the delimiter-produced terminal
	// record, but does not discard malformed records in the stream.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for lineNo, raw := range lines {
		fields := yumModifiedSplit.Split(raw, -1)
		if raw == "" || fields[0] == "" || (len(fields) != 2 && len(fields) != 3) {
			return nil, fmt.Errorf("yum modified: malformed record on line %d", lineNo+1)
		}
		changes, file := fields[0], fields[len(fields)-1]
		// rpm -Va historically emitted eight status columns.  Salt appends
		// the capabilities column for those records before interpreting the
		// status string, so preserve that source-compatible slot here.
		if len(changes) == 8 {
			changes += "."
		}
		stats := make([]string, 0, len(yumModifiedFlags)+1)
		for i, flag := range yumModifiedFlags {
			// rpm's status alphabet is extensible.  Salt's positional parser
			// treats every non-dot marker as a change, including unknown ones.
			if i < len(changes) && changes[i] != '.' {
				stats = append(stats, flag.name)
			}
		}
		if len(fields) == 3 {
			stats = append(stats, "config")
		}
		all[file] = stats
	}
	filtered := make(map[string]any, len(all))
	for file, value := range all {
		stats := value.([]string)
		set := make(map[string]bool, len(stats))
		for _, stat := range stats {
			set[stat] = true
		}
		include := true
		for _, flag := range yumModifiedFlags {
			v, present := args[flag.name]
			if !present || v == nil {
				continue
			}
			want, ok := v.(bool)
			if !ok {
				if ptr, ok := v.(*bool); ok && ptr != nil {
					want = *ptr
				} else {
					continue
				}
			}
			if want != set[flag.name] {
				include = false
				break
			}
		}
		if include {
			filtered[file] = stats
		}
	}
	return filtered, nil
}

func yumVerifyValuesDefault(value any) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	return yumVerifyValues(value)
}

func yumVerifyNames(value any) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	var names []string
	switch v := value.(type) {
	case string:
		names = []string{v}
	case []string:
		names = append(names, v...)
	default:
		return nil, errors.New(`argument "names" must be a string or string list`)
	}
	for _, name := range names {
		if err := validateYUMArgToken(name); err != nil {
			return nil, fmt.Errorf("invalid package name %q: %w", name, err)
		}
	}
	return names, nil
}

func parseYumVerify(output string, ignored map[string]bool) map[string]any {
	ret := map[string]any{}
	flags := []struct {
		flag byte
		name string
	}{
		{'S', "size"}, {'M', "mode"}, {'5', "md5sum"}, {'D', "device major/minor number"},
		{'L', "readlink path"}, {'U', "user"}, {'G', "group"}, {'T', "mtime"}, {'P', "capabilities"},
	}
	types := map[byte]string{'c': "config", 'd': "doc", 'g': "ghost", 'l': "license", 'r': "readme"}
	for _, raw := range strings.Split(output, "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		line := raw
		missing := strings.Contains(line, "missing")
		if missing {
			line = " " + line
		}
		if len(line) < 13 {
			continue
		}
		entry := map[string]any{}
		if missing {
			entry["missing"] = true
		} else {
			entry["mismatch"] = []string{}
		}
		if typ, ok := types[line[11]]; ok {
			entry["type"] = typ
		}
		if typ, ok := entry["type"].(string); ok && ignored[typ] {
			continue
		}
		if !missing {
			mismatch := entry["mismatch"].([]string)
			for index, item := range flags {
				if line[index] == byte(item.flag) {
					mismatch = append(mismatch, item.name)
				}
			}
			entry["mismatch"] = mismatch
		}
		ret[line[13:]] = entry
	}
	return ret
}

type yumPackageInfo struct {
	name, base, arch, version, repoid string
}

// yumPkgInfo mirrors yumpkg._yum_pkginfo: output is tokenized as whitespace,
// headers are removed only when they occupy a complete line, and incomplete
// triples are ignored rather than invented.
func yumPkgInfo(output, osarch string) []yumPackageInfo {
	lines := strings.Split(output, "\n")
	var tokens []string
	for _, line := range lines {
		lower := strings.ToLower(line)
		switch lower {
		case "installed packages", "available packages", "available upgrades", "updated packages", "upgraded packages":
			continue
		}
		tokens = append(tokens, strings.Fields(line)...)
	}
	ret := make([]yumPackageInfo, 0, len(tokens)/3)
	for i := 0; i+2 < len(tokens); i += 3 {
		base, arch := yumRecordNameArch(tokens[i], osarch)
		name := yumResolvedRecordName(base, arch, osarch)
		ret = append(ret, yumPackageInfo{name: name, base: base, arch: arch, version: strings.TrimRight(tokens[i+1], "-"), repoid: strings.TrimLeft(tokens[i+2], "@")})
	}
	return ret
}

const yumInstalledQueryFormat = "%{NAME}_|-%{EPOCH}_|-%{VERSION}_|-%{RELEASE}_|-%{ARCH}_|-(none)_|-%{INSTALLTIME}\n"

// yumInstalledPkgInfo is the bounded equivalent of rpm.parse_pkginfo for the
// list_pkgs(versions_as_list=True) data needed by latest_version.  Keeping
// records rather than reducing to one version is important for multilib and
// parallel RPM installs.
func yumInstalledPkgInfo(output, osarch string) []yumPackageInfo {
	ret := []yumPackageInfo{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(line, "_|-")
		if len(fields) != 7 {
			continue
		}
		base, epoch, version, release, arch := fields[0], fields[1], fields[2], fields[3], fields[4]
		if base == "" || arch == "" {
			continue
		}
		if epoch == "(none)" || epoch == "" {
			epoch = "0"
		}
		evr := epoch + ":" + version
		if release != "" && release != "(none)" {
			evr += "-" + release
		}
		ret = append(ret, yumPackageInfo{
			name: yumResolvedRecordName(base, arch, osarch), base: base,
			arch: arch, version: evr, repoid: fields[5],
		})
	}
	return ret
}

// yumNameMatches mirrors latest_version's source comparison: the requested
// name is not normalized, while each package record has already passed
// through rpm.resolve_name in yumPkgInfo/yumInstalledPkgInfo.
func yumNameMatches(info yumPackageInfo, requested string) bool {
	return info.name == requested
}

func yumCandidateArchMatches(info yumPackageInfo, requested, osarch string) bool {
	arch := yumRequestedArch(requested, osarch)
	return info.arch == "noarch" || info.arch == arch ||
		check32RPMArch(info.arch, osarch)
}

// yumRequestedArch mirrors yumpkg.latest_version's requested-name branch.
// Unlike candidate records, an unknown final-dot suffix is not an explicit
// architecture and therefore falls back to the machine architecture.
func yumRequestedArch(requested, osarch string) string {
	if arch, known := yumArch(requested); known {
		if _, requestedArch := yumRequestedArchitectures[arch]; requestedArch {
			return arch
		}
	}
	return osarch
}

// check32RPMArch is the pinned rpm.check_32 rule: only two 32-bit x86/ARM
// arches are compatible. The second argument is always the OS architecture,
// matching yumpkg.latest_version's call to rpm.check_32(pkg.arch).
func check32RPMArch(arch, osarch string) bool {
	return (is32RPMArch(arch) && is32RPMArch(osarch)) || (is32ARMArch(arch) && is32ARMArch(osarch))
}

func yumRefresh(ctx context.Context, rt *runtime.Runtime, manager string, options []string, checkUpdate bool) error {
	commands := [][]string{{manager, "--quiet", "--assumeyes", "clean", "expire-cache"}}
	if checkUpdate {
		update := []string{manager, "--quiet", "--assumeyes", "check-update"}
		if yumRHEL7(rt) {
			update = append(update, "--setopt=autocheck_running_kernel=false")
		}
		commands = append(commands, update)
	}
	for _, argv := range commands {
		argv = append(argv, options...)
		cmd := runtime.Command(argv...)
		cmd.MaxStdoutBytes, cmd.MaxStderrBytes = yumUpgradeOutputLimit, yumUpgradeOutputLimit
		res := rt.Runner.Run(ctx, cmd)
		if res.Err != nil {
			return res.Err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

func yumListUpgrades(ctx context.Context, rt *runtime.Runtime, manager string, a map[string]any) (any, error) {
	options, err := yumMetadataOptions(a)
	if err != nil {
		return nil, err
	}
	refresh, err := yumBoolArg(a, "refresh", true)
	if err != nil {
		return nil, err
	}
	if rt == nil || rt.Runner == nil || rt.Facts == nil {
		return nil, errors.New("YUM list_upgrades requires a runner and facts")
	}
	if refresh {
		if err := yumRefresh(ctx, rt, manager, options, false); err != nil {
			return nil, err
		}
	}
	action := "updates"
	if manager == "dnf" || manager == "dnf5" {
		action = "--upgrades"
	}
	argv := append([]string{manager, "--quiet"}, options...)
	argv = append(argv, "list", action)
	cmd := runtime.Command(argv...)
	cmd.MaxStdoutBytes, cmd.MaxStderrBytes = yumUpgradeOutputLimit, yumUpgradeOutputLimit
	res := rt.Runner.Run(ctx, cmd)
	if res.Err != nil {
		return nil, res.Err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// yumpkg checks for "Error:" in the result mapping, which tests keys
	// rather than stdout/stderr; therefore every completed result is parsed.
	ret := map[string]string{}
	for _, info := range yumPkgInfo(string(res.Stdout), rt.Facts.CPU().Arch) {
		ret[info.name] = info.version
	}
	return ret, nil
}

func yumUpgradeAvailable(ctx context.Context, rt *runtime.Runtime, manager string, a map[string]any) (any, error) {
	name, _ := yumStringArg(a, "name")
	options, err := yumMetadataOptions(a)
	if err != nil {
		return nil, err
	}
	if rt == nil || rt.Runner == nil || rt.Facts == nil {
		return nil, errors.New("YUM upgrade_available requires a runner and facts")
	}
	refresh, err := yumBoolArg(a, "refresh", true)
	if err != nil {
		return nil, err
	}
	if refresh {
		if err := yumRefresh(ctx, rt, manager, options, true); err != nil {
			return nil, err
		}
	}
	// This query deliberately uses the same format as rpm.QUERYFORMAT and is
	// parsed locally. The generic Provider.List contract intentionally reduces
	// duplicates, which is not sufficient for RPM's multiple-installed-EVR
	// semantics.
	installedCmd := runtime.Command("rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", yumInstalledQueryFormat)
	installedCmd.MaxStdoutBytes, installedCmd.MaxStderrBytes = yumUpgradeOutputLimit, yumUpgradeOutputLimit
	installedResult := rt.Runner.Run(ctx, installedCmd)
	if installedResult.Err != nil {
		return nil, installedResult.Err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	installed := yumInstalledPkgInfo(string(installedResult.Stdout), rt.Facts.CPU().Arch)
	argv := append([]string{manager, "--quiet"}, options...)
	argv = append(argv, "list", "available", name)
	cmd := runtime.Command(argv...)
	cmd.MaxStdoutBytes, cmd.MaxStderrBytes = yumUpgradeOutputLimit, yumUpgradeOutputLimit
	res := rt.Runner.Run(ctx, cmd)
	if res.Err != nil {
		return nil, res.Err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// latest_version explicitly discards the available list when the manager
	// completed with a nonzero retcode. This differs from list_upgrades, whose
	// source mapping-key check still permits parsing completed stdout.
	if res.ExitCode != 0 {
		return false, nil
	}
	updates := yumPkgInfo(string(res.Stdout), rt.Facts.CPU().Arch)
	sort.SliceStable(updates, func(i, j int) bool {
		return yumLooseVersionCmp(updates[i].version, updates[j].version) > 0
	})
	for _, candidate := range updates {
		if !yumNameMatches(candidate, name) || !yumCandidateArchMatches(candidate, name, rt.Facts.CPU().Arch) {
			continue
		}
		newer := true
		installedForName := false
		for _, current := range installed {
			if !yumNameMatches(current, name) {
				continue
			}
			installedForName = true
			if yumVersionCmp(current.version, candidate.version, false) >= 0 {
				newer = false
				break
			}
		}
		if newer || !installedForName {
			return true, nil
		}
	}
	return false, nil
}

// yumGroupDiff mirrors the pinned yumpkg.group_diff implementation: installed
// packages come from list_pkgs (the provider's List method), while group
// membership comes from group_info with expansion forced on. The source
// yumpkg.py implementation accepts only name and the three repository options.
func yumGroupDiff(ctx context.Context, rt *runtime.Runtime, p *commandProvider, a map[string]any) (any, error) {
	installed, err := p.List(ctx, rt)
	if err != nil {
		return nil, err
	}
	groupArgs := map[string]any{"name": a["name"], "expand": true}
	for _, key := range []string{"fromrepo", "enablerepo", "disablerepo"} {
		if value, ok := a[key]; ok {
			groupArgs[key] = value
		}
	}
	infoAny, err := yumGroupInfo(ctx, rt, p.spec.manager, groupArgs)
	if err != nil {
		return nil, err
	}
	info, ok := infoAny.(map[string]any)
	if !ok {
		return nil, errors.New("YUM group_diff: malformed group_info result")
	}
	result := make(map[string]any, 4)
	for _, category := range []string{"mandatory", "optional", "default", "conditional"} {
		members, ok := info[category].([]string)
		if !ok {
			return nil, fmt.Errorf("YUM group_diff: malformed group_info %q", category)
		}
		// Allocate fresh slices: callers must not observe or mutate group_info's
		// source-backed result while consuming the diff.
		got := map[string]any{"installed": []string{}, "not installed": []string{}}
		for _, member := range members {
			key := "not installed"
			if _, present := installed[member]; present {
				key = "installed"
			}
			got[key] = append(got[key].([]string), member)
		}
		result[category] = got
	}
	return result, nil
}

// yumGroupList mirrors yumpkg.group_list. The command deliberately uses the
// provider's selected manager and preserves the source's tolerant parsing:
// command errors are fatal, while a nonzero child status does not discard
// parseable stdout.
func yumGroupList(ctx context.Context, rt *runtime.Runtime, manager string) (any, error) {
	if manager != "yum" && manager != "dnf" && manager != "dnf5" {
		return nil, ErrUnsupportedYUM
	}
	if rt == nil || rt.Runner == nil {
		return nil, errors.New("YUM group_list requires a runner")
	}
	cmd := runtime.Command(manager, "grouplist", "hidden")
	cmd.MaxStdoutBytes, cmd.MaxStderrBytes = yumGroupsOutputLimit, yumGroupsOutputLimit
	res := rt.Runner.Run(ctx, cmd)
	if res.Err != nil {
		return nil, res.Err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	ret := map[string]any{
		"installed":              []string{},
		"available":              []string{},
		"installed environments": []string{},
		"available environments": []string{},
		"available languages":    map[string]any{},
	}
	sectionMap := map[string]string{
		"installed groups:":             "installed",
		"available groups:":             "available",
		"installed environment groups:": "installed environments",
		"available environment groups:": "available environments",
		"available language groups:":    "available languages",
	}
	key := ""
	lines := yumGroupInfoLines(string(res.Stdout))
	for _, line := range lines {
		lineLC := strings.ToLower(line)
		if lineLC == "done" {
			break
		}
		if section, ok := sectionMap[lineLC]; ok && section != key {
			key = section
			continue
		}
		if key == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if key != "available languages" {
			ret[key] = append(ret[key].([]string), trimmed)
			continue
		}
		match := yumLanguageGroupLine.FindStringSubmatch(trimmed)
		if len(match) == 3 {
			ret[key].(map[string]any)[trimmed] = map[string]any{"name": match[1], "language": match[2]}
		}
	}
	return ret, nil
}

// yumGroupInfo mirrors yumpkg.group_info's deliberately tolerant parser. The
// recursion guard is stricter than Salt's unbounded recursion because this
// runtime must remain safe when repository metadata is adversarial.
func yumGroupInfo(ctx context.Context, rt *runtime.Runtime, manager string, a map[string]any) (any, error) {
	name, ok := yumStringArg(a, "name")
	if !ok || name == "" {
		return nil, errors.New(`argument "name" must be a non-empty string`)
	}
	if err := validateYUMGroupToken(name); err != nil {
		return nil, fmt.Errorf(`argument "name": %w`, err)
	}
	expand, err := yumBoolArg(a, "expand", false)
	if err != nil {
		return nil, err
	}
	ignored := []string{}
	if value, present := a["ignore_groups"]; present && value != nil {
		var ok bool
		ignored, ok = value.([]string)
		if !ok {
			return nil, errors.New(`argument "ignore_groups" must be a string list`)
		}
		ignored = append([]string(nil), ignored...)
	}
	options, err := yumGroupInfoOptions(a)
	if err != nil {
		return nil, err
	}
	state := &yumGroupInfoState{completedGroups: make(map[string]struct{}, len(ignored))}
	for _, group := range ignored {
		state.completedGroups[group] = struct{}{}
	}
	if expand {
		state.completedGroups[name] = struct{}{}
	}
	result, err := yumGroupInfoWalk(ctx, rt, manager, name, expand, options, 0, state)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func yumGroupInfoOptions(a map[string]any) ([]string, error) {
	fromrepo, _ := yumStringArg(a, "fromrepo")
	if fromrepo != "" {
		if err := validateYUMGroupToken(fromrepo); err != nil {
			return nil, fmt.Errorf(`argument "fromrepo": %w`, err)
		}
		return []string{"--disablerepo=*", "--enablerepo=" + fromrepo}, nil
	}
	options := []string{}
	for _, key := range []string{"disablerepo", "enablerepo"} {
		values, err := yumStringListArg(a, key)
		if err != nil {
			return nil, err
		}
		for _, value := range values {
			if err := validateYUMGroupToken(value); err != nil {
				return nil, fmt.Errorf(`argument %q: %w`, key, err)
			}
			options = append(options, "--"+key+"="+value)
		}
	}
	return options, nil
}

func validateYUMGroupToken(value string) error {
	if err := validateYUMOption(value); err != nil {
		return err
	}
	for _, r := range value {
		switch r {
		case ';', '|', '&', '$', '>', '<', '`':
			return errors.New("value contains unsafe shell metacharacter")
		}
	}
	return nil
}

type yumGroupInfoState struct {
	completedGroups map[string]struct{}
	nodes           int
}

func yumGroupInfoWalk(ctx context.Context, rt *runtime.Runtime, manager, name string, expand bool, options []string, depth int, state *yumGroupInfoState) (map[string]any, error) {
	if depth > yumGroupMaxDepth {
		return nil, errors.New("YUM group_info recursion limit exceeded")
	}
	if state.nodes >= yumGroupMaxNodes {
		return nil, errors.New("YUM group_info recursion limit exceeded")
	}
	state.nodes++
	if rt == nil || rt.Runner == nil {
		return nil, errors.New("YUM group_info requires a runner")
	}
	cmdArgs := append([]string{manager, "--quiet"}, options...)
	cmdArgs = append(cmdArgs, "groupinfo", name)
	cmd := runtime.Command(cmdArgs...)
	cmd.MaxStdoutBytes, cmd.MaxStderrBytes = yumGroupInfoOutputLimit, yumGroupInfoOutputLimit
	res := rt.Runner.Run(ctx, cmd)
	if res.Err != nil {
		return nil, res.Err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ret := map[string]any{
		"mandatory": []string{}, "optional": []string{}, "default": []string{}, "conditional": []string{},
	}
	metadata := map[string]string{}
	// Salt's itertools.split(out, "\n") only recognizes LF. It also omits the
	// empty item after a terminal LF; retain that behavior without applying
	// Python's broader splitlines() set of separators.
	lines := strings.Split(string(res.Stdout), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		metadata[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
	}
	if value, ok := metadata["environment group"]; ok {
		ret["type"] = "environment group"
		ret["group"] = value
	} else if value, ok := metadata["group"]; ok {
		ret["type"] = "package group"
		ret["group"] = value
	}
	var groupValue string
	if value, ok := metadata["environment group"]; ok {
		groupValue = value
	} else if value, ok := metadata["group"]; ok {
		groupValue = value
	}
	var idValue string
	if value, ok := metadata["environment-id"]; ok {
		ret["id"] = value
		idValue = value
	} else if value, ok := metadata["group-id"]; ok {
		ret["id"] = value
		idValue = value
	}
	if groupValue == "" && idValue == "" {
		return nil, &yumGroupNotFoundError{name: name}
	}
	if _, ok := ret["group"]; !ok {
		ret["group"] = nil
	}
	if _, ok := ret["id"]; !ok {
		ret["id"] = nil
	}
	ret["description"] = metadata["description"]
	if ret["description"] == nil {
		ret["description"] = ""
	}
	typeNames := []string{"mandatory", "optional", "default", "conditional"}
	for _, typeName := range typeNames {
		entries := map[string]struct{}{}
		inSection := false
		for _, raw := range lines {
			line := strings.TrimSpace(raw)
			line = strings.TrimLeft(line, string([]byte("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")))
			match := regexp.MustCompile(`^(mandatory|optional|default|conditional) (?:groups|packages):\s*$`).FindStringSubmatch(strings.ToLower(line))
			if match != nil {
				if inSection {
					break
				}
				inSection = match[1] == typeName
				continue
			}
			if inSection && line != "" {
				entries[line] = struct{}{}
			}
		}
		values := map[string]struct{}{}
		if !expand || ret["type"] != "environment group" {
			for entry := range entries {
				values[entry] = struct{}{}
			}
			ret[typeName] = sortedYUMGroupValues(values)
			continue
		}
		for _, group := range sortedYUMGroupValues(entries) {
			if _, done := state.completedGroups[group]; done {
				continue
			}
			// Mark before the lookup/recursion so sibling branches and cycles share
			// one traversal state, rather than maintaining a per-path guard.
			state.completedGroups[group] = struct{}{}
			expanded, expandErr := yumGroupInfoWalk(ctx, rt, manager, "@"+group, true, options, depth+1, state)
			if errors.Is(expandErr, errYUMGroupNotFound) {
				expanded, expandErr = yumGroupInfoWalk(ctx, rt, manager, group, true, options, depth+1, state)
			}
			if expandErr != nil {
				return nil, expandErr
			}
			for _, category := range typeNames {
				for _, packageName := range expanded[category].([]string) {
					values[packageName] = struct{}{}
				}
			}
		}
		ret[typeName] = sortedYUMGroupValues(values)
	}
	return ret, nil
}

func yumGroupInfoLines(output string) []string {
	lines := strings.Split(output, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func sortedYUMGroupValues(values map[string]struct{}) []string {
	ret := make([]string, 0, len(values))
	for value := range values {
		ret = append(ret, value)
	}
	sort.Strings(ret)
	return ret
}

func yumServicesNeedRestart(ctx context.Context, rt *runtime.Runtime, manager string) (any, error) {
	if manager != "dnf" && manager != "dnf5" {
		return nil, errors.New("dnf or dnf5 is required to list outdated services.")
	}
	if rt == nil || rt.Facts == nil || rt.Facts.InitSystem() != "systemd" {
		return nil, errors.New("systemd is required to list outdated services.")
	}
	if rt.Runner == nil {
		return nil, errors.New("services_need_restart requires a runner")
	}
	res := rt.Runner.Run(ctx, yumBoundedCommand([]string{manager, "--quiet", "needs-restarting"}))
	if res.Err != nil {
		return nil, res.Err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	services := map[string]struct{}{}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		pid, _, hasDelimiter := strings.Cut(line, ":")
		pid = strings.TrimSpace(pid)
		if !hasDelimiter {
			continue
		}
		service, err := yumPIDToService(ctx, rt, pid)
		if err != nil {
			return nil, err
		}
		if service != "" {
			services[service] = struct{}{}
		}
	}
	out := make([]string, 0, len(services))
	for service := range services {
		out = append(out, service)
	}
	sort.Strings(out)
	return out, nil
}

func yumBoundedCommand(argv []string) process.Command {
	cmd := runtime.Command(argv...)
	cmd.MaxStdoutBytes, cmd.MaxStderrBytes = yumServicesOutputLimit, yumServicesOutputLimit
	return cmd
}

func yumPIDToService(ctx context.Context, rt *runtime.Runtime, pid string) (string, error) {
	res := rt.Runner.Run(ctx, yumBoundedCommand([]string{"systemctl", "--output", "json", "status", pid}))
	if res.Err != nil {
		return "", res.Err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", nil
	}
	var status map[string]any
	if err := json.Unmarshal(res.Stdout, &status); err != nil {
		return "", nil
	}
	name, ok := status["_SYSTEMD_UNIT"].(string)
	if !ok || !strings.HasSuffix(name, ".service") {
		return "", nil
	}
	name = strings.TrimSuffix(name, ".service")
	if name == "" {
		return "", nil
	}
	return name, nil
}

func yumListPatches(ctx context.Context, rt *runtime.Runtime, manager string, installedOnly bool, a map[string]any) (any, error) {
	if manager != "yum" && manager != "dnf" {
		return nil, ErrUnsupportedYUM
	}
	if rt == nil || rt.Runner == nil {
		return nil, errors.New("YUM list_patches requires a runner")
	}
	refresh := false
	if value, ok := a["refresh"]; ok && value != nil {
		switch v := value.(type) {
		case bool:
			refresh = v
		case *bool:
			if v != nil {
				refresh = *v
			}
		}
	}
	if refresh {
		if err := yumPatchesRefreshDB(ctx, rt, manager); err != nil {
			return nil, err
		}
	}
	cmd := runtime.Command(manager, "--quiet", "updateinfo", "list", "all")
	cmd.MaxStdoutBytes, cmd.MaxStderrBytes = yumPatchesOutputLimit, yumPatchesOutputLimit
	res := rt.Runner.Run(ctx, cmd)
	if res.Err != nil {
		return nil, res.Err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// yumpkg._get_patches uses cmd.run_stdout: a nonzero child retcode does
	// not discard parseable stdout. Runner errors remain fatal, but otherwise
	// parse the captured stream exactly as the source does.
	patches := map[string]any{}
	for _, line := range sourceSplitLines(string(res.Stdout)) {
		match := yumPatchesLine.FindStringSubmatch(line)
		if len(match) != 5 {
			continue
		}
		advisory, packageName := match[2], match[4]
		entry, exists := patches[advisory]
		if !exists {
			patches[advisory] = map[string]any{"installed": match[1] == "i", "summary": []string{packageName}}
			continue
		}
		patch := entry.(map[string]any)
		patch["summary"] = append(patch["summary"].([]string), packageName)
		if match[1] != "i" {
			patch["installed"] = false
		}
	}
	if installedOnly {
		for advisory, value := range patches {
			if !value.(map[string]any)["installed"].(bool) {
				delete(patches, advisory)
			}
		}
	}
	return patches, nil
}

// yumPatchesRefreshDB follows yumpkg.refresh_db's retcode policy.  The
// metadata clean/check commands are best-effort: command-runner failures and
// cancellation abort, while manager exit codes are deliberately ignored so
// updateinfo still runs, including yum's check-update=100 result.
func yumPatchesRefreshDB(ctx context.Context, rt *runtime.Runtime, manager string) error {
	for _, argv := range yumPatchesRefreshCommands(rt, manager) {
		cmd := runtime.Command(argv...)
		cmd.MaxStdoutBytes, cmd.MaxStderrBytes = yumPatchesOutputLimit, yumPatchesOutputLimit
		if result := rt.Runner.Run(ctx, cmd); result.Err != nil {
			return result.Err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

func yumPatchesRefreshCommands(rt *runtime.Runtime, manager string) [][]string {
	clean := []string{manager, "--quiet", "--assumeyes", "clean", "expire-cache"}
	check := []string{manager, "--quiet", "--assumeyes", "check-update"}
	if yumRHEL7(rt) {
		check = append(check, "--setopt=autocheck_running_kernel=false")
	}
	return [][]string{clean, check}
}

const yumHoldOutputLimit = 1 << 20
const yumHoldPattern = `[\w+]+(?:[.-][^-]+)*`

func yumListHolds(ctx context.Context, rt *runtime.Runtime, manager string, a map[string]any) (any, error) {
	if manager == "dnf5" {
		// The standard library has no TOML parser and adding a permissive parser
		// here would make malformed lock data unsafe to interpret. Fail closed
		// before consulting FS; a typed TOML dependency can enable this later.
		return nil, &runtime.UnsupportedError{Kind: "function", Name: "pkg.list_holds.dnf5"}
	}
	plugin, err := yumVersionlockPlugin(rt, manager)
	if err != nil {
		return nil, err
	}
	pattern := yumHoldPattern
	if value, ok := yumStringArg(a, "pattern"); ok {
		pattern = value
	}
	full := true
	if value, ok := a["full"]; ok && value != nil {
		switch v := value.(type) {
		case bool:
			full = v
		case *bool:
			if v != nil {
				full = *v
			}
		}
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return nil, fmt.Errorf("argument \"pattern\": invalid regular expression: %w", err)
	}
	lockPattern := pattern + `-\S+`
	if manager == "yum" {
		if full {
			lockPattern = `\d+:` + lockPattern
		} else {
			lockPattern = `\d+:(` + lockPattern + `)`
		}
	} else if !full {
		lockPattern = `(` + lockPattern + `)`
	}
	if full {
		lockPattern = `(` + lockPattern + `)`
	}
	re, err := regexp.Compile(lockPattern)
	if err != nil {
		return nil, fmt.Errorf("argument \"pattern\": invalid regular expression: %w", err)
	}
	if rt == nil || rt.Runner == nil {
		return nil, errors.New("YUM list_holds requires a runner")
	}
	installed, err := (&commandProvider{spec: rpmSpec(manager)}).List(ctx, rt)
	if err != nil {
		return nil, err
	}
	if _, ok := installed[plugin]; !ok {
		return nil, fmt.Errorf("Cannot proceed, %s is not installed.", plugin)
	}
	cmd := runtime.Command(manager, "versionlock", "list")
	cmd.MaxStdoutBytes, cmd.MaxStderrBytes = yumHoldOutputLimit, yumHoldOutputLimit
	res := rt.Runner.Run(ctx, cmd)
	if res.Err != nil {
		return nil, res.Err
	}
	ret := []string{}
	for _, line := range sourceSplitLines(string(res.Stdout)) {
		match := re.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}
		value := match[1]
		if !full {
			value = strings.TrimSuffix(value, "."+value[strings.LastIndexByte(value, '.')+1:])
			if i := strings.LastIndexByte(value, '-'); i >= 0 {
				value = value[:i]
			}
			if i := strings.LastIndexByte(value, '-'); i >= 0 {
				value = value[:i]
			}
		}
		ret = append(ret, value)
	}
	return ret, nil
}

// yumVersionlockPlugin mirrors yumpkg._versionlock_pkg using typed facts.
// Unknown or malformed versions use the legacy RedHat branch, matching the
// source's pre-Python-3 package choice where no major fact is available.
func yumVersionlockPlugin(rt *runtime.Runtime, manager string) (string, error) {
	if manager == "yum" {
		return "yum-plugin-versionlock", nil
	}
	if manager != "dnf" {
		return "", &runtime.UnsupportedError{Kind: "function", Name: "pkg.list_holds." + manager}
	}
	if rt != nil && rt.Facts != nil {
		os := rt.Facts.OS()
		major := os.Version
		if i := strings.IndexByte(major, '.'); i >= 0 {
			major = major[:i]
		}
		if strings.EqualFold(os.ID, "fedora") {
			if n, err := strconv.Atoi(major); err == nil && n >= 26 {
				return "python3-dnf-plugin-versionlock", nil
			}
			return "python3-dnf-plugins-extras-versionlock", nil
		}
		if n, err := strconv.Atoi(major); err == nil && n >= 8 {
			return "python3-dnf-plugin-versionlock", nil
		}
	}
	return "python2-dnf-plugin-versionlock", nil
}

const yumMetadataOutputLimit = 1 << 20

func yumMetadataOptions(a map[string]any) ([]string, error) {
	for _, key := range []string{"repo", "fromrepo", "disableexcludes", "branch"} {
		if value, present := a[key]; present && value != nil {
			v, ok := yumStringArg(a, key)
			if !ok {
				return nil, fmt.Errorf("argument %q must be a string", key)
			}
			if v == "" {
				return nil, fmt.Errorf("argument %q: value must be non-empty", key)
			}
			if err := validateYUMOption(v); err != nil {
				return nil, fmt.Errorf("argument %q: %w", key, err)
			}
		}
	}
	fromrepo, _ := yumStringArg(a, "fromrepo")
	if fromrepo == "" {
		fromrepo, _ = yumStringArg(a, "repo")
	}
	options := []string{}
	if fromrepo != "" {
		options = append(options, "--disablerepo=*", "--enablerepo="+fromrepo)
	} else {
		for _, key := range []string{"disablerepo", "enablerepo"} {
			values, err := yumStringListArg(a, key)
			if err != nil {
				return nil, err
			}
			for _, value := range values {
				if err := validateYUMOption(value); err != nil {
					return nil, fmt.Errorf("argument %q: %w", key, err)
				}
				options = append(options, "--"+key+"="+value)
			}
		}
	}
	for _, key := range []string{"disableexcludes", "branch"} {
		if value, ok := yumStringArg(a, key); ok && value != "" {
			if err := validateYUMOption(value); err != nil {
				return nil, fmt.Errorf("argument %q: %w", key, err)
			}
			options = append(options, "--"+key+"="+value)
		}
	}
	setopts, err := yumStringListArg(a, "setopt")
	if err != nil {
		return nil, err
	}
	for _, value := range setopts {
		if err := validateYUMOption(value); err != nil {
			return nil, fmt.Errorf("argument %q: %w", "setopt", err)
		}
		options = append(options, "--setopt="+value)
	}
	return options, nil
}

func yumStringListArg(a map[string]any, key string) ([]string, error) {
	v, ok := a[key]
	if !ok || v == nil {
		return nil, nil
	}
	var values []string
	switch value := v.(type) {
	case string:
		if key == "setopt" {
			values = strings.Split(value, ",")
		} else {
			values = []string{value}
		}
	case []string:
		values = append([]string(nil), value...)
	case []any:
		values = make([]string, len(value))
		for i, item := range value {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("argument %q must be a string or string list", key)
			}
			values[i] = s
		}
	default:
		return nil, fmt.Errorf("argument %q must be a string or string list", key)
	}
	for i := range values {
		values[i] = strings.TrimSpace(values[i])
		if err := validateYUMOption(values[i]); err != nil {
			return nil, fmt.Errorf("argument %q: %w", key, err)
		}
	}
	return values, nil
}

func validateYUMOption(value string) error {
	if value == "" {
		return errors.New("value must be non-empty")
	}
	if strings.IndexByte(value, 0) >= 0 {
		return errors.New("value must contain no NUL")
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return errors.New("value must contain no control characters")
		}
	}
	return nil
}

func yumCleanMetadata(ctx context.Context, rt *runtime.Runtime, manager string, a map[string]any) (any, error) {
	options, err := yumMetadataOptions(a)
	if err != nil {
		return nil, err
	}
	checkUpdate, err := yumBoolArg(a, "check_update", true)
	if err != nil {
		return nil, err
	}
	if rt == nil || rt.Runner == nil {
		return nil, errors.New("YUM clean_metadata requires a runner")
	}
	clean := append([]string{manager, "--quiet", "--assumeyes", "clean", "expire-cache"}, options...)
	cleanCommand := runtime.Command(clean...)
	cleanCommand.MaxStdoutBytes = yumMetadataOutputLimit
	cleanCommand.MaxStderrBytes = yumMetadataOutputLimit
	result := rt.Runner.Run(ctx, cleanCommand)
	if result.Err != nil {
		return nil, result.Err
	}
	if !checkUpdate {
		return true, nil
	}
	update := append([]string{manager, "--quiet", "--assumeyes", "check-update"}, options...)
	if yumRHEL7(rt) {
		update = append([]string{manager, "--quiet", "--assumeyes", "check-update", "--setopt=autocheck_running_kernel=false"}, options...)
	}
	updateCommand := runtime.Command(update...)
	updateCommand.MaxStdoutBytes = yumMetadataOutputLimit
	updateCommand.MaxStderrBytes = yumMetadataOutputLimit
	result = rt.Runner.Run(ctx, updateCommand)
	if result.Err != nil {
		return nil, result.Err
	}
	switch result.ExitCode {
	case 100:
		return true, nil
	case 0:
		return nil, nil
	default:
		return false, nil
	}
}

// yumRHEL7 uses the existing typed OS facts. An absent or unparsable version
// deliberately defaults to false rather than assuming every RedHat host is 7.
func yumRHEL7(rt *runtime.Runtime) bool {
	if rt == nil || rt.Facts == nil {
		return false
	}
	os := rt.Facts.OS()
	if os.Family != "redhat" {
		return false
	}
	major := os.Version
	if i := strings.IndexByte(major, '.'); i >= 0 {
		major = major[:i]
	}
	return major == "7"
}

func yumBoolArg(a map[string]any, key string, fallback bool) (bool, error) {
	v, ok := a[key]
	if !ok || v == nil {
		return fallback, nil
	}
	switch value := v.(type) {
	case bool:
		return value, nil
	case *bool:
		if value == nil {
			return fallback, nil
		}
		return *value, nil
	default:
		return false, fmt.Errorf("argument %q must be a boolean", key)
	}
}

func yumFilesArgs(a map[string]any) ([]string, string, error) {
	p, ok := a["packages"]
	if !ok {
		p = []string{}
	}
	packages, ok := p.([]string)
	if !ok {
		return nil, "", errors.New("argument \"packages\" must be a string list")
	}
	root, err := yumRoot(a)
	return packages, root, err
}
func yumOwnerArgs(a map[string]any) ([]string, string, error) {
	p, ok := a["paths"]
	if !ok {
		p = []string{}
	}
	paths, ok := p.([]string)
	if !ok {
		return nil, "", errors.New("argument \"paths\" must be a string list")
	}
	root, err := yumRoot(a)
	return paths, root, err
}
func yumRoot(a map[string]any) (string, error) {
	v, ok := a["root"]
	if !ok {
		return "", nil
	}
	s, ok := v.(*string)
	if ok {
		if s == nil {
			return "", nil
		}
		return *s, nil
	}
	if s, ok := v.(string); ok {
		return s, nil
	}
	return "", errors.New("argument \"root\" must be a string")
}

func yumStringArg(a map[string]any, key string) (string, bool) {
	v, ok := a[key]
	if !ok || v == nil {
		return "", false
	}
	if s, ok := v.(string); ok {
		return s, true
	}
	if s, ok := v.(*string); ok && s != nil {
		return *s, true
	}
	return "", false
}

// sourceSplitLines implements Python str.splitlines(). In addition to the
// ASCII line endings, Python recognizes VT, FF, the C0 record separators, NEL,
// and the Unicode line and paragraph separators. A CRLF is one boundary.
func sourceSplitLines(s string) []string {
	if s == "" {
		return []string{}
	}
	runes := []rune(s)
	lines := make([]string, 0)
	start := 0
	for i := 0; i < len(runes); i++ {
		if !sourceLineBoundary(runes[i]) {
			continue
		}
		lines = append(lines, string(runes[start:i]))
		if runes[i] == '\r' && i+1 < len(runes) && runes[i+1] == '\n' {
			i++
		}
		start = i + 1
	}
	if start < len(runes) {
		lines = append(lines, string(runes[start:]))
	}
	return lines
}

func sourceLineBoundary(r rune) bool {
	switch r {
	case '\n', '\r', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029':
		return true
	default:
		return false
	}
}

var yumInfoAttributes = []struct {
	name, format string
}{
	{"name", "name: %{NAME}\\n"},
	{"relocations", "relocations: %|PREFIXES?{[%{PREFIXES} ]}:{(not relocatable)}|\\n"},
	{"version", "version: %{VERSION}\\n"},
	{"vendor", "vendor: %{VENDOR}\\n"},
	{"release", "release: %{RELEASE}\\n"},
	{"epoch", "%|EPOCH?{epoch: %{EPOCH}\\n}|"},
	{"build_date_time_t", "build_date_time_t: %{BUILDTIME}\\n"},
	{"build_date", "build_date: %{BUILDTIME}\\n"},
	{"install_date_time_t", "install_date_time_t: %|INSTALLTIME?{%{INSTALLTIME}}:{(not installed)}|\\n"},
	{"install_date", "install_date: %|INSTALLTIME?{%{INSTALLTIME}}:{(not installed)}|\\n"},
	{"build_host", "build_host: %{BUILDHOST}\\n"},
	{"group", "group: %{GROUP}\\n"},
	{"source_rpm", "source_rpm: %{SOURCERPM}\\n"},
	{"size", "size: %{SIZE}\\n"},
	{"arch", "arch: %{ARCH}\\n"},
	{"license", "%|LICENSE?{license: %{LICENSE}\\n}|"},
	{"signature", "signature: %|DSAHEADER?{%{DSAHEADER:pgpsig}}:{%|RSAHEADER?{%{RSAHEADER:pgpsig}}:{%|SIGGPG?{%{SIGGPG:pgpsig}}:{%|SIGPGP?{%{SIGPGP:pgpsig}}:{(none)}|}|}|}|\\n"},
	{"packager", "%|PACKAGER?{packager: %{PACKAGER}\\n}|"},
	{"url", "%|URL?{url: %{URL}\\n}|"},
	{"summary", "summary: %{SUMMARY}\\n"},
	{"description", "description:\\n%{DESCRIPTION}\\n"},
	{"edition", "edition: %|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\\n"},
}

func yumInfoQueryFormat(a map[string]any, sizeTag string) (string, error) {
	var attr []string
	if s, ok := yumStringArg(a, "attr"); ok && s != "" {
		attr = strings.Split(s, ",")
	}
	valid := make(map[string]string, len(yumInfoAttributes))
	for _, item := range yumInfoAttributes {
		valid[item.name] = strings.Replace(item.format, "%{SIZE}", sizeTag, 1)
	}
	var query []string
	if len(attr) > 0 {
		for _, name := range attr {
			if format, ok := valid[name]; ok && name != "description" {
				query = append(query, format)
			}
		}
		if len(query) == 0 {
			return "", errors.New("No valid attributes found.")
		}
		if !containsString(attr, "name") {
			attr = append(attr, "name")
			query = append(query, valid["name"])
		}
		if !containsString(attr, "edition") {
			attr = append(attr, "edition")
			query = append(query, valid["edition"])
		}
		if containsString(attr, "description") {
			query = append(query, valid["description"])
		}
	} else {
		for _, item := range yumInfoAttributes {
			if item.name != "description" {
				query = append(query, valid[item.name])
			}
		}
		query = append(query, valid["description"])
	}
	return strings.Join(query, "") + "-----\\n", nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func yumInfoInstalled(ctx context.Context, rt *runtime.Runtime, a map[string]any) (any, error) {
	names := []string{}
	if v, ok := a["names"]; ok {
		var good bool
		names, good = v.([]string)
		if !good {
			return nil, errors.New("argument \"names\" must be a string list")
		}
	}
	all := false
	if v, ok := a["all_versions"]; ok {
		switch x := v.(type) {
		case *bool:
			if x != nil {
				all = *x
			}
		case bool:
			all = x
		default:
			return nil, errors.New("argument \"all_versions\" must be a boolean")
		}
	}
	root, err := yumRoot(a)
	if err != nil {
		return nil, err
	}
	if attr, ok := yumStringArg(a, "attr"); ok && strings.TrimSpace(attr) != "" {
		valid := map[string]bool{"name": true, "relocations": true, "version": true, "vendor": true, "release": true, "build_date": true, "build_date_time_t": true, "install_date": true, "install_date_time_t": true, "build_host": true, "group": true, "source_rpm": true, "arch": true, "epoch": true, "size": true, "license": true, "signature": true, "packager": true, "url": true, "summary": true, "description": true, "edition": true}
		found := false
		for _, item := range strings.Split(attr, ",") {
			if valid[strings.TrimSpace(item)] {
				found = true
			}
		}
		if !found {
			return nil, errors.New("No valid attributes found.")
		}
	}
	// rpm_lowpkg probes querytags first so SIZE remains compatible with older
	// rpm versions. yumpkg passes root/all_versions/attr through to lowpkg.
	tags := rt.Runner.Run(ctx, runtime.Command("rpm", "--querytags"))
	if tags.Err != nil {
		return nil, tags.Err
	}
	if tags.ExitCode != 0 {
		return nil, fmt.Errorf("rpm exited with code %d: %s", tags.ExitCode, tags.Stderr)
	}
	sizeTag := "%{SIZE}"
	if strings.Contains(string(tags.Stdout), "LONGSIZE") {
		sizeTag = "%{LONGSIZE}"
	}
	cmd := []string{"rpm"}
	if root != "" {
		cmd = append(cmd, "--root", root)
	}
	if len(names) == 0 {
		cmd = append(cmd, "-qa")
	} else {
		cmd = append(cmd, "-q")
		cmd = append(cmd, names...)
	}
	format, err := yumInfoQueryFormat(a, sizeTag)
	if err != nil {
		return nil, err
	}
	cmd = append(cmd, "--queryformat", format)
	// lowpkg.info invokes cmd.run_all with env={"TZ": "UTC"} and
	// clean_env=True. Command.Env is the runtime's equivalent boundary.
	queryCmd := runtime.Command(cmd...)
	queryCmd.Env = []string{"TZ=UTC"}
	r := rt.Runner.Run(ctx, queryCmd)
	if r.Err != nil {
		return nil, r.Err
	}
	// lowpkg.info uses ignore_retcode=True: usable stdout is parsed even when
	// rpm reports missing packages. Runner errors (including cancellation) are
	// still surfaced above rather than converted into fake success.
	ret := map[string]any{}
	type packageRecord struct {
		name    string
		fields  map[string]any
		edition string
	}
	var records []packageRecord
	for _, record := range strings.Split(string(r.Stdout), "-----") {
		record = strings.TrimSpace(record)
		if record == "" {
			continue
		}
		fields := map[string]any{}
		var name string
		description := []string{}
		inDesc := false
		for _, line := range strings.Split(record, "\n") {
			if inDesc {
				description = append(description, line)
				continue
			}
			if line == "description:" {
				inDesc = true
				continue
			}
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if k == "name" {
				name = v
				continue
			}
			// yumpkg translates this lowpkg field to source without
			// normalizing sentinel values such as (none) or (not installed).
			// Empty values are omitted by the lowpkg truthy-field parser.
			if k == "source_rpm" {
				if v != "" {
					fields["source"] = v
				}
				continue
			}
			if v == "" {
				continue
			}
			switch k {
			case "build_date", "install_date":
				if seconds, e := strconv.ParseInt(v, 10, 64); e == nil {
					fields[k] = time.Unix(seconds, 0).UTC().Format("2006-01-02T15:04:05Z")
				}
			case "build_date_time_t", "install_date_time_t":
				if seconds, e := strconv.ParseInt(v, 10, 64); e == nil {
					fields[k] = seconds
				}
			default:
				fields[k] = v
			}
		}
		if name == "" || strings.HasPrefix(name, "gpg-pubkey") {
			continue
		}
		// lowpkg.info adds the package name to every metadata object.
		fields["name"] = name
		if attrRequested(a, "description") {
			fields["description"] = strings.Join(description, "\n")
		}
		edition, _ := fields["edition"].(string)
		records = append(records, packageRecord{name: name, fields: fields, edition: edition})
	}
	// lowpkg.info sorts by edition descending and yumpkg.info_installed keeps
	// that order, selecting the first record unless all_versions is requested.
	sort.SliceStable(records, func(i, j int) bool {
		return yumVersionCmp(records[i].edition, records[j].edition, false) > 0
	})
	for _, item := range records {
		fields := item.fields
		if attr, ok := yumStringArg(a, "attr"); ok && strings.TrimSpace(attr) != "" {
			wanted := map[string]bool{"name": true, "edition": true}
			for _, key := range strings.Split(attr, ",") {
				key = strings.TrimSpace(key)
				if key == "source_rpm" {
					key = "source"
				}
				wanted[key] = true
			}
			for key := range fields {
				if !wanted[key] {
					delete(fields, key)
				}
			}
		}
		if all {
			if prior, exists := ret[item.name].([]any); exists {
				ret[item.name] = append(prior, fields)
			} else {
				ret[item.name] = []any{fields}
			}
		} else if _, exists := ret[item.name]; !exists {
			delete(fields, "edition")
			ret[item.name] = fields
		}
	}
	return ret, nil
}

func attrRequested(a map[string]any, name string) bool {
	attr, ok := yumStringArg(a, "attr")
	if !ok || strings.TrimSpace(attr) == "" {
		return !ok || strings.TrimSpace(attr) == ""
	}
	for _, item := range strings.Split(attr, ",") {
		if strings.TrimSpace(item) == name {
			return true
		}
	}
	return false
}
