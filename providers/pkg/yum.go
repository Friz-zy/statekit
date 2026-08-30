package pkg

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/runtime"
)

var ErrUnsupportedYUM = errors.New("YUM capability is not supported by this package provider")

var yumArchitectures = map[string]struct{}{
	"x86_64": {}, "x86_64_v2": {}, "athlon": {}, "amd64": {}, "ia32e": {}, "ia64": {}, "geode": {},
	"i386": {}, "i486": {}, "i586": {}, "i686": {},
	"ppc": {}, "ppc64": {}, "ppc64le": {}, "ppc64iseries": {}, "ppc64pseries": {},
	"s390": {}, "s390x": {},
	"alpha": {}, "alphaev4": {}, "alphaev45": {}, "alphaev5": {}, "alphaev56": {}, "alphapca56": {}, "alphaev6": {}, "alphaev67": {}, "alphaev68": {}, "alphaev7": {},
	"armv5tel": {}, "armv5tejl": {}, "armv6l": {}, "armv6hl": {}, "armv7l": {}, "armv7hl": {}, "armv7hnl": {},
	"aarch64": {}, "sh3": {}, "sh4": {}, "sh4a": {}, "noarch": {},
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
	case "list_holds":
		return yumListHolds(ctx, rt, p.spec.manager, a)
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
	case "list_holds":
		allowed = map[string]bool{"pattern": true, "full": true}
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
	for _, key := range []string{"all_versions", "ignore_epoch"} {
		if v, present := a[key]; present && v != nil {
			switch v.(type) {
			case bool, *bool:
			default:
				return fmt.Errorf("argument %q must be a boolean", key)
			}
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
	if v, present := a["check_update"]; present && v != nil {
		switch v.(type) {
		case bool, *bool:
		default:
			return errors.New(`argument "check_update" must be a boolean`)
		}
	}
	return nil
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
