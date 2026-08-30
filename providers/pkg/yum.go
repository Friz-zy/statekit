package pkg

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
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

func (p *commandProvider) Yum(_ context.Context, rt *runtime.Runtime, function string, args any) (any, error) {
	if p.spec.manager != "yum" && p.spec.manager != "dnf" {
		return nil, ErrUnsupportedYUM
	}
	a, ok := args.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("YUM function %q: malformed arguments", function)
	}
	switch function {
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
