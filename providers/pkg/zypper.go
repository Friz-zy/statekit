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

var ErrUnsupportedZypper = errors.New("Zypper capability is not supported by this package provider")

var (
	errInvalidZypperPackageName    = errors.New("invalid package name")
	errInvalidZypperPackageVersion = errors.New("invalid package version")
)

const (
	// Zypper token limits are rune-based so supported Unicode RPM digits are
	// bounded by semantic characters rather than their UTF-8 byte width.
	maxZypperTokenRunes = 4096
	maxZypperEpochRunes = 1024
)

// Zypper implements the explicitly ported zypperpkg functions. The six
// lowpkg functions delegate to rpm through the central Runner. Upgrade queries
// use zypper XML/text; unported long-tail functions remain unsupported rather
// than being approximated through a generic RPM path.
func (p *commandProvider) Zypper(ctx context.Context, rt *runtime.Runtime, function string, args any) (any, error) {
	if p.spec.manager != "zypper" {
		return nil, ErrUnsupportedZypper
	}
	if !zypperFunctionSupported(function) {
		return nil, &runtime.UnsupportedError{Kind: "function", Name: function}
	}
	a, ok := args.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Zypper function %q: malformed arguments", function)
	}
	if err := validateZypperArgs(function, a); err != nil {
		return nil, err
	}
	switch function {
	case "list_upgrades", "upgrade_available":
		return zypperUpgrades(ctx, rt, function, a)
	case "normalize_name":
		return zypperNormalizeName(a["name"].(string), zypperOSArch(rt)), nil
	case "parse_arch":
		return zypperParseArch(a["name"].(string)), nil
	case "version_cmp":
		return zypperVersionCmp(a["ver1"].(string), a["ver2"].(string), boolDefault(a, "ignore_epoch", false)), nil
	case "file_list":
		return zypperFileList(ctx, rt, a)
	case "file_dict":
		return zypperFileDict(ctx, rt, a)
	case "info_installed":
		return zypperInfoInstalled(ctx, rt, a)
	case "modified":
		return zypperModified(ctx, rt, a)
	case "owner":
		return zypperOwner(ctx, rt, a)
	case "verify":
		return zypperVerify(ctx, rt, a)
	default:
		panic("unreachable")
	}
}

func zypperFunctionSupported(function string) bool {
	if function == "list_upgrades" || function == "upgrade_available" {
		return true
	}
	if function == "normalize_name" || function == "parse_arch" || function == "version_cmp" {
		return true
	}
	return zypperLowpkgFunction(function)
}

func validateZypperArgs(function string, args map[string]any) error {
	if function == "list_upgrades" || function == "upgrade_available" {
		return validateZypperUpgradeArgs(function, args)
	}
	allowed := map[string]bool{}
	switch function {
	case "normalize_name", "parse_arch":
		allowed["name"] = true
	case "version_cmp":
		allowed["ver1"], allowed["ver2"], allowed["ignore_epoch"] = true, true, true
	default:
		return validateZypperLowpkgArgs(function, args)
	}
	for key := range args {
		if !allowed[key] {
			return fmt.Errorf("Zypper function %q: unsupported argument %q", function, key)
		}
	}
	if function == "normalize_name" || function == "parse_arch" {
		name, ok := args["name"].(string)
		if !ok {
			return errors.New(`argument "name" must be a string`)
		}
		if !validZypperToken(name, false) {
			return errInvalidZypperPackageName
		}
		return nil
	}
	for _, key := range []string{"ver1", "ver2"} {
		version, ok := args[key].(string)
		if !ok {
			return fmt.Errorf("argument %q must be a string", key)
		}
		if !validZypperVersionToken(version) {
			return errInvalidZypperPackageVersion
		}
	}
	if value, exists := args["ignore_epoch"]; exists && value != nil {
		switch value.(type) {
		case bool, *bool:
		default:
			return errors.New(`argument "ignore_epoch" must be a boolean`)
		}
	}
	return nil
}

// validZypperToken rejects values that cannot be represented as one safe
// package-manager token. RPM punctuation remains intentionally unrestricted;
// the grammar-specific pure functions decide how punctuation is interpreted.
func validZypperToken(value string, allowEmpty bool) bool {
	if !allowEmpty && value == "" {
		return false
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxZypperTokenRunes {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func validZypperVersionToken(value string) bool {
	// Empty EVRs are accepted by rpm.version_to_evr and remain valid source
	// inputs; package names are the fields that require a non-empty token.
	if !validZypperToken(value, true) {
		return false
	}
	epochIndex := strings.IndexByte(value, ':')
	if epochIndex < 0 {
		return true
	}
	epoch := value[:epochIndex]
	if len(epoch) > 0 && (epoch[0] == '+' || epoch[0] == '-') {
		epoch = epoch[1:]
	}
	return utf8.RuneCountInString(epoch) <= maxZypperEpochRunes
}

func zypperEpochWithinBounds(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	value = strings.TrimSpace(value)
	if len(value) > 0 && (value[0] == '+' || value[0] == '-') {
		value = value[1:]
	}
	return utf8.RuneCountInString(value) <= maxZypperEpochRunes
}

// zypperRPMArch converts Go's runtime architecture names to the RPM
// osarch spellings used by Salt's zypper module. Already-RPM names are
// intentionally preserved so injected or platform-specific facts remain
// usable without a lossy normalization pass.
func zypperRPMArch(arch string) string {
	switch arch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "386":
		return "i686"
	case "arm":
		return "armv7l"
	default:
		return arch
	}
}

func zypperOSArch(rt *runtime.Runtime) string {
	if rt == nil || rt.Facts == nil {
		return ""
	}
	return zypperRPMArch(rt.Facts.CPU().Arch)
}

// yumArchitectures is the pinned salt.utils.pkg.rpm.ARCHES set plus noarch;
// it deliberately excludes the separately declared SPARC tuple.
func zypperKnownArch(arch string) bool {
	_, ok := yumArchitectures[arch]
	return ok
}

func zypperCheck32RPMArch(arch, osarch string) bool {
	return check32RPMArch(arch, zypperRPMArch(osarch))
}

func zypperNormalizeName(name, osarch string) string {
	osarch = zypperRPMArch(osarch)
	arch := name
	if index := strings.LastIndexByte(name, '.'); index >= 0 {
		arch = name[index+1:]
	}
	if !zypperKnownArch(arch) {
		return name
	}
	if arch != osarch && arch != "noarch" && !zypperCheck32RPMArch(arch, osarch) {
		return name
	}
	// Python's name[:-(len(arch) + 1)] returns an empty string when the
	// recognized value has no package-name prefix; keep that edge case exact.
	end := len(name) - len(arch) - 1
	if end <= 0 {
		return ""
	}
	return name[:end]
}

func zypperParseArch(name string) map[string]any {
	base, arch := name, ""
	if index := strings.LastIndexByte(name, '.'); index >= 0 {
		base, arch = name[:index], name[index+1:]
	}
	if !zypperKnownArch(arch) {
		return map[string]any{"name": name, "arch": nil}
	}
	return map[string]any{"name": base, "arch": arch}
}

// zypperVersionCmp follows rpm_lowpkg.version_cmp and its pinned RPM
// fallback. Unlike the older YUM compatibility helper, a missing release on
// either side suppresses both releases before comparison.
func zypperVersionCmp(ver1, ver2 string, ignoreEpoch bool) int {
	if !validZypperVersionToken(ver1) || !validZypperVersionToken(ver2) {
		return 0
	}
	if ignoreEpoch {
		if index := strings.IndexByte(ver1, ':'); index >= 0 {
			ver1 = ver1[index+1:]
		}
		if index := strings.IndexByte(ver2, ':'); index >= 0 {
			ver2 = ver2[index+1:]
		}
	}
	epoch1, version1, release1 := zypperVersionToEVR(ver1)
	epoch2, version2, release2 := zypperVersionToEVR(ver2)
	if release1 == "" || release2 == "" {
		release1, release2 = "", ""
	}
	n1, ok1 := new(big.Int).SetString(epoch1, 10)
	n2, ok2 := new(big.Int).SetString(epoch2, 10)
	if !ok1 {
		n1 = new(big.Int)
	}
	if !ok2 {
		n2 = new(big.Int)
	}
	if epochCompare := n1.Cmp(n2); epochCompare != 0 {
		return yumSign(epochCompare)
	}
	if comparison := rpmVerCmp(version1, version2); comparison != 0 {
		return comparison
	}
	return rpmVerCmp(release1, release2)
}

// zypperVersionToEVR mirrors rpm.version_to_evr without sharing YUM's
// epoch parser. Keeping the parser local is important because Python int()
// accepts valid underscore-separated decimal literals while the historical
// YUM helper intentionally retains its existing behavior.
func zypperVersionToEVR(s string) (epoch, version, release string) {
	if !validZypperVersionToken(s) {
		return "0", "", ""
	}
	epoch = "0"
	epochIndex := strings.IndexByte(s, ':')
	if epochIndex >= 0 {
		if parsed, ok := zypperPythonIntDecimal(s[:epochIndex]); ok {
			epoch = parsed
		}
	}
	releaseIndex := strings.IndexByte(s, '-')
	versionStart := epochIndex + 1
	if releaseIndex >= 0 {
		version = ""
		if releaseIndex >= versionStart {
			version = s[versionStart:releaseIndex]
		}
		return epoch, version, s[releaseIndex+1:]
	}
	return epoch, s[versionStart:], ""
}

// zypperPythonIntDecimal implements the decimal form accepted by Python's
// int() for the epoch field: surrounding whitespace, one optional sign,
// Unicode decimal digits, and single underscores only between digits.
func zypperPythonIntDecimal(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || !zypperEpochWithinBounds(s) {
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
	needDigit := true
	for _, r := range s {
		if r == '_' {
			if needDigit {
				return "", false
			}
			needDigit = true
			continue
		}
		digit, ok := zypperUnicodeDecimalValue(r)
		if !ok {
			return "", false
		}
		value.Mul(value, ten)
		value.Add(value, big.NewInt(int64(digit)))
		needDigit = false
	}
	if needDigit {
		return "", false
	}
	if negative && value.Sign() != 0 {
		value.Neg(value)
	}
	return value.String(), true
}

func zypperUnicodeDecimalValue(r rune) (int, bool) {
	if r >= '0' && r <= '9' {
		return int(r - '0'), true
	}
	for _, rr := range unicode.Digit.R16 {
		lo, hi := rune(rr.Lo), rune(rr.Hi)
		if r >= lo && r <= hi {
			return int((r-lo)/rune(rr.Stride)) % 10, true
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
