package pkg

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// Repository selectors are data, never additional command-line switches.
func zypperUpgradeRepos(args map[string]any, key string) ([]string, error) {
	v, exists := args[key]
	if !exists || v == nil {
		return nil, nil
	}
	var values []string
	switch v := v.(type) {
	case string:
		values = []string{v}
	case []string:
		values = v
	case []any:
		if len(v) > zypperLowpkgMaxItems {
			return nil, zypperUnsupportedArgument(key)
		}
		for _, item := range v {
			var s string
			switch item := item.(type) {
			case string:
				s = item
			case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
				s = fmt.Sprint(item)
			case float32:
				s = zypperRepoFloat(float64(item))
			case float64:
				s = zypperRepoFloat(item)
			case bool:
				if item {
					s = "True"
				} else {
					s = "False"
				}
			case nil:
				s = "None"
			default:
				return nil, zypperUnsupportedArgument(key)
			}
			values = append(values, s)
		}
	default:
		return nil, zypperUnsupportedArgument(key)
	}
	if len(values) > zypperLowpkgMaxItems {
		return nil, zypperUnsupportedArgument(key)
	}
	for _, value := range values {
		if validateZypperPath(value, false) != nil || strings.HasPrefix(value, "-") {
			return nil, zypperUnsupportedArgument(key)
		}
	}
	return values, nil
}

// Python str(float) retains .0 and uses scientific notation outside [-4, 16).
func zypperRepoFloat(value float64) string {
	s := strings.ToLower(strconv.FormatFloat(value, 'e', -1, 64))
	if i := strings.IndexByte(s, 'e'); i >= 0 {
		exponent, _ := strconv.Atoi(s[i+1:])
		if exponent >= -4 && exponent < 16 {
			s = strconv.FormatFloat(value, 'f', -1, 64)
			if !strings.Contains(s, ".") {
				s += ".0"
			}
		}
	}
	return strings.TrimPrefix(s, "+")
}

func validateZypperUpgradeArgs(function string, args map[string]any) error {
	for key := range args {
		if key != "refresh" && key != "root" && key != "repos" && key != "gpgautoimport" && key != "fromrepo" && !(function == "upgrade_available" && key == "name") {
			return zypperUnsupportedArgument(key)
		}
	}
	for _, key := range []string{"refresh", "gpgautoimport"} {
		if _, err := zypperBool(args, key); err != nil {
			return err
		}
	}
	if _, err := zypperLowpkgRoot(args); err != nil {
		return err
	}
	for _, key := range []string{"repos", "fromrepo"} {
		if _, err := zypperUpgradeRepos(args, key); err != nil {
			return err
		}
	}
	if function == "upgrade_available" {
		name, ok := args["name"].(string)
		if !ok || !validZypperToken(name, false) || strings.HasPrefix(name, "-") {
			return errInvalidZypperPackageName
		}
	}
	return nil
}

// zypperQueryRun centralizes bounded, cancellable zypper execution. Lock errors
// fail promptly instead of reproducing Salt's unbounded lock/host-FS polling.
func zypperQueryRun(ctx context.Context, rt *runtime.Runtime, root string, xmlMode, refresh bool, args []string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	argv := []string{"zypper", "--non-interactive"}
	if xmlMode {
		argv = append(argv, "--xmlout")
	}
	if !refresh {
		argv = append(argv, "--no-refresh")
	}
	if root != "" {
		argv = append(argv, "--root", root)
	}
	argv = append(argv, args...)
	env := []string{"LC_ALL=C"}
	if !refresh {
		env = append(env, "ZYPP_READONLY_HACK=1")
	}
	result, err := zypperRPMRun(ctx, rt, argv, env)
	if err != nil {
		return "", err
	}
	switch result.ExitCode {
	case 0, 6, 100, 101, 102, 103, 106, 107:
		return string(result.Stdout), nil
	default:
		// Do not expose arbitrary command output through errors.
		return "", fmt.Errorf("zypper command failed with exit code %d", result.ExitCode)
	}
}

func zypperUpgrades(ctx context.Context, rt *runtime.Runtime, function string, args map[string]any) (any, error) {
	root, _ := zypperLowpkgRoot(args)
	repos, _ := zypperUpgradeRepos(args, "repos")
	fromrepo, _ := zypperUpgradeRepos(args, "fromrepo")
	query := []string{"list-updates"}
	if function == "upgrade_available" {
		query = []string{"info", "-t", "package", args["name"].(string)}
	} else {
		for _, repo := range fromrepo {
			query = append(query, "--repo", repo)
		}
	}
	// Validate the complete query before a potentially mutating refresh.
	if err := zypperValidateArgv(append([]string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root}, query...)); err != nil {
		return nil, err
	}
	refreshArgs := []string{"refresh"}
	// Pinned callers pass root positionally as refresh_db's force argument.
	// list_upgrades consumes root; info_available retains it in **kwargs.
	force := true
	switch value := args["root"].(type) {
	case string:
		force = value != ""
	case *string:
		if value != nil {
			force = *value != ""
		}
	}
	if force {
		refreshArgs = append(refreshArgs, "--force")
	}
	refreshArgs = append(refreshArgs, repos...)
	if boolDefault(args, "gpgautoimport", false) {
		refreshArgs = append([]string{"--gpg-auto-import-keys"}, refreshArgs...)
	}
	if err := zypperValidateArgv(append([]string{"zypper", "--non-interactive", "--root", root}, refreshArgs...)); err != nil {
		return nil, err
	}
	if boolDefault(args, "refresh", true) {
		refreshRoot := ""
		if function == "upgrade_available" {
			refreshRoot = root
		}
		if _, err := zypperQueryRun(ctx, rt, refreshRoot, false, true, refreshArgs); err != nil {
			return nil, err
		}
	}
	output, err := zypperQueryRun(ctx, rt, root, function == "list_upgrades", false, query)
	if err != nil {
		return nil, err
	}
	if function == "list_upgrades" {
		return zypperParseUpgrades(ctx, output)
	}
	return zypperParseUpgradeAvailable(ctx, output, args["name"].(string))
}

func zypperParseUpgrades(ctx context.Context, output string) (map[string]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	decoder := xml.NewDecoder(strings.NewReader(output))
	result := map[string]string{}
	depth, roots, items := 0, 0, 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("invalid zypper updates XML")
		}
		switch node := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			if depth > 128 || roots > 1 {
				return nil, errors.New("invalid zypper updates XML structure")
			}
			if node.Name.Local != "update" {
				continue
			}
			items++
			if items > zypperLowpkgMaxItems {
				return nil, process.ErrOutputLimit
			}
			attrs := map[string]string{}
			for _, attr := range node.Attr {
				attrs[attr.Name.Local] = attr.Value
			}
			if attrs["kind"] == "package" {
				result[attrs["name"]] = attrs["edition"]
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(node)) != "" {
				return nil, errors.New("invalid zypper updates XML")
			}
		}
	}
	if roots != 1 || depth != 0 {
		return nil, errors.New("invalid zypper updates XML")
	}
	return result, nil
}

var zypperInfoSeparator = regexp.MustCompile(`Information for package*`)

func zypperParseUpgradeAvailable(ctx context.Context, output, name string) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	blocks := zypperInfoSeparator.Split(output, -1)
	if len(blocks) > zypperLowpkgMaxItems {
		return false, process.ErrOutputLimit
	}
	available := false
	for _, block := range blocks {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "-----") {
				continue
			}
			key, value, ok := strings.Cut(line, ":")
			if ok && strings.TrimSpace(value) != "" {
				fields[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
			}
		}
		if fields["name"] != name {
			continue
		}
		status := strings.ToLower(fields["status"])
		available = fields["version"] != "" && (strings.Contains(status, "not installed") || strings.Contains(status, "out-of-date"))
	}
	return available, nil
}
