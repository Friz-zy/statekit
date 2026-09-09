package pkg

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

var errZypperPatternsInvalidXML = errors.New("zypper: invalid patterns XML")

type zypperPatternRecord struct {
	name    string
	summary string
	status  string
}

// validateZypperPatternArgs keeps the provider contract identical to the
// pinned zypperpkg signatures: list_patterns(refresh=False, root=None) and
// list_installed_patterns(root=None). Repository selectors and arbitrary
// zypper options are intentionally rejected because neither source function
// accepts them.
func validateZypperPatternArgs(function string, args map[string]any) error {
	allowed := map[string]bool{"root": true}
	if function == "list_patterns" {
		allowed["refresh"] = true
	}
	for key := range args {
		if !allowed[key] {
			return zypperUnsupportedArgument(key)
		}
	}
	if _, err := zypperLowpkgRoot(args); err != nil {
		return err
	}
	if function == "list_patterns" {
		if _, err := zypperBool(args, "refresh"); err != nil {
			return err
		}
	}
	return nil
}

func zypperPatterns(ctx context.Context, rt *runtime.Runtime, function string, args map[string]any) (any, error) {
	root, err := zypperLowpkgRoot(args)
	if err != nil {
		return nil, err
	}

	if function == "list_patterns" && boolDefault(args, "refresh", false) {
		// list_patterns calls refresh_db(root) positionally in the pinned
		// source. The supplied root therefore becomes refresh_db's force
		// argument; refresh_db's root remains unset. The query still uses root.
		refresh := []string{"refresh"}
		if zypperSearchRefreshForce(args) {
			refresh = append(refresh, "--force")
		}
		if _, err := zypperQueryRun(ctx, rt, "", false, true, refresh); err != nil {
			return nil, err
		}
	}

	if function == "list_installed_patterns" {
		patterns, err := zypperInstalledPatterns(ctx, rt, root)
		if err != nil {
			return nil, err
		}
		return patterns, nil
	}
	patterns, err := zypperVisiblePatterns(ctx, rt, root, false)
	if err != nil {
		return nil, err
	}
	return patterns, nil
}

func zypperVisiblePatterns(ctx context.Context, rt *runtime.Runtime, root string, installedOnly bool) (map[string]any, error) {
	output, err := zypperQueryRun(ctx, rt, root, true, false, []string{"se", "-t", "pattern"})
	if err != nil {
		return nil, err
	}
	return zypperParsePatterns(ctx, output, installedOnly)
}

func zypperInstalledPatterns(ctx context.Context, rt *runtime.Runtime, root string) (map[string]any, error) {
	// _get_installed_patterns queries RPM first, then obtains all visible
	// patterns and retains only visible entries whose status is installed.
	capabilities, err := zypperInstalledPatternCapabilities(ctx, rt, root)
	if err != nil {
		return nil, err
	}
	patterns, err := zypperVisiblePatterns(ctx, rt, root, true)
	if err != nil {
		return nil, err
	}

	for _, name := range capabilities {
		if _, exists := patterns[name]; exists {
			continue
		}
		patterns[name] = map[string]any{
			"installed": true,
			"summary":   "Non-visible pattern",
		}
	}
	return patterns, nil
}

func zypperInstalledPatternCapabilities(ctx context.Context, rt *runtime.Runtime, root string) ([]string, error) {
	argv := []string{"rpm"}
	if root != "" {
		argv = append(argv, "--root", root)
	}
	argv = append(argv, "-q", "--provides", "--whatprovides", "pattern()")

	// Salt invokes cmd.run(ignore_retcode=True). zypperRPMRun deliberately
	// preserves completed RPM results, including retcode 1 with no output;
	// only runner/cancellation/bound failures are execution errors.
	result, err := zypperRPMRun(ctx, rt, argv, nil)
	if err != nil {
		return nil, err
	}
	if len(result.Stdout) == 0 {
		return nil, nil
	}

	const prefix = "pattern() = "
	names := make([]string, 0, 8)
	seen := make(map[string]struct{})
	matched := 0
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		matched++
		if matched > zypperLowpkgMaxItems {
			return nil, process.ErrOutputLimit
		}
		name := zypperPatternCapabilityName(line)
		if strings.HasPrefix(name, ".") {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		if len(names) >= zypperLowpkgMaxItems {
			return nil, process.ErrOutputLimit
		}
		names = append(names, name)
	}
	return names, nil
}

func zypperPatternCapabilityName(capability string) string {
	parts := strings.Split(capability, "=")
	return strings.TrimSpace(parts[len(parts)-1])
}

const (
	zypperPatternsMaxAttributesPerElement = 64
	zypperPatternsMaxAttributeBytes       = 64 << 10
)

// zypperParsePatterns mirrors _get_visible_patterns. zypper's XML search
// response is a document containing solvable elements; only exact solvable
// attributes are read, and status is installed only for the literal value
// "installed". Records are applied at StartElement time, matching
// getElementsByTagName's document order so nested duplicates retain the
// source dict's last-record-wins value while preserving first-seen key order.
func zypperParsePatterns(ctx context.Context, output string, installedOnly bool) (map[string]any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(output) > zypperLowpkgOutputLimit {
		return nil, process.ErrOutputLimit
	}

	decoder := xml.NewDecoder(strings.NewReader(output))
	stack := make([]xml.Name, 0, 4)
	roots, elements, attributes := 0, 0, 0
	records := make(map[string]zypperPatternRecord)
	order := make([]string, 0)
	seenNames := make(map[string]struct{})

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		token, err := decoder.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errZypperPatternsInvalidXML
		}

		switch token := token.(type) {
		case xml.StartElement:
			if len(stack) == 0 {
				roots++
				if roots > 1 {
					return nil, errZypperPatternsInvalidXML
				}
			}
			depth := len(stack) + 1
			if depth > zypperSearchMaxXMLDepth {
				return nil, process.ErrOutputLimit
			}
			elements++
			if elements > zypperLowpkgMaxItems {
				return nil, process.ErrOutputLimit
			}

			attributeBytes := 0
			if len(token.Attr) > zypperPatternsMaxAttributesPerElement {
				return nil, process.ErrOutputLimit
			}
			for _, attr := range token.Attr {
				attributes++
				if attributes > zypperLowpkgMaxItems {
					return nil, process.ErrOutputLimit
				}
				attrBytes := len(attr.Name.Space) + len(attr.Name.Local) + len(attr.Value)
				if attrBytes > zypperPatternsMaxAttributeBytes || attributeBytes > zypperPatternsMaxAttributeBytes-attrBytes {
					return nil, process.ErrOutputLimit
				}
				attributeBytes += attrBytes
			}

			// RawToken deliberately retains the lexical prefix in Name.Space.
			// This accepts <solvable> under a default xmlns while ignoring
			// <ns:solvable>, matching minidom's exact lexical lookup.
			if token.Name.Space == "" && token.Name.Local == "solvable" {
				record := zypperPatternRecord{}
				for _, attr := range token.Attr {
					if attr.Name.Space != "" {
						continue
					}
					switch attr.Name.Local {
					case "name":
						record.name = attr.Value
					case "summary":
						record.summary = attr.Value
					case "status":
						record.status = attr.Value
					}
				}
				if _, exists := seenNames[record.name]; !exists {
					order = append(order, record.name)
					seenNames[record.name] = struct{}{}
				}
				records[record.name] = record
			}
			stack = append(stack, token.Name)

		case xml.CharData:
			if len(stack) == 0 && strings.TrimSpace(string(token)) != "" {
				return nil, errZypperPatternsInvalidXML
			}

		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != token.Name {
				return nil, errZypperPatternsInvalidXML
			}
			stack = stack[:len(stack)-1]
		}
	}

	if roots != 1 || len(stack) != 0 {
		return nil, errZypperPatternsInvalidXML
	}

	result := make(map[string]any, len(records))
	for _, name := range order {
		record, exists := records[name]
		if !exists {
			continue
		}
		if installedOnly && record.status != "installed" {
			continue
		}
		result[name] = map[string]any{
			"installed": record.status == "installed",
			"summary":   record.summary,
		}
	}
	return result, nil
}
