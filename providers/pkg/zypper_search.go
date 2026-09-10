package pkg

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const zypperSearchMaxXMLDepth = 128

var errZypperSearchInvalidXML = errors.New("zypper: invalid search XML")

type zypperSearchOption struct {
	name string
	flag string
}

var zypperSearchOptions = []zypperSearchOption{
	{name: "provides", flag: "--provides"},
	{name: "recommends", flag: "--recommends"},
	{name: "requires", flag: "--requires"},
	{name: "suggests", flag: "--suggests"},
	{name: "conflicts", flag: "--conflicts"},
	{name: "obsoletes", flag: "--obsoletes"},
	{name: "file_list", flag: "--file-list"},
	{name: "search_descriptions", flag: "--search-descriptions"},
	{name: "case_sensitive", flag: "--case-sensitive"},
	{name: "installed_only", flag: "--installed-only"},
	{name: "not_installed_only", flag: "-u"},
	{name: "details", flag: "--details"},
}

func zypperSearch(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	if err := validateZypperSearchArgs(args); err != nil {
		return nil, err
	}
	criteria := args["criteria"].(string)
	root, _ := zypperLowpkgRoot(args)
	match, _ := zypperSearchMatch(args)
	refresh, _ := zypperBool(args, "refresh")

	query := []string{"search"}
	if match != "" {
		query = append(query, zypperSearchMatchFlag(match))
	}
	for _, option := range zypperSearchOptions {
		if zypperSearchOptionSupplied(args, option.name) {
			query = append(query, option.flag)
		}
	}
	query = append(query, criteria)

	if refresh {
		refreshArgs := []string{"refresh"}
		if zypperSearchRefreshForce(args) {
			refreshArgs = append(refreshArgs, "--force")
		}
		if _, err := zypperQueryRun(ctx, rt, root, false, true, refreshArgs); err != nil {
			return nil, err
		}
	}
	output, err := zypperQueryRun(ctx, rt, root, true, false, query)
	if err != nil {
		return nil, err
	}
	result, err := zypperParseSearch(ctx, output, criteria)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func validateZypperSearchArgs(args map[string]any) error {
	allowed := map[string]bool{
		"criteria": true,
		"refresh":  true,
		"root":     true,
		"match":    true,
	}
	for _, option := range zypperSearchOptions {
		allowed[option.name] = true
	}
	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !allowed[key] {
			return zypperUnsupportedArgument(key)
		}
	}
	value, exists := args["criteria"]
	if !exists || value == nil {
		return errors.New(`argument "criteria" is required`)
	}
	criteria, ok := value.(string)
	if !ok {
		return errors.New(`argument "criteria" must be a string`)
	}
	if !validZypperSearchCriteria(criteria) {
		return errors.New(`argument "criteria" is invalid`)
	}
	if _, err := zypperBool(args, "refresh"); err != nil {
		return err
	}
	if _, err := zypperLowpkgRoot(args); err != nil {
		return err
	}
	if _, err := zypperSearchMatch(args); err != nil {
		return err
	}
	for _, option := range zypperSearchOptions {
		if _, err := zypperBool(args, option.name); err != nil {
			return err
		}
	}
	return nil
}

func validZypperSearchCriteria(criteria string) bool {
	if criteria == "" || strings.TrimSpace(criteria) == "" || strings.HasPrefix(criteria, "-") {
		return false
	}
	if !validZypperSearchText(criteria) {
		return false
	}
	return true
}

func validZypperSearchText(value string) bool {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxZypperTokenRunes {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func zypperSearchOptionSupplied(args map[string]any, key string) bool {
	value, exists := args[key]
	if !exists || value == nil {
		return false
	}
	if typed, ok := value.(*bool); ok {
		return typed != nil
	}
	return true
}

func zypperSearchMatch(args map[string]any) (string, error) {
	value, exists := args["match"]
	if !exists || value == nil {
		return "", nil
	}
	var match string
	switch typed := value.(type) {
	case string:
		match = typed
	case *string:
		if typed == nil {
			return "", nil
		}
		match = *typed
	default:
		return "", errors.New(`argument "match" must be a string`)
	}
	switch match {
	case "exact", "words", "substrings":
		return match, nil
	default:
		return "", zypperUnsupportedArgument("match")
	}
}

func zypperSearchMatchFlag(match string) string {
	switch match {
	case "exact":
		return "--match-exact"
	case "words":
		return "--match-words"
	default:
		return "--match-substrings"
	}
}

func zypperSearchRefreshForce(args map[string]any) bool {
	value, exists := args["root"]
	if !exists || value == nil {
		return true
	}
	switch typed := value.(type) {
	case string:
		return typed != ""
	case *string:
		return typed == nil || *typed != ""
	default:
		return true
	}
}

func zypperParseSearch(ctx context.Context, output, criteria string) (map[string]map[string]string, error) {
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
	result := make(map[string]map[string]string)
	depth := 0
	roots := 0
	elements := 0
	solvables := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errZypperSearchInvalidXML
		}
		switch element := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
				if roots > 1 {
					return nil, errZypperSearchInvalidXML
				}
			}
			depth++
			if depth > zypperSearchMaxXMLDepth {
				return nil, process.ErrOutputLimit
			}
			elements++
			if elements > zypperLowpkgMaxItems {
				return nil, process.ErrOutputLimit
			}
			if element.Name.Local != "solvable" {
				continue
			}
			solvables++
			if solvables > zypperLowpkgMaxItems {
				return nil, process.ErrOutputLimit
			}
			attrs := make(map[string]string, len(element.Attr))
			for _, attr := range element.Attr {
				attrs[attr.Name.Local] = attr.Value
			}
			result[attrs["name"]] = attrs
		case xml.EndElement:
			depth--
			if depth < 0 {
				return nil, errZypperSearchInvalidXML
			}
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(element)) != "" {
				return nil, errZypperSearchInvalidXML
			}
		}
	}
	if roots != 1 || depth != 0 {
		return nil, errZypperSearchInvalidXML
	}
	if solvables == 0 {
		return nil, &zypperSearchNoResultsError{criteria: criteria}
	}
	return result, nil
}

// zypperSearchNoResultsError is the ported analog of the CommandExecutionError
// raised by zypperpkg.search when no solvables match. It stays typed so
// composites such as list_holds can skip exactly this failure category.
type zypperSearchNoResultsError struct{ criteria string }

func (e *zypperSearchNoResultsError) Error() string {
	if validZypperSearchCriteria(e.criteria) {
		return fmt.Sprintf("No packages found matching '%s'", e.criteria)
	}
	return "No packages found matching the supplied criteria"
}
