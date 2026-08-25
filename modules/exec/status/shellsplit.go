package status

import "strings"

// shellSplit mirrors salt.utils.args.shlex_split: whitespace separation
// honoring double/single quotes and backslash escapes outside quotes.
func shellSplit(cmd string) []string {
	var args []string
	var cur strings.Builder
	has := false
	inDouble := false
	inSingle := false
	escaped := false
	for _, c := range cmd {
		switch {
		case escaped:
			cur.WriteRune(c)
			escaped = false
		case c == '\\' && !inSingle && !inDouble:
			escaped = true
		case c == '"' && !inSingle:
			inDouble = !inDouble
			has = true
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			has = true
		case (c == ' ' || c == '\t') && !inSingle && !inDouble:
			if cur.Len() > 0 || has {
				args = append(args, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 || has {
		args = append(args, cur.String())
	}
	return args
}

func indexOf(list []string, needle string) int {
	for i, item := range list {
		if item == needle {
			return i
		}
	}
	return -1
}

func compAt(list []string, idx int) string {
	if idx < len(list) {
		return list[idx]
	}
	return ""
}

func compSlice(list []string, from int) []string {
	if from < len(list) {
		return list[from:]
	}
	return nil
}

func orEmptyMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func orEmptyList(v any) []map[string]any {
	if l, ok := v.([]map[string]any); ok {
		return l
	}
	return []map[string]any{}
}

func orEmptyValue(v any) any {
	if v != nil {
		return v
	}
	return map[string]any{}
}
