// Package smbios implements Salt-compatible SMBIOS/DMI queries through
// dmidecode (or the smbios fallback binary).
//
// Reference: saltstack/salt/modules/smbios.py @ pinned revision. The
// module has no upstream unit tests; this suite pins the source-derived
// parser contract hermetically.
package smbios

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts this module to linux.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// dmiBin mirrors which_bin(["dmidecode", "smbios"]).
var dmiBin = func() string {
	for _, name := range []string{"dmidecode", "smbios"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}

// runQuiet mirrors salt.modules.cmdmod._run_quiet: stdout text, non-zero
// exits raise with stderr.
func runQuiet(ctx context.Context, rt *runtime.Runtime, args string) (string, error) {
	bin := dmiBin()
	if bin == "" {
		return "", fmt.Errorf("The smbios execution module failed to load: neither dmidecode nor smbios in the path.")
	}
	cmd := strings.TrimSpace(bin + " " + args)
	res := rt.Runner.Run(ctx, process.Command{Name: cmd, Shell: true})
	if res.Err != nil {
		return "", res.Err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("%s", string(res.Stderr))
	}
	return string(res.Stdout), nil
}

// dmidecoder ports _dmidecoder.
func dmidecoder(ctx context.Context, rt *runtime.Runtime, args string) (string, error) {
	return runQuiet(ctx, rt, args)
}

// GetArgs mirrors Salt's get signature; clean defaults to True via the
// tri-state pointer.
type GetArgs struct {
	String string `statekit:"required,name=string"`
	Clean  *bool  `statekit:"name=clean"`
}

type getFunc struct{ linuxOnly }

func (getFunc) Name() string { return "smbios.get" }
func (getFunc) Args() any    { return GetArgs{} }

func (getFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetArgs)
	clean := true
	if a.Clean != nil {
		clean = *a.Clean
	}

	valRaw, err := dmidecoder(ctx, rt, "-s "+a.String)
	if err != nil {
		return nil, err
	}
	val := strings.TrimSpace(valRaw)

	// Cleanup possible comments in strings.
	var kept []string
	for _, line := range strings.Split(val, "\n") {
		if !strings.HasPrefix(line, "#") {
			kept = append(kept, line)
		}
	}
	val = strings.Join(kept, "\n")
	if strings.HasPrefix(val, "/dev/mem") || (clean && !dmiIsClean(a.String, val)) {
		return nil, nil
	}
	return val, nil
}

// RecordsArgs mirrors Salt's records signature.
type RecordsArgs struct {
	RecType *string  `statekit:"name=rec_type"`
	Fields  []string `statekit:"name=fields"`
	Clean   *bool    `statekit:"name=clean"`
}

type recordsFunc struct{ linuxOnly }

func (recordsFunc) Name() string { return "smbios.records" }
func (recordsFunc) Args() any    { return RecordsArgs{} }

func (recordsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RecordsArgs)
	clean := true
	if a.Clean != nil {
		clean = *a.Clean
	}
	query := ""
	if a.RecType != nil {
		query = "-t " + *a.RecType
	}
	out, err := dmidecoder(ctx, rt, query)
	if err != nil {
		return nil, err
	}
	return dmiParse(out, clean, a.Fields), nil
}

// handleSplitRe detects & splits Handle records exactly like upstream's
// "(handle [0-9]x[0-9a-f]+[^\n]+)\n" pattern.
var handleSplitRe = regexp.MustCompile(`(?mi)(handle [0-9]x[0-9a-f]+[^\n]+)\n`)

// dmiParse ports _dmi_parse: pairs each handle header with its body and
// structures the data dict. Python's re.split inserts capture groups into
// the piece list while Go's Split does not, so the pairing walks match
// indices instead.
func dmiParse(data string, clean bool, fields []string) []any {
	dmi := []any{}
	locations := handleSplitRe.FindAllStringSubmatchIndex(data, -1)
	for i, loc := range locations {
		handleLine := data[loc[2]:loc[3]]
		bodyEnd := len(data)
		if i+1 < len(locations) {
			bodyEnd = locations[i+1][0]
		}
		body := data[loc[1]:bodyEnd]

		headerParts := strings.Split(handleLine, ",")
		if len(headerParts) < 2 {
			continue
		}
		handleFields := strings.Fields(headerParts[0])
		typeFields := strings.Fields(headerParts[1])
		if len(handleFields) == 0 || len(typeFields) == 0 {
			continue
		}
		handle := handleFields[len(handleFields)-1]
		htype := typeFields[len(typeFields)-1]

		lines := strings.Split(body, "\n")
		description := ""
		if len(lines) > 0 {
			description = strings.TrimSpace(lines[0])
			lines = lines[1:]
		}

		htypeNum, err := strconv.Atoi(htype)
		if err != nil {
			continue
		}
		record := map[string]any{
			"handle":      handle,
			"description": description,
			"type":        int64(htypeNum),
		}

		if len(lines) == 0 {
			if !clean {
				dmi = append(dmi, record)
			}
			continue
		}

		dmiData := dmiData(lines, clean, fields)
		if len(dmiData) > 0 {
			record["data"] = dmiData
			dmi = append(dmi, record)
		} else if !clean {
			dmi = append(dmi, record)
		}
	}
	return dmi
}

// tabKeyRe matches a single-tab-indented key line ("\t[^\s]+").
var tabKeyRe = regexp.MustCompile(`^\t[^\s]+`)

// doubleTabKeyRe matches deeper list items ("\t\t[^\s]+").
var doubleTabKeyRe = regexp.MustCompile(`^\t\t[^\s]+`)

// dmiData ports _dmi_data: single-tab lines define keys, double-tab lines
// append list items to the current key.
func dmiData(dmiRaw []string, clean bool, fields []string) map[string]any {
	dmiDataOut := map[string]any{}

	key := ""
	haveKey := false
	var value any
	var vlist []any

	flush := func() {
		if !haveKey || key == "" {
			return
		}
		if len(vlist) > 0 {
			if value != nil {
				vlist = append([]any{value}, vlist...)
			}
			dmiDataOut[key] = vlist
		} else if value != nil {
			dmiDataOut[key] = value
		}
	}

	fieldsSet := map[string]bool{}
	for _, f := range fields {
		fieldsSet[f] = true
	}

	for _, line := range dmiRaw {
		switch {
		case tabKeyRe.MatchString(line):
			flush()
			key = ""
			value = nil
			vlist = nil

			kv := strings.SplitN(line, ":", 2)
			if len(kv) != 2 {
				continue
			}
			key = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(kv[0])), " ", "_")
			val := strings.TrimSpace(kv[1])
			if (clean && key == "header_and_data") || (len(fieldsSet) > 0 && !fieldsSet[key]) {
				key = ""
				haveKey = true // key suppressed; continuation lines are skipped
				continue
			}
			haveKey = true
			value = dmiCast(key, val, clean)
		case !haveKey:
			continue
		case key == "":
			// Key was filtered out; its continuations are dropped too.
			continue
		case doubleTabKeyRe.MatchString(line):
			item := dmiCast(key, strings.TrimSpace(line), clean)
			if item != nil {
				vlist = append(vlist, item)
			}
		}
	}
	flush()
	return dmiDataOut
}

// serialKeyRe guards the no-cast group of keys ("serial|part|asset|
// product"), matching upstream's case-insensitive prefix rule.
var serialKeyRe = regexp.MustCompile(`(?i)serial|part|asset|product`)

// dmiCast ports _dmi_cast: comma lists and ints are extracted unless the
// key looks like an identifier field; dirty values vanish under clean.
func dmiCast(key, val string, clean bool) any {
	if clean && !dmiIsClean(key, val) {
		return nil
	}
	if !serialKeyRe.MatchString(key) {
		if strings.Contains(val, ",") {
			var parts []any
			for _, el := range strings.Split(val, ",") {
				parts = append(parts, strings.TrimSpace(el))
			}
			return parts
		}
		if n, err := strconv.Atoi(val); err == nil {
			return int64(n)
		}
	}
	return val
}

var (
	nonePrefixRe   = regexp.MustCompile(`(?i)^none`)
	uuidKeyRe      = regexp.MustCompile(`uuid`)
	serialValRe    = regexp.MustCompile(`serial|part|version`)
	zerosRe        = regexp.MustCompile(`^[0]+$`)
	seqDigitsRe    = regexp.MustCompile(`[0]?1234567[8]?[9]?[0]?`)
	sernumWordsRe  = regexp.MustCompile(`(?i)sernum|part[_-]?number|specified|filled|applicable`)
	assetWordsRe   = regexp.MustCompile(`(?i)manufacturer|to be filled|available|asset|^no(ne|t)`)
	genericDirtyRe = regexp.MustCompile(`(?i)to be filled`)
	unSpecRe       = regexp.MustCompile(`(?i)un(known|specified)|no(t|ne)? (asset|provided|defined|available|present|specified)`)
)

// uuidVersions validates canonical RFC4122 forms for versions 1-4 like
// Python's uuid.UUID(val, version=N) round-trip used by _dmi_isclean.
func uuidValid(val string) bool {
	if len(val) != 36 || val[8] != '-' || val[13] != '-' || val[18] != '-' || val[23] != '-' {
		return false
	}
	hex := strings.ReplaceAll(strings.ReplaceAll(
		strings.ReplaceAll(strings.ReplaceAll(val, "-", ""), "{", ""), "}", ""), "urn:", "")
	if len(hex) != 32 {
		return false
	}
	for _, r := range hex {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	version, err := strconv.Atoi(string(val[14]))
	if err != nil {
		return false
	}
	return version >= 1 && version <= 4
}

// dmiIsClean ports _dmi_isclean: filters well-known bogus DMI values.
func dmiIsClean(key, val string) bool {
	if val == "" || nonePrefixRe.MatchString(val) {
		return false
	}
	if uuidKeyRe.MatchString(key) {
		return uuidValid(val)
	}
	if serialValRe.MatchString(key) {
		return !zerosRe.MatchString(val) &&
			!seqDigitsRe.MatchString(val) &&
			!sernumWordsRe.MatchString(val)
	}
	if assetOrMfrRe.MatchString(key) {
		return !assetWordsRe.MatchString(val)
	}
	return !genericDirtyRe.MatchString(val) && !unSpecRe.MatchString(val)
}

var assetOrMfrRe = regexp.MustCompile(`asset|manufacturer`)

// Register installs all smbios-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		getFunc{},
		recordsFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
