package selinux

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// fileTypeDescriptions mirrors Salt's SeFileType enum: the single-letter
// filetype code maps to the descriptive label `semanage fcontext -l` uses.
var fileTypeDescriptions = map[string]string{
	"a": "all files",
	"f": "regular file",
	"d": "directory",
	"c": "character device",
	"b": "block device",
	"s": "socket",
	"l": "symbolic link",
	"p": "named pipe",
}

// fileTypeOrder preserves the enum declaration order used in the
// SaltInvocationError text of SeFileType.from_code.
var fileTypeOrder = []string{"a", "f", "d", "c", "b", "s", "l", "p"}

// fileTypeFromCode mirrors SeFileType.from_code, including its verbatim
// SaltInvocationError message (Python repr quoting of the offending code).
func fileTypeFromCode(code string) (string, error) {
	if desc, ok := fileTypeDescriptions[code]; ok {
		return desc, nil
	}
	return "", fmt.Errorf("Invalid file type code %s; expected one of: %s",
		pyRepr(code), strings.Join(fileTypeOrder, ", "))
}

// pyRepr renders a Go string like Python's repr (single quotes, backslash
// and quote escaping) so error texts stay byte-identical to upstream.
func pyRepr(s string) string {
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `'`, `\'`)
	return "'" + escaped + "'"
}

type FiletypeIdToStringArgs struct {
	Filetype string `statekit:"name=filetype"`
}

type filetypeIdToStringFunc struct {
	linuxOnly
}

func (filetypeIdToStringFunc) Name() string { return "selinux.filetype_id_to_string" }
func (filetypeIdToStringFunc) Args() any    { return FiletypeIdToStringArgs{} }
func (filetypeIdToStringFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*FiletypeIdToStringArgs)
	filetype := a.Filetype
	if filetype == "" {
		// Salt's default argument is "a" (all files).
		filetype = "a"
	}
	return fileTypeFromCode(filetype)
}
