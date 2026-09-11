//go:build windows

package file

// Windows implementation of win_file.py. Native filesystem primitives use
// Runtime.FS; ownership/attributes/ACL/version metadata use encoded
// PowerShell or reg.exe-compatible Windows utilities through Runner. The
// registration selector in file.go keeps the existing POSIX surface on other
// GOOS values.

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/friz-zy/statekit/internal/filesum"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func registerWindowsFile(reg *runtime.ExecRegistry) error {
	// Cross-platform file operations which do not collide with win_file's
	// Windows-specific definitions remain available on Windows.
	for _, fn := range []runtime.ExecFunction{
		fileExistsFunc{}, directoryExistsFunc{}, renameFunc{}, copyFunc{}, readFunc{}, writeFunc{},
		containsFunc{}, appendFunc{}, touchFunc{}, readlinkFunc{},
		basenameFunc{}, dirnameFunc{}, normpathFunc{}, pardirFunc{}, joinFunc{}, pathExistsGlobFunc{},
		prependFunc{}, seekReadFunc{}, seekWriteFunc{}, truncateFunc{}, commentLineFunc{}, commentFunc{},
		uncommentFunc{}, blockreplaceFunc{}, readdirFunc{}, rmdirFunc{}, linkFunc{}, isHardlinkFunc{},
		getSumFunc{}, getHashFunc{}, checkHashFunc{}, extractHashFunc{}, lstatFunc{}, accessFunc{},
		sedFunc{}, sedContainsFunc{}, patchFunc{},
		winGidToGroupFunc{}, winGroupToGidFunc{}, winGetPgidFunc{}, winGetPgroupFunc{},
		winGetGidFunc{}, winGetGroupFunc{}, winUidToUserFunc{}, winUserToUidFunc{}, winGetUidFunc{},
		winGetUserFunc{}, winGetModeFunc{}, winLchownFunc{}, winChownFunc{}, winChpgrpFunc{},
		winChgrpFunc{}, winStatsFunc{}, winVersionFunc{}, winVersionDetailsFunc{},
		winGetAttributesFunc{}, winSetAttributesFunc{}, winSetModeFunc{}, winRemoveFunc{},
		winSymlinkFunc{}, winIsLinkFunc{}, winMkdirFunc{}, winMakedirsFunc{}, winMakedirsPermsFunc{},
		winCheckPermsFunc{}, winSetPermsFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

func winFileExists(rt *runtime.Runtime, path string, follow bool) bool {
	var info fs.FileInfo
	var err error
	if follow {
		info, err = rt.FS.Stat(path)
	} else {
		info, err = rt.FS.Lstat(path)
	}
	return err == nil && info != nil
}

func winFileStat(rt *runtime.Runtime, path string, follow bool) (fs.FileInfo, error) {
	if follow {
		return rt.FS.Stat(path)
	}
	return rt.FS.Lstat(path)
}

func winPSCommand(script string) process.Command {
	units := make([]uint16, 0, len(script)+1)
	for _, r := range script + "\x00" {
		if r <= 0xffff {
			units = append(units, uint16(r))
		} else {
			r -= 0x10000
			units = append(units, uint16(0xd800+(r>>10)), uint16(0xdc00+(r&0x3ff)))
		}
	}
	raw := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], unit)
	}
	return process.Command{Name: "powershell.exe", Args: []string{
		"-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw),
	}}
}

func winPS(ctx context.Context, rt *runtime.Runtime, script string, secrets []string) (string, error) {
	cmd := winPSCommand(script)
	cmd.Redact = secrets
	result := rt.Runner.Run(ctx, cmd)
	if result.Err != nil && result.ExitCode == -1 {
		return string(result.Stdout), result.Err
	}
	if result.ExitCode != 0 {
		return string(result.Stdout), fmt.Errorf("PowerShell command failed (exit code %d): %s", result.ExitCode, strings.TrimSpace(string(result.Stderr)))
	}
	return string(result.Stdout), nil
}

func winPSJSON(ctx context.Context, rt *runtime.Runtime, script string) (map[string]any, error) {
	out, err := winPS(ctx, rt, script, nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(out) == "" || strings.TrimSpace(out) == "null" {
		return map[string]any{}, nil
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(out), &value); err != nil {
		return nil, err
	}
	return value, nil
}

func winOwnerInfo(ctx context.Context, rt *runtime.Runtime, path string) (map[string]any, error) {
	script := "$a=Get-Acl -LiteralPath " + winPSLiteral(path) + " -ErrorAction Stop;[ordered]@{owner=$a.Owner;group=$a.Group}|ConvertTo-Json -Compress"
	return winPSJSON(ctx, rt, script)
}

func winPSLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func winPathError(path string) error { return fmt.Errorf("Path not found: %s", path) }

func winNameToSID(ctx context.Context, rt *runtime.Runtime, name string) (string, error) {
	script := "([System.Security.Principal.NTAccount]" + winPSLiteral(name) + ").Translate([System.Security.Principal.SecurityIdentifier]).Value"
	out, err := winPS(ctx, rt, script, nil)
	return strings.TrimSpace(out), err
}

func winSIDToName(ctx context.Context, rt *runtime.Runtime, sid string) (string, error) {
	script := "([System.Security.Principal.SecurityIdentifier]" + winPSLiteral(sid) + ").Translate([System.Security.Principal.NTAccount]).Value"
	out, err := winPS(ctx, rt, script, nil)
	return strings.TrimSpace(out), err
}

// ---------------------------------------------------------------------------
// identity and metadata

type winPathFollowArgs struct {
	Path           string `statekit:"required"`
	FollowSymlinks *bool  `statekit:"name=follow_symlinks"`
}

func winFollow(a *winPathFollowArgs) bool { return a.FollowSymlinks == nil || *a.FollowSymlinks }

type winGidToGroupArgs struct {
	GID string `statekit:"required,name=gid"`
}
type winGidToGroupFunc struct{}

func (winGidToGroupFunc) Name() string        { return "file.gid_to_group" }
func (winGidToGroupFunc) Args() any           { return winGidToGroupArgs{} }
func (winGidToGroupFunc) Platforms() []string { return []string{"windows"} }
func (winGidToGroupFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*winGidToGroupArgs)
	if a.GID == "" {
		return "", nil
	}
	return winSIDToName(ctx, rt, a.GID)
}

type winGroupToGidArgs struct {
	Group string `statekit:"required,name=group"`
}
type winGroupToGidFunc struct{}

func (winGroupToGidFunc) Name() string        { return "file.group_to_gid" }
func (winGroupToGidFunc) Args() any           { return winGroupToGidArgs{} }
func (winGroupToGidFunc) Platforms() []string { return []string{"windows"} }
func (winGroupToGidFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*winGroupToGidArgs)
	if a.Group == "" {
		return "", nil
	}
	return winNameToSID(ctx, rt, a.Group)
}

type winGetPgidFunc struct{}

func (winGetPgidFunc) Name() string        { return "file.get_pgid" }
func (winGetPgidFunc) Args() any           { return winPathFollowArgs{} }
func (winGetPgidFunc) Platforms() []string { return []string{"windows"} }
func (winGetPgidFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winPathFollowArgs)
	if !winFileExists(rt, a.Path, winFollow(a)) {
		return nil, winPathError(a.Path)
	}
	owner, e := winOwnerInfo(ctx, rt, a.Path)
	if e != nil {
		return nil, e
	}
	return winNameToSID(ctx, rt, fmt.Sprint(owner["group"]))
}

type winGetPgroupFunc struct{}

func (winGetPgroupFunc) Name() string        { return "file.get_pgroup" }
func (winGetPgroupFunc) Args() any           { return winPathFollowArgs{} }
func (winGetPgroupFunc) Platforms() []string { return []string{"windows"} }
func (winGetPgroupFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winPathFollowArgs)
	if !winFileExists(rt, a.Path, winFollow(a)) {
		return nil, winPathError(a.Path)
	}
	owner, e := winOwnerInfo(ctx, rt, a.Path)
	if e != nil {
		return nil, e
	}
	return owner["group"], nil
}

type winGetGidFunc struct{}

func (winGetGidFunc) Name() string        { return "file.get_gid" }
func (winGetGidFunc) Args() any           { return winPathFollowArgs{} }
func (winGetGidFunc) Platforms() []string { return []string{"windows"} }
func (winGetGidFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return winGetUidFunc{}.Execute(ctx, rt, args)
}

type winGetGroupFunc struct{}

func (winGetGroupFunc) Name() string        { return "file.get_group" }
func (winGetGroupFunc) Args() any           { return winPathFollowArgs{} }
func (winGetGroupFunc) Platforms() []string { return []string{"windows"} }
func (winGetGroupFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return winGetUserFunc{}.Execute(ctx, rt, args)
}

type winUidToUserArgs struct {
	UID string `statekit:"required,name=uid"`
}
type winUidToUserFunc struct{}

func (winUidToUserFunc) Name() string        { return "file.uid_to_user" }
func (winUidToUserFunc) Args() any           { return winUidToUserArgs{} }
func (winUidToUserFunc) Platforms() []string { return []string{"windows"} }
func (winUidToUserFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*winUidToUserArgs)
	if a.UID == "" {
		return "", nil
	}
	name, e := winSIDToName(ctx, rt, a.UID)
	if e != nil {
		return a.UID, nil
	}
	return name, nil
}

type winUserToUidArgs struct {
	User string `statekit:"required,name=user"`
}
type winUserToUidFunc struct{}

func (winUserToUidFunc) Name() string        { return "file.user_to_uid" }
func (winUserToUidFunc) Args() any           { return winUserToUidArgs{} }
func (winUserToUidFunc) Platforms() []string { return []string{"windows"} }
func (winUserToUidFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*winUserToUidArgs)
	return winNameToSID(ctx, rt, a.User)
}

type winGetUidFunc struct{}

func (winGetUidFunc) Name() string        { return "file.get_uid" }
func (winGetUidFunc) Args() any           { return winPathFollowArgs{} }
func (winGetUidFunc) Platforms() []string { return []string{"windows"} }
func (winGetUidFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winPathFollowArgs)
	if !winFileExists(rt, a.Path, winFollow(a)) {
		return nil, winPathError(a.Path)
	}
	owner, e := winOwnerInfo(ctx, rt, a.Path)
	if e != nil {
		return nil, e
	}
	return winNameToSID(ctx, rt, fmt.Sprint(owner["owner"]))
}

type winGetUserFunc struct{}

func (winGetUserFunc) Name() string        { return "file.get_user" }
func (winGetUserFunc) Args() any           { return winPathFollowArgs{} }
func (winGetUserFunc) Platforms() []string { return []string{"windows"} }
func (winGetUserFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winPathFollowArgs)
	if !winFileExists(rt, a.Path, winFollow(a)) {
		return nil, winPathError(a.Path)
	}
	owner, e := winOwnerInfo(ctx, rt, a.Path)
	if e != nil {
		return nil, e
	}
	return owner["owner"], nil
}

type winGetModeFunc struct{}

func (winGetModeFunc) Name() string        { return "file.get_mode" }
func (winGetModeFunc) Args() any           { return winPathFollowArgs{} }
func (winGetModeFunc) Platforms() []string { return []string{"windows"} }
func (winGetModeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winPathFollowArgs)
	if !winFileExists(rt, a.Path, winFollow(a)) {
		return nil, winPathError(a.Path)
	}
	return nil, nil
}

type winSetModeArgs struct {
	Path string `statekit:"required"`
	Mode string `statekit:"required,name=mode"`
}
type winSetModeFunc struct{}

func (winSetModeFunc) Name() string        { return "file.set_mode" }
func (winSetModeFunc) Args() any           { return winSetModeArgs{} }
func (winSetModeFunc) Platforms() []string { return []string{"windows"} }
func (winSetModeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*winSetModeArgs)
	if !winFileExists(rt, a.Path, true) {
		return nil, winPathError(a.Path)
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// ownership

type winChownArgs struct {
	Path           string  `statekit:"required"`
	User           string  `statekit:"required,name=user"`
	Group          *string `statekit:"name=group"`
	Pgroup         *string `statekit:"name=pgroup"`
	FollowSymlinks *bool   `statekit:"name=follow_symlinks"`
}
type winChownFunc struct{}

func (winChownFunc) Name() string        { return "file.chown" }
func (winChownFunc) Args() any           { return winChownArgs{} }
func (winChownFunc) Platforms() []string { return []string{"windows"} }
func (winChownFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winChownArgs)
	if !winFileExists(rt, a.Path, a.FollowSymlinks == nil || *a.FollowSymlinks) {
		return nil, winPathError(a.Path)
	}
	script := "$a=Get-Acl -LiteralPath " + winPSLiteral(a.Path) + ";$a.SetOwner([System.Security.Principal.NTAccount]" + winPSLiteral(a.User) + ");Set-Acl -LiteralPath " + winPSLiteral(a.Path) + " -AclObject $a"
	if a.Pgroup != nil && *a.Pgroup != "" {
		script += ";# primary group is not exposed by Set-Acl"
	}
	_, e := winPS(ctx, rt, script, nil)
	return e == nil, e
}

type winLchownFunc struct{}

func (winLchownFunc) Name() string        { return "file.lchown" }
func (winLchownFunc) Args() any           { return winChownArgs{} }
func (winLchownFunc) Platforms() []string { return []string{"windows"} }
func (winLchownFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return winChownFunc{}.Execute(ctx, rt, args)
}

type winChpgrpArgs struct {
	Path  string `statekit:"required"`
	Group string `statekit:"required,name=group"`
}
type winChpgrpFunc struct{}

func (winChpgrpFunc) Name() string        { return "file.chpgrp" }
func (winChpgrpFunc) Args() any           { return winChpgrpArgs{} }
func (winChpgrpFunc) Platforms() []string { return []string{"windows"} }
func (winChpgrpFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*winChpgrpArgs)
	return winChownFunc{}.Execute(ctx, rt, &winChownArgs{Path: a.Path, User: a.Group})
}

type winChgrpArgs struct {
	Path  string `statekit:"required"`
	Group string `statekit:"required,name=group"`
}
type winChgrpFunc struct{}

func (winChgrpFunc) Name() string                                                { return "file.chgrp" }
func (winChgrpFunc) Args() any                                                   { return winChgrpArgs{} }
func (winChgrpFunc) Platforms() []string                                         { return []string{"windows"} }
func (winChgrpFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) { return nil, nil }

// ---------------------------------------------------------------------------
// stats/version/attributes

type winStatsArgs struct {
	Path           string  `statekit:"required"`
	HashType       *string `statekit:"name=hash_type"`
	FollowSymlinks *bool   `statekit:"name=follow_symlinks"`
}
type winStatsFunc struct{}

func (winStatsFunc) Name() string        { return "file.stats" }
func (winStatsFunc) Args() any           { return winStatsArgs{} }
func (winStatsFunc) Platforms() []string { return []string{"windows"} }
func (winStatsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winStatsArgs)
	follow := a.FollowSymlinks == nil || *a.FollowSymlinks
	info, e := winFileStat(rt, a.Path, follow)
	if e != nil {
		return nil, winPathError(a.Path)
	}
	uid, _ := winGetUidFunc{}.Execute(ctx, rt, &winPathFollowArgs{Path: a.Path, FollowSymlinks: pbFile(follow)})
	user, _ := winGetUserFunc{}.Execute(ctx, rt, &winPathFollowArgs{Path: a.Path, FollowSymlinks: pbFile(follow)})
	hashType := "sha256"
	if a.HashType != nil {
		hashType = *a.HashType
	}
	out := map[string]any{"inode": int64(0), "uid": uid, "gid": uid, "user": user, "group": user, "pgid": uid, "pgroup": user, "atime": float64(0), "mtime": float64(info.ModTime().Unix()), "ctime": float64(0), "size": info.Size(), "mode": fmt.Sprintf("%04o", info.Mode().Perm()), "type": "file", "target": a.Path}
	if info.IsDir() {
		out["type"] = "dir"
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		out["type"] = "link"
		if target, e := rt.FS.Readlink(a.Path); e == nil {
			out["target"] = target
		}
	}
	if hashType != "" {
		data, e := rt.FS.ReadFile(a.Path)
		if e == nil {
			h, e := filesum.New(hashType)
			if e != nil {
				return nil, e
			}
			_, _ = h.Write(data)
			out["sum"] = fmt.Sprintf("%x", h.Sum(nil))
		}
	}
	return out, nil
}
func pbFile(value bool) *bool { return &value }

type winVersionArgs struct {
	Path string `statekit:"required"`
}
type winVersionFunc struct{}

func (winVersionFunc) Name() string        { return "file.version" }
func (winVersionFunc) Args() any           { return winVersionArgs{} }
func (winVersionFunc) Platforms() []string { return []string{"windows"} }
func (winVersionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winVersionArgs)
	info, e := winFileStat(rt, a.Path, true)
	if e != nil {
		return nil, fmt.Errorf("File not found: %s", a.Path)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("Not a file: %s", a.Path)
	}
	out, e := winPS(ctx, rt, "(Get-Item -LiteralPath "+winPSLiteral(a.Path)+").VersionInfo.FileVersion", nil)
	return strings.TrimSpace(out), e
}

type winVersionDetailsFunc struct{}

func (winVersionDetailsFunc) Name() string        { return "file.version_details" }
func (winVersionDetailsFunc) Args() any           { return winVersionArgs{} }
func (winVersionDetailsFunc) Platforms() []string { return []string{"windows"} }
func (winVersionDetailsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winVersionArgs)
	info, e := winFileStat(rt, a.Path, true)
	if e != nil {
		return nil, fmt.Errorf("File not found: %s", a.Path)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("Not a file: %s", a.Path)
	}
	script := "$v=(Get-Item -LiteralPath " + winPSLiteral(a.Path) + ").VersionInfo;[ordered]@{Version=$v.FileVersion;FileVersion=$v.FileVersion;ProductVersion=$v.ProductVersion;CompanyName=$v.CompanyName;FileDescription=$v.FileDescription;ProductName=$v.ProductName;OriginalFilename=$v.OriginalFilename}|ConvertTo-Json -Compress"
	return winPSJSON(ctx, rt, script)
}

type winGetAttributesFunc struct{}

func (winGetAttributesFunc) Name() string        { return "file.get_attributes" }
func (winGetAttributesFunc) Args() any           { return winVersionArgs{} }
func (winGetAttributesFunc) Platforms() []string { return []string{"windows"} }
func (winGetAttributesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winVersionArgs)
	if !winFileExists(rt, a.Path, true) {
		return nil, winPathError(a.Path)
	}
	result := rt.Runner.Run(ctx, runtime.Command("attrib.exe", a.Path))
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("Path not found: %s", a.Path)
	}
	text := string(result.Stdout)
	attrs := map[string]any{"archive": false, "reparsePoint": false, "compressed": false, "directory": false, "encrypted": false, "hidden": false, "mountedVolume": false, "normal": false, "notIndexed": false, "offline": false, "readonly": false, "symbolicLink": false, "system": false, "temporary": false}
	if info, e := rt.FS.Lstat(a.Path); e == nil {
		attrs["directory"] = info.IsDir()
		attrs["symbolicLink"] = info.Mode()&fs.ModeSymlink != 0
		attrs["reparsePoint"] = attrs["symbolicLink"]
	}
	fields := strings.Fields(text)
	for _, flag := range fields {
		switch strings.ToUpper(flag) {
		case "A":
			attrs["archive"] = true
		case "H":
			attrs["hidden"] = true
		case "R":
			attrs["readonly"] = true
		case "S":
			attrs["system"] = true
		case "I":
			attrs["notIndexed"] = true
		case "T":
			attrs["temporary"] = true
		}
	}
	if !attrs["archive"].(bool) && !attrs["hidden"].(bool) && !attrs["readonly"].(bool) && !attrs["system"].(bool) {
		attrs["normal"] = true
	}
	return attrs, nil
}

type winSetAttributesArgs struct {
	Path       string `statekit:"required"`
	Archive    *bool  `statekit:"name=archive"`
	Hidden     *bool  `statekit:"name=hidden"`
	Normal     *bool  `statekit:"name=normal"`
	NotIndexed *bool  `statekit:"name=notIndexed"`
	Readonly   *bool  `statekit:"name=readonly"`
	System     *bool  `statekit:"name=system"`
	Temporary  *bool  `statekit:"name=temporary"`
}
type winSetAttributesFunc struct{}

func (winSetAttributesFunc) Name() string        { return "file.set_attributes" }
func (winSetAttributesFunc) Args() any           { return winSetAttributesArgs{} }
func (winSetAttributesFunc) Platforms() []string { return []string{"windows"} }
func (winSetAttributesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winSetAttributesArgs)
	if !winFileExists(rt, a.Path, true) {
		return nil, winPathError(a.Path)
	}
	if a.Normal != nil && *a.Normal {
		for _, v := range []*bool{a.Archive, a.Hidden, a.NotIndexed, a.Readonly, a.System, a.Temporary} {
			if v != nil {
				return nil, fmt.Errorf("Normal attribute may not be used with any other attributes")
			}
		}
	}
	argv := []string{"attrib"}
	if a.Normal != nil && *a.Normal {
		argv = append(argv, "-a", "-h", "-i", "-r", "-s", "-t")
	} else {
		for flag, value := range map[string]*bool{"a": a.Archive, "h": a.Hidden, "i": a.NotIndexed, "r": a.Readonly, "s": a.System, "t": a.Temporary} {
			if value != nil {
				prefix := "-"
				if *value {
					prefix = "+"
				}
				argv = append(argv, prefix+flag)
			}
		}
	}
	argv = append(argv, a.Path)
	result := rt.Runner.Run(ctx, runtime.Command(argv...))
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	return result.ExitCode == 0, nil
}

// ---------------------------------------------------------------------------
// remove/links/directories

type winRemoveArgs struct {
	Path  string `statekit:"required"`
	Force bool   `statekit:"name=force"`
}
type winRemoveFunc struct{}

func (winRemoveFunc) Name() string        { return "file.remove" }
func (winRemoveFunc) Args() any           { return winRemoveArgs{} }
func (winRemoveFunc) Platforms() []string { return []string{"windows"} }
func (winRemoveFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winRemoveArgs)
	if !winFileExists(rt, a.Path, false) {
		return nil, winPathError(a.Path)
	}
	return true, rt.FS.RemoveAll(a.Path)
}

type winSymlinkArgs struct {
	Src            string `statekit:"required,name=src"`
	Link           string `statekit:"required,name=link"`
	Force          bool   `statekit:"name=force"`
	Atomic         bool   `statekit:"name=atomic"`
	FollowSymlinks *bool  `statekit:"name=follow_symlinks"`
}
type winSymlinkFunc struct{}

func (winSymlinkFunc) Name() string        { return "file.symlink" }
func (winSymlinkFunc) Args() any           { return winSymlinkArgs{} }
func (winSymlinkFunc) Platforms() []string { return []string{"windows"} }
func (winSymlinkFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winSymlinkArgs)
	if !filepath.IsAbs(a.Link) {
		return nil, fmt.Errorf("Link path must be absolute: %s", a.Link)
	}
	if !winFileExists(rt, a.Src, true) {
		return nil, winPathError(a.Src)
	}
	if winFileExists(rt, a.Link, false) {
		if !a.Force && !a.Atomic {
			return nil, fmt.Errorf("Existing path is not a symlink: %s", a.Link)
		}
		if e := rt.FS.RemoveAll(a.Link); e != nil {
			return nil, e
		}
	}
	return true, rt.FS.Symlink(a.Src, a.Link)
}

type winIsLinkArgs struct {
	Path string `statekit:"required"`
}
type winIsLinkFunc struct{}

func (winIsLinkFunc) Name() string        { return "file.is_link" }
func (winIsLinkFunc) Args() any           { return winIsLinkArgs{} }
func (winIsLinkFunc) Platforms() []string { return []string{"windows"} }
func (winIsLinkFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	info, e := rt.FS.Lstat(args.(*winIsLinkArgs).Path)
	if e != nil {
		return false, nil
	}
	return info.Mode()&fs.ModeSymlink != 0, nil
}

type winMkdirArgs struct {
	Path        string         `statekit:"required"`
	Owner       *string        `statekit:"name=owner"`
	GrantPerms  map[string]any `statekit:"name=grant_perms"`
	DenyPerms   map[string]any `statekit:"name=deny_perms"`
	Inheritance *bool          `statekit:"name=inheritance"`
	Reset       bool           `statekit:"name=reset"`
}
type winMkdirFunc struct{}

func (winMkdirFunc) Name() string        { return "file.mkdir" }
func (winMkdirFunc) Args() any           { return winMkdirArgs{} }
func (winMkdirFunc) Platforms() []string { return []string{"windows"} }
func (winMkdirFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winMkdirArgs)
	if e := rt.FS.MkdirAll(a.Path, 0o755); e != nil {
		return nil, e
	}
	if a.Owner != nil && *a.Owner != "" {
		_, e := winChownFunc{}.Execute(ctx, rt, &winChownArgs{Path: a.Path, User: *a.Owner})
		if e != nil {
			return false, e
		}
	}
	_, e := winSetPermsImpl(ctx, rt, a.Path, a.GrantPerms, a.DenyPerms, a.Inheritance, a.Reset)
	return e == nil, e
}

type winMakedirsArgs struct {
	Path        string         `statekit:"required"`
	Owner       *string        `statekit:"name=owner"`
	GrantPerms  map[string]any `statekit:"name=grant_perms"`
	DenyPerms   map[string]any `statekit:"name=deny_perms"`
	Inheritance *bool          `statekit:"name=inheritance"`
	Reset       bool           `statekit:"name=reset"`
}
type winMakedirsFunc struct{}

func (winMakedirsFunc) Name() string        { return "file.makedirs" }
func (winMakedirsFunc) Args() any           { return winMakedirsArgs{} }
func (winMakedirsFunc) Platforms() []string { return []string{"windows"} }
func (winMakedirsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winMakedirsArgs)
	path := a.Path
	if !strings.HasSuffix(path, `\`) && !strings.HasSuffix(path, "/") {
		path = filepath.Dir(path)
	}
	if e := rt.FS.MkdirAll(path, 0o755); e != nil {
		return nil, e
	}
	return true, nil
}

type winMakedirsPermsFunc struct{}

func (winMakedirsPermsFunc) Name() string        { return "file.makedirs_perms" }
func (winMakedirsPermsFunc) Args() any           { return winMakedirsArgs{} }
func (winMakedirsPermsFunc) Platforms() []string { return []string{"windows"} }
func (winMakedirsPermsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return winMkdirFunc{}.Execute(ctx, rt, args)
}

// ---------------------------------------------------------------------------
// ACL permissions

type winPermsArgs struct {
	Path        string         `statekit:"required"`
	GrantPerms  map[string]any `statekit:"name=grant_perms"`
	DenyPerms   map[string]any `statekit:"name=deny_perms"`
	Inheritance *bool          `statekit:"name=inheritance"`
	Reset       bool           `statekit:"name=reset"`
	Ret         map[string]any `statekit:"name=ret"`
}
type winCheckPermsFunc struct{}

func (winCheckPermsFunc) Name() string        { return "file.check_perms" }
func (winCheckPermsFunc) Args() any           { return winPermsArgs{} }
func (winCheckPermsFunc) Platforms() []string { return []string{"windows"} }
func (winCheckPermsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winPermsArgs)
	if !winFileExists(rt, a.Path, true) {
		return nil, winPathError(a.Path)
	}
	ok, e := winSetPermsImpl(ctx, rt, a.Path, a.GrantPerms, a.DenyPerms, a.Inheritance, a.Reset)
	if e != nil {
		return nil, e
	}
	if a.Ret != nil {
		return a.Ret, nil
	}
	return map[string]any{"result": ok}, nil
}

type winSetPermsFunc struct{}

func (winSetPermsFunc) Name() string        { return "file.set_perms" }
func (winSetPermsFunc) Args() any           { return winPermsArgs{} }
func (winSetPermsFunc) Platforms() []string { return []string{"windows"} }
func (winSetPermsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinFile(&res, &err)
	a := args.(*winPermsArgs)
	return winSetPermsImpl(ctx, rt, a.Path, a.GrantPerms, a.DenyPerms, a.Inheritance, a.Reset)
}
func winSetPermsImpl(ctx context.Context, rt *runtime.Runtime, path string, grant, deny map[string]any, inheritance *bool, reset bool) (bool, error) {
	if !winFileExists(rt, path, true) {
		return false, winPathError(path)
	}
	if reset {
		r := rt.Runner.Run(ctx, runtime.Command("icacls", path, "/reset"))
		if r.ExitCode != 0 {
			return false, fmt.Errorf("icacls reset failed: %s", r.Stderr)
		}
	}
	args := []string{"icacls", path}
	if inheritance != nil {
		if *inheritance {
			args = append(args, "/inheritance:e")
		} else {
			args = append(args, "/inheritance:r")
		}
	}
	for principal, raw := range grant {
		args = append(args, "/grant", principal+":"+winPermText(raw))
	}
	for principal, raw := range deny {
		args = append(args, "/deny", principal+":"+winPermText(raw))
	}
	if len(args) == 2 {
		return true, nil
	}
	r := rt.Runner.Run(ctx, runtime.Command(args...))
	if r.Err != nil && r.ExitCode == -1 {
		return false, r.Err
	}
	return r.ExitCode == 0, nil
}
func winPermText(raw any) string {
	m, ok := raw.(map[string]any)
	if ok {
		raw = m["perms"]
	}
	switch strings.ToLower(fmt.Sprint(raw)) {
	case "full_control", "full":
		return "F"
	case "modify":
		return "M"
	case "read_execute", "read and execute":
		return "RX"
	case "read":
		return "R"
	case "write":
		return "W"
	default:
		return fmt.Sprint(raw)
	}
}

func recoverWinFile(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}
