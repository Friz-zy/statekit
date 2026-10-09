package user

import (
	"context"
	"errors"
	"reflect"
	goruntime "runtime"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"github.com/friz-zy/statekit/internal/runtime"
)

var (
	errWinProfileInput             = errors.New("invalid profile arguments")
	errWinProfileUnsupported       = errors.New("profile operation unsupported")
	errWinProfileRole              = errors.New("local account role could not be verified")
	errWinProfileMissing           = errors.New("profile account not found")
	errWinProfileGet               = errors.New("profile account lookup failed")
	errWinProfileSet               = errors.New("profile update failed; account state unknown")
	errWinProfileBuffer            = errors.New("invalid profile account buffer")
	errWinProfileCleanup           = errors.New("profile buffer cleanup failed")
	errWinProfileCleanupNoMutation = errors.New("profile existence check completed but cleanup failed; no profile mutation was issued")
)

const (
	// Input bounds exclude the terminating UTF-16 NUL. Native account and path
	// acceptance remains the server's decision; paths are not canonicalized.
	maxWinProfileUnits = 32767

	winUserInfo1052Level              = 1052
	dsRolePrimaryDomainInfoBasicLevel = 1
)

const (
	dsRoleStandaloneWorkstation uint32 = iota
	dsRoleMemberWorkstation
	dsRoleStandaloneServer
	dsRoleMemberServer
	dsRoleBackupDomainController
	dsRolePrimaryDomainController
)

type winProfileAPI interface {
	SetProfile(context.Context, string, string) (bool, error)
}

type winChprofileArgs struct {
	Name    string  `statekit:"required"`
	Profile *string `statekit:"required,name=profile"`
}

type winChprofileFunc struct {
	api winProfileAPI
}

func (winChprofileFunc) Name() string        { return "user.chprofile" }
func (winChprofileFunc) Args() any           { return winChprofileArgs{} }
func (winChprofileFunc) Platforms() []string { return []string{"windows"} }
func (f winChprofileFunc) Execute(ctx context.Context, _ *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*winChprofileArgs)
	if !ok || a == nil || a.Profile == nil {
		return false, errWinProfileInput
	}
	if _, err := profileNameUTF16(a.Name); err != nil {
		return false, err
	}
	if _, err := profileUTF16(*a.Profile); err != nil {
		return false, err
	}
	if ctx == nil {
		return false, errWinProfileInput
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	api := f.api
	if api == nil {
		api = newWinProfileAPI()
	}
	if nilProfileAPI(api) {
		return false, errWinProfileUnsupported
	}
	return api.SetProfile(ctx, a.Name, *a.Profile)
}

// Private seams also reject typed nils rather than dispatching into nil receivers.
func nilProfileAPI(api any) bool {
	if api == nil {
		return true
	}
	v := reflect.ValueOf(api)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func profileNameUTF16(name string) ([]uint16, error) {
	// These forms ask Windows to resolve an identity outside the local SAM.
	// Never resolve or reinterpret them as a local account name.
	if name == "" || strings.ContainsAny(name, `\/@`) {
		return nil, errWinProfileInput
	}
	return profileUTF16(name)
}

func profileUTF16(value string) ([]uint16, error) {
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return nil, errWinProfileInput
	}
	count := 0
	for _, r := range value {
		count++
		if r > 0xffff {
			count++
		}
		if count > maxWinProfileUnits {
			return nil, errWinProfileInput
		}
	}
	return append(utf16.Encode([]rune(value)), 0), nil
}

// USER_INFO_1052 has exactly one field: the profile path pointer.
// https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_1052
type winUserInfo1052 struct {
	Profile *uint16
}

// Only MachineRole is read from this native allocation. Other values and
// pointers are intentionally opaque and remain owned by DsRoleFreeMemory.
type winDSRolePrimaryDomainInfoBasic struct {
	MachineRole      uint32
	Flags            uint32
	DomainNameFlat   *uint16
	DomainNameDNS    *uint16
	DomainForestName *uint16
	DomainGUID       winGUID
}

type winGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type profileNetAPI interface {
	SupportedWindowsVersion() bool
	GetRoleInfo(server *uint16, level uint32) (unsafe.Pointer, uint32)
	FreeRole(owner unsafe.Pointer)
	GetInfo(server, name *uint16, level uint32) (unsafe.Pointer, uint32)
	SetInfo(server, name *uint16, level uint32, owner unsafe.Pointer, parmErr *uint32) uint32
	Free(owner unsafe.Pointer) uint32
}

type netWinProfileAPI struct {
	api profileNetAPI
}

func profileStatus(status uint32, failure error) error {
	if status == 0 {
		return nil
	}
	if status == 2221 { // NERR_UserNotFound
		return errors.Join(failure, errWinProfileMissing)
	}
	return failure
}

func (a netWinProfileAPI) SetProfile(ctx context.Context, name, profile string) (success bool, err error) {
	if ctx == nil {
		return false, errWinProfileInput
	}
	user, err := profileNameUTF16(name)
	if err != nil {
		return false, err
	}
	path, err := profileUTF16(profile)
	if err != nil {
		return false, err
	}
	if nilProfileAPI(a.api) {
		return false, errWinProfileUnsupported
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !a.api.SupportedWindowsVersion() {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		return false, errWinProfileUnsupported
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	role, roleErr := a.localMachineRole()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if roleErr != nil {
		return false, roleErr
	}
	if !localProfileRole(role) {
		return false, errWinProfileRole
	}

	if profile == "" {
		return a.profileExists(ctx, &user[0])
	}

	info := winUserInfo1052{Profile: &path[0]}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	role, roleErr = a.localMachineRole()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if roleErr != nil {
		return false, roleErr
	}
	if !localProfileRole(role) {
		return false, errWinProfileRole
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// NetUserSetInfo is synchronous; keep all Go-owned pointers live until it
	// returns. A failure has unknown state and is never retried or rolled back.
	status := a.api.SetInfo(nil, &user[0], winUserInfo1052Level, unsafe.Pointer(&info), nil)
	goruntime.KeepAlive(info)
	goruntime.KeepAlive(path)
	goruntime.KeepAlive(user)
	if err := profileStatus(status, errWinProfileSet); err != nil {
		return false, err
	}
	return true, nil
}

func (a netWinProfileAPI) localMachineRole() (uint32, error) {
	owner, status := a.api.GetRoleInfo(nil, dsRolePrimaryDomainInfoBasicLevel)
	if owner != nil {
		defer a.api.FreeRole(owner)
	}
	if status != 0 || owner == nil {
		return 0, errWinProfileRole
	}
	return (*winDSRolePrimaryDomainInfoBasic)(owner).MachineRole, nil
}

func localProfileRole(role uint32) bool {
	switch role {
	case dsRoleStandaloneWorkstation, dsRoleMemberWorkstation, dsRoleStandaloneServer, dsRoleMemberServer:
		return true
	default:
		return false
	}
}

func (a netWinProfileAPI) profileExists(ctx context.Context, name *uint16) (success bool, err error) {
	owner, status := a.api.GetInfo(nil, name, 0)
	goruntime.KeepAlive(name)
	if owner != nil {
		defer func() {
			if cleanup := profileStatus(a.api.Free(owner), errWinProfileCleanup); cleanup != nil {
				if success {
					cleanup = errors.Join(cleanup, errWinProfileCleanupNoMutation)
				}
				err = errors.Join(err, cleanup)
			}
		}()
	}
	if statusErr := profileStatus(status, errWinProfileGet); statusErr != nil {
		return false, statusErr
	}
	if owner == nil {
		return false, errWinProfileBuffer
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// The opaque buffer establishes existence only. Never inspect, clear, or
	// write it; the supplied empty value does not prove profile-write access.
	return true, nil
}
