//go:build windows

package user

import (
	"errors"
	goruntime "runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type nativeProfileNetAPI struct {
	version  *windows.LazyProc
	roleGet  *windows.LazyProc
	roleFree *windows.LazyProc
	set      *windows.LazyProc
}

type winOSVersionInfoEx struct {
	Size             uint32
	MajorVersion     uint32
	MinorVersion     uint32
	BuildNumber      uint32
	PlatformID       uint32
	CSDVersion       [128]uint16
	ServicePackMajor uint16
	ServicePackMinor uint16
	SuiteMask        uint16
	ProductType      byte
	Reserved         byte
}

func newWinProfileAPI() winProfileAPI {
	netapi := windows.NewLazySystemDLL("netapi32.dll")
	dsrole := windows.NewLazySystemDLL("dsrole.dll")
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	return netWinProfileAPI{api: nativeProfileNetAPI{
		version:  kernel.NewProc("GetVersionExW"),
		roleGet:  dsrole.NewProc("DsRoleGetPrimaryDomainInformation"),
		roleFree: dsrole.NewProc("DsRoleFreeMemory"),
		set:      netapi.NewProc("NetUserSetInfo"),
	}}
}

// This slice's documented native APIs have a combined Vista/Server 2008
// minimum. Check the reported OS version at runtime; resolving exports alone
// does not establish that minimum-version contract.
func (a nativeProfileNetAPI) SupportedWindowsVersion() bool {
	if a.version == nil || a.version.Find() != nil {
		return false
	}
	version := winOSVersionInfoEx{Size: uint32(unsafe.Sizeof(winOSVersionInfoEx{}))}
	result, _, _ := a.version.Call(uintptr(unsafe.Pointer(&version)))
	goruntime.KeepAlive(&version)
	return result != 0 && version.MajorVersion >= 6
}

func nativeProfileStatus(err error) uint32 {
	if err == nil {
		return 0
	}
	var status syscall.Errno
	if errors.As(err, &status) {
		return uint32(status)
	}
	return 50
}

func (a nativeProfileNetAPI) GetRoleInfo(server *uint16, level uint32) (unsafe.Pointer, uint32) {
	// Verify both exports before allocating a role buffer so every successful
	// allocation has its matching, VOID-returning DsRoleFreeMemory routine.
	if a.roleGet == nil || a.roleFree == nil || a.roleGet.Find() != nil || a.roleFree.Find() != nil {
		return nil, 127
	}
	var buffer *byte
	status, _, _ := a.roleGet.Call(
		uintptr(unsafe.Pointer(server)),
		uintptr(level),
		uintptr(unsafe.Pointer(&buffer)),
	)
	goruntime.KeepAlive(&buffer)
	return unsafe.Pointer(buffer), uint32(status)
}

func (a nativeProfileNetAPI) FreeRole(owner unsafe.Pointer) {
	if owner == nil || a.roleFree == nil || a.roleFree.Find() != nil {
		return
	}
	// DsRoleFreeMemory returns VOID. Its call result is deliberately ignored.
	a.roleFree.Call(uintptr(owner))
}

func (nativeProfileNetAPI) GetInfo(server, name *uint16, level uint32) (unsafe.Pointer, uint32) {
	var buffer *byte
	err := windows.NetUserGetInfo(server, name, level, &buffer)
	return unsafe.Pointer(buffer), nativeProfileStatus(err)
}

func (a nativeProfileNetAPI) SetInfo(server, name *uint16, level uint32, owner unsafe.Pointer, parmErr *uint32) uint32 {
	if a.set == nil || a.set.Find() != nil {
		return 50
	}
	status, _, _ := a.set.Call(
		uintptr(unsafe.Pointer(server)),
		uintptr(unsafe.Pointer(name)),
		uintptr(level),
		uintptr(owner),
		uintptr(unsafe.Pointer(parmErr)),
	)
	// NET_API_STATUS is the primary return value, never GetLastError.
	goruntime.KeepAlive(owner)
	goruntime.KeepAlive(name)
	return uint32(status)
}

func (nativeProfileNetAPI) Free(owner unsafe.Pointer) uint32 {
	return nativeProfileStatus(windows.NetApiBufferFree((*byte)(owner)))
}
