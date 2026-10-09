//go:build windows && (amd64 || arm64)

package user

import "unsafe"

var (
	_ [8 - unsafe.Sizeof(winUserInfo1052{})]byte
	_ [unsafe.Sizeof(winUserInfo1052{}) - 8]byte
	_ [8 - unsafe.Alignof(winUserInfo1052{})]byte
	_ [unsafe.Alignof(winUserInfo1052{}) - 8]byte
	_ [0 - unsafe.Offsetof(winUserInfo1052{}.Profile)]byte
	_ [unsafe.Offsetof(winUserInfo1052{}.Profile) - 0]byte

	_ [48 - unsafe.Sizeof(winDSRolePrimaryDomainInfoBasic{})]byte
	_ [unsafe.Sizeof(winDSRolePrimaryDomainInfoBasic{}) - 48]byte
	_ [8 - unsafe.Alignof(winDSRolePrimaryDomainInfoBasic{})]byte
	_ [unsafe.Alignof(winDSRolePrimaryDomainInfoBasic{}) - 8]byte
	_ [0 - unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.MachineRole)]byte
	_ [unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.MachineRole) - 0]byte
	_ [4 - unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.Flags)]byte
	_ [unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.Flags) - 4]byte
	_ [8 - unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainNameFlat)]byte
	_ [unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainNameFlat) - 8]byte
	_ [16 - unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainNameDNS)]byte
	_ [unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainNameDNS) - 16]byte
	_ [24 - unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainForestName)]byte
	_ [unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainForestName) - 24]byte
	_ [32 - unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainGUID)]byte
	_ [unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainGUID) - 32]byte
)
