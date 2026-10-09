//go:build windows && 386

package user

import "unsafe"

var (
	_ [4 - unsafe.Sizeof(winUserInfo1052{})]byte
	_ [unsafe.Sizeof(winUserInfo1052{}) - 4]byte
	_ [4 - unsafe.Alignof(winUserInfo1052{})]byte
	_ [unsafe.Alignof(winUserInfo1052{}) - 4]byte
	_ [0 - unsafe.Offsetof(winUserInfo1052{}.Profile)]byte
	_ [unsafe.Offsetof(winUserInfo1052{}.Profile) - 0]byte

	_ [36 - unsafe.Sizeof(winDSRolePrimaryDomainInfoBasic{})]byte
	_ [unsafe.Sizeof(winDSRolePrimaryDomainInfoBasic{}) - 36]byte
	_ [4 - unsafe.Alignof(winDSRolePrimaryDomainInfoBasic{})]byte
	_ [unsafe.Alignof(winDSRolePrimaryDomainInfoBasic{}) - 4]byte
	_ [0 - unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.MachineRole)]byte
	_ [unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.MachineRole) - 0]byte
	_ [4 - unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.Flags)]byte
	_ [unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.Flags) - 4]byte
	_ [8 - unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainNameFlat)]byte
	_ [unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainNameFlat) - 8]byte
	_ [12 - unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainNameDNS)]byte
	_ [unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainNameDNS) - 12]byte
	_ [16 - unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainForestName)]byte
	_ [unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainForestName) - 16]byte
	_ [20 - unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainGUID)]byte
	_ [unsafe.Offsetof(winDSRolePrimaryDomainInfoBasic{}.DomainGUID) - 20]byte
)
