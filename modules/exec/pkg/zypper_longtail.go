package pkg

type ZypperListUpgradesArgs struct {
	Refresh       *bool   `statekit:"name=refresh"`
	Root          *string `statekit:"name=root"`
	Fromrepo      any     `statekit:"name=fromrepo"`
	Repos         any     `statekit:"name=repos"`
	Gpgautoimport *bool   `statekit:"name=gpgautoimport"`
}

type ZypperUpgradeAvailableArgs struct {
	Name          string  `statekit:"required,name=name"`
	Refresh       *bool   `statekit:"name=refresh"`
	Root          *string `statekit:"name=root"`
	Fromrepo      any     `statekit:"name=fromrepo"`
	Repos         any     `statekit:"name=repos"`
	Gpgautoimport *bool   `statekit:"name=gpgautoimport"`
}

// ZypperListPatternsArgs mirrors zypperpkg.list_patterns exactly.  The
// source exposes only refresh and root; repository/options kwargs are not
// invented here because this function does not support them.
type ZypperListPatternsArgs struct {
	Refresh *bool   `statekit:"name=refresh"`
	Root    *string `statekit:"name=root"`
}

// ZypperListInstalledPatternsArgs mirrors
// zypperpkg.list_installed_patterns exactly.  It has no refresh or repository
// selector in the pinned source signature.
type ZypperListInstalledPatternsArgs struct {
	Root *string `statekit:"name=root"`
}

// ZypperListLocksArgs mirrors zypperpkg.list_locks(root=None) exactly.
type ZypperListLocksArgs struct {
	Root *string `statekit:"name=root"`
}

// ZypperCleanLocksArgs mirrors zypperpkg.clean_locks(root=None) exactly.
type ZypperCleanLocksArgs struct {
	Root *string `statekit:"name=root"`
}

// ZypperInfoAvailableArgs mirrors zypperpkg.info_available.  The source uses
// variadic package names plus **kwargs; only kwargs with source-backed
// repository refresh semantics are represented here.
type ZypperInfoAvailableArgs struct {
	Names         []string `statekit:"name=names"`
	Refresh       *bool    `statekit:"name=refresh"`
	Root          *string  `statekit:"name=root"`
	Repos         any      `statekit:"name=repos"`
	Gpgautoimport *bool    `statekit:"name=gpgautoimport"`
}

// ZypperSearchArgs mirrors zypperpkg.search and keeps every search selector
// explicit so the provider can reject unrecognized or mistyped options.
type ZypperSearchArgs struct {
	Criteria           string  `statekit:"required"`
	Refresh            *bool   `statekit:"name=refresh"`
	Root               *string `statekit:"name=root"`
	Match              *string `statekit:"name=match"`
	Provides           *bool   `statekit:"name=provides"`
	Recommends         *bool   `statekit:"name=recommends"`
	Requires           *bool   `statekit:"name=requires"`
	Suggests           *bool   `statekit:"name=suggests"`
	Conflicts          *bool   `statekit:"name=conflicts"`
	Obsoletes          *bool   `statekit:"name=obsoletes"`
	FileList           *bool   `statekit:"name=file_list"`
	SearchDescriptions *bool   `statekit:"name=search_descriptions"`
	CaseSensitive      *bool   `statekit:"name=case_sensitive"`
	InstalledOnly      *bool   `statekit:"name=installed_only"`
	NotInstalledOnly   *bool   `statekit:"name=not_installed_only"`
	Details            *bool   `statekit:"name=details"`
}

// ZypperVersionCmpArgs mirrors zypperpkg.version_cmp's source argument
// names. It is provider-specific because aptpkg/yumpkg use pkg1/pkg2.
type ZypperVersionCmpArgs struct {
	Ver1        string `statekit:"required,name=ver1"`
	Ver2        string `statekit:"required,name=ver2"`
	IgnoreEpoch *bool  `statekit:"name=ignore_epoch"`
}

// The six functions below are thin zypperpkg wrappers around rpm_lowpkg.
// Their vararg names intentionally follow zypperpkg.py rather than the
// compatibility names used by the existing APT/YUM prototypes.
type ZypperFilesArgs struct {
	Packages []string `statekit:"name=packages"`
	Root     *string  `statekit:"name=root"`
}

type ZypperInfoInstalledArgs struct {
	Names       []string `statekit:"name=names"`
	Root        *string  `statekit:"name=root"`
	Attr        *string  `statekit:"name=attr"`
	AllVersions *bool    `statekit:"name=all_versions"`
	Errors      *string  `statekit:"name=errors"`
}

type ZypperModifiedArgs struct {
	Packages     []string `statekit:"name=packages"`
	Root         *string  `statekit:"name=root"`
	Size         *bool    `statekit:"name=size"`
	Mode         *bool    `statekit:"name=mode"`
	Checksum     *bool    `statekit:"name=checksum"`
	Device       *bool    `statekit:"name=device"`
	Symlink      *bool    `statekit:"name=symlink"`
	Owner        *bool    `statekit:"name=owner"`
	Group        *bool    `statekit:"name=group"`
	Time         *bool    `statekit:"name=time"`
	Capabilities *bool    `statekit:"name=capabilities"`
}

type ZypperOwnerArgs struct {
	Paths []string `statekit:"name=paths"`
	Root  *string  `statekit:"name=root"`
}

type ZypperVerifyArgs struct {
	Names         []string `statekit:"name=names"`
	Root          *string  `statekit:"name=root"`
	VerifyOptions any      `statekit:"name=verify_options"`
	IgnoreTypes   any      `statekit:"name=ignore_types"`
}

// ZypperPrototype returns the provider-specific argument shape for the
// read-only zypperpkg functions. Registration remains canonical in the
// shared execution functions.
func ZypperPrototype(name string) (any, bool) {
	switch name {
	case "list_patterns":
		return ZypperListPatternsArgs{}, true
	case "list_installed_patterns":
		return ZypperListInstalledPatternsArgs{}, true
	case "list_locks":
		return ZypperListLocksArgs{}, true
	case "clean_locks":
		return ZypperCleanLocksArgs{}, true
	case "list_upgrades":
		return ZypperListUpgradesArgs{}, true
	case "upgrade_available":
		return ZypperUpgradeAvailableArgs{}, true
	case "info_available":
		return ZypperInfoAvailableArgs{}, true
	case "search":
		return ZypperSearchArgs{}, true
	case "file_list", "file_dict":
		return ZypperFilesArgs{}, true
	case "info_installed":
		return ZypperInfoInstalledArgs{}, true
	case "modified":
		return ZypperModifiedArgs{}, true
	case "owner":
		return ZypperOwnerArgs{}, true
	case "verify":
		return ZypperVerifyArgs{}, true
	default:
		return nil, false
	}
}
