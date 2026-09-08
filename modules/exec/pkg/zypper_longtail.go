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
	case "list_upgrades":
		return ZypperListUpgradesArgs{}, true
	case "upgrade_available":
		return ZypperUpgradeAvailableArgs{}, true
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
