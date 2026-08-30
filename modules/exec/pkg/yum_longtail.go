package pkg

// Signatures mirror salt/modules/yumpkg.py at pinned revision 8b63e700637e40d76f80a00d95c60471797c73b9.
// These functions delegate to salt/modules/rpm_lowpkg.py.
type YumFilesArgs struct {
	Packages []string `statekit:"name=packages"`
	Root     *string  `statekit:"name=root"`
}
type YumInfoInstalledArgs struct {
	Names       []string `statekit:"name=names"`
	AllVersions *bool    `statekit:"name=all_versions"`
	Root        *string  `statekit:"name=root"`
	Attr        *string  `statekit:"name=attr"`
}
type YumOwnerArgs struct {
	Paths []string `statekit:"name=paths"`
	Root  *string  `statekit:"name=root"`
}

// YumPrototype returns the exact provider-specific argument shape for a
// shared longtail function. Registration and dispatch remain canonical in
// apt_longtail.go.
func YumPrototype(name string) (any, bool) {
	switch name {
	case "file_list", "file_dict":
		return YumFilesArgs{}, true
	case "info_installed":
		return YumInfoInstalledArgs{}, true
	case "owner":
		return YumOwnerArgs{}, true
	default:
		return nil, false
	}
}
