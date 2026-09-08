package pkg

// ZypperVersionCmpArgs mirrors zypperpkg.version_cmp's source argument
// names. It is provider-specific because aptpkg/yumpkg use pkg1/pkg2.
type ZypperVersionCmpArgs struct {
	Ver1        string `statekit:"required,name=ver1"`
	Ver2        string `statekit:"required,name=ver2"`
	IgnoreEpoch *bool  `statekit:"name=ignore_epoch"`
}
