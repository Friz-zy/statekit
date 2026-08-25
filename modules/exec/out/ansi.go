package out

import "regexp"

type regexpT = regexp.Regexp

func compileANSI() *regexpT {
	return regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]")
}
