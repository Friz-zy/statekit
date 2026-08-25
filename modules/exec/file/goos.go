package file

import (
	"os"
	"path/filepath"
	goruntime "runtime"
)

func goosIdent() string { return goruntime.GOOS }

// lookPathBin resolves an executable on PATH like salt.utils.path.which.
// lookPathBin is injectable so suites can pin binary resolution.
var lookPathBin = func(exe string) string {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, exe)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}
