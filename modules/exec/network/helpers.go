package network

import (
	"context"
	"os"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// toolPath mirrors salt.utils.path.which for which-guarded tools.
var toolPath = func(ostool string) string {
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(dir + "/" + ostool); err == nil {
			return dir + "/" + ostool
		}
	}
	return ""
}

// runText mirrors __salt__["cmd.run"](<string>, python_shell=False).
func runText(ctx context.Context, rt *runtime.Runtime, argv []string) string {
	res := rt.Runner.Run(ctx, process.Command{
		Name: argv[0],
		Args: append([]string{}, argv[1:]...),
	})
	if res.Err != nil {
		return res.Err.Error()
	}
	return string(res.Stdout)
}

func ctx0() context.Context { return context.Background() }

func sortStrings(s []string) {
	sort.Strings(s)
}

func toAnySlice(items []string) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	return out
}
