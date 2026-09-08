package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
)

func TestZypperUpgradesCLI(t *testing.T) {
	for _, tc := range []struct {
		args         []string
		output, want string
		argv         []string
	}{
		{[]string{"exec", "pkg.list_upgrades", "--refresh=false", "--root", "/target", "--fromrepo", "base"}, `<stream><update kind="package" name="demo" edition="2"/></stream>`, `"demo": "2"`, []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "list-updates", "--repo", "base"}},
		{[]string{"exec", "pkg.upgrade_available", "--name", "demo.x86_64", "--refresh=false"}, "Name: demo.x86_64\nVersion: 2\nStatus: not installed", "true", []string{"zypper", "--non-interactive", "--no-refresh", "info", "-t", "package", "demo.x86_64"}},
	} {
		r := &cliRecordingRunner{results: []process.CommandResult{{Stdout: []byte(tc.output)}}}
		fsys := &cliCountingFS{}
		code, out, errS := captureCode(t, providerCLIAppWithFS(t, "zypper", r, fsys), append(tc.args, "-o", "json")...)
		if code != ExitOK || errS != "" || !strings.Contains(out, tc.want) || len(r.calls) != 1 || fsys.calls != 0 {
			t.Fatalf("code=%d out=%q err=%q calls=%d", code, out, errS, len(r.calls))
		}
		if argv := append([]string{r.calls[0].Name}, r.calls[0].Args...); !reflect.DeepEqual(argv, tc.argv) {
			t.Fatalf("argv=%v", argv)
		}
	}
	for _, args := range [][]string{
		{"exec", "pkg.list_upgrades", "--dist-upgrade"}, {"exec", "pkg.upgrade_available", "--name", "--evil"},
		{"exec", "pkg.upgrade_available"}, {"exec", "pkg.list_upgrades", "--refresh=invalid"},
	} {
		r := &cliRecordingRunner{}
		code, _, _ := captureCode(t, providerCLIApp(t, "zypper", r), args...)
		if code == ExitOK || len(r.calls) != 0 {
			t.Fatalf("args=%v code=%d calls=%d", args, code, len(r.calls))
		}
	}
}
