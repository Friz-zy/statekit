package pkg

import (
	"context"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func TestZypperUpgradesRegistry(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name            string
		prototype, args any
		names           []string
		output          string
		want            any
		argv            []string
	}{
		{"pkg.list_upgrades", ZypperListUpgradesArgs{}, &ZypperListUpgradesArgs{Refresh: zypperInfoRegistryBoolPtr(false), Root: strptr("/target"), Fromrepo: "base"}, []string{"fromrepo", "gpgautoimport", "refresh", "repos", "root"}, `<stream><update kind="package" name="demo" edition="2"/></stream>`, map[string]string{"demo": "2"}, []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "list-updates", "--repo", "base"}},
		{"pkg.upgrade_available", ZypperUpgradeAvailableArgs{}, &ZypperUpgradeAvailableArgs{Name: "demo", Refresh: zypperInfoRegistryBoolPtr(false)}, []string{"fromrepo", "gpgautoimport", "name", "refresh", "repos", "root"}, "Name: demo\nVersion: 2\nStatus: not installed", true, []string{"zypper", "--non-interactive", "--no-refresh", "info", "-t", "package", "demo"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &zypperLowpkgExecRunner{results: []process.CommandResult{{Stdout: []byte(tc.output)}}}
			rt := zypperRegistryRuntime("zypper", r)
			prototype, err := reg.ResolveArgs(rt, tc.name)
			if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(tc.prototype) {
				t.Fatalf("prototype=%T err=%v", prototype, err)
			}
			names, err := config.ArgumentNames(prototype)
			if err != nil || !reflect.DeepEqual(names, tc.names) {
				t.Fatalf("names=%v err=%v", names, err)
			}
			if !reflect.DeepEqual(reg.ProviderCapabilities(tc.name), []string{"aptpkg", "yumpkg", "zypperpkg"}) {
				t.Fatal("wrong capabilities")
			}
			if _, err := reg.Call(context.Background(), rt, tc.name, &YumListUpgradesArgs{}); err == nil || len(r.commands) != 0 {
				t.Fatal("cross-provider args reached runner")
			}
			got, err := reg.Call(context.Background(), rt, tc.name, tc.args)
			if err != nil || !reflect.DeepEqual(got, tc.want) || len(r.commands) != 1 {
				t.Fatalf("got=%v err=%v calls=%d", got, err, len(r.commands))
			}
			if argv := append([]string{r.commands[0].Name}, r.commands[0].Args...); !reflect.DeepEqual(argv, tc.argv) {
				t.Fatalf("argv=%v", argv)
			}
		})
	}
}
