// Command statekit is the portable StateKit binary.
package main

import (
	"os"

	"github.com/friz-zy/statekit/internal/cli"
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"

	execaliases "github.com/friz-zy/statekit/modules/exec/aliases"
	execarchive "github.com/friz-zy/statekit/modules/exec/archive"
	execat "github.com/friz-zy/statekit/modules/exec/at"
	execbcache "github.com/friz-zy/statekit/modules/exec/bcache"
	execblockdev "github.com/friz-zy/statekit/modules/exec/blockdev"
	execcmd "github.com/friz-zy/statekit/modules/exec/cmd"
	execcron "github.com/friz-zy/statekit/modules/exec/cron"
	execcryptdev "github.com/friz-zy/statekit/modules/exec/cryptdev"
	execdevinfo "github.com/friz-zy/statekit/modules/exec/devinfo"
	execdevmap "github.com/friz-zy/statekit/modules/exec/devmap"
	execdisk "github.com/friz-zy/statekit/modules/exec/disk"
	execenviron "github.com/friz-zy/statekit/modules/exec/environ"
	execethtool "github.com/friz-zy/statekit/modules/exec/ethtool"
	execextfs "github.com/friz-zy/statekit/modules/exec/extfs"
	execfile "github.com/friz-zy/statekit/modules/exec/file"
	execgit "github.com/friz-zy/statekit/modules/exec/git"
	execgroup "github.com/friz-zy/statekit/modules/exec/group"
	exechashutil "github.com/friz-zy/statekit/modules/exec/hashutil"
	exechosts "github.com/friz-zy/statekit/modules/exec/hosts"
	exechttp "github.com/friz-zy/statekit/modules/exec/http"
	execini "github.com/friz-zy/statekit/modules/exec/ini"
	execiptables "github.com/friz-zy/statekit/modules/exec/iptables"
	execiwtools "github.com/friz-zy/statekit/modules/exec/iwtools"
	execkeyboard "github.com/friz-zy/statekit/modules/exec/keyboard"
	execkmod "github.com/friz-zy/statekit/modules/exec/kmod"
	execlocale "github.com/friz-zy/statekit/modules/exec/locale"
	execlogrotate "github.com/friz-zy/statekit/modules/exec/logrotate"
	execlvm "github.com/friz-zy/statekit/modules/exec/lvm"
	execmdadm "github.com/friz-zy/statekit/modules/exec/mdadm"
	execmount "github.com/friz-zy/statekit/modules/exec/mount"
	execnpm "github.com/friz-zy/statekit/modules/exec/npm"
	execpart "github.com/friz-zy/statekit/modules/exec/partition"
	execpip "github.com/friz-zy/statekit/modules/exec/pip"
	execpkg "github.com/friz-zy/statekit/modules/exec/pkg"
	execpkgresource "github.com/friz-zy/statekit/modules/exec/pkgresource"
	execps "github.com/friz-zy/statekit/modules/exec/ps"
	execquota "github.com/friz-zy/statekit/modules/exec/quota"
	execrandom "github.com/friz-zy/statekit/modules/exec/random"
	execrsync "github.com/friz-zy/statekit/modules/exec/rsync"
	execscsi "github.com/friz-zy/statekit/modules/exec/scsi"
	execselinux "github.com/friz-zy/statekit/modules/exec/selinux"
	execservice "github.com/friz-zy/statekit/modules/exec/service"
	execshadow "github.com/friz-zy/statekit/modules/exec/shadow"
	execsmbios "github.com/friz-zy/statekit/modules/exec/smbios"
	execstatus "github.com/friz-zy/statekit/modules/exec/status"
	execsysctl "github.com/friz-zy/statekit/modules/exec/sysctl"
	execsysfs "github.com/friz-zy/statekit/modules/exec/sysfs"
	exectest "github.com/friz-zy/statekit/modules/exec/test"
	executimezone "github.com/friz-zy/statekit/modules/exec/timezone"
	execudev "github.com/friz-zy/statekit/modules/exec/udev"
	execuser "github.com/friz-zy/statekit/modules/exec/user"
	execvirtualenv "github.com/friz-zy/statekit/modules/exec/virtualenv"
	execxfs "github.com/friz-zy/statekit/modules/exec/xfs"
	statealiases "github.com/friz-zy/statekit/modules/state/aliases"
	statecmd "github.com/friz-zy/statekit/modules/state/cmd"
	statecron "github.com/friz-zy/statekit/modules/state/cron"
	statefile "github.com/friz-zy/statekit/modules/state/file"
	stategroup "github.com/friz-zy/statekit/modules/state/group"
	statehost "github.com/friz-zy/statekit/modules/state/host"
	stateini "github.com/friz-zy/statekit/modules/state/ini"
	statelvm "github.com/friz-zy/statekit/modules/state/lvm"
	statepkg "github.com/friz-zy/statekit/modules/state/pkg"
	statequota "github.com/friz-zy/statekit/modules/state/quota"
	stateselinux "github.com/friz-zy/statekit/modules/state/selinux"
	stateservice "github.com/friz-zy/statekit/modules/state/service"
	statesysctl "github.com/friz-zy/statekit/modules/state/sysctl"
	statesysfs "github.com/friz-zy/statekit/modules/state/sysfs"
	statetest "github.com/friz-zy/statekit/modules/state/test"
	stateuser "github.com/friz-zy/statekit/modules/state/user"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
	serviceprovider "github.com/friz-zy/statekit/providers/service"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

func buildRuntime() (*runtime.Runtime, error) {
	runner := process.NewRunner()
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.Detect(runner),
		Providers: runtime.NewProviderRegistry(),
		Runner:    runner,
		FS:        runtime.NewOSFileSystem(),
	}

	if err := pkgprovider.Register(rt.Providers); err != nil {
		return nil, err
	}
	if err := serviceprovider.Register(rt.Providers); err != nil {
		return nil, err
	}
	for _, register := range []func(*runtime.ExecRegistry) error{
		exectest.Register,
		execcryptdev.Register,
		execdevmap.Register,
		execextfs.Register,
		execcmd.Register,
		execfile.Register,
		execstatus.Register,
		execuser.Register,
		execgroup.Register,
		execshadow.Register,
		execpkg.Register,
		execpkgresource.Register,
		execservice.Register,
		execarchive.Register,
		execat.Register,
		execbcache.Register,
		execenviron.Register,
		execethtool.Register,
		execkmod.Register,
		execcron.Register,
		execdevinfo.Register,
		execdisk.Register,
		exechosts.Register,
		execlocale.Register,
		execgit.Register,
		exechttp.Register,
		execiwtools.Register,
		execkeyboard.Register,
		execlogrotate.Register,
		execblockdev.Register,
		execrsync.Register,
		execscsi.Register,
		execsmbios.Register,
		execnpm.Register,
		execpip.Register,
		execps.Register,
		execvirtualenv.Register,
		execaliases.Register,
		exechashutil.Register,
		execini.Register,
		execiptables.Register,
		execrandom.Register,
		execselinux.Register,
		execlvm.Register,
		execmdadm.Register,
		execmount.Register,
		execpart.Register,
		execquota.Register,
		execxfs.Register,
		execsysctl.Register,
		execsysfs.Register,
		execudev.Register,
		executimezone.Register,
	} {
		if err := register(rt.Exec); err != nil {
			return nil, err
		}
	}
	for _, registerState := range []func(*runtime.StateRegistry) error{
		statetest.Register,
		statequota.Register,
		statefile.Register,
		statepkg.Register,
		stateservice.Register,
		stateuser.Register,
		stategroup.Register,
		statecmd.Register,
		statecron.Register,
		statehost.Register,
		statesysctl.Register,
		statesysfs.Register,
		statealiases.Register,
		stateini.Register,
		statelvm.Register,
		stateselinux.Register,
	} {
		if err := registerState(rt.States); err != nil {
			return nil, err
		}
	}
	return rt, nil
}

func main() {
	os.Exit(cli.NewApp(version, buildRuntime).Run(os.Args[1:]))
}
