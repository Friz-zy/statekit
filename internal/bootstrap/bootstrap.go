// Package bootstrap centralizes provider and family registration so the
// CLI binary, differential harnesses, and coverage tooling observe exactly
// the same execution surface.
package bootstrap

import (
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"

	execacl "github.com/friz-zy/statekit/modules/exec/acl"
	execaliases "github.com/friz-zy/statekit/modules/exec/aliases"
	execalt "github.com/friz-zy/statekit/modules/exec/alternatives"
	execarchive "github.com/friz-zy/statekit/modules/exec/archive"
	execat "github.com/friz-zy/statekit/modules/exec/at"
	execbcache "github.com/friz-zy/statekit/modules/exec/bcache"
	execblockdev "github.com/friz-zy/statekit/modules/exec/blockdev"
	execbridge "github.com/friz-zy/statekit/modules/exec/bridge"
	execcmd "github.com/friz-zy/statekit/modules/exec/cmd"
	execcp "github.com/friz-zy/statekit/modules/exec/cp"
	execcron "github.com/friz-zy/statekit/modules/exec/cron"
	execcryptdev "github.com/friz-zy/statekit/modules/exec/cryptdev"
	execdata "github.com/friz-zy/statekit/modules/exec/datastore"
	execdebconf "github.com/friz-zy/statekit/modules/exec/debconfmod"
	execdefaults "github.com/friz-zy/statekit/modules/exec/defaults"
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
	execincron "github.com/friz-zy/statekit/modules/exec/incron"
	execini "github.com/friz-zy/statekit/modules/exec/ini"
	execipset "github.com/friz-zy/statekit/modules/exec/ipset"
	execiptables "github.com/friz-zy/statekit/modules/exec/iptables"
	execiwtools "github.com/friz-zy/statekit/modules/exec/iwtools"
	execjinja "github.com/friz-zy/statekit/modules/exec/jinja"
	execkeyboard "github.com/friz-zy/statekit/modules/exec/keyboard"
	execkmod "github.com/friz-zy/statekit/modules/exec/kmod"
	execlocale "github.com/friz-zy/statekit/modules/exec/locale"
	execlogrotate "github.com/friz-zy/statekit/modules/exec/logrotate"
	execlvm "github.com/friz-zy/statekit/modules/exec/lvm"
	execmdadm "github.com/friz-zy/statekit/modules/exec/mdadm"
	execmount "github.com/friz-zy/statekit/modules/exec/mount"
	execnetwork "github.com/friz-zy/statekit/modules/exec/network"
	execnftables "github.com/friz-zy/statekit/modules/exec/nftables"
	execnpm "github.com/friz-zy/statekit/modules/exec/npm"
	execout "github.com/friz-zy/statekit/modules/exec/out"
	execpam "github.com/friz-zy/statekit/modules/exec/pam"
	execpart "github.com/friz-zy/statekit/modules/exec/partition"
	execpip "github.com/friz-zy/statekit/modules/exec/pip"
	execpkg "github.com/friz-zy/statekit/modules/exec/pkg"
	execpkgbuild "github.com/friz-zy/statekit/modules/exec/pkgbuild"
	execpkgrepo "github.com/friz-zy/statekit/modules/exec/pkgrepo"
	execpkgresource "github.com/friz-zy/statekit/modules/exec/pkgresource"
	execps "github.com/friz-zy/statekit/modules/exec/ps"
	execpyenv "github.com/friz-zy/statekit/modules/exec/pyenv"
	execpython "github.com/friz-zy/statekit/modules/exec/python"
	execquota "github.com/friz-zy/statekit/modules/exec/quota"
	execrandom "github.com/friz-zy/statekit/modules/exec/random"
	execrestartcheck "github.com/friz-zy/statekit/modules/exec/restartcheck"
	execret "github.com/friz-zy/statekit/modules/exec/ret"
	execrsync "github.com/friz-zy/statekit/modules/exec/rsync"
	execscsi "github.com/friz-zy/statekit/modules/exec/scsi"
	execselinux "github.com/friz-zy/statekit/modules/exec/selinux"
	execservice "github.com/friz-zy/statekit/modules/exec/service"
	execshadow "github.com/friz-zy/statekit/modules/exec/shadow"
	execsmbios "github.com/friz-zy/statekit/modules/exec/smbios"
	execssh "github.com/friz-zy/statekit/modules/exec/ssh"
	execstatus "github.com/friz-zy/statekit/modules/exec/status"
	execsysctl "github.com/friz-zy/statekit/modules/exec/sysctl"
	execsysfs "github.com/friz-zy/statekit/modules/exec/sysfs"
	exectemp "github.com/friz-zy/statekit/modules/exec/temp"
	exectest "github.com/friz-zy/statekit/modules/exec/test"
	executimezone "github.com/friz-zy/statekit/modules/exec/timezone"
	execudev "github.com/friz-zy/statekit/modules/exec/udev"
	execuser "github.com/friz-zy/statekit/modules/exec/user"
	execvirtualenv "github.com/friz-zy/statekit/modules/exec/virtualenv"
	execwebutil "github.com/friz-zy/statekit/modules/exec/webutil"
	execxfs "github.com/friz-zy/statekit/modules/exec/xfs"
	execxml "github.com/friz-zy/statekit/modules/exec/xml"
	execyaml "github.com/friz-zy/statekit/modules/exec/yamlhelper"
	statealiases "github.com/friz-zy/statekit/modules/state/aliases"
	statecmd "github.com/friz-zy/statekit/modules/state/cmd"
	statecron "github.com/friz-zy/statekit/modules/state/cron"
	statedebconf "github.com/friz-zy/statekit/modules/state/debconfmod"
	statefile "github.com/friz-zy/statekit/modules/state/file"
	stategroup "github.com/friz-zy/statekit/modules/state/group"
	statehost "github.com/friz-zy/statekit/modules/state/host"
	stateini "github.com/friz-zy/statekit/modules/state/ini"
	statelogrotate "github.com/friz-zy/statekit/modules/state/logrotate"
	statelvm "github.com/friz-zy/statekit/modules/state/lvm"
	statepkg "github.com/friz-zy/statekit/modules/state/pkg"
	statepkgbuild "github.com/friz-zy/statekit/modules/state/pkgbuild"
	statepkgrepo "github.com/friz-zy/statekit/modules/state/pkgrepo"
	statepyenv "github.com/friz-zy/statekit/modules/state/pyenv"
	statepython "github.com/friz-zy/statekit/modules/state/python"
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

// BuildRuntime assembles a fully populated runtime with every registered
// provider, execution family, and state family.
func BuildRuntime() (*runtime.Runtime, error) {
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
		execfile.RegisterExt,
		execfile.RegisterSums,
		execfile.RegisterDevices,
		execfile.RegisterPatch,
		execfile.RegisterMeta,
		execcp.Register,
		execssh.Register,
		execacl.Register,
		execpam.Register,
		execwebutil.Register,
		execssh.RegisterAuth,
		exectemp.Register,
		execxml.Register,
		execyaml.Register,
		execjinja.Register,
		execdata.Register,
		execdefaults.Register,
		execret.Register,
		execout.Register,
		execincron.Register,
		execrestartcheck.Register,
		execstatus.Register,
		execstatus.RegisterTail,
		execuser.Register,
		execgroup.Register,
		execshadow.Register,
		execpkg.Register,
		execpkgresource.Register,
		execpkgrepo.Register,
		execpkgbuild.Register,
		execalt.Register,
		execdebconf.Register,
		execpython.Register,
		execpyenv.Register,
		execservice.Register,
		execarchive.Register,
		execat.Register,
		execbcache.Register,
		execenviron.Register,
		execethtool.Register,
		execkmod.Register,
		execbridge.Register,
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
		execnftables.Register,
		execnpm.Register,
		execnetwork.Register,
		execpip.Register,
		execps.Register,
		execvirtualenv.Register,
		execaliases.Register,
		exechashutil.Register,
		execipset.Register,
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
		statepkgrepo.Register,
		statelogrotate.Register,
		statedebconf.Register,
		statepyenv.Register,
		statepython.Register,
		statepkgbuild.Register,
		statelvm.Register,
		stateselinux.Register,
	} {
		if err := registerState(rt.States); err != nil {
			return nil, err
		}
	}
	return rt, nil
}
