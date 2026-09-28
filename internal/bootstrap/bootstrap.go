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
	execassistive "github.com/friz-zy/statekit/modules/exec/assistive"
	execasym "github.com/friz-zy/statekit/modules/exec/asymmetric"
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
	execdesktop "github.com/friz-zy/statekit/modules/exec/desktop"
	execdevinfo "github.com/friz-zy/statekit/modules/exec/devinfo"
	execdevmap "github.com/friz-zy/statekit/modules/exec/devmap"
	execdig "github.com/friz-zy/statekit/modules/exec/dig"
	execdisk "github.com/friz-zy/statekit/modules/exec/disk"
	execenviron "github.com/friz-zy/statekit/modules/exec/environ"
	execethtool "github.com/friz-zy/statekit/modules/exec/ethtool"
	execextfs "github.com/friz-zy/statekit/modules/exec/extfs"
	execfile "github.com/friz-zy/statekit/modules/exec/file"
	execfirewall "github.com/friz-zy/statekit/modules/exec/firewall"
	execfmadm "github.com/friz-zy/statekit/modules/exec/fmadm"
	execgit "github.com/friz-zy/statekit/modules/exec/git"
	execgotemplate "github.com/friz-zy/statekit/modules/exec/gotemplate"
	execgpg "github.com/friz-zy/statekit/modules/exec/gpg"
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
	execkeychain "github.com/friz-zy/statekit/modules/exec/keychain"
	execkmod "github.com/friz-zy/statekit/modules/exec/kmod"
	execlocale "github.com/friz-zy/statekit/modules/exec/locale"
	execlogrotate "github.com/friz-zy/statekit/modules/exec/logrotate"
	execlvm "github.com/friz-zy/statekit/modules/exec/lvm"
	execmacdefaults "github.com/friz-zy/statekit/modules/exec/macdefaults"
	execmacpackage "github.com/friz-zy/statekit/modules/exec/macpackage"
	execmdadm "github.com/friz-zy/statekit/modules/exec/mdadm"
	execmount "github.com/friz-zy/statekit/modules/exec/mount"
	execmysql "github.com/friz-zy/statekit/modules/exec/mysql"
	execnacl "github.com/friz-zy/statekit/modules/exec/nacl"
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
	execpkgutil "github.com/friz-zy/statekit/modules/exec/pkgutil"
	execpostgres "github.com/friz-zy/statekit/modules/exec/postgres"
	execpower "github.com/friz-zy/statekit/modules/exec/power"
	execps "github.com/friz-zy/statekit/modules/exec/ps"
	execpyenv "github.com/friz-zy/statekit/modules/exec/pyenv"
	execpython "github.com/friz-zy/statekit/modules/exec/python"
	execquota "github.com/friz-zy/statekit/modules/exec/quota"
	execrabbitmq "github.com/friz-zy/statekit/modules/exec/rabbitmq"
	execrandom "github.com/friz-zy/statekit/modules/exec/random"
	execrbac "github.com/friz-zy/statekit/modules/exec/rbac"
	execreg "github.com/friz-zy/statekit/modules/exec/reg"
	execrestartcheck "github.com/friz-zy/statekit/modules/exec/restartcheck"
	execret "github.com/friz-zy/statekit/modules/exec/ret"
	execrsync "github.com/friz-zy/statekit/modules/exec/rsync"
	execscsi "github.com/friz-zy/statekit/modules/exec/scsi"
	execselinux "github.com/friz-zy/statekit/modules/exec/selinux"
	execservice "github.com/friz-zy/statekit/modules/exec/service"
	execshadow "github.com/friz-zy/statekit/modules/exec/shadow"
	execslack "github.com/friz-zy/statekit/modules/exec/slack"
	execsmbios "github.com/friz-zy/statekit/modules/exec/smbios"
	execsoftwareupdate "github.com/friz-zy/statekit/modules/exec/softwareupdate"
	execsqlite3 "github.com/friz-zy/statekit/modules/exec/sqlite3"
	execssh "github.com/friz-zy/statekit/modules/exec/ssh"
	execsshpki "github.com/friz-zy/statekit/modules/exec/ssh_pki"
	execstatus "github.com/friz-zy/statekit/modules/exec/status"
	execsysctl "github.com/friz-zy/statekit/modules/exec/sysctl"
	execsysfs "github.com/friz-zy/statekit/modules/exec/sysfs"
	execsystem "github.com/friz-zy/statekit/modules/exec/system"
	exectemp "github.com/friz-zy/statekit/modules/exec/temp"
	exectest "github.com/friz-zy/statekit/modules/exec/test"
	executimezone "github.com/friz-zy/statekit/modules/exec/timezone"
	exectls "github.com/friz-zy/statekit/modules/exec/tls"
	execudev "github.com/friz-zy/statekit/modules/exec/udev"
	execuser "github.com/friz-zy/statekit/modules/exec/user"
	execvirtualenv "github.com/friz-zy/statekit/modules/exec/virtualenv"
	execwebutil "github.com/friz-zy/statekit/modules/exec/webutil"
	execwindacl "github.com/friz-zy/statekit/modules/exec/win_dacl"
	execwindns "github.com/friz-zy/statekit/modules/exec/win_dns_client"
	execwinevent "github.com/friz-zy/statekit/modules/exec/win_event"
	execwiniis "github.com/friz-zy/statekit/modules/exec/win_iis"
	execwinpath "github.com/friz-zy/statekit/modules/exec/win_path"
	execwinpki "github.com/friz-zy/statekit/modules/exec/win_pki"
	execwinservermanager "github.com/friz-zy/statekit/modules/exec/win_servermanager"
	execwinsmtp "github.com/friz-zy/statekit/modules/exec/win_smtp_server"
	execwinsnmp "github.com/friz-zy/statekit/modules/exec/win_snmp"
	execwinwua "github.com/friz-zy/statekit/modules/exec/win_wua"
	execx509 "github.com/friz-zy/statekit/modules/exec/x509"
	execxattr "github.com/friz-zy/statekit/modules/exec/xattr"
	execxfs "github.com/friz-zy/statekit/modules/exec/xfs"
	execxml "github.com/friz-zy/statekit/modules/exec/xml"
	execyaml "github.com/friz-zy/statekit/modules/exec/yamlhelper"
	execzoneadm "github.com/friz-zy/statekit/modules/exec/zoneadm"
	execzonecfg "github.com/friz-zy/statekit/modules/exec/zonecfg"
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
	statewinfirewall "github.com/friz-zy/statekit/modules/state/win_firewall"
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
	if err := exechosts.ConfigureRuntime(rt); err != nil {
		return nil, err
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
		execsshpki.Register,
		execasym.Register,
		execnacl.Register,
		execgpg.Register,
		execgpg.RegisterKeyMgmt,
		execpam.Register,
		execwebutil.Register,
		execssh.RegisterAuth,
		exectemp.Register,
		execxml.Register,
		execyaml.Register,
		execjinja.Register,
		execgotemplate.Register,
		execdata.Register,
		execdefaults.Register,
		execret.Register,
		execout.Register,
		execincron.Register,
		execrestartcheck.Register,
		execstatus.Register,
		execstatus.RegisterTail,
		exectls.Register,
		execx509.Register,
		execuser.Register,
		execgroup.Register,
		execmacdefaults.Register,
		execmacpackage.Register,
		execpkgutil.Register,
		execsoftwareupdate.Register,
		execdesktop.Register,
		execassistive.Register,
		execxattr.Register,
		execkeychain.Register,
		execpower.Register,
		execreg.Register,
		execfirewall.Register,
		execfmadm.Register,
		execwindns.Register,
		execwindacl.Register,
		execwinpki.Register,
		execwinevent.Register,
		execwiniis.Register,
		execwinpath.Register,
		execwinservermanager.Register,
		execwinsmtp.Register,
		execwinsnmp.Register,
		execwinwua.Register,
		execshadow.Register,
		func(reg *runtime.ExecRegistry) error { return execpkg.RegisterForRuntime(reg, rt.Facts) },
		execpkgresource.Register,
		execpkgrepo.Register,
		execpkgbuild.Register,
		execalt.Register,
		execdebconf.Register,
		execpython.Register,
		execpyenv.Register,
		execservice.Register,
		execrbac.Register,
		execarchive.Register,
		execat.Register,
		execzoneadm.Register,
		execzonecfg.Register,
		execbcache.Register,
		execenviron.Register,
		execethtool.Register,
		execkmod.Register,
		execbridge.Register,
		execcron.Register,
		execdevinfo.Register,
		execdig.Register,
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
		execsystem.Register,
		execlvm.Register,
		execmdadm.Register,
		execmount.Register,
		execpart.Register,
		execquota.Register,
		execrabbitmq.Register,
		execmysql.Register,
		execpostgres.Register,
		execsqlite3.Register,
		execslack.Register,
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
		statewinfirewall.Register,
	} {
		if err := registerState(rt.States); err != nil {
			return nil, err
		}
	}
	return rt, nil
}
