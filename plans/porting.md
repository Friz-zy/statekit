# StateKit Full Porting Plan — exec & state, all platforms

Companion to `plans/init.md` (scope/DoD) and `plans/testing.md` (verification).
Goal: bring **every** SaltStack exec & state family from the pinned catalog
(`docs/catalog/`, revision `references/salt.lock`) to an explicit terminal
state — *ported*, or *excluded with a recorded reason* — including non-Linux
operating systems.

Baseline at plan creation:

| Metric | Value |
|---|---|
| Catalog families (exec+states) | 246 |
| Implemented | 34 |
| Functions implemented | 133 exec / 24 states (catalog totals: 4284 / 669) |
| Not applicable (auto-classified) | 69 families |
| Deferred | 143 families |

## 0. Principles

1. **Contract-first**: every ported function mirrors the pinned Salt source
   (`docs/catalog/<kind>/<module>.yaml`) — signature, return shape, comments;
   divergences recorded under `docs/compatibility/` per init.md §28.
2. **No blind ports**: a family enters a round only with its Salt unit-test
   references mapped to StateKit fixtures.
3. **Dependency policy**: no new Go module dependencies. External system
   binaries are called through the central Runner; stdlib implementations are
   preferred where they enable hermetic tests. Any exception requires an ADR.
4. **Per-family DoD** = init.md §47–48: contract tests green on every platform
   the family declares, fixtures present, compatibility annotation written.
5. Terminal states per family: `implemented` / `partial` (documented subset) /
   `excluded` (reason + ADR line: master-minion-by-design, platform-EOL,
   impossible without Go deps).

## 1. Enablers (must land before dependents)

| ID | Deliverable | Unblocks | Verification |
|---|---|---|---|
| E1 | **Runner v2 OS profiles**: per-GOOS/runtime shell model (`sh` / PowerShell 7 / cmd), argv escaping, binary suffix, env semantics | Windows, macOS tracks | profile unit tests; smoke on GH `windows-*`/`macos-*` runners |
| E2 | **Elevation model**: sudo/doas (unix), runas/UAC notes (windows) behind one `Elevate(ctx, cmd)`; non-root failure contracts preserved (init.md §39) | storage, firewall, package, service rounds | fake-runner units; privileged containers; QEMU |
| E3 | **Platform-scoped registration**: build-tag trees `modules/exec/<family>/os_{linux,darwin,windows,bsd,solaris}.go`; registry registers by runtime facts; `--list` becomes platform-aware | R6–R8 | cross-GOOS build matrix extended (windows/darwin/freebsd) |
| E4 | **Facts v2**: per-OS providers (win: registry/CIM via PowerShell; mac: `system_profiler`, `dscl`; bsd: `sysctl`/`kenv`) feeding PackageManager/InitSystem/Virt | platform rounds, pkg/service selection | golden facts fixtures per OS image |
| E5 | **Services test tier**: compose harness booting real mysql/postgres/redis/rabbitmq/mongo/elasticsearch/kafka | R9 | new `integration-services.yml` |
| E6 | **QEMU promotion**: vm-nightly becomes blocking for `vm-required` suites | R1, R2, R8 | Packer recipes in `tests/images/vm/` |
| E7 | **Compatibility ledger v2**: buckets renamed `implemented/partial/excluded/planned`; every family carries target round + ADR link | all rounds | existing golden determinism |


## 2. Rounds

Sizing = Salt functions in scope (catalog counts). Each round ends with
coverage regen, differential scope extension for its families, gates green.

### R1 — Linux storage & filesystem CLIs (~90 funcs)
`lvm`, `linux_lvm`, `partition`, `extfs`, `xfs`, `mdadm_raid`, `bcache`,
`devmap`, `loop`, `cryptdev`, `quota`, blockdev extensions, pkg_resource
helpers. Binaries: lvm toolset, parted/lsblk, mkfs.*, xfs tools, mdadm,
losetup, cryptsetup, quota.
Verify: hermetic argv tests + **QEMU** loopback-disk suites (E6); differential
vs Salt in privileged VM images.

### R2 — Linux network, firewall, hardware (~110 funcs)
`iptables`, `nftables`, `firewalld`, `ipset`, `ip`, `route`, `network`
(read-only /sys/class/net with `ip` fallback), `bridge`, `ethtool`, `sysfs`,
`udev`, `ps`, `process`, `scsi`, `smbios`, `devinfo`, `iwtools`,
`kernelpkg_linux_apt/_yum` (on the pkg provider).
Verify: argv units + QEMU; differential on normalized iptables/nftables dumps.

### R3 — Package ecosystem deepening (~70 funcs)
`pkgrepo` (apt/yum/zypper), `pkgbuild` (rpm/deb), `alternatives`,
`debconfmod`, `python`, `pyenv`, virtualenv/npm/pip long tail.
Verify: Tier 1 six-distro matrix; differential install/remove/list cycles of
throwaway packages per provider.

### R4 — Files, text, templates, misc Linux (~80 funcs)
`file.*` long tail (patch, blockreplace, makedirs_perms, copy options),
`cp` (local source), `incron`, logrotate extras, `temp`, `xml` (encoding/xml),
`yaml` (existing dep), `jinja` — **minimal** variable/substitution engine only
(full Jinja excluded by ADR), `data`, `defaults`, `out`, `ret`, `restartcheck`,
status long tail.
Verify: hermetic unit + fixture suites.

### R5 — Security, crypto, auth on Linux (~85 funcs)
`ssh_auth`, `ssh_known_hosts` (FS parsing first), `ssh_pki`, `x509`, `tls`,
`asymmetric`, `webutil`, `gpg`, `nacl`, `pam`, selinux booleans/modules
(semanage), `linux_acl`.
Binaries: openssl, ssh-keygen, gpg, getfacl/setfacl, semanage.
Verify: container suites; differential for authorized_keys and self-signed
x509 generation (normalized PEM).

### R6 — macOS track (~55 funcs)
`mac_user`(dscl), `mac_group`, mac pkg/brew, launchctl service variant,
`macdefaults`, `keychain`(security), `softwareupdate`, `desktop`, `assistive`,
`xattr`, `power`, `macpackage`.
Enablers: E1–E4. CI: `macos-*` runners; platform-split fixture roots;
darwin binaries already build in release matrix.
Verify: host-runner smoke; differential where Salt installs via pip.

### R7 — Windows track (~230 funcs, largest)
`reg`, `dism`, `dsc(_resource)`, `lgpo`, `lgpo_reg`, `win_firewall`,
`win_dns_client`, `win_iis`, `win_servermanager`, `win_path`, `win_pki`,
`win_dacl`, `win_event`, task(schtasks), `powercfg`, `rdp`, license,
autoruns, auditpol, wua, wusa, psget, chocolatey, winrepo, shortcut,
smtp_server, snmp-windows, appx, plus win_file/user/group/service/pkg/
timezone variants, certutil.
Enablers: E1–E4 mandatory; PowerShell scriptlets emitted by Runner profile;
registry access through `reg.exe` (no Go deps).
CI: `windows-*` runners; dedicated fixture root; differential where Salt is
installable.
Sequencing inside R7: core objects first (reg→user/group/service/pkg/file),
then policy stacks (lgpo/firewall/dns), then optional roles (iis/smtp/snmp).

### R8 — BSD / Solaris tracks (~60 funcs)
freebsd (`pkgng`, pw_user/pw_group), openbsd/netbsd small sets,
`solaris_system/user/group/shadow/fmadm/logadm/rbac/ipspkg/smf_service`,
`zoneadm`, `zonecfg`.
Enablers: E3/E4/E6. CI: QEMU cloud images (freebsd/openbsd/netbsd/solaris 11)
promoted to blocking after soak.
Verify: same fixture format; differential best-effort (Salt on BSD/Solaris is
install-constrained — record coverage caveats).

### R9 — Databases & brokers via native CLIs (~120 funcs)
`mysql`, `postgres*`(10 families), redis-cli, mongosh, influx, elasticsearch
(REST via http.query core), kafka, rabbitmqctl family, cassandra cqlsh,
couchbase, zk_concurrency, sqlite3 (sqlite3 binary).
Enabler: E5. Credentials passed per-fixture; secrets never logged (Runner
redaction).
Verify: services tier integration + differential for list/create/drop cycles
on disposable databases.

### R10 — Cloud & SaaS APIs (~70 funcs)
Policy: vendor CLI wrappers first (`aws`, `az`, `gcloud`, `doctl`, `govc`),
thin stdlib HTTP for webhook-style APIs (slack_notify, telegram, twilio,
victorops, pagerduty, github/gitlab signatures — hmac core exists).
Families: cloud*, boto*/ec2/route53 subsets actually exercised by CLIs,
azurearm, google_*, gcp_*, digital_ocean, linode, vsphere/esxi/govc,
openstack stack (keystone/glance/heat/neutron/nova/cinder/swift),
dnsutil/dig (bind9-client), netbox, saltcloud.
Excluded-by-ADR candidates: any API requiring OAuth flows or signed request
canonicalization beyond stdlib scope.
Verify: contract tests against recorded-response fixtures; live smoke behind
opt-in label only.

### R11 — Network devices (plugin boundary) (~40 funcs)
`napalm_*`, `junos`, `nxos(_api)`, `arista_pyeapi`, netmiko-style drivers.
Requires SSH/NETCONF clients — either pure-Go SSH (stdlib has none → would
break dependency policy) or out-of-tree plugin consuming external CLIs.
Decision gate: ADR before R11 starts; default outcome = plugin boundary
documented, core repo ships discovery/error contracts only.

## 3. Cross-cutting workstreams

- **States mirror exec**: every exec round ships its state counterparts in the
  same round (DoD blocks otherwise).
- **Fixtures**: each family adds real-case scenarios under its suite directory
  (testing.md §"Real-case coverage families"); vm-required flags respected.
- **Differential**: scope grows one round behind ports (R_n ports → R_{n+1}
  differential), report artifacts retained 90 days.
- **Compatibility annotations**: `docs/compatibility/<family>.md` per init.md
  §28 classification checklist; ledger v2 links them.
- **Coverage targets** (of relevant-exec set): R2→20%, R5→30%, R7+R8→55%,
  R9+R10→75%, R12 done → 100% of catalog in terminal states.
- **Estimation**: ~700 functions remain across rounds; sequencing DAG:
  E1–E4 → {R1,R2,R3,R4,R5} parallelizable → {R6,R7,R8} after enablers →
  R9 after E5 → R10 anytime after R4 → R11 last (ADR-gated).

## 4. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Windows/mac CI cost | path-filtered platform jobs; nightly full, PR fast lane |
| Flaky service-tier tests | compose healthchecks + retry-once annotation policy (testing.md §Cost controls) |
| Salt drift | catalog re-index job fails golden check on submodule bump |
| Protocol client creep into Go deps | ADR gate; wrapper-first default |
| Scope explosion in jinja/templating | minimal engine ADR; full Jinja excluded |

## 5. Acceptance

- [ ] Every catalog family appears in exactly one terminal bucket
      (implemented / partial / excluded) with annotations.
- [ ] Each round's suites green across declared platforms before DoD claims.
- [ ] Differential reports exist for every ported family with runtime parity
      potential.
- [ ] Zero new Go module dependencies at completion (ADR-listed exceptions).


## 6. Execution state (handoff ledger, updated per phase)

Committed phases: E7 ledger v2, E1 runner OS profiles, E2 elevation,
E3.1 cross-GOOS tree + CI matrix, E3.2 platform-scoped registration,
E3.3 tags kmod/shadow/selinux, E3.4 tags sysctl/cron/environ,
E3.5 tags status.loadavg/uptime linux-only,
E3.6 tags status.meminfo/pid_list + mount family linux-only,
E4 Facts v2 (per-OS providers: darwin sw_vers, windows CIM via
PowerShell scriptlet through the Runner shell model, BSD sysctl;
GOOS-neutral parsers verified by golden fixtures under
internal/facts/testdata), R1.1 lvm family ported (15 exec functions +
6 states mirroring linux_lvm.py/states/lvm.py contracts; tri-state
*bool args added to the decoder for Salt default-true force flags),
R1.2 storage CLI batch ported: devmap (2), cryptdev (6, incl crypttab
set/rm machinery), extfs (5, kwarg-flag maps + dumpe2fs parser),
quota (7 exec + quota.mode state, mirroring Salt's set_ zero-fallback
quirk with a section-28 note), mdadm/raid (9, facts-driven config path,
stop retcode quirk pinned by test); decoder gains *string tri-state;
salt-reference generator honors __func_alias__ so counters match
CLI-facing names (families implemented 35→40, planned 142→137),
R1.3 xfs family ported (9 exec functions: xfs_info kv-parser ported
against Salt's verbatim fixture, blkid export blocks, xfsdump scalar
fields, indentation-walk inventory parser replacing Salt's eval,
prune/estimate/mkfs/modify/defragment; families 40→41, planned
137→136), R1.4 partition family ported (22 exec functions: parted
machine-format list parser incl. free-row and 7/8-column info variants,
sfdisk system-id round-trip, full Salt validation message surface,
block-device validation via injectable hook; families 41→42, planned
136→135), R1.5 pkg_resource family ported (11 registered exec functions
+ _repack_pkgs kept unexported like Salt's loader-hidden privates:
repack_dictlist semantics with collision error carrying a Python-style
repr, pack_sources empty-dict error paths, parse_targets branch order
pkgs+sources → advisory_ids → pkgs → sources → name with the macOS
sources-ignore mapped to GOOS darwin behind an injectable hook and the
absolute-path invocation error verbatim, version with fnmatch glob
semantics and bare-value single returns, LooseVersion/fnmatch.translate
ports for version_compare returning false on invalid operators, and
format_pkg_list attr-set algebra incl. arch-suffix folding via the
optional pkg.parse_arch delegate; optional __salt__-style delegates
(normalize_name/version_clean/parse_arch/check_extra_requirements)
resolve through registry lookups and degrade exactly like Salt minions
without them; remote sources surface UnsupportedError for cp.cache_file
until the cp family lands, salt:// stays master-minion excluded; the
decoder gains []any structured list args with safe_load-style YAML-string
coercion and pkg.list_pkgs gains versions_as_list; intentional
divergence pinned by test: sort_pkglist/stringify reject non-list scalar
values instead of Python's silent char-decomposition; families 42→43,
planned 135→134). Enablers E1-E4 are complete: R6-R8 unblocked. Known gap
parked for R8: statfs_unix.go (!windows tag) does not compile under
GOOS=openbsd/netbsd (pre-existing, outside gated matrix). Remaining
in R1, in order:
  1. sysfs + bcache in one phase — bcache is blocked on the sysfs
     family: port sysfs.attr/interfaces/read (+ minimal udev.env via
     udevadm --export parse) together with bcache; _wait needs an
     injectable sleep hook. Head item for the next session.
  2. loop state — OPEN DECISION for the user: loop.until eval()s
     arbitrary Python conditions and is not honestly portable; proposal
     is to mark until excluded-by-ADR (code-eval contract) and port
     only until_no_eval restricted to builtin compare operators +
     data.subdict_match once the data/util layer lands. Do not port
     silently.
  3. blockdev "extensions": no catalog entry exists for blockdev.*
     (info was a pre-catalog extension); nothing to port without a
     differential catalog pass.

Next in order: rounds R1-R5 (parallel), R6-R8 (enablers done),
R9 after services tier (E5), R10 cloud, R11 netdev behind ADR gate.
Master-minion families stay excluded.
