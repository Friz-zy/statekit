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
planned 135→134), R1.6 storage-sysfs cluster ported in one phase as the
ledger required: sysfs family (5 exec functions — attr/write/read/target/
interfaces with realpath-per-component resolution so ".." hops resolve
after symlinks, owner-bit r/w/rw interface classification, int-then-float
value coercion, false-not-error failure contract, list-form read tree)
plus the sysfs.present state (choice-list "[selected]" extraction,
test-mode no-mutation, registry-driven read/write) and udev.env
(minimal per the recorded decision: udevadm --export argv through the
Runner, E-section parser with numeric coercion and single-element list
collapse; info/name/path/links/exportdb stay unregistered until their
round) plus bcache (11 exec functions under __func_alias__ names
attach/config/super: uuid via /sys/fs/bcache discovery or cache-link
resolution, attach/detach recursion over status with None-means-nothing
results, start/stop flows, back_make/cache_make make-bcache argv incl.
Salt's bucket-size quirk where the computed bucket is discarded, config_
kwargs writes filtered of dunders, status/device sysfs-parse reshaping
(stats re-keying, internals nesting, config writeback_* grouping),
super_ bcache-super-show parsing with [value, comment] tuples; _wait
sleeps through an injectable hook, tries=300 for detach/stop mirrored
verbatim; bcache has no Salt unit tests so the suite pins the
source-derived contract hermetically; documented divergence:
status() synthesizes the cache-dev entry Salt would KeyError on).
loop.until is RESOLVED: user accepted exclusion-by-ADR (code-eval
contract, docs/adr/0001-loop-until-excluded.md); the loop family's
remaining port surface is until_no_eval with builtin compare operators +
data.subdict_match, planned behind the data/util layer — family terminal
state will be partial. Also fixed: .gitignore's coverage.* rule was
swallowing docs/catalog/coverage.yaml, so the generated coverage ledger
was never committed; now tracked (families 43→46 implemented /
134→131 planned; exec 221→238, state 31→32). R2.1 opened the hardware
round with the small CLI batch: ethtool (11 exec functions — the six
python-ethtool-backed queries/sets re-implemented over the ethtool CLI
parsing into the same key shapes, documented mechanism divergence, plus
the four CLI-native pause/features functions and verbatim "Not
supported"/"Invalid arguments" failure strings), devinfo (filter via a
/sys/block-derived disks hook and udev.info delegation, hwinfo with both
hwinfo parsers ported fixture-exact including upstream's always-true
stack-truncation quirk, grains side-sections filled from direct
sysfs/procfs/resolv/net readers behind injectable hooks), scsi (ls with
column pops incl. model skipping key/type/vendor, error strings and the
invalid-option hint verbatim, rescan_all through the host sysfs tree),
iwtools (scan/list_interfaces parsers, set_mode gated on ip.down/ip.up
registry delegates → UnsupportedError until the ip family lands),
smbios (get/records over dmidecode with the full _dmi_isclean bogus-value
filters, canonical UUID v1-v4 validation, scalar-on-list insertion;
upstream has no unit tests so the suite pins source-derived fixtures).
Go Split does not interleave capture groups like Python re.split — the
handle-record pairing walks FindAllStringSubmatchIndex. udev.info
registered alongside env for devinfo's dependency; name/path/links/
exportdb still pending their round (families 46→51 implemented /
126→131→126 planned; exec 238→259). R2.2 ported the ps family (24
exec functions) off a local /proc reader replacing psutil — documented
mechanism divergence with identical observable shapes: pids/stat/cmdline
parsing tolerant of comm names containing spaces and parens, tick
conversion at USER_HZ=100, top with two-sample CPU deltas and an
injectable sleep, pgrep/pkill substring-or-regex matching over name or
full cmdline with user filters and None-means-no-matches results,
kill_pid/pkill signal delivery behind build-tagged syscall helpers
(stdlib only), cpu_percent two-sample busy math incl. per-cpu lists,
/proc/meminfo-backed virtual_memory/swap_memory/total_physical_memory
with psutil percent rounding, /proc/net/dev and /proc/diskstats counter
dicts with aggregate-vs-per-unit False misses, disk_partitions filtered
by the /proc/filesystems nodev set unless all=True, disk_usage via
stdlib statfs, boot_time with a strftime-subset converter raising the
verbatim invalid-format error, get_users via little-endian utmp record
parsing, lsof/netstat/ss/psaux shell wrappers with which-guards carrying
the exact "binary was not found in $PATH" message, and status() mapping
kernel state characters to psutil names. Upstream tests mock psutil
internals on macOS, so the suite pins source-derived hermetic /proc
fixtures instead (families 51→52 implemented / 125 planned; exec
259→283). R2.3 opened the firewall stack with iptables (16 exec
functions): build_rule ports the full assembly order (if/of, proto/
protocol with the policy-match exception, match lists with name_ for
pknock/quota2/recent, negated multiport lists collapsing to one "!",
comment quoting, the verbatim after-jump option table, generic leftover
rendering) with upstream's error strings ("Error: protocol must be
specified" and friends returned as results); check() probes --check
support through the help text and falls back to the temporary-chain
round-trip named by uuid.getnode's 0x-hex MAC; _parse_conf reimplements
the shlex + swap/merge preprocessing plus a Go-side parse_known_args
over the generated 381-option table (Go Split does not interleave
capture groups, so pairing walks indices; unknown flags fall to extras);
save() routes through config.option save_filters regexes and the
file.write delegate. cmdmod gained cmd.run_stderr (additive, required by
the family contract); os_family/os grains resolve behind injectable
hooks defaulting to the unsupported-distro error path. Upstream's 17
tests map onto StateKit fixtures covering every public function
(families 52→53 implemented / 124 planned; exec 283→299). R2.4 ported
ipset (11 exec functions): commands run as argv through the central
Runner mirroring upstream's python_shell=False lists; new_set carries
the full create-option tables with set()-nondeterministic ordering
mirrored as Go map iteration, family suffix only for types that support
it and the comment flag; add() validates timeout/counters/comment/
skbinfo support against the live set Header before building the -exist
argv and short-circuits duplicates with the Warn string; membership
checking ports _parse_member's ipaddress semantics over netip (slash
networks masked, dash ranges summarized to covering prefixes, unparseable
parts keeping raw strings like the swallowed ValueError) and
_compare_member_parts including its all-items AND behavior over range
lists and the networks-never-contain rule. All 12 upstream tests map
onto StateKit fixtures (families 53→54 implemented / 123 planned; exec
299→310). R2.5 ported nftables (21 exec functions): every result is the
upstream dict shape {comment, rule?, result}; build_rule renders nft
syntax (meta iifname/oifname, ct state braces, reverse-sorted port sets,
after-jump ordering) with the empty-proto substring quirk preserved;
check_table/check_chain/check return comment dicts and chain through a
shared preflight; get_rule_handle extracts handles by regex over the
--handle listing; list_tables/get_rules/get_rules_json parse real JSON
envelopes; save() aggregates unique families into one file honoring
file.directory_exists with a local-stat fallback (documented divergence);
set_policy rebuilds base chains from live JSON info requiring type/hook/
prio; get_policy keeps upstream's always-None double-index quirk past
chain validation; new_chain emits upstream's literal backslash-brace
tokens for typed base chains. Upstream's 25 tests map onto StateKit
fixtures (families 54→55 implemented / 122 planned; exec 310→331).
R2.6 ported bridge (9 exec functions under the list_→list alias):
kernel dispatch (Linux brctl vs FreeBSD/OpenBSD ifconfig vs NetBSD
brconfig) resolves behind an injectable grains hook defaulting from
GOOS; the brctl parser mirrors upstream's brname-persistence quirk with
the orphan-interface crash surfacing as a documented error; BSD show
parses -g bridge listings plus member/STP markers, and NetBSD keeps its
brconfig-specific shape; add/del/addif/delif/stp build the per-kernel
argv (addem/deletem vs add/delete, stp on/off vs stp/-stp with the
required iface). Upstream's 9 dispatch-mock tests map onto StateKit
fixtures pinning both parser families and per-kernel argv (families
55→56 implemented / 121 planned; exec 331→340).
R2.7 opened the network family with its
pure-compute surface (9 exec functions): subnet/CIDR math over netip
(in_subnet scanning the host addresses behind an injectable hook,
ip_in_subnet, calc_net with dotted/prefix netmasks rejecting
non-contiguous masks, convert_cidr with v4 broadcast and v6 no-broadcast
semantics), classification tables ported from CPython's ipaddress
constants including CGNAT 100.64/10 and the full not-globally-reachable
v4/v6 ranges, reverse_pointer for both families, uppercase hex octet
encoding, and wol building the 102-byte magic packet behind an
injectable UDP hook with mac_str_to_bytes separator handling. The
tool-backed remainder of the family (ping/netstat/routes/interfaces/
fqdns and the per-platform parsers) lands in R2.8. Upstream fixtures
for these functions map one-to-one (families 56→57 implemented / 120
R2.8 shipped the tool-backed Linux surface (14 more exec functions):
interfaces/hw_addr/interface/interface_ip/subnets/subnets6 over a port
of _interfaces_ip (group parsing of ip link+addr with prefixlen keys,
secondary addresses, and per-interface merge so the link-pass hwaddr
survives the addr pass), routes/default_route via the _ip_route_linux
parser (netstat fallback deferred), get_route through the ip route get
regex extraction, active_tcp off /proc/net/tcp(6) little-endian hex
records with ESTABLISHED filtering, arp/ping/traceroute/dig wrappers
with sanitize_host and which-guards. Remaining pending functions in
the family: netstat/ss per-platform parsers, bufsize pair, hostname
trio, connect, ip_networks(6), ifacestartswith, fqdns, ip_neighs(6)
(families stay counted at 57 implemented; exec 349→363).
planned; exec 340→349).
R2.8 shipped the tool-backed Linux surface (14 more exec functions):
interfaces/hw_addr/interface/interface_ip/subnets/subnets6 over a port
of _interfaces_ip (group parsing of ip link+addr with prefixlen keys,
secondary addresses, and per-interface merge so the link-pass hwaddr
survives the addr pass), routes/default_route via the _ip_route_linux
parser (netstat fallback deferred), get_route through the ip route get
regex extraction, active_tcp off /proc/net/tcp(6) little-endian hex
records with ESTABLISHED filtering, arp/ping/traceroute/dig wrappers
with sanitize_host and which-guards. Remaining pending functions in
the family: netstat/ss per-platform parsers, bufsize pair, hostname
trio, connect, ip_networks(6), ifacestartswith, fqdns, ip_neighs(6)
(families stay counted at 57 implemented; exec 349→363).
R2.9 completed the network family (13 final exec functions): netstat
with the Linux dispatch (netstat -tulpnea columns vs ss -tulpnea with
users/uid/ino trailing-field extraction and ESTAB→ESTABLISHED rename),
ip_neighs/ip_neighs6 over `ip neigh show` (mac-keyed like upstream's
comps[4] mapping), get_hostname/get_fqdn behind injectable resolver
hooks, mod_hostname for hostnamectl/hostname flows including /etc/hosts
token rewrite and RedHat/Debian hostname-file persistence, connect with
TCP dial plus UDP probe and verbatim comment dictionary,
get_bufsize/mod_bufsize over literal /sbin/ethtool -g/-G with the
max-suffix state machine and rx/tx/rx-mini/rx-jumbo kwargs, ip_networks/
ip_networks6 with glob interface filtering, loopback exclusion and the
verbose dict shape, ifacestartswith with label preference, and fqdns as
sorted reverse-resolved names (sequential; upstream parallelizes —
documented divergence). The network family is now complete at 55/55
catalog functions (exec 363→377).
R2 CLOSED (differential scope pass executed): registration moved into
internal/bootstrap so the CLI binary and the new tests/differential
harness observe one identical execution surface; the pass reconciles
the live registry against docs/catalog for every R2 family and emits a
golden report at docs/differential/R2/report.yaml — R2 public surface
119/119 registered (177 catalog entries incl. privates), zero pending.
The twin-container scenario manifest (iptables/nftables restore-
validation, ipset membership matrix, bridge lifecycle, ps vs procps,
network math vs python-ipaddress) ships inside the report and waits on
differential.yml runtime enablement; network family completed at 55/55
catalog functions including ip_addrs/ip_addrs6 (exec 377→379).
Enablers E1-E4 are complete: R6-R8 unblocked. Known gap
parked for R8: statfs_unix.go (!windows tag) does not compile under
GOOS=openbsd/netbsd (pre-existing, outside gated matrix). loop.until is
excluded per docs/adr/0001-loop-until-excluded.md; until_no_eval waits
for the data/util layer. Remaining in R1, in order:
  1. blockdev "extensions": no catalog entry exists for blockdev.*
     (info was a pre-catalog extension); nothing to port without a
     differential catalog pass. With that, R1's function scope is
     exhausted — R1 closes after a differential-scope pass over its
     families (R1 ports → R2 differential per section 3).
  2. Round status: **R2 CLOSED** (ports + differential scope pass,
     report at docs/differential/R2/report.yaml). Next: R3 pkg deep
     port (head item); R4-R5 per plan; R6-R8 unblocked via E1-E4; R9
     awaits the services tier (E5); R10 cloud; R11 netdev behind the
     ADR gate. Twin-container differential runs activate with
     differential.yml.

R3.1 opened the package deepening round with the APT repository surface
(the pkgrepo family, exec side): the Debian sources engine ported from
salt/utils/pkg/deb.py — classic SourceEntry/SourcesList plus Deb822
section stanzas, cdrom-line parsing, first-bracket-group option
extraction, split_source_line's bracket-aware walk, repo_line rendering
with trusted=no dropping and comment round-trip — and seven
CLI-facing pkg.* functions registered from the new modules/exec/pkgrepo
package: list_repos with deb822 per-uri/suite/type expansion, get_repo
with ppa expansion and slash-insensitive matching, del_repo with
suite/comps subtraction, the two cleanup-message shapes and the
sources.list.d part-file removal, mod_repo with the full kwargs
machinery (consolidate dedup onto sources.list deleting every
processed part file, keyid/keyserver/key_url/key_text side doors,
.sources creation behind the signedby/trusted gate when apt-key is
absent, the _MODIFY_OK/_MODIFY_OK_LEGACY setattr allow-lists), plus
get_repo_keys/add_repo_key/del_repo_key over gpg --with-colons parsing
and the .asc armor-preservation rule from regression #68464. Upstream
quirks pinned by tests: del_repo formats LP_PVT_SRC_FORMAT with swapped
arguments (DIST before OWNER), _decrypt_key returns the .decrypted path
even when dearmoring failed, get_repo_keys references an undefined
local on apt-key failure (StateKit raises an explicit error instead),
and the SyntaxError guard around _split_repo_str is dead code at the
pinned revision because parse raises SaltInvocationError. Documented
divergences: remote schemes surface UnsupportedError for cp.cache_file
until the cp family lands while local absolute paths pass through,
systemd-run scoping is not reproduced though the dpkg-lock retry
backoff is, comps set-difference keeps first-seen order where Python's
set iteration is unordered, truncated gpg colon-records degrade missing
fields to None instead of crashing, and config.option degrades like
minions lacking the module so proxy env injection for apt-key calls
stays inert. Salt's test_aptpkg repo surface maps onto hermetic
MemoryFS/fake-runner fixtures; expandRepoDef is ported internally for
the pkgrepo state module (managed/absent), which lands as its own phase
and flips the family terminal (exec 379→386; catalog regen also
reconciled the stale implemented_families list that had drifted since
R2.5 — network/nftables now recorded, summary consistent at 57
implemented / 120 planned).

R3.2 completed the yum/dnf repository surface and unified the pkg.*
registrations behind Salt's virtual-module selection: backendOf routes
on OS family (Debian→apt engine, RedHat→yum engine; zypper stays
unsupported until its phase, and the apt-only key trio reports
unsupported on other families). The yum side ports configparser
semantics into a local subset — lowercased keys, first-occurring "=" /
":" delimiter, indented continuations joined with "\n", DEFAULT
sections invisible to iteration, strict duplicate detection,
MissingSectionHeaderError degrading _parse_repo_file to ("", {}) — plus
yum.conf reposdir discovery over the /etc/yum/yum.conf, /etc/yum.conf,
/etc/dnf/dnf.conf, /etc/tdnf/tdnf.conf lookup order with the verbatim
no-config error list. list/get/del/mod_repo carry the upstream message
shapes (including the copr alias expansion inside the not-found text),
the single-file deletion path, comment-preserving multi-stanza rewrites
with multiline value re-indentation, COPR name mapping
(copr:owner/name → copr:copr.fedorainfracloud.org:owner:name), and the
mod_repo kwargs machinery where every non-dunder kwarg lands in the
stanza (basedir included — upstream never filters it) while blank-value
deletion keeps False and numeric zero because Python evaluates
False == 0. Documented divergences: option apply order is sorted where
upstream preserves request insertion order (Go map decoding loses it),
and .repo file scans iterate deterministically where os.listdir is
arbitrary. Salt's test_yumpkg repo tests map onto hermetic fixtures;
the CLI dispatch was smoke-checked against a live Fedora repos.d.

R3.3 completed the zypper repository surface: a scoped port of the
_Zypper wrapper (argv assembly with --non-interactive/--xmlout/
--no-refresh-unless-refreshable/--root, the success 0/100-103 and
warning 6/7/106/107 exit-code classification, XML
<message type="error"> extraction over an encoding/xml DOM subset, and
the lock-7 retry loop with five-second waits behind an injectable hook)
plus list/get/del/mod_repo and refresh_db. The del_repo XML feedback
contract keeps upstream's fall-through not-found raise when `rr`
returns no progress/message nodes; mod_repo carries URL-parse
six-tuple equality for the duplicate-alias probe, remove-and-readd on
baseurl changes, the mr flag ordering (enabled/refresh/cache/gpgcheck/
priority/humanname/name), and the no-op comment marker; refresh_db
tolerates retcode 6 via success_retcodes and parses up-to-date/done
lines. Documented divergences: systemd-run scoping is not reproduced,
event.fire_master lock notifications are dropped (master-minion
excluded) while the wait-and-retry behavior remains, and the rpm-lock
fcntl probe is not reproduced (zypper-lock retries cover exit 7).
Salt's test_zypperpkg refresh_db argv shapes and the zypp/*.cfg repo
fixtures map onto hermetic fake-runner/MemoryFS tests.

R3.4 landed the pkgrepo state module (managed/absent) and flipped the
family terminal. managed ports the full flow — the key-argument
conflict battery, enabled/disabled inversion per family, the
already-configured comparison loop (comps/key_url set compares, the
Debian line comparison with sorted tails and comment text, RedHat
comment combining, boolean disambiguation for 1/0 vs True/False),
clean_file staleness reconfiguration (#68208), the test-mode delta, and
the mod_repo/post-get_repo change recording — delegating to the
registered pkg.* functions; ExpandRepoDef/SplitRepoStr are exported
from the exec package mirroring Salt's cross-module private imports.
absent carries ppa/copr renaming, deb strip_uri, the architecture-
mismatch invalidation, and optional key removal. The catalog
classifier fix ships alongside: classifyFamilies previously received
only exec-side shipped names, so state-led families could never reach
terminal; with both surfaces counted, pkgrepo flipped implemented and
the same gap surfaced a second latent family — host — whose state
module predates the porting plan but lacked only() against its catalog.
host.only plus the hosts.get_alias/set_host exec long tail were ported
in this phase to complete it honestly (exec 386→388, states 32→35,
families 57→59 implemented / 118 planned).

Next in order: R3 continues (pkgbuild, alternatives, debconfmod,
python/pyenv, npm/pip/virtualenv long-tail check), R4-R5 per plan,
R6-R8 unblocked via E1-E4, R9 awaits the services tier (E5), R10 cloud,
R11 netdev behind the ADR gate. Master-minion families stay excluded.
