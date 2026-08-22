# StateKit

A portable, standalone **Go** binary that implements the useful *local* functionality of [SaltStack](https://github.com/saltstack/salt) — essentially portable `salt-call --local` plus `state.single` — without a master, minion daemon, Python runtime, or any configuration-management server.

> Copy one binary to any machine and manage it:
>
> ```bash
> scp statekit host:/tmp/
> ssh host sudo /tmp/statekit state pkg.installed --name curl
> ```

**Status:** Phases 0-2 implemented: core architecture (`version`, `facts`, `exec`/`state` registries, four input channels with precedence, JSON/YAML/text outputters, exit codes, Runtime, Runner, minimal Facts, provider registry, fixture-driven integration harness) plus Salt reference tooling (`tools/salt-reference`, pinned `references/salt.lock`, generated catalog under `docs/catalog/`) and the core execution module families (test, cmd, file, status, system, user, group, shadow, pkg, service, sysctl, mount, disk, archive, cron, hosts, timezone, locale) with APT/DNF/YUM/Zypper/Pacman/APK and systemd/OpenRC providers. The authoritative specification is [`plans/init.md`](plans/init.md).

SaltStack is the primary behavioral reference for available modules, functions, arguments, defaults, return values, state results, platform-specific behavior, edge cases, tests, provider selection, and system detection. StateKit copies **observable Salt behavior**, not Salt's internal architecture.

---

## Contents

- [Concept](#concept)
- [Quick examples](#quick-examples)
- [Architecture](#architecture)
- [CLI structure](#cli-structure)
- [Input methods and precedence](#input-methods-and-precedence)
- [Output formats](#output-formats)
- [State result contract](#state-result-contract)
- [Execution function results](#execution-function-results)
- [Test mode (dry run)](#test-mode-dry-run)
- [Runtime model](#runtime-model)
- [Facts instead of grains](#facts-instead-of-grains)
- [Providers (virtual modules)](#providers-virtual-modules)
- [Relationship to SaltStack](#relationship-to-saltstack)
- [Compatibility program](#compatibility-program)
- [Repository layout](#repository-layout)
- [MVP scope](#mvp-scope)
- [Roadmap](#roadmap)
- [Testing strategy](#testing-strategy)
- [Security model](#security-model)
- [Exit codes](#exit-codes)
- [References](#references)
- [License](#license)

---

## Concept

StateKit exposes two APIs over one shared set of modules:

```bash
# Execution function — immediate action or inspection
statekit exec service.restart --name nginx

# State function — declarative desired-state convergence
statekit state service.running --name nginx
```

State functions normally consume execution functions instead of duplicating low-level host manipulation:

```text
service.running
       │
       ├── service.status        (check desired state)
       └── service.start         (enforce change)
                │
                ▼
          ServiceProvider
                │
              systemd
```

The closest Salt equivalent of the whole project:

```text
salt-call --local + state.single + execution modules + state modules
+ only the minimum system detection those modules require
```

Everything else in Salt is intentionally out of scope.

## Quick examples

```bash
statekit version

statekit exec --list
statekit state --list

statekit facts

statekit exec test.echo --text hello
statekit state test.nop --name example

statekit exec pkg.version --name curl
statekit exec file.remove --path /tmp/foo

statekit state pkg.installed --name curl
statekit state file.managed --name /etc/example.conf --source /tmp/example.conf
statekit state service.running --name nginx --enable true
```

## CLI structure

Canonical invocation forms:

```text
statekit exec  <module>.<function> [args...]
statekit state <module>.<function> [args...]
```

Explicit `exec` and `state` namespaces stay canonical because identical module names exist in both APIs (e.g., `file.*`, `pkg.*`, `service.*`). Shortcuts such as `statekit pkg.version ...` may be added later without changing the canonical form.

## Input methods and precedence

Every function accepts identical input through four channels:

| Channel | Example |
|---|---|
| CLI flags | `--name curl --version 8.14.1` |
| Inline YAML/JSON | `--config '{"name":"curl","version":"8.14.1"}'` |
| File | `--file request.yaml` |
| stdin | `cat request.yaml \| statekit state pkg.installed -` |

Resolution precedence (lower never overrides higher):

```text
function defaults
        ↓
file / stdin / --config
        ↓
explicit CLI arguments
```

Ambiguous combinations (`--stdin` + `--file`, `--stdin` + `--config`) are rejected until an explicit merge mechanism exists.

## Output formats

```bash
--output json | yaml | text      # short form: -o json
```

Machine-readable output (`json`, `yaml`) is treated as the stable API.

## State result contract

State functions preserve Salt's core state return shape:

```yaml
name: nginx
result: true
changes:
  service:
    old: stopped
    new: running
comment: Service nginx was started
```

Core fields: `name`, `result`, `changes`, `comment`.

`result` is tri-state, matching Salt semantics:

| Value | Meaning |
|---|---|
| `true` | desired state successfully reached |
| `false` | operation failed |
| `null` | test mode; changes would be required |

Go representation:

```go
type StateResult struct {
    Name    string         `json:"name" yaml:"name"`
    Result  *bool          `json:"result" yaml:"result"`
    Changes map[string]any `json:"changes" yaml:"changes"`
    Comment string         `json:"comment" yaml:"comment"`

    Meta *ResultMeta `json:"meta,omitempty" yaml:"meta,omitempty"`
}
```

`changes` carries real old/new deltas (never a bare `{"changed": true}`); a derived `changed = len(changes) > 0` may optionally be exposed. Optional non-core metadata may extend results without breaking compatibility:

```yaml
meta:
  type: state
  module: service
  function: running
  provider: systemd
  duration_ms: 23
```

## Execution function results

Execution functions preserve the natural result type of the corresponding Salt function — bool, string, integer, list, map, or structured object. They are not forced into an artificial common envelope. For example:

```bash
$ statekit exec pkg.version --name curl -o yaml
curl: 8.14.1
```

Errors and optional StateKit metadata may be wrapped separately when machine-API consistency requires it.

## Test mode (dry run)

```bash
statekit state pkg.installed --name curl --test    # equivalent structured form: test: true
```

Already satisfied → `result: true`, empty changes, no mutation. Modification required → `result: null`, would-be changes reported, comment explains. **No modification ever occurs in test mode.** Behavior follows Salt's `test=True` semantics as closely as practical.

## Runtime model

Salt's implicit global dunder variables (`__salt__`, `__states__`, `__grains__`, `__opts__`, `__pillar__`, `__context__`) are replaced by an explicit runtime object passed to every function:

```go
type Runtime struct {
    Exec      *ExecRegistry
    States    *StateRegistry
    Facts     *Facts
    Providers *ProviderRegistry
    Runner    Runner
    FS        FileSystem
    Options   RuntimeOptions
}
```

State functions call execution functions explicitly:

```go
runtime.Exec.Call("pkg.version", ...)
runtime.Exec.Call("pkg.install", ...)
```

Functions are registered explicitly:

```go
type ExecFunction interface {
    Name() string
    Execute(context.Context, *Runtime, any) (any, error)
}

type StateFunction interface {
    Name() string
    Apply(context.Context, *Runtime, any) StateResult
}
```

## Facts instead of grains

There is no user-facing grains subsystem. A minimal, read-only detection layer called **facts** provides exactly what modules need to choose implementations and behave compatibly:

```text
OS, OS family, OS version, kernel, architecture, hostname,
UID/GID, init system, package manager, filesystem information,
network interfaces, SELinux/AppArmor status,
virtualization where required
```

Rules: facts are read-only, local, auto-detected, typed internally, lazy where useful, cached only for process lifetime. No custom grain files, persistent grains, targeting, configuration, sync, or remote grains. Salt's grains sources remain the reference for detecting obscure systems correctly.

## Providers (virtual modules)

Salt's virtual-module idea is preserved: generic module names resolve to concrete implementations via minimal facts.

```text
pkg      → apt, dnf, zypper, pacman, apk
service  → systemd, OpenRC
+ similar abstractions for user, group, shadow, sysctl, firewall, network, mount
```

Selection flow: `minimal facts → provider resolver → implementation`.

In the pinned Salt revision, the corresponding reference implementations include `salt/modules/aptpkg.py`, `salt/modules/yumpkg.py`, `salt/modules/dnfmodule.py`, `salt/modules/zypperpkg.py`, `salt/modules/pacmanpkg.py`, `salt/modules/systemd_service.py` (`__virtualname__ = "service"`), and `salt/modules/debian_service.py`. Platform-split modules such as `linux_sysctl.py`, `linux_shadow.py`, and their `mac_*`/`win_*`/`solaris_*` siblings illustrate how Salt maps platforms onto virtual names.

## Relationship to SaltStack

Used as reference from Salt:

```text
salt/modules/*     execution modules
salt/states/*      state modules
salt/utils/*       utilities (as behavior reference)
salt/grains/*      only as reference for required system detection
tests/*            behavioral specification
```

Intentionally **not** reproduced:

```text
salt-master, salt-minion daemon, transport, authentication protocol,
event bus, job system, targeting, returners, reactor, beacons,
runners, wheel, pillar, fileserver, SLS/highstate orchestration,
renderer system, Jinja, scheduler, Salt configuration hierarchy,
proxy minions, Salt Cloud
```

No new configuration-management language is created either: StateKit operates on individual execution functions and individual states. The furthest it goes toward multi-operation input is an ordered, sequential `apply` list with explicit stop/continue policy — no requisites, no dependency graph, no highstate.

## Compatibility program

### Pinned Salt revision

The SaltStack upstream repository is vendored as a git submodule and pinned; every compatibility decision refers to this exact revision:

```text
submodule: https://github.com/saltstack/salt.git @ 8b63e700637e40d76f80a00d95c60471797c73b9
           (v3008.2-180-g8b63e70063)
lock file: references/salt.lock   { repository, commit, version }
```

Upgrading the Salt reference is an explicit, reviewable project operation.

### Automated source index

`tools/salt-reference/` scans the pinned tree (`salt/modules/`, `salt/states/`, `salt/utils/`, `salt/grains/`, `tests/`) with AST analysis and emits a machine-readable catalog per function: kind, module, function, source path/symbol, parameters, defaults, execution dependencies, platform restrictions, related tests. Implementation work must use this inventory rather than memory.

Example entry:

```yaml
kind: state
module: service
function: running
source:
  path: salt/states/service.py
  symbol: running
execution_dependencies:
  - service.status
  - service.start
  - service.enable
parameters: [name, enable, sig, init_delay]
tests: [...]
```

### Compatibility classification

Each migrated function gets a status:

```text
COMPATIBLE | PARTIAL | INTENTIONAL_DIVERGENCE | UNSUPPORTED | NOT_APPLICABLE
```

and each argument a decision:

```text
KEEP | RENAME | GENERALIZE | DROP | DEFER
```

Salt-infrastructure arguments (`saltenv`, `pillar`, `template`, `source_hash_name`, `__env__`) are evaluated individually and never silently drag Salt infrastructure into StateKit. Per-operation machine-readable manifests live under `docs/compatibility/`:

```yaml
kind: state
operation: file.managed
reference:
  module: salt.states.file
  function: managed
  revision: <salt commit>
status: partial
supported:   [name, user, group, mode, contents]
unsupported: ["salt:// source", saltenv]
differences: ["remote Salt fileserver sources are not supported"]
tests: { referenced: 74, ported: 61, excluded: 13 }
```

### Tests as specification

Salt's own tests are treated as the primary behavioral reference. The workflow per function: read Salt source and its tests → extract the observable contract (inputs, defaults, output, change semantics, side effects, platform differences, edge cases) → port scenarios into language-independent YAML fixtures before/alongside the Go implementation → implement using existing core primitives → differential-test against the pinned Salt release where feasible → update coverage data. Salt-internals testing (loader mocks, `__salt__` plumbing) is not reproduced.

### Salt bugs

Salt bugs are not automatically copied. Suspicious behavior is reproduced, traced through Salt tests/source/upstream issues, classified (Salt-compatible / bug intentionally fixed / undefined / platform-specific / intentional divergence), and recorded in compatibility metadata. Divergence is allowed only when explicitly tested and documented.

## Repository layout

```text
statekit/
├── cmd/statekit/
├── internal/
│   ├── cli/
│   ├── config/
│   ├── runtime/
│   ├── result/
│   ├── registry/
│   ├── facts/
│   ├── platform/
│   ├── process/
│   └── output/
├── modules/
│   ├── exec/    (file, pkg, service, user, ...)
│   └── state/   (file, pkg, service, user, ...)
├── providers/   (pkg/, service/, user/, ...)
├── tests/       (compatibility/, integration/, fixtures/, images/)
├── tools/salt-reference/
├── docs/compatibility/
├── plans/init.md
└── go.mod
```

CLI flags/help/JSON Schema/completion are generated from single-source function metadata (e.g., struct tags on typed argument structs), so signatures are never maintained twice.

## MVP scope

First useful release targets Linux only.

Execution: `cmd.*`, `file.*`, `pkg.*`, `service.*`, `user.*`, `group.*`, `sysctl.*`, `mount.*`, `archive.*`, `cron.*`, `status.*`
States: `cmd.*`, `file.*`, `pkg.*`, `service.*`, `user.*`, `group.*`, `sysctl.*`, `mount.*`, `archive.*`, `cron.*`

Priority state functions: `file.managed`, `file.directory`, `file.absent`, `file.symlink`, `pkg.installed`, `pkg.removed`, `pkg.latest`, `service.running`, `service.dead`, `service.enabled`, `service.disabled`, `user.present`, `user.absent`, `group.present`, `group.absent`.

Platforms: Debian/Ubuntu, Fedora/RHEL-like, openSUSE, Arch, Alpine.
Providers: APT, DNF, Zypper, Pacman, APK; systemd, OpenRC. (APK/OpenRC coverage in the pinned Salt revision must be confirmed during Phase 1 indexing; other platforms are added incrementally from Salt implementations.)

## Roadmap

| Phase | Content |
|---|---|
| 0 | Core skeleton: CLI parser, exec/state registries, typed argument decoding, input methods + precedence, outputters, exit codes, Runtime, Runner, minimal Facts, provider registry, test harness, compatibility metadata (`test.echo` / `test.nop` end-to-end) |
| 1 | Salt reference tooling: AST indexer, catalog generation, coverage reporting against the pinned revision |
| 2 | Core execution modules in dependency order: cmd, file, test, status, system, user, group, shadow, pkg, service, sysctl, mount, disk, archive, cron, hosts, timezone, locale |
| 3 | Core state modules mirroring Phase 2, starting with the priority functions above |
| 4 | Broader system modules: acl, alternatives, apparmor, at, blockdev, bridge, disk, firewalld, iptables, nftables, kmod, kernel, network, parted, selinux, ssh, swap, udev, xfs, zfs, ... (scope generated from the Salt catalog, not hand-maintained) |
| 5 | State coverage expansion across relevant `salt/states/*`; prioritize local OS state over external integrations |
| 6 | Generic `statekit state single <fun>` interface (closest equivalent of Salt's `state.single`) |
| 7 | Optional ordered multi-operation `statekit apply operations.yaml` — explicitly not SLS |

## Testing strategy

- **Unit:** parsers, validation, output formatting, fact detection, provider resolution, file algorithms, argument normalization.
- **Integration:** real binary behavior in Docker containers on Debian, Ubuntu, Fedora, openSUSE, Arch, Alpine (plain containers + privileged systemd-enabled images for `service.*`).
- **VM:** systemd units, mounts, filesystems, kernel modules, network/firewall changes, SELinux/AppArmor, reboots, block devices (QEMU-based nightly suite).
- **Differential:** identical scenarios executed via `salt-call --local` and `statekit` in twin containers built from the same distro base, environment-dependent fields normalized, then comparing return data, resulting system state, `changes`, `result`, and failure behavior.

The full CI/CD design — GitHub Actions workflows (`ci.yml` PR gate, integration matrix, nightly Salt differential, QEMU VM suite), digest-pinned Docker images, fixture schema validation, a real-case scenario catalog per module family, and the phase-by-phase CI rollout — is specified in [`plans/testing.md`](plans/testing.md). Language-independent YAML fixtures are the single source of truth driving unit tests, container integration runs, and differential comparisons alike.

## Security model

StateKit performs no privilege escalation itself: no setuid binary, embedded sudo, authorization daemon, remote API, or secret service. Operations requiring elevation fail normally when unprivileged; invoke `sudo statekit ...` or use external privilege mechanisms. All subprocess execution is centralized behind a `Runner` interface (argv without shell by default, explicit shell opt-in, timeout, signal handling, sensitive-argument redaction).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | operation completed successfully |
| 1 | operation/state failed |
| 2 | invalid invocation/input |
| 3 | unsupported function/provider |
| 4 | runtime/internal failure |

Detailed subsystem errors belong in JSON/YAML output, not in an ever-growing exit-code namespace.

## References

SaltStack source (pinned revision `8b63e700637e40d76f80a00d95c60471797c73b9`, also available locally under `saltstack/`):

- Repository: <https://github.com/saltstack/salt>
- Pinned tree: <https://github.com/saltstack/salt/tree/8b63e700637e40d76f80a00d95c60471797c73b9>
- Execution modules: `saltstack/salt/modules/` — e.g. [`pkg` providers](https://github.com/saltstack/salt/tree/8b63e700637e40d76f80a00d95c60471797c73b9/salt/modules/aptpkg.py), [`systemd_service.py`](https://github.com/saltstack/salt/blob/8b63e700637e40d76f80a00d95c60471797c73b9/salt/modules/systemd_service.py), [`state.py`](https://github.com/saltstack/salt/blob/8b63e700637e40d76f80a00d95c60471797c73b9/salt/modules/state.py) (home of `state.single`)
- State modules: `saltstack/salt/states/` — e.g. [`service.py`](https://github.com/saltstack/salt/blob/8b63e700637e40d76f80a00d95c60471797c73b9/salt/states/service.py), [`pkg.py`](https://github.com/saltstack/salt/blob/8b63e700637e40d76f80a00d95c60471797c73b9/salt/states/pkg.py), [`file.py`](https://github.com/saltstack/salt/blob/8b63e700637e40d76f80a00d95c60471797c73b9/salt/states/file.py)
- System detection reference: `saltstack/salt/grains/core.py`
- Behavioral spec: `saltstack/tests/unit/`, `saltstack/tests/pytests/`

SaltStack documentation (<https://docs.saltproject.io/en/latest/>):

- [`salt-call` CLI reference](https://docs.saltproject.io/en/latest/ref/cli/salt-call.html) — `--local`, output options, return codes
- [Salt system architecture](https://docs.saltproject.io/en/latest/topics/salt_system_architecture.html)
- [Execution modules reference](https://docs.saltproject.io/en/latest/ref/modules/all/index.html)
- [State modules reference](https://docs.saltproject.io/en/latest/ref/states/all/index.html)
- [`state.single`](https://docs.saltproject.io/en/latest/ref/modules/all/salt.modules.state.html)
- [Configuration management / states topics](https://docs.saltproject.io/en/latest/topics/states/index.html)
- [Grains](https://docs.saltproject.io/en/latest/topics/grains/index.html) — reference for facts detection rules
- [Outputters](https://docs.saltproject.io/en/latest/ref/output/all/index.html)

Project planning: [`plans/init.md`](plans/init.md) (50 sections covering concept, compatibility policy, phases 0–7, definitions of done, and agent workflow rules) and [`plans/testing.md`](plans/testing.md) (GitHub Actions + Docker test system with real-case coverage).

## License

Apache License 2.0 — see [LICENSE](LICENSE). Upstream SaltStack (the vendored `saltstack/` submodule) is also Apache-2.0.
