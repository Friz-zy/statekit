# StateKit Implementation Plan

## 1. Project Definition

**StateKit** is a portable standalone Go binary implementing the useful local functionality of SaltStack in a form similar to `salt-call --local` / `state.single`, but without Salt infrastructure and complex runtime concepts.

Primary goal:

> Provide SaltStack execution modules and state modules as a portable local CLI with compatible behavior, arguments, results, and edge cases.

StateKit should be usable by copying a single binary to a machine:

```bash
scp statekit host:/tmp/
ssh host sudo /tmp/statekit state pkg.installed --name curl
```

No installation, daemon, Python runtime, master, minion, or configuration-management server should be required.

SaltStack is the primary reference implementation for:

* available modules;
* available functions;
* arguments;
* default values;
* return values;
* state results;
* platform-specific behavior;
* edge cases;
* tests;
* provider selection;
* system detection.

StateKit should copy **observable Salt behavior**, not Salt's internal architecture.

---

# 2. Conceptual Model

StateKit consists of three major layers:

```text
                    StateKit
                       │
          ┌────────────┴────────────┐
          │                         │
     Execution API              State API
          │                         │
          │                 desired-state logic
          │                         │
          └────────────┬────────────┘
                       │
                    Modules
                       │
                   Providers
                       │
                  Local system
```

Examples:

```bash
# Execution function
statekit exec service.restart --name nginx

# State function
statekit state service.running --name nginx
```

State functions should normally consume execution functions rather than duplicating low-level host manipulation.

Conceptually:

```text
service.running
       │
       ├── service.status
       └── service.start
                │
                ▼
          ServiceProvider
                │
              systemd
```

---

# 3. Relationship to SaltStack

The closest Salt equivalent is:

```text
salt-call --local
+
state.single
+
execution modules
+
state modules
+
only the minimum system detection required by those modules
```

StateKit intentionally removes the rest.

## Use from SaltStack

```text
salt/modules/*
salt/states/*
salt/utils/*
salt/grains/*      only as reference for required system detection
tests/*
```

## Do not reproduce

```text
salt-master
salt-minion daemon
transport
authentication protocol
event bus
job system
targeting
returners
reactor
beacons
runners
wheel
pillar
fileserver
SLS/highstate orchestration
renderer system
Jinja
scheduler
Salt configuration hierarchy
proxy minions
Salt Cloud
```

---

# 4. Design Principle

Do not create a new configuration-management language.

StateKit should operate on individual execution functions or states.

Examples:

```bash
statekit exec file.remove --path /tmp/foo

statekit state file.managed \
  --name /etc/example.conf \
  --source /tmp/example.conf

statekit state pkg.installed --name curl

statekit state service.running \
  --name nginx \
  --enable true
```

Structured invocation must provide exactly the same functionality.

---

# 5. CLI Structure

Canonical CLI:

```text
statekit exec <module>.<function>
statekit state <module>.<function>
```

Examples:

```bash
statekit exec pkg.version --name curl
statekit exec service.restart --name nginx

statekit state pkg.installed --name curl
statekit state service.running --name nginx
```

Optional shortcuts may later allow:

```bash
statekit pkg.version ...
statekit service.running ...
```

but explicit `exec` and `state` namespaces should remain canonical because identical module names exist in both APIs.

---

# 6. Input Methods

Every function must support the same input through:

1. CLI flags
2. inline YAML/JSON
3. YAML/JSON file
4. stdin

### Flags

```bash
statekit state pkg.installed \
  --name curl \
  --version 8.14.1
```

### Inline JSON

```bash
statekit state pkg.installed \
  --config '{"name":"curl","version":"8.14.1"}'
```

### Inline YAML

```bash
statekit state pkg.installed --config '
name: curl
version: 8.14.1
'
```

### File

```bash
statekit state pkg.installed --file request.yaml
```

### stdin

```bash
cat request.yaml | statekit state pkg.installed --stdin
```

or:

```bash
cat request.yaml | statekit state pkg.installed -
```

All methods must resolve into the same typed internal request.

---

# 7. Input Precedence

Use:

```text
function defaults
        ↓
file / stdin / --config
        ↓
explicit CLI arguments
```

Example:

```bash
statekit state pkg.installed \
  --file package.yaml \
  --version 8.14.1
```

CLI arguments override structured configuration.

Reject ambiguous combinations such as:

```text
--stdin + --file
--stdin + --config
```

unless an explicit merge mechanism is introduced later.

---

# 8. Output

Support:

```bash
--output json
--output yaml
--output text
```

Short form:

```bash
-o json
-o yaml
-o text
```

Machine-readable output should be treated as the stable API.

---

# 9. Salt-Compatible State Result

Preserve the core Salt state result:

```yaml
name: nginx
result: true
changes:
  service:
    old: stopped
    new: running
comment: Service nginx was started
```

Core fields:

```text
name
result
changes
comment
```

`result` must support three values:

```text
true    state successfully reached
false   operation failed
null    test mode; changes would be required
```

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

Do not replace Salt's `changes` with merely:

```json
{"changed": true}
```

`changes` is substantially more useful.

A derived `changed` value may optionally be exposed:

```text
changed = len(changes) > 0
```

---

# 10. Extended Metadata

StateKit may add metadata without changing the Salt-compatible core:

```yaml
name: nginx
result: true
changes:
  service:
    old: stopped
    new: running
comment: Service nginx was started

meta:
  type: state
  module: service
  function: running
  provider: systemd
  duration_ms: 23
```

Metadata should remain optional.

---

# 11. Execution Module Results

Execution modules should preserve the natural result type of the corresponding Salt function.

Examples may be:

```text
bool
string
integer
list
map
structured object
```

Example:

```bash
statekit exec pkg.version --name curl -o yaml
```

```yaml
curl: 8.14.1
```

Avoid forcing all execution functions into an artificial common result structure.

Errors and optional StateKit metadata may be wrapped separately when machine API consistency requires it.

---

# 12. Test / Dry-Run Mode

State functions must support:

```bash
statekit state pkg.installed --name curl --test
```

Equivalent structured configuration:

```yaml
test: true
```

If the desired state is already satisfied:

```yaml
name: curl
result: true
changes: {}
comment: Package curl is already installed
```

If a modification would be required:

```yaml
name: curl
result: null
changes:
  curl:
    old: ""
    new: latest
comment: Package curl would be installed
```

No modifications may occur in test mode.

Test-mode behavior should follow Salt as closely as practical.

---

# 13. Internal Runtime

Do not reproduce Salt global runtime variables such as:

```text
__salt__
__states__
__grains__
__opts__
__pillar__
__context__
```

Replace them with an explicit runtime object:

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

State functions can therefore perform:

```go
runtime.Exec.Call("pkg.version", ...)
runtime.Exec.Call("pkg.install", ...)
```

rather than using Salt's dynamic `__salt__` dictionary.

---

# 14. Minimal System Detection

Do not expose a full Salt grains subsystem.

StateKit only needs enough host information to:

* choose implementations;
* implement compatible module behavior;
* expose useful local inspection data.

Call this subsystem:

```text
facts
```

not `grains`.

Example internal facts:

```text
OS
OS family
OS version
kernel
architecture
hostname
UID/GID
init system
package manager
filesystem information
network interfaces
SELinux/AppArmor status
virtualization where required
```

Example:

```go
type Facts struct {
    OS          OSFacts
    Kernel      KernelFacts
    CPU         CPUFacts
    Host        HostFacts
    Init        InitFacts
    Package     PackageFacts
    Security    SecurityFacts
}
```

---

# 15. Facts Rules

Facts should be:

```text
read-only
local
automatically detected
typed internally
lazy where useful
cached only for process lifetime
```

Do not implement:

```text
custom grains files
persistent grains
grains targeting
grain configuration
grains sync
remote grains
```

Salt grains source code may nevertheless be used as the reference for detecting obscure systems correctly.

---

# 16. Providers

Preserve Salt's useful idea of virtual system modules.

Example:

```text
pkg
 │
 ├── apt
 ├── dnf
 ├── zypper
 ├── pacman
 └── apk
```

Interface:

```go
type PackageProvider interface {
    Install(...)
    Remove(...)
    Upgrade(...)
    Version(...)
    List(...)
    Latest(...)
}
```

Provider selection:

```text
minimal facts
    ↓
provider resolver
    ↓
package implementation
```

Similar abstractions:

```text
service
pkg
user
group
shadow
sysctl
firewall
network
mount
```

---

# 17. Module Layout

Recommended repository structure:

```text
statekit/
├── cmd/
│   └── statekit/
│
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
│
├── modules/
│   ├── exec/
│   │   ├── file/
│   │   ├── pkg/
│   │   ├── service/
│   │   ├── user/
│   │   └── ...
│   │
│   └── state/
│       ├── file/
│       ├── pkg/
│       ├── service/
│       ├── user/
│       └── ...
│
├── providers/
│   ├── pkg/
│   ├── service/
│   ├── user/
│   └── ...
│
├── tests/
│   ├── compatibility/
│   ├── integration/
│   ├── fixtures/
│   └── images/
│
├── tools/
│   └── salt-reference/
│
├── docs/
│   └── compatibility/
│
└── go.mod
```

---

# 18. Execution Registry

Execution functions should be registered explicitly.

Conceptual API:

```go
type ExecFunction interface {
    Name() string
    Execute(context.Context, *Runtime, any) (any, error)
}
```

Example names:

```text
file.remove
file.replace
pkg.install
pkg.version
service.start
service.restart
user.info
cmd.run
```

---

# 19. State Registry

State functions:

```go
type StateFunction interface {
    Name() string
    Apply(context.Context, *Runtime, any) StateResult
}
```

Examples:

```text
file.managed
file.directory
file.absent

pkg.installed
pkg.removed
pkg.latest

service.running
service.dead

user.present
user.absent

group.present
group.absent
```

State functions should use execution functions wherever Salt does conceptually equivalent work.

---

# 20. Salt Reference Repository

Build an automated source indexer under:

```text
tools/salt-reference/
```

It should scan a pinned SaltStack source revision and produce a machine-readable catalog.

Inputs:

```text
salt/modules/
salt/states/
salt/utils/
salt/grains/
tests/
```

Generated catalog:

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

parameters:
  - name
  - enable
  - sig
  - init_delay

tests:
  - ...
```

Agents must use this inventory instead of implementing functions from memory.

---

# 21. Pin Salt Versions

Salt must not be treated as an unspecified moving target.

Maintain:

```text
SALT_REFERENCE_VERSION
```

or:

```text
SALT_REFERENCE_COMMIT
```

For example:

```text
references/salt.lock
```

containing:

```yaml
repository: https://github.com/saltstack/salt
commit: <commit>
version: <release>
```

Every compatibility decision should refer to this revision.

Upgrading the Salt reference becomes an explicit project operation.

---

# 22. Compatibility Categories

Each Salt function should be classified as:

```text
COMPATIBLE
PARTIAL
INTENTIONAL_DIVERGENCE
UNSUPPORTED
NOT_APPLICABLE
```

Arguments:

```text
KEEP
RENAME
GENERALIZE
DROP
DEFER
```

Salt-specific arguments such as:

```text
saltenv
pillar
template
source_hash_name
__env__
```

must not automatically drag Salt infrastructure into StateKit.

Each must be individually evaluated.

---

# 23. Compatibility Manifest

Maintain:

```text
docs/compatibility/
```

Example:

```yaml
kind: state
operation: file.managed

reference:
  module: salt.states.file
  function: managed
  revision: <salt commit>

status: partial

supported:
  - name
  - user
  - group
  - mode
  - contents

unsupported:
  - salt:// source
  - saltenv

differences:
  - remote Salt fileserver sources are not supported

tests:
  referenced: 74
  ported: 61
  excluded: 13
```

Keep manifests machine-readable and concise.

---

# 24. Salt Tests as Specification

Salt tests are a primary behavioral reference.

Do not mechanically convert Python code to Go.

For each relevant Salt test:

```text
read test
   ↓
determine observable contract
   ↓
represent scenario
   ↓
implement StateKit test
```

Avoid reproducing tests of Salt internals such as:

```text
loader mocks
__salt__ dictionary behavior
minion configuration
event system
```

Test externally observable semantics.

---

# 25. Compatibility Fixture Format

Use language-independent YAML fixtures where practical.

Example:

```yaml
id: service.running.start-stopped-service

type: state

request:
  function: service.running
  arguments:
    name: nginx

before:
  service:
    nginx:
      running: false
      enabled: true

expected:
  result: true

  changes:
    nginx:
      old: stopped
      new: running
```

Fixtures can drive:

```text
Go integration tests
StateKit CLI tests
Salt differential tests
```

---

# 26. Differential Salt Testing

Where practical, run identical scenarios against:

```text
Salt reference container/VM
StateKit container/VM
```

Process:

```text
prepare A
prepare B

Salt:
    salt-call --local ...

StateKit:
    statekit ...

normalize environment-dependent fields

compare:
    return data
    resulting system state
    changes
    result
    failure behavior
```

This is particularly useful for poorly documented edge cases.

---

# 27. Test Layers

## Unit tests

Test:

```text
parsers
validation
result formatting
fact detection
provider resolution
file manipulation algorithms
argument normalization
```

## Integration tests

Test actual binary behavior on real OS environments.

Initial matrix:

```text
Debian
Ubuntu
Fedora
openSUSE
Arch
Alpine
```

## VM tests

Use VMs rather than containers for:

```text
systemd
mounts
filesystems
kernel modules
network changes
firewall
SELinux/AppArmor
reboots
block devices
```

## Differential tests

Compare StateKit against the pinned Salt release.

---

# 28. Salt Bugs

Do not automatically reproduce Salt bugs.

When behavior appears incorrect:

```text
1. reproduce it
2. inspect Salt tests
3. inspect Salt source
4. inspect relevant Salt issue/fix if necessary
5. classify it
```

Classification:

```text
Salt-compatible
Salt bug intentionally fixed
undefined Salt behavior
platform-specific behavior
StateKit intentional divergence
```

Record the decision in compatibility metadata.

---

# 29. Phase 0 — Core Architecture

Implement before module migration:

```text
CLI parser
exec registry
state registry
typed argument decoding
CLI flag mapping
YAML parsing
JSON parsing
stdin
--config
--file
outputters
exit codes
Runtime
Runner
minimal Facts
provider registry
test harness
Salt compatibility metadata
```

Acceptance examples:

```bash
statekit version

statekit exec --list
statekit state --list

statekit facts

statekit exec test.echo --text hello
statekit state test.nop --name example
```

---

# 30. Phase 1 — Salt Reference Tooling

Build source-analysis tooling before broad migration.

Generate inventories of:

```text
execution modules
state modules
functions
arguments
defaults
function dependencies
utility dependencies
platform restrictions
tests
```

Generate migration coverage:

```text
Salt functions:       1234
Relevant functions:    680
Implemented:            53
Partial:                18
Unsupported:           609
```

Exact numbers are generated from the pinned Salt revision.

---

# 31. Phase 2 — Core Execution Modules

Implement foundation modules required by many states:

```text
cmd
file
test
status
system
user
group
shadow
pkg
service
sysctl
mount
disk
archive
cron
hosts
timezone
locale
```

Prioritize dependency order rather than alphabetic migration.

---

# 32. Phase 3 — Core State Modules

Implement corresponding state modules:

```text
file
pkg
service
user
group
sysctl
mount
cron
host
timezone
locale
archive
cmd
```

Important first state functions:

```text
file.managed
file.directory
file.absent
file.symlink

pkg.installed
pkg.removed
pkg.latest

service.running
service.dead
service.enabled
service.disabled

user.present
user.absent

group.present
group.absent
```

---

# 33. Phase 4 — Broader System Modules

Migrate additional host-management functionality:

```text
acl
alternatives
apparmor
at
blockdev
bridge
cp
disk
environment
firewalld
iptables
nftables
kmod
kernel
network
parted
rsync
selinux
ssh
swap
system
timezone
udev
xfs
zfs
```

Actual migration scope must be generated from the Salt reference catalog rather than maintained manually.

---

# 34. Phase 5 — State Coverage Expansion

Continue through relevant:

```text
salt/states/*
```

For every state determine whether it represents:

```text
local OS state
external service integration
Salt infrastructure
orchestration
```

Prioritize local OS state.

Avoid importing integrations merely because Salt contains them.

---

# 35. Phase 6 — `state.single`-Style Generic Invocation

Implement a generic operation interface:

```bash
statekit state single service.running \
  --name nginx \
  --enable true
```

Potentially also:

```bash
statekit state single \
  --config '
fun: service.running
name: nginx
enable: true
'
```

This becomes the closest StateKit equivalent to Salt's `state.single`.

Normal direct form remains simpler:

```bash
statekit state service.running --name nginx
```

---

# 36. Phase 7 — Multiple Local Operations

Only after single-operation APIs stabilize, optionally support:

```yaml
operations:
  - state: pkg.installed
    args:
      name: nginx

  - state: file.managed
    args:
      name: /etc/nginx/nginx.conf
      source: /tmp/nginx.conf

  - state: service.running
    args:
      name: nginx
```

Invocation:

```bash
statekit apply operations.yaml
```

This is explicitly **not an SLS implementation**.

Initial semantics:

```text
ordered
sequential
stop/continue policy explicit
no requisites
no dependency graph
no Jinja
no highstate
```

Do not allow this feature to dominate the core project.

---

# 37. Command Runner

Centralize all subprocess execution:

```go
type Runner interface {
    Run(context.Context, Command) CommandResult
}
```

Required functionality:

```text
argv without shell by default
stdin
stdout
stderr
environment
working directory
timeout
signal handling
exit status
sensitive argument redaction
```

Shell execution must be explicit.

This subsystem replaces repeated Python subprocess logic across Salt modules.

---

# 38. Filesystem Layer

Provide a filesystem abstraction for:

```text
testing
atomic replacement
permissions
ownership
symlinks
hardlinks
xattrs
ACL integration
```

Avoid introducing an abstraction so large that it hides normal Go filesystem APIs.

Use it where it materially improves compatibility testing.

---

# 39. Security Model

StateKit itself performs no privilege escalation.

No:

```text
setuid StateKit
embedded sudo
authorization daemon
remote API
secret service
```

Operations requiring elevated privileges fail normally.

Users can invoke:

```bash
sudo statekit ...
```

or configure external privilege mechanisms.

---

# 40. Exit Codes

Keep CLI exit status simple and stable.

Suggested:

```text
0  operation completed successfully
1  operation/state failed
2  invalid invocation/input
3  unsupported function/provider
4  runtime/internal failure
```

Detailed subsystem errors belong in JSON/YAML output rather than an ever-growing exit-code namespace.

---

# 41. Generated CLI

Function metadata should generate:

```text
CLI flags
help
argument documentation
JSON Schema
YAML/JSON validation
shell completion
compatibility tables
```

Avoid maintaining multiple representations of the same function signature manually.

Example definition:

```go
type InstalledArgs struct {
    Name    string `statekit:"required"`
    Version string
    Refresh bool
}
```

---

# 42. Source Traceability

Every migrated function should be traceable to its Salt origin.

Prefer generated metadata rather than code comments everywhere.

Example:

```yaml
statekit: pkg.installed

salt:
  source: salt/states/pkg.py
  symbol: installed
  revision: abcdef1234
```

Tests should also retain source-test references.

This makes later Salt upgrades manageable.

---

# 43. AI Agent Workflow

Every implementation agent follows this workflow.

## A. Select function

Take work from generated migration inventory.

Example:

```text
salt.states.service.running
```

## B. Research Salt

Inspect:

```text
state implementation
called execution functions
provider implementations
Salt utilities
tests
documentation
```

Do not implement from documentation alone.

## C. Extract contract

Record only:

```text
inputs
defaults
output
changes semantics
test behavior
side effects
platform differences
edge cases
dependencies
Salt-only concepts
```

Avoid long architecture prose.

## D. Port behavioral tests

Create StateKit tests/fixtures before or alongside implementation.

## E. Implement Go

Use existing:

```text
Runtime
Exec registry
State registry
providers
facts
Runner
result types
```

Do not create module-specific infrastructure unless genuinely necessary.

## F. Differential test

Compare against the pinned Salt implementation where feasible.

## G. Update coverage

Update generated/machine-readable compatibility status.

---

# 44. Agent Output Requirements

Agent completion report should contain only:

```text
Implemented
Tests
Salt compatibility differences
Unsupported cases
```

No multi-thousand-line implementation report.

The repository itself is the detailed source of truth.

---

# 45. Agent Restrictions

Agents must not:

```text
rewrite Salt architecture in Go
invent new state semantics unnecessarily
introduce orchestration
implement master/minion concepts
introduce grains as a user-facing dependency
introduce Pillar
introduce SLS
introduce Jinja
silently alter Salt defaults
silently drop edge cases
use Python at StateKit runtime
duplicate provider logic across state and execution layers
```

Agents may improve Salt behavior only when the divergence is explicitly tested and documented.

---

# 46. Parallel Development

Freeze these APIs first:

```text
Runtime
ExecFunction
StateFunction
StateResult
Runner
Facts
ProviderRegistry
argument decoding
output API
test fixture format
```

Then parallelize:

```text
Agent A  Salt indexer
Agent B  CLI/runtime
Agent C  facts/providers
Agent D  file exec/state
Agent E  pkg exec/state
Agent F  service exec/state
Agent G  user/group exec/state
Agent H  integration infrastructure
Agent I  compatibility/differential testing
```

---

# 47. Definition of Done — Execution Function

```text
[ ] Salt source inspected
[ ] Salt providers inspected where applicable
[ ] Salt tests inspected
[ ] function signature represented
[ ] Salt defaults represented
[ ] CLI flags supported
[ ] YAML input supported
[ ] JSON input supported
[ ] stdin supported
[ ] JSON output supported
[ ] YAML output supported
[ ] unit tests implemented
[ ] integration tests implemented where needed
[ ] key Salt edge cases covered
[ ] divergences documented
[ ] compatibility index updated
```

---

# 48. Definition of Done — State Function

Everything required for an execution function where applicable, plus:

```text
[ ] desired-state detection implemented
[ ] no-op behavior tested
[ ] change behavior tested
[ ] failure behavior tested
[ ] result=true semantics tested
[ ] result=false semantics tested
[ ] result=null semantics tested
[ ] test mode causes no mutation
[ ] changes structure verified
[ ] comment behavior verified
[ ] required execution functions reused
[ ] final state verified where Salt does so
```

---

# 49. MVP

The first useful release should provide:

### Execution

```text
cmd.*
file.*
pkg.*
service.*
user.*
group.*
sysctl.*
mount.*
archive.*
cron.*
status.*
```

### State

```text
cmd.*
file.*
pkg.*
service.*
user.*
group.*
sysctl.*
mount.*
archive.*
cron.*
```

### Platform support

Initially target Linux:

```text
Debian / Ubuntu
Fedora / RHEL-like
openSUSE
Arch
Alpine
```

### Providers

```text
APT
DNF
Zypper
Pacman
APK

systemd
OpenRC
```

Other platforms should be added incrementally based on Salt implementations.

---

# 50. Long-Term Goal

StateKit should evolve toward:

```text
                 statekit
                    │
       ┌────────────┴────────────┐
       │                         │
   execution                   state
    modules                   modules
       │                         │
       └────────────┬────────────┘
                    │
                providers
                    │
                  OS/API
```

with enough Salt-derived functionality that a user can perform:

```bash
statekit exec <almost-any-useful-local-Salt-function>

statekit state <almost-any-useful-local-Salt-state>
```

without installing Salt.

The defining boundary is:

> **StateKit is essentially portable `salt-call --local` plus `state.single`, implemented as a standalone Go binary, while deliberately excluding Salt's distributed runtime, configuration infrastructure, and orchestration complexity.**

SaltStack remains the canonical behavioral reference for functions, arguments, results, edge cases, platform handling, and tests unless StateKit explicitly documents a divergence.
