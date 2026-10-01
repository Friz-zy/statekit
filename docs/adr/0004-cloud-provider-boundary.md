# ADR 0004: Cloud provider and vSphere transport boundary

Status: Proposed — awaiting project owner decision
Date: 2026-10-01
Reference revision: references/salt.lock (8b63e700637e40d76f80a00d95c60471797c73b9)
Workflow stages: `decision_context` + `options_analysis` (draft only)

## Context

R10 needs an explicit boundary before public Cloud/provider implementation.
The vendor CLI preference in `plans/porting.md` §2, R10 is a planning policy,
not evidence that the pinned execution modules implement those CLI contracts.
The policy names `aws`, `az`, `gcloud`, `doctl` and `govc`; this list is not
currently backed by matching pinned execution-module source for the proposed
adapters. No provider or public function set has been selected here.

The relevant evidence and constraints are:

| Evidence | Boundary implication |
|---|---|
| Pinned `salt/modules/cloud.py`, especially `_get_client` and its public delegating functions; locally `saltstack/salt/modules/cloud.py` | Public APIs delegate to `salt.cloud.CloudClient`, constructed from cloud configuration and a copy of cloud pillar data. A CLI name alone does not reproduce this contract. |
| Pinned `salt/cloud/__init__.py#CloudClient` and `Cloud.__init__`; locally `saltstack/salt/cloud/__init__.py` | CloudClient reads configuration/pillar and the cloud layer discovers provider plugins through `salt.loader.clouds`. StateKit has no Go CloudClient or Salt-cloud provider loader/registry. The existing generic fact-driven `internal/runtime/runtime.go#ProviderRegistry` for kinds such as package/service is not this cloud layer; reproducing that layer would be new scope. |
| Pinned `salt/modules/saltcloudmod.py#create`; `plans/porting.md` row `PTD-EXEC-1195` | `saltcloud.create` invokes `salt-cloud` in the source but is explicitly excluded by the existing local-only architecture classification. That exclusion remains in force; this proposal does not reverse it. |
| Pinned `salt/modules/vsphere.py`, pyVmomi imports, `esxcli_cmd`, and `_format_coredump_stdout`, `_format_firewall_stdout`, `_format_syslog_config`; locally `saltstack/salt/modules/vsphere.py` | The public API uses pyVmomi/ESXCLI. The source does not use `govc`; a govc adapter would be an intentional transport divergence, not a source-derived API. |
| `plans/porting.md`, R10.4a, R10.4b and R10.4c status/ledger rows; `modules/exec/vsphere` | Existing helpers only parse synthetic coredump/firewall/syslog text. They are private, register no public provider API, and do not constitute provider functionality. |
| `modules/exec/dnsutil/dnsutil.go` package boundary and `plans/porting.md`, R10.3b status | `dnsutil.serial` remains pending because no persistent Grains store exists. That storage decision is distinct from a Cloud provider boundary. |
| `plans/porting.md` §0 dependency/contract rules and §2 R11 decision gate; ADRs 0001, 0002 and 0003 | Preserve honest source-level exclusions and subsets, require separately scoped dependency authorization, and prefer an explicit plugin boundary over speculative core machinery. R11 defaults to a plugin boundary; it does not establish an existing Cloud plugin implementation. |

The verified base phase commits are R9.2t `3342199`, R10.1 `343e9fe`,
R10.2 `d30d3a2`, R10.3a `b09faf6`,
R10.3b `2ce0fbb`, R10.4a `61c7944`, R10.4b `d1a5126` and R10.4c
`efc4303`. Historical ledger descriptions of working-tree state do not turn
the R10.4a-c parsers into public Cloud/provider coverage.

This draft changes only this ADR. It adds no code, dependency, registry,
configuration, CI workflow or live integration. It does not claim any new
test run or external verification: `external_ci=pending_external_ci`.
The unrelated dirty `tests/live/mysql/Containerfile.go-build` is out of scope.

The user's phased migration request continues to require quality gates,
local Podman tests and configured GitHub CI, without stopping after every
completed phase. This ADR gates only the unresolved public provider boundary,
not independently authorized migration work. This documentation-only stage
does not dispatch the next phase or alter those existing gates.

## Decision scope

The unresolved scope is public `cloud` and vSphere/provider operations whose
source contracts depend on provider discovery, configuration, authentication
and remote execution. Any future adapter must map an actual pinned source
function's inputs, results, errors and side effects before registration.
The R10 vendor CLI plan does not prove a source API: matching proposed
vendor-specific execution source/catalog entries are absent in this pinned
tree. It does not authorize inventing modules from CLI product names.

Out of scope: selecting a provider, designing a plugin ABI, implementing a
CloudClient, changing classifications/catalogs/plans/CI, accepting this ADR,
reopening the local-only/master-minion exclusion, or solving persistent Grains
storage. No live calls, credential-bearing integrations, images or dependencies
are introduced, fetched or executed here.

## Decision/Status

**Recommendation, not an accepted decision:** use **C** as the default
architectural boundary, with **D** as the permissible direction for separately
authorized source-backed stateless work. Keep provider-specific CloudClient
and vSphere operations outside core, and defer public provider code until the
project owner approves scope and a reviewed contract. This chooses the
smallest reversible proposal without pretending to port CloudClient or to
implement a plugin protocol now.

**Blocking owner choice before public Cloud/provider implementation:**

- Approve the boundary/exclusions under **C/D**, explicitly identifying which
  functions are deferred versus excluded; or
- Choose a selected-provider contract (potentially **A/B** or a later adapter
  behind **C**) and specify the exact provider(s), public functions, source
  mapping, transport, credential model and test environment. This must include
  the intended read/write scope and acceptable compatibility divergences.

Neither the R10 CLI preference nor this recommendation supplies that approval.
`saltcloud.create` remains excluded under `PTD-EXEC-1195` in either branch.
Reconsidering it requires a separate explicit owner decision about the
local-only exclusion; provider selection alone does not authorize reversal.
No option automatically enables live CI or cloud access.

### Decision record and re-review

Keep this record Proposed until the project owner records the selected option,
exact scope, rationale, actual decision authority, decision date and compatibility
ceilings in an explicit amendment or superseding ADR. The individual decision
owner/approver and any expiry are not assigned by this draft. Re-review is required
before any public provider registration and when the pinned Salt revision,
provider transport/version, dependency policy, credential policy or test
environment changes. An unresolved authorization cannot become permission by
elapsed time; public provider work remains blocked pending the owner decision.
Security exceptions, if any are later requested, need their own scoped owner
and expiry record rather than an implicit ADR waiver.

## Options

All options are proposals, not approved transports. The dimension-by-dimension
analysis below uses the same criteria for A-D; the summary makes the relative
advantages and costs explicit.

| Option | Principal pros | Principal cons |
|---|---|---|
| A: in-process SDK/drivers | Could express selected provider dispatch and typed results without parsing CLI text; mock transports can pin contracts. | Largest new core/dependency and credential-handling scope; neither SDK types nor a new registry recreate Salt semantics automatically. |
| B: selected vendor CLI adapters | Fits the plan's transport preference; central Runner supports bounded offline command/result contracts. | External executable/provenance obligations; CLI authentication and output diverge from source substrates, and process isolation does not reduce remote privileges. |
| C: provider boundary outside core, no implementation now | No new runtime, credentials, dependencies or billing exposure; easiest to revise after actual requirements. | No public provider capability; future plugin contract and compatibility work remain unresolved. |
| D: bounded source-backed stateless helpers only | Allows useful offline source-contract work with existing tools and no provider access. | Parser success cannot establish connectivity, discovery, authorization or lifecycle parity; helpers may not fit the eventual transport. |

### A. In-process SDK/plugin interface with provider drivers

- **Source fidelity:** can model CloudClient configuration, provider discovery
  and dispatch, but each function's arguments, outputs, errors and lifecycle
  must be mapped to the pinned source. SDK availability is not parity evidence.
- **Dependency/quarantine:** introduces a new abstraction and likely SDK/direct
  and transitive dependencies. Requires a scoped dependency ADR, immutable
  versions, integrity/provenance and graph/license review, and the seven-day
  exact-version quarantine before fetch or execution; unverifiable age fails
  closed. Prefer already-reviewed dependencies where sufficient.
- **Credentials:** brings authentication/session handling into the process;
  requires explicit least-privilege acquisition, lifetime, redaction and
  denial of ambient host credentials. No credential values belong in fixtures.
- **Billing/blast radius:** provisioning or deletion may affect paid resources
  and data. Provider/account/environment and mutation limits must be confirmed
  before any separately authorized live use; mocks cannot verify those limits.
- **Testability:** fake SDK transports can check dispatch and result/error
  contracts offline, but cannot establish provider authorization or live parity.
- **Migration/upgrade path:** version the approved contract and driver mapping;
  isolate SDK upgrades behind reviewed fixtures and explicit compatibility
  changes. Avoid promising all providers through one premature interface.
- **Scope:** largest expansion; justified only by an owner-selected provider and
  function set. It is not authorized by this draft.

### B. Out-of-process vendor CLI adapters for selected providers

- **Source fidelity:** consistent with the plan's CLI preference but subject to
  an intentional source-compatibility ceiling. CLI arguments/output, discovery,
  authentication and errors are not assumed equivalent to CloudClient or
  pyVmomi/ESXCLI. In particular, `govc` is not the pinned vSphere substrate.
- **Dependency/quarantine:** avoids an in-process SDK but adds external binary
  and version obligations. Require immutable executable identity, provenance,
  integrity, reviewed installation/source and applicable package quarantine;
  do not auto-install tools or bypass dependency policy by calling a CLI.
- **Credentials:** use the central Runner with explicit argv/environment and
  redaction policy; prohibit uncontrolled inherited profiles, host homes and
  credential discovery. Approve the credential transport before implementation.
- **Billing/blast radius:** process isolation does not limit cloud privileges.
  Exact provider/environment, commands, endpoints and mutation permissions need
  scoped approval; never treat a CLI wrapper as safe by default.
- **Testability:** fake Runner responses permit hermetic command/result/error
  contracts; synthetic output cannot prove live API behavior or version parity.
- **Migration/upgrade path:** pin output contracts and retain per-function
  compatibility annotations. A later SDK transport needs a reviewed mapping
  and regression fixtures rather than a silent replacement.
- **Scope:** potentially narrower than A when exact providers/functions are
  selected, but not a license to implement the whole vendor CLI list.

### C. Explicit plugin boundary outside core; no provider code yet

- **Source fidelity:** honestly preserves the missing CloudClient/provider
  layer instead of substituting invented APIs. No claim of provider parity.
- **Dependency/quarantine:** adds no SDK, executable or plugin loader now.
  Any future plugin is separately reviewed and remains subject to dependency,
  provenance, quarantine and runtime policies; out-of-tree is not an exemption.
- **Credentials:** core acquires none for this proposal. A future approved
  plugin contract must specify the credential trust boundary before use.
- **Billing/blast radius:** no new provider execution or paid-resource actions.
  Future plugins still require explicit environment and mutation boundaries.
- **Testability:** review absence of public registration and preservation of
  exclusions now; later discovery/error and plugin contracts need mock tests.
- **Migration/upgrade path:** reserve a decision boundary, not a concrete ABI.
  Approve the smallest contract only after actual provider requirements exist;
  a later ADR may select A/B without migrating a speculative implementation.
- **Scope:** safest default consistent with ADR 0001's honest exclusions,
  ADR 0002's scoped dependency exceptions, ADR 0003's source/subset distinctions
  and R11's default plugin boundary. It does not blanket-exclude all R10 work.

### D. Source-backed stateless helpers only; provider APIs deferred

- **Source fidelity:** permits bounded pure helper contracts directly traceable
  to pinned source, as in R10.4a-c, without confusing them with public APIs.
- **Dependency/quarantine:** prefer standard library/existing reviewed code;
  no provider dependency or transport is needed for the existing parsers.
- **Credentials:** synthetic inputs only; no provider credential acquisition.
- **Billing/blast radius:** no network/provider execution or resource mutation
  in the helper scope. This cannot validate eventual provider safety.
- **Testability:** deterministic mock/rootless fixtures and source-oracle
  comparisons can validate parsing, bounds and errors only.
- **Migration/upgrade path:** retain helpers privately if useful to a later
  approved transport; discard them if the selected transport has a different
  contract. Every source upgrade needs contract revalidation.
- **Scope:** supports limited progress but does not solve provider discovery,
  authentication or lifecycle. Use with C, not as indefinite implied approval
  for public registration or unbounded helper work.

### Comparative recommendation

A offers the greatest potential to model the missing provider layer but also
the largest speculative scope. B reduces in-process SDK coupling, not provider
authority or the need for a source mapping. C/D preserve honest coverage and
reversibility while requirements are unresolved. Recommend C with only bounded,
separately authorized D helper work now; source-backed public adapters remain
conditional on a selected provider contract. No AWS, Azure, GCP or other
provider is selected, and no existing plugin capability is implied.

## Consequences

- The recommended C/D boundary avoids new core abstractions and dependencies
  while leaving a reviewed A/B path open. Its deliberate ceiling is no public
  Cloud/provider functionality; upgrading requires the blocking owner choice
  and a scoped contract rather than exposing existing parsers.
- Public Cloud/provider coverage remains unchanged. R10.4a-c private parser
  work earns no public registration or provider coverage increment. This draft
  does not regenerate catalogs or change family/function classifications.
- The current R10 report remains the Slack/dig/dnsutil subset, not the entire
  Cloud/provider plan: `round: R10.3b`, 25 registered public functions,
  1 pending public function and 7 dig aliases, as recorded in
  `plans/porting.md` R10.4c status and the R10 report generator
  `tests/differential/r10_test.go`. These are scoped totals, not all-provider
  coverage or a new verification result.
- Deferred provider functions must not be relabeled implemented or silently
  converted to terminal exclusions. Future classification changes must cite
  the owner-approved per-function scope; `saltcloud.create` stays excluded.
- `dnsutil.serial` remains independently pending on persistent Grains storage.
  Choosing a Cloud transport cannot close that dependency.
- Deferral leaves a capability gap for callers needing actual provider
  operations. The tradeoff is explicit rather than hidden behind partial CLI
  wrappers or private helper tests.
- **Rollback/reversibility:** this documentation-only proposal can be amended
  or superseded without runtime migration. Existing private parsers can remain
  untouched. For a future A/B implementation, require an opt-in registration
  boundary and a disable/unregister path before release. Disabling code does
  not undo remote mutations or charges: any live mutation proposal needs an
  explicit resource/data recovery and cleanup plan before authorization.

## Security/Testing

No live cloud actions, credentials, billing resources, DNS operations or GitHub
CI runs are authorized or performed by this draft. The existing R10 gate is
configured for rootless offline contract-only execution (see
`plans/testing.md`, R10 `dig-contract` section); no local test is run for this
ADR, and `external_ci=pending_external_ci`. This does not characterize unrelated
service gates as offline. The plan's opt-in live
smoke description is not current authorization, and mock success must not be
reported as live-provider validation.

Future execution requires a fail-closed runtime preflight verifying rootless/
non-root isolation, denied network by default, no host credentials/home,
runtime sockets or privileged devices/mounts, appropriate read-only mounts,
dropped capabilities and no-new-privileges. Human approval never substitutes
for that preflight. Dependency fetch, if later approved, must be separate from
execution with reviewed allowlisted egress. Scoped live/cloud, credential,
billing or permission expansion requires independent security review and
explicit human authorization; no secrets enter logs, fixtures or ADR records.

Draft acceptance checks (documentation review, not executed provider tests):

- All A-D options address fidelity, dependencies/quarantine, credentials,
  billing/blast radius, testability, migration and scope.
- Status stays Proposed; the owner choice is explicit; no public API or vendor
  CLI mapping is invented and `PTD-EXEC-1195` remains excluded.
- Pinned paths and plan rows distinguish private parser evidence, provider
  deferral, the separate Grains gap and pending external CI.
- Only this ADR is added; no code, catalogs, workflows, dependencies or
  unrelated dirty files are changed.

## Follow-ups

These are conditional handoff actions, not dispatched work or implementation
approval. No generated agent ID is assigned in this draft.

| Executor role / seniority | Action and review criterion |
|---|---|
| Project owner / decision authority (not an implementation seniority assignment) | Record C/D boundary approval with explicit deferrals/exclusions, or choose exact provider(s), functions, transport, credential model and test environment for a selected-provider contract. Do not reverse `saltcloud.create` without a separate explicit decision. |
| solution-architect-lead / lead | After that choice, amend or supersede this ADR with the actual decision record, re-review conditions and source-to-contract mapping, including compatibility ceilings and rollback. Reconcile the R10 CLI preference with the selected substrate; do not invent provider signatures or approval/expiry details. |
| backend-engineer-senior / senior | Only after approved scope/contract, map selected pinned functions to bounded mock fixtures for arguments, result/error shapes and registration behavior; preserve private-helper/public-provider separation. Implementation requires a subsequent authorized phase. |
| security-architect-lead / lead | Before any expanded trust boundary, independently review dependency/executable provenance, quarantine, credential transport/redaction, endpoint validation, mutation blast radius and recovery; identify human gates and fail-closed runtime controls separately. |
| devops-platform-engineer-lead / lead | For an authorized later phase, reuse existing local Podman/offline CI gates where sufficient and verify fail-closed runtime preflight. Any required protected CI change needs separate scoped human authorization and independent security review. Keep external CI pending until separately evidenced; do not trigger GitHub Actions or enable live CI, provider credentials or paid resources from this ADR. |
