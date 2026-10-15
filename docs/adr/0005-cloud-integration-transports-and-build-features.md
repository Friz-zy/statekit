# ADR 0005: External-service transports and optional Go SDK build features

Status: Accepted — policy only; the R10 research/evaluation cohort is
fixed by user direction (2026-10-13) and listed in `plans/porting.md`.
As accepted on 2026-10-13, this base policy selected no implementation
provider, API operation, SDK package/version or support commitment and
authorized no dependency, credential or live access. The 2026-10-14
amendment authorizes one bounded exception — the six-provider HTTP
machine-metadata subset defined there; no broad provider support commitment
is made, and as of 2026-10-14 no code for it was implemented yet (see
[Amendment 2026-10-14](#amendment-2026-10-14-narrow-http-machine-metadata-exception));
the Go-SDK default is retained for every other external service.
Status addendum (2026-10-15): the six-provider HTTP machine-metadata subset
is now IMPLEMENTED and offline-validated as recorded in `plans/testing.md` —
security source review complete after remediations, and build tags
implemented as specified (no longer merely proposed). Every other
authorization boundary is unchanged: no SDK dependencies, no credentials,
and no live provider validation performed or implied; deferred providers
and future capabilities remain NOT IMPLEMENTED; metadata results remain
unverified provider claims. This addendum records the position as of
2026-10-15 and supersedes the dated 2026-10-14 not-implemented and
no-test-result statements above; all earlier text is retained unchanged as
history.
Date: 2026-10-13 (decision recorded)
Decision authority: project owner, explicit approval supplied in the active
user request; individual identity or title is not recorded or invented
Authorization (2026-10-13, base record): author this ADR plus narrow edits
to `docs/adr/0004-cloud-provider-boundary.md`, `plans/porting.md` and
`plans/testing.md` only; no Go code, dependencies, builds, tests, credentials
or live cloud/CI operations. The subsequent active user request (2026-10-14)
authorizes code implementation only for the bounded native HTTP
machine-metadata subset in the amendment below, subject to the unchanged
runtime-preflight, security and test gates; it authorizes no cloud SDK
dependency, credential use, live metadata/cloud API call or gate bypass.
As of 2026-10-14 no build or test result existed or was claimed by this
record; the 2026-10-15 status addendum above records the current
implemented and offline-validated state.
Reference revision: references/salt.lock (8b63e700637e40d76f80a00d95c60471797c73b9)
Workflow stage: `documentation_edits` (`decision_record` gate passed)
Supersedes: the ADR-0004 project-wide external-CLI transport default and its
mandatory per-migration ADR gate (see
[Superseded ADR-0004 sections](#superseded-adr-0004-sections))

## Context

[ADR 0004](0004-cloud-provider-boundary.md) accepted a project-wide external
CLI default for external services (2026-10-01) and required a separately
approved ADR for every CLI-to-Go-library migration. Completed lead review
(solution architect lead, tech lead, security lead, DevOps lead) confirmed
that the active planning policy now conflicts with the owner's current
direction: `plans/porting.md` §0 banned new Go module dependencies, §2 R10
planned vendor CLI wrappers first, §4 carried a wrapper-first risk mitigation
and §5 required zero new Go module dependencies at completion. Those active
sections are updated in the same documentation pass; ADR-0004's historical
text is preserved and annotated with a supersession notice, not rewritten.

This record accepts the replacement policy. As of the base 2026-10-13
policy, acceptance is a policy decision only: it is not implementation
approval, it selects no provider, operation, SDK or dependency version, and
it does not claim that any supported SDK integration or build tag exists
today. Separately, on 2026-10-13 the user fixed the R10 evaluation cohort
for research scope only; it is listed in `plans/porting.md` and makes those
names candidates for research and evaluation, not support or implementation
selections. All other provider and tool names appearing in plans or in this
record remain candidates or examples, not selections. The sole carve-out is
the six-provider HTTP machine-metadata subset in
[Amendment 2026-10-14](#amendment-2026-10-14-narrow-http-machine-metadata-exception)
— the current authorized implementation scope, whose code is not implemented
yet; beyond that subset, no broad provider support, SDK package/version or
other API-operation approval exists.

## Evidence and constraints

| Input | Consequence for this policy |
|---|---|
| Solution architect lead and tech lead review | ADR-0004's global CLI default and the R10 CLI-first, §0 dependency ban, §4 wrapper-first and §5 zero-dependency statements are the conflicting active policy to update. Historical round logs, ledgers, append-only evidence, coverage stats and unrelated dirty content stay untouched. R10 public counts (R10.3b: 25 registered / 1 pending / 7 aliases; 15 canonical + 7 dig aliases) are not altered. |
| Security lead review | Effective machine/key/provider IAM permissions are an outer ceiling, never StateKit's complete application authorization. Fixed method/resource mapping, identity/target scope, secret redaction and sensitive-read handling, bounded response/pagination/timeouts/retries, endpoint constraints, object destination/integrity and no dangerous-operation dispatch are required and must be reviewed before any implementation. |
| DevOps lead review | Native Go build constraints are preferred. The default (no tags) build includes approved and implemented SDK integrations; one negative tag per integration plus one aggregate tag. Exclusion removes imports/implementation/registration while retaining local CLI/core, but does not remove module manifests and does not guarantee offline builds or size reduction. Compile-matrix acceptance only; no validation executed for this record. |
| Official Go documentation (`cmd/go` build constraints; `cmd/go` compile packages and dependencies; Go modules reference, `go mod tidy`) | Boolean build constraints combined with `-tags` are the standard native compile-time opt-out mechanism. Module manifests and dependency metadata are managed by the module graph and `go mod tidy`; build tags do not remove `go.mod`/`go.sum` entries, caches or dependency resolution from the module graph. |
| SDK vendor documentation | Cloud SDKs are distributed as vendor per-service libraries; no package-size study exists. No binary-size effect is claimed, and none is measured by this record. |

## Decision

The owner approves the following policy, effective 2026-10-13. It replaces
ADR-0004's accepted transport policy; it does not waive scoped implementation,
dependency, security, compatibility, human or runtime-preflight gates.

1. **Local CLI, narrow and dual-condition.** An external CLI is retained only
   for a service that (a) is already running on the StateKit execution host
   and (b) whose CLI is naturally expected there. Both conditions are
   required; CLI presence or `PATH` discovery alone does not prove a local
   target. There is no remote CLI fallback and no automatic CLI installation.
2. **Official Go SDKs elsewhere.** All other external-service integrations use
   a Go SDK, preferring official, maintained SDKs. If no acceptable official
   SDK exists, the integration is deferred pending an explicit exception
   decision; there is no silent fallback to a CLI and no invented generic
   arbitrary HTTP client. No provider or operation is selected or implemented
   solely by this policy.
3. **Cloud operations: approved reads only.** In-scope cloud provider
   operations are read-only facts, secret/parameter reads, object/file reads
   and similar approved reads, behind fixed method/resource contracts.
   Effective machine, key and provider IAM permissions are an outer ceiling,
   not StateKit's complete application authorization. Arbitrary SDK dispatch,
   writes/mutations, provisioning, IAM mutation and Salt Cloud VM/minion
   creation are out of scope; Terraform/Pulumi own provisioning.
4. **Optional SDK build features: default on, negative-tagged off.** In
   normal builds, approved and implemented optional Go SDK integration
   features are enabled by default; enabling is not auto-run and does not
   activate any network operation by itself. Native Go build tags must permit
   per-integration compile-time opt-out and one aggregate tag disabling all
   optional SDK integrations, expressed as negative opt-out constraints. The
   illustrative names `statekit_no_sdk_X` (per integration) and
   `statekit_no_sdks` (aggregate) are policy proposals pending
   implementation, not existing tags. SDK-specific imports, code and
   registration are gated together behind the same constraints.
   Aggregate-disabled builds preserve essential core and eligible local CLI
   features. Compile exclusion of a feature's SDK package from the selected
   import graph is guaranteed only when every retained import edge to that
   package is removed; while any retained feature still imports the same
   shared SDK package or dependency, that package/dependency remains linked.
   Exclusion is therefore verified per feature — never claimed as universal
   absence of every SDK package — using the same tags combined with Go
   package/dependency graph inspection (for example `go list`) and
   registration checks. Build tags do not remove `go.mod`/`go.sum` entries,
   caches, dependency metadata or module-graph network resolution, and no
   binary-size reduction is guaranteed; any size effect must be measured
   later, like-for-like. No binary-size number is measured by this record.
5. **Authority and limits.** This policy is accepted on the user's active
   direction, recorded here without inventing any personal identity or title.
   It does not waive scoped implementation, dependency, security,
   compatibility, human or runtime-preflight gates, and it does not authorize
   provider selection, dependency acquisition, credential use or live access.

## Amendment 2026-10-14: narrow HTTP machine-metadata exception

Recorded by explicit user direction (2026-10-14; original instruction in
Russian): where machine metadata is available over HTTP, collect it through
native Go standard-library HTTP clients rather than a cloud SDK, and record
every other R10 function/feature in the plan as possible/future, explicitly
marked not to implement yet. This is a narrowly scoped amendment to the
transport policy, not a general HTTP exception: it authorizes implementation
only for the six-provider safe HTTP machine-metadata subset defined below,
and that implementation is not yet done. Every other external service
remains SDK-by-default or deferred, and no credentials, live
metadata/cloud API calls, SDK dependencies or gate bypass are authorized;
the unchanged IAM/security, human and runtime-preflight gates apply in full.

- **Narrow transport exception.** Decision 2 is amended for HTTP
  machine-metadata collection only. The official-Go-SDK default remains
  binding for every other external service, including provider
  control-plane reads, secret/parameter reads and object/file reads. This
  is not a generic arbitrary HTTP client: each provider uses a fixed,
  compile-time literal request contract, and no cloud SDK or new module
  dependency is approved by this record.
- **Fixed transport contract.** Standard-library `net/http` only; the
  literal provider endpoint is 169.254.169.254:80 (link-local IPv4, port
  80). Proxy, DNS resolution, redirects (including same-origin), cookies,
  compression, retries/fallbacks and user-supplied base URL, path or
  headers are prohibited. Timeout and response-size bounds apply, and
  diagnostics are value-free closed-set errors. Metadata functions compile
  in by default but run only on explicit request; there is no default
  network activity.
- **Authorized safe subset vs research cohort.** The 13-member R10 research
  cohort is unchanged. Only six providers have an authorized, documented
  safe HTTP subset: AWS (EC2 IMDSv2), Azure (VM IMDS), Google Cloud
  (instance id only — zone, machine-type and image leaves transport project
  identifiers and must not be requested), Oracle Cloud (IMDS; zone from
  `ociAdName`, not the tenant-prefixed `availabilityDomain`), DigitalOcean,
  and OpenStack (dated EC2-compatible leaves recorded with `ec2_compat`
  provenance — compatibility labels, not Nova/Glance UUIDs; the bulk
  `meta_data.json` document is prohibited; Azure image/resourceId leaves
  are excluded). This is not provider-wide support and not feature parity.
  The remaining cohort members — IBM Cloud, Akamai/Linode, Hetzner,
  OVHcloud, Scaleway, Vultr and VMware vSphere — are deferred/not
  implemented until safe HTTP field/transport evidence and any necessary
  authentication design exist; VMware GuestInfo is non-HTTP and stays
  outside this exception. A deferred provider must never be implied absent.
- **Collected values and hard exclusions.** Only documented safe field
  values are collected: instance ID, plus region/zone/machine type/image
  only where that exact leaf response is safe. Excluded for every provider:
  account/project/tenant identifiers, hostnames and names, IP/MAC addresses
  and network topology, tags and labels, user/vendor data and cloud-init
  payloads, keys and certificates, and every credential, service-account or
  IAM-token endpoint. The protocol-only AWS IMDSv2 token stays transient
  and is never persisted or logged. HTTP metadata is unverified
  provider-claimed data: never attestation of the executing host and never
  authorization for local actions.
- **User-facing surface and results.** Opt-in `statekit facts --cloud
  --provider=<enum>` with both flags required together and the provider
  explicitly selected; no provider sweep and no autodetection. Ordinary
  `statekit facts`, `Facts.Detect` and runtime/bootstrap behavior remain
  local-only, network-free and unchanged. Invalid flags or an unknown
  provider exit 2 before any request; a recognized deferred or
  build-disabled provider exits 3 before any request; required-identity,
  unsafe-content, protocol and transport/timeout failures exit 1 and
  discard the entire cloud payload; only a documented optional leaf's
  404/empty may be omitted, giving a partial result with exit 0. The
  existing exit 4 internal behavior is unchanged and is not a cloud result
  code.
- **Build features.** Proposed negative tags, pending implementation:
  per-provider `statekit_no_metadata_<provider>`, an aggregate
  `statekit_no_metadata`, and the all-cloud `statekit_no_cloud_extras`;
  `statekit_no_sdks` remains SDK-only and does not disable native metadata.
  No binary-size, manifest or cache effect is promised.
- **Gates unchanged.** Every IAM/security, dependency, human and
  runtime-preflight gate of this ADR applies unchanged to any metadata
  implementation; human approval never substitutes for runtime preflight.
  The associated test plan in `plans/testing.md` is recorded as pending
  runtime preflight and NOT EXECUTED; no passing build or test is claimed
  by this amendment.

## Superseded ADR-0004 sections

Only the following parts of [ADR 0004](0004-cloud-provider-boundary.md) are
superseded, effective 2026-10-13:

- the accepted project-wide external-CLI transport default for external
  services across all portable functions ("use external CLIs by default");
- the mandatory separate ADR requirement for each CLI-to-Go-library
  migration.

Everything else in ADR-0004 carries forward unchanged and remains binding
where not superseded, including: its security gates and runtime-preflight
requirements, compatibility and pinned-source mappings, options C/D
implementation boundaries, the `saltcloud.create` exclusion
(`PTD-EXEC-1195`), the `external_ci=pending_external_ci` status, the R10
public counts, and its historical evidence and dates. ADR-0004 now carries a
supersession notice pointing here; the rest of that file was not rewritten.

## Options considered

Transport options:

| Option | Assessment |
|---|---|
| Project-wide CLI default (ADR-0004 status quo) | Keeps transport out-of-process and avoids in-process dependency scope, but conflicts with the owner's current direction, adds executable provenance/version obligations everywhere, and expresses typed read contracts only through CLI text parsing. Rejected as the global default; retained only through the narrow local-CLI predicate. |
| Go SDK everywhere | Typed contracts and no external executables, but forces SDK choices where none is acceptable and links integrations into builds that never use them unless gated. Rejected as unconditional. |
| Hybrid: local-CLI predicate + official SDKs + deferred exceptions (accepted) | Matches the owner's direction, keeps each dependency individually reviewable, and the deferred-exception path avoids silent CLI/HTTP fallbacks. Cost: policy complexity and per-integration review load. |

Build-feature mechanism options:

| Option | Assessment |
|---|---|
| Native negative build tags (accepted) | Standard Go mechanism (Boolean constraints + `-tags`), zero runtime cost, composable per integration and as one aggregate. Limitation stated, not hidden: tags do not remove manifests, caches or dependency metadata and do not guarantee smaller binaries. |
| ldflags / runtime configuration | One binary, but "disabled" integrations stay linked and selection becomes runtime state that misconfiguration can flip. Rejected as the sole mechanism. |
| Separate Go modules per integration | Strongest isolation, but fragments the module and complicates registration and the single-binary distribution model at this stage. Rejected for now; may be revisited if tag granularity proves insufficient. |

## Consequences

- No supported SDK integration and no `statekit_no_sdk_*` build tag exists
  today. This record creates none; each future integration starts from an
  explicit scoped approval, and tag naming/pattern is settled at
  implementation within the proposed convention.
- The active plan sections now reference this policy: `plans/porting.md` §0
  (dependency policy), §2 R10 (cloud/SaaS transport), §2 R11 (network
  devices), §4 (risk table) and §5 (acceptance), plus a future test-plan
  section in `plans/testing.md`. Older CLI-first wording elsewhere in the
  plans and in round logs is historical as of its original date and does not
  override this ADR.
- R10 public counts and all existing coverage statistics are unchanged by
  this record; no catalog, classification or report is regenerated.
- Deferred integrations must not be relabeled implemented, and a missing
  official SDK must not be quietly converted into a CLI or generic HTTP
  implementation; each exception requires an explicit decision record.
- Dependency hygiene is unchanged in rigor: approved SDK dependencies remain
  individually reviewed, pinned and gated (integrity, provenance, licensing,
  transitive graph, existing quarantine rules). There is no broad dependency
  ban lift and no blanket preapproval of SDK dependencies.
- Rollback/reversibility: this is a documentation-only policy change; a later
  ADR can amend or supersede it without runtime migration. No binary, module
  manifest, cache or CI configuration is touched by this record.

## Migration plan

Sequential and gated; no step is dispatched or scheduled by this record.

1. **Done in this stage (documentation only):** ADR-0005 accepted;
   ADR-0004 supersession notice added; the active `plans/porting.md` policy
   sections updated with an ADR-0005 cross-reference; a future test-plan
   section added to `plans/testing.md`.
2. **Future inventory/migration pass (project-wide, not only R10; planning
   only):** inventory every existing external-service CLI use and custom HTTP
   integration across the project and classify each by its effective target.
   Migrate to an official, maintained Go SDK where required, defer pending an
   explicit exception decision where no acceptable SDK exists, and retain a
   local service CLI only where the eligibility predicate holds —
   eligibility is established by the service actually running on the StateKit
   execution host with its CLI naturally expected there, never inferred from
   CLI presence or `PATH` discovery. Accepting this policy does not
   retrospectively implement anything and does not automatically grandfather
   existing remote CLI or custom HTTP use; every inventory item passes
   through the same gates as new integrations.
3. **Before any implementation:** per-integration suitability and security
   review — official maintained SDK availability, license and maintenance
   posture, fixed method/resource contracts for approved read operations,
   credential handling and redaction, bounds (response size, pagination,
   timeouts, retries), endpoint constraints, object destination/integrity —
   plus explicit provider/function/operation selection and the existing
   dependency review (pinned versions, integrity/provenance, transitive
   graph, quarantine).
4. **Implementation phase (separately authorized):** negative build tags per
   integration and one aggregate tag, gating SDK imports, code and
   registration together; aggregate-disabled builds preserve essential core
   and eligible local CLI features.
5. **Verification:** per `plans/testing.md` — compile matrix (default, each
   per-integration opt-out, aggregate opt-out, combined tags), with each
   feature's exclusion verified per feature by package/dependency graph
   inspection and registration checks under the same tags (a shared SDK
   package remains linked while another retained feature still imports it),
   selection of a disabled integration failing before any credential or
   network use, and credential-free mocked contract tests for allowlisted
   reads, denied mutations, redaction and bounds. No live services, real
   credentials or CI runs are part of this plan.
6. **Measurement (optional, later):** reproducible like-for-like binary-size
   comparison if separately authorized; no numeric goal is imposed and no
   number is measured today.

## Unselected scope and non-authorizations

- As of the base 2026-10-13 policy, no provider implementation or support
  list is approved. The R10 evaluation cohort is selected for research
  scope only by user direction (2026-10-13) and is listed in
  `plans/porting.md`; that selection is not a provider implementation or
  support choice, approves no API operation list, and pins no exact SDK
  package/version. AWS, Azure, GCP and other names outside that dated
  cohort entry remain candidates/examples only, and no SDK or dependency
  version is pinned. Sole exception: the six-provider HTTP machine-metadata
  subset authorized by Amendment 2026-10-14 — the current implementation
  scope, still unimplemented; beyond it, no broad provider support, SDK
  package/version or other API-operation approval exists.
- No operation list is approved beyond the read-only categories in
  Decision 3 and the amendment's bounded metadata subset; selection happens
  per integration under scoped review.
- No implementation, build, test, dependency or live cloud/CI operation has
  been performed by this record. Implementation is authorized solely by the
  2026-10-14 user request and only for the bounded HTTP machine-metadata
  subset, which remains unimplemented; the unchanged runtime-preflight,
  security and test gates must pass first. No credentials, live cloud access
  or SDK dependencies are authorized, and no test or build is authorized or
  completed by this record; human approval never substitutes for runtime
  preflight.
- Policy acceptance is distinct from implementation approval: nothing here
  dispatches work, selects executors for implementation, or implies that any
  integration, tag or feature already exists.

## Sources

- Go build constraints: https://pkg.go.dev/cmd/go#hdr-Build_constraints
- Go package/dependency compilation: https://pkg.go.dev/cmd/go#hdr-Compile_packages_and_dependencies
- Go modules reference (`go mod tidy`): https://go.dev/ref/mod#go-mod-tidy
- SDK vendor documentation: per-service library distribution; no package-size
  study exists.
- Recorded lead reviews for this stage: solution architect lead (file plan and
  supersession scoping), tech lead (conflicting active sections), security
  lead (IAM ceiling and read boundaries), DevOps lead (build-constraint and
  matrix expectations).
