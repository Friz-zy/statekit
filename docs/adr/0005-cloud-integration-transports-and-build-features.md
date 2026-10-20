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
Status addendum (2026-10-19): the active user instruction dated 2026-10-19
authorizes continuation only for the two GCP reads in [Amendment
2026-10-19](#amendment-2026-10-19-bounded-gcp-secret-manager-and-parameter-manager-reads)
and the task-authorized dependency versions recorded there. This narrowly
supersedes the 2026-10-14 metadata-only/no-SDK boundary only for those reads
and that package scope; it is not a generic SDK or dependency pre-approval.
Implementation source and tests are present as uncommitted worktree changes.
The reported offline validation passed `go mod verify`, a GCP-enabled build
with AWS excluded, and focused tests under `statekit_no_sdk_aws` and
`statekit_no_sdks`, in rootless Podman with `--network=none`. A final offline
check also passed `go mod verify`, plus `go build` and focused tests run with
`-mod=readonly` and
`-tags=statekit_no_sdk_gcp,statekit_no_sdk_aws`, in rootless Podman with
`--network=none`. This combined-tag profile exercises the GCP-disabled stubs
while excluding AWS source dependencies; it does not prove the per-GCP-only
profile with AWS enabled. The full
default/AWS-enabled profile was not tested; an earlier full CLI-package run
failed at the unrelated `TestFreeBSDTrackCLIGOOSGating`. No live cloud calls,
production credentials, IAM changes, or live provider validation occurred.
No live validation or IAM mutation is authorized by this amendment, and
independent security/runtime gates remain in force. The dated 2026-10-13/14/15
statements above remain historical except where this amendment expressly
supersedes them.
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
it did not claim that any supported SDK integration or build tag existed as
of 2026-10-13; the base decision itself created none. Separately, on
2026-10-13 the user fixed the R10 evaluation cohort
for research scope only; it is listed in `plans/porting.md` and makes those
names candidates for research and evaluation, not support or implementation
selections. All other provider and tool names appearing in plans or in this
record remain candidates or examples, not selections. The sole carve-out as
of 2026-10-14 was
the six-provider HTTP machine-metadata subset in
[Amendment 2026-10-14](#amendment-2026-10-14-narrow-http-machine-metadata-exception)
— the authorized implementation scope as of 2026-10-14, whose code was not
implemented as of that date. The 2026-10-15 status addendum records its
subsequent implementation. The [2026-10-19 amendment](#amendment-2026-10-19-bounded-gcp-secret-manager-and-parameter-manager-reads)
adds only the two GCP reads and task-authorized dependency versions stated
there. These later records supersede that date-scoped scope/status only
within their stated boundaries; beyond them, no broad provider support, SDK
package/version or other API-operation approval exists.

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

## Amendment 2026-10-19: bounded GCP Secret Manager and Parameter Manager reads

Decision authority: active user instruction dated 2026-10-19; no individual
name or title is recorded or inferred. This amendment authorizes only the two
GCP API reads below and the task-authorized dependency versions recorded here.
It narrowly supersedes the 2026-10-14 metadata-only/no-SDK boundary for these
operations and this dependency scope only. It is not a general SDK or
dependency pre-approval. Any other GCP API operation, provider SDK integration
or dependency addition/version change requires separate explicit approval.
Historical 2026-10-13/14/15 decision wording and authority remain intact
except for this explicitly bounded supersession.

- **Secret Manager — `AccessSecretVersion` only.** Read only from the global
  `projects/{project}/secrets/{secret}/versions/{selector}` resource
  contract. The request uses the current workload identity obtained through
  the fixed GCP metadata-token flow from `metadata.google.internal`; there is
  no ADC, profile, static-credential or environment-credential fallback. The
  application validates the response against the requested
  global secret resource and selected version (requiring a concrete numeric
  version when `latest` is selected) and verifies payload CRC32C before
  accepting bytes. An omitted selector reads mutable `latest`;
  `--version-id` selects a numeric version to pin the content, while
  `--version-alias latest` remains an explicit selector. No Secret Manager
  write or IAM methods are in scope. Payloads stay on the
  dedicated sensitive-value path and are not logged or serialized into
  ordinary StateKit results.
- **Parameter Manager — `GetParameterVersion` only.** Accept only the
  `param://gcp/parametermanager/{location}/{percent-encoded-resource}` global
  or regional resource contract. The operation retrieves only the stored raw
  payload; it does not render a parameter, evaluate templates, or resolve
  Secret Manager references. `RenderParameterVersion`, writes,
  list operations and IAM methods are out of scope. An omitted selector reads
  mutable `latest`. Project-wide IAM is an external permission ceiling and
  residual blast radius, is not changed by StateKit, and remains subject to
  least-privilege configuration. The project-scoped IAM risk is accepted only
  as pre-existing task context, not as authorization to change IAM.
- **Shared runtime and build limits.** Both operations are opt-in and inert at
  startup and help. They use bounded official GCP SDK/RPC endpoints and
  validate resource/version and payloads under payload-size and time limits
  (1 MiB payload maximum; 15-second operation deadline; 2-second metadata
  token deadline). Secret Manager RPCs use the fixed
  `secretmanager.googleapis.com:443` authority; Parameter Manager uses the
  fixed `parametermanager.googleapis.com:443` global authority or
  `parametermanager.<location>.rep.googleapis.com:443` regional authority.
  The requested sink is preflighted before provider construction; file sinks
  are denied. There is no application-level retry or fallback; the transport
  may retry or reconnect the same RPC. The negative build tags
  `statekit_no_sdk_gcp` and
  `statekit_no_sdks` gate the GCP imports and implementation. Tags do not
  remove module manifest or checksum entries or guarantee removal from the
  selected dependency graph when another retained import edge exists.
- **Task-authorized dependency versions.** The direct SDK pins are
  `cloud.google.com/go/secretmanager v1.22.0` and
  `cloud.google.com/go/parametermanager v1.1.0`. Relevant graph pins recorded
  in `go.mod`/`go.sum` include `cloud.google.com/go/iam v1.11.0`,
  `google.golang.org/grpc v1.83.2`,
  `google.golang.org/genproto v0.0.0-20260319201613-d00831a3d3e7`,
  `google.golang.org/genproto/googleapis/api
  v0.0.0-20260630182238-925bb5da69e7`,
  `google.golang.org/genproto/googleapis/rpc
  v0.0.0-20260928230214-8a89bd6388cc`,
  `google.golang.org/protobuf v1.36.12`,
  `go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc
  v0.72.0`,
  `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.72.0`,
  and `go.opentelemetry.io/otel` plus its `log`, `metric` and `trace` modules
  at `v1.47.0`. The additional graph pins `golang.org/x/crypto v0.57.0`,
  `golang.org/x/net v0.60.0`, `golang.org/x/sys v0.48.0` and
  `golang.org/x/text v0.42.0` are also allowed ZIP artifacts in the list
  below. The available integrity evidence is the recorded module checksums
  and passing `go mod verify`; this does not assert a complete
  transitive-closure provenance, license or vulnerability review.
### Approved module ZIP identity boundary

The task-approved allowlist
  contains exactly these 35 permitted module ZIP acquisition identities.
  They are acquisition identities only—not proof that every item is in the
  compiled runtime closure or that provenance, licensing or vulnerability
  clearance is complete:

  ```text
  cloud.google.com/go/auth@v0.20.0
  cloud.google.com/go/auth/oauth2adapt@v0.2.8
  cloud.google.com/go/compute/metadata@v0.9.0
  cloud.google.com/go/iam@v1.11.0
  cloud.google.com/go/secretmanager@v1.22.0
  github.com/cespare/xxhash/v2@v2.3.0
  github.com/felixge/httpsnoop@v1.1.0
  github.com/go-logr/logr@v1.4.4
  github.com/go-logr/stdr@v1.2.2
  github.com/google/s2a-go@v0.1.9
  github.com/googleapis/enterprise-certificate-proxy@v0.3.17
  github.com/googleapis/gax-go/v2@v2.23.0
  go.opentelemetry.io/auto/sdk@v1.2.1
  go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc@v0.72.0
  go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp@v0.72.0
  go.opentelemetry.io/otel@v1.47.0
  go.opentelemetry.io/otel/log@v1.47.0
  go.opentelemetry.io/otel/metric@v1.47.0
  go.opentelemetry.io/otel/trace@v1.47.0
  golang.org/x/crypto@v0.57.0
  golang.org/x/net@v0.60.0
  golang.org/x/oauth2@v0.36.0
  golang.org/x/sys@v0.48.0
  golang.org/x/text@v0.42.0
  golang.org/x/time@v0.15.0
  google.golang.org/api@v0.287.1
  google.golang.org/genproto@v0.0.0-20260319201613-d00831a3d3e7
  google.golang.org/genproto/googleapis/api@v0.0.0-20260630182238-925bb5da69e7
  google.golang.org/genproto/googleapis/rpc@v0.0.0-20260928230214-8a89bd6388cc
  google.golang.org/grpc@v1.83.2
  google.golang.org/protobuf@v1.36.12
  golang.org/x/mod@v0.40.0
  golang.org/x/term@v0.46.0
  golang.org/x/tools@v0.49.0
  cloud.google.com/go/parametermanager@v1.1.0
  ```

  These five T-only identities are explicitly excluded and are not authorized
  for module ZIP fetch:

  ```text
  github.com/google/go-cmp@v0.7.0
  github.com/stretchr/testify@v1.12.1
  go.opentelemetry.io/otel/sdk@v1.47.0
  go.opentelemetry.io/otel/sdk/metric@v1.47.0
  go.yaml.in/yaml/v3@v3.0.5
  ```

  This list is from the approved ZIP manifest independently read by the
  coordinator. The recorded `standard_fetch` `profile.json` invokes
  `go mod download -json` for exactly these 35 identities, and its
  `result.json` lists 35 successful results. `cache-validation.json` reports
  `approved_archives=35`, `excluded_archives_in_staging=0`, and
  `archive_and_mod_h1_verified=35`. These results describe that invocation and
  staging set; they do not establish the provenance of all material in the
  shared module cache or checksum file.

  The later SumDB proof refresh for the allowlisted
  `google.golang.org/genproto/googleapis/api@v0.0.0-20260630182238-925bb5da69e7`
  records eight lookup/tile requests, copies one SumDB tile file, and fetches
  no module ZIP. The final offline builds and tests used `GOPROXY=off`.

  Current shared state also contains out-of-allowlist material: the module
  cache has `golang.org/x/text/@v/v0.41.0.zip`; `go.sum` has entries for
  `golang.org/x/mod v0.41.0` (h1 only), `golang.org/x/net v0.58.0` (h1 and
  `/go.mod`), `golang.org/x/sync v0.23.0` (h1 only), and
  `golang.org/x/text v0.41.0` (h1 and `/go.mod`). The package profile selected
  `golang.org/x/text v0.42.0`. The acquisition time and source of this older
  cache/checksum material are not established; current records do not
  attribute the cached ZIP to this task or establish that it was executed.
  This is a release-assurance gap, not evidence of a current-task download or
  execution, and no provenance is asserted for the older artifacts.
### Implementation and verification status

The implementation and tests
  are present as uncommitted worktree changes. Package-scoped offline
  validation passed `go mod verify`, a GCP-enabled build with AWS excluded,
  and focused tests under `statekit_no_sdk_aws` and `statekit_no_sdks` in
  rootless Podman with `--network=none`. A final package-scoped offline check
  also passed `go mod verify`, plus `go build` and focused tests run with
  `-mod=readonly` and
  `-tags=statekit_no_sdk_gcp,statekit_no_sdk_aws`, in rootless Podman with
  `--network=none`. This combined-tag profile exercises the GCP-disabled stubs
  while excluding AWS source dependencies; it does not prove the per-GCP-only
  profile with AWS enabled. The full default/AWS-enabled profile
  was not tested. The full `go list -m all` did not complete: the module graph
  query remains unsuccessful with 20 unavailable metadata entries. The
  existing vulnerability snapshot was unreadable/corrupt; no clean scan is
  claimed. An earlier full CLI-package run failed at the unrelated
  `TestFreeBSDTrackCLIGOOSGating`. No live credentials, cloud endpoint
  validation or IAM mutation occurred or is authorized. This amendment does
  not waive independent security or runtime-preflight gates; human approval
  never substitutes for runtime preflight.

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

- As of the 2026-10-13 base-record date, no supported SDK integration and no
  `statekit_no_sdk_*` build tag existed; the base record itself created none.
  Later dated amendments/addenda authorize or record only their stated
  exceptions; they do not establish general SDK support. Each additional future
  integration starts from explicit scoped approval, and tag naming/pattern
  is settled at implementation within the proposed convention.
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

Historical-scope clarification (2026-10-19): the base-policy and
2026-10-14 statements in the bullets below preserve the decision as recorded
at those dates. The later, narrow exception is the GCP read scope and
task-authorized dependency set in [Amendment
2026-10-19](#amendment-2026-10-19-bounded-gcp-secret-manager-and-parameter-manager-reads).
It supersedes earlier “sole exception,” “no API-operation approval,”
“no SDK dependency,” and “not implemented” statements only within that exact
scope. No broader provider/API approval or live-access/IAM authorization
follows.

- As of the base 2026-10-13 policy, no provider implementation or support
  list is approved. The R10 evaluation cohort is selected for research
  scope only by user direction (2026-10-13) and is listed in
  `plans/porting.md`; that selection is not a provider implementation or
  support choice, approves no API operation list, and pins no exact SDK
  package/version. AWS, Azure, GCP and other names outside that dated
  cohort entry remain candidates/examples only; the 2026-10-13 base decision
  pinned no SDK or dependency version. Sole exception as of 2026-10-14: the
  six-provider HTTP machine-metadata subset authorized by Amendment
  2026-10-14; it remained unimplemented as of that date. The 2026-10-15
  status addendum records its subsequent implementation. The 2026-10-19
  amendment authorizes only the two GCP reads and task-authorized dependency
  versions stated there. Beyond these dated exceptions, no broad provider
  support, SDK package/version or other API-operation approval exists.
- As of the 2026-10-14 amendment, no operation list was approved beyond the
  read-only categories in Decision 3 and that amendment's bounded metadata
  subset. The 2026-10-19 amendment adds only its two GCP read operations;
  other selections remain subject to per-integration scoped review.
- This record itself did not perform implementation, build, test, dependency
  or live cloud/CI operations. Under the 2026-10-14 user request, only the
  bounded HTTP machine-metadata subset was authorized and it was unimplemented
  as of that date; the 2026-10-15 status addendum records its subsequent
  implementation. The 2026-10-19 amendment authorizes only the two GCP reads
  and task-authorized dependency versions stated there. The unchanged
  runtime-preflight, security and test gates remain applicable; the reported
  offline validation is status evidence, not broader build/test authority.
  No broader provider/API support, credentials, live cloud access or IAM
  mutation is authorized; no dependency beyond the task-authorized versions
  is approved. Human approval never substitutes for runtime preflight.
- Policy acceptance is distinct from implementation approval: the 2026-10-13
  base policy itself did not dispatch work or select executors. Current
  implementation status is recorded in the dated addenda above.

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
