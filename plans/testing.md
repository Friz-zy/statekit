# StateKit Test System — GitHub Actions + Docker

Companion to `plans/init.md` (§24–§28). Defines the concrete CI/CD implementation of the five test layers (unit / integration / live service / VM / differential) using GitHub Actions and Docker containers.

## Goals

1. Every migrated function is validated against its Salt-derived contract before its Definition of Done checkbox counts (init.md §47–§48).
2. Fast PR feedback (<10 min gate); full matrix on `main`; heavy suites nightly.
3. One fixture format drives everything: unit tests in Go, container integration runs, and Salt differential comparisons (init.md §25).
4. Machine-readable results: JUnit XML per job, coverage profile per PR, compatibility coverage numbers regenerated from real runs.

## Test layers

| Layer | What it validates | Where | When |
|---|---|---|---|
| Static checks | lint, vet, fmt, fixture schema, manifest/catalog consistency | GH runner | every push/PR |
| Unit (Go) | parsers, precedence, outputters, exit codes, provider resolution, file algorithms, fixture loader | GH runner | every push/PR |
| Smoke integration | binary boots; `version`, `--list`, `facts`, `test.echo`, `test.nop` | Docker (2 distros) | every push/PR |
| Integration matrix | real-case fixtures per module family on each target distro | Docker matrix | push to `main`, path-filtered PRs |
| E5.2 live service gate | workflow-ready authenticated disposable MySQL 8.4; StateKit E5.1 read-only/catalog/plugin calls plus R9.3j lifecycle, R9.3l alter/create/seed/read-back, R9.3m process/replication status, R9.3n `mysql.slave_lag`, R9.3o plugin lifecycle, R9.3p `mysql.query`, and R9.3q `mysql.file_query` cases with native-client postconditions | private rootless Podman network | every PR event, `main`, manual, nightly; live execution `pending_external_ci` |
| E5.3 live SQLite file gate | intended production `statekit`/native-observer workflow controls for a disposable actual SQLite file; exact value-free inventory | protected workflow with an inspected isolated Podman runner and owned temporary file | every PR event, `main`, manual, nightly; live execution `pending_external_ci` |
| E5 PostgreSQL live gate | production `postgres.psql_query` and independent native `psql` against an owned disposable database on the `ubuntu-24.04` runner's bundled PostgreSQL 16.15; exactly 20 ordered cases | rootless Podman `--rootfs` from exact runner Go/psql runtime files; no OCI image/service, image pull, published port, or repository secret | main push/manual/schedule only; no PR path; live run remains `external_ci: pending_external_ci` |
| Differential vs Salt | identical scenarios via `salt-call --local` vs `statekit`, normalized comparison | Docker twins | nightly + label `differential` |
| VM suite | systemd units, mounts, firewall, kernel-level cases containers cannot cover faithfully | QEMU on GH runner | nightly after Phase 3 |

## Distro matrix

Base images are pinned by digest in `tests/images/`. Two tiers:

### Tier 1 — plain containers (no init system)

| Image | pkg provider | Covers |
|---|---|---|
| `debian:12` | apt | cli.contract, cmd.*, file.*, user.*, group.*, cron, hosts, timezone |
| `ubuntu:24.04` | apt | same as debian |
| `fedora:latest` | dnf | same set |
| `opensuse/leap` | zypper | same set |
| `archlinux` | pacman | same set |
| `alpine:3` | apk | same set + OpenRC service basics |

### Tier 2 — systemd-enabled images

Built from `tests/images/systemd/<distro>/Dockerfile` (official base image + systemd entrypoint), run with:

```bash
docker run --privileged --cgroupns=host -v ./statekit:/usr/local/bin/statekit <image>
```

Used only by `service.*` and mount/sysctl suites that require a real init system or privileged mode. Prebuilt upstream systemd images are avoided; images are built in-CI from pinned digests for reproducibility.

## Fixtures — single source of truth

```text
tests/
├── fixtures/
│   ├── schema.json            # JSON Schema for fixture format (init.md §25)
│   ├── cli/                   # input methods, precedence, outputs, exit codes
│   ├── pkg/                   # per-provider scenario files
│   ├── service/               # requires Tier 2
│   ├── file/
│   ├── user/
│   ├── group/
│   ├── sysctl/                # some marked vm-required
│   └── ...
├── run-fixtures.sh            # in-container driver: statekit + assertions → JUnit XML
├── run-differential.sh        # twin-container driver: salt-call vs statekit → diff report
└── images/                    # Dockerfiles, pinned digests, salt install scripts
```

Fixture rules (per init.md §24–§25): observable contracts only; no mocks of Salt internals; environment-dependent fields declared for normalization; every fixture references its Salt source test(s).

## Real-case coverage families

Each family lists representative case IDs; all map to MVP modules (init.md §49).

### `cli.contract`
- `cli.input.flags-config-file-stdin-equivalence` — all four input channels produce the identical typed request.
- `cli.precedence.cli-overrides-file-overrides-defaults`.
- `cli.reject.stdin-plus-file`, `cli.reject.stdin-plus-config` → exit code 2.
- `cli.output.json-yaml-text-stable-shape` — snapshot schema tests.
- `cli.exitcodes.mapping` — 0/1/2/3/4 table from init.md §40.

### `pkg.*`
- installed no-op (`result: true`, empty changes); install specific version; remove; latest upgrade path; nonexistent package → `result: false`, exit 1; `--test` reports would-change with no mutation; second run idempotent (empty changes).

### `service.*` (Tier 2)
- running starts stopped unit; running already-running no-op; dead stops running unit; enabled/disabled without state change semantics; restart unknown unit failure; `--test` verified by `systemctl is-active` before/after.

### `file.*`
- managed contents/mode/owner/group; managed idempotency; local `source:` copy; symlink create/relink; absent recursive error path; directory perms; content-same-mtime-changed → no change; replace-with-backup.

### `user.*` / `group.*`
- present create with uid/gid/home/shell; present no-op; absent removes; uid conflict failure; group membership add/remove.

### `cmd.*`
- argv execution without shell quoting hazards; explicit shell opt-in; timeout kill semantics; env/cwd handling; sensitive argument redaction in output (init.md §37).

### `sysctl.*` / `mount.*` / `cron.*` / `hosts.*` / `timezone.*`
- one representative real case each; kernel/persistence-sensitive ones flagged `vm-required`.

### Cross-cutting
- non-root execution of privileged operations fails gracefully (`result: false`, exit 1) instead of crashing; output redaction never leaks secrets; concurrent invocation safety smoke.

## Workflows

```text
.github/workflows/
├── ci.yml              # PR gate
├── integration.yml     # reusable full matrix (workflow_call + main pushes)
├── integration-services.yml # E5.2 MySQL + E5.3 SQLite + PostgreSQL live gates
├── differential.yml    # nightly + workflow_dispatch + label:differential
└── vm-nightly.yml      # QEMU suite (Phase 4+, allow-fail initially)

.github/actions/
└── setup-statekit/     # composite action: build static binary, upload artifact
```

### `ci.yml` — PR gate (~<10 min)

1. checkout + setup-go (module/build cache via `actions/cache`)
2. `gofmt -l`, `go vet ./...`, `golangci-lint run`
3. `go test ./... -race -coverprofile=coverage.out` → artifact + summary badge
4. build static binary: `CGO_ENABLED=0 go build -trimpath ./cmd/statekit`
5. smoke tier: parallel `docker run` on debian + alpine executing `tests/run-fixtures.sh cli`
6. validate all fixtures against `schema.json`; yamllint; shellcheck
7. (Phase 1+) regenerate catalog golden files and fail on drift; validate `docs/compatibility/*` against generated catalog

### `integration.yml` — full matrix

- Trigger: push to `main`, `workflow_dispatch`, path filters (`modules/**`, `providers/**`, `internal/**`, `tests/fixtures/**`)
- Job sharding: one job per distro × suite group; Tier 2 jobs only where the suite needs them
- Each job: download binary artifact → `docker run --rm -v ...` distro image → `/tests/run-fixtures.sh <suite>` → JUnit XML published via `dorny/test-reporter`
- Gate rule: a module family's DoD is accepted only when its suite is green across the whole Tier 1 matrix (+ Tier 2 for service states)
- Summary: markdown matrix table posted to the run summary

### `integration-services.yml` — E5.2 live MySQL gate (workflow-ready; external execution pending)

- **Current state:** implementation files and workflow are ready. The local
  mock/static gate covers the exact 101-case inventory: the prior 96 cases plus
  five R9.3r free_slave cases. The prior 65 include the 13 R9.3o
  plugin cases, followed by 20 R9.3p query cases and 11 R9.3q file-query
  cases.
  `plugin_add`/`plugin_remove` built-in/idempotence, native status,
  uppercase/mixed-case StateKit exact-Go identity, missing-shared-object, invalid-input, authentication, and
  connection cases. The prior 36 cases comprise the earlier E5.1/R9.3j/R9.3l
  inventory, followed by 12 R9.3m processlist/master-status/slave-status and
  four R9.3n `slave_lag` StateKit/native/negative
  cases, with deterministic
  lifecycle, validation, cleanup, report-integrity, status-classification, and
  missing-vs-null-key fault injections. R9.3r adds the fixed free_slave
  no-dispatch/unsupported StateKit/native correlation plus authentication and
  connection cases that each pair a native negative observation with the
  guarded StateKit JSON empty string. Its runtime case is deterministic
  classifier-only and invokes neither StateKit nor a native runtime. The
  current bounded transport returns the source-compatible empty string without
  a Runner call; the native unsupported check is independent. It never
  provisions a replica, opens a status-derived master connection, or dispatches
  FLUSH/STOP/RESET/CHANGE, so the harness makes no promotion or partial
  mutation claim. No live
  MySQL GitHub execution has run; status is `pending_external_ci`, and no live 101/101
  result is claimed in this ledger. The user will validate the external run
  after synchronization. The local backend contract additionally has explicit
   source-result vectors for representative truthy/falsy `cursor.execute`
   returns, separate native process-exit vectors, failed-preflight no-mutation
   cases, and a stateful post-alter/readback mock that verifies seed
   preservation. The native CLI limitation is explicit: it cannot expose the
   exact MySQLdb cursor return predicate, and its legacy replication statement
   errors are classified independently rather than treated as successful
   replication data. The scalar `slave_lag` `-3` result is accepted only when
   the independent native `SHOW SLAVE STATUS` observation proves the pinned
   MySQL 8.4 unsupported diagnostic; it is never treated as retrieved lag.
   R9.3o deliberately does not claim a positive plugin installation: the pinned
   MySQL 8.4 image has no test plugin `.so`. The built-in
   `caching_sha2_password` is observed without uninstalling it, and default/
   custom SONAME attempts must independently classify the exact missing shared
    library failure rather than be reported as successful installation. R9.3p
    adds 20 fixed production-binary query cases: scalar/table SELECTs with
    independent native observations, a reserved disposable database DDL/DML
    lifecycle and native postconditions, multiline/comment/quoted SQL through
    bounded stdin, and invalid-database/auth/connection/timeout/oversize/
    diagnostic-classification negatives. The workflow supplies an explicit
     `MYSQL_QUERY_LIVE_ENABLED=1` control; all credentials are generated locally
     and disposable, no repository secret is available, and no arbitrary SQL
     supplied by a PR or a secret is executed. The report records only
     value-free classifications and cleanup verifies the disposable database is
     absent.
     The R9.3p transport remediation keeps SQL and request JSON out of every
     container argv: native SQL is an owned 0600 bounded stdin file, while the
     complete StateKit request is an owned ephemeral bounded stdin file. The
     client proves the production binary with a version preflight before the
     `exec --stdin` call. Terminated, unterminated, trailing-comment, and
     quoted-semicolon framing fixtures are byte-exact; inserted and observed
     `quote; value;` data use one decoded expected value. Expected input-limit
     and query-timeout diagnostics require an exited client and exact
     value-free stderr, while setup, exec, cleanup, and outer-timeout classes
     are rejected. Native syntax negatives likewise require one exited code-1
     diagnostic and reject mixed/unrelated output.
     R93P-01 is tested without live MySQL: the direct, registered, and CLI
     mysql.query paths reject odd/even backslash-containing quoted SQL before
     Runner dispatch because the server SQL mode is not proven; ordinary
     quoted semicolons, comments, executable-comment rejection, and affected
     query framing remain covered. The documented upgrade path is a proven
     matching mode before scan, not relaxing this ceiling.
      Local orchestration tests execute the JSON result matchers against both
      matching and deliberately mismatched decoded fixtures; they do not rely
      on source-marker assertions alone.
      R9.3q explicitly names `mysql.file_query` and adds its 11 exact native
      postcondition cases (85 -> 96): StateKit file-backed SELECT and DML with
      independent native postconditions, multiline and
      multiple-statement quote/comment framing, invalid path/oversize/content,
      authentication and connection negatives, and value-free cleanup/report
      checks. Each case creates a job-owned 0600 SQL file inside the disposable
      client through a bounded stdin frame; SQL/file contents never enter
       Podman argv or shell text. The bounded descriptor/no-follow file-read
       boundary is used where supported, and native client SQL crosses only the
       bounded stdin boundary; the wrapper removes the file on exit, and no
       local live MySQL evidence is claimed. `external_ci: pending_external_ci`
       remains the live-evidence boundary.
       The local fake-Runner contract additionally checks exact-once `%%`
       normalization parity between `mysql.query` and `mysql.file_query`, the
       complete-file SQL control policy (only space/tab/LF/CR/form feed), and
       whole-operation ceilings of 256 statements, 10000 positive
       returned/affected rows, 100000 result items, 8 MiB compact-JSON
       statement results, and one 30-second deadline. A limit, cancellation,
       or deadline returns no partial aggregate; cancellation/deadline tests
       prove that no later statement is dispatched.
   The implementation and test-plan update executor is the senior backend
  engineer; external CI execution remains an independent workflow gate.
  The independent backend and security gates requested changes on the local
  sandbox/trust boundary; they are not approvals.

- **Triggers:** `pull_request` opened/synchronize/reopened/ready_for_review,
  push to `main`, `workflow_dispatch`, and a nightly schedule are the intended
  external CI triggers. The workflow is intended to supply the E5.2 live check;
  making that check required is repository branch-protection administration, not
  asserted by this plan. It never uses `pull_request_target`.
- **Runtime intent / CI-enforced checks:** the official Docker Hub image manifest reference
  `mysql:8.4@sha256:85b9bf2e29cf836ecb8c2a15a935d4ba0c606631dff1dd79531a11983c638f2a`
  is intended to be pinned and checked after pull. The only accepted runtime
  is local rootless Podman. External CI must run host/runtime preflight before
  any image pull, client build, network, secret, or container creation and reject
  root, remote, Docker, malformed, or isolation-incomplete runtimes. A
  disposable server and an ephemeral client image copied from that digest must
  share an internal private container network; no host path, port, socket,
  device, privileged mode, or host credential is exposed. Runtime-generated
  passwords must be created from stdin as Podman secrets: the server must receive
  only `_FILE` paths and client processes must copy a defaults file onto tmpfs for one
  invocation. No env-file, credential-bearing Config.Env value, argv value,
  image layer, inspect output, log, or artifact may be used. The server must be
  requested with explicit `999:999` non-root identity and no added
  capabilities; client containers must run as explicit `65532:65532` with all
  capabilities dropped. Created-container policy must be inspected before start
  through allowlisted direct format fields only; exact no-new-privileges,
  network, user, capability, device, bind, socket, secret, and tmpfs policy
  mismatches must fail closed.
- **Workflow execution intent / CI-enforced checks:** the first workflow
  operation after checkout must be the same fail-closed rootless Podman
  preflight. Go dependency resolution must run in a pinned immutable toolchain
  image on a disposable egress-only fetch network; the production Go build and
  Python compile/orchestration checks must run as non-root in pinned
  images with explicit OCI isolation and `--network=none`, read-only roots, tmpfs-only scratch space,
  bounded resources, and no secrets. A hosted runner that cannot prove this
  preflight must not run a direct host build or test.
- **External cases:** 101 exact cases are required: the prior 65 cases
  (`14 + 9 + 13 + 12 + 4 + 13 = 65`, including the R9.3o plugin lifecycle
  cases) plus 20 R9.3p query cases, 11 R9.3q file-query cases, and five
  R9.3r free_slave cases (`65 + 20 + 11 + 5 = 101`). The plugin group covers installed add
  idempotence, independent native built-in status, uppercase/mixed-case
  StateKit exact-Go status identity, absent remove idempotence, independent native absence, default/custom
  SONAME missing-library false results with native `ERROR 1126 (HY000)`
  classification, invalid name/SONAME, negative authentication, and negative
  connection. Each new four-case group contains a production
  StateKit call, an independent native `mysql` observation, a negative
  authentication call, and a negative connection call. Processlist must be
  available and structurally typed. On pinned MySQL 8.4, StateKit
  `get_master_status`/`get_slave_status` must retain the exact source SQL and
  return the source-compatible `[]`, while the independent native call must
  classify that same legacy statement as `unsupported-sql`; native empty
  output, an available status map, auth failure, connection failure, unrelated
  error, or a StateKit/native classification mismatch fails the case. The
  The R9.3r group has exactly five cases: the StateKit no-dispatch empty
  contract, independent native unsupported classification, authentication and
  connection negatives that each pair a native negative observation with the
  guarded StateKit JSON empty string, and one deterministic runtime
  classifier-only negative that invokes neither StateKit nor a native runtime.
  It accepts only the source-facing empty string, verifies that no FLUSH LOGS,
  STOP SLAVE, RESET MASTER, or CHANGE MASTER command is claimed or dispatched,
  and makes no `promoted` or partial-mutation claim; the pinned MySQL 8.4
  harness has no replica. Runtime, timeout, setup, cleanup, unrelated, or
  native/StateKit mismatch outcomes fail rather than skip. The `slave_lag`
  StateKit call must retain `-3` for the native query/connection
  exit on MySQL 8.4, and only the independent native 1064/42000 syntax
  diagnostic for `SHOW SLAVE STATUS` can classify it as `unsupported-sql`;
  native empty/available output, auth failure, connection failure, runtime,
  timeout, setup, cleanup, or unrelated error must fail. The local static
  status vectors cover the runtime/timeout negative classifications without
  claiming a live server runtime failure.
  The earlier 36 case IDs and behavior remain byte-for-byte ordered before the
  appended status inventory. The 9 R9.3j lifecycle cases and 13 R9.3l cases cover reserved absence, native
  create/seed, independent default observation, explicit StateKit ALTER,
  native and StateKit read-back, empty-option default preservation, invalid
  authentication/connection/identifier/option negatives. The prior 52 case IDs
  and behavior are preserved. Zero
  cases or any skipped case must fail the external gate. Native negative cases
  require the expected MySQL error marker and must reject timeout, runtime,
  setup, and unrelated exit paths. Lifecycle CREATE/REMOVE dispatch is gated
  by the successful absence reservation; ownership is established before each
  CREATE dispatch, ambiguous CREATE is reconciled within that reservation, and
  normal REMOVE requires ownership. The lifecycle and alter disposable databases
  are always dropped and independently checked absent; cleanup uncertainty fails
  the report. Alter cases use a generated validated database name and a seeded
  table, and never mutate the shared seed database. Each successful
  alter/readback pair must also re-check the seeded row; this proves
  post-alter seed preservation, but does not prove the unobservable MySQLdb
  cursor return value. The local stateful mock covers that postcondition
  without starting MySQL. The R9.3p group requires scalar and table SELECT
  result/header shapes plus separate native observations, reserved absence
  before creating a generated disposable database, query-driven CREATE TABLE
  and INSERT postconditions, a multiline/comment/quoted SELECT, query-driven
  DROP and native absence, invalid database/auth/connection negatives, the
  finite native-client timeout, bounded oversize rejection, and an independent
  native 1064/42000 diagnostic classification. All query SQL is fixed test
  input and enters the production binary through its JSON/stdin request; it is
  never placed in the mysql argv or report. The StateKit query contract itself
  documents the CLI ceilings for DB-API exception classes, rowcount predicates,
  and bare NULL ambiguity.
   The R9.3q file-query group adds SELECT/DML aggregate results with independent
   native postconditions, multiline/multiple-statement quote/comment framing,
   invalid path/oversize/content and authentication/connection negatives. Each
   file case creates a private 0600 SQL file inside the client job through a
   bounded stdin frame; the SQL/file path never enters Podman argv or shell,
   invalid files dispatch no Runner command, and wrapper/DB cleanup remains
   value-free and failure-checked.
   Plugin lifecycle dispatch never removes the known built-in plugin and never
  treats a missing `.so` as an installation success. The uppercase/mixed-case
  case must prove StateKit's exact Go string identity rather than a case-folded
  match. This is StateKit's contract, not a byte-for-byte parity claim about
  Salt's parameterized equality, whose result is collation-dependent.
  Native status can correlate only with the selected MySQL server/column
  collation and cannot establish Salt parity independent of that collation.
  Validation cases must complete with the value-free diagnostic and no SQL mutation. Native
  plugin-install classification must reject auth, connection, timeout,
  runtime, setup, cleanup, unexpected-success, and unrelated error paths.
  The invalid-identifier case requires a completed StateKit execution with the
  expected validation category and diagnostic; setup, runtime, timeout, cleanup,
  and unrelated validation failures fail. `record_case` rejects unknown and
  duplicate IDs, and report success requires exactly one ordered result for
  every inventory ID. Polling and client calls must be bounded; every owned
  client must be tracked by name and ID, and server/network cleanup must run on
  success, failure, and cancellation. Cleanup failures must fail the gate.
- **External evidence requirement:** a stale report must be removed or rejected
  before execution, and a fresh value-free text report must be written before a
  successful exit. It must contain exact pass/fail/skipped counts and fixed
  limitations. The live gate is not a JUnit fixture and must not upload command output, credentials, SQL
  results, or container logs.
- **Boundary:** once externally executed, this is live evidence only for the
  listed MySQL subset, not full R9 coverage or Salt differential parity.
  Repeated INT/TERM must be shielded during bounded TERM-then-KILL cleanup;
  SIGKILL, host power loss,
  and runner loss can still prevent cleanup and report publication, so missing
  or incomplete evidence cannot claim a pass. Existing fake-Runner unit,
  registry, and CLI contract tests remain necessary for parser, redaction,
  mutation, unsupported, and cross-platform behavior. The checked-in Go/CLI
  tests are the applicable evidence for timeout, cancellation, output bounds,
  and redaction; the external gate must remain `pending_external_ci` until its
  native run publishes a fresh value-free report. No SQLite dependency is
  introduced in E5.2.

### `integration-services.yml` — E5.3 live SQLite file gate (workflow controls defined; external execution pending)

- **Current state:** `sqlite-live` is a separate job from the unchanged E5.2
  MySQL job. Repository checks cover deterministic orchestration and fault paths,
  shell syntax, and other non-live project behavior; no local sandbox, container,
  Podman, or live-harness execution is claimed. No GitHub SQLite execution has
  run; status is `pending_external_ci` (`external_ci: pending_external_ci`), and
  no live result is claimed.
- **Workflow controls (not executed evidence):** the intended external job first
  requires a native SQLite observer (`sqlite3` CLI or the image's native Python
  SQLite extension) and the bounded `timeout` command. It builds the production
  binary in the pinned Go dependency-fetch/network-denied build split, then
  invokes the binary and native observer together inside an inspected, non-root,
  network-denied runner container against an owned temporary file. The workflow
  reserves and creates a uniquely named, credential-free Podman output volume
  containing only the value-free report; it mounts that volume with non-root
  writable ownership, copies the report from the still-owned container after the
  run exits, and verifies a regular, non-symlink, non-empty destination. Stale
  host reports, missing or failed copies, and report cleanup failures fail the
  job. No fake Runner, service, repository secret, host database, or system
  SQLite library is used by the intended production build. Native observation is
  independent of StateKit's Go connection and reads the same file after each
  mutation. These are workflow controls, not local execution evidence.
- **Dependency verification boundary:** the workflow configuration contains
  pinned image references and the repository's declared Go module/checksum state,
  but authoritative dependency provenance, maintainer/license review, and
  quarantine-age verification remain pending. This plan claims no dependency
  provenance evidence.
- **External cases:** 14 exact IDs cover both version probes, create/insert,
  fetch, tables, indices, indexes alias, three native row/schema/index
  postconditions, invalid path, invalid SQL, and missing-db compatibility.
  The report requires one ordered result for every ID; zero cases or any
  skipped case fails the gate. Native observer unavailability is a failed
  preflight, not a skip. SQL/path values and command output are never written
  to the report or artifact. Owned temporary-file cleanup is verified on every
  exit path; cleanup uncertainty fails the gate.
- **Boundary:** this job proves only live production-binary/file behavior for
  the listed SQLite family once an external GitHub run produces evidence. The
  checked-in controls do not themselves prove live behavior. It does not claim
  Salt live differential parity, GitHub success, MySQL behavior, or any external
  database service result.

### `integration-services.yml` — runner-bundled PostgreSQL live query gate (external execution pending)

- **Platform and exact baseline:** `postgres-live` uses the GitHub-hosted
  `ubuntu-24.04` runner's existing PostgreSQL cluster and Go toolchain; it adds
  no OCI image, service, pull, dependency, or digest claim. The runner bundle is
  mutable, so preflight fails closed unless Go, PostgreSQL server, `pg_config`,
  and `psql` are exactly `1.26.8` / `16.15`. Only PostgreSQL `16/main` on port
  5432 is accepted. The workflow job condition is restricted to `push`,
  `workflow_dispatch`, and `schedule` on `refs/heads/main`; PR events do not
  execute the privileged controller. SHA-pinned actions, `contents: read`,
  `persist-credentials: false`, no secrets/OIDC/write permissions, and the job
  timeout remain in force.
- **Executor and review:** `devops-platform-engineer-senior` owns the CI
  controller and `security-architect-lead` (independent senior security
  reviewer) owns the required security review. The user explicitly authorized
  this isolated workflow remediation; the independent review remains a separate
  pre-merge gate. No generated Agent Manager session ID is available.
  `backend-engineer-senior` owns the PostgreSQL API and existing Go mock
  contract. Human approval does not replace runtime preflight.
- **Preflight and admin separation:** before module fetch or project/toolchain
  execution, the live controller checks the trusted main event/ref, exact
  toolchain, a noexec `/dev/shm` parent, an unused safe
  `/dev/shm/statekit-exec-<20hex>` path, and noninteractive sudo authorization
  for the exact mount/unmount argv. It also checks the single cluster, effective
  loopback listener configuration, and (if online) the selected postmaster PID,
  UID, executable/config arguments, and PID-to-listener association. The
  main-only admin bootstrap provisions a temporary rootless test identity with
  a no-sudo policy and an isolated subordinate-ID range, mounts one bounded
  tmpfs for the minimal executable rootfs, performs PostgreSQL setup/cleanup,
  and installs/removes the per-UID firewall. The test process has no sudo and an
  allowlist containing only `psql`.
- **Manifest-closed rootfs and execution boundary:** dependency acquisition runs
  only in its own manifest-closed dependency-fetch rootfs container: fixed
  `go mod download` with the fixed Go binary/argv, the copied read-only
  `go.mod`/`go.sum` pair at `/deps`, one writable go-module cache output at
  `/modules`, an isolated tmpfs `HOME`, fixed `GOPROXY=https://proxy.golang.org`
  with no direct fallback, public `GOSUMDB`, no checkout source, scripts, hooks,
  credentials, sockets, or other host paths, and bounded resources. The host
  never executes `go mod download`. That one container uses host networking
  behind per-test-UID iptables and ip6tables OUTPUT chains that are installed
  **unconditionally for both families**: an empty resolved address set for a
  family installs that family's resolver-only default-drop chain instead of
  leaving the family unfiltered. The chains allow only the loopback resolver
  (UDP/TCP 53, exact configured address), the resolved and pinned
  `proxy.golang.org`/`sum.golang.org`/`storage.googleapis.com` addresses over
  TCP/443, and then DROP all remaining traffic. Rule verification parses
  canonical `iptables -S` tuples (normalizing `-m tcp` serialization and
  `/32`//`/128` suffixes) and requires the exact ordered owned chain plus a
  single first-position owner jump for both families — any extra
  ACCEPT/RETURN/bypass, wrong DNS/proxy address, source, port, or altered
  ordering fails closed. Chain ownership is recorded the moment each chain is
  created, cleanup is idempotent/bounded and proves absence for every owned
  chain of both families (failure invalidates the published report), and the
  effective dual-family policy is re-verified immediately before the fetch
  container starts. A builder then stages exact runner Go 1.26.8, PostgreSQL 16.15
  `psql`, Python standard library, shell/test utilities, and trusted `ldd`
  shared-library closure into a minimal rootfs under the dedicated
  `/dev/shm/statekit-exec-<20hex>` tmpfs mounted with
  `rw,exec,nosuid,nodev,size=4g,mode=0700`. The noexec `/dev/shm` parent remains
  required for the isolated `/dev/shm/statekit-pg-*` workspace and credentials;
  the child mount is independently verified with `findmnt` for exact target,
  source `tmpfs`, `tmpfs` type, effective executable/noexec/nosuid/nodev/size/mode
  options, and dedicated test-user ownership. Since kernel mount tables may omit
  default `exec`, the verifier derives effective `exec` only when `noexec` is
  absent and independently confirms VFS flags with `statvfs`. The builder
  requires the exact run mount,
  direct nonsymlink paths, and these flags before staging; unsupported exec
  tmpfs fails closed with no ordinary-host-rootfs fallback. The rootfs manifest
  distinguishes `live-executable`, `dependency-fetch`, and `mock-only`. The
  builder verifies every source/symlink path against explicit public
  tool/library roots, rejects sockets/devices/escapes, and writes a hashed
  path/content manifest with exact Go/PostgreSQL versions. Immediately before
  every create and every start, the controller independently revalidates the
  manifest digest, canonical root/parent, exact entry list (no unlisted
  files/dirs/sockets/devices), per-entry type/mode/hash, and symlink targets
  that stay inside the staged root; labels alone are never rootfs proof. The
  Podman inspect gate additionally requires an authoritative rootfs source field
  (`RootfsPath`/`Rootfs`/`GraphDriver` merged directory) to match the staged
  root and fails closed when none is present. The exact libpod inspect schema
  is not observed on GitHub yet; if the runtime names these fields differently
  the gate rejects the runtime rather than trusting labels.
  Every build/mock/live/fetch container command is wrapped by a trusted
  in-rootfs preflight entrypoint that is itself manifest-hashed: it checks the
  real `/proc/self/status` UID/EUID/GID/groups, `NoNewPrivs`, and
  `CapInh`/`CapPrm`/`CapEff`/`CapBnd`/`CapAmb` — absent fields are failures,
  never implicit zeros — plus `/proc/self/mountinfo` source/readonly/exec
  identity for the root, `/tmp`, `/dev/shm`, `/workspace`, `/artifact`,
  `/run/pgpass`, `/out`, `/modules`, and `/deps` mounts with a closed
  mountpoint allowlist, and the manifest digest, before exec'ing the payload
  command.
  Go verify/build/all Go tests and the Python orchestration mocks run in
  separate rootless Podman `--rootfs` containers with `--userns=keep-id`, a
  non-root user, dropped capabilities, no-new-privileges, read-only rootfs,
  private PID/IPC/UTS, bounded CPU/memory/PID/tmpfs/timeout, and no network.
  Container inspect checks effective rootfs manifest, user, environment key
  allowlist, exact bind/tmpfs mounts, network mode, namespaces, capabilities,
  devices, and resource limits before each start. The build/mock containers
  receive the checkout read-only (`/workspace`, `noexec`) in `network=none`;
  the **live payload container never receives the checkout**: the trusted
  controller stages reviewed copies of exactly two harness files (`run.py`
  and the psql dispatch probe) under the isolated workspace, digest-pins them
  against the reviewed sources before create and again before start, and
  binds only that staged tree at `/workspace` — no repository content,
  working tree, or `.git` path crosses the boundary. Moving those two files
  into the manifest-closed rootfs profile is the recorded follow-up that
  removes this last `/workspace` bind as well. The compiled
  `statekit` binary is stored under the verified exec tmpfs
  (`<exec-mount>/artifacts`) rather than the noexec workspace: digest, owner,
  and mode are verified after the build and re-verified before live
  create/start, it is mounted read-only (exec) into the live container at
  `/artifact/statekit`, and the controller never executes it on the host. No
  host root, runner home, credentials, or runtime socket is mounted.
- **Rootless bootstrap and container lifecycle:** the Podman client wrapper
  runs as the isolated test user without `no-new-privileges` or capability
  bounding restrictions so the setuid `newuidmap`/`newgidmap` subordinate
  mapping helpers still work; those helpers are verified for exact path,
  root ownership, and setuid mode, the subordinate ranges are exactly one
  65536-ID range, and the test user has no sudo authorization. Payload
  containers carry their own controls (`--cap-drop=ALL`,
  `no-new-privileges`, non-root UID) and those are enforced again by the
  in-rootfs preflight before project code runs. Container existence is handled
  as a tri-state (`present`/`absent`/`unknown` from `podman container
  exists`): every create collision check fails on present or unknown,
  cleanup/removal proves absence, and repeated cleanup stays idempotent; mount
  teardown happens only after every run container is proven absent. The
  behavior is exercised by a mocked Podman lifecycle self-test.
- **Live PostgreSQL exception and credentials:** only the live test container
  uses host networking, and only after the selected server is verified
  loopback-only and the effective IPv4/IPv6 per-test-UID OUTPUT chains are
  structurally verified. IPv4 allows only `127.0.0.1:5432`; the IPv6 chain is
  installed unconditionally and allows `[::1]:5432` only when the selected
  service actually binds IPv6 loopback (probed from the listener snapshot) —
  otherwise it contains no ACCEPT rule at all. Every other address and port
  defaults to DROP in both families, and the exact canonical rules of both
  families are verified again immediately before the live container starts.
  Container mounts/network/privileges are inspected again before start. The
  passfile is a
  single-link regular mode-0600 file mounted read-only at `/run/pgpass`; SQL and
  request JSON remain stdin-only, and temporary bad-auth passfiles live on the
  private tmpfs and are removed per call. The parallel backend task owns moving
  the production Go transport from `PGPASSWORD` child-environment transit to the
  same per-call passfile boundary (`modules/exec/postgres/postgres.go` is not
  modified by the CI harness task); this harness retains the `PGPASSFILE`
  boundary for that change and makes no claim about its completion. Values are
  not logged or included in reports/artifacts. This is a rootless execution
  boundary, not a claim that the hosted
  runner controller itself is untrusted.
- **Cases, cleanup, and evidence:** preserve the exact 20 ordered case IDs and
  semantics, with no renames; tests continue to assert exact inventory equality
  and the 50/50 PostgreSQL registration report is unchanged. The live cases
  cover only `postgres.psql_query`, not the other 49 PostgreSQL functions, and
  are not Salt parity evidence. Database/role, container, account/subuid,
  firewall, passfile, rootfs/workspace, and job-started cluster cleanup are
  bounded and checked before report publication. After containers are stopped,
  removed, and confirmed absent, cleanup verifies the exact run-owned tmpfs,
  performs bounded `sudo -n umount` on that path only, proves mount absence,
  removes the empty mountpoint, and proves path absence; cleanup failure removes
  or invalidates the report. Report publication itself is success-only and
  gated by an **independent trusted-controller validator**
  (`tests/live/postgres/validate_report.py`, no shared code with the payload
  harness): after the payload container has exited and been removed and
  teardown is verified, and before any artifact copy, it checks a
  regular single-link mode-0600 file of bounded size, the exact 16-field
  value-free top-level schema (including `postgres_major: 16` and
  `postgres_version: 16.15`), the exact ordered 20 known case IDs exactly once
  with `status=pass` for every case, no extra fields, nested structures, or
  SQL/query/output/password-bearing content, and the expected aggregate
  status; on failure it logs only a fixed category and never report bytes, and
  any later cleanup failure removes the published artifact. Runner loss can
  still prevent cleanup/publication.
  `external_ci: pending_external_ci`; no live pass or successful GitHub
  execution is claimed.
- **Local validation boundary:** only mock/static tests run in rootless Podman
  using scratch storage `.gotmp`; do not start PostgreSQL, run Actions, pull an
  image, or invoke the live controller. Local tests use a Python-only rootfs
  built in executable `.gotmp`; that profile is explicitly `mock-only`, bypasses
  the live-mount requirement, and makes no claim to be an executable live
  toolchain rootfs. The live rootfs remains required to use the separately
  verified exec tmpfs. Exact Go 1.26.8 and PostgreSQL 16.15 are not required
  locally. On 2026-09-26, all 21 Python orchestration tests passed in a
  rootless
  `--rootfs --network=none` mock container on the existing `.gotmp` store
  (source mounted read-only, non-root UID, all capabilities dropped,
  no-new-privileges), including the exact 20-case inventory, the mocked
  container-existence tri-state lifecycle self-test
  (reserve/create/remove/repeated cleanup/mount teardown for
  present/absent/unknown), behavioral firewall mocks over a canonicalizing
  iptables/ip6tables simulator (dual-family install with an empty IPv6 set
  defaulting to DROP, unexpected ACCEPT/RETURN bypass rejection, altered
  DNS-rule/proxy-rule ordering, wrong resolver/port/source, unapproved pinned
  address, foreign rule before and duplicate owner jump, ownership recorded
  immediately after chain creation with failures before and after the hook,
  and idempotent bounded cleanup proving absence), the independent
  controller-side report validator (accepts the exact generated all-pass
  report; rejects extra fields, value-bearing/JSON-shaped content,
  duplicate/unknown/missing/reordered case IDs, skip/fail statuses, wrong
  major/minor, truncation, symlink/hardlink/wrong-mode/wrong-owner/oversize
  files, and emits only its fixed failure category), staged-rootfs manifest
  revalidation
  positives and unlisted-socket/mode/content/symlink-escape negatives, the
  generated in-rootfs preflight entrypoint against synthetic
  status/mountinfo/manifest fixtures (success plus missing-field, wrong-UID,
  nonzero-capability, wrong-digest, unexpected-mount, and mount-policy
  negatives, with the live `/workspace` mount modeled as the staged harness
  directory), synthetic noexec-parent/exec-child mount policy, mount
  identity/cleanup rejection fixtures, Go/psql rootfs closure,
  symlink-escape rejection, and per-phase Podman-inspect policy fixtures
  (fetch/build/mock/live bind sets, including rejection of a live container
  that still binds the checkout, and the fail-closed authoritative rootfs
  field). Bash syntax and diff
  checks also passed. As an explicitly authorized local-only exception, offline
  host Go validation ran with `-mod=readonly` and `GOPROXY=off` against the
  populated module cache: `go vet ./...` passed; `go test ./...` passed for all
  packages except the backend-owned `tests/differential` scope-report
  staleness check (report regeneration belongs to the parallel backend task and
  was not performed) and a pre-existing unrelated
  `tools/salt-reference` lock-fallback expectation; the integration harness
  needed the executable `.gotmp` tmpdir because the host `/tmp` is noexec. No
  local PostgreSQL, GitHub Actions, exact Go 1.26.8, exact PostgreSQL 16.15,
  sudo, or actual mount/umount operation was performed. This evidence cannot
  substitute for independent security review or external CI.
- **Follow-up ownership:** `security-architect-lead` (independent senior
  security reviewer) reviews the protected workflow, rootfs builder, Podman
  inspection boundary, and live host-network/firewall exception before merge.
  `devops-platform-engineer-senior` verifies local mock/static results and
  reviews the artifact; the requesting user (human CI operator; seniority not
  specified) runs GitHub Actions after synchronization. External evidence stays
  `pending_external_ci` until that user-run job completes. No generated
  Agent Manager session is assigned in this plan.

### `integration-services.yml` — R10.2 dig dns_contract offline contract gate (workflow controls defined; external execution pending)

- **Test boundary (R10.2):** the dig exec family is verified exclusively by
  recorded-response contract tests against the backend's scripted fake Runner
  behind the `dns_contract` build tag, with the tagged command covering
  `./modules/exec/dig`, `./internal/cli`, and `./tests/differential`. No dig contract test executes the dig
  binary, resolves DNS, or opens a network connection. A live DNS smoke and
  any external resolver destination are **not implemented in this phase**;
  the R10 plan records live smoke as opt-in-label-only and the resolver
  destination/provenance remains unapproved, so no such job, step, or local
  command exists. Default host CI (`go test ./...`) continues to skip the
  build-tagged files.
- **Job (`dig-contract`, main-only):** push/workflow_dispatch/schedule on
  `refs/heads/main` only — the same trusted-event guard as the postgres live
  job. Ordinary PR CI still compiles the code; the build-tagged dig tests run
  in this isolated rootless job after merge. Job-level `contents: read`,
  finite `timeout-minutes`, `checkout` at its verified commit SHA with
  `persist-credentials: false`, no `inputs:` anywhere in the workflow (no
  caller-selectable domains or nameservers), and nothing uploaded from the
  job (value-free artifact boundary: none — success is the test exit code).
- **Scoped HUMAN authorization:** approver is the project user via direct
  instructions on 2026-09-21, reaffirmed 2026-09-27 22:31 UTC and supplied
  directly to this remediation session. Target: only the R10.2 `dig-contract`
  job in `.github/workflows/integration-services.yml`. Scope: rootless Podman,
  `network=none` fake-Runner contract tests; push/main, workflow_dispatch/main,
  schedule/main; `contents: read`; no secrets, OIDC, write permissions, native
  dig, live DNS/smoke, new OCI identities, or new dependencies. Expiry:
  completion of R10 migration or explicit user revocation, whichever comes
  first. No permission for live DNS or user-controlled resolver targets.
  This approval does not waive runtime preflight or independent review.
  The direct 2026-09-28 continuation explicitly authorizes reuse of the existing
  PostgreSQL rootfs/preflight controller in `--dig-contract-only` mode, including
  its fixed locked dependency-fetch stage when needed. Approval owner is the
  authorized user in active chat, not a peer claim. This is not an exception:
  no new dependency version, OCI identity, package/image installation, live DNS
  target, or assistant-triggered GitHub run is authorized.
- **Execution model:** the job and `tests/live/dig/run.sh` invoke
  `tests/live/postgres/ci.sh --dig-contract-only`. The existing rootless identity,
  private store, verified executable tmpfs, manifest builder and inspector are
  reused. The new `dig-contract` rootfs profile copies the runner-installed Go
  and Python runtimes but excludes psql and the PostgreSQL harness. No image
  cache or preseeded module cache is required; no image is pulled or built.
  The shared rootfs toolchain policy is Go 1.26.8 (compatible with the unchanged
  module's Go 1.26.6 minimum), checked at its allowlisted installed path before
  staging and again inside the sandbox. An unavailable/wrong version fails
  closed rather than installing a toolchain. GitHub-hosted Ubuntu 24.04 and the
  exact trusted main event/ref are required before controller mutations.
- **Stages:** the shared fixed fetch rootfs receives only read-only go.mod/go.sum
  and the writable private module cache. Its manifest-hashed preflight executes
  `/opt/go/bin/go mod download`; no project source, hooks, secrets or direct
  fallback enters fetch. `GOTOOLCHAIN=local`, `GOWORK=off`, `GOENV=off`, fixed
  proxy/checksum settings and readonly manifest mode are preserved. After
  receipt-based fetch removal, the offline inspected runtime executes Python
  mocks, `go mod verify`, and exactly
  `go test -tags=dns_contract -count=1 ./modules/exec/dig ./internal/cli ./tests/differential`.
  There is no statekit artifact build, PG mock/live phase, cluster startup,
  database/role/password operation, live-service firewall or report upload.
- **Egress:** only the existing dependency-fetch exception uses host networking
  with the isolated test UID and verified IPv4+IPv6 owner-filter chains for
  fixed proxy/checksum/storage TCP/443 and loopback DNS. The shared preflight
  validates canonical ordered rules before fetch; all test execution uses
  network=none. No broad network is called allowlisted. The dependency egress
  path is not exercised during local verification; its actual GitHub-runner
  execution remains external evidence, not a local DNS success claim.
- **Runtime policy:** each stage uses create → canonical receipt/label check →
  effective-policy inspection → start by ID. Non-root keep-id, read-only root,
  cap-drop ALL, NNP, private ipc/pid/uts, explicit environment keys, authoritative
  rootfs source and manifest, exact staged mounts, no devices/secrets/socket/home binds, and
  requested memory/CPU/PID/time limits. Dig-only inspection rejects disabled
  or unverifiable cgroups instead of accepting requested limit numbers without
  an enabled enforcement mechanism. Offline source and cache binds are
  read-only/noexec/nosuid/nodev; ephemeral tmpfs holds executable Go test output.
  The existing build-role policy retains a private, bounded, noexec `/out`
  mount for the dig Go build cache (`GOCACHE=/out/gocache`); no production
  artifact is built there. The generated
  manifest-hashed `statekit-rootfs-preflight` rechecks UID/GID/groups, all
  capability sets, NNP, mount identities/options and manifest digest before
  dispatch. Source and module cache remain read-only; only private scratch
  surfaces are writable. The earlier image-controller CLI is disabled.
- **Receipt ownership:** name-present and unknown-existence results fail before
  create. Ownership is recorded only after successful create, canonical ID and
  exact name/run/gate/phase labels. Cleanup rechecks identity and uses only that
  ID. Failed/ambiguous partial creates are preserved, never claimed via labels;
  the controller preserves the workspace on ambiguous ownership.
  Disposable runner teardown is the recovery boundary, not guessed cleanup.
- **Local evidence:** on 2026-09-28 the rootfs-mode changes passed all 21 dig
  mocks plus all 21 shared PostgreSQL orchestration tests (42 total, zero skips)
  in create/inspect/start rootless Podman on `.gotmp`, using
  the already cached Python image, network=none, uid 1000, empty capabilities,
  NNP, read-only selective source mounts, private executable `/tmp` for fixture
  tests and private noexec `/dev/shm`. An additional inspected network=none
  container passed YAML parsing/job assertions (using already-installed PyYAML
  mounted read-only), Python syntax and shell syntax checks; `git diff --check`
  also passed. This cached local Python image is not used by the image-free CI job. Resource limits were
  requested; this local Podman reports cgroups disabled, so CPU/memory/PID
  enforcement is not claimed. No image pull, Go contract execution, dependency
  fetch, live dig/DNS or GitHub Actions execution occurred in that validation.
- **Quality gates and phased handoff:** executor `devops-platform-engineer-lead`
  owns runtime/static mock validation; executor `backend-engineer-senior` owns
  the differential dig fake vectors behind the existing build tag. The backend
  split is now present in `tests/differential/r10_dig_contract_test.go`; static
  assertions verify its build tag and absence of `TestR10Dig*` functions from
  the untagged report file. Neither backend file was edited by this DevOps task.
  Executor `security-architect-lead` independently reviews the workflow,
  receipt, rootless mapping, fetch firewall and effective-policy boundaries
  before commit. No commit is authorized by this task. The requesting project
  user (human CI operator; seniority unspecified) runs the synced main workflow
  only after review. External evidence remains `pending_external_ci`; the actual
  Ubuntu runner rootfs execution path is unverified locally. Exact external
  preflight dependencies are the installed allowlisted Go 1.26.8 runtime,
  authorized executable tmpfs mount, rootless subordinate mappings/private
  store, and authoritative rootfs inspect fields. These checks are not weakened
  if the runner lacks a capability; their fixed failure stage identifies the gap.
  Rollback is to disable this job, not restore Containerfile execution or bypass
  a failed policy check. No live-smoke upgrade is authorized.

### `differential.yml` — Salt comparison (init.md §26)

- Nightly cron + manual dispatch + `label:differential` on PRs touching core modules
- Per scenario pair:
  1. container A: distro base + pinned Salt (`pip install salt==<version from references/salt.lock>`)
  2. container B: same base + StateKit binary
  3. both execute the identical fixture; snapshots of return data and filesystem/system state captured
  4. normalization filter strips declared environment fields (`duration_ms`, provider paths, package epoch quirks listed per fixture)
  5. compare `result`, `changes`, `comment` semantics, resulting state → pass/fail report artifact
- Initial scope: file/pkg/service/user on debian + fedora; expands per Phase 3–5 needs. Failures open an auto-labeled issue referencing the fixture ID and classification checklist (init.md §28).

### `vm-nightly.yml` — QEMU suite (Phase 4+)

- Boots prebuilt minimal cloud images (built by Packer recipes under `tests/images/vm/`) on GitHub-hosted runners (KVM available on ubuntu runners)
- Runs the `vm-required` fixture subset: persistent sysctl, mounts/fstabs, firewall stacks, SELinux/AppArmor probes, reboot-persistence checks
- Non-blocking (`continue-on-error: true`) until stable, then promoted to blocking gate

## Cost and reliability controls

- `concurrency` groups with `cancel-in-progress` per ref
- Go cache + Docker layer cache (`buildx` GHA backend)
- Path filters keep unrelated PRs on the fast gate only
- Matrix shards time out individually (30 min hard cap); flakes get automatic retry-once annotation, repeated flake = failing issue
- All external images pinned by digest; no floating tags in Tier 2 builds
- Secrets: none required — differential jobs use public PyPI Salt packages at the pinned version only

## Rollout mapping to implementation phases

| Phase (init.md §29–36) | Test system milestone |
|---|---|
| 0 | `ci.yml` live: lint + unit + build + smoke (`test.echo`/`test.nop`) on debian/alpine; fixture schema + harness skeleton |
| 1 | indexer golden tests in CI; catalog determinism check; manifest-vs-catalog validation |
| 2 | `integration.yml` grows per module family (Tier 1 first); coverage gates for new code |
| 3 | Tier 2 systemd images; service/user/file/pkg suites complete matrix; `differential.yml` first run for core families |
| 4 | broader module suites join matrix; `vm-nightly.yml` bootstrap |
| E5.2 | `integration-services.yml` live MySQL 8.4 gate for the E5.1 read-only/catalog/plugin surface plus R9.3j lifecycle, R9.3l alter/create/seed/read-back, R9.3m process/replication status, R9.3n `slave_lag`, R9.3r `mysql.free_slave` unsupported/negative preflights, R9.3o plugin lifecycle, R9.3p `mysql.query`, and R9.3q `mysql.file_query`; exact inventory is 101 and external execution remains `pending_external_ci` |
| E5.3 | separate `sqlite-live` production-binary/file/native-observer gate for R9.3k; exact inventory, value-free report, cleanup, and zero-skip enforcement; external execution `pending_external_ci` |
| E5 PostgreSQL | separate `postgres-live` production-binary/native-psql service gate for the R9.2t query boundary; 20 exact ordered cases, independent cleanup and zero-skip enforcement; external execution `pending_external_ci` |
| 5+ | differential scope expansion driven by generated catalog; flake budget review |

## Acceptance criteria for the test system itself

- [ ] PR gate completes < 10 min on typical change
- [ ] Full matrix green on `main` before any DoD checkbox is claimed
- [ ] Every fixture references its Salt origin (source path/symbol/test)
- [ ] Differential report artifacts retained 90 days; failures traceable to fixture IDs
- [ ] No test requires network beyond package mirrors inside containers; mirror endpoints documented
- [ ] E5.2 live reports, when produced by external CI, contain exact 101-case counts, zero skipped cases, native charset/collation/seed/query postconditions, available processlist correlation, built-in plugin status plus uppercase/mixed-case StateKit exact-Go observations with the native collation ceiling documented, default/custom missing-shared-object INSTALL classifications without a positive installation claim, explicit MySQL 8.4 unsupported classifications for the two removed legacy replication statements plus `slave_lag`'s `-3` and `free_slave`'s empty-string compatibility results, five truthful free_slave cases in which auth/connection negatives pair native observations with the guarded StateKit JSON empty string and the runtime negative is classifier-only without StateKit/native runtime invocation, no replica/promotion claim, mysql.query and mysql.file_query scalar/table/DDL/multiline/negative classifications, owned-file cleanup success, disposable-database cleanup success, and no credential-bearing or SQL-bearing output
- [ ] E5.3 live reports, when produced by external CI, contain exact 14-case counts, zero skipped cases, native postconditions, cleanup success, and no value-bearing output; status remains `pending_external_ci` until an external run exists
- [ ] PostgreSQL live reports, when produced by external CI, contain exactly 20 ordered case IDs, zero skipped cases, fixed-value StateKit/native correlation, explicit `write=false` persistence proof, no-dispatch and output-cap negatives, independent database-absence proof, successful cleanup and no SQL, credentials, or query result values, and are accepted by the independent controller-side validator (strict mode-0600 single-link file, exact 16-field value-free schema with PostgreSQL 16/16.15, ordered all-pass inventory) before artifact publication. The runner-bundled PostgreSQL major-16 source is not a digest-pinned image; no OCI image or quarantine exception is used. External CI and independent protected-workflow security review remain pending.
