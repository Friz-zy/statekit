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
| E5.2 live service gate | workflow-ready authenticated disposable MySQL 8.4; StateKit E5.1 read-only/catalog/plugin calls plus R9.3j lifecycle and R9.3l alter/create/seed/read-back cases with native-client postconditions | private rootless Podman network | every PR event, `main`, manual, nightly; live execution `pending_external_ci` |
| E5.3 live SQLite file gate | intended production `statekit`/native-observer workflow controls for a disposable actual SQLite file; exact value-free inventory | protected workflow with an inspected isolated Podman runner and owned temporary file | every PR event, `main`, manual, nightly; live execution `pending_external_ci` |
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
├── integration-services.yml # E5.2 MySQL + E5.3 SQLite live gates
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
  mock/static gate covers the exact 36-case inventory: the prior 23 cases plus
  13 R9.3l create/seed/observe/alter/read-back/negative cases, with deterministic
  lifecycle, validation, cleanup, and report-integrity fault injections. No live
  MySQL GitHub execution has run; status is `pending_external_ci`, and no live 36/36
  result is claimed in this ledger. The user will validate the external run
  after synchronization. The local backend contract additionally has explicit
  source-result vectors for representative truthy/falsy `cursor.execute`
  returns, separate native process-exit vectors, failed-preflight no-mutation
  cases, and a stateful post-alter/readback mock that verifies seed
  preservation. The native CLI limitation is explicit: it cannot expose the
  exact MySQLdb cursor return predicate.
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
- **External cases:** 36 exact cases are required: the prior 14 E5.1 cases,
  9 R9.3j lifecycle cases, and 13 R9.3l cases for reserved absence, native
  create/seed, independent default observation, explicit StateKit ALTER,
  native and StateKit read-back, empty-option default preservation, invalid
  authentication/connection/identifier/option negatives. The prior 23 case IDs
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
  without starting MySQL.
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
| E5.2 | `integration-services.yml` live MySQL 8.4 gate for the E5.1 read-only/catalog/plugin surface plus R9.3j lifecycle and R9.3l alter/create/seed/read-back cases; exact inventory is 36 and external execution remains `pending_external_ci` |
| E5.3 | separate `sqlite-live` production-binary/file/native-observer gate for R9.3k; exact inventory, value-free report, cleanup, and zero-skip enforcement; external execution `pending_external_ci` |
| 5+ | differential scope expansion driven by generated catalog; flake budget review |

## Acceptance criteria for the test system itself

- [ ] PR gate completes < 10 min on typical change
- [ ] Full matrix green on `main` before any DoD checkbox is claimed
- [ ] Every fixture references its Salt origin (source path/symbol/test)
- [ ] Differential report artifacts retained 90 days; failures traceable to fixture IDs
- [ ] No test requires network beyond package mirrors inside containers; mirror endpoints documented
- [ ] E5.2 live reports, when produced by external CI, contain exact 36-case counts, zero skipped cases, native charset/collation and seed read-backs, cleanup success, and no credential-bearing output
- [ ] E5.3 live reports, when produced by external CI, contain exact 14-case counts, zero skipped cases, native postconditions, cleanup success, and no value-bearing output; status remains `pending_external_ci` until an external run exists
