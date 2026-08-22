# StateKit Test System — GitHub Actions + Docker

Companion to `plans/init.md` (§24–§28). Defines the concrete CI/CD implementation of the four test layers (unit / integration / VM / differential) using GitHub Actions and Docker containers.

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
| 5+ | differential scope expansion driven by generated catalog; flake budget review |

## Acceptance criteria for the test system itself

- [ ] PR gate completes < 10 min on typical change
- [ ] Full matrix green on `main` before any DoD checkbox is claimed
- [ ] Every fixture references its Salt origin (source path/symbol/test)
- [ ] Differential report artifacts retained 90 days; failures traceable to fixture IDs
- [ ] No test requires network beyond package mirrors inside containers; mirror endpoints documented
