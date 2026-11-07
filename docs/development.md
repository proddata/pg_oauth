# Development and verification

Engineering and review rules are in [AGENTS.md](../AGENTS.md). The native
validator builds against PostgreSQL 18 or 19 and rejects other majors; the
optional [PAM module](#pam-module) also builds on 15 to 17. RPM-specific commands
are in [rpm-platforms.md](rpm-platforms.md).

## Container workflow

Docker with Compose provides the pinned toolchains without local PostgreSQL
dependencies. Source is mounted read-only and separate named volumes retain
incremental output for each major. The launcher copies Git-tracked files and
non-ignored new files into a fresh temporary tree, reflecting local edits and
deletions. Ignored release artifacts, caches, local profiles and Git metadata stay
out. Git and Python 3 are included in the pinned toolchain; copying fails rather
than falling back to the entire checkout:

```sh
docker compose -f compose.test.yml build
docker compose -f compose.test.yml run --rm pg18
docker compose -f compose.test.yml run --rm pg19
```

The default developer gate runs strict builds and unit/component tests, omits
release-package reproducibility, and runs integration tests with two workers
excluding `slow` tests. Run the complete integration suites with:

```sh
docker compose -f compose.test.yml run --rm pg18 dev-test-full-pg18
docker compose -f compose.test.yml run --rm pg19 dev-test-full-pg19
```

For a shorter loop:

```sh
docker compose -f compose.test.yml run --rm \
  -e DEV_CHECK_TARGETS='check-policy check-claims check-identity' \
  pg18 dev-check-pg18

docker compose -f compose.test.yml run --rm \
  -e INTEGRATION_TEST_ARGS='-k direct_identity_and_delegated_roles' \
  pg18 dev-integration-pg18
```

Rebuild images after changing installers, the development Containerfile, package
versions or image digests. `docker compose -f compose.test.yml down --volumes`
removes compiler caches.

## Native builds

Require Git, C17, GNU Make/PGXS, PostgreSQL server headers, `nm`, pkg-config, system
OpenSSL and libcurl, and the reviewed Jansson/libjwt sources. Integration also
requires Python 3, pytest, `runuser`, server programs and matching libpq headers.
The installers pin commits and archive hashes and install PIC static archives
into `/usr/local`; distribution Jansson archives may lack PIC.

```sh
./scripts/ci/install-jansson.sh
./scripts/ci/install-libjwt.sh
make test-pg18 PG18_CONFIG=/path/to/postgresql-18/bin/pg_config
make test-pg19 PG19_CONFIG=/path/to/postgresql-19/bin/pg_config
```

These targets isolate all build products under `build/pg18` and `build/pg19`
and include `verify` and the complete `integrationcheck`. `make verify-all`
runs both with the corresponding configurations. Direct PGXS builds are also
supported:

```sh
make clean
make verify PG_CONFIG=/path/to/postgresql/bin/pg_config
make integrationcheck PG_CONFIG=/path/to/postgresql/bin/pg_config
```

`verify` checks strict compilation, exported initialization and fail-closed
callbacks, unit/component behavior, dependency installers, demo configuration,
release artifacts, and runtime libcurl/DNS requirements. `integrationcheck`
starts isolated real servers and a local HTTPS issuer; it checks authorization,
TLS, hostile transport, reloads, rotation, outage/recovery, concurrency and
redaction. PostgreSQL 19 additionally tests custom HBA policy options.

## PAM module

The optional [PAM module](pam.md) is built and tested separately for PostgreSQL 15
to 19. Its tests write a PAM service under `/etc/pam.d` and need root, so they
refuse to run unless `OAUTH_TEST_PAM_DISPOSABLE=1` is set inside a disposable
Linux container. Use the Compose services, one per major:

```sh
docker compose -f compose.test.yml build pg17
docker compose -f compose.test.yml run --rm \
  -e OAUTH_TEST_PAM_DISPOSABLE=1 pg17 pam-check-pg17
```

`pam-check-pgNN` runs the unit tests, the exported-symbol and allowed-server-symbol
checks, a staged-install check and the real-connection suite. On PostgreSQL 18
and 19 `pam-both-check-pgNN` additionally installs the native validator and the PAM
module in one cluster. CI runs the same targets. `make pam-module` builds only the
module, and `make install-pam` installs it into the system PAM directory.

`make fuzz-pam-policy` builds a libFuzzer target (Clang, ASan and UBSan) for the
stack-argument parser. Besides memory safety it checks that an error leaves no
usable policy and that an accepted policy is bounded and has a stable digest. It
is part of `make fuzz-smoke`; seeds live in `tests/fuzz/pam-policy-seeds/`. Compose
mounts `/source` without execute permission, so run it from the build volume as
the `dev-*` targets do.

Four more libFuzzer targets are part of `make fuzz-smoke`, each with an oracle
that does not depend on the code under test:

- `make fuzz-claims` runs every input under three policies (default, delegated
  roles, custom identity claim). An accepted result must have a nonempty,
  bounded identity that passes the shared text rule, and with delegation the
  requested role must really be listed in the claim.
- `make fuzz-policy` builds a validation policy from fuzzed GUC and HBA values
  (numeric settings come from a table of boundary values) and derives the
  metadata URL from the issuer. An error must leave a zeroed policy, an accepted
  policy must be complete and bounded, and a scope list of only `openid` must
  never be accepted. Seeds are in `tests/fuzz/policy-seeds/`.
- `make fuzz-signature` verifies mutated tokens against real RS256, ES256 and
  Ed25519 keys (generated at start-up; the unmodified tokens must verify). A
  signature that verifies must have been computed over exactly the original
  signing input, which also covers algorithm confusion. Seeds are in
  `tests/fuzz/signature-seeds/`.

- `make fuzz-http-freshness` feeds the Cache-Control, Date, Expires and Age
  header values (any of them absent or empty) and the response time to the
  freshness calculation, which decides how long fetched provider keys are
  trusted. Each result is compared with a strict run (minimum lifetime zero) of
  the same input: the minimum may only fill a zero lifetime or cap a `no-store`
  one, never changes a revalidation requirement or a positive cacheable
  lifetime, and in strict mode an added Age header or a later response time can
  never lengthen freshness. Seeds are in `tests/fuzz/http-freshness-seeds/`.

The signing helpers shared with `tests/signature_test.c` are in
`tests/signing_support.h`.

Run the Compose commands from a normal clone. A Git worktree's `.git` is a pointer
into another directory that the container cannot read, which breaks the source
snapshot step.

## Quality and packaging gates

```sh
sh scripts/ci/check-source-tree.sh
./scripts/ci/install-pgindent.sh
make formatcheck
make sanitizercheck
make fuzz-smoke
make packagecheck
```

Pass `PG_CONFIG` when needed. Formatting uses pinned PostgreSQL 19 beta 3
`pgindent`, `pg_bsd_indent` 2.1.3 and the checked-in typedef list. Its installer
requires a compiler, Bison and Flex and writes under `.tools/`. `make format`
applies formatting. Sanitizers require Clang ASan/UBSan runtimes; fuzz smoke
runs bounded libFuzzer targets. Individual `fuzz-*` targets and
`make dependency-spike SANITIZE=1` are available in the Makefile.

`packagecheck` verifies staged contents, permissions, callback symbol, dynamic
dependencies and optional LLVM bitcode. `make installedcheck` installs into the
real PostgreSQL directories and tests that library; run it only with the required
privileges in a disposable container. [Release preparation](release-readiness.md)
adds reproducibility and lifecycle gates.

CI covers GCC/Clang builds on both majors, installed paths, formatting, static
analysis, sanitizers and fuzz smoke. Inspect [.github/workflows](../.github/workflows/)
for exact invocations. Source-tree hygiene runs on the host: pinned containers
lack Git and checkout falls back to a tarball, preventing an untracked-file check
inside them. Debian image digests, snapshot and exact package versions in
`scripts/ci/install-debian-dependencies.sh` form one reviewed input set; update
them together without unversioned fallback installs.

## Interoperability and test limits

```sh
make interop-keycloak
```

This opt-in Compose suite uses pinned Keycloak 26.5.0 and real PostgreSQL 19
OAuth connections. It checks access-token acceptance, ID-token and authorization
rejection, rotation, outage and recovery. See
[provider compatibility](../PROVIDER-COMPATIBILITY.md) for evidence limits.
Deterministic local-issuer/cache tests remain the primary regression coverage;
live-provider tests do not replace them.

The local DNS shim checks lookup failure and cancellation during a delayed
threaded lookup on Linux. Repeat cancellation testing with deployed libcurl/DNS.
CI robustness ceilings are five seconds for cache exhaustion and twelve seconds
for the mixed unknown-key/valid-token burst; these are regression limits, not
throughput benchmarks or production-readiness claims.
