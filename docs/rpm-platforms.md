# Experimental RPM packaging

Fedora 43/44 and Rocky Linux 10 are experimental PostgreSQL 18 targets on
x86-64 and arm64 (`aarch64` in RPM). Containers check compatibility; they do not
establish production support or SELinux confinement. Debian/PGDG remains the
reviewed candidate environment. See [release requirements](release-readiness.md)
and ADRs [0005](adr/0005-experimental-rpm-packaging.md),
[0006](adr/0006-selinux-enforcing-vm-gate.md) and
[0007](adr/0007-frozen-rpm-release-builders.md) for the decisions.

## Compatibility builds

```sh
docker compose -f compose.rpm-test.yml build
docker compose -f compose.rpm-test.yml up --abort-on-container-failure
```

Defaults use x86-64. On arm64, append `fedora43-arm64 fedora44-arm64 rocky10-arm64`
to both commands. CI runs all six cells natively; emulation is not equivalent
evidence. Base manifests are pinned but compatibility repositories are mutable.
`/etc/pg-oauth-build-inputs` records selected packages; these images are not the
locked release authority.

Fedora uses `/usr/bin/pg_server_config` and its server-private libpq development
packages, which conflict with standalone `libpq-devel`. Rocky uses PGDG's
`/usr/pgsql-18/bin/pg_config`, CRB dependencies and hash-verified PGDG bootstrap
RPMs with repository signatures enforced. Rocky 9's libcurl is below the required
7.87.0 minimum; Fedora 42 is not a continuous target.

Each cell runs strict unit/component and installed-path OAuth suites. Run only
in disposable containers: installation writes real PostgreSQL paths. Integration
covers TLS, roles, reloads, rotation, outage/recovery, concurrency and redaction;
PostgreSQL-19-only cases are expected skips. No live provider is required.

## Offline RPM packaging

The [spec](../packaging/rpm/pg_oauth_validator.spec.in) builds
`postgresql18-pg_oauth_validator`, with architecture-qualified `>=18.6`, `<19`
server dependencies and Fedora's `MODULE_COMPAT_18` ABI requirement. PostgreSQL
19 RPM packaging is not implemented. Distribution/architecture binaries are not
interchangeable. Only `MAJOR.MINOR.PATCH` versions are accepted.

Images retain hash-verified embedded dependency archives under
`/opt/rpm-dependencies`. Source0 comes from an exact full Git commit, excluding
working-tree edits; the current generated spec is a separately hashed input.
Prepare and build offline, as in this native arm64 example:

```sh
python3 tests/ci/test_rpm_sources.py
mkdir -p dist
docker run --rm --network=none --entrypoint python3 \
  -v "$PWD:/workspace:ro" -v "$PWD/dist:/output" \
  pg-oauth-validator-rpm-test:fedora44-arm64 \
  /workspace/scripts/ci/prepare-rpm-sources.py prepare \
  0.0.0 "$(git rev-parse HEAD)" /opt/rpm-dependencies /output/rpm-inputs

docker run --rm --network=none --tmpfs /source:exec --entrypoint /bin/sh \
  -v "$PWD:/workspace:ro" -v "$PWD/dist/rpm-inputs:/inputs:ro" \
  pg-oauth-validator-rpm-test:fedora44-arm64 \
  /workspace/scripts/ci/test-rpm-package.sh /inputs
```

Use the corresponding image for Fedora 43 or Rocky 10; on x86-64 use the image
name without `-arm64`. Preparation refuses to overwrite an existing input
directory. Review and retain it, or select a new output directory for a new run.
To fetch the reviewed archives separately, run
`python3 scripts/ci/prepare-rpm-sources.py fetch /path/to/dependencies`; fetching
is the only online operation and never substitutes an unreviewed archive.

The gate builds unprivileged with normal RPM hardening/debug checks and private
PIC dependency builds; it cannot reuse `/usr/local` libraries or networking.
It checks complete SRPM sources, ABI/dependency bounds, licenses, linkage,
permissions, symbol, scriptlet absence, installation, real OAuth, file digests
and removal. Packages contain optional bitcode, documentation, full licenses,
bundled-library metadata and a `BUILD-SOURCE` inventory. They do not change
configuration, provision roles or restart services. Unsigned test RPMs are not
release provenance.

## Upgrade and rollback rehearsal

Prepare a second version and pass both retained input directories:

```sh
docker run --rm --network=none --entrypoint python3 \
  -v "$PWD:/workspace:ro" -v "$PWD/dist:/output" \
  pg-oauth-validator-rpm-test:fedora44-arm64 \
  /workspace/scripts/ci/prepare-rpm-sources.py prepare \
  0.0.1 "$(git rev-parse HEAD)" /opt/rpm-dependencies /output/rpm-candidate

docker run --rm --network=none --tmpfs /source:exec --entrypoint /bin/sh \
  -v "$PWD:/workspace:ro" -v "$PWD/dist/rpm-inputs:/inputs:ro" \
  -v "$PWD/dist/rpm-candidate:/candidate:ro" \
  pg-oauth-validator-rpm-test:fedora44-arm64 \
  /workspace/scripts/ci/test-rpm-package.sh /inputs /candidate

python3 tests/ci/test_rpm_upgrade.py
```

Omit the second input for install/authenticate/remove only. The two-version gate
stops PostgreSQL before each transaction and performs A -> B -> A in one cluster,
checking retained data, new processes, untouched operator configuration, changed
candidate audience, rejected implicit downgrade, explicit `--oldpackage`
rollback and exact restored module/configuration digests and permissions.
Every phase checks verified TLS, acceptance/denial, rotation, outage/recovery,
protected administration and redaction. Never weaken trust policy to recover.

Compatibility CI's `0.0.0`/`0.0.1` use the same source and prove transaction
mechanics only. Real release evidence must consume retained previous/candidate
artifacts with reviewed configuration migration. Retain package and matching
configuration together; restart on replacement or rollback.

## Locked release-candidate inputs

`rpm-builders.yml` captures complete native builder images for all six targets.
The [lock](../packaging/rpm/builders.lock.json) binds archives, inventories, image
configuration and tools to hashes/sizes, source/base identity, artifact ID and
run ID. Verify before Docker load, then check native architecture, OS, image ID
and labels. Missing/expired/mismatched inputs fail without online replacement.

`RPM candidate rehearsal` loads these images on two fresh native runners per
target, builds offline with pulling disabled, and requires byte equality of full
binary/debug RPMs, SRPMs, source/spec inputs and inventories. Fixed exclusive
build roots preserve reproducibility without suppressing hardening; pre-existing
roots fail. `rpm-release.py` seals bundles and checks sanitized lifecycle receipts
against actual retained files. Exports exclude tokens, keys and raw server logs.

The recorded baseline is rebuilt v0.1.2 source at
`56dfb631718acd2a17d2608729f10bd015fe6f2d`, not previously published RPMs;
0.1.3 was [published as a prerelease](releases/0.1.3-prerelease.md); workflow
defaults still name that historical candidate. Select a new version for future
release preparation. Baseline assertions use its exact release contract with
the current isolated transport fixture. The candidate runs the current suite;
both run shared lifecycle, denial, redaction and recovery probes. No negative
assertions are removed. See [ADR 0007](adr/0007-frozen-rpm-release-builders.md).

For local comparison, export each candidate into an empty mounted directory
with `RPM_CANDIDATE_EXPORT_DIR`, then run:

```sh
python3 tests/ci/test_rpm_candidates.py
python3 scripts/ci/check-rpm-candidates.py /path/to/first /path/to/second
```

The comparator rejects missing/changed files, symlinks and special files.
Exports alone do not run the two-version gate. CI retention is 90 days; approved
inputs/evidence need durable storage and verified restore before expiry, subject
to the [scoped 0.1.3 exception](release-readiness.md#limited-prerelease-retention-decision-2026-10-24).
Signatures and the dated [dependency review](rpm-dependency-review.md) remain
separate approval gates. Support requires all packaging/lifecycle/security
checks, reviewed vulnerabilities, reproducibility and enforcing SELinux evidence
for the exact distribution and architecture. Existing enforcing evidence covers
Fedora 44 x86-64 only.

## SELinux enforcing gate

Run from a clean checkout without persisted Git credentials on Linux with
writable `/dev/kvm`, QEMU, `cloud-localds`, curl, OpenSSH and tar:

```sh
sh scripts/ci/test-selinux-vm.sh
```

This boots a hash-pinned Fedora 44 x86-64 Cloud guest, builds/installs the tested
RPM, and runs the complete suite under `postgresql_t` with global enforcement
and no domain-permissive exception. Guest repositories remain mutable.
Only fixture files/ports receive test labels; installed files retain distribution
labels. Unit journals supply protected diagnostics/redaction assertions.

The gate first requires a fresh provider `name_connect` AVC and authentication
denial, installs the reviewed optional grant, runs the suite, removes the grant
and proves denial again in a fresh cluster so cached keys cannot mask removal.
It enables audit visibility, checks lost records, restores diagnostic suppression
and verifies the RPM payload. Audit adjustments grant no access and are not
operator prerequisites. No token files, provider keys or raw PostgreSQL logs
are uploaded. See ADR 0006 for the confinement/audit design and evidence limits.

Investigate denials using `ausearch --input-logs -m AVC,USER_AVC -ts recent`.
Do not disable enforcement, make PostgreSQL permissive, enable broad networking
booleans or blindly install `audit2allow` output. Missing permissions must leave
authentication denied; any additional permission requires separate review.

## Optional HTTP-port policy

The shipped example `docs/selinux/pg_oauth_https.cil` adds exactly one permission:
`postgresql_t` may initiate TCP connections to ports labeled `http_port_t`.
Installation of the RPM does not load this policy. After reviewing it against
the host's requirements, an administrator can load the RPM-owned copy:

```sh
semodule -i /usr/share/doc/postgresql18-pg_oauth_validator/docs/selinux/pg_oauth_https.cil
```

This permission applies to **every process in `postgresql_t`**, including other
PostgreSQL instances and extensions, and **every port of that type**. The type
also includes HTTP ports; it does not enforce TLS, a hostname, or an individual
library. The validator continues to enforce its configured issuer host, HTTPS,
certificate verification, and redirect/proxy prohibitions. Review other code
running in this domain and any host egress controls. Inspect custom provider
port labels before changing them; do not overwrite another service's mapping
blindly. This example does not grant DNS, general filesystem, arbitrary-port,
or unconfined-domain access.

To remove the added permission:

```sh
semodule -r pg_oauth_https
```

Removal prevents the additional network access; it does not revoke keys already
in the validator's cache. Follow the documented cache/outage policy, or restart
the server when immediate cache invalidation is required. An absent, rejected,
or removed module must leave a fresh validator unable to retrieve keys; the VM
regression checks this denial and secret redaction before installation and after
removal. Kernel/audit visibility changes in the disposable test VM are diagnostic
steps, not operator prerequisites for the module.
