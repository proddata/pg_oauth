# Release readiness

This is the reusable publication checklist. Dated evidence belongs in
[releases/](releases/), the [RPM dependency review](rpm-dependency-review.md),
and the [security traceability snapshot](security/initial-review-traceability.md).
Passing checks establishes evidence for exact inputs, not general production
readiness. Installation and recovery procedures are in [operations](operations.md).

## Version and tag policy

Use SemVer `MAJOR.MINOR.PATCH`; `0.x.y` releases are GitHub prereleases even
without a suffix. Later prereleases use a suffix such as `-rc.1`. Source version,
notes, manifest, archive, annotated tag and checksums must agree. Patch releases
must not intentionally broaden trust. Configuration, identity, cache, ABI or
trust-policy changes need migration notes and an appropriate version increment.

Tag the reviewed commit on `main` with a signed, annotated `vVERSION` tag from
an approved release key. Never move or reuse a published version/tag. The
`Release draft` workflow verifies tag type, name, ancestry, exact target and
GitHub signature status; the owner must separately confirm the signer is
approved. It reruns CI/CodeQL, builds per-major archives, runs Keycloak interop,
verifies artifacts/manifests and creates a draft with `SHA256SUMS`.
It does not publish or attach RPMs. Manual `Release candidate` runs support
pre-tag rehearsals.

## Release record and required checks

Record the following against the exact reviewed source revision, with no
uncommitted or untracked release inputs:

- Version, tag, full commit, tree status and `SOURCE_DATE_EPOCH` (normally the
  commit timestamp); OS/architecture, image digests, compiler/linker versions,
  exact PostgreSQL version, package inventory and immutable dependency inputs.
- Commands/results for every required check, including explained expected
  skips; CI evidence must use the tagged commit and the same pinned inputs.
- Archive/manifests/checksums/signatures, rollback artifact IDs, known limits,
  reviewer and release approver, and compatibility/migration notes.

Complete [development gates](development.md#quality-and-packaging-gates), the
full `test-pg18`/`test-pg19` suites, static analysis, CodeQL, dependency/license
and secret scanning, installed-path tests, TLS/robustness and provider interop.
A release that includes the PAM module also passes the PAM gate below.
Required failures, unexpected skips, flakes or unreproducible results block
publication. Do not normalize reruns until green.

## PAM module gate

The PAM module is experimental until [ADR 0009](adr/0009-pam-cache-and-module-isolation.md)'s
release gate is met. Do not call a release production-ready for PAM, or remove
the experimental label from [PAM](pam.md) and `FEATURES.md`, until all of the
following hold for the exact reviewed commit:

- `make pam-check-pgNN` passes on every PostgreSQL major 15 to 19 and
  `make pam-both-check-pgNN` on 18 and 19, with no unexpected skips (the CI
  `PAM module / PostgreSQL N` jobs), and `make check-modules-disjoint` passes.
- Every row of the PAM section of the
  [traceability matrix](security/initial-review-traceability.md#pam-module-experimental-and-the-adr-0009-release-gate)
  is **Covered**, or its gap is closed by a recorded, dated decision that names
  a reviewer. Open gaps today are capacity isolation, lock contention, a killed
  refresh owner and slow-DNS behavior.
- The RPM subpackage and the SELinux enforcing run pass on each packaged
  platform ([RPM platforms](rpm-platforms.md)), with PAM upgrade and rollback
  rehearsed using matching module and configuration.
- Any PAM-specific operator documentation change is reviewed with the release,
  including the libpam preload requirement on PostgreSQL 15 and 16.

A `0.x` prerelease may ship the module while it stays experimental, with the
open gaps stated in its release notes.

## PostgreSQL-specific artifacts

Build/test/install/retain each PostgreSQL major separately; cross-major module
ABI compatibility is not provided. Run `make installedcheck` only in disposable,
suitably privileged per-major environments. Build each archive with:

```sh
SOURCE_DATE_EPOCH=... make release-package \
  RELEASE_VERSION=... PG_CONFIG=/path/to/postgresql-18/bin/pg_config \
  RELEASE_OUTPUT="$PWD/dist/pg18"
```

Repeat with PostgreSQL 19 and a separate output path. The target stages and
checks installation, normalizes archive metadata, and emits `BUILD-MANIFEST`
and SHA-256. Inspect per-file digests, exact PostgreSQL release and full licenses;
prove each package rejects the other major's environment.

Debian image digest, snapshot and exact package versions in
`scripts/ci/install-debian-dependencies.sh` are one reviewed input set. Record
them in the manifest; missing versions must fail rather than select newer ones.

Build twice in fresh environments using identical inputs and compare archive
digests and unpacked manifests. Unexplained differences block release. The
candidate/draft workflow's same-environment check and `RELEASE-EVIDENCE.md`
record do not replace this fresh-environment rehearsal. For experimental RPMs,
use the separate six-target [locked-builder gate](rpm-platforms.md#locked-release-candidate-inputs).
Retain approved inputs and artifacts durably and verify restoration before CI
expiry, subject only to the scoped prerelease exception below.

## Dependency, license, and vulnerability review

For every release:

1. Inventory direct/transitive build and runtime dependencies using package
   records, pkg-config and staged-module `ldd`; reconcile with ADR 0001. Verify
   embedded PIC libjwt/Jansson and vendor-supported system OpenSSL/libcurl.
2. Verify installer commits/hashes and review upstream changes. Dependency
   updates require the spike, boundary tests, sanitizers and fuzz smoke.
3. Review all component versions/licenses and notice/source-offer obligations.
   Require `LICENSE`, `THIRD-PARTY-NOTICES.md`,
   `THIRD-PARTY-LICENSES/JANSSON` and `THIRD-PARTY-LICENSES/LIBJWT-MPL-2.0`
   in each archive/manifest, with matching notice paths.
4. Query vendor trackers and official upstream advisories; record date,
   identifiers, applicability and disposition, including vendor backports.
   Scanners support but do not replace applicability review.
5. Review GitHub alerts, secret/code scanning and CI for the tagged commit.
   Waivers need a named reviewer, rationale, expiry and follow-up issue.

Exploitable unpatched authentication-path vulnerabilities, unsupported runtime
libraries, integrity mismatches and unresolved licenses block publication.
The dated [RPM review](rpm-dependency-review.md) records owner-reported review
and a scoped Rocky exception; it is not blanket security or release approval.

## Installation, upgrade, and rollback rehearsal

For each supported major, use a representative disposable staging environment:

1. Install cleanly; verify manifest, ownership, permissions, linkage, callback
   symbol and optional bitcode. Run the installed-library integration suite.
2. Prove mapped low-privilege access, protected non-OAuth administration and
   denial of wrong issuer/audience/scope/type, unmapped and administrative-role
   attempts. Check server/client redaction.
3. Upgrade the previous package and matching configuration; restart, then test
   rotation, provider outage/recovery, freshness and reloads.
4. Restore the retained previous package and its exact matching configuration,
   restart and repeat acceptance/denial/redaction probes. Verify restored digests.
5. Recover from provider failure and invalid configuration using only the
   protected recovery path. Never weaken issuer, audience, algorithm, type,
   scope, TLS or role-mapping policy to recover.

Replacing a loaded library requires restart. RPM same-source transaction tests
are not compatibility evidence between actual releases.

## PostgreSQL 19 prerelease-to-final gates

Keep preview labeling until final source/packages are available and reviewed:
replace prerelease pins with exact final digests, rebuild with final server/libpq
headers, and record `pg_config --version`. Review OAuth callbacks, custom HBA,
memory/error, shared-memory and PGXS contracts against final source/release notes,
including changes since the tested prerelease. Repeat every quality gate above,
clean installation, PostgreSQL 18 coexistence and upgrade/rollback rehearsals.
Update features, operator compatibility and notes only after evidence approval.
Never relabel a prerelease-built module as a final PostgreSQL 19 module.

## Approval and publication

A `0.x` maintainer may self-review and approve; record final diff inspection,
denial behavior, secret exposure, security changes, test gaps/results and risks.
From `v1.0.0`, security-sensitive review and release approval require someone
other than the author. Verify approved-key signatures on final archives and
checksums, upload/verify them, and record approval before publishing the draft.
Checksums alone are not provenance or vulnerability approval.

Missing evidence/signatures, secret disclosure, unresolved high-impact findings,
failed lifecycle tests, incomplete major separation or authorization on
uncertainty block publication. Retain rejected inputs/evidence, identify the
last known-good version and track corrective action. Fix inputs/source and use
a new version/tag; never overwrite rejected artifacts. PostgreSQL 18 and 19 may
be promoted independently unless they share the defect or version contract.

## Limited prerelease retention decision, 2026-10-24

For the provisional **0.1.3 prerelease**, the deployment owner (`proddata`)
explicitly deferred additional durable storage while the project is not yet
production-ready. Existing CI retention is accepted for this prerelease:
RPM builder/candidate/evidence artifacts have a 90-day retention setting;
PostgreSQL release-candidate archives have a 14-day retention setting. Each
artifact's actual expiry is determined by its upload time and GitHub policy.
The locked builder capture predates the candidate, so a candidate rebuild does
not extend builder retention. Local copies are convenience copies, not a
verified backup.

This is a prerelease-only exception to the durable-retention requirement above, not a
claim of durable recovery or a relaxation of integrity/authentication tests.
After expiry, archived inputs may be unavailable and exact reproduction or
rollback may no longer be possible. Missing locked inputs must still fail
closed; never substitute current repository packages. Before production
promotion, arrange durable retention and verify a restore, or capture/review new
inputs and rerun affected gates if the original inputs are unavailable.

The dependency/security and license review is owner-reported complete, subject
to the scoped Rocky exception in the RPM review record. Final candidate checks,
source/version identity, signatures and release-owner approval still apply.
No release tag or publication is authorized merely by preparing a candidate.
