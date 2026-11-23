# PostgreSQL 19.0 compatibility check

- **Review date:** 2026-11-23
- **PostgreSQL package:** `19.0-1.pgdg12+1`
- **Container:** `postgres:19.0-bookworm@sha256:f4859caf96de494e38efa69ed703b08a5bbd9605e152e604f2daec8841c87c41`
- **Debian snapshot:** `20261104T212339Z`
- **Reviewed revision:** `1f1e6b1409c72ae1be46d0b6a20a519563986437` (merged as `a829cf1`)
- **Architecture tested locally:** `aarch64`; CI also covers `x86_64`
- **Status:** evidence recorded; support-status labels unchanged pending
  maintainer approval of this record

PostgreSQL 19.0 was released on 2026-11-19, together with the 18.7, 17.12,
16.16 and 15.20 minor releases. This record covers the
[prerelease-to-final gates](../release-readiness.md#postgresql-19-prerelease-to-final-gates)
for the validator and the PAM module. It replaces the
[RC1 check](pg19-rc1-compatibility.md) as the current source review.

## Source review: RC1 to 19.0

The official `postgresql-19rc1.tar.bz2` and `postgresql-19.0.tar.bz2` archives
were compared after verifying each against its published SHA-256
(`af105fc8…d701` and `a89fd70e…692d`).

Byte-for-byte unchanged between RC1 and 19.0:

- the OAuth validator callback header (`libpq/oauth.h`) and
  `common/oauth-common.h`;
- the HBA implementation and header (`libpq/hba.c`, `libpq/hba.h`) and
  `libpq/auth.c`, so the custom HBA option API behind `validator.policy` is
  unchanged;
- the shared-memory, DSM-registry, LWLock, condition-variable and
  wait-event APIs the shared cache uses (`storage/dsm_registry.{h,c}`,
  `storage/lwlock.h`, `storage/shmem.h`, `storage/ipc.h`,
  `storage/condition_variable.h`, `utils/wait_event.h`);
- the GUC API (`utils/guc.h`, `guc.c`), `miscadmin.h`, and every PGXS file
  (`pgxs.mk`, `Makefile.global.in`);
- the module magic block in `fmgr.h` (`Pg_magic_struct`, `FMGR_ABI_EXTRA`).

Changed, and reviewed:

1. **`auth-oauth.c`: validator allowlist is re-checked at connection start.**
   If a reload failed after `oauth_validator_libraries` was changed, PostgreSQL
   kept the old HBA lines; 19.0 now re-checks the allowlist in `oauth_init()`
   before loading the validator and fails the connection with the generic
   authentication error (details only in the server log). It also rejects an
   empty quoted name in `oauth_validator_libraries`. Both changes only tighten
   behavior. They are server-side checks that run before this module is
   loaded; the module's callbacks and result handling are unaffected. The
   project does not test this behavior itself: it belongs to PostgreSQL.
2. **`fmgr.h`: `DatumGetHeapTupleHeader*` became functions.** The project does
   not use `HeapTuple` APIs.
3. **`c.h`, `utils/elog.h`, `varatt.h`:** comment changes and one new
   declaration (`HaveCompleteError()`); no layout or macro behavior used by the
   project changed.

No validator, PAM or shared-cache source change was required.

## Local gate results

Run against the pinned 19.0 and updated minor images:

- `docker compose -f compose.test.yml run --build --rm pg19 dev-test-pg19`:
  strict C17 build, unit/component checks and the real PostgreSQL integration
  suite (**59 passed**).
- `dev-test-pg18` against 18.7: **57 passed, 2 PostgreSQL-19-only tests
  skipped**.
- `pam-check-pg15`, `pam-check-pg16`, `pam-check-pg17`: **74, 74, 73 passed**;
  `pam-both-check-pg18` and `pam-both-check-pg19`: **7 passed** each (PAM
  suites need `OAUTH_TEST_PAM_DISPOSABLE=1`).
- Keycloak 26.5.0 interoperability on PostgreSQL 19.0: **1 passed**.
- `tests/ci/test_prepare_release_draft.sh` and the RPM source tests passed.

## CI results

All 50 checks passed on the reviewed revision, including `PostgreSQL 19 /
Clang / C17` (which also runs the AddressSanitizer/UndefinedBehaviorSanitizer
component checks and the fuzz smoke suite against 19.0) and `GCC / C17`, the
PAM jobs for PostgreSQL 15 to 19, C
formatting and Clang static analysis, CodeQL, Keycloak interoperability, the
Fedora and Rocky Linux 10 RPM jobs and the SELinux enforcing VM gate.

Rocky Linux 10 needed two input changes first: PGDG replaced its
`pgdg-redhat-repo` RPM, and the PGDG 18.7 EL10 development package expects
LLVM 21 while Rocky ships LLVM 22, so that build omits the optional LLVM
bitcode (see [RPM platforms](../rpm-platforms.md#enterprise-linux-10-bitcode)).

## Not yet done

These release-readiness gates were **not** run for 19.0 and block relabeling
PostgreSQL 19 as a production target:

- clean-installation, PostgreSQL 18 coexistence and upgrade/rollback
  rehearsals with a 19.0-built release package;
- a release-candidate build of the PostgreSQL 19.0 archive (the manually
  dispatched `release-candidate` workflow was not run);
- maintainer approval of this evidence.

Until those pass, PostgreSQL 19 keeps its preview labeling in
[`FEATURES.md`](../../FEATURES.md) and the operator documentation.
