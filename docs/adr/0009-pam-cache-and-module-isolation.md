# ADR 0009: PAM cache storage and module isolation

- Status: Proposed; bridge feasibility required before production PAM release
- Scope: PostgreSQL-only Linux-PAM module on majors 15, 16, 17, 18 and 19 preview
- Implementation language: C17

## Context

PostgreSQL uses separate backend processes. A process-local cache usually
disappears with each new authentication backend and cannot suppress refresh
storms across connections. [ADR 0002](0002-metadata-jwks-cache-and-outage-policy.md)
already defines bounded metadata/JWKS cache semantics and PostgreSQL named-DSM
storage without preload configuration. [ADR 0008](0008-postgresql-pam-token-authentication.md)
makes PAM an independent module that may be installed with or without the OAuth
validator.

## Decision

Reuse the existing C cache implementation (`src/cache_state.c`, `src/cache_key.c`,
`src/shared_cache.c`) for PAM. The PAM module is PostgreSQL-specific and compiled
against each supported major; it is not a general-purpose system-login PAM
module. Real-backend feasibility and lifecycle evidence are required before the
packaging names and installed paths are finalized.

### Isolation from OAuth

PAM and OAuth use separate, versioned shared-memory namespaces so that neither
can consume the other's capacity or inherit its entries. Define one
administrator-owned capacity per namespace and reject conflicting capacities
from different profiles. All trust policy, service/profile and resource inputs
remain in canonical cache keys compared in full; hashes are accelerators only.
A policy reload cannot use entries created under different policy.

Because each module is optional, every mode (OAuth only, PAM only, both) must
work with the other module absent, and neither module may depend on the other's
cache existing. Each artifact links its validation and cache code privately and
binds symbols locally, so loading both in one process cannot cause either to
call into the other's copy or share mutable static state.

### Cache contents and behavior

Do not store requested identities or bearer tokens. Share only validated public
metadata/JWKS payloads and bounded control state across backends.

Preserve single refresh ownership, obsolete-owner rejection, atomic publication,
unknown-key cooldown independent of attacker-selected `kid`, preservation of the
last good set when a refresh fails, bounded waits and deterministic eviction.
Known-key invalid signatures do not trigger refresh. Metadata is never served
stale; stale JWKS use is explicit, bounded and disabled by default, and respects
response revalidation rules. Perform no network I/O and no waiting while holding
a lock.

Use versioned storage and reject an incompatible capacity or layout. Changing
capacity or replacing installed binaries requires a PostgreSQL restart. Cache
contents are disposable public data and are not migrated as authorization state.

### Majors without the named DSM registry (15 and 16)

`GetNamedDSMSegment` (`storage/dsm_registry.h`) exists on PostgreSQL 17 and later
but not on 15 or 16: the header is absent from the `REL_15_STABLE` and
`REL_16_STABLE` branches, while it is present on `REL_17_STABLE`. The no-preload shared cache from ADR 0002 therefore
works for PAM on 17, 18 and 19, but not on 15 or 16. `LWLockNewTrancheId` and
`LWLockRegisterTranche` are declared on 15, 16 and 17 (branch heads; confirm
the signatures against pinned releases).

PostgreSQL 15 and 16 obtain cross-backend refresh coordination through
`shared_preload_libraries`. The PAM module is also loadable as a preload library
and, from `_PG_init`, requests shared memory and a named LWLock tranche through
the `shmem_request_hook` and `shmem_startup_hook` mechanism. On the 15 and 16
branch heads inspected, `shmem_request_hook`, `shmem_startup_hook`,
`RequestNamedLWLockTranche` and `GetNamedLWLockTranche` are declared. Confirm the
exact behavior against pinned 15.x and 16.x releases before implementation.

Consequences:

- Enabling the cache on 15 and 16 needs a configuration change and a server
  restart; 17 and later need neither.
- If the module is not preloaded on 15 or 16, it must not fall back to a weaker
  cache. Refuse production use: deny authentication with a stable diagnostic and
  documented operator guidance, or run only in an explicitly configured
  experimental mode that is process-local and rate-limited. The default is deny.
- The same cache semantics, namespace isolation and capacity rules apply on
  every major. A major with a different storage mechanism must not weaken them.
- Whether preload and the libpam-loaded PAM module resolve to a single mapped
  copy, and the interaction of the two load paths in one process, is a gate in
  the release criteria below.

## Alternatives and consequences

- Process-local storage could support an experimental controlled-rate slice but
  does not meet the production refresh-coordination gate. It is not used on 15
  and 16 unless an administrator explicitly selects the experimental mode.
- Independent shared memory or files add tamper resistance, namespace
  permissions, locking and crash recovery to the trust boundary. Defer without a
  demonstrated need.
- A helper service adds authenticated IPC, availability and lifecycle costs.
  Current evidence does not justify a daemon.
- Separate namespaces cost some duplicated memory when both modules are used.
  This is accepted to keep the modes independent and failure domains separate.

## Release gate

Before a production PAM release, prove:

- cross-backend cooldown and refresh suppression;
- policy, reload and capacity isolation;
- owner failure, flood, outage and recovery behavior;
- bounded lock contention;
- installed paths, permissions and SELinux enforcement for the PAM module;
- OAuth-only, PAM-only and both-installed deployments, including loading both
  modules into one process in either order and verifying symbol and static-state
  independence;
- that removing or failing either module leaves the other's behavior unchanged;
- on 15 and 16, that a preloaded module and the libpam-loaded module share one
  cache without duplicate or divergent state, and that a missing preload denies
  authentication rather than weakening coordination.

Rollback restores matching per-major artifacts and configuration and restarts
the server. Never weaken validation to recover.

## References

- [ADR 0001](0001-jose-json-crypto-http-dependencies.md)
- [ADR 0002](0002-metadata-jwks-cache-and-outage-policy.md)
- [ADR 0008](0008-postgresql-pam-token-authentication.md)
- [Current storage implementation](../../src/shared_cache.c)
