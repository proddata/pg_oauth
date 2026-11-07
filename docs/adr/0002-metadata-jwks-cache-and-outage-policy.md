# ADR 0002: Metadata/JWKS cache and provider-outage policy

- Status: Accepted for Milestone 1 implementation
- Date: 2026-08-08
- Scope: Strict offline JWT validation for PostgreSQL 18 and 19

## Context

The validator needs authorization-server metadata and public signing keys, but
making both HTTP requests for every database connection would add provider
latency and availability to every authentication attempt. It would also turn
attacker-controlled connection attempts and unknown `kid` values into outbound
request amplification.

Conversely, retaining signing keys indefinitely can continue trusting removed
or compromised keys. A provider outage must never turn an unverifiable token
into an accepted token, and configuration reloads must not leave cache entries
valid under a changed trust policy.

PostgreSQL backends are separate processes. A process-local cache would provide
little benefit during connection authentication, while requiring the validator
to be listed separately in `shared_preload_libraries` would add an unnecessary
operator contract. PostgreSQL 18 provides `GetNamedDSMSegment()` for bounded
shared state created and initialized safely after server startup.

RFC 9111 distinguishes fresh and stale responses, prohibits stale reuse unless
explicitly permitted, and requires `must-revalidate` to be honored. RFC 8414
requires HTTPS metadata/JWKS locations and exact issuer validation remains an
independent trust check; HTTP cache metadata never establishes issuer trust.

## Decision

### Shared cache shape

Use one fixed-size named dynamic shared-memory segment per PostgreSQL instance.
Do not require `shared_preload_libraries`.

The segment contains a fixed maximum number of entries and fixed-size bounded
metadata. Response bodies are stored only after transport bounds, strict JSON
parsing, exact issuer validation, URL policy, and JWKS validation succeed. No
bearer token, JWT payload, authenticated identity, secret, or complete claims
are cached.

Each entry is keyed by all trust-relevant inputs:

- exact issuer;
- exact metadata URL;
- exact JWKS URL returned by validated metadata;
- named provider policy/profile;
- allowed algorithms and key constraints;
- discovery/JWKS host policy; and
- all remaining trust-policy limits and authorization inputs.

The bounded canonical key material is versioned and compared in full before
reuse; an implementation may use a hash only as an accelerator, never as
equality. Cache capacity, response sizes, URLs, key counts and key identifiers
remain bounded. When capacity is exhausted, replacement is
deterministic and prefers an expired least-recently-used entry that is not being
refreshed. If no safe victim exists, the request fails closed.

### Freshness

Metadata and JWKS freshness are tracked separately using monotonic time for
elapsed intervals. Wall-clock HTTP dates may inform freshness but never replace
monotonic expiry inside a running server.

- Honor valid `Cache-Control: max-age` and `Expires` values, capped by a local
  administrator maximum.
- Honor `no-store` by not retaining the response beyond the current validation.
- Honor `no-cache` and `must-revalidate` by requiring successful revalidation
  before reuse once fresh use ends.
- Treat malformed or conflicting freshness directives conservatively as an
  immediately stale response. The current validated response may still serve
  its initiating request, but it is not reusable without revalidation.
- When no usable explicit freshness exists, apply a bounded local default TTL.
- Never extend a provider's shorter explicit freshness lifetime up to the local
  default. The local setting is a fallback and upper bound, not a minimum.

Defaults and accepted ranges are maintained in
[configuration](../configuration.md#metadata-and-jwks-cache).
`cache_max_ttl` must be at least both fallback TTLs; inconsistent values fail
closed. Reloadable trust inputs participate in canonical keys;
`refresh_wait_timeout` affects scheduling only. Capacity determines shared-memory
layout and requires restart.

`jwks_stale_grace = 0s` is the fail-closed default. An operator may explicitly
choose a short nonzero value, bounded to at most one hour, as an availability
tradeoff. Metadata has no stale grace in Milestone 1: expired metadata must be
successfully refreshed before a changed or newly discovered JWKS URL can be
trusted.

### Outage behavior

On metadata or JWKS retrieval failure:

1. A still-fresh, policy-matching cached entry may be used.
2. An expired metadata entry is not used to discover or authorize a JWKS URL.
3. An expired JWKS entry may be used only when `jwks_stale_grace` is nonzero,
   the entry is within that bound, the response did not require revalidation,
   and every trust-policy input still matches exactly.
4. Otherwise validation fails closed with a stable, non-sensitive diagnostic.

Stale-key use never skips signature, issuer, audience, token type, expiry,
scope, or identity validation. It only supplies previously validated public
verification keys. Successful refresh atomically replaces an entry; a failed
refresh never destroys an otherwise permitted fresh or stale entry.

### Rotation and request suppression

A JWT referencing an unknown `kid` may cause at most one JWKS refresh during
that validation attempt. Refresh is additionally limited by the exact issuer
entry's monotonic cooldown. Attacker-selected `kid` values are not part of the
cache key and cannot create cache entries or bypass the cooldown.

A fetched key set that is well-formed but cannot serve the token's key
(`kid` not present, algorithm mismatch, key not for signatures) is still the
provider's current key set and is published like any other refresh; only that
token is denied. Discarding it would keep a cold or expired cache empty, so the
cooldown above could never apply and each hostile token would cost two provider
requests. The cooldown clock starts with the first refresh that begins on an
unknown `kid`, so a flood against an empty cache causes at most two JWKS
requests before suppression. Documents that fail validation, and keys carrying
private material, are never published. Publishing adds no trust: cached bytes
are parsed and checked again on every lookup.

Only one backend marks an entry as refreshing. The shared lock protects brief
lookup, copy, state-transition and replacement operations only. It is released
before DNS, connection, TLS or HTTP work. Other backends may use an eligible
fresh/stale snapshot. If none exists, they sleep on a shared condition variable
for a bounded, operator-configured time without holding or polling a PostgreSQL
lock. Refresh completion wakes waiters, which re-check the exact canonical
entry and proceed only with an eligible published value. A zero timeout retains
immediate fail-closed behavior.

Signature failure with a known key does not automatically trigger refresh in
Milestone 1. This avoids turning arbitrary invalid signatures into outbound
traffic. A future change requires a separate threat analysis and tests.

### Reload and invalidation

Every lookup recomputes the versioned canonical key from the complete effective
trust policy. A mismatch makes the entry ineligible immediately, even if its
TTL has not expired. Reload changes to issuer, metadata URL, audience/profile,
algorithms, key limits, TLS/host policy, or stale policy therefore cannot reuse
an entry created under the old contract.

Reducing cache bounds or changing the cache's shared-memory layout requires a
PostgreSQL restart. Reloadable policy changes use canonical-key invalidation and
lazy bounded replacement; raw old entries are never accepted under the new
canonical key.

### Diagnostics and observability

Expose aggregate bounded counters for fresh hit, refresh, refresh suppression,
stale use, eviction and failure. Logs use stable codes and exact configured
issuer/profile identifiers only where PostgreSQL log policy permits. Never log
tokens, signatures, JWK private material or response bodies.

## Consequences and rejected alternatives

Fixed shared memory bounds resource use and shares fresh keys across backends.
Per-connection fetching amplifies attacker/provider load; process-local caching
cannot serve new authentication backends. Indefinite or default stale reuse
would silently extend removed-key trust. Holding locks during network work would
let provider latency block unrelated backends. libjwt's cache cannot enforce
this project's issuer, reload and outage rules.

## Verification

Cache unit tests cover injected time, exact keys, capacity/expired-LRU eviction,
ownership tokens, obsolete-owner denial, atomic publication, freshness directives,
cooldown and failed-refresh preservation. Component tests cover HTTP freshness
and issuer retrieval; real PostgreSQL tests cover cross-backend publication,
bounded waits, network work outside locks, policy reload separation, rotation,
outage/recovery and redaction on both majors. See
[architecture](../architecture.md) for implementation and
[development](../development.md) for commands. Detailed development progress is
retained in Git history rather than maintained in this decision.

## References

- PostgreSQL 18, C-language functions: dynamic shared memory and LWLocks
- PostgreSQL 18/19, OAuth validator callbacks
- RFC 8414, OAuth 2.0 Authorization Server Metadata
- RFC 9111, HTTP Caching
- RFC 9068, JWT Profile for OAuth 2.0 Access Tokens
