# Architecture

[FEATURES.md](../FEATURES.md) defines the security contract;
[ADRs](adr/) explain design choices. This guide maps that contract to code.

## Source layout

The repository holds two independent PostgreSQL modules built on one shared
validation core:

| Directory | Contents |
|---|---|
| `shared/` | The validation pipeline and everything it uses: JWT envelope, JWKS, signature, claims, identity, metadata and key retrieval, HTTP transport and freshness, the canonical cache key and cache state, shared-memory cache access, and policy. It contains no validator callback or PAM entry point and depends on neither module. `shared/validator.c` is the module-independent pipeline. |
| `validator/` | The native OAuth validator module (`pg_oauth_validator`, PostgreSQL 18 and 19): the PostgreSQL callback glue (`pg_oauth_validator.c`), the GUCs (`config.c`) and matched-HBA access (`hba_policy.c`). |
| `pam/` | The PAM module (`pg_oauth_pam`, PostgreSQL 15 to 19): the PAM entry points, the stack-argument parser, credential handling and its cache namespace. |

A source file may include a project header only from its own directory or from
`shared/`. `scripts/ci/check-source-tree.sh` enforces this, so shared code never
depends on a module and the two modules never depend on each other. Module,
library and setting names (`pg_oauth_validator`, `pg_oauth_pam`, the
`pg_oauth_validator.*` and `pg_oauth_pam.*` settings) are unchanged by the
directory layout.

## Validation path and trust boundaries

`pg_oauth_validator.c` initializes callback outputs to denial/NULL and adapts
PostgreSQL results and memory ownership. `hba_policy.c` isolates version-specific
matched-HBA access and PostgreSQL 19's `validator.policy=default` selector.
`config.c` and `policy.c` combine administrator/HBA inputs into validated policy.
Token claims never select the trusted issuer.

`validator.c` composes these boundaries, authorizing only when all succeed:

| Boundary | Implementation |
| --- | --- |
| Bounded compact JWS, canonical Base64URL, duplicate JSON and header policy | `jwt_envelope.c`, `base64url.c` |
| Issuer-derived discovery, exact issuer and allowed JWKS URL | `metadata.c`, `issuer_key.c` |
| Bounded HTTPS, exact hosts, TLS verification, no redirects/implicit proxies | `http_transport.c` |
| Unique trusted key and local algorithm/key constraints | `jwks.c` |
| Signature under the selected key/algorithm | `signature.c`, reviewed libjwt/OpenSSL |
| Post-signature issuer, audience, time, scope and identity/role claims | `claims.c` |
| Bounded unchanged authenticated identity | `identity.c` |

Library parsing and time defaults do not establish project policy. Rejected
results retain no authenticated identity. PostgreSQL gets generic client errors;
protected logs get stable non-sensitive diagnostics.

PostgreSQL applies exact identity comparison or `pg_ident.conf` unless HBA
explicitly delegates mapping. Delegated mode additionally requires a configured
role claim and exact requested-role membership; HBA independently limits roles.
Examples and settings belong in [configuration](configuration.md).

## Shared cache

`cache_key.c` builds versioned length-prefixed keys containing the exact resource
and complete trust policy; equality compares full bytes rather than a hash.
`cache_state.c` performs bounded, allocation-free transitions using injected
monotonic time: fresh/stale lookup, single-owner refresh, unknown-key cooldown,
failed-refresh preservation and deterministic expired-LRU eviction.
`http_freshness.c` interprets bounded cache headers under local caps.
[ADR 0002](adr/0002-metadata-jwks-cache-and-outage-policy.md) defines policy.

`shared_cache.c` stores fixed-size validated payloads in a versioned named DSM
segment, without preload configuration. PostgreSQL 18/19 compatibility branches
isolate named-DSM initializer and tranche API differences. An LWLock protects
bounded copies and state transitions; publication updates bytes/freshness
atomically and rejects obsolete refresh owners. Network operations and bounded
condition-variable waits happen after releasing the lock.

`issuer_key.c` publishes metadata only after issuer/URL checks, and JWKS only
after strict parsing and requested-key selection. Fresh entries avoid HTTP;
unknown keys permit bounded refresh. Eligible stale JWKS fallback is explicitly
configured; metadata is never used stale. Complete policy keys isolate reloads.
No tokens, claims or authenticated identities enter the cache.

A separate test-only library probes cache behavior across real backends; it adds
no SQL surface to the production module. Real OAuth integration exercises the
same cache and callback. Verification commands are in [development](development.md).
