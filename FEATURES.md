# Feature specification

## Purpose

This document defines the intended product behavior and security contract of the PostgreSQL OAuth validator. [`AGENTS.md`](AGENTS.md) defines engineering and contribution practices. The [architecture](docs/architecture.md) describes the implementation, and the [ADRs](docs/adr/) record design decisions.

The specification is deliberately narrower than the full roadmap. Features not listed as active are unsupported unless this document is updated through review.

## Product objective

Build a production-oriented PostgreSQL OAuth validator that accepts standards-compliant OAuth 2.0 access tokens for an explicitly configured PostgreSQL resource.

The validator keeps three decisions separate:

1. **Token validation:** Is this a genuine, currently valid access token issued by a trusted authorization server for this PostgreSQL resource?
2. **Authentication:** Which stable external principal does the token identify?
3. **Authorization:** May the validated principal connect to PostgreSQL under the configured access policy?

The validator supports PostgreSQL-owned identity matching and explicitly
delegated, claim-based role authorization. Both modes require complete token
validation and an authenticated identity.

## Implementation baseline

- The PostgreSQL module and validator callbacks are implemented in C17.
- PostgreSQL 18 is the stable production target.
- PostgreSQL 19 is a preview target during its prerelease period and will become a production target only after its stable release and final compatibility verification.
- Each PostgreSQL major version receives a separately compiled module and its own CI job because PostgreSQL does not provide cross-major ABI compatibility.
- The shared library uses PostgreSQL's native C ABI and PGXS build infrastructure.
- Protocol parsing and cryptographic primitives will come from reviewed, established libraries rather than bespoke implementations.
- The callback starts denied and authorizes only after the complete configured validation pipeline succeeds.
- Issuer and required scopes come from the matched HBA rule through a small, isolated PostgreSQL-internal compatibility adapter.
- PostgreSQL 19 registers `validator.policy` through the supported custom HBA option API; only `default` is accepted.
- A validated immutable policy combines matched-HBA issuer/scopes with configured audience, algorithms, token type, identity claim, clock skew, and token-size limit.
- Audience is mandatory and has no implicit default. Algorithms default to `RS256,ES256` (`EdDSA`, Ed25519 only, is available when the administrator lists it; see [`ADR 0003`](docs/adr/0003-eddsa-ed25519-support.md)), allowed token types to `at+jwt,application/at+jwt`, missing token type to denied, identity claim to `sub`, clock skew to 60 seconds, and maximum token size to 16 KiB.

## Active release scope: strict offline JWT validation

The active release scope provides strict offline validation of signed JWT access tokens:

- PostgreSQL 18 and 19 OAuth validator module initialization and callback integration, with version-specific result handling.
- Explicit trusted issuer configuration and exact issuer validation.
- OIDC discovery derived from the configured issuer at
  `/.well-known/openid-configuration`, followed by the validated `jwks_uri`.
- Explicit allowlist of the two RFC 9068 access-token type spellings. An
  administrator may allow a missing `typ` only when issuer-specific audience
  and scope rules distinguish access tokens from ID and session tokens.
- Local asymmetric signing-algorithm allowlist (`RS256`, `ES256`, and opt-in Ed25519 `EdDSA`).
- Hardened JWKS key selection and signature verification.
- Mandatory configured audience validation.
- Required expiry and stable authenticated identity.
- Bounded clock skew and resource limits.
- Required connection-scope validation using the strict `scope` claim and all
  scopes configured by the matched HBA rule.
- Configurable authenticated-identity claim, defaulting to `sub`.
- Direct authenticated-identity representation; every accepted token also has
  a valid `sub`, even when another identity claim is selected.
- Normal PostgreSQL exact-name/usermap authorization and opt-in delegated exact
  role-claim authorization.
- Controlled single JWKS refresh for legitimate signing-key rotation.
- Negative unit and integration test coverage for the threat model.
- Sanitized, stable diagnostic codes without token or secret disclosure.

## Active scope: PostgreSQL PAM token authentication (experimental)

An opt-in module accepted by [`ADR 0008`](docs/adr/0008-postgresql-pam-token-authentication.md)
and [`ADR 0009`](docs/adr/0009-pam-cache-and-module-isolation.md). It remains
experimental: the release gate in ADR 0009 and the evidence listed in ADR 0008
must be met before a production release, and no packaging, SELinux or
distribution qualification beyond what those documents record is claimed. It
exists for clients that can send a password but cannot perform native OAuth
authentication. It adds no token introspection or other authentication mechanism.

Supported PostgreSQL versions. The native OAuth validator targets PostgreSQL 18
and 19 only, because earlier majors have no validator API. The PAM module targets
PostgreSQL 15, 16, 17, 18 and 19 (preview), each compiled separately, so PAM is
the only supported path on 15, 16 and 17. Cross-backend cache sharing needs no
preload configuration on PostgreSQL 17 or later; PostgreSQL 15 and 16 require
the module in `shared_preload_libraries` and deny authentication without it (ADR 0009).

Deployment modes. The OAuth validator and the PAM module are independent,
separately built and installed modules that share validation source code but no
runtime state:

- **OAuth only (18, 19):** `pg_oauth_validator` with HBA method `oauth`. No PAM
  module or PAM dependency is installed.
- **PAM only (15, 16, 17, 18, 19):** `pg_oauth_pam` with HBA method `pam`. The OAuth
  validator is not required.
- **Both (18, 19):** HBA rules choose `oauth` or `pam` per rule. Installing or removing
  one module never changes the other's behavior, configuration or cache.

PAM contract, requiring a PAM-enabled PostgreSQL build:

- The credential is a raw compact JWT access token, validated by the same
  pipeline and token policy as OAuth. No `Bearer` prefix, trimming, truncation or
  alternate formats are accepted.
- By default authorization requires the validated identity (`identity_claim`,
  `sub` unless configured) to equal the requested database role exactly. No
  usermaps or `PAM_USER` changes.
- Setting the stack argument `role_claim=<claim>` selects delegated roles mode as
  for the native validator: the requested role must appear exactly in that claim
  (a string or an array of distinct, nonempty strings), the identity claim is
  still required but need not equal the role, privileged roles get no special
  treatment, and the HBA `USER` field remains the allowlist. The claim is part of
  the policy digest compared between the two stack lines and of every cache key.
- A dedicated PAM service with fail-closed, success-only controls is required;
  no `sufficient`/`optional` rules, `pam_permit`, system includes or password
  fallback. The module cannot protect a stack that skips it. HBA restrictions
  and `hostssl` with verifying clients remain mandatory deployment practice.
- Policy (issuer, audience, scopes and the other validator settings) is given as
  arguments in the dedicated PAM stack, selected per HBA rule by `pamservice`.
  Unknown, duplicate, missing or malformed arguments deny, and the authentication
  and account lines must carry identical policy.
- Account management rechecks expiry from bound transaction state (role,
  profile, policy generation, expiry) and never stores the token or claims.
- The default credential limit is 16 KiB and the hard maximum is 65530 bytes;
  oversized credentials are rejected, never truncated.
- PAM cache storage is isolated from OAuth's, with bounded cross-backend refresh
  coordination required before production release.
- Diagnostics are stable codes without credential-derived text. PAM logs the
  database username, not the external authenticated identity. Token replay
  during validity and established-session lifetime follow the limits in ADR 0008.

## Required validation pipeline

All stages fail closed and execute in this trust order:

1. Select the trusted issuer from the matched HBA rule; never select trust from token claims.
2. Retrieve bounded OIDC metadata from the issuer-derived discovery URL, then
   JWKS from the validated, allowed `jwks_uri`.
3. Parse the token under strict size and complexity limits.
4. Enforce the accepted access-token type.
5. Select a trusted signing key and locally allowed asymmetric algorithm.
6. Verify the signature before using claims for decisions.
7. Validate issuer, audience, expiry, activation time, identity, and other configured claims.
8. Validate required PostgreSQL connection scopes/entitlements.
9. Construct a safe, stable authenticated identity.
10. Return resource-level authorization and the identity to PostgreSQL for usermap processing.

Callback outputs must begin denied. Success at an earlier stage never compensates for failure or uncertainty at a later stage.

## Security invariants

- Only OAuth access tokens are accepted. ID tokens are rejected even when signed by the trusted issuer and key. Deployments allowing missing `typ` must establish mutually exclusive validation rules for access, ID, and session tokens from their issuer.
- `iss`, `sub`, `aud`, `exp`, and the configured stable identity claim are mandatory and correctly typed.
- Audience matching is exact and requires at least one configured PostgreSQL resource identifier.
- Issuer matching is exact; no substring detection or silent trailing-slash normalization is allowed.
- The validator returns the configured identity string unchanged as `authn_id`.
- Delegated authorization requires the exact requested PostgreSQL role in a
  configured nonempty string or bounded array of distinct, nonempty strings.
- `openid` alone is not sufficient authorization to connect to PostgreSQL.
- Signing algorithms come from a local allowlist. `none`, algorithm confusion, and remote HMAC keys are rejected by default.
- Key selection uses trusted JWKS data. Missing or ambiguous key identifiers are rejected.
- Token-provided `jku` and `x5u` locations are never followed.
- Inputs, network activity, retries, refreshes, caches, parsing, and clock skew are bounded.
- Complete bearer tokens, signatures, secrets, and sensitive claim sets are never logged or returned to clients.
- Detailed diagnostics remain in protected server logs; client-facing errors are generic.
- Network or internal failures cannot produce authorization success.
- Authentication-time HTTP fetches require libcurl 7.87.0 or newer with
  asynchronous DNS and quick-exit support so timeout and shutdown interrupts
  can release an in-progress resolver lookup without waiting for it to finish.

## Identity and role mapping

In normal identity mode:

```text
authorized = valid token for PostgreSQL AND required connection privileges
authn_id   = stable external identity
```

Without `map=`, PostgreSQL requires `authn_id` to exactly equal the requested
role. With `map=`, PostgreSQL applies the selected `pg_ident.conf` usermap.

The authenticated identity, the `sub` claim and every delegated role name are
rejected, not normalized, when they contain ASCII or C1 controls, malformed
UTF-8, or an invisible, line-breaking or text-reordering character (soft hyphen,
zero width characters and joiners, bidi marks, embeddings, overrides and
isolates, line and paragraph separators, the byte order mark, and interlinear
annotation characters). The exact set is in `src/identity_text.h` and
`docs/configuration.md`. Emoji sequences joined with U+200D are refused as a
consequence.

In delegated roles mode:

```text
authorized = valid token for PostgreSQL AND required connection privileges
             AND requested role exactly matches the configured role claim
authn_id   = configured external identity for auditing
```

Delegated mode requires `delegate_ident_mapping=1` in the matched HBA rule and
a configured `role_claim`. Either setting without the other fails closed. The HBA `USER` field
should independently allowlist reachable roles. It must not be combined with
`map=`.

The validator applies no special denylist, allowlist, or privilege
classification to delegated role names. A privileged role, including a
superuser, may be authorized when the HBA `USER` field permits that requested
role and the validated token contains its exact name. This is deliberate: the
HBA rule and issuer-side claim policy are the administrator-controlled
authorization boundaries. Deployments should enumerate delegated roles rather
than use `all` or a broad `+group` unless that wider authority is intentional.

## Metadata, JWKS, and network behavior

- Discovery parsing is independent of network transport and accepts only a bounded JSON object with a unique, exact configured `issuer` and one structurally valid absolute `jwks_uri`.
- The transport adapter requires an exact allowed host, disables environment proxies and redirects, verifies TLS, bounds connection/total time and response bytes, and accepts only successful JSON responses.
- Issuer-bound retrieval composes issuer-derived OIDC metadata fetch, exact
  issuer validation, separately allowlisted JWKS fetch, and strict single-key
  selection without implicit retry or cache behavior.
- The standalone orchestrator executes envelope, key retrieval, signature, claims/scopes, and identity stages in fail-closed order while preserving typed non-sensitive failures.
- Production metadata and JWKS retrieval requires HTTPS with certificate verification.
- Any development-only HTTP option must be explicit, disabled by default, and clearly unsafe for production.
- Metadata `issuer` must exactly equal the configured issuer.
- URL schemes, redirects, response sizes, timeouts, and allowed hosts are restricted by policy.
- Cache entries are separated by exact URL, issuer, and complete validation policy.
- Unknown signing keys may trigger at most one controlled refresh, subject to a cooldown on the exact cache entry. An entry is keyed by issuer, URLs and complete validation policy, so the entries for one issuer differ only by administrator-defined policy and their number is bounded by configuration.
- A well-formed key set that cannot serve a token's key is still published; only that token is denied.
- Metadata and JWKS are accepted only from a `200` response. Within the size and key-count limits, JWKS members that are not objects or lack a usable `kid` are ignored (RFC 7517 section 5); duplicate `kid` values, an empty set, and a malformed selected key still deny.
- The token `typ` is matched ignoring ASCII case (RFC 7515 section 4.1.9); the allowlist selects the accepted spelling.
- Responses that would otherwise be fetched on every authentication (`no-store`, `no-cache`, `max-age=0`, unusable freshness headers) are retained for a short administrator-set minimum, `cache_min_ttl` (default 30 s, at most 5 minutes). Zero restores per-authentication fetching. A positive provider lifetime is never extended, and nothing retained this way is used stale.
- When another backend is already refreshing the same cold cache entry,
  authentication waits for bounded publication by default and then retries the
  shared cache. The wait can be set to zero for immediate fail-closed behavior.
- Failed refreshes do not erase a still-permitted last-known-good key set.
- Any stale-key availability window is bounded and administrator-defined.
- Provider outage behavior is deterministic and documented; an unverifiable token is never accepted for availability.
- PostgreSQL locks are not held during network operations.
- PostgreSQL locks are not held while waiting for another refresh owner.

## Issuer compatibility

The validation core defaults to RFC 9068 token-type behavior. The explicit
`allow_missing_token_type` setting is a compatibility exception for issuers
that omit `typ`; it never accepts a present unrecognized type. Operators must
verify that issuer, audience, and required scopes distinguish access tokens
from other JWTs issued by the same provider. See
[ADR 0004](docs/adr/0004-token-type-compatibility.md).

The implementation has one policy, with explicit configuration for token type,
algorithms, audience, identity, and optional role claim. It requires a `scope`
claim and does not infer compatibility from issuer hostnames. An issuer needing
different claim syntax or validation rules is unsupported until a reviewed
specification, implementation, and negative interoperability tests establish
those rules. [Provider compatibility](PROVIDER-COMPATIBILITY.md) records the
evidence available for particular deployments.

## Explicitly deferred or unsupported

The following are outside the active release scope:

- browser authorization and device-code flows performed by clients;
- acting as an authorization server or identity provider;
- automatic PostgreSQL role provisioning or deletion;
- accepting arbitrary JWTs solely because their signature verifies;
- accepting opaque tokens or using token introspection;
- PAM usermaps or session/password PAM operations, and PAM use outside
  PostgreSQL;
- revocation-aware online validation;
- implicit provider compatibility;
- implicit provider-group transformations into PostgreSQL roles;
- anonymous or identity-less access;
- automatic acceptance of arbitrary provider roles without explicit delegated
  configuration and an HBA role boundary.

## Acceptance criteria for the `v1.0.0` security review

The implementation is ready for the `v1.0.0` security review only when:

- a correctly signed token for another audience is rejected;
- a trusted issuer's ID token is rejected as an access token;
- tokens missing `iss`, `sub`, `exp`, `aud`, or the configured identity are rejected;
- wrong-type and malformed security-sensitive claims are rejected;
- only administrator-allowed asymmetric algorithms and valid keys are accepted;
- rotated signing keys can be adopted without attacker-driven refresh storms;
- a valid principal cannot assume a role that fails normal exact-name/usermap
  authorization or delegated exact role-claim authorization;
- delegated mapping fails unless both HBA delegation and validator delegated
  policy are explicitly enabled;
- malformed, duplicate, oversized, missing, and insufficient delegated role
  claims are rejected for both scalar and array shapes;
- no token or secret appears in normal, debug, or error logs;
- network failures and cache behavior are deterministic and documented;
- negative tests cover the documented threat model and run in CI;
- PostgreSQL integration tests exercise real connections over TLS.

## Current constraints and deferred decisions

- The first release uses the single JWT policy described above. Additional
  issuer-specific behavior requires a reviewed specification and evidence.
- Audience is an explicit, administrator-configured cluster-wide GUC; there is
  no implicit canonical audience. Per-rule audience selection is deferred to
  a future policy design.
- Metadata/JWKS freshness bounds and outage behavior follow
  [`ADR 0002`](docs/adr/0002-metadata-jwks-cache-and-outage-policy.md).
  Changes to that policy require a new reviewed decision.
- Reload uses complete canonical-key separation. Shared-memory layout changes
  and same-path CA bundle replacement require restart or an explicitly
  versioned CA path.

Resolve and document any change to these constraints before implementing it as
part of the public configuration or compatibility contract.
