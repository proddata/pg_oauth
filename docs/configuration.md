# Configuration

This document describes the currently implemented operator-facing contract.
[`../FEATURES.md`](../FEATURES.md) remains the authoritative product and
security specification.

## Policy inputs and defaults

The validator reads issuer and required scopes from the matched OAuth HBA rule.
Audience has no safe universal default and must be configured explicitly:

```conf
pg_oauth_validator.audiences = 'https://postgres.example.internal/'
```

The remaining settings have restrictive defaults:

```conf
pg_oauth_validator.allowed_algorithms = 'RS256,ES256'
pg_oauth_validator.allowed_token_types = 'at+jwt,application/at+jwt'
pg_oauth_validator.allow_missing_token_type = off
pg_oauth_validator.identity_claim = 'sub'
pg_oauth_validator.role_claim = ''
pg_oauth_validator.allowed_jwks_hosts = ''
pg_oauth_validator.ca_file = ''
pg_oauth_validator.clock_skew = '60s'
pg_oauth_validator.max_token_size = '16kB'
pg_oauth_validator.allow_insecure_http = off
pg_oauth_validator.metadata_default_ttl = '5min'
pg_oauth_validator.jwks_default_ttl = '5min'
pg_oauth_validator.cache_max_ttl = '1h'
pg_oauth_validator.cache_min_ttl = '30s'
pg_oauth_validator.jwks_stale_grace = '0s'
pg_oauth_validator.unknown_kid_refresh_cooldown = '30s'
pg_oauth_validator.cache_max_entries = 32
```

`allowed_algorithms` accepts `RS256`, `ES256`, and `EdDSA`. `EdDSA` is opt-in
and means Ed25519 only: the signing JWK must be `kty=OKP`, `crv=Ed25519`,
`alg=EdDSA`, and the token header must say `EdDSA`. The fully-specified
`Ed25519` name from RFC 9864 is not accepted. Enable it with, for example,
`pg_oauth_validator.allowed_algorithms = 'RS256,EdDSA'`. Operators on a
FIPS-restricted OpenSSL should confirm Ed25519 support before enabling it.
See [`ADR 0003`](adr/0003-eddsa-ed25519-support.md).

`allowed_token_types` is a nonempty, comma-separated allowlist containing only
`at+jwt` and `application/at+jwt`. Both spellings are allowed by RFC 9068 and
both are accepted by default. Duplicate, empty, and other entries fail closed.
The token's `typ` is compared ignoring ASCII case, as RFC 7515 section 4.1.9
requires for media types (RFC 9068's own example is `at+JWT`); the allowlist
still decides which spelling is accepted, so `at+jwt` alone rejects
`application/at+jwt`. Whitespace and non-ASCII look-alikes never match.
`allow_missing_token_type` defaults to `off`. When enabled, an absent `typ`
is accepted, but a present type must still be in the allowlist. This is a
provider-compatibility exception, not RFC 9068 validation. Enable it only when
the issuer's access-token audience and required database scope cannot also
occur in ID or session tokens; test those token kinds before deployment.

An empty audience, empty HBA scope, unsupported or duplicate algorithm, token
type outside the configured allowlist, unsafe identity or role claim
name, mismatched HBA delegation,
invalid additional JWKS hostname, excessive clock skew, or invalid token-size
bound causes validation to fail closed. `cache_max_ttl` must not be shorter
than either fallback TTL; an inconsistent cache policy also fails closed. Only
the `default` named policy exists;
PostgreSQL 19 rejects other `validator.policy` values.

## Metadata and JWKS cache

`metadata_default_ttl` and `jwks_default_ttl` apply only when a successful
provider response carries no explicit freshness (`Cache-Control: max-age` or
`Expires`). `cache_max_ttl` caps both fallback and provider-advertised
freshness. The accepted ranges are 1 second to 1 hour for each fallback and
1 second to 24 hours for the maximum.

`cache_min_ttl` (default 30 seconds, 0 to 5 minutes, and not above
`cache_max_ttl`) is the shortest time a response is retained when the provider
sends `no-store`, `no-cache`, `max-age=0` or unusable headers. Without it such a
provider is queried on every authentication and overlapping authentications
fail while waiting. Metadata and JWKS are public, so retention does not
disclose anything; the cost is that a key the provider withdraws stays trusted
for up to this time. A positive provider lifetime is never extended, `no-store`
lifetimes are capped at the minimum, and `no-cache` or `must-revalidate`
responses are revalidated once it ends and are never used stale. `0` restores
strict RFC 9111 behavior and one provider request per authentication.

Freshness headers that are present but unusable never deny authentication and
never extend freshness. Duplicate or malformed `max-age`, malformed `Age`, an
invalid `Expires` (including `0`) or a malformed argument to `no-store` or
`must-revalidate` make the response immediately stale: it serves the
authentication that fetched it and is refetched by the next one. `no-store`
is honored even beside a malformed directive. Empty list elements such as a
trailing comma are ignored, an invalid `Date` is replaced by the local receive
time, and a delta-seconds value too large to represent is treated as 2^31
seconds and then capped by `cache_max_ttl` (RFC 9111 sections 1.2.2, 4.2.1
and 5.3; RFC 9110 section 5.6.1.2). Headers from interim (1xx) responses and
trailer fields are ignored, and each freshness header is limited to 4096 bytes
in total.

`jwks_stale_grace` is an explicit outage-availability tradeoff from zero to one
hour. Its default of zero rejects authentication after JWKS freshness expires.
A nonzero value permits previously validated public keys during that bounded
grace only when the response did not require revalidation. It never bypasses
token signature, claim, scope, identity, or role-mapping validation. Metadata
is never used stale.

`unknown_kid_refresh_cooldown` accepts 1 second to 5 minutes and limits
attacker-triggered JWKS refreshes per canonical issuer policy. `cache_max_entries`
accepts 8 to 256 and bounds the combined metadata/JWKS shared cache. The
default of 32 preserves the original fixed capacity.

`refresh_wait_timeout` controls how long an authentication backend waits when
another backend is already refreshing the same metadata or JWKS cache entry.
It accepts zero to 5 seconds and defaults to 5 seconds. Waiters sleep without
holding the shared-cache lock, retry the exact entry after publication, and
fail closed when the owner fails or the deadline expires. Set it to `0` to
restore immediate fail-closed behavior for concurrent cold-cache requests.

## HBA and identity mapping

Every accepted token must contain a valid `iss` and `sub`. The selected
`identity_claim` (default `sub`) must also be a nonempty string and is returned
unchanged as PostgreSQL's authenticated identity. It is limited to 63 bytes to
fit a PostgreSQL role name when exact matching is used.

The identity, the `sub` claim and each delegated role name must be valid UTF-8
and are rejected, not normalized, if they contain any of the following, because
a person reading the connection log or a usermap cannot see them, or they make
one identity look like another or one log line look like several:

- ASCII controls and the C1 controls U+0080 to U+009F;
- U+00AD (soft hyphen), U+061C (Arabic letter mark) and U+180E (Mongolian
  vowel separator);
- U+200B to U+200F (zero width space, non-joiner, joiner, left-to-right and
  right-to-left marks);
- U+2028 to U+202E (line and paragraph separators, bidirectional embeddings and
  overrides);
- U+2060 to U+206F (word joiner, invisible operators, bidirectional isolates and
  the deprecated format controls);
- U+FEFF (byte order mark) and U+FFF9 to U+FFFB (interlinear annotation).

Ordinary non-ASCII text, such as accented letters, CJK ideographs and emoji, is
accepted. Emoji sequences that use U+200D (zero width joiner), for example
family or skin-tone sequences, are refused. A PostgreSQL role whose name
contains one of these characters cannot be reached through OAuth or PAM even
with a matching token; rename the role.

Without `map=` or delegation, PostgreSQL requires the identity to exactly
match the requested role:

```conf
hostssl appdb app_reader 10.0.0.0/8 oauth \
    issuer="https://idp.example/" scope="connect:postgres" \
    validator=pg_oauth_validator
```

For this rule, the token needs `sub=app_reader` with the default identity
claim. A custom `identity_claim` can be selected when the issuer provides a
stable, issuer-controlled identity; the token still needs `sub`.

With `map=`, PostgreSQL checks `pg_ident.conf` after token validation:

```conf
# pg_hba.conf
hostssl appdb app_reader 10.0.0.0/8 oauth \
    issuer="https://idp.example/" scope="connect:postgres" \
    validator=pg_oauth_validator map=oauthmap

# pg_ident.conf; token sub is principal-123
oauthmap principal-123 app_reader
```

For token-provided roles, configure a claim name and delegate mapping in the
matched HBA rule. The claim may be a single role-name string or a nonempty,
bounded array of distinct role-name strings. The validator checks an exact,
case-sensitive match to the requested role:

```conf
# postgresql.conf
pg_oauth_validator.role_claim = 'postgres_roles'

# pg_hba.conf
hostssl appdb app_reader,reporting 10.0.0.0/8 oauth \
    issuer="https://idp.example/" scope="connect:postgres" \
    validator=pg_oauth_validator delegate_ident_mapping=1
```

For example, `{"sub":"principal-123","postgres_roles":"app_reader"}` and
`{"sub":"principal-123","postgres_roles":["app_reader","reporting"]}`
both authorize `app_reader`. The second also authorizes `reporting`. The HBA
`USER` field must independently permit the requested role. Missing, malformed,
duplicate, oversized, or nonmatching role claims deny access. A configured
`role_claim` without HBA delegation, or delegation without `role_claim`, fails
closed. PostgreSQL disallows combining delegation with `map=`.

The validator does not separately deny privileged roles. A requested role,
including a superuser, is reachable when both the validated claim and HBA
`USER` field permit it. Enumerate roles explicitly in the HBA rule.

PostgreSQL 19 rules may add `validator.policy=default`; PostgreSQL 18 must omit
that option. Roles must already exist with `LOGIN`.

PostgreSQL's OAuth connection log records the returned authenticated identity,
and `system_user` is `oauth:<identity>`. Connection authorization and `%u`
identify the requested PostgreSQL role. Standard pgAudit statement lines do
not contain `system_user`; correlate using PostgreSQL session IDs when needed.
With a custom `identity_claim`, the logged identity is that claim's value, not
necessarily `sub`.

### Choosing identity and role claims

PostgreSQL treats the returned identity as proof of who connected, so use only
a claim that the issuer controls and that is never reassigned to another
person. `sub` qualifies: OpenID Connect Core section 5.7 defines the `iss` and
`sub` pair as the only stable identifier. Profile claims such as `email` or
`preferred_username` can often be edited by the user or an administrator, or
reused after an account is deleted. Do not select one as `identity_claim`
unless your provider's documentation guarantees that it is immutable and
unique; this validator cannot check that.

The same applies to `role_claim`. If a user can edit the attribute that feeds
the claim at the provider, that user can grant themselves every role the HBA
`USER` field permits. Populate it only from an administrator-assigned
attribute or group mapping.

A `pg_ident.conf` system-username that starts with `/` is a regular
expression, and PostgreSQL documents that it "can match just part of a
string". Anchor it with `^` and `$` and escape literal dots, for example
`/^(.*)@example\.com$`. An unanchored `/example.com/` also matches
`attacker@example-com.evil.test`.

### Issuer, scope and time-claim values

`issuer` in the HBA rule (or the PAM `issuer=` argument) is the issuer
identifier, not the discovery URL. The module requests
`<issuer>/.well-known/openid-configuration`, adding no extra slash when the
issuer already ends in `/`. An issuer that already is a `/.well-known/` URL
gets the suffix appended again, metadata retrieval fails, and every token is
denied. The HBA issuer, the metadata `issuer` member and the token `iss` claim
must be the same string: there is no trailing-slash or case normalization, so
`https://idp.example` and `https://idp.example/` are different issuers.

The HBA `scope` is a space-separated list, and every listed scope must be
present in the token, compared exactly and case-sensitively. The token's `scope`
claim may be a space-delimited string (RFC 9068 section 2.2.3) or an array of
strings. A malformed scope value, a duplicate entry, a non-string member or an
over-long list denies the token.

`exp` is required; `nbf` and `iat` are checked when present. NumericDate values
must be JSON integers. RFC 7519 section 2 also allows non-integer values;
this validator rejects fractional values, and strings, so a provider that
emits `1700000000.5` is denied. Check that your provider issues integer
timestamps.

### Configuration transition before first release

This pre-release contract does not accept `identity_format`,
`authorization_mode`, `roles_claim`, or `required_token_type`. Remove those settings from local
configuration. Replace delegated `roles_claim` with `role_claim` and keep
`delegate_ident_mapping=1` on the matched HBA rule. Replace encoded
`pg_ident.conf` identities with direct selected claim values. Restart
PostgreSQL after replacing the module; a rollback also requires restoring the
matching configuration and restarting.
Replace `required_token_type = 'at+jwt'` with
`allowed_token_types = 'at+jwt'` to retain exact old behavior, or omit it to
accept both RFC 9068 spellings. The old setting fails at module startup.

## JWKS locations and TLS

JWKS retrieval permits the exact hostname of the trusted discovery endpoint by
default. `allowed_jwks_hosts` is an optional comma-separated list of additional
exact hostnames for deployments whose discovery document deliberately points
at another host. Entries contain hostnames only, without schemes, ports, paths,
wildcards, or credentials. Keep the setting empty unless verified provider
metadata requires an exception.

This transport restriction works the same way on PostgreSQL 18 and 19 and is
independent of PostgreSQL 19's `validator.policy` selector. HTTP redirects are
not followed.

The validator verifies the provider's certificate chain and host name but does
not check certificate revocation: it enables no CRL, OCSP or OCSP-stapling
check. A provider certificate that was revoked but has not expired stays
trusted until it expires or is removed from the trust store. To limit that
window, trust a private CA through `ca_file` that you can rotate quickly, use
short-lived provider certificates, and restrict which networks can reach the
issuer.

Tokens are validated offline against cached keys. A token revoked at the
provider stays valid until its `exp`, and key material withdrawn at the
provider stays trusted until the cache entry expires; the key-flush procedure
is in [operations](operations.md#initial-configuration). Online revocation
checking is deferred in `FEATURES.md`.

Metadata and JWKS are accepted only from a `200` response (RFC 8414 section 3.2,
RFC 7517 section 5). Other `2xx` statuses such as `203`, `204` and `206` can
carry no body or a partial or transformed one, and are treated as failures.

### JWKS limits and unusable entries

A key set is limited to 64 KiB, 16 keys and 1024-byte `kid` values; a larger
set is rejected as a whole, which keeps work per refresh bounded. Within those
limits, members that cannot identify a key are ignored (RFC 7517 section 5):
entries that are not JSON objects, and entries whose `kid` is missing or is not
a usable string. Such an entry can never match a token, so ignoring it cannot
admit a key. Duplicate usable `kid` values, an empty `keys` array, and a
selected key that is malformed, private, or unsuitable for signature
verification still deny the token that selects it.
Issuers whose key set exceeds 16 keys must reduce it; the limit is not
configurable.

`ca_file` optionally selects a PEM CA bundle for metadata and JWKS HTTPS. An
empty value uses the system trust store. `allow_insecure_http` exists only for
isolated development and is disabled by default.

Metadata and JWKS fetches use bounded libcurl multi-interface waits. The
backend checks for PostgreSQL interrupts between waits so authentication
timeouts and shutdown can stop an in-progress fetch after releasing its HTTP
resources and failing any owned cache refresh. The build and runtime libcurl
must support `CURLOPT_QUICK_EXIT` (7.87.0 or newer), and runtime libcurl must
report asynchronous DNS support; a fetch fails closed otherwise. During
authentication cancellation, quick exit avoids waiting for a threaded resolver
lookup to finish. The backend exits after the authentication interrupt, so any
resolver resources abandoned by libcurl are process bounded. Use bounded,
reliable DNS for the trusted issuer and verify timeout and shutdown behavior
on the deployed libcurl build.
Run `make check-libcurl-runtime PG_CONFIG=/path/to/pg_config` in the deployment
environment to record the linked libcurl version and resolver backend. The
automated tests inject a DNS failure and a delayed threaded DNS lookup, but
cannot guarantee cancellation latency for every operating-system resolver
configuration.

Do not place credentials, bearer tokens, or other secrets in `ca_file` paths or
any validator GUC. PostgreSQL core can include changed setting names and values
in configuration-reload diagnostics; GUC values are therefore operator-visible
configuration, not secret storage. Protect the referenced CA bundle with normal
filesystem permissions and use a non-sensitive path.

## Reload behavior

All validator GUCs use `PGC_SIGHUP` because the validator is loaded lazily. New backends recompute canonical
cache keys from the complete effective policy after reload. A changed audience,
algorithm, token type, identity claim, host rule, CA path, bound, or transport
policy cannot reuse an entry created under the previous policy.

The fallback TTLs, maximum TTL, stale grace, and unknown-key cooldown also
participate in canonical keys. Reloading any of them makes entries created
under the previous cache policy ineligible immediately. `cache_max_entries`
is accepted from PostgreSQL configuration on reload because the validator is
loaded after server startup, but it determines named shared-memory layout and
therefore requires a PostgreSQL restart to become usable. If it changes during
a reload, cache attachment and authentication fail closed until restart; this
prevents a backend from silently continuing with the old capacity.

The trust-root path is part of the canonical cache key. Replacing the contents
of `ca_file` at the same path is not observable as a GUC change: use a new,
versioned path and reload, or restart PostgreSQL, when rotating that bundle.

## Security constraints

- The accepted credential is an OAuth access token, not an OIDC ID token.
- Audience and required HBA scopes are mandatory.
- HTTPS and certificate verification are required in production.
- `openid` alone is not a sufficient PostgreSQL connection scope. An HBA rule
  (or PAM `scope=` argument) whose required scopes are only `openid` fails
  policy construction, so every connection through it is denied.
- No certificate revocation or token introspection is performed; see
  [JWKS locations and TLS](#jwks-locations-and-tls).
- A valid token does not permit an identity to assume a role unless normal
  exact-name/usermap authorization or delegated exact role-claim authorization
  succeeds.
- No provider-specific policy is selected from issuer hostnames. The only
  compatibility exception is the explicitly configured missing-`typ` option
  described above; other claim syntax remains unsupported.

See [`../PROVIDER-COMPATIBILITY.md`](../PROVIDER-COMPATIBILITY.md) before
configuring a specific authorization server.
