# Installation and operations

This guide covers the pre-release strict JWT validator for PostgreSQL 18 and
the PostgreSQL 19 preview. Validate every upgrade in staging and retain the
previous package until rollback has been tested.

Publishing a candidate additionally requires the complete
[`release-readiness.md`](release-readiness.md) evidence and approval process.

The reviewed candidate environment is Debian/PGDG. Fedora and Enterprise
Linux work remains experimental until the RPM, installed-runtime, and
SELinux-enforcing gates in [`rpm-platforms.md`](rpm-platforms.md) are complete.

## Runtime and package requirements

Build against the exact PostgreSQL major version used by the server. The
installed module dynamically uses the operating system's libcurl and OpenSSL.
The reviewed libjwt and Jansson builds are linked into the module as
position-independent static archives. Production packages must use
vendor-supported libcurl and OpenSSL releases and be rebuilt after relevant
security updates. The linked libcurl must be at least 7.87.0 and report
asynchronous DNS support. Run `make check-libcurl-runtime` with the deployment
`pg_config` to record the runtime version and resolver backend.

The validator does not require `shared_preload_libraries`. PostgreSQL loads it
through `oauth_validator_libraries` when OAuth authentication is configured.

## Build and staged installation

Install the PostgreSQL server-development package, C toolchain, libcurl,
OpenSSL, and the reviewed Jansson and libjwt builds described in the
development guide. Then run:

```sh
make clean
make verify
make packagecheck
make install DESTDIR=/path/to/package-root
```

`packagecheck` verifies the shared library, installed documentation,
permissions, exported callback symbol, static libjwt/Jansson linkage, and the
optional PostgreSQL LLVM-bitcode manifest. Build a separate package for each
PostgreSQL major version. Never install a PostgreSQL 18 binary into PostgreSQL
19 or the reverse.

For direct installation, run `make install` with the privileges required by
`pg_config --pkglibdir`. CI additionally runs `make installedcheck` in a
disposable container. That target installs into the real PostgreSQL directories
and exercises OAuth connections using the installed library path.

## Initial configuration

Configure an explicit audience and retain the restrictive defaults:

```conf
# postgresql.conf
oauth_validator_libraries = 'pg_oauth_validator'
pg_oauth_validator.audiences = 'https://postgres.example.internal/'
pg_oauth_validator.allowed_algorithms = 'RS256,ES256'
pg_oauth_validator.allowed_token_types = 'at+jwt,application/at+jwt'
pg_oauth_validator.allow_missing_token_type = off
pg_oauth_validator.ca_file = '/etc/postgresql/oauth/provider-ca.pem'
# Fail closed after provider-advertised key freshness expires.
pg_oauth_validator.jwks_stale_grace = '0s'
```

Use TLS, restrict database, roles, and source networks, and retain normal
PostgreSQL usermap authorization:

```conf
# pg_hba.conf
hostssl appdb +oauth_login 10.0.0.0/8 oauth \
    issuer="https://id.example/realms/production" \
    scope="connect:postgres" \
    validator=pg_oauth_validator \
    map=oauthmap
```

```conf
# pg_ident.conf
oauthmap  <validated-sub>  app_user
```

Use `delegate_ident_mapping=1` only with a configured `role_claim` and an
explicit HBA `USER` role list. The validator does not separately
deny superusers or classify role privileges: a role named by both HBA and the
validated token is reachable. Avoid `all` and broad `+group` matches unless
that authority is intentional, and treat issuer-side role-claim mapping as
database authorization policy. Never place client secrets or bearer tokens in
PostgreSQL configuration. PostgreSQL may
write changed GUC values to its server log during reload, so validator settings
and filesystem paths are not secret-storage boundaries.

Require clients to validate the PostgreSQL server certificate and hostname
with `sslmode=verify-full` and an explicitly managed `sslrootcert` (or the
platform-equivalent trusted root configuration). `sslmode=require` encrypts
the connection but does not provide the same explicit server-identity check.
The provider CA configured by `pg_oauth_validator.ca_file` is a separate trust
boundary: it must authenticate the exact hostname in the configured HTTPS
issuer and must not be replaced in place without the restart described below.

For Keycloak 26.2 or later, enable **Use "at+jwt" as access token header
type**, configure an explicit PostgreSQL audience mapper, attach the required
scope, and include stable `sub`. The reproducible configuration is in
`tests/interop/keycloak/realm.json`.

Keycloak 26.5.0 advertises discovery with `no-store` and JWKS with `no-cache`.
The validator honors those response directives, so a Keycloak outage prevents
new OAuth authentications even if the server recently fetched the signing
keys. Keep a strongly protected non-OAuth recovery path and monitor provider
availability; the interoperability suite verifies rejection during a complete
Keycloak stop and recovery after restart.

The validator otherwise defaults metadata and JWKS freshness to five minutes
when a provider supplies no freshness headers and caps freshness at one hour.
Unusable headers make the response immediately stale instead (see
[configuration](configuration.md#metadata-and-jwks-cache)). Responses stale
from the start, and `no-store`/`no-cache` responses, are retained for
`pg_oauth_validator.cache_min_ttl` (30 seconds by default) so that a provider
that always sends them is not queried on every authentication.
Provider-advertised shorter lifetimes remain authoritative. Increasing
`jwks_stale_grace` can bridge a provider outage with previously validated
public keys, but also delays the effect of emergency key removal by up to the
configured grace. Enable it only after documenting that tradeoff and retaining
a protected recovery path. Responses marked `no-cache`, `must-revalidate`, or
`no-store` cannot be used stale.

After a key compromise, a withdrawn key stays trusted until its cached entry
expires: the provider's lifetime (capped by `cache_max_ttl`), at most
`cache_min_ttl` for providers that forbid caching, plus `jwks_stale_grace` when
enabled. To drop cached keys at once, restart PostgreSQL, or change any
setting that is part of the cache key (for example `cache_min_ttl` by one
millisecond) and reload: entries under the old key are ineligible immediately
and the next authentication refetches. Revoke the compromised signing key at
the provider as well; flushing the cache does not invalidate tokens that other
systems already accept.

After PostgreSQL restart, the first OAuth authentication for an issuer owns
the cold metadata/JWKS refresh. Other authentications for the same issuer wait
up to `pg_oauth_validator.refresh_wait_timeout` (5 seconds by default) and use
the atomically published cache entry. They do not hold a PostgreSQL lock while
sleeping. A provider failure or expired wait still fails closed. Set the value
to `0` only when immediate rejection is preferable to a bounded cold-start
delay.

Removed `identity_format`, `authorization_mode`, and `roles_claim` settings
cause module initialization to fail with a named configuration error. Remove
them before restart. Inspect `pg_settings` after configuration changes to
catch other misspelled custom settings, which PostgreSQL may hold as
placeholders until the module loads.

## Validation before rollout

1. Verify the package matches the server's PostgreSQL major version.
2. Run the full unit and integration suites in staging.
3. Test a mapped low-privilege role and rejection of an unmapped role.
4. Test wrong audience, issuer, scope, token type, and expiry rejection.
5. Confirm metadata and JWKS are reachable over validated HTTPS.
6. Confirm PostgreSQL and client logs contain no bearer token.
7. Retain a non-OAuth administrative recovery path restricted to local or
   otherwise strongly protected access.

## Reload and restart

HBA rules, usermaps, and reloadable validator settings take effect after
`SELECT pg_reload_conf()` or a service reload. Canonical cache keys prevent
entries validated under an old effective policy from being reused under a
changed policy.

A restart is required when:

- installing or replacing the validator shared library;
- changing shared-cache layout or capacity;
- replacing CA contents at the same configured path.

For CA rotation without an immediate restart, install the new bundle at a new,
versioned path, update `pg_oauth_validator.ca_file`, and reload. Keep the old
file until backends using the previous policy have exited.

Changing `pg_oauth_validator.cache_max_entries` requires restart. Cache TTLs,
JWKS stale grace, and unknown-key refresh cooldown are reloadable; canonical
key separation prevents reuse of entries populated under their previous
values. An invalid relationship such as a maximum TTL below a fallback TTL
fails validation closed until configuration is corrected and reloaded.
Because the validator is loaded lazily rather than through
`shared_preload_libraries`, PostgreSQL can parse a changed capacity during
reload. Authentication deliberately fails closed from that point until the
required restart creates a segment with the requested layout.

## Upgrade

1. Build and test a version-specific package in isolation.
2. Review configuration/default and dependency changes.
3. Back up the current package and OAuth configuration.
4. Install the new package while retaining a recoverable previous artifact.
5. Restart PostgreSQL; reload is insufficient for a replaced library.
6. Run positive and negative connection probes and inspect sanitized logs.
7. Roll out gradually across instances where the deployment permits.

Do not mix library files or LLVM bitcode from different builds.

Rebuild and retest the module against the headers of every PostgreSQL minor
release you deploy, not only each major. The matched HBA issuer and scope are
read from PostgreSQL's internal HBA structure, and minor releases are not an
ABI guarantee for server-internal types.

## Rollback

1. Restore the previous version-specific package as one complete unit.
2. Restore matching configuration if its public contract changed.
3. Restart PostgreSQL.
4. Verify the protected administrative recovery path.
5. Repeat mapped-role acceptance, unmapped-role rejection, and redaction checks
   before restoring normal traffic.

Never bypass a failure by broadening issuer, audience, algorithm, token type,
scope, TLS, or usermap policy. Keep authentication failed closed while the
cause is investigated.
