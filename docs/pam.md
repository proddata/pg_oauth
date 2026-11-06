# PAM token authentication (experimental)

`pg_oauth_pam` lets clients that can send a password but cannot perform native
OAuth authentication connect with a signed JWT access token. The client puts the
raw token in the password field; PostgreSQL's PAM support passes it to this
module, which validates it with the same pipeline and token policy as the
[native validator](configuration.md). It is a separate module: install it with
or without `pg_oauth_validator`, and either keeps working without the other.

[FEATURES.md](../FEATURES.md) defines the contract; [ADR 0008](adr/0008-postgresql-pam-token-authentication.md)
and [ADR 0009](adr/0009-pam-cache-and-module-isolation.md) record the design.
This feature is experimental and is not part of the active release scope.

## Status and supported versions

| PostgreSQL | Native OAuth validator | PAM module |
| --- | --- | --- |
| 15, 16 | not available | built and tested; must be preloaded (see below) |
| 17 | not available | built and tested (PAM only) |
| 18 | supported | built and tested |
| 19 preview | preview | built and tested |

Build a separate module for each PostgreSQL major version. PostgreSQL 15 to 19
are built and tested. The module has been exercised on Linux in
disposable Docker containers only; distribution packages and SELinux enforcing
mode are not qualified.

## Requirements

- A PostgreSQL server built with PAM support (`pg_config --configure` contains
  `--with-pam`).
- Linux-PAM and its development files to build.
- The same build dependencies as the native validator (libcurl, OpenSSL, and the
  reviewed libjwt and Jansson builds from the [development guide](development.md)).
- TLS between client and server. A token is a bearer credential: connect only
  with `hostssl` rules and clients that verify the server certificate
  (`sslmode=verify-full`). PAM cannot detect or enforce TLS for you.

## Install

```sh
make pam-module          # builds pam/pg_oauth_pam.so for the selected PostgreSQL
make check-pam-install   # stages an install and checks the result
make install-pam         # installs into the system PAM module directory
```

`install-pam` detects the PAM module directory (for example `/usr/lib64/security`
or `/usr/lib/<triplet>/security`); set `PAM_MODULE_DIR` if it is not found. It is
never part of `make install`, so an OAuth-only installation has no PAM module and
no PAM dependency. Restart is not required for a first install, but replacing
the module file affects only backends started afterwards.

## Configure

Three pieces work together.

**1. `pg_hba.conf`** sends selected connections to a dedicated PAM service. The
HBA `USER` field remains an independent allowlist of reachable roles.

```text
hostssl  all  appuser,reporting  0.0.0.0/0  pam  pamservice=postgresql-jwt
```

**2. The PAM service** (`/etc/pam.d/postgresql-jwt`, owned by root) carries the
policy as module arguments. The stack must contain exactly these two module
lines: authentication and account.

```text
auth    [success=ok default=die] pg_oauth_pam.so issuer=https://idp.example/ \
            audience=postgres://primary scope=connect:postgres
account [success=ok default=die] pg_oauth_pam.so issuer=https://idp.example/ \
            audience=postgres://primary scope=connect:postgres
```

- The `auth` and `account` lines must carry identical arguments. A mismatch
  denies, which catches an edit between the two stages.
- Do not use `sufficient` or `optional`, `pam_permit`, `@include`, or any
  password fallback. The module cannot protect a stack that skips it.
- Different HBA rules can name different services, and so use different issuers,
  audiences and scopes.
- libpam rereads the file for each authentication, so an edit applies to new
  connections only.

**3. `postgresql.conf`** sets the one module-level option:

```text
pg_oauth_pam.cache_max_entries = 32   # 8 to 256; changing it needs a restart
```

### PostgreSQL 15 and 16: preload the module

PostgreSQL 17 introduced the named shared-memory registry the cache uses. Before
that only the postmaster can create shared memory, so on **15 and 16 the module
must also be listed in `shared_preload_libraries`**, using the same file that the
PAM stack loads:

```text
shared_preload_libraries = '/usr/lib64/security/pg_oauth_pam'
pg_oauth_pam.cache_max_entries = 32
```

This needs a server restart. Without the preload the module has no storage and
**denies every authentication** rather than validate without refresh coordination.
Preloading is not needed, and not supported, on 17 and later. The preloaded
library and the one libpam loads must be the same file, or the module finds no
shared cache and denies.

### Module arguments

Arguments are `name=value`. They mirror the native validator's settings and use
the same defaults; time values are in milliseconds.

| Argument | Required | Default | Meaning |
| --- | --- | --- | --- |
| `issuer` | yes | | Exact trusted issuer URL. Discovery is derived from it. |
| `audience` | yes | | Comma-separated accepted audiences. |
| `scope` | yes | | Space-separated scopes the token must contain. |
| `algorithms` | no | `RS256,ES256` | Allowed signing algorithms (`EdDSA` is opt-in). |
| `token_types` | no | `at+jwt,application/at+jwt` | Accepted `typ` values. |
| `allow_missing_token_type` | no | `off` | Accept tokens without `typ` (see the [compatibility notes](configuration.md)). |
| `identity_claim` | no | `sub` | Claim used as the validated identity. |
| `clock_skew_ms` | no | `60000` | Clock skew, 0 to 300000. |
| `max_token_size` | no | `16384` | Credential limit in bytes, 1024 to 65530. |
| `jwks_hosts` | no | empty | Extra exact hostnames allowed for JWKS retrieval. |
| `ca_file` | no | system store | CA bundle for provider HTTPS. Must be readable by the server's operating-system account. |
| `metadata_default_ttl_ms`, `jwks_default_ttl_ms`, `cache_max_ttl_ms`, `jwks_stale_grace_ms`, `unknown_kid_refresh_cooldown_ms`, `refresh_wait_timeout_ms` | no | as in the [configuration guide](configuration.md) | Cache and refresh timing. |
| `allow_insecure_http` | no | `off` | Development only: permit HTTP provider URLs. |

Parsing is strict and fails closed. An unknown, duplicate, missing, malformed or
out-of-range argument denies every authentication on that line. Booleans are
exactly `on` or `off`; numbers are plain decimal digits. `role_claim` and
delegated roles are not supported. Each value is limited to 4096 bytes and the
whole cache key to 4096 bytes, so very long lists deny.

## Connect

The client supplies the raw compact JWT as the password, with no `Bearer` prefix:

```sh
PGPASSWORD="$ACCESS_TOKEN" psql \
  "host=db.example dbname=app user=appuser sslmode=verify-full sslrootcert=ca.pem"
```

- The validated identity (the `identity_claim`, `sub` by default) must equal the
  requested role exactly. There is no usermap and no delegated role claim: a token
  whose subject is `appuser` can sign in as `appuser` and nobody else.
- The default credential limit is 16 KiB and the hard maximum is 65530 bytes
  (PostgreSQL's password packet bound). Longer credentials are rejected, never
  truncated.
- Connection pools need a valid token for every new physical connection. A token's
  expiry does not end an established session.

## What is checked

The same stages as the native validator, in the same order: discovery from the
configured issuer, bounded key retrieval, signature verification before any
claim is trusted, then issuer, audience, expiry, token type and scopes. The
account stage then checks, using a fresh clock, that:

- an authentication for this role and service succeeded in this PAM transaction;
- the policy on the `account` line equals the policy on the `auth` line;
- no more than five seconds have passed since validation completed; and
- the token has not expired, using the same skew rule as claim validation.

The module keeps only the role, service, a policy digest and the expiry. It never
stores the token or its claims.

## Cache, outages and interrupts

Provider metadata and signing keys are cached in shared memory so separate
connection processes do not each contact the provider. The module's cache is
separate from the native validator's: its own segment, lock tranche and capacity,
and keys that include the PAM service name and the whole policy. A changed policy
never reuses another policy's entries. Freshness, stale-key, cooldown and outage
behavior follow [ADR 0002](adr/0002-metadata-jwks-cache-and-outage-policy.md); an
unknown key identifier triggers at most one cooldown-limited refresh. If the cache
cannot be attached, authentication is denied rather than run without refresh
coordination.

Provider fetches stop promptly on `authentication_timeout` and on fast shutdown;
the module returns a denial and PostgreSQL handles the interrupt.

## Logging and diagnostics

PostgreSQL logs `PAM authentication failed for user "..."` for a denial and gives
the client no detail. The module writes stable diagnostic codes to the system log
(syslog or the journal, prefixed with the PAM service and module name), never the token or any claim:

| Message | Meaning |
| --- | --- |
| `invalid module arguments: policy_...` | A stack argument is unknown, duplicate, missing, malformed or out of range. |
| `token rejected: validator=...` | Token validation failed; the code names the stage (envelope, key retrieval, signature, claims). |
| `token rejected: role_mismatch` | A valid token, but its identity is not the requested role. |
| `account denied: account_...` | The account stage failed (policy mismatch, expired, too much delay, no authentication state). |

## Limits and known gaps

- No RPM, SELinux policy or release artifact exists for this module yet.
- Bearer tokens can be replayed until they expire. Use short-lived tokens and TLS.
- PostgreSQL's PAM logging records the database username, not the external
  identity, so audit trails differ from the native validator's.

## Upgrade and rollback

Build and install a matching module for the PostgreSQL major version. To roll
back, restore the previous module file and the previous PAM service file. New
connections use whatever is installed; established sessions are unaffected. A
change to `pg_oauth_pam.cache_max_entries` or to the module's shared-memory
layout needs a server restart. Removing the PAM HBA rule disables the feature
without any fallback to another authentication method.
