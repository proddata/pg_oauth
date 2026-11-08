# ADR 0008: PostgreSQL PAM authentication with JWT access tokens

- Status: Accepted as an opt-in module (experimental until v0.2.0, a prerelease since); the gates under "Evidence and gates" remain required before a production release
- Maintainer decision: 2026-11-06
- Scope: Linux-PAM used by PostgreSQL 15, 16, 17, 18 and 19 preview; the OAuth validator remains PostgreSQL 18 and 19 only
- Implementation language: C17, the same as the OAuth validator

## Context

Some PostgreSQL clients can provide a password but cannot perform native OAuth
authentication, and PostgreSQL 15, 16 and 17 have no native OAuth validator API
at all. PostgreSQL's existing PAM path can transport a JWT access token through
the password field on every supported major without a server fork. This is client ergonomics only; it
adds no token introspection or other authentication mechanism.

The OAuth validator already implements strict offline JWT validation in C
(see [FEATURES.md](../../FEATURES.md) and [ADR 0001](0001-jose-json-crypto-http-dependencies.md)).
The PAM module should reuse that validation code rather than introduce a second,
independently evolving policy.

## Decision

### Supported PostgreSQL versions

| Module | PostgreSQL 15 | 16 | 17 | 18 | 19 preview |
| --- | --- | --- | --- | --- | --- |
| `pg_oauth_validator` (native OAuth) | no | no | no | yes | yes |
| `pg_oauth_pam` | yes | yes | yes | yes | yes |

On PostgreSQL 15, 16 and 17 only PAM can authenticate JWT access tokens, because
the OAuth validator API does not exist there. Each major gets a separately
compiled module and its own build tree and CI job. Other majors are rejected at
build time. The PAM module must avoid PostgreSQL-internal structures and
version-specific behavior beyond what the shared-memory cache needs (ADR 0009),
so that adding a major is a small, reviewed change.

### Deployment modes

PAM support is a separate, opt-in module built from the same C validation
sources as the OAuth validator. The two modules are independent artifacts:

| Mode | Installed modules | HBA method | PostgreSQL majors |
| --- | --- | --- | --- |
| OAuth only | `pg_oauth_validator` | `oauth` | 18, 19 |
| PAM only | `pg_oauth_pam` | `pam` | 15, 16, 17, 18, 19 |
| Both | both | per rule: `oauth` or `pam` | 18, 19 |

Neither module requires, loads or configures the other. Installing PAM never
changes OAuth behavior, and the reverse. Each is compiled separately per
supported PostgreSQL major. Packaging may ship them as separate packages or
separate build targets; an OAuth-only installation contains no PAM module and
needs no PAM development or runtime dependency. PAM requires a PAM-enabled
PostgreSQL build; no PostgreSQL fork is proposed.

The shared validation sources are compiled privately into each artifact. Each
artifact exports only its own entry points (the PostgreSQL validator symbols for
OAuth, `pam_sm_*` for PAM) and binds all other symbols locally, following the
interposition findings in ADR 0001. Loading both in one process must not let
either artifact resolve a symbol into the other's copy.

### Credential and policy

Accept only a raw compact JWT access token as the PAM credential, validated by
the same pipeline and token policy as OAuth: issuer-derived metadata and JWKS,
algorithm allowlist, signature before claims, audience, scopes, expiry and
token type. Do not strip `Bearer`, trim, truncate or accept alternate formats.

PAM authorization has two explicit modes, chosen by the stack arguments. Do not
mutate `PAM_USER` and do not apply OAuth usermaps; arbitrary maps are out of scope
and need a separate policy review.

- **Identity mode (default):** the validated identity, from `identity_claim`
  (`sub` by default), must equal the original requested database role exactly.
- **Delegated roles mode (`role_claim=<claim>`):** the configured claim must be a
  string or an array of distinct, nonempty strings that contains the requested
  role exactly. The identity claim is still required and validated and is the
  token's stable subject, but it need not equal the role. The semantics are those
  of the native validator's delegated mode: no special treatment of privileged
  roles, and the HBA `USER` field remains the independent allowlist of reachable
  roles. Native OAuth requires both `delegate_ident_mapping=1` in HBA and a role
  claim; PAM has no HBA switch, so the stack argument is the single explicit
  opt-in, and an unset or empty `role_claim` selects identity mode. A missing,
  wrong-typed, duplicate, empty or oversized claim denies.

The role claim is part of the policy: it is included in the policy digest that the
account stage compares and in every cache key.

### PAM stack requirements

Require a dedicated PAM service with authentication and account checks using
explicit success-only controls. No system includes, `sufficient`/`optional`
rules, `pam_permit` or password fallback may bypass denial. The module cannot
protect a stack that skips it. PostgreSQL HBA database/role/network restrictions
remain independent; deploy `hostssl` rules and clients that verify server
identity. Standard PAM items do not establish PostgreSQL TLS state or the
database name.

### Credential acquisition

Acquire the credential through one fixed echo-off conversation, without
forwarding it to other modules. Reject absent or empty credentials, conversation
failure, oversized replies and unsupported or asynchronous replies. Borrowed PAM
items remain PAM-owned; responses returned directly by the conversation use libc
ownership and are zeroized on a best-effort basis. A generic PAM C-string
response cannot reveal bytes hidden after its terminator, and PostgreSQL rejects
embedded NUL on the wire.

### Module entry points

Export `pam_sm_authenticate`, `pam_sm_acct_mgmt` and `pam_sm_setcred`. No OS
credentials are created: `setcred` deletion performs idempotent cleanup and
other operations deny. Session and password stacks are unsupported; explicit
stubs, if present, deny. Unsupported flags are handled deliberately rather than
silently enabling a credential-management mode.

### Transaction state

Invalidate old state before each authentication. Publish per-handle validated
state only after token validation and exact requested-role authorization. Bind
it to the original role, service/profile, immutable policy generation and
expiry/skew. Account checks deny missing or mismatched state and recheck expiry
with the same skew and a fresh clock, adding no second grace. The
maximum delay between validation completion and the account check is five
seconds. Repeated account checks require that same valid state; a new
authentication replaces it. Clean up on replacement and `pam_end`; process
termination must be safe when normal cleanup is skipped. Retain no bearer token
or full claim set in transaction state.

### Configuration

Policy is supplied as module arguments in the dedicated PAM stack, not in a
separate configuration file. The stack is already the root-owned trust anchor
that this ADR requires to be fail-closed, so policy there adds no new place where
it can be tampered with, and it needs no file-permission, symlink, schema or
reload handling in the module. HBA `pamservice=<name>` selects the stack, so
different HBA rules can use different issuers, audiences and scopes, as native
OAuth does through HBA. libpam reads the stack for each authentication and hands
the module a stable `argv`, so an edit affects only later transactions.

```
auth    [success=ok default=die] pg_oauth_pam.so issuer=https://idp.example/ \
            audience=postgres://primary scope=connect:postgres
account [success=ok default=die] pg_oauth_pam.so issuer=https://idp.example/ \
            audience=postgres://primary scope=connect:postgres
```

Arguments are `name=value` and mirror the OAuth validator's settings, with the
same meaning, defaults and ranges. The required arguments are `issuer`,
`audience` and `scope`. Optional arguments are `algorithms`, `token_types`,
`allow_missing_token_type`, `identity_claim`, `clock_skew_ms`, `max_token_size`
(PAM default 16 KiB, maximum 65530), `jwks_hosts`, `ca_file`, the cache and
refresh timing settings, and `allow_insecure_http` (development only, off by
default). `role_claim` (empty by default) enables delegated roles mode. No token claim, client environment or
path argument selects trust.

Parsing is strict and fail-closed. Deny on an unknown or duplicate argument, a
missing required argument, a malformed or out-of-range value, an embedded NUL or
control character, or an argument count or value length over a fixed bound. Do
not read or write any other file for policy; `ca_file` is read only for TLS
verification of provider endpoints.

The authentication and account lines must carry identical policy arguments. The
module computes a canonical policy digest at authentication and binds it into the
transaction state; the account stage denies if its own digest differs. This
catches a mismatched or edited stack between the two stages.

Policy identity for caching and isolation is the service name plus the canonical
policy bytes, compared in full (see ADR 0009). Cache capacity is a single
module-level setting, not a per-stack argument, because shared storage cannot be
resized per service; its mechanism is defined by the cache design. Linux-PAM
1.5.2 was tested: backslash continuation works; a value with spaces needs the
whole argument in brackets (`[name=a b]`); and configuration lines are read into
a fixed buffer, so a line over about 1 KiB fails closed instead of reaching the
module with arguments dropped. Operators must keep each module line short. The
same behavior was then observed with Linux-PAM 1.6.1, 1.7.1 and 1.7.2 through the
distribution RPM jobs; builds not exercised there (for example other
distributions or Enterprise Linux 9) still need qualification.

### Limits and diagnostics

PostgreSQL bounds the password packet to 65535 bytes including its four-byte
length and NUL, leaving 65530 credential bytes. Propose a 16 KiB default and a
65530-byte hard maximum for PAM. OAuth limits are unchanged. Never truncate.

Use stable, bounded diagnostics without token, identity, signature, raw `kid`,
claim set or provider-body disclosure. PostgreSQL's PAM logging records the
database username; do not promise OAuth's external authenticated-identity audit
representation. Bearer replay during token validity remains possible; expiry
does not terminate an established session, and connection pools need valid
tokens for each new physical connection.

## Evidence and gates

A follow-up check of the `REL_15_STABLE`, `REL_16_STABLE` and `REL_17_STABLE`
branch heads (not pinned commits) found the same PAM sequence in `auth.c`: set `PAM_USER`,
`PAM_RHOST` and the conversation, then call `pam_authenticate` and
`pam_acct_mgmt`. Both also define `PG_MAX_AUTH_TOKEN_LENGTH` as 65535. Pin exact
15.x, 16.x and 17.x release commits and repeat the inspection before implementation.

The initial source inspection covered PostgreSQL REL_18_6 commit
`724edf9bde9d356724ad384a2e196edc3c9f80f7` and REL_19_RC1 commit
`0b8bff042a997fe50fcd1c4c83b9ef1cc9ed8a89`. Both set the requested `PAM_USER` and
network `PAM_RHOST`, acquire the password through the conversation, and call both
`pam_authenticate` and `pam_acct_mgmt`. Linux-PAM v1.7.1 commit
`693c4f75b10b25e09f70fe0b22f41bdcf9a48968` provides the inspected module, item
and data contracts, and its prompt implementation does not enforce
`PAM_MAX_RESP_SIZE` as a universal credential limit. These are source-inspection
facts, not qualification of packaged libraries, drivers or terminals.

Before implementation is accepted:

- Confirm that a module loaded by libpam into a PostgreSQL backend can use the
  PostgreSQL symbols it needs (memory, logging, named shared memory) on both
  majors, and record the exact build and link flags.
- Run disposable Linux container tests on both majors with an unprivileged
  server, realistic and oversized signed JWTs, raw malformed packets,
  conversation failures, role mismatches, repeated calls, state/expiry failures,
  stack bypass, TLS/HBA enforcement, secret redaction and installed artifacts.
- Run the PAM real-connection suite on every supported major (15, 16, 17, 18, 19).
  Source inspection does not establish behavior on PostgreSQL 15, 16 and 17.
- Prove each deployment mode (OAuth only, PAM only, both) with real
  connections, and that removing either module does not affect the other.

Cross-connection cache coordination under [ADR 0009](0009-pam-cache-and-module-isolation.md)
blocks production release. No host PAM setup is part of contract review.

## References

- [18.6 authentication](https://github.com/postgres/postgres/blob/724edf9bde9d356724ad384a2e196edc3c9f80f7/src/backend/libpq/auth.c)
- [19 RC1 authentication](https://github.com/postgres/postgres/blob/0b8bff042a997fe50fcd1c4c83b9ef1cc9ed8a89/src/backend/libpq/auth.c)
- [Linux-PAM interfaces](https://github.com/linux-pam/linux-pam/blob/v1.7.1/libpam/include/security/pam_modules.h)
- [PAM item ownership](https://github.com/linux-pam/linux-pam/blob/v1.7.1/doc/man/pam_get_item.3.xml)
- [PAM transaction cleanup](https://github.com/linux-pam/linux-pam/blob/v1.7.1/libpam/pam_data.c)
- [PAM stack controls](https://github.com/linux-pam/linux-pam/blob/v1.7.1/doc/man/pam.conf-syntax.xml)
