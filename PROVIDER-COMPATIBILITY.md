# OAuth provider compatibility

Last updated: 2026-10-18

This page records what has actually been exercised and the configuration needed
for those setups. It is not a provider support guarantee. The validator accepts
signed **access tokens** for PostgreSQL; OIDC discovery locates issuer metadata
and keys. OIDC ID tokens are not database credentials.

There are no provider-specific validator profiles. Every issuer uses the same
validation policy. PostgreSQL 19 accepts only `validator.policy=default` in an
OAuth HBA rule; PostgreSQL 18 omits that option. The demo's `provider.yml` is a
configuration input, not a validator profile or provider detector.

## Evidence

| Provider | Evidence in this repository | Limit |
| --- | --- | --- |
| Keycloak 26.5.0 | Opt-in [interoperability suite](tests/interop/keycloak/test_keycloak.py) with real PostgreSQL 19 OAuth connections | Pinned setup only; suite is separate from the default offline CI |
| WorkOS AuthKit Connect | Successful manual staging connection on 2026-10-18 using the [example configuration](demo/providers/workos.example.yml) | One positive smoke test; no tracked provider-specific negative suite |
| Auth0 | User-reported manual test with an older validator version | Version, configuration, and negative results are not recorded; retest with the current version before relying on it |

Other issuers have not been exercised as provider interoperability tests here.
Passing generic JWT unit or local-IdP tests does not establish compatibility
with a particular provider.

## Configuration by provider

The values below describe the tested setup or, for Auth0, a configuration to
verify during a new test. Set `pg_oauth_validator.audiences` to the exact `aud`
in the **access token**. Set the HBA `issuer` to the exact discovered issuer and
`scope` to a database-specific scope actually present in the access token.
The scopes may be in the `scope` claim or, when that is absent, in `scp` (as
Microsoft Entra ID and Okta emit); a token with both is denied. `scp` handling
is unit-tested only, and there is no interoperability evidence for either
provider.
These values are deployment-specific; no issuer, audience, or client ID is
inferred from a provider name. `audiences` is also cluster-wide; the current
configuration does not assign a different audience or token-type exception to
each HBA issuer.

| Setting | Keycloak 26.5.0 | WorkOS AuthKit Connect | Auth0, retest required |
| --- | --- | --- | --- |
| Provider setup | Enable RFC 9068 access-token header type; add PostgreSQL audience mapper and consent-visible `connect:postgres` scope | Issue a Connect user access token with a database scope; configure a role claim if delegating role mapping | Configure a custom API with RFC 9068 access-token dialect and a database scope |
| HBA `issuer` | Exact realm issuer | Exact AuthKit tenant issuer | Exact tenant or custom-domain issuer used to obtain the token |
| `pg_oauth_validator.audiences` | PostgreSQL audience added by mapper | Exact Connect user access-token `aud`; in the tested setup this was distinct from the public device client ID | Custom API identifier, matching access-token `aud` |
| HBA `scope` | `connect:postgres` | `connect:postgres` | Database scope granted to the client, for example `connect:postgres` |
| Token type | `at+jwt`; default settings | Missing `typ` observed; set `allow_missing_token_type=on` | RFC 9068 token type expected; verify actual header with current Auth0 setup |
| Signing algorithm | RS256 in the test realm | Must match `allowed_algorithms` | Configure and verify an allowed asymmetric algorithm |
| Identity and role | `sub` plus `pg_ident.conf` in the test | `identity_claim=sub`, `role_claim=role`, HBA `delegate_ident_mapping=1` in the tested setup | Choose stable identity and an explicit usermap or delegated role claim |

The default `allowed_token_types` is `at+jwt,application/at+jwt`; missing `typ`
is rejected by default. WorkOS required the explicit missing-type exception in
the tested setup. This is a cluster-wide setting, so enabling it affects every
issuer served by the same PostgreSQL instance. Enable it only after establishing
that ID and session tokens
from the same issuer cannot satisfy **both** the configured access-token
audience and database scope. A present unrecognized `typ` still fails. See
[ADR 0004](docs/adr/0004-token-type-compatibility.md) and the [configuration
reference](docs/configuration.md).

For direct mapping, the selected identity claim (default `sub`) must match the
requested PostgreSQL role or a `pg_ident.conf` entry. For delegated mapping,
configure `role_claim` and `delegate_ident_mapping=1`; the requested role must
match the token claim and the HBA `USER` field. `sub` and a valid selected
identity remain required and are recorded in `system_user` even with delegation.

### Keycloak

The [demo realm](demo/keycloak-realm.json) shows the RFC 9068 header option,
audience mapper, and requested scope. Run `make interop-keycloak` for the pinned
26.5.0 setup. Its [test description](docs/development.md#interoperability-and-test-limits)
lists accepted and rejected connections, signing-key rotation, and outage
behavior. The generic [demo tutorial](demo/README.md) shows how to connect.
Keycloak documents the [audience protocol mapper](https://www.keycloak.org/admin-api/protocol-mappers).

### WorkOS AuthKit Connect

Copy [the WorkOS example](demo/providers/workos.example.yml) to the ignored
`demo/local/provider.yml`, fill in your tenant issuer, access-token audience,
and public device client ID, then follow the [external-provider tutorial](demo/README.md).
The observed token had no `typ`; the example opts into the missing-type
exception and delegates `app_reader` authorization to its `role` claim. The
successful query returned `current_user=app_reader` and
`system_user=oauth:<WorkOS user ID>`. This does not yet establish rejection of
WorkOS ID or session tokens. Consult the WorkOS [Connect token claims](https://workos.com/docs/authkit/connect/token-claims)
and [JWT template](https://workos.com/docs/authkit/jwt-templates) documentation
when setting its audience, scope, and role claim.

### Auth0

Auth0 documents a [`rfc9068_profile` access-token dialect](https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles)
for custom APIs. A new interoperability test should record the exact issuer,
custom API audience, scope, token header and claims, signing algorithm, and
Auth0 tenant configuration. It must reject same-issuer ID tokens, wrong
audience, missing scope, and unauthorized role requests before this page calls
the current validator interoperable with Auth0. The existing unit test for a
literal `auth0|…` subject only checks identity handling; it is not a live Auth0
test.

## Evaluating another issuer

Use the [configuration reference](docs/configuration.md) and inspect a
sanitized access-token header and claims before setting policy. Verify exact
issuer, audience, token type, allowed asymmetric algorithm, `scope`, stable
identity, and role mapping. Exercise both an accepted access token and rejected
ID/session tokens, wrong audience, missing scope, expired token, untrusted key,
and provider outage. Keep tokens and private credentials out of repository
fixtures and logs. If the issuer needs a claim syntax the validator does not
implement, document that incompatibility instead of assuming a profile exists.
