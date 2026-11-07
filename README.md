# pg_oauth_validator

Authenticate PostgreSQL connections with signed OAuth 2.0 JWT access tokens
from an explicitly trusted issuer. The validator discovers signing keys through
OIDC, verifies the token and required database scopes, and returns a stable
identity for PostgreSQL role mapping. Optional delegated role claims are also
supported.

PostgreSQL 18 is the stable target; PostgreSQL 19 support is preview-only.
Build a separate module for each major version. The project is prerelease
software; passing tests alone does not establish production readiness.

The default accepts `at+jwt` and `application/at+jwt` access tokens. OIDC ID
tokens and opaque tokens are not database credentials. A missing `typ` requires
an explicit [compatibility setting](docs/configuration.md) and issuer-specific
evidence that ID/session tokens cannot satisfy the audience and scope policy.

## Quickstart: connect with Keycloak

This runnable example starts PostgreSQL 18 with the validator and a local
Keycloak realm. You need Docker with Compose; no local PostgreSQL installation
or provider account is required. From the repository root:

1. Start the services. The first build may take a few minutes.

   ```sh
   docker compose up --build -d
   ```

2. Connect with the bundled PostgreSQL 18 `psql` client and run a query:

   ```sh
   docker compose run --rm psql -c 'SELECT current_user, system_user;'
   ```

3. `psql` prints a device code and waits for authorization. In your browser,
   open `https://localhost:8443/realms/pg-oauth/device?user_code=CODE`, replacing
   `CODE` with the printed code. Sign in as **alice** with password
   **demo-alice-password**, then approve **Connect to the demo PostgreSQL
   database**. The locally generated HTTPS certificate may require you to trust
   the demo CA; the [Keycloak quickstart guide](demo/README.md) shows how.

4. Return to the terminal. The query should show `app_reader` as
   `current_user` and `oauth:00000000-0000-0000-0000-000000000001` as
   `system_user`. Run `docker compose run --rm psql` for an interactive session;
   each new connection starts a new device authorization.

Stop the services with `docker compose down`. To also delete the disposable
database and generated certificates, run `docker compose down --volumes`. The
[Keycloak quickstart guide](demo/README.md) explains the sample configuration
and how to use [`compose.external.yml`](compose.external.yml) with a single
ignored YAML profile for your own issuer, including a locally verified
[WorkOS AuthKit example](demo/providers/workos.example.yml). This stack uses
published demo credentials and is intended for local evaluation.

## Configure your own server

[Install](docs/operations.md) the module for your PostgreSQL major version.
Configure the explicit resource audience in `postgresql.conf`:

```conf
oauth_validator_libraries = 'pg_oauth_validator'
pg_oauth_validator.audiences = 'https://postgres.example.internal/'
```

Suppose your issuer issues access tokens with `sub=principal-123`, that audience,
and the scope `connect:postgres`. Map the external identity to a database role:

```conf
# pg_hba.conf
hostssl appdb app_reader 10.0.0.0/8 oauth \
    issuer="https://idp.example/" scope="connect:postgres" \
    validator=pg_oauth_validator map=oauthmap

# pg_ident.conf: map-name  authenticated-identity  PostgreSQL-role
oauthmap principal-123 app_reader
```

Create the role if it does not already exist:

```sql
CREATE ROLE app_reader LOGIN;
```

Reload PostgreSQL after configuration changes. A client requests `app_reader`;
the validator authenticates `principal-123`, and PostgreSQL checks the usermap.
`current_user` is `app_reader`; `system_user` is `oauth:principal-123`.
Use an OAuth-capable client configured for your issuer, with `sslmode=verify-full`
and the appropriate PostgreSQL CA trust.

Without `map=`, the identity must exactly equal the requested role. For custom
identity claims or delegated roles, see the
[configuration guide](docs/configuration.md#hba-and-identity-mapping).
PostgreSQL 19 additionally accepts `validator.policy=default`; PostgreSQL 18
must omit it.

Before rollout, test accepted and rejected tokens, restrict HBA databases,
roles and networks, and retain a protected non-OAuth administrative recovery
path. Configuration, token, network and internal failures deny authentication.
See [operations](docs/operations.md) for provider outages, redaction, reloads,
upgrades and rollback.

## Documentation

| Need | Read |
| --- | --- |
| Settings and role mapping | [Configuration](docs/configuration.md) |
| Installation, rollout and recovery | [Operations](docs/operations.md) |
| PAM token authentication for PostgreSQL 15-19 (experimental) | [PAM guide](docs/pam.md) |
| Demo and external issuer setup | [Tutorial](demo/README.md) |
| Tested issuers and limitations | [Provider compatibility](PROVIDER-COMPATIBILITY.md) |
| Product and security contract | [Features](FEATURES.md) |
| Implementation and design rationale | [Architecture](docs/architecture.md), [ADRs](docs/adr/) |
| Build and test commands | [Development](docs/development.md) |
| Packaging and publication | [Release checklist](docs/release-readiness.md), [experimental RPMs](docs/rpm-platforms.md) |

Each topic has one maintained reference above. ADRs record decisions; dated
release and security records capture evidence at the time of review and are
not rolling claims about the current tree. Older development narratives remain
available in Git history.

## License

[PostgreSQL License](LICENSE). See [third-party notices](THIRD-PARTY-NOTICES.md)
for incorporated and linked components.
