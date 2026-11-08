import base64
import json
import os
import pathlib
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from integration_support import (
    AUDIENCE,
    SCOPE,
    TemporaryPostgres,
    attempt_oauth,
    psql,
)


ISSUER = "https://keycloak:8443/realms/pg-oauth"
TOKEN_ENDPOINT = ISSUER + "/protocol/openid-connect/token"
CLIENT_ID = "postgres-test"
WRONG_AUDIENCE_CLIENT_ID = "wrong-audience-test"
CLIENT_SECRET = "keycloak-interop-client-secret"
ADMIN_TOKEN_ENDPOINT = (
    "https://keycloak:8443/realms/master/protocol/openid-connect/token"
)
ADMIN_REALM_ENDPOINT = "https://keycloak:8443/admin/realms/pg-oauth"


def decode_segment(segment):
    padding = "=" * ((4 - len(segment) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


def token_parts(token):
    segments = token.split(".")
    assert len(segments) == 3
    return decode_segment(segments[0]), decode_segment(segments[1])


def fetch_tokens(ca_file, *, client_id=CLIENT_ID, scope=f"openid {SCOPE}"):
    context = ssl.create_default_context(cafile=str(ca_file))
    request = urllib.request.Request(
        TOKEN_ENDPOINT,
        data=urllib.parse.urlencode({
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": CLIENT_SECRET,
            "username": "alice",
            "password": "keycloak-interop-user-password",
            "scope": scope,
        }).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    last_error = None
    for _attempt in range(60):
        try:
            with urllib.request.urlopen(request, context=context, timeout=2) as response:
                assert response.status == 200
                return json.load(response)
        except urllib.error.HTTPError as error:
            body = error.read(4096).decode("utf-8", errors="replace")
            raise AssertionError(
                f"Keycloak token endpoint returned HTTP {error.code}: {body}"
            ) from error
        except (OSError, urllib.error.URLError) as error:
            last_error = error
            time.sleep(0.5)
    raise AssertionError(f"Keycloak did not become ready: {last_error}")


def admin_access_token(ca_file):
    context = ssl.create_default_context(cafile=str(ca_file))
    request = urllib.request.Request(
        ADMIN_TOKEN_ENDPOINT,
        data=urllib.parse.urlencode({
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "interop-admin",
            "password": "interop-admin-password",
        }).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(request, context=context, timeout=5) as response:
        assert response.status == 200
        return json.load(response)["access_token"]


def admin_request(ca_file, admin_token, url, *, method="GET", value=None,
                  expected=(200,)):
    context = ssl.create_default_context(cafile=str(ca_file))
    data = None
    headers = {"Authorization": f"Bearer {admin_token}"}
    if value is not None:
        data = json.dumps(value, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        url, data=data, headers=headers, method=method,
    )
    with urllib.request.urlopen(request, context=context, timeout=5) as response:
        assert response.status in expected
        body = response.read()
        return json.loads(body) if body else None


def rotate_signing_key(ca_file, admin_token, old_kid):
    realm = admin_request(ca_file, admin_token, ADMIN_REALM_ENDPOINT)
    admin_request(
        ca_file,
        admin_token,
        ADMIN_REALM_ENDPOINT + "/components",
        method="POST",
        expected=(201,),
        value={
            "name": "interop-rotated-rsa",
            "providerId": "rsa-generated",
            "providerType": "org.keycloak.keys.KeyProvider",
            "parentId": realm["id"],
            "config": {
                "priority": ["200"],
                "enabled": ["true"],
                "active": ["true"],
                "algorithm": ["RS256"],
                "keySize": ["2048"],
            },
        },
    )
    for _attempt in range(20):
        tokens = fetch_tokens(ca_file)
        header, _claims = token_parts(tokens["access_token"])
        if header["kid"] != old_kid:
            return tokens
        time.sleep(0.1)
    raise AssertionError("Keycloak did not activate the rotated signing key")


def wait_realm_available(ca_file):
    context = ssl.create_default_context(cafile=str(ca_file))
    url = ISSUER + "/.well-known/openid-configuration"
    for _attempt in range(150):
        try:
            with urllib.request.urlopen(url, context=context, timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.2)
    raise AssertionError("Keycloak realm did not become available")


def signal_and_wait(control_dir, signal_name, response_name):
    (control_dir / signal_name).write_text("ready\n", encoding="ascii")
    response = control_dir / response_name
    for _attempt in range(300):
        if response.exists():
            return
        time.sleep(0.1)
    raise AssertionError(f"interoperability harness did not create {response_name}")


def has_audience(claims, audience):
    value = claims.get("aud", [])
    return audience in ([value] if isinstance(value, str) else value)


def test_keycloak_26_5_rfc9068_access_token_and_rejections():
    pg_config = os.environ["PG_CONFIG"]
    validator_library = os.environ["VALIDATOR_LIBRARY"]
    client = pathlib.Path(os.environ["OAUTH_TEST_CLIENT"]).resolve()
    ca_file = pathlib.Path(os.environ["KEYCLOAK_CA_FILE"]).resolve()
    tls_key = pathlib.Path(os.environ["KEYCLOAK_TLS_KEY_FILE"]).resolve()
    control_dir = pathlib.Path(os.environ["KEYCLOAK_CONTROL_DIR"]).resolve()
    tokens = fetch_tokens(ca_file)
    wrong_scope_tokens = fetch_tokens(ca_file, scope="openid")
    wrong_audience_tokens = fetch_tokens(
        ca_file, client_id=WRONG_AUDIENCE_CLIENT_ID,
    )
    access_token = tokens["access_token"]
    id_token = tokens["id_token"]
    wrong_scope_token = wrong_scope_tokens["access_token"]
    wrong_audience_token = wrong_audience_tokens["access_token"]
    access_header, access_claims = token_parts(access_token)
    id_header, id_claims = token_parts(id_token)
    wrong_scope_header, wrong_scope_claims = token_parts(wrong_scope_token)
    wrong_audience_header, wrong_audience_claims = token_parts(
        wrong_audience_token
    )

    # Inspect only the documented, non-secret token shape. These unverified
    # fields are test observations and are never used to establish trust.
    assert access_header["alg"] == "RS256"
    assert access_header["typ"] == "at+jwt"
    assert access_header.get("kid")
    assert access_claims["iss"] == ISSUER
    assert has_audience(access_claims, AUDIENCE)
    assert SCOPE in access_claims["scope"].split()
    assert access_claims["sub"]
    assert access_claims["postgres_role"] == "appuser"
    assert set(access_claims["postgres_roles"]) >= {"app_reader", "reporting"}
    assert id_header["typ"] == "JWT"
    assert id_claims["iss"] == ISSUER
    assert id_claims["aud"] == CLIENT_ID
    assert wrong_scope_header["typ"] == "at+jwt"
    assert SCOPE not in wrong_scope_claims["scope"].split()
    assert wrong_audience_header["typ"] == "at+jwt"
    assert not has_audience(wrong_audience_claims, AUDIENCE)

    identity = access_claims["sub"]
    # Keycloak sends no-store/no-cache. The default cache_min_ttl would keep the
    # fetched keys usable for 30 s, so the outage check below needs 0 to see
    # the provider's directives honored.
    cluster = TemporaryPostgres(
        pg_config,
        validator_library,
        issuer=ISSUER,
        identity_map=(identity, "appuser"),
        extra_config="pg_oauth_validator.cache_min_ttl = 0\n",
        ca_file=ca_file,
        server_certificate=ca_file,
        server_key=tls_key,
    )
    scalar_cluster = TemporaryPostgres(
        pg_config,
        validator_library,
        issuer=ISSUER,
        role_claim="postgres_role",
        delegate_ident_mapping=True,
        hba_users="appuser",
        ca_file=ca_file,
        server_certificate=ca_file,
        server_key=tls_key,
    )
    delegated_cluster = TemporaryPostgres(
        pg_config,
        validator_library,
        issuer=ISSUER,
        role_claim="postgres_roles",
        delegate_ident_mapping=True,
        hba_users="app_reader,reporting,postgres",
        ca_file=ca_file,
        server_certificate=ca_file,
        server_key=tls_key,
    )
    admin_token = None
    try:
        cluster.start()
        psql(cluster, "CREATE ROLE appuser LOGIN")

        scalar_cluster.start()
        psql(scalar_cluster, "CREATE ROLE appuser LOGIN")
        scalar_result = attempt_oauth(
            scalar_cluster, client, token=access_token, user="appuser",
            issuer=ISSUER, sslmode="require",
        )
        scalar_wrong_role_result = attempt_oauth(
            scalar_cluster, client, token=access_token, user="postgres",
            issuer=ISSUER, sslmode="require",
        )

        delegated_cluster.start()
        psql(delegated_cluster, "CREATE ROLE app_reader LOGIN")
        psql(delegated_cluster, "CREATE ROLE reporting LOGIN")
        delegated_result = attempt_oauth(
            delegated_cluster, client, token=access_token, user="reporting",
            issuer=ISSUER, sslmode="require",
        )
        delegated_absent_role_result = attempt_oauth(
            delegated_cluster, client, token=access_token, user="postgres",
            issuer=ISSUER, sslmode="require",
        )

        access_result = attempt_oauth(
            cluster, client, token=access_token, user="appuser", issuer=ISSUER,
            sslmode="require",
        )
        id_result = attempt_oauth(
            cluster, client, token=id_token, user="appuser", issuer=ISSUER,
            sslmode="require",
        )
        wrong_scope_result = attempt_oauth(
            cluster, client, token=wrong_scope_token, user="appuser",
            issuer=ISSUER, sslmode="require",
        )
        wrong_audience_result = attempt_oauth(
            cluster, client, token=wrong_audience_token, user="appuser",
            issuer=ISSUER, sslmode="require",
        )
        wrong_issuer_result = attempt_oauth(
            cluster, client, token=access_token, user="appuser",
            issuer="https://keycloak:8443/realms/other", sslmode="require",
        )
        unmapped_role_result = attempt_oauth(
            cluster, client, token=access_token, user="postgres", issuer=ISSUER,
            sslmode="require",
        )

        admin_token = admin_access_token(ca_file)
        rotated_tokens = rotate_signing_key(
            ca_file, admin_token, access_header["kid"],
        )
        rotated_token = rotated_tokens["access_token"]
        rotated_header, rotated_claims = token_parts(rotated_token)
        assert rotated_header["typ"] == "at+jwt"
        assert rotated_header["kid"] != access_header["kid"]
        assert rotated_claims["sub"] == access_claims["sub"]

        rotated_result = attempt_oauth(
            cluster, client, token=rotated_token, user="appuser",
            issuer=ISSUER, sslmode="require",
        )
        old_key_result = attempt_oauth(
            cluster, client, token=access_token, user="appuser",
            issuer=ISSUER, sslmode="require",
        )
        assert rotated_result.returncode == 0
        assert old_key_result.returncode == 0

        signal_and_wait(
            control_dir, "outage-requested", "outage-ready",
        )
        outage_result = attempt_oauth(
            cluster, client, token=rotated_token, user="appuser",
            issuer=ISSUER, sslmode="require",
        )
        assert outage_result.returncode != 0

        signal_and_wait(
            control_dir, "recovery-requested", "recovery-ready",
        )
        wait_realm_available(ca_file)
        recovered_result = attempt_oauth(
            cluster, client, token=rotated_token, user="appuser",
            issuer=ISSUER, sslmode="require",
        )
        assert recovered_result.returncode == 0

        assert access_result.returncode == 0, access_result.stderr + "\n" + cluster.logs()
        assert scalar_result.returncode == 0, (
            scalar_result.stderr + "\n" + scalar_cluster.logs()
        )
        assert scalar_result.stdout.strip() == f"appuser|oauth:{identity}"
        assert scalar_wrong_role_result.returncode != 0
        assert delegated_result.returncode == 0, (
            delegated_result.stderr + "\n" + delegated_cluster.logs()
        )
        assert delegated_result.stdout.strip() == f"reporting|oauth:{identity}"
        assert delegated_absent_role_result.returncode != 0
        assert id_result.returncode != 0
        assert wrong_scope_result.returncode != 0
        assert wrong_audience_result.returncode != 0
        assert wrong_issuer_result.returncode != 0
        assert unmapped_role_result.returncode != 0
        logs = cluster.logs()
        results = (
            access_result, id_result, wrong_scope_result,
            wrong_audience_result, wrong_issuer_result, unmapped_role_result,
            rotated_result, old_key_result, outage_result, recovered_result,
            scalar_result, scalar_wrong_role_result, delegated_result,
            delegated_absent_role_result,
        )
        for token in (
            access_token, id_token, wrong_scope_token, wrong_audience_token,
            rotated_token,
        ):
            assert token not in logs
            for result in results:
                assert token not in result.stderr
    finally:
        cluster.stop()
        scalar_cluster.stop()
        delegated_cluster.stop()
