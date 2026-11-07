import concurrent.futures
import os
import pathlib
import subprocess
import tempfile
import time
import uuid

import pytest

from integration_support import (
    AUDIENCE,
    IDP_RESPONSE_SECRET,
    ISSUER,
    TOKEN,
    LocalIdp,
    TemporaryPostgres,
    attempt_oauth,
    psql,
    psql_argv,
    reload_setting,
    wait_setting,
)


@pytest.fixture
def integration_environment():
    pg_config = os.environ["PG_CONFIG"]
    validator_library = os.environ["VALIDATOR_LIBRARY"]
    client = pathlib.Path(os.environ["OAUTH_TEST_CLIENT"]).resolve()
    return pg_config, validator_library, client


@pytest.mark.parametrize("policy", [None, "default"])
def test_real_oauth_connection_fails_closed(integration_environment, policy):
    pg_config, validator_library, client = integration_environment
    cluster = TemporaryPostgres(pg_config, validator_library, policy=policy)
    if policy is not None and cluster.major < 19:
        pytest.skip("validator.policy is available in PostgreSQL 19 and later")

    try:
        cluster.start()
        assert psql(cluster, "SHOW unix_socket_directories").stdout.strip() == str(cluster.root)
        assert psql(cluster, "SHOW logging_collector").stdout.strip() == "off"
        assert psql(cluster, "SHOW log_destination").stdout.strip() == "stderr"
        result = attempt_oauth(cluster, client)
        logs = cluster.logs()

        assert result.returncode != 0
        assert TOKEN not in result.stdout
        assert TOKEN not in result.stderr
        assert TOKEN not in logs
        assert "pg_oauth_validator" in logs
    finally:
        cluster.stop()

def test_pg19_unknown_policy_fails_closed(integration_environment):
    pg_config, validator_library, client = integration_environment
    cluster = TemporaryPostgres(pg_config, validator_library, policy="unknown")
    if cluster.major < 19:
        pytest.skip("custom validator options are available in PostgreSQL 19 and later")

    try:
        cluster.start()
        result = attempt_oauth(cluster, client)
        logs = cluster.logs()

        assert result.returncode != 0
        assert TOKEN not in result.stderr
        assert TOKEN not in logs
    finally:
        cluster.stop()


def test_missing_audience_fails_closed(integration_environment):
    pg_config, validator_library, client = integration_environment
    cluster = TemporaryPostgres(pg_config, validator_library, audience="")

    try:
        cluster.start()
        result = attempt_oauth(cluster, client)
        logs = cluster.logs()

        assert result.returncode != 0
        assert TOKEN not in result.stderr
        assert TOKEN not in logs
    finally:
        cluster.stop()


@pytest.mark.parametrize("setting,value", [
    ("identity_format", "issuer_qualified"),
    ("authorization_mode", "claim_roles"),
    ("roles_claim", "roles"),
])
def test_removed_setting_fails_closed(integration_environment, setting, value):
    pg_config, validator_library, client = integration_environment
    cluster = TemporaryPostgres(
        pg_config, validator_library,
        extra_config=f"pg_oauth_validator.{setting} = '{value}'\n",
    )
    try:
        cluster.start()
        result = attempt_oauth(cluster, client)
        assert result.returncode != 0
        assert f"removed OAuth validator setting is configured: pg_oauth_validator.{setting}" in cluster.logs()
        assert TOKEN not in cluster.logs() + result.stderr
    finally:
        cluster.stop()


def test_valid_token_uses_normal_pg_ident_mapping(integration_environment):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-idp-") as directory:
        idp = LocalIdp(pathlib.Path(directory))
        identity = "principal"
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            identity_map=(identity, "appuser"), ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        valid = idp.sign()
        insufficient_scope = idp.sign(scope="read:metadata")
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)
        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN")

            accepted = attempt_oauth(
                cluster, client, token=valid, user="appuser", issuer=idp.issuer,
                sslmode="require",
            )
            assert accepted.returncode == 0, accepted.stderr + "\n" + cluster.logs()
            assert accepted.stdout.strip() == "appuser|oauth:principal"
            assert 'identity="principal" method=oauth' in cluster.logs()

            psql(cluster, "ALTER SYSTEM SET pg_oauth_validator.audiences "
                          "TO 'https://other-resource.example/'")
            psql(cluster, "SELECT pg_reload_conf()")
            wait_setting(cluster, "pg_oauth_validator.audiences",
                         "https://other-resource.example/")
            rejected_after_reload = attempt_oauth(
                cluster, client, token=valid, user="appuser", issuer=idp.issuer,
                sslmode="require",
            )
            assert rejected_after_reload.returncode != 0

            psql(cluster, "ALTER SYSTEM SET pg_oauth_validator.audiences "
                          f"TO '{AUDIENCE}'")
            psql(cluster, "SELECT pg_reload_conf()")
            wait_setting(cluster, "pg_oauth_validator.audiences", AUDIENCE)
            accepted_after_reload = attempt_oauth(
                cluster, client, token=valid, user="appuser", issuer=idp.issuer,
                sslmode="require",
            )
            assert accepted_after_reload.returncode == 0

            administrative = attempt_oauth(
                cluster, client, token=valid, user="postgres", issuer=idp.issuer,
                sslmode="require",
            )
            assert administrative.returncode != 0

            hba_path = cluster.data / "pg_hba.conf"
            hba = hba_path.read_text(encoding="utf-8")
            hba_path.write_text(
                hba.replace("map=oauthmap", "delegate_ident_mapping=1"),
                encoding="utf-8",
            )
            psql(cluster, "SELECT pg_reload_conf()")
            hba_errors = psql(
                cluster,
                "SELECT error FROM pg_hba_file_rules WHERE error IS NOT NULL",
            )
            assert hba_errors.stdout.strip() == ""
            delegated = attempt_oauth(
                cluster, client, token=valid, user="postgres", issuer=idp.issuer,
                sslmode="require",
            )
            assert delegated.returncode != 0

            rejected_scope = attempt_oauth(
                cluster, client, token=insufficient_scope,
                user="appuser", issuer=idp.issuer,
                sslmode="require",
            )
            assert rejected_scope.returncode != 0

            logs = cluster.logs()
            for secret in (valid, insufficient_scope):
                assert secret not in logs
                assert secret not in administrative.stderr
                assert secret not in rejected_scope.stderr
                assert secret not in rejected_after_reload.stderr
                assert secret not in delegated.stderr
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


def test_invalid_access_tokens_are_denied_by_postgres(integration_environment):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-invalid-token-") as directory:
        idp = LocalIdp(pathlib.Path(directory))
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            identity_map=("principal", "appuser"), ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)
        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN")
            valid = idp.sign()
            signed_prefix, signature = valid.rsplit(".", 1)
            tampered = signed_prefix + "." + (
                "A" if signature[0] != "A" else "B"
            ) + signature[1:]
            invalid_tokens = {
                "expired": idp.sign(expiry=int(time.time()) - 120),
                "wrong audience": idp.sign(audience="postgres://other"),
                "wrong issuer": idp.sign(
                    extra_claims={"iss": "https://wrong.example/"}
                ),
                "insufficient scope": idp.sign(scope="read:metadata"),
                "non-string scope": idp.sign(extra_claims={"scope": None}),
                "ID token": idp.sign(token_type="JWT"),
                "tampered signature": tampered,
                "malformed token": "not-a-jwt",
            }

            def connect(token):
                return attempt_oauth(
                    cluster, client, token=token, user="appuser",
                    issuer=idp.issuer, sslmode="require",
                )

            assert connect(valid).returncode == 0, cluster.logs()
            for reason, token in invalid_tokens.items():
                rejected = connect(token)
                assert rejected.returncode != 0, f"{reason} was accepted"
                assert token not in rejected.stderr
            assert connect(valid).returncode == 0, cluster.logs()
            logs = cluster.logs()
            for token in (valid, *invalid_tokens.values()):
                assert token not in logs
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


def test_direct_identity_and_delegated_roles(integration_environment):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-idp-roles-") as directory:
        idp = LocalIdp(pathlib.Path(directory))
        direct_cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        delegated_cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            role_claim="roles", delegate_ident_mapping=True,
            hba_users="app_reader,reporting,postgres", ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        policy_only_cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            role_claim="roles", delegate_ident_mapping=False,
            hba_users="reporting", ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        hba_only_cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            delegate_ident_mapping=True,
            hba_users="reporting", ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        hba_capped_cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            role_claim="roles", delegate_ident_mapping=True,
            hba_users="reporting", ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        direct_token = idp.sign(subject="provider-subject")
        delegated_token = idp.sign(
            extra_claims={"roles": ["app_reader", "reporting"]},
        )
        insufficient_roles = idp.sign(
            extra_claims={"roles": ["app_reader"]},
        )
        privileged_token = idp.sign(
            extra_claims={"roles": ["postgres"]},
        )
        duplicate_roles = idp.sign(
            extra_claims={"roles": ["reporting", "reporting"]},
        )
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)
        try:
            direct_cluster.start()
            psql(direct_cluster, 'CREATE ROLE "provider-subject" LOGIN')
            accepted_direct = attempt_oauth(
                direct_cluster, client, token=direct_token,
                user="provider-subject", issuer=idp.issuer, sslmode="require",
            )
            assert accepted_direct.returncode == 0, (
                accepted_direct.stderr + "\n" + direct_cluster.logs()
            )
            assert accepted_direct.stdout.strip() == "provider-subject|oauth:provider-subject"
            assert 'identity="provider-subject" method=oauth' in direct_cluster.logs()
            assert attempt_oauth(
                direct_cluster, client, token=direct_token,
                user="postgres", issuer=idp.issuer, sslmode="require",
            ).returncode != 0

            delegated_cluster.start()
            psql(delegated_cluster, "CREATE ROLE app_reader LOGIN")
            psql(delegated_cluster, "CREATE ROLE reporting LOGIN")
            accepted_delegated = attempt_oauth(
                delegated_cluster, client, token=delegated_token,
                user="reporting", issuer=idp.issuer, sslmode="require",
            )
            assert accepted_delegated.returncode == 0, (
                accepted_delegated.stderr + "\n" + delegated_cluster.logs()
            )
            assert accepted_delegated.stdout.strip() == "reporting|oauth:principal"
            assert 'identity="principal" method=oauth' in delegated_cluster.logs()
            scalar_role = idp.sign(extra_claims={"roles": "app_reader"})
            accepted_scalar = attempt_oauth(
                delegated_cluster, client, token=scalar_role,
                user="app_reader", issuer=idp.issuer, sslmode="require",
            )
            assert accepted_scalar.returncode == 0, accepted_scalar.stderr
            assert accepted_scalar.stdout.strip() == "app_reader|oauth:principal"
            assert attempt_oauth(
                delegated_cluster, client, token=scalar_role,
                user="reporting", issuer=idp.issuer, sslmode="require",
            ).returncode != 0
            assert attempt_oauth(
                delegated_cluster, client, token=delegated_token,
                user="postgres", issuer=idp.issuer, sslmode="require",
            ).returncode != 0
            accepted_privileged = attempt_oauth(
                delegated_cluster, client, token=privileged_token,
                user="postgres", issuer=idp.issuer, sslmode="require",
            )
            assert accepted_privileged.returncode == 0, (
                accepted_privileged.stderr + "\n" + delegated_cluster.logs()
            )
            assert accepted_privileged.stdout.strip() == "postgres|oauth:principal"
            assert attempt_oauth(
                delegated_cluster, client, token=insufficient_roles,
                user="reporting", issuer=idp.issuer, sslmode="require",
            ).returncode != 0
            assert attempt_oauth(
                delegated_cluster, client, token=duplicate_roles,
                user="reporting", issuer=idp.issuer, sslmode="require",
            ).returncode != 0

            policy_only_cluster.start()
            psql(policy_only_cluster, "CREATE ROLE reporting LOGIN")
            assert attempt_oauth(
                policy_only_cluster, client, token=delegated_token,
                user="reporting", issuer=idp.issuer, sslmode="require",
            ).returncode != 0

            hba_only_cluster.start()
            psql(hba_only_cluster, "CREATE ROLE reporting LOGIN")
            assert attempt_oauth(
                hba_only_cluster, client, token=delegated_token,
                user="reporting", issuer=idp.issuer, sslmode="require",
            ).returncode != 0

            hba_capped_cluster.start()
            assert attempt_oauth(
                hba_capped_cluster, client, token=privileged_token,
                user="postgres", issuer=idp.issuer, sslmode="require",
            ).returncode != 0
        finally:
            direct_cluster.stop()
            delegated_cluster.stop()
            policy_only_cluster.stop()
            hba_only_cluster.stop()
            hba_capped_cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


def test_reload_separates_trust_policy_cache_entries(integration_environment):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-idp-reload-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=120)
        default_identity = (
            "principal"
        )
        uid_identity = "stable-1"
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            identity_map=(default_identity, "appuser"), ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        default_token = idp.sign()
        alternate_type_token = idp.sign(token_type="application/at+jwt")
        missing_type_token = idp.sign(token_type=None)
        uid_token = idp.sign(extra_claims={"uid": "stable-1"})
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)

        def connect(token, user="appuser"):
            return attempt_oauth(
                cluster, client, token=token, user=user,
                issuer=idp.issuer, sslmode="require",
            )

        def assert_accepts_after_fresh_fetch(token=default_token, user="appuser"):
            before = idp.request_counts()
            result = connect(token, user=user)
            assert result.returncode == 0, result.stderr + "\n" + cluster.logs()
            after = idp.request_counts()
            assert after["metadata"] > before["metadata"]
            assert after["jwks"] > before["jwks"]

        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN")
            psql(cluster, "CREATE ROLE uiduser LOGIN")
            accepted = connect(default_token)
            assert accepted.returncode == 0, accepted.stderr + "\n" + cluster.logs()
            assert connect(alternate_type_token).returncode == 0
            assert connect(missing_type_token).returncode != 0

            reload_setting(
                cluster, "pg_oauth_validator.allowed_algorithms", "RS256",
            )
            assert_accepts_after_fresh_fetch()

            reload_setting(
                cluster, "pg_oauth_validator.allowed_token_types",
                "application/at+jwt",
            )
            assert connect(default_token).returncode != 0
            assert_accepts_after_fresh_fetch(alternate_type_token)

            reload_setting(cluster, "pg_oauth_validator.allow_missing_token_type", "on")
            assert_accepts_after_fresh_fetch(missing_type_token)
            assert connect(idp.sign(token_type="JWT")).returncode != 0
            assert connect(idp.sign(token_type=None, scope="openid")).returncode != 0
            assert connect(idp.sign(token_type=None,
                                    audience="https://client.example/")).returncode != 0

            ident_path = cluster.data / "pg_ident.conf"
            ident_path.write_text(
                ident_path.read_text(encoding="utf-8") +
                f"oauthmap {uid_identity} uiduser\n",
                encoding="utf-8",
            )
            reload_setting(cluster, "pg_oauth_validator.identity_claim", "uid")
            psql(cluster, "SELECT pg_reload_conf()")
            before_identity_reload = idp.request_counts()
            assert connect(alternate_type_token).returncode != 0
            after_identity_reload = idp.request_counts()
            assert (after_identity_reload["metadata"] >
                    before_identity_reload["metadata"])
            assert after_identity_reload["jwks"] > before_identity_reload["jwks"]
            uid_alternate_type_token = idp.sign(
                token_type="application/at+jwt",
                extra_claims={"uid": "stable-1"},
            )
            accepted_uid = connect(uid_alternate_type_token, user="uiduser")
            assert accepted_uid.returncode == 0
            assert accepted_uid.stdout.strip() == "uiduser|oauth:stable-1"
            assert 'identity="stable-1" method=oauth' in cluster.logs()
            no_subject = idp.sign(
                token_type="application/at+jwt",
                extra_claims={"sub": None, "uid": "stable-1"},
            )
            assert connect(no_subject, user="uiduser").returncode != 0

            reload_setting(
                cluster, "pg_oauth_validator.allowed_jwks_hosts", "localhost",
            )
            assert_accepts_after_fresh_fetch(uid_alternate_type_token, user="uiduser")

            reload_setting(
                cluster, "pg_oauth_validator.allow_insecure_http", "on",
            )
            assert_accepts_after_fresh_fetch(uid_alternate_type_token, user="uiduser")

            reload_setting(
                cluster, "pg_oauth_validator.clock_skew", "30s",
            )
            assert_accepts_after_fresh_fetch(uid_alternate_type_token, user="uiduser")

            reload_setting(
                cluster, "pg_oauth_validator.max_token_size", "4kB",
            )
            assert_accepts_after_fresh_fetch(uid_alternate_type_token, user="uiduser")

            for setting, value in (
                ("metadata_default_ttl", "4min"),
                ("jwks_default_ttl", "4min"),
                ("cache_max_ttl", "30min"),
                ("jwks_stale_grace", "1s"),
                ("unknown_kid_refresh_cooldown", "10s"),
            ):
                reload_setting(
                    cluster, f"pg_oauth_validator.{setting}", value,
                )
                assert_accepts_after_fresh_fetch(
                    uid_alternate_type_token, user="uiduser",
                )

            reload_setting(cluster, "pg_oauth_validator.ca_file", "/missing/ca.pem")
            rejected_bad_ca = connect(uid_alternate_type_token, user="uiduser")
            assert rejected_bad_ca.returncode != 0

            original_ca = str(cluster.data / "oauth-ca.pem")
            reload_setting(cluster, "pg_oauth_validator.ca_file", original_ca)
            restored = connect(uid_alternate_type_token, user="uiduser")
            assert restored.returncode == 0, restored.stderr + "\n" + cluster.logs()

            reload_setting(
                cluster, "pg_oauth_validator.cache_max_entries", "33",
            )
            rejected_capacity_mismatch = connect(
                uid_alternate_type_token, user="uiduser",
            )
            assert rejected_capacity_mismatch.returncode != 0
            reload_setting(
                cluster, "pg_oauth_validator.cache_max_entries", "32",
            )
            restored_capacity = connect(uid_alternate_type_token, user="uiduser")
            assert restored_capacity.returncode == 0

            logs = cluster.logs()
            for secret in (
                default_token, alternate_type_token, uid_token,
                uid_alternate_type_token,
            ):
                assert secret not in logs
                assert secret not in rejected_bad_ca.stderr
                assert secret not in rejected_capacity_mismatch.stderr
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


def test_eddsa_requires_administrator_allowance_and_binds_key_type(
    integration_environment,
):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-idp-eddsa-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=120)
        # A mixed key set is what an issuer with per-client algorithms
        # publishes; only the kid-matched key may be considered.
        idp.rotate("eddsa-key", retain_previous=True, algorithm="EdDSA")
        identity = "principal"
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            identity_map=(identity, "appuser"), ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        rsa_token = idp.sign(key_id="integration-key")
        eddsa_token = idp.sign(key_id="eddsa-key")
        # Algorithm confusion: an EdDSA signature claiming RS256 against the
        # Ed25519 key, and an EdDSA header selecting the RSA key.
        relabelled_token = idp.sign(key_id="eddsa-key", header_algorithm="RS256")
        wrong_key_token = idp.sign(
            key_id="eddsa-key", header_key_id="integration-key",
        )
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)

        def connect(token):
            return attempt_oauth(
                cluster, client, token=token, user="appuser",
                issuer=idp.issuer, sslmode="require",
            )

        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN")

            # Secure default: EdDSA is not enabled unless an administrator
            # lists it; the RSA key in the same set remains usable.
            assert connect(rsa_token).returncode == 0, cluster.logs()
            rejected_default = connect(eddsa_token)
            assert rejected_default.returncode != 0

            reload_setting(
                cluster, "pg_oauth_validator.allowed_algorithms", "RS256,EdDSA",
            )
            accepted = connect(eddsa_token)
            assert accepted.returncode == 0, accepted.stderr + "\n" + cluster.logs()
            assert connect(rsa_token).returncode == 0

            rejected_relabelled = connect(relabelled_token)
            rejected_wrong_key = connect(wrong_key_token)
            assert rejected_relabelled.returncode != 0
            assert rejected_wrong_key.returncode != 0

            reload_setting(
                cluster, "pg_oauth_validator.allowed_algorithms", "EdDSA",
            )
            assert connect(eddsa_token).returncode == 0
            rejected_rsa_only = connect(rsa_token)
            assert rejected_rsa_only.returncode != 0

            logs = cluster.logs()
            for secret in (
                rsa_token, eddsa_token, relabelled_token, wrong_key_token,
            ):
                assert secret not in logs
                for result in (
                    rejected_default, rejected_relabelled, rejected_wrong_key,
                    rejected_rsa_only,
                ):
                    assert secret not in result.stderr
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


@pytest.mark.slow
@pytest.mark.xdist_group(name="timing")
def test_local_idp_rotation_outage_and_recovery(integration_environment):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-idp-lifecycle-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=3)
        identity = "principal"
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            identity_map=(identity, "appuser"), ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        token_a = idp.sign(key_id="integration-key")
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)

        def connect(token):
            return attempt_oauth(
                cluster, client, token=token, user="appuser",
                issuer=idp.issuer, sslmode="require",
            )

        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN")

            assert connect(token_a).returncode == 0

            idp.rotate("rotated-key")
            token_b = idp.sign(key_id="rotated-key")
            assert connect(token_b).returncode == 0
            assert connect(token_a).returncode == 0

            idp.retire("integration-key")
            time.sleep(3.2)
            assert connect(token_b).returncode == 0
            retired = connect(token_a)
            assert retired.returncode != 0

            requests_before_outage = idp.request_counts()
            idp.outage = True
            assert connect(token_b).returncode == 0
            assert idp.request_counts() == requests_before_outage

            time.sleep(3.2)
            expired_during_outage = connect(token_b)
            assert expired_during_outage.returncode != 0
            assert (idp.request_counts()["metadata"] >
                    requests_before_outage["metadata"])

            idp.outage = False
            recovered = connect(token_b)
            assert recovered.returncode == 0, recovered.stderr + "\n" + cluster.logs()

            logs = cluster.logs()
            for token in (token_a, token_b):
                assert token not in logs
                assert token not in retired.stderr
                assert token not in expired_during_outage.stderr
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


@pytest.mark.slow
@pytest.mark.xdist_group(name="timing")
def test_expired_jwks_refetch_and_outage_denies_all_tokens(integration_environment):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-jwks-expiry-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=120,
                       jwks_cache_max_age=1)
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            identity_map=("principal", "appuser"), ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)

        def connect(token):
            return attempt_oauth(
                cluster, client, token=token, user="appuser",
                issuer=idp.issuer, sslmode="require",
            )

        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN")
            first_token = idp.sign()
            second_token = idp.sign(extra_claims={"jti": "second-token"})
            assert connect(first_token).returncode == 0, cluster.logs()
            initial_requests = idp.request_counts()
            assert initial_requests == {"metadata": 1, "jwks": 1}

            time.sleep(1.2)
            assert connect(first_token).returncode == 0, cluster.logs()
            refetched = idp.request_counts()
            assert refetched == {"metadata": 1, "jwks": 2}

            idp.set_fault("jwks", "http_error")
            time.sleep(1.2)
            for token in (first_token, second_token):
                rejected = connect(token)
                assert rejected.returncode != 0, "expired JWKS survived fetch failure"
                assert token not in rejected.stderr
            failed_requests = idp.request_counts()
            assert failed_requests["metadata"] == 1
            assert failed_requests["jwks"] > refetched["jwks"]

            idp.set_fault("jwks", None)
            assert connect(first_token).returncode == 0, cluster.logs()
            assert idp.request_counts()["jwks"] > failed_requests["jwks"]
            logs = cluster.logs()
            assert first_token not in logs and second_token not in logs
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


@pytest.mark.parametrize("headers,reusable", [
    # Well-formed but unusual: RFC 9110 section 5.6.1.2 ignores empty elements.
    ([("Cache-Control", "max-age=60,")], True),
    ([("Cache-Control", ", ,max-age=60,,public")], True),
    # Overflow saturates (RFC 9111 section 1.2.2) and is capped locally.
    ([("Cache-Control", "max-age=99999999999999999999999999")], True),
    # Unusable freshness is immediately stale, never a denial (ADR 0002).
    ([("Cache-Control", "max-age=60, max-age=120")], False),
    ([("Cache-Control", "max-age=invalid")], False),
    ([("Cache-Control", "max-age=")], False),
    ([("Expires", "0")], False),
    ([("Expires", "-1")], False),
    ([("Expires", "not a date")], False),
    ([("Cache-Control", "max-age=60"), ("Age", "1,2")], False),
], ids=["trailing-comma", "empty-elements", "overflow", "duplicate-max-age",
        "malformed-max-age", "empty-max-age", "expires-0", "expires-minus-1",
        "expires-garbage", "ambiguous-age"])
def test_unusual_freshness_headers_do_not_deny_authentication(
        integration_environment, headers, reusable):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-freshness-") as directory:
        idp = LocalIdp(pathlib.Path(directory))
        idp.freshness_headers = headers
        # The minimum retention is disabled here so that "immediately stale"
        # stays observable; the default minimum is covered in test_robustness.
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            identity_map=("principal", "appuser"), ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
            extra_config="pg_oauth_validator.cache_min_ttl = '0'\n",
        )
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)
        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN")
            token = idp.sign()
            # Cold cache: the response that was just fetched must serve its
            # own request even though it cannot be reused afterwards.
            first = attempt_oauth(cluster, client, token=token, user="appuser",
                                  issuer=idp.issuer, sslmode="require")
            assert first.returncode == 0, first.stderr + cluster.logs()
            assert idp.request_counts() == {"metadata": 1, "jwks": 1}
            second = attempt_oauth(cluster, client, token=token, user="appuser",
                                   issuer=idp.issuer, sslmode="require")
            assert second.returncode == 0, second.stderr + cluster.logs()
            if reusable:
                assert idp.request_counts() == {"metadata": 1, "jwks": 1}
            else:
                assert idp.request_counts() == {"metadata": 2, "jwks": 2}
            assert token not in cluster.logs()
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


@pytest.mark.slow
@pytest.mark.xdist_group(name="timing")
def test_authentication_timeout_interrupts_provider_fetch(integration_environment):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-interrupt-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=120)
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            identity_map=("principal", "appuser"), ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
            extra_config=(
                "authentication_timeout = '1s'\n"
                "pg_oauth_validator.unknown_kid_refresh_cooldown = '1s'\n"
            ),
        )
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)

        def connect(token):
            return attempt_oauth(
                cluster, client, token=token, user="appuser",
                issuer=idp.issuer, sslmode="require",
            )

        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN")
            token = idp.sign()
            idp.set_delay("metadata", 2.5)
            started = time.monotonic()
            rejected = connect(token)
            assert rejected.returncode != 0
            assert time.monotonic() - started < 2.2, cluster.logs()
            idp.set_delay("metadata", 0)
            assert connect(token).returncode == 0

            idp.rotate("interrupt-jwks-key")
            rotated = idp.sign()
            idp.set_delay("jwks", 2.5)
            started = time.monotonic()
            rejected_jwks = connect(rotated)
            assert rejected_jwks.returncode != 0
            assert time.monotonic() - started < 2.2, cluster.logs()
            idp.set_delay("jwks", 0)
            time.sleep(1.1)  # The aborted unknown-key refresh still starts cooldown.
            assert connect(rotated).returncode == 0
            logs = cluster.logs()
            assert token not in logs and rotated not in logs
            assert token not in rejected.stderr
            assert rotated not in rejected_jwks.stderr
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


@pytest.mark.slow
@pytest.mark.xdist_group(name="timing")
def test_fast_shutdown_interrupts_provider_fetch(integration_environment):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-shutdown-") as directory:
        idp = LocalIdp(pathlib.Path(directory))
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)
        try:
            cluster.start()
            token = idp.sign(subject="postgres")
            idp.set_delay("metadata", 5.5)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                connection = pool.submit(
                    attempt_oauth, cluster, client, token=token,
                    user="postgres", issuer=idp.issuer, sslmode="require",
                )
                deadline = time.monotonic() + 3
                while idp.request_counts()["metadata"] == 0:
                    assert time.monotonic() < deadline, "metadata fetch did not begin"
                    time.sleep(0.01)
                started = time.monotonic()
                stopping = subprocess.Popen(
                    ["runuser", "-u", "postgres", "--",
                     str(cluster.bindir / "pg_ctl"), "-D", str(cluster.data),
                     "-m", "fast", "-w", "stop"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                try:
                    # Measure the fetching backend's exit, not the subsequent
                    # shutdown checkpoint/fsync. Preserve both deadlines: the
                    # authentication attempt must end within 2.5s and pg_ctl
                    # must finish within 4s, before the delayed response.
                    denied = connection.result(timeout=2.5)
                    assert time.monotonic() - started < 2.5, "shutdown waited for the provider response"
                    assert denied.returncode != 0
                finally:
                    try:
                        _stdout, stderr = stopping.communicate(
                            timeout=max(0.001, 4 - (time.monotonic() - started)),
                        )
                    except subprocess.TimeoutExpired:
                        stopping.kill()
                        stopping.communicate()
                        raise
                assert stopping.returncode == 0, stderr
            assert token not in cluster.logs()
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


@pytest.mark.slow
@pytest.mark.xdist_group(name="timing")
def test_local_idp_transport_failures_deny_and_recover(integration_environment):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-idp-transport-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=0)
        identity = "principal"
        # max-age=0 must mean "fetch on every login" here, so that every
        # injected fault is reached; the default minimum retention would
        # serve these responses from the cache.
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            identity_map=(identity, "appuser"), ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
            extra_config="pg_oauth_validator.cache_min_ttl = '0'\n",
        )
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)

        def connect(token):
            return attempt_oauth(
                cluster, client, token=token, user="appuser",
                issuer=idp.issuer, sslmode="require",
            )

        failure_modes = (
            "http_error", "redirect", "malformed_json", "wrong_content_type",
            "oversized", "truncated", "total_timeout",
        )
        results = []
        tokens = []
        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN")
            initial = idp.sign()
            tokens.append(initial)
            assert connect(initial).returncode == 0

            # Stopping the accept loop while retaining the listening socket makes
            # the TLS handshake hit the validator's connection-timeout bound.
            idp.pause_accepting_connections()
            started = time.monotonic()
            connection_timeout = connect(initial)
            elapsed = time.monotonic() - started
            results.append(connection_timeout)
            assert connection_timeout.returncode != 0
            assert elapsed < 4.0, "connection timeout exceeded its configured bound"
            idp.resume_accepting_connections()
            assert connect(initial).returncode == 0

            for resource in ("metadata", "jwks"):
                for index, fault in enumerate(failure_modes):
                    idp.rotate(f"transport-{resource}-{index}")
                    token = idp.sign()
                    tokens.append(token)
                    idp.set_fault(resource, fault)
                    started = time.monotonic()
                    rejected = connect(token)
                    elapsed = time.monotonic() - started
                    results.append(rejected)
                    assert rejected.returncode != 0, f"{resource} {fault} accepted"
                    assert elapsed < 8.0, f"{resource} {fault} was not bounded"
                    # The client's 5s connect timeout can expire together with the
                    # validator's total HTTP timeout, before the backend has
                    # finished the failed refresh. Recovery is only meaningful
                    # once that refresh is over.
                    idp.wait_until_idle()

                    idp.set_fault(resource, None)
                    recovered = connect(token)
                    assert recovered.returncode == 0, (
                        f"{resource} did not recover after {fault}: "
                        f"{recovered.stderr}\n{cluster.logs()}"
                    )

            logs = cluster.logs()
            assert IDP_RESPONSE_SECRET not in logs
            for token in tokens:
                assert token not in logs
            for result in results:
                assert IDP_RESPONSE_SECRET not in result.stdout
                assert IDP_RESPONSE_SECRET not in result.stderr
                for token in tokens:
                    assert token not in result.stdout
                    assert token not in result.stderr
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


@pytest.mark.slow
@pytest.mark.xdist_group(name="timing")
def test_unknown_kid_refresh_is_suppressed_across_backends(
        integration_environment):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-idp-unknown-kid-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=120)
        identity = "principal"
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            identity_map=(identity, "appuser"), ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        valid = idp.sign()
        unknown_tokens = [
            idp.sign(header_key_id=f"attacker-key-{index}")
            for index in range(8)
        ]
        after_cooldown = idp.sign(header_key_id="attacker-key-after-cooldown")
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)

        def connect(token):
            return attempt_oauth(
                cluster, client, token=token, user="appuser",
                issuer=idp.issuer, sslmode="require",
            )

        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN")
            assert connect(valid).returncode == 0
            warmed = idp.request_counts()

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                rejected = list(pool.map(connect, unknown_tokens))
            assert all(result.returncode != 0 for result in rejected)
            after_attack = idp.request_counts()
            assert after_attack["jwks"] == warmed["jwks"] + 1

            assert connect(valid).returncode == 0
            assert idp.request_counts() == after_attack

            time.sleep(30.2)
            assert connect(after_cooldown).returncode != 0
            assert idp.request_counts()["jwks"] == after_attack["jwks"] + 1

            logs = cluster.logs()
            for token in [valid, after_cooldown, *unknown_tokens]:
                assert token not in logs
            for result in rejected:
                for token in unknown_tokens:
                    assert token not in result.stderr
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


@pytest.mark.xdist_group(name="timing")
def test_cold_cache_concurrent_authentications_wait_for_refresh(
        integration_environment):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-idp-") as directory:
        idp = LocalIdp(pathlib.Path(directory))
        idp.set_delay("metadata", 0.5)
        idp.set_delay("jwks", 0.5)
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        token = idp.sign(subject="postgres")
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)

        try:
            cluster.start()
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                attempts = [
                    pool.submit(
                        attempt_oauth, cluster, client, token=token,
                        user="postgres", issuer=idp.issuer, sslmode="require",
                    )
                    for _ in range(8)
                ]
                results = [attempt.result(timeout=8) for attempt in attempts]

            for result in results:
                assert result.returncode == 0, result.stderr + "\n" + cluster.logs()
            assert idp.request_counts() == {"metadata": 1, "jwks": 1}
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


@pytest.mark.xdist_group(name="timing")
def test_zero_refresh_wait_timeout_retains_fail_fast_behavior(
        integration_environment):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-idp-") as directory:
        idp = LocalIdp(pathlib.Path(directory))
        idp.set_delay("metadata", 0.75)
        idp.set_delay("jwks", 0.75)
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
            refresh_wait_timeout="0",
        )
        token = idp.sign(subject="postgres")
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)

        try:
            cluster.start()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                owner = pool.submit(
                    attempt_oauth, cluster, client, token=token,
                    user="postgres", issuer=idp.issuer, sslmode="require",
                )
                deadline = time.monotonic() + 2
                while idp.request_counts()["metadata"] == 0:
                    if time.monotonic() >= deadline:
                        raise AssertionError("refresh owner did not fetch metadata")
                    time.sleep(0.01)

                started = time.monotonic()
                competitor = attempt_oauth(
                    cluster, client, token=token, user="postgres",
                    issuer=idp.issuer, sslmode="require",
                )
                elapsed = time.monotonic() - started
                owner_result = owner.result(timeout=5)

            assert competitor.returncode != 0
            assert elapsed < 0.5, "disabled refresh wait did not fail promptly"
            assert owner_result.returncode == 0, owner_result.stderr
            assert idp.request_counts() == {"metadata": 1, "jwks": 1}
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


@pytest.mark.xdist_group(name="timing")
def test_refresh_wait_timeout_fails_closed_at_deadline(integration_environment):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-idp-") as directory:
        idp = LocalIdp(pathlib.Path(directory))
        idp.set_delay("metadata", 1)
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
            refresh_wait_timeout="100ms",
        )
        token = idp.sign(subject="postgres")
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)

        try:
            cluster.start()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                owner = pool.submit(
                    attempt_oauth, cluster, client, token=token,
                    user="postgres", issuer=idp.issuer, sslmode="require",
                )
                deadline = time.monotonic() + 2
                while idp.request_counts()["metadata"] == 0:
                    if time.monotonic() >= deadline:
                        raise AssertionError("refresh owner did not fetch metadata")
                    time.sleep(0.01)

                started = time.monotonic()
                competitor = attempt_oauth(
                    cluster, client, token=token, user="postgres",
                    issuer=idp.issuer, sslmode="require",
                )
                elapsed = time.monotonic() - started
                owner_result = owner.result(timeout=5)

            assert competitor.returncode != 0
            assert 0.08 <= elapsed < 0.75
            assert owner_result.returncode == 0, owner_result.stderr
            assert idp.request_counts() == {"metadata": 1, "jwks": 1}
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


@pytest.mark.xdist_group(name="timing")
def test_shared_cache_cross_backend_refresh_suppression(integration_environment):
    pg_config, validator_library, _client = integration_environment
    cache_probe = pathlib.Path(os.environ["CACHE_PROBE"]).resolve()
    cluster = TemporaryPostgres(pg_config, validator_library)
    key = "concurrency-" + uuid.uuid4().hex
    payload = "validated-public-resource"

    try:
        cluster.start()
        library = str(cache_probe).replace("'", "''")
        psql(cluster, f"""
            CREATE FUNCTION pg_oauth_test_cache_refresh(text, bigint, integer, text)
            RETURNS integer AS '{library}', 'pg_oauth_test_cache_refresh'
            LANGUAGE C STRICT;
            CREATE FUNCTION pg_oauth_test_cache_begin(text, bigint)
            RETURNS integer AS '{library}', 'pg_oauth_test_cache_begin'
            LANGUAGE C STRICT;
            CREATE FUNCTION pg_oauth_test_cache_lookup(text, bigint)
            RETURNS text AS '{library}', 'pg_oauth_test_cache_lookup'
            LANGUAGE C STRICT;
        """)

        owner_sql = (
            "SELECT pg_oauth_test_cache_refresh("
            f"'{key}', 1000, 3000, '{payload}')"
        )
        owner = subprocess.Popen(
            [str(value) for value in psql_argv(cluster, owner_sql)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        time.sleep(0.5)

        started = time.monotonic()
        cold_lookup = psql(
            cluster,
            f"SELECT pg_oauth_test_cache_lookup('{key}', 1001) IS NULL",
        )
        competitor = psql(
            cluster, f"SELECT pg_oauth_test_cache_begin('{key}', 1001)"
        )
        elapsed = time.monotonic() - started
        owner_stdout, owner_stderr = owner.communicate(timeout=5)

        assert cold_lookup.stdout.strip() == "t"
        assert competitor.stdout.strip() == "1"  # refresh in progress
        assert elapsed < 1.5, "competitor waited on refresh/network work"
        assert owner.returncode == 0, owner_stderr
        assert owner_stdout.strip() == "0"  # refresh owner
        published = psql(
            cluster, f"SELECT pg_oauth_test_cache_lookup('{key}', 1002)"
        )
        assert published.stdout.strip() == payload
    finally:
        cluster.stop()
