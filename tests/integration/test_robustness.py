import concurrent.futures
import os
import pathlib
import subprocess
import tempfile
import time
import uuid

import pytest

from integration_support import (
    LocalIdp,
    TemporaryPostgres,
    attempt_oauth,
    b64,
    psql,
    psql_argv,
)


@pytest.fixture
def integration_environment():
    return (
        os.environ["PG_CONFIG"],
        os.environ["VALIDATOR_LIBRARY"],
        pathlib.Path(os.environ["OAUTH_TEST_CLIENT"]).resolve(),
    )


def install_cache_probe(cluster):
    library = str(pathlib.Path(os.environ["CACHE_PROBE"]).resolve()).replace(
        "'", "''"
    )
    psql(cluster, f"""
        CREATE FUNCTION pg_oauth_test_cache_refresh(text, bigint, integer, text)
        RETURNS integer AS '{library}', 'pg_oauth_test_cache_refresh'
        LANGUAGE C STRICT;
        CREATE FUNCTION pg_oauth_test_cache_begin(text, bigint)
        RETURNS integer AS '{library}', 'pg_oauth_test_cache_begin'
        LANGUAGE C STRICT;
    """)


@pytest.mark.xdist_group(name="timing")
def test_shared_cache_capacity_fails_closed_with_bounded_contention(
        integration_environment):
    pg_config, validator_library, _client = integration_environment
    cluster = TemporaryPostgres(pg_config, validator_library)
    owners = []
    capacity = 32
    prefix = "robust-capacity-" + uuid.uuid4().hex

    try:
        cluster.start()
        setting = psql(cluster, """
            LOAD 'pg_oauth_validator';
            SELECT setting, min_val, max_val, context
            FROM pg_settings
            WHERE name = 'pg_oauth_validator.cache_max_entries'
        """).stdout.strip()
        assert setting.endswith("32|8|256|sighup")
        install_cache_probe(cluster)

        # Every owner reserves a distinct slot, then performs simulated
        # network work without holding the shared-cache lock.
        for index in range(capacity):
            sql = (
                "SELECT pg_oauth_test_cache_refresh("
                f"'{prefix}-{index}', 1000, 3000, 'public-payload')"
            )
            owners.append(subprocess.Popen(
                [str(value) for value in psql_argv(cluster, sql)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ))
        time.sleep(0.75)

        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            overflow = list(pool.map(
                lambda index: psql(
                    cluster,
                    "SELECT pg_oauth_test_cache_begin("
                    f"'{prefix}-overflow-{index}', 1001)",
                ).stdout.strip(),
                range(16),
            ))
        elapsed = time.monotonic() - started

        # 3 is PG_OAUTH_CACHE_REFRESH_CAPACITY. No excess request may become
        # a refresh owner while all configured slots are occupied.
        assert overflow == ["3"] * 16
        assert elapsed < 5.0, "cache exhaustion handling exceeded its CI bound"

        for owner in owners:
            stdout, stderr = owner.communicate(timeout=8)
            assert owner.returncode == 0, stderr
            assert stdout.strip() == "0"
    finally:
        for owner in owners:
            if owner.poll() is None:
                owner.terminate()
                owner.communicate(timeout=5)
        cluster.stop()


@pytest.mark.xdist_group(name="timing")
def test_valid_cached_authentication_remains_responsive_under_hostile_load(
        integration_environment):
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-robustness-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=120)
        identity = "principal"
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            identity_map=(identity, "appuser"), ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        valid = idp.sign()
        hostile = [
            idp.sign(header_key_id=f"robust-unknown-{index}")
            for index in range(24)
        ]
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

            inputs = hostile + [valid] * 8
            started = time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                results = list(pool.map(connect, inputs))
            elapsed = time.monotonic() - started

            assert all(result.returncode != 0 for result in results[:24])
            assert all(result.returncode == 0 for result in results[24:])
            assert idp.request_counts()["jwks"] == warmed["jwks"] + 1
            assert elapsed < 12.0, "hostile authentication smoke exceeded CI budget"

            logs = cluster.logs()
            for token in [valid, *hostile]:
                assert token not in logs
            for result in results:
                assert valid not in result.stdout
                assert valid not in result.stderr
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


@pytest.mark.xdist_group(name="timing")
def test_unknown_key_flood_on_a_cold_cache_is_bounded(integration_environment):
    """The existing hostile-load test warms the cache first. With an empty cache
    the fetched key set used to be discarded whenever the token's key was not in
    it, so the unknown-key cooldown never applied and every hostile token cost
    two provider requests."""
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-cold-flood-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=120)
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            identity_map=("principal", "appuser"), ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
        )
        valid = idp.sign()
        hostile = [
            idp.sign(header_key_id=f"cold-unknown-{index}") for index in range(12)
        ]
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
            assert idp.request_counts() == {"metadata": 0, "jwks": 0}

            for token in hostile:
                assert connect(token).returncode != 0
            flooded = idp.request_counts()
            # One fetch publishes the key set; one more refresh starts the
            # unknown-key cooldown; the other ten are suppressed.
            assert flooded["metadata"] == 1, flooded
            assert flooded["jwks"] <= 2, flooded

            # A legitimate login is served from the key set the hostile tokens
            # caused to be cached.
            accepted = connect(valid)
            assert accepted.returncode == 0, accepted.stderr + cluster.logs()
            assert idp.request_counts() == flooded

            logs = cluster.logs()
            for token in [valid, *hostile]:
                assert token not in logs
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca
