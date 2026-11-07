import concurrent.futures
import contextlib
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
    reload_setting,
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


@contextlib.contextmanager
def provider_cluster(integration_environment, freshness_headers=None,
                     extra_config="", delays=None):
    """A real server with one local provider; yields (idp, cluster, connect)."""
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-retention-") as directory:
        idp = LocalIdp(pathlib.Path(directory))
        idp.freshness_headers = freshness_headers
        for resource, seconds in (delays or {}).items():
            idp.set_delay(resource, seconds)
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            identity_map=("principal", "appuser"), ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
            extra_config=extra_config,
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
            yield idp, cluster, connect
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


@pytest.mark.parametrize("directive", ["no-store", "no-cache", "max-age=0"])
@pytest.mark.xdist_group(name="timing")
def test_provider_forbidding_caching_is_retained_and_shared_by_concurrent_logins(
        integration_environment, directive):
    """Before the minimum retention, every login refetched, and overlapping
    cold logins failed: the owner published nothing for the waiters to use."""
    with provider_cluster(
            integration_environment,
            freshness_headers=[("Cache-Control", directive)],
            delays={"metadata": 0.5, "jwks": 0.5}) as (idp, cluster, connect):
        token = idp.sign()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(connect, [token] * 8))
        for result in results:
            assert result.returncode == 0, result.stderr + cluster.logs()
        assert idp.request_counts() == {"metadata": 1, "jwks": 1}
        # Still inside the 30 s default minimum: served from the cache.
        assert connect(token).returncode == 0
        assert idp.request_counts() == {"metadata": 1, "jwks": 1}
        assert token not in cluster.logs()


@pytest.mark.xdist_group(name="timing")
def test_minimum_retention_expires_and_no_cache_must_revalidate(
        integration_environment):
    with provider_cluster(
            integration_environment,
            freshness_headers=[("Cache-Control", "no-cache")],
            extra_config="pg_oauth_validator.cache_min_ttl = '1s'\n"
            ) as (idp, cluster, connect):
        token = idp.sign()
        assert connect(token).returncode == 0
        assert connect(token).returncode == 0
        assert idp.request_counts() == {"metadata": 1, "jwks": 1}
        time.sleep(1.3)
        assert connect(token).returncode == 0
        assert idp.request_counts() == {"metadata": 2, "jwks": 2}


@pytest.mark.parametrize("directive", ["no-store", "no-cache"])
@pytest.mark.xdist_group(name="timing")
def test_zero_minimum_retention_restores_a_request_per_login(
        integration_environment, directive):
    with provider_cluster(
            integration_environment,
            freshness_headers=[("Cache-Control", directive)],
            extra_config="pg_oauth_validator.cache_min_ttl = '0'\n"
            ) as (idp, cluster, connect):
        token = idp.sign()
        assert connect(token).returncode == 0
        assert connect(token).returncode == 0
        assert idp.request_counts() == {"metadata": 2, "jwks": 2}


@pytest.mark.xdist_group(name="timing")
def test_positive_provider_lifetime_is_never_raised_to_the_minimum(
        integration_environment):
    with provider_cluster(
            integration_environment,
            freshness_headers=[("Cache-Control", "max-age=1")],
            extra_config="pg_oauth_validator.cache_min_ttl = '30s'\n"
            ) as (idp, cluster, connect):
        token = idp.sign()
        assert connect(token).returncode == 0
        time.sleep(1.3)
        assert connect(token).returncode == 0
        assert idp.request_counts() == {"metadata": 2, "jwks": 2}


@pytest.mark.xdist_group(name="timing")
def test_changing_a_cache_setting_flushes_cached_keys(integration_environment):
    """The documented key-compromise procedure: a reload that changes any
    setting in the cache key makes existing entries ineligible at once."""
    with provider_cluster(integration_environment) as (idp, cluster, connect):
        token = idp.sign()
        assert connect(token).returncode == 0
        assert connect(token).returncode == 0
        assert idp.request_counts() == {"metadata": 1, "jwks": 1}
        reload_setting(cluster, "pg_oauth_validator.cache_min_ttl", "31s")
        assert connect(token).returncode == 0
        assert idp.request_counts() == {"metadata": 2, "jwks": 2}
        assert connect(token).returncode == 0
        assert idp.request_counts() == {"metadata": 2, "jwks": 2}


@pytest.mark.xdist_group(name="timing")
def test_unrelated_refresh_completions_do_not_fail_a_waiting_login(
        integration_environment):
    """Every completed refresh wakes every waiter. A login waiting for the cold
    refresh of its own entry must keep waiting, not fail on the first wakeup
    caused by some other entry."""
    with provider_cluster(
            integration_environment,
            delays={"metadata": 1.0, "jwks": 1.0}) as (idp, cluster, connect):
        install_cache_probe(cluster)
        token = idp.sign()
        prefix = "robust-wakeup-" + uuid.uuid4().hex
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            owner = pool.submit(connect, token)
            time.sleep(0.4)
            waiter = pool.submit(connect, token)
            time.sleep(0.2)
            # Each probe refresh begins, holds briefly and completes, which
            # broadcasts to every waiter in the shared cache.
            for index in range(6):
                psql(cluster, "SELECT pg_oauth_test_cache_refresh("
                     f"'{prefix}-{index}', 1000, 80, 'public-payload')")
            owner_result = owner.result(timeout=15)
            waiter_result = waiter.result(timeout=15)
        assert owner_result.returncode == 0, owner_result.stderr + cluster.logs()
        assert waiter_result.returncode == 0, waiter_result.stderr + cluster.logs()
        assert idp.request_counts() == {"metadata": 1, "jwks": 1}


@pytest.mark.parametrize("headers", [
    [("Cache-Control", "max-age=60, max-age=120")],
    [("Cache-Control", "max-age=invalid")],
    [("Cache-Control", "max-age=")],
    [("Expires", "0")],
    [("Expires", "-1")],
    [("Expires", "not a date")],
    [("Cache-Control", "max-age=60"), ("Age", "1,2")],
], ids=["duplicate-max-age", "malformed-max-age", "empty-max-age", "expires-0",
        "expires-minus-1", "expires-garbage", "ambiguous-age"])
@pytest.mark.xdist_group(name="timing")
def test_unusable_freshness_headers_are_retained_for_the_minimum(
        integration_environment, headers):
    """Unusable headers are stale (ADR 0002), and stale responses fall under the
    minimum retention, so the second login is served from the cache."""
    with provider_cluster(
            integration_environment, freshness_headers=headers) as (
                idp, cluster, connect):
        token = idp.sign()
        assert connect(token).returncode == 0
        assert connect(token).returncode == 0
        assert idp.request_counts() == {"metadata": 1, "jwks": 1}


def test_unusable_jwks_entries_and_status_and_type_spelling(integration_environment):
    """RFC 7517 section 5: unusable key-set members are ignored, so one of them
    cannot take an issuer's keys offline. RFC 8414 / RFC 7517: only a 200
    response carries the document. RFC 7515 section 4.1.9: the token type
    compares case-insensitively."""
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-strictness-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=0)
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            identity_map=("principal", "appuser"), ca_file=idp.tls_certificate,
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

        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN")

            # Statuses other than 200 are not trusted, for either document.
            for resource in ("metadata", "jwks"):
                for code in (203, 204, 206):
                    idp.set_fault(resource, f"status_{code}")
                    assert connect(idp.sign()).returncode != 0, (resource, code)
                idp.set_fault(resource, None)
            assert connect(idp.sign()).returncode == 0, cluster.logs()

            # Unusable members next to the real key do not deny the real key.
            idp.extra_jwks_entries = [
                1, "x", None, [], {}, {"kid": 5}, {"kid": "bad\nid"},
                {"kty": "oct", "kid": "sym", "k": "AA"},
            ]
            accepted = connect(idp.sign())
            assert accepted.returncode == 0, accepted.stderr + cluster.logs()
            # ...and never stand in for a key: a token naming one is denied.
            assert connect(idp.sign(header_key_id="sym")).returncode != 0
            idp.extra_jwks_entries = []

            assert connect(idp.sign(token_type="AT+JWT")).returncode == 0, cluster.logs()
            assert connect(idp.sign(token_type="at+jwt ")).returncode != 0
        finally:
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca
            cluster.stop()
            idp.close()


def test_an_owner_aborted_mid_fetch_does_not_block_later_logins(integration_environment):
    """The backend that is refreshing a cache entry can be ended by PostgreSQL
    itself (authentication_timeout) while the provider is slow. The entry must
    not stay marked as refreshing: the next login has to fetch normally."""
    pg_config, validator_library, client = integration_environment
    with tempfile.TemporaryDirectory(prefix="pg-oauth-owner-abort-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=120)
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            identity_map=("principal", "appuser"), ca_file=idp.tls_certificate,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
            extra_config="authentication_timeout = 2s\n",
        )
        previous_ca = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)

        def connect():
            return attempt_oauth(
                cluster, client, token=idp.sign(), user="appuser",
                issuer=idp.issuer, sslmode="require",
            )

        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN")
            idp.set_delay("metadata", 6)
            aborted = connect()
            assert aborted.returncode != 0
            assert "canceling authentication due to timeout" in cluster.logs()
            idp.set_delay("metadata", 0)
            idp.wait_until_idle()
            recovered = connect()
            assert recovered.returncode == 0, recovered.stderr + "\n" + cluster.logs()[-3000:]
        finally:
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca
