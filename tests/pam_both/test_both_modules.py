"""Native OAuth and PAM installed together in one PostgreSQL (ADR 0008, 0009).

HBA routes each role to exactly one method. The two modules must not depend on
or disturb each other: configuration, files and failures stay independent.
"""

import contextlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import uuid

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "integration"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "pam"))
from integration_support import (AUDIENCE, SCOPE, LocalIdp, TemporaryPostgres,
                                 attempt_oauth, psql, reload_setting, wait_setting)
from test_pam_module import Libpq, require_disposable


@contextlib.contextmanager
def both_environment(extra_config="", cache_max_age=60):
    """One cluster with both modules; `extra_config` adds postgresql.conf lines."""
    require_disposable()
    pg_config = os.environ["PG_CONFIG"]
    validator_library = pathlib.Path(os.environ["VALIDATOR_LIBRARY"]).resolve()
    client = pathlib.Path(os.environ["OAUTH_TEST_CLIENT"]).resolve()
    module = pathlib.Path(os.environ["PAM_MODULE"]).resolve()
    previous_ca = os.environ.get("SSL_CERT_FILE")
    with tempfile.TemporaryDirectory(prefix="pg-oauth-both-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=cache_max_age)
        os.environ["SSL_CERT_FILE"] = str(idp.tls_certificate)
        service = "pg-oauth-both-" + uuid.uuid4().hex
        service_file = pathlib.Path("/etc/pam.d") / service
        cluster = TemporaryPostgres(
            pg_config, validator_library, issuer=idp.issuer,
            ca_file=idp.tls_certificate, extra_config=extra_config,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
            hba_lines=(
                "local all all trust\n"
                f'hostssl postgres oauthuser 127.0.0.1/32 oauth issuer={idp.issuer} '
                f'scope="{SCOPE}" validator=pg_oauth_validator\n'
                f"hostssl postgres pamuser 127.0.0.1/32 pam pamservice={service}\n"),
        )
        try:
            cluster.start()
            psql(cluster, "CREATE ROLE oauthuser LOGIN; CREATE ROLE pamuser LOGIN;")
            ca_file = cluster.root / "provider-ca.pem"
            shutil.copyfile(idp.tls_certificate, ca_file)
            ca_file.chmod(0o644)
            policy = (f"issuer={idp.issuer} audience={AUDIENCE} scope={SCOPE} "
                      f"ca_file={ca_file}")
            service_file.write_text(f"auth [success=ok default=die] {module} {policy}\n"
                                    f"account [success=ok default=die] {module} {policy}\n")
            service_file.chmod(0o644)
            yield cluster, client, Libpq(pg_config), idp, service_file, module, validator_library
        finally:
            service_file.unlink(missing_ok=True)
            cluster.stop()
            idp.close()
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca


@pytest.fixture(scope="module")
def environment():
    with both_environment() as shared:
        yield shared


def oauth_login(environment, idp_token, user="oauthuser"):
    cluster, client, _, idp, *_ = environment
    result = attempt_oauth(cluster, client, token=idp_token, user=user,
                           issuer=idp.issuer, sslmode="require")
    return result.returncode == 0


def pam_login(environment, token, user="pamuser"):
    cluster, _, libpq, *_ = environment
    return libpq.connect(cluster, token.encode(), user=user)[0]


def test_each_rule_uses_exactly_one_method(environment):
    _, _, _, idp, *_ = environment
    assert oauth_login(environment, idp.sign(subject="oauthuser"))
    assert pam_login(environment, idp.sign(subject="pamuser"))
    # A role routed to one method cannot sign in through the other.
    assert not pam_login(environment, idp.sign(subject="oauthuser"), user="oauthuser")
    assert not oauth_login(environment, idp.sign(subject="pamuser"), user="pamuser")


def test_caches_are_separate(environment):
    cluster, _, _, idp, *_ = environment
    token_o = idp.sign(subject="oauthuser")
    token_p = idp.sign(subject="pamuser")
    assert oauth_login(environment, token_o)
    assert pam_login(environment, token_p)
    # Each module warmed its own cache: neither served the other's entries.
    assert idp.request_counts()["metadata"] >= 2
    if cluster.major >= 19:
        names = psql(cluster, "SELECT name FROM pg_dsm_registry_allocations").stdout
        assert "pg_oauth_pam.cache.v1" in names
        assert "pg_oauth_validator.cache.v3" in names


def test_breaking_pam_leaves_oauth_working(environment):
    _, _, _, idp, service_file, *_ = environment
    original = service_file.read_text()
    service_file.write_text("auth [success=ok default=die] pg_oauth_pam.so bogus=1\n"
                            "account [success=ok default=die] pg_oauth_pam.so bogus=1\n")
    try:
        assert not pam_login(environment, idp.sign(subject="pamuser"))
        assert oauth_login(environment, idp.sign(subject="oauthuser"))
    finally:
        service_file.write_text(original)
    assert pam_login(environment, idp.sign(subject="pamuser"))


def test_breaking_oauth_leaves_pam_working(environment):
    cluster, _, _, idp, *_ = environment
    reload_setting(cluster, "pg_oauth_validator.audiences", "https://wrong.example/")
    wait_setting(cluster, "pg_oauth_validator.audiences", "https://wrong.example/")
    try:
        assert not oauth_login(environment, idp.sign(subject="oauthuser"))
        assert pam_login(environment, idp.sign(subject="pamuser"))
    finally:
        reload_setting(cluster, "pg_oauth_validator.audiences", AUDIENCE)
        wait_setting(cluster, "pg_oauth_validator.audiences", AUDIENCE)
    assert oauth_login(environment, idp.sign(subject="oauthuser"))


def test_removing_either_module_leaves_the_other_working(environment):
    _, _, _, idp, service_file, module, validator_library = environment
    hidden = module.with_name(module.name + ".hidden")
    module.rename(hidden)
    try:
        assert not pam_login(environment, idp.sign(subject="pamuser"))
        assert oauth_login(environment, idp.sign(subject="oauthuser"))
    finally:
        hidden.rename(module)
    hidden = validator_library.with_name(validator_library.name + ".hidden")
    validator_library.rename(hidden)
    try:
        assert not oauth_login(environment, idp.sign(subject="oauthuser"))
        assert pam_login(environment, idp.sign(subject="pamuser"))
    finally:
        hidden.rename(validator_library)
    assert oauth_login(environment, idp.sign(subject="oauthuser"))
    assert pam_login(environment, idp.sign(subject="pamuser"))


@pytest.mark.parametrize("filled", ["pam", "oauth"])
def test_a_full_cache_in_one_module_does_not_affect_the_other(filled):
    """ADR 0009: the two modules share no segment, lock or capacity.

    Both caches are set to the minimum of eight entries. One module's cache is
    filled until it denies a new policy, which proves it is really full. The
    other module must still serve its warm entry without a provider request and
    must still be able to cache new policies."""
    capacity = "pg_oauth_validator.cache_max_entries = 8\npg_oauth_pam.cache_max_entries = 8\n"
    with both_environment(capacity, cache_max_age=3600) as environment:
        cluster, _, _, idp, service_file, *_ = environment
        original = service_file.read_text()
        # A policy generation caches metadata and key set: two of the eight entries.
        generations = 4

        def pam_with(variant):
            """Log in under a PAM policy that differs from the others by one argument."""
            if variant:
                service_file.write_text("".join(
                    f"{line} clock_skew_ms={60000 + variant}\n"
                    for line in original.splitlines()))
            else:
                service_file.write_text(original)
            return pam_login(environment, idp.sign(subject="pamuser"))

        def oauth_generation(number):
            """Log in after changing a setting that is part of the OAuth cache key."""
            reload_setting(cluster, "pg_oauth_validator.cache_min_ttl", f"{number}s")
            return oauth_login(environment, idp.sign(subject="oauthuser"))

        assert pam_with(0) and oauth_login(environment, idp.sign(subject="oauthuser"))

        if filled == "pam":
            for variant in range(1, generations):
                assert pam_with(variant), f"PAM policy {variant} was denied before the cache was full"
            assert not pam_with(generations), "the PAM cache never filled"
            before = idp.request_counts()
            assert pam_with(0), "a warm PAM entry was lost"
            assert oauth_login(environment, idp.sign(subject="oauthuser")), "the warm OAuth entry was lost"
            assert idp.request_counts() == before, "a warm entry needed a provider request"
            for number in range(1, generations):
                assert oauth_generation(number), f"OAuth could not cache policy {number}"
        else:
            for number in range(1, generations):
                assert oauth_generation(number), f"OAuth policy {number} was denied before the cache was full"
            assert not oauth_generation(generations), "the OAuth cache never filled"
            before = idp.request_counts()
            assert pam_with(0), "a warm PAM entry was lost"
            assert idp.request_counts() == before, "a warm entry needed a provider request"
            for variant in range(1, generations):
                assert pam_with(variant), f"PAM could not cache policy {variant}"
