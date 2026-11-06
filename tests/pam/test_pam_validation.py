"""Disposable Linux-only end-to-end tests: real tokens through PostgreSQL PAM.

A local HTTPS identity provider issues signed JWTs; PostgreSQL authenticates
them through pg_oauth_pam using the shared validation pipeline.
"""

import os
import pathlib
import shutil
import sys
import tempfile
import time
import uuid

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "integration"))
from integration_support import AUDIENCE, SCOPE, LocalIdp, TemporaryPostgres, command, psql
from test_pam_module import Libpq, require_disposable


def stack(module, policy, account_policy=None):
    account_policy = policy if account_policy is None else account_policy
    return (f"auth [success=ok default=die] {module} {policy}\n"
            f"account [success=ok default=die] {module} {account_policy}\n")


@pytest.fixture(scope="module")
def environment():
    require_disposable()
    pg_config = os.environ["PG_CONFIG"]
    module = pathlib.Path(os.environ["PAM_MODULE"]).resolve()
    with tempfile.TemporaryDirectory(prefix="pg-oauth-pam-idp-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=60)
        service = "pg-oauth-pam-validate-" + uuid.uuid4().hex
        service_file = pathlib.Path("/etc/pam.d") / service
        cluster = TemporaryPostgres(
            pg_config, os.environ["VALIDATOR_LIBRARY"],
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
            hba_lines=("local all all trust\n"
                       f"hostssl postgres appuser,other 127.0.0.1/32 pam pamservice={service}\n"),
        )
        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN; CREATE ROLE other LOGIN;")
            # The module runs inside the unprivileged server, so it must be able
            # to read the CA bundle it uses to verify the provider.
            ca_file = cluster.root / "provider-ca.pem"
            shutil.copyfile(idp.tls_certificate, ca_file)
            ca_file.chmod(0o644)
            policy = (f"issuer={idp.issuer} audience={AUDIENCE} scope={SCOPE} "
                      f"ca_file={ca_file}")
            service_file.write_text(stack(module, policy))
            service_file.chmod(0o644)
            yield (cluster, Libpq(pg_config), idp, service_file, module, policy)
        finally:
            service_file.unlink(missing_ok=True)
            cluster.stop()
            idp.close()


def connect(environment, token, user="appuser"):
    cluster, client, *_ = environment
    return client.connect(cluster, token.encode() if token is not None else None, user=user)


def test_valid_token_authenticates_the_matching_role(environment):
    cluster, _, idp, *_ = environment
    token = idp.sign(subject="appuser")
    accepted, error = connect(environment, token)
    assert accepted, error + cluster.logs()
    assert token not in error + cluster.logs()
    # A token minted for one role never authenticates another (exact equality).
    accepted, _ = connect(environment, token, user="other")
    assert not accepted


def test_token_for_another_principal_is_denied(environment):
    _, _, idp, *_ = environment
    accepted, _ = connect(environment, idp.sign(subject="other"))
    assert not accepted


@pytest.mark.parametrize("claims", [
    {"audience": "https://other.example/"},
    {"scope": "something-else"},
    {"expiry": 1},
    {"token_type": "JWT"},
    {"token_type": None},
    {"extra_claims": {"iss": "https://evil.example/"}},
], ids=["audience", "scope", "expired", "wrong-typ", "missing-typ", "issuer"])
def test_invalid_tokens_are_denied(environment, claims):
    cluster, _, idp, *_ = environment
    token = idp.sign(subject="appuser", **claims)
    accepted, error = connect(environment, token)
    assert not accepted
    assert token not in error + cluster.logs()


def test_signature_key_and_algorithm_attacks_are_denied(environment):
    _, _, idp, *_ = environment
    good = idp.sign(subject="appuser")
    head, body, signature = good.split(".")
    tampered = ".".join([head, body, signature[:-4] + ("AAAA" if signature[-4:] != "AAAA" else "BBBB")])
    assert not connect(environment, tampered)[0]
    assert not connect(environment, idp.sign(subject="appuser", header_key_id="unknown"))[0]
    assert not connect(environment, idp.sign(subject="appuser", header_algorithm="HS256"))[0]
    assert not connect(environment, idp.sign(subject="appuser", header_algorithm="none"))[0]
    assert not connect(environment, head + "." + body + ".")[0]


def test_malformed_and_missing_credentials_are_denied(environment):
    for value in (None, "", "not-a-jwt", "a.b.c", "Bearer " + "x" * 40):
        assert not connect(environment, value)[0]


def test_provider_outage_denies_without_poisoning_recovery(environment):
    _, _, idp, *_ = environment
    token = idp.sign(subject="appuser")
    idp.outage = True
    try:
        assert not connect(environment, token)[0]
    finally:
        idp.outage = False
    assert connect(environment, token)[0]


def test_account_stage_requires_identical_policy_on_both_lines(environment):
    _, _, idp, service_file, module, policy = environment[:6]
    original = service_file.read_text()
    token = idp.sign(subject="appuser")
    try:
        service_file.write_text(stack(module, policy, policy + " clock_skew_ms=1000"))
        accepted, _ = connect(environment, token)
        assert not accepted
    finally:
        service_file.write_text(original)
    assert connect(environment, token)[0]


def test_expired_between_stages_is_denied(environment):
    # A token that expires right after validation must not pass the account stage
    # once the clock passes expiry plus skew; exp one second ahead with zero skew.
    _, _, idp, service_file, module, policy = environment[:6]
    original = service_file.read_text()
    strict = policy + " clock_skew_ms=0"
    try:
        service_file.write_text(stack(module, strict))
        token = idp.sign(subject="appuser", expiry=int(time.time()) + 1)
        time.sleep(2)
        assert not connect(environment, token)[0]
    finally:
        service_file.write_text(original)


def test_policy_changes_apply_to_later_connections_only(environment):
    _, _, idp, service_file, module, policy = environment[:6]
    original = service_file.read_text()
    token = idp.sign(subject="appuser")
    assert connect(environment, token)[0]
    try:
        # Tightening the audience takes effect on the next authentication.
        service_file.write_text(stack(module, policy.replace(AUDIENCE, "https://changed.example/")))
        assert not connect(environment, token)[0]
    finally:
        service_file.write_text(original)
    assert connect(environment, token)[0]
