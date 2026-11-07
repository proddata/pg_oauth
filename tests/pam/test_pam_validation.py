"""Disposable Linux-only end-to-end tests: real tokens through PostgreSQL PAM.

A local HTTPS identity provider issues signed JWTs; PostgreSQL authenticates
them through pg_oauth_pam using the shared validation pipeline.
"""

import concurrent.futures
import contextlib
import os
import pathlib
import shutil
import socket
import sys
import tempfile
import time
import uuid

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "integration"))
from integration_support import AUDIENCE, SCOPE, LocalIdp, TemporaryPostgres, command, psql
from test_pam_module import Libpq, preload_config, require_disposable, server_major


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
            pg_config, None,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
            extra_config=preload_config(pg_config, module),
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


_variant = iter(range(1000, 100000))


@pytest.fixture
def cold_policy(environment):
    """Install a policy no earlier test used, so its cache entries start cold.

    The full policy is part of the cache key, so a unique clock skew isolates
    one test's cache entries from every other test's.
    """
    _, _, _, service_file, module, policy = environment[:6]
    original = service_file.read_text()
    service_file.write_text(stack(module, f"{policy} clock_skew_ms={next(_variant)}"))
    try:
        yield
    finally:
        service_file.write_text(original)


def test_cache_is_shared_across_backends(environment, cold_policy):
    _, _, idp, *_ = environment
    token = idp.sign(subject="appuser")
    before = idp.request_counts()
    assert connect(environment, token)[0]
    first = idp.request_counts()
    assert first["metadata"] == before["metadata"] + 1
    assert first["jwks"] == before["jwks"] + 1
    # Each login is a new backend process; the cache must still serve them.
    for _ in range(3):
        assert connect(environment, token)[0]
    assert idp.request_counts() == first


def test_cold_cache_outage_denies_and_recovers(environment, cold_policy):
    _, _, idp, *_ = environment
    token = idp.sign(subject="appuser")
    idp.outage = True
    try:
        assert not connect(environment, token)[0]
    finally:
        idp.outage = False
    assert connect(environment, token)[0]


def test_fresh_cache_survives_a_provider_outage(environment, cold_policy):
    _, _, idp, *_ = environment
    token = idp.sign(subject="appuser")
    assert connect(environment, token)[0]
    idp.outage = True
    try:
        counts = idp.request_counts()
        assert connect(environment, token)[0]
        assert idp.request_counts() == counts
    finally:
        idp.outage = False


def test_unknown_key_refresh_is_suppressed_across_backends(environment, cold_policy):
    _, _, idp, *_ = environment
    assert connect(environment, idp.sign(subject="appuser"))[0]
    baseline = idp.request_counts()["jwks"]
    for _ in range(5):
        assert not connect(environment, idp.sign(subject="appuser", header_key_id="nope"))[0]
    # At most one cooldown-limited refresh for attacker-chosen key ids.
    assert idp.request_counts()["jwks"] <= baseline + 1


def test_unknown_key_flood_on_a_cold_cache_is_bounded(environment, cold_policy):
    """With an empty cache every attacker-chosen key id used to cost two provider
    requests, because the fetched key set was discarded when it lacked the
    token's key. The key set is now published, so the cooldown applies."""
    _, _, idp, *_ = environment
    before = idp.request_counts()
    for index in range(12):
        accepted, _ = connect(
            environment, idp.sign(subject="appuser", header_key_id=f"cold-unknown-{index}"))
        assert not accepted
    flooded = idp.request_counts()
    assert flooded["metadata"] - before["metadata"] == 1, (before, flooded)
    assert flooded["jwks"] - before["jwks"] <= 2, (before, flooded)
    # A legitimate login is served from the key set the flood caused to be cached.
    accepted, error = connect(environment, idp.sign(subject="appuser"))
    assert accepted, error
    assert idp.request_counts() == flooded


def test_concurrent_cold_logins_share_one_refresh(environment, cold_policy):
    _, _, idp, *_ = environment
    token = idp.sign(subject="appuser")
    idp.set_delay("metadata", 0.5)
    idp.set_delay("jwks", 0.5)
    before = idp.request_counts()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: connect(environment, token), range(6)))
    finally:
        idp.set_delay("metadata", 0)
        idp.set_delay("jwks", 0)
    assert all(accepted for accepted, _ in results), results
    after = idp.request_counts()
    # One backend refreshes; the others wait for it instead of stampeding.
    assert after["metadata"] - before["metadata"] == 1
    assert after["jwks"] - before["jwks"] == 1


def test_cache_uses_its_own_namespace(environment, cold_policy):
    cluster, _, idp, *_ = environment
    if cluster.major < 19:
        pytest.skip("pg_dsm_registry_allocations exists from PostgreSQL 19")
    assert connect(environment, idp.sign(subject="appuser"))[0]
    names = psql(cluster, "SELECT name FROM pg_dsm_registry_allocations").stdout
    assert "pg_oauth_pam.cache.v1" in names
    # The OAuth validator was never used, so its segment must not exist.
    assert "pg_oauth_validator.cache" not in names


def test_oversized_cache_key_denies_instead_of_skipping_the_cache(environment):
    _, _, idp, service_file, module, policy = environment[:6]
    original = service_file.read_text()
    # A parser-valid policy whose canonical cache key exceeds the 4096-byte bound.
    long_audience = AUDIENCE + "," + "a" * 4000
    token = idp.sign(subject="appuser")
    try:
        service_file.write_text(stack(module, policy.replace(AUDIENCE, long_audience)))
        before = idp.request_counts()
        assert not connect(environment, token)[0]
        assert idp.request_counts() == before, "validated without the cache"
    finally:
        service_file.write_text(original)


def test_policy_change_never_reuses_other_policy_cache(environment, cold_policy):
    _, _, idp, service_file, module, policy = environment[:6]
    token = idp.sign(subject="appuser")
    assert connect(environment, token)[0]
    warmed = idp.request_counts()
    service_file.write_text(stack(module, f"{policy} clock_skew_ms={next(_variant)}"))
    assert connect(environment, token)[0]
    # A different policy has a different key: it must fetch again, not share.
    assert idp.request_counts()["metadata"] == warmed["metadata"] + 1


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


def test_missing_preload_denies_before_postgresql_17():
    """Without shared_preload_libraries the module has no storage and must deny."""
    require_disposable()
    pg_config = os.environ["PG_CONFIG"]
    if server_major(pg_config) >= 17:
        pytest.skip("PostgreSQL 17 and later attach shared memory without a preload")
    module = pathlib.Path(os.environ["PAM_MODULE"]).resolve()
    with tempfile.TemporaryDirectory(prefix="pg-oauth-pam-nopreload-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=60)
        service = "pg-oauth-pam-nopreload-" + uuid.uuid4().hex
        service_file = pathlib.Path("/etc/pam.d") / service
        cluster = TemporaryPostgres(
            pg_config, None,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
            hba_lines=("local all all trust\n"
                       f"hostssl postgres appuser 127.0.0.1/32 pam pamservice={service}\n"),
        )
        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN")
            ca_file = cluster.root / "provider-ca.pem"
            shutil.copyfile(idp.tls_certificate, ca_file)
            ca_file.chmod(0o644)
            policy = (f"issuer={idp.issuer} audience={AUDIENCE} scope={SCOPE} "
                      f"ca_file={ca_file}")
            service_file.write_text(stack(module, policy))
            service_file.chmod(0o644)
            accepted, _ = Libpq(pg_config).connect(cluster, idp.sign(subject="appuser").encode())
            assert not accepted
            assert idp.request_counts() == {"metadata": 0, "jwks": 0}, "validated without storage"
        finally:
            service_file.unlink(missing_ok=True)
            cluster.stop()
            idp.close()


def test_bracket_quoted_arguments_reach_the_module_intact(environment):
    """Linux-PAM splits arguments on whitespace; a value with spaces needs the
    whole argument in brackets, [name=value with spaces]."""
    _, _, idp, service_file, module, policy = environment[:6]
    original = service_file.read_text()
    two_scopes = f"{SCOPE} extra:scope"
    quoted = policy.replace(f"scope={SCOPE}", f"[scope={two_scopes}]")
    try:
        service_file.write_text(stack(module, quoted))
        # Both scopes are required: a token with only one must be denied, which
        # also proves the value was not truncated at the space.
        assert connect(environment, idp.sign(subject="appuser", scope=two_scopes))[0]
        assert not connect(environment, idp.sign(subject="appuser", scope=SCOPE))[0]
        # The unbracketed spelling splits into two arguments and fails closed.
        service_file.write_text(stack(module, policy.replace(f"scope={SCOPE}", f"scope=[{two_scopes}]")))
        assert not connect(environment, idp.sign(subject="appuser", scope=two_scopes))[0]
    finally:
        service_file.write_text(original)


def test_continuation_lines_under_the_libpam_line_limit_work(environment):
    _, _, idp, service_file, module, policy = environment[:6]
    original = service_file.read_text()
    filler = ",".join(f"https://f{index}.example/{'a' * 40}" for index in range(6))
    long_policy = policy.replace(f"audience={AUDIENCE}", f"audience={AUDIENCE},{filler}")
    lines = " \\\n    ".join(long_policy.split())
    assert len(f"{module} {long_policy}") < 900
    try:
        service_file.write_text(f"auth [success=ok default=die] {module} {lines}\n"
                                f"account [success=ok default=die] {module} {long_policy}\n")
        assert connect(environment, idp.sign(subject="appuser"))[0]
        # A truncated argument would reject a token minted for the last entry.
        assert connect(environment, idp.sign(subject="appuser", audience=filler.split(",")[-1]))[0]
    finally:
        service_file.write_text(original)


def test_a_stack_line_over_the_libpam_limit_never_weakens_policy(environment):
    """Linux-PAM reads configuration lines into a fixed buffer. Whatever it does
    with an overlong line, no authentication may succeed with a restrictive
    trailing argument silently dropped."""
    _, _, idp, service_file, module, policy = environment[:6]
    original = service_file.read_text()
    filler = ",".join(f"https://f{index}.example/{'a' * 60}" for index in range(20))
    # ES256-only is a restriction stated last; an RS256 token must never pass.
    long_policy = policy.replace(f"audience={AUDIENCE}",
                                 f"audience={AUDIENCE},{filler}") + " algorithms=ES256"
    assert len(f"{module} {long_policy}") > 1500
    try:
        service_file.write_text(stack(module, long_policy))
        assert not connect(environment, idp.sign(subject="appuser"))[0]
    finally:
        service_file.write_text(original)


@pytest.fixture
def syslog():
    """Collect what PAM modules write to syslog (the container runs no daemon)."""
    path = pathlib.Path("/dev/log")
    path.unlink(missing_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    listener.bind(str(path))
    path.chmod(0o666)
    listener.settimeout(0.2)

    def messages():
        found = []
        while True:
            try:
                found.append(listener.recv(65536).decode("utf-8", "replace"))
            except socket.timeout:
                return found

    try:
        yield messages
    finally:
        listener.close()
        path.unlink(missing_ok=True)


def test_diagnostics_use_stable_codes_and_never_the_token(environment, syslog):
    cluster, _, idp, service_file, module, policy = environment[:6]
    original = service_file.read_text()
    token = idp.sign(subject="other")  # valid, but not the requested role
    assert not connect(environment, token, user="appuser")[0]
    try:
        service_file.write_text(stack(module, policy + " bogus=1"))
        assert not connect(environment, token, user="appuser")[0]
    finally:
        service_file.write_text(original)
    text = "\n".join(syslog())
    assert "token rejected: role_mismatch" in text
    assert "invalid module arguments: policy_unknown_argument" in text
    # Format: prefixed with the PAM service and module, as docs/pam.md says.
    assert "pg_oauth_pam" in text and "pg-oauth-pam-validate-" in text
    assert token not in text and token.split(".")[2] not in text


@contextlib.contextmanager
def stack_with(environment, arguments, account_arguments=None):
    """Temporarily install the stack with extra policy arguments on each line."""
    _, _, _, service_file, module, policy = environment[:6]
    original = service_file.read_text()
    account = arguments if account_arguments is None else account_arguments
    service_file.write_text(
        f"auth [success=ok default=die] {module} {policy} {arguments}\n"
        f"account [success=ok default=die] {module} {policy} {account}\n")
    try:
        yield
    finally:
        service_file.write_text(original)


def delegated(idp, roles, **claims):
    return idp.sign(subject="someone-else", extra_claims={"pg_roles": roles, **claims})


def test_identity_claim_selects_the_claim_that_must_equal_the_role(environment):
    _, _, idp, *_ = environment
    with stack_with(environment, "identity_claim=preferred_username"):
        token = idp.sign(subject="unrelated", extra_claims={"preferred_username": "appuser"})
        assert connect(environment, token)[0]
        # The default claim no longer decides anything, and a missing one denies.
        assert not connect(environment, idp.sign(subject="appuser"))[0]
        assert not connect(environment, token, user="other")[0]


def test_delegated_roles_authorize_exactly_the_listed_roles(environment):
    _, _, idp, *_ = environment
    with stack_with(environment, "role_claim=pg_roles"):
        # The subject need not equal the role; the claim names what may be used.
        both = delegated(idp, ["appuser", "other"])
        assert connect(environment, both, user="appuser")[0]
        assert connect(environment, both, user="other")[0]
        only_other = delegated(idp, ["other"])
        assert connect(environment, only_other, user="other")[0]
        assert not connect(environment, only_other, user="appuser")[0]
        assert connect(environment, delegated(idp, "appuser"), user="appuser")[0]
        # Exact match: case and prefix differences do not authorize.
        assert not connect(environment, delegated(idp, ["AppUser"]), user="appuser")[0]
        assert not connect(environment, delegated(idp, ["appuser2"]), user="appuser")[0]


def test_delegated_roles_never_widen_what_hba_allows(environment):
    _, _, idp, *_ = environment
    with stack_with(environment, "role_claim=pg_roles"):
        # A token may list a role the HBA rule does not route through PAM.
        assert not connect(environment, delegated(idp, ["postgres"]), user="postgres")[0]


@pytest.mark.parametrize("claims", [
    {},
    {"pg_roles": 7},
    {"pg_roles": {"appuser": True}},
    {"pg_roles": [7]},
    {"pg_roles": [["appuser"]]},
    {"pg_roles": [""]},
    {"pg_roles": ""},
    {"pg_roles": ["appuser", "appuser"]},
    {"pg_roles": [f"role{index}" for index in range(64)] + ["appuser"]},
    {"pg_roles": ["a" * 64]},
    {"pg_roles": ["appuser"], "sub": 7},
    {"pg_roles": ["appuser"], "sub": None},
], ids=["missing", "number", "object", "number-entry", "nested", "empty-entry",
        "empty-string", "duplicate", "too-many", "too-long", "wrong-type-subject",
        "null-subject"])
def test_malformed_role_claims_are_denied(environment, claims):
    _, _, idp, *_ = environment
    with stack_with(environment, "role_claim=pg_roles"):
        subject = claims.get("sub", "someone-else")
        extra = {key: value for key, value in claims.items() if key != "sub"}
        token = idp.sign(subject=subject, extra_claims=extra if "sub" not in claims
                         else {**extra, "sub": subject})
        assert not connect(environment, token, user="appuser")[0]


def test_delegated_roles_with_invisible_characters_are_denied(environment):
    """One role entry that hides or reorders text denies the whole claim, even
    when the requested role is also listed: the claim is trusted only if every
    entry is readable."""
    with stack_with(environment, "role_claim=pg_roles"):
        listed = ["appuser", "other"]
        assert connect(environment, environment[2].sign(
            subject="p", extra_claims={"pg_roles": listed}))[0]
        for hostile in ("other\u200b", "o\u202ether", "\ufeffother", "other\u2028"):
            accepted, _ = connect(environment, environment[2].sign(
                subject="p", extra_claims={"pg_roles": ["appuser", hostile]}))
            assert not accepted, hostile


def test_role_claim_must_match_between_the_two_stack_lines(environment):
    _, _, idp, *_ = environment
    token = delegated(idp, ["appuser"])
    with stack_with(environment, "role_claim=pg_roles", ""):
        assert not connect(environment, token)[0]
    with stack_with(environment, "", "role_claim=pg_roles"):
        assert not connect(environment, idp.sign(subject="appuser"))[0]
    with stack_with(environment, "role_claim=pg_roles", "role_claim=other_roles"):
        assert not connect(environment, token)[0]


def test_delegated_roles_are_opt_in_per_stack(environment):
    _, _, idp, *_ = environment
    token = delegated(idp, ["appuser"])
    # Without the argument a roles claim is ignored: identity must equal the role.
    assert not connect(environment, token)[0]
    with stack_with(environment, "role_claim=pg_roles"):
        assert connect(environment, token)[0]
    assert not connect(environment, token)[0]


def test_session_identity_is_the_role_with_the_pam_prefix(environment):
    """PostgreSQL records the database role as the PAM identity (not the token's
    subject); system_user exists from PostgreSQL 16."""
    cluster, client, idp, *_ = environment
    token = idp.sign(subject="appuser").encode()
    assert client.query(cluster, token, "SELECT current_user") == "appuser"
    if cluster.major >= 16:
        assert client.query(cluster, token, "SELECT system_user") == "pam:appuser"
    assert 'identity="appuser" method=pam' in cluster.logs()


def test_delegated_session_identity_is_the_role_not_the_subject(environment):
    cluster, client, idp, *_ = environment
    with stack_with(environment, "role_claim=pg_roles"):
        token = delegated(idp, ["other"]).encode()
        assert client.query(cluster, token, "SELECT current_user", user="other") == "other"
        if cluster.major >= 16:
            identity = client.query(cluster, token, "SELECT system_user", user="other")
            assert identity == "pam:other"
            assert "someone-else" not in identity
    assert 'identity="other" method=pam' in cluster.logs()
    assert "someone-else" not in cluster.logs()


def test_settings_and_server_stay_usable_after_libpam_ends_the_transaction(environment):
    """libpam may dlclose a module at pam_end. PostgreSQL keeps pointers into it
    (the custom setting's variable and description, the lock tranche name), so a
    backend that authenticated through PAM must survive SHOW ALL, pg_settings and
    a configuration reload afterwards."""
    cluster, client, idp, *_ = environment
    token = idp.sign(subject="appuser").encode()
    description = "Maximum number of shared PAM metadata and JWKS cache entries."
    with client.session(cluster, token) as run:
        assert run("SELECT current_user") == "appuser"
        psql(cluster, "SELECT pg_reload_conf()")
        # The backend applies the reload before it reads its next command.
        assert run("SELECT 1") == "1"
        run("SHOW ALL")
        assert int(run("SELECT count(*) FROM pg_settings")) > 100
        assert run("SELECT short_desc FROM pg_settings "
                   "WHERE name = 'pg_oauth_pam.cache_max_entries'") == description
        assert run("SHOW pg_oauth_pam.cache_max_entries") == "32"
    # A backend crash makes the postmaster restart every connection.
    assert "terminated by signal" not in cluster.logs()
    assert client.query(cluster, token, "SELECT 1") == "1"
