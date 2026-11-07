"""PAM validation must yield to PostgreSQL's authentication timeout and shutdown.

These mirror the OAuth validator's interrupt tests: a stalled provider must not
hold an unauthenticated backend past the signals PostgreSQL sends it.
"""

import concurrent.futures
import contextlib
import os
import pathlib
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "integration"))
from integration_support import AUDIENCE, SCOPE, LocalIdp, TemporaryPostgres, psql
from test_pam_module import Libpq, preload_config, require_disposable


@contextlib.contextmanager
def pam_environment(extra_config="", policy_args="", issuer=None, with_stack=False):
    """One PAM cluster. `issuer` overrides the trusted issuer; `with_stack` also
    yields (service file, module, policy) so a test can switch policies."""
    require_disposable()
    pg_config = os.environ["PG_CONFIG"]
    module = pathlib.Path(os.environ["PAM_MODULE"]).resolve()
    with tempfile.TemporaryDirectory(prefix="pg-oauth-pam-interrupt-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=120)
        service = "pg-oauth-pam-interrupt-" + uuid.uuid4().hex
        service_file = pathlib.Path("/etc/pam.d") / service
        cluster = TemporaryPostgres(
            pg_config, None,
            server_certificate=idp.tls_certificate, server_key=idp.tls_key,
            extra_config=preload_config(pg_config, module) + extra_config,
            hba_lines=("local all all trust\n"
                       f"hostssl postgres appuser 127.0.0.1/32 pam pamservice={service}\n"),
        )
        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN")
            ca_file = cluster.root / "provider-ca.pem"
            shutil.copyfile(idp.tls_certificate, ca_file)
            ca_file.chmod(0o644)
            policy = (f"issuer={issuer or idp.issuer} audience={AUDIENCE} scope={SCOPE} "
                      f"ca_file={ca_file} {policy_args}")
            service_file.write_text(f"auth [success=ok default=die] {module} {policy}\n"
                                    f"account [success=ok default=die] {module} {policy}\n")
            service_file.chmod(0o644)
            if with_stack:
                yield cluster, Libpq(pg_config), idp, service_file, module, policy
            else:
                yield cluster, Libpq(pg_config), idp
        finally:
            service_file.unlink(missing_ok=True)
            cluster.stop()
            idp.close()


@pytest.mark.slow
@pytest.mark.xdist_group(name="timing")
def test_authentication_timeout_interrupts_provider_fetch():
    with pam_environment("authentication_timeout = '1s'\n") as (cluster, client, idp):
        token = idp.sign(subject="appuser").encode()
        idp.set_delay("metadata", 2.5)
        started = time.monotonic()
        accepted, _ = client.connect(cluster, token)
        assert not accepted
        assert time.monotonic() - started < 2.2, cluster.logs()
        idp.set_delay("metadata", 0)
        assert client.connect(cluster, token)[0], "stalled attempt poisoned later logins"
        assert token.decode() not in cluster.logs()


@pytest.mark.slow
@pytest.mark.xdist_group(name="timing")
def test_authentication_timeout_interrupts_key_refresh():
    with pam_environment("authentication_timeout = '1s'\n",
                         "unknown_kid_refresh_cooldown_ms=1000") as (cluster, client, idp):
        warm = idp.sign(subject="appuser").encode()
        assert client.connect(cluster, warm)[0]
        idp.rotate("interrupt-jwks-key")
        rotated = idp.sign(subject="appuser").encode()
        idp.set_delay("jwks", 2.5)
        started = time.monotonic()
        accepted, _ = client.connect(cluster, rotated)
        assert not accepted
        assert time.monotonic() - started < 2.2, cluster.logs()
        idp.set_delay("jwks", 0)
        time.sleep(1.1)  # the aborted refresh still starts the unknown-key cooldown
        assert client.connect(cluster, rotated)[0]
        assert rotated.decode() not in cluster.logs()


@pytest.mark.slow
@pytest.mark.xdist_group(name="timing")
def test_fast_shutdown_interrupts_provider_fetch():
    with pam_environment() as (cluster, client, idp):
        token = idp.sign(subject="appuser").encode()
        idp.set_delay("metadata", 5.5)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            connection = pool.submit(client.connect, cluster, token)
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
                # The authentication attempt must end well before the delayed
                # response (5.5s), as soon as the backend is told to exit.
                accepted, _ = connection.result(timeout=2.5)
                assert time.monotonic() - started < 2.5, "shutdown waited for the provider"
                assert not accepted
            finally:
                try:
                    _stdout, stderr = stopping.communicate(
                        timeout=max(0.001, 4 - (time.monotonic() - started)))
                except subprocess.TimeoutExpired:
                    stopping.kill()
                    stopping.communicate()
                    raise
            assert stopping.returncode == 0, stderr
        assert token.decode() not in cluster.logs()


def backend_pid_after(cluster, offset):
    """PID of the backend that accepted the newest connection after `offset`."""
    for _ in range(50):
        pids = re.findall(r"\[(\d+)\] LOG:\s+connection received", cluster.logs()[offset:])
        if pids:
            return int(pids[-1])
        time.sleep(0.1)
    raise AssertionError("the server logged no new connection")


@pytest.mark.slow
@pytest.mark.xdist_group(name="timing")
def test_a_hung_refresh_owner_fails_waiters_closed_and_blocks_nothing_else():
    """ADR 0009, owner failure. The backend refreshing an entry can stay alive but
    stop making progress. Logins waiting for that entry must be denied within the
    configured wait, not held until the owner returns; entries the owner does not
    hold must be unaffected; and the entry must be usable again once the owner
    is released."""
    with pam_environment(policy_args="refresh_wait_timeout_ms=1000",
                         with_stack=True) as (cluster, client, idp, service_file, module, policy):
        def stack_for(extra=""):
            line = f"{module} {policy} {extra}".rstrip()
            service_file.write_text(f"auth [success=ok default=die] {line}\n"
                                    f"account [success=ok default=die] {line}\n")

        token = idp.sign(subject="appuser").encode()
        stack_for()
        assert client.connect(cluster, token)[0], "the base policy could not be primed"
        stack_for("clock_skew_ms=61000")  # a policy with no cache entries yet
        idp.set_delay("metadata", 30)
        before = idp.request_counts()["metadata"]
        offset = len(cluster.logs())
        pid = None
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                owner = pool.submit(client.connect, cluster, token)
                pid = backend_pid_after(cluster, offset)
                for _ in range(100):  # the owner is now inside the provider request
                    if idp.request_counts()["metadata"] > before:
                        break
                    time.sleep(0.1)
                else:
                    raise AssertionError("the owner never reached the provider")
                os.kill(pid, signal.SIGSTOP)

                started = time.monotonic()
                accepted, _ = pool.submit(client.connect, cluster, token).result(timeout=12)
                waited = time.monotonic() - started
                assert not accepted, "a waiter was accepted although the refresh never completed"
                assert waited < 4.0, f"the waiter was held for {waited:.1f}s by a hung owner"

                stack_for()  # an entry the hung owner does not hold
                started = time.monotonic()
                assert client.connect(cluster, token)[0]
                assert time.monotonic() - started < 2.0

                os.kill(pid, signal.SIGCONT)
                pid = None
                idp.set_delay("metadata", 0)
                owner.result(timeout=30)
        finally:
            if pid is not None:
                os.kill(pid, signal.SIGCONT)
            idp.set_delay("metadata", 0)

        stack_for("clock_skew_ms=61000")
        for _ in range(20):  # the released owner has completed and cleared its entry
            if client.connect(cluster, token)[0]:
                break
            time.sleep(0.5)
        else:
            raise AssertionError("the entry stayed unusable after its owner was released")
        assert "terminated by signal" not in cluster.logs()


@pytest.mark.slow
@pytest.mark.xdist_group(name="timing")
@pytest.mark.parametrize("config,limit", [
    # Cancellation: the authentication timeout (1s) must end the login before
    # the fetch's own two-second connect timeout would.
    ("authentication_timeout = '1s'\n", 1.7),
    # No authentication timeout: the fetch's connect timeout (two seconds, which
    # includes name resolution) must end the stall before the lookup's three.
    ("", 2.6),
], ids=["authentication-timeout", "fetch-timeout"])
def test_slow_name_resolution_does_not_hold_an_unauthenticated_backend(monkeypatch, config, limit):
    """ADR 0009, slow DNS. Name resolution that does not answer must be bounded
    like any other provider stall, by PostgreSQL's authentication timeout and by
    the fetch's own timeout, and must leave the server healthy. A resolver shim
    (tests/dns_failure_shim.c) makes lookups of one name pause for three seconds;
    the shim also records that the server process used it, so the test cannot
    pass without exercising it."""
    if platform.system() != "Linux":
        pytest.skip("the resolver shim is Linux only")
    work = pathlib.Path(tempfile.mkdtemp(prefix="pg-oauth-dns-shim-"))
    work.chmod(0o777)  # the server runs as another user and writes the marker
    shim = work / "dns_failure_shim.so"
    marker = work / "marker"
    source = pathlib.Path(__file__).resolve().parents[1] / "dns_failure_shim.c"
    subprocess.run([*os.environ.get("CC", "cc").split(), "-std=c17", "-Wall", "-Wextra",
                    "-Werror", "-shared", "-fPIC", "-o", str(shim), str(source), "-ldl"],
                   check=True)
    shim.chmod(0o755)
    monkeypatch.setenv("LD_PRELOAD", str(shim))
    monkeypatch.setenv("DNS_FAILURE_SHIM_MARKER", str(marker))
    monkeypatch.setenv("DNS_FAILURE_SHIM_DELAY", "1")
    try:
        with pam_environment(config,
                             issuer="https://resolver-probe.invalid/") as (cluster, client, idp):
            token = idp.sign(subject="appuser").encode()
            started = time.monotonic()
            accepted, _ = client.connect(cluster, token)
            elapsed = time.monotonic() - started
            assert not accepted
            assert marker.exists(), "the server never used the resolver shim"
            assert elapsed < limit, f"the stalled lookup held the backend for {elapsed:.1f}s"
            assert token.decode() not in cluster.logs()
            time.sleep(1.5)  # the abandoned lookup finishes while the server keeps running
            assert psql(cluster, "SELECT 1").stdout.strip() == "1"
            assert "terminated by signal" not in cluster.logs()
            assert "server process" not in cluster.logs() or "was terminated" not in cluster.logs()
    finally:
        shutil.rmtree(work, ignore_errors=True)


@pytest.mark.slow
@pytest.mark.xdist_group(name="timing")
def test_cache_hits_are_not_delayed_by_a_refresh_in_flight():
    """ADR 0009, bounded lock contention. The shared cache lock must never be held
    across provider I/O. While one login owns a slow refresh for a cold policy,
    logins that hit the cache for another policy, one after another and
    concurrently, must finish at once and not wait for the provider.

    It runs in its own cluster because it deliberately creates a cold policy, and
    the shared cluster of test_pam_validation.py has a fixed cache capacity that
    its later tests rely on."""
    with pam_environment(with_stack=True) as (cluster, client, idp, service_file, module, policy):
        def stack_for(extra=""):
            line = f"{module} {policy} {extra}".rstrip()
            service_file.write_text(f"auth [success=ok default=die] {line}\n"
                                    f"account [success=ok default=die] {line}\n")

        token = idp.sign(subject="appuser").encode()
        stack_for()
        assert client.connect(cluster, token)[0], "the base policy could not be primed"
        stack_for("clock_skew_ms=61000")  # no cache entries yet
        idp.set_delay("metadata", 1.5)
        idp.set_delay("jwks", 1.5)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                slow = pool.submit(client.connect, cluster, token)
                time.sleep(0.6)  # the slow login now waits on the provider
                # libpam read the cold stack when that login started; later logins
                # use the primed base policy.
                stack_for()
                started = time.monotonic()
                for _ in range(5):
                    assert client.connect(cluster, token)[0]
                hits = list(pool.map(lambda _: client.connect(cluster, token)[0], range(8)))
                elapsed = time.monotonic() - started
                assert all(hits)
                assert not slow.done(), "the refresh finished first, so nothing overlapped"
                assert elapsed < 2.0, f"cache hits took {elapsed:.2f}s during a refresh"
                assert slow.result(timeout=15)[0], "the slow login was denied"
        finally:
            idp.set_delay("metadata", 0)
            idp.set_delay("jwks", 0)
