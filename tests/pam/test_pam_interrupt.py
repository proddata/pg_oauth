"""PAM validation must yield to PostgreSQL's authentication timeout and shutdown.

These mirror the OAuth validator's interrupt tests: a stalled provider must not
hold an unauthenticated backend past the signals PostgreSQL sends it.
"""

import concurrent.futures
import contextlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "integration"))
from integration_support import AUDIENCE, SCOPE, LocalIdp, TemporaryPostgres, psql
from test_pam_module import Libpq, require_disposable


@contextlib.contextmanager
def pam_environment(extra_config=""):
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
            extra_config=extra_config,
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
            service_file.write_text(f"auth [success=ok default=die] {module} {policy}\n"
                                    f"account [success=ok default=die] {module} {policy}\n")
            service_file.chmod(0o644)
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
