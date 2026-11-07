"""Enforcing-mode evidence for the installed PAM module, run in the SELinux VM.

Usage: selinux_check.py denied|allowed

``denied`` runs before the optional HTTPS policy is installed (and again after
it is removed): a valid token must be refused and the audit log must hold a fresh
``name_connect`` denial for the provider's port. ``allowed`` runs with the policy
installed: the token must authenticate and the module must cause no other
``postgresql_t`` denial. The PAM module is loaded by libpam inside a confined
PostgreSQL backend, so any file, socket or syslog access the module needs and
the policy does not grant shows up here.
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "integration"))
from integration_support import AUDIENCE, SCOPE, LocalIdp, TemporaryPostgres, psql
from selinux_denial import audit_records, matches_https_denial, require
from selinux_support import require_enforcing, run

SERVICE_PREFIX = "pg-oauth-pam-selinux-"


def postgres_denials(records):
    """Audit lines that deny an action to a PostgreSQL backend."""
    return sorted(line for line in records
                  if re.search(r"avc:\s+denied\b", line)
                  and re.search(r"\bscontext=\S*:postgresql_t:\S+", line))


def client_connect(cluster, idp, token, user="appuser"):
    conninfo = (f"host=localhost hostaddr=127.0.0.1 port={cluster.port} dbname=postgres "
                f"user={user} sslmode=verify-full sslrootcert={idp.tls_certificate} "
                "connect_timeout=5 passfile=/nonexistent-pg-oauth-pam-passfile")
    environment = {**os.environ, "PGPASSWORD": token}
    return subprocess.run(
        [str(cluster.bindir / "psql"), "-X", "-A", "-t", conninfo, "-c", "SELECT system_user"],
        env=environment, capture_output=True, text=True, timeout=30, check=False)


def main():
    phase = sys.argv[1] if len(sys.argv) == 2 else ""
    require(phase in ("denied", "allowed"), "usage")
    require(os.environ.get("OAUTH_TEST_SELINUX") == "1", "launcher_required")
    require_enforcing()
    module = pathlib.Path(os.environ["PAM_MODULE"]).resolve()
    require(module.is_file(), "module_missing")
    with tempfile.TemporaryDirectory(prefix="pg-oauth-pam-selinux-idp-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=0)
        service = SERVICE_PREFIX + uuid.uuid4().hex
        service_file = pathlib.Path("/etc/pam.d") / service
        cluster = None
        try:
            cluster = TemporaryPostgres(
                os.environ["PG_CONFIG"], None,
                server_certificate=idp.tls_certificate, server_key=idp.tls_key,
                hba_lines=("local all all trust\n"
                           f"hostssl postgres appuser,other 127.0.0.1/32 pam pamservice={service}\n"),
            )
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN; CREATE ROLE other LOGIN;")
            ca_file = cluster.root / "provider-ca.pem"
            shutil.copyfile(idp.tls_certificate, ca_file)
            ca_file.chmod(0o644)
            policy = (f"issuer={idp.issuer} audience={AUDIENCE} scope={SCOPE} ca_file={ca_file}")
            service_file.write_text(
                f"auth [success=ok default=die] {module} {policy}\n"
                f"account [success=ok default=die] {module} {policy}\n")
            service_file.chmod(0o644)
            run("restorecon", "-v", service_file)
            run("semodule", "-DB")
            previous = audit_records()
            token = idp.sign(subject="appuser")
            result = client_connect(cluster, idp, token)
            logs = cluster.logs()
            output = result.stdout + result.stderr + logs
            require(token not in output and token.rsplit(".", 1)[1] not in output,
                    "private_data_exposed")
            if phase == "denied":
                require(result.returncode != 0, "unexpected_authorization")
                require("PAM authentication failed" in logs, "wrong_failure_stage")
                require(idp.request_counts() == {"metadata": 0, "jwks": 0}, "provider_reached")
                for _attempt in range(30):
                    if any(matches_https_denial(line, idp.server.server_port)
                           for line in audit_records() - previous):
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("SELinux PAM check: matching_https_avc_missing")
                print("SELinux PAM policy absence: valid token denied; fresh HTTPS AVC verified",
                      flush=True)
            else:
                require(result.returncode == 0, "authentication_failed: " + output)
                require(result.stdout.strip() == "pam:appuser", "unexpected_system_user")
                counts = idp.request_counts()
                require(counts["metadata"] >= 1 and counts["jwks"] >= 1, "provider_not_used")
                # Denials must still hold under confinement.
                require(client_connect(cluster, idp, token, user="other").returncode != 0,
                        "role_mismatch_accepted")
                require(client_connect(cluster, idp, idp.sign(
                    subject="appuser", audience="https://other.example/")).returncode != 0,
                    "wrong_audience_accepted")
                time.sleep(1)
                denials = postgres_denials(audit_records() - previous)
                require(not denials, "unexpected_postgresql_denials:\n" + "\n".join(denials))
                print("SELinux PAM policy present: token authenticates; no other PostgreSQL AVC",
                      flush=True)
            require_enforcing()
        finally:
            try:
                if cluster is not None:
                    cluster.stop()
            finally:
                service_file.unlink(missing_ok=True)
                idp.close()


if __name__ == "__main__":
    main()
