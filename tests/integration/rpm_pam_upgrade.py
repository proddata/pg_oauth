"""Rehearse retained PAM subpackage RPMs: A -> B -> A in one disposable cluster.

The PAM module is an independent package (ADR 0008). This mirrors rpm_upgrade.py
for it: the baseline is installed and works, the candidate replaces it while the
operator's configuration stays untouched, a rejected implicit downgrade and an
explicit rollback restore the exact module bytes and configuration, and each
phase must authenticate, deny, survive a provider outage and keep secrets out of
the logs. The validator package is not installed.

Run as root inside the disposable, --network=none RPM test container:
    rpm_pam_upgrade.py BASELINE.rpm CANDIDATE.rpm
with the baseline package already installed (as rpm_upgrade.py expects).
"""

import argparse
import os
import pathlib
import re
import shutil
import stat
import sys
import tempfile
import uuid

from integration_support import IDP_RESPONSE_SECRET, SCOPE, LocalIdp, TemporaryPostgres, command, psql
from rpm_upgrade import fingerprint, require, resume_server, stop_server

PACKAGE = "postgresql18-pg_oauth_validator-pam"
AUDIENCE_A = "https://postgres.example/rpm-pam-a"
AUDIENCE_B = "https://postgres.example/rpm-pam-b"
PRIVATE_CLAIM = "rpm-pam-rehearsal-private-claim-never-log"
RAW_TOKEN = "rpm-pam-rehearsal-private-token-never-log"
SIGNATURE = "rpm-pam-rehearsal-private-signature-never-log"
CONFIG_FILES = (
    "postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf",
    "server.crt", "server.key",
)


def module_path():
    libdir = command("rpm", "--eval", "%{_libdir}").stdout.strip()
    return pathlib.Path(libdir) / "security" / "pg_oauth_pam.so"


def package_metadata(path):
    values = command(
        "rpm", "-qp", "--qf", "%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n", path,
    ).stdout.splitlines()
    require(len(values) == 4 and values[0] == PACKAGE, "package_identity")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", values[1]) is not None, "package_version")
    return values


def verify_installed(package, module):
    expected = package_metadata(package)
    actual = command("rpm", "-q", "--qf", "%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n",
                     PACKAGE).stdout.splitlines()
    require(actual == expected, "installed_version")
    command("rpm", "--verify", PACKAGE)
    require(command("rpm", "-qf", "--qf", "%{NAME}", module).stdout == PACKAGE,
            "installed_owner")


def snapshot(paths):
    result = {}
    for path in paths:
        require(path.is_file() and not path.is_symlink(), "configuration_file")
        metadata = path.stat()
        require(metadata.st_size <= 1024 * 1024, "configuration_size")
        result[str(path)] = (path.read_bytes(), stat.S_IMODE(metadata.st_mode),
                             metadata.st_uid, metadata.st_gid)
    return result


def restore(content_by_path, owned):
    # Only the files this rehearsal owns may be written back.
    require(set(content_by_path) == {str(path) for path in owned}, "configuration_manifest")
    for name, (content, mode, uid, gid) in content_by_path.items():
        path = pathlib.Path(name)
        require(not path.is_symlink(), "configuration_symlink")
        path.write_bytes(content)
        if (path.stat().st_uid, path.stat().st_gid) != (uid, gid):
            os.chown(path, uid, gid)
        path.chmod(mode)
    require(snapshot([pathlib.Path(name) for name in content_by_path]) == content_by_path,
            "configuration_restore")


def service_text(module, policy):
    return (f"auth [success=ok default=die] {module} {policy}\n"
            f"account [success=ok default=die] {module} {policy}\n")


def check_phase(cluster, libpq, idp, audience, other_audience, phase, protected, results):
    def attempt(token, accepted=False, user="appuser"):
        protected.add(token)
        protected.add(token.rsplit(".", 1)[-1])
        ok, error = libpq.connect(cluster, token.encode(), user=user)
        results.append(error)
        require(ok == accepted, f"{phase}_authorization")

    valid = idp.sign(audience=audience, subject="appuser",
                     extra_claims={"private": PRIVATE_CLAIM})
    attempt(valid, accepted=True)
    for token in (
        RAW_TOKEN,
        valid.rsplit(".", 1)[0] + "." + SIGNATURE,
        idp.sign(audience=other_audience, subject="appuser"),
        idp.sign(audience=audience, scope="read:metadata", subject="appuser"),
        idp.sign(audience=audience, subject="other"),
        idp.sign(audience=audience, subject="appuser", token_type="JWT"),
        idp.sign(audience=audience, subject="appuser", expiry=1),
    ):
        attempt(token)
    # A valid token for appuser never opens another role.
    attempt(valid, user="postgres")

    # Zero advertised freshness forces retrieval; an outage must then deny, and
    # recovery must authenticate again without any configuration change.
    idp.outage = True
    attempt(idp.sign(audience=audience, subject="appuser"))
    require(psql(cluster, "SELECT 1").stdout.strip() == "1", f"{phase}_recovery_path")
    idp.outage = False
    attempt(idp.sign(audience=audience, subject="appuser"), accepted=True)

    require(psql(cluster, "SELECT value FROM rpm_rehearsal_marker").stdout.strip() == "retained",
            f"{phase}_database_retained")
    logs = cluster.logs()
    for secret in protected:
        require(secret not in logs, f"{phase}_server_redaction")
        for error in results:
            require(secret not in error, f"{phase}_client_redaction")
    require(IDP_RESPONSE_SECRET not in logs, f"{phase}_provider_response_redaction")


def rehearse(baseline, candidate, pg_config):
    # Imported here: the PAM suite module needs pytest, which the unit tests of
    # this file's pure helpers do not.
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "pam"))
    from test_pam_module import Libpq, preload_config, require_disposable

    require_disposable()
    a, b = package_metadata(baseline), package_metadata(candidate)
    require(a[3] == b[3], "package_architecture")
    require(tuple(map(int, a[1].split("."))) < tuple(map(int, b[1].split("."))), "package_order")
    artifacts = {path: fingerprint(path) for path in (baseline, candidate)}
    module = module_path()
    verify_installed(baseline, module)
    original_module = fingerprint(module)
    service = "pg-oauth-rpm-pam-" + uuid.uuid4().hex
    service_file = pathlib.Path("/etc/pam.d") / service
    protected = {PRIVATE_CLAIM, RAW_TOKEN, SIGNATURE, IDP_RESPONSE_SECRET}
    results = []
    with tempfile.TemporaryDirectory(prefix="rpm-pam-upgrade-idp-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=0)
        cluster = TemporaryPostgres(
            pg_config, None, server_certificate=idp.tls_certificate, server_key=idp.tls_key,
            extra_config=preload_config(pg_config, module),
            hba_lines=("local all all trust\n"
                       f"hostssl postgres appuser 127.0.0.1/32 pam pamservice={service}\n"),
        )
        try:
            cluster.start()
            psql(cluster, "CREATE ROLE appuser LOGIN; CREATE TABLE rpm_rehearsal_marker "
                  "(value text PRIMARY KEY); INSERT INTO rpm_rehearsal_marker VALUES ('retained')")
            ca_file = cluster.root / "provider-ca.pem"
            shutil.copyfile(idp.tls_certificate, ca_file)
            ca_file.chmod(0o644)

            def policy(audience):
                # cache_min_ttl_ms=0 keeps strict per-login retrieval so the
                # outage and recovery probes are meaningful.
                return (f"issuer={idp.issuer} audience={audience} scope={SCOPE} "
                        f"ca_file={ca_file} cache_min_ttl_ms=0")

            service_file.write_text(service_text(module, policy(AUDIENCE_A)))
            service_file.chmod(0o644)
            owned = [cluster.data / name for name in CONFIG_FILES] + [service_file, ca_file]
            saved_a = snapshot(owned)
            service_b = (service_text(module, policy(AUDIENCE_B)).encode(),
                         *saved_a[str(service_file)][1:])
            saved_b = {**saved_a, str(service_file): service_b}
            libpq = Libpq(pg_config)
            check_phase(cluster, libpq, idp, AUDIENCE_A, AUDIENCE_B, "baseline", protected, results)

            start_a = psql(cluster, "SELECT pg_postmaster_start_time()").stdout
            stop_server(cluster)
            require(fingerprint(candidate) == artifacts[candidate], "candidate_integrity")
            command("rpm", "--upgrade", candidate)
            verify_installed(candidate, module)
            require(snapshot(owned) == saved_a, "upgrade_changed_configuration")
            restore(saved_b, owned)
            resume_server(cluster)
            start_b = psql(cluster, "SELECT pg_postmaster_start_time()").stdout
            require(start_b != start_a, "upgrade_restart")
            check_phase(cluster, libpq, idp, AUDIENCE_B, AUDIENCE_A, "candidate", protected, results)

            stop_server(cluster)
            require(fingerprint(baseline) == artifacts[baseline], "baseline_integrity")
            denied = command("rpm", "--upgrade", "--test", baseline, check=False)
            require(denied.returncode != 0, "implicit_downgrade")
            verify_installed(candidate, module)
            command("rpm", "--upgrade", "--oldpackage", baseline)
            verify_installed(baseline, module)
            require(fingerprint(module) == original_module, "rollback_module_digest")
            require(snapshot(owned) == saved_b, "rollback_changed_configuration")
            restore(saved_a, owned)
            resume_server(cluster)
            require(psql(cluster, "SELECT pg_postmaster_start_time()").stdout != start_b,
                    "rollback_restart")
            check_phase(cluster, libpq, idp, AUDIENCE_A, AUDIENCE_B, "rollback", protected, results)
            require(snapshot(owned) == saved_a, "rollback_configuration_digest")
            return {
                "package": PACKAGE,
                "versions": [a[1], b[1], a[1]],
                "module_sha256": original_module,
                "phases": ["baseline", "candidate", "rollback"],
                "checks": ["restart", "authorization", "denial", "provider_outage_recovery",
                           "retained_data", "redaction", "untouched_configuration",
                           "implicit_downgrade_rejected", "explicit_rollback_digest"],
            }
        finally:
            service_file.unlink(missing_ok=True)
            cluster.stop()
            idp.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=pathlib.Path)
    parser.add_argument("candidate", type=pathlib.Path)
    arguments = parser.parse_args()
    outcome = rehearse(arguments.baseline, arguments.candidate, os.environ["PG_CONFIG"])
    print("PAM package rehearsal passed:", ", ".join(outcome["versions"]))
