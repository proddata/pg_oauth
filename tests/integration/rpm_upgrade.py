"""Rehearse retained RPM/configuration pairs in one disposable PostgreSQL cluster."""

import argparse
import hashlib
import os
import pathlib
import re
import stat
import tempfile
import uuid

from integration_support import (
    IDP_RESPONSE_SECRET, LocalIdp, TemporaryPostgres, command, psql,
)


PACKAGE = "postgresql18-pg_oauth_validator"
AUDIENCE_A = "https://postgres.example/rpm-a"
AUDIENCE_B = "https://postgres.example/rpm-b"
PRIVATE_CLAIM = "rpm-rehearsal-private-claim-never-log"
RAW_TOKEN = "rpm-rehearsal-private-token-never-log"
SIGNATURE = "rpm-rehearsal-private-signature-never-log"
CONFIG_FILES = (
    "postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf",
    "oauth-ca.pem", "server.crt", "server.key",
)


def require(condition, code):
    if not condition:
        raise RuntimeError(f"rpm_rehearsal_{code}")


def snapshot_configuration(data):
    snapshot = {}
    for name in CONFIG_FILES:
        path = data / name
        require(path.is_file() and not path.is_symlink(), "configuration_file")
        metadata = path.stat()
        require(metadata.st_size <= 1024 * 1024, "configuration_size")
        snapshot[name] = (
            path.read_bytes(), stat.S_IMODE(metadata.st_mode),
            metadata.st_uid, metadata.st_gid,
        )
    return snapshot


def restore_configuration(data, snapshot):
    require(set(snapshot) == set(CONFIG_FILES), "configuration_manifest")
    # All paths are fixed fixture names in a protected, stopped cluster.
    for name in CONFIG_FILES:
        path = data / name
        require(not path.is_symlink(), "configuration_symlink")
        content, mode, uid, gid = snapshot[name]
        path.write_bytes(content)
        if (path.stat().st_uid, path.stat().st_gid) != (uid, gid):
            os.chown(path, uid, gid)
        path.chmod(mode)
    require(snapshot_configuration(data) == snapshot, "configuration_restore")


def candidate_configuration(baseline):
    content, mode, uid, gid = baseline["postgresql.conf"]
    old = f"pg_oauth_validator.audiences = '{AUDIENCE_A}'".encode()
    new = f"pg_oauth_validator.audiences = '{AUDIENCE_B}'".encode()
    require(content.count(old) == 1, "configuration_audience")
    return {**baseline, "postgresql.conf": (content.replace(old, new), mode, uid, gid)}


def package_metadata(path):
    values = command(
        "rpm", "-qp", "--qf", "%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n", path,
    ).stdout.splitlines()
    require(len(values) == 4 and values[0] == PACKAGE, "package_identity")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", values[1]) is not None,
            "package_version")
    return values


def fingerprint(path):
    require(path.is_file() and not path.is_symlink(), "artifact_file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_installed(package, library, source_revision=None):
    expected = package_metadata(package)
    actual = command("rpm", "-q", "--qf", "%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n",
                     PACKAGE).stdout.splitlines()
    require(actual == expected, "installed_version")
    command("rpm", "--verify", PACKAGE)
    require(command("rpm", "-qf", "--qf", "%{NAME}", library).stdout == PACKAGE,
            "installed_owner")
    source = pathlib.Path(f"/usr/share/doc/{PACKAGE}/BUILD-SOURCE").read_text()
    require(f"release-version: {expected[1]}\n" in source, "installed_source_record")
    if source_revision is not None:
        require(f"source-revision: {source_revision}\n" in source, "installed_source_revision")


def stop_server(cluster):
    command(cluster.bindir / "pg_ctl", "-D", cluster.data, "-m", "fast",
            "-t", "10", "-w", "stop", user="postgres")
    cluster.started = False
    # pg_ctl status documents exit 3 for a stopped server, distinct from errors.
    require(command(cluster.bindir / "pg_ctl", "-D", cluster.data, "status",
                    user="postgres", check=False).returncode == 3, "server_stopped")


def resume_server(cluster):
    # Ensure finally cleans up even if startup fails after spawning postgres.
    cluster.started = True
    command(cluster.bindir / "pg_ctl", "-D", cluster.data, "-l", cluster.log,
            "-t", "10", "-w", "start", user="postgres")


def connect(cluster, client, idp, token, user="appuser"):
    token_file = cluster.root / f"rpm-token-{uuid.uuid4().hex}"
    token_file.write_text(token)
    token_file.chmod(0o600)
    conninfo = (
        f"host=localhost hostaddr=127.0.0.1 port={cluster.port} dbname=postgres "
        f"user={user} sslmode=verify-full sslrootcert={idp.tls_certificate} "
        f"oauth_issuer={idp.issuer} oauth_client_id=test-client connect_timeout=5"
    )
    return command(client, token_file, conninfo, check=False)


def check_phase(cluster, client, idp, audience, other_audience, phase, protected, results):
    log_offset = len(cluster.logs())

    def attempt(token, accepted=False, user="appuser"):
        protected.add(token)
        protected.add(token.rsplit(".", 1)[-1])
        result = connect(cluster, client, idp, token, user)
        results.append(result)
        require((result.returncode == 0) == accepted, f"{phase}_authorization")
        if accepted:
            require(result.stdout.strip() == "appuser|oauth:principal", f"{phase}_identity")

    valid = idp.sign(audience=audience, extra_claims={"private": PRIVATE_CLAIM})
    attempt(valid, accepted=True)
    for token in (
        RAW_TOKEN,
        valid.rsplit(".", 1)[0] + "." + SIGNATURE,
        idp.sign(audience=other_audience),
        idp.sign(audience=audience, scope="read:metadata"),
        idp.sign(audience=audience, subject="unmapped-principal"),
        idp.sign(audience=audience, token_type="JWT"),
        idp.sign(audience=audience, expiry=1),
        idp.sign(audience=audience, extra_claims={"iss": "https://wrong-issuer.example/"}),
    ):
        attempt(token)
    attempt(valid, user="postgres")

    # Zero advertised freshness forces retrieval without sleeps or TTL races.
    idp.rotate(f"rpm-{phase}-rotated", retain_previous=False)
    rotated = idp.sign(audience=audience)
    attempt(rotated, accepted=True)
    attempt(valid)
    idp.set_fault("metadata", "http_error")
    attempt(rotated)
    require(psql(cluster, "SELECT 1").stdout.strip() == "1", f"{phase}_recovery_path")
    idp.set_fault("metadata", None)
    attempt(rotated, accepted=True)

    # Exercise recovery from incomplete validator configuration without leaving
    # ALTER SYSTEM edits behind or weakening any trust setting. Restore the
    # exact protected configuration pair while the server is stopped.
    saved = snapshot_configuration(cluster.data)
    content, mode, uid, gid = saved["postgresql.conf"]
    old = f"pg_oauth_validator.audiences = '{audience}'".encode()
    require(content.count(old) == 1, f"{phase}_recovery_configuration")
    invalid = {**saved, "postgresql.conf": (
        content.replace(old, b"pg_oauth_validator.audiences = ''"), mode, uid, gid,
    )}
    stop_server(cluster)
    restore_configuration(cluster.data, invalid)
    resume_server(cluster)
    attempt(rotated)
    require(psql(cluster, "SELECT 1").stdout.strip() == "1", f"{phase}_configuration_recovery_path")
    stop_server(cluster)
    restore_configuration(cluster.data, saved)
    resume_server(cluster)
    attempt(rotated, accepted=True)
    require(snapshot_configuration(cluster.data) == saved, f"{phase}_recovery_configuration_digest")

    require(psql(cluster, "SHOW pg_oauth_validator.audiences").stdout.strip() == audience,
            f"{phase}_audience")
    require(psql(cluster, "SELECT value FROM rpm_rehearsal_marker").stdout.strip() == "retained",
            f"{phase}_database_retained")
    logs = cluster.logs()
    current_logs = logs[log_offset:]
    for diagnostic in ("validator=validator_envelope", "validator=validator_claims",
                       "validator=validator_issuer_key"):
        require(diagnostic in current_logs, f"{phase}_diagnostics")
    for secret in protected:
        require(secret not in logs, f"{phase}_server_redaction")
        for result in results:
            require(secret not in result.stdout + result.stderr, f"{phase}_client_redaction")


def rehearse(baseline, candidate, pg_config, library, client, source_revisions=None):
    source_revisions = {} if source_revisions is None else source_revisions
    require(not source_revisions or set(source_revisions) == {baseline, candidate}, "source_manifest")
    require(all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value)
                for value in source_revisions.values()),
            "source_revision")
    a, b = package_metadata(baseline), package_metadata(candidate)
    require(a[3] == b[3], "package_architecture")
    require(tuple(map(int, a[1].split("."))) < tuple(map(int, b[1].split("."))),
            "package_order")
    artifacts = {path: fingerprint(path) for path in (baseline, candidate)}
    verify_installed(baseline, library, source_revisions.get(baseline))
    original_library = fingerprint(library)
    with tempfile.TemporaryDirectory(prefix="rpm-upgrade-idp-") as directory:
        idp = LocalIdp(pathlib.Path(directory), cache_max_age=0)
        cluster = TemporaryPostgres(
            pg_config, library, issuer=idp.issuer, audience=AUDIENCE_A,
            identity_map=("principal", "appuser"), hba_users="appuser",
            ca_file=idp.tls_certificate, server_certificate=idp.tls_certificate,
            server_key=idp.tls_key,
            # The rotation checks need a provider fetch on every login, so
            # they run with the retention floor disabled (strict RFC 9111).
            extra_config="pg_oauth_validator.cache_min_ttl = '0'\n",
        )
        protected = {PRIVATE_CLAIM, RAW_TOKEN, SIGNATURE, IDP_RESPONSE_SECRET}
        results = []
        try:
            cluster.start()
            require(stat.S_IMODE(cluster.root.stat().st_mode) == 0o700, "recovery_permissions")
            psql(cluster, "CREATE ROLE appuser LOGIN; CREATE TABLE rpm_rehearsal_marker "
                  "(value text PRIMARY KEY); INSERT INTO rpm_rehearsal_marker VALUES ('retained')")
            saved_a = snapshot_configuration(cluster.data)
            saved_b = candidate_configuration(saved_a)
            check_phase(cluster, client, idp, AUDIENCE_A, AUDIENCE_B, "baseline", protected, results)

            start_a = psql(cluster, "SELECT pg_postmaster_start_time()").stdout
            stop_server(cluster)
            require(fingerprint(candidate) == artifacts[candidate], "candidate_integrity")
            command("rpm", "--upgrade", candidate)
            verify_installed(candidate, library, source_revisions.get(candidate))
            require(snapshot_configuration(cluster.data) == saved_a, "upgrade_changed_configuration")
            restore_configuration(cluster.data, saved_b)
            resume_server(cluster)
            start_b = psql(cluster, "SELECT pg_postmaster_start_time()").stdout
            require(start_b != start_a, "upgrade_restart")
            check_phase(cluster, client, idp, AUDIENCE_B, AUDIENCE_A, "candidate", protected, results)

            stop_server(cluster)
            require(fingerprint(baseline) == artifacts[baseline], "baseline_integrity")
            denied = command("rpm", "--upgrade", "--test", baseline, check=False)
            require(denied.returncode != 0, "implicit_downgrade")
            verify_installed(candidate, library, source_revisions.get(candidate))
            # RPM's --oldpackage permits an explicit downgrade, preserving its
            # normal dependency, architecture, and conflict checks (rpm(8)).
            command("rpm", "--upgrade", "--oldpackage", baseline)
            verify_installed(baseline, library, source_revisions.get(baseline))
            require(fingerprint(library) == original_library, "rollback_library_digest")
            require(snapshot_configuration(cluster.data) == saved_b, "rollback_changed_configuration")
            restore_configuration(cluster.data, saved_a)
            resume_server(cluster)
            require(psql(cluster, "SELECT pg_postmaster_start_time()").stdout != start_b,
                    "rollback_restart")
            check_phase(cluster, client, idp, AUDIENCE_A, AUDIENCE_B, "rollback", protected, results)
            require(snapshot_configuration(cluster.data) == saved_a, "rollback_configuration_digest")
            print("RPM A -> B -> A: restarts, retained data/configuration, authorization, "
                  "rotation, outage/configuration recovery, and redaction passed")
            return {
                "baseline_version": a[1], "candidate_version": b[1],
                "baseline_rpm_sha256": artifacts[baseline],
                "candidate_rpm_sha256": artifacts[candidate],
                "restored_library_sha256": original_library,
                "restored_configuration_sha256": {
                    name: hashlib.sha256(record[0]).hexdigest() for name, record in saved_a.items()
                },
                "phases": ["baseline", "candidate", "rollback"],
                "checks": ["retained_data", "restart", "authorization", "denial", "rotation",
                           "provider_outage_recovery", "invalid_configuration_recovery", "redaction"],
            }
        finally:
            cluster.stop()
            idp.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=pathlib.Path)
    parser.add_argument("candidate", type=pathlib.Path)
    args = parser.parse_args()
    rehearse(args.baseline, args.candidate, os.environ["PG_CONFIG"],
             pathlib.Path(os.environ["VALIDATOR_LIBRARY"]),
             pathlib.Path(os.environ["OAUTH_TEST_CLIENT"]))
