"""Disposable Linux-only tests that load pg_oauth_pam into a real PostgreSQL.

This revision of the module acquires the credential and denies unconditionally
(validation is not wired in yet), so every connection must fail closed and no
credential byte may reach any client or server log.
"""

import contextlib
import ctypes
import os
import pathlib
import re
import socket
import ssl
import struct
import sys
import uuid

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "integration"))
from integration_support import TemporaryPostgres, command, psql

CANARY = b"pam-credential-redaction-canary"


def require_disposable():
    if (sys.platform != "linux" or os.geteuid() != 0
            or not pathlib.Path("/.dockerenv").is_file()
            or os.environ.get("OAUTH_TEST_PAM_DISPOSABLE") != "1"):
        raise RuntimeError("PAM tests require explicit opt-in in a disposable Linux container")


def server_major(pg_config):
    version = command(pg_config, "--version").stdout
    return int(re.search(r"PostgreSQL (\d+)", version).group(1))


def preload_config(pg_config, module):
    """postgresql.conf lines the PAM module needs on this major.

    Before PostgreSQL 17 shared memory can only be created by the postmaster, so
    the module must be preloaded; later majors attach it on first use.
    """
    if server_major(pg_config) >= 17:
        return ""
    return f"shared_preload_libraries = '{module.with_suffix('')}'\n"


class Libpq:
    def __init__(self, pg_config):
        directory = command(pg_config, "--libdir").stdout.strip()
        self.lib = ctypes.CDLL(str(pathlib.Path(directory) / "libpq.so"))
        self.lib.PQconnectdbParams.argtypes = [ctypes.POINTER(ctypes.c_char_p),
                                              ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]
        self.lib.PQconnectdbParams.restype = ctypes.c_void_p
        self.lib.PQstatus.argtypes = [ctypes.c_void_p]
        self.lib.PQstatus.restype = ctypes.c_int
        self.lib.PQerrorMessage.argtypes = [ctypes.c_void_p]
        self.lib.PQerrorMessage.restype = ctypes.c_char_p
        self.lib.PQfinish.argtypes = [ctypes.c_void_p]
        self.lib.PQfinish.restype = None

    def query(self, cluster, password, sql, user="appuser"):
        """Connect over verified TLS, run one statement, return its first value."""
        with self.session(cluster, password, user) as run:
            return run(sql)

    @contextlib.contextmanager
    def session(self, cluster, password, user="appuser"):
        """Hold one authenticated backend open and run statements in it, so a test
        can observe what the PAM module left behind in that same process."""
        lib = self.lib
        lib.PQexec.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.PQexec.restype = ctypes.c_void_p
        lib.PQresultStatus.argtypes = [ctypes.c_void_p]
        lib.PQresultStatus.restype = ctypes.c_int
        lib.PQgetvalue.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
        lib.PQgetvalue.restype = ctypes.c_char_p
        lib.PQclear.argtypes = [ctypes.c_void_p]
        lib.PQclear.restype = None
        conn = self._open(cluster, password, user)

        def run(sql):
            result = lib.PQexec(conn, sql.encode())
            try:
                if lib.PQresultStatus(result) != 2:  # PGRES_TUPLES_OK
                    raise RuntimeError(lib.PQerrorMessage(conn).decode())
                return lib.PQgetvalue(result, 0, 0).decode()
            finally:
                lib.PQclear(result)

        try:
            if lib.PQstatus(conn) != 0:
                raise RuntimeError(lib.PQerrorMessage(conn).decode())
            yield run
        finally:
            lib.PQfinish(conn)

    def _open(self, cluster, password, user):
        pairs = [(b"host", b"localhost"), (b"port", str(cluster.port).encode()),
                 (b"dbname", b"postgres"), (b"user", user.encode()),
                 (b"sslmode", b"verify-full"),
                 (b"sslrootcert", str(cluster.server_certificate).encode()),
                 (b"connect_timeout", b"5"),
                 (b"passfile", b"/nonexistent-pg-oauth-pam-passfile"),
                 (b"password", password)]
        array = ctypes.c_char_p * (len(pairs) + 1)
        conn = self.lib.PQconnectdbParams(array(*(key for key, _ in pairs), None),
                                        array(*(value for _, value in pairs), None), 0)
        if not conn:
            raise RuntimeError("libpq connection allocation failed")
        return conn

    def connect(self, cluster, password, user="appuser"):
        pairs = [(b"host", b"localhost"), (b"port", str(cluster.port).encode()),
                 (b"dbname", b"postgres"), (b"user", user.encode()),
                 (b"sslmode", b"verify-full"),
                 (b"sslrootcert", str(cluster.server_certificate).encode()),
                 (b"connect_timeout", b"5"),
                 (b"passfile", b"/nonexistent-pg-oauth-pam-passfile")]
        if password is not None:
            pairs.append((b"password", password))
        array = ctypes.c_char_p * (len(pairs) + 1)
        conn = self.lib.PQconnectdbParams(array(*(key for key, _ in pairs), None),
                                        array(*(value for _, value in pairs), None), 0)
        if not conn:
            raise RuntimeError("libpq connection allocation failed")
        try:
            return self.lib.PQstatus(conn) == 0, self.lib.PQerrorMessage(conn).decode()
        finally:
            self.lib.PQfinish(conn)


POLICY = ("issuer=https://issuer.example/ audience=postgres://primary "
          "scope=connect:postgres")


def stack(module, arguments=POLICY):
    # Dedicated fail-closed stack: success-only controls, no includes (ADR 0008).
    # The continuation line also exercises libpam's argument handling.
    return (f"auth [success=ok default=die] {module} {arguments.split()[0]} \\\n"
            f"    {' '.join(arguments.split()[1:])}\n"
            f"account [success=ok default=die] {module} {arguments}\n")


@pytest.fixture(scope="module")
def environment(tmp_path_factory):
    require_disposable()
    root = tmp_path_factory.mktemp("pam-module")
    tls_key, certificate = root / "tls.key", root / "tls.pem"
    command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", tls_key, "-out", certificate, "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost")
    service = "pg-oauth-pam-test-" + uuid.uuid4().hex
    service_file = pathlib.Path("/etc/pam.d") / service
    pg_config = os.environ["PG_CONFIG"]
    assert "--with-pam" in command(pg_config, "--configure").stdout
    module = pathlib.Path(os.environ["PAM_MODULE"]).resolve()
    assert module.is_file() and " " not in str(module)
    cluster = TemporaryPostgres(
        pg_config, None,
        server_certificate=certificate, server_key=tls_key,
        extra_config=preload_config(pg_config, module),
        hba_lines=("local all all trust\n"
                   f"hostssl postgres appuser,other 127.0.0.1/32 pam pamservice={service}\n"),
    )
    try:
        cluster.start()
        psql(cluster, "CREATE ROLE appuser LOGIN; CREATE ROLE other LOGIN;")
        server_pid = int((cluster.data / "postmaster.pid").read_text().splitlines()[0])
        assert pathlib.Path(f"/proc/{server_pid}").stat().st_uid != 0
        # Dedicated fail-closed stack: success-only controls, no includes (ADR 0008).
        service_file.write_text(stack(module))
        service_file.chmod(0o644)
        yield cluster, Libpq(pg_config), service_file
    finally:
        service_file.unlink(missing_ok=True)
        cluster.stop()


@pytest.mark.parametrize("size", [len(CANARY), 1024, 16384, 16385, 65530])
def test_every_credential_is_denied_without_disclosure(environment, size):
    cluster, client, _ = environment
    # Every credential starts with the canary, so a leak of any prefix, however
    # short the credential, is detectable without matching common letters.
    credential = (CANARY * (size // len(CANARY) + 1))[:size]
    accepted, error = client.connect(cluster, credential)
    assert not accepted
    output = error + cluster.logs()
    assert CANARY.decode() not in output
    assert credential.decode() not in output
    assert "pam_authenticate failed" in cluster.logs()


def test_single_byte_credential_is_denied(environment):
    cluster, client, _ = environment
    accepted, _ = client.connect(cluster, b"x")
    assert not accepted


def test_missing_wrong_user_and_empty_credentials_are_denied(environment):
    cluster, client, _ = environment
    for user, value in (("appuser", None), ("appuser", b""), ("other", b"abc")):
        accepted, _ = client.connect(cluster, value, user=user)
        assert not accepted


@pytest.mark.parametrize("arguments", [
    "",
    POLICY + " unknown=1",
    POLICY + " issuer=https://other.example/",
    POLICY + " max_token_size=65531",
    POLICY + " clock_skew_ms=-1",
    "issuer=https://issuer.example/ audience=postgres://primary",
])
def test_invalid_policy_denies(environment, arguments):
    cluster, client, service_file = environment
    original = service_file.read_text()
    module = original.split()[2]
    service_file.write_text(stack(module, arguments or "x"))
    try:
        accepted, error = client.connect(cluster, CANARY)
        assert not accepted
        assert CANARY.decode() not in error + cluster.logs()
    finally:
        service_file.write_text(original)


def test_denial_does_not_poison_later_attempts(environment):
    cluster, client, _ = environment
    for _ in range(3):
        accepted, _ = client.connect(cluster, b"abc")
        assert not accepted
    # The server still serves ordinary local administrative connections.
    assert psql(cluster, "SELECT 1").returncode == 0


def test_account_stage_alone_cannot_authenticate(environment):
    cluster, client, service_file = environment
    original = service_file.read_text()
    module_line = next(line for line in original.splitlines()
                       if line.startswith("account "))
    # A bypassed auth stack must not let account management allow the login.
    # pam_permit is confined to this negative test, never a shipped stack.
    service_file.write_text("auth required pam_permit.so\n" + module_line + "\n")
    try:
        accepted, _ = client.connect(cluster, b"abc")
        assert not accepted
        assert "pam_acct_mgmt failed" in cluster.logs()
    finally:
        service_file.write_text(original)


def receive(stream, size):
    data = b""
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise EOFError("connection ended before complete protocol message")
        data += part
    return data


@pytest.mark.parametrize("credential", [b"abc\0hidden\0", b"no-terminator", b"\0"])
def test_malformed_password_packets_deny_without_leaking(environment, credential):
    cluster, _, _ = environment
    context = ssl.create_default_context(cafile=str(cluster.server_certificate))
    with socket.create_connection(("127.0.0.1", cluster.port), timeout=5) as raw:
        raw.sendall(struct.pack("!II", 8, 80877103))
        assert receive(raw, 1) == b"S"
        with context.wrap_socket(raw, server_hostname="localhost") as stream:
            startup = b"user\0appuser\0database\0postgres\0\0"
            stream.sendall(struct.pack("!II", len(startup) + 8, 196608) + startup)
            kind = receive(stream, 1)
            length = struct.unpack("!I", receive(stream, 4))[0]
            assert kind == b"R" and receive(stream, length - 4) == struct.pack("!I", 3)
            stream.sendall(b"p" + struct.pack("!I", len(credential) + 4) + credential)
            kind = receive(stream, 1)
            length = struct.unpack("!I", receive(stream, 4))[0]
            assert kind == b"E" and length < 8192
            assert b"hidden" not in receive(stream, length - 4)
    assert "hidden" not in cluster.logs()
