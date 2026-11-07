import base64
import http.server
import json
import os
import pathlib
import pwd
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid


ISSUER = "https://issuer.example/"
SCOPE = "connect:postgres"
AUDIENCE = "https://postgres.example/"
TOKEN = "integration-secret-token-that-must-not-appear"
IDP_RESPONSE_SECRET = "idp-response-secret-that-must-not-appear"


def command(*args, user=None, check=True):
    argv = [str(arg) for arg in args]
    if user is not None:
        argv = ["runuser", "-u", user, "--", *argv]
    return subprocess.run(argv, check=check, capture_output=True, text=True)


def unused_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TemporaryPostgres:
    def __init__(self, pg_config, validator_library, policy=None, audience=AUDIENCE,
                 issuer=ISSUER, identity_map=None, allow_insecure_http=False,
                 ca_file="", server_certificate=None, server_key=None,
                 identity_claim="sub", role_claim="",
                 delegate_ident_mapping=False, hba_users="all",
                 refresh_wait_timeout="5s", extra_config="", hba_lines=None,
                 scope=SCOPE):
        self.pg_config = pathlib.Path(pg_config)
        self.bindir = pathlib.Path(
            command(self.pg_config, "--bindir").stdout.strip()
        )
        self.validator_library = (None if validator_library is None
                                  else pathlib.Path(validator_library).resolve())
        version = command(self.pg_config, "--version").stdout
        match = re.search(r"PostgreSQL (\d+)", version)
        if match is None:
            raise RuntimeError(f"could not parse PostgreSQL version: {version.strip()}")
        self.major = int(match.group(1))
        self.policy = policy
        self.audience = audience
        self.issuer = issuer
        self.identity_map = identity_map
        self.allow_insecure_http = allow_insecure_http
        self.ca_file = ca_file
        self.server_certificate = server_certificate
        self.server_key = server_key
        self.identity_claim = identity_claim
        self.role_claim = role_claim
        self.delegate_ident_mapping = delegate_ident_mapping
        self.hba_users = hba_users
        self.refresh_wait_timeout = refresh_wait_timeout
        self.extra_config = extra_config
        self.hba_lines = hba_lines
        self.scope = scope
        self.port = unused_port()
        self.selinux = os.environ.get("OAUTH_TEST_SELINUX") == "1"
        self.root = pathlib.Path(tempfile.mkdtemp(
            prefix="pg-oauth-validator-",
            dir="/var/lib/pgsql" if self.selinux else None,
        ))
        self.data = self.root / "data"
        self.log = self.root / "postgres.log"
        self.started = False
        self.confined = None

        postgres = pwd.getpwnam("postgres")
        os.chown(self.root, postgres.pw_uid, postgres.pw_gid)

    def start(self):
        command(
            self.bindir / "initdb",
            "--auth-local=trust",
            "--auth-host=reject",
            "--no-instructions",
            "-D",
            self.data,
            user="postgres",
        )

        # Socket defaults vary by distribution (PostgreSQL 18, section 19.3.1).
        # Keep administrative connections inside this cluster's private root.
        socket_dir = str(self.root).replace("'", "''")
        audience = self.audience.replace("'", "''")
        ca_file = ""
        if self.ca_file:
            ca_path = self.data / "oauth-ca.pem"
            shutil.copyfile(self.ca_file, ca_path)
            postgres = pwd.getpwnam("postgres")
            os.chown(ca_path, postgres.pw_uid, postgres.pw_gid)
            ca_path.chmod(0o600)
            ca_file = str(ca_path)
        ssl_configuration = ""
        hba_type = "host"
        if self.server_certificate and self.server_key:
            server_certificate = self.data / "server.crt"
            server_key = self.data / "server.key"
            shutil.copyfile(self.server_certificate, server_certificate)
            shutil.copyfile(self.server_key, server_key)
            postgres = pwd.getpwnam("postgres")
            os.chown(server_certificate, postgres.pw_uid, postgres.pw_gid)
            os.chown(server_key, postgres.pw_uid, postgres.pw_gid)
            server_certificate.chmod(0o600)
            server_key.chmod(0o600)
            ssl_configuration = (
                "ssl = on\nssl_cert_file = 'server.crt'\n"
                "ssl_key_file = 'server.key'\n"
            )
            hba_type = "hostssl"
        # Without a validator library the cluster is configured for PAM only: the
        # OAuth settings do not exist before PostgreSQL 18.
        oauth_configuration = ""
        if self.validator_library is not None:
            library_dir = str(self.validator_library.parent).replace("'", "''")
            oauth_configuration = (
                f"dynamic_library_path = '{library_dir}'\n"
                "oauth_validator_libraries = 'pg_oauth_validator'\n"
                f"pg_oauth_validator.audiences = '{audience}'\n"
                f"pg_oauth_validator.identity_claim = '{self.identity_claim}'\n"
                f"pg_oauth_validator.role_claim = '{self.role_claim}'\n"
                f"pg_oauth_validator.refresh_wait_timeout = "
                f"'{self.refresh_wait_timeout}'\n"
                f"pg_oauth_validator.allow_insecure_http = "
                f"{'on' if self.allow_insecure_http else 'off'}\n"
                f"pg_oauth_validator.ca_file = '{ca_file}'\n"
            )
        with (self.data / "postgresql.conf").open("a", encoding="utf-8") as config:
            config.write(
                f"\nlisten_addresses = '127.0.0.1'\n"
                f"port = {self.port}\n"
                f"unix_socket_directories = '{socket_dir}'\n"
                f"{oauth_configuration}"
                f"{self.extra_config}"
                f"{ssl_configuration}"
                # RPM samples enable the collector; keep all diagnostics in
                # pg_ctl's protected log so redaction assertions inspect them.
                "logging_collector = off\n"
                "log_destination = 'stderr'\n"
                "log_connections = on\n"
                "log_min_messages = debug1\n"
            )

        options = (
            f"issuer={self.issuer} scope=\"{self.scope}\" "
            "validator=pg_oauth_validator"
        )
        if self.identity_map is not None:
            options += " map=oauthmap"
        if self.delegate_ident_mapping:
            options += " delegate_ident_mapping=1"
        if self.policy is not None:
            options += f" validator.policy={self.policy}"
        (self.data / "pg_hba.conf").write_text(
            self.hba_lines if self.hba_lines is not None else (
                "local all all trust\n"
                f"{hba_type} all {self.hba_users} 127.0.0.1/32 oauth {options}\n"
            ),
            encoding="utf-8",
        )
        if self.identity_map is not None:
            identity, role = self.identity_map
            (self.data / "pg_ident.conf").write_text(
                f"oauthmap {identity} {role}\n", encoding="utf-8"
            )

        if self.selinux:
            from selinux_support import ConfinedPostgres
            self.confined = ConfinedPostgres(self)
            self.confined.start()
        else:
            command(
                self.bindir / "pg_ctl",
                "-D",
                self.data,
                "-l",
                self.log,
                "-w",
                "start",
                user="postgres",
            )
        self.started = True

    def stop(self):
        if self.confined is not None:
            self.confined.stop()
            self.started = False
        if self.started:
            command(
                self.bindir / "pg_ctl",
                "-D",
                self.data,
                "-m",
                "immediate",
                "-w",
                "stop",
                user="postgres",
                check=False,
            )
            self.started = False
        shutil.rmtree(self.root, ignore_errors=True)

    def logs(self):
        if self.confined is not None:
            return self.confined.logs()
        return self.log.read_text(encoding="utf-8", errors="replace")


def attempt_oauth(cluster, client, token=TOKEN, user="postgres", issuer=ISSUER,
                  sslmode="disable"):
    token_file = cluster.root / f"token-{uuid.uuid4().hex}"
    token_file.write_text(token, encoding="utf-8")
    token_file.chmod(0o600)
    conninfo = (
        f"host=127.0.0.1 port={cluster.port} dbname=postgres user={user} "
        f"sslmode={sslmode} oauth_issuer={issuer} oauth_client_id=test-client "
        "connect_timeout=5"
    )
    return command(client, token_file, conninfo, check=False)


def psql_argv(cluster, sql):
    return [
        "runuser", "-u", "postgres", "--", cluster.bindir / "psql",
        "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1",
        "-h", cluster.root, "-p", cluster.port, "-d", "postgres", "-c", sql,
    ]


def psql(cluster, sql):
    return subprocess.run(
        [str(value) for value in psql_argv(cluster, sql)],
        check=True, capture_output=True, text=True,
    )


def wait_setting(cluster, name, expected):
    for _attempt in range(30):
        value = psql(cluster, f"SHOW {name}").stdout.strip()
        if value == expected:
            return
        time.sleep(0.1)
    raise AssertionError(f"{name} did not reload to the expected value")


def reload_setting(cluster, name, value):
    escaped_value = value.replace("'", "''")
    psql(cluster, f"ALTER SYSTEM SET {name} TO '{escaped_value}'")
    psql(cluster, "SELECT pg_reload_conf(); SELECT pg_sleep(0.1)")


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class LocalIdp:
    def __init__(self, root, cache_max_age=60, jwks_cache_max_age=None):
        self.root = root
        self.tls_key = root / "idp-tls-key.pem"
        self.tls_certificate = root / "idp-tls-certificate.pem"
        self.cache_max_age = cache_max_age
        self.jwks_cache_max_age = (cache_max_age if jwks_cache_max_age is None
                                   else jwks_cache_max_age)
        self.outage = False
        # (name, value) pairs sent instead of Cache-Control: max-age=N, to
        # exercise provider freshness headers that are unusual or malformed.
        self.freshness_headers = None
        self.faults = {"metadata": None, "jwks": None}
        self.delays = {"metadata": 0, "jwks": 0}
        self.requests = {"metadata": 0, "jwks": 0}
        self.requests_lock = threading.Lock()
        self.idle = threading.Condition()
        self.active_requests = 0
        self.keys = {}
        self.published_keys = []
        self.active_key_id = None
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", self.tls_key, "-out", self.tls_certificate,
             "-days", "1", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.rotate("integration-key", retain_previous=False)
        idp = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                idp.begin_request()
                try:
                    self.serve()
                finally:
                    idp.end_request()

            def serve(self):
                if self.path == "/.well-known/openid-configuration":
                    resource = "metadata"
                    idp.record_request(resource)
                    value = {"issuer": idp.issuer, "jwks_uri": idp.issuer + "/jwks"}
                elif self.path == "/jwks":
                    resource = "jwks"
                    idp.record_request(resource)
                    value = {"keys": [idp.keys[key_id][1]
                                      for key_id in idp.published_keys]}
                else:
                    self.send_error(404)
                    return
                if idp.outage:
                    self.send_error(503)
                    return
                if idp.delays[resource] > 0:
                    time.sleep(idp.delays[resource])
                fault = idp.faults[resource]
                if fault == "http_error":
                    self.send_response(503)
                    self.send_header("Content-Type", "application/json")
                    body = json.dumps({"error": IDP_RESPONSE_SECRET}).encode()
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if fault == "redirect":
                    self.send_response(302)
                    self.send_header("Location", idp.issuer + "/redirect-target")
                    self.end_headers()
                    return
                if fault == "malformed_json":
                    body = (b'{"broken":"' + IDP_RESPONSE_SECRET.encode())
                elif fault == "wrong_content_type":
                    body = json.dumps(value, separators=(",", ":")).encode()
                elif fault == "oversized":
                    body = IDP_RESPONSE_SECRET.encode() + b"x" * (65537)
                elif fault == "truncated":
                    body = (b'{"truncated":"' + IDP_RESPONSE_SECRET.encode())
                else:
                    body = json.dumps(value, separators=(",", ":")).encode()
                if fault == "total_timeout":
                    time.sleep(5.5)
                content_type = ("text/plain" if fault == "wrong_content_type"
                                else "application/json")
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                max_age = (idp.jwks_cache_max_age if resource == "jwks"
                           else idp.cache_max_age)
                if idp.freshness_headers is None:
                    self.send_header("Cache-Control", f"max-age={max_age}")
                else:
                    for name, value in idp.freshness_headers:
                        self.send_header(name, value)
                content_length = len(body) + 100 if fault == "truncated" else len(body)
                self.send_header("Content-Length", str(content_length))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                if fault == "truncated":
                    self.close_connection = True

            def log_message(self, *_args):
                pass

        self.server = http.server.ThreadingHTTPServer(("localhost", 0), Handler)
        self.selinux_port = os.environ.get("OAUTH_TEST_SELINUX") == "1"
        if self.selinux_port:
            from selinux_support import label_port
            label_port(self.server.server_port, "http_port_t")
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(self.tls_certificate, self.tls_key)
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.issuer = f"https://localhost:{self.server.server_port}"
        self.accepting_connections = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def rotate(self, key_id, retain_previous=True, algorithm="RS256"):
        key = self.root / f"idp-{key_id}.pem"
        if algorithm == "EdDSA":
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ED25519", "-out", key],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            # The raw Ed25519 public key is the last 32 bytes of its DER SPKI.
            public_der = subprocess.check_output(
                ["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER"],
                stderr=subprocess.DEVNULL,
            )
            jwk = {
                "kty": "OKP", "crv": "Ed25519", "x": b64(public_der[-32:]),
                "kid": key_id, "alg": "EdDSA", "use": "sig",
            }
        else:
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "RSA", "-out", key,
                 "-pkeyopt", "rsa_keygen_bits:2048"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            modulus_output = subprocess.check_output(
                ["openssl", "rsa", "-in", key, "-noout", "-modulus"],
                stderr=subprocess.DEVNULL,
            ).decode().strip()
            modulus = bytes.fromhex(modulus_output.split("=", 1)[1])
            jwk = {
                "kty": "RSA", "n": b64(modulus), "e": "AQAB",
                "kid": key_id, "alg": "RS256", "use": "sig",
            }
        self.keys[key_id] = (key, jwk)
        if not retain_previous:
            self.published_keys = []
        self.published_keys.append(key_id)
        self.active_key_id = key_id

    def retire(self, key_id):
        self.published_keys.remove(key_id)

    def record_request(self, resource):
        with self.requests_lock:
            self.requests[resource] += 1

    def begin_request(self):
        with self.idle:
            self.active_requests += 1

    def end_request(self):
        with self.idle:
            self.active_requests -= 1
            self.idle.notify_all()

    def wait_until_idle(self, timeout=10.0):
        """Wait until every request the provider has accepted has been answered.

        A client can give up (libpq connect_timeout) at the same moment the
        validator's own HTTP deadline expires, while the backend is still
        finishing the failed refresh. A request issued then would legitimately
        wait for that refresh owner and be denied with it (docs/configuration.md,
        refresh_wait_timeout), so tests that need a clean follow-up wait here.
        """
        with self.idle:
            if not self.idle.wait_for(lambda: self.active_requests == 0, timeout):
                raise AssertionError("provider requests were still in flight")

    def request_counts(self):
        with self.requests_lock:
            return dict(self.requests)

    def set_fault(self, resource, fault):
        if resource not in self.faults:
            raise ValueError(f"unknown IdP resource: {resource}")
        self.faults[resource] = fault

    def set_delay(self, resource, delay):
        if resource not in self.delays or delay < 0:
            raise ValueError(f"invalid IdP delay for {resource}: {delay}")
        self.delays[resource] = delay

    def pause_accepting_connections(self):
        self.server.shutdown()
        self.thread.join()
        self.accepting_connections = False

    def resume_accepting_connections(self):
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.accepting_connections = True

    def sign(self, *, subject="principal", scope=SCOPE, audience=AUDIENCE,
             expiry=None, key_id=None, header_key_id=None, token_type="at+jwt",
             extra_claims=None, header_algorithm=None):
        key_id = key_id or self.active_key_id
        now = int(time.time())
        key_algorithm = self.keys[key_id][1]["alg"]
        header = {
            "alg": header_algorithm or key_algorithm,
            "kid": header_key_id or key_id,
        }
        if token_type is not None:
            header["typ"] = token_type
        claims = {
            "iss": self.issuer, "aud": audience,
            "exp": expiry if expiry is not None else now + 300,
            "sub": subject, "scope": scope,
        }
        if extra_claims is not None:
            claims.update(extra_claims)
        signing_input = (
            b64(json.dumps(header, separators=(",", ":")).encode()) + "." +
            b64(json.dumps(claims, separators=(",", ":")).encode())
        )
        input_file = self.root / "idp-signing-input"
        signature_file = self.root / "idp-signature"
        input_file.write_bytes(signing_input.encode())
        if key_algorithm == "EdDSA":
            sign_command = ["openssl", "pkeyutl", "-sign", "-rawin",
                            "-inkey", self.keys[key_id][0], "-in", input_file,
                            "-out", signature_file]
        else:
            sign_command = ["openssl", "dgst", "-sha256", "-sign",
                            self.keys[key_id][0], "-out", signature_file,
                            input_file]
        subprocess.run(
            sign_command,
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return signing_input + "." + b64(signature_file.read_bytes())

    def close(self):
        if self.accepting_connections:
            self.server.shutdown()
            self.thread.join()
        self.server.server_close()
        if self.selinux_port:
            from selinux_support import run
            run("semanage", "port", "-d", "-p", "tcp", self.server.server_port)
            self.selinux_port = False
