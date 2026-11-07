import http.server
import os
import pathlib
import platform
import shlex
import ssl
import subprocess
import sys
import tempfile
import threading
import time


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def raw(self, data):
        """Send a hand-built response, for interim responses and trailers that
        BaseHTTPRequestHandler cannot produce."""
        self.close_connection = True
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ssl.SSLEOFError):
            pass

    def do_GET(self):
        body = b'{"ok":true}'
        if self.path == "/underflow-freshness-header":
            # The first value is exactly the 4096-byte limit; a second value
            # must be rejected, not appended.
            self.raw(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     b"Cache-Control: " + b"x" * 4096 + b"\r\n"
                     b"Cache-Control: " + b"y" * 100000 + b"\r\n"
                     b"Content-Length: 11\r\nConnection: close\r\n\r\n" + body)
            return
        if self.path == "/interim-freshness-header":
            # RFC 9110 section 15.2: a 1xx response is not the final response.
            self.raw(b"HTTP/1.1 100 Continue\r\nCache-Control: max-age=99999\r\n"
                     b"Age: 0\r\n\r\n"
                     b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     b"Content-Length: 11\r\nConnection: close\r\n\r\n" + body)
            return
        if self.path == "/trailer-freshness-header":
            # RFC 9110 section 6.5.1: trailers must not be merged into headers.
            self.raw(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     b"Transfer-Encoding: chunked\r\nTrailer: Cache-Control\r\n"
                     b"Connection: close\r\n\r\n"
                     b"b\r\n" + body + b"\r\n0\r\nCache-Control: max-age=99999\r\n\r\n")
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            body = b"{}"
        elif self.path == "/large":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = b'{"x":"' + b'x' * 128 + b'"}'
        elif self.path == "/text":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            body = b'{"ok":true}'
        elif self.path == "/jwks":
            self.send_response(200)
            self.send_header("Content-Type", "Application/JWK-Set+JSON")
            body = b'{"keys":[]}'
        elif self.path == "/fresh":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "public")
            self.send_header("Cache-Control", "max-age=120")
            self.send_header("Age", "20")
            self.send_header("Expires", "Sun, 06 Nov 1994 08:51:37 GMT")
            body = b'{"ok":true}'
        elif self.path == "/large-freshness-header":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "x" * 5000)
            body = b'{"ok":true}'
        elif self.path == "/error":
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            body = b'{}'
        elif self.path == "/slow":
            time.sleep(0.3)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = b'{"ok":true}'
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            body = b'{"ok":true}'
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ssl.SSLEOFError):
            pass

    def log_message(self, *_args):
        pass


def serve(tls_context=None):
    server = http.server.ThreadingHTTPServer(("localhost", 0), Handler)
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def main():
    binary = pathlib.Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as directory:
        temp = pathlib.Path(directory)
        key = temp / "key.pem"
        cert = temp / "cert.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        http_server, http_thread = serve()
        https_server, https_thread = serve(context)
        try:
            environment = os.environ.copy()
            environment.update({"HTTP_PROXY": "http://127.0.0.1:1",
                                "HTTPS_PROXY": "http://127.0.0.1:1",
                                "ALL_PROXY": "http://127.0.0.1:1",
                                "NO_PROXY": ""})
            subprocess.run(
                [binary, f"http://localhost:{http_server.server_port}",
                 f"https://localhost:{https_server.server_port}", cert],
                check=True, env=environment)
            if platform.system() == "Linux":
                shim = temp / "dns_failure_shim.so"
                source = pathlib.Path(__file__).with_name("dns_failure_shim.c")
                subprocess.run(
                    [*shlex.split(os.environ.get("CC", "cc")), "-std=c17",
                     "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                     "-o", shim, source, "-ldl"],
                    check=True,
                )
                marker = temp / "dns-failure-marker"
                dns_environment = environment.copy()
                dns_environment["LD_PRELOAD"] = str(shim)
                dns_environment["DNS_FAILURE_SHIM_MARKER"] = str(marker)
                result = subprocess.run(
                    [binary, "--dns-failure"], env=dns_environment,
                    check=False,
                )
                if result.returncode not in (0, 77):
                    raise RuntimeError("DNS failure was not denied")
                if result.returncode == 0 and not marker.exists():
                    raise RuntimeError("DNS failure shim was not exercised")
                if result.returncode == 0:
                    marker.unlink()
                    dns_environment["DNS_FAILURE_SHIM_DELAY"] = "1"
                    started = time.monotonic()
                    subprocess.run(
                        [binary, "--dns-cancel"], env=dns_environment,
                        check=True, timeout=5,
                    )
                    elapsed = time.monotonic() - started
                    if elapsed >= 1.5:
                        raise RuntimeError(
                            f"DNS cancellation cleanup took {elapsed:.2f}s"
                        )
                    if not marker.exists():
                        raise RuntimeError("delayed DNS failure shim was not exercised")
        finally:
            http_server.shutdown()
            https_server.shutdown()
            http_thread.join()
            https_thread.join()


if __name__ == "__main__":
    main()
