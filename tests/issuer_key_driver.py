import base64
import http.server
import json
import os
import pathlib
import subprocess
import sys
import threading


def base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class Handler(http.server.BaseHTTPRequestHandler):
    issuer = None
    jwks_requests = 0
    cache_metadata_requests = 0
    cache_jwks_requests = 0
    flaky_jwks_requests = 0
    flood_metadata_requests = 0
    flood_jwks_requests = 0
    bad_jwks_requests = 0
    private_jwks_requests = 0
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        if self.path == "/metadata-cache":
            Handler.cache_metadata_requests += 1
            value = {"issuer": self.issuer,
                     "jwks_uri": self.issuer + "/jwks-cache"}
        elif self.path == "/metadata-stale":
            value = {"issuer": self.issuer,
                     "jwks_uri": self.issuer + "/jwks-flaky"}
        elif self.path == "/metadata":
            value = {"issuer": self.issuer, "jwks_uri": self.issuer + "/jwks"}
        elif self.path == "/metadata-wrong-issuer":
            value = {"issuer": self.issuer + "/other",
                     "jwks_uri": self.issuer + "/jwks"}
        elif self.path == "/metadata-bad-host":
            port = self.server.server_port
            value = {"issuer": self.issuer,
                     "jwks_uri": f"http://127.0.0.1:{port}/jwks"}
        elif self.path == "/metadata-flood":
            Handler.flood_metadata_requests += 1
            value = {"issuer": self.issuer,
                     "jwks_uri": self.issuer + "/jwks-flood"}
        elif self.path == "/metadata-bad-cached":
            value = {"issuer": self.issuer,
                     "jwks_uri": self.issuer + "/jwks-bad-cached"}
        elif self.path == "/metadata-private-jwks":
            value = {"issuer": self.issuer,
                     "jwks_uri": self.issuer + "/jwks-private"}
        elif self.path == "/metadata-bad-jwks":
            value = {"issuer": self.issuer,
                     "jwks_uri": self.issuer + "/bad-jwks"}
        elif self.path == "/metadata-jwks-http-error":
            value = {"issuer": self.issuer,
                     "jwks_uri": self.issuer + "/jwks-http-error"}
        elif self.path in ("/metadata-http-error", "/jwks-http-error"):
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")
            return
        elif self.path == "/bad-jwks":
            self.respond(b"not-json", "application/jwk-set+json")
            return
        elif self.path == "/jwks-bad-cached":
            Handler.bad_jwks_requests += 1
            self.respond(b"not-json", "application/jwk-set+json")
            return
        elif self.path == "/jwks-private":
            # A well-formed document whose key carries private material must
            # be refused and never retained.
            Handler.private_jwks_requests += 1
            modulus = bytes([0x80]) + bytes([0xA5]) * 255
            value = {"keys": [{"kty": "RSA", "n": base64url(modulus),
                                "e": "AQAB", "d": base64url(modulus),
                                "kid": "test-key", "alg": "RS256",
                                "use": "sig"}]}
        elif self.path == "/jwks-flaky":
            Handler.flaky_jwks_requests += 1
            Handler.jwks_requests += 1
            if Handler.flaky_jwks_requests > 1:
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")
                return
            modulus = bytes([0x80]) + bytes([0xA5]) * 255
            value = {"keys": [{"kty": "RSA", "n": base64url(modulus),
                                "e": "AQAB", "kid": "test-key",
                                "alg": "RS256", "use": "sig"}]}
        elif self.path in ("/jwks", "/jwks-cache", "/jwks-flood"):
            if self.path == "/jwks-flood":
                Handler.flood_jwks_requests += 1
            else:
                Handler.jwks_requests += 1
            if self.path == "/jwks-cache":
                Handler.cache_jwks_requests += 1
            modulus = bytes([0x80]) + bytes([0xA5]) * 255
            value = {"keys": [{"kty": "RSA", "n": base64url(modulus),
                                "e": "AQAB", "kid": "test-key",
                                "alg": "RS256", "use": "sig"}]}
        self.respond(json.dumps(value, separators=(",", ":")).encode(),
                     "application/jwk-set+json" if "jwks" in self.path
                     else "application/json")

    def respond(self, body, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if self.path in ("/jwks-cache", "/jwks-flaky"):
            self.send_header("Cache-Control", "max-age=1")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main():
    server = http.server.ThreadingHTTPServer(("localhost", 0), Handler)
    Handler.issuer = f"http://localhost:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    environment = os.environ.copy()
    environment.update({"HTTP_PROXY": "http://127.0.0.1:1", "NO_PROXY": ""})
    try:
        subprocess.run([pathlib.Path(sys.argv[1]).resolve(), Handler.issuer],
                       check=True, env=environment)
        if Handler.jwks_requests != 9:
            raise RuntimeError("issuer-key stage performed an implicit JWKS retry")
        if Handler.cache_metadata_requests != 2 or Handler.cache_jwks_requests != 4:
            raise RuntimeError("fresh cache hit or policy separation was incorrect")
        if Handler.flaky_jwks_requests != 2:
            raise RuntimeError("stale JWKS outage path did not attempt one refresh")
        # Cold-cache unknown-key flood: one fetch publishes the document and one
        # more starts the cooldown; the rest are suppressed. A known key with
        # the wrong algorithm publishes too.
        if Handler.flood_jwks_requests != 3 or Handler.flood_metadata_requests != 2:
            raise RuntimeError("a well-formed JWKS without the requested key was "
                               "not published, or the flood was not suppressed")
        # Documents that fail validation must never be cached.
        if Handler.bad_jwks_requests != 2 or Handler.private_jwks_requests != 2:
            raise RuntimeError("an invalid JWKS was cached")
    finally:
        server.shutdown()
        thread.join()


if __name__ == "__main__":
    main()
