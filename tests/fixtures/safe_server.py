"""Misleading-but-safe loopback HTTP fixture for scanner calibration.

The responses intentionally contain common heuristic traps: generic errors,
escaped reflections, different resource sizes, compression, redirects, and
small delays.  None of those controls represents a vulnerability.
"""
from __future__ import annotations

import gzip
import html
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse


SAFE_PORT = 18944


class SafeHandler(BaseHTTPRequestHandler):
    login_attempts = 0
    coupon_attempts = 0
    lock = threading.Lock()

    def log_message(self, *_args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/":
            return self._html(
                '<html><body><form method="post" action="/transfer">'
                '<input type="hidden" name="csrf_token" value="fixture-token">'
                '<input name="amount"></form></body></html>'
            )
        if path == "/search":
            value = html.escape(qs.get("q", [""])[0], quote=True)
            return self._html(f"<html><body>Search: {value}</body></html>")
        if path == "/products":
            value = qs.get("cat", [""])[0]
            if any(marker in value.upper() for marker in ("'", '"', " OR ", "UNION")):
                return self._text("Request could not be processed", status=500)
            return self._html(f"<html><body>Products {html.escape(value)}</body></html>")
        if path == "/profile":
            # Constant status/body size prevents object-enumeration inference.
            return self._json({"error": "access denied"}, status=403)
        if path == "/public-profile":
            ident = qs.get("id", ["1"])[0]
            # Different-length public objects are not evidence of BOLA/IDOR.
            value = {"id": ident, "display_name": "A" if ident == "1" else "A longer public name"}
            return self._json(value)
        if path == "/api/data":
            # JSON intentionally lacks document-only CSP/XFO controls.
            return self._json({"status": "public", "items": []}, security_headers=False)
        if path == "/redirect":
            return self._redirect("/safe-destination")
        if path == "/safe-destination":
            return self._html("<html><body>Safe destination</body></html>")
        if path == "/compressed":
            body = gzip.compress(b"<html><body>Compressed safe response</body></html>")
            self.send_response(200)
            self._security_headers("text/html; charset=utf-8")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/delayed":
            time.sleep(0.08)
            return self._text("Completed normally")
        if path == "/ping":
            return self._text("Input rejected; no command was executed")
        if path == "/view":
            return self._text("File access denied", status=403)
        if path == "/fetch":
            return self._text("Remote fetch disabled", status=403)
        if path == "/template":
            value = html.escape(qs.get("name", [""])[0], quote=True)
            return self._text(f"Hello {value}")
        if path in ("/login", "/admin", "/wp-admin", "/administrator", "/panel"):
            return self._html(
                '<html><body><h1>Sign in</h1><form method="post"><input name="username">'
                '<input name="password" type="password"><input type="hidden" '
                'name="csrf_token" value="fixture-token"></form></body></html>'
            )
        if path == "/forgot-password":
            return self._html("<html><body>Reset request accepted</body></html>")
        if path == "/transfer":
            return self._html(
                '<html><body><form method="post" action="/transfer">'
                '<input name="csrf_token" value="fixture-token">'
                '<input name="amount"></form></body></html>'
            )
        if path == "/coupon/apply":
            return self._json({"status": "already_used"}, status=409)
        if path == "/graphql":
            return self._json({"errors": [{"message": "Query rejected"}]}, status=400)
        if path == "/robots.txt":
            return self._text("User-agent: *\nDisallow:")
        if path in {
            "/.env", "/.env.production", "/.git/config", "/.git/HEAD",
            "/backup.zip", "/db_backup.sql", "/config.json", "/application.yml",
            "/swagger.json", "/v2/api-docs", "/actuator/env",
            "/actuator/heapdump", "/.DS_Store", "/phpinfo.php", "/server-status",
        }:
            return self._text("Not found", status=404)
        return self._html("<html><body>Not found</body></html>", status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

        if path in ("/login", "/admin", "/wp-admin", "/administrator", "/panel"):
            with self.lock:
                type(self).login_attempts += 1
                attempts = type(self).login_attempts
            if attempts >= 4:
                self.send_response(429)
                self.send_header("Retry-After", "60")
                self._security_headers("text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Too many attempts")
                return
            return self._text("Invalid credentials", status=401)
        if path == "/forgot-password":
            return self._text("Reset request accepted", status=202)
        if path == "/transfer":
            if "csrf_token=fixture-token" not in body:
                return self._text("Invalid CSRF token", status=403)
            return self._text("Accepted", status=202)
        if path == "/coupon/apply":
            with self.lock:
                type(self).coupon_attempts += 1
                first = type(self).coupon_attempts == 1
            return self._json(
                {"status": "accepted" if first else "already_used"},
                status=200 if first else 409,
            )
        if path in ("/api/xml", "/graphql"):
            if "xml" in self.headers.get("Content-Type", "").lower():
                return self._text("XML external entities disabled", status=400)
            return self._json({"errors": [{"message": "Query rejected"}]}, status=400)
        return self._text("Method not allowed", status=405)

    def do_OPTIONS(self):
        origin = self.headers.get("Origin", "")
        self.send_response(204)
        self._security_headers("text/plain; charset=utf-8")
        if origin == "https://app.safe.example":
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()

    def do_PUT(self):
        self._text("Method not allowed", status=405)

    do_DELETE = do_PUT
    do_PATCH = do_PUT
    do_TRACE = do_PUT

    def _security_headers(self, content_type: str):
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=()")
        if content_type.startswith("text/html"):
            self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'")
            self.send_header("X-Frame-Options", "DENY")

    def _html(self, body: str, status: int = 200):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self._security_headers("text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _text(self, body: str, status: int = 200):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self._security_headers("text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _json(self, value, status: int = 200, *, security_headers: bool = True):
        encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        if security_headers:
            self._security_headers("application/json")
        else:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()


_server = None
_thread = None


def start_safe_server(port: int = SAFE_PORT) -> str:
    global _server, _thread
    if _server is not None:
        return f"http://127.0.0.1:{port}"
    SafeHandler.login_attempts = 0
    SafeHandler.coupon_attempts = 0
    _server = ThreadingHTTPServer(("127.0.0.1", port), SafeHandler)
    _thread = threading.Thread(target=_server.serve_forever, daemon=True)
    _thread.start()
    return f"http://127.0.0.1:{port}"


def stop_safe_server() -> None:
    global _server, _thread
    if _server is not None:
        _server.shutdown()
        _server.server_close()
    if _thread is not None:
        _thread.join(timeout=2)
    _server = None
    _thread = None
