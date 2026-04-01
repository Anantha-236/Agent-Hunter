"""
Intentionally-vulnerable local test server for Agent-Hunter scanner validation.
This server is ONLY for testing — it deliberately returns vulnerable responses.
DO NOT expose to the internet.
"""
from __future__ import annotations

import json
import time
import threading
import asyncio
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote

# ── Port ──────────────────────────────────────────────────────────────────────
VULN_PORT = 18943  # high port to avoid conflicts


class VulnHandler(BaseHTTPRequestHandler):
    """Handler that returns intentionally-vulnerable responses."""

    def log_message(self, *_args):
        pass  # suppress noisy logs during tests

    # ── GET ────────────────────────────────────────────────────
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        # ── Root / index ──────────────────────────────────────
        if path == "/":
            body = self._index_page()
            return self._html(body)

        # ── XSS: reflect param unescaped ──────────────────────
        if path == "/search":
            q = qs.get("q", [""])[0]
            body = f"<html><body>Search results for: {q}</body></html>"
            return self._html(body)

        # ── SQLi: echo error on bad input ────────────────────
        if path == "/products":
            cat = qs.get("cat", [""])[0]
            if "'" in cat or '"' in cat or "OR" in cat.upper() or "UNION" in cat.upper():
                body = (
                    '<html><body>Error: SQL syntax error in MySQL near '
                    f"'{cat}' at line 1</body></html>"
                )
                return self._html(body, status=500)
            body = f"<html><body>Products for category {cat}</body></html>"
            return self._html(body)

        # ── Command Injection: echo uid ──────────────────────
        if path == "/ping":
            ip = qs.get("ip", [""])[0]
            if "id" in ip or "uid" in ip:
                body = f"Ping result: uid=0(root) gid=0(root) groups=0(root)"
            elif "sleep" in ip or "SLEEP" in ip:
                time.sleep(2)  # shortened for tests; scanner expects 5 but we use tolerance
                body = "Ping timeout"
            elif "passwd" in ip:
                body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
            else:
                body = f"Pinging {ip}..."
            return self._text(body)

        # ── Path Traversal / LFI ─────────────────────────────
        if path == "/view":
            f = qs.get("file", [""])[0]
            decoded = unquote(unquote(f))
            if "passwd" in decoded:
                body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
                return self._text(body)
            if "win.ini" in decoded:
                body = "[fonts]\n[extensions]\n"
                return self._text(body)
            return self._text(f"File: {f}")

        # ── SSRF ─────────────────────────────────────────────
        if path == "/fetch":
            url = qs.get("url", [""])[0]
            decoded = unquote(url)
            if "169.254" in decoded or "metadata" in decoded:
                body = "ami-id: ami-0123456789\ninstance-id: i-abcdef01234"
                return self._text(body)
            if "127.0.0.1" in decoded or "localhost" in decoded:
                body = "root:x:0:0:root:/root:/bin/bash"
                return self._text(body)
            return self._text(f"Fetched: {url}")

        # ── SSTI ─────────────────────────────────────────────
        if path == "/template":
            tpl = qs.get("name", [""])[0]
            if "6375624792" in tpl or "79831" in tpl:
                body = f"Result: 6375624792"
                return self._text(body)
            body = f"Hello {tpl}"
            return self._text(body)

        # ── CRLF Injection ────────────────────────────────────
        if path == "/redirect":
            ref = qs.get("ref", [""])[0]
            decoded = unquote(unquote(ref))
            if "BugBountyAgent" in decoded:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Injected-Header", "BugBountyAgent")
                self.end_headers()
                self.wfile.write(b"OK")
                return
            if "<script>" in decoded.lower():
                body = f"<html><body>{decoded}</body></html>"
                return self._html(body)
            return self._redirect_to("/")

        # ── Open Redirect ────────────────────────────────────
        if path == "/login":
            redir = qs.get("redirect", qs.get("next", qs.get("return", [""])))
            redir = redir[0] if redir else ""
            if redir and ("evil.com" in redir or redir.startswith("//")):
                self.send_response(302)
                self.send_header("Location", redir)
                self.end_headers()
                return
            body = '<html><body><form method="post" action="/login"><input name="username"><input name="password" type="password"><input type="submit"></form></body></html>'
            return self._html(body)

        # ── IDOR ─────────────────────────────────────────────
        if path == "/profile":
            uid = qs.get("id", [""])[0]
            if uid == "1":
                body = json.dumps({
                    "id": 1, "name": "Alice Johnson", "email": "alice@example.com",
                    "role": "admin", "phone": "+1-555-0100",
                    "address": "123 Main Street, Springfield, IL 62701",
                    "ssn": "123-45-6789", "notes": "Senior administrator account with full access"
                })
                return self._json(body)
            elif uid == "2":
                body = json.dumps({
                    "id": 2, "name": "Bob", "email": "bob@example.com", "role": "user"
                })
                return self._json(body)
            elif uid:
                return self._json("{}", status=200)
            return self._json('{"error":"missing id"}', status=400)

        # ── Host Header Injection ────────────────────────────
        if path == "/forgot-password":
            host = self.headers.get("X-Forwarded-Host", self.headers.get("Host", ""))
            body = f'<html><body>Reset link: https://{host}/reset?token=abc123</body></html>'
            return self._html(body)

        # ── Auth: default creds page ─────────────────────────
        if path in ("/admin", "/wp-admin", "/administrator"):
            body = '<html><body><form method="post" action="/admin"><input name="username"><input name="password" type="password"><input type="submit"></form></body></html>'
            return self._html(body)

        # ── Sensitive Files ──────────────────────────────────
        if path == "/.env":
            return self._text("DATABASE_USER=admin\nDATABASE_PASS=secret123\nSECRET_KEY=mysecretkey")
        if path == "/.git/HEAD":
            return self._text("ref: refs/heads/main")
        if path == "/phpinfo.php":
            return self._html("<html><body><h1>PHP Info</h1><p>PHP Version 8.1.0</p></body></html>")
        if path == "/robots.txt":
            # CORS reflection
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\n")
            return
        if path == "/backup.zip":
            return self._text("PK\x03\x04fake-zip-content-for-testing")
        if path == "/actuator/env":
            return self._json('{"propertySources": [{"name": "server.ports"}]}')

        # ── Directory listing ────────────────────────────────
        if path == "/uploads/":
            body = '<html><title>Index of /uploads/</title><body><h1>Index of /uploads/</h1><a href="secret.txt">secret.txt</a></body></html>'
            return self._html(body)

        # ── GraphQL endpoint ─────────────────────────────────
        if path == "/graphql":
            return self._json('{"errors":[{"message":"Must provide query string."}]}')

        # ── Race condition endpoint ──────────────────────────
        if path == "/coupon/apply":
            body = json.dumps({"status": "ok", "message": "Coupon applied", "discount": "10%"})
            return self._json(body)

        # ── CSRF: form without token ─────────────────────────
        if path == "/transfer":
            body = '<html><body><form method="post" action="/transfer"><input name="amount"><input name="to"><input type="submit"></form></body></html>'
            return self._html(body)

        # ── 404 ──────────────────────────────────────────────
        self._html("<html><body>Not Found</body></html>", status=404)

    # ── POST ──────────────────────────────────────────────────
    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(length) if length else b""
        body_str = body_bytes.decode("utf-8", errors="replace")
        content_type = self.headers.get("Content-Type", "")

        # ── XXE ──────────────────────────────────────────────
        if path in ("/api/xml", "/graphql") and "xml" in content_type.lower():
            if "passwd" in body_str.lower():
                return self._text("root:x:0:0:root:/root:/bin/bash")
            if "win.ini" in body_str.lower():
                return self._text("[fonts]\n[extensions]")
            if "169.254" in body_str or "meta-data" in body_str:
                return self._text("ami-id: ami-0123456789\ninstance-id: i-abcdef01234")
            return self._text("<root>OK</root>")

        # ── GraphQL POST ─────────────────────────────────────
        if path == "/graphql":
            return self._handle_graphql(body_str)

        # ── Auth: default creds ──────────────────────────────
        if path in ("/admin", "/wp-admin", "/login"):
            if "username=admin" in body_str and ("password=admin" in body_str or "password=password" in body_str):
                return self._html('<html><body><h1>Dashboard</h1><a href="/logout">Logout</a></body></html>')
            return self._html('<html><body>Invalid credentials</body></html>', status=401)

        # ── CSRF: form submission ────────────────────────────
        if path == "/transfer":
            return self._html('<html><body>Transfer successful! $100 sent.</body></html>')

        # ── Race condition ───────────────────────────────────
        if path == "/coupon/apply":
            return self._json('{"status":"ok","message":"Coupon applied","discount":"10%"}')

        self._html("OK", status=200)

    # ── OPTIONS (for CORS preflight) ─────────────────────────
    def do_OPTIONS(self):
        origin = self.headers.get("Origin", "*")
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Forwarded-Host")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()

    # ── GraphQL handler ──────────────────────────────────────
    def _handle_graphql(self, body_str: str):
        try:
            data = json.loads(body_str)
        except json.JSONDecodeError:
            return self._json('{"errors":[{"message":"Invalid JSON"}]}', status=400)

        # Batch query
        if isinstance(data, list):
            results = [{"data": {"__typename": "Query"}} for _ in data]
            return self._json(json.dumps(results))

        query = data.get("query", "") if isinstance(data, dict) else ""

        # Introspection
        if "__schema" in query:
            resp = {
                "data": {
                    "__schema": {
                        "types": [
                            {"name": "Query", "fields": [{"name": "user", "args": [{"name": "id", "type": {"name": "Int"}}]}]},
                            {"name": "User", "fields": [{"name": "id"}, {"name": "name"}, {"name": "email"}, {"name": "role"}, {"name": "ssn"}]},
                            {"name": "Mutation", "fields": [{"name": "deleteUser", "args": []}]},
                        ]
                    }
                }
            }
            return self._json(json.dumps(resp))

        # User IDOR query
        if "user" in query.lower() and "id" in query.lower():
            if "OR 1=1" in query or "' " in query:
                return self._json('{"errors":[{"message":"SQL syntax error in MySQL near \'1=1\'"}]}')
            resp = {"data": {"user": {"id": 1, "name": "Alice", "email": "alice@example.com", "role": "admin", "ssn": "123-45-6789"}}}
            return self._json(json.dumps(resp))

        # Users list query
        if "users" in query.lower():
            resp = {"data": {"users": [
                {"id": 1, "name": "Alice", "email": "alice@example.com", "role": "admin"},
                {"id": 2, "name": "Bob", "email": "bob@example.com", "role": "user"},
            ]}}
            return self._json(json.dumps(resp))

        # Field suggestions
        if "__typenameXYZ" in query or "XYZ" in query:
            return self._json('{"errors":[{"message":"Cannot query field XYZ. Did you mean __typename?","extensions":{"suggestions":["__typename"]}}]}')

        return self._json('{"data":{"__typename":"Query"}}')

    # ── Helpers ──────────────────────────────────────────────
    def _html(self, body: str, status: int = 200):
        self.send_response(status)
        # Intentionally missing security headers
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")  # version disclosure
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _text(self, body: str, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _json(self, body: str, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _redirect_to(self, location: str, status: int = 302):
        self.send_response(status)
        self.send_header("Location", location)
        self.end_headers()

    def _index_page(self) -> str:
        return """<html><head><title>Test App</title></head><body>
<h1>Test Application</h1>
<form action="/search" method="get"><input name="q"><button>Search</button></form>
<a href="/products?cat=1">Products</a>
<a href="/login">Login</a>
<a href="/admin">Admin</a>
<a href="/profile?id=1">Profile</a>
<a href="/view?file=readme.txt">View File</a>
<a href="/fetch?url=http://example.com">Fetch URL</a>
<a href="/template?name=World">Template</a>
<a href="/ping?ip=127.0.0.1">Ping</a>
<a href="/transfer">Transfer</a>
<a href="/coupon/apply?code=TEST10">Apply Coupon</a>
<form action="/transfer" method="post"><input name="amount"><input name="to"><button>Send</button></form>
</body></html>"""


# ── Server lifecycle ─────────────────────────────────────────────────────────

_server_instance = None
_server_thread = None


def start_vuln_server(port: int = VULN_PORT) -> str:
    """Start the vulnerable test server in a daemon thread; return base_url."""
    global _server_instance, _server_thread
    if _server_instance is not None:
        return f"http://127.0.0.1:{port}"

    _server_instance = HTTPServer(("127.0.0.1", port), VulnHandler)
    _server_thread = threading.Thread(target=_server_instance.serve_forever, daemon=True)
    _server_thread.start()
    # Give server a moment to bind
    time.sleep(0.3)
    return f"http://127.0.0.1:{port}"


def stop_vuln_server():
    global _server_instance, _server_thread
    if _server_instance:
        _server_instance.shutdown()
        _server_instance = None
        _server_thread = None
