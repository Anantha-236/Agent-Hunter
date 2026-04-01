"""Quick sanity check for the vuln test server."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests.vuln_server import start_vuln_server, stop_vuln_server
import httpx

base = start_vuln_server()
print(f"Server at {base}")

checks = [
    ("/", 200, "Test Application"),
    ("/search?q=<script>alert(1)</script>", 200, "<script>alert(1)</script>"),
    ("/products?cat=1%27", 500, "SQL syntax"),
    ("/ping?ip=;id;", 200, "uid=0"),
    ("/view?file=../../../etc/passwd", 200, "root:x:0:0"),
    ("/.env", 200, "DATABASE_PASS"),
    ("/.git/HEAD", 200, "ref: refs/"),
    ("/profile?id=1", 200, "alice@example.com"),
    ("/fetch?url=http://169.254.169.254/", 200, "ami-id"),
    ("/template?name={{79831*79832}}", 200, "6375624792"),
]

failed = 0
for path, exp_status, exp_body in checks:
    r = httpx.get(f"{base}{path}", timeout=5)
    ok = r.status_code == exp_status and exp_body in r.text
    tag = "OK" if ok else "FAIL"
    print(f"  {tag}: {path}")
    if not ok:
        failed += 1
        print(f"       got status={r.status_code}, body has '{exp_body}'={exp_body in r.text}")

stop_vuln_server()
print(f"\nResult: {len(checks) - failed}/{len(checks)} passed")
sys.exit(1 if failed else 0)
