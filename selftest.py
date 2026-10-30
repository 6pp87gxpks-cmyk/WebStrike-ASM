#!/usr/bin/env python3
import asyncio, threading, uuid, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from webstrike.config import Options
from webstrike.engine import Engine
from webstrike import modules  # noqa: F401

PORT = 8899
HOME = """<!doctype html><html><head><title>WebStrike TestApp</title></head>
<body><h1>hello</h1><script src="/app.js"></script></body></html>"""
JS = """const API = "https://api.test";
const KEY = "AKIAIOSFODNN7EXAMPLE";
fetch("/api/v1/users"); fetch("/internal/debug"); fetch("/graphql");
//# sourceMappingURL=app.js.map
"""
ROUTES = {
    "/": (200, "text/html", HOME),
    "/app.js": (200, "application/javascript", JS),
    "/app.js.map": (200, "application/json", "{}"),
    "/.env": (200, "text/plain", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nSECRET=abc"),
    "/.git/HEAD": (200, "text/plain", "ref: refs/heads/main\n"),
    "/swagger.json": (200, "application/json", '{"openapi":"3.0.0","paths":{"/a":{}}}'),
    "/graphql": (200, "application/json", '{"data":{"__schema":{"types":[{"name":"Query"}]}}}'),
    "/robots.txt": (200, "text/plain", "User-agent: *\nDisallow: /admin\n"),
    "/admin": (200, "text/html", "<html>admin</html>"),
}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, ctype, body):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        o = self.headers.get("Origin")
        if o:
            self.send_header("Access-Control-Allow-Origin", o)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ROUTES: self._send(*ROUTES[p])
        else: self._send(404, "text/plain", "nope")
    do_HEAD = do_GET

CHECKS = [
    ("exposure", lambda fs: any(".env" in f.title for f in fs), "exposed .env"),
    ("exposure", lambda fs: any(".git" in f.title for f in fs), "exposed .git"),
    ("cors", lambda fs: bool(fs), "CORS origin reflection"),
    ("api", lambda fs: bool(fs), "swagger/openapi spec"),
    ("graphql", lambda fs: any("introspection" in f.title for f in fs), "graphql introspection"),
    ("secrets", lambda fs: any("AWS" in f.title for f in fs), "AWS key in JS"),
    ("discovery", lambda fs: any("/admin" in (f.url or "") for f in fs), "hidden /admin"),
    ("js", lambda fs: any("ourcemap" in f.title for f in fs), "sourcemap exposure"),
]

DOMAIN_CASES = {
    "https://user:pass@example.com/path?next=x@y": "example.com",
    "user@example.com": "example.com",
    "https://example.com/path": "example.com",
}

async def main():
    for target, expected in DOMAIN_CASES.items():
        actual = Engine._domain_of(target)
        if actual != expected:
            raise AssertionError(f"{target!r}: expected {expected!r}, got {actual!r}")

    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    only = ["robots", "fingerprint", "paths", "exposure", "js", "secrets",
            "graphql", "swagger", "cors"]
    opt = Options(profile="danger", only_modules=only, timeout=10)
    eng = Engine(uuid.uuid4().hex[:8], f"http://127.0.0.1:{PORT}", "url", opt)
    await eng.run()
    srv.shutdown()
    cats = {}
    for f in eng.findings:
        cats.setdefault(f.category, []).append(f)
    passed = failed = 0
    for cat, fn, label in CHECKS:
        ok = fn(cats.get(cat, []))
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
        passed += ok; failed += (not ok)
    print(f"\n{passed} passed, {failed} failed  "
          f"({len(eng.findings)} findings across {len(cats)} categories)")
    for e in [e for e in eng.history if e["kind"] == "module_error"]:
        print(f"  ! module error: {e['module']}: {e['error']}")
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
