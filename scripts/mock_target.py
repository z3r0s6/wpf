"""Tiny local target with intentional weaknesses for wpf self-test.

Run: python scripts/mock_target.py
Listens on http://127.0.0.1:8765 — designed to trigger many WSTG findings:
- Server header reveals "vulnnginx/4.2"
- No security headers (CSP, X-Content-Type-Options, X-Frame-Options, HSTS skipped — we're plain HTTP)
- Cookie set without HttpOnly/Secure/SameSite
- robots.txt + security.txt exposed
- HTML comments leaking 'TODO: rotate admin password'
- POST form without CSRF token
- /admin/../etc/passwd path returns a Whoops debug page
- /api/users/1?id=1' SQL error in the response
- Reflected XSS canary in `q` param
- /.env file exposed
- CORS reflects Origin with credentials=true
- /api-docs exposes swagger
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8765

PAGE = b"""<!doctype html>
<html><head>
<title>vulnnginx demo</title>
<!-- TODO: rotate admin password before launch -->
<!-- INTERNAL: api-key=abcd1234 -->
</head><body>
<h1>vulnnginx demo</h1>
<form method="POST" action="/comment">
  <input name="q" value="">
  <input type="hidden" name="csrf_what" value="not-a-token">
  <button>send</button>
</form>
<form method="POST" action="/login">
  <input name="username">
  <input type="password" name="password">
  <button>login</button>
</form>
<a href="/api-docs">api-docs</a>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "vulnnginx/4.2"
    sys_version = ""

    def log_message(self, *_args):  # silence
        pass

    def _send(self, body, code=200, ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Server", "vulnnginx/4.2")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # intentionally missing HSTS / CSP / X-Frame-Options / X-Content-Type-Options
        self.send_header("Set-Cookie", "sid=abc123")  # no HttpOnly/Secure/SameSite
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path, _, qs = self.path.partition("?")
        if path == "/robots.txt":
            return self._send(b"User-agent: *\nDisallow: /admin\nDisallow: /secret-area\n", ctype="text/plain")
        if path in ("/security.txt", "/.well-known/security.txt"):
            return self._send(b"Contact: security@example.tld\nExpires: 2099-01-01T00:00:00Z\n", ctype="text/plain")
        if path == "/.env":
            return self._send(b"AWS_ACCESS_KEY_ID=AKIAFAKE1234567890XY\nAWS_SECRET_ACCESS_KEY=fake/secret/key\n", ctype="text/plain")
        if path == "/admin/../etc/passwd":
            return self._send(b"<h1>Whoops, looks like something went wrong</h1>"
                              b"<pre>Traceback (most recent call last):\n  File '/app/admin.py', line 42\nFatal error</pre>",
                              code=500)
        if path == "/api/users/1":
            if "id=1%27" in qs or "id=1'" in qs:
                return self._send(b"<pre>SQL syntax; check the manual that corresponds to your MySQL server version</pre>",
                                  code=500)
            return self._send(b'{"id":1,"name":"alice","email":"alice@example.com"}', ctype="application/json")
        if path == "/api-docs":
            return self._send(b'{"swagger":"2.0","info":{"title":"vulnnginx demo","version":"1.0"}}', ctype="application/json")
        if path == "/":
            body = PAGE
            # reflect q param unencoded for XSS canary check
            if "q=" in qs:
                from urllib.parse import unquote
                val = unquote(qs.split("q=", 1)[1].split("&", 1)[0])
                body = body.replace(b'value=""', f'value="{val}"'.encode())
            return self._send(body)
        return self._send(b"<h1>404</h1>", code=404)

    def do_POST(self):
        return self._send(b"{'ok':true}", ctype="application/json")


if __name__ == "__main__":
    print(f"vulnnginx mock target on http://127.0.0.1:{PORT}/")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
