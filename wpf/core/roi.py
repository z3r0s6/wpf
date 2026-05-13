"""Port of ars0n-framework-v2's ``calculateROIScore``.

Source: client/src/components/ROIReport.js (calculateROIScore ~line 222).
Each url_fact starts at 50 and gets adders for status code, auth surface, input
opportunities, info disclosure, and TLS hygiene. The breakdown is preserved.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# Pattern catalog mirrors the ROIReport.js heuristics.
_SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"),                                "AWS access key"),
    (re.compile(r"aws_secret_access_key", re.I),                     "AWS secret reference"),
    (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY"), "private key block"),
    (re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"), "JWT"),
    (re.compile(r"mongodb(\+srv)?://[^\s\"']+"),                     "MongoDB URI"),
    (re.compile(r"SECRET_KEY\s*[:=]\s*[\"']?[A-Za-z0-9+/=_-]{12,}"), "SECRET_KEY literal"),
    (re.compile(r"api[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9_-]{16,}"),    "api key literal"),
    (re.compile(r"xoxb-[A-Za-z0-9-]{20,}"),                          "Slack bot token"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"),                             "GitHub PAT"),
]

_STACK_TRACE_HINTS = (
    "Traceback (most recent call last)", "at java.", "at org.springframework",
    "Exception in thread", "Stack trace:", "fatal error:", "Symfony\\Component",
    "<b>Fatal error</b>", "PHP Notice", "PHP Warning", "ActionController::",
    "System.NullReferenceException", "System.Web.HttpException",
)
_DEBUG_PAGE_HINTS = (
    "Whoops, looks like something went wrong", "Werkzeug Debugger", "Django at",
    "Phusion Passenger", "DEBUG = True", "Symfony Profiler", "Web Console enabled",
    "<title>Action Controller: Exception caught</title>",
)
_LOGIN_HINTS = re.compile(r"type=[\"']?password[\"']?|name=[\"']?password[\"']?|<form[^>]*\\baction=[\"'][^\"']*login", re.I)
_OAUTH_PATHS = ("/oauth", "/sso", "/saml", "/openid", "/.well-known/openid-configuration")
_FILE_UPLOAD = re.compile(r"<input[^>]*type=[\"']?file[\"']?", re.I)
_HIDDEN_INPUT = re.compile(r"<input[^>]*type=[\"']?hidden[\"']?", re.I)
_TEXT_INPUT = re.compile(r"<input[^>]*type=[\"']?(text|email|search|url)[\"']?", re.I)
_HTML_COMMENT = re.compile(r"<!--[\s\S]*?-->")
_RFC1918 = re.compile(r"\b(10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b")


@dataclass
class RoiBreakdown:
    base: int = 50
    score: int = 50
    notes: list[str] = field(default_factory=list)

    def add(self, points: int, why: str) -> None:
        self.score += points
        self.notes.append(f"{'+' if points >= 0 else ''}{points} {why}")


def calculate(*, status_code: int | None = None,
              body: str = "",
              headers: dict[str, str] | None = None,
              path: str = "",
              ssl_flags: dict[str, bool] | None = None) -> RoiBreakdown:
    """Compute a single url_fact's ROI score and return the breakdown.

    All inputs are optional. Headers dict keys are case-insensitive at the user's
    discretion; this function lower-cases them defensively.
    """
    b = RoiBreakdown()
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    body = body or ""

    # ---- status code -----
    if status_code is not None:
        if 200 <= status_code < 300:
            b.add(15, "2xx response")
        elif status_code in (401, 403):
            b.add(10, f"{status_code} auth-protected")
        elif 300 <= status_code < 400:
            b.add(5, f"{status_code} redirect")
        elif 500 <= status_code < 600:
            b.add(5, f"{status_code} server error (potential disclosure)")

    # ---- auth surface ----
    if _LOGIN_HINTS.search(body):
        b.add(25, "login form / password input")
    if any(p in path.lower() for p in _OAUTH_PATHS):
        b.add(10, "OAuth/SSO/SAML path")
    if "set-cookie" in headers:
        b.add(15, "Set-Cookie present")
        cookie_val = headers.get("set-cookie", "").lower()
        if "httponly" not in cookie_val:
            b.add(10, "missing HttpOnly")
        if "secure" not in cookie_val:
            b.add(5, "missing Secure")
        if "samesite" not in cookie_val:
            b.add(8, "missing SameSite")
    if "authorization" in headers and any(s in headers.get("authorization", "").lower() for s in ("bearer", "jwt")):
        b.add(15, "Bearer/JWT auth header")

    # ---- input opportunities ----
    forms = body.lower().count("<form")
    if forms:
        b.add(min(forms, 5) * 10, f"HTML forms ({forms})")
    if _FILE_UPLOAD.search(body):
        b.add(20, "file upload input")
    hidden_count = len(_HIDDEN_INPUT.findall(body))
    if hidden_count >= 2:
        b.add(8, f"{hidden_count} hidden inputs")
    if _TEXT_INPUT.search(body):
        b.add(5, "text input present")

    # ---- info disclosure ----
    if any(hint in body for hint in _STACK_TRACE_HINTS):
        b.add(15, "stack trace in response")
    if any(hint in body for hint in _DEBUG_PAGE_HINTS):
        b.add(15, "framework debug page")
    for pat, label in _SECRET_PATTERNS:
        if pat.search(body):
            b.add(20, f"secret leak: {label}")
            break  # one is enough; the breakdown shouldn't explode
    comments = _HTML_COMMENT.findall(body)
    if len(comments) >= 3:
        b.add(5, f"{len(comments)} HTML comments")
    if _RFC1918.search(body):
        b.add(10, "RFC1918 IP in body")

    # ---- TLS hygiene ----
    s = ssl_flags or {}
    for k in ("has_expired_ssl", "has_mismatched_ssl", "has_revoked_ssl", "has_self_signed_ssl"):
        if s.get(k):
            b.add(3, f"SSL flag {k}")
    if s.get("has_untrusted_root_ssl"):
        b.add(5, "untrusted root SSL")

    return b


def calculate_from_dict(d: dict[str, Any]) -> RoiBreakdown:
    """Convenience: accept an httpx-style record dict."""
    return calculate(
        status_code=d.get("status_code") or d.get("status-code"),
        body=d.get("body") or d.get("response") or "",
        headers=d.get("headers") or d.get("response_headers") or {},
        path=d.get("path") or d.get("url") or "",
        ssl_flags=d.get("ssl_flags") or {},
    )
