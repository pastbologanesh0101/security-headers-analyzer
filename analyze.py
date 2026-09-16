#!/usr/bin/env python3
"""
Security Headers Analyzer
==========================

A small CLI tool that fetches a URL's HTTP response headers and grades
them against a security best-practices checklist (similar in spirit to
securityheaders.com).

Usage:
    python analyze.py https://example.com

The core grading logic lives in the pure function `grade_headers(headers)`,
which takes an already-fetched dict of response headers and returns a
`Report`. This makes the grading logic trivially unit-testable without any
network access. `fetch_headers()` is a thin wrapper that performs the real
HTTP request and is not covered by unit tests.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class Status(Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


# Points awarded per status, used to compute the overall score.
_STATUS_POINTS = {
    Status.PASS: 1.0,
    Status.WARN: 0.5,
    Status.FAIL: 0.0,
}


@dataclass
class HeaderResult:
    name: str
    status: Status
    message: str
    remediation: str = ""


@dataclass
class Report:
    results: list = field(default_factory=list)  # list[HeaderResult]
    score: float = 0.0          # 0-100
    grade: str = "F"

    def add(self, result: HeaderResult) -> None:
        self.results.append(result)

    def summary_lines(self) -> list:
        lines = []
        for r in self.results:
            lines.append(f"[{r.status}] {r.name}: {r.message}")
            if r.remediation and r.status != Status.PASS:
                lines.append(f"    -> {r.remediation}")
        return lines


# ---------------------------------------------------------------------------
# Checklist configuration
# ---------------------------------------------------------------------------

# Each checker is a function taking (normalized_headers, is_https) and
# returning a HeaderResult. normalized_headers keys are lowercase.

def _get(headers: dict, name: str) -> Optional[str]:
    """Case-insensitive header lookup."""
    return headers.get(name.lower())


def _check_csp(headers: dict, is_https: bool) -> HeaderResult:
    value = _get(headers, "content-security-policy")
    name = "Content-Security-Policy"
    remediation = (
        "Set a Content-Security-Policy that restricts script/style sources, "
        "e.g. \"default-src 'self'\"."
    )
    if not value:
        return HeaderResult(
            name, Status.FAIL,
            "Header is missing. The browser has no restriction on where "
            "scripts/styles/frames can load from.",
            remediation,
        )
    lowered = value.lower()
    risky_tokens = ["unsafe-inline", "unsafe-eval", "*"]
    found_risky = [t for t in risky_tokens if t in lowered]
    if found_risky:
        return HeaderResult(
            name, Status.WARN,
            f"Present but contains overly permissive directive(s): "
            f"{', '.join(found_risky)}.",
            "Avoid 'unsafe-inline', 'unsafe-eval', and wildcard '*' sources; "
            "use nonces/hashes and explicit source lists instead.",
        )
    return HeaderResult(name, Status.PASS, "Present and does not contain obviously risky directives.")


def _check_hsts(headers: dict, is_https: bool) -> HeaderResult:
    value = _get(headers, "strict-transport-security")
    name = "Strict-Transport-Security"
    remediation = (
        "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
        "(and consider 'preload') on all HTTPS responses."
    )
    if not is_https:
        if value:
            return HeaderResult(name, Status.PASS, "Present (informational on a non-HTTPS check).")
        return HeaderResult(
            name, Status.WARN,
            "Not applicable/observed over a non-HTTPS connection.",
            "Serve the site over HTTPS and set HSTS.",
        )
    if not value:
        return HeaderResult(
            name, Status.FAIL,
            "Missing on an HTTPS response. Browsers may still allow "
            "downgrade to HTTP on first visit or after cache expiry.",
            remediation,
        )
    lowered = value.lower()
    try:
        max_age = int(lowered.split("max-age=")[1].split(";")[0].strip())
    except (IndexError, ValueError):
        max_age = 0
    if max_age < 15552000:  # 180 days
        return HeaderResult(
            name, Status.WARN,
            f"Present but max-age is low or unparsable ({value!r}).",
            "Use a max-age of at least 15552000 (180 days), ideally 31536000 (1 year).",
        )
    return HeaderResult(name, Status.PASS, f"Present with adequate max-age ({value}).")


def _check_x_content_type_options(headers: dict, is_https: bool) -> HeaderResult:
    value = _get(headers, "x-content-type-options")
    name = "X-Content-Type-Options"
    remediation = "Set 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing."
    if not value:
        return HeaderResult(name, Status.FAIL, "Header is missing.", remediation)
    if value.lower().strip() != "nosniff":
        return HeaderResult(
            name, Status.WARN,
            f"Present but value is not exactly 'nosniff' (got {value!r}).",
            remediation,
        )
    return HeaderResult(name, Status.PASS, "Present with value 'nosniff'.")


def _check_x_frame_options(headers: dict, is_https: bool) -> HeaderResult:
    value = _get(headers, "x-frame-options")
    name = "X-Frame-Options"
    remediation = (
        "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' (or rely on CSP "
        "'frame-ancestors') to prevent clickjacking."
    )
    csp = _get(headers, "content-security-policy") or ""
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if not value:
        if has_frame_ancestors:
            return HeaderResult(
                name, Status.PASS,
                "Header missing but CSP 'frame-ancestors' directive provides equivalent protection.",
            )
        return HeaderResult(name, Status.FAIL, "Header is missing.", remediation)
    if value.lower().strip() not in ("deny", "sameorigin"):
        return HeaderResult(
            name, Status.WARN,
            f"Present but value is unusual (got {value!r}).",
            remediation,
        )
    return HeaderResult(name, Status.PASS, f"Present with value {value!r}.")


def _check_referrer_policy(headers: dict, is_https: bool) -> HeaderResult:
    value = _get(headers, "referrer-policy")
    name = "Referrer-Policy"
    remediation = (
        "Set 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter) "
        "to limit referrer leakage."
    )
    if not value:
        return HeaderResult(name, Status.FAIL, "Header is missing.", remediation)
    risky_values = ("unsafe-url",)
    if value.lower().strip() in risky_values:
        return HeaderResult(
            name, Status.WARN,
            f"Present but set to a permissive value ({value!r}) that leaks full URLs cross-origin.",
            remediation,
        )
    return HeaderResult(name, Status.PASS, f"Present with value {value!r}.")


def _check_permissions_policy(headers: dict, is_https: bool) -> HeaderResult:
    value = _get(headers, "permissions-policy")
    name = "Permissions-Policy"
    remediation = (
        "Set a 'Permissions-Policy' (e.g. \"geolocation=(), camera=(), microphone=()\") "
        "to disable powerful browser features you don't use."
    )
    if not value:
        return HeaderResult(
            name, Status.WARN,
            "Header is missing. Browser features (camera, geolocation, etc.) are not explicitly restricted.",
            remediation,
        )
    return HeaderResult(name, Status.PASS, "Present.")


# Ordered list of checkers that make up the checklist.
_CHECKERS = [
    _check_csp,
    _check_hsts,
    _check_x_content_type_options,
    _check_x_frame_options,
    _check_referrer_policy,
    _check_permissions_policy,
]


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _score_to_grade(score: float) -> str:
    """Map a 0-100 score to a letter grade. Thresholds are inclusive lower bounds."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def grade_headers(headers: dict, is_https: bool = True) -> Report:
    """Pure function: grade a dict of HTTP response headers.

    Parameters
    ----------
    headers:
        A mapping of header name -> value, as returned by an HTTP client.
        Header names are matched case-insensitively, matching real HTTP
        semantics (header names are case-insensitive per RFC 7230).
    is_https:
        Whether the response was (or would be) served over HTTPS. This
        affects how the Strict-Transport-Security check is scored, since
        HSTS is only meaningful over HTTPS.

    Returns
    -------
    Report
        A `Report` containing one `HeaderResult` per checked header, plus
        an overall 0-100 `score` and letter `grade`.
    """
    if headers is None:
        headers = {}

    # Normalize keys to lowercase for case-insensitive lookups, while
    # tolerating duplicate keys that differ only by case (last one wins,
    # consistent with how most HTTP client libraries merge headers).
    normalized = {str(k).lower(): v for k, v in headers.items()}

    report = Report()
    for checker in _CHECKERS:
        report.add(checker(normalized, is_https))

    total_points = sum(_STATUS_POINTS[r.status] for r in report.results)
    max_points = len(report.results)
    score = (total_points / max_points * 100) if max_points else 0.0

    report.score = round(score, 1)
    report.grade = _score_to_grade(report.score)
    return report


# ---------------------------------------------------------------------------
# Network fetch (thin wrapper, not unit tested)
# ---------------------------------------------------------------------------

def fetch_headers(url: str, timeout: float = 10.0) -> dict:
    """Fetch `url` and return its response headers as a plain dict.

    Tries to use `requests` if it is installed, falling back to the
    standard library `urllib` otherwise, so the tool works even without
    third-party dependencies installed.
    """
    try:
        import requests  # type: ignore

        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        return dict(resp.headers)
    except ImportError:
        import urllib.request

        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "security-headers-analyzer/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - user-supplied URL is the point of the tool
            return dict(resp.headers.items())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_report(url: str, report: Report) -> None:
    print(f"Security Headers Report for: {url}")
    print("=" * 60)
    for line in report.summary_lines():
        print(line)
    print("=" * 60)
    print(f"Score: {report.score}/100   Grade: {report.grade}")


def main(argv: Optional[list] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print("Usage: python analyze.py <url>", file=sys.stderr)
        return 2

    url = argv[0]
    is_https = url.lower().startswith("https://")

    try:
        headers = fetch_headers(url)
    except Exception as exc:  # noqa: BLE001 - top-level CLI error handling
        print(f"Error fetching {url}: {exc}", file=sys.stderr)
        return 1

    report = grade_headers(headers, is_https=is_https)
    _print_report(url, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
