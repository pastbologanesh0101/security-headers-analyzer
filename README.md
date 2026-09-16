# Security Headers Analyzer

A small command-line tool that fetches a URL's HTTP response headers and
grades them against a security best-practices checklist — the same idea
as [securityheaders.com](https://securityheaders.com), but as a local,
scriptable CLI.

## What it checks

For each response, the analyzer checks the following headers and assigns
each one a `PASS`, `WARN`, or `FAIL` status with a short explanation and a
remediation suggestion:

| Header | What's checked |
|---|---|
| `Content-Security-Policy` | Present, and doesn't contain overly permissive directives like `unsafe-inline`, `unsafe-eval`, or a wildcard `*` source. |
| `Strict-Transport-Security` | Present on HTTPS responses with a `max-age` of at least 180 days (ideally 1 year). Missing HSTS on an `https://` URL is a hard fail. |
| `X-Content-Type-Options` | Present and set exactly to `nosniff`, to stop browsers from MIME-sniffing responses. |
| `X-Frame-Options` | Present and set to `DENY` or `SAMEORIGIN` to prevent clickjacking (a CSP `frame-ancestors` directive is accepted as an equivalent). |
| `Referrer-Policy` | Present and not set to the overly leaky `unsafe-url`. |
| `Permissions-Policy` | Present, to explicitly restrict powerful browser features (camera, geolocation, microphone, etc.). Missing is a `WARN`, not a hard fail. |

### Scoring

Each header contributes points: `PASS` = 1, `WARN` = 0.5, `FAIL` = 0,
averaged across all six checks and scaled to 0–100. That score maps to a
letter grade:

| Score | Grade |
|---|---|
| 90–100 | A |
| 75–89 | B |
| 60–74 | C |
| 40–59 | D |
| 0–39 | F |

## Installation

```bash
git clone https://github.com/pastbologanesh0101/security-headers-analyzer.git
cd security-headers-analyzer
pip install -r requirements.txt
```

`requests` is optional — if it isn't installed, the tool falls back to the
Python standard library's `urllib` for the actual HTTP fetch.

## Usage

```bash
python analyze.py https://example.com
```

This fetches the URL's response headers over the network and prints a
report to stdout.

## Example output

Given a hypothetical response with a weak configuration:

```
headers = {
    "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "unsafe-url",
}
```

Running that through `grade_headers(headers, is_https=True)` (missing
`Strict-Transport-Security`, `X-Frame-Options`, and `Permissions-Policy`)
produces a report like:

```
Security Headers Report for: https://example-weak-site.test
============================================================
[WARN] Content-Security-Policy: Present but contains overly permissive directive(s): unsafe-inline.
    -> Avoid 'unsafe-inline', 'unsafe-eval', and wildcard '*' sources; use nonces/hashes and explicit source lists instead.
[FAIL] Strict-Transport-Security: Missing on an HTTPS response. Browsers may still allow downgrade to HTTP on first visit or after cache expiry.
    -> Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains' (and consider 'preload') on all HTTPS responses.
[PASS] X-Content-Type-Options: Present with value 'nosniff'.
[FAIL] X-Frame-Options: Header is missing.
    -> Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' (or rely on CSP 'frame-ancestors') to prevent clickjacking.
[WARN] Referrer-Policy: Present but set to a permissive value ('unsafe-url') that leaks full URLs cross-origin.
    -> Set 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter) to limit referrer leakage.
[WARN] Permissions-Policy: Header is missing. Browser features (camera, geolocation, etc.) are not explicitly restricted.
    -> Set a 'Permissions-Policy' (e.g. "geolocation=(), camera=(), microphone=()") to disable powerful browser features you don't use.
============================================================
Score: 41.7/100   Grade: D
```

A fully-hardened response (valid CSP, HSTS with a long `max-age`, `nosniff`,
`X-Frame-Options: DENY`, a strict `Referrer-Policy`, and a `Permissions-Policy`)
scores 100/100 and grades out at `A`.

## Design: pure grading function + thin network wrapper

All of the actual grading logic lives in a pure function:

```python
from analyze import grade_headers

report = grade_headers({"X-Content-Type-Options": "nosniff", ...}, is_https=True)
print(report.score, report.grade)
for result in report.results:
    print(result.name, result.status, result.message)
```

`grade_headers()` takes a plain `dict` of headers (already fetched, from
anywhere) and returns a `Report`. It does no I/O, so it's fully
deterministic and safe to unit test without a network connection.

`fetch_headers(url)` is a thin wrapper around `grade_headers()` that
performs the actual HTTP GET request (via `requests` if available, else
`urllib`) and hands the resulting headers to `grade_headers()`. Only
`grade_headers()` is covered by the automated test suite — see
[`tests/test_analyze.py`](tests/test_analyze.py).

## Running the tests

```bash
python -m unittest discover -s tests -v
```

or, if you prefer pytest:

```bash
pytest tests/
```

These tests only exercise the pure `grade_headers()` function and require
no network access, which is also how they run in CI
(`.github/workflows/tests.yml`, on Python 3.11 and 3.12).

## License

MIT — see [LICENSE](LICENSE).
