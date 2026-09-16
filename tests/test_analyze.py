"""
Unit tests for the pure `grade_headers()` function in analyze.py.

These tests do not touch the network at all -- they construct header
dicts by hand and check the resulting Report. This is what the CI
workflow (.github/workflows/tests.yml) runs.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyze import grade_headers, Status  # noqa: E402


GOOD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=()",
}


class GradeHeadersTests(unittest.TestCase):
    def test_all_good_headers_score_highly(self):
        report = grade_headers(GOOD_HEADERS, is_https=True)
        self.assertGreaterEqual(report.score, 90)
        self.assertEqual(report.grade, "A")
        self.assertTrue(all(r.status == Status.PASS for r in report.results))

    def test_all_missing_headers_score_poorly_with_correct_failures(self):
        report = grade_headers({}, is_https=True)
        self.assertLess(report.score, 40)
        self.assertEqual(report.grade, "F")

        failed_names = {r.name for r in report.results if r.status == Status.FAIL}
        # CSP, HSTS (missing on https), X-Content-Type-Options, X-Frame-Options,
        # and Referrer-Policy should all be reported as FAIL when absent.
        expected_fails = {
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
        }
        self.assertTrue(expected_fails.issubset(failed_names))

        # Permissions-Policy is treated as a softer WARN, not a hard FAIL,
        # when missing.
        permissions_result = next(r for r in report.results if r.name == "Permissions-Policy")
        self.assertEqual(permissions_result.status, Status.WARN)

    def test_weak_csp_with_unsafe_inline_is_warned_not_passed(self):
        headers = dict(GOOD_HEADERS)
        headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-inline'"
        report = grade_headers(headers, is_https=True)
        csp_result = next(r for r in report.results if r.name == "Content-Security-Policy")
        self.assertEqual(csp_result.status, Status.WARN)
        self.assertNotEqual(csp_result.status, Status.PASS)

    def test_wildcard_csp_is_warned(self):
        headers = dict(GOOD_HEADERS)
        headers["Content-Security-Policy"] = "default-src *"
        report = grade_headers(headers, is_https=True)
        csp_result = next(r for r in report.results if r.name == "Content-Security-Policy")
        self.assertEqual(csp_result.status, Status.WARN)

    def test_hsts_missing_on_https_is_flagged_fail(self):
        headers = dict(GOOD_HEADERS)
        del headers["Strict-Transport-Security"]
        report = grade_headers(headers, is_https=True)
        hsts_result = next(r for r in report.results if r.name == "Strict-Transport-Security")
        self.assertEqual(hsts_result.status, Status.FAIL)

    def test_hsts_missing_on_non_https_is_warn_not_fail(self):
        headers = dict(GOOD_HEADERS)
        del headers["Strict-Transport-Security"]
        report = grade_headers(headers, is_https=False)
        hsts_result = next(r for r in report.results if r.name == "Strict-Transport-Security")
        # Over plain HTTP, HSTS absence shouldn't be scored as a hard FAIL
        # the same way it would be over HTTPS.
        self.assertNotEqual(hsts_result.status, Status.FAIL)

    def test_case_insensitive_header_matching(self):
        lower_case_headers = {k.lower(): v for k, v in GOOD_HEADERS.items()}
        report_lower = grade_headers(lower_case_headers, is_https=True)

        mixed_case_headers = {
            "content-SECURITY-policy": GOOD_HEADERS["Content-Security-Policy"],
            "STRICT-Transport-security": GOOD_HEADERS["Strict-Transport-Security"],
            "x-Content-Type-OPTIONS": GOOD_HEADERS["X-Content-Type-Options"],
            "X-FRAME-options": GOOD_HEADERS["X-Frame-Options"],
            "referrer-POLICY": GOOD_HEADERS["Referrer-Policy"],
            "Permissions-policy": GOOD_HEADERS["Permissions-Policy"],
        }
        report_mixed = grade_headers(mixed_case_headers, is_https=True)

        self.assertEqual(report_lower.score, report_mixed.score)
        self.assertEqual(report_lower.grade, report_mixed.grade)
        self.assertEqual(report_mixed.grade, "A")

    def test_unknown_extra_headers_do_not_break_scoring(self):
        headers = dict(GOOD_HEADERS)
        headers["X-Powered-By"] = "PHP/8.2"
        headers["Some-Totally-Made-Up-Header"] = "banana"
        report = grade_headers(headers, is_https=True)
        self.assertEqual(report.grade, "A")
        # Extra headers should not appear as their own checked results.
        names = {r.name for r in report.results}
        self.assertNotIn("X-Powered-By", names)
        self.assertNotIn("Some-Totally-Made-Up-Header", names)

    def test_grade_thresholds_are_correctly_ordered(self):
        from analyze import _score_to_grade

        self.assertEqual(_score_to_grade(100), "A")
        self.assertEqual(_score_to_grade(90), "A")
        self.assertEqual(_score_to_grade(89.9), "B")
        self.assertEqual(_score_to_grade(75), "B")
        self.assertEqual(_score_to_grade(74.9), "C")
        self.assertEqual(_score_to_grade(60), "C")
        self.assertEqual(_score_to_grade(59.9), "D")
        self.assertEqual(_score_to_grade(40), "D")
        self.assertEqual(_score_to_grade(39.9), "F")
        self.assertEqual(_score_to_grade(0), "F")

    def test_none_headers_does_not_raise(self):
        report = grade_headers(None, is_https=True)
        self.assertEqual(report.grade, "F")

    def test_x_frame_options_missing_but_csp_frame_ancestors_present_passes(self):
        headers = dict(GOOD_HEADERS)
        del headers["X-Frame-Options"]
        headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        report = grade_headers(headers, is_https=True)
        xfo_result = next(r for r in report.results if r.name == "X-Frame-Options")
        self.assertEqual(xfo_result.status, Status.PASS)


if __name__ == "__main__":
    unittest.main()
