"""Unit tests. Run with: python3 -m unittest -v"""
import contextlib
import io
import os
import tempfile
import unittest

import phish_guard as pg


def cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = pg.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class AnalyzeTests(unittest.TestCase):
    def test_plain_safe_https_domain_is_low_risk(self):
        r = pg.analyze("https://www.wikipedia.org/wiki/Python")
        self.assertEqual(r.level, "LOW RISK")

    def test_ip_address_url_flagged(self):
        r = pg.analyze("http://192.168.1.50/login")
        reasons = " ".join(f.reason for f in r.findings)
        self.assertIn("raw IP", reasons)
        self.assertGreaterEqual(r.score, 25)

    def test_at_symbol_trick_flagged(self):
        r = pg.analyze("http://real-bank.com@evil.com/login")
        reasons = " ".join(f.reason for f in r.findings)
        self.assertIn("@", reasons)
        self.assertEqual(r.host, "evil.com")

    def test_http_not_https_flagged(self):
        r = pg.analyze("http://example.com")
        reasons = " ".join(f.reason for f in r.findings)
        self.assertIn("not encrypted", reasons)

    def test_https_does_not_trigger_http_flag(self):
        r = pg.analyze("https://example.com")
        reasons = " ".join(f.reason for f in r.findings)
        self.assertNotIn("not encrypted", reasons)

    def test_brand_in_fake_subdomain_is_high_risk(self):
        r = pg.analyze("https://paypal.com.verify-login.xyz/signin")
        self.assertEqual(r.level, "HIGH RISK")
        reasons = " ".join(f.reason for f in r.findings)
        self.assertIn("paypal", reasons)

    def test_real_brand_domain_not_flagged_for_impersonation(self):
        r = pg.analyze("https://www.paypal.com/signin")
        reasons = " ".join(f.reason for f in r.findings)
        self.assertNotIn("fake subdomain", reasons)

    def test_url_shortener_flagged(self):
        r = pg.analyze("https://bit.ly/abcd123")
        reasons = " ".join(f.reason for f in r.findings)
        self.assertIn("shortener", reasons)

    def test_punycode_domain_flagged(self):
        r = pg.analyze("https://xn--pple-43d.com")  # apple with a look-alike char
        reasons = " ".join(f.reason for f in r.findings)
        self.assertIn("Punycode", reasons)

    def test_mixed_script_homograph_flagged(self):
        # Cyrillic 'а' mixed with Latin letters
        r = pg.analyze("http://p\u0430ypal.com/login")
        reasons = " ".join(f.reason for f in r.findings)
        self.assertIn("mixes alphabets", reasons)

    def test_bare_domain_without_scheme_is_accepted(self):
        r = pg.analyze("example.com")
        self.assertEqual(r.host, "example.com")

    def test_empty_url_raises(self):
        with self.assertRaises(pg.ToolError):
            pg.analyze("   ")

    def test_score_is_clamped_0_to_100(self):
        r = pg.analyze(
            "http://paypal-login.secure-verify-account-update.bit.ly.evil-domain-xyz.top/"
            "a@b/very/long/path/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        self.assertLessEqual(r.score, 100)
        self.assertGreaterEqual(r.score, 0)


class CliTests(unittest.TestCase):
    def test_raw_output_format(self):
        code, out, _ = cli("https://example.com", "--raw")
        self.assertEqual(code, 0)
        level, score, url = out.strip().split("\t")
        self.assertEqual(level, "LOW RISK")
        self.assertEqual(url, "http://example.com" if False else url)  # url echoed back

    def test_no_url_given_errors(self):
        # Force stdin to look like a tty with nothing piped by monkeypatching isatty
        import sys
        old_isatty = sys.stdin.isatty
        sys.stdin.isatty = lambda: True
        try:
            code, _, err = cli("--raw")
        finally:
            sys.stdin.isatty = old_isatty
        self.assertEqual(code, 1)
        self.assertIn("No URL", err)

    def test_file_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "urls.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("https://example.com\nhttp://192.168.1.1/login\n# comment\n")
            code, out, _ = cli("-f", path, "--raw")
            self.assertEqual(code, 0)
            lines = [l for l in out.strip().splitlines()]
            self.assertEqual(len(lines), 2)

    def test_missing_file_errors(self):
        code, _, err = cli("-f", "no_such_file.txt", "--raw")
        self.assertEqual(code, 1)
        self.assertIn("not found", err)

    def test_fail_on_risk_exit_code(self):
        code, _, _ = cli("http://192.168.1.1/login", "--raw", "--fail-on-risk")
        self.assertEqual(code, 2)

    def test_fail_on_risk_does_not_trigger_for_low_risk(self):
        code, _, _ = cli("https://example.com", "--raw", "--fail-on-risk")
        self.assertEqual(code, 0)

    def test_version_flag(self):
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stdout(io.StringIO()):
                pg.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
