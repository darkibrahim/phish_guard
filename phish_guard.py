#!/usr/bin/env python3
"""
PHISH-GUARD - Phishing URL Checker

Analyzes a URL using offline heuristics (no external services required) and
reports a risk score with the reasons behind it.

IMPORTANT: This is a heuristic helper, not a guarantee. A low score does not
mean a URL is safe, and a high score does not prove it is malicious. Always
use your own judgement, and never enter passwords or personal data on a site
you are not sure about.

Copyright (c) 2026 DARK IBRAHIM. Released under the MIT License (see LICENSE).
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shutil
import sys
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlsplit

__author__ = "DARK IBRAHIM"
__version__ = "1.0.0"
__license__ = "MIT"

EXAMPLES = """\
examples:
  phish_guard.py https://paypal-login.verify-account.com
  phish_guard.py example.com --raw
  phish_guard.py -f urls.txt
  echo "http://192.168.1.1/login" | phish_guard.py --raw
"""

EXIT_OK, EXIT_ERROR, EXIT_INTERRUPTED = 0, 1, 130

# ==========================================================
#  THEME (shared look & feel with the rest of the toolkit)
# ==========================================================
GREEN, CYAN, PINK = 46, 51, 201
RED, ORANGE, YELLOW, WHITE, GRAY = 196, 208, 226, 255, 244
WIDTH = 66

ANSI_RE = re.compile(r"\033\[[0-9;]*m")
USE_COLOR = False


def init_color(force_off: bool = False) -> None:
    global USE_COLOR
    USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ and not force_off
    if USE_COLOR and os.name == "nt":
        os.system("")


def paint(text: str, color: int | None = None, bold: bool = False) -> str:
    if not USE_COLOR:
        return text
    codes = "\033[1m" if bold else ""
    if color is not None:
        codes += f"\033[38;5;{color}m"
    return f"{codes}{text}\033[0m"


def visible_len(text: str) -> int:
    return len(ANSI_RE.sub("", text))


def term_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


def is_compact() -> bool:
    return term_width() < WIDTH + 2


# ==========================================================
#  BANNER
# ==========================================================
class Brand:
    NAME = __author__
    TITLE = "Cyber Security Expert"
    TAGLINE = "Phishing URL Checker"
    VERSION = __version__
    LICENSE = __license__


FONT = {
    "P": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔═══╝ ", "██║     ", "╚═╝     "],
    "H": ["██╗  ██╗", "██║  ██║", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    "I": ["██╗", "██║", "██║", "██║", "██║", "╚═╝"],
    "S": [" ██████╗", "██╔════╝", "╚█████╗ ", " ╚═══██╗", "██████╔╝", "╚═════╝ "],
    "G": [" ██████╗ ", "██╔════╝ ", "██║  ███╗", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "U": ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    "R": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
    "D": ["██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "],
    "-": ["   ", "   ", "███", "   ", "   ", "   "],
}


def render_word(word: str) -> list[str]:
    return ["".join(FONT[ch][i] for ch in word) for i in range(6)]


def box_row(content: str = "", center: bool = False) -> str:
    pad = WIDTH - visible_len(content)
    left = pad // 2 if center else 1
    right = max(pad - left, 0)
    edge = paint("│", CYAN)
    return f"{edge}{' ' * left}{content}{' ' * right}{edge}"


def banner() -> None:
    if is_compact():
        rule = paint("─" * max(10, min(term_width() - 4, 38)), GRAY)
        print(f"  {paint('◆ PHISH-GUARD ◆', GREEN, bold=True)}")
        print(f"  {paint(Brand.TAGLINE, CYAN)}")
        print(f"  {paint('v' + Brand.VERSION + ' · ' + Brand.LICENSE, GRAY)}")
        print(f"  {rule}\n")
        return

    print(paint("╭" + "─" * WIDTH + "╮", CYAN))
    print(box_row())
    gradient = [196, 208, 226, 46, 51, 201]
    for word in ("PHISH", "GUARD"):
        for i, line in enumerate(render_word(word)):
            print(box_row(paint(line, gradient[i], bold=True), center=True))
        print(box_row())
    print(box_row(paint(Brand.TAGLINE.upper(), CYAN, bold=True), center=True))
    print(box_row(paint("─ ◆ ─", GRAY), center=True))
    print(paint("├" + "─" * WIDTH + "┤", CYAN))
    info = [
        ("AUTHOR", Brand.NAME, GREEN),
        ("ROLE", Brand.TITLE, GREEN),
        ("VERSION", "v" + Brand.VERSION, CYAN),
        ("LICENSE", Brand.LICENSE, CYAN),
    ]
    for key, value, color in info:
        label = paint(f"{key:<8}", GRAY)
        line = f"{paint('◈', PINK)} {label} {paint(':', GRAY)} {paint(value, color, bold=True)}"
        print(box_row(line))
    print(paint("╰" + "─" * WIDTH + "╯", CYAN))
    print()


def success(message: str) -> None:
    print(f"  {paint('✔', GREEN, bold=True)} {paint(message, WHITE)}")


def error(message: str) -> None:
    print(f"\n  {paint('✖', RED, bold=True)} {paint(message, RED, bold=True)}\n", file=sys.stderr)


# ==========================================================
#  HEURISTIC ENGINE
# ==========================================================
class ToolError(Exception):
    """A user-facing error."""


@dataclass
class Finding:
    points: int
    reason: str


@dataclass
class Report:
    url: str
    host: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return max(0, min(100, sum(f.points for f in self.findings)))

    @property
    def level(self) -> str:
        if self.score >= 60:
            return "HIGH RISK"
        if self.score >= 30:
            return "SUSPICIOUS"
        return "LOW RISK"


# Shorteners are not malicious by themselves, but they hide the real
# destination, which is exactly what a phishing link needs.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "lnkd.in",
}

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "secure", "update", "confirm", "signin",
    "password", "billing", "suspend", "unlock", "support", "security",
    "wallet", "recover", "validate",
]

# A short list of widely-impersonated brands, used only to flag a brand
# name combined with a different, unrelated domain (typosquatting signal).
WATCHED_BRANDS = [
    "paypal", "google", "facebook", "apple", "microsoft", "amazon",
    "netflix", "instagram", "whatsapp", "bankofamerica", "chase",
    "wellsfargo", "binance", "coinbase",
]

HIGH_RISK_TLDS = {
    "zip", "mov", "xyz", "top", "work", "click", "gq", "tk", "ml", "cf", "ga",
}


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def has_mixed_scripts(text: str) -> bool:
    """Detect a mix of Latin + non-Latin letters, a classic homograph trick."""
    scripts = set()
    for ch in text:
        if ch.isalpha():
            try:
                name = unicodedata.name(ch)
            except ValueError:
                continue
            scripts.add(name.split()[0])
    non_latin = scripts - {"LATIN", "DIGIT"}
    return "LATIN" in scripts and bool(non_latin)


def registrable_parts(host: str) -> tuple[str, str]:
    """Split "a.b.example.co.uk"-like hosts into (subdomains, core domain).

    This is a simplified heuristic (no public-suffix list), good enough to
    flag unusual subdomain depth and brand-in-subdomain tricks.
    """
    labels = host.split(".")
    if len(labels) <= 2:
        return "", host
    return ".".join(labels[:-2]), ".".join(labels[-2:])


def analyze(raw_url: str) -> Report:
    url = raw_url.strip()
    if not url:
        raise ToolError("Empty URL.")
    if "://" not in url:
        url = "http://" + url  # allow "example.com" style input

    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise ToolError(f"Could not parse URL: {exc}") from exc

    host = (parts.hostname or "").lower()
    if not host:
        raise ToolError("No host found in that URL.")

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_host = host

    report = Report(url=url, host=host)
    add = report.findings.append
    subdomains, core_domain = registrable_parts(host)

    # --- structural red flags -------------------------------------------------
    if is_ip_address(host):
        add(Finding(25, "The address uses a raw IP instead of a domain name"))

    if parts.scheme == "http":
        add(Finding(10, "Connection is not encrypted (plain http://, no TLS)"))

    if "@" in parts.netloc:
        add(Finding(30, "Contains an '@' in the address — browsers ignore everything before it"))

    if len(url) > 90:
        add(Finding(10, "Unusually long URL, often used to hide the real destination"))

    label_count = len(host.split("."))
    if label_count >= 5:
        add(Finding(20, f"Very deep subdomain structure ({label_count} parts: {host})"))
    elif label_count == 4:
        add(Finding(10, f"Many subdomains ({host})"))

    if host.count("-") >= 3:
        add(Finding(10, "Many hyphens in the domain, a common disguise tactic"))

    tld = core_domain.rsplit(".", 1)[-1] if "." in core_domain else ""
    if tld in HIGH_RISK_TLDS:
        add(Finding(10, f"Uses a top-level domain often abused for abuse/spam (.{tld})"))

    # --- homograph / punycode --------------------------------------------------
    # Two independent signals: the user may type a domain that already
    # contains literal "xn--" labels, or type real Unicode look-alike
    # letters (which idna-encoding above would convert to "xn--" labels).
    if "xn--" in host:
        add(Finding(30, "Domain uses Punycode (xn--), a classic look-alike-character trick"))
    elif has_mixed_scripts(host):
        add(Finding(25, "Domain mixes alphabets (e.g. Latin + Cyrillic look-alike letters)"))
    elif ascii_host != host and "xn--" in ascii_host:
        add(Finding(25, "Domain contains look-alike Unicode characters (converts to Punycode)"))

    # --- shorteners --------------------------------------------------------------
    if core_domain in URL_SHORTENERS or host in URL_SHORTENERS:
        add(Finding(15, "Uses a URL shortener, which hides the real destination"))

    # --- suspicious keywords ------------------------------------------------------
    full_lower = url.lower()
    hit_words = sorted({w for w in SUSPICIOUS_WORDS if w in full_lower})
    if hit_words:
        shown = ", ".join(hit_words[:4])
        add(Finding(min(20, 5 * len(hit_words)), f"Contains phishing-style keywords ({shown})"))

    # --- brand impersonation -------------------------------------------------------
    core_name = core_domain.split(".")[0] if core_domain else ""
    for brand in WATCHED_BRANDS:
        brand_in_sub = brand in subdomains
        brand_in_full = brand in full_lower
        if brand_in_full and brand != core_name:
            if brand_in_sub:
                add(Finding(30, f"Brand name '{brand}' appears as a fake subdomain, not the real domain"))
            else:
                add(Finding(20, f"Mentions brand '{brand}' but the actual domain is '{core_domain or host}'"))
            break  # one brand hit is enough signal; avoid double counting

    if not report.findings:
        add(Finding(0, "No common phishing red flags detected by these heuristics"))

    return report


# ==========================================================
#  OUTPUT
# ==========================================================
def level_color(level: str) -> int:
    return {"LOW RISK": GREEN, "SUSPICIOUS": YELLOW, "HIGH RISK": RED}[level]


def print_report(report: Report, quiet: bool) -> None:
    if quiet:
        print(f"{report.level}\t{report.score}\t{report.url}")
        return

    color = level_color(report.level)
    print()
    print(paint(f"  ╭─── RESULT " + "─" * (WIDTH - 15), CYAN))
    print(paint("  │ ", CYAN) + paint(report.url, WHITE))
    print(paint("  │ ", CYAN) + paint(f"{report.level}", color, bold=True) + paint(f"  (score {report.score}/100)", GRAY))
    print(paint("  ├" + "─" * (WIDTH - 4), CYAN))
    for f in report.findings:
        marker = paint("•", color if f.points else GRAY)
        pts = paint(f"+{f.points:<3}", GRAY) if f.points else paint("    ", GRAY)
        print(paint("  │ ", CYAN) + f"{marker} {pts} {f.reason}")
    print(paint("  ╰" + "─" * (WIDTH - 4), CYAN))
    print()


def print_summary(reports: list[Report]) -> None:
    counts = {"LOW RISK": 0, "SUSPICIOUS": 0, "HIGH RISK": 0}
    for r in reports:
        counts[r.level] += 1
    print(paint("  ── SUMMARY " + "─" * (WIDTH - 15), GRAY))
    for level, n in counts.items():
        print(f"    {paint(level, level_color(level), bold=True):<28} {n}")
    print()


# ==========================================================
#  CLI
# ==========================================================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phish_guard",
        description="Offline heuristic phishing-URL checker.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", nargs="?", help="the URL to check")
    parser.add_argument("-f", "--file", metavar="PATH", help="check one URL per line from a file")
    parser.add_argument("--raw", action="store_true", help="print 'LEVEL<TAB>SCORE<TAB>URL' only")
    parser.add_argument("--no-banner", action="store_true", help="hide the banner")
    parser.add_argument("--no-color", action="store_true", help="disable colors")
    parser.add_argument("--fail-on-risk", action="store_true",
                        help="exit with status 2 if any checked URL is SUSPICIOUS or HIGH RISK")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def collect_urls(args: argparse.Namespace) -> list[str]:
    if args.file:
        path = args.file
        if not os.path.isfile(path):
            raise ToolError(f"File not found: {path}")
        with open(path, encoding="utf-8") as fh:
            urls = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        if not urls:
            raise ToolError(f"No URLs found in '{path}'.")
        return urls
    if args.url:
        return [args.url]
    if not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]
        if urls:
            return urls
    raise ToolError("No URL given. Provide a URL, use -f FILE, or pipe URLs in.")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = sys.argv[1:] if argv is None else argv

    if not argv:
        init_color()
        banner()
        parser.print_help()
        return EXIT_OK

    args = parser.parse_args(argv)
    init_color(force_off=args.no_color or args.raw)

    try:
        urls = collect_urls(args)
    except ToolError as exc:
        error(str(exc))
        return EXIT_ERROR

    if not args.raw and not args.no_banner:
        banner()

    reports: list[Report] = []
    had_error = False
    for raw in urls:
        try:
            report = analyze(raw)
        except ToolError as exc:
            if args.raw:
                print(f"ERROR\t-\t{raw}\t{exc}")
            else:
                error(f"{raw}: {exc}")
            had_error = True
            continue
        reports.append(report)
        print_report(report, args.raw)

    if not args.raw and len(reports) > 1:
        print_summary(reports)

    if had_error:
        return EXIT_ERROR
    if args.fail_on_risk and any(r.level != "LOW RISK" for r in reports):
        return 2
    return EXIT_OK


def _use_utf8_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass


if __name__ == "__main__":
    _use_utf8_streams()
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n  Interrupted by user.", file=sys.stderr)
        sys.exit(EXIT_INTERRUPTED)
    except BrokenPipeError:
        sys.exit(EXIT_OK)
