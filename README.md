# PHISH-GUARD · Phishing URL Checker

A fast, dependency-free command-line tool that scores a URL for common **phishing red flags**, using offline heuristics — no external service or internet connection required.

> **This is a helper, not a verdict.** A low score does not guarantee a URL is safe, and a high score does not prove it is malicious. Always use your own judgement, and never enter passwords or personal data on a site you're unsure about.

## Author

**DARK IBRAHIM** — Cyber Security Expert

## What it checks

| Signal | Why it matters |
| --- | --- |
| Raw IP address instead of a domain | Real services rarely link to a bare IP |
| Plain `http://` (no TLS) | No encryption between you and the site |
| `@` in the address | Browsers ignore everything before `@`, a classic disguise |
| Very long URL | Used to bury or hide the real destination |
| Deep / unusual subdomains | e.g. `paypal.com.verify-login.xyz` |
| Many hyphens in the domain | Common in generated look-alike domains |
| Risky top-level domains | `.xyz`, `.top`, `.click`, etc. often abused for throwaway sites |
| Punycode / mixed-alphabet domains | Look-alike letters from another script (e.g. Cyrillic "а" instead of Latin "a") |
| URL shorteners | Hide the real destination behind `bit.ly`, `tinyurl.com`, etc. |
| Phishing-style keywords | `login`, `verify`, `secure`, `confirm`, `suspend`, ... |
| Brand name in the wrong place | e.g. `paypal` used as a subdomain of an unrelated domain |

Each signal adds points to a 0–100 score:

- **0–29** → `LOW RISK`
- **30–59** → `SUSPICIOUS`
- **60–100** → `HIGH RISK`

## Requirements

- Python 3.8 or newer. No third-party packages.

## Quick start

```bash
python3 phish_guard.py "https://paypal-login.verify-account.com"
python3 phish_guard.py example.com --raw
```

**Android (Termux):**

```bash
pkg install python
python phish_guard.py "https://example.com"
```

## Usage

| Option | Description |
| --- | --- |
| `url` | The URL to check (can be bare, e.g. `example.com`) |
| `-f PATH` | Check one URL per line from a file (`#` lines are comments) |
| `--raw` | Print `LEVEL<TAB>SCORE<TAB>URL` only (script friendly) |
| `--fail-on-risk` | Exit with status `2` if any URL is `SUSPICIOUS` or `HIGH RISK` |
| `--no-banner` | Hide the banner |
| `--no-color` | Disable colors |
| `-V`, `--version` | Show the version |
| `-h`, `--help` | Show help |

## Examples

```bash
# Check a single URL
python3 phish_guard.py "https://secure-paypal-verify.top/login"

# Check a list of URLs from a file
python3 phish_guard.py -f urls.txt

# Use in a pipeline / script, fail the script if anything looks risky
echo "http://192.168.1.1/login" | python3 phish_guard.py --raw --fail-on-risk
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Checked successfully (no risky URL, or `--fail-on-risk` not set) |
| `1` | Error (bad input, missing file, ...) |
| `2` | At least one URL was flagged, only when `--fail-on-risk` is set |
| `130` | Interrupted by the user (Ctrl+C) |

## How it works

`phish_guard.py` parses the URL, inspects its structure and text with a set of independent heuristic rules (see the table above), and adds up the points each rule contributes. There is no network request and no external blocklist — everything runs locally and instantly.

## Limitations

- This tool does **not** check live blocklists, SSL certificate details, or page content — it only looks at the URL's structure and text.
- The brand list and keyword list are small examples, not exhaustive.
- A clean score is a signal, not a guarantee. When in doubt, don't enter sensitive information, and check the site through a trusted bookmark or search engine instead of a link.

## Running the tests

```bash
python3 -m unittest -v
```

## License

Released under the [MIT License](LICENSE).
