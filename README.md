# URL Checker

Checks a URL against several threat-intelligence sources at once (instead of
pasting it into 3+ separate websites), plus a couple of local heuristics
(userinfo tricks like `https://fedex@evil.com`, punycode domains, etc.) that
need no API key at all.

## Setup

```bash
cd url_checker
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Rename `sample.env` to `.env`. Open `.env` and paste in whichever API keys you already have. Leave the rest
blank for now -- those sources will just show as "skipped", not break
anything. See the comments in `.env` for where to get each key.

## Run it

**Command line:**
```bash
python cli.py "https://fedex@dalsisxgm.shop/query"
```

**Web UI:**
```bash
python app.py
```
then open http://127.0.0.1:5000 in your browser.

## Sources checked

| Source | Needs a key? | Notes |
|---|---|---|
| Local heuristics | No | Userinfo trick, punycode, http vs https, excessive subdomains |
| Google Safe Browsing | Yes | Same list Chrome itself uses |
| VirusTotal | Yes | 70+ engine consensus; free tier is 4 req/min, 500/day |
| urlscan.io | Yes | Actually visits the URL in a sandbox -- best for brand-new domains |
| IPQualityScore | Yes | Heuristic risk scoring (domain age, typosquatting, etc.) |
| URLhaus | No (optional key raises rate limit) | Malware distribution URLs |
| ThreatFox | No (optional key raises rate limit) | Malware/C2 indicators |
| PhishTank | Yes | Community-reported phishing |

## Adding a source later

Add a new `check_x(url)` function to `checkers.py` following the same
pattern (return a dict with `service`/`status`/`summary`, use `_skipped()` if
the key isn't set), then add it to the `ALL_CHECKS` list at the bottom of
that file. The aggregator and both UIs pick it up automatically.

## Notes

- `.env` is in `.gitignore` -- never commit it. If a key ever leaks, rotate
  it at the provider rather than trying to "un-commit" it.
- Some checks (VirusTotal, urlscan.io) submit unseen URLs for scanning and
  poll briefly for a verdict -- a first check on a brand-new URL can take a
  few extra seconds, or come back "unknown" with a link if the scan wasn't
  done yet.
