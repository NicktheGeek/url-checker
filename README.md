# URL Checker

Checks a URL against several threat-intelligence sources at once (instead of
pasting it into 3+ separate websites), plus a couple of local heuristics
(userinfo tricks like `https://fedex@evil.com`, punycode domains, etc.) that
need no API key at all.

## Quick start (recommended)

You need Python 3 installed (nothing else -- no manual `pip`/`venv` commands).

- **Mac:** double-click `start.command`. First time you do this, Finder may
  refuse to run it ("cannot be opened because it is from an unidentified
  developer") -- right-click it, choose **Open**, then confirm once. After
  that, double-clicking just works.
- **Windows:** double-click `start.bat`.
- **Any OS from a terminal:** `python3 start.py`

The first run creates a private `.venv` and installs dependencies into it
automatically (this takes a few seconds); every run after that just starts
the server straight away and opens your browser to it. It also copies
`sample.env` to `.env` for you if you don't have one yet -- add API keys
afterwards from the app's **Settings** tab (no hand-editing `.env` required,
though you still can).

The terminal window it opens prints two addresses:

```
On this computer:      http://127.0.0.1:5050
On your phone/tablet:  http://192.168.x.x:5050   (same WiFi network)
```

Open the second address on a phone or tablet connected to the same WiFi,
then use the browser's **Add to Home Screen** (iOS Safari) or **Install
app** (Android/desktop Chrome, Edge) option. This installs a real app icon
that opens in its own window, no browser bar -- the page ships a PWA
manifest and service worker for exactly this. Desktop browsers can install
it the same way by visiting either address.

Leave the terminal window open while you're using it on other devices --
closing it stops the server. Press Ctrl+C in it (or just close the window)
to stop.

> **Heads up:** because the server now listens on your whole WiFi network
> (not just this computer), anyone else on that network can reach it too --
> including the **Settings** page, which shows your API keys in plain text
> with no login. Fine for a trusted home network; don't run it this way on
> a shared/public WiFi (coffee shop, office guest network, etc.) unless you
> add some form of access control first.

## Manual setup (alternative)

If you'd rather manage the virtualenv yourself:

```bash
cd url_checker
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Rename `sample.env` to `.env`. Open `.env` and paste in whichever API keys you already have. Leave the rest
blank for now -- those sources will just show as "skipped", not break
anything. See the comments in `.env` for where to get each key.

A bare domain (no `http://`/`https://`) is assumed to be `https://` -- type
the scheme explicitly if you actually want to check the plain-`http://`
version of a site.

**Command line:**
```bash
python cli.py "https://fedex@dalsisxgm.shop/query"
```

**Web UI:**
```bash
python app.py
```
then open http://127.0.0.1:5050 in your browser -- or, from another device
on the same WiFi, `http://<this computer's LAN IP>:5050`. (Port 5000 is
skipped because macOS's AirPlay Receiver claims it by default -- if you've
disabled that in System Settings, feel free to change the port back in
`app.py`.)

Flask's debug mode (auto-reload + the interactive Werkzeug traceback/code
console) is off by default -- a bad request that trips an unhandled
exception would otherwise hand back a live Python console. Turn it on for
active development with:
```bash
FLASK_DEBUG=1 python app.py
```

## Web UI features

- **Check** -- single-URL check. Results stream in via Server-Sent Events as
  each source finishes, so fast sources (heuristics, Safe Browsing) show up
  immediately instead of waiting on slow ones (VirusTotal, urlscan.io can
  take 20-30s on a URL they haven't seen before).
- **Batch** -- paste a list of URLs (one per line) and check them all in one
  go; each URL's own sources still run in parallel, results stream in per-URL.
- **History** -- every finished check (single or batch) is saved to a local
  `history.db` SQLite file. Browse past checks, expand one to see the full
  per-source breakdown, or delete entries you don't want kept.
- **Export** -- any saved report can be downloaded as CSV from its history
  entry (`/history/<id>/export.csv`).
- Dark mode (follows your system setting, or toggle manually -- the ☽/☀
  button in the top right) and a responsive layout for narrow windows.
- **Installable as an app** -- on a phone, tablet, or desktop browser, "Add
  to Home Screen" / "Install app" gives it a real icon and its own window
  (no address bar), backed by a PWA manifest + service worker.

`history.db` is gitignored, same as `.env` -- it's local-only and never
meant to be committed.

## Native desktop app (optional)

Want a real app instead of a browser tab -- its own window, no address bar,
a Dock (Mac) / taskbar (Windows) icon you launch without touching a
Terminal? Build one:

- **Mac:** `./build_mac_app.sh`
- **Windows:** `build_windows_app.bat` (written and documented, but not
  tested on Windows -- this project was built on macOS; needs the
  [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/),
  which almost every current Windows 10/11 machine already has)

**Mac:** this creates `dist/URL Checker.app`. Double-click it from Finder,
or drag it to `/Applications`. First launch may still get an "unidentified
developer" Gatekeeper prompt the same way `start.command` does -- right-click,
choose **Open**, confirm once.

**Windows:** this creates a `URL Checker.lnk` shortcut on your Desktop.
Double-click it to launch.

Either way, it's the *same* app underneath -- same `.env`, same `history.db`,
same LAN binding -- just wrapped in a native window instead of a browser tab.
A few things worth knowing:

- It shares one `history.db`/`.env` with `start.command`/`start.py`/
  `python app.py` -- nothing is duplicated or goes out of sync no matter
  which way you launch it.
- Don't run the desktop app and `start.command`/`python app.py` at the same
  time -- both bind port 5050, and whichever started second will fail to
  bind (you'll still see a window, but it'll be showing the other instance).
- Phone/tablet LAN access and "Add to Home Screen" still work exactly as
  before while the desktop app is running -- it's the same server.
- If it won't launch, check the log: `~/Library/Logs/URL Checker.log` (Mac)
  or `%LOCALAPPDATA%\URL Checker\log.txt` (Windows).
- If you move this project folder afterward, re-run the build script -- the
  app points at this specific folder's `.venv`, so it needs rebuilding after
  a move.

## Sources checked

| Source | Needs a key? | Notes |
|---|---|---|
| Local heuristics | No | Userinfo trick, punycode, http vs https, excessive subdomains |
| Spamhaus DBL | No | Free DNS-based domain blocklist (spam/phish/malware/botnet) |
| Google Safe Browsing | Yes | Same list Chrome itself uses |
| VirusTotal | Yes | 70+ engine consensus; free tier is 4 req/min, 500/day |
| urlscan.io | Yes | Actually visits the URL in a sandbox -- best for brand-new domains |
| IPQualityScore | Yes | Heuristic risk scoring (domain age, typosquatting, etc.) |
| URLhaus | Yes (shared abuse.ch key) | Malware distribution URLs |
| ThreatFox | Yes (shared abuse.ch key) | Malware/C2 indicators |
| PhishTank | Yes | Community-reported phishing |
| AbuseIPDB | Yes | Abuse reports for the URL's resolved IP, not the domain |
| AlienVault OTX | Yes | Domain checked against community threat pulses |
| MetaDefender Cloud | Yes | Multi-engine URL reputation (different engine set than VirusTotal) |
| CriminalIP | Yes | Domain risk report; free tier has a small shared daily scan quota |
| Cloudflare Radar URL Scanner | Yes | Sandbox scan, similar to urlscan.io; needs an API token (with the "URL Scanner: Edit" permission specifically) + account ID |

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
