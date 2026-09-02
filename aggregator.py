"""
Runs every checker in checkers.ALL_CHECKS concurrently against one URL and
rolls the results up into a single verdict.

Before any of that: _resolve_redirects follows the URL's redirect chain to
find what it actually points at. An email/wrapper link (Outlook Safelinks,
a URL shortener, click-tracking, ...) checked as submitted would only ever
tell you the wrapper's own domain is fine -- every checker in ALL_CHECKS
runs against the *final* URL that resolves to, not the one the user pasted
in.
"""
import concurrent.futures
import time
import urllib.parse

import requests
from dotenv import load_dotenv

from env_store import ENV_PATH

# Explicit path, not dotenv's own upward-search default: that default walks
# up from this file's own location, which only happens to match ENV_PATH
# for an unfrozen/dev run (both are the repo root). Frozen into a packaged
# app, this file lives inside the bundle while ENV_PATH is a separate
# per-user data directory -- dotenv's default search would never find it,
# silently leaving os.environ empty even though the file itself (and the
# Settings tab, which reads it directly) is correct.
load_dotenv(ENV_PATH)  # populate os.environ from .env before checkers.py reads it

from checkers import ALL_CHECKS, TIMEOUT  # noqa: E402  (must come after load_dotenv)

STATUS_ORDER = {"flagged": 0, "unknown": 1, "error": 2, "clean": 3, "skipped": 4}

REDIRECT_SERVICE = "Redirect Chain"


def _resolve_redirects(url: str) -> dict:
    """Follow url's redirect chain and report what it actually points at.

    Not folded into checkers.py: every function there is a peer, dispatched
    in parallel against the same URL by _run_checks. This one is different
    on purpose -- it has to run *before* the others and its result changes
    what URL they check, so aggregator.py owns it directly instead of
    pretending it's just one more uniform source.

    A redirect on its own isn't suspicious -- most newsletter/email links
    go through one -- so this reports "unknown" (a yellow flag: distinct
    from the actual threat-intel sources, worth a second look) rather than
    "flagged" (red, actively bad). It's excluded from _build_report's
    flagged-count either way, so a redirect alone never flips the verdict
    to SUSPICIOUS by itself.
    """
    session = requests.Session()
    session.max_redirects = 10  # a real chain is rarely more than a few hops;
    # bounds worst-case latency and doubles as its own signal something's off
    try:
        resp = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            stream=True,  # only need .url/.history, never the final body
            headers={"User-Agent": "Mozilla/5.0 (compatible; url-checker/1.0)"},
        )
        resp.close()
    except requests.RequestException as exc:
        return {
            "service": REDIRECT_SERVICE,
            "status": "error",
            "summary": f"Could not follow redirects: {exc}",
            "final_url": url,
        }

    hops = [r.url for r in resp.history]
    final_url = resp.url
    if not hops:
        return {
            "service": REDIRECT_SERVICE,
            "status": "clean",
            "summary": "No redirects -- this is already the final URL",
            "final_url": final_url,
        }

    chain = hops + [final_url]
    hosts = [urllib.parse.urlparse(h).hostname or h for h in chain]
    return {
        "service": REDIRECT_SERVICE,
        "status": "unknown",
        "summary": (
            f"Redirected {len(hops)} time(s) before reaching the final destination -- "
            "not necessarily suspicious, but the checks below ran against the real "
            "target, not the link you pasted: " + " -> ".join(hosts)
        ),
        "detail": {"chain": chain},
        "final_url": final_url,
    }


def _run_checks(url: str, timeout_per_check: float = 30.0):
    """Generator: yields each check's result dict as soon as it completes.

    Every source runs in its own thread so a slow one (VirusTotal, urlscan.io
    polling an unseen URL) never blocks the fast ones from showing up first.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ALL_CHECKS)) as pool:
        future_to_check = {pool.submit(fn, url): fn for fn in ALL_CHECKS}
        for future in concurrent.futures.as_completed(future_to_check, timeout=timeout_per_check + 5):
            fn = future_to_check[future]
            try:
                yield future.result(timeout=timeout_per_check)
            except Exception as exc:  # noqa: BLE001 - a single bad checker must never sink the run
                yield {
                    "service": getattr(fn, "__name__", "unknown check"),
                    "status": "error",
                    "summary": f"Checker crashed: {exc}",
                }


def _build_report(url: str, results: list, started: float, checked_url: str | None = None) -> dict:
    results = sorted(results, key=lambda r: STATUS_ORDER.get(r["status"], 9))

    flagged = [r for r in results if r["status"] == "flagged"]
    checked = [r for r in results if r["status"] not in ("skipped",)]
    skipped = [r for r in results if r["status"] == "skipped"]

    if flagged:
        verdict = "SUSPICIOUS"
        verdict_summary = f"{len(flagged)} of {len(checked)} active source(s) flagged this URL"
    elif not checked:
        verdict = "NO DATA"
        verdict_summary = "No API keys configured yet -- add keys to .env to get real results"
    else:
        verdict = "NO ISSUES FOUND"
        verdict_summary = f"{len(checked)} active source(s) checked, none flagged it"

    report = {
        "url": url,
        "verdict": verdict,
        "verdict_summary": verdict_summary,
        "results": results,
        "sources_checked": len(checked),
        "sources_skipped": len(skipped),
        "elapsed_seconds": round(time.time() - started, 2),
    }
    if checked_url and checked_url != url:
        # Only present when redirects actually moved us somewhere else --
        # callers that don't know about this field are unaffected.
        report["checked_url"] = checked_url
    return report


def check_url(url: str, timeout_per_check: float = 30.0) -> dict:
    """Resolve redirects, then run every check in parallel against the
    final URL and return an aggregate report."""
    started = time.time()
    redirect_result = _resolve_redirects(url)
    effective_url = redirect_result["final_url"]
    results = [redirect_result] + list(_run_checks(effective_url, timeout_per_check))
    return _build_report(url, results, started, checked_url=effective_url)


def check_url_streaming(url: str, timeout_per_check: float = 30.0):
    """Like check_url, but yields progress as it happens.

    Yields ("result", result_dict) for each source as it finishes -- the
    redirect-chain result first, since every other source depends on it --
    then finally yields ("done", report_dict) with the same shape
    check_url() returns.
    """
    started = time.time()
    redirect_result = _resolve_redirects(url)
    effective_url = redirect_result["final_url"]
    results = [redirect_result]
    yield ("result", redirect_result)
    for result in _run_checks(effective_url, timeout_per_check):
        results.append(result)
        yield ("result", result)
    yield ("done", _build_report(url, results, started, checked_url=effective_url))
