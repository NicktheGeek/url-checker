"""
Runs every checker in checkers.ALL_CHECKS concurrently against one URL and
rolls the results up into a single verdict.
"""
import concurrent.futures
import time

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

from checkers import ALL_CHECKS  # noqa: E402  (must come after load_dotenv)

STATUS_ORDER = {"flagged": 0, "unknown": 1, "error": 2, "clean": 3, "skipped": 4}


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


def _build_report(url: str, results: list, started: float) -> dict:
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

    return {
        "url": url,
        "verdict": verdict,
        "verdict_summary": verdict_summary,
        "results": results,
        "sources_checked": len(checked),
        "sources_skipped": len(skipped),
        "elapsed_seconds": round(time.time() - started, 2),
    }


def check_url(url: str, timeout_per_check: float = 30.0) -> dict:
    """Run every check in parallel and return an aggregate report."""
    started = time.time()
    results = list(_run_checks(url, timeout_per_check))
    return _build_report(url, results, started)


def check_url_streaming(url: str, timeout_per_check: float = 30.0):
    """Like check_url, but yields progress as it happens.

    Yields ("result", result_dict) for each source as it finishes, in
    whatever order they complete, then finally yields ("done", report_dict)
    with the same shape check_url() returns.
    """
    started = time.time()
    results = []
    for result in _run_checks(url, timeout_per_check):
        results.append(result)
        yield ("result", result)
    yield ("done", _build_report(url, results, started))
