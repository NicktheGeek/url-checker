"""
Runs every checker in checkers.ALL_CHECKS concurrently against one URL and
rolls the results up into a single verdict.
"""
import concurrent.futures
import time

from dotenv import load_dotenv

load_dotenv()  # populate os.environ from .env before checkers.py reads it

from checkers import ALL_CHECKS  # noqa: E402  (must come after load_dotenv)

STATUS_ORDER = {"flagged": 0, "unknown": 1, "error": 2, "clean": 3, "skipped": 4}


def check_url(url: str, timeout_per_check: float = 30.0) -> dict:
    """Run every check in parallel and return an aggregate report."""
    started = time.time()
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ALL_CHECKS)) as pool:
        future_to_check = {pool.submit(fn, url): fn for fn in ALL_CHECKS}
        for future in concurrent.futures.as_completed(future_to_check, timeout=timeout_per_check + 5):
            fn = future_to_check[future]
            try:
                results.append(future.result(timeout=timeout_per_check))
            except Exception as exc:  # noqa: BLE001 - a single bad checker must never sink the run
                results.append(
                    {
                        "service": getattr(fn, "__name__", "unknown check"),
                        "status": "error",
                        "summary": f"Checker crashed: {exc}",
                    }
                )

    results.sort(key=lambda r: STATUS_ORDER.get(r["status"], 9))

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
