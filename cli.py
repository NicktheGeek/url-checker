#!/usr/bin/env python3
"""
Command-line URL checker.

Usage:
    python cli.py https://fedex@dalsisxgm.shop/query
"""
import sys

from aggregator import check_url

STATUS_LABEL = {
    "flagged": "FLAGGED",
    "clean": "clean",
    "unknown": "unknown",
    "skipped": "skipped (no key)",
    "error": "error",
}


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <url>")
        sys.exit(1)

    url = sys.argv[1].strip()
    if url and not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url
    print(f"Checking: {url}\n")
    report = check_url(url)

    name_width = max(len(r["service"]) for r in report["results"]) + 2
    for r in report["results"]:
        label = STATUS_LABEL.get(r["status"], r["status"])
        line = f"  {r['service']:<{name_width}} [{label:<16}] {r['summary']}"
        print(line)
        if r.get("link"):
            print(f"  {'':<{name_width}}   -> {r['link']}")

    print()
    print(f"Verdict: {report['verdict']}  --  {report['verdict_summary']}")
    print(
        f"({report['sources_checked']} source(s) checked, "
        f"{report['sources_skipped']} skipped for missing API keys, "
        f"{report['elapsed_seconds']}s)"
    )


if __name__ == "__main__":
    main()
