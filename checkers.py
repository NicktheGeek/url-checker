"""
One function per threat-intelligence source. Every function has the same shape:

    check_x(url: str) -> dict

Return dict always has these keys:
    service   - human readable name
    status    - one of: "flagged", "clean", "unknown", "skipped", "error"
    summary   - short human readable message
    link      - (optional) a URL the user can click to see the full report
    detail    - (optional) raw/extra info, dict or str

"skipped" means the API key for that service isn't set in .env yet -- this
is expected and not a bug. "error" means the key IS set but the call failed
(network issue, bad key, rate limit, unexpected response shape, etc).

Nothing here raises. Every network call is wrapped so one flaky/misconfigured
source can never take down the whole check.
"""
import base64
import hashlib
import os
import time
import urllib.parse

import requests

TIMEOUT = 10  # seconds, per HTTP call


def _skipped(service, env_var):
    return {
        "service": service,
        "status": "skipped",
        "summary": f"No API key set ({env_var} is empty in .env)",
    }


def _error(service, exc):
    return {
        "service": service,
        "status": "error",
        "summary": f"Request failed: {exc}",
    }


# ---------------------------------------------------------------------------
# 1. Google Safe Browsing (v4 Lookup API)
# ---------------------------------------------------------------------------
def check_safe_browsing(url: str) -> dict:
    service = "Google Safe Browsing"
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return _skipped(service, "GOOGLE_SAFE_BROWSING_API_KEY")

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    body = {
        "client": {"clientId": "url-checker-personal", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=body, timeout=TIMEOUT)
        if resp.status_code != 200:
            return {
                "service": service,
                "status": "error",
                "summary": f"HTTP {resp.status_code}: {resp.text[:200]}",
            }
        data = resp.json()
        matches = data.get("matches", [])
        if matches:
            threats = ", ".join(sorted({m.get("threatType", "?") for m in matches}))
            return {
                "service": service,
                "status": "flagged",
                "summary": f"Flagged: {threats}",
                "detail": matches,
            }
        return {"service": service, "status": "clean", "summary": "No match in Safe Browsing lists"}
    except requests.RequestException as exc:
        return _error(service, exc)


# ---------------------------------------------------------------------------
# 2. VirusTotal (API v3)
# ---------------------------------------------------------------------------
def check_virustotal(url: str) -> dict:
    service = "VirusTotal"
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return _skipped(service, "VIRUSTOTAL_API_KEY")

    headers = {"x-apikey": api_key}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    try:
        # First: has anyone already scanned this exact URL?
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            return _vt_format(service, resp.json())

        if resp.status_code != 404:
            return {
                "service": service,
                "status": "error",
                "summary": f"HTTP {resp.status_code}: {resp.text[:200]}",
            }

        # Not seen before -- submit it, then poll briefly for a result.
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=TIMEOUT,
        )
        if submit.status_code not in (200, 201):
            return {
                "service": service,
                "status": "error",
                "summary": f"Submit failed, HTTP {submit.status_code}: {submit.text[:200]}",
            }
        analysis_id = submit.json()["data"]["id"]

        for _ in range(3):  # ~9 seconds of polling, worst case
            time.sleep(3)
            poll = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=TIMEOUT,
            )
            if poll.status_code != 200:
                continue
            attrs = poll.json().get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                stats = attrs.get("stats", {})
                return _vt_format_from_stats(service, stats, url)

        return {
            "service": service,
            "status": "unknown",
            "summary": "Newly submitted, scan still queued -- check back in a minute",
            "link": f"https://www.virustotal.com/gui/url/{url_id}",
        }
    except requests.RequestException as exc:
        return _error(service, exc)


def _vt_format(service, payload):
    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    url_id = payload.get("data", {}).get("id", "")
    return _vt_format_from_stats(service, stats, None, url_id=url_id)


def _vt_format_from_stats(service, stats, url, url_id=None):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    link = f"https://www.virustotal.com/gui/url/{url_id}" if url_id else None
    if malicious or suspicious:
        return {
            "service": service,
            "status": "flagged",
            "summary": f"{malicious} engine(s) flagged malicious, {suspicious} suspicious",
            "detail": stats,
            "link": link,
        }
    return {
        "service": service,
        "status": "clean",
        "summary": "No engines flagged this URL",
        "detail": stats,
        "link": link,
    }


# ---------------------------------------------------------------------------
# 3. urlscan.io
# ---------------------------------------------------------------------------
def check_urlscan(url: str) -> dict:
    service = "urlscan.io"
    api_key = os.environ.get("URLSCAN_API_KEY", "").strip()
    if not api_key:
        return _skipped(service, "URLSCAN_API_KEY")

    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    try:
        submit = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": url, "visibility": "unlisted"},
            timeout=TIMEOUT,
        )
        if submit.status_code not in (200, 201):
            return {
                "service": service,
                "status": "error",
                "summary": f"Submit failed, HTTP {submit.status_code}: {submit.text[:200]}",
            }
        data = submit.json()
        result_url = data.get("api")
        ui_url = data.get("result")

        # Scans usually take 10-40s to finish. Poll briefly; if it's not
        # done yet, hand back the link so the user can check shortly.
        for _ in range(4):
            time.sleep(5)
            poll = requests.get(result_url, timeout=TIMEOUT)
            if poll.status_code == 200:
                verdicts = poll.json().get("verdicts", {}).get("overall", {})
                score = verdicts.get("score", 0)
                malicious = verdicts.get("malicious", False)
                if malicious or score > 0:
                    return {
                        "service": service,
                        "status": "flagged",
                        "summary": f"Malicious verdict (score {score})",
                        "link": ui_url,
                    }
                return {
                    "service": service,
                    "status": "clean",
                    "summary": "No malicious verdict",
                    "link": ui_url,
                }

        return {
            "service": service,
            "status": "unknown",
            "summary": "Scan submitted, still processing -- view live at the link",
            "link": ui_url,
        }
    except requests.RequestException as exc:
        return _error(service, exc)


# ---------------------------------------------------------------------------
# 4. IPQualityScore
# ---------------------------------------------------------------------------
def check_ipqs(url: str) -> dict:
    service = "IPQualityScore"
    api_key = os.environ.get("IPQS_API_KEY", "").strip()
    if not api_key:
        return _skipped(service, "IPQS_API_KEY")

    encoded = urllib.parse.quote(url, safe="")
    endpoint = f"https://ipqualityscore.com/api/json/url/{api_key}/{encoded}"
    try:
        resp = requests.get(endpoint, timeout=TIMEOUT)
        if resp.status_code != 200:
            return {
                "service": service,
                "status": "error",
                "summary": f"HTTP {resp.status_code}: {resp.text[:200]}",
            }
        data = resp.json()
        if not data.get("success", False):
            return {
                "service": service,
                "status": "error",
                "summary": data.get("message", "Unknown API error"),
            }
        risk_score = data.get("risk_score", 0)
        flags = [k for k in ("phishing", "malware", "suspicious", "spamming") if data.get(k)]
        if flags or risk_score >= 75:
            return {
                "service": service,
                "status": "flagged",
                "summary": f"Risk score {risk_score}/100; flags: {', '.join(flags) or 'high risk score'}",
                "detail": data,
            }
        return {
            "service": service,
            "status": "clean",
            "summary": f"Risk score {risk_score}/100",
            "detail": data,
        }
    except requests.RequestException as exc:
        return _error(service, exc)


# ---------------------------------------------------------------------------
# 5. URLhaus (abuse.ch) -- no key required, but an Auth-Key raises rate limits
# ---------------------------------------------------------------------------
def check_urlhaus(url: str) -> dict:
    service = "URLhaus"
    headers = {}
    auth_key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    if auth_key:
        headers["Auth-Key"] = auth_key
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers=headers,
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return {
                "service": service,
                "status": "error",
                "summary": f"HTTP {resp.status_code}: {resp.text[:200]}",
            }
        data = resp.json()
        if data.get("query_status") == "no_results":
            return {"service": service, "status": "clean", "summary": "Not found in URLhaus"}
        if data.get("query_status") == "ok":
            return {
                "service": service,
                "status": "flagged",
                "summary": f"Listed as malware distribution ({data.get('url_status', 'unknown status')})",
                "link": data.get("urlhaus_reference"),
                "detail": data,
            }
        return {
            "service": service,
            "status": "unknown",
            "summary": f"Unexpected response: {data.get('query_status')}",
        }
    except requests.RequestException as exc:
        return _error(service, exc)


# ---------------------------------------------------------------------------
# 6. ThreatFox (abuse.ch) -- no key required for community search
# ---------------------------------------------------------------------------
def check_threatfox(url: str) -> dict:
    service = "ThreatFox"
    domain = urllib.parse.urlparse(url).hostname or url
    headers = {}
    auth_key = os.environ.get("THREATFOX_AUTH_KEY", "").strip()
    if auth_key:
        headers["Auth-Key"] = auth_key
    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": domain},
            headers=headers,
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return {
                "service": service,
                "status": "error",
                "summary": f"HTTP {resp.status_code}: {resp.text[:200]}",
            }
        data = resp.json()
        if data.get("query_status") == "no_result":
            return {"service": service, "status": "clean", "summary": "Not found in ThreatFox"}
        if data.get("query_status") == "ok":
            iocs = data.get("data", [])
            threats = ", ".join(sorted({i.get("threat_type", "?") for i in iocs})) or "listed IOC"
            return {
                "service": service,
                "status": "flagged",
                "summary": f"Domain associated with: {threats}",
                "detail": iocs,
            }
        return {
            "service": service,
            "status": "unknown",
            "summary": f"Unexpected response: {data.get('query_status')}",
        }
    except requests.RequestException as exc:
        return _error(service, exc)


# ---------------------------------------------------------------------------
# 7. PhishTank
# ---------------------------------------------------------------------------
def check_phishtank(url: str) -> dict:
    service = "PhishTank"
    api_key = os.environ.get("PHISHTANK_API_KEY", "").strip()
    if not api_key:
        return _skipped(service, "PHISHTANK_API_KEY")

    try:
        resp = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={
                "url": url,
                "format": "json",
                "app_key": api_key,
            },
            headers={"User-Agent": "phishtank/url-checker"},
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return {
                "service": service,
                "status": "error",
                "summary": f"HTTP {resp.status_code}: {resp.text[:200]}",
            }
        data = resp.json().get("results", {})
        if data.get("in_database") and data.get("valid"):
            return {
                "service": service,
                "status": "flagged",
                "summary": "Confirmed phishing URL in PhishTank database",
                "link": data.get("phish_detail_page"),
                "detail": data,
            }
        if data.get("in_database"):
            return {
                "service": service,
                "status": "unknown",
                "summary": "In database but not yet verified",
                "link": data.get("phish_detail_page"),
            }
        return {"service": service, "status": "clean", "summary": "Not found in PhishTank database"}
    except (requests.RequestException, ValueError) as exc:
        return _error(service, exc)


# ---------------------------------------------------------------------------
# 8. Zero-key heuristics -- always run, no API key needed
# ---------------------------------------------------------------------------
def check_heuristics(url: str) -> dict:
    service = "Heuristics (local)"
    parsed = urllib.parse.urlparse(url)
    flags = []

    # Userinfo trick: https://fedex@evil.com looks like it's going to fedex
    # but the browser just treats "fedex" as a (discarded) username.
    if "@" in (parsed.netloc or ""):
        fake_part, _, real_host = parsed.netloc.rpartition("@")
        flags.append(
            f"URL contains an '@' before the real host -- '{fake_part}' is decoration, "
            f"the actual destination is '{real_host}'"
        )

    host = parsed.hostname or ""
    if "xn--" in host:
        flags.append(f"Punycode/IDN domain ('{host}') -- can render as lookalike characters")

    if host.count(".") >= 4:
        flags.append(f"Unusually many subdomain levels ({host})")

    if parsed.scheme == "http":
        flags.append("Not using HTTPS")

    if flags:
        return {
            "service": service,
            "status": "flagged",
            "summary": "; ".join(flags),
        }
    return {"service": service, "status": "clean", "summary": "No obvious structural red flags"}


# Registry the aggregator iterates over.
ALL_CHECKS = [
    check_heuristics,
    check_safe_browsing,
    check_virustotal,
    check_urlscan,
    check_ipqs,
    check_urlhaus,
    check_threatfox,
    check_phishtank,
]
