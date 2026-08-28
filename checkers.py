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
import socket
import time
import urllib.parse

import requests

TIMEOUT = 10  # seconds, per HTTP call
SLOW_TIMEOUT = 30  # for sources whose single-request latency varies a lot by
# domain (AlienVault OTX computes some sections live and can take 15s+ on a
# domain it hasn't cached) -- matches aggregator.py's per-check budget


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
# 5. URLhaus (abuse.ch) -- abuse.ch now requires a free Auth-Key for every
#    request (get one at https://auth.abuse.ch/); it's no longer optional.
# ---------------------------------------------------------------------------
def check_urlhaus(url: str) -> dict:
    service = "URLhaus"
    auth_key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    if not auth_key:
        return _skipped(service, "URLHAUS_AUTH_KEY")
    headers = {"Auth-Key": auth_key}
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
# 6. ThreatFox (abuse.ch) -- abuse.ch now requires a free Auth-Key for every
#    request (get one at https://auth.abuse.ch/); it's no longer optional.
# ---------------------------------------------------------------------------
def check_threatfox(url: str) -> dict:
    service = "ThreatFox"
    domain = urllib.parse.urlparse(url).hostname or url
    auth_key = os.environ.get("THREATFOX_AUTH_KEY", "").strip()
    if not auth_key:
        return _skipped(service, "THREATFOX_AUTH_KEY")
    headers = {"Auth-Key": auth_key}
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
# 8. AbuseIPDB -- reputation for the URL's resolved IP, not the domain itself
# ---------------------------------------------------------------------------
def check_abuseipdb(url: str) -> dict:
    service = "AbuseIPDB"
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return _skipped(service, "ABUSEIPDB_API_KEY")

    host = urllib.parse.urlparse(url).hostname or ""
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        return {"service": service, "status": "error", "summary": f"Could not resolve host: {exc}"}

    headers = {"Key": api_key, "Accept": "application/json"}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return {
                "service": service,
                "status": "error",
                "summary": f"HTTP {resp.status_code}: {resp.text[:200]}",
            }
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        status = "flagged" if score >= 25 else "clean"
        return {
            "service": service,
            "status": status,
            "summary": f"IP {ip}: {score}% abuse confidence, {reports} report(s)",
            "link": f"https://www.abuseipdb.com/check/{ip}",
            "detail": data,
        }
    except requests.RequestException as exc:
        return _error(service, exc)


# ---------------------------------------------------------------------------
# 9. AlienVault OTX -- checks the domain against community threat pulses
# ---------------------------------------------------------------------------
def check_alienvault_otx(url: str) -> dict:
    service = "AlienVault OTX"
    api_key = os.environ.get("OTX_API_KEY", "").strip()
    if not api_key:
        return _skipped(service, "OTX_API_KEY")

    domain = urllib.parse.urlparse(url).hostname or url
    headers = {"X-OTX-API-KEY": api_key}
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers=headers,
            timeout=SLOW_TIMEOUT,
        )
        if resp.status_code != 200:
            return {
                "service": service,
                "status": "error",
                "summary": f"HTTP {resp.status_code}: {resp.text[:200]}",
            }
        data = resp.json()
        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        link = f"https://otx.alienvault.com/indicator/domain/{domain}"
        if pulse_count:
            names = [p.get("name", "?") for p in pulse_info.get("pulses", [])[:3]]
            return {
                "service": service,
                "status": "flagged",
                "summary": f"Referenced in {pulse_count} threat pulse(s): {', '.join(names)}",
                "link": link,
                "detail": pulse_info,
            }
        return {
            "service": service,
            "status": "clean",
            "summary": "No threat pulses reference this domain",
            "link": link,
        }
    except requests.RequestException as exc:
        return _error(service, exc)


# ---------------------------------------------------------------------------
# 10. MetaDefender Cloud (OPSWAT) -- multi-engine URL reputation. This is a
# plain synchronous GET, not a submit-then-poll flow like urlscan.io/VT --
# the URL goes URL-encoded straight into the path.
# ---------------------------------------------------------------------------
def check_metadefender(url: str) -> dict:
    service = "MetaDefender Cloud"
    api_key = os.environ.get("METADEFENDER_API_KEY", "").strip()
    if not api_key:
        return _skipped(service, "METADEFENDER_API_KEY")

    headers = {"apikey": api_key, "Content-Type": "application/json"}
    encoded = urllib.parse.quote(url, safe="")
    try:
        resp = requests.get(
            f"https://api.metadefender.com/v4/url/{encoded}",
            headers=headers,
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return {
                "service": service,
                "status": "error",
                "summary": f"HTTP {resp.status_code}: {resp.text[:200]}",
            }
        sources = resp.json().get("lookup_results", {}).get("sources", [])
        if not sources:
            return {"service": service, "status": "unknown", "summary": "No lookup results yet for this URL"}

        # status 0 = clean, 5 = unknown/not enough data, anything else = flagged
        flagged = [s for s in sources if s.get("status") not in (0, 5)]
        if flagged:
            names = ", ".join(sorted({s.get("provider", "?") for s in flagged}))
            return {
                "service": service,
                "status": "flagged",
                "summary": f"{len(flagged)}/{len(sources)} source(s) flagged: {names}",
                "detail": sources,
            }
        return {
            "service": service,
            "status": "clean",
            "summary": f"0/{len(sources)} source(s) flagged this URL",
            "detail": sources,
        }
    except requests.RequestException as exc:
        return _error(service, exc)


# ---------------------------------------------------------------------------
# 11. CriminalIP -- domain risk report, submit + poll.
#
# Two quirks confirmed against a live account:
#  - The scan-submit endpoint takes form-encoded params, not JSON (a JSON
#    body gets back a 200 with body {"status": 412, "message": "Missing
#    Parameter"} -- it doesn't 4xx at the HTTP layer).
#  - CriminalIP generally reports its real result via the JSON body's own
#    "status"/"message" fields, with the HTTP status staying 200 even for
#    errors (e.g. re-scanning a domain still being scanned) -- so the body
#    is authoritative, not just resp.status_code.
# The report's {"data": {"summary": {...}}} has counts/booleans, not one
# overall score -- see https://www.criminalip.io/en/mypage/information/api
# for the full field list if you want to weigh more of them.
# ---------------------------------------------------------------------------
def check_criminalip(url: str) -> dict:
    service = "CriminalIP"
    api_key = os.environ.get("CRIMINALIP_API_KEY", "").strip()
    if not api_key:
        return _skipped(service, "CRIMINALIP_API_KEY")

    domain = urllib.parse.urlparse(url).hostname or url
    headers = {"x-api-key": api_key}
    try:
        scan = requests.post(
            "https://api.criminalip.io/v1/domain/scan",
            headers=headers,
            data={"query": domain},
            timeout=TIMEOUT,
        )
        scan_body = scan.json() if scan.content else {}
        if scan.status_code != 200 or scan_body.get("status") != 200:
            return {
                "service": service,
                "status": "error",
                "summary": f"Scan submit failed: {scan_body.get('message', scan.text[:200])}",
            }
        scan_id = scan_body.get("data", {}).get("scan_id")
        if not scan_id:
            return {
                "service": service,
                "status": "error",
                "summary": f"No scan_id in submit response: {scan.text[:200]}",
            }
        link = f"https://www.criminalip.io/domain/report/{scan_id}"

        for _ in range(5):
            time.sleep(4)
            status_poll = requests.get(
                f"https://api.criminalip.io/v1/domain/status/{scan_id}",
                headers=headers,
                timeout=TIMEOUT,
            )
            status_body = status_poll.json() if status_poll.content else {}
            if status_poll.status_code != 200 or status_body.get("status") != 200:
                continue
            if status_body.get("data", {}).get("scan_percentage") != 100:
                continue

            report = requests.get(
                f"https://api.criminalip.io/v1/domain/report/{scan_id}",
                headers=headers,
                timeout=TIMEOUT,
            )
            report_body = report.json() if report.content else {}
            if report.status_code != 200 or report_body.get("status") != 200:
                return {
                    "service": service,
                    "status": "error",
                    "summary": f"Report fetch failed: {report_body.get('message', report.text[:200])}",
                }
            summary = report_body.get("data", {}).get("summary", {})
            abuse = summary.get("abuse_record", {})
            flags = []
            if abuse.get("critical") or abuse.get("dangerous"):
                flags.append(f"abuse reports ({abuse.get('critical', 0)} critical, {abuse.get('dangerous', 0)} dangerous)")
            if summary.get("phishing_record"):
                flags.append(f"{summary['phishing_record']} phishing record(s)")
            if summary.get("url_phishing_prob", 0) >= 0.5:
                flags.append(f"phishing probability {summary['url_phishing_prob']}")
            if summary.get("fake_domain"):
                flags.append("flagged as a fake/lookalike domain")
            if summary.get("mitm_attack"):
                flags.append("MITM attack indicator")
            return {
                "service": service,
                "status": "flagged" if flags else "clean",
                "summary": "; ".join(flags) if flags else "No risk indicators in CriminalIP's domain report",
                "link": link,
                "detail": summary,
            }

        return {
            "service": service,
            "status": "unknown",
            "summary": "Scan submitted, still processing -- check back shortly",
            "link": link,
        }
    except requests.RequestException as exc:
        return _error(service, exc)


# ---------------------------------------------------------------------------
# 12. Cloudflare Radar URL Scanner -- visits the URL in a sandbox, submit + poll
# ---------------------------------------------------------------------------
def check_cloudflare_radar(url: str) -> dict:
    service = "Cloudflare Radar URL Scanner"
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
    if not token or not account_id:
        return _skipped(service, "CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID")

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    base = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/urlscanner"
    try:
        submit = requests.post(
            f"{base}/v2/scan",
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
        submitted = submit.json()
        # The submit response has `uuid` and `result` (the Radar UI link) as
        # top-level fields, NOT nested under a "result" object.
        scan_id = submitted.get("uuid")
        ui_url = submitted.get("result")
        if not scan_id:
            return {
                "service": service,
                "status": "error",
                "summary": f"No scan uuid in submit response: {submit.text[:200]}",
            }

        for _ in range(5):
            time.sleep(5)
            # Docs: this 404s while the scan is still processing, 200 once done.
            poll = requests.get(f"{base}/v2/result/{scan_id}", headers=headers, timeout=TIMEOUT)
            if poll.status_code != 200:
                continue
            # Verdicts also live at the top level here, not under "result".
            overall = poll.json().get("verdicts", {}).get("overall", {})
            malicious = overall.get("malicious", False)
            if malicious:
                categories = ", ".join(overall.get("categories", [])) or "none"
                return {
                    "service": service,
                    "status": "flagged",
                    "summary": f"Malicious verdict (categories: {categories})",
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
# 13. Spamhaus DBL -- free DNS-based domain blocklist, no API key needed.
#
# Public DNSBL usage policy: fine for personal, low-volume lookups like this,
# but Spamhaus rate-limits/blocks queries that go through certain public
# resolvers (e.g. Google/Cloudflare DNS) at scale. See
# https://www.spamhaus.org/faq/section/DNSBL%20Usage#291 before scripting
# heavy usage.
# ---------------------------------------------------------------------------
def check_spamhaus_dbl(url: str) -> dict:
    service = "Spamhaus DBL"
    domain = urllib.parse.urlparse(url).hostname or ""
    if not domain:
        return {"service": service, "status": "error", "summary": "Could not extract a hostname from URL"}

    # Non-exhaustive map of return codes -> what they mean.
    # https://www.spamhaus.org/faq/section/Spamhaus%20DBL
    codes = {
        "127.0.1.2": "spam domain",
        "127.0.1.4": "phish domain",
        "127.0.1.5": "malware domain",
        "127.0.1.6": "botnet C&C domain",
    }
    link = f"https://check.spamhaus.org/results?query={domain}"
    try:
        answer = socket.gethostbyname(f"{domain}.dbl.spamhaus.org")
        return {
            "service": service,
            "status": "flagged",
            "summary": f"Listed in Spamhaus DBL: {codes.get(answer, f'listed ({answer})')}",
            "link": link,
        }
    except socket.gaierror:
        return {"service": service, "status": "clean", "summary": "Not listed in Spamhaus DBL", "link": link}
    except OSError as exc:
        return _error(service, exc)


# ---------------------------------------------------------------------------
# 14. Zero-key heuristics -- always run, no API key needed
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
    check_spamhaus_dbl,
    check_safe_browsing,
    check_virustotal,
    check_urlscan,
    check_ipqs,
    check_urlhaus,
    check_threatfox,
    check_phishtank,
    check_abuseipdb,
    check_alienvault_otx,
    check_metadefender,
    check_criminalip,
    check_cloudflare_radar,
]
