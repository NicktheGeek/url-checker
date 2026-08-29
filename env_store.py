"""
Backs the web UI's Settings tab: what API key fields exist, their current
values, and writing edits back into .env.

SETTINGS_SCHEMA is the one place that lists every key this app knows about --
sample.env's comments and the README's source table are meant to stay in
sync with it, but this is the copy the app itself reads.
"""
from app_paths import BASE_DIR, DATA_DIR

ENV_PATH = DATA_DIR / ".env"
SAMPLE_ENV_PATH = BASE_DIR / "sample.env"

SETTINGS_SCHEMA = [
    {
        "id": "safe_browsing",
        "label": "Google Safe Browsing",
        "signup": "https://developers.google.com/safe-browsing/v4/get-started",
        "note": None,
        "fields": [{"keys": ["GOOGLE_SAFE_BROWSING_API_KEY"], "label": "API Key"}],
    },
    {
        "id": "virustotal",
        "label": "VirusTotal",
        "signup": "https://www.virustotal.com",
        "note": "70+ engine consensus; free tier is 4 req/min, 500/day",
        "fields": [{"keys": ["VIRUSTOTAL_API_KEY"], "label": "API Key"}],
    },
    {
        "id": "urlscan",
        "label": "urlscan.io",
        "signup": "https://urlscan.io/user/signup",
        "note": None,
        "fields": [{"keys": ["URLSCAN_API_KEY"], "label": "API Key"}],
    },
    {
        "id": "ipqs",
        "label": "IPQualityScore",
        "signup": "https://www.ipqualityscore.com/create-account",
        "note": None,
        "fields": [{"keys": ["IPQS_API_KEY"], "label": "API Key"}],
    },
    {
        "id": "abusech",
        "label": "URLhaus & ThreatFox (abuse.ch)",
        "signup": "https://auth.abuse.ch/",
        "note": "One free Auth-Key covers both sources",
        "fields": [{"keys": ["URLHAUS_AUTH_KEY", "THREATFOX_AUTH_KEY"], "label": "Auth-Key"}],
    },
    {
        "id": "phishtank",
        "label": "PhishTank",
        "signup": "https://www.phishtank.com/developer_info.php",
        "note": None,
        "fields": [{"keys": ["PHISHTANK_API_KEY"], "label": "API Key"}],
    },
    {
        "id": "abuseipdb",
        "label": "AbuseIPDB",
        "signup": "https://www.abuseipdb.com/register",
        "note": "Reputation for the URL's resolved IP, not the domain",
        "fields": [{"keys": ["ABUSEIPDB_API_KEY"], "label": "API Key"}],
    },
    {
        "id": "otx",
        "label": "AlienVault OTX",
        "signup": "https://otx.alienvault.com/api",
        "note": None,
        "fields": [{"keys": ["OTX_API_KEY"], "label": "API Key"}],
    },
    {
        "id": "metadefender",
        "label": "MetaDefender Cloud",
        "signup": "https://metadefender.opswat.com/",
        "note": None,
        "fields": [{"keys": ["METADEFENDER_API_KEY"], "label": "API Key"}],
    },
    {
        "id": "criminalip",
        "label": "CriminalIP",
        "signup": "https://www.criminalip.io/",
        "note": "Free tier has a small shared daily domain-scan quota",
        "fields": [{"keys": ["CRIMINALIP_API_KEY"], "label": "API Key"}],
    },
    {
        "id": "cloudflare",
        "label": "Cloudflare Radar URL Scanner",
        "signup": "https://dash.cloudflare.com/",
        "note": 'Token needs the "Account > URL Scanner" permission set to "Edit" specifically',
        "fields": [
            {"keys": ["CLOUDFLARE_API_TOKEN"], "label": "API Token"},
            {"keys": ["CLOUDFLARE_ACCOUNT_ID"], "label": "Account ID"},
        ],
    },
]

ALL_KEYS = {key for service in SETTINGS_SCHEMA for field in service["fields"] for key in field["keys"]}


def mask_value(value: str) -> str:
    """Preview shown in the Settings UI. Never the real value -- safe to
    send to the browser even on an untrusted network -- just a fixed-length
    run of bullets plus the last few characters, so it doesn't even leak
    the real length of a short secret."""
    if not value:
        return ""
    tail = value[-4:] if len(value) > 8 else ""
    return "•" * 10 + tail


def read_current_values() -> dict:
    """Read whatever's actually in .env right now (not os.environ, which
    could be stale if something else edited the file on disk)."""
    if not ENV_PATH.exists():
        return {}
    values = {}
    for line in ENV_PATH.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key.strip()] = value.strip()
    return values


def save_values(new_values: dict) -> None:
    """Write new_values into .env, updating each KEY= line in place and
    leaving every comment/blank line untouched. Creates .env from
    sample.env first if it doesn't exist yet, so the helpful comments are
    there from the start rather than a bare list of KEY= lines."""
    if not ENV_PATH.exists():
        base = SAMPLE_ENV_PATH.read_text() if SAMPLE_ENV_PATH.exists() else ""
        ENV_PATH.write_text(base)

    lines = ENV_PATH.read_text().splitlines()
    updated = set()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in new_values:
            lines[i] = f"{key}={new_values[key]}"
            updated.add(key)

    for key, value in new_values.items():
        if key not in updated:
            lines.append(f"{key}={value}")

    ENV_PATH.write_text("\n".join(lines) + "\n")
