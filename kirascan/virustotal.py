"""Optional VirusTotal v3 hash lookup. Only the SHA-256 leaves the machine — never the file."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

API = "https://www.virustotal.com/api/v3/files/{}"


class VTError(RuntimeError):
    pass


def lookup(sha256: str, api_key: str, timeout: float = 15) -> dict | None:
    """Detection summary for a hash, or None if VirusTotal has never seen it."""
    req = urllib.request.Request(API.format(sha256), headers={"x-apikey": api_key, "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            doc = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise VTError(f"HTTP {e.code}") from None
    except urllib.error.URLError as e:
        raise VTError(str(e.reason)) from None
    return summarize(doc)


def summarize(doc: dict) -> dict:
    attrs = doc.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "engines": sum(stats.values()),
        "label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label"),
    }
