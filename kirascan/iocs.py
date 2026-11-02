"""String extraction (ASCII + UTF-16LE) and indicator-of-compromise matching."""

from __future__ import annotations

import re
from collections.abc import Iterable

MIN_LEN = 5
MAX_PER_KIND = 50

_ASCII = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LEN)

PATTERNS = {
    "urls": re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\\^`{|}]{4,}", re.I),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"),
    "emails": re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}\b", re.I),
    "registry": re.compile(
        r"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HK(?:LM|CU|CR|U))\\[\w\\.{}-]+", re.I),
    "onion": re.compile(r"\b(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion\b", re.I),
    "bitcoin": re.compile(r"\bbc1[ac-hj-np-z02-9]{25,59}\b"),
}


def extract_strings(data: bytes, limit: int = 100_000) -> list[str]:
    """Printable runs of at least MIN_LEN chars, both ASCII and UTF-16LE (Windows wide strings)."""
    out = [m.group().decode("ascii") for m in _ASCII.finditer(data)]
    out += [m.group().decode("utf-16-le") for m in _UTF16.finditer(data)]
    return out[:limit]


def _looks_like_version(ip: str) -> bool:
    """'6.0.0.0' / '5.1.0.0' are file versions, not hosts."""
    return ip.split(".").count("0") >= 2


def find_iocs(strings: Iterable[str]) -> dict[str, list[str]]:
    found: dict[str, set[str]] = {kind: set() for kind in PATTERNS}
    for s in strings:
        for kind, rx in PATTERNS.items():
            found[kind].update(m.rstrip(".,;:)]") for m in rx.findall(s))
    found["ipv4"] = {ip for ip in found["ipv4"] if not _looks_like_version(ip)}
    return {kind: sorted(v)[:MAX_PER_KIND] for kind, v in found.items() if v}
