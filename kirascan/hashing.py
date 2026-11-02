"""Streaming file hashes, so multi-GB samples never land in memory at once."""

from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK = 1 << 20


def file_hashes(path: Path) -> dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            for h in (md5, sha1, sha256):
                h.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}
