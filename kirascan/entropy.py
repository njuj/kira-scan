"""Shannon entropy — the cheapest signal that a blob is packed or encrypted."""

from __future__ import annotations

import math
from collections import Counter


def shannon(data: bytes) -> float:
    """Return entropy in bits per byte (0.0 = constant, 8.0 = uniformly random)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())
