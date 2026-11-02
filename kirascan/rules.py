"""A tiny signature engine: JSON rules with string / hex / regex patterns and N-of conditions.

Rule format (one object per rule)::

    {
      "id": "win-process-injection",
      "description": "Remote process injection API chain",
      "severity": "high",                    # low | medium | high | critical
      "strings": ["VirtualAllocEx", "..."],  # matched as ASCII *and* UTF-16LE
      "hex": ["55 50 58 21"],                # raw byte sequences
      "regex": ["https?://\\d+\\.\\d+"],     # Python regex over raw bytes
      "condition": "all",                    # any | all | <int> (N of the patterns)
      "nocase": true,
      "scope": "imports"                     # content (default) | imports (PE import table)
    }
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

SEVERITY_SCORE = {"low": 5, "medium": 15, "high": 30, "critical": 60}
SCOPES = ("content", "imports")


class RuleError(ValueError):
    """A rule file is malformed."""


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    severity: str
    condition: int
    patterns: tuple  # (label, kind, needle) — needle: tuple[bytes, ...] or compiled regex
    nocase: bool = False
    tags: tuple = ()
    scope: str = "content"

    @property
    def score(self) -> int:
        return SEVERITY_SCORE[self.severity]

    def match(self, data: bytes, lowered: bytes, name_boundary: bool = False) -> list[str]:
        """Labels of the patterns that matched if the rule fires, otherwise [].

        With `name_boundary`, `data` is a NUL-separated name list and strings must start a name:
        "SetWindowsHookEx" matches "SetWindowsHookExW" but "GetAsyncKeyState" not "NtUserGetAsyncKeyState".
        """
        prefix = b"\0" if name_boundary else b""
        hits = []
        for label, kind, needle in self.patterns:
            if kind == "regex":
                found = needle.search(data) is not None
            else:
                haystack = lowered if self.nocase and kind == "string" else data
                found = any(prefix + n in haystack for n in needle)
            if found:
                hits.append(label)
        return hits if len(hits) >= self.condition else []


def _compile(raw: dict, source: str) -> Rule:
    if not isinstance(raw, dict) or "id" not in raw:
        raise RuleError(f"{source}: every rule needs an 'id'")
    rid = raw["id"]
    severity = raw.get("severity", "medium")
    if severity not in SEVERITY_SCORE:
        raise RuleError(f"{source}:{rid}: unknown severity {severity!r}")
    nocase = bool(raw.get("nocase", False))
    scope = raw.get("scope", "content")
    if scope not in SCOPES:
        raise RuleError(f"{source}:{rid}: scope must be one of {', '.join(SCOPES)}")

    patterns = []
    for s in raw.get("strings", []):
        forms = (s.encode("utf-8"), s.encode("utf-16-le"))
        patterns.append((s, "string", tuple(f.lower() for f in forms) if nocase else forms))
    for h in raw.get("hex", []):
        try:
            patterns.append((h, "hex", (bytes.fromhex(h.replace(" ", "")),)))
        except ValueError:
            raise RuleError(f"{source}:{rid}: bad hex pattern {h!r}") from None
    for r in raw.get("regex", []):
        try:
            patterns.append((r, "regex", re.compile(r.encode(), re.IGNORECASE if nocase else 0)))
        except re.error as e:
            raise RuleError(f"{source}:{rid}: bad regex {r!r}: {e}") from None
    if not patterns:
        raise RuleError(f"{source}:{rid}: rule has no patterns")

    cond = raw.get("condition", "any")
    n = {"any": 1, "all": len(patterns)}.get(cond) if isinstance(cond, str) else cond
    if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= len(patterns):
        raise RuleError(f"{source}:{rid}: condition must be 'any', 'all' or 1..{len(patterns)}")

    return Rule(rid, raw.get("description", rid), severity, n, tuple(patterns), nocase,
                tuple(raw.get("tags", ())), scope)


def parse_rules(doc, source: str) -> list[Rule]:
    items = doc.get("rules") if isinstance(doc, dict) else doc
    if not isinstance(items, list):
        raise RuleError(f"{source}: expected a list of rules")
    rules = [_compile(r, source) for r in items]
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleError(f"{source}: duplicate rule ids: {', '.join(sorted(dupes))}")
    return rules


def load_builtin() -> list[Rule]:
    text = resources.files("kirascan").joinpath("rules/builtin.json").read_text(encoding="utf-8")
    return parse_rules(json.loads(text), "builtin")


def load_path(path: Path) -> list[Rule]:
    files = sorted(path.glob("*.json")) if path.is_dir() else [path]
    rules: list[Rule] = []
    for f in files:
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise RuleError(f"{f}: {e}") from None
        rules += parse_rules(doc, str(f))
    return rules
