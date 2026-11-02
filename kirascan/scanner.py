"""Static triage of a single file: identify, hash, measure, match, score.

Scoring philosophy
------------------
* **anomalies** — structural red flags (packing, W+X sections, disguised
  extensions, destructive commands). Rarely present in legitimate software.
* **behaviors** — capabilities matched by rules (keyboard hooks, autorun keys,
  injection APIs). Plenty of legitimate software has them, so their combined
  weight is capped: capabilities alone can make a file *suspicious*, never
  *malicious*.
* **intel** — third-party reputation (VirusTotal).
"""

from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .entropy import shannon
from .hashing import file_hashes
from .iocs import extract_strings, find_iocs
from .pe import PACKER_SECTIONS, parse_pe
from .rules import Rule

HIGH_ENTROPY = 7.2
BEHAVIOR_CAP = 60
DOS_STUB = b"This program cannot be run in DOS mode"
EXEC_EXTS = {".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".efi", ".drv", ".mui", ".node", ".pyd"}
DOUBLE_EXT = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|zip|rar|mp[34])\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|ps1|lnk|hta)$",
    re.I)

MAGIC = [
    (b"MZ", "PE executable"),
    (b"\x7fELF", "ELF executable"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP / OOXML archive"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 (legacy Office)"),
    (b"Rar!", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"\x89PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"#!", "script (shebang)"),
]
# Formats that are high-entropy by design; flagging them would be pure noise.
COMPRESSED = {"ZIP / OOXML archive", "RAR archive", "7-Zip archive", "GZIP archive", "PNG image", "JPEG image"}

VERDICTS = ((70, "malicious"), (40, "suspicious"), (1, "low"), (0, "clean"))


@dataclass
class Finding:
    title: str
    detail: str
    score: int
    kind: str = "anomaly"  # anomaly | behavior | intel
    source: str = "heuristic"


@dataclass
class ScanResult:
    path: str
    size: int
    filetype: str
    hashes: dict
    entropy: float
    findings: list[Finding] = field(default_factory=list)
    iocs: dict = field(default_factory=dict)
    pe: dict | None = None
    virustotal: dict | None = None
    elapsed_ms: float = 0.0

    @property
    def score(self) -> int:
        behaviors = sum(f.score for f in self.findings if f.kind == "behavior")
        others = sum(f.score for f in self.findings if f.kind != "behavior")
        return min(100, others + min(behaviors, BEHAVIOR_CAP))

    @property
    def verdict(self) -> str:
        return next(v for threshold, v in VERDICTS if self.score >= threshold)

    def to_dict(self) -> dict:
        return {**asdict(self), "score": self.score, "verdict": self.verdict}


def detect_type(data: bytes) -> str:
    for magic, name in MAGIC:
        if data.startswith(magic):
            return name
    if data and all(32 <= b < 127 or b in (9, 10, 13) for b in data[:512]):
        return "text"
    return "data"


def scan_file(path: Path, rules: list[Rule], max_bytes: int = 32 << 20, iocs: bool = True) -> ScanResult:
    start = time.perf_counter()
    with open(path, "rb") as f:
        data = f.read(max_bytes)

    res = ScanResult(str(path), path.stat().st_size, detect_type(data), file_hashes(path), round(shannon(data), 3))
    res.findings += _name_heuristics(path, data)
    pe = parse_pe(data)
    res.findings += _content_heuristics(data, res, pe)

    content = (data, data.lower())
    # For PEs, API rules look at what the binary actually *uses* (imports it doesn't re-export),
    # not every string it contains: kernel32.dll exporting VirtualAllocEx says nothing about intent.
    imports = b"\0" + "\0".join(pe.used_imports).encode() + b"\0" if pe else None
    import_view = (imports, imports.lower()) if imports else None
    for rule in rules:
        by_imports = rule.scope == "imports" and pe is not None
        target = import_view if by_imports else content
        if target is None:
            continue
        hits = rule.match(*target, name_boundary=by_imports)
        if hits:
            kind = "anomaly" if rule.severity == "critical" else "behavior"
            res.findings.append(Finding(rule.description, ", ".join(hits), rule.score, kind, f"rule:{rule.id}"))

    if iocs:
        res.iocs = find_iocs(extract_strings(data))
    res.elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    return res


def _name_heuristics(path: Path, data: bytes) -> list[Finding]:
    out = []
    if "‮" in path.name:
        out.append(Finding("Right-to-left override in filename", "classic trick to hide the real extension", 50))
    if DOUBLE_EXT.search(path.name):
        out.append(Finding("Deceptive double extension", path.name, 40))
    if data.startswith(b"MZ") and path.suffix.lower() not in EXEC_EXTS:
        out.append(Finding("Executable disguised by extension",
                           f"PE header inside a '{path.suffix or '(no extension)'}' file", 35))
    return out


def _content_heuristics(data: bytes, res: ScanResult, pe) -> list[Finding]:
    out = []
    if len(data) >= 4096 and res.entropy >= HIGH_ENTROPY and res.filetype not in COMPRESSED:
        out.append(Finding("High entropy", f"{res.entropy:.2f} bits/byte, likely packed or encrypted", 15))

    stubs = data.count(DOS_STUB)
    if stubs > 1 or (stubs == 1 and not data.startswith(b"MZ")):
        out.append(Finding("Embedded executable", f"{stubs} DOS stub(s) inside the file", 25))

    if pe is None:
        return out
    res.pe = pe.to_dict()
    wx = [s.name for s in pe.sections if s.executable and s.writable]
    if wx:
        out.append(Finding("Writable + executable section", ", ".join(wx), 25))
    packed = [s.name for s in pe.sections if s.name in PACKER_SECTIONS]
    if packed:
        out.append(Finding("Packer section names", ", ".join(packed), 20))
    dense = [f"{s.name} ({s.entropy:.2f})" for s in pe.sections if s.executable and s.entropy >= HIGH_ENTROPY]
    if dense:
        out.append(Finding("High-entropy code section", ", ".join(dense), 20))
    if not pe.sections:
        out.append(Finding("PE without sections", "malformed or heavily obfuscated header", 15))
    # No "future compile timestamp" check on purpose: reproducible builds (/Brepro) put a
    # content hash in that field, so half of Windows itself would trip it.
    return out
