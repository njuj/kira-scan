"""Command-line entry point. Exit codes: 0 clean/low · 1 suspicious · 2 malicious · 3 error."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__, virustotal
from .report import Style, enable_windows_ansi, glyphs_for, render_text, use_color
from .rules import RuleError, load_builtin, load_path
from .scanner import Finding, ScanResult, scan_file

EXIT = {"clean": 0, "low": 0, "suspicious": 1, "malicious": 2}
EXIT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="kira-scan",
        description="Zero-dependency static malware triage: hashes, entropy, PE anomalies, IOCs and signature rules.")
    ap.add_argument("paths", nargs="+", type=Path, help="files or directories to scan")
    ap.add_argument("-r", "--recursive", action="store_true", help="descend into sub-directories")
    ap.add_argument("--rules", action="append", type=Path, default=[], metavar="PATH",
                    help="extra rule file or directory of *.json rules (repeatable)")
    ap.add_argument("--no-builtin", action="store_true", help="skip the built-in rule set")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("-v", "--verbose", action="store_true", help="show hashes, PE sections and extracted IOCs")
    ap.add_argument("--vt", action="store_true", help="look up SHA-256 on VirusTotal (needs VT_API_KEY)")
    ap.add_argument("--max-size", type=int, default=32, metavar="MB", help="bytes analysed per file (default: 32)")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def iter_files(paths: list[Path], recursive: bool):
    for p in paths:
        if p.is_dir():
            yield from sorted(f for f in (p.rglob("*") if recursive else p.iterdir()) if f.is_file())
        elif p.is_file():
            yield p
        else:
            print(f"kira-scan: no such file or directory: {p}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rules = [] if args.no_builtin else load_builtin()
        for p in args.rules:
            rules += load_path(p)
    except (RuleError, OSError) as e:
        print(f"kira-scan: {e}", file=sys.stderr)
        return EXIT_ERROR

    vt_key = os.environ.get("VT_API_KEY")
    if args.vt and not vt_key:
        print("kira-scan: --vt needs the VT_API_KEY environment variable", file=sys.stderr)
        return EXIT_ERROR

    start = time.perf_counter()
    results = []
    for path in iter_files(args.paths, args.recursive):
        try:
            res = scan_file(path, rules, max_bytes=args.max_size << 20)
        except OSError as e:
            print(f"kira-scan: {path}: {e.strerror}", file=sys.stderr)
            continue
        if args.vt:
            _add_virustotal(res, vt_key)
        results.append(res)
    elapsed = time.perf_counter() - start

    if args.json:
        print(json.dumps({"version": __version__, "results": [r.to_dict() for r in results]}, indent=2))
    else:
        enable_windows_ansi()
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(errors="replace")
        style = Style(use_color(sys.stdout, args.no_color))
        print(render_text(results, elapsed, style, glyphs_for(sys.stdout), args.verbose))

    if not results:
        return EXIT_ERROR
    return max(EXIT[r.verdict] for r in results)


def _add_virustotal(res: ScanResult, api_key: str) -> None:
    try:
        vt = virustotal.lookup(res.hashes["sha256"], api_key)
    except virustotal.VTError as e:
        print(f"kira-scan: VirusTotal lookup failed for {res.path}: {e}", file=sys.stderr)
        return
    res.virustotal = vt
    if vt and vt["malicious"] >= 3:
        label = f", {vt['label']}" if vt["label"] else ""
        score = 70 if vt["malicious"] >= 10 else 40
        res.findings.append(Finding("Flagged on VirusTotal", f"{vt['malicious']}/{vt['engines']} engines{label}",
                                    score, "intel", "virustotal"))
