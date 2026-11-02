"""Human-friendly terminal report."""

from __future__ import annotations

import os

from . import __version__

COLORS = {"clean": "32", "low": "36", "suspicious": "33", "malicious": "1;31"}

UNICODE = {"clean": "✔", "low": "•", "suspicious": "⚠", "malicious": "✖", "mid": "├─", "end": "└─", "sep": "·", "dash": "—"}
ASCII = {"clean": "+", "low": "-", "suspicious": "!", "malicious": "x", "mid": "|-", "end": "`-", "sep": "|", "dash": "-"}


class Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text


def use_color(stream, disabled: bool) -> bool:
    return not disabled and "NO_COLOR" not in os.environ and getattr(stream, "isatty", lambda: False)()


def glyphs_for(stream) -> dict:
    """Unicode box-drawing where the stream can encode it, plain ASCII otherwise (e.g. cp1252 pipes)."""
    try:
        "".join(UNICODE.values()).encode(getattr(stream, "encoding", None) or "ascii")
        return UNICODE
    except (UnicodeEncodeError, LookupError):
        return ASCII


def enable_windows_ansi() -> None:
    """Turn on VT escape processing for legacy Windows consoles."""
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except (AttributeError, OSError):
        pass


def render_text(results, elapsed: float, style: Style, glyphs: dict = UNICODE, verbose: bool = False) -> str:
    g = glyphs
    sep = f"  {g['sep']}  "
    lines = [style(f" kira-scan v{__version__}", "1;36") + style(f"{sep}{len(results)} file(s){sep}{elapsed:.2f}s", "2"), ""]
    for r in results:
        color = COLORS[r.verdict]
        badge = f"{g[r.verdict]} {r.verdict.upper():<10}"
        lines.append(f" {style(badge, color)}  {r.path}  " +
                     style(f"score {r.score}{sep}{r.filetype}{sep}entropy {r.entropy:.2f}", "2"))
        for i, f in enumerate(r.findings):
            branch = g["end"] if i == len(r.findings) - 1 else g["mid"]
            lines.append(f"     {style(branch, '2')} {style(f'+{f.score:<3}', color)} {f.title} " +
                         style(f"{g['dash']} {f.detail}", "2"))
        if verbose:
            lines.append(style(f"     sha256    {r.hashes['sha256']}", "2"))
            if r.pe:
                secs = " ".join(f"{s['name']}[{s['flags']}]" for s in r.pe["sections"])
                lines.append(style(f"     pe        {r.pe['machine']}{sep}{r.pe['import_count']} imports{sep}{secs}", "2"))
            for kind, values in r.iocs.items():
                more = f" (+{len(values) - 6})" if len(values) > 6 else ""
                lines.append(style(f"     {kind:<10}", "36") + style(", ".join(values[:6]) + more, "2"))
        if r.findings or verbose:
            lines.append("")

    counts = {v: sum(r.verdict == v for r in results) for v in COLORS}
    lines.append(" " + style(sep, "2").join(style(f"{n} {v}", COLORS[v]) for v, n in counts.items()))
    return "\n".join(lines)
