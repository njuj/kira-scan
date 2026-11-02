"""Minimal, defensive PE (Windows executable) header parser.

Only what triage needs: machine, compile timestamp, DLL flag, the section table
and imported / exported function names. Every offset is bounds-checked because malware
headers lie.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .entropy import shannon

MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x1C0: "arm", 0x1C4: "armnt"}

PACKER_SECTIONS = {
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".petite", ".themida", ".vmp0", ".vmp1", ".vmp2",
    "MPRESS1", "MPRESS2", ".nsp0", ".nsp1", ".enigma1", ".enigma2",
}

SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000
FILE_DLL = 0x2000
PE32_PLUS = 0x20B
MAX_SECTIONS = 96
MAX_DLLS = 512
MAX_FUNCS = 4096


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_pointer: int
    raw_size: int
    characteristics: int
    entropy: float

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_EXECUTE)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_WRITE)

    @property
    def flags(self) -> str:
        return ("R" if self.characteristics & SCN_MEM_READ else "-") + \
               ("W" if self.writable else "-") + ("X" if self.executable else "-")


@dataclass
class PEInfo:
    machine: str
    timestamp: int
    is_dll: bool
    sections: list[Section] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    imported_dlls: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)

    @property
    def used_imports(self) -> list[str]:
        """Imports minus the ones re-exported: wrapper DLLs (kernel32 -> kernelbase) import what they forward."""
        exported = set(self.exports)
        return [name for name in self.imports if name not in exported]

    @property
    def compiled(self) -> str:
        try:
            return datetime.fromtimestamp(self.timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OverflowError, OSError, ValueError):
            return str(self.timestamp)

    def to_dict(self) -> dict:
        return {
            "machine": self.machine,
            "compiled": self.compiled,
            "is_dll": self.is_dll,
            "sections": [
                {"name": s.name, "raw_size": s.raw_size, "entropy": round(s.entropy, 3), "flags": s.flags}
                for s in self.sections
            ],
            "imported_dlls": self.imported_dlls,
            "import_count": len(self.imports),
            "export_count": len(self.exports),
        }


def parse_pe(data: bytes) -> PEInfo | None:
    """Return header info, or None if `data` is not a well-formed PE."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return None
        machine, nsections, timestamp, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    except struct.error:
        return None

    opt = e_lfanew + 24
    sections = []
    for i in range(min(nsections, MAX_SECTIONS)):
        off = opt + opt_size + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b"\0").decode("latin-1")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
        characteristics = struct.unpack_from("<I", data, off + 36)[0]
        sections.append(Section(name, vaddr, vsize, rptr, rsize, characteristics, shannon(data[rptr:rptr + rsize])))

    info = PEInfo(MACHINES.get(machine, hex(machine)), timestamp, bool(chars & FILE_DLL), sections)
    for parse in (_parse_imports, _parse_exports):
        try:
            parse(data, opt, opt_size, info)
        except struct.error:
            pass  # truncated table: keep whatever was read
    return info


def _rva_to_offset(sections: list[Section], rva: int) -> int | None:
    for s in sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            return s.raw_pointer + (rva - s.virtual_address)
    return None


def _cstr(data: bytes, off: int | None, limit: int = 256) -> str | None:
    if off is None or off >= len(data):
        return None
    end = data.find(b"\0", off, off + limit)
    raw = data[off:end if end != -1 else off + limit]
    return raw.decode("latin-1") if raw else None


def _data_directory(data: bytes, opt: int, opt_size: int, index: int) -> tuple[int, bool]:
    """(RVA of data directory `index`, is PE32+) — RVA 0 when absent."""
    if opt_size < 2:
        return 0, False
    plus = struct.unpack_from("<H", data, opt)[0] == PE32_PLUS
    count_off, dirs_off = (opt + 108, opt + 112) if plus else (opt + 92, opt + 96)
    entry = dirs_off + index * 8
    if entry + 8 > opt + opt_size or struct.unpack_from("<I", data, count_off)[0] <= index:
        return 0, plus
    return struct.unpack_from("<I", data, entry)[0], plus


def _parse_exports(data: bytes, opt: int, opt_size: int, info: PEInfo) -> None:
    rva, _ = _data_directory(data, opt, opt_size, 0)
    directory = _rva_to_offset(info.sections, rva) if rva else None
    if directory is None:
        return
    count, names_rva = struct.unpack_from("<II", data, directory + 24)[0], struct.unpack_from("<I", data, directory + 32)[0]
    names = _rva_to_offset(info.sections, names_rva)
    for i in range(min(count, MAX_FUNCS * 4)):
        if names is None or names + 4 * i + 4 > len(data):
            break
        name = _cstr(data, _rva_to_offset(info.sections, struct.unpack_from("<I", data, names + 4 * i)[0]))
        if name:
            info.exports.append(name)


def _parse_imports(data: bytes, opt: int, opt_size: int, info: PEInfo) -> None:
    rva, plus = _data_directory(data, opt, opt_size, 1)
    desc = _rva_to_offset(info.sections, rva) if rva else None
    if desc is None:
        return

    size, fmt, ordinal_flag = (8, "<Q", 1 << 63) if plus else (4, "<I", 1 << 31)
    for _ in range(MAX_DLLS):
        if desc + 20 > len(data):
            break
        lookup, _, _, name_rva, iat = struct.unpack_from("<IIIII", data, desc)
        if not (lookup or name_rva or iat):
            break
        dll = _cstr(data, _rva_to_offset(info.sections, name_rva))
        if dll:
            info.imported_dlls.append(dll)
        thunk = _rva_to_offset(info.sections, lookup or iat)
        for _ in range(MAX_FUNCS):
            if thunk is None or thunk + size > len(data):
                break
            value = struct.unpack_from(fmt, data, thunk)[0]
            if value == 0:
                break
            if not value & ordinal_flag:
                hint_name = _rva_to_offset(info.sections, value & 0x7FFFFFFF)
                name = _cstr(data, hint_name + 2 if hint_name is not None else None)
                if name:
                    info.imports.append(name)
            thunk += size
        desc += 20
