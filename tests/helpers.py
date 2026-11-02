"""Synthetic samples built in memory — no real malware ever touches this repo."""

import random
import struct

RWX = 0x20000000 | 0x40000000 | 0x80000000
RX = 0x20000000 | 0x40000000
RW = 0x40000000 | 0x80000000
OPT_SIZE = 240  # PE32+ optional header with 16 data directories


def _idata(imports, va):
    """Import directory for {dll: [functions]} laid out at virtual address `va`."""
    desc = bytearray((len(imports) + 1) * 20)
    body = bytearray()
    base = len(desc)
    for i, (dll, funcs) in enumerate(imports.items()):
        thunks = base + len(body)
        body += bytes((len(funcs) + 1) * 8)
        for j, fn in enumerate(funcs):
            struct.pack_into("<Q", body, thunks - base + j * 8, va + base + len(body))
            body += b"\0\0" + fn.encode() + b"\0"
        dll_name = base + len(body)
        body += dll.encode() + b"\0"
        struct.pack_into("<IIIII", desc, i * 20, va + thunks, 0, 0, va + dll_name, va + thunks)
    return bytes(desc + body), len(desc)


def make_pe(sections, timestamp=0x60000000, machine=0x8664, imports=None):
    """Smallest PE32+ the parser accepts: DOS header, PE header, optional header, section table, raw data.

    `sections` is a list of (name, characteristics, raw_bytes); `imports` an optional {dll: [functions]}.
    Section i is mapped at virtual address 0x1000 * (i + 1).
    """
    sections = list(sections)
    optional = bytearray(OPT_SIZE)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<I", optional, 108, 16)
    if imports:
        va = 0x1000 * (len(sections) + 1)
        blob, size = _idata(imports, va)
        struct.pack_into("<II", optional, 112 + 8, va, size)
        sections.append((".idata", RW, blob))

    header = bytearray(b"MZ" + b"\0" * 0x3A + struct.pack("<I", 0x40))
    header += b"PE\0\0" + struct.pack("<HHIIIHH", machine, len(sections), timestamp, 0, 0, OPT_SIZE, 0x0002)
    header += optional
    data_start = len(header) + 40 * len(sections)
    blobs = b""
    for i, (name, characteristics, raw) in enumerate(sections):
        header += struct.pack("<8sIIIIIIHHI", name.encode(), max(len(raw), 1), 0x1000 * (i + 1), len(raw),
                              data_start + len(blobs), 0, 0, 0, 0, characteristics)
        blobs += raw
    return bytes(header) + blobs


def random_bytes(n, seed=1):
    return random.Random(seed).randbytes(n)
