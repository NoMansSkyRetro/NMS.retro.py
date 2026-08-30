"""Shared plumbing for the legacy RE scripts.

Edit the paths here if your local layout differs. These scripts are offline tools;
nothing in the nmspy package imports them.
"""

import sqlite3
import struct
from dataclasses import dataclass

STATIC_BASE = 0x140000000

EXE_ROOT = r"E:\NMSLegacy"
DECOMP_ROOT = r"E:\NMSLegacy_Decomp"

BUILDS = {
    # The Steam 1.09.1 database is rebuilt by build_all_ghidra.py --only 109; the old
    # analysis (now NMS1091_GHIDRA_ANALYSIS_GOG) was made from the GOG binary and its
    # addresses do NOT transfer to the Steam exe.
    "1.09.1": (
        rf"{EXE_ROOT}\no_mans_sky_v1.09.1\Binaries\NMS.exe",
        rf"{DECOMP_ROOT}\NMS1091_GHIDRA_ANALYSIS\decomp.db",
    ),
    "1.13": (
        rf"{EXE_ROOT}\no_mans_sky_v1.13\Binaries\NMS.exe",
        rf"{DECOMP_ROOT}\NMS113_GHIDRA_ANALYSIS\decomp.db",
    ),
    "1.24": (
        rf"{EXE_ROOT}\no_mans_sky_v1.24\Binaries\NMS.exe",
        rf"{DECOMP_ROOT}\NMS124_GHIDRA_ANALYSIS\decomp.db",
    ),
    "1.38": (
        rf"{EXE_ROOT}\no_mans_sky_v1.38\Binaries\NMS.exe",
        rf"{DECOMP_ROOT}\NMS138_GHIDRA_ANALYSIS\decomp.db",
    ),
}


@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int  # RVA
    raw_size: int
    raw_offset: int


class Binary:
    """A legacy NMS.exe plus its Ghidra decompilation database."""

    def __init__(self, build: str):
        exe_path, db_path = BUILDS[build]
        self.build = build
        with open(exe_path, "rb") as f:
            self.data = f.read()
        self.db = sqlite3.connect(db_path)
        self.sections = self._parse_sections()

    def _parse_sections(self):
        d = self.data
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        opt_size = struct.unpack_from("<H", d, pe + 20)[0]
        first = pe + 24 + opt_size
        out = []
        for o in range(first, first + nsec * 40, 40):
            name = d[o : o + 8].rstrip(b"\0").decode()
            vsize, va, rsize, raw = struct.unpack_from("<IIII", d, o + 8)
            out.append(Section(name, vsize, va, rsize, raw))
        return out

    def va_to_file_offset(self, va: int):
        rva = va - STATIC_BASE
        for s in self.sections:
            if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
                off = s.raw_offset + (rva - s.virtual_address)
                return off if off < s.raw_offset + s.raw_size else None
        return None

    def file_offset_to_va(self, off: int):
        for s in self.sections:
            if s.raw_offset <= off < s.raw_offset + s.raw_size:
                return STATIC_BASE + s.virtual_address + (off - s.raw_offset)
        return None

    def read_ptr(self, va: int):
        off = self.va_to_file_offset(va)
        return struct.unpack_from("<Q", self.data, off)[0] if off is not None else None

    def function_at(self, address: int):
        return self.db.execute(
            "SELECT name, address, size, raw_decomp FROM decompilations WHERE address=?",
            (address,),
        ).fetchone()

    def functions_matching(self, like: str, limit: int = 40):
        return self.db.execute(
            "SELECT name, address, size FROM decompilations WHERE raw_decomp LIKE ? "
            "ORDER BY address LIMIT ?",
            (like, limit),
        ).fetchall()
