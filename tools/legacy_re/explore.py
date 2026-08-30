"""Interactive exploration of a legacy build's binary + decompilation database.

    python explore.py strings 1.09.1 AppBoot
    python explore.py grep 1.09.1 "FSM IGNORED"
    python explore.py dump 1.09.1 0x140bc25f0
    python explore.py range 1.09.1 0x140bc2000 0x140bc3200
    python explore.py vtable 1.09.1 0x1413188a0 16
    python explore.py sections 1.09.1
"""

import re
import sys

from common import STATIC_BASE, Binary


def cmd_strings(b: Binary, needle: str):
    pat = re.escape(needle.encode())
    vas = []
    for m in re.finditer(pat + b"\0", b.data):
        off = m.start()
        if b.data[off - 1] != 0:  # only standalone NUL-terminated strings
            continue
        va = b.file_offset_to_va(off)
        if va is not None:
            vas.append(va)
    if not vas:
        print("no standalone string found")
        return
    # Ghidra renders references either as a named string symbol or a bare address.
    refs = {}
    for like in [f"%_{va:08x}%" for va in vas] + [f"%s_{needle[:24]}%"]:
        for name, addr, size in b.functions_matching(like, 20):
            refs[addr] = (name, size)
    for va in vas:
        print(f'"{needle}" @ 0x{va:X}')
    for addr in sorted(refs):
        name, size = refs[addr]
        print(f"  ref: {name}  0x{addr:X}  size={size}")


def cmd_grep(b: Binary, pattern: str):
    rows = b.functions_matching(f"%{pattern}%")
    print(f"{len(rows)} functions containing {pattern!r}")
    for name, addr, size in rows:
        print(f"  {name}  0x{addr:X}  size={size}")


def cmd_dump(b: Binary, addr: str):
    row = b.function_at(int(addr, 16))
    if row is None:
        print("no function at that address")
        return
    name, address, size, decomp = row
    print(f"{name}  0x{address:X}  size={size}\n")
    print(decomp)


def cmd_range(b: Binary, start: str, end: str):
    for name, addr, size in b.db.execute(
        "SELECT name, address, size FROM decompilations WHERE address BETWEEN ? AND ? ORDER BY address",
        (int(start, 16), int(end, 16)),
    ):
        print(f"  {name}  0x{addr:X}  size={size}")


def cmd_vtable(b: Binary, addr: str, n: str = "16"):
    va = int(addr, 16)
    for i in range(int(n)):
        ptr = b.read_ptr(va + i * 8)
        if ptr is None:
            print(f"[{i}] <unmapped>")
            continue
        row = b.function_at(ptr)
        desc = f"{row[0]}  size={row[2]}" if row else "<not a known function>"
        print(f"[{i}] 0x{ptr:X}  {desc}")


def cmd_sections(b: Binary):
    for s in b.sections:
        print(
            f"{s.name:<8} rva=0x{s.virtual_address:08X} vsize=0x{s.virtual_size:08X} "
            f"raw=0x{s.raw_offset:08X} rsize=0x{s.raw_size:08X}"
        )


if __name__ == "__main__":
    cmd, build, *args = sys.argv[1:]
    globals()[f"cmd_{cmd}"](Binary(build), *args)
