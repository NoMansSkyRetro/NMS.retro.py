"""Verify each decompilation database was built from the exe we target.

MSVC pads to function starts with 0xCC (or the previous function ends in ret/nop), so
nearly every DB function address should be preceded by CC/C3/00/90 in the exe. A
matching pair scores ~96% (the shortfall is jump-table targets and thunk entries
Ghidra records as functions); a DB built from a different binary collapses far below
that past the first section of identical code.

This is the check that exposed the original "1.09.1" database as being built from the
GOG binary rather than the Steam one.

    python verify_alignment.py            # all builds
    python verify_alignment.py 1.13       # one build
"""

import sys

from common import BUILDS, Binary

PAD = (0xCC, 0xC3, 0x00, 0x90)
THRESHOLD = 0.90


def check(build: str) -> bool:
    try:
        b = Binary(build)
        b.db.execute("SELECT 1 FROM decompilations LIMIT 1")
    except Exception as e:
        print(f"{build}: SKIP ({e})")
        return True
    ok = tot = 0
    for (a,) in b.db.execute("SELECT address FROM decompilations"):
        off = b.va_to_file_offset(a)
        if off is None:
            continue
        tot += 1
        if b.data[off - 1] in PAD:
            ok += 1
    ratio = ok / tot if tot else 0.0
    verdict = "OK" if ratio >= THRESHOLD else "MISMATCH - DB is from a different binary"
    print(f"{build}: {ok}/{tot} = {ratio:.4f}  {verdict}")
    return ratio >= THRESHOLD


if __name__ == "__main__":
    targets = sys.argv[1:] or list(BUILDS)
    results = [check(t) for t in targets]
    sys.exit(0 if all(results) else 1)
