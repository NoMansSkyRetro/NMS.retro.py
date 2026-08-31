"""Gather the decompiled bodies of a runtime class's located methods, for field RE.

Runtime C++ classes (`cGcApplication`, `cGcPlanet`, `cTkDynamicGravityControl`, ...) are not
mbin-backed, so their `_vfields_` offsets come from the exe, not libMBIN. The offsets are
readable straight out of the cached Ghidra decompilations: a method's `*(T *)(this + 0xNN)`
accesses are the field offsets, and the Construct/ctor writes them in declaration order. This
pulls every located `Class::*` method's `raw_decomp` per build so those accesses can be read
(and cross-checked across builds and across methods).

    python field_evidence.py cGcPlanet            # all builds
    python field_evidence.py cGcPlanet 1.09.1     # one build
    python field_evidence.py cGcPlanet --ctor     # just the constructor(s), the field-init map
"""
import json
import sys
from pathlib import Path

from common import BUILDS, Binary

OFFSETS = Path(__file__).parents[2] / "nmspy" / "data" / "offsets.json"
_FUNCS = json.loads(OFFSETS.read_text())["functions"]


def methods(cls: str):
    """Located `Class::method` -> {build: int address}."""
    out = {}
    for name, entry in _FUNCS.items():
        if not name.startswith(cls + "::"):
            continue
        addrs = {b: int(entry[b], 16) for b in BUILDS if isinstance(entry.get(b), str) and entry[b].startswith("0x")}
        if addrs:
            out[name] = addrs
    return out


def decomp(build: str, address: int):
    b = Binary(build)
    row = b.db.execute("SELECT raw_decomp FROM decompilations WHERE address=?", (address,)).fetchone()
    return row[0] if row else None


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    ctor_only = "--ctor" in sys.argv
    cls = args[0]
    only_build = args[1] if len(args) > 1 else None
    builds = [only_build] if only_build else list(BUILDS)

    ms = methods(cls)
    if not ms:
        raise SystemExit(f"no located methods for {cls}")
    if ctor_only:
        ms = {n: a for n, a in ms.items() if n.endswith("::Construct") or n.endswith(f"::{cls.split('::')[-1]}")}

    for name, addrs in ms.items():
        for build in builds:
            if build not in addrs:
                continue
            body = decomp(build, addrs[build])
            print(f"\n{'='*78}\n{name}  [{build}]  0x{addrs[build]:X}\n{'='*78}")
            print(body or "  <no decomp row>")


if __name__ == "__main__":
    main()
