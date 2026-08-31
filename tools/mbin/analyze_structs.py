"""Compare a metadata struct's fields across builds, from the decompiled EXML.

`decompile.py` writes ``out/exml/<build>/<NAME>.exml`` per build. This reads a struct's
top-level fields (name + a coarse kind inferred from the EXML) in each build and prints a
side-by-side that highlights fields added, removed, or reordered between versions, i.e. the
raw material for a per-version ``versioned_struct``.

    python analyze_structs.py GCENVIRONMENTGLOBALS.GLOBAL

Note: EXML gives field NAMES and order reliably, and a coarse kind (nested struct / list /
leaf), but not byte-exact types or offsets; those need the compiler's type metadata. This
is a field-inventory/diff, not the final layout.
"""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).parent
EXML = HERE / "out" / "exml"
BUILDS = ["1.09.1", "1.13", "1.24", "1.38"]


def fields(exml_path):
    """Ordered [(name, kind)] of the root template's direct fields."""
    root = ET.parse(exml_path).getroot()
    out = []
    for prop in root.findall("Property"):
        name = prop.get("name")
        value = prop.get("value") or ""
        kids = prop.findall("Property")
        if value.endswith(".xml"):
            kind = value[:-4]                    # nested struct type
        elif prop.findall("Property") and all(k.get("value", "").endswith(".xml") for k in kids) and kids:
            kind = "list"                        # repeated sub-elements
        elif value in ("true", "false"):
            kind = "bool"
        elif value and value.replace("-", "").replace(".", "").isdigit():
            kind = "number"
        else:
            kind = "enum/string"
        out.append((name, kind))
    return out


def main():
    name = sys.argv[1].upper().replace(".EXML", "")
    per = {}
    for b in BUILDS:
        p = EXML / b.replace(".", "_") / f"{name}.exml"
        if p.exists():
            per[b] = fields(p)
    if not per:
        raise SystemExit(f"no EXML for {name} in any build (run decompile.py first)")

    have = [b for b in BUILDS if b in per]
    print(f"{name}: fields per build " + "  ".join(f"{b}={len(per[b])}" for b in have))
    # union of field names in first-seen order
    order, seen = [], set()
    for b in have:
        for n, _ in per[b]:
            if n not in seen:
                seen.add(n)
                order.append(n)
    kinds = {b: dict(per[b]) for b in have}
    width = max((len(n) for n in order), default=8)
    print(f"\n{'field':<{width}}  " + "  ".join(f"{b:<14}" for b in have))
    for n in order:
        cells = []
        for b in have:
            cells.append(f"{kinds[b].get(n, '-'):<14}")
        flag = "" if all(n in kinds[b] for b in have) else "   <- differs"
        print(f"{n:<{width}}  " + "  ".join(cells) + flag)


if __name__ == "__main__":
    main()
