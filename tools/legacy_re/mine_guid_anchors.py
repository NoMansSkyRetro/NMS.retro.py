"""Mine MBIN template GUIDs into per-build code anchors.

Every metadata template's GUID is a 64-bit constant that appears in the code as a `mov
reg, imm64`, in the one function that constructs/registers that template. handles.py already
indexes every imm64 by owning function (`by_token[("imm", value)]`, and `distinctive` for the
uniquely-owned ones), so a GUID resolves straight to its loader function. That gives ~hundreds
of named anchors per build (each tagged with the struct it loads), which the hunt can port and
expand from to reach the still-unmapped upstream surface.

    python mine_guid_anchors.py            # resolve + stats, writes out/guid_anchors.json
    python mine_guid_anchors.py <Struct>   # show one struct's owner across builds
"""
import json
import sys
from pathlib import Path

from handles import Xverse

HERE = Path(__file__).parent
CENSUS = HERE.parents[1] / "tools" / "mbin" / "guid_census.json"
OUT = HERE / "out" / "guid_anchors.json"
OFFSETS = json.loads((HERE.parents[1] / "nmspy" / "data" / "offsets.json").read_text())["functions"]

BUILDS = ["1.09.1", "1.13", "1.24", "1.38"]


def located_addrs(build):
    """VA -> upstream name for every function already located in this build."""
    out = {}
    for name, e in OFFSETS.items():
        v = e.get(build)
        if isinstance(v, str) and v.startswith("0x"):
            out[int(v, 16)] = name
    return out


def owner(ix, guid):
    """(va, unique) for the function that references this imm64 GUID, or (None, False)."""
    tok = ("imm", guid)
    fns = ix.by_token.get(tok)
    if not fns:
        return None, False
    if len(fns) == 1:
        return next(iter(fns)), True
    # multiple owners: still useful, return the lowest VA but flag non-unique
    return min(fns), False


def main():
    census = json.loads(CENSUS.read_text(encoding="utf-8"))
    xv = Xverse(builds=BUILDS)

    single = len(sys.argv) > 1
    want = sys.argv[1] if single else None

    result = {}
    for b in BUILDS:
        ix = xv.idx[b]
        loc = located_addrs(b)
        entries = census.get(b, {})
        resolved = uniq = coincide_unmapped = coincide_located = 0
        table = {}
        for struct, info in entries.items():
            if single and struct != want:
                continue
            g = info.get("guid")
            if not g or g == "0x0" or int(g, 16) == 0:
                continue
            va, is_uniq = owner(ix, int(g, 16))
            if va is None:
                continue
            resolved += 1
            uniq += int(is_uniq)
            rec = {"guid": g, "owner": f"0x{va:X}", "unique": is_uniq}
            if va in loc:
                rec["already"] = loc[va]
                coincide_located += 1
            table[struct] = rec
        result[b] = table
        print(f"{b}: {len(entries)} templates, {resolved} GUIDs resolved to an owner "
              f"({uniq} unique), {coincide_located} owners already in offsets.json",
              file=sys.stderr)

    if single:
        for b in BUILDS:
            print(f"{b}: {json.dumps(result[b].get(want, {}))}")
        return

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1))
    print(f"wrote {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
