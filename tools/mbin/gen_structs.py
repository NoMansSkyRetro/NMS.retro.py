"""Generate nmspy `versioned_struct` classes by merging per-build libMBIN layout dumps.

Each build's layout is dumped from its own MBINCompiler serializer (structdump for the rc1
build, `--dumplayout` for the patched 1.24.4/1.38.0.2 tags; see README). This merges them
by field name into `versioned_struct` classes whose `_vfields_` offsets are keyed per
version, so a field at the same offset everywhere collapses to a single int and a field
that moved (or a rename) is expressed per version. libMBIN gives the authoritative type,
so primitives/vectors map to real ctypes and everything else becomes a correctly-sized
opaque blob tagged with the real type.

    python gen_structs.py Globals            # every *Globals struct
    python gen_structs.py GcEnvironmentGlobals

Prints a module to stdout.
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).parent
OUT = HERE / "layouts"
# build -> committed layout dump (1.09.1 = the rc1/RC1 layout via structdump; 1.24/1.38 via
# the patched tag's --dumplayout). 1.13 predates any MBINCompiler, still to be dumped.
LAYOUTS = {
    "1.09.1": "layout_1.09.1.json",
    "1.24": "layout_1.24.json",
    "1.38": "layout_1.38.json",
}
PRIM = {
    "Boolean": "c_bool", "Byte": "c_uint8", "SByte": "c_int8",
    "Int16": "c_int16", "UInt16": "c_uint16", "Int32": "c_int32", "UInt32": "c_uint32",
    "Int64": "c_int64", "UInt64": "c_uint64", "Single": "c_float", "Double": "c_double",
    "Vector2f": "Vector2f", "Vector3f": "Vector3f", "Vector4f": "Vector4f", "Colour": "Colour",
}


def ctype_for(type_name, size):
    if type_name in PRIM:
        return PRIM[type_name], None
    m = re.match(r"NMSString0x([0-9A-Fa-f]+)$", type_name)
    if m:
        return f"c_char * 0x{int(m.group(1), 16):X}", None
    return f"c_ubyte * 0x{max(1, size):X}", type_name   # nested/list/enum/array/padding


def load():
    builds = {}
    for v, fn in LAYOUTS.items():
        p = OUT / fn
        if p.exists():
            builds[v] = json.loads(p.read_text())
    if not builds:
        raise SystemExit("no layout dumps found in out/ (see README)")
    return builds


def merge(struct, builds):
    """field name -> {'offsets': {ver: off}, 'type': str, 'size': int, 'order': min off}."""
    fields = {}
    for ver, layout in builds.items():
        info = layout.get(struct)
        if not info:
            continue
        for f in info["fields"]:
            e = fields.setdefault(f["name"], {"offsets": {}, "type": f["type"], "size": f["size"], "order": f["offset"]})
            e["offsets"][ver] = f["offset"]
            e["order"] = min(e["order"], f["offset"])
            # prefer a non-padding, named type from any build
            if e["type"] in ("Byte[]",) and f["type"] not in ("Byte[]",):
                e["type"] = f["type"]
    return fields


def gen(struct, builds):
    fields = merge(struct, builds)
    have = [v for v in LAYOUTS if v in builds and struct in builds[v]]
    sizes = ", ".join(f'{v}=0x{builds[v][struct]["size"]:X}' for v in have)
    lines = ["@versioned_struct", f"class {struct}(Structure):",
             f'    """sizes {sizes}. Generated from libMBIN layouts (tools/mbin/gen_structs.py)."""',
             "    _vfields_ = {"]
    for name, e in sorted(fields.items(), key=lambda kv: (kv[1]["order"], kv[0])):
        ctype, note = ctype_for(e["type"], e["size"])
        offs = e["offsets"]
        # collapse to a single int only when present in every build with the same offset
        if len(offs) == len(have) and len(set(offs.values())) == 1:
            spec = f"0x{next(iter(offs.values())):X}"
        else:
            spec = "{" + ", ".join(f'"{v}": 0x{offs[v]:X}' for v in have if v in offs) + "}"
        comment = f"  # {note}" if note else ""
        lines.append(f'        "{name}": ({ctype}, {spec}),{comment}')
    lines.append("    }")
    return "\n".join(lines)


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "Globals"
    builds = load()
    names = set()
    for layout in builds.values():
        names |= {k for k in layout if (k.endswith("Globals") if which == "Globals" else which.lower() in k.lower())}
    if not names:
        raise SystemExit(f"no struct matching {which!r}")

    print('"""Auto-generated mbin-backed struct layouts. Regenerate with tools/mbin/gen_structs.py."""')
    print("from ctypes import (Structure, c_bool, c_char, c_double, c_float, c_int8, c_int16,")
    print("                    c_int32, c_int64, c_ubyte, c_uint8, c_uint16, c_uint32, c_uint64)")
    print("from nmspy.data.basic_types import Vector2f, Vector3f, Vector4f, Colour")
    print("from nmspy.data.offsets import versioned_struct")
    print()
    for k in sorted(names):
        print(gen(k, builds))
        print()
    print(f"[gen_structs] {len(names)} structs across builds {list(builds)}", file=sys.stderr)


if __name__ == "__main__":
    main()
