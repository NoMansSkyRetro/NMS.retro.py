"""Generate nmspy `versioned_struct` classes from a libMBIN layout dump (structdump).

Reads out/rc1_layout.json ({struct: {size, fields:[{name,type,offset,size}]}}) and emits
`versioned_struct` classes with per-version offsets. libMBIN gives the authoritative type,
offset and size for every field, so primitives/vectors map to real ctypes and everything
else (nested templates, lists, enums we do not model yet) becomes a correctly-sized opaque
blob with the real type in a comment. Offsets are keyed by version so more builds can be
merged in later (currently only the rc1/1.09.1-era layout is dumped).

    python gen_structs.py Globals            # every *Globals struct
    python gen_structs.py GcEnvironmentGlobals

Prints a module to stdout.
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).parent
LAYOUT = HERE / "out" / "rc1_layout.json"
VERSION = "1.09.1"   # the rc1 branch encodes the RC1/1.0 layout, which matches 1.09.1

# libMBIN field type -> (nmspy ctype expression, is it from basic_types)
PRIM = {
    "Boolean": "c_bool", "Byte": "c_uint8", "SByte": "c_int8",
    "Int16": "c_int16", "UInt16": "c_uint16", "Int32": "c_int32", "UInt32": "c_uint32",
    "Int64": "c_int64", "UInt64": "c_uint64", "Single": "c_float", "Double": "c_double",
    "Vector2f": "Vector2f", "Vector3f": "Vector3f", "Vector4f": "Vector4f",
    "Colour": "Colour",
}


def ctype_for(field):
    t, sz = field["type"], field["size"]
    if t in PRIM:
        return PRIM[t], None
    m = re.match(r"NMSString0x([0-9A-Fa-f]+)$", t)
    if m:
        return f"c_char * 0x{int(m.group(1), 16):X}", None
    # nested template / list / enum / array: keep the right size, note the real type
    n = max(1, sz)
    return f"c_ubyte * 0x{n:X}", t


def gen(struct, info):
    lines = [f"@versioned_struct", f"class {struct}(Structure):",
             f'    """size 0x{info["size"]:X}. Generated from libMBIN (rc1/1.09.1 layout)."""',
             "    _vfields_ = {"]
    for f in info["fields"]:
        if f["offset"] < 0:
            continue
        ctype, note = ctype_for(f)
        comment = f"  # {note}" if note else ""
        lines.append(f'        "{f["name"]}": ({ctype}, {{"{VERSION}": 0x{f["offset"]:X}}}),{comment}')
    lines.append("    }")
    return "\n".join(lines)


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "Globals"
    layout = json.loads(LAYOUT.read_text())
    picked = {k: v for k, v in layout.items() if which.lower() in k.lower()} \
        if which != "Globals" else {k: v for k, v in layout.items() if k.endswith("Globals")}
    if not picked:
        raise SystemExit(f"no struct matching {which!r} in {LAYOUT.name}")

    print('"""Auto-generated mbin-backed struct layouts. Regenerate with tools/mbin/gen_structs.py."""')
    print("from ctypes import (Structure, c_bool, c_char, c_double, c_float, c_int8, c_int16,")
    print("                    c_int32, c_int64, c_ubyte, c_uint8, c_uint16, c_uint32, c_uint64)")
    print("from nmspy.data.basic_types import Vector2f, Vector3f, Vector4f, Colour")
    print("from nmspy.data.offsets import versioned_struct")
    print()
    for k in sorted(picked):
        print(gen(k, picked[k]))
        print()
    print(f"[gen_structs] {len(picked)} structs", file=sys.stderr)


if __name__ == "__main__":
    main()
