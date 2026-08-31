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
ROOT = HERE.parents[1]
# build -> committed layout dump. All four are the *effective* per-build layouts emitted by
# MBINCompiler.retro's `dumplayout --nms-version=<build>` (each build's own struct folder
# overlaid on the shared base, exactly as the runtime resolves types).
LAYOUTS = {
    "1.09.1": "layout_1.09.1.json",
    "1.13": "layout_1.13.json",
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
    """field name -> {ver: (offset, ctype_str, note)} plus 'order' (min offset).

    Every build's field carries its *own* type and size, so a field whose layout differs
    across builds (a nested struct that grew, a retype) reads each build correctly. A single
    cross-build ctype would drift: partial_struct places fields sequentially, so a size taken
    from the wrong build pushes every following field off (see tools/mbin/test_layouts.py)."""
    fields = {}
    for ver, layout in builds.items():
        info = layout.get(struct)
        if not info:
            continue
        for f in info["fields"]:
            ctype, note = ctype_for(f["type"], f["size"])
            e = fields.setdefault(f["name"], {"per": {}, "order": f["offset"]})
            e["per"][ver] = (f["offset"], ctype, note)
            e["order"] = min(e["order"], f["offset"])
    return fields


def gen(struct, builds, classname=None):
    classname = classname or struct
    fields = merge(struct, builds)
    have = [v for v in LAYOUTS if v in builds and struct in builds[v]]
    sizes = ", ".join(f'{v}=0x{builds[v][struct]["size"]:X}' for v in have)
    lines = ["@versioned_struct", f"class {classname}(Structure):",
             f'    """sizes {sizes}. Generated from libMBIN layouts (tools/mbin/gen_structs.py)."""',
             "    _vfields_ = {"]
    for name, e in sorted(fields.items(), key=lambda kv: (kv[1]["order"], kv[0])):
        per = e["per"]
        offs = {v: per[v][0] for v in have if v in per}
        ctypes_ = {v: per[v][1] for v in have if v in per}
        notes = {per[v][2] for v in have if v in per and per[v][2]}
        # collapse offset/type to a single value only when identical across every build present
        if len(offs) == len(have) and len(set(offs.values())) == 1:
            off_spec = f"0x{next(iter(offs.values())):X}"
        else:
            off_spec = "{" + ", ".join(f'"{v}": 0x{offs[v]:X}' for v in have if v in offs) + "}"
        if len(ctypes_) == len(have) and len(set(ctypes_.values())) == 1:
            ct_spec = next(iter(ctypes_.values()))
        else:
            ct_spec = "{" + ", ".join(f'"{v}": {ctypes_[v]}' for v in have if v in ctypes_) + "}"
        comment = f"  # {'/'.join(sorted(notes))}" if notes else ""
        lines.append(f'        "{name}": ({ct_spec}, {off_spec}),{comment}')
    lines.append("    }")
    return "\n".join(lines)


def header(doc):
    print(f'"""{doc}"""')
    print("from ctypes import (Structure, c_bool, c_char, c_double, c_float, c_int8, c_int16,")
    print("                    c_int32, c_int64, c_ubyte, c_uint8, c_uint16, c_uint32, c_uint64)")
    print("from nmspy.data.basic_types import Vector2f, Vector3f, Vector4f, Colour")
    print("from nmspy.data.offsets import versioned_struct")


def globals_module(builds):
    """Emit the module `nmspy/globals.py` imports: a versioned class per mbin-backed global
    it maps, and a modern (4.13) fallback import for the globals absent from every 1.x build
    (fishing/fleet/settlement postdate these builds; a few are runtime-composed, not MBINs)."""
    refs = sorted(set(re.findall(r"nms_types\.(c[A-Za-z]\w+)", (ROOT / "nmspy" / "globals.py").read_text())))
    present, absent = [], []
    for name in refs:
        key = name[1:]  # nmspy `cGcFooGlobals` -> MBIN template `GcFooGlobals`
        (present if any(key in b for b in builds.values()) else absent).append((name, key))

    header("Auto-generated mbin-backed globals for nmspy/globals.py. Per-build layouts dumped "
           "from MBINCompiler.retro; regenerate with `python tools/mbin/gen_structs.py "
           "globals-module`. Do not edit by hand. Field offsets are exact per build "
           "(tools/mbin/test_layouts.py); sizeof can be a few bytes short of the true struct "
           "size where a build has trailing alignment padding, which does not affect field "
           "reads. Nested struct/list fields are correctly-sized opaque blobs, not yet drillable.")
    if absent:
        print("\n# Not mbin-backed in the 1.x builds (feature postdates them, or runtime-composed);")
        print("# fall back to the 4.13 definition so nmspy/globals.py still imports the name.")
        print("from nmspy.data.exported_types import (  # noqa: F401")
        for name, _ in absent:
            print(f"    {name},")
        print(")")
    print()
    for name, key in present:
        print(gen(key, builds, classname=name))
        print()
    print(f"[gen_structs] globals-module: {len(present)} versioned, {len(absent)} modern-fallback "
          f"({', '.join(n for n, _ in absent)})", file=sys.stderr)


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "Globals"
    builds = load()
    if which == "globals-module":
        return globals_module(builds)

    names = set()
    for layout in builds.values():
        names |= {k for k in layout if (k.endswith("Globals") if which == "Globals" else which.lower() in k.lower())}
    if not names:
        raise SystemExit(f"no struct matching {which!r}")

    header("Auto-generated mbin-backed struct layouts. Regenerate with tools/mbin/gen_structs.py.")
    print()
    for k in sorted(names):
        print(gen(k, builds))
        print()
    print(f"[gen_structs] {len(names)} structs across builds {list(builds)}", file=sys.stderr)


if __name__ == "__main__":
    main()
