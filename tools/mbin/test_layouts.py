"""Verify the generated versioned globals place every field at libMBIN's own offset.

For each build, force that build active, (re)build `nmspy.data.mbin_globals`, and assert each
ctypes field's `.offset` equals the offset in the build's authoritative layout dump. This is
the referee for gen_structs + versioned_struct + partial_struct: if any field drifts (a wrong
per-field size upstream would push following fields), it fails here.

    python tools/mbin/test_layouts.py        # all four builds, asserts

Needs pymhf importable; PYTEST_VERSION is set so pymhf skips its interactive config prompt.
"""
import ctypes
import importlib
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("PYTEST_VERSION", "1")  # skip pymhf's interactive config on import

ROOT = Path(__file__).parents[2]
LAYOUTS = ROOT / "tools" / "mbin" / "layouts"
sys.path.insert(0, str(ROOT))

import nmspy.data.offsets as offsets  # noqa: E402
from nmspy.versions import GameVersion  # noqa: E402


def check(version: str):
    layout = json.loads((LAYOUTS / f"layout_{version}.json").read_text())
    offsets.CURRENT_VERSION = GameVersion(version)
    mod = importlib.import_module("nmspy.data.mbin_globals")
    importlib.reload(mod)  # re-run @versioned_struct with this build active

    checked = fields = 0
    bad = []
    for cls in vars(mod).values():
        if not (isinstance(cls, type) and issubclass(cls, ctypes.Structure)):
            continue
        info = layout.get(cls.__name__[1:])  # cGcFoo -> GcFoo
        if not info:
            continue  # modern-fallback class, or not in this build
        checked += 1
        for f in info["fields"]:
            desc = getattr(cls, f["name"], None)
            if desc is None or not hasattr(desc, "offset"):
                continue  # opaque/unmapped field name
            fields += 1
            if desc.offset != f["offset"]:
                bad.append(f'{cls.__name__}.{f["name"]}: got 0x{desc.offset:X}, want 0x{f["offset"]:X}')
    return checked, fields, bad


def test_generated_globals_match_libmbin():
    """pytest entry: every generated field lands at libMBIN's offset in every build."""
    bad = []
    for v in ("1.09.1", "1.13", "1.24", "1.38"):
        bad += check(v)[2]
    assert not bad, "field offset mismatches:\n" + "\n".join(bad[:30])


def main():
    total_bad = 0
    for v in ("1.09.1", "1.13", "1.24", "1.38"):
        checked, fields, bad = check(v)
        total_bad += len(bad)
        print(f"{v}: {checked} structs, {fields} field offsets checked, {len(bad)} wrong")
        for b in bad[:15]:
            print("   ", b)
    assert total_bad == 0, f"{total_bad} field offsets do not match libMBIN"
    print("OK: every generated global field matches its libMBIN offset in all four builds")


if __name__ == "__main__":
    main()
