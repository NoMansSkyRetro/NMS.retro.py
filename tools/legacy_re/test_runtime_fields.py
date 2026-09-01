"""Guard the exe-RE'd runtime-class field offsets in nmspy/data/types.py.

These offsets are reverse-engineered from the cached decompilations (field_evidence.py) and
adversarially verified, then written into each class's `_vfields_`. This checks that
versioned_struct + partial_struct actually place the field at the declared offset for each
build, so a regression in that machinery (or a bad edit) fails here rather than in-game.

pytest sets PYTEST_VERSION, so pymhf skips its interactive config on import.
"""
import importlib
import os

os.environ.setdefault("PYTEST_VERSION", "1")

import nmspy.data.offsets as offsets  # noqa: E402
from nmspy.versions import GameVersion  # noqa: E402

# A subset of the confirmed offsets (the Newton-relevant fields); one per class is enough to
# catch placement regressions, several to catch a cross-build mixup.
EXPECT = {
    "cGcPlanet": {
        "miPlanetIndex": {"1.09.1": 0x50, "1.13": 0x50, "1.24": 0x50, "1.38": 0x58},
        "mNode": {"1.09.1": 0xE7CE8, "1.13": 0x12E318, "1.24": 0x12E318, "1.38": 0x12E868},
        "mPosition": {"1.09.1": 0xE7D00, "1.13": 0x12E330, "1.24": 0x12E330, "1.38": 0x12E880},
    },
    "cGcShipHUD": {
        "miSelectedPlanet": {"1.09.1": 0x212A8, "1.13": 0x21998, "1.24": 0x21998, "1.38": 0x22438},
        "mbSelectedPlanetPanelVisible": {"1.09.1": 0x212AC, "1.13": 0x2199C, "1.24": 0x2199C, "1.38": 0x2243C},
    },
    "cGcSolarSystem": {
        "maPlanets": {"1.09.1": 0x16B0, "1.13": 0x17A0, "1.24": 0x17A0, "1.38": 0x1C30},
    },
    "cGcNGuiText": {
        "mpTextData": {"1.09.1": 0x60, "1.13": 0x60, "1.24": 0x60, "1.38": 0x60},
    },
    "cGcMarkerPoint": {
        "mCustomName": {"1.09.1": 0x38, "1.13": 0x38, "1.24": 0x38, "1.38": 0x38},
    },
    "cGcAlienPuzzleEntry": {
        "Id": {"1.09.1": 0x0, "1.13": 0x0, "1.24": 0x0, "1.38": 0x0},
        "Options": {"1.09.1": 0x420, "1.13": 0x420, "1.24": 0x420, "1.38": 0x4B0},
    },
}


def test_runtime_field_offsets_placed_per_build():
    bad = []
    for v, fields in [(b, EXPECT) for b in ("1.09.1", "1.13", "1.24", "1.38")]:
        offsets.CURRENT_VERSION = GameVersion(v)
        types = importlib.reload(importlib.import_module("nmspy.data.types"))
        for cls_name, cls_fields in fields.items():
            cls = getattr(types, cls_name)
            for fname, bmap in cls_fields.items():
                got = getattr(getattr(cls, fname), "offset", None)
                if got != bmap[v]:
                    bad.append(f"{v} {cls_name}.{fname}: got {got:#x} want {bmap[v]:#x}")
    assert not bad, "runtime field offset mismatches:\n" + "\n".join(bad)


if __name__ == "__main__":
    test_runtime_field_offsets_placed_per_build()
    print("OK: runtime field offsets place correctly in all four builds")
