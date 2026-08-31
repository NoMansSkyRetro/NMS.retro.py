"""Self-check for the PSARC + MBIN readers: round-trips a known globals MBIN out of the
1.38 install and asserts the decompressed header parses. Run: python test_mbin.py"""
import glob
import os

from mbin import MAGIC_STD, read_header
from psarc import Psarc

PCBANKS = r"E:\NMSLegacy\no_mans_sky_v1.38\GAMEDATA\PCBANKS"
PROBE = "GCENVIRONMENTGLOBALS.GLOBAL.MBIN"


def test_read_globals_mbin():
    assert os.path.isdir(PCBANKS), f"legacy 1.38 install not found at {PCBANKS}"
    for p in sorted(glob.glob(os.path.join(PCBANKS, "*.pak"))):
        pak = Psarc(p)
        assert pak.names, f"{p}: empty manifest"           # PSARC TOC + manifest parsed
        hit = next((n for n in pak.names if n.upper().endswith(PROBE)), None)
        if hit:
            h = read_header(pak.read(hit))                  # extract + decompress + header
            assert h.magic == MAGIC_STD, f"bad magic {h.magic:#x}"
            assert h.template == "cGcEnvironmentGlobals", h.template
            assert len(str(h.timestamp)) == 12, h.timestamp  # YYYYMMDDHHMM stamp
            return
    raise AssertionError(f"{PROBE} not found in any 1.38 pak")


if __name__ == "__main__":
    test_read_globals_mbin()
    print("ok")
