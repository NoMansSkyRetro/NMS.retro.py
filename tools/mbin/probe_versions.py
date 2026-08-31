"""Report the MBIN version stamp of each legacy build, to pin the matching libMBIN era.

For each build it finds GCENVIRONMENTGLOBALS.GLOBAL.MBIN in that install's PAKs and prints
the header stamp (decimal YYYYMMDDHHMM) and format version. The stamp is what libMBIN keys
on, so it tells us which point in libMBIN's git history holds the struct definitions that
match this build.

    python probe_versions.py
"""
import glob
import os

from mbin import read_header
from psarc import Psarc

BUILDS = {
    "1.09.1": r"E:\NMSLegacy\no_mans_sky_v1.09.1\GAMEDATA\PCBANKS",
    "1.13": r"E:\NMSLegacy\no_mans_sky_v1.13\GAMEDATA\PCBANKS",
    "1.24": r"E:\NMSLegacy\no_mans_sky_v1.24\GAMEDATA\PCBANKS",
    "1.38": r"E:\NMSLegacy\no_mans_sky_v1.38\GAMEDATA\PCBANKS",
}
PROBE = "GCENVIRONMENTGLOBALS.GLOBAL.MBIN"


def find_mbin(pcbanks, wanted):
    """(Psarc, name) for the first pak containing `wanted` (case-insensitive)."""
    for p in sorted(glob.glob(os.path.join(pcbanks, "*.pak"))):
        try:
            pak = Psarc(p)
        except Exception:
            continue
        for n in pak.names:
            if n.upper().endswith(wanted.upper()):
                return pak, n, os.path.basename(p)
    return None, None, None


# MBINCompiler's tagged history starts at 1.24.3, so only 1.24 and 1.38 have an
# exact-era release. For 1.09.1/1.13 (which predate it) the fallback is the template
# GUID: where a struct's GUID equals the 1.24 build's, the 1.24.4 definition applies
# unchanged; a differing GUID means the layout changed and needs the exe or a hand port.
LIBMBIN_TAG = {"1.24": "1.24.4", "1.38": "1.38.0.2"}


def main():
    print(f"{'build':8} {'format':>7}  {'stamp':<16} {'guid':<18} {'libMBIN tag':<12} template")
    guids = {}
    for build, pcbanks in BUILDS.items():
        if not os.path.isdir(pcbanks):
            print(f"{build:8} (PCBANKS not found: {pcbanks})")
            continue
        pak, name, _ = find_mbin(pcbanks, PROBE)
        if pak is None:
            print(f"{build:8} ({PROBE} not found)")
            continue
        h = read_header(pak.read(name))
        guids[build] = h.guid
        tag = LIBMBIN_TAG.get(build, "(pre-release)")
        flag = "" if h.ok else " !bad-magic"
        print(f"{build:8} {h.version:>7}  {h.stamp_str:<16} 0x{h.guid:016X}  {tag:<12} {h.template}{flag}")
    if guids.get("1.24") is not None:
        for b in ("1.09.1", "1.13"):
            if b in guids:
                same = guids[b] == guids["1.24"]
                print(f"  {b} {PROBE} GUID {'==' if same else '!='} 1.24: "
                      f"{'1.24.4 struct def applies' if same else 'layout changed, needs exe/hand port'}")


if __name__ == "__main__":
    main()
