"""Extract metadata MBINs from a legacy build's PAKs and decompile them to EXML with the
era-matched MBINCompiler, so the struct field names/order can be read per version.

    python decompile.py 1.24                     # all *.GLOBAL.MBIN
    python decompile.py 1.24 GCENVIRONMENTGLOBALS # substring filter

Writes ``out/exml/<build>/*.exml``. The MBINCompiler binaries are third-party and not in
the repo: drop them in ``tools/mbin/bin/`` (see README.md for the source). Each build uses
the closest-era compiler; a mismatch is flagged so a struct that changed since that
compiler's era is not silently mis-decompiled.
"""
import glob
import os
import subprocess
import sys
from pathlib import Path

from mbin import read_header
from psarc import Psarc

HERE = Path(__file__).parent
BIN = HERE / "bin"
OUT = HERE / "out" / "exml"

PCBANKS = {
    "1.09.1": r"E:\NMSLegacy\no_mans_sky_v1.09.1\GAMEDATA\PCBANKS",
    "1.13": r"E:\NMSLegacy\no_mans_sky_v1.13\GAMEDATA\PCBANKS",
    "1.24": r"E:\NMSLegacy\no_mans_sky_v1.24\GAMEDATA\PCBANKS",
    "1.38": r"E:\NMSLegacy\no_mans_sky_v1.38\GAMEDATA\PCBANKS",
}
# era-matched MBINCompiler per build (exact where available)
COMPILER = {
    "1.09.1": "MBINCompiler.1.09.1.exe",
    "1.13": "MBINCompiler.1.13.2.exe",
    "1.24": "MBINCompiler.1.24.4.exe",
    "1.38": "MBINCompiler.1.38.0.2.exe",   # build from tag 1.38.0.2; zip copy was corrupt
}


def extract(build, name_filter):
    # dot-free dir: the old MBINCompiler mis-parses a folder path containing a dot as a
    # file with that "extension" (".24"), so "1.24" -> "1_24".
    workdir = OUT / build.replace(".", "_")
    workdir.mkdir(parents=True, exist_ok=True)
    seen = {}
    for p in sorted(glob.glob(os.path.join(PCBANKS[build], "*.pak"))):
        try:
            pak = Psarc(p)
        except Exception:
            continue
        for n in pak.names:
            up = n.upper()
            if up.endswith(".MBIN") and name_filter.upper() in up:
                base = up.rsplit("/", 1)[-1]
                if base in seen:
                    continue
                data = pak.read(n)
                (workdir / base).write_bytes(data)
                seen[base] = read_header(data).template
    return workdir, seen


def main():
    build = sys.argv[1]
    name_filter = sys.argv[2] if len(sys.argv) > 2 else ".GLOBAL.MBIN"
    exe = BIN / COMPILER[build]
    if not exe.exists():
        raise SystemExit(f"missing compiler {exe} (see tools/mbin/README.md for the source)")

    workdir, seen = extract(build, name_filter)
    print(f"[decompile] {build}: extracted {len(seen)} MBIN to {workdir}", file=sys.stderr)
    if not seen:
        return
    # MBINCompiler folder mode: decompiles every *.MBIN in the folder to *.exml beside it
    r = subprocess.run([str(exe), str(workdir)], capture_output=True, text=True)
    exml = list(workdir.glob("*.exml"))
    print(f"[decompile] {build}: wrote {len(exml)} EXML (compiler exit {r.returncode})", file=sys.stderr)
    if r.returncode != 0:
        print(r.stderr.strip()[-600:], file=sys.stderr)


if __name__ == "__main__":
    main()
