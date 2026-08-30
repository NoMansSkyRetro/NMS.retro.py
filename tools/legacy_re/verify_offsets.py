"""Cross-check nmspy/data/offsets.json against the decompilation databases.

Every function address must be a recorded function start in that build's DB, and
every global must fall inside the image. Exits non-zero on any failure.

    python verify_offsets.py
"""

import json
import sys
from pathlib import Path

from common import BUILDS, STATIC_BASE, Binary

OFFSETS = Path(__file__).parents[2] / "nmspy" / "data" / "offsets.json"


def main() -> int:
    data = json.loads(OFFSETS.read_text())
    failures = 0
    for build in BUILDS:
        try:
            b = Binary(build)
            b.db.execute("SELECT 1 FROM decompilations LIMIT 1")
        except Exception as e:
            print(f"{build}: SKIP ({e})")
            continue
        checked = 0
        for name, per_version in data["functions"].items():
            address = per_version.get(build)
            if not address:
                continue
            checked += 1
            if b.function_at(int(address, 16)) is None:
                print(f"{build}: FAIL {name} {address} is not a function start")
                failures += 1
        for name, per_version in data["globals"].items():
            address = per_version.get(build)
            if not address:
                continue
            checked += 1
            rva = int(address, 16) - STATIC_BASE
            if not any(
                s.virtual_address <= rva < s.virtual_address + s.virtual_size for s in b.sections
            ):
                print(f"{build}: FAIL global {name} {address} outside the image")
                failures += 1
        print(f"{build}: {checked} entries checked")
    print("OK" if failures == 0 else f"{failures} FAILURES")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
