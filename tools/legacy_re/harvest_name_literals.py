"""Harvest functions that carry their own name as a profiler string literal.

Legacy builds wrap some functions in a profiler scope that does
``strncpy(buf, "cGcGameState::LoadFromPersistentStorage", 0x80)``, so the decompiled
C contains the function's real name. This maps each such literal to its containing
function and merges the result into nmspy/data/offsets.json.

A literal appearing in more than one function (inlined profiler scopes) is reported
and skipped rather than guessed at.

    python harvest_name_literals.py 1.13 1.24 1.38 [--write]
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from common import Binary

OFFSETS = Path(__file__).parents[2] / "nmspy" / "data" / "offsets.json"
NAME_RE = re.compile(r'"(c(?:Gc|Tk)\w+::~?\w+)"')


def harvest(build: str) -> dict:
    b = Binary(build)
    owners = defaultdict(set)
    for addr, decomp in b.db.execute(
        "SELECT address, raw_decomp FROM decompilations WHERE raw_decomp LIKE '%::%'"
    ):
        for name in set(NAME_RE.findall(decomp)):
            owners[name].add(addr)
    unique = {}
    for name, addrs in sorted(owners.items()):
        if len(addrs) == 1:
            unique[name] = next(iter(addrs))
        else:
            print(f"{build}: SKIP ambiguous {name}: {[hex(a) for a in sorted(addrs)]}")
    return unique


def main():
    builds = [a for a in sys.argv[1:] if not a.startswith("--")]
    write = "--write" in sys.argv
    data = json.loads(OFFSETS.read_text())
    for build in builds:
        found = harvest(build)
        for name, addr in found.items():
            entry = data["functions"].setdefault(name, {})
            existing = entry.get(build)
            if existing and int(existing, 16) != addr:
                sys.exit(f"{build}: MISMATCH {name}: json {existing} vs found 0x{addr:X}")
            entry[build] = f"0x{addr:X}"
        print(f"{build}: {len(found)} functions harvested")
    if write:
        OFFSETS.write_text(json.dumps(data, indent=2) + "\n")
        print(f"wrote {OFFSETS}")


if __name__ == "__main__":
    main()
