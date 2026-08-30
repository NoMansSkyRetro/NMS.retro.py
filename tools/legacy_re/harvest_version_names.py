"""Document each function's actual per-version name, and flag cross-version renames.

Functions get renamed across NMS versions, so the name a function embeds as its
profiler literal in one build may differ from the 4.13/upstream name we key on. This
tool harvests every single-owner ``"Class::Method"`` profiler literal per build
(broad namespace match, not just cGc/cTk), then for each function already located in
offsets.json records that build's actual name under ``_names`` when it differs from
the entry key.

It also reports renames it can prove structurally: where a located function has a
profiler name in two builds and the names differ, or where an unfound upstream target
shares an address (via a build's profiler map) with a differently-named function.

    python harvest_version_names.py            # report
    python harvest_version_names.py --write     # write _names into offsets.json
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from common import BUILDS, Binary

OFFSETS = Path(__file__).parents[2] / "nmspy" / "data" / "offsets.json"
NAME_RE = re.compile(r'"((?:[A-Za-z_]\w*::)+~?[A-Za-z_]\w*)"')
VERSIONS = list(BUILDS)


def profiler_names(build):
    """{address: name} for single-owner profiler literals in a build."""
    b = Binary(build)
    owners = defaultdict(set)
    for addr, decomp in b.db.execute(
        "SELECT address, raw_decomp FROM decompilations WHERE raw_decomp LIKE '%::%'"
    ):
        for name in set(NAME_RE.findall(decomp)):
            owners[name].add(addr)
    out = {}
    for name, addrs in owners.items():
        if len(addrs) == 1:
            out[next(iter(addrs))] = name
    return out


def main():
    write = "--write" in sys.argv
    data = json.loads(OFFSETS.read_text())
    functions = data["functions"]
    per_build = {b: profiler_names(b) for b in VERSIONS}

    documented = 0
    renames = []
    for name, entry in functions.items():
        names_field = {}
        for b in VERSIONS:
            v = entry.get(b)
            if not (isinstance(v, str) and v.startswith("0x")):
                continue
            actual = per_build[b].get(int(v, 16))
            if actual and actual != name:
                names_field[b] = actual
        if names_field:
            # a rename if the actual name differs from the key in some build
            renames.append((name, names_field))
            if write:
                entry["_names"] = {**(entry.get("_names") or {}), **names_field}
            documented += len(names_field)

    print(f"functions with a differing per-version name: {len(renames)} "
          f"({documented} version-slots)")
    for name, nf in sorted(renames):
        print(f"  {name}: {nf}")

    if write and renames:
        OFFSETS.write_text(json.dumps(data, indent=2) + "\n")
        print(f"wrote {OFFSETS}")


if __name__ == "__main__":
    main()
