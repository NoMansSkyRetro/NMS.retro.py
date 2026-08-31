"""Commit cross-build decompiler-in-the-loop matches for functions already located in
1.38 (see match_workflow_older.js). Reads out/fleet_confirmed_older.json:

    {"1.24": {"cGcX::Y": "0x140...", ...}, "1.13": {...}, "1.09.1": {...}}

Each address was located directly in that build (not ported), so it is emitted as-is;
merge_finder_results.py re-validates every one as a real function start and refuses to
overwrite a curated slot.

    python finders/find_anchor_matches_older.py            # prints the merge JSON contract
"""
import json
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
CONFIRMED = HERE / "out" / "fleet_confirmed_older.json"


def main():
    per_build = json.loads(CONFIRMED.read_text()) if CONFIRMED.exists() else {}
    funcs = defaultdict(dict)
    for build, matches in per_build.items():
        for name, va in matches.items():
            if str(va).startswith("0x"):
                funcs[name][build] = va
    print(json.dumps({"functions": funcs, "unresolved": {}}))


if __name__ == "__main__":
    main()
