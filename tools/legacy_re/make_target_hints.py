"""Precompute hunting hints for every NOT_YET_FOUND upstream function.

For each target, dumps what the modern (4.13) implementation looks like so a legacy
hunt has something version-stable to search for:

- referenced string literals (distinctive ones first) and imm64 TkID constants,
- named callees and callers from the 4.13 call graph,
- the PDB signature, source file and function length.

Output: out/target_hints.json — the shared evidence base for cross-version work.

    python make_target_hints.py
"""

import json
from pathlib import Path

from propagate_symbols import REF_413, load_side_413, load_targets

OFFSETS = Path(__file__).parents[2] / "nmspy" / "data" / "offsets.json"
OUT = Path(__file__).parent / "out" / "target_hints.json"
VERSIONS = ["1.09.1", "1.13", "1.24", "1.38"]


def main():
    side, ref_names, ref_mangled = load_side_413()
    targets = load_targets(ref_mangled)
    ref_db = {f["name"]: f for f in json.load(open(REF_413))["functions"]}

    offsets = json.loads(OFFSETS.read_text())["functions"]
    upstream = json.loads((Path(__file__).parent / "upstream_data_413.json").read_text())
    by_name = {e["name"]: e for e in upstream}

    hints = {}
    for name, entry in offsets.items():
        if name not in by_name:
            continue
        missing = [v for v in VERSIONS if entry.get(v) == "NOT_YET_FOUND"]
        if not missing:
            continue
        va = targets.get(name)
        pdb = ref_db.get(by_name[name]["mangled_name"])
        tokens = side.prints.get(va, set())
        strings = sorted(
            (t.decode("ascii", "replace") for t in tokens if isinstance(t, bytes)),
            key=lambda s: (s not in _distinct_strs(side), len(s)),
        )[:25]
        imms = sorted(f"0x{t[1]:X}" for t in tokens if isinstance(t, tuple))[:15]
        callees = sorted(
            {ref_names[c] for c in side.callees.get(va, ()) if not ref_names.get(c, "").startswith("FUN_")}
        )[:20] if va else []
        callers = sorted(
            {ref_names[c] for c in side.callers.get(va, ()) if not ref_names.get(c, "").startswith("FUN_")}
        )[:20] if va else []
        hints[name] = {
            "missing_in": missing,
            "modern_signature": (pdb or {}).get("signature"),
            "source_file": (pdb or {}).get("source_file"),
            "modern_length": (pdb or {}).get("length"),
            "strings": strings,
            "imm64": imms,
            "modern_callees": callees,
            "modern_callers": callers,
        }

    OUT.write_text(json.dumps(hints, indent=1) + "\n")
    with_strings = sum(1 for h in hints.values() if h["strings"])
    print(f"wrote {OUT}: {len(hints)} targets, {with_strings} with string evidence")


_distinct_cache = None


def _distinct_strs(side):
    global _distinct_cache
    if _distinct_cache is None:
        _distinct_cache = {
            t.decode("ascii", "replace") for t in side.distinctive if isinstance(t, bytes)
        }
    return _distinct_cache


if __name__ == "__main__":
    main()
