"""Narrow anchor-starved targets to a small legacy address window by 4.13 source-file
adjacency, and auto-locate the rare unambiguous case.

Functions from one .cpp compile contiguously (ordered by source line). So an unmapped
target's nearest already-mapped same-file neighbours bracket a legacy address window it
must fall inside — a strong search constraint for functions that have no strings,
constants, or mapped callees. When the window holds exactly one legacy function and the
target is the only 4.13 function in it, that is a lock (rare at current coverage; the
windows tighten as more functions get mapped).

Source paths come from reference_symbol_db.json (81.5k/85.4k 4.13 functions).

    python locate_by_source.py            # self-check, write out/source_ranges.json, list locks
    python locate_by_source.py --write     # also merge the unambiguous locks into offsets.json

`out/source_ranges.json` gives, per still-missing target, the bracketing legacy window
and the functions inside it for each build — the lead an agent or a manual pass uses.
"""

import json
import sys
from bisect import bisect_left, bisect_right
from collections import defaultdict
from pathlib import Path

from common import BUILDS, Binary

REF = r"E:\AI_NMS_DISASM\NMS1091_GHIDRA_ANALYSIS\reference_symbol_db.json"
OFFSETS = Path(__file__).parents[2] / "nmspy" / "data" / "offsets.json"
TARGETS = Path(__file__).parent / "upstream_data_413.json"
VERSIONS = list(BUILDS)


def load_source_index():
    """source_file -> sorted list of (rva, mangled_name); plus name->rva, rva->names."""
    ref = json.load(open(REF))
    by_file = defaultdict(list)
    rva_of_mangled = {}
    for f in ref["functions"]:
        src = f.get("source_file")
        if not src:
            continue
        by_file[src].append((f["rva"], f["name"]))
        rva_of_mangled[f["name"]] = f["rva"]
    for src in by_file:
        by_file[src].sort()
    return by_file, rva_of_mangled, ref


def build_func_lists():
    return {b: sorted(a for a, _ in Binary(b).db.execute("SELECT address, size FROM decompilations"))
            for b in VERSIONS}


def propose(target_rva, by_file, file_of_rva, offsets_by_rva, funcs, build):
    """Return a legacy address for target_rva in `build`, or None.

    offsets_by_rva: {4.13 rva: legacy addr} for already-mapped functions in this build.
    """
    src = file_of_rva.get(target_rva)
    if src is None:
        return None
    file_funcs = by_file[src]
    rvas = [r for r, _ in file_funcs]
    i = bisect_left(rvas, target_rva)
    if i >= len(rvas) or rvas[i] != target_rva:
        return None
    # nearest mapped same-file anchor before and after
    prev_addr = prev_rva = None
    for j in range(i - 1, -1, -1):
        if rvas[j] in offsets_by_rva:
            prev_rva, prev_addr = rvas[j], offsets_by_rva[rvas[j]]
            break
    next_addr = next_rva = None
    for j in range(i + 1, len(rvas)):
        if rvas[j] in offsets_by_rva:
            next_rva, next_addr = rvas[j], offsets_by_rva[rvas[j]]
            break
    if prev_addr is None or next_addr is None or prev_addr >= next_addr:
        return None
    # The only reliable transfer: the target is the SOLE 4.13 same-file function
    # between two consecutive mapped anchors, and exactly ONE legacy function sits
    # between the anchors' legacy addresses. Then they must correspond. Any other
    # count can't be aligned across the six-year gap (lambdas/inlines shift it).
    n_413_between = sum(1 for r in rvas if prev_rva < r < next_rva)
    if n_413_between != 1:
        return None
    between = funcs[build][bisect_right(funcs[build], prev_addr):bisect_left(funcs[build], next_addr)]
    if len(between) != 1:
        return None
    return between[0]


def main():
    write = "--write" in sys.argv
    by_file, rva_of_mangled, ref = load_source_index()
    file_of_rva = {}
    for src, lst in by_file.items():
        for r, _ in lst:
            file_of_rva[r] = src
    funcs = build_func_lists()

    data = json.loads(OFFSETS.read_text())
    functions = data["functions"]
    targets = {e["name"]: e["mangled_name"] for e in json.loads(TARGETS.read_text())}

    # Map every offsets.json function that has a known 4.13 rva -> its legacy addrs.
    # Key on mangled name via the upstream list, else by matching undecorated name.
    name_to_rva = {}
    for name, mangled in targets.items():
        if mangled in rva_of_mangled:
            name_to_rva[name] = rva_of_mangled[mangled]

    offsets_by_rva = {b: {} for b in VERSIONS}
    for name, entry in functions.items():
        rva = name_to_rva.get(name)
        if rva is None:
            continue
        for b in VERSIONS:
            v = entry.get(b)
            if isinstance(v, str) and v.startswith("0x"):
                offsets_by_rva[b][rva] = int(v, 16)

    # --- validate precision: re-derive already-known targets, compare ---
    correct = wrong = 0
    for name, rva in name_to_rva.items():
        for b in VERSIONS:
            known = functions[name].get(b)
            if not (isinstance(known, str) and known.startswith("0x")):
                continue
            # hide this one from the anchor set, then propose
            saved = offsets_by_rva[b].pop(rva, None)
            got = propose(rva, by_file, file_of_rva, offsets_by_rva, funcs, b)
            if saved is not None:
                offsets_by_rva[b][rva] = saved
            if got is None:
                continue
            if got == int(known, 16):
                correct += 1
            else:
                wrong += 1
    print(f"source-adjacency self-check: correct={correct} wrong={wrong}")

    # --- unambiguous locks + range hints for NOT_YET_FOUND targets ---
    proposals = defaultdict(dict)   # confident single-function-window locks
    ranges = defaultdict(dict)      # {name: {build: {"window":[lo,hi], "funcs":[...], "n":N}}}
    for name, rva in name_to_rva.items():
        src = file_of_rva.get(rva)
        if not src:
            continue
        rvas = [r for r, _ in by_file[src]]
        i = bisect_left(rvas, rva)
        for b in VERSIONS:
            if functions[name].get(b) != "NOT_YET_FOUND":
                continue
            prev = next_ = None
            for j in range(i - 1, -1, -1):
                if rvas[j] in offsets_by_rva[b]:
                    prev = offsets_by_rva[b][rvas[j]]
                    break
            for j in range(i + 1, len(rvas)):
                if rvas[j] in offsets_by_rva[b]:
                    next_ = offsets_by_rva[b][rvas[j]]
                    break
            if prev is None or next_ is None or prev >= next_:
                continue
            window = funcs[b][bisect_right(funcs[b], prev):bisect_left(funcs[b], next_)]
            if len(window) <= 12:
                ranges[name][b] = {
                    "window": [f"0x{prev:X}", f"0x{next_:X}"],
                    "funcs": [f"0x{a:X}" for a in window],
                }
            got = propose(rva, by_file, file_of_rva, offsets_by_rva, funcs, b)
            if got is not None and Binary(b).function_at(got):
                proposals[name][b] = f"0x{got:X}"

    (Path(__file__).parent / "out" / "source_ranges.json").write_text(
        json.dumps(ranges, indent=1) + "\n"
    )
    tight = sum(1 for r in ranges.values() for w in r.values() if len(w["funcs"]) <= 3)
    print(f"range hints: {sum(len(v) for v in ranges.values())} bracketed slots "
          f"({tight} within 3 functions) -> out/source_ranges.json")
    total = sum(len(v) for v in proposals.values())
    print(f"unambiguous locks: {total} addresses across {len(proposals)} functions")
    for name, per in sorted(proposals.items()):
        print(f"  {name}: {per}")

    if write and proposals:
        for name, per in proposals.items():
            functions[name].update(per)
        OFFSETS.write_text(json.dumps(data, indent=2) + "\n")
        print(f"wrote {OFFSETS}")


if __name__ == "__main__":
    main()
