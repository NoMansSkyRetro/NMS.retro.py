"""Commit fleet decompiler-in-the-loop matches: 1.38 addresses located by reading Ghidra
decompilation against the 4.13 profile (see match_workflow.js / HUNTING.md method 6),
ported sideways to the other builds.

Reads out/fleet_confirmed.json:
    {"confirmed": {"cGcX::Y": "0x1408...", ...},   # 1.38 addresses (verified by the fleet)
     "unresolved": {"cGcX::Z": "inlined into ...", ...}}

For each confirmed target it emits the 1.38 address plus, via handles.Xverse.port() (high
precision; only commits a build when the distinctive-token and call-graph winners agree),
the address in the other three builds. merge_finder_results.py re-validates every address
as a real function start and never overwrites a curated value, so a wrong 1.38 guess that
somehow slipped the fleet's verify still cannot corrupt an existing slot; and a 1.38
address that fails to port simply lands 1.38-only.

    python finders/find_anchor_matches.py            # prints the merge JSON contract
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from handles import Xverse  # noqa: E402

HERE = Path(__file__).resolve().parents[1]
CONFIRMED = HERE / "out" / "fleet_confirmed.json"


def main():
    data = json.loads(CONFIRMED.read_text()) if CONFIRMED.exists() else {"confirmed": {}, "unresolved": {}}
    confirmed = data.get("confirmed", {})
    unresolved = data.get("unresolved", {})
    if not confirmed:
        print(json.dumps({"functions": {}, "unresolved": unresolved}))
        return

    xv = Xverse(verbose=True)
    out_funcs = {}
    for name, va138 in confirmed.items():
        va = int(va138, 16)
        if not xv.is_func("1.38", va):
            print(f"[anchor_matches] SKIP {name}: 0x{va:X} not a 1.38 function start", file=sys.stderr)
            continue
        slots = {"1.38": f"0x{va:X}"}
        ported = xv.port("1.38", va)
        for b, addr in ported.items():
            if b != "1.38" and xv.is_func(b, addr):
                slots[b] = f"0x{addr:X}"
        out_funcs[name] = slots
        print(f"[anchor_matches] {name}: {slots}", file=sys.stderr)

    print(json.dumps({"functions": out_funcs, "unresolved": unresolved}))


if __name__ == "__main__":
    main()
