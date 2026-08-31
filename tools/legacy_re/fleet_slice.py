"""Focused dossier slice for a matching agent.

Given target function names, prints for each: its 4.13 profile (signature, size,
distinctive callees) and, for every mapped 1.38 anchor it hangs off, the anchor's
decompiled body plus the anchor's callees whose size is in the target's plausible band,
each with its own decompiled body. The agent reads this and decides which 1.38 callee
address (if any) IS the target, or reports it inlined/fused/absent.

    python fleet_slice.py 1.38 cGcInteractionComponent::GetPuzzle cGcSky::SetSunAngle ...

First arg is the build. Reads out/dossiers_<build>.json (from `ghidra_live.py dossier`),
out/anchor_worklist_<build>.json, and out/target_hints.json. Pure stdout; deterministic.
The 1.38 files may also be named out/dossiers_138.json / out/anchor_worklist.json.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent


def _load(build):
    tag = build.replace(".", "")
    for name in (f"dossiers_{tag}.json", f"dossiers_{build}.json"):
        p = HERE / "out" / name
        if p.exists():
            dossiers = json.loads(p.read_text())
            break
    else:
        raise SystemExit(f"no dossier file for build {build}")
    for name in (f"anchor_worklist_{build}.json", "anchor_worklist.json"):
        p = HERE / "out" / name
        if p.exists():
            worklist = json.loads(p.read_text())
            break
    else:
        raise SystemExit(f"no worklist for build {build}")
    return dossiers, worklist


BUILD = sys.argv[1] if len(sys.argv) > 1 else "1.38"
DOSSIERS, WORKLIST = _load(BUILD)
HINTS = json.loads((HERE / "out" / "target_hints.json").read_text())

ANCHOR_DECOMP_CAP = 4000     # chars of anchor body (the call context)
CALLEE_DECOMP_CAP = 2600     # chars per candidate body


def band(modern_len):
    # legacy size drifts from 4.13; keep a wide band so nothing is filtered out wrongly
    lo = max(8, int(modern_len * 0.30))
    hi = max(400, int(modern_len * 4.0))
    return lo, hi


def emit(target):
    info = WORKLIST.get(target)
    h = HINTS.get(target, {})
    print(f"\n{'='*78}\nTARGET: {target}")
    print(f"  4.13 signature: {h.get('modern_signature')}")
    print(f"  4.13 size: {h.get('modern_length')} bytes")
    print(f"  4.13 distinctive callees: {info['modern_callees'] if info else h.get('modern_callees')}")
    if not info:
        print("  (no mapped 1.38 anchor in the work-list)")
        return
    lo, hi = band(h.get("modern_length") or 300)
    anchors = info.get("anchors_va") or info.get("anchors_138") or {}
    for aname, ava in anchors.items():
        dos = DOSSIERS.get(ava)
        print(f"\n  ---- ANCHOR {aname} @ {ava} ----")
        if not dos or "callees" not in dos:
            print("    (anchor not in dossier extract)")
            continue
        body = dos.get("anchor_decomp") or ""
        print(f"    anchor size {dos.get('anchor_size')}; body (call context):")
        print("    " + body[:ANCHOR_DECOMP_CAP].replace("\n", "\n    "))
        cands = [c for c in dos["callees"] if lo <= c["size"] <= hi]
        print(f"\n    CANDIDATE callees in size band [{lo},{hi}] ({len(cands)} of {len(dos['callees'])}):")
        for c in sorted(cands, key=lambda x: x["size"]):
            print(f"\n    * candidate {c['va']}  size={c['size']}  named_callees={c['named_callees']}")
            if c.get("decomp"):
                print("      " + c["decomp"][:CALLEE_DECOMP_CAP].replace("\n", "\n      "))


def main():
    for t in sys.argv[2:]:
        emit(t)


if __name__ == "__main__":
    main()
