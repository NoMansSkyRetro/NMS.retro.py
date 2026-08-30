"""Finder for the "base_building" batch.

Targets (cGcBaseBuildingManager / cGcBaseSearch / cGcBuilding /
cGcPlayerBasePersistentBuffer). Base building shipped with Foundation (1.1), so the
manager/search/persistent-buffer slots do not exist in 1.09.1 (already flagged
NOT_IN_THIS_VERSION in offsets.json); only 1.13/1.24/1.38 are hunted for those.
cGcBuilding lives in simulation/solarsystem/buildings and predates Foundation, so it
is hunted in all four builds.

Run from tools/legacy_re/:  python finders/find_base_building.py
Prints one JSON object to stdout; all reasoning goes to stderr.

Result summary
--------------
Resolved (all four builds):
  cGcBuilding::Visited      via the DISC_WAYPOINTS anchor + a unique void(this,bool)
                            signature (self-recursive from 1.13 on; sets the visited
                            flag; strupr's DISC_WAYPOINTS; saves an interaction).

Unresolved (honest, see per-entry reasons):
  cGcBuilding::DestroyIntersectingVolcanoes   "VOLCANO" (an inline 8-byte immediate
        in 4.13) is absent from every legacy .text and .rdata -- the volcano-landmark
        feature post-dates 1.38.
  cGcBaseBuildingManager::Update (1.13 only; 1.24/1.38 already curated)   both curated
        addresses centre on the OffensiveBaseScreenshot.dds handling; that string /
        feature is absent from 1.13 and cGcSimulation::Update does not call it directly.
  cGcBaseBuildingManager::{AddHUDMarker, GetBaseBuildingRootMatrix, GetBaseRootNode},
  cGcBaseSearch::FindNearestBaseInCurrentSystem,
  cGcPlayerBasePersistentBuffer::LoadGalacticAddress   no distinctive string/imm
        fingerprint (only the shared sentinel 0xEEEEEEEEEEEEEEEF). Call-graph anchoring
        failed: AddHUDMarker / GetBaseBuildingRootMatrix / LoadGalacticAddress have
        zero mapped callees or callers in the propagated data; for GetBaseRootNode and
        FindNearestBaseInCurrentSystem the mapped anchors are polluted (e.g. the
        "Engine::AddGroupNode" mapping is actually a TkID resolver) and every surviving
        candidate fails the decompiled signature check. Committing any of these would be
        a guess, so they are left unresolved per protocol.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import Binary  # noqa: E402

BUILDS = ["1.09.1", "1.13", "1.24", "1.38"]

# Visited(bool): void method taking (this, char). Ghidra renders this exactly as a
# one-pointer-one-char signature. The other DISC_WAYPOINTS users are multi-argument
# (the interaction/waypoint handlers) or the giant dispatch blob, so this is unique.
VISITED_SIG = re.compile(r"\bvoid FUN_[0-9a-fA-F]+\(longlong \*param_\w+,char param_\w+\)")


def find_visited(b: Binary):
    """cGcBuilding::Visited -- anchored on the DISC_WAYPOINTS string it strupr's."""
    rows = b.functions_matching("%DISC_WAYPOINTS%", 40)
    hits = []
    for name, addr, size in rows:
        row = b.function_at(addr)
        if not row:
            continue
        decomp = row[3] or ""
        if "DISC_WAYPOINTS" in decomp and VISITED_SIG.search(decomp):
            hits.append((addr, size))
    if len(hits) == 1:
        addr = hits[0][0]
        print(f"[{b.build}] Visited -> {hex(addr)} (unique DISC_WAYPOINTS + void(this,bool))",
              file=sys.stderr)
        return addr
    print(f"[{b.build}] Visited: expected 1 signature match, got {len(hits)}: "
          f"{[hex(a) for a, _ in hits]}", file=sys.stderr)
    return None


def main():
    functions: dict[str, dict] = {}
    unresolved: dict[str, str] = {}

    # ---- resolved: cGcBuilding::Visited (all four builds) ----
    visited = {}
    for build in BUILDS:
        b = Binary(build)
        va = find_visited(b)
        if va is not None:
            # confirm it is a real function start before emitting
            assert b.function_at(va), f"{build}: {hex(va)} not a function start"
            visited[build] = f"0x{va:X}"
    if visited:
        functions["cGcBuilding::Visited"] = visited

    # ---- honest unresolved ----
    unresolved["cGcBuilding::DestroyIntersectingVolcanoes"] = (
        "'VOLCANO' (inline 8-byte immediate in 4.13) absent from every legacy "
        ".text/.rdata; no caller/callee match. Volcano-landmark feature post-dates 1.38."
    )
    unresolved["cGcBaseBuildingManager::Update"] = (
        "1.13 only (1.24/1.38 curated): both curated addresses handle "
        "OffensiveBaseScreenshot.dds, a string/feature absent from 1.13; "
        "cGcSimulation::Update does not call it directly, so no reliable 1.13 counterpart."
    )
    unresolved["cGcBaseBuildingManager::AddHUDMarker"] = (
        "No string/imm fingerprint; zero mapped callees/callers in propagated data."
    )
    unresolved["cGcBaseBuildingManager::GetBaseBuildingRootMatrix"] = (
        "Only shared sentinel 0xEEEEEEEEEEEEEEEF; zero mapped callees, callers unmapped."
    )
    unresolved["cGcBaseBuildingManager::GetBaseRootNode"] = (
        "No distinctive tokens; propagated callee anchors mislabeled (the "
        "'Engine::AddGroupNode' mapping is a TkID resolver) and candidates fail the "
        "decompiled signature check."
    )
    unresolved["cGcBaseSearch::FindNearestBaseInCurrentSystem"] = (
        "Callee/caller anchoring yields only candidates whose signatures contradict "
        "BaseIndex(cTkVector3 const&, ePersistentBaseTypes) (void/1-arg, or a strlen "
        "helper); no two-signal confirmation."
    )
    unresolved["cGcPlayerBasePersistentBuffer::LoadGalacticAddress"] = (
        "NMS-Newton hook; no string/imm fingerprint and zero mapped callees/callers in "
        "the propagated data."
    )

    print(json.dumps({"functions": functions, "unresolved": unresolved}))


if __name__ == "__main__":
    main()
