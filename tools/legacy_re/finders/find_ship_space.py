"""Finder for the ``ship_space`` batch (spaceship / ship-HUD / ship-freighter-vehicle
ownership functions).

Deterministic, self-contained. Prints one JSON object to stdout:
    {"functions": {name: {build: "0x..."}}, "unresolved": {name: "reason"}}
All reasoning is logged to stderr.

Two targets are located with two independent signals each and committed; the rest are
left unresolved with a specific reason (see the module docstring notes at the bottom of
each block). Honest ``unresolved`` is preferred over call-graph guesses that the sibling
ownership/getter functions cannot be distinguished from.

Confirmed:

* ``cGcShipHUD::ReadPlanetStats`` (all four builds). Signal 1: it is the unique
  non-render function that calls ``DiscoveryResolver::ComputeDisplayNameAndOwnerForDiscovery``
  (a modern callee, address known from out/propagated_<build>.json) AND is called by a
  cGcShipHUD render function (RenderHeadsUp, and RenderFlightHUD where it exists; known
  from offsets.json). Signal 2: in 1.38 it additionally references the ReadPlanetStats
  string set (DISC_TYPE_MOON / UI_UNKNOWN_PLANET / DISC_OWNER_NOT_VISITED) and a seeded
  call-graph vote ranks it #1 with a clear gap.
* ``cGcSpaceshipComponent::UpdateControlled`` (all four builds). The debug-tuning string
  ``"CRUISE: Max Boost"`` is referenced by exactly one function per build; that function
  is the ~23-26 KB spaceship-flight update, i.e. UpdateControlled. Single-owner string.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import Binary  # noqa: E402

HERE = Path(__file__).resolve().parents[1]
OFFSETS = HERE.parents[1] / "nmspy" / "data" / "offsets.json"
BUILDS = ["1.09.1", "1.13", "1.24", "1.38"]


def log(*a):
    print(*a, file=sys.stderr)


def callers_via_decomp(b, va):
    """Functions whose decompilation references FUN_<va> (i.e. call it), excluding self."""
    return [a for _, a, _ in b.functions_matching(f"%FUN_{va:x}%", 400) if a != va]


def find_read_planet_stats(build, offsets):
    """The cGcShipHUD planet-stat reader: unique caller-of-Compute that a render calls."""
    b = Binary(build)
    prop = json.loads((HERE / "out" / f"propagated_{build}.json").read_text())
    comp = prop.get("DiscoveryResolver::ComputeDisplayNameAndOwnerForDiscovery")
    if not comp:
        return None, "no ComputeDisplayNameAndOwnerForDiscovery anchor in propagated"
    comp_va = int(comp["address"], 16)

    renders = []
    for name in ("cGcShipHUD::RenderHeadsUp", "cGcShipHUD::RenderFlightHUD"):
        v = offsets["functions"].get(name, {}).get(build)
        if isinstance(v, str) and v.startswith("0x"):
            renders.append(int(v, 16))
    if not renders:
        return None, "no cGcShipHUD render anchor in offsets.json"

    comp_callers = set(callers_via_decomp(b, comp_va))
    # Of those, keep the ones that a render function calls (render's decomp references them).
    render_decomps = {r: b.function_at(r)[3] for r in renders}
    hits = []
    for ca in comp_callers:
        if ca in renders:
            continue
        calling_renders = [r for r, d in render_decomps.items() if f"FUN_{ca:x}" in d]
        if calling_renders:
            hits.append((ca, len(calling_renders)))
    if not hits:
        return None, "no caller-of-Compute is called by a cGcShipHUD render function"
    # Prefer the one called by the most render functions; require a unique winner.
    hits.sort(key=lambda t: -t[1])
    best = [h for h in hits if h[1] == hits[0][1]]
    if len(best) != 1:
        return None, f"ambiguous ReadPlanetStats candidates: {[hex(a) for a,_ in best]}"
    va = best[0][0]
    if b.function_at(va) is None:
        return None, f"0x{va:X} is not a function start"
    log(f"  {build} ReadPlanetStats = 0x{va:X} (calls Compute 0x{comp_va:X}, "
        f"called by {best[0][1]} render fn)")
    return va, None


def find_update_controlled(build):
    """The single function referencing the 'CRUISE: Max Boost' flight-tuning string."""
    b = Binary(build)
    rows = b.db.execute(
        "SELECT address, size FROM decompilations WHERE raw_decomp LIKE '%CRUISE: Max Boost%' "
        "ORDER BY size DESC"
    ).fetchall()
    if not rows:
        return None, "no function references 'CRUISE: Max Boost'"
    if len(rows) != 1:
        return None, f"'CRUISE: Max Boost' referenced by {len(rows)} functions"
    va, size = rows[0]
    if size < 8000:
        return None, f"candidate 0x{va:X} too small ({size}B) to be UpdateControlled"
    if b.function_at(va) is None:
        return None, f"0x{va:X} is not a function start"
    log(f"  {build} UpdateControlled = 0x{va:X} ({size}B, single 'CRUISE: Max Boost' owner)")
    return va, None


UNRESOLVED_REASONS = {
    # Ownership cluster (multi-ship / vehicle / freighter). In the unsymbolized legacy
    # decomp the sibling ownership updates (ship/creature/freighter/vehicle), all called
    # by cGcGameState::Update/::cGcGameState and all built on cGcPlacementArc, are not
    # distinguishable by call-graph structure alone; seeded call-graph votes tie among
    # them with no distinctive string/imm64 to break it. No confident anchor.
    "cGcPlayerShipOwnership::DestroyShip":
        "1.24/1.38 only; no distinctive string/imm; call-graph vote ties among ship-ownership siblings",
    "cGcPlayerShipOwnership::GetShipComponent":
        "1.24/1.38 only; tiny accessor, no unique anchor; vote non-unique",
    "cGcPlayerShipOwnership::SpawnNewShip":
        "1.24/1.38 only; hint string 'cGcCustomisationComponentData' not a literal in legacy decomp; vote non-unique",
    "cGcPlayerShipOwnership::Update":
        "1.24/1.38 only; only caller cGcGameState::Update also parents 3 near-identical ownership updates; vote ties",
    "cGcPlayerShipOwnership::UpdateMeshRefresh":
        "1.24/1.38 only; private helper of ::Update but ::Update itself unresolved; no anchor",
    "cGcPlayerShipOwnership::cGcPlayerShipOwnership":
        "1.24/1.38 only; ctor shares all seeded callees with cGcPlayerVehicleOwnership ctor; indistinguishable by call-graph",
    "cGcPlayerVehicleOwnership::cGcPlayerVehicleOwnership":
        "1.24/1.38 only; ctor shares all seeded callees with cGcPlayerShipOwnership ctor; indistinguishable by call-graph",
    "cGcPlayerFreighterOwnership::ResetPlayerFreighterBase":
        "string UI_FREIGHT_BASE_RESET_OWNER_OSD / imm64 0xA3784A062B2E43DB absent in 1.13-1.38 (freighter-base feature post-dates 1.38)",
    "cGcPlayerFreighterOwnership::cGcPlayerFreighterOwnership":
        "1.13-1.38; no strings/imm; ctor call-graph indistinct from sibling ownership ctors",
    # Ship HUD ctor.
    "cGcShipHUD::cGcShipHUD":
        "constructor: only 1 seeded neighbour, no vtable/string anchor; call-graph vote non-unique",
    # Spaceship component / warp / weapons getters.
    "cGcSpaceshipComponent::Eject":
        "no distinctive string/imm; seeded neighbours only via 2 callers; vote ties across builds",
    "cGcSpaceshipComponent::GetVelocity":
        "34-byte accessor (rigidbody GetLinearVelocity); inlined in legacy callers, no standalone function found",
    "cGcSpaceshipWarp::GetPulseDriveFuelFactor":
        "84-byte stat getter; one of many indistinguishable small callers of GetPrimaryItemForStat; vote score 1, non-unique",
    "cGcSpaceshipWarp::UpdatePulseDrive":
        "target_hints signature is mismatched (points at cGcPlayerExperienceDirector::UpdatePulseEncounters); no reliable anchor",
    "cGcSpaceshipWeapons::GetAverageBarrelPos":
        "no strings/imm and none of its 4.13 call-neighbours are in the propagated seed; no anchor",
    "cGcSpaceshipWeapons::GetCurrentShootPoints":
        "no strings/imm and no seeded call-neighbours; cTkHmdOpenVR::GetInstance / GetTypedComponent anchors unavailable",
    "cGcSpaceshipWeapons::GetHeatFactor":
        "17-byte header (.h) inline accessor; not emitted as a standalone function in legacy builds",
    "cGcSpaceshipWeapons::GetOverheatProgress":
        "39-byte inline accessor; no call-neighbours seeded; not separately identifiable",
}


def main():
    offsets = json.loads(OFFSETS.read_text())
    functions = {}
    unresolved = {}

    log("== cGcShipHUD::ReadPlanetStats ==")
    rps = {}
    for build in BUILDS:
        va, err = find_read_planet_stats(build, offsets)
        if va is not None:
            rps[build] = f"0x{va:X}"
        else:
            log(f"  {build}: {err}")
    if rps:
        functions["cGcShipHUD::ReadPlanetStats"] = rps

    log("== cGcSpaceshipComponent::UpdateControlled ==")
    uc = {}
    for build in BUILDS:
        va, err = find_update_controlled(build)
        if va is not None:
            uc[build] = f"0x{va:X}"
        else:
            log(f"  {build}: {err}")
    if uc:
        functions["cGcSpaceshipComponent::UpdateControlled"] = uc

    for name, reason in UNRESOLVED_REASONS.items():
        unresolved[name] = reason

    json.dump({"functions": functions, "unresolved": unresolved}, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
