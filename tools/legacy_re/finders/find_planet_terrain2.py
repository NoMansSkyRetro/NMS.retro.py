"""Round-2 finder for the ``planet_terrain`` batch.

Round 1 (``find_planet_terrain.py``) already mapped Construct / SetDefaults /
GenerateCreatureRoles / GenerateCreatureInfo / cGcSky::Update / UpdateRender(1.13+)
and the 1.38 SpawnData/Fill pair.  This round revisits the remaining
NOT_YET_FOUND slots with the handles.py cross-version toolkit and the newer
propagated anchors (cGcPlanet::UpdatePhase2, cGcTerrainEditorBeam::{Construct,
Update,UpdateRender}, cGcPlayerWeapon::Fire, cTkResourceDescriptor::GenerateInstance).

NEW find (all four builds)
--------------------------
cGcSky::UpdateSunPosition -- the single callee of the mapped cGcSky::Update whose
  body is void(this), ~1126 bytes, and calls BOTH cTkTrig::Cos and cTkTrig::Sin
  (the trig pair is located per build by porting the 1.38 Cos/Sin leaves).  In every
  build this predicate has exactly one match and the size is identically 1126.
  Decompilation confirms the same function in 1.09.1 and 1.38: it copies a vec3
  (sky+0x320..0x328 -> +0x330..0x338, w=1), derives the sun angle from time-of-day,
  and rotates the sun axis with the Sin/Cos polynomials.  In these builds
  cGcSky::SetSunAngle(float) is fused (inlined) into this function -- there is no
  separate small GetSunDirection-calling callee -- so SetSunAngle stays unresolved.

Everything else is left unresolved with the specific obstacle (see UNRESOLVED); the
reasons were re-verified this round and are no longer just inherited from round 1:

* UpdateWeather/UpdateClouds/UpdateGravity -- the storm code lives in cGcSky::Update
  (it is the ONLY caller of the mapped cGcSky::SetStormState in every build), so
  cGcPlanet::UpdateWeather is not a distinct legacy function; and neither a ~784 B
  Cos+Sin cloud leaf nor a ~171 B gravity leaf appears among cGcSky::Update's or
  cGcPlanet::UpdatePhase2's callees -- the weather->clouds/gravity split postdates
  these builds.
* Terrain-editor beam (1.38-only) -- Construct/Update/UpdateRender are now anchored
  and cGcPlayerWeapon::Fire (0x140E4EF20) is mapped, but none of Fire's callees in
  the terrain unit calls two big single-caller ApplyTerrainEdit* functions the way
  modern Fire does; the Flatten/Stroke split (and a separately-emitted StartEffect)
  postdate 1.38, and the distinctive callees stay unmapped.
* GenerateQueryInfo -- the two "TkID" imm64s are not distinctive (150+ occurrences
  each in .text), so they cannot lock a function; its unique caller
  cGcSolarSystemQuery::Run is unmapped.
* CreateGenerationTask -- restructured: it is not a direct caller of the mapped
  cTkResourceDescriptor::GenerateInstance in 1.38 (no ~452 B / 16-caller match), and
  its 16 callers give tied call-graph votes.
* SpawnData/Fill (1.09.1/1.13/1.24) -- port() picks a Generate-callee in each build,
  but the size drifts backwards in time (Fill 1704 modern -> 1744 in 1.38 -> 3477 in
  1.24), which is implausible for one function; the port is matching a different
  Generate-callee, so these are not committed.
* cGcEnvironment::UpdateRender (1.09.1) -- absent: its uniform strings
  (gLightOriginVec4 etc.) do not exist in 1.09.1 and it is not among the callees of
  the (derived) cGcSimulation::UpdateRender there -- the reflection-probe render was
  inlined/added later.
* cGcEnvironment::Update -- no string/imm/callee anchor at all.

Run from tools/legacy_re/:  python finders/find_planet_terrain2.py
Prints one JSON object to stdout; all reasoning goes to stderr.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from handles import Xverse  # noqa: E402

BUILDS = ["1.09.1", "1.13", "1.24", "1.38"]

# Anchors (committed in offsets.json).
SKY_UPDATE = {
    "1.09.1": 0x140986910,
    "1.13": 0x140AE4B80,
    "1.24": 0x140C5A670,
    "1.38": 0x140DEDBC0,
}
# 1.38 cTkTrig::Cos / cTkTrig::Sin leaves (used only as port seeds).
COS_138 = 0x1406E6360
SIN_138 = 0x1406E6440


def log(*a):
    print(*a, file=sys.stderr)


def find_update_sun_position(xv):
    """cGcSky::UpdateSunPosition per build: the unique void(this) ~1126 B callee of
    cGcSky::Update that calls both Cos and Sin."""
    cos = xv.port("1.38", COS_138)
    sin = xv.port("1.38", SIN_138)
    log("  Cos ports:", {b: hex(v) for b, v in cos.items()})
    log("  Sin ports:", {b: hex(v) for b, v in sin.items()})
    out = {}
    for b in BUILDS:
        sky = SKY_UPDATE[b]
        cos_b, sin_b = cos.get(b), sin.get(b)
        if cos_b is None or sin_b is None:
            log(f"  {b}: no ported trig leaf; skip")
            continue
        cands = []
        for a in xv.callees(b, sky):
            nm = xv.name(b, a)
            if not nm:
                continue
            sz = nm[1]
            if not (900 <= sz <= 1400):
                continue
            cl = set(xv.callees(b, a))
            if cos_b in cl and sin_b in cl:
                cands.append((a, sz))
        if len(cands) == 1:
            va, sz = cands[0]
            out[b] = va
            log(f"  {b}: UpdateSunPosition = 0x{va:X} (size {sz})")
        else:
            log(f"  {b}: ambiguous UpdateSunPosition candidates: "
                f"{[(hex(a), s) for a, s in cands]}")
    return out


UNRESOLVED = {
    "cGcSky::SetSunAngle":
        "fused (inlined) into cGcSky::UpdateSunPosition in these builds: the "
        "angle->sun-direction rotation is the tail of UpdateSunPosition and there is "
        "no separate small GetSunDirection-calling callee to latch onto.",
    "cGcPlanet::UpdateWeather":
        "not a distinct legacy function -- the storm logic is in cGcSky::Update, the "
        "sole caller of the mapped cGcSky::SetStormState in every build; "
        "cGcPlanet::UpdatePhase2 has no callee that calls SetStormState.",
    "cGcPlanet::UpdateClouds":
        "no ~784 B Cos+Sin cloud leaf among cGcSky::Update's or UpdatePhase2's callees; "
        "the UpdateWeather->UpdateClouds split postdates these builds and there is no "
        "distinctive token.",
    "cGcPlanet::UpdateGravity":
        "no ~171 B cTkDynamicGravityControl leaf among UpdatePhase2's/Sky::Update's "
        "callees; the gravity leaf has no mapped callee (cTkDynamicGravityControl is "
        "unmapped) and no distinctive token.",
    "cGcEnvironment::Update":
        "no PDB entry with a unique 4.13 VA (overloaded/inlined); no string, imm, or "
        "mapped callee/caller anchor.",
    "cGcEnvironment::UpdateRender":
        "1.09.1 only: absent -- its uniform strings (gLightOriginVec4/ProbeReflections) "
        "do not exist in 1.09.1 and it is not among the callees of the derived "
        "cGcSimulation::UpdateRender (0x14086CB40); the probe-reflection render path "
        "was inlined/added after 1.09.1.",
    "cGcPlanetGenerator::GenerateCreatureSpawnData":
        "1.09.1/1.13/1.24: port() picks a Generate-callee but its size drifts backwards "
        "(641 B in 1.38 -> 1095/1124/1891 in older builds), implausible for one "
        "function; no callee/string tiebreaker, so not committed. 1.38 curated already.",
    "cGcPlanetGenerator::FillCreatureSpawnDataFromDescription":
        "1.09.1/1.13/1.24: the ported 'Fill' exclusive callee is 3168-3477 B vs 1744 B "
        "in 1.38 / 1704 B modern -- shrinking forward in time, so it is a different "
        "function; not committed. 1.38 curated already.",
    "cGcPlanetGenerator::GenerateQueryInfo":
        "the two creature-role imm64s are non-distinctive (150+ .text occurrences "
        "each), so they cannot lock a function; the unique caller "
        "cGcSolarSystemQuery::Run is unmapped, leaving it indistinguishable from the "
        "other imm-cluster generators.",
    "cGcResourceCustomisation::CreateGenerationTask":
        "restructured in 1.38: not a direct caller of the mapped "
        "cTkResourceDescriptor::GenerateInstance (no ~452 B / 16-caller match among "
        "its callers), and its 16 callers give tied call-graph votes.",
    "cGcTerrainEditorBeam::Fire":
        "1.38-only; cGcPlayerWeapon::Fire (0x140E4EF20) is now mapped but none of its "
        "terrain-unit callees calls two big single-caller ApplyTerrainEdit* functions "
        "as modern Fire does -- the Flatten/Stroke split postdates 1.38, so Fire cannot "
        "be uniquely pinned.",
    "cGcTerrainEditorBeam::StartEffect":
        "1.38-only; the sole LASER_LIGHT referencer (0x140C9C320) is a shared beam "
        "light-node helper, not StartEffect, and StartEffect no longer references the "
        "string directly; its callees stay unmapped, so it cannot be separated from "
        "other beams' StartEffects.",
    "cGcTerrainEditorBeam::ApplyTerrainEditFlatten":
        "1.38-only; no string/imm tokens and its callees (CanApplyTerrainEdit, "
        "EditTerrain, GenerateElevation, BroadcastEdits) are all unmapped. Same-size "
        "candidates (e.g. 0x140EB59C0) turn out to be called by non-terrain weapon "
        "megafunctions, so size/adjacency give false positives.",
    "cGcTerrainEditorBeam::ApplyTerrainEditStroke":
        "1.38-only; same obstacle as ApplyTerrainEditFlatten -- callee set entirely "
        "unmapped and near-identical to Flatten, so it cannot be separated.",
}


def main():
    xv = Xverse()
    functions = {}

    def put(name, mapping):
        for b, va in mapping.items():
            nm = xv.name(b, va)
            if not nm:
                log(f"!! {name} {b}: 0x{va:X} is not a function start; dropping")
                continue
            functions.setdefault(name, {})[b] = f"0x{va:X}"

    log("== cGcSky::UpdateSunPosition")
    put("cGcSky::UpdateSunPosition", find_update_sun_position(xv))

    print(json.dumps({"functions": functions, "unresolved": UNRESOLVED}, indent=1))


if __name__ == "__main__":
    main()
